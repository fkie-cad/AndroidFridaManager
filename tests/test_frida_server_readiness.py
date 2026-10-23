"""Unit tests for frida-server readiness / process detection / stop logic.

Covers the frida-17 "jailed" trap: with no frida-server running, the USB
device still answers enumerate_processes() and query_system_parameters()
(``access: jailed``) through an ADB fallback, so only ``access: full`` means
the server is usable. Also covers versioned binary names
(``frida-server-17.18.0-android-arm64``) that pidof/killall miss.

No device required: FridaManager is built via ``__new__`` and collaborators
are mocked.
"""

import logging
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from AndroidFridaManager.FridaManager import FridaManager

SLEEP = "AndroidFridaManager.FridaManager.time.sleep"

PS_OUTPUT = """  PID NAME
    1 init
  812 zygote64

 4242 frida-server-17.18.0-android-arm64
 4300 frida-server
 abc frida-server
 5000 com.example.frida-server-client
"""


def _ps(stdout: str) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr="", returncode=0)


def _make_fm(rooted: bool = True) -> FridaManager:
    fm = FridaManager.__new__(FridaManager)
    fm.logger = logging.getLogger("test-afm-ready")
    fm.adb = Mock()
    fm.adb.is_rooted = rooted
    fm.is_remote = False
    fm.device_socket = ""
    fm._device_serial = None
    fm.frida_install_dst = "/data/local/tmp/"
    fm.verbose = False
    return fm


def _device(params=None, params_exc=None, enum_exc=None) -> Mock:
    dev = Mock()
    if params_exc:
        dev.query_system_parameters.side_effect = params_exc
    else:
        dev.query_system_parameters.return_value = params or {}
    if enum_exc:
        dev.enumerate_processes.side_effect = enum_exc
    else:
        dev.enumerate_processes.return_value = []
    return dev


class TestIsFridaServerReady:
    def test_jailed_is_not_ready(self):
        fm = _make_fm()
        fm._get_fresh_frida_device = Mock(return_value=_device({"access": "jailed"}))
        assert fm.is_frida_server_ready() is False

    def test_full_is_ready(self):
        fm = _make_fm()
        fm._get_fresh_frida_device = Mock(return_value=_device({"access": "full"}))
        assert fm.is_frida_server_ready() is True

    def test_missing_access_key_falls_back_to_enumerate_ok(self):
        fm = _make_fm()
        dev = _device({"arch": "arm64"})
        fm._get_fresh_frida_device = Mock(return_value=dev)
        assert fm.is_frida_server_ready() is True
        dev.enumerate_processes.assert_called_once()

    def test_missing_access_key_enumerate_fails(self):
        fm = _make_fm()
        dev = _device({"arch": "arm64"}, enum_exc=RuntimeError("closed"))
        fm._get_fresh_frida_device = Mock(return_value=dev)
        assert fm.is_frida_server_ready() is False

    def test_exception_is_not_ready(self):
        fm = _make_fm()
        fm._get_fresh_frida_device = Mock(side_effect=RuntimeError("no device"))
        assert fm.is_frida_server_ready() is False

    def test_query_exception_is_not_ready(self):
        fm = _make_fm()
        dev = _device(params_exc=RuntimeError("closed"))
        fm._get_fresh_frida_device = Mock(return_value=dev)
        assert fm.is_frida_server_ready() is False


class TestGetFreshFridaDevice:
    def test_serial(self):
        fm = _make_fm()
        fm._device_serial = "ABC123"
        with patch("AndroidFridaManager.FridaManager.frida") as frida_mod:
            fm._get_fresh_frida_device()
        frida_mod.get_device.assert_called_once_with("ABC123", timeout=2)

    def test_usb(self):
        fm = _make_fm()
        with patch("AndroidFridaManager.FridaManager.frida") as frida_mod:
            fm._get_fresh_frida_device(timeout=5)
        frida_mod.get_usb_device.assert_called_once_with(timeout=5)

    def test_remote(self):
        fm = _make_fm()
        fm.is_remote, fm.device_socket = True, "1.2.3.4:27042"
        with patch("AndroidFridaManager.FridaManager.frida") as frida_mod:
            fm._get_fresh_frida_device()
        frida_mod.get_device_manager.return_value.add_remote_device.assert_called_once_with(
            "1.2.3.4:27042"
        )


class TestWaitUntilFridaReady:
    def test_times_out_when_jailed(self):
        fm = _make_fm()
        fm._get_fresh_frida_device = Mock(return_value=_device({"access": "jailed"}))
        clock = iter([0.0, 0.0, 0.6, 1.2, 99.0])
        with patch(SLEEP), patch("AndroidFridaManager.FridaManager.time.time",
                                 side_effect=lambda: next(clock)):
            assert fm._wait_until_frida_ready(timeout=1.5) is False
        assert fm._get_fresh_frida_device.call_count == 3

    def test_succeeds_when_full(self):
        fm = _make_fm()
        devs = [_device({"access": "jailed"}), _device({"access": "full"})]
        fm._get_fresh_frida_device = Mock(side_effect=devs)
        with patch(SLEEP):
            assert fm._wait_until_frida_ready(timeout=5.0) is True
        assert fm._get_fresh_frida_device.call_count == 2


class TestIsProcessAliveReadinessGate:
    def test_false_when_jailed_even_if_pid_enumerated(self):
        fm = _make_fm()
        fm._get_fresh_frida_device = Mock(return_value=_device({"access": "jailed"}))
        adb_fallback = Mock()
        adb_fallback.enumerate_processes.return_value = [SimpleNamespace(pid=4242)]
        fm.get_frida_device = Mock(return_value=adb_fallback)
        assert fm.is_process_alive(4242) is False
        adb_fallback.enumerate_processes.assert_not_called()

    def test_true_when_full(self):
        fm = _make_fm()
        fm._get_fresh_frida_device = Mock(return_value=_device({"access": "full"}))
        dev = Mock()
        dev.enumerate_processes.return_value = [SimpleNamespace(pid=4242)]
        fm.get_frida_device = Mock(return_value=dev)
        assert fm.is_process_alive(4242) is True


class TestFridaServerPids:
    def test_parses_versioned_names_and_skips_junk(self):
        assert FridaManager._parse_frida_server_pids(PS_OUTPUT) == [4242, 4300]

    def test_path_style_name(self):
        out = "PID NAME\n77 /data/local/tmp/frida-server\n"
        assert FridaManager._parse_frida_server_pids(out) == [77]

    def test_empty(self):
        assert FridaManager._parse_frida_server_pids("") == []

    def test_rooted_uses_root_shell(self):
        fm = _make_fm(rooted=True)
        fm.adb.root_shell.return_value = _ps(PS_OUTPUT)
        assert fm._frida_server_pids() == [4242, 4300]
        fm.adb.root_shell.assert_called_once_with("ps -A -o PID,NAME")
        fm.adb.shell.assert_not_called()

    def test_non_rooted_uses_shell(self):
        fm = _make_fm(rooted=False)
        fm.adb.shell.return_value = _ps(PS_OUTPUT)
        assert fm._frida_server_pids() == [4242, 4300]
        fm.adb.shell.assert_called_once_with("ps -A -o PID,NAME")

    def test_none_stdout(self):
        fm = _make_fm()
        fm.adb.root_shell.return_value = _ps(None)
        assert fm._frida_server_pids() == []


class TestIsFridaServerRunning:
    def test_true_for_versioned_binary(self):
        fm = _make_fm()
        fm._frida_server_pids = Mock(return_value=[4242])
        assert fm.is_frida_server_running() is True

    def test_false_when_no_pids(self):
        fm = _make_fm()
        fm._frida_server_pids = Mock(return_value=[])
        fm._is_frida_server_running_legacy = Mock(return_value=True)
        assert fm.is_frida_server_running() is False
        fm._is_frida_server_running_legacy.assert_not_called()

    def test_falls_back_to_legacy_on_error(self):
        fm = _make_fm()
        fm._frida_server_pids = Mock(side_effect=RuntimeError("adb gone"))
        fm._is_frida_server_running_legacy = Mock(return_value=True)
        assert fm.is_frida_server_running() is True


class TestStopFridaServer:
    def test_kills_versioned_pids_and_returns_true(self):
        fm = _make_fm()
        fm._frida_server_pids = Mock(side_effect=[[4242, 4300], [4242], []])
        with patch(SLEEP):
            assert fm.stop_frida_server() is True
        cmds = [c.args[0] for c in fm.adb.root_shell.call_args_list]
        assert cmds[0] == "/system/bin/killall frida-server"
        assert "kill 4242 4300" in cmds
        assert not any(c.startswith("kill -9") for c in cmds)

    def test_escalates_to_sigkill_and_returns_false_if_survives(self):
        fm = _make_fm()
        fm._frida_server_pids = Mock(return_value=[4242])
        with patch(SLEEP) as sleep:
            assert fm.stop_frida_server() is False
        cmds = [c.args[0] for c in fm.adb.root_shell.call_args_list]
        assert cmds.count("kill -9 4242") == 1
        assert sum(c.args[0] for c in sleep.call_args_list) == pytest.approx(5.25)

    def test_sigkill_resolves(self):
        fm = _make_fm()
        alive = [[4242]] * 14 + [[]]  # initial lookup + 13 polls, then gone
        fm._frida_server_pids = Mock(side_effect=alive)
        with patch(SLEEP):
            assert fm.stop_frida_server() is True
        cmds = [c.args[0] for c in fm.adb.root_shell.call_args_list]
        assert "kill -9 4242" in cmds

    def test_returns_false_when_pid_lookup_fails(self):
        fm = _make_fm()
        fm._frida_server_pids = Mock(side_effect=RuntimeError("adb gone"))
        with patch(SLEEP):
            assert fm.stop_frida_server() is False

    def test_non_rooted_warns_and_returns_false(self):
        fm = _make_fm(rooted=False)
        fm.logger.warning = Mock()
        assert fm.stop_frida_server() is False
        fm.logger.warning.assert_called_once()
        fm.adb.root_shell.assert_not_called()


class TestInstallStopsRunningServer:
    def _prep(self, fm, pids):
        fm._frida_server_pids = Mock(return_value=pids)
        fm.stop_frida_server = Mock(return_value=True)
        fm.download_frida_server = Mock(return_value="/tmp/x/frida-server.xz")
        fm.extract_frida_server_comp = Mock(return_value="/tmp/x/frida-server")
        order = Mock()
        fm.stop_frida_server.side_effect = lambda: order.stop()
        fm._adb_remove_file_if_exist = Mock(side_effect=lambda p: order.remove(p))
        fm.make_frida_server_executable = Mock()
        return order

    def test_stops_before_replacing_when_pids_present(self):
        fm = _make_fm()
        order = self._prep(fm, [4242])
        assert fm.install_frida_server(version="17.18.0") is True
        assert [c[0] for c in order.mock_calls] == ["stop", "remove"]

    def test_no_stop_when_nothing_running(self):
        fm = _make_fm()
        self._prep(fm, [])
        assert fm.install_frida_server(version="17.18.0") is True
        fm.stop_frida_server.assert_not_called()


class TestStatusAndArch:
    def test_get_frida_server_status_shape(self):
        fm = _make_fm()
        fm.is_frida_server_running = Mock(return_value=True)
        fm.is_frida_server_ready = Mock(return_value=False)
        fm.get_installed_server_version = Mock(return_value="17.18.0")
        assert fm.get_frida_server_status() == {
            "process": True,
            "ready": False,
            "installed_version": "17.18.0",
        }

    def test_get_device_arch_delegates(self):
        fm = _make_fm()
        fm._get_android_device_arch = Mock(return_value="arm64")
        assert fm.get_device_arch() == "arm64"
