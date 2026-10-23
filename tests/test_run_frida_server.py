"""Unit tests for the detached frida-server launch, run_frida_server flow and CLI.

Device findings these guard (rooted Pixel 7, Android 17): a frida-server whose
stdout/stderr are adbd sockets dies from SIGPIPE once the host adb client goes
away, so the launch is ``setsid nohup sh -c "<cmd>" >><log> 2>&1 </dev/null &``
under each elevation style. The log is appended (``>>``) because a second
launch with ``>`` would truncate the log held by the running server.

No device required: FridaManager is built via ``__new__``; ADB calls are mocked.
"""

import base64
import logging
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from AndroidFridaManager.FridaManager import FridaManager
from AndroidFridaManager.adb import ADB, MagiskADB, RootADB, SuADB

CMD = "echo QUJD | base64 -d | sh"
LOG = "/data/local/tmp/frida-server.log"
DETACHED = f'setsid nohup sh -c "{CMD}" >>{LOG} 2>&1 </dev/null &'
MARKER = FridaManager.FRIDA_SERVER_LAUNCH_MARKER
# The package __init__ re-exports the class under the submodule's name.
fm_module = sys.modules["AndroidFridaManager.FridaManager"]


def _out(stdout: str = "", returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


def _make_fm(rooted: bool = True) -> FridaManager:
    fm = FridaManager.__new__(FridaManager)
    fm.logger = logging.getLogger("test-afm-run")
    fm.adb = Mock()
    fm.adb.is_rooted = rooted
    fm.is_remote = False
    fm.device_socket = ""
    fm._device_serial = None
    fm.frida_install_dst = "/data/local/tmp/"
    fm.verbose = False
    return fm


def _launchable_fm(ready_after_launch: bool = True) -> FridaManager:
    """A rooted fm with no running server, an existing binary and setsid."""
    fm = _make_fm()
    fm.is_frida_server_ready = Mock(return_value=False)
    fm._safe_frida_server_pids = Mock(return_value=[])
    fm._frida_server_binary_exists = Mock(return_value=True)
    fm._device_supports_detached_launch = Mock(return_value=True)
    fm.adb.root_detached_shell.return_value = _out()
    fm._wait_until_frida_ready = Mock(return_value=ready_after_launch)
    return fm


# ── ADB detached command strings ────────────────────────────────────────


class TestDetachedCommandPerElevation:
    def test_detached_command_appends_and_detaches(self):
        assert ADB.detached_command(CMD, LOG) == DETACHED

    def test_root_adb(self):
        assert RootADB("S")._elevate_detached(DETACHED) == DETACHED

    def test_su_adb(self):
        assert SuADB("S")._elevate_detached(DETACHED) == f"su 0 sh -c '{DETACHED}'"

    def test_magisk_adb(self):
        assert MagiskADB("S")._elevate_detached(DETACHED) == f"su -c '{DETACHED}'"

    def test_magisk_escapes_single_quotes(self):
        assert MagiskADB("S")._elevate_detached("echo 'x'") == "su -c 'echo '\\''x'\\'''"

    def test_unrooted_raises(self):
        with pytest.raises(ValueError):
            ADB("S")._elevate_detached(DETACHED)

    @pytest.mark.parametrize("cls,expected", [
        (RootADB, DETACHED),
        (SuADB, f"su 0 sh -c '{DETACHED}'"),
        (MagiskADB, f"su -c '{DETACHED}'"),
    ])
    def test_root_detached_shell_runs_blocking(self, cls, expected):
        with patch("AndroidFridaManager.adb.subprocess.run") as run:
            run.return_value = _out()
            cls("SERIAL").root_detached_shell(CMD, LOG)
        run.assert_called_once()
        assert run.call_args.args[0] == ["adb", "-s", "SERIAL", "shell", expected]
        assert run.call_args.kwargs["timeout"] == 30

    def test_background_shell_kept(self):
        assert MagiskADB("S")._elevate_background("x") == """su -c 'sh -c "x &"'"""


# ── launcher script ─────────────────────────────────────────────────────


class TestLauncher:
    def _script(self) -> str:
        cmd = _make_fm()._build_frida_server_launcher("/data/local/tmp/frida-server")
        assert cmd.startswith("echo ") and cmd.endswith(" | base64 -d | sh")
        assert '"' not in cmd and "'" not in cmd  # survives every wrapper
        return base64.b64decode(cmd.split()[1]).decode()

    def test_forwards_zygote_env_and_execs(self):
        script = self._script()
        assert "/proc/$ZPID/environ" in script
        assert script.rstrip().endswith("exec /data/local/tmp/frida-server </dev/null")

    def test_unsets_inherited_android_socket_vars(self):
        script = self._script()
        assert "ANDROID_SOCKET_" in script and 'unset "$v"' in script
        assert script.index('unset "$v"') < script.index("exec ")

    def test_writes_launch_marker(self):
        assert MARKER in self._script()


# ── run_frida_server ────────────────────────────────────────────────────


class TestRunFridaServer:
    def test_skips_when_ready(self):
        fm = _make_fm()
        fm.is_frida_server_ready = Mock(return_value=True)
        fm._launch_frida_server = Mock()
        assert fm.run_frida_server() is True
        fm._launch_frida_server.assert_not_called()

    def test_not_rooted(self):
        fm = _make_fm(rooted=False)
        fm.is_frida_server_ready = Mock(return_value=False)
        fm._launch_frida_server = Mock()
        assert fm.run_frida_server() is False
        fm._launch_frida_server.assert_not_called()

    def test_stale_pids_stopped_then_launched(self):
        fm = _launchable_fm()
        fm._safe_frida_server_pids = Mock(return_value=[4242])
        parent = Mock()
        fm.stop_frida_server = parent.stop
        parent.stop.return_value = True
        fm.adb.root_detached_shell = parent.launch
        assert fm.run_frida_server() is True
        assert [c[0] for c in parent.mock_calls] == ["stop", "launch"]

    def test_stop_failure_returns_false(self):
        fm = _launchable_fm()
        fm._safe_frida_server_pids = Mock(return_value=[4242])
        fm.stop_frida_server = Mock(return_value=False)
        assert fm.run_frida_server() is False
        fm.adb.root_detached_shell.assert_not_called()

    def test_missing_binary_returns_false(self):
        fm = _launchable_fm()
        fm._frida_server_binary_exists = Mock(return_value=False)
        fm.logger.error = Mock()
        assert fm.run_frida_server() is False
        fm.adb.root_detached_shell.assert_not_called()
        msg = fm.logger.error.call_args.args[0]
        assert "/data/local/tmp/frida-server" in msg and "install_frida_server()" in msg

    def test_launch_then_ready(self):
        fm = _launchable_fm()
        assert fm.run_frida_server() is True
        fm.adb.root_detached_shell.assert_called_once()
        cmd, log = fm.adb.root_detached_shell.call_args.args
        assert cmd.endswith("| base64 -d | sh")
        assert log == LOG
        fm._wait_until_frida_ready.assert_called_once_with(timeout=15)

    def test_custom_path(self):
        fm = _launchable_fm()
        assert fm.run_frida_server("/data/local/custom/") is True
        fm._frida_server_binary_exists.assert_called_once_with("/data/local/custom/frida-server")

    def test_launch_exception_returns_false(self):
        fm = _launchable_fm()
        fm.adb.root_detached_shell.side_effect = RuntimeError("adb gone")
        assert fm.run_frida_server() is False
        fm._wait_until_frida_ready.assert_not_called()

    def test_not_ready_reports_log_tail(self):
        fm = _launchable_fm(ready_after_launch=False)
        fm._read_frida_server_log_tail = Mock(return_value="Abort message: boom")
        fm.logger.error = Mock()
        assert fm.run_frida_server() is False
        msg = fm.logger.error.call_args.args[0]
        assert "Abort message: boom" in msg and "logcat" in msg

    def test_address_in_use_message(self):
        fm = _launchable_fm(ready_after_launch=False)
        fm._read_frida_server_log_tail = Mock(return_value=(
            "Unable to start: Error binding to address 127.0.0.1:27042: Address already in use"))
        fm.logger.error = Mock()
        assert fm.run_frida_server() is False
        msg = fm.logger.error.call_args.args[0]
        assert "27042" in msg and "another process" in msg

    def test_setsid_fallback_uses_background_shell(self):
        fm = _launchable_fm(ready_after_launch=False)
        fm._device_supports_detached_launch = Mock(return_value=False)
        fm._read_frida_server_log_tail = Mock(return_value="stale")
        fm.logger.warning = Mock()
        assert fm.run_frida_server() is False
        fm.adb.root_background_shell.assert_called_once()
        fm.adb.root_detached_shell.assert_not_called()
        assert "setsid" in fm.logger.warning.call_args.args[0]
        fm._read_frida_server_log_tail.assert_not_called()  # no log in fallback

    def test_setsid_fallback_ready(self):
        fm = _launchable_fm()
        fm._device_supports_detached_launch = Mock(return_value=False)
        assert fm.run_frida_server() is True
        fm.adb.root_background_shell.assert_called_once()


# ── small helpers ───────────────────────────────────────────────────────


class TestHelpers:
    def test_log_path(self):
        fm = _make_fm()
        fm.frida_install_dst = "/data/local/other/"
        assert fm.frida_server_log_path == "/data/local/other/frida-server.log"

    def test_log_tail_only_latest_launch(self):
        fm = _make_fm()
        fm.adb.root_shell.return_value = _out(
            f"{MARKER} Mon ===\nAddress already in use\n{MARKER} Tue ===\nnew line\n")
        assert fm._read_frida_server_log_tail() == "new line"
        assert fm.adb.root_shell.call_args.args[0] == f'tail -n 20 "{LOG}"'

    def test_log_tail_without_marker(self):
        fm = _make_fm()
        fm.adb.root_shell.return_value = _out("a\nb\n")
        assert fm._read_frida_server_log_tail(n=5) == "a\nb"
        assert fm.adb.root_shell.call_args.args[0] == f'tail -n 5 "{LOG}"'

    def test_log_tail_error(self):
        fm = _make_fm()
        fm.adb.root_shell.side_effect = RuntimeError("x")
        assert fm._read_frida_server_log_tail() == ""

    @pytest.mark.parametrize("stdout,expected", [("ok\n", True), ("", False)])
    def test_binary_exists(self, stdout, expected):
        fm = _make_fm()
        fm.adb.root_shell.return_value = _out(stdout)
        assert fm._frida_server_binary_exists("/x/frida-server") is expected
        assert 'test -x "/x/frida-server"' in fm.adb.root_shell.call_args.args[0]

    @pytest.mark.parametrize("stdout,expected", [("ok", True), ("", False)])
    def test_supports_detached_launch(self, stdout, expected):
        fm = _make_fm()
        fm.adb.root_shell.return_value = _out(stdout)
        assert fm._device_supports_detached_launch() is expected
        assert "command -v setsid" in fm.adb.root_shell.call_args.args[0]

    def test_supports_detached_launch_error(self):
        fm = _make_fm()
        fm.adb.root_shell.side_effect = RuntimeError("x")
        assert fm._device_supports_detached_launch() is False


class TestRestartChecksStop:
    def test_stop_failure_aborts(self):
        fm = _make_fm()
        fm.stop_frida_server = Mock(return_value=False)
        fm.run_frida_server = Mock()
        assert fm.restart_frida_server_and_wait() is False
        fm.run_frida_server.assert_not_called()

    def test_no_settle_sleep(self):
        fm = _make_fm()
        fm.stop_frida_server = Mock(return_value=True)
        fm.run_frida_server = Mock(return_value=True)
        fm._wait_until_frida_ready = Mock(return_value=True)
        with patch("AndroidFridaManager.FridaManager.time.sleep") as sleep:
            assert fm.restart_frida_server_and_wait() is True
        sleep.assert_not_called()


# ── CLI ─────────────────────────────────────────────────────────────────


def _run_main(argv, fm_instance):
    with patch.object(sys, "argv", ["afrim", *argv]), \
         patch.object(fm_module, "FridaManager") as cls:
        cls.return_value = fm_instance
        cls.get_connected_devices = Mock(return_value=[])
        with pytest.raises(SystemExit) as exc:
            fm_module.main()
    return exc.value.code, cls


def _cli_fm(ready: bool) -> Mock:
    inst = Mock()
    inst.get_frida_server_status.return_value = {
        "process": ready, "ready": ready, "installed_version": "17.0.0" if ready else None}
    return inst


class TestCli:
    def test_is_running_ready_exits_zero(self):
        inst = _cli_fm(ready=True)
        code, _ = _run_main(["-r"], inst)
        assert code == 0
        inst.install_frida_server.assert_not_called()

    def test_is_running_not_ready_exits_nonzero(self):
        code, _ = _run_main(["-r"], _cli_fm(ready=False))
        assert code != 0

    def test_is_running_honours_device_and_dst(self):
        _, cls = _run_main(["-r", "-d", "emulator-5554", "--frida_install_dst", "/data/x/"],
                           _cli_fm(ready=True))
        args, kwargs = cls.call_args
        assert args[3] == "/data/x/"
        assert kwargs["device_serial"] == "emulator-5554"

    def test_is_running_reports_process_and_version(self):
        inst = _cli_fm(ready=True)
        _run_main(["-r"], inst)
        logged = " ".join(c.args[0] for c in inst.logger.info.call_args_list)
        assert "process running: yes" in logged and "17.0.0" in logged

    def test_default_flow_exit_by_run_result(self):
        inst = Mock()
        inst.run_frida_server.return_value = True
        inst.get_installed_server_version.return_value = "17.0.0"
        code, _ = _run_main(["--verbose"], inst)
        assert code == 0
        inst.install_frida_server.assert_called_once()
        assert "17.0.0" in inst.logger.info.call_args.args[0]

    def test_default_flow_run_failure_nonzero(self):
        inst = Mock()
        inst.run_frida_server.return_value = False
        code, _ = _run_main(["--verbose"], inst)
        assert code != 0
