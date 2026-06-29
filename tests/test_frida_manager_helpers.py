"""Unit tests for the spawn-reliability helpers added to FridaManager.

Both helpers are additive and reusable:
- ``is_process_alive`` — pid membership in ``enumerate_processes``; False on
  ProcessNotFoundError and on any transport/protocol error (a wedged server is
  not "confirmed alive").
- ``restart_frida_server_and_wait`` — stop -> settle -> start -> readiness probe,
  honouring the caller's timeout.

No device required: the FridaManager instance is built via ``__new__`` (skips
the ADB-touching constructor) and its collaborators are mocked.
"""

import logging
from unittest.mock import Mock, patch

import frida
import pytest

from AndroidFridaManager.FridaManager import FridaManager


class _Proc:
    def __init__(self, pid: int) -> None:
        self.pid = pid


def _make_fm() -> FridaManager:
    fm = FridaManager.__new__(FridaManager)
    fm.logger = logging.getLogger("test-afm")
    return fm


class TestIsProcessAlive:
    def test_present(self):
        fm = _make_fm()
        dev = Mock()
        dev.enumerate_processes.return_value = [_Proc(1), _Proc(4242), _Proc(7)]
        fm.get_frida_device = Mock(return_value=dev)
        assert fm.is_process_alive(4242) is True

    def test_absent(self):
        fm = _make_fm()
        dev = Mock()
        dev.enumerate_processes.return_value = [_Proc(1), _Proc(7)]
        fm.get_frida_device = Mock(return_value=dev)
        assert fm.is_process_alive(4242) is False

    def test_process_not_found_returns_false(self):
        fm = _make_fm()
        dev = Mock()
        dev.enumerate_processes.side_effect = frida.ProcessNotFoundError("gone")
        fm.get_frida_device = Mock(return_value=dev)
        assert fm.is_process_alive(4242) is False

    def test_transport_error_returns_false(self):
        """A wedged/unreachable server is not 'confirmed alive' => False."""
        fm = _make_fm()
        fm.get_frida_device = Mock(side_effect=RuntimeError("transport wedged"))
        assert fm.is_process_alive(4242) is False


class TestRestartFridaServerAndWait:
    def test_stop_before_start_and_timeout_propagation(self):
        fm = _make_fm()
        parent = Mock()  # records child-call ordering on parent.mock_calls
        fm.stop_frida_server = parent.stop
        fm.run_frida_server = parent.run
        fm._wait_until_frida_ready = parent.wait
        parent.run.return_value = True
        parent.wait.return_value = True

        with patch("AndroidFridaManager.FridaManager.time.sleep"):
            result = fm.restart_frida_server_and_wait(timeout=7.5)

        assert result is True
        ordered = [c[0] for c in parent.mock_calls]
        assert ordered == ["stop", "run", "wait"]  # stop -> start -> probe
        parent.wait.assert_called_once_with(timeout=7.5)  # timeout propagated

    def test_default_timeout(self):
        fm = _make_fm()
        fm.stop_frida_server = Mock()
        fm.run_frida_server = Mock(return_value=True)
        fm._wait_until_frida_ready = Mock(return_value=True)
        with patch("AndroidFridaManager.FridaManager.time.sleep"):
            assert fm.restart_frida_server_and_wait() is True
        fm._wait_until_frida_ready.assert_called_once_with(timeout=15.0)

    def test_returns_false_when_run_fails_without_probing(self):
        fm = _make_fm()
        fm.stop_frida_server = Mock()
        fm.run_frida_server = Mock(return_value=False)
        fm._wait_until_frida_ready = Mock(return_value=True)
        with patch("AndroidFridaManager.FridaManager.time.sleep"):
            assert fm.restart_frida_server_and_wait() is False
        # No point probing readiness if the start itself failed.
        fm._wait_until_frida_ready.assert_not_called()

    def test_returns_false_when_probe_times_out(self):
        fm = _make_fm()
        fm.stop_frida_server = Mock()
        fm.run_frida_server = Mock(return_value=True)
        fm._wait_until_frida_ready = Mock(return_value=False)
        with patch("AndroidFridaManager.FridaManager.time.sleep"):
            assert fm.restart_frida_server_and_wait(timeout=3.0) is False
