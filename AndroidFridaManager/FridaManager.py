#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import frida
import os
import sys
import logging
import time
from colorlog import ColoredFormatter
import requests
import lzma
import re
import tempfile
import argparse
from typing import Optional, List, Dict
from .adb import ADB, RootADB, SuADB, MagiskADB

# some parts are taken from ttps://github.com/Mind0xP/Frida-Python-Binding/

class FridaManager():

    def __init__(self, is_remote=False, socket="", verbose=False, frida_install_dst="/data/local/tmp/", device_serial: Optional[str] = None, adb: Optional["ADB"] = None, prefer_adb_root: bool = False):
        """
        Constructor of the current FridaManager instance

        :param is_remote: Whether to use remote Frida connection.
        :type is_remote: bool
        :param socket: The socket to connect to the remote device. The remote device needs to be set by <ip:port>. By default this string will be empty in order to indicate that FridaManger is working with the first connected USB device.
        :type socket: string
        :param verbose: Set the output to verbose, so that the logging information gets printed. By default set to False.
        :type verbose: bool
        :param frida_install_dst: The path where the frida server should be installed. By default it will be installed to /data/local/tmp/.
        :type frida_install_dst: string
        :param device_serial: Specific device serial to target (e.g., 'emulator-5554'). If None, auto-selects device (prefers emulators when multiple devices connected).
        :type device_serial: Optional[str]
        :param adb: Pre-initialised ADB instance. When *None* one is created via ``ADB.find()``.
        :type adb: Optional[ADB]
        :param prefer_adb_root: When True, attempt ``adb root`` before ``su`` escalation. Useful on emulators and eng/userdebug builds.
        :type prefer_adb_root: bool

        """
        self.is_remote = is_remote
        self.device_socket = socket
        self.verbose = verbose
        self.frida_install_dst = frida_install_dst
        self._setup_logging()
        self.logger = logging.getLogger(__name__)

        # ADB wrapper (auto-detects device + root mode)
        self.adb = adb if adb is not None else ADB.find(device_id=device_serial, prefer_adb_root=prefer_adb_root)
        self._device_serial = self.adb.device_id

        if self.is_remote:
            frida.get_device_manager().add_remote_device(self.device_socket)

    @property
    def device_serial(self) -> Optional[str]:
        """Get the current target device serial."""
        return self._device_serial

    @device_serial.setter
    def device_serial(self, serial: str) -> None:
        """Set the target device serial."""
        self.adb = ADB.find(device_id=serial)
        self._device_serial = serial

    @property
    def is_magisk_mode(self) -> bool:
        """Backward-compatible flag: True when root is provided by Magisk."""
        return isinstance(self.adb, MagiskADB)

    @property
    def is_adb_root_mode(self) -> bool:
        """Backward-compatible flag: True when adbd is running as root."""
        return isinstance(self.adb, RootADB)

    def _setup_logging(self):
        """
        Setup logging for the current instance of FridaManager
        """
        logger = logging.getLogger()

        # Check if the logger already has handlers (i.e., if another project has set it up)
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            color_formatter = ColoredFormatter(
                    "%(log_color)s[%(asctime)s] [%(levelname)-4s]%(reset)s - %(message)s",
                    datefmt='%d-%m-%y %H:%M:%S',
                    reset=True,
                    log_colors={
                        'DEBUG':    'cyan',
                        'INFO':     'green',
                        'WARNING':  'bold_yellow',
                        'ERROR':    'bold_red',
                        'CRITICAL': 'bold_red',
                    },
                    secondary_log_colors={},
                    style='%')
            logging_handler = logging.StreamHandler()
            logging_handler.setFormatter(color_formatter)
            logger.addHandler(logging_handler)

    @classmethod
    def get_connected_devices(cls) -> List[Dict[str, str]]:
        """
        Get list of all connected Android devices via ADB.

        :return: List of device dictionaries with 'serial', 'state', 'type', and 'model' keys
        :rtype: List[Dict[str, str]]
        """
        return ADB.devices()

    @classmethod
    def get_frida_devices(cls) -> List[Dict[str, str]]:
        """
        Get list of devices visible to Frida.

        :return: List of device dictionaries with 'id', 'name', 'type' keys
        :rtype: List[Dict[str, str]]
        """
        try:
            devices = []
            for device in frida.enumerate_devices():
                if device.type in ('usb', 'remote'):
                    devices.append({
                        'id': device.id,
                        'name': device.name,
                        'type': device.type,
                    })
            return devices
        except Exception as e:
            logging.getLogger(__name__).debug(f"Error enumerating Frida devices: {e}")
            return []

    def get_frida_device(self):
        """
        Get the Frida device object for the current target device.

        :return: Frida Device object
        :raises RuntimeError: If device cannot be found
        """
        if self.is_remote:
            return frida.get_device_manager().add_remote_device(self.device_socket)

        if self._device_serial:
            try:
                # Try to get device by ID (matches ADB serial for USB devices)
                return frida.get_device(self._device_serial)
            except frida.InvalidArgumentError:
                # Fallback: enumerate and find by ID
                for device in frida.enumerate_devices():
                    if device.id == self._device_serial:
                        return device
                raise RuntimeError(f"Frida device '{self._device_serial}' not found")
        else:
            # Fallback to get_usb_device for single device scenario
            return frida.get_usb_device()

    # ==================== Frida Server Management ====================

    # Marker the launcher writes before exec, so log tails only show the latest
    # launch (the log is appended to, never truncated -- see run_frida_server).
    FRIDA_SERVER_LAUNCH_MARKER = "=== AndroidFridaManager: frida-server launch"

    @property
    def frida_server_log_path(self) -> str:
        """Device path of the log that receives frida-server's stdout/stderr."""
        return self.frida_install_dst + "frida-server.log"


    def run_frida_server(self, frida_server_path=None) -> bool:
        """Start frida-server detached from adb and wait until the client can use it.

        Skips the launch when a ready server (``access: full``) already exists,
        restarts a stale/unresponsive one, and verifies the binary first.

        :param frida_server_path: Directory holding ``frida-server`` (defaults
            to ``frida_install_dst``).
        :return: True once the frida client can attach/spawn, False otherwise.
        :rtype: bool
        """
        if self.is_frida_server_ready():
            if self.verbose:
                self.logger.info("[*] frida-server is already running and ready, skipping start")
            return True

        if not self.is_device_rooted:
            self.logger.error("Cannot start frida-server: device is not rooted")
            return False

        if not self._stop_stale_frida_server():
            return False

        frida_bin = (self.frida_install_dst if frida_server_path is None else frida_server_path) + "frida-server"
        if not self._frida_server_binary_exists(frida_bin):
            self.logger.error(f"frida-server binary not found at {frida_bin} -- call install_frida_server()")
            return False

        try:
            logged = self._launch_frida_server(frida_bin)
        except Exception as e:
            self.logger.error(f"Error starting frida-server: {e}")
            return False

        if self._wait_until_frida_ready(timeout=15):
            if self.verbose:
                self.logger.info("[*] frida-server is ready (client can attach)")
            return True
        self._report_frida_server_start_failure(logged)
        return False


    def _stop_stale_frida_server(self) -> bool:
        """Stop frida-server processes that exist but are not ready.

        :return: False only if such processes exist and could not be stopped.
        """
        pids = self._safe_frida_server_pids()
        if not pids:
            return True
        self.logger.warning(f"stale/unresponsive frida-server (pids {pids}) -- restarting")
        if self.stop_frida_server():
            return True
        self.logger.error(f"Could not stop stale frida-server (pids {pids}); not starting a new one")
        return False


    def _frida_server_binary_exists(self, frida_bin: str) -> bool:
        """Return True iff *frida_bin* exists and is executable (root ``test -x``)."""
        try:
            result = self.adb.root_shell(f'test -x "{frida_bin}" && echo ok')
        except Exception as e:
            self.logger.debug(f"frida-server binary check failed: {e}")
            return False
        return (result.stdout or "").strip() == "ok"


    def _build_frida_server_launcher(self, frida_bin: str) -> str:
        """Return the quote-free one-liner that runs the zygote-env launcher.

        frida-server 17.x boots an ART/Dalvik runtime at startup
        (JNI_CreateJavaVM). On Android 14+ ART aborts (SIGABRT) unless the
        environment init hands to zygote is present -- BOOTCLASSPATH,
        DEX2OATBOOTCLASSPATH and the ANDROID_* roots -- which a bare adb/su
        shell does not inherit. The launcher forwards zygote's environment,
        unsets inherited ANDROID_SOCKET_* vars (e.g. ANDROID_SOCKET_adbd leaks
        in from adbd), writes a launch marker to the log and execs
        frida-server. It is delivered base64-encoded so the command survives
        every su/elevation wrapper unchanged and nothing extra is written to
        the device filesystem.
        """
        launcher = f"""ZPID=$(pidof zygote64 || pidof zygote)
if [ -n "$ZPID" ]; then
  while IFS= read -r line; do
    case "$line" in
      ANDROID_SOCKET_*) ;;
      *=*) export "$line" ;;
    esac
  done <<EOF
$(tr '\\0' '\\n' < /proc/$ZPID/environ)
EOF
fi
for v in $(env | sed -n 's/^\\(ANDROID_SOCKET_[A-Za-z0-9_]*\\)=.*/\\1/p'); do
  unset "$v"
done
echo "{self.FRIDA_SERVER_LAUNCH_MARKER} $(date) ==="
exec {frida_bin} </dev/null
"""
        b64 = base64.b64encode(launcher.encode()).decode()
        return f"echo {b64} | base64 -d | sh"


    def _launch_frida_server(self, frida_bin: str) -> bool:
        """Launch frida-server; return True if its output goes to the log file.

        The launch is fully detached (setsid + nohup, stdio -> log file and
        /dev/null). Device experiments showed that a server whose stdout/stderr
        are adbd sockets (the old Popen-of-``adb shell`` launch) dies from
        SIGPIPE on its next write once the host adb client goes away
        (``adb kill-server``, USB replug). Readiness is confirmed separately
        via :meth:`_wait_until_frida_ready`.
        """
        frida_cmd = self._build_frida_server_launcher(frida_bin)
        if self._device_supports_detached_launch():
            result = self.adb.root_detached_shell(frida_cmd, self.frida_server_log_path)
            if getattr(result, "returncode", 0):
                self.logger.debug(f"detached launch returned {result.returncode}: {result.stderr}")
            return True
        self.logger.warning(
            "setsid/nohup not available on the device -- falling back to the legacy "
            "background launch (frida-server may die when the adb connection drops)"
        )
        self.adb.root_background_shell(frida_cmd)
        return False


    def _device_supports_detached_launch(self) -> bool:
        """Return True iff ``setsid`` and ``nohup`` exist on the device."""
        try:
            result = self.adb.root_shell(
                "command -v setsid >/dev/null && command -v nohup >/dev/null && echo ok"
            )
        except Exception as e:
            self.logger.debug(f"setsid availability check failed: {e}")
            return False
        return (result.stdout or "").strip() == "ok"


    def _read_frida_server_log_tail(self, n: int = 20) -> str:
        """Return the last *n* lines of the frida-server log from the latest launch.

        Lines up to and including the most recent launch marker are dropped,
        since the log is appended to across launches. Returns "" if the log
        cannot be read.
        """
        try:
            result = self.adb.root_shell(f'tail -n {int(n)} "{self.frida_server_log_path}"')
        except Exception as e:
            self.logger.debug(f"Could not read frida-server log: {e}")
            return ""
        lines = (result.stdout or "").splitlines()
        for i in range(len(lines) - 1, -1, -1):
            if lines[i].startswith(self.FRIDA_SERVER_LAUNCH_MARKER):
                lines = lines[i + 1:]
                break
        return "\n".join(lines).strip()


    def _report_frida_server_start_failure(self, logged: bool = True) -> None:
        """Log why a launched frida-server never became ready."""
        tail = self._read_frida_server_log_tail() if logged else ""
        if "Address already in use" in tail:
            self.logger.error(
                "frida-server could not bind 127.0.0.1:27042 (Address already in use) "
                "and no ready frida-server answers: another process holds the port "
                "(a hung instance, or a server not named 'frida-server'). "
                "Find it with `adb shell su -c 'netstat -tlnp'` and stop it."
            )
            return
        details = f"; log ({self.frida_server_log_path}):\n{tail}" if tail else ""
        self.logger.error(
            "frida-server did not become ready within 15s (frida client cannot attach)"
            f"{details}\nHint: check `adb logcat` for an ART/SIGABRT tombstone."
        )


    def _get_fresh_frida_device(self, timeout: int = 2):
        """Return a newly looked-up frida Device (remote socket / serial / usb).

        A fresh lookup avoids reusing a cached Device whose transport went
        stale across a frida-server restart.

        :param timeout: Seconds frida may wait for the device to appear.
        :type timeout: int
        :return: Frida Device object
        """
        if self.is_remote and self.device_socket:
            return frida.get_device_manager().add_remote_device(self.device_socket)
        if self._device_serial:
            return frida.get_device(self._device_serial, timeout=timeout)
        return frida.get_usb_device(timeout=timeout)


    def is_frida_server_ready(self) -> bool:
        """Return True iff a root frida-server is reachable and usable.

        Frida 17 trap: with NO frida-server running, the USB device still
        answers ``enumerate_processes()`` (full ADB process list) and
        ``query_system_parameters()`` through an ADB fallback -- the latter
        reports ``'access': 'jailed'``, and ``attach()``/``spawn()`` then fail
        with ``ServerNotRunningError``. So "enumerate succeeds" is a false
        positive. A real root frida-server reports ``'access': 'full'``.

        Older frida versions omit the ``access`` key; there a successful
        ``enumerate_processes()`` is the best available signal. Any exception
        means "not ready".

        :return: True if the client can attach/spawn through frida-server.
        :rtype: bool
        """
        try:
            device = self._get_fresh_frida_device()
            params = device.query_system_parameters()
            if "access" in params:
                return params["access"] == "full"
            device.enumerate_processes()
            return True
        except Exception as e:
            self.logger.debug(f"frida readiness probe failed: {e}")
            return False


    def _wait_until_frida_ready(self, timeout: float = 15.0, interval: float = 0.5) -> bool:
        """Block until the frida CLIENT can actually use frida-server.

        ``is_frida_server_running()`` only confirms a frida-server *process*
        exists. That is not enough: the control socket may not accept
        connections yet, and on frida 17 ``enumerate_processes()`` succeeds
        even with no server at all (ADB fallback, ``access: jailed``). Poll
        :meth:`is_frida_server_ready` until it reports ``access: full`` so
        callers can spawn/attach immediately after a start.

        :param timeout: Maximum seconds to wait for client reachability.
        :type timeout: float
        :param interval: Seconds between probes.
        :type interval: float
        :return: True if the server became ready within *timeout*.
        :rtype: bool
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.is_frida_server_ready():
                return True
            time.sleep(interval)
        return False


    def _frida_server_pids(self) -> List[int]:
        """Return pids of every process whose name starts with ``frida-server``.

        Matches versioned binaries such as ``frida-server-17.18.0-android-arm64``
        that ``pidof frida-server`` / ``killall frida-server`` miss. Uses a root
        shell when available (non-root ``ps`` may hide root processes).

        :return: List of matching pids (possibly empty).
        :rtype: List[int]
        :raises Exception: Propagates ADB errors so callers can fall back.
        """
        cmd = "ps -A -o PID,NAME"
        run = self.adb.root_shell if self.is_device_rooted else self.adb.shell
        return self._parse_frida_server_pids(run(cmd).stdout or "")


    @staticmethod
    def _parse_frida_server_pids(ps_output: str) -> List[int]:
        """Parse ``ps -o PID,NAME`` output; skip header, blanks and junk."""
        pids = []
        for line in ps_output.splitlines():
            fields = line.split(None, 1)
            if len(fields) != 2 or not fields[0].isdigit():
                continue
            name = fields[1].strip().rsplit("/", 1)[-1]
            if name.startswith("frida-server"):
                pids.append(int(fields[0]))
        return pids


    def is_frida_server_running(self) -> bool:
        """
        Checks if on the connected device a frida-server *process* exists.

        Matches versioned binary names (``frida-server-17.18.0-android-arm64``)
        via :meth:`_frida_server_pids`; falls back to the legacy
        ``pidof``/``ps | grep`` probes if that helper fails. Safe to call on
        non-rooted devices (returns False).

        NOTE: this does NOT prove the server is usable (socket ready, root
        access). Use :meth:`is_frida_server_ready` for that.

        :return: True if a frida-server process is running otherwise False.
        :rtype: bool
        """
        try:
            return bool(self._frida_server_pids())
        except Exception as e:
            self.logger.debug(f"ps-based frida-server lookup failed, using fallback: {e}")
            return self._is_frida_server_running_legacy()


    def _is_frida_server_running_legacy(self) -> bool:
        """Legacy pidof / ps|grep probes (fallback for is_frida_server_running)."""
        try:
            # Method 1: Try pidof without root (works on some devices)
            result = self.adb.shell("pidof frida-server")
            if result.stdout.strip():
                try:
                    int(result.stdout.strip().split()[0])  # Validate it's a number
                    return True
                except (ValueError, IndexError):
                    pass

            # Method 2: Try ps -A without root
            result = self.adb.shell("ps -A 2>/dev/null | grep frida-server | grep -v grep")
            if result.stdout.strip():
                return True

            # Method 3: Try with root if available
            if self.is_device_rooted:
                result = self.adb.root_shell("pidof frida-server")
                if result.stdout.strip():
                    return True

                result = self.adb.root_shell("ps | grep frida-server | grep -v grep")
                if result.stdout.strip():
                    return True

            return False

        except Exception as e:
            self.logger.debug(f"Error checking frida-server status: {e}")
            return False


    def get_installed_server_version(self) -> Optional[str]:
        """Return the version reported by `frida-server --version` on the device.

        :return: Version string like "17.9.11", or None if the binary is missing
            or doesn't respond with a version number.
        :rtype: Optional[str]
        """
        binary = self.frida_install_dst + "frida-server"
        try:
            result = self.adb.shell(f"{binary} --version")
            out = (result.stdout or "").strip()
        except Exception as e:
            self.logger.debug(f"Could not query frida-server version: {e}")
            return None
        return out if re.match(r"^\d+\.\d+\.\d+", out) else None


    def list_available_versions(self, limit: int = 15) -> List[str]:
        """Fetch recent frida release tags from GitHub.

        :param limit: Maximum number of releases to return (newest first).
        :type limit: int
        :return: Version strings like ``["17.9.11", "17.9.10", ...]``. Empty
            list on network failure — caller decides on fallback behavior.
        :rtype: List[str]
        """
        url = "https://api.github.com/repos/frida/frida/releases"
        try:
            res = requests.get(url, timeout=10, params={"per_page": limit})
            res.raise_for_status()
            return [r["tag_name"] for r in res.json() if "tag_name" in r]
        except requests.RequestException as e:
            self.logger.warning(f"Could not fetch frida releases: {e}")
            return []


    def stop_frida_server(self) -> bool:
        """Stop every frida-server process (including versioned binary names).

        Sends ``killall frida-server`` (compatibility), then ``kill`` to every
        pid from :meth:`_frida_server_pids`, and waits until none remain
        (escalating to ``kill -9``).

        :return: True if no frida-server process remains, False otherwise
            (also False on a non-rooted device).
        :rtype: bool
        """
        if not self.is_device_rooted:
            self.logger.warning("Cannot stop frida-server: device not rooted")
            return False
        self.adb.root_shell("/system/bin/killall frida-server")
        self._kill_pids(self._safe_frida_server_pids() or [])
        return self._wait_for_frida_server_exit()


    def _safe_frida_server_pids(self) -> Optional[List[int]]:
        """:meth:`_frida_server_pids`, or None if the lookup failed."""
        try:
            return self._frida_server_pids()
        except Exception as e:
            self.logger.debug(f"frida-server pid lookup failed: {e}")
            return None


    def _kill_pids(self, pids: List[int], force: bool = False) -> None:
        """Send SIGTERM (or SIGKILL when *force*) to *pids* via a root shell."""
        if not pids:
            return
        flag = "-9 " if force else ""
        self.adb.root_shell(f"kill {flag}{' '.join(str(p) for p in pids)}")


    def _wait_for_frida_server_exit(self, timeout: float = 5.0, escalate_after: float = 3.0,
                                    step: float = 0.25) -> bool:
        """Poll until no frida-server pid remains; ``kill -9`` after *escalate_after*."""
        escalate_at = int(escalate_after / step)
        for i in range(int(timeout / step) + 1):
            pids = self._safe_frida_server_pids()
            if pids == []:
                return True
            if i == escalate_at and pids:
                self.logger.debug(f"frida-server still alive, sending SIGKILL to {pids}")
                self._kill_pids(pids, force=True)
            time.sleep(step)
        return False


    def is_process_alive(self, pid: int) -> bool:
        """Return True iff *pid* is a live process on the target device.

        Membership check against ``get_frida_device().enumerate_processes()``.
        Spawn-reliability ladders use this to detect a target that crashed off
        the splash and was relaunched *uninstrumented* right after ``resume()``
        — the original instrumented pid vanishes while the package keeps the
        same name, so polling the *specific* pid is the only reliable signal.

        A wedged/unreachable frida-server (transport/protocol error) is itself
        "not confirmed alive", so this returns False rather than raising — the
        caller can then decide whether to recover the server. Readiness is
        checked first via :meth:`is_frida_server_ready`, because on frida 17
        ``enumerate_processes()`` answers via an ADB fallback even when no
        frida-server runs (``access: jailed``).

        :param pid: The process id to check.
        :type pid: int
        :return: True if *pid* is currently enumerated by frida-server.
        :rtype: bool
        """
        if not self.is_frida_server_ready():
            return False
        try:
            device = self.get_frida_device()
            for proc in device.enumerate_processes():
                if proc.pid == pid:
                    return True
            return False
        except frida.ProcessNotFoundError:
            return False
        except Exception as e:
            self.logger.debug(f"is_process_alive({pid}) probe failed: {e}")
            return False


    def restart_frida_server_and_wait(self, timeout: float = 15.0) -> bool:
        """Stop then start frida-server, blocking until the client can reach it.

        Recovery primitive for a wedged/crashed frida-server. ``stop`` already
        waits until no frida-server process remains, so ``run`` starts a fresh
        instance immediately. The *timeout* is honoured for the final
        client-reachability confirmation (on the normal success path
        ``run_frida_server`` has already confirmed readiness, so it returns
        promptly).

        :param timeout: Max seconds to wait for client reachability after start.
        :type timeout: float
        :return: True if frida-server came back up and the client can reach it.
        :rtype: bool
        """
        if not self.stop_frida_server():
            self.logger.error("Could not stop frida-server; not restarting")
            return False
        if not self.run_frida_server():
            return False
        return self._wait_until_frida_ready(timeout=timeout)


    def remove_frida_server(self, frida_server_path=None):
        cmd = (self.frida_install_dst if frida_server_path is None else frida_server_path) + "frida-server"

        self.stop_frida_server()
        self._adb_remove_file_if_exist(cmd)


    def install_frida_server(self, dst_dir=None, version=None):
        """
        Install the frida server binary on the Android device.
        This includes downloading the frida-server, decompress it and pushing it to the Android device.
        By default it is pushed into the /data/local/tmp/ directory.
        Further the binary will be set to executable in order to run it.

        :param dst_dir: The destination folder where the frida-server binary should be installed (pushed).
        :type dst_dir: string
        :param version: The version to install. When *None* (default) the version
            of the host ``frida`` Python package is used so that client and server
            stay in sync. Pass ``"latest"`` to pull the newest release from GitHub.
        :type version: string
        :raises RuntimeError: If device is not rooted

        """
        if version is None:
            try:
                import frida as _frida
                version = _frida.__version__
                self.logger.info(f"Auto-detected frida version from host package: {version}")
            except Exception:
                version = "latest"
                self.logger.warning("Could not detect host frida version, falling back to 'latest'")

        # Check root access BEFORE downloading - fail fast to save time
        if not self.is_device_rooted:
            self.logger.error(
                "Device is not rooted. Frida server installation requires root access. "
                "Please root the device or use an emulator."
            )
            raise RuntimeError("Cannot install frida-server: device not rooted")

        frida_dir = self.frida_install_dst if dst_dir is None else dst_dir

        self.logger.info("Installing frida-server now...")

        with tempfile.TemporaryDirectory() as dir:
            if self.verbose:
                self.logger.info(f"[*] downloading frida-server to {dir}")
            file_path = self.download_frida_server(dir,version)
            tmp_frida_server = self.extract_frida_server_comp(file_path)
            self._stop_running_server_before_replace()
            # ensure's that we always overwrite the current installation with our recent downloaded version
            self._adb_remove_file_if_exist(frida_dir + "frida-server")
            if self.verbose:
                self.logger.info(f"[*] pushing frida-server to {frida_dir}")
            self.adb.push(tmp_frida_server, frida_dir)
            self.make_frida_server_executable()
            return True


    def _stop_running_server_before_replace(self) -> None:
        """Stop a running frida-server so it doesn't keep running from a deleted inode."""
        pids = self._safe_frida_server_pids()
        if pids:
            self.logger.info(f"Stopping running frida-server (pids {pids}) before replacing the binary")
            self.stop_frida_server()


    # by default the frida-server version matching the host package is downloaded
    def download_frida_server(self, path, version=None):
        """
        Downloads a frida server. By default the version matching the host
        ``frida`` Python package is used. Pass ``"latest"`` to fetch the
        newest release from GitHub, or a specific version string like
        ``"16.3.3"``.

        :param path: The path where the compressed frida-server should be downloded.
        :type path: string
        :param version: The version. When *None* the host frida package version is
            used. Pass ``"latest"`` for the newest GitHub release.
        :type version: string

        :return: The location of the downloaded frida server in its compressed form.
        :rtype: string
        """
        if version is None:
            try:
                import frida as _frida
                version = _frida.__version__
                self.logger.info(f"Auto-detected frida version from host package: {version}")
            except Exception:
                version = "latest"
                self.logger.warning("Could not detect host frida version, falling back to 'latest'")

        url = self.get_frida_server_for_android_url(version)
        with open(path+"/frida-server","wb") as fsb:
            res = requests.get(url)
            fsb.write(res.content)
            if self.verbose:
                self.logger.info(f"[*] writing frida-server to {path}")

        return path+"/frida-server"



    def extract_frida_server_comp(self, file_path):
        if self.verbose:
            self.logger.info(f"[*] extracting {file_path} ...")
        # create a subdir for the specified filename
        frida_server_dir = file_path[:-3]
        os.makedirs(frida_server_dir)
        with lzma.open(file_path, 'rb') as f:
            decompressed_file = f.read()
        with open(frida_server_dir+'/frida-server', 'wb') as f:
            f.write(decompressed_file)

        # del compressed file
        os.remove(file_path)
        return frida_server_dir+"/frida-server"


    def get_frida_server_for_android_url(self, version):
        arch = self._get_android_device_arch()

        if self.verbose:
            self.logger.info(f"[*] Android architecture: {arch}")
        arch_map = {"arm64": "arm64", "arm": "arm", "ia32": "x86", "x64": "x86_64"}
        arch_str = arch_map.get(arch, "x86")

        if self.verbose:
            self.logger.info(f"[*] Android architecture string: {arch_str}")

        download_url = self._get_frida_server_download_url(arch_str,version)
        return download_url


    def _get_frida_server_download_url(self, arch, version):
        frida_download_prefix = "https://github.com/frida/frida/releases"

        if version == "latest":
            url = "https://api.github.com/repos/frida/frida/releases/"+version

            try:
                res = requests.get(url)
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error making request to {url}: {e}")
                raise RuntimeError(f"Failed to fetch Frida release information: {e}")

            frida_server_path = re.findall(
                r'/download/\d+\.\d+\.\d+/frida-server-\d+\.\d+\.\d+-android-' + arch + r'\.xz',
                res.text,
            )

            final_url = frida_download_prefix + frida_server_path[0]

        else:
            final_url = "https://github.com/frida/frida/releases/download/"+ version +"/frida-server-"+version+"-android-"+arch+".xz"


        if self.verbose:
            self.logger.info(f"[*] frida-server download url: {final_url}")

        return final_url


    def make_frida_server_executable(self, frida_server_path=None):
        cmd = (self.frida_install_dst if frida_server_path is None else frida_server_path) + "frida-server"
        final_cmd = f'chmod +x "{cmd}"'
        if self.verbose:
            self.logger.info(f"[*] making frida-server executable: {final_cmd}")
        self.adb.root_shell(final_cmd)


    def get_device_arch(self) -> str:
        """Public alias of :meth:`_get_android_device_arch` (frida arch name, e.g. ``arm64``)."""
        return self._get_android_device_arch()


    def get_frida_server_status(self) -> Dict[str, object]:
        """Summarise frida-server state on the device.

        :return: ``{"process": bool, "ready": bool, "installed_version": Optional[str]}``
            -- *process*: a frida-server process exists; *ready*: the client can
            attach/spawn (``access: full``); *installed_version*: version of the
            binary at the install destination, or None.
        :rtype: Dict[str, object]
        """
        return {
            "process": self.is_frida_server_running(),
            "ready": self.is_frida_server_ready(),
            "installed_version": self.get_installed_server_version(),
        }


    def _get_android_device_arch(self) -> str:
        """Get the architecture of the target Android device."""
        try:
            device = self.get_frida_device()
            return device.query_system_parameters()['arch']
        except Exception as e:
            self.logger.warning(f"Failed to get arch via Frida, falling back to ADB: {e}")
            # Fallback to ADB
            result = self.adb.shell("getprop ro.product.cpu.abi")
            abi = result.stdout.strip()
            # Map ABI to Frida arch
            if 'arm64' in abi or 'aarch64' in abi:
                return 'arm64'
            elif 'armeabi' in abi or 'arm' in abi:
                return 'arm'
            elif 'x86_64' in abi:
                return 'x64'
            elif 'x86' in abi:
                return 'ia32'
            return 'arm64'  # Default


    def _adb_make_binary_executable(self, path):
        self.adb.root_shell(f'chmod +x "{path}"')


    def _adb_does_file_exist(self, path: str) -> bool:
        """Check if a file exists on the device."""
        if self.is_device_rooted:
            output = self.adb.root_shell(f'ls "{path}"')
        else:
            output = self.adb.shell(f'ls "{path}" 2>/dev/null')
        return len(output.stderr) <= 1 and bool(output.stdout.strip())

    @property
    def is_device_rooted(self) -> bool:
        """
        Check if the target device has root access.

        :return: True if device is rooted, False otherwise
        """
        return self.adb.is_rooted

    def _adb_remove_file_if_exist(self, path="/data/local/tmp/frida-server"):
        if self._adb_does_file_exist(path):
            if self.is_device_rooted:
                self.adb.root_shell(f'rm "{path}"')
            else:
                self.adb.shell(f'rm "{path}"')


def _print_device_list() -> None:
    """Print connected ADB devices as a table."""
    devices = FridaManager.get_connected_devices()
    if not devices:
        print("No devices connected")
        return
    print(f"{'Serial':<20} {'Type':<10} {'State':<12} {'Model'}")
    print("-" * 60)
    for d in devices:
        print(f"{d['serial']:<20} {d['type']:<10} {d['state']:<12} {d['model']}")


def _report_status(afm_obj: "FridaManager") -> int:
    """Log frida-server status; return exit code 0 only if the server is ready."""
    status = afm_obj.get_frida_server_status()
    afm_obj.logger.info(f"[*] frida-server process running: {'yes' if status['process'] else 'no'}")
    afm_obj.logger.info(f"[*] frida-server ready (client can attach): {'yes' if status['ready'] else 'no'}")
    afm_obj.logger.info(f"[*] installed frida-server version: {status['installed_version'] or 'not installed'}")
    return 0 if status["ready"] else 1


def _install_and_run(afm_obj: "FridaManager") -> int:
    """Install the pinned frida-server and start it; return the exit code."""
    afm_obj.install_frida_server()
    if afm_obj.run_frida_server():
        version = afm_obj.get_installed_server_version() or frida.__version__
        afm_obj.logger.info(f"[*] successfully installed and launched frida-server {version} on Android device")
        return 0
    afm_obj.logger.error("[-] unable to run frida-server on Android device")
    return 1


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='FridaManager initialization parameters.')
    parser.add_argument('--is_remote', type=lambda x: (str(x).lower() == 'true'), default=False, help='Whether to use Frida in remote mode. Default is False.')
    parser.add_argument('--socket', type=str, default="", help='Socket to use for the connection. Expected in the format <ip:port>.')
    parser.add_argument('--verbose', required=False, action="store_const", const=True, default=False, help='Enable verbose output. Default is False.')
    parser.add_argument('--frida_install_dst', type=str, default="/data/local/tmp/", help='Frida installation destination. Default is "/data/local/tmp/".')
    parser.add_argument('-r','--is_running', required=False, action="store_const", const=True, default=False, help='Print frida-server status (process / ready / installed version). Exits 0 only if the server is ready for the frida client.')
    parser.add_argument('-d', '--device', type=str, default=None, help='Target device serial (e.g., emulator-5554). Auto-selects if not specified.')
    parser.add_argument('-l', '--list-devices', required=False, action="store_const", const=True, default=False, help='List all connected devices and exit.')
    parser.add_argument('--adb-root', required=False, action="store_const", const=True, default=False, help='Use "adb root" to restart adbd as root before trying su escalation (useful on emulators and eng/userdebug builds).')
    return parser


def main():
    if len(sys.argv) > 1:
        args = _build_arg_parser().parse_args()

        if args.list_devices:
            _print_device_list()
            sys.exit(0)

        afm_obj = FridaManager(args.is_remote, args.socket, args.verbose, args.frida_install_dst, device_serial=args.device, prefer_adb_root=args.adb_root)

        if args.is_running:
            sys.exit(_report_status(afm_obj))
    else:
        afm_obj = FridaManager()

    sys.exit(_install_and_run(afm_obj))


if __name__ == "__main__":
    main()
