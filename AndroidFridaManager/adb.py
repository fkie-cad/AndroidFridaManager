"""Standalone ADB wrapper with polymorphic root elevation."""

import logging
import shutil
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ADB:
    """Base ADB wrapper. Does not assume root access."""

    def __init__(self, device_id: Optional[str] = None) -> None:
        self._device_id = device_id

    # ── command helpers ──────────────────────────────────────────────

    def _build_cmd(self, args: List[str]) -> List[str]:
        base = ["adb"]
        if self._device_id:
            base += ["-s", self._device_id]
        return base + args

    def _run(self, args: List[str], timeout: int = 5) -> subprocess.CompletedProcess:
        return subprocess.run(
            self._build_cmd(args),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    # ── elevation (overridden by subclasses) ─────────────────────────

    def _elevate(self, cmd: str) -> str:
        raise ValueError("Device is not rooted")

    def _elevate_background(self, cmd: str) -> str:
        raise ValueError("Device is not rooted")

    # ── shell commands ───────────────────────────────────────────────

    def shell(self, cmd: str, timeout: int = 5) -> subprocess.CompletedProcess:
        return self._run(["shell", cmd], timeout=timeout)

    def root_shell(self, cmd: str, timeout: int = 5) -> subprocess.CompletedProcess:
        return self._run(["shell", self._elevate(cmd)], timeout=timeout)

    def root_background_shell(self, cmd: str) -> subprocess.Popen:
        full_cmd = self._build_cmd(["shell", self._elevate_background(cmd)])
        return subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            text=True,
        )

    # ── file transfer ────────────────────────────────────────────────

    def push(self, local: str, remote: str, timeout: int = 30) -> subprocess.CompletedProcess:
        return self._run(["push", local, remote], timeout=timeout)

    def pull(self, remote: str, local: str, timeout: int = 30) -> subprocess.CompletedProcess:
        return self._run(["pull", remote, local], timeout=timeout)

    # ── properties ───────────────────────────────────────────────────

    @property
    def is_rooted(self) -> bool:
        return False

    @property
    def device_id(self) -> Optional[str]:
        return self._device_id

    # ── static helpers ───────────────────────────────────────────────

    @staticmethod
    def devices() -> List[Dict[str, str]]:
        """Return connected devices parsed from ``adb devices -l``."""
        try:
            result = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            devices: List[Dict[str, str]] = []
            for line in result.stdout.strip().split("\n")[1:]:
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                serial = parts[0]
                state = parts[1]

                model = ""
                product = ""
                for part in parts[2:]:
                    if part.startswith("model:"):
                        model = part.split(":", 1)[1]
                    elif part.startswith("product:"):
                        product = part.split(":", 1)[1]

                device_type = "emulator" if serial.startswith("emulator-") else "physical"

                devices.append({
                    "serial": serial,
                    "state": state,
                    "type": device_type,
                    "model": model or product or serial,
                })

            return devices

        except subprocess.TimeoutExpired:
            return []
        except Exception as exc:
            logger.debug("Error getting devices: %s", exc)
            return []

    # ── factory ──────────────────────────────────────────────────────

    @staticmethod
    def find(device_id: Optional[str] = None) -> "ADB":
        """Detect the best ADB subclass for the connected device."""

        if not shutil.which("adb"):
            raise RuntimeError("adb not found on PATH")

        # --- resolve device_id -------------------------------------------
        if device_id is None:
            all_devices = ADB.devices()
            ready = [d for d in all_devices if d["state"] == "device"]

            if not ready:
                info = [f"{d['serial']} ({d['state']})" for d in all_devices]
                available = ", ".join(info) if info else "none"
                raise RuntimeError(f"No ready Android devices found. Connected: {available}")

            if len(ready) == 1:
                device_id = ready[0]["serial"]
                logger.info("Auto-selected single device: %s", device_id)
            else:
                emulators = [d for d in ready if d["serial"].startswith("emulator-")]
                if emulators:
                    device_id = emulators[0]["serial"]
                    logger.info("Multiple devices found; preferring emulator: %s", device_id)
                else:
                    device_id = ready[0]["serial"]
                    logger.info("Multiple physical devices found; selected first: %s", device_id)
        else:
            known = {d["serial"] for d in ADB.devices()}
            if device_id not in known:
                raise RuntimeError(
                    f"Device '{device_id}' not found. "
                    f"Available: {', '.join(known) if known else 'none'}"
                )
            logger.info("Using specified device: %s", device_id)

        # --- root detection ----------------------------------------------
        def _quick_run(*args: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                ["adb", "-s", device_id, *args],
                capture_output=True,
                text=True,
                timeout=5,
            )

        # 1. Already root (adbd running as root)
        try:
            res = _quick_run("shell", "id", "-u")
            if res.stdout.strip() == "0":
                logger.info("adbd is running as root")
                return RootADB(device_id)
        except subprocess.TimeoutExpired:
            logger.debug("Timeout checking adbd root")

        # 2. Magisk su
        try:
            res = _quick_run("shell", "su -v")
            if res.stdout.strip():
                logger.info("Magisk su detected (%s)", res.stdout.strip())
                return MagiskADB(device_id)
        except subprocess.TimeoutExpired:
            logger.debug("Timeout checking Magisk su")

        # 3. Legacy su
        try:
            res = _quick_run("shell", "su 0 id -u")
            if res.stdout.strip() == "0":
                logger.info("Legacy su detected")
                return SuADB(device_id)
        except subprocess.TimeoutExpired:
            logger.debug("Timeout checking legacy su")

        logger.info("No root access detected; returning base ADB")
        return ADB(device_id)


# ── rooted subclasses ────────────────────────────────────────────────


class RootADB(ADB):
    """adbd is already running as root; no elevation wrapper needed."""

    def _elevate(self, cmd: str) -> str:
        return cmd

    def _elevate_background(self, cmd: str) -> str:
        return f"{cmd} &"

    @property
    def is_rooted(self) -> bool:
        return True


class SuADB(ADB):
    """Root via legacy ``su 0`` binary."""

    def _elevate(self, cmd: str) -> str:
        return f"su 0 {cmd}"

    def _elevate_background(self, cmd: str) -> str:
        return f'su 0 sh -c "{cmd} &"'

    @property
    def is_rooted(self) -> bool:
        return True


class MagiskADB(ADB):
    """Root via Magisk ``su -c``."""

    def _elevate(self, cmd: str) -> str:
        escaped = cmd.replace("'", "'\\''")
        return f"su -c '{escaped}'"

    def _elevate_background(self, cmd: str) -> str:
        return f"""su -c 'sh -c "{cmd} &"'"""

    @property
    def is_rooted(self) -> bool:
        return True
