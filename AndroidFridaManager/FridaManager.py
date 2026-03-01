#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

    def __init__(self, is_remote=False, socket="", verbose=False, frida_install_dst="/data/local/tmp/", device_serial: Optional[str] = None, adb: Optional["ADB"] = None):
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

        """
        self.is_remote = is_remote
        self.device_socket = socket
        self.verbose = verbose
        self.frida_install_dst = frida_install_dst
        self._setup_logging()
        self.logger = logging.getLogger(__name__)

        # ADB wrapper (auto-detects device + root mode)
        self.adb = adb if adb is not None else ADB.find(device_id=device_serial)
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

    def run_frida_server(self, frida_server_path=None):
        # Check if frida-server is already running
        if self.is_frida_server_running():
            if self.verbose:
                self.logger.info("[*] frida-server is already running, skipping start")
            return True

        # Ensure root access is available
        if not self.is_device_rooted:
            self.logger.error("Cannot start frida-server: device is not rooted")
            return False

        frida_bin = (self.frida_install_dst if frida_server_path is None else frida_server_path) + "frida-server"

        try:
            process = self.adb.root_background_shell(frida_bin)
            # Give it a moment to start and potentially fail
            time.sleep(1)

            # Check if process failed immediately
            if process.poll() is not None:
                _, stderr_text = process.communicate()
                if stderr_text and "Address already in use" in stderr_text:
                    self.logger.info("[*] frida-server is already running on the device")
                    return True
                else:
                    self.logger.error(f"Failed to start frida-server: {stderr_text}")
                    return False
            else:
                if self.verbose:
                    self.logger.info("[*] frida-server started successfully in background")

            if self.is_frida_server_running():
                return True
            else:
                self.logger.error("frida-server does not seem to be running after start command")
                return False

        except Exception as e:
            self.logger.error(f"Error starting frida-server: {e}")
            return False


    def is_frida_server_running(self) -> bool:
        """
        Checks if on the connected device a frida server is running.

        This method first tries non-root commands, then falls back to root commands
        if available. Safe to call on non-rooted devices (returns False).

        :return: True if a frida-server is running otherwise False.
        :rtype: bool
        """
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


    def stop_frida_server(self):
        if self.is_device_rooted:
            self.adb.root_shell("/system/bin/killall frida-server")
        else:
            self.logger.warning("Cannot stop frida-server: device not rooted")


    def remove_frida_server(self, frida_server_path=None):
        cmd = (self.frida_install_dst if frida_server_path is None else frida_server_path) + "frida-server"

        self.stop_frida_server()
        self._adb_remove_file_if_exist(cmd)


    def install_frida_server(self, dst_dir=None, version="latest"):
        """
        Install the frida server binary on the Android device.
        This includes downloading the frida-server, decompress it and pushing it to the Android device.
        By default it is pushed into the /data/local/tmp/ directory.
        Further the binary will be set to executable in order to run it.

        :param dst_dir: The destination folder where the frida-server binary should be installed (pushed).
        :type dst_dir: string
        :param version: The version. By default the latest version will be used.
        :type version: string
        :raises RuntimeError: If device is not rooted

        """
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
            # ensure's that we always overwrite the current installation with our recent downloaded version
            self._adb_remove_file_if_exist(frida_dir + "frida-server")
            if self.verbose:
                self.logger.info(f"[*] pushing frida-server to {frida_dir}")
            self.adb.push(tmp_frida_server, frida_dir)
            self.make_frida_server_executable()
            return True


    # by default the latest frida-server version will be downloaded
    def download_frida_server(self, path, version="latest"):
        """
        Downloads a frida server. By default the latest version is used.
        If you want to download a specific version you have to provide it trough the version parameter.

        :param path: The path where the compressed frida-server should be downloded.
        :type path: string
        :param version: The version. By default the latest version will be used.
        :type version: string

        :return: The location of the downloaded frida server in its compressed form.
        :rtype: string
        """
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


def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description='FridaManager initialization parameters.')

        parser.add_argument('--is_remote', type=lambda x: (str(x).lower() == 'true'), default=False, help='Whether to use Frida in remote mode. Default is False.')
        parser.add_argument('--socket', type=str, default="", help='Socket to use for the connection. Expected in the format <ip:port>.')
        parser.add_argument('--verbose', required=False, action="store_const", const=True, default=False, help='Enable verbose output. Default is False.')
        parser.add_argument('--frida_install_dst', type=str, default="/data/local/tmp/", help='Frida installation destination. Default is "/data/local/tmp/".')
        parser.add_argument('-r','--is_running', required=False, action="store_const", const=True, default=False, help='Checks only if frida-server is running on the Android device or not.')
        parser.add_argument('-d', '--device', type=str, default=None, help='Target device serial (e.g., emulator-5554). Auto-selects if not specified.')
        parser.add_argument('-l', '--list-devices', required=False, action="store_const", const=True, default=False, help='List all connected devices and exit.')

        args = parser.parse_args()

        # List devices mode
        if args.list_devices:
            devices = FridaManager.get_connected_devices()
            if not devices:
                print("No devices connected")
            else:
                print(f"{'Serial':<20} {'Type':<10} {'State':<12} {'Model'}")
                print("-" * 60)
                for d in devices:
                    print(f"{d['serial']:<20} {d['type']:<10} {d['state']:<12} {d['model']}")
            sys.exit(0)

        if args.is_running:
            afm_obj = FridaManager(device_serial=args.device)
            if afm_obj.is_frida_server_running():
                afm_obj.logger.info("[*] frida-server is running on Android device")
            else:
                afm_obj.logger.info("[*] frida-server is not running on Android device")

            sys.exit()



        afm_obj = FridaManager(args.is_remote, args.socket, args.verbose, args.frida_install_dst, device_serial=args.device)
    else:
        afm_obj = FridaManager()

    afm_obj.install_frida_server()
    afm_obj.run_frida_server()
    result = afm_obj.is_frida_server_running()
    if result:
        afm_obj.logger.info("[*] succesfull installed and launched latest frida-server version on Android device")
    else:
        afm_obj.logger.error("[-] unable to run frida-server on Android device")


if __name__ == "__main__":
    main()
