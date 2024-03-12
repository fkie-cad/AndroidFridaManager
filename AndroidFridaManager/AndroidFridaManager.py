#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import os
import sys 
import logging
from colorlog import ColoredFormatter
import subprocess
import requests
import lzma
import re
from shutil import copyfile
import tempfile
import argparse

# some parts are taken from ttps://github.com/Mind0xP/Frida-Python-Binding/

class FridaManager():

    def __init__(self, is_remote=False, socket="", verbose=False, frida_install_dst="/data/local/tmp/"):
        """
        Constructor of the current FridaManager instance

        :param is_remote: The number to multiply.
        :type number: bool
        :param socket: The socket to connect to the remote device. The remote device needs to be set by <ip:port>. By default this string will be empty in order to indicate that FridaManger is working with the first connected USB device.
        :type number: string
        :param verbose: Set the output to verbose, so that the logging information gets printed. By default set to False.
        :type number: bool
        :param frida_install_dst: The path where the frida server should be installed. By default it will be installed to /data/local/tmp/.
        :type number: bool

        """
        self.is_remote = is_remote
        self.device_socket = socket
        self.verbose = verbose
        self.is_magisk_mode = False
        self.frida_install_dst = frida_install_dst
        self._setup_logging()
        self.logger = logging.getLogger(__name__)

        if self.is_remote:
            frida.get_device_manager().add_remote_device(self.socket)


    def _setup_logging(self):
        """
        Setup logging for the current instance of FridaManager 

        """
        logger = logging.getLogger()
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



    
    def run_frida_server(self, frida_server_path="/data/local/tmp/"):
        if frida_server_path is self.run_frida_server.__defaults__[0]:
            cmd = self.frida_install_dst + "frida-server &"
        else:
            cmd = frida_server_path + "frida-server &"

        if self.is_magisk_mode:
            command = "adb shell su -c " + cmd
        else:
            command = "adb shell su 0 "+ cmd 

        subprocess.Popen(command, shell=True)


    def is_frida_server_running(self):
        """
        Checks if on the connected device a frida server is running. 
        The test is done by the Android system command pidof and is looking for the string frida-server.

        :return: True if a frida-server is running otherwise False.
        :rtype: bool
        """
        result = self.run_adb_command_as_root("/system/bin/pidof frida-server")
        if len(result.stdout) > 1:
            return True
        else:
            return False


    def stop_frida_server(self):
        self.run_adb_command_as_root("/system/bin/killall frida-server")


    def remove_frida_server(self, frida_server_path="/data/local/tmp/"):
        if frida_server_path is self.remove_frida_server.__defaults__[0]:
            cmd = self.frida_install_dst + "frida-server"
        else:
            cmd = frida_server_path + "frida-server"
        
        self.stop_frida_server()
        self._adb_remove_file_if_exist(cmd)


    def install_frida_server(self, dst_dir="/data/local/tmp/", version="latest"):
        """
        Install the frida server binary on the Android device. 
        This includes downloading the frida-server, decompress it and pushing it to the Android device.
        By default it is pushed into the /data/local/tmp/ directory.
        Further the binary will be set to executable in order to run it.

        :param dst_dir: The destination folder where the frida-server binary should be installed (pushed). 
        :type number: string
        :param version: The version. By default the latest version will be used.
        :type number: string

        """
        if dst_dir is self.install_frida_server.__defaults__[0]:
            frida_dir = self.frida_install_dst
        else:
            frida_dir = dst_dir

        with tempfile.TemporaryDirectory() as dir:
            if self.verbose:
                self.logger.info(f"[*] downloading frida-server to {dir}")
            file_path = self.download_frida_server(dir,version)
            tmp_frida_server = self.extract_frida_server_comp(file_path)
            # ensure's that we always overwrite the current installation with our recent downloaded version
            self._adb_remove_file_if_exist(frida_dir + "frida-server")
            self._adb_push_file(tmp_frida_server,frida_dir)
            self.make_frida_server_executable()


    # by default the latest frida-server version will be downloaded
    def download_frida_server(self, path, version="latest"):
        """
        Downloads a frida server. By default the latest version is used.
        If you want to download a specific version you have to provide it trough the version parameter.

        :param path: The path where the compressed frida-server should be downloded.
        :type number: string
        :param version: The version. By default the latest version will be used.
        :type number: string

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
        arch_str = "x86"

        if arch == "arm64":
            arch_str = "arm64"
        elif arch == "arm":
            arch_str = "arm"
        elif arch == "ia32":
            arch_str = "x86"
        elif arch == "x64":
            arch_str == "x86_64"
        else:
            arch_str = "x86"

        download_url = self._get_frida_server_donwload_url(arch_str,version)
        return download_url


    def _get_frida_server_donwload_url(self, arch, version):
        frida_download_prefix = "https://github.com/frida/frida/releases"

        if version is "latest":
            url = "https://api.github.com/repos/frida/frida/releases/"+version
        
            try:
                res = requests.get(url)
            except requests.exceptions.RequestException as e:
                print("[-] error in doing requests: "+e)
                exit(2)

            frida_server_path = re.findall(r'\/download\/\d+\.\d+\.\d+\/frida\-server\-\d+\.\d+\.\d+\-android\-'+arch+'\.xz',res.text)
            final_url = frida_download_prefix + frida_server_path[0]

        else:
            final_url = "https://github.com/frida/frida/releases/download/"+ version +"/frida-server-"+version+"-android-"+arch+".xz"


        if self.verbose:
            print(f"[*] frida-server download url: {final_url}")

        return final_url


    def make_frida_server_executable(self, frida_server_path="/data/tmp/local/tmp/"):
        if frida_server_path is self.make_frida_server_executable.__defaults__[0]:
            cmd = self.frida_install_dst + "frida-server"
        else:
            cmd = frida_server_path + "frida-server"

        self.run_adb_command_as_root(f"chmod +x {cmd}")
 


    ### some functions to work with adb ### 


    def run_adb_command_as_root(self,command):
        if self.adb_check_root() == False:
            print("[-] none rooted device. Please root it before using FridaAndroidManager and ensure that you are able to run commands with the su-binary....")
            exit(2)

        if self.is_magisk_mode:
            output = subprocess.run(['adb', 'shell','su -c '+command], capture_output=True, text=True)
        else:
            output = subprocess.run(['adb', 'shell','su 0 '+command], capture_output=True, text=True)

        return output


    def _adb_push_file(self,file,dst):
        output = subprocess.run(['adb', 'push',file,dst], capture_output=True, text=True)
        return output

    
    def _adb_pull_file(self,src_file,dst):
        output = subprocess.run(['adb', 'pull',src_file,dst], capture_output=True, text=True)
        return output
    

    def _get_android_device_arch(self):
        if self.is_remote:
            frida_usb_json_data = frida.get_remote_device().query_system_parameters() 
        else:
            frida_usb_json_data = frida.get_usb_device().query_system_parameters()
        return frida_usb_json_data['arch']
    
    
    def _adb_make_binary_executable(self, path):
        output = self.run_adb_command_as_root("chmod +x "+path)


    def _adb_does_file_exist(self,path):
        output = self.run_adb_command_as_root("ls "+path)
        if len(output.stderr) > 1:
            return False
        else:
            return True
          


    def adb_check_root(self):
        if bool(subprocess.run(['adb', 'shell','su -v'], capture_output=True, text=True).stdout):
            self.is_magisk_mode = True
            return True

        return bool(subprocess.run(['adb', 'shell','su 0 id -u'], capture_output=True, text=True).stdout)


    def _adb_remove_file_if_exist(self, path="/data/local/tmp/frida-server"):
        if self._adb_does_file_exist(path):
            output = self.run_adb_command_as_root("rm "+path)



if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description='FridaManager initialization parameters.')
        
        parser.add_argument('--is_remote', type=lambda x: (str(x).lower() == 'true'), default=False, help='Whether to use Frida in remote mode. Default is False.')
        parser.add_argument('--socket', type=str, default="", help='Socket to use for the connection. Expected in the format <ip:port>.')
        parser.add_argument('--verbose', action='store_true', default=False, help='Enable verbose output. Default is False.')
        parser.add_argument('--frida_install_dst', type=str, default="/data/local/tmp/", help='Frida installation destination. Default is "/data/local/tmp/".')
        parser.add_argument('-r','--is_running', type=bool, default=False, help='Checks only if frida-server is running on the Android device or not.')

        args = parser.parse_args()

        if args.is_running:
            afm_obj = FridaManager()
            if afm_obj.is_frida_server_running():
                print("[*] frida-server is running on Android device")
            else:
                print("[*] frida-server is not running on Android device")

            sys.exit()



        afm_obj = FridaManager(args.is_remote, args.socket, args.verbose, args.frida_install_dst)
    else:
        afm_obj = FridaManager()

    afm_obj.install_frida_server()
    result = afm_obj.is_frida_server_running()
    if result:
        print("[*] succesfull installed and launched latest frida-server version on Android device")
    else:
        print("[-] unable to run frida-server on Android device")

