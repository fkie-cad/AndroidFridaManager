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

# some parts are taken from ttps://github.com/Mind0xP/Frida-Python-Binding/

class FridaAndroidManager():

    def __init__(self, install_latest_frida_server=False ,verbose=False):
        self.verbose = verbose
        self.install_latest_frida_server = install_latest_frida_server
        self._setup_logging()
        self.logger = logging.getLogger(__name__)


    def _setup_logging(self):
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



    def install_frida_server(self):
        with tempfile.TemporaryDirectory() as dir:
            self.logger.info(f"[*] downloading frida-server to {dir}")
            file_path = self.download_frida_server(dir)
            tmp_frida_server = self.extract_frida_server_comp(file_path)
            # ensure's that we always overwrite the current installation with our recent downloaded version
            self.adb_remove_file_if_exist("/data/local/tmp/frida-server")
            self._adb_push_file(tmp_frida_server,"/data/local/tmp/")


    # by default the latest frida-server version will be downloaded
    def download_frida_server(self, path, version="latest"):
        url = self.get_frida_server_for_android_url(version)
        with open(path+"/frida-server","wb") as fsb:
            res = requests.get(url)
            fsb.write(res.content)
            self.logger.info(f"[*] writing frida-server to {path}")

        return path+"/frida-server"



    def extract_frida_server_comp(self, file_path):
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
        url = "https://api.github.com/repos/frida/frida/releases/"+version
        try:
            res = requests.get(url)
        except requests.exceptions.TooManyRedirects:
            # invalid version therfore set to latest 
            url = "https://api.github.com/repos/frida/frida/releases/latest"
            res = requests(url)
        except requests.exceptions.RequestException as e:
            print("[-] error in doing requests: "+e)
            exit(2)

        frida_server_path = re.findall(r'\/download\/\d+\.\d+\.\d+\/frida\-server\-\d+\.\d+\.\d+\-android\-'+arch+'\.xz',res.text)
        final_url = frida_download_prefix + frida_server_path[0]

        if self.verbose:
            print(f"[*] frida-server download url: {final_url}")

        return final_url
 

    def run_adb_command_as_root(self,command):
        if self.adb_check_root() == False:
            print("[-] none rooted device. Please root it before using FridaAndroidManager and ensure that you are able to run commands with the su-binary....")
            exit(2)
        output = subprocess.run(['adb', 'shell','su 0 '+command], capture_output=True, text=True)
        return output


    def _adb_push_file(self,file,dst):
        output = subprocess.run(['adb', 'push',file,dst], capture_output=True, text=True)
        return output

    
    def _adb_pull_file(self,src_file,dst):
        output = subprocess.run(['adb', 'pull',src_file,dst], capture_output=True, text=True)
        return output
    

    def _get_android_device_arch(self):
        frida_usb_json_data = frida.get_usb_device().query_system_parameters()
        return frida_usb_json_data['arch']
    
    
    def _adb_make_binary_executable(self, path):
        output = self.run_adb_command_as_root("chmod +x "+path)


    def adb_does_file_exist(self,path):
        output = self.run_adb_command_as_root("ls "+path)
        if len(output.stderr) > 1:
            return False
        else:
            return True
          


    def adb_check_root(self):
        return bool(subprocess.run(['adb', 'shell','su 0 id -u'], capture_output=True, text=True).stdout)


    def adb_remove_file_if_exist(self, path="/data/local/tmp/frida-server"):
        if self.adb_does_file_exist(path):
            output = self.run_adb_command_as_root("rm "+path)

# only there in order to do some tests will be removed soon
if __name__ == "__main__":
    afm_obj = FridaAndroidManager()
    afm_obj.install_frida_server()
    result = afm_obj.adb_does_file_exist("/data/local/tmp/frida-server")
    print(result)
