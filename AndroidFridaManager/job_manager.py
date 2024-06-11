#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import atexit
import subprocess
import frida
from typing import Optional, Dict, Union
from .job import Job, FridaBasedException
import time
import re

class JobManager(object):
    """  A class representing the current Job manager. """


    def __init__(self,host="", enable_spawn_gating=False) -> None:
        """
            Init a new job manager. This method will also
            register an atexit(), ensuring that cleanup operations
            are performed on jobs when this class is GC'd.
        """

        self.jobs = {}
        self.is_first_job = True
        self.process_session = None
        self.host = host
        self.pid = -1
        self.device = None
        self.package_name = ""
        self.enable_spawn_gating = enable_spawn_gating
        self.first_instrumenation_script = None
        self.last_created_job = None
        self.init_last_job = False
        atexit.register(self.cleanup)


    def cleanup(self) -> None:
        """
            Clean up all of the job in the job manager.

            This method is typical called when at the end of an
            session.

            :return:
        """
        if len(self.jobs) > 0:
            print("[*] Program closed. Stopping active jobs...")
            self.stop_jobs()

        print("\n[*] Have a nice day!")
    

    def job_list(self):
        return list(self.jobs.keys())


    def running_jobs(self):
        return [job_id for job_id, job in self.jobs.items() if job.state == "running"]

    '''
    # only used for debugging
    def running_jobs2(self):
        tuple_jobs = [job for job in self.jobs.items()]
        for job_id, job in tuple_jobs:
            print(f"Job state of Job {job_id} in state {job.state}")
        return tuple_jobs
    '''

    def spawn(self, target_process):
        self.package_name = target_process
        print("[*] spawning app: "+ target_process)
        pid = self.device.spawn(target_process)
        self.process_session = self.device.attach(pid)
        print(f"Spawned {target_process} with PID {pid}")
        return pid


    def start_android_app(self, package_name: str, main_activity: Optional[str] = None, extras: Optional[Dict[str, Union[str, bool]]] = None):
        """
        Start an Android app using adb.

        :param package_name: The package name of the app.
        :param main_activity: The main activity of the app (optional).
        :param extras: A dictionary of extras to pass to the intent (optional).
        """
        if main_activity:
            self.package_name = package_name
            # Prepare the base command for starting the app with main activity
            cmd = ['adb', 'shell', 'am', 'start', '-n', f'{package_name}/{main_activity}']
            
            # Add extras if provided
            if extras:
                for key, value in extras.items():
                    if isinstance(value, bool):
                        cmd.extend(['--ez', key, 'true' if value else 'false'])
                    elif isinstance(value, str):
                        cmd.extend(['--es', key, value])
        else:
            # Command to start the app using monkey if no main activity is provided
            cmd = ['adb', 'shell', 'monkey', '-p', package_name, '-c', 'android.intent.category.LAUNCHER', '1']
        
        # Run the command and capture the output
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    
        # Extract the PID from the output
        pid = None
        if 'ThisTime' in result.stdout:
            # `am start` command includes the PID in the output
            pid_match = re.search(r'(?<=ThisTime: \d+\s)Proc=\w+,\s(\d+)', result.stdout)
            if pid_match:
                pid = int(pid_match.group(1))
        elif 'Events injected' in result.stdout:
            # `monkey` command does not provide PID directly, need to get it separately
            pid_cmd = ['adb', 'shell', 'pidof', package_name]
            pid_result = subprocess.run(pid_cmd, capture_output=True, text=True, check=True)
            if pid_result.stdout:
                pid = int(pid_result.stdout.split()[0])

        if pid is None:
            raise RuntimeError("Failed to get PID of the started app")

        return pid


    def attach_app(self, target_process, foreground=False):
        self.package_name = target_process

        if foreground:
            target_process = self.device.get_frontmost_application()
            if target_process is None or len(target_process.identifier) < 2:
                print("[-] unable to attach to the frontmost application. Aborting ...")

            target_process = target_process.identifier

        if isinstance(target_process, int):
            print(f"[*] attaching to PID: {target_process}")
            self.process_session = self.device.attach(target_process)
        else:
            print(f"[*] attaching to app: {target_process}")
            self.process_session = self.device.attach(int(target_process) if target_process.isnumeric() else target_process)

             


    def setup_frida_session(self, target_process, custom_hooking_handler_name, should_spawn=True,foreground=False):
        self.first_instrumenation_script = custom_hooking_handler_name
        self.device = self.setup_frida_handler(self.host, self.enable_spawn_gating)

        try:  
            if should_spawn:
                self.pid = self.spawn(target_process)
            else:
                self.attach_app(target_process,foreground)
        except frida.TimedOutError as te:
            raise FridaBasedException(f"TimeOutError: {te}")
        except frida.ProcessNotFoundError as pe:
            raise FridaBasedException(f"ProcessNotFoundError: {pe}")
        
    
    def init_job(self,frida_script_name, custom_hooking_handler_name):
        try:
            if self.process_session:
                job = Job(frida_script_name, custom_hooking_handler_name, self.process_session)
                job.create_job_script()
                self.init_last_job = True
                print(f"[*] created job: {job.job_id}")
                self.jobs[job.job_id] = job
                self.last_created_job = job

            else:
                print("[-] no frida session. Aborting...")

        except frida.TransportError as fe:
            raise FridaBasedException(f"Problems while attaching to frida-server: {fe}")
        except FridaBasedException as e:
            raise FridaBasedException(f"Frida based error: {e}")
        except frida.TimedOutError as te:
            raise FridaBasedException(f"TimeOutError: {te}")
        except frida.ProcessNotFoundError as pe:
            raise FridaBasedException(f"ProcessNotFoundError: {pe}")


    def run_last_created_job(self, custom_hooking_handler_name):
        try:
            if self.init_last_job:
                self.last_created_job.run_job()
                self.init_last_job = False
                if self.is_first_job:
                    self.is_first_job = False
                    self.first_instrumenation_script = custom_hooking_handler_name
                    if self.pid != -1:
                        self.device.resume(self.pid)
                        time.sleep(1) # without it Java.perform silently fails
        except Exception as fe:
            raise FridaBasedException(f"Frida-Error: {fe}")

        
    def start_job(self,frida_script_name, custom_hooking_handler_name):
        try:
            if self.process_session:
                job = Job(frida_script_name, custom_hooking_handler_name, self.process_session)
                print(f"[*] created job: {job.job_id}")
                self.jobs[job.job_id] = job
                self.last_created_job = job
                job.run_job()
                if self.is_first_job:
                    self.is_first_job = False
                    self.first_instrumenation_script = custom_hooking_handler_name
                    if self.pid != -1:
                        self.device.resume(self.pid)
                        time.sleep(1) # without it Java.perform silently fails

            else:
                print("[-] no frida session. Aborting...")

        except frida.TransportError as fe:
            raise FridaBasedException(f"Problems while attaching to frida-server: {fe}")
        except FridaBasedException as e:
            raise FridaBasedException(f"Frida based error: {e}")
        except frida.TimedOutError as te:
            raise FridaBasedException(f"TimeOutError: {te}")
        except frida.ProcessNotFoundError as pe:
            raise FridaBasedException(f"ProcessNotFoundError: {pe}")
        except KeyboardInterrupt:
            self.stop_app_with_last_job(job,self.package_name)
            pass

    
    def stop_jobs(self):
        jobs_to_stop = [job_id for job_id, job in self.jobs.items() if job.state == "running"]
        for job_id in jobs_to_stop:
            try:
                print('[job manager] Job: {0} - Stopping'.format(job_id))
                self.stop_job_with_id(job_id)
            except frida.InvalidOperationError:
                print('[job manager] Job: {0} - An error occurred stopping job. Device may '
                             'no longer be available.'.format(job_id))
    
    
    def stop_job_with_id(self,job_id):
        if job_id in self.jobs:
            job = self.jobs[job_id]
            job.close_job()
            del self.jobs[job_id]


    def get_last_created_job(self):
        if self.last_created_job:
            return self.last_created_job


    def get_job_by_id(self, job_id):
        if job_id in self.jobs:
            return self.jobs[job_id]
        else:
            raise ValueError(f"Job mit ID {job_id} nicht gefunden.")


    def detach_from_app(self):
        if self.process_session:
            self.process_session.detach()


    def stop_app(self, app_package):
        subprocess.run(["adb", "shell", "am", "force-stop", app_package])


    def stop_app_with_last_job(self, last_job, app_package):
        last_job.close_job()
        self.stop_app(app_package)
        


    def stop_app_with_closing_frida(self, app_package):
        jobs_to_stop = [job_id for job_id, job in self.jobs.items() if job.state == "running"]
        for job_id in jobs_to_stop:
            print(f"[*] trying to close job: {job_id}")
            self.stop_job_with_id(job_id)
        
        self.detach_from_app()
        subprocess.run(["adb", "shell", "am", "force-stop", app_package])


    def kill_app(self, pid):
        subprocess.run(["adb", "shell", "kill", str(pid)])

    
    def setup_frida_handler(self,host="", enable_spawn_gating=False):
        try:
            if len(host) > 4:
                # we can also use the IP address ot the target machine instead of using USB - e.g. when we have multpile AVDs
                device = frida.get_device_manager().add_remote_device(host)
            else:
                device = frida.get_usb_device()

            # to handle forks
            def on_child_added(child):
                print(f"Attached to child process with pid {child.pid}")
                self.first_instrumenation_script(device.attach(child.pid))
                device.resume(child.pid)

            # if the target process is starting another process 
            def on_spawn_added(spawn):
                print(f"Process spawned with pid {spawn.pid}. Name: {spawn.identifier}")
                self.first_instrumenation_script(device.attach(spawn.pid))
                device.resume(spawn.pid)

            device.on("child_added", on_child_added)
            if enable_spawn_gating:
                device.enable_spawn_gating()
                device.on("spawn_added", on_spawn_added)
            
            return device

        except frida.InvalidArgumentError:
            raise FridaBasedException("Unable to find device")
        except frida.ServerNotRunningError:
            raise FridaBasedException("Frida server not running. Start frida-server and try it again.")
