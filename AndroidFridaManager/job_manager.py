#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Frida JobManager for coordinating multiple instrumentation jobs.

This module provides the JobManager class for managing Frida sessions and
coordinating multiple instrumentation jobs on Android devices.
"""

import atexit
import subprocess
import frida
from typing import Optional, Dict, Union, List, Callable
from .job import Job, FridaBasedException
import time
import re
import logging


class JobManager(object):
    """Job manager with multi-device support and hook coordination.

    Manages Frida sessions and coordinates multiple instrumentation jobs,
    providing hook conflict detection and session status information.

    Attributes:
        jobs: Dictionary of active jobs by job_id.
        process_session: Current Frida session.
        device: Current Frida device.
        package_name: Name of the attached/spawned package.
        pid: Process ID (-1 if attach mode).
    """

    def __init__(self, host="", enable_spawn_gating=False, device_serial: Optional[str] = None) -> None:
        """Init a new job manager with optional device targeting.

        Args:
            host: Remote host for Frida connection (ip:port format).
            enable_spawn_gating: Enable spawn gating for child process tracking.
            device_serial: Specific device serial to target (e.g., 'emulator-5554').
                          If None, uses default device selection.
        """
        self.jobs: Dict[str, Job] = {}
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
        self.logger = logging.getLogger(__name__)
        self._ensure_logging_setup()

        # Multi-device support
        self._device_serial = device_serial
        self._multiple_devices = self._check_multiple_devices()

        # Hook coordination (NEW)
        self._hook_registry: Dict[str, str] = {}  # hook_target -> job_id
        self._mode: Optional[str] = None  # "spawn" or "attach"
        self._paused: bool = False  # Track if spawned process is paused

        atexit.register(self.cleanup)

    def _ensure_logging_setup(self):
        """
        Ensure basic logging setup if not already configured.
        This provides a fallback for when JobManager is used independently.
        """
        root_logger = logging.getLogger()
        if not root_logger.handlers:
            # Set up basic logging if no handlers exist
            root_logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(asctime)s] [%(levelname)-4s] - %(message)s',
                                        datefmt='%d-%m-%y %H:%M:%S')
            handler.setFormatter(formatter)
            root_logger.addHandler(handler)

    def _check_multiple_devices(self) -> bool:
        """Check if multiple devices are connected."""
        try:
            result = subprocess.run(
                ['adb', 'devices'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Count device lines (skip header)
            device_count = sum(
                1 for line in result.stdout.strip().split('\n')[1:]
                if line.strip() and '\tdevice' in line
            )
            return device_count > 1
        except Exception:
            return False

    def _build_adb_command(self, args: List[str]) -> List[str]:
        """
        Build ADB command with device targeting if needed.

        :param args: ADB command arguments (without 'adb' prefix)
        :return: Complete command list including device targeting
        """
        cmd = ['adb']
        if self._device_serial and self._multiple_devices:
            cmd.extend(['-s', self._device_serial])
        cmd.extend(args)
        return cmd

    @property
    def device_serial(self) -> Optional[str]:
        """Get the current target device serial."""
        return self._device_serial

    @device_serial.setter
    def device_serial(self, serial: str) -> None:
        """Set the target device serial."""
        self._device_serial = serial
        self._multiple_devices = self._check_multiple_devices()

    def cleanup(self) -> None:
        """
            Clean up all of the job in the job manager.

            This method is typical called when at the end of an
            session.

            :return:
        """
        if len(self.jobs) > 0:
            self.logger.info("[*] Program closed. Stopping active jobs...")
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
            self.logger.debug(f"Job state of Job {job_id} in state {job.state}")
        return tuple_jobs
    '''

    def spawn(self, target_process):
        """Spawn a new process and attach to it.

        Args:
            target_process: Package name to spawn.

        Returns:
            Process ID of the spawned process.
        """
        self._mode = "spawn"
        self.package_name = target_process
        self.logger.info("[*] spawning app: "+ target_process)
        pid = self.device.spawn(target_process)
        self.process_session = self.device.attach(pid)
        self.pid = pid
        self._paused = True  # Spawned processes start paused
        self.logger.info(f"Spawned {target_process} with PID {pid}")
        return pid

    def spawn_paused(self, target_process: str) -> int:
        """Spawn a process but keep it paused for multi-tool loading.

        Unlike the regular spawn flow where resume happens on first job,
        this method keeps the process paused until explicitly resumed
        via resume_app(). This allows loading multiple Jobs before
        the app starts executing.

        Args:
            target_process: Package name to spawn.

        Returns:
            Process ID of the spawned (paused) process.
        """
        self._mode = "spawn"
        self.package_name = target_process
        self.logger.info(f"[*] spawning app (paused): {target_process}")
        pid = self.device.spawn(target_process)
        self.process_session = self.device.attach(pid)
        self.pid = pid
        self._paused = True
        # Mark that auto-resume should NOT happen
        self.is_first_job = False  # Prevent auto-resume in start_job()
        self.logger.info(f"Spawned {target_process} with PID {pid} (PAUSED - awaiting manual resume)")
        return pid

    def resume_app(self) -> bool:
        """Resume a paused spawned process.

        Call this after loading all Jobs to start the app with
        all hooks already installed.

        Returns:
            True if resumed successfully, False if not paused or failed.
        """
        if not self._paused or self.pid == -1:
            self.logger.warning("No paused process to resume")
            return False

        try:
            self.device.resume(self.pid)
            self._paused = False
            time.sleep(1)  # Required for Java.perform stability
            self.logger.info(f"Resumed process {self.pid}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to resume process: {e}")
            return False

    def is_paused(self) -> bool:
        """Check if the spawned process is currently paused.

        Returns:
            True if process is spawned and waiting for resume.
        """
        return self._paused

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
            cmd = self._build_adb_command(['shell', 'am', 'start', '-n', f'{package_name}/{main_activity}'])

            # Add extras if provided
            if extras:
                for key, value in extras.items():
                    if isinstance(value, bool):
                        cmd.extend(['--ez', key, 'true' if value else 'false'])
                    elif isinstance(value, str):
                        cmd.extend(['--es', key, value])
        else:
            # Command to start the app using monkey if no main activity is provided
            cmd = self._build_adb_command(['shell', 'monkey', '-p', package_name, '-c', 'android.intent.category.LAUNCHER', '1'])

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
            pid_cmd = self._build_adb_command(['shell', 'pidof', package_name])
            pid_result = subprocess.run(pid_cmd, capture_output=True, text=True, check=True)
            if pid_result.stdout:
                pid = int(pid_result.stdout.split()[0])

        if pid is None:
            raise RuntimeError("Failed to get PID of the started app")

        return pid


    def attach_app(self, target_process, foreground=False):
        """Attach to a running process.

        Args:
            target_process: Package name or PID to attach to.
            foreground: If True, attach to the frontmost application.
        """
        self._mode = "attach"
        self.package_name = target_process

        if foreground:
            target_process = self.device.get_frontmost_application()
            if target_process is None or len(target_process.identifier) < 2:
                self.logger.error("[-] unable to attach to the frontmost application. Aborting ...")

            target_process = target_process.identifier

        if isinstance(target_process, int):
            self.logger.info(f"[*] attaching to PID: {target_process}")
            self.process_session = self.device.attach(target_process)
        else:
            self.logger.info(f"[*] attaching to app: {target_process}")
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
                self.logger.info(f"[*] created job: {job.job_id}")
                self.jobs[job.job_id] = job
                self.last_created_job = job

            else:
                self.logger.error("[-] no frida session. Aborting...")

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


    def start_job(
        self,
        frida_script_name: str,
        custom_hooking_handler_name: Callable,
        job_type: str = "custom",
        display_name: Optional[str] = None,
        hooks_registry: Optional[List[str]] = None,
        priority: int = 50,
    ) -> Optional[Job]:
        """Start a new instrumentation job.

        Args:
            frida_script_name: Path to the Frida script file.
            custom_hooking_handler_name: Callback for handling Frida messages.
            job_type: Category of job (e.g., "fritap", "dexray", "trigdroid").
            display_name: Human-readable name for UI display.
            hooks_registry: List of hooked methods for conflict detection.
            priority: Job priority (lower = higher priority).

        Returns:
            The created Job instance, or None if no session exists.

        Raises:
            FridaBasedException: If Frida encounters an error.
        """
        job = None  # Initialize before try block for safe exception handling
        try:
            if self.process_session:
                job = Job(
                    frida_script_name,
                    custom_hooking_handler_name,
                    self.process_session,
                    job_type=job_type,
                    display_name=display_name,
                    hooks_registry=hooks_registry,
                    priority=priority,
                )
                self.logger.info(f"[*] created job: {job.job_id} ({job.display_name})")
                self.jobs[job.job_id] = job
                self.last_created_job = job
                job.run_job()
                if self.is_first_job:
                    self.is_first_job = False
                    self.first_instrumenation_script = custom_hooking_handler_name
                    if self.pid != -1:
                        self.device.resume(self.pid)
                        self._paused = False  # Mark as resumed
                        time.sleep(1)  # without it Java.perform silently fails

                return job

            else:
                self.logger.error("[-] no frida session. Aborting...")
                return None

        except frida.TransportError as fe:
            raise FridaBasedException(f"Problems while attaching to frida-server: {fe}")
        except FridaBasedException as e:
            raise FridaBasedException(f"Frida based error: {e}")
        except frida.TimedOutError as te:
            raise FridaBasedException(f"TimeOutError: {te}")
        except frida.ProcessNotFoundError as pe:
            raise FridaBasedException(f"ProcessNotFoundError: {pe}")
        except KeyboardInterrupt:
            if job:
                self.stop_app_with_last_job(job, self.package_name)
            return None


    def stop_jobs(self, timeout_per_job: float = 3.0) -> dict:
        """Stop all running jobs.

        Args:
            timeout_per_job: Maximum seconds to wait per job.

        Returns:
            Dictionary mapping job_id to success status.
        """
        results = {}
        jobs_to_stop = [job_id for job_id, job in self.jobs.items() if job.state == "running"]

        for job_id in jobs_to_stop:
            try:
                self.logger.info(f'[job manager] Job: {job_id} - Stopping')
                results[job_id] = self.stop_job_with_id(job_id, timeout=timeout_per_job)
            except frida.InvalidOperationError:
                self.logger.error(f'[job manager] Job: {job_id} - Error stopping')
                results[job_id] = False

        return results


    def stop_job_with_id(self, job_id: str, timeout: float = 5.0) -> bool:
        """Stop a specific job by ID.

        Args:
            job_id: UUID of the job to stop.
            timeout: Maximum seconds to wait for job to stop.

        Returns:
            True if job stopped cleanly, False if timed out or not found.
        """
        if job_id not in self.jobs:
            return False

        job = self.jobs[job_id]
        # Unregister hooks before closing
        self.unregister_hooks(job_id)
        success = job.close_job(timeout=timeout)
        del self.jobs[job_id]
        return success


    def get_last_created_job(self):
        if self.last_created_job:
            return self.last_created_job


    def get_job_by_id(self, job_id):
        if job_id in self.jobs:
            return self.jobs[job_id]
        else:
            raise ValueError(f"Job with ID {job_id} not found.")


    def detach_from_app(self, timeout: float = 3.0) -> bool:
        """Detach from the current app session.

        Args:
            timeout: Maximum seconds to wait for detach.

        Returns:
            True if detached successfully, False if timed out or failed.
        """
        if not self.process_session:
            return True

        import concurrent.futures

        def _detach():
            self.process_session.detach()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_detach)
                future.result(timeout=timeout)
            self.process_session = None
            return True
        except concurrent.futures.TimeoutError:
            self.logger.warning(f"Detach timed out after {timeout}s")
            self.process_session = None  # Clear anyway to avoid reuse
            return False
        except Exception as e:
            self.logger.warning(f"Detach failed: {e}")
            self.process_session = None
            return False


    def stop_app(self, app_package):
        cmd = self._build_adb_command(["shell", "am", "force-stop", app_package])
        subprocess.run(cmd)


    def stop_app_with_last_job(self, last_job, app_package):
        last_job.close_job()
        self.stop_app(app_package)



    def stop_app_with_closing_frida(self, app_package):
        jobs_to_stop = [job_id for job_id, job in self.jobs.items() if job.state == "running"]
        for job_id in jobs_to_stop:
            self.logger.info(f"[*] trying to close job: {job_id}")
            self.stop_job_with_id(job_id)

        self.detach_from_app()
        cmd = self._build_adb_command(["shell", "am", "force-stop", app_package])
        subprocess.run(cmd)


    def kill_app(self, pid):
        cmd = self._build_adb_command(["shell", "kill", str(pid)])
        subprocess.run(cmd)


    def setup_frida_handler(self, host="", enable_spawn_gating=False):
        """
        Setup the Frida device handler with multi-device support.

        :param host: Remote host for Frida connection
        :param enable_spawn_gating: Enable spawn gating
        :return: Frida Device object
        """
        try:
            if len(host) > 4:
                # Remote device connection
                device = frida.get_device_manager().add_remote_device(host)
            elif self._device_serial:
                # Multi-device: Get specific device by serial
                try:
                    device = frida.get_device(self._device_serial)
                except frida.InvalidArgumentError:
                    # Fallback: enumerate and find by ID
                    device = None
                    for d in frida.enumerate_devices():
                        if d.id == self._device_serial:
                            device = d
                            break
                    if device is None:
                        raise FridaBasedException(f"Frida device '{self._device_serial}' not found")
            else:
                # Single device: Use USB device
                device = frida.get_usb_device()

            # to handle forks
            def on_child_added(child):
                self.logger.info(f"Attached to child process with pid {child.pid}")
                if callable(self.first_instrumenation_script):
                    self.first_instrumenation_script(device.attach(child.pid))
                device.resume(child.pid)

            # if the target process is starting another process
            def on_spawn_added(spawn):
                self.logger.info(f"Process spawned with pid {spawn.pid}. Name: {spawn.identifier}")
                if callable(self.first_instrumenation_script):
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

    # ==================== Hook Coordination Methods ====================

    def register_hooks(self, job_id: str, hooks: List[str]) -> List[str]:
        """Register hooks for a job and detect conflicts.

        Args:
            job_id: UUID of the job registering hooks.
            hooks: List of hook targets (method names, function signatures).

        Returns:
            List of conflicting hooks that are already registered by other jobs.
        """
        conflicts = []
        for hook in hooks:
            if hook in self._hook_registry:
                existing_job_id = self._hook_registry[hook]
                if existing_job_id != job_id:
                    conflicts.append(hook)
                    self.logger.warning(
                        f"Hook conflict: '{hook}' already registered by job {existing_job_id[:8]}"
                    )
            else:
                self._hook_registry[hook] = job_id

        if conflicts:
            self.logger.warning(
                f"Job {job_id[:8]} has {len(conflicts)} hook conflict(s)"
            )

        return conflicts

    def unregister_hooks(self, job_id: str) -> None:
        """Remove all hooks registered by a job.

        Args:
            job_id: UUID of the job whose hooks should be removed.
        """
        hooks_to_remove = [
            hook for hook, jid in self._hook_registry.items() if jid == job_id
        ]
        for hook in hooks_to_remove:
            del self._hook_registry[hook]

        if hooks_to_remove:
            self.logger.debug(
                f"Unregistered {len(hooks_to_remove)} hooks for job {job_id[:8]}"
            )

    def check_hook_conflicts(self, hooks: List[str]) -> Dict[str, str]:
        """Check for potential conflicts before registering hooks.

        Args:
            hooks: List of hook targets to check.

        Returns:
            Dictionary mapping conflicting hooks to their owning job IDs.
        """
        return {
            hook: self._hook_registry[hook]
            for hook in hooks
            if hook in self._hook_registry
        }

    def get_hook_registry(self) -> Dict[str, str]:
        """Get a copy of the current hook registry.

        Returns:
            Dictionary mapping hook targets to job IDs.
        """
        return self._hook_registry.copy()

    # ==================== Session Info Methods ====================

    def has_active_session(self) -> bool:
        """Check if there's an active Frida session.

        Returns:
            True if a session is active, False otherwise.
        """
        return self.process_session is not None

    def get_session_info(self) -> Dict[str, any]:
        """Get current session information for UI display.

        Returns:
            Dictionary containing session state information.
        """
        return {
            "package": self.package_name,
            "pid": self.pid,
            "mode": self._mode or ("spawn" if self.pid != -1 else "attach"),
            "device_serial": self._device_serial,
            "has_session": self.process_session is not None,
            "job_count": len(self.jobs),
            "running_job_count": len(self.running_jobs()),
        }

    def get_running_jobs_info(self) -> List[Dict[str, any]]:
        """Get information about running jobs for UI display.

        Returns:
            List of dictionaries containing job information.
        """
        return [
            job.get_info()
            for job in self.jobs.values()
            if job.state == "running"
        ]

    def get_all_jobs_info(self) -> List[Dict[str, any]]:
        """Get information about all jobs (running and stopped).

        Returns:
            List of dictionaries containing job information.
        """
        return [job.get_info() for job in self.jobs.values()]

    @property
    def mode(self) -> Optional[str]:
        """Get the current session mode ('spawn' or 'attach')."""
        return self._mode

    def reset_session(self, timeout_per_job: float = 2.0, detach_timeout: float = 2.0) -> None:
        """Reset the session state for a new connection.

        Args:
            timeout_per_job: Max seconds to wait per job when stopping.
            detach_timeout: Max seconds to wait for session detach.
        """
        # Stop all running jobs with timeout
        self.stop_jobs(timeout_per_job=timeout_per_job)

        # Clear hook registry
        self._hook_registry.clear()

        # Detach from app with timeout
        self.detach_from_app(timeout=detach_timeout)

        # Reset state
        self.process_session = None
        self.pid = -1
        self.package_name = ""
        self._mode = None
        self.is_first_job = True
        self.last_created_job = None
        self.init_last_job = False

        self.logger.info("[*] Session reset complete")
