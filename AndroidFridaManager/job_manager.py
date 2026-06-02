#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Frida JobManager for coordinating multiple instrumentation jobs.

This module provides the JobManager class for managing Frida sessions and
coordinating multiple instrumentation jobs on Android devices.
"""

import atexit
import concurrent.futures
import frida
import json
import os
import shlex
import tempfile
import uuid
from typing import Optional, Dict, Union, List, Callable, Tuple
from .job import Job, FridaBasedException
from .adb import ADB
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

    def __init__(self, host="", enable_spawn_gating=False, device_serial: Optional[str] = None, adb: Optional["ADB"] = None) -> None:
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
        self.first_instrumentation_script = None
        self.last_created_job = None
        self.init_last_job = False
        self.logger = logging.getLogger(__name__)
        self._ensure_logging_setup()

        # ADB wrapper
        self.adb = adb if adb is not None else ADB.find(device_id=device_serial)
        self._device_serial = self.adb.device_id

        # Hook coordination (NEW)
        self._hook_registry: Dict[str, str] = {}  # hook_target -> job_id
        self._mode: Optional[str] = None  # "spawn" or "attach"
        self._paused: bool = False  # Track if spawned process is paused

        # Bundle coordination: bundle_id -> bundle record. A bundle is a set of
        # named hook-sets loaded under one opaque, stable id (see start_bundle).
        self._bundles: Dict[str, dict] = {}

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

    @property
    def device_serial(self) -> Optional[str]:
        """Get the current target device serial."""
        return self._device_serial

    @device_serial.setter
    def device_serial(self, serial: str) -> None:
        self.adb = ADB.find(device_id=serial)
        self._device_serial = serial

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

        self.logger.info("[*] Have a nice day!")


    def job_list(self):
        return list(self.jobs.keys())


    def running_jobs(self):
        return [job_id for job_id, job in self.jobs.items() if job.state == "running"]

    def spawn(self, target_process):
        """Spawn a new process and attach to it.

        Args:
            target_process: Package name to spawn.

        Returns:
            Process ID of the spawned process.
        """
        self._mode = "spawn"
        self.package_name = target_process
        # Lazily set up the Frida device handler if a caller reached spawn()
        # without going through setup_frida_session() (e.g. spawn_paused()
        # for multi-tool loading). No-op on the normal path, where
        # setup_frida_session() already assigned self.device.
        if self.device is None:
            self.device = self.setup_frida_handler(self.host, self.enable_spawn_gating)
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
        pid = self.spawn(target_process)
        self.is_first_job = False  # Prevent auto-resume in start_job()
        self.logger.info(
            f"Spawned {target_process} with PID {pid} "
            "(PAUSED - will resume after hooks load)"
        )
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

    def mark_resumed(self) -> None:
        """Mark a previously-paused spawned process as resumed.

        The explicit-resume path (a caller invoking ``device.resume(pid)``
        directly to preserve a ProcessNotFoundError diagnostic, rather than
        :meth:`resume_app`) bypasses the flag flip that ``resume_app`` and the
        ``auto_resume`` branch of :meth:`start_job` perform. Calling this after
        such a resume keeps :meth:`is_paused` truthful, so later live bundle
        operations don't mistake a running process for a paused one.
        """
        self._paused = False

    def start_android_app(self, package_name: str, main_activity: Optional[str] = None, extras: Optional[Dict[str, Union[str, bool]]] = None):
        """
        Start an Android app using adb.

        :param package_name: The package name of the app.
        :param main_activity: The main activity of the app (optional).
        :param extras: A dictionary of extras to pass to the intent (optional).
        """
        if main_activity:
            self.package_name = package_name
            cmd_parts = f"am start -n {package_name}/{main_activity}"

            if extras:
                for key, value in extras.items():
                    if isinstance(value, bool):
                        cmd_parts += f" --ez {shlex.quote(key)} {'true' if value else 'false'}"
                    elif isinstance(value, str):
                        cmd_parts += f" --es {shlex.quote(key)} {shlex.quote(value)}"

            result = self.adb.shell(cmd_parts, timeout=10)
        else:
            result = self.adb.shell(f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1", timeout=10)

        # Extract the PID from the output
        pid = None
        if 'ThisTime' in result.stdout:
            pid_match = re.search(r'(?<=ThisTime: \d+\s)Proc=\w+,\s(\d+)', result.stdout)
            if pid_match:
                pid = int(pid_match.group(1))
        elif 'Events injected' in result.stdout:
            pid_result = self.adb.shell(f"pidof {package_name}")
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
            self.process_session = self.device.attach(
                int(target_process) if target_process.isnumeric() else target_process
            )



    def setup_frida_session(self, target_process, custom_hooking_handler_name, should_spawn=True, foreground=False):
        """Set up a Frida session for instrumenting a target process.

        Args:
            target_process: Package name to spawn or PID to attach to.
            custom_hooking_handler_name: Callback for handling Frida messages.
            should_spawn: If True, spawn the process; if False, attach to existing.
            foreground: If True, attach to the frontmost application.
        """
        self.first_instrumentation_script = custom_hooking_handler_name
        self.device = self.setup_frida_handler(self.host, self.enable_spawn_gating)

        try:
            if should_spawn:
                self.pid = self.spawn(target_process)
            else:
                self.attach_app(target_process, foreground)
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
                    self.first_instrumentation_script = custom_hooking_handler_name
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
        auto_resume: bool = True,
    ) -> Optional[Job]:
        """Start a new instrumentation job.

        Args:
            frida_script_name: Path to the Frida script file.
            custom_hooking_handler_name: Callback for handling Frida messages.
            job_type: Category of job (e.g., "fritap", "dexray", "trigdroid").
            display_name: Human-readable name for UI display.
            hooks_registry: List of hooked methods for conflict detection.
            priority: Job priority (lower = higher priority).
            auto_resume: When True (default, byte-identical legacy behavior),
                resume the spawned process right after its first job is
                created. Pass False to keep the process paused after loading
                this job so callers can stack several jobs on a freshly
                spawned (paused) session and resume exactly once when all
                hooks are loaded -- avoiding a hardened app running with only
                a partial bypass set installed.

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
                    self.first_instrumentation_script = custom_hooking_handler_name
                    # Only auto-resume when the caller wants it. Deferring the
                    # resume (auto_resume=False) lets a caller stack multiple
                    # jobs on a paused spawn and resume once, after every hook
                    # set is loaded.
                    if auto_resume and self.pid != -1:
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


    # ==================== Bundle Management ====================
    #
    # A "bundle" is a set of named hook-sets (scripts) loaded under one opaque,
    # stable ``bundle_id``. The caller hands AFM a *declarative* set of
    # ``(label, source)`` pairs and AFM picks the load strategy — so the
    # workaround for the upstream frida-java-bridge #218 / frida #1712 crash
    # (loading a 2nd script on a PAUSED spawn SIGSEGVs the agent, because each
    # script gets its own Java bridge and they collide before resume) lives
    # entirely here:
    #
    #   * PAUSED session  -> concatenate every source into ONE merged script
    #     (each wrapped in a try/catch IIFE that reports failures via
    #     ``send({merge_error: <label>})``) and load it as a single job, so all
    #     hooks install before the single resume and #218 never fires.
    #   * LIVE session     -> load each source as its own job (multi-script on a
    #     running process is safe), so toggling one hook-set never blinks the
    #     others off.
    #
    # The day frida fixes #218, the merge can be dropped here with zero churn
    # for callers. The bundle_id is stable across update_bundle() calls so the
    # caller's TaskService entry and message handler never need to be rebound.

    #: Max seconds to wait for a bundle job's script to finish loading.
    BUNDLE_READINESS_TIMEOUT = 15.0

    def start_bundle(
        self,
        scripts: List[Tuple[str, str]],
        custom_hooking_handler_name: Callable,
        *,
        job_type: str = "bundle",
        display_name: Optional[str] = None,
        hooks_registry: Optional[List[str]] = None,
        priority: int = 50,
        auto_resume: bool = False,
    ) -> Optional[str]:
        """Load a declarative set of hook-sets under one opaque bundle id.

        Args:
            scripts: Ordered list of ``(label, source)`` pairs. ``label`` is a
                stable identifier for the hook-set (e.g. a category key); the
                merged-load order follows this list.
            custom_hooking_handler_name: Message handler ``(job, message, data)``
                shared by every job in the bundle (message fan-in to one
                handler). ``merge_error`` payloads are intercepted by AFM before
                being forwarded.
            job_type: Job category for coordination/UI.
            display_name: Human-readable name for UI display.
            hooks_registry: Union of hook ids across all hook-sets (advisory
                conflict detection / UI). Registered once under the bundle's
                primary job.
            priority: Job priority (lower = higher).
            auto_resume: Forwarded to ``start_job`` for the bundle's first job.
                Defaults to False. On a paused spawn ``is_first_job`` is already
                False (set by ``spawn_paused``), so no resume happens regardless;
                on the attach path passing False prevents the first job from
                issuing a redundant ``device.resume`` on an already-running PID.

        Returns:
            The opaque ``bundle_id``, or None if no session / load failed.
        """
        if not self.process_session:
            self.logger.error("[-] no frida session for bundle. Aborting...")
            return None

        bundle_id = str(uuid.uuid4())
        bundle = {
            "merged": None,        # {"job_id", "labels", "sources", "temp"}
            "separate": {},        # label -> {"job_id", "source", "temp"}
            "temps": set(),        # all temp files AFM owns for this bundle
            "merge_errors": set(),  # labels whose IIFE threw at merged load
            "registry_job_id": None,
            "meta": {
                "job_type": job_type,
                "display_name": display_name,
                "hooks_registry": list(hooks_registry or []),
                "priority": priority,
                "handler": custom_hooking_handler_name,
            },
        }
        self._bundles[bundle_id] = bundle
        handler = self._make_bundle_handler(bundle_id, custom_hooking_handler_name)

        try:
            if self.is_paused():
                self._load_merged_group(bundle, list(scripts), handler, auto_resume)
            else:
                first = True
                for label, src in scripts:
                    self._load_separate_job(
                        bundle, label, src, handler,
                        auto_resume if first else False,
                    )
                    first = False
            self._reconcile_bundle_registry(bundle)
            return bundle_id
        except Exception as e:
            self.logger.error(f"[-] start_bundle failed: {e}")
            self.stop_bundle(bundle_id)
            return None

    def update_bundle(self, bundle_id: str, scripts: List[Tuple[str, str]]) -> bool:
        """Reconcile a bundle's loaded hook-sets to a new desired set.

        ``scripts`` is the COMPLETE desired set (declarative, never a delta).

        * Live: *added* labels load as new separate jobs (no gap); *removed*
          separate-job labels are stopped (no gap); removing a label that lives
          inside the merged group rebuilds that group unload-first (the only
          residual brief gap, affecting just the survivors of that group).
        * Paused / jobs-gone (e.g. after ``reset_session``): rebuild from
          scratch under the same bundle_id.

        Returns:
            True on success, False if the bundle is unknown or a load failed.
        """
        bundle = self._bundles.get(bundle_id)
        if bundle is None:
            return False
        scripts = list(scripts)

        # Jobs gone (reset_session) or paused -> rebuild fresh under same id.
        if not self._bundle_has_live_jobs(bundle) or self.is_paused():
            return self._rebuild_bundle_fresh(bundle_id, scripts)

        target = {label: src for label, src in scripts}
        target_labels = set(target)
        merged = bundle["merged"]
        merged_labels = set(merged["labels"]) if merged else set()
        separate_labels = set(bundle["separate"])
        current_labels = merged_labels | separate_labels

        handler = self._make_bundle_handler(bundle_id, bundle["meta"]["handler"])
        to_add = target_labels - current_labels
        to_remove = current_labels - target_labels

        try:
            # Remove separate-job labels (no gap).
            for label in (to_remove & separate_labels):
                rec = bundle["separate"].pop(label, None)
                if rec:
                    if rec["job_id"] in self.jobs:
                        self.stop_job_with_id(rec["job_id"])
                    self._unlink_temp(bundle, rec.get("temp"))

            # Remove merged-group labels -> rebuild survivors unload-first.
            merged_removals = to_remove & merged_labels
            if merged_removals and merged:
                survivors = [l for l in merged["labels"] if l not in to_remove]
                old_job_id = merged["job_id"]
                old_temp = merged.get("temp")
                bundle["merged"] = None
                if old_job_id in self.jobs:
                    self.stop_job_with_id(old_job_id)
                self._unlink_temp(bundle, old_temp)
                if survivors:
                    survivor_scripts = [
                        (l, merged["sources"][l]) for l in survivors
                    ]
                    self._load_merged_group(
                        bundle, survivor_scripts, handler, auto_resume=False
                    )

            # Add new labels as separate live jobs (no gap), in caller order.
            for label, src in scripts:
                if label in to_add:
                    self._load_separate_job(
                        bundle, label, src, handler, auto_resume=False
                    )

            self._reconcile_bundle_registry(bundle)
            return True
        except Exception as e:
            self.logger.error(f"[-] update_bundle failed: {e}")
            return False

    def stop_bundle(self, bundle_id: str) -> bool:
        """Stop every job in a bundle and unlink all of its temp files.

        Returns:
            True if the bundle existed, False otherwise.
        """
        bundle = self._bundles.get(bundle_id)
        if bundle is None:
            return False
        try:
            self._stop_bundle_jobs(bundle)
        finally:
            for path in list(bundle.get("temps", set())):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            self._bundles.pop(bundle_id, None)
        return True

    def bundle_clean_labels(self, bundle_id: str) -> List[str]:
        """Labels that loaded without a ``merge_error`` (for caller reconcile).

        Returns:
            Sorted list of loaded labels minus any that reported a merge_error.
        """
        bundle = self._bundles.get(bundle_id)
        if bundle is None:
            return []
        loaded = set(bundle["separate"])
        if bundle.get("merged"):
            loaded |= set(bundle["merged"]["labels"])
        return sorted(loaded - bundle.get("merge_errors", set()))

    # ---- bundle helpers -------------------------------------------------

    def _build_merged_source(self, scripts: List[Tuple[str, str]]) -> str:
        """Concatenate ``(label, source)`` pairs into one IIFE-wrapped script.

        Each source runs inside its own ``try``/``catch`` IIFE so a throw in one
        hook-set neither aborts the others nor corrupts the global scope
        (top-level ``var`` declarations stay function-local), and reports itself
        via ``send({merge_error: <label>})``.
        """
        parts = ["'use strict';\n"]
        for label, src in scripts:
            label_json = json.dumps(label)
            parts.append(
                "(function () {\ntry {\n"
                f"{src}\n"
                "} catch (e) {\n"
                f"send({{merge_error: {label_json}, error: '' + e}});\n"
                "}\n})();\n"
            )
        return "".join(parts)

    def _new_bundle_temp(self, bundle: dict, source: str) -> str:
        """Write ``source`` to a fresh unique temp file owned by the bundle."""
        fd, path = tempfile.mkstemp(prefix="afm-bundle-", suffix=".js")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(source)
        bundle["temps"].add(path)
        return path

    def _unlink_temp(self, bundle: dict, path: Optional[str]) -> None:
        if not path:
            return
        try:
            os.unlink(path)
        except OSError:
            pass
        bundle["temps"].discard(path)

    def _make_bundle_handler(self, bundle_id: str, user_handler: Callable):
        """Wrap the caller's handler to intercept/track ``merge_error``."""
        def _handler(job, message, data):
            try:
                if message.get("type") == "send":
                    payload = message.get("payload")
                    if isinstance(payload, dict) and "merge_error" in payload:
                        label = payload.get("merge_error")
                        bundle = self._bundles.get(bundle_id)
                        if bundle is not None:
                            bundle["merge_errors"].add(label)
                        self.logger.warning(
                            f"[bundle {bundle_id[:8]}] hook-set '{label}' failed "
                            f"to load: {payload.get('error', '')}"
                        )
            except Exception:
                pass
            if callable(user_handler):
                user_handler(job, message, data)
        return _handler

    def _load_merged_group(
        self, bundle: dict, scripts: List[Tuple[str, str]], handler, auto_resume
    ):
        """Load ``scripts`` as ONE merged job (the paused-spawn strategy)."""
        if not scripts:
            return None
        source = self._build_merged_source(scripts)
        path = self._new_bundle_temp(bundle, source)
        meta = bundle["meta"]
        job = self.start_job(
            path,
            custom_hooking_handler_name=handler,
            job_type=meta["job_type"],
            display_name=meta["display_name"],
            hooks_registry=meta["hooks_registry"],
            priority=meta["priority"],
            auto_resume=auto_resume,
        )
        if job is None:
            self._unlink_temp(bundle, path)
            raise FridaBasedException("merged bundle job failed to start")
        if not job.wait_until_ready(timeout=self.BUNDLE_READINESS_TIMEOUT):
            err = job.get_error() or "hooks did not load (timeout)"
            self.stop_job_with_id(job.get_id())
            self._unlink_temp(bundle, path)
            raise FridaBasedException(f"merged bundle load failed: {err}")
        bundle["merged"] = {
            "job_id": job.get_id(),
            "labels": [l for l, _ in scripts],
            "sources": {l: s for l, s in scripts},
            "temp": path,
        }
        return job

    def _load_separate_job(
        self, bundle: dict, label: str, src: str, handler, auto_resume
    ):
        """Load a single hook-set as its own job (the live strategy)."""
        path = self._new_bundle_temp(bundle, src)
        meta = bundle["meta"]
        dn = meta.get("display_name")
        dn = f"{dn} [{label}]" if dn else label
        job = self.start_job(
            path,
            custom_hooking_handler_name=handler,
            job_type=meta["job_type"],
            display_name=dn,
            hooks_registry=meta["hooks_registry"],
            priority=meta["priority"],
            auto_resume=auto_resume,
        )
        if job is None:
            self._unlink_temp(bundle, path)
            raise FridaBasedException(f"bundle job '{label}' failed to start")
        if not job.wait_until_ready(timeout=self.BUNDLE_READINESS_TIMEOUT):
            err = job.get_error() or "hooks did not load (timeout)"
            self.stop_job_with_id(job.get_id())
            self._unlink_temp(bundle, path)
            raise FridaBasedException(f"bundle job '{label}' load failed: {err}")
        bundle["separate"][label] = {
            "job_id": job.get_id(), "source": src, "temp": path,
        }
        return job

    def _rebuild_bundle_fresh(
        self, bundle_id: str, scripts: List[Tuple[str, str]]
    ) -> bool:
        """Stop any surviving jobs and reload the whole set under the same id."""
        bundle = self._bundles.get(bundle_id)
        if bundle is None:
            return False
        self._stop_bundle_jobs(bundle)
        bundle["merged"] = None
        bundle["separate"] = {}
        bundle["merge_errors"] = set()
        bundle["registry_job_id"] = None
        handler = self._make_bundle_handler(bundle_id, bundle["meta"]["handler"])
        try:
            if self.is_paused():
                self._load_merged_group(bundle, list(scripts), handler, False)
            else:
                # A rebuild never owns the resume (the caller manages it), so
                # every job loads with auto_resume=False.
                for label, src in scripts:
                    self._load_separate_job(bundle, label, src, handler, False)
            self._reconcile_bundle_registry(bundle)
            return True
        except Exception as e:
            self.logger.error(f"[-] bundle rebuild failed: {e}")
            return False

    def _bundle_job_ids(self, bundle: dict) -> List[str]:
        ids = []
        if bundle.get("merged"):
            ids.append(bundle["merged"]["job_id"])
        ids += [r["job_id"] for r in bundle["separate"].values()]
        return ids

    def _bundle_has_live_jobs(self, bundle: dict) -> bool:
        return any(jid in self.jobs for jid in self._bundle_job_ids(bundle))

    def _stop_bundle_jobs(self, bundle: dict) -> None:
        for jid in self._bundle_job_ids(bundle):
            if jid in self.jobs:
                try:
                    self.stop_job_with_id(jid)
                except Exception as e:
                    self.logger.warning(f"stop bundle job {jid[:8]} failed: {e}")

    def _reconcile_bundle_registry(self, bundle: dict) -> None:
        """Register the union hook-set under the bundle's current primary job.

        ``stop_job_with_id`` auto-unregisters a job's hooks, so when the primary
        job changes (merged group rebuilt, or last merged label removed leaving
        only separate jobs) the union is re-pointed at a still-live job.
        """
        union = bundle["meta"]["hooks_registry"]
        if not union:
            return
        primary = None
        if bundle.get("merged"):
            primary = bundle["merged"]["job_id"]
        elif bundle["separate"]:
            primary = next(iter(bundle["separate"].values()))["job_id"]
        prev = bundle.get("registry_job_id")
        if prev == primary:
            return
        if prev:
            self.unregister_hooks(prev)
        if primary:
            self.register_hooks(primary, union)
        bundle["registry_job_id"] = primary

    def get_last_created_job(self):
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
        self.adb.shell(f"am force-stop {app_package}")


    def stop_app_with_last_job(self, last_job, app_package):
        last_job.close_job()
        self.stop_app(app_package)



    def stop_app_with_closing_frida(self, app_package):
        jobs_to_stop = [job_id for job_id, job in self.jobs.items() if job.state == "running"]
        for job_id in jobs_to_stop:
            self.logger.info(f"[*] trying to close job: {job_id}")
            self.stop_job_with_id(job_id)

        self.detach_from_app()
        self.adb.shell(f"am force-stop {app_package}")


    def kill_app(self, pid):
        self.adb.shell(f"kill {pid}")


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
                if callable(self.first_instrumentation_script):
                    self.first_instrumentation_script(device.attach(child.pid))
                device.resume(child.pid)

            # if the target process is starting another process
            def on_spawn_added(spawn):
                self.logger.info(f"Process spawned with pid {spawn.pid}. Name: {spawn.identifier}")
                if callable(self.first_instrumentation_script):
                    self.first_instrumentation_script(device.attach(spawn.pid))
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
        self._paused = False  # No process => nothing paused

        self.logger.info("[*] Session reset complete")
