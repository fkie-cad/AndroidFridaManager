#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Frida Job management for AndroidFridaManager.

This module provides the Job class for managing individual Frida instrumentation
jobs, including script loading, message handling, and lifecycle management.
"""

import threading
import frida
import uuid
import logging
import datetime
from typing import Optional, List, Callable, Any


# Define a custom exception for handling frida based exceptions
class FridaBasedException(Exception):
    pass


class Job:
    """Represents a single Frida instrumentation job.

    A job encapsulates a Frida script, its message handler, and lifecycle
    management. Jobs run in separate threads and can be started/stopped
    independently.

    Attributes:
        job_id: Unique identifier for this job.
        job_type: Category of job (e.g., "fritap", "dexray", "trigdroid", "custom").
        display_name: Human-readable name for UI display.
        hooks_registry: List of methods/functions this job hooks (for conflict detection).
        priority: Job priority (lower = higher priority, default 50).
        state: Current state ("initialized", "running", "stopping", "error", "stopped").
        started_at: Timestamp when job was started (None if not started).
    """

    def __init__(
        self,
        frida_script_name: str,
        custom_hooking_handler: Callable,
        process: Any,
        job_type: str = "custom",
        display_name: Optional[str] = None,
        hooks_registry: Optional[List[str]] = None,
        priority: int = 50,
    ):
        """Initialize a new Job.

        Args:
            frida_script_name: Path to the Frida script file.
            custom_hooking_handler: Callback function for handling Frida messages.
            process: Frida session/process to attach the script to.
            job_type: Category of job for coordination (default: "custom").
            display_name: Human-readable name (default: script filename).
            hooks_registry: List of hooked methods for conflict detection.
            priority: Job priority, lower = higher (default: 50).
        """
        self.frida_script_name = frida_script_name
        self.job_id = str(uuid.uuid4())
        self.state = "initialized"
        self.custom_hooking_handler = custom_hooking_handler
        self.script = None
        self.stop_event = threading.Event()
        self.process_session = process
        self.thread = None
        self.is_script_created = False
        self.logger = logging.getLogger(__name__)

        # New metadata fields for job coordination
        self.job_type = job_type
        self.display_name = display_name or frida_script_name
        self.hooks_registry = hooks_registry or []
        self.priority = priority
        self.started_at: Optional[datetime.datetime] = None

        # State propagation for callers to wait on job readiness
        self._ready_event = threading.Event()
        self._error_message: Optional[str] = None

    def _set_state(self, new_state: str, error_msg: Optional[str] = None) -> None:
        """Set state and signal ready event if terminal state reached.

        Args:
            new_state: New state value ("initialized", "running", "error", "stopping", "stopped").
            error_msg: Optional error message when transitioning to "error" state.
        """
        self.state = new_state
        if error_msg:
            self._error_message = error_msg
        # Signal ready event when job reaches a terminal state (running, error, stopped)
        if new_state in ("running", "error", "stopped"):
            self._ready_event.set()

    def wait_until_ready(self, timeout: float = 10.0) -> bool:
        """Wait for job to reach running or error state.

        Blocks until the job thread signals that hooks have been loaded
        successfully (state="running") or an error occurred (state="error").

        Args:
            timeout: Maximum seconds to wait (default: 10.0).

        Returns:
            True if job is running successfully, False if error or timeout.
        """
        if self._ready_event.wait(timeout=timeout):
            return self.state == "running"
        # Timeout occurred
        self._error_message = f"Timeout waiting for job to start after {timeout}s"
        return False

    def get_error(self) -> Optional[str]:
        """Get error message if job failed.

        Returns:
            Error message string if job is in error state, None otherwise.
        """
        return self._error_message


    def create_job_script(self):
        self.instrument(self.process_session)
        self.is_script_created = True
    
    
    def run_job(self):
        """Start the job execution in a separate thread."""
        self.started_at = datetime.datetime.now()
        self.run_job_as_thread()


    def run_job_as_thread(self):
        self.thread = threading.Thread(target=self.invoke_handle_hooking)
        self.thread.start()


    def invoke_handle_hooking(self):
        try:
            if self.is_script_created == False:
                self.instrument(self.process_session)
                self.is_script_created = True
            self.script.on("message", self.wrap_custom_hooking_handler_with_job_id(self.custom_hooking_handler))
            self.script.load()
            self._set_state("running")
            self.logger.info("[+] hooks successfully loaded")

            #if self.is_running_as_thread:
            # Keep the thread alive to handle messages until stop_event is set
            while not self.stop_event.is_set():
                self.stop_event.wait(1) # Sleep for 1 second and check again
        except frida.TransportError as e:
            error_msg = f"TransportError during script load: {e} - target app may have crashed or restarted"
            self._set_state("error", error_msg)
            self.logger.error(f"[-] {error_msg}")
        except frida.InvalidOperationError as e:
            error_msg = f"InvalidOperationError during script load: {e}"
            self._set_state("error", error_msg)
            self.logger.error(f"[-] {error_msg}")
        except frida.ProcessNotFoundError as e:
            error_msg = f"ProcessNotFoundError: Target process no longer exists: {e}"
            self._set_state("error", error_msg)
            self.logger.error(f"[-] {error_msg}")
        except frida.ProtocolError as e:
            error_msg = f"ProtocolError: Connection issue with target: {e}"
            self._set_state("error", error_msg)
            self.logger.error(f"[-] {error_msg}")
        except Exception as e:
            error_msg = f"Unexpected error in hook thread: {type(e).__name__}: {e}"
            self._set_state("error", error_msg)
            self.logger.error(f"[-] {error_msg}")


    def wrap_custom_hooking_handler_with_job_id(self, handler):

        def wrapped_handler(message, data):
            # Add job_id to the message
            message['job_id'] = self.job_id
            handler(self, message, data)

        return wrapped_handler


    def instrument(self, process_session,runtime="qjs"):
            try:
                with open(self.frida_script_name, encoding='utf8', newline='\n') as f:
                    script_string = f.read()
                    self.script = process_session.create_script(script_string, runtime=runtime)
                    return self.script
                
            except frida.ProcessNotFoundError:
                raise FridaBasedException("Unable to find target process")
            except frida.InvalidOperationError:
                raise FridaBasedException("Invalid operation! Please run in debug mode in order to understand the source of this error and report it.")
            except frida.TransportError:
                raise FridaBasedException("Timeout error due to some internal frida error's. Try to restart frida-server again.")
            except frida.ProtocolError:
                raise FridaBasedException("Connection is closed. Probably the target app crashed")


    def close_job(self, timeout: float = 5.0) -> bool:
        """Stop the job and cleanup resources.

        Uses a staged shutdown approach:
        1. Set stop_event FIRST to signal thread to exit wait loop
        2. Wait briefly for thread to notice stop_event
        3. Try to unload script (may hang if connection broken)
        4. Set final stopped state

        Args:
            timeout: Maximum seconds to wait for thread to stop.
                     Default 5.0 seconds. Use 0 for no wait.

        Returns:
            True if job stopped cleanly, False if timed out.
        """
        self._set_state("stopping")

        # Step 1: Signal thread to exit wait loop FIRST
        self.stop_event.set()

        # Step 2: Wait for thread to notice stop_event (short timeout)
        thread_timeout = min(1.0, timeout) if timeout > 0 else 1.0
        timed_out = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=thread_timeout)
            if self.thread.is_alive():
                self.logger.warning(
                    f"Job {self.job_id} thread did not stop within {thread_timeout}s"
                )
                timed_out = True

        # Step 3: Try to unload script (may hang if connection broken)
        if self.script:
            try:
                self.script.unload()
            except Exception as e:
                self.logger.warning(f"Script unload failed (connection may be broken): {e}")

        # Step 4: Set final state
        self._set_state("stopped")

        status = "timed out" if timed_out else "stopped"
        self.logger.info(f"Job {self.job_id} {status}")
        return not timed_out


    def get_id(self):
        return self.job_id


    def get_script_of_job(self):
        return self.script

    def get_info(self) -> dict:
        """Get job information as a dictionary for UI display.

        Returns:
            Dictionary containing job metadata and state information.
        """
        return {
            "job_id": self.job_id,
            "job_type": self.job_type,
            "display_name": self.display_name,
            "state": self.state,
            "priority": self.priority,
            "hooks_count": len(self.hooks_registry),
            "hooks_registry": self.hooks_registry.copy(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "script_name": self.frida_script_name,
        }