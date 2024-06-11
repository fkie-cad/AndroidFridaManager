#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import threading
import frida
import uuid

# Define a custom exception for handling frida based exceptions
class FridaBasedException(Exception):
    pass

class Job:
    def __init__(self, frida_script_name, custom_hooking_handler, process):
        self.frida_script_name = frida_script_name
        self.job_id = str(uuid.uuid4())
        self.state = "initialized"
        self.custom_hooking_handler = custom_hooking_handler
        self.script = None
        self.stop_event = threading.Event()
        self.process_session = process
        self.thread = None
        self.is_script_created = False


    def create_job_script(self):
        self.instrument(self.process_session)
        self.is_script_created = True
    
    
    def run_job(self):
        #self.is_running_as_thread = True
        self.run_job_as_thread()


    def run_job_as_thread(self):
        self.thread = threading.Thread(target=self.invoke_handle_hooking)
        self.thread.start()


    def invoke_handle_hooking(self):
        if self.is_script_created == False:
            self.instrument(self.process_session)
            self.is_script_created = True
        self.script.on("message", self.wrap_custom_hooking_handler_with_job_id(self.custom_hooking_handler))
        self.script.load()
        self.state = "running"
        print("[+] hooks succesfully loaded")

        #if self.is_running_as_thread:
        # Keep the thread alive to handle messages until stop_event is set
        while not self.stop_event.is_set():
            self.stop_event.wait(1) # Sleep for 1 second and check again


    def wrap_custom_hooking_handler_with_job_id(self, handler):

        def wrapped_handler(message, data):
            # Add job_id to the message
            message['job_id'] = self.job_id
            handler(message, data)

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


    def close_job(self):
        self.state = "stopping"
        self.stop_event.set()
        if self.thread:
            self.thread.join()
        if self.script:
            self.script.unload()
        
        print(f"Job {self.job_id} stopped")


    def get_id(self):
        return self.job_id


    def get_script_of_job(self):
        return self.script