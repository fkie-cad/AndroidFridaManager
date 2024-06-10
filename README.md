# AndroidFridaManager

AndroidFridaManager is a Python API designed to simplify the installation and management of Frida on Android devices. It provides an easy-to-use interface for installing and running the latest Frida server, as well as the flexibility to install specific versions as needed.

Key Features

    Frida Server Management: Seamlessly install and run the latest Frida server on your Android device, or choose to install a specific version as required.
    Job Management: Execute Frida scripts as independent jobs, managed by the `JobManager()`. This feature allows for concurrent execution of multiple Frida scripts, with each job running in its own thread.
    `afrim` Tool Integration: Utilize the `afrim` tool to check for existing Frida server installations on your device and ensure you are always running the latest version.


The project was inspired by [Frida-Python-Binding](https://github.com/Mind0xP/Frida-Python-Binding/tree/master).

## Install

Just install it via pip:
```bash
python3 -m pip install AndroidFridaManager
```

This will install the `afrim`-command to your system.

## Usage

In order to easily install the latest frida-server version to your Android device just run the following command:

```bash
$ afrim 
```


In order to check only if frida-server is running invoke it with the `-r`-parameter:

```bash
$ afrim -r
```


## API Usage

In order to install and run Frida on your Android device use the `FridaManager`-API:
```python
from AndroidFridaManager import FridaManager
...
afm_obj = FridaManager(is_remote=False, socket="ip:port", verbose=False, frida_install_dst="/data/local/tmp/")
afm_obj.install_frida_server()
afm_obj.run_frida_server()
```

For running Frida scripts as jobs use the `JobManager`-API:
```python
from AndroidFridaManager import JobManager
...
app_package = "net.classwindexampleyear.bookseapiececountry"
frida_script_path = "./frida_script1.js"
job_manager = JobManager()
job_manager.setup_frida_session(app_package, myAwesomeHookingHandler)
job_manager.start_job(frida_script_path, myAwesomeHookingHandler)
print("Running jobs:", job_manager.running_jobs())
job_manager.stop_app_with_closing_frida(app_package)
``` 

The `setup_frida_session()` function accepts a callback function as its second parameter, typically provided by `script.on('message', on_message)`. This initializes the first job and, by default, is the only job where you can activate [child_gating and spawn_gating](https://frida.re/news/#child-gating). To execute the job, you must invoke the `start_job()` function.

## API

```python
install_frida_server(dst_dir="/data/local/tmp/", version="latest")
run_frida_server()
is_frida_server_running()
stop_frida_server()
remove_frida_server()

# JobManager
JobManager(host="", enable_spawn_gating=False)
running_jobs() # list running jobs
start_android_app(package_name, main_activity = None, extras = None) # returns the PID of the start app
setup_frida_session(target_process, frida_callback_function, should_spawn=True,foreground=False)
start_job(frida_script_name, frida_callback_function)
stop_jobs() # stops all running jobs
stop_job_with_id(job_id) # stop only job with job_id
detach_from_app() # will also be invoked when running stop_app_with_closing_frida()
stop_app_with_closing_frida(app_package)
stop_app(app_package)
kill_app(pid)
setup_frida_handler(host="", enable_spawn_gating=False) # returns the device object and is used by setup_frida_session()

# setup_frida_handler,setup_frida_session will raise the FridaBasedException(Exception). Ensure to handle it
```
