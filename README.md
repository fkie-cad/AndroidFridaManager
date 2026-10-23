![version](https://img.shields.io/badge/version-2.0.6-blue) [![PyPI version](https://badge.fury.io/py/AndroidFridaManager.svg)](https://badge.fury.io/py/AndroidFridaManager) [![Publish status](https://github.com/fkie-cad/friTap/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/fkie-cad/AndroidFridaManager/actions/workflows/publish-to-pypi.yml)

# AndroidFridaManager

AndroidFridaManager is a Python API designed to simplify the installation and management of Frida on Android devices. It provides an easy-to-use interface for installing and running the latest Frida server, as well as the flexibility to install specific versions as needed.

Key features:

- Frida Server Management:  Seamlessly install and run the latest Frida server on your Android device, or choose to install a specific version as required. By default the installed version matches your host `frida` Python package so that client and server stay in sync.
- Job Management: Execute Frida scripts as independent jobs, managed by the `JobManager()`. This feature allows for concurrent execution of multiple Frida scripts, with each job running in its own thread.
- Bundle API: Load a declarative set of hook-sets under one opaque bundle id. On a paused spawn all scripts are merged into a single Frida script (working around frida-java-bridge [#218](https://github.com/niclas3003/frida-java-bridge/issues/218)); on a live process each script runs as its own job so toggling one hook-set never blinks the others.
- Session & Script Lifecycle: Automatic detection of session detachment and script destruction — running jobs are marked as errored so callers can react immediately.
- `afrim` Tool Integration: Utilize the `afrim` tool to check for existing Frida server installations on your device and ensure you are always running the latest version.


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

In order to check the frida-server status invoke it with the `-r`-parameter:

```bash
$ afrim -r                      # first auto-selected device
$ afrim -r -d emulator-5554     # specific device
```

It prints whether a frida-server process exists, whether it is *ready* (the frida client can attach/spawn through it) and the installed frida-server version. The exit code is `0` only if the server is ready and non-zero otherwise, so it can be used in scripts (`afrim -r && frida -U ...`). `-d/--device`, `--frida_install_dst` and `--adb-root` are honoured.

Without `-r`, `afrim` installs the frida-server version matching your host `frida` package and starts it; the exit code is `0` only if the server ended up ready.


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

For loading multiple hook-sets on a paused spawn (e.g. bypass + tooling scripts), use the Bundle API:
```python
from AndroidFridaManager import JobManager

job_manager = JobManager()
pid = job_manager.spawn_paused("com.example.app")

bundle_id = job_manager.start_bundle(
    scripts=[
        ("root-bypass", root_bypass_source),
        ("ssl-pinning", ssl_pinning_source),
    ],
    custom_hooking_handler_name=my_handler,
)

job_manager.resume_app()
```

## API

### FridaManager

```python
FridaManager(is_remote=False, socket="", verbose=False, frida_install_dst="/data/local/tmp/",
             device_serial=None, adb=None)

install_frida_server(dst_dir=None, version=None)
    # version=None auto-matches host frida package version;
    # pass "latest" for newest GitHub release, or a specific version string

run_frida_server(frida_server_path=None)   # -> bool
    # no-op (True) if a ready server already exists; restarts a stale/unresponsive
    # one; fails (False) if the binary is missing. Launches frida-server fully
    # detached from adb (setsid + nohup, stdio -> log file), so it survives
    # `adb kill-server`, USB replugs and the host adb client going away. Its
    # output is appended to <frida_install_dst>frida-server.log
    # (default /data/local/tmp/frida-server.log). Waits up to 15s until the frida
    # client can actually use the server; on failure the log tail is reported.

is_frida_server_ready()      # True iff the frida client can attach/spawn (access == "full")
is_frida_server_running()    # True iff a frida-server *process* exists (also versioned
                             # names like frida-server-17.x-android-arm64); does NOT
                             # prove the server is usable -- prefer is_frida_server_ready()
get_frida_server_status()    # {"process": bool, "ready": bool, "installed_version": str|None}
stop_frida_server()          # -> bool; kills every frida-server process and waits until
                             # none remain (escalates to SIGKILL)
restart_frida_server_and_wait(timeout=15.0)   # stop + run; True once ready
is_process_alive(pid)        # True iff pid is enumerated by a ready frida-server
remove_frida_server()
get_device_arch()            # frida arch name of the device, e.g. "arm64"

get_installed_server_version()       # returns version string from device, or None
list_available_versions(limit=15)    # fetches recent release tags from GitHub

get_connected_devices()              # classmethod — list ADB devices
get_frida_devices()                  # classmethod — list Frida-visible devices
```

> **Frida 17 "jailed" fallback:** with *no* frida-server running, a frida 17 USB device still answers `enumerate_processes()` and `query_system_parameters()` through an ADB fallback (reporting `access: "jailed"`), while `attach()`/`spawn()` then fail (e.g. "need Gadget to attach on jailed Android"). "Enumerating processes works" is therefore not proof of a running server. `is_frida_server_ready()` only returns True for `access: "full"`, and `run_frida_server()` / `afrim -r` use that check.

### JobManager

```python
JobManager(host="", enable_spawn_gating=False, device_serial=None, adb=None)

# Session setup
setup_frida_session(target_process, frida_callback_function, should_spawn=True, foreground=False)
setup_frida_handler(host="", enable_spawn_gating=False)

# Spawn / attach
spawn(target_process)
spawn_paused(target_process)         # keeps process paused for multi-tool loading
resume_app()                         # resume a paused spawn after hooks are loaded
mark_resumed()                       # sync flag after an external device.resume() call
is_paused()

# Jobs
start_job(frida_script_name, frida_callback_function, job_type="custom",
          display_name=None, hooks_registry=None, priority=50, auto_resume=True)
running_jobs()
stop_jobs()
stop_job_with_id(job_id)

# Bundle API — declarative multi-script coordination
start_bundle(scripts, custom_hooking_handler_name, *, job_type="bundle",
             display_name=None, hooks_registry=None, priority=50, auto_resume=False)
    # scripts: list of (label, source) pairs
    # paused spawn → merged into one script; live → separate jobs
update_bundle(bundle_id, scripts)    # declarative reconcile (not a delta)
stop_bundle(bundle_id)
bundle_clean_labels(bundle_id)       # labels that loaded without error

# Session lifecycle
attach_app(target_process, foreground=False)
reset_session(timeout_per_job=2.0, detach_timeout=2.0)
get_job_by_id(job_id)

# App control
start_android_app(package_name, main_activity=None, extras=None)
stop_app(app_package)
stop_app_with_closing_frida(app_package)
kill_app(pid)
detach_from_app()

# Hook coordination
register_hooks(job_id, hooks)
unregister_hooks(job_id)
check_hook_conflicts(hooks)
get_hook_registry()

# Session info
has_active_session()
get_session_info()
get_running_jobs_info()
get_all_jobs_info()

# setup_frida_handler, setup_frida_session will raise FridaBasedException(Exception). Ensure to handle it.
```

The JobManager expects a running `frida-server` on the target device. 
