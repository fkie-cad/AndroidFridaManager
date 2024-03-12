# AndroidFridaManager

A python API in order to install and run the frida-server on an Android device. The project was inspired by [Frida-Python-Binding](https://github.com/Mind0xP/Frida-Python-Binding/tree/master).

## Install

Just install it via pip:
```bash
pip install AndroidFridaManager
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

```python
from AndroidFridaManager import FridaManager
...
afm_obj = FridaManager(is_remote=False, socket="ip:port", verbose=False, frida_install_dst="/data/local/tmp/")
afm_obj.install_frida_server()
afm_obj.run_frida_server()
```


## API

```python
install_frida_server(dst_dir="/data/local/tmp/", version="latest")
run_frida_server()
is_frida_server_running()
stop_frida_server()
remove_frida_server()
```
