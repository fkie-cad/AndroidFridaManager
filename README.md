# AndroidFridaManager

A python API in order to install and run the frida-server on an Android device. The project was inspired by [Frida-Python-Binding](https://github.com/Mind0xP/Frida-Python-Binding/tree/master).

## Usage

```python
afm_obj = FridaAndroidManager(is_remote=False, socket="ip:port", verbose=False, frida_install_dst="/data/local/tmp/")
afm_obj.install_frida_server()
afm_obj.run_frida_server()
```

## API

```python
install_frida_server(version="latest")
run_frida_server()
is_frida_server_running()
stop_frida_server()
remove_frida_server()
```
