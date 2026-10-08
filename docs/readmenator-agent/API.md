# API

## beacon.py
- `aes_cfb_decrypt` (function) `beacon.py:87` `def aes_cfb_decrypt(data_b64)`
- `aes_cfb_encrypt` (function) `beacon.py:94` `def aes_cfb_encrypt(data)`
- `get_ips` (function) `beacon.py:102` `def get_ips()`
- `exec_cmd` (function) `beacon.py:113` `def exec_cmd(cmd)`
- `set_executable_permissions` (function) `beacon.py:120` `def set_executable_permissions(address, size)` -- Establece los permisos R+W+X en una región de memoria.
- `init_beacon_stubs` (function) `beacon.py:162` `def init_beacon_stubs()`
- `BeaconPrintf_stub` (method) `beacon.py:170` `def BeaconPrintf_stub(_type, fmt)`
- `BeaconOutput_stub` (method) `beacon.py:185` `def BeaconOutput_stub(_type, data, length)`
- `align` (function) `beacon.py:210` `def align(x, a)` -- Alinear x al múltiplo superior de a
- `RunELF.__init__` (method) `beacon.py:221` `def __init__(self, blob)` -- Parsear cabeceras ELF y preparar estructuras.
- `RunELF.load` (method) `beacon.py:363` `def load(self)` -- Cargar y preparar el ELF para ejecución.
- `RunELF.run` (method) `beacon.py:552` `def run(self, func, args)` -- Ejecuta el BOF delegando la llamada a la librería C externa 'libbofloader.so', que se encarga del aislamiento de...
- `RunELF.cleanup` (method) `beacon.py:589` `def cleanup(self)` -- Liberar todas las secciones mapeadas.
- `RunELF.run_bof_and_capture` (method) `beacon.py:612` `def run_bof_and_capture(elf_blob, args)`
- `RunELF.download_bof` (method) `beacon.py:628` `def download_bof(url)`
- `RunELF.beacon` (method) `beacon.py:640` `def beacon()`

## lazyown_minimal_c2.py
- `encrypt_data` (function) `lazyown_minimal_c2.py:22` `def encrypt_data(data)`
- `decrypt_data` (function) `lazyown_minimal_c2.py:28` `def decrypt_data(b64data, is_file)`
- `init_db` (function) `lazyown_minimal_c2.py:36` `def init_db()`
- `send_command` (function) `lazyown_minimal_c2.py:50` `def send_command(client_id)`
- `recv_result` (function) `lazyown_minimal_c2.py:55` `def recv_result(client_id)`
- `upload` (function) `lazyown_minimal_c2.py:70` `def upload()`
- `download` (function) `lazyown_minimal_c2.py:81` `def download(filename)`
- `panel` (function) `lazyown_minimal_c2.py:91` `def panel()`

## loader_wrapper.c
- `execute_bof` (function) `loader_wrapper.c:9` `void execute_bof(void* go_addr, char* args, int len)`
