# API

## beacon.py

### aes_cfb_decrypt (function) `def aes_cfb_decrypt(data_b64)`
- Defined: `beacon.py:87`

### aes_cfb_encrypt (function) `def aes_cfb_encrypt(data)`
- Defined: `beacon.py:94`

### get_ips (function) `def get_ips()`
- Defined: `beacon.py:102`

### exec_cmd (function) `def exec_cmd(cmd)`
- Defined: `beacon.py:113`

### set_executable_permissions (function) `def set_executable_permissions(address, size)`
- Defined: `beacon.py:120`
- Doc: Establece los permisos R+W+X en una región de memoria.

### init_beacon_stubs (function) `def init_beacon_stubs()`
- Defined: `beacon.py:162`

### align (function) `def align(x, a)`
- Defined: `beacon.py:210`
- Doc: Alinear x al múltiplo superior de a

### run_bof_and_capture (method) `def run_bof_and_capture(elf_blob, args)`
- Defined: `beacon.py:612`

### download_bof (method) `def download_bof(url)`
- Defined: `beacon.py:628`

### beacon (method) `def beacon()`
- Defined: `beacon.py:640`

### BeaconPrintf_stub (method) `def BeaconPrintf_stub(_type, fmt)`
- Defined: `beacon.py:170`

### BeaconOutput_stub (method) `def BeaconOutput_stub(_type, data, length)`
- Defined: `beacon.py:185`

### __init__ (method) `def __init__(self, blob)`
- Defined: `beacon.py:221`
- Doc: Parsear cabeceras ELF y preparar estructuras.

### _shdr (method) `def _shdr(self, idx)`
- Defined: `beacon.py:257`
- Doc: Leer una section header por índice.

### _find_sym_str (method) `def _find_sym_str(self)`
- Defined: `beacon.py:269`
- Doc: Encontrar índices de las secciones SHT_SYMTAB y SHT_STRTAB.

### _preresolve_external_symbols (method) `def _preresolve_external_symbols(self)`
- Defined: `beacon.py:297`
- Doc: FASE 1: Pre-resolver TODOS los símbolos externos antes de mapear secciones.

### load (method) `def load(self)`
- Defined: `beacon.py:363`
- Doc: Cargar y preparar el ELF para ejecución.

### _reloc (method) `def _reloc(self)`
- Defined: `beacon.py:427`
- Doc: Aplicar todas las relocalizaciones usando símbolos pre-resueltos,

### _get_symbol_value (method) `def _get_symbol_value(self, idx)`
- Defined: `beacon.py:490`
- Doc: Obtener el valor (dirección) de un símbolo por su índice.

### _find_sym (method) `def _find_sym(self, name)`
- Defined: `beacon.py:529`
- Doc: Buscar un símbolo por nombre.

### run (method) `def run(self, func, args)`
- Defined: `beacon.py:552`
- Doc: Ejecuta el BOF delegando la llamada a la librería C externa 'libbofloader.so',

### cleanup (method) `def cleanup(self)`
- Defined: `beacon.py:589`
- Doc: Liberar todas las secciones mapeadas.

### __del__ (method) `def __del__(self)`
- Defined: `beacon.py:603`
- Doc: Destructor: limpiar memoria automáticamente

## lazyown_minimal_c2.py

### encrypt_data (function) `def encrypt_data(data)`
- Defined: `lazyown_minimal_c2.py:22`

### decrypt_data (function) `def decrypt_data(b64data, is_file)`
- Defined: `lazyown_minimal_c2.py:28`

### init_db (function) `def init_db()`
- Defined: `lazyown_minimal_c2.py:36`

### send_command (function) `def send_command(client_id)`
- Defined: `lazyown_minimal_c2.py:50`

### recv_result (function) `def recv_result(client_id)`
- Defined: `lazyown_minimal_c2.py:55`

### upload (function) `def upload()`
- Defined: `lazyown_minimal_c2.py:70`

### download (function) `def download(filename)`
- Defined: `lazyown_minimal_c2.py:81`

### panel (function) `def panel()`
- Defined: `lazyown_minimal_c2.py:91`

## loader_wrapper.c

### execute_bof (function) `void execute_bof(void* go_addr, char* args, int len)`
- Defined: `loader_wrapper.c:8`

### void (function) `typedef void (*bof_func)(char*, int);`
- Defined: `loader_wrapper.c:6`
- Doc: include <stdio.h> include <stdlib.h> include <sys/mman.h> include <stdint.h> include <string.h>

### perror (function) `perror("mmap para el stack falló");`
- Defined: `loader_wrapper.c:15`

### munmap (function) `munmap(stack, stack_size);`
- Defined: `loader_wrapper.c:52`
- Doc: 3. Liberar la memoria del stack del BOF
