# Subsystem: root

## app.py
- Layer: utility
- Doc: _*_ coding: utf8 _*_
- Language: py

## beacon.py
- Layer: utility
- Language: py
- Symbols:
  - `aes_cfb_decrypt` (function, line 87) `def aes_cfb_decrypt(data_b64)`
  - `aes_cfb_encrypt` (function, line 94) `def aes_cfb_encrypt(data)`
  - `get_ips` (function, line 102) `def get_ips()`
  - `exec_cmd` (function, line 113) `def exec_cmd(cmd)`
  - `set_executable_permissions` (function, line 120) `def set_executable_permissions(address, size)`
  - `init_beacon_stubs` (function, line 162) `def init_beacon_stubs()`
  - `align` (function, line 210) `def align(x, a)`
  - `RunELF` (class, line 215) `class RunELF`
  - `run_bof_and_capture` (method, line 612) `def run_bof_and_capture(elf_blob, args)`
  - `download_bof` (method, line 628) `def download_bof(url)`
  - `beacon` (method, line 640) `def beacon()`
  - `BeaconPrintf_stub` (method, line 170) `def BeaconPrintf_stub(_type, fmt)`
  - `BeaconOutput_stub` (method, line 185) `def BeaconOutput_stub(_type, data, length)`
  - `__init__` (method, line 221) `def __init__(self, blob)`
  - `_shdr` (method, line 257) `def _shdr(self, idx)`
  - `_find_sym_str` (method, line 269) `def _find_sym_str(self)`
  - `_preresolve_external_symbols` (method, line 297) `def _preresolve_external_symbols(self)`
  - `load` (method, line 363) `def load(self)`
  - `_reloc` (method, line 427) `def _reloc(self)`
  - `_get_symbol_value` (method, line 490) `def _get_symbol_value(self, idx)`
  - `_find_sym` (method, line 529) `def _find_sym(self, name)`
  - `run` (method, line 552) `def run(self, func, args)`
  - `cleanup` (method, line 589) `def cleanup(self)`
  - `__del__` (method, line 603) `def __del__(self)`

## install.sh
- Layer: utility
- Language: sh

## lazyown_minimal_c2.py
- Layer: presentation
- Language: py
- Symbols:
  - `encrypt_data` (function, line 22) `def encrypt_data(data)`
  - `decrypt_data` (function, line 28) `def decrypt_data(b64data, is_file)`
  - `init_db` (function, line 36) `def init_db()`
  - `send_command` (function, line 50) `def send_command(client_id)`
  - `recv_result` (function, line 55) `def recv_result(client_id)`
  - `upload` (function, line 70) `def upload()`
  - `download` (function, line 81) `def download(filename)`
  - `panel` (function, line 91) `def panel()`

## loader_wrapper.c
- Layer: utility
- Doc: include <stdio.h> include <stdlib.h> include <sys/mman.h> include <stdint.h> include <string.h>
- Language: c
- Symbols:
  - `execute_bof` (function, line 8) `void execute_bof(void* go_addr, char* args, int len)`
  - `void` (function, line 6) `typedef void (*bof_func)(char*, int);`
  - `perror` (function, line 15) `perror("mmap para el stack falló");`
  - `munmap` (function, line 52) `munmap(stack, stack_size);`
