# root

*Community 0 | 5 files | cohesion 1.00*

## Definition

This community groups 5 file(s) rooted at `root` with dominant language py (cohesion 1.00). Central symbols: `BeaconOutput_stub`, `BeaconPrintf_stub`, `RunELF`, `__del__`, `__init__`, `_find_sym`, `_find_sym_str`, `_get_symbol_value`. Core file: `beacon.py` (24 symbols). Documented purpose: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `app.py` | py | utility | 0 | yes |
| `beacon.py` | py | utility | 24 | yes |
| `install.sh` | sh | utility | 0 | no |
| `lazyown_minimal_c2.py` | py | presentation | 8 | yes |
| `loader_wrapper.c` | c | utility | 1 | no |

## Key Symbols

- `aes_cfb_decrypt` (function, `beacon.py:87`) `def aes_cfb_decrypt(data_b64)`
- `aes_cfb_encrypt` (function, `beacon.py:94`) `def aes_cfb_encrypt(data)`
- `get_ips` (function, `beacon.py:102`) `def get_ips()`
- `exec_cmd` (function, `beacon.py:113`) `def exec_cmd(cmd)`
- `set_executable_permissions` (function, `beacon.py:120`) `def set_executable_permissions(address, size)` - Establece los permisos R+W+X en una región de memoria.
- `init_beacon_stubs` (function, `beacon.py:162`) `def init_beacon_stubs()`
- `BeaconPrintf_stub` (method, `beacon.py:170`) `def BeaconPrintf_stub(_type, fmt)`
- `BeaconOutput_stub` (method, `beacon.py:185`) `def BeaconOutput_stub(_type, data, length)`
- `align` (function, `beacon.py:210`) `def align(x, a)` - Alinear x al múltiplo superior de a
- `RunELF` (class, `beacon.py:215`) `class RunELF` - Loader ELF ET_REL (relocable) para ejecutar BOFs en Python.
- `__init__` (method, `beacon.py:221`) `def __init__(self, blob)` - Parsear cabeceras ELF y preparar estructuras.
- `_shdr` (method, `beacon.py:257`) `def _shdr(self, idx)` - Leer una section header por índice.
- `_find_sym_str` (method, `beacon.py:269`) `def _find_sym_str(self)` - Encontrar índices de las secciones SHT_SYMTAB y SHT_STRTAB.
- `_preresolve_external_symbols` (method, `beacon.py:297`) `def _preresolve_external_symbols(self)` - FASE 1: Pre-resolver TODOS los símbolos externos antes de mapear secciones.
- `load` (method, `beacon.py:363`) `def load(self)` - Cargar y preparar el ELF para ejecución.
- `_reloc` (method, `beacon.py:427`) `def _reloc(self)` - Aplicar todas las relocalizaciones usando símbolos pre-resueltos,
- `_get_symbol_value` (method, `beacon.py:490`) `def _get_symbol_value(self, idx)` - Obtener el valor (dirección) de un símbolo por su índice.
- `_find_sym` (method, `beacon.py:529`) `def _find_sym(self, name)` - Buscar un símbolo por nombre.
- `run` (method, `beacon.py:552`) `def run(self, func, args)` - Ejecuta el BOF delegando la llamada a la librería C externa 'libbofloader.so',
- `cleanup` (method, `beacon.py:589`) `def cleanup(self)` - Liberar todas las secciones mapeadas.
- `__del__` (method, `beacon.py:603`) `def __del__(self)` - Destructor: limpiar memoria automáticamente
- `run_bof_and_capture` (method, `beacon.py:612`) `def run_bof_and_capture(elf_blob, args)`
- `download_bof` (method, `beacon.py:628`) `def download_bof(url)`
- `beacon` (method, `beacon.py:640`) `def beacon()`
- `encrypt_data` (function, `lazyown_minimal_c2.py:22`) `def encrypt_data(data)`
- `decrypt_data` (function, `lazyown_minimal_c2.py:28`) `def decrypt_data(b64data, is_file)`
- `init_db` (function, `lazyown_minimal_c2.py:36`) `def init_db()`
- `send_command` (function, `lazyown_minimal_c2.py:50`) `def send_command(client_id)`
- `recv_result` (function, `lazyown_minimal_c2.py:55`) `def recv_result(client_id)`
- `upload` (function, `lazyown_minimal_c2.py:70`) `def upload()`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- [taint medium] `beacon.py` -> `beacon.py` via `requests` (0 hops)
- [taint high] `beacon.py` -> `beacon.py` via `subprocess` (0 hops)
- [dataflow UNCHECKED_ALLOC] `beacon.py:105` `get_ips` `s`: Result of allocator stored in `s` is never checked against NULL.

## Open Questions

- Why do 2 file(s) lack file-level docs (e.g. `install.sh`)? What purpose do they serve?
- Is the dangerous import `requests` in `beacon.py` still required, or can it be isolated?
- What would break if the most connected file in root changed?
- Should root be split, given cohesion 1.00?

## Sources

- `app.py`
- `beacon.py`
- `install.sh`
- `lazyown_minimal_c2.py`
- `loader_wrapper.c`
