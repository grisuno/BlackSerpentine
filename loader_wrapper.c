#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

typedef void (*bof_func)(char*, int);

void execute_bof(void* go_addr, char* args, int len) {
    // 1. Mapear un nuevo stack para el BOF (64KB)
    size_t stack_size = 65536;
    void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        perror("mmap para el stack falló");
        return;
    }

    // Apuntar al final del stack, dejando 128 bytes de "red zone"
    void* stack_top = stack + stack_size - 128;

    bof_func entry = (bof_func)go_addr;

    // 2. Ensamblador inline para aislar la ejecución y proteger registros
    __asm__ __volatile__(
        // --- Prólogo: Preservar el estado del llamador (Python/ctypes) ---
        "pushq %%rcx;"              // Guardar rcx
        "pushq %%r11;"              // Guardar r11
        "movq %%rsp, %%r15;"         // Guardar RSP original en un registro seguro (callee-saved)

        // --- Cambio de Stack ---
        "movq %0, %%rsp;"            // Cambiar al nuevo stack del BOF
        "andq $-16, %%rsp;"          // Asegurar alineación de 16 bytes

        // --- Llamada al BOF ---
        // Los argumentos 'args' y 'len' se pasan a través de RDI y RSI
        // gracias a los constraints "D" y "S" del asm.
        "call *%1;"                  // Llamar a la función 'go' del BOF

        // --- Epílogo: Restaurar el estado del llamador ---
        "movq %%r15, %%rsp;"         // Restaurar el RSP original
        "popq %%r11;"               // Restaurar r11
        "popq %%rcx;"               // Restaurar rcx

        : // Sin operandos de salida
        : "r"(stack_top), "r"(entry), "D"(args), "S"(len)
        // Lista de clobbers: informa al compilador qué registros se modifican
        : "rax", "rdx", "r8", "r9", "r10", "memory"
    );

    // 3. Liberar la memoria del stack del BOF
    munmap(stack, stack_size);
}
