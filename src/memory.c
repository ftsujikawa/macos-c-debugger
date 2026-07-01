#include "memory.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

int cdbg_mem_read(pid_t pid, uintptr_t addr, void *buf, size_t len)
{
    uint8_t *out = buf;

    for (size_t i = 0; i < len; i++) {
        errno = 0;
        long word = ptrace(PT_READ_D, pid, (caddr_t)(addr + i), 0);
        if (word == -1 && errno != 0) {
            perror("ptrace(PT_READ_D)");
            return -1;
        }
        out[i] = (uint8_t)word;
    }

    return 0;
}

int cdbg_mem_write(pid_t pid, uintptr_t addr, const void *buf, size_t len)
{
    const uint8_t *in = buf;

    for (size_t i = 0; i < len; i++) {
        if (ptrace(PT_WRITE_D, pid, (caddr_t)(addr + i), in[i]) == -1) {
            perror("ptrace(PT_WRITE_D)");
            return -1;
        }
    }

    return 0;
}

int cdbg_mem_read_u64(pid_t pid, uintptr_t addr, uint64_t *out)
{
    return cdbg_mem_read(pid, addr, out, sizeof(*out));
}

int cdbg_mem_write_u64(pid_t pid, uintptr_t addr, uint64_t value)
{
    return cdbg_mem_write(pid, addr, &value, sizeof(value));
}
