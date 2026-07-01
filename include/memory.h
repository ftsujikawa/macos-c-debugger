#ifndef CDBG_MEMORY_H
#define CDBG_MEMORY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int cdbg_mem_read(pid_t pid, uintptr_t addr, void *buf, size_t len);
int cdbg_mem_write(pid_t pid, uintptr_t addr, const void *buf, size_t len);
int cdbg_mem_read_u64(pid_t pid, uintptr_t addr, uint64_t *out);
int cdbg_mem_write_u64(pid_t pid, uintptr_t addr, uint64_t value);

#endif /* CDBG_MEMORY_H */
