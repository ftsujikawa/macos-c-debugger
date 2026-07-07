#ifndef CDBG_PROCESS_H
#define CDBG_PROCESS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

int cdbg_resolve_program(const char *name, char *out, size_t out_len);
int cdbg_process_spawn(pid_t *child_pid, char *const argv[], bool malloc_stack_logging);
int cdbg_process_wait(pid_t pid, int *status);

#endif /* CDBG_PROCESS_H */
