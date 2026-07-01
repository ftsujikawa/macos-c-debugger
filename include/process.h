#ifndef CDBG_PROCESS_H
#define CDBG_PROCESS_H

#include <sys/types.h>

int cdbg_process_spawn(pid_t *child_pid, char *const argv[]);
int cdbg_process_wait(pid_t pid, int *status);

#endif /* CDBG_PROCESS_H */
