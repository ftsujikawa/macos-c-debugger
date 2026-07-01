#include "process.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int cdbg_process_spawn(pid_t *child_pid, char *const argv[])
{
    if (argv == NULL || argv[0] == NULL) {
        errno = EINVAL;
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        if (ptrace(PT_TRACE_ME, 0, NULL, 0) == -1) {
            perror("ptrace(PT_TRACE_ME)");
            _exit(127);
        }

        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    }

    *child_pid = pid;
    return 0;
}

int cdbg_process_wait(pid_t pid, int *status)
{
    if (waitpid(pid, status, 0) == -1) {
        perror("waitpid");
        return -1;
    }
    return 0;
}
