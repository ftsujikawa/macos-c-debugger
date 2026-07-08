#include "process.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int cdbg_resolve_program(const char *name, char *out, size_t out_len)
{
    if (name == NULL || out == NULL || out_len == 0) {
        errno = EINVAL;
        return -1;
    }

    if (strchr(name, '/') != NULL) {
        if (snprintf(out, out_len, "%s", name) >= (int)out_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }

    char cwd_path[PATH_MAX];
    if (snprintf(cwd_path, sizeof(cwd_path), "./%s", name) >= (int)sizeof(cwd_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (access(cwd_path, X_OK) == 0) {
        if (snprintf(out, out_len, "%s", cwd_path) >= (int)out_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }

    if (snprintf(out, out_len, "%s", name) >= (int)out_len) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

int cdbg_process_spawn(pid_t *child_pid, char *const argv[], bool malloc_stack_logging)
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
        setpgid(0, 0);

        if (ptrace(PT_TRACE_ME, 0, NULL, 0) == -1) {
            perror("ptrace(PT_TRACE_ME)");
            _exit(127);
        }

        if (malloc_stack_logging) {
            setenv("MallocStackLogging", "1", 1);
        }

        execv(argv[0], argv);
        perror(argv[0]);
        _exit(127);
    }

    *child_pid = pid;
    return 0;
}

int cdbg_process_wait(pid_t pid, int *status)
{
    int ret;
    do {
        ret = waitpid(pid, status, 0);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1) {
        perror("waitpid");
        return -1;
    }
    return 0;
}
