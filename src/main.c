#include <stdio.h>
#include <stdlib.h>

#include "debugger.h"

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <program> [args...]\n", prog);
    fprintf(stderr, "Interactive debugger for C programs on macOS (ptrace-based).\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    cdbg_t dbg;
    if (cdbg_init(&dbg) != 0) {
        return EXIT_FAILURE;
    }

    if (cdbg_spawn(&dbg, &argv[1]) != 0) {
        return EXIT_FAILURE;
    }

    if (cdbg_wait(&dbg) != 0) {
        return EXIT_FAILURE;
    }

    printf("Attached to pid %d (initial stop)\n", dbg.pid);

    if (cdbg_refresh_regs(&dbg) != 0) {
        return EXIT_FAILURE;
    }

    if (cdbg_repl(&dbg) != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
