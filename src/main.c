#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debugger.h"
#include "process.h"

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

    char program[PATH_MAX];
    if (cdbg_resolve_program(argv[1], program, sizeof(program)) != 0) {
        fprintf(stderr, "cdbg: invalid program path: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    char *spawn_argv[256];
    if (argc > (int)(sizeof(spawn_argv) / sizeof(spawn_argv[0]))) {
        fprintf(stderr, "cdbg: too many arguments\n");
        return EXIT_FAILURE;
    }
    size_t spawn_argc = 0;
    spawn_argv[spawn_argc++] = program;
    for (int i = 2; i < argc; i++) {
        spawn_argv[spawn_argc++] = argv[i];
    }
    spawn_argv[spawn_argc] = NULL;

    cdbg_t dbg;
    if (cdbg_init(&dbg) != 0) {
        return EXIT_FAILURE;
    }

    if (cdbg_set_run_target(&dbg, spawn_argv) != 0) {
        return EXIT_FAILURE;
    }

    if (cdbg_run(&dbg, NULL) != 0) {
        return EXIT_FAILURE;
    }

    if (cdbg_repl(&dbg) != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
