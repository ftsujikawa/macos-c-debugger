#ifndef CDBG_DEBUGGER_H
#define CDBG_DEBUGGER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "breakpoint.h"
#include "regs.h"

#define CDBG_MAX_BREAKPOINTS 64
#define CDBG_MAX_CMD         256

typedef enum {
    CDBG_STATE_IDLE,
    CDBG_STATE_RUNNING,
    CDBG_STATE_STOPPED,
} cdbg_state_t;

typedef struct cdbg {
    pid_t pid;
    cdbg_state_t state;
    int wait_status;
    cdbg_regs_t regs;
    cdbg_breakpoint_t breakpoints[CDBG_MAX_BREAKPOINTS];
    size_t breakpoint_count;
} cdbg_t;

int  cdbg_init(cdbg_t *dbg);
int  cdbg_spawn(cdbg_t *dbg, char *const argv[]);
int  cdbg_wait(cdbg_t *dbg);
int  cdbg_continue(cdbg_t *dbg);
int  cdbg_single_step(cdbg_t *dbg);
int  cdbg_refresh_regs(cdbg_t *dbg);
void cdbg_print_regs(const cdbg_t *dbg);
int  cdbg_repl(cdbg_t *dbg);

#endif /* CDBG_DEBUGGER_H */
