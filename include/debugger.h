#ifndef CDBG_DEBUGGER_H
#define CDBG_DEBUGGER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "breakpoint.h"
#include "lineno.h"
#include "regs.h"
#include "syms.h"

#define CDBG_MAX_BREAKPOINTS 64
#define CDBG_MAX_CMD         256
#define CDBG_MAX_PATH        1024

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
    cdbg_lineno_t lineno;
    cdbg_syms_t syms;
    char executable_path[CDBG_MAX_PATH];
    char debug_info_path[CDBG_MAX_PATH];
} cdbg_t;

int  cdbg_init(cdbg_t *dbg);
int  cdbg_load_symbols(cdbg_t *dbg, const char *executable_path);
int  cdbg_spawn(cdbg_t *dbg, char *const argv[]);
int  cdbg_wait(cdbg_t *dbg);
int  cdbg_continue(cdbg_t *dbg);
int  cdbg_single_step(cdbg_t *dbg);
int  cdbg_step_next_line(cdbg_t *dbg);
int  cdbg_next_source_line(cdbg_t *dbg);
int  cdbg_frame_up(cdbg_t *dbg);
int  cdbg_refresh_regs(cdbg_t *dbg);
void cdbg_print_regs(const cdbg_t *dbg);
void cdbg_print_stop_context(cdbg_t *dbg);
int  cdbg_repl(cdbg_t *dbg);

#endif /* CDBG_DEBUGGER_H */
