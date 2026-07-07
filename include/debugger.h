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
#define CDBG_MAX_RUN_ARGS    64

typedef enum {
    CDBG_STATE_IDLE,
    CDBG_STATE_RUNNING,
    CDBG_STATE_STOPPED,
} cdbg_state_t;

typedef enum {
    CDBG_LANG_AUTO,
    CDBG_LANG_C,
    CDBG_LANG_CXX,
    CDBG_LANG_OBJC,
    CDBG_LANG_FORTRAN,
    CDBG_LANG_PASCAL,
    CDBG_LANG_ADA,
    CDBG_LANG_MODULA2,
    CDBG_LANG_JAVA,
    CDBG_LANG_GO,
    CDBG_LANG_RUST,
    CDBG_LANG_ASSEMBLY,
} cdbg_language_t;

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
    char run_argv_storage[CDBG_MAX_RUN_ARGS][CDBG_MAX_PATH];
    char *run_argv[CDBG_MAX_RUN_ARGS + 1];
    size_t run_argc;
    bool print_pretty;
    bool malloc_stack_logging;
    cdbg_language_t language;
} cdbg_t;

int           cdbg_language_parse(const char *name, cdbg_language_t *out);
const char   *cdbg_language_name(cdbg_language_t lang);
cdbg_language_t cdbg_language_effective(const cdbg_t *dbg);
bool          cdbg_language_supports_expr(cdbg_language_t lang);
int           cdbg_language_check_expr(const cdbg_t *dbg);
int           cdbg_resolve_lvalue_expr(cdbg_t *dbg, char *expr, uintptr_t *addr_out,
                                       char *type_out, size_t type_out_len);

int  cdbg_init(cdbg_t *dbg);
int  cdbg_set_run_target(cdbg_t *dbg, char *const argv[]);
int  cdbg_run(cdbg_t *dbg, char *const argv[]);
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
