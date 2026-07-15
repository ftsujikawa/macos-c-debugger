#ifndef CDBG_REPL_CMDS_H
#define CDBG_REPL_CMDS_H

#include "debugger.h"

/* Outcome of dispatching one parsed REPL command line, mirroring what the
 * old inline strtok-dispatch loop used to signal via continue/return. */
typedef enum {
    CDBG_REPL_OK,    /* handled; read the next line */
    CDBG_REPL_QUIT,  /* "quit"/"q": stop the REPL cleanly */
    CDBG_REPL_FATAL, /* unrecoverable ptrace/wait failure: abort the REPL */
} cdbg_repl_outcome_t;

/* Handlers whose body has REPL loop control flow baked in (state checks,
 * fatal-error propagation). Extracted verbatim from the old dispatch loop. */
cdbg_repl_outcome_t cdbg_repl_cmd_continue(cdbg_t *dbg);
cdbg_repl_outcome_t cdbg_repl_cmd_step(cdbg_t *dbg);
cdbg_repl_outcome_t cdbg_repl_cmd_si(cdbg_t *dbg);
cdbg_repl_outcome_t cdbg_repl_cmd_next(cdbg_t *dbg);
cdbg_repl_outcome_t cdbg_repl_cmd_regs(cdbg_t *dbg);
cdbg_repl_outcome_t cdbg_repl_cmd_kill(cdbg_t *dbg);
cdbg_repl_outcome_t cdbg_repl_cmd_quit(cdbg_t *dbg);

/* Plain one-shot command handlers (return value already ignored by the REPL). */
int  cmd_help(char *args);
int  cmd_run(cdbg_t *dbg, char *args);
void cmd_print_from_repl(cdbg_t *dbg, const char *cmd, char *rest);
int  cmd_set(cdbg_t *dbg, char *args);
int  cmd_show(cdbg_t *dbg, char *args);
int  cmd_backtrace(cdbg_t *dbg);
int  cmd_leaks(cdbg_t *dbg);
int  cmd_break(cdbg_t *dbg, const char *target);
int  cmd_del(cdbg_t *dbg, char *args);
int  cmd_watch(cdbg_t *dbg, char *expr);
int  cmd_unwatch(cdbg_t *dbg, char *args);
int  cmd_dis(cdbg_t *dbg, const char *target);
int  cmd_list(cdbg_t *dbg, char *target);
int  cmd_lines(cdbg_t *dbg, const char *file_filter);
int  cmd_examine(cdbg_t *dbg, const char *addr_text, const char *count_text);

/* Parses and dispatches a single trimmed, non-empty REPL input line
 * (no trailing newline). Implemented by the generated flex/bison
 * command parser (src/cmd_lexer.l / src/cmd_grammar.y). */
cdbg_repl_outcome_t cdbg_repl_dispatch_line(cdbg_t *dbg, char *line);

#endif /* CDBG_REPL_CMDS_H */
