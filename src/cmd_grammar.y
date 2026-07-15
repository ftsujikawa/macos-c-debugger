%{
/*
 * Grammar for the cdbg REPL command line. Tokenizing is done by
 * cmd_lexer.l; this file only decides, per recognized command keyword,
 * how many/what shape of trailing arguments to accept and which existing
 * cmd_* handler to call with them. The handlers themselves (struct/array
 * printing, DWARF lookups, breakpoint/watchpoint bookkeeping, ...) are
 * untouched and live in debugger.c.
 */
#include "repl_cmds.h"
#include "lineno.h"
#include "syms.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern YY_BUFFER_STATE cmdyy_scan_string(const char *yystr);
extern void cmdyy_delete_buffer(YY_BUFFER_STATE b);
extern void cmdyy_reset_state(void);
extern int cmdyylex(void);

static void cmdyyerror(cdbg_t *dbg, cdbg_repl_outcome_t *out_outcome, const char *msg);
%}

%name-prefix="cmdyy"

%union {
    char *str;
}

%parse-param { cdbg_t *dbg }
%parse-param { cdbg_repl_outcome_t *out_outcome }

%token <str> WORD RESTLINE UNKNOWN_TOK PRINT_TOK
%token HELP_TOK RUN_TOK CONTINUE_TOK STEP_TOK SI_TOK NEXT_TOK UP_TOK REGS_TOK
%token SET_TOK SHOW_TOK TB_TOK LEAKS_TOK BREAK_TOK DEL_TOK WATCH_TOK
%token UNWATCH_TOK DIS_TOK LIST_TOK LINES_TOK LISTS_TOK SYMS_TOK X_TOK
%token KILL_TOK QUIT_TOK

%%

line:
      HELP_TOK                 { (void)cmd_help(NULL); }
    | HELP_TOK RESTLINE        { (void)cmd_help($2); free($2); }
    | RUN_TOK                  { (void)cmd_run(dbg, NULL); }
    | RUN_TOK RESTLINE         { (void)cmd_run(dbg, $2); free($2); }
    | CONTINUE_TOK              { *out_outcome = cdbg_repl_cmd_continue(dbg); }
    | STEP_TOK                  { *out_outcome = cdbg_repl_cmd_step(dbg); }
    | SI_TOK                    { *out_outcome = cdbg_repl_cmd_si(dbg); }
    | NEXT_TOK                  { *out_outcome = cdbg_repl_cmd_next(dbg); }
    | UP_TOK                    { (void)cdbg_frame_up(dbg); }
    | REGS_TOK                  { *out_outcome = cdbg_repl_cmd_regs(dbg); }
    | PRINT_TOK                 { cmd_print_from_repl(dbg, $1, NULL); free($1); }
    | PRINT_TOK RESTLINE        { cmd_print_from_repl(dbg, $1, $2); free($1); free($2); }
    | SET_TOK                   { (void)cmd_set(dbg, NULL); }
    | SET_TOK RESTLINE          { (void)cmd_set(dbg, $2); free($2); }
    | SHOW_TOK                  { (void)cmd_show(dbg, NULL); }
    | SHOW_TOK RESTLINE         { (void)cmd_show(dbg, $2); free($2); }
    | TB_TOK                    { (void)cmd_backtrace(dbg); }
    | LEAKS_TOK                 { (void)cmd_leaks(dbg); }
    | BREAK_TOK                 { fputs("Usage: break <addr|name|file:line|line>\n", stderr); }
    | BREAK_TOK WORD            { (void)cmd_break(dbg, $2); free($2); }
    | DEL_TOK                   { (void)cmd_del(dbg, NULL); }
    | DEL_TOK RESTLINE          { (void)cmd_del(dbg, $2); free($2); }
    | WATCH_TOK                 { (void)cmd_watch(dbg, NULL); }
    | WATCH_TOK RESTLINE        { (void)cmd_watch(dbg, $2); free($2); }
    | UNWATCH_TOK                { (void)cmd_unwatch(dbg, NULL); }
    | UNWATCH_TOK RESTLINE       { (void)cmd_unwatch(dbg, $2); free($2); }
    | DIS_TOK                   { (void)cmd_dis(dbg, NULL); }
    | DIS_TOK RESTLINE          { (void)cmd_dis(dbg, $2); free($2); }
    | LIST_TOK                  { (void)cmd_list(dbg, NULL); }
    | LIST_TOK RESTLINE         { (void)cmd_list(dbg, $2); free($2); }
    | LINES_TOK                  { (void)cmd_lines(dbg, NULL); }
    | LINES_TOK WORD             { (void)cmd_lines(dbg, $2); free($2); }
    | LISTS_TOK                  { cdbg_lineno_print_list(&dbg->lineno, NULL); }
    | LISTS_TOK WORD             { cdbg_lineno_print_list(&dbg->lineno, $2); free($2); }
    | SYMS_TOK                   { cdbg_syms_print_list(&dbg->syms, NULL); }
    | SYMS_TOK WORD              { cdbg_syms_print_list(&dbg->syms, $2); free($2); }
    | X_TOK                     { fputs("Usage: x <addr> [count]\n", stderr); }
    | X_TOK WORD                { (void)cmd_examine(dbg, $2, NULL); free($2); }
    | X_TOK WORD WORD           { (void)cmd_examine(dbg, $2, $3); free($2); free($3); }
    | KILL_TOK                   { *out_outcome = cdbg_repl_cmd_kill(dbg); }
    | QUIT_TOK                   { *out_outcome = cdbg_repl_cmd_quit(dbg); }
    | UNKNOWN_TOK                { printf("Unknown command: %s\n", $1); free($1); }
    ;

%%

static void cmdyyerror(cdbg_t *dbg, cdbg_repl_outcome_t *out_outcome, const char *msg)
{
    (void)dbg;
    (void)out_outcome;
    fprintf(stderr, "%s\n", msg);
}

cdbg_repl_outcome_t cdbg_repl_dispatch_line(cdbg_t *dbg, char *line)
{
    cdbg_repl_outcome_t outcome = CDBG_REPL_OK;

    cmdyy_reset_state();
    YY_BUFFER_STATE buf = cmdyy_scan_string(line);
    (void)cmdyyparse(dbg, &outcome);
    cmdyy_delete_buffer(buf);
    cmdyy_reset_state();

    return outcome;
}
