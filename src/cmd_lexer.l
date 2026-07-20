%{
/*
 * Lexer for the cdbg REPL command line. Each input line is fed through
 * cmdyy_scan_string() exactly once (see cdbg_repl_dispatch_line in
 * cmd_grammar.y) so no newline handling or multi-line state is needed.
 *
 * A recognized command keyword switches the scanner into ARGSTATE (capture
 * everything remaining on the line as one RESTLINE token, for commands that
 * take a free-form argument like "print", "set", "run") or WORDSTATE
 * (tokenize the remainder as individual whitespace-separated WORDs, for
 * commands like "break" and "x" that take one or two simple tokens).
 *
 * The start-condition state (YY_START) is a global that survives across
 * separate yy_scan_string() calls in this non-reentrant scanner. A line
 * that ends mid-ARGSTATE/WORDSTATE (e.g. because bison hit a syntax error
 * and stopped pulling tokens before the scanner reached <<EOF>>) would
 * otherwise leak that state into the next command's parse. cdbg_repl_
 * dispatch_line() calls cmdyy_reset_state() before every parse to guard
 * against that.
 */
#include "cmd_grammar.tab.h"
#include <stdlib.h>
#include <string.h>
%}

%option prefix="cmdyy"
%option noyywrap nounput noinput
%option never-interactive

%x ARGSTATE
%x WORDSTATE

%%

<INITIAL>[ \t]+                        { /* skip leading whitespace */ }

<INITIAL>"help"|"h"                    { BEGIN(ARGSTATE); return HELP_TOK; }
<INITIAL>"run"                         { BEGIN(ARGSTATE); return RUN_TOK; }
<INITIAL>"continue"|"c"                { return CONTINUE_TOK; }
<INITIAL>"step"|"s"                    { return STEP_TOK; }
<INITIAL>"si"                          { return SI_TOK; }
<INITIAL>"next"|"n"                    { return NEXT_TOK; }
<INITIAL>"up"                          { return UP_TOK; }
<INITIAL>"regs"|"r"                    { return REGS_TOK; }
<INITIAL>"print"|"p"|"print/"[^ \t]*|"p/"[^ \t]* {
                                            cmdyylval.str = strdup(yytext);
                                            BEGIN(ARGSTATE);
                                            return PRINT_TOK;
                                        }
<INITIAL>"set"                         { BEGIN(ARGSTATE); return SET_TOK; }
<INITIAL>"show"                        { BEGIN(ARGSTATE); return SHOW_TOK; }
<INITIAL>"tb"                          { return TB_TOK; }
<INITIAL>"threads"                     { return THREADS_TOK; }
<INITIAL>"thread"                      { BEGIN(WORDSTATE); return THREAD_TOK; }
<INITIAL>"lock"                        { BEGIN(WORDSTATE); return LOCK_TOK; }
<INITIAL>"unlock"                      { return UNLOCK_TOK; }
<INITIAL>"leaks"                       { return LEAKS_TOK; }
<INITIAL>"break"|"b"                   { BEGIN(WORDSTATE); return BREAK_TOK; }
<INITIAL>"del"|"delete"                { BEGIN(ARGSTATE); return DEL_TOK; }
<INITIAL>"watch"                       { BEGIN(ARGSTATE); return WATCH_TOK; }
<INITIAL>"unwatch"                     { BEGIN(ARGSTATE); return UNWATCH_TOK; }
<INITIAL>"dis"                         { BEGIN(ARGSTATE); return DIS_TOK; }
<INITIAL>"list"|"l"                    { BEGIN(ARGSTATE); return LIST_TOK; }
<INITIAL>"lines"                       { BEGIN(WORDSTATE); return LINES_TOK; }
<INITIAL>"lists"                       { BEGIN(WORDSTATE); return LISTS_TOK; }
<INITIAL>"syms"|"sym"                  { BEGIN(WORDSTATE); return SYMS_TOK; }
<INITIAL>"x"                           { BEGIN(WORDSTATE); return X_TOK; }
<INITIAL>"kill"                        { return KILL_TOK; }
<INITIAL>"quit"|"q"                    { return QUIT_TOK; }

<INITIAL>[^ \t]+                       { cmdyylval.str = strdup(yytext); return UNKNOWN_TOK; }
<INITIAL><<EOF>>                       { return 0; }

<ARGSTATE>[ \t]+                       { /* skip */ }
<ARGSTATE>[^ \t][^\n]*                 {
                                            cmdyylval.str = strdup(yytext);
                                            BEGIN(INITIAL);
                                            return RESTLINE;
                                        }
<ARGSTATE><<EOF>>                      { BEGIN(INITIAL); return 0; }

<WORDSTATE>[ \t]+                      { /* skip */ }
<WORDSTATE>[^ \t]+                     { cmdyylval.str = strdup(yytext); return WORD; }
<WORDSTATE><<EOF>>                     { BEGIN(INITIAL); return 0; }

%%

void cmdyy_reset_state(void)
{
    BEGIN(INITIAL);
}
