%{
/*
 * Lexer for the C-like expression grammar used by "print"/"p" and "set"
 * (and, via cdbg_resolve_lvalue_expr_sized, "watch"). See ast_expr.y for
 * the grammar and ast_eval.c for how the resulting AST is evaluated /
 * resolved to an lvalue.
 */
#include "ast.h"
#include "ast_expr.tab.h"
#include <stdlib.h>
#include <string.h>
%}

%option prefix="exprp"
%option noyywrap nounput noinput
%option never-interactive

DIGIT   [0-9]
HEX     [0-9a-fA-F]

%%

[ \t]+                  { /* skip */ }

0[xX]{HEX}+             { exprplval.num = strtoull(yytext, NULL, 16); return NUMBER; }
{DIGIT}+"."{DIGIT}*([eE][+-]?{DIGIT}+)?[fFlL]? |
{DIGIT}*"."{DIGIT}+([eE][+-]?{DIGIT}+)?[fFlL]? |
{DIGIT}+[eE][+-]?{DIGIT}+[fFlL]?               { exprplval.fnum = strtod(yytext, NULL); return FLOATNUM; }
{DIGIT}+                { exprplval.num = strtoull(yytext, NULL, 0); return NUMBER; }

[a-zA-Z_][a-zA-Z0-9_]*  { exprplval.str = strdup(yytext); return IDENT; }

"->"                     { return ARROW; }
"<<"                     { return LSHIFT; }
">>"                     { return RSHIFT; }
"<="                     { return LE; }
">="                     { return GE; }
"=="                     { return EQ; }
"!="                     { return NE; }
"&&"                     { return ANDAND; }
"||"                     { return OROR; }

[-+*/%&|^!~<>().\[\]]    { return yytext[0]; }

.                        { return INVALID_CHAR; }

%%
