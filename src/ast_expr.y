%{
/*
 * Grammar for the C-like expression language shared by "print"/"p" and
 * "set" (and "watch", via cdbg_resolve_lvalue_expr_sized). Precedence is
 * declared below instead of being encoded as a chain of mutually
 * recursive parse functions. Semantic actions only build an AST
 * (ast.h); evaluating it (arithmetic) or resolving it to an lvalue
 * (address + type, for print's struct/array display and set's
 * assignment target) happens afterwards in ast_eval.c, reusing the
 * existing DWARF/symbol lookups in debugger.c unchanged.
 */
#include "ast.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern YY_BUFFER_STATE exprp_scan_string(const char *yystr);
extern void exprp_delete_buffer(YY_BUFFER_STATE b);
extern int exprplex(void);

static void exprperror(cdbg_ast_t **out_ast, const char *msg);
%}

%name-prefix="exprp"
%error-verbose

%union {
    uint64_t     num;
    double       fnum;
    char        *str;
    cdbg_ast_t  *ast;
}

%parse-param { cdbg_ast_t **out_ast }

%token <num> NUMBER
%token <fnum> FLOATNUM
%token <str> IDENT
%token ARROW LSHIFT RSHIFT LE GE EQ NE ANDAND OROR INVALID_CHAR

%type <ast> expr

%left OROR
%left ANDAND
%left '|'
%left '^'
%left '&'
%left EQ NE
%left '<' '>' LE GE
%left LSHIFT RSHIFT
%left '+' '-'
%left '*' '/' '%'
%right UNARY_PREC
%left '.' ARROW '['

%%

start: expr { *out_ast = $1; }
     ;

expr:
      expr OROR expr             { $$ = cdbg_ast_new_binop(CDBG_AST_OP_LOR, $1, $3); }
    | expr ANDAND expr           { $$ = cdbg_ast_new_binop(CDBG_AST_OP_LAND, $1, $3); }
    | expr '|' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_BOR, $1, $3); }
    | expr '^' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_BXOR, $1, $3); }
    | expr '&' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_BAND, $1, $3); }
    | expr EQ expr               { $$ = cdbg_ast_new_binop(CDBG_AST_OP_EQ, $1, $3); }
    | expr NE expr               { $$ = cdbg_ast_new_binop(CDBG_AST_OP_NE, $1, $3); }
    | expr '<' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_LT, $1, $3); }
    | expr '>' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_GT, $1, $3); }
    | expr LE expr               { $$ = cdbg_ast_new_binop(CDBG_AST_OP_LE, $1, $3); }
    | expr GE expr               { $$ = cdbg_ast_new_binop(CDBG_AST_OP_GE, $1, $3); }
    | expr LSHIFT expr           { $$ = cdbg_ast_new_binop(CDBG_AST_OP_SHL, $1, $3); }
    | expr RSHIFT expr           { $$ = cdbg_ast_new_binop(CDBG_AST_OP_SHR, $1, $3); }
    | expr '+' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_ADD, $1, $3); }
    | expr '-' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_SUB, $1, $3); }
    | expr '*' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_MUL, $1, $3); }
    | expr '/' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_DIV, $1, $3); }
    | expr '%' expr              { $$ = cdbg_ast_new_binop(CDBG_AST_OP_MOD, $1, $3); }
    | '+' expr %prec UNARY_PREC  { $$ = cdbg_ast_new_unop(CDBG_AST_POS, $2); }
    | '-' expr %prec UNARY_PREC  { $$ = cdbg_ast_new_unop(CDBG_AST_NEG, $2); }
    | '!' expr %prec UNARY_PREC  { $$ = cdbg_ast_new_unop(CDBG_AST_NOT, $2); }
    | '~' expr %prec UNARY_PREC  { $$ = cdbg_ast_new_unop(CDBG_AST_BNOT, $2); }
    | '&' expr %prec UNARY_PREC  { $$ = cdbg_ast_new_unop(CDBG_AST_ADDR, $2); }
    | '*' expr %prec UNARY_PREC  { $$ = cdbg_ast_new_unop(CDBG_AST_DEREF, $2); }
    | expr '.' IDENT             { $$ = cdbg_ast_new_member($1, $3); }
    | expr ARROW IDENT           { $$ = cdbg_ast_new_arrow($1, $3); }
    | expr '[' expr ']'          { $$ = cdbg_ast_new_index($1, $3); }
    | '(' expr ')'               { $$ = $2; }
    | NUMBER                     { $$ = cdbg_ast_new_num($1); }
    | FLOATNUM                   { $$ = cdbg_ast_new_float($1); }
    | IDENT                      { $$ = cdbg_ast_new_ident($1); }
    ;

%%

static void exprperror(cdbg_ast_t **out_ast, const char *msg)
{
    (void)out_ast;
    fprintf(stderr, "%s\n", msg);
}

cdbg_ast_t *cdbg_ast_parse(const char *text)
{
    cdbg_ast_t *ast = NULL;

    YY_BUFFER_STATE buf = exprp_scan_string(text);
    int rc = exprpparse(&ast);
    exprp_delete_buffer(buf);

    if (rc != 0) {
        cdbg_ast_free(ast);
        return NULL;
    }
    return ast;
}
