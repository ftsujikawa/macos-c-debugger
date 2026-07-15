#ifndef CDBG_AST_EVAL_H
#define CDBG_AST_EVAL_H

#include "ast.h"
#include "expr.h"
#include "varinfo.h"

/* Parses text with the generated flex/bison expression grammar
 * (ast_expr.l / ast_expr.y). Returns NULL and prints a diagnostic to
 * stderr on a syntax error. Caller owns the result (cdbg_ast_free). */
cdbg_ast_t *cdbg_ast_parse(const char *text);

/* True for node kinds that can denote a memory location (variable,
 * member/arrow access, array/pointer indexing, pointer dereference).
 * Arithmetic, literals, and address-of are not lvalue-shaped. */
bool cdbg_ast_is_lvalue_shaped(const cdbg_ast_t *node);

/* Evaluates node to a scalar rvalue: literals, arithmetic, variable
 * reads, pointer dereference reads, and &lvalue address-of. */
int cdbg_ast_eval(cdbg_t *dbg, cdbg_ast_t *node, cdbg_expr_result_t *out);

/* Resolves an lvalue-shaped node to a memory location: address plus a
 * full description of what's stored there (type, size, signedness,
 * pointer-ness, and, for a bare array variable, its element type/count).
 * Used by "print"/"p" (to decide scalar vs struct vs array display),
 * "set" (assignment target), and "watch" (watchpoint target). */
int cdbg_ast_resolve_lvalue(cdbg_t *dbg, cdbg_ast_t *node, uintptr_t *addr_out,
                            cdbg_var_info_t *var_out);

#endif /* CDBG_AST_EVAL_H */
