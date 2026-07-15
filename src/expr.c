#include "expr.h"

#include "ast.h"
#include "ast_eval.h"
#include "debugger.h"

#include <string.h>

/* Thin compatibility wrapper: the actual lexing/parsing (ast_expr.l /
 * ast_expr.y) and evaluation (ast_eval.c) live elsewhere. Kept as the
 * stable entry point since cdbg_expr_eval is part of debugger.h's public
 * surface (used by "set" for both plain assignment and $register
 * assignment). */
int cdbg_expr_eval(cdbg_t *dbg, const char *text, cdbg_expr_result_t *out)
{
    if (dbg == NULL || text == NULL || out == NULL) {
        return -1;
    }

    if (cdbg_language_check_expr(dbg) != 0) {
        return -1;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    cdbg_ast_t *ast = cdbg_ast_parse(text);
    if (ast == NULL) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    int rc = cdbg_ast_eval(dbg, ast, out);
    cdbg_ast_free(ast);
    return rc;
}
