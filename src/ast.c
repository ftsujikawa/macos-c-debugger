#include "ast.h"

#include <stdlib.h>

static cdbg_ast_t *ast_alloc(cdbg_ast_kind_t kind)
{
    cdbg_ast_t *node = calloc(1, sizeof(cdbg_ast_t));
    node->kind = kind;
    return node;
}

cdbg_ast_t *cdbg_ast_new_num(uint64_t value)
{
    cdbg_ast_t *node = ast_alloc(CDBG_AST_NUM);
    node->num = value;
    return node;
}

cdbg_ast_t *cdbg_ast_new_float(double value)
{
    cdbg_ast_t *node = ast_alloc(CDBG_AST_FLOAT);
    node->fnum = value;
    return node;
}

cdbg_ast_t *cdbg_ast_new_ident(char *name)
{
    cdbg_ast_t *node = ast_alloc(CDBG_AST_IDENT);
    node->name = name;
    return node;
}

cdbg_ast_t *cdbg_ast_new_binop(cdbg_ast_op_t op, cdbg_ast_t *lhs, cdbg_ast_t *rhs)
{
    cdbg_ast_t *node = ast_alloc(CDBG_AST_BINOP);
    node->op = op;
    node->lhs = lhs;
    node->rhs = rhs;
    return node;
}

cdbg_ast_t *cdbg_ast_new_unop(cdbg_ast_kind_t kind, cdbg_ast_t *operand)
{
    cdbg_ast_t *node = ast_alloc(kind);
    node->lhs = operand;
    return node;
}

cdbg_ast_t *cdbg_ast_new_member(cdbg_ast_t *base, char *name)
{
    cdbg_ast_t *node = ast_alloc(CDBG_AST_MEMBER);
    node->lhs = base;
    node->name = name;
    return node;
}

cdbg_ast_t *cdbg_ast_new_arrow(cdbg_ast_t *base, char *name)
{
    cdbg_ast_t *node = ast_alloc(CDBG_AST_ARROW);
    node->lhs = base;
    node->name = name;
    return node;
}

cdbg_ast_t *cdbg_ast_new_index(cdbg_ast_t *base, cdbg_ast_t *index)
{
    cdbg_ast_t *node = ast_alloc(CDBG_AST_INDEX);
    node->lhs = base;
    node->rhs = index;
    return node;
}

void cdbg_ast_free(cdbg_ast_t *node)
{
    if (node == NULL) {
        return;
    }
    cdbg_ast_free(node->lhs);
    cdbg_ast_free(node->rhs);
    free(node->name);
    free(node);
}
