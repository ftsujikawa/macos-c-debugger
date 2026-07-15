#ifndef CDBG_AST_H
#define CDBG_AST_H

#include <stdint.h>

/* AST produced by the flex/bison expression grammar (ast_expr.l / .y) and
 * consumed by the evaluator/lvalue resolver in ast_eval.c. Shared by the
 * "print"/"p" and "set" commands (and, transitively, "watch"). */
typedef enum {
    CDBG_AST_NUM,     /* integer literal:            .num */
    CDBG_AST_FLOAT,   /* floating-point literal:     .fnum */
    CDBG_AST_IDENT,   /* variable name:               .name */
    CDBG_AST_BINOP,   /* .op(.lhs, .rhs) */
    CDBG_AST_POS,     /* unary +expr:                 .lhs */
    CDBG_AST_NEG,     /* unary -expr:                 .lhs */
    CDBG_AST_NOT,     /* unary !expr:                 .lhs */
    CDBG_AST_BNOT,    /* unary ~expr:                 .lhs */
    CDBG_AST_ADDR,    /* unary &expr (lhs must be an lvalue): .lhs */
    CDBG_AST_DEREF,   /* unary *expr:                 .lhs */
    CDBG_AST_MEMBER,  /* expr.name:                   .lhs, .name */
    CDBG_AST_ARROW,   /* expr->name:                  .lhs, .name */
    CDBG_AST_INDEX,   /* expr[expr]:                  .lhs, .rhs */
} cdbg_ast_kind_t;

typedef enum {
    CDBG_AST_OP_ADD, CDBG_AST_OP_SUB, CDBG_AST_OP_MUL, CDBG_AST_OP_DIV, CDBG_AST_OP_MOD,
    CDBG_AST_OP_SHL, CDBG_AST_OP_SHR,
    CDBG_AST_OP_LT, CDBG_AST_OP_GT, CDBG_AST_OP_LE, CDBG_AST_OP_GE,
    CDBG_AST_OP_EQ, CDBG_AST_OP_NE,
    CDBG_AST_OP_BAND, CDBG_AST_OP_BOR, CDBG_AST_OP_BXOR,
    CDBG_AST_OP_LAND, CDBG_AST_OP_LOR,
} cdbg_ast_op_t;

typedef struct cdbg_ast cdbg_ast_t;

struct cdbg_ast {
    cdbg_ast_kind_t kind;
    cdbg_ast_op_t   op;    /* valid when kind == CDBG_AST_BINOP */
    uint64_t        num;   /* valid when kind == CDBG_AST_NUM */
    double          fnum;  /* valid when kind == CDBG_AST_FLOAT */
    char           *name;  /* owned; valid for IDENT/MEMBER/ARROW */
    cdbg_ast_t     *lhs;   /* owned; operand, or left-hand side of BINOP/INDEX */
    cdbg_ast_t     *rhs;   /* owned; right-hand side of BINOP, or index expr of INDEX */
};

cdbg_ast_t *cdbg_ast_new_num(uint64_t value);
cdbg_ast_t *cdbg_ast_new_float(double value);
cdbg_ast_t *cdbg_ast_new_ident(char *name);
cdbg_ast_t *cdbg_ast_new_binop(cdbg_ast_op_t op, cdbg_ast_t *lhs, cdbg_ast_t *rhs);
cdbg_ast_t *cdbg_ast_new_unop(cdbg_ast_kind_t kind, cdbg_ast_t *operand);
cdbg_ast_t *cdbg_ast_new_member(cdbg_ast_t *base, char *name);
cdbg_ast_t *cdbg_ast_new_arrow(cdbg_ast_t *base, char *name);
cdbg_ast_t *cdbg_ast_new_index(cdbg_ast_t *base, cdbg_ast_t *index);

void cdbg_ast_free(cdbg_ast_t *node);

#endif /* CDBG_AST_H */
