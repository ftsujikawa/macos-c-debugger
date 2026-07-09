#ifndef CDBG_EXPR_H
#define CDBG_EXPR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct cdbg cdbg_t;

typedef struct cdbg_expr_result {
    uint64_t value;
    double   fvalue;
    bool     is_float;
    bool     is_address;
    char     type[128];
} cdbg_expr_result_t;

int cdbg_expr_eval(cdbg_t *dbg, const char *text, cdbg_expr_result_t *out);

#endif /* CDBG_EXPR_H */
