#include "ast_eval.h"

#include "debugger.h"
#include "memory.h"

#include <stdio.h>
#include <string.h>

static int combine_binary(uint64_t left, uint64_t right, cdbg_ast_op_t op, uint64_t *out)
{
    switch (op) {
    case CDBG_AST_OP_ADD: *out = left + right; return 0;
    case CDBG_AST_OP_SUB: *out = left - right; return 0;
    case CDBG_AST_OP_MUL: *out = left * right; return 0;
    case CDBG_AST_OP_DIV:
        if (right == 0) {
            fputs("Division by zero\n", stderr);
            return -1;
        }
        *out = left / right;
        return 0;
    case CDBG_AST_OP_MOD:
        if (right == 0) {
            fputs("Division by zero\n", stderr);
            return -1;
        }
        *out = left % right;
        return 0;
    case CDBG_AST_OP_SHL: *out = left << right; return 0;
    case CDBG_AST_OP_SHR: *out = left >> right; return 0;
    case CDBG_AST_OP_LT:  *out = left < right  ? 1 : 0; return 0;
    case CDBG_AST_OP_GT:  *out = left > right  ? 1 : 0; return 0;
    case CDBG_AST_OP_LE:  *out = left <= right ? 1 : 0; return 0;
    case CDBG_AST_OP_GE:  *out = left >= right ? 1 : 0; return 0;
    case CDBG_AST_OP_EQ:  *out = left == right ? 1 : 0; return 0;
    case CDBG_AST_OP_NE:  *out = left != right ? 1 : 0; return 0;
    case CDBG_AST_OP_BAND: *out = left & right; return 0;
    case CDBG_AST_OP_BXOR: *out = left ^ right; return 0;
    case CDBG_AST_OP_BOR:  *out = left | right; return 0;
    case CDBG_AST_OP_LAND: *out = (left && right) ? 1 : 0; return 0;
    case CDBG_AST_OP_LOR:  *out = (left || right) ? 1 : 0; return 0;
    }
    fputs("Invalid operator\n", stderr);
    return -1;
}

static void make_pointer_type(const char *base_type, char *out, size_t out_len)
{
    if (base_type == NULL || base_type[0] == '\0') {
        out[0] = '\0';
        return;
    }

    size_t len = strlen(base_type);
    while (len > 0 && base_type[len - 1] == ' ') {
        len--;
    }

    if (len >= out_len - 3) {
        len = out_len - 4;
    }
    memcpy(out, base_type, len);
    out[len] = '\0';
    snprintf(out + len, out_len - len, " *");
}

bool cdbg_ast_is_lvalue_shaped(const cdbg_ast_t *node)
{
    switch (node->kind) {
    case CDBG_AST_IDENT:
    case CDBG_AST_MEMBER:
    case CDBG_AST_ARROW:
    case CDBG_AST_INDEX:
    case CDBG_AST_DEREF:
        return true;
    default:
        return false;
    }
}

int cdbg_ast_resolve_lvalue(cdbg_t *dbg, cdbg_ast_t *node, uintptr_t *addr_out,
                            cdbg_var_info_t *var_out)
{
    memset(var_out, 0, sizeof(*var_out));

    switch (node->kind) {
    case CDBG_AST_IDENT: {
        bool found_local = false;
        if (resolve_variable_address(dbg, node->name, var_out, addr_out, &found_local) != 0) {
            fprintf(stderr, "Unknown variable: %s\n", node->name);
            return -1;
        }
        return 0;
    }

    case CDBG_AST_MEMBER:
    case CDBG_AST_ARROW: {
        uintptr_t base_addr = 0;
        cdbg_var_info_t base_var = {0};
        if (cdbg_ast_resolve_lvalue(dbg, node->lhs, &base_addr, &base_var) != 0) {
            return -1;
        }

        char struct_type[128];
        uintptr_t struct_addr;
        if (node->kind == CDBG_AST_ARROW) {
            if (!base_var.is_pointer) {
                fputs("Not a pointer\n", stderr);
                return -1;
            }
            uint64_t ptr = 0;
            if (read_scalar_value(dbg->pid, base_addr, sizeof(uintptr_t), &ptr) != 0) {
                return -1;
            }
            pointer_pointee_type(&base_var, struct_type, sizeof(struct_type));
            struct_addr = (uintptr_t)ptr;
        } else {
            snprintf(struct_type, sizeof(struct_type), "%s", base_var.type);
            struct_addr = base_addr;
        }

        size_t offset = 0, size = 0;
        bool is_signed = false;
        char member_type[128] = {0};
        if (lookup_struct_member(dbg, struct_type, node->name, &offset, &size,
                                 &is_signed, member_type, sizeof(member_type)) != 0) {
            fprintf(stderr, "Unknown member: %s\n", node->name);
            return -1;
        }

        *addr_out = struct_addr + offset;
        snprintf(var_out->name, sizeof(var_out->name), "%s", node->name);
        snprintf(var_out->type, sizeof(var_out->type), "%s", member_type);
        var_out->size = size;
        var_out->is_signed = is_signed;
        var_out->is_pointer = strchr(member_type, '*') != NULL;
        return 0;
    }

    case CDBG_AST_INDEX: {
        uintptr_t base_addr = 0;
        cdbg_var_info_t base_var = {0};
        if (cdbg_ast_resolve_lvalue(dbg, node->lhs, &base_addr, &base_var) != 0) {
            return -1;
        }

        cdbg_expr_result_t idx_result = {0};
        if (cdbg_ast_eval(dbg, node->rhs, &idx_result) != 0) {
            return -1;
        }
        uint64_t index = idx_result.value;

        if (base_var.is_array) {
            if (index >= base_var.array_count) {
                fprintf(stderr, "Array index out of bounds: %llu\n",
                        (unsigned long long)index);
                return -1;
            }
            *addr_out = base_addr + index * base_var.element_size;
            snprintf(var_out->type, sizeof(var_out->type), "%s", base_var.element_type);
            var_out->size = base_var.element_size;
            var_out->is_signed = strstr(base_var.element_type, "unsigned") == NULL;
            var_out->is_pointer = strchr(base_var.element_type, '*') != NULL;
            return 0;
        }

        if (base_var.is_pointer) {
            uint64_t ptr = 0;
            if (read_scalar_value(dbg->pid, base_addr, sizeof(uintptr_t), &ptr) != 0) {
                return -1;
            }
            char pointee_type[128] = {0};
            pointer_pointee_type(&base_var, pointee_type, sizeof(pointee_type));
            size_t elem_size = type_element_size(dbg, pointee_type);
            *addr_out = (uintptr_t)ptr + index * elem_size;
            snprintf(var_out->type, sizeof(var_out->type), "%s", pointee_type);
            var_out->size = elem_size;
            var_out->is_signed = strstr(pointee_type, "unsigned") == NULL;
            var_out->is_pointer = strchr(pointee_type, '*') != NULL;
            return 0;
        }

        fputs("Not an array or pointer\n", stderr);
        return -1;
    }

    case CDBG_AST_DEREF: {
        cdbg_expr_result_t inner = {0};
        if (cdbg_ast_eval(dbg, node->lhs, &inner) != 0) {
            return -1;
        }
        *addr_out = (uintptr_t)inner.value;

        /* Best-effort pointee type: only recoverable when dereferencing a
         * plain pointer variable by name, matching what the old lvalue
         * parser supported ("*ptr"). Anything else (a raw address, or a
         * computed expression) reads back as an untyped 8-byte value. */
        if (node->lhs->kind == CDBG_AST_IDENT) {
            cdbg_var_info_t ptr_var = {0};
            uintptr_t ptr_addr = 0;
            bool found = false;
            if (resolve_variable_address(dbg, node->lhs->name, &ptr_var, &ptr_addr,
                                         &found) == 0 && ptr_var.is_pointer) {
                char pointee_type[128] = {0};
                pointer_pointee_type(&ptr_var, pointee_type, sizeof(pointee_type));
                snprintf(var_out->type, sizeof(var_out->type), "%s", pointee_type);
                var_out->size = type_element_size(dbg, pointee_type);
                var_out->is_signed = strstr(pointee_type, "unsigned") == NULL;
                var_out->is_pointer = strchr(pointee_type, '*') != NULL;
                return 0;
            }
        }
        var_out->size = sizeof(uint64_t);
        return 0;
    }

    default:
        return -1;
    }
}

int cdbg_ast_eval(cdbg_t *dbg, cdbg_ast_t *node, cdbg_expr_result_t *out)
{
    memset(out, 0, sizeof(*out));

    switch (node->kind) {
    case CDBG_AST_NUM:
        out->value = node->num;
        return 0;

    case CDBG_AST_FLOAT: {
        uint64_t bits;
        memcpy(&bits, &node->fnum, sizeof(bits));
        out->value = bits;
        out->fvalue = node->fnum;
        out->is_float = true;
        return 0;
    }

    case CDBG_AST_IDENT: {
        cdbg_var_info_t var = {0};
        uintptr_t addr = 0;
        bool found_local = false;
        if (resolve_variable_address(dbg, node->name, &var, &addr, &found_local) != 0) {
            fprintf(stderr, "Unknown variable: %s\n", node->name);
            return -1;
        }
        if (read_scalar_value(dbg->pid, addr, var.size, &out->value) != 0) {
            return -1;
        }
        return 0;
    }

    case CDBG_AST_BINOP: {
        cdbg_expr_result_t lhs = {0}, rhs = {0};
        if (cdbg_ast_eval(dbg, node->lhs, &lhs) != 0) {
            return -1;
        }
        if (cdbg_ast_eval(dbg, node->rhs, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(lhs.value, rhs.value, node->op, &out->value) != 0) {
            return -1;
        }
        out->is_float = lhs.is_float;
        out->fvalue = lhs.fvalue;
        return 0;
    }

    case CDBG_AST_POS:
        return cdbg_ast_eval(dbg, node->lhs, out);

    case CDBG_AST_NEG: {
        cdbg_expr_result_t inner = {0};
        if (cdbg_ast_eval(dbg, node->lhs, &inner) != 0) {
            return -1;
        }
        if (inner.is_float) {
            out->fvalue = -inner.fvalue;
            out->is_float = true;
            uint64_t bits;
            memcpy(&bits, &out->fvalue, sizeof(bits));
            out->value = bits;
        } else {
            out->value = (uint64_t)(-(int64_t)inner.value);
        }
        return 0;
    }

    case CDBG_AST_NOT: {
        cdbg_expr_result_t inner = {0};
        if (cdbg_ast_eval(dbg, node->lhs, &inner) != 0) {
            return -1;
        }
        out->value = inner.value ? 0 : 1;
        return 0;
    }

    case CDBG_AST_BNOT: {
        cdbg_expr_result_t inner = {0};
        if (cdbg_ast_eval(dbg, node->lhs, &inner) != 0) {
            return -1;
        }
        out->value = ~inner.value;
        return 0;
    }

    case CDBG_AST_ADDR: {
        uintptr_t addr = 0;
        cdbg_var_info_t var = {0};
        if (!cdbg_ast_is_lvalue_shaped(node->lhs) ||
            cdbg_ast_resolve_lvalue(dbg, node->lhs, &addr, &var) != 0) {
            fputs("Cannot take address of expression\n", stderr);
            return -1;
        }
        out->value = addr;
        out->is_address = true;
        make_pointer_type(var.type, out->type, sizeof(out->type));
        return 0;
    }

    case CDBG_AST_DEREF: {
        cdbg_expr_result_t inner = {0};
        if (cdbg_ast_eval(dbg, node->lhs, &inner) != 0) {
            return -1;
        }
        if (read_scalar_value(dbg->pid, (uintptr_t)inner.value, sizeof(uint64_t),
                              &out->value) != 0) {
            return -1;
        }
        return 0;
    }

    case CDBG_AST_MEMBER:
    case CDBG_AST_ARROW:
    case CDBG_AST_INDEX: {
        uintptr_t addr = 0;
        cdbg_var_info_t var = {0};
        if (cdbg_ast_resolve_lvalue(dbg, node, &addr, &var) != 0) {
            return -1;
        }
        if (read_scalar_value(dbg->pid, addr, var.size, &out->value) != 0) {
            return -1;
        }
        return 0;
    }
    }

    fputs("Invalid expression\n", stderr);
    return -1;
}
