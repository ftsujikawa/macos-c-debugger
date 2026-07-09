#include "expr.h"

#include "debugger.h"
#include "memory.h"
#include "regs.h"
#include "syms.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    TOK_END,
    TOK_NUMBER,
    TOK_IDENT,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_PLUS,
    TOK_MINUS,
    TOK_STAR,
    TOK_SLASH,
    TOK_PERCENT,
    TOK_AMP,
    TOK_PIPE,
    TOK_CARET,
    TOK_BANG,
    TOK_TILDE,
    TOK_LSHIFT,
    TOK_RSHIFT,
    TOK_LT,
    TOK_GT,
    TOK_LE,
    TOK_GE,
    TOK_EQ,
    TOK_NE,
    TOK_ANDAND,
    TOK_OROR,
    TOK_DOT,
    TOK_ARROW,
    TOK_LBRACKET,
    TOK_RBRACKET,
} tok_type_t;

typedef struct {
    tok_type_t type;
    uint64_t   number;
    double     fvalue;
    bool       is_float;
    char       ident[128];
} token_t;

typedef struct {
    cdbg_t *dbg;
    const char *cursor;
    token_t current;
    bool has_current;
} parser_t;

static void skip_space(parser_t *p)
{
    while (*p->cursor != '\0' && isspace((unsigned char)*p->cursor)) {
        p->cursor++;
    }
}

static bool is_ident_start(char c)
{
    return isalpha((unsigned char)c) || c == '_';
}

static bool is_ident_char(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

static token_t read_token(parser_t *p)
{
    skip_space(p);
    token_t tok = {.type = TOK_END};

    if (*p->cursor == '\0') {
        return tok;
    }

    if (is_ident_start(*p->cursor)) {
        size_t i = 0;
        while (is_ident_char(p->cursor[i]) && i + 1 < sizeof(tok.ident)) {
            tok.ident[i] = p->cursor[i];
            i++;
        }
        tok.ident[i] = '\0';
        p->cursor += i;
        tok.type = TOK_IDENT;
        return tok;
    }

    if (isdigit((unsigned char)*p->cursor)) {
        char *end_i = NULL;
        unsigned long long uval = strtoull(p->cursor, &end_i, 0);
        if (end_i > p->cursor && (*end_i == '.' || *end_i == 'e' || *end_i == 'E')) {
            char *end_d = NULL;
            double dval = strtod(p->cursor, &end_d);
            uint64_t bits;
            memcpy(&bits, &dval, sizeof(bits));
            tok.number   = bits;
            tok.fvalue   = dval;
            tok.is_float = true;
            p->cursor    = end_d;
            if (*p->cursor == 'f' || *p->cursor == 'F' ||
                *p->cursor == 'l' || *p->cursor == 'L') {
                p->cursor++;
            }
        } else {
            if (end_i == p->cursor) {
                tok.type = TOK_END;
                return tok;
            }
            tok.number   = uval;
            tok.is_float = false;
            p->cursor    = end_i;
        }
        tok.type = TOK_NUMBER;
        return tok;
    }

    /* float literal starting with '.' (e.g. .5) */
    if (*p->cursor == '.' && isdigit((unsigned char)p->cursor[1])) {
        char *end_d = NULL;
        double dval = strtod(p->cursor, &end_d);
        uint64_t bits;
        memcpy(&bits, &dval, sizeof(bits));
        tok.number   = bits;
        tok.fvalue   = dval;
        tok.is_float = true;
        p->cursor    = end_d;
        if (*p->cursor == 'f' || *p->cursor == 'F') p->cursor++;
        tok.type = TOK_NUMBER;
        return tok;
    }

    const char *start = p->cursor;
    switch (*p->cursor) {
    case '-':
        if (p->cursor[1] == '>') {
            tok.type = TOK_ARROW;
            p->cursor += 2;
            return tok;
        }
        tok.type = TOK_MINUS;
        break;
    case '.': tok.type = TOK_DOT; break;
    case '[': tok.type = TOK_LBRACKET; break;
    case ']': tok.type = TOK_RBRACKET; break;
    case '+': tok.type = TOK_PLUS; break;
    case '*': tok.type = TOK_STAR; break;
    case '/': tok.type = TOK_SLASH; break;
    case '%': tok.type = TOK_PERCENT; break;
    case '&':
        if (p->cursor[1] == '&') {
            tok.type = TOK_ANDAND;
            p->cursor += 2;
            return tok;
        }
        tok.type = TOK_AMP;
        break;
    case '|':
        if (p->cursor[1] == '|') {
            tok.type = TOK_OROR;
            p->cursor += 2;
            return tok;
        }
        tok.type = TOK_PIPE;
        break;
    case '^': tok.type = TOK_CARET; break;
    case '!':
        if (p->cursor[1] == '=') {
            tok.type = TOK_NE;
            p->cursor += 2;
            return tok;
        }
        tok.type = TOK_BANG;
        break;
    case '~': tok.type = TOK_TILDE; break;
    case '(': tok.type = TOK_LPAREN; break;
    case ')': tok.type = TOK_RPAREN; break;
    case '<':
        if (p->cursor[1] == '<') {
            tok.type = TOK_LSHIFT;
            p->cursor += 2;
            return tok;
        }
        if (p->cursor[1] == '=') {
            tok.type = TOK_LE;
            p->cursor += 2;
            return tok;
        }
        tok.type = TOK_LT;
        break;
    case '>':
        if (p->cursor[1] == '>') {
            tok.type = TOK_RSHIFT;
            p->cursor += 2;
            return tok;
        }
        if (p->cursor[1] == '=') {
            tok.type = TOK_GE;
            p->cursor += 2;
            return tok;
        }
        tok.type = TOK_GT;
        break;
    case '=':
        if (p->cursor[1] == '=') {
            tok.type = TOK_EQ;
            p->cursor += 2;
            return tok;
        }
        tok.type = TOK_END;
        return tok;
    default:
        tok.type = TOK_END;
        return tok;
    }

    if (tok.type != TOK_END) {
        p->cursor = start + 1;
    }
    return tok;
}

static void advance(parser_t *p)
{
    p->current = read_token(p);
    p->has_current = true;
}

static bool accept(parser_t *p, tok_type_t type)
{
    if (p->current.type == type) {
        advance(p);
        return true;
    }
    return false;
}

static bool expect(parser_t *p, tok_type_t type)
{
    if (!accept(p, type)) {
        return false;
    }
    return true;
}

typedef struct cdbg_var_info {
    char name[128];
    char type[128];
    int64_t fbreg_offset;
    size_t size;
    size_t pointee_size;
    bool has_location;
    bool is_pointer;
    bool is_signed;
} cdbg_var_info_t;

static size_t type_scalar_size(const char *type);
static void complete_var_type(cdbg_var_info_t *var);
static int find_local_var(cdbg_t *dbg, const char *name, cdbg_var_info_t *out);

static int read_scalar_value(pid_t pid, uintptr_t addr, size_t size, uint64_t *out)
{
    if (size == 0 || size > sizeof(uint64_t)) {
        size = sizeof(uint64_t);
    }

    uint8_t buf[sizeof(uint64_t)] = {0};
    if (cdbg_mem_read(pid, addr, buf, size) != 0) {
        return -1;
    }

    uint64_t value = 0;
    memcpy(&value, buf, size);
    *out = value;
    return 0;
}

static int resolve_variable_address(cdbg_t *dbg, const char *name,
                                    cdbg_var_info_t *var, uintptr_t *addr,
                                    bool *found_local)
{
    memset(var, 0, sizeof(*var));
    *found_local = find_local_var(dbg, name, var) == 0;
    if (*found_local) {
        uintptr_t fp = cdbg_regs_fp(&dbg->regs);
        *addr = (uintptr_t)((int64_t)fp + var->fbreg_offset);
        return 0;
    }

    const cdbg_sym_entry_t *sym = cdbg_syms_lookup_name(&dbg->syms, name);
    if (sym == NULL || sym->address == 0 || sym->type == 'U' || sym->type == 'u') {
        return -1;
    }

    *addr = cdbg_syms_runtime_addr(&dbg->syms, sym->address);
    snprintf(var->name, sizeof(var->name), "%s", name);
    snprintf(var->type, sizeof(var->type), "unsigned long");
    complete_var_type(var);
    return 0;
}

static int read_variable_value(cdbg_t *dbg, const char *name, uint64_t *out)
{
    cdbg_var_info_t var = {0};
    uintptr_t addr = 0;
    bool found_local = false;
    if (resolve_variable_address(dbg, name, &var, &addr, &found_local) != 0) {
        return -1;
    }
    (void)found_local;
    return read_scalar_value(dbg->pid, addr, var.size, out);
}

static int read_address_value(cdbg_t *dbg, uint64_t addr, uint64_t *out)
{
    return read_scalar_value(dbg->pid, (uintptr_t)addr, sizeof(uint64_t), out);
}

static int parse_expression(parser_t *p, cdbg_expr_result_t *out);
static int parse_logical_or(parser_t *p, cdbg_expr_result_t *out);
static int parse_logical_and(parser_t *p, cdbg_expr_result_t *out);
static int parse_bit_or(parser_t *p, cdbg_expr_result_t *out);
static int parse_bit_xor(parser_t *p, cdbg_expr_result_t *out);
static int parse_bit_and(parser_t *p, cdbg_expr_result_t *out);
static int parse_equality(parser_t *p, cdbg_expr_result_t *out);
static int parse_relational(parser_t *p, cdbg_expr_result_t *out);
static int parse_shift(parser_t *p, cdbg_expr_result_t *out);
static int parse_additive(parser_t *p, cdbg_expr_result_t *out);
static int parse_multiplicative(parser_t *p, cdbg_expr_result_t *out);
static int parse_unary(parser_t *p, cdbg_expr_result_t *out);
static int parse_primary(parser_t *p, cdbg_expr_result_t *out);

static int parse_expression(parser_t *p, cdbg_expr_result_t *out)
{
    return parse_logical_or(p, out);
}

static int combine_binary(uint64_t left, uint64_t right, tok_type_t op, uint64_t *out)
{
    switch (op) {
    case TOK_PLUS: *out = left + right; return 0;
    case TOK_MINUS: *out = left - right; return 0;
    case TOK_STAR: *out = left * right; return 0;
    case TOK_SLASH:
        if (right == 0) {
            fputs("Division by zero\n", stderr);
            return -1;
        }
        *out = left / right;
        return 0;
    case TOK_PERCENT:
        if (right == 0) {
            fputs("Division by zero\n", stderr);
            return -1;
        }
        *out = left % right;
        return 0;
    case TOK_LSHIFT: *out = left << right; return 0;
    case TOK_RSHIFT: *out = left >> right; return 0;
    case TOK_LT: *out = left < right ? 1 : 0; return 0;
    case TOK_GT: *out = left > right ? 1 : 0; return 0;
    case TOK_LE: *out = left <= right ? 1 : 0; return 0;
    case TOK_GE: *out = left >= right ? 1 : 0; return 0;
    case TOK_EQ: *out = left == right ? 1 : 0; return 0;
    case TOK_NE: *out = left != right ? 1 : 0; return 0;
    case TOK_AMP: *out = left & right; return 0;
    case TOK_CARET: *out = left ^ right; return 0;
    case TOK_PIPE: *out = left | right; return 0;
    case TOK_ANDAND: *out = (left && right) ? 1 : 0; return 0;
    case TOK_OROR: *out = (left || right) ? 1 : 0; return 0;
    default:
        fputs("Invalid operator\n", stderr);
        return -1;
    }
}

static int parse_logical_or(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_logical_and(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_OROR) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_logical_and(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_logical_and(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_bit_or(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_ANDAND) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_bit_or(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_bit_or(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_bit_xor(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_PIPE) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_bit_xor(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_bit_xor(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_bit_and(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_CARET) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_bit_and(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_bit_and(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_equality(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_AMP) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_equality(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_equality(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_relational(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_EQ || p->current.type == TOK_NE) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_relational(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_relational(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_shift(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_LT || p->current.type == TOK_GT ||
           p->current.type == TOK_LE || p->current.type == TOK_GE) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_shift(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_shift(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_additive(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_LSHIFT || p->current.type == TOK_RSHIFT) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_additive(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_additive(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_multiplicative(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_PLUS || p->current.type == TOK_MINUS) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_multiplicative(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_multiplicative(parser_t *p, cdbg_expr_result_t *out)
{
    if (parse_unary(p, out) != 0) {
        return -1;
    }

    while (p->current.type == TOK_STAR || p->current.type == TOK_SLASH ||
           p->current.type == TOK_PERCENT) {
        tok_type_t op = p->current.type;
        advance(p);
        cdbg_expr_result_t rhs = {0};
        if (parse_unary(p, &rhs) != 0) {
            return -1;
        }
        if (combine_binary(out->value, rhs.value, op, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
    }
    return 0;
}

static int parse_primary(parser_t *p, cdbg_expr_result_t *out)
{
    if (p->current.type == TOK_NUMBER) {
        out->value      = p->current.number;
        out->fvalue     = p->current.fvalue;
        out->is_float   = p->current.is_float;
        out->is_address = false;
        advance(p);
        return 0;
    }

    if (p->current.type == TOK_IDENT) {
        char name[128];
        snprintf(name, sizeof(name), "%s", p->current.ident);
        advance(p);
        if (read_variable_value(p->dbg, name, &out->value) != 0) {
            fprintf(stderr, "Unknown variable: %s\n", name);
            return -1;
        }
        out->is_address = false;
        return 0;
    }

    if (p->current.type == TOK_LPAREN) {
        advance(p);
        if (parse_expression(p, out) != 0) {
            return -1;
        }
        if (!expect(p, TOK_RPAREN)) {
            fputs("Expected ')'\n", stderr);
            return -1;
        }
        return 0;
    }

    fputs("Invalid expression\n", stderr);
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

static int lvalue_expr_append(char *expr, size_t expr_len, size_t *pos, const char *text)
{
    if (text == NULL) {
        return 0;
    }

    int n = snprintf(expr + *pos, expr_len - *pos, "%s", text);
    if (n < 0 || (size_t)n >= expr_len - *pos) {
        return -1;
    }
    *pos += (size_t)n;
    return 0;
}

static int parse_lvalue_path(parser_t *p, char *expr_out, size_t expr_len)
{
    if (p->current.type != TOK_IDENT) {
        fputs("Expected lvalue expression\n", stderr);
        return -1;
    }

    size_t pos = 0;
    if (lvalue_expr_append(expr_out, expr_len, &pos, p->current.ident) != 0) {
        return -1;
    }
    advance(p);

    for (;;) {
        if (accept(p, TOK_DOT)) {
            if (p->current.type != TOK_IDENT) {
                fputs("Expected member name after '.'\n", stderr);
                return -1;
            }
            if (lvalue_expr_append(expr_out, expr_len, &pos, ".") != 0 ||
                lvalue_expr_append(expr_out, expr_len, &pos, p->current.ident) != 0) {
                return -1;
            }
            advance(p);
            continue;
        }

        if (accept(p, TOK_ARROW)) {
            if (p->current.type != TOK_IDENT) {
                fputs("Expected member name after '->'\n", stderr);
                return -1;
            }
            if (lvalue_expr_append(expr_out, expr_len, &pos, "->") != 0 ||
                lvalue_expr_append(expr_out, expr_len, &pos, p->current.ident) != 0) {
                return -1;
            }
            advance(p);
            continue;
        }

        if (accept(p, TOK_LBRACKET)) {
            if (p->current.type != TOK_NUMBER) {
                fputs("Expected array index\n", stderr);
                return -1;
            }
            char index_buf[32];
            snprintf(index_buf, sizeof(index_buf), "[%llu]",
                     (unsigned long long)p->current.number);
            if (lvalue_expr_append(expr_out, expr_len, &pos, index_buf) != 0) {
                return -1;
            }
            advance(p);
            if (!expect(p, TOK_RBRACKET)) {
                fputs("Expected ']'\n", stderr);
                return -1;
            }
            continue;
        }

        break;
    }

    expr_out[pos] = '\0';
    return pos > 0 ? 0 : -1;
}

static int parse_unary_address(parser_t *p, cdbg_expr_result_t *out)
{
    advance(p);

    char expr[256];
    if (parse_lvalue_path(p, expr, sizeof(expr)) != 0) {
        fputs("Cannot take address of expression\n", stderr);
        return -1;
    }

    char work[256];
    snprintf(work, sizeof(work), "%s", expr);
    uintptr_t addr = 0;
    char value_type[128] = {0};
    if (cdbg_resolve_lvalue_expr(p->dbg, work, &addr, value_type, sizeof(value_type)) != 0) {
        fprintf(stderr, "Unknown lvalue: %s\n", expr);
        return -1;
    }

    out->value = addr;
    out->is_address = true;
    make_pointer_type(value_type, out->type, sizeof(out->type));
    return 0;
}

static int parse_unary(parser_t *p, cdbg_expr_result_t *out)
{
    switch (p->current.type) {
    case TOK_PLUS:
        advance(p);
        return parse_unary(p, out);
    case TOK_MINUS: {
        advance(p);
        cdbg_expr_result_t inner = {0};
        if (parse_unary(p, &inner) != 0) {
            return -1;
        }
        if (inner.is_float) {
            out->fvalue   = -inner.fvalue;
            out->is_float = true;
            uint64_t bits;
            memcpy(&bits, &out->fvalue, sizeof(bits));
            out->value = bits;
        } else {
            out->value = (uint64_t)(-(int64_t)inner.value);
        }
        out->is_address = false;
        return 0;
    }
    case TOK_BANG: {
        advance(p);
        cdbg_expr_result_t inner = {0};
        if (parse_unary(p, &inner) != 0) {
            return -1;
        }
        out->value = inner.value ? 0 : 1;
        out->is_address = false;
        return 0;
    }
    case TOK_TILDE: {
        advance(p);
        cdbg_expr_result_t inner = {0};
        if (parse_unary(p, &inner) != 0) {
            return -1;
        }
        out->value = ~inner.value;
        out->is_address = false;
        return 0;
    }
    case TOK_AMP:
        return parse_unary_address(p, out);
    case TOK_STAR: {
        advance(p);
        cdbg_expr_result_t inner = {0};
        if (parse_unary(p, &inner) != 0) {
            return -1;
        }
        if (read_address_value(p->dbg, inner.value, &out->value) != 0) {
            return -1;
        }
        out->is_address = false;
        return 0;
    }
    default:
        return parse_primary(p, out);
    }
}

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

    parser_t parser = {
        .dbg = dbg,
        .cursor = text,
        .has_current = false,
    };
    advance(&parser);

    memset(out, 0, sizeof(*out));
    if (parse_expression(&parser, out) != 0) {
        return -1;
    }

    skip_space(&parser);
    if (*parser.cursor != '\0') {
        fprintf(stderr, "Unexpected token near: %s\n", parser.cursor);
        return -1;
    }
    return 0;
}

/* ---- duplicated helpers from debugger.c (static there) ---- */

static size_t type_scalar_size(const char *type)
{
    if (strchr(type, '*') != NULL) {
        return sizeof(uintptr_t);
    }
    if (strstr(type, "char") != NULL) {
        return 1;
    }
    if (strstr(type, "short") != NULL) {
        return 2;
    }
    if (strstr(type, "long") != NULL) {
        return 8;
    }
    if (strstr(type, "int") != NULL || strstr(type, "bool") != NULL) {
        return 4;
    }
    return sizeof(uintptr_t);
}

static void complete_var_type(cdbg_var_info_t *var)
{
    var->is_pointer = strchr(var->type, '*') != NULL;
    var->is_signed = strstr(var->type, "unsigned") == NULL;
    var->size = type_scalar_size(var->type);
    var->pointee_size = sizeof(uintptr_t);
}

static int parse_quoted_value(const char *line, char *out, size_t out_len)
{
    const char *start = strchr(line, '"');
    if (start == NULL) {
        return -1;
    }
    const char *end = strchr(start + 1, '"');
    if (end == NULL) {
        return -1;
    }

    size_t len = (size_t)(end - start - 1);
    if (len >= out_len) {
        len = out_len - 1;
    }
    memcpy(out, start + 1, len);
    out[len] = '\0';
    return 0;
}

static int parse_hex_value(const char *line, uintptr_t *out)
{
    const char *hex = strstr(line, "0x");
    if (hex == NULL) {
        return -1;
    }

    char *end = NULL;
    unsigned long long value = strtoull(hex, &end, 16);
    if (end == hex) {
        return -1;
    }

    *out = (uintptr_t)value;
    return 0;
}

static int parse_fbreg_offset(const char *line, int64_t *out)
{
    const char *fbreg = strstr(line, "DW_OP_fbreg");
    if (fbreg == NULL) {
        return -1;
    }

    char *end = NULL;
    long long value = strtoll(fbreg + strlen("DW_OP_fbreg"), &end, 10);
    if (end == fbreg + strlen("DW_OP_fbreg")) {
        return -1;
    }

    *out = value;
    return 0;
}

static int dwarf_line_depth(const char *line)
{
    const char *colon = strchr(line, ':');
    if (colon == NULL) {
        return 0;
    }

    int depth = 0;
    for (const char *p = colon + 1; *p == ' '; p++) {
        depth++;
    }
    return depth;
}

static bool dwarf_starts_die(const char *line)
{
    return strstr(line, "DW_TAG_") != NULL || strstr(line, "NULL") != NULL;
}

static bool pc_in_range(uintptr_t pc, uintptr_t low, uintptr_t high)
{
    if (low == 0 || high == 0) {
        return false;
    }
    if (high < low) {
        high += low;
    }
    return pc >= low && pc < high;
}

static bool var_ready(const cdbg_var_info_t *var, const char *name)
{
    return var->has_location && var->name[0] != '\0' &&
           strcmp(var->name, name) == 0;
}

static int finish_var_if_match(cdbg_var_info_t *var, const char *name,
                               cdbg_var_info_t *out)
{
    if (!var_ready(var, name)) {
        return -1;
    }

    complete_var_type(var);
    *out = *var;
    return 0;
}

static int find_local_var(cdbg_t *dbg, const char *name, cdbg_var_info_t *out)
{
    if (dbg->debug_info_path[0] == '\0') {
        return -1;
    }

    uintptr_t runtime_pc = cdbg_regs_pc(&dbg->regs);
    uintptr_t link_pc = runtime_pc - dbg->lineno.slide;
    char cmd[CDBG_MAX_PATH + 64];
    int n = snprintf(cmd, sizeof(cmd), "dwarfdump --debug-info '%s' 2>/dev/null",
                     dbg->debug_info_path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return -1;
    }

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    bool in_func = false;
    bool func_matches = false;
    int func_depth = 0;
    uintptr_t func_low = 0;
    uintptr_t func_high = 0;
    bool reading_var = false;
    cdbg_var_info_t var = {0};
    char line[1024];

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (reading_var && dwarf_starts_die(line)) {
            if (finish_var_if_match(&var, name, out) == 0) {
                pclose(fp);
                return 0;
            }
            memset(&var, 0, sizeof(var));
            reading_var = false;
        }

        if (dwarf_starts_die(line)) {
            int depth = dwarf_line_depth(line);
            if (strstr(line, "DW_TAG_subprogram") != NULL) {
                in_func = true;
                func_matches = false;
                func_depth = depth;
                func_low = 0;
                func_high = 0;
                continue;
            }
            if (in_func && depth <= func_depth) {
                in_func = false;
                func_matches = false;
            }
            if (in_func && func_matches &&
                (strstr(line, "DW_TAG_variable") != NULL ||
                 strstr(line, "DW_TAG_formal_parameter") != NULL)) {
                memset(&var, 0, sizeof(var));
                reading_var = true;
                continue;
            }
        }

        if (in_func && strstr(line, "DW_AT_low_pc") != NULL) {
            (void)parse_hex_value(line, &func_low);
            func_matches = pc_in_range(link_pc, func_low, func_high);
            continue;
        }
        if (in_func && strstr(line, "DW_AT_high_pc") != NULL) {
            (void)parse_hex_value(line, &func_high);
            func_matches = pc_in_range(link_pc, func_low, func_high);
            continue;
        }

        if (!reading_var) {
            continue;
        }
        if (strstr(line, "DW_AT_location") != NULL &&
            parse_fbreg_offset(line, &var.fbreg_offset) == 0) {
            var.has_location = true;
        } else if (strstr(line, "DW_AT_name") != NULL) {
            (void)parse_quoted_value(line, var.name, sizeof(var.name));
        } else if (strstr(line, "DW_AT_type") != NULL) {
            (void)parse_quoted_value(line, var.type, sizeof(var.type));
        }
    }

    int rc = -1;
    if (reading_var && finish_var_if_match(&var, name, out) == 0) {
        rc = 0;
    }
    pclose(fp);
    return rc;
}
