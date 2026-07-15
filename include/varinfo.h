#ifndef CDBG_VARINFO_H
#define CDBG_VARINFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct cdbg cdbg_t;

typedef struct cdbg_struct_member {
    char name[64];
    char type[64];
    size_t offset;
    size_t size;
    bool is_signed;
} cdbg_struct_member_t;

typedef struct cdbg_var_info {
    char name[128];
    char type[128];
    char element_type[128];
    int64_t fbreg_offset;
    size_t size;
    size_t element_size;
    size_t pointee_size;
    size_t array_count;
    bool has_location;
    bool is_pointer;
    bool is_signed;
    bool is_array;
} cdbg_var_info_t;

/* Semantic helpers implemented in debugger.c, reused by the AST-based
 * expression evaluator/lvalue resolver in ast_eval.c. These do the actual
 * DWARF/symbol-table work; the parser only builds the AST that describes
 * which of them to call and in what order. */
int    resolve_variable_address(cdbg_t *dbg, const char *name, cdbg_var_info_t *var,
                                uintptr_t *addr, bool *found_local);
int    lookup_struct_member(cdbg_t *dbg, const char *struct_type, const char *member_name,
                            size_t *offset_out, size_t *size_out, bool *signed_out,
                            char *type_out, size_t type_out_len);
size_t type_element_size(cdbg_t *dbg, const char *type);
void   pointer_pointee_type(const cdbg_var_info_t *var, char *out, size_t out_len);
bool   type_is_scalar(const char *type);
int    read_scalar_value(pid_t pid, uintptr_t addr, size_t size, uint64_t *out);

#endif /* CDBG_VARINFO_H */
