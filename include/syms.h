#ifndef CDBG_SYMS_H
#define CDBG_SYMS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CDBG_SYM_MAX_NAME 256

typedef struct cdbg_sym_entry {
    uintptr_t address;
    char type;
    char name[CDBG_SYM_MAX_NAME];
} cdbg_sym_entry_t;

typedef struct cdbg_syms {
    cdbg_sym_entry_t *entries;
    size_t count;
    uintptr_t link_base;
    uintptr_t slide;
} cdbg_syms_t;

int  cdbg_syms_load(cdbg_syms_t *syms, const char *executable_path);
int  cdbg_syms_update_slide(cdbg_syms_t *syms, pid_t pid);
void cdbg_syms_free(cdbg_syms_t *syms);
void cdbg_syms_print_list(const cdbg_syms_t *syms, const char *name_filter);
uintptr_t cdbg_syms_runtime_addr(const cdbg_syms_t *syms, uintptr_t link_addr);
const cdbg_sym_entry_t *cdbg_syms_lookup_name(const cdbg_syms_t *syms, const char *name);

#endif /* CDBG_SYMS_H */
