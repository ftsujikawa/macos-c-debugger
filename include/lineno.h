#ifndef CDBG_LINENO_H
#define CDBG_LINENO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CDBG_LINENO_MAX_FILE 512

typedef struct cdbg_line_entry {
    uintptr_t address;
    uint32_t line;
    uint32_t column;
    char file[CDBG_LINENO_MAX_FILE];
} cdbg_line_entry_t;

typedef struct cdbg_lineno {
    cdbg_line_entry_t *entries;
    size_t count;
    uintptr_t link_base;
    uintptr_t slide;
    char comp_dir[CDBG_LINENO_MAX_FILE];
    char exe_dir[CDBG_LINENO_MAX_FILE];
} cdbg_lineno_t;

int  cdbg_lineno_load(cdbg_lineno_t *ln, const char *executable_path);
int  cdbg_lineno_update_slide(cdbg_lineno_t *ln, pid_t pid);
void cdbg_lineno_free(cdbg_lineno_t *ln);
void cdbg_lineno_print_list(const cdbg_lineno_t *ln, const char *file_filter);
int  cdbg_lineno_print_source_at_pc(const cdbg_lineno_t *ln, uintptr_t runtime_pc);
int  cdbg_lineno_print_source_at_line(const cdbg_lineno_t *ln,
                                      const char *file_filter,
                                      uint32_t line);
int  cdbg_lineno_line_at_pc(const cdbg_lineno_t *ln, uintptr_t runtime_pc,
                            char *file_out, size_t file_len, uint32_t *line_out);
const cdbg_line_entry_t *cdbg_lineno_lookup_next_line_after_pc(const cdbg_lineno_t *ln,
                                                               uintptr_t runtime_pc);
uintptr_t cdbg_lineno_runtime_addr(const cdbg_lineno_t *ln, uintptr_t link_addr);
const cdbg_line_entry_t *cdbg_lineno_lookup_pc(const cdbg_lineno_t *ln, uintptr_t runtime_pc);
const cdbg_line_entry_t *cdbg_lineno_lookup_line(const cdbg_lineno_t *ln,
                                                 const char *file_filter,
                                                 uint32_t line);
const cdbg_line_entry_t *cdbg_lineno_lookup_line_unique(const cdbg_lineno_t *ln,
                                                        uint32_t line);

#endif /* CDBG_LINENO_H */
