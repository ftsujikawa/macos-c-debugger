#include "syms.h"

#include <ctype.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

typedef struct mapped_file {
    uint8_t *data;
    size_t size;
} mapped_file_t;

static int map_file(const char *path, mapped_file_t *out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }

    if (st.st_size == 0) {
        close(fd);
        return -1;
    }

    void *data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) {
        return -1;
    }

    out->data = data;
    out->size = (size_t)st.st_size;
    return 0;
}

static void unmap_file(mapped_file_t *file)
{
    if (file->data != NULL) {
        munmap(file->data, file->size);
        file->data = NULL;
        file->size = 0;
    }
}

static int dsym_object_path(const char *executable_path, char *out, size_t out_len)
{
    char exe_copy[PATH_MAX];
    if (strlen(executable_path) >= sizeof(exe_copy)) {
        return -1;
    }
    strncpy(exe_copy, executable_path, sizeof(exe_copy));
    exe_copy[sizeof(exe_copy) - 1] = '\0';

    const char *base = basename(exe_copy);
    int n = snprintf(out, out_len, "%s.dSYM/Contents/Resources/DWARF/%s",
                     executable_path, base);
    if (n < 0 || (size_t)n >= out_len) {
        return -1;
    }
    return access(out, R_OK) == 0 ? 0 : -1;
}

static uintptr_t macho_text_vmaddr(const uint8_t *data, size_t size)
{
    if (size < sizeof(struct mach_header_64)) {
        return 0;
    }

    const struct mach_header_64 *mh = (const struct mach_header_64 *)data;
    if (mh->magic != MH_MAGIC_64) {
        return 0;
    }

    const uint8_t *cursor = data + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((size_t)(cursor - data) + sizeof(struct load_command) > size) {
            break;
        }
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                return (uintptr_t)seg->vmaddr;
            }
        }
        cursor += lc->cmdsize;
    }

    return 0;
}

static char nlist_type_char(uint8_t type)
{
    uint8_t base = type & N_TYPE;

    if (base == N_UNDF) {
        return (type & N_EXT) ? 'U' : 'u';
    }
    if (base == N_ABS) {
        return (type & N_EXT) ? 'A' : 'a';
    }
    if (base == N_SECT) {
        if (type & N_EXT) {
            return 'T';
        }
        return 't';
    }
    if (base == N_PBUD) {
        return 'Z';
    }
    if (base == N_INDR) {
        return 'I';
    }
    return '?';
}

static bool sym_name_interesting(const char *name, char type)
{
    if (name == NULL || name[0] == '\0') {
        return false;
    }
    if (type == '?' || type == '-') {
        return false;
    }
    if (name[0] == '.' || name[0] == 'L') {
        return false;
    }
    return isprint((unsigned char)name[0]) != 0;
}

static int syms_push(cdbg_syms_t *syms, uintptr_t addr, char type, const char *name)
{
    if (!sym_name_interesting(name, type)) {
        return 0;
    }

    cdbg_sym_entry_t *next = realloc(syms->entries, (syms->count + 1) * sizeof(*syms->entries));
    if (next == NULL) {
        return -1;
    }

    syms->entries = next;
    cdbg_sym_entry_t *entry = &syms->entries[syms->count++];
    entry->address = addr;
    entry->type = type;
    snprintf(entry->name, sizeof(entry->name), "%s", name);
    return 0;
}

static int syms_load_macho(cdbg_syms_t *syms, const uint8_t *data, size_t size)
{
    if (size < sizeof(struct mach_header_64)) {
        return -1;
    }

    const struct mach_header_64 *mh = (const struct mach_header_64 *)data;
    if (mh->magic != MH_MAGIC_64) {
        return -1;
    }

    const struct symtab_command *symtab = NULL;
    const uint8_t *cursor = data + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((size_t)(cursor - data) + sizeof(struct load_command) > size) {
            break;
        }
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SYMTAB) {
            symtab = (const struct symtab_command *)cursor;
        }
        cursor += lc->cmdsize;
    }

    if (symtab == NULL || symtab->nsyms == 0) {
        return -1;
    }
    if ((size_t)symtab->symoff + symtab->nsyms * sizeof(struct nlist_64) > size) {
        return -1;
    }
    if ((size_t)symtab->stroff + symtab->strsize > size) {
        return -1;
    }

    const struct nlist_64 *symbols = (const struct nlist_64 *)(data + symtab->symoff);
    const char *strtab = (const char *)(data + symtab->stroff);

    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        const struct nlist_64 *sym = &symbols[i];
        if ((sym->n_type & N_STAB) != 0) {
            continue;
        }
        if (sym->n_un.n_strx >= symtab->strsize) {
            continue;
        }

        const char *name = strtab + sym->n_un.n_strx;
        char type = nlist_type_char(sym->n_type);
        if (syms_push(syms, (uintptr_t)sym->n_value, type, name) != 0) {
            return -1;
        }
    }

    return syms->count > 0 ? 0 : -1;
}

static int syms_load_from_nm(cdbg_syms_t *syms, const char *path)
{
    char cmd[PATH_MAX + 32];
    int n = snprintf(cmd, sizeof(cmd), "nm -n '%s' 2>/dev/null", path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return -1;
    }

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0' || *p == '\n') {
            continue;
        }

        unsigned long long addr = 0;
        char type = 0;
        char name[CDBG_SYM_MAX_NAME];

        if (sscanf(p, "%llx %c %255s", &addr, &type, name) == 3) {
            (void)syms_push(syms, (uintptr_t)addr, type, name);
            continue;
        }
        if (sscanf(p, "%c %255s", &type, name) == 2) {
            (void)syms_push(syms, 0, type, name);
        }
    }

    return pclose(fp) == 0 && syms->count > 0 ? 0 : -1;
}

int cdbg_syms_load(cdbg_syms_t *syms, const char *executable_path)
{
    memset(syms, 0, sizeof(*syms));

    mapped_file_t exe = {0};
    if (map_file(executable_path, &exe) == 0) {
        syms->link_base = macho_text_vmaddr(exe.data, exe.size);
        unmap_file(&exe);
    }

    char dwarf_path[PATH_MAX];
    const char *objects[2];
    size_t object_count = 0;
    objects[object_count++] = executable_path;
    if (dsym_object_path(executable_path, dwarf_path, sizeof(dwarf_path)) == 0) {
        objects[object_count++] = dwarf_path;
    }

    for (size_t i = 0; i < object_count; i++) {
        if (syms_load_from_nm(syms, objects[i]) == 0) {
            return 0;
        }
    }

    cdbg_syms_free(syms);
    memset(syms, 0, sizeof(*syms));

    if (map_file(executable_path, &exe) != 0) {
        return -1;
    }
    syms->link_base = macho_text_vmaddr(exe.data, exe.size);
    int rc = syms_load_macho(syms, exe.data, exe.size);
    unmap_file(&exe);
    if (rc == 0) {
        return 0;
    }

    if (object_count > 1 && map_file(dwarf_path, &exe) == 0) {
        if (syms->link_base == 0) {
            syms->link_base = macho_text_vmaddr(exe.data, exe.size);
        }
        rc = syms_load_macho(syms, exe.data, exe.size);
        unmap_file(&exe);
    }

    return rc;
}

int cdbg_syms_update_slide(cdbg_syms_t *syms, pid_t pid)
{
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    while (true) {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        natural_t depth = 0;
        kr = mach_vm_region_recurse(task, &addr, &size, &depth,
                                    (vm_region_info_t)&info, &count);
        if (kr != KERN_SUCCESS) {
            break;
        }

        if ((info.protection & VM_PROT_EXECUTE) != 0 &&
            (info.protection & VM_PROT_READ) != 0) {
            syms->slide = (uintptr_t)addr - syms->link_base;
            mach_port_deallocate(mach_task_self(), task);
            return 0;
        }

        addr += size;
    }

    mach_port_deallocate(mach_task_self(), task);
    return -1;
}

void cdbg_syms_free(cdbg_syms_t *syms)
{
    free(syms->entries);
    memset(syms, 0, sizeof(*syms));
}

uintptr_t cdbg_syms_runtime_addr(const cdbg_syms_t *syms, uintptr_t link_addr)
{
    return link_addr + syms->slide;
}

const cdbg_sym_entry_t *cdbg_syms_lookup_name(const cdbg_syms_t *syms, const char *name)
{
    if (name == NULL) {
        return NULL;
    }

    char alt[CDBG_SYM_MAX_NAME];
    const char *lookup = name;
    if (name[0] != '_') {
        snprintf(alt, sizeof(alt), "_%s", name);
        lookup = alt;
    }

    for (size_t i = 0; i < syms->count; i++) {
        if (strcmp(syms->entries[i].name, lookup) == 0) {
            return &syms->entries[i];
        }
    }
    return NULL;
}

static bool sym_matches(const char *name, const char *filter)
{
    if (filter == NULL || filter[0] == '\0') {
        return true;
    }
    if (strstr(name, filter) != NULL) {
        return true;
    }
    if (name[0] == '_' && strstr(name + 1, filter) != NULL) {
        return true;
    }
    return false;
}

void cdbg_syms_print_list(const cdbg_syms_t *syms, const char *name_filter)
{
    if (syms->count == 0) {
        puts("No symbol information loaded.");
        return;
    }

    printf("%18s  %-4s  %s\n", "Address", "Type", "Name");
    printf("%18s  %-4s  %s\n", "-------", "----", "----");

    for (size_t i = 0; i < syms->count; i++) {
        const cdbg_sym_entry_t *entry = &syms->entries[i];
        if (!sym_matches(entry->name, name_filter)) {
            continue;
        }

        if (entry->address == 0) {
            printf("%18s  %-4c  %s\n", "", entry->type, entry->name);
        } else {
            uintptr_t runtime = cdbg_syms_runtime_addr(syms, entry->address);
            printf("0x%016lx  %-4c  %s\n",
                   (unsigned long)runtime,
                   entry->type,
                   entry->name);
        }
    }
}
