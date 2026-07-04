#include "lineno.h"

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
#include <mach-o/fat.h>

#define DW_LNS_copy             1
#define DW_LNS_advance_pc       2
#define DW_LNS_advance_line     3
#define DW_LNS_set_file         4
#define DW_LNS_set_column       5
#define DW_LNS_const_add_pc     8
#define DW_LNS_fixed_advance_pc 9
#define DW_LNE_end_sequence     1
#define DW_LNE_set_address      2

#define DW_LNCT_path              1
#define DW_LNCT_directory_index   2
#define DW_LNCT_MD5               5
#define DW_FORM_string            0x08
#define DW_FORM_udata             0x0f
#define DW_FORM_data16            0x1e
#define DW_FORM_line_strp         0x1f

typedef struct mapped_file {
    uint8_t *data;
    size_t size;
} mapped_file_t;

typedef struct parse_cursor {
    const uint8_t *data;
    const uint8_t *end;
} parse_cursor_t;

typedef struct line_state {
    uint64_t address;
    int64_t line;
    uint64_t file_index;
    uint64_t column;
    bool is_stmt;
    bool end_sequence;
} line_state_t;

static int map_file(const char *path, mapped_file_t *out)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("fstat");
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
        perror("mmap");
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

static bool cursor_ok(parse_cursor_t *cursor, size_t n)
{
    return (size_t)(cursor->end - cursor->data) >= n;
}

static uint8_t read_u8(parse_cursor_t *cursor)
{
    if (!cursor_ok(cursor, 1)) {
        return 0;
    }
    return *cursor->data++;
}

static uint16_t read_u16(parse_cursor_t *cursor)
{
    if (!cursor_ok(cursor, 2)) {
        return 0;
    }
    uint16_t value = (uint16_t)cursor->data[0] | ((uint16_t)cursor->data[1] << 8);
    cursor->data += 2;
    return value;
}

static uint32_t read_u32(parse_cursor_t *cursor)
{
    if (!cursor_ok(cursor, 4)) {
        return 0;
    }
    uint32_t value = (uint32_t)cursor->data[0]
        | ((uint32_t)cursor->data[1] << 8)
        | ((uint32_t)cursor->data[2] << 16)
        | ((uint32_t)cursor->data[3] << 24);
    cursor->data += 4;
    return value;
}

static uint64_t read_u64(parse_cursor_t *cursor)
{
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value |= (uint64_t)read_u8(cursor) << (8 * i);
    }
    return value;
}

static uint64_t read_uleb128(parse_cursor_t *cursor)
{
    uint64_t value = 0;
    unsigned shift = 0;
    for (int i = 0; i < 10; i++) {
        uint8_t byte = read_u8(cursor);
        value |= (uint64_t)(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            return value;
        }
        shift += 7;
    }
    return value;
}

static int64_t read_sleb128(parse_cursor_t *cursor)
{
    uint64_t value = 0;
    unsigned shift = 0;
    uint8_t byte = 0;
    for (int i = 0; i < 10; i++) {
        byte = read_u8(cursor);
        value |= (uint64_t)(byte & 0x7f) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    if ((byte & 0x40) != 0 && shift < 64) {
        value |= ~0ULL << shift;
    }
    return (int64_t)value;
}

static const char *read_cstr(parse_cursor_t *cursor)
{
    const char *start = (const char *)cursor->data;
    while (cursor->data < cursor->end && *cursor->data != '\0') {
        cursor->data++;
    }
    if (cursor->data >= cursor->end) {
        return start;
    }
    cursor->data++;
    return start;
}

static int dsym_dwarf_path(const char *executable_path, char *out, size_t out_len)
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

static bool sect_name_eq(const char *a, const char *b)
{
    return strncmp(a, b, 16) == 0;
}

static bool macho_find_section(const uint8_t *data, size_t size,
                               const char *segname, const char *sectname,
                               uint32_t *offset, uint32_t *sect_size)
{
    if (size < sizeof(struct mach_header_64)) {
        return false;
    }

    const struct mach_header_64 *mh = (const struct mach_header_64 *)data;
    if (mh->magic != MH_MAGIC_64) {
        return false;
    }

    const uint8_t *cursor = data + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((size_t)(cursor - data) + sizeof(struct load_command) > size) {
            break;
        }
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sec = (const struct section_64 *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (sect_name_eq(sec[j].segname, segname) &&
                    sect_name_eq(sec[j].sectname, sectname)) {
                    *offset = sec[j].offset;
                    *sect_size = sec[j].size;
                    return true;
                }
            }
        }
        cursor += lc->cmdsize;
    }

    return false;
}

typedef struct {
    char **items;
    size_t count;
} str_table_t;

static int str_table_push(str_table_t *table, const char *value)
{
    char *copy = strdup(value);
    if (copy == NULL) {
        return -1;
    }

    char **next = realloc(table->items, (table->count + 1) * sizeof(char *));
    if (next == NULL) {
        free(copy);
        return -1;
    }

    table->items = next;
    table->items[table->count++] = copy;
    return 0;
}

static void str_table_free(str_table_t *table)
{
    for (size_t i = 0; i < table->count; i++) {
        free(table->items[i]);
    }
    free(table->items);
    table->items = NULL;
    table->count = 0;
}

typedef struct {
    char **items;
    uint64_t *dir_indices;
    size_t count;
} file_table_t;

static int file_table_push(file_table_t *table, const char *name, uint64_t dir_index)
{
    char *copy = strdup(name);
    if (copy == NULL) {
        return -1;
    }

    char **next_names = realloc(table->items, (table->count + 1) * sizeof(char *));
    uint64_t *next_dirs = realloc(table->dir_indices, (table->count + 1) * sizeof(uint64_t));
    if (next_names == NULL || next_dirs == NULL) {
        free(copy);
        free(next_names);
        free(next_dirs);
        return -1;
    }

    table->items = next_names;
    table->dir_indices = next_dirs;
    table->items[table->count] = copy;
    table->dir_indices[table->count] = dir_index;
    table->count++;
    return 0;
}

static void file_table_free(file_table_t *table)
{
    for (size_t i = 0; i < table->count; i++) {
        free(table->items[i]);
    }
    free(table->items);
    free(table->dir_indices);
    table->items = NULL;
    table->dir_indices = NULL;
    table->count = 0;
}

static int build_file_path(char *out, size_t out_len,
                           const str_table_t *dirs, const file_table_t *files,
                           uint64_t file_index)
{
    if (file_index >= files->count || file_index == 0) {
        return -1;
    }

    const char *file = files->items[file_index];
    uint64_t dir_index = files->dir_indices[file_index];
    const char *dir = "";
    if (dirs->count > 0 && dir_index < dirs->count) {
        dir = dirs->items[dir_index];
    }

    if (dir[0] == '\0') {
        snprintf(out, out_len, "%s", file);
    } else {
        snprintf(out, out_len, "%s/%s", dir, file);
    }
    return 0;
}

static int entries_push(cdbg_lineno_t *ln, const line_state_t *state,
                        const str_table_t *dirs, const file_table_t *files)
{
    char full_path[CDBG_LINENO_MAX_FILE];
    if (build_file_path(full_path, sizeof(full_path), dirs, files, state->file_index) != 0) {
        return 0;
    }

    cdbg_line_entry_t *next = realloc(ln->entries, (ln->count + 1) * sizeof(*ln->entries));
    if (next == NULL) {
        return -1;
    }

    ln->entries = next;
    cdbg_line_entry_t *entry = &ln->entries[ln->count++];
    entry->address = (uintptr_t)state->address;
    entry->line = (uint32_t)state->line;
    entry->column = (uint32_t)state->column;
    snprintf(entry->file, sizeof(entry->file), "%s", full_path);
    return 0;
}

static void emit_row(cdbg_lineno_t *ln, line_state_t *state,
                     const str_table_t *dirs, const file_table_t *files)
{
    if (state->line <= 0) {
        return;
    }
    (void)entries_push(ln, state, dirs, files);
}

static const char *lookup_line_str(const uint8_t *line_str, size_t line_str_size,
                                   uint64_t offset)
{
    if (line_str == NULL || offset >= line_str_size) {
        return "";
    }
    return (const char *)(line_str + offset);
}

typedef struct {
    uint64_t type;
    uint64_t form;
} format_desc_t;

static int read_format_descriptors(parse_cursor_t *cursor,
                                   format_desc_t **out, size_t *out_count)
{
    uint8_t count = read_u8(cursor);
    if (count == 0) {
        *out = NULL;
        *out_count = 0;
        return 0;
    }

    format_desc_t *descs = calloc(count, sizeof(format_desc_t));
    if (descs == NULL) {
        return -1;
    }

    for (uint8_t i = 0; i < count; i++) {
        descs[i].type = read_uleb128(cursor);
        descs[i].form = read_uleb128(cursor);
    }

    *out = descs;
    *out_count = count;
    return 0;
}

static int read_form_string(parse_cursor_t *cursor, uint64_t form,
                            const uint8_t *line_str, size_t line_str_size,
                            char *out, size_t out_len)
{
    if (form == DW_FORM_line_strp) {
        if (!cursor_ok(cursor, 1)) {
            return -1;
        }
        uint64_t offset = read_uleb128(cursor);
        snprintf(out, out_len, "%s", lookup_line_str(line_str, line_str_size, offset));
        return 0;
    }
    if (form == DW_FORM_string) {
        snprintf(out, out_len, "%s", read_cstr(cursor));
        return 0;
    }
    return -1;
}

static int skip_form_value(parse_cursor_t *cursor, uint64_t form)
{
    switch (form) {
    case DW_FORM_udata:
        (void)read_uleb128(cursor);
        return 0;
    case DW_FORM_data16:
        if (!cursor_ok(cursor, 16)) {
            return -1;
        }
        cursor->data += 16;
        return 0;
    case DW_FORM_string:
        (void)read_cstr(cursor);
        return 0;
    case DW_FORM_line_strp:
        (void)read_uleb128(cursor);
        return 0;
    default:
        return -1;
    }
}

static void skip_padding_zeros(parse_cursor_t *cursor)
{
    while (cursor->data < cursor->end && *cursor->data == 0) {
        cursor->data++;
    }
}

static int parse_v5_directories(parse_cursor_t *cursor,
                                const uint8_t *line_str, size_t line_str_size,
                                str_table_t *dirs)
{
    format_desc_t *descs = NULL;
    size_t desc_count = 0;
    if (read_format_descriptors(cursor, &descs, &desc_count) != 0) {
        return -1;
    }
    if (desc_count == 0) {
        free(descs);
        return 0;
    }

    uint64_t entry_count = read_uleb128(cursor);
    for (uint64_t i = 0; i < entry_count; i++) {
        char path[CDBG_LINENO_MAX_FILE] = "";
        for (size_t d = 0; d < desc_count; d++) {
            if (descs[d].type == DW_LNCT_path) {
                if (read_form_string(cursor, descs[d].form, line_str, line_str_size,
                                     path, sizeof(path)) != 0) {
                    free(descs);
                    return -1;
                }
            } else if (skip_form_value(cursor, descs[d].form) != 0) {
                free(descs);
                return -1;
            }
        }
        if (str_table_push(dirs, path) != 0) {
            free(descs);
            return -1;
        }
    }

    skip_padding_zeros(cursor);
    free(descs);
    return 0;
}

static int parse_v5_file_names(parse_cursor_t *cursor,
                               const uint8_t *line_str, size_t line_str_size,
                               file_table_t *files)
{
    format_desc_t *descs = NULL;
    size_t desc_count = 0;
    if (read_format_descriptors(cursor, &descs, &desc_count) != 0) {
        return -1;
    }
    if (desc_count == 0) {
        free(descs);
        return 0;
    }

    uint64_t entry_count = read_uleb128(cursor);
    for (uint64_t i = 0; i < entry_count; i++) {
        char name[CDBG_LINENO_MAX_FILE] = "";
        uint64_t dir_index = 0;
        for (size_t d = 0; d < desc_count; d++) {
            if (descs[d].type == DW_LNCT_path) {
                if (read_form_string(cursor, descs[d].form, line_str, line_str_size,
                                     name, sizeof(name)) != 0) {
                    free(descs);
                    return -1;
                }
            } else if (descs[d].type == DW_LNCT_directory_index &&
                       descs[d].form == DW_FORM_udata) {
                dir_index = read_uleb128(cursor);
            } else if (descs[d].type == DW_LNCT_MD5 &&
                       descs[d].form == DW_FORM_data16) {
                if (!cursor_ok(cursor, 16)) {
                    free(descs);
                    return -1;
                }
                cursor->data += 16;
            } else if (skip_form_value(cursor, descs[d].form) != 0) {
                free(descs);
                return -1;
            }
        }
        if (file_table_push(files, name, dir_index) != 0) {
            free(descs);
            return -1;
        }
    }

    free(descs);
    return 0;
}

static int parse_file_names_v4(parse_cursor_t *cursor, file_table_t *files)
{
    while (cursor->data < cursor->end) {
        const char *name = read_cstr(cursor);
        if (name[0] == '\0') {
            break;
        }
        uint64_t dir_index = read_uleb128(cursor);
        if (!cursor_ok(cursor, 16)) {
            return -1;
        }
        cursor->data += 16;
        if (file_table_push(files, name, dir_index) != 0) {
            return -1;
        }
    }
    return 0;
}

static int parse_line_program(cdbg_lineno_t *ln, parse_cursor_t *unit,
                              const str_table_t *dirs, const file_table_t *files,
                              uint8_t opcode_base, int8_t line_base,
                              uint8_t line_range, uint8_t min_inst_length,
                              uint8_t max_ops_per_inst, uint8_t default_is_stmt,
                              uint8_t address_size, const uint8_t *std_lengths)
{
  (void)max_ops_per_inst;
    line_state_t state = {
        .address = 0,
        .line = 1,
        .file_index = 1,
        .column = 0,
        .is_stmt = default_is_stmt != 0,
        .end_sequence = false,
    };

    while (unit->data < unit->end) {
        uint8_t opcode = read_u8(unit);
        if (opcode == 0) {
            uint64_t ext_len = read_uleb128(unit);
            const uint8_t *ext_end = unit->data + ext_len;
            if (ext_end > unit->end) {
                return -1;
            }
            uint8_t sub = read_u8(unit);
            if (sub == DW_LNE_end_sequence) {
                state.end_sequence = true;
                emit_row(ln, &state, dirs, files);
                state = (line_state_t){
                    .address = 0,
                    .line = 1,
                    .file_index = 1,
                    .column = 0,
                    .is_stmt = default_is_stmt != 0,
                    .end_sequence = false,
                };
            } else if (sub == DW_LNE_set_address) {
                if (address_size == 8) {
                    state.address = read_u64(unit);
                } else if (address_size == 4) {
                    state.address = read_u32(unit);
                }
            }
            unit->data = ext_end;
            continue;
        }

        if (opcode < opcode_base) {
            switch (opcode) {
            case DW_LNS_copy:
                emit_row(ln, &state, dirs, files);
                break;
            case DW_LNS_advance_pc: {
                uint64_t delta = read_uleb128(unit);
                state.address += delta * min_inst_length;
                break;
            }
            case DW_LNS_advance_line:
                state.line += read_sleb128(unit);
                break;
            case DW_LNS_set_file:
                state.file_index = read_uleb128(unit);
                break;
            case DW_LNS_set_column:
                state.column = read_uleb128(unit);
                break;
            case DW_LNS_const_add_pc:
                state.address += (uint64_t)(255 - opcode_base) / line_range * min_inst_length;
                break;
            case DW_LNS_fixed_advance_pc: {
                uint16_t delta = read_u16(unit);
                state.address += delta;
                break;
            }
            default:
                if (opcode < opcode_base && std_lengths[opcode] > 0) {
                    unit->data += std_lengths[opcode];
                }
                break;
            }
            continue;
        }

        uint8_t adjusted = (uint8_t)(opcode - opcode_base);
        uint8_t operation_advance = (uint8_t)(adjusted / line_range);
        int8_t line_increment = (int8_t)(line_base + (adjusted % line_range));
        state.line += line_increment;
        state.address += (uint64_t)operation_advance * min_inst_length;
        emit_row(ln, &state, dirs, files);
    }

    return 0;
}

static int parse_line_table(cdbg_lineno_t *ln, const uint8_t *section, size_t section_size,
                            const uint8_t *line_str, size_t line_str_size)
{
    parse_cursor_t cursor = { section, section + section_size };

    while (cursor.data < cursor.end) {
        const uint8_t *unit_start = cursor.data;
        uint32_t unit_length = read_u32(&cursor);
        if (unit_length == 0xffffffffU) {
            return -1;
        }

        const uint8_t *unit_end = cursor.data + unit_length;
        if (unit_end > cursor.end) {
            return -1;
        }

        parse_cursor_t unit = { cursor.data, unit_end };
        uint16_t version = read_u16(&unit);
        if (version != 5 && version != 4) {
            cursor.data = unit_end;
            continue;
        }

        uint8_t address_size = 8;
        uint8_t segment_size = 0;
        if (version == 5) {
            address_size = read_u8(&unit);
            segment_size = read_u8(&unit);
            (void)segment_size;
        }

        uint32_t prologue_length = read_u32(&unit);
        const uint8_t *prologue_end = unit.data + prologue_length;
        if (prologue_end > unit.end) {
            return -1;
        }

        parse_cursor_t prologue = { unit.data, prologue_end };
        const uint8_t *prologue_start = prologue.data;
        uint8_t min_inst_length = read_u8(&prologue);
        uint8_t max_ops_per_inst = version == 5 ? read_u8(&prologue) : 1;
        uint8_t default_is_stmt = read_u8(&prologue);
        int8_t line_base = (int8_t)read_u8(&prologue);
        uint8_t line_range = read_u8(&prologue);
        uint8_t opcode_base = read_u8(&prologue);

        uint8_t std_lengths[16] = {0};
        for (uint8_t i = 1; i < opcode_base && i < sizeof(std_lengths); i++) {
            std_lengths[i] = read_u8(&prologue);
        }

        str_table_t dirs = {0};
        file_table_t files = {0};

        if (version != 5) {
            if (str_table_push(&dirs, "") != 0) {
                return -1;
            }
        }
        if (file_table_push(&files, "", 0) != 0) {
            str_table_free(&dirs);
            return -1;
        }

        if (version == 5) {
            if (parse_v5_directories(&prologue, line_str, line_str_size, &dirs) != 0 ||
                parse_v5_file_names(&prologue, line_str, line_str_size, &files) != 0) {
                str_table_free(&dirs);
                file_table_free(&files);
                return -1;
            }
            if (dirs.count > 0 && ln->comp_dir[0] == '\0') {
                snprintf(ln->comp_dir, sizeof(ln->comp_dir), "%s", dirs.items[0]);
            }
        } else {
            while (prologue.data < prologue.end) {
                const char *dir = read_cstr(&prologue);
                if (dir[0] == '\0') {
                    break;
                }
                if (str_table_push(&dirs, dir) != 0) {
                    str_table_free(&dirs);
                    file_table_free(&files);
                    return -1;
                }
            }

            if (parse_file_names_v4(&prologue, &files) != 0) {
                str_table_free(&dirs);
                file_table_free(&files);
                return -1;
            }
            if (ln->comp_dir[0] == '\0') {
                for (size_t di = 0; di < dirs.count; di++) {
                    if (dirs.items[di][0] != '\0') {
                        snprintf(ln->comp_dir, sizeof(ln->comp_dir), "%s", dirs.items[di]);
                        break;
                    }
                }
            }
        }

        unit.data = (version == 5) ? (prologue_end - 1) : prologue.data;
        (void)prologue_start;
        if (parse_line_program(ln, &unit, &dirs, &files, opcode_base, line_base,
                               line_range, min_inst_length, max_ops_per_inst,
                               default_is_stmt, address_size, std_lengths) != 0) {
            str_table_free(&dirs);
            file_table_free(&files);
            return -1;
        }

        str_table_free(&dirs);
        file_table_free(&files);
        cursor.data = unit_end;
        (void)unit_start;
    }

    return 0;
}

static int lineno_push(cdbg_lineno_t *ln, uintptr_t addr, uint32_t line,
                       uint32_t column, const char *file)
{
    cdbg_line_entry_t *next = realloc(ln->entries, (ln->count + 1) * sizeof(*ln->entries));
    if (next == NULL) {
        return -1;
    }

    ln->entries = next;
    cdbg_line_entry_t *entry = &ln->entries[ln->count++];
    entry->address = addr;
    entry->line = line;
    entry->column = column;
    snprintf(entry->file, sizeof(entry->file), "%s", file);
    return 0;
}

static int lineno_load_from_dwarfdump(cdbg_lineno_t *ln, const char *debug_obj)
{
    char cmd[PATH_MAX + 64];
    int n = snprintf(cmd, sizeof(cmd), "dwarfdump --debug-line '%s' 2>/dev/null", debug_obj);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return -1;
    }

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    char current_dir[CDBG_LINENO_MAX_FILE] = "";
    char current_file[CDBG_LINENO_MAX_FILE] = "";
    char line_buf[512];

    while (fgets(line_buf, sizeof(line_buf), fp) != NULL) {
        char *dir_marker = strstr(line_buf, "include_directories");
        if (dir_marker != NULL) {
            char *quote = strchr(dir_marker, '"');
            if (quote != NULL) {
                char *end = strchr(quote + 1, '"');
                if (end != NULL) {
                    size_t len = (size_t)(end - quote - 1);
                    if (len >= sizeof(current_dir)) {
                        len = sizeof(current_dir) - 1;
                    }
                    memcpy(current_dir, quote + 1, len);
                    current_dir[len] = '\0';
                }
            }
            continue;
        }

        char *name_marker = strstr(line_buf, "name: \"");
        if (name_marker != NULL) {
            char *quote = name_marker + strlen("name: \"");
            char *end = strchr(quote, '"');
            if (end != NULL) {
                size_t len = (size_t)(end - quote);
                if (len >= sizeof(current_file)) {
                    len = sizeof(current_file) - 1;
                }
                memcpy(current_file, quote, len);
                current_file[len] = '\0';
            }
            continue;
        }

        unsigned long long addr = 0;
        unsigned int line_no = 0;
        unsigned int column = 0;
        if (line_buf[0] != '0' || line_buf[1] != 'x') {
            continue;
        }
        if (sscanf(line_buf, "0x%llx %u %u", &addr, &line_no, &column) != 3) {
            continue;
        }

        char full_path[CDBG_LINENO_MAX_FILE];
        if (current_file[0] == '\0') {
            snprintf(full_path, sizeof(full_path), "<unknown>");
        } else if (strchr(current_file, '/') != NULL || current_dir[0] == '\0') {
            snprintf(full_path, sizeof(full_path), "%s", current_file);
        } else {
            snprintf(full_path, sizeof(full_path), "%s/%s", current_dir, current_file);
        }

        if (lineno_push(ln, (uintptr_t)addr, line_no, column, full_path) != 0) {
            pclose(fp);
            return -1;
        }
    }

    if (current_dir[0] != '\0') {
        snprintf(ln->comp_dir, sizeof(ln->comp_dir), "%s", current_dir);
    }

    return pclose(fp) == 0 && ln->count > 0 ? 0 : -1;
}

int cdbg_lineno_load(cdbg_lineno_t *ln, const char *executable_path)
{
    memset(ln, 0, sizeof(*ln));

    char exe_dir_buf[CDBG_LINENO_MAX_FILE];
    snprintf(exe_dir_buf, sizeof(exe_dir_buf), "%s", executable_path);
    snprintf(ln->exe_dir, sizeof(ln->exe_dir), "%s", dirname(exe_dir_buf));

    mapped_file_t exe = {0};
    if (map_file(executable_path, &exe) != 0) {
        return -1;
    }
    ln->link_base = macho_text_vmaddr(exe.data, exe.size);
    unmap_file(&exe);

    char dwarf_path[PATH_MAX];
    const char *debug_obj = executable_path;
    if (dsym_dwarf_path(executable_path, dwarf_path, sizeof(dwarf_path)) == 0) {
        debug_obj = dwarf_path;
    }

    if (lineno_load_from_dwarfdump(ln, debug_obj) == 0) {
        return 0;
    }

    char saved_exe_dir[CDBG_LINENO_MAX_FILE];
    snprintf(saved_exe_dir, sizeof(saved_exe_dir), "%s", ln->exe_dir);

    cdbg_lineno_free(ln);
    memset(ln, 0, sizeof(*ln));
    snprintf(ln->exe_dir, sizeof(ln->exe_dir), "%s", saved_exe_dir);

    if (map_file(executable_path, &exe) != 0) {
        return -1;
    }
    ln->link_base = macho_text_vmaddr(exe.data, exe.size);
    unmap_file(&exe);

    mapped_file_t dwarf = {0};
    if (map_file(debug_obj, &dwarf) != 0) {
        fprintf(stderr, "No debug info found for %s\n", executable_path);
        return -1;
    }

    uint32_t line_offset = 0;
    uint32_t line_size = 0;
    uint32_t line_str_offset = 0;
    uint32_t line_str_size = 0;
    if (!macho_find_section(dwarf.data, dwarf.size, "__DWARF", "__debug_line",
                            &line_offset, &line_size)) {
        unmap_file(&dwarf);
        fprintf(stderr, "Missing __debug_line section\n");
        return -1;
    }
    (void)macho_find_section(dwarf.data, dwarf.size, "__DWARF", "__debug_line_str",
                             &line_str_offset, &line_str_size);

    if ((size_t)line_offset + line_size > dwarf.size) {
        unmap_file(&dwarf);
        return -1;
    }

    const uint8_t *line_str = NULL;
    if (line_str_size > 0 && (size_t)line_str_offset + line_str_size <= dwarf.size) {
        line_str = dwarf.data + line_str_offset;
    }

    int rc = parse_line_table(ln, dwarf.data + line_offset, line_size,
                              line_str, line_str_size);
    unmap_file(&dwarf);
    if (rc != 0 || ln->count == 0) {
        fprintf(stderr, "Failed to parse line number table\n");
        cdbg_lineno_free(ln);
        return -1;
    }

    return 0;
}

int cdbg_lineno_update_slide(cdbg_lineno_t *ln, pid_t pid)
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
            ln->slide = (uintptr_t)addr - ln->link_base;
            mach_port_deallocate(mach_task_self(), task);
            return 0;
        }

        addr += size;
    }

    mach_port_deallocate(mach_task_self(), task);
    return -1;
}

void cdbg_lineno_free(cdbg_lineno_t *ln)
{
    free(ln->entries);
    memset(ln, 0, sizeof(*ln));
}

uintptr_t cdbg_lineno_runtime_addr(const cdbg_lineno_t *ln, uintptr_t link_addr)
{
    return link_addr + ln->slide;
}

static bool file_matches(const char *entry_file, const char *filter);

const cdbg_line_entry_t *cdbg_lineno_lookup_pc(const cdbg_lineno_t *ln, uintptr_t runtime_pc)
{
    const cdbg_line_entry_t *best = NULL;
    for (size_t i = 0; i < ln->count; i++) {
        uintptr_t addr = cdbg_lineno_runtime_addr(ln, ln->entries[i].address);
        if (addr <= runtime_pc) {
            if (best == NULL ||
                addr > cdbg_lineno_runtime_addr(ln, best->address)) {
                best = &ln->entries[i];
            }
        }
    }
    return best;
}

const cdbg_line_entry_t *cdbg_lineno_lookup_line(const cdbg_lineno_t *ln,
                                                   const char *file_filter,
                                                   uint32_t line)
{
    const cdbg_line_entry_t *match = NULL;

    for (size_t i = 0; i < ln->count; i++) {
        const cdbg_line_entry_t *entry = &ln->entries[i];
        if (entry->line != line) {
            continue;
        }
        if (!file_matches(entry->file, file_filter)) {
            continue;
        }
        if (match == NULL || entry->address < match->address) {
            match = entry;
        }
    }

    return match;
}

const cdbg_line_entry_t *cdbg_lineno_lookup_line_unique(const cdbg_lineno_t *ln,
                                                        uint32_t line)
{
    const cdbg_line_entry_t *match = NULL;
    const char *only_file = NULL;

    for (size_t i = 0; i < ln->count; i++) {
        const cdbg_line_entry_t *entry = &ln->entries[i];
        if (entry->line != line) {
            continue;
        }
        if (only_file == NULL) {
            only_file = entry->file;
            match = entry;
            continue;
        }
        if (strcmp(only_file, entry->file) != 0) {
            return NULL;
        }
        if (entry->address < match->address) {
            match = entry;
        }
    }

    return match;
}

static bool file_matches(const char *entry_file, const char *filter)
{
    if (filter == NULL || filter[0] == '\0') {
        return true;
    }
    const char *base = strrchr(entry_file, '/');
    base = base != NULL ? base + 1 : entry_file;
    return strstr(entry_file, filter) != NULL || strcmp(base, filter) == 0;
}

#define CDBG_SOURCE_CONTEXT 3
#define CDBG_LIST_SOURCE_LINES 10

static FILE *lineno_open_source(const cdbg_lineno_t *ln, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp != NULL) {
        return fp;
    }

    if (path[0] != '/' && ln->comp_dir[0] != '\0') {
        char resolved[CDBG_LINENO_MAX_FILE];
        snprintf(resolved, sizeof(resolved), "%s/%s", ln->comp_dir, path);
        fp = fopen(resolved, "r");
        if (fp != NULL) {
            return fp;
        }
    }

    if (path[0] != '/' && ln->exe_dir[0] != '\0') {
        char resolved[CDBG_LINENO_MAX_FILE];
        snprintf(resolved, sizeof(resolved), "%s/%s", ln->exe_dir, path);
        fp = fopen(resolved, "r");
        if (fp != NULL) {
            return fp;
        }
    }

    const char *base = strrchr(path, '/');
    base = (base != NULL) ? base + 1 : path;
    return fopen(base, "r");
}

static int lineno_print_source_window(const cdbg_lineno_t *ln, const char *file,
                                      uint32_t target, uint32_t total_lines)
{
    FILE *fp = lineno_open_source(ln, file);
    if (fp == NULL) {
        fprintf(stderr, "Cannot read source: %s\n", file);
        return -1;
    }

    uint32_t before = total_lines / 2;
    uint32_t start = (target > before) ? target - before : 1;
    uint32_t end = start + total_lines - 1;

    printf("\n%s:%u\n", file, target);

    char buf[4096];
    uint32_t line_no = 0;
    bool printed_target = false;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        line_no++;
        if (line_no < start) {
            continue;
        }
        if (line_no > end) {
            break;
        }

        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
            buf[--len] = '\0';
        }

        const char *marker = (line_no == target) ? ">" : " ";
        if (line_no == target) {
            printed_target = true;
        }
        printf("%s%4u | %s\n", marker, line_no, buf);
    }

    fclose(fp);
    putchar('\n');
    return printed_target ? 0 : -1;
}

static const cdbg_line_entry_t *lineno_entry_at_pc(const cdbg_lineno_t *ln,
                                                   uintptr_t runtime_pc)
{
    const cdbg_line_entry_t *entry = cdbg_lineno_lookup_pc(ln, runtime_pc);
    if (entry == NULL || entry->line == 0) {
        return NULL;
    }

    uintptr_t entry_runtime = cdbg_lineno_runtime_addr(ln, entry->address);
    uintptr_t max_pc = entry_runtime + 128;
    for (size_t i = 0; i < ln->count; i++) {
        uintptr_t addr = cdbg_lineno_runtime_addr(ln, ln->entries[i].address);
        if (addr > entry_runtime && addr < max_pc) {
            max_pc = addr - 1;
        }
    }
    if (runtime_pc > max_pc) {
        return NULL;
    }

    return entry;
}

int cdbg_lineno_line_at_pc(const cdbg_lineno_t *ln, uintptr_t runtime_pc,
                           char *file_out, size_t file_len, uint32_t *line_out)
{
    const cdbg_line_entry_t *entry = lineno_entry_at_pc(ln, runtime_pc);
    if (entry == NULL) {
        return -1;
    }

    snprintf(file_out, file_len, "%s", entry->file);
    *line_out = entry->line;
    return 0;
}

const cdbg_line_entry_t *cdbg_lineno_lookup_next_line_after_pc(const cdbg_lineno_t *ln,
                                                               uintptr_t runtime_pc)
{
    const cdbg_line_entry_t *current = cdbg_lineno_lookup_pc(ln, runtime_pc);
    if (current == NULL) {
        return NULL;
    }

    const cdbg_line_entry_t *next = NULL;
    for (size_t i = 0; i < ln->count; i++) {
        const cdbg_line_entry_t *entry = &ln->entries[i];
        uintptr_t addr = cdbg_lineno_runtime_addr(ln, entry->address);
        if (addr <= runtime_pc) {
            continue;
        }
        if (strcmp(entry->file, current->file) != 0 || entry->line == current->line) {
            continue;
        }
        if (next == NULL || entry->address < next->address) {
            next = entry;
        }
    }

    return next;
}

int cdbg_lineno_print_source_at_pc(const cdbg_lineno_t *ln, uintptr_t runtime_pc)
{
    const cdbg_line_entry_t *entry = lineno_entry_at_pc(ln, runtime_pc);
    if (entry == NULL) {
        return -1;
    }

    return lineno_print_source_window(ln, entry->file, entry->line,
                                      CDBG_SOURCE_CONTEXT * 2 + 1);
}

int cdbg_lineno_print_source_at_line(const cdbg_lineno_t *ln,
                                     const char *file_filter,
                                     uint32_t line)
{
    if (ln->count == 0) {
        fputs("No line number information loaded\n", stderr);
        return -1;
    }

    const char *matched_file = NULL;
    for (size_t i = 0; i < ln->count; i++) {
        const cdbg_line_entry_t *entry = &ln->entries[i];
        if (!file_matches(entry->file, file_filter)) {
            continue;
        }
        if (matched_file == NULL) {
            matched_file = entry->file;
            continue;
        }
        if (strcmp(matched_file, entry->file) != 0) {
            if (file_filter == NULL || file_filter[0] == '\0') {
                fprintf(stderr, "Line %u is ambiguous; use file:line\n", line);
            } else {
                fprintf(stderr, "File filter is ambiguous: %s\n", file_filter);
            }
            return -1;
        }
    }

    if (matched_file == NULL) {
        if (file_filter == NULL || file_filter[0] == '\0') {
            fprintf(stderr, "No source file for line %u\n", line);
        } else {
            fprintf(stderr, "No source file matches: %s\n", file_filter);
        }
        return -1;
    }

    return lineno_print_source_window(ln, matched_file, line, CDBG_LIST_SOURCE_LINES);
}

void cdbg_lineno_print_list(const cdbg_lineno_t *ln, const char *file_filter)
{
    if (ln->count == 0) {
        puts("No line number information loaded.");
        return;
    }

    const char *current_file = "";
    uint32_t last_line = 0;
    bool has_last_line = false;

    for (size_t i = 0; i < ln->count; i++) {
        const cdbg_line_entry_t *entry = &ln->entries[i];
        if (!file_matches(entry->file, file_filter)) {
            continue;
        }

        if (strcmp(current_file, entry->file) != 0) {
            if (current_file[0] != '\0') {
                putchar('\n');
            }
            current_file = entry->file;
            last_line = 0;
            has_last_line = false;
            printf("File: %s\n", current_file);
            printf("%6s  %-18s  %s\n", "Line", "Address", "Column");
            printf("%6s  %-18s  %s\n", "----", "-------", "------");
        }

        if (has_last_line && entry->line == last_line) {
            continue;
        }

        last_line = entry->line;
        has_last_line = true;
        uintptr_t runtime = cdbg_lineno_runtime_addr(ln, entry->address);
        printf("%6u  0x%016lx  %u\n",
               entry->line,
               (unsigned long)runtime,
               entry->column);
    }
}
