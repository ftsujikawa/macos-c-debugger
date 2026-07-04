#include "debugger.h"

#include <ctype.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "memory.h"
#include "process.h"

static int report_stop(cdbg_t *dbg);
static void print_stop_location(cdbg_t *dbg, uintptr_t pc);

static int debugger_dsym_path(const char *executable_path, char *out, size_t out_len)
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

int cdbg_init(cdbg_t *dbg)
{
    memset(dbg, 0, sizeof(*dbg));
    dbg->state = CDBG_STATE_IDLE;
    return 0;
}

int cdbg_load_symbols(cdbg_t *dbg, const char *executable_path)
{
    cdbg_lineno_free(&dbg->lineno);
    cdbg_syms_free(&dbg->syms);
    snprintf(dbg->executable_path, sizeof(dbg->executable_path), "%s", executable_path);
    if (debugger_dsym_path(executable_path, dbg->debug_info_path,
                           sizeof(dbg->debug_info_path)) != 0) {
        snprintf(dbg->debug_info_path, sizeof(dbg->debug_info_path), "%s", executable_path);
    }

    int lineno_ok = cdbg_lineno_load(&dbg->lineno, executable_path) == 0;
    int syms_ok = cdbg_syms_load(&dbg->syms, executable_path) == 0;

    if (dbg->pid > 0) {
        if (lineno_ok) {
            (void)cdbg_lineno_update_slide(&dbg->lineno, dbg->pid);
        }
        if (syms_ok) {
            (void)cdbg_syms_update_slide(&dbg->syms, dbg->pid);
        }
    }

    return (lineno_ok || syms_ok) ? 0 : -1;
}

int cdbg_spawn(cdbg_t *dbg, char *const argv[])
{
    pid_t pid;

    if (cdbg_process_spawn(&pid, argv) != 0) {
        return -1;
    }

    dbg->pid = pid;
    dbg->state = CDBG_STATE_RUNNING;
    if (dbg->lineno.count > 0) {
        (void)cdbg_lineno_update_slide(&dbg->lineno, pid);
    }
    if (dbg->syms.count > 0) {
        (void)cdbg_syms_update_slide(&dbg->syms, pid);
    }
    return 0;
}

int cdbg_wait(cdbg_t *dbg)
{
    if (cdbg_process_wait(dbg->pid, &dbg->wait_status) != 0) {
        return -1;
    }

    if (WIFEXITED(dbg->wait_status) || WIFSIGNALED(dbg->wait_status)) {
        dbg->state = CDBG_STATE_IDLE;
        return 1;
    }

    dbg->state = CDBG_STATE_STOPPED;
    return 0;
}

int cdbg_continue(cdbg_t *dbg)
{
    if (ptrace(PT_CONTINUE, dbg->pid, (caddr_t)1, 0) == -1) {
        perror("ptrace(PT_CONTINUE)");
        return -1;
    }

    dbg->state = CDBG_STATE_RUNNING;
    return 0;
}

int cdbg_single_step(cdbg_t *dbg)
{
    if (ptrace(PT_STEP, dbg->pid, (caddr_t)1, 0) == -1) {
        perror("ptrace(PT_STEP)");
        return -1;
    }

    dbg->state = CDBG_STATE_RUNNING;
    return 0;
}

#define CDBG_MAX_STEP_ITERATIONS 100000

static int call_return_address(cdbg_t *dbg, uintptr_t pc, uintptr_t *return_addr)
{
#if defined(__x86_64__)
    uint8_t opcode = 0;
    if (cdbg_mem_read(dbg->pid, pc, &opcode, sizeof(opcode)) != 0) {
        return -1;
    }
    if (opcode == 0xe8) {
        *return_addr = pc + 5;
        return 0;
    }
#elif defined(__aarch64__)
    uint32_t insn = 0;
    if (cdbg_mem_read(dbg->pid, pc, &insn, sizeof(insn)) != 0) {
        return -1;
    }
    if ((insn & 0xfc000000U) == 0x94000000U) {
        *return_addr = pc + 4;
        return 0;
    }
#endif
    return -1;
}

static int finish_temp_breakpoint(cdbg_t *dbg, cdbg_breakpoint_t *temp_bp)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        (void)cdbg_bp_disable(temp_bp, dbg->pid);
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    if (!cdbg_bp_matches_pc(pc, temp_bp)) {
        (void)cdbg_bp_disable(temp_bp, dbg->pid);
        return report_stop(dbg);
    }

    if (cdbg_bp_disable(temp_bp, dbg->pid) != 0) {
        return -1;
    }

#if defined(__x86_64__)
    (void)cdbg_regs_set_pc(&dbg->regs, temp_bp->addr);
    if (cdbg_regs_set(dbg->pid, &dbg->regs) != 0) {
        return -1;
    }
#endif
    return 0;
}

static int step_over_call(cdbg_t *dbg, uintptr_t return_addr)
{
    cdbg_breakpoint_t temp_bp = {0};
    if (cdbg_bp_enable(&temp_bp, dbg->pid, return_addr) != 0) {
        return -1;
    }

    if (cdbg_continue(dbg) != 0) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        return -1;
    }
    if (cdbg_wait(dbg) != 0) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
    }
    if (dbg->state != CDBG_STATE_STOPPED) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        return 0;
    }

    return finish_temp_breakpoint(dbg, &temp_bp);
}

typedef struct disasm_entry {
    uintptr_t address;
    char text[512];
} disasm_entry_t;

static int disasm_entry_push(disasm_entry_t **entries, size_t *count,
                             uintptr_t address, const char *text)
{
    disasm_entry_t *next = realloc(*entries, (*count + 1) * sizeof(**entries));
    if (next == NULL) {
        return -1;
    }

    *entries = next;
    disasm_entry_t *entry = &(*entries)[(*count)++];
    entry->address = address;
    snprintf(entry->text, sizeof(entry->text), "%s", text);
    return 0;
}

static int parse_otool_instruction(char *line, uintptr_t *address, char **text)
{
    char *p = line;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (!isxdigit((unsigned char)*p)) {
        return -1;
    }

    char *end = NULL;
    unsigned long long value = strtoull(p, &end, 16);
    if (end == p || !isspace((unsigned char)*end)) {
        return -1;
    }

    while (isspace((unsigned char)*end)) {
        end++;
    }
    size_t len = strlen(end);
    while (len > 0 && (end[len - 1] == '\n' || end[len - 1] == '\r')) {
        end[--len] = '\0';
    }

    *address = (uintptr_t)value;
    *text = end;
    return 0;
}

static int print_otool_disassembly(cdbg_t *dbg, uintptr_t runtime_pc)
{
    if (dbg->executable_path[0] == '\0') {
        return -1;
    }

    char cmd[CDBG_MAX_PATH + 64];
    int n = snprintf(cmd, sizeof(cmd), "otool -tvV '%s' 2>/dev/null",
                     dbg->executable_path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return -1;
    }

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    disasm_entry_t *entries = NULL;
    size_t count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        uintptr_t address = 0;
        char *text = NULL;
        if (parse_otool_instruction(line, &address, &text) != 0) {
            continue;
        }
        if (disasm_entry_push(&entries, &count, address, text) != 0) {
            free(entries);
            pclose(fp);
            return -1;
        }
    }
    (void)pclose(fp);

    uintptr_t slide = dbg->lineno.slide != 0 ? dbg->lineno.slide : dbg->syms.slide;
    uintptr_t link_pc = runtime_pc - slide;
    size_t current = count;
    for (size_t i = 0; i < count; i++) {
        if (entries[i].address <= link_pc) {
            current = i;
        } else {
            break;
        }
    }

    if (current == count || link_pc - entries[current].address > 32) {
        free(entries);
        return -1;
    }

    printf("\nDisassembly at 0x%lx:\n", (unsigned long)runtime_pc);
    uintptr_t runtime_addr = entries[current].address + slide;
    printf("=> 0x%016lx: %s\n", (unsigned long)runtime_addr, entries[current].text);
    putchar('\n');

    free(entries);
    return 0;
}

static const char *x86_reg64(unsigned int reg)
{
    static const char *names[] = {
        "%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi"
    };
    return names[reg & 7U];
}

static int64_t read_i32_le(const uint8_t *p)
{
    uint32_t value = (uint32_t)p[0] |
                     ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) |
                     ((uint32_t)p[3] << 24);
    return (int32_t)value;
}

static size_t decode_x86_64_instruction(uintptr_t pc, const uint8_t *bytes,
                                        size_t len, char *out, size_t out_len)
{
    if (len == 0) {
        return 0;
    }

    if (bytes[0] == 0x55) {
        snprintf(out, out_len, "pushq %%rbp");
        return 1;
    }
    if (bytes[0] == 0x5d) {
        snprintf(out, out_len, "popq %%rbp");
        return 1;
    }
    if (bytes[0] == 0xc3) {
        snprintf(out, out_len, "retq");
        return 1;
    }
    if (bytes[0] == 0x90) {
        snprintf(out, out_len, "nop");
        return 1;
    }
    if (bytes[0] == 0xcc) {
        snprintf(out, out_len, "int3");
        return 1;
    }
    if (bytes[0] == 0x6a && len >= 2) {
        snprintf(out, out_len, "pushq $0x%02x", bytes[1]);
        return 2;
    }
    if (bytes[0] == 0xe8 && len >= 5) {
        uintptr_t target = pc + 5 + read_i32_le(bytes + 1);
        snprintf(out, out_len, "callq 0x%lx", (unsigned long)target);
        return 5;
    }
    if (bytes[0] == 0xe9 && len >= 5) {
        uintptr_t target = pc + 5 + read_i32_le(bytes + 1);
        snprintf(out, out_len, "jmp 0x%lx", (unsigned long)target);
        return 5;
    }
    if (bytes[0] == 0xeb && len >= 2) {
        uintptr_t target = pc + 2 + (int8_t)bytes[1];
        snprintf(out, out_len, "jmp 0x%lx", (unsigned long)target);
        return 2;
    }
    if ((bytes[0] == 0x74 || bytes[0] == 0x75) && len >= 2) {
        uintptr_t target = pc + 2 + (int8_t)bytes[1];
        snprintf(out, out_len, "%s 0x%lx", bytes[0] == 0x74 ? "je" : "jne",
                 (unsigned long)target);
        return 2;
    }
    if (bytes[0] == 0x0f && len >= 6 && (bytes[1] == 0x84 || bytes[1] == 0x85)) {
        uintptr_t target = pc + 6 + read_i32_le(bytes + 2);
        snprintf(out, out_len, "%s 0x%lx", bytes[1] == 0x84 ? "je" : "jne",
                 (unsigned long)target);
        return 6;
    }

    if (bytes[0] == 0x48 && len >= 3) {
        uint8_t op = bytes[1];
        uint8_t modrm = bytes[2];
        unsigned int mod = (modrm >> 6) & 3U;
        unsigned int reg = (modrm >> 3) & 7U;
        unsigned int rm = modrm & 7U;

        if (op == 0x89 && mod == 3) {
            snprintf(out, out_len, "movq %s, %s", x86_reg64(reg), x86_reg64(rm));
            return 3;
        }
        if (op == 0x8b && mod == 3) {
            snprintf(out, out_len, "movq %s, %s", x86_reg64(rm), x86_reg64(reg));
            return 3;
        }
        if (op == 0x83 && len >= 4 && mod == 3) {
            const char *mnemonic = NULL;
            if (reg == 0) {
                mnemonic = "addq";
            } else if (reg == 4) {
                mnemonic = "andq";
            } else if (reg == 5) {
                mnemonic = "subq";
            } else if (reg == 7) {
                mnemonic = "cmpq";
            }
            if (mnemonic != NULL) {
                snprintf(out, out_len, "%s $0x%x, %s", mnemonic, bytes[3],
                         x86_reg64(rm));
                return 4;
            }
        }
        if (op == 0xc7 && len >= 7 && mod == 3 && reg == 0) {
            uint32_t imm = (uint32_t)bytes[3] |
                           ((uint32_t)bytes[4] << 8) |
                           ((uint32_t)bytes[5] << 16) |
                           ((uint32_t)bytes[6] << 24);
            snprintf(out, out_len, "movq $0x%x, %s", imm, x86_reg64(rm));
            return 7;
        }
    }

    snprintf(out, out_len, ".byte 0x%02x", bytes[0]);
    return 1;
}

static void print_memory_disassembly(cdbg_t *dbg, uintptr_t pc)
{
    uint8_t bytes[96];
    if (cdbg_mem_read(dbg->pid, pc, bytes, sizeof(bytes)) != 0) {
        return;
    }

    printf("\nDisassembly at 0x%lx:\n", (unsigned long)pc);
    size_t offset = 0;
    if (offset < sizeof(bytes)) {
        char text[128];
        size_t used = 0;
#if defined(__x86_64__)
        used = decode_x86_64_instruction(pc + offset, bytes + offset,
                                         sizeof(bytes) - offset,
                                         text, sizeof(text));
#elif defined(__aarch64__)
        if (sizeof(bytes) - offset >= 4) {
            uint32_t insn = (uint32_t)bytes[offset] |
                            ((uint32_t)bytes[offset + 1] << 8) |
                            ((uint32_t)bytes[offset + 2] << 16) |
                            ((uint32_t)bytes[offset + 3] << 24);
            snprintf(text, sizeof(text), ".inst 0x%08x", insn);
            used = 4;
        }
#endif
        if (used == 0) {
            snprintf(text, sizeof(text), ".byte 0x%02x", bytes[offset]);
            used = 1;
        }

        printf("=> 0x%016lx: %-24s ;", (unsigned long)(pc + offset), text);
        for (size_t j = 0; j < used; j++) {
            printf(" %02x", bytes[offset + j]);
        }
        putchar('\n');
    }
    putchar('\n');
}

static void print_disassembly_at_pc(cdbg_t *dbg, uintptr_t pc)
{
    if (print_otool_disassembly(dbg, pc) == 0) {
        return;
    }
    print_memory_disassembly(dbg, pc);
}

static void print_stop_location(cdbg_t *dbg, uintptr_t pc)
{
    if (cdbg_lineno_print_source_at_pc(&dbg->lineno, pc) == 0) {
        return;
    }
    print_disassembly_at_pc(dbg, pc);
}

int cdbg_step_next_line(cdbg_t *dbg)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    char start_file[CDBG_LINENO_MAX_FILE];
    uint32_t start_line = 0;
    if (cdbg_lineno_line_at_pc(&dbg->lineno, pc, start_file, sizeof(start_file),
                               &start_line) != 0) {
        if (cdbg_single_step(dbg) != 0) {
            return -1;
        }
        if (cdbg_wait(dbg) != 0) {
            return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
        }
        if (dbg->state == CDBG_STATE_STOPPED) {
            (void)report_stop(dbg);
        }
        return 0;
    }

    for (unsigned int i = 0; i < CDBG_MAX_STEP_ITERATIONS; i++) {
        if (cdbg_single_step(dbg) != 0) {
            return -1;
        }
        if (cdbg_wait(dbg) != 0) {
            return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
        }
        if (dbg->state != CDBG_STATE_STOPPED) {
            return 0;
        }

        if (cdbg_refresh_regs(dbg) != 0) {
            return -1;
        }

        pc = cdbg_regs_pc(&dbg->regs);
        if (cdbg_bp_is_trap(pc, dbg->breakpoints, dbg->breakpoint_count)) {
            return report_stop(dbg);
        }

        char cur_file[CDBG_LINENO_MAX_FILE];
        uint32_t cur_line = 0;
        if (cdbg_lineno_line_at_pc(&dbg->lineno, pc, cur_file, sizeof(cur_file),
                                   &cur_line) != 0) {
            continue;
        }

        if (strcmp(cur_file, start_file) != 0 || cur_line != start_line) {
            printf("Stopped (pc=0x%lx)\n", (unsigned long)pc);
            print_stop_location(dbg, pc);
            return 0;
        }
    }

    fputs("Step limit exceeded\n", stderr);
    return -1;
}

int cdbg_next_source_line(cdbg_t *dbg)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    char start_file[CDBG_LINENO_MAX_FILE];
    uint32_t start_line = 0;
    if (cdbg_lineno_line_at_pc(&dbg->lineno, pc, start_file, sizeof(start_file),
                               &start_line) != 0) {
        if (cdbg_single_step(dbg) != 0) {
            return -1;
        }
        if (cdbg_wait(dbg) != 0) {
            return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
        }
        if (dbg->state == CDBG_STATE_STOPPED) {
            (void)report_stop(dbg);
        }
        return 0;
    }

    for (unsigned int i = 0; i < CDBG_MAX_STEP_ITERATIONS; i++) {
        uintptr_t return_addr = 0;
        if (call_return_address(dbg, pc, &return_addr) == 0) {
            if (step_over_call(dbg, return_addr) != 0) {
                return -1;
            }
            if (dbg->state != CDBG_STATE_STOPPED) {
                return 0;
            }
        } else {
            if (cdbg_single_step(dbg) != 0) {
                return -1;
            }
            if (cdbg_wait(dbg) != 0) {
                return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
            }
            if (dbg->state != CDBG_STATE_STOPPED) {
                return 0;
            }
        }

        if (cdbg_refresh_regs(dbg) != 0) {
            return -1;
        }

        pc = cdbg_regs_pc(&dbg->regs);
        if (cdbg_bp_is_trap(pc, dbg->breakpoints, dbg->breakpoint_count)) {
            return report_stop(dbg);
        }

        char cur_file[CDBG_LINENO_MAX_FILE];
        uint32_t cur_line = 0;
        if (cdbg_lineno_line_at_pc(&dbg->lineno, pc, cur_file, sizeof(cur_file),
                                   &cur_line) != 0) {
            continue;
        }

        if (strcmp(cur_file, start_file) != 0 || cur_line != start_line) {
            printf("Stopped (pc=0x%lx)\n", (unsigned long)pc);
            print_stop_location(dbg, pc);
            return 0;
        }
    }

    fputs("Step limit exceeded\n", stderr);
    return -1;
}

int cdbg_frame_up(cdbg_t *dbg)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    if (cdbg_regs_frame_up(dbg->pid, &dbg->regs) != 0) {
        fputs("Cannot unwind to caller frame\n", stderr);
        return -1;
    }

    if (cdbg_regs_set(dbg->pid, &dbg->regs) != 0) {
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    printf("Now at caller frame (pc=0x%lx)\n", (unsigned long)pc);
    print_stop_location(dbg, pc);
    return 0;
}

int cdbg_refresh_regs(cdbg_t *dbg)
{
    return cdbg_regs_get(dbg->pid, &dbg->regs);
}

void cdbg_print_regs(const cdbg_t *dbg)
{
    cdbg_regs_print(&dbg->regs);
}

void cdbg_print_stop_context(cdbg_t *dbg)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        return;
    }
    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    print_stop_location(dbg, pc);
}

static int handle_breakpoint_hit(cdbg_t *dbg, size_t index)
{
    cdbg_breakpoint_t *bp = &dbg->breakpoints[index];

    if (cdbg_bp_disable(bp, dbg->pid) != 0) {
        return -1;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    if (pc > 0) {
        (void)cdbg_regs_set_pc(&dbg->regs, pc - 1);
        if (cdbg_regs_set(dbg->pid, &dbg->regs) != 0) {
            return -1;
        }
    }

    printf("Breakpoint hit at 0x%lx\n", (unsigned long)bp->addr);
    print_stop_location(dbg, bp->addr);
    return 0;
}

static int report_stop(cdbg_t *dbg)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    if (cdbg_bp_is_trap(pc, dbg->breakpoints, dbg->breakpoint_count)) {
        for (size_t i = 0; i < dbg->breakpoint_count; i++) {
            if (cdbg_bp_matches_pc(pc, &dbg->breakpoints[i])) {
                return handle_breakpoint_hit(dbg, i);
            }
        }
    }

    printf("Stopped (pc=0x%lx)\n", (unsigned long)pc);
    print_stop_location(dbg, pc);
    return 0;
}

static int parse_u64(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 0);

    if (end == text || *end != '\0') {
        return -1;
    }

    *out = (uint64_t)value;
    return 0;
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

static char *trim_space(char *text)
{
    while (isspace((unsigned char)*text)) {
        text++;
    }
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return text;
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

static size_t type_pointee_size(const char *type)
{
    const char *star = strchr(type, '*');
    if (star == NULL) {
        return 0;
    }

    char base[128];
    size_t len = (size_t)(star - type);
    if (len >= sizeof(base)) {
        len = sizeof(base) - 1;
    }
    memcpy(base, type, len);
    base[len] = '\0';
    return type_scalar_size(trim_space(base));
}

static void complete_var_type(cdbg_var_info_t *var)
{
    var->is_pointer = strchr(var->type, '*') != NULL;
    var->is_signed = strstr(var->type, "unsigned") == NULL;
    var->size = type_scalar_size(var->type);
    var->pointee_size = type_pointee_size(var->type);
    if (var->pointee_size == 0) {
        var->pointee_size = sizeof(uintptr_t);
    }
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

static int write_scalar_value(pid_t pid, uintptr_t addr, size_t size, uint64_t value)
{
    if (size == 0 || size > sizeof(uint64_t)) {
        size = sizeof(uint64_t);
    }

    uint8_t buf[sizeof(uint64_t)] = {0};
    memcpy(buf, &value, size);
    return cdbg_mem_write(pid, addr, buf, size);
}

static int parse_assignment_value(const char *text, uint64_t *out)
{
    char *end = NULL;
    long long signed_value = strtoll(text, &end, 0);
    if (end != text && *end == '\0') {
        *out = (uint64_t)signed_value;
        return 0;
    }

    return parse_u64(text, out);
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

static int64_t sign_extend_value(uint64_t value, size_t size)
{
    if (size == 0 || size >= sizeof(uint64_t)) {
        return (int64_t)value;
    }

    unsigned int bits = (unsigned int)(size * 8);
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t mask = (1ULL << bits) - 1ULL;
    value &= mask;
    if ((value & sign) != 0) {
        value |= ~mask;
    }
    return (int64_t)value;
}

static void print_scalar_result(const char *label, uint64_t value, size_t size,
                                bool is_signed, bool is_pointer)
{
    if (is_pointer) {
        printf("%s = 0x%016llx\n", label, (unsigned long long)value);
        return;
    }

    if (is_signed) {
        printf("%s = %lld (0x%llx)\n", label,
               (long long)sign_extend_value(value, size),
               (unsigned long long)value);
    } else {
        printf("%s = %llu (0x%llx)\n", label,
               (unsigned long long)value,
               (unsigned long long)value);
    }
}

static int cmd_print(cdbg_t *dbg, char *expr)
{
    if (expr == NULL) {
        fputs("Usage: print <expr>\n", stderr);
        return -1;
    }

    expr = trim_space(expr);
    if (expr[0] == '\0') {
        fputs("Usage: print <expr>\n", stderr);
        return -1;
    }

    char op = '\0';
    if (expr[0] == '&' || expr[0] == '*') {
        op = expr[0];
        expr = trim_space(expr + 1);
    }
    if (expr[0] == '\0') {
        fputs("Usage: print <expr>\n", stderr);
        return -1;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uint64_t parsed = 0;
    if (parse_u64(expr, &parsed) == 0) {
        if (op == '&') {
            fputs("Cannot take address of a literal\n", stderr);
            return -1;
        }
        if (op == '*') {
            uint64_t value = 0;
            if (read_scalar_value(dbg->pid, (uintptr_t)parsed, sizeof(uint64_t), &value) != 0) {
                return -1;
            }
            char label[160];
            snprintf(label, sizeof(label), "*0x%llx", (unsigned long long)parsed);
            print_scalar_result(label, value, sizeof(uint64_t), false, false);
            return 0;
        }
        print_scalar_result(expr, parsed, sizeof(uint64_t), false, false);
        return 0;
    }

    cdbg_var_info_t var = {0};
    uintptr_t addr = 0;
    bool found_local = find_local_var(dbg, expr, &var) == 0;
    if (found_local) {
        uintptr_t fp = cdbg_regs_fp(&dbg->regs);
        addr = (uintptr_t)((int64_t)fp + var.fbreg_offset);
    } else {
        const cdbg_sym_entry_t *sym = cdbg_syms_lookup_name(&dbg->syms, expr);
        if (sym == NULL || sym->address == 0 || sym->type == 'U' || sym->type == 'u') {
            fprintf(stderr, "Unknown variable: %s\n", expr);
            return -1;
        }
        addr = cdbg_syms_runtime_addr(&dbg->syms, sym->address);
        snprintf(var.name, sizeof(var.name), "%s", expr);
        snprintf(var.type, sizeof(var.type), "unsigned long");
        complete_var_type(&var);
    }

    if (op == '&') {
        printf("&%s = 0x%016lx\n", expr, (unsigned long)addr);
        return 0;
    }

    if (op == '*') {
        if (found_local && !var.is_pointer) {
            fprintf(stderr, "%s is not a pointer\n", expr);
            return -1;
        }
        uint64_t ptr = 0;
        if (read_scalar_value(dbg->pid, addr, sizeof(uintptr_t), &ptr) != 0) {
            return -1;
        }
        uint64_t value = 0;
        if (read_scalar_value(dbg->pid, (uintptr_t)ptr, var.pointee_size, &value) != 0) {
            return -1;
        }
        char label[160];
        snprintf(label, sizeof(label), "*%s", expr);
        print_scalar_result(label, value, var.pointee_size, var.is_signed, false);
        return 0;
    }

    uint64_t value = 0;
    if (read_scalar_value(dbg->pid, addr, var.size, &value) != 0) {
        return -1;
    }
    print_scalar_result(expr, value, var.size, var.is_signed, var.is_pointer);
    return 0;
}

static int split_assignment(char *args, char **lhs_out, char **rhs_out)
{
    if (args == NULL) {
        return -1;
    }

    args = trim_space(args);
    if (args[0] == '\0') {
        return -1;
    }

    char *eq = strchr(args, '=');
    if (eq != NULL) {
        *eq = '\0';
        *lhs_out = trim_space(args);
        *rhs_out = trim_space(eq + 1);
        return (*lhs_out)[0] != '\0' && (*rhs_out)[0] != '\0' ? 0 : -1;
    }

    char *p = args;
    while (*p != '\0' && !isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '\0') {
        return -1;
    }

    *p = '\0';
    *lhs_out = trim_space(args);
    *rhs_out = trim_space(p + 1);
    return (*lhs_out)[0] != '\0' && (*rhs_out)[0] != '\0' ? 0 : -1;
}

static int cmd_set(cdbg_t *dbg, char *args)
{
    char *lhs = NULL;
    char *rhs = NULL;
    if (split_assignment(args, &lhs, &rhs) != 0) {
        fputs("Usage: set <var> <value> | set <var> = <value>\n", stderr);
        return -1;
    }

    if (lhs[0] == '&') {
        fputs("Cannot assign to an address expression\n", stderr);
        return -1;
    }

    uint64_t value = 0;
    if (parse_assignment_value(rhs, &value) != 0) {
        fprintf(stderr, "Invalid value: %s\n", rhs);
        return -1;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uintptr_t addr = 0;
    cdbg_var_info_t var = {0};
    bool found_local = false;
    size_t size = sizeof(uint64_t);
    bool is_signed = false;
    bool is_pointer = false;
    const char *label = lhs;

    if (lhs[0] == '*') {
        char *target = trim_space(lhs + 1);
        if (target[0] == '\0') {
            fputs("Usage: set <var> <value> | set <var> = <value>\n", stderr);
            return -1;
        }

        uint64_t parsed_addr = 0;
        if (parse_u64(target, &parsed_addr) == 0) {
            addr = (uintptr_t)parsed_addr;
        } else if (resolve_variable_address(dbg, target, &var, &addr, &found_local) == 0) {
            if (found_local && !var.is_pointer) {
                fprintf(stderr, "%s is not a pointer\n", target);
                return -1;
            }
            uint64_t ptr = 0;
            if (read_scalar_value(dbg->pid, addr, sizeof(uintptr_t), &ptr) != 0) {
                return -1;
            }
            addr = (uintptr_t)ptr;
            size = var.pointee_size;
            is_signed = var.is_signed;
        } else {
            fprintf(stderr, "Unknown variable: %s\n", target);
            return -1;
        }
    } else {
        if (resolve_variable_address(dbg, lhs, &var, &addr, &found_local) != 0) {
            fprintf(stderr, "Unknown variable: %s\n", lhs);
            return -1;
        }
        size = var.size;
        is_signed = var.is_signed;
        is_pointer = var.is_pointer;
    }

    if (write_scalar_value(dbg->pid, addr, size, value) != 0) {
        return -1;
    }

    uint64_t written = 0;
    if (read_scalar_value(dbg->pid, addr, size, &written) == 0) {
        print_scalar_result(label, written, size, is_signed, is_pointer);
    } else {
        printf("%s set\n", label);
    }
    return 0;
}

#define CDBG_MAX_BACKTRACE_FRAMES 64
#define CDBG_MAX_SYMBOL_OFFSET    0x100000

static const cdbg_sym_entry_t *lookup_symbol_for_pc(const cdbg_syms_t *syms,
                                                    uintptr_t pc,
                                                    uintptr_t *offset_out)
{
    const cdbg_sym_entry_t *best = NULL;
    uintptr_t best_addr = 0;

    for (size_t i = 0; i < syms->count; i++) {
        const cdbg_sym_entry_t *entry = &syms->entries[i];
        if (entry->address == 0 || (entry->type != 'T' && entry->type != 't')) {
            continue;
        }

        uintptr_t runtime = cdbg_syms_runtime_addr(syms, entry->address);
        if (runtime <= pc && (best == NULL || runtime > best_addr)) {
            best = entry;
            best_addr = runtime;
        }
    }

    if (best != NULL) {
        *offset_out = pc - best_addr;
        if (*offset_out > CDBG_MAX_SYMBOL_OFFSET) {
            return NULL;
        }
    }
    return best;
}

static const char *display_sym_name(const cdbg_sym_entry_t *sym)
{
    if (sym == NULL) {
        return "??";
    }
    if (sym->name[0] == '_' && sym->name[1] != '\0') {
        return sym->name + 1;
    }
    return sym->name;
}

static void print_backtrace_frame(cdbg_t *dbg, unsigned int frame_no, uintptr_t pc)
{
    uintptr_t offset = 0;
    const cdbg_sym_entry_t *sym = lookup_symbol_for_pc(&dbg->syms, pc, &offset);

    printf("#%-2u 0x%016lx in %s", frame_no, (unsigned long)pc, display_sym_name(sym));
    if (sym != NULL && offset != 0) {
        printf(" + %lu", (unsigned long)offset);
    }

    char file[CDBG_LINENO_MAX_FILE];
    uint32_t line = 0;
    if (cdbg_lineno_line_at_pc(&dbg->lineno, pc, file, sizeof(file), &line) == 0) {
        printf(" at %s:%u", file, line);
    }
    putchar('\n');
}

static int frame_record_next(cdbg_t *dbg, uintptr_t fp,
                             uintptr_t *next_fp, uintptr_t *ret_addr)
{
    uint64_t saved_fp = 0;
    uint64_t saved_pc = 0;
    if (cdbg_mem_read_u64(dbg->pid, fp, &saved_fp) != 0 ||
        cdbg_mem_read_u64(dbg->pid, fp + 8, &saved_pc) != 0) {
        return -1;
    }

    if (saved_fp == 0 || saved_pc < 0x1000 || saved_fp <= fp) {
        return -1;
    }

    *next_fp = (uintptr_t)saved_fp;
    *ret_addr = (uintptr_t)saved_pc;
    return 0;
}

static int cmd_backtrace(cdbg_t *dbg)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    uintptr_t fp = cdbg_regs_fp(&dbg->regs);

    puts("Backtrace:");
    print_backtrace_frame(dbg, 0, pc);

    for (unsigned int frame_no = 1; frame_no < CDBG_MAX_BACKTRACE_FRAMES; frame_no++) {
        uintptr_t next_fp = 0;
        uintptr_t ret_addr = 0;
        if (fp == 0 || frame_record_next(dbg, fp, &next_fp, &ret_addr) != 0) {
            break;
        }

        print_backtrace_frame(dbg, frame_no, ret_addr);
        fp = next_fp;
    }

    return 0;
}

static void print_help(void)
{
    puts("Commands:");
    puts("  help | h              Show this help");
    puts("  continue | c          Resume execution");
    puts("  step | s              Step one source line, entering calls");
    puts("  si                    Single-step one instruction");
    puts("  next | n              Step one source line, stepping over calls");
    puts("  up                    Stop at caller frame");
    puts("  regs | r              Print registers");
    puts("  print <expr> | p      Print variable, &addr, or *pointer");
    puts("  set <var> <value>     Set variable value");
    puts("  tb                    Show backtrace");
    puts("  break <addr|name|line> | b  Set breakpoint");
    puts("  list [line|file:line|function]  Show source code");
    puts("  lists [file]          List source line to address mappings");
    puts("  syms [name]           List symbol table");
    puts("  x <addr> [count]      Examine memory (hex dump)");
    puts("  quit | q              Detach and exit");
}

static int cmd_examine(cdbg_t *dbg, const char *addr_text, const char *count_text)
{
    uint64_t addr = 0;
    uint64_t count = 16;
    uint8_t buf[64];

    if (parse_u64(addr_text, &addr) != 0) {
        fputs("Invalid address\n", stderr);
        return -1;
    }

    if (count_text != NULL && parse_u64(count_text, &count) != 0) {
        fputs("Invalid count\n", stderr);
        return -1;
    }

    if (count == 0 || count > sizeof(buf)) {
        fputs("Count must be 1-64\n", stderr);
        return -1;
    }

    if (cdbg_mem_read(dbg->pid, (uintptr_t)addr, buf, (size_t)count) != 0) {
        return -1;
    }

    for (uint64_t i = 0; i < count; i += 8) {
        printf("0x%016llx: ", (unsigned long long)(addr + i));
        for (uint64_t j = 0; j < 8 && (i + j) < count; j++) {
            printf("%02x ", buf[i + j]);
        }
        putchar('\n');
    }

    return 0;
}

static int resolve_break_line(cdbg_t *dbg, const char *file, uint32_t line,
                              uintptr_t *addr_out, char *label_out, size_t label_len)
{
    const cdbg_line_entry_t *entry = NULL;

    if (file != NULL && file[0] != '\0') {
        entry = cdbg_lineno_lookup_line(&dbg->lineno, file, line);
    } else {
        entry = cdbg_lineno_lookup_line_unique(&dbg->lineno, line);
    }

    if (entry == NULL) {
        if (file != NULL && file[0] != '\0') {
            fprintf(stderr, "No line info for %s:%u\n", file, line);
        } else if (dbg->lineno.count == 0) {
            fprintf(stderr, "No line number information loaded\n");
        } else {
            fprintf(stderr, "Line %u is ambiguous; use file:line\n", line);
        }
        return -1;
    }

    *addr_out = cdbg_lineno_runtime_addr(&dbg->lineno, entry->address);
    snprintf(label_out, label_len, "%s:%u", entry->file, entry->line);
    return 0;
}

static int cmd_list(cdbg_t *dbg, char *target)
{
    if (target == NULL || trim_space(target)[0] == '\0') {
        if (cdbg_refresh_regs(dbg) != 0) {
            return -1;
        }
        cdbg_lineno_print_source_at_pc(&dbg->lineno, cdbg_regs_pc(&dbg->regs));
        return 0;
    }

    target = trim_space(target);

    char *colon = strrchr(target, ':');
    if (colon != NULL && colon[1] != '\0') {
        char file_part[CDBG_LINENO_MAX_FILE];
        size_t file_len = (size_t)(colon - target);
        if (file_len == 0 || file_len >= sizeof(file_part)) {
            fputs("Usage: list [line|file:line|function]\n", stderr);
            return -1;
        }
        memcpy(file_part, target, file_len);
        file_part[file_len] = '\0';

        uint64_t line_no = 0;
        if (parse_u64(colon + 1, &line_no) != 0 || line_no == 0) {
            fputs("Usage: list [line|file:line|function]\n", stderr);
            return -1;
        }

        return cdbg_lineno_print_source_at_line(&dbg->lineno, file_part, (uint32_t)line_no);
    }

    uint64_t line_no = 0;
    if (parse_u64(target, &line_no) == 0) {
        if (line_no == 0) {
            fputs("Usage: list [line|file:line|function]\n", stderr);
            return -1;
        }
        return cdbg_lineno_print_source_at_line(&dbg->lineno, NULL, (uint32_t)line_no);
    }

    const cdbg_sym_entry_t *sym = cdbg_syms_lookup_name(&dbg->syms, target);
    if (sym == NULL) {
        fprintf(stderr, "Unknown function: %s\n", target);
        return -1;
    }
    if (sym->address == 0 || sym->type == 'U' || sym->type == 'u') {
        fprintf(stderr, "Symbol is undefined: %s\n", sym->name);
        return -1;
    }

    uintptr_t addr = cdbg_syms_runtime_addr(&dbg->syms, sym->address);
    char file[CDBG_LINENO_MAX_FILE];
    uint32_t line = 0;
    if (cdbg_lineno_line_at_pc(&dbg->lineno, addr, file, sizeof(file), &line) != 0) {
        fprintf(stderr, "No source line for function: %s\n", target);
        return -1;
    }

    return cdbg_lineno_print_source_at_line(&dbg->lineno, file, line);
}

static int cmd_break(cdbg_t *dbg, const char *target)
{
    uintptr_t addr = 0;
    char label_buf[CDBG_LINENO_MAX_FILE + 32];
    const char *label = target;
    uint64_t parsed = 0;

    char *colon = strrchr(target, ':');
    if (colon != NULL && colon[1] != '\0') {
        char file_part[CDBG_LINENO_MAX_FILE];
        size_t file_len = (size_t)(colon - target);
        if (file_len == 0 || file_len >= sizeof(file_part)) {
            fputs("Invalid file:line\n", stderr);
            return -1;
        }
        memcpy(file_part, target, file_len);
        file_part[file_len] = '\0';

        uint64_t line_no = 0;
        if (parse_u64(colon + 1, &line_no) != 0 || line_no == 0) {
            fputs("Invalid file:line\n", stderr);
            return -1;
        }

        if (resolve_break_line(dbg, file_part, (uint32_t)line_no, &addr,
                               label_buf, sizeof(label_buf)) != 0) {
            return -1;
        }
        label = label_buf;
    } else if (parse_u64(target, &parsed) == 0) {
        if (strncmp(target, "0x", 2) == 0 || strncmp(target, "0X", 2) == 0) {
            addr = (uintptr_t)parsed;
        } else if (resolve_break_line(dbg, NULL, (uint32_t)parsed, &addr,
                                      label_buf, sizeof(label_buf)) == 0) {
            label = label_buf;
        } else {
            addr = (uintptr_t)parsed;
        }
    } else {
        const cdbg_sym_entry_t *sym = cdbg_syms_lookup_name(&dbg->syms, target);
        if (sym == NULL) {
            fprintf(stderr, "Unknown symbol: %s\n", target);
            return -1;
        }
        if (sym->address == 0 || sym->type == 'U' || sym->type == 'u') {
            fprintf(stderr, "Symbol is undefined: %s\n", sym->name);
            return -1;
        }
        addr = cdbg_syms_runtime_addr(&dbg->syms, sym->address);
        const cdbg_line_entry_t *first_body_line =
            cdbg_lineno_lookup_next_line_after_pc(&dbg->lineno, addr);
        if (first_body_line != NULL) {
            addr = cdbg_lineno_runtime_addr(&dbg->lineno, first_body_line->address);
        }
        label = sym->name;
    }

    if (dbg->breakpoint_count >= CDBG_MAX_BREAKPOINTS) {
        fputs("Breakpoint table full\n", stderr);
        return -1;
    }

    size_t index = dbg->breakpoint_count;
    if (cdbg_bp_enable(&dbg->breakpoints[index], dbg->pid, addr) != 0) {
        return -1;
    }

    dbg->breakpoint_count++;
    printf("Breakpoint %zu at %s (0x%lx)\n", index, label, (unsigned long)addr);
    return 0;
}

int cdbg_repl(cdbg_t *dbg)
{
    char line[CDBG_MAX_CMD];

    print_help();

    while (fputs("cdbg> ", stdout), fflush(stdout),
           fgets(line, sizeof(line), stdin) != NULL) {
        char *newline = strchr(line, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        char *cmd = strtok(line, " \t");
        if (cmd == NULL || cmd[0] == '\0') {
            continue;
        }

        if (strcmp(cmd, "help") == 0 || strcmp(cmd, "h") == 0) {
            print_help();
        } else if (strcmp(cmd, "continue") == 0 || strcmp(cmd, "c") == 0) {
            if (cdbg_continue(dbg) != 0) {
                return -1;
            }
            if (cdbg_wait(dbg) != 0) {
                return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
            }
            if (dbg->state == CDBG_STATE_STOPPED) {
                (void)report_stop(dbg);
            }
        } else if (strcmp(cmd, "step") == 0 || strcmp(cmd, "s") == 0) {
            if (cdbg_step_next_line(dbg) != 0) {
                return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
            }
        } else if (strcmp(cmd, "si") == 0) {
            if (cdbg_single_step(dbg) != 0) {
                return -1;
            }
            if (cdbg_wait(dbg) != 0) {
                return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
            }
            if (dbg->state == CDBG_STATE_STOPPED) {
                (void)report_stop(dbg);
            }
        } else if (strcmp(cmd, "next") == 0 || strcmp(cmd, "n") == 0) {
            if (cdbg_next_source_line(dbg) != 0) {
                return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
            }
        } else if (strcmp(cmd, "up") == 0) {
            (void)cdbg_frame_up(dbg);
        } else if (strcmp(cmd, "regs") == 0 || strcmp(cmd, "r") == 0) {
            if (cdbg_refresh_regs(dbg) != 0) {
                return -1;
            }
            cdbg_print_regs(dbg);
        } else if (strcmp(cmd, "print") == 0 || strcmp(cmd, "p") == 0) {
            char *expr = strtok(NULL, "\n");
            (void)cmd_print(dbg, expr);
        } else if (strcmp(cmd, "set") == 0) {
            char *args = strtok(NULL, "\n");
            (void)cmd_set(dbg, args);
        } else if (strcmp(cmd, "tb") == 0) {
            (void)cmd_backtrace(dbg);
        } else if (strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0) {
            char *addr_text = strtok(NULL, " \t");
            if (addr_text == NULL) {
                fputs("Usage: break <addr|name|file:line|line>\n", stderr);
            } else {
                (void)cmd_break(dbg, addr_text);
            }
        } else if (strcmp(cmd, "list") == 0 || strcmp(cmd, "l") == 0) {
            char *target = strtok(NULL, "\n");
            (void)cmd_list(dbg, target);
        } else if (strcmp(cmd, "lists") == 0) {
            char *file_filter = strtok(NULL, " \t");
            cdbg_lineno_print_list(&dbg->lineno, file_filter);
        } else if (strcmp(cmd, "syms") == 0 || strcmp(cmd, "sym") == 0) {
            char *name_filter = strtok(NULL, " \t");
            cdbg_syms_print_list(&dbg->syms, name_filter);
        } else if (strcmp(cmd, "x") == 0) {
            char *addr_text = strtok(NULL, " \t");
            char *count_text = strtok(NULL, " \t");
            if (addr_text == NULL) {
                fputs("Usage: x <addr> [count]\n", stderr);
            } else {
                (void)cmd_examine(dbg, addr_text, count_text);
            }
        } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "q") == 0) {
            for (size_t i = 0; i < dbg->breakpoint_count; i++) {
                if (dbg->breakpoints[i].enabled) {
                    (void)cdbg_bp_disable(&dbg->breakpoints[i], dbg->pid);
                }
            }
            ptrace(PT_DETACH, dbg->pid, (caddr_t)1, 0);
            cdbg_lineno_free(&dbg->lineno);
            cdbg_syms_free(&dbg->syms);
            return 0;
        } else {
            printf("Unknown command: %s\n", cmd);
        }
    }

    return 0;
}
