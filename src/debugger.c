#include "debugger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "memory.h"
#include "process.h"

static int report_stop(cdbg_t *dbg);

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
        fputs("No line info at current pc\n", stderr);
        return -1;
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
            cdbg_lineno_print_source_at_pc(&dbg->lineno, pc);
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
    cdbg_lineno_print_source_at_pc(&dbg->lineno, pc);
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
    cdbg_lineno_print_source_at_pc(&dbg->lineno, pc);
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
    cdbg_lineno_print_source_at_pc(&dbg->lineno, bp->addr);
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
    cdbg_lineno_print_source_at_pc(&dbg->lineno, pc);
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

static void print_help(void)
{
    puts("Commands:");
    puts("  help | h              Show this help");
    puts("  continue | c          Resume execution");
    puts("  step | s              Single-step one instruction");
    puts("  next | n              Step to next source line");
    puts("  up                    Stop at caller frame");
    puts("  regs | r              Print registers");
    puts("  break <addr|name|line> | b  Set breakpoint");
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
            if (cdbg_step_next_line(dbg) != 0) {
                return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
            }
        } else if (strcmp(cmd, "up") == 0) {
            (void)cdbg_frame_up(dbg);
        } else if (strcmp(cmd, "regs") == 0 || strcmp(cmd, "r") == 0) {
            if (cdbg_refresh_regs(dbg) != 0) {
                return -1;
            }
            cdbg_print_regs(dbg);
        } else if (strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0) {
            char *addr_text = strtok(NULL, " \t");
            if (addr_text == NULL) {
                fputs("Usage: break <addr|name|file:line|line>\n", stderr);
            } else {
                (void)cmd_break(dbg, addr_text);
            }
        } else if (strcmp(cmd, "lists") == 0 || strcmp(cmd, "list") == 0) {
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
