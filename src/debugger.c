#include "debugger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "memory.h"
#include "process.h"

int cdbg_init(cdbg_t *dbg)
{
    memset(dbg, 0, sizeof(*dbg));
    dbg->state = CDBG_STATE_IDLE;
    return 0;
}

int cdbg_spawn(cdbg_t *dbg, char *const argv[])
{
    pid_t pid;

    if (cdbg_process_spawn(&pid, argv) != 0) {
        return -1;
    }

    dbg->pid = pid;
    dbg->state = CDBG_STATE_RUNNING;
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

int cdbg_refresh_regs(cdbg_t *dbg)
{
    return cdbg_regs_get(dbg->pid, &dbg->regs);
}

void cdbg_print_regs(const cdbg_t *dbg)
{
    cdbg_regs_print(&dbg->regs);
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
    puts("  regs | r              Print registers");
    puts("  break <addr> | b      Set software breakpoint");
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

static int cmd_break(cdbg_t *dbg, const char *addr_text)
{
    uint64_t addr = 0;

    if (parse_u64(addr_text, &addr) != 0) {
        fputs("Invalid address\n", stderr);
        return -1;
    }

    if (dbg->breakpoint_count >= CDBG_MAX_BREAKPOINTS) {
        fputs("Breakpoint table full\n", stderr);
        return -1;
    }

    size_t index = dbg->breakpoint_count;
    if (cdbg_bp_enable(&dbg->breakpoints[index], dbg->pid, (uintptr_t)addr) != 0) {
        return -1;
    }

    dbg->breakpoint_count++;
    printf("Breakpoint %zu at 0x%lx\n", index, (unsigned long)addr);
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
                if (cdbg_refresh_regs(dbg) != 0) {
                    return -1;
                }
                uintptr_t pc = cdbg_regs_pc(&dbg->regs);
                if (cdbg_bp_is_trap(pc, dbg->breakpoints, dbg->breakpoint_count)) {
                    for (size_t i = 0; i < dbg->breakpoint_count; i++) {
                        if (cdbg_bp_matches_pc(pc, &dbg->breakpoints[i])) {
                            (void)handle_breakpoint_hit(dbg, i);
                            break;
                        }
                    }
                } else {
                    printf("Stopped with signal (pc=0x%lx)\n", (unsigned long)pc);
                }
            }
        } else if (strcmp(cmd, "step") == 0 || strcmp(cmd, "s") == 0) {
            if (cdbg_single_step(dbg) != 0) {
                return -1;
            }
            if (cdbg_wait(dbg) != 0) {
                return dbg->state == CDBG_STATE_IDLE ? 0 : -1;
            }
            if (dbg->state == CDBG_STATE_STOPPED && cdbg_refresh_regs(dbg) == 0) {
                printf("pc=0x%lx\n", (unsigned long)cdbg_regs_pc(&dbg->regs));
            }
        } else if (strcmp(cmd, "regs") == 0 || strcmp(cmd, "r") == 0) {
            if (cdbg_refresh_regs(dbg) != 0) {
                return -1;
            }
            cdbg_print_regs(dbg);
        } else if (strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0) {
            char *addr_text = strtok(NULL, " \t");
            if (addr_text == NULL) {
                fputs("Usage: break <addr>\n", stderr);
            } else {
                (void)cmd_break(dbg, addr_text);
            }
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
            return 0;
        } else {
            printf("Unknown command: %s\n", cmd);
        }
    }

    return 0;
}
