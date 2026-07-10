#include "debugger.h"

#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "expr.h"
#include "memory.h"
#include "process.h"

static int report_stop(cdbg_t *dbg);
static void report_process_exit(cdbg_t *dbg);
static void print_stop_header(const cdbg_t *dbg);
static void print_stop_location(cdbg_t *dbg, uintptr_t pc);

static cdbg_t *g_sigint_dbg = NULL;

static void sigint_handler(int sig)
{
    (void)sig;
    if (g_sigint_dbg != NULL && g_sigint_dbg->state == CDBG_STATE_RUNNING) {
        kill(g_sigint_dbg->pid, SIGINT);
    }
}

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
    dbg->print_pretty = true;
    dbg->language = CDBG_LANG_AUTO;
    return 0;
}

typedef struct {
    const char *alias;
    cdbg_language_t lang;
} cdbg_language_alias_t;

static const cdbg_language_alias_t k_language_aliases[] = {
    {"auto", CDBG_LANG_AUTO},
    {"c", CDBG_LANG_C},
    {"c++", CDBG_LANG_CXX},
    {"cpp", CDBG_LANG_CXX},
    {"cxx", CDBG_LANG_CXX},
    {"objective-c", CDBG_LANG_OBJC},
    {"objc", CDBG_LANG_OBJC},
    {"fortran", CDBG_LANG_FORTRAN},
    {"pascal", CDBG_LANG_PASCAL},
    {"ada", CDBG_LANG_ADA},
    {"modula-2", CDBG_LANG_MODULA2},
    {"modula2", CDBG_LANG_MODULA2},
    {"java", CDBG_LANG_JAVA},
    {"go", CDBG_LANG_GO},
    {"rust", CDBG_LANG_RUST},
    {"assembly", CDBG_LANG_ASSEMBLY},
    {"asm", CDBG_LANG_ASSEMBLY},
};

static bool str_ieq(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

int cdbg_language_parse(const char *name, cdbg_language_t *out)
{
    if (name == NULL || out == NULL || name[0] == '\0') {
        return -1;
    }

    for (size_t i = 0; i < sizeof(k_language_aliases) / sizeof(k_language_aliases[0]); i++) {
        if (str_ieq(name, k_language_aliases[i].alias)) {
            *out = k_language_aliases[i].lang;
            return 0;
        }
    }
    return -1;
}

const char *cdbg_language_name(cdbg_language_t lang)
{
    switch (lang) {
    case CDBG_LANG_AUTO: return "auto";
    case CDBG_LANG_C: return "c";
    case CDBG_LANG_CXX: return "c++";
    case CDBG_LANG_OBJC: return "objective-c";
    case CDBG_LANG_FORTRAN: return "fortran";
    case CDBG_LANG_PASCAL: return "pascal";
    case CDBG_LANG_ADA: return "ada";
    case CDBG_LANG_MODULA2: return "modula-2";
    case CDBG_LANG_JAVA: return "java";
    case CDBG_LANG_GO: return "go";
    case CDBG_LANG_RUST: return "rust";
    case CDBG_LANG_ASSEMBLY: return "assembly";
    }
    return "unknown";
}

cdbg_language_t cdbg_language_effective(const cdbg_t *dbg)
{
    if (dbg == NULL || dbg->language == CDBG_LANG_AUTO) {
        return CDBG_LANG_C;
    }
    return dbg->language;
}

bool cdbg_language_supports_expr(cdbg_language_t lang)
{
    switch (lang) {
    case CDBG_LANG_AUTO:
    case CDBG_LANG_C:
    case CDBG_LANG_CXX:
    case CDBG_LANG_OBJC:
        return true;
    default:
        return false;
    }
}

int cdbg_language_check_expr(const cdbg_t *dbg)
{
    const cdbg_language_t lang = cdbg_language_effective(dbg);
    if (!cdbg_language_supports_expr(lang)) {
        fprintf(stderr, "Expressions are not supported for language \"%s\"\n",
                cdbg_language_name(lang));
        return -1;
    }
    return 0;
}

static void print_language_usage(void)
{
    fputs("Usage: set language auto|c|c++|objective-c|fortran|pascal|ada|"
          "modula-2|java|go|rust|assembly\n", stderr);
}

int cdbg_set_run_target(cdbg_t *dbg, char *const argv[])
{
    if (dbg == NULL || argv == NULL || argv[0] == NULL) {
        return -1;
    }

    size_t argc = 0;
    while (argv[argc] != NULL) {
        if (argc >= CDBG_MAX_RUN_ARGS) {
            fputs("Too many run arguments\n", stderr);
            return -1;
        }
        snprintf(dbg->run_argv_storage[argc], sizeof(dbg->run_argv_storage[argc]), "%s",
                 argv[argc]);
        dbg->run_argv[argc] = dbg->run_argv_storage[argc];
        argc++;
    }

    dbg->run_argv[argc] = NULL;
    dbg->run_argc = argc;
    return 0;
}

static int resolve_entry_stop_addr(cdbg_t *dbg, uintptr_t *addr_out, char *label_out,
                                   size_t label_len)
{
    static const char *entry_names[] = {"main", NULL};

    for (size_t i = 0; entry_names[i] != NULL; i++) {
        const cdbg_sym_entry_t *sym = cdbg_syms_lookup_name(&dbg->syms, entry_names[i]);
        if (sym == NULL || sym->address == 0 || sym->type == 'U' || sym->type == 'u') {
            continue;
        }

        uintptr_t addr = cdbg_syms_runtime_addr(&dbg->syms, sym->address);
        const cdbg_line_entry_t *first_body_line =
            cdbg_lineno_lookup_next_line_after_pc(&dbg->lineno, addr);
        if (first_body_line == NULL) {
            for (size_t j = 0; j < dbg->lineno.count; j++) {
                const cdbg_line_entry_t *entry = &dbg->lineno.entries[j];
                uintptr_t entry_runtime =
                    cdbg_lineno_runtime_addr(&dbg->lineno, entry->address);
                if (entry_runtime < addr) {
                    continue;
                }
                if (first_body_line == NULL ||
                    entry->address < first_body_line->address) {
                    first_body_line = entry;
                }
            }
        }
        if (first_body_line != NULL) {
            addr = cdbg_lineno_runtime_addr(&dbg->lineno, first_body_line->address);
            snprintf(label_out, label_len, "%s:%u", first_body_line->file,
                     first_body_line->line);
        } else {
            const char *name = sym->name;
            if (name[0] == '_' && name[1] != '\0') {
                name++;
            }
            snprintf(label_out, label_len, "%s", name);
        }

        *addr_out = addr;
        return 0;
    }

    return -1;
}

static void print_run_banner(cdbg_t *dbg)
{
    printf("Starting program: %s", dbg->run_argv[0]);
    for (size_t i = 1; i < dbg->run_argc; i++) {
        printf(" %s", dbg->run_argv[i]);
    }
    putchar('\n');
    printf("Attached to pid %d\n", dbg->pid);
}

static int run_to_entry_stop(cdbg_t *dbg)
{
    if (dbg->state != CDBG_STATE_STOPPED) {
        return 0;
    }

    uintptr_t entry_addr = 0;
    char label[256];
    if (resolve_entry_stop_addr(dbg, &entry_addr, label, sizeof(label)) != 0) {
        return 0;
    }

    cdbg_breakpoint_t temp_bp = {0};
    if (cdbg_bp_enable(&temp_bp, dbg->pid, entry_addr) != 0) {
        return -1;
    }

    if (cdbg_continue(dbg) != 0) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        return -1;
    }
    if (cdbg_wait(dbg) != 0) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        return -1;
    }
    if (dbg->state != CDBG_STATE_STOPPED) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        return 0;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    if (cdbg_bp_matches_pc(pc, &temp_bp)) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        if (pc > 0) {
            (void)cdbg_regs_set_pc(&dbg->regs, pc - 1);
            if (cdbg_regs_set(dbg->pid, &dbg->regs) != 0) {
                return -1;
            }
        }
        print_stop_header(dbg);
        printf("Stopped at %s\n", label);
        print_stop_location(dbg, entry_addr);
        return 1;
    }

    (void)cdbg_bp_disable(&temp_bp, dbg->pid);
    return 0;
}

static int stop_debuggee(cdbg_t *dbg)
{
    if (dbg->pid <= 0) {
        dbg->state = CDBG_STATE_IDLE;
        return 0;
    }

    if (dbg->state != CDBG_STATE_IDLE) {
        if (ptrace(PT_KILL, dbg->pid, (caddr_t)0, 0) == -1) {
            perror("ptrace(PT_KILL)");
            return -1;
        }
        if (cdbg_process_wait(dbg->pid, &dbg->wait_status) != 0) {
            return -1;
        }
    }

    dbg->pid = 0;
    dbg->state = CDBG_STATE_IDLE;
    for (size_t i = 0; i < dbg->breakpoint_count; i++) {
        dbg->breakpoints[i].enabled = false;
    }
    return 0;
}

int cdbg_run(cdbg_t *dbg, char *const argv[])
{
    if (dbg == NULL) {
        return -1;
    }

    if (argv != NULL && cdbg_set_run_target(dbg, argv) != 0) {
        return -1;
    }
    if (dbg->run_argc == 0 || dbg->run_argv[0] == NULL) {
        fputs("No executable specified. Usage: run <program> [args...]\n", stderr);
        return -1;
    }

    if (stop_debuggee(dbg) != 0) {
        return -1;
    }

    dbg->breakpoint_count = 0;
    memset(dbg->breakpoints, 0, sizeof(dbg->breakpoints));
    memset(&dbg->regs, 0, sizeof(dbg->regs));
    dbg->wait_status = 0;

    const char *program = dbg->run_argv[0];
    if (cdbg_load_symbols(dbg, program) != 0) {
        fprintf(stderr, "Warning: could not load debug info for %s\n", program);
    }

    if (cdbg_spawn(dbg, dbg->run_argv) != 0) {
        return -1;
    }

    int wait_rc = cdbg_wait(dbg);
    if (wait_rc != 0 && dbg->state == CDBG_STATE_IDLE) {
        report_process_exit(dbg);
        return -1;
    }
    if (wait_rc != 0) {
        return -1;
    }

    if (dbg->lineno.count > 0) {
        (void)cdbg_lineno_update_slide(&dbg->lineno, dbg->pid);
    }
    if (dbg->syms.count > 0) {
        (void)cdbg_syms_update_slide(&dbg->syms, dbg->pid);
    }

    print_run_banner(dbg);

    int entry_rc = run_to_entry_stop(dbg);
    if (entry_rc < 0) {
        if (dbg->state == CDBG_STATE_IDLE) {
            report_process_exit(dbg);
        }
        return -1;
    }
    if (entry_rc == 0 && dbg->state == CDBG_STATE_STOPPED) {
        cdbg_print_stop_context(dbg);
    }

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

    if (cdbg_process_spawn(&pid, argv, dbg->malloc_stack_logging) != 0) {
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

static cdbg_breakpoint_t *disabled_breakpoint_at_pc(cdbg_t *dbg, uintptr_t pc)
{
    for (size_t i = 0; i < dbg->breakpoint_count; i++) {
        cdbg_breakpoint_t *bp = &dbg->breakpoints[i];
        if (!bp->enabled && bp->addr == pc) {
            return bp;
        }
    }
    return NULL;
}

static int reenable_breakpoints_after_step(cdbg_t *dbg)
{
    if (dbg->breakpoint_count == 0 || dbg->state != CDBG_STATE_STOPPED) {
        return 0;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    for (size_t i = 0; i < dbg->breakpoint_count; i++) {
        cdbg_breakpoint_t *bp = &dbg->breakpoints[i];
        if (!bp->enabled && bp->addr != pc) {
            if (cdbg_bp_enable(bp, dbg->pid, bp->addr) != 0) {
                return -1;
            }
        }
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
    if (reenable_breakpoints_after_step(dbg) != 0) {
        return -1;
    }
    return 0;
}

static int step_over_disabled_breakpoint(cdbg_t *dbg)
{
    if (dbg->state != CDBG_STATE_STOPPED || dbg->breakpoint_count == 0) {
        return 0;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    uintptr_t pc = cdbg_regs_pc(&dbg->regs);
    if (disabled_breakpoint_at_pc(dbg, pc) == NULL) {
        return 0;
    }

    if (cdbg_single_step(dbg) != 0) {
        return -1;
    }
    return cdbg_wait(dbg);
}

int cdbg_continue(cdbg_t *dbg)
{
    int step_rc = step_over_disabled_breakpoint(dbg);
    if (step_rc != 0) {
        return step_rc;
    }
    if (dbg->state == CDBG_STATE_IDLE) {
        return 0;
    }

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
    if (dbg->state == CDBG_STATE_IDLE) {
        (void)cdbg_bp_disable(&temp_bp, dbg->pid);
        return 0;
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

static int load_otool_disassembly(cdbg_t *dbg, disasm_entry_t **entries_out,
                                  size_t *count_out)
{
    *entries_out = NULL;
    *count_out = 0;

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

    if (count == 0) {
        free(entries);
        return -1;
    }

    *entries_out = entries;
    *count_out = count;
    return 0;
}

#define CDBG_DISASM_DEFAULT_COUNT 10

static int print_otool_disassembly_range(cdbg_t *dbg, uintptr_t runtime_pc,
                                         size_t insn_count, const char *label)
{
    disasm_entry_t *entries = NULL;
    size_t count = 0;
    if (load_otool_disassembly(dbg, &entries, &count) != 0) {
        return -1;
    }

    uintptr_t slide = dbg->lineno.slide != 0 ? dbg->lineno.slide : dbg->syms.slide;
    uintptr_t link_pc = runtime_pc - slide;
    size_t start = count;
    for (size_t i = 0; i < count; i++) {
        if (entries[i].address <= link_pc) {
            start = i;
        } else {
            break;
        }
    }

    if (start == count || link_pc - entries[start].address > 32) {
        free(entries);
        return -1;
    }

    if (label != NULL && label[0] != '\0') {
        printf("\nDisassembly at %s (0x%lx):\n", label, (unsigned long)runtime_pc);
    } else {
        printf("\nDisassembly at 0x%lx:\n", (unsigned long)runtime_pc);
    }

    for (size_t n = 0; n < insn_count && start + n < count; n++) {
        uintptr_t runtime_addr = entries[start + n].address + slide;
        const char *marker = (runtime_addr == runtime_pc) ? "=>" : "  ";
        printf("%s 0x%016lx: %s\n", marker, (unsigned long)runtime_addr,
               entries[start + n].text);
    }
    putchar('\n');

    free(entries);
    return 0;
}

static int print_otool_disassembly(cdbg_t *dbg, uintptr_t runtime_pc)
{
    return print_otool_disassembly_range(dbg, runtime_pc, 1, NULL);
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

static void print_memory_disassembly_range(cdbg_t *dbg, uintptr_t pc, size_t insn_count,
                                           const char *label)
{
    uint8_t bytes[256];
    if (cdbg_mem_read(dbg->pid, pc, bytes, sizeof(bytes)) != 0) {
        return;
    }

    if (label != NULL && label[0] != '\0') {
        printf("\nDisassembly at %s (0x%lx):\n", label, (unsigned long)pc);
    } else {
        printf("\nDisassembly at 0x%lx:\n", (unsigned long)pc);
    }

    size_t offset = 0;
    for (size_t n = 0; n < insn_count && offset < sizeof(bytes); n++) {
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

        const char *marker = (pc + offset == pc) ? "=>" : "  ";
        printf("%s 0x%016lx: %-24s ;", marker, (unsigned long)(pc + offset), text);
        for (size_t j = 0; j < used; j++) {
            printf(" %02x", bytes[offset + j]);
        }
        putchar('\n');
        offset += used;
    }
    putchar('\n');
}

static void print_memory_disassembly(cdbg_t *dbg, uintptr_t pc)
{
    print_memory_disassembly_range(dbg, pc, 1, NULL);
}

static void print_disassembly_range(cdbg_t *dbg, uintptr_t pc, size_t count,
                                    const char *label)
{
    if (print_otool_disassembly_range(dbg, pc, count, label) == 0) {
        return;
    }
    print_memory_disassembly_range(dbg, pc, count, label);
}

static void print_disassembly_at_pc(cdbg_t *dbg, uintptr_t pc)
{
    if (print_otool_disassembly(dbg, pc) == 0) {
        return;
    }
    print_memory_disassembly(dbg, pc);
}

static uint64_t get_primary_thread_id(pid_t pid)
{
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        return 0;
    }
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t kr = task_threads(task, &threads, &count);
    mach_port_deallocate(mach_task_self(), task);
    if (kr != KERN_SUCCESS || count == 0) {
        return 0;
    }
    thread_identifier_info_data_t info;
    mach_msg_type_number_t info_count = THREAD_IDENTIFIER_INFO_COUNT;
    uint64_t tid = 0;
    if (thread_info(threads[0], THREAD_IDENTIFIER_INFO,
                    (thread_info_t)&info, &info_count) == KERN_SUCCESS) {
        tid = info.thread_id;
    }
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  count * sizeof(thread_act_t));
    return tid;
}

static void print_stop_header(const cdbg_t *dbg)
{
    uint64_t tid = get_primary_thread_id(dbg->pid);
    if (tid != 0) {
        printf("[PID: %d  TID: %llu]\n",
               (int)dbg->pid, (unsigned long long)tid);
    } else {
        printf("[PID: %d]\n", (int)dbg->pid);
    }
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
            print_stop_header(dbg);
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
            print_stop_header(dbg);
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

static void report_process_exit(cdbg_t *dbg)
{
    if (dbg->state != CDBG_STATE_IDLE) {
        return;
    }

    pid_t exited_pid = dbg->pid;
    if (WIFEXITED(dbg->wait_status)) {
        printf("Process %d exited with code %d\n", (int)exited_pid,
               WEXITSTATUS(dbg->wait_status));
    } else if (WIFSIGNALED(dbg->wait_status)) {
        printf("Process %d terminated by signal %d\n", (int)exited_pid,
               WTERMSIG(dbg->wait_status));
    } else {
        printf("Process %d exited\n", (int)exited_pid);
    }

    for (size_t i = 0; i < dbg->breakpoint_count; i++) {
        dbg->breakpoints[i].enabled = false;
    }
    dbg->pid = 0;
}

static int report_stop(cdbg_t *dbg)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    print_stop_header(dbg);

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

static int parse_member_offset(const char *line, size_t *out)
{
    const char *loc = strstr(line, "DW_AT_data_member_location");
    if (loc == NULL) {
        return -1;
    }

    const char *open = strchr(loc, '(');
    if (open == NULL) {
        return -1;
    }

    char *end = NULL;
    unsigned long long value = strtoull(open + 1, &end, 16);
    if (end == open + 1) {
        return -1;
    }

    *out = (size_t)value;
    return 0;
}

static bool type_is_scalar(const char *type)
{
    if (type == NULL || type[0] == '\0') {
        return false;
    }
    if (strchr(type, '*') != NULL) {
        return true;
    }
    if (strstr(type, "char") != NULL || strstr(type, "short") != NULL ||
        strstr(type, "int") != NULL || strstr(type, "long") != NULL ||
        strstr(type, "bool") != NULL) {
        return true;
    }
    return false;
}

static int parse_array_type(const char *type, char *elem_type, size_t elem_len,
                            size_t *count_out)
{
    const char *bracket = strchr(type, '[');
    if (bracket == NULL || bracket == type) {
        return -1;
    }

    size_t name_len = (size_t)(bracket - type);
    if (name_len >= elem_len) {
        name_len = elem_len - 1;
    }
    memcpy(elem_type, type, name_len);
    elem_type[name_len] = '\0';

    char *end = NULL;
    unsigned long count = strtoul(bracket + 1, &end, 10);
    if (end == bracket + 1 || *end != ']') {
        return -1;
    }

    *count_out = (size_t)count;
    return 0;
}

typedef enum {
    CDBG_AGG_NONE,
    CDBG_AGG_STRUCT,
    CDBG_AGG_UNION,
} cdbg_aggregate_kind_t;

static bool type_has_struct_union_prefix(const char *type)
{
    return strncmp(type, "struct ", 7) == 0 || strncmp(type, "union ", 6) == 0;
}

static cdbg_aggregate_kind_t dwarf_lookup_aggregate_kind(cdbg_t *dbg, const char *name)
{
    if (dbg->debug_info_path[0] == '\0' || name == NULL || name[0] == '\0' ||
        type_is_scalar(name)) {
        return CDBG_AGG_NONE;
    }

    char cmd[CDBG_MAX_PATH + 64];
    int n = snprintf(cmd, sizeof(cmd), "dwarfdump --debug-info '%s' 2>/dev/null",
                     dbg->debug_info_path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return CDBG_AGG_NONE;
    }

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        return CDBG_AGG_NONE;
    }

    bool in_aggregate = false;
    cdbg_aggregate_kind_t current_kind = CDBG_AGG_NONE;
    cdbg_aggregate_kind_t found = CDBG_AGG_NONE;
    char line[1024];

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (dwarf_starts_die(line)) {
            if (strstr(line, "DW_TAG_structure_type") != NULL) {
                in_aggregate = true;
                current_kind = CDBG_AGG_STRUCT;
                continue;
            }
            if (strstr(line, "DW_TAG_union_type") != NULL) {
                in_aggregate = true;
                current_kind = CDBG_AGG_UNION;
                continue;
            }
            if (in_aggregate && strstr(line, "NULL") != NULL) {
                in_aggregate = false;
                continue;
            }
            if (in_aggregate) {
                in_aggregate = false;
            }
        }

        if (!in_aggregate) {
            continue;
        }

        if (strstr(line, "DW_AT_name") != NULL) {
            char agg_name[128];
            if (parse_quoted_value(line, agg_name, sizeof(agg_name)) == 0 &&
                strcmp(agg_name, name) == 0) {
                found = current_kind;
                break;
            }
        }
    }

    pclose(fp);
    return found;
}

static void format_type_for_display(cdbg_t *dbg, const char *type, char *out, size_t out_len)
{
    if (type == NULL || type[0] == '\0') {
        out[0] = '\0';
        return;
    }
    if (type_has_struct_union_prefix(type)) {
        snprintf(out, out_len, "%s", type);
        return;
    }

    char work[256];
    snprintf(work, sizeof(work), "%s", type);

    char array_suffix[64] = {0};
    char *bracket = strchr(work, '[');
    if (bracket != NULL) {
        snprintf(array_suffix, sizeof(array_suffix), "%s", bracket);
        *bracket = '\0';
    }

    char ptr_suffix[8] = {0};
    char *star = strchr(work, '*');
    if (star != NULL) {
        snprintf(ptr_suffix, sizeof(ptr_suffix), " *");
        *star = '\0';
    }

    const char *base = trim_space(work);
    cdbg_aggregate_kind_t kind = dwarf_lookup_aggregate_kind(dbg, base);
    if (kind == CDBG_AGG_STRUCT) {
        snprintf(out, out_len, "struct %s%s%s", base, array_suffix, ptr_suffix);
    } else if (kind == CDBG_AGG_UNION) {
        snprintf(out, out_len, "union %s%s%s", base, array_suffix, ptr_suffix);
    } else {
        snprintf(out, out_len, "%s", type);
    }
}

static int dwarf_lookup_struct(cdbg_t *dbg, const char *name,
                              cdbg_struct_member_t *members, size_t max_members,
                              size_t *member_count_out, size_t *byte_size_out)
{
    if (dbg->debug_info_path[0] == '\0' || name == NULL || name[0] == '\0') {
        return -1;
    }

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

    bool in_struct = false;
    bool struct_matches = false;
    bool reading_member = false;
    cdbg_struct_member_t member = {0};
    size_t member_count = 0;
    size_t byte_size = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (reading_member && dwarf_starts_die(line)) {
            if (member.name[0] != '\0' && member_count < max_members) {
                member.size = type_scalar_size(member.type);
                member.is_signed = strstr(member.type, "unsigned") == NULL;
                members[member_count++] = member;
            }
            memset(&member, 0, sizeof(member));
            reading_member = false;
            if (in_struct && struct_matches && strstr(line, "NULL") != NULL) {
                break;
            }
        }

        if (dwarf_starts_die(line)) {
            if (strstr(line, "DW_TAG_structure_type") != NULL) {
                in_struct = true;
                struct_matches = false;
                byte_size = 0;
                continue;
            }
            if (in_struct && struct_matches &&
                strstr(line, "DW_TAG_member") != NULL) {
                memset(&member, 0, sizeof(member));
                reading_member = true;
                continue;
            }
            if (in_struct && struct_matches && strstr(line, "NULL") != NULL) {
                break;
            }
            if (in_struct && !struct_matches) {
                in_struct = false;
            }
        }

        if (!in_struct) {
            continue;
        }

        if (strstr(line, "DW_AT_name") != NULL && !reading_member) {
            char struct_name[128];
            if (parse_quoted_value(line, struct_name, sizeof(struct_name)) == 0 &&
                strcmp(struct_name, name) == 0) {
                struct_matches = true;
            }
            continue;
        }

        if (!struct_matches) {
            continue;
        }

        if (strstr(line, "DW_AT_byte_size") != NULL) {
            const char *open = strchr(line, '(');
            if (open != NULL) {
                char *end = NULL;
                unsigned long long value = strtoull(open + 1, &end, 16);
                if (end != open + 1) {
                    byte_size = (size_t)value;
                }
            }
            continue;
        }

        if (!reading_member) {
            continue;
        }

        if (strstr(line, "DW_AT_name") != NULL) {
            (void)parse_quoted_value(line, member.name, sizeof(member.name));
        } else if (strstr(line, "DW_AT_type") != NULL) {
            (void)parse_quoted_value(line, member.type, sizeof(member.type));
        } else if (strstr(line, "DW_AT_data_member_location") != NULL) {
            (void)parse_member_offset(line, &member.offset);
        }
    }

    if (reading_member && member.name[0] != '\0' && member_count < max_members) {
        member.size = type_scalar_size(member.type);
        member.is_signed = strstr(member.type, "unsigned") == NULL;
        members[member_count++] = member;
    }

    pclose(fp);
    if (member_count == 0) {
        return -1;
    }

    *member_count_out = member_count;
    *byte_size_out = byte_size;
    return 0;
}

static size_t type_element_size(cdbg_t *dbg, const char *type)
{
    if (type == NULL || type[0] == '\0') {
        return 0;
    }

    if (type_is_scalar(type)) {
        return type_scalar_size(type);
    }

    cdbg_struct_member_t members[32];
    size_t member_count = 0;
    size_t byte_size = 0;
    if (dwarf_lookup_struct(dbg, type, members, 32, &member_count, &byte_size) == 0 &&
        byte_size > 0) {
        return byte_size;
    }

    return sizeof(uintptr_t);
}

static void complete_var_type(cdbg_t *dbg, cdbg_var_info_t *var)
{
    char element_type[128];
    size_t array_count = 0;

    var->is_pointer = strchr(var->type, '*') != NULL;
    var->is_signed = strstr(var->type, "unsigned") == NULL;
    var->is_array = parse_array_type(var->type, element_type, sizeof(element_type),
                                     &array_count) == 0;
    if (var->is_array) {
        snprintf(var->element_type, sizeof(var->element_type), "%s", element_type);
        var->array_count = array_count;
        var->element_size = type_element_size(dbg, element_type);
        var->size = var->element_size * array_count;
        var->pointee_size = var->element_size;
        return;
    }

    var->element_type[0] = '\0';
    var->array_count = 0;
    var->element_size = 0;
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

static int finish_var_if_match(cdbg_t *dbg, cdbg_var_info_t *var, const char *name,
                               cdbg_var_info_t *out)
{
    if (!var_ready(var, name)) {
        return -1;
    }

    complete_var_type(dbg, var);
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
            if (finish_var_if_match(dbg, &var, name, out) == 0) {
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
    if (reading_var && finish_var_if_match(dbg, &var, name, out) == 0) {
        rc = 0;
    }
    pclose(fp);
    return rc;
}

#define CDBG_MAX_SHOW_VARS 128

typedef enum {
    CDBG_SHOW_LOCALS,
    CDBG_SHOW_ARGS,
    CDBG_SHOW_GLOBALS,
} cdbg_show_scope_t;

typedef struct {
    cdbg_var_info_t var;
    uintptr_t addr;
} cdbg_show_var_t;

static int parse_addr_location(const char *line, uintptr_t *out)
{
    const char *op = strstr(line, "DW_OP_addr");
    if (op == NULL) {
        return -1;
    }

    const char *p = op + strlen("DW_OP_addr");
    while (*p == ' ') {
        p++;
    }

    char *end = NULL;
    unsigned long long value = strtoull(p, &end, 0);
    if (end == p) {
        return -1;
    }

    *out = (uintptr_t)value;
    return 0;
}

static bool show_var_name_exists(const cdbg_show_var_t *vars, size_t count, const char *name)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(vars[i].var.name, name) == 0) {
            return true;
        }
    }
    return false;
}

static int show_var_push(cdbg_t *dbg, cdbg_show_var_t *vars, size_t *count, size_t max,
                         cdbg_var_info_t *var, uintptr_t addr)
{
    if (var->name[0] == '\0') {
        return 0;
    }
    if (*count >= max) {
        return 0;
    }
    if (show_var_name_exists(vars, *count, var->name)) {
        return 0;
    }

    var->has_location = true;
    complete_var_type(dbg, var);
    vars[*count].var = *var;
    vars[*count].addr = addr;
    (*count)++;
    return 0;
}

static bool sym_is_global_data(char type)
{
    switch (type) {
    case 'b':
    case 'B':
    case 'd':
    case 'D':
    case 'g':
    case 'G':
    case 's':
    case 'S':
    case 'C':
        return true;
    default:
        return false;
    }
}

static void collect_globals_from_syms(cdbg_t *dbg, cdbg_show_var_t *vars, size_t *count,
                                      size_t max)
{
    for (size_t i = 0; i < dbg->syms.count && *count < max; i++) {
        const cdbg_sym_entry_t *entry = &dbg->syms.entries[i];
        if (entry->address == 0 || !sym_is_global_data(entry->type)) {
            continue;
        }
        if (show_var_name_exists(vars, *count, entry->name)) {
            continue;
        }

        cdbg_var_info_t var = {0};
        snprintf(var.name, sizeof(var.name), "%s", entry->name);
        snprintf(var.type, sizeof(var.type), "unsigned long");
        uintptr_t addr = cdbg_syms_runtime_addr(&dbg->syms, entry->address);
        (void)show_var_push(dbg, vars, count, max, &var, addr);
    }
}

static int collect_show_vars(cdbg_t *dbg, cdbg_show_scope_t scope, cdbg_show_var_t *vars,
                             size_t max, size_t *count_out)
{
    *count_out = 0;
    if (dbg->debug_info_path[0] == '\0') {
        if (scope == CDBG_SHOW_GLOBALS) {
            collect_globals_from_syms(dbg, vars, count_out, max);
        }
        return *count_out > 0 ? 0 : -1;
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
    bool in_lex_block = false;
    bool lex_matches = false;
    uintptr_t lex_low = 0;
    uintptr_t lex_high = 0;
    bool reading_var = false;
    bool reading_formal = false;
    cdbg_var_info_t var = {0};
    bool loc_fbreg = false;
    uintptr_t link_addr = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (reading_var && dwarf_starts_die(line)) {
            if (var.name[0] != '\0') {
                bool include = false;
                switch (scope) {
                case CDBG_SHOW_ARGS:
                    include = reading_formal && func_matches && in_func && loc_fbreg;
                    break;
                case CDBG_SHOW_LOCALS:
                    include = !reading_formal && func_matches && in_func && loc_fbreg &&
                              (!in_lex_block || lex_matches);
                    break;
                case CDBG_SHOW_GLOBALS:
                    include = !reading_formal && !in_func && !in_lex_block &&
                              link_addr != 0;
                    break;
                }

                if (include) {
                    uintptr_t addr = 0;
                    if (scope == CDBG_SHOW_GLOBALS) {
                        addr = cdbg_syms_runtime_addr(&dbg->syms, link_addr);
                    } else {
                        uintptr_t fp_reg = cdbg_regs_fp(&dbg->regs);
                        addr = (uintptr_t)((int64_t)fp_reg + var.fbreg_offset);
                    }
                    (void)show_var_push(dbg, vars, count_out, max, &var, addr);
                }
            }
            memset(&var, 0, sizeof(var));
            reading_var = false;
            reading_formal = false;
            loc_fbreg = false;
            link_addr = 0;
        }

        if (dwarf_starts_die(line)) {
            int depth = dwarf_line_depth(line);
            if (strstr(line, "DW_TAG_subprogram") != NULL) {
                in_func = true;
                func_matches = false;
                func_depth = depth;
                func_low = 0;
                func_high = 0;
            } else if (in_func && depth <= func_depth) {
                in_func = false;
                func_matches = false;
                in_lex_block = false;
                lex_matches = false;
            } else if (in_func && func_matches &&
                       strstr(line, "DW_TAG_lexical_block") != NULL) {
                in_lex_block = true;
                lex_matches = false;
                lex_low = 0;
                lex_high = 0;
            } else if (in_func && func_matches &&
                       strstr(line, "DW_TAG_formal_parameter") != NULL) {
                memset(&var, 0, sizeof(var));
                reading_var = true;
                reading_formal = true;
                loc_fbreg = false;
                link_addr = 0;
            } else if (strstr(line, "DW_TAG_variable") != NULL) {
                memset(&var, 0, sizeof(var));
                reading_var = true;
                reading_formal = false;
                loc_fbreg = false;
                link_addr = 0;
            } else if (in_lex_block && strstr(line, "NULL") != NULL) {
                in_lex_block = false;
                lex_matches = false;
            }
        }

        if (in_func && strstr(line, "DW_AT_low_pc") != NULL) {
            if (in_lex_block) {
                (void)parse_hex_value(line, &lex_low);
                lex_matches = pc_in_range(link_pc, lex_low, lex_high);
            } else {
                (void)parse_hex_value(line, &func_low);
                func_matches = pc_in_range(link_pc, func_low, func_high);
            }
            continue;
        }
        if (in_func && strstr(line, "DW_AT_high_pc") != NULL) {
            if (in_lex_block) {
                (void)parse_hex_value(line, &lex_high);
                lex_matches = pc_in_range(link_pc, lex_low, lex_high);
            } else {
                (void)parse_hex_value(line, &func_high);
                func_matches = pc_in_range(link_pc, func_low, func_high);
            }
            continue;
        }

        if (!reading_var) {
            continue;
        }
        if (strstr(line, "DW_AT_location") != NULL) {
            if (parse_fbreg_offset(line, &var.fbreg_offset) == 0) {
                loc_fbreg = true;
            } else if (parse_addr_location(line, &link_addr) == 0) {
                loc_fbreg = false;
            }
        } else if (strstr(line, "DW_AT_name") != NULL) {
            (void)parse_quoted_value(line, var.name, sizeof(var.name));
        } else if (strstr(line, "DW_AT_type") != NULL) {
            (void)parse_quoted_value(line, var.type, sizeof(var.type));
        }
    }

    if (reading_var && var.name[0] != '\0') {
        bool include = false;
        switch (scope) {
        case CDBG_SHOW_ARGS:
            include = reading_formal && func_matches && in_func && loc_fbreg;
            break;
        case CDBG_SHOW_LOCALS:
            include = !reading_formal && func_matches && in_func && loc_fbreg &&
                      (!in_lex_block || lex_matches);
            break;
        case CDBG_SHOW_GLOBALS:
            include = !reading_formal && !in_func && !in_lex_block && link_addr != 0;
            break;
        }
        if (include) {
            uintptr_t addr = 0;
            if (scope == CDBG_SHOW_GLOBALS) {
                addr = cdbg_syms_runtime_addr(&dbg->syms, link_addr);
            } else {
                uintptr_t fp_reg = cdbg_regs_fp(&dbg->regs);
                addr = (uintptr_t)((int64_t)fp_reg + var.fbreg_offset);
            }
            (void)show_var_push(dbg, vars, count_out, max, &var, addr);
        }
    }

    pclose(fp);

    if (scope == CDBG_SHOW_GLOBALS) {
        collect_globals_from_syms(dbg, vars, count_out, max);
    }

    return *count_out > 0 ? 0 : -1;
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
    complete_var_type(dbg, var);
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

typedef enum {
    PRINT_FMT_DEFAULT,
    PRINT_FMT_DEC,
    PRINT_FMT_HEX,
    PRINT_FMT_OCT,
    PRINT_FMT_BIN,
    PRINT_FMT_CHAR,
    PRINT_FMT_STRING,
} print_format_t;

#define CDBG_MAX_PRINT_STRING 256

static print_format_t parse_print_format(char **expr)
{
    if (expr == NULL || *expr == NULL || (*expr)[0] != '/') {
        return PRINT_FMT_DEFAULT;
    }

    print_format_t fmt = PRINT_FMT_DEFAULT;
    switch ((*expr)[1]) {
    case 'd':
    case 'i':
        fmt = PRINT_FMT_DEC;
        break;
    case 'x':
        fmt = PRINT_FMT_HEX;
        break;
    case 'o':
        fmt = PRINT_FMT_OCT;
        break;
    case 't':
        fmt = PRINT_FMT_BIN;
        break;
    case 'c':
        fmt = PRINT_FMT_CHAR;
        break;
    case 's':
        fmt = PRINT_FMT_STRING;
        break;
    default:
        return PRINT_FMT_DEFAULT;
    }

    if ((*expr)[2] != '\0' && !isspace((unsigned char)(*expr)[2])) {
        return PRINT_FMT_DEFAULT;
    }

    *expr = trim_space(*expr + 2);
    return fmt;
}

static uint64_t mask_to_size(uint64_t value, size_t size)
{
    if (size == 0 || size >= sizeof(uint64_t)) {
        return value;
    }
    unsigned int bits = (unsigned int)(size * 8);
    uint64_t mask = (1ULL << bits) - 1ULL;
    return value & mask;
}

static void print_binary_value(uint64_t value, size_t size)
{
    unsigned int bits = (unsigned int)((size == 0 || size > sizeof(uint64_t)) ?
                                         sizeof(uint64_t) * 8 : size * 8);
    value = mask_to_size(value, size);
    for (unsigned int i = bits; i > 0; i--) {
        putchar((value >> (i - 1)) & 1 ? '1' : '0');
    }
}

static int read_c_string(pid_t pid, uintptr_t addr, char *out, size_t out_len)
{
    if (out_len == 0) {
        return -1;
    }

    size_t i = 0;
    while (i + 1 < out_len) {
        uint8_t byte = 0;
        if (cdbg_mem_read(pid, addr + i, &byte, 1) != 0) {
            return -1;
        }
        out[i++] = (char)byte;
        if (byte == '\0') {
            return 0;
        }
    }

    out[out_len - 1] = '\0';
    return 0;
}

static void print_char_value(unsigned char ch)
{
    if (ch == '\\') {
        fputs("'\\\\'", stdout);
    } else if (ch == '\'') {
        fputs("'\\''", stdout);
    } else if (isprint((unsigned char)ch)) {
        printf("'%c'", ch);
    } else {
        printf("'\\x%02x'", ch);
    }
}

static void print_type_annotation(const cdbg_t *dbg, print_format_t fmt, const char *type)
{
    if (dbg != NULL && dbg->print_pretty && fmt == PRINT_FMT_DEFAULT &&
        type != NULL && type[0] != '\0') {
        char display[256];
        format_type_for_display((cdbg_t *)dbg, type, display, sizeof(display));
        printf("(%s) ", display);
    }
}

static void print_scalar_result_fmt(cdbg_t *dbg, const char *label, print_format_t fmt,
                                    uint64_t value, size_t size, bool is_signed,
                                    bool is_pointer, bool is_address, const char *type)
{
    value = mask_to_size(value, size);

    switch (fmt) {
    case PRINT_FMT_HEX:
        printf("%s = ", label);
        print_type_annotation(dbg, fmt, type);
        printf("0x%llx\n", (unsigned long long)value);
        return;
    case PRINT_FMT_OCT:
        printf("%s = ", label);
        print_type_annotation(dbg, fmt, type);
        printf("%#llo\n", (unsigned long long)value);
        return;
    case PRINT_FMT_BIN:
        printf("%s = ", label);
        print_type_annotation(dbg, fmt, type);
        print_binary_value(value, size);
        putchar('\n');
        return;
    case PRINT_FMT_CHAR: {
        unsigned char ch = (unsigned char)value;
        printf("%s = ", label);
        print_type_annotation(dbg, fmt, type);
        print_char_value(ch);
        putchar('\n');
        return;
    }
    case PRINT_FMT_STRING: {
        char str[CDBG_MAX_PRINT_STRING];
        if (read_c_string(dbg->pid, (uintptr_t)value, str, sizeof(str)) != 0) {
            fprintf(stderr, "Cannot read string at 0x%llx\n",
                    (unsigned long long)value);
            return;
        }
        printf("%s = ", label);
        print_type_annotation(dbg, fmt, type);
        printf("\"%s\"\n", str);
        return;
    }
    case PRINT_FMT_DEC:
        printf("%s = ", label);
        print_type_annotation(dbg, fmt, type);
        if (is_signed) {
            printf("%lld\n", (long long)sign_extend_value(value, size));
        } else {
            printf("%llu\n", (unsigned long long)value);
        }
        return;
    case PRINT_FMT_DEFAULT:
        break;
    }

    printf("%s = ", label);
    print_type_annotation(dbg, fmt, type);

    if (is_pointer || is_address) {
        printf("0x%016llx\n", (unsigned long long)value);
        return;
    }

    if (is_signed) {
        printf("%lld (0x%llx)\n", (long long)sign_extend_value(value, size),
               (unsigned long long)value);
    } else {
        printf("%llu (0x%llx)\n", (unsigned long long)value,
               (unsigned long long)value);
    }
}

static void print_scalar_result(const char *label, uint64_t value, size_t size,
                                bool is_signed, bool is_pointer)
{
    (void)size;
    (void)is_signed;
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

static bool is_simple_identifier(const char *expr)
{
    if (expr == NULL || expr[0] == '\0') {
        return false;
    }
    if (!isalpha((unsigned char)expr[0]) && expr[0] != '_') {
        return false;
    }
    for (const char *p = expr + 1; *p != '\0'; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_') {
            return false;
        }
    }
    return true;
}

static void print_scalar_inline(uint64_t value, size_t size, bool is_signed,
                                bool is_pointer)
{
    if (is_pointer) {
        printf("0x%llx", (unsigned long long)value);
        return;
    }
    if (is_signed) {
        printf("%lld", (long long)sign_extend_value(value, size));
    } else {
        printf("%llu", (unsigned long long)value);
    }
}

static int print_struct_element(cdbg_t *dbg, uintptr_t addr,
                                const cdbg_struct_member_t *members,
                                size_t member_count, bool pretty)
{
    if (!pretty) {
        putchar('{');
        for (size_t i = 0; i < member_count; i++) {
            const cdbg_struct_member_t *m = &members[i];
            uint64_t value = 0;
            if (read_scalar_value(dbg->pid, addr + m->offset, m->size, &value) != 0) {
                return -1;
            }
            if (i > 0) {
                fputs(", ", stdout);
            }
            printf("%s=", m->name);
            print_scalar_inline(value, m->size, m->is_signed, false);
        }
        putchar('}');
        return 0;
    }

    puts("{");
    for (size_t i = 0; i < member_count; i++) {
        const cdbg_struct_member_t *m = &members[i];
        uint64_t value = 0;
        if (read_scalar_value(dbg->pid, addr + m->offset, m->size, &value) != 0) {
            return -1;
        }
        printf("  %s = ", m->name);
        print_type_annotation(dbg, PRINT_FMT_DEFAULT, m->type);
        print_scalar_inline(value, m->size, m->is_signed, false);
        putchar('\n');
    }
    putchar('}');
    return 0;
}

static bool parse_array_index_expr(const char *expr, char *name, size_t name_len,
                                   size_t *index_out)
{
    const char *bracket = strchr(expr, '[');
    if (bracket == NULL || bracket == expr) {
        return false;
    }

    size_t nlen = (size_t)(bracket - expr);
    if (nlen >= name_len) {
        return false;
    }
    memcpy(name, expr, nlen);
    name[nlen] = '\0';
    if (!is_simple_identifier(name)) {
        return false;
    }

    const char *p = bracket + 1;
    if (*p == '\0' || !isdigit((unsigned char)*p)) {
        return false;
    }

    char *end = NULL;
    unsigned long idx = strtoul(p, &end, 10);
    if (end == p || *end != ']' || end[1] != '\0') {
        return false;
    }

    *index_out = (size_t)idx;
    return true;
}

static void pointer_pointee_type(const cdbg_var_info_t *var, char *out, size_t out_len)
{
    const char *star = strchr(var->type, '*');
    if (star == NULL) {
        snprintf(out, out_len, "%s", var->type);
        return;
    }

    size_t len = (size_t)(star - var->type);
    while (len > 0 && var->type[len - 1] == ' ') {
        len--;
    }
    if (len >= out_len) {
        len = out_len - 1;
    }
    memcpy(out, var->type, len);
    out[len] = '\0';
}

static int resolve_subscript_element(cdbg_t *dbg, const char *var_name, size_t index,
                                     cdbg_var_info_t *elem_view, uintptr_t *elem_addr)
{
    cdbg_var_info_t var = {0};
    uintptr_t addr = 0;
    bool found_local = false;
    if (resolve_variable_address(dbg, var_name, &var, &addr, &found_local) != 0) {
        fprintf(stderr, "Unknown variable: %s\n", var_name);
        return -1;
    }

    if (var.is_array) {
        if (index >= var.array_count) {
            fprintf(stderr, "Array index out of bounds: %zu\n", index);
            return -1;
        }
        *elem_view = var;
        *elem_addr = addr + index * var.element_size;
        return 0;
    }

    if (var.is_pointer) {
        uint64_t ptr = 0;
        if (read_scalar_value(dbg->pid, addr, sizeof(uintptr_t), &ptr) != 0) {
            return -1;
        }

        char pointee_type[128];
        pointer_pointee_type(&var, pointee_type, sizeof(pointee_type));
        memset(elem_view, 0, sizeof(*elem_view));
        snprintf(elem_view->element_type, sizeof(elem_view->element_type), "%s",
                 pointee_type);
        elem_view->element_size = type_element_size(dbg, pointee_type);
        *elem_addr = (uintptr_t)ptr + index * elem_view->element_size;
        return 0;
    }

    fprintf(stderr, "%s is not an array or pointer\n", var_name);
    return -1;
}

static int print_array_element_value(cdbg_t *dbg, const cdbg_var_info_t *var,
                                     uintptr_t elem_addr)
{
    cdbg_struct_member_t members[32];
    size_t member_count = 0;
    size_t struct_size = 0;
    bool is_struct = !type_is_scalar(var->element_type) &&
                     dwarf_lookup_struct(dbg, var->element_type, members, 32,
                                         &member_count, &struct_size) == 0;

    if (is_struct) {
        print_type_annotation(dbg, PRINT_FMT_DEFAULT, var->element_type);
        return print_struct_element(dbg, elem_addr, members, member_count, false);
    }

    uint64_t value = 0;
    bool elem_signed = strstr(var->element_type, "unsigned") == NULL;
    bool elem_pointer = strchr(var->element_type, '*') != NULL;
    if (read_scalar_value(dbg->pid, elem_addr, var->element_size, &value) != 0) {
        return -1;
    }
    print_type_annotation(dbg, PRINT_FMT_DEFAULT, var->element_type);
    print_scalar_inline(value, var->element_size, elem_signed, elem_pointer);
    printf(" (0x%llx)", (unsigned long long)value);
    return 0;
}

#define CDBG_MAX_ARRAY_PRINT 256

static int print_array_variable(cdbg_t *dbg, const char *name,
                                const cdbg_var_info_t *var, uintptr_t base_addr)
{
    if (var->array_count == 0 || var->element_size == 0) {
        return -1;
    }
    if (var->array_count > CDBG_MAX_ARRAY_PRINT) {
        fprintf(stderr, "Array too large to print (%zu elements)\n", var->array_count);
        return -1;
    }

    if (!dbg->print_pretty) {
        printf("%s = [", name);
        for (size_t i = 0; i < var->array_count; i++) {
            uintptr_t elem_addr = base_addr + i * var->element_size;
            if (i > 0) {
                fputs(", ", stdout);
            }
            if (print_array_element_value(dbg, var, elem_addr) != 0) {
                return -1;
            }
        }
        puts("]");
        return 0;
    }

    printf("%s = ", name);
    print_type_annotation(dbg, PRINT_FMT_DEFAULT, var->type);
    puts("[");
    for (size_t i = 0; i < var->array_count; i++) {
        uintptr_t elem_addr = base_addr + i * var->element_size;
        printf("  [%zu] ", i);
        if (print_array_element_value(dbg, var, elem_addr) != 0) {
            return -1;
        }
        putchar('\n');
    }
    puts("]");
    return 0;
}

static int print_named_variable(cdbg_t *dbg, const cdbg_var_info_t *var, uintptr_t addr)
{
    const char *name = var->name;

    if (var->is_array) {
        return print_array_variable(dbg, name, var, addr);
    }

    if (!var->is_pointer && !type_is_scalar(var->type)) {
        cdbg_struct_member_t members[32];
        size_t member_count = 0;
        size_t struct_size = 0;
        if (dwarf_lookup_struct(dbg, var->type, members, 32, &member_count,
                                &struct_size) == 0) {
            printf("%s = ", name);
            print_type_annotation(dbg, PRINT_FMT_DEFAULT, var->type);
            if (print_struct_element(dbg, addr, members, member_count,
                                     dbg->print_pretty) != 0) {
                return -1;
            }
            putchar('\n');
            return 0;
        }
    }

    uint64_t value = 0;
    if (read_scalar_value(dbg->pid, addr, var->size, &value) != 0) {
        return -1;
    }
    print_scalar_result_fmt(dbg, name, PRINT_FMT_DEFAULT, value, var->size,
                            var->is_signed, var->is_pointer, false, var->type);
    return 0;
}

static int lookup_struct_member(cdbg_t *dbg, const char *struct_type,
                                const char *member_name, size_t *offset_out,
                                size_t *size_out, bool *signed_out,
                                char *type_out, size_t type_out_len);

static int split_access_path(char *expr, char **base_out, char **member_out,
                             bool *via_pointer);

static int resolve_lvalue(cdbg_t *dbg, char *expr, uintptr_t *addr_out,
                          size_t *size_out, bool *signed_out, char *value_type,
                          size_t value_type_len, bool *whole_struct_out);

static int cmd_print(cdbg_t *dbg, char *expr)
{
    if (expr == NULL) {
        fputs("Usage: print [/fmt] <expr>\n", stderr);
        return -1;
    }

    expr = trim_space(expr);
    if (expr[0] == '\0') {
        fputs("Usage: print [/fmt] <expr>\n", stderr);
        return -1;
    }

    print_format_t fmt = parse_print_format(&expr);
    if (expr[0] == '\0') {
        fputs("Usage: print [/fmt] <expr>\n", stderr);
        return -1;
    }

    if (cdbg_language_check_expr(dbg) != 0) {
        return -1;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    if (is_simple_identifier(expr)) {
        cdbg_var_info_t var = {0};
        uintptr_t addr = 0;
        bool found_local = false;
        if (resolve_variable_address(dbg, expr, &var, &addr, &found_local) == 0) {
            if (var.is_array && fmt == PRINT_FMT_DEFAULT) {
                return print_array_variable(dbg, expr, &var, addr);
            }

            if (!var.is_pointer && fmt == PRINT_FMT_DEFAULT &&
                !type_is_scalar(var.type)) {
                cdbg_struct_member_t members[32];
                size_t member_count = 0;
                size_t struct_size = 0;
                if (dwarf_lookup_struct(dbg, var.type, members, 32, &member_count,
                                        &struct_size) == 0) {
                    printf("%s = ", expr);
                    print_type_annotation(dbg, fmt, var.type);
                    if (print_struct_element(dbg, addr, members, member_count,
                                             dbg->print_pretty) != 0) {
                        return -1;
                    }
                    putchar('\n');
                    return 0;
                }
            }

            uint64_t value = 0;
            if (read_scalar_value(dbg->pid, addr, var.size, &value) != 0) {
                return -1;
            }
            print_scalar_result_fmt(dbg, expr, fmt, value, var.size, var.is_signed,
                                    var.is_pointer, false, var.type);
            return 0;
        }
    }

    char work_expr[256];
    snprintf(work_expr, sizeof(work_expr), "%s", expr);
    uintptr_t addr = 0;
    size_t size = 0;
    bool is_signed = false;
    char value_type[128];
    bool whole_struct = false;
    if (resolve_lvalue(dbg, work_expr, &addr, &size, &is_signed, value_type,
                       sizeof(value_type), &whole_struct) == 0) {
        if (whole_struct && fmt == PRINT_FMT_DEFAULT) {
            cdbg_struct_member_t members[32];
            size_t member_count = 0;
            size_t struct_size = 0;
            if (dwarf_lookup_struct(dbg, value_type, members, 32, &member_count,
                                    &struct_size) != 0) {
                return -1;
            }
            printf("%s = ", expr);
            print_type_annotation(dbg, fmt, value_type);
            if (print_struct_element(dbg, addr, members, member_count,
                                     dbg->print_pretty) != 0) {
                return -1;
            }
            putchar('\n');
            return 0;
        }

        uint64_t value = 0;
        if (read_scalar_value(dbg->pid, addr, size, &value) != 0) {
            return -1;
        }
        print_scalar_result_fmt(dbg, expr, fmt, value, size, is_signed, false, false,
                                value_type);
        return 0;
    }

    cdbg_expr_result_t result = {0};
    if (cdbg_expr_eval(dbg, expr, &result) != 0) {
        return -1;
    }

    print_scalar_result_fmt(dbg, expr, fmt, result.value, sizeof(uint64_t), true,
                            false, result.is_address,
                            result.type[0] != '\0' ? result.type : NULL);
    return 0;
}

static int lookup_struct_member(cdbg_t *dbg, const char *struct_type,
                                const char *member_name, size_t *offset_out,
                                size_t *size_out, bool *signed_out,
                                char *type_out, size_t type_out_len)
{
    cdbg_struct_member_t members[32];
    size_t member_count = 0;
    size_t byte_size = 0;
    if (dwarf_lookup_struct(dbg, struct_type, members, 32, &member_count,
                            &byte_size) != 0) {
        return -1;
    }

    for (size_t i = 0; i < member_count; i++) {
        if (strcmp(members[i].name, member_name) == 0) {
            *offset_out = members[i].offset;
            *size_out = members[i].size;
            *signed_out = members[i].is_signed;
            if (type_out != NULL && type_out_len > 0) {
                snprintf(type_out, type_out_len, "%s", members[i].type);
            }
            return 0;
        }
    }
    return -1;
}

static int split_access_path(char *expr, char **base_out, char **member_out,
                             bool *via_pointer)
{
    char *arrow = strstr(expr, "->");
    if (arrow != NULL) {
        *arrow = '\0';
        *base_out = trim_space(expr);
        *member_out = trim_space(arrow + 2);
        *via_pointer = true;
        if ((*member_out)[0] == '\0' || !is_simple_identifier(*member_out)) {
            return -1;
        }
        return 0;
    }

    char *dot = strchr(expr, '.');
    if (dot != NULL) {
        *dot = '\0';
        *base_out = trim_space(expr);
        *member_out = trim_space(dot + 1);
        *via_pointer = false;
        if ((*member_out)[0] == '\0' || !is_simple_identifier(*member_out)) {
            return -1;
        }
        return 0;
    }

    *base_out = trim_space(expr);
    *member_out = NULL;
    *via_pointer = false;
    return 0;
}

static int resolve_lvalue(cdbg_t *dbg, char *expr, uintptr_t *addr_out,
                          size_t *size_out, bool *signed_out, char *value_type,
                          size_t value_type_len, bool *whole_struct_out)
{
    *whole_struct_out = false;

    char *base = NULL;
    char *member = NULL;
    bool via_ptr = false;
    if (split_access_path(expr, &base, &member, &via_ptr) != 0) {
        return -1;
    }

    char type_buf[128] = {0};
    uintptr_t addr = 0;
    size_t value_size = 0;
    bool value_signed = false;

    if (base[0] == '*') {
        const char *inner = trim_space(base + 1);
        if (inner[0] == '\0') {
            return -1;
        }

        uint64_t parsed = 0;
        if (parse_u64(inner, &parsed) == 0) {
            addr = (uintptr_t)parsed;
            value_size = sizeof(uint64_t);
        } else {
            cdbg_var_info_t var = {0};
            uintptr_t var_addr = 0;
            bool found = false;
            if (resolve_variable_address(dbg, inner, &var, &var_addr, &found) != 0) {
                fprintf(stderr, "Unknown variable: %s\n", inner);
                return -1;
            }
            if (!var.is_pointer) {
                fprintf(stderr, "%s is not a pointer\n", inner);
                return -1;
            }
            uint64_t ptr = 0;
            if (read_scalar_value(dbg->pid, var_addr, sizeof(uintptr_t), &ptr) != 0) {
                return -1;
            }
            addr = (uintptr_t)ptr;
            pointer_pointee_type(&var, type_buf, sizeof(type_buf));
            value_size = type_element_size(dbg, type_buf);
        }
    } else {
        char arr_name[128];
        size_t arr_index = 0;
        if (parse_array_index_expr(base, arr_name, sizeof(arr_name), &arr_index)) {
            cdbg_var_info_t elem_var = {0};
            if (resolve_subscript_element(dbg, arr_name, arr_index, &elem_var, &addr) != 0) {
                return -1;
            }
            snprintf(type_buf, sizeof(type_buf), "%s", elem_var.element_type);
            value_size = elem_var.element_size;
        } else if (is_simple_identifier(base)) {
            cdbg_var_info_t var = {0};
            uintptr_t var_addr = 0;
            bool found = false;
            if (resolve_variable_address(dbg, base, &var, &var_addr, &found) != 0) {
                fprintf(stderr, "Unknown variable: %s\n", base);
                return -1;
            }
            if (var.is_array && member == NULL) {
                return -1;
            }
            if (via_ptr) {
                if (!var.is_pointer) {
                    fprintf(stderr, "%s is not a pointer\n", base);
                    return -1;
                }
                uint64_t ptr = 0;
                if (read_scalar_value(dbg->pid, var_addr, sizeof(uintptr_t), &ptr) != 0) {
                    return -1;
                }
                addr = (uintptr_t)ptr;
                pointer_pointee_type(&var, type_buf, sizeof(type_buf));
                value_size = type_element_size(dbg, type_buf);
            } else {
                addr = var_addr;
                snprintf(type_buf, sizeof(type_buf), "%s", var.type);
                value_size = var.size;
                value_signed = var.is_signed;
            }
        } else {
            return -1;
        }
    }

    if (member != NULL) {
        size_t offset = 0;
        size_t member_size = 0;
        bool member_signed = false;
        char member_type[64] = {0};
        if (lookup_struct_member(dbg, type_buf, member, &offset, &member_size,
                                 &member_signed, member_type, sizeof(member_type)) != 0) {
            fprintf(stderr, "Unknown member: %s\n", member);
            return -1;
        }
        *addr_out = addr + offset;
        *size_out = member_size;
        *signed_out = member_signed;
        snprintf(value_type, value_type_len, "%s",
                 member_type[0] != '\0' ? member_type : type_buf);
        return 0;
    }

    *addr_out = addr;
    *size_out = value_size;
    if (type_buf[0] != '\0') {
        value_signed = strstr(type_buf, "unsigned") == NULL;
    }
    *signed_out = value_signed;
    snprintf(value_type, value_type_len, "%s", type_buf);
    if (type_buf[0] != '\0' && !type_is_scalar(type_buf)) {
        *whole_struct_out = true;
    }
    return 0;
}

int cdbg_resolve_lvalue_expr(cdbg_t *dbg, char *expr, uintptr_t *addr_out,
                             char *type_out, size_t type_out_len)
{
    if (dbg == NULL || expr == NULL || addr_out == NULL) {
        return -1;
    }

    size_t size = 0;
    bool is_signed = false;
    bool whole_struct = false;
    char type_buf[128] = {0};
    if (resolve_lvalue(dbg, expr, addr_out, &size, &is_signed, type_buf, sizeof(type_buf),
                       &whole_struct) != 0) {
        return -1;
    }

    if (type_out != NULL && type_out_len > 0) {
        snprintf(type_out, type_out_len, "%s", type_buf);
    }
    (void)is_signed;
    (void)whole_struct;
    return 0;
}

static int resolve_set_lhs(cdbg_t *dbg, char *lhs, uintptr_t *addr_out,
                           size_t *size_out, bool *signed_out)
{
    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    if (lhs[0] == '&') {
        fputs("Cannot assign to an address expression\n", stderr);
        return -1;
    }

    char value_type[128];
    bool whole_struct = false;
    if (resolve_lvalue(dbg, lhs, addr_out, size_out, signed_out, value_type,
                       sizeof(value_type), &whole_struct) != 0) {
        return -1;
    }
    if (whole_struct) {
        fputs("Cannot assign to a struct value\n", stderr);
        return -1;
    }
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

    for (char *eq = args; *eq != '\0'; eq++) {
        if (*eq != '=') {
            continue;
        }
        if (eq > args && strchr("<>!", eq[-1]) != NULL) {
            continue;
        }
        if (eq[1] == '=') {
            continue;
        }
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

static int cmd_set_language(cdbg_t *dbg, char *args)
{
    args = trim_space(args);
    cdbg_language_t lang;
    if (cdbg_language_parse(args, &lang) != 0) {
        fprintf(stderr, "Unknown language: %s\n", args);
        print_language_usage();
        return -1;
    }

    dbg->language = lang;
    printf("The current source language is \"%s\".\n", cdbg_language_name(lang));
    return 0;
}

static int cmd_set_print(cdbg_t *dbg, char *args)
{
    args = trim_space(args);
    if (strncmp(args, "pretty", 6) != 0) {
        fprintf(stderr, "Unknown print option: %s\n", args);
        fputs("Usage: set print pretty on|off\n", stderr);
        return -1;
    }

    const char *value = trim_space(args + 6);
    if (strcmp(value, "on") == 0) {
        dbg->print_pretty = true;
        puts("Print pretty printing is on.");
        return 0;
    }
    if (strcmp(value, "off") == 0) {
        dbg->print_pretty = false;
        puts("Print pretty printing is off.");
        return 0;
    }

    fputs("Usage: set print pretty on|off\n", stderr);
    return -1;
}

static int cmd_set_malloc_log(cdbg_t *dbg, char *args)
{
    args = trim_space(args);
    if (strcmp(args, "on") == 0) {
        dbg->malloc_stack_logging = true;
        puts("Malloc stack logging is on. Takes effect on the next 'run'.");
        return 0;
    }
    if (strcmp(args, "off") == 0) {
        dbg->malloc_stack_logging = false;
        puts("Malloc stack logging is off.");
        return 0;
    }

    fputs("Usage: set malloc-log on|off\n", stderr);
    return -1;
}

static int cmd_set(cdbg_t *dbg, char *args)
{
    if (args == NULL) {
        fputs("Usage: set <var> <expr> | set print pretty on|off | "
              "set language <name> | set malloc-log on|off\n", stderr);
        return -1;
    }

    char work[CDBG_MAX_CMD];
    snprintf(work, sizeof(work), "%s", args);
    char *trimmed = trim_space(work);
    if (strncmp(trimmed, "print ", 6) == 0) {
        return cmd_set_print(dbg, trimmed + 6);
    }
    if (strncmp(trimmed, "language ", 9) == 0) {
        return cmd_set_language(dbg, trimmed + 9);
    }
    if (strncmp(trimmed, "malloc-log ", 11) == 0) {
        return cmd_set_malloc_log(dbg, trimmed + 11);
    }

    char *lhs = NULL;
    char *rhs = NULL;
    if (split_assignment(trimmed, &lhs, &rhs) != 0) {
        fputs("Usage: set <var> <expr> | set print pretty on|off | "
              "set language <name> | set malloc-log on|off\n", stderr);
        return -1;
    }

    if (lhs[0] == '&') {
        fputs("Cannot assign to an address expression\n", stderr);
        return -1;
    }

    if (lhs[0] == '$') {
        const char *reg_name = lhs + 1;
        if (cdbg_language_check_expr(dbg) != 0) {
            return -1;
        }
        cdbg_expr_result_t reg_result = {0};
        if (cdbg_expr_eval(dbg, rhs, &reg_result) != 0) {
            fprintf(stderr, "Invalid expression: %s\n", rhs);
            return -1;
        }
        if (reg_result.is_address) {
            fputs("Cannot assign an address expression\n", stderr);
            return -1;
        }
        if (cdbg_refresh_regs(dbg) != 0) {
            return -1;
        }
        if (cdbg_regs_set_by_name(dbg->pid, &dbg->regs, reg_name,
                                   reg_result.value, reg_result.is_float,
                                   reg_result.fvalue) != 0) {
            fprintf(stderr, "Unknown register: %s\n", reg_name);
            return -1;
        }
        if (reg_result.is_float) {
            printf("$%s = 0x%016llx  (%.17g)\n", reg_name,
                   (unsigned long long)reg_result.value, reg_result.fvalue);
        } else {
            uint64_t readback = 0;
            if (cdbg_regs_get_by_name(&dbg->regs, reg_name, &readback) == 0) {
                printf("$%s = 0x%016llx\n", reg_name, (unsigned long long)readback);
            }
        }
        return 0;
    }

    if (cdbg_language_check_expr(dbg) != 0) {
        return -1;
    }

    cdbg_expr_result_t result = {0};
    if (cdbg_expr_eval(dbg, rhs, &result) != 0) {
        fprintf(stderr, "Invalid expression: %s\n", rhs);
        return -1;
    }
    if (result.is_address) {
        fputs("Cannot assign an address expression\n", stderr);
        return -1;
    }
    uint64_t value = result.value;

    uintptr_t addr = 0;
    size_t size = sizeof(uint64_t);
    bool is_signed = false;
    char label_buf[256];
    snprintf(label_buf, sizeof(label_buf), "%s", lhs);
    const char *label = label_buf;

    if (resolve_set_lhs(dbg, lhs, &addr, &size, &is_signed) != 0) {
        return -1;
    }

    if (write_scalar_value(dbg->pid, addr, size, value) != 0) {
        return -1;
    }

    uint64_t written = 0;
    if (read_scalar_value(dbg->pid, addr, size, &written) == 0) {
        print_scalar_result(label, written, size, is_signed, false);
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

static int cmd_run(cdbg_t *dbg, char *args)
{
    if (args != NULL) {
        args = trim_space(args);
    }

    if (args != NULL && args[0] != '\0') {
        char line[CDBG_MAX_PATH * 2];
        char storage[CDBG_MAX_RUN_ARGS][CDBG_MAX_PATH];
        char *argv_ptrs[CDBG_MAX_RUN_ARGS + 1];

        snprintf(line, sizeof(line), "%s", args);
        size_t argc = 0;
        for (char *tok = strtok(line, " \t"); tok != NULL;
             tok = strtok(NULL, " \t")) {
            if (argc >= CDBG_MAX_RUN_ARGS) {
                fputs("Too many run arguments\n", stderr);
                return -1;
            }
            if (argc == 0) {
                char resolved[PATH_MAX];
                if (cdbg_resolve_program(tok, resolved, sizeof(resolved)) != 0) {
                    fprintf(stderr, "Invalid program: %s\n", tok);
                    return -1;
                }
                snprintf(storage[argc], sizeof(storage[argc]), "%s", resolved);
            } else {
                snprintf(storage[argc], sizeof(storage[argc]), "%s", tok);
            }
            argv_ptrs[argc] = storage[argc];
            argc++;
        }
        argv_ptrs[argc] = NULL;
        if (argc == 0) {
            fputs("Usage: run <program> [args...]\n", stderr);
            return -1;
        }
        if (cdbg_run(dbg, argv_ptrs) != 0) {
            return -1;
        }
    } else if (cdbg_run(dbg, NULL) != 0) {
        return -1;
    }

    return 0;
}

static int cmd_show_breakpoints(const cdbg_t *dbg)
{
    if (dbg->breakpoint_count == 0) {
        puts("No breakpoints.");
        return 0;
    }

    printf("%-4s %-4s %-18s  %s\n", "Num", "Enb", "Address", "Location");
    for (size_t i = 0; i < dbg->breakpoint_count; i++) {
        const cdbg_breakpoint_t *bp = &dbg->breakpoints[i];
        char location[CDBG_LINENO_MAX_FILE + 32] = "<unknown>";
        char file[CDBG_LINENO_MAX_FILE];
        uint32_t line = 0;

        if (cdbg_lineno_line_at_pc(&dbg->lineno, bp->addr, file, sizeof(file),
                                   &line) == 0) {
            snprintf(location, sizeof(location), "%s:%u", file, line);
        } else {
            uintptr_t offset = 0;
            const cdbg_sym_entry_t *sym =
                lookup_symbol_for_pc(&dbg->syms, bp->addr, &offset);
            if (sym != NULL) {
                if (offset == 0) {
                    snprintf(location, sizeof(location), "%s",
                             display_sym_name(sym));
                } else {
                    snprintf(location, sizeof(location), "%s+0x%lx",
                             display_sym_name(sym), (unsigned long)offset);
                }
            }
        }

        printf("%-4zu %-4s 0x%016lx  %s\n", i, bp->enabled ? "y" : "n",
               (unsigned long)bp->addr, location);
    }
    return 0;
}

static int cmd_show(cdbg_t *dbg, char *args)
{
    if (args == NULL) {
        fputs("Usage: show locals|args|globals|bp\n", stderr);
        return -1;
    }

    args = trim_space(args);
    if (strcmp(args, "bp") == 0) {
        return cmd_show_breakpoints(dbg);
    }

    if (dbg->state != CDBG_STATE_STOPPED) {
        fputs("Not stopped or no process is running\n", stderr);
        return -1;
    }

    cdbg_show_scope_t scope;
    if (strcmp(args, "locals") == 0) {
        scope = CDBG_SHOW_LOCALS;
    } else if (strcmp(args, "args") == 0) {
        scope = CDBG_SHOW_ARGS;
    } else if (strcmp(args, "globals") == 0) {
        scope = CDBG_SHOW_GLOBALS;
    } else {
        fprintf(stderr, "Unknown show option: %s\n", args);
        fputs("Usage: show locals|args|globals|bp\n", stderr);
        return -1;
    }

    if (cdbg_language_check_expr(dbg) != 0) {
        return -1;
    }

    if (cdbg_refresh_regs(dbg) != 0) {
        return -1;
    }

    cdbg_show_var_t vars[CDBG_MAX_SHOW_VARS];
    size_t count = 0;
    (void)collect_show_vars(dbg, scope, vars, CDBG_MAX_SHOW_VARS, &count);

    if (count == 0) {
        puts("(none)");
        return 0;
    }

    for (size_t i = 0; i < count; i++) {
        if (print_named_variable(dbg, &vars[i].var, vars[i].addr) != 0) {
            fprintf(stderr, "Cannot print variable: %s\n", vars[i].var.name);
        }
    }
    return 0;
}

static int cmd_leaks(cdbg_t *dbg)
{
    if (dbg->pid <= 0 || dbg->state == CDBG_STATE_IDLE) {
        fputs("No process is running\n", stderr);
        return -1;
    }

    if (!dbg->malloc_stack_logging) {
        puts("Note: 'set malloc-log on' before 'run' to get allocation "
             "backtraces in the report below.");
    }

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "leaks %d 2>&1", (int)dbg->pid);

    fflush(stdout);
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen(leaks)");
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs(line, stdout);
    }

    int status = pclose(fp);
    if (status != 0) {
        fputs("Could not run the 'leaks' tool. It requires Xcode command line "
              "tools and permission to inspect this process.\n", stderr);
        return -1;
    }
    return 0;
}

typedef struct {
    const char *category;
    const char *names;
    const char *usage;
    const char *summary;
    const char *detail;
} cdbg_help_entry_t;

static const cdbg_help_entry_t k_help_entries[] = {
    {
        "General",
        "help, h",
        "help [command]",
        "List commands or show help for a specific command.",
        "Without an argument, prints a one-line summary of every command.\n"
        "With a command name, prints usage and full details.\n"
        "\n"
        "Examples:\n"
        "  help\n"
        "  help break\n"
        "  help set\n",
    },
    {
        "General",
        "quit, q",
        "quit",
        "Kill the debuggee (if running) and exit the debugger.",
        "Sends SIGKILL to the debuggee, waits for it to exit, then\n"
        "terminates the debugger session.\n"
        "Use 'kill' to terminate only the debuggee and stay in the REPL.\n",
    },
    {
        "Execution",
        "run",
        "run [program [args...]]",
        "Start or restart the debuggee. Without arguments, rerun the last program.",
        "If a process is already running it is killed before the new one starts.\n"
        "Breakpoints set before 'run' are preserved across restarts.\n"
        "\n"
        "Examples:\n"
        "  run                     Rerun the last program\n"
        "  run ./target            Run a specific program\n"
        "  run ./target arg1 arg2  Run with arguments\n",
    },
    {
        "Execution",
        "continue, c",
        "continue",
        "Resume execution until the next breakpoint or process exit.",
        "Resumes the stopped debuggee and waits for the next stop event.\n"
        "Stop events: breakpoint hit, signal received, or process exit.\n",
    },
    {
        "Execution",
        "step, s",
        "step",
        "Execute one source line, entering function calls.",
        "Steps one source line. If the line contains a function call the\n"
        "debugger enters the callee.\n"
        "Use 'next' to step over calls instead.\n"
        "Use 'si' to step one machine instruction.\n",
    },
    {
        "Execution",
        "si",
        "si",
        "Execute a single machine instruction.",
        "Useful when there is no source information (e.g. inside a library)\n"
        "or when inspecting compiler-generated code closely.\n"
        "Use 'step' / 'next' for source-level stepping.\n",
    },
    {
        "Execution",
        "next, n",
        "next",
        "Execute one source line, stepping over function calls.",
        "Steps one source line. Function calls are executed as a unit;\n"
        "the debugger does not enter the callee.\n"
        "Use 'step' to step into calls instead.\n",
    },
    {
        "Execution",
        "up",
        "up",
        "Move to the caller frame and stop there.",
        "Reads the saved frame pointer and return address from the stack\n"
        "and updates the register context to the calling frame.\n"
        "Use 'regs' or 'print' to inspect the caller's state.\n",
    },
    {
        "Execution",
        "kill",
        "kill",
        "Kill the debuggee and return to the prompt (debugger stays open).",
        "Sends SIGKILL to the debuggee and waits for it to exit.\n"
        "The debugger stays open; use 'run' to start a new session.\n"
        "Use 'quit' to also exit the debugger.\n",
    },
    {
        "Inspection",
        "regs, r",
        "regs",
        "Print all registers: general-purpose, floating-point/NEON, and SSE/x87.",
        "ARM64 registers:\n"
        "  General-purpose:  x0-x28, fp (x29), lr (x30), sp, pc, cpsr\n"
        "  NEON/FP:          v0-v31, fpsr, fpcr\n"
        "\n"
        "x86_64 registers:\n"
        "  General-purpose:  rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp,\n"
        "                    r8-r15, rip, rflags, cs, fs, gs\n"
        "  SSE:              xmm0-xmm15, mxcsr\n"
        "  x87 FPU:          st0-st7, fctrl, fstat, ftag\n",
    },
    {
        "Inspection",
        "print, p",
        "print [/fmt] <expr>",
        "Evaluate and print an expression. Formats: /d /x /o /t /c /s.",
        "Format specifiers:\n"
        "  /d   decimal (default for integers)\n"
        "  /x   hexadecimal\n"
        "  /o   octal\n"
        "  /t   binary\n"
        "  /c   character\n"
        "  /s   C string (dereference as char*)\n"
        "\n"
        "Expression examples:\n"
        "  p x              Variable\n"
        "  p/x ptr          Pointer in hex\n"
        "  p sa             Array\n"
        "  p f.a, p p->b    Struct members\n"
        "  p 3.14           Float literal\n"
        "  p x + y * 2      Arithmetic\n"
        "  p *ptr           Dereference\n"
        "  p &x             Address of\n",
    },
    {
        "Inspection",
        "show",
        "show locals|args|globals|bp",
        "Print local variables, arguments, global variables, or breakpoints.",
        "Subcommands:\n"
        "  show locals    Local variables of the current function\n"
        "  show args      Arguments of the current function\n"
        "  show globals   Global variables in the program\n"
        "  show bp        All breakpoints (same as 'show bp' in Breakpoints)\n",
    },
    {
        "Inspection",
        "x",
        "x <addr> [count]",
        "Examine memory as a hexadecimal dump (default 16 bytes).",
        "Dumps <count> bytes of memory at <addr> as hex + ASCII.\n"
        "\n"
        "Examples:\n"
        "  x 0x100003f20        16 bytes at address\n"
        "  x 0x100003f20 64     64 bytes at address\n"
        "  x &buf               Address of a variable\n",
    },
    {
        "Inspection",
        "dis",
        "dis <func|file:line|line|addr>",
        "Disassemble about 10 instructions at the given location.",
        "Location forms:\n"
        "  dis main             Function name\n"
        "  dis target.c:42     File and line number\n"
        "  dis 42               Line number (single source file)\n"
        "  dis 0x100003f20      Absolute address\n",
    },
    {
        "Inspection",
        "list, l",
        "list [line|file:line|function]",
        "Show source code around the current or specified location.",
        "Displays 10 lines centred on the target location.\n"
        "\n"
        "Location forms:\n"
        "  list                 Current instruction\n"
        "  list 42              Line 42 in the current file\n"
        "  list target.c:42     Line 42 in a specific file\n"
        "  list main            Start of function 'main'\n",
    },
    {
        "Inspection",
        "lines",
        "lines [file]",
        "List line number to address mappings.",
        "Prints DWARF line-number entries (address → file:line).\n"
        "Useful for finding the address of a specific source line.\n"
        "\n"
        "Examples:\n"
        "  lines              All mappings\n"
        "  lines target.c     Only mappings for target.c\n",
    },
    {
        "Inspection",
        "lists",
        "lists [file]",
        "List source line to address mappings.",
        "Like 'lines' but grouped by source line number.\n"
        "\n"
        "Examples:\n"
        "  lists              All mappings\n"
        "  lists target.c     Only mappings for target.c\n",
    },
    {
        "Inspection",
        "syms, sym",
        "syms [name]",
        "List loaded symbols, optionally filtered by name.",
        "Prints address and name for every loaded symbol.\n"
        "The optional argument is a substring filter.\n"
        "\n"
        "Examples:\n"
        "  syms               All symbols\n"
        "  syms main          Symbols whose name contains \"main\"\n",
    },
    {
        "Inspection",
        "tb",
        "tb",
        "Show a backtrace of the current call stack.",
        "Prints each frame as: #n  <address>  <function> (if known)\n"
        "Unwinding follows saved FP/LR chains on the stack.\n",
    },
    {
        "Inspection",
        "leaks",
        "leaks",
        "Run the macOS 'leaks' tool against the debuggee to report unreachable "
        "malloc blocks.",
        "Runs 'leaks <pid>' and prints the output.\n"
        "For allocation backtraces, enable malloc stack logging before running:\n"
        "\n"
        "  set malloc-log on\n"
        "  run\n"
        "  (trigger the leak)\n"
        "  leaks\n",
    },
    {
        "Breakpoints",
        "show bp",
        "show bp",
        "List breakpoints with number, enabled state, address, and location.",
        "Each line shows:\n"
        "  #n   breakpoint number (used with 'del')\n"
        "  [+]  enabled   [-]  disabled\n"
        "  address\n"
        "  source location (file:line, if known)\n",
    },
    {
        "Breakpoints",
        "del, delete",
        "del <n> [n...] | del all",
        "Delete one or more breakpoints by number.",
        "Examples:\n"
        "  del 1          Delete breakpoint #1\n"
        "  del 1 2 3      Delete multiple breakpoints\n"
        "  del all        Delete all breakpoints\n",
    },
    {
        "Breakpoints",
        "break, b",
        "break <addr|name|file:line|line>",
        "Set a breakpoint at an address, symbol, or source line.",
        "Location forms:\n"
        "  break main           Function name\n"
        "  break target.c:42    File and line number\n"
        "  break 42             Line number (single source file)\n"
        "  break 0x100003f20    Absolute address\n",
    },
    {
        "Settings",
        "set",
        "set <var> = <expr>  |  set $<reg> = <expr>",
        "Assign a value to a variable, struct member, array element, or register.",
        "Variable examples:\n"
        "  set x = 42\n"
        "  set arr[0] = 1\n"
        "  set s.field = 100\n"
        "  set p->n = 0\n"
        "\n"
        "Register examples (x86_64):\n"
        "  set $rax = 0x10              Integer GPR\n"
        "  set $xmm0 = 3.14            SSE register (float)\n"
        "  set $xmm0 = 0x3ff0000000000000  SSE register (bit pattern = 1.0)\n"
        "  set $st0 = 1.5              x87 FPU register\n"
        "\n"
        "Register examples (ARM64):\n"
        "  set $x0 = 0xff              Integer GPR\n"
        "  set $v0 = 0x3ff0000000000000  NEON register (lower 64 bits)\n"
        "  set $fpsr = 0               FP status register\n",
    },
    {
        "Settings",
        "set print",
        "set print pretty on|off",
        "Enable or disable multi-line struct and array formatting.",
        "  set print pretty on    Indent structs and arrays across multiple lines\n"
        "  set print pretty off   Single-line output (default)\n",
    },
    {
        "Settings",
        "set language",
        "set language <name>",
        "Set the expression language (c, c++, auto, fortran, ...).",
        "Affects how expressions in 'print' and 'set' are parsed.\n"
        "Supported: c, c++, fortran, auto\n"
        "'auto' selects based on the current source file extension.\n",
    },
    {
        "Settings",
        "set malloc-log",
        "set malloc-log on|off",
        "Enable MallocStackLogging for the debuggee so 'leaks' can show "
        "allocation backtraces. Takes effect on the next 'run'.",
        "Sets the MallocStackLogging environment variable for the next 'run'.\n"
        "This lets 'leaks' report the call stack at each allocation.\n"
        "\n"
        "  set malloc-log on     Record allocation backtraces\n"
        "  set malloc-log off    Disable (default)\n",
    },
};

static bool help_name_matches(const cdbg_help_entry_t *entry, const char *name)
{
    if (entry == NULL || name == NULL || name[0] == '\0') {
        return false;
    }

    char names_copy[128];
    snprintf(names_copy, sizeof(names_copy), "%s", entry->names);
    for (char *token = strtok(names_copy, ","); token != NULL;
         token = strtok(NULL, ",")) {
        while (*token == ' ') {
            token++;
        }
        char *end = token + strlen(token);
        while (end > token && end[-1] == ' ') {
            *--end = '\0';
        }
        if (str_ieq(token, name)) {
            return true;
        }
    }

    size_t name_len = strlen(name);
    if (strlen(entry->usage) >= name_len &&
        strncmp(entry->usage, name, name_len) == 0) {
        const char next = entry->usage[name_len];
        return next == '\0' || next == ' ' || next == '<';
    }

    return false;
}

static void print_help_entry(const cdbg_help_entry_t *entry)
{
    printf("  %-22s  %s\n", entry->names, entry->summary);
}

static void print_help_entry_detail(const cdbg_help_entry_t *entry)
{
    printf("%s\n", entry->names);
    printf("  Usage: %s\n", entry->usage);
    printf("  %s\n", entry->summary);
    if (entry->detail != NULL) {
        putchar('\n');
        /* Indent each line of the detail block by two spaces. */
        const char *p = entry->detail;
        while (*p != '\0') {
            const char *nl = strchr(p, '\n');
            size_t len = (nl != NULL) ? (size_t)(nl - p) : strlen(p);
            if (len > 0) {
                printf("  %.*s\n", (int)len, p);
            } else {
                putchar('\n');
            }
            p = (nl != NULL) ? nl + 1 : p + len;
        }
    }
}

static void print_help_all(void)
{
    puts("Available commands (type 'help <command>' for details):");
    puts("");

    const char *category = NULL;
    for (size_t i = 0; i < sizeof(k_help_entries) / sizeof(k_help_entries[0]); i++) {
        if (category == NULL || strcmp(category, k_help_entries[i].category) != 0) {
            if (category != NULL) {
                putchar('\n');
            }
            category = k_help_entries[i].category;
            printf("%s:\n", category);
        }
        print_help_entry(&k_help_entries[i]);
    }

    puts("");
    puts("Expression examples:");
    puts("  p x                  Print variable x");
    puts("  p/x ptr              Print pointer in hex");
    puts("  p sa                 Print an array");
    puts("  p f.a, p p->b        Print struct members");
    puts("  p 3.14               Print float literal");
    puts("  set x = 1            Assign to a variable");
    puts("  set sa[1].b = 100    Assign to an array element member");
    puts("  set $rax = 0x10      Assign to an integer register");
    puts("  set $xmm0 = 3.14     Assign float to SSE register");
}

static int cmd_help(char *args)
{
    if (args == NULL) {
        print_help_all();
        return 0;
    }

    args = trim_space(args);
    if (args[0] == '\0') {
        print_help_all();
        return 0;
    }

    for (size_t i = 0; i < sizeof(k_help_entries) / sizeof(k_help_entries[0]); i++) {
        if (help_name_matches(&k_help_entries[i], args)) {
            print_help_entry_detail(&k_help_entries[i]);
            return 0;
        }
    }

    fprintf(stderr, "No help available for: %s\n", args);
    fputs("Try 'help' for a list of commands.\n", stderr);
    return -1;
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

static int resolve_dis_target(cdbg_t *dbg, const char *target, uintptr_t *addr_out,
                              char *label_out, size_t label_len)
{
    char label_buf[CDBG_LINENO_MAX_FILE + 32];
    uint64_t parsed = 0;

    char *colon = strrchr((char *)target, ':');
    if (colon != NULL && colon[1] != '\0') {
        char file_part[CDBG_LINENO_MAX_FILE];
        size_t file_len = (size_t)(colon - target);
        if (file_len == 0 || file_len >= sizeof(file_part)) {
            fputs("Usage: dis <function|file:line|line>\n", stderr);
            return -1;
        }
        memcpy(file_part, target, file_len);
        file_part[file_len] = '\0';

        uint64_t line_no = 0;
        if (parse_u64(colon + 1, &line_no) != 0 || line_no == 0) {
            fputs("Usage: dis <function|file:line|line>\n", stderr);
            return -1;
        }

        if (resolve_break_line(dbg, file_part, (uint32_t)line_no, addr_out,
                               label_buf, sizeof(label_buf)) != 0) {
            return -1;
        }
        snprintf(label_out, label_len, "%s", label_buf);
        return 0;
    }

    if (parse_u64(target, &parsed) == 0) {
        if (parsed == 0) {
            fputs("Usage: dis <function|file:line|line>\n", stderr);
            return -1;
        }
        if (resolve_break_line(dbg, NULL, (uint32_t)parsed, addr_out,
                               label_buf, sizeof(label_buf)) == 0) {
            snprintf(label_out, label_len, "%s", label_buf);
            return 0;
        }
        fprintf(stderr, "Line %llu is ambiguous; use file:line\n",
                (unsigned long long)parsed);
        return -1;
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

    *addr_out = cdbg_syms_runtime_addr(&dbg->syms, sym->address);
    const char *name = sym->name;
    if (name[0] == '_' && name[1] != '\0') {
        name++;
    }
    snprintf(label_out, label_len, "%s", name);
    return 0;
}

static int cmd_dis(cdbg_t *dbg, const char *target)
{
    if (target == NULL) {
        fputs("Usage: dis <function|file:line|line>\n", stderr);
        return -1;
    }

    char work[CDBG_MAX_PATH + 64];
    snprintf(work, sizeof(work), "%s", target);
    const char *trimmed = trim_space(work);
    if (trimmed[0] == '\0') {
        fputs("Usage: dis <function|file:line|line>\n", stderr);
        return -1;
    }

    if (dbg->executable_path[0] == '\0') {
        fputs("No debug info loaded; use run first\n", stderr);
        return -1;
    }

    uintptr_t addr = 0;
    char label[256];
    if (resolve_dis_target(dbg, trimmed, &addr, label, sizeof(label)) != 0) {
        return -1;
    }

    print_disassembly_range(dbg, addr, CDBG_DISASM_DEFAULT_COUNT, label);
    return 0;
}

static int cmd_lines(cdbg_t *dbg, const char *file_filter)
{
    cdbg_lineno_print_list(&dbg->lineno, file_filter);
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

static int delete_breakpoint_at(cdbg_t *dbg, size_t index)
{
    if (index >= dbg->breakpoint_count) {
        fprintf(stderr, "No breakpoint number %zu\n", index);
        return -1;
    }

    cdbg_breakpoint_t *bp = &dbg->breakpoints[index];
    if (dbg->pid > 0 && dbg->state != CDBG_STATE_IDLE) {
        if (cdbg_bp_disable(bp, dbg->pid) != 0) {
            return -1;
        }
    } else {
        bp->enabled = false;
    }

    for (size_t i = index + 1; i < dbg->breakpoint_count; i++) {
        dbg->breakpoints[i - 1] = dbg->breakpoints[i];
    }
    dbg->breakpoint_count--;
    memset(&dbg->breakpoints[dbg->breakpoint_count], 0, sizeof(cdbg_breakpoint_t));
    return 0;
}

static int cmd_del(cdbg_t *dbg, char *args)
{
    if (dbg->breakpoint_count == 0) {
        puts("No breakpoints.");
        return 0;
    }

    if (args == NULL) {
        fputs("Usage: del <n> [n...] | del all\n", stderr);
        return -1;
    }

    args = trim_space(args);
    if (args[0] == '\0') {
        fputs("Usage: del <n> [n...] | del all\n", stderr);
        return -1;
    }

    if (strcmp(args, "all") == 0) {
        while (dbg->breakpoint_count > 0) {
            if (delete_breakpoint_at(dbg, dbg->breakpoint_count - 1) != 0) {
                return -1;
            }
        }
        puts("All breakpoints deleted.");
        return 0;
    }

    size_t indices[CDBG_MAX_BREAKPOINTS];
    size_t index_count = 0;
    char work[CDBG_MAX_CMD];
    snprintf(work, sizeof(work), "%s", args);

    for (char *token = strtok(work, " \t"); token != NULL;
         token = strtok(NULL, " \t")) {
        uint64_t number = 0;
        if (parse_u64(token, &number) != 0) {
            fprintf(stderr, "Invalid breakpoint number: %s\n", token);
            return -1;
        }
        if (number >= dbg->breakpoint_count) {
            fprintf(stderr, "No breakpoint number %llu\n",
                    (unsigned long long)number);
            return -1;
        }

        bool duplicate = false;
        for (size_t i = 0; i < index_count; i++) {
            if (indices[i] == (size_t)number) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            indices[index_count++] = (size_t)number;
        }
    }

    for (size_t i = 0; i < index_count; i++) {
        for (size_t j = i + 1; j < index_count; j++) {
            if (indices[j] > indices[i]) {
                size_t tmp = indices[i];
                indices[i] = indices[j];
                indices[j] = tmp;
            }
        }
    }

    for (size_t i = 0; i < index_count; i++) {
        printf("Deleting breakpoint %zu\n", indices[i]);
        if (delete_breakpoint_at(dbg, indices[i]) != 0) {
            return -1;
        }
    }
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

static void cmd_print_from_repl(cdbg_t *dbg, const char *cmd, char *rest)
{
    char expr[CDBG_MAX_CMD];
    const char *fmt = NULL;

    if (strncmp(cmd, "p/", 2) == 0) {
        fmt = cmd + 2;
    } else if (strncmp(cmd, "print/", 6) == 0) {
        fmt = cmd + 6;
    }

    if (fmt != NULL) {
        if (rest != NULL && rest[0] != '\0') {
            snprintf(expr, sizeof(expr), "/%s %s", fmt, rest);
        } else {
            snprintf(expr, sizeof(expr), "/%s", fmt);
        }
    } else if (rest != NULL) {
        snprintf(expr, sizeof(expr), "%s", rest);
    } else {
        expr[0] = '\0';
    }

    (void)cmd_print(dbg, expr);
}

int cdbg_repl(cdbg_t *dbg)
{
    char line[CDBG_MAX_CMD];

    g_sigint_dbg = dbg;
    signal(SIGINT, sigint_handler);

    puts("Type 'help' for available commands.");

    for (;;) {
        fputs("cdbg> ", stdout);
        fflush(stdout);
        if (fgets(line, sizeof(line), stdin) == NULL) {
            if (ferror(stdin) && errno == EINTR) {
                clearerr(stdin);
                putchar('\n');
                continue;
            }
            break;
        }
        char *newline = strchr(line, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        char *cmd = strtok(line, " \t");
        if (cmd == NULL || cmd[0] == '\0') {
            continue;
        }

        if (strcmp(cmd, "help") == 0 || strcmp(cmd, "h") == 0) {
            char *args = strtok(NULL, "\n");
            (void)cmd_help(args);
        } else if (strcmp(cmd, "run") == 0) {
            char *args = strtok(NULL, "\n");
            (void)cmd_run(dbg, args);
        } else if (strcmp(cmd, "continue") == 0 || strcmp(cmd, "c") == 0) {
            if (dbg->state == CDBG_STATE_IDLE) {
                fputs("No process is running\n", stderr);
                continue;
            }
            if (cdbg_continue(dbg) != 0) {
                return -1;
            }
            if (dbg->state == CDBG_STATE_IDLE) {
                report_process_exit(dbg);
                continue;
            }
            if (cdbg_wait(dbg) != 0) {
                if (dbg->state == CDBG_STATE_IDLE) {
                    report_process_exit(dbg);
                    continue;
                }
                return -1;
            }
            if (dbg->state == CDBG_STATE_STOPPED) {
                (void)report_stop(dbg);
            } else if (dbg->state == CDBG_STATE_IDLE) {
                report_process_exit(dbg);
            }
        } else if (strcmp(cmd, "step") == 0 || strcmp(cmd, "s") == 0) {
            if (dbg->state == CDBG_STATE_IDLE) {
                fputs("No process is running\n", stderr);
                continue;
            }
            if (cdbg_step_next_line(dbg) != 0 && dbg->state != CDBG_STATE_IDLE) {
                return -1;
            }
            if (dbg->state == CDBG_STATE_IDLE) {
                report_process_exit(dbg);
            }
        } else if (strcmp(cmd, "si") == 0) {
            if (dbg->state == CDBG_STATE_IDLE) {
                fputs("No process is running\n", stderr);
                continue;
            }
            if (cdbg_single_step(dbg) != 0) {
                return -1;
            }
            if (cdbg_wait(dbg) != 0) {
                if (dbg->state == CDBG_STATE_IDLE) {
                    report_process_exit(dbg);
                    continue;
                }
                return -1;
            }
            if (dbg->state == CDBG_STATE_STOPPED) {
                (void)report_stop(dbg);
            } else if (dbg->state == CDBG_STATE_IDLE) {
                report_process_exit(dbg);
            }
        } else if (strcmp(cmd, "next") == 0 || strcmp(cmd, "n") == 0) {
            if (dbg->state == CDBG_STATE_IDLE) {
                fputs("No process is running\n", stderr);
                continue;
            }
            if (cdbg_next_source_line(dbg) != 0 && dbg->state != CDBG_STATE_IDLE) {
                return -1;
            }
            if (dbg->state == CDBG_STATE_IDLE) {
                report_process_exit(dbg);
            }
        } else if (strcmp(cmd, "up") == 0) {
            (void)cdbg_frame_up(dbg);
        } else if (strcmp(cmd, "regs") == 0 || strcmp(cmd, "r") == 0) {
            if (cdbg_refresh_regs(dbg) != 0) {
                return -1;
            }
            cdbg_print_regs(dbg);
        } else if (strcmp(cmd, "print") == 0 || strcmp(cmd, "p") == 0 ||
                   strncmp(cmd, "p/", 2) == 0 || strncmp(cmd, "print/", 6) == 0) {
            char *rest = strtok(NULL, "\n");
            cmd_print_from_repl(dbg, cmd, rest);
        } else if (strcmp(cmd, "set") == 0) {
            char *args = strtok(NULL, "\n");
            (void)cmd_set(dbg, args);
        } else if (strcmp(cmd, "show") == 0) {
            char *args = strtok(NULL, "\n");
            (void)cmd_show(dbg, args);
        } else if (strcmp(cmd, "tb") == 0) {
            (void)cmd_backtrace(dbg);
        } else if (strcmp(cmd, "leaks") == 0) {
            (void)cmd_leaks(dbg);
        } else if (strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0) {
            char *addr_text = strtok(NULL, " \t");
            if (addr_text == NULL) {
                fputs("Usage: break <addr|name|file:line|line>\n", stderr);
            } else {
                (void)cmd_break(dbg, addr_text);
            }
        } else if (strcmp(cmd, "del") == 0 || strcmp(cmd, "delete") == 0) {
            char *args = strtok(NULL, "\n");
            (void)cmd_del(dbg, args);
        } else if (strcmp(cmd, "dis") == 0) {
            char *target = strtok(NULL, "\n");
            (void)cmd_dis(dbg, target);
        } else if (strcmp(cmd, "list") == 0 || strcmp(cmd, "l") == 0) {
            char *target = strtok(NULL, "\n");
            (void)cmd_list(dbg, target);
        } else if (strcmp(cmd, "lines") == 0) {
            char *file_filter = strtok(NULL, " \t");
            (void)cmd_lines(dbg, file_filter);
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
        } else if (strcmp(cmd, "kill") == 0) {
            if (dbg->pid <= 0 || dbg->state == CDBG_STATE_IDLE) {
                fputs("No process is running.\n", stderr);
            } else {
                pid_t killed_pid = dbg->pid;
                (void)stop_debuggee(dbg);
                printf("Process %d killed.\n", killed_pid);
            }
        } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "q") == 0) {
            (void)stop_debuggee(dbg);
            cdbg_lineno_free(&dbg->lineno);
            cdbg_syms_free(&dbg->syms);
            return 0;
        } else {
            printf("Unknown command: %s\n", cmd);
        }
    }

    return 0;
}
