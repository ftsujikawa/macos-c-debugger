#ifndef CDBG_WATCHPOINT_H
#define CDBG_WATCHPOINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* macOS exposes 4 usable hardware watchpoint registers on both
 * arm64 (DBGWVR/DBGWCR) and x86_64 (DR0-DR3), so a watchpoint's
 * index in cdbg_t::watchpoints[] doubles as its hardware slot. */
#define CDBG_WP_MAX_HW 4

typedef struct cdbg_watchpoint {
    bool     enabled;
    uintptr_t addr;
    size_t   size;
    uint64_t old_value;
    char     expr[128];
    char     type[64];
} cdbg_watchpoint_t;

/* Programs hardware watchpoint register `slot` to trap on writes to
 * [addr, addr+size). Returns -1 if size/addr cannot be represented
 * by the architecture's debug registers (caller should retry with a
 * smaller size). */
int cdbg_wp_hw_install(pid_t pid, int slot, uintptr_t addr, size_t size);
int cdbg_wp_hw_uninstall(pid_t pid, int slot);

#endif /* CDBG_WATCHPOINT_H */
