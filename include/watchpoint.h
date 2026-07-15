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

/* x86 debug registers have no read-only trap mode (only write, or
 * read-or-write), so CDBG_WP_ACCESS is used for both platforms to keep
 * `watch`'s /r flag consistent across arm64 and x86_64. */
typedef enum cdbg_wp_mode {
    CDBG_WP_WRITE  = 0, /* trap on writes only */
    CDBG_WP_ACCESS = 1, /* trap on reads or writes */
} cdbg_wp_mode_t;

typedef struct cdbg_watchpoint {
    bool     enabled;
    uintptr_t addr;
    size_t   size;
    uint64_t old_value;
    cdbg_wp_mode_t mode;
    char     expr[128];
    char     type[64];
} cdbg_watchpoint_t;

/* Programs hardware watchpoint register `slot` to trap on accesses to
 * [addr, addr+size) matching `mode`. Returns -1 if size/addr cannot be
 * represented by the architecture's debug registers (caller should retry
 * with a smaller size). */
int cdbg_wp_hw_install(pid_t pid, int slot, uintptr_t addr, size_t size,
                        cdbg_wp_mode_t mode);
int cdbg_wp_hw_uninstall(pid_t pid, int slot);

#endif /* CDBG_WATCHPOINT_H */
