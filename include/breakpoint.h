#ifndef CDBG_BREAKPOINT_H
#define CDBG_BREAKPOINT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct cdbg_breakpoint {
    uintptr_t addr;
    uint8_t saved_byte;
    bool enabled;
} cdbg_breakpoint_t;

int cdbg_bp_enable(cdbg_breakpoint_t *bp, pid_t pid, uintptr_t addr);
int cdbg_bp_disable(cdbg_breakpoint_t *bp, pid_t pid);
bool cdbg_bp_matches_pc(uintptr_t pc, const cdbg_breakpoint_t *bp);
bool cdbg_bp_is_trap(uintptr_t pc, const cdbg_breakpoint_t *bps, size_t count);

#endif /* CDBG_BREAKPOINT_H */
