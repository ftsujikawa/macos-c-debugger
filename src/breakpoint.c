#include "breakpoint.h"

#include "memory.h"

#include <stdio.h>

#if defined(__aarch64__)
#define CDBG_TRAP_BYTE 0xd4  /* BRK #0 */
#elif defined(__x86_64__)
#define CDBG_TRAP_BYTE 0xcc  /* INT3 */
#else
#error "Unsupported architecture"
#endif

int cdbg_bp_enable(cdbg_breakpoint_t *bp, pid_t pid, uintptr_t addr)
{
    uint8_t byte = 0;

    if (cdbg_mem_read(pid, addr, &byte, 1) != 0) {
        return -1;
    }

    bp->addr = addr;
    bp->saved_byte = byte;
    bp->enabled = true;

    uint8_t trap = CDBG_TRAP_BYTE;
    if (cdbg_mem_write(pid, addr, &trap, 1) != 0) {
        bp->enabled = false;
        return -1;
    }

    return 0;
}

int cdbg_bp_disable(cdbg_breakpoint_t *bp, pid_t pid)
{
    if (!bp->enabled) {
        return 0;
    }

    if (cdbg_mem_write(pid, bp->addr, &bp->saved_byte, 1) != 0) {
        return -1;
    }

    bp->enabled = false;
    return 0;
}

bool cdbg_bp_matches_pc(uintptr_t pc, const cdbg_breakpoint_t *bp)
{
    if (!bp->enabled) {
        return false;
    }
#if defined(__x86_64__)
    return bp->addr + 1 == pc;
#else
    return bp->addr == pc;
#endif
}

bool cdbg_bp_is_trap(uintptr_t pc, const cdbg_breakpoint_t *bps, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (cdbg_bp_matches_pc(pc, &bps[i])) {
            return true;
        }
    }
    return false;
}
