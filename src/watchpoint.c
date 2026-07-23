#include "watchpoint.h"

#include <mach/mach.h>
#include <stdio.h>

static mach_port_t task_for_traced_pid(pid_t pid)
{
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %s (%d)\n", mach_error_string(kr), kr);
        return MACH_PORT_NULL;
    }
    return task;
}

/* Hardware debug registers (DR0-DR3/DR7 on x86_64, DBGWVR/DBGWCR on arm64)
 * are per-thread machine state, and pthread_create() gives each new thread
 * its own zeroed set. A watchpoint programmed onto only one thread (e.g.
 * the process's first thread) never traps on accesses made by any other
 * thread. Apply `fn` (installing or clearing one hardware slot) to every
 * thread currently in the task so a watchpoint catches accesses regardless
 * of which thread performs them. Threads created after this call still
 * won't have the slot set; callers re-apply active watchpoints whenever
 * the debugger regains control to catch up on any that appeared since.
 * Returns -1 if the task has no threads or `fn` failed on any of them. */
static int for_each_thread(pid_t pid, int (*fn)(thread_act_t, void *), void *ctx)
{
    mach_port_t task = task_for_traced_pid(pid);
    if (task == MACH_PORT_NULL) {
        return -1;
    }

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t kr = task_threads(task, &threads, &count);
    mach_port_deallocate(mach_task_self(), task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_threads failed: %s (%d)\n", mach_error_string(kr), kr);
        return -1;
    }

    int rc = count > 0 ? 0 : -1;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (fn(threads[i], ctx) != 0) {
            rc = -1;
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_act_t));
    return rc;
}

#if defined(__aarch64__)
#include <mach/arm/thread_status.h>

/* DBGWCRn_EL1 field layout (ARMv8 Architecture Reference Manual). */
#define WCR_E          (1ULL << 0)          /* Watchpoint enable          */
#define WCR_PAC_EL0EL1 (0x3ULL << 1)        /* Trap at EL0 and EL1        */
#define WCR_LSC_STORE  (0x2ULL << 3)        /* Trap on stores (writes)    */
#define WCR_LSC_ANY    (0x3ULL << 3)        /* Trap on loads or stores    */
#define WCR_BAS_SHIFT  5                    /* Byte address select        */

struct arm_wp_ctx {
    int slot;
    uint64_t wvr;
    uint64_t wcr;
};

static int install_arm_thread(thread_act_t thread, void *ctx_)
{
    const struct arm_wp_ctx *ctx = ctx_;
    arm_debug_state64_t state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    if (thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state, &count) !=
        KERN_SUCCESS) {
        return -1;
    }

    state.__wvr[ctx->slot] = ctx->wvr;
    state.__wcr[ctx->slot] = ctx->wcr;

    return thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state,
                            ARM_DEBUG_STATE64_COUNT) == KERN_SUCCESS ? 0 : -1;
}

static int uninstall_arm_thread(thread_act_t thread, void *ctx_)
{
    int slot = *(int *)ctx_;
    arm_debug_state64_t state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    if (thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state, &count) !=
        KERN_SUCCESS) {
        return -1;
    }

    state.__wvr[slot] = 0;
    state.__wcr[slot] = 0;

    return thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state,
                            ARM_DEBUG_STATE64_COUNT) == KERN_SUCCESS ? 0 : -1;
}

int cdbg_wp_hw_install(pid_t pid, int slot, uintptr_t addr, size_t size,
                        cdbg_wp_mode_t mode)
{
    if (slot < 0 || slot >= CDBG_WP_MAX_HW) {
        return -1;
    }
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        return -1;
    }

    unsigned offset = (unsigned)(addr & 0x7);
    if (offset + size > 8) {
        /* Crosses an 8-byte aligned window; not representable via BAS. */
        return -1;
    }

    uint64_t lsc = (mode == CDBG_WP_ACCESS) ? WCR_LSC_ANY : WCR_LSC_STORE;
    uint64_t bas = (uint64_t)(((1u << size) - 1u) << offset);
    struct arm_wp_ctx ctx = {
        .slot = slot,
        .wvr = (uint64_t)(addr & ~0x7ULL),
        .wcr = WCR_E | WCR_PAC_EL0EL1 | lsc | (bas << WCR_BAS_SHIFT),
    };

    return for_each_thread(pid, install_arm_thread, &ctx);
}

int cdbg_wp_hw_uninstall(pid_t pid, int slot)
{
    if (slot < 0 || slot >= CDBG_WP_MAX_HW) {
        return -1;
    }

    int slot_copy = slot;
    return for_each_thread(pid, uninstall_arm_thread, &slot_copy);
}

#elif defined(__x86_64__)
#include <mach/i386/thread_status.h>

static uint64_t *dr_slot_ptr(x86_debug_state64_t *state, int slot)
{
    switch (slot) {
        case 0: return &state->__dr0;
        case 1: return &state->__dr1;
        case 2: return &state->__dr2;
        case 3: return &state->__dr3;
        default: return NULL;
    }
}

struct x86_wp_ctx {
    int slot;
    uintptr_t addr;
    uint64_t len_bits;
    cdbg_wp_mode_t mode;
};

static int install_x86_thread(thread_act_t thread, void *ctx_)
{
    const struct x86_wp_ctx *ctx = ctx_;
    x86_debug_state64_t state;
    mach_msg_type_number_t count = x86_DEBUG_STATE64_COUNT;
    if (thread_get_state(thread, x86_DEBUG_STATE64, (thread_state_t)&state, &count) !=
        KERN_SUCCESS) {
        return -1;
    }

    *dr_slot_ptr(&state, ctx->slot) = (uint64_t)ctx->addr;

    /* DR7 RW field: 0x1 = writes only, 0x3 = reads or writes. Intel has
     * no read-only mode (0x0 is instruction execution, not applicable). */
    const uint64_t rw_bits = (ctx->mode == CDBG_WP_ACCESS) ? 0x3 : 0x1;
    unsigned local_enable_bit = (unsigned)(ctx->slot * 2);
    unsigned rw_shift = 16 + (unsigned)(ctx->slot * 4);
    unsigned len_shift = 18 + (unsigned)(ctx->slot * 4);

    state.__dr7 &= ~((uint64_t)0x3 << rw_shift);
    state.__dr7 &= ~((uint64_t)0x3 << len_shift);
    state.__dr7 |= (rw_bits << rw_shift);
    state.__dr7 |= (ctx->len_bits << len_shift);
    state.__dr7 |= ((uint64_t)1 << local_enable_bit);

    return thread_set_state(thread, x86_DEBUG_STATE64, (thread_state_t)&state,
                            x86_DEBUG_STATE64_COUNT) == KERN_SUCCESS ? 0 : -1;
}

static int uninstall_x86_thread(thread_act_t thread, void *ctx_)
{
    int slot = *(int *)ctx_;
    x86_debug_state64_t state;
    mach_msg_type_number_t count = x86_DEBUG_STATE64_COUNT;
    if (thread_get_state(thread, x86_DEBUG_STATE64, (thread_state_t)&state, &count) !=
        KERN_SUCCESS) {
        return -1;
    }

    *dr_slot_ptr(&state, slot) = 0;
    unsigned local_enable_bit = (unsigned)(slot * 2);
    state.__dr7 &= ~((uint64_t)1 << local_enable_bit);

    return thread_set_state(thread, x86_DEBUG_STATE64, (thread_state_t)&state,
                            x86_DEBUG_STATE64_COUNT) == KERN_SUCCESS ? 0 : -1;
}

int cdbg_wp_hw_install(pid_t pid, int slot, uintptr_t addr, size_t size,
                        cdbg_wp_mode_t mode)
{
    if (slot < 0 || slot >= CDBG_WP_MAX_HW) {
        return -1;
    }

    uint64_t len_bits;
    switch (size) {
        case 1: len_bits = 0x0; break;
        case 2: len_bits = 0x1; break;
        case 8: len_bits = 0x2; break;
        case 4: len_bits = 0x3; break;
        default: return -1;
    }
    if ((addr & (size - 1)) != 0) {
        /* Intel debug registers require natural alignment. */
        return -1;
    }

    struct x86_wp_ctx ctx = { .slot = slot, .addr = addr, .len_bits = len_bits, .mode = mode };
    return for_each_thread(pid, install_x86_thread, &ctx);
}

int cdbg_wp_hw_uninstall(pid_t pid, int slot)
{
    if (slot < 0 || slot >= CDBG_WP_MAX_HW) {
        return -1;
    }

    int slot_copy = slot;
    return for_each_thread(pid, uninstall_x86_thread, &slot_copy);
}

#else
#error "Unsupported architecture"
#endif
