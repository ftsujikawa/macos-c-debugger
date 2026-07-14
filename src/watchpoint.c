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

static thread_act_t primary_thread_for_task(mach_port_t task)
{
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t kr = task_threads(task, &threads, &count);

    if (kr != KERN_SUCCESS || count == 0) {
        fprintf(stderr, "task_threads failed: %s (%d)\n", mach_error_string(kr), kr);
        return MACH_PORT_NULL;
    }

    thread_act_t primary = threads[0];
    for (mach_msg_type_number_t i = 1; i < count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  count * sizeof(thread_act_t));

    return primary;
}

static int primary_thread_for_pid(pid_t pid, thread_act_t *thread_out)
{
    mach_port_t task = task_for_traced_pid(pid);
    if (task == MACH_PORT_NULL) {
        return -1;
    }

    thread_act_t thread = primary_thread_for_task(task);
    mach_port_deallocate(mach_task_self(), task);
    if (thread == MACH_PORT_NULL) {
        return -1;
    }

    *thread_out = thread;
    return 0;
}

#if defined(__aarch64__)
#include <mach/arm/thread_status.h>

/* DBGWCRn_EL1 field layout (ARMv8 Architecture Reference Manual). */
#define WCR_E          (1ULL << 0)          /* Watchpoint enable          */
#define WCR_PAC_EL0EL1 (0x3ULL << 1)        /* Trap at EL0 and EL1        */
#define WCR_LSC_STORE  (0x2ULL << 3)        /* Trap on stores (writes)    */
#define WCR_BAS_SHIFT  5                    /* Byte address select        */

static int get_debug_state(pid_t pid, arm_debug_state64_t *state, thread_act_t *thread_out)
{
    thread_act_t thread;
    if (primary_thread_for_pid(pid, &thread) != 0) {
        return -1;
    }

    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)state, &count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_get_state(DEBUG) failed: %s (%d)\n",
                mach_error_string(kr), kr);
        mach_port_deallocate(mach_task_self(), thread);
        return -1;
    }

    *thread_out = thread;
    return 0;
}

int cdbg_wp_hw_install(pid_t pid, int slot, uintptr_t addr, size_t size)
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

    arm_debug_state64_t state;
    thread_act_t thread;
    if (get_debug_state(pid, &state, &thread) != 0) {
        return -1;
    }

    uint64_t bas = (uint64_t)(((1u << size) - 1u) << offset);
    state.__wvr[slot] = (uint64_t)(addr & ~0x7ULL);
    state.__wcr[slot] = WCR_E | WCR_PAC_EL0EL1 | WCR_LSC_STORE | (bas << WCR_BAS_SHIFT);

    kern_return_t kr = thread_set_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)&state, ARM_DEBUG_STATE64_COUNT);
    mach_port_deallocate(mach_task_self(), thread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state(DEBUG) failed: %s (%d)\n",
                mach_error_string(kr), kr);
        return -1;
    }
    return 0;
}

int cdbg_wp_hw_uninstall(pid_t pid, int slot)
{
    if (slot < 0 || slot >= CDBG_WP_MAX_HW) {
        return -1;
    }

    arm_debug_state64_t state;
    thread_act_t thread;
    if (get_debug_state(pid, &state, &thread) != 0) {
        return -1;
    }

    state.__wvr[slot] = 0;
    state.__wcr[slot] = 0;

    kern_return_t kr = thread_set_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)&state, ARM_DEBUG_STATE64_COUNT);
    mach_port_deallocate(mach_task_self(), thread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state(DEBUG) failed: %s (%d)\n",
                mach_error_string(kr), kr);
        return -1;
    }
    return 0;
}

#elif defined(__x86_64__)
#include <mach/i386/thread_status.h>

static int get_debug_state(pid_t pid, x86_debug_state64_t *state, thread_act_t *thread_out)
{
    thread_act_t thread;
    if (primary_thread_for_pid(pid, &thread) != 0) {
        return -1;
    }

    mach_msg_type_number_t count = x86_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, x86_DEBUG_STATE64,
                                        (thread_state_t)state, &count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_get_state(DEBUG) failed: %s (%d)\n",
                mach_error_string(kr), kr);
        mach_port_deallocate(mach_task_self(), thread);
        return -1;
    }

    *thread_out = thread;
    return 0;
}

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

int cdbg_wp_hw_install(pid_t pid, int slot, uintptr_t addr, size_t size)
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

    x86_debug_state64_t state;
    thread_act_t thread;
    if (get_debug_state(pid, &state, &thread) != 0) {
        return -1;
    }

    *dr_slot_ptr(&state, slot) = (uint64_t)addr;

    const uint64_t rw_write = 0x1;
    unsigned local_enable_bit = (unsigned)(slot * 2);
    unsigned rw_shift = 16 + (unsigned)(slot * 4);
    unsigned len_shift = 18 + (unsigned)(slot * 4);

    state.__dr7 &= ~((uint64_t)0x3 << rw_shift);
    state.__dr7 &= ~((uint64_t)0x3 << len_shift);
    state.__dr7 |= (rw_write << rw_shift);
    state.__dr7 |= (len_bits << len_shift);
    state.__dr7 |= ((uint64_t)1 << local_enable_bit);

    kern_return_t kr = thread_set_state(thread, x86_DEBUG_STATE64,
                                        (thread_state_t)&state, x86_DEBUG_STATE64_COUNT);
    mach_port_deallocate(mach_task_self(), thread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state(DEBUG) failed: %s (%d)\n",
                mach_error_string(kr), kr);
        return -1;
    }
    return 0;
}

int cdbg_wp_hw_uninstall(pid_t pid, int slot)
{
    if (slot < 0 || slot >= CDBG_WP_MAX_HW) {
        return -1;
    }

    x86_debug_state64_t state;
    thread_act_t thread;
    if (get_debug_state(pid, &state, &thread) != 0) {
        return -1;
    }

    *dr_slot_ptr(&state, slot) = 0;
    unsigned local_enable_bit = (unsigned)(slot * 2);
    state.__dr7 &= ~((uint64_t)1 << local_enable_bit);

    kern_return_t kr = thread_set_state(thread, x86_DEBUG_STATE64,
                                        (thread_state_t)&state, x86_DEBUG_STATE64_COUNT);
    mach_port_deallocate(mach_task_self(), thread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state(DEBUG) failed: %s (%d)\n",
                mach_error_string(kr), kr);
        return -1;
    }
    return 0;
}

#else
#error "Unsupported architecture"
#endif
