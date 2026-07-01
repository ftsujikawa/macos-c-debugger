#include "regs.h"

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

int cdbg_regs_get(pid_t pid, cdbg_regs_t *regs)
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

    mach_msg_type_number_t count = CDBG_THREAD_FLAVOR_COUNT;
    kern_return_t kr = thread_get_state(thread, CDBG_THREAD_FLAVOR,
                                        (thread_state_t)&regs->native, &count);
    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_get_state failed: %s (%d)\n", mach_error_string(kr), kr);
        return -1;
    }

    return 0;
}

int cdbg_regs_set(pid_t pid, const cdbg_regs_t *regs)
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

    kern_return_t kr = thread_set_state(thread, CDBG_THREAD_FLAVOR,
                                        (thread_state_t)&regs->native,
                                        CDBG_THREAD_FLAVOR_COUNT);
    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state failed: %s (%d)\n", mach_error_string(kr), kr);
        return -1;
    }

    return 0;
}

uintptr_t cdbg_regs_pc(const cdbg_regs_t *regs)
{
#if defined(__aarch64__)
    return (uintptr_t)regs->native.__pc;
#elif defined(__x86_64__)
    return (uintptr_t)regs->native.__rip;
#endif
}

int cdbg_regs_set_pc(cdbg_regs_t *regs, uintptr_t pc)
{
#if defined(__aarch64__)
    regs->native.__pc = pc;
#elif defined(__x86_64__)
    regs->native.__rip = pc;
#endif
    return 0;
}

void cdbg_regs_print(const cdbg_regs_t *regs)
{
#if defined(__aarch64__)
    printf("pc  = 0x%016llx\n", (unsigned long long)regs->native.__pc);
    printf("sp  = 0x%016llx\n", (unsigned long long)regs->native.__sp);
    printf("fp  = 0x%016llx\n", (unsigned long long)regs->native.__fp);
    printf("lr  = 0x%016llx\n", (unsigned long long)regs->native.__lr);
#elif defined(__x86_64__)
    printf("rax = 0x%016llx  rbx = 0x%016llx\n",
           (unsigned long long)regs->native.__rax,
           (unsigned long long)regs->native.__rbx);
    printf("rcx = 0x%016llx  rdx = 0x%016llx\n",
           (unsigned long long)regs->native.__rcx,
           (unsigned long long)regs->native.__rdx);
    printf("rsi = 0x%016llx  rdi = 0x%016llx\n",
           (unsigned long long)regs->native.__rsi,
           (unsigned long long)regs->native.__rdi);
    printf("rbp = 0x%016llx  rsp = 0x%016llx\n",
           (unsigned long long)regs->native.__rbp,
           (unsigned long long)regs->native.__rsp);
    printf("rip = 0x%016llx  rflags = 0x%016llx\n",
           (unsigned long long)regs->native.__rip,
           (unsigned long long)regs->native.__rflags);
#endif
}
