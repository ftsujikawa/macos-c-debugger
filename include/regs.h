#ifndef CDBG_REGS_H
#define CDBG_REGS_H

#include <stdint.h>
#include <sys/types.h>

#if defined(__aarch64__)
#include <mach/arm/thread_status.h>
typedef struct cdbg_regs {
    arm_thread_state64_t native;
} cdbg_regs_t;
#define CDBG_THREAD_FLAVOR       ARM_THREAD_STATE64
#define CDBG_THREAD_FLAVOR_COUNT ARM_THREAD_STATE64_COUNT
#elif defined(__x86_64__)
#include <mach/i386/thread_status.h>
typedef struct cdbg_regs {
    x86_thread_state64_t native;
} cdbg_regs_t;
#define CDBG_THREAD_FLAVOR       x86_THREAD_STATE64
#define CDBG_THREAD_FLAVOR_COUNT x86_THREAD_STATE64_COUNT
#else
#error "Unsupported architecture"
#endif

int  cdbg_regs_get(pid_t pid, cdbg_regs_t *regs);
int  cdbg_regs_set(pid_t pid, const cdbg_regs_t *regs);
void cdbg_regs_print(const cdbg_regs_t *regs);
uintptr_t cdbg_regs_pc(const cdbg_regs_t *regs);
int cdbg_regs_set_pc(cdbg_regs_t *regs, uintptr_t pc);

#endif /* CDBG_REGS_H */
