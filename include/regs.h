#ifndef CDBG_REGS_H
#define CDBG_REGS_H

#include <stdint.h>
#include <sys/types.h>

#if defined(__aarch64__)
#include <mach/arm/thread_status.h>
typedef struct cdbg_regs {
    arm_thread_state64_t native;
    arm_neon_state64_t   neon;
} cdbg_regs_t;
#define CDBG_THREAD_FLAVOR       ARM_THREAD_STATE64
#define CDBG_THREAD_FLAVOR_COUNT ARM_THREAD_STATE64_COUNT
#define CDBG_NEON_FLAVOR         ARM_NEON_STATE64
#define CDBG_NEON_FLAVOR_COUNT   ARM_NEON_STATE64_COUNT
#elif defined(__x86_64__)
#include <mach/i386/thread_status.h>
typedef struct cdbg_regs {
    x86_thread_state64_t native;
    x86_float_state64_t  fp;
} cdbg_regs_t;
#define CDBG_THREAD_FLAVOR       x86_THREAD_STATE64
#define CDBG_THREAD_FLAVOR_COUNT x86_THREAD_STATE64_COUNT
#define CDBG_FP_FLAVOR           x86_FLOAT_STATE64
#define CDBG_FP_FLAVOR_COUNT     x86_FLOAT_STATE64_COUNT
#else
#error "Unsupported architecture"
#endif

int  cdbg_regs_get(pid_t pid, cdbg_regs_t *regs);
int  cdbg_regs_set(pid_t pid, const cdbg_regs_t *regs);
void cdbg_regs_print(const cdbg_regs_t *regs);
uintptr_t cdbg_regs_pc(const cdbg_regs_t *regs);
uintptr_t cdbg_regs_fp(const cdbg_regs_t *regs);
int cdbg_regs_set_pc(cdbg_regs_t *regs, uintptr_t pc);
int cdbg_regs_frame_up(pid_t pid, cdbg_regs_t *regs);
#include <stdbool.h>
int cdbg_regs_get_by_name(const cdbg_regs_t *regs, const char *name, uint64_t *out);
int cdbg_regs_set_by_name(pid_t pid, cdbg_regs_t *regs, const char *name,
                           uint64_t value, bool is_float, double fvalue);

#endif /* CDBG_REGS_H */
