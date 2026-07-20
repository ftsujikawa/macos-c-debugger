#ifndef CDBG_REGS_H
#define CDBG_REGS_H

#include <stdbool.h>
#include <stddef.h>
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

/* `tid` selects which thread of the debuggee a call applies to: pass 0 for
 * the process's primary (first) thread, or a thread id as reported by
 * cdbg_threads_list()/`threads` for any other thread. */
#define CDBG_TID_PRIMARY ((uint64_t)0)

#define CDBG_MAX_THREADS 64

typedef struct {
    uint64_t tid;
    bool     is_primary;
} cdbg_thread_info_t;

/* Lists up to `max_count` of the debuggee's threads into `out`, primary
 * thread first. Returns 0 on success (with *count_out set), -1 on failure. */
int cdbg_threads_list(pid_t pid, cdbg_thread_info_t *out, size_t max_count,
                       size_t *count_out);

int  cdbg_regs_get(pid_t pid, uint64_t tid, cdbg_regs_t *regs);
int  cdbg_regs_set(pid_t pid, uint64_t tid, const cdbg_regs_t *regs);
void cdbg_regs_print(const cdbg_regs_t *regs);
uintptr_t cdbg_regs_pc(const cdbg_regs_t *regs);
uintptr_t cdbg_regs_fp(const cdbg_regs_t *regs);
int cdbg_regs_set_pc(cdbg_regs_t *regs, uintptr_t pc);
int cdbg_regs_frame_up(pid_t pid, cdbg_regs_t *regs);
int cdbg_regs_get_by_name(const cdbg_regs_t *regs, const char *name, uint64_t *out);
int cdbg_regs_set_by_name(pid_t pid, uint64_t tid, cdbg_regs_t *regs, const char *name,
                           uint64_t value, bool is_float, double fvalue);

/* Mach thread_suspend()/thread_resume() on thread `tid` (CDBG_TID_PRIMARY
 * for the primary thread). Independent of ptrace's process-wide stop: a
 * suspended thread does not run even while the task as a whole is resumed
 * via PT_CONTINUE/PT_STEP. Used by the `lock`/`unlock` REPL commands to
 * restrict execution to a single thread. */
int cdbg_thread_suspend(pid_t pid, uint64_t tid);
int cdbg_thread_resume(pid_t pid, uint64_t tid);

#endif /* CDBG_REGS_H */
