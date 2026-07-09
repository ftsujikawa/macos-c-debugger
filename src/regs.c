#include "regs.h"

#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memory.h"

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
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_get_state failed: %s (%d)\n", mach_error_string(kr), kr);
        mach_port_deallocate(mach_task_self(), thread);
        return -1;
    }

#if defined(__aarch64__)
    mach_msg_type_number_t neon_count = CDBG_NEON_FLAVOR_COUNT;
    kr = thread_get_state(thread, CDBG_NEON_FLAVOR,
                          (thread_state_t)&regs->neon, &neon_count);
#elif defined(__x86_64__)
    mach_msg_type_number_t fp_count = CDBG_FP_FLAVOR_COUNT;
    kr = thread_get_state(thread, CDBG_FP_FLAVOR,
                          (thread_state_t)&regs->fp, &fp_count);
#endif
    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_get_state (fp) failed: %s (%d)\n", mach_error_string(kr), kr);
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

uintptr_t cdbg_regs_fp(const cdbg_regs_t *regs)
{
#if defined(__aarch64__)
    return (uintptr_t)regs->native.__fp;
#elif defined(__x86_64__)
    return (uintptr_t)regs->native.__rbp;
#endif
}

static int ret_addr_valid(uint64_t addr)
{
    return addr >= 0x1000;
}

static int unwind_from_stack_top(pid_t pid, cdbg_regs_t *regs, uintptr_t sp)
{
#if defined(__aarch64__)
    uint64_t ret_addr = regs->native.__lr;
    if (!ret_addr_valid(ret_addr)) {
        return -1;
    }
    if (cdbg_regs_set_pc(regs, (uintptr_t)ret_addr) != 0) {
        return -1;
    }
    uintptr_t fp = cdbg_regs_fp(regs);
    if (fp != 0) {
        uint64_t saved_fp = 0;
        if (cdbg_mem_read_u64(pid, fp, &saved_fp) == 0 && saved_fp > fp) {
            regs->native.__fp = saved_fp;
        }
    }
    regs->native.__sp = sp + 16;
#elif defined(__x86_64__)
    uint64_t ret_addr = 0;
    if (cdbg_mem_read_u64(pid, sp, &ret_addr) != 0 || !ret_addr_valid(ret_addr)) {
        return -1;
    }
    if (cdbg_regs_set_pc(regs, (uintptr_t)ret_addr) != 0) {
        return -1;
    }
    regs->native.__rsp = sp + 8;
#endif
    return 0;
}

int cdbg_regs_frame_up(pid_t pid, cdbg_regs_t *regs)
{
    uintptr_t fp = cdbg_regs_fp(regs);
#if defined(__aarch64__)
    uintptr_t sp = (uintptr_t)regs->native.__sp;
#elif defined(__x86_64__)
    uintptr_t sp = (uintptr_t)regs->native.__rsp;
#endif

#if defined(__x86_64__)
    uint8_t insn = 0;
    uintptr_t pc = cdbg_regs_pc(regs);
    if (cdbg_mem_read(pid, pc, &insn, 1) == 0 && insn == 0x55) {
        return unwind_from_stack_top(pid, regs, sp);
    }
#endif

    if (fp != 0) {
        uint64_t saved_fp = 0;
        uint64_t ret_addr = 0;
        if (cdbg_mem_read_u64(pid, fp, &saved_fp) == 0 &&
            cdbg_mem_read_u64(pid, fp + 8, &ret_addr) == 0 &&
            saved_fp > fp && ret_addr_valid(ret_addr)) {
            if (cdbg_regs_set_pc(regs, (uintptr_t)ret_addr) != 0) {
                return -1;
            }
#if defined(__aarch64__)
            regs->native.__fp = saved_fp;
            regs->native.__sp = fp + 16;
#elif defined(__x86_64__)
            regs->native.__rbp = saved_fp;
            regs->native.__rsp = fp + 16;
#endif
            return 0;
        }
    }

    return unwind_from_stack_top(pid, regs, sp);
}

void cdbg_regs_print(const cdbg_regs_t *regs)
{
#if defined(__aarch64__)
    printf("--- General-Purpose Registers ---\n");
    for (int i = 0; i < 28; i += 2) {
        printf("x%-2d = 0x%016llx  x%-2d = 0x%016llx\n",
               i,     (unsigned long long)regs->native.__x[i],
               i + 1, (unsigned long long)regs->native.__x[i + 1]);
    }
    printf("x28 = 0x%016llx\n", (unsigned long long)regs->native.__x[28]);
    printf("fp  = 0x%016llx  lr  = 0x%016llx\n",
           (unsigned long long)regs->native.__fp,
           (unsigned long long)regs->native.__lr);
    printf("sp  = 0x%016llx  pc  = 0x%016llx\n",
           (unsigned long long)regs->native.__sp,
           (unsigned long long)regs->native.__pc);
    printf("cpsr = 0x%08x\n", (unsigned)regs->native.__cpsr);

    printf("\n--- Floating-Point / NEON Registers ---\n");
    printf("fpsr = 0x%08x  fpcr = 0x%08x\n",
           (unsigned)regs->neon.__fpsr, (unsigned)regs->neon.__fpcr);
    for (int i = 0; i < 32; i++) {
        uint64_t lo = (uint64_t)regs->neon.__v[i];
        uint64_t hi = (uint64_t)(regs->neon.__v[i] >> 64);
        double d;
        memcpy(&d, &lo, sizeof(d));
        printf("v%-2d = 0x%016llx%016llx  (f64: %g)\n",
               i, (unsigned long long)hi, (unsigned long long)lo, d);
    }
#elif defined(__x86_64__)
    printf("--- General-Purpose Registers ---\n");
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
    printf("r8  = 0x%016llx  r9  = 0x%016llx\n",
           (unsigned long long)regs->native.__r8,
           (unsigned long long)regs->native.__r9);
    printf("r10 = 0x%016llx  r11 = 0x%016llx\n",
           (unsigned long long)regs->native.__r10,
           (unsigned long long)regs->native.__r11);
    printf("r12 = 0x%016llx  r13 = 0x%016llx\n",
           (unsigned long long)regs->native.__r12,
           (unsigned long long)regs->native.__r13);
    printf("r14 = 0x%016llx  r15 = 0x%016llx\n",
           (unsigned long long)regs->native.__r14,
           (unsigned long long)regs->native.__r15);
    printf("rip = 0x%016llx  rflags = 0x%016llx\n",
           (unsigned long long)regs->native.__rip,
           (unsigned long long)regs->native.__rflags);
    printf("cs  = 0x%04llx  fs = 0x%04llx  gs = 0x%04llx\n",
           (unsigned long long)regs->native.__cs,
           (unsigned long long)regs->native.__fs,
           (unsigned long long)regs->native.__gs);

    printf("\n--- SSE / Floating-Point Registers ---\n");
    printf("mxcsr = 0x%08x\n", (unsigned)regs->fp.__fpu_mxcsr);
    const _STRUCT_XMM_REG *xmm = &regs->fp.__fpu_xmm0;
    for (int i = 0; i < 16; i++) {
        uint64_t lo, hi;
        memcpy(&lo, xmm[i].__xmm_reg,     8);
        memcpy(&hi, xmm[i].__xmm_reg + 8, 8);
        double d;
        memcpy(&d, &lo, sizeof(d));
        printf("xmm%-2d = 0x%016llx%016llx  (f64: %g)\n",
               i, (unsigned long long)hi, (unsigned long long)lo, d);
    }

    printf("\n--- x87 FPU Registers ---\n");
    uint16_t fctrl = 0, fstat = 0;
    memcpy(&fctrl, &regs->fp.__fpu_fcw, 2);
    memcpy(&fstat, &regs->fp.__fpu_fsw, 2);
    printf("fctrl = 0x%04x  fstat = 0x%04x  ftag = 0x%02x\n",
           (unsigned)fctrl, (unsigned)fstat, (unsigned)regs->fp.__fpu_ftw);
    const _STRUCT_MMST_REG *st = &regs->fp.__fpu_stmm0;
    for (int i = 0; i < 8; i++) {
        printf("st%d = 0x", i);
        for (int j = 9; j >= 0; j--) {
            printf("%02x", (unsigned char)st[i].__mmst_reg[j]);
        }
        printf("\n");
    }
#endif
}

static int cdbg_regs_set_fp(pid_t pid, const cdbg_regs_t *regs)
{
    mach_port_t task = task_for_traced_pid(pid);
    if (task == MACH_PORT_NULL) return -1;
    thread_act_t thread = primary_thread_for_task(task);
    mach_port_deallocate(mach_task_self(), task);
    if (thread == MACH_PORT_NULL) return -1;

#if defined(__aarch64__)
    kern_return_t kr = thread_set_state(thread, CDBG_NEON_FLAVOR,
                                        (thread_state_t)&regs->neon,
                                        CDBG_NEON_FLAVOR_COUNT);
#elif defined(__x86_64__)
    kern_return_t kr = thread_set_state(thread, CDBG_FP_FLAVOR,
                                        (thread_state_t)&regs->fp,
                                        CDBG_FP_FLAVOR_COUNT);
#endif
    mach_port_deallocate(mach_task_self(), thread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "thread_set_state (fp) failed: %s (%d)\n", mach_error_string(kr), kr);
        return -1;
    }
    return 0;
}

static int set_gpr_field(cdbg_regs_t *regs, const char *name, uint64_t value)
{
#if defined(__aarch64__)
    if (strcmp(name, "pc") == 0)  { regs->native.__pc = value; return 0; }
    if (strcmp(name, "sp") == 0)  { regs->native.__sp = value; return 0; }
    if (strcmp(name, "fp") == 0 || strcmp(name, "x29") == 0)
                                  { regs->native.__fp = value; return 0; }
    if (strcmp(name, "lr") == 0 || strcmp(name, "x30") == 0)
                                  { regs->native.__lr = value; return 0; }
    if (strcmp(name, "cpsr") == 0){ regs->native.__cpsr = (uint32_t)value; return 0; }
    if (name[0] == 'x') {
        char *endp;
        long idx = strtol(name + 1, &endp, 10);
        if (*endp == '\0' && idx >= 0 && idx <= 28) {
            regs->native.__x[idx] = value;
            return 0;
        }
    }
#elif defined(__x86_64__)
    if (strcmp(name, "rax") == 0)    { regs->native.__rax    = value; return 0; }
    if (strcmp(name, "rbx") == 0)    { regs->native.__rbx    = value; return 0; }
    if (strcmp(name, "rcx") == 0)    { regs->native.__rcx    = value; return 0; }
    if (strcmp(name, "rdx") == 0)    { regs->native.__rdx    = value; return 0; }
    if (strcmp(name, "rsi") == 0)    { regs->native.__rsi    = value; return 0; }
    if (strcmp(name, "rdi") == 0)    { regs->native.__rdi    = value; return 0; }
    if (strcmp(name, "rbp") == 0)    { regs->native.__rbp    = value; return 0; }
    if (strcmp(name, "rsp") == 0)    { regs->native.__rsp    = value; return 0; }
    if (strcmp(name, "rip") == 0)    { regs->native.__rip    = value; return 0; }
    if (strcmp(name, "rflags") == 0 || strcmp(name, "eflags") == 0)
                                     { regs->native.__rflags = value; return 0; }
    if (strcmp(name, "cs") == 0)     { regs->native.__cs     = value; return 0; }
    if (strcmp(name, "fs") == 0)     { regs->native.__fs     = value; return 0; }
    if (strcmp(name, "gs") == 0)     { regs->native.__gs     = value; return 0; }
    if (name[0] == 'r') {
        char *endp;
        long idx = strtol(name + 1, &endp, 10);
        if (*endp == '\0') {
            switch (idx) {
                case 8:  regs->native.__r8  = value; return 0;
                case 9:  regs->native.__r9  = value; return 0;
                case 10: regs->native.__r10 = value; return 0;
                case 11: regs->native.__r11 = value; return 0;
                case 12: regs->native.__r12 = value; return 0;
                case 13: regs->native.__r13 = value; return 0;
                case 14: regs->native.__r14 = value; return 0;
                case 15: regs->native.__r15 = value; return 0;
            }
        }
    }
#endif
    return -1;
}

#if defined(__x86_64__)
static void double_to_80bit(double d, uint8_t bytes[10])
{
    uint64_t bits;
    memcpy(&bits, &d, sizeof(bits));
    int      sign  = (int)((bits >> 63) & 1);
    int      exp64 = (int)((bits >> 52) & 0x7FF);
    uint64_t mant  = bits & 0x000FFFFFFFFFFFFFULL;
    uint16_t exp80;
    uint64_t mant80;
    if (exp64 == 0x7FF) {
        exp80  = 0x7FFF;
        mant80 = (mant == 0) ? (1ULL << 63) : ((1ULL << 63) | mant);
    } else if (exp64 == 0) {
        exp80  = 0;
        mant80 = mant << 11;
    } else {
        exp80  = (uint16_t)(exp64 - 1023 + 16383);
        mant80 = (1ULL << 63) | (mant << 11);
    }
    uint16_t exp_sign = (uint16_t)((sign << 15) | exp80);
    memcpy(bytes,     &mant80,   8);
    memcpy(bytes + 8, &exp_sign, 2);
}
#endif

static int set_fp_field(cdbg_regs_t *regs, const char *name,
                         uint64_t value, bool is_float, double fvalue)
{
#if defined(__aarch64__)
    if (strcmp(name, "fpsr") == 0) { regs->neon.__fpsr = (uint32_t)value; return 0; }
    if (strcmp(name, "fpcr") == 0) { regs->neon.__fpcr = (uint32_t)value; return 0; }
    if (name[0] == 'v') {
        char *endp;
        long idx = strtol(name + 1, &endp, 10);
        if (*endp == '\0' && idx >= 0 && idx <= 31) {
            regs->neon.__v[idx] = (__uint128_t)value;
            return 0;
        }
    }
    (void)is_float; (void)fvalue;
#elif defined(__x86_64__)
    if (strncmp(name, "xmm", 3) == 0) {
        char *endp;
        long idx = strtol(name + 3, &endp, 10);
        if (*endp == '\0' && idx >= 0 && idx <= 15) {
            _STRUCT_XMM_REG *xmm = &regs->fp.__fpu_xmm0;
            memcpy(xmm[idx].__xmm_reg, &value, 8);
            memset(xmm[idx].__xmm_reg + 8, 0, 8);
            return 0;
        }
    }
    if (strncmp(name, "st", 2) == 0) {
        char *endp;
        long idx = strtol(name + 2, &endp, 10);
        if (*endp == '\0' && idx >= 0 && idx <= 7) {
            double d = is_float ? fvalue : (double)(int64_t)value;
            _STRUCT_MMST_REG *st = &regs->fp.__fpu_stmm0;
            double_to_80bit(d, (uint8_t *)st[idx].__mmst_reg);
            return 0;
        }
    }
#endif
    return -1;
}

int cdbg_regs_get_by_name(const cdbg_regs_t *regs, const char *name, uint64_t *out)
{
#if defined(__aarch64__)
    if (strcmp(name, "pc") == 0)   { *out = (uint64_t)regs->native.__pc;   return 0; }
    if (strcmp(name, "sp") == 0)   { *out = (uint64_t)regs->native.__sp;   return 0; }
    if (strcmp(name, "fp") == 0 || strcmp(name, "x29") == 0)
                                   { *out = (uint64_t)regs->native.__fp;   return 0; }
    if (strcmp(name, "lr") == 0 || strcmp(name, "x30") == 0)
                                   { *out = (uint64_t)regs->native.__lr;   return 0; }
    if (strcmp(name, "cpsr") == 0) { *out = (uint64_t)regs->native.__cpsr; return 0; }
    if (strcmp(name, "fpsr") == 0) { *out = (uint64_t)regs->neon.__fpsr;   return 0; }
    if (strcmp(name, "fpcr") == 0) { *out = (uint64_t)regs->neon.__fpcr;   return 0; }
    if (name[0] == 'x') {
        char *endp;
        long idx = strtol(name + 1, &endp, 10);
        if (*endp == '\0' && idx >= 0 && idx <= 28) {
            *out = (uint64_t)regs->native.__x[idx];
            return 0;
        }
    }
    if (name[0] == 'v') {
        char *endp;
        long idx = strtol(name + 1, &endp, 10);
        if (*endp == '\0' && idx >= 0 && idx <= 31) {
            *out = (uint64_t)regs->neon.__v[idx];
            return 0;
        }
    }
#elif defined(__x86_64__)
    if (strcmp(name, "rax") == 0)    { *out = regs->native.__rax;    return 0; }
    if (strcmp(name, "rbx") == 0)    { *out = regs->native.__rbx;    return 0; }
    if (strcmp(name, "rcx") == 0)    { *out = regs->native.__rcx;    return 0; }
    if (strcmp(name, "rdx") == 0)    { *out = regs->native.__rdx;    return 0; }
    if (strcmp(name, "rsi") == 0)    { *out = regs->native.__rsi;    return 0; }
    if (strcmp(name, "rdi") == 0)    { *out = regs->native.__rdi;    return 0; }
    if (strcmp(name, "rbp") == 0)    { *out = regs->native.__rbp;    return 0; }
    if (strcmp(name, "rsp") == 0)    { *out = regs->native.__rsp;    return 0; }
    if (strcmp(name, "rip") == 0)    { *out = regs->native.__rip;    return 0; }
    if (strcmp(name, "rflags") == 0 || strcmp(name, "eflags") == 0)
                                     { *out = regs->native.__rflags; return 0; }
    if (strcmp(name, "cs") == 0)     { *out = regs->native.__cs;     return 0; }
    if (strcmp(name, "fs") == 0)     { *out = regs->native.__fs;     return 0; }
    if (strcmp(name, "gs") == 0)     { *out = regs->native.__gs;     return 0; }
    if (name[0] == 'r') {
        char *endp;
        long idx = strtol(name + 1, &endp, 10);
        if (*endp == '\0') {
            switch (idx) {
                case 8:  *out = regs->native.__r8;  return 0;
                case 9:  *out = regs->native.__r9;  return 0;
                case 10: *out = regs->native.__r10; return 0;
                case 11: *out = regs->native.__r11; return 0;
                case 12: *out = regs->native.__r12; return 0;
                case 13: *out = regs->native.__r13; return 0;
                case 14: *out = regs->native.__r14; return 0;
                case 15: *out = regs->native.__r15; return 0;
            }
        }
    }
    if (strncmp(name, "xmm", 3) == 0) {
        char *endp;
        long idx = strtol(name + 3, &endp, 10);
        if (*endp == '\0' && idx >= 0 && idx <= 15) {
            const _STRUCT_XMM_REG *xmm = &regs->fp.__fpu_xmm0;
            uint64_t lo;
            memcpy(&lo, xmm[idx].__xmm_reg, 8);
            *out = lo;
            return 0;
        }
    }
    if (strncmp(name, "st", 2) == 0) {
        char *endp;
        long idx = strtol(name + 2, &endp, 10);
        if (*endp == '\0' && idx >= 0 && idx <= 7) {
            const _STRUCT_MMST_REG *st = &regs->fp.__fpu_stmm0;
            uint64_t lo;
            memcpy(&lo, st[idx].__mmst_reg, 8);
            *out = lo;
            return 0;
        }
    }
#endif
    return -1;
}

int cdbg_regs_set_by_name(pid_t pid, cdbg_regs_t *regs, const char *name,
                           uint64_t value, bool is_float, double fvalue)
{
    if (set_gpr_field(regs, name, value) == 0) {
        return cdbg_regs_set(pid, regs);
    }
    if (set_fp_field(regs, name, value, is_float, fvalue) == 0) {
        return cdbg_regs_set_fp(pid, regs);
    }
    return -1;
}
