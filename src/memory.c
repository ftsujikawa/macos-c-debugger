#include "memory.h"

#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

static mach_port_t task_for_traced_pid(pid_t pid)
{
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        return MACH_PORT_NULL;
    }
    return task;
}

static int mem_read_ptrace(pid_t pid, uintptr_t addr, void *buf, size_t len)
{
    uint8_t *out = buf;

    for (size_t i = 0; i < len; i++) {
        errno = 0;
        long word = ptrace(PT_READ_D, pid, (caddr_t)(addr + i), 0);
        if (word == -1 && errno != 0) {
            return -1;
        }
        out[i] = (uint8_t)word;
    }

    return 0;
}

static int mem_write_ptrace(pid_t pid, uintptr_t addr, const void *buf, size_t len)
{
    const uint8_t *in = buf;

    for (size_t i = 0; i < len; i++) {
        if (ptrace(PT_WRITE_D, pid, (caddr_t)(addr + i), in[i]) == -1) {
            return -1;
        }
    }

    return 0;
}

static int mem_write_mach(mach_port_t task, uintptr_t addr, const void *buf, size_t len)
{
    kern_return_t kr = mach_vm_write(task, (mach_vm_address_t)addr,
                                     (vm_offset_t)buf, (mach_msg_type_number_t)len);
    if (kr == KERN_SUCCESS) {
        return 0;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return -1;
    }

    mach_vm_address_t page = (mach_vm_address_t)addr & ~((mach_vm_address_t)page_size - 1U);
    kr = mach_vm_protect(task, page, (mach_vm_size_t)page_size, FALSE,
                         VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    kr = mach_vm_write(task, (mach_vm_address_t)addr,
                       (vm_offset_t)buf, (mach_msg_type_number_t)len);
    (void)mach_vm_protect(task, page, (mach_vm_size_t)page_size, FALSE,
                          VM_PROT_READ | VM_PROT_EXECUTE);
    return kr == KERN_SUCCESS ? 0 : -1;
}

int cdbg_mem_read(pid_t pid, uintptr_t addr, void *buf, size_t len)
{
    mach_port_t task = task_for_traced_pid(pid);
    if (task != MACH_PORT_NULL) {
        vm_offset_t data = 0;
        mach_msg_type_number_t read_size = 0;
        kern_return_t kr = mach_vm_read(task, (mach_vm_address_t)addr, (mach_vm_size_t)len,
                                        &data, &read_size);
        mach_port_deallocate(mach_task_self(), task);
        if (kr == KERN_SUCCESS && read_size == len) {
            memcpy(buf, (void *)data, len);
            mach_vm_deallocate(mach_task_self(), data, read_size);
            return 0;
        }
        if (data != 0) {
            mach_vm_deallocate(mach_task_self(), data, read_size);
        }
    }

    if (mem_read_ptrace(pid, addr, buf, len) != 0) {
        perror("cdbg_mem_read");
        return -1;
    }
    return 0;
}

int cdbg_mem_write(pid_t pid, uintptr_t addr, const void *buf, size_t len)
{
    mach_port_t task = task_for_traced_pid(pid);
    if (task != MACH_PORT_NULL) {
        int rc = mem_write_mach(task, addr, buf, len);
        mach_port_deallocate(mach_task_self(), task);
        if (rc == 0) {
            return 0;
        }
    }

    if (mem_write_ptrace(pid, addr, buf, len) != 0) {
        perror("cdbg_mem_write");
        return -1;
    }
    return 0;
}

int cdbg_mem_read_u64(pid_t pid, uintptr_t addr, uint64_t *out)
{
    return cdbg_mem_read(pid, addr, out, sizeof(*out));
}

int cdbg_mem_write_u64(pid_t pid, uintptr_t addr, uint64_t value)
{
    return cdbg_mem_write(pid, addr, &value, sizeof(value));
}
