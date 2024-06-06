// SPDX-License-Identifier: GPL-2.0-only
/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <asm/cpufeature.h>
#include <asm/syscall.h>
#include <linux/mman.h>
#include <linux/arm-smccc.h>

extern int do_mprotect_pkey(unsigned long start, size_t len, unsigned long prot, int pkey);

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	if (offset_in_page(off) != 0)
		return -EINVAL;
	unsigned long res = 0;
	struct file *filep = NULL;
	if (current->is_shelter) {
		printk(KERN_INFO "\nsyscall mmap in kernel/sys.c\n");
		res = ksys_mmap_pgoff(addr, len, prot, (addr ? MAP_FIXED : 0) | flags | MAP_LOCKED, current->fd_cma, off >> PAGE_SHIFT);
        if (!(flags & MAP_ANONYMOUS)) { // Not MAP_ANONYMOUS
            filep = fget(fd);
            loff_t file_pos = off;
            vfs_read(filep, (void *)res, len, &file_pos);
            printk(KERN_INFO "mmap %s addr:0x%lx, len:0x%lx, end:0x%lx\n", filep->f_path.dentry->d_iname, res, len, res + len);
        } else { // MAP_ANONYMOUS
            printk(KERN_INFO "MAP_ANONYMOUS addr:0x%lx, len:0x%lx, end:0x%lx\n", res, len, res + len);
        }
    } else {
		res = ksys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
	}
	return res;
}

SYSCALL_DEFINE1(arm64_personality, unsigned int, personality)
{
	if (personality(personality) == PER_LINUX32 &&
		!system_supports_32bit_el0())
		return -EINVAL;
	return ksys_personality(personality);
}

asmlinkage long sys_ni_syscall(void);

asmlinkage long __arm64_sys_ni_syscall(const struct pt_regs *__unused)
{
	return sys_ni_syscall();
}

/*
 * Wrappers to pass the pt_regs argument.
 */
#define __arm64_sys_personality		__arm64_sys_arm64_personality

#undef __SYSCALL
#define __SYSCALL(nr, sym)	asmlinkage long __arm64_##sym(const struct pt_regs *);
#include <asm/unistd.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = __arm64_##sym,

const syscall_fn_t sys_call_table[__NR_syscalls] = {
	[0 ... __NR_syscalls - 1] = __arm64_sys_ni_syscall,
#include <asm/unistd.h>
};
