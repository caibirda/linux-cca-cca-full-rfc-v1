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
	struct arm_smccc_res smccc_res;
	if (current->is_shelter) {
		printk(KERN_INFO "\nsyscall mmap in kernel/sys.c\n");
		if (!(flags & MAP_ANONYMOUS)) { // Not MAP_ANONYMOUS
			filep = fget(fd);
			if (!filep) {
				printk(KERN_ERR "get filep failed!\n");
				return -EBADF;
			}
			if (strncmp(filep->f_path.dentry->d_iname, "memfd:", 6) == 0) {
				// File name starts with "memfd:"
				printk(KERN_INFO "mmap %s, addr = 0x%lx, len = 0x%lx, off = 0x%lx\n",filep->f_path.dentry->d_iname, addr, len, off);
				// goto origin;
			} else 
				printk(KERN_INFO "mmap filename:%s, addr = 0x%lx, len = 0x%lx, off = 0x%lx\n",filep->f_path.dentry->d_iname, addr, len, off);
		} else { // MAP_ANONYMOUS
			printk(KERN_INFO "MAP_ANONYMOUS: addr = 0x%lx, len = 0x%lx, off = 0x%lx\n", addr, len, off);
		}
		if (addr != 0) {
			res = ksys_mmap_pgoff(addr, len, prot, MAP_FIXED | MAP_SHARED | MAP_LOCKED, current->fd_cma, off >> PAGE_SHIFT);
		} else {
			res = ksys_mmap_pgoff(addr, len, prot, MAP_SHARED | MAP_LOCKED, current->fd_cma, off >> PAGE_SHIFT);
		}
		// arm_smccc_smc(0x80000FF2, res, 0, 0, 0, 0, 0, 0, &smccc_res); // panic in EL3 translation_va!
		if (!(flags & MAP_ANONYMOUS)) { // Not MAP_ANONYMOUS
			// printk(KERN_INFO "mmap filename:%s, addr/paddr = 0x%lx/0x%lx, len = 0x%lx, end = 0x%lx\n", filep->f_path.dentry->d_iname, res, smccc_res.a0, len, res + len);
			printk(KERN_INFO "mmap filename:%s, addr = 0x%lx, len = 0x%lx, end = 0x%lx\n", filep->f_path.dentry->d_iname, res, len, res + len);
			loff_t file_pos = off;
			vfs_read(filep, (void*)res, len, &file_pos);
		} else { // MAP_ANONYMOUS
			// printk(KERN_INFO "MAP_ANONYMOUS result: addr/paddr = 0x%lx/0x%lx, len = 0x%lx, end = 0x%lx\n", res, smccc_res.a0, len, res + len);
			printk(KERN_INFO "MAP_ANONYMOUS result: addr = 0x%lx, len = 0x%lx, end = 0x%lx\n", res, len, res + len);

		}
		if ((prot & PROT_EXEC) != 0) { // PROT_EXEC
			do_mprotect_pkey(res, len, PROT_EXEC|PROT_READ, -1);
		} else if ((prot & PROT_WRITE) == 0 ) { //NOT PROT_WRITE
			do_mprotect_pkey(res, len, PROT_READ, -1);
		}
	} else {
// origin:;
		res = ksys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
	}
	if (current->is_shelter) {
		printk(KERN_INFO "syscall mmap result: addr/paddr = 0x%lx/0x%lx, len = 0x%lx, end = 0x%lx\n\n", res, smccc_res.a0, len, res + len);
		// arm_smccc_smc(0x80000FF3, res, current->pid, 0, 0, 0, 0, 0, &smccc_res);
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
