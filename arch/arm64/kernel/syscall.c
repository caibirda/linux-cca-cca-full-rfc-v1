// SPDX-License-Identifier: GPL-2.0

#include <linux/compiler.h>
#include <linux/syscalls.h>
#include <linux/context_tracking.h>
#include <linux/errno.h>
#include <linux/nospec.h>
#include <linux/ptrace.h>
#include <linux/randomize_kstack.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/file.h>

#include <asm/daifflags.h>
#include <asm/debug-monitors.h>
#include <asm/exception.h>
#include <asm/fpsimd.h>
#include <asm/syscall.h>
#include <asm/thread_info.h>
#include <asm/unistd.h>
#include <linux/arm-smccc.h>
#include <linux/sched.h>
#include <linux/mman.h>

long compat_arm_syscall(struct pt_regs *regs, int scno);
long sys_ni_syscall(void);

static long do_ni_syscall(struct pt_regs *regs, int scno)
{
#ifdef CONFIG_COMPAT
	long ret;
	if (is_compat_task()) {
		ret = compat_arm_syscall(regs, scno);
		if (ret != -ENOSYS)
			return ret;
	}
#endif

	return sys_ni_syscall();
}

static long __invoke_syscall(struct pt_regs *regs, syscall_fn_t syscall_fn)
{
	return syscall_fn(regs);
}

static void invoke_syscall(struct pt_regs *regs, unsigned int scno,
			   unsigned int sc_nr,
			   const syscall_fn_t syscall_table[])
{
	long ret;

	add_random_kstack_offset();

	if (scno < sc_nr) {
		syscall_fn_t syscall_fn;
		syscall_fn = syscall_table[array_index_nospec(scno, sc_nr)];
		ret = __invoke_syscall(regs, syscall_fn);
	} else {
		ret = do_ni_syscall(regs, scno);
	}

	syscall_set_return_value(current, regs, 0, ret);

	/*
	 * Ultimately, this value will get limited by KSTACK_OFFSET_MAX(),
	 * but not enough for arm64 stack utilization comfort. To keep
	 * reasonable stack head room, reduce the maximum offset to 9 bits.
	 *
	 * The actual entropy will be further reduced by the compiler when
	 * applying stack alignment constraints: the AAPCS mandates a
	 * 16-byte (i.e. 4-bit) aligned SP at function boundaries.
	 *
	 * The resulting 5 bits of entropy is seen in SP[8:4].
	 */
	choose_random_kstack_offset(get_random_u16() & 0x1FF);
}

static inline bool has_syscall_work(unsigned long flags)
{
	return unlikely(flags & _TIF_SYSCALL_WORK);
}

int syscall_trace_enter(struct pt_regs *regs);
void syscall_trace_exit(struct pt_regs *regs);

static int should_page_fault(unsigned long addr, struct task_struct *task) {
	// printk(KERN_INFO "should addr: 0x%lx page fault?\n", addr);
	struct mm_struct *mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct page *page;
	mm = task->mm;
	if (!mm)
		return -EINVAL;
	if (addr >= TASK_SIZE)
		return -EINVAL;
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 1;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 1;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return 1;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return 1;
	pte = pte_offset_map(pmd, addr);
	if (!pte)
		return 1;
	if (!pte_present(*pte)) {
		pte_unmap(pte);
		return 1;
	}
	page = pte_page(*pte);
	if (!page) {
		pte_unmap(pte);
		return 1;
	}
	pte_unmap(pte);
	return 0;
}

static void el0_svc_common(struct pt_regs *regs, int scno, int sc_nr,
			   const syscall_fn_t syscall_table[])
{
	unsigned long flags = read_thread_flags();

	regs->orig_x0 = regs->regs[0];
	regs->syscallno = scno;

	/*
	 * BTI note:
	 * The architecture does not guarantee that SPSR.BTYPE is zero
	 * on taking an SVC, so we could return to userspace with a
	 * non-zero BTYPE after the syscall.
	 *
	 * This shouldn't matter except when userspace is explicitly
	 * doing something stupid, such as setting PROT_BTI on a page
	 * that lacks conforming BTI/PACIxSP instructions, falling
	 * through from one executable page to another with differing
	 * PROT_BTI, or messing with BTYPE via ptrace: in such cases,
	 * userspace should not be surprised if a SIGILL occurs on
	 * syscall return.
	 *
	 * So, don't touch regs->pstate & PSR_BTYPE_MASK here.
	 * (Similarly for HVC and SMC elsewhere.)
	 */

	local_daif_restore(DAIF_PROCCTX);

	if (flags & _TIF_MTE_ASYNC_FAULT) {
		/*
		 * Process the asynchronous tag check fault before the actual
		 * syscall. do_notify_resume() will send a signal to userspace
		 * before the syscall is restarted.
		 */
		syscall_set_return_value(current, regs, -ERESTARTNOINTR, 0);
		return;
	}

	if (has_syscall_work(flags)) {
		/*
		 * The de-facto standard way to skip a system call using ptrace
		 * is to set the system call to -1 (NO_SYSCALL) and set x0 to a
		 * suitable error code for consumption by userspace. However,
		 * this cannot be distinguished from a user-issued syscall(-1)
		 * and so we must set x0 to -ENOSYS here in case the tracer doesn't
		 * issue the skip and we fall into trace_exit with x0 preserved.
		 *
		 * This is slightly odd because it also means that if a tracer
		 * sets the system call number to -1 but does not initialise x0,
		 * then x0 will be preserved for all system calls apart from a
		 * user-issued syscall(-1). However, requesting a skip and not
		 * setting the return value is unlikely to do anything sensible
		 * anyway.
		 */
		if (scno == NO_SYSCALL)
			syscall_set_return_value(current, regs, -ENOSYS, 0);
		scno = syscall_trace_enter(regs);
		if (scno == NO_SYSCALL)
			goto trace_exit;
	}
	struct arm_smccc_res smccc_res;
	if (current->is_shelter && current->wait_alloc) {
		// printk(KERN_INFO "\npid %d wait_alloc\n", current->pid);
		struct fd f = fdget(current->fd_cma);
		// printk(KERN_INFO "before allocating task_shared/singal_virt:\n");
		// printk(KERN_INFO "current->fd_cma:%d, filename:%s\n", current->fd_cma, f.file->f_path.dentry->d_name.name);
		if (strncmp(f.file->f_path.dentry->d_name.name, "SHELTER", 7) != 0) {
			printk("current->fd_cma has been changed!!!\n\n");
			// struct file *filp_temp = filp_open("/dev/SHELTER", O_RDWR, 0);
			// int fd_temp = get_unused_fd_flags(O_RDWR);
			// fd_install(fd_temp, filp_temp);
			// printk("before fd_cma is %d\n", current->fd_cma);
			// current->fd_cma = fd_temp;
			// printk("now fd_cma is %d\n", current->fd_cma);
		}
		// unsigned long task_shared_virt = ksys_mmap_pgoff(0, SHELTER_TASK_SHARED_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED, current->fd_cma, 0);
		// unsigned long task_singal_stack_virt = ksys_mmap_pgoff(0, SHELTER_TASK_SIGNAL_STACK_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED, current->fd_cma, 0);
		// printk(KERN_INFO "handle_wait_alloc, task_shared_virt:0x%lx, task_singal_stack_virt:0x%lx\n", task_shared_virt, task_singal_stack_virt);
		// current->task_signal_stack_virt = task_singal_stack_virt;
		// arm_smccc_smc(0x80000FFD, current->pid, task_shared_virt, task_singal_stack_virt, 0, 0, 0, 0, &smccc_res);
		current->wait_alloc = 0;
		// printk(KERN_INFO "after handle_wait_alloc\n");
	}
	// if (current->is_shelter && (scno == __NR_newfstatat || scno == __NR_readlinkat || scno == __NR_write || scno == __NR_openat)) {
	// 	unsigned long ptr = regs->regs[1];
	// 	struct task_struct *task = current;
	// 	if (should_page_fault(ptr, task)) {
	// 		void *buffer = kzalloc(1, GFP_KERNEL);
	// 		current->wait_page_fault = 1;
	// 		if (copy_from_user(buffer, (const void __user *)ptr, 1) != 0) {
	// 			panic("\nfailed to copy data from user space\n\n");
	// 		// } else {
	// 		// 	printk(KERN_INFO "\nsyscall %s need page fault!!!\n", scno == __NR_newfstatat ? "newfstatat" : (scno == __NR_readlinkat ? "readlinkat" : (scno == __NR_write ? "write" : "openat")));
	// 		}
	// 		current->wait_page_fault = 0;
	// 		kfree(buffer);
	// 	}
	// }
	if (current->is_shelter && scno != __NR_shelter_exec){ // sync
		arm_smccc_smc(0x80000FF7, (unsigned long *)regs->regs, 0, 0, 0, 0, 0, 0, &smccc_res);
	}

	invoke_syscall(regs, scno, sc_nr, syscall_table);

	if (scno == __NR_shelter_exec && current->is_shelter) {
		// trap to EL3 to create the new shelter app environment. ENC_NEW_TEST 0x80000FFE
		current->gpt_id = ksys_ioctl(current->fd_cma, 0x80000FFE, 0);
		// printk(KERN_INFO "after ksys_ioctl, gpt_id is %d\n", current->gpt_id);
		if (current->gpt_id <= 0) {
			current->is_shelter = 0;
			do_group_exit(current->gpt_id);
		}
		// unsigned long task_shared_virt = ksys_mmap_pgoff(0, SHELTER_TASK_SHARED_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED, current->fd_cma, 0);
		// unsigned long task_singal_stack_virt = ksys_mmap_pgoff(0, SHELTER_TASK_SIGNAL_STACK_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED, current->fd_cma, 0);
		// current->task_signal_stack_virt = task_singal_stack_virt;
		// // printk(KERN_INFO "pid %d task_shared_virt: 0x%lx, task_singal_stack_virt: 0x%lx\n", current->pid, task_shared_virt, task_singal_stack_virt);
		// arm_smccc_smc(0x80000FFD, current->pid, task_shared_virt, task_singal_stack_virt, 0, 0, 0, 0, &smccc_res);// enc_nc_ns
		// printk(KERN_INFO "\npid %d done shelter_exec\n", current->pid);
	}

	/*
	 * The tracing status may have changed under our feet, so we have to
	 * check again. However, if we were tracing entry, then we always trace
	 * exit regardless, as the old entry assembly did.
	 */
	if (!has_syscall_work(flags) && !IS_ENABLED(CONFIG_DEBUG_RSEQ)) {
		local_daif_mask();
		flags = read_thread_flags();
		if (!has_syscall_work(flags) && !(flags & _TIF_SINGLESTEP))
			return;
		local_daif_restore(DAIF_PROCCTX);
	}

trace_exit:
	syscall_trace_exit(regs);
}

/*
 * As per the ABI exit SME streaming mode and clear the SVE state not
 * shared with FPSIMD on syscall entry.
 */
static inline void fp_user_discard(void)
{
	/*
	 * If SME is active then exit streaming mode.  If ZA is active
	 * then flush the SVE registers but leave userspace access to
	 * both SVE and SME enabled, otherwise disable SME for the
	 * task and fall through to disabling SVE too.  This means
	 * that after a syscall we never have any streaming mode
	 * register state to track, if this changes the KVM code will
	 * need updating.
	 */
	if (system_supports_sme() && test_thread_flag(TIF_SME)) {
		u64 svcr = read_sysreg_s(SYS_SVCR);

		if (svcr & SVCR_SM_MASK)
			sme_smstop_sm();
	}

	if (!system_supports_sve())
		return;

	if (test_thread_flag(TIF_SVE)) {
		unsigned int sve_vq_minus_one;

		sve_vq_minus_one = sve_vq_from_vl(task_get_sve_vl(current)) - 1;
		sve_flush_live(true, sve_vq_minus_one);
	}
}

void do_el0_svc(struct pt_regs *regs)
{
	fp_user_discard();
	el0_svc_common(regs, regs->regs[8], __NR_syscalls, sys_call_table);
}

#ifdef CONFIG_COMPAT
void do_el0_svc_compat(struct pt_regs *regs)
{
	el0_svc_common(regs, regs->regs[7], __NR_compat_syscalls,
		       compat_sys_call_table);
}
#endif
