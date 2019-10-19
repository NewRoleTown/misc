/*
 * The IDT has to be page-aligned to simplify the Pentium
 * F0 0F bug workaround.. We have a special link segment
 * for this.
 */
struct desc_struct idt_table[256] __attribute__((__section__(".data.idt"))) = { {0, 0}, };

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void nmi(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void simd_coprocessor_error(void);
asmlinkage void alignment_check(void);
asmlinkage void spurious_interrupt_bug(void);
asmlinkage void machine_check(void);

/* The form of the top of the frame on the stack */
struct stack_frame {
	struct stack_frame *next_frame;
	unsigned long return_address;
};

static inline unsigned long print_context_stack(struct thread_info *tinfo,
				unsigned long *stack, unsigned long ebp,
				const struct stacktrace_ops *ops, void *data)
{
#ifdef	CONFIG_FRAME_POINTER
	struct stack_frame *frame = (struct stack_frame *)ebp;
	while (valid_stack_ptr(tinfo, frame, sizeof(*frame))) {
		struct stack_frame *next;
		unsigned long addr;

		addr = frame->return_address;
		ops->address(data, addr);
		/*
		 * break out of recursive entries (such as
		 * end_of_stack_stop_unwind_function). Also,
		 * we can never allow a frame pointer to
		 * move downwards!
		 */
		next = frame->next_frame;
		if (next <= frame)
			break;
		frame = next;
	}
#else
	while (valid_stack_ptr(tinfo, stack, sizeof(*stack))) {
		unsigned long addr;

		addr = *stack++;
		if (__kernel_text_address(addr))
			ops->address(data, addr);
	}
#endif
	return ebp;
}

void dump_trace(struct task_struct *task, struct pt_regs *regs,
	        unsigned long *stack,
		const struct stacktrace_ops *ops, void *data)
{
	unsigned long ebp = 0;

	if (!task)
		task = current;

	if (!stack) {
		unsigned long dummy;
		stack = &dummy;
		if (task != current)
			stack = (unsigned long *)task->thread.esp;
	}

#ifdef CONFIG_FRAME_POINTER
	if (!ebp) {
		if (task == current) {
			/* Grab ebp right from our regs */
			asm ("movl %%ebp, %0" : "=r" (ebp) : );
		} else {
			/* ebp is the last reg pushed by switch_to */
			ebp = *(unsigned long *) task->thread.esp;
		}
	}
#endif

	while (1) {
		struct thread_info *context;
		context = (struct thread_info *)
			((unsigned long)stack & (~(THREAD_SIZE - 1)));
		ebp = print_context_stack(context, stack, ebp, ops, data);
		/* Should be after the line below, but somewhere
		   in early boot context comes out corrupted and we
		   can't reference it -AK */
		if (ops->stack(data, "IRQ") < 0)
			break;
		stack = (unsigned long*)context->previous_esp;
		if (!stack)
			break;
		touch_nmi_watchdog();
	}
}
EXPORT_SYMBOL(dump_trace);

void show_registers(struct pt_regs *regs)
{
	int i;

	print_modules();
	__show_registers(regs, 0);
	printk(KERN_EMERG "Process %.*s (pid: %d, ti=%p task=%p task.ti=%p)",
		TASK_COMM_LEN, current->comm, task_pid_nr(current),
		current_thread_info(), current, task_thread_info(current));
	/*
	 * When in-kernel, we also print out the stack and code at the
	 * time of the fault..
	 */
	if (!user_mode_vm(regs)) {
		u8 *eip;
		unsigned int code_prologue = code_bytes * 43 / 64;
		unsigned int code_len = code_bytes;
		unsigned char c;

		printk("\n" KERN_EMERG "Stack: ");
		show_stack_log_lvl(NULL, regs, &regs->esp, KERN_EMERG);

		printk(KERN_EMERG "Code: ");

		eip = (u8 *)regs->eip - code_prologue;
		if (eip < (u8 *)PAGE_OFFSET ||
			probe_kernel_address(eip, c)) {
			/* try starting at EIP */
			eip = (u8 *)regs->eip;
			code_len = code_len - code_prologue + 1;
		}
		for (i = 0; i < code_len; i++, eip++) {
			if (eip < (u8 *)PAGE_OFFSET ||
				probe_kernel_address(eip, c)) {
				printk(" Bad EIP value.");
				break;
			}
			if (eip == (u8 *)regs->eip)
				printk("<%02x> ", c);
			else
				printk("%02x ", c);
		}
	}
	printk("\n");
}	

int is_valid_bugaddr(unsigned long eip)
{
	unsigned short ud2;

	if (eip < PAGE_OFFSET)
		return 0;
	if (probe_kernel_address((unsigned short *)eip, ud2))
		return 0;

	return ud2 == 0x0b0f;
}

/*
 * This is gone through when something in the kernel has done something bad and
 * is about to be terminated.
 */
void die(const char * str, struct pt_regs * regs, long err)
{
	static struct {
		raw_spinlock_t lock;
		u32 lock_owner;
		int lock_owner_depth;
	} die = {
		.lock =			__RAW_SPIN_LOCK_UNLOCKED,
		.lock_owner =		-1,
		.lock_owner_depth =	0
	};
	static int die_counter;
	unsigned long flags;

	oops_enter();

	if (die.lock_owner != raw_smp_processor_id()) {
		console_verbose();
		raw_local_irq_save(flags);
		__raw_spin_lock(&die.lock);
		die.lock_owner = smp_processor_id();
		die.lock_owner_depth = 0;
		bust_spinlocks(1);
	} else
		raw_local_irq_save(flags);

	if (++die.lock_owner_depth < 3) {
		unsigned long esp;
		unsigned short ss;

		report_bug(regs->eip, regs);

		printk(KERN_EMERG "%s: %04lx [#%d] ", str, err & 0xffff,
		       ++die_counter);
#ifdef CONFIG_PREEMPT
		printk("PREEMPT ");
#endif
#ifdef CONFIG_SMP
		printk("SMP ");
#endif
#ifdef CONFIG_DEBUG_PAGEALLOC
		printk("DEBUG_PAGEALLOC");
#endif
		printk("\n");

		if (notify_die(DIE_OOPS, str, regs, err,
					current->thread.trap_no, SIGSEGV) !=
				NOTIFY_STOP) {
			show_registers(regs);
			/* Executive summary in case the oops scrolled away */
			esp = (unsigned long) (&regs->esp);
			savesegment(ss, ss);
			if (user_mode(regs)) {
				esp = regs->esp;
				ss = regs->xss & 0xffff;
			}
			printk(KERN_EMERG "EIP: [<%08lx>] ", regs->eip);
			print_symbol("%s", regs->eip);
			printk(" SS:ESP %04x:%08lx\n", ss, esp);
		}
		else
			regs = NULL;
  	} else
		printk(KERN_EMERG "Recursive die() failure, output suppressed\n");

	bust_spinlocks(0);
	die.lock_owner = -1;
	add_taint(TAINT_DIE);
	__raw_spin_unlock(&die.lock);
	raw_local_irq_restore(flags);

	if (!regs)
		return;

	if (kexec_should_crash(current))
		crash_kexec(regs);

	if (in_interrupt())
		panic("Fatal exception in interrupt");

	if (panic_on_oops)
		panic("Fatal exception");

	oops_exit();
	do_exit(SIGSEGV);
}

DO_VM86_ERROR_INFO( 0, SIGFPE,  "divide error", divide_error, FPE_INTDIV, regs->eip)
#ifndef CONFIG_KPROBES
DO_VM86_ERROR( 3, SIGTRAP, "int3", int3)
#endif
DO_VM86_ERROR( 4, SIGSEGV, "overflow", overflow)
DO_VM86_ERROR( 5, SIGSEGV, "bounds", bounds)
DO_ERROR_INFO( 6, SIGILL,  "invalid opcode", invalid_op, ILL_ILLOPN, regs->eip, 0)
DO_ERROR( 9, SIGFPE,  "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, SIGSEGV, "invalid TSS", invalid_TSS)
DO_ERROR(11, SIGBUS,  "segment not present", segment_not_present)
DO_ERROR(12, SIGBUS,  "stack segment", stack_segment)
DO_ERROR_INFO(17, SIGBUS, "alignment check", alignment_check, BUS_ADRALN, 0, 0)
DO_ERROR_INFO(32, SIGSEGV, "iret exception", iret_error, ILL_BADSTK, 0, 1)

fastcall void __kprobes do_general_protection(struct pt_regs * regs,
					      long error_code)
{
	int cpu = get_cpu();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);
	struct thread_struct *thread = &current->thread;

	/*
	 * Perform the lazy TSS's I/O bitmap copy. If the TSS has an
	 * invalid offset set (the LAZY one) and the faulting thread has
	 * a valid I/O bitmap pointer, we copy the I/O bitmap in the TSS
	 * and we set the offset field correctly. Then we let the CPU to
	 * restart the faulting instruction.
	 */
	if (tss->x86_tss.io_bitmap_base == INVALID_IO_BITMAP_OFFSET_LAZY &&
	    thread->io_bitmap_ptr) {
		memcpy(tss->io_bitmap, thread->io_bitmap_ptr,
		       thread->io_bitmap_max);
		/*
		 * If the previously set map was extending to higher ports
		 * than the current one, pad extra space with 0xff (no access).
		 */
		if (thread->io_bitmap_max < tss->io_bitmap_max)
			memset((char *) tss->io_bitmap +
				thread->io_bitmap_max, 0xff,
				tss->io_bitmap_max - thread->io_bitmap_max);
		tss->io_bitmap_max = thread->io_bitmap_max;
		tss->x86_tss.io_bitmap_base = IO_BITMAP_OFFSET;
		tss->io_bitmap_owner = thread;
		put_cpu();
		return;
	}
	put_cpu();

	if (regs->eflags & VM_MASK)
		goto gp_in_vm86;

	if (!user_mode(regs))
		goto gp_in_kernel;

	current->thread.error_code = error_code;
	current->thread.trap_no = 13;
	if (show_unhandled_signals && unhandled_signal(current, SIGSEGV) &&
	    printk_ratelimit())
		printk(KERN_INFO
		    "%s[%d] general protection eip:%lx esp:%lx error:%lx\n",
		    current->comm, task_pid_nr(current),
		    regs->eip, regs->esp, error_code);

	force_sig(SIGSEGV, current);
	return;

gp_in_vm86:
	local_irq_enable();
	handle_vm86_fault((struct kernel_vm86_regs *) regs, error_code);
	return;

gp_in_kernel:
	if (!fixup_exception(regs)) {
		current->thread.error_code = error_code;
		current->thread.trap_no = 13;
		if (notify_die(DIE_GPF, "general protection fault", regs,
				error_code, 13, SIGSEGV) == NOTIFY_STOP)
			return;
		die("general protection fault", regs, error_code);
	}
}

static __kprobes void
mem_parity_error(unsigned char reason, struct pt_regs * regs)
{
	printk(KERN_EMERG "Uhhuh. NMI received for unknown reason %02x on "
		"CPU %d.\n", reason, smp_processor_id());
	printk(KERN_EMERG "You have some hardware problem, likely on the PCI bus.\n");

#if defined(CONFIG_EDAC)
	if(edac_handler_set()) {
		edac_atomic_assert_error();
		return;
	}
#endif

	if (panic_on_unrecovered_nmi)
                panic("NMI: Not continuing");

	printk(KERN_EMERG "Dazed and confused, but trying to continue\n");

	/* Clear and disable the memory parity error line. */
	clear_mem_error(reason);
}

static __kprobes void
io_check_error(unsigned char reason, struct pt_regs * regs)
{
	unsigned long i;

	printk(KERN_EMERG "NMI: IOCK error (debug interrupt?)\n");
	show_registers(regs);

	/* Re-enable the IOCK line, wait for a few seconds */
	reason = (reason & 0xf) | 8;
	outb(reason, 0x61);
	i = 2000;
	while (--i) udelay(1000);
	reason &= ~8;
	outb(reason, 0x61);
}


#ifdef CONFIG_KPROBES
fastcall void __kprobes do_int3(struct pt_regs *regs, long error_code)
{
	trace_hardirqs_fixup();

	if (notify_die(DIE_INT3, "int3", regs, error_code, 3, SIGTRAP)
			== NOTIFY_STOP)
		return;
	/* This is an interrupt gate, because kprobes wants interrupts
	disabled.  Normal trap handlers don't. */
	restore_interrupts(regs);
	do_trap(3, SIGTRAP, "int3", 1, regs, error_code, NULL);
}
#endif

/*
 * Our handling of the processor debug registers is non-trivial.
 * We do not clear them on entry and exit from the kernel. Therefore
 * it is possible to get a watchpoint trap here from inside the kernel.
 * However, the code in ./ptrace.c has ensured that the user can
 * only set watchpoints on userspace addresses. Therefore the in-kernel
 * watchpoint trap can only occur in code which is reading/writing
 * from user space. Such code must not hold kernel locks (since it
 * can equally take a page fault), therefore it is safe to call
 * force_sig_info even though that claims and releases locks.
 * 
 * Code in ./signal.c ensures that the debug control register
 * is restored before we deliver any signal, and therefore that
 * user code runs with the correct debug control register even though
 * we clear it here.
 *
 * Being careful here means that we don't have to be as careful in a
 * lot of more complicated places (task switching can be a bit lazy
 * about restoring all the debug state, and ptrace doesn't have to
 * find every occurrence of the TF bit that could be saved away even
 * by user code)
 */
fastcall void __kprobes do_debug(struct pt_regs * regs, long error_code)
{
	unsigned int condition;
	struct task_struct *tsk = current;

	trace_hardirqs_fixup();

	get_debugreg(condition, 6);

	if (notify_die(DIE_DEBUG, "debug", regs, condition, error_code,
					SIGTRAP) == NOTIFY_STOP)
		return;
	/* It's safe to allow irq's after DR6 has been saved */
	if (regs->eflags & X86_EFLAGS_IF)
		local_irq_enable();

	/* Mask out spurious debug traps due to lazy DR7 setting */
	if (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) {
		if (!tsk->thread.debugreg[7])
			goto clear_dr7;
	}

	if (regs->eflags & VM_MASK)
		goto debug_vm86;

	/* Save debug status register where ptrace can see it */
	tsk->thread.debugreg[6] = condition;

	/*
	 * Single-stepping through TF: make sure we ignore any events in
	 * kernel space (but re-enable TF when returning to user mode).
	 */
	if (condition & DR_STEP) {
		/*
		 * We already checked v86 mode above, so we can
		 * check for kernel mode by just checking the CPL
		 * of CS.
		 */
		if (!user_mode(regs))
			goto clear_TF_reenable;
	}

	/* Ok, finally something we can handle */
	send_sigtrap(tsk, regs, error_code);

	/* Disable additional traps. They'll be re-enabled when
	 * the signal is delivered.
	 */
clear_dr7:
	set_debugreg(0, 7);
	return;

debug_vm86:
	handle_vm86_trap((struct kernel_vm86_regs *) regs, error_code, 1);
	return;

clear_TF_reenable:
	set_tsk_thread_flag(tsk, TIF_SINGLESTEP);
	regs->eflags &= ~TF_MASK;
	return;
}

fastcall unsigned long patch_espfix_desc(unsigned long uesp,
					  unsigned long kesp)
{
	struct desc_struct *gdt = __get_cpu_var(gdt_page).gdt;
	unsigned long base = (kesp - uesp) & -THREAD_SIZE;
	unsigned long new_kesp = kesp - base;
	unsigned long lim_pages = (new_kesp | (THREAD_SIZE - 1)) >> PAGE_SHIFT;
	__u64 desc = *(__u64 *)&gdt[GDT_ENTRY_ESPFIX_SS];
	/* Set up base for espfix segment */
 	desc &= 0x00f0ff0000000000ULL;
 	desc |=	((((__u64)base) << 16) & 0x000000ffffff0000ULL) |
		((((__u64)base) << 32) & 0xff00000000000000ULL) |
		((((__u64)lim_pages) << 32) & 0x000f000000000000ULL) |
		(lim_pages & 0xffff);
	*(__u64 *)&gdt[GDT_ENTRY_ESPFIX_SS] = desc;
	return new_kesp;
}

void set_intr_gate(unsigned int n, void *addr)
{
	_set_gate(n, DESCTYPE_INT, addr, __KERNEL_CS);
}

/*
 * This routine sets up an interrupt gate at directory privilege level 3.
 */
static inline void set_system_intr_gate(unsigned int n, void *addr)
{
	_set_gate(n, DESCTYPE_INT | DESCTYPE_DPL3, addr, __KERNEL_CS);
}

static void __init set_trap_gate(unsigned int n, void *addr)
{
	_set_gate(n, DESCTYPE_TRAP, addr, __KERNEL_CS);
}

static void __init set_system_gate(unsigned int n, void *addr)
{
	_set_gate(n, DESCTYPE_TRAP | DESCTYPE_DPL3, addr, __KERNEL_CS);
}

static void __init set_task_gate(unsigned int n, unsigned int gdt_entry)
{
	_set_gate(n, DESCTYPE_TASK, (void *)0, (gdt_entry<<3));
}


void __init trap_init(void)
{
	int i;

#ifdef CONFIG_EISA
	void __iomem *p = ioremap(0x0FFFD9, 4);
	if (readl(p) == 'E'+('I'<<8)+('S'<<16)+('A'<<24)) {
		EISA_bus = 1;
	}
	iounmap(p);
#endif

#ifdef CONFIG_X86_LOCAL_APIC
	init_apic_mappings();
#endif

	set_trap_gate(0,&divide_error);
	set_intr_gate(1,&debug);
	set_intr_gate(2,&nmi);
	set_system_intr_gate(3, &int3); /* int3/4 can be called from all */
	set_system_gate(4,&overflow);
	set_trap_gate(5,&bounds);
	set_trap_gate(6,&invalid_op);
	set_trap_gate(7,&device_not_available);
	set_task_gate(8,GDT_ENTRY_DOUBLEFAULT_TSS);
	set_trap_gate(9,&coprocessor_segment_overrun);
	set_trap_gate(10,&invalid_TSS);
	set_trap_gate(11,&segment_not_present);
	set_trap_gate(12,&stack_segment);
	set_trap_gate(13,&general_protection);
	set_intr_gate(14,&page_fault);
	set_trap_gate(15,&spurious_interrupt_bug);
	set_trap_gate(16,&coprocessor_error);
	set_trap_gate(17,&alignment_check);
#ifdef CONFIG_X86_MCE
	set_trap_gate(18,&machine_check);
#endif
	set_trap_gate(19,&simd_coprocessor_error);

	if (cpu_has_fxsr) {
		/*
		 * Verify that the FXSAVE/FXRSTOR data will be 16-byte aligned.
		 * Generates a compile-time "error: zero width for bit-field" if
		 * the alignment is wrong.
		 */
		struct fxsrAlignAssert {
			int _:!(offsetof(struct task_struct,
					thread.i387.fxsave) & 15);
		};

		printk(KERN_INFO "Enabling fast FPU save and restore... ");
		set_in_cr4(X86_CR4_OSFXSR);
		printk("done.\n");
	}
	if (cpu_has_xmm) {
		printk(KERN_INFO "Enabling unmasked SIMD FPU exception "
				"support... ");
		set_in_cr4(X86_CR4_OSXMMEXCPT);
		printk("done.\n");
	}

	set_system_gate(SYSCALL_VECTOR,&system_call);

	/* Reserve all the builtin and the syscall vector. */
	for (i = 0; i < FIRST_EXTERNAL_VECTOR; i++)
		set_bit(i, used_vectors);
	set_bit(SYSCALL_VECTOR, used_vectors);

	/*
	 * Should be a barrier for any external CPU state.
	 */
	cpu_init();

	trap_init_hook();
}


struct Xgt_desc_struct {
	unsigned short size;
	unsigned long address __attribute__((packed));
	unsigned short pad;
} __attribute__ ((packed));

struct gdt_page
{
	struct desc_struct gdt[GDT_ENTRIES];
} __attribute__((aligned(PAGE_SIZE)));
DECLARE_PER_CPU(struct gdt_page, gdt_page);

static inline struct desc_struct *get_cpu_gdt_table(unsigned int cpu)
{
	return per_cpu(gdt_page, cpu).gdt;
}

extern struct Xgt_desc_struct idt_descr;
extern struct desc_struct idt_table[];
extern void set_intr_gate(unsigned int irq, void * addr);

static inline void pack_descriptor(__u32 *a, __u32 *b,
	unsigned long base, unsigned long limit, unsigned char type, unsigned char flags)
{
	*a = ((base & 0xffff) << 16) | (limit & 0xffff);
	*b = (base & 0xff000000) | ((base & 0xff0000) >> 16) |
		(limit & 0x000f0000) | ((type & 0xff) << 8) | ((flags & 0xf) << 20);
}

static inline void pack_gate(__u32 *a, __u32 *b,
	unsigned long base, unsigned short seg, unsigned char type, unsigned char flags)
{
	*a = (seg << 16) | (base & 0xffff);
	*b = (base & 0xffff0000) | ((type & 0xff) << 8) | (flags & 0xff);
}

#define DESCTYPE_LDT 	0x82	/* present, system, DPL-0, LDT */
#define DESCTYPE_TSS 	0x89	/* present, system, DPL-0, 32-bit TSS */
#define DESCTYPE_TASK	0x85	/* present, system, DPL-0, task gate */
#define DESCTYPE_INT	0x8e	/* present, system, DPL-0, interrupt gate */
#define DESCTYPE_TRAP	0x8f	/* present, system, DPL-0, trap gate */
#define DESCTYPE_DPL3	0x60	/* DPL-3 */
#define DESCTYPE_S	0x10	/* !system */

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
#define load_TR_desc() native_load_tr_desc()
#define load_gdt(dtr) native_load_gdt(dtr)
#define load_idt(dtr) native_load_idt(dtr)
#define load_tr(tr) __asm__ __volatile("ltr %0"::"m" (tr))
#define load_ldt(ldt) __asm__ __volatile("lldt %0"::"m" (ldt))

#define store_gdt(dtr) native_store_gdt(dtr)
#define store_idt(dtr) native_store_idt(dtr)
#define store_tr(tr) (tr = native_store_tr())
#define store_ldt(ldt) __asm__ ("sldt %0":"=m" (ldt))

#define load_TLS(t, cpu) native_load_tls(t, cpu)
#define set_ldt native_set_ldt

#define write_ldt_entry(dt, entry, a, b) write_dt_entry(dt, entry, a, b)
#define write_gdt_entry(dt, entry, a, b) write_dt_entry(dt, entry, a, b)
#define write_idt_entry(dt, entry, a, b) write_dt_entry(dt, entry, a, b)
#endif

static inline void write_dt_entry(struct desc_struct *dt,
				  int entry, u32 entry_low, u32 entry_high)
{
	dt[entry].a = entry_low;
	dt[entry].b = entry_high;
}

static inline void native_set_ldt(const void *addr, unsigned int entries)
{
	if (likely(entries == 0))
		__asm__ __volatile__("lldt %w0"::"q" (0));
	else {
		unsigned cpu = smp_processor_id();
		__u32 a, b;

		pack_descriptor(&a, &b, (unsigned long)addr,
				entries * sizeof(struct desc_struct) - 1,
				DESCTYPE_LDT, 0);
		write_gdt_entry(get_cpu_gdt_table(cpu), GDT_ENTRY_LDT, a, b);
		__asm__ __volatile__("lldt %w0"::"q" (GDT_ENTRY_LDT*8));
	}
}


static inline void native_load_tr_desc(void)
{
	asm volatile("ltr %w0"::"q" (GDT_ENTRY_TSS*8));
}

static inline void native_load_gdt(const struct Xgt_desc_struct *dtr)
{
	asm volatile("lgdt %0"::"m" (*dtr));
}

static inline void native_load_idt(const struct Xgt_desc_struct *dtr)
{
	asm volatile("lidt %0"::"m" (*dtr));
}

static inline void native_store_gdt(struct Xgt_desc_struct *dtr)
{
	asm ("sgdt %0":"=m" (*dtr));
}

static inline void native_store_idt(struct Xgt_desc_struct *dtr)
{
	asm ("sidt %0":"=m" (*dtr));
}

static inline unsigned long native_store_tr(void)
{
	unsigned long tr;
	asm ("str %0":"=r" (tr));
	return tr;
}

static inline void native_load_tls(struct thread_struct *t, unsigned int cpu)
{
	unsigned int i;
	struct desc_struct *gdt = get_cpu_gdt_table(cpu);

	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++)
		gdt[GDT_ENTRY_TLS_MIN + i] = t->tls_array[i];
}

static inline void _set_gate(int gate, unsigned int type, void *addr, unsigned short seg)
{
	__u32 a, b;
	pack_gate(&a, &b, (unsigned long)addr, seg, type, 0);
	write_idt_entry(idt_table, gate, a, b);
}

static inline void __set_tss_desc(unsigned int cpu, unsigned int entry, const void *addr)
{
	__u32 a, b;
	pack_descriptor(&a, &b, (unsigned long)addr,
			offsetof(struct tss_struct, __cacheline_filler) - 1,
			DESCTYPE_TSS, 0);
	write_gdt_entry(get_cpu_gdt_table(cpu), entry, a, b);
}


#define set_tss_desc(cpu,addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)

#define LDT_entry_a(info) \
	((((info)->base_addr & 0x0000ffff) << 16) | ((info)->limit & 0x0ffff))

#define LDT_entry_b(info) \
	(((info)->base_addr & 0xff000000) | \
	(((info)->base_addr & 0x00ff0000) >> 16) | \
	((info)->limit & 0xf0000) | \
	(((info)->read_exec_only ^ 1) << 9) | \
	((info)->contents << 10) | \
	(((info)->seg_not_present ^ 1) << 15) | \
	((info)->seg_32bit << 22) | \
	((info)->limit_in_pages << 23) | \
	((info)->useable << 20) | \
	0x7000)

#define LDT_empty(info) (\
	(info)->base_addr	== 0	&& \
	(info)->limit		== 0	&& \
	(info)->contents	== 0	&& \
	(info)->read_exec_only	== 1	&& \
	(info)->seg_32bit	== 0	&& \
	(info)->limit_in_pages	== 0	&& \
	(info)->seg_not_present	== 1	&& \
	(info)->useable		== 0	)

static inline void clear_LDT(void)
{
	set_ldt(NULL, 0);
}

/*
 * load one particular LDT into the current CPU
 */
static inline void load_LDT_nolock(mm_context_t *pc)
{
	set_ldt(pc->ldt, pc->size);
}

static inline void load_LDT(mm_context_t *pc)
{
	preempt_disable();
	load_LDT_nolock(pc);
	preempt_enable();
}

static inline unsigned long get_desc_base(unsigned long *desc)
{
	unsigned long base;
	base = ((desc[0] >> 16)  & 0x0000ffff) |
		((desc[1] << 16) & 0x00ff0000) |
		(desc[1] & 0xff000000);
	return base;
}

#else /* __ASSEMBLY__ */

/*
 * GET_DESC_BASE reads the descriptor base of the specified segment.
 *
 * Args:
 *    idx - descriptor index
 *    gdt - GDT pointer
 *    base - 32bit register to which the base will be written
 *    lo_w - lo word of the "base" register
 *    lo_b - lo byte of the "base" register
 *    hi_b - hi byte of the low word of the "base" register
 *
 * Example:
 *    GET_DESC_BASE(GDT_ENTRY_ESPFIX_SS, %ebx, %eax, %ax, %al, %ah)
 *    Will read the base address of GDT_ENTRY_ESPFIX_SS and put it into %eax.
 */
#define GET_DESC_BASE(idx, gdt, base, lo_w, lo_b, hi_b) \
	movb idx*8+4(gdt), lo_b; \
	movb idx*8+7(gdt), hi_b; \
	shll $16, base; \
	movw idx*8+2(gdt), lo_w;

#endif /* !__ASSEMBLY__ */

#endif

struct thread_info {
	struct task_struct	*task;		/* main task structure */
	struct exec_domain	*exec_domain;	/* execution domain */
	unsigned long		flags;		/* low level flags */
	unsigned long		status;		/* thread-synchronous flags */
	__u32			cpu;		/* current CPU */
	int			preempt_count;	/* 0 => preemptable, <0 => BUG */


	mm_segment_t		addr_limit;	/* thread address space:
					 	   0-0xBFFFFFFF for user-thead
						   0-0xFFFFFFFF for kernel-thread
						*/
	void			*sysenter_return;
	struct restart_block    restart_block;

	unsigned long           previous_esp;   /* ESP of the previous stack in case
						   of nested (IRQ) stacks
						*/
	__u8			supervisor_stack[0];
};

union irq_ctx {
	struct thread_info      tinfo;
	u32                     stack[THREAD_SIZE/sizeof(u32)];
};

static union irq_ctx *hardirq_ctx[NR_CPUS] __read_mostly;
static union irq_ctx *softirq_ctx[NR_CPUS] __read_mostly;



//之前在创进程的时候预留2个位置，猜是如果不留，则regs指针所指向的区域会超出去
由common_interrupt进入
/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
fastcall unsigned int do_IRQ(struct pt_regs *regs)
{	
	struct pt_regs *old_regs;
	/* high bit used in ret_from_ code */
	int irq = ~regs->orig_eax;
	struct irq_desc *desc = irq_desc + irq;
#ifdef CONFIG_4KSTACKS
	union irq_ctx *curctx, *irqctx;
	u32 *isp;
#endif

	old_regs = set_irq_regs(regs);
    //add_preempt_count(HARDIRQ_OFFSET);	\
	irq_enter();
#ifdef CONFIG_4KSTACKS

	curctx = (union irq_ctx *) current_thread_info();
	irqctx = hardirq_ctx[smp_processor_id()];

    //是否已经切换了栈了
	if (curctx != irqctx) {
		int arg1, arg2, ebx;

		/* build the stack frame on the IRQ stack */
		isp = (u32*) ((char*)irqctx + sizeof(*irqctx));
        //设置current
		irqctx->tinfo.task = curctx->tinfo.task;
        //保存当前栈指针
		irqctx->tinfo.previous_esp = current_stack_pointer;

        //复制irqmask到4K栈
		irqctx->tinfo.preempt_count =
			(irqctx->tinfo.preempt_count & ~SOFTIRQ_MASK) |
			(curctx->tinfo.preempt_count & SOFTIRQ_MASK);

        ebx = isp
        //交换ebx,esp，调handle_irq，完事ebx再赋给esp
		asm volatile(
			"       xchgl  %%ebx,%%esp      \n"
			"       call   *%%edi           \n"
			"       movl   %%ebx,%%esp      \n"
			: "=a" (arg1), "=d" (arg2), "=b" (ebx)
			:  "0" (irq),   "1" (desc),  "2" (isp),
			   "D" (desc->handle_irq)
			: "memory", "cc"
		);
	} else
#endif
		desc->handle_irq(irq, desc);

	irq_exit();
	set_irq_regs(old_regs);
	return 1;
}



#ifdef CONFIG_4KSTACKS

static char softirq_stack[NR_CPUS * THREAD_SIZE]
		__attribute__((__section__(".bss.page_aligned")));

static char hardirq_stack[NR_CPUS * THREAD_SIZE]
		__attribute__((__section__(".bss.page_aligned")));


中断的初始化在init_IRQ中
init_IRQ初始化8259控制器，将irq_desc和8259联系起来
interrupt数组


#define IRQ(x,y) \
	IRQ##x##y##_interrupt

#define IRQLIST_16(x) \
	IRQ(x,0), IRQ(x,1), IRQ(x,2), IRQ(x,3), \
	IRQ(x,4), IRQ(x,5), IRQ(x,6), IRQ(x,7), \
	IRQ(x,8), IRQ(x,9), IRQ(x,a), IRQ(x,b), \
	IRQ(x,c), IRQ(x,d), IRQ(x,e), IRQ(x,f)

/* for the irq vectors */
static void (*interrupt[NR_VECTORS - FIRST_EXTERNAL_VECTOR])(void) = {
					  IRQLIST_16(0x2), IRQLIST_16(0x3),
	IRQLIST_16(0x4), IRQLIST_16(0x5), IRQLIST_16(0x6), IRQLIST_16(0x7),
	IRQLIST_16(0x8), IRQLIST_16(0x9), IRQLIST_16(0xa), IRQLIST_16(0xb),
	IRQLIST_16(0xc), IRQLIST_16(0xd), IRQLIST_16(0xe), IRQLIST_16(0xf)
};
