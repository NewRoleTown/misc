v2.6.24的gdt布局如下所示

/*
 * The layout of the per-CPU GDT under Linux:
 *
 *   0 - null
 *   1 - reserved
 *   2 - reserved
 *   3 - reserved
 *
 *   4 - unused			<==== new cacheline
 *   5 - unused
 *
 *  ------- start of TLS (Thread-Local Storage) segments:
 *
 *   6 - TLS segment #1			[ glibc's TLS segment ]
 *   7 - TLS segment #2			[ Wine's %fs Win32 segment ]
 *   8 - TLS segment #3
 *   9 - reserved
 *  10 - reserved
 *  11 - reserved
 *
 *  ------- start of kernel segments:
 *
 *  12 - kernel code segment		<==== new cacheline
 *  13 - kernel data segment
 *  14 - default user CS
 *  15 - default user DS
 *  16 - TSS					//linux不用
 *  17 - LDT
 *  18 - PNPBIOS support (16->32 gate)
 *  19 - PNPBIOS support
 *  20 - PNPBIOS support
 *  21 - PNPBIOS support
 *  22 - PNPBIOS support
 *  23 - APM BIOS support
 *  24 - APM BIOS support
 *  25 - APM BIOS support 
 *
 *  26 - ESPFIX small SS
 *  27 - per-cpu			[ offset to per-cpu data area ]
 *  28 - unused
 *  29 - unused
 *  30 - unused
 *  31 - TSS for double fault handler
 */


//多核处理器每个核有一个gdt,它的存储和获取如下
struct gdt_page
{
	struct desc_struct gdt[GDT_ENTRIES];
} __attribute__((aligned(PAGE_SIZE)));
DECLARE_PER_CPU(struct gdt_page, gdt_page);

static inline struct desc_struct *get_cpu_gdt_table(unsigned int cpu)
{
	return per_cpu(gdt_page, cpu).gdt;
}


kernel_init---->//此函数是rest_init创建的线程,rest_init在start_kernel中（结尾处）
	smp_prepare_cpus(max_cpus);------>
		native_smp_prepare_cpus;--------->
static void __init smp_boot_cpus(unsigned int max_cpus)--------->
				do_boot_cpu//boot的cpu不调这个函数
				----->init_gdt

do_boot_cpu中
start_eip = setup_trampoline();
这里获取的是跳板函数的物理地址
apic_write_around(APIC_ICR, APIC_DM_STARTUP
					| (start_eip >> 12));
激活这个cpu，以实模式从start_eip运行

跳板相关定义
ENTRY(trampoline_data)
r_base = .
	wbinvd			# Needed for NUMA-Q should be harmless for others
	mov	%cs, %ax	# Code and data in the same place
	mov	%ax, %ds

	cli			# We should be safe anyway

	movl	$0xA5A5A5A5, trampoline_data - r_base
				# write marker for master knows we're running

	/* GDT tables in non default location kernel can be beyond 16MB and
	 * lgdt will not be able to load the address as in real mode default
	 * operand size is 16bit. Use lgdtl instead to force operand size
	 * to 32 bit.
	 */

	lidtl	boot_idt_descr - r_base	# load idt with 0, 0
	lgdtl	boot_gdt_descr - r_base	# load gdt with whatever is appropriate

	xor	%ax, %ax
	inc	%ax		# protected mode (PE) bit
	//开a20是老方法
	lmsw	%ax		# into protected mode
	# flush prefetch and jump to startup_32_smp in arch/i386/kernel/head.S
	ljmpl	$__BOOT_CS, $(startup_32_smp-__PAGE_OFFSET)

	# These need to be in the same 64K segment as the above;
	# hence we don't use the boot_gdt_descr defined in head.S
boot_gdt_descr:
	.word	__BOOT_DS + 7			# gdt limit
	.long	boot_gdt - __PAGE_OFFSET	# gdt base

boot_idt_descr:
	.word	0				# idt limit = 0
	.long	0				# idt base = 0L

.globl trampoline_end
trampoline_end:


__cpuinit void init_gdt(int cpu)
{
	struct desc_struct *gdt = get_cpu_gdt_table(cpu);

	//per_cpu段不同
	pack_descriptor((u32 *)&gdt[GDT_ENTRY_PERCPU].a,
			(u32 *)&gdt[GDT_ENTRY_PERCPU].b,
			__per_cpu_offset[cpu], 0xFFFFF,
			0x80 | DESCTYPE_S | 0x2, 0x8);

	per_cpu(this_cpu_off, cpu) = __per_cpu_offset[cpu];
	per_cpu(cpu_number, cpu) = cpu;
}

//do_boot_cpu后会进这个流程
void __cpuinit cpu_init(void)
{
	int cpu = smp_processor_id();
	struct task_struct *curr = current;
	//由do_boot_cpu设置好
	struct tss_struct * t = &per_cpu(init_tss, cpu);
	struct thread_struct *thread = &curr->thread;

	if (cpu_test_and_set(cpu, cpu_initialized)) {
		printk(KERN_WARNING "CPU#%d already initialized!\n", cpu);
		for (;;) local_irq_enable();
	}

	printk(KERN_INFO "Initializing CPU#%d\n", cpu);
	{...CR4相关}

	//load idt,切换gdt
	load_idt(&idt_descr);
	switch_to_new_gdt();

	/*
	 * Set up and load the per-CPU TSS and LDT
	 */
	atomic_inc(&init_mm.mm_count);
	curr->active_mm = &init_mm;
	if (curr->mm)
		BUG();
	enter_lazy_tlb(&init_mm, curr);

	//设置TSS的esp0
	load_esp0(t, thread);
	//设置TSS到gdt
	set_tss_desc(cpu,t);
	load_TR_desc();
	load_LDT(&init_mm.context);

#ifdef CONFIG_DOUBLEFAULT
	/* Set up doublefault TSS pointer in the GDT */
	__set_tss_desc(cpu, GDT_ENTRY_DOUBLEFAULT_TSS, &doublefault_tss);
#endif

	/* Clear %gs. */
	asm volatile ("mov %0, %%gs" : : "r" (0));

	/* Clear all 6 debug registers: */
	set_debugreg(0, 0);
	set_debugreg(0, 1);
	set_debugreg(0, 2);
	set_debugreg(0, 3);
	set_debugreg(0, 6);
	set_debugreg(0, 7);

	/*
	 * Force FPU initialization:
	 */
	current_thread_info()->status = 0;
	clear_used_math();
	mxcsr_feature_mask_init();
}


--------------------PER_CPU------------------------

unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;
#define PERCPU_ENOUGH_ROOM						\
	(__per_cpu_end - __per_cpu_start + PERCPU_MODULE_RESERVE)

static void __init setup_per_cpu_areas(void)
{
	unsigned long size, i;
	char *ptr;
	unsigned long nr_possible_cpus = num_possible_cpus();

	/* Copy section for each CPU (we discard the original) */
	//大小由链接脚本给出
	size = ALIGN(PERCPU_ENOUGH_ROOM, PAGE_SIZE);
	ptr = alloc_bootmem_pages(size * nr_possible_cpus);

	//每个cpu获取一个地址，将.data.percpu中的内容拷贝到这个地址
	for_each_possible_cpu(i) {
		__per_cpu_offset[i] = ptr - __per_cpu_start;
		memcpy(ptr, __per_cpu_start, __per_cpu_end - __per_cpu_start);
		ptr += size;
	}
}
