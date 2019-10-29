/* ld script to make i386 Linux kernel
 * Written by Martin Mares <mj@atrey.karlin.mff.cuni.cz>;
 *
 * Don't define absolute symbols until and unless you know that symbol
 * value is should remain constant even if kernel image is relocated
 * at run time. Absolute symbols are not relocated. If symbol value should
 * change if kernel is relocated, make the symbol section relative and
 * put it inside the section definition.
 */

/* Don't define absolute symbols until and unless you know that symbol
 * value is should remain constant even if kernel image is relocated
 * at run time. Absolute symbols are not relocated. If symbol value should
 * change if kernel is relocated, make the symbol section relative and
 * put it inside the section definition.
 */
#define LOAD_OFFSET __PAGE_OFFSET

#include <asm-generic/vmlinux.lds.h>
#include <asm/thread_info.h>
#include <asm/page.h>
#include <asm/cache.h>
#include <asm/boot.h>

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(phys_startup_32)
jiffies = jiffies_64;

PHDRS {
	text PT_LOAD FLAGS(5);	/* R_E */
	data PT_LOAD FLAGS(7);	/* RWE */
	note PT_NOTE FLAGS(0);	/* ___ */
}


32位初始布局如下
0-4k第一个页帧
随后为640k可用至0x9e800
之后一段映射内存
0x100000开始是内核代码_text标号至_etext,内核获取的这些标号似乎是va
之后是数据至_edata
之后是bss至_end
arch/x86/kernel/setup_32.c中有详细记录过程，但是这些标号的值是在打包为二进制文件时才生成的
arch/x86/vmlinux_32.ld.S控制
System.map

/proc/iomem也提供物理内存划分的一些信息
SECTIONS
{
  . = LOAD_OFFSET + LOAD_PHYSICAL_ADDR;
  phys_startup_32 = startup_32 - LOAD_OFFSET;

  .text.head : AT(ADDR(.text.head) - LOAD_OFFSET) {
  	_text = .;			/* Text and read-only data */
	*(.text.head)
  } :text = 0x9090

  /* read-only */
  .text : AT(ADDR(.text) - LOAD_OFFSET) {
	TEXT_TEXT
	SCHED_TEXT
	LOCK_TEXT
	KPROBES_TEXT
	*(.fixup)
	*(.gnu.warning)
  	_etext = .;			/* End of text section */
  } :text = 0x9090

  . = ALIGN(16);		/* Exception table */
  __ex_table : AT(ADDR(__ex_table) - LOAD_OFFSET) {
  	__start___ex_table = .;
	 *(__ex_table)
  	__stop___ex_table = .;
  }

  NOTES :text :note

  BUG_TABLE :text

  . = ALIGN(4);
  .tracedata : AT(ADDR(.tracedata) - LOAD_OFFSET) {
  	__tracedata_start = .;
	*(.tracedata)
  	__tracedata_end = .;
  }

  RODATA

  /* writeable */
  . = ALIGN(4096);
  .data : AT(ADDR(.data) - LOAD_OFFSET) {	/* Data */
	DATA_DATA
	CONSTRUCTORS
	} :data

  . = ALIGN(4096);
  .data_nosave : AT(ADDR(.data_nosave) - LOAD_OFFSET) {
  	__nosave_begin = .;
	*(.data.nosave)
  	. = ALIGN(4096);
  	__nosave_end = .;
  }

  . = ALIGN(4096);
  .data.page_aligned : AT(ADDR(.data.page_aligned) - LOAD_OFFSET) {
	*(.data.page_aligned)
	*(.data.idt)
  }

  . = ALIGN(32);
  .data.cacheline_aligned : AT(ADDR(.data.cacheline_aligned) - LOAD_OFFSET) {
	*(.data.cacheline_aligned)
  }

  /* rarely changed data like cpu maps */
  . = ALIGN(32);
  .data.read_mostly : AT(ADDR(.data.read_mostly) - LOAD_OFFSET) {
	*(.data.read_mostly)
	_edata = .;		/* End of data section */
  }

  . = ALIGN(THREAD_SIZE);	/* init_task */
  .data.init_task : AT(ADDR(.data.init_task) - LOAD_OFFSET) {
	*(.data.init_task)
  }

  /* might get freed after init */
  . = ALIGN(4096);
  .smp_locks : AT(ADDR(.smp_locks) - LOAD_OFFSET) {
  	__smp_locks = .;
	*(.smp_locks)
	__smp_locks_end = .;
  }
  /* will be freed after init
   * Following ALIGN() is required to make sure no other data falls on the
   * same page where __smp_alt_end is pointing as that page might be freed
   * after boot. Always make sure that ALIGN() directive is present after
   * the section which contains __smp_alt_end.
   */
  . = ALIGN(4096);

  /* will be freed after init */
  . = ALIGN(4096);		/* Init code and data */
  .init.text : AT(ADDR(.init.text) - LOAD_OFFSET) {
  	__init_begin = .;
	_sinittext = .;
	*(.init.text)
	_einittext = .;
  }
  .init.data : AT(ADDR(.init.data) - LOAD_OFFSET) { *(.init.data) }
  . = ALIGN(16);
  .init.setup : AT(ADDR(.init.setup) - LOAD_OFFSET) {
  	__setup_start = .;
	*(.init.setup)
  	__setup_end = .;
   }
  .initcall.init : AT(ADDR(.initcall.init) - LOAD_OFFSET) {
  	__initcall_start = .;
	INITCALLS
  	__initcall_end = .;
  }
  .con_initcall.init : AT(ADDR(.con_initcall.init) - LOAD_OFFSET) {
  	__con_initcall_start = .;
	*(.con_initcall.init)
  	__con_initcall_end = .;
  }
  SECURITY_INIT
  . = ALIGN(4);
  .altinstructions : AT(ADDR(.altinstructions) - LOAD_OFFSET) {
  	__alt_instructions = .;
	*(.altinstructions)
	__alt_instructions_end = .;
  }
  .altinstr_replacement : AT(ADDR(.altinstr_replacement) - LOAD_OFFSET) {
	*(.altinstr_replacement)
  }
  . = ALIGN(4);
  .parainstructions : AT(ADDR(.parainstructions) - LOAD_OFFSET) {
  	__parainstructions = .;
	*(.parainstructions)
  	__parainstructions_end = .;
  }
  /* .exit.text is discard at runtime, not link time, to deal with references
     from .altinstructions and .eh_frame */
  .exit.text : AT(ADDR(.exit.text) - LOAD_OFFSET) { *(.exit.text) }
  .exit.data : AT(ADDR(.exit.data) - LOAD_OFFSET) { *(.exit.data) }
#if defined(CONFIG_BLK_DEV_INITRD)
  . = ALIGN(4096);
  .init.ramfs : AT(ADDR(.init.ramfs) - LOAD_OFFSET) {
	__initramfs_start = .;
	*(.init.ramfs)
	__initramfs_end = .;
  }
#endif
  . = ALIGN(4096);
  .data.percpu  : AT(ADDR(.data.percpu) - LOAD_OFFSET) {
	__per_cpu_start = .;
	*(.data.percpu)
	*(.data.percpu.shared_aligned)
	__per_cpu_end = .;
  }
  . = ALIGN(4096);
  /* freed after init ends here */
	
  .bss : AT(ADDR(.bss) - LOAD_OFFSET) {
	__init_end = .;
	__bss_start = .;		/* BSS */
	*(.bss.page_aligned)
	*(.bss)
	. = ALIGN(4);
	__bss_stop = .;
  	_end = . ;
	/* This is where the kernel creates the early boot page tables */
	. = ALIGN(4096);
	pg0 = . ;
  }

  /* Sections to be discarded */
  /DISCARD/ : {
	*(.exitcall.exit)
	}

  STABS_DEBUG

  DWARF_DEBUG
}

//可见swapper_pg_dir存在于内核BSS段
.section ".bss.page_aligned","wa"
	.align PAGE_SIZE_asm
ENTRY(swapper_pg_dir)
	.fill 1024,4,0
ENTRY(swapper_pg_pmd)
	.fill 1024,4,0
ENTRY(empty_zero_page)
	.fill 4096,1,0


dmesg输出
[    0.000000] e820: BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009d7ff] usable
[    0.000000] BIOS-e820: [mem 0x000000000009d800-0x000000000009ffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000000e0000-0x00000000000fffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000d241efff] usable
[    0.000000] BIOS-e820: [mem 0x00000000d241f000-0x00000000d2425fff] ACPI NVS
[    0.000000] BIOS-e820: [mem 0x00000000d2426000-0x00000000d285cfff] usable
[    0.000000] BIOS-e820: [mem 0x00000000d285d000-0x00000000d2c88fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000d2c89000-0x00000000d7ee3fff] usable
[    0.000000] BIOS-e820: [mem 0x00000000d7ee4000-0x00000000d7ffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000d8000000-0x00000000d875dfff] usable
[    0.000000] BIOS-e820: [mem 0x00000000d875e000-0x00000000d87fffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000d8800000-0x00000000d8fadfff] usable
[    0.000000] BIOS-e820: [mem 0x00000000d8fae000-0x00000000d8ffffff] ACPI data
[    0.000000] BIOS-e820: [mem 0x00000000d9000000-0x00000000da71bfff] usable
[    0.000000] BIOS-e820: [mem 0x00000000da71c000-0x00000000da7fffff] ACPI NVS
[    0.000000] BIOS-e820: [mem 0x00000000da800000-0x00000000db7fffff] usable
[    0.000000] BIOS-e820: [mem 0x00000000db800000-0x00000000dbffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000dd000000-0x00000000df1fffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000f8000000-0x00000000fbffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fec00000-0x00000000fec00fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fed00000-0x00000000fed03fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fed1c000-0x00000000fed1ffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fee00000-0x00000000fee00fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000ff000000-0x00000000ffffffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000041fdfffff] usable
[    0.000000] NX (Execute Disable) protection: active

setup_arch中获取上表
之后算出几个内存域的界限
以及初始化bootmem管理

//2.6 code
void __init setup_arch(char **cmdline_p)
{
	unsigned long max_low_pfn;

	memcpy(&boot_cpu_data, &new_cpu_data, sizeof(new_cpu_data));
	pre_setup_arch_hook();
	early_cpu_init();

	/*
	 * FIXME: This isn't an official loader_type right
	 * now but does currently work with elilo.
	 * If we were configured as an EFI kernel, check to make
	 * sure that we were loaded correctly from elilo and that
	 * the system table is valid.  If not, then initialize normally.
	 */
#ifdef CONFIG_EFI
	if ((boot_params.hdr.type_of_loader == 0x50) &&
			boot_params.efi_info.efi_systab)
		efi_enabled = 1;
#endif

	//根设备号
	ROOT_DEV = old_decode_dev(boot_params.hdr.root_dev);
	screen_info = boot_params.screen_info;
	edid_info = boot_params.edid_info;
	apm_info.bios = boot_params.apm_bios_info;
	ist_info = boot_params.ist_info;
	saved_videomode = boot_params.hdr.vid_mode;
	if( boot_params.sys_desc_table.length != 0 ) {
		set_mca_bus(boot_params.sys_desc_table.table[3] & 0x2);
		machine_id = boot_params.sys_desc_table.table[0];
		machine_submodel_id = boot_params.sys_desc_table.table[1];
		BIOS_revision = boot_params.sys_desc_table.table[2];
	}
	bootloader_type = boot_params.hdr.type_of_loader;

#ifdef CONFIG_BLK_DEV_RAM
	rd_image_start = boot_params.hdr.ram_size & RAMDISK_IMAGE_START_MASK;
	rd_prompt = ((boot_params.hdr.ram_size & RAMDISK_PROMPT_FLAG) != 0);
	rd_doload = ((boot_params.hdr.ram_size & RAMDISK_LOAD_FLAG) != 0);
#endif
	ARCH_SETUP
		if (efi_enabled)
			efi_init();
		else {
			printk(KERN_INFO "BIOS-provided physical RAM map:\n");
			print_memory_map(memory_setup());
		}

	copy_edd();
	if (!boot_params.hdr.root_flags)
		root_mountflags &= ~MS_RDONLY;
	//代码段的起始位置，按照链接脚本的意思是虚拟地址
	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	//第一个可用位置
	init_mm.brk = init_pg_tables_end + PAGE_OFFSET;

	//物理地址
	code_resource.start = virt_to_phys(_text);
	code_resource.end = virt_to_phys(_etext)-1;
	data_resource.start = virt_to_phys(_etext);
	data_resource.end = virt_to_phys(_edata)-1;
	bss_resource.start = virt_to_phys(&__bss_start);
	bss_resource.end = virt_to_phys(&__bss_stop)-1;

	parse_early_param();

	if (user_defined_memmap) {
		printk(KERN_INFO "user-defined physical RAM map:\n");
		print_memory_map("user");
	}

	strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = command_line;

	max_low_pfn = setup_memory();

#ifdef CONFIG_VMI
	/*
	 * Must be after max_low_pfn is determined, and before kernel
	 * pagetables are setup.
	 */
	vmi_init();
#endif

	/*
	 * NOTE: before this point _nobody_ is allowed to allocate
	 * any memory using the bootmem allocator.  Although the
	 * allocator is now initialised only the first 8Mb of the kernel
	 * virtual address space has been mapped.  All allocations before
	 * paging_init() has completed must use the alloc_bootmem_low_pages()
	 * variant (which allocates DMA'able memory) and care must be taken
	 * not to exceed the 8Mb limit.
	 */

#ifdef CONFIG_SMP
	//多核CPU实模式初始化时的内存的分配
	smp_alloc_memory(); /* AP processor realmode stacks in low memory*/
#endif
	//下面开启分页
	paging_init();
	remapped_pgdat_init();
	sparse_init();
	zone_sizes_init();

	/*
	 * NOTE: at this point the bootmem allocator is fully available.
	 */

	paravirt_post_allocator_init();

	dmi_scan_machine();

#ifdef CONFIG_X86_GENERICARCH
	generic_apic_probe();
#endif	
	if (efi_enabled)
		efi_map_memmap();

#ifdef CONFIG_ACPI
	/*
	 * Parse the ACPI tables for possible boot-time SMP configuration.
	 */
	acpi_boot_table_init();
#endif

#ifdef CONFIG_PCI
	early_quirks();
#endif

#ifdef CONFIG_ACPI
	acpi_boot_init();

#if defined(CONFIG_SMP) && defined(CONFIG_X86_PC)
	if (def_to_bigsmp)
		printk(KERN_WARNING "More than 8 CPUs detected and "
				"CONFIG_X86_PC cannot handle it.\nUse "
				"CONFIG_X86_GENERICARCH or CONFIG_X86_BIGSMP.\n");
#endif
#endif
#ifdef CONFIG_X86_LOCAL_APIC
	if (smp_found_config)
		get_smp_config();
#endif

	e820_register_memory();
	e820_mark_nosave_regions();

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	if (!efi_enabled || (efi_mem_type(0xa0000) != EFI_CONVENTIONAL_MEMORY))
		conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif
}


static unsigned long __init setup_memory(void)
{
	/*
	 * partially used pages are not usable - thus
	 * we are rounding upwards:
	 */
	//此处有疑问
	//end后面有4096个字节,再后面的位置空出来给页表，再之后就是min_low_pfn的位置，详见lds.S
	//最小可用页框号
	min_low_pfn = PFN_UP(init_pg_tables_end);

	//根据e820找出最大页框号
	find_max_pfn();

	//normal区最大页框号
	max_low_pfn = find_max_low_pfn();

#ifdef CONFIG_HIGHMEM
	highstart_pfn = highend_pfn = max_pfn;
	if (max_pfn > max_low_pfn) {
		highstart_pfn = max_low_pfn;
	}
	printk(KERN_NOTICE "%ldMB HIGHMEM available.\n",
			pages_to_mb(highend_pfn - highstart_pfn));
	num_physpages = highend_pfn;
	high_memory = (void *) __va(highstart_pfn * PAGE_SIZE - 1) + 1;
#else
	num_physpages = max_low_pfn;
	high_memory = (void *) __va(max_low_pfn * PAGE_SIZE - 1) + 1;
#endif
	printk(KERN_NOTICE "%ldMB LOWMEM available.\n",
			pages_to_mb(max_low_pfn));

	//mem_map的分配也在里面
	setup_bootmem_allocator();

	return max_low_pfn;
}


之后paging_init初始化页表
固定映射也在这里初始化
 
the length of vmalloc section
unsigned int __VMALLOC_RESERVE = 128 << 20;

/* Just any arbitrary offset to the start of the vmalloc VM area: the
 * current 8MB value just means that there will be a 8MB "hole" after the
 * physical memory until the kernel virtual memory starts.  That means that
 * any out-of-bounds memory accesses will hopefully be caught.
 * The vmalloc() routines leaves a hole of 4kB between each vmalloced
 * area for the same reason. ;)
 */
#define VMALLOC_OFFSET	(8 * 1024 * 1024)

#ifndef __ASSEMBLY__
extern bool __vmalloc_start_set; /* set once high_memory is set */
#endif

#define VMALLOC_START	((unsigned long)high_memory + VMALLOC_OFFSET)
#ifdef CONFIG_X86_PAE
#define LAST_PKMAP 512
#else
#define LAST_PKMAP 1024
#endif

#define PKMAP_BASE ((FIXADDR_BOOT_START - PAGE_SIZE * (LAST_PKMAP + 1))	\
		    & PMD_MASK)

#ifdef CONFIG_HIGHMEM
# define VMALLOC_END	(PKMAP_BASE - 2 * PAGE_SIZE)
#else
# define VMALLOC_END	(FIXADDR_START - 2 * PAGE_SIZE)
#endif

#define MODULES_VADDR	VMALLOC_START
#define MODULES_END	VMALLOC_END
#define MODULES_LEN	(MODULES_VADDR - MODULES_END)

#define MAXMEM	(VMALLOC_END - PAGE_OFFSET - __VMALLOC_RESERVE)

MAXMEM
/*
 * paging_init() sets up the page tables - note that the first 8MB are
 * already mapped by head.S.
 *
 * This routines also unmaps the page at virtual kernel address 0, so
 * that we can trap those pesky NULL-reference errors in the kernel.
 */
//2.6
void __init paging_init(void)
{
	//PAE部分省略
	pagetable_init();

	load_cr3(swapper_pg_dir);

	__flush_tlb_all();

	kmap_init();
}


#ifdef CONFIG_X86_PAE
#define LAST_PKMAP 512
#else
#define LAST_PKMAP 1024
#endif
/*
 * Ordering is:
 *
 * FIXADDR_TOP
 * 			fixed_addresses
 * FIXADDR_START
 * 			temp fixed addresses
 * FIXADDR_BOOT_START
 * 			Persistent kmap area
 * PKMAP_BASE
 * VMALLOC_END
 * 			Vmalloc area
 * VMALLOC_START
 * high_memory
 */
static void __init permanent_kmaps_init(pgd_t *pgd_base)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long vaddr;

	//pkmap的位置在vmalloc_end后面2个页面(highmem存在)
	//共1024个页面
	vaddr = PKMAP_BASE;
	page_table_range_init(vaddr, vaddr + PAGE_SIZE*LAST_PKMAP, pgd_base);

	pgd = swapper_pg_dir + pgd_index(vaddr);
	pud = pud_offset(pgd, vaddr);
	pmd = pmd_offset(pud, vaddr);
	pte = pte_offset_kernel(pmd, vaddr);
	//记录这个地址的内核虚拟地址
	pkmap_page_table = pte;	
}

unsigned long __FIXADDR_TOP = 0xfffff000;

enum fixed_addresses {
	FIX_HOLE,
	FIX_VDSO,
	FIX_DBGP_BASE,
	FIX_EARLYCON_MEM_BASE,
#ifdef CONFIG_X86_LOCAL_APIC
	FIX_APIC_BASE,	/* local (CPU) APIC) -- required for SMP or not */
#endif
#ifdef CONFIG_X86_IO_APIC
	FIX_IO_APIC_BASE_0,
	FIX_IO_APIC_BASE_END = FIX_IO_APIC_BASE_0 + MAX_IO_APICS-1,
#endif
#ifdef CONFIG_X86_F00F_BUG
	FIX_F00F_IDT,	/* Virtual mapping for IDT */
#endif
#ifdef CONFIG_X86_CYCLONE_TIMER
	FIX_CYCLONE_TIMER, /*cyclone timer register*/
#endif 
#ifdef CONFIG_HIGHMEM
	FIX_KMAP_BEGIN,	/* reserved pte's for temporary kernel mappings */		//各个CPU的临时映射地址
	FIX_KMAP_END = FIX_KMAP_BEGIN+(KM_TYPE_NR*NR_CPUS)-1,
#endif
#ifdef CONFIG_ACPI
	FIX_ACPI_BEGIN,
	FIX_ACPI_END = FIX_ACPI_BEGIN + FIX_ACPI_PAGES - 1,
#endif
#ifdef CONFIG_PCI_MMCONFIG
	FIX_PCIE_MCFG,
#endif
#ifdef CONFIG_PARAVIRT
	FIX_PARAVIRT_BOOTMAP,
#endif
	__end_of_permanent_fixed_addresses,
	/* temporary boot-time mappings, used before ioremap() is functional */
#define NR_FIX_BTMAPS	16
	FIX_BTMAP_END = __end_of_permanent_fixed_addresses,
	FIX_BTMAP_BEGIN = FIX_BTMAP_END + NR_FIX_BTMAPS - 1,
	FIX_WP_TEST,
	__end_of_fixed_addresses
};

set_fixmap

static void __init pagetable_init (void)
{
	unsigned long vaddr, end;
	pgd_t *pgd_base = swapper_pg_dir;

	..virtual,PGE,numa...
		//内核页表的建立
		kernel_physical_mapping_init(pgd_base);

	/*
	 * Fixed mappings, only the page table structure has to be
	 * created - mappings will be set by set_fixmap():
	 */
	vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
	end = (FIXADDR_TOP + PMD_SIZE - 1) & PMD_MASK;
	//范围地址分配表(不分配具体页面)
	//fix map还是分配了的
	page_table_range_init(vaddr, end, pgd_base);

	//固定映射
	permanent_kmaps_init(pgd_base);

	paravirt_pagetable_setup_done(pgd_base);
}

static void __init kernel_physical_mapping_init(pgd_t *pgd_base)
{
	unsigned long pfn;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	int pgd_idx, pmd_idx, pte_ofs;

	pgd_idx = pgd_index(PAGE_OFFSET);
	pgd = pgd_base + pgd_idx;
	pfn = 0;

	for (; pgd_idx < PTRS_PER_PGD; pgd++, pgd_idx++) {
		//32位非pae直接返回pgd
		pmd = one_md_table_init(pgd);
		//只映射低端内存(32位896)
		if (pfn >= max_low_pfn)
			continue;
		for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD && pfn < max_low_pfn; pmd++, pmd_idx++) {
			//从3G起的虚拟地址
			unsigned int address = pfn * PAGE_SIZE + PAGE_OFFSET;

			//分配页表并设置到pgd
			pte = one_page_table_init(pmd);

			for (pte_ofs = 0;
					pte_ofs < PTRS_PER_PTE && pfn < max_low_pfn;
					pte++, pfn++, pte_ofs++, address += PAGE_SIZE) {
				if (is_kernel_text(address))
					set_pte(pte, pfn_pte(pfn, PAGE_KERNEL_EXEC));
				else
					set_pte(pte, pfn_pte(pfn, PAGE_KERNEL));
			}
		}
	}
}

static void __init kmap_init(void)
{
	unsigned long kmap_vstart;

	/* cache the first kmap pte */
	//虚拟地址
	kmap_vstart = __fix_to_virt(FIX_KMAP_BEGIN);
	//页表项
	kmap_pte = kmap_get_fixmap_pte(kmap_vstart);

	kmap_prot = PAGE_KERNEL;
}

//3.14
void __init paging_init(void)
{
	pagetable_init(); ~ permanent_kmaps_init(pgd_base);

	__flush_tlb_all();

	kmap_init();

	/*
	 * NOTE: at this point the bootmem allocator is fully available.
	 */
	olpc_dt_build_devicetree();
	sparse_memory_present_with_active_regions(MAX_NUMNODES);
	sparse_init();
	zone_sizes_init(); ~ free_area_init_nodes(max_zone_pfns);
}

