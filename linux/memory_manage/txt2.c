cr0的PG(31)位开启分页
	PE(0)位开启保护模式
	CacheDisable(30)
	WriteProtect(16)
NowWriteThrought(29)

	cr3页目录基址寄存器
	cr4中PGE和页表global相关,用于不从tlb缓存中刷出

64位系统使用48位地址(9+9+9+9+12)

	各个CPU的TLB不必同步，而CACHE要同步

#define VMALLOC_OFFSET	(8*1024*1024)
#define VMALLOC_START	(((unsigned long) high_memory + \
			2*VMALLOC_OFFSET-1) & ~(VMALLOC_OFFSET-1))
#ifdef CONFIG_HIGHMEM
# define VMALLOC_END	(PKMAP_BASE-2*PAGE_SIZE)
#else
# define VMALLOC_END	(FIXADDR_START-2*PAGE_SIZE)
#endif

	/*
	 * _PAGE_PSE set in the page directory entry just means that
	 * the page directory entry points directly to a 4MB-aligned block of
	 * memory. 
	 */
	//present为0时，表项被其他功能复用
#define _PAGE_BIT_PRESENT	0
	//x86可读便可执行，PAE或x64才有nx
#define _PAGE_BIT_RW		1
#define _PAGE_BIT_USER		2
	//write-throughi:写内存和写缓存同步
	//write-back:只改缓存，刷缓存才写回去
#define _PAGE_BIT_PWT		3
	//是否对该页启用高速缓存
#define _PAGE_BIT_PCD		4
#define _PAGE_BIT_ACCESSED	5
#define _PAGE_BIT_DIRTY		6
	//仅用于页目录项
#define _PAGE_BIT_PSE		7	/* 4 MB (or 2MB) page, Pentium+, if present.. */
	//仅用于页表项
#define _PAGE_BIT_GLOBAL	8	/* Global TLB entry PPro+ */
#define _PAGE_BIT_UNUSED1	9	/* available for programmer */
#define _PAGE_BIT_UNUSED2	10
#define _PAGE_BIT_UNUSED3	11
#define _PAGE_BIT_NX		63

#define _PAGE_PRESENT	0x001
#define _PAGE_RW	0x002
#define _PAGE_USER	0x004
#define _PAGE_PWT	0x008
#define _PAGE_PCD	0x010
#define _PAGE_ACCESSED	0x020
#define _PAGE_DIRTY	0x040
#define _PAGE_PSE	0x080	/* 4 MB (or 2MB) page, Pentium+, if present.. */
#define _PAGE_GLOBAL	0x100	/* Global TLB entry PPro+ */
#define _PAGE_UNUSED1	0x200	/* available for programmer */
#define _PAGE_UNUSED2	0x400
#define _PAGE_UNUSED3	0x800

	/* If _PAGE_PRESENT is clear, we use these: */
	//不存在的页不可能是脏的
#define _PAGE_FILE	0x040	/* nonlinear file mapping, saved PTE; unset:swap */
#define _PAGE_PROTNONE	0x080	/* if the user mapped it with PROT_NONE;
								   pte_present gives true */
#ifdef CONFIG_X86_PAE
#define _PAGE_NX	(1ULL<<_PAGE_BIT_NX)
#else
#define _PAGE_NX	0
#endif

	pte_t用于页表项

#define pte_present(x)	((x).pte_low & (_PAGE_PRESENT | _PAGE_PROTNONE))

#define pte_index(address) \
		(((address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

#define pgd_offset(mm, address) ((mm)->pgd+pgd_index(address))

	/*
	 * a shortcut which implies the use of the kernel's pgd, instead
	 * of a process's
	 */
#define pgd_offset_k(address) pgd_offset(&init_mm, address)

	pgd_t *p = pgd_offset_k(addr);

#define pte_offset_kernel(dir, address) \
		((pte_t *) pmd_page_vaddr(*(dir)) +  pte_index(address))

	//如果配置了页表可以放在high内存区
#if defined(CONFIG_HIGHPTE)
#define pte_offset_map(dir, address) \
	(*dir)获取的物理地址不能直接va,要通过映射才能访问
((pte_t *)kmap_atomic_pte(pmd_page(*(dir)),KM_PTE0) + pte_index(address))
#define pte_offset_map_nested(dir, address) \
		((pte_t *)kmap_atomic_pte(pmd_page(*(dir)),KM_PTE1) + pte_index(address))
#define pte_unmap(pte) kunmap_atomic(pte, KM_PTE0)
#define pte_unmap_nested(pte) kunmap_atomic(pte, KM_PTE1)
#else
#define pte_offset_map(dir, address) \
		((pte_t *)page_address(pmd_page(*(dir))) + pte_index(address))
#define pte_offset_map_nested(dir, address) pte_offset_map(dir, address)
#define pte_unmap(pte) do { } while (0)
#define pte_unmap_nested(pte) do { } while (0)
#endif

#define pte_alloc_map(mm, pmd, address)			\
		((unlikely(!pmd_present(*(pmd))) && __pte_alloc(mm, pmd, address))? \
		 NULL: pte_offset_map(pmd, address))

	//根据配置可以选择页表是否可存HIHG内存
struct page *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *pte;

#ifdef CONFIG_HIGHPTE
	pte = alloc_pages(GFP_KERNEL|__GFP_HIGHMEM|__GFP_REPEAT|__GFP_ZERO, 0);
#else
	pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO, 0);
#endif
	return pte;
}

swapper_pg_dir是主内核页目录

static pmd_t *pmd_cache_alloc(int idx)
{
	pmd_t *pmd;

	//如果不是内核空间虚拟地址，简单分配
	//否则，将其统一成内核地址
	if (idx >= USER_PTRS_PER_PGD) {
		pmd = (pmd_t *)__get_free_page(GFP_KERNEL);

		if (pmd)
			memcpy(pmd,
					(void *)pgd_page_vaddr(swapper_pg_dir[idx]),
					sizeof(pmd_t) * PTRS_PER_PMD);
	} else
		pmd = kmem_cache_alloc(pmd_cache, GFP_KERNEL);

	return pmd;
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	int i;
	//快速分配
	pgd_t *pgd = quicklist_alloc(0, GFP_KERNEL, pgd_ctor);

	//2层表或者分配失败直接退出
	if (PTRS_PER_PMD == 1 || !pgd)
		return pgd;

	//分配pgd的同时分配pmd?
	//pae开启时，4PTRS_PER_PGD
	for (i = 0; i < UNSHARED_PTRS_PER_PGD; ++i) {
		pmd_t *pmd = pmd_cache_alloc(i);

		if (!pmd)
			goto out_oom;

		//准虚拟华相关
		paravirt_alloc_pd(__pa(pmd) >> PAGE_SHIFT);
		//设置页目录，present置位
		set_pgd(&pgd[i], __pgd(1 + __pa(pmd)));
	}
	return pgd;

out_oom:
	for (i--; i >= 0; i--) {
		pgd_t pgdent = pgd[i];
		void* pmd = (void *)__va(pgd_val(pgdent)-1);
		paravirt_release_pd(__pa(pmd) >> PAGE_SHIFT);
		pmd_cache_free(pmd, i);
	}
	quicklist_free(0, pgd_dtor, pgd);
	return NULL;
}

//页表的快速分配
/*
 * Specifying a NULL ctor can remove constructor support. Specifying
 * a constant quicklist allows the determination of the exact address
 * in the per cpu area.
 *
 * The fast patch in quicklist_alloc touched only a per cpu cacheline and
 * the first cacheline of the page itself. There is minmal overhead involved.
 */
static inline void *quicklist_alloc(int nr, gfp_t flags, void (*ctor)(void *))
{
	struct quicklist *q;
	void **p = NULL;

	q =&get_cpu_var(quicklist)[nr];
	p = q->page;
	if (likely(p)) {
		q->page = p[0];
		p[0] = NULL;
		q->nr_pages--;
	}
	put_cpu_var(quicklist);
	if (likely(p))
		return p;

	p = (void *)__get_free_page(flags | __GFP_ZERO);
	if (ctor && p)
		ctor(p);
	return p;
}

static inline void __quicklist_free(int nr, void (*dtor)(void *), void *p,
		struct page *page)
{
	struct quicklist *q;

	q = &get_cpu_var(quicklist)[nr];
	//将p的第一个字段作为一个指针，指向原先链表中的元素
	*(void **)p = q->page;
	//更新链表头部
	q->page = p;
	q->nr_pages++;
	put_cpu_var(quicklist);
}


enum km_type {
D(0)	KM_BOUNCE_READ,
D(1)	KM_SKB_SUNRPC_DATA,
D(2)	KM_SKB_DATA_SOFTIRQ,
D(3)	KM_USER0,
D(4)	KM_USER1,
D(5)	KM_BIO_SRC_IRQ,
D(6)	KM_BIO_DST_IRQ,
D(7)	KM_PTE0,
D(8)	KM_PTE1,
D(9)	KM_IRQ0,
D(10)	KM_IRQ1,
D(11)	KM_SOFTIRQ0,
D(12)	KM_SOFTIRQ1,
D(13)	KM_TYPE_NR
};

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
#ifdef CONFIG_X86_VISWS_APIC
	FIX_CO_CPU,	/* Cobalt timer */
	FIX_CO_APIC,	/* Cobalt APIC Redirection Table */ 
	FIX_LI_PCIA,	/* Lithium PCI Bridge A */
	FIX_LI_PCIB,	/* Lithium PCI Bridge B */
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
这个结构包含持久和固定映射
通过set_fixmap设定
	带page_kernel属性
(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_NX)
	nocache时 | PCD表示不缓存


	PAGE_ALIGN(6000) = 8192


	//这个可配置值用于确定内核在内存中的位置
	CONFIG_PHYSICAL_START=0x100000

	32位初始布局如下
	0-4k第一个页帧
	随后为640k可用至0x9e800
	之后一段映射内存
	0x100000开始是内核代码_text标号至_etext,内核获取的这些标号似乎是va
	之后是数据至_edata
	之后是bss至_end
	arch/x86/kernel/setup_32.c中有详细记录过程，但是这些标号的值是在打包为二进制文件时才生成的
	arch/x86/vmlinux_32.ld.S控制

	/proc/iomem也提供物理内存划分的一些信息

dmesg输出(16G内存物理机)
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


	struct boot_params {
		struct screen_info screen_info;			/* 0x000 */
		struct apm_bios_info apm_bios_info;		/* 0x040 */
		__u8  _pad2[12];				/* 0x054 */
		struct ist_info ist_info;			/* 0x060 */
		__u8  _pad3[16];				/* 0x070 */
		__u8  hd0_info[16];	/* obsolete! */		/* 0x080 */
		__u8  hd1_info[16];	/* obsolete! */		/* 0x090 */
		struct sys_desc_table sys_desc_table;		/* 0x0a0 */
		__u8  _pad4[144];				/* 0x0b0 */
		struct edid_info edid_info;			/* 0x140 */
		struct efi_info efi_info;			/* 0x1c0 */
		__u32 alt_mem_k;				/* 0x1e0 */
		__u32 scratch;		/* Scratch field! */	/* 0x1e4 */
		__u8  e820_entries;				/* 0x1e8 */
		__u8  eddbuf_entries;				/* 0x1e9 */
		__u8  edd_mbr_sig_buf_entries;			/* 0x1ea */
		__u8  _pad6[6];					/* 0x1eb */
		struct setup_header hdr;    /* setup header */	/* 0x1f1 */
		__u8  _pad7[0x290-0x1f1-sizeof(struct setup_header)];
		__u32 edd_mbr_sig_buffer[EDD_MBR_SIG_MAX];	/* 0x290 */
		struct e820entry e820_map[E820MAX];		/* 0x2d0 */
		__u8  _pad8[48];				/* 0xcd0 */
		struct edd_info eddbuf[EDDMAXNR];		/* 0xd00 */
		__u8  _pad9[276];				/* 0xeec */
	} __attribute__((packed));

	setup_arch中获取上表
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


之后算出几个内存域的界限
	以及初始化bootmem管理
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
/*
 * paging_init() sets up the page tables - note that the first 8MB are
 * already mapped by head.S.
 *
 * This routines also unmaps the page at virtual kernel address 0, so
 * that we can trap those pesky NULL-reference errors in the kernel.
 */
void __init paging_init(void)
{
	//PAE部分省略
	pagetable_init();

	load_cr3(swapper_pg_dir);

	__flush_tlb_all();

	kmap_init();
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
		//只映射低端内存
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

unsigned long __FIXADDR_TOP = 0xfffff000;
//fix映射的末端地址
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
	//范围地址分配页表(不分配具体页面)
	page_table_range_init(vaddr, end, pgd_base);

	permanent_kmaps_init(pgd_base);

	paravirt_pagetable_setup_done(pgd_base);
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

//可见swapper_pg_dir存在于内核BSS段
.section ".bss.page_aligned","wa"
	.align PAGE_SIZE_asm
ENTRY(swapper_pg_dir)
	.fill 1024,4,0
ENTRY(swapper_pg_pmd)
	.fill 1024,4,0
ENTRY(empty_zero_page)
	.fill 4096,1,0

	AMD64
	48位地址空间0xFFFF_8000_0000_0000开始为内核空间
	0-0x0000_7ffff_ffff_ffff用户空间

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
		   //pg0在这个位置
	   }

	   /* Sections to be discarded */
	   /DISCARD/ : {
		   *(.exitcall.exit)
	   }

	   STABS_DEBUG

		   DWARF_DEBUG
}

/*


*/

