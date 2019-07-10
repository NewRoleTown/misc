

bootmap_size = init_bootmem(min_low_pfn, max_low_pfn);


typedef struct bootmem_data {
	unsigned long node_boot_start;
	unsigned long node_low_pfn;
	void *node_bootmem_map;

	unsigned long last_offset;
	unsigned long last_pos;
	unsigned long last_success;	/* Previous allocation point.  To speed
					 * up searching */
	struct list_head list;
} bootmem_data_t;

unsigned long __init init_bootmem(unsigned long start, unsigned long pages)
{
	max_low_pfn = pages;
	min_low_pfn = start;
	return init_bootmem_core(NODE_DATA(0), start, 0, pages);
}

static unsigned long __init init_bootmem_core(pg_data_t *pgdat,
	unsigned long mapstart, unsigned long start, unsigned long end)
{
	bootmem_data_t *bdata = pgdat->bdata;
	unsigned long mapsize;

	bdata->node_bootmem_map = phys_to_virt(PFN_PHYS(mapstart));
	bdata->node_boot_start = PFN_PHYS(start);
	bdata->node_low_pfn = end;
	link_bootmem(bdata);

	/*
	 * Initially all pages are reserved - setup_arch() has to
	 * register free RAM areas explicitly.
	 */
	mapsize = get_mapsize(bdata);
	memset(bdata->node_bootmem_map, 0xff, mapsize);

	return mapsize;
}


/*
 * Register fully available low RAM pages with the bootmem allocator.
 */
void __init register_bootmem_low_pages(unsigned long max_low_pfn)
{
    //省略检查
	for (i = 0; i < e820.nr_map; i++) {
		unsigned long curr_pfn, last_pfn, size;
		curr_pfn = PFN_UP(e820.map[i].addr);
		last_pfn = PFN_DOWN(e820.map[i].addr + e820.map[i].size);

		size = last_pfn - curr_pfn;
		free_bootmem(PFN_PHYS(curr_pfn), PFN_PHYS(size));
	}
}

	/*
	 * Reserve the bootmem bitmap itself as well. We do this in two
	 * steps (first step was init_bootmem()) because this catches
	 * the (very unlikely) case of us accidentally initializing the
	 * bootmem allocator with an invalid RAM area.
	 */
    //由代码段至位图结束都被reserve
	reserve_bootmem(__pa_symbol(_text), (PFN_PHYS(min_low_pfn) +
			 bootmap_size + PAGE_SIZE-1) - __pa_symbol(_text));


#define reserve_bootmem(addr, size) \
	reserve_bootmem_node(NODE_DATA(0), (addr), (size))
#define alloc_bootmem(x) \
	__alloc_bootmem_node(NODE_DATA(0), (x), SMP_CACHE_BYTES, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_low(x) \
	__alloc_bootmem_node(NODE_DATA(0), (x), SMP_CACHE_BYTES, 0)
#define alloc_bootmem_pages(x) \
	__alloc_bootmem_node(NODE_DATA(0), (x), PAGE_SIZE, __pa(MAX_DMA_ADDRESS))
#define alloc_bootmem_low_pages(x) \
	__alloc_bootmem_node(NODE_DATA(0), (x), PAGE_SIZE, 0)



static unsigned long __init free_all_bootmem_core(pg_data_t *pgdat)
{
	struct page *page;
	unsigned long pfn;
	bootmem_data_t *bdata = pgdat->bdata;
	unsigned long i, count, total = 0;
	unsigned long idx;
	unsigned long *map; 
	int gofast = 0;

	count = 0;
	/* first extant page of the node */
	pfn = PFN_DOWN(bdata->node_boot_start);
	idx = bdata->node_low_pfn - pfn;
	map = bdata->node_bootmem_map;
	/* Check physaddr is O(LOG2(BITS_PER_LONG)) page aligned */
	if (bdata->node_boot_start == 0 ||
	    ffs(bdata->node_boot_start) - PAGE_SHIFT > ffs(BITS_PER_LONG))
		gofast = 1;
	for (i = 0; i < idx; ) {
		unsigned long v = ~map[i / BITS_PER_LONG];
        
		if (gofast && v == ~0UL) {
			int order;
            //如果全空,成块释放
			page = pfn_to_page(pfn);
			count += BITS_PER_LONG;
			order = ffs(BITS_PER_LONG) - 1;
            //count置0后置1,清reserve,
			__free_pages_bootmem(page, order);
			i += BITS_PER_LONG;
			page += BITS_PER_LONG;
		} else if (v) {
			unsigned long m;
			page = pfn_to_page(pfn);
			for (m = 1; m && i < idx; m<<=1, page++, i++) {
				if (v & m) {
					count++;
					__free_pages_bootmem(page, 0);
				}
			}
		} else {
            //全占用，不释放
			i += BITS_PER_LONG;
		}
		pfn += BITS_PER_LONG;
	}
	total += count;

	/*
	 * Now free the allocator bitmap itself, it's not
	 * needed anymore:
	 */
	page = virt_to_page(bdata->node_bootmem_map);
	count = 0;
	idx = (get_mapsize(bdata) + PAGE_SIZE-1) >> PAGE_SHIFT;
	for (i = 0; i < idx; i++, page++) {
		__free_pages_bootmem(page, 0);
		count++;
	}
	total += count;
	bdata->node_bootmem_map = NULL;

	return total;
}




void __init mem_init(void)
{
	extern int ppro_with_ram_bug(void);
	int codesize, reservedpages, datasize, initsize;
	int tmp;
	int bad_ppro;

	bad_ppro = ppro_with_ram_bug();

#ifdef CONFIG_HIGHMEM
	/* check that fixmap and pkmap do not overlap */
	if (PKMAP_BASE+LAST_PKMAP*PAGE_SIZE >= FIXADDR_START) {
		printk(KERN_ERR "fixmap and kmap areas overlap - this will crash\n");
		printk(KERN_ERR "pkstart: %lxh pkend: %lxh fixstart %lxh\n",
				PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE, FIXADDR_START);
		BUG();
	}
#endif
 
	/* this will put all low memory onto the freelists */
	totalram_pages += free_all_bootmem();

	reservedpages = 0;
	for (tmp = 0; tmp < max_low_pfn; tmp++)
		/*
		 * Only count reserved RAM pages
		 */
		if (page_is_ram(tmp) && PageReserved(pfn_to_page(tmp)))
			reservedpages++;

	set_highmem_pages_init(bad_ppro);

	codesize =  (unsigned long) &_etext - (unsigned long) &_text;
	datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
	initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

	kclist_add(&kcore_mem, __va(0), max_low_pfn << PAGE_SHIFT); 
	kclist_add(&kcore_vmalloc, (void *)VMALLOC_START, 
		   VMALLOC_END-VMALLOC_START);

	printk(KERN_INFO "Memory: %luk/%luk available (%dk kernel code, %dk reserved, %dk data, %dk init, %ldk highmem)\n",
		(unsigned long) nr_free_pages() << (PAGE_SHIFT-10),
		num_physpages << (PAGE_SHIFT-10),
		codesize >> 10,
		reservedpages << (PAGE_SHIFT-10),
		datasize >> 10,
		initsize >> 10,
		(unsigned long) (totalhigh_pages << (PAGE_SHIFT-10))
	       );

#if 1 /* double-sanity-check paranoia */
	printk("virtual kernel memory layout:\n"
	       "    fixmap  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#ifdef CONFIG_HIGHMEM
	       "    pkmap   : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#endif
	       "    vmalloc : 0x%08lx - 0x%08lx   (%4ld MB)\n"
	       "    lowmem  : 0x%08lx - 0x%08lx   (%4ld MB)\n"
	       "      .init : 0x%08lx - 0x%08lx   (%4ld kB)\n"
	       "      .data : 0x%08lx - 0x%08lx   (%4ld kB)\n"
	       "      .text : 0x%08lx - 0x%08lx   (%4ld kB)\n",
	       FIXADDR_START, FIXADDR_TOP,
	       (FIXADDR_TOP - FIXADDR_START) >> 10,

#ifdef CONFIG_HIGHMEM
	       PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE,
	       (LAST_PKMAP*PAGE_SIZE) >> 10,
#endif

	       VMALLOC_START, VMALLOC_END,
	       (VMALLOC_END - VMALLOC_START) >> 20,

	       (unsigned long)__va(0), (unsigned long)high_memory,
	       ((unsigned long)high_memory - (unsigned long)__va(0)) >> 20,

	       (unsigned long)&__init_begin, (unsigned long)&__init_end,
	       ((unsigned long)&__init_end - (unsigned long)&__init_begin) >> 10,

	       (unsigned long)&_etext, (unsigned long)&_edata,
	       ((unsigned long)&_edata - (unsigned long)&_etext) >> 10,

	       (unsigned long)&_text, (unsigned long)&_etext,
	       ((unsigned long)&_etext - (unsigned long)&_text) >> 10);

#ifdef CONFIG_HIGHMEM
	BUG_ON(PKMAP_BASE+LAST_PKMAP*PAGE_SIZE > FIXADDR_START);
	BUG_ON(VMALLOC_END                     > PKMAP_BASE);
#endif
	BUG_ON(VMALLOC_START                   > VMALLOC_END);
	BUG_ON((unsigned long)high_memory      > VMALLOC_START);
#endif /* double-sanity-check paranoia */

	if (boot_cpu_data.wp_works_ok < 0)
		test_wp_bit();

	/*
	 * Subtle. SMP is doing it's boot stuff late (because it has to
	 * fork idle threads) - but it also needs low mappings for the
	 * protected-mode entry to work. We zap these entries only after
	 * the WP-bit has been tested.
	 */
#ifndef CONFIG_SMP
	zap_low_mappings();
#endif
}

initmem在kernel_start结束时释放给伙伴系统

static int pkmap_count[LAST_PKMAP];

PKMAP_BASE到FIXADDR_START用于持久映射
pkmap_count数组是持久映射页的计数器,为0可用，为1表示没人用但还未刷新TLB

void *kmap(struct page *page)
{
	might_sleep();
	if (!PageHighMem(page))
		return page_address(page);
	return kmap_high(page);
}

void kunmap(struct page *page)
{
	if (in_interrupt())
		BUG();
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}

void *page_address(struct page *page)
{
	unsigned long flags;
	void *ret;
	struct page_address_slot *pas;

	if (!PageHighMem(page))
		return lowmem_page_address(page);

	pas = page_slot(page);
	ret = NULL;
	spin_lock_irqsave(&pas->lock, flags);
	if (!list_empty(&pas->lh)) {
		struct page_address_map *pam;

		list_for_each_entry(pam, &pas->lh, list) {
			if (pam->page == page) {
				ret = pam->virtual;
				goto done;
			}
		}
	}
done:
	spin_unlock_irqrestore(&pas->lock, flags);
	return ret;
}

struct page_address_map {
	struct page *page;
	void *virtual;
	struct list_head list;
};

static struct page_address_slot *page_slot(struct page *page)
{
	return &page_address_htable[hash_ptr(page, PA_HASH_ORDER)];
}

中断处理和可延迟函数不可调用kmap
void fastcall *kmap_high(struct page *page)
{
	unsigned long vaddr;

	/*
	 * We cannot call this from interrupts, as it may block
	 */
	spin_lock(&kmap_lock);
	vaddr = (unsigned long)page_address(page);
	if (!vaddr)
		vaddr = map_new_virtual(page);
	pkmap_count[PKMAP_NR(vaddr)]++;
	BUG_ON(pkmap_count[PKMAP_NR(vaddr)] < 2);
	spin_unlock(&kmap_lock);
	return (void*) vaddr;
}

临时映射
void *kmap_atomic_prot(struct page *page, enum km_type type, pgprot_t prot)
{
	enum fixed_addresses idx;
	unsigned long vaddr;

	/* even !CONFIG_PREEMPT needs this, for in_atomic in do_page_fault */
	pagefault_disable();

	if (!PageHighMem(page))
		return page_address(page);

	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
	BUG_ON(!pte_none(*(kmap_pte-idx)));
	set_pte(kmap_pte-idx, mk_pte(page, prot));
	arch_flush_lazy_mmu_mode();

	return (void *)vaddr;
}


void __set_fixmap (enum fixed_addresses idx, unsigned long phys, pgprot_t flags)
{
	unsigned long address = __fix_to_virt(idx);

	if (idx >= __end_of_fixed_addresses) {
		BUG();
		return;
	}
	set_pte_pfn(address, phys >> PAGE_SHIFT, flags);
	fixmaps++;
}
