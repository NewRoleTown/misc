//_end标号后面有4096个字节空出来给页表，再之后就是min_low_pfn的位置，详见lds.S
typedef struct bootmem_data {
	unsigned long node_min_pfn;	//general = 0
	unsigned long node_low_pfn;	//last pfn of zone normal
	void *node_bootmem_map;			
	unsigned long last_end_off;
	unsigned long hint_idx;
	struct list_head list;
} bootmem_data_t;

setup_memory
	->setup_bootmem_allocator();
void __init setup_bootmem_allocator(void)
{
	unsigned long bootmap_size;
	/*
	 * Initialize the boot-time allocator (with low memory only):
	 */
	//bitmap在min_low_pfn位置
	bootmap_size = init_bootmem(min_low_pfn, max_low_pfn);

	register_bootmem_low_pages(max_low_pfn);
	/*
	 * Reserve the bootmem bitmap itself as well. We do this in two
	 * steps (first step was init_bootmem()) because this catches
	 * the (very unlikely) case of us accidentally initializing the
	 * bootmem allocator with an invalid RAM area.
	 */
	//0地址和_text开始的一段内存标记为不可用
	reserve_bootmem(__pa_symbol(_text), (PFN_PHYS(min_low_pfn) +
			 bootmap_size + PAGE_SIZE-1) - __pa_symbol(_text));

	/*
	 * reserve physical page 0 - it's a special BIOS page on many boxes,
	 * enabling clean reboots, SMP operation, laptop functions.
	 */
	reserve_bootmem(0, PAGE_SIZE);

	/* reserve EBDA region, it's a 4K region */
	reserve_ebda_region();

    /* could be an AMD 768MPX chipset. Reserve a page  before VGA to prevent
       PCI prefetch into it (errata #56). Usually the page is reserved anyways,
       unless you have no PS/2 mouse plugged in. */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
	    boot_cpu_data.x86 == 6)
	     reserve_bootmem(0xa0000 - 4096, 4096);

#ifdef CONFIG_SMP
	/*
	 * But first pinch a few for the stack/trampoline stuff
	 * FIXME: Don't need the extra page at 4K, but need to fix
	 * trampoline before removing it. (see the GDT stuff)
	 */
	reserve_bootmem(PAGE_SIZE, PAGE_SIZE);
#endif
	reserve_crashkernel();
}
init_bootmem_core(NODE_DATA(0), start, 0, pages);
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
	//先全标记为不可用
	memset(bdata->node_bootmem_map, 0xff, mapsize);

	return mapsize;
}

__alloc_bootmem


MAX_DMA_ADDRESS
_end+4096:bootmap{start = 0,end = max_low_pfn}
0x10000:kernel
0-0x100000:dma
