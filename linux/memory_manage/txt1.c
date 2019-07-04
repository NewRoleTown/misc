代码段描述符的L位指示代码是否默认为64位(只有ia-32使用)
代码段的D/B位指示代码32位还是16位

低特权级的代码到高特权级运行只有一种情况，就是call调用門到非一致代码段
此时dpl < gate_dpl,cpl > dest_dpl,进call后cpl不变

选择子的值在asm/segment.h文件中定义



enum zone_type {
#ifdef CONFIG_ZONE_DMA
	/*
	 * ZONE_DMA is used when there are devices that are not able
	 * to do DMA to all of addressable memory (ZONE_NORMAL). Then we
	 * carve out the portion of memory that is needed for these devices.
	 * The range is arch specific.
	 *
	 * Some examples
	 *
	 * Architecture		Limit
	 * ---------------------------
	 * arm			Various
	 * i386, x86_64 and multiple other arches
	 * 			<16M.
	 */
	ZONE_DMA,
#endif
    //只有64位机有这个zone
#ifdef CONFIG_ZONE_DMA32
	/*
	 * x86_64 needs two ZONE_DMAs because it supports devices that are
	 * only able to do DMA to the lower 16M but also 32 bit devices that
	 * can only do DMA areas below 4G.
	 */
	ZONE_DMA32,
#endif
	/*
	 * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
	 * performed on pages in ZONE_NORMAL if the DMA devices support
	 * transfers to all addressable memory.
	 */
	ZONE_NORMAL,
#ifdef CONFIG_HIGHMEM
	/*
	 * A memory area that is only addressable by the kernel through
	 * mapping portions into its own address space. This is for example
	 * used by i386 to allow the kernel to address the memory beyond
	 * 900MB. The kernel will set up special mappings (page
	 * table entries on i386) for each page that the kernel needs to
	 * access.
	 */
	ZONE_HIGHMEM,
#endif
	ZONE_MOVABLE,
	MAX_NR_ZONES
};

//节点
typedef struct pglist_data {
    //节点下的zone
	struct zone node_zones[MAX_NR_ZONES];
    //备用zone列表
	struct zonelist node_zonelists[MAX_ZONELISTS];
    //zone数量
	int nr_zones;
#ifdef CONFIG_FLAT_NODE_MEM_MAP
    //内存页数组
	struct page *node_mem_map;
#endif
    //自举分配器(系统初始化之后置NULL)
	struct bootmem_data *bdata;
#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Must be held any time you expect node_start_pfn, node_present_pages
	 * or node_spanned_pages stay constant.  Holding this will also
	 * guarantee that any pfn_valid() stays that way.
	 *
	 * Nests above zone->lock and zone->size_seqlock.
	 */
	spinlock_t node_size_lock;
#endif
    //第一个页帧的逻辑编号(全局唯一),UMA总是0
	unsigned long node_start_pfn;
    //不包含洞的页数
	unsigned long node_present_pages; /* total number of physical pages */
    //包含洞的页数
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
    //节点id
	int node_id;
	wait_queue_head_t kswapd_wait;
    //交换守护进程
	struct task_struct *kswapd;
	int kswapd_max_order;
} pg_data_t;


struct zone {
	/* Fields commonly accessed by the page allocator */
    //内存水限，空闲页低于low时，内和开始执行页交换
	unsigned long		pages_min, pages_low, pages_high;
	/*
	 * We don't know if the memory that we're going to allocate will be freeable
	 * or/and it will be released eventually, so to avoid totally wasting several
	 * GB of ram we must reserve some of the lower zone memory (otherwise we risk
	 * to run OOM on the lower zones despite there's tons of freeable ram
	 * on the higher zones). This array is recalculated at runtime if the
	 * sysctl_lowmem_reserve_ratio sysctl changes.
	 */
    //为各区域准备的保留页
	unsigned long		lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	int node;
	/*
	 * zone reclaim becomes active if more unmapped pages exist.
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
	struct per_cpu_pageset	*pageset[NR_CPUS];
#else
    //页缓存，单页
	struct per_cpu_pageset	pageset[NR_CPUS];
#endif
	/*
	 * free areas of different sizes
	 */
	spinlock_t		lock;
#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif
	struct free_area	free_area[MAX_ORDER];

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
    //包含pageblock_nr_pages个页的可移动性位图
    //此处与注释似乎不符，这个位图包含了zone的全部内存
    //但是是以pageblock_order为单位,位图每一格就是一个pageblock_order
    //每个page占3个比特位
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */


	ZONE_PADDING(_pad1_)

	/* Fields commonly accessed by the page reclaim scanner */
	spinlock_t		lru_lock;	
    //活动页链表(page实例)
	struct list_head	active_list;
	struct list_head	inactive_list;
	unsigned long		nr_scan_active;
	unsigned long		nr_scan_inactive;
	unsigned long		pages_scanned;	   /* since last reclaim */
	unsigned long		flags;		   /* zone flags, see below */
/*
typedef enum {
	ZONE_ALL_UNRECLAIMABLE,		//all pages pinned 所有页被钉住，mlock系统调用可使页不能被换出,本质上是添加#define VM_LOCKED	0x00002000
	ZONE_RECLAIM_LOCKED,		//prevents concurrent reclaim防止并发回收
	ZONE_OOM_LOCKED,		//zone is in OOM killer zonelist
} zone_flags_t;*/

	/* Zone statistics */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];

	/*
	 * prev_priority holds the scanning priority for this zone.  It is
	 * defined as the scanning priority at which we achieved our reclaim
	 * target at the previous try_to_free_pages() or balance_pgdat()
	 * invokation.
	 *
	 * We use prev_priority as a measure of how much stress page reclaim is
	 * under - it drives the swappiness decision: whether to unmap mapped
	 * pages.
	 *
	 * Access to both this field is quite racy even on uniprocessor.  But
	 * it is expected to average out OK.
	 */
	int prev_priority;


	ZONE_PADDING(_pad2_)
	/* Rarely used or read-mostly fields */

	/*
	 * wait_table		-- the array holding the hash table
	 * wait_table_hash_nr_entries	-- the size of the hash table array
	 * wait_table_bits	-- wait_table_size == (1 << wait_table_bits)
	 *
	 * The purpose of all these is to keep track of the people
	 * waiting for a page to become available and make them
	 * runnable again when possible. The trouble is that this
	 * consumes a lot of space, especially when so few things
	 * wait on pages at a given time. So instead of using
	 * per-page waitqueues, we use a waitqueue hash table.
	 *
	 * The bucket discipline is to sleep on the same queue when
	 * colliding and wake all in that wait queue when removing.
	 * When something wakes, it must check to be sure its page is
	 * truly available, a la thundering herd. The cost of a
	 * collision is great, but given the expected load of the
	 * table, they should be so rare as to be outweighed by the
	 * benefits from the saved space.
	 *
	 * __wait_on_page_locked() and unlock_page() in mm/filemap.c, are the
	 * primary users of these fields, and in mm/page_alloc.c
	 * free_area_init_core() performs the initialization of them.
	 */
	wait_queue_head_t	* wait_table;
	unsigned long		wait_table_hash_nr_entries;
	unsigned long		wait_table_bits;

	/*
	 * Discontig memory support fields.
	 */
	struct pglist_data	*zone_pgdat;
	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
    //第一个页帧的索引
	unsigned long		zone_start_pfn;

	/*
	 * zone_start_pfn, spanned_pages and present_pages are all
	 * protected by span_seqlock.  It is a seqlock because it has
	 * to be read outside of zone->lock, and it is done in the main
	 * allocator path.  But, it is written quite infrequently.
	 *
	 * The lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 */
    //总长度，包含洞
	unsigned long		spanned_pages;	/* total size, including holes */
    //除去洞的长度
	unsigned long		present_pages;	/* amount of memory (excluding holes) */

	/*
	 * rarely used fields:
	 */
	const char		*name;
} ____cacheline_internodealigned_in_smp;

/*
 * Initialise min_free_kbytes.
 *
 * For small machines we want it small (128k min).  For large machines
 * we want it large (64MB max).  But it is not linear, because network
 * bandwidth does not increase linearly with machine size.  We use
 *
 * 	min_free_kbytes = 4 * sqrt(lowmem_kbytes), for better accuracy:
 *	min_free_kbytes = sqrt(lowmem_kbytes * 16)
 *
 * which yields
 *
 * 16MB:	512k
 * 32MB:	724k
 * 64MB:	1024k
 * 128MB:	1448k
 * 256MB:	2048k
 * 512MB:	2896k
 * 1024MB:	4096k
 * 2048MB:	5792k
 * 4096MB:	8192k
 * 8192MB:	11584k
 * 16384MB:	16384k
 */
计算内存水印及保留内存
static int __init init_per_zone_pages_min(void)
{
	unsigned long lowmem_kbytes;

	lowmem_kbytes = nr_free_buffer_pages() * (PAGE_SIZE >> 10);

	min_free_kbytes = int_sqrt(lowmem_kbytes * 16);
	if (min_free_kbytes < 128)
		min_free_kbytes = 128;
	if (min_free_kbytes > 65536)
		min_free_kbytes = 65536;
	setup_per_zone_pages_min();
	setup_per_zone_lowmem_reserve();
	return 0;
}

高端内存的min_pages的下限为
#define SWAP_CLUSTER_MAX 32
上限128
/*

*/


/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 */
struct page {
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	atomic_t _count;		/* Usage count, see below. */
	union {
        //映射的页表项计数,用于限制逆向映射
		atomic_t _mapcount;	/* Count of ptes mapped in mms,
					 * to show when page is mapped
					 * & limit reverse map searches.
					 */
	};
	union {
	    struct {
		unsigned long private;		/* Mapping-private opaque data:
					 	 * usually used for buffer_heads
						 * if PagePrivate set; used for
						 * swp_entry_t if PageSwapCache;
						 * indicates order in the buddy
						 * system if PG_buddy is set.
						 */
        //最低位0则指向inode,address_space,或NULL
        //否则，为匿名内存，指向anon_vma
        //PAGE_MAPPING_ANON
		struct address_space *mapping;	/* If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
	    };
	    struct kmem_cache *slab;	/* SLUB: Pointer to slab */
        //用于复合页
	    struct page *first_page;	/* Compound tail pages */
	};
	union {
        //映射的偏移量
		pgoff_t index;		/* Our offset within mapping. */
	};
    //active,inactiv链表项
    //空闲时链入free_area链表
	struct list_head lru;		/* Pageout list, eg. active_list
					 * protected by zone->lru_lock !
					 */
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
};

#define PG_locked	 	 0	/* Page is locked. Don't touch. */
#define PG_error		 1
#define PG_referenced		 2
#define PG_uptodate		 3

#define PG_dirty	 	 4
#define PG_lru			 5
#define PG_active		 6
#define PG_slab			 7	/* slab debug (Suparna wants this) */

#define PG_owner_priv_1		 8	/* Owner use. If pagecache, fs may use*/
#define PG_arch_1		 9
#define PG_reserved		10
#define PG_private		11	/* If pagecache, has fs-private data */

#define PG_writeback		12	/* Page is under writeback */
#define PG_compound		14	/* Part of a compound page */
//页用于交换缓存,private用于swap_entry_t
#define PG_swapcache		15	/* Swap page: swp_entry_t in private */

#define PG_mappedtodisk		16	/* Has blocks allocated on-disk */
//决定回收这个页
#define PG_reclaim		17	/* To be reclaimed asap */
//是否在伙伴系统管理下
#define PG_buddy		19	/* Page is free, on buddy lists */

/* PG_readahead is only used for file reads; PG_reclaim is only for writes */
#define PG_readahead		PG_reclaim /* Reminder to do async read-ahead */

/* PG_owner_priv_1 users should have descriptive aliases */
#define PG_checked		PG_owner_priv_1 /* Used by some filesystems */
#define PG_pinned		PG_owner_priv_1	/* Xen pinned pagetable */



#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))


/*
 * PGDIR_SHIFT determines what a top-level page table entry can map
 */
//64位
#define PGDIR_SHIFT	39
#define PTRS_PER_PGD	512

/*
 * 3rd level page
 */
#define PUD_SHIFT	30
#define PTRS_PER_PUD	512

/*
 * PMD_SHIFT determines the size of the area a middle-level
 * page table can map
 */
#define PMD_SHIFT	21
#define PTRS_PER_PMD	512

/*
 * entries per page directory level
 */
#define PTRS_PER_PTE	512

/*

*/
