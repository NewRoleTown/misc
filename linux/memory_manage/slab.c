struct array_cache {
	unsigned int avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int touched;
	spinlock_t lock;
	void *entry[];	/*
			 * Must have this definition in here for the proper
			 * alignment of array_cache. Also simplifies accessing
			 * the entries.
			 */
};
static struct arraycache_init initarray_cache __initdata =
    { {0, BOOT_CPUCACHE_ENTRIES, 1, 0} };

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
	struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
	//进货出货的单位
	unsigned int batchcount;
	//空闲缓存的最大数量
	unsigned int limit;
	unsigned int shared;

	unsigned int buffer_size;
	u32 reciprocal_buffer_size;
/* 3) touched by every alloc & free from the backend */

	//如果slab描述符在slab外部，cflags_off_slab置位
	unsigned int flags;		/* constant flags */
	unsigned int num;		/* # of objs per slab */

/* 4) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t gfpflags;

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *slabp_cache;
	//单个slab的大小
	unsigned int slab_size;
	unsigned int dflags;		/* dynamic flags */

	/* constructor func */
	void (*ctor)(struct kmem_cache *, void *);

/* 5) cache creation/removal */
	const char *name;
	//高速缓存链表
	struct list_head next;

/* 6) statistics */
#if STATS
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;
#endif
#if DEBUG
	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. buffer_size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
	int obj_size;
#endif
	/*
	 * We put nodelists[] at the end of kmem_cache, because we want to size
	 * this array to nr_node_ids slots instead of MAX_NUMNODES
	 * (see kmem_cache_init())
	 * We still use [MAX_NUMNODES] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of nodes.
	 */
	struct kmem_list3 *nodelists[MAX_NUMNODES];
	/*
	 * Do not add fields after nodelists[]
	 */
};


struct kmem_list3 {
	//链接slab结构体的三个链表
	struct list_head slabs_partial;	/* partial list first, better asm code */
	struct list_head slabs_full;
	struct list_head slabs_free;

	unsigned long free_objects;
	unsigned int free_limit;
	unsigned int colour_next;	/* Per-node cache coloring */
	spinlock_t list_lock;
	struct array_cache *shared;	/* shared per node */
	struct array_cache **alien;	/* on other nodes */
	unsigned long next_reap;	/* updated without locking */
	int free_touched;		/* updated without locking */
};

struct slab {
	struct list_head list;
	unsigned long colouroff;
	//第一个obj的地址
	void *s_mem;		/* including colour offset */
	//非空闲的obj数
	unsigned int inuse;	/* num of objs active in slab */
	//空闲下标
	kmem_bufctl_t free;
	unsigned short nodeid;
};

//系统中的第一个高速缓存，其object为高速缓存描述符
struct kmem_cache {
	unsigned int size, align;
	unsigned long flags;
	const char *name;
	void (*ctor)(struct kmem_cache *, void *);
};
static struct kmem_cache cache_cache = {
	.batchcount = 1,
	.limit = BOOT_CPUCACHE_ENTRIES,
	.shared = 1,
	.buffer_size = sizeof(struct kmem_cache),
	.name = "kmem_cache",
};


static void cache_estimate(unsigned long gfporder, size_t buffer_size,
			   size_t align, int flags, size_t *left_over,
			   unsigned int *num)
{
	int nr_objs;
	size_t mgmt_size;
	size_t slab_size = PAGE_SIZE << gfporder;

	/*
	 * The slab management structure can be either off the slab or
	 * on it. For the latter case, the memory allocated for a
	 * slab is used for:
	 *
	 * - The struct slab
	 * - One kmem_bufctl_t for each object
	 * - Padding to respect alignment of @align
	 * - @buffer_size bytes for each object
	 *
	 * If the slab management structure is off the slab, then the
	 * alignment will already be calculated into the size. Because
	 * the slabs are all pages aligned, the objects will be at the
	 * correct alignment when allocated.
	 */
	if (flags & CFLGS_OFF_SLAB) {
		mgmt_size = 0;
		//如果是外部描述符，则页全部用来放obj
		nr_objs = slab_size / buffer_size;

		if (nr_objs > SLAB_LIMIT)
			nr_objs = SLAB_LIMIT;
	} else {
		/*
		 * Ignore padding for the initial guess. The padding
		 * is at most @align-1 bytes, and @buffer_size is at
		 * least @align. In the worst case, this result will
		 * be one greater than the number of objects that fit
		 * into the memory allocation when taking the padding
		 * into account.
		 */
		nr_objs = (slab_size - sizeof(struct slab)) /
			  (buffer_size + sizeof(kmem_bufctl_t));

		/*
		 * This calculated number will be either the right
		 * amount, or one greater than what we want.
		 */
		if (slab_mgmt_size(nr_objs, align) + nr_objs*buffer_size
		       > slab_size)
			nr_objs--;

		if (nr_objs > SLAB_LIMIT)
			nr_objs = SLAB_LIMIT;

		mgmt_size = slab_mgmt_size(nr_objs, align);
	}
	*num = nr_objs;
	*left_over = slab_size - nr_objs*buffer_size - mgmt_size;
}

kmem_cache_init
void __init kmem_cache_init(void)
{
	size_t left_over;
	struct cache_sizes *sizes;
	struct cache_names *names;
	int i;
	int order;
	int node;

	for (i = 0; i < NUM_INIT_LISTS; i++) {
		kmem_list3_init(&initkmem_list3[i]);
		if (i < MAX_NUMNODES)
			cache_cache.nodelists[i] = NULL;
	}

	/* Bootstrap is tricky, because several objects are allocated
	 * from caches that do not exist yet:
	 * 1) initialize the cache_cache cache: it contains the struct
	 *    kmem_cache structures of all caches, except cache_cache itself:
	 *    cache_cache is statically allocated.
	 *    Initially an __init data area is used for the head array and the
	 *    kmem_list3 structures, it's replaced with a kmalloc allocated
	 *    array at the end of the bootstrap.
	 * 2) Create the first kmalloc cache.
	 *    The struct kmem_cache for the new cache is allocated normally.
	 *    An __init data area is used for the head array.
	 * 3) Create the remaining kmalloc caches, with minimally sized
	 *    head arrays.
	 * 4) Replace the __init data head arrays for cache_cache and the first
	 *    kmalloc cache with kmalloc allocated arrays.
	 * 5) Replace the __init data for kmem_list3 for cache_cache and
	 *    the other cache's with kmalloc allocated memory.
	 * 6) Resize the head arrays of the kmalloc caches to their final sizes.
	 */

	/* 1) create the cache_cache */
	//高速缓存链表
	INIT_LIST_HEAD(&cache_chain);
	list_add(&cache_cache.next, &cache_chain);
	cache_cache.colour_off = cache_line_size();
	cache_cache.array[smp_processor_id()] = &initarray_cache.cache;
	cache_cache.nodelists[node] = &initkmem_list3[CACHE_CACHE];

	/*
	 * struct kmem_cache size depends on nr_node_ids, which
	 * can be less than MAX_NUMNODES.
	 */
	cache_cache.buffer_size = offsetof(struct kmem_cache, nodelists) +
				 nr_node_ids * sizeof(struct kmem_list3 *);
	/*************************************************************************************************************************************/
#if DEBUG
	cache_cache.obj_size = cache_cache.buffer_size;
#endif
	cache_cache.buffer_size = ALIGN(cache_cache.buffer_size,
					cache_line_size());
	/*************************************************************************************************************************************/
	cache_cache.reciprocal_buffer_size =
		reciprocal_value(cache_cache.buffer_size);

	for (order = 0; order < MAX_ORDER; order++) {
		cache_estimate(order, cache_cache.buffer_size,
			cache_line_size(), 0, &left_over, &cache_cache.num);
		if (cache_cache.num)
			break;
	}
	BUG_ON(!cache_cache.num);
	cache_cache.gfporder = order;
	cache_cache.colour = left_over / cache_cache.colour_off;
	cache_cache.slab_size = ALIGN(cache_cache.num * sizeof(kmem_bufctl_t) +
				      sizeof(struct slab), cache_line_size());

	/* 2+3) create the kmalloc caches */
	sizes = malloc_sizes;
	names = cache_names;

	/*
	 * Initialize the caches that provide memory for the array cache and the
	 * kmem_list3 structures first.  Without this, further allocations will
	 * bug.
	 */

	sizes[INDEX_AC].cs_cachep = kmem_cache_create(names[INDEX_AC].name,
					sizes[INDEX_AC].cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_PANIC,
					NULL);

	if (INDEX_AC != INDEX_L3) {
		sizes[INDEX_L3].cs_cachep =
			kmem_cache_create(names[INDEX_L3].name,
				sizes[INDEX_L3].cs_size,
				ARCH_KMALLOC_MINALIGN,
				ARCH_KMALLOC_FLAGS|SLAB_PANIC,
				NULL);
	}

	slab_early_init = 0;

	//创建32，64，128...65536，131072字节的obj的slab(kmalloc)
	while (sizes->cs_size != ULONG_MAX) {
		/*
		 * For performance, all the general caches are L1 aligned.
		 * This should be particularly beneficial on SMP boxes, as it
		 * eliminates "false sharing".
		 * Note for systems short on memory removing the alignment will
		 * allow tighter packing of the smaller caches.
		 */
		if (!sizes->cs_cachep) {
			sizes->cs_cachep = kmem_cache_create(names->name,
					sizes->cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_PANIC,
					NULL);
		}
#ifdef CONFIG_ZONE_DMA
		sizes->cs_dmacachep = kmem_cache_create(
					names->name_dma,
					sizes->cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_CACHE_DMA|
						SLAB_PANIC,
					NULL);
#endif
		sizes++;
		names++;
	}
	/* 4) Replace the bootstrap head arrays */
	{
		struct array_cache *ptr;

		ptr = kmalloc(sizeof(struct arraycache_init), GFP_KERNEL);

		local_irq_disable();
		BUG_ON(cpu_cache_get(&cache_cache) != &initarray_cache.cache);
		memcpy(ptr, cpu_cache_get(&cache_cache),
		       sizeof(struct arraycache_init));
		/*
		 * Do not assume that spinlocks can be initialized via memcpy:
		 */
		spin_lock_init(&ptr->lock);

		cache_cache.array[smp_processor_id()] = ptr;
		local_irq_enable();

		ptr = kmalloc(sizeof(struct arraycache_init), GFP_KERNEL);

		local_irq_disable();
		BUG_ON(cpu_cache_get(malloc_sizes[INDEX_AC].cs_cachep)
		       != &initarray_generic.cache);
		memcpy(ptr, cpu_cache_get(malloc_sizes[INDEX_AC].cs_cachep),
		       sizeof(struct arraycache_init));
		/*
		 * Do not assume that spinlocks can be initialized via memcpy:
		 */
		spin_lock_init(&ptr->lock);

		malloc_sizes[INDEX_AC].cs_cachep->array[smp_processor_id()] =
		    ptr;
		local_irq_enable();
	}
	/* 5) Replace the bootstrap kmem_list3's */
	{
		int nid;

		/* Replace the static kmem_list3 structures for the boot cpu */
		init_list(&cache_cache, &initkmem_list3[CACHE_CACHE], node);

		for_each_online_node(nid) {
			init_list(malloc_sizes[INDEX_AC].cs_cachep,
				  &initkmem_list3[SIZE_AC + nid], nid);

			if (INDEX_AC != INDEX_L3) {
				init_list(malloc_sizes[INDEX_L3].cs_cachep,
					  &initkmem_list3[SIZE_L3 + nid], nid);
			}
		}
	}

	/* 6) resize the head arrays to their final sizes */
	{
		struct kmem_cache *cachep;
		mutex_lock(&cache_chain_mutex);
		list_for_each_entry(cachep, &cache_chain, next)
			if (enable_cpucache(cachep))
				BUG();
		mutex_unlock(&cache_chain_mutex);
	}

	/* Annotate slab for lockdep -- annotate the malloc caches */
	init_lock_keys();


	/* Done! */
	g_cpucache_up = FULL;

	/*
	 * Register a cpu startup notifier callback that initializes
	 * cpu_cache_get for all new cpus
	 */
	register_cpu_notifier(&cpucache_notifier);

	/*
	 * The reap timers are started later, with a module init call: That part
	 * of the kernel is not yet operational.
	 */
}
