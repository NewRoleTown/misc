/proc/slabinfo中有活动缓存列表

kmalloc
kmem_cache_alloc


KMALLOC_MAX_SIZE
为kmalloc最大分配单体

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
	struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
    //percpu列表为空时从slab中获取的数目
	unsigned int batchcount;

	unsigned int limit;
    //percpu中保存的对象的最大数目
	unsigned int shared;

    //对象长度
	unsigned int buffer_size;
    //快速计算用
	u32 reciprocal_buffer_size;
/* 3) touched by every alloc & free from the backend */

    //缓存的性质,当前只有1中，标志着管理结构是否和slab在一起
	unsigned int flags;		/* constant flags */
    //每个slab中的对象数量
	unsigned int num;		/* # of objs per slab */

/* 4) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
    //每个slab中的页数的log数
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t gfpflags;

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
    //外部slab用，否则为0
	struct kmem_cache *slabp_cache;
	unsigned int slab_size;
	unsigned int dflags;		/* dynamic flags */

	/* constructor func */
	void (*ctor)(struct kmem_cache *, void *);

/* 5) cache creation/removal */
	const char *name;
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
    //对齐后的单体长度
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

这之后是一个链表式数组，标记可用对象

struct kmem_list3 {
    //部分空闲
	struct list_head slabs_partial;	/* partial list first, better asm code */
    //完全用尽
	struct list_head slabs_full;
    //完全空闲
	struct list_head slabs_free;
	unsigned long free_objects;
    //空闲对象上限
	unsigned int free_limit;
	unsigned int colour_next;	/* Per-node cache coloring */
	spinlock_t list_lock;
	struct array_cache *shared;	/* shared per node */
	struct array_cache **alien;	/* on other nodes */
	unsigned long next_reap;	/* updated without locking */
    //从这里移除一个对象后，置1,缓存收缩置0
	int free_touched;		/* updated without locking */
};

struct slab {
	struct list_head list;
	unsigned long colouroff;
    //第一个对象地址
	void *s_mem;		/* including colour offset */
    //非空闲对象数
	unsigned int inuse;	/* num of objs active in slab */
    //首个空闲下标
	kmem_bufctl_t free;
	unsigned short nodeid;
};

struct array_cache {
    //当前可用数
	unsigned int avail;
	unsigned int limit;
	unsigned int batchcount;
    //从这里移除一个对象后，置1,缓存收缩置0
	unsigned int touched;
	spinlock_t lock;
	void *entry[];	/*
			 * Must have this definition in here for the proper
			 * alignment of array_cache. Also simplifies accessing
			 * the entries.
			 */
};

在slab中的页，lru.next指向页驻留的缓存的管理结构
prev指向保存该页的slab的管理结构


static struct arraycache_init initarray_cache __initdata =
    { {0, BOOT_CPUCACHE_ENTRIES, 1, 0} };
static struct arraycache_init initarray_generic =
    { {0, BOOT_CPUCACHE_ENTRIES, 1, 0} };

/* internal cache of cache description objs */
static struct kmem_cache cache_cache = {
	.batchcount = 1,
	.limit = BOOT_CPUCACHE_ENTRIES,
	.shared = 1,
	.buffer_size = sizeof(struct kmem_cache),
	.name = "kmem_cache",
};

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

	/*
	 * Fragmentation resistance on low memory - only use bigger
	 * page orders on machines with more than 32MB of memory.
	 */
	if (num_physpages > (32 << 20) >> PAGE_SHIFT)
		slab_break_gfp_order = BREAK_GFP_ORDER_HI;

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
	INIT_LIST_HEAD(&cache_chain);
	list_add(&cache_cache.next, &cache_chain);
	cache_cache.colour_off = cache_line_size();
	cache_cache.array[smp_processor_id()] = &initarray_cache.cache;
	cache_cache.nodelists[node] = &initkmem_list3[CACHE_CACHE];

	/*
	 * struct kmem_cache size depends on nr_node_ids, which
	 * can be less than MAX_NUMNODES.
	 */
    //获取kmem_cache的大小
	cache_cache.buffer_size = offsetof(struct kmem_cache, nodelists) +
				 nr_node_ids * sizeof(struct kmem_list3 *);
#if DEBUG
	cache_cache.obj_size = cache_cache.buffer_size;
#endif
    //缓存对齐
	cache_cache.buffer_size = ALIGN(cache_cache.buffer_size,
					cache_line_size());
	cache_cache.reciprocal_buffer_size =
		reciprocal_value(cache_cache.buffer_size);

	for (order = 0; order < MAX_ORDER; order++) {
        //计算2^order页能包含多少个对象
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

    //建立array_cache和list3的slab
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

    //////////////////////////
	slab_early_init = 0;

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
        //替换静态的arraycache
		struct array_cache *ptr;

		ptr = kmalloc(sizeof(struct arraycache_init), GFP_KERNEL);

		local_irq_disable();
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
    ////////////////////////////////////////////////////////
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


struct kmem_cache *
kmem_cache_create (const char *name, size_t size, size_t align,
	unsigned long flags,
	void (*ctor)(struct kmem_cache *, void *))
{
	size_t left_over, slab_size, ralign;
	struct kmem_cache *cachep = NULL, *pc;

	if (!name || in_interrupt() || (size < BYTES_PER_WORD) ||
	    size > KMALLOC_MAX_SIZE) {
		BUG();
	}

	mutex_lock(&cache_chain_mutex);

#if DEBUG
	WARN_ON(strchr(name, ' '));	/* It confuses parsers */
#if FORCED_DEBUG
	/*
	 * Enable redzoning and last user accounting, except for caches with
	 * large objects, if the increased size would increase the object size
	 * above the next power of two: caches with object sizes just above a
	 * power of two have a significant amount of internal fragmentation.
	 */
	if (size < 4096 || fls(size - 1) == fls(size-1 + REDZONE_ALIGN +
						2 * sizeof(unsigned long long)))
		flags |= SLAB_RED_ZONE | SLAB_STORE_USER;
	if (!(flags & SLAB_DESTROY_BY_RCU))
		flags |= SLAB_POISON;
#endif
	if (flags & SLAB_DESTROY_BY_RCU)
		BUG_ON(flags & SLAB_POISON);
#endif
	/*
	 * Always checks flags, a caller might be expecting debug support which
	 * isn't available.
	 */
	BUG_ON(flags & ~CREATE_MASK);

	/*
	 * Check that size is in terms of words.  This is needed to avoid
	 * unaligned accesses for some archs when redzoning is used, and makes
	 * sure any on-slab bufctl's are also correctly aligned.
	 */
	if (size & (BYTES_PER_WORD - 1)) {
		size += (BYTES_PER_WORD - 1);
		size &= ~(BYTES_PER_WORD - 1);
	}

	/* calculate the final buffer alignment: */

	/* 1) arch recommendation: can be overridden for debug */
	if (flags & SLAB_HWCACHE_ALIGN) {
		/*
		 * Default alignment: as specified by the arch code.  Except if
		 * an object is really small, then squeeze multiple objects into
		 * one cacheline.
		 */
		ralign = cache_line_size();
		while (size <= ralign / 2)
			ralign /= 2;
	} else {
		ralign = BYTES_PER_WORD;
	}

	/*
	 * Redzoning and user store require word alignment or possibly larger.
	 * Note this will be overridden by architecture or caller mandated
	 * alignment if either is greater than BYTES_PER_WORD.
	 */
	if (flags & SLAB_STORE_USER)
		ralign = BYTES_PER_WORD;

	if (flags & SLAB_RED_ZONE) {
		ralign = REDZONE_ALIGN;
		/* If redzoning, ensure that the second redzone is suitably
		 * aligned, by adjusting the object size accordingly. */
		size += REDZONE_ALIGN - 1;
		size &= ~(REDZONE_ALIGN - 1);
	}

	/* 2) arch mandated alignment */
	if (ralign < ARCH_SLAB_MINALIGN) {
		ralign = ARCH_SLAB_MINALIGN;
	}
	/* 3) caller mandated alignment */
	if (ralign < align) {
		ralign = align;
	}
	/* disable debug if necessary */
	if (ralign > __alignof__(unsigned long long))
		flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);
	/*
	 * 4) Store it.
	 */
	align = ralign;

	/* Get cache's description obj. */
	cachep = kmem_cache_zalloc(&cache_cache, GFP_KERNEL);
	if (!cachep)
		goto oops;

#if DEBUG
	cachep->obj_size = size;

	/*
	 * Both debugging options require word-alignment which is calculated
	 * into align above.
	 */
	if (flags & SLAB_RED_ZONE) {
		/* add space for red zone words */
		cachep->obj_offset += sizeof(unsigned long long);
		size += 2 * sizeof(unsigned long long);
	}
	if (flags & SLAB_STORE_USER) {
		/* user store requires one word storage behind the end of
		 * the real object. But if the second red zone needs to be
		 * aligned to 64 bits, we must allow that much space.
		 */
		if (flags & SLAB_RED_ZONE)
			size += REDZONE_ALIGN;
		else
			size += BYTES_PER_WORD;
	}
#endif
	/*
	 * Determine if the slab management is 'on' or 'off' slab.
	 * (bootstrapping cannot cope with offslab caches so don't do
	 * it too early on.)
	 */
    //size大于等于512则启用外部slab描述
	if ((size >= (PAGE_SIZE >> 3)) && !slab_early_init)
		/*
		 * Size is large, assume best to place the slab management obj
		 * off-slab (should allow better packing of objs).
		 */
		flags |= CFLGS_OFF_SLAB;

	size = ALIGN(size, align);

	left_over = calculate_slab_order(cachep, size, align, flags);

	if (!cachep->num) {
		printk(KERN_ERR
		       "kmem_cache_create: couldn't create cache %s.\n", name);
		kmem_cache_free(&cache_cache, cachep);
		cachep = NULL;
		goto oops;
	}
	slab_size = ALIGN(cachep->num * sizeof(kmem_bufctl_t)
			  + sizeof(struct slab), align);

	/*
	 * If the slab has been placed off-slab, and we have enough space then
	 * move it on-slab. This is at the expense of any extra colouring.
	 */
	if (flags & CFLGS_OFF_SLAB && left_over >= slab_size) {
		flags &= ~CFLGS_OFF_SLAB;
		left_over -= slab_size;
	}

	if (flags & CFLGS_OFF_SLAB) {
		/* really off slab. No need for manual alignment */
		slab_size =
		    cachep->num * sizeof(kmem_bufctl_t) + sizeof(struct slab);
	}

	cachep->colour_off = cache_line_size();
	/* Offset must be a multiple of the alignment. */
	if (cachep->colour_off < align)
		cachep->colour_off = align;
	cachep->colour = left_over / cachep->colour_off;
	cachep->slab_size = slab_size;
	cachep->flags = flags;
	cachep->gfpflags = 0;
	if (CONFIG_ZONE_DMA_FLAG && (flags & SLAB_CACHE_DMA))
		cachep->gfpflags |= GFP_DMA;
	cachep->buffer_size = size;
	cachep->reciprocal_buffer_size = reciprocal_value(size);

	if (flags & CFLGS_OFF_SLAB) {
        //此描述符从这个缓存中获取
		cachep->slabp_cache = kmem_find_general_cachep(slab_size, 0u);
		/*
		 * This is a possibility for one of the malloc_sizes caches.
		 * But since we go off slab only for object size greater than
		 * PAGE_SIZE/8, and malloc_sizes gets created in ascending order,
		 * this should not happen at all.
		 * But leave a BUG_ON for some lucky dude.
		 */
		BUG_ON(ZERO_OR_NULL_PTR(cachep->slabp_cache));
	}
	cachep->ctor = ctor;
	cachep->name = name;

	if (setup_cpu_cache(cachep)) {
		__kmem_cache_destroy(cachep);
		cachep = NULL;
		goto oops;
	}

	/* cache setup completed, link it into the list */
	list_add(&cachep->next, &cache_chain);
oops:
	if (!cachep && (flags & SLAB_PANIC))
		panic("kmem_cache_create(): failed to create slab `%s'\n",
		      name);
	mutex_unlock(&cache_chain_mutex);
	return cachep;
}

//分配阶写在cachep里面
static void *kmem_getpages(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
	struct page *page;
	int nr_pages;
	int i;

	flags |= cachep->gfpflags;
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		flags |= __GFP_RECLAIMABLE;

	page = alloc_pages_node(nodeid, flags, cachep->gfporder);

	nr_pages = (1 << cachep->gfporder);
    //以下更新统计量,可回收/不可回收内存量
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		add_zone_page_state(page_zone(page),
			NR_SLAB_RECLAIMABLE, nr_pages);
	else
		add_zone_page_state(page_zone(page),
			NR_SLAB_UNRECLAIMABLE, nr_pages);
	for (i = 0; i < nr_pages; i++)
		__SetPageSlab(page + i);
	return page_address(page);
}

static int cache_grow(struct kmem_cache *cachep,
		gfp_t flags, int nodeid, void *objp)
{
	struct slab *slabp;
	size_t offset;
	gfp_t local_flags;
	struct kmem_list3 *l3;

	/*
	 * Be lazy and only check for valid flags here,  keeping it out of the
	 * critical path in kmem_cache_alloc().
	 */
	BUG_ON(flags & GFP_SLAB_BUG_MASK);
	local_flags = flags & (GFP_CONSTRAINT_MASK|GFP_RECLAIM_MASK);

	/* Take the l3 list lock to change the colour_next on this node */
	check_irq_off();
	l3 = cachep->nodelists[nodeid];
	spin_lock(&l3->list_lock);
    ...
	spin_unlock(&l3->list_lock);

	offset *= cachep->colour_off;

	if (local_flags & __GFP_WAIT)
		local_irq_enable();
    ...
	if (!objp)
		objp = kmem_getpages(cachep, local_flags, nodeid);

	/* Get slab management. */
	slabp = alloc_slabmgmt(cachep, objp, offset,
			local_flags & ~GFP_CONSTRAINT_MASK, nodeid);

	slab_map_pages(cachep, slabp, objp);

	cache_init_objs(cachep, slabp);

	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	check_irq_off();
	spin_lock(&l3->list_lock);

	/* Make slab active. */
	list_add_tail(&slabp->list, &(l3->slabs_free));
	STATS_INC_GROWN(cachep);
	l3->free_objects += cachep->num;
	spin_unlock(&l3->list_lock);
	return 1;
opps1:
	kmem_freepages(cachep, objp);
failed:
	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	return 0;
}


static struct slab *alloc_slabmgmt(struct kmem_cache *cachep, void *objp,
				   int colour_off, gfp_t local_flags,
				   int nodeid)
{
	struct slab *slabp;

	if (OFF_SLAB(cachep)) {
		/* Slab management obj is off-slab. */
		slabp = kmem_cache_alloc_node(cachep->slabp_cache,
					      local_flags & ~GFP_THISNODE, nodeid);
		if (!slabp)
			return NULL;
	} else {
		slabp = objp + colour_off;
		colour_off += cachep->slab_size;
	}
	slabp->inuse = 0;
	slabp->colouroff = colour_off;
    //由slab查缓存
	slabp->s_mem = objp + colour_off;
	slabp->nodeid = nodeid;
	return slabp;
}

static inline void *____cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *objp;
	struct array_cache *ac;

	check_irq_off();

	ac = cpu_cache_get(cachep);
	if (likely(ac->avail)) {
		STATS_INC_ALLOCHIT(cachep);
		ac->touched = 1;
		objp = ac->entry[--ac->avail];
	} else {
		STATS_INC_ALLOCMISS(cachep);
		objp = cache_alloc_refill(cachep, flags);
	}
	return objp;
}


static void *cache_alloc_refill(struct kmem_cache *cachep, gfp_t flags)
{
	int batchcount;
	struct kmem_list3 *l3;
	struct array_cache *ac;
	int node;

	node = numa_node_id();

	check_irq_off();
	ac = cpu_cache_get(cachep);
retry:
	batchcount = ac->batchcount;
	if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
		/*
		 * If there was little recent activity on this cache, then
		 * perform only a partial refill.  Otherwise we could generate
		 * refill bouncing.
		 */
		batchcount = BATCHREFILL_LIMIT;
	}
	l3 = cachep->nodelists[node];

	BUG_ON(ac->avail > 0 || !l3);
	spin_lock(&l3->list_lock);

	/* See if we can refill from the shared array */
	if (l3->shared && transfer_objects(ac, l3->shared, batchcount))
		goto alloc_done;

	while (batchcount > 0) {
		struct list_head *entry;
		struct slab *slabp;
		/* Get slab alloc is to come from. */
        //部分空闲表
		entry = l3->slabs_partial.next;
		if (entry == &l3->slabs_partial) {
            //部分和全空都用尽了
			l3->free_touched = 1;
			entry = l3->slabs_free.next;
			if (entry == &l3->slabs_free)
				goto must_grow;
		}

		slabp = list_entry(entry, struct slab, list);
        //检查使用中，空闲，总量是否等式成立
		check_slabp(cachep, slabp);
		check_spinlock_acquired(cachep);

		/*
		 * The slab was either on partial or free list so
		 * there must be at least one object available for
		 * allocation.
		 */
		BUG_ON(slabp->inuse < 0 || slabp->inuse >= cachep->num);

		while (slabp->inuse < cachep->num && batchcount--) {
			STATS_INC_ALLOCED(cachep);
			STATS_INC_ACTIVE(cachep);
			STATS_SET_HIGH(cachep);

            //获取对象，修改ctl链式数组的内容
			ac->entry[ac->avail++] = slab_get_obj(cachep, slabp,
							    node);
		}
		check_slabp(cachep, slabp);

		/* move slabp to correct slabp list: */
		list_del(&slabp->list);
		if (slabp->free == BUFCTL_END)
			list_add(&slabp->list, &l3->slabs_full);
		else
			list_add(&slabp->list, &l3->slabs_partial);
	}

must_grow:
	l3->free_objects -= ac->avail;
alloc_done:
	spin_unlock(&l3->list_lock);

	if (unlikely(!ac->avail)) {
		int x;
		x = cache_grow(cachep, flags | GFP_THISNODE, node, NULL);

		/* cache_grow can reenable interrupts, then ac could change. */
		ac = cpu_cache_get(cachep);
		if (!x && ac->avail == 0)	/* no objects in sight? abort */
			return NULL;

		if (!ac->avail)		/* objects refilled by interrupt? */
			goto retry;
	}
	ac->touched = 1;
	return ac->entry[--ac->avail];
}


static int cache_grow(struct kmem_cache *cachep,
		gfp_t flags, int nodeid, void *objp)
{
	struct slab *slabp;
	size_t offset;
	gfp_t local_flags;
	struct kmem_list3 *l3;

	/*
	 * Be lazy and only check for valid flags here,  keeping it out of the
	 * critical path in kmem_cache_alloc().
	 */
	BUG_ON(flags & GFP_SLAB_BUG_MASK);
	local_flags = flags & (GFP_CONSTRAINT_MASK|GFP_RECLAIM_MASK);

	/* Take the l3 list lock to change the colour_next on this node */
	check_irq_off();
	l3 = cachep->nodelists[nodeid];
	spin_lock(&l3->list_lock);

	/* Get colour for the slab, and cal the next value. */
	offset = l3->colour_next;
	l3->colour_next++;
	if (l3->colour_next >= cachep->colour)
		l3->colour_next = 0;
	spin_unlock(&l3->list_lock);

	offset *= cachep->colour_off;

	if (local_flags & __GFP_WAIT)
		local_irq_enable();

	/*
	 * The test for missing atomic flag is performed here, rather than
	 * the more obvious place, simply to reduce the critical path length
	 * in kmem_cache_alloc(). If a caller is seriously mis-behaving they
	 * will eventually be caught here (where it matters).
	 */
	kmem_flagcheck(cachep, flags);

	if (!objp)
		objp = kmem_getpages(cachep, local_flags, nodeid);

	/* Get slab management. */
	slabp = alloc_slabmgmt(cachep, objp, offset,
			local_flags & ~GFP_CONSTRAINT_MASK, nodeid);

	slabp->nodeid = nodeid;
	slab_map_pages(cachep, slabp, objp);

    //slab_bufctl(slabp)[i] = i + 1;
	cache_init_objs(cachep, slabp);

	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	check_irq_off();
	spin_lock(&l3->list_lock);

	/* Make slab active. */
	list_add_tail(&slabp->list, &(l3->slabs_free));
	STATS_INC_GROWN(cachep);
	l3->free_objects += cachep->num;
	spin_unlock(&l3->list_lock);
	return 1;
opps1:
	kmem_freepages(cachep, objp);
failed:
	if (local_flags & __GFP_WAIT)
		local_irq_disable();
	return 0;
}

static inline void __cache_free(struct kmem_cache *cachep, void *objp)
{
	struct array_cache *ac = cpu_cache_get(cachep);

	check_irq_off();
	objp = cache_free_debugcheck(cachep, objp, __builtin_return_address(0));

    //cache array上的对象数还没有到最大值就直接释放到上面
	if (likely(ac->avail < ac->limit)) {
		STATS_INC_FREEHIT(cachep);
		ac->entry[ac->avail++] = objp;
		return;
	} else {
		STATS_INC_FREEMISS(cachep);
		cache_flusharray(cachep, ac);
		ac->entry[ac->avail++] = objp;
	}
}

cache_flusharray(cachep, ac);---free_block，之后将entry数组后面的项挪到前面
static void free_block(struct kmem_cache *cachep, void **objpp, int nr_objects,
		       int node)
{
	int i;
	struct kmem_list3 *l3;

	for (i = 0; i < nr_objects; i++) {
		void *objp = objpp[i];
		struct slab *slabp;

		slabp = virt_to_slab(objp);
		l3 = cachep->nodelists[node];

        //先断链
		list_del(&slabp->list);

		check_spinlock_acquired_node(cachep, node);
		check_slabp(cachep, slabp);

		slab_put_obj(cachep, slabp, objp, node);

		STATS_DEC_ACTIVE(cachep);
		l3->free_objects++;
		check_slabp(cachep, slabp);

		if (slabp->inuse == 0) {
			if (l3->free_objects > l3->free_limit) {
                //free slab数大于限制数量，释放一个slab
				l3->free_objects -= cachep->num;
				slab_destroy(cachep, slabp);
			} else {
                //链入全空
				list_add(&slabp->list, &l3->slabs_free);
			}
		} else {
			/* Unconditionally move a slab to the end of the
			 * partial list on free - maximum time for the
			 * other objects to be freed, too.
			 */
			list_add_tail(&slabp->list, &l3->slabs_partial);
		}
	}
}


static void slab_put_obj(struct kmem_cache *cachep, struct slab *slabp,
				void *objp, int nodeid)
{
	unsigned int objnr = obj_to_index(cachep, slabp, objp);

	slab_bufctl(slabp)[objnr] = slabp->free;
	slabp->free = objnr;
	slabp->inuse--;
}

flush_cache_mm()
    操作页表
flush_tlb_mm

刷出高速缓存，操作内存，刷出TLB
某些体系需要依赖tlb拿cache







/*

4.花王cruel的控油保湿系列（这个牌子的这个系列真是为敏感肌且混油或油皮而生的啊，完全不用在意用了会敏感！）
5.芙丽芳丝 控油调护系列 和 保湿修护系列 （也是无添加的牌子，比较温和，适合敏感肌）

①油性皮肤如何控油

②干性瘙痒皮肤如何处理

③红血丝皮肤怎么办

④色素性皮肤如何护肤

-----------------------------------------------------

①油性皮肤如何控油



油性痘痘肌常常给爱美的年轻人平添了不少烦恼，有人说，青春期之后就不会再长痘了，事实上，成年人也会因工作、生活压力导致内分泌失调而同样长痘。青春痘是清洁不彻底引起的吗？青春痘是饮食不当引起的吗？对于油性痘痘肌我们应当怎样应对呢？本篇将告诉您怎样只留“青春”，不留“痘”。


背景知识1：什么是青春痘？

青春痘学名痤疮，是皮肤科最常见的疾病之一，据统计，80～90%的青少年患过痤疮。痤疮在青春期过后往往能自然减轻和痊愈，但也有少数人一直到40岁仍然有痤疮。痤疮是皮肤上毛囊皮脂腺单位的病变，表现可以是粉刺、丘疹、脓疱、囊肿和瘢痕形成。当今最有名的痤疮患者当属田径运动大明星刘翔，大明星脸上的小坑就是痤疮愈合后留下的瘢痕

民间有“十男九痔”的说法，意思是说痔疮发病率很高，从这个角度上看，痤疮决不输给痔疮。不管男女，10个人中就有8～9个得过痤疮，但为什么上大街一走，多数人脸上还是比较平整，而刘翔哥脸上的小坑却有如月球上的环形山呢？这还要从痤疮的发病机制说起。


背景知识2：痤疮是怎么来的

痤疮由多种原因造成，最重要的相关因素有遗传易患性、激素水平变化、饮食不当、精神压力、皮肤护理不当等。高雄激素水平、皮脂腺大量分泌、局部细菌增殖、毛囊皮脂腺导管角化异常是痤疮发病过程中的4个核心环节。

青春期，在雄性激素的刺激下（雄激素不是男性专利，女性体内的肾上腺皮质部分也有雄激素分泌），人体的皮脂分泌增加，毛囊皮脂腺导管也受雄激素影响而过度角化。由于导管口径变小、狭窄或阻塞，皮脂等物质不能正常排出，于是在开口处聚集。起初这些聚集物比较松散，随压力增大，它们逐渐变得紧密而形成板层凝固物。这时皮肤表面会鼓起一些白色或黑色尖顶的小丘疹，称为白头或黑头粉刺。挤出的粉刺中有白色凝乳状团块，就是由这些板层凝固物组成。在这些堆积物质的滋养下，原本定植于皮肤的一些正常细菌开始异常繁殖，从而诱导皮肤产生炎症，于是形成了红色的丘疹和脓疱。如果堵塞物继续堆积，粉刺内部破裂导致局部炎症加剧并破坏了局部真皮组织，则会形成结节、囊肿，最终留下瘢痕。

在痤疮发生的早期进行干预，通过减少皮脂分泌、解除毛囊堵塞、抑制局部细菌繁殖等各种医学手段控制痤疮的发展，可以防止痤疮变成结节或囊肿型，减少遗留瘢痕的风险。目前通过这些方面治疗痤疮的药物发展较为成熟，因此，得了痤疮不要紧，在初起时积极就医，多数可以控制和治愈。


粉刺到底能不能挤？
图示面部危险三角区：指两侧口角至鼻根连线所形成的三角形区域。

对于粉刺而言，人们曾经尝试过取出皮肤中的粉刺，以改善外表，并帮助提高粉刺溶解剂等药物的治疗效果。在医院内，开口粉刺的角质内容物可以用粉刺挤出器挤出。尤其对于深在、浓缩而持久的粉刺，外用药物联合粉刺挤出可以获得较好的疗效。但是，如果是挤压炎性粉刺或者脓头，则很可能留下瘢痕。现在治疗痤疮主要依靠外用和口服药物治疗，效果基本令人满意，粉刺挤出这一操作在医疗机构实行得已经越来越少。

换句话说，医院都尽量不进行的操作，在家做风险会更大。一来，自己挤粉刺不能很好分辨哪些能挤、哪些不能挤，因此很容易挤到炎性的粉刺，从而遗留瘢痕。二来，自行操作对于机械和皮肤的消毒往往不到位，从而增加了感染的风险，而局部皮肤感染进一步增加了遗留瘢痕的风险。运气再差点，如果挤的炎症性痤疮位于面部危险三角区里，还有可能使感染播散到颅内，导致海绵窦血栓性静脉炎，这种情况将有可能危及生命。因此，自己挤粉刺是一种很不明智的做法。对于痘痘，能不碰尽量不要碰。


停车坐爱枫林晚，得了痤疮怎么办？

痤疮根据皮肤损害的类型和严重程度，有一套系统和规范的治疗方法。大多数人无法准确判断自己的病情，应该及时就医。

轻中度痤疮如果是以粉刺为主的损害或者皮肤较为粗厚的痤疮患者，则在整个面部（避开眼部）使用维A酸乳膏或者阿达帕林凝胶是一个较好的选择。对于丘疹、脓疱型的痤疮，则应在外用维A酸类药物的基础上，在丘疹和脓疱局部外用抗菌药物，如过氧化苯甲酰凝胶等。中重度痤疮的治疗需要口服药物。常用的口服药物有红霉素、四环素、具有抗雄激素活性的口服避孕药以及口服维A酸类药物(如异维A酸胶丸)等。


“痘印”是什么？

很多人即使痤疮消除后脸上仍然会留下或黑或红的“痘印”，这是为什么呢？由于痤疮往往伴有局部皮肤的炎症，而炎症清除后大多会有短期的炎症后色素沉着，因此会留下黑色的痘印。而略微严重的炎症可引起局部毛细血管扩张、增生，从而留下红色的痘印。这两种痘印在痤疮控制后都会慢慢消退，无需特别处理。维A酸类药物由于其对表皮分化具有调整作用，因而适量外用可以加速痘印的去除。而含有肝素类物质因其抗炎和促进皮肤愈合的作用，对痘印的去除也有一定帮助。


痤疮留疤了怎么办？

痤疮最让人苦恼的危害是瘢痕形成。对于痤疮瘢痕治疗常常无法获得满意的效果，无法再完全恢复皮肤的平整光滑。但一些医疗手段可以对瘢痕的外观有一定改善，比如点阵激光、微晶磨削、化学或者激光皮肤剥脱术甚至手术切除等。对于严重的痤疮瘢痕，医生也回天乏术。因此在最后还是要再次强调，患上痤疮应当及时治疗，避免病情加重而遗留瘢痕！。


油性痘痘肌日常护理的七个细节

除了以上这些治疗对策，生活中一些细节也能帮助我们尽可能远离痤疮的伤害：

营养均衡

高糖食物比高脂肪食物更易刺激皮脂腺的过度分泌，因此，应减少精制淀粉、糖果等高血糖指数食物的摄入。高碘食物、乳酪等也可促进皮脂分泌，因而适当减少这类食物的摄入也对皮肤有帮助。此外，缺乏某些维生素也可导致皮肤粗糙、毛囊角化异常，因此均衡的营养摄入对皮肤健康有益。

睡眠规律不熬夜

在夜间，肾上腺皮质会进入休眠状态，各种肾上腺皮质激素分泌都处于较低水平，但熬夜时，这些激素的分泌会增加。而高水平的肾上腺皮质激素和部分来源于肾上腺皮质的雄激素正是痤疮的元凶之一，因此规律的睡眠对于预防痤疮的产生是必要的。

精神放松，缓解压力

情绪紧张、精神压力大也是一种应激因素，可导致肾上腺皮质的分泌亢进，导致内分泌失调，诱发痘痘产生。因此要学会放松自己，多做一些让自己心情愉快的事情，适当减轻每天工作或学业上的压力。

适当运动

研究表明，规律的有氧运动可抑制雄激素的过度分泌，对痤疮有一定预防作用。有效的有氧运动可总结为“3、5、7”三个数字：连续运动不少于30分钟；每周确保运动5天；运动时的适宜心率为（170 - 年龄）。适度运动可以促进新陈代谢，对于心血管及皮肤健康都有好处。但应注意观测室外空气污染情况，不要在污染天气进行室外运动。

正确洗脸

无泡洁面产品清洁力差，无法解除皮脂和角质的堆积；反之使用去污力和刺激性较强的清洁用品或洗脸次数过多反而会刺激皮脂腺分泌更多的油脂。香皂等固体清洁剂易与硬水结合为钙皂，堵塞毛孔。因此，最好选用痤疮皮肤专用的性质柔和的液体泡沫型洁面产品。除了洗脸之外，毛发也是细菌附着的温床，因此，勤剃须勤洗头有助于降低细菌的携带量。

管住双手

双手一直暴露在外面，常会接触各种各样的东西，难免有污染，一双沾满灰尘和细菌的手总去摸脸时，必然将环境中的细菌带到脸上，造成皮肤感染，加重痘痘。此外，再次强调尽量不要用手挤已经长出的痘痘。

注意环境清洁

重度污染时出门最好带口罩。有的痤疮经过正规治疗仍不好转要考虑特殊类型的痤疮，如革兰氏阴性菌毛囊炎、真菌性毛囊炎、毛囊虫皮炎甚至玫瑰痤疮等。对于这类情况，应当注意直接接触面部的家居用品的清洁，平时用的被子、床单、枕头、洗脸毛巾等，要时常保持清洁，定期清洗和更换，可适当在阳光下晾晒，以除去上面的细菌和螨虫，这对预防痘痘也有一定的帮助。





----------------------------------------------------

②干性瘙痒皮肤如何处理


身边总有一些朋友一到了冬天来暖气便浑身皮肤不自在，干燥、瘙痒、脱皮总伴随左右。有时用热水烫一烫就觉得特别解痒，过后反而痒得更厉害了。另外还有一些朋友抱怨皮肤总是十分粗糙，看起来跟蛇皮一样。皮肤干燥是因为缺水吗？用热水烫一烫皮肤是否能缓解瘙痒？怎样防止皮肤干燥掉皮？本篇将向您详细解答干性瘙痒性皮肤的应对策略。


皮肤的屏障功能

说到皮肤干燥，首先我们先要了解皮肤的屏障功能。完整的皮肤屏障能够将机体与外界有害因素隔离，抵抗它们对机体的侵袭和损伤，防止体内营养物质、水分的丢失。如果皮肤屏障受损，水分便会经表皮蒸发流失，皮肤将出现干燥、脱屑、瘙痒。同时，受损的皮肤屏障对外界微生物及过敏物质的抵御作用减弱，可诱发和加重某些皮肤病发生。那么，如此重要的皮肤屏障是由什么构成的呢？

皮肤屏障结构的基础是位于皮肤的表面的角质层，由死亡的表皮角质细胞互相重叠交错排列而成，这就是人们常说的“死皮”。这些细胞之间由细胞间脂质相互粘合，形成牢固的“砖墙结构”：砖块就是死去的角质细胞，水泥就是细胞间脂质。细胞间脂质主要由脂肪酸、神经酰胺和胆固醇等组成，这些脂质不但维持着皮肤屏障的完整性，防止过多水分经表皮蒸发流失，还有滋润角质层、抑制细菌生长、抗皮肤老化的作用。因而过度清洁、去角质事实上是在损伤皮肤屏障结构。

与细胞间脂质相对应的是皮肤表面脂质，又叫皮脂。皮脂由皮脂腺分泌，主要成分是脂肪酸、蜡脂和角鲨烯。皮脂与汗液中的水分及皮肤代谢产物等共同组成皮肤最外层的水脂膜。这层水脂膜除了润滑皮肤之外，能减少皮肤表面的水分蒸发，也是皮肤屏障的重要组成部分和第一道防线。过度洗涤可使这些脂质流失破坏皮肤的水脂膜屏障，造成水分过量蒸发及皮肤干燥，这是老年性皮肤瘙痒症的原因。

皮肤水脂膜还有许多代谢产物或水溶性物质，在皮肤屏障结构中起到重要的保持水分功能，被称为天然保湿因子（NMF），主要由氨基酸、吡络烷酮羧酸、乳酸盐、尿素等物质构成。天然保湿因子的这些成分不仅存在于表皮水脂膜，也分布在角质层细胞间隙中。它们与蛋白质和脂质共同使角质层保持一定的含水量，维持着角质层内外的水分平衡。皮肤屏障结构的破坏导致天然保湿因子流失，皮肤的保湿作用也会相应下降。

皮肤表面脂质与细胞间脂质的来源和成分都有所不同，皮肤表面脂质（皮脂）的成分中以角鲨烯为标志，而细胞间脂质的特征性成分为神经酰胺。因此，保湿类护肤品因其主要成分不同，侧重的屏障保护和修复效果也略有不同。正常皮肤选用含脂肪酸、蜡脂、角鲨烯等皮肤表面脂质或其近似成分的护肤品即可，而对于一些干燥性、瘙痒性、敏感性、炎性皮肤病等合并皮肤屏障损伤的患者，应选用额外添加神经酰胺的护肤品，帮助角质层“砖墙结构”的修复。


皮肤干燥是因为缺水吗？

事实上，皮肤的“供水系统”是由内及外的，真皮血管网负责供应表皮的水分和营养。皮肤干燥往往并非由于水分不足，而是皮肤表面脂质屏障受损导致天然保湿因子流失和水分蒸发过多所致。因此，缺水的本质还是缺油，想要补水，首先要补充皮肤生理性脂质。保湿的方法并不是敷黄瓜、面膜，而是通过保护和修复皮肤屏障，使皮肤表面的脂质阻止水分的过度蒸发。使用含有类似皮肤表面脂质成分的保湿产品，能够恢复皮肤的润泽，也有助于修复受损的皮肤表面屏障结构，缓解皮肤干燥。


皮肤为什么会越抓越痒？

很久以前，人们曾认为，瘙痒是一种特殊的疼痛。但后来的研究表明，瘙痒由独立的神经元感受和传递，与疼痛的神经感受和传导机制并不相同。皮肤病相关的瘙痒大多和皮肤屏障受损，外界刺激物和过敏原进入皮肤，刺激瘙痒相关炎症介质（如组胺和P物质等）的释放有关。同时，皮肤干燥时其物理性状也会发生改变，这种变化如果被角质层下部的神经末梢感受器所感受也会产生瘙痒症状。搔抓可以通过神经的抑制机制暂时控制瘙痒，但反而使神经变得对机械刺激更为敏感。搔抓同时也会刺激皮肤，增加皮肤内瘙痒相关炎症物质的释放，带来更为剧烈的瘙痒，形成“痒—抓—痒”的恶性循环。


长期反复的皮肤干燥瘙痒有可能是哪些皮肤病引起的？

很多皮肤病都合并干燥、瘙痒的症状，但多数为一过性，随着皮肤的新老更替和自我修复，都可以逐渐好转。但一些慢性或者遗传性皮肤病，由于皮肤屏障受损而修复又有障碍，可带来持久或反复的皮肤干燥和瘙痒，包括特应性皮炎、寻常型鱼鳞病、银屑病、老年瘙痒症和手部湿疹等。


干性皮肤护理的5个要点

干性瘙痒性皮肤的日常护理应当注意些什么呢？由于皮肤屏障破坏能导致或者加重皮肤的干燥和瘙痒，因此干性皮肤的护理主要是围绕皮肤屏障的保护和修复来进行的。下面5点有助于应对干性皮肤所出现的各种问题：

减少过度清洁

起泡类清洁用品或多或少都会在去除污垢的同时带走皮肤表面的脂质，因此干性皮肤的朋友应当适当减少洗澡频率，夏季可1-2天洗一次，冬季可3-5天洗一次，给皮肤屏障自我修复的时间。此外应当尽量慎用去角质的磨砂膏等日用品，避免角质层的过量丢失。

皮肤的清洁过程应尽量温和

碱性过强的肥皂或者清洁力过强的清洁用品能够迅速带走皮肤表面脂质，破坏水脂膜，引起皮肤屏障损伤。过热的水虽然能够暂时抑制瘙痒的感觉，但另一方面会加速皮肤表面的脂质流失（想想洗碗时是不是热水更容易去除油污），还会刺激皮肤释放炎性物质，导致瘙痒加重。此外，长时间浸泡皮肤（如泡脚、泡澡和长时间游泳）也会使皮脂流失、角质层过度吸水膨胀，通透性增加，导致皮肤屏障损伤，因此干性皮肤应当避免上述这些习惯。

选择适合自己的保湿剂

如果既想天天洗澡，又不想皮肤干燥瘙痒，那么选择一款适合自己的保湿剂是必不可少的。理想的保湿剂应含有与皮肤生理性脂质成分相似的成分：游离脂肪酸、神经酰胺、胆固醇。记住，甘油和食用油并不是理想的保湿剂！甘油不是油，而是一种水溶性的醇类，不能阻止皮肤水分蒸发，外界空气干燥时，反而会吸取皮肤内的水分。橄榄油等食用油富含脂肪酸，但缺少其他生理性脂质成分，因此不能有效保护和修复皮肤屏障。沐浴后迅速使用保湿剂，能够“锁住”皮肤已经吸收的水分，促进皮肤屏障修复。

避免搔抓刺激皮肤

要打断“痒—抓—痒”的恶性循环，管住自己的手是十分重要的。干性皮肤出现瘙痒时应当尽量避免搔抓。剧烈的瘙痒除了积极治疗原发皮肤病外，还可通过使用帮助皮肤屏障修复的润肤剂以及在医生指导下使用抗组胺药物来从源头上控制瘙痒。

注意劳动保护

如果自己的皮肤屏障很脆弱，不妨借助外来“雇佣兵”的能力，买一双橡胶手套来保护自己的双手。比如从事一些需要用水清洗的工作（如洗发、餐饮、印染）及家务（洗衣服、洗菜、洗碗）时，勤戴手套是保护双手的一个非常不错的办法。


----------------------------------------------------


③红血丝皮肤怎么办



健康的皮肤具有完整的屏障功能，能够抵抗外界日常的物理、化学因素和微生物对皮肤的损伤。皮肤屏障完整的人使用大多数护肤品都不会出现皮肤发红、刺痛感，也很少出现红血丝和脱屑的现象。但一部分人就没有那么幸运了。据国外资料，超过40%的人是敏感性皮肤。敏感性皮肤除了皮肤经常出现发红发痒，还容易受到护肤品中某些成分的刺激而产生不适。敏感皮肤还能正常化妆吗？皮肤上的红血丝应当怎样去除？本篇将告诉你怎样对抗红血丝皮肤。


什么是红血丝？

我们知道，正常皮肤的结构从表到里分为表皮层、真皮层。表皮中没有血管，其营养代谢有赖于真皮血管网的供应。由于不透明的表皮的遮盖，位于真皮层的血管通常是并不抛头露面的，它们默默工作时我们只能从外面隐约看到皮肤粉润的颜色。即使是天气炎热或者晒伤时，皮肤也只会变得潮红，其中的一根根血管并不能被一一辨认。但在一些炎症状态下，血管受到炎性物质的作用会出现剧烈扩张，尤其是慢性炎症状态下，皮肤还会产生异常的新生血管，这样我们便会在皮肤表面看到一根根可辨的红血丝。当皮肤屏障发生异常时，表皮还会变薄，本来被遮盖的血管更加显露无余。


什么导致了皮肤敏感和红血丝？

通常我们所说的敏感性皮肤是一种亚健康的皮肤状态，主要与遗传相关，同时也受到内分泌、情绪、微生物等多种因素的影响。敏感皮肤经过适当的护理和生活方式调整，敏感状态能够逐渐减轻，至少不会对生活造成太大影响。而随着皮肤炎症的加重和慢性炎症对皮肤影响的时间延长，亚健康状态慢慢过渡到炎症性皮肤病。出现面部发红刺痛的炎症性皮肤病中，脂溢性皮炎和玫瑰痤疮是最常见的两种。


什么是脂溢性皮炎？
脂溢性皮炎患者(http://dermis.net)

脂溢性皮炎是发生在头面部、胸前等出油区域的轻度慢性湿疹。典型的临床表现是头皮、面部，尤其是鼻旁和口周的轻度红斑、瘙痒和皮肤脱屑。脂溢性皮炎的确切的发病机制并不完全清楚，但异常的皮脂分泌和一种称为糠秕马拉色菌的真菌大量繁殖被认为是脂溢性皮炎发病的重要原因。糠秕马拉色菌大量繁殖分解皮脂中的甘油三酯，产生游离脂肪酸，刺激表皮代谢加快，同时导致皮肤局部炎症状态和皮肤屏障破坏，而皮肤屏障破坏和炎症物质刺激皮脂异常分泌，过多的脂质又进一步促进糠秕马拉色菌的繁殖，形成恶性循环。脂溢性皮炎患者的皮肤由于屏障受损，对外界刺激十分敏感，皮肤暴露于日光、高温环境或使用某些化妆品会引起皮肤瘙痒、刺痛，这些外界刺激反过来又促进了皮肤炎症的加重及扩散。长期脂溢性皮炎往往导致血管异常扩张和增生，于是转变为另一种更为严重和持久的炎症性皮肤病——玫瑰痤疮。


玫瑰痤疮，到底是玫瑰还是痤疮？
Bill Clinton

通常经典的玫瑰痤疮指人们俗称的“酒糟鼻”，但鼻子并非玫瑰痤疮的唯一受害者，整个面部乃至眼睛都有可能罹患这种慢性炎症。玫瑰痤疮与寻常痤疮（即“青春痘”，也就是我们通常在默认情况下所说的“痤疮”）不同，虽然二者有时相伴出现在同一张脸上，但伴有持久而明显的血管扩张（红血丝）是玫瑰痤疮的标志之一，而寻常痤疮和脂溢性皮炎往往看不到清晰可辨的红血丝。面部血管扩张导致血浆中的炎症物质进入皮肤，而皮肤局部炎症物质升高又刺激血管进一步扩张，形成又一个恶性循环。玫瑰痤疮的确切原因目前仍未完全明确，但现有资料显示，日晒、营养失衡、过量饮酒、药物、胃肠紊乱、精神紧张、内分泌异常、皮肤局部细菌异常繁殖等多种因素可以诱发玫瑰痤疮。一些玫瑰痤疮与毛囊蠕形螨过量繁殖有关，因此有时玫瑰痤疮与毛囊虫皮炎在表现和治疗方法方面都有相似之处。玫瑰痤疮患者的代表人物为美国前总统比尔克林顿（Bill Clinton），相信大家对他的红鼻头都印象深刻。


激素依赖性皮炎

面部短期使用中弱效类固醇激素是皮肤科医生应对某些面部皮炎的常用方案，激素是一种奇妙的药物，具有抗炎、收缩血管、抗表皮增生等效应，能够使炎症状态下粗糙发红的皮肤变得光滑细腻。某些不法商家看中了激素这种短期效果，将其添加于化妆品中出售，导致消费者在不知情的状况下长期使用。俗话说是药三分毒，激素在抗炎抗增生的同时，也使表皮萎缩变薄，同时皮肤对激素产生依赖，在停用之后，出现皮肤瘙痒、炎症性丘疹、毛细血管扩张等皮肤炎症状态，一根根红血丝也出现在脸上。这种和激素相关的皮肤问题现在也被纳入玫瑰痤疮的诊断之中，由于和类固醇激素相关，有人也称之为“激素依赖性皮炎”。由于我国对化妆品的监管力度较弱，在利益驱使下，添加类固醇激素的化妆品打着各种“秘方”、“神器”的旗号大行其道，造成了激素依赖性皮炎的大量出现。


敏感性及红血丝皮肤的应对策略

对于敏感性或者红血丝皮肤，如果是由于长期使用激素药物或者含有激素的不法化妆品所致，那么应当亡羊补牢，及时停用这些产品。由于敏感性皮肤往往有皮肤屏障的损伤和破坏，因此，应当选择一些性质温和，成分尽量简单的护肤品。神经酰胺是细胞间脂质的关键成分之一，近年来逐步被人们所认识，一些新近开发的含有神经酰胺的护肤品能够促进皮肤屏障的修复，对敏感皮肤来说是个不错的选择。

由于敏感皮肤往往表皮较薄，对日光的防御能力较差，而日光本身作为一种物理刺激能够加重皮肤的炎症状态。因此防晒是敏感皮肤日常护肤中的重要步骤。防晒产品的主要功效成份可以分为以反射紫外线为主的物理性防晒成份和以吸收紫外线为主的化学性防晒成份。正常皮肤对各种防晒成份的耐受性都比较好，但敏感性皮肤对防晒产品中的某些化学防晒成分有可能出现不耐受的情况，因此，以二氧化钛和氧化锌等物理性防晒剂作为主要成分的防晒产品对敏感性皮肤来说相对温和。

敏感皮肤使用某些护肤产品出现刺痛通常并不是由于过敏引起，刺痛是由于表皮角质层过薄，皮肤屏障较差，导致真皮内敏感的神经末梢暴露所致。因此，避免过度清洁能够保护残留角质层，给皮肤屏障一个良好的修复环境。另外，经常出现皮肤刺痛的人群应当谨慎使用酸性或者去角质成分的产品。

一些含有抗炎、控油等活性成分（如烟酰胺及吡咯烷酮羧酸盐）的功能性护肤品对敏感皮肤具有舒缓和调理作用。烟酰胺属于一种B族维生素，具有抗炎、抗氧化和平衡油脂分泌的作用，口服或外用均表现出一定效果，被添加于多种护肤品中。吡咯烷酮羧酸盐（PCA）是一种氨基酸衍生物，是皮肤角质层中天然保湿因子（NMF）的主要成分之一。除了保湿效果之外，PCA铜及PCA锌有一定的抗炎和控油效果。

一些情况较为严重的皮肤炎症，需要在医生指导下用药治疗。外用药物中，抗真菌药酮康唑、含硫洗剂（如二硫化硒），以及含有吡硫翁锌（ZTP）的洗剂具有抑制糠秕马拉色菌的作用，因此对于脂溢性皮炎具有一定效果；外用甲硝唑凝胶、他克莫司等能够缓解轻度玫瑰痤疮的症状。严重的脂溢性皮炎和玫瑰痤疮需要就诊，在皮肤科医生指导下使用口服药物治疗，红血丝的持久存在影响外观，可以通过脉冲染料激光等物理治疗去除。


敏感性皮肤护理的6个细节避免高温，注意防晒

过热的饮料、辛辣刺激性食物可刺激皮肤，加重炎症状态，因此，应当尽量减少摄入这类食物。高温环境促使皮肤血管扩张，因此应当尽量避免泡热水澡、蒸桑拿、高温天气下长时间的户外活动等。白天出门应注意防晒，防止日光对皮肤的进一步损伤。

避免机械刺激

搔抓、摩擦或者按摩皮肤也是刺激皮肤的因素，并且容易将细菌等微生物传给皮肤，带来多重感染，所以请尽量克制这些习惯。

适度控油

除了使用温和的洁面泡沫进行有效清洁外，使用含有锌盐或烟酰胺的护肤品，能够减少过多的皮脂分泌。适当摄入粗粮等富含B族维生素的食物，也可以调节皮肤油脂的平衡，对缓解脂溢性皮炎等与油脂分泌异常有关的皮肤问题有帮助。

抗炎抗氧化

鱼油、亚麻籽油等富含ω-3脂肪酸的食物具有抗炎症活性，有条件可以酌情选择。氧化应激和炎症关系密切，适量摄入具有抗氧化功效的成分如茶多酚、辅酶Q10、α-硫辛酸等或许能降低皮肤的氧化应激水平，减轻炎症。

戒烟限酒

吸烟可增加体内氧化应激水平，使皮肤倾向炎症状态，因此应当立刻戒烟；酒精不但刺激皮肤，还会扩张面部血管，加重面部潮红和红血丝，应当尽量避免摄入。

生活规律，精神放松

皮肤的状态也受神经、内分泌因素影响，保证规律的生活、充足的睡眠，同时注意自我情绪的调整和放松，能够缓解神经和内分泌系统的压力，对皮肤改善有益。





----------------------------------------------------


④色素性皮肤如何护肤



俗话说，“一白遮百丑”，西方白种人如今已在煞费苦心地想要变黑，以小麦色甚至古铜色皮肤为美，而美白似乎仍然是东方人亘古不变的追求。不过，不管是东方人还是西方人，审美取向有多大差异，色斑导致的肤色不均却是地球人共同深恶痛绝的。皮肤的颜色从何而来？什么原因导致皮肤变黑？面部出现色斑该怎么办？怎样科学的美白？本篇将向你介绍色素性皮肤的应对策略。


皮肤的颜色从何而来？

影响皮肤颜色的因素是多方面的，其中黑素是决定肤色的主要因素。表皮基底层的黑素细胞将其合成的黑素转移到邻近的36个表皮角质形成细胞，形成一个功能单位，称为表皮黑素单位。黑素生成、转移和降解过程中任何一个环节出现问题，均可影响黑素代谢，导致皮肤颜色变化。此外，皮肤颜色还与皮肤内胡萝卜素及血管内氧化血红蛋白和还原血红蛋白的相对含量有关。

皮肤的黑素主要可以分真黑素和褐黑素两种。真黑素颜色较深，是构成有色人种皮肤颜色的主要因素；褐黑素为红褐色，与红头发和雀斑有关。真黑素和褐黑素的合成都是在黑素细胞内进行的。在酪氨酸酶的作用下，体内的酪氨酸转化为多巴，再进一步转化为多巴醌，进而形成黑素，以黑素小体的形式转移至附近的表皮细胞。表皮细胞由内向外更替，最终将黑素带到皮肤表面。由于丁达尔（Tyndall）现象，黑素位于皮肤不同深度所呈现的颜色有所差别，位于表皮的黑素呈现棕色至黑色（皮肤黑斑的颜色），位于真皮层的黑素呈现为灰色至蓝色（蓝痣或太田痣的颜色）。


皮肤为什么会变黑或者出现色斑呢？

皮肤的颜色主要由遗传因素决定，后天因素中影响肤色的最明确且可干预的因素是日光（紫外线）的照射。病理性因素中，炎症后色素沉着和系统性用药反应是导致皮肤色素沉着过度的两个最重要的原因。此外，肤色还受内分泌因素、营养、免疫病、肿瘤、感染，以及皮肤衰老、过敏等多种因素的影响。比如脑垂体分泌的促肾上腺皮质激素（ACTH）与促黑素（MSH）的结构类似，如果ACTH异常分泌，除了肥胖、多毛等ACTH引起的代谢问题，皮肤黑素细胞也会受其影响而大量产生黑素，导致皮肤变黑。因此，如果短期出现异常的皮肤颜色加深，而又没有日晒、皮肤炎症及用药等因素影响时，应当及时就医以明确原因。


紫外线——皮肤变黑和色斑的罪魁

紫外线是日光中的不可见部分之一。紫外线照射皮肤时可以刺激皮肤色素的产生，这是皮肤为了避免受到更多紫外线伤害的防御机制，因为黑素可以吸收和阻挡部分紫外线。除了使皮肤晒黑之外，紫外线会加重黄褐斑、雀斑等色素性皮肤病，还可导致日光性黑子（晒斑）的产生。长波紫外线（UVA）可直达真皮，使胶原纤维和弹性纤维断裂，导致皱纹形成和皮肤老化。紫外线能直接损伤细胞遗传物质（DNA），也可以通过激活氧自由基造成细胞膜和DNA的损伤，这种损伤带来的后续效应便是细胞氧化应激水平增加、炎症状态、肿瘤、细胞衰老和凋亡。因此紫外线同时也是很多皮肤肿瘤的诱发因素。

想要不做防晒又让皮肤年轻白皙是不可能的，任何未加防护的日晒都会伤害皮肤。有人认为只有皮肤晒伤潮红疼痛时日光才对皮肤造成伤害，其实只要在白天走出户外，即使是在阴天，穿过云层的长波紫外线都能对皮肤造成负面影响。日光对皮肤的损伤具有累加效应，短时间内可能看不出变化，但如果您年龄在40岁以上，可以对比暴露部位皮肤（如面部、前臂外侧）和较少暴露于日光的皮肤（臀部、大腿内侧），看看哪个部位的肤色更均匀，更紧实有弹性？


哪些药物或者食物会让皮肤变黑？

许多药物和化学成分可以引起皮肤色素沉着过度或脱色，其机制多种多样，包括诱导黑素产生、药物复合物或重金属在皮肤内沉积等。这种色素沉着常在中断用药后逐渐消退，但消退过程往往需要数月乃至数年。导致皮肤色素沉着的口服或注射药物中最常见的包括米诺环素（一种抗生素）、羟氯喹、某些化疗药和齐多夫定（一种抗病毒药）等。化学元素中铁、铅、汞、银、砷、铋、金等重金属可在皮肤中沉着引起肤色加深。激素类药物中，某些口服避孕药可以起黄褐斑和乳头色素沉积。此外，一些精神类药物、心血管用药中也有导致色素沉着的成分。外用药物中，补骨脂素类、糖皮质激素等可引起用药局部的肤色加深，美白药物氢醌使用不当时可刺激局部皮肤产生炎症后色素沉着，或直接导致外源性褐黄病。日光照射往往可以加重药物相关的色素沉着。

一些食物中因含有呋喃香豆素而具有所谓的“光敏性”，呋喃香豆素在受到日光照射后可被激活为一种毒性物质，对细胞造成损伤。因此在大量食用富含这种物质的食物后再接受日光照射，会出现皮肤红肿、炎症，而后留下色素沉着。富含呋喃香豆素的蔬菜水果包括香菜、欧芹、柠檬、酸橙、佛手柑，以及无花果等。如果记不住的话，以后碰到气味芳香的食物多留个心眼，吃完以后尽量避免日光照射。


皮肤外伤或者痘痘痊愈后为什么留下黑印？

炎症后色素沉着（PIH）是在皮肤外伤或者炎症后出现的一种色素沉着过度，局限于炎症发生的部位，在红斑消退后出现，在深肤色人群中尤其常见。炎症引起表皮细胞损伤，释放出黑素，进入真皮的黑素被吞噬细胞吞噬后长期滞留在真皮内，因而导致皮肤局部颜色加深。持续的炎症或日光照射可加重色素沉着的程度。褐色到黑色的皮损说明色素位于表皮，可以在1-2月内消退，灰褐色到蓝灰色的皮损说明色素位于真皮，可持续数月甚至数年。除了烧伤、擦伤等皮肤损伤原因之外，寻常痤疮、虫咬或过敏相关的皮炎、银屑病、病毒疹等伴有炎症的皮肤病都是炎症后色素沉着的较常见原因。


怎样去除面部色斑？

国外资料显示，皮肤科就诊患者中21%是以去除面部色斑为主要诉求的。色斑有的和黑素细胞增殖有关，有的和黑素合成增多有关，治疗必须在明确诊断之后才能有针对性进行，因此如果皮肤出现色斑，应当及时求助皮肤科医生，切勿听信偏方、秘方，或自己在家土法祛斑。一些主要因为单纯局部黑素增多所致的色斑可以在医生指导下使用外用药物治疗。随着技术进步，基于“选择性光热作用原理”开发的调Q激光能够特异性作用于黑素小体，在去除色斑的同时避免对周围皮肤的损伤，对于色斑的治疗是一个飞跃。一些物理性磨削或化学性剥脱治疗也可以有效改善肤色。


哪些美白方法既安全又有效？

既安全又有效的美白方法大概只有防晒了。即使皮肤色斑去除或肤色改善之后，如果不注意防晒，色斑还会卷土重来。防晒不仅仅是涂抹防晒霜而已，因为目前市场上最好的防晒霜也不能阻挡100%的紫外线。通常认为，防晒效果的排序是室内活动>衣物遮盖>防晒霜，因此严格的防晒应当做到上午10点到下午4点间尽量避免出门，在白天出门时应当尽量使用深色遮阳伞或宽檐帽遮挡直射的阳光，再借助墨镜及口罩、衣物的遮挡来阻隔地面反射的大量紫外线。防晒霜作为最后一道防线，最好做到每天使用。防晒系数（SPF值）是防晒产品对中波紫外线（UVB）防护强度的指标，但导致皮肤色斑和衰老的元凶却是长波紫外线（UVA），这一波段的紫外线防护水平通过PA+到PA+++来进行标识。由于大多数人不能足量使用防晒霜，因此应当尽量选择高防晒水平，能同时阻隔UVA和UVB的宽谱防晒产品。为了防止紫外线导致的氧化损伤，可选用同时含有抗氧化剂（如维生素E衍生物）的防晒产品。

外用的淡化色斑的药物中，目前公认的皮肤脱色金标准仍然是氢醌，又称对苯二酚，临床上被用于治疗黄褐斑、炎症后色素沉着等多种色素性皮肤病。氢醌可以阻止酪氨酸酶将酪氨酸转变为黑素前体，还可以选择性破坏黑素小体和黑素细胞，因此可以“漂白”皮肤。但氢醌具有一定的毒性和刺激性，使用不当可导致接触性皮炎、炎症后色素沉着以及外源性褐黄病，因此我国化妆品内是禁止添加的。维A酸及其类似物可以加速表皮转化，使每个角质形成细胞得到的黑素减少，从而淡化色斑。但相比氢醌，不仅效果一般，也需要更多的治疗时间（至少6个月起效）。虽然维A酸对于色斑的改善表现平平，但在另一方面，它能促进真皮胶原合成，改善皮肤纹理和弹性，是抗衰老成分中效果最为确切的。不论对于黄褐斑还是炎症后色素沉着，联合使用氢醌、维A酸、弱效糖皮质激素的外用治疗比单一疗法表现出更好的疗效。

其他美白类外用成分中比较公认的包括果酸类、壬二酸、曲酸、熊果苷，以及大豆和甘草等植物的提取物等。口服药物中，具有美白效果且相对安全的有维生素C、维生素E、氨甲环酸、烟酰胺等。谷胱甘肽可以结合氧自由基从而发挥抗氧化效果，因此被认为可以对抗人体内与氧自由基相关的细胞损伤和色素沉着。由于肽类结构口服吸收不佳，所以是唯一一种需经静脉给药发挥效果的成分，是“美白针”的主要成分之一。另外一些新兴的美白成分，它们大多是以抗炎和抗氧化为目标开发的。理论上任何抗氧化物都能阻断氧自由基对皮肤的损伤，从而具有美白效果。但这些成分的效果是否确切尚有待时间的验证。

除了药物之外，强脉冲光（IPL）、调Q激光、点阵（像素）激光、磨削治疗等物理治疗和果酸剥脱等方法都能对肤色和色斑有不同程度的改善。上述美容治疗建议在医生的指导下进行。


色素性皮肤的5个护理要点防晒为重

永远记住“防范胜于救灾”的道理，防晒花1元钱产生的效果，要超过花10元钱挽救晒后色斑的效果。

慎重选择化妆品

不用说在乱象丛生的中国化妆品市场了，就是在监管极为严格的日本，不久前也发生了美白产品中所含杜鹃醇引起皮肤白斑的不良事件。非法添加有汞或砷的“神器”在使皮肤变白的同时增加了人体慢性中毒的风险；荧光增白剂通过肉眼不可见的紫外线激发荧光物质产生蓝色光来中和皮肤的黄色，从而使皮肤看起来很白，但其长期安全性至今未有定论。因此，要尽量选择正规厂商生产的美白产品。

正确对待美白药物

美白药物琳琅满目，但是药三分毒，即使是维生素C，过量服用也有泌尿系结石、干扰其他营养物质代谢等风险。因此，能外用就不口服，能口服就不注射。对美白针这类治疗，尽量还是慎重选择。

不要忘记抗氧化

氧自由基可使体内氧化应激压力升高，使机体倾向炎症状态，从而导致皮肤色斑和衰老。理论上，选用含有抗氧化成分的护肤品，以及适量摄入维生素C、维生素E，以及含有巯基、多酚类物质如α-硫辛酸、辅酶Q、花青素、茶多酚等具有抗氧化活性的物质可以降低皮肤内氧自由基水平，或许对肤色改善有所帮助。

调整情绪和生活方式

黄褐斑等一些色素性皮肤病与情绪和内分泌变化有关。因此，保持心情愉快、生活规律、睡眠充足对色斑的改善有一定帮助。


以上。
编辑于 2015-04-06
sharon 包
sharon 包

       -豁出去了，我看了大众的答案都觉得你们！不够严重！不够严重！虽然有痘痘看着也木有很恶心嘛～好了，本宫要开始装逼了～吃饭的请撂下筷子

这才叫赤果果的从烂脸回来吧～不信的话本宫再来一张

从美国飞回香港坐了16小时飞机，还吃了泡面喝了汽水眼屎还挂在眼角的照片 哦呵呵呵呵（胖这回事请不要指出来了，我会努力的～我们说的是皮肤）

我觉得呢皮肤变好，最大的变化应该是皮肤状态变的稳定，耐受性好，而不是，每天吃了点辣辣或者睡了晚一点，脸上总有一块觉得不对劲，结果第二天起来一片痘痘。本宫是油皮，虽然是93年的老阿姨，但好歹刚过青春期，长点痘痘很正常的，不要大惊小怪。

容本宫先吃个饭，稍后再更 本宫是靖王妃 

------------------我是分割线-------------------

本宫回来啦，接下来呢我就要说说具体的护肤了，也会推荐一些产品，不要拍板砖不要拍，我只是想要分享。

露珠油皮，毛孔较大，地处东南沿海地带，在武汉上学，肤白～

首先，如果你处于烂脸期，请注意，不要擦防晒，不要，怎么防晒，打伞，会不会，大下午的少出去会不会，你要说非要在大太阳底下做什么事情，那我只能说，祝你烂到底 

然后，针对烂皮来说，不要用卸妆水，表活成分➕化妆棉擦拭，还是有刺激的；卸妆油 ，你想死吗，比较好的是卸妆乳或者卸妆膏，即使不化妆，一周也要卸妆2次这样，有些灰尘跟油脂再加废气的结合，洗面奶还真的洗不大掉。

洗面奶，不要用什么纯中药，祛痘，控油、还有什么美白，好好用一只温和的洗的干净的洁面就好。我不是唯氨基酸，透明质酸党，皂基用用也无妨。但是我绝不希望你们去用什么手工精油皂，不是正规品牌的东西吹上天我都不能相信。洗脸之前，一定要洗手，一定，然后洗脸要用温水，敏感肌还有冬天我都不建议什么最后用冷水冲一下，太刺激了，温水洗完，不要用毛巾，毛巾可脏了，用干净的纸巾或者化妆棉，将水压干，不要擦干，那是你的脸不是地面。我自己用过的洗面奶里面，比较喜欢的有：
1.霓净思的氨基酸洗面泡

温和而干净，挤出来是一种很清新的气味，泡泡比较丰富，也很扎实，我在烂脸的时候一直用，洗完不会有擦盘子感，摸起来会比较软，不油腻，很干净。
2.雅诗兰黛白金级高保湿洗面奶

这只洗感真的很好，香味不是俗气脂粉香，很舒适的香味，泡沫很容易起来，泡泡不算细腻但是很丰富，洗完之后脸真的是很惊艳！超级嫩！软嫩软嫩的感觉！！露珠语文不大好，但真的是力推
3.悦诗风吟青苹果洗面奶和资生堂洗颜专科
这俩只露珠在夏天很喜欢，洗完很干爽，但绝对不是干，就是干爽，然后气味也很清新，特别是青苹果，虽然也知道是香精，但是露珠就是爱闻啊


露珠真的有拖延症啊，又是在实习，更新龟速……大家见谅

Ok，露珠又回来了，在地铁上码字。每日这样的清洁是不够的，还需要定期做清洁面膜，清洁面膜露珠prefer泥状的，而且建议大家在上清洁面膜之前，用热毛巾包住脸5分钟左右，打开毛孔、然后再上清洁面膜，泥状涂厚一点,不要吝啬啦，反正清洁面膜都很大只，一礼拜就一次最多两次。泥状清洁面膜得等干透才洗掉，建议辅助海绵清洗效果更好。露珠个人觉得清洁面膜想一次就黑头粉刺乱蹦是不大可能的，但是清洁面膜之后确实有毛孔透亮的感觉，我觉着这样的清洁面膜就不错了。清洁面膜之后，强烈建议配合仔细消毒对暗疮针！用圆的那一头，对于露出头顶黑头白头进行清理。不要怕留疤，新陈代谢快，总会没有的，而且也没那么容易留疤～这里露珠分享一下比较喜欢对清洁面膜

清洁面膜得避开眼周皮肤，进来厚涂，至少盖住皮肤原色，感觉有一点紧绷是正常的，可以用喷雾缓解一下。清洁面膜10-15分钟为宜。

露珠比较心水的是origins泥娃娃，找代购在美国买会便宜很多，而且很经用。
清洁面膜之后要收缩和保湿，露珠觉得毛孔这件事情要内服外养一起进行。内服上，露珠建议可以吃些维生素和胶原蛋白，如果没有闲钱，要多吃果蔬，少用填平毛孔的妆前乳！美一时毁一世。毛孔粗大多见于油性皮肤和熟龄肌，成因是不同的。油性肌肤是由于出油丰富，处理不好就毛孔堵塞了，所以是撑大的。熟龄肌是由于弹性不如年轻时候紧致，难以对抗地心引力，被拉大的。所以毛孔这件事，露珠觉得心态要好。天生优劣势我们就不让他继续恶化，熟龄肌了就让它延缓衰老。跑题了……拉回来，所以清洁面膜之后要使用收敛效果的水，露珠觉得凉的就好，除非大夏天不要放冰箱里，如果放冰箱里了最好提前拿出来一会儿，可以用化妆棉湿敷，或者就直接上凉的补水面膜，这里prefer片装补水面膜。

收敛毛孔的水我觉得要坚持用，露珠很喜欢科颜氏金盏花水，同样的建议去美国代购买，便宜一些。每天用每天用，调节水油平衡不错，而且觉得脸会软软的，露珠总觉得自己烂脸时期脸是硬的，也许因为皮肤下面都是炎症？ 
露珠在美国免税店撸了个大瓶，觉得幸福哭 

片状面膜露珠觉得，正规牌子，好吸收，不粘腻就可以了，不用追求什么大牌子。露珠自己就很喜欢森田，魔法森林，还有可莱丝的面膜，夏天酷爱用悦诗风吟的香榧，凉凉的挺舒服的～烂脸期间面膜的用法露珠会在以后的痘痘分类治理里面讲到。

痘痘分类治理

痘痘常见的有粉刺，脓包，闭口，还有一大块一大块的，露珠忘记叫啥了。
总体方针来说，不要用手摸脸，手上细菌多到哭晓不晓得，摸脸皮肤一点不会好；别用头发遮脸，已经烂脸了，头发遮着更阴森；勤换枕巾，被套，睡觉朝天睡，不然蒙一晚上捂出痘痘真是祝你开心，这三点做到好吗！露珠那时候碰脸前先洗手，或者拿着湿巾碰……露珠就是这样的小砸表 然后，什么百多邦，什么红霉素，求你了别上脸，别说什么红霉素能用在眼睛上，他妈眼睛上长痘痘吗亲！

闭口：
露珠最烦闭口，最烦，躺尸一样在脸上，顺其自然800年没动静，药膏涂上也是憋了再生、比如狮王和白兔……平了，然后又长。露珠觉得闭口是有毛孔堵塞引起，而且油脂代谢不正常，炎症在一层厚厚的角质下面，角质正常了，闭口出来的通道顺畅了，自然就好了。所以对于闭口，露珠建议使用去角质，补水，局部使用酸类产品，适当使用暗疮针的方式 ，不建议使用精油类产品或者药膏厚敷，真是堵堵堵堵堵堵。这里也说了，是局部，没让你全脸刷酸，点在闭口上会不会。补水一定要在去角质以后，但不能不补水，过度补水会加剧毛孔堵塞，但是不补水，肌肤耐受性真的差好多。只有在滋润的土地上施肥才有效，闹旱灾的时候当然是求雨而不是史丹利化合肥啊 ，所以要去角质之后用补水提高耐受力。然后局部点酸，露珠没用过什么酸，但这里力荐一款美国药妆，kate somerville祛痘水。美国丝芙兰24刀一瓶，一天只能用一次，建议晚上使用，盖子拧紧。

绝对闭口救星。好像爱丽小屋出了个类似概念的粉末，

不知道效果如何。吃饭去了～

哎哟，露珠回来了啦……贪吃所以那么肉啊 

粉刺不是很想说，清洁补水保湿做好，慢慢就没了啦～

脓包

千万不要在成熟之前瞎挤！！不要在脓包严重的时候瞎做面膜，信不信成连成片的那种或者是闭口……正常护肤就好，但是成熟之后露珠建议挤干净，消毒好，涂上药膏或者茶树精油消炎～～

另外对于长痘痘的部位，修容区和下颚骨周围，注意衣物清洁，不要用手托脸～不要瞎挤；
女生如果唇周容易生痘痘，很可能是妇科疾病，可以喝点黑糖玫瑰什么的，少吃生冷，注意休息；额头长痘痘一般是青春期，女生们把刘海掀上去，可以涂抹药膏～这里推荐一个小药膏，虽然是微商牌子，但露珠觉得镇定消炎真的很好，用完3个了

啊……露珠要去洗澡了……还欠你们精华，乳液和面霜是不是，还有眼霜……你们慢慢看哦～露珠会回来的。欢迎评论区提问～本宫是话唠

这里提醒一下，防晒霜涂是好习惯，露珠只是说烂脸很严重的时期减少刺激而已啦～即使是雅漾小金瓶也是有点油油的感觉
------------------------露珠真的好懒啊------------分割线卖萌啊--------------------------------------------------------------

继续啦，我先来回答同学们的问题，关于痘印，露珠还是推荐内服外养。有痘印的地方，建议涂抹茶树精油，白天不喝维C含量高的柠檬水，做好防晒，晚上针对性点涂美白精华。。。。穷啊，全脸涂钱包就废了，然后多吃燕麦等，可以提高新陈代谢率的，最后呢，不长痘痘或者少长痘痘才是痘印的第一步，白糖去痘印这种，建议还是不要用了。

关于男士护肤，首先，露珠没有男票，露珠的表弟是从来不用护肤品却皮肤好的令人羡慕的人，爹地是从不用的人，没有什么男闺蜜一说，关系比较好的男生朋友。。。。都是不用的糙汉。。。。。哦no~，所以露珠问了一个韩国留学生，还有一个美国玩的时候认识的小哥，给大家一点建议。男生护肤，重在清洁和保湿，因为一般角质层较厚，更容易有痘痘啊，毛孔堵塞的问题，在清洁面膜上露珠已经推荐了。但是日常护肤，就是洗面奶，爽肤水，乳液等，不要追求控油，磨砂，只选择保湿的，不黏腻的。这里听说科颜氏男士护肤口碑不错，爱茉莉有新出一套男士护肤，韩国留学生皮肤确实好，然后有钱的可以撸撸资生堂男士和碧欧泉。悦诗风吟也新出男士护肤，值得尝试。至于欧莱雅男士。。。。。露珠对欧莱雅护肤一生黑，一脸痘痘欧莱雅功不可没，虽然好像兰蔻啥的也是欧莱雅旗下的，不过不可同日而语。

乳液和面霜选一个用就可以，干皮可以叠加。露珠最近喜欢minon氨基酸保湿乳液，面霜对悦诗风吟的绿茶面霜和寒兰面霜都比较满意。露珠认为面霜和乳液一定要按进皮肤去，所以是要在掌心或者指尖温热后上脸的。

所有护肤步骤之间要留15s给上一步的去吸收，全糊在脸上前功尽弃。酒精不是恶魔，但是痘痘严重的时候尽量用无酒精的东西。所以倩碧三部曲，露珠持理性态度。

最后给大家推荐一下防晒霜，露珠比较喜欢资生堂的蓝瓶，ipsa蓝胖子，冬天可能就会用新碧或者碧柔。近江小熊不是很建议上脸。防晒最好用卸妆产品卸掉。

还有关于眼霜，20岁加都可以撸，露珠眼睛比较大的那种，很容易有眼袋，又爱笑，细纹也是大敌。露珠很喜欢科颜氏牛油果眼霜，接骨木眼胶很适合夏天用。

露珠从12岁开始长痘痘，整个青春期都在抗争，20岁的时候爆发了很严重的一次，那时候露珠都是出门打伞，低头走路，看见熟人都远远绕开的，所以很能理解大家的焦急的心态。但是露珠真的建议大家，护肤要给自己至少3个月来看效果，循序渐进，护肤品有适应期，至少一个月以后才能调换新的护肤品。露珠一直强调内服外养，所以会建议大家喝豆浆代替牛奶，少喝咖啡汽水，可以喝花茶，女生很多是偏寒偏湿体质，可以喝点黑糖，多跑跑跳跳。

关于化妆这件事情，其实楼主在没有那么多大痘痘以后都会化妆，因为在外资银行实习，形象比较重要，黄黄的脸，气色不好的唇，心情也会不好，大家用好底妆产品，做好卸妆和清洁，化妆并不会使皮肤变差的。淡妆是对别人的礼貌。

有什么问题都可以私信露珠，露珠会尽快回复的。第一次写那么长，是因为自己也为这张皮哭过恨过，可是，既然长在了你脸上，你不爱它，还会有谁来爱呢。露珠现在会被人夸皮肤好，一般都笑称是肉多所以撑得饱满，O(∩_∩)O。

希望大家喜欢露珠的分享~~~如果问题很统一的话还会再更的。
-------------露珠是玻璃心-------------------------------
有人说我是卖护肤品的 ，呵呵嗒，我只是推荐一下，我连个链接都没放，我有这么多点赞我傻吗！大家各取所需，我在评论里面从来都建议大家觉得舒服的没有必要换，露珠好受伤啊啊啊啊！

痘坑很严重的事需要时间和医美的，但是不那么容易长痘痘，提高肌肤耐受性是我们可以做到的。也希望大家一旦下定决心好好护肤，就稍微忌一忌口啦^_^

露珠求安慰的！对！ 

你推荐你的神器我也推荐我的，互不影响。喷雾 、奥尔滨和南非芦荟胶我都用过，在我脸上没有很惊艳的效果，特别是大喷和芦荟胶我觉得没什么用。我并没有完全不留痘印，不明显而已。我写的普通吗，我不知道，但开头的照片真的是我，结尾处的心酸也是我。我只是share一下我的经验，为什么要否定我。

露珠用了很多方法，对的错的都有，所以也是斟酌以后写出的这样一篇。至于微商，在互联网金融时代，它不过是一类新型群体，新的销售方式，最终还是要归结货物本身上来。

露珠是文科生，学的是金融，化学生物不好，所以没办法写出很专业的知识。露珠护肤期间一之坚持喝胶原蛋白和葡萄籽，一直坚持吃燕麦和维生素，一直坚持白天不喝柠檬水，一直坚持不摸脸朝天睡。也许有些有科学道理，有些真的没有，但是，我只是真心想分享我做过的那些事情。

本来已经更完了，但谢谢大家的厚爱，我依然会回复问题的。最近实习和申请很忙，回复不及时，也希望大家原谅。

谢谢大家支持，很多爬宇问我底妆用的啥～那么露珠可以给大家八一八～洗完澡更哈～

底妆其实分两步，妆前和粉底，那么其实上底妆的选择也是要根据肤质来定的。

妆前主要有几大类：保湿妆前，主要针对干皮，可以保持肌肤水润度，减少起干皮；调色妆前，主要是指有颜色的妆前乳，比较大众的是苍白肤色可以用粉色，暗黄用紫色，泛红用绿色，还有类似蓝色，黄色妆前等等（露珠懒癌又来了，让我缓一缓）控油妆前：主要是给油皮使用，一般也会有填平毛孔的功效； 提亮妆前：给肌肤增加光泽感

露珠其实不大用专业的妆前，但是一定会每天抹防晒，夏天spf 50滴，冬天spf30滴，补妆会带有防晒指数的气垫BB，毕竟化了妆再补防晒不大方便咯。
妆前乳露珠曾经很喜欢用美宝莲的一款粉宝贝

能有效提亮肤色，看上去有白皙粉嫩的气色，而且保湿效果不错，上粉底不容易起皮。
露珠还是有油皮普遍都有的毛孔粗大问题，虽然不推荐用毛孔修饰的东东，但是偶尔为了无暇底妆，而且这款控油不错，所以还是备了一只

其他露珠看过口碑比较好的有smashbox的各色妆前乳，sofina的控油和保湿的妆前乳等。提亮乳我更倾向于打高光滴方式  

接下来就要说到最重要的底妆了，露珠并没有很直观觉得BB霜不如粉底液或者BB更闷痘之类滴，因为露珠两个都用。底妆的宗旨确实是在经济许可的范围内尽量买贵的，但是呢，平价里面也是有不错的好物的  露珠这里推荐的都是自己用过的，感同身受的告诉大家，没有用过的再好的口碑呢，也不敢推荐。自己从烂皮过来，真的不希望任何一个姑娘小伙们用出一点点问题。

气垫BB上来说，露珠推荐两个品牌，Holika和Clio  露珠不是很喜欢特别白的妆容，所以用的都是自然色号。这两款BB遮瑕都不错，而且不那么容易脱妆，油了之后还是比较自然美丽的。Holika当时大概人民币150买入没有替换装，CLIO230买入，送一个替换还有定妆喷雾。妆效上来看呢，Holika还是比较有光泽的，特别是苹果肌这里在光下光泽特别美好，在露珠仍有比较严重的痘印和零星痘痘的时候，因为这款BB好多人夸我皮肤好 。CLIO的呢是雾面效果，比较哑光，但是夏天特别合适，在office里面雾面看上去更为合适～

同学从韩国回来又给我顺了一个雪花秀，使用之后告诉大家结果噜～

然后这里呢，露珠会觉得气垫粉扑上BB是很好的，上粉底的时候呢，露珠建议瑕疵皮用葫芦海绵上妆，遮瑕度更高，妆也很贴；在刷子上建议用平口或者斜口刷，适用于不那么多瑕疵的皮肤和光泽感好的妆容～露珠有个小刷子有推荐，这里不放链接，因为真滴便宜好用呢～

粉底液上，露珠用过蜜丝佛陀双效修护粉底液，Aupress 粉底液，雅诗兰黛白金系列粉膏，兰蔻奇迹薄纱粉底液，露珠比较幸运的没怎么踩雷～遮瑕这里一起说了吧，露珠觉得遮瑕用快干掉的粉底液叠加就挺强的，所以遮瑕只用过美宝莲橡皮擦和蜜丝佛陀的遮瑕膏～最近新入手The Saem遮瑕液，意外的便宜好用哦～～嘻嘻～～图片明天再放啦～

另外，露珠是个爱剁手滴，有些朋友私信我说什么什么哪里有卖什么滴，其实露珠说！有需要可以找露珠啊！给你们出点分装也不错……最近穷到只能吃两块钱滴包子当午饭哩偶呵呵呵～希望大家希望。

又：最近申请工作压力很大，又有长痘痘了= =，不过呢，不是很怕了呢～露珠跟你们一起努力～

露珠又回来了，这次是分享闭口的好东西，露珠亲自刷了杏仁酸，水杨酸，最后最惊艳的是药店卖价不到50的维A酸，爆出好几颗老闭口 酸爽～但是可以先用杏仁酸建立耐受，所以我用维A酸没有痛或者肿，只是稍微有一点点起小干皮。但是维A酸不可以全脸刷 不然好皮也会长痘痘的
编辑于 2016-01-13
伪少女nina姐姐
伪少女nina姐姐

想要让皮肤变得好，就要知道该如何搭配护肤品使用哦~

关于护肤品大家都知道单用化妆水，或者单用乳液的效果没有一起用化妆水和乳液的效果好，这就是护肤的1+1>2了，所以就让Nina姐姐来给大家介绍这些护肤界的黄金搭档吧~！







很多人使用护肤品喜欢一套一套的用，循规蹈矩自然不会出错。但是有时候根据自己的肌肤诉求搭配说不定会有惊喜呢！

想了解Nina姐姐更多的护肤知识以及自己的皮肤类型可以关注 公 众 号：ACTION28 更有护肤优选计划帮你解决皮肤问题哦。
发布于 2017-06-13
荼靡
荼靡
W:371117765
我很少回答问题～近期关注了这类型的话题，开始回答！知乎有时回复的不及时，望见谅～
好多知友问我他们皮肤状况应该怎么办，没看到，我没办法解答，也可加我微信xinxin7h
若有空，都会及时回复～
好了～我来添加回答～ 不定期更新，因为我实在懒啊！！！
前方预警～高能！！！    
—————
管住嘴～别吃你那些明知道会长痘，还抱着侥幸心理说就吃一次不会长痘，谁给你的自信！
管住手，别手贱，别瞎扣，你不懂得会发炎，会感染，会有痘印痘坑么～长太多就去正规的美容院针清～
迈开腿～滚去运动，多出汗，你会发现皮肤好了～身材好了～生活也轻松了！
干净很重要好么！！勤洗床单被罩，没事就把衣物被子拿出去晒太阳好么！！它们需要杀杀毒，晒晒太阳！！
多喝水～没事就喝水可以么～能不喝那些个没营养的饮料么～
别没事看见什么祛痘有效果就去尝试～你这是脸啊～不是抹布啊！！！用对产品是关键！
面膜能不用就别用了～我们这种大油田，还往里灌什么养分，吸收不了，只能往外排～然后初期你发现有效，过后又长痘痘，死循环 ！！
好了～不爆照你们当我说假的是不是～
编辑于 2016-05-07
陈兮兮儿
陈兮兮儿
微信公众号：陈兮兮儿。关注我提高生活质量哦!

第一个爆照的回答，有点瑟瑟发抖。(ಥ_ಥ)

我本不长痘，自己在大学期间花样作死给作成了一个爆痘狂魔，后来没有看医生（错误示范）自己把皮肤养好了。

刷知乎的有很多高中生大学生，如果你们看到了我的回答，又恰好对护肤一知半解正在摸索中，恭喜你遇到了我，那么请你一定要看完我的血泪史。因为你们的皮肤还可以抢救一下。25+的妹纸们也一样适用，因为我也是25岁+了哈哈哈哈。


以前各种长痘真的挺自卑的，现在的皮肤养回来了不少，也经常被身边的朋友夸好（当然我知道再也回不去过去的肤如凝脂了）

按照惯例好像要上图。不过我不太习惯在答案里爆照hhh，可是不发照片无法说明皮肤以前的糟糕状态哎。

▲为了避免答案的封面图太丑的表情包▲

▼大学期间因为极差的饮食和作息习惯，导致我下巴和嘴巴周围各种爆痘，完全好不起来非常绝望。爆痘期的照片没有，能找到的照片都是好的差不多的时候拍的，可以明显看出嘴巴周围真的长了很多痘，

▼化妆了的，痘印遮盖住不少，但是依然可以看到（摄影师手抖我也很绝望），顺便说一下，当时大学疯狂熬夜肝，黑眼圈已经很明显了，心塞，人生第一大后悔的事情就是大学一直在熬夜

然后现在：



重点强调：我已经27岁了，27岁这样的肌肤状态，我个人不算非常满意，但是客观来讲在这27岁这个年龄，也算保养得当了。各位小可爱不要拿我和其他回答爆照的小年轻比较，谢谢你们，比心。哈哈哈。




▼无妆，只有口红，手机前置拍的，这张照片比上一张年龄差了4岁，emmm。。上了年纪了。。 ╮(╯_╰)╭不过我这个年纪（27岁）皮肤还能保持这样，我也心满意足了。护肤保养的奥义不是要妙手回春，而是永远看起来都比同龄人显得状态更好。还年轻的小可爱也许体会不到这句话，待你们渐渐老去，就知道年轻时的护肤习惯会多影响以后的容颜了。

要不是大学熬夜作死，应该会比现在更好。

▼上了妆+美颜相机那就是这样：


▼无妆，只有口红，忽略我刚下班热到油腻的刘海：


知乎很多漂亮小姐姐，所以大家轻喷我的颜，好人一生平安。

爆完照赶紧跑，真刺激

10秒快速看完答案核心内容：

1.以前的弯路和经验总结，

2.现在的护肤经验和心得分享，

3.产品推荐

    那时候的我（请对号入座）：


1.经常凌晨四五点睡觉；

2.三餐不按时，没课的周末就吃一顿，接下来就是永无止境的熬夜，白天用来睡觉；

3.吃方面也是无辣不欢，因为怕胖所以不太吃零食和烧烤；

4.经常自己炖汤和炖雪耳百合羹什么的；

5.谢谢评论区的小可爱提醒，我当时还有有便秘困扰，已经好多年没这个困扰了所以居然完全给忘记了hhhh，

然而事实证明，良好的作息比良好的饮食习惯更重要。尽管那段时间我吃的很养生，各种水果五谷杂粮吃的不少，然而还是改变不了我爆痘的命运。

anyway,也许因为吃的比较养生，所以让痘痘没有恶化，基本就是长出来一到两星期又会自己淡化，有些严重点的痘痘留下了痘印和少量痘坑，现在几年过去了，除了下巴附近还有不算清晰可见的痘印外，基本没啥问题了。

结论：如果你现在是10几岁的高中生，或者是20几岁的大学生，调整好自己的作息，好好睡觉，年轻的肌肤只要不熬夜，都不需要太好的护肤品保养。如果你超过25岁，emmm。。。更加别熬夜，因为你熬夜不仅拼不过年轻人，她们第二天起来依旧血气方刚，你只会无精打采、工作效率低、看起来比同龄人老、还要花更多的钱做保养，实在得不偿失。


    下面是错误示范环节（也欢迎对号入座）：


一、没有及时就医

长痘那时候蠢到没有去看皮肤科医生，心里就单纯觉得是青春痘，所以没有就医的意识，而且我的痘痘属于不折腾就会自己消退那种人于是我一直放养我的痘痘。现在想想真的是人生十大后悔的事之一了。蠢哭。不过靠自己也能养好也是因为不算十分严重，只是好的过程太慢了，调养了很久身体才调回来。

结论：不管看文章的你现在几岁，16或者20或者30，轻微或者重度长痘，都请去看医生，不要指望护肤品能够歼灭你脸上的痘痘大军，基本等于做梦。


二、过度清洁肌肤

年轻嘛，16岁到22岁之间皮肤油脂分泌旺盛，所以那时候我用一些清洁力很强的洗面奶，洗完脸就是有种搓盘子的感觉，以为那样能洗掉油脂皮肤不再油腻。

结论：过度清洁肌肤会破坏皮肤表面的屏障，造成内干外油的情况，皮肤反而越来越油；年轻人油脂分泌旺盛，不用过于担心；使用氨基酸温和的洗面奶，以洗完面部不紧绷为选购原则。


三、不防晒

emmm....我大学毕业之前都不重视防晒的，简直花样作死，难怪我毕业一两年后脸上居然有一点儿小雀斑。尤其长痘痘不防晒，简直就是痘印的福音，一辈子都要赖着你不跑了。

结论：女孩子越早做防晒越好，防止皮肤老化、防止出现色斑等；儿童也有专用防晒霜了，你敢说防晒真的不重要吗？如果不防晒，那么泡在神仙水里也拯救不了大家的肌肤。

防晒步骤：物理防晒-防晒霜。防晒霜是最弱的防晒了，在户外活动别以为涂了防晒霜就了不起啦皮肤不用晒黑啦！navie！能打伞的千万打伞，能戴墨镜千万戴墨镜，能戴帽子千万戴帽子！然后才轮到防晒霜出场。


顺便，当我们谈防晒，我们在谈什么？

众所周知防晒不是为了防住阳光，而是防住紫外线，紫外线分3种：

1.UVA：可以直达肌肤的真皮层，破坏弹性纤维和胶原蛋白纤维，将我们的皮肤晒黑。

2.UVB：UVB紫外线对人体具有红斑作用，能促进体内矿物质代谢和维生素D的形成，但长期或过量照射会令皮肤晒黑，并引起红肿脱皮。

3.UVC：又称为短波灭菌紫外线。短波紫外线对人体的伤害很大，短时间照射即可灼伤皮肤，长期或高强度照射还会造成皮肤癌。

结论：一年四季都要防晒，紫外线无处不在，别心疼防晒霜的钱，在户外的防晒奥义是每隔2小时左右补涂一次。by the way,在室内如果你长期呆在靠近窗户的地方，也要防晒，系数可以低一点，质地轻薄一点，让肌肤没那么大负担。

分享一下著名的光老化科普图，emmmmmmmmm你还不赶紧防晒吗？


四、不懂挑选适合自己的护肤品

啊那时候其实真的不太懂得护肤，经常看一些台湾的综艺节目比如我是大美人啊，然后还什么牛尔老师啊，那时候又是御泥坊什么的大火的时候，太容易跟风别人说好用就买了，买了又本着不想浪费所以不管好不好用都要用完，那些年踩过的雷又可以写一篇回答了，泪目。

结论：根据自己的肌肤状况选择适合的护肤品，自己学习一些基本的护肤常识，学会看护肤品的成分（这个我现在也依然在学习中），比如敏感肌不适合刷酸，成分中有矿物油的产品会致痘，敏感肌肤+干皮，对皂基、碱性配方或含果酸高浓度产品都要避免……blablabla~


    ▼下面是护肤经验分享环节，说说这样放养痘痘不去看医生的是怎么把皮肤养好的，不作为指南，仅作为参考（快记小笔记）： 
    一、早睡，一般我11点睡觉，最晚12点就要睡觉了。初中高中生10.30乖乖睡觉去

这个一定是排第一位。有一段时间我沉迷守望先锋，周末可以打到凌晨三四点可以想象吗？后果就是眼袋浮肿，黑眼圈加重，看起来无精打采，如果你长期熬夜，是可以从你的脸上看出来的。那时候我处于换工作期，闲了大概一个多月吧，熬夜作死把自己的皮肤作坏了，每天起来照镜子，我快吓死我自己了。现在我的眼袋都没有完全消退，悔不当初。现在就算是林更新叫我开黑通宵吃鸡，我也要，拒绝！（首先，林更新要认识你....）

且看我的守望先锋游戏时间，玩了一年半左右，累计752小时......


前排表白我家林狗：


我大学时候碰到初中同学，她的肌肤看起来真的吹弹可破，没有任何瑕疵，真的！！我问她怎么保养的，她说她们学校强制熄灯，每晚11点就熄灯了，大学也依然早睡。想起我那不熄灯不断网的大学。。我是熬夜通宵打游戏或者看电影各种花样作死。。

已经征得她的同意放上她的照片，emmm。。。。这就是大学保持11点睡觉的美好结局，现在已经是一个孩子的麻麻了



截几段聊天记录，一些话家常的话就去掉了hhh，


    二、认真防晒▼

这个是第二重要。如果你不防晒，真的擦再贵的水乳，紫外线分分让你的肌肤容易老化，晒多了到老了，脸上容易长斑。如果长期爆痘，不要天真的以为晒晒痘痘消消毒，我真的有朋友是这样，我劝都劝不住很绝望。我的具体防晒操作可以看篇回答：陈兮兮：如何让皮肤白得发光？


简单说就是一定一定一定要物理防晒：遮阳伞，墨镜，帽子。不过我上班通勤基本遮阳伞足够，太阳太猛就来一个墨镜，眼睛的防护也很重要。然后才是轮到防晒霜出场。平常去浪啊聚会啊可以偶尔穿的清凉，日常夏季就是大部分时间都是长裙+雪纺防晒衫+遮阳伞+防晒霜。



    三、心情的内调▼

心情好的时候会感觉整个人都在发光，如果保持每天都是好心情，皮肤真的会变好很多。如果经常生气经常哭，女生很容易会内分泌不调的，特别是姨妈期更加别动气，如果你脾气不好、爱生气，其实最终也是害的自己。


    四、没啥事别化妆▼

化妆品确实会对皮肤造成一定的伤害，身边那些不太化妆的同龄妹纸，不得不说她们的皮肤比我费尽心思保养的皮肤更好，羡慕不已。另外她们也是在十一点多就会睡觉，上班后最晚也是12点左右，很少熬夜，更别说通宵。

也已征得同意放上我那位不懂化妆的朋友的照片，by the way，这2位小姐姐包括我都是已经属于晚婚晚育的年龄了，大家自行想象大概几岁吧哈哈哈哈，


中间省去一些闲聊:

(嗯？低调吗，嗯哼，才没有！！哈哈哈哈哈！！明明很多！！！)


    五、认真卸妆，包括隔离乳防晒霜。▼

平常上班我不化妆，一个月下来只有聚会的时候才会化点淡妆。但凡我化妆了就一定会非常认真的卸妆，这一步真的很重要。我的卸妆品：




淡妆，尽量用卸妆乳，直接用手在脸上卸妆，避免卸妆棉摩擦。

浓妆，我会用到卸妆油，这样才会卸的比较干净。

眼妆，用专门的眼唇卸妆液，眼睛最后要用棉签卸妆，直到棉签没有颜色。

唇妆，先用卸妆棉用卸妆水打湿，然后贴在嘴唇上，大概一分钟之后擦掉，再用棉签仔细的把唇纹里的口红卸干净，直到棉签没有颜色。


    六、饮食分享（以下图片都是自己拍摄的hhh）▼
    大家的饮食也要多加留意自己的体质，因为体质差异，不是每种食物都适合每个人，发现不适要马上停下哦！

大家有下厨房的可以去我的下厨房主页围观一波：咕噜咕噜Anna

作为一个超级吃货，上了点年纪（25+）如果还是乱七八糟什么都吃，真的会在我的脸上反应出来，所以都比较注重饮食，油炸高脂肪都放在朋友聚餐吃，一人食的时候都尽量清淡，经常喜欢上传自己美食到下厨房，一人食全在这里了：健身の营养餐


平常我会吃一些杂粮粥，自己搭配的，煮出来意外好吃

▼养颜补血八宝粥▼

具体做法，戳链接►：养颜补血八宝粥


▼雪耳莲子百合羹▼

具体做法，戳链接►：雪耳莲子百合羹

作为广东人，我一个月会喝2-3次汤，广东人不仅吃福建人还喜欢拿福建人来煲汤怕不怕！（开玩笑），我炖汤的秘诀就是高压锅炖足1小时，真的很好喝。

▼莲藕排骨汤▼

具体做法，戳链接►：莲藕排骨汤－滋补


▼夏日冬瓜汤▼

具体做法，戳链接►：夏日冬瓜汤


▼牛奶▼

我超爱喝牛奶的，我没有乳糖不耐受，如果你有那么你就不适合啦！并且我基本只喝纯牛奶，牌子有德运、安佳、广州本土的风行牛奶，因为太经常喝所以很多牌子都喝过，对牛奶选购也有一定心得，最后基本锁定我提到的牌子喝。qiao好喝的。

偶尔：周末在家一天的水就是纯牛奶；

经常：早餐要喝纯牛奶，下午要喝酸奶；

我和我上面提到的小姐姐坚持了好几年都没有什么问题。

更新一下：有好几个评论都说喝牛奶会长痘，我特地查了一下，牛奶属于热性的，如果你本身体质比较偏向于热性的话，就会发痘痘，建议少喝不要一天喝太多。我的体质是寒性的，难怪这么多年也没问题呢hhh。谢谢各位小可爱的评论，欢迎大家继续交流。


▼水果▼

从大学到现在我都超爱吃水果的，每月生活费大部分都买水果了，而且一天能吃很多，如果我很穷了，我一定是吃水果吃穷的。在某APP下的水果订单，隔几天就买个几十块，碰上爱吃的进口车厘子、青岛大樱桃我也是吃起来不心疼钱包。平常多吃水果，补充维生素，多吃菌类，西兰花，葡萄，圣女果富含VC的，会不那么容易晒黑。随便截几张我买水果的记录：


周末日常水果，可以一天吃完：

水果根据体质不要乱吃。我不太吃西瓜，因为它是寒性食物，我体寒；不吃哈密瓜，糖分太高了会胖；很爱芒果但是会克制少吃，因为它湿热；荔枝不太吃，因为我易上火…………吧啦吧啦。葡萄圣女果柚子都是富含vc的，糖分也还好，葡萄太甜也不会吃太多。




▼适当吃保健品▼

这个量力而行，经济允许可以适当吃一些保健品，尤其是都市女性，一线的高压生活，女生25岁后在职场打拼很容易累，各种加班不在话下，忙起来饭也来不及吃几口，吃的又是外卖，很容易维生素什么的摄入不足，推荐吃一些葡萄籽胶囊、月见草胶囊什么的。目前在吃的葡萄籽胶囊，一个澳洲品牌。当然这个东西有些人觉得是没用的，所以如果你很不屑吃保健品的可以忽略我的经验哦。


▼保持运动▼

在肌肤稳定，没什么毛病的情况下，运动确实会让皮肤状态看起来很好。可是光运动完全不给肌肤维稳，也别指望有太大的改善，毕竟也不是每个运动员都肤如凝脂啊，假如不防晒，不好好护肤，皮肤该差的差，细纹该有的有，不好好睡觉黑眼圈照来。


    接下来是喜闻乐见的护肤品推荐环节了
    不要迷信护肤品可以妙手回春，肌肤有严重问题的，可以看中医喝中药，可以看皮肤科西药治疗，可以去靠谱的医美机构改善肌肤状况

▼拍点我的部分护肤品，为了你们的流量着想一张图搞定，有没有觉得我很贴心！我是混油皮，两颊偏干：

从上左往右：

1，珂润卸妆蜜，混油皮也不焖痘，适合敏感肌，本来就是敏感肌专用的；

2，珂润控油化妆水+乳液，也是敏感肌专用，我混油皮用着很控油；

3，freeplus保湿化妆水+乳液，依旧适合敏感肌，然而我混油皮觉得非常好用hhh；

4，碧柔防晒，清爽不油腻，适合上班通勤，用完要打伞，碧柔家不防晒黑，防晒伤；

5，肌美精3D面膜，面膜剪裁很好，精华液很多，补水很棒；

6，日本曼丹婴儿面膜，不多说，一生推，保湿很好；

7，城野医生毛孔收敛水，不适合敏感肌，混油皮很OK，收缩毛孔；

8，索菲娜控油隔离乳，好用不油很贴妆；

9，雅诗兰黛眼部精华，好吸收不油腻，对于我可以淡化黑眼圈；

10，泰国牛奶洗面奶，便宜，洗完不干，唯一我不喜欢的就是味道太甜。是有皂基成分，适合混油皮和油皮，但是最好不要天天使用皂基洗面奶，最好和氨基酸的换着用。

▼以上产品有更详细的使用感，感兴趣可以移步▼：

    第一次发的文章还有抽奖活动，大家快去围观：
    护肤测评|混油皮，有什么护肤品比较适合的呢？



这个回答已经写了很多内容了，更多护肤品推荐可以戳下面的链接：

陈兮兮：你买到过性价比最高的化妆品/护肤品是什么？

陈兮兮：你买到过性价比超低，不好用的化妆品/护肤品是什么？

陈兮兮：有哪些好用的平价护肤品？

陈兮兮：如何让皮肤白得发光？

陈兮兮：怎么样养头发？

陈兮兮：有哪些让你相见恨晚的化妆品和护肤品？



说了那么多内容，都是自己辛苦码字的经验总结和分享，不一定适合每一个人，但是希望可帮助各位小可爱一起变美变漂亮。喜欢可以给我点个赞支持我一下哦！

最后再跟我念一遍：

护肤保养的奥义不是要妙手回春，而是永远看起来都比同龄人显得状态更好。还年轻的小可爱也许体会不到这句话，待你们渐渐老去，就知道年轻时的护肤习惯会多影响以后的容颜了。


知乎的礼仪是能赞就别感谢，收藏了就去看看作者其他回答。

…………………………可爱分割线……………………




我是陈兮兮儿，爱生活爱美食还很爱臭美，更多的护肤美妆、美食烘焙、居家生活相关内容，在我的公众号【陈兮兮儿】都可以找到。如果你爱美又爱生活，那么你一定要点波关注找我玩呀！



http://weixin.qq.com/r/QDkhORHEwEy-rVVa92xS (二维码自动识别)



大家有什么好的建议和推荐，欢迎留言和我交流哦！
编辑于 2017-11-13
洋葱头
洋葱头

第二次更新，在另一个帖子分享了祛痘印的一些利器，欢迎围观~

https://www.zhihu.com/question/37375085/answer/234885924

------------------------------------------------------------------------------------

两天居然破四百啦！一大早看到这个数字实在是惊喜万分，第一次在知乎答题能得到这么多人的喜爱和认可，答主这边谢谢大家啦 

这边统一回答一下评论区集中关注的几个问题

1. 问题皮肤长痘，毛孔粗大或是长斑，无一例外都是我们身体素质反应出来的一个信号，饮食作息，体质原因，外界天气季节因素，或是日常护肤不当都有可能导致，除了注意一些老生常谈的日常习惯之外，准确找到原因，内外兼调，对症下药也很重要，有的人吃西药抹抹药膏就能好，有的人靠吃中药调个一两年才慢慢有好转，这都是正常哒，大家不要着急，要有信心，皮肤调理需要一个过程，慢慢转变，然后再稳定下来，它都需要一点时间，但是一切都会往好的方向发展哒，有什么问题如果答主知道都会尽力解答哒～但是大家如果皮肤问题比较严重的话还是先要及时去医院看医生噢，找到问题根源，错过治疗期留下印子就不好了，答主这边啰嗦几句提醒大家一下哈 

2. 大家集中催产的护肤和其他系列，答主最近在考试周呢，恨不得一天分身48小时用，可能会晚一点噢，大家耐心等待，稍安勿躁哈哈哈哈 

3. 评论区要求解匿的评论居然得到了高票赞同，哈哈哈哈这个真是让答主受宠若惊，大家一起讨论护肤体验，这其实也是答主一开始在知乎答题的初衷，群众的呼声这么高，我会好好考虑一下哒，现在还是有点小小害羞☺️

4. 答主虽然在澳洲生活，但是我这边目前是不做代购哒，为什么 因为怕事儿太多又把痘憋出来了，皮肤刚有点好转想集中精力养一养，但是答主周围有朋友在做，如果你有需要还是可以让我私你的，没关系哒～

最后再次感谢大家的支持噢～


华丽丽的分割线

---------------------------------------------

以下是原答案

这个问题放开让我来！！太有发言权了！！

目前地标：澳洲 悉尼

常用地标：新疆 乌鲁木齐 及 江苏 苏州

肤质：春夏油皮，秋冬混油（100%遗传亲老爹）

战痘篇

我的战痘历史要从5年前说起，刚刚进入大学那一年，因为实在胖的不成人形，所以下决心减肥，可能因为饮食习惯突然受到外界的禁食挑战，以及全英本科带给我的极大压力，生活作息不规律和膳食营养不达标使得我从到达了苏州之后就开始一发不可收拾的长痘，从那儿开始我的脸就变成了祛痘产品的试验田，也还好，她终于还是试验了点东西出来。

首先，先给大家看一下我的脸从最严重的时候到现在的变化吧（前方高能啊！） 

2015年11月




2017年8月




（以上照片都是用iPhone 6s Plus前置所拍）

前两张照片是2015年痘痘最严重的时候，那时候感觉整个头都是肿的，一笑起来笑肌会完全顶到眼镜上，脸根本不能上妆，不仅疼而且还会堵塞毛孔，但为了避免脸上的情况吓到同学，所以每天靠口罩度日。后来终于找到了合适的外用药和口服药之后，终于有了后面两张照片的变化，虽然偶尔会长两颗姨妈痘，而且

现在的皮肤也仍然存在毛孔粗大和痘坑的问题，所以还在持续护肤修复焕肤中~

不过至少痘痘是真真儿的没有啦

就给大家分享一下我实践过，真心觉得好用的祛痘产品


外用类：

1. Kiehl’s Acne Blemish Control
Daily Skin-Clearing Treatment 30ml科颜氏清痘修护精华露 专柜价¥330




闭口&粉刺克星！科颜氏这只清痘乳是我无限回购的一只药膏，因为爱长闭口，而闭口又会发展成痘痘，所以预防这种发展变得尤为重要，有时候感觉到皮肤上出现闭口的时候涂上，用洗干净的小手手均匀抹在闭口上，睡一觉，第二天闭口就真的不见啦！药膏上说它也可以用于被挤破的痘痘上，帮助愈合皮肤伤口，在没有Thursday planation的祛痘啫喱之前，它是我愈合皮肤的心头好，但有了新欢之后，这只旧爱就被我拿来作为祛闭口专用药膏了。据说它也可以祛痘印，但是我没感觉出来有什么作用，可能不适合我的皮肤吧。这只价格略贵，但是一只可以用很久，而且效果真的好，也就不计较那么多了~


2. 薇诺娜清痘修复精华液30g 天猫旗舰店¥218


薇诺娜是我当年从中医院走出来进到一家药店中，无意间被药店阿姨安利的药膏，因为薇诺娜当时真的没名气，所以内心觉得很贵，不过还是挣扎着买了一只试了试，不得不说，薇诺娜突然火起来是有原因的，绝对国货中的战斗机，药妆新风尚啊！这只精华液针对新长出来的痘痘有奇效，涂一天之后痘痘基本就不红了，第二天痘痘就会瘪下去，坚持到涂几天以后，痘痘会彻底消失，而且不留痘印！有时候第一天长出来忘记涂了，第二天再涂，它就有可能会催熟痘痘，然后熟透了之后挤掉就好，但是这样留痘印的几率就很大，后续一定要配合祛痘印的产品来淡化痘印哦！
3. Thursday Plantation Tea Tree Medicated Gel For Acne 25g 星期四茶树祛痘啫喱 参考价¥85



Thursday Planation是个专门战痘的品牌，我手比较贱，爱挤痘痘，这只啫喱我是专门用来愈合手贱后破掉的皮肤伤口的，味道真的就是大自然的味道，但是厚涂后消炎消肿一级棒，因为不贵，所以厚涂完全不心疼哈哈哈，它针对红肿大痘效果很好，涂上睡觉，第二天就不会那么疼了，但是针对闭口基本没用，据朋友说也可以用于蚊虫叮咬，还能用于学习时的提神醒脑，一膏多用有没有，90块，值！
4. Clearasil
Ultra Rapid Treatment Cream 15ml 
Clearasil 4小时速效祛痘霜 参考价¥90


澳洲本土的牌子，因为澳洲保健品的好口碑让我很相信它的产品，所以在药店的柜姐倾心推荐后我选择了这个4小时速效祛痘霜，使用下来感觉它虽然并没有4小时帮你速效祛痘，但是一只可以用很久，而且效果真的好，也就不计较那么多了~
口服类：
1. 普仁堂 麻仁滋脾丸9g 10丸 药店参考价¥10


这个“大力丸”主治润肠通便，大便不通，是一个中医给我推荐的，他说脸上长痘的人通常会因为肠胃不好而反射在脸上，建议我吃一吃这个，当然我是实力拒绝的，我这辈子可能最害怕吃的东西就是中药了，但因为当时我也真的大便干燥并且伴随便秘，所被娘请逼着买来试了试，讲道理，这玩意儿真的难吃，超大一颗，每次都要我娘亲帮我搓成一个个小球球然后分好几次喝水咽下，吃的时候总有种英雄服毒打死不说英勇就义的英姿飒爽，不过说良心话，这真的是我吃的算是十分有效的中药了，但有一点点药物依赖性，因为我有了它，真的畅通无阻，一旦离开，如同一条死鱼。
2. Nu-Lax乐康膏 500g 代购参考价¥90


主要功效是清肠治便秘的，接触这个是因为一个跟我妈关系超好的阿姨看到我脸上的痘痘以后问我是不是偶尔会便秘，我说会的，于是她就给我安利了这个，并且托朋友从澳洲给我带了一盒让我试试，说真心话，吃之前我也是很害怕的，因为怕副作用和药物依赖，但事实证明，一切都是瞎担心，纯天然植物水果制成，吃的时候还可以吃到无花果籽，甜甜的，通常在睡前8小时服用，一次10g，不可以因为好吃过多服用哦！吃完以后要喝大量的温水，帮助肠胃蠕动。第二天可能会有轻微的肚子痛现象，亲测一盒吃完会很好的改善便秘，并且断了它也可以轻松如厕~
3. Swisse 葡萄籽 180片 代购参考价¥140


主要功能抗氧化，第一次吃葡萄籽是当时的室友推荐的，说是有奇效，皮肤真的会变滑变嫩毛孔变小，所以抱着尝试的心态当时找了英国留学的好朋友帮我买了HB的葡萄籽，可能是因为当时皮肤真的太差了，所以效果不是特别明显，后来自己来了澳洲留学，就分别试了试Swisse的和Healthy Care的葡萄籽，但是真的，一分价钱一分货，Swisse的比HC的不知道神奇多少倍！只要遵从要求服用，毛孔是肉眼可见的在变小，气色也会变好，手贱挤烂的痘痘的恢复周期也会变短，而且不依赖，无副作用。

最后来一张大合照吧~



最后给大家来个对比图合集，给大家增加一点信心！

15年8月妆后未美颜状态



17年7月妆后未美颜状态


10分钟前素颜状态



最后还是一些老生常谈，各位小仙女们，战痘需要一些时间，不要着急，平时一些小习惯也要注意好，一定要勤换床单被罩枕套，少熬夜多休息，按时吃饭，多喝水，少吃或不吃辛辣油腻和甜食，平时在注意一些护肤步骤，内外调理一并进行，皮肤一定会慢慢变好嗒！

大家要是有什么问题私信我，我会尽量解答，毕竟曾经都是战痘中人，非常理解作为一个一心当花季少女，空有一脸疙瘩的焦虑和痛楚...之后我还会慢慢把我尝试过有效的护肤遮瑕系列分享给大家~


能看到这里的都是真爱，左下方点赞收藏噢！
编辑于 2017-09-26
玛丽酥
玛丽酥
科学护肤派，专治不要脸。

说到让皮肤变好，饮食肯定是大头。

但是到了痘痘肌，怎么就变成什么都不能吃了？像“痘痘肌的饮食禁忌”这类不让痘痘肌吃什么的文章很多，却没有人告诉他们，有一些“好食物”吃下去是能够对痘痘有好处的。

所以今天我要强答一下痘痘肌饮食的问题。

-----

长痘的人，因为害怕，连吃的东西都要小心翼翼地对待。

“你们说米饭高GI，我已经一天没吃饭了”

“土豆是高GI食物吗？是不是不能吃了”

“水果含糖量也很高，难道连水果都要戒掉吗”

这种“戒掉某某食物”、“绝对不能吃”的对话在班级里每天都能看到。

他们也在经受着改善饮食过程中痘痘反复的煎熬，因为眼里一直都在盯着食物升糖指数表，盼着脸上的痘痘快快消失掉，即使痘痘好了，内心对于食物的恐惧却有增无减。在痘痘不明真相地再次爆发以后，就开始怀疑人生。

-----

当然，我今天不是给喂鸡汤的，只是希望你们在科学的饮食建议面前，先建立起基本的【饮食原则】：

1.“忌口”不是一口都不能吃，不要矫枉过正地“戒”，食物不是你的敌人，你要学会用心搭配饮食。

2.有的人喝牛奶长痘，有的人却是吃甜点长痘，不同的人对不同的食物反应都不一样，人体如此复杂，科学的理论研究绝对不是它说了算。所以在与食物打交道的过程中，学会了解自己的皮肤状况和你吃下去的食物之间的关系，才能最大地减少对食物的恐惧。

3.懂得“适量”不仅仅是克制，更是学会对自己宽容。

下面，去正片（文末附彩蛋）！

    一项针对13215名12-20岁的汉族青少年的研究表明，痤疮的患病率达51.03%；患与未患皮肤病的青少年相比，患者发生便秘、口臭、胃反流等胃肠道症状显著增多，约有37%的腹胀可能与痤疮等脂溢性疾病有关。[1]
    [1]Zhang H，Liao W，Chao W，et al.Risk factors for sebaceous gland diseases and their relationship to gastrointestinal dysfunction in Hanadolescents.J Dermatol，2008，35:555–561
    肠道和皮肤状况密切相关，研究已经表明肠道微生物可以通过影响系统性炎症、氧化应激、血糖控制、组织脂质含量，甚至宿主的情绪等影响皮肤疾病[2]。而食物在塑造和维持肠道微生物方面具有决定作用，不同的饮食习惯肠道微生物组成不同。
    [2]Bowe W P，Logan A C.Acne vulgaris，probiotics and the gut-brain-skin axis—back to the future?Gut Pathog，2011，3:1–11

所以饮食是引起痘痘的重要因素。

-----

饮食建议：

1.补充富含维生素A、类胡萝卜素（维生素A的前体）等微量元素，能够降低油脂分泌量，促进皮肤正常角化，降低长痘风险。同时，它们也是有效的抗氧化剂，保护受损皮肤免受自由基的侵害，加速痘痘部位的修复。

维生素A：只存在于动物的组织中，动物肝脏、蛋、奶酪和鱼肝油中天然维生素A含量最高。在植物性食品中所含的β-胡萝卜素能在人体中转化为维生素A，多吃深颜色的绿色、红色和黄色的蔬菜和水果，如番茄、胡萝卜、南瓜、红薯、菠菜，红椒，以及香蕉、橘子、柿子等。


2.补充益生菌和益生元

研究表明益生菌具有改善肠道屏障功能，恢复肠道微生态健康的作用。能够对皮肤起到抗炎功效，对治疗痘痘和皮肤过敏都有作用。益生元则是益生菌的养料，通过补充益生元，能够促进有益细菌的生长繁殖，间接调理肠道。

    19世纪30年代，Stokes和Pillsbury就曾提出了干预肠-脑-皮轴的方法，他们建议采用添加嗜酸的微生物，如嗜酸乳杆菌(Bacillus acidophilus)来终止由压力引起的皮肤炎症.此外，他们还推荐一种嗜酸菌酸奶(acidophilus milk)和鱼肝油来辅助治疗皮肤炎症，并且发现口服乳酸杆菌片和乳酸菌发酵饮料有明显促进心理健康的作用。

常见食物如奶酪、酸奶(yogurt)、香蕉、燕麦粥、开心果、泡茶和红酒等，也可以通过补剂进行补充。

【注意】虽然奶酪中含有较多益生菌和维生素A，但由于其也含有较高的亮氨酸，能够（通过激活TLR）促进炎症发展而对痘痘肌不利。

3.补充ω-3多不饱和脂肪酸

金枪鱼，鲭鱼，鲱鱼和三文鱼等这些具有大量脂肪的深海鱼富含ω-3脂肪酸，能够有效抗炎，改善痤疮和面部泛红。除了深海鱼，像鲢鱼和鲈鱼等淡水鱼也会含有一些ω-3脂肪酸，吃这类鱼类的时候可以多吃一点它们肚子上的脂肪。

ω-3的其他食物来源：亚麻籽、奇亚籽、核桃等坚果，深海鱼油胶囊等进行补充。

4.补充膳食纤维

现有研究表明高糖、低纤维及高碳水化合物食品是痤疮发生的危险因素，传统饮食的人群肠道微生物群具有多样性，长期高糖、高脂及低纤维饮食会使肠道微生物群失调，即双歧杆菌及乳杆菌等有益菌数量减少。而膳食纤维在肠道后端的发酵能够促进有益菌的增殖，帮助调理肠道。

谷物和薯类等粗粮含有较多的膳食纤维，单纯因为它的升糖指数高而放弃它们是非常不明智的，还有可能因为膳食纤维摄入不足而导致便秘问题，引起肠道菌群失衡，同样也会导致痘痘问题。

主要来源：蔬菜、水果、谷类和豆类。


5.控制热量

饮食也会对皮脂腺的分泌有一定的影响。实验就发现低热量的食物可以快速降低皮脂分泌，减少痘痘的生发。所以减少高油和高脂等加工食品和油炸食品的摄入，对治疗痘痘还是有非常明显的效果。

-----

以上是给痘痘肌的饮食建议。

还是回到我最开始强调的，饮食建议只是给你的一份参考指南，但不要老是纠结该吃什么，不该吃什么，你应该先学会怎么吃。


总是压抑自己的欲望，糟糕的情绪会让我们破罐子破摔，不利于我们长期坚持，结果往往适得其反。

我一直强调心态对于治疗痘痘的重要性，这不是我瞎吹，近年来的研究已经确证肠-脑-皮肤统一理论，肠道、大脑和皮肤之间可以通过血液系统、免疫系统、内分泌系统和神经系统进行双向联接。

所以，不要看到自己的痘痘就觉得不爽，眼里就知道盯着食物的GI。

把痘痘、情绪和饮食三者的关系处理好，才是大学问。


-----

【噔噔，彩蛋！】

其实皮肤科大牛Leslie Baumann对不同肤质的长痘人群也给出了针对性的饮食方案，

油性耐受、油性敏感痘痘肌和干性敏感痘痘肌在饮食上的侧重点会有所差异。

下周大酥将会在科学护肤15班进行专题分享，把这位大大的饮食方案介绍给大家。

添加大酥的WeChat「sususumali」，报上暗语「改变」就可以加入班级一起学起来啦……

【相关阅读】

痘痘心态篇：长痘（痤疮）是怎样一种体验? - 知乎

痘痘医院药物篇：怎么消除脸上痘痘和挤完痘痘留下的斑？ - 知乎

最全的治痘指南：有没有去除痘痘比较好的方法？ - 知乎
编辑于 2017-04-06
Blair晓然
Blair晓然
微博@Blair晓然

欢迎大家来微博找我玩啊哈哈哈哈@Blair晓然

-------------------------------------------------
总结了下评论，大家有问题的话继续评论问哈～

1.不要总是“我觉得”洗不干净，个人感受不能作为清洁力度大小的判断标准。
2.洗面奶起泡上脸10到20秒洗掉就好，卸妆油溶解掉彩妆马上洗掉，不要一直揉。
3.屏障修复是很重要的事情，大家对照我说屏障修复的段落，判断自己是否有同样症状，然后精简护肤就好。
4.屏障健康的肌肤用防晒霜完全没问题，屏障受损就老老实实硬防晒，口罩帽子戴起来，把自己想象成碰到阳光就灰飞烟灭的妖精就好了。
5.问题描述越细致我能给出的建议就越细致。

-----------------------------------------------

哈哈哈怎么感觉评论是精华更值得翻翻翻～

-----------------------------------------------

分享下皮肤变好路上关于祛痘、皮肤屏障修复和Plasma去水痘坑的事情～

惯例上照



关键字：三石医生，糊奔奔，阿达帕林，班赛，克林霉素，至本，雅漾，伊丽莎白雅顿，精简护肤，飞顿

 祛痘：
    治痘先治脑子。
    别相信美容院、中药、针灸、放血…之类靠玄学治痘的方法。
    皮肤好除了强大基因以外，更多的是遵循人体最基本规则和正确使用药物及护肤品的必然结果。

    微博推荐：@三石医生 
    轻度痤疮（粉刺类）不需要口服异维A酸类药物，可以外用克林霉素或者阿达帕林（A酸）和班赛（过氧化苯甲酰），如果觉得阿达帕林刺激可以加乳液打底，或者按照涂半小时洗掉、一小时洗掉循序渐进建立耐受。
    中度及以上以及以上去医院看医生，靠谱医生在三石微博里搜索关键字比如“北京”。

一些Tips：
1.忌甜食及乳制品。
2.早睡（我没做到（微笑脸。
3.手贱挤了痘之后，用纸巾止血，涂一层金霉素眼膏，别什么都不擦更别湿敷。
4.长痘就别湿敷别敷片状面膜，湿敷会导致皮肤过度水合，闭口更严重。
5.停用防晒霜，改为硬防晒（口罩帽子）
6.三石微博里的痤疮治疗方案：


 皮肤屏障修复：
皮肤屏障：皮肤屏障由皮脂膜、角质层角蛋白、细胞间脂质组成。
皮肤屏障是肌肤的保护墙，由于不当护理导致皮肤屏障受损，肌肤就没有了抵抗力。
任何细微的刺激都会导致皮肤情况紊乱，发红，刺痒，皮疹接踵而至。
    有下列任何2个以上问题困扰即可判断为屏障受损皮肤。外油内干、脆弱易敏、泛红发痒、肤质不平滑、肤色不均匀、护肤品不易吸收、 “闭口”疙瘩频发、毛孔堵塞。

    微博推荐：@糊奔奔

    之前我在用阿达帕林和班赛的时候，可能用药过猛，皮肤干燥起皮还一碰就红，凡士林都拯救不了，于是开始修复皮肤屏障。

    早上清水洁面，纸巾擦干，雅漾大喷+至本舒颜修复霜。
    晚上至本洁面，纸巾擦干，雅漾大喷+至本舒颜修复霜+克林霉素或者阿达帕林点涂。
    买了粉胶和金胶，总的来说金胶吸收感更好提亮效果更明显～

    以下Tips是糊奔奔写的，挑了一些关于护肤的复制过来每天大声朗读五十遍。

1.洗脸之前，请认真地洗干净手。
2.温水洗脸最佳，冷水热水冷热交替都不要。
3.毛巾按压吸干水分，不是揉搓。
4.不要用花洒冲脸。
5.对于绝大多数皮肤来说，每天晚上用一次洁面产品足够了。
6.洗面奶在脸上停留时间最长不要超过30s，习惯1、2分钟的，几乎没有好皮肤。
7.中午别洗了，带妆睡那么一会儿没事儿，求您。
8.爽肤水不要总是擦拭和湿敷，轻拍是它们最合适的方式。
9.面膜是健康皮肤的玩具，烂脸没资格用面膜。
10.敷面膜是一场交易，牺牲一部分 得到一部分，不要在渣膜上浪费感情。
11.护肤品在脸上轻轻抹匀再轻拍就好。一直揉并不会加速吸收，只是加速它干掉，负面影响是揉搓对皮肤的刺激（泛红 粟丘疹 脂肪粒 细纹）和搓泥。
12.护肤品不可能祛痘坑，不可能，不可能。
13.抗老产品主要作用是延缓而非逆转，不抱有不切实际的幻想。
14.防晒很重要，但防晒不等于防晒霜。
15.防晒最终是防止光老化和美白，皮肤状态很差的情况，用防晒霜刺激皮肤炎症，老化速度和炎症后色素沉淀更可怕。
16.整形不是坏事儿，但是你必须有审美。如果审美情趣不高，一定要认清现实，并找个好大夫帮你把关。有时候6mm的双眼皮比8mm美。
17.祛痘机构·皮肤管理中心·美容院。（微笑）
18.物极必反，再安全的东西瞎用也会出事。即使是雅漾矿泉水不停的喷、湿敷 一样烂脸。
19.出生起，人无时无刻不在老化。当你有意识要护肤了就是抗老的开始。
20.当你看到这一条时，说明你很关注护肤，不要纠结年纪，请认真擦眼霜。
21.VC不感光。
22.瞎买护肤品，不如瞎买口红。
23.如果不能保证每天一斤蔬菜 200g水果 半斤杂粮，请坚持服用复合维生素。
24.对客服有礼貌。
25.点痘产品，除非包装说明需要厚敷，其余统统都薄擦。
26.运动和早睡是最好的抗老。嗯 比全套la prairie还好。
27.屏障受损不完全等于皮肤敏感，认清现实，直视自己，不要得过且过。
28.不拿皮肤差当常态，不要用基因差搪塞没有努力过的自己。
38.糖是万恶之源，长痘 衰老 发黄都赖它。
39.不要因为便宜或者已经买了就得用完的心态，委屈自己将就一样护肤品，要知道它服务与你，而不是你妥协于它。
40.上脸的每一样东西必须是有意义的。
41.涂抹式瘦身产品，只能消水肿。别瞎想！

45.老“闷痘”的皮肤，审视自己是不是折腾太厉害了。痘和闷在大部分情况下没关系。
46.外油内干不是皮肤状态。
47.坚持擦身体乳。
48.嘴唇也会老化。
49.长脂肪粒是你太粗暴了，皮肤在无声抗议，别想赖我们眼霜。

 Plasma手术：
Plasma是去痘坑的，我左脸有两个小痘坑，大概半个月前去打掉的，现在还在色沉期（没注意防晒而且做完三天就化妆的后果，血一般的教训）。
    机器是以色列飞顿，因为我不是全脸做，只是打掉两个坑，所以没敷麻药，痛感跟纹身时候差不多～可能我比较抗疼。
    开始手术之前医生会拍VISIA图，确定激光范围和力度，开始打激光的时候会有一点……嗯……烤肉味……（做完我就去吃烤肉了也是心大）。
    激光结束之后马上涂红霉素，会有渗出液，结痂前不要沾水，结痂后轻柔洁面就好。
    我是第二天结渗出液痂，第三天痂全部脱落，然后就化妆了……
    总的来说是个小手术，而且很便宜，毛孔粗大或者去痘坑首选～推荐推荐～
 大概就是这些啦～
编辑于 2017-05-11
我叫陈世美
我叫陈世美
护肤科普/淘宝店主/APP开发/房地产

谢邀~   

首先看到这个问题和描述的时候，习惯性的看了看回答内容，可惜见到几个热门回答真的让人有点心塞。我没有故意抹黑或是衬托我水平多专业怎样怎样，只要大家认真看看就能看的出来，有些回答是不知道从哪里东拼西凑抄上去的看上去好似很专业的回答，实际上和提问的问题却半毛钱关系都没有；另外有些则是根本不走心的推荐，纯粹是在为了写回答而回答，连问题想要get的点都不知道。

所以看完了之后想想还是来回答一下这个问题。首先呢，皮肤的好坏并不取决于单一的某个或某些因素，而是由自己的基因、日常的生活习惯、饮食作息习惯和护肤方案及策略所共同决定的，只要想让自己的皮肤变好，除了基因无法改变外，其他的好的生活习惯，规律的饮食作息，正确的护肤观念和正确的产品搭配却可以轻松的让人皮肤状况更上一层楼。我接触护肤也有些年头了，毫不夸张的说现今多数人的保养方法都是错误甚至离谱的，看到一些努力想让自己变好却因错误的保养方法而毁了自己的也比比皆是，正因此每每看到与护肤相关的问题我都会尽自己所能来向大家科普最正确的与护肤相关的知识，希望能够帮助到任何看到我的回答的人，这样我的心里也会很高兴并且还有点小小的成就感和欣慰。好了，废话不多说了，直接进入主题吧。

在问题中提问人阐述了多年疏忽保养以及自己的生活习惯，皮肤粗糙，皮肤状态不稳定，并且还说自己是敏感皮肤。那么就就着这几个问题来一一回答究竟如何能让自己的皮肤变好。

首先，坚持良好的生活习惯与合理健康的饮食作息习惯是绝大多数人都知道的同时它们也是很重要的影响因素，那么就在这里简单的说一下。

①生活习惯对人的影响：良好的生活习惯包括范围很广泛，实际上它是能将饮食和作息包括在内的，但是在这里分开写的主要原因就是想说说生活习惯中一个重要的影响因素——运动。在现在的社会中，许多人因为这样那样的原因普遍缺乏运动。在人类已知世界中，运动是人类自主活动中最能够改善人体状态的途径，为什么呢？因为在运动过程中，会提高细胞生命力，提升细胞寿命，并且在某些未知基因的影响下还能够逆转已衰老的细胞、组织、器官（当然，作用效果有限）！而运动对皮肤的影响也是不容忽视的，它能够加强皮肤的代谢，让皮肤细胞充满活力，在影响激素水平的条件下还能够显著提升人的气色。运动金字塔的数据中建议人们应该至少每日进行不少于30分钟最好能达到1小时的低强度运动（走路，上楼梯，做家务等）；至少每周进行三次最好能达到六次的20分钟-60分钟的有氧运动（快走，慢跑等）；至少进行每周三次最好能达到七次的5分钟-10分钟的柔韧运动（瑜伽，体操等）；至少每周进行两次最好能达到三次的15分钟-30分钟的抗阻运动（参见健身房内的各种抗阻训练），并且还强烈建议最大化的减少静坐不动的时间。由此可见运动的重要性和久坐的危害。

②饮食习惯对人的影响：饮食习惯的好坏同样对人有着不小的影响作用，好的饮食习惯包括低GI食物的摄入，维生素的全面摄入，蛋白质及碳水的供应足够，必需脂肪酸的摄入等等。这我想不需我多说大家也能够明白，通俗的解释上面几条就是用杂粮饭代替精米精面（由于精米精面都只是单一的高淀粉化合物，毫无营养可言），日常饮食中多吃各种蔬菜水果少吃肉尤其是肥肉，保持一定量的植物油摄入。它们对皮肤状态的影响是潜移默化的，不良的饮食习惯会提升人体内自由基含量（氧化效应），并还会引发皮肤醣化（诱发皮肤老化的间接原因的一种），也许多数人对醣化较为陌生，但对抗氧化的名声应该如雷贯耳了，就是这个道理。

③作息习惯对人的影响：在作息习惯中，影响因素因素最大的就是熬夜！保证充足的睡眠是给整个机体提供动力的最主要的影响条件，当人睡眠不足时，不仅皮肤状况会受到显著影响，整个人的精神也会萎靡不振，大脑反应能力下降，这还只是我们能感受到的表面现象，诸如潜在现象例如对各种激素水平的影响，对身体内各器官的影响及对人细胞环境的影响都不容忽视。有着充分的实验数据证明熬夜对于人体来说绝对是百害而无一利的，所以在此再次提醒大家能够时刻注意，在能不熬夜的时候就不要熬夜。我们正常人每天所需睡眠的时间至少是7小时，一般人比较理想的时间能够达到8小时。如果长期连续每日睡眠时间低于6小时就会对人体产生意想不到的巨大伤害，谨慎为之！但若长期睡眠过多（10小时或以上）同样有坏处，那会使得人体大脑处于半休眠状态，使机体反应能力迟缓（婴幼儿除外）。

不要觉得以上三点没什么。。

我就上个我的图。 （发现最近很多人喷我嘛，您瞧好了。看看您自己是什么样子的。）

OK 。正题。（意思就是以上三点，除开护肤对体型塑造也是基础的工作）

说了这么多大家也都能够看的出这些内在的因素对人体的影响，除了上述因素外还包括人的情绪，心理，压力等，因为这些都是能够影响我们激素水平稳定的神经因素，所以都应注意。那么内因说完了就开始说说外因吧，也就是在护肤中占有重要地位的护肤品，合理使用含有精良优秀配方的护肤品能够为我们的皮肤提供最大化的保护和滋养。总的来说，皮肤护理除了包括基础的清洁、保湿、防晒之外，还应该进行适当的去角质工作和抗氧化工作，同时如果脸上有小痘印的话还要根据痘印的种类不同采取不同的措施来处理，加速痘印的淡化速度。

1.清洁

清洁是护肤中最基础的步骤，如果清洁就出了问题那么整个护肤过程也会随之受到影响。鉴于敏感皮肤的情况下，在洁面产品中应该选择温和的水溶性洁面，尽量少的使用或者不使用卸妆类产品，尽量避免二次清洁。

先来介绍一下在洁面产品中最重要的成分——表面活性剂

表面活性剂（界面活性剂）是能够使目标溶液表面张力显著下降的物质，它可以降低两种液体或是液体与固体间的表面张力。表面活性剂一般由具有亲水基团与疏水基团的有机两性分子构成，在水中与多数有机溶剂均可溶。当表面活性剂在溶液中的浓度超过某一个临界点后就会自发缔合形成胶束（micelle）。而胶束开始明显形成时的浓度称为临界胶束浓度（CMC），它是表面活性剂的重要参数。表面活性剂应用在洁面产品中的原理是因为它具有能够同时利用疏水基团吸附油脂，再利用亲水基团溶于水的特点，进而可以使原本不相溶的水和油混合在一起被带走，从而就能够达到清洁除污的效果。在洁面产品的挑选上尽量选择以氨基酸表面活性剂（椰油酰甘氨酸钠等）、两性离子表面活性剂（椰油基甜菜碱等）、非离子表面活性剂（椰油基-葡糖苷等）为主表面活性剂的洁面产品比较好，如非必要应尽量避免清洁皂或是以皂性（高级脂肪酸盐）阴离子表面活性剂（肉豆蔻酸钠/肉豆蔻酸+氢氧化钠等）。也许有的人看到会不以为然的认为答主死扣成分，但是事实上对于敏感皮肤来说长期使用皂类清洁剂所带来的弊要远远大于利，因为他们不需要过强的清洁力，却需要温和的清洁条件，这是由无数实验研究数据证明过的结果（有些人现在喜欢跟潮流谈论所谓的工艺，只能说连门都没入）。温和清洁对于敏感皮肤来说是使皮肤变好的第一步，过强的清洁力会导致皮肤屏障功能下降，使皮肤干燥，对外界抵抗力下降，使得皮肤更加易敏感和易泛红。

表面活性剂示意图

2.保湿

能够起到保湿作用的护肤品有很多，甚至可以说除了洁面和一些控油防晒产品之外几乎所有抹在脸上的护肤品都有一定的保湿作用，保湿是护肤中的基础步骤之一，同时它的作用也是至关重要的。因为在洁面之后，即使是再温和的表面活性剂，在带走面部油脂的同时也会带走一部分我们皮肤中的细胞间质，而这些细胞间质的含量及结构的完整性就成为了保证皮肤自身保水力的强弱。而当我们面临现在这越来越恶劣的环境，光靠皮肤的自我保水力并不足以抵抗外界环境所带走的水分，从而皮肤会出现干燥、紧绷甚至脱皮的现象，这时保湿产品的应用就显得尤为重要。

保湿以方式不同主要分为三类，分别是滋润剂、封闭剂、吸水剂

①滋润剂

顾名思义，滋润剂就是对皮肤有滋养润泽的油性成分，在当下的护肤品中使用的最多的是各种植物油和动物脂成分，因为植物油中多含有不饱和脂肪酸，不饱和脂肪酸尤其是其中的亚油酸可以协助皮肤生成神经酰胺（细胞间质重要组分之一），同时相比于动物油油腻性不高。而动物油由于高度饱和，性质稳定更不易氧化也不易对屏障引发其他反应。常见的这类成分主要有玫瑰果油、荷荷巴油、甜杏仁油、乳木果油、角鲨烯、角鲨烷、羊毛脂等。

②封闭剂

封闭剂指的是能够在我们的皮肤表面形成一个相对封闭的环境从而防止水分蒸发的一类成分，它们只会在皮肤表面形成一层“油膜”。因为其惰性较高，所以不仅不会被皮肤吸收而且还能给受损伤的皮肤提供良好的恢复环境。这类成分我们最常见的就是各种矿油，需要注意的是由于它们的特性，如果你皮肤本身含水量就比较低，那么单纯的使用封闭剂保湿剂只能让你感受到油腻感却感受不到保湿的效果。还有一点就是，这类成分理论上并不会堵塞毛孔，但如果比例太大或者以凡士林为基底做的药膏之类对于痤疮患者来说，可能会出现“闷痘的现象”。

③吸水剂

这类成分是护肤品中应用最多的，同样可以从名称上得知，它们是以吸收外界环境或锁住自身的水分来达到保湿的目的的。再细分的话还可以分为两类：一类是多元醇、天然保湿因子（NMF）及其他具有保湿功效的成分和植物提取物。多元醇属于水溶性的小分子保湿剂，如甘油、丁二醇等，它们具有“吸湿保湿”的功效，但通常保湿力不强。而天然保湿因子存在于皮肤的角质层中，比如各种氨基酸、吡咯烷酮羧酸盐（PCA X）、尿素、乳酸及乳酸盐等，它们能够拽住水分，并能通过调节角质层含水量同时降低皮肤的水分蒸发速率来维持皮肤水分的相对恒定。另外如透明质酸钠、粘多糖、水解胶原蛋白等这类与真皮层成分相同的成分及维生素原b5、藻类提取物、银耳孢子提取物等保湿成分也应用的相对广泛。

另一类则是构成我们皮肤屏障的细胞间质成分，包括神经酰胺、胆固醇、磷脂和游离脂肪酸。合理浓度配比的细胞间质成分可以显著修复皮肤屏障从而提升皮肤自身的水合能力。从而直接增加皮肤储水力，达到保湿的作用。

无论是爽肤水/化妆水，还是精华液，乳霜等都能够提供保湿的功能，其区别不过在于保湿性能的强弱和功效诉求的不同，一般来说，化妆水和精华液中水性保湿剂会加入的更多，而在乳液面霜产品中则会加入更多的油性保湿剂。不同的肤质需要选择不同的保湿产品，皮肤过油应选择轻薄的化妆水、精华液或轻薄的乳液来达到保湿的目的，并非一定要靠乳霜才能够“锁水”。

没图。



3.防晒

作为基础护肤步骤中最为重要的一步也是在整个护肤过程中均为最重要的一步就是防晒！不同波长的紫外线能够对皮肤产生不同程度的伤害，并不仅仅是晒黑这么简单。紫外线对皮肤的损伤主要来自于UVC、UVB与UVA，它们的波长依次递增，波长越长，对应的能量越小，穿透能力则越强。它们能促使皮肤癌的发生，因为紫外线能够诱发DNA的损伤，实验研究发现DNA经紫外线照射后同一条链上的两个邻接嘧啶核苷酸会共价联结形成某些嘧啶二聚体，这些嘧啶二聚体会使DNA的双螺旋结构局部变形，导致DNA在复制时碱基互补配对出错，这时DNA会进行自我修复（损伤旁路），从而可能导致基因突变，如果突变的是原癌基因和抑癌基因的话就会导致细胞癌变。另外，能量较强的UVB会使皮肤产生红斑，长期照射还会引起灼伤；而由于UVA具有极强的穿透力，所以可以深入至真皮层，破坏弹性纤维和胶原蛋白纤维，同时还会引起脂质过氧化，长此以往，这不可逆转的过程不断积累就形成了光老化，对外的表现就是面部皮肤产生不规则沟壑般的皱纹；而对于UVC来说，虽然其能量强度最高，对人体产生的损伤最大，一般认为大气中的臭氧层能够将其全部吸收使得它不能到达地面，但是最新发现南极上的臭氧层空洞范围一直在逐渐扩大，所以以后是否还要防UVC还真不好说。

好在现在的防晒技术已经十分成熟，只要挑选配方合理，能够撑起全波段防护的防晒霜来擦还是问题不大的。防晒霜主要分为物理防晒、化学防晒、物化结合防晒三种。物理防晒成分仅有氧化锌和二氧化钛两种成分，原理是靠反射、散射和吸收微量紫外线来达到防晒目的的，化学防晒剂则占了防晒产品的大半江山，UVB防晒剂主要有甲氧基肉桂酸乙基己酯、聚硅氧烷-15、胡莫柳酯、奥克立林等，现在对于UVB的防护基本上都能达标，而且不是长期呆在室外的人对UVB的防护要求也没有那么大，所以化学防晒的研发主流依旧在于提升UVA的防护力上，常用的成分主要有帕索1789、Tinosorb S/M、欧莱雅集团专利成分麦素滤宁光环（Mexoryl® SX/XL）及DHHB（Uvinul A Plus）。

对于敏感皮肤来说挑选防晒应该尽量以低刺激，足防护为准则来选择防晒产品，我更推崇物理防晒或是不含刺激性化学防晒剂的防晒产品，因为它们不会为皮肤造成额外的负担。还可以通过硬防晒和防晒霜相结合的形式来达到防护的目的，在硬防晒手段中，遮阳伞和太阳镜是个不错的选择，总的来说室外防晒应该是以遮阳伞遮蔽阳光的直射，太阳镜来防护防晒霜不能防护的眼睛和不易防护的眼周的方式进行，这样才算周全。

如果你能够按照我上面回答的内容坚持去做，那么对于皮肤的护理工作就已经完成了一半，而另外剩下的一半则需要在此基础上合理的应用一些产品，同时规避一些成分或产品（如较高浓度的酒精、具有挥发性的芳香精油和其他的一些刺激成分），并要做到搭配精简高效的护肤方案。

4.抗氧化

如果能够配合抗氧化产品使用会让皮肤的整体状态变的更好，抗氧化作用的最终目的是清除自由基及活性氧类物质（ROS）。因为自由基同样会对DNA产生影响，所以使用抗氧化剂来中和过多的自由基，不仅可以有效的延缓衰老，同时也能因自由基含量下降而降低炎症因子的过度释放，所以能够间接的达到辅助抗炎的目的。常见的抗氧化成分有多酚类物质（白藜芦醇、大豆异黄酮等）、多羟基物质（阿魏酸，抗坏血酸等）、醌类物质（泛醌/辅酶Q10、艾地苯等）、硫醇类物质（谷胱甘肽、硫辛酸等）。当多种抗氧化成分互相配合相互加成后能够形成较之单一抗氧化剂1+1>2的效果。抗氧化剂的好处不言而喻，现今有越来越多的实验研究充分的证实了抗氧化剂可以减少紫外线损伤。因此，每日在护肤过程中，增加抗氧化成分来搭配防晒共同使用，可以显著降低紫外线带来的伤害。同时，做好抗氧化工作还能够减轻皮肤暗沉，辅助皮肤美白。

5.皮肤粗糙，毛孔粗大的处理

皮肤粗糙和毛孔粗大一般是由两个常见原因导致的，一个是天生皮肤稍微油些或是平时不注意进行去角质工作使得老废角质过多堆积；另一种则是由于使用不当的护肤品所导致的皮肤屏障受损，皮肤状态下降导致的角质层不平稳显的粗糙。从问题上看，提问者应该是属于前者的情况，也就是说只要注意适当的去角质工作就能够让皮肤粗糙，毛孔粗大的情况加以改善（但当毛孔扩大到一定程度后，是不能靠护肤品涂涂抹抹就能消失的，尽管市面上有很多“收缩毛孔”产品）。

在去角质工作上，相比于磨砂膏或其他类似的产品来说，我个人更倾向于酸类产品的使用。酸类产品指的就是添加一定量的各类可以应用于护肤品当中发挥去角质效应的酸（最常见的为水杨酸，果酸中的甘醇酸）的护肤品。它们除了能够去角质外，对痤疮患者来说也是疗效非常好的成分。区别在于一种是脂溶性酸（水杨酸BHA），一种是水溶性酸（甘醇酸AHA）。一般情况下，由于浓度和诉求的限制，市面上的果酸类产品的去角质效果要优于水杨酸产品（BHA更多被应用于抗痘产品中），但对于油性皮肤来说水杨酸除了能够发挥去角质的作用外还能够深入至毛孔内达到清理、疏通毛孔、防止毛孔堵塞的效果。两者可以说各有优缺点。不过，近几年新兴起的杏仁酸产品则结合了两者的优点而出现在人们眼前。杏仁酸是果酸（包括甘醇酸、乳酸、苹果酸、酒石酸、柠檬酸、杏仁酸等）的一种，由于它的化学结构特点使得它既具有果酸本身的去角质特性，同时还具有脂溶性的特点，并且由于它的分子量大，透皮速率慢使得它也非常温和，一般的敏感皮肤也可以应用，是我最推荐的，坚持使用后就能发现皮肤的日趋光亮平整。

6.痘印的分类处理

痘印通常被我们分为红痘印和黑痘印。红痘印的成因是由于皮肤的慢性炎症却并未完全消退从而引起皮下的毛细血管扩张，在外观上看起来就是一块淡红色或者粉色的“斑”；而黑痘印则是由于炎症消退后产生的色素沉淀，叫做炎症后色素沉着（PIH），也因此黑痘印一般都是在红痘印之后出现的。

无论是哪种痘印，想要祛除首先必须要做好防晒。红痘印是通过局部抑制炎症因子产生从而使得炎症减轻直至消退来使红痘印加速消退。而黑痘印相比于红痘印来说黑痘印就要简单的多了。与一些斑点不同，它只会沉积在表皮层，因此可以通过外用产品祛除，通常采取加快代谢、还原已形成的黑色素和抑制黑色素的产生的方法，所以有效的淡斑精华类都会对黑痘印起到一定的效果。常见的加快色素代谢成分就是上面提过的去角质的酸类成分，而还原黑色素最著名的成分同时也是被证实的最多的成分则是抗坏血酸及其部分衍生物（维生素C）了。研究显示维生素C能够明显的使已生成的黑色素还原并且效率非常高，同时安全性也经过许多年进行过一系列的充分评估，值得肯定。


OK 你居然看完了我的文章，一个一个码字而成。

如果你是糊弄糊弄随便看看，或者看完觉得不够针对。

那么我的回答里有这些。

1.痘印:如何去除脸上的痘印、痘坑？ - 我叫陈世美的回答

2.油皮：油性皮肤如何寻找控油和补水之间的平衡？ - 我叫陈世美的回答

3.生活习惯饮食：有什么好的生活习惯、饮食习惯、运动习惯可以去除痘痘，让皮肤变好？ - 我叫陈世美的回答

4.刷酸 青春痘：用于治疗青春痘（痤疮）的维A酸、尿素、果酸、水杨酸分别有什么不同？ - 我叫陈世美的回答

5.一个广告强势插入：有哪些很棒很有特色的产品是知友经营的？ - 我叫陈世美的回答

以上！ 为了逼格高一些，未经本人同意请千万不要转载，我会躶上身带刀去找你要巨额广告费。

最后继续嘲讽喷子。哈哈哈哈哈哈哈。 会慢慢继续完善答案。 
编辑于 2015-06-28
海豚可爱多君
海豚可爱多君
护肤与祛痘 微博：海豚可爱多君

窗外大雨淅沥，心里湿漉漉的，每天都能收到你们的反馈，也是蛮开心的。我的力量很小，能帮助你们地方很少。痘痘如果波及前胸后背甚至头皮，就100%就是中度以上（2-3级+），单纯外用药物基本无效，一般需要采用联合治疗，对于治疗痘痘，达芙文起效时间2个月，短效避孕药起效时间约3个月，维胺酯一般至少也要3个月，抗生素一般需要6-8周不能随便停药，光动力也需要3次以上……治疗痘痘你已经经历很多，如果能坚持一下，忍耐一下副作用，可能会更好，一起加油吧！

前言：

1.痘痘是如何产生的？

一般原因如下：

痤疮是毛囊皮脂腺单位慢性炎症性疾病，发病机制仍未完全阐明。遗传、雄激素诱导的皮脂大量分泌、毛囊皮脂腺导管角化、痤疮丙酸杆菌繁殖、炎症和免疫反应等因素都可能与之相关。

2.痘痘的类型

显著表现为开放性或闭合性粉刺（黑头粉刺和白头粉刺）及炎症性皮损，后者包括丘疹、脓疱或结节（亦称囊肿） 。

黑头，白头，丘疹，脓包，囊肿结节，大家没必要觉得恶心之类的，如果你都觉得恶心，那么身边的朋友怎么看长痘痘的你呢？ 5张图是一个理想状态，实际上每个痤疮患者，都可能长好几类。去看医生，分级治疗。

3.痘痘的分级

其实痤疮分级只是一种参考，比如：Pillsbury的4级分级法/Cunliffe的12级分级法。目前国内外最长采用的是前者，根据皮损性质将痤疮分为3度和4级。痤疮分级是痤疮治疗及疗效评价的重要依据。无论是按照皮损数目进行分级的国际改良分类法，还是按照强调皮损性质的痤疮分级法对痤疮进行分级，其治疗方案选择基本上是相同的。为临床使用简单方便，主要依据皮损性质将痤疮分为3度和4级：轻度（I级）：仅有粉刺；中度（Ⅱ级）：炎性丘疹；中度（Ⅲ级）：脓疱；重度(IV级）：结节、囊肿。 

但是通常门诊3-5分钟/每人，基本不会有医生会花时间去数你脸上有多少痘痘，不论是黑头/粉刺/丘疹/囊肿等它们产生的本质都是一样的：毛囊皮脂腺导管角化异常，判断痘痘类型更多的是靠经验。

寻常痤疮和内分泌基本没有关系，和你有没有性生活/自慰也没有关系，相信我，绝大多数人检查激素6项基本都是正常，包括我的家长和一些医生都曾经对我说过“结婚后痘痘（痤疮）就会好的”。有了性生活痘痘就会好的，事实上并非如此：据文献报告，大约85%的12～24岁的年轻人患有痤疮而且12%女性和3%男性会持续到44岁。意味着，等你的孩子到了长痘的年纪，你还在长痘。自己学习这么多痤疮知识，也许改变不了父母的认识，但是一定会对自己的孩子可能会遇到的痤疮问题有所帮助，不想让他们重走上自己的曾经的曲折之路。我们考虑要检查内分泌有以下情况：和月经周期相关，多毛，面颊1/3以下，下颌脖处等位置处痤疮可能和雄性激素过高有关，有条件是可以检查一下。


很多女生在我微博咨询，为什么月经前痘痘会加重，周期反复，真的有姨妈痘之说吗？那么，到底是什么原因会导致月经前痘痘加重？查询资料和文献，总结出如下可能原因，希望能对症下药，不再受月经困扰： 1.有研究发现月经前皮肤表面的脂质构成与其他期皮肤存在明显差别，毛囊皮脂腺导管在月经周期的第15～20日(月经前)最小，皮脂分泌易受阻，从而导致月经前痘痘加重； 2.在月经周期形成过程中，雌二醇与孕酮呈周期性变化，在经期前激素水平会降到最低水平，所以此时雄激素的含量或雄激素与雌激素的比例相对较高，导致皮脂腺活性会相应增强，因此容易造成青春痘的加重。 3.经期综合征，医学上我们称作PMS。比如：乳房胀痛，烦躁，失眠，焦虑之类。这些谈不上大病，大部分无需治疗，我在微博不止一次说过，情绪对一个人影响很大。有学者研究认为，当人们受到来自各方的精神压力时，抑郁、焦虑等情绪变化都将通过“大脑皮层-边缘系统”的情感环路，发放神经冲动到下丘脑-脑垂体-性腺轴或肾上腺轴, 使雄激素增加。所以与其你每天对着镜子唉声叹气，不如多出去走走，心情好，皮肤才能好。

4.自身过敏性孕酮皮炎，女生月经前都会长姨妈痘，但是此痘一定是痤疮么？答案是否定的。可能患有menstrual eruption（月经疹，又名自身过敏性孕酮皮炎）了。是一种与月经周期密切有关发疹性皮肤病。一般在月经来潮前2～3天发疹，持续到月经后的1～2天消退，周期性发生。其四肢、躯干局部或多处出现红斑、丘疹风团、水疱、大疱、糜烂渗液，自觉瘙痒，随着月经的结束皮疹自然减退和消失。一般认为与月经来潮前，卵巢分泌的孕酮骤增而引起的变态反应有关。一般通过饮食和运动可以调节，可逐渐恢复，太严重可以看医生。 5.多囊卵巢综合征：我微博提到过很多次PCOS，美国内分泌学会（ The Endocrine Society）2013 年颁布了 PCOS 的诊疗指南（以下简称指南），沿用 2003 年鹿特丹诊断标准，即符合以下 3 条中的 2 条，并排除其他疾病导致的类似临床表现，即可诊断 PCOS：（1）雄激素过多的临床和（或）生化表现，如多毛、痤疮、雄激素性脱发、血清总睾酮或游离睾酮升高；（2）稀发排卵或无排卵；（3）卵巢多囊样改变，即单侧卵巢体积增大超过 10 ml（排除囊肿及优势卵泡）或单侧卵巢内有超过 12 个的直径 2～9 mm 卵泡。其中治疗方法之一：短效口服避孕药：适用于典型的青春期多囊卵巢综合征患者如同时合并高雄、多毛、痤疮、月经过多或者延长。常用的药物炔雌醇环丙孕酮片，从月经第一天，每天一粒，连续 21 天。PCOS确诊还要检测激素六项，妇科超声，血糖等。 该如何治疗呢？

对于1.2.3项导致的月经痘痘，大都与雄性激素促进皮脂分泌导致，为此，我们在月经前就有做好皮肤清洁，保持水油平衡，避免高糖高脂高蛋白的的食物，放松心情，愉快的度过月经期，同时在月经前使用一些含有水杨酸和果酸角质溶解的产品，具有抗炎作用的甘草提取物，多种锌制剂等，还可以使用一些控油和抑制油脂分泌的产品，比如维生素a衍生物，维生素b族及烟酰胺等产品。针对4.5，如果加重，一定要及时就医治疗。 

所以不要问我的痘痘使用什么类型，如果你来找我，我应该会摸你一脸，用手摸和按你脸上痘痘病灶的深度/硬度。病灶深，硬度大的痘痘治疗时间肯定会相应更长，会影响医生给药，一位体重60kg患有重度痤疮的男生如果口服异维A酸/泰尔丝治疗，如果要达到60mg/kg累积量，每天2粒（20mg）大概需要连续口服180天。

综上，知道自己的痘痘产生的原因，类型，和等级分型，那么就阐述4好精神吧！

一，好好用药吃药

♥对于1-2级痤疮：简单说，脸上有 仅有粉刺为主和小丘疹  

一般我们采用局部治疗。首选外用维A酸类药物，必要时可加用过氧化苯甲酰或水杨酸等以提高疗效。而且还可以联合果酸换肤，推荐患者使用果酸换肤治疗以粉刺、炎性丘疹为主的痤疮，一般2～4周1次，4次为1个疗程。

这里谈谈果酸换肤：

果酸换肤对炎性皮损和非炎性皮损均有效。果酸治疗后局部可出现淡红斑、白霜、肿胀、刺痛、烧灼感等，均可在3～5d内恢复，如出现炎症后色素沉着则需3～6个月恢复。治疗间期注意防晒。

正规标准的果酸治疗，不会让皮肤越变越薄。目前中国医院使用比较多的果酸：和瑞士合作的百植萃果酸，中国的薇诺娜果酸，美国的芯丝翠果酸，芯丝翠使用最广。薇诺娜果酸换肤价格在460元左右一次，芯丝翠果酸换肤价格在700-800元左右一次。果酸最适合的痤疮类型是粉刺。其次是痤疮遗留的红色痘印和色斑，尤其对黑色痘印和毛孔粗大非常好。一般4次一个疗程。使用果酸换肤也是有爆痘风险的，选对时机很重要，爆痘后可以在医生指导下口服多西环素或者米诺环素，外涂夫西地酸乳膏，配合红蓝光。不过现在果酸换肤，是医院很常规的项目了，比较经济的解决顽固粉刺闭口，痘印，毛孔粗大的手段之一，选择果酸换肤时，一定仔细咨询医生，不是人人适合。

一般治疗痘痘的药膏有：维A酸和班赛，这两种药膏基本就能解决很多痘痘了。

各种各样的淘宝月售10万+爆款祛痘药膏或者他人推荐的三无祛痘膏其实很不安全，“杀鸡膏”2016年也是网红祛痘膏，但是添加大量的激素和抗生素，祸害一批少男少女。如果只能推荐两类祛痘产品，我只推荐：维A酸类（全反式维A酸乳膏/国产阿达帕林/进口达芙文）和BPO（国产过氧化苯甲酰凝胶/进口班赛）。

对于维A酸：中国痤疮指南、国际痤疮指南及美国痤疮指南均将外用维A酸作为轻度粉刺型痤疮的单独一线用药、丘疹脓疱型中度痤疮的首选联合用药以及痤疮维持治疗的首选用药。国际指南指出：外用维A酸理论上适用于所有痤疮患者，特别是对于轻中度痤疮。而且FDA目前批准外用维A酸用于 ≥ 12岁青少年，同时FDA批准达芙文（0.1%）为非处方药用于治疗痤疮。

对于BPO:由于不存在痤疮丙酸杆菌耐药性被所有指南推荐为外用抗微生物药物首选，也可以单独使用或者联合外用维A酸或外用抗生素。特别强调BPO与全反式维A酸叠加使用会使其失活，要分时间段使用，和阿达帕林/达芙文叠加则可以正常使用。

很多人也会问我班赛刺激性比较大，夫西地酸乳膏耐受性好，但是容易耐药。到底能用多长时间？国际痤疮指南强调了外用不应超过3 ~ 4个月，即使无法避免停药也要联合BPO继续使用，比如单日班赛，双日夫西。

看到这里你还要去买各种网红祛痘膏：狮王祛痘，白兔暗疮膏，茶树精油祛痘膏吗……？ 



具有调节表皮角质形成细胞分化、改善毛囊皮脂腺导管角化、溶解微粉刺和粉刺及抗炎的作用，还具有控制痤疮炎症后色素沉着和改善痤疮瘢痕等功效,和抗炎抗菌药物联合使用可 以增加相关药物的皮肤渗透性。外用维A酸类药物是轻度痤疮的单独一线用药，中度痤疮的联合用药以及痤疮维持治疗的首选药物。目前常用的外用维A酸类药物包括第一代维A酸类药物如0.025％～0.1％全反式维A酸霜或凝胶和异维A酸凝胶，第三代维A酸类药物如0.1％阿达帕林凝胶。阿达帕林在耐受性和安全性上优于全反式维A酸和异维A酸，对非炎症性皮损疗效优于全反式维A酸，可以作为外用维A酸类药物治疗痤疮的一线选择药物。外用维A酸类药物常会出现轻度皮肤刺激反应，如局部红斑、脱屑，出现紧绷和烧灼感,但随着使用时间延长可逐渐消失。建议低浓度或小范围使用，每晚1次，避光。  

班赛：  



为过氧化物，外用后可缓慢释放出新生态氧和苯甲酸，具有杀灭痤疮丙酸杆菌、溶解粉刺及收敛的作用。可配制成2.5％、5％和10％不同浓度的洗剂、乳剂或凝胶，少数敏感皮肤会出现轻度刺激反应，建议敏感性皮肤从低浓度及小范围开始试用。过氧化苯甲酰可以减少痤疮丙酸杆菌耐药的发生,如患者能耐受，可作为炎性痤疮的首选外用抗菌药物之一，本药可以单独使用，也可联合外用维A酸类药物或外用抗生素。

大学时曾用过一次国产班赛，使用感至今难忘。

班赛属于刺激性较大的药物，我大学时候第一次用时，就开始全脸使用，晚上直接疼的眼泪一直流，直接脱了一层皮⋯⋯目前比较靠谱的用法：“只能取少量在指尖，揉成薄薄一层，点在痘痘的部位，不能涂抹。”多不一定更好，要点涂使用，后期耐受会好很多！



其实，使用维a酸，班赛，夫西地酸乳膏等一系列药膏治疗痤疮时，也会有初期的爆痘现象，这是正常的免疫反应，毕竟痘痘里面的炎症性物质需要排出，不可能凭空消失，不能因为初期的皮肤恶化而停药，如果后期过度敏感或者恶化爆痘，停用并在医生指导下口服抗生素/激素/光疗等，外用医学修复皮肤屏障产品。  

♥♥对于2-3级痤疮：简单说，脸上以丘疹脓包为主

口服抗生素如大环内酯类、四环素或多西环素、米诺环素，要保证足够的疗程，通常连续使用6周-8周，并配合果酸、红蓝光、光子（IPL）外用药膏。  并配合外用维A酸类药物、过氧化苯甲酰或其他抗菌药物 ， 对有适应证并有避孕要求的女性患者可选择抗雄激素药物治疗,个别女性患者可考虑口服抗雄激素药物联合抗生素治疗

其中系统使用抗生素是基础治疗的方法之一,要保证足够的疗程。对于抗生素，我们优 选四环素类如多西环素、米诺环素等，不能使用时可考虑选择大环内酯类如红霉素、阿奇霉素、克拉霉素等。其四环素口服吸收差，耐药性高，而新一代四环素类药物如米诺环素、多西环素和赖甲四环素应优先选择 。 

使用抗生素治疗痤疮应规范用药的剂量和疗程。通常米诺环素和多西环素的剂量为100～200mg/d(通常100mg/d)，可以1次或2次口服；四环素1.0 g/d,分2次空腹口服;红霉素1.0g/d，分2次口服。疗程6～8周。　　

海豚君这里提醒下，如果医生开的是100mg规格的多西或者米诺那就晚上吃，防止光敏。 




医生在给痤疮患者开抗生素时，常会开多西环素肠溶胶囊/多西环素分散片/多西环素片，药效基本区别不大，简单说下：

1.多西环素片和多西环素分散片，都可以直接口服使用，多西环素分散片还可以加水分散后口服，毕竟一些老年患者吞咽药片可能困难，对胃刺激性比较大，有恶心、呕吐等不良反应，另外吃药后短时间内不要直接躺下睡觉。我以前治疗痤疮时对多西环素片反应还是蛮大的，眩晕加恶心。

2.多西环素肠溶胶囊，肠溶胶囊在胃内停留几个小时不崩解，需到十二指肠或空肠后再崩解释放。由于多西环素片对胃黏膜刺激性较大，易引起恶心、呕吐，制成肠溶片或肠溶胶囊服用，可防止此类现象发生。另外胶囊药粉倒出来服用，这种做法对于有些药物是不科学的。

医生也会开些抗雄性激素的药物比如：

A口服短效避孕药

口服避孕药治疗痤疮的作用机制：雌、孕激素可以对抗雄激素的作用，还可以直接作用在毛囊皮脂腺，减少皮脂的分泌和抑制粉刺的形成。目前常用的避孕药包括达英—35



 在月经周期的第1天开始每天服用1片，连用21d，停药7d，再次月经后重复用药21d。
口服避孕药的起效时间需要2～3个月，通常疗程＞6个月，一般要求皮损完全控制后再巩固1~2个月再停药，停药过早会增加复发的概率。口服避孕药绝对禁忌证包括妊娠、静脉血栓或心脏病病史、年龄＞35岁且吸烟者。相对禁忌证包括高血压、糖尿病、偏头痛、哺乳期妇女、乳腺癌及肝癌患者。

B螺内酯



作用机制:竞争性地抑制二氢睾酮与皮肤靶器官的受体结合，从而抑制皮脂腺的功能；抑制5α还原酶，减少睾酮向二氢睾酮转化。推荐剂量每日1～2mg/kg，疗程为3～6个月。不良反应有月经不调(发生概率与剂量呈正相关）、恶心、嗜睡、疲劳、头昏、头痛和高钾血症。孕妇禁用。男性患者使用后可能出现乳房发育、乳房胀痛等症状，故不推荐使用。　　

西咪替丁/丹参酮胶囊

西咪替丁治疗座疮一般是有多种药物配合使用的，也具有抗雄性激素的作用




丹参酮有较温和的雌激素活性，产生类似于雌激素的效应，具有抗雄性激素的作用，但是它不是性激素，男生没必要担心。豆浆也含有类雌激素大豆异黄酮，具有双向调节的作用。只是，豆浆中的钙含量和牛奶比少的可怜！少林的和尚整天吃豆腐，也没见哪个胸变大了 

西咪替丁和丹参酮胶囊男女都能用的，避孕药和螺内酯是女生服用的，不过也有医生给男生开螺内酯，问清楚情况就好了。







痘痘多/身材胖/月经少/体毛重，月经前痘痘明显加重的女性痤疮患者，可以去妇科检查是否患有#多囊卵巢综合症#。方法：

1.B超。腹部B超漏检大，未婚女性可以行肛门B超，已婚女性可以行阴道B超。

2.激素6项。通过测量DHEAS和睾酮水平可以明确PCOS诊断。此外，LH和FSH比值也可帮助诊断。

如果确诊多囊，需要口服短效避孕药，达英-35或者优思明，月经来潮第一天开始服用，连服21天停药，中间不能断，要定小闹钟提醒自己，一般口服3-6个月，具体方法医生会指导你。

其实对中重度女性痘痘患者来说，口服短效避孕药（达英-35/优思明）也是一种效果非常好治疗方法。女生不一定患有#多囊卵巢综合症#才吃优思明，优思明治疗痤疮的临床实验已经完成，不久以后优思明的说明书中的适应症中会增加用于治疗痤疮这一项。

只有医生知道，有些不孕症，须通过先吃避孕药治疗后，才能怀孕。多囊卵巢综合征（PCOS）通常会导致女性痤疮，而女性痤疮不一定是由多囊卵巢综合征导致。由多囊卵巢综合征导致的女性痤疮必须由通过服用短效口服避孕药来治疗，而服用短效口服避孕药治疗女性痤疮，女性不一定要患有多囊卵巢综合征。

♥♥♥3-4级痤疮：简单说，脸部囊肿很多。 


口服异维A酸是一线治疗方法。对炎性丘疹和脓疱较多者，也可先采用系统应用抗生素和外用过氧化苯甲酰联合治疗，待炎症改善后改用口服异维A酸治疗，目前无循证医学证据支持口服异维A 酸联合抗生素治疗。并依据炎症的轻重配合果酸、红蓝光、光子（IPL）外用药膏等治疗。

想到前段时间，一位男生咨询两位老师说：“口服维胺酯胶囊两个月后，发现妻子怀孕该怎么办？”。女老师则认为：维胺酯胶囊在体内的代谢途径尤其是在脂肪细胞，没有异维a酸那么清晰彻底，对精子的影响不好说，还得有待观察，异维a酸对精子没有影响。男老师则认为：如果有影响的话，那么直接会导致精子不育，但是如果怀上的话，那就不必担心，致畸是相对于孕妇和胎儿而言。两位老师和国内外指南都强调，不论维胺酯胶囊还是异维a酸，都不会对男生或女生的生育能力产生影响。后来我查了维胺脂胶囊和异维a酸胶囊（泰尔丝）的说明书后才恍然大悟。

可见自己服用异维A酸，还是有一定的风险的，所以用药一定要遵医嘱。

现在FDA和NIH对于异维A酸的停药后避孕期限，已缩短为1个月。但是国内说明书还是建议停药后应避孕3个月，但是我个人还是停药半年（6个月）左右才考虑怀孕的这件事！！！

那么到底该怎么吃，在够量呢？

海豚君，帮你计算了下，治疗痤疮的过程中，一个要及时复诊，口服药物一定要在医生指导下使用，体重60kg的男生，异维 a 酸口服计算：按照国内标准60mg每公斤体重计算，需要60×60，3600mg，泰尔丝每盒200mg，折算需要吃18盒。国内痤疮治疗指南为降低不量反应建议不超过每公斤0.5mg每日，也就是说每日最多3粒，一般2粒就够了，饭中吃，其他体重的可自己计算。简言之，18盒，每天3粒（2粒）。这些都是理想化的数据，但是后期具体用量调整还是要你的主治医生根据你的皮肤情况指导，切记不要独自服用，新浪爱问医生也有很好的医生，花少钱咨询他们也是蛮方便的。

害怕副作用的，服用泰尔丝期间每间隔一个月就要对血常规、肝功、血脂进行一次检测。一旦发生异常，要及时进行复查。如果复查之后，没有经过治疗很快就恢复常态，就没有什么问题。如果不能够自行恢复，就需要吃点降血脂的药或保肝的药，基本上也就能调回正常的数值了。肝功能的检测花费还是很少的。

对于重度痤疮，还可以考虑光动力，

介绍下光动力吧







#泰尔丝#没吃够6个月，#光动力#没做3次以上不能说祛痘用尽洪荒之力。光动力是目前的祛痘核武器。尤其适合中、重度囊肿聚合性痤疮患者。对于口服药效果不佳、副反应太大不能耐受、内脏疾病或有近期生育需求等原因不能口服异维A酸胶囊的患者，都可以用光动力治疗。用光敏剂（5-氨基酮戊酸，ALA）外涂于面部痘痘处，湿敷封包1~3小时后照射红光消除痘痘的疗法。原理是：皮肤中的毛囊皮脂腺吸收光敏剂后，经过光照激发产生单态氧和氧自由基，在皮肤内杀灭细菌、消除炎症、调节局部免疫，起到消除痤疮结节脓包的作用。

--------------------------------------------------------------------------------------------------------------------------

二，好好吃饭 

啊，对不起翔哥。以前有个很火的段子：“所有的美容护肤贴里都告诉你，要想毛孔不粗大不出油不长痘痘，就早睡早起不要熬夜多吃蔬菜少吃炸物，一定要多运动。想问下说这话的人，你们见过刘翔的脸吗？”。


不过刘翔后来经过治疗，特别帅气，看起来特别自信，笔芯！



单靠饮食来改变痘痘，其实还是很难的，只能说有辅佐作用：



1.富含OMEGA-3的食物

OMEGA-3是人体不能合成的，必须从食物中摄取脂肪酸，对皮肤来说，它可以减轻炎症，促进皮肤屏障功能

中国人饮食结构中缺乏OMEGA-3，亚麻籽油，紫苏油，芝麻油，海鱼油等含量丰富，但是植物油在体内转化率低，选择海鱼油比较方便，注意海鱼油选择低汞的，鲨鱼，剑鱼，鲑鱼等因为“富集”作用，汞含量还是比较高的，鲨鱼处于食物链的高位，所以鱼翅不要吃，也不该吃。

2.富含胡萝卜素和维生素B的食物。

胡萝卜素在体内会转化成维生素 A ，可以维持皮肤角质细胞正常代谢，减少皮脂分泌。

多吃：柑橘，橙子，胡萝卜，西红柿等含胡萝卜素的食物。维生素A和维生素B不同，VA属于脂溶性的过量补充会蓄积中毒，VB属于水溶性的补充快消耗也快，一般不必太担心补充的副作用，所以一般不建议吃VA片。

一般黄颜色的食物富含胡萝卜素比较多，大学食堂的西红柿炒鸡蛋可以多吃点。

3.含锌的食物

锌能够调节，皮肤黏膜感觉，分泌，排泄，抗体产生，当缺乏锌或者含量不足时，皮肤皮脂溢出增多，容易长痘。很多医生也会患者开甘草锌颗粒，葡萄糖酸锌片治疗痘痘，也是有道理的，所以可以多吃海鲜，含锌较多的动物内脏，海带，干果类，牡蛎的含量算是比较高的一种。没有啥发物之说，如果你对海鲜过敏，就不吃，我是不喜欢吃海鲜的，味道怪怪的。

4.绿茶

绿茶中的茶多酚可以对抗DHT，可以抑制雄性激素对皮脂腺的作用，睡眠质量不好的，谨慎喝。

5.豆浆等豆类

豆腐豆浆也含有植物雌激素大豆异黄酮，可以对激素水平双向调节，注意无糖最好，以前我们大学食堂每天都会现磨的还是很便宜的1块钱1杯，每天都是排队等豆浆。可以把亚麻籽油直接倒进豆浆里，混合吃，也是比较不错的选择，因为亚麻籽油，其中的木脂素可以抑制DHT，减少皮脂分泌，内含亚麻酸也能平衡炎症，可以10-15g加入饮食。

6.抗氧化食物

BBC有部纪录片《The Truth About Look》，要想皮肤好一点就是多吃西红柿，西兰花和油性鱼。西兰花，富含硒的食物（蘑菇，全麦面包，三文鱼）等具有比较强的抗氧化作用，可以减少皮肤炎症，利于皮肤修复。

【打字很累，记得点赞】

参考资料：维生素矿物质补充剂在几种常见皮肤病防治中的临床应用：专家共识



其实吧，饮食和痘痘的关系，一直都有争议，反正甜食少吃，是对的，微博很多咨询我的爱长痘的女生，我发现很多都有吃冰淇淋/奶油蛋糕/甜品的习惯，而且是狂吃，关注我最多的是广东娃，是不是广东人吃甜食很多？

我自己对牛奶比较有体会，高三那一年我妈买了各式各样的牛奶，喝的我痘痘猛长。牛奶每天不要超过400ml，可以喝酸奶但是要无糖的。

--------------------------------------------------------------------------------------------------------------------------

三，好好防晒

为什么夏天会痘痘频繁复发和爆痘？





因为，体温每变化1度,皮脂的分泌率可以变化10%,日晒,可促使皮脂的分泌增多,同时,高温下表皮因吸水而膨胀,毛囊皮脂腺导管会反应性回缩,毛囊漏斗部开口缩小,引起毛囊内脂质分泌不畅,发生堵塞,加重粉刺的形成。因而,避免日晒是减少及预防痤疮发生的重要因素。

海豚君想说，真正喜欢你的不会在乎你脸上的痘痘，身边很多女生满脸痘痘，依然有帅气的男朋友呢？痤疮还是很好治疗的，多学习微博，加油吧！

不论是外用维A酸，还是口服多西环素，米诺环素，泰尔丝，因为药物具有光敏性，都有可能造成皮肤色素沉着的风险，一般停药几个月后都会消失。所以建议口服泰尔丝2-3个月后再激光治疗痘印痘坑，而达芙文不需要，药物洗掉就能做。同时红斑型玫瑰痤疮，不建议红蓝光，红蓝光能量对血管是一种刺激因素，紫外线也会加重痤疮和玫瑰痤疮。

对于口服一些光敏药物，建议白天防晒或者避免强紫外线，或者晚上才口服外用，所以不管是长痘期间还是红色痘印消退期间，所以如果想尽快赶走他们，不管天气如何，都要涂SPF30同时PA+++以上的防晒。同是要注意选择轻薄不堵塞毛孔的产品，否则痘痘有可能又来了。

有太多的防晒可以去选择，关于防晒，你们应该比我懂的都多，防晒呢适合自己的最好。你如果实在不喜欢防晒也可以选择硬防。

世界卫生组织WHO提倡的防晒ABC原则：不被晒到，是最好的防晒；首选硬防晒；没有哪一种防晒霜能与硬防晒相比。；在必要时涂防晒霜。 A：Avoid，避免晒。 B：Block，遮挡，防止被晒到。 C: Cream，防晒霜。 在A、B不能满足防晒需求的时候，采用C补足。




防晒怎么涂？

把防晒霜挤在手上，在手心里揉匀，轻轻拍在脸上，既均匀又不堵塞毛孔，而不是用手指在脸上把防晒揉开，像刷墙一样。

中午防晒要不要卸妆？






好多人问午休需不需要卸防晒？如果下午不出门，不需要直接触阳光，我会卸防晒；如果下午要出门，就不卸防晒了，睡醒会补涂！大部分防晒都不需要卸妆，洁面就能洗干净，我也是越来越懒了！

怎么硬防？戴着口罩或者打伞。

UV100的防晒口罩（29元/1个），也是微博上好评颇多的防晒口罩，用防晒容易致痘的可以考虑，这个是比较轻薄的。缺点显而易见：眼睛以及上部位，容易晒黑。平时不涂防晒的话，我会选择戴口罩，另外还会加一个帽子或者防晒伞。







618防晒到了一部分，前几天再朋友圈晒过。


谈谈防晒#闷痘#：
1.防水性极高的防晒，为了有高防水性，不被水溶解和冲释，需要选择不被水溶解的油性基质，会让皮肤感到“油腻”，同时较高的封闭性，会让皮肤“闷，拔干”，拔干会让皮肤表面张力发生改变，并不是一件好事，皮肤分泌油脂很难正常从毛孔排出，更容易致粉刺，也很难清洗。

2.化学防晒的原理：将紫外线转化为热量，这个热量导致汗腺分泌增加，同时也会皮脂腺分泌更多的油脂，前者容易使皮肤“捂”出痱子，比如额头，后者会导致更多的粉刺，比如脸颊，这也可能是所谓的闷痘，同时防水型防晒热量更不容易释放，时常有涂防晒中暑的新闻。

3.还有可能是防晒某些成分对某些人导致接触性皮炎，光敏性皮炎，比如：二苯酮类，国内防晒较常用。





4.碧柔温和防晒乳液，挤出来浓稠，涂开水润，3分钟左右皮肤清爽，因为添加滑石粉吸油，把分泌的油吸出比把油闷在毛孔里，我更喜欢前者方式，油皮也能保持6个小时左右皮肤清爽。用了很长时间，没有出现所谓浮白，拔干现象，也不会像碧柔蓝管让皮肤瞬间暗沉，这款是比较适合油皮的，我使用没有感到任何不适感，刺激感，虽然只有两种防晒剂，但也是难得兼顾UVA和UVB的一款基础防晒，价格也很便宜，不需要卸妆，新版本还未尝试，流汗就补涂。

5.我没有那么伟大去为关注我的人去尝试各种护肤品，不现实也没必要，脸是我自己的，不是大家的试验田。很多博主基本都推荐高SPF或者PA的防晒，不能说不好，只是油和闷能吓跑一些想要防晒的人，防晒从基础做起，慢慢适应才对。皮肤科中，常说：增加患者依从性。吃泰尔丝，嘴发干会导致唇炎；使用a酸前期皮肤会发红脱皮短暂加重痘痘，如果我们提前和患者沟通好，告诉副作用，患者才会愿意听医生的话，才会去积极治疗。防晒也是这个道理，我们不是每天都生活在海边，防晒最初目的也不是预防光老化。

------------------------------------------------------------------------------------------------------------------------------ 

四，好好维稳

痤疮不能根治，它是一种慢性炎症疾病，需要我们引起重视，很多人治疗好了痤疮以为就不用管了，其实不是，大部分会复发，要维稳6-12月。痤疮可以很好的控制和缓解，注意饮食和生活习惯也可减少或避免复发，但并不能绝对根治，好在多数人随年龄自愈。尽管不能绝对根治，还是建议早期治疗，以避免留下永久性痘印和痘疤而影响美观。

综上所述，我们前期治疗+后期维稳，消除痘痘大概也需要1-2年时间，才基本能够保持自己的皮肤长时间不长痘，海豚君从2014年不长痘后，到现在也在坚持维稳，所以痘痘很少会找上门了。这就是会战痘，懂痘之人的成功之处。一些美容院和你签约几个月绝对能根治痘痘，看了我的文章你便会发现是是不靠谱的。治疗痤疮，需要的是耐心和时间及金钱，没有耐心和坚持的，那你还是早早放弃吧，男士美容吧有很多痘痘患者开贴记录自己战痘过程，99%的人都是3分钟热度，坚持不了几天就放弃了，我只能无奈摇摇头

痤疮可以很好的控制和缓解，注意饮食和生活习惯也可减少或避免复发，但并不能绝对根治，好在多数人随年龄自愈。尽管不能绝对根治，还是建议早期治疗，以避免留下永久性痘印和痘疤而影响美观。 

收到的反馈和大家分享下（5.13-7.13两个月的时间）：达芙文起效时间约2个月，痤疮是“慢性病”，接受正规治疗时，一定要有耐心，不要反复换药，即使脸上痘痘好了，达芙文也要再使用6-12月维稳，不然容易复发，关于祛痘印，一定要等脸上无痘，稳定几个月再考虑！孔凤春喷雾，10多元一瓶，保湿又不黏！





再分享一个案例：这位云南的小姑娘去年5月份找到我，我推荐她去找何黎面诊，经过一年的治疗（果酸换肤，药物治疗），皮肤也恢复了差不多了，剩下痘坑和痘印。所以长痤疮，一定看医生，在医生的指导下合理用药，随时复诊，复诊时医生会根据不同时间的皮肤状况，调整用药。痘痘好后，千万别忘了维稳！








维A酸乳膏一直是让我保持几年不长痘的产品，一直保持低剂量低频使用，真的战痘高手都是灵活使用它。脸厚之人可以直接使用，先低浓度后高浓度，比如我；脸薄之人，先乳液打底后使用，耐受后可以直接使用，也可以第一周和乳液1:4混合使用，第二周1:2混合使用；第三周1:1混合使用，第四周可以直接使用，时间也根据耐受程度因人而异。还有其他方法我微博都有介绍。

我在战痘时期，基本每天使用或者隔天使用，维稳时期改成每周3次，维稳后期保持每月3次，直至现在每个月1次，或者每几个月1次。比如我在吃火锅的前一天和当天都会使用，也不怕长痘的。使用期间严格防晒，备孕期间禁用。结婚以后！会选择更安全的产品。


维持治疗的意义：

由于痤疮的慢性过程和易复发的临床特点，因此无论哪一级痤疮，症状改善后的维持治疗都是很重要的。维持治疗可减轻和预防复发，提高患者的依从性，改善患者生活质量，是一种更为积极和主动的治疗选择，也被认为是痤疮系统和完整治疗的一部分。

方法:

循证医学证据表明，外用维A酸是痤疮维持治疗的一线首选药物。外用维A酸可以阻止微粉刺的形成，从而防止粉刺和炎性皮损的发生。目前还没有任何已知的药物在维持治疗的疗效和安全性方面优于外用维A酸。对有轻度炎性皮损需要抗菌药物治疗的，可考虑联合外用过氧化苯甲酰。一些经过临床功效验证的抗粉刺类医学护肤品也可用于辅助维持治疗。

疗程：

目前临床试验的疗程多为3～4个月，在预防复发和减轻症状方面取得了明显疗效，停止治疗后症状很快复发，提示更长时间的治疗是有益的，但目前无更长疗程治疗的循证医学资料。

--------------------------------------------------------------------------------------------------------------------------

关于痘坑

#痘坑#我曾经在微博写过，战痘成功至少需要3-6个月时间，后期还需要更长时间去修复痘坑。痘坑类型不同，采用光电治疗手段不同。治疗前后我们一般采用VISIA拍照分析并进行国际上常用ECCA痤疮瘢痕评分/填表，冰锥痘坑/滚筒痘坑/厢车痘坑权重分数不同，通过治疗前后来对比，告诉你帮你改善比如85%的痘坑。通常冰锥状痘坑是不建议使用C02点阵激光，因为坑位置比较深。滚筒状和厢车状采用C02点阵激光是还是比较好的，但也要进行很多次治疗，要想取得好的效果至少1-2万元是免不了的，海豚君想说，你觉得自己做3次点阵激光效果还不错，面部改善很大，自己也能心理上接受目前皮肤状态，也没必花太多钱去接下来治疗，也可以省一笔钱。比如图一：C02点阵激光一次治疗改善就很明显。

要想不那么轻易留坑，平时就要少挤痘痘，正规吃药，比如：多西环素它不仅是抗生素，还兼有抗炎效果，也可以预防真皮萎缩性痘坑！
编辑于 2017-10-15
蝎蝎
蝎蝎
“懂肌肤学养护~战痘开始！！！”
（图|网络）【已更，最新的放最前】

第一期“基础肌理”
第二期“吃饭睡觉灭痘印”
第三期“美白保湿”
第四期“控制大油田”
第五期“刷酸知多少”

——————————————————NO\5——————————————————

说说吧，刷酸到底是什么，我们的皮肤为什么要刷酸，我们应该注意些什么~

随着年龄增加，皮肤新陈代谢减缓，老化角质层未能及时脱落会造成角质堆积，皮肤变得粗糙并产生皱纹。果酸能将老化角质层剥落，加快皮肤新陈代谢，同时也把一些黑斑及青春痘的色素沉淀一并去除。低浓度果酸用作保养，高浓度果酸可作换肤。但是会有皮肤不适应及发生副作用的可能，由医生来指导使用会比较安全。

【果酸，来自水果的有机酸】

果酸，简称AHA，顾名思义，是从水果或酸奶中提取的各种有机酸。包含葡萄酸、苹果酸、柑橘酸及乳酸等。在医学美容界中最常被应用到的成份为甘醇酸及乳酸。

甘醇酸：又称为甘蔗酸，具有果酸中最小的分子量，因此最容易渗透皮肤的表层，吸收的效果也最明显，是最常被用在换肤使用的果酸。

乳酸：具有果酸中的第二小的分子量，因为保湿度强、天然成份不会刺激人体皮肤，所以广泛被用在改善肌肤干燥及角化现象。

果酸的细小分子有着超强的渗透力，对于皮肤的作用是非常明显的。

对表皮的疏通更新作用：

1、减少角质细胞间的桥粒连接（聚合力），促使老化角质层脱落。

2、增进表皮新陈代谢速度，促进肌肤更新，淡化痘印与色素沉着。

3、让毛孔导管口角化栓易于脱落，有效防止毛孔阻塞和痘痘生成。

4、促使表皮层细胞结构正常排列，角质层变得光滑。

对真皮的保湿补水作用：

刺激玻尿酸、黏多醣、胶原蛋白及弹力纤维的增生及重新排列，使皮肤的含水量增加，皮肤变得紧实有弹性，细纹和皱纹也会减少。

但是不同浓度，果酸的作用是不一样的：

1、低浓度果酸（小于10%）：去除老化角质，改善粗糙、暗沉、调理肤质。

2、中浓度果酸（10%－30%）：到达真皮组织，对于青春痘、淡化黑斑、抚平皱纹的效果良好。

3、高浓度果酸（大于30%）：具有相当强的渗透力，可将老化角质一次剥落，属换肤性质，最好寻求专业的医生进行治疗。

很多人对“果酸换肤”有兴趣，这里就简单讲讲它的流程：

把患部用特殊清洁剂洗净后，医生将高浓度的甘醇酸 （20%-70%）由额头、鼻子、脸颊、下巴的顺序涂抹，数分钟后喷上中和液，终止甘醇酸的作用，之后再用冰敷以减轻疼痛及发红，接着涂上营养霜即可。

这是医学美容上比较严谨规范的果酸换肤步骤，平时使用含果酸的护肤品也一定要注意，一旦出现灼伤过敏肿胀等不良反应，应马上寻求帮助。即使果酸有再好的效果，使用时一定要慎重！

测试敏感的反应

购买果酸产品不要心急，不妨先将产品小范围涂擦，待5-10分钟后，看看皮肤有无过敏反应。如发现皮肤又红又痛，或有不能忍受的灼痛感，应放弃购买。

小心涂擦免敏感

为使果酸产品发挥出最大功效，不妨选择含果酸的洗面奶，可在洗面的同时去除死皮，也可配合果酸润肤霜，让果酸更均匀地停留在皮肤上。最好妨循环使用，用一个月停两周，给肌肤充分的休息机会就比较安全。此外，不要让产品触及眼部周围及颈部肌肤，因为这些部位的肌肤较幼嫩。

勿轻视防晒工夫

虽然果酸不像a酸有光敏感性，早晚都可以使用，但是使用后不擦防晒乳，反而容易晒黑晒伤。因此在使用含果酸成分的护肤品或接受果酸化学换肤时，一定要充分做好防晒工作，即便是阴天也要涂擦防晒用品，因为紫外线同样能穿过云层，需使用可同时抵抗UVA和UVB的产品。防晒产品要在出门前半小时便均匀涂抹在肌肤裸露处，尤其是额头，颧骨、鼻梁和上唇等为部位，因为这些部位最易晒伤。如果所在环境比较潮湿，建议挑选防水系列，并且定时补擦，方能有效抵抗紫外线。

（UVA是生活紫外线，可透过窗户玻璃和云层射入人的肌肤；UVB是户外紫外线，人们在室外活动时直接射入皮肤。没有被臭氧层吸收掉的UVA和UVB会照射到地球表面，给我们的肌肤带来伤害。防晒产品中SPF就是防UVB的时间强度，PA就是防UVA的指数）

不要反复去角质

果酸本身可以去除角质，不需要再使用去角质的产品，也不要蒸脸，不要过度按摩，以免皮肤受伤。洗脸动作尽量轻柔，避免刺激到皮肤。高浓度的果酸与a酸、维他命c都属于PH酸碱值较低的产品，不建议同时使用。

增加护肤的措施

使用果酸时，角质层较薄，对一些外来刺激较敏感，如日晒、风吹及一些含酒精、去角质成份的化妆保养品等，可增加一些保护措施，如使用滋润保湿剂、修复药膏。

——————————————————NO\4——————————————————

秋季到，大油田的童鞋是不是特别想在叶落时喊一句，“TMD好歹出花生油还能循环利用一下！”很多人以为进入秋季，大油田就会歇息一段时间，可现实根本不是这样的。“控油尚未完成，童鞋仍需努力！”

【控油尚未完成...】

为什么秋季脸上的油还是不停地流啊流啊？

在秋天，气温舒适后，我们不经常出汗就会很容易忽略给身体补充水分，加上秋风促使脸部皮肤的水分蒸发，于是脸部皮肤变得异常干燥。

那干燥跟油有什么关系？我们的肌肤本身有着一定的调控“水油平衡”的功能，当水油不平衡时，皮脂腺就不得不分泌出更多的皮脂来保护皮肤，防止更多的水份流失。所以在秋季，出现这样的症状就是在提醒我们，身体缺水啦！

虽然控油指的是调整皮肤分泌的油脂含量，但是仅从字面上理解，只进行控油的话，油是无法得到很好地控制的。只有达到水油平衡的状态才能有效控油。所以，控油补水是相辅相成。甚至有时候，控油只是一个幌子，实际上是补水的化身，如果你们还没觉悟过来，大油田会继续在脸上肆意妄为地长痘痘！

【童鞋仍需努力！】

从反面讲讲控油误区——————

误区一：频繁洗脸去油光

很多人以为通过增加洗脸的次数可以改善油光现象，结果却是越洗越油。这是因为我们的肌肤本身有着一定调控“水油平衡”的功能，当肌肤过度清洁，大量的油脂被清洗掉之后，皮脂腺就会收分泌出更多的油脂来补充流失的油脂，导致越洗越油的尴尬状态。

误区二：把吸油纸当法宝

一出油就用吸油面纸“猛”擦，恰巧手边没有吸油纸，干脆用普通纸巾替代，油光暂时是消除了，但也损害了肌肤。

误区三：过分依赖收缩水

长期使用强效收缩水，毛孔变小确实是能够帮助肌肤的控油，减少油分的分泌。但是毛孔长期处理收缩的状态很容易会导致毛孔的堵塞，时间长了就会积聚大量的细菌和毒素，从而产生出痘痘和黑头。

误区四：避开含油保养品

这个错误特别是油性肌肤的童鞋会饭，因为他们会担心肌肤本来出油严重，再涂保湿乳液或保湿霜的话会更厉害，所以洁面后觉得上化妆水就行了。其实，这是不对的。如果我们用完化妆水之后不涂上保湿乳液或者保湿霜（薄薄的也好啊）帮助把水分锁住，那么肌肤就会再次陷入“水油不平衡”的状况。

误区五：不停用保湿喷雾

不要被保湿喷雾的“保湿”所误导，很多保湿喷雾中并不含有锁水保湿成分。在脸上不断地使用保湿喷雾，虽能能感受到皮肤短暂性的清凉和湿润，但当水分蒸发时反而会带走肌肤表面水分使肌肤更加干燥。可以在皮肤感觉特别干燥时使用，或者在使用前检查成分是否有锁水保湿作用。

最误区：只控油不补水！

有80%的油性肌肤都有缺水现象，这种旺盛的油脂量会掩盖肌肤缺水的事实。如果你只控油不补充水分，身体内的平衡系统就会自然启动，不断分泌更多的油脂以补充大量流失的油脂，形成“越控越油”的恶性循环。

【那要怎么破啊？】

第一：清洁油污

每日需进行皮肤清洁，可选用温水和适合自己的洗面奶洁肤。

第二：补水紧肤　　

清洁皮肤后，接下来就要使用爽肤水（又称化妆水）等进行补水紧肤。

第三：保湿锁水

补水之后一定要保湿，否则无法锁住水分。

△补水保湿：补充失去的水分和油脂。

看出来了吗，控油怎么破的解决步骤其实就是补水的一般步骤。水油不平衡导致的油多是油田的根源，所以控油是要控制水油平衡。很多人只看到了“水油失衡”的多油，却没看出，“多油”先生背后的“女人”是“缺水”小姐。两者相辅相成，小蝎子这么讲你们懂了吗？别再拆散“多油”先生和“缺水”小姐，别再只说“控油”，还有“补水”啊！

—————————————————NO\3——————————————————

第二期主要有3部分：

one [痘印痘坑大起底]
番外 [“顺溜”和“麦当当”]
two [消消印填填坑哟]

咳咳咳咳咳咳咳咳咳咳~~~~~
今天的话题涉及【美白+保湿】

PS：
请未满18岁的儿童在家长的陪护下观看
避免因自己的错误护肤方法
产生沉入海底的念头

——————————————————————————————————————

ONE
【都说一白遮百丑，其实黑的银是不需要遮丑的对吧思密达开玩笑啦
由内而外的美白】

首先
皮肤的颜色是由皮肤内黑色素的多少决定的 
而黑色素的多少是与太阳光照的强弱有关的

【太阳光】
包括可见光线、红外线、紫外线，其中UVC（波长最短的紫外线）对人体细胞中的脱氧核糖核酸（DNA）具有伤害作用，如果长期照射紫外线，会得皮肤病、皮肤癌等，严重的会导致基因突变
所以皮肤细胞会在生理上释放出黑色素，黑色素有效可以吸收紫外线，减少紫外线对人体的伤害

其次
为什么黑了之后很难白回来

①不防晒，黑色素不断地生成
②皮肤新陈代谢缓慢，黑色素无法正常脱落
③自由基或氧化剂将细胞和组织分解，影响代谢功能

————————三点美白—————————

①防晒，减少黑色素生成
②定期去角质，促进黑色素脱落
（但是第一期也说过，不同肤质是不能乱去角质的
系统学习才能更好护肤，没看的童鞋要耐心看完哦）
③抗氧化，抑制自由基的氧化反应

【氧化+自由基+抗氧化】
这些跟人体嘻嘻相关的，国际蝎尽量送些易懂的

氧化：
氧元素与其他的物质元素发生的化学反应
氧化是肌肤衰老的最大威胁，饮食不健康，日晒、压力、环境污染等都能让肌肤自由基泛滥，从而产生面色黯淡、缺水等氧化现象


点评：
化合物的分子在光热等外界条件下，共价键发生均裂而形成的具有不成对电子的原子或基团——自由基：

自由基具有强氧化性，可损害机体的组织和细胞

通俗地说【自由基就是一个单身汉，它会去破坏成对的稳定的细胞结构】
科学地说【自由基就是游离基，断裂的共价键让它随时去吸附其他细胞】

抗氧化：
抗氧化是抵抗集体氧化作用的过程
其作用机理可以是直接作用在自由基，或是间接消耗掉容易生成自由基的物质，防止发生进一步反应

小贴士：

抗氧化剂能在自然饮食中找到，被称为三大抗氧化物质的
维生素E+维生素C+β-胡萝卜素
他们可以利用自身结构的特性来稳定自由基多余的电子
防止对细胞造成老化（就是做“替罪羔羊”）

————————7种美白成分———————

①果酸

提炼自水果的一种酸，其中又以提炼自甘蔗的甘醇酸效果最佳，目前最常被使用。

作用乃在去除过度角化的角质层后，刺激新细胞的生长，同时有助于去除脸部细纹，

淡化表皮色素，使皮肤变得更柔软、白皙、光滑且富有弹性。

②曲酸

在对比试验中发现，现有的美白成分中，它的效果最明显。曲酸一般从青霉、曲霉等丝

状真菌中提取，是一种含有毒性的细胞，因而没有在市场上完全普及开来。

根据日本最新的研究报告，曲酸成分可能会有致癌的危险。

【不能乱用！】

③熊果苷

熊果苷又叫杨梅苷和熊葡萄叶素，是从熊果的叶子中提取的成分。在不影响细胞增殖的

浓度下熊果苷能够加速黑色素的分解与排泄，从而减少皮肤色素沉积，且安全性比高。

熊果苷是近年来中高端化妆品比较常用的美白原料，如芭特尔芙莱的微晶皙白精华液、

佰草集新七白美白精华液等。

④维生素C

最早用在美白品中的、有代表性的添加剂之一。它的安全性很好，但稳定性很差。

如果不加保护，在膏霜中会很快失去活性。为了稳定它，人们提出了各种办法，如利用橙子肉中的果胶保持天然活性，直到涂敷到皮肤上时，果胶被破坏才被释放出来。

⑤芦荟

芦荟用在美白产品中是因为它对晒后的皮肤有很好的护理作用，减轻紫外线刺激而带来

的皮肤黑化。芦荟是上世纪90年代发掘出的令人惊喜的美容植物，几乎是全能的——

保湿、防晒、祛斑、除皱、美白、防衰老，甚至护发。

【但是，泥萌不要误会，国际蝎说的是芦荟，不是芦荟胶

芦荟和芦荟胶（充其量保湿）的功效是不一样的】

⑥甘草、桑树提取物

从甘草的根中提取而来，一般添加在日晒后的护理产品中，用来消除强烈日晒后皮肤上

的细微炎症。甘草提取物安全性很好。

⑦内皮素桔抗剂

内皮素在皮肤中分布不均，是造成色斑的主要原因。内皮素桔抗剂进入皮肤，可以和黑

色素细胞膜的受体结合，使内皮素失去作用。内皮素桔抗剂是一种很新的原料，代表了当今美白技术的最新水平。

————————4美白功能————————

① 抑制黑色素：即阻断性美白。

同样是常见的美白成分，如麴酸、熊果素等，它们可以抑制黑色素的生成，具有很强的

淡斑功效。

缺点：往往需要渗透到肌肤底层才能发挥其阻断作用，这对产品制剂提出了较高要求。

②截堵黑色素：

即抑制黑色素从黑素细胞转运到角质细胞，如维生素B3。

③淡化黑色素：即还原美白。

皮肤变黑产生斑点，本身是肌肤氧化的过程。而我们熟悉的维生素C及其衍生物便是坚强的抗氧化小卫士，它能把已经氧化了的过程再还原回去，抑制黑色素的氧化反应，让肌肤逐渐透白。

缺点：它不是一个安稳的卫士，很容易在空气中分解，失去功效。

④代谢黑色素：即代谢美白。

像果酸、水杨酸A醇等，像拨开鸡蛋壳一样，剥落肌肤过多的角质层，从而把黑色素

从皮肤上带走，让肌肤新生。

缺点：这种美白方式只是在祛除皮肤表层的黑色素，而黑色素是存在于皮肤底层，不断

的向外生产，所以这种方法治标不治本，还需要结合深层美白产品使用，并且，敏感肌肤要小心采用这种剥落角质的美白方式，要与保湿、防晒相结合。

————————————————赶紧来拿干货！——————————————

抽出泥萌的笔记本

把这些最基本的成分+知识记下

然后选择产品的时候请查查成分表

小贴士：

选择美白产品尽量选一套适合自己的
美白成分各不相同，理论上最好是使用同一品牌同一系列的产品
这样可以防止不同美白成分互相冲突产生的不良反应

—————————————————————————————————————

TWO
【补水？泥萌说什么？补水？补水？
保湿才是王道啊】

①告诉泥萌一个好消息：
我们都有天然的保湿因子

天然保湿因子的合成，是一种存在于人体表皮层中的蛋白质-丝聚合蛋白
由角质层的角化细胞内崩解而产生的亲水性吸湿物质


天然保湿因子能在角质层中与水结合，并通过调节、贮存水份达到保持角质细胞间含水量的作用，使皮肤自然呈现水润状态。
若天然保湿因子缺乏或不健全，便会造成肤色黯沉，产生细纹并变得干燥、敏感。
24小时持续密集的活化皮肤天然保湿因子能帮助肌肤恢复健康的吸水、锁水机制，提供肌肤源源不绝的长效保湿效果。

②再告诉泥萌一个坏消息：
补水不等于保湿

保湿补水通常被人们连在一起谈
经常觉得面膜没少做，为什么还觉得干
其实，补水就只是补水，它一样是会蒸发掉的啊

————国际蝎这么跟泥萌说吧————

角质细胞像砖块一样垒在表皮层的最外部

它们是角蛋白，能吸水，而用于粘合这些砖块的水泥

就是脂质（油脂）

用补水面膜，最多只能让表面几层角质层吸水泡软

皮肤暂时显得水润柔滑

没有皮脂膜（敷面膜前洗走了）

水分一会儿就蒸发掉

况且水怎么可能穿过油脂渗透到表皮层里面~

————看看国际蝎之前的干货————

任何敷完补水面膜不抹乳液的行为都是耍流氓
只想到了补水却偏偏没有想到要

锁水（保湿）是大错特错的


大家都知道水油不相溶吧

我们的皮肤表面都有一层皮脂膜（毛囊皮脂腺分泌的皮脂+汗水+角质分泌的油脂），这就是为什么敷面膜之前我们应该先用洗面奶把那层“油脂膜”洗走，不然面膜再多的水分都补不进去，只能白白留在表面随着时间蒸发掉（但是，皮脂膜平时都是有锁水作用的，可以用油阻挡皮肤里的水分蒸发，所以不要经常用洗面奶洗走它）

当第一道屏障——皮脂膜被我们洗走之后，也不要得意忘形地以为水分进得去=吸收！错错错！是该感慨一下我们的皮肤无处不在分泌油油油油...就连皮肤里面的表皮层都有层层层层“油”！

敷面膜只是补水，当精华液进入皮肤后，如果没有乳液的携带，它还是只能停留在表皮层（虽然不是表面），然后乖乖地蒸发掉。

重点说说乳液，这样就会好理解很多：乳液是由油和水混合组成的乳浊液，分成油包水型乳剂和水包油型乳剂。

想象一下，当“精华液小姐”进入皮肤表层这个“易蒸发危险区”，正面临被逐出皮肤表层的时候遇见了“乳液先生”，辛亏有“乳液先生”的保护携带（油包水），“精华液小姐”才得以穿过层层“油障”，远离“易蒸发危险区”！

————————————————保湿才是王道啊——————————————

保湿涵盖“抓水湿润”与“密封锁水”

前者为吸水，后者为油脂封水

乳液成分通过“油包水”形式穿过亲油的脂质

让皮肤里的亲水性保湿成分发挥抓水的特殊技能

抓住补给的水分，不让它们蒸发掉

—————————————————罗里吧嗦—————————————————

昨天国际蝎游回深海，打开知乎，评论私信的都有
所以今天@国际蝎惯例得改一改：
祛痘美白保湿护肤之类的产品现在是不会一一推荐的

Reason：

①国际蝎还没享受够播种知识收获美丽人生的life
②满足啥都不造的产品伸手萌......“臣妾做唔到啊”

反复强调的肌理，要勤快点好好学习天天向上
懂肌肤知识才能在面对漫天狂舞飘散的治疗护肤ideas时
有自己的判断，也不至于懵懂地被骗啦

—————————————————NO\2——————————————————

第一期主要有4部分：

one [解密肌肤构造]
two [亲测皮肤类型]
three [进击的痘痘]
four [科学护理肌肤问题+养护误区]

（还不造+还在挤痘痘的童鞋，再不“知乎”就要后悔惹::>_<:: ）

—————————————————————————————————————

重要提示，今天新增一条@国际蝎惯例：
评论中的问题，文里没有提到过的都会放在本期内容中......
有些问题，知道泥萌比较心塞，但国际蝎是不会直接说要怎么治疗哒
还不如给一些干货知识让泥萌自己心里有个底：“哦~原来是这样的”

好，废话不多说，上“评论问题”：已经大作死留下坑坑洼洼怎么办？Q_Q
【来自“不高兴”童鞋，看来确实不太开心~~没关系，有问题一起解决嘛】

—————————————————————————————————————

ONE
【如果不知道脸上坑坑洼洼伤在哪里，还怎么“本来就很美”~~
痘印痘坑大起底】

痘印不只是痘印那么简单，它分为【红豆+黑豆】
“红豆”就是红印，“黑豆”就是黑印
不要问我它们来自哪里将去向何处，因为.......
不要打断我，我正要说呢~~~

【红印】
有过痘史的朋友们都知道，长痘痘之后很容易留下红色的印记，摸起来跟其他皮肤没有区别，就是红红的，这就是红印（红色痘印）

那么它是哪里来的呢？这里要讲讲炎症反应引起的发红：

当痤疮丙酸杆菌这种致炎因子进入真皮层，机体就会发生急性炎症反应：

血管扩张→血液流动速度加快→血管壁变薄→血液呈现出更深的红色
血管内的【白细胞和抗体】等透过血管壁进入炎症反应部位，消灭病原体

（那些脓就是白细胞+抗体+细菌等的尸体啊~~~~~~~~~~~~~~~~~~~~~~~~~）

红印是因为原本长痘痘处，细胞发炎引起血管扩张

BUT，痘痘消下去后血管并不会马上缩下去，因为内部的伤口还没有长好，于是逐渐形成了一个一个平平红红的暂时性红斑
SO，痘印只是由于真皮浅层的皮损，引发了毛细血管的增生和扩张，呈现出红色深浅不一的痕迹，会在半年内渐渐退去

【补充《坏痘痘长成记》简图，资料来自“豆乎”】
（毛囊在真皮层内，真皮层有血管，受伤的话就会出血）

【黑印】
黑印是痘痘发炎后的色素沉淀
主要涉及黑色素

【黑色素】其实是一种蛋白质，在每个人的体内都有
而且，它一点也不讨厌！
它是保护我们皮肤免受紫外线及各种射线伤害的重要物质
如果体内黑色素合成能力降低，皮肤就会变得很敏感，甚至会得皮肤癌

白化病：与黑色素合成能力降低有关

那么黑色素是怎么形成的呢？
当我们的皮肤受紫外线及各种射线照射时，分布在角质层的黑色素会先起到防御作用，同时召唤醒在黑色素细胞里的休眠黑色素，也会刺激新的黑色素生成

黑印的消退过程
比一般晒黑和日晒后形成的日晒斑更加漫长有两个原因：

①痘痘消退后留下的伤口更容易受到紫外线的刺激，黑色素的分泌会更多更快
②这个伤口不仅对外暴露，容易接受外在刺激，而且伤口处皮肤脆弱，底部溃口，位于【表皮层底部+真皮层间的基底层】的黑色素颗粒掉入真皮层，它们只有被巨噬细胞吃了以后，通过淋巴、血液新陈代谢经过人体内一道道关卡才能排出体外，这个过程比从表面皮肤排出去要慢得多

（敏感肌的过敏发炎要和红印区分开来）

【痘坑......
又称“橘子皮”】

真皮层里胶原纤维如果排列整齐，就会维持皮肤平滑和光泽、弹性和韧性

但如果痘痘比较严重，长成【结节和囊肿】，就会造成伤口太深，伤及真皮

（毛囊溃口，里面的脓排出后，相当于在皮肤上留坑）

最紧张的是！！！！！！！！！！！！！！！！！！！！！！！！！！

这会使胶原蛋白构成的真皮组织缺损，并造成胶原蛋白结构的错乱

而新生结缔组织对伤口进行修复是无序的，原本整齐有序排列的

胶原纤维开始萎缩、错乱、积压、断裂→错位排列+新生

使愈合后的皮肤变成一个没有弹性和韧性的凹洞

【番外】

一、

咳咳咳咳咳咳咳咳咳~~~~

干货有点多，老板再来碗“顺溜”

口渴口渴口渴口渴可口可口可口

口渴口渴口渴可口可口可口可口

“砰”！咦，脸上有什么东西流下来

老板：Stop！别念。

您脸变形到都把痘痘给戳破啊！】

二、

宝宝：妈妈妈妈，麦当当叔叔鼻子跟你的好像，都有颗红豆豆耶

！！！！！！千万憋生气，你造的，一生气那颗痘痘就要爆炸了

人家麦当当叔叔那是可爱，人脸上的只能说是，特色到没朋友啊

（如果伤害了泥萌，对不起啊，我再也不是国际蝎了→这是我们

可爱的诺一说的哟~~下面上点”小菜“）

TWO

【知己知彼百战百胜

消消印填填坑哟】


【红印】与发炎和血管扩张有关
要想消退，就要对症下药：

①消炎

芦荟：
消炎效果不错，大家可以去
寻寻觅觅觅觅寻寻

②收缩血管

脉冲光：
可收缩微血管，有淡疤效果，但需要经多次治疗
脉冲光还可增加真皮层的胶原蛋白，使凹陷不再明显
改善毛孔粗大，所以也适用于轻微凹洞并存的皮肤

（任何一个治疗过程都有需要注意的地方
这里先不展开讲，怕泥萌消化不良呢）

【黑印】

黑印和黑色素形成有关，那么真相只有两个！
首先，抑制黑色素形成

①防晒防晒，还是防晒
②美白护肤，护肤美白

黑印和黑色素代谢有关，既然这样......
其次，促进皮肤新陈代谢，加速黑色素排除

①定期去角质
②刷酸刷刷刷

PS：先简单说说刷酸——
使用产品中带有水杨酸或果酸这两种成分，并且主要目的就是剥落角质
但是过程有很多需要注意的，怕泥萌...所以留到后面再讲啦~~~

【痘坑】

很不幸，因为痘坑已经是伤及真皮层很深了~~~很深~~~了
所以填起来比较困难，一般都要通过医学美容来解决
例如：局部皮下注射或者光照疗法

—————————————————————————————————————

今天上的菜就这些啦，泥萌看着吃
明天国际蝎再烹饪出菜~~~~

等不及的娃儿也可以评论区说说自己的问题
国际蝎会根据这些QS看看放哪些干货

有兴趣的话题也可以提出来哟
一起热闹热闹叽叽喳喳
才能奋起战痘精神！

嗯，拉钩一百年，不许变
说好要一起“你本来就很美”的

—————————————————————————————————————

开心一刻（大家都是这么过来的）


—————————————————NO\1——————————————————

ONE
【如果不懂肌肤机理，光有养护的劲是行不通的
解密肌肤构造】


PS：重点看毛囊、皮脂腺的位置，长痘痘跟它最有关

皮肤由表皮、真皮和皮下组织构成
表皮层：基底层+有棘层+颗粒层+透明层+角质层
真皮层：乳头层+网状层

问：为什么我们的皮肤会有弹性？
真皮里的网状层由两大纤维组成，一是胶原纤维，主要成分是胶原蛋白，坚韧柔软；二是弹力纤维，主要成分是弹力蛋白，弹性极强。这两种纤维交叉形成一张弹性的网，保持了肌肤的弹性和张力。

问：为什么我们的皮肤会表现的水嫩？
真皮层的含水量约占18%-40%，可以说是人体的“蓄水库”，表皮层所需要的身体总水量的水分基本都是从真皮层运输，从而保持了皮肤所需要的水分，我们的皮肤才会显得水嫩有光泽。

问：为什么我们的脸上长痘后会留有疤痕？
如果痘痘的生发主要伤及到真皮层的乳头层，不会有疤痕，只有色素沉着，留有痘印；但痘痘生发伤及到真皮层的网状层或者皮下组织，一般都会留下痘痕，比如痘痘痊愈后留下的凹坑，主要是因为破坏了网状层的胶原纤维和弹力纤维，不会自我修复。

TWO
【每个人的肤质都不同，看清自己的肤质才能“对症下药”
亲测皮肤类型】

油性皮肤：在洗脸后半小时内面部出现油腻
干性皮肤：在洗脸1小时后皮肤仍感觉干燥
中性皮肤：在洗脸后半小时至1小时恢复滋润，不干燥也不油腻
敏感性皮肤：遇冷或遇热都会发红发痒，用化妆品后容易出现过敏
混合型皮肤：部分人存在额，鼻部为油性，其余部分为中性或干性

THREE
【从痘痘的萌芽开始，反说肌肤为何受伤
进击的痘痘】

简图：


痘痘发生过程：
①毛囊导管口角化过度
②皮脂腺分泌过多皮脂（油态半流状）并且排出受阻
③毛孔堵塞，毛囊内厌氧的痤疮丙杆酸菌大量繁殖
④毛囊内形成粉刺（早期痘痘）

如果粉刺不及时消退就会发展：
粉刺（分白头粉刺和黑头粉刺）→炎性丘疹→脓包→结节→囊肿

【毛囊皮脂腺导管角化过度，皮脂排出不畅，堵塞导管口，造成毛囊内厌氧的痤疮丙酸杆菌大量繁殖，毛囊口堆积的异物使皮肤隆起，产生粉刺（白头和黑头），接着致使毛囊和毛囊壁周围发生炎症反应，产生丘疹、脓包等。进一步会导致毛囊壁损伤破裂，从而使皮脂和皮脂中的游离脂肪酸以及痤疮丙酸杆菌等异物进入真皮，引起感染，恶化成结节、囊肿等。】

痘痘发生原因：
①皮脂腺分泌过旺
（影响其分泌的是雄性激素和类雄性激素）
②毛囊皮脂腺导管口角化过度
③痤疮丙酸杆菌大量繁殖

结合到生活中：
①在压力、熬夜、劳累、紧张时，肾上腺会分泌对抗压力的皮脂酮，它类似雄性激素，会刺激皮脂腺。
②水土不服、便秘等疾患，会导致毒素在体内过度吸收，引起内分泌紊乱；而饮食辛辣、油腻、高糖、烧烤等食物后，导致胃脾不和，内分泌紊乱。
③女生在月经前几天，体内“类雄性激素”水平明显变化，黄体酮增加，刺激皮脂腺分泌，造成皮脂分泌过量。特别是月经不调、痛经等症状，更加会影响类雄性激素的增加。

下图可参考：痘痘长在不同位置，代表身体不同部位的“警示”



FOUR【科学护理肌肤问题+养护误区】

关于如何祛痘？

这个问题其实很简单，终止任何一个痘痘发生环节都可以祛痘
比如说，毛囊导管口角化过度，皮脂分泌过旺
这就警示我们要勤洗脸，作息要规律，吃清淡点的食物
不要让（雄性激素和类雄性激素）过度刺激皮脂腺分泌

①减少皮脂腺分泌：少熬夜，吃清淡点的食物，作息和饮食都要规律
②避免表层角化过度：去角质
③消炎，抑制感染恶化

△注意，每个人的肤质都不一样，油性肤质的可以去角质，但是敏感肌NO！

关于养护误区：

【问一：为避免长痘痘，只要脸一油就用洗面奶洗！
NONONONONONONONONONONONO~~~~~~~~】

虽然，洗脸有很大的作用：
①皮肤需要呼吸，外界灰尘和皮肤自身的皮脂积聚在脸上，容易堵塞毛孔，也会引起细菌滋生，所以需要定时清洁。
②在使用保湿、去痘等产品之前需要先洁面，否则有效成分可能会因为皮脂分泌形成的皮脂膜的阻挡作用和角质堆积造成的毛孔堵塞而作用效果下降。

但是————————————————————

首先：皮脂膜不是想洗就允许洗走的
皮肤表层有皮脂膜，是由（皮脂腺分泌的皮脂+汗水+角质层分泌的角质）组成
它可以对我们的皮肤起到阻止水分蒸发润滑的作用，过多地用洗面奶洗走皮脂膜
会有利于空气中的细菌和灰尘伤害我们的皮肤

其次：不是每个人的皮肤都能用同样的洗面奶洗
【油性皮肤】：油性皮肤因为皮肤分泌油脂比一般人多，所以需要选择一些清洁能力比较强的产品。通常需要选择一些皂剂产品。因为皂剂产品去脂力强，又容易冲洗，洗后肤感非常清爽。
【混合型皮肤】：这类皮肤主要T字位比较油，而脸颊部位一般是中性，有点可能是干性。所以这种皮肤要在T字位和脸颊部位取个平衡，不能只考虑T字位清洁干净而选一些去脂力非常强的产品，尤其是在秋冬季节。但是脸颊是中性的，所以一般夏天用一些皂剂类洗面奶。在秋冬季节，因为油脂分泌没有那么旺盛，就换成普通泡沫洗面奶。
【中性皮肤】：这类皮肤是最容易护理的。一般选一些泡沫型洗面奶就可以。
【干性皮肤】：这类皮肤最好不使用泡沫型洗面奶。可以用一些清洁油，清洁霜或者是无泡型洗面奶。 

然后，洗脸的步骤也要注意
①洁面乳：选择对的清洁产品，更安全地清除污垢。 
②水温：适度水温（估计26℃-30℃左右）是不伤害皮肤的重要条件。 
③材质：皮肤科医师建议「以双手，不使用任何毛巾」最安全。手部与脸部都是皮肤，都是角质蛋白，「以柔克柔」安全性最高。 
④搓揉力道：搓揉力道也决定清洁干净与清洁风险，请充足而温和地揉搓。

倒数，监督情节是否到位
①皮肤本来就有自我检测能力，当皮肤受到刺激后，会逐渐出现「干燥、紧绷、搔痒、微刮、小痛、刺痛、大痛」这些不同等级的表现。 
②很多人喜欢「洗完脸，感觉清爽、绷绷的」，其实就已经是轻度伤害了。 
③理想上「把脸洗乾淨，而且不伤害脸皮」的现实结果，就是：「洗完脸可能觉得清爽，但决不紧绷」。

最后提醒两点：
①「油性痘痘肌」
对于痘痘肌，在使用祛痘的产品之前也需要先洁面，否则有效成分可能会因为皮脂分泌过多形成的皮脂膜的防御作用和角质堆积造成的毛孔堵塞而进不去。
②「敏感痘痘肌」
对于敏感肌，可使用清水洗脸，如果害怕清洁力不足，可使用温和氨基酸洁面产品，远离碱性皂基。

【问二：痘痘亮红灯，我先挤一挤！
前方高能，妈妈知道你这么做一定不会给你吃炸鸡啤酒的】


知道你很想战痘，但是你知道吗，这样会适得其反哦~
挤压的同时不仅【伤害毛孔周围的毛细血管+损伤细胞留下烦人的痘印和痘坑+很容易引起发炎、扩散→引发更多的痘痘】
正确的护理应该是根据“敌人”痘痘的情况、安排合理的方案、调理肤质、消炎杀菌、疏通毛孔、清洁毛孔、修复毛孔、排除肠胃毒素、调节内分泌、调节饮食、安排合理的作息时间表等、改善成因、才能抑制痘痘不反复

千万不要吃饭睡觉打痘痘啊！！！忍住忍住忍住恩恩恩恩~~~~~


———————————————————————

看完这篇so-long战痘养鸡策略（养肌）
你是时候该喝水啦
“肌肤保卫battle”
知乎首秀开始
明天@2内容 
将会同时
呈上
———
【祛痘产品？那些哪些哪些那些】
【食疗shiliaoshiliao？什么鬼】
———————————————
你的关注是蝎蝎最大的动力
我要给泥萌生猴子
哈哈开玩笑
我要给泥萌送干货
——————————
WHY
因为伦家寂寞→自己一个人美不好玩（委屈脸）
See you tomorrow~~~~~~~
编辑于 2015-10-15
知乎用户
知乎用户
前百度| 运营策划 | 公众号：BBC纪录片解毒

欢迎大家来关注（害羞脸），其实我还有很多经验和教训可以讲给大家听。如果之前有人指导我，我想会少走很多弯路～谢谢小伙伴们的关爱

读研以前比较黑，痘痘也很严重，大学的时候有段时间快要烂脸了。


现在白很多，也很少长痘。

从初中开始陆陆续续长痘，一直到读研之前。差不多折磨了我十年的痘痘，让我的青春黯然无光，毫无美感可言。而我的蜕变，也是从不长痘开始，才有机会去化点淡妆，研究各种穿搭。

之前因为长痘的关系除了水什么都不敢涂，因为会很油腻，防晒更不必说，所以也养成了不涂防晒的习惯，导致我很黑。后来开始涂防晒，注意避免太阳直射后白了很多。

本篇主要分以下四个方面叙述

一、 我的日常习惯

二、 BBC研究调查发现的护肤秘密

三、 常用化妆品

四、 战痘经验

一、关于我养成的让皮肤变好的小习惯，主要有以下

1. 不熬夜，这个不用说了，很多人都强调但是做到的人很少。我一直以来都有不熬夜的习惯，跟身边熬夜的朋友比，确实状态好很多。身边熬夜的朋友到我这个年纪已经明显出现眼角皱纹，皮肤松弛，暗淡无光的情况，我的状态就好很多。

2. 多喝水，不用多说。

3. 办公室放加湿器。北方比较干燥，所以桌上总有一个加湿器。

4. 多吃蔬菜和水果。我算是半个素食主义者（主要是因为不爱吃肉），每周会吃很多水果和蔬菜。而研究也表明颜色鲜艳的水果和蔬菜确实有助于延缓皮肤衰老。大学的时候听室友讲确实有同学为了护肤，每天只才吃白菜西红柿黄瓜这样非常清淡的菜，据说皮肤是真的好。

5. 注意防晒。如果你观察一下妈妈辈大腿内侧和皮肤和脸上的皮肤，会发现大腿内侧的皮肤要好很多，这就说明长期的风吹日常确实会加速皮肤的衰老。Get到这一点后，防晒就显得非常必要了。通常外出的时候我会打伞，如果不方便我也会拿一个小纱巾披着，把裸露的皮肤都遮上

6. 少吃垃圾食品和甜食，少吃碳水化合物。

7. 关于吃辣椒这点，我一直都很能吃。之前长痘的时候也没有停止过吃辣椒，偶尔不吃了发现没什么卵用就接着吃了，现在不长痘了依然在吃，也没什么反应。所以这个可能还是要看个人体质，需要自己实验。

8. 早起喝一大杯水

9. 燕窝。关于这点大家有疑问，我也看过类似无用的报道，但确实是看了同事的现状以后觉得真的有用，当然具体可能还是看要个人体会。同事今年快30，经常吃燕窝，现在看上去还是刚毕业学生的样子。据她自己说也管用。她吃的是这家



如果没有条件吃银耳也可以，打算吃起来。天猫上有这家店，会比较贵，如果有朋友去香港帮忙带就更好了。


二、之前BBC一个记录片有提到，防止衰老的几个秘诀，主要是以下几点

1. 注意涂防晒。

2. 挑选颜色鲜亮的食物。比如番茄，它有一种特殊的成分--茄红素，它能良好吸收氧气并防止氧化应激。

3. 选择味道苦涩的蔬果。像西兰花、小红萝卜，他们含有一种叫芥子油苷的成分，使皮肤自我保护。

4. 食用含有大量油脂的鱼类，比如鲭鱼

5.  试着避免淀粉类的食物，比如米饭土豆或面食。（原因纪录片中没写...... ）但是有小伙伴评论中指出原因应该是淀粉中糖分比较多，同6

6. 减少饮食中的糖分。原因在于一旦糖分依附于胶原蛋白，胶原蛋白会很容易遭到破坏，并且皮肤会很难自我修复。

关于纪录片的全文，可戳此处http://t.cn/RCC2feg


三、关于化妆品，只选适合自己的，不选贵的

具体还是看自己感受，甲之蜜糖乙之砒霜。

1. 卸妆：卸妆一定要卸干净，哪怕只是一层隔离或者防晒，否则毛孔很容易堵塞。

我用的是贝德玛，也是推荐较多的卸妆水之一。



2. 水、乳液和洗脸液目前用的都是雪肌精，主要是因为雪肌精据说有美白效果。酒精成分是肯定有的，但是我没有出现过敏反应。这个具体还是要看个人



不过还是要推荐一款性价比较高的无印良品乳液



100块非常大瓶，我不是敏感肌也在用，滋润不油腻

3. 粉底。关于BB霜毁皮肤的言论已经很多了，所以我都是用粉底。用之前会涂一层植村秀隔离



妙巴黎粉底，也是性价比超高



4. 面膜：森田药妆，香港的药妆店有卖，大概50多一盒。如果不知道哪里购买靠谱倒是推荐莎莎的app，虽然也人说莎莎实体店有假货，但我买这么多年目前还没发现。



5. 口红：mac系列，CK的颜色也是我比较喜欢的。还有一款性价比很高我觉得颜色很好看的韩国Bbia 7号（绿色那款）



6. 眼线：也是推荐度很高的kiss me ，睫毛膏是agnes b 的

7. 眉笔：资生堂六角眉笔，个人感觉比kate的好用



8. 彩妆，在澳门免税店买的Lancôme套装，好像不到300，很划算也很方便



那个里面的盒子有备用,相当于是两份

9. 防晒霜 亲测好用的有水宝宝、香蕉船。安耐晒据说很不错。去长滩岛和青岛的时候都没晒黑。




四、如何不长痘

我的痘痘是从什么时候开始好了呢？大概就是在我完全放弃不再瞎折腾以后，大概就是从去香港读研，毕业后又来了北京，水土变好以后。以下三点客观原因对我来说还挺重要的

1. 心情，之前很发愁，每天臭美苦恼，用尽各种办法，什么酒精姜片芦荟中药都用了一遍都没什么用，后来真的是放弃了顺其自然了。放弃以后发现慢慢竟然有了好转。

2. 水土也挺重要的。高中的时候就听老师说过以前有个学生长痘很厉害，后来去北京读书以后就自然变好了。我是从去香港读研开始好转，来北京以后也几乎不长了。（我理解的水土应该是水质比较好，气候的话有很多小伙伴去了香港以后反而长得更厉害）

3. 再就是年龄，过了25以后发现油脂分泌的少了，不像以前总是油油的。大概也是不长痘的原因之一。

主观上，后知后觉发现还是有很多措施可以做的，可惜我当时病急乱投医

1. 多运动。多运动有助于排毒。男朋友的皮肤就非常好非常细腻，主要原因就是运动量比较大。

2. 毛巾，床单枕巾勤消毒

3. 从内部调理身体。之前虽然去看中医吃了不少药，但是始终没有跟医生搞清楚是什么体质，应该吃什么。每个人长痘的原因不一样，有的是湿气重，有的是火气大，还是要根据体质的不同，从内部进行调理。

4. 手不要在脸上乱摸，有很多细菌

5. 勤卸妆，一个月去2-3次角质


关于我的日常搭配，可以看这个https://www.zhihu.com/question/35931586/answer/135178926

感谢关注，这是一个三观和颜值才华一样正的迷你V。
编辑于 2017-09-12
知乎用户
知乎用户

上面的妹子都回答的各种详细了，我也是来偷偷学习的。
本人就是基本上从高中时代就开始长痘痘，此起彼伏，到了大学，由于贪吃长胖了大概快20斤，那个时候脸也不知道为什么就变成了油性敏感肌，并且最可怕的是还不自知- -觉得自己还挺好的。现在再看以前的照片，简直想死100次。
差不多快10年的痘痘史，分享几个绝对不要走的歪路给大家：

1.千万不要相信网上的手工皂之类的自制产品。
谁用谁知道，除了能让你的皮肤变得更加脆弱，长红血丝以外，没！有！任！何！帮！助！
哦，还可以帮你花一大堆钱。
买护肤品，一定一定要买合适自己的，尤其是含酒精类的产品，一定要先在手腕或者耳后试一下。
记住一句话：便宜没好货。护肤不是用一个产品就能解决的问题。

2.不要买很多人都推荐的化妆品
血泪史，听别人说倩碧、薇姿、理肤泉、雅漾等等都适合油性皮肤痘痘肌使用，于是就跑去买了一堆，最可气的是有一次买了一套，忘在地铁上了- -，但这不是重点，重点是所有这些大牌产品，在我脸上都产生了非常恶劣的影响，不断的白头，粉刺。我绝对不是一个人，因为我上网查了，很多人跟我一样，当时年少无知，真的相信了这是皮肤在“排毒”，现在想想，仿佛是被猪亲了。
这些产品对有一些人来说可能是很有效的，但对你不一定是。
现在还是想喊一句：辣鸡产品，毁我皮肤，坏我前程！
尤其点名批评雅漾，除了喷雾以外，其他的产品都是鸡肋。
声明：对我个人来说，如果对某些姑娘有效，恭喜你们并且羡慕你们。反正我花出去的钱就像长出来的痘痘一样多- -....

3.不要不防晒
防晒有多重要，大概就是你早上起来洗完脸，可以先不穿衣服，也要先擦防晒吧。
作用上面的妹子都说了，我就不再强调了。
有段时间受了刺激追求健康的小麦色，于是天天跑出去不打伞不防晒，把自己晒的我妈都不想认我了┑(￣Д ￣)┍
不防晒的结果就是：皮肤更差，并且你不停地搜索，怎么变白，怎么缩小毛孔。
记住：防晒是第一步。

4.不要相信某产品可以缩小毛孔
缩小毛孔的产品根！本！不！存！在!至少目前为止，没有。
毛孔的生产是不可逆的，只要撑开了，想缩小，最好的方法就是：医美。
妹子们努力赚钱吧。

5.不要吃高GI食物
什么是高GI，简单的记就是，不要吃任何的甜食。
甜食虽美，可会让你变丑。我当初长胖20斤以及长痘痘都是甜食的错（其实都是自己的错.......

下面再分享一些个人的经验给大家：
大概就是大学快毕业的时候，可能也是照镜子的时候把自己吓哭了吧- -决心要把烂脸给治一下。于是开始查各种的资料，并且也不在盲目的相信大牌了。学校有健身房，于是就开始了每天早上6点半准时到公园晨跑，跑到7点半（速度不定），然后会慢慢的走回去，学校离公园很近，回去之后就热牛奶，吃麦片，写作业。大约到9点半的时候就去健身房开始做辛勤的小蜜蜂，热身，无氧，有氧。
那个时候差不多坚持了小半年，直到毕业。我的脸也小了一圈，皮肤也好了不止10倍吧，虽然现在还是会冒痘痘，但已经不是痘痘随处可见的程度了。
后来毕业就回国了，回国的第一件事去北大附属医院看了医生，血泪史，为什么之前不相信医生，却偏偏相信一些别人分享的“小秘诀呢”，心里苦。也在同皮肤的妹子的推荐下，结合医生的意见，用了非常适合自己的护肤品，等下可以介绍给大家，但你们不一定要用~好么~还是选适合自己的啦。

1.坚持运动
关于运动，只要记住，运动不会让你变得更差。前提是：你要合理的运动，不要节食。

2.相信科学
推荐一个医生给大家，如果痘痘肌的妹子一定都知道他：三石医生。（大家理智关注吧，觉得有用就多研究下，没用就找对自己来说最有效的医生啦~）
满满的都是干货。先治好脑子，再来治脸，是我的人生格言。
如果在北京的妹子，也可以直接到北大附属医院找吴艳主任医师，不过她的号非常难挂，可能你得排上一个月吧~其他地区的妹子可以直接在三石医生的微博上搜索一下，他都会推荐很多医生的~

现在分享一下自己会用的洗面奶吧，也欢迎使用同样产品的妹子来跟我交流一下心得哦
①欧丽缇洁面

对我来说好用到不能再好用的产品。
②大葡萄水
有了它，雅漾直接抛弃。
③REN玫瑰洁面

欧丽缇和REN家的产品，好像还没有用到特别不好用的。

另外还有一个有机牌子叫PAI，是英国的产品，有一段时间买的特别特别多，但怎么说呢？
好评非常多，但我感受不到好处，当然也没什么不好。总之如果有人感兴趣也可以搜一下。

以及大家知道有一个神奇的网站可以查到各种化妆品的成分么？除了产品成分之外，它还会告诉你致粉刺率有多少，买护肤品的时候我都会先查一下成分，特别感谢发明这个网站的人，相信她一定是个妹子。

总之，从内要调整饮食，要运动。从外要选择适合自己的产品。
妄想只做一边就想有好皮肤的（除了天生的），还是洗洗睡吧~

ps图片来源于网络，自己没有拍过QAQ 如有不妥亲告知删除，谢谢！

补充一个
成分查询的网站：化妝品、保養品成分查詢分析
最最最重要的一点就是：希望姑娘们（或者少年们）都能先好好地去检查一下自己皮肤究竟是什么问题，然后再对症下药，不要盲目相信，要先了解自己。
编辑于 2016-12-02
冲冲冲冲天
冲冲冲冲天
谁活着未靠感觉做人才 可悲.

之前写的回答我也搞不懂为什么被人举报了，审核两天还没通过懒得等，所以干脆换个地方扑。。。



大概背景介绍：图一大三成都，图二重庆工作。本人敏感肌+油皮。两颊皮层很薄轻微红血丝，易泛红，春秋换季还是会莫名其妙长很多小红疙瘩还痒，但来得多也去得快。有闭口或者发白痘痘会自己挤掉，因为也不会留痘印。体质属阴虚火旺，其中肝火较旺（脾气会很急很大那种），体质导致脸容易泛红和长痘。 
所以，每个不同情况的人应根据自身特有的情况再对症下药。我的方法对我有用，对你呢有可能效果并不会那么明显。我也并不是很懂护肤方面的各种知识，也许我只是更了解自己需要什么而已。。。。

今晚进入正文持续更新中（10.11 ， 19：50）~~~~~~手机码字很慢，请大家稍安勿躁呜呜啦啦哇哇

可爱分割线，以下为原文
—————————

2014年8月 （标清无P日常照）
。
。
。
。
前
。
。
。
方
。
。
。
高
。
。
。
能
。
。
。



2016年9月 (只是早上出门前涂了无任何粉底成分的防晒霜的手机原图)

中间护肤历程艰辛坎坷，我主要分为运动和基础护理两大方面的改善。先留住以后有空再慢慢详谈。



1运动篇
我皮肤的改变应该是从运动开始的。因为之前吃了些激素药，整个人变得像发泡的馒头，所以就决心减肥。从2013.10.7开始下定决心，那个时候就是不吃晚饭加运动（后来才了解到不吃晚饭减肥真的很不科学不健康）。身高157cm，4个月从49Kg减到44Kg.（感觉关于减肥我又可以单独发一篇。。。）但，，，这都不是重点！！！重点是我因此而爱上了跑步，两天不跑腿就痒！！皮肤改变最大的时期是开始晨跑时期。大四下学期，每天早上六点二十出门跟室友晨跑，八点左右去食堂吃稀饭白水蛋和蔬菜。因为那段时间运动排毒加健康作息时间，那时的皮肤状态基本就和图二差不多了（可惜没照片，遗憾脸…）
总结汗水才是最好的洁面乳，运动完后会有最完美的腮红。改变皮肤状态我从运动开始，从身体内在的改变开始！！！



2护肤篇(持续更新中…)

以下的所以护肤方法仅针对油皮痘痘敏感肌部分适用，不会推荐具体产品除非真的特别好用的必须要大声说出来o(≧o≦)o

2.1清洁

面部清洁我是根据自身情况分为日常清洁，去角质和清洁面膜的深层清洁。 

日常清洁选对适合自己肤质的产品很重要，经评论友人传教，像我们这种皮肤选用氨基酸洗面奶还不错。脸之前先把手洗干净配合打泡网用，泡沫丰富细腻且蓬松。注意，敲黑板啦。。。。洗面奶一定是要先把泡沫打起来了再往脸上抹的。。。。直接上脸挫泡泡洁面效果减半（我也是错了好多年才晓得）。洗完脸用专门擦脸的一次性纸巾（一大盒，X宝上买的）把脸上的水慢慢点干。早晚两次，我都没用洗脸帕擦脸，总觉得不够柔软不够标准。

去角质没什么可说的，但也有两点要强调:
1,对于敏感肌肤红血丝和两颊皮层很薄的妹子们来说，不要再用搓的那种，要买涂在脸上轻轻拍就能拍出角质的那种。我之前也用了很多搓的，所以当年的红血丝和脸颊薄很大程度都是自己的无知造成的罪孽深重啊啊。。。
2,不管什么肌肤，定期去角质是很有必要的。因为脸上堵了很多死皮不清除，你再多再好的护肤品脸吸收不进去用再多也白搭呀。。。

清洁面膜对于油脂分泌比较旺盛的妹子们比较适用，定期深层清洁皮肤深处垃圾，效果与去角质一样。

2.2补水

作为护肤步骤中最基础且最重要的环节，只要做好补水工作，绝大多数皮肤问题都能迎刃而解。面部补水我的日常大致分为化妆水，随身喷雾，自制水面膜，面膜和睡眠面膜。

化妆水用于日常洁面后，首先选购一瓶适合自己肤质的水，然后用化妆棉按压就行。

随身喷雾我多用于上班期间，感觉面部有点泛油或任何不适，喷雾一喷，再用厚一点的化妆面轻轻按压即可。

重点来了，第二次敲小黑板。。。我要说的是自制水面膜。 首先选购一款适合自己且质地较为清爽的水，倒在压缩面膜纸上使用。这个面膜的好处是即使天天敷也不会对皮肤产生任何负担，而且持之以恒皮肤状态明显稳定因为喝饱了水的呀，什么油光啊敏感出小红疙瘩毛孔粗大之类的现象都得到及时的管控。所以这个补水小诀窍很希望安利给大家。。。

日常单张面膜一周三次左右，次数不宜太多。但每次夏天晒黑了敷这种面膜，连续三天左右，会很快白回来。

睡眠面膜会让你的肌肤整夜都处在喝水状态，这样的第二天早上呈现的皮肤状态基本都是巅峰。尤其是夏天呆在空调房里更少不了睡眠面膜来伴你度过干燥的一夜。。。

2.3防晒

我曾陷入一个较大的误区，就是只有在夏天的焰阳天才会涂防晒霜，其他季节都不会实施防晒工作。这样长期以往的后果就是会加速肌肤老化程度，肌底黑色素持续沉淀。防晒霜是为了抵抗紫外线对皮肤带来的损伤，原则上来讲，所有白天都应该进行面部防晒措施。就我自身来说，这样坚持一段时间后能明显感觉皮肤甚至毛孔问题得到修复。虽然不能完全归功于防晒霜的原因，但我觉得他肯定也有功不可没的力量。之前在知乎看到一句话 说你想要变白，那就把防晒霜当乳液抹咯:)。乍一听觉得简单粗暴，其实细思还是很有道理的。。。。当然都是建立在要做好日常清洁工作之上的哈¬_¬

为了使用感比较清爽，我都是选择化学防晒方式的防晒霜。也用过很多款，目前最喜欢的还是小金瓶。真的是油皮亲妈，墙裂推荐！！！

基础护理的其他步骤我都按常规进行。水、眼霜、精华和乳液。不化妆，一年涂BB的次数加一起不到二十次。一周会有一天只喷水让肌肤断食（其实还是懒.....）。
饮食方面我基本不吃零食和深度加工的食物。很少很少很少吃蛋糕之类的甜食。但从不会忌辛辣油腻。日常饮水量偏大，都是喝白开或自己泡的各种茶，饮料最多喝宜简，基本不喝任何碳酸和其他饮料。
我总结自己皮肤状态的改变都是靠运动和规律饮食结构下的健康作息时间慢慢自身修复转变的。在自身肌肤已经提升到一定好的阶段，再靠护肤品进行稳固（我运动期间有半年没用过任何护肤品包括洗面奶）。就是要让皮肤启动自身调节机制，从而达到最自然的修复方式。
最后希望大家都能在充分了解自身情况后，寻找一条能坚持下去又适合自己蜕变的道路。好身材会有的，好皮肤也会有的，相信明天是美好的。
   以上完结，谢谢大家，祝福所有人 
编辑于 2016-10-15
单单酱
单单酱
立志美到老～个微mixiaoniu01

一定要被看到的答案，更新去黑头小技巧

清洁面部以后，用热毛巾敷一会有黑头的地方，敷5到10分钟，这样可以让毛孔打开，更容易清理黑头。然后用小苏打、牙膏、纯净水按1:1:1的比例混合均匀，用细软毛的牙刷蘸取混合物轻刷黑头的位置，三到五分钟后温水洗脸。这个时候不要用手去挤，用热毛巾轻轻擦拭，如果表面有黑头浮出，可以用毛巾轻轻按压。最后用冷水洗一遍脸。最后用水、精华、乳液完成护肤步骤。一般这种情况下我选择用收缩毛孔的水，效果更好。不过这种方法不适合每天都用，建议一个月2-3次即可。

更新于2016年5月4号

一定要被看到的答案.……午休时间来更新了……

先自诉一下，不爱运动，皮白，无斑，无痘印（几年前长过满脸痘痘，那时候我爹我妈估计都嫌弃我，反正我弟弟直接把嫌弃挂嘴上，不肯和我一起逛街出门），身上皮肤也很白，超级懒怕麻烦，所以不喜欢化妆，但是出门会打个底妆（反正打不打底妆回家都要卸妆，不要和我说你不知道用了防晒霜后要卸妆哦）。本人看上去比实际年龄小很多，经常被误认为90后。

话说想让皮肤变好，真的是一件需要很多耐心和票子的事情。虽然我不觉得我皮肤好，但是经常被夸赞皮肤好皮肤白，而且不是只有脸白哦，是全身都白。我还成功影响了身边一堆的朋友，把她们带到了美丽的大道上。

接下来分三个个部分分享，身体篇、面部篇和内养篇。原谅手机党无法编辑加黑。

1.身体篇

大家每天都洗澡，但是一大半的人懒得擦润肤露。润肤露一定要擦，一定要擦，一定要擦！重要的事情说三遍。沐浴露和润肤露都要选择保湿滋润的，一定要清爽，尤其是润肤露，味道也要淡。香味太重太厚的润肤露涂身上真的很难受，就像没洗澡一样（我个人觉得）。我所处的地区也比较干燥，还有一个小诀窍就是洗澡之后，身上的水没擦之前，倒少许婴儿油（我喜欢强生的）均匀涂抹全身，然后干毛巾或者浴巾擦干，之后可以正常涂抹润肤露。这个步骤只是多花几分钟，但是收获是非常大的。全身的皮肤都会变的又细腻又柔软又有光泽。我有时候犯懒就涂完婴儿油擦干不涂润肤露（捂脸，懒是女人天性）。我猜大家会希望我推荐好用的沐浴露和润肤乳，我也推荐一个非常非常小众的（暂时没图，以后贴上）。去年去泰国玩，带了两套牛奶沐浴露和润肤乳，回来一用，太好用了，然后就找代购买了十几套送给了身边的朋友，她们用过都说非常棒。价格很实惠，几十块一大瓶，也超级经用，一瓶用一两个月绝对没问题（不过我用润肤乳比较费，一个月一瓶）。记得胳膊肘和膝盖需要格外用心护理，平时涂完脸手上剩下的水、精华、乳液可以涂胳膊肘和脖子，坚持就一定有收获！


2.面部篇

用适合自己的护肤品和化妆品。角质层薄的要注意防晒，同时不要用刺激性的护肤品，少用去角质清洁面膜。干性皮肤用滋润保湿的护肤品，油性皮肤用清爽控油水油平衡的护肤品，混合性皮肤冬天用滋润夏天用清爽型护肤品。平时多做面膜。都不建议大家使用含有酒精的护肤品。

这里说一下正确的护肤步骤：
早上：卸妆-洁面-水-精华-眼霜-乳液（-面霜）-防晒霜
晚上：卸妆-洁面（-水-精华）-面膜-精华-乳液-面霜/睡眠面膜
括号里的部分可以根据个人情况要不要。可能你会觉得看起来很麻烦，其实操作起来还是很简单的，早上也最多花5-10分钟。晚上要贴面膜，需要的时间就比较多一些。一般情况下，我贴面膜前会先去除老化角质层。下面贴一个我的面膜三部曲的图。

左边去除老化角质的，又被称为充电面膜，可以急救，快速提亮肤色，洗脸后涂于面部保持3-5分钟洗掉。中间蓝色的是去黑头收细毛孔的，哪里有毛孔涂哪里，也是保持5分钟，然后温水洗掉。最后贴一个贴片面膜，一般贴贴面前，我会涂一点水和精华，吸收一下再贴面膜。面膜贴完后把面膜取下对折，然后贴在脖子上5-10分钟，同时利用这个时间按摩一下面部，促进脸上的精华吸收。面膜之后我会涂精华和乳液，然后睡觉。我的护肤品一直到防晒霜都是fancl的，另外备了一支SK2神仙水作为急救用。

推荐一个好用的面霜，澳洲VE面霜，真心好用，价格也不贵。可以代购也可以天猫国际。还有一个泰国的ele睡眠面膜，也真不错。这两款平价性价比高，学生党也适用。不知道你们要不要推荐好用的平价面膜？如果需要我来帮你们扒。

改天我再给大家安利一个去黑头的妙招，原料家里都有，而且简单易行，打算拍成视频给大家发福利（不过我还不知道如何拍视频，捂脸）。


3.内养篇

我平时比较注意养生，现在每天都喝养生茶保养自己。所以，现在肤色和气色一直都很好，人也精神很多。建议气色不好的女孩要补补气血，气血好了，皮肤才会真的好，人也才会更漂亮。女孩子平时可以自己泡点桂圆红枣茶喝喝，方便简单，还能养气血，大姨妈的时候喝更好。

晨起一杯温开水，然后一杯蜂蜜温开水。可以帮助清理肠胃和排毒。我自己是没喝水之前吃不下饭的。而且每天一杯蜂蜜水真的好养人，不过也要坚持。对了，如果有便秘的，一定要调理好，否则会长斑、皮肤暗黄、有口气，还容易致癌哦！

几年前我内分泌失调，大姨妈不准时，而且量时多时少，有时会有痛经，脸色也很不好看（那时候脸上还有痘印），整个人给人感觉很没精神。看了西医，开了药吃了没用反而长胖好多，我把药拿给好朋友看（她是医生），她说都是激素，让我不要吃了。她家里是中医世家，她给我一个方子，我喝了不到两个月，月经规律了，而且不再停经，不仅如此，整个人的皮肤也变得更白更亮了（全身的哦）。后来我配合喝黑枸杞，脸上的痘印慢慢淡了，那个夏天也没有晒黑（我不喜欢打伞哦）。真的，看着自己越来越美，心情真的会变好，人也会自信起来的！

除了喝养生茶，还要食补的。女孩子一定要多补充胶原蛋白，这样皮肤才会好，才会显得年轻。我经常炖汤，我是可以不吃米饭，但是必须要喝汤的人。可以是鸡汤、骨头汤、排骨汤，猪蹄，我习惯放一小把红枸杞、十几片西洋参，有时候也会放虫草花、羊肚菌什么的。放西洋参是为了防止上火的，还能补气。
如果不喜欢吃荤的，可以经常炖一些银耳红枣枸杞百合羹。有条件的可以天天早上吃燕窝。
先更这么多。我要去忙了，有空再来补充。如果你觉得我的答案有一些道理，记得点赞和关注我哟！
编辑于 2016-05-04
不爱喝水的喵喵
不爱喝水的喵喵
皆是虚妄 V： jiaowoxiaoshiyi11

更新：

昨天晚上半夜写的答案，今天看到好多小可爱们关注，回复。真的好开心~

评论里有仙女指出是药三分毒，这点我没考虑到。关于黄芪当归炖蛋这个大家尽量去医院咨询过医生之后再尝试。

我本人贫血，脾胃不太好。之前有在同仁堂喝过中药。黄芪当归炖蛋也是在问过医生之后开始吃的。大家能看到我的药也是从同仁堂买的。

看到评论里有伪科学的字眼还是挺委屈的，文章里写的每一条我都有亲自实践，一点一点码出来分享给大家。真心希望能帮到其他小仙女~

黑头和闭口的内容，我写到文章下面啦~有需要的小可爱可以去看

作为一个没有才艺的猪猪女孩，翻遍知乎好像只有这个问题适合我答

毕竟我是一个研究护肤的狂魔，当年考大学都没这么认真过（捂脸）

从内调到外用再到口服保健品，有一肚子内容迫不及待的想跟你们分享~~

会有点长，小可爱们答应我要耐心看哦~~

先来个美少女镇楼~

大家有什么问题也可以直接问我，比如黑头，，痘印，，毛孔，，美白，，补水等等

以下内容都是答主研究了很久而且亲自实践过

毫不保留的分享给大家，真心希望能帮到每一个小仙女

半夜还在呕心沥血的码字，善良的仙女们真的不给我点个赞吗~


一、内调

1.每天早上起床后喝一杯温盐水

其实想要皮肤好，排出身体中的毒素是第一要务，每天早上一杯温盐水，润肠通便又排毒。长期坚持还能帮我们形成易瘦体质~

答主每天早上起床都要喝上一杯

关于盐水中的盐，我用的是超级粉嫩可爱的 { 喜马拉雅盐 } ，大家也可以用家里普通的盐哦~

另：便秘的小可爱一定要试试哦，超级有用的


2.拥有好气色的一些食补技巧

答主因为总是晚睡，加上有点轻微贫血，所以气色不太好。每天不涂口红的话朋友们都说我苍白得像病人

所以答主真的认真研究了好长一段时间怎样才能拥有好气色的方法，虽然中间也有踩过坑，但还是总结出了几个很有用的小方法：

- { 五谷杂粮粥 }

《黄帝内经》中有说：“五谷为养，五果为助，五畜为益，五菜为充，气味合而服之，以补益精气”

五谷杂粮中不仅含量丰富的膳食纤维能清除体内毒素，而且含有维E,维A，B2等多种元素能促进新陈代谢，让皮肤细腻光滑。另外它还有辅助减肥的作用~

我经常喝的搭配：

&  黑豆，黑米，红豆，绿豆，薏米，芡实，小米，糙米，燕麦，山药，红枣  &

（薏米性凉，经期妹子不要放哦）

材料都很容易买到的，菜市场或者淘宝都能轻松搞定

黑色的食物补肾，有乌发的作用。红色补气血，山药健脾~这样搭配下来整个人都很有安全感呢~~

这里说一下，山药不是你在菜市场买的那种哦，要去药店买，我是在同仁堂买的，下面会放图~

答主的部分杂粮

药店买的山药

做法也很简单的哈：

将以上材料取适量泡一晚上，早上丢到锅中煮熟就好了。我一般是早上起床喝完盐水之后，把材料洗净放到电饭煲里，设置为煮粥模式，然后就去洗漱化妆。大概一个小时左右粥煮熟的同时大概也收拾得差不多啦，吃一碗暖暖的粥就要以开始新的一天啦。亲测，杂粮粥饱腹感很强哦，在减肥的妹子一定不要错过。

ps：还在上学的妹子可以去网上买那种养生壶之类的，功能很强大~可以定时煮粥


- { 红枣核桃黑芝麻泥 }

这个做法稍微麻烦一点，但是真的超级好喝~补气血嗷嗷的

适量红枣，核桃，黑芝麻。红枣的量大概是核桃+黑芝麻的2倍。

将核桃，黑芝麻磨成粉，现在超市里有好多卖这种粉的地方，可以买现成的。

红枣加水，大火烧开后转小火慢慢煮成枣泥，切记后面要常搅拌。枣泥完成后交枣核挑出来，

最后将核桃粉和黑芝麻粉放到枣泥中拌匀，装进瓶子里。每天早上可以挖出一两勺冲水喝

超级好喝而且又补气血，黑发~

要注意，每天吃少量就行。不能多吃，因为这个很容易上火


- { 各种汤 }

之前湖南卫视播的真正男子汉第二季大家应该都有看过，上交行李的时候佟丽娅的包里竟然装了全套的煲汤工具。这说明啥，说明啥

想要好皮肤煲汤很重要~

要要皮肤水嫩的女生，一定要多多喝汤

而且，煲汤真的没你想像中那么难，连我这个只会下方便面的菜鸟都能做好

推荐几种我经常喝的：

{ 花胶玉竹美肤汤 }

材料 ：花胶 玉竹 枸杞 淮山药 蜜枣  莲子 排骨（可替换为鸽子或鸡肉）

做法：

- 花胶加姜片泡3-5个小时，淮山药泡2-3个小时，莲子和玉竹泡30分钟，蜜枣和枸杞洗净

- 排骨或其他肉类在开水中煮1-2分钟左右，这个做法好像叫飞水，不太懂，反正就是去腥味

- 将以上所有材料放入锅中，（最好是砂锅）加2L水，大火煮开转小火煲1.5个小时左右，起锅前加盐调味。

不喜欢甜味的妹子，可以不放蜜枣。我觉得放蜜枣甜甜的还蛮好喝的


{ 虫草花干贝玉米汤 }

材料 ： 虫草花  干贝 枸杞  芡实  莲子  排骨（可替换为鸽子或鸡肉）

做法：

- 芡实泡2个小时， 其他材料洗净

- 排骨或其他肉类在开水中煮1-2分钟左右，这个做法好像叫飞水，不太懂，反正就是去腥味

- 将以上所有材料放入锅中，（最好是砂锅）加2L水，大火煮开转小火煲1.5个小时左右，起锅前加盐调味。

上面这两种汤真的特别好喝，吐血推荐给仙女们~~


{银耳汤}

银耳汤我就不多说，太多太多人推荐啦，植物燕窝真的不是白叫的

银耳汤其实做法特别特别多，大家可以随心做

入秋之后，我做银耳汤的频率会就高，银耳滋阴润肤效果极佳。尤其是秋冬多吃银耳可以让皮肤细腻光滑

做银耳汤我真的是看心情，每次用的材料也都不太相同，大概总结一下，大家可以变通的哈

银耳+梨+马蹄 + 冰糖

银耳 + 枣 + 莲子 + 百合 + 冰糖

银耳 + 桃胶 + 皂角米 + 枸杞 + 玫瑰花 + 冰糖    （ 桃胶性凉，孕妇不可以吃）

银耳  + 莲子 +枸杞 +冰糖

冰糖是一定要放的，这样煮出的银耳更加软糯

{当归黄芪炖蛋}

这个主要还是补气血，虽然里面有两味中药，但是味道并不难喝的

材料：当归 10克  黄芪 10克  红枣去核 6个  鸡蛋 2个  红糖适量

当归，我一般每次用2片

黄芪，一般每次也用两片

- 先将当归 和 黄芪 用冷水浸泡 20分钟 （更容易出药性）

- 将鸡蛋煮熟，剥去壳待用

- 将当归 黄芪 红枣放入砂锅，放3碗水，大火煮开

- 将鸡蛋放入锅中，转小火煮40分钟左右，直至剩下1碗

- 放入适量红糖调味后，就可以啦

主要是喝汤吃鸡蛋，黄芪和当归千万不能吃哦~~

因为做起来比较麻烦，我一般周末才会做一次，手机里也没存图啦，就不发图片啦

内调部分先写到这，宝宝真的要睡啦，困死了。

明天继续补~

———————— 关于黑头/闭口————————

评论里有小仙女问我闭口，黑头，白头的问题~我先答一下

先说一下我长闭口的经历

去年脑子进水斥重金买了一瓶希思黎的全能乳液，就是那瓶号称

“如果你有钱一定要买一瓶”的全球经典护肤品之一

然而我用了之后额头和下巴就开始长闭口，不过幸好除了长闭口没有其他问题，整体上无功无过

所以，看在毛爷爷的面子上我还是忍痛用完了

-------------------------------------------------------------------

除了闭口外，鼻子上有黑头也是我的一个烦恼之一，下面来说说解决方案

处理闭口和黑头我基本上是用一个方案

- -首先是清洁。

清洁，首先是卸妆（卸妆这个事有多重要我就不多说了）其次是清洁面膜

我自己用过的清洁面膜有三，四个，目前在用的是科颜氏白泥（其他用过的产品后面再细说）

洗脸后，在闭口和黑头部位涂上清洁面膜（有条件的话可以先蒸一下脸，让毛孔充分打开）

我一般过10分钟后用刷子将泥膜弄掉，用水洗净

-- 敷水膜。

第一步清洁完成后，闭口和黑头应该会上浮出来，我会用粉刺针将闭口和黑头挤出来。挤不挤这个看自己哈，很多人都说用这样挤不好，但是我对闭口和黑头的恨让我失去了理智，必须要挤出来才解气。有时候挤出黑头心里还会暗爽（0 . 0）

挤完之后迅速敷上城野家的收敛水。（这一步很重要，加粗加黑！！）

之后，用{ 悦木之源家的菌菇水做水膜 }，这款水对我来说真的是去闭口神器

但是也有人说很鸡肋，护肤品这个东西真的是因人而异。要找到真正适合自己的肯定会踩几个坑

还有之前用过{ 黛珂家的紫苏水 }，我觉得对闭口也蛮有用。

然而对比下价格之后，我还是果断选择菌菇水~~（贫穷使我节俭！！）


上面的方法，我是一周一次。清洁皮肤不能太频繁的大家肯定都知道

另外，本着负责任的态度提醒小仙女们，敏感肌慎用！！因为我自己不是敏感肌，不确定敏感肌是否适用 。我本人秋冬干性，夏季混油


用过的清洁面膜产品汇总：欣兰冻膜 / 科颜氏白泥  / 雪花秀撒拉面膜 / 希腊玫瑰的一个清洁面膜（这个牌子很小众）/ 还有一个不知道叫啥名的韩国的一个清洁泥，我在网上找到了图片。值得一说的是这款产品虽然用起来效果一般，但是送的那个刷子真的很好用。我一直用它来辅助清除清洁面膜~~


这里面性价比最高的是 欣兰冻膜  价格不高，清洁力强。每次刚用完，脸都会白半度，当然过不了多久就恢复原来肤色啦~；其他的产品除了韩国的那个清洁泥，我觉得都还不错，大家可以根据心情选择。至于希腊玫瑰这个品牌，我回头有时间再单独写吧。知道这个品牌的人应该蛮少的


除了上面这些，我真的推荐大家买个luna，我用了小半年，鼻子上的黑头真的有少。当然肯定也跟我长期护理有关系。但是luna真的是我买过的仪器里唯一一个没有闲置的~（refa,日立，洁面刷，去黑头仪.....它们都静静的在柜子里吃灰）

luna真的蛮贵的，所以大家一定根据自己情况选择哦。

穷到吃土的我买了一个玩趣版，不能充电，大概能用半年~


黑头和闭口先说到这里哈，有问题的小仙女可以留言或者私信我。

工作不忙的情况下，会第一时间回复大家~

一无是处的我，真的是特别喜欢护肤相关的东西。大家有什么问题尽管问我~

最后一更~

二、外用篇

1.关于美白，痘印

- 先说内服：牛奶，豆浆，西红柿，柠檬水，杏仁粉

{ 牛奶 } 应该有好多人不喜欢喝牛奶吧，其实我也是。但是，我现在每天都要喝。一个是因为想要更白，

另外一个原因是缺钙，腿老是抽筋，每天喝牛奶真的有缓解。不知道有没有小仙女和我一样，身上各处的关节总爱咔嚓咔嚓响，具体怎么响的我也不知道怎么描述，反正如果有这个症状的话真的建议你多喝牛奶~亲测有用！！

我自己喝：特仑苏 、 澳洲蓝胖子全脂奶粉

特仑苏其实蛮贵的，我觉得没有蓝胖子划算。牛奶大家可以根据自己喜欢的口味选择

怕胖的小仙女尽量选择低脂型，我因为要补钙都喝全脂（结果就是，我现在白胖白胖的...）


{ 柠檬水 }  我一个朋友喝了一年，真的白了好多。注意要用新鲜柠檬。至于白天能不能喝的问题网上有两种不同的声音，有说感光不能白天喝的，有说一只柠檬的量根本不足以感光的。反正我胆子大，我白天也会喝。仙女们随意~

好像有人说胃不好的妹子要少喝~胃不好的妹子可以注意下


{ 西红柿 }  这个推荐的人太多太多啦，相对来说每天吃西红柿也很容易坚持。不管你是生吃，榨汁或者炒菜吃都要坚持哦~


{ 豆浆 }  这个我不知道是什么原理，但是我喝了真的会白。有时候杂粮粥喝烦了，我就用豆子磨豆浆喝，

黄豆 、 红豆 、绿豆 、 黑豆 有时候掺着来，有时候只打黄豆。仙女们如果在家可以试试


{ 杏仁粉 }   具体的方法是用牛奶冲杏仁粉喝。我跟同事一起买了好多杏仁粉，刚开始信誓旦旦的说要每天坚持，后来.....好像.....哈哈。喜欢杏仁粉的妹子可以试试


除了上面的这些我还有个比较麻烦的食疗方法，需要榨汁。因为怕有争议就不放出来了，如果有妹子需要私信我吧


- 外用  ： 

先上个我目前在用美白产品的全家福，有点乱别嫌弃

科颜氏的淡斑精华和乐敦CC是我买来去痘印的。这两个产品对新痘印都有明显效果。让我很惊喜的是乐敦CC，因为它实在是太便宜了，所以当时买的时候真的完全不报希望。没想到效果挺惊艳的。这个质地偏油，我每次也就用一两滴。晚上涂在有痘印的地方，大概一周左右吧，新痘印真的淡了好多。


卡姆果睡眠面膜，我觉得很鸡肋。


Only的为个忘记了什么名字的美白精华，网上号称平价版小灯泡。里面含有烟酰胺，不耐受的亲要甚用。虽然我用这个真的很干....但是它确实有提亮的作用。


分享两个我自己在用的美白和祛痘印的小方法

1.美白

纸膜强烈推荐 MUJI家的！！

薏仁水适量 +  自然哲理维C粉  + 两滴太阳社玻尿酸   用纸膜湿敷

薏仁水真的是平价又好用的典范。VC粉我用完了还没买，所以没上照片。

VC粉带的有个小勺子，取一小勺就可以啦

加玻尿酸一方面是补水，另外一个是因为它质地比较粘稠，能减少化妆水往下滴的现象

湿敷后再用自己的美白精华，及面霜正常护肤就可以啦~


VC粉其实也可以混在其他产品里一起使用，但是我很懒....

另外，VC粉这么用可能会有争议，但是我就是这么用的~~如果你不认可可以忽视


2. 去痘印

- 洗完脸之后，先涂一层玫瑰果油（上张照片里，挨着olay的那个小瓶）

- 之后湿敷

薏仁水适量 +  科颜氏美白精华两滴 + 自然哲理VC粉    用纸膜湿敷

- 湿敷后，取乐敦CC抹在痘印处，后续正常用用自己的面霜就可以啦~


这个方法仅适用于新痘印，陈年老痘印或者很严重的痘印，一定要去医院看医生哦

外用的药我就不推荐了，不一定适合每个人。去找医生开最靠谱


我觉得美白是一个长期的过程，化妆品只是起辅助作用，想要由内而外的白一定要从饮食和作息做起。

关于美白还有一个最最最重要的事------防晒！！！！

一年四季都要防晒！！！

我之前做过一个皮肤的基因检测，结果上说我的抗氧化能力比较差，

要一年四季不论阴天下雨都要坚持用防晒！！


当初年少轻狂的我，大夏天都不用防晒，太阳伞更是嫌麻烦从来不打。然后，然后，脸上就长了斑

那时候也没想到斑是晒出来的，就可劲的用淡斑的产品。斑这个东西基本上长出来之后就很难通过护肤品去掉。只能求助医美。评论里有问我怎么去斑的，这里我统一说一下哈

祛斑的话真的只能去医美。我打算过段时间去医院做激光，如果有北京的妹子咱们可以一起约呀~


ok,回到正题，知道防晒的重要性之后家一定要用防晒哦

不防晒就不要说美白！！

防晒霜我自用过觉得还不错的：安耐晒金瓶/蓝瓶spf50，图片里应该有  嘉娜宝ALLIE spf50，

YOJIYA spf36

夏天或者军训的话，强推安耐晒。之前我去泰国玩了几天，回来之后朋友都很差异我为啥没被晒黑，

我觉得全靠安耐晒！！


嘉娜宝ALLIE 我也挺推荐的，这个涂上之后脸白白的，我有时候懒得上粉底的时候直接涂一层就出门啦


YOJIYA 这个品牌可能有点小众，也是日本的。我自己用的是spf36那支，超级轻薄，涂完之后跟没涂一样，有时候我甚至一度怀疑它到底能不能防晒..（0 . 0）但事实证明，它是一支合格的防晒~


大家可以根据自己的肤质选择，另外经常在外的仙女除了防晒一定不要嫌麻烦，记得打伞，或者戴遮阳帽

遮阳帽我自己也有个可以推荐，有需要的小可爱可以私信我


2.补水和毛孔问题

其实很多皮肤问题都是皮肤缺水引起的，除了一些补水面膜之外，做水膜湿敷是我最最最推荐的方法

我自己平时用的几种大概写一下

薏仁水适量 +  自然哲理维C粉  + 两滴太阳社玻尿酸   用纸膜湿敷

纯露适量 + 两滴太阳社玻尿酸   用纸膜湿敷


湿敷的化妆水就用你自己平时常用的就行，我家里常备的就是薏仁水，橙花纯露，菌菇水

敏感肌的妹子可以用成分很简单的，MUJI的水，IPSA流金水，

另外朋友推荐了一款玉泽的水，据说敏感肌用效果很好，不过我还没用过。亲可自行功课


玻尿酸真的是干皮妹子必备!！我一年四季长备，真的是谁用谁知道 

皮肤状态不太好的时候，怕粉底不均匀，也可以在粉底里加一滴。


毛孔问题

我之前脸颊的毛孔略粗，本来想去做点阵的。但是这阵子不知道为啥，毛孔竟然小了点..

评论中问我毛孔问题的仙女，如果你毛孔真的特别大，建议去医美，我之前一直关注的是

点阵。但是还没去做

然而最近毛孔小了点，我又在纠结要不要去做了...


至于为啥变小，我觉得，一个肯定跟饮食有关，毕竟我又喝杂粮粥，又给自己煲汤。

身体总要点良心吧。

另外跟运动也有关系，前段时间我一直在坚持运动，在健身房跑步之类的，

出汗之后皮肤真的会透亮。顺便说一句，仙女们跑步不要带太厚的妆哦~

因为跑步之后要拉伸，做瑜伽之类的。竟然意外收获了一个一字马...

但是这几周总加班都没去运功，一字马可能已经还回去了...


最后的最后总结 ：饮食 +  运动  + 认真护肤  =  好皮肤

为了打消一此小仙女的疑惑，我把我自己用的护肤品图片放上来，证明我说的每一条都有亲自用过，有点乱别嫌弃

用过化妆品和护肤品之类的东西真的太多了，一时半会也说不完。仙女们私下问我吧


至于口服的保健品，基本叫得上名字的我至少买过50%，买什么之前可以先问下我。

swisse胶原蛋白，叶绿素，维C，还有好几个牌子的葡萄籽，还有什么神经酰胺，透明质酸

美白的胶囊.....我都记不全了......

我吃过的保健品里，比较推荐的就是葡萄籽，和 维C 


护肤不是单靠这篇文章就能讲完的，评论和私信有点多，受宠若惊（毕竟之前我是一个知乎小透明）


收藏的人辣么多，点赞的人却辣么少~~你们不乖哦~
编辑于 2017-11-19
萌说
萌说
微信公众号：萌说（ID：mengshuo233），让我们一起变得更美好

说到如何让皮肤变好？
啊啊啊，我不禁仰天长啸。
因为在很长一段时间里，都深受痘痘的困扰，
回想起来，那是我逝去的青春。

现在痘痘问题基本上好的差不多了，
当然，我的青春也飞逝而去。
大概也是因为以前小，不懂事，随便乱用东西，所以现在皮肤状态很奇怪，
角质层很薄（不是我说的，是专柜的大姐姐说的），油的地方很油，干的地方很干。
唉，一言难尽。

推荐几个我用了感觉比较好的产品吧。
我可不是做广告啊，这些都是我自己从可怜巴巴的工资里抠出钱来买的，既然买了用了，不分享一下感觉太吃亏了，啊哈哈哈哈。所以我就来了。
当然，你必须要明白一个道理，皮肤至自己的，一定要好好的保护。。。

首先，就是洁面。
关于洁面产品，我真是用了好多好多，什么泡沫状的啊，慕斯状的啊，乳液状的啊，水状的啊......
等等等，仿佛神农尝百草，我对于一切大家推荐的产品都想去尝试一下，
发现也并非所有的都好用。
最后发现还是氨基酸洁面比较好用，推荐芙丽芳丝洁面，总的来说挺好的，清洁力不会太强，但是也洗的很干净，清清爽爽的。
对了，除了洁面，还有重要的一步就是卸妆，
作为现代女性，出门最起码要涂个防晒和BB吧，那肯定是要卸妆了。
可能很多人怕卸妆伤皮肤，不卸妆反而更伤皮肤吧。实际上可以选择比较温和的。
我个人不喜欢卸妆油，觉得还是卸妆水比较好用，温和，而且卸的也比较干净。
还是推荐经典的产品——贝德玛卸妆水，我买的是蓝色的，混合油性肌肤用蓝瓶。（突然脑补了：蓝瓶的钙，好喝的钙。。。。哈哈哈哈，醒醒啊喂）
用起来很方便，用卸妆棉来卸。想到以前用卸妆油，那油腻的感觉，一言难尽。
卸妆水虽然柔和，但是也不要弄到眼睛里，如果花了眼妆，还是乖乖的用眼唇专用卸妆产品吧。

对了，说到清洁，除了卸妆、洗面奶，还有就是用清洁面膜了，这个也是很有必要的。
以前我可不信什么清洁面膜，后来尝试之后，觉得这种面膜的存在是非常有必要的，
因为你即使每天洁面，还是需要清洁面膜做一个深层次的清洁，因为洁面产品在脸上最多也就按摩个几分钟吧。清洁面膜敷个十五二十分钟，还是能够比较深入的。
推荐一个大家应该都知道的，科颜氏白泥，不多说，真的好用。

清洁之后，就是在脸上涂涂抹抹了，哈哈哈，我母上大人说那是在糊墙。
一般我会先用大喷来喷我的大脸，冬天有点酸爽啊哈哈。
大喷很多，大家都知道的雅漾啊，理肤泉啊之类的。但是我还是喜欢欧缇丽葡萄水大喷，感觉用起来很舒服，看到评论区很多大神也都推荐了。不过有人说味道甜甜的，这个我确实是没尝。
基础护肤也就离不开水乳之类的，其实关于水乳的挑选，我确实没啥特别的感受，感觉自己用着舒服就行，我建议还是不要贸然使用那些带酒精的，先试试自己皮肤的接受程度，我是不太适合用。感觉整个皮肤状态都变差了，但是这个是个体的差异哈，并不代表所有人都是。
因为不知道听那位大师说过，肌肤的关键是补水补水补水，
然后我就相信了。我用来用去，觉得兰芝补水套装其实还不错，我买的是清爽型的。天地良心，都快认真的用完了。

对了，说到补水，我有用过超级辣鸡的东西，就是悦诗风吟家的一个新品吧，是朋友从韩国带回来的，店员说是新品哦，超好用哦，但事实证明，店员在骗人。一点卵用都没有，哼。
就是下面这俩货，我还坚持用完了哦，一个是喷雾，还有一个是精华还是啥，上面的字看不懂，但是量不是很多，我用到最后也没有感觉好用。

对了，对于有痘印的朋友们，推荐乐敦CC精华，好像也能祛斑吧，
很平价，但是还是蛮好用的，记得要在睡前用，抹完就关灯睡觉，美美的睡到天亮哦。
那个香味我很喜欢，战痘圣斗士必备。

然后关于化妆用的推荐，我确实没有心得，就简单的随便抹点就出门的那种，
但是一定要记得防晒防晒防晒！！
防晒产品很多，我觉得还是推荐安耐晒，因为大家都推荐也不是随随便便说的，是真的比较好用，但我每次都是挤出一些了，才想起来“用前摇一摇”，记得摇一摇哦。还有那股子酒精味，有点浓郁。

结尾还有一个小小的推荐，就是关于水解胶原蛋白的，因为大家都形容少女有张”满满胶原蛋白“的脸蛋，但是到了一定的年纪，胶原蛋白确实会流失。
我抱着宁可信其有不可信其无的心态，开始吃水解胶原蛋白片，真的，超大颗，一天要吃很多粒，导致我现在吃个感冒药，都感觉简直很轻松嘛。
这个效果还是有一些的，但是我又觉得会不会是心理作用，反正等我吃更长的周期，再来告诉大家到底有没有用吧。
不要随便乱买哦，这玩意毕竟是吃进肚子里的。
今天就是随手小分享，以后有的话再补充，不过护肤这个东西还是因人而异的，也没有什么统一的答案。
总的来说，要把这件事当回事才行。
发布于 2016-12-03
贺子桐
贺子桐
最佳华人女Rapper在路上

写一个小众点的：家用激光祛痘仪。原理是用蓝光杀菌。

适用对象：作息不规律＋外涂产品作用不明显＋没耐心＋敢尝试新事物的妹子／汉子们。

先说我为什么推荐这货，再放亲测效果图，结尾附带痘痘脸化妆经验。

一、推荐原因，也是为何其他答案对我不适用的理由：

1. 无法规律作息。

谁不知道早睡早起跟爷爷一起做运动对皮肤最好啊！？真做不到啊啊啊啊啊啊啊啊啊啊啊！！！！

也别是期末：如山的作业＋不干活的组员＋社交的需求＝半夜三点喝醉回家，吃着披萨巧克力做PPT到凌晨六点，冲澡后补妆去Pre，回家妆都懒得卸直接昏睡过去。

这样的生活就是皮肤的死循环，所幸马上毕业，工作后同事靠谱一点，生活也会规律些。

我这样是最极端，脸成这样也是活该。但若你短时间内无法达到某些题主提倡的健康生活，不妨试试这个救急的快方法。

2. 外涂／吃药无效。

知乎、豆瓣、美容院，朋友口碑、看医生...能试的都尝试了。

大多数外涂对我无效，可能是我没有耐心？黏黏糊糊惹我烦。

有用的基本含抗生素／激素，停用后变本加厉。

内服：长效避孕药到第二个月，除了mess up（长胖，月经连来14天）外没有看到效果；异维A酸不敢吃；空总大夫开的痤疮颗粒出国后也无法补货了。但长痘的强烈推荐先看医生，查查激素水平

3. 性价比高。

我随手截的亚马逊上Acne Device，比一瓶爽肤水还便宜。很多美容院有类似的蓝光疗法，但一半一个疗程需要几千块。我现在在国外不方便，打算回国体验下差别。

我买的更屌丝了..真便宜啊...食堂一顿饭也比这个贵...这是室友推荐的，按照她的逻辑：先买便宜的，有用再买更贵的。经过这一星期我决定升级到三种光源：祛痘／淡斑／嫩肤的一款，到时候持续更新使用体验～

知乎这个地儿就不需要翻译了吧？原理大概就是用蓝光杀菌



二、使用感受：

我是4.21日收到包裹，4.22日上午开始用的。

使用方法很简单：打开开关，对着长痘痘的地方怼，换地儿的时候再消毒一下。2分钟后自动会停止，跟计时电动牙刷相似。所有痘痘照顾到了，就可以正常护肤／上妆了。每天三次。

使用的时候只会感觉到热和震动，但对于严重、要长脓包的痘痘，能感觉到明显的刺痛感。

使用效果：我一只是不惮以总大的恶意揣度祛痘方法的。变量太多了。对我来说，好好护肤意味着同时规律健身，按时作息，饮食健康，到底是哪一个因素起作用？不得而知。

真正觉得这个方法有效，是因为左眉上那一串最恶心的囊肿群，从我三月回国到现在一个多月，不管使用什么战术攻略都无法令它们缴械，顽固的高耸着，在我biubiubiu照了几天后，这货竟然！瘪！平！了！主要凭这点，我觉得还是很有效的。

废话完毕上图了（很丑很恶心，观看请慎重。。。）：

使用前4.18：恶心吧哈哈哈哈哈哈小朋友们不要学姐姐哦，好好吃饭睡觉


使用第二天4.23晚：脸颊和两眼之间的脓出来了，总的来说像是火山活动变平静了..红红的是眼镜架

使用第四天4.25：手机摔过很多次，像素渣渣，但自我感觉脸部更平静了，那些活跃在痘痘间的细菌被我干死了不少。Yeah！

使用第六天4.27：左眼那几个囊肿小妖精真的缴械了诶！超！开！心！基本没有脓包了，红色炎症也好了不少。这张像素问题太模糊，真实皮肤没有这么好

使用第七天4.28：终于在光线好的地方照了张。还是可以看到痘印，但比上周已经好太多啦～～

三、长痘化妆：

身在经常需要Networking//Career Fair/Party的商学院，化妆是家常便饭。痘痘肌化妆的Tips我也总结出一些。（图片主要选Snapchat截图，有的带滤镜但无P图）
1. 防痘痘恶化，重点在底妆产品选择：

日常妆用BareMineral

BareMineral主打不含矿物油，对痘痘肌非常友好。虽然不至于治痘痘，但确实没有加重。我用的是粉饼，中国妹子肤色用Fair就可以。另外价格也很美好。

这是我用过三小时后，可以隐约看到痘印但很自然（当时真的有点醉了，自己名字都错）


最近看很喜欢的答主 
@易烫YCC
 推荐了它的粉底，打算下周买回来试试


非日常用Covermark

这款粉底用完皮肤状态很好。美中不足的是品牌本身很Snob，不喜欢。记得当时微博上XXY强推她家遮瑕粉霜，导致各地卖断货，他们赶紧出了一款全新遮瑕。效果好多少我不知道，但价格是上涨了三倍。

用CoverMark的好处就是大浓妆也Hold得住

2. 遮瑕是重中之重，重要场合需要绿色隔离。

遮瑕是越干效果越好。BareMineral的液状遮瑕感觉很鸡肋，一直的心头好是丝芙兰柜姐推荐的这款Cover FX anti-blemish Concealer

效果真的好，一直回购。图片是我皮肤最差的时候用它遮痘痘来着


痘痘肌皮肤一般都偏红。如果很重要的场合豁出去了，特别是要用红色系妆容时，需要用绿色隔离／遮瑕平衡。去年Winter Former时我选了红眼影红嘴唇红裙子，下狠手涂了很重的绿色隔离，结果喝高了脸色也很平静。




3. 勤补妆

出门一定要带好遮瑕和粉饼，没事就补啊补。痘痘肌很容易透妆拔干，红红一块显得妆很脏。


最近小伙伴纷纷推荐Proactiv这货，说是拯救大部分美国少女的青春期。今天下单，后续有用就来更新～
发布于 2017-04-30
Reynold少爷
Reynold少爷
留学生 数学系 摄影师 烹饪爱好者

主要提到大家关心的：闭口 ！痘印！ 以及过敏！的一些解决办法

之前有问过大家想看什么 最后提名护肤的最多

所以赶在双十一之前 把护肤的写了 这样大家就可以在双十一的时候剁手剁手剁手

虽然最近不想爆照 但知道这种题不爆照没有说服力

iPhone自带的相机 前置拍摄 无滤镜 无磨皮 素颜 没熬夜 （至于我熬夜后什么样 关注了我朋友应该都懂 就别说了）

介绍一下皮肤状况 中性偏干 t区偶尔会油 无痘（偶尔会长） 无印 无闭口 无斑点 不算太白 会有一点红血丝

好了 接下来上干货

我是个很在乎自己脸的人 曾经每天护肤要花40分钟

流程：洁面+yaman美容仪+面膜+喷雾+爽肤水+眼霜+精华+面霜+黄金棒瘦脸

现在比较忙 也相信一句话叫less is more 就精简了护肤 今天主要讲经过我精挑细选 现在每天固定用的护肤品 

1.洁面 (主要解决了闭口问题）

FOREO LUNA mini2

去年黑五购入的 非常好用 是我买过的 最值得的仪器之一 我个人的体验是 它有三大优势

1⃣️. 不需要换刷头 硅胶材质抑菌 比较卫生卫生 

2⃣.清洁力优秀 完全是手洗不能比的 对闭口很有效 自从买了这个并坚持使用后 经过大概一年的时间 我脸上已经没有闭口了 被闭口困扰的小伙伴可以考虑一下 

3⃣️.便捷 充一次电可以用半年作业 非常省心 而且全身防水 直接放在浴缸旁边就行了

ps:我不是敏感皮 敏感皮尽量还是不要用 我记得它有款专为敏感皮设计 可以考虑那款 以及这个不能每天使用 我大概是一周用2次 作为深层清洁 而且这个还带去角质的功效

我搭配的是sk2的洗面奶 之前洗面奶的推荐大案例有写 是我最近的新宠 就不多说了 想看的去翻我洁面的那篇答案把

2. 喷雾

一般做完洁面后 我会习惯用喷雾镇定一下 用过雅漾 理肤泉 依云 还有欧丽缇 感觉都差不多 基本上哪个打折我就囤哪个 我觉得大概就是不觉得他有什么大作用 但还是会去做的一步

特别推荐一个 欧丽缇的皇后水

对毛孔有点作用 可以短暂的缩小毛孔 但对控油效果还蛮好的 如果哪天早上起来脸特别油 喷一下 可以保证大半天都不泛油光 推荐给油皮

3.爽肤水／精华水

澳尔滨的健康水 已经空瓶2个330ml的了

用了以后皮肤状态非常稳定 有消炎 很少长痘了 虽然很多人都说要湿敷 但我不建议湿敷 

虽然这款水有一定争议 但我觉得他至少还是非常适合我的 相比神仙水（用了1／3就送人了）我还是更喜欢它 

不过说真的 爽肤水这种东西也就补补水 二次清洁一下 为后续保养做准备（重要的还是精华）

4.眼霜／眼部精华

最近很喜欢这款 the ordinary的咖啡因眼部精华 

对于眼部去水肿 简直是神效 

5. 精华（细化毛孔 抗老 祛痘印）

雅思兰黛的新版小棕瓶 和兰蔻的小黑瓶一起买的 用了一段时间后

我觉得还是小棕瓶更适合我 当初也给我妈带了2瓶 她反而更喜欢小黑瓶 所以护肤真的是甲之砒霜乙之蜜糖

用了一段时间后 能感觉皮肤明显细腻了 感觉痘印好得比较快了 然后皮肤状况比较稳定了 虽然可能有的人会说 你才21岁 用这个会不会太早了 我不这样觉得 看个人肌肤需求吧 而且我觉得现在做些抗老挺好的 总比等你有了细纹再去做的好 

有时候我会搭配着这款the ordinray的Niacinamide 来使用 也就是烟酰胺 

众所周知 sk2非常喜欢用烟酰胺这个成分 美白效果非常明显 

之前olayx的小白瓶就号称sk2小灯泡的平价版 我用过以后 觉得效果一般 

这款the ordinray 烟酰胺的浓度在10% 而小白瓶只有4%

相比较 我觉得这款见效非常明显 用了一个月以后能感觉到皮肤明显白了一个度左右 而且皮肤非常有光泽

同时它也是一款猛药 敏感皮千万要慎入 一般我都会先稀释过后再使用 

总得来说还是很推荐的！毕竟100rmb不到 能买这么一大瓶精华 拿来擦脖子也不亏是不是！

6.乳液／面霜 （修护）

这款是杜克的Epidermal Repair（表皮修护）霜

之前用高浓度 烟酰胺的时候 没有注意好浓度 结果第二天皮肤就不耐受了过敏发红脱皮

后来用了这款以后 大概2天 就完全消下去了 虽然这款有点略贵 但我觉得还是非常值得在家里备一支的 在你皮肤状态不好 或者受损的时候 可以拿出来救急 而且也不油腻 非常清爽 保湿效果也不错 

7.涂抹面膜（补水保湿）

一般我会把这个放在洗完脸以后 涂上10分钟 然后洗掉 接着开始上喷雾（但不是每天都会用 所以放在最后）

这款涂抹面膜是我回购得最多也是最喜欢的一款

使用以后皮肤状态非常好 甚至可以用在妆前 敷个10分钟 然后再上妆 就不会再卡粉

这就是我最近的护肤步骤和使用的产品 

希望能帮到你 

还有一点 也是最重要的 睡眠！！！早睡！！不熬夜！！！不然都白搭

不要学我 用最贵的护肤 熬最狠的夜！

如果有什么皮肤上的问题 欢迎给我留言 

最后谢谢观看

终于又填完了一个坑  ️刚考完试就来填坑我也是不容易 

之后应该还会测评美容仪 或者新买的一些护肤品以及以前用过的一些好用的彩妆 和曾经的爱用护肤品

有兴趣的可以关注一下 

老规矩 如果你觉得有帮到你 就点个赞呗～
编辑于 2017-11-05
KIKI
KIKI
微博@炸尾喵 痘痘肌种草 | 不定期唠嗑

9月4日持续更新

痘痘后遗症之毛孔痘印对策
https://zhuanlan.zhihu.com/p/28836358

之前写了了针对各种痘痘的祛痘篇
https://zhuanlan.zhihu.com/p/28638869

我是一个特别容易长痘的油皮，认真的写了关于这些年祛痘过程中对于这些产品的使用心得，特别关于A酸这方面，特意强调了谨慎使用，尽量避开全脸涂抹

然而有评论质疑为什么A酸不能全脸使用只要建立耐受全脸用了也挺好呀，硫磺皂为什么不能洗脸等

看到这里，我只想说一句，你们都是混过果壳美组的吧→_→

上高中那会我经常混迹于此，每每看到那些刷酸的科普惊为天人，完全给我打开新世界的大门，于是我果酸水杨酸A酸杏仁酸都往脸上抹（当然不是所有一起抹），哪里有问题哪里就涂哪里，效果的确很好，用最短的时间扫荡了我脸上的闭口粉刺，消除我脸上红肿的痘痘，我也自觉建立了耐受，欢快地刷酸

可是尽管如此，我还是一直断断续续长痘，脸上时不时就会闭口粉刺一片，还是会烂脸，别人会真的很不解的问我，为什么你用的东西这么多，皮肤却还是不好？

是啊我明明都用这么多好东西了，为什么我的皮肤还是不好？我一晒就容易刺痛爆痘，皮肤总是很油，脸上经常泛红灼热，鼻头下巴周围一片粉刺黑头。

到底是什么出了问题？直到我看了这篇

rox大神的角质层养护科普长文（答应我就算看不懂也一定要认真做功课）
http://blog.sina.cn/dpool/blog/s/blog_682c43f20101iwlh.html

其中传达了一个重要的理念就是，保养一定要从角质层开始，只有健康良好的角质层，才能让其它一切保养升华，只有角质层水油平衡，厚薄合适的时候，后续保养效果才能最大化，健康的角质层这类皮肤通常自我保湿能力较强，不易敏感发红，抵抗外界伤害较强；良好的自我分泌调节，也不容易产生黑头闭口痤疮等问题。

无论是是毛囊炎，也就是俗称的闭口粉刺痤疮，还是脂溢性皮炎，玫瑰痤疮等，因为反复长痘发炎造成皮损，皮肤已经相当脆弱，长期刷酸虽然有效抑制了当时的发炎感染，但是鉴于自身对皮肤角质层刷酸量的把握其实不那么专业，其实反而容易加剧问题皮肤屏障的受损，使得角质层愈发脆弱，免疫力下降，容易产生皮肤问题，并不是说刷酸不好（我写的祛痘文里大部分都是各种酸），大家都别刷酸了，而是注意刷酸过程中要配合屏障修护

看看rox在文章里写的测试

如果有上述行为超过三种，建议应该改改护肤的习惯。当然会有人跳出来说我一直都用皂基洗脸，我一直都在刷酸皮肤超级光滑，人家范冰冰每天敷面膜皮肤皮肤不是挺好的吗，我不想和你们抬杠→_→。确实无法用一种护肤理念对应所有人的情况，但是没有表面的问题不代表你的皮肤在最佳状态，如果改掉这种行为，试试更温和更精简护肤理念，就能让你的皮肤变好，为什么不试试呢？


反正都买都买了总要用完的全家福镇楼


上到一千多，下到几十块钱，有的特别难用，只是秉着中华民族勤俭节约的美德没扔，只选对的不选贵的，证明我后面推荐的东西并不是为了追求便宜哦

因为懒得再一个一个拍照(￣▽￣)~*，都用网上找的图吧（侵删）

黑喂狗
————————————————

护肤的第一步从洗脸开始

有木有看过wuli 景甜的代表作（大误）洗脸视频，大甜甜素颜皮肤白嫩光滑细腻，是小仙女本仙没错了，她也说了护肤特别重视清洁，所以

敲黑板划重点啦小葵花课堂开课了(•̀ω•́)✧

相信大家多多少少都听过氨基酸洁面，其最大的特点就是高效清洁的同时，温和亲肤，低刺激，小孩和敏感肌肤都可以使用。氨基酸洗面奶采用的则是弱酸性的氨基酸类表面活性剂，PH值与人体肌肤接近，加上氨基酸是构成蛋白质的基本物质，不但适合痘痘肌肤的MM使用，更是为数不多的敏感肌肤也可以放心使用的清洁产品（来自不靠谱百度百科不要相信啊喂），如果是干敏皮，用氨基酸洗面奶也会带走皮肤的水分和油脂，建议还是用清水或者无泡洗面奶洗脸

市面上也有很多打着氨基酸旗号的洁面产品，比如这一款

我们来看看它的成分表


虽然打着氨基酸的旗号，但是没有一个氨基酸表活，主要清洁成分仍是皂基

再来一款大热的芙丽芳丝，真正的氨基酸洁面


由此得出结论（不要问我为什么这么早就得出，懒得再找图片了→_→）

当洁面产品出现
肉豆蔻酸，硬脂酸，月桂酸，氢氧化钾/钠，SLS,SELS等位置靠前，作为主要清洁成分时，基本还是一款传统的皂基洁面，不论后面添加了多少所谓的氨基酸，长期使用会加剧皮肤干燥，敏感，长痘等状况。

清洁成分是--xx酰xx酸钠/钾，才能称为氨基酸洁面产品，甜菜碱也是温和的表活哦

如果你和我一样是敏感痘痘肌，可以拔草：
资生堂洗颜专科，悦诗风吟绿茶洗面奶，AHC的B5玻尿酸洗面奶，花印水漾洗面奶，Beauty Buffet牛奶洗面奶，雅诗兰黛红石榴洁面等等皂基洁面产品

所以正确地洗脸方式，用接近人体温度的水，把洁面产品用手搓出泡沫，轻轻带到脸上稍稍按摩一下T区，不到一分钟后，用水冲掉，而不是手大力搓掉泡沫

如果细致点，早晚都应该有适合的洁面，特别是我这种爱长痘又敏感的皮肤，个人比较偏向晨洁无泡，夜间泡泡的洗脸方式

欧树蜂蜜洁面凝胶


早晨皮肤虽然油，对比晚上回家有彩妆和一天的灰尘，皮肤整体还算干净，没有泡沫，香香甜甜的蜂蜜味，乍一用觉得太甜腻，后来习惯了觉得还挺舒服，大早上朦朦胧胧能被甜甜的味道唤醒也还不错

至本舒颜修护洁面乳

号称芙丽芳丝平价替代，确实非常温和，泡沫绵密，清洁能力不错，能把脸洗得很干净又不会很干

———————我是分割线———————

一个小测试，如果像我一样经常，皮肤经常有一块泛红的，进出气温相差较大的地方容易脸红，夏天太阳一晒就刺痛泛红，冬天进暖气房就脸红，情绪激动也脸红，鼻头很多黑头总是红红的，很有可能是中国几亿个患者里面的玫瑰痤疮哦，玫瑰痤疮并没有搜出来的图片那样恐怖（知道你们肯定去搜了），但是反复潮红，长一些丘疹脓包是很多人都有的，并且脂溢性皮炎，毛囊炎并发也是常态

以下是微博@美妆情报局提供的2017年最新的判断玫瑰痤疮症状https://m.weibo.cn/6177004357/4134517662685210

如果严重的话一定要去看医生啦，轻微的，比如我，按照皮肤屏障受损来护肤，可以补充皮肤天然就有的组成部分，如神经酰胺，天然保湿因子，天然生长因子（EGF），多元醇等来达到修复皮肤目的

市面上针对干敏皮的修复产品太多了，国外有
珂润，施泰福，Cerave，伊丽莎白雅顿等，国内的玉泽，薇诺娜，启初等（干敏皮可以默默打开某宝了）。但无一不是乳霜，乳液这一类，特别是雅顿对油皮最丧心病狂，直接都是面油了。可是我这个油敏皮可是涂一层乳液都能糊在脸上亮瞎的自带闪光灯，所以下面的产品都是我喜欢的清爽不黏腻的水或者精华 (•̤̀ᵕ•̤́๑)，以下都有药监局备案

上水和肌修护生肌水




上水和肌肌底液


上水和肌的生肌水和肌底液，大概回购了三次瓶，没有酒精没有防腐剂没有矿物油（大声念出来），重点是非常清爽！拍在脸上都好苏胡，特别舒缓，刷酸干燥皮屑和太阳晒的灼热的皮肤基本当下就可见效，大概用完一瓶后，皮肤就不会经常发痒灼热了，之后熬夜也不会轻易爆痘了，粉刺和闭口再也没有了（骗你是小狗），皮肤不会容易刺痛泛红啦，原来皮肤屏障修护后，整体感觉皮肤细腻光滑，状态很健康，并且油皮和干皮都适用

艾诗可因修复肽egf冻干粉生长因子精华液



这名字取得也太野鸡了，导致我一直有种莫名的嫌弃（都不好意思给你们推荐），之前偶然看到微博皮肤科医生推荐了，认真研究了一下，原来是专门做EGF（寡肽），学名人体表皮生长因子，正儿八经的各大医院在用的医美品牌。主要针对敏感，红血丝，激光术后，晒伤等问题。

我是用来在使用高强度的美白抗衰老（强调一下抗衰老不分年龄哦）产品后喷一喷舒缓，增强皮肤屏障，高浓度的EGF甚至对于皱纹和痘印痘坑都有一定改善（划重点是高浓度），总之是个好东西，但是其活性物很难保存，对技术有着非常高的要求，价格也居高不下，但是市面上有很多野鸡牌号称EGF冻干粉，卖的很便宜，大家不要被骗啦。

———————29日更新——————

人生的前二十年，我基本有七八年都在为皮肤操心，不论是早些年网传珍珠粉蛋清，中药血毒丸，中药自制面膜，各种奶奶辈只出现在网络里的国货，还是后来刷酸用抗生素，断断续续痘痘就没有彻底好过，虽然不是很极端的满脸大包，但是对于爱美的纯真少女（？？？）来说已经是人生头等大事了

尤其是偶尔烂脸的时候，一度让人产生自我怀疑，别人用个强生婴儿霜都能肤若凝脂，我在这天天折腾到底是为了个甚啊ヽ(#`Д´)ﾉ，这时候还有一些不明真相的围观群众跑出来（尤其是我爸），天天用这些皮肤也不好！你这么年轻用这些这么多对皮肤不好！这些化学品弄在脸上如何不好对我进行惨无人道的指责

每次都在内心怒嚎你懂个p

要知道我也只是用个洗面奶水乳液精华而已（虽然剁手的确实很多），我烂脸，可是我想皮肤变好的心比任何人都迫切啊(｡･ˇ_ˇ･｡)

吐槽到此完毕，接下来就是正在烂脸的各位准备的干货，去医院做过好几次果酸换肤，最后一次百分之五十浓度的时候，华丽丽爆痘了，整个过程大概如烟花般绚烂（大误）持续了三个月才彻底平复，当然中间也走了很多弯路，所以下面的都是精华，快拿小本本记好(•̀ω•́)✧

蓝润蓝科肤宁医用愈肤生物膜水剂活性敷料

如果是严重的烂脸，比如满脸痤疮，或者脂溢性皮炎，玫瑰痤疮，激素性皮炎，皮肤科医生都会开给患者用来湿敷
［主要成分是原花青素，还有壳聚糖。其中原花青素是非常强效的抗氧化剂。有很好的消炎，对抗过敏，去肿的作用。壳聚糖的保湿功效非常强，而且自身携带正电荷，可以有效的杀死皮肤表面的微生物。］摘自皮肤科李远宏医生微博


芙清FQ抗菌功能性敷料凝胶面膜

还是医美产品，没错我就是很喜欢用国产医美产品，要技术有技术，要疗效有疗效，要包装没有包装(｡・`ω´･)，但是比微博代购炒疯的韩国面膜好用多了，完全不是一个档次

这个成分表我一直没有看懂过，味道和颜色说不出得诡异，但是懂行的人说含有广谱抗菌肽，已经用了两盒，对脸上成片发的小红疹子，小脓包，轻度的皮炎泛红效果非常好，脸敷几天皮肤立马镇定下来了

可复美类人胶原蛋白敷料


［西安交大巨子集团产品，为我国星火计划的科研成果，是类人胶原蛋白。利用人的胶原蛋白的基因，转到大肠杆菌的基因组里，通过细菌发酵技术生产的胶原蛋白。因为人的胶原蛋白肽链，所以外用可以吸收］——还是李远宏教授微博

专供医院的医美品牌可复美，医学护肤品可丽金，都是一个同公司，所有产品主打类人胶原蛋白（至今没有懂这个是什么），我皮肤最不好那阵不但爆痘而且灼热发痒，这个修复能力确实非常好，肉眼可见那种第二天醒来皮肤水润，而且舒缓通透，而且可丽金有专门针对油敏痘痘肌肤的修护面膜，对于一个不是在祛痘，就是在祛痘印的痘妹，冰箱常备几片以备不时之需 (•̤̀ᵕ•̤́๑)

法国URIAGE/依泉舒缓保湿喷雾


［打来自阿尔卑斯山的依泉等渗活泉水，与人体细胞渗透压相等，更容易吸收，无须拍干，也不担忧如其他活泉喷雾般不拍干自然干化后皮肤反而有收紧感。强健肌肤屏障，11g/L的高矿物盐含量，味道微咸，多种矿物质达成舒缓镇静修复抗氧化效果。］  ——   摘自我妇女之宝              
说白了就是水，主要是屈臣氏经常打折而且比雅漾便宜(￣▽￣)~*



总得来说，常在江湖飘，哪能不烂脸，早睡早起好，护肤要精简

—————摘自答主一段freestyle 

保持良好的心态，烂脸时期撑伞戴上帽子口罩无死角防晒，不要化妆，早睡早起，过了这段时间还是小仙女

————————9.4更新——————

痘痘肌油敏皮维稳篇，干敏皮也可以做参考

我前几天还在嘚瑟快小半年没长痘了，没想到上个礼拜因为丧心病狂的熬夜和肆无忌惮的饮食，脸上长了一个巨大的包，也就是囊肿痘，下巴那也起了一堆小红包(҂⌣̀_⌣́)

这就是自作自受本人了

因为皮肤出油严重，很容易就角质层不通畅堵塞毛孔，隔一段时间就会去正规三甲医院果酸换肤，这小半年因为自以为皮肤好就疏于这些特殊保养，没想到这么快就来打脸了(Ｔ▽Ｔ)

所以周末又去医院刷酸了，赶紧用喷雾，睡前敷了一张面膜，第二天那个脸光滑通透呀，虽然大包依然屹立不倒，但是下巴那隐隐约约本来要发的痘痘已经没了，脸上又白皙又光滑，是小仙女本人没错了！（大误）

之前刷酸修复的面膜都是医院开的创福康或者薇诺娜，虽然也很好用，可是没有这么惊艳

可丽金类人胶原蛋白健肤喷雾150ml


不是雅漾依泉那种矿泉水，主打的还是类人胶原蛋白（可溶性胶原），还有资生堂红腰子吹上天的B葡聚糖。官宣修护屏障受损，抗敏感抗刺激，补水锁水。我最大的感受就是缓解刺痛泛红非常之舒服，喷头的喷雾非常细腻啊，应该还会回购。

可丽金类人胶原蛋白健肤修护蚕丝面膜


修护能力简直抵得上十片创福康，成分表里的泛醇就是维生素B5，用于皮肤修护，神经酰胺也是修复届的好手。没有市面上普通面膜普遍各种高分子胶堆砌然后糊一脸的黏腻感，贴完可以不用洗脸。第二天醒来后皮肤状态简直让我有不化妆就出门的冲动（幸好后面劝住了自己），我应该一直会回购，用于刷酸或者晒后修复。


艺霏虾青素 莹润修复精华液 

来自皮肤科医生推荐，主要成分是虾青素，神经酰胺&玻尿酸，抗氧化的同时也有修复强健皮脂膜的功效，敏感肌用起来也完全没问题。让我最喜欢的是使用感，质地更清润，非常清爽薄透易吸收，抗红抗衰老提亮都能一步到位，可以说是今年发现的爱用品前三了



九千的收藏和两千的赞真让人想哭(Ｔ▽Ｔ)


微博@炸尾喵，会不定期分享购买的东西和反馈，但是不要跟着我盲目瞎买哦╮(︶﹏︶")╭
https://weibo.com/u/2140137830
看心情持续更新吧
To be continued
编辑于 2017-10-10
咖啡怪
咖啡怪
唯香烟与护肤不可辜负

我要来给大家安利一个超级好用的公众号  微信搜索：美丽修行  中国第一个可以查询化妆品成分的手机端  可以搜产品查成分  也可以搜成分查产品  每种成分还有相应的注解  产品成分与药监局备案同步  不用担心有假  真的非常好用  目前APP正在开发中  （不要再上cosdna了  因为我查到过赤裸裸的假成分表）
又来更新了  原答案中我也有很多不严谨的地方  随着我不断地学习我也一直在发现我以前的误区  如果误导了哪位知友在这里先说个抱歉   最后  护肤品个体差异大  种草需谨慎


紧急更新！！新美肌祛黑头露被查出含有激素！！请各位不要购买！已经购买的请立即停用！！！原答案中关于新美肌的推荐已经删除

-------------------------------------------------------------第四次更新  有小伙伴要我讲讲防晒～
紫外线中的什么A波B波我就不讲了已经被说烂了
防晒的两大基本体系是物理防晒和化学防晒  物理防晒易泛白  化学防晒易油腻  现在比较通用的是物理+化学
防晒的奥义在于涂够量  涂够厚  及时补涂  参考用量是一张脸一粒骰子大小的量  如果是日常生活我觉得没有必要补涂太频繁  中午补一次就好了  
我个人选购防晒霜的条件是：可以轻微泛白但不要太严重  最最重要的是清爽不油腻  保湿我到没什么追求毕竟我又不拿防晒当保湿霜用
不多说了  上干货
1.安耐晒小金牌
这个都被说烂了我就不上图了  上脸不油腻  防水效果好  SPF50防晒系数很高  适合夏天易流汗或者去海边的时候使用  用前摇一摇喔～
2.佳丽宝ALLIE防晒
据说有个什么创新的扁平锌技术  涂不均匀也可以防晒  同样上脸不油腻  分好几个颜色不同功效  拿来涂脸涂身体都棒棒哒～

3.SOFINA防晒
这个牌子的有好多防晒我到现在还没分清  但是每一款都不油腻可以放心选购  他家最出名的是控油隔离  价格比上面那两个都便宜  在台湾屈臣氏里完全就是白菜价  使用感受比小金瓶更清爽！！！

4.水宝宝
这个没什么好说的  之前看过成分控解读说水宝宝都不好  所以我只是拿来涂身体  从来不上脸

5.妮维雅防晒乳
不多说了  便宜大碗  还好用  拿来涂身体再合适不过了


—————————————————
反对
@莫嫡
的部分答案  他提到少用粉类  因为含有二氧化钛和滑石粉会致癌  二氧化钛和滑石粉确实是致癌物没错  但是要看吸入途径  滑石粉经过生殖道或者肺吸入才会致癌  所以爽身粉中的滑石粉才会被玉米淀粉所取代  但问题是你平常上个粉底液都能上到生殖道里去我也是醉了  也没见人拿着粉底液大口往肺里吸吧  况且大品牌的添加量都是在安全范围内的  抛开剂量谈危害的都是耍流氓
二氧化钛也是要经由肺吸入才会致癌  况且二氧化钛还是一种常用的物理防晒剂  反正我是没见过有人拿着防晒霜吸入肺的  还是那句话  抛开剂量谈危害的都是耍流氓  防腐剂的添加也是这个道理
关于防晒：他说上班下班或者在室内不用涂防晒霜我更是不能赞同  众所周知防晒的重要性  我曾经看过资料表明80%的皮肤问题来源于日晒  紫外线中的UVB使皮肤晒伤晒红  不能穿透玻璃  而UVA使皮肤晒黑晒老  可以穿透玻璃  所以室内也是要防晒的  况且我们防晒防的是紫外线  不是防阳光  不要以为没有阳光就没有紫外线！！
关于防晒霜的危害问题  我保守一点说  其实我觉得化妆品对皮肤多多少少是有危害的  但绝对利大于弊
这么多年的小白鼠不是白当的  我不是专业的  但也查阅过大量权威资料  请相信科技改变生活！！
以上就是我对
@莫嫡
部分答案的反对  个人意见  爱信不信
—————————————————
最近天天熬夜我居然开始爆痘了  还好我有城野医生富氧面霜（后面会说）这是我近期发现的一大好物
不要再让我推荐适合某某肤质的洗面奶了  洗面奶除了清洁不要指望会有其他功效  任何肤质都一样  对皮肤刺激小的就是好的
先说一下  我推荐的不一定就是好的  我只是在分享自己的护肤心得而已  哪怕你跟我肤质一样  我推荐的东西你也不一定适合  so 不喜勿喷  个体差异很重要

【洁面】
油性肌肤因为油脂分泌旺盛 所以如果清洁不当很容易堵塞毛孔 针对你毛孔粗大的问题 我给你推荐以下产品
其实没有必要一定要选用氨基酸洗面奶  有很多皂基+氨基酸的洁面产品已经大大降低了刺激性  况且很多大品牌的工艺可以把皂基做得很温和
1.石泽研究所苏打洁面乳/洁面粉
这个苏打系列对毛孔粗大很有效 分为洁面乳和洁面粉 洁面粉的功效比洁面乳要猛 所以建议每周二到三次 所以如果你毛孔问题比较严重建议选择洁面乳 这样可以每天用
单价在百元左右 目前没有见到专柜 可找靠谱代购 谨慎淘宝

2.肌研 极润泡沫洁面
适合敏感肌肤 挤出来就是泡沫 不会伤害肌肤角质 添加透明质酸 有效保湿 用完以后皮肤那叫一个滑啊
单价百元 屈臣氏有售

3.旁氏米粹
看过知乎上各种大神各种成分控都推荐过了  确实是氨基酸洁面没错  马上冲去屈臣氏败了一瓶  哎哟真的是白菜价啊20块不到啊  业界良心啊洗完后不干燥不紧绷  马上抛弃所有洗面奶  以后就用它了
唯一的缺点是清洁力不是太强  大不了洗两遍就OK了啊这么良心的东西上哪找去啊（其实氨基酸洗面奶清洁力普遍不是太强  太强的那是皂基）  



【化妆水】
因为你的皮肤外油内干 关键是要补水 选择一款补水能力强大但是不油腻的水很重要
1.科颜氏高保湿清爽水科颜氏家的东西只要根据肤质选对产品 基本上都是值得回购的好产品 这也是科颜氏广告少还这么火的原因 这个高保湿清爽系列包含洗面奶 水 啫喱面霜 补水效果卓越 并且一点也不油腻（科颜氏还有个系列叫高保湿系列 不要混起来）
单价185元/250ml 专柜有售

2.肌研 极润保湿化妆水（清爽型）
肌研真的是良心品牌 全线产品主打保湿和去角质 好用还不贵 没有钱的初中时代曾一度对它爱不释手  这款化妆水补水能力卓越 上脸就能感觉到 用后真的很润并且不油腻
单价125元/170ml 屈臣氏有售
（注意：图片是滋润型 油性皮肤请一定选择清爽型 买的时候看好）

3.科颜氏金盏花水
科颜氏家明星产品 也是科颜氏最贵的水 补水能力比前两个都好 并且兼具去痘印的功能 非常适合油性皮肤夏天使用 但是注意千万不能用来湿敷 因为敷久了会让你的皮肤变成金盏花色
单价330元/250ml  专柜有售

4.SK2神仙水
神仙水之所以这么贵 主要是因为它针对肌肤可以做一个全面的修复 什么痘印啊暗淡啊出油啊都可以搞定 控油和去痘印能力非常卓越 单价700+ 如果它超出了你的预算也可以不买 因为还有替代品
电视上天天都在放广告所以我就不上图了

5.IOPE神仙水
对 就是那个气垫BB霜很出名的那个IOPE 就是星你里面那个IOPE SK2的替代品 功效可以和SK2媲美 但是价格只是一半 单价六万韩元 和三百多人民币 国内好像无专柜 请找靠谱代购

6.城野医生毛孔水
淡淡的柚子香味啊  冲这点我就满足了啊  上脸凉飕飕的  夏天使用超爽的好吗  我本身是没有什么毛孔的  所以也不知道效果  有毛孔的可以试试  城野家的东西我本人非常喜欢  特别是美白系列

7.城野医生O2富氧水
健康水的大名我就不用对说  这款号称平价健康水  我本人没有用过  但是用过同系列的面霜  简直是棒到不能再棒  所以我猜想水可能也不错  面霜具体我后续会说

【乳液】
乳液与面霜相比含油量较少  质地清爽不油腻 油性皮肤除了冬天就尽量用乳液不要用面霜了
1.悦诗风吟绿茶籽精华
韩国国民品牌之一 质地与兰蔻小黑瓶相似 就像鸡蛋清一样 补水很好 非常轻薄 完全不会油腻 口碑与销量一直很好
单价210元/80ml 专柜有售  靠谱代购也行

2.悦诗风吟绿茶乳液
悦诗风吟的这个绿茶系列都很好用 主打保湿 非常适合预算有限的顾客 因为真！的！很！平！价！
单价120元

3.it's skin蜗牛乳液（清爽型）
妈蛋真的好清爽啊真的是油皮真爱啊啊啊啊  主打修复祛痘印什么的  但是对于我来说效果不明显  一瓶用下来也就无功无过  不过确实清爽不油腻


市场上的乳液实在太多了 这几年用下来感觉主打保湿的乳液也就都一个样  无论大牌杂牌 题主有时间自己买些小样回来试下 找到自己最喜欢的那一款 不想试的话 悦诗风吟绝对是最好的选择

3.【面霜】
面霜可能会比乳液有一点  但是冬天的话没有油会很难保湿 千万注意 补水和保湿是两个步骤 不要混起来
1.it's skin蜗牛面霜
此款面霜主打保湿 修复功能 也是韩国人气产品 刚涂上去可能会略显油腻 但是没事过一分钟就会完全吸收一点也不油 如果还是嫌油的话可以晚上用白天不用 
单价六万韩元 合三百多人名币 国内无专柜  可找代购
但我身边也有朋友反应太油腻不吸收  请大家谨慎选择

重点是包装真的很好看！！（谁让我是外貌协会呢～）

2.珂润保湿霜
日本牌子 在价位实惠的基础上 保湿能力非常不错 涂上一层能感觉到它在但是一点不油腻 油性皮肤福音
单价折合120人民币 请找代购

3.城野医生富氧面霜
重点来了  改变人生的面霜！！15种植物精华  20种天然精油  干燥暗沉粗糙痘痘都解决了  虽然是面霜但是是果冻质地 缺点是稍显油腻   我会一直回购

【面膜】
面膜太多我就不一个一个推荐了
敷面膜真的有用 我曾经有段时间一天一张面膜然后真的感觉脸不那么油了 出油明显减少了 但是一定要坚持
保湿面膜就好 别指望一张二十分钟的面膜就能让你美白抗老什么的
韩国的可莱丝啊丽得姿啊中国的美即啊美丽日记啊不管什么牌子多囤几天 囤个一百片放冰箱里然后天天敷 相信我坚持下去绝对有用！绝对！
撕面膜的时候记得从下往上撕
还有清洁面膜 油性皮肤一定要做清洁面膜 科颜氏的亚马逊白泥面膜 贝斯佳的绿泥都是很好的选择 但是贝斯佳的绿泥上脸会痛 

时间关系就写这么多啦 喜欢的话请给我点个赞 希望我的回答可以帮助题主 推荐给你的都是些平价好物 还有什么护肤问题也欢迎大家来问我

——————时间分割线—————

看到这么多赞真的很开心  周末我再来多补充一些回答
————————————————
【清洁面膜】
所谓清洁面膜  就是深层清洁皮肤的面膜  在空气污染严重的年代  不管是爱长痘还是不爱长痘的皮肤都还是很有需要选购的 但是清洁面膜的普遍缺点是偏干 且多带有轻微去角质的功能 所以做完清洁面膜最好再敷个补水面膜 可能有些耗时 当然不做也没关系 注重好后续补水程序即可 一周两次为上限 角质层本来就薄的朋友一周一次就够了
注意：清洁面膜一定要厚厚地敷 完全盖住皮肤为佳
1.科颜氏亚马逊白泥面膜
没错又是科颜氏  科颜氏珍爱一生推 这款白泥面膜口碑极好 算是众多清洁面膜中比较温和的一款 刚上脸会有些许刺痛 没事过一会儿就好了 清洁力不错 有收缩毛孔的作用 
单价240～280人民币

2.贝斯佳绿泥
这个敷上去真的很！痛！ 但是号称世界上最好的清洁面膜 好吧虽然我个人觉得科颜氏白泥完全可以替代它 但在价格方面它还是有优势的
价格一百多元
耐不住痛的亲们出门左转科颜氏～

3.悦诗风吟火山泥面膜
同样都是清洁面膜也没什么好说的  这个的优点是价格非常非常非常美丽
价格：109元  天猫官方旗舰店有售  韩国的价格是国内的一半

5.台湾DMC黑里透面膜
唯一一款果冻状清洁面膜 但是我个人非常不推荐 因为很费 看起来一大罐实际敷几次就没了 而且敷一次要一个小时 还不能洗要用小勺刮掉！尼玛角质层都给刮薄了！！价格175元也没有多美丽！！
因为不是特别推荐所以就不上图了

【关于一些护肤心得】
1.我个人对网上说的冷热水交替洗脸持怀疑态度 我觉得用温热水清洗最为适宜 水温不能过烫也千万不要过冷 以手腕试水温最科学最准确
2.洁面真的很重要 早晚都要千万别忽视 还有 特别是要美白的亲们和痘痘肌请一定重视洁面！
3.如果你觉得护肤品眼花缭乱不知从何下手 那你先做好保湿就可以了 充分补水保湿 怎么保湿都不过分 再次说明 补水和保湿真的是两个问题啊！！！
4.除了面部护理 手部脚部身体护理同样不可忽视 
5.彩妆我是真的没有接触过！千万不要来问我！！
6.手部特别干燥的 去超市买一堆便宜到爆的袋装美加净啊隆力奇啊郁美净啊 晚上厚厚的涂一层 然后戴上塑料手套睡觉 第二天你会发现你的手换了一层皮！！坚持下去有！奇！效！（我一般喜欢三种混在一起涂 超市一两块一袋涂多少都不心疼 买质量好的塑料手套可以多次连续使用）
7.护肤真的是一个漫长的过程 别指望单靠护肤品 调节身体也很重要
心得暂时只想到这些 以后想起来还会来补充的

以上都是我的心血啊！对你有帮助就点个赞在再呗亲（≧∇≦）
还有能不能不要反驳我的推荐  我都说过了甲之蜜糖乙之砒霜  这很正常  每个人肤质都不一样  我推荐的都是我觉得好的你觉得不好也没必要来跟我吵OK？
编辑于 2016-08-22
凌暴暴
凌暴暴
懂美妆，尤其是营销。业内出身的野生KOL
看到几位点赞数很高的回答，列举了很多。我就针对你的问题做几点补充：
1. 之前不太护肤+油皮+爆痘，有可能角质比较厚，但你又说到是敏感肌。那么有两种情况：要么你局部敏感，比如脸颊，同时T区角质厚，毛孔明显；要么你不是真的敏感，只是用了不合适的产品。区分方法看你是否局部皮肤偏红偏薄，有的话就是第一种，没的话可能是第二种。
2. 偶尔爆一两颗痘在北京这种空气不好的地方很正常，或者跟你休息不好有关，这个基本不用花大力气，主要要解决的是调理肤质、收毛孔及淡化痘印的问题。
3. 关于调理肤质，外油内干的话就是一周敷三次补水面膜（面膜要看是否适合自己，建议去柜台试一下，如果懒的话我推荐蕾舒翠、卡尼尔，这两个配方不错也不贵。虽然卡尼尔退出中国了，但可能还是买得到）。面膜之外，这个天气你肌肤敏感、又要控油的话可以用薇姿的绿色系列。但一定还是会出油，需要配合面膜慢慢调理。
4. 关于收毛孔，其实毛孔真的很粗的话基本是很难收小的。比较好的办法是首先清除里面的黑头，因为有明显黑头会让毛孔看起来更大。。。黑头清除基本靠毅力。用清洁类的面膜敷在鼻头（推荐羽西的一款净化面膜（200多）、科颜氏的亚马逊白泥），但切记敏感的话只敷有黑头的地方。解决黑头之后，如果你毛孔粗的地方不是敏感的地方，可以用一些有水杨酸的、收敛的精华或水（比如Fancl的一款毛孔收敛精华）尽量控制毛孔大小。但如果毛孔粗的地方也敏感，就不要去动它了，基本所有收敛毛孔的产品都有刺激性的。
5.关于痘印，痘印和有炎症的痘痘是不一样的。如果像你说的临时爆痘，且是红色当中有白点的那种大痘，推荐用理肤泉的A.I.，局部涂在痘痘上，不！要！抹！开！基本两天就消，但不要用在没痘的地方，因为很刺激。关于痘印的话，推荐一个香港能买到的“喜疗疤暗疮疤痕专用配方”（129港币），名字有点土但很！有！效！
其他的目前从你的肌肤描述中还看不出，有问题的话可以补充。
发布于 2015-03-17
anne
anne
:)

烂豆5年，混合皮，粗毛孔来回答。
nononono：
1.去医院皮肤科，西药中药吃的涂的，垃圾，没用。
2.去美容院or民间有名私人诊所，买整套产品，清痘，痛到你怀疑自己为啥生而为人。清完你自己看镜子都会哭，更加严重！什么挤干净了就好了，放你麻痹狗屁。脸完全受伤废了，破坏自己的表皮组织。
3.香港药店买一堆涂痘痘的药膏。有一点点用。一瓶药用到后来基本就产生抗性了没啥效果。油皮的就不要再涂油啧啧的精油了，好吸收的，涂的时候划圈轻压。注意不要交叉感染了。
yeyeyeye：
1.枕头套常换。睡前洗头。你知道多脏吗多脏吗不洗的话！
2.bb霜扔了吧。闭合一堆我保证。
3.不要晒太阳。长痘的绝对知道脸皮火辣辣燥热的感觉。出门伞啊帽子啊墨镜啊扇子啊。防晒霜涂清爽的，不然又是闷出痘痘。隔离不错。要卸妆。推荐fancl。
4.手机接电话。屏幕你知道多脏吗。注意。
5.手脏不要碰脸。
6.fresh黑茶面膜我爱你。镇定好帮手。
7.森田补水面膜用啊用啊。
8.保持出汗运动，每天排便。

现在比以前的烂脸好太多了。
晒斑是基本没救也不打算救了。以后考虑高科技救。
狂吃花生巧克力油炸各种，过几天一定有报应。
鼻头粉刺看情况用导出液清。
痘印有的话多吃猪蹄。

危言耸听：
1.谈恋爱皮肤会变好。放屁好吧，每天晚上聊电话那么晚睡能好？约会各种吃喝能好？对象要是不注重卫生也是烂脸，螨虫会交叉感染你不知道？不一定的啊。
2.这药非常好用，某某用了就完全好了。每个人体质情况不一样的，不一定的。
3.我运动了痘痘反而严重了。流汗排毒是真理是上帝。你是不是毛巾不好，你手脏你摸啊摸。很多原因的，你不要怪罪运动。
4.怀孕了女的话你皮肤会好，男的就会烂脸长豆。放屁好吧，就我周围而言还有自己亲身怀孕而已，怀孕前皮肤就敏感就经常长的怀孕时也会长、结果生了女儿。怀孕前就皮肤好的怀孕时也好，而且因为休息多了补品吃多了皮肤完全亮的，结果生男生女的都有例子。我自己状态是偶尔长，所以现在也是偶尔冒几粒。
5.燕窝吃了皮肤好啊。哦呵呵，那世上就没人长痘了。跟这减肥药有用啊一样，真有用哪里还会有这么多胖子。反正普通人不可能一周两次，那我自己也没有一周两次过不好说。偶尔喝反正我觉得没啥用。
6.熊胆吃了排毒啊。黄莲喝了去火啊。这个我觉得有点点用。



皮肤25岁以前是妈给的，25以后就是环境和个人习惯了。
每个人长痘情况不一样，保持好心情自己折腾相信自己肌肤的复原能力。一定会好起来的。抗痘路上很孤独的。要坚强。

毛孔啥的很慢的。肤色啥的靠饮食作息了。
路漫漫。共勉。
男生的话：老公是it男，经常熬夜，最近用整套的娇韵诗男士系列，味道不错，效果有待考察。
编辑于 2015-09-02
青菜鸡蛋面
青菜鸡蛋面
专治护肤难症，是配方师的小跟班啊

The Desperate Man (Self-Portrait),1843-1845

爱美之心人皆有之。你看，连这位生于十九世纪的现实主义画家库尔贝都能如此自恋臭屁得要死。放在今天，这个绝望的男人(The Desperate Man)发的朋友圈下面写的一定是：啊，额头长了颗闭口，哦多茄！

更不用说生在二十一世纪的你了。

但是我们实际看到的是什么呢，除了靠脸吃饭的职业，大多数的现代职业者并不重视自己的皮肤，也不愿意花费时间去科学地学习皮肤基础知识，我问你几点，你告诉我怎么做手表干什么？
整个护肤品行业也是近乎急功近利的浮躁，炒作品牌与概念让消费者不辨真假。
最终共同导向的结果是：用了银子，却因为盲目护肤导致大量皮肤问题出现。

所以，不然你们也不会这么心焦地问：如何让皮肤变好。

作为女性，我看到过女权解放运动，也有发生在1920年民国时期的女性胸部解放运动，代号：天乳运动，都是为了精神自由与身体自由而作的努力。

我在想，为了我们的脸，在二十一世纪再次发起一场女性解放运动：美丽解放运动。
口号：长脸除了长脑，还得长心眼。

心：重视你的皮肤问题

 现在像知乎这样的高质量内容输出平台，在美容护肤话题动态下也开始被这类问题占领：
你为你的这张脸花了多少银子？ - 美容护肤
还有许多问题下，回答里以晒护肤品和化妆品为荣。

其实背后表达是一种歪曲的价值观：用金钱去衡量你对皮肤的重视程度。
然而真是这样的吗？做一个愿意给自己的脸花钱的人，就是重视自己的皮肤了吗？我所说的「解放」，难道就是纵容女人强烈的天性吗？最终的结果是，你拉动了国民生产总值，以及闲置一大堆对你来说无用的护肤品。

就像谈恋爱，如果一个人男人仅仅会为你花钱，却不在意你的生活细节，想你到底喜欢什么，你觉得他是真正爱你的吗？那么，你真正爱你的脸吗？
所以真正重视皮肤问题的开始，是观察并且记录你的皮肤状况。
像下定决心要掉肉的胖子一样，每日计算自己的热量摄入和运动消耗，定期测量体重和记录围度。我们要让皮肤变好，首先要学会观察和记录。

一、选择并排序目前最主要的皮肤问题
痤疮，黑头，毛孔粗大，面部油光或干燥，粗糙，皱纹，黑眼圈，红血丝，色素沉着，皮肤炎症，过敏等。
如果皮肤患有炎症或过敏等突发状况，需首先处理。
而痤疮与黑头，面部油腻或干燥等在皮肤问题中普遍影响最大，但治疗显效，只要正确护肤与保持良好生活习惯，就能有效改善。
受基因影响较大的肤色以及由于年龄因素而产生的皱纹等不可抗逆因素形成的皮肤状况，则应该调整心态，对一切「神奇功效」保持理性态度。

按重要次序排列，在选择护肤品时应有所侧重，并且不能指望有限的护肤品可以一次解决所有问题，先解决主要矛盾。

二、记录影响自己皮肤的内在和外在因素

根据需要选择和使用日常护肤品后，你需要每日通过照片记录皮肤变化，只有对比才能清晰看到皮肤状态的走向。并且，由于影响皮肤的内在因素和外在因素非常多，我们通过记录发现皮肤状况出现较大波动时，能够对应到当时的生活时间线上我们到底受到什么因素的影响，从而在日后能够尽量避免或是做出适当反应。
每个人出现皮肤问题的原因都是不一样的，这个记录就是你的日记。
如果熬夜会立即反应到库尔贝的额头上，你觉得这个自恋到疯狂的男人还会再深夜作画吗？

三、让我看到你的决心
现在很多女生活得比男生还粗糙，不愿意在护肤这件事上用上哪怕一点意志力和执行力，
护肤这件事如果你三天打鱼两天晒网，这种亏本买卖我劝你还不如省点饭钱。

坚持两个月，把观察和记录变成你的习惯，可以最大程度降低它对你意志力的损耗。

执行力：
我就不相信你平时开小差的时候不会拿着任何反光物体来看自己的脸。
更加不相信你不会自拍！

脑：系统学习皮肤基础知识

如果你打开这篇文章，并且看到这里，你已经成功了一半，起码你在遇到问题后能够主动寻找答案。但是好学的学生就能成为成绩好的学生吗？

一、知识来源与及时反馈
先问你们一个问题，关于皮肤的基础知识你们是从以下哪些途径获得：
http://Baidu.com
http://Zhihu.com
http://Cnki.net论文
博客博主X
微博美妆网红Y
护肤品垂直网站内容推送Z等等

很显然，在知网(http://Cnki.net)上获取的论文文献的知识准确性一定高于在百度或是微博上搜索关键词所获得的某个人提供的知识性答案，哪怕他是匿名用户也好，是意见领袖也好。
因为第一手信息或知识经过加工和转译，加工者的专业水平高低，是否带有商业利益等因素，都会导致信息和知识失实。

你所关注的知识提供者就像你的老师，往往会影响到你的关注视野和知识质量，所以选择一个好老师很重要。好的老师也会在你提问时给出及时反馈，纠正你的知识性错误并提供正确的发展方向。

二、方法论
关于如何学习已经脱离我的专业范围，你们可以在知乎「学习方法」话题参考相关回答。

这里我只针对性说一句：从基础学起，开始总是枯燥的。但对「角质层」、「皮肤屏障」等生物学和医学基础概念的理解是系统学习皮肤知识的第一步，不要再满足于别人已经啃完肉剩下的骨头了。

三、学以致用，举一反三
学习知识，如果不能运用到实践上也不过纸上谈兵。
通过实践，也可以知道你到底是理论背得很溜，还是真正把书“越读越薄”。

其实这也是学习的方法论之一。

一开始可以尝试运用理论分析常见的误区和谣言，如果你对皮肤结构有整体认识，你就可以知道：
补水面膜的水分只能到达表皮角质层浅层。
透明质酸虽然是真皮层的成分，但是外用透明质酸面膜其成分是补充不到真皮层的。
皮肤粗糙是因为受外界干燥等环境因素影响而导致脱落酶活性不足造成角质细胞脱落受阻，这时应该加强保湿而不是使用磨砂膏。

平时在阅读知识性文章时，要带着批判精神，不要认为他是大V他说的都是对的。

眼：提高识别护肤品功效的能力

知乎上有不少自称成分党的人，但是懂成分并不代表懂配方，除非你是学精细化工专业出身。
所以那些「伪成分党」往往也是离开剂量谈毒性，制造各种骚动的那群人。
我们当然不可能为了看明白护肤品配方而去学习精细化工专业，但是简单了解常见成分的主要功效和原理，在比较产品功效时还是能够发挥一定作用的。
而且目前作为消费者我们对护肤品功效的了解最主要就是通过产品的包装信息，而学习如何去看产品包装信息，也是一门学问，比如功效成分在成分信息中的排列位置。
以上是从观念上去指导各位如何让皮肤变好。
马克思他老人家说只有正确的认知才能指导实践，如果没有改变错误的护肤观念，说再多实操也是白搭。
发布于 2016-10-14
小白羊
小白羊
充满正能量的女瘦子 （Vchat：ys-user）

谢邀～
注重护肤多年虽还未能养成婴儿时期的瓷肌，但是还是有些小心得哒～


开始上干货
答主的另一篇帖子也是干货满满
https://www.zhihu.com/question/34546303/answer/149501917

细观周围皮肤好的姑娘并不是用了多大牌的护肤品，也不是吃了多贵的保养品。但是饮食习惯都比较健康，皮肤其实主要还是得靠养，虽说二十郎当岁的年纪讲养生有些过早，但是皮肤在一定程度上反映了健康状态，而对任何年纪来说健康都很重要。

【生活习惯】
 梅雨季切勿整日门窗紧闭，要注意通风；冬天要多穿衣注保暖；夏天不要贪凉喝冷饮吃冰棒睡地板（答主就有此不良习惯，改正中）这些习惯导致胃寒、体凉，从而湿气就会产生。而湿气重就容易导致长痘、湿疹引起皮肤问题。
湿气重多喝红豆薏米粥另外多运动流汗吧。

 作息规律，千万别熬夜啊千万别熬夜啊千万别熬夜啊，说眼霜精华贵也许劝不了你，可能熬一晚上赶个方案一箱眼霜精华都来啦。可是黑眼圈、脸色暗黄事儿小；消耗的精气神补几个晚上也能回来 可是内分泌收到影响导致姨妈问题就事大了啊！！！内分泌失调也容易导致长痘长斑。

 多喝热水，暖胃清肠给身体和皮肤双补水尤其夏季长待冷气房更是要多喝。如果白开水喝不下就加点东西吧～ 推荐蜂蜜柠檬 答主天天靠它喝热水呢 口感棒又美白，周围找不出几个比我白的了，真的内养全靠它啦～
步骤一：柠檬用盐摩擦表皮 泡一会用清水洗净擦干 然后切成薄片
步骤二：取一个干净干燥的玻璃瓶 然后一层蜂蜜一层柠檬铺上去 压得紧一些不要浪费空间
步骤三：放冰箱每天两到三片即可

 饮食清淡、多吃易消化食物 以植物蛋白为主、少吃动物蛋白，肉食难消化容易给胃造成负担。很多时候身体强壮并不是全靠吃肉。 很多强壮动物就是素食者例如：牛、马 一样身强体壮还性情温顺，人若吃素食也会心平气和。心情好自然皮肤也会稳定。

 多喝银耳莲子、猪蹄这种炖出粘稠胶质的汤。补充胶原蛋白。这都是好皮肤的圣品呢！

 多运动流汗，身体皮肤的毒素会随着汗液排出，也加速了身体的新城代谢。答主这两年健身皮肤状态、气色真的越来越好，比天天吃保健品的同龄人要好很多。

 多喝纯牛奶（不是什么花生奶、核桃奶、旺仔牛奶）就是普通纯牛奶。看似普通身边闺蜜从高中喝到现在，脸比身上皮肤白了不止一个度！只是作用比较慢，答主这两年喝也发现脸上皮肤比身上要通透了一些。如果不爱喝牛奶不要为了改善皮肤而强喝这样不利于吸收呢～ 可以加点东西 比如热一下加点燕麦或者夏天做点龟苓膏加牛奶拌着吃～
味道好才吃得香从而才有利于吸收

 多吃粗粮吧，推荐杂粮粥，养胃也养肤。可用炖锅睡前定时预约好第二天一大早就能喝到啦，冬季多喝小米燕麦红枣桂圆核桃粥，补气补血不二之选～ 平实也会和红豆黑米 红豆薏米 小米燕麦切换

 多吃水果补水养气色，可摆成小果盘。这种小仪式感也能给生活增添乐趣啊～

 与皮肤直接接触的衣物勤洗勤换，例如毛巾枕套被套内衣，很多肉眼看不见的细菌、螨虫直接和皮肤接触容易引发痤疮。

 刮痧 建议大家一个月可以去一次理疗馆按摩下经络刮刮痧，现在社会压力大很多人都处于亚健康状态，如果能保持经脉畅通不仅病痛也能迎刃而解，肤色也能更均匀～ 面部刮痧可自己买个牛角刮痧板结合精华或者乳液做介质，可去痘印，瘦脸！答主用的修复精华坚持一周至少四次刮痧，痘印、毛孔几乎看不见了，脸也瘦了瘦了很多！

手法：先由眉心刮至太阳穴。刮两条眉毛。再由眉毛向上至发际线。照顾到整个额头。 

网上找的图，侵删。

手法按照图中所示重复
一定要对称一定要对称一定要对称

【护肤品】
 护肤品是一定要用的不要以为做到内养就可以忽视外用，清洁、保湿、防晒一定要做到啊。
别盲目跟风买产品 甲之蜜糖，乙之砒霜。适合别人的不一定适合你

 功效上多研究产品成分
保湿成分：透明质酸、甘油、丁二醇、神经酰胺、牛油果树、矿油、尿囊素、矿物元素等。

美白成分：抗坏血酸及其衍生物、烟酰胺、曲酸、氨甲环酸、光果甘草提取物、熊果苷等。

抗老成分：视黄醇及其衍生物、烟酰胺、胜肽、氨基酸肽、玻色因、神经酰胺、大豆异黄酮、酚类等。

护肤品不在于多也不在于大牌，而在于适合与成效。真正精致的人是懂得物尽其用，买很多真的用不完，曾经我也是铺满一桌每次出门一个化妆包都装不下，其实我们只有一张脸（何况还都是在追求巴掌脸）买那么多真的不见得每天都有那么多功夫去用，可能随着年纪越大越注重节约，每次看到护肤品到了过期时间还剩那么多就觉得好浪费很不开心。与其买一堆像例行公事一瓶一瓶等着上脸，真不如做好功课了解自己肤质与诉求选择真正适合自己的产品认真感受，产品的灵性也能得到最大的发挥！

以上是注重护肤后自己的一些小心得，希望对正在改善肤质道路上的姑娘们有所帮助。
爱生活也爱护肤充满正能量的女瘦子
V信：ys-user
情感、护肤都可以跟我聊聊呀
社会压力那么大，现实那么糟糕
能直面黑暗还心怀温柔才是有能力幸福的人啊
我们来一起成为可爱又有趣的人吧～
编辑于 2017-04-04
小豆腐
小豆腐
系统提醒：你的战痘护肤小仙女已上线！为了证明我的回答干货满满，直接上目录✧

研究痘痘专业户第一课：痘痘篇
研究痘痘专业户第二课：痘印篇
研究护肤小流氓第三课：洁面篇
研究护肤小流氓第四课：控油篇

在放干（大）货（招）之前，想先跟你们来唠唠关于祛痘护肤的嗑：
看到题主这番描述简直想起以前不忍心看镜子的岁月：爆痘！满脸痘印！泛红发痒！还有……长得跟煤球没啥区别！如果可以，真的想穿越回去天天盯着18岁的我碎碎念：

1.早上洗脸麻烦把硫磺皂扔了，这东西用久了是会破坏皮肤屏障导致长痘的。
2.洗完脸连水乳都不抹，等着脱皮起皱纹吗？
3.夏天：外面暴晒，你却想防晒霜都不擦伞也不撑就出去，以后是要来这搜“怎样才能美白”的啊！
4.别老往屈臣氏跑，听到BA说缺水就买补水面膜，说出油就买深层清洁面膜！也不看看护肤品的成分表就往脸上抹！难怪会过敏哦。
5.知道你看着镜子里满脸的痘痘很不舒服，可是你也不能一言不合就上美容院针清吧！你那样做是会把皮肤弄坏哒，以后用什么都过敏是很惨的……
6.脸上即使再多的黑头和闭口，都不能刷酸，敏感肌的宝宝说脸红就脸红，从来都不会给你反驳的机会哟！听话先把皮肤养好。


7.痘痘多不要着急，停止乱试方法和护肤品才是第一步。
8.不要熬夜刷帖想尝试各种偏方，什么白醋洗脸美白、茶包敷眼去黑眼圈，就别折腾了。
9.买护肤品不在于别人推荐和越贵越好，适合自己肤质的才是最好的，甲之蜜糖乙之砒霜啊。
10.冬天：睡觉之前要用温和的洗面奶洗脸，过敏的话清水就可以啦，实在不行就去药店买个扑尔敏或者息斯敏吃吃。
11.洗完脸，觉得水乳不够保湿的话，要记得擦面霜，里面含有较多的封闭剂可以帮你锁住皮肤的水分。千万不要等到脱屑的时候再补救，因为那时擦面霜皮肤会！很疼！
12.一年四季，只要姨妈没有来，就抓紧时间运动运动，加快皮肤的新陈代谢。
13.还有，要忌口，油炸麻辣食品是高糖食物，很容易导致长痘痘哒。

一言不合就狂说，证明我老了喜欢自言自语（现在除了00后其他都老了吧），好吧废话不多说，干货在此：（目前收藏明显比赞数要高！但是只有点赞才能把答案送给更多有需要的盆友啊！）

不可错过的祛痘护肤宝典还有：
*10.25痘印番外：如何去除脸上的痘印、痘坑？
1.长痘原因与痘痘类型：有什么好的方法可以祛痘让皮肤变好？ （其他你可以不看，这个不行！）
2.系统的清洁保湿知识：对于护肤与化妆毫无经验的大一女生，应该如何入门？ 
3.闭口粉刺的处理方法：补水时痘痘会越来越多吗？开口闭口型粉刺怎么办？ 
4.关于刷酸：看到大家说刷酸，a酸水杨酸杏仁酸果酸，这些酸到底怎么个刷法？用手还是棉签点涂吗？用化妆棉轻擦吗？ 
5.美白与防晒：如何美白？ - 小豆腐的回答
（收藏着哈，不要掉坑啦）

——————————∞———————————
研究痘痘专业户第一课：痘痘，痘痘，痘痘，✧
——————————∞———————————

一、如果你是一只大油田（男生发育期直到三十而立），正好你也长痘痘：

皮肤耐受的话可以尝试使用皂基洁面产品，虽然很多人（包括豆腐）都说皂基存在刺激性。表活中虽然皂基清洁力（脱脂力，把你脸上的油腻腻洗掉）最强，脱脂力太强把表皮上的皮脂膜过度洗去，破坏了细胞间脂质，锁水能力就会变差，皮肤内水分蒸发量更大，造成紧绷感，这是最轻微的刺激。

但是这个刺激性是可以通过配方加入氨基酸调和的。且真正的刺激性是由于个人对产品某个成分或某些成分综合作用感到不适，或是产品酸碱度偏酸偏碱造成的皮肤过敏发炎（表现为发红，发痒，掉皮等）。

排除那些成分不靠谱的产品，再排除那些成分表上成分跟宣称效果根本没有毛关系基本靠吹的产品，你就已经可以通关了。然而，每个人肤质真不一样，你让我给你们一堆我认为有用的产品，然并卵啊，我的同学。
（所以，你以为你不跟我好好学，学完以后不好好记，你能顺利把肥皂捡起来？）

不过，学渣看这里。给一个最粗暴简单的洁面标准：清爽而不紧绷。

不管是十块还是一百块，只要满足这一点，都是个好东西！但如果洗到持续发红发痒，干燥，甚至洗掉皮的，给我住手！有的人洗了过会儿又是一层油，结果居然做出短时间连续洗两次脸的傻事儿。同学，洗脸不就是为了洗掉脏东西吗，不是洗油。

油多了积聚让角质变厚，堵住毛孔，但是过度清洁也是错错错！

油是皮脂膜的重要成分，皮肤为了保护角质层分泌皮脂膜，你这样子过度清洗，皮脂膜答应了吗？
皮脂膜被过度破坏，导致水油不平衡，肌肤问题接着来。嘤嘤嘤油皮同学，欢迎加入敏感皮小班。

个人已经对面膜无感（面膜市场被微商玩坏了，还充斥各种补水骗局，真是够了），直接用洁面乳，那些说洁面乳有保湿，美白，淡斑各种附加作用的也给我停，洗洗就没了你还想干嘛？

洗完脸，想收敛毛孔的就拍个紧肤水（收敛水），想要加点保湿效果就拍个爽肤水。做到这里就好，如果有过度清洁（一边出油长痘，又一边干燥掉皮），可以再涂个清爽型保湿。

如果长的闭口痘，一周到两周用水杨酸，果酸等酸类去去角质，平常也可以用去角质洁面产品。如果长到脓包甚至是结节，囊肿，应该去角质，消炎和杀菌要跟上。一切为了排脓！让脓排出来，或是通过淋巴组织内部消化后排出。

二、如果你是个小油皮妹子，正好你也长痘痘：

如果使用皂基洁面后，皮肤感到紧绷，还是选择使用温和的氨基酸洗面奶。
嗯哼，反正男女不是问题，年龄也不是距离。我们只看脸。护肤同大油田。

敏感皮，干皮和混合皮：
敏感皮和干皮一定要好好养皮，第一步是不要乱用洗面奶。基本用氨基酸洁面产品，长期使用清洁力强的皂基会因为过度清洁造成发炎。

第二步是保湿（特别是那些脸老是发炎，红红的，痒痒的，老是掉皮的孩子），选择油性成分比较多的滋润型保湿乳，再不行就上保湿霜。
（≧'◡'≦，如果有洗脸后拍水的习惯，可以拍个柔肤水）
一般长痘痘是因为过敏发炎而长的炎性丘疹，应该注意消炎。
（应急的话，药房的消炎药可以满足你，但只能说应急的，如果想长期解决，必须保湿养皮）。

第三步是尽量不要化妆！实在要化妆也要卸干净，使用卸妆乳或是卸妆油，不要乱用靠一堆表活增强卸妆力的卸妆水。（乳和妆要充分乳化，摩擦摩擦后变乳白色洗掉）

卸完以后再用氨基酸洗面奶洗掉残留的卸妆产品成分（很多时候敏感皮和干皮长闭口就是因为没有卸干净堵了毛孔）。如果真的是因为化妆而堵了毛孔长闭口痘，这时候可以温和去角质。

去角质效果的强度：
磨砂膏＞磨砂型的洗面奶＞去角质啫喱/凝胶状＞去角质乳液＞面霜、面膜、精华液和化妆水

混合皮，粗暴的汉子当油皮养，脆弱的妹子当敏感皮养，勤劳的孩子分区养。
我是说真的，以前混合敏感皮，脸颊有红血丝，只能乖乖用氨基酸洁面乳了。

——————————∞———————————
研究痘痘专业户第二课：痘印，痘印，痘印，✧
——————————∞———————————

讲之前先插播一个知识点：如果补水是骗局那还有没有拍水的必要啊？
≧'◡'≦：说补水是骗局，涉及两个点。一是（大分子）水可以补进角质层，二是以为水补进去以后就不会跑掉一直保湿。我说的拍水，不是单纯的拍自来水，而是添加了油性密封成份的化妆水，如爽肤水和柔肤水。柔肤水涂起来会比爽肤水黏一些，证明添加的油性密封成分会多一些，这样就会有保湿效果。但效果肯定不如乳和霜。想要收敛和保湿，拍水还是可以满足的。

（比如某爽肤水含金缕梅、甘油和蜂王乳：金缕梅就有收敛毛孔的作用，而保湿方面，就有甘油和蜂王乳等油性成分对丁二醇和玻尿酸等水性保湿成分进行密封锁住。）

好！下面的内容是：痘印篇！
先说痘印形成原因。其实痘痘泛红有两个阶段。

首先是长到炎性丘疹和脓包以及更严重的痘痘，都会发红，这是因为长痘痘的地方发炎了。
虽然那时候还不叫痘印，但是我们首先得知道发炎是什么？发炎就是细菌坏人来了，机体防御反应放出白细胞要跟它打一架！

白细胞哪里来？通过毛细血管中的血液输送。所以一旦发炎，毛细血管就会扩张：毛细血管数量增多，同时血液流动速度加快，血管壁被撑大撑薄，皮肤显现出来是痘痘处呈血液的深红。这就是我们长痘痘的时候，痘痘发红的原因。
而我们手痒挤出来的脓，就是白细胞和细菌干架以后两败俱伤的尸体。

而痘痘消了以后，炎症痘痘对皮肤造成的伤害依然处于修复阶段，毛细血管继续提供养分，不会马上收缩回去。这就我们说的红印。

≧'◡'≦：敏感皮，干皮和痘痘肌等问题肌看这里！
有些同学因为化妆或者经常抠脸导致脸部皮肤非常脆弱，和天生敏感肌一样容易因为受外界刺激而导致过敏发炎，脸颊一片泛红，带有痒感，这个要跟痘印区分开来。

我不是天然无添加的脑残粉，但是我确实认为芦荟的消炎效果很不错。
而市面上的完美芦荟胶和自然乐园芦荟胶只是打着芦荟的名义，只能满足基本保湿需要。

一般脓包消退后留下的痘印需要三个月到半年才能完全淡化，而且想淡化痘印，请先把痘痘稳定住，不然这头把痘印淡了，痘痘又冒出来，作死星球饭迎你。
（手贱星人因为乱抠乱挤痘印有可能呆得更长，而且可能留坑，请对自己行为负责！）

除了消炎，收缩血管，让血管更有弹性以及促进血液循环也是淡化痘印的两个重要环节。

那么黑色的痘印呢？黑印不是所谓的红印氧化变黑，而是炎症后的色素沉着。因为痘痘对皮肤形成损伤，损伤皮肤容易被紫外线二次伤害，所以人体会分泌黑色素去防晒。
去黑印跟美白是一个道理，从源头，过程和尾巴对付黑色素。

源头：减少黑色素形成
①防止黑色素细胞被刺激：除了宅宅宅，做好防晒。
②抑制酪胺酸酶：熊果素、麴酸、洋甘菊萃取物、甘草萃取物等成分就是常见的有效成分。
过程：减少黑色素被释放到角质层（抗氧化）
①简单粗暴：吃饭睡觉打豆豆。
（≧'◡'≦，多吃富含维C和维E的食物，特别是水果，抗氧化效果棒棒哒！而护肤品中的维C和维E衍生物抗氧化作用也是杠杠的。
虽然褪黑素跟美白没有毛关系，但是好好睡觉能够让身体代谢正常，促黑色素的排出。）
②护肤品中其他有效的抗氧化植物提取物：如根皮素、番茄红素等。

尾巴：加速黑色素剥落（定期去角质）
去角质方法太多了，磨砂（比如洁面仪和洗面奶里面的小颗粒），卸妆，连剃须也在去角质，而刷酸是现在最流行的方法。
很多同学一直在追着我问到底刷酸是什么意思，其实就是说使用的护肤品中带有水杨酸或果酸这两种成分，并且主要目的就是剥落角质。
对于增生性痘疤、痘坑的治疗，目前最常见有效是通过医学美容手段解决。

——————————————————————

今天更到这里啦，豆腐马上滚肥去泡茶！准备迎接千里迢迢跋山涉水来找豆腐把皮肤养好的同学呐！评论区是问题收集站，大家有不懂的想要问的都可以在下面告诉豆腐哦~~~
编辑于 2016-10-25
皮肤科医生甘国端
皮肤科医生甘国端
更多的知识积累给你更好的选择！！订阅号GGDplastic

如何让皮肤变好，作为一个皮肤科医生，我无法给大家推荐护肤品，只能给到一些建议，希望可以帮到大家。要想让皮肤变好，首先要了解到皮肤为什么会变老？有哪些特征？


皮肤的老化与机体的衰老是同步进行、不可抗拒的，是一种生物降解的过程。随着年龄增长，加之紫外线辐射、空气污染、风、冷、热、潮湿、活性物质外源因素，皮肤固有的功能逐步降低，不受或较少受到外界因素的影响。直观表现于体表，如出现皮肤松弛、细小皱纹，同时皮肤干燥、脱屑，脆性增强，修复功能减退等。

（图片来自网络）

护肤的第一步从了解皮肤开始。皮肤也是一个单独的器官，并且是人体面积最大的器官，是阻隔人体与外界有害物质的第一道防线。人体皮肤可分为表皮、真皮及皮下组织，还有毛囊、皮脂腺、汗腺等附属器。以下大致说说:

表皮层犹如皮肤的外衣，是与化妆品关系最密切的部位；有新陈代谢的作用及保护的作用；共有五层分为角质层、透明层（手掌和足掌底）、颗粒层、生发层（包括棘细胞层和基层细胞层），由最外层的角质细胞和细胞间脂质构成的牢固结构可以维持角质层含水量、防止水分流失，同时也可以对抗微生物入侵、各种损伤、刺激和紫外线等，我们把这种结构叫做表皮屏障。当皮肤病变、环境干燥、长期日晒、过度摩擦或清洁都会导致表皮屏障功能受损。这一层是护肤品基本都能到达，对肌肤影响比较大；饮食可通过调整代谢，影响此皮肤层。

（图片来自网络）

真皮层位于表皮层下面，是皮肤组织中最厚一层，有乳头层和网状层，皮肤总厚度为0.5—4毫米，平均为2毫米。由富有弹性的胶原质和弹性组织构成，并通过毛孔的分泌油脂，汗腺和分泌腺，是皮肤的弹性组织层、保湿层和油脂层。只有少量护肤精华液能到达；饮食中胶原蛋白和脂肪是影响此层的重要因素。


皮下层或皮下组织， 这里充满脂肪细胞，血管和神经，它的厚度也不均一。例如臀部厚几厘米，但是上眼皮部位完全不存在皮下组织，脖子位置则很薄。这一层组织有助于皮肤丰满，帮助人体保温，并保护你的骨头，同时作为人体在饥荒时储存能量的备用油箱。它参与和阳光反应合成维生素D的工作，它对骨骼和牙齿的健康很重要的，维生素D还可以强化免疫系统，减少体内炎症。通常情况下，皮下组织相当松散，连接着肌肉和骨骼与结缔组织，变成像床垫般的凹陷，这就是赘肉。


另外，皮肤附属器之一的皮脂腺对皮肤也有重要影响。皮脂腺和角质细胞产生的脂质以及汗腺排出的汗液会在皮肤表面形成一层皮脂膜，皮脂膜可以保护皮肤、润泽角质、减少水分蒸发。但是，当皮脂腺分泌过多油脂时，也会造成毛孔堵塞，产生痘痘，例如青春期时，体内雄激素增多导致的皮脂腺分泌旺盛。


由以上内容我们可知，皮肤并不是绝对严密而无通透性的组织，某些物质可以选择性被表皮及真皮吸收，但其效果是有限的。皮肤的衰老不是仅仅通过护肤品就可以改善延缓的。 

那么，我们还能做些什么呢？

1、保持愉快的心情，保证良好的睡眠和维持规律的生活习惯是维持皮肤新陈代谢的最重要保障。人体是一个统一的有机整体。养成合理、规律的生活习惯，有助于机体形成良好的内分泌系统和免疫系统。


2、世上绝无灵丹妙药可以使人长生不老，但善守养生之道，持之以恒，是能够推迟衰老到来的，所以我们也需要在各种食物中摄取营养，以维持机体的生长、发育和多种生理功能的过程。在我们生活中常常会遇到一些女孩子，为了减肥不愿意吃饭，营养不充分，面部的肌肉紧实感不足，更易显老。


3、彻底清洁皮肤是延缓皮肤衰老的必要条件。皮肤的皮脂腺、汗腺每时每刻都在分泌这皮脂、汗液。皮肤的交织形成细胞也在不断更新。特别是面部皮肤长时间暴露在外界，极易被各种刺激物、微生物及灰尘侵蚀，及时清洁皮肤的污垢，有助于皮肤新陈代谢，避免皮肤过敏，保持皮肤年轻态。  


4、俗话说，女人是水做的。全身水分主要存在于皮肤，可占全身的18%～20%，其余的水分分布在肌肉、内脏和血液中。要保持水润细嫩的皮肤，皮肤的补水非常重要。由于皮肤屏障功能的存在，普通的面膜补水作用其实是非常有限的。最有效的皮肤补水的办法一定是运动排汗。皮肤在身体充分运动后能开放所有的毛孔，就像久旱逢甘霖，充足的血供高效地完成了对我们的皮肤灌溉补水。


5、防晒是另外一个需要严格注意的生活细节。紫外线是我们皮肤衰老的头号敌人，任何肆意让皮肤暴露在紫外线下的做法都会对皮肤造成不可逆的损害。要知道皮肤的损伤和老化大多是不可逆的过程，返老还童很难实现，所以只能最大限度的使皮肤状态得以保持，减缓老化的过程。保护好表皮屏障，少用磨砂膏和刺激性产品，适度清洁，做好基础的保湿和防晒就是护肤品的基本使用原则。


在新英格兰医学杂志上报道了一个很有意思的案例：66岁的卡车司机威廉·麦克艾力哥特在过去的28年里一直在芝加哥运输牛奶。这28年来他都要经受透过卡车侧窗的太阳光线暴晒，最终两个侧脸的老化程度相差十分明显（图1）。 

（图片来自网络）

由上述案例可知，保持年轻肌肤，防晒有多重要！！！虽有许多渠道获得护肤养生的秘籍，但对于那些没有时间，也没有精力的努力奋斗的人们，也可以选择医学美容。


1、16-18岁年龄偏小的求美者，一般来说不存在胶原蛋白流失、皮肤凹陷的问题，最多的烦恼就是因内分泌失调导致的青春痘，或日常护肤不力，导致的部分颊部有雀斑。具体的护肤方案可根据每个人不同的个体情况有针对性的选择一项或多项无创综合治疗方案。


2、25-30岁初遇衰老的人群，多存在面部皮肤质地——色素不均或沉着、毛孔粗大、痤疮性瘢痕等问题：其实需要的医疗干预是很少的。可采用光子、局部微针改善肤质、IPL收缩毛孔等以激光为主的手段，也可采用生物、化学手段如美塑疗法，使用肉毒毒素、维生素C改善肤质。局部肌肉张力过高——咬肌肥大、露龈笑、鼻背纹等：可局部注射肉毒毒素放松肌肉，降低肌张力，达到去除皱纹、改变脸型等效果。


3、30-60岁的人群面临的主要问题是皮肤松弛、面部凹陷、法令纹、川字纹等，这个年龄段的皮肤需要适当补充抗氧化剂。建议可以开始使用处方类药物维A 酸（备孕，怀孕和哺乳期的女性禁用），具体的情况还需针对性治疗：

（1）皮肤松弛——可选用以紧肤为目的的激光、射频等治疗手段。

（2）肌肉张力过高——皱眉纹、鱼尾纹、木偶纹等：注射肉毒毒素。

（3）针对软组织容量丢失造成的局部凹陷——颞部、额部、颊部凹陷等：通过玻尿酸、胶原蛋白等填充剂补充容量

（4）针对软组织松弛并重力作用造成的下垂——法令纹、下颌赘肉：补充容量的基础上使用射频类，可应用mesoBOTOX方法收紧皮肤。

（5）体形臃肿肥胖——建议通过饮食控制，身体锻炼和合理膳食搭配来调节形体，抽脂和溶脂都不作为这个年龄段形体塑形的首选。


一般来讲，越早进行抗衰老干预，将越有效的延缓衰老进程，多种手段联合应用，能够更有效的改善每一层次、每一部位因为不同原因（肌肉张力、重力、容量缺失等）造成的衰老表现。此外，需要提醒求美者，衰老是不可逆的，我们能做的一切护理治疗手段，只能是改善和延缓衰老。


参考文献： 

1.黄威主译《化学换肤、微晶磨削与外用产品使用指南》. 北京大学医学出版社. 2015. 9.

2.Murad Alam主编. 史同新主译《美容皮肤学》. 人民卫生出版社. 2011. 4.

3.田燕, 刘玮. 皮肤屏障[J]. 实用皮肤病学杂志, 2013: (6): 346-648.

4.周展超 《专家谈美容—护出来的美丽》 人民卫生出版社 2015年6月第一版

5.查旭山《面部年轻化的综合设计与治疗》北京大学医学出版社
发布于 2017-09-25
匿名用户
匿名用户

添加一下对比照吧，不知道算不算有说服力哎～

这是以前

这是现在
如果没说服力就告诉我，说明我还有做得不到位的地方，马上去学习！^_^ 
皮肤烂的朋友请看这里，满满干货，用自己几年的青春换到的，希望像我一样的人少走弯路，起码能拥有正常的、不至于让他人惊骇的皮肤。


我皮肤油易长痘，大学之前长痘不多但是也有，大学期间病情加重，满脸红肿大痘，就是一挤出来有黄豆体积般的脓液那种大痘，正是由于大痘长得太不正常才发现自己的病，开始了正规治疗。

所以说有个思路，一旦自己的皮肤出现了太不正常、持续性的问题，一定早日去医院皮肤科，按西医流程吃药涂药。长痘这种问题和激素水平相关性巨大，按正规流程来治疗比其他方法有效一万倍，不要觉得吃激素药不好伤身体就不听医生的，你已经是有病了就把自己当病人看待，正常人吃着不好吐槽的药就是为你准备的！（这是对于那些持续性红肿大痘来说，一般长痘激素查着没问题的就按皮肤科医生开的药走）

我大概是吃了两个礼拜消炎药和涂了两个月的a酸就慢慢不长痘的，之前已经吃了两个月的达英35。并不是一开始吃药涂药就马上会好，要有一个过程，我开始以为一吃药一个礼拜之内肯定会消，然而并没有，急人，但是选择相信科学，果然后面就稳住了。

中间穿插了一个小故事，让我奠定了现在的护肤理念，并获益巨大。之前我在微博上关注的一位大v，给人的感觉讲科学，很懂保养，她自身的皮肤非常好。她自身有一个淘宝店，卖护肤品的，我一直是常客，她推荐的东西我都会尝试去买，并不是三无哈，就是现在都还很红的一些日货什么的，也不存在假货，我没怀疑过她的人品和能力。然而，你懂得，皮肤从没好过，我扪心自问她说的营养补剂我也有吃，生活作息也不至于差，各种护肤品都是她推荐的，为何皮肤和她比一个天上一个地下？
 直到看到微博上冰寒的文章，我才知道我是吃了没文化的亏。冰寒他本身是男人，皮肤比起前面这位当然是没得比，而且名气也不算大，并不受广大女人的追捧，但是我可以说，我皮肤变好的关键就是他。他的护肤文章逻辑严密，论据充分，操作性强。不得不说男人做事就是有理有据令人信服啊，从他这，我提炼了几个护肤原则：
1.问题皮肤不要寄托于护肤品，此时的重心是治疗，而不是保养，护肤品再有效，它的作用针对性强不过药品。
2.一定要保护好皮肤屏障，也就是不要折腾它使它变薄。屏障受损会导致感染，感染反过来又加重屏障受损。当初因为长痘皮肤屏障受损，脸上什么问题都有，用达克宁（不含激素的广谱抗真菌药）、曼灵精华（治疗螨虫的）还有医生开的药协同作用，同时不再用皂基洗面奶，换成氨基酸洗面奶，不再用面膜（长痘还用面膜是作大死），乳液换成Cerave，就这样皮肤在两个月之内明显好起来，不长痘了，也褪红了许多。
3.防晒非常非常非常重要。然而并不只涂防晒霜的方法。我本身算是白，长痘之后再也没有人夸过这点-_-#只有大片与细菌斗争遗留下的一片红色狼藉，当时我已经知道防晒重要每天涂防晒霜，实不相瞒皮肤负担非常重啊，高倍数又要卸，卸了又有损皮肤屏障，可能对于正常皮肤没什么但对于我这种烂皮雪上加霜。别人都当面说你防晒做得再好皮肤也不见得白啊（那当然每天长痘只有红），心里觉得很苦。看到冰寒用他的实验证明，物理防晒比起防晒霜更有效且不会有损皮肤屏障，我开始用伞和口罩还有墨镜防晒衣代替防晒霜。一开始肯定有人说你很奇怪，但是自己的皮肤比别人的眼光更加重要。我坚持一年多，再加上战后重建的工作做得好，结果拍照时白到像p的！甚至照毕业照时一眼看过去像是收买了摄影师皮肤白得透亮！要知道我这一年并没有买过一瓶防晒啊。

还有一点其他方面的思考。以前被大家普遍接受的是，寻求意见要询问比你厉害的人的意见，这大体是没错的，想赚钱咨询富翁，想读书咨询学霸，想美咨询美女。但更仔细一想，要解决一个问题必须考虑自身目前的水平。就拿护肤这个问题来说，排名靠前那个美女的皮肤确实好，而且用的东西都真的很有档次，但这两者构成完全的正相关关系吗？答者的基因、生活习惯、经济水平都是相关因素，我的经验告诉我，如果其他方面没能跟上，想单凭用一样的护肤品获取同样的效果是不可能的，学霸考的好也许是因为他记忆力高于常人。所以如果要寻求捷径的话，更应该听专业人士的意见，英语想要学好，咨询英语本身非常吊炸天的人固然好，但如果能找到一位对语言规律认识很深刻的教英语的老师，那更是好啦。

最后说说我用来战后重建的东西，c15、c20，轮着用，每月一瓶，已经用掉十瓶以上了，一点不夸张，一年时间不到，现在只剩坑，这个只能靠医美我也不贪心。
详细说下c15和c20，牌子是nufountain,淘宝搜下就有。有钱的就不要看下去了，这是穷学生用的方法。说缺点，保质期短，使用感一般，但是比起它的性价比，我都是不在意的。c15是褪红效果强大，也就是说等痘痘控制住后，持续用它用三个月，你会感谢我的推荐滴，褪红效果那真是！c20主要是美白，顾名思义它的vc浓度是百分之二十，这是最大的vc经皮吸收浓度，再配合熊果苷和烟酰胺，自己想想那酸爽。大致过程就是先去医院治好痘，再用c15褪红，然后用c20美白。就这样交替使用就好。没长痘想美白的也可以使用c20，看看它成分你就懂。价格在130以下，30ml。
开心了吧，是不是马上点开淘宝啦，莫急，再让我分析下利弊。
除了上面两点缺点，还有其他的。它的成分是vc衍生物为主，辅以烟酰胺、熊果苷、阿魏酸什么的，且浓度都较高啊，所以它怕光（白天用的话请你一定不要偷懒把自己想像成吸血鬼那样防晒），很容易氧化（保存在冰箱里是最好的，最好在两个月内用完），并且皮肤薄的易过敏的一定要确认自己烟酰胺耐受啊（烟酰胺不耐受会泛红并且长小豆豆），另外还有一些小烦恼，睡觉之前用c20枕巾就会黄，用手涂精华的那只手也会变黄，不过是可褪的。味道也很销魂，一股子铁锈味。能忍受以上缺点再剁手。
编辑于 2015-10-08
naomi
naomi
少女

“皮肤变好”是一个大工程。坚持运动，积极护肤，都对皮肤变好有所增益。

我的答案包含以下内容：

Ⅰ年龄和护肤品
Ⅱ洗脸
Ⅲ黑头粉刺
Ⅳ美白
Ⅴ化妆水
Ⅵ手工皂diy
Ⅶ去角质
Ⅷ不应该吃啥

关于护肤，我想请大家盯着你家的那一大堆瓶瓶罐罐好好的问下自己：

我到底要干什么？？？？？

我先来告诉你这些瓶瓶罐罐能做到什么事情吧：

1、洗干净脸；
2、改善青春痘、黑头粉刺、干癣等明显的皮肤问题；
3、调理油或者干的肤质，恢复到中性比较平衡的肤质状态；
4、抗氧化，抵抗自由基的伤害，也就是寻常说的抗老、延缓衰老等等；
5、防晒和抵抗各种刺激，所谓的隔离；
6、在皮肤状况很糟的情况下，利用细胞沟通因子改善整个皮肤运转情况，这一种的确只有一线护肤品才做的到。但只要你一直勤奋的做好前五样，其实不太会需要砸大把银子在这项上面。

你再把所有瓶瓶罐罐分类一下，分别是干什么的，你缺什么，是不是有的重复了，是不是有的不需要，（凭我的观察，多数的姑娘都是用的太多，而不是用的太少）。

以上所有六项之外的诉求，都请移步健身穿搭话题；

✿按年龄选择护肤品

几乎所有的护肤品牌和杂志媒体都在怂恿你根据年龄选择保养品，起因浅显易懂，年轻人和老年人的皮肤肯定是不一样的，所以按年龄划分保养品真是顺理成章。

但其实产品只和肤质有关，而一般来说老年人皮肤要比年轻人的更干些，所以熟龄保养品总是很油，而设计给年轻人的产品总是很干，但事实上中老年人一样有青春痘、油性皮肤、湿疹的问题，年轻人也会有干性皮肤、斑点、皮肤老化的问题，肤质的改变是随着荷尔蒙、季节、压力等因素而改变的，并不仅仅是年龄，可以説同一个年龄段的人会有非常不一样的保养需求，所以，请根据肤质来做保养，不要迷信产品的年龄划分。

关于自己的肤质，干性还是油性还是混合，混合的话要把部位确定出来。

接着看有什么重要的皮肤问题，比如青春痘、粉刺、皱纹以及很普遍但很少人关注的酒糟性皮肤炎、干癣、湿疹等；
测试方法其实网上很多地方都有説的，就是洗完脸后什么都不擦，4小时之后判断。简单说是否有部位皮肤特别油亮，那地方就是油的。是否有地方比较干或者暗沉，那地方就是干性的。

另外如果在鼻子和两颊有红疹，有些像青春痘但又不是，并有扩张的微血管，脸蛋特别容易泛红，那你可能有酒糟性皮肤炎，这是皮肤病要去看皮肤医生；

如果有层出不穷的青春痘，那你要关注下痘痘肌的护理；

如果在鼻子下巴前额有明显的黑头粉刺，那你要关注下粉刺问题；

如果干燥脱皮的红疹子，这也可能是干癣或者皮炎，也要看医生；

要始终明白我们保养的目标，护肤品不可能让你返老还童，只能帮你解决各种皮肤问题，让斑点淡化，皱纹不明显，油皮中和等等；

✿✿关于洗脸

1、洗脸一定要温水。洗脸的水温非常非常重要，冷水和热水都对皮肤有刺激作用，会导致很多皮肤问题，而且只有温水才可能真正把脸洗干净，所谓冷热水交替洗脸刺激血液循环，用蒸脸机蒸脸，都只能偶尔为之，我建议尤其是敏感皮，红血丝姑娘压根不要做～

2、洗脸要用毛巾／洗脸巾，毛巾可以帮助你更好的清洁洗面奶或者卸妆油的残留物，而且可以帮忙去除老废角质，一举两得的好东西。但毛巾的确容易滋生细菌，如果青春痘皮肤一定注意要经常杀菌，怎么杀？把毛巾晾干，或者扔微波炉里高火5分钟；

✿✿✿关于黑头粉刺

其实对抗黑头粉刺和粗大毛孔与治疗青春痘类似，只不过后者由于长了脓疱，所以还需要增加杀菌的程序；

一般来说黑头主要是由皮脂、细胞屑和细菌组成的一种“栓”样物，阻塞在毛囊开口处而形成的，加上空气中的尘埃、污垢和氧化作用，使其接触空气的一头逐渐变黑，当然也有化妆品和保养品使用不当而造成堵塞油脂通道，所以首先要避免使用过油的产品；

接着还有几种产品可以帮到你：
1、温和的洗脸产品，一般氨基酸系的洗面奶相对温和；
2、温和的水杨酸去角质产品，但一定要注意浓度，1－2%浓度最好，太低了没用，太高了刺激，你可以从1%开始尝试。水杨酸是目前发现最安全的可以同时去除皮肤表面和毛孔内角质的产品。
3、吸收过多的油脂（仅限油性皮肤），可以使用粘土面膜，或者一些品牌出的控油凝胶、控油定妆液等等，有专业独立诉求的产品，往往才是最有效的。听到过所谓控油保湿液，让我很费解的。
4、果酸换肤、微晶磨皮等，可以改善黑头粉刺的外观，让皮肤看起来好看些，但不能改善毛孔的功能，如果不能控制多余油脂，继续使用不合适的护肤品，很快黑头又回来了。

✿✿✿✿关于美白：冬季马上过去，春夏来临，美白产品又要热卖了

我在前面说的护肤品基本功效里面并没有美白这一项，因为很多人期待的美白——将现在的亚洲黄皮变成日光灯或卫生纸，这是不可能的（大s就是个骗子。。。逃）或许微整型领域可以，但护肤品真的不行。

真正护肤品能做到的美白是这样的：
——抑制新的黑色素的形成，加速已经形成的色素沉着的皮肤更新。（也就是让皮肤不要更黑了，而不是让它白回来，皮肤的确可以白回来，但那是皮肤自己的功劳，和美白产品无关。）

其实如果你已经有了黄褐斑、色斑等问题还是直接去做激光治疗的好，护肤品真的作用不大。它只能作用在它能够渗透到的位置，就是皮肤表层的地方。果酸、水杨酸去角质的同时可以帮助表层色斑的淡化，但比如痘疤、比如你去海边把自己晒黑了，根本上还是要靠皮肤自己白回来。至于抑制黑色素的形成，宝拉阿姨很推崇对苯二酚，但因为成分研究出来很久没什么噱头了，又有些致癌传言，现在很多美白产品也不用，而是去用一些听起来更新鲜的东西，比如熊果素、维生素A醇、维生素c、杜鹃花酸，其实只要你天天擦，都会有效果的。

美白的同时你还需要：

1、抗氧化
很多姑娘説的“黄气、暗沉”，其实就是皮肤出油氧化形成大量自由基时的一种皮肤状态，我们常常觉得刚洗完脸的皮肤是最白净的，可在外奔波忙碌一天后就非常蜡黄。其实正是因为你那时的皮肤脏掉了，有太多不该有的东西在上面，你洗把脸，可能又白净回来了。要想全天都有白净的状态，就要及时控油，并选抗氧化能力强的产品。抗氧化能力要强，一定不能只靠一种成分，你看产品宣传语，一定要“富含多种抗氧化成分”这种才叫靠谱。维生素c、e、a、辅酶Ｑ１０、葡萄籽萃取、石榴萃取、大豆固醇、绿茶包括一些中药成分都有抗氧化的效果，这些都不是贵东西。

2、防晒
我在之前关于防晒的答案有详细的说明：哪个牌子的防晒霜比较好？ - naomi 的回答 - 知乎

简单说来非常简单就是两样东西：二氧化钛和氧化锌，你不认得就看防晒指数好了，SPF15以上PA++日常就可以了，但记得一定要涂的厚才有用，油性皮肤可以结合防晒粉饼吸收过多的油份。（要注意如果你有做水杨酸果酸去角质，防晒就一定不能少）

但请不要选择号称美白、防晒、抗氧化三合一的产品，因为防晒成分要求不渗入皮肤，可抗氧化与美白成分都要求即停留到皮肤表面又尽可能渗入，也就是大小分子的成分都要有，你硬要三合一我们就很难搞 ，最后的结果就是料的确加进去了，可根本靠近不了皮肤。你只可选择美白+抗氧化和抗氧化+防晒两类商品。反正所有的合格的护肤品一定是有抗氧化成分的。

✿✿✿✿✿关于面膜
面膜最主要就是防腐剂的问题，片状的面膜都是湿答答的一块布，你想想这种状态多容易滋生细菌阿，要么使用杀菌技术，要么使用大量防腐剂，所以不建议购买平价的片状面膜，一定都是加防腐剂的。

罐装面膜（除掉泥膏式）基本就是大瓶的乳液，可能在装罐之前都和身体乳、保湿乳之类装在同一个大桶里面的。防腐剂的量相对会少一些，但其实如果有乳液，也不用专门购买了。

这两种面膜敷完后都有种水当当的美好效果，其实都是把大量保湿剂卡在角质里，造成的一种暂时效果，如果你要见男朋友，临时这么整一下是可以的，但并不能真正的改善皮肤状况。

泥膏面膜其实也有防腐剂过量的问题，所以贝斯佳的绿泥有人説用了刺痛，就是对防腐剂敏感，但它有一个独特的功效是控油，如果你没有不良反应，油性皮肤用一下是挺好的。

✿✿✿✿✿✿关于化妆水
这个问题我一直很纠结，好像没有办法下定论，也不知道怎样说清楚：化妆水的类别现在太多了，配方可能完全不同，可是都叫化妆水，尴尬）

我归纳一下，总结原则如下：

1、如果你后面还要擦精华乳的话，就不要买太稠的化妆水，或者那种分两层，用前摇一摇的。因为这种水里面油和胶类都太多了，会阻碍你后续保养品有效成分的吸收；

2、不要买擦起来过滑，而且号称可以二次清洁，可以擦出污垢的化妆水。那都是加了太多表面活性剂的；

3、其实更建议买精华水，最好是完全水状，擦起来还有点涩的。主要诉求以抗氧化、活肤为主，美白基本靠水是不行的。香奈儿的抗氧化喷雾相当不错阿，从配方到包装都非常合理，预算允许的姑娘可以试一下；

我建议大家去选择精华水（一般富含抗氧化成分，而且配方简单，方便吸收，如果是油皮，你甚至不需要再用任何乳液），所有号称补水、收敛毛孔和二次清洁的化妆水其实真的对皮肤没什么帮助，都是迎合你们的心理。你老老实实用温水和洗面奶把脸洗干净了，哪里害需要二次清洁，而且刚刚洗完脸，哪里又需要补水，至于收敛毛孔，那都是假象。。

不要相信神马化妆水收缩毛孔之类的，都是大骗咋；毛孔是不可能缩小的，所谓“化妆水可以收敛毛孔”是20世纪最大的谎言。
你要做的是勤快去角质，好好做清洁，让毛孔看起来不脏，然后用化妆品遮盖。

✿✿✿✿✿✿✿关于手工皂diy
在之前的答案中，我就强烈反对过任何diy的护肤品，以及任何号称各种精油制作的手工皂，特别是作坊手工品；

真正的soap，包括手工皂，都是碱性的（不过有品牌出的“弱酸性的洁面皂”其实只是按流行说法叫皂而已，英文是Bar，不是soap，所以应该叫洁面块才对）。但碱性的并不是说不好，很多洗面奶都是碱性的，会让人感觉洗的很干净。但是洁面皂的全皂配方很怕硬水，如果你的城市是用地下水，就容易生成皂垢，卡在毛孔里面洗不干净。

而且手工皂的操作流程和使用油脂品级都没有标准化，即便制作者很用心，也无法保证其安全性。如果用标准的程序说，洗掉黑头和粉刺，还是用安全的洗面产品，和正确的洗脸方法，外加去角质。

再就是前几年很火的精油，精油是一样非常不好的东西，是皮肤刺激和敏感的元凶，很多人认为合成香料才会刺激，感觉天然精油很美好，其实都一样，刺激皮肤以及造成光敏感。薰衣草中有一种芳樟醇，具有细胞毒性，会造成皮肤细胞死亡。去做过所谓芳香疗法的人应该知道，按摩师们都只会用几滴精油，难道真是这东西很矜贵么，真正的应该是用多了客人容易敏感才对。

精油都属于香料，很多厂商将香料标识为精油或者植物萃取精华，都是糊弄人，精油还是适合点在蜡烛里面。护肤品与其去追逐“不含防腐剂”，不如寻求“不含香料”的好。

✿✿✿✿✿✿✿✿关于去角质
我在公众号“女神化妆包”详细说过去角质的问题，可以关注后回复角质；
在这里简单说一下，果酸和水杨酸是去角质佳品，油皮用水杨酸，干皮用果酸。

有姑娘说果酸可以帮助去痘印，其实就是去除老废角质，让皮肤更新的更快。健康的皮肤是不会被果酸弄薄的，当然如果你以前一堆厚厚的角质堆在上面，果酸帮你去除了，那皮肤的确是薄了阿； 果酸最佳浓度2－10%，超过20%就是换肤了，要美容医生帮你弄了；

不过使用果酸和水杨酸产品都会有一定刺痛感哦，因为ph值要3－4才会有效果，有求实精神的可以买张ph试纸测一下，因为有的厂商害怕消费者用着痛，放弃购买，特意调高产品ph值，那样即使果酸的浓度够了，可是还是没有效果；

✿✿✿✿✿✿✿✿✿最后还想说一说我们日常吃的东西，有句话是：you are what you eat，想要皮肤好好的，应该尽量不吃啥，尽量多吃啥。

食品添加剂类

食用色素蓝色1号（亮蓝1，E133）
几乎所有的人工合成色素都是用芳香烃从石油里提取的，芳香烃中毒素含量极高，也是科学验证的致癌物。虽然许多人工合成色素已经被禁止在食品中使用，它依然出现在护肤品和彩妆里。

含有亮蓝1号的食物：冰淇淋，奶昔等乳制品，糖衣，覆盆子味道食物，糖果；
另另欧莱雅，多芬护肤系列也含有亮蓝1号，某些标榜天然的品牌如lush也有亮蓝1号存在；

氢化油
氢化油是脂肪酸的反式异构体，是痤疮的一大诱因；而反式脂肪会让皮肤变的更具酸性，刺激毛孔内皮肤，使痘痘看起来更红肿并加剧炎症；
另外，通过食物摄入的反式脂肪还会改变皮脂成分，让它变得更硬更油腻，因此更容易使毛孔堵塞。

含反式脂肪的食物：饼干，蛋糕，巧克力，油炸食品，薯条；

除了以上食物，怎样确定某产品中是否含有反式脂肪呢？看下成分表中是否含有“氢化”，“部分氢化”，“分馏”等字样；

爱烘焙的姑娘们，如果需求固体油，请选择天然固体油，如棕榈油或椰子油；

乳制品
牛奶中的很多成分都能诱发痘痘。首先，牛奶中的睾丸激素会刺激皮脂腺释放更多油脂；另外，胰岛素和睾酮的结合，乳糖和胰岛素的作用，都给痘痘的蓬勃发展创造了有利条件；

因此，需要尽量远离牛奶，脱脂奶粉，速溶早餐饮料，奶酪；

除此之外，糖和牛奶一样，会使胰岛素激增，导致痘痘出现。
更多的护肤彩妆心得在公众号：女神化妆包，希望和你一起更美更自信～
编辑于 2017-01-17
万青
万青
矫情码文，朴实做人
谢邀，这么大一个问题不分好几次能说完吗？
只有懒女孩，没有丑女孩！
（为什么我一个大粗汉说这句话一点违和感都没有？）

但是，现在护肤更多的是笨女孩，皮肤都不懂就让人推荐产品了。
老夫不禁长叹一声，现在女生的钱原来都是这么扔进下水道的。
论有一个懂皮肤的男朋友的重要性啊！

好吧，入正题。
想要皮肤变好，除了要知道自己的肌肤问题，然后选对护肤品，也要学会促进护肤品的吸收（不然买买买那么贵的护肤品也是然并卵），除了护肤，日常生活的饮食、作息和运动习惯都是让肌肤变化缺一不可的啊。

本汉子一眼看下去发现几个重要问题：
①糙糙的女汉子不护肤，现在的问题是痘痘肌、敏感肌；
②喜欢吃辣，
③坐标北京；
④每天都有运动习惯，然后结果告诉我只跑1公里。

因为问题太多了，今天先说你的皮肤问题吧，饮食和运动这些来日方长，且更且珍惜啊。


————————————————————————
皮肤问题分析（更新时间：2015/11/20）
————————————————————————
题主的皮肤问题很明显啦，帮你逐一分析之前需要问清楚几个问题：
①你说的“外油内干”不知道是怎样自己作出判断的，是“脸部”出油长痘但是又掉皮吗？
考虑是不是选择了错误的洁面产品导致的清洁过度造成细胞间脂质被破坏了。
②听你说是敏感肌，也需要你提供判断依据啊，到底是现在天生还是后天？
还有你脸上的出油情况也不明晰，出油程度和敏感程度是肌肤的两个维度，传统的油性皮肤、干性皮肤、敏感性皮肤分类其实是很简单粗暴的，所以有一个正确的皮肤认知才可能开始正确护肤啊！
连自己是男是女都不知道就买开裆裤一样
嗯，所以题主如果想解决问题，快评论区给我详细的出油情况和敏感肌肤类型判断吧。

下面简单给你敏感肌肤的判断依据：

常见的敏感皮肤可分为三类：
一、低耐受性皮肤
二、一般敏感皮肤
三、突发敏感皮肤

一、低耐受性皮肤
祛斑、美白或者用激素和铅汞以后最为常见，皮肤反复敏感，已形成对某种成分的依赖。

其一般特征是：
①皮肤反复出现水肿、灼热、脱屑、瘙痒、红斑或皮疹等症状；
②皮肤薄弱、毛细血管扩张，适应能力下降；
③日晒和闷热可以加剧和诱发症状；

其易发的情况：
①使用快速祛斑产品与其他不当护肤品；
②皮肤磨损、激光手术等机械因素以及维甲酸、皮肤磨削等治疗因素诱发；
③身体功能障碍导致皮肤耐受力下降；

二、一般敏感皮肤
由于遗传原因容易过敏、对某些成分容易过敏、对环境变化容易过敏、特别干燥而容易过敏的皮肤，50-60%的女性有这个现象。

其一般特征：
①在食用辛辣饮食或者气候变化等情况下，皮肤容易出现紧绷、发痒、刺痛感。
②干燥脱屑、水油不平衡，严重时，皮肤表面细纹（缺水纹）明显，使用保湿护肤品后有短时刺痛感，易松弛老化。
③易出现红斑、有过敏趋向的皮肤状况。

其易发的情况：
①常在室内与干燥环境中工作与生活饮食不规律的人，更容易出现此种趋向的皮肤状况；
②晒后需要修复的皮肤；
③皮肤直接接触到花粉、日光、灰尘、粉末、金属、酒精及化妆品中的某些成分等过敏源时会出现应激反应。

三、突发过敏肌肤
有红疹、刺痛、搔痒痒等典型症状的皮肤。

特征：
①由于受外界刺激造成发红、脱皮、红疹但无渗出等过敏想象。
②与个人的特异体质相关，由于季节和环境变化容易出现过敏皮肤。

————————————————————————

好，废话不多说，进入正题。
打开评论区一片“我是低耐受敏感/一般性敏感/突发性过敏肌肤怎！么！办！”
嗯，敏感肌同学请往下看，如果情况特别特殊我会在这里分析回答一下。

一、敏感肌日常生活中一定要注意以下五点：
1、注意饮食和生活规律，避免咖啡、辛辣食物及加班熬夜对皮肤的损害。
2、避免在各种恶劣环境下长时间逗留，如极度寒冷、日晒及干燥和灰尘等环境。
3、选择无刺激安全性高并具有修护皮肤功能的护肤品，非万不得已，不要选择激素类药品。
4、适当体育锻炼。但如果正在过敏的皮肤，出汗只会加重病重。
5、不要频繁更换护肤品，如果更换，前一个产品最好逐步减少使用，后续产品逐步增加使用次数。

（估计有的喷子又嚷嚷然并卵。但这跟妹纸们嚷着要减肥但是大吃大喝又不运动是一个道理。）

二、然后再说说现在的治疗方法：
对于三类敏感肌肤，正确的方法是先抗敏，然后修复，但因原因复杂，全世界也不存在最有效的方法，只能因个人状况，通过一一试用与慢慢调理。
1、所谓抗敏，就是依靠补充外来物质，来抑制皮肤组织的过度免疫反应而起作用。对于抗敏，正确的方法是选用天然提取物，而不到万不得已，不要使用合成与动物激素（如地塞米松）。因为，皮肤如果长期接受外来激素，体内自身分泌激素的能力随之下降，一旦外来激素停止，皮肤容易出现过敏反应。

—————我是案例饼心馅儿（线）——————
像这位同学，我想知道你现在用的面膜是什么牌子啊？
如果是因为选择错误护肤品，特别是那些为了追求快速美白和祛斑功效而添加激素和重金属的面膜，特别是某宝和微商的三无产品，现在面膜市场不是一般的乱啊，荧光剂什么的我就不说了。如果判断是后天的低耐受性皮肤的同学要注意了，千万不要贪便宜乱买面膜啊。
那些激素面膜停用之后皮肤会出现过敏症状，发红发痒掉皮，贴上后皮肤会变好，但是那是错觉，那是错觉啊！那是因为形成对激素的依赖了。
如果是的话尽早换用比较靠谱的护肤品牌，注意保湿吧！
以上是来自一条汉子的赤裸裸的担心，你们女生笨起来真是让男人没眼看下去想骂一顿。
（算了，舍不得）

——————哔哔哔，案例完毕———————

2、再来说说修复。修复是一个综合的概念，皮肤修护是皮肤恢复正常功能所必须的。可以通过补充维生素（如维生素B6）、微量元素（如硒、锰）、天然植物提取物（如红没药醇）、增加表皮厚度（比如表皮细胞增殖类物质）等来达到恢复皮肤正常功能的目的，这个概念已经被国际医学和美容界所认可。

——————我是案例饼心线儿———————

天生敏感肌（就是上面说的一般敏感肌类型）的同学，发现评论区一抓一大把啊。
除了要注意五个日常注意事项，选择天然提取的护肤品以外，还要尽量避免食用辛辣，远离如花粉、日光、灰尘、粉末、金属、酒精等敏感源（敏感源炒鸡多的孩子的苦痛，我等糙汉只能深表同情啊）。
尽量不要长期呆在干燥的地方，平时随身带瓶舒缓保湿喷雾，保湿效果就不要太多想了，但是对肌肤还是会有舒缓的作用的。
早上出门和晚上洗脸后，都要尽量做好乳液保湿（如果是特别干燥的地区和季节，乳液无法满足干皮同学，还可能需要用到面霜）这一步，形成保护性的皮脂膜，才能保护薄薄的角质层，让它更加远离刺激源啊。
有红血丝、遇冷遇热吃点辣的脸就红的痒的，也算天生敏感肌孩子要面对的。但皮肤会好起来的，多认真学点护肤知识，好好对待自己的脸，起码不要被人骗。

——————哔哔哔，案例完毕———————


————————————————————————
能不能好好洗脸了！（更新时间：2015/11/24）
————————————————————————

大叔我又更新，看到评论区里面有这么一位懂护肤的妹子，我就放心了，一定要好好守护身边的笨女孩啊！确实像妹子说的，天生敏感肌不多，多是后天作的。不好好学习护肤就去胡乱地买买买，钱花了，脸也毁了。那我就应约说说过度清洁的坏处吧。

一、正常洁面会把皮肤表面的皮脂膜（天然保护膜）洗掉，封闭的一层膜没了，锁水能力就会减弱。但是皮脂腺会感知到皮肤表面缺少保护，所以会分泌皮脂，与角质细胞形成的脂质以及汗腺分泌的汗液中的水份混合，排出皮肤表现形成皮脂膜再次形成保护。但如果过度清洁，特别是像上面那位妹子说的“一天洗三遍恨不得每遍洗半个小时”，老是把锁水的保护膜洗掉，皮肤不干燥才怪。而且角质层裸露在外界环境中，更容易受到刺激，加大过敏的可能。

二、这一点，也是最重要的一点。破坏了角质层砖墙结构。
亲水的角质层和亲油的细胞间脂质以砖墙结构共同构成了皮肤的天然屏障，过度清洁会把角质层洗得越来越薄，而细胞间脂质结构被打散，也让它们无法正常起到对角质细胞的保护作用。
皮肤无法维持正常的保湿和锁水机制，保护功能下降，皮肤脆弱敏感可想而知。

正确护肤的第一步，首先要知道：不伤害就是最好的保护，先学会正确洁面。先不要想着买多少后续的护肤保养品，皮肤角质层结构都被破坏了，后续的有效成分怎么可能被有效吸收？

下面都是对角质层的破坏啊，看看自己中了多少枪： 
1、每天早晚用无论何种表面活性剂的产品洗两遍脸，全年不断，连续多年； 
2、一周超过2次以上的磨砂膏或去角质清洁产品，全年不断，连续多年； 
3、一周超过2次高频度使用8%以上AHA、1%以上BHA、0.1% Retin A调理皮肤； 
4、洗脸水的温度超过35度或低于10度； 
5、一周超过2次高频度使用深层清洁面膜； 
6、过度补水补油或过度控油清脂； 
7、环境温度湿度变化过于激列； 
8、人为的抹太多层。 

————————————————————————
嗯，今天就到这里。
有什么需要就评论区留言吧，看需更新，绝不偷懒。
回答这么勤快，不点赞真的会生气啊！
今天就更新到这，工作日愉快。
编辑于 2015-12-19
白姬沙
白姬沙
不够理性的死理性派

支持陈世美的答案，写得非常专业，所以我也没啥要写的了。只想说一句，题主请抛弃露得清洁面，他家洁面据我所知是典型的皂基。

更新。

这个问题还真是各路人士都来回答了。
然而这仅仅是一个研究护肤的问题吗？
不，在我所了解的范围内，当我们做到：
保持早睡早起、
坚持在我们常识内所知的较好的饮食方式（哪怕仅仅来自于小学课本，而不是朋友圈或者其它传言）、
适量的运动、
防晒、
不使用三无产品野鸡品牌，
那么，我们的皮肤所能得到的提升已经比使用昂贵的护肤品所能达到的程度好更多。

至于说额外的护肤，请学会自己做功课。
我知道不是所有的人都有能力去取得一手的科研成果来决定自己该用什么成份，更不是所有人都有护肤品公司的内部资料来比较相同成份下哪个产品更适合自己。
但是，从你能取得的资料入手。
比如说这个答案下。
肯定有看起来靠谱的人吧？
关注他。
这样的人至少同时关注个几个。
对于真心想要改善皮肤的人来说不难吧？
当然如果你觉得麻烦，很简单啊，找大牌的导购给你推荐产品。
虽然不一定靠谱但是肯定不会烂脸啊~
但是如果你说你还不想花冤枉钱。
那就别别人说什么你就信什么啊~

比如防晒。
防晒的功课最好做了。
因为大多数人坚持不了每天防晒。
但是不防晒美白了也还会被晒黑啊~抗老化了还是会被晒老化啊~对不对~
所以口碑产品先一个一个试过去啊~
找到自己愿意每天用的，用了不过敏不闷痘的~然后做功课就好做一些了不是嘛？或者说，你的选项已经如此之少都不用再做功课了~

保湿。
保湿的功课就更简单了。
先了解为什么要保湿啊。
皮肤的结构是什么啊。
为什么油了还要补水？
补的水过一段时间以后上哪儿去了？
如果它们过一会儿就没了补水有什么意义？
为什么有的护肤品油油的有的又全是水？
它们有什么区别？该在什么情况下用？
我的脸现在油不油，洗完脸过多久会油，需不需要另外补充类似“油”的成份？
我的脸现在干不干，是不是老觉得皮肤没有被滋润够老是有小伤口？
为什么有了足够的油/水我的皮肤就会比干得时候感觉更结实？
你把这些问题问个遍我不相信导购还能再拿“你皮肤外油内干所以还是需要保湿的”来忽悠你。你要知道保湿过度也是会张痘的。

祛痘就更搞笑了。
其实祛痘的药物就那么几种，至少短期内是没听过有什么新的成份能够如万金油般药到病除，可是每年还是大把大把的年轻人因为祛痘被美容院忽悠掉上千上万的rmb，完了之后还发现自己烂脸了。
一样，自己做功课，有的是先人把全套的东西总结好了。
搞清楚痘痘大概有哪些影响因素：
自己是生病了还是青春期的暂时情况？
要不要用药，药物有没有副作用？
抹在脸上的东西除了去痘痘还有没有别的效果，长期用会不会有影响？
是病治好了痘痘就没了还是要论持久战就这么一直用药物/护肤品控制着？
调整生活方式是否就可以不再依靠药物/护肤品了？
控制到什么程度自己就可以与痘痘和平共处了？
黑头是不是痘痘（痤疮）的一种？
有没有必要/可能完全消灭痘痘？
这些问题问下来，你也该知道自己要干嘛了吧？

至于美白、抗氧化、抗衰老，那就更加进阶了，先确保自己有能力做功课再去追求这些，不要乱抹些民间的偏方，吃些来历不明的东西就以为能怎样了。如果能了，angelababy素颜还会黑嘛？周迅素颜还会黑嘛？欧美的年纪稍大的女明星们脸上还会一道道的褶嘛？当然，我这几个问题问下来想必认真看的朋友也能明白，即使是以靠谱的渠道来进行护肤，某些功效也依然是很玄妙的，可能也只能一定程度上达到某些效果，而绝对不会神奇到让你永葆青春。

所以我是在干嘛呢？
我写了这么多是希望每一个想要尝试着护肤的姑娘自己学会着思考。你们学会思考，那么市场上靠忽悠为生的商家就会越来越少，而真正有效的产品会越来越多，有能力把产品做好的商家会有更大的发展空间，最终受益的也依然是我们自己…以上是装逼的…
咳咳。其实学会思考无非也就是图个放心，对自己更了解更有针对性，最最重要的是，自己懂了肯定能比不懂的人多省一大把银子~
所以还等什么呢？想想自己的需求是什么，快做功课去啊！！！
编辑于 2015-10-21
一修姐
一修姐
化妆品公司不告诉你的，闪开！都让我来！APP/公众号：美丽修行

很多时候，我们的皮肤不好，其实是自己作的。

我们的皮肤，每天要收到灰尘、紫外线的侵害，还要禁受住气候的变化、岁月的痕迹，也是非常的累。

然而，还有一部分爱美之人，想要在人群中白成一道闪电，更是美白精华、美白面膜，美白乳液等等，什么美白就把什么往脸上抹。或者想要永葆青春，什么抗老什么就往脸上抹。


这么一来二去，就容易把皮肤作出问题。于是就有人开始长痘、面部泛红、皮肤敏感。这些问题归根结底，是因为皮肤耐受性差，无法抵御环境变化造成的刺激，或者是皮肤屏障受损出了问题。很多人不太了解皮肤屏障的概念，其实大家常说的角质层，就是皮肤屏障的一部分。今天，就来聊聊敏感问题的核心之一——角质层修复。

角质层受损，到底是怎么回事？

角质层是我们肉眼见到的那层皮肤，它的健康与否不仅直接影响我们面部皮肤的美观度，也对真皮层的防护有很大的影响。

把你的皮肤想象成砖墙！她的结构是这样的。角质形成细胞是“砖块”，细胞间的连接是“钢筋”，细胞间的脂质是“灰浆”,这个结构形成了一道人体皮肤天然保护屏障。


这堵“墙“对外不仅能将细菌、灰尘阻挡在外，还能阻挡一部分短波紫外线uvb进入皮肤破坏皮肤细胞。阻挡外来侵害的同时，还能锁住皮肤水分，防止水分流失，起到保湿的作用。

一旦这座保护皮肤免受外界伤害的“墙“出了问题，会有带来哪些皮肤问题呢？

1皮肤敏感

皮肤敏感的时候，对外界刺激抵抗能力差，更容易诱发各种皮肤问题。除了少数是先天敏感肌，更多都是后天的护肤不当，造成的皮肤屏障受损，进而引起皮肤敏感。

2面部泛红

我们所看到的皮肤泛红其实是面部的毛细血管，毛细血管在真皮层，本来是看不见的。但是有些人天生角质层薄，当面部的毛细血管受到刺激而扩张的时候就容易透过角质层被看到。

角质层受损的时候，对皮肤防护的能力下降，所以皮肤更容易受到刺激泛红。

3发炎、长痘

夏季的皮脂腺活跃，和角质细胞一起形成皮肤屏障的皮脂增多，这时候角质层受损，保护能力下降就容易让外来者趁虚而入，就很容易引起皮肤的发炎，进而产生痘痘的烦恼。

4皮肤干燥、有刺痛

角质层除了作为皮肤屏障的一部分保护皮肤免受外界伤害，还有保持皮肤水分，防止经表皮失水的作用。而角质层受损后，它的“锁水”能力就会下降，引起皮肤干燥、起皮。这个时候，往往还伴随着刺痛感。就算是以前觉得使用起来并没有问题的产品，上了脸还是会刺痛。

那么，到底如何修复角质层？

1及时止损

停止一切对皮肤的刺激和伤害，避免频繁化妆和卸妆，用温水、和温和清洁的洁面产品，避免过多的去除皮肤的天然油脂。

避免可能有潜在刺激的产品。如酒精，香精，刺激性表面活性剂，刺激性防腐剂等。

2主动修复修复表皮屏障


角质层薄有时候是天生的，这类人的皮肤往往容易过敏、发红，面对这个“老天爷决定“的问题，就真的束手无策吗？

选择含有修复皮肤屏障成分，能模拟正常皮脂的护肤品。健康肌肤本身含有脂肪酸、胆固醇、卵磷脂、NMF（天然保湿因子）和神经酰胺等重要成分。这些都是皮肤相似或修复成分，研究证明它们对肌肤健康至关重要。

3充分防晒


紫外线对皮肤的伤害远远不止是晒黑，晒伤、光老化都会随之而来，具体我们就不多赘述，感兴趣的可以搜索之前的文章查看。反正就记住，越是皮肤屏障受损，也是要防晒，防晒也是修复皮肤屏障的关键！
编辑于 2017-06-01
止于沉澱
止于沉澱
嗜甜症患者

如果一句话能说清楚大概就是 清洁+保湿+消炎
很久以前我是不把消炎算在内的，然而今年活生生把自己折腾成了敏感皮，so......

清洁：
基础洁面很重要，很多黑头、痤疮问题的产生是由于面部油脂分泌过旺，日常的洁面有助于防止毛孔堵塞。一般早晚各一次洁面是很合适的～过敏期间除外，像我现在角质没完全修复就早晨清水晚上洗面奶，具体还要看肤质！
普通的皂基洗面奶连我这样的油皮也不能承受得了，建议还是选择氨基酸洁面，最普通的旁氏米粹就不错，然后敏皮根据各自需求选择温和款，神马boscia、fancl、curel、丝塔芙都以温和著称。

除了基础洁面以外还有清洁面膜，一般频率为一周一次～清洁面膜的用处不仅是让黑头白头浮出，也可以带走面部老化的角质，可以让护肤品吸收的效率更高以及上妆更服帖～
！！千万不能清洁过度！！
有一阵痴迷于清洁的我角质严重受损，两颊和前额像过敏一样又红又脆弱，心都要碎了......后面会说说消炎和修复。
豆瓣和微博上有个蛮有名的人叫温柔的巨油皮不知你们知不知道，她早期的理论我还是蛮赞成的，就是提倡“疏通”，虽然不知道近期她在搞什么幺蛾子......我当然不提倡用那些机器残暴地对待自己的脸，但是偶尔的针清还是有必要的，先用蒸脸器或者清洁面膜让黑头浮出，表面角质软化，然后用消毒过的粉刺针在黑头或闭口出按压，把角栓挤出，很多时候就是那些闭口时期没有挤出的角栓发炎才长成了红肿痘(T ^ T)

保湿：
保湿很重要很重要......众所周知，不但皮肤干是因为缺水，皮肤油也是因为缺水(T . T) 除了日常的水乳以外还要注意多喝水～由内而外才是关键( ´ ▽ ` )ﾉ 面膜那种精华密集型的一周两次就好，过度使用反而会加重皮肤负担，如果是水膜可以每天敷！～对了，有一年冬天每天在空调房都爆皮了，后来连用三天科颜氏的高保湿霜以后！竟然！好了！而且没！有！再！爆！从此一生推☆*:.｡. o(≧▽≦)o .｡.:*☆ 
对了，我是混油，高保湿霜对我来讲真的不油，我也不懂会啥辣么多人嫌弃它呜呜呜......

消炎：
消炎针对痘肌和问题肌。
如果是痘痘可以做一做理肤泉的功课，一套乳针对红肿痘、闭口痘、挤完脓的痘基本都很全，当然如果太严重 一 定 要 去 看 医 生！
对了，只要不是闭口我一般都会用芦荟原液，纯度很高的那种，温和又消炎。
痘印可以用薰衣草精油，有点消炎作用。

如果是过敏或者皮炎就没这么简单了。
过敏最重要的是温和，清水洁面，雅漾理肤泉大喷可以时刻用来镇定下。尽量不要用有香料、防腐剂的护肤品，也尽量不要化妆。
过敏的原因如果是对某样化妆品或者食物排异，一定要停止接触过敏源。
如果是季节性过敏一般用一用B5或者吃两颗息斯敏就能好。
如果是角质受损那一定不要再过度清洁，建议用habaSQ油或者其他温和但修复角质的产品，油润一点也没关系，我用了科颜氏的蓝精灵修复精华觉得很不错，有点像薰衣草精油，还能消炎。

皮炎太严重的还是先去找医生吧，不要自己折腾，乖。我患过脂溢性皮炎，没办法根治而且医生开的外用药膏都是激素，有效但是不能长期使用，只适合严重时应急。复发的时候我一般只用理肤泉B5和Fab急救霜，这两个过敏的时候也可以用。然后内调也很重要，我会吃混合维B和甘草片，这两样都是当时医生开的，不算处方药吃了没啥副作用，但是对脂溢性皮炎有一定的缓解，饮食也一定要清淡，辛辣的刺激的就别吃啦。
其他的想到了再补充⊂((・⊥・))⊃
编辑于 2015-10-26
刚子
刚子
闲不住的闲人

谢邀。

这个问题非常大，护肤绝对是一个系统工程。

每个人的肤质千差万别，导致问题皮肤的原因有很多。不清楚具体情况的前提下，为不误导题主，恕不推荐不解答。

以上。

～～～～～～～～～～～～～

还是忍不住多说几句。

1.护肤越早越好

2.良好的作息、饮食习惯和对皮肤帮助非常大

3.彻底清洁的情况下补水最重要

4.防晒

5.适合你的才是最好的（别人用着不错的不见得就适合你）

6.护肤是“私人订制”的行为（包括上妆）

楼上的那几个营销号，呵呵～
对了，可以点“没有帮助”，谢谢。
发布于 2015-11-21
知乎用户
知乎用户
律师/心理咨询师/考证狂/90后老阿姨/金融爱好者

我来说说我见过的皮肤最好的女生A好了~我们那里气候湿润，身边水灵的妹子一向一把抓。但是A的肤质真的是...好到夸张。

她的皮肤状态怎么形容呢？完全就是剥了壳的鸡蛋...白就不用说了，堪比欧美人，非常自然。同时无斑无痘，不干不油，皮肤细腻光滑有弹性，满脸的胶原蛋白！~最重要的是真正健康的肌肤会自然有一种淡淡的亮度，脸会亮，白里透红萌萌哒~广告里所谓的”无瑕疵的肌肤”莫过于此了，身边真正的素颜女神。

咳咳，重点来了。我们当时高中嘛，一起寄住在阿姨家，天天黏一起~ 有天晚上我看她洗脸后往脸上涂护肤品。当时我好奇心就上来了，就问她平时都在抹什么呀？
她说："我经常换，都随便在用。不过别人用来抹脸的呢，我用来抹手，别人用来抹手的呢，我用来抹脚...."
当时我就震惊了，弱弱的问了一句：“呃，那你用什么抹脸呢？”
她说：“人参膏。“
哈哈，不过除了这些外用的护肤品，我相信A的皮肤那么好肯定还有别的原因。比如我看到的就有：饮食清淡，爱喝水喝牛奶，注意防晒，早睡早起，坚持泡脚等等。总之她的生活习惯非常健康，而且天天都很开心很欢乐。所以皮肤想变好应该从多方面调理，而不是仅仅依赖用一些好的护肤品那么简单哦~共勉，想变美的女生们都加油吧~
发布于 2015-04-19
知乎用户
知乎用户

我是中性肌，冬天两颊会有一点点干，此处只做经验分享，大家不必义愤填膺。我不是专家，不研究成分，产品推荐方面只说自己用过觉得好用的产品。

1  绝对绝对不要用手碰脸，除了洗脸的时候。平常少做一些托腮的动作。

2 不要用毛巾擦脸，也不要用洗脸海绵，都会大量滋生细菌。可以用抽式洗脸巾。用的时候最好用水打湿，然后挤掉水分再擦脸，不要干擦。淘宝上很多洗脸巾化妆棉一起卖的，普通的就可以。


3 脸上有痘痘或者小颗粒的时候千万不要去挤。洗澡的时候用去角质颗粒按摩下脸，然后洗干净。洗完澡再接着敷片状面膜。颗粒的面膜可以用innisfree棕色瓶子黎麦的，也可以用柚子海盐的，都有很小的颗粒。贵点的有fresh的澄糖面膜。

4 洗完脸最好用爽肤水-精华-乳液（面霜），很多人不用爽肤水的，我觉得爽肤水很重要，不用的话感觉乳液什么的擦不上去。

5 简化护肤步骤，基础的步骤就够了。很多人洗完脸后脸上要涂抹十几层，皮肤会很容易老化，失去自身的光泽。

6 尽量不要用含有酒精的护肤品。爽肤水的话可以用娇韵诗黄水或橙水，不含酒精。

7 最好使用精华。欧莱雅紫色瓶子的抗老精华很好用，美白产品我一般不用，有美白需求可以用olay pro x。

8 不上班不约会的话最好少化妆。粉底bb 都很容易使皮肤起皮或者闷油。如果化了妆，回家第一件事情就是好好洗手，然后再卸妆。

9 卸妆油推荐碧柔粉瓶子，卸妆水也推荐碧柔，还是粉色瓶子，都不超过100rmb ，但很好用，清水可以洗净。

10 只要出门就涂防晒。我同一时期有五六瓶防晒挑着用，这样有新鲜感。防晒推荐碧柔蓝色瓶子和sofina 白蕾丝。成分啥的我不研究，这两个都是使用感好，不油，不白，不搓泥。

11 一天最多洗两次脸。

12 早上不用洗面奶，只用清水洗脸。

13 用卸妆棉卸妆时，一定要用卸妆水全部浸湿化妆棉再上脸，减少摩擦。以前不够就用两片，一定要卸干净。

14 片状面膜两天敷一次，最好在刚洗完澡之后。片状十块钱一片的就可以了，不需要太贵。

15去角质的面膜在洗澡时候涂抹，一周一次，轻柔摩擦以后洗掉。

16 不用睡眠面膜，换句话说，面膜在脸上不过夜。虽然origins 牛油果和雪花秀与润使用感非常好，但是最好别过夜，脸上停留半小时就可以洗掉了。

17 气垫bb谨慎使用，因为非常容易滋生细菌。可以有一个随身带着，以防不时之需。平时每天用的话还是推荐压泵瓶。粉底推荐兰蔻。

18 两周换洗一次枕套。最近刚淘宝了真丝枕套，好用的话准备去the beast买全套真丝床上用品。

19 喷雾不要全天候随时喷，喷雾在脸上蒸发的同时会带走皮肤本身的水分，使用喷雾后及时用乳液。喷雾推荐大葡萄，成分就是葡萄水，这个尤其夏天使用感一级棒，还有一点甜甜的。


先只想到这么多。
编辑于 2017-07-27
nina pu
nina pu
Nina 姐姐
痘印


痘印其实是很难靠护理去除的，长期长痘，除了痘印之外,还会导致毛孔粗大，暗黄无光，看起来非常老态，这个时候,建议去做一些激光类的护理,这也是目前最理想的去痘印的方法。

个人护理方面：

首先平时要缓解压力，

做好防晒，经常按摩皮肤，促进新陈代谢；

最好每月配合着做一次激光类项目。

激光类项目：

首先，光子嫩肤对痘印和痘疤的效果都是非常明显的，而且通过光子嫩肤治疗，不光对痘印及痘疤有一定改善，对红血丝、毛孔粗大等都有很明显的改善。

基本上我自己会隔个两三月做一次，

根据我以往的经验，

做完光子嫩肤一周后，色素开始淡化，结痂，最后脱落，

只有轻微痛感，没有恢复期，

不过需要特别注意的是，做完后一周，一定要勤补水，注意防晒！

然后你提到毛孔粗大的问题.

像护肤品，化妆品对于毛孔基本上并无卵用。至于那些拿着精华、水、面霜跟你说它有缩小毛孔作用的，都可以让他洗洗睡了。

因为毛孔撑大之后确实是不可逆的，不太严重的还可以考虑光子嫩肤这类的轻量级光电项目来解决,但严重的话连光子嫩肤都束手无策.

这种情况,建议考虑医美手段,比如微针,或者像素激光,铒激光等~

但说白了这种剥脱性激光也不是让你的毛孔变小，而是把你皮肤表层处理掉（就像蜕皮一样），长出新的皮肤表层。

所以,如果你的毛孔还没有到无可救药的地步,抓紧时间拯救它吧!
发布于 2016-09-08
艾特bb
艾特bb

这个回答不是第一次出现，前面我用其他号也发过，由于分歧比较大，很多争议，被管理员禁言了，所以换号重发的。有人说我黑西医，高级黑，我只能说呵呵了，我说中医治痘的问题，你说我黑西医。西医和中医个有优势，这不得不承认吧? 要是不认可，亲不用往下看了。急病看西医 慢性病，疑难杂症看中医更好些，这就是我的观点。【痘痘就是慢性皮肤病】

有人说，长痘痘都是年轻人的事么？那是因为年轻，肝火旺，污浊的痰湿就会随火气往上升。身体本来是在找出口把这痰湿排出去的，但人体的孔道7个在头上，下边的只有前后阴。所以，更容易随着肝火往上升，脸部的皮肤总是要细嫩些，于是，肝火就容易从脸部往外排。这是痘痘形成的原因之一。　如果年龄大些，身体内的肝火和痰湿就不可能一次排尽了，有些就沉淀在了皮下，光存在那里也还不错，关键是它还会出来污染血液，血液一污染，就像油污一样，飘到了哪里，哪里的皮肤就冒出一片来，什么蝴蝶斑、黄褐斑。 
　大多数人没有经验，一见痘痘，就认为自己上火了，于是找些祛火的中药来吃，祛火的药没有不寒凉伤脾的。有痘痘本来就说明脾胃虚了，再用寒凉一攻伐，于是更加虚弱，更多的痘痘就源源不断地冒了出来。如果你长期被痘痘困扰的话，那你就千万别指望抹什么药膏、用什么洗面奶在一夜或者几天内就把痘痘彻底祛除，最根本的方法还是要调理好我们的五脏。青春痘在中医临床看来，就是由体内郁热，或因风热外侵，或因过食辛辣油腻之物，使脾胃湿热，蕴久成毒，热毒上攻，通过人体阳经经脉循行上达头面，溢于肌表而发病。就好比，你的脸面是你身体的‘排毒口’，你体内的湿热之毒积聚的过多了，大小便也排不完了，出汗也排不完了，湿毒热毒就只冲你的脸面而来了，所以去除你脸上的痘痘，重要的就是把你体内多余的毒和热从你体内袪除。只有把你整个身体的健康状况全面的调理好了，你脸上的痘痘才算能从根上祛除了.如果你的胃火过大，痘痘会长在鼻子附近，这可是传说中的“危险三角区”，该区内的疖肿，那怕是个小痘痘，也千万不要用手去挤压，那样会引起感染扩散。本来只是一个微不足道的痘痘，因为挤了一下，发生了脑膜炎，以至丧失生命的实例也是不少的。我们只需要耐心一点等痘痘自行熟透，自然会破裂，根本不需要用外力去挤压它。即使是有幸没有被感染，用手抠挤也会留下痘印痘坑，要好久才能恢复，所以千万不要一时手痒就去抠挤，真的是得不偿失！下面介绍的华林胡氏中药面膜催熟闭口很有效果。 
【第一部分：关于长痘的忌讳和基本问题解析】 

长话短说，有三点是祛痘最基本的忌讳。 

一，现在是大夏天，洗脸当然是必要的程序，但如果是寒冷的冬天，早上起来，除非皮肤实在太油，尽量不要洗脸。或者稍微用纸巾擦一下眼睛和口水。至于皂基洗面奶，就千万不要再用了。关于这点很多人要质疑了，为什么呢？你可以看看那些不长痘痘的正常人。大多数都是很少用护肤品的吧，因为人体本身的皮肤是有相当的抵抗力和自我修复能力，皮肤每时每刻都在分泌一种天然的完美护肤油，这种季节人本身新陈代谢降低至少20%-35%，若还随意破坏之，怎能不敏感不发红不褪色不修复？你活该一直长闭合，一直冒油光，一直痘印疤痕不退，一直淤青紫红。 

二，不要想着化妆遮掩痘痘这种事情了。那是实在是太老的女人才做的事情，你那么年轻，最多到了夏天，皮肤就会好起来，而且会愈发出众。只要不发痘痘了，只要不用乱七八糟的东西，只要注意作息规律。无论何种粉底（散粉、蜜粉和BB霜都是粉底的一类形式，而BB霜就是含有粉底成份和护肤成份、隔离成份的东西，实在没那么高尚），其实都是含有金属成分，劣质一些就是铅汞，好一些就是氧化锌，一样的堵塞毛孔，而且那种调色之后，仍然是添加了相当的化学成份。否则你以为什么东西能一直贴在皮肤上而不被吸收呢？整天敷在脸上怎能不堵塞毛孔之类的？不要说很多很多明星啊美女啊都在用，就是没长痘痘，那是扯淡，不长痘痘不意味着皮肤会比不化妆得好。 

然后关于化妆最大的问题，也是所有姑娘需要面对的一个定论:只要是封闭性粉刺，就必然是油性成份太腻的霜、卸妆油和化妆的问题。 

你说你以前也算是不错的女孩，皮肤很白很细，然后化妆之后，没有好好卸妆，变成了这个样子，先是闭合，然后遮掩，直到再也遮掩不住，痘痘从额头到脸颊，再到全脸。这是多么可怕呀？ 

然后请你看看的母亲和阿姨们，我相信她们即使是有皱纹，即使有色斑，但是基本上是一张完好健康的皮肤吧？为什么，因为她们年轻的时候，没有随便用一些乱七八糟的东西，她们更不会每天没事有事就用那些所谓控油去黑头的洗面奶洗脸。问问吧，以前除了结婚探亲和重要的节日，哪个妇女会整天化妆的？ 以前明星都很少化，内地。。 

三，无论何种外用产品，都是在治标而不治本。所谓的七天祛痘，20天去印，简直就是痴人说梦！显而易见的强效激素和抗生素之类的成份，即使好了，也会容易敏感，有红血丝 ，肤色不均衡之类的，痘印和毛孔是不可避免的，极其有可能留下痘坑和长年反复不断的问题肌肤。。我看你说过“还是看西医好啊，效果快。中医又慢又麻烦。”真是很可爱的论调。 因为西医的快，是需要付出代价的，事实上，青春痘在中医里面根本不算什么问题，大多数中医看到青春痘的患者都是很淡定的，因为这完全就是年轻人自我折腾的结果。至于西医，事实上，除了抗生素和手术方面有独到之处，它对顽固的青春痘来说，是完全不能治本的，而且极其容易留下终身的隐患，逼迫你不得不去做激光磨皮。。。到时候就生不如死了。。

年轻人还是不要用那些多的护肤品，大多都标榜着天然，但大家都学过化学吧？混合物是不稳定的，是容易变质的。而那些产品的保质期又是那么长，因为里面含有相当的化学稳定剂、调和剂之类的东西，即使在安全范围内，但长期使用，只是在慢性自杀。别没事有事给自己年轻的皮肤吃补药，会破坏皮肤本身良好的平衡。还懵懵懂懂的，看看你身边不长痘的正常人吧。或者反思自己，为什么以前那么好，突然这么严重，还不是用了一些美曰其名的护肤品吗？！ 这些都不是长久之计，可能一开始会很有效，但时间久了，就会损害皮肤原本的平衡和抗性，会变得依赖这些，而且容易衰老【看看那些长期化妆的脸 卸妆后的样子吧】。 

而中医源自《黄帝内经》的整体治疗的观念来说: 

痘痘本身就是一种身体内部的小疾，当然要从内部开始着手，痘痘的生成不外乎火邪和湿毒的相互浸淫作用而形成的，无论是肝火、胃火、肺火甚至肾火，均可促进痘痘的生成。具体到每个人身上，火邪与湿毒的轻重而形成了表现各不相同的痘痘。针对这些痘痘，采取清热、解毒、祛湿、排脓的治法，内清外透，逐渐祛除长痘的因素，痘痘自然就会痊愈了。注意：因为有湿邪的存在，湿毒粘滞，所以祛痘只能缓治，想一周内治好痘痘，无疑是痴人说梦。这就需要时间，一般2个月，具体因人而异。 

（看完以上，大家仍然对化学类护肤品抱有侥幸心理的话，请看看你的手，脚和颈部的皮肤，也是很脆弱，也是经常水洗的，但就是很少抹东西吧？对比脸部，结果呢，＾＾） 

至于大家说的“吃了很多中药总是反反复复没有用啊”，这是因为中医的能力和医德是有高下之分的，他们只管短期迅速治好你，以谋取利益和声望，顺便等你小孩子不懂事复发了再找他，以此循环，可明白？ 

辩证整体治疗的方法：“痘痘的生成不外乎火邪和湿毒的相互浸淫作用而形成的，无论是肝火、胃火、肺火甚至肾火，均可促进痘痘的生成。具体到每个人身上，火邪与湿毒的轻重而形成了表现各不相同的痘痘。针对这些痘痘，采取清热、解毒、祛湿、排脓的治法，内清外透，逐渐祛除长痘的因素，痘痘自然就会痊愈了。” 

大家往往只是看到了辩证论治，忽视了整体观念，所以祛痘效果往往不佳。就是只见树木不见森林，只看见痘痘了，没看见引起痘痘根本因素。 

一般的中医就是会告诉你什么左肝右肺之类的发痘原理，然后给你开一些清热去火的药，大多为寒性的菊花、夏枯草、金银花之类，这没有错，有些中成药如皮肤病血毒丸、黄连上清片啊都是这个原理，但这是治标不治本，而且长期服用寒性的药物会伤害脾胃，很容易复发。从长远来看，只是饮鸩止渴罢了。 

关于 “是药三分毒”解释一下吧！比较专业一些。 

除确切的毒性中药外，一般所谓的中药“毒性”是指药物的“偏性”，一般分为寒、热、温、凉四大偏性。就比如喝番泻叶拉肚子啊，泡胖大海清润咽喉啊，就是运用的番泻叶的寒凉泻下和胖大海微凉的偏性。 

而长痘痘本身就是身体的偏性出现了异常，多为热性并有有湿邪混杂而致。所以，祛痘也是“以偏治偏”，痘痘没好之前就是说身体还是存在偏性的，吃药就没问题。 

另外请允许我直接说明中医养生中的两个重点： 

一，只要你肾脏坚强有力，身体就不会出大问题，所以要注意喝水，不能憋尿之类的。尤其是男人，欲望太盛，不节制，这个季节了，那就是找死，活该长满脸大脓包。 吃黑色食物是补肾的，黑芝麻，黑豆之类。 

二，对于女人而言，最重要的是月经的问题。只要你月经正常，就不会有什么大问题。正常就是，一个月，允许提前一两天，但绝对不能拖后，而且不痛，不硬块，不白带异常之类的^^ 请注意，如果初潮以来，一直有规律的提前或者延迟一周左右，只要不痛经。那也是正常的。 补充，月经期间严禁用药、上蹦下跳，洗头，冷水和补血。 以上两类，请去医院做相关检查和治疗。恢复后再看上面所说的所有。 

特别补充：黄帝内经有言“秋冬，乃百病淤滞潜藏之时；春夏，乃万物生发泄通之道。”简单说就是夏天是阳气最盛的时候，气血最足，所以通泻百病，冬天是阴气最盛的时候，气血最弱，所以淤滞湿泄。这不难理解吧？万物都是向着太阳生长，所谓生物钟就是个体受群体制约的一种身体阴阳运转的规律。正如不见天日的沼泽都是有毒有害生物的温床，此乃阴湿长邪毒；向日葵永远生长在阳光充裕的大草原即具有“平肝祛风，清湿热，消滞气”的效果，此乃阳生化万物。 

所以不再对中西医治疗做任何辩论和解释了，怀疑的看官请一定止步！止步！嘘声离开吧。

【第二部分:关于各种常见可以祛痘去火的饮食养生的推荐和禁忌。】 

1，请大家注意，对于便秘就吃芦荟胶囊的朋友。 

请参照以下： 

芦荟：有毒，清热泻火型中药。对于体质虚弱或者脾胃虚寒者应谨慎服用。对于吃了芦荟鲜叶后就呕吐，或引起剧烈腹痛和伴有腹泻者也应禁止食用。芦荟是一热解毒峻下之药，对强体质比较适宜，而对弱体质，效果可能就不理想，甚至加重病情，比如阳虚、虚证，以及心脑血管病、肝病、肾病、肾阳虚腰痛等寒性病症以及肾虚的人。只有了解适应性后，才能更好地发挥作用。 

2，关于薏仁的特别注释： 

薏仁是常用的中药．又是普遍常吃的食物，性味甘淡微寒,有利水消肿、健脾去湿、舒筋除痹、清热排脓等功效，为常用的利水渗湿药。主要成分为蛋白质、维生素B1、B2有使皮肤光滑，减少皱纹，消除色素斑点的功效，长期饮用，可以美白和抗辐射。 它能促进体内血液和水分的新陈代谢，有活血调经止痛、利尿、消水肿的作用。美白滋润，消斑，防止脱发，瘦脸，同时也有节食的效果。可预防癌症。另外对面部粉刺及皮肤粗糙的有明显的疗效, 

它的禁忌是：本品力缓，宜多服久服。脾虚无湿（身体虚弱），大便燥结（口干舌燥）及孕妇慎服。女子经期也不宜服用。 

3，关于绿茶的禁忌，少女要小心啊 

适宜人群:一般人均可饮用。 

（1）.适宜高血压、高血脂、冠心病、动脉硬化、糖尿病、油腻食品食用过多者、醉酒者。

（2）.不适宜发热、肾功能不全、心血管疾病、习惯性便秘、消化道溃疡、神经衰弱、失眠、孕妇*期妇女、儿童。 

特别注意: ,因为绿茶能在很短的时间内，迅速降低人体血糖.所以低血糖患者慎用. 

食物相克:不要用茶水送服药物；服药前后1小时内不要饮茶。人参、西洋参不宜和茶一起食用。 

忌饮浓茶解酒；饭前不宜饮茶；饭后忌立即喝茶；少女忌喝浓茶。 

【第三部分:关于一些天然护理的推荐，比如纯露，中药面膜之类】 

１.关于纯露花水。 

只有到了我这个年龄，才会明白，最简单的东西就是最好的道理。 

考虑到大多数MM不知道纯露和花水的区别，甚至不知道纯露是为什么的情况，特做以下注释： 

什么是纯露？ 

“纯露”，是指精油在蒸馏萃取过程中留下来的蒸馏水，是精油的一种副产品。植物精油在蒸馏的过程中，油水会分离，因为密度不同，精油会漂浮在上面，水分会沉淀在下面，在蒸馏分离精油后，留下的这些水分就叫“纯露”。纯露中含有微量的“酸“与“脂”类物质，化学结构与一般纯水不同，对身体调理很有帮助。纯露除了含有微量精油外，还含有许多植物体内的其他水溶性物质，这些都是一般精油中所缺乏的东西。蒸馏的过程中，水不断的流过植物组织，将组织中大量的水溶性物质溶出。纯露成份天然纯净，香味清淡怡人，特性和精油接近而清淡，多了精油没有的许多矿物质，其亲水性更容易被皮肤吸收，也更温和没有刺激，用起来也比精油简单，成为MM们天然补水的最爱。 

花水不是纯露 
花水是用很少量的单方精油合成的，用果油和其他添加剂混合而成的，比如玫瑰花水，它是由万分之三到万分之五的玫瑰油和其他香料等合成的，不是纯天然的，而是化工合成品的原料、与天然的原料，光是成本就有百倍之差，远远不等同于百分百蒸馏获取的纯露。 

以上只是国内的说法。 

（另外一些欧美产品的纯露产品翻译过来成了花水，请大家不要在意，其实都是纯露一个意思。但需要特别区别于国内那些不良商家利用你的无知进行欺骗，说纯露和花水是一样的）

误区 

水精油（纯露）不是花水，它除了含有微量精油外，还含有许多植物体内的水溶性物质。此种纯正露香味多半以[植物水溶性物质]为主，但并没有精油独特的香息，相反的，它类似人体血液里充塞着各种矿物质的味道。此混合大地矿物养分与地泉水之物质便是植物水溶性物质。 

拥有100%植物水溶性物质的纯露，其所含的矿物养分，是精油所缺乏的。所以纯露同精油有相同地方也有不同的地方，各有所长。而花水是 

精油和一些化学剂调配而成，一般都很芳香很粘稠，而且摇一下，泡沫很快消散。 

而现在市场上和TB上大多数表明天然纯露的店铺，其实都大多不是天然的。 

纯天然的纯露摇过之后，一般需要几分钟不等，泡沫才会下去，而且天然纯露里面都是有一些沉淀的，不可能是完全干净的水的样子。 

2.关于祛痘的万金油组合，因为LZ自己长过痘痘，所以后来很注意家里弟弟妹妹之类的问题，经过多方实践考核，确定了以下的搭配。。 

首先是英国AA网或者德国O家或者类似欧洲品牌的薰衣草纯露+洋甘菊纯露，和不可替代的英国AA网最受欢迎的王牌面霜金盏花膏作为主要用，而以德国O家的问题肌肤面油（以前是NYR康复利，但是现在国内市场很难保证正品，所以不好推荐了。。）作为重点涂抹痘痘，这样就可以用很久很久，外加上华林胡氏中药面膜做消炎清理只之用。请大家根据自己的条件购买，其实AA的康复力霜也很好，而且相当温和。 

补充一点，如果十八岁以下的孩子，只需要薰衣草纯露+AA的金盏花膏就可以，除非你皮肤受损很严重，再加上洋甘菊纯露吧。 

洋甘菊纯露对于面膜的修复效果，不用多说所以不做另外说明了，我重复得头晕。 

关于华林胡氏中药祛痘去印面膜，纯中药的不必多说，关于中医西医的论证第一部分已经说得够多，另外，他家清理修复面膜对毛孔效果也很棒。 

关于NYR的康复力霜，不了解的，请大家务必看看百度和各种介绍。 只能说，NYR康复力霜对闭合粉刺有特效！！！！ 

一分钱一分货，我很推崇。 

上面从纯露到水到面霜都做了推荐，一般问题肌痘痘肌如此已经够用。这就是所谓的万金油组合，经过多方长期实验，本人至少重复不下1000次。亲口说，结果是很多一般性的痘痘都痊愈了，皮肤变得稳定了。 

所有的推荐都建议大家某宝自己找，找信誉好的评价好的买就行，我就不私信了。 

补充：平时可作为日常饮用，特别适合阳虚体寒者服用的茶水配方，即枸杞、黄芪、胎菊花一起，以3:1:5的比例直接泡水喝，1就是5G。 此方乃肩顾了清热去火，温补养肾、转弱升阳的功效，但切记过犹不及啊。 

关于这三味药，请大家详细查阅百度百科。胎菊花就是杭白菊的胎型，清热去火但寒性最小，可以久服，不是寒性大的野菊花等可以比的。 

另外，那阴虚怎么办呢？实话说，正常情况下，阴虚都是阳虚引起的，阴虚必然包括了阳虚，所以只要治好了阳虚，阴虚就自己好了。 如果实在需要补的话，阴虚只要补肾阴即可。五色粥和养生粥都可以哦，记得买点纯正的黑芝麻或者冰糖作为添加，效果也很好的。 ” 
这个非常适合体寒虚症的姑娘们，可以每天喝，早晚两杯400ML即可，配合不定期的红糖生姜汤，对MC提前血块痛经等有特效 但经期前三天和经期时请不要喝。。。 
当然，如果你还同时服用药物，请务必请教你的医生。 
西医把人看成一架组织严密的机器，都是零件，坏哪修哪。中医把人看成生命，整体性的。不是说西医不好，各有所长！一个同学的爸爸，西医医院宣布等死了，没办法回家了，找了个中医，调理好了，真真切切！也许是偶然，但是不找那个中医看也许就真死了！中医的上火，人参大补流鼻血，西医都是不认可的，可确实存在不是吗？人参在西医的眼里就是草根！在中医眼里却是了不得。生命的神秘人还不能了解，但绝对不是一堆有组织的细胞就能成为生命体！
观点可以存异,有的时候也可以中西结合嘛。西医很强大 中医很伟大！也许我的回答有不足之处，请指正。觉得有帮助的请点个赞。
编辑于 2016-10-10
汤圆滚滚来
汤圆滚滚来
痴迷日剧日影的英专学生

我觉得夏天 
是又能美白又能减肥的大好时候

醒来600ml的凉水（温水当然更好啦～

每天运动40分钟（随便干嘛反正能流汗就行）

夏天超喜欢每天一勺蜂蜜柚子茶泡起来喝

还有就是！！！！！
大
招
来
了
！
每天来两小碗（银耳 红枣 百合 莲子 枸杞）煮的汤呀！！嫌苦就放两小颗冰糖 。我不喜欢枸杞就没放

亲身实践 喝了这个皮肤不可能不变好 


（在这儿统一回复一下，傲娇地拒绝对每一个问的人夸过去！app：你今天真好看）



补充1：每天排便很重要！！！我妈妈说排便等于排毒呐！我这两天可忙了都没时间想着这个大事就...长了一颗痘....听说甜食吃多了也会爆痘？？？

补充2:   不只一个人来和我说一口气喝600ml好像太多了....嘤嘤嘤真的吗....答主爸妈也很爱喝水，每晚都要烧3壶才能保障全家一天的供应，那应该是水牛世家没错了。
我这个月初去南京玩，因为天气好热，怕在外面口渴但又喝不惯矿泉水，自己又懒得带杯子，就每早从民宿出发前一口气喝了1L的水＞＜一口气喝了这么多水后也没尿频估计因为一直在出汗。活得像个骆驼kkkk

补充3: 因为这五样好几个偏凉性来姨妈的那一个星期最好别喝了
编辑于 2017-07-27
木木然
木木然
一个没有什么行动力的白羊座

养皮肤养了那么久终于可以回答这个问题了

为了让你们有看下去的欲望…我先上个对比图…请一定要做好心理准备…我个人感觉还蛮可怕的



你们确定要看哦？




……………


……………

………………

……………


下面是我长得最严重的时候…

然后下面是我现在


虽然现在也没有很好吧但是和长痘痘的时候已经是天差地别了…下面我分析一下长痘原因，下一页我讲了祛痘心得。

长痘原因分析：

答主青春期的时候就一直在长，但是不严重，后来高三的时候就自己好了…结果现在二十岁了突然来了个大爆发，让我这种已经享受过一年美貌的人怎么接受

但是也怪不得别人…是答主自己太折腾…其实早就发现开始长闭口了但是一点也没上心，还是三文鱼牛油果，各种牛肉开心的吃吃喝喝…然后火锅烧烤也吃的巨多。长痘痘了就喜欢用化妆品遮遮遮但是这种都是越遮越多啊！！然后还作死的用了茶树精油泡纸膜敷着…不作死就不会死…这个真的是大爆发的直接原因…当年年纪太小不懂事…大家不要喷我…

然后就整个脸又过敏又长痘，一长痘就喜欢用手摸…细菌什么的上去就更夸张了…也怪我当年没建立起一套护肤体系

—————————————————————

下面是干货！！注意！注意！！

首先是生活习惯，这是最最最重要的，你拼命熬夜晚睡吃辣吃油…用再好的护肤品也没用…当然我身边也有非常多怎么折腾皮肤都又白又透的小贱人们…只可惜我没有那个资本…

我下决心要养皮肤的时候，我就开始戒油戒荤…开启素食时代…一天可能会吃一个蛋补充蛋白质，然后就是完全水煮的蔬菜。中医的发物比如牛羊海鲜我都一点都没碰，水果里的芒果菠萝也不敢碰。在这里引入一个GI（升糖指数），可能平时只有糖尿病人会注意GI指数，但是有科学研究表明…高升糖还是会引起痤疮的…所以我吃的时候也尽量不碰高升糖的。还有就是牛乳类的我都不碰。长痘痘最忌的就是甜食…爱吃糖爱吃蛋糕的朋友们…你们忍忍吧等美了以后再吃。

目前为止还没有发现运动和皮肤的关系…据可靠消息称，运动多了痘印会好得快皮肤也会变得透亮。然后！！多喝水！！每天准备一桶桶的热水全部喝下去！！每次喝水喝的多了我都感觉皮肤水润很多…

给大家分享一下我的食谱：

早上：红豆薏米粥

中午：蔬菜意大利面

晚上：蔬菜汤

零食：坚果葡萄干


我尝试了半年素食，但是偶尔还是会开个荤，皮肤总体透亮了很多，也不存在什么营养不够或者觉得没力气的情况。现在的话每顿会吃一块鸡胸肉，但是依旧是水煮，不吃油。

话说我做祛痘功课的时候有很多人说红豆薏米粥对皮肤真的很好…大家可以尝试一下。

然后就是不熬夜。我自从知道睡眠的重要性之后，我基本十点一定上床，早的话九点就会睡觉，每天也都会有午睡的时间。我睡的算比较久的…可能有快十个小时…但是每天早上起来真的都可以看见皮肤比之前好了，每天都很期待。

然后就是防晒，如果你可以宅，那么就请你宅到发霉，如果你一定要出门，那么只要是白天就一定要涂防晒并打伞。紫外线特别容易引起毛孔发炎，但是毕竟防晒霜也会闷痘，可以的话就呆在家里或者晚上了再出门吧。

不论你是什么类型的痘痘，我相信如果你能做到良好的生活习惯，不说痊愈，至少会好很多。

针清：

总的来说针清真的是拯救了我…长痘痘的时候其实油脂完全堵住了毛孔，你再用补水面膜都没有办法补进去，只有通畅了毛孔你才能补水…针清的话美容院就可以了，我找的是祛痘中心…店名就不说了哈哈哈知名的那几所都蛮好的。如果你只有一两颗痘痘的话自己买根针自己清就好了，如果你超级超级多…那么还是去专业机构吧。注意：刚清完的时候脸会特别红特别肿…不要太在意，忍一天就会好很多，我的话是一周内就完全看不出了并且皮肤会比去之前光滑特！别！多！

冷喷：

我长痘痘的时候整个皮肤脆弱到不行经常过敏，就去医院皮肤科开了冷喷，很舒缓很好用，喷一下皮肤就镇静很多。然后我就自己买了一个迷你冷喷机，什么时候皮肤痒了就喷一下。这个可以自行淘宝了 

护肤品：

首先是祛痘的，祛痘的药很容易让皮肤产生抗体…所以大家选购的时候最好囤几种不同类型的，不要一直用一种。


克林霉素用药：这是我我认为最好用的！！注意！！注意！克林霉素凝胶！！克林霉素擦剂！！爱到不行…果然这种专门的药品效果就是不一样…凝胶的话我点涂在痘痘上，不管是大痘痘还是小粉刺都特别有用…这个是消炎的也不会像刷酸那样有风险。擦剂的话我是拿来治黑头闭口粉刺这种，感觉也是特别好…反正用了之后我就没怎么长痘了。不过这种要最好不要用超过三个月，不然很容易没效果

以下是我觉得还算可以的：

理肤泉k乳和duo+：这两个的话还是很好用的，但是毕竟是刷酸很容易烂脸…刚长痘的时候什么也不懂，用了这些以后也没忌口啊什么的但是还是好了蛮多，特别是k乳，疏通毛孔还是非常好的。但是问题是，k乳用了以后很容易爆痘…我有蛮多痘印都是因为用了k乳长了特别大的痘痘才留下的。duo+也是双刃剑…虽然它号称不会留疤，但是每次涂完皮肤都会黑很大一块，持续好几天，然后那一块会自然脱落才不留疤………但是问题是！！我会忍不住去撕那块黑的！！然后就导致我留了好大一块疤…入购还是需谨慎。

TP茶树祛痘凝胶：这个的话感觉就是把皮肤吸干…也会留下一块黑印子，说实话我不太喜欢，但是我好多朋友都说好…我用了几次都不尽人意…不过对于由肿又痛的痘痘还是有一定用处的。

尤皙祛痘膏：不像是上面两种会拔干皮肤，但是涂一个晚上红肿的痘痘就不痛了！没有用过很多次但是好满意。


然后是美白去印和日常护肤啦

美白去印：

下图是我的最爱…


美白的话我倾向于用美白精华和面膜。上图的四个小瓶都是精华…然后左右两边的是资生堂精华的新旧版…不小心放多了一个…

资生堂新透白：这个的话去印我没有觉得很明显，但是皮肤真的是会变得透亮透亮的。

sk ii小灯泡去痘印版：因为它我彻底变成了sk ii的死忠饭，祛痘印美白好用到不行…也没有觉得皮肤用了会干，反正用它的时候痘印真的好的特…别…快…

尤皙美白修复精华：这个也是巨…好用的祛痘印产品，号称烂脸救星。首先要记住一开始用的时候要隔一天用一次建立耐受，之后的话就可以天天用啦。我的皮肤略敏感但是用起来还是不错。我都是晚上涂这个白天涂sk ii。要记住如果想要白天涂一定要做好防晒！！这个不能见光！！

sk ii美白面膜+前男友面膜：面膜的话我都是一周用一次，如果我有钱的话会选择一天一次的…这两个面膜反正都特别好…皮肤用完以后透透白白可以持续好多天。虽然他们很贵，但是我还是推荐…把每天敷普通面膜的钱省下来…一周敷一次好的吧

日常护肤：

卸妆：我比较怕卸不干净所以用的是卸妆油，植村秀的，我感觉不会闷痘什么的

洗脸：这里推入一个PH值的概念…长痘的人出油多皮肤易呈碱性，但是弱酸性对皮肤是最好的，所以大家选洗面奶的时候不要选皂基的，尽量选氨基洗面奶。具体哪些洗面奶请自行百度/微博/知乎啦～我用的是理肤泉的ph5.5的祛痘洗面奶

精华和面膜我上面都说啦

总结：

生活习惯：早睡，饮食控制，戒大鱼大肉大辣，多喝水，防晒，其实还有一个是保持心情舒畅…相由心生啊！

祛痘（按好用度排列）：针清，克林霉素凝胶，克林霉素擦剂，理肤泉duo+k乳，尤皙祛痘凝胶，TP茶树凝胶。

美白去印（按好用度排列）：sk ii精华+面膜，尤皙美白修复精华，资生堂精华（其实这一块已经都特别好用了）

洗面奶：拒绝皂基类，用弱酸性洗面奶

我的感受就是，先天的基因给了你一个基本分，之后的努力都只是往上加加减减。我身边有特别多女生经常不卸防晒不洗脸，吃香喝辣熬夜也一样皮肤好的吓人…那种类型的天生丽质我们可能是一辈子也赶不上了…但是你认真护肤的话皮肤至少会比你之前要好。

到这里就结束了…希望你们的皮肤…越！来！越！好！
发布于 2016-09-08
唐世岳
唐世岳
不是很正经的正经人

讲道理，没想到现在在知乎上面拿PPT的照片也可以骗赞了。更重要的是，这PPT还不是自己的。

1. 难道知乎上面直接拿来的知识就可以用了？我们曾经的考据精神呢？

2. 我质疑国家美容师这个名头，请问是跟国家炼金术师一样，二次元萌来的吗？

3. 谴责随意转发叶老师上课照片的人，请问你利用叶老师的PPT吸粉有经过他的同意吗？

-------------------------------

1.  考据精神

医学上有一句话，一切抛开剂量谈毒性的行为都是耍流氓。这句话的本意是告诉我们理论要结合实际。

叶老师的讲解才是精华，而你就把PPT放上来，答主用了毁容你负责吗？呐，毁容可是叶老师自己说的哦。

以上文字截选自广州日报对叶老师的采访

常言道“甲之蜜糖，乙之砒霜”。护肤品也是这样的，只要是长过痘的人都肯定有过经验：我闺蜜用XX没事，我用了毁了；我朋友用XX没事，我用了毁了；我隔壁王大妈家的小丫头用XX没事，我特么又毁了！（喵的，这跟性别没关系吧）

不信？PPT里不是推荐SK2和“阿达帕林+抗生素”吗？麻烦用SK2长痘的筒子们在评论区举个手！长痘痘用阿达帕林和抗生素治不好的也在评论区举个手！

---------------------------------

2. 国家美容师资质问题

首先，没有国家美容师这个称号。事实上，正统的科班出身的美容师比医生还要稀缺，本科培养周期一般在5到8年。但是国家是有开放美容师证的考试的。

分别对应国家一级（高级技师级），国家二级（技师级），国家三级（高级），国家四级（中级），国家五级（初级）。请问您是哪一级呢？或者还没考过？

---------------------------------

3. 授权问题

这位叶老师全名叫叶剑清，今年39岁。中山大学化学与化学工程学院出身，并且一直在中大读完了博士并留教。本硕博读的都是化学，不过现在是中山大学药学院的讲师，这个PPT是他在他的公开课【美容药物学】上放出来的。

叶老师百度百科链接在此：叶剑清_百度百科

另外，叶老师是有把他的PPT放在他的QQ空间供学生下载的，但是某答主放出来的是网上非常盛行的学生拍摄的版本，所以我猜测你应该没有听过这门课，也没有经过叶老师的授权。当然，这是推测，欢迎打脸哦。

----------------------------------

【还是分享一点干货】

最后，我作为一个在护肤上面交了太多学费的职业学渣想跟萌新们分享一点体会⁄(⁄ ⁄•⁄ω⁄•⁄ ⁄)⁄）

护肤应该是理性对待的，一定要先懂得自己是什么肤质，有什么问题，想要解决什么问题。我们才能对应的去找解决办法。此外，我们接触到的所有皮肤知识，一定知识参考，不能全信，不能照搬，包括我这里说的。

比如叶老师PPT里面就有几个我明显不认同的地方：

1. 对于痘痘的分类，明显是有缺失的，我更容易接受的是医院分类：白头粉刺、黑头粉刺、炎性丘疹、脓包、结节、囊肿和聚合性粉刺。

2. 面部和胸背部的痘痘不能混为一谈，面部痘痘大多是由于毛囊皮脂腺功能问题造成的炎症，而胸背部很多主要是由于细菌和真菌原因造成的炎症，也就是毛囊炎。比如特别常见的马拉色菌毛囊炎。那处理的方式应该也是不同的。

3. 每日一杯红酒，这个谣言早就被辟谣了，酒由于是典型的阀值类摄入物，每个人阀值不同，酒驾取得是中位数，20年前倒是有这么个说法（每日一杯），基本上都是经过很不严谨的随机双盲而得出的结论 。大部分人基本就是1杯啤酒，即到阀值 ，阀值以下，对人的好处，是几乎没有，如果在阀值以上，是一定有坏处。 另外，红酒预防心血管疾病，也早已被美国每年发的心血管年报去除，现在所有的刊物，都是不建议饮用任何酒精类饮品 。

4. 氢醌，这个真的是要命了啊，叶老师可能由于是化工出身又在药学院任教，可能习惯了“解决问题”这么一个视角。但是作为一个没有皮肤疾病的人，我真的很想说，我们的问题没有那么重，需要的反而是护理啊老师。氢醌是有毒的，正常人服用5g即可致死，护肤品严禁添加，只能用于药物。而且添加氢醌的药物一般是用于治疗黄褐斑之类的“色素性皮肤病”，痘印没这么严重吧老师！

5. 提到痘印也是一个心病，痘印分为红印和黑印，而叶老师明显没有把红印拎出来。氢醌对红印是无效的，因为这个成分影响的是黑色素的表达。

……

……

综上，其实这个PPT有非常多至少不能让我肯定的地方。可能精华都在叶老师肚子里吧。

所以，建议姑娘们护肤前，先了解自己的肤质吧。

--------------------------------

【最后吐个槽】

什么时候知乎的人变得这么Low了？

这是PPT诶！

一点解释都没有的PPT你们竟然可以接受！

不考虑应用场景吗！不考虑知识对错吗！

基本的版权意识也都没有了吗！

你们当这是百度贴吧还是虎扑了！
编辑于 2016-10-24
Ford
Ford
心理学者

护肤这个问题，只要方法正确，坚持付出就一定会有收获。皮肤问题除了外养，内调也是相当重要的，相由心生，情绪平和、保持一颗善良的童心。

 首先说一下护肤品，答主属于敏感肌，也尝试过很多种护肤品，但是坚持用的，用的多的就是日系的两种，芙丽芳丝和花印纳豆。

芙丽芳丝的氨基酸洗面奶和花印纳豆的水乳，芙丽芳丝的氨基酸答主曾经迷恋了很久，后面换成日系一些其他牌子的效果也感觉没多大区别。

但是适合自己的早晚洁面一定要有。花印纳豆的水乳答主用着还可以，长期用基本的保湿够了。护肤品这块甲之蜜糖乙之砒霜，在此提醒各位爱美的宝宝一定要有自己的想法和主见，千万不能看见别人用什么就跟着瞎买什么。还有要买什么护肤品尽量去专柜或是屈臣氏购买，答主把网购的和在屈臣氏购买的相比，不说谁真谁假，但是有一定的区别的。

 今天十月份答主去参加堂妹的婚礼，堂妹是小县城公务员一枚，收入还算可以，堂妹的强大伴娘团也都是她同事，早上化妆的时候，从各自包包里拿出护肤品化妆品全是一线大牌，什么香奈儿、雪花秀之类的，但是一个个素颜那真的是惨不忍睹。毛孔粗大加各种荧光剂脸、激素脸还有痘痘！对于她们是如何搞成这样的答主真的不解。答主这种基础护肤加两天一张面膜的已婚大妈，皮肤彻底完善她们这些小年轻。另外，据答主表哥讲，以前在华强北做手机电子产品的如今很多已经转行做进口护肤品了，听到这个消息，答主从此护肤品拒绝网购！拒绝大牌！拒绝跟风！

 答主作为一个已婚大妈，也经历过皮肤常见的三个问题，痘痘肌、脸黄气色差、长斑。但是解决的还算顺利，下面将这三个问题的护肤心得分享给大家。

 痘痘肌那是在上高三的时候，主要可能是高三压力太大以及缺少运动等引起的，反正高三到大一都是反反复复的痘痘脸。吃了n多方子的中药，每次最终疗效都是发一脸。美容院的修护疗程也没少做，巨额花费治标不治本，有时候连本都治不了。在答主不折腾放弃治疗半年后，痘痘好了，所以痘痘这个问题还是只能靠自己找到问题的根源，坚持调理，养成健康的生活习惯。

排除一些病理性的原因多囊卵巢、内分泌等，很多宝宝们长痘的原因是因为脾胃湿热，所以调理好脾胃，去湿健脾是关键。

对于脾胃湿热引起的痘痘，有个扁鹊的典故和方子大家也可以试试。

扁鹊，姓秦氏，名越人，战国神医。时江南地势低湿，疫疠为害，邪毒为患，士之居者，面疮伤颜。适扁鹊出齐，隐荆楚。时窈窕少妇，以纱遮面，向隅而叹。扁鹊取赤小豆、黑豆、绿豆、甘草若干，熬制成汤，嘱妇上药淘净，用水煮熟，每日空腹时任服。七日，妇尤遮面。问之，曰：“过美，恐红颜祸水。”民仿而效之，疮者暗刺祛褪，体毒尽解，粉面朱唇，遂尊世间奇方，曰“扁鹊三豆饮"。

主要配方其实就是：绿豆、赤小豆、黑豆和甘草

搭配和熬煮挺简单的，大家可以按照方子尝试一下，答主也试过这个方子，感觉对于去湿毒效果比较好，对于吃甜食、油炸等食物造成的痘痘有比较好的疗效。不方便天天熬的也可以么宝剁手熬好的扁鹊三豆饮，除了扁鹊配方的材料外，还添加药食同源类的食材和木糖醇，口味清淡，去湿清火祛毒。

内分泌失调引起的痘痘主要从饮食、运动上入手，必要时辅以药物治疗，要养成良好的饮食习惯，多吃新鲜果蔬、高蛋白类的食物，多喝水，补充身体所需的水分，同时多参加各种运动锻炼，加强体质，还要有科学的生活规律，不要经常熬夜，以免破坏正常的生理规律保证充足睡眠。

最后，痘痘肌一定要解决排便问题，这里答主推荐一款早餐，酸奶燕麦粥，不是超市卖的燕麦酸奶，将纯燕麦片开水冲泡好之后静止两分钟，再加入酸奶，搅拌均匀后食用，清肠效果特别好，排便很通畅，平时喜欢吃五谷粉的，也可以用红豆薏米红五谷粉代替燕麦片，调成酸奶五谷糊。

  脸黄长斑这个情况主要发生在答主生完孩子之后，掉头发、脸色差、斑斑点点一脸！气色差答主也吃过中药、阿胶糕等等但是真的太难坚持了，而且容易上火。后面答主在美容院的闺蜜建议早餐吃点五谷杂粮来改善气色，多敷面膜来淡化斑点。简单的两个小细节却收获了意外的效果。五谷杂粮可以自己搭配打豆浆或者熬粥吃，也可以冲泡现成的五谷粉。答主阿宝购的神洲杂粮粉配方还可以，口感稍逊五谷磨房，但是价格要优惠很多主要是配方值得推荐，改善气色的粉粉除了红皮花生、红枣、枸杞、红曲米这些补气补血的食材外，还有红豆和红薏仁这两种健脾去湿的成分。食物太精细，缺乏运动，湿气也是现代人的一大问题。湿气太重会让人萎靡不振，整个人精气神特别差。

    心情不好、压力大导致的面色差，可以试试月季花、玫瑰花、绿梅花等这些花茶。如果没有糖尿病，可以放点冰糖。月季花“疏肝解郁”，玫瑰花除了能疏肝 解郁，还有活血和调和气血的作用。另外，积极投入到大自然当中，爬爬山、多交朋友，唱歌、跳舞，调节自己的性格和心情。每天喝一杯红酒也能调养好气色喔。最后强调一点，菇娘家家的千万不要熬夜，更加不要懒，每天坚持运动，不仅能保持健康和好的身材，对于促进血液循环、改善脸色也是很重要的方面。所以懒和不忌口的小仙女只想烧钱用护肤品不内调改善，却想要收获特别好的皮肤那是不可能的喔。

   好了就想到这么多了，之后想起来再补充。。。。。。善良的小仙女们清动动小手给个赞喔。
编辑于 2017-11-15
Judy Cheng小姐姐
Judy Cheng小姐姐
有紧急提分需求可以私信约托福听力/阅读/GRE阅读课

如果基因无法改变，想要皮肤变好，就要对自己狠，说得到，做得出，这是做任何事的本质。

天生皮肤敏感/不好的人，我能推荐的是换一个环境，打个比方，不一定对，从南方换到北方，从温带换到热带，从中国换到欧洲，从欧洲换到美国。个人只要回到南方，皮肤就会更好，但容易着凉感冒，所以我还是待在干燥的霾都北京了。我朋友说在瑞士奥地利那边，姑娘们皮肤特别好，因为水土养人，紫外线少，个个胸大肤白貌美，羡煞我也，今年年底让我会去那边，感受一下他们的水土。他还给我讲中东美女多，皮肤好，有一个秘诀，一般不轻易外传，所以大概明年要去体验一下。我一个朋友去年去台湾交换，今年回来后脸上的陈年痤疮都消掉了好多，他说那儿空气好，食物干净，养人。还有他用日本的Albion健康水，我心里是服气的，建议亲们可以试试，据说是医用的。所以这次我还从香港给他带回来两瓶，每次帮人带货也会买这买那的。

-------------------

最重要的绝对不是金钱，在今年之前，我几乎不买任何化妆品和护肤品，最重要的是执行力。（还有说钱多的亲们试试工作14-16小时，还有赚再多几乎月光有什么用，都奉献给买买买和旅游了，所以我最近开始反思，减少工作量，身心健康最重要）

护肤事业就我不到半年的时间来看，时间，精力，坚持才是最重要的。我给自己的要求是早上护肤，晚上护肤， 也出现过早上/晚上不规律护肤，但很快就发现不能这样。之前刚开始护肤，还会走完一道道程序，摸索一段时间发现根本不需要这么多，继续摸索继续学习，在我看来，护肤也是有学问的。之前也会时不时化妆，捯饬完看到自己美美的，感觉很开心。但慢慢得越来越少，一般只需要口红或BB霜就可以，把眉眼部分处理一下，就不会差。


感觉我现在做什么事都是秉持这个态度，还真的能无往不利，要不然不做，要做就做好。

* 你是如何将词汇量提升到 2 万，甚至 3 万的？

*有哪些值得推荐的纪录片？ - 知乎

*在中国国内上学的学生如何申请到海外实习？--以德国为例 - 知乎

*英语相关专业毕业的你现在工作如何？对高考志愿填报语言类专业的同学有什么建议？ - 知乎

*如何提高聊天能力? - 知乎

*纯素食者怎样管理自己的饮食？ - 知乎

*怎样在一个暑假内变美？ - 知乎

不管是戒掉辛辣刺激，还是规律运动，还是雷打不动护肤，都需要意志力和执行力，想要皮肤变好却没有行动，结果只会打脸，想拥有美好的皮肤，嘴上说说不难，难的是持之以恒。


你的努力要配得上你想要的东西，


*金钱很重要，那些化妆或护肤仪器都是钱砸出来的，但也只是工具手段，执行者最重要。

我三年前买的日立也在积灰基本没用过，拿出来一样用。

之前脸上糊多了，长了脂肪粒，最后我买的18元一只的芦荟胶，立马消除，因为我的肤质主要是补水即可，超级好用，这是药店的阿姨给我私心推荐的（多次出现陌生的老中医/阿姨/柜姐/门卫对我特别好，总是给我秘诀/秘方）我当时感慨，放着la mer不用，18元芦荟胶各种嗨皮，所以真的不是钱的问题。

*买护肤品或护肤仪器一定要专柜买，不要为了节约钱在网上买，据说各大网站真假掺着卖（我这几个朋友很有信息渠道都这么说）比我在原产地免税店买都便宜，表示不相信网上买大牌护肤品了，一想到一两千的东西为了节约一两百不小心买到假的，我就不能忍。

其次专柜有很多设备，仪器，可以试用，可以赠送样品，新产品或新品牌是探索出来的。个人感觉每个大牌的拳头产品是不会差的，但是千人千面，肤质不一样，问题不一样，千万不要盲从，绝对不要盲目跟风，不要买三无产品，手工产品，廉价产品，不过有时候每个人的肤质和问题不一样，用一些10-20元的产品，效果一样牛，一定要小心，是否合适最重要。

我最喜欢卖萌和柜姐要很多小样，每次都会多要到好多，导致我小样一大堆，/(ㄒoㄒ)/我买东西太爽快，再加上我现在整个人说话很温柔，有时候他们会送我好多东东，感觉超级棒，就算比机场免税店贵一点，但为了体验，我也会在专柜买。刚发现很多大商场的大牌专柜有各种检测仪器，护肤沙龙，虽然距离有点远，但一次几百的服务平时可是舍不得钱花，导致我差点挨个在香港各大品牌办了N多会员。

*论护肤事业，有条件的妹子去日本走几遭，香港，韩国，泰国也可以，这几个国家对女人把护肤/化妆/身材/美丽当作终生事业，我只能表示膜拜。

-----------------------------

好皮肤好是公认的，我们家的人总体偏白，我是非常白的那种，以前皮肤是一直真的好，哪怕熬夜，无辣不欢，无所不吃，我皮肤依然很好，就是冒2-3颗痘痘，黑头很少，没有毛孔粗大，但因为之前太懒太自以为是，不护肤，不防晒，糟蹋了，虽然还是属于皮肤好的那一拨，但和我的川妹子朋友们相比（他们比我作息规律，饮食规律），我感觉自己不断在老去，真的感觉到年龄的迫近，身体各方面都发出信号，我已经不能再作了。

今年2-3月，垂死病中惊坐起，开始疯狂研究护肤，我从年轻3-5岁变成年轻了7-10岁，但是还是能看到年龄的痕迹吧，毕竟我现在毫无例外会被叫阿姨，之前都是小姑娘们自觉叫姐姐。

（因为矮小和婴儿肥，所以我不显老，在本命年的时候还被游轮工作人员以为未成年，当然也有土导致的）

今年开始全面蜕变，终于知道大限已到，赶紧捯饬自己啊

砸钱啊，砸时间啊(⊙﹏⊙)

这是在大阪用苹果照的完全没有p，带一点妆，真的是皮肤红润光泽啊，状态好挡都挡不住，状态不好还被人吐槽，你今天脸咋这么黄，好吧，我是黄脸婆，所以女人真是靠一张脸活啊（可能跟突然开始素食有关系，我现在还没有完全找到平衡）女人皮肤真的很看状态滴/(ㄒoㄒ)/~

最近皮肤太白发亮，上下一色，拍照都不能找太亮的背景，也有滤镜导致的，也有衣服配色导致的，所以皮肤看起来好坏是和衣服妆容有关系的，虽然不能让皮肤变好，但会让肤色看起来很好，这是很深的学问了，我最近正在慢慢地研究。


穿着运动服在本来想跑香港，大热天跑了一会太热到了商场，那些人都震惊了


-----------------------------------

1基因

基因决定基础。

（在今年3月开始系统护肤之前，我都是真的素面朝天，不护肤，不化妆，看起来差不多年轻3-5岁，但下面才是重点，基因决定25岁前的状态，但25岁后状态，就拼执行力，忍耐心和财力了，这是我今年才发现的，前几年都作死，深感后悔）

2护肤品

神仙水，兰蔻粉水，精华（la mer，兰蔻，ysl）面霜 

3面膜

自从今年开始买买买模式，开始囤货，skii面膜，雅诗兰黛面膜，清水面膜，








4身体乳，沐浴乳，颈部护理，护手霜，护脚

不只是脸部皮肤了，包括全身皮肤，还有最暴露年龄的是颈纹，也要注意，范冰冰也无法抵挡脖子出卖自己的年龄

目前试了三个牌子，在日本东京表参道买的一个以色列牌子，叫做laline，他家的身体油body oil不错，浴盐也很经验，好像去死海感受漂浮，这个牌子国内有没有我不知道，但在万能的淘宝上有。

欧舒丹的粉瓶子，擦完亮亮的。

在香港败了很多crabtree家，才导致行李超重，一句话，多试，找到自己喜欢的，所以专柜很重要了，我现在在摸索阶段，走到专柜挪不动腿，觉得什么都很好，什么都可以一试，买起来眼睛都不眨，好不好都要自己试一试才知道。



5唇部护理，防止干裂死皮，防止唇纹

之前好多年基本不擦润唇膏，在北京的风里来霾里去，但是从去年开始就发现裂唇了，干，而且以前红润的嘴唇好像变得像两片香肠，唇线也乱了，我都震惊了，加上唇毛，加上下巴嘴角上常年痘痘此起彼伏，我感觉我以前曾经光洁的唇部皮肤完全变成了我最不能容忍的灾难皮肤，所以我才火急火燎开始护肤，我打算啥时候去做一个润唇手术，说真的，我有一个女神朋友没事去打水光针，补玻尿酸，纹眉，假睫毛，这些都不是事，这些医美小手段在发达地区不知道有多么泛滥。

能够早晚润唇，擦唇膏前有专门的唇部打底，还有有专门的眼唇卸妆液，bodyshop的好用。

6眼膜+眼霜

在连续一周工作14/16小时后，狗眼已瞎，7月在香港买买买的时候，资生堂测出来眼部皮肤脆弱，但弹性满级，目前电脑手机用得太多，都是靠雅诗兰黛的眼霜+眼精华，果然是神器。

眼睛快要瞎了，用日本的蒸汽眼罩就会好很多，这是是神器，我经常可以戴着眼罩闭着眼睛讲课。


7光子嫩肤脱毛仪

我的毛发很淡很淡，其实不脱也可以，但后来被口水灌溉的唇毛/(ㄒoㄒ)/，还有腋毛，要去除，很多人毛发重，毛孔粗大， 皮肤粗糙，这个都可以治。




8 yaman全套，素水蒸脸仪，按摩器（还没用）去角质+按摩仪

素水蒸脸仪，当时试用的时候，感觉到水更细密，果断入手，但价格翻倍，要4000+



9运动

基本一周5-6次运动 每次90分钟-2小时甚至3小时，跑步+器械+跳舞，频率过高，强度过大，所以体测数据一朝大跃进。

目前体脂率15.4%，丧心病狂不过如此。

运动，出汗，排毒，我因此变黑了，毕竟跑得太多，但看起来还好，整体皮肤的紧绷感力量感爆发了，加上护肤品身体乳，所以感觉皮肤好到爆炸






能想象我穿着美美的裙子，满身肌肉，提着10kg的东西，穿着小高跟，毫无压力吗

（有时候为了运动没有打车，而且打车也蛮贵，只有东西多到不行的时候，我会打车，所以去香港我就会瘦2-3斤，运动多，还没啥可吃，(⊙﹏⊙)）

所以地铁里人看到一个满身肌肉的白嫩菇娘两手肌肉暴起提着自己买买买的战利品暴走

（因为给我自己/爸妈买了太多东西，导致我每三次回来都是30kg行李）



运动是最好的护肤品之一，当然也只能是锦上添花。

咕咚的运动记录是从计时开始就算，我买的nike防水运动apple watch，对应一个app，只算我移动范围的时间，如果我停下来拉伸是不算的，但我一般经常跑2-3公里就会jog，主要也看地形啊，所以我已经转战操场，动不动就10圈。最高记录是15km（跑+jog+走）7km不喘气，1km保持7分钟左右，快的话6分50秒，慢的话7分40秒。我买了各大品牌的专业跑鞋，（感觉半年内就会被我跑费）还有运动耳机，运动袜子，apple watch，压缩裤（压缩裤才是最贵的！！！）最新记录是小跑+快走+边走边跳17km，我也是服了自己。

跑步这事我真的觉得不可思议，我以前从来不跑，800米困难户，也就开始一个多月，但是我已经进入了丧心病狂模式，越跑越快越远越嗨，我也不知道为什么o(╯□╰)o











10喝水

平均每天喝3L水，800ml的杯子，装500ml，我基本可以喝4-5杯，加上2杯蜂蜜柠檬水

跑步10km以上衣服基本湿透，最近几次跑12-17km，可能是肌肉增加，一跑就全身出汗，可见范围内，至少50-100ml，汗水都挤了N把，甚至17km下来我全身都被汗水浸透。

而且我怕冷，大夏天不开空调，坐在热空气里，出汗，好像蒸桑拿，肌肉太多，稍微一动，大汗淋漓，每天洗澡2-3次都没得救，只能循环喝水，出汗，换衣服，洗澡的流程。

这是多年皮肤好的秘诀，我的喝水量在每次旅游的时候对比特别明显，喝水量是其他妹子的2-3倍，然鹅上厕所的频率是他们的一半，出水率是1/4o(╯□╰)o


12戒掉高GI，高热量，辛辣刺激食物

我是川妹子无辣不欢无所不吃都已经放弃了绝大部分，因为之前吃辣上厕所会不舒服，还有长痘，但目前也长痘，(⊙﹏⊙)，一定是缺X生活

（个人已经放弃主食，选择吃素+鸡蛋，不吃肉了，所以连放屁都不臭了，拉shi也不臭了）

偶尔吃点辣的，比如螺蛳粉微辣（以前我吃超辣，变态辣毫无压力）泡椒豆干，老干妈炒蔬菜，饭扫光菌菇类，这些竟然还是会带来痘痘，我也是醉了，我目前基本要放弃大部分了


13不外食，不点饮料咖啡奶茶，戒掉外卖，在家做饭（雇了阿姨），她每天按照我的要求做蜂蜜柠檬汁，自制果汁（百香果+加多宝，芒果，猕猴桃，大枣+牛奶）我负责买水果（火龙果，樱桃，桃子等）

阿姨都是下午菜市场顺便给我买菜，买好的，还讲价，对我真是太好了

每天为了带饭/带果汁（如果我上课工作8-10小时，她会给我送饭），左手一个包，右手一个包，有时候还有伞，穿着一个小高跟，如此女汉子，也是没得治了






以前一日三餐都点外卖，无辣不欢，麻辣诱惑老吃，吃得快，急，多，杂，现在基本朝着另一个极端发展。

重油重辣重口味对皮肤没有好处，其实我以前无所不吃的时候也没有这感觉，但深深感觉年龄大了，一切都不如当年了，很多原因凑在一起做出了如此决定。

外卖的油能有多好，尤其是那种廉价的火爆的，就不可能有好油，越便宜越糟糕，贵的也没有保障。目前开始用橄榄油，西班牙产的。我看的纪录片里说，罗马帝国就是用西班牙产的橄榄油，用双耳瓶装好运到罗马，扔了一山的瓶子。233

建议橄榄油，白醋，不要用老抽之类的。

其实我真的可以不用这么禁忌，但如果因为贪嘴，皮肤不好了，又要砸多少钱才能挽回呢？这么一想，什么好吃的，我都可以不吃，我连肉都不吃了，丧失了90%的食物快乐，所以少点油盐酱醋有什么可怕的呢？




----------


刚刚测出来的肌龄17

刚去完角质，皮肤细腻，黑头2个，但痘痘4个，被这个软件评委剥壳鸡蛋般的皮肤，我要是不用这般工作就好了






上个月测还是19/20/21岁呢














香港7月11日 资生堂皮肤测试

上个月在莎莎测出来，皮肤很好，就是干
编辑于 2017-07-21
早靈雪氏
早靈雪氏
坐下来慢慢聊，我的世界有点复杂。

这么实际的女性的问题还是很想答一发。

我是过敏体质，很难挑到合适的护肤品。喜欢追求自然无妆效果的干净细腻。

我的皮肤天生底子比较好，遗传我爸，比较细腻，但是偏黑，虽然后来长大了开始有点我妈基因的凸显了，但怎么着也还是小麦色╮(╯▽╰)╭……问题在于，用护肤品，用厚了会觉得油，起脂肪粒，用薄了又会觉得干，现在基本是挑选单品搭配来用。

保养皮肤的一大关键是：睡觉！睡觉！睡觉！

一定要保证充足的睡眠，能早睡早起就更好，如果不能早睡早起也至少要保证睡到自己不困了为止。

如果睡眠不足，或者睡眠质量差，气就不顺畅，容易胸闷气短心情烦躁，毛孔会变大。

睡眠充足，干痒和粉刺会少很多。

第二大关键：运动！出汗！排毒！

最开始选择的运动是健身，有专业教练带，效果是还不错，但教练流动性比较大，专业水平层次不齐，一直带我的教练不做了，我也就不想练了。

后来选择的是瑜伽，相对来说，瑜伽还是很稳定的，练习效果也不错。论排毒，我个人认为瑜伽排毒的效果比健身要好很多，我觉得更全面一些。

每次练完瑜伽，会觉得气色提亮了一个档。不是皮肤变白那种亮，就是整个人会觉得气场都提亮了不少，皮肤就更不用说了，粉刺、暗黄、细纹之类的，都改善了很多。

目前是每周练习三次左右。

第三大关键：吃！

在吃方面，可以说走过不少坑了。生酮饮食、素食、果食、荤素搭配等几种吃法都试过。

生酮饮食很难熬，最长坚持了两个月就跪了，但瘦的很快，皮肤的紧致马马虎虎吧，主要是身体的感觉，在度过第一个月之后，第二个月会感觉到身体很轻松，很好控制，练习瑜伽之类的改善特别明显。但是最后败给了大姨妈不来。

素食，坚持了五年。有效控制出油、痘痘，素食很好排便，身体也比较轻松，除了皮肤比较暗黄不知道怎么办以外，其他一切都还不错，后来因为尝试生酮饮食而断了素食，但继失败之后准备慢慢恢复素食。

果食，一星期不到就跪了，天生不爱吃甜的，果食简直就要命，吃不到盐我愿意去死，果食那几天，皮肤过敏加重了。可能体质不适合吧。

荤素搭配，暗黄的情况有改善，但是出油，容易起脂肪粒又开始了……而且便秘几率也开始增加。

目前的饮食状况：大部分时候吃素，家里偶尔做肉会吃一点，但肉食的量控制在整体饮食的15%以内，更多以五谷杂粮、蔬菜、水果为主，少吃油，少吃辣，少吃生冷的食物。

（最近工作忙也顾不上吃饭，每天吃了啥都不太清楚……但一定会有水果、蔬菜、杂粮）

其他的小贴士：

加湿器或者空气净化器是必须的！云南气候还算好，所以空气净化器用不到，基本就用加湿器，晚上睡觉的时候床头放一个加湿器，会发现睡觉呼吸很顺畅，早上醒来喉咙不容易有异物感，精神也会好很多。

蒸脸机！兑10%自己做的纯露，效果很惊喜，迅速消红肿，舒缓过敏现象。差不多一周用2-3次，能很好的稳定肌肤状态。（对于容易过敏的妹子来说真是福音）

香薰~！有香薰的日子皮肤都亮了不少，喜欢点自己做的精油蜡烛，味道更温和无刺激，香味都是自己调的，不管是办公室还是家里都会备着。毕竟练瑜伽，呼吸是很重要的，香味和呼吸直接挂钩，呼吸的顺，舒服，身体循环的许多东西自然也通畅，皮肤跟着就会好起来。（不要用劣质香，不但没有帮助，吸多了还会容易得病）

绿植！不知道为什么，家里绿植环绕的时候我的皮肤会跟着好起来……

尽量远离电脑！远离手机！工作原因长时间对着电脑之后脸上斑点变多了！变多了！变多了！这真是个噩耗！导致我不得不又开始研究淡斑！

目前搭配的护肤品（仅供参考）：

雅诗兰黛红石榴套（去黄！我用着还不错），城野医生毛孔收缩水+DMC冻膜（提亮肤色，美白），高丝美白淡斑洗面奶（淡斑），大创美白淡斑精华液（淡斑），维E霜+GNC芦荟胶（淡斑美白+修护），AHC眼霜（提拉紧致），小棕瓶眼霜（滋润减少细纹），玫瑰果油精华液（修护）。

红石榴和高丝的洗面奶基本是交替用，用一次红石榴下次就用高丝。

水的话，早上涂城野医生晚上涂红石榴，如果做了冻膜也会涂城野医生。

大创的精华液每天必擦，充当了霜，因为霜擦多了我会起脂肪粒。（雅诗兰黛的棕瓶精华液略有过敏，擦了会有点痒）

红石榴霜三天擦一次就足够。

维E霜和芦荟胶调和擦，一周一次，一般是配合面膜。

玫瑰果油精华液在蒸脸的时候涂，一般也会调和芦荟胶一起。

两种眼霜交替擦，小棕瓶更滋润，AHC紧致效果会更好一点。

洗脸有时候也会用手工皂，清洁力度强，但是我容易干痒，一般一周一次。


综合以上，我几乎不化妆，最多描个眉，擦个口红，但皮肤和别人擦了粉差不多，过敏也能很快调回来。


另一点，如果，我说如果，愿意相信中医，愿意内调的，内调才是关键。

发布于 2017-07-20
知乎用户
知乎用户
没有故事的女同学

对于20岁左右的女生，有哪些性价比较高的护肤品？ - 知乎用户的回答

回答之前，先附上条链接（本人在知乎的回答）

—————————————我是分割线——————————————

1.“题主18岁，外油内干”，这种肤质要注意清洁和补水。

清洁产品推荐氨基酸洗面奶，补水产品参考链接：你用过的最好用的补水产品是什么？ - 知乎用户的回答

护肤步骤 （仅供参考）： 洗脸（请自行搜索正确的洗脸方式）→敷面膜（15min-20min后撕掉，静待30min左右把脸上残余的精华液用清水洗净）→喷喷雾（题主年纪小，首推雅漾的大喷）→擦乳液 面霜 眼霜 等。

2.“题主脸颊额头有痘印”，建议使用科颜氏的金盏花水，坚持用对去痘印是有效果的。

3.“题主毛孔粗”，毛孔粗大是皮脂分泌过旺而引起的，原因有很多 包括清洁工作没做好或者压力过大 等等。

跟第一条相同要先做好清洁工作而且尽量不要化妆（避免卸妆时清洁不干净而使毛孔堵塞越演越盛），毛孔粗大的地方也要少擦点面霜。

ps.很抱歉 本人没有用过收缩毛孔的产品无法更好的推荐给你。

4.“题主额头脸颊太阳穴常年长痘”，脸颊 太阳穴 长痘多半与 皮脂分泌过旺，胆囊负荷重（食用过多油脂食物） 有关；额头长痘多半与心火旺或者压力大有关。
编辑于 2015-02-22
痘痘我来啦
痘痘我来啦

小编今年刚毕业，毕业了代表着我要工作了。（小编内心是在是不想去啊！以后我的寒暑假要没了。~~~~(>_<)~~~~）。

小编带着纠结的心情下，终于和小伙伴踏上了找工作和上班的旅程。我和小伙伴要去的地方呢？是亲爱的首都北京。北京。我来啦！（呜呜）

在我辛苦奋斗的时候，我的小脸蛋保护不当，长痘痘了。（我那个内心啊，不要不要的！）我呢？还是最不想要的油性肌肤，夏天一到，脸上突突的冒油。我都不知道怎么形容我的心情啦！

自从长了痘痘，祛痘产品用的也挺多，但都无功无过，今天要跟大家说的不是什么祛痘产品，而是一些基本祛痘护肤的方法。以下纯属个人亲测有效的方法，可能并不适合所有人，小仙女们自行筛选哈。



1.清洁。清洁，清洁，清洁！重要话说三遍，对于大油皮来说，油脂分泌旺盛，很容易阻塞毛孔，然后就冒痘，所以，清洁真的很重要。大家要选择好清洁产品，现在市面上有很多洗面奶可以选择。我个人对洗面奶的要求很简单，清洁，不刺激就好。哦，对，还有很重要的一点，洗面奶要在脸上停留一分钟左右才能达到清洁的作用。

2.补水保湿。脸部出油旺盛绝大多数是因为皮肤缺水，我完美的印证了这一观点。讲真，如果晚上敷了补水面膜，第二天起来皮肤会好很多，痘痘也会消一些，可能是因为皮肤喝足了水。关于补水，市面上有很多补水面膜，油皮易出痘小仙女们要选择清爽不油腻的面膜哦，不然，会闷痘的。我都是两天敷一次补水面膜，在不用面膜的时候，我都会敷一些清爽的爽肤水，一般五分钟就好。在敷完面膜之后用乳液保湿。我的皮肤真的很容易出油，所以，我一般不用面霜，不好吸收，只用爽肤水和乳液。

3.清洁面膜。油皮清洁真的很重要啊啊啊啊！我都是一周敷一次清洁面膜，一周去一次角质。在去角质之后敷清洁面膜，清洁作用会比较好。坚持下来真的会看到效果的。我都是用泥状清洁面膜，吸附能力比较好。

4.化妆。我基本不会化全妆出门，一是因为我脸特别爱出油，二是因为带妆时间久了会阻塞毛孔，然后冒痘。我一般都是只化眉毛，用口红。偶尔化一次全妆出门，第二天立马冒痘，亲测有效（微笑脸）。

5.饮食。其实，我一直觉得我脸上痘痘是因为我爱吃辣，我不怎么吃油炸，但真的是无辣不欢。吃辣容易上火啊，然后就冒痘。大一到大二，虽然一直在护肤，但从不忌口，痘痘也就一直没下去过。从大二上学期开始有意识的少吃辣，对祛痘真的有效果。所以，爱吃辣的小仙女如果要祛痘的话，一定要少吃辣，少吃辣，少吃辣！虽然很难做到，但真的有用啊！

6.作息。这是个老生常谈的话题，大家都知道早睡对皮肤好，就是做不到。我一般都是11点左右上床，玩会儿手机，11点半左右放下手机，开始睡觉，12点之前就能睡着。偶尔也会熬夜，每次一熬夜，脸上的痘痘会明显的多起来。我有个室友，不吃辣，但每天很晚睡，脸上的痘痘也是一直没消过。所以，小仙女们，饮食跟作息一样重要，没事就要睡觉，嗯，对，就是这样。

7.内分泌。这个就很有针对性了，因为每个人痘痘的成因都不一样。我一直冒痘，感觉是内分泌的问题，因为，我之前的祛痘护肤功课都有坚持做下来，脸上还是有痘痘，不过，跟之前比是比较少啦，我就在想可能是我内分泌问题，就去看了中医，喝了一个星期的中药。现在脸上的痘痘是很少了，但就是不知道是中药的功劳还是我一直来坚持护肤的功劳。

8.卫生。这个怎么说呢，说得好像小仙女们都不爱干净一样，不是啦。我说的是，枕巾，被单，被套的卫生。一般很少有人去注重这个。我都是一个星期换洗一次枕巾，被单，被套等床上用品。我睡觉的时候喜欢脸贴着枕头，如果枕头比较脏的话，上面的灰尘什么的都会弄到脸上，然后混着我脸上出的油，然后阻塞毛孔，然后，然后你们就知道了。还有一点也很重要，擦脸毛巾一定要经常洗！！！

9.坚持。有时候大家都知道该怎么祛痘，但就是做不到，或者坚持不下来，怎么说呢，如果你要是真的想祛痘，一定要坚持下来。做什么事都是要坚持才能看见效果，特别是祛痘这件事，小仙女们一定不能指望有立竿见影的效果，今天护肤了，明天就想没痘，这是不现实的。拿我来说，我从大一开始护肤，也没有特意祛痘，就用一下基础的护肤品，只是比较清爽。刚开始，也没什么效果，我一直坚信护肤的成果不是一两天就能看到的，特别是祛痘。坚持两年下来，室友都说，我脸上的痘痘基本没了，皮肤也比大一刚入学的时候好很多（虽然脸上还是会出油），室友都被我带的开始用面膜了呢。

10.最后。最重要的一点！！！不要老用手摸脸，起痘的时候不要直接用手去挤痘痘。我高中的时候真的好喜欢用手摸脸，挤痘，做题卡住思路的时候就用手摸脸，结果，结果就是高中三年脸上痘痘一天比一天多（手动捂脸）。到了大学，得到教训的我就强迫自己没事不要用手摸脸，挤痘。每次长痘，就让它自己在那儿长着，不碰。一般痘痘都是有生命周期的，我一般脸上长痘不碰它的话，基本一个星期它就会自己消的。如果要是自己动手挤的话，留下的痘印一个月都下不去，惨痛教训，真的不要用手挤痘啊！小仙女们。

以上纯干货，可能有些大家觉得没新意，但坚持下来真的有用哦。祛痘的方法大家都知道，贵在坚持，坚持，坚持！最后，希望小仙女们都能如愿祛痘，一起走进无痘的世界。么么哒～
发布于 2017-07-24
怪阿姨
怪阿姨
已经过了出油年龄天天愁脸干的阿姨来答一个，很多都是个人经验理论支持不足求不嫌弃。
首先说痘印，如果是痘坑那用护肤品基本上是没戏的，除非题主有勇气自己在家搞高浓度果酸焕肤，不过这个风险巨大非常不建议操作！强烈不建议！不建议！（重要的话要说三遍）。如果实在想去除可以以后走医美路线。
如果是表面光滑的痘印，那要看下是红色还是黑色（褐色），红色是还有炎症（比如痘印不平整感觉里面还有东西迟迟不好），需要消炎；黑色是痘痘已经愈合（好利索了）还有黑色素沉淀，需要美白。相关产品有很多，也有可以双管齐下的，我不是成分党就说些个人用过的——
消炎方面：健康水（敷脸），茶树精油（高品质单方纯精油点涂）
美白：各种（靠谱的）美白精华，以及做好防晒！！！
————————
关于毛孔大加出油（外油内干这种说法我个人不太赞同，当然也有皮肤一边脱皮一边狂出油的情况，这种一般是角质受损到一定程度了，建议弃用一切控油刺激性产品也不要刷酸，可以用雅漾一段时间养厚皮再研究其他），主要原因还是天生加年龄加饮食，前两个没办法了，饮食还是可以控制的，少油盐啥的都是老话了不多说。
可是平时还是狂出油怎么办呢？个人建议与其搜寻各种质量参差不齐多少刺激皮肤容易倒拔干的控油护肤品，不如找一个靠谱的散粉随身带着，需要了随时补涂，散粉妆感不重基本上直男看不出来(>﹏推荐：make up forever家的散粉，控油杠杠的还不倒拔干
毕竟，老了就造了，年轻时的油皮是多幸福的事情，不要摧残它让它自由地……出油吧＠_＠只有别傲娇发痘痘起闭口憋黑头就行！！！
————————
关于痘痘（非炎性）闭口黑头毛孔——
刷酸
刷酸有风险！有风险！有风险！
不过弱弱说百分之二的水杨酸楼主感觉没啥大事，最多爆皮几天停用就好了（胡说！）高于这个浓度就需要谨慎了。
具体操作方法及产品：略
实在受机无力啊T^T
简单说就是：简搭配（配合成分简单水乳），晚上用，记防晒，以及——见好就收，周期用就好
产品：最好买到且比较靠谱的，宝拉珍选水杨酸精华液
相关搭配推荐：无印良品敏感肌化妆水清爽型，（中间放酸），科颜氏高保湿霜（其实有个pm乳据说是绝配，但是淘宝水深我没试过……）
效果：因人而异（捂脸逃走）
我刚用时惊为天人，鼻子从来没这么干净过有没有！下巴上的小凸起都没了有木有！我擦竟然连背上吃麻辣烫起的包包都治好了！！
用了一瓶后，现在就无感了，泪奔T^T
我朋友大油田用了跟我说啥感觉没有，也没掉层皮（我刚用还是掉了两层皮的）也没去黑头也没收毛孔。
最后再强调一遍：刷酸需谨慎！请多多做功课再下手！
另，酸种类繁多，这里只提到水杨酸，还有果酸啥啥的，题主有兴趣可以自行百度（百度男士护肤吧里有各种干货）
——————
关于清洁
三个字——
氨基酸
然后是旁氏（米粹）还是sk2还是黛珂就看银子了。
至于皂基，我的个人感觉（强调个人感觉）是年轻时用用洗的干净也没啥，毕竟氨基酸系清洁力真的也就那样。产品的话雅诗兰黛红石榴和纯肌萃洁面膏都挺好，很有钱就cpb那个富裕层皂（绝对是洁面里的挂逼，想起它就不敢说洁面洗不了黑头收不了毛孔了）
注意：一，刷酸的时候用氨基酸系洁面。二，涂了防晒散粉啥的注意卸妆（清洁到位就好，也不要过度清洁）
——————
关于补水保湿。
这个不同地域区别太大，题主没说坐标我就不推荐产品了。
最后祝题主健康美丽么么哒，暗搓搓嚎一句年轻真好真羡慕十八岁的年纪啊嗷呜(>﹏
编辑于 2015-02-24
prince惜繁年
prince惜繁年
学生党
这个是中山大学叶老师的美容课讲座 用药理来解决和缓解我们的肌肤问题！这是对大多数皮肤不好的妹子们有用的噢！！全是干货(￣▽￣)！

http://weidian.com/item.html?itemID=1080181447 (二维码自动识别)

http://weidian.com/item.html?itemID=1079159618 (二维码自动识别)

http://weidian.com/item.html?itemID=1579011049 (二维码自动识别)
好啦！亲测有效！要是觉得好的话 就给俺点个赞吧☆*:.｡. o(≧▽≦)o .｡.:*☆
发布于 2016-08-04
匿名用户
匿名用户
去医院！
去医院！
去医院！
长痘痘是病，皮肤病也是病！护肤品什么的就和保健品一样虽能有效果，但是治病还得吃药。痘治好了，皮肤才可能好！
妹妹你都觉得花600的产品不是啥问题，去医院要不了多少钱的，一定要看完我答案，知乎第一答！！！
看到下面一群皮肤好的人，推荐自己的方法，大约是平时不怎么长痘痘的人，自以为这些方法(如保湿啊，不熬夜啊，吃水果啊，运动啊)是让自己不长痘的原因。其实不是，油性皮肤本来就是容易出现皮肤问题的人，你们这些方法对于痘肌来说，只是隔靴搔痒。
怎么形容呢，就以当前得了诺奖的青蒿素来说，得了疟疾的原因，是因为疟原虫侵蚀人体，这是根本原因，青蒿素能够有效杀灭疟原虫，所以能够得大奖。题主你的状态大约如此，你问那些身体正常的人怎样才能身体变好啊，大多数人都是外行。他们说:运动啊，这样增强免疫力，我就是这么做的。还有人说:吃好的，营养好了也就好了。好你妹啊，这些答主的答案看似很有道理，是啊，身体素质好，免疫力增强当然有助于疟疾的治疗，但根本方法是杀死疟原虫，这样才能让你身体变好，而不是隔靴搔痒的什么调理身体。
回到题主身上来:偶尔长一两颗痘痘，大约和身体小不适一样，大多数人不注意，当然也确实不太需要关注。而经常性出现痘痘，这就确实是问题了，是病！去医院吧。长痘的原因大约归为这三个:1皮肤出油较多,主要原因是皮脂腺功能太强。2皮肤毛孔堵塞，有些人出油但不会堵塞毛孔，所以也不长痘。3面部菌群失调，大量的病菌，导致痘痘的恶化与化脓。
这三个主要的原因，尤其是1和3.需要医生或者药物来帮你解决。而不是简单的吃吃喝喝，运动运动就能达到的效果。目前的解决方法:原因1，主要通过药物抑制皮脂腺的分泌，减少出油，是祛痘的根本；原因2主要是通过皮肤清洁；原因3通过外用药物来杀灭面部病菌。
所以题主，一定要去医院，有病就得去医院。长痘就是身体状况出现了原因，在我国大多数情况下不认为是病。保养可以自己瞎做做，治病就得去医院。
编辑于 2018-01-18
漾儿nino
漾儿nino
你可知道茴香豆的“茴”字有几种写法？

纯分享 希望更多妹子找到适合自己的产品变美upup


首先美白去黑痘印推推推≥﹏≤言语无法表达我对它的爱～  ！！！敏感皮慎用！！！！
Nufountain C20+亮白精华露VC+烟酰胺+熊果苷 华丽丽的成分 一百多的价格 ⊙﹏⊙而且淘宝上卖得不多 不用担心假货 
除了味道，使用感会有点恶心，但价位摆在那里嘛～
关键是效果好到哭(ﾟДﾟ)ﾉ 痘印淡了很多，整体光滑了棒棒哒 谁用谁知道←_←
ps：但是睡前使用时，要垫好枕巾，不然会沾到枕头


痘痘肌清洁灰常重要，选择泡沫细腻温和的洁面，旁氏啊，free plus啊都行
一天早晚洁面，晚间可选择清洁力较强的洁面产品。推荐dhc蜂蜜滋养皂

洗澡干净不紧绷，泡沫丰富，手残党可以选用打泡网。。哦对它还耐用。。
DHC的产品用过蛮多的，橄榄唇膏
使用感比其他的唇膏好蛮多的，很滋润但是抹上不会像偷吃了猪油一样。
相对好用一些的还有磨砂膏，大S有推荐。但不可过度，从厚皮变成现在的敏感皮就是磨砂加乱抹药膏加乱抓。。。
其他挺多产品属于无功无过，用了感觉不太出效果，但是肌肤状态蛮稳定的。

澳尔滨健康水 大名鼎鼎 
用来做水膜，可以把肌肤维持在稳定的状态。

清洁面膜推荐
 DMC冻膜 曾经敷着它吓到了生管老师 用完之后白头会浮出来，得自己用暗疮针刮掉
 朋友用过科颜氏白泥反馈也不错。
一周一次或者两周一次吧。。

如果毛孔堵塞严重，可在洗澡后毛孔较大状态用暗疮针挑就来，或者去美容店里弄一两次，把不平的小疙瘩除去摸着心情也好好～

美国Freeman黄瓜洋甘菊深层清洁撕拉式面膜150ml 
喜欢她是因为。。很好玩。。享受。。一层。。薄膜。。慢慢。。慢慢。。剥落。。。的感觉。。。虽说是清理面膜，补水镇定效果还是可以的

关于蜗牛霜，达不到祛痘印的效果，当做普通的霜来使用吧

一直是一只小白鼠，爆发过好几次大面积的痘痘，也好一阵子脸上特别特别嫩。
心得呢 
1别熬夜老对着手机
2 多吃水果，当时每天喝各种果汁绿豆汤，食疗调养啊什么的，一整年皮肤都没有长痘特别白嫩。
3 别偷懒，每天晚上必须要搓干净
4 忌口 少吃油腻 辛辣食品 有一次大爆发持续了一年，当时每天吃鸭脖凤爪，摁手机到很晚，于是就，悲剧了。

关于雪肌精→_→用了一阵子感觉有变白但是不会很明显，刺激还是有的，不推荐敏感皮使用。有的人用了变白挺多的，有的人就没什么感觉，因人而异咯。

知乎首答。。没有逻辑。。。嗯。。。。
编辑了图片传不上去 心塞
编辑于 2015-03-03
小灵
小灵
化学硕士/Skincare研发

大学的时候也长了一额头的痘子，后来就不长了，皮肤变得白嫩无比。方法其实也很简单，天底下能拿来美肤的方法，无外乎两种，一是内服，二是外敷。

排干净肠子无比重要

宋美龄年轻时曾得过乳腺癌，接受了美国医生的手术之后，一直坚持用灌肠来清肠，我读过的书上说她每天晚上灌肠一次，到老没有复发癌症，并且皮肤白净，完全木有老年斑。

我常年都是便秘的，后来为了减肥喝了一段时间减肥茶，每天排泄的无比透彻，然后额头上痘痘全部好了，皮肤无比细腻干净，看起来比学妹还要小几岁。

想要皮肤好，先排毒吧。益生菌、膳食纤维吃起来，一天排两次的人不长痘痘不长斑。

心情愉悦无比重要

有男朋友的好好享受男朋友带来的快乐，没有男朋友的好好享受女朋友带来的快乐，没有朋友的就买买买，钱也没有就读读书、健健身。总归大脑要释放多巴胺，皮肤才会好起来。

有了以上两点，涂涂抹抹的可以随性来。
编辑于 2017-05-16
璐璐粥
璐璐粥
玻璃心晚期，你批评我我就骂你
楼主情况和我差不多～我是一年内逆袭嗒～
【减肥】跑步是可以嗒，但是要慢跑，跑完最好再走一圈，然后用手按摩小腿～否则全身都瘦了，你会发现你有一个无比粗壮的小腿！
【吃辣问题】我也是无辣不欢的那种妹纸，每顿饭不吃辣就啥都吃不进去！你可以吃完辣的时候吃一些清凉的药，成份越简单越好～比如什么金银花颗粒一类中成药～然后每天喝叶绿素或者日本清汁类植物提取的东西，答主长期喝体质以有所改变～多喝纯净水白开水～
【防晒】其实对皮肤伤害最大的就是光！每天出门要涂防晒涂防晒涂防晒！重要的事情说三遍！长时间在户外还要补防晒补防晒补防晒！最好养成打伞的习惯！
【洁面】请用弱碱性洗面奶，氨基酸类型的洗面奶很好！然后温水洗脸～
【祛痘】含蜗牛原液成分（推荐：泰国snail white 蜗牛霜～在知乎推荐过，妹子用完都说好～美丽加芬蜗牛原液，国内屈臣氏为数不多的好产品！不推荐韩国的蜗牛霜，原液成分少，难吸收！）含金盏花成分的（科颜氏金盏花水不用说了）～澳尔滨健康水～等等，更多可以看我之前的帖子！
【祛痘印】内服vc、胶原蛋白～外涂美白类的精华～比如科颜氏、资生堂、欧缇丽的美白精华～口碑都很好～
【补水】皮肤糙、又油又干的根本原因都是水油不平衡！现在已经进入秋冬！更需要补水～补水喷雾随便带！可以根据自身的具体情况来选择保湿型好一点的乳液和霜！
发布于 2015-10-15
剁手盟萌主
剁手盟萌主
专注剁手二十年(๑•̀ㅂ•́) ✧

说到护肤，最迫切的想让皮肤变好的不应该是肌肤敏感的妹纸们吗？？？一晒太阳就变红、闻到花香就发痒、遇到雾霾就长痘，化不了妆、种的草想拔也拔不了，简直想摔掉家里那些所以没用的瓶瓶罐罐啊！(ノ｀⊿´)ノ 

于是萌主看不下去了，必须要给大家分享一波如何让过敏性肌肤护肤变好的技巧！

对于敏感肌，首先是护肤老三样：洁面、保湿、防晒。

1、  洁面：

洁面是很重要的步骤，相信对在意护肤的妹纸们已经是老生常谈了。不过萌主还是要强调一下，洁面在于清洁毛孔，所以使用一般洗面奶的时候一定要在脸上搓啊搓啊搓泡泡搓足一分钟~  然后最后用温水最好是流动的水清洗干净，不然你为了洗干净却又把洗面奶的成分残留在脸上就得不偿失了。╮(￣⊿￣)╭ 

针对过敏肌，萌主推荐两个牌子的洗面产品：丝塔芙
和 雅漾

Cetaphil/丝塔芙洁面乳473ml 温和保湿 近零刺激 男女洗面奶

这款洗面奶旗舰店售价89RMB，大约可以用12周。

它的配方特别温和，不含香精，全面洁肤近零刺激，不会产生泡沫，不会堵塞毛孔产生粉刺。

用完之后，脸上好像形成了一层薄薄的润肤保护膜，感觉不紧绷不干燥，特别舒服~

相对于丝塔芙，雅漾的洁面产品的可选性就要多一些了。可以根据过敏肌的细微差别来选择，比如干燥、易发痒、毛细血管明显吧啦吧啦……对症下药~



（舒缓特护洁面乳 295RMB 200ml 清爽免洗，清洁舒缓型）

这一款适用于耐受性差及高度敏感肌肤的日常清洁，可以早晚都使用，用指尖涂抹，然后轻柔地在脸上打圈按摩，最后用化妆棉轻轻拭去就好啦。高度敏感的眼周肌肤都可以接触，而且是用化妆棉轻轻擦，不需要反复摩擦，不会像平时清洁完面部感觉脸上又少了一层皮~




（净柔洁面摩丝 218RMB 150ml）

适用于所有敏感及健康状态肌肤

而且成分相当精简：皂基、色素、酒精、对羟基苯甲酸脂——都没有~当然，几乎每款雅漾都不含这些成分，所以懒癌，以及完全不想细究自己是那种肌肤的妹纸，就放心大胆地选这款就好啦。




（活泉修护洁面乳 220RMB 200ml）

这款是皮肤薄、易受刺激、发红的妹纸们发福音~

对于天生敏感肌肤或者皮肤受到外界刺激（污染、天气、压力、刺激物质）时，会出现紧绷、刺痛、灼热问题，且皮肤有干燥蜕皮现象时，这款洁面乳中的丝氨酸配方能够有效修护。

而且这款仍然是免清洗的，减少了生活用水对皮肤的刺激。




（清爽无皂基洁肤凝胶 192RMB 200ml）

这是祛脂系列的洁肤凝胶，适用于青春期、油性及易生痘敏感肌肤。

萌主每次用它洗完之后，都感觉脸上有一毫米的水膜，并不是那种滑滑的化学添加剂造成的感觉。

除了雅漾产品的基本功效外，这一款还可以调节油脂分泌、收敛毛孔、减少黑头哦~




（修红洁面乳 248RMB 300ml）

适用于皮肤泛红，面部毛细血管明显的皮肤。

这款着力于缓解皮肤灼热、泛红，修护敏感。也是一款免洗洁面乳。




（滋润洁肤皂 98RMB 100g）

针对干性及特干性敏感肌肤，面部及身体皮肤的日常清洁。

搭配同系列产品可帮助肌肤有效防止瘙痒，增强皮肤屏障；改善肌肤干燥、脱屑现象。

雅漾以上六款洁面产品都有其他乳液呀、面霜呀搭配成系列，功能和适用皮肤和上面介绍的基本相同。强迫症或者懒癌可以直接在雅漾的旗舰店找到一套产品下单，而且在某宝上买护肤品，一定要抓住旗舰店做活动的时机，送起赠品来简直像不要钱一样。

2、  补水、保湿：

说到补水，不得不提过敏界的两款大喷：依云
和 雅漾


Evian依云天然矿泉水喷雾大喷300ml*2支装
补水保湿定妆 129RMB

对，就是你所知道的那个膜法师的矿泉水品牌，它家出的保湿喷雾。与普通矿泉水的区别如下图。




雅漾 舒护活泉喷雾喷雾300ml
大喷补水保湿定妆
舒缓敏感肌肤 爽肤水 186RMB

法国塞文山脉的地下1500米深处的雅漾活泉水，无菌灌装。

依云的商品详情里有一张图详细说明了大喷的用法：



第三点高亮！

给过敏肌做面膜一个超级省钱的方法，有没有！

这个时候你只需要有
化妆棉 或者 压缩面膜纸 就好了~



看，一袋MUJI的压缩面膜纸35RMB，共有20枚，就算做20次面膜要用完一整瓶雅漾大喷也是186+35=221RMB。

而五片雅漾修护舒缓面膜就是228RMB。

看起来是不是超级划得来！

当然啦，用大喷做水面膜只能起到日常补水的作用，为了修护肌肤一个月还是得用几次真·面膜的~

然后呢，萌主咨询了个朋友六角水和活泉水都是什么东西？和一般矿泉水有什么差别？

但是嘞~萌主并没有得到靠谱答案；所以，萌主又上了知网，以“活泉水”为关键词搜索到了N篇论文，证明这些喷雾和矿泉水还是有很大的区别的~

不过你要是想用矿泉水代替喷雾的话，只用作补水功能面膜那也是真真便宜的。

3、  防晒：

真·敏感肌就不要乱用防晒霜了，多宅在家里，出门就打伞啊，乖~

全世界的护肤专家都会告诉你，物理防晒比化学防晒有效100倍【真诚脸】

萌主给大家推荐几个比较喜欢的遮阳伞的品牌：

天堂伞：老牌子嘛，就不多说啦~



蓝雨伞：他家价格合适又好看，特别是男士伞的风格，甚和萌主心意。

Adima：传说adima的遮阳伞能够为身体带来12摄氏度的降温效果。有极厚的四层抗晒色胶涂层和无毒印染，可选色很多。

日本的遮阳伞品牌还有：TO-PLAN、FaSola、w.p.c等。

Coolibar：它家的银胶伞特别有名，前面有一个回答提到银胶是最好的防晒面料，虽然它家的伞折合人民币300左右，但是也就一两瓶防晒霜的价格对吧~




最后萌主还是要强调一下饮食：

一定多喝水，饮料最多选择酸奶和鲜榨果汁

然后，你看下图好吃吗？

请戒掉它~
编辑于 2016-12-24
小小
小小
日本化妆品检定协会认证资深美容管家 Cosme Concierge
谢邀。别人用的好的产品，用在自己脸上没效果也就算了，搞不好还毁容，这样的事难道我们遇见的还不够多吗！！
护肤最重要的不是别人用过的好产品，而是了解自己的皮肤、科学的护肤方法、和一定的护肤品知识。
敏感分先天敏感和后天敏感。先天敏感，是指遗传的皮肤较薄较脆弱、或敏感体质。这样的人稍不注意就会敏感。后天敏感，是因为恶劣的气候、加上错误的护肤方法，自己做出来的。
现在很多人都有敏感。实际上先天敏感的人很少，大部分人，都是自己zuo出来的。
科学的护肤方法我讲过很多次了。这里想说的是，与其刷微博刷微信刷知乎看别人的护肤经验，不如自己多读几本皮肤科医生写的书！
顺便建议下题主对洁面加大投资。事实上，护肤品中，卸妆和洁面应该是最好的，水乳霜却是其次的。
编辑于 2017-09-13
张妍儿
张妍儿
一点就着 一哄就好


上图 我照片真的一点没p过
用我的人格保证

首先是吃的健康
我用的护肤品都很简单（嗯是因为穷
其实也真的没必要 我觉得你吃的东西会直接体现在你的身体上
身体干净没什么毒素
皮肤不会差

我日常的饮食是这样的
饿了会吃水果酸奶
有时候（甚至经常
会控制不住 出去聚餐之类
但还是健康饮食的日子多 
出去吃高热量高糖高油一周顶多三次
几乎不怎么长痘

然后就是运动

发发汗整个人都很清爽

偶尔敷面膜
别的真的没什么了
你要相信自然的力量
编辑于 2016-05-14
自然卷的丽日酱
自然卷的丽日酱
150的小巨人！抑郁症好起来的丽日～ 热爱梵高，热爱星空

来来来，来说一点儿不太一样哒～ (⌒▽⌒)

1. 关于水土。
“大学去了广州以后，脸上就开始冒痘痘。放假回家养好了一点，回学校又冒～ ”
“到北京工作了以后，皮肤变得粗糙干燥，很痒，脱屑，又干又油还长痘痘。 ”
我遇到的很多人，皮肤变差就是从他们换了一个新的地方生活开始。这就和每个地方不同的气候，以及不同的气候形成的水质等等有关了。广州就是湿热的，相对来说北京就是干燥的。有的人适合干燥，四季分明的气候以及水质，那就适合呆在北方。反之，就适合呆在南方。一般来说油性，痘痘肌肤更适合呆在水土不太湿热的地方。而特别干燥的肌肤适合呆在湿润的地方。
可是万一必须呆在一个不适合自己的地方怎么办呐？最好的方法就是入乡随俗。当地人吃什么就吃些什么。比如广东有凉茶，糖水。在北方寒冷干燥的时候大家喜欢吃牛肉羊肉，各种肉类。这些在当地世世代代形成的饮食习惯和习俗都会帮助人平衡气候，水土，对人造成的影响。

像我自己，每一次毁脸都是和水土有关。一回南方就开始过敏，一直过敏… 一回北方，皮肤就开始渐渐地转好。粗了一趟国，带了大概半年，好好的皮肤被损伤得不像样子… 去了趟云南旅游，一个星期的时间，全身就开始长湿疹… 回北方几天就好了… 
也不是说每个人都和我一样，对气候，水土特别敏感，并且也是爱过敏的体质… 但是对于和我一样的小伙伴们，呆在适合自己的地方，真的对皮肤，身体都会有帮助的呐～ (＾ｰ^)ノ

2.关于饮食。
最常听到的有利于皮肤的食物就是水果蔬菜。其实这并不适用于每个人，每一种体质。
一般来说，果蔬含有丰富的膳食纤维，维生素，和水分确实对皮肤有很多好处。
可是果蔬多寒凉。
不知道有没有一些妹纸们发现，自己已经喝了很多很多的凉茶，吃了很多蔬菜水果，皮肤仍然没有改善，甚至痘痘长得更凶了… 
这时候，可以试试看，减少水果的摄入。我自己的话，就是这种情况。肠胃也不好，遇寒很容易胃痛，吃冰的，吃水果很容易胃痛… 也就是所谓的脾胃虚寒。这样的体质，又吃大量寒凉的水果，就会加剧脾胃虚寒，反而恶化了身体的平衡，导致虚火更加旺盛，从而引起过敏和痘痘。（我不是中医哈… 大家也不要喷我…(╥﹏╥) 求求你们啦～ ）喝水，运动其实是很好的方法。
皮肤干燥的妹纸，可以尝试多吃一点肉类，增加脂肪的摄入量，特别是在寒冷的天气。那样会帮助皮肤分泌油脂，增加胶原蛋白，从而由内而外的改善皮肤。

3. 油性？干性？ 
很多人以为长痘痘就是油性皮肤，过敏就是干性皮肤。（那就不会有油性脂溢性皮炎和干性脂溢性皮炎之分啦～ ） 很多时候，皮肤过于干燥，脱屑，引起皮肤屏障受损，同样会长痘痘… 同样油性皮肤也同样可能会因为天生皮肤薄，或者后天的损伤变成敏感性皮肤。这个时候千万不要道听途说的疯狂去角质，清洁，敷清洁面膜。皮肤是有自身平衡的，水油的平衡，菌群的平衡… 当皮肤出现问题其实是我们自身保护，免疫机制引起的… 这个时候一味的去磨损皮肤，很可能会加剧痘痘和过敏。
皮肤问题变得严重的时期，不要心急。尽量精简护肤程序。如果哪个产品，包括洁面，清洁面膜让你感到刺痛，请立即把它们收起来，暂时不要用了，等以后好了再用。避免暴晒，多喝水，保证睡眠，尽量要保持心情舒畅。
皮肤是会长，会自愈的。给它时间让它自己长回去，会比我们自己干扰它愈合要来的好。
同样的，在这里要强调：不要挤痘痘，不要挤痘痘！！痘痘自己生长，大概1个星期就结束了，然后它会自行愈合。痘印大概一两个月就可以自行消失了。很多人的痘印，都是因为挤痘痘的时候伤到了皮肤深层，形成的。因此，明明一两个月就可以消失的因子，硬是一两年也消失不了。no zuo no die～ 
ヾ(＠⌒ー⌒＠)ノ
不论是长痘痘，还是过敏，我都不会挤，抠皮肤，所以一直都没有留下什么印子。
我记得有一次，被晒伤得厉害。大面积的日光性皮炎，起疹子。我明智的去了医院，医生给我开了一针激素，说是怕我会留印子影响美观。
那也是我唯一一次打激素。那一次非常非常严重，印子花了很久才消下去，但是都消了嘛！
感谢这位医生！！！！(o^^o)

4. 心情舒畅很重要。 
当我们精神紧张，比如工作特别繁忙，考前压力特别大的时候，皮肤就会变差。情绪会影响到内分泌。所以要尽量保持心情的舒畅。 
所以脸烂的时候，表老照镜子… 照镜子除了会让人心情更差，恨不得砸了它以外，对皮肤没有帮助。心情越差，皮肤就越不好，就更是要照镜子时刻关注，然后心情就更差… 啊啊啊啊啊… 这是一个可怕的循环。
有一阵子，皮肤过敏虚弱到极点… 我心一狠，把镜子都蒙了起来…除了洗脸完毕，保养的的时候看一眼，其他的时候，就当作自己的脸美若天仙… （我不要看，不要看… ！！！！）\(//∇//)\
总之，皮肤不美了，心情还是要美美的嘛～ 

5. 成分，成份很重要！ 
千万不要去跟风买一堆不适合自己的护肤品。平常护肤的时候一定要多留心，要了解自己的皮肤不喜欢哪些成分，尽量避开。护肤品并不是越贵就越适合自己… 真的不是这样。 敏感皮常常要避开酒精，酵素，水杨酸（几乎一切剥落角质的成分，虽然油厚皮最爱… ），一些刺激性强的防腐剂，香精，甚至矿物油（当然很多干敏皮很喜欢矿物油！！效果非常好！）。毕竟掏的是自己的钱，涂的是自己的脸，所以在买买买之前做好功课是很重要的。不要被BA给骗了啦～ 
对，我就是从前被BA忽悠，花了很多冤枉钱来交学费的白痴少女… （其实是阿姨… \(//∇//)\）现在都是我去忽悠BA… 哼～ 

最后要给大家说，皮肤好不好主要还是看基因的呢～ 所以不要强求，奢求自己的皮肤都是零毛孔，又白又嫩，健康不过敏的呐！
每一种皮肤都有它的利弊… 比如敏感性皮肤很多都白白嫩嫩，白里透红的，可事实上很脆弱。比如油性皮肤，容易暗沉，容易长痘痘，可是经得起时间的考验，不容易老。比如干性皮肤，零毛孔，不长痘痘，可是要一大坨一大坨的往脸上糊，不然会很容易干燥，长皱纹… 
再比如中性皮肤… 中性皮肤还有什么好说哒，没毛病，没毛病～ 
皮肤能稳定，健康就是最好的啦！ ！（≧∇≦）
要学会倾听，倾听皮肤的诉求，不要乱来哈～ 乖～ 
希望各位少年，少女们都有健康的皮肤，心情都棒棒哒～ 嗷嗷嗷嗷～ (=^x^=)
编辑于 2017-05-22
王雕楽
王雕楽
忘掉了。

如何让皮肤变好？这应该是所有女生日思夜想的问题，也是所有爱美的女生都愿意为之努力的一件事情。

关于这个问题，最重要的是你要了解你自己的肌肤。

简单来说，就是要找到自己皮肤的主要特征、主要问题（一般来说皮肤不好意味着脸上有很多问题，主要问题就是你迫切需要解决的）。

那么你是属于痘痘肌？偏油的肌肤？干燥的肌肤？混合性肌肤？抑或你面部有些发红（红血色过剩）或是色斑晒斑太多.......等等。

总之，请一定要在记住：
了解自己的肌肤，才能更好地去改善、护理自己的肌肤。

那么接下来讲方法论。这个时候，请你做好心理准备，要让皮肤变“好”....这是一个长期坚持的过程。

如果你连最基础的、早晚坚持擦水乳都做不到，那么也就根本不用去想着改善了，更谈不上变、好。真的是这样。请跟我一起大声说：

只有懒女人没有丑女人。~~~~(>_<)~~~~ 

一个人妆容的好坏，化妆技术固然重要，但更重要的是皮肤的本身，也就是化妆时我们常说的“皮肤底子”。因此，皮肤一定要护理。更重要的是，从年轻时就开始护理的肌肤，会让脸上的细纹、皱纹的生长速度都有一定程度的减缓。（消灭细纹不长皱纹之类的事情就不要想了，不，可，能。）

一般来说，护肤的方向基本上可以分为清洁和保养两大块。

清洁：

这个部分我具体分三个小方面来说好啦。

第一、洁面！

请注意，这是首当其冲、不容忽视、重点加粗、并且打了感叹号的两个字。洁！面！ 

对此，你需要选择一款适合自己的洗面奶。

痘痘肌、偏油的肌肤，这一类的男生女生，在洗面奶的选择上，可以去选择一些控油的、或是清洁力度相对强一些的产品。

平价的有资生堂的洗颜专科洗面奶。这个洗面奶我猜好多人都用过，性价比真的很高。四五十的样子。

再就是露得清的洗面奶，清洁力度也超强，价格也很亲民。50左右。

价格中高的，我觉得碧欧泉的洗面奶（绿色那只）清洁力度也还算OK，不过它有颗粒质感，所以不喜欢颗粒的MM就不要选啦~专柜应该是二百多。

这里特别也提一下男生护肤品的问题。因为男生的护肤一般比较基础，所以我通常都是推荐碧欧泉和科颜氏的洗面奶给他们。

科颜氏算是一个比较中性的品牌，很多单品都是男女通用的。他们家深蓝色的清洁洗面奶，力度真的很棒。洗完之后，脸上真的一点油也不剩了呢。

也有人说，我的脸虽然很油，但是只是局部油呀，脸颊其实很干。这些问题其实就已经细化了，单靠一个洗面奶来改善我觉得是不靠谱的。但是针对这种情况，如果有推荐洗面奶的需求，我会建议买一些含有芦荟成分的单品。它既能保湿补水，同时也有镇定的作用，洗完之后不会很干，也不易滋生痘痘。

如果没有特殊的需求，只是简单的日常清洁，选保湿的就ok。日韩的洗面奶性价比都很高，KOSE啦，婵真啊都可以。我个人也很喜欢skin food的蜂蜜泡沫洗面奶，很便宜但很补水哦，味道也不错~

当然泡沫洗面奶，欧舒丹的洋甘菊系列吧，泡沫真的很细，我高中脸部有些过敏的时候，就是用的这整个一系列产品，把脸给养回来的~

关于洗面奶你的选择有很多，并不见得贵就是好，不过有些产品贵，也是有它的道理的。

第二、卸妆！

请注意，这也是不容忽视、重点加粗、并且打了感叹号的两个字。卸！妆！ 


很多女生平日里出门都浓妆艳抹，但是却不重视卸妆。那么我告诉你，你皮肤变差，和这有着密不可分的关系。

现在市面上卸妆的产品现在越来越多，卸妆油、卸妆水、卸妆膏、卸妆蜜、卸妆洗面奶也都有MM在用。

我是不推荐使用卸妆洗面奶的。因为我觉得卸妆洗面奶就是给懒人设计的，出行偶尔使用还好，但对于平常底妆较厚，以及会化眼妆的MM来说，它是坚决不能选的哦。对于眼妆较为浓的MM来说，还是选择卸妆油做清洁会比较恰当。

我下面枚举的这几款卸妆油价位由高到低，大家可以自行选择。

一是shu uemura的卸妆油。这一款我我自己也在用，因为它很柔和。

不过很多人都推荐的是DHC的卸妆油。我个人真的没那么喜欢，一是它太油，二是它的味道也不太中我的意。

性价比很高的卸妆油我觉得kose的不错，很便宜，很耐用，也没什么奇怪的味道。在我看来，卸妆油之间的差异并不会太大。

需要注意的是：痘痘肌的女生，或是皮肤本身爱出油的MM在卸妆上最好就不要选择卸妆油啦，听话，油的东西，咱都不碰。在卸妆膏、卸妆蜜里做选择吧。

卸妆水的话，我主要接触的是Bioderma。我个人不是很喜欢用化妆棉，所以用卸妆水来卸，总觉得没那么方便。不过它的清洁力度还算ok~痘痘肌应该选择绿色的，我没有痘痘当时用的是粉色款。

眼唇妆容通常会比较细致和浓烈，因此也就更容易残留，所以再推荐几个眼唇卸妆液好啦。Lancome、Chanel、HR这三家的眼唇卸妆液都不错哦，可以试试。

卸妆膏现在市面上很火。我用过的感受确实挺不错的。很温和啊，不会刺激到皮肤。不过对于我这种每天都化妆出门的人来说，确实用得好快，好快.... 咦这瓶不是才买没几天嘛！！！

具体要说到产品的话，EVE LOM它家的卸妆膏呢确实不错，不过价位着实有些偏高，所以对于每天都上妆的MM来说，其实芭妮兰的就ok啦。性价比很高，卸妆也很干净。痘痘肌最好也买绿色的哦，绿色是控油版，普通肤质的MM粉色的就好啦~

卸妆蜜也是很温和的卸妆产品，痘痘肌的女生可以试试，日本的curel珂润很推荐。

第三、清洁面膜

这里我的看法是，清洁面膜一定要做的哦。建议一周1~2次。一个星期可以考虑去一次面部角质~

现在的空气质量你懂的，面部也需要专门清洁打扫才会干净呀。

清洁面膜的产品，我觉得Borghese的各种颜色的泥都还不错啦，痘痘肌选择绿泥吧。我之前用的粉泥，一罐能用好久好久，身体也可以一起使用呢，第一次使用的MM会觉得脸上有刺痛感，不要害怕，因为里面有火山泥的成分，所以，前几次有刺痛感很正常，用久了就无感了。不过每次用完脸确实滑滑的，第一次使用的MM也可以涂得相对薄一点点，我每次做完都会用洗面奶再一次脸（可以用泡沫洗面奶啦），不然总觉得用清水洗不干净。T^T

我现在的清洁面膜用的是Aesop的樱草面膜，也是会有刺痛感啦。味道嘛，我是不太喜欢，不过确实用完，皮肤很舒服。它家的香芹籽精华也不错，虽然味道我一直都不太适应，但是瓶身的设计看起来很酷，赞赞赞！

如果让我推荐一个比较不会有刺痛感的清洁面膜，可以考虑SUM的泡泡清洁面膜哦。用完也是滑滑的，而且一点也不疼，重点是好好玩！嘻嘻！

清洁面膜一般敷在脸上5~8分钟，泡泡面膜就是涂在脸上之后，生成泡泡，待泡泡消失的差不多的时候洗掉就ok。

个人的经验呢，通常清洁面膜之后，我都会再敷一个补水面膜。（敷完之后，我都是用清水把面膜残留的精华洗掉，再擦精华、水、乳液、Dior修颜乳（修颜乳感觉效果一般）、心机限量夜间粉（当时找日代买着玩的，盒子超好看、不过淡淡的香味倒是不错啦）、再用一下睫毛精华、再涂一层厚厚的润唇蜜，然后觉觉。我不嫌累~~~

护肤：

护肤最关键的是选择适合自己肌肤的产品，价位不重要，重要的是用着舒服。

我高中的时候，基本上试过了韩国skin food这类牌子的所有护肤品。因为住校嘛，所以我和同学都会买不同系列的，然后一起用。不过韩国的产品我没有用太久啦，原因不是我自己感觉不好，而是总有报道说里面添加了一些乱七八糟的东西，后来就干脆换掉了。

在这里我一定要推荐一下the body shop的护肤品，性价比高！好用不贵！而且含量不是很大，每天使用也就是3~4个月，可以满足少女总是换新品的小心思~

我冬天的时候会觉得皮肤很干，这种情况我一般就会使用VE的系列。痘痘肌的女生可以使用茶树的，不过味道没那么好闻，如果觉得那套不喜欢也可以尝试一下芦荟的哦~还有它家的身体霜，也赞赞的！

再就是如果脸部比较敏感的MM，L'OCCITANE也不错。我很喜欢这个牌子，杏仁的沐浴油、身体霜算是我最爱，乳木果手霜和杏仁手霜也棒棒的，最近也觉得樱花的身体护体味道甜甜的呢。

Biotherm、Kiehles、Lancome......还有很多哈，这就要看你自己对品牌的爱好啦，我只觉得都还好。碧欧泉的可以不试啦，效果平平，Sisely的全能乳液确实不错，不过味道一般般，Sisely家我最喜欢的是蓝色的那个睡眠面膜，真的很舒服呢，不过Lancome的睡眠面膜也不错。

现在人在台湾，我有购入一套For beloved one的水乳，性价比很高，价格不贵而且味道很舒服呢。如果你要来台湾买的话，可以不在专柜买，台湾的屈臣氏里也有，偶尔会有某个单品的活动让你买的爽爽的。哈哈。

Dior的美白单品，我也有购入，就觉得还ok啦，瓶子看起来很喜欢。之前说过的，新光三越的BA人太好，所以不由自主......多买了些......

这里还想推荐一下莱珀妮的护肤水，价格偏高，不过真的很好用啊，想改善肌肤的MM真的可以用一下！而且水要多擦点，让肌肤喝饱它！娇兰则是我个人心头爱，买买买！！不论是兰花的还是美白的，都赞哦！

看了我整篇回答会发现，我个人是对欧美化妆品品牌接触更多哈，比如有人喜欢的cpb、奥尔滨、skii，这些吧我接触着实没那么多，不敢妄自评论。不过建议是找日代买。日本本土的产品和内地的是有区分的。痘痘肌的MM可以试试奥尔滨的健康水，身边的朋友都说不错。

水乳基本上都还是建议配套，比如有人说高保湿的单品什么的，我觉得吧，都差不多，你吸收得好的就是好的单品，跟大家一起选择吧是没错啦，不过就我自己的经验，比如科颜氏的高保湿霜口碑就很高，可我真的觉得很一般。所以呢，选择适合自己的就好，这事儿跟谈恋爱是一样一样儿的。

既然爱美丽就多去专柜试一试，比较比较。

眼部呢，我现在21岁，暂时不打算用眼霜。不过Dior的眼部精华不错，一个红色的小瓶哈，我买东西不太care系列，还有一个diorsnow的眼霜吧（它是一个小管的，有按摩的胶头）这是最近准备购入的产品，原因是....... 我太爱笑啦，眼睛下面会有小细纹，所以很着急.......

不过坚持做眼贴也是可以改善的，不过我算一下还是觉得眼部精华更合适一些。

眼贴的话，我最近做了一下台湾本土的眼贴，觉得都还ok。之前在内地有买贵妇眼贴，我是蛮喜欢的，可以和家里人一下贴。妈妈还用它贴法令纹哈哈。

基本上护肤的路数你把上述的部分执行个百分之六七十、七八十就能拥有非常不错的皮肤了。

我也不介意跟大家分享一下我自己另外的一些小经验。我自己是每天都要敷面膜，我还年轻，并没有永太贵的面膜，来台湾就买本土的在用，在内地就买日韩的面膜，snp、克莱斯、丽得资、kose、肌美精..... 我都随意用啦，也不固定，现在是每天晚上敷，早上呢，洗完脸就用一个眼贴，然后洗掉再开始我的那些步骤，不过我觉得化妆前敷面膜也不错哦。

lululun就有妆前面膜（白色的），但我感觉不太舒服，不够滋润。罐装面膜fresh的玫瑰面膜、黄糖面膜、红茶面膜也都是不错的面膜产品，fresh现在也是人家心头爱啦。（捂脸）

睡眠面膜呀，sisely、lancome、givenchy的都很有市场，当然我还是觉得sisely的最好。高中的时候也是解救过我脸的单品。

也一直有人和我推荐雪花秀的玉容面膜之类的，但我暂时没什么接触，所以先不说。要是你们很好奇好不好用我可以买个来试试嘻嘻。噢，既然提到雪花秀就推荐一下它的气垫bb吧，哈哈，喜欢的气垫bb的女生试试吧，你会觉得其他家的气垫bb都弱爆了~~

今天先写到这儿吧~我手累了~

觉得写得好欢迎点赞！也欢迎关注我的微博！我要持续写的！！

写了一整个晚上，每一个字都是钱砸出来的嗷呜！认真得跟谈恋爱似的 T T

好啦早睡才会有好皮肤哦！小胖脸跟大家说晚安~~

么么哒，美美哒。
编辑于 2015-03-18
李羽娴
李羽娴
人生是一场冒险

本人皮肤好，是整个班公认的，我就不说用什么产品了，网上太多，而且每个人肤质习惯不一样，说了也白说！我说点生活的，我的外婆是医生，我妈妈是一个特别讲究的人，生活上要求特别严，有几个建议可以推荐大家

……………………………………………………………………

1.每天早上喝蜂蜜水，比白开水更好，美容养颜，这个的坚持，我坚持了十几年，最好根据体质选蜂蜜，我已经喝到随便一闻就知道是什么味的，实在是喝太多，我可怕的妈…………
2.平时多换洗脸帕，多洗床上用品，这样不容易有螨虫，就不容易长痘，夏天多晒被子！！这是真的，可以百度！
3.防晒，防晒，防晒！真的，我高中就开始防晒了，这个让我白了好几度！最好晚上也喝柠檬水！喝了就睡！
4吃番茄，天，我高中吃了3年，每天中午起床就吃个番茄，一个苹果…那段时间感觉闻着番茄就想吐，不过白了好多啊！直到大学，我都不怎么吃苹果，真的太烦了！
4.吃芝麻，我每天都吃一把，我去，真的头发就像拍广告的，大一还去做了发模的！我平时都没有摸护发素，一半就是精油比较多，但是我头发特别黑，特别亮！！！！
5.就是敷面膜，最好每天，这是我大学发现的，我是干性皮肤，所以感觉之水！
6，多喝牛奶，这个对皮肤好
7.最重要的！就是别吃辣椒别吃零食，楼主很奇葩，在家吃的少油无辣，我还是一个四川人啊！但是就这样坚持了20多年，除了大学熬夜写论文上火长了痘，大学前就没长过，至今长过9颗！皮肤光滑到要死，不是我自夸，是真的，拍照我的脸可以反光……………我同学说我远看就像灯泡！这还是夸奖么！！！……………
8.就是月经期间，一定喝四物汤，我的天，这个是真的，补气补血，气色好的一逼，某宝可以买，很便宜的！！！


一点生活经验，不用赞\(≧▽≦)/看了说好就行

对了，还要补充，女生多吃一些五谷粉和银耳汤哦⊙∀⊙！
编辑于 2017-11-07
莫嫡
莫嫡
研究皮肤、研究配方，让肌肤健康的美丽
【引子：作为一个研究皮肤的配方师, 经常遇到由于错误护肤而成为问题肌肤的女生, 深感痛惜, 借此题好好论述一下:  一切护肤保养的基础是,   你的肌肤需要什么】


为便于大家浏览， 先列提纲如下：

【一】什么是好皮肤？
1. 皮肤颜色
2. 皮肤光泽
3. 皮肤细腻
4. 皮肤滋润
5. 皮肤弹性

【二】哪些因素影响皮肤好坏？
1. 内源性
a. 遗传
b. 营养
c. 内分泌
d. 睡眠
e. 心理因素

2.外源性
a. 湿度
b. 紫外线
c. 吸烟
d. 污染
e. 皮肤护理

【三】我们的皮肤需要什么?

【四】如何让皮肤变好?

【五】给楼主的建议

====================================

我们回到问题， 楼主的题目是“如何让皮肤变好”， 我们先回答， 什么是好皮肤？

【一】什么是好皮肤？


皮肤的好坏，从下面5个方面来区分

1. 皮肤颜色 
皮肤的颜色和深浅取决于皮肤内黑色素和胡萝卜素含量的多少、真皮内血液供应的情况以及表皮的厚薄。

1） 黑色素：是由基底层的黑素细胞分泌的，黑素细胞起源于外胚层的神经嵴，其数量与部位、年龄有关而与肤色、人种、性别等无关。黑素细胞位于基底层，数量约占基底层细胞总数的10％，细胞胞质透明，胞核较小，银染色及多巴染色显示细胞有较多树枝状突起。电镜下可见黑素细胞胞质内含有特征性黑素小体（melanosome），后者为含酪氨酸酶的细胞器，是合成黑素的场所。1个黑素细胞可通过其树枝状突起向周围约10～36个角质形成细胞提供黑素，形成1个表皮黑素单元（epidermal melanin unit）。黑素能遮挡和反射紫外线，保护真皮及深部组织免受辐射损伤。黑色素分为优黑色和褐黑素两种。黄种人的皮肤中既存在优黑素，又存在褐黑素。尽管皮肤的颜色主要是由遗传因素决定的，但是紫外线照射、内脏疾病、精神因素、睡眠不好、体内维生素、氨基酸代谢紊乱、炎症反应、内分泌的改变（如怀孕期间，患有阿迪森氏病）等都会导致色素增多，使皮肤显得晦暗、出现色斑。反之，如果黑素细胞数目减少，酪氨酸酶异常，亦可出现色素减退或脱失。因此，皮肤颜色实际上是遗传背景，紫外线的照射，激素等因素共同作用的结果。皮肤美容的目的在与通过正确的养护和治疗来保持正常肤色，驱除病态肤色。

2） 胡萝卜素：胡萝卜素主要存在于表皮角质层和皮下组织中，是皮肤呈黄色的因素。β-胡萝卜素是胡萝卜家族中最重要的一员，主要来源于颜色鲜艳（红、黄、橙）的蔬菜和水果中，如杏、胡萝卜、青椒、菠菜、地瓜。在体内，胡萝卜素可以转化为活性维生素A，所以胡萝卜素往往被看作是一种维生素前提。因为机体将胡萝卜素转化为维生素A醇的能力有限，所以如果补充过多的胡萝卜素，就会引起掌跖部位的皮肤变黄，角膜也会同时出现黄色改变。只要限制胡萝卜素的摄入即能缓解。

3）  脂褐素：脂褐素(1ipofuscin)是一种不溶性的脂类色素，是不饱和脂肪酸由于过氧化作用而衍生的脂肪色素复合物。通常认为属于一种细胞内贮存病，由于脂褐素不能被正常的溶酶体酯酶所分解，而大多数细胞又没有排除能力，因而在细胞内蓄积。电镜下，脂褐素为致密颗粒、空泡和脂肪小滴的凝聚物。医学上称“脂褐质色素”，俗称老年斑，由此认为，寿斑并不表示高寿，倒是衰老的象征。

4)   真皮内所含的氧合血红蛋白，赋予皮肤以红色，而缺氧血红蛋白则使皮肤呈现蓝紫色。在眼睑下方，由于皮肤较薄，血管的颜色显露，故而皮肤呈现出紫红色或者蓝黑色的“黑眼圈”。当皮肤处于寒冷的环境中时，血管收缩或者痉挛，故而皮肤呈现出青紫色，由以血运丰富的口唇表现的最为明显。老年人的皮肤较年轻人缺乏“血色”，也与老年人真皮中血管变细，数量变少有关。

2. 皮肤光泽
皮肤的角质层外覆盖着一层皮脂膜，有皮脂腺分泌的脂类和汗腺分泌的水分乳化而成。

1)    正常皮肤含水量应在10-20%，水油平衡，皮肤才能有光泽。缺水的皮肤则晦暗干燥。

2)    皮脂膜含有的脂类能够滋润皮肤，使皮肤有光泽。受损伤的皮肤其屏障功能下降，透皮水丢失增多，导致皮肤含水量下降。如果皮肤营养状态差，皮脂生成减少，皮肤也会显得晦暗无光泽。长期的素食使得脂肪，尤其是胆固醇的摄入减低，因此皮脂分泌减少，皮肤干燥无光泽。

3)    真皮中致密的胶原蛋白、弹力蛋白以及糖氨聚糖会像镜子一样将入射光反射回去，使皮肤显得光泽。老化的皮肤由于真皮萎缩变薄，从皮肤上反射回去的光线减少，就会显得晦暗。经过维甲酸治疗或者进行激光换肤、强脉冲光治疗后真皮的胶原蛋白合成增加就会改善皮肤晦暗的状态。

4)   老化的皮肤角质层脱落速度变慢，而角质层中滞留的色素粉尘也会使皮肤显得缺少光泽。所以老化的皮肤定期清理角质，会使皮肤显得有光泽。

3. 皮肤细腻
皮肤细腻主要由皮肤纹理和毛孔大小决定。健美的皮肤质地细腻，毛孔细小。皮肤附着于深部组织并受纤维束牵引形成致密的多走向沟纹，称为皮沟（skin grooves），其将皮肤划分为大小不等的细长隆起称为皮嵴（skin ridges），皮沟与皮嵴构成皮纹。较深的皮沟将皮肤表面划分为许多三角形、菱形或多角形的微小区域，称为皮野（皮丘）。皮肤细腻是指皮肤具有皮沟浅而细，皮丘小而平整的纹理。这种皮肤能给人以质地细腻的美感。

1)  日光或其他因素都会使真皮胶原纤维和弹力纤维发生变性、断裂，引起皮肤纹理加深。如光老化引起的项部菱形皮肤，长期搔抓导致的皮肤苔藓样变等。

2)  影响皮肤细腻外观的另一个重要因素是毛孔的大小。毛孔的直径大概为0.02～0.05毫米，面部皮肤大约有两万多个毛孔。毛孔粗大常见的原因：    (a）青春期油脂分泌过度，代谢产物以及细菌分解产物堆积至排泄不畅堵塞毛孔。此外，季节、女性生理周期、怀孕、精神压力、脂溢性皮炎等因素都会造成油脂分泌过盛，从而导致毛孔粗大；   ( b）老年人由于真皮中胶原蛋白和基质成分的减少，造成萎缩性毛孔粗大。

3)   橘皮样皮肤也会造成皮纹的改变，影响美观。
皮肤美容治疗和护理有助于改善皮肤纹理，缩小毛孔，使皮肤细腻光滑。

4. 皮肤滋润
健美的皮肤应该是湿润的。

1)   当皮肤中水分含量过低时，就会出现龟裂和裂缝。因为水是皮肤中主要的增塑剂。如果皮肤屏障功能受到破坏，导致透表皮水丢失增加，皮肤就会变得干燥。一般来说，去污剂、丙酮、热水、频繁的空中旅行、衣物的摩擦、污染、空调等都能破坏皮肤的天然屏障，导致透表皮水丢失的增
多，皮肤干燥。当皮肤严重缺水时，角质层变硬形成龟裂，进而形成裂缝，皮肤变得易受刺激、发炎并瘙痒。

2)   表皮的屏障就像是灰泥砖墙结构—角质层的细胞就像是砖墙，而细胞外的脂质构成灰泥。如果屏障功能受到破坏，皮肤抵御外界病原、刺激物和致敏物的能力大大下降，容易形成感染性疾病和过敏性疾病。在皮脂腺分布相对稀少的部位，如四肢和躯干，皮肤容易干燥缺水。

3)   如果角质层的水分不足，那么分解桥粒的酶的活性受到抑制，角质层的正常脱落就会受阻，形成肉眼可见的大片鳞屑，皮肤变得粗糙而干燥。

4)  角质层的含水量主要受天然保湿因子调控。天然保湿因子是角质层中存在的天然亲水性吸湿物质，是丝聚蛋白（filaggrin）的代谢产物，均为水溶性低分子物质，在皮肤的保湿上起着重要的作用。天然保湿因子的主要成分是氨基酸、吡咯烷酮羧酸和乳酸盐。

5)  水分除靠简单的弥散方式进出皮肤外，还通过细胞膜上的水通道蛋白（Aquaporins, AQPs）进行转运。在哺乳动物中已发现13中水通道蛋白。动物试验证实，如果老鼠AQP3缺陷，那么就会出现表皮水分和甘油减少，角质层脱水，皮肤弹性和屏障功能下降。提高皮肤含水量的方法有很多，主要是外用各种保湿剂或封包剂，如神经酰胺、甘油等。

5. 皮肤弹性
皮肤的弹性体现为皮肤的湿度、张力、韧性、丰满。健美的皮肤应该是湿润、有弹性、丰满且充实的。

1)   如果皮肤的角质层水分充足，皮肤就会显得润泽有弹性。反之，皮肤干燥就容易出现细小皱纹、弹力下降。

2)   在真皮中，由胶原蛋白、弹力蛋白和透明质酸共价结合，构成三维立体结构。胶原蛋白是人体也是皮肤中含量最高的蛋白质。胶原蛋白

维持皮肤的张力，其韧性大但弹力差。真皮中共有11中胶原蛋白。胶原蛋白是在纤维母细胞中合成的，被细胞外基质金属蛋白酶分解。随着年龄的增长，其合成的速度逐渐减少，而分解代谢的速度逐渐增加，所以真皮中胶原蛋白的含量以大约1%的速度递减。外界的刺激，如紫外线，污染以及
机体的状态（疾病、压力）等都会影响胶原蛋白的代谢，使皮肤失去张力，松弛，无光泽。

3)   赋予皮肤弹性的是弹力蛋白，真皮中的弹力蛋白也是在纤维母细胞中合成的，最终被弹力蛋白酶水解掉。随年龄的增长，弹力蛋白的含量也逐年下降，80岁时仅为20岁的一半。但曝晒会使得弹力蛋白变性，失去原有的网状结构，代之以局灶性的弹力蛋白样物质的沉积（弹力蛋白变性）。

4)   真皮中的主要基质成分是糖胺聚糖，主要功能为结合水分，维持水盐平衡。透明质酸是糖胺多糖中的含量最高，能结合水分，使真皮充盈饱满。

5)   果酸和左旋维生素C能够刺激胶原蛋白的合成，外用维甲酸能减少光老化导致的胶原蛋白的破坏，激光或者化学换肤技术剥脱掉老化的胶原蛋白，取而代之以新生的排列更加规律的胶原蛋白，局部注射透明质酸、胶原蛋白或其他化学合成的物质从而促进胶原蛋白的新生和沉积，这些方法都能够通过调节胶原蛋白的合成和排列从而提高皮肤的弹性，补充因老化而丢失的体积，使皮肤年轻化。

6)   皮下脂肪主要由脂肪细胞、纤维组织和血管构成。在体重正常的男性，皮下脂肪占体重的9%-18%；而在体重正常的女性，皮下脂肪的含量为14%-20%。随着年龄的增长，脂肪含量逐渐减少，并导致其上层的真皮松弛、下垂、弹性下降。所以皮肤的弹性也间接受到皮下脂肪的影响。自体脂肪移植能够暂时性缓解由于脂肪缺失或减少而造成的皮肤松弛下垂。

总结： 皮肤的这5个维度出发， 好皮肤的标准是：肤色均匀红润，皮肤水分含量充足，水油分泌平衡，肤质细腻有光泽，皮肤光滑有弹性，无明显色斑，面部皱纹程度与年龄相当，对外界刺激不敏感，对日光反应正常。




-------------------------------------------------------------------------------------------------
那么，
【二】哪些因素影响皮肤好坏？

1. 内源性因素


a.  遗传  皮肤的许多性状都是由遗传因素和环境因素共同作用的结果。皮肤的颜色，屏障功能、真皮中胶原蛋白、弹力蛋白及糖胺多糖的含量，皮下脂肪的分布等等都和遗传因素相关。某些皮肤问题，如雀斑、黄褐斑、色素痣等就是在基因的基础上，由紫外线所诱发或加重的。着色性干皮病和鱼鳞病都是由于遗传因素所造成的皮肤干燥、粗糙、角化异常。

b. 营养  均衡的营养是健康的身体和健美的皮肤的基石。某些食物和皮肤的状态息息相关。痤疮是毛囊和皮脂腺的炎症。如果饮食过甜（碳酸饮料摄入过多），就会引起胰岛素分泌增多，胰岛素样生长因子-1(Insulin-like growth factor-1, ILG-1)表达上调，刺激雄性激素的合成，引起皮脂腺的肥大和过度分泌。摄入过多的牛奶（包括奶制品）也会加重痤疮。牛奶中的生物活性物质，激素成分会干扰机体自身的激素分泌，从而有可能加重痤疮。不同类型的皮肤适宜于补充不同的营养。能够改善皮肤干燥的食品有：鳄梨、玻璃苣籽油、油菜籽油、夜来香油、鱼、亚麻籽油、大麻籽油、坚果、橄榄油、橄榄、花生、红花油、大豆、葵花籽油和核桃。能够控制皮肤油脂分泌过剩的食品有：富含维生素A的食品（哈密瓜、胡萝卜、杏干、蛋黄、肝脏、芒果、菠菜和地瓜）；富含类胡萝卜素的食品（番茄红素、叶黄素）；其他抗氧化剂(如青橄榄油)；鱼或鱼油（富
含Ω-3脂肪酸）。能够改善色斑、提亮肤色的食品有：维生素C、维生素E、石榴提取物（富含鞣花酸）、葡萄籽提取物（原花青素）、碧萝芷（多种类黄酮多酚，包括月桂酸、富马酸、没食子酸、咖啡酸、阿魏酸等）。能够延缓皱纹产生的食品有：蔬菜（绿叶蔬菜、芦笋、芹菜、茄子、葱、
蒜和洋葱等）；橄榄油；单不饱和脂肪酸、豆类，应少摄入奶及奶制品、黄油和糖。

c. 内分泌  皮肤及附属器中都存在性激素的受体。女性在怀孕期间，由于雌孕激素水平上升，黑色素的合成增多，所以肤色加重，尤其是性激素受体较多的位置，如乳晕、腋窝等处。此外，雌激素会增强紫外线的作用，导致孕妇容易出现黄褐斑。随着年龄的增长，激素水平也逐渐下降。男性的下降较为缓慢，但女性在绝经期性激素骤减。

d. 睡眠   睡眠不足引起氧合血红蛋白含量降低，使皮肤细胞得不到充足的营养， 影响皮肤的新陈代谢，加速皮肤老化，使皮肤显得晦暗而苍白；同时，睡眠不足导致副交感神经兴奋，引起促黑素细胞生成素增加，色素生成增加。

e. 心理因素  情绪低落时，皮肤新陈代谢变慢，肤色晦暗，色素斑出现或加重。精神愉悦时，皮肤的新陈代谢增快，容光焕发，充满青春活力。

2.外源性因素


a.  湿度  正常状态下， 体外的相对湿度与表皮层水分含量可达到动态平衡，湿度较低时，表皮层水分散失增多，皮肤干燥无光泽，皱纹增多，加速皮肤老化，因此， 在北方及各地区的冬季，更应使用保湿剂。 当相对湿度较高时，皮肤可从外界吸收水分， 以保持表皮层水分含量的稳定。

b.  紫外线   同自然老化比起来，光老化对皮肤的影响更大。在曝光部位，由于紫外线的破坏，皮肤过度干燥，出现鳞屑。由于紫外线造成胶原蛋白合成减少、分解加速，使得真皮变得萎缩，提早出现细纹甚至是粗大的皱纹。紫外线造成的弹力变性使得真皮失去应有的弹性，变得松弛无张力。在某些曝光部位，如项部会出现菱形皮肤。由于紫外线破坏了皮肤的免疫屏障，干扰了抗原递呈细胞的活性，从而导致抵抗能力下降，皮肤容易出现感染和敏感。常见的有日光性雀斑样痣、脂溢性角化、皮赘等。长时间的曝晒还会导致一些癌前性疾病，如日光性角化和皮肤癌的发生。


c.  吸烟   一项长达20年的流行病性调查表明，吸烟者比不吸烟者皱纹明显增多，出现早衰征兆。在一项双胞胎的研究中，发现吸烟能显著增加皱纹和老化程度。典型的吸烟者表现为“吸烟者面容”或者“吸烟者皮肤”，包括：面部皱纹，轻度红或黄的肤色，整体外观灰白，浮肿，面色憔悴。烟草中的主要成分尼古丁有利尿作用，所以吸烟可以导致表皮含水量下降，屏障功能受到破坏。吸烟可增加真皮中基质金属蛋白酶的表达，导致胶原蛋白和弹力蛋白被分解，断裂，皮肤松弛下垂，皱纹增多。吸烟会减少皮肤中维生素A的水平，后者对中和氧自由基有着重要的作用，所以吸烟可导致早衰。吸烟还会减少毛细血管及动脉的血供，抑制创伤修复机制。

d.  污染   环境中的各种污染物，包括化学物质、声电污染、尘埃等都会造成氧自由基的增多，从而诱导炎症反应，最重导致皮肤的衰老。

e.  皮肤护理   护肤品及美容方式不当，不仅造成皮肤化妆品不良反应及破坏皮肤屏障功能，而且是损容性皮肤病，如痤疮、黄褐斑等疾病的诱发或加剧因素。


-----------------------------------------------------------------------------------------------
通过以上分析， 那么
【三】我们的皮肤需要什么?


我们从下面的几个现象来分析

【现象一】为什么身边那些不用护肤品的男人虽然脸上油油的但是皮肤很少出问题？

是的，这是因为他们表皮外面的皮脂膜是健康的在保护着肌肤。

        【皮脂膜是啥？】皮肤角质层的表面有一层由皮脂腺里分泌出来的皮脂、角质细胞产生的脂质及从汗腺里分泌出来的汗液融合而形成的一层膜。

         它有两个作用，一个是锁水，防止表皮内的水分蒸发；另一个就是滋润皮肤。

Ok， 看到这里， 从皮肤角度出发， 我相信大家就明白：当我们频繁洗脸、用40度以上热水洗脸的时候， 轻易就能洗去皮脂膜，从而失去皮肤最外面的保护层。

下图：皮脂膜示意图


【现象二】为什么有些人洗完脸之后，会觉得脸很干？即使外面是瓢泼大雨，空气湿乎乎的，不涂护肤品脸还是干干的？

         如果是这样，很遗憾，你的角质层已经受损了。

        【角质层是啥？】 是表皮最外层的部分，主要由 5 至10 层扁平、没有细胞核的死亡细胞组成。角质层起到非常重要的屏障功能，可以保护其皮下组织；锁水；防止皮下组织遭受微生物感染；以及抵抗化学侵袭和外力所带来的压力。

         同样， 从皮肤角度出发， 大家就能明白：当你用脱脂力很强的洗面奶和皂、当你频繁的去角质、当你用美白产品刷酸溶角质的时候， 你的角质层的屏障保护功能就会下降， 就会出现过敏，问题肌肤等。

下图：角质层屏障功能示意图


【现象三】为什么这个从业28年的美国货车司机左脸老化更严重？

         各位看官都知道， 美国的驾驶位和我们一样， 在车的左边， 一个开了28年的货车司机， 左脸累积的光照光强高于右脸（左脸距离车窗玻璃更近）， 导致了左脸看上去比右脸老十多岁！

         乍一看照片， 叔也给吓着了， 从皮肤的角度看， 这就是光导致的皮肤损伤：皮肤干燥、发黄、大量的深皱纹、不规则的色素沉着、各种癌前病变、毛细血管扩张以及血管脆性增加。

         几乎我们能想到的皮肤问题， 都与光老化有关， 如：色斑、皱纹、松弛及红血丝等。 而且，紫外线对皮肤的伤害是累积的， 每接受一次没有防护的日光照射，就向衰老迈进了一步。可怕！

下图：货车司机的脸部照片


【现象四】为什么四川雅安的妹子皮肤最好？

         这要从雅安的气候说起。雅安为亚热带季风性湿润气候，年均气温在14.1℃～17.9℃间，降雨多，多数县年降雨1000~1800毫米以上，有"雨城"、"天漏"之称。湿度大，日照少。

See？ 从皮肤角度出发，空气中湿度大， 经表皮流失水分少， 皮肤不缺水；太阳照射少，光对皮肤的损伤少，所以雅安妹子皮肤大部分都很好。 

         现象即规律，由此， 我们总结出来， 从皮肤的角度，  我们的皮肤真正需要的是：在不伤害皮肤的基础上，  保湿+防晒！

下图：雅安著名的雅雨




-------------------------------------------------------------------------------------------------------------------
知道了我们的皮肤需要什么， 那么
【四】如何让皮肤变好?

         下面是个人总结的护肤保养的方法：

1、常开加湿器。


         我自己家里和办公室都有加湿器，24小时离不开它，睡觉也是一直开着。为什么？ 

营造一个皮肤舒适的湿度空间， 湿度在60-70之间是皮肤最喜欢的。如果能达到这个湿度，皮肤可以从外环境吸水来补充角质层水分。

下图：空间加湿


2、吃吃吃，补补补。

         补充维生素C、E，减少胶原蛋白的流失；多吃新鲜水果蔬菜，尤其是山药、木耳、银耳等中医所云补阴生津的食物。

         各位爱美的看官，特别是女人，通过食疗真的可以大大改善皮肤哦。

         最简单的就是银耳汤，银耳撕碎，十颗红枣，十粒莲子，一小把百合，八朵干玫瑰捏碎撒入，再加点枸杞和红糖，一锅炖，焖个一整晚，连续吃一个月，保证皮肤变滑滑，还会变白哦~~

私人秘方，轻易我不告诉别人哦~~

下图：温润银耳汤


3、选用温和的洁面产品。

         洗脸一定要把握“温和”， 成分上要选氨基酸+糖苷的，千万不要用脱脂力超强的皂基系和sls的。参考这篇洗面奶的文章： 是什么成分导致很多洗面奶（包括氨基酸洗面奶）洗后有滑腻感，或者感觉乳状物洗不干净？ - 莫嫡的回答 。

洗脸的时候也不要过度摩擦肌肤。有迹象表明，女性过度摩擦脸部肌肤可能导致黄褐斑。

下图：温和洁面，如触摸婴儿肌肤




4、少用带粉的产品，粉底、粉底液、隔离霜、BB霜等。

粉类产品是个伟大的发明，用于调整肤色，改善面部质感，遮盖瑕疵，体现质感。

         但是由于粉类产品含有极细颗粒的滑石粉、高岭土和二氧化钛等粉类，容易堵塞毛孔，致使皮肤无法正常呼吸，从而产生粉刺、暗疮和痘；长期使用会令皮肤粗糙、暗沉。

这里补充【微镜下上了BB霜的皮肤】的检测：二十岁的经济能力有限的女孩怎样护肤和化妆呢？ - 莫嫡的回答


5、防晒非常关键。

光对皮肤的损伤是日积月累的，用黑色素检查仪器能看到皮下黑色素的分布情况。皮肤的自然衰老目前是不可逆转的， 所以我们一定要做好光的防护，尽可能减轻光导致的皮肤衰老。

这里请参考防晒的详细描述：什么是物理防晒，什么是化学防晒？ - 莫嫡的回答

1)  防晒效果： 太阳伞、衣服、帽子 > 太阳镜 > 防晒霜

2)  避免紫外线高峰时段(10-16点)外出

3)  防晒霜对皮肤多多少少有些不好, 问题肌肤、敏感肌肤 尽量采用物理遮蔽的方式。

4)  户外时间长, 可以 物理遮蔽(衣服伞帽镜)+防晒霜


6、选成分而不是选品牌。

         我们护肤保养的基础是不伤害皮肤， 对皮肤有刺激和伤害的成分是我坚决摒弃的。

         我在做配方的的时候， 坚持2个原则： 

1）原料一定是安全的对皮肤无刺激的  

2）只选用有效合适成分， 不堆砌成分。

         所以我的配方是简约的， 成分列表一般不会超过10个，但是举目望去， 市场上的琳琅满目的各种护肤化妆品里的成分少则2、30种多则6、70种， 我们的皮肤并不需要这么多乱七八糟的成分！

下图：某牌的成分列表。绿色的成分是安全的，红色黄色的成分是对皮肤有刺激的。

          免责申明： 以上数据来自CosDNA 化妝品便利資訊網




------------------------------------------------------------------------------------------------------------------

好了，貌似废话太多了，结合楼主的实际情况

【五】给楼主单独的建议

1.  换洗面奶。 露得清是皂基系的洗面奶， 脱脂力很强， 你的敏感肌肤耐受不了。换成氨基酸表活+糖苷 的温和洗面奶。

2. 用乳液保湿。 北京我待过， 特别干燥，化妆水是不够的， 一定要涂抹保湿效果好的乳液， 不光脸上， 身体也需要。 长期下去， 皮肤会水润光滑有弹性的。


如果大家想更多了解护肤tips，可以微博：Morettie莫嫡  或微信：M17712869031 
编辑于 2015-07-06
Van Shaun
Van Shaun
是个设计，也是个大梦想家。
你所需要的不是金钱能买到的。是勤快。
发布于 2015-02-23
ZZZZ
ZZZZ
Sex , freedom, whisky sours

内容比较丰富，请自选！无论是祛痘新手或大神，相信此文都会有所收获。 

直击方法与要点，没有过多的理论。

正规答案之前，先露一手！

答主今天教小主们一个如何辨别好的保湿水的小诀窍

用力摇，使劲摇 摇完之后看泡泡。

1⃣泡泡很少，说明营养少

2⃣泡泡多但是大，说明含有水杨酸。水杨酸洁肤的效果较好，但刺激性大易过敏。 

3⃣泡泡很多很细，而且很快就消失了，说明含酒精。不要长期的使用，容易伤害皮肤的保护膜。

4⃣泡泡细腻丰富，有厚厚的一层，而且经久不消，那就是好的水。


--------------高能分割线--------------------

一、按照以下爆痘原因，自我检查：

1.雄性激素分泌过多; 

2.油脂分泌过多，分泌过多的皮脂和未及时清除的汗液、灰尘、病菌、螨虫等阻塞皮脂腺口; 

3.局部炎症; 

4.细菌感染、交叉感染：病原微生物—痤疮杆菌的作用; 

5.免疫抗体作用; 

6.遗传因素;

7.微量元素缺乏，导致角化过度; 

8.矿物油类的接触，如碘化物、溴化物的使用; 

9.多吃动物脂肪及糖类食物，消化不良或便秘等胃肠障碍;

10.心理状态不平和，精神紧张，烦躁易怒，睡眠不足;

11.水土不服、湿热气候等;

12.清洁不彻底，毛孔污物太多；

13.喝中药，很多中药祛痘是排毒的方式外在表现就是爆痘；

14.挤痘痘的方式，挤痘痘会将原本在毛孔浅层的栓塞物推向深层诱发炎症引起爆痘；

15.还有一种情况就是随意涂抹消炎激素药膏，产生了过敏反应；

二、大家私信我的问题及解决方案（如果时间不够，请选择你想看的问题）

1.	什么是腮边痘？

腮边痘（淋巴痘）主要是长期肝胆超负荷，淋巴排毒不畅引起，主要在耳际、脖子和脸交界处产生，反复爆发在同一位置，严重会形成结节。 

建议：！

❶早睡，少熬夜，帮助肝胆排毒

❷生活规律

❸饮食清淡，忌烟酒、辛辣油腻食物、如火锅、麻辣烫、烧烤、海鲜、牛羊肉等。

❹每天涂抹护肤品的时候可以轻轻对整个面部进行轻柔按摩，帮助改善皮下的血液循环和淋巴循环，从而达到排除淤积毒素的作用。

2.为什么长痘痘要少吃甜食？

甜食本就会刺激类胰岛素生长因子升高，胰岛素生长因子属于一种荷尔蒙，当它分泌增加时就易加速人体内雄性激素分泌，进而刺激皮肤分泌更多油脂。

过多的皮脂加上毛囊口的角质栓就会形成粉刺与痘痘，所以过多食用甜食很容易诱发痘痘，而且会加重原来痘肌的病情！！

少甜食、以及含亚油酸的食物也可能会造成你毛孔粗大长痘痘喔！随著年龄增长，人体对糖的代谢速度会变慢，不能被及时代谢的糖会产生糖化现象导致胶原蛋白流失，皮肤就会出现松弛型毛孔粗大。

3.长痘时，月经期要注意什么？

（1）注意选择信得过的卫生巾。宁可少买衣服，少吃点零售，也要买最好的卫生巾。 

（2）勤洗热水澡，不要洗冷水澡，但要清洗热水澡，保护身体清洁、干净。洗澡采取沐浴。注意不共用别人衣服、毛巾，自己的用具勤洗勤晒。 

（3）注意保暖。月经期间抵抗力下降，要注意保暖。避免涉水、淋雨、游泳、下水田或冷水洗头、洗脚，也不要坐凉席、凉地，夏天避免吃过多冷饮。 

（4）多吃些鸡汤、猪肝、鸡蛋、水果、蔬菜、红枣等，补充体内各种维生素和蛋白质等，增强体质，提高抵抗力。不吃辛辣生冷等刺激性食物，多吃纤维食物，如地瓜、窝笋、香蕉等，保持大便畅通。

4.	如何预防生理期痘？

❶及时进补。生理期除了注意不要熬夜、不吃辛辣生冷食物、按时作息以外，在生理期前7天可以吃一些红枣、莲子、川贝等食物，多吃一些含铁的食物，从身体内部调节

❷配合祛痘产品。在成分上避免使用激素类产品，以免皮肤依赖，反而对消痘不利。

5.青春期长痘正不正常？会不会年龄大了就好了？

很多家长认为“很多人都长痘就不是病”的观念其实是错误的，别看青春痘常见，一是影响孩子身心，二是可能造成永久创伤，三是早期不治疗会造成痘痘情况加重，今后再治疗的投入和难度更大。所以，绝不能忽视青春痘，建议越早治越好！

6.该不该排痘痘？

如果新生痘痘在两周之内自动消退则不需要排逗。

但长期不退，并发炎红肿甚至发紫那么这种痘痘必须要排。举个例子，身体伤口发炎后会留下色素，时间越长，色素积累越多，同时发炎的痘痘在脸上逗留时间过久，这个部位就会受损，及时好了也会留下痘坑。所以顽固的痘痘要尽早排掉，不要担心排痘是否会留下疤痕，你如果不排会留下更多。很多正规大医院都是有排痘的程序，有些痘痘真的必须趁早排。

去排痘的时候，尽量不要买推荐的什么什么东西，就只排痘就好，同时建议去正规大医院排痘！排完痘可以自己涂一层芦荟胶，同时注意防晒！还有生活习惯和饮食！

7.干性肌肤为啥也长痘？

一般情况干性皮肤发痘几率较油性皮肤低的多，但也有10-20%左右，这由多种因素造成，如电脑辐射，空气污染，内分泌以及摄入水分不足。夏季气温升高导致皮肤油脂分泌加剧，油脂大量从毛孔排出，如皮肤一旦缺水或清洁不彻底就会导致油脂堵塞毛孔，久之就会形成痘痘哦

8.为什么痘痘会连成片？

这是因为毛孔堵塞之后没有及时清理，逐渐发炎"殃及"到周遭的皮肤，导致周边的毛孔也堵塞。每颗痘痘又在你的毛孔深层“结交”下了很深的友谊!用一句话来形容：星星之火，可以燎原，所以有长痘趋势的时候，要及时进行清理！ 

9.有痘友问抽烟会对痘痘有不良影响吗？

抽烟会导致痘痘更加严重，而且会加速皮肤的衰老！因为香烟中的尼古丁会收缩微血管管壁，使血液和淋巴中的毒素堆积，皮肤细胞的复氧率降低，因而使皮肤的愈合能力减弱，容易形成痤疮伤口的交叉感染。所以请你在治疗时，需要忌口啦！

10.长痘痘的脸可以化妆吗❓

从理论上来讲，脸上已经长了痘痘，最好暂时还是保持素颜好‼️因为粉底大多偏油，涂在多油的皮肤上透气性差，容易堵塞毛囊口，使毛囊口发生病变形成痤疮脓包等‼️因此痘痘皮肤不建议使用粉底哦

记住三大原则：

1，	尽量化淡妆2，尽量不化妆3，卸妆要干净。

11.祛痘印最佳时机？

一年之中，祛痘印的最佳时机是冬天。

因为经过春、夏、秋的光晒，大多数痘友的痘印会变深。

而冬天，因为，紫外线相对减少，有利于痘印的修复。 

还在受到痘印困扰的痘友们，可别错过这最佳的修复时期！

12.	如何洗脸？（直男直接跳过这一点，看下一点）

越洗越美的方法:

第1步：从下巴到耳根，由下往上由里向外打圈的方式清洁； 

第2步：从嘴角开始到耳中，打圈清洁；

第3步：从鼻翼开始到太阳穴，不能用洗面乳洗眼睛； 

第4步：从额头中间到太阳穴； 

第5步：从上至下洗鼻梁，两边打圈洗鼻翼； 

第6步：嘴唇周围上下打括号，多清洁几下。每天早晚按此手法清洁皮肤，脸部轮廓上提效很好！

给T区去角质，每周两次。这样可以让肌肤透透气，也能够避免其他肌肤问题的产生。具体去角质次数依个人来定，比较敏感的肌肤一周一次，或者两周一次

13.做不到上面一点的直男怎么办？

洁面时，注意在易出油、毛孔粗大的T区部位稍作按摩，从下往上、由里往外打圈，以彻底清除表层油脂及毛孔内污物。记住每天的洁面次数不宜过多，每天两次就好。

如果还做不到怎么办？

那么请你注意，洗一定要洗干净！冲也一定要冲干净！用温水！冲的时候换一盆水！

14.怎么观察最近的生活状态和身体健康状态？

睡醒之后的脸色

1、如果脸色暗沉发黄，有可能是消化系统不好；

2、如果有不正常的潮红，有可能是心血管有潜在风险；

3、如果脸色发黑，有可能是肾脏系统有问题。观察“隔夜脸”，从调理生活方式入手。

15.体内湿气诱发起痘，怎么判断体内湿气重？

①看舌苔：若舌苔白厚带腻，提示体内有湿；

②看精神：早上起床后困顿头重，肢体乏力，懒得动，提示有湿气；

③看胃口：湿重时常会口淡、口甜、食欲下降、腹胀，甚至腹泻；

④看大便：大便不成形，或总有一些黏在马桶上，或是刚大便完又想大便

16.	痘印怎么办？

痘印分好多种，无论哪种痘印，都需要先治好痘痘，让痘痘不再长，痘痘还在长就去印，不可能有好的效果；还有个情况需要区分注意，痘印摸上去是平的，如是摸上去不平，就是痘痘里的栓塞物还没有排出来，而表皮已经封口， 必须先消除栓塞物，颜色才会退。

【加速痘印淡化十招快来看看】

1、先确保不再长痘痘； 2、多喝水； 3、多摄取维生素[c]； 4、保持充足的睡眠；5、少吃含有添加剂的食物；6、外用激活细胞，加速代谢的护肤品；7、使用补水护肤品；8、少吃颜色较深的食物；9、多运动；10、避免照射太阳

17.	不得不熬夜怎么办？

1、熬夜前千万记得卸妆，或是先把脸洗干净。2、不要吃泡面，最好尽量以水果、面包、清粥小菜来充饥。3、开始熬夜前，来一颗维他命B增强人体免疫力。4、提神饮料，最好以茶为主。5、熬夜之后，第二天中午时千万记得打个小盹哦。6、以后尽量不要熬夜哇。

18.	痘痘分几种？

️痘痘可以分为发炎的和不发炎的：不发炎的是白头粉刺和黑头粉刺，发炎的是丘疹、脓疮。很多痘友不拿白头和黑头当痘痘，通常都是等到细菌活跃开始发炎，脸上的皮肤变得比较“吓人”后才开始紧张，其实这种情况在白头黑头时期及时诊治，是完全可以避免的。

19.	夏季炎热，不同类型的皮肤怎么护理？

4⃣ 大类肌肤对症护肤重点➿

1️⃣.油性皮肤（清洁保湿面膜交替使用。)

2️⃣.敏感性肌肤（保护角质层、注意补水缓解过敏、上妆尽量轻柔）。

3️⃣.中性肌肤（清洁工作、均衡适度、保湿工作）。

4️⃣.干性肌肤（补水是王道、避免碱性强的洁面品、做好保养、防晒工作。

20.	面膜到底该怎么敷？

每日敷面膜的最佳时间：敷面膜有两个最佳时间段：一个是在早晨九点到十一点，因为这个时间段是人体脾经的运行时间，面膜中的精华成分吸收会特别好。另一个就是在晚上九点半到十一点左右，这个时间段是人体三焦经运行的时间，也是肌肤自我修复和吸收的最佳时间！

21.怀孕后停掉所有护肤品？

基底层细胞缺水，断裂，长斑，变黑。

生完宝宝就开始抱怨皮肤怎么会变成这样[抓狂]斑长的容易，想祛斑就不容易了。

请记住！！！任何时候补水都是不能停，水是万物之源，生物没水会枯萎，身体缺水会跨去，皮肤缺水会加速衰老！

三、吃货们看过来！

【护肤篇·蔬菜】

1、冬菇，排毒祛痘印。2、苦瓜，凉拌可降火滋阴。3、海带，排除放射性物质。4、木耳，清胃涤肠，凉血滋润。 5、南瓜，延缓肠道对糖和脂质的吸收6、花椰菜，清理血管 。7、胡萝卜，所含B族维生素和维生素C等可润肤。8、菠菜，抗衰老清热毒。

【清理肠道，美颜防痘】1地瓜含纤维质松软易消化，可促进肠胃蠕动；2绿豆可清热解毒、除湿利尿、消暑解渴；3燕麦能滑肠通便；4薏仁可促进体内血液循环、水分代谢，利尿消肿；5胡萝卜能清热解毒，润肠通便；6山药健胃整肠；7牛蒡可软化粪便；8芦笋有利尿作用；9莲藕可利尿；10茼蒿润肠通便。11祛痘清毒茶

【护肤篇·便秘】

如果消化管道不畅及大便不通畅，毒素就会存留于体内而被机体重新吸收，进而外发于肌肤，蒸熏面部就会长痘痘了，同时这种毒素可阻碍人体气机，影响人的气血运行，导致内分泌失调，致使痘痘长不停，痘友们一定要保持规律饮食和作息！天气高温干燥，一定要多喝水多吃水果哦

四、看了这么多干货，你一定渴了！那么就来说说这个水，该怎么喝。

水是我们身体最重要的一部分，干燥会令皮肤手感粗糙，不再丰盈柔软，还会出现细纹。[心碎][心碎]不管你是18岁还是80岁，保湿都是每日必须的基础功课。每天都保持肌肤水水润润的，你会比别人更年轻。[玫瑰][玫瑰]

失去水份的皮肤不但会加快衰老，代谢缓慢，大量出油，严重的就会慢慢引发闭口，再演变成痘痘

缺水还会出现干纹细纹，缺水的小裂纹

【清晨第一杯水你喝对了嘛】

1️.白开水：排毒瘦小腹，一般人最好的选择；

2️.盐水：加快肠胃蠕动排出毒素，便秘者适用；

3️.柠檬水：增加食欲，但长期饮用会引起钙流失，造成胃酸分泌过多:

4️.蜂蜜水：不适合早晨喝，更适合睡前，中医有云：朝朝盐水，晚晚蜜汤；

5️.牛奶：空腹喝牛奶，营养流失。

【水是最好的药】

    色斑：清晨一杯凉白开；

    感冒：要喝比平时更多的水；

    便秘：大口大口喝水；

    恶心：用盐水催吐。

    发热：间断性、小口补水为宜；

    肥胖：餐后半小时多喝水；

    咳嗽：多喝热水；

    失眠：洗澡泡脚，热水是强效安神剂；

    烦躁：多喝水；心脏病：睡前一杯水

【花茶】

1.改善过敏肤质：茉莉+马鞭草+薄荷；

2.促进新陈代谢：玉蝴蝶+千日红+素馨花；

3.养胃美容：粉红玫瑰+马鞭草+矢车菊+茉莉；

4.明目润肠：蔷薇果+杭白菊+干百合+月桂叶；

5.调节内分泌：玫瑰花+枸杞+杭白菊+金盏花+乌梅

楼主有点事情，再更哈，还有一大部分干料！

以上是来自一个工科男的问候！
编辑于 2018-01-11
陶晓皮
陶晓皮
寄几治疗寄几

做为一个长痘长到27岁的老姑娘，好想来答题！    
 讲真，如果大家真的认认真真做到以下几点，我保证你皮肤变的透亮白皙有光泽啊！！！！

1:远离不健康食品！大家可以看我的回答里另一个答案～饮食清淡对容易长痘痘的人来说太重要了！少吃肉少吃肉！多吃蔬菜多吃蔬菜！水果别吃芒果之类容易上火的东西！海鲜除了鱼！什么螃蟹虾都先给戒了吧！什么油炸之类的就别碰了！

 2:适当运动！这是我最近才真的切身体会！以前太懒，都不愿意动！最近被公司逼着参加一个徒步比赛，相当于半马！我就被拉着训练啊！跑步都是10公里打底，晚上下了班之后去，被人追着赶啊！虽然累的要死，第二天全身酸痛！但是我惊奇的发现！皮肤变透亮了～不相信我的话你去试试回来就知道了！

3:长痘痘容易出油，所以护肤洗脸就很重要！化妆的妹子晚上回家花10分钟老老实实的卸妆，卸干净了！我用的是fancl系列的产品！那个洗面粉用打泡网打泡沫简直不要洗的太干净哦！我每次都是遇上海淘打折的时候买许多囤着！我上次朋友去日本让带了大半箱的水乳什么的回来！反正这个牌子给我的感受是真的很温和，比较适合油性皮肤的！

4:还是那句话，早睡早起身体好啊同志们！不要拿脸去熬夜啊！皮肤糟糕的时候更要好好生活才对！ 

还想说，我最近发现一个东西还蛮好用！是救急用的那种，起了大颗的豆豆，就擦这个，第二天不会红肿，会消退一点下去的！
回答完毕，到时候想到什么漏了就再说吧！早睡早起哟！
发布于 2017-04-09
八毛酱
八毛酱
饮冰十年，难凉血热

长文预警，多图预警
关于辣个不能吃奶制品，好多人都问我为什么。我是看到微博上好多博主都讲到这一点，但是我自己其实也不知道为什么=￣ω￣=。反正平时在学校里也没有卖新鲜牛奶的，基本上用豆浆代替牛奶了。本身也不喜欢喝牛奶啦。
第一次回答居然得到了三十几个赞！好激动！知乎人民好热情！mua爱你们！谢谢前辈们的鼓励！！
==============================
更新:)
好久没来。要高三了最近超忙
我是来安利的

理肤泉的k乳！!！这个太神奇。第一天晚上抹了之后，早上起来，我都要哭了。额头上居然……辣么光滑！！我平时那种小小的粉刺很多，居然，消失一大片。酷！

用一个理肤泉大哥大防晒。不算油，轻微泛白，会搓泥。会考虑回购
  还有契尔氏的白泥清洁面膜。简直酷炫，黑头全出来了QAQ好感动。无限回购
  最近每天晚上都下楼跑步，大概每天都跑四十几分钟吧。跑到脸上头上全是汗，感觉皮肤都变得通透起来了!一定要尝试一下运动排汗哦!!!
  夏天来了，多喝点绿豆汤，降火的。（但也不要喝太多，毕竟寒性的东西） 还有冰的东西别吃啊别吃啊别吃啊 前几天跟好盆友出去吃了一个麦当劳的甜筒现在还后悔，鼻子上长了一颗巨大的痘（第二个半价真是难以抗拒）


  谢谢大家都赞和喜欢！！！超感动。祝大家能有一个开心的夏天mua

高三前的小长假已经放完啦，下午就要回学校了。桑心

……………………………………………………………………
我十七岁。情况跟题主差不多啦。初一长痘痘，到现在还有，不过有些好转，我深知护肤这种事不是一天两天能好的。不过题主别灰心，一起加油喽。 我现在在做的： 
1.每天吃水果（苹果啊什么啊都行喜欢就好，但是西瓜这种含糖量太高的不要吃会长痘）
 2.忌口！！辣的别吃，甜的别吃，油炸别吃，奶制品少吃！！拜托为了你的脸着想！忍不住的时候想想自己的脸啊都这样了还吃。想要变好真的要自制力。这个真的很重要啊，真的管住自己的嘴比什么超贵的护肤品都有用。周围的人告诉你没事啦尽管吃你看我都不会长痘的时候，请白他一眼，别人肤质跟我的不一样好吗。
 3.保持脸部干净。就是洗脸洗干净，洗面奶确定要冲干净，多冲几遍啊，尽量保证无残留。还有手机，眼镜，被单，枕套保持干净！推荐小林护镜宝，可以用来擦眼镜和手机屏。
 4.运动。这点你做的很好了啦，保持！每次回家有空就去看郑多燕阿姨，减肥排毒！ 
5.泡脚！！俗话说得好 天天泡脚，养生法宝！泡了脚睡得香，最重要的是，坚持泡脚有控！油！功能啊！
 6.多喝水！老生常谈了！北京应该很干吧，所以要多喝水，然后买个加湿器尽量保持生活环境湿润。Bruno的加湿器挺可爱的 最近长草了 
7.早睡早起！！！讲到这点我就要咆哮了啊！有些人凌晨一点还在刷微博，但是皮肤超好啊！为什么？！因为人家基因好啊！像我们这样长痘痘的，自觉一点早睡早起！！不要羡慕人家熬夜还有好皮肤，二十年之后，那群熬夜的人还能有好皮肤嘛！?现在就乖乖地早睡早起！ 关于生活习惯的暂时只想到这么多，以后想到了补充。
8.好心情！！长痘痘我郁闷了很久，都怀疑自己是不是抑郁症。我本身就是个很玻璃心的人，有段时间痘痘严重都不想出来见人。但是后来发现痘痘真的在自己眼里很严重，其他人真的都不！在！意！后来我渐渐心情好起来之后真的皮肤好了一些，至少我妈说有看出来了挺明显的
9.前段时间有吃善存的维生素。就是那个一大瓶的。反正各种维生素和微量元素都有啦。听说对皮肤好，吃了一段时间吃光了忘记去买了。没多大感觉，不过一直坚持的话应该有感觉的吧。

总之啦，想要皮肤好就要注重健康啊！关注自己的身体！
 **********分割线***********
关于护肤品，感觉这个年龄不用太多啊。我的步骤一般是洁面-补水-保湿 
洁面的话就是洗面奶喽。我冬天用的是丝塔芙的洗面奶。感觉挺温和的，就是清洁力感觉不够强，冬天用可以，夏天不可以。每周敷两次清洁面膜，推荐innsfree！！火山泥面膜！！白菜价超大碗！ 

补水的话，用的是muji的水，便宜大碗，效果还行。平时还有雅漾的喷雾。还有每天都会做水膜，买了依云的喷雾，打湿面膜纸敷个五分钟左右，不要太久。

 面霜是丝塔芙配套的那个霜。不推荐哦，有点鸡肋。现在一大瓶没用完，一边当身体乳。 护肤品大概就是这些了。
哦平时我有个坏喜欢就是不涂防晒霜因为油。现在知道悔改了QAQ,所以长草花王的有款防晒霜(一下子想不起来叫什么名字了) 
妹子加油(^ω^)护肤真的不是一天两天的事，需要坚持下来。我长痘痘四年了。真的每年过年见亲戚，平时见小学同学都是一种折磨啊，每次看到别人惊讶的表情，喔脸怎么这样了，皮肤怎么了啊，真的很伤心。伤心之余也反思了很久，是自己不健康的生活作息造成的。现在我基本上是戒掉了所以零食。皮肤也好了很多，但是还是不好。我知道我们这个年龄皮肤不好是多么悲催的事，看着同龄的女孩子都漂漂亮亮的，自己却是丑小鸭一样。但是现在开始努力也来得及！！只要坚持下去，总会变好的！不知不觉写了这么多，这些仅仅是我自己的想法，题主和所以被皮肤问题困扰的妹子加油。知乎第一答献给这个问题了。手机码字不容易，赏个赞啊
编辑于 2015-07-12
皇后娘娘
皇后娘娘
顾问 自由创业者

犹豫好久，怕被人说是广告贴
先发一张我的皮肤，时间是一周前，卸妆油加洁面皂之后，完全的素颜

上面这一张是今年夏天拍的，没有美颜，就是苹果的相机里一个复古风的风格自拍的
年龄30。我22岁眼角开始有皱纹，很深，微笑也能看出来，可惜手机换了好多次，没有当时的照片（当时也很少拍）我给大家描述一下吧，我是干性皮肤，当时除了眼纹，黑眼圈，皮肤暗黄，起干皮，主要肤质不细腻。现在没有这些问题，眼纹有点，不大笑看不出来。下面分享一下我挽救皮肤的过程。
这是我那时候买的，蒸脸器和导入仪，效果真的有，有兴趣的可以某只猫上详细看看，蒸脸的时候放一滴精油，去年微商好多蒸脸器，大家似乎觉的是神器一般，我在2010年就扒出了露华浓的，露华浓的可以治鼻炎，个人认为很好，而且品牌硬，我的现在还在用。导入仪也是。
下面有广告嫌疑了，不喜欢的美女，可以关了……
首先说一下我的消费习惯，我毕业自己创业，每月收入1w多，个人生活用品基本都是进口店的，衣服也不是随随便便的质量（毫无任何歧视意思），几十块一百多的衣服基本不存在我的衣柜，有点像男性消费，买个好的，穿很多年，有件毛衣穿了9年，质量和款式都没有落伍，还在穿。
但我的护肤品特别平价
一直用膜法世家，2010年到现在，感兴趣的也可以搜搜，各种面膜，护肤套装，纯天然的，我换着用，面膜种类多，分的细，针对性特别强，而且可以温和去角质，不像专门去角质产品给皮肤带来伤害。

下面是我保持皮肤的护肤习惯
1，一周最少三次面膜，如果皮肤特别差刚开始可以连续一周每天两次做，有人说这样一周相当于做了一次光子嫩肤，没有那么夸张，但皮肤真的会变好，前提是找信得过的品牌，不要买三无。
2，卸妆，这个很重要，有些干性皮肤用化妆品时间长也会发现脸上有毛孔，就是长期卸妆不干净导致
3，不必要的时候尽量不化妆，我以前bb霜都不用，现在用，但彩妆除了口红偶尔用（例假期间），其他都不用
4，良好的睡眠！！！这可不仅是为了皮肤，对整个身体器官都很重要，不熬夜，不抽烟不喝酒，晚上不好好睡觉，容易给皮肤造成封闭性粉刺，记得有个文章说过身体器官晚上排毒的时间，是有一定关系的，有很多朋友闭合性粉刺很多，分析到是熬夜喝酒的原因，可是就是改不了，皮肤护理不是简单抹点东西就行了，生活习惯真的很重要
5，少在外面吃饭，远离垃圾食品和地沟油对身体和皮肤的伤害，食品对体内任何器官的伤害都能最后体现在脸上。就比如有的人吃辣椒会冒痘痘，长期吃各种不健康的东西，皮肤问题就会开始多样化了。
6，不要一味追求白，皮肤只要不干不油，看着就很好看很健康，怎么鉴别你皮肤还有没有可变白的空间，女性找一块身上没有晒过的皮肤（胸，屁股等隐秘地方）如果脸上皮肤已经和这些地方肤色相近，那就不用再追求白了，激素产品白的不自然的原因就是脱离了肤色。
7，好心情，这个原因多说无用，原理还是肝脏的排毒，不相信的妹子可以试试
8，运动出汗，出汗，一定要出汗一天可能没感觉，坚持一周你自己都觉得不一样
9，多吃水果蔬菜，我已经好几年没有喝过有色饮料了，都是自己在家榨新鲜果汁，这两年也一直在喝德国铁元，一种维生素补充剂，防贫血补充维生素，改善睡眠
补充一条，护肤品最好用整套的，因为产品生产工艺以及成分的不同，不同品牌化妆品之间可能会有不同的化学反应，容易皮肤过敏或者产生不了效果，相同系列化妆品的水，精华，乳液，日霜走向成分是互相促进的，所以效果更快
另外有朋友会代购欧洲，美洲化妆品，不建议大家使用，肤质不同，消费者追求效果的不同都会导致你花大价钱却达不到想要的效果，护肤品可以用日韩的，彩妆可以适当用欧美的。
还有一些我暂时想不起来，可以后续补充
好几条都跟护肤品无关，但护肤品真没必要买最贵的，护肤的因素太多了，以上几条不仅可以护肤还可以养成健康的生活习惯
最后教大家分辨皮肤干油的方法
洗完脸找个光线好的地方，看看脸上的毛孔形状，如果是明显的圆形，那就是油性皮肤，那护肤就从控油开始，在补水，如果是扁平像一条线的那就是干性皮肤，那就以补水为主，如果扁平，但明显有一边往下耷拉，那就注意了，皮肤开始衰老了，抗衰为主，多补水
最后，皮肤问题很多样，一定对症下药才能保持好皮肤，我所了解的护肤常识未必对，也未必适合每一个妹子，不过有兴趣的我们可以交流
编辑于 2015-11-05
Maulina
Maulina
好好学习 好好减肥
运动出汗，早睡早起，忌吃油腻，有个健康的生活规律，还有洁面要仔细，多多补水保湿，绝对会把皮肤弄好。
发布于 2015-02-22
弱水之名
弱水之名
爱护肤/爱生活/爱旅游/爱摄影

回答这个问题之前我们先弄明白第一件事：什么才叫好皮肤？ 严格一点的话，个人觉得女生拥有一个 好皮肤的5个要素，缺一不可 ！

1 、婴儿般的皮肤靠的就是“丰满”

细胞保持丰满，就有充足的水分和良好的弹性，皮肤就会像一个新鲜的苹果或水蜜桃，呈现水润亮泽的完美状态。我们之所以说婴儿的皮肤是最好的，就是因为它的细胞处于饱满通透、排列紧密的最原始状态。

2 、表皮层的数亿细胞决定肌肤青春

大家都知道皮肤由表皮层和真皮层组成，表皮层虽然只有一张A4纸那么薄，却分布着数亿个皮肤细胞，这些细胞的状态才直接决定了皮肤的好坏，而真皮层主要起到的是弹性支撑作用。

3 、细胞丰满从“水”开始

皮肤细胞主要由水构成，而且还生活在水环境中。健康的皮肤细胞，细胞间质均匀水润，整个细胞有序地游离于透明质酸中，因此，水是让细胞丰满起来的最基本要素。

4 、护肤就是护理细胞

我们通常所说的皮肤护理，说到底就是护理皮肤细胞，无论是清洁、去角质、补水还是补充各种营养，如果没有作用到细胞就等于做无用功，因此护肤的原始目的和终极目标就是让皮肤的细胞更饱满、健康，而且运作得更好。现在有很多品牌的产品都直接瞄准细胞说事儿，更多地强调通过调理细胞来改善皮肤的外在状况。

=========================================

如何让糟糕皮肤彻底变成好皮肤？

虽然知道了平时的护肤功课都是在护理细胞，但要让细胞真正丰满起来，必须掌握几个秘诀，才能让皮肤在干燥寒冷的冬季也能轻松晋升到水润、光泽、紧致、细致、弹性好的标准。另外吃什么对皮肤好是很多人关心的问题，春天吃什么对皮肤好专家提醒：皮肤干燥大致原因一是天气干燥，二是洗澡水过热，三是皮肤油脂分泌过少。春天吃什么对皮肤好，主要是平时不吃辛辣食物，多吃水果蔬菜，补充优质蛋白质。多喝水。  

还有补充一点就是了解清楚你自己的肤质情况哦！ 一切不以皮肤状况、年龄和预算为前提的护肤都是耍流氓，连自己肤质类型都没搞清楚，还谈什么护肤？想要对抗岁月问题和各种肌肤难题，一定不能忽视平日里最基础的护肤步骤，如果不了解自己肤质类型该如何正确护理可以参考：腾讯专业在线皮肤测试调查，精准分析皮肤问题，获取正确护理方案，任何肌肤问题必须要先打好底子，而每日的基础护理在这时显得尤为重要。 

1 、让细胞喝饱水 表皮供水不间断

秘密武器：化妆棉

重点：提升水润度

皮肤在干燥的冬季仍能水水润润，关键是给皮肤细胞补水，只有让细胞充满了水分，才能从皮肤基底层源源不断地向皮肤表面输送水分，真正提升皮肤的水润度。

用化妆棉把水分按入细胞：要真正让细胞喝到水，拍爽肤水时就一定要用化妆棉，因为皮肤细胞是被动吸收体，需要通过拍打、按压以及按摩的外力帮助，水分才能被细胞吸收，而化妆棉能暂时存储水分，轻轻按压皮肤并停留几秒，能将水分按入皮肤细胞中，如果做湿敷，停留时间更长，细胞就能喝饱水而更丰满，因此用化妆棉拍爽肤水后皮肤更有透明感。而在30岁以后，光靠爽肤水细胞已不能完全解渴，敷补水面膜是让皮肤细胞吸收更多水分的好方法，细胞水分充足，在保持皮肤水润度的同时，还能延缓肌肤老化。

2 洗出细胞透明感 肌肤光泽透出来

秘密武器：保湿洁面品

重点：提升光泽度

一个干瘪的红色气球，如果把它吹起来，红色就会变得很浅甚至透明，而且表面也会有光泽。同样，皮肤细胞如果饱满而透明，那么皮肤的通透感和光泽度自然会提升。

正确清洁让细胞饱满、透明：皮肤随着年龄的增加渐渐失去光泽，这与日常的清洁有很大的关系，不正确的清洁方式不仅夺取了细胞的水分，而且无法将附着在细胞内外的污垢清除干净，久而久之，细胞就变得干瘪而浑浊，皮肤越来越晦暗无光。

因此，尤其在冬季，无论你是什么类型的肌肤都要选择有保湿效果的洁面品，保证清洁时不会让细胞失水。另外建议按照皮肤污垢的类型区别使用洁面品，水性污垢和油性污垢要分别使用水性和油性两种洁面品。这样清洁完的细胞才是干净透明的，很多细胞堆积在一起，皮肤就会有光泽。

3、寻找细胞填充剂 改善松弛和皱纹

秘密武器：细胞成分替代品

重点：提升紧致度

一个新鲜苹果，表皮鲜亮、饱满，但放上几天就会逐渐干瘪、黯淡，出现皱巴巴的纹路，皮肤也是一样，如果细胞丰满度高，皮肤就能保持紧致状态。选对替代品填充细胞：随着年龄的增长，皮肤中的胶原蛋白和透明质酸逐渐流失，皮肤就会出现松弛和皱纹，因此，需要寻找替代品来填充细胞失去的这两种物质。能填充细胞间质的透明质酸已被广泛运用于各种保湿品中，胶原蛋白更是外抹加内服双管齐下，还有和皮肤细胞成分相近的G因子，能补充细胞流逝的能量。另外，由内而外补充细胞所需营养也很重要，要多吃含胶质的食物，比如猪蹄、银耳等。

4、缩小细胞间隙 让皮肤看起来更细

秘密武器：去角质产品

重点：提升细致度

细胞干瘪不饱满，毛孔就会主动扩大来填补细胞空隙，毛孔就会变大，因此只有扩大细胞体积，才能缩小细胞间隙，达到缩小毛孔，让皮肤更细、更光滑的目的。

辞旧迎新提高细胞亲密度：要提升皮肤的细致度，细胞必须维持一个健康的新陈代谢，否则细胞就会变得大小不一甚至产生棱角，加上毛孔中堆积过多死皮和油脂，皮肤就变得很粗糙。要主动去推动细胞代谢，定期给皮肤去角质不可少，把老化细胞清除干净才能给新生细胞“让位”，而新生细胞吸收水分和营养多而快，能让细胞间隙变小，皮肤也就细致很多。

5、给细胞做运动 增强细胞壁弹性

秘密武器：按摩产品

晋级重点：提升弹性度

除了让细胞内部丰盈饱满，细胞壁的弹性和支撑作用也是获得丰满细胞的关键所在，而且很大程度上影响着皮肤的弹性。

按摩帮助保持细胞弹性：给细胞做运动的最好方法是每天给细胞做按摩：配合按摩产品，以中指和无名指由内向外做打圈按摩，从下巴中央斜向上，打5个圈左右到达太阳穴，并轻轻按住太阳穴，重复三到四次，然后用手掌从下巴中央开始向上提至颧骨位置；最后用食指、中指和无名指在面部来回轻弹。这样能增强细胞壁的韧性，从而大大增强皮肤的弹性。

By the way 哪些生活习惯能让皮肤越变越好？

1、温水洗脸 

2、按时摘面膜 （ 做任何的面膜，都不要让面膜停留时间超过15分钟，因为面膜纸变干后，会从肌肤中吸收水分，同时还阻隔了空气中的日然湿润成分和皮肤接触，容易影响营养的吸收和油脂的正常分泌，而引起过敏现象。 ）

3、荤素搭配 

脂肪是保持健康皮肤不可缺少的营养，可保持皮肤滋润和弹性，因此，鱼油、鸡蛋和蔬菜中摄取的重要脂肪酸，对保持皮肤健康是非常重要的，所以，不要因为吃得太素，脂肪的摄入不足，而导致皮肤出现早衰的情况哦。 

4、注意睡眠 

晚上10点到早上5点，是皮肤修复的最佳时间，而睡眠中的修复才有效。如果入睡时间超过了子夜，即使是第二天起得再晚，睡得再长，也会对皮肤有所伤害。 

上面讲了怎么多， 最难做的四个字，早睡早起 ！

————待更新————2017.3.20————
编辑于 2017-03-20
艾琳酱
艾琳酱
化学狗准备变成化工狗
交个男朋友。
发布于 2017-04-10
额额
额额
##就个人而言，还是更注重内调，当然外敷也是必要的。 ##内调:1.早睡早起，想要皮肤好熬夜绝对 要禁止，早起一大杯水早餐苹果一个姨妈快来时每天早上会喝黄豆浆(调节体内激素，降低长痘概率) 2.每天都会切半个柠檬泡水，会根据身体状况可添加不同材料，比如觉得天气特别干就会在柠檬水的基础上加玉竹和麦冬，二者会为身体提供水分。上火了会加菊花，平常就加玫瑰。在这里强调一点一般人白天喝柠檬水并不会被晒黑，一天吃够132个柠檬才有可能会光过敏晒黑，但是如果柠檬水滴在皮肤上，接受了紫外线的照射，这种情况下是会被晒黑的. 3.每天都会喝银耳莲子汤，学校餐厅有卖，滋阴润肺，胶质食物对皮肤提供胶原蛋白，皮肤会嫩嫩的，每天吃15颗红枣。 4.不来姨妈的时候会喝黑芝麻和薏米粉，除湿的，宿舍比较潮。 5.一般不在饭点，饿的时候就吃水果，之前喜欢吃零食，但是会长痘就戒了，最多有时候会吃面包。 ##目前吃的方面就想到这么多，因为我吃的太多太杂以后想起来再补充。 ##对了，本人肤质是属于敏感混合型皮肤，超级爱过敏，心情不好也会过敏，天气太干也会过敏，之前因为过敏烂过脸，容易长痘，所以吃东西特别注意。太痛苦。以上内在护理会帮助我保持内部皮肤稳定以下外在护理在一定程度上保护皮肤。 1.早上洗脸秋冬是不用洗面奶的，天气本来就干燥所以尽量不去破坏皮肤自然行程的保护膜，只用清水洗脸，然后抹水跟精华，防晒(下雨阴天也不例外)，懒人霜(皮肤稳定的时候，秋冬天抹)和遮瑕(遮痘印或者痘痘，我一般姨妈快来的时候会下巴会长个痘)。秋冬天我是不用粉饼的，几乎不用定妆。 2.画个眉，夹睫毛，涂睫毛膏，我会戴美瞳，涂口红，我不化眼妆。整体淡妆。妆容大方就好。(每天睡觉前我会用ve涂睫毛跟嘴巴) 3.卸妆我喜欢用卸妆膏，我用芭妮兰粉瓶，真的跟温和干净，已经用了好多盒。 4.洗脸水晚上的话我会加牛奶兑温水，洗脸，周一二四五日六用丝塔芙，三，六用泊美。在这里说，其实丝塔芙是能洗干净的，只要你认真卸妆，认真清洁。泊美是洗完干净还不干。毕竟我是混合型皮肤还是需要有点泡沫的洗面奶。之前买过hz的洗 面奶，洗面奶可以拉丝，可以敷脸，就是小贵，398人民币，超级好用但是太贵了。 5.换季我面膜做的挺勤奋的，每两天就做补水保湿的。如果不做面膜，我就是水，马油霜(秋冬天)，荷荷巴油，卓尔诗婷牛油果眼霜。 本来想上传产品图片的但是太多了一直传不上π_π
发布于 2015-10-09
杨关关
杨关关
订阅号：杨关关（iamygg），相亲战略研究者及行动派

前面个人经验也有了，系统科普贴也有了，针对题主的问题描述，我还是想苦口婆心地提醒几点：

1.爆痘，大部分人长痘痘最大的原因不是因为肤质怎样怎样，而是内在，建议题主找到内因，可以去医院的皮肤科和内分泌科问个诊（先不要去美容机构），是因为内分泌引起的？激素引起的？器官功能不良引起的？还是皮肤本身的原因？然后普适性的抗痘方法自然就是多喝水多运动（为了加快新陈代谢），早睡早起身体好。北京的空气对皮肤的负能量很大，天气不好的时候记得出门戴口罩和涂隔离涂防晒。另外，不要乱用化妆品，不要乱用化妆品，不要乱用化妆品！重要事情说三遍，很多人的血泪史告诉你，不要拿自己的脸做实验田，造成的后果都是不可逆的。在国外买换妆品，柜员都要给你测试过皮肤敏感性才敢卖给你的，在国内就是一味我们的产品好好好、推销推销推销……所以建议想试某个新产品请去专柜往自己胳膊上脖子上多抹抹样品……

2.运动，每天坚持跑1公里也叫运动吗？？还跑累就走……很多人从家里到地铁站走走都不止1公里了好吗？？这可能每天基本的运动量都不够，还“一直有运动的习惯”，手动扶额，这样都能变瘦子的话，那些运动达人要哭了。可以看出题主是真的“比较懒”，建议每天跑步量增加200-500米，直到能坚持跑完5公里，跑的慢没关系，5公里跑1个小时也没关系，1个半小时也没关系，但是关键不能停下来走。等你能坚持跑完5公里了，你就会发现自己皮肤也好了，身材也好了(•ૢ⚈͒⌄⚈͒•ૢ)

3. 嗜辣和电子产品包围我就不说了，吃辣本身没什么，但是餐馆里重辣的菜往往伴随着重油……

最后 Cow牛乳石碱洁面是皂基洗面奶，敏感肌用真的好吗？

最后最后，放张图，免得有人嫌看字枯燥(￣▽￣)／
编辑于 2017-04-06
老寇
老寇
大陆法系律师执业证持有者，三观正，取向明。

不邀自来，纯粹就是说下我自己的心得，估计没人会赞我。
我是男的，不客气的说，原来长得还是比较清秀的，不过是油性皮肤，油和汗都很多，头发两天不洗就能看见油光的那种。不过男的貌似好多这样，我到现在也不怎么伺候脸，用洗面奶纯粹看心情，一瓶用一年得那种，应该好多男的跟我一样吧。活的糙，大家随便笑话。
大二之前，皮肤还是比较不错的，从来没有抹过护肤品，冬天偶尔抹点防寒的东西，真的是偶尔，好几天一次的那种。从大二开始长痘，不是一个两个的，是一片片的长，你方唱罢我登场，一个区域好了另一个区域又冒出来，可能跟那时候体内激素分泌有关。
那会也不像鲜肉们那么爱美，其实对外貌没啥感觉，但是长痘真的各种不得劲，痘长到一定程度，碰到挺疼的。
然后一年之后，痘都消了，再过半年，所有的痘印也都消除了，目前脸上没有任何留存。
我没啥秘方窍门，也不用各种水啊液啊轮番上，也没有张医生李医生的看。就是注意两条：
一、有耐心，痘是有生长周期的，到时候了自然就没了，包括痘印也会慢慢消除。请诸位看看，二十七岁以后的女孩子，痘没消的有几个？有痘印的都不多吧？这事得有耐心，劝各位妹子们别整天琢磨漂亮了丑了，男的没几个人会关注你脸上长了几个痘，你的男神更不会因为痘消了过来献殷勤。你不去关注它，把心思放正事上，不知不觉就找不着了。
二、别作。好好对待自己，规律生活。我针对痘采取的唯一方式就是好好洗脸，洗脸洗干净，发际线的泡沫都洗掉。其他的饮食习惯没变，作息习惯没变，照旧对着电脑，运动也不算多，主要是尊重痘痘的规律，搞好清洁，别各种东西往自己身上招呼，我的痘印什么都没抹，人体自然代谢掉的，不知道抹各种东西会不会弄巧成拙。
发布于 2015-10-06
请叫我锅儿君
请叫我锅儿君
但行好事，莫问前程

首先对于你每天跑步一公里的举动深感钦佩，跑步出汗能排除毛孔里的油脂垃圾，跑完步后用冷热水交替洗脸让你毛孔变小（亲测有效）.为了方便编辑就去网上找了一些皂片请谅解啦
lz不化妆的话卸妆就省略了首先说说洁面的话强力推荐芙丽芳丝氨基酸洁面


非常温和不刺激，洗完脸不会干，价格也适中炒鸡喜欢的一款绝对心头大爱
再者就是洗颜专科了


绝对的白菜，很便宜清洁效果也不错，洗完也不紧绷也很推荐啊
爽肤水推荐芙丽芳丝的深水

它主要的功能就是保湿，真的很保湿啊，很温和，植物成分不会对皮肤造成刺激，其他没什么感觉
还有就是品木宣言的菌菇水

这款爽肤它没有什么突出的功能，但它又什么功能都具备，水主要是调理你的皮肤到很好的状态，皮肤熬夜长痘统统靠他啦
润肤乳推荐无限极的护肤品牌维雅

这款润肤露非常滋润，很冷门的一款润肤乳，滋润度超高，干皮冬天用完全没问题，关键是很白菜啊
还有一款就是雅漾的舒缓面霜

这款面霜主要是舒缓保湿镇静皮肤，滋润度也还可以，雅漾主要针对名感肌肤

强生蜂蜜防皱霜

还是喜欢强生，很滋润，皮肤一整个冬天都不会起皮，很白菜，两瓶安然过冬

肌研极润面霜

肌研极润的滋润保湿能力自然不用多说，对皮肤一点也不会刺激
眼霜科颜氏牛油果眼霜

主要是保湿祛黑眼圈，很厚重却很好抹开，非常滋润，不会长脂肪粒，适合年轻一点的mm，话说眼霜有必要早点开始用以后就会看见与同龄人的差别了

好了就推荐这些了，第一次写这么多，还希望能对你有所帮助啦，么么
发布于 2015-02-22
一颗麦子
一颗麦子
公众号:一颗麦子

去闭口的话，我用的法国珍贵水，便宜大碗。

法国珍贵水！

包装很好看！

要坚持用两周以后才会初见成效！坚持！

刚开始我都要放弃了。。后来刚过了两周多
我室友突然发现我的皮肤变好了

闭口真的小了

我的脸比较结实，所以都是卸了妆洗了脸后稍微拍一点在脸上，然后涂水乳。

隔两天做一次湿敷，时间不超过十分钟吧…

化妆之前我是坚决不用这个东西的，只有洗脸过后才会用

这是我用过唯一有效果的去闭口的东西
而且真的便宜大碗！

我买了两瓶，一百六十多。一瓶375毫升，用了半个多月了，连100毫升都没用到。。。我用这个真的特别不省，嗷嗷的用，但是还是用的很慢

不过！敏感肌！慎重使用！

干皮！慎重使用！

这个最好不要单纯当作爽肤水来用，后续要涂其他的东西！

没用过菌菇水，貌似也是挺好用的。。

还有一点，这个珍贵水是有点刺鼻的，所以如果装进喷雾瓶子喷全脸我是很不赞同的。。很容易刺激鼻子然后打喷嚏，或者刺激眼睛。。
我还买了一瓶给我男朋友，他一直把这个水叫成轻松水来着。。他室友一直以为这个是饮料。。
编辑于 2017-11-11
匿名用户
匿名用户

麻痹…………早睡，多喝水

真心的……我也是sk2系列，神马各类有用的没用的祛痘系列，神马早起水膜睡前面霜系列堆过来的…………
可是……我是资深夜猫子，仍然逃脱不了痘痘的命运，严重的不行
这几天生病了，每天吃的清淡，喝水喝的多，更是早睡早起（十点睡五点醒）………我能说现在皮肤一颗痘痘也没有了吗？！！困扰了我十多年的痘痘啊！！！早知道这么容易我真的………至于砸了好几万吗我哭一会去………
对了，配合妈富隆调理一下自己的周期更好
发布于 2015-03-08
病猫怀里的闹钟
病猫怀里的闹钟
哼～我才不是流氓我是小兔叽(。・д・。)

。。。刚刚码了一堆突然不见了，心塞。。
一、洁面
清洁力度不能过大也不能过小，过大破坏了皮肤本身起保护作用的油脂层，反而使油脂分泌更旺，皮肤更糟。清洁力度过小则会造成清洁不到位，造成油脂堆积妆品残旧，痘痘自然蹭蹭长。敏感肌角质层薄，基本可以禁磨砂洁面了。。晨洁建议使用温和的含氨基酸的产品，晚上清洁力大一些但一！定！不！可！以！狠！命！揉！搓！露得清挺好的。

二、保养
外油内干最主要的是控油补水，先控油再补水，不然水分无法抵达真皮层，建议使用补水分子小的产品。不要使用霜而是乳液，因为霜的油份含量较多水分较少，所以适合干皮，而乳液是水分较多油份较少。还是那句话，先控油再补水！我认为刷酸很好，但是有的皮肤耐受有的不耐受，建议刷酸之前先在耳后测试有无过敏现象，如果没有，恭喜你，水杨酸会是你的真爱。
建议一周两到三次面膜，一个月一到两次去角质（去角质最好使用凝胶、嘟哩，适合敏感肌），一个月两次清洁面膜，做完后记得使用收敛功效的护肤品。

三、日常作息
最好控制在十一点以前睡觉，在十点半左右进行皮肤护理，熬夜是内分泌紊乱的最大凶手。如果内分泌失调，不仅会长痘还会使经期不规律(#ﾟДﾟ)

四、饮食
我是无辣不欢的女孩子～所以我不认为控制痘痘就一定要忌辣，倒是酒请少喝。爱吃辣没关系，一定要多喝水多运动，一般长痘痘的人都便秘。。所以一定要清宿便。

四、痘印
使用美白产品，如含vc、熊果苷的产品。这里主推熊果苷！！闻起来味道超棒的效果也很好，但是美白产品最好不要白天使用。还有就是日常要注意防晒，防晒后请记得卸妆（最好使用卸妆乳）。还可以吃一些葡萄籽（不要买三无）、薏仁粉效果也不错。
痘痘最喜欢的品牌还是理肤泉～
编辑于 2015-02-25
王世虎
王世虎
1
广州军美医疗整容门诊部 整形外科副主任医师

我是整形外科医生，也是业余健身爱好者，我想这话题我可以说几句。

其实我相信怎样让皮肤变得更好，怎么样保持年轻，提问的人自己应该都知道，到目前为止，有效的方法有两个：运动和医学美容。

保持良好的运动习惯可以让你比同龄人看着年轻5-10岁，我相信很多人都明白，知乎上也有很多人在健身和跑步话题下分享自己的经历，但是尽管成功的案例有那么多，但是大部分人还是做不到，原因大家自己也都知道。

然后说说各种化妆品。我说句实话，每天去健身房练半小时，或者出门跑半小时，这比任何昂贵的化妆品都有效。这道理也不用我来解释。无论厂家广告里怎样宣传其化妆品的神奇成分，受过基本教育的人其实都能明白，她自己皮肤一直在非常有效且高效地防止任何外来物质的渗透呢。想一想，如果人类的皮肤没有这种功能，人类皮肤像广告宣传中那样OPEN，那结果是什么样子？我一直都认为，其实女性也不会相信她的皮肤会“吸收”什么东西，不过是自欺欺人而已。

很多化妆品中有效的成分其实就是玻尿酸，但是外用的玻尿酸基本不会渗透到皮肤里面去，所以我记得微针还是水光针好像有这样的宣传：一次水光针（？）胜过4000次皮肤护理。
除了运动之外，真正能改善皮肤质量的是医学美容的手段。在此补充一下什么是好的皮肤，从我们整形外科医生的角度来看，好的皮肤应该具有干净白嫩、无斑无纹、水润光滑、紧致有弹性等特点。怎样获得这样的好皮肤？方法大概有这些：

    需要收紧皮肤，改善皮肤质地的，可以尝试光电治疗，如二氧化碳激光、彩光等；
    皮肤松弛，需要收紧皮下组织，可以考虑超声刀；
    皮肤黑等，想改善皮肤色泽，可以尝试强脉冲光治疗色素、色斑；
    想让皮肤水嫩，吹弹可破的，想改善皮肤光泽度和水润度的，可以考虑水光针。


我一直觉得各种护肤品的作用其实就和安慰剂差不多，当然我说这话你可能不信，毕竟我属于利益相关，但是我请你想一想，如果生活美容真的那么有效，哪还有医学美容存在的余地呢？医学美容一直都是奢侈效果，你觉得那些走进整形机构的女性是买不起好的化妆护肤品的人吗？

关于人的面部衰老的原因和治疗方法，请参考：想做美肤的微整形，求推荐？ - 王世虎的回答
编辑于 2016-04-01
丫头要做白瘦美
丫头要做白瘦美
减脂护肤小达人、资深剁手党

不同年龄段的肌肤状态各有其特点，根据不同的肌肤状态进行保养，才会达到更理想的效果。 

20岁左右时，清洁是最好的保养。油性皮肤，容易有青春痘等问题产生，应该彻底清除面部污垢、油脂，治疗暗疮，增加自信魅力。 

20至30岁时，要注意预防皱纹的产生，慎重选择适合自己肤质的保湿类护肤品并增加营养。 

30至40岁时，需要防止皮肤光泽暗淡。除了合理的清洁习惯和规律的生活外，还应有一整套的系统保养方法对抗衰老。 

40至50岁时，需要加强水分和营养的补充。 

50岁以后，皮肤胶质及弹性蛋白减少，皮肤细胞再生能力减退。应选择有效延缓皮肤衰老的产品，增强皮肤新陈代谢。 

保养皮肤的20种方法 
>■ 1 
>要睡觉的时候，拿小黄瓜切雹放置脸上过几分钟拿下来，一个月您的脸就会白嫩。 
> 
>■ 2 
>睡前用最便宜的化妆棉加上化妆水完全浸湿后，敷在脸上20分钟，每周3次，您的皮肤会有想不到的水亮清透喔！！ 
> 
>■ 3 
>每天起床喝2杯水，其中一杯加些盐巴，可以清肠胃。 
> 
>■ 4 
>出门前一定要擦隔离霜及防晒乳，回到家记得要马上卸妆。 
> 
>■ 5 
>先用温水再用冷水洗脸会让肌肤既干净且毛细孔会变小喔。 
> 
>■ 6 
>一定要多喝水不熬夜，少吃油炸类的东西，保持皮肤清洁。 
> 
>■ 7 
>每晚洗完脸后，将养乐多倒在化妆棉上，直接敷在两颊，甚至连额头、下巴也可顺便敷上，不但去斑兼美白，因每次用量大约只有六分之一瓶的养乐多。 
> 
>■ 8 
>晚上少喝水，白天多喝水，睡前敷水亮面膜；多吃水果，不喝酒不抽烟不熬夜，保证水亮。 
> 
>■ 9 
>首先用冷茶包敷眼五分钟，接着做一个类似瑜珈的动作，这个动作是先盘腿，再将手举高后往前趴下，保持这个姿势约十分钟。这个动作一开始不容易做到十分钟，要一段时间的练习，但是效果真的很好。 
> 
>■ 10 
>市售的纯水一瓶（600! cc），只要一周用纯水洗脸3～4次，并经常以化妆绵沾纯水敷面，脸脸自然而然的漂漂喔！！ 
> 
>■ 11 
>据医学报导，阳光中的紫外线，除了一般人所知的UVA及UVB外，还有所谓的UVC，平常有阳光出现的日子，UVC及UVB易造成晒伤，但可别以为阴天就不需防晒了，因为阴天时仍有UVA长波射线会对肌肤造成伤害，因此最好还是撑伞，才能防止老化的提早发生喔！ 
> 
>■ 12 
>使用意仁粉，加一小匙在大约1000cc的水中，当饮用水喝，不单只对皮肤好，连对减肥都有神奇的功效喔！这是利用意仁具有利尿的效果，可以减少浮肿，所以具有瘦身及瘦脸的功效，而且对美白肌肤也有很大的帮助。 
> 
>■ 13 
>泡温泉，泡温泉不仅可让肌肤粉润光滑，且还可消除疲劳。若有皮肤过敏者，泡有疗效的温泉还可改善哦！！ 
> 
>■ 14 
>酵母粉1大匙（超市均有售）加统一优格1╱2杯取适量涂抹于面膜纸上再贴于脸上5～10分钟即可，一周约2～3次美白效果会更好。与SK－II面膜具有相同效果又省钱喔！ 
> 
>■ 15 
>小偏方：就是黑砂糖＋蜂蜜＋一点点水；虽然有点麻烦，但能让肌肤水嫩水嫩喔！ 
> 
>■ 16 
>把优酪乳粉倒入鲜奶中（需密闭）时，冬天需要久一点，然后放入冰箱冷藏就可以用了，制作多一点可以用来喝，原本是用来减肥的啦！不过用来敷脸更棒，美白功效很好。不过要忍受一下优酪乳酸酸的味道喔！！ 
> 
>■ 17 
>用面粉蜂蜜及牛奶，以2：1：1的配方调匀，每周敷脸2次，每次15～20分钟，用温水洗净，将化妆绵沾湿化妆水轻拍脸蛋，此项秘方需加配上一项独门绝招～～每天洗澡前先将脸蛋清洁干净，然后将蜂蜜涂抹脸上，让洗澡时的蒸汽，将珍贵的蜂蜜蒸入毛细孔。 
> 
>■ 18 
>要拥有婴儿般的肌肤很简单： 
>A．饮食：拒绝任何辛辣，油炸食物。多吃蔬菜水果，多喝水。 
>B．睡眠：每天一定要11：00前上床睡觉。 
>C．运动每天早晚各运动一小时 
> 
>■ 19 
>只要觉得毛孔粗大时，可用以下几种不同的面膜来敷脸： 
>A．new skin的冰河泥加上敷面膏调匀后敷整晚睡觉效果超霹雳！ 
>B．蛋白直接抹匀在脸上待干冲洗即可。 
>C．用市售干燥的敷面纸泡在牛奶里沥干后敷在脸上有美白的功\\效。 
>D．绿豆粉加蛋白调匀后均匀涂在脸上。 
> 
>■ 20 
>在吃的方面，好吃又不会发胖的几种选择如下： 
>A．薏仁洗净加水不加糖煮1～2个小时待凉当开水喝可消肿及美白。 
>B．苟杞加红枣加桂圆煮开不加糖待凉当开水喝可使脸色红润眼睛有神ㄛ！ 
>C．多喝用排骨炖的各种汤品。

发布于 2016-11-06
飞羽他妈
飞羽他妈
蹉跎带娃
二十几岁我会说这个护肤品那个保养品。但是三十岁了，我要说光子嫩肤是正解。没试过就别哔哔，试了就知道护肤品都是玩儿啊。
发布于 2017-03-14
刹那
刹那
最近采购已回国~WX: sins01用生命在搬砖•̀.̫•́✧

知乎的广告评判体系真是让人无力吐槽，我只是为了避免自己采购拍摄和做功课而来的资料和图片别被心怀不轨的店家拿去借真品图卖假货用，从而才打上水印，何况水印还没留任何联系方式，这样都能被判为广告，我也是无语了，那就不打水印了，分享还是要做的，欢迎剽窃党来随便取用，摊手。

下面回归正文：
推荐2个产品，TAKAMI角质调理精华液和Obagi欧邦琪的维他命c精华液。需要声明的是，为了避免图被无良假代购拿去用（万一卖假货，带来的影响更大），文中的图片我打上了水印（只表明出处，不留联系方式），希望知友小伙伴不要介意 ：






TAKAMI角质调理精华液

価格 4,950円（税込）


质地是透明水状的液体，没有什么味道，流动性很强，上脸后瞬间会被吸收，不粘腻，没有负担感

用法也很简单，擦在毛孔粗大，容易长闭口粉刺或皮肤粗糙的地方，然后轻轻按摩吸收就可以了，清除对于黑头和闭口的状况能明显改善。原理是软化角质，深层清除肌肤中的污染，让新生的肌肤进入一个健康的代谢循环。



takami的脑残粉水谷雅子，笑

takami的日本顾客使用效果图，左边是使用前，右边是使用后。




有两位是比较严重的姑娘，效果都立竿见影。


照片是我拍摄于大阪高岛屋百货的TESTER药妆柜台 ：










OBAGI欧邦琪维他命c精华液

C5 10ml 3,240円（税込）

C10 12ml 4,320円（税込）

C10 26ml 7,560円（税込）

C20 15ml 8,640円（税込）

乐敦为最大限度地发挥维生素C的美白护肤效果，研发出高浓度、高渗透、超安定的Obagi系列精华营养液。

配合维生素C①和维生素E②，滋润角质层，解决毛孔粗大、肤色不均、皮肤粗糙等问题，全面提升肌肤透明感。

·不含防腐剂，不含油类成分，有柑橘系葡萄柚精华的味道

①：抗坏血酸（整肌保湿成分）

②：生育酚（保湿成分）

功效从C5依次到C20，数值越大功效越强。

仅祛痘消肿C5美白祛痘精华已经足够。

要淡痘印/均匀肤色的妹子建议试试C10美白淡斑精华。

最强效C20，提亮肤色、淡化斑点、去痘印和凹凸、皮肤不光滑统统适用。


OBAGI公司对客户使用感的调查，让使用者感受到最最明显的效果就是去小斑点、痘印、雀斑

第1位　小斑点,豆印,雀斑

第2位　皮肤粗糙

第3位　皮肤发黄和发红

第4位　暗疮,白头

第5位　黑头和粗大毛孔


微博上也有很多功课和推荐

Obagi这款被《MAQUIA》杂志评为14年美容液部门大赏。







这期封面还是绫濑遥哈哈
在日采购期间的拍摄 ：




先写这两款， 同类的优秀产品其实各大护肤品牌家都有， 以后有机会了再分享其他~

文中引用的部分使用心得若有版权问题，请和我联系，侵删。



看完觉得不错请点个赞支持一下！:-)

看完觉得不错请点个赞支持一下！:-)

看完觉得不错请点个赞支持一下！:-)

看完觉得不错请点个赞支持一下！:-)

相关回答：
有哪些靠谱的护肤品代购淘宝店铺？ - 知乎

怎样找到真日本代购？ - 知乎

日本的FANCL和POLA美白丸能吃吗？对人体有没有害处？ - 知乎

日本哪些化妆品护肤品特别好？ - 知乎
编辑于 2017-06-21
龙葵
龙葵
幻想症晚期，寡言性感

我总是留下一个又一个坑，
对没错是我，，，，，差不多一年又来答题，我也是，，，好吧话不多说，我最近比较闲了，我会努力答题的，微信号，我留在文章最后，有啥就问我，知无不言言无不尽。
让皮肤变好，真是妹纸一辈子的问题，一白遮百丑，其实也不尽然，只要皮肤自然健康，一切都是妥妥的。重点在下面，，，，，，，，，，，，，，，，
1，从食疗开始，这个我忘了原来说过没有，有条件的妹子，可以每天给自己熬粥，最近发现一个超好喝超有用的粥，红枣银耳，应该喝的还挺多的，熬起来也特别简单，这个可以增加皮肤胶原蛋白，现在夏天，熬好了放在冰箱，每天回来喝点又爽又护肤不要太爽哦。粥给你们建议几个简单的，木瓜银耳，补血养颜，有一点丰胸作用，这个看个人，燕麦红枣，安神补益健脾，蕙仁紫米粥，这个是美白的，我喝了一周有那么一点卵用吧，还是要坚持。具体做法可以百度。其他食疗不同的要用不同方法，但是少吃辣，多喝热水，记住啊是热水，冷水特别是冰水对女孩子真的不太好，不喜欢热水味道的可以在里面加蜂蜜，加柠檬片。
2下面是给你们安利面膜产品的，想要皮肤好，面膜少不了，但是不同肌肤不同问题，用的面膜也不一样，不是越贵越好，买面膜，避免淘宝，最好找代购或者去专柜。下面面膜是我自己亲测有效的
补水效果不错的，一叶子面膜，我觉得补水不错价格适中，打折的时候多屯了点，基本上隔一天用一次，味道也还行，以下的图是各种百度，
　蔷薇

嫩石榴

蔷薇
发布于 2016-07-20
漫步
漫步
设计
看了辣么说经验，我从一开始配合淘宝各种看，从一开始很想买个试试到后面越看越无感，这明明是各种名贵护肤品堆着皮肤才好的！（只是有些，不是全部！）
皮肤状态：客观来说，一般，不过我已经很知足了，去年的我，还一个月过敏一次 一次得要个3、4天，过敏的时候什么都不能用，皮肤又黑又红 脸颊发烫难受！
下面说说我的基本情况：上班族，工资3000，喜欢买衣服，所以留给我买护肤品的钱就不多了，平时也会跑跑步，不是为了别的，只为了洗澡不冷！好的，费话不多说，请看下面：
洗面奶：旁氏米粹 18元 （这个洗的真心好！干净不是很干）

水和乳：豆乳 价格屈成氏70-80元 （这个说实话不是很好也不坏，有个朋友说护肤品效果太好的话也会有副作用，只要用着不错就行！我觉得说得很对所以一直用这个！放心！）

霜：百雀灵 7元 （这个我觉得真心好用 润润的）

气垫bb：赫拉的21号色，价格：275元，（这个对我来说有点奢侈。这个是让同事在香港代的，很清薄，这个就不推荐了，这个因人而异）
面膜：森田药妆台湾版 价格60元 这个强烈推荐！！超好用！！同事的女朋友是医生也用，她给好的同事用了一片说太好用了！！太好用了！！

平时也会化妆用的是：
卡姿兰：眉笔、眼线膏、睫毛膏（这个眼线膏我个人有点晕，其它的都很好！）

口红就不推荐了，至今没遇到好的，
卸妆：相宜本草卸妆油 价格：69 还不错！一直都用这个！

补水喷雾：依云矿泉水 价格：69元，天天对着电脑，喷喷总会好点！
体乳：屈臣氏体乳 20几块钱吧，身上一到冬天特别干！有点雨林腿似的，这天我天天涂，效果很满意！！

用的都是很便宜的护肤品这都源于没钱！
编辑于 2015-10-30
西柚deer
西柚deer
健身读书热爱生活gogogo

6知乎上第一次做答 随便说咯 首先 我想说我是有资格回答这个问题的 本人大二女 痘痘肌 关于额头总是长痘这个梗我也就不说了 在医院花了300多没弄好我会说？这学期开学后我就好了很多了 下面说原因 1 有痘痘首先还是需要一些西药配合治疗 维生素b6加夫西地酸软膏 我吃了这个就好些了 不贵的 不是做广告 2 饮食方面 清淡为主 油炸的马上扔掉！！！爆痘良品 ！！！！多吃青菜呀亲！！！ 3 运动！！！健身！！别把这些挂嘴边啊！去做啊！我现在是每天晚上8点半开始做郑多燕的小红帽健身操！外加十分钟甩油操！真的会瘦！！记得要坚持！如果你腻了做操就可以换换口味 去操场跑操 起码6圈大概30分钟吧 还可以钓凯子哈哈 4 关于护肤 ！首先 不要太相信网络上很多人推得产品 尽管里面也可能有好的 但是你得皮肤不一定合适啊！ 去专卖店或者屈臣氏 自己试 适合你的肤质的 长痘痘的话尽量清爽的为主！ 还有！！！韩妆日妆什么的！！有的确实好用！但是！！！你一定要有一个你无比相信的代购童鞋哦！！不然。。。 有痘痘爱生油的基础护肤就可以了 水＋乳＋精华＋面膜（面膜一周两次吧） 永远要记住 内调更重要 饮食 健身比护肤要重要一些 你的健康！ 水早上拍两遍 晚上拍3遍 乳你自己看着办 晚上精华一定要擦的 精华是神器好么 一个月正常的话应该是一个月一瓶水！
5  洗发水  我是油性发质  原先就是那种一天一洗！！不然会油啊  当年的痛苦   真特么！突然想到一句话  你都不值得我洗头哈哈哈  最近人家遇到了真爱 巴黎欧莱雅的洗发水  真的超好用  可以撑到两天了！想哭555当然  不怎么出油和洗发水有关系外 和我每天做有氧运动出汗肯定是有关系了   所以一定要内调啊   反正我室友说我气色好多了 皮肤也好太多 没什么痘痘了 白里透红啊哈哈
妈蛋！我也7点半了  我要准备一下去跑步咯    o
打字好累  随意打的  嘻嘻  拜拜么么

上面这张是我想成为的女人    好害羞O__O"…第一次在知乎做答  捂脸ing  希望能够帮到你 不懂可以问我哈
发布于 2015-03-23
叶冬天
叶冬天
我二十岁~我家乡海拔比较高紫外线强，以前也是又黑 毛孔粗 痘痘~ 现在不说皮肤可以说好了很多，几乎不长痘，白了很多…以下方法个人试用快速有效~希望对lz有用~--------------------------- 日常： 1.早晨2杯水:淡盐水，蜂蜜水，矿泉水都可以 2.日常饮食尽量多深色蔬菜。我也是很喜欢吃辣，吃辣和油腻后多吃蔬菜水果。梨能很好的排毒。 3.保持好的睡眠，早睡早起。 4.保持手机，衣着，头发的清洁。千万不要用没有清洗过的手摸脸。 5.晚上用过电脑一定要再次洗脸，静电会让灰尘附着在脸上，痘痘不断不断再次出现。--------------------------------------------------- 护肤： 1.注重补水:水+乳+面霜 ，要相信护肤越仔细皮肤也会越细。个人用的skin food的套装，比较清淡，比较白菜可以去专柜选适合自己的。lz的肤质不要用太多去油的，补水补水补水，水够了自然就不油了。
2.注重护肤步骤: 早上温水洗脸，皮肤不太脏时尽量少用洗面奶，之后水，乳 ，面霜，防晒霜，隔离等。晚上，卸妆，洗面奶，面膜（隔两三天一张，之间可用睡眠面膜或泥质清洁面膜，有时间可做下水膜，推荐依云白菜效果好）。面膜清洗之后依旧，水，乳，睡眠面膜或面霜。水拍五次，拍一次吸收了之后继续。五次以后你会发现你的皮肤不一样了。
3.防晒 :无论室内室外，晴天阴天，一定要搽防晒霜一定啊！！！！！ 不仅防晒还可以减少点灰尘雾霾导致的痘痘。
4.清洁:回家后及时卸妆，不管化妆没，涂了防
晒一定要卸干净，不然会长痘痘!! 卸妆油一定要选不含矿油的，会长闭口粉笔……DHC的卸妆油很不错~
3痘痘:补水之后你会发现痘痘会好一些了，平时红肿痘痘搽芦荟胶，也可以敷全脸，一定不要乱用祛痘产品有依赖还会反复。调整生活规律，痘痘真的会好很多。
其他再想想~大家喜欢再继续啦
发布于 2015-03-03
月城
月城
想做一个梦，一个可以和你好好道别的梦！

建议先把痘痘去掉，要不涂什么都没什么大用，没准还会导致痘痘疯狂的增长，针对痘痘，你应该先一瓶匈牙利纯植物的ilcsi的七草面膜，去祛痘，对于开口，闭口，痘印的效果非常好，是有痘痘的女生，首选的面膜。
编辑于 2017-07-17
cherryfrancegogogo
cherryfrancegogogo

咱先来个对比图～找不到最最最烂脸时期 因为换了n个手机了。
呃呃呃 将近两年护肤历程 稍有成效 给大家分享一下～ 非专业人士 轻拍～

这不是最烂时期 但是还能看出来吧 我这当时还是已经用了bb霜了 脸颊两侧 下巴 哎 那红印遮都遮不住！那时候都不想粗门！感觉很烦躁  

现在大概是这样！嗯 虽然还没到达完美状态 但是真的好多了 可以素颜出门鸟～～
折腾时间较长 祛痘 去痘印真的太费时间 用过杂七杂八n多产品。最后也算是总结出一点经验。

我坐标法国 所用产品基本全是天然有机系列 对大牌护肤品不是特别感兴趣～相信药妆 相信天然有机 嘻嘻～
要说的实在太多 卸妆 清洁 保湿 每一步都重要 。得慢慢来 先问下大家感兴趣么？？？？方法以及产品 我慢慢更～
ps 本人混油皮一枚～

开始写～～～～～～～～～～～～～～
我的心得限于混油性皮肤哦～
脸部保养除了护肤品外 当然最重要的就是生活习惯。早睡 白天多喝水等等。这些我就不赘述了。
我的护肤步骤分为 卸妆 清洁 保湿。
卸妆 嗯非常非常重要的一步！！！很多妹子开始长痘 原因是清洁不当 堵塞了毛孔。好吧 那用什么卸妆呢？嗯 我不用卸妆油 我用基础植物油！绝对神物～种类很多 如何选择呢？
我用过的：
椰子油 质感清薄 还伴有椰子香味-油性皮肤
荷荷巴油 好油 液体黄金-油性肌
甜杏仁油 去黑头好手！-干性肌适用

使用方法：手清洁后 干手干脸 将适量油摊手心 在脸上按摩 大概一两分钟就oki。然后用纸巾将脸上的浮油擦掉。（擦掉后 最好在来个二次清洁 用花水沾湿化妆棉 擦拭脸部）之后用温水洗脸部 上洁面～痘肌的话 早上洁面最好选用温和系 晚上卸妆可选用清洁力强点的。
自从用上了基础油 我就再也没用过任何其他卸妆产品！卸的超级干净 而且同时滋润皮肤～一举两得
关于基础油我用的牌子 嗯florihana 法国有机芳疗品牌 安全 可信任～

先写到这，会继续更～
编辑于 2015-10-31
匿名用户
匿名用户

20岁。同外油内干，现在你的皮肤最需要的是补水

水水：没有找到真爱，一直是巨型一号的丝瓜水原液。因为脸太油，稍微用营养高的水就粘粘的。

喷雾：大葡萄喷雾，雅漾喷雾，理肤泉喷雾。一直用大葡萄，最近试了下理肤泉，还是喜欢大葡萄。

洗面奶：森田药妆的玻尿酸洗面奶

乳液：森田药妆玻尿酸乳液

面霜：AHA果酸面霜，祛痘印兼美白，太刺激敏感皮不能用。雅漾日霜，用稍微有点油，但是找不到好的……

眼霜：the body shop接骨木花眼胶。你年龄小用这个正好

面膜：首推！森田药妆的玻尿酸面膜，平价面膜里最好的补水面膜。好用到哭。
既然皮肤有那么多问题那肯定有黑头，hanaka黑白冻膜，黑膜清洁白膜补水，但是我没用过……
本人用的是Eminence南瓜青柠益生菌木莓

防晒：资生堂安耐小金瓶/sofina jenne防晒   两只差不多，只是后者的瓶子比安耐低调一点……

痘痘可以用理肤泉的祛痘系列…因为很少长痘所以我也没试过- -但是朋友用看着挺好
都是最基础的护肤品，不敢说一定有用，毕竟每个人肤质都不同，上面的用了应该不会出太大的问题
，但是还是要注意，就像科颜氏的高保湿和金盏花，周围的油皮朋友用就很好，我就冒痘，闭口
发布于 2015-02-22
马克兔温
马克兔温
推荐是我，买不买在你，请不要恶言相向或者恶意诋毁，谢谢。

    变美从正确洗脸开始
    根据调查，7成多女人都没有选对适合自己的洁面产品，而且洗脸方法也存在着不同程度的误区。及时调整洗脸方式，否则错误护理会日日侵害肌肤，让你擦什么保养品都不见效。

    常笑可以自动调节内分泌
    　　每天摆“苦瓜脸”会使皮肤细胞缺乏营养，脸上的皮肤干枯无华，出现皱纹，同时还会加深面部的“愁纹”。笑一笑，十年少。情绪稳定对内分泌平衡十分重要，拥有一颗温和宽容心的女人是美丽的，这不只是一种心理上的印象。

    避免因为化妆品而伤脸
    　　少女孩爱美心切，通常都是把自己的脸当成护肤品、化妆品的“试验田”，就此，痘痘、红血丝、枯黄气色都由此而生。只有合理选择化妆品，才不会变成自己给自己挖陷阱。

    控油让脸面更干净
    　　油乎乎的脸看起来就很脏，无论肤色如何，都是一脸邋遢样。其实神秘的“油脂腺”通俗说来就像一根水管。大家要像对自家不断冒水的龙头一样，进行一次有效的管道维护。
    试试看跨牌混用护肤品
    　　有许多人对于护肤品混用有误解，认为从洗面到晚霜全用一个牌子才可以。其实，混用护肤品基本上不会对皮肤造成不良影响，反而有利于补充皮肤所需的营养。由于各种护肤品品牌都有自己的强项，在护肤营养配方上也有独到之处，因此，混用不同品牌的护肤品能在营养上形成互补。
    嚼口香糖就可以美容
    　　经美国洛杉矶面部神经医学中心主任福克斯博士临床试验证实，每天咀嚼口香糖15—20分钟的人，几个星期后面部皱纹开始减少，面色也变得更加红润。在日常生活中，咀嚼甘蔗、面筋等，也会起到同样的作用。

编辑于 2015-03-13
竹子君
竹子君
一往无前的拼搏
我26岁，之前也是混合，T区油。用着倩碧三部曲调理半年之后脸上水油平衡了，再用契尔氏的黄瓜水二个月，目前皮肤状态不错。现在用思亲肤的水和佰草集的霜。各种感觉良好
发布于 2015-03-10
祎洛馫
祎洛馫
其实还是不要乱用的好，你看好的产品不一定适用自己，用的多反而增加皮肤的负担。对皮肤不好。有好的生活习惯，愉悦的心情，不要抽烟酗酒。每天做做有氧运动，瑜伽。少食辛辣刺激食物，多食水果蔬菜。每早晚洁面，之后使用水，乳液或者霜。可以一周做2-3次的面膜。这是按照自己的肤质来护理的。干性肌肤用补水，保湿的产品，质地可以厚点，但油性，敏感型肌肤就要选择质地轻薄，清爽型的，不能盲目的只要别人说好就用。有什么问题可以私聊我。
发布于 2015-02-26
Min Zhang
Min Zhang
金融生 留学党 护肤狗

2015.3.10 原答案

1.先把洗面奶换掉。换氨基酸洗面奶，避免皂基，常见的旁氏米粹，肌研白润，到freeplus。倩碧液体皂也可以。 
2.敏感肌你用什么雪肌精啊喂！！尽量避免含酒精的产品，雪肌精的酒精含量我就不说了你也能闻出来。雅漾和理肤泉有的产品针对敏感皮，可以去专柜问问有什么适合的水乳和精华。
3.一定要注意防晒，少吃辣椒，少吃糖，早点睡觉，作息时间规规律些。反正我是一吃辣椒就爆痘，绝对不会吃辣椒的。
4.不要相信什么三无产品，什么马油啦俏十岁啦，祛斑淡化痘印一抹黑眼圈全部都没有了这种全部都是假的，面膜少敷，大部分面膜容易刺激皮肤。
5.多补充知识，推荐宝拉的书，买来看看，可以关注一些果壳和微博达人的动态，护肤也是一门科学啊。

2015.11.08更新

6.题主如果去痘印的话，有钱的话可以激光去痘印，记得挑靠谱的机构。不要相信什么马油啊什么的去痘印，除了医疗美容，痘印是无法去除的。
7.另外看题主入了菌菇水，我不建议，因为也是含酒精，容易刺激。不过我不是酒精黑，看皮肤敏感程度了。
8.建议题主可以入精华和眼霜了，这个年龄也该用精华和眼霜了。
题主加油！
编辑于 2015-11-08
白小鹿
白小鹿
公众号/微博：时尚主编白小鹿

干了六年美容编辑，经常被很多女生问美容相关的问题：

脸上有斑怎么办？

毛孔粗大怎么办？

如何去皱？

如何祛痘？

其实总结起来就一句话：我的皮肤糟透了，如何让皮肤变好？

今天就顺便来谈一谈皮肤保养中最重要的一个概念：分肤质保养。分享一个个人观点：一切不谈肤质的护肤心得分享都是耍流氓。

看到这里也许你会不屑：分肤质保养不就是：油性皮肤控油，干性皮肤保湿。如果你是这么认为的，我只能大笑三声：难怪你还在看我的文章。

见过太多人在护肤上有很多简单粗暴的误区，作为一名互联网时代的美容编辑，我没有把科学的护肤知识传播出去，港真，我经常有一种森森的挫败感。

在这里我只能粗浅地通过四种肤质保养告诉你如何改善肤质，实际上皮肤种类实在太多了，很多问题不及深谈，如果你想了解更多护肤知识，科学、理性美容，甚至直接想让我告诉你买什么护肤品好，欢迎加我的围信（zhubianxiaolu）向我提问。

本文会比较长，如果没时间看请直接滑到自己的皮肤类型即可。记住鹿姐倡导高效变美哦~

日常生活中，我们的皮肤通常被分为：油性肌肤、干性肌肤、中性肌肤、混合性肌肤这四大类，还会有一些敏感性肌肤，不过著名美容专家宝拉培刚认为每个人的肤质多少都有点敏感，不需要单独列出敏感性肤质。而痘性肤质通常被归类为油性肤质或混合性肤质。

各种肤质的特征：

中性肤质：皮肤没有出油或干燥的区域

油性肤质：整个脸部的皮肤都很油，完全没有干燥的区域

干性肤质：皮肤干燥紧绷，甚至有些脱皮，完全没有出油的区域

混合性肤质：T区部位出油，其他部位是中性或干性肤质

为什么要认清楚自己的肤质？

因为不同的肤质需要不同的成分，虽然有些成分每个人都需要，但需要不同的剂型，比如防晒剂，可制作成乳霜、乳液、喷雾等不同类型，不同类型适合不一样的肤质。

肤质会不会改变？

当然会改变，我们的皮肤随着季节、生活压力、护理方法等变化。例如一位油性肌肤的女性如果过度清洁，就会变成外油内干型的肤质。对问题肌肤进行调理，并根据肤质变化选择适合自己的化妆品就非常重要了。

下面就来说说各种肤质的保养建议

干性皮肤的保养建议：

干性皮肤通常有角质层薄、角质粗糙、易过敏起疹子等状况。

首先你需要明白的一点是，干性皮肤并不是指皮肤缺少水分，而是皮肤细胞间质受到损坏，导致水分流失。换句话说，就是皮肤没有防止水分流失或保持皮肤足够水分的能力。如果你不明白这一点，就无法从源头上阻止干性皮肤的产生~~

因为有些自身的因素导致干性皮肤，也有很多是人为的因素，比如使用太干或清洁力太强的护肤品，使皮肤外层崩解，破坏细胞间质。干性皮肤选用护肤品需要做到以下几点：

清洁：

首先选用温和的清洁和卸妆产品，尽量选择不含皂基且清洁力不太强的洁面品。每天可以用果酸类产品去一次角质。

保湿防晒：

白天使用含抗氧化物的防晒霜，晚上使用含抗氧化物的保湿霜（晚上可不使用防晒霜），产品越滋润，对干性皮肤越有帮助。比如一些含油脂的乳霜：矿物油、荷荷巴油、红花油、葵花油、月见草油、琉璃苣油、夏威夷核果油等。

喝水：

许多女生认为皮肤保养食补比擦护肤品重要，每天8杯水可以预防或改变干性皮肤吗？喝水的确对人体健康有帮助，但它无法摆脱干性皮肤。水分通常还没有达到皮肤层，就已经转化成尿液排出了，因此擦护肤品才是干性皮肤的最佳保养途径。

干性皮肤需要经常敷面膜吗？

敷保湿面膜对皮肤瞬时补水效果大有帮助，如果你需要化妆，妆前敷一片面膜会对上妆效果大有帮助。如果想要皮肤保水能力更好，敷脸后记得擦上一层含油脂的乳霜，效果自然会好很多。

最后最重要的事情说三遍：

一定要注意防晒！！！

一定要注意防晒！！！

一定要注意防晒！！！

未加防护的阳光暴晒也是致使皮肤外层受伤的原因，没有晒过太阳的部位一般是不会产生干性皮肤的。

干性皮肤护理TIPS：

1、使用加湿器增加室内的相对湿度（这个非常推荐）。

2、避免皮肤在水中浸泡太久，也不要长时间洗淋浴。

3、早上擦防晒系数SPF15以上并含有紫外线UVA防护成分的产品。

4、对于非常干燥的皮肤，可以在擦完晚霜之后，额外多擦一层橄榄油或其他植物油。

5、晚上擦果酸或水杨酸产品对腿、手臂、脸部等部位的干燥情形很有帮助，果酸和水杨酸可以除去皮肤外层的因干燥紫外线伤害造成的不健康皮肤。

 另外干皮还要记住以下两个“千万”：  

千万不要使用闻起来酒精味特别重的护肤品！  

千万不要用很热的水洗脸。   

油性皮肤保养建议：

鹿姐长期生活在南方，常听身边的人抱怨皮肤油腻，而且男性多于女性，以年轻至中年的人为主。脸上长期泛着油光，有谁喜欢呢？有人对油性皮肤就是不停的洗脸，用清洁力较强的洁面乳，想拼命洗掉脸上的油脂。

如果你正在或者曾经这样做，那我跟你说完蛋了。注意下你的肤质是否已经变成内油外干型。这种皮肤处理起来比油性皮肤更麻烦~

实际上无论洗多少次脸都是无法改变油性皮肤的。洁面乳清洁力度太强，反而会衍生更多的皮肤问题。

油性皮肤清洁：

洗脸对油性肤质来说特别重要，用中度去脂的洗面乳（一般中度清洁力的产品洗完脸部不会有干涩及紧绷感，而是比较柔润的感觉），一天洗多次，比用强去脂力的产品来的恰当。

油性皮肤保湿：

油性肤质不适宜使用增稠剂较多的保湿霜，只适合使用亲水性产品（比如化妆水、美容液），以免毛孔堵塞，增加皮肤的不透气感。

油性皮肤调理：

1、勤清洁，包含洗脸、清洁性敷脸（使用高岭土、绿豆泥膜等）。

2、调节皮脂腺的代谢机能。像是维生素 B2、B6、Zn-PCA 的使用等（一些紧致毛孔的产品通常含有此成分）。

此外，植物萃取液中，具有收敛效果的鼠尾草(Sage)、百里香(Thyme)、绣线菊(Meadowsweet)、圣约翰草(St-jon，s-wort)等，都很适合作为油性肌肤用的化妆水成分。

可每天用婴儿油或卸妆油充分地按摩脸部，对毛孔中“卡住”的固化皮脂，有充分清洁、代谢的功效。按摩完洗去这层油脂，毛孔更显干净透明。

不习惯用油清洁的人，可改用蒸汽蒸脸。利用毛孔扩张，皮肤温度升高的机会，清洁毛孔中所有的污垢。不堆积污垢，无残败油脂，皮肤自然健康。

油性皮肤保养TIPS：

1. 清洁建议：勿使用去污力很强的洁面乳洗脸，改酸性洗面乳（氨基酸洁面乳），可一日多次。每晚用婴儿油彻底按摩或以蒸汽蒸脸，清洁毛孔、促进代谢。

2. 调节油脂：多用 Zn-PCA 或植物萃取调理成分。

3. 保养搭配：以低油美容液、化妆水取代营养霜。日间保养，应选择抗氧化功能的保湿产品，不油腻、轻薄的防晒制品。

混合性皮肤保养建议：

很多人认为混合性皮肤就是两颊干，T区油，其实从皮肤专家的角度来说，混合性皮肤要复杂得多，鹿姐就只挑最典型的一种来讲：T区油两颊干。

其实混合性皮肤的保养并不难，至少要比敏感性皮肤简单。因为混皮只是干性区域拥有干性皮肤特征，油性区域拥有油性皮肤特征罢了。当我们去购买化妆品时，会发现很多产品含有控制T区油性皮肤的成分，对较干的两颊不仅毫无益处，反而会造成较多皮肤问题。

那混合性皮肤是否需要准备2套护肤品，一套for两颊。，一套for T区呢？我个人认为不需如此麻烦。

混合性皮肤的保养只有一个原则：分区域保养。挑选护肤品的时候只要注意哪些是针对T区的，哪些是针对两颊的，混搭在一起使用就可以了，下面就会说到混皮怎样选择护肤品。

混合性皮肤清洁：

混合性皮肤也同样不能使用清洁力太强的洁面乳，洁面的时候可以重点照顾T区，而两颊只需轻微带过即可，不可使用过多的洁面乳。

混合性皮肤保养：

在使用化妆品时需注意：含有抑制油脂成分的产品需避开两颊，而含有油脂成分的产品则要尽量避开T区。

最好的方法是：挑选化妆水和精华时，选择含有细致毛孔调理油脂的成分，擦的适合避开两颊，而面霜则选择含适量油脂的成分，使用的时候避开T区，做到分区域保养。

看到这里也许你会想，妈的护肤为什么要这么麻烦？！！！我只想一瓶化妆水面霜从头擦到尾啊！

但是你知道有这么一句老少皆知的名言吧：世界上只有懒女人没有丑女人，要想皮肤状态胜出同龄人，就要做到细致保养啊。要知道范冰冰的好肤质也不是天生的，据说她一年要敷一千多张面膜，相比明星，我们的保养算得了什么呢？

中性皮肤保养建议：

鹿姐就是夏季属于中性皮肤，而冬季有些干。

中性皮肤一般不油不干，难道这就是天生丽质的皮肤吗？其实我们也同样要面临日晒、皱纹等问题。

白天外出时使用的保养品，必须选择含抗氧化效果与防晒效果的成分使用。最简单的说法是：要躲太阳或避免再无限制的受光害。

当然中性皮肤也可能产生痘痘、斑点等问题，在面对这些问题时也会束手无策。

分肤质保养就聊到这里，回去仔细检查一下自己的护肤品，把该丢的丢掉，该买的买齐。

如果你还想深入探讨护肤问题，欢迎加我的围信（zhubianxiaolu）跟我讨论哦~
发布于 2017-05-04
果姐
果姐
果酱爱美妆 订阅号小编，爱护肤爱实验的工科妹子。

护肤这项工作在日常生活中是必不可少的，不是矫情，因为空气越来越差，紫外线越来越强，不管是上课还是上班，我们的皮肤都在一秒不停地被氧化，变老，还面临着被污染物伤害的风险。

 你再懒也必须做到的最基本的几件事，就是好吃好睡好心情，防晒保湿洗好脸。不要相信今天没睡好明早起来敷个面膜立马肤白人美，这是没有用的！也不要相信今天根本没太阳，根本不用涂防晒，紫外线随时都有，冬天低倍数，夏天高倍数，全脸超过1g（大约一枚一元硬币大小）千万不要懒。（嗯，我对自己也是这么说的）另外，洗脸这件事情不是重在洗面奶多贵，而是选择成分温和不刺激并且能洗干净的，宁愿选择一些价格便宜的氨基酸洁面也不要选择伤害大的皂基，成分的选择和怎么挑选会在之后的文章中提到。洗脸的时候一定要温柔，你再用力也不可能把痘痘和粉刺洗干净，不如温柔一点，认真地在手上打好泡沫，然后再上脸，用你最长的那两个指头轻轻按摩，不要超过三十秒就用清水冲洗干净，别玩了脖子和耳后。洁面之后的保湿就看你的喜欢啦，乳液和面霜都可以选择，这之前可以加一些抗氧化或者保湿的精华，这些东西没有贵贱，主要是适合你自己的肤质，不要跟风 不要三无 不要只卖贵的，尽量买大牌，很多大牌有平价线的产品提供给还没有收入的学生党，我们要相信大牌的成分的搭配技术成熟，有效成分的发挥肯定都是有保证的。韩国爱茉莉集团旗下悦诗风吟的绿茶系列，德国的MIVEA的护手霜和面霜，美国的旁氏米粹洗面奶，日本花王旗下的碧柔的各种防晒，法国欧丽提的大葡萄系列。

    如果你爱长痘痘，反思一下自己的饮食习惯，想想自己化完妆有没有认真卸妆，注意饮食别太刺激，减少糖的摄入。毛孔粗大的同学，如果是天生的油脂分泌过多，吃点维生素B控制激素分泌，饮食少油少辣，平常一周做两次泥土型清洁面膜，不要用手，有粉刺针，不要用鼻贴，那只会带走你本来健康的角质，让皮肤变得敏感泛红，清洁完之后用纸膜浸泡化妆水冷敷一下收缩毛孔。

    慢慢来，护肤都急不来，天生底子好的不要放松警惕，生活中到处都是氧化剂，皮肤不太健康的，暗沉，毛孔粗，不要操之过急，不要寄希望于广告效果太快太明显的护肤品，便宜的面膜里面有荧光剂，涂完第二天就没有痘痘的八成有激素，要用也可以，但是长期下去只会增添皮肤负担，不要做这种急功近利的傻事哟。

    还有就是保证睡眠，一周运动30min三到四次，看起来也会精神一些.

原文刊载在“果酱爱美妆”订阅号
发布于 2015-06-29
芥末番
芥末番
同道，童趣，换个新的她
皮肤是人体的排泄器官而非吸收。吸收器官是脾胃，脾为后天之本。
皮肤的好坏，先天决定了一大半。后天的保养是锦上添花，不要妄想去改变基因里的东西。明白这些后，会冷静下来，不要狂热去追逐护肤品。
早前，我皮肤可好了，巅峰实在高二前。那时候每天骑自行车上学，挺远的。睡觉吃饭好规律，基本十点就睡着了，只有冬季用强生的两元一包的婴儿油。后来高中，看到都在用洗面奶，自己也用了，然后天然皮质膜破坏了，也不分洗面奶的类型，角质层变薄。皮肤坏了，然后开始了作死，而且深信不疑，有段时间见到新产品就去用，皮肤可能有底子，所以也不是很差，但是就恢复不到高二前了。
上了大学依旧如此，而且喜欢囤积，基本品牌都有用，四年，尝百草。
今年考研压力大长痘了，从来没长过痘的我，不以为然，觉得是压力，可是后来都考完了，也没有说是不冒痘了，于是着急了，开始喝中药，大夫不让抹东西，喝了快四服药，不冒痘了，可是停药又长，大夫说养病养心，于是想想，自己对于护肤品的贪念太大，不好好吃饭，后来自己做饭，各种蔬菜，水果，注意休息，不和讨厌的人住一起，心情也好，情况好转。
现在三餐规律，护肤品不追求太多，洗面奶一天一次，晚上用。现在状态比之前好。
后续如果有可能会列出中药如何变食材。
发布于 2016-05-07
广戚
广戚

首先，没有内油外干这种说法，所谓内油外干其实是皮肤屏障受损的表现。 题主身处帝都且有痘痘和痘印，所以我认为题主应该要做的主要是修复为主，维持皮肤稳定，再想办法去痘印。想要皮肤好，必须要有一个稳定作息规律，不要熬夜，注意忌口，注意少吃高GI食品
 如果按照正常简洁护理程序来说：洁面—化妆水—精华—面霜—防晒。
洁面的话可以考虑：sk2，黛珂精致，艾杜莎等～
水的话，流金水，玉泽，健康水，紫苏水什么的都可以。
精华我推荐，娇诗韵黄金双瓶，资生堂红腰子，雪花秀润燥，雪花秀珍雪。
面霜：cerave夜乳，安露莎乳液，百优面霜，珍雪面霜。
防晒：防晒真是重中之重，答应我一年四季，白天阴天都要防晒好么。我就推个便宜的za，贵一点的安耐晒。
痘痘：痘痘的成因多种多样，但在大部分人身上就那么几种。比如内分泌失调，真菌感染，青春期等。。小面积的痘痘可以通过护肤品干预，大面积爆痘请去三甲医院皮肤科。如果妹子总有痘的话可以去查下激素六项。如果只是几颗的话，可以稍微尝试下水杨酸和果酸。具体的功课就不说了。去医院的话大概要开些阿达帕林，班赛什么的，就听医生的就好了。
就这样
编辑于 2016-03-06
匿名用户
匿名用户

--—--—--—--—--—--—--—--—--—【更新了祛痘疤】--—--—--—--—--—--—--—--—--—

从12月到现在，皮肤好了很多，用我同学的话来说就是换了层皮。其实我只改变了两件事：饮食结构，运动出汗。

【饮食结构】
说白了，多吃菜，多喝水，少吃少喝加工复杂的食品（比如泡面，零食等）。
用我的饮食来举个例子：

平常
早餐：菠菜炒鸡蛋，牛奶加咖啡，一点燕麦。
午餐：鸡胸肉/蛋白/鱼肉/虾，西红柿炒蛋，糙米
晚餐： 自制smoothie
零食：坚果，酸奶，西梅

放纵日
那天的话，选一餐放纵，其余基本上按照平常吃。

每月三天的清肠日（我朋友一般只能坚持一天）
方子是按照下厨房的果蔬汁做的（搜果蔬汁就好啦），加上一些自己的调整，轻松三天坚持下来。

我最开始感觉饮食结构改变会让皮肤好就是有一天心血来潮去买果蔬汁喝。 三天快200刀，贵的也是肉疼。但是之后皮肤就好像会发光一样，不那么暗沉了，下巴上的大包也下去了一些。真是收获多多（同时体重也下去了一两磅）。于是觉得应该把果蔬汁带到日常生活中来。于是每天做自制smoothie，喝起来也是棒棒哒。

【运动出汗】
其实就是跑步。我之前也会做一些椭圆机啊，阻力训练啊，羽毛球之类的运动。虽然都出汗而且运动量很大，但是没有哪一个能和跑步的出汗量相提并论的。每次跑个三千米下来都像是刚从水里捞过来的。回家洗个澡，涂一些lotion，补一下精华，皮肤那感觉，是相当的好。

【护肤品】
我自己是过敏性混合皮肤，不敢用太多的化妆品，现在能用的也是有最最基本的cerave lotion，低敏性的。精华我一直用契尔氏的蓝精灵，防晒是资生堂的蓝瓶。对了，一定要做好防晒！一定要做好防晒！一定要做好防晒！洗面奶是origin 的一举两得（其实用的不多，大多还是清水洗）。清洁的话，我会加上声波洗脸仪和lush的碳洗面皂来个一分钟的马杀鸡，主攻额头和下吧，之后还是origin家的碳面膜和补水面膜。
可能这些护肤品并不适合所有人，买之前最还有三天量的小样试一试。

之前我也是各种化妆品买买买摸摸摸涂涂涂的，然而只是治标不治本，有的甚至引发大规模杀伤。我本身是油性皮肤，后来在美帝变成了混合皮肤。常年爆豆，加上手欠，脸看上去也是惨不忍睹。慢慢改变之后皮肤可好啦，虽然还有些痘印（正在努力奋斗中），但是跟去年12月相比简直换了个人。而且因为做好了防晒，我比暑假回国的同学还白一两个色号呢（期间我还天天去健身房运动），简直不要太开心~~~~

--—--—--—--—--—--—--—--—--—

10.19
更新痘印

话说我的痘印分成两种，一种就是黑色素沉淀，一种是坑。

坑基本上没办法解决了，得去医院和美容院之类的吧。黑色痘印目前比较好解决，但是也分人跟体质。也就是说，我的方法不一定在你身上管用，但是你可以借鉴参考。

前言：
大概是14年初，脖子上开始起淋巴痘，去医院验血说是激素紊乱。痘子大概就是先红肿，然后冒白尖，最后是个直径三四毫米的脓包。我手贱，全给挤了。留下的全是大黑疤。脸上的包没有这个严重，是那种闷包，正面是粉色/红的小包，侧面看比较明显，像个小山峰。一般不会冒白，但是消下去之后会有很大一块黑褐色的痘疤。

【试过的有用的方法】

1. bio-oil
中文名叫百洛油？里面主要成分是VA, VE和各种草本精华，成分我查过，大概是镇定和促进新陈代谢的功能。试了几次觉得不是那么油，吸收还挺快的，就每天晚上点两滴在我脖子的疤上，揉揉搓搓的。大概有两个半个月吧，据我爸说，颜色淡了很多。直至现在只有点淡淡的印子，不知道我以前起过痘根本看不出来。但是，我觉得这个不要用在脸上的好。

2. 化学换肤
基本上就是各种酸。我买的是Dr. Dennis Gross的加强版。一包两个棉片儿分开装，先擦A，停两分钟再擦B，一盒30包将近一个月的量。我皮肤比较容易过敏，所以这个第一次擦上去痛得我呀……效果是相当不错，当时下巴上的一大片痘疤痘淡了很多。整个脸的皮肤状态都很好，毛孔什么的细小了很多。但是，用这个要注意防晒并且坚持（并不便宜呢 TAT）。

3. 精华
有次我去逛商场，有个La Mar柜台的BA就跟我说，我们家有一款很好的精华可以把你的痘痘和dark spot去掉等等等。然后我经不住诱惑就买了个小瓶，加上送的一些小样，用了有一个半月在脸颊上。我觉得这是我目前用过最好的祛疤（甚至祛痘！）产品了。因为我用的时候，脸上的痘痘还在发炎中，用了第二天就消了狠多，直到痘痘完全消失痘疤都没有再出现过。是不是很神奇！当然价钱也很神奇。后来我同学用了契尔氏的精华跟我说去痘疤也很好用。
以上的三个方法，本质都是促进新陈代谢，增加皮肤机能，所以痘疤在很短的时间都能有所改善。但是，这些绝对是治标不治本。痘疤下去了，又有新的痘痘冒出。这个问题也困扰我了好久，终于在我最早的篇章中出现了质的改变。现在我偶尔也会出些小痘痘，滴一滴精华很快又下去了，加上运动等大量运动出汗，痘疤消失也是无比的快（相比之前半年甚至一年才消失的），更是省钱（相比那些祛疤产品）。现在最烦人的就是那些小坑坑了~~
编辑于 2015-10-22
野兽生活
野兽生活
1
微信公众号：野兽生活研究所（ID：paleolifestyle）

评论都是爆照的，我歪一下楼来个科普向。

要知道怎么能祛痘，首先我们还得拿出老学究的姿态，研究一下痘痘到底是怎么形成的。


坐正看图，这是一个正常的毛囊：

这是一个正在孕育痘痘的毛囊：

所以用一分钟归纳总结一下，造成痘痘的最直接原因可以概括为：

    （1）毛孔被本应该正常脱落的角质细胞阻塞；
    （2）血液中的雄性激素浓度升高，造成皮脂分泌过量；
    （3）变多了的皮脂里开始滋生细菌；
    （4）细菌感染毛囊腺里的皮脂和周围的组织，患处开始发炎；

但知道了这些...好像还是没有卵用啊。

日子过得好好的，角质细胞怎么就不能正常脱落了？健健康康活蹦乱跳的，血液中的雄性激素浓度为什么会升高？细菌滋生我能理解，但别人长痘痘也没有像我一样总是发炎呀？

为了解答这三个更核心的问题，我们需要继续看看这两张图：

这是一个健康皮肤毛囊结构图：

可以看到，毛囊的内表面是由上皮细胞组成的，上皮细胞又有两种：角质形成细胞、角质细胞。这些细胞之间由一种叫做桥粒的东西连接。角质形成细胞构成了毛囊内表面的那层膜，它们不停地向上生长、成熟、死去。这个过程称为分化。

当角质形成细胞死去以后，它们的尸体失去了细胞核，变平变老变硬——这，就是角质细胞，它形成了皮肤的外层，健康的皮肤一般包含15~20个角质细胞层。角质细胞继续老化，最终桥粒分解，粘合解除，角质细胞脱落。整个过程大约持续四周，循环往复，也就是护肤品广告里老提的皮肤的28天代谢周期。

那么在孕育痘痘的毛囊里发生了什么呢：

这里的桥粒不！愿！意！分！解！了！

...

问：好好的怎么就耍小脾气不分解了？

答：是因为角质形成细胞的分化过程出了问题，角质细胞死去的太晚，影响了桥粒的分解。

问：那角质形成细胞为什么不能按时去死呢？

答：胰岛素分泌上升了。

问：emmm...胰岛素还会影响痘痘？

答：胰岛素是胰腺分泌的一种荷尔蒙，而且是荷尔蒙中的大佬，它以直接或间接的方式影响人体几乎其他所有类型的荷尔蒙的分泌。胰岛素上升会抑制一种叫IGFBP-3的荷尔蒙分泌，而它的作用正是监督角质形成细胞按时去死；同时还会促进另一种荷尔蒙IGF-1的分泌，而它会刺激皮肤细胞过度生长。而且IGF-1和IGFBP-3是对头，它也会抑制IGFBP-3的分泌。

这样缕一下思路，就变成了这张图：

所以你应该明白，为什么之前去医院看痘痘，医生会告诫你少吃甜的多喝水了吧。医生可没说废话。


那血液中的雄性激素浓度升高，造成皮脂分泌过多，这又是怎么一回事呢？

雄性激素是直接刺激毛囊中皮脂分泌的激素，男性在睾丸中分泌，女性在卵巢中分泌。它在血液中的浓度是由肝脏分泌的一种蛋白SHBG控制的，SHBG高的时候，雄性激素的血液浓度就下降；反之SHBG低的时候，雄性激素血液浓度就上升；因此SHBG低的时候，就会间接刺激皮脂分泌。

那SHBG为什么会低呢？还要怪胰岛素分泌上升及IGF-1分泌上升。所以这一条的逻辑是这样的：

上面我们说到，长痘痘的同学，不仅本身就容易长出痘痘，而且他们患处发炎的情况也比健康皮肤要多得多，这又是为什么呢？

病从口入，这还得从我们平时吃的东西——脂肪，说起。

脂肪分为三类：

    （1）饱和脂肪，比如黄油、肥肉、奶酪中的脂肪；
    （2）单不饱和脂肪酸，比如坚果、牛油果、橄榄油中的脂肪；
    （3）多不饱和脂肪酸，比如植物油中的脂肪。

跟人体免疫系统的炎症反应密切相关的是多不饱和脂肪酸，而它又可以分为两个子类：omega-6脂肪酸和Omega-3脂肪酸。

这两者最合适的摄入比例应该是omega-6/omega-3=2，而高碳水饮食中，这两者的比例远远大于这个数值。

身体摄入太多omega-6脂肪酸，太少omega-3脂肪酸，就会刺激一种叫IL-1 alpha的荷尔蒙分泌，它的作用恰恰是控制免疫系统的炎症反应。当这种荷尔蒙受到刺激，分泌大增，身体发炎的风险就会大增，当然，毛囊发炎也包括在内。

除此之外，如果高碳水的基础是面食，那情况更糟糕。因为小麦中含有血凝素（lectin）。（除了小麦，黄豆、花生、豌豆等豆类中也含有血凝素）这可不是什么好东西。它会阻止一种酶类ZAG (Zinc-Alpha 2)的形成，这种酶的作用恰恰是分解使细胞聚合在一起的蛋白。因此也会导致角质细胞阻塞毛孔。

此外血凝素还会刺激IL-1 alpha和其他炎症荷尔蒙的分泌，还会阻止对微量元素锌的吸收，血液中锌含量低也会导致炎症。如果想改善痤疮，就要避免摄入血凝素，最好尝试一下停止食用小麦和豆类。

奶制品由于含钙量高，也会在一定程度上阻碍锌的吸收，如果痤疮严重，最好也避免食用。

所以古人说的好，药补不如食补。

如果你的痘痘久治不愈，而你却想重回蛋壳般的脸蛋儿，从今天起就尝试降低碳水在膳食中的比例吧。

那么低碳水到底怎么吃呢，简单来说就是这样：

你可以通过逐步减少对以上食物的摄取来降低碳水。

当然，如果你是进阶型选手，想了解更多关于低碳水饮食的知识，关注我的知乎和微信公众号（野兽生活研究所），本学究会持续给你带来科学又健康的全新饮食知识～

完。
编辑于 2018-01-17
周凸凸
周凸凸
一只小猴子

1 洁面 尽量选用氨基酸洁面 刺激小
a 开架货 可以选择旁氏米粹  价格在20元左右
b 芙丽芳丝洗面奶 100元左右

2 痘和粉刺可以考虑 理肤泉这个牌子的K乳 ai
如果有挤痘习惯的 可备一只理肤泉B5 消炎 对刚开始的痘印比较有效

3 护肤品最多能维持到你皮肤曾经最巅峰的状态，并不可能发生巨大改变。
皮肤底子很关键 

4 皮肤状态好的时候，少叠加护肤品，更要精简。

5 适量的运动

6 相对清淡的饮食

7 皮肤出现大面积爆痘的话 请务必去医院。护肤品并没有卵用。

8 如果本身皮肤底子可以 那么少折腾 少叠加 就是最好的保护了 。

9 注意防晒

10 最后也是最重要的一点！长痘和皮肤状态不好，不怎么稳定的时候。务必不要用片装以及补水面膜。
编辑于 2015-10-27
匿名用户
匿名用户

从2014年九月大一开始正式的护肤，都没有什么很大的成效，脸上夏油冬干，黑皮肤，易晒黑难变白，一年四季都有痘，吃辣的长，姨妈来也长。冬天脸上甚至起皮，化妆一点不服帖。2015年暑假到现在换了一种理念后很多人都说我皮肤状态变好了(๑•ั็ω•็ั๑)。
总结就是内服加外用。
之前刚入学被在各种护肤品上花了不少忙内，想想好心疼。后来我妈跟我说了好多化学添加剂的危害真的是怕了。
2015年7月放暑假，在家里妈咪都不让用化妆品护肤品，于是就用各种水果蔬菜榨汁敷脸。常用的就是黄瓜榨汁加一点蜂蜜两滴柠檬汁泡纸膜，说实话见效比较慢，但是两个月暑假下来脸真的有变很光滑，白也有一点，但是夏天真的太容易晒黑，只有白一点。还有一个很喜欢的就是银耳。用锅很难把银耳的胶原给熬出来，但是把它剪碎放进豆浆机里用湿豆原磨那一档糖都不用放就打出浓浓的胶原了。浓度看个人喜好加水多少。我都是留一小杯加水稀释泡纸膜剩下的跟爸妈一起喝掉用完脸草鸡滑的！苹果真的不好用，刚榨好汁就氧化了而且糖分多，粘脸。。。
这些天然的真的好用，但是来学校后没有榨汁的工具了就放弃了。
之后一直用的植物的水和药妆，勉强保持皮肤状态。
刚开学9月，微博看到有人说吃维C维E和葡萄籽一年变白好多的，我也试了。吃了两个月，有变白一点，不明显，但至少脚上的凉鞋印淡了不少，身上变白比以前快了很多，就是脸没有变白。。。估计是我防晒不到位。但是后来担心这种内服的营养类药物乱吃不好就没坚持，不过维C真的好厉害，我们寝室全感冒了我都没感冒( •̀∀•́ )。
皮肤真正变好是在2015年11月，我姐跟我说让我喝牛奶，长个！(身高是永远的痛)姐是女神一样的存在，她说啥我做啥。买了两大桶奶粉回来(全脂的)，冬天喝着热乎。早晚各一杯，不规定时间，但是规定量！最神奇的就是每天晚上用一点冲的牛奶泡纸膜敷脸加上每天喝牛奶，六天白了一个度！我没有开玩笑！到现在我还在喝，真的很有效。每天早上起床看见自己变白的脸心情都会变好。
当然，护肤品不可能完全不用，不过减少了种类和频率。
我每天洗脸只在晚上用洁面产品，其他时候都只用清水。白天出门擦水乳霜，晚上用水精华乳(个人认为冬天出门风大，涂厚一点好，晚上皮肤要呼吸涂薄一点)。对了，我用的水是国产某牌的甘油！好用不贵！完美代替了我之前用的贵死人的水。乳液用的是修复皮脂层的，用完一瓶半脸上已经很少出油了T区都被征服了！正在向中性皮肤发展！精华买了俩，水杨酸和美白淡斑的。长痘留下的毛孔真真是太恐怖了！这个酸真的很神奇，我大脑门现在又光又亮！鼻子上的毛孔除了鼻翼那边的基本看不见了。一开始我每天晚上在长痘的部位和毛孔粗的地方涂一点，现在一周用四次左右。千万不要白天用！我刚买回来白天用了结果一暑假保养出来的成果全晒没了，擦防晒霜也没用！美白精华和保湿美白霜都是某大牌。。。不得不感慨贵的有道理(打了两份工才狠下心买的=_=)。
还有作息饮食，我每天吃食堂，偶尔吃火锅什么的，辣这种东西一学期给自己规定了最多吃三次。。。吃完就疯狂长痘。。。全靠我的水杨酸，但是也只能遏制住痘的生长，不会真的消失的一干二净的，姑娘们一定要管住自己的嘴！水果，一天至少一个，橙子猕猴桃苹果我都爱吃。
排便=排毒，，，便秘又尴尬又伤皮肤。。。没有什么有奇效的方法都是靠平时调理饮食，水果不能断！我初中因为便秘长超大的痘，痘坑现在还在脸上。后来每天逼自己上厕所，多喝汤吃水果，坚持久了最明显的效果就是手上的指甲变得很光滑，现在一天没排便就会心里不舒服。。。。
睡觉！最直观的就是每到暑假睡眠充足我的痘就很少出没。但是大学后我有个糟糕的室友，每天不到一点半就不睡觉，还不让我们睡。不过我忍了她两个月后就直接说她了，现在虽然她照旧但是我保证自己在11点之前睡觉(我在家都是十点睡觉算迟的！)。

到现在我的护肤历程还很短，用过的护肤品也不多。。。没啥经验，就是给大家介绍点我觉得经济实惠又有效的╮(╯▽╰)╭。

。。。。。。。。。。。。。。。。。。。
忍不住来推护肤品了，因为实在是太好用！
我除了牛奶继续喝，修复皮脂层的乳液继续用，最近一直在用sk2的小样。我之前给我妈咪买了青春敷送了小样，觉着用的不错干脆去买了一个月的用量回来。就是眼部精华乳，美白淡斑精华和美白保湿霜。现在酸已经很久不用了，皮肤又白又光滑，鼻子上黑头毛孔也没有出来。眼部精华乳一般般，室友用了还长脂肪粒，精华用完白的很明显但是会干，然后霜真的草鸡好用！在家里被妖风吹成狗晚上涂一层乳加霜第二天起来脸又亮又滑(๑•ั็ω•็ั๑)。过年了每个亲戚都说你越来越漂亮了那种感觉是特别爽的( •̀∀•́ )。
编辑于 2016-02-10
Ziva
Ziva

请停用露得清 这种超强碱性的洗面奶只能让你刚洗完脸时很爽然后让你的脸越来越敏感 我高中时的完美中性皮肤就是被它弄成混合皮的 还有 你娘亲的护肤品不适合你 那些基本上都是30+用的

下面推荐些个人认为比较好的护肤品
洗面奶:丝塔芙还有各种国货洗面奶比如戴春林凤凰液，安安，肤美灵，大宝(个人用完感觉不是很好 但很多人推）什么的 自己挑一款适合自己肌肤的用 每次用时都至少要按摩3-5分钟 都是无泡的 不过不习惯的可能会觉得洗不干净

然后每周一次去角质或者清洁面膜 记得做完后要用一片补水面膜 个人比较喜欢森田还有曼丹的有个bb在上面的那款 

水膜可以每天敷 就是用纸膜敷水 日本的薏芢水或者你的昭贵或者巨型一号什么的都可以 有钱一些的就用雅漾 实在不想买的 矿泉水都可以 相信我 把水拍在脸上基本上是没什么用的

毛孔可以用珍珠粉来收 每天洗脸时混一些在洗面奶内 按摩

至于豆豆什么的片仔癀珍珠膏和春娟是真爱 也是看个人体质挑选 我一般急需消痘会用春娟做三明治面膜 做法百度一下就有了
以上推荐的产品都是大学里总结的便宜大碗的好东西 虽然推荐了很多 但是护肤流程其实还是蛮简单的 主要就是早上洗脸+霜 晚上洗脸+水膜 毕竟脸上还是不要抹太多东西好 护肤是个持久战 你花多少心思在上面就会有多少收获
发布于 2015-03-12
知乎用户
知乎用户
知易行难

看到题目，满以为点进来能看到前排几个现身说法的人里能有！那！么！一！两！个！发几张用！相！机！拍出来的真实照片来卖自己皮肤的。



果然，我想多了！


用渣手机自拍我忍，用美图软件磨皮我也忍！能特么不加滤镜吗！
发布于 2017-04-02
何洛
何洛
这个，我有经验诶。。
内调part：
1、如果你是个有自制力的妹子（从你每天跑步来看，应该是），那就坚持早睡早起。答主我不是，所以我的皮肤比你还糟糕=。=
2、每天泡脚。以微微出汗为标准。
3、饮食：1）低GI：少吃蛋糕、烘焙面包、牛奶、奶酪、糖一类的东西。2）忌油炸辛辣、忌发物。3）多吃水果（我的建议是苹果，无论你什么体质都可以吃）和蔬菜、杂粮，多喝水。
【15-02-28更新：补充胶原蛋白貌似真的有用，因为我这个月喝了蛮多次银耳桃胶糖水，感觉皮肤有润泽一丢丢】
4、运动。这个虽然你的提问表明你已经做到了，但我作为一个处女座，不喜欢自己的答案缺一角=。=
以上都会对你新陈代谢有帮助。
外用part:
1、理肤泉。详细单品不多说，Duo+,K乳等等，要自己做功课~
2、痘痘严重的话看皮肤科（西医）。不推荐中医是因为我已经看过几家大医院的中医了，收效甚微。西医的话可以到好大夫在线网站上去看口碑，最好是选择大医院的名医生。再贵也贵不过美容院，钱要舍得用到科学的地方。
3、去痘印的产品需要等到痘痘稳定下来再用。
以下几个美白精华是目前口碑很好的一些去痘印可能有效的：1、OLAY小绿瓶、小白瓶，平价但不一定每个人都耐受。2、资生堂新透白。3、契尔氏美白精华。4、雅芳无痕霜+再生霜。5、杜克色修加强版。
【15-02-28更新：小绿瓶断断续续用了一个月，这两天放假回来有几个同学说我变白了。但是用小绿瓶的地方我长了不少闭口，所以估计我不是很耐受。不知道这算给大家长草还是拔草。资生堂新透白败了，正在来的路上。一个月后写反馈。雅芳无痕昨天刚开罐使用，感觉用完第二天醒来皮肤很滑，过一阵子再来写反馈吧~】
4、清洁面膜：比较平价的：DMC，悦诗风吟火山泥。贵一点的：契尔氏白泥，eminence青柠。
==================================================================
建议你微博上关注：功课菌Sina Visitor System和AA酱婶儿Sina Visitor System。
编辑于 2015-02-28
努力的邵小灰
努力的邵小灰
奔跑在法律道路上的懵懂汪
早睡早起不熬夜 运动心情少折腾
看到过一句话 20岁女生最好的护肤品是汗水和笑容
发布于 2015-03-21
知乎用户
知乎用户
follow your heart你想要什么样的生活？

运动排毒
规律饮食作息
忌辛辣甜品油炸
补水，防晒，洁面
多吃水果蔬菜
一天一便
八分饱，吃营养
共勉
编辑于 2015-04-29
satchmo
satchmo
铲屎官



从烂脸到现在..
我已经很
满足了 
现在偶尔会有姨妈痘 马上消下去 不会大面积长了...
真的 没啥技巧哈哈 习惯很重要 
少吃外卖 外卖特油 三餐规律 多喝水 最重要的是！！多运动排汗！
因为我一次严重高烧 唔了很多汗 之后 脸上粉刺居然好的差不多了..
阿达帕林是猛药 要谨慎..
现在用神仙水+小灯泡+面霜 +自然哲理vc粉 +安瓶photoage.
编辑于 2017-03-18
潮流阁
潮流阁
美容护肤

保持充足的睡眠。睡美人，顾名思义，美女是睡出来的，足够的睡眠可以改善很多的皮肤问题，促进皮肤的新陈代谢。，而经常熬夜的人就容易有黑眼圈，粉刺等，严重影响皮肤。

饮食有规律。饮食要有规律，不能暴饮暴食，也不能随意的节食，这些不好的习惯都会对皮肤和气色产生不好的影响。

要学会自我减压。每个人贼面对生活，工作和学业问题时都会有或大或小的压力，要学会自我减压，否则压力过大，额头就会长小痘痘哦。

每天运动。每天的规律运动可以促进血液循环，血液循环好的人皮肤会自然红润，有光泽，而长时间不运动的人皮肤就显得苍白，怎么看都没有朝气。

面部按摩。经常做面部按摩可以很好的改善自己的皮肤状态，增加皮肤的弹性，减轻皱纹痕迹。

深层洁面。在皮肤的毛孔里面会隐藏很多的垃圾，最好在洗脸的时候做的深层洁面，将里面的垃圾打扫干净，以免时间长了影响皮肤的健康。

注意防晒。俗话说，一白遮三丑。如果晒黑了，就严重影响皮肤美观了，所以要注意防晒，强烈的紫外线照射会使皮肤粗糙，甚至会引起皮肤癌。

皮肤护理。定期为皮肤做护理，不光有利于皮肤美白，还会让你的皮肤更加健康。
发布于 2016-03-29
青酱
青酱
不熬夜+好心情
发布于 2015-02-22
一座大山
一座大山
互联网营销/新闻系专业

本人是地道的广东妹纸，但大学四年是在宁夏银川度过的（没错，就是传说中干的鼻子喷血，紫外线巨强，还喜欢时不时挂个沙尘暴的大！西！北！）。

虽然答主在这里度过了非常愉快的四年大学生活，也早已把这里当成第二个家乡，但不得不说，相比起湿润的南方，西北这一块不能说是养人的地方，尤其对妹纸来说。

先说说本人的情况

在广东的时候皮肤尚可，偏白，属于混合偏油肤质，但到了银川后，活生生被整成了外油内干加敏感肌肤质！！！ （去医院查是说对这地方的紫外线还有沙尘过敏），而且刚来时由于水土不服，皮肤又黄又黑，还干的起屑。。。。。。总之是我人生中的一个黑暗时期。

SO，为了拯救自己的颜值，我开启了漫漫探索护肤的道路，到现在大四下学期，不说皮肤有多好，但现在皮肤已经被调成正常肤质，不再三天两头过敏。而且基本上见过我的人都会说一句你皮肤好白，或者皮肤好好，有时候出门偷懒不想化底妆也毫无压力。

天知道我背后是踩了多少雷，试了多少错，才达到今天这种效果！！（不要小看任何一个爱美的女生好么，你永远不知道她在背后付出多少努力只为让自己看起来美一点点~）

---------------------------------------------------------------------------------------------------------------------------------

我心目中的好皮肤用一个词就可以形容：白净

这个词我们要分开来解释，所谓白不是指单纯的死白或苍白，而是白的透亮，白的透水，白白嫩嫩的。而所谓净是干净，你不能有小痘痘或黑头啥的，脸上干干净净。

要做到这两点，说实话，挺难的。答主也在往这两方面进行修炼，到现在为止，不说完全达到这两个标准，但也算初有成就。我会说有时候我自己猛一照镜子，会被吓一跳“卧槽，我咋这么白吗”（答主是个自恋狂哈哈）

为了能更好的帮助大家，我把这些年来通过无数踩雷获得的血泪经验总结成一道公式：

皮肤好=早睡+运动出汗+ 护肤品

下面干货奉上：

-----------------------------------------------------------------------------------------------------------------------

1.早睡：

可能有些人看到这个就失望了“切，我早知道了，都是一些陈词滥调”，但你仅仅是停留在知道，而没有真正去做过。

相信我，坚持个三四天，你会明白早睡的威力。

我第一次被这个方法深深折服是源于一次放暑假回家，那段时间我还在饱受皮肤过敏之苦，脸上又红又痒，但因为怕对药物有依赖性，所以忍着没涂药。由于我家人都睡得早，所以十点多我也早早的上床睡觉了，第一天还没怎么发觉，但第二天、第三天、第四天。。。。。 眼看着脸上的包包慢慢消下去了，也不发红了，直到最后完全痊愈了。当时我特么就惊呆了好么！

也是从那时起，我开始对早睡重视起来。虽然回学校后住集体宿舍做不到十点多就睡，但起码保证在12点以前睡就行了。而且记住，必须得是关灯睡觉，因为光线会影响皮肤自身休养的。

坚持下来，不论是从气色、光泽度还是细腻度等等，皮肤会从整体上有很大改善。

2.运动出汗

其实当时的初衷是因为要减肥，但后面发现对改善皮肤的功效也是杠杠滴！

不用花大把银子到健身房，就每晚到学校的小操场去跑步。答主坚持了2个多月，感觉不仅对瘦身很有帮助，跑完后出一身汗对皮肤也很好，特别是对去黄气有显著作用，可能是促进皮肤自身的新陈代谢吧。

以上两点就是所谓的内调，是我觉得对我来说效果很明显的两个方法，当然，平常的饮食合理也很重要，比如多吃蔬果和五谷什么的，但我觉得这是长期作业，相对于前面2个方法来说效果没那么立竿见影，所以就没列出来。

3.护肤品

答主对护肤品的理念是“适合自己的才是有用的”，坚决不搞什么幺蛾子新噱头（其实近些年来很多层出不穷的护肤新概念产品都是商家基于自身的营销体系细分市场区别竞争对手定位而已，不用问我是怎么知道的），所以我在这里推荐的是一些虽然看起来不起眼，甚至很朴素，但用下来才发现真真对皮肤好的护肤品（为了防止有打广告的嫌疑，所有推荐品不贴链接，想要的自行到某宝或实体店去找）

3.1  G&M 澳芝曼绵羊油

绵羊油其实几年下来也七七八八的买过不少了，除开踩过的一些雷，总结起来一瓶好的绵羊油可以帮助你做到这些：

1.温和不刺激，敏感肌伤不起呀
2.滋润保湿不油腻，作为一瓶面霜，最大的诉求就是滋润保湿，而不油腻是区别好绵羊油和差绵羊油的重要评分点
3.美白，虽然查了下相关资料，发现并没有明确说明绵羊油里的成分跟美白有什么关系。但根据答主以及身边小伙伴的经验来看，皮肤的确会变的白净不少，也许是保湿滋润做够了，皮肤自然而然会变好变白？！


而推荐的这款绵羊油，完全符合以上3个标准

有些人可能没听说过这个牌子，其实它在澳洲很火，算是一个老字号牌子，主打天然护肤品

这个是答主去香港时在药房买的，便宜大碗，只要20元港币！！！（其实除开一些定位中高端的，在香港或者澳大利亚新西兰本地，绵羊油大都是二三十元的样子）。

本来结账的时候还有些许担心，因为还从来没用过他家的绵羊油，但事后证明，我的担心纯属多余。

第一次打开用就体会出它的好了。由于绵羊油自身产品特性（绵羊油是一种从天然羊毛中精炼出来的油脂）,很多擦完后虽然滋润，但都会给人一种油腻腻的感觉。但这个完全不会有这种问题！！！ 相反，在把它擦上按摩直至吸收后，皮肤会有一种很轻松的呼吸感，用手摸摸皮肤，软糯滑嫩，重点是一点也不油。

但神奇的还在后面。。。。。

大约一个星期后，早上睡醒起来照镜子，明显感觉皮肤状态变好，属于白的发亮那种，注意，不是死白，而是干净透亮的那种（我自己都快爱死自己了好么！！）

3.2.无印良品的水和乳液

我买的是敏感机系列，一瓶大概就70元的样子，涂在脸上真的是完全没有负担，非常清爽，同时保湿度也是够够的，敏感肌完全不用担心会过敏，很好的做到了一瓶化装水和一瓶乳液的本职工作。

目前已经回购3瓶了。。。。

好累，不想码字了，如果还想看的点个赞，超过20个赞我再回来更（偷懒耍下赖皮哈哈）。。。。。。。。

oƫV�^�
发布于 2017-03-28
砧板猪
砧板猪
与先生在一起九年，第十年成亲。嗯，成了亲。^_^
关于养肤我有一个特别省事的方法，就是用花粉和蜂蜜温水冲服，早晚各一次，蓝后就可以随便吃辣熬夜玩电脑各种嗨皮都不会长痘，毛孔细腻不出油，还会越来越白且抗晒哦。亲试有效。连护肤品都可以只用最基础的保湿产品就够了，好省钱有木有！
关于花粉和蜂蜜的品种可以根据自己肌肤需要着重改善的方面来选择，其实差别不大的，重要的是早晚记得喝ღ(๑╯◡╰๑ღ)
忘了说了，花粉能买破壁的最好。
编辑于 2016-02-02
莫奈花园
莫奈花园
美妆公司运营

自己看书，丰衣足食。

很多常见问题都能从书中找到解答，从此告别伸手党~/(ㄒoㄒ)/~~

百度云链接（2013年6月22日已更新有效链接）

http://pan.baidu.com/share/link?shareid=269308129&uk=1409610847（百度云下载链接）

http://pan.baidu.com/share/link?shareid=1488937550&uk=1409610847
发布于 2015-03-11
匿名用户
匿名用户

我的体会是 要想皮肤好，不能光靠外涂，一定要内调。从内而外，身体内部没有问题，皮肤才会真正变好。

 1、护肤品。 一定要每天卸妆，无论化不化妆，现在雾霾这么严重。 推荐 贝德玛，毫无刺激性，我是敏感肌肤，用起来也很舒服。 清洁：选择适合自己肌肤的洁面品。

 化妆水、面霜：选择合适自己的。你是什么类型的肌肤就选择针对自己肌肤的产品使用。不是越贵越好，而是越适合自己越好。 

我是敏感肌肤，科颜氏高保湿水，高保湿霜简直好到不行！

 面膜：不要信赖太多功效的面膜，什么美白紧致瘦脸。只要补水就好。

 2、内调 
（1） 请一定要早睡觉！！！！不要熬夜，熬夜不光毁身体，皮肤也会变差。之前大一熬夜，烂脸，花了好长时间才恢复。

 （2） 看个人体质，饮食结构尽量健康。 -_-||之前为了脸，戒了辣椒，烧烤，油炸。 刚开始嘴会馋，越是看见辣烧烤就控制不住，但是为了脸，就控制。 到现在，已经习惯了更健康的饮食。

 （3） 保持运动。 女生可以做好多运动。长跑，游泳，羽毛球，快步走，爬山。 迈开腿，管住嘴，不光可以瘦，运动让你的新陈代谢加快，每天排汗，保持年轻的姿态。
 你的身材是你运动习惯的反映。 
你的皮肤是你生活作息的反映。
 慢慢来，健身护肤都不是一朝一夕就可以做好的事。 
长久坚持才是硬道理。
发布于 2015-11-21
qimaoliu
qimaoliu
最近得出最最最靠谱的答案：“足够的睡眠+好心情”才是万能的护肤品
发布于 2015-06-10
知乎用户
知乎用户
知易行難～
1.我认为最重要的就是保持心情的愉悦，有积极乐观的生活态度。不要为一些小事而毁了自己的好心情，人的心情好了整个人都会容光焕发，皮肤也会变好。 
2.保持良好的作息时间，早睡早起，有条件的话可以坚持午睡，午睡半个小时足够了。
 3.多吃水果蔬菜粗纤维，多喝水，多喝绿茶，口味尽量清淡，提高新陈代谢。
 4.养成运动的好习惯。找到自己喜欢的运动方式。我个人很喜欢跑步，经常会去操场跑上一二十圈，大汗淋漓，真的很排毒，皮肤会很好，也有时间留给自己放空和思考，我也会和朋友去打乒乓球，羽毛球等。 
5.在自己经济能力承受范围内买最好的最适合自己的护肤品和底妆。不要天天化妆，一周最好留个一两天不化妆让肌肤透透气。做补水面膜。
6.皮肤的清洁，保湿和防晒很关键。
编辑于 2015-03-19
阿甜
阿甜
法学女/画手/浪漫现实主义者
楼主你好，我和你的情况其实很像。我从初三开始长痘，现在读大学了，痘痘比以前好了很多。我稍稍总结了下这么多年的战痘经验，都是干货，不骗你。
1.做不到早睡别想祛痘！
　　我在这苦口婆心地劝一句，一定得早睡。睡美人就是睡出来的美人啊！长痘痘其实就是体内的器官出了问题，而在睡眠里我们的身体会主动地修复。原来看一个美容节目说睡眠是最好的消炎药。我觉得很有道理，而且一定要早睡。我从初三开始长痘，而恰恰也是从初三开始熬夜。所以熬夜是痘痘的始作俑者啊～～～听我的，内调比外敷有用多了，什么护肤品都只是辅助你的皮肤，而皮肤要好最重要的还是内分泌。每次我想要晚睡，想到自己的痘痘，想到长痘痘以后丑丑的样子，我就乖乖去睡觉。睡觉真的是最简单易行的方法了，但一定得坚持。
2.补水　
　　长痘痘也可能是皮肤缺水了，皮肤大部分是由水组成的。喝水很重要，不仅是要给自己喝水，还要给皮肤喝水。我坚持每天喝1.5升水，皮肤感觉水润了很多。而且喝水也有助于排便，排除体内的毒素，是健康最大的帮手。反正，我觉得水是越喝越觉得好喝，越喝越觉得需要。我就算是出门吃饭也不喝其他的饮料，我只喝白开水，因为饮料有太多色素和香精了，不健康。给肌肤喝水，就是说早晚的水和乳液都是必备的。产品我就不推荐了，护肤品最好是买高档一点的，别心疼钱，要不然就得心疼你的脸了。然后就是常常做补水面膜，我常常用的是这个。韩国可莱丝胶原蛋白面膜，同学从韩国带回来的，蛮好用，感觉水水的。
除了这个我原来还用过EXO代言的自然乐园芦荟胶。这个也算一个有口皆碑的产品吧，当时蛮火的，效果很好，可以做面膜用。

面膜有时间天天做也可以，我推荐的都是比较温和的面膜，亲身体验过的。明星们之所以天天化妆皮肤还那么好原因之一就是经常做面膜吧。其实我还听过一个补水的小方法。可以带一个小喷雾瓶，里面装水，闲暇的时候喷一喷也可以补水。据说韩国的女生出门都带喷雾的，所以皮肤才水润润的。没用过，冬天太冷了。
      多吃水果，补充维生素。道理不用多讲。每天坚持吃水果。猕猴桃的维生素最丰富。有时候我上火长痘，我会吃柿子降降火。但是柿子忌口比较多，月经期不能吃，因为它是止血的。苹果和梨也是不错的选择。西红柿富含维生素Ｂ，而且可以美白，一举两得。
　　哦对，还要声明一下。我从来不用祛痘产品。大概是因为我妈不让用，我又胆小不敢用吧。祛痘产品效果好应该也会有很大的副作用，伤皮肤，不敢用。而且治标不治本，消掉以后肯定还会长。再加上国内的祛痘产品实在不敢恭维，没有可信度哟。
3.饮食很重要，清淡为佳，但一定别吃油炸！我就是一个无辣不欢的人，但我觉得吃辣椒也不会很容易长痘，所以偶尔吃一吃辣椒也不觉得有什么。但是油炸一直是我的雷区。我从来不允许自己吃油炸烧烤类的食物。太容易长痘了！！简直是每吃必长啊！！但我从来就管不住自己的嘴，前几天吃了烤肉，长了一个坨大的痘到现在还没消掉，哎，我可是血淋淋的例子。饮食嘛，还是清淡一点，多吃蔬菜，补充维生素，这句话真心不会错。
4.洗干净脸，别堵住了毛孔～我还记得迎新晚会的时候，化妆的姐姐给我化妆时一脸嫌弃地说，你怎么长痘痘啊，是不是没洗干净脸？然后我开始注意到，其实洗脸也是很重要的。首先要洗干净，就得有个好的洗面奶。我用的是innisfree的绿茶洗面奶～（不是绿茶婊）泡泡很细腻，感觉也很温和，有绿茶的香味，我真的超级喜欢这款。
第二，洗脸不要用太大太粗糙的毛巾。用小一点的帕子或者是洗脸棉也可以，大毛巾容易沾上细菌而且太粗糙。还有就是不要太用力地洗脸，使劲搓会搓出一脸皱纹的，孩子。
5.长痘就别用化妆品了，真心不要碰。用化妆品会堵住毛孔，加剧痘痘的长势。就算用的话，用好一点的化妆品，而且要卸干净。我也油性皮肤，长痘，我现在不化妆。因为长痘也不好上妆，年轻的时候还是好好保养皮肤比较重要。毕竟化妆是一时的，皮肤好了底子就好，不化妆也美～
还有长痘痘不要抠，不要挤，留下痘印很丑的。
　　嗯，大概就这些了。
发布于 2015-03-04
付大脑袋
付大脑袋
养生 护肤 美妆 英文发烧友
老规矩，我先po照片，看大家觉得是否有变化吧，如果有变化我会把一些方法告诉大家

上图是我刚来澳洲一个月，由于水土不服导致了痘痘，脸肿，晒伤等问题。

上图是五个月护肤调整之后

上图是现在，无滤镜处理，可以看出皮肤已经状态有所改善了。护肤真的是个很长的过程，不要给皮肤增加负担才是最重要的
编辑于 2016-05-17
小猴子summer
小猴子summer
言论只代表个人，不代表任何单位、群体、职业

火车站候车手机回答。 我常常被人说皮肤好，一是白，二是毛孔小，没豆，没斑，有红血丝，皮肤薄，比较敏感，89年生。 说一下自己的护肤心得吧。 我认为最重要的就是防晒。因为紫外线过敏，从上大学开涂防晒霜，夏天会打伞，不让强光长时间照射皮肤。 接着就是日常护理了，没有科学依据，只讲自己的经验 1.吃，西北姑凉，喜欢吃酸辣口，爱吃水果和蔬菜，吃大碗面都喜欢放很多菜。不爱喝碳酸饮料，极少喝咖啡，正常喝茶。 2.作息，爱睡觉。十八岁之前每天最少十个小时，经常趴在课桌上睡觉。除了大学期间有两年喜欢通宵玩dota，白天也是会正常补觉。现在年龄大了，除非特殊情况，一般也都在十一点以前睡觉。 3.护肤品，近几年都是在用国货，主要是大牌用不起。。。泊美，za，肌研，豆乳，这样的平价护肤也用过，觉得洗面奶洗干净就好，水和乳液选好一点的。推荐两个好东东，上海牌的芦荟面膜，用着很舒服，补水效果也好，现在有点买不到了。za的隔离霜，挺轻薄的，不油，不厚。每天抹点就当日常防晒了。 4.护肤习惯，我每天只有晚上睡觉前是认真洗脸的，洗面奶洗两次，然后是水和乳液，或者面膜。早上起来用清水洗脸，我个人油分泌的不多，清水洗后剩余的油脂就是天然护肤品啦，涂上水，乳，隔离就可以出门了。定期做面膜，一周或者两周一次，我不用什么美容院啊高科技的蚕丝面膜，小时候是丁家宜，中期是上海，现在在用台湾产的一个什么医生。 最后呢就是心情啦，我是个乐观的姑娘，古龙说爱笑的女孩运气不会太差，开心的姑凉皮肤也不会太差，套用知乎老话，有些姑娘总摆着臭脸，都轮不到让别人注意观察她是否拥有好皮肤。 
祝每一位姑凉都能拥有好皮肤，更希望大家都有个好心情！


这如果是个爆照钓鱼贴，容本姑凉考虑考虑。
发布于 2015-02-25
SpongeMel
SpongeMel
高校辅导员/旅行迷/不吃好不高兴/拍照炫耀狂/买买买

本人刚毕业上班狗，90年人，爱吃辣和油腻的东西以及不爱运动（感觉自己没救了）。身体底子不好，体寒+胃病+心脏不好+内分泌失调，又以及懒+不爱运动，所以只能跌跌撞撞地活着………高考那一年不堪回首，半张脸长满痘痘（真的是长满，很多很红的小痘痘），而且肤色非常暗，闺蜜都叫我黄脸婆。那会儿就不上图了，上张现在的。（真的没磨皮美白，像素略渣）

生活习惯非常重要！生活习惯非常重要！生活习惯非常重要！前面说了心脏不好，一旦熬夜睡不好觉第二天巨难受。想想高三每天只有五六个小时可睡，皮肤不差才怪。现在当老师，每到假期基本每天都保持着10h左右的睡眠，上班时也基本晚上十点睡早上六点半起，真的是非常规律。不抽烟不喝酒，每天多喝水（觉得水不好喝就加花茶加柚子茶加大麦茶柠檬蜂蜜等等等等）。

想要脸，保养品肯定少不了。关于保养品我想说的是：别抠，别懒。只用一两样地摊货（或者图便宜买假货），三天打鱼两天晒网地用肯定难有效果。先来展示一下我家的化妆品柜。

下面进入正文了：我就按顺序说好了惹。相关产品我用【括号】标一下方便查找。
1.卸妆&洁面。卸妆的重要程度不用我说了。之前用【贝德玛卸妆水】，用了一整瓶感觉很舒服，可我偏偏也是个不甘寂寞的人，又入了【Nursery柚子卸妆】和【RMK玫瑰卸妆】，唯一的感触就是味道真的好好闻！！！！！！卸干净程度差异不大。我的个人习惯是晚上用洗面奶早上用洁面皂。洗面奶倾向于洗的很干净的那种，很讨厌滑腻感，推荐【兰蔻洗面奶】，【资生堂洗面奶】，【雅诗兰黛红石榴洗面奶】，【露得清洗面奶】。洁面皂就是【雪花秀宫中蜜皂】，已经用了两块。
2.精华。个人目前比较倾向肌底精华。用完了一瓶【雪花秀润燥精华】，目前正在用【Innisfree小绿瓶精华】，没有感觉效果很明显，但是用完真的感觉很舒服，皮肤很水嫩，后续也不会搓泥，这也许就是效果～～～拉入黑名单的是【娇韵诗恒润精华】，很油腻，味道也不喜欢，搭配娇韵诗同款面霜会搓泥 。夜间精华稍有不同，我一般用油状的，最早接触的是【摩洛哥阿甘油】，朋友出国带回，但某宝搜不到，这简直为我打开了新世纪的大门，用过第二天皮肤状态很好，真正是“水油平衡”。空瓶之后入了【科颜氏夜间修复精华素】，也是油状的，有薰衣草的味道。【乐敦VC精华】也用过，感觉多少有一点美白效果，想美白的不妨一试。
3.水&乳液。这个强烈建议成套入，不仅价格划算，同系列产品搭配使用可以达到1+1>2的效果。白天使用主要以保湿功能为主，一整天皮肤水润不脱妆就是大赢家！！美白的大多含有VC会感光，白天可能适得其反。不得不推荐【雪花秀滋阴套装】，正是这一套用完把我的皮肤维护在一个非常稳定的状态，不油腻保湿效果好，味道也很好闻。现在在用的是【雪肌精】，主要因为去年夏天晒的有点黑，想在下一个夏天来之前白回来hiahia～【雅诗兰黛红石榴套装】也用过，去黄效果是有的，但还是说，要坚持（这次去美国准备再入一套）。另外值得推荐的还有【科颜氏高保湿水】，【科颜氏高保湿面霜】，【倩碧水磁场】，【茱莉蔻玫瑰水】，【Naturie薏仁水】（这个推荐用做喷雾和泡纸膜）。
4.眼霜。【倩碧水磁场眼霜】用过一罐，感觉有点厚重。【雅诗兰黛ANR】眼霜是真爱，很轻薄水润，但功能感没有太明显。【FreezeFrame眼霜】正在路上，我黑眼圈有点重，这个微整形品牌据说效果不错，坐等～
5.防晒&隔离。这个一定要用的，皮肤一旦破坏了再修补可就不容易了。防晒首推【安耐晒】，晒不黑晒不伤。身体上我一般用喷雾，但真的晒的很黑了，此处不推荐……隔离（妆前乳）推【娇兰金箔妆前乳】和【娇兰珍珠妆前乳】，【Make up forever妆前乳】，修正肤色比较自然，也不会厚重。【香奈儿妆前乳】太厚了，而且涂上惨白。
6.粉底。超推荐【兰蔻气垫BB】，我觉得比韩国气垫好用一万倍～～～自用粉色那款，轻薄透气而且肤色很自然、也不会轻易脱妆，基本你皮肤瑕疵不多的话用这个轻松裸妆。已经用完两块了。不过仁者见仁，我有朋友觉得那个又贵又难用 。
7.清洁面膜。关于清洁我是有点强迫症的，其实清洁不干净再多保养品也是白费。目前常用的是【Fresh黄糖面膜】（去角质），【雪花秀撕拉面膜】，【About Me柠檬排毒膏】，【Suisai酵素洁面粉】，这些换着用，基本频率是2～3天一次，去角质一周一次。
8.其他面膜。【Fresh玫瑰面膜】是每次犯懒不想扑水涂精华和面霜的时候就洗完脸涂上这个睡觉。【Doctorcos爆水神器】是当晚霜用了，第二天早起皮肤超级白嫩。此外就是大把大把的韩国保湿or美白面膜，不过最近是真的懒一直没怎么用 



综上，希望有帮助～
发布于 2015-12-30
我耳闻的
我耳闻的
设计
多吃黄瓜补水噢
发布于 2016-10-13
贾萌萌懵懵
贾萌萌懵懵
西安天津切换

大一学生狗来怒答一发。我就是痘痘肌。严重到什么情况呢。前两天我室友跟我说。我刚来学校那阵。痘痘多到有点可怕。。。。亏我还一直感觉良好。不过现在好多了。基本只剩下痘印啦。（要知道痘印只要死磕美白精华就行啦啊）我就讲讲我的护肤步骤吧。

先从清洁开始吧。平时上学会涂个粉底。卸妆水买的是贝德玛的粉皮。很好用啊。可是看微博上有人说卸妆水对皮肤不好。so。不知道该不该推荐你们。。。卸完妆后就会赶紧去洗脸。我一直怕卸妆卸不干净。所以洁面乳买的是宝拉珍选的大地洁面。俗称绿鼻涕。如果雨天只涂了防晒的话。就直接用宝拉珍选卸掉。这个有卸妆功能。（但单用是有点不放心呢）。

之后就开始护肤啦。对于痘肌来说。less is more。不要涂太多层啊。baby。我呢。是先涂个神仙水。sk2。贵就是有贵的好啊。出油明显减少了。然后涂个ipsa自律乳。记得要用化妆棉擦拭啊亲。然后就用美白精华。我不是痘痘都好了吗。就开始祛痘印啦。我现在正在用的是城野医生的377美白精华。很温和。效果不好说。主要是我还没用多久。但是好多人都说有效果（好吧。我就是个跟风狗。摊手）。等我用这有效果再来追加吧哈啊。

你以为这样就完了吗。no。图样图森破。我还买了个美容仪器。不贵。wion（是这么拼吧）美白精华那么贵。不好好吸收了我就甩了她。（不可能啦）

最后。重点来啦（其实没有啦）按摩。很重要。就是手握成拳。按摩腮部（好怪啊！）两边肉会收着点。网上还有好多手法。自己学学就可以啦。还挺好学哒。

最最后。忘了说了。眼部。我现在在大西安上学。很干。摔。每天晚上都要涂眼霜。刚上大学那阵。买了好多彩妆。导致吃土。后来在网上看了好多功课。最后买了个美加净的眼霜。橙花的那个。旗舰店广网买的也不贵。五六十吧。我用了好久还没用完。到时我后来又买了牛油果眼霜。到现在还没有开瓶。n0。。。用无名指轻拍上眼。（第四个指头）没人不知道吧。完后再做眼保健操第四节。轮刮眼眶那个。（不知道我记得对不对）

最最最后。原谅我没有条理吧。涂上canmake的睫毛增长液。真的会变长。四五十一个。能用一个多月吧。然后拉上蚊帐。现在西安就有蚊子啦。睡觉吧。baby。

其实早睡比什么都重要。最重要的是还省钱啊。我就是个穷鬼。no。。。再然后就是运动。每天晚上跑跑步。不要想什么几公里。跑到累走会。再跑。坚持坚持。拉个人和你一起跑。那就更好啦。

女生嘛。只要坚信自己美美哒就会变美哈。。为你一碗鸡汤。加油吧少女。春风十里不如你。

最后感觉不上个图没什么说服力啊。好吧来了






我已经预警了啊






戴隐形好累啊。。。


好吧。正答是。。。找个可以把自己变得萌萌的的app啊

我玩这个都停不下来了。

一米七二的个子我妈老担心我找不到对象。红红火火。宝宝才不担心呢。因为我还是个宝宝啊。
希望看到这里的人都美美哒。momoda
编辑于 2016-09-12
大鳗君是个女人
大鳗君是个女人
芳疗爱好者 手工爱好者 超脱者

身边总会有些人会被我桌上的一大坨护肤品吓到，呀！！这么多你涂的的完么?是的，我涂不完，但是我在战痘战敏感的路途上也总结除了我的很多护肤心得，知道哪些产品适合我，这就够了，哈哈，我的护肤品基本上都不贵，一直觉得适合自己才重要，目标是追求性价比最高的护理品~

来嗮一下我的战利品，哦耶~
有很长的一段时间我都在长痘痘，痘痘最严重的时候绝望了，差不多毁容，别人的妈妈给自己的孩子打电话就是吃的怎么样，被子有木有盖厚一点，我妈每次打电话给我的第一句话就是你痘痘好点没有啊。不要乱吃外面油炸的，听多了感觉这是我和她之间最普通的问候语了。 心塞！
　　每次去商场经过化妆品柜会想哭。不想去见人，每个人见到都会说：阿！你怎么这样了 你就又要解释一遍。 
　　然后每个人都会说，我告诉你一个方法。很好用噢。。BLABLABLA = = 
　　逛街的时候任何发传单阿，去屈臣氏阿，都会有人上来说：小姐我们这有个产品很适合你噢。。去痘的。。 
　　！！！真是够了！！！ 
　　虽然现在不是皮肤特别好~~比不过那些从来不长痘的人，但是我已经非常非常满足了。 
　　写这个帖子之前想告诉你们，就算长痘痘也可以变回来。就算有一天你快毁容也不要放弃！！！真的！！！

　　写这个帖子是因为上次买过一瓶纯露后咨询掌柜长痘痘的事情。聊了很多关于护肤产品的东西，感觉自己以前用的一些产品存在很多误区，所以痘痘一直好不起来= =。所以鼓起勇气将这些分享写出来，警惕自己，也希望可以帮助到一些MM ~
　　我是到夏天就容易爆发的痘痘肌肤，还很敏感，想很久当初爆豆的原因。 
　　第一个是我用BB霜以后没有用卸妆油，拿洗面奶卸妆。现在想起来这种行为简直是！找死！
　　第二 我很爱吃辣，吃甜，不爱喝水，第三，三餐不规律，喜欢熬夜，喜欢在电脑面前
　　第三 我在长痘痘的时候还化妆，特别爱美，受不了不化妆的自己，唉，这样只会让豆豆恶化!!! 
　　第四 不做运动 
　　以上是我想到的大致原因，你们先参考一下对号入座。 
　　重症痘痘肌肤看这里 
　　如果你已经很严重，去看医生吧。没有化妆品保养品可以治好你的。 
　　有的人就是天生吃辣的晚睡还是皮肤好，体质原因决定我们不可能成为前者。。 
　　去专业的皮肤医院，挂个号听听医生的建议。 重症程度的只要找到根源和合适的方式。1个月之内会有非常显著的效果。 敏感肌最好换护肤品，换成药妆，理肤泉还可以，我当时用的另一种，下面有说。 
　　我是敏感型的中度痘痘~ 本该是如花似玉的年纪，就是因为痤疮毁了一张脸，当初每个星期去医院照红光蓝光。 一种光一次大概40-60块。据说可以深入肌肤杀死毛囊里的痘痘~ ! 
　　平时再做一些清洁矿物泥面膜，用了表姐推荐了一款薰衣草纯露舒缓，某宝的产品，第一次用就好舒服，纯天然薰衣草的味道，是喷雾型的设计，直接就可以喷到脸上，好方便，主要没有用过喷雾型的纯露，所以觉得很新奇！！！以前用过理肤泉的喷雾，那个是矿物质水，没有深层的用处，所以我后来就没用了···
　　喝的药, 最开始严重的时候医生开了一种叫泰尔丝的药给我，还说吃这个药一年内不能怀孕！！！就算怀孕了生出来的也是畸胎！！！我吓住了！
　　不过这个药的确有些效果，吃了后脸会变干，吃了一两个月后，他就不让我吃了，说吃多了对身体不好- - 我有些恐惧！！
　　换了另一种中成药叫做黄地养阴颗粒 
　　湿热解肺毒。每次快来月事时喝就太适合了，味道是偏甜的。喝下去整个人热热的，晚上睡觉很舒服。很养人。皮肤好的也推荐去买2盒回来放着，如果是每次大姨妈来的时候就爆豆，然后没消完下一次就又开始爆累计出来的，建议一天一次黄地养阴颗粒。涂下面会说的药膏。有复方芙蓉町和姜黄消痤计。药店有卖。不过药膏这种东西都是含有激素的，不能多涂，建议涂半月后，痘痘木有那么严重了就停掉，否则皮肤会依赖药膏，变激素脸！！！多喝水，少上网。上网的话半小时清水洗一次脸。可以用阿达帕林晚上擦全脸就没问题的。

　　嗯。。把我用到的药物 擦的吃的 做的治疗 和现在用的都慢慢写上来 你们有问题也可以直接留言~ 

卸妆篇
贝德玛卸妆水

我觉得油性肌肤最好选择卸妆水，因为这样卸妆皮肤不会容易油，贝德玛有粉色和蓝色的，粉色针对敏感肌肤用的，我是敏感痘痘肌，这里我说一下，一般长过痘痘的肌肤，皮肤都是偏敏感型的，所以选产品最好选择适合敏感肌肤的产品！！这款我已经用第二瓶了，貌似代购有港版和法版的，建议买法版，港版的只是一个说法，就是冒名的假货！！！现在假货太多了，坚持打假！！！！

凡西绿豆卸妆水
国产的牌子，性价比很高，挺清爽的，不过卸完之后脸很快就干了，可能滋润度不太够，建议卸完之后立刻洗脸涂霜，否则会很不舒服！

洗面奶篇 
痘痘肌肤对皮肤的清洁要求是非常高的。。要清洗干净又不可以太频繁~ 次数太多会洗掉保护面部的油脂 

理肤泉祛痘控油平衡洗面奶~ 

其实长痘痘的肌肤反而不能用特别丰富清洁力度太强的洗面奶，要选择那些洗完之后脸不会很紧绷的，因为长痘痘是发炎期，不能过度的做清洁，这款洗面奶洗了之后不会紧绷，泡沫也不会很多，最重要是很大瓶，吼吼，这个是法国代购，貌似国内的不是这样的包装~

薇诺娜 

这个要先解释一下这个牌子是药妆。我也是去了医院才知道。医生强烈推荐我用的。 除了雅漾的产品，这个我买的最多了。已经是第3瓶了。它是挤压出泡泡的，泡泡非常细腻。 去除油脂，抑制痘痘方面的效果很惊艳，如果痘痘状态较为严重且容易过敏的话我很推荐这一款。在淘宝也有商城。个人感觉适合晚上用。可以自己先购买小样试试。 

爽肤水
特安保湿水
调理过敏肌肤的最佳选择，我在木有痘痘状态下会用的保湿水

倩碧爽肤水
被很多人扒了说味道太难闻了···酒精味太重！！的确，痘痘非常严重的MM可以用一下，不过建议不要用太久，因为刺激性会比较大，毕竟长过痘痘的肌肤很容易变成敏感肌肤~
　　素耳薰衣草纯露
之前有用过薰衣草精油，不过精油纯度太高，涂脸上要进行稀释，所以就用了纯露，某宝的产品，被人种草了，本来不太喜欢在某宝上淘东西，既然有效果了，也木有副作用，那就无所谓了。

面霜篇
理肤泉特安面霜
比较油，很适合敏感干燥的肌肤，我两颊就是用这款，T字部位比较油，有些时候会搭配用理肤泉的祛痘乳，感觉性价比不是很高，用起来比较麻烦，不过它的包装挺精致的，吼吼！

素耳金缕梅甘草凝胶
这款是搭配薰衣草纯露一起用的，某宝淘过来的，主要是锁水的功能，超级好用，刚涂上去有些黏黏的，轻拍就吸收，用了一段时间痘痘真的都好了，神奇

面膜篇
DHC净白矿物泥面膜
无刺激无敏感，不过感觉也没什么效果，木有把毛孔深层的东西清出来，做完面膜之后还要自己对着镜子用工具请一下毛孔深层里的脏东西，我觉得所谓市面上的清洁面膜要么清的很干净可是刺激性比较大，要么无刺激，可是脏东西清不太出来，我说的对么？？！！良心建议清洁做好洗面奶这一块，如果洗头特别严重的，隔一个月去美容院做一次深层清洁（就是挑黑头），这个比价有针对性！！注意：去美容院不要办卡，可以团购的！！普通的深层清洁的很多美容院可以做的！！！

Bodyshop的维生素E面膜
睡眠面膜，有些油，我拿来当霜用，皮肤很干的时候，涂了睡觉，感觉涂太多练会有点难受，身边有些朋友说用了会长痘，我用了还好，建议隔个半个月用一次，皮肤补水还是需要的！

香水篇
原宿女孩
奶香味，比较适合冬天，温暖的味道。
发布于 2016-01-24
sherry
sherry
喜欢一只野生的喵

我得得瑟瑟过来答个题XD。

【黄瓜切片敷脸绝对有效的=￣ω￣=】
高中住校的时候我就经常周末批发黄瓜回寝室，当做消暑佳肴。
午睡之前用刮水果皮的小玩意把黄瓜皮刮下来，留着，吃掉中间又冰又甜又多汁的芯以后，把刚刚的皮拿过来，像裹木乃伊一样把脸和脖子缠起来。
ps:这里要注意一点是脖子也要敷，不然脸部和脖子差别对待，它会生气的（>_经济实惠，你值得拥有

【洗完澡全身涂润肤乳】
具体什么牌子哪种类型我就不说啦，毕竟肤质不一样，要选合适自己的。
身为南方人，在去东北读大学之前我一直都没有领悟到妈妈说的“要打香嘞崽啊”是多么正确…
当然脸也是要重点保护的，水，乳液，其他东西一个都不能放过。

【痘痘必杀大招:敷绿豆】
从小口味比较重，辣的和油重的没停过。每一次痘痘泛滥，就用这一招。
具体就是把绿豆熬烂，然后把泥敷在痘痘上面就可以了。
这一个也是经济实惠的~

【重点:多喝水！！】
就算用再好再贵的保养品，身体缺水的话还是不行的。
就酱ฅ●ω●ฅ～
发布于 2015-02-22
Cherry
Cherry
不考虑医美整容的前提下。用对护肤品以及多喝水多运动。防晒不能少，不能少，不能少。先上图，下图是今年4月份与今年8月份的对比图。都是苹果后置，未修图。

介绍下背景，坐标北方，经常出差，经常加班熬夜，天天对着电脑。以前韩国的护肤品几乎试遍了，但是没有一套完整用完的，只有兰芝基础补水用完过一套，依然很鸡肋。我也厌倦了为广告编织的梦买单。后来干脆破罐子破摔，早晨清水洗脸就出门，晚上也是。极度混油，毛孔粗，暗沉，起皮，风一吹脸两边就过敏，图一已经算是状态较好的时候。后来今年2月份吧，我突然觉得我做其他事情都那么执着一定要成功，为什么护肤和运动就是无法突破。于是开始买护肤品和运动，运动是五月份开始，也不是每天坚持，但是每周能保证两三天以上。重点说护肤吧，我用的品牌比较小众，很多是院线品牌，价格有高有低，但是都是这么久以来层层筛选的。
              卸妆，dermacept卸妆油，
1.首先是洁面，用的Dermacept 的铂金洁面泡沫，非常绵密，上脸按摩两分钟后包裹着脏东西，用水一冲温和而不失清洁力，后续吸收会更好。
2.打底精华，SAL抗氧化APP精华，水剂质地，上脸迅速吸收消失。
3.水，保湿补水的水。
4.打底精华，杜清乐肌底重建精华，油状质地，但是一点都不油，任何肤质适应，就是肌底重建，恢复皮肤的健康状态。
5.从这里开始才开始功效型的针对性的精华，我用的收毛孔的细胞再生精华。
6.眼霜。
7.面霜或精华乳，白天用清爽型面霜，晚上用滋润精华乳。
8.防晒！防晒！防晒！仅指白天。
大体就这样，手机码字着实累呀。现在皮肤首先很舒服很健康，不会敏感，不会起皮，不会大出油不会暗沉，其次也细了很多，前几天见一个客户，仅一年没见的，她见了我就惊讶的说你皮肤变好了很多，透白，而且还细了。哈哈开心，虽然跟天生好皮肤的没法比，但是有改进就不能停止脚步。
编辑于 2016-09-14
匿名用户
匿名用户
谢邀。
前话，多喝水少吃辣，多吃水果蔬菜，休息好，禁抽烟喝酒。
后话。
洁面开始——一定要好好卸妆。没有化妆也可以用卸妆膏来溶解油脂清理毛孔。推荐evelom卸妆膏和fancl卸妆油。彩妆重且不好卸的话可以配合美宝莲眼唇或者曼丹。正常的妆用前两个足够了。然后重要的还要用洁面。配合洗脸刷可以清洗的更干净。科莱丽或者feoro都挺好用的，洁面产品我用过蛮多的，推荐纪梵希dr white和sk2护肤洁面膏，平价款推荐freeplus和碧柔洁面泡。
水——痘痘肌油性首选sk2神仙水了，越大瓶越合算啊。250ml的1370rmb用三个月刚刚好。奥尔滨健康水也可以的330ml五六百。不过还是需要自身多喝水来保证水油平衡，你20不到，不需要功能性的护肤，多保湿就够了。
乳液——我自己用的是chanel十号乳液，是我目前用着比较顺的，下一瓶准备入全能乳液，等用上我再来写评论。。。平价款有用过minon保湿乳液，一百出头的价格挺合适的。也有用过肌研和契尔氏，肌研有点粘扔一边了，契尔氏太大瓶，而且特别油，一次一颗绿豆就够了根本用不完。。。
面霜——根据你的皮肤，推荐你用碧欧泉的活泉面霜，好像代购300块左右吧，保湿还可以。薇姿理肤泉也应该是适合你肤质的牌子。
精华——感觉精华是护肤的重点呀。毕竟最有营养的都在精华里了。自用的是chanel山茶花保湿微精华露810rmb 30ml，很舒服的质地，味道也清香。然后是欧舒丹的蜡菊精华1020rmb30ml和蜡菊精华油（我估计你20多以后才会考虑用）精华油是新出的，没多少人知道它好用，但是一个月会给你完全不同的肤质【画重点】一个月真的可以消除暗沉细化毛孔痘印什么的都会好很多。尽管它是油！但吸收完超级赞的！价格980rmb30ml。代购差不多七百。
面膜——雅漾的芙蓉蜜啊保湿一级棒，回购很多次了，超好用的，也很便宜，代购100多块钱。
发布于 2016-07-19
[已重置]
[已重置]
我自己的经验，调理皮肤不是一个一蹴而就的过程，给自己一年到两年的时间，定一个目标，然后坚持以下几个点：
1、饮食要有规划，不是说一定不能吃辛辣，但是最好每天都喝一碗燕麦
2、用对护肤品，不要买三无低档产品，也不必盲目去买高价大牌子，有些欧美大牌子其实不适合亚洲人肤质
3、每个月至少去一次美容院，能做到这一点其实自己就不用买什么特殊的保养品了。但是要去一些比较资深老牌的美容院，最好是全国连锁，例如娇莉芙、克丽缇娜、思妍丽这些
发布于 2015-05-23
abby
abby
运动每天五千米或者GYM一小时以上，喝豆浆（自己磨的，有小叶增生就别喝）规律的生活习惯和性生活，晚饭不吃，每天排便，不要乱用护肤品。
发布于 2015-03-10
闪闪发光
闪闪发光
一入护肤深似海啊QAQ
其实我觉得护肤品还是次要的，我想说的很重要的一点是饮食，皮肤很大程度上是你吃的东西的一个反映。
不知道题主是否有玩微博，这里我给博主推荐几个我觉得比较好的营养学的博主
1.范志红_原创营养信息
2.营养师顾中一
虽然我不长痘痘，可是我个人感觉长痘痘就别吃辣了，别吃零食。
还有，运动也非常重要，我感觉护肤，健身，这两个主题都是相互联系的，不论如何，都是为了让自己变的更好嘛。
所以在这里再推荐几个博主：
1.kenjijoel 超大神超男神不多说了。
2.superfood 女王
3.小仙儿要做企业家
4.我就是小机灵啊
5.Jiessie_D 
5.Healthy_Fitness
6.健身厨男
7.马甲县吕夏夏
8.lolapola 
其实我想这些博主分享的不仅仅是护肤健身的信息，更是一种积极向上的健康的生活态度，要记得，瘦身，皮肤好，都是你努力生活的一个附带品。
发布于 2015-03-06
匿名用户
匿名用户
18岁还嫩的很呢！我大学前一直都是糙妹子，只知道往脸上擦大宝只是因为脸干的疼！天生就是黑，从小到大没白过，不懂什么是爱美！而且我妈妈就是觉得我长的不好看，爱美不是光荣的事，不喜欢我捯饬！我就特羡慕我闺蜜，她妈妈都是想着法让她闺女变美，经常给很惊人的建议，我那时羡慕的不行。不过妹子我真正开始护肤也是因为已经糙见底了！我妈常说我是不是藏区朋友…皮肤黑，脸颊还有高原红…从小雀斑，不过因为黑，也不明显 …回正题，我真正开始护肤，自己也是没有什么计划，第一步就是想变白，从此一把天堂太阳伞不离手，za隔离天天摸，偶尔肌研爽肤水或者乳液，（我发誓我这辈子唯一十年如一日坚持了8年的事情就是护肤了，其实这些目的总结起来就是防晒！补水！仅此）记住，要坚持你想买一款产品一周一个月马上改善肤质是不可能的，一定要慢慢来！我不记得是什么时候开始，反正现在陌生人见我经常问我是不是四川妹子，皮肤那么好。当年学生党穷，这些钱都是自己生活费抠出来的，也是当年比较火的平价产品   如今自己工作了，购买能力大大提升以后虽然也迷失一段时间想尝遍一线，贵妇，明星产品，最后发现只是苦了钱包而已。，不适合，再贵也不用 。这些都是8.9年的事情了，自己也走过弯路，一言难尽，我表达不佳，只是想说，护肤品不在价格，重要是要适度 。
发布于 2015-02-22
Amber
Amber
契约关系不谈感情。

我，痘油敏喝喝，看了之前很多JMS的经验之谈，基本是离不开几大要素：
一，清洁：洁面和清洁面膜，概念就不累述啦，就给大家推荐各类皮肤口碑较好清洁力不错的单品，全部都是用过的不踩雷~

先说干性及混合肌肤：现在最火的氨基酸洁面， elta MD 泡沫洁面乳，日本的绢丝洁面有卸妆功效，还有台湾的UNT，日本药妆芙丽芳丝，sk2的氨基酸洁面。对氨基酸洁面无爱的妹子可以考虑shuuemura睡莲慕斯，Origins一举两得。韩国SU:M37呼吸的海洋精华洁面膏，whoo的平衡洁面都没问题

油性肌肤（大油田）：Sulwhasoo宫中蜜皂，whoo的平衡洁面，Origins一举两得
大油田真的要选好洁面，补水做好，一周1-2次清洁

清洁面膜：油性肌肤首推贝佳斯绿泥，这几年觉得最好用的没有之一！724性价比太低，并且觉得724的很多产品都很鸡肋。2333跑题建议用完敷一个补水面膜，缓解干燥！

混合肌肤及干性肌肤：英国Sudocrem屁屁霜，这个建议敷面20-30分钟以上，敷时间短了没效果时间长了长脂肪粒，它主要亮点是敏感肌肤可以用。Sulwhasoo的玉容面膜（非常温和的撕拉类面膜，不会拉大毛孔！再就是DMC冻膜，我基本都是用手往脸上抓，敷的厚厚的！清洁效果特别棒！

二，保养及美白还有祛痘
干性健康肌肤：
 主打保湿水：兰嘉丝汀粉水，伊思蜗牛水2号， 兰蔻粉水，724高保湿水，Origins菌菇水（控痘也不错）
 主打保湿乳：chanel山茶花，珂润保湿乳，SANA豆乳

混油肌肤保湿水：ALBION健康水，AQ紫苏水，HERA神仙水，薏仁水（据说日本原产的薏仁水和ALBION健康水成分差不多！）
混油肌肤保湿乳：JUJU玻尿酸乳，AH果酸乳（健康肌考虑，不然会不耐受，AHA会达到10% ，但保湿抗痘收毛孔）

油性肌肤保湿水：ALBION健康水，sk2神仙水，薏仁水，724小黄瓜，juju玻尿酸水
油性肌肤保湿乳：whoo粉乳，EA 24小时乳，原谅我是一个用了各种精华的人，对乳用的不是太多
美白：资生堂haku精华及面膜，乐敦CC水及精华，kose雪水,sk2极效超净斑！
祛痘：chanel的周末焕肤BHA刷酸，比较温和。AQ的晶透角质调理露，ALBION健康水及初级渗透乳 Origins菌菇水以及精华+面膜，whoo郁安瓶精华，很重要的一点，刷酸对痘肌效果很棒，但是第二天一定要做好防晒！！不然会破坏角质层！
三，防晒
脸部
大名鼎鼎的安热沙（安耐晒被你国人民抢先注册了名字，跟724当年一样悲剧）防水防汗建议卸妆
资生堂旗下还有一款艳阳夏，特别油的肌肤，如果追求防护效果，可以考虑。如果追求使用感受层面的完美建议考虑安耐晒。防水防汗轻微润色
碧柔小蓝：清爽无油不防水，不用卸妆，油皮优先考虑
Kanebo嘉娜宝 ALLIE：清爽，酒精味重，不防水，轻微润色
近江蓝小熊：防水防汗不用卸妆~5岁以上儿童可用
Cosme大赏 NARIS UP Parasola 喷雾：今年突然就火了？护肤类防晒，能喷脸啊头发啊身体，不耐用，基本喷胳膊和大腿的话3-5次。略油，轻微润色
身体
个人觉得身体用涂抹的费劲死了，暂时就建议露得清防晒喷雾。防晒类产品建议每隔2-3个小时补一次。
四。作息及饮食
呵呵还真是处女座，说别人头头是道，自己从来不照做。姑娘们早睡是基本，饮食少辣少油少凉。最重要！一定要运动出汗！事实证明我跑了一个月的步脸上的痘痘基本全干净了，当然因人而异，但是多排毒总是没错的，差不多6分靠自身4分靠保养，下班啦今天码到这里，有哪里说的不完善的欢迎指正补充么么哒。
发布于 2015-06-28
青南
青南
https://kingname.info 推荐系统/大数据。
来成都。
发布于 2015-10-10
美誓懒懒
美誓懒懒
爱分享的美妆购物狂，推广勿扰

37岁，头像手残自拍阳光下美图1格微调。13岁开始历经你们能想到的除了斑以外的所有问题。用过5000➕护肤彩妆内服。没用过任何医美手段。以上为背景。

随便放一张今年用的产品图证明非吹非黑。
想要皮肤好，三分外用七分调。
1:外用.
找准皮肤类型，并且认识到皮肤类型是变化的，随季节不同护肤方法也不同。对肤用品才是王道。
less is more ，不要左一层右一层涂各种。有些姑娘一天要往脸上涂几十层东西耗时两三个小时。

这样做费钱费力不说，一个不小心还容易毁脸。
没必要，老老实实针对肤质做好卸妆深层清洁，保湿，修复，防晒，然后根据需要添加精华和特殊功效保养品。搭配个美容仪，整体皮肤就差不到哪里去。
2.内调
内调包括必需营养素补充，排毒，功效型内调。别扯什么玄学问题说都没用，十几年内服经验的大活人实证有效。为啥？因为绝大多数姑娘饮食都既不健康也不够量，不补充，营养哪里来？

但是也不能乱补充，一天一把药光 都吃饱了。
必需补充剂.综合维生素，复合维生素b族，葡萄籽类抗氧化产品。
这可以让你营养均衡不大量脱发皮肤不粗糙抗氧化提亮。
排毒.桃胶➕皂角米➕银耳➕蜂蜜，排毒类酵素
可以帮你清理肠道残渣。
功效型内调.看自己需要什么功效，常见的抗糖化抗氧化补充氨基酸玻尿酸等，比较实用。
内调原则.必需的每天吃，其他的先排毒后功效，我是吃三个月休一个月。

其他的，每天3升水，想起来就喝。尽量保持睡眠。
这把年纪了，每天护肤时间平均不超过一刻钟，除了有轻微泪沟法令纹没啥别的问题，也是很满意了。
第一次用知乎，喜欢欢迎关注点赞，有人看我就继续分享更多的踩着大坑的血泪总结喔。
发布于 2017-07-23
心之所想
心之所想
竟然没有兴趣
自己喜欢研究护肤品，为了这张脸看了好多书，甚至毕业专业论文也看过了。


最初的时候，对别人的观点，要么全盘接受要么全部否定，但如果，身边有两种截然相反的观点，且两人都属于权威保养得当的人，那你应该信谁？
在我们的生活中，有一些概念，是可以重叠累加的接受，而有些注定没有权威化的答案。这种时候，选择一种能够说服自己相信的，接受，并且暂且深信不疑。 


刷酸
一个朋友说，她自己diy刷酸，果酸水杨酸都试过，我听完虎躯一震，还好，她的皮肤还算健康，没被折腾的敏感。
最初的我，肯定会敢于马上操刀就尝试。刷酸浪潮刚开始，我也荣幸地赶上了这股潮流，特别是看完宝拉的书，但刷完对于我无功无过，也就没有坚持。
后来遇到一位皮肤科医生，她特别反对刷酸，她认为这些破坏皮肤表皮层的做法非常不可取，在芳疗百科、宝拉的书里中也写到，只要不人为刺激破坏皮肤，你就会看到它强大的恢复能力。
自此，我再没有尝试过刷酸。我认为，刷酸去角质可能确有其效，但浓度需要好好控制，同时还需要持续性，后续产品的跟进，做足防晒，不能化妆饮食节制等等，而我承认，我是个没有毅力的人，且我对刷酸存疑，放弃是最佳选择。

关于颈霜的涂抹手法（来源于 “鸢尾花期”的故事）
从我知道有这种产品的存在以来，我就坚信，这个东西，应该是从下到上的涂抹方式。这样的看法来源于各大美容论坛、美容院和曾经购买过的一些产品中详细的说明。因此，我相信，这个说法是无比正确的。 
但是，在娇韵诗的专柜，我第一次听到了完全不同的声音。娇家的BA，我所遇到过的，无一例外，在讲述手法的时候，都多次强调，颈霜应该由下巴部位朝胸部，以推拿的方式进行按摩。在面对我的疑问时，她们的解释是：推拿的手法，可以将下巴到脖子的皱纹抚平的同时，也是将脖子、肩膀这些部位的少量脂肪推往胸部，而如果从下而上，则很可能推拿出双下巴。。。。
这样的观点，我第一次听到，但是，它竟然让我觉得很有道理。于是，回家以后，我与一些朋友进行了讨论，到底颈霜应该如何涂抹？从下到上，还是从上到下？很明显，这些同样经历过无数产品的人，也都开始觉得动摇，不知道坚持了多年的从下而上，是否正确，甚至还有一个美女开始怀疑，自己近年来新产生的双下巴，是否与颈霜的使用方法有关？ 
怀疑归怀疑，颈霜还是要用的，但是到底相信哪一种观念？到底选择哪一种方式进行使用？在经过了10分钟的思考以后，LZ毫不犹豫地选择了从上而下，倒不是真的害怕双下巴，而是LZ决定，既然在用娇韵诗，那么，就遵循它家提倡的手法吧，用其他产品的时候，再换回从下而上。 
事实上，那一整瓶颈霜用的我十分纠结，每天，就在使用方法上纠结万分。导致的结果是，每次从上而下的预防了双下巴以后，等它彻底吸收，LZ总是忍不住再用两只手在脖子上做几个向上提拉和轻弹得动作。 
而曾经和LZ一起讨论过这个问题的一个朋友，在一个月后告诉LZ：自从听你说了娇韵诗那里的按摩手法以后，我想来想去，实在不知道朝上还是朝下，现在，我已经采取按压的方式了。。。。。。。。最多，我就横着按摩我那条纹。。。。。。。。 
这个问题，我曾经咨询过不少相关的人士，企图寻找到一个完美的答案，因为在当时，这是我第一次遇到两种相逆反观念的碰撞。最终我发现，尽管更多的人都认为，市面上的大部分颈霜都应该遵循从下而上的涂抹方式。但是，不可否认的是，也许娇家的产品确实需要那样的使用手法。而且，不少人都对从上而下的方法是否可能会双向解决双下巴及胸部产生了巨大兴趣 
对于这一点，后来LZ渐渐坚定了一个观点：从下而上。 
为什么？ 
因为LZ意识到一个重要的问题。从下而上，是大多数JM甚至LZ自己，都熟悉的方式，而且手法并不复杂，然而娇家的那套理念，且不说可能性是否成立，更重要的是，即使它成立，肯定也需要比较专业的手法，才能达到相关的效果。手法错误，也许就适得其反。产品有很多，方法也有很多，但是，我们的脸只有这么一张，我们的皮肤经不起太多的错误，所以，不要去盲目的赌博。 
很多时候，少伤害，就已经是最好的保养方式。

关于夜间护肤的加减
这是一个很让我困扰的问题。
最初我赞成夜间吸收力加强，需要层层涂抹，睡眠面膜也是必备的。于是，在涂了水精华眼霜乳后，还恨不得加霜加面膜。先生说，涂这么多皮肤不累么？我一时语塞。
我有一个大学室友，一直坚持晚上是皮肤呼吸的时候，只涂一层水，无论宿舍女孩子对她怎么"威胁利诱"都无法动摇她的观念。现在她皮肤还不错。
皮肤主宰呼吸排泄，最终我决定放弃原来的加法做减法，来源于朋友的一句话，她说任何东西都是有分子运动的，化妆品涂在脸上你看不到什么，但它也会和皮肤分子产生运动，不然怎么叫化妆品？那么多层，你都不知道脸上在经历些什么故事，更何况，高营养把脸上的细菌都喂饱了。
ok，我接受了。
从此不再纠结，晚上洗完脸涂个乳就睡了，皮肤也很稳定。

关于皮肤按摩
在spa店，老师帮我们按得好舒服，做完出来整个人光彩如新，这时候老师也会推加我们买一瓶油回去自己按按。
西方的观点，觉得衰老来源于面部表情，按摩会将衰老提前送到我们身边，而东方人认为人体面部有许多经络，经常按摩有助于疏通经络堵塞的垃圾，让面色红润年轻。
生活中也遇到这两类人，她们皮肤都不错，无论按与不按，这取决于自己。
刚开始我选择按摩，想起来摸一把脸，还会用牛角梳按摩苹果肌，可效果平平，只有刚刚按过皮肤好像紧致了点，可不多久就恢复了。我有一个有点胖的女同学，脸颊的苹果肌有点下垂迹象，她于是想起来就做一次提拉，干手也搓，然而似乎没有什么效果。
所以，我选择了放弃按摩。
因为，几乎所有的产品使用说明书都写了轻轻按压或轻涂于面部，那么我就按说明来吧，更重要的是，自己没有毅力，又急功近利，看不到效果便焦虑。
按摩这点时间用来做平板支撑还是不错的。
身体按摩也是同理，做了一次淋巴排毒，特别是腋下，疼得我咬牙切齿，做完后，两块出现了不同程度的红斑，老师说这是因为平时穿内衣压迫的，血液运行不畅。一会就会觉得很舒服。
可是，并没有很轻松，夜里疼的辗转反侧。后来跟一位西医聊起这段经历，她轻描淡写地说，那不是排毒，那是造成了表面擦伤之类的，我忘记那个词，说你即便经常去做，你还是会有拍不完的毒。
这里特别想提醒一下去美容院的女孩子，在美容院进行按摩的时候，一定让美容师尽量以轻柔的手法来按摩，自己在家也要轻柔按摩时间不宜过长，且需要长期坚持。
现在电商很发达，好多女孩子都在上面购物，我也是，但是好多按摩产品需要专柜BA示范，即便不买也需要装成买的样子，去学一学，这样才不会浪费好东西。

http://weixin.qq.com/r/dEQ1LeXEibj2raFO9xFm (二维码自动识别)

创建于 22:39
著作权归作者所有
发布于 2016-10-26
吧嗒吧嗒
吧嗒吧嗒

今年28-从上大学就各种捯饬护肤品，美容仪，及其爱吃水果就是不爱动。但是皮肤一直一般般 根本对不起脸上的几千块好么（虽然也并不很多）
特别是法令纹，由于我本身颧骨略高，苹果肌略大，法令纹那个深啊，我能说我曾经天天靠眼膜保持么..
后来开始跑步，水果也不常吃，每天喝蜂蜜水，效果居然好的不行，最起码法令纹已经很轻了，整个脸部皮肤都很紧实，nuface也不用了～
发布于 2016-05-05
諳啡
諳啡
寻寻觅觅
每天晚上洗完脸之后，涂一层芦荟胶，然后去跑步，至少五公里，然后洗澡，涂眼霜，晚霜，十点半前睡觉。坚持一个月，一定大有改善。本人亲测有效。对了，如果一吃辣就爆痘的还是忌个口吧，如果不嫌麻烦能泡脚那就更好了～
发布于 2016-04-03
发完神经就睡觉
发完神经就睡觉
简单就好
        前一段时间爆痘痘和闭口，觉得比爆痘更恐怖好吗！那一颗一颗突出来的异物感，分分钟想像刮青瓜一样刮干净！！！为了消除这些痘痘和闭口，我又百度又天涯的，马克了不少大家力荐的护肤品，就等哪天托朋友买买买了，还好终于有一天醒悟过来了：我冒痘长闭口不用药物治疗，还使劲买个毛线的护肤品啊！！！于是果断转头上网搜去痘痘闭口的药膏，通过自己总结出来的方法终于把痘痘闭口压下去了，不容易啊……方法现在贡献出来，大家记得点赞哦～
        首先，用两根棉签把痘痘闭口里面的脓挤掉（我是信奉挤痘痘才会好的人，不挤痘痘，难道让脓自己消化回皮肤里咩！）要不断换棉签去挤，不然脏脏的棉签继续用也是蛮恶心的，也容易感染细菌……接着用新的棉签蘸痤康王的克林霉素甲硝唑搽剂（实物图在最下面）涂在刚挤完痘痘闭口的地方，接着该干啥就干啥去吧～另外，一切护肤品化妆品都停用！！！每天早上晚上清水洗脸后就开始我上述的方法祛痘，等到后面快好的时候，找不到闭口痘痘挤，我也是挺失落的，哈哈哈哈
        上述方法只对我个人生效，大家三思后再采用，一旦毁容，本人概不负责……！！！
编辑于 2015-10-13
李梦
李梦

多喝水，早睡早起才是王道，不要说什么我这样做了，我皮肤还是不好，坚持好吗，重要的事说三遍，坚持坚持坚持     

喝水最好小口喝，白开最好

再就是基本的保湿，防晒，清洁

恩就酱
潜水了这么久，第一次回答，希望这可以帮到看到的人
发布于 2015-10-10
李佳萱
李佳萱
喜欢跟有趣的人玩儿

坚持运动
坚持运动
坚持运动

不要熬夜
不要熬夜
不要熬夜

再懒也不要带妆睡觉
再懒也不要带妆睡觉
再懒也不要带妆睡觉


重要的事情一定要说三遍哒~
昨晚回家太累倒头就睡，结果今早起床一看我的妈呀╮(╯▽╰)╭
暗黄粗糙眼睛无神全脸肿的跟包子一样
果然懒是没有好下场的
所以要想有好皮肤 千万不能懒
内调外养总是没错的
护肤品永远大于彩妆
多多运动才能更加分
不然你以为那些女神的好皮肤都是天生丽质的吗
别开玩笑了
发布于 2015-10-06
知乎用户
知乎用户
上个世纪末生人
早晚两顿粥，中午别吃辣，只擦隔离防晒不化浓妆，一个月下来皮肤变好体重减轻。
发布于 2015-03-02
王大王
王大王
只学习，不说话
先说结论：夜间长跑———————————————研究对象：我自己（现在还有我女朋友）———————————————————————————————————在中医望诊里有个词叫做“色泽”，色就是肤色，泽就是光泽。肤色天注定，光泽才是根本。就算肤色黑，只要有光泽，那你也像吉克隽逸似的( ´▽` )。就算皮肤再白，没了光泽那就是贞子了。————————————————————————————————————————————————————————————————————————————对于我女朋友（各种女人）的各
种化妆品（美白补水类），我都嗤之以鼻的눈_눈，因为我觉得那都是本末倒置，我们老师把人体比作池塘，你说如果池塘变成了死水，你再是怎么补水怎么清理，池水变臭也是时间问题，只有从池塘本身入手，才能解决问题（例子我改过，不是很贴切，意会就行）——————————————————————————————————————————————————————没流量了，回宿舍再继续吧。。。。
发布于 2015-06-05
Dr.ACNE痘院长
Dr.ACNE痘院长
精专祛痘●三十连城●百家连锁
帮你分析了 几点 


1.皮肤的角质层比较厚，正常的皮肤一般28天 为一个代谢的周期，而代谢的 老化角质却没  正常脱落，所以会出现角质层增厚的现象，那么会导致皮肤腺体的 油脂和废物无法正常排异出来 ，堵塞毛孔，从而发炎，红肿长痘，另外老化的角质会使肤色看  上去暗淡没光泽。


2.清洁不 彻底


3.色素不 均匀是因为T区的角质相对两颊来说更厚重，【角质就是皮肤最外层组织】平常没  注重防晒，紫外线照射导致黑色素分泌不均匀也是问题存在原因.这是外在的 几点因素 建议痘痘很 严重的 话可以去看下中医内在是 什么 因素引起的，配合吃中药内调才是  根本，而且那种中药都 很便宜的.　　
解决办法



1.定期给皮肤去角质，特别是T区【额头 鼻子一直到嘴下】可2天去一次，脸上前期可3天祛一次，后期一个  星期去一次　　


2.洁面乳可用泡沫比较丰富的，清洁力度会更强


3.最好去专业的美容院请美容师帮你（痘院长全国连锁）  清理痘痘，自己弄的 话要 注意力度　　


4.清洁完后用蛋清按摩脸部，15分钟　　


5.用剩余的 蛋清加半支香蕉加适量的  珍珠粉调匀后敷到脸上，前期2天敷一次 直到好转为止　　一般2个星期就会有明显的 效果，
祝你早日摆脱面子上的问题. 
发布于 2017-05-22
匿名用户
匿名用户
表示我自己不抽烟不喝酒的时候 皮肤很棒很棒很棒 从没有痘痘红血丝 黑头也零星几颗 如果不是凑近10厘米以内根本看不出 放图吧 毫无美图过
然后 早睡真的很重要 我熬夜抽烟喝酒 现在皮肤已经开始走下坡路了
虽然我回答的似乎和题目没有什么关系 但我主要想表达的是保持良好习惯 会对皮肤有很大的帮助 心情也是很重要的 不 超重要
发布于 2015-10-06
某仙女
某仙女
阳光打在我身上

有很多方法可以让皮肤变好

适合自己的才是最好的。不是每个方法都适合你，但选对方法效果可能会事半功倍。

每个人的皮肤类型不一样，比如有干性、油性、敏感性、混合性、中性常见的五大类。

可以根据下图去百度搜索判断下自己属于哪种类型皮肤从而对症下药。


那说说每种皮肤类型的优势和劣势和特征以及护理方法

一：干性皮肤
优势：皮肤细腻，不易长痘，不易出油。
劣质：容易干燥起皮，长皱纹，长斑，容易肤色暗黄。

护理：
1:首先肯定是多补水啦
2:选择温和不刺激护肤品
3:做好防晒工作

二：油性皮肤
优势：不易长皱纹，不易干燥起皮
劣势：油脂分泌过多，容易毛孔堵塞，从而长痘，毛孔粗大，有黑头、粉刺、暗疮等问题

护理：
1:注意清洁干净皮肤
2:皮肤表面容易吸附灰尘，要擦隔离
3:多补水，皮肤水油不平衡

三：敏感性皮肤
属于问题性皮肤，角质层薄
特征：
1:红血丝
2:过冷过热，皮肤都容易泛红、发热
3:容易受环境、季节变化、化妆品影响

护理：
1:不用清洁力很强的清洁产品
2:洗脸不要太频，一天最好不超过两次
3:温水洗脸最佳
4:少使用祛角质的产品
5:护肤品用添加剂少的


四：混合性皮肤
特征：
1:额头、鼻子、下颌处于油性肤质，脸颊处于干性肤质，这种皮肤不好护理

护理：
1:用清洁力强的洗面奶清洁额头、鼻子、下颌。可用冷热水交替洗脸，温热水清洁额头、鼻子、下颌，冷水清洁整个面部


五：中性皮肤
中性皮肤是健康理想的皮肤，皮脂分泌量适中，介于干性油性皮肤之间，成年人中性皮肤的比较少

特征：
1:含水量适中
2:毛孔细小
3:夏季趋于油性，冬季趋于干性

护理：
一般不需要特别的护理
1:一天清洁两次面部为宜
2:注意卸妆
3:基础护理

— — — — — —

选择护肤品太重要了，每个人适合的护肤品不一样，我也就不推荐了，免得被说打广告。还是那句话适合自己的才是最好的！！！

但并不是所有人就护肤品就能够让皮肤变好的
还有以下方法可以借鉴：
皮肤的状态和身体健康状况是有很大联系的




泡澡。
这个有好多种，可以去网上查找，有的可以调理身体，有的美容养颜




练瑜伽
能够有效提升内分泌，加速新陈代谢和血液循环，修复受损组织，促进皮肤内的胶原蛋白再生，而且还可以帮助排出体内的毒素和废物

运动
这个应该都知道，就不多说了

食补
食疗比较慢，要坚持

— — — — — —

（以上文字说的是大体特征情况，不包括个别情况，凡事不绝对。我不是学皮肤生理学的，也不是卖化妆品护肤品的。这段时间有查资料和咨询专业人士以及自己一点护肤的经验作为分享）


— — — — — —
呼～
编辑于 2017-12-25
我在水里
我在水里
我在水里

先上一张对比图
可能引起不适
从小皮肤一直挺好的没什么问题，一进大学，各种莫名其妙的护肤品都往脸上抹，再加上水土不服，清洁不到位，长了满脸痘痘。
（为什么找不到我的图！！）

太可怕了太可怕，再次看到这个照片我心里还是一颤，真实的情况只有更严重！上的图还是症状减轻的时候，严重的时候满脸脓包痘痘根本没勇气拍照，自己看到都想吐。


（这是现在的状态啦，虽然还有一些痘印，状态也没高中时期好，但是和长痘痘那会儿是天壤之别了）在这里我要挂一个倩碧紫水也就是2号水，一生黑，说起来都是泪，我身边也有很多女生，用了这个皮肤各种出问题，因为这个水强力去角质，宣传的二次清洁，每次用化妆棉擦都会出现一些黑黑的或者黄黄的东西，年少无知的我还心里窃喜，脏东西都去除了！耶！但其实，皮肤的屏障都被打碎了，我去检查发现角质层已经薄的不能再薄了。
我长痘痘的状态起码持续了近两年。
然后我用过很多医生给开的药，也包含有激素的，我看到含量有激素就没有去用，另外，其他答主提到的维a什么的药膏我也全都用过，一点都没用，这种东西因人而异，我也只是提供多一种方法而已，有一种药膏我还因为用的太多，刺痛红肿。狮王的祛痘膏也买过，鸡肋。
后来开始尝试中药，但也只持续了一个疗程，大概一两周，也没有效果。
起床吃饭了，也不知道有没有人看，晚点更

（就用我嘎的美颜分割吧）


后来呢，我大学同学，一个很可爱的女孩子，也是大学以后各种长痘痘，她和我推荐了一个牌子，好像是叫小米吧，就叫祛痘膏，还是个微商，其实挺贵的，一百块一盒，里面就一点点用不了几次，特别是我这种满脸痘的，基本三四次就没了。

（涂起来就是我右脸的效果）但是真的稍微有点效果，开始我觉得很忐忑，我怕这种东西没保障，想想皮肤都这种鬼样子了还能多差，我就用了。一点点的有好转，这个祛痘膏很奇怪，就是膏状，扣一块涂上去不要按摩，不然就掉了，第二天会干了有点粉状洗掉就好了，有种珍珠粉加了一点凝露的效果，我觉得还有点美白效果，味道很香，别人闻说有点中药的味道，可是我觉得超香第一次涂起来香的睡不着。（刚刚退出去想看看成分为什么那么香，结果发现买的淘宝店已经不存在了）
然后我翻了翻最初加的那个微商的微信，还出了各种新产品，已经从护肤到洗护产品了，我用的那个祛痘膏还升级了，据说已经没有那个我说的珍珠粉状了，哈哈哈哈因为她天天刷屏我很早就屏蔽了，看了一下淘宝买了四盒，微信上买了几盒已经忘记了，真的是那种很典型的微商，发的广告让人不想看还常常发一些爆痘的图，总勾起我不好的回忆哈哈哈哈，但是不得不说是我皮肤恢复的转折点。（写上转折点之后觉得自己在编写教科书般厉害，类似于斯大林格勒是什么什么转折点）
之后，我用了后的万能膏。
真的很好，巨好，感觉让我的皮肤到达了稳定期，痘痘都消了而且一直都没再长，虽然第一次用我就过敏了，我也不太确定是不是就是万能膏致敏，过了挺长一段时间，我才鼓起勇气再用一次，感觉很好，虽然油油的一脸，每次我都睡前涂一层有痘痘地方涂厚一点，痘痘会瘪下去，好棒。
然后，剩下的就是痘印和痘坑了。
这里最最推荐大葡萄的美白淡斑精华，美白效果立竿见影，空瓶会回购。我觉得淡斑和痘印差不多买的反正就是这么想的。嘿嘿但是效果意外的好。
好到我挂一下淘宝随便搜的图。第一条评论问我是不是广告，我很桑心，真的。反正东西你自己买啊，我又不会赚钱，或者说不信的话就看看过了，不然右滑吧……呜呜呜
痘坑这种东西就没办法了，去医美吧，等我有钱！！
编辑于 2017-08-16
匿名用户
匿名用户
在你护肤正常的情况下，防晒和早睡不上火就是最好的办法。
编辑于 2017-08-09
知乎用户
知乎用户

真心想要皮肤好，内调比外养重要。

意思是，护肤品的作用有限，并不像广告里那么功效神奇。不过外油内干的话，补水控油还是挺重要的。

养成早睡的习惯，千万不要熬夜。戒断油炸食品以及一切高油高糖的零食。口味清淡，吃任何菜都少油少盐少糖，学会品尝蔬菜的原味。平时没事儿的时候煲点银耳莲子汤什么的，对了，你说你有痘痘？那多吃点薏苡仁红豆粥嘛。这些看上去很容易做到吧？坚持几年甚至一直坚持下去并不容易，但亲测有效。身体调理好了，睡眠充足了，随便抹点什么都光彩照人呢~
但愿你的皮肤尽快变好，美美的~
发布于 2015-11-20
Z325
Z325
把知乎当微博。
有时候皮肤好也是靠遗传的。
发布于 2015-10-12
海狗
海狗
HR/应用心理学
《暗黑者》告诉我们，答案必须是喝酸奶。男主凭借第一季喝了一整季的酸奶后，脸成功在第二季变好了！
发布于 2015-08-21
唐宝儿
唐宝儿
分歧者，地产业，一级建造师，中年失业妇女。（作为一个抑郁倾向者还想加上废物二字）
这个我非常有发言权。
之前在南方或海边城市，皮肤状态好的不得了，一天下来皮肤不知道什么是油。
回到北方，大油田，毛孔增大。。。其实原因很简单，南方湿润，北方干燥。通过我的观察，北方姑娘皮肤好的少，十个有一个，而南方姑娘相反。
北方的姑娘，油皮很多，原因无一例外是缺水，想补水这点是任何化妆品都做不到的，唯一的秘密武器就是家中，公司自备一台加湿器，保证每天皮肤水水的。车里能有一台就更完美了。
我已试用十天，皮肤光滑了很多。记得备个温湿度计，湿度40%以上是最低要求。尤其在有空调的时候，一定要补足。
绝对好过买各种化学品在脸上乱涂。
发布于 2015-06-28
陈瑾瑜
陈瑾瑜
你不能用一个青春的时光悼念青春，再用一个老去的时光害怕老去。

妹子的皮肤状况跟我蛮像的，所以来分享一下自己的心得。

       皮肤的调理需要内外兼施。内部的话无非是内分泌系统的正常运转，需要靠忌口、多吃水果蔬菜、多喝水、多运动、早睡早起、经常泡脚等良好生活习惯的配合。在这一方面前面的回答都已经很完善了，便不再赘述。

       在护肤品的使用方面，外油内干的肤质最主要的问题还是缺水，基础护肤时保湿工作需要做好。其次，不同的季节需要根据肤质情况选择不同的护肤品，比如夏天应选择清爽类型的水和乳液，冬天则使用滋润型。另外，换季更换护肤品的时候可能会引发过敏等皮肤问题，所以尽量选择温和的植物类型的护肤品。最后，针对痘痘，需要搞清诱发原因，是清洁不彻底还是身体内部原因造成，再根据实际情况进行调理。

       作为一个只会往脸上抹粉的不化妆星人，我还是更注重基础护肤的相关问题～我的肤质也是外油内干，角质层薄，下巴经常冒痘，且痘印较多。目前正处于25岁的门槛，眼睛下部已堆积了较多细纹，脸颊上也有点点斑痕在形成中。。。想想自己在慢慢变老就好心酸，所以保养一定要趁早～我基本是大三的时候才忽然醒悟过来护肤的种种问题，其实已经很迟了。。。因为年纪轻没有品牌意识，又往脸上使用了较多便宜的被称作“毁皮天使”的护肤品或化妆品，很多肌肤问题在早期就已经埋下了种子，只能靠现在一点一点地补救。。。妹子虽然还年轻，肌肤问题估计也不会太严重，但是保养意识一定要尽早养成，可以先从最基本的保湿做起，为年龄的增长打下一个良好的基础。

        下面我介绍的都是我长期在使用的护肤品，基本都是较为温和的植物性成份，不太会引起过敏问题。但是个人肤质不同，所以在挑选护肤品的时候还是要根据自己的肤质作出选择。

        水：春夏为娇韵诗的绿水，很清爽。我的脸夏天出油较厉害，用这个水也不会觉得很滋润；秋冬比较干燥，一般使用彼得罗夫的芦荟喷雾，保湿效果很好，我每次都要喷两到三次，每喷完一次拍打吸收再喷上一层，做好保湿工作。另外，全年可以配一个雅漾的喷雾带在身上，随时都可以进行保湿工作。

        乳：春夏用自然堂的活泉保湿乳液，不会觉得油，感觉很清爽。秋冬为宠爱之名的保湿乳液或科颜氏的高保湿乳液。宠爱的保湿效果很赞，涂多了也不会觉得过于滋润；科颜氏的高保湿乳液较滋润，对我来说适合少量涂抹，用量如果多了的话会觉得油，不过睡前使用的话可以涂上厚厚一层做晚间保养。今年冬天准备入科颜氏的明星产品高保湿面霜试一试效果。

        眼霜：目前仍然以保湿为主，使用科颜氏的牛油果眼霜。细腻好推，已用完一罐。不过有的童鞋因为角质层厚用了容易长脂肪粒，所以这一点需要多加注意。雅诗兰黛比较适合年纪再大一些的妹子用，18岁用有点早了～

        防晒：防晒是非常重要的。无论阴天晴天夏天冬天，防晒都是需要的。它的作用不仅仅是为了防止我们变黑，更是保护我们的肌肤远离紫外线的伤害，防止黑色素、淡斑的形成等。冬天我比较偷懒，只进行面部防晒，使用曼秀雷敦的新碧水薄防晒乳。夏天，脸部、颈部，全身都要防晒，脸部使用彼得罗夫的的轻盈防晒乳液，适合有粉刺的痘痘肌，全身的话用便宜大碗的曼秀雷敦就好啦～今年夏天想入dicila的绿色防晒，适合油皮的痘痘肌，听说效果很好～

        卸妆、清洁：只要用了防晒就要卸妆。卸妆我用的是日本柚子卸妆乳，便宜大碗好用，对于我这种从不化浓妆的人来说清洁力度足够了。曾经买过植村秀的卸妆油，虽然外界评价超高，但是不知道是乳化过程不足还是皮肤不适应，下巴爆痘严重，不敢再用。好像有的油性皮肤用卸妆油都会出现一些问题，妹子在选择卸妆产品的时候需要注意～洗面奶的话我一直在用the face shop的芦荟洗面奶，三四十块钱好大一只，性价比较高，只是用完皮肤有点干，需要进行后续保湿～另外，今年准备入freeplus的氨基酸洗面，口碑很好，尝试一下新事物haha～

        面膜方面，主要使用三种：彼得罗夫的青瓜保湿面膜、科颜氏的白泥、origins的out of trouble。
1、青瓜保湿面膜主要用作保湿，两天一次，每次十分钟，再洗掉进行后续保养。保湿效果较好，长时间使用下来会改善皮肤缺水的状态。夏天放在冰箱里用做晒后镇定非常舒服。
2、白泥作为清洁面膜，一周一次，每次十分钟。清洁做完后，肤色确实会提亮不少。长时间使用下来，皮肤状态会稳定一些。
3、out of trouble主要是在下巴上冒痘的时候用来敷一下。面膜有点中草药的味道，敷在脸上也凉丝丝的。第二天起床后能发现红肿的痘痘会消下去一些。

       精华方面，主要是两种功能：修复和美白，且都在夜间使用。修复精华试用过科颜氏的蓝精灵和彼得罗夫的维A夜间修复精华，两者的修复能力都很好，只是前者对我来说略油一些。美白精华为彼得罗夫的斑点狗，主打温和的美白淡斑效果，因为脸颊角质层较薄不敢用美白产品所以我用来涂下巴上的痘印。要想通过护肤品祛痘印的话只有美白精华最有效哦～斑点狗三周用下来痘印确实消下去不少，会回购。这两种精华每天晚上都要坚持使用，才会慢慢看出效果。
      如果偶尔长少量痘痘的话可以尝试一下欣蔓的祛痘笔，我有朋友用过反馈说对红肿的痘痘很有效，但是不能祛痘印。如果是大面积的长期长痘的话还是建议去医院检查，配合使用整套的调理痘痘的护肤品，比如理肤泉等。总之，对肌肤的调理一定不能懒，要坚持，不要心疼money要用足量，这样才能看得见效果哈～
编辑于 2015-03-05
Arya
Arya

首先我觉得相比于皮肤不好，更重要的是胖的问题→_→减肥减肥减肥！！！炒鸡重要啊妹妹！所谓一白遮百丑，一胖毁所有啊，这一直是最深刻的至理名言啊。
皮肤的话，姐姐高中的时候也什么也不用，不用洗面奶洗脸，不用什么护肤品，只是冬天涂一点强生婴儿这类的东西。
姐姐现在皮肤也不是很好，有点痘印，去年还因为被室友带着用了bb爽而没有卸妆导致悲剧的长了一额头一下巴的闭合性粉刺，幸好经过大半年的奋斗，现在已经好多了，只有一点痘印了。
我相信你瘦下来之后，因为体内的油脂没那么多了，皮肤也会不那么油了，护肤的话，补水是重中之重，甚至比美白重要的多。丝瓜水啊黄瓜水啊之类的云云，没事就用吧，就擦吧，其实也可以百度一些DIY的自己弄的面膜，效果也很赞哦，主要是DIY的都是天然的，用了如果不好也不至于毁脸，成本也低。
嗯嗯，说了这么多，还有一点很重要的，就是运动啊，生命在于运动，年轻健康的身体在于运动，养成运动的习惯后，你会发现每一天都是朝气蓬勃充满活力的感觉。整个人的精神状态都完全不一样了，绝对的青春焕发啊！还有重要的一点就是，多运动，加速身体的新陈代谢，多出点汗，毛孔就不会容易堵塞，对痘痘也有好处哦。

说了那么多，总之祝妹妹早日变成大美女哦，嘿嘿，自称姐姐了，不好意思哦。你才18岁，超级大的潜力股哦，怀挺！
让我们一起努力加油，运动，护肤，减肥，做阳光一样青春活力的大美女哦么么哒
发布于 2015-02-23
贝大仙
贝大仙
投资理财
谈恋爱
发布于 2015-02-22
匿名用户
匿名用户
我要开始一轮暴风自夸了！
我的皮肤先天条件就好 不长痘 不油 白且透红 人称移动红富士苹果加水蜜桃。
活到现在还没发现能比我皮肤好的 势均力敌的都少见◟(◡ູ̈)◞
然而有先天的优势是万万不够哒！
首先我是从来不化妆（因为不会化థ౪థ ）
每天精华乳液四五次 而且我每次擦这些都会按摩脸 
夏天比较喜欢敷面膜 不过也不多 勤快点一周三四次 懒的时候一周至少一两次 
面膜真心不用太贵 补水就好 不要买美白的 水分充足你还怕不白？
不管晴天阴天雨天什么天防晒是必须的 
紫外线会侵害皮肤 所以出门一定要擦
洗脸就最简单的 因为我不化妆嘛 洗面奶就够了
然后兴致高的时候蒸蒸脸  
其实最重要的是！补水防晒！
送上夏季护肤日常
编辑于 2016-03-09
邵婷婷
邵婷婷

自认为皮肤还不错，近期没化妆没处理手机摄像头自拍效果是这样的。
颜值与本题无关，求别喷。
个人介绍
性别：女
年龄：24周岁
肤质：混合偏油
地点：浙江宁波，空气偏潮湿

我属于生活习惯特别不好的人，熬夜早起不爱动，不爱喝水不爱吃蔬菜，炸鸡奶茶火锅停不下来，就是这样的。从高中开始特别臭美，护肤品换了一套又一套，但生活习惯上还是没有太大改善。所以我要说的是，怎么通过护肤品，让皮肤变好。（都是个人经验，推荐都是自用，模仿请慎重！）

因为在公司，图片都是晚上找的，晚上拍一下换图。

一、基础
根据我的经验，不管什么肤质，护肤最基础的是以下三件事：清洁、补水、保湿。照顾好这三块，再去做其他功能性的工作：控油、美白、抗衰老、抗过敏、祛斑、去痘疤等等。

清洁
我在洗面奶上花的钱最少，个人理解洗面奶和牙膏一样，停留时间很短，所以功能性并不强，能洗干净就好。早晚最好选择不同的清洁用品，一般早上我选择低泡或者无泡的洗面奶，比较温和，晚上选择洁面皂或其他清洁力强的。

这里种颗草，洁面仪什么的可以有。
我自己在用的就是这款，找同学帮忙海淘的，1000块左右。为什么说洁面仪有用呢？个人感觉和电动牙刷原理差不多，洗的干不干净另说，主要是它有定时功能，能延长你洗脸的时间。不用这个的话，洗面奶停留在我脸上的时间大概20秒，用了这个以后，洗脸至少1分钟。所以洗完确实有一种毛孔都清透了的感觉。

放送一个买家秀，这是我男朋友使用3个月的效果，当然除了这个我还给他用了其他的护肤品，之后会说。痘疤什么的都还在，但是痘痘已经基本不长了。

除了日常洁面，清洁面膜也很重要。精简以后我现在有两罐清洁面膜。一个是DHC的矿物泥，另一个是雪花秀的玉容面膜。

DHC是我用过最棒的矿物泥，它的优点就是温和，一般矿物泥用脸上会有刺痛感，这罐涂眼睛上都没事。另外就是它非常方便，五分钟洗掉就行，而且非常非常好洗，洗脸棉一擦就下来了，也不回把洗脸棉弄得脏脏的。

玉容面膜是不推荐的，我跟风买的，用完确实会干净一点，但和所有的清洁面膜一样，第二天就没有效果了。而且用的时候挺不方面，不好涂匀，干得又慢。回购的话我只会买DHC那个。

清洁面膜一周一次就差不多了，不过护肤跟给花浇水一样，不能规定什么频率，要看感觉。你觉得脸发黄，易出油，护肤品怎么用都不吸收，就应该来一次。

补水和保湿
大家都知道补水和保湿是两个概念，但是这两个怎么都是分不开的。因为我是混油，日常水和乳液就能满足我的需求了，冬天特别干的时候还会加个面霜。

推荐两个搭配：
夏天 黛珂紫苏水+牛油果乳液（植物那个也可以）
春秋冬 黛珂白檀水乳+雪花秀人参面霜

对，我推荐的都是黛珂的，反正这是我目前用到过的觉得最好用的品牌，以后应该也会生生世世用下去。

除了日常的，补水面膜推荐肌美精，也是我目前用过最喜欢的。说不上为什么，就觉得用完以后皮肤特别好，在发光，效果比SK2那个前男友面膜还好。

二、功能
说完了基础的，可以说说功能性的了。

美白
一白遮三丑，我是深知这个道理，而且我五官那么平面的人，黑的时候真特别丑。但我家人都不白，小时候又爱去海边玩，所以高中之前我一直是黑妹啊！

上个黑历史，这是高一。

然后用过一堆美白产品，雪肌精敷脸啊，SK2小灯泡啊，有的没的都试了。最后，我总结出来，美白的关键是防晒！只要你新陈代谢不是太慢，做好防晒工作以及日常清洁补水保湿，几个月就能白。美白产品可能有一定效果，我感觉雪肌精确实有效，但是不防晒还是没用的。

我是硬防晒加软防晒，买双面的黑伞，然后涂防晒霜，角角落落都要涂到。防晒霜推荐苏菲娜和安耐晒。

应该是最白的时候，最近偷懒不爱涂防晒，又晒黑了。

祛痘
我很少长痘痘，偶尔额头会有姨妈痘，所以这方面没经验。但前几月交了个痘皮男朋友，就让他当小白鼠做实验。

成人痘生成原因很复杂啊，内分泌啊什么的，我只能治本。首先我就是改变他不爱补水这点，之前他很不爱往脸上涂东西，怕油腻，所以脸实际干得爆皮，但是T区超容易出油。

天天用紫苏水，出油稍微好了点。然后每周一次DHC矿物泥，每两天一次悦木之源的菌菇面膜。然后的事情，真的不关我的事，他每天跑步10公里，或者去游泳一个半小时，油的辣的忌口，皮肤就好起来了...

不要骂我坑，我说的都是真实情况。

过敏
过敏我有真实的体验，就是追求美白那会儿，天天敷面膜，皮肤开始很脆弱。经常大片都是红的，特别痒，之后还脱皮，会有色素沉淀。

之后我先精简了护肤品，面膜固定几种，水乳也是，不要换得太频繁。然后有两大神器，一是之前提过的悦木之源的菌菇面膜。
是这个，不要买菌菇水，那个超级臭。这个面膜刚涂脸上的时候会微微发热，缓解干燥过敏的症状，然后镇静补水，第二天过敏就没那么红了。虽然还是会经历脱皮的过程，但总体来说过敏的时间会短很多。

过敏那时候我把水乳都换成理肤泉的抗敏系列，那个特安乳液真的很好用，保湿又不油腻。现在基本不过敏了，但是菌菇面膜还是居家旅行必备。之前这个国内特别贵，590，现在降价了380好像，代购更便宜。

另一个神器之前也说过了，就是雪花秀人参面霜。之前我挺抗拒雪花秀这个系列的，总觉得是抗衰老的啊，但是从妈妈那里偷来用过一次以后，真的超棒！前一天涂好，少量就可以了，第二天皮肤光滑特别弹，而且不泛油光，长期用感觉能修复皮肤。
我的经验大概就这么多了，真的没有科学依据，都是我自己的感受~信不信随你，信了我也不负责！
编辑于 2016-10-12
知乎用户
知乎用户
学渣 不约 小心眼 评论只举报不删除，祝你们友善度都比我高

吃VC和VE

别停下来....

不用贵的，便宜的那种8块钱一瓶30颗的VE和双鹤那种成板的VC就行...

大部分青春期的问题在你激素水平稳定下来后会好，只要你别用太多东西给它变敏感肌

另外看看你妈妈的皮肤状态。

很大部分人会遗传下来一些问题。

我妈是30之前连油都不擦，我在25之前什么都不擦，只用洗面奶，孩儿面都没有。住校时候同学都已经惊讶到不行...

25之后直接上的抗皱抗老化产品（因为工作原因夜班量大概是70%）

哦对，还有防晒。玩命涂。

保持夏天2个月一定用完一瓶，冬天4个月一瓶
基本上就能确认户外运动量和防晒是够的....
发布于 2015-06-28
秋雨
秋雨
达人护肤Queen级医师指导

均衡的营养是健康的身体和健美的皮肤的基石。

某些食物和皮肤的状态息息相关。痤疮是毛囊和皮脂腺的炎症。如果饮食过甜（碳酸饮料摄入过度），就会引起胰岛素分泌增多，胰岛素样生长因子表达上调，刺激雄性激素的合成，引起皮脂腺的肥大和过度分泌。摄入过多的牛奶（包括奶制品）也会加重痤疮。牛奶中的生物活性物质，激素成分会干扰机体自身的激素分泌，从而有可能加重痤疮。不同类型的皮肤适宜于补充不同的营养。


能够改善皮肤干燥的食品有：鳄梨，玻璃苣籽油，油菜籽油，夜来香油，鱼，亚麻籽油，大麻籽油，坚果，橄榄油，橄榄，花生，大豆，葵花籽油核核桃。

能够控制皮肤油脂分泌过剩的食品有：富含维生素A的食品（哈密瓜，胡萝卜，杏干，蛋黄，肝脏，芒果，菠菜和地瓜）；富含胡萝卜素的食品（番茄红素，叶黄素）；其他抗氧化剂（如 青橄榄油）；鱼或鱼油

能够改善色斑，提亮肤色的食品有：维生素C，维生素E，石榴提取物（富含鞣花酸），葡萄籽提取物（原花青素），碧萝芷（多种类黄铜多酚，包括月桂酸，富马酸，没石子酸，咖啡酸，阿魏酸等）。

能够延缓皱纹产生的 食品有：蔬菜（绿叶蔬菜，芦笋，芹菜，茄子，葱，蒜和洋葱等）；橄榄油；单不饱和脂肪酸，豆类，应摄入奶及奶制品，黄油和糖。
编辑于 2017-08-25
杨小咩
杨小咩
建筑设计师
以前上班偶尔一天不涂粉底液，皮肤暗沉到同事会问，你今天怎么了?没睡好吗?看着挺没精神的!!吃了连续一个多月的红枣银耳莲子汤（每天吃，几乎没有中断一天）,不擦粉底液，完全素颜的情况下被同事夸，你最近皮肤真好!
代价是:那段时间看到银耳汤就会想吐，银耳炖过1个多小时后，那种滑滑软软的口感常让我想起某物，呃......现在想想，还是有点酸爽
编辑于 2017-08-07
安莫
安莫
真实。
不贪凉不贪夜，迈开小腿就蹦哒(˘•ω•˘)多喝水来多泡澡，热爱生活心情好(⁎⁍̴̛ᴗ⁍̴̛⁎)ps：好喜欢游泳⊙∀⊙！
发布于 2017-07-24
于明朗
于明朗
一个在治疗手汗症道路上走了很久的青春痘患者

前方高能‼️做好心理准备再进来呦！


这个话题我不多说话 看图看图（楼楼真不是来吓人的）

⬇️今年端午的时候 惨的要命 完全感染了！此图为iphone后置 已经很吓人了 何况肉眼看呢！吓人到天天戴口罩 终于等到端午回家 治疗一下！



⬆️此图为iphone前置自拍 拍出来没有肉眼看得吓人


⬇️ 上图为用某产品10天之后和15天之后（马上例假所以爆了几颗痘）

图的颜色有差别是因为不一样光拍的 但是效果如图所示呦

这个差距超级大有没有！无论痘痘的面积还是红的程度 完全变了！我拍完之后开心的飞了起来！
痘友啊痘友！战痘了这么多年！来分享一下自己的战痘经验啊！我也会无私的分享给你们！想要中药的有中药经历！想要我用的产品的也都分享给大家 ！
有没有人在看..点个赞..评论一下..让我看到你们哈 
未完待续……
编辑于 2017-07-07
五月的五花肉c
五月的五花肉c
七情六欲，食欲最为凶残。

第一次回答问题，如有不恰当欢迎指出。
多图，谨慎？结尾有自拍皮肤照~
皮肤状态，t区油，四周基本上微微偏干，一般般吧

1.身份介绍
普通女生，普通学生，生活费1500左右，年龄21岁，马上大四狗，理工科，
坐标重庆，山水养人我不懂，但是重庆妹纸皮肤感觉大部分都比较好。
2.作息时间一般晚上12点之前就睡觉了，早上七点钟起床
3.口味吃得比较素，食堂都不怎么吃肉。吃肉的情况是一个月回家吃很多肉，和男票出去下馆子吃肉，和男票食堂他分肉给我吃，其余都是吃素。也爱吃辣，火锅烧烤，但是没有经常吃。经常喝燕麦，自己寝室煮红豆粥，薏仁这些东西，粉粉是偶尔代餐，需要煮食物频率大概是一个月三次左右
电饭煲前天晚上泡好，第二天早上起来煮，我一般一煮就喝一天
另外：因为减肥曾经特别严重导致现在很喜欢甜食，冰激凌和饼干，频率有点高一周可能就三四次吧，不然感觉皮肤还会比较好一点？
4.运动，我一周平均运动三次，一次超过一个小时，基本上是有氧，跑操场五公里起步，或者寝室跟着b站跳操，我不去健身房，一次都没有去，最喜欢跑步，流汗水之后超级爽，跑完后身轻如燕

5.喝水，我没有早上起床喝水的习惯，以前故意想培养，喝了一段时间就放弃了，没有培养起早上喝水的习惯，但是我一天基本上平均3杯水，一杯500ml。
我不喜欢喝白开水，不喜欢喝饮料，基本上我就不喝饮料，也不喝奶茶。
一般泡水会泡枸杞，红枣，桂圆，大麦茶，乌龙茶，只要不是白开水，有点味道就可以啦~

6.化妆品，学生资金有限，所以我用的普通人基本上都可以用呀~我是按照我早上涂抹的顺序来的。
①洗脸，我不用洗面奶，温水洗脸，我用毛巾，比较柔软的毛巾，好像很多人说毛巾细菌多什么的，但是不用毛巾我不习惯呀！忽略这一步，嘻嘻(◍•ᴗ•◍)
如果介意的，推荐有一种纯棉的一次性面巾
②水，我很懒，不怎么擦水的，有时候会擦，反正比较柔和的水

③霜，各种霜我没有怎么区分，我也不分早上擦和晚上擦，霜我比较多，基本上都是温和补水的。
我强烈推荐强生婴儿和珂润，我都回购很多次了，资金不够就强生先用起，有钱就买珂润，这两款都超级好吸收，不油腻。冰冰霜最近入的我感觉还不错。

④防晒，真的特别重要，不管什么天气我都要擦防晒霜：碧柔全部是擦脸的，我囤的货;便宜的大宝是太阳特别大就擦身体哒
重庆虽然很热，但是紫外线不强，我觉得碧柔就够了。其实很想要安耐晒，但是我觉得蛮贵的，一直没有下手，像云南这个地方紫外线强烈的还是推荐安耐晒。

⑤底妆：A.粉底液，最开始入我就做功课了，不能买贵的，我的第一瓶是dior永恒哪一款？忘记名字了，现在这个我用的是植村秀小灯泡，我不经常化妆，有时候心情好，逛街约会才涂粉底液，感觉还可以呀！
有时候会za的隔离代替粉底液，因为懒，za隔离便宜，推开不会死白，但是尽量不要用隔离，bb，cc这些东西，我也是做功课的我都不用，只用粉底液和za隔离
B.粉饼，粉底液之后用的坎妹的棉花糖，真的有雾面效果，或者悦诗风吟的散粉，控油不错，t区出油扑扑朴马上就好啦~
其余彩妆就不用说了，化妆技术不好

⑥卸妆：肯定一定必须要卸妆，我是用的贝德玛，会回购，感觉还不错。直接喷瓶喷到脸上，用手轻轻按摩，没有用卸妆棉噢~感觉对皮肤摩擦太大了

⑦洗面奶：我就晚上用洗面奶，芙丽芳丝会回购。就是好贵啊，伤心~150块钱，我太伤心了，太贵了

⑧霜，和早上步骤③一样，我没有区分太多，都是随便用，想用那种就是那种，只要保证不油腻好吸收就可以了
⑨面膜，超级懒，一个月偶尔才敷面膜，10面膜我这一学期都还没有敷完，你说我是有懒

ok，对于脸上的化妆品大概就是这些了
⑩其余杂七杂八，如果有痘痘冒出来，我会涂这两个。
芦荟胶如果粉底液之前我也会涂在t区

——————————
还有什么想到再补充，噢，最近入了一瓶vc，希望自己更加白~
晒苹果6前置摄像头无滤镜的照片


编辑于 2017-06-13
csiny
csiny
健康行业工作

    皮肤黑黄 

 维生素C是很强的还原剂，可以使黑色素褪色甚至还原；而维生素E也有抑制氧化的作用。选择富含维生素C、E的食物可以起到美白效果。 

    斑 点 

 女性承载了孕育分娩大任，体内雌激素、孕激素等的微妙结合稍有差池，脸上就会出现斑点，既然如此，斑点的关键还是身体的调理。 

    皱 纹  松 弛  暗沉无光泽 内调方法：【母亲节特辑】解决女人脸部五大烦恼的食疗方

编辑于 2017-05-12
李由
李由
不要做懒癌患者了啊！我是公号：给你一个李由 的主人

 从高中开始我的痘痘就一直没消下去过，这个瘪了那个冒，跟打地鼠似的，高考以后总算有时间好好治理一下，到现在接近两年的时间总算已经好了很多，虽然没有达到完美的地步，但是比当初已经好了很多了啊。

先给你们看看我原来的痘痘

可能引起不适！

就是这种红红的小痘痘，一直都好不了

下面我就讲讲我的一些小经验吧。

①掀起你的头盖骨…啊不，是厚刘海   

因为我的痘痘主要是长在了额头上，高中时期一直留着厚厚的刘海，高考以后立马就掀了起来，给我的痘痘透气。可能这个办法并没有什么卵用，而且会让别人看到你痘痘的惨状，但是不要怕，不要想着不能让别人看到所以就想尽办法遮挡它，给肌肤一个透气的空间是很重要的。

（这个办法只针对和我一样额头长痘并且还有刘海的同学，其他情况那就往下看吧）

②看医生，了解自身的身体状况是否出现了问题

很多人都依赖于护肤品或者药品治疗痘痘，很可能做了很多功课用了很多产品都没有用，但是除了外疗，内养也很重要。我原来觉得只是痘痘而已，也没有要去看医生的地步，虽然看的很多文章都在推荐“不要乱用护肤品，去看医生”，但拖延症一直发作没有去。终于有一天，我忍无可忍，去男朋友学校的校医院找皮肤科的医生看，医生没有直接开药，而是问了我身体的一些状况，我把问题列在下面你们可以自己对着看是否自己也有这样的问题。

✔熬不熬夜

✔经不经常吃水果

✔爱不爱喝水

✔吃不吃辣条

✔爱不爱吃甜食

✔月经是否正常

✔排便是否正常（正常是一天1～2次，我记得当时我说正常，医生追问我多久一次，我还不知所以地说2～3天一次，医生丢过来一个白眼：你觉得你这正常？！）这个很重要！

如果有上面这些问题的话先自己坚持调理一下，也就是饮食+作息的问题。如果你以上都没有问题还是有痘痘，就去医院吧，医生还是要专业很多的。

然后医生给我开了助排便的中成药，还开了一管维A酸点涂痘痘的地方。


这药还挺有效的，一般头天晚上点涂在痘痘上，第二天就瘪下去了。

  除了排便不正常，我也改掉了偶尔熬夜的毛病，放假在家老是熬夜痘痘就又有点爆发的感觉，回学校以后11点左右睡觉，能感觉到好了很多，虽然早睡在现在可能感觉很难，但是坚持下来肯定会不一样的。

----------------一点题外话的分割线---------------------- 

 然后我来啰嗦两句我是怎么调养自己排便正常的，有需要的同学可以借鉴，没有的话我只能说：我真的很羡慕你们肠胃好的啊！

☞多吃红薯之类助消化的食物。我一个星期都要挑几天晚上只吃红薯，还是有作用的噢。

☞多吃水果，起码保证一天吃一个，就算是一个小橘子也好。

☞多喝水，虽然喝多了容易跑厕所，但是还是要多喝啊！这里说的水是白开水，不是饮料奶茶之类的。

☞早上吃清淡点，我一般早上都不吃带油的东西，都吃馒头，鸡蛋，粥，面之类的。

大概就是饮食方面一定要注意，一开始可能没什么效果，别急，坚持下来就会好很多，我现在基本可以保证一天一次。

 ---------------------------分割任务完成---------------------

③找到对自己的有效护肤品（不作推荐，自行选择）

我是当时看了一个b站up主推荐的悦木之源的菌菇水，她是混油痘肌，说菌菇水很好用，自己做功课也发现是无酒精的（我个人比较喜欢用无酒精不刺激的护肤品），但是这个产品好像因人各异，因为b站也有人吐槽难用，所以我当时没直接入正装，在闲鱼上买了别人出的圣诞 套盒里的50ml的小装。怎么说呢，其实我觉得这个水对我痘痘的感觉我不好说，因为我是和医生开的药一起用的，所以不能说完全是菌菇水的功劳，但是这个水让我的肤质变好了！我额头原来应该是敏感肌，除了痘痘还老是红红的，红紫红紫地看起来很不健康，皮肤有种很脆弱的感觉，用了这个水以后肤质感觉变强了，摸起来明显能感觉到好了很多。菌菇水闻起来有股中药味儿，很滋润不刺激，应该是营养比较足，所以如果和我一样皮肤又有点脆弱的同学可以试试，最好买分装小样先试试，看和自己的皮肤八字合不合先。

④不要吃甜食！

对，这条就是要禁嘴，想必只要做过这方面功课的同学都知道甜食对痘痘有很大的影响，所以一定不要吃。我从高中毕业以后就没有再喝过奶茶，碳酸饮料之类的，甜食也是能少吃就少吃，吃粥都不要加糖，除非有时候真的很嘴馋会吃一点哈哈 。这种习惯养成以后，口味会变清淡很多，我现在就不喜欢吃口味重的食物，太甜的都不太吃的下去，觉得很腻。对于喜欢吃甜食的人来说可能比较残忍吧，但是想发生改变就得要做出改变的啊，也别低估了你的自制力。

⑤勤洗枕套床单，尤其是枕套

毕竟是脸部皮肤最直接碰到的地方，干净一点肯定好一些啊。

现在我的额头是这样的，自己看着心里都舒畅了很多


还是有一些闭口的问题，不过我已经超级开心了。

我的战痘史大致就是这样了，如果还没有完善的想起来了我会再加进来的，祝各位痘痘早点好，再也没烦恼～

公众号：忙里偷闲岛

 我的公众号到现在还只有我自己关注，真是让人忍不住眼泪要掉下来... 
编辑于 2017-04-24
鲁幸运
鲁幸运
特别边缘的地质女

痘龄从初三开始长算起的话应该快有小十年了...光阴似箭日月如梭

基本情况：

23+，目前坐标北京，混合肌，皮肤油脂分泌旺盛（体内雄性气焰太强。。），容易留下印子的疤痕体。

从初三开始，我就已经告别了烤瓷肌这个行列。最开始是鼻翼两侧出现脂肪粒，当时手欠并且挤过第一次之后狠狠地体验了一把快感，导致挤痘和长痘这两件事一发不可收拾，一直持续到现在...期间因为出国留学到  ，大量的吃油炸食品以及不规律的生活导致皮肤整个烂掉，脸颊两侧一直冒特别大颗的闭口，只能用很厚的粉底去遮，最后每天出门就像一个陈皮。再加上忍不住去挤，导致脸部发炎严重，并且留下了很黑的色沉。实在忍不下去了就开始上网找各种测评自己买产品走了很多弯路也没有什么效果，从蘑菇水到SK2，洗面奶产品也是尝试各种，淡斑精华还有祛痘的精华也是尝试了一大堆，最终也是无功而返。这里想说，护肤品真的只是锦上添花，皮肤的改善是要从内而外，如果有问题了一定是身体的哪个部分不和谐，一定要尽快看医生，遵医嘱，不要自己瞎尝试，很有可能就是花了大价钱最后效果却不尽人意。

今年过年的时候我从高铁站下来我妈看到我第一眼的第一句话是“你是不是中毒了。。。”（没错是亲妈），然后就被我妈摁倒医院去了，我当时还是花了一点妆的，可想而知当时的皮肤状态是由多差。这两个月一直在遵医嘱，从家里到北京都一直坚持，效果还蛮喜人的，所以大家还是要相信三甲医院的皮肤科医生。

医生给我诊断的是痤疮，没有到重度，但是炎症严重，我坐下来的时候医生一直跟我说来晚了啊，两边都色沉的这么厉害才来，早点来就不会这样了。。悔的肠子都清了。现在我把医生要求我做的每一件事情列出来，有些是我以前真的观念错误的，我觉得可以出来分享

1. 忌口。这个影响真的太大了，医生告诉我忌甜、油、辣，所以今年是我过得最寡淡的一个年。。重口的东西长痘不能吃是众所周知的，但是甜这个我以前是真的没有意识到。

2.早睡。没错...我知道很难，但是必须要做到，北京的医生给我看的时候直接就说...你先做到早睡了再来我这看病,....

3.洗脸。洗脸不要太大力的搓，我去医院做果酸洗脸的时候就被护士骂了.. 最好是用手接住水，再把脸打湿即可，用洗面奶洗脸的时候从中间到外部用指腹较轻的按摩即可，不能很大力的搓。洗面奶不用选择清洁力太强的，因为皮肤已经有损伤了，我自己喜欢用无皂基的。

4.护肤品的选择，在长痘的时候，只需要保湿...只需要保湿...不要抹太多层太油的，消炎的部分要交给医生开的涂抹型消炎药，并且在有成熟的痘痘并且进行了针清的情况下，不要抹油！只要抹药！我当时有做果酸加针清，医生叮嘱的是做完针清之后当天不要洗脸，三天之内做了针清的部分不要涂任何护肤品，只能涂开的药。一开始很不习惯，洗完脸会特别紧绷，但是坚持三天发现真的痘痘自己愈合的能力有变快并且不会留下痘坑，连痘印都很浅，我不知道这个的原理是不把恢复交给皮肤本身自己，但是医生的叮嘱还蛮有效果的。

5.果酸，这个应该是因人而异，因为我本身粉刺比较顽固所以医生建议我做果酸，我也乖乖去做了，鼻翼两侧的粉刺在刷过第一次酸的时候冒出来了，我也没动它，后来自己就不见了，现在再摸脸不会有以前那种刺刺的有小粉刺的感觉。但是这个也是要认真听医生的话，做的次数，刷酸的浓度都是因人而异的，我觉得最好不要自己去刷，医院会有一整套的前期后期的护理，我当时做一次果酸会有一个灯照15分钟，好像是消炎的。并且果酸本身就有提亮以及淡化色斑的功效，虽然不是一次就显得效果特别显著，但是是有明显改善的。

6.面膜，跟护肤品一样，保湿即可！保湿即可！每天敷面膜对皮肤会有负担，但是做果酸的话需要面膜加强保湿

7.吃药。医生给我开了异维A酸，吃这个药也是要谨遵医嘱，他对体内分泌油脂的调节效果真的还蛮厉害的，我吃了之后能感觉到比以前干很多，脸上的新的脂肪粒也变少了。但是吃这个药对胎儿有致畸性，所以两年之内想生小孩的女生就不能吃了（对的，，，，这两年之内我应该是找不到人跟我生小孩）

其实我觉得皮肤不好就是身体不舒适的一种表现，如果出现了问题我觉得还是一定要去医生那里看看是什么问题，认真听医生的话，不要瞎买各种产品，早睡忌口运动这些其实都是改善身体平衡的手段，身体健康了皮肤自然就好了。我还在战痘的途中，最后爆一个前置无PS的照片（我化妆了，但是以前化妆出来是凹凸不平的陈皮。。。现在用粉底效果明显比之前好很多），祝大家都能皮肤变好一直美美的自信的开心的！
发布于 2017-03-12
LtM
LtM
材料研发人员

从自身经验来说，皮肤变好有三个必须要做的事情：
1、拥有好的睡眠及睡眠习惯。（晚上11点前必需睡着，坚持两个月就会有效果）
2、改变心态。把事情往前面做，避免焦虑、急躁的情绪长期围绕。
3、科学的护肤理念和合理的选择护肤产品，不盲目种草。
—------------------------------------------------------------
我青春期的时候也是大爆痘，还黑……………
两颊角质较薄，T区油腻，而且毛孔粗大。
过敏性体质…………
大学开始注意护肤问题，现在出门素颜都被夸皮肤超好，看起来跟上了很细腻的粉底一样。

我的招数就是最开始说的那三点，下面来具体说说吧：
1、好的睡眠和好的睡眠质量。
我不相信什么早睡排毒的说法，但早睡对皮肤好是绝对的。我们家管的比较严，所以高中之前我也都是九点就睡了。高中三年压力特别大。睡眠质量差，也睡的少，皮肤真是史无前例的黑，痘痘，大毛孔…………
大学起，压力变小了，而且从小养成的习惯导致我晚上特别不爱出门…………写完作业看看美剧，八点半九点就会昏睡过去…………
军训晒成狗，我是我们宿舍恢复肤色最快的，而且恢复的比以前更白了………
四年下来已经跻身白皮行列。
不过早睡并不能让黑人变白人，但能让你的肤色回到你能白的最白，而且皮肤不会发黄。黄种人很少皮肤是真的黑，大部分都是黄…………………
买那么多去黄气的面膜，不如多睡觉。我妈跟我一样这么多年都是九点睡觉。现在由于不护肤皮肤皱纹满多，但真的很白。一点黄气都没有。
 我的经验：早睡才对皮肤好。哪怕第二天早点起也不要晚睡。

2、焦虑和坏情绪是皮肤的大敌。
皮肤是直观反映一个人身体状况的，身体劳累睡一觉就好了，但情绪心情上的劳累会让人每天处于一种焦虑、悲哀的情绪中，睡眠也不好，也没心情护肤，长期以往不仅脸色蜡黄，估计身体也不好。
学会调节自己的情绪，每天开开心心的很重要。

3、正确的护肤理念

护肤真的可以算是一个很复杂的交叉学科，有化学，生物医药，人体，等等。而且网上有太多看似很厉害，其实在误导人的某某老师。

多看看权威的书（不是某某老师的护肤宝典，而是教科书）

这么多年我有几个觉得很重要的概念：
1，一定要有效防晒。
光老化有多么厉害，我就不赘述了，除了人们常有的认知会黑之外，会让人长斑。最重要的是：会导致或恶化皮肤炎症。
我每天都是防晒霜+硬防晒。（一把能真正遮挡紫外线的伞很重要）
选择防晒霜的原则：
我是常年spf50，PA++++
一是怕自己量不够，防晒力强一点，也能稍稍弥补，二来是我上班太忙了，很少记得要补防晒，选一个防晒时间长的，也是为了弥补。
选择产品不要一味的迷信大牌，或者嫌弃开价货。选一个质地清爽，适合自己的就行。
我用的防晒如下：（因为在外面，不在家，图片都来自TB，有侵权跟我说一下我立刻删）

1、资生堂时光琉璃防晒霜 日版
这么多年来，使用感最好的防晒。成膜快，防水防汗，清爽又不拔干。含有乙醇，但是一点都不刺激。除了贵没有缺点。
日常用。

2、怡思丁fusion water防晒（水防晒）
水感质地，没有酒精，眼部可用，防水防汗，UVB/UVA全效防护。
便宜又大瓶，已经用了一年了，夏天一点都不油腻！我一般先上一层这个，再上时光琉璃防晒霜。然后这瓶随身带用来补。

3、兰蔻轻呼吸防护露
秋冬用，因为不防水不防汗水感
质地像一般乳液，使用感非常好。
特别好卸。
秋冬日常。

2、靠护肤是不能缩毛孔的，但要注意温和的清洁。
护肤并没有那么神，没办法缩小毛孔，但是让自己的毛孔里变干净，看起来也会变小。注意频率。
我用的清洁产品有契尔氏的姜黄面膜，sk2的清莹露，阿玛尼的卸妆洁面啫喱

3、常年抗氧化和美白，学会分区护理，学会按照自己的肌肤状况选产品和选步骤。
不要乱种草，今天这个说好立刻买，明天那个好，立刻买。买东西贵精不贵多。
每一个步骤都选自己接受范围内最好的。虽然最好的不一定最贵，但贵的一般比较好也是事实。
学会适当的看成分，选有效成分最好的，别花钱买广告。
 基础护肤买大集团的中档线，精华面霜买贵的。
洗面奶最好用氨基酸洁面的。

推荐的中档线：olay、倩碧。

自用品：
1，洁面
sk2洗面奶
经典的氨基酸界面洗面奶，认真搓揉起泡力还凑合，清洁力足够。
预算不够的可以买旁氏米萃…………

2、水
美素人参水+sk2神仙水
美素人参水其实是肌底液的概念，用完再用sk2明显感觉后续好吸收。
美素是国货牌子，和自然堂一个公司。
质感已经像欧美大牌靠拢了。
价格也不贵。

神仙水爱的人爱，恨的人恨。迷思也很多，传闻也很多。
我想说，用完真的不爱出油了。
没有版本区别，别听代购瞎逼逼。

3、精华
olay光塑精华液

这个必须推荐。三年已经用掉三十几瓶了…………
olay是宝洁集团的中低线。和sk2有共享的烟酰胺。
这个效果要长期用，晒后用不爱变黑。我闺蜜说用完皮肤明显变好，
雅诗兰黛ANR修护精华
维稳一把好手。
4、霜
我很少用乳液的……
都是直接用霜
lamer gel cream 用在夏天白天全脸用，晚上T区保湿又不油腻。
阿玛尼黑曜石奂颜霜：秋冬早晚全脸，夏天晚上用在两颊。
HR澄光精华乳 高浓度VC，白天用在霜后面，抗氧化。
5、特别护理：
origins菌菇面膜、sk2青春敷面膜
契尔氏香菜面膜
发布于 2016-07-25
我是小骏马呀
我是小骏马呀
我们都美好且值得被爱
锻炼加早睡加饮食加护肤（我也做不到）（摊手耸肩）（丑的自己哭出来）
发布于 2016-07-25
郝琳琳
郝琳琳
产品

在北京，大雾霾，干皮，易过敏！

1.前段时间过慢，被误诊成光敏，敷了硼酸水，然后脸上更厉害了……

这段时间脸上特别敏感！一碰就红……每天顶着脸上两坨红，只有睡一觉到早上才好一点，只能擦一点护肤品，就算抹一点隔离都起皮！崩溃！

然后我用了一个神奇的东西！！！

它治好了我脸上的两坨红！痘痘也基本下去了！还误打误撞祛掉了黑眼圈！！！

这件神奇的东西！就是！！！

➡️ 马应龙痔疮膏 ⬅️


2.我特别爱咬嘴上起皮，所以我嘴上的皮就是越起越咬，越咬越起，然后我就发现了一个特别好用的，摸一晚上就好。

这个是个乳头霜，就是在哺乳时造成的乳头干裂，摸在乳头上的，宝宝吃到也没关系，还是很安全的，要是想买去淘宝找个代购就好了！

➡️ ￼ Lansinoh 羊毛脂乳头保护霜膏 ⬅️


3.皮肤特干，还有点鸡皮，有一次，一个洗面奶剩了好多，又不想用了，就洗澡用了，用完以后决定都用它了！

因为没有假滑，皮肤感觉超级嫩，鸡皮竟然淡了好多！

就是它！

➡️ 大宝洗面奶 ⬅️


写完了突然发现，擦在 pp 上的，擦在脸上！擦在乳头上的，擦在嘴上！洗脸的，用在身上！ 
发布于 2016-06-10
匿名用户
匿名用户
額頭上的痘痘其實就是胃熱。現在為什麼那麼多年輕人長痘？喝冷飲吃雪糕。冷飲冷食引起胃熱。當然熬夜，吃煎炸東西也會長痘痘。但是最主要而且沒人注意的就是冷飲冷食。（冷的汽水啤酒饮料果汁雪糕酸奶）。我常常想：如果說年輕的時候有人告訴我這些就好了。所以我現在就告訴這些給年輕人。知道了根源，注意飲食，不吃中藥也會慢慢消退。吃中藥的的話，加速康复這個過程。
发布于 2016-05-09
时丢丢
时丢丢
在人生中修行的人
居然没人点赞，看来必须上图了。
必须回答一波，我皮肤还可以吧，反正从来不化妆的我老有人问有没有涂BB霜。
第一，热水洗脸，冷水容易长黑头痘痘。你想啊，油脂用冷水洗，它不是凝固在毛孔里了，反正我自从用热水洗脸后，几乎没有痘痘和黑头烦恼了。
第二，防晒，冬天在家都不出来晒太阳的。我不怎么用防晒霜，因为我夏天带帽子打伞长袖，冬天口罩帽子出门必备。实在不行我才用那些，我会卸的非常干净。总感觉它们会堵我毛孔。
第三，早睡早起，经常10点前睡觉的人皮肤一定会好。
第四，水乳面膜，我有个计划表，但是回家就不用了，因为家里空气好，人也放松。作息也很好。一般在学校里，一个星期几乎天天敷，悦诗风吟火山泥面膜，一张补水面膜，美白的酸奶面膜，眼膜，睡眠面膜。都5个了，我再自由呼吸一天，还有一天想用哪个用哪个。
第五，少吃辣是不够的，甜的，油腻的也要少吃。这些都会长痘痘皮肤出油。
第六，皮肤红点点多的，痘痘多，防止是过敏，有痘痘就不要化妆了，会更严重的。如果是过敏，查找过敏源，可能水乳酒精含量高之类，停用看还有没有大面积红痘痘。
第七，勤按摩脸部，促进血液循环。
编辑于 2016-02-12
匿名用户
匿名用户
哈哈，这大概是每个爱美人士关注的问题，我的亲身经历，我来说一下！自己是大三学生一枚，皮肤白但是会偶尔冒痘，特别是考试前特别严重。所以我要说的是，一定要早睡早起，生活规律！我相信现在的大学生都一样，睡的晚，所以当你坚持早睡后你就会发现皮肤明显会改善。我自己每天都坚持在11点前睡，所以我的痘痘基本不长了。可见睡眠对皮肤有多重要！其次就是要每天坚持锻炼身体，一定要出汗！动两下的不算运动！我每天都回去健身房，每天都坚持1小时，1小时不短，真的够了！坚持一个星期，再看镜子气色明显变好！最好的就是要注意清洁，面部的清洁，和面部有直接接触的枕头、口罩等等等等之类的东西的清洁，螨虫也是导致皮肤不好的原因哦。
以上这些都是亲身经历拿出来分享下，希望给和我有一样问题的妹纸们一个帮助哦
发布于 2015-11-24
HL Wei
HL Wei
微信个人订阅号《南城趣事》，欢迎关注
1. 良好的作息时间。真的，如果能过每天10点到11点左右睡，大部分的肌肤问题都可以解决了。
2. 多喝水、喝茶、喝果汁（柠檬胡萝卜汁我的最爱）
3. 多吃胶原蛋白类的食物。不信的话你连着几天吃银耳试一试，隔水炖，炖到胶质出来合起来有点黏黏的感觉，保证你一觉起来满脸胶原蛋白。或者买一些胶原蛋白胶囊啥的，虽然之前有人说其实吃进去分解了就是普通氨基酸，但是我真心感觉对皮肤有好处。
4. 忌口。对我来说，吃了辣的，高糖的脸就容易冒痘，而且会泛红（敏感肌的痛）
5. 清洁保湿。这个就不用多讲了吧，如果化妆的话一定要注意卸妆哦。有时候我化了妆第二天脸就会偏红，sign.
发布于 2015-11-23
知乎用户
知乎用户
坚决不改
今天学习分神了 ，我就来答一个好啦。
嗯我是坐标武汉，夏天混油，冬天混干。曾经不懂得祛痘的时候买过乱七八糟的祛痘药膏，把自己整疼成敏感肌。但是现在好像又好了……总之，我反反复复长痘好几年。也是最近一次去看医生和关注了大量护肤博主才搞清痘痘到底咋回事儿。
  9月份我去苏州写生脸上冒油，起大颗红肿痘痘。

就酱紫的。非常着急，于是就去苏州人民医院看了一下。医生说我脓包痘痘，小部分结节。问了下我长痘痘的病史，我大概长了四五年吧，反反复复时好时坏的那种，吃过中药也看过武汉同济医院还用过合个医院自己调配的药膏。医生问了下我是否结婚最近有没有要小孩啊什么的，就给我开了

还有擦拭的夫西地酸乳膏。口服异维A这个挺多非议的，我有看过几个护肤博主争论，这个真的因人而异。我服用以来除了嘴干需要大量喝水以外，没有别的不舒服。要宝宝的女孩子还是注意一下。医生嘱咐我了几点让我一定一定要做到：1.11点前睡觉 2.啤酒烧烤巧克力咖啡不能吃 3.晚上喝异维A（因为这个药光敏）4.………后面忘了
但是我自己也会特别注意几点就是1.不吃甜食（蛋糕啊糖啊人工加工的甜食都不吃）2.少喝牛奶，除非是低脂偶尔喝，因为有乳清蛋白好像也会诱发。酸奶也很少喝，因为自己做过酸奶的都知道会非常酸，可见外面放了很多糖。3.运动，我本身很喜欢出汗的感觉啦～4.多喝水5.护肤流程简单 我发现我不倒腾那些护肤品的时候皮肤最好。我就那几个喷雾牌子换着用+Cerave乳液 最近在用Dr.Wu的杏仁酸～防晒也要擦，但是我现在不太想……想等脸上一颗痘痘都没有了再擦。
然后该上图了？

这个是口服异维A第7天的样子

这个是第10几天吧
然后是现在

嘻嘻我真的挺不要Face的……
我稀里糊涂的回答的
补充点1.医生主张口服1天1粒 3个月可以吃好但是我有看到过一个表格是3个月是个临界值，应该吃半年吧
2.害怕的可以去查一下肝功再去吃
3.微博博主的话我主要关注，Yumi_520
三石医生……多的我记不起来了。
4.不要在意别人怎么看怎么想，人生嘛就是你笑笑我，我笑笑你。心态好很重要！特别是气色好，气质好！皮肤病从来都不是什么不治之症，怕什么？有一天总会好！
就酱～～希望大家皮肤越来越好哦 
发布于 2015-10-14
桑刘
桑刘
做人最要紧是开心。
学会为脸花钱。
尤其是你不想改变不良生活习惯，不想放弃垃圾食品，不想锻炼运动的时候，你尤其要学会怎么为脸花钱。相信我，明星皮肤好，绝不是全是因为比你生活得更健康。
发布于 2015-10-10
Lucia
Lucia

护肤什么时候都来得及，个人皮肤配合饮食长期会有改善。我就各大护肤都爱折腾，化妆品也爱买，就是画不好囤着了。
首先，洗面，我是混合中性皮肤，所以洗面用得随便一些，肌研这样温和的产品就用，不刺激，不含香精。

如果皮肤太油，毛孔大，可以选择清洁力强一点的产品，但切忌选择洗后太干的，这样后续要充分补水。IPSA粘土面膜，清洁口碑很好，有磨砂颗粒，皮肤太薄有红血丝的不太适合。一般皮肤都行。价格是340港币。


护肤水origins的蘑菇水，专门针对敏感肌肤的，味道有点怪，不是那种普通香味，有一种清冽潮湿的感觉。

这其实是两只的价格，一只320港币。
科颜氏金盏花用了几个月了。补水保湿都还不错，关键太美了，价格记得似乎是330港币左右。

精华液
森田药妆
价格100多吧，小票不在了不记得。质地非常粘稠，涂在脸上很保湿，我脸上有斑，祛斑有效吗目前看不太出。



乳液
科颜氏高效保湿
用了一段时间，保湿效果很好。质地是清爽型的，香味很淡。就是用后开始脸湿呼呼的，有刘海会弄脏刘海。价格100多吧太久远了不记得了。


资生堂小红瓶，价格比较贵，湿润易吸收。最便宜的30ml 是港币640。

面霜
以前不喜欢用，冬天以及现在季节爱上了。现在用的雅诗兰黛，很喜欢。质地紧密，用后感觉皮肤很紧致。

最后随身携带喷雾。感觉皮肤有干干的紧张感就喷一下，大葡萄水香港各处卖断货。港币68。

最后，就是防晒防晒。我是用防晒隔离或者BB，防晒还调整皮肤肤色均匀。防晒乳我个人觉得太油了不喜欢，不然就用了之后铺上散粉。
科颜氏BB 自然色spf 50 pa +++
价格330港币

Ipsa 蓝色 会显白 spf 20 pa ++
价格260港币

当然也可以选择质地清爽的防晒，我反正要用BB就直接选防晒功能的了。
最后，卸妆
如果化妆选卸妆油，不画选卸妆乳。
DHC便宜一大瓶卸妆干净。

卸妆乳
Fancl温和不伤皮肤，一般淡妆卸妆足够。

最后，面膜就在可以的范围内狂敷吧。选择补水的种类就好。美丽日记，我的心机，森田药妆，便宜又好用。我一直储备很多。
我护肤就是选择补水补水，水份足够细胞活力满满。另外，就是不刺激，成分安全。仍然在各大产品选择中。最后，温和补水保湿中，选择最适合自己的。
编辑于 2015-03-08
匿名用户
匿名用户
早睡早起。
发布于 2015-03-03
匿名用户
匿名用户
早睡早起，多喝水， 敷面膜 一周两三次， 少用洗面奶 觉得油就用热毛巾在脸上闷五六秒钟，多吃水果蔬菜，猪蹄汤 鸡汤 银耳汤之类的东西，不要看那些人推荐的这个那个贵的要死的护肤品，有个屁用，如果你熬夜抽烟吃垃圾食品 用再好的保养品都没用，平时大宝涂涂就行了，你心理觉得不到位就买一套好点的基础保养品，化妆的话记得卸干净，最后保持好心情～
发布于 2015-02-25
老周
老周
中医药、传统健身法、现代运动综合调理康复研究者。
五脏调和则一切皆好，不仅仅皮肤！
发布于 2015-06-28
知乎用户
知乎用户
内调真的很重要！！！本人是资深护肤控，但是很少能用到什么东西达到“：哇，真的赞！但有一段时间生病不舒服，待在家里每天喝小米粥，吃红枣，蔬菜，喝鸡汤，休息了两周以后，发现，哇，皮肤白里透红，有光泽，有弹性，重量级精华也打造不出来的效果，顿时明白，内调比外养更重要！但我也有很多坏习惯，比如说，爱吃辣！哎，好难改！
发布于 2015-03-12
匿名用户
匿名用户

19岁，皮肤外油内干，坐标大吃货省。 

╮(╯_╰)╭答主为一名标准的作死大学生，去年刚入学报了一堆部门，结果工作满满（曾经三天没闭眼）以及疯狂减肥的11月之后开始大面积爆痘TAT当时简直快要吓哭了，第二天赶紧上医院去！ 

关于医院：坑，就是一个坑。一套治疗：拔火罐，蒸脸，针挑，中药面膜，照一个不知道是啥的光。针挑的时候，疼得我心里直想我为什么要经历这些一般人都不用经历的痛苦TAT旁边的大叔疼得都要骂人了，而我自己一个人，不敢出声闭着眼默默忍受这样的痛。一整套做完之后脸上全是红的印子，回到学校之后一直带着口罩，医生给我开了一堆乱七八糟清热的药。每一次去医院就要给相当高昂的费用。非常痛苦的一个半月，总结来说就是：没用。 

关于美容院：查了很多资料在我们当地找到一家口碑较好的美容院，针挑比医院专业多了，很干净，但是针挑治标不治本，很快就会又长出来，并且真的很疼啊。。。答主作为一名傲娇的少女，去了几次就没再去过了。 

关于内调：答主在吃一个叫月见草油的东西，两百多块钱一大瓶，是调内分泌的，吃了一个月左右了，表示气色好了，重点是痘痘也好了很多哟~题主可以去某宝上面查一下，找个靠谱的澳洲代购买一瓶╮(╯_╰)╭另外一个方法是我最近被哥哥安利的，苦瓜加红糖榨汁，还可以加上金银花，对痘痘有帮助，题主也可以试试。 

关于产品：不敢说自己是大神，但是从初一开始接触护肤品到现在已经7年了还是有点水平的啦~以下安利part，是我自己用过的觉得有效的产品，但是效果因人而异你懂的！btw真的不是广告。。。 

洁面：自然哲学philosophy的purity洁面乳，保湿度高，可以卸掉隔离；奥伦纳素erno laszlo大黑皂，清洁度高不刺激有效去黑头，但使用方法有点复杂，据说是拯救皇室婚姻的一块皂呢╮(╯_╰)╭ 

水：奥尔滨/奥比虹健康水；erno laszlo蛋白水。这两瓶水都巨好用，浸湿化妆棉敷脸最有效！但是嘛，奥尔滨的水味道有点像肥皂有人不喜欢，erno蛋白水有点粘粘的并且瓶口略坑。另外还有SK II神仙水，但神仙水要配合爽肤水使用。补水效果比较好的还有kiehl's青瓜水，痘痘肌还可以选择kiehl's金盏花水以及origins蘑菇水。

乳霜：理肤泉k乳保你一生平安（还有理肤泉的ai duo）；NYR箸草面霜；it's skin蜗牛霜修复蛮有效的哦。 

精华：aesop无油保湿精华露，虽然看上去油油的但是真的一整天都很保湿；石泽研究所的acne barrier祛痘精华，这个强推，亲眼看着痘痘消失。

眼部护理：kiehl's牛油果眼霜；the body shop接骨木眼部啫喱。年轻肌肤用这两个不会错哒~

特别护理：狮王pair暗疮膏乐敦维c去痘印美容液。

手霜：瑰柏翠，香味推荐百合，喷泉，红石榴，蔷薇；欧舒丹，味道推荐乳木果，樱花。

护唇膏：DHC橄榄润唇膏。

面膜：minon；lululun；肌美精；kose；盛田玉興豆腐面膜；森田玻尿酸面膜；以及。。。DIY三明治面膜（大大的安利！巨补水！还淡化痘印！做法是：先敷一层自然乐园的芦荟胶，然后用薏仁水泡面膜纸，敷上作为第二层，最后再在面膜纸上敷一层芦荟胶。芦荟胶和薏仁水都很便宜，用量多一点无所谓。btw面膜纸推荐天威。）
ps评论有用户说自然乐园芦荟胶不能用在脸上哦，需谨慎。

喷雾：大葡萄皇后水；理肤泉；雅漾；依云；repole活肤温泉水喷雾。其中雅漾喷头最值得吐槽。。。

防晒隔离：paul & joe隔离；sofina防晒；orbis防晒；haba防晒；fancl防晒。

卸妆：fancl卸妆；贝德玛卸妆水；alovivi皇后卸妆水。

暂时只能想到那么多了。。。本少女已把活到现在所得到的护肤经验告诉大家了。。。希望对大家有帮助(￣∇￣)

希望大家皮肤都棒棒O(∩_∩)O
that's all~
编辑于 2015-09-14
柠檬521345
柠檬521345
拯救地球的环保卫士
作为一个追求生活精致得我来说，可以分为一下几点
1.饮食清淡，多吃绿叶菜，忌垃圾食品和过辣
2.多吃新鲜水果，并且选择早上吃
3.经常运动，出出汗，心情好，皮肤好
4.充足的睡眠
一定要自律，坚持下来以上几点，皮肤好，不单单是依靠各种化学护肤品，生活习惯特别重要
发布于 2017-12-21
yoyo
yoyo
渴望无坚不摧 偏偏柔情似水

终于有机会来回答这个问题了hhh。

先交代一下背景，我学化妆比较晚，大三暑假才开始，本身肤色不均，嘴巴周围暗沉和黑眼圈让我本不太会化妆的自己捣鼓的妆容总是暗沉。一直寻找适合自己的粉底或气垫，最后直接破罐子破摔，我不化了！我要开始认真从根源解决我的皮肤问题。

夏天混油，T字部位油腻到骗自己可以当高光，两颊干到用化妆水都疼。

冬天偏干，不用乳液和面霜就干，用了还是觉得油腻腻。心塞……

于是。经历了无数次翻看知乎答案后我开始了所谓好好爱自己的道路。

1、每天早上起床后必须上厕所，这也是我多年的习惯，也正是如此，想睡到八点以后非常困难。便后站一会儿就喝一杯温水，想象自己肠道在清理hh。

2、洗脸的时候我每周一次用洁面粉+洗面奶混合深度清洁一次，不得不承认，洁面粉这个东西泡沫是真的细腻啊，用一次就爱上了。

3、然后水乳霜，这里不推荐水乳，我用的都是比较基础款的无印良品家的，毕竟每个人的肤质是不一样的，就算一样也不一定合适的，所以我建议先试再买，或者买小样自己先试试看。但是最让我惊艳的是玉兰油多效修护霜，不能更爱了。很好推开，很柔软，晚上厚厚的涂上一层，第二天醒来我的小毛孔都不见了。

4、每周一次用米醋洗脸，需要加温水稀释哦，不然刺激太大了，一开始听说可以美白，用了一个月后皮肤确实是亮了，重要的是每次用米醋洗完脸后再擦护肤品神一般的好吸收，而且不干。

5、每晚睡前都自己边数节奏边做眼保健操，每天对着电脑我的眼睛实在是太辛苦了。早晚用眼霜，最近入手了日本的大眼立现，因为我的双眼皮本身就比较窄，一肿就成了内双，巨丑。用了两周效果还不是很明显，有待考察。

6、我原本是不爱喝水的，但是为了皮肤好我开始小口小口不停的喝水，当然也不能一直喝，不然对身体会起反作用。因为我很容易痛经，所以从来不敢喝凉水，不得不说温水真的是个好东西。

7、拒绝垃圾食品。之前看过一句话我觉得特别好，说你的皮肤反应了你吃进肚子里的东西。我非常非常喜欢吃薯片，以前几乎是每天必须吃，现在顶多一个月吃一次。很多人都说不能吃辛辣，但是没办法我无辣不欢，这个正在非常纠结的去改正。

8、多吃水果蔬菜。因为在学校吃饭的缘故，中午的员工餐一般都搭配的比较合理，中午要么会发一个水果要么就是牛奶。还是那句话为了好皮肤和健康，我真的是强忍着吃自己不愿吃的东西。

结果就是，我本身暗沉的肤色经过了将近两个月的慢慢调理改善了好多，犯懒的时候直接水乳霜就可以素颜出门了哈哈哈，这是以前打死我都不敢的事儿嘛~

编辑于 2017-12-05
徐不语
徐不语
想做诗人
早睡早睡早睡！！！
喝水喝水喝水！！！
最简单粗暴并且有效的方法了
可惜很多人都做不到
编辑于 2017-10-17
满月
满月

关于这个问题我真的是要怒答！因为自己真的太有发言权了！

按照国际惯例先上对比图

图上可以看出左上角脸几乎是烂了

右边那个是烂脸调理的后期，最下边是最近的照片，可以看出脸是有明显的好转了。
首先说明一下，自己因为基因的缘故，我的父亲大人就是痘痘肌，母亲大人又白又没有痘痘，可以说是非常羡慕了。但是自己没有遗传到我妈的优良基因，而是遗传了我爸的油痘肌的坏基因！

高中的时候脸上就不要平整，上了大学可能因为作息原因也可能因为水土原因，自己的脸由不太平整变成了上面的太不平整。后来自己渐渐的意识到自己不能这么堕落下去，于是开始漫漫长路拯救烂脸。


下面开始步入正题
❶几乎所有的皮肤问题都和你的内分泌有关系，之前高中的时候总是熬夜，后来上了大学以后熬夜更是家常便饭。在此告诫所有的妹子汉子，要想皮肤好，一定要早睡。
有一句话说得好：敢熬夜到3点的人都在用HR Lamer La prairie；敢熬夜到2点的人都在用兰蔻 EL SK2；敢熬夜到1点的人都在用欧莱雅 玉兰油 （垂死挣扎）；贫穷女孩不敢熬夜。 所以如果你买不起上述任何产品，我ball ball你们11点以前一定要入眠好嘛！

❷注意饮食。多喝水，多吃蔬菜，少吃甜，吃多了对你的皮肤没有任何好处。如果你一天像水缸一样喝至少八杯水，坚持三个月皮肤不好，你来拽掉我的头，机会这么自信。
还有一个要注意的，痘痘肌尽量少喝牛奶，具体高深的道理我也不多讲了，真的就是这样。（对，我就是解释不出原因）
❸说说关于保健品的问题。大家可以看出来，我的皮肤真的是肉眼可见的在变好，而且不仅皮肤细腻了也变白了。
说下自己其实为了美白也努力了不少，年轻不懂的时候吃过很多葡萄籽，还吃过美白丸。但是真的不管用，内分泌更加失调，美白丸有副作用你我他都知道，不要说你没有副作用，每个人体质不一样，你没有副作用那恭喜恭喜恭喜你。葡萄籽这种东西就更是了，其实抗氧化效果肯定好，但是说美白的话真的效果甚微，不过对于防晒黑还是有作用的。
在自己了解到这些情况以后，狂做功课，最后锁定了食补内调的方向。大家都知道大s皮肤很好很白，她就是杏仁粉食补的方法坚持，年复一年的坚持。
自己了解到这些以后终日寻找可靠的杏仁粉，但是某宝真的一言难尽，自己买过几家，味道气味都难闻，喝了也没效果。
后来表姐给我推荐了一个人，是她坚持喝了很久的，也很有效果。自己买回来尝了下，真的好喝！而且非常方便，是一袋一袋的，值得一提的是，里面有胶原蛋白和葡萄籽，又省去我一笔费用有没有！早饭钱都省了！就这个自己真的坚持了小半年，大家都知道胶原蛋白对皮肤也是很好的，从我脸上痘印可以看出来，修复痘印的效果也很不错。而且真的不贵，会一直坚持下去。
在此我要给你们看下我肉体的变化，我骄傲！

❹化妆品的推荐。对于油痘肌建议真的不要总是花大浓妆了，对皮肤的刺激真的大。但是有一个东西是必须要买的，那就是防晒。
说下自己入手的几款防晒

这个是开始入的防晒，总体来说比较推荐，不粘腻，防晒倍数也可以。后来又陆续入手了安耐晒金瓶和软管，因为听说金瓶直接涂在脸上会闷痘，而且倍数太高会对皮肤有刺激，所以不放心买了软管专用面部的。


总之一定要注意的就是要确保正品，毕竟买到假货被坑是一方面，对脸有更多的伤害就不好了。
关于洗面奶，买过悦诗风吟家的绿茶洗面奶，用过几次觉得有些干就弃用了。后来换了芙丽芳丝的，很温和感觉洗的也很干净。自己同时配合luna一起用，但是不要用太强力的档位，也不要每天都用。自己曾经有两天连续用了以后，脸热热红红的人，后来就改成一周两三次。不过没回洗完脸真的觉得干净，滑滑的吹弹可破！（呸！还要不要脸！）

关于水乳，自己用的是珂润的清爽型的水乳，总体来说还不错。开始买的时候主要看中敏感肌专用，因为自己虽然脸烂，但是还容易过敏，哭唧唧。洁面后一定要注意用水乳，皮肤多多补水也是极好的。

基本上要说的就是这些，想到可能有人会求链接求购买方式，之前的保健品都是找的澳洲代购，大家可以自行选择。至于五谷粉是在微信上：yl123qie，自己可以肯定的告诉大家不是三无产品，自己在吃肯定对自己负责的。化妆品也是基本找的代购，推荐一家个人感觉还不错的淘宝店：松清药妆，可能跟别家店比起来会贵些还要邮费，但是自己在他家买过挺多东西都没有假货，大家自行判断～先说好，我没有收广告费，纯分享，不喜勿喷关掉就好，有什么问题可以问我，看下会回答～
发布于 2017-09-26
一个小煤球
一个小煤球
家里蹲
只能说，一大半是天生的，来自父母的基因。怀孕九个月。我的皮肤，纯素颜，无滤镜
亲爱的，不要嫌弃我丑哦。。。。
发布于 2017-09-21
张槿花
张槿花
有着一颗胡思乱想的聪明脑袋

别听楼上瞎吹，护肤品我用这么多了。
大牌的，国产的，都用过了。夜夜敷面膜，并没啥卵用。公众号和大v都是为资本主义服务的， 甭以为割肉掏钱就能让皮肤变好。

我的亲身经验是:
坚持运动，使劲儿防晒(在室内也防晒)，多吃水果，心理压力小点，每天保持好心情。如果有个可爱的男友啪啪啪，气色绝逼upupup(大实话)
没有男票也可以自己买个棒棒，这个对调节体内激素有效。纯天然，无刺激。
(前提是这项运动你要做得开心，不开心就算了)

这绝对比楼上一堆护肤品要有效得多呀～皮肤好这事儿，真不能光靠化学品呀。如果你天天熬夜，喝酒，心事重重，用啥啥sk2都没用..

现在的我已经返璞归真，每晚就用国产护肤品简单拍拍脸。卸妆液防晒霜，看哪个打折就拿哪个。气色比一般人不要好太多～

我的护肤品就三瓶，都是国产货…还用不完...不过防晒霜倒有六七瓶...

当然，这我并不代表我是个省钱娘们...
我只是不希望可爱的姑娘们,把钱都交给楼上那些坏坏的资本主义~so,男人们要省钱的话，还是别把这篇转给女票了

毕竟，每天要保持心情好。一不开心就吃大餐，买进口水果，买让人开心的衣服，去这儿玩那儿玩，听音乐会看画展读小说，还不努力赚钱...
这...这比化妆品花钱多多了( •̀∀•́ )
编辑于 2017-12-06
王志刚
王志刚
整形外科教授，中国最大假体隆胸记录医生。

很多女人都希望自己的肌肤越来越水嫩，为拥有无瑕靓丽的年轻皮肤，不少女性都在脸上下了不少的“血本”，各种乳液、精华、面膜等护肤品都往脸上“堆”，然后效果却没有那么明显。是自己肌肤问题，还是自己护肤方法有问题？这也是很多女性比较困惑的地方。



作为一个整形外科医生，我同时也是一个业余健身爱好者，我的亲身经历告诉我，运动不仅可以增强身体的抵抗力，还能让人保持年轻，让肌肤变好。想要肌肤变好，运动是一个不错的方式。

人在运动的时候，皮肤的血液循环会加快，血液中的氧气和水分等就能有效的传送到皮肤细胞中，细胞水分饱满了，皮肤自然就看起来更加充满弹性和光泽。同时，运动的时候，还会排除汗水，这时候就需要水分来补充身体流失的水分，这样一来，就可以达到清洁皮肤的作用。长时间的坚持运动，还会促进身体细胞的新陈代谢，皮肤表层死亡细胞脱落，新细胞的生成，就会不断改善肌肤暗哑、干燥等问题，让皮肤变得细嫩光滑。


除了运动，另一个让皮肤变好的方法就是医学美容了。医学美容是指通过医学手段，包括手术、药物以及设备等，对人体的容貌等部位进行美化、改善、修复和再生，达到改变人体外部形态、色泽甚至生理功能，让人体变得更加美感的一种医疗手段。目前医学美容的运用已经非常成熟。针对皮肤的医学美容，就是让皮肤变得水润光滑、无斑无纹、紧致有弹性。目前主要有下面几个方法：

1.水光针。这是大家比较熟悉的一种美容方式，也是目前运用比较多的一种美容手段。就是向皮肤深层补充玻尿酸和多种补充营养，补水效果非常好，可以让肌肤持久水润光泽。



2.强脉冲光治疗。就是运用简单的、经选择吸收的脉冲激光对含有色素的结构进行大量破坏。对脸上有雀斑、痤疮等肌肤问题，有比较大的治疗效果。而且治疗之后，皮肤还会变得光亮白皙。

3.超声刀。就是利用超音波能量，让肌肤胶原蛋白大量产生，给肌肤焕发新生活力，增强肌肤弹性，细腻光泽。如果皮肤出现松弛，可以用超声刀进行皮下组织收紧。




至于很多女性使用的护肤品，其中对皮肤有效的成分也就是玻尿酸。也有很多护肤品打出了玻尿酸的概念，但是玻尿酸外用的话，基本不会渗透到皮肤里面去，对皮肤的改善作用也是有限的。

运动，可以让人保持年轻健康的状态；医学美容，让肌肤变水嫩红润。想要肌肤变好，这两种方式是最好的。
编辑于 2017-09-03
白二小姐
白二小姐
♈️University of Western Ontario

作为一个手残党，通过化妆变好看真是难啊，每次画不好反而显得脸很脏，所以在护肤上下了很大功夫，希望素颜有一个好的精神状态。
老规矩，先说一下我的原来的皮肤状态：干皮，经常脸上起白皮，有黑头，熬夜会冒痘痘。
我在去年（大三）才开始意识到要护肤，之前都是很粗糙的瞎往脸上涂。于是在知乎，小红书等app上各种查阅，把很多网上流行的护肤品，秘方试过后暂时总结为以下几种：
卸妆：化妆棉➕卸妆油

这款卸妆油不是那种黏黏的感觉，而且如果洁面后使用，轻轻揉搓半个小时会感觉有小颗粒被揉出，能改善并不严重的黑头。

洁面：洗脸仪➕洗面奶➕一次性擦脸巾

（luna家的洗脸仪）


（倩碧洗面奶）
（一次性洗脸巾淘宝搜，洗脸后用来擦脸，用后就扔，不会担心有滋生细菌）

洗后护肤（早晨）：爽肤水➕乳液➕防晒
觉得倩碧家的这一套还蛮好用的。味道不大，不油腻。


防晒我还没用到特别好用的，就先不推荐喽（略略略）

洗后护肤（晚上）：喷雾➕眼霜➕面膜

（大葡萄喷雾，这款喷雾真的超级超级推荐，平时白天没事就喷，一个月后改善干皮效果很明显！！！感觉会爱到地老天荒，哈哈哈）


（眼霜还是倩碧家的，上面有滚珠，可以一边享受眼霜带来的水润的感觉一边按摩眼袋，感觉这款设计炒鸡赞！）


（兰芝家的睡眠面膜我用了两年了，基本天天使用，个人觉得睡眠面膜在脸上过夜的效果不如敷后洗掉。我一般每天晚上8点就洗脸，敷面膜。然后10点多洗掉。）


（这是AHC家的补水面膜，我一般一周用一片，都是在去黑头之后，个人喜欢先把面膜放在冰箱半个小时后再拿出来使用，那种冰凉的感觉……啧啧啧～）

这些步骤完成就可以美美的睡觉啦～每次敷完AHC家的面膜躺在床上都感觉自己天下第一美，哈哈哈哈哈哈

哦对了，刚刚说到去黑头，关于黑头我觉得我真的太有发言权了。我几乎试过我在网上找到的所有办法，各种去黑头贴，鸡蛋清，盐和小苏打等等。最后终于找到真正好用的办法：
热毛巾敷脸五分钟➕科颜氏白泥面膜➕去黑头针➕城野先生收敛水➕补水面膜
这一套下来真的好用啊，每个步骤都不可以少。我已经每周一次的频率坚持两个月了，黑头基本看不见了

（科颜氏白泥）


（城野先生收敛水）
（去黑头针淘宝啥的都有，不贵）

好啦，这些是我这一年来陆陆续续发现的好用的东西啦，以后有新发现再补充。希望有帮助,哈哈哈。
编辑于 2017-09-01
蓝色树叶熊
蓝色树叶熊
护肤达人

首先让自己的皮肤变好，肯定是需要正确的护肤顺序，不然再用再好的化妆品，每天再好的饮食也无济于事。

护肤顺序这种知识，每次说起来大家都有一种你觉得你懂但是又不太懂的感觉。


为什么好评如潮的化妆品在你脸上不起作用？为什么你怎么护肤都达不到理想的效果呢？


其实很有可能是因为你没有按照正确的护肤顺序来护肤的说。所以，今天我们就老调重弹，再来聊聊正确的护肤顺序。





完整的护肤是包含四个部分的

清洁→补水→精华→保湿


四个步骤相辅相成，做好清洁才能补水，水分充足精华才能吸收，最后做到保湿营养才不会流失。





清洁部分 


首先是面部清洁部分，如果化妆了请洗脸前先卸妆，然后用洗面奶洗脸，洗完脸后可以用一些清洁类面，之后再用化妆水进行二次清洁。如下图所示。





清洁Q&A


Q：为什么要先洁面再去角质？

A：因为去角质并不能起到清洁的作用，去角质只是帮你把老废角质去除，先用洗面奶进行面部清洁有助于去角质产品哦。


Q：清洁面膜和去角质去黑头产品可以一起用吗？

A：最好不要。虽然说现在很多清洁面膜没有去角质的效果，但多少会让皮肤变得脆弱，这时候再去去角质会加重皮肤的负担，所以最好不要同时用。


Q：常常去角质，可是皮肤还是黯淡无光怎么办？

A：去角质其实一周2次就已经算是非常频繁的了，有时候你觉得额头黯淡无光其实并不一定是角质层太厚造成的，而是因为你的皮肤缺水，角质层排列错乱导致你觉得皮肤不光滑，这个时候连续敷补水面膜会有特别大的改善的。所以去角质不要太频繁。


Q：用撕拉面膜之前为什么要用化妆水？

A：因为洗完脸后脸会很干，而撕拉面膜会带走脸上的水分让脸变得更干，所以在使用撕拉面膜前稍微做一些补水工作更有利于皮肤的健康。


Q：化妆水二次清洁一定要做吗？

A：不一定。

1、如果皮肤比较油，建议先使用二次清洁化妆水来减少皮肤油脂负担。

2、干性皮肤可以一周使用一次二次清洁化妆水清洁，相当于温和去角质。

2、一些特定品牌的产品最好先使用二次清洁的化妆水，比如使用SK2的神仙水之前先用SK2清莹露。




补水部分


补水部分很简单啦，就是直接用你的化妆水抹在脸上就行啦。好多人说拍比较有利于吸收，不过明月更喜欢用按压的手法啦。


干皮用滋润一点的有利于水分的补充，油皮用清爽一点的有利于油脂的控制啦~





化妆水Q&A


Q：柔肤水亲肤水美肤水爽肤水紫苏水健康水又是什么呢？

A：其实这些都是化妆水的统称，想爽肤水就是适合油皮用的化妆水啦，紫苏水健康水是某个品牌的某种化妆水专有的名称。但是有一类化妆水却需要注意了，就是有某种特别功效的水，比如SKII的神仙水，雪肌精的雪水，我们给这种水专门起了一个名字叫高机能水。


Q：为什么有些产品需要先乳后水？

A：日本的一些品牌认为越老角质层越厚就越不容易吸收护肤品，所以提倡先乳后水的护肤顺序，即在使用化妆水之前先使用乳液，起到软化角质的作用，帮助护肤品吸收。最具代表性的品牌是日本的奥尔滨和黛珂。






参考价：800RMB/套





参考价：600RMB/套




精华部分


精华真的是最最最最最花钱的部分啊，每一个稍微稍微有点高级的产品就得小一千的感觉，心好累心好累~


精华种类繁多复杂使用顺序很容易搞乱，但只要你抓住一条核心要义，本着这个核心去使用产品就不会出错，那就是先用小分子产品，再用大分子产品。


不过也是很有可能你只会一瓶精华，哈哈哈，是我多虑了~




精华Q&A


Q：肌底液是个啥？有必要用吗？

A：肌底液是为了帮助皮肤吸收化妆品，一般人越老越皮肤越不容易吸收，所以要用肌底液，如果皮肤本身吸收能力就比较强的话就不要用拉的说。你最熟悉的肌底液应该是兰蔻小黑瓶哦~


Q：高机能水是指什么？

A：高机能水是指具有一定特别功效的化妆水，比如IPSA流金水可以帮助IPSA乳液更好地吸收，SK2神仙水促进皮肤再生，雪肌精化妆水具有美白的功能等等。高机能水可以当做质地比较清爽的精华来使用哦。


Q：如果使用多种精华应该按照什么顺序？

A：护肤的总之说先使用小分子产品再使用大分子产品，理论上抗衰精华分子最小，其次是美白精华，最后是保湿精华，但是也要根据具体产品分别对待，不过95%的情况下可以遵循抗衰美白保湿这个顺序的说。




面膜部分


面膜这部分不是每天必须的，2-3天一次面膜比较科学，可以是纸膜也可以是泥膜，要是睡眠面膜的话要用过眼霜之后再用哦。





面膜Q&A


Q：面膜一定要洗吗？

A：一定。这个问题虽然很多人给出的答案不太一样，但是女王认为面膜最好洗掉哦。泥膜就不必说了，一定要洗的。


纸膜的话在脸上呆个15-20分钟，其实精华都已经被你给吸收掉了，剩下很多黏黏的东西其实都是没有什么营养的东西。这种黏糊糊的东西很容易滋生细菌，另外糊在脸上也不利于你后面使用面霜什么的，所以女王觉得一定要洗掉哦~


Q：为什么不能先用面膜再用精华，这样岂不是会把精华洗掉？

A：先用精华再用面膜有利于你的精华液抵达面部深层部分，这样如果已经被皮肤吸收了其实是不管你怎么洗液不会洗掉的说。





保湿部分







保湿Q&A


Q：乳液和面霜需要都涂抹吗？

A：不需要。乳液和面霜的作用都是为了保水，只不过乳液的质地比较稀薄，面霜比较厚重。所以在冬天很干燥的时候建议大家使用面霜，保水力更强，夏天炎热潮湿的时候使用面霜有可能加重油脂分泌，所以只使用乳液即可。另外油皮冬天也油，那只用乳液甚至不用乳液都是可以的。


Q：一定要用特别的颈霜吗？

A：嗯，其实颈霜可以用面霜来代替，但是因为颈部的皮脂腺和汗腺分布数量相对于来面来说少了很多，所以颈部所使用的产品就很有可能和面部使用的产品要有所区别。另外因为颈部皮肤很薄，加上颈部需要常常运动，所以很容易产生颈纹，这时候使用颈霜就可以更好地来呵护颈部了。


来一张完整的护肤顺序图！





有点长~有点多~




没关系，这些护肤步骤不是每一步都要做！


护肤要根据自己的需求来做。


比如你已经白到天际了，就可以不适用美白精华了；或者你才十八九岁胶原蛋白满脸，那肌底液、精华完全可以不用；又或者你在夏天出油非常严重，那乳液都可以不使用的。


去角质和深层清洁操作也要控制使用周期，比如干皮两周一次、混合皮一周一次，油皮一周2-3次。


补水美白面膜一周使用2-3次即可。


但是，但是根据需求来做并不是让要把需求减少到最低，比如25+了还不用眼霜，和干皮不去角质是两码事，还请女王们认真对待自己的皮肤！


今天的讲解就到这里了，还有什么问题大家可以留言给我哦？明月会一一解答的！



前几天扫到女神妮可基德曼的和汤姆克鲁斯的照片，感觉要被她白的闪瞎了。




女神防晒出不出门都会涂的，白天出门长袖长裤墨镜太阳伞一样都不少，而且据说不在太阳下呆超过三个小时，这种自控力获得的回报就是白的发光！


护肤是件持久的事情，不要期待洗一次脸就会把黑头消灭干净，用一次美白精华就会白的发光，一定要坚持并且不断的尝试才行的说！


嗯哼，记得上面那个常常的护肤步骤，晚上多花十几分钟在皮肤护理上，你就可以比别人美十几倍！

编辑于 2017-08-24
匿名用户
匿名用户

中山大学老师的课件....
不知道算不算侵权啊....
网上之前一直流传...
所以就匿了吧……

除了激光没试过外...别的都用过，很有效，感觉比内服vc，vb6等等见效更快

大二大三一年半的时间，因为压力大、熬夜、作息不规律，长了满脸的痤疮，胸前背后也有不少，吃了很多药，但是一直不见好，最后控制住就是内服又加了外抹的这些药好的....

不过，还是要规律作息...大三下学期开始，除了期末复习那段时间几乎没怎么熬过夜，而且绝对忌口，所以现在已经彻底控制住了，痘印也消得差不多了
编辑于 2017-07-26
匿名用户
匿名用户

先放一张12年高三的照片镇楼

那时候一脸的痘痘  后面才知道它叫玫瑰痤疮





再来一张恐怖的自拍 
这也是我唯一一张痘痘鼎盛时期的无滤镜自拍
看着好可怕啊 
好带杀啊
一脸的痘痘 
可怕的是 还没想着去医院

那段时间的照片没有留没加滤镜的 要不然真的都让自己看的作呕
超级自卑
然后 看了医生
湘雅医院 
谢红付教授
确实非常好

然后 就在刚刚 洗完脸的我 无滤镜 虽然现在毛孔还是很大 但比以前好了很多 至少没痘痘了 不红了 












我觉得如果皮肤问题非常严重的话请先相信医生
有时候药物比任何护肤品都好

其次就是 多运动啦 

还有多喝水


我现在坚持每天上午一杯酸奶
下午一个苹果
晚上一片面膜

顺便放下前两天的自拍吧 无滤镜噢 有点暗 所以皮肤毛孔都看不见啦


嗯 以上
 还有看完此条答案马上点赞睡觉吧 
科科
过百再更新吧 
晚安 小仙女们
编辑于 2017-07-25
冯十柒
冯十柒

点券买皮肤啊  全皮肤绝对好
编辑于 2017-07-24
鬼迷日眼
鬼迷日眼
历史，间歇丧

首先，，别太指望护肤品能够从根本上改善些什么，都是自己作的哈哈哈哈哈哈

还是会有安利的，图都贴在最后面，，

A.多喝水，也不单单指液态那些，蔬菜水果啊，含水量高的东西。
B.少喝奶茶，我就很讨厌甜食。另外，鲜榨的果汁那些，NFC是嘛，真的比不上你直接吃个苹果橙子来得好。
C.不要熬夜啊，不能排毒，还有辐射（基本熬夜都是耍手机嘿嘿~）不过多晚睡觉才算熬夜这个问题，我也不知道，看到有些答主是，坚持十二点就睡觉不熬夜这种话，，emmmm，看个人吧，我是十一点（放假后放飞自我又开始爆痘了），因为我妈总是唠叨要给肝脏排毒的时间啊balabala...
D.护肤要适度，主要是指清洁方面，别为了黑头就选择磨砂质地的，一整张脸，角质层的薄厚是不一样的，也许就会伤到别的脆弱的地方，敏感红血丝什么的都来了（嗯我作过），换成清洁面膜，泥状的哈，就比较方便集中鼻头额头那些。我用的是 美丽之旅 ，纯粹是给我爸买大宝然后被导购阿姨诓去买的，口才真是好啊，，脸皮薄就不要去实体店了口袋也跟着薄。。。实用感嘛，第一次用有点刺痛，后来就没了，薄薄一层，别听什么10到15分钟，最面上差不多干了，拿指腹划划去只粘上一点点就可以卸了，能看见白头出来，不过我都没理，下学期准备入粉刺针配合着，鼻子两边那些倒着搓凹凸不平的地方都没了，还行。
E.别给肌肤太多负担。不用太遵循什么，洁面水乳精华面霜这些步骤，你自己皮肤觉得吸收得舒服，刚刚好，就可以了。也不要把所有的需求，比如补水美白都集中在一起，精华面膜各种堆，喝喝柠檬水啊，给自己买顶喜欢的帽子啊，就是无时无刻都要护肤。。。
F.习惯。让自己的护肤成为规律，不能三天打鱼emmmm...以我自己为例吧，两天用一次去角质（就是鼻头额头），三天用一次补水面膜（片式的），平时觉得干就涂层薄薄的睡眠面膜，安利一个玫凯娜的睡眠面膜，搓开在掌心就能化成小水珠，吸收得很快，感觉脸上有层膜但是不会觉得闷啊重啊搓泥啊。。
G.不要拿手指去抠！哈哈哈我家里每个人发现我长痘后的第一句话都是这个。高中压力大，两颊和额头爆痘很厉害，于是某一天，我把刘海夹起来了（对对对我以前就是作，能遮点不就遮点嘛），内心一定要坚定啊，虽然第二天同学都会问我怎么想不开，，还是以前好看，，，如果痘痘实在红肿啊，之前考拉海购凑单的时候买了个the body shop的急救祛痘棒，茶树精油的那个，小啊，真的小，2.5ml，快用完了，，准备剁那个小罐子的。抹上去清清凉凉的，我觉得是有作用，但是看卖家秀里有人说最开始有用但后来就废了，，还是得自己去试吧。。（PS,我姐千年烂脸，我大学后她给我推荐了一个晨欣粉刺清，里头有粉和乳两个，混着搽，她说那个拯救了她，我没太大感觉，上脸以后第二天还能闻到中药味，一个小盒子装着的，一打开，面上写着，“一位老人留给这个世界最后的礼物”，，，差不多意思吧就，看得我哆嗦，感觉有点微商体质）
H.继续安利，，，我是大一下把痘痘基本消下去的~~~首先，感谢成都的水土！蜜汁适合我！！其次，感谢万达里头屈臣氏的导购小姐姐，误打误撞买了套很适合自己的水乳！实体店里头，水乳一个88一个98吧记不清了，当时还肉疼了一下... 室友就各种“鼓励”我emmmm，玫凯娜控油系列的，还买了洁面，小小一个居然用了一学期，，我是每天用两次的人诶，，泡沫易出也挺丰富细密的，味道是超级舒服，什么橄榄，，清洁力度温和，日常足够了，水乳都好好闻，尤其是水，每次洁面完拍上去让我有种干涸了很久的土地瞬间喝饱水的感觉，嘿嘿，一学期里有较长时间都是直接水然后上睡眠面膜的，美滋滋啊别反驳我没按步骤，不听。。乳的质地很滋润，个人感觉上脸比无印的更容易吸收，挤在手上都差不多啦。。

最右边盒装的我没用过，，
从左到右是，水，洁面，乳。
乳打开是压泵（不知道是不是这个叫法），比无印那个好控制些，
水就是一个小孔直接倒
没试过拿化妆棉湿敷，，，

这是那个睡眠面膜啊，快半年用完吧

那个泥膜，某宝上109，气喔当时大妈卖我168，睡眠面膜在屈臣氏也是168，，罐身绝对不是这种打光打得一片白的，就是黑，易推开，送的小平棒挺好用的，多涂几次就熟练啦~~~
但是好奇怪的是，我贴了图的这些，全都没有在其他文章或视频里出现过。满大街的薏仁水啊神仙水啊科颜氏的白泥欣兰的冻膜，都要疲劳了。明明那些那么好用啊，拿去造福吧！ 
编辑于 2017-07-24
陌萱
陌萱
看了这么多答案，我来总结一下。要想皮肤好、无非就是吃好（银耳红枣莲子各种汤、红豆紫米红薯各种杂粮粥，忌糖忌辣忌重口味）睡好，适量运动再加合适的护肤品（保湿防晒清洁），偶尔有几个小姐姐泡泡脚。
发布于 2017-07-23
QR Code of Downloading Zhihu App
下载知乎客户端
与世界分享知识、经验和见解
相关问题
脸颊老是长痘痘？ 4 个回答
怎么样除去痘痘脸？ 16 个回答
皮肤干起皮还长痘，是为什么？ 4 个回答
有什么好的方法可以祛痘让皮肤变好？ 351 个回答
腮帮子两侧长痘痘，反反复复，怎么办？？？ 27 个回答
相关推荐
live
斯坦福心理学课堂：津巴多巨著《心理学与生活》
共 60 节课
live
男生护肤：做好你的面子工程
892 人参与
live
好好洗个澡：护肤从正确洁肤开始
30,618 人读过​
阅读
刘看山知乎指南知乎协议应用工作
侵权举报网上有害信息举报专区
违法和不良信息举报：010-82716601
儿童色情信息举报专区
联系我们 © 2018 知乎

洗面奶+日常水乳：芙丽芳丝（日系护肤品好用真的不是没有道理的，非常补水但是一点都不油！）

创福康（尤其适合痘皮，修护皮肤屏障，淡化痘印，可自行百度）
可复美（适合痘痘恢复差不多后期的维稳，以及减轻早期痘印、痘坑。注意是早期）
这真的不是三无产品！！吐血推荐！！请自行百度，小红书！！
成分简直不要太安全，只有一样就是胶原原液，非常适合皮肤受损之后的修护皮肤，当然如果完全是健康皮肤，这两个就没有必要了，是痘皮朋友的福音！

回答了“怎样把皮肤养的好好的”这个问题
写了一篇纯粹的养生帖，满满的都是干货，可以让你的皮肤吃的白白嫩嫩、细腻紧致的私藏方法全在里面了！不看真的会后悔！
很多宝宝问我的银耳莲子百合枸杞红枣羹的做法，我也写在这个回答里了～
https://www.zhihu.com/question/35033860/answer/202053891
（一）每天一碗银耳莲子百合红枣枸杞羹

定期脸部去角质，次数一定要控制好，不然脸部皮肤会越来越薄。
2.眼部肌肤按状态选择眼霜，不是看年龄大小。别说什么我才十八岁，简单保湿就好了，现在十八岁的女孩子有的是天天捧着手机的、打游戏的、熬夜的，眼部肌肤早就不年轻啦（说的就是我）所以要提早使用功效型的眼霜，比如去细纹的，否则出现第一条细纹就再也修复不了了（说的还是我）

4.防晒霜一定要涂，不管哪个季节，不管有没有太阳。虽然我脸部肤色有点不均匀，有暗沉，但是总体还是比较白的，所以我对防晒这方面一直很忽视，想着自己反正挺白的。直到这个学期，研究护肤到了一定阶段，就了解了防晒的重要性。于是开始每天擦防晒霜。真的，你不尝试永远都不知道结果会是怎样。我比以前又白了一个度，关键是我眼睛下面之前有很多斑点，我一直以为去不掉，央求我妈带我去医美弄掉来着（当然她还没答应）在我坚持涂了一个月防晒➕美白精华之后，居然淡的几乎看不见了。我以前真的挺懒的，有两颗陈年痘印我都懒得管他，虽然每天看着挺讨厌的，但是还是选择了忽视。现在痘印也没了，脸看起来真的干净好多。所以说，人真的不能懒，你不努力，就不知道自己能变得多多好。

 FILORGA菲洛嘉360度雕塑眼霜
（参考价格：345）
FILORGA是法国比较高端的药妆品牌，我是抱着试一试的心态买的，但是出乎意料的好用啊！保湿度刚刚好，很轻薄，涂上眼一下就吸收了，完全不会长脂肪粒。去细纹效果也很不错，我的细纹有淡化，真的很欣慰。最明显的是去眼部浮肿，早上起来眼部浮肿得很厉害，去浮肿可以让眼睛看起来更大～真的误打误撞买了一瓶超喜欢的眼霜，很适合初期抗老的仙女们。

 saborino早安面膜

（参考价格：138/32片）
最近很 的一款面膜，是真的好用。我觉得很多东西成了网红款，除开本身的宣传，能够做到口口相传，是真的有它的道理的，那些用了说不好的，我觉得只是产品不适合自己的皮肤而已。所以，理性跟风。这个早安面膜，敷60秒就可以了，特别适合懒人有没有！我现在每天早上起来洗完脸之后敷一片，然后涂个面霜，防晒就好了。因为它包含了洁面、化妆水、乳液的功效，敷完之后，脸会紧致提亮很多。熬夜之后，皮肤状态不好，化妆前可以敷一片这个，算很平价的急救面膜～而且它是薄荷味，早上瞌睡都没了，提神醒脑哈哈哈。

 Trilogy玫瑰果油

 （参考价格：248 45ml）
这是新西兰认证的纯天然植物品牌，我对这些纯天然的、植物的东西都很有好感，觉得更加温和，效果更为持久。画个重点！玫瑰果油不是精油！果油是从蔷薇果榨取而来，可以直接涂抹于脸部。以前从来没用过油类的护肤品，但是用了就爱上了。皮肤会变的又软又有弹性，而且这个有美白效果！皮肤会透亮有光泽。超级适合干皮，想必干皮都想要有光泽肌吧～
油皮慎入！！！

 Minon氨基酸乳液

（参考价格：155）
日系护肤品牌。真的巨好用，还便宜。就是纯粹的补水保湿，无其他功效。保湿效果真的很棒棒，有一些乳液虽然很滋润，但会油腻，这个完全不会，滋润度高的同时，还保持了清爽！一点都不沾！分清爽型和滋润型，价格是颗小白菜，不好用来捏我～

 elta md氨基酸洁面


（参考价格：156）
这个是真爱洁面了！淡淡的青瓜味很好闻，泡沫很细腻，一点都不刺激！洗脸的感觉简直不要太美好，洗完之后脸又干净又嫩滑，一点都不干。关键是性价比很高啊！156左右的价格，用量很省的，一瓶早晚用，我可以用三个月。

 Olay小白瓶

～（参考价格：160）
看K大的微博中的草，平价版的美白精华。k大推荐的是美版小白瓶，烟酰胺浓度更高，但我是找台湾代购买的台版的，我觉得浓度对我来说够了～ 美白淡斑的效果很明显，一个月肉眼可见的变白了，对我来说，主要是斑淡了很多～ 还有防晒的功劳啦，一定要记得防晒，不然美白精华就白涂了哟

 下面就是些老生常谈的产品了，因为很好用，还是把它们写了上来。

Fancl卸妆油

（参考价格：160）非常好用，完全不会堵塞毛孔，对黑头也很有效，虽然是油状，但不会油腻，很好乳化，彩妆能卸的很干净。唯一的不足是，它家主打无添加，是不含防腐剂的，因此两个月就要用完。我用不完，所以，把爱转移到了贝德玛。

 贝德玛卸妆水

（参考价格：156）
目前已经用了三瓶了，无限回购～
我用的是粉色，粉色适合干性、中性、敏感肌，蓝色适合混油、油性、痘痘肌。
温和不刺激，卸妆水卸妆真的很清爽，这款卸妆力也很足够，我一般用化妆棉擦两遍就好了。这么好用还便宜大碗，500ml可以用很久～
 曼丹眼唇卸妆

（参考价格：68）一直在用的眼唇卸妆液，很温和，卸妆力很强，化妆棉浸湿敷一会儿，就可以轻松卸掉眼唇妆了。

 freeplus氨基酸洁面

（参考价格：148）用了三四支，氨基酸洁面的网红款了，真的挺好用的。泡沫不算很丰富，但是非常细腻，洗的很干净，洗完之后不会紧绷，如果喜欢泡沫丰富的，用个起泡网就好了。

 Aesop樱草深层清洁面膜

（参考价格：330/120ml）
Aesop是澳洲的护肤品牌，主打纯天然纯植物，买他家的东西，基本不会踩雷，性冷淡风的外貌也深得我心～
这个清洁面膜是朋友安利给我的，相比科颜氏的清洁面膜，这款没有那么厚重，但是清洁力却不相上下，这款更适合干皮和敏感肌～每次用完，脸又嫩又滑，自己都忍不住捏两下qaq

 欣兰冻膜

（参考价格：115）
这个我主要用来祛黑头的，厚敷在鼻子上，过20-30分钟，用自带的刮板刮掉，就能看到很多黑头白头冒出来，我就会用粉刺针的圆环那头挂掉它们。虽然黑头是护肤品不能完全去除的，但是定期去黑头，还是能让鼻子维持在一个比较干净的状态。
这里还推荐一个泰国white去黑头水，效果真很明显，不过力度比较大，要注意使用次数。小小的一个才20来块钱。

 城野医生毛孔收敛水

（参考价格：108/100ml）
用完清洁面膜一定要记得收缩毛孔！！！
这个已经是火到不需要我推荐的产品，真的是有火的道理的，上脸很清凉，会有明显的缩小毛孔的效果，橘子味特别适合夏天，还能镇定皮肤，也是我一直会回购的。

一直觉得护肤和减肥一样，是一件你努力就会有回报的事情。
“如果有方法的事情你都做不好，那么那些诸如爱情之类的无迹可循的事情你又能把握的住吗？”
4.城野医生毛孔收敛水我用着收缩毛孔效果挺好的，我身边的朋友也是习惯性回购的。如果一些小可爱觉得对你来说效果不明显的话，可以用别的产品收缩毛孔呀。我并不是让你一定要用它，只是告诉你，做完清洁面膜之后一定一定要收缩毛孔，

城野医生egf原液！
1. 不要浪费，痘痘痘疤部位做了去角质再涂这个吸收更好，洗完脸直接涂它，之后再水.精华.乳。
2. 如果痘痘有点肿，我喜欢用的最粗暴的方法就是把阿莫西林胶囊拔开把药粉倒出来混点芦荟胶糊在上面，一觉醒来就消下去了，接着就可以涂egf了！液！

无印良品（三种型号）
这款水乳没有什么惊人之处，但是基础保湿和性价比相当好，而且成分安全。皮肤过敏期间用这个也没问题。
近江小熊
防晒力好，在我看来和小金瓶一样。而且不油腻，有点泛白而且很干，但是价格便宜，用来擦身体的首选。晚上用皂基洁面奶可以洗干净，洗完要擦身体乳，不然会让皮肤变粗糙。

吃粗粮杂粮并不只是为了增加营养，同时也是为了稳定血糖。因为五谷杂粮里含有较多的纤维，纤维可以延缓血糖的上升速度。评论区里说受不了不吃米饭面条的小伙伴们，号主我也是吃的啊。不是让你们戒掉，细粮也是要吃的啊，粗细粮搭配，大家注意看清楚！请大家每天至少把主食里的1/3-1/2换成五谷杂粮，吃饭的时候先蔬菜（每天500g）、再荤菜、最后淀粉，对降糖是非常有帮助的。每天水果的量，男生3个拳头大小，女生2个拳头大小。


卸妆油：DHC深层卸妆油
洗面奶：旁氏米萃润白洗面奶（不到20块，以前答主楼下超市就有卖，知乎推荐火了之后，到处都断货，上周走了五家店才买到）、植村秀泡沫洗面奶（好好闻）
保湿水：只求无过的话，雅漾咯；欧缇丽的葡萄籽喷雾保湿也不错；（买Melvita的玫瑰果油时，顺手买了他家喷雾香香的也喜欢）
眼部精华：Elizabeth Arden新生代时空复合眼部胶囊
眼霜：资生堂百优眼霜（也没觉得特别有效，但是一直也没找到更好的替代的）
精华：EsteeLauder雅诗兰黛 ANR精华露、雅顿的黄金导航也很好用，就是脸部精华那个，颗粒比眼部精华大，用完之后脸都Q弹Q弹的，但是要按摩好久才能抹匀
乳液：倩碧黄油（无油那款）
面霜：Olay新生塑颜金纯面霜（只在冬天用，去北方的时候，会自己加一点点Melvita的玫瑰果油在面霜里）
防晒霜：长时间户外就用Allie，平时觉得碧柔那个奶黄色瓶装的就够了（涂很多）
磨砂膏：DHC天然原粒磨砂膏（配合DHC的卸妆油真的还挺好用呀）
面膜：Fresh红茶面膜（非常非常非常爱）+玫瑰面膜（非常爱）；彼得罗夫的玫瑰啫喱面膜也还可以，也更平价。纸膜除非要救急，基本上不太喜欢用。
