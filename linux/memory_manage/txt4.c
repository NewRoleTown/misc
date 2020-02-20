
#define MIGRATE_UNMOVABLE     0
#define MIGRATE_RECLAIMABLE   1
#define MIGRATE_MOVABLE       2
#define MIGRATE_RESERVE       3
#define MIGRATE_ISOLATE       4 /* can't allocate from here */
#define MIGRATE_TYPES         5

默认
#define MAX_ORDER 11

struct free_area {
	struct list_head	free_list[MIGRATE_TYPES];
	unsigned long		nr_free;
};

static int fallbacks[MIGRATE_TYPES][MIGRATE_TYPES-1] = {
	[MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE,   MIGRATE_RESERVE },
	[MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE,   MIGRATE_RESERVE },
	[MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE, MIGRATE_RESERVE },
	[MIGRATE_RESERVE]     = { MIGRATE_RESERVE,     MIGRATE_RESERVE,   MIGRATE_RESERVE }, /* Never used */
};

#define pageblock_order		(MAX_ORDER-1)
#define pageblock_nr_pages	(1UL << pageblock_order)

build_all_zonelists中
	if (vm_total_pages < (pageblock_nr_pages * MIGRATE_TYPES))
		page_group_by_mobility_disabled = 1;
这里的判断启用迁移

#define __GFP_RECLAIMABLE ((__force gfp_t)0x80000u) /* Page is reclaimable */
#define __GFP_MOVABLE	((__force gfp_t)0x100000u)  /* Page is movable */
如果没有这两个标记，就是不可移动的


//00    unmovable
//01    reclaimable
//10    movable
//可用作freearea数组索引
/* Convert GFP flags to their corresponding migrate type */
static inline int allocflags_to_migratetype(gfp_t gfp_flags)
{
	WARN_ON((gfp_flags & GFP_MOVABLE_MASK) == GFP_MOVABLE_MASK);

	if (unlikely(page_group_by_mobility_disabled))
		return MIGRATE_UNMOVABLE;

	/* Group based on mobility */
	return (((gfp_flags & __GFP_MOVABLE) != 0) << 1) |
		((gfp_flags & __GFP_RECLAIMABLE) != 0);
}

//页的移动性在释放页时会回到正确的地方
//这是否意味着可以在页还在伙伴系统时，就用set修改
static inline int get_pageblock_migratetype(struct page *page)
{
	if (unlikely(page_group_by_mobility_disabled))
		return MIGRATE_UNMOVABLE;

	return get_pageblock_flags_group(page, PB_migrate, PB_migrate_end);
}

//内存初始化时所有的页都是可移动的
/*
 * Initially all pages are reserved - free ones are freed
 * up by free_all_bootmem() once the early boot process is
 * done. Non-atomic initialization, single-pass.
 */
void __meminit memmap_init_zone(unsigned long size, int nid, unsigned long zone,
		unsigned long start_pfn, enum memmap_context context)
{
	struct page *page;
	unsigned long end_pfn = start_pfn + size;
	unsigned long pfn;

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		/*
		 * There can be holes in boot-time mem_map[]s
		 * handed to this function.  They do not
		 * exist on hotplugged memory.
		 */
		if (context == MEMMAP_EARLY) {
			if (!early_pfn_valid(pfn))
				continue;
			if (!early_pfn_in_nid(pfn, nid))
				continue;
		}
		page = pfn_to_page(pfn);
		set_page_links(page, zone, nid, pfn);
		init_page_count(page);
		reset_page_mapcount(page);
		SetPageReserved(page);

		/*
		 * Mark the block movable so that blocks are reserved for
		 * movable at startup. This will force kernel allocations
		 * to reserve their blocks rather than leaking throughout
		 * the address space during boot when many long-lived
		 * kernel allocations are made. Later some blocks near
		 * the start are marked MIGRATE_RESERVE by
		 * setup_zone_migrate_reserve()
		 */
		if ((pfn & (pageblock_nr_pages-1)))
			set_pageblock_migratetype(page, MIGRATE_MOVABLE);

		INIT_LIST_HEAD(&page->lru);
#ifdef WANT_PAGE_VIRTUAL
		/* The shift won't overflow because ZONE_NORMAL is below 4G. */
		if (!is_highmem_idx(zone))
			set_page_address(page, __va(pfn << PAGE_SHIFT));
#endif
	}
}

free_area_init_nodes
在DMA区之后寻找一个位置分配mem_map



gfp_zone(gfp_t flags)返回zone类型
#define __GFP_WAIT	((__force gfp_t)0x10u)	/* Can wait and reschedule? */
#define __GFP_HIGH	((__force gfp_t)0x20u)	/* Should access emergency pools? */
#define __GFP_IO	((__force gfp_t)0x40u)	/* Can start physical IO? */
#define __GFP_FS	((__force gfp_t)0x80u)	/* Can call down to low-level FS? */
#define __GFP_COLD	((__force gfp_t)0x100u)	/* Cache-cold page required */
#define __GFP_NOWARN	((__force gfp_t)0x200u)	/* Suppress page allocation failure warning */
#define __GFP_REPEAT	((__force gfp_t)0x400u)	/* Retry the allocation.  Might fail */
#define __GFP_NOFAIL	((__force gfp_t)0x800u)	/* Retry for ever.  Cannot fail */
#define __GFP_NORETRY	((__force gfp_t)0x1000u)/* Do not retry.  Might fail */
#define __GFP_COMP	((__force gfp_t)0x4000u)/* Add compound page metadata */
#define __GFP_ZERO	((__force gfp_t)0x8000u)/* Return zeroed page on success */
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) /* Don't use emergency reserves */
#define __GFP_HARDWALL   ((__force gfp_t)0x20000u) /* Enforce hardwall cpuset memory allocs */
#define __GFP_THISNODE	((__force gfp_t)0x40000u)/* No fallback, no policies */
#define __GFP_RECLAIMABLE ((__force gfp_t)0x80000u) /* Page is reclaimable */
#define __GFP_MOVABLE	((__force gfp_t)0x100000u)  /* Page is movable */

__alloc_pages(gfp_mask, order,NODE_DATA(nid)->node_zonelists + gfp_zone(gfp_mask));

#define ALLOC_NO_WATERMARKS	0x01 /* don't check watermarks at all */
#define ALLOC_WMARK_MIN		0x02 /* use pages_min watermark */
#define ALLOC_WMARK_LOW		0x04 /* use pages_low watermark */
#define ALLOC_WMARK_HIGH	0x08 /* use pages_high watermark */
#define ALLOC_HARDER		0x10 /* try to alloc harder */
#define ALLOC_HIGH		0x20 /* __GFP_HIGH set */
#define ALLOC_CPUSET		0x40 /* check for correct cpuset */

int zone_watermark_ok(struct zone *z, int order, unsigned long mark,
		      int classzone_idx, int alloc_flags)
{
	/* free_pages my go negative - that's OK */
	long min = mark;
    //获取空闲页数目
	long free_pages = zone_page_state(z, NR_FREE_PAGES) - (1 << order) + 1;
	int o;

	if (alloc_flags & ALLOC_HIGH)
		min -= min / 2;
	if (alloc_flags & ALLOC_HARDER)
		min -= min / 4;

	if (free_pages <= min + z->lowmem_reserve[classzone_idx])
		return 0;
	for (o = 0; o < order; o++) {
		/* At the next order, this order's pages become unavailable */
		free_pages -= z->free_area[o].nr_free << o;

		/* Require fewer higher order pages to be free */
		min >>= 1;

		if (free_pages <= min)
			return 0;
	}
	return 1;
}

get_page_from_freelist

struct page * fastcall
__alloc_pages(gfp_t gfp_mask, unsigned int order,
		struct zonelist *zonelist)
{
	const gfp_t wait = gfp_mask & __GFP_WAIT;
	struct zone **z;
	struct page *page;
	struct reclaim_state reclaim_state;
	struct task_struct *p = current;
	int do_retry;
	int alloc_flags;
	int did_some_progress;

    //可能会睡眠并调度
	might_sleep_if(wait);

	if (should_fail_alloc_page(gfp_mask, order))
		return NULL;

restart:
	z = zonelist->zones;  /* the list of zones suitable for gfp_mask */

	if (unlikely(*z == NULL)) {
		/*
		 * Happens if we have an empty zonelist as a result of
		 * GFP_THISNODE being used on a memoryless node
		 */
		return NULL;
	}

    //首次尝试分配内存
	page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, order,
				zonelist, ALLOC_WMARK_LOW|ALLOC_CPUSET);
	if (page)
		goto got_pg;

	/*
	 * GFP_THISNODE (meaning __GFP_THISNODE, __GFP_NORETRY and
	 * __GFP_NOWARN set) should not cause reclaim since the subsystem
	 * (f.e. slab) using GFP_THISNODE may choose to trigger reclaim
	 * using a larger set of nodes after it has established that the
	 * allowed per node queues are empty and that nodes are
	 * over allocated.
	 */
	if (NUMA_BUILD && (gfp_mask & GFP_THISNODE) == GFP_THISNODE)
		goto nopage;

    //唤醒kswapd守护进程
	for (z = zonelist->zones; *z; z++)
		wakeup_kswapd(*z, order);

	/*
	 * OK, we're below the kswapd watermark and have kicked background
	 * reclaim. Now things get more complex, so set up alloc_flags according
	 * to how we want to proceed.
	 *
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_HARDER (!wait) and ALLOC_HIGH (__GFP_HIGH).
	 */

    //调整水位
	alloc_flags = ALLOC_WMARK_MIN;
    //不能睡眠
	if ((unlikely(rt_task(p)) && !in_interrupt()) || !wait)
		alloc_flags |= ALLOC_HARDER;
	if (gfp_mask & __GFP_HIGH)
		alloc_flags |= ALLOC_HIGH;
	if (wait)
		alloc_flags |= ALLOC_CPUSET;

	/*
	 * Go through the zonelist again. Let __GFP_HIGH and allocations
	 * coming from realtime tasks go deeper into reserves.
	 *
	 * This is the last chance, in general, before the goto nopage.
	 * Ignore cpuset if GFP_ATOMIC (!wait) rather than fail alloc.
	 * See also cpuset_zone_allowed() comment in kernel/cpuset.c.
	 */
	page = get_page_from_freelist(gfp_mask, order, zonelist, alloc_flags);
	if (page)
		goto got_pg;

	/* This allocation should allow future memory freeing. */
rebalance:
    //当前进程是内存分配器
    //或者当前进程正在被OOM清理
    //且不在中断中
	if (((p->flags & PF_MEMALLOC) || unlikely(test_thread_flag(TIF_MEMDIE)))
			&& !in_interrupt()) {
        //没标记不使用紧急内存
		if (!(gfp_mask & __GFP_NOMEMALLOC)) {
nofail_alloc:
			/* go through the zonelist yet again, ignoring mins */
            //忽略水印
			page = get_page_from_freelist(gfp_mask, order,
				zonelist, ALLOC_NO_WATERMARKS);
			if (page)
				goto got_pg;
			if (gfp_mask & __GFP_NOFAIL) {
				congestion_wait(WRITE, HZ/50);
				goto nofail_alloc;
			}
		}
		goto nopage;
	}

	/* Atomic allocations - we can't balance anything */
	if (!wait)
		goto nopage;
    //调度,下面是低速路径
	cond_resched();

	/* We now go into synchronous reclaim */
	cpuset_memory_pressure_bump();
	p->flags |= PF_MEMALLOC;
    //
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;
    //换出不常用的页,设置MEMALLOC标记的原因是这个函数可能自己需要再分配内存，而这个标记在上面那段分配很积极
	did_some_progress = try_to_free_pages(zonelist->zones, order, gfp_mask);

	p->reclaim_state = NULL;

	p->flags &= ~PF_MEMALLOC;

	cond_resched();

    //per-cpu缓存拿回伙伴系统
	if (order != 0)
		drain_all_local_pages();

	if (likely(did_some_progress)) {
		page = get_page_from_freelist(gfp_mask, order,
						zonelist, alloc_flags);
		if (page)
			goto got_pg;
	} else if ((gfp_mask & __GFP_FS) && !(gfp_mask & __GFP_NORETRY)) {
		if (!try_set_zone_oom(zonelist)) {
			schedule_timeout_uninterruptible(1);
			goto restart;
		}

		/*
		 * Go through the zonelist yet one more time, keep
		 * very high watermark here, this is only to catch
		 * a parallel oom killing, we must fail if we're still
		 * under heavy pressure.
		 */
		page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, order,
				zonelist, ALLOC_WMARK_HIGH|ALLOC_CPUSET);
		if (page) {
			clear_zonelist_oom(zonelist);
			goto got_pg;
		}

		/* The OOM killer will not help higher order allocs so fail */
		if (order > PAGE_ALLOC_COSTLY_ORDER) {
			clear_zonelist_oom(zonelist);
			goto nopage;
		}

		out_of_memory(zonelist, gfp_mask, order);
		clear_zonelist_oom(zonelist);
		goto restart;
	}

	/*
	 * Don't let big-order allocations loop unless the caller explicitly
	 * requests that.  Wait for some write requests to complete then retry.
	 *
	 * In this implementation, __GFP_REPEAT means __GFP_NOFAIL for order
	 * <= 3, but that may not be true in other implementations.
	 */
	do_retry = 0;
	if (!(gfp_mask & __GFP_NORETRY)) {
		if ((order <= PAGE_ALLOC_COSTLY_ORDER) ||
						(gfp_mask & __GFP_REPEAT))
			do_retry = 1;
		if (gfp_mask & __GFP_NOFAIL)
			do_retry = 1;
	}
	if (do_retry) {
		congestion_wait(WRITE, HZ/50);
		goto rebalance;
	}

nopage:
	if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit()) {
		printk(KERN_WARNING "%s: page allocation failure."
			" order:%d, mode:0x%x\n",
			p->comm, order, gfp_mask);
		dump_stack();
		show_mem();
	}
got_pg:
	return page;
}
static struct page *buffered_rmqueue(struct zonelist *zonelist,
			struct zone *zone, int order, gfp_t gfp_flags)
{
	unsigned long flags;
	struct page *page;
	int cold = !!(gfp_flags & __GFP_COLD);
	int cpu;
    //迁移类型
	int migratetype = allocflags_to_migratetype(gfp_flags);

again:
	cpu  = get_cpu();
	if (likely(order == 0)) {
        //1页，从pcpu高速缓存获取
		struct per_cpu_pages *pcp;

		pcp = &zone_pcp(zone, cpu)->pcp[cold];
		local_irq_save(flags);
		if (!pcp->count) {
            //高速缓存不够
            //将新获取的页的迁移类型写入private
			pcp->count = rmqueue_bulk(zone, 0,
					pcp->batch, &pcp->list, migratetype);
			if (unlikely(!pcp->count))
				goto failed;
		}

		/* Find a page of the appropriate migrate type */
		list_for_each_entry(page, &pcp->list, lru)
			if (page_private(page) == migratetype)
				break;

		/* Allocate more to the pcp list if necessary */
		if (unlikely(&page->lru == &pcp->list)) {
			pcp->count += rmqueue_bulk(zone, 0,
					pcp->batch, &pcp->list, migratetype);
			page = list_entry(pcp->list.next, struct page, lru);
		}

		list_del(&page->lru);
		pcp->count--;
	} else {
		spin_lock_irqsave(&zone->lock, flags);
		page = __rmqueue(zone, order, migratetype);
		spin_unlock(&zone->lock);
		if (!page)
			goto failed;
	}

	__count_zone_vm_events(PGALLOC, zone, 1 << order);
	zone_statistics(zonelist, zone);
	local_irq_restore(flags);
	put_cpu();

	VM_BUG_ON(bad_range(zone, page));
    //_count设置为1
	if (prep_new_page(page, order, gfp_flags))
		goto again;
	return page;

failed:
	local_irq_restore(flags);
	put_cpu();
	return NULL;
}
巨型页的lru另作他用，private指向第一个页

static struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
						int migratetype)
{
	unsigned int current_order;
	struct free_area * area;
	struct page *page;

	/* Find a page of the appropriate size in the preferred list */
	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		area = &(zone->free_area[current_order]);
		if (list_empty(&area->free_list[migratetype]))
			continue;

		page = list_entry(area->free_list[migratetype].next,
							struct page, lru);
		list_del(&page->lru);
		rmv_page_order(page);
		area->nr_free--;
		__mod_zone_page_state(zone, NR_FREE_PAGES, - (1UL << order));
		expand(zone, page, order, current_order, area, migratetype);
		return page;
	}

	return NULL;
}

static struct page *__rmqueue_fallback(struct zone *zone, int order,
						int start_migratetype)
{
	struct free_area * area;
	int current_order;
	struct page *page;
	int migratetype, i;

    //上面函数失败后,偷取其他类型
    //偷取的时候需要从最大块开始
	/* Find the largest possible block of pages in the other list */
	for (current_order = MAX_ORDER-1; current_order >= order;
						--current_order) {
		for (i = 0; i < MIGRATE_TYPES - 1; i++) {
			migratetype = fallbacks[start_migratetype][i];

			/* MIGRATE_RESERVE handled later if necessary */
			if (migratetype == MIGRATE_RESERVE)
				continue;

			area = &(zone->free_area[current_order]);
			if (list_empty(&area->free_list[migratetype]))
				continue;

			page = list_entry(area->free_list[migratetype].next,
					struct page, lru);
			area->nr_free--;
            //偷取到一块

			/*
			 * If breaking a large block of pages, move all free
			 * pages to the preferred allocation list. If falling
			 * back for a reclaimable kernel allocation, be more
			 * agressive about taking ownership of free pages
			 */
            //如果当前偷取的块很大
            //或者偷取者是reclaimable
			if (unlikely(current_order >= (pageblock_order >> 1)) ||
					start_migratetype == MIGRATE_RECLAIMABLE) {
				unsigned long pages;
				pages = move_freepages_block(zone, page,
								start_migratetype);

				/* Claim the whole block if over half of it is free */
                //如果偷取的页数大于阈值，讲位图标记为新的类型
				if (pages >= (1 << (pageblock_order-1)))
					set_pageblock_migratetype(page,
								start_migratetype);

				migratetype = start_migratetype;
			}

			/* Remove the page from the freelists */
			list_del(&page->lru);
			rmv_page_order(page);
			__mod_zone_page_state(zone, NR_FREE_PAGES,
							-(1UL << order));

            //下面这段不理解，延时到free再合到start_migratetype上?
			if (current_order == pageblock_order)
				set_pageblock_migratetype(page,
							start_migratetype);

            //这里如果进过前面的if,切割剩下的块还给原类型
			expand(zone, page, order, current_order, area, migratetype);
			return page;
		}
	}

	/* Use MIGRATE_RESERVE rather than fail an allocation */
	return __rmqueue_smallest(zone, order, MIGRATE_RESERVE);
}

int move_freepages_block(struct zone *zone, struct page *page, int migratetype)
{
	unsigned long start_pfn, end_pfn;
	struct page *start_page, *end_page;

    //第一页的pfn
	start_pfn = page_to_pfn(page);
    //对齐第一个页，应为位图的管理是按这个对齐来得
	start_pfn = start_pfn & ~(pageblock_nr_pages-1);
    //对齐后的第一个page
	start_page = pfn_to_page(start_pfn);
    //该位图所包含的最后一个page
	end_page = start_page + pageblock_nr_pages - 1;
    //该位图所包含的最后一个pfn
	end_pfn = start_pfn + pageblock_nr_pages - 1;

    //不能跨zone
	/* Do not cross zone boundaries */
	if (start_pfn < zone->zone_start_pfn)
		start_page = page;
	if (end_pfn >= zone->zone_start_pfn + zone->spanned_pages)
		return 0;

	return move_freepages(zone, start_page, end_page, migratetype);
}

/*
 * Move the free pages in a range to the free lists of the requested type.
 * Note that start_page and end_pages are not aligned on a pageblock
 * boundary. If alignment is required, use move_freepages_block()
 */
int move_freepages(struct zone *zone,
			struct page *start_page, struct page *end_page,
			int migratetype)
{
	struct page *page;
	unsigned long order;
	int pages_moved = 0;

	for (page = start_page; page <= end_page;) {
		if (!pfn_valid_within(page_to_pfn(page))) {
			page++;
			continue;
		}
		if (!PageBuddy(page)) {
			page++;
			continue;
		}

		order = page_order(page);
		list_del(&page->lru);
		list_add(&page->lru,
			&zone->free_area[order].free_list[migratetype]);
		page += 1 << order;
		pages_moved += 1 << order;
	}

	return pages_moved;
}

	local_irq_save(flags);
	free_one_page(page_zone(page), page, order);
	local_irq_restore(flags);

static void free_one_page(struct zone *zone, struct page *page, int order)
{
	spin_lock(&zone->lock);
	zone_clear_flag(zone, ZONE_ALL_UNRECLAIMABLE);
	zone->pages_scanned = 0;
	__free_one_page(page, zone, order);
	spin_unlock(&zone->lock);
}

static inline void __free_one_page(struct page *page,
		struct zone *zone, unsigned int order)
{
	unsigned long page_idx;
	int order_size = 1 << order;
	int migratetype = get_pageblock_migratetype(page);
    ...
	page_idx = page_to_pfn(page) & ((1 << MAX_ORDER) - 1);

	VM_BUG_ON(page_idx & (order_size - 1));
	VM_BUG_ON(bad_range(zone, page));

	__mod_zone_page_state(zone, NR_FREE_PAGES, order_size);
	while (order < MAX_ORDER-1) {
		unsigned long combined_idx;
		struct page *buddy;

		buddy = __page_find_buddy(page, page_idx, order);
		if (!page_is_buddy(page, buddy, order))
			break;		/* Move the buddy up one level. */

		list_del(&buddy->lru);
		zone->free_area[order].nr_free--;
		rmv_page_order(buddy);
		combined_idx = __find_combined_index(page_idx, order);
		page = page + (combined_idx - page_idx);
		page_idx = combined_idx;
		order++;
	}
	set_page_order(page, order);
	list_add(&page->lru,
		&zone->free_area[order].free_list[migratetype]);
	zone->free_area[order].nr_free++;
}
