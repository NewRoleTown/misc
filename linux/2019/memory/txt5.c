alloc_pages_node
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
			struct zonelist *zonelist, nodemask_t *nodemask)
{
	enum zone_type high_zoneidx = gfp_zone(gfp_mask);
	struct zone *preferred_zone;
	struct page *page = NULL;
	//可移动性
	int migratetype = allocflags_to_migratetype(gfp_mask);
	unsigned int cpuset_mems_cookie;
	//分配标志
	int alloc_flags = ALLOC_WMARK_LOW|ALLOC_CPUSET;
	struct mem_cgroup *memcg = NULL;

	gfp_mask &= gfp_allowed_mask;

	lockdep_trace_alloc(gfp_mask);

	might_sleep_if(gfp_mask & __GFP_WAIT);

	if (should_fail_alloc_page(gfp_mask, order))
		return NULL;

	/*
	 * Check the zones suitable for the gfp_mask contain at least one
	 * valid zone. It's possible to have an empty zonelist as a result
	 * of GFP_THISNODE and a memoryless node
	 */
	if (unlikely(!zonelist->_zonerefs->zone))
		return NULL;

retry_cpuset:
	cpuset_mems_cookie = get_mems_allowed();

	/* The preferred zone is used for statistics later */
	first_zones_zonelist(zonelist, high_zoneidx,
				nodemask ? : &cpuset_current_mems_allowed,
				&preferred_zone);
	if (!preferred_zone)
		goto out;

#ifdef CONFIG_CMA
	if (allocflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;
#endif
	/* First allocation attempt */
	//初次尝试分配
	page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, nodemask, order,
			zonelist, high_zoneidx, alloc_flags,
			preferred_zone, migratetype);
	if (unlikely(!page)) {
		/*
		 * Runtime PM, block IO and its error handling path
		 * can deadlock because I/O on the device might not
		 * complete.
		 */
		gfp_mask = memalloc_noio_flags(gfp_mask);
		//slow path会调用下面的函数设置更严峻的标志
		//再次失败后会设置NO_WATERMARKS
		//之后进入极限处理
		page = __alloc_pages_slowpath(gfp_mask, order,
				zonelist, high_zoneidx, nodemask,
				preferred_zone, migratetype);
	}

	trace_mm_page_alloc(page, order, gfp_mask, migratetype);

out:
	/*
	 * When updating a task's mems_allowed, it is possible to race with
	 * parallel threads in such a way that an allocation can fail while
	 * the mask is being updated. If a page allocation is about to fail,
	 * check if the cpuset changed during allocation and if so, retry.
	 */
	if (unlikely(!put_mems_allowed(cpuset_mems_cookie) && !page))
		goto retry_cpuset;

	memcg_kmem_commit_charge(page, memcg, order);

	return page;
}


get_page_from_freelist(gfp_t gfp_mask, nodemask_t *nodemask, unsigned int order,
		struct zonelist *zonelist, int high_zoneidx, int alloc_flags,
		struct zone *preferred_zone, int migratetype)
{
	struct zoneref *z;
	struct page *page = NULL;
	int classzone_idx;
	struct zone *zone;
	nodemask_t *allowednodes = NULL;/* zonelist_cache approximation */
	int zlc_active = 0;		/* set if using zonelist_cache */
	int did_zlc_setup = 0;		/* just call zlc_setup() one time */

	classzone_idx = zone_idx(preferred_zone);
zonelist_scan:
	/*
	 * Scan zonelist, looking for a zone with enough free.
	 * See also __cpuset_node_allowed_softwall() comment in kernel/cpuset.c.
	 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
						high_zoneidx, nodemask) {
		unsigned long mark;

		if ((alloc_flags & ALLOC_CPUSET) &&
			!cpuset_zone_allowed_softwall(zone, gfp_mask))
				continue;
		BUILD_BUG_ON(ALLOC_NO_WATERMARKS < NR_WMARK);
		if (unlikely(alloc_flags & ALLOC_NO_WATERMARKS))
			goto try_this_zone;
		/*
		 * Distribute pages in proportion to the individual
		 * zone size to ensure fair page aging.  The zone a
		 * page was allocated in should have no effect on the
		 * time the page has in memory before being reclaimed.
		 *
		 * Try to stay in local zones in the fastpath.  If
		 * that fails, the slowpath is entered, which will do
		 * another pass starting with the local zones, but
		 * ultimately fall back to remote zones that do not
		 * partake in the fairness round-robin cycle of this
		 * zonelist.
		 *
		 * NOTE: GFP_THISNODE allocations do not partake in
		 * the kswapd aging protocol, so they can't be fair.
		 */
		if ((alloc_flags & ALLOC_WMARK_LOW) &&
		    !gfp_thisnode_allocation(gfp_mask)) {
			if (zone_page_state(zone, NR_ALLOC_BATCH) <= 0)
				continue;
			if (!zone_local(preferred_zone, zone))
				continue;
		}
		/*
		 * When allocating a page cache page for writing, we
		 * want to get it from a zone that is within its dirty
		 * limit, such that no single zone holds more than its
		 * proportional share of globally allowed dirty pages.
		 * The dirty limits take into account the zone's
		 * lowmem reserves and high watermark so that kswapd
		 * should be able to balance it without having to
		 * write pages from its LRU list.
		 *
		 * This may look like it could increase pressure on
		 * lower zones by failing allocations in higher zones
		 * before they are full.  But the pages that do spill
		 * over are limited as the lower zones are protected
		 * by this very same mechanism.  It should not become
		 * a practical burden to them.
		 *
		 * XXX: For now, allow allocations to potentially
		 * exceed the per-zone dirty limit in the slowpath
		 * (ALLOC_WMARK_LOW unset) before going into reclaim,
		 * which is important when on a NUMA setup the allowed
		 * zones are together not big enough to reach the
		 * global limit.  The proper fix for these situations
		 * will require awareness of zones in the
		 * dirty-throttling and the flusher threads.
		 */
		if ((alloc_flags & ALLOC_WMARK_LOW) &&
		    (gfp_mask & __GFP_WRITE) && !zone_dirty_ok(zone))
			goto this_zone_full;

		mark = zone->watermark[alloc_flags & ALLOC_WMARK_MASK];
		if (!zone_watermark_ok(zone, order, mark,
				       classzone_idx, alloc_flags)) {
			int ret;

			if (zone_reclaim_mode == 0 ||
			    !zone_allows_reclaim(preferred_zone, zone))
				goto this_zone_full;

			ret = zone_reclaim(zone, gfp_mask, order);
			switch (ret) {
			case ZONE_RECLAIM_NOSCAN:
				/* did not scan */
				continue;
			case ZONE_RECLAIM_FULL:
				/* scanned but unreclaimable */
				continue;
			default:
				/* did we reclaim enough */
				if (zone_watermark_ok(zone, order, mark,
						classzone_idx, alloc_flags))
					goto try_this_zone;

				/*
				 * Failed to reclaim enough to meet watermark.
				 * Only mark the zone full if checking the min
				 * watermark or if we failed to reclaim just
				 * 1<<order pages or else the page allocator
				 * fastpath will prematurely mark zones full
				 * when the watermark is between the low and
				 * min watermarks.
				 */
				if (((alloc_flags & ALLOC_WMARK_MASK) == ALLOC_WMARK_MIN) ||
				    ret == ZONE_RECLAIM_SOME)
					goto this_zone_full;

				continue;
			}
		}

try_this_zone:
		//实际分配
		page = buffered_rmqueue(preferred_zone, zone, order,
						gfp_mask, migratetype);
		if (page)
			break;
this_zone_full:
		if (IS_ENABLED(CONFIG_NUMA))
			zlc_mark_zone_full(zonelist, z);
	}

	if (unlikely(IS_ENABLED(CONFIG_NUMA) && page == NULL && zlc_active)) {
		/* Disable zlc cache for second zonelist scan */
		zlc_active = 0;
		goto zonelist_scan;
	}

	if (page)
		/*
		 * page->pfmemalloc is set when ALLOC_NO_WATERMARKS was
		 * necessary to allocate the page. The expectation is
		 * that the caller is taking steps that will free more
		 * memory. The caller should avoid the page being used
		 * for !PFMEMALLOC purposes.
		 */
		page->pfmemalloc = !!(alloc_flags & ALLOC_NO_WATERMARKS);

	return page;
}

/* The ALLOC_WMARK bits are used as an index to zone->watermark */
#define ALLOC_WMARK_MIN		WMARK_MIN
#define ALLOC_WMARK_LOW		WMARK_LOW
#define ALLOC_WMARK_HIGH	WMARK_HIGH
#define ALLOC_NO_WATERMARKS	0x04 /* don't check watermarks at all */

/* Mask to get the watermark bits */
#define ALLOC_WMARK_MASK	(ALLOC_NO_WATERMARKS-1)

#define ALLOC_HARDER		0x10 /* try to alloc harder */
#define ALLOC_HIGH		0x20 /* __GFP_HIGH set */
#define ALLOC_CPUSET		0x40 /* check for correct cpuset */
#define ALLOC_CMA		0x80 /* allow allocations from CMA areas */

static bool __zone_watermark_ok(struct zone *z, int order, unsigned long mark,
		      int classzone_idx, int alloc_flags, long free_pages)
{
	/* free_pages my go negative - that's OK */
	long min = mark;
	long lowmem_reserve = z->lowmem_reserve[classzone_idx];
	int o;
	long free_cma = 0;

	free_pages -= (1 << order) - 1;
	if (alloc_flags & ALLOC_HIGH)
		min -= min / 2;
	if (alloc_flags & ALLOC_HARDER)
		min -= min / 4;
#ifdef CONFIG_CMA
	/* If allocation can't use CMA areas don't use free CMA pages */
	if (!(alloc_flags & ALLOC_CMA))
		free_cma = zone_page_state(z, NR_FREE_CMA_PAGES);
#endif
	//空闲页需要 > min + 保留内存
	if (free_pages - free_cma <= min + lowmem_reserve)
		return false;
	for (o = 0; o < order; o++) {
		/* At the next order, this order's pages become unavailable */
		free_pages -= z->free_area[o].nr_free << o;

		/* Require fewer higher order pages to be free */
		min >>= 1;

		if (free_pages <= min)
			return false;
	}
	return true;
}


gfp_to_alloc_flags(gfp_t gfp_mask)
{
	int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;
	const gfp_t wait = gfp_mask & __GFP_WAIT;

	/* __GFP_HIGH is assumed to be the same as ALLOC_HIGH to save a branch. */
	BUILD_BUG_ON(__GFP_HIGH != (__force gfp_t) ALLOC_HIGH);

	/*
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_HARDER (!wait) and ALLOC_HIGH (__GFP_HIGH).
	 */
	alloc_flags |= (__force int) (gfp_mask & __GFP_HIGH);

	if (!wait) {
		/*
		 * Not worth trying to allocate harder for
		 * __GFP_NOMEMALLOC even if it can't schedule.
		 */
		if  (!(gfp_mask & __GFP_NOMEMALLOC))
			alloc_flags |= ALLOC_HARDER;
		/*
		 * Ignore cpuset if GFP_ATOMIC (!wait) rather than fail alloc.
		 * See also cpuset_zone_allowed() comment in kernel/cpuset.c.
		 */
		alloc_flags &= ~ALLOC_CPUSET;
	} else if (unlikely(rt_task(current)) && !in_interrupt())
		alloc_flags |= ALLOC_HARDER;

	if (likely(!(gfp_mask & __GFP_NOMEMALLOC))) {
		if (gfp_mask & __GFP_MEMALLOC)
			alloc_flags |= ALLOC_NO_WATERMARKS;
		else if (in_serving_softirq() && (current->flags & PF_MEMALLOC))
			alloc_flags |= ALLOC_NO_WATERMARKS;
		else if (!in_interrupt() &&
				((current->flags & PF_MEMALLOC) ||
				 unlikely(test_thread_flag(TIF_MEMDIE))))
			alloc_flags |= ALLOC_NO_WATERMARKS;
	}
#ifdef CONFIG_CMA
	if (allocflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;
#endif
	return alloc_flags;
}



static inline
struct page *buffered_rmqueue(struct zone *preferred_zone,
			struct zone *zone, int order, gfp_t gfp_flags,
			int migratetype)
{
	unsigned long flags;
	struct page *page;
	int cold = !!(gfp_flags & __GFP_COLD);

again:
	if (likely(order == 0)) {
		struct per_cpu_pages *pcp;
		struct list_head *list;

		local_irq_save(flags);
		pcp = &this_cpu_ptr(zone->pageset)->pcp;
		//pcp单页缓存也是分迁移类型的
		list = &pcp->lists[migratetype];
		if (list_empty(list)) {
			pcp->count += rmqueue_bulk(zone, 0,
					pcp->batch, list,
					migratetype, cold);
			if (unlikely(list_empty(list)))
				goto failed;
		}

		if (cold)
			page = list_entry(list->prev, struct page, lru);
		else
			page = list_entry(list->next, struct page, lru);

		list_del(&page->lru);
		pcp->count--;
	} else {
		if (unlikely(gfp_flags & __GFP_NOFAIL)) {
			/*
			 * __GFP_NOFAIL is not to be used in new code.
			 *
			 * All __GFP_NOFAIL callers should be fixed so that they
			 * properly detect and handle allocation failures.
			 *
			 * We most definitely don't want callers attempting to
			 * allocate greater than order-1 page units with
			 * __GFP_NOFAIL.
			 */
			WARN_ON_ONCE(order > 1);
		}
		spin_lock_irqsave(&zone->lock, flags);
		page = __rmqueue(zone, order, migratetype);
		spin_unlock(&zone->lock);
		if (!page)
			goto failed;
		__mod_zone_freepage_state(zone, -(1 << order),
					  get_pageblock_migratetype(page));
	}

	/*
	 * NOTE: GFP_THISNODE allocations do not partake in the kswapd
	 * aging protocol, so they can't be fair.
	 */
	if (!gfp_thisnode_allocation(gfp_flags))
		__mod_zone_page_state(zone, NR_ALLOC_BATCH, -(1 << order));

	__count_zone_vm_events(PGALLOC, zone, 1 << order);
	zone_statistics(preferred_zone, zone, gfp_flags);
	local_irq_restore(flags);

	VM_BUG_ON_PAGE(bad_range(zone, page), page);
	if (prep_new_page(page, order, gfp_flags))
		goto again;
	return page;

failed:
	local_irq_restore(flags);
	return NULL;
}

巨型页的lru另作他用，private指向第一个页
//核心分配函数
static struct page *__rmqueue(struct zone *zone, unsigned int order,
						int migratetype)
{
	struct page *page;

retry_reserve:
	page = __rmqueue_smallest(zone, order, migratetype);

	if (unlikely(!page) && migratetype != MIGRATE_RESERVE) {
    	//上面函数失败后,偷取其他类型
    	//偷取的时候需要从最大块开始
		page = __rmqueue_fallback(zone, order, migratetype);

		/*
		 * Use MIGRATE_RESERVE rather than fail an allocation. goto
		 * is used because __rmqueue_smallest is an inline function
		 * and we want just one call site
		 */
		//最后尝试reserve
		if (!page) {
			migratetype = MIGRATE_RESERVE;
			goto retry_reserve;
		}
	}

	return page;
}


static inline
struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
						int migratetype)
{
	unsigned int current_order;
	struct free_area *area;
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
		expand(zone, page, order, current_order, area, migratetype);
		return page;
	}

	return NULL;
}


static inline struct page *
__rmqueue_fallback(struct zone *zone, int order, int start_migratetype)
{
	struct free_area *area;
	int current_order;
	struct page *page;
	int migratetype, new_type, i;

	/* Find the largest possible block of pages in the other list */
	for (current_order = MAX_ORDER-1; current_order >= order;
						--current_order) {
		for (i = 0;; i++) {
			migratetype = fallbacks[start_migratetype][i];

			/* MIGRATE_RESERVE handled later if necessary */
    		//上面函数失败后,偷取其他类型
    		//偷取的时候需要从最大块开始
			if (migratetype == MIGRATE_RESERVE)
				break;

			area = &(zone->free_area[current_order]);
			if (list_empty(&area->free_list[migratetype]))
				continue;

			page = list_entry(area->free_list[migratetype].next,
					struct page, lru);
			area->nr_free--;

			//start为原类型
			new_type = try_to_steal_freepages(zone, page,
							  start_migratetype,
							  migratetype);

			/* Remove the page from the freelists */
			list_del(&page->lru);
			rmv_page_order(page);

			expand(zone, page, order, current_order, area,
			       new_type);

			trace_mm_page_alloc_extfrag(page, order, current_order,
				start_migratetype, migratetype, new_type);

			return page;
		}
	}

	return NULL;
}


/*
 * If breaking a large block of pages, move all free pages to the preferred
 * allocation list. If falling back for a reclaimable kernel allocation, be
 * more aggressive about taking ownership of free pages.
 *
 * On the other hand, never change migration type of MIGRATE_CMA pageblocks
 * nor move CMA pages to different free lists. We don't want unmovable pages
 * to be allocated from MIGRATE_CMA areas.
 *
 * Returns the new migratetype of the pageblock (or the same old migratetype
 * if it was unchanged).
 */
static int try_to_steal_freepages(struct zone *zone, struct page *page,
				  int start_type, int fallback_type)
{
	int current_order = page_order(page);

	/*
	 * When borrowing from MIGRATE_CMA, we need to release the excess
	 * buddy pages to CMA itself.
	 */
	//偷cma返回cma
	if (is_migrate_cma(fallback_type))
		return fallback_type;

	/* Take ownership for orders >= pageblock_order */
	//偷取比较多的内存时，需要改变目标的迁移类型
	if (current_order >= pageblock_order) {
		change_pageblock_range(page, current_order, start_type);
		return start_type;
	}

	if (current_order >= pageblock_order / 2 ||
	    start_type == MIGRATE_RECLAIMABLE ||
	    page_group_by_mobility_disabled) {
		int pages;

		//移动这一部分的页面(迁移位图不变)
		pages = move_freepages_block(zone, page, start_type);

		/* Claim the whole block if over half of it is free */
		if (pages >= (1 << (pageblock_order-1)) ||
				page_group_by_mobility_disabled) {

			set_pageblock_migratetype(page, start_type);
			return start_type;
		}

	}

	return fallback_type;
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
	if (start_pfn < zone->zone_start_pfn)
		start_page = page;
	if (end_pfn >= zone->zone_start_pfn + zone->spanned_pages)
		return 0;

	//把页面转到对应的链表上
	return move_freepages(zone, start_page, end_page, migratetype);
}
