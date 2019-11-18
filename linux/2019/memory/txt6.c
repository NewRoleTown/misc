void __free_pages(struct page *page, unsigned int order)
{
	if (put_page_testzero(page)) {
		if (order == 0)
			free_hot_cold_page(page, 0);
		else
			__free_pages_ok(page, order);
	}
}

static void __free_pages_ok(struct page *page, unsigned int order)
{
	unsigned long flags;
	int migratetype;

	if (!free_pages_prepare(page, order))
		return;

	local_irq_save(flags);
	__count_vm_events(PGFREE, 1 << order);
	//通过位图获取
	migratetype = get_pageblock_migratetype(page);
	page->index = migratetype;
	free_one_page(page_zone(page), page, order, migratetype);
	local_irq_restore(flags);
}

#define PAGE_BUDDY_MAPCOUNT_VALUE (-128)

static inline int PageBuddy(struct page *page)
{
	return atomic_read(&page->_mapcount) == PAGE_BUDDY_MAPCOUNT_VALUE;
}

//order存在private
static inline void __SetPageBuddy(struct page *page)
{
	VM_BUG_ON_PAGE(atomic_read(&page->_mapcount) != -1, page);
	atomic_set(&page->_mapcount, PAGE_BUDDY_MAPCOUNT_VALUE);
}
