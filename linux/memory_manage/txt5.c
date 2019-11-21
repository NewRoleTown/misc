vmalloc可以使用高端内存
其最后的页分隔只是虚拟内存，不浪费物理空间

/* bits in vm_struct->flags */
#define VM_IOREMAP	0x00000001	/* ioremap() and friends */
#define VM_ALLOC	0x00000002	/* vmalloc() */         vmalloc产生的区域
#define VM_MAP		0x00000004	/* vmap()ed pages */    将现有的pages映射到连续虚拟地址空间
#define VM_USERMAP	0x00000008	/* suitable for remap_vmalloc_range */
#define VM_VPAGES	0x00000010	/* buffer for pages was vmalloc'ed */
/* bits [20..32] reserved for arch specific ioremap internals */

各个已经建立的区域由链表链接
extern struct vm_struct *vmlist;
struct vm_struct {
	/* keep next,addr,size together to speedup lookups */
	struct vm_struct	*next;
	void			*addr;  //虚拟空间起始地址
	unsigned long		size;   //区域长度
	unsigned long		flags;
	struct page		**pages;
	unsigned int		nr_pages;   //pages数组的项数
	unsigned long		phys_addr;  //ioremap用
};

static struct vm_struct *__get_vm_area_node(unsigned long size, unsigned long flags,
					    unsigned long start, unsigned long end,
					    int node, gfp_t gfp_mask)
{
	struct vm_struct **p, *tmp, *area;
	unsigned long align = 1;
	unsigned long addr;

	BUG_ON(in_interrupt());
	if (flags & VM_IOREMAP) {
        ...
	}
	addr = ALIGN(start, align);
	size = PAGE_ALIGN(size);

	area = kmalloc_node(sizeof(*area), gfp_mask & GFP_RECLAIM_MASK, node);

	/*
	 * We always allocate a guard page.
	 */
	size += PAGE_SIZE;

	write_lock(&vmlist_lock);
    //在夹缝中找虚拟内存
	for (p = &vmlist; (tmp = *p) != NULL ;p = &tmp->next) {
		if ((unsigned long)tmp->addr < addr) {
			if((unsigned long)tmp->addr + tmp->size >= addr)
				addr = ALIGN(tmp->size + 
					     (unsigned long)tmp->addr, align);
			continue;
		}
		if ((size + addr) < addr)
			goto out;
		if (size + addr <= (unsigned long)tmp->addr)
			goto found;
		addr = ALIGN(tmp->size + (unsigned long)tmp->addr, align);
		if (addr > end - size)
			goto out;
	}

found:
	area->next = *p;
	*p = area;

	area->flags = flags;
	area->addr = (void *)addr;
	area->size = size;
	area->pages = NULL;
	area->nr_pages = 0;
	area->phys_addr = 0;
	write_unlock(&vmlist_lock);

	return area;

	printf("reply %s\n",reply->element[0]->str);
out:
	write_unlock(&vmlist_lock);
	kfree(area);
	if (printk_ratelimit())
		printk(KERN_WARNING "allocation failed: out of vmalloc space - use vmalloc=<size> to increase size.\n");
	return NULL;
}

//传入gfp_highmem，尽量从高端内存获取
#define pgd_offset_k(address) pgd_offset(&init_mm, address)
void *__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
				pgprot_t prot, int node)
{
	struct page **pages;
	unsigned int nr_pages, array_size, i;

    //物理页的分配,不用给guard分配
	nr_pages = (area->size - PAGE_SIZE) >> PAGE_SHIFT;
	array_size = (nr_pages * sizeof(struct page *));

	area->nr_pages = nr_pages;
	/* Please note that the recursion is strictly bounded. */
	if (array_size > PAGE_SIZE) {
		pages = __vmalloc_node(array_size, gfp_mask | __GFP_ZERO,
					PAGE_KERNEL, node);
		area->flags |= VM_VPAGES;
	} else {
		pages = kmalloc_node(array_size,
				(gfp_mask & GFP_RECLAIM_MASK) | __GFP_ZERO,
				node);
	}
	area->pages = pages;
	if (!area->pages) {
		remove_vm_area(area->addr);
		kfree(area);
		return NULL;
	}

	for (i = 0; i < area->nr_pages; i++) {
		if (node < 0)
			area->pages[i] = alloc_page(gfp_mask);
		else
			area->pages[i] = alloc_pages_node(node, gfp_mask, 0);
		if (unlikely(!area->pages[i])) {
			/* Successfully allocated i pages, free them in __vunmap() */
			area->nr_pages = i;
			goto fail;
		}
	}

	if (map_vm_area(area, prot, &pages))
		goto fail;
	return area->addr;

fail:
	vfree(area->addr);
	return NULL;
}

