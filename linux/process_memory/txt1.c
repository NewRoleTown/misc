task_struct中mmap_base用于内存映射起始地址,get_unmapped_area在mmap区域中找适当位置
#define PF_RANDOMIZE	0x00400000	/* randomize virtual address space */
arch_get_unmapped_area_topdown

elf文件执行时会调用如下
正向mmap_base是1/3的tasksize
反向tasksize - stackmaxsize - random
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	/*
	 * Fall back to the standard layout if the personality
	 * bit is set, or if the expected stack growth is unlimited:
	 */
	if (sysctl_legacy_va_layout ||
			(current->personality & ADDR_COMPAT_LAYOUT) ||
			current->signal->rlim[RLIMIT_STACK].rlim_cur == RLIM_INFINITY) {
		mm->mmap_base = TASK_UNMAPPED_BASE;
		mm->get_unmapped_area = arch_get_unmapped_area;
		mm->unmap_area = arch_unmap_area;
	} else {
		mm->mmap_base = mmap_base(mm);
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
		mm->unmap_area = arch_unmap_area_topdown;
	}
}
PF_RANDOMIZE在task->personxxty没设置NO_RANDOM时启用

如果栈的增长无限制回退标准布局
/proc/sys/kernel/legacy_va_layout指示是否启用新布局
以上两者共同决定布局

struct vm_area_struct {
	struct mm_struct * vm_mm;	/* The address space we belong to. */
	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
    //虚拟内存区链表
	struct vm_area_struct *vm_next;

    //访问权限
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
    //标志
	unsigned long vm_flags;		/* Flags, listed below. */

    //虚拟内存区红黑结点，为了加速而已
	struct rb_node vm_rb;

    //如果有back store或者address space,shared连接到address_space->i_mmap优先树,或者挂在优先树结点外，或连接到address_space->i_mmap_nonlinear链表中的虚拟内存区
	union {
		struct {
			struct list_head list;
			void *parent;	/* aligns with prio_tree_node parent */ //vm_set不使用parent字段，所以如果这个字段不等于NULL表示在树中,否则,list链接起来
			struct vm_area_struct *head;
		} vm_set;

		struct raw_prio_tree_node prio_tree_node;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
    //指向相同页的映射都保存在一个链表，以下为链表元素
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	struct vm_operations_struct * vm_ops;

	/* Information about our backing store: */
    //vm_file内的偏移量,pagesize对齐
	unsigned long vm_pgoff;
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */
	unsigned long vm_truncate_count;/* truncate_count or restart_addr */

#ifndef CONFIG_MMU
	atomic_t vm_usage;		/* refcount (VMAs shared if !MMU) */
#endif
};

//vm flags
#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_GROWSUP	0x00000200
#define VM_PFNMAP	0x00000400	/* Page-ranges managed without "struct page", just pure PFN */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */

#define VM_EXECUTABLE	0x00001000
#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

					/* Used by sys_madvise() */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
#define VM_RESERVED	0x00080000	/* Count as reserved_vm like IO */
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
#define VM_NONLINEAR	0x00800000	/* Is non-linear (remap_file_pages) */
#define VM_MAPPED_COPY	0x01000000	/* T if mapped copy of data (nommu mmap) */
#define VM_INSERTPAGE	0x02000000	/* The vma has had "vm_insert_page()" done on it */
#define VM_ALWAYSDUMP	0x04000000	/* Always include in core dumps */

#define VM_CAN_NONLINEAR 0x08000000	/* Has ->fault & does nonlinear pages */

#ifndef VM_STACK_DEFAULT_FLAGS		/* arch can override this */
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#endif

#ifdef CONFIG_STACK_GROWSUP
#define VM_STACK_FLAGS	(VM_GROWSUP | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#else
#define VM_STACK_FLAGS	(VM_GROWSDOWN | VM_STACK_DEFAULT_FLAGS | VM_ACCOUNT)
#endif

#define VM_READHINTMASK			(VM_SEQ_READ | VM_RAND_READ)
#define VM_ClearReadHint(v)		(v)->vm_flags &= ~VM_READHINTMASK
#define VM_NormalReadHint(v)		(!((v)->vm_flags & VM_READHINTMASK))
#define VM_SequentialReadHint(v)	((v)->vm_flags & VM_SEQ_READ)
#define VM_RandomReadHint(v)		((v)->vm_flags & VM_RAND_READ)

struct file中有一个指向address_space的指针f_mapping

struct address_space {
	struct inode		*host;		/* owner: inode, block_device */
	struct radix_tree_root	page_tree;	/* radix tree of all pages */
	rwlock_t		tree_lock;	/* and rwlock protecting it */
	unsigned int		i_mmap_writable;/* count VM_SHARED mappings */
	struct prio_tree_root	i_mmap;		/*私有和共享映射的树 */
    //VM_NONLINEAR映射链表,非线性映射用
	struct list_head	i_mmap_nonlinear;/*list VM_NONLINEAR mappings */
	spinlock_t		i_mmap_lock;	/* protect tree, count, list */
	unsigned int		truncate_count;	/* Cover race condition with truncate */
	unsigned long		nrpages;	/* number of total pages */
	pgoff_t			writeback_index;/* writeback starts here */
	const struct address_space_operations *a_ops;	/* methods */
	unsigned long		flags;		/* error bits/gfp mask */
	struct backing_dev_info *backing_dev_info; /* device readahead, etc */
	spinlock_t		private_lock;	/* for use by the address_space */
	struct list_head	private_list;	/* ditto */
	struct address_space	*assoc_mapping;	/* ditto */
} __attribute__((aligned(sizeof(long))));

和list_head i_mmap_nonlinear

//先尝试插入优先树，如果已经有了相同(地址起始,地址结束)，则进if流程，此时ptr指向相同的结点
void vma_prio_tree_insert(struct vm_area_struct *vma,
			  struct prio_tree_root *root)
{
	struct prio_tree_node *ptr;
	struct vm_area_struct *old;

	vma->shared.vm_set.head = NULL;

	ptr = raw_prio_tree_insert(root, &vma->shared.prio_tree_node);

	if (ptr != (struct prio_tree_node *) &vma->shared.prio_tree_node) {
        //获取vm_area
		old = prio_tree_entry(ptr, struct vm_area_struct,
					shared.prio_tree_node);
		vma_prio_tree_add(vma, old);
	}
}

如果这个结点有parent,说明在树里，如果head还没有初始化，初始化一下，然后建链，否则add_tail
void vma_prio_tree_add(struct vm_area_struct *vma, struct vm_area_struct *old)
{
	vma->shared.vm_set.head = NULL;
	vma->shared.vm_set.parent = NULL;

	if (!old->shared.vm_set.parent)
		list_add(&vma->shared.vm_set.list,
				&old->shared.vm_set.list);
	else if (old->shared.vm_set.head)
		list_add_tail(&vma->shared.vm_set.list,
				&old->shared.vm_set.head->shared.vm_set.list);
	else {
		INIT_LIST_HEAD(&vma->shared.vm_set.list);
		vma->shared.vm_set.head = old;
		old->shared.vm_set.head = vma;
	}
}

unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;
	unsigned long begin, end;
	
    //如果设置了固定地址，直接返回不寻找空闲区
	if (flags & MAP_FIXED)
		return addr;

	find_start_end(flags, &begin, &end); 

	if (len > end)
		return -ENOMEM;
    //如果该地址可用,返回
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (end - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
	if (((flags & MAP_32BIT) || test_thread_flag(TIF_IA32))
	    && len <= mm->cached_hole_size) {
	        mm->cached_hole_size = 0;
		mm->free_area_cache = begin;
	}
	addr = mm->free_area_cache;
	if (addr < begin) 
		addr = begin; 
	start_addr = addr;
//忽略addr找其他的
full_search:
	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (end - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			if (start_addr != begin) {
				start_addr = addr = begin;
				mm->cached_hole_size = 0;
				goto full_search;
			}
			return -ENOMEM;
		}
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
			mm->free_area_cache = addr + len;
			return addr;
		}
		if (addr + mm->cached_hole_size < vma->vm_start)
		        mm->cached_hole_size = vma->vm_start - addr;

		addr = vma->vm_end;
	}
}

#define PAGE_MAPPING_ANON	1
static void __page_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;

    //算出文件偏移量(pagesize对齐)
	page->index = linear_page_index(vma, address);

    //更新统计量
	__inc_zone_page_state(page, NR_ANON_PAGES);
}

page_add_new_anon_rmap
page_add_anon_rmap
page_referenced

static int page_referenced_one(struct page *page,
	struct vm_area_struct *vma, unsigned int *mapcount)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;
	int referenced = 0;
    //获取该页在进程虚拟空间中的地址
	address = vma_address(page, vma);
	if (address == -EFAULT)
		goto out;

	pte = page_check_address(page, mm, address, &ptl);
	if (!pte)
		goto out;

	if (ptep_clear_flush_young(vma, address, pte))
		referenced++;

	/* Pretend the page is referenced if the task has the
	   swap token and is in the middle of a page fault. */
	if (mm != current->mm && has_swap_token(mm) &&
			rwsem_is_locked(&mm->mmap_sem))
		referenced++;

	(*mapcount)--;
	pte_unmap_unlock(pte, ptl);
out:
	return referenced;
}
