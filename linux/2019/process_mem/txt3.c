//每个打开的文件对应file结构体，其中有一个指针指向address_space
//inode中也有字段指向address_space
struct address_space {
	struct inode		*host;		/* owner: inode, block_device */
	struct radix_tree_root	page_tree;	/* radix tree of all pages */
	spinlock_t		tree_lock;	/* and lock protecting it */
	unsigned int		i_mmap_writable;/* count VM_SHARED mappings */
	//vm_area_struct红黑树
	struct prio_tree_root	i_mmap;		/* tree of private and shared mappings */
	struct list_head	i_mmap_nonlinear;/*list VM_NONLINEAR mappings */
	struct mutex		i_mmap_mutex;	/* protect tree, count, list */
	/* Protected by tree_lock together with the radix tree */
	unsigned long		nrpages;	/* number of total pages */
	pgoff_t			writeback_index;/* writeback starts here */
	const struct address_space_operations *a_ops;	/* methods */
	unsigned long		flags;		/* error bits/gfp mask */
	struct backing_dev_info *backing_dev_info; /* device readahead, etc */
	spinlock_t		private_lock;	/* for use by the address_space */
	struct list_head	private_list;	/* ditto */
	void			*private_data;	/* ditto */
} __attribute__((aligned(sizeof(long))));


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
	//fork时不复制
	//#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */

    //虚拟内存区红黑结点，为了加速而已
	struct rb_node vm_rb;

    //如果有back store或者address space,shared连接到address_space->i_mmap优先树,或者挂在优先树结点外，
	//或连接到address_space->i_mmap_nonlinear链表中的虚拟内存区
	
	//当相同的区间被插入时，通过head指向后续的vma结构，
	//vm_set的parent成员在vm_set中不使用,vm_area_struct的parent!=NULL则表示该
	//vma在树中
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
	//匿名映射的情况下
    //指向相同页的映射都保存在一个链表，以下为链表元素
	struct list_head anon_vma_node;	/* Serialized by anon_vma->lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	//mm/filemap.c .fault = filemap_fault
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

int insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	struct vm_area_struct * __vma, * prev;
	struct rb_node ** rb_link, * rb_parent;

	/*
	 * The vm_pgoff of a purely anonymous vma should be irrelevant
	 * until its first write fault, when page's anon_vma and index
	 * are set.  But now set the vm_pgoff it will almost certainly
	 * end up with (unless mremap moves it elsewhere before that
	 * first wfault), so /proc/pid/maps tells a consistent story.
	 *
	 * By setting it to reflect the virtual start address of the
	 * vma, merges and splits can happen in a seamless way, just
	 * using the existing file pgoff checks and manipulations.
	 * Similarly in do_mmap_pgoff and in do_brk.
	 */
	if (!vma->vm_file) {
		BUG_ON(vma->anon_vma);
		vma->vm_pgoff = vma->vm_start >> PAGE_SHIFT;
	}
	//在红黑树中寻找前一个__vma,红黑树上层节点
	__vma = find_vma_prepare(mm,vma->vm_start,&prev,&rb_link,&rb_parent);
	if (__vma && __vma->vm_start < vma->vm_end)
		return -ENOMEM;
	vma_link(mm, vma, prev, rb_link, rb_parent);
	return 0;
}

static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
			struct vm_area_struct *prev, struct rb_node **rb_link,
			struct rb_node *rb_parent)
{
	struct address_space *mapping = NULL;

	//如果这个区域和文件相关，获取其address_space
	if (vma->vm_file)
		mapping = vma->vm_file->f_mapping;

	if (mapping) {
		spin_lock(&mapping->i_mmap_lock);
		vma->vm_truncate_count = mapping->truncate_count;
	}
	anon_vma_lock(vma);

	__vma_link(mm, vma, prev, rb_link, rb_parent);
	__vma_link_file(vma);

	anon_vma_unlock(vma);
	if (mapping)
		spin_unlock(&mapping->i_mmap_lock);

	mm->map_count++;
	validate_mm(mm);
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, struct rb_node **rb_link,
	struct rb_node *rb_parent)
{
	//插入mm链表和mm红黑树
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);

	__anon_vma_link(vma);
}

void __anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	if (anon_vma)
		list_add_tail(&vma->anon_vma_node, &anon_vma->head);
}

static inline void __vma_link_file(struct vm_area_struct *vma)
{
	struct file * file;

	file = vma->vm_file;
	if (file) {
		struct address_space *mapping = file->f_mapping;

		if (vma->vm_flags & VM_DENYWRITE)
			atomic_dec(&file->f_path.dentry->d_inode->i_writecount);
		if (vma->vm_flags & VM_SHARED)
			mapping->i_mmap_writable++;

		flush_dcache_mmap_lock(mapping);
		//如果是非线性区域
		if (unlikely(vma->vm_flags & VM_NONLINEAR))
			vma_nonlinear_insert(vma, &mapping->i_mmap_nonlinear);
		else//插入优先树
			vma_prio_tree_insert(vma, &mapping->i_mmap);
		flush_dcache_mmap_unlock(mapping);
	}
}


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
		//第一个重复的不在list里面
		vma->shared.vm_set.head = old;
		old->shared.vm_set.head = vma;
	}
}

//此树要保证父节点的heap_index大于子节点
//同时子节点的左右通过mask掩码来算，一定程度平衡高度
struct prio_tree_node *prio_tree_insert(struct prio_tree_root *root,
		struct prio_tree_node *node)
{
	struct prio_tree_node *cur, *res = node;
	unsigned long radix_index, heap_index;
	unsigned long r_index, h_index, index, mask;
	int size_flag = 0;

	//获取待插入的node的起始位置和结束位置(pg_off)
	get_index(root, node, &radix_index, &heap_index);

	if (prio_tree_empty(root) ||
			heap_index > prio_tree_maxindex(root->index_bits))
		return prio_tree_expand(root, node, heap_index);

	cur = root->prio_tree_node;
	mask = 1UL << (root->index_bits - 1);

	while (mask) {
		get_index(root, cur, &r_index, &h_index);

		//如果当前节点的范围和待插入节点范围一致，返回
		if (r_index == radix_index && h_index == heap_index)
			return cur;

		//待插的结束 > 当前的结束
                if (h_index < heap_index ||
						//待插的结束 == 当前的结束 并且 当前起始 > 待插起始
		    (h_index == heap_index && r_index > radix_index)) {
			struct prio_tree_node *tmp = node;
			node = prio_tree_replace(root, cur, node);
			cur = tmp;
			/* swap indices */
			index = r_index;
			r_index = radix_index;
			radix_index = index;
			index = h_index;
			h_index = heap_index;
			heap_index = index;
			//此时待插入节点范围比当前节点大，替换之
		}

		if (size_flag)
			index = heap_index - radix_index;
		else
			index = radix_index;

		if (index & mask) {
			if (prio_tree_right_empty(cur)) {
				//待插入节点插入到当前节点的右边，返回
				INIT_PRIO_TREE_NODE(node);
				cur->right = node;
				node->parent = cur;
				return res;
			} else
				cur = cur->right;
		} else {
			if (prio_tree_left_empty(cur)) {
				INIT_PRIO_TREE_NODE(node);
				cur->left = node;
				node->parent = cur;
				return res;
			} else
				cur = cur->left;
		}

		mask >>= 1;

		if (!mask) {
			mask = 1UL << (BITS_PER_LONG - 1);
			size_flag = 1;
		}
	}
	/* Should not reach here */
	BUG();
	return NULL;
}

//如果mmap区向下扩展，分配函数改为arch_get_unmapped_area_topdown
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

	//#define TASK_UNMAPPED_BASE	(PAGE_ALIGN(TASK_SIZE / 3))   ~~~~~~   TASK_SIZE
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
	...
}
