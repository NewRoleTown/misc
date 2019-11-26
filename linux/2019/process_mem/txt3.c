//每个打开的文件对应file结构体，其中有一个指针指向address_space
//inode中也有字段指向address_space
struct address_space {
	struct inode		*host;		/* owner: inode, block_device */
	struct radix_tree_root	page_tree;	/* radix tree of all pages */
	spinlock_t		tree_lock;	/* and lock protecting it */
	unsigned int		i_mmap_writable;/* count VM_SHARED mappings */
	//vm_area_struct红黑树
	struct rb_root		i_mmap;		/* tree of private and shared mappings */
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
