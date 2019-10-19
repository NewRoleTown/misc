inode不包含文件名
网络设备不是文件

struct inode {
	struct hlist_node	i_hash;
	struct list_head	i_list;
	struct list_head	i_sb_list;  //表头在superblock里
	struct list_head	i_dentry;
	unsigned long		i_ino;
	atomic_t		i_count;        //引用计数，软硬链接
	unsigned int		i_nlink;    //硬链接数
	uid_t			i_uid;
	gid_t			i_gid;
	dev_t			i_rdev;         //设备号
	unsigned long		i_version;
	loff_t			i_size;         //文件大小(字节)
#ifdef __NEED_I_SIZE_ORDERED
	seqcount_t		i_size_seqcount;
#endif
	struct timespec		i_atime;        //最后访问时间
	struct timespec		i_mtime;        //最后修改时间(数据)
	struct timespec		i_ctime;        //最后修改inode的时间
	unsigned int		i_blkbits;
	blkcnt_t		i_blocks;           //按块对齐的大小
	unsigned short          i_bytes;
	umode_t			i_mode;
	spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
	struct mutex		i_mutex;
	struct rw_semaphore	i_alloc_sem;
	const struct inode_operations	*i_op;
	const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
	struct super_block	*i_sb;              //指向超级块
	struct file_lock	*i_flock;
	struct address_space	*i_mapping;
	struct address_space	i_data;
#ifdef CONFIG_QUOTA
	struct dquot		*i_dquot[MAXQUOTAS];
#endif
	struct list_head	i_devices;  //同一个设备的多个inode通过这里链接
	union {
		struct pipe_inode_info	*i_pipe;
		struct block_device	*i_bdev;
		struct cdev		*i_cdev;
	};
	int			i_cindex;

	__u32			i_generation;

#ifdef CONFIG_DNOTIFY
	unsigned long		i_dnotify_mask; /* Directory notify events */
	struct dnotify_struct	*i_dnotify; /* for directory notifications */
#endif

#ifdef CONFIG_INOTIFY
	struct list_head	inotify_watches; /* watches on this inode */
	struct mutex		inotify_mutex;	/* protects the watches list */
#endif

	unsigned long		i_state;
	unsigned long		dirtied_when;	/* jiffies,第一次dirty的时间*/

	unsigned int		i_flags;

	atomic_t		i_writecount;
#ifdef CONFIG_SECURITY
	void			*i_security;
#endif
	void			*i_private; /* fs or device private pointer */
};


struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	/*
	 * fu_list becomes invalid after file_free is called and queued via
	 * fu_rcuhead for RCU freeing
	 */
	union {
		struct list_head	fu_list;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
#define f_dentry	f_path.dentry
#define f_vfsmnt	f_path.mnt
	const struct file_operations	*f_op;          //和inode中的相同
	atomic_t		f_count;
	unsigned int 		f_flags;
	mode_t			f_mode;
	loff_t			f_pos;      //当前偏移量
	struct fown_struct	f_owner;    //当前文件所有者
	unsigned int		f_uid, f_gid;
	struct file_ra_state	f_ra;

	u64			f_version;
#ifdef CONFIG_SECURITY
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others */
	void			*private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct list_head	f_ep_links;
	spinlock_t		f_ep_lock;
#endif /* #ifdef CONFIG_EPOLL */
	struct address_space	*f_mapping; // = inode->i_mapping
};

inode操作包含创建链接，文件重命名，目录下生成新文件，删除文件等
struct inode_operations {
	int (*create) (struct inode *,struct dentry *,int, struct nameidata *);
	struct dentry * (*lookup) (struct inode *,struct dentry *, struct nameidata *);
	int (*link) (struct dentry *,struct inode *,struct dentry *);
	int (*unlink) (struct inode *,struct dentry *);
	int (*symlink) (struct inode *,struct dentry *,const char *);
	int (*mkdir) (struct inode *,struct dentry *,int);
	int (*rmdir) (struct inode *,struct dentry *);
	int (*mknod) (struct inode *,struct dentry *,int,dev_t);
	int (*rename) (struct inode *, struct dentry *,
			struct inode *, struct dentry *);
	int (*readlink) (struct dentry *, char __user *,int);
	void * (*follow_link) (struct dentry *, struct nameidata *);
	void (*put_link) (struct dentry *, struct nameidata *, void *);
	void (*truncate) (struct inode *);
	int (*permission) (struct inode *, int, struct nameidata *);
	int (*setattr) (struct dentry *, struct iattr *);
	int (*getattr) (struct vfsmount *mnt, struct dentry *, struct kstat *);
	int (*setxattr) (struct dentry *, const char *,const void *,size_t,int);
	ssize_t (*getxattr) (struct dentry *, const char *, void *, size_t);
	ssize_t (*listxattr) (struct dentry *, char *, size_t);
	int (*removexattr) (struct dentry *, const char *);
	void (*truncate_range)(struct inode *, loff_t, loff_t);
	long (*fallocate)(struct inode *inode, int mode, loff_t offset,
			  loff_t len);
};

同一文件系统可能拥有不同的超级块，只要装载点/分区不同，就有不同超级块，如home，root都是ext3,但是不同超级块

//有效但不活动
LIST_HEAD(inode_in_use);
//已使用但未改变
LIST_HEAD(inode_unused);
//脏的inode保存在超级块链表中
//无效的inode保存在一个链表中


struct super_block {
	struct list_head	s_list;		/* Keep this first ,链表元素，表头super_blocks串起系统全部超级块*/
	dev_t			s_dev;		/* search index; _not_ kdev_t */
	unsigned long		s_blocksize;        //文件系统的块长度,字节单位
	unsigned char		s_blocksize_bits;   //同上，2为底的对数表示
	unsigned char		s_dirt;             //指示超级块是否改变，需要回写
	unsigned long long	s_maxbytes;	/*最大文件长度 */
	struct file_system_type	*s_type;        //指向文件系统type实例
	const struct super_operations	*s_op;  //超级块操作
	struct dquot_operations	*dq_op;
 	struct quotactl_ops	*s_qcop;
	const struct export_operations *s_export_op;
	unsigned long		s_flags;
	unsigned long		s_magic;
	struct dentry		*s_root;    //根目录的dentry
	struct rw_semaphore	s_umount;
	struct mutex		s_lock;
	int			s_count;
	int			s_syncing;
	int			s_need_sync_fs;
	atomic_t		s_active;
#ifdef CONFIG_SECURITY
	void                    *s_security;
#endif
	struct xattr_handler	**s_xattr;      //处理扩展属性的函数

	struct list_head	s_inodes;	/* inode链表 */
	struct list_head	s_dirty;	/* 脏inodes */
	struct list_head	s_io;		/* parked for writeback */
	struct list_head	s_more_io;	/* parked for more writeback */
	struct hlist_head	s_anon;		/* anonymous dentries for (nfs) exporting */
	struct list_head	s_files;    //打开文件链表

	struct block_device	*s_bdev;        //指向块设备
	struct mtd_info		*s_mtd;
	struct list_head	s_instances;
	struct quota_info	s_dquot;	/* Diskquota specific options */

	int			s_frozen;
	wait_queue_head_t	s_wait_unfrozen;    //等待队列

	char s_id[32];				/* Informational name */

    //具体文件系统相关
	void 			*s_fs_info;	/* Filesystem private info */

	/*
	 * The next field is for VFS *only*. No filesystems have any business
	 * even looking at it. You had been warned.
	 */
	struct mutex s_vfs_rename_mutex;	/* Kludge */

	/* Granularity of c/m/atime in ns.
	   Cannot be worse than a second */
	u32		   s_time_gran;

	/*
	 * Filesystem subtype.  If non-empty the filesystem type field
	 * in /proc/mounts will be "type.subtype"
	 */
	char *s_subtype;
};



//inode和超级块快速访问inode,长度通过可用内存计算
static struct hlist_head *inode_hashtable __read_mostly;

struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;
	struct fdtable *fdt;

	struct fdtable fdtab;
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	int next_fd;
	struct embedded_fd_set close_on_exec_init;  //exec时关闭的文件描述符，位图
	struct embedded_fd_set open_fds_init;
	struct file * fd_array[NR_OPEN_DEFAULT];    //允许打开的文件数的默认值是32,64位系统64
};


struct fdtable {
	unsigned int max_fds;   //文件描述符的最大数目
	struct file ** fd;      //当前fd_array,指向上面
	fd_set *close_on_exec;  //当前close_on_exec位图，指向上面
	fd_set *open_fds;
	struct rcu_head rcu;
	struct fdtable *next;
};

struct dentry {
	atomic_t d_count;   //为0置于lru上
    //是否连接到超级块的dentry树，是否被任何inode散列表所包含
	unsigned int d_flags;		/* protected by d_lock */
	spinlock_t d_lock;		/* per dentry lock */
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	/*
	 * The next three fields are touched by __d_lookup.  Place them here
	 * so they all fit in a cache line.
	 */
	struct hlist_node d_hash;	/* lookup hash list dentry_hashtable*/
	struct dentry *d_parent;	/* 父目录*/
	struct qstr d_name;     //不存绝对路径，只存文件名

    //dentry_unused
	struct list_head d_lru;		/* LRU list */
	/*
	 * d_child and d_rcu can share memory
	 */
	union {
		struct list_head d_child;	/* 链入父目录d_subdirs */
	 	struct rcu_head d_rcu;
	} d_u;
	struct list_head d_subdirs;	/* our children */
	struct list_head d_alias;	/* 链入inode的i_dentry,硬链接啥的 */
	unsigned long d_time;		/* used by d_revalidate */
	struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	void *d_fsdata;			/* fs-specific data */
#ifdef CONFIG_PROFILING
	struct dcookie_struct *d_cookie; /* cookie, if any */
#endif
	int d_mounted;          //是否为装载点
	unsigned char d_iname[DNAME_INLINE_LEN_MIN];	/* 短文件名 */
};

-6x = -8(mod 7)

