inode�������ļ���
�����豸�����ļ�

struct inode {
	struct hlist_node	i_hash;
	struct list_head	i_list;
	struct list_head	i_sb_list;  //��ͷ��superblock��
	struct list_head	i_dentry;
	unsigned long		i_ino;
	atomic_t		i_count;        //���ü�������Ӳ����
	unsigned int		i_nlink;    //Ӳ������
	uid_t			i_uid;
	gid_t			i_gid;
	dev_t			i_rdev;         //�豸��
	unsigned long		i_version;
	loff_t			i_size;         //�ļ���С(�ֽ�)
#ifdef __NEED_I_SIZE_ORDERED
	seqcount_t		i_size_seqcount;
#endif
	struct timespec		i_atime;        //������ʱ��
	struct timespec		i_mtime;        //����޸�ʱ��(����)
	struct timespec		i_ctime;        //����޸�inode��ʱ��
	unsigned int		i_blkbits;
	blkcnt_t		i_blocks;           //�������Ĵ�С
	unsigned short          i_bytes;
	umode_t			i_mode;
	spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
	struct mutex		i_mutex;
	struct rw_semaphore	i_alloc_sem;
	const struct inode_operations	*i_op;
	const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
	struct super_block	*i_sb;              //ָ�򳬼���
	struct file_lock	*i_flock;
	struct address_space	*i_mapping;
	struct address_space	i_data;
#ifdef CONFIG_QUOTA
	struct dquot		*i_dquot[MAXQUOTAS];
#endif
	struct list_head	i_devices;  //ͬһ���豸�Ķ��inodeͨ����������
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
	unsigned long		dirtied_when;	/* jiffies,��һ��dirty��ʱ��*/

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
	const struct file_operations	*f_op;          //��inode�е���ͬ
	atomic_t		f_count;
	unsigned int 		f_flags;
	mode_t			f_mode;
	loff_t			f_pos;      //��ǰƫ����
	struct fown_struct	f_owner;    //��ǰ�ļ�������
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

inode���������������ӣ��ļ���������Ŀ¼���������ļ���ɾ���ļ���
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

ͬһ�ļ�ϵͳ����ӵ�в�ͬ�ĳ����飬ֻҪװ�ص�/������ͬ�����в�ͬ�����飬��home��root����ext3,���ǲ�ͬ������

//��Ч�����
LIST_HEAD(inode_in_use);
//��ʹ�õ�δ�ı�
LIST_HEAD(inode_unused);
//���inode�����ڳ�����������
//��Ч��inode������һ��������


struct super_block {
	struct list_head	s_list;		/* Keep this first ,����Ԫ�أ���ͷsuper_blocks����ϵͳȫ��������*/
	dev_t			s_dev;		/* search index; _not_ kdev_t */
	unsigned long		s_blocksize;        //�ļ�ϵͳ�Ŀ鳤��,�ֽڵ�λ
	unsigned char		s_blocksize_bits;   //ͬ�ϣ�2Ϊ�׵Ķ�����ʾ
	unsigned char		s_dirt;             //ָʾ�������Ƿ�ı䣬��Ҫ��д
	unsigned long long	s_maxbytes;	/*����ļ����� */
	struct file_system_type	*s_type;        //ָ���ļ�ϵͳtypeʵ��
	const struct super_operations	*s_op;  //���������
	struct dquot_operations	*dq_op;
 	struct quotactl_ops	*s_qcop;
	const struct export_operations *s_export_op;
	unsigned long		s_flags;
	unsigned long		s_magic;
	struct dentry		*s_root;    //��Ŀ¼��dentry
	struct rw_semaphore	s_umount;
	struct mutex		s_lock;
	int			s_count;
	int			s_syncing;
	int			s_need_sync_fs;
	atomic_t		s_active;
#ifdef CONFIG_SECURITY
	void                    *s_security;
#endif
	struct xattr_handler	**s_xattr;      //������չ���Եĺ���

	struct list_head	s_inodes;	/* inode���� */
	struct list_head	s_dirty;	/* ��inodes */
	struct list_head	s_io;		/* parked for writeback */
	struct list_head	s_more_io;	/* parked for more writeback */
	struct hlist_head	s_anon;		/* anonymous dentries for (nfs) exporting */
	struct list_head	s_files;    //���ļ�����

	struct block_device	*s_bdev;        //ָ����豸
	struct mtd_info		*s_mtd;
	struct list_head	s_instances;
	struct quota_info	s_dquot;	/* Diskquota specific options */

	int			s_frozen;
	wait_queue_head_t	s_wait_unfrozen;    //�ȴ�����

	char s_id[32];				/* Informational name */

    //�����ļ�ϵͳ���
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



//inode�ͳ�������ٷ���inode,����ͨ�������ڴ����
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
	struct embedded_fd_set close_on_exec_init;  //execʱ�رյ��ļ���������λͼ
	struct embedded_fd_set open_fds_init;
	struct file * fd_array[NR_OPEN_DEFAULT];    //����򿪵��ļ�����Ĭ��ֵ��32,64λϵͳ64
};


struct fdtable {
	unsigned int max_fds;   //�ļ��������������Ŀ
	struct file ** fd;      //��ǰfd_array,ָ������
	fd_set *close_on_exec;  //��ǰclose_on_execλͼ��ָ������
	fd_set *open_fds;
	struct rcu_head rcu;
	struct fdtable *next;
};

struct dentry {
	atomic_t d_count;   //Ϊ0����lru��
    //�Ƿ����ӵ��������dentry�����Ƿ��κ�inodeɢ�б�������
	unsigned int d_flags;		/* protected by d_lock */
	spinlock_t d_lock;		/* per dentry lock */
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	/*
	 * The next three fields are touched by __d_lookup.  Place them here
	 * so they all fit in a cache line.
	 */
	struct hlist_node d_hash;	/* lookup hash list dentry_hashtable*/
	struct dentry *d_parent;	/* ��Ŀ¼*/
	struct qstr d_name;     //�������·����ֻ���ļ���

    //dentry_unused
	struct list_head d_lru;		/* LRU list */
	/*
	 * d_child and d_rcu can share memory
	 */
	union {
		struct list_head d_child;	/* ���븸Ŀ¼d_subdirs */
	 	struct rcu_head d_rcu;
	} d_u;
	struct list_head d_subdirs;	/* our children */
	struct list_head d_alias;	/* ����inode��i_dentry,Ӳ����ɶ�� */
	unsigned long d_time;		/* used by d_revalidate */
	struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	void *d_fsdata;			/* fs-specific data */
#ifdef CONFIG_PROFILING
	struct dcookie_struct *d_cookie; /* cookie, if any */
#endif
	int d_mounted;          //�Ƿ�Ϊװ�ص�
	unsigned char d_iname[DNAME_INLINE_LEN_MIN];	/* ���ļ��� */
};

-6x = -8(mod 7)

