#if 1
调度器不仅仅可以调度进程，还可以以调度实体为单位，一个调度实体可以是一个用户，一个用户组等

EXIT_DEAD状态是指wait系统调用已经发出，进程完全从系统中移除之前的状态

资源限制的数组在signal_struct里面,用户层通过/proc/self/limits查看

pid,tgid为0层pid命名空间的值，既全局值

task_struct 结构体
struct task_struct {
    //进程状态
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
    //指向相应的thread_info结构
	void *stack;
	atomic_t usage;
	unsigned int flags;	/* per process flags, defined below */
	unsigned int ptrace;

    //大内核锁深度
	int lock_depth;		/* BKL lock depth */

#ifdef CONFIG_SMP
#ifdef __ARCH_WANT_UNLOCKED_CTXSW
	int oncpu;
#endif
#endif
    //优先级相关
    //static可通过nice调用修改
    //调度器使用prio
	int prio, static_prio, normal_prio;
	struct list_head run_list;
    //调度器类
	const struct sched_class *sched_class;
	struct sched_entity se;

#ifdef CONFIG_PREEMPT_NOTIFIERS
	/* list of struct preempt_notifier: */
	struct hlist_head preempt_notifiers;
#endif

	unsigned short ioprio;
	/*
	 * fpu_counter contains the number of consecutive context switches
	 * that the FPU is used. If this is over a threshold, the lazy fpu
	 * saving becomes unlazy to save the trap. This is an unsigned char
	 * so that after 256 times the counter wraps and the behavior turns
	 * lazy again; this to deal with bursty apps that only use FPU for
	 * a short time
	 */
	unsigned char fpu_counter;
	s8 oomkilladj; /* OOM kill score adjustment (bit shift). */
#ifdef CONFIG_BLK_DEV_IO_TRACE
	unsigned int btrace_seq;
#endif

    //调度策略,一般为SCHED_NORMAL,使用cfs
    //BATCH(非交互，cpu密集)和IDLE也通过cfs
    //RR,FIFO用于实时
	unsigned int policy;
    //允许运行的cpu掩码
	cpumask_t cpus_allowed;
    //时间片
	unsigned int time_slice;

#if defined(CONFIG_SCHEDSTATS) || defined(CONFIG_TASK_DELAY_ACCT)
	struct sched_info sched_info;
#endif

	struct list_head tasks;
	/*
	 * ptrace_list/ptrace_children forms the list of my children
	 * that were stolen by a ptracer.
	 */

    //子进程，但是在调试器控制下
	struct list_head ptrace_children;
	struct list_head ptrace_list;

    //内存描述符,内核线程无前者，借助寄生进程的mm,赋给active_mm
	struct mm_struct *mm, *active_mm;

/* task state */
    //二进制格式(一般elf)
	struct linux_binfmt *binfmt;
    //退出状态（EXIT_ZOMBIE,EXIT_DEAD）
	int exit_state;
	int exit_code, exit_signal;
    //父进程终止时发送的信号
	int pdeath_signal;  /*  The signal sent when the parent dies  */
	/* ??? */
	unsigned int personality;
	unsigned did_exec:1;
    //进程id
	pid_t pid;
    //线程组id
	pid_t tgid;

#ifdef CONFIG_CC_STACKPROTECTOR
	/* Canary value for the -fstack-protector gcc feature */
	unsigned long stack_canary;
#endif
	/* 
	 * pointers to (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with 
	 * p->parent->pid)
	 */
    //真正的父进程，也可能改为init
	struct task_struct *real_parent; /* real parent process (when being debugged) */
    //调试状态下为调试者进程
	struct task_struct *parent;	/* parent process */
	/*
	 * children/sibling forms the list of my children plus the
	 * tasks I'm ptracing.
	 */
    //最年轻(prev)的子进程/最老的(next)子进程  的sibling，
	struct list_head children;	/* list of my children */
	struct list_head sibling;	/* linkage in my parent's children list */
    //指向线程组组长
	struct task_struct *group_leader;	/* threadgroup leader */

	/* PID/PID hash table linkage. */
    //PID散列表
	struct pid_link pids[PIDTYPE_MAX];
    //线程组的链表
	struct list_head thread_group;

	struct completion *vfork_done;		/* for vfork() */
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */

    //实时优先级0-99,99最高优先，和nice的使用相反
	unsigned int rt_priority;
	cputime_t utime, stime, utimescaled, stimescaled;
	cputime_t gtime;
	cputime_t prev_utime, prev_stime;
    //上下文切换次数
	unsigned long nvcsw, nivcsw; /* context switch counts */
	struct timespec start_time; 		/* monotonic time */
    //启动以来的时间
	struct timespec real_start_time;	/* boot based time */
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
	unsigned long min_flt, maj_flt;

  	cputime_t it_prof_expires, it_virt_expires;
	unsigned long long it_sched_expires;
	struct list_head cpu_timers[3];

/* process credentials */
    //身份凭据
	uid_t uid,euid,suid,fsuid;
	gid_t gid,egid,sgid,fsgid;
	struct group_info *group_info;
	kernel_cap_t   cap_effective, cap_inheritable, cap_permitted;
	unsigned keep_capabilities:1;
	struct user_struct *user;
#ifdef CONFIG_KEYS
	struct key *request_key_auth;	/* assumed request_key authority */
	struct key *thread_keyring;	/* keyring private to this thread */
	unsigned char jit_keyring;	/* default keyring to attach requested keys to */
#endif
    //进程名
	char comm[TASK_COMM_LEN]; /* executable name excluding path
				     - access with [gs]et_task_comm (which lock
				       it with task_lock())
				     - initialized normally by flush_old_exec */
/* file system info */
	int link_count, total_link_count;
#ifdef CONFIG_SYSVIPC
/* ipc stuff */
	struct sysv_sem sysvsem;
#endif
/* CPU-specific state of this task */
	struct thread_struct thread;
/* filesystem information */
	struct fs_struct *fs;
/* open file information */
    //打开文件信息
	struct files_struct *files;         //fd号为索引
/* namespaces */
    //命名空间
	struct nsproxy *nsproxy;
/* signal handlers */
    //信号处理
	struct signal_struct *signal;
	struct sighand_struct *sighand;

	sigset_t blocked, real_blocked;
	sigset_t saved_sigmask;		/* To be restored with TIF_RESTORE_SIGMASK */
	struct sigpending pending;

	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	int (*notifier)(void *priv);
	void *notifier_data;
	sigset_t *notifier_mask;
#ifdef CONFIG_SECURITY
	void *security;
#endif
	struct audit_context *audit_context;
	seccomp_t seccomp;

/* Thread group tracking */
   	u32 parent_exec_id;
   	u32 self_exec_id;
/* Protection of (de-)allocation: mm, files, fs, tty, keyrings */
    //可用于一切分配释放的锁
	spinlock_t alloc_lock;

	/* Protection of the PI data structures: */
	spinlock_t pi_lock;

#ifdef CONFIG_RT_MUTEXES
	/* PI waiters blocked on a rt_mutex held by this task */
	struct plist_head pi_waiters;
	/* Deadlock detection and priority inheritance handling */
	struct rt_mutex_waiter *pi_blocked_on;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	/* mutex deadlock detection */
	struct mutex_waiter *blocked_on;
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned int irq_events;
	int hardirqs_enabled;
	unsigned long hardirq_enable_ip;
	unsigned int hardirq_enable_event;
	unsigned long hardirq_disable_ip;
	unsigned int hardirq_disable_event;
	int softirqs_enabled;
	unsigned long softirq_disable_ip;
	unsigned int softirq_disable_event;
	unsigned long softirq_enable_ip;
	unsigned int softirq_enable_event;
	int hardirq_context;
	int softirq_context;
#endif
#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH 30UL
	u64 curr_chain_key;
	int lockdep_depth;
	struct held_lock held_locks[MAX_LOCK_DEPTH];
	unsigned int lockdep_recursion;
#endif

/* journalling filesystem info */
	void *journal_info;

/* stacked block device info */
	struct bio *bio_list, **bio_tail;

/* VM state */
	struct reclaim_state *reclaim_state;

	struct backing_dev_info *backing_dev_info;

	struct io_context *io_context;

	unsigned long ptrace_message;
	siginfo_t *last_siginfo; /* For ptrace use.  */
#ifdef CONFIG_TASK_XACCT
/* i/o counters(bytes read/written, #syscalls */
	u64 rchar, wchar, syscr, syscw;
#endif
	struct task_io_accounting ioac;
#if defined(CONFIG_TASK_XACCT)
	u64 acct_rss_mem1;	/* accumulated rss usage */
	u64 acct_vm_mem1;	/* accumulated virtual memory usage */
	cputime_t acct_stimexpd;/* stime since last update */
#endif
#ifdef CONFIG_NUMA
  	struct mempolicy *mempolicy;
	short il_next;
#endif
#ifdef CONFIG_CPUSETS
	nodemask_t mems_allowed;
	int cpuset_mems_generation;
	int cpuset_mem_spread_rotor;
#endif
#ifdef CONFIG_CGROUPS
	/* Control Group info protected by css_set_lock */
	struct css_set *cgroups;
	/* cg_list protected by css_set_lock and tsk->alloc_lock */
	struct list_head cg_list;
#endif
#ifdef CONFIG_FUTEX
	struct robust_list_head __user *robust_list;
#ifdef CONFIG_COMPAT
	struct compat_robust_list_head __user *compat_robust_list;
#endif
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
#endif
	atomic_t fs_excl;	/* holding fs exclusive resources */
	struct rcu_head rcu;

	/*
	 * cache last used pipe for splice
	 */
	struct pipe_inode_info *splice_pipe;
#ifdef	CONFIG_TASK_DELAY_ACCT
    //GHCND
	struct task_delay_info *delays;
#endif
#ifdef CONFIG_FAULT_INJECTION
	int make_it_fail;
#endif
	struct prop_local_single dirties;
};

struct thread_struct {
/* cached TLS descriptors. */
	struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];
	unsigned long	esp0;
	unsigned long	sysenter_cs;
	unsigned long	eip;
	unsigned long	esp;
	unsigned long	fs;
	unsigned long	gs;
/* Hardware debugging registers */
	unsigned long	debugreg[8];  /* %%db0-7 debug registers */
/* fault info */
	unsigned long	cr2, trap_no, error_code;
/* floating point info */
	union i387_union	i387;
/* virtual 86 mode info */
	struct vm86_struct __user * vm86_info;
	unsigned long		screen_bitmap;
	unsigned long		v86flags, v86mask, saved_esp0;
	unsigned int		saved_fs, saved_gs;
/* IO permissions */
	unsigned long	*io_bitmap_ptr;
 	unsigned long	iopl;
/* max allowed port in the bitmap, in bytes: */
	unsigned long	io_bitmap_max;
};


//pid命名空间
struct pid_namespace {
	struct kref kref;
    //位图，加速分配用?
	struct pidmap pidmap[PIDMAP_ENTRIES];
	int last_pid;
    //指向"局部init"进程，该进程对孤儿进程wait4
	struct task_struct *child_reaper;
    //pid分配器
	struct kmem_cache *pid_cachep;
    //层数,全局空间为0
	int level;
    //指向父空间
	struct pid_namespace *parent;
#ifdef CONFIG_PROC_FS
	struct vfsmount *proc_mnt;
#endif

    kernel/pi.c->copy_pid_ns()函数中 flags & CLONE_NEWPID与CLONE_THREAD不能共存
    kernel/fork.c->fork()函数中
        if( thread_group_leader(p) ){
            if( clone_flags & CLONE_NEWPID )
                p->nsproxy->pid_ns->child_reaper = p;
        }
    创建新命名空间的进程组组长有责任成为“局部init”
};


enum pid_type
{
	PIDTYPE_PID,
	PIDTYPE_PGID,
	PIDTYPE_SID,

	PIDTYPE_MAX
};

struct upid {
	/* Try to keep pid_chain in the same cacheline as nr for find_pid */
	int nr;
	struct pid_namespace *ns;
	struct hlist_node pid_chain;
};

struct pid
{
    //引用计数
	atomic_t count;
	/* lists of tasks that use this pid */
    //第一层应该只会有一个人用?
	struct hlist_head tasks[PIDTYPE_MAX];
	struct rcu_head rcu;
    //层数
	int level;
    //每层一个upid结构，upid中有指向相应命名空间的指针
	struct upid numbers[1];
};

struct pid_link
{
	struct hlist_node node;
	struct pid *pid;
};

//img_pid_hash.png
每个task_struct有PIDTYPE_MAX个pid_link,link中的pid指向一个pid结构,所有指向pid结构的task_struct被pid结构中对应的ID类型的hlist_head相连接
( 既pid结构为全局结构 )
举例来说，A的PID为N，B的PGID为N，C的PGID为N，则A的pids[0]指向pid,B,C的pids[1]指向pid，而pid->tasks[1]将B，C串起

pid_hash是一个全局散列表
将upid串起

attach( task,type,pid ){
    task->pids[type]->pid = pid;
    insert( pid->tasks[type],&task->pids[type]->node );
}

vfork不创建父进程的副本，共享数据，子进程退出或开始新程序之前，父进程阻塞
线程的栈是事先分配的

#endif
