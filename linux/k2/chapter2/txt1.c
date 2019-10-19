#if 1
���������������Ե��Ƚ��̣��������Ե���ʵ��Ϊ��λ��һ������ʵ�������һ���û���һ���û����

EXIT_DEAD״̬��ָwaitϵͳ�����Ѿ�������������ȫ��ϵͳ���Ƴ�֮ǰ��״̬

��Դ���Ƶ�������signal_struct����,�û���ͨ��/proc/self/limits�鿴

pid,tgidΪ0��pid�����ռ��ֵ����ȫ��ֵ

task_struct �ṹ��
struct task_struct {
    //����״̬
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
    //ָ����Ӧ��thread_info�ṹ
	void *stack;
	atomic_t usage;
	unsigned int flags;	/* per process flags, defined below */
	unsigned int ptrace;

    //���ں������
	int lock_depth;		/* BKL lock depth */

#ifdef CONFIG_SMP
#ifdef __ARCH_WANT_UNLOCKED_CTXSW
	int oncpu;
#endif
#endif
    //���ȼ����
    //static��ͨ��nice�����޸�
    //������ʹ��prio
	int prio, static_prio, normal_prio;
	struct list_head run_list;
    //��������
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

    //���Ȳ���,һ��ΪSCHED_NORMAL,ʹ��cfs
    //BATCH(�ǽ�����cpu�ܼ�)��IDLEҲͨ��cfs
    //RR,FIFO����ʵʱ
	unsigned int policy;
    //�������е�cpu����
	cpumask_t cpus_allowed;
    //ʱ��Ƭ
	unsigned int time_slice;

#if defined(CONFIG_SCHEDSTATS) || defined(CONFIG_TASK_DELAY_ACCT)
	struct sched_info sched_info;
#endif

	struct list_head tasks;
	/*
	 * ptrace_list/ptrace_children forms the list of my children
	 * that were stolen by a ptracer.
	 */

    //�ӽ��̣������ڵ�����������
	struct list_head ptrace_children;
	struct list_head ptrace_list;

    //�ڴ�������,�ں��߳���ǰ�ߣ������������̵�mm,����active_mm
	struct mm_struct *mm, *active_mm;

/* task state */
    //�����Ƹ�ʽ(һ��elf)
	struct linux_binfmt *binfmt;
    //�˳�״̬��EXIT_ZOMBIE,EXIT_DEAD��
	int exit_state;
	int exit_code, exit_signal;
    //��������ֹʱ���͵��ź�
	int pdeath_signal;  /*  The signal sent when the parent dies  */
	/* ??? */
	unsigned int personality;
	unsigned did_exec:1;
    //����id
	pid_t pid;
    //�߳���id
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
    //�����ĸ����̣�Ҳ���ܸ�Ϊinit
	struct task_struct *real_parent; /* real parent process (when being debugged) */
    //����״̬��Ϊ�����߽���
	struct task_struct *parent;	/* parent process */
	/*
	 * children/sibling forms the list of my children plus the
	 * tasks I'm ptracing.
	 */
    //������(prev)���ӽ���/���ϵ�(next)�ӽ���  ��sibling��
	struct list_head children;	/* list of my children */
	struct list_head sibling;	/* linkage in my parent's children list */
    //ָ���߳����鳤
	struct task_struct *group_leader;	/* threadgroup leader */

	/* PID/PID hash table linkage. */
    //PIDɢ�б�
	struct pid_link pids[PIDTYPE_MAX];
    //�߳��������
	struct list_head thread_group;

	struct completion *vfork_done;		/* for vfork() */
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */

    //ʵʱ���ȼ�0-99,99������ȣ���nice��ʹ���෴
	unsigned int rt_priority;
	cputime_t utime, stime, utimescaled, stimescaled;
	cputime_t gtime;
	cputime_t prev_utime, prev_stime;
    //�������л�����
	unsigned long nvcsw, nivcsw; /* context switch counts */
	struct timespec start_time; 		/* monotonic time */
    //����������ʱ��
	struct timespec real_start_time;	/* boot based time */
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
	unsigned long min_flt, maj_flt;

  	cputime_t it_prof_expires, it_virt_expires;
	unsigned long long it_sched_expires;
	struct list_head cpu_timers[3];

/* process credentials */
    //���ƾ��
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
    //������
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
    //���ļ���Ϣ
	struct files_struct *files;         //fd��Ϊ����
/* namespaces */
    //�����ռ�
	struct nsproxy *nsproxy;
/* signal handlers */
    //�źŴ���
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
    //������һ�з����ͷŵ���
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


//pid�����ռ�
struct pid_namespace {
	struct kref kref;
    //λͼ�����ٷ�����?
	struct pidmap pidmap[PIDMAP_ENTRIES];
	int last_pid;
    //ָ��"�ֲ�init"���̣��ý��̶Թ¶�����wait4
	struct task_struct *child_reaper;
    //pid������
	struct kmem_cache *pid_cachep;
    //����,ȫ�ֿռ�Ϊ0
	int level;
    //ָ�򸸿ռ�
	struct pid_namespace *parent;
#ifdef CONFIG_PROC_FS
	struct vfsmount *proc_mnt;
#endif

    kernel/pi.c->copy_pid_ns()������ flags & CLONE_NEWPID��CLONE_THREAD���ܹ���
    kernel/fork.c->fork()������
        if( thread_group_leader(p) ){
            if( clone_flags & CLONE_NEWPID )
                p->nsproxy->pid_ns->child_reaper = p;
        }
    �����������ռ�Ľ������鳤�����γ�Ϊ���ֲ�init��
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
    //���ü���
	atomic_t count;
	/* lists of tasks that use this pid */
    //��һ��Ӧ��ֻ����һ������?
	struct hlist_head tasks[PIDTYPE_MAX];
	struct rcu_head rcu;
    //����
	int level;
    //ÿ��һ��upid�ṹ��upid����ָ����Ӧ�����ռ��ָ��
	struct upid numbers[1];
};

struct pid_link
{
	struct hlist_node node;
	struct pid *pid;
};

//img_pid_hash.png
ÿ��task_struct��PIDTYPE_MAX��pid_link,link�е�pidָ��һ��pid�ṹ,����ָ��pid�ṹ��task_struct��pid�ṹ�ж�Ӧ��ID���͵�hlist_head������
( ��pid�ṹΪȫ�ֽṹ )
������˵��A��PIDΪN��B��PGIDΪN��C��PGIDΪN����A��pids[0]ָ��pid,B,C��pids[1]ָ��pid����pid->tasks[1]��B��C����

pid_hash��һ��ȫ��ɢ�б�
��upid����

attach( task,type,pid ){
    task->pids[type]->pid = pid;
    insert( pid->tasks[type],&task->pids[type]->node );
}

vfork�����������̵ĸ������������ݣ��ӽ����˳���ʼ�³���֮ǰ������������
�̵߳�ջ�����ȷ����

#endif
