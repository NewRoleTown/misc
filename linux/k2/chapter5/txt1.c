
static inline void __raw_spin_lock(raw_spinlock_t *lock)
{
	asm volatile("\n1:\t"
            //自减1
		     LOCK_PREFIX " ; decb %0\n\t"
             //如果不是负数,跳3
		     "jns 3f\n"
		     "2:\t"
             //未取锁流程
		     "rep;nop\n\t"
             //判断是否为0
		     "cmpb $0,%0\n\t"
             //小于等于0，跳2
		     "jle 2b\n\t"
             //大于0,跳1
		     "jmp 1b\n"
		     "3:\n\t"
		     : "+m" (lock->slock) : : "memory");
}

static inline void __raw_spin_unlock(raw_spinlock_t *lock)
{
	asm volatile("movb $1,%0" : "+m" (lock->slock) :: "memory");
}

struct semaphore {
	atomic_t count;
	int sleepers;   //等待数
	wait_queue_head_t wait;
};

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.count		= ATOMIC_INIT(n),				\
	.sleepers	= 0,						\
	.wait		= __WAIT_QUEUE_HEAD_INITIALIZER((name).wait)	\
}


RCU在受保护资源被改动时创建他的一个副本
RCU保护的代码不能进入睡眠

#define rcu_read_lock() \
	do { \
		preempt_disable(); \
		__acquire(RCU); \
		rcu_read_acquire(); \
	} while(0)


void fastcall call_rcu(struct rcu_head *head,
				void (*func)(struct rcu_head *rcu))
{
	unsigned long flags;
	struct rcu_data *rdp;

	head->func = func;
	head->next = NULL;
	local_irq_save(flags);
	rdp = &__get_cpu_var(rcu_data);
	*rdp->nxttail = head;
	rdp->nxttail = &head->next;
	if (unlikely(++rdp->qlen > qhimark)) {
		rdp->blimit = INT_MAX;
		force_quiescent_state(rdp, &rcu_ctrlblk);
	}
	local_irq_restore(flags);
}

/*
 * Per-CPU data for Read-Copy UPdate.
 * nxtlist - new callbacks are added here
 * curlist - current batch for which quiescent cycle started if any
 */
struct rcu_data {
	/* 1) quiescent state handling : */
	long		quiescbatch;     /* Batch # for grace period */
	int		passed_quiesc;	 /* User-mode/idle loop etc. */
	int		qs_pending;	 /* core waits for quiesc state */

	/* 2) batch handling */
	long  	       	batch;           /* Batch # for current RCU batch */
	struct rcu_head *nxtlist;
	struct rcu_head **nxttail;
	long            qlen; 	 	 /* # of queued callbacks */
	struct rcu_head *curlist;
	struct rcu_head **curtail;
	struct rcu_head *donelist;
	struct rcu_head **donetail;
	long		blimit;		 /* Upper limit on a processed batch */
	int cpu;
	struct rcu_head barrier;
};

static void __cpuinit rcu_online_cpu(int cpu)
{
	struct rcu_data *rdp = &per_cpu(rcu_data, cpu);
	struct rcu_data *bh_rdp = &per_cpu(rcu_bh_data, cpu);

	rcu_init_percpu_data(cpu, &rcu_ctrlblk, rdp);
	rcu_init_percpu_data(cpu, &rcu_bh_ctrlblk, bh_rdp);
	tasklet_init(&per_cpu(rcu_tasklet, cpu), rcu_process_callbacks, 0UL);
}

static void rcu_init_percpu_data(int cpu, struct rcu_ctrlblk *rcp,
						struct rcu_data *rdp)
{
	memset(rdp, 0, sizeof(*rdp));
    //初始化三个链表
	rdp->curtail = &rdp->curlist;
	rdp->nxttail = &rdp->nxtlist;
	rdp->donetail = &rdp->donelist;
	rdp->quiescbatch = rcp->completed;
	rdp->qs_pending = 0;
	rdp->cpu = cpu;
	rdp->blimit = blimit;
}
schedule--->rdp->passed_quiesc = 1;

static int __rcu_pending(struct rcu_ctrlblk *rcp, struct rcu_data *rdp)
{
	/* This cpu has pending rcu entries and the grace period
	 * for them has completed.
	 */
    //待处理回调 且 
	if (rdp->curlist && !rcu_batch_before(rcp->completed, rdp->batch))
		return 1;

	/* This cpu has no pending entries, but there are new entries */
    //没有待处理，有新注册的
	if (!rdp->curlist && rdp->nxtlist)
		return 1;

	/* This cpu has finished callbacks to invoke */
    //等待已完成，回调未执行
	if (rdp->donelist)
		return 1;

	/* The rcu core waits for a quiescent state from the cpu */
    //等待quiescent
	if (rdp->quiescbatch != rcp->cur || rdp->qs_pending)
		return 1;

	/* nothing to do */
	return 0;
}

update_process_times
void rcu_check_callbacks(int cpu, int user)
{
	if (user || 
	    (idle_cpu(cpu) && !in_softirq() && 
				hardirq_count() <= (1 << HARDIRQ_SHIFT))) {
		rcu_qsctr_inc(cpu);
		rcu_bh_qsctr_inc(cpu);
	} else if (!in_softirq())
		rcu_bh_qsctr_inc(cpu);
	tasklet_schedule(&per_cpu(rcu_tasklet, cpu));
}
schedule
per_cpu__rcu_tasklet

GDT-->27

#define raw_smp_processor_id() (x86_read_percpu(cpu_number))
smp_setup_processor_id(void)
{
	current_thread_info()->cpu = hard_smp_processor_id();
	x86_write_percpu(cpu_number, hard_smp_processor_id());
}


/* Initialize the CPU's GDT.  This is either the boot CPU doing itself
   (still using the master per-cpu area), or a CPU doing it for a
   secondary which will soon come up. */
__cpuinit void init_gdt(int cpu)
{
	struct desc_struct *gdt = get_cpu_gdt_table(cpu);

	pack_descriptor((u32 *)&gdt[GDT_ENTRY_PERCPU].a,
			(u32 *)&gdt[GDT_ENTRY_PERCPU].b,
			__per_cpu_offset[cpu], 0xFFFFF,
			0x80 | DESCTYPE_S | 0x2, 0x8);

	per_cpu(this_cpu_off, cpu) = __per_cpu_offset[cpu];
	per_cpu(cpu_number, cpu) = cpu;
}
