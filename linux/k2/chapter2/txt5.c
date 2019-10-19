//调度实体嵌在task_struct里面
struct sched_entity {
    //权重
    //内核中存在一张表格，将nice值映射到load，nice越大，权重越小
	struct load_weight	load;		/* for load-balancing */
    //红黑结点
	struct rb_node		run_node;
    //入队为1否则为0
	unsigned int		on_rq;

    //这次获取CPU开始运行的时间
	u64			exec_start;
    //从开始运行到当前的时间
	u64			sum_exec_runtime;
	u64			vruntime;
    //撤出cpu时，sum_exec_runtime保存到这里
	u64			prev_sum_exec_runtime;

#ifdef CONFIG_SCHEDSTATS
	u64			wait_start;
	u64			wait_max;

	u64			sleep_start;
	u64			sleep_max;
	s64			sum_sleep_runtime;

	u64			block_start;
	u64			block_max;
	u64			exec_max;
	u64			slice_max;

	u64			nr_migrations;
	u64			nr_migrations_cold;
	u64			nr_failed_migrations_affine;
	u64			nr_failed_migrations_running;
	u64			nr_failed_migrations_hot;
	u64			nr_forced_migrations;
	u64			nr_forced2_migrations;

	u64			nr_wakeups;
	u64			nr_wakeups_sync;
	u64			nr_wakeups_migrate;
	u64			nr_wakeups_local;
	u64			nr_wakeups_remote;
	u64			nr_wakeups_affine;
	u64			nr_wakeups_affine_attempts;
	u64			nr_wakeups_passive;
	u64			nr_wakeups_idle;
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct sched_entity	*parent;
	/* rq on which this entity is (to be) queued: */
	struct cfs_rq		*cfs_rq;
	/* rq "owned" by this entity/group: */
	struct cfs_rq		*my_q;
#endif
};

//调度器类
struct sched_class {
	const struct sched_class *next;

	void (*enqueue_task) (struct rq *rq, struct task_struct *p, int wakeup);
	void (*dequeue_task) (struct rq *rq, struct task_struct *p, int sleep);
    //进程自愿放弃控制权时
	void (*yield_task) (struct rq *rq);

    //抢占时调用，如wake_up_new_task
	void (*check_preempt_curr) (struct rq *rq, struct task_struct *p);

	struct task_struct * (*pick_next_task) (struct rq *rq);
	void (*put_prev_task) (struct rq *rq, struct task_struct *p);

#ifdef CONFIG_SMP
	unsigned long (*load_balance) (struct rq *this_rq, int this_cpu,
			struct rq *busiest, unsigned long max_load_move,
			struct sched_domain *sd, enum cpu_idle_type idle,
			int *all_pinned, int *this_best_prio);

	int (*move_one_task) (struct rq *this_rq, int this_cpu,
			      struct rq *busiest, struct sched_domain *sd,
			      enum cpu_idle_type idle);
#endif

    //将当前task给某个队列
	void (*set_curr_task) (struct rq *rq);
    //周期调用
	void (*task_tick) (struct rq *rq, struct task_struct *p);
    //fork时
	void (*task_new) (struct rq *rq, struct task_struct *p);
};

struct load_weight {
    //inv是黑科技产生的1/weight，没有深究
	unsigned long weight, inv_weight;
};

//cfs
static const struct sched_class fair_sched_class = {
	.next			= &idle_sched_class,
	.enqueue_task		= enqueue_task_fair,
	.dequeue_task		= dequeue_task_fair,
	.yield_task		= yield_task_fair,

	.check_preempt_curr	= check_preempt_wakeup,

	.pick_next_task		= pick_next_task_fair,
	.put_prev_task		= put_prev_task_fair,

#ifdef CONFIG_SMP
	.load_balance		= load_balance_fair,
	.move_one_task		= move_one_task_fair,
#endif
	.set_curr_task          = set_curr_task_fair,
	.task_tick		= task_tick_fair,
	.task_new		= task_new_fair,
};


static void task_new_fair(struct rq *rq, struct task_struct *p)
{
	struct cfs_rq *cfs_rq = task_cfs_rq(p);
	struct sched_entity *se = &p->se, *curr = cfs_rq->curr;
	int this_cpu = smp_processor_id();

	sched_info_queued(p);

	update_curr(cfs_rq);
	place_entity(cfs_rq, se, 1);

	/* 'curr' will be NULL if the child belongs to a different group */
	if (sysctl_sched_child_runs_first && this_cpu == task_cpu(p) &&
			curr && curr->vruntime < se->vruntime) {
		/*
		 * Upon rescheduling, sched_class::put_prev_task() will place
		 * 'current' within the tree based on its new key value.
		 */
		swap(curr->vruntime, se->vruntime);
	}

	enqueue_task_fair(rq, p, 0);
	resched_task(rq->curr);
}

static void check_preempt_wakeup(struct rq *rq, struct task_struct *p)
{
	struct task_struct *curr = rq->curr;
	struct cfs_rq *cfs_rq = task_cfs_rq(curr);
	struct sched_entity *se = &curr->se, *pse = &p->se;
	unsigned long gran;

    //实时进程的处理
	if (unlikely(rt_prio(p->prio))) {
		update_rq_clock(rq);
		update_curr(cfs_rq);
		resched_task(curr);
		return;
	}
	/*
	 * Batch tasks do not preempt (their preemption is driven by
	 * the tick):
	 */
	if (unlikely(p->policy == SCHED_BATCH))
		return;

    //如果没开唤醒抢占
	if (!sched_feat(WAKEUP_PREEMPT))
		return;

	while (!is_same_group(se, pse)) {
		se = parent_entity(se);
		pse = parent_entity(pse);
	}

	gran = sysctl_sched_wakeup_granularity;
	if (unlikely(se->load.weight != NICE_0_LOAD))
		gran = calc_delta_fair(gran, &se->load);

	if (pse->vruntime + gran < se->vruntime)
		resched_task(curr);
}

//权重
struct load_weight {
	unsigned long weight, inv_weight;
};

struct cfs_rq {
	struct load_weight load;
	unsigned long nr_running;

	u64 exec_clock;
    //最小虚拟运行时间，有可能比最左边的树结点vruntime大
	u64 min_vruntime;

    //树根
	struct rb_root tasks_timeline;
	struct rb_node *rb_leftmost;
	struct rb_node *rb_load_balance_curr;
	/* 'curr' points to currently running entity on this cfs_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	struct sched_entity *curr;

	unsigned long nr_spread_over;

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct rq *rq;	/* cpu runqueue to which this cfs_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a cpu. This
	 * list is used during load balance.
	 */
	struct list_head leaf_cfs_rq_list;
	struct task_group *tg;	/* group that "owns" this runqueue */
#endif
};

//所有队列保存在全局PCPU数组
static DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);
//队列
struct rq {
	/* runqueue lock: */
	spinlock_t lock;

	/*
	 * nr_running and cpu_load should be in the same cacheline because
	 * remote CPUs use both these fields when doing load calculation.
	 */
    //当前队列上可运行进程数
	unsigned long nr_running;
	#define CPU_LOAD_IDX_MAX 5
	unsigned long cpu_load[CPU_LOAD_IDX_MAX];
	unsigned char idle_at_tick;
#ifdef CONFIG_NO_HZ
	unsigned char in_nohz_recently;
#endif
	/* capture load from *all* tasks on this cpu: */
    //所有进程的权重之和
	struct load_weight load;
	unsigned long nr_load_updates;
	u64 nr_switches;

    //嵌入的cfs子就绪队列
	struct cfs_rq cfs;
#ifdef CONFIG_FAIR_GROUP_SCHED
	/* list of leaf cfs_rq on this cpu: */
	struct list_head leaf_cfs_rq_list;
#endif
	struct rt_rq rt;
#if 0
#endif

	/*
	 * This is part of a global counter where only the total sum
	 * over all CPUs matters. A task can increase this counter on
	 * one CPU and if it got migrated afterwards it may decrease
	 * it on another CPU. Always updated under the runqueue lock:
	 */
	unsigned long nr_uninterruptible;

    //当前和idle进程
	struct task_struct *curr, *idle;
	unsigned long next_balance;
	struct mm_struct *prev_mm;
    
    //队列时钟，每次调周期性调度器都会更clock
    //prev为上次更新后的时间
	u64 clock, prev_clock_raw;
    //统计量，最大delta
	s64 clock_max_delta;

	unsigned int clock_warps, clock_overflows;
	u64 idle_clock;
	unsigned int clock_deep_idle_events;
	u64 tick_timestamp;

	atomic_t nr_iowait;

#ifdef CONFIG_SMP
	struct sched_domain *sd;

	/* For active balancing */
	int active_balance;
	int push_cpu;
	/* cpu of this runqueue: */
	int cpu;

	struct task_struct *migration_thread;
	struct list_head migration_queue;
#endif

#ifdef CONFIG_SCHEDSTATS
	/* latency stats */
	struct sched_info rq_sched_info;

	/* sys_sched_yield() stats */
	unsigned int yld_exp_empty;
	unsigned int yld_act_empty;
	unsigned int yld_both_empty;
	unsigned int yld_count;

	/* schedule() stats */
	unsigned int sched_switch;
	unsigned int sched_count;
	unsigned int sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int ttwu_count;
	unsigned int ttwu_local;

	/* BKL stats */
	unsigned int bkl_count;
#endif
	struct lock_class_key rq_lock_key;
};


/*
 * This function gets called by the timer code, with HZ frequency.
 * We call it with interrupts disabled.
 *
 * It also gets called by the fork code, when changing the parent's
 * timeslices.
 */
周期性调度器
void scheduler_tick(void)
{
	int cpu = smp_processor_id();
	struct rq *rq = cpu_rq(cpu);
	struct task_struct *curr = rq->curr;
	u64 next_tick = rq->tick_timestamp + TICK_NSEC;

	spin_lock(&rq->lock);
	__update_rq_clock(rq);
	/*
	 * Let rq->clock advance by at least TICK_NSEC:
	 */
	if (unlikely(rq->clock < next_tick))
		rq->clock = next_tick;
	rq->tick_timestamp = rq->clock;
	update_cpu_load(rq);
	if (curr != rq->idle) /* FIXME: needed? */
		curr->sched_class->task_tick(rq, curr);
	spin_unlock(&rq->lock);

#ifdef CONFIG_SMP
	rq->idle_at_tick = idle_cpu(cpu);
	trigger_load_balance(rq, cpu);
#endif
}

static void entity_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	/*
	 * Update run-time statistics of the 'current'.
	 */
	update_curr(cfs_rq);

	if (cfs_rq->nr_running > 1 || !sched_feat(WAKEUP_PREEMPT))
		check_preempt_tick(cfs_rq, curr);
}

check_preempt_tick(struct cfs_rq *cfs_rq, struct sched_entity *curr)
{
	unsigned long ideal_runtime, delta_exec;

    //一个真实周期中该任务所占时间
	ideal_runtime = sched_slice(cfs_rq, curr);
	delta_exec = curr->sum_exec_runtime - curr->prev_sum_exec_runtime;
	if (delta_exec > ideal_runtime)
		resched_task(rq_of(cfs_rq)->curr);
}

static void update_curr(struct cfs_rq *cfs_rq)
{
	struct sched_entity *curr = cfs_rq->curr;
    //获取当前真实时间
	u64 now = rq_of(cfs_rq)->clock;
	unsigned long delta_exec;

	if (unlikely(!curr))
		return;

	/*
	 * Get the amount of time the current task was running
	 * since the last time we changed load (this cannot
	 * overflow on 32 bits):
	 */
    //已经运行的时间
	delta_exec = (unsigned long)(now - curr->exec_start);

	__update_curr(cfs_rq, curr, delta_exec);
	curr->exec_start = now;

	if (entity_is_task(curr)) {
		struct task_struct *curtask = task_of(curr);

		cpuacct_charge(curtask, delta_exec);
	}
}



__update_curr(struct cfs_rq *cfs_rq, struct sched_entity *curr,
	      unsigned long delta_exec)
{
	unsigned long delta_exec_weighted;
	u64 vruntime;

    //更新统计量，最大的运行时间
	schedstat_set(curr->exec_max, max((u64)delta_exec, curr->exec_max));

    //当前进程总运行时间增加
	curr->sum_exec_runtime += delta_exec;
    //更新统计量，当前rq的运行时长
	schedstat_add(cfs_rq, exec_clock, delta_exec);
	delta_exec_weighted = delta_exec;
    //NICE_0_LOAD的权重，其物理时间和虚拟时间相同
	if (unlikely(curr->load.weight != NICE_0_LOAD)) {
        //虚拟时间 = 真实时间 * NICE_0_LOAD/权重
		delta_exec_weighted = calc_delta_fair(delta_exec_weighted,
							&curr->load);
	}
    //增加虚拟时间
	curr->vruntime += delta_exec_weighted;

	/*
	 * maintain cfs_rq->min_vruntime to be a monotonic increasing
	 * value tracking the leftmost vruntime in the tree.
	 */
    //如果有最左节点
	if (first_fair(cfs_rq)) {
        //取当前虚拟时间和最左节点的虚拟时间的最小值
		vruntime = min_vruntime(curr->vruntime,
				__pick_next_entity(cfs_rq)->vruntime);
	} else
		vruntime = curr->vruntime;
    //更新当前队列的最小虚拟时间,保证其单调递增
	cfs_rq->min_vruntime =
		max_vruntime(cfs_rq->min_vruntime, vruntime);
}

//红黑树排序用的key值
static inline s64 entity_key(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	return se->vruntime - cfs_rq->min_vruntime;
}

//以下的量控制cfs调度的特性
/*
 * Targeted preemption latency for CPU-bound tasks:
 * (default: 20ms * (1 + ilog(ncpus)), units: nanoseconds)
 *
 * NOTE: this latency value is not the same as the concept of
 * 'timeslice length' - timeslices in CFS are of variable length
 * and have no persistent notion like in traditional, time-slice
 * based scheduling concepts.
 *
 * (to see the precise effective timeslice length of your workload,
 *  run vmstat and monitor the context-switches (cs) field)
 */
//良好的调度延迟
unsigned int sysctl_sched_latency = 20000000ULL;

/*
 * Minimal preemption granularity for CPU-bound tasks:
 * (default: 4 msec * (1 + ilog(ncpus)), units: nanoseconds)
 */
unsigned int sysctl_sched_min_granularity = 4000000ULL;

/*
 * is kept at sysctl_sched_latency / sysctl_sched_min_granularity
 */
//一个延迟周期中最大活动数目,如果进程增加，延迟周期也会成比例线性增长
static unsigned int sched_nr_latency = 5;

/*
 * After fork, child runs first. (default) If set to 0 then
 * parent will (try to) run first.
 */
const_debug unsigned int sysctl_sched_child_runs_first = 1;


/*
 * We calculate the wall-time slice from the period by taking a part
 * proportional to the weight.
 *
 * s = p*w/rw
 */
// 良好的周期 * 权重/总权重
static u64 sched_slice(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	u64 slice = __sched_period(cfs_rq->nr_running);

	slice *= se->load.weight;
	do_div(slice, cfs_rq->load.weight);

	return slice;
}

/*
 * We calculate the vruntime slice.
 *
 * vs = s/w = p/rw
 */
//良好的周期 * nice0的权重/总权重
static u64 __sched_vslice(unsigned long rq_weight, unsigned long nr_running)
{
	u64 vslice = __sched_period(nr_running);

	vslice *= NICE_0_LOAD;
	do_div(vslice, rq_weight);

	return vslice;
}

static u64 sched_vslice(struct cfs_rq *cfs_rq)
{
	return __sched_vslice(cfs_rq->load.weight, cfs_rq->nr_running);
}

static u64 sched_vslice_add(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	return __sched_vslice(cfs_rq->load.weight + se->load.weight,
			cfs_rq->nr_running + 1);
}


static void
enqueue_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int wakeup)
{
	/*
	 * Update run-time statistics of the 'current'.
	 */
	update_curr(cfs_rq);

	if (wakeup) {
        /*
	    if (!initial) {
		//sleeps upto a single latency don't count.
		if (sched_feat(NEW_FAIR_SLEEPERS) && entity_is_task(se))
			vruntime -= sysctl_sched_latency;
		//ensure we never gain time by being placed backwards.
		vruntime = max_vruntime(se->vruntime, vruntime);
	    }
        
        */
		place_entity(cfs_rq, se, 0);
		enqueue_sleeper(cfs_rq, se);
	}

    //更新wait_start到当前时间
	update_stats_enqueue(cfs_rq, se);
	check_spread(cfs_rq, se);
    //插入红黑树
	if (se != cfs_rq->curr)
		__enqueue_entity(cfs_rq, se);
	account_entity_enqueue(cfs_rq, se);
}


static void
place_entity(struct cfs_rq *cfs_rq, struct sched_entity *se, int initial)
{
	u64 vruntime;

	vruntime = cfs_rq->min_vruntime;

	/*
	 * The 'current' period is already promised to the current tasks,
	 * however the extra weight of the new task will slow them down a
	 * little, place the new task so that it fits in the slot that
	 * stays open at the end.
	 */
    //增加一部分虚拟时间
	if (initial && sched_feat(START_DEBIT))
		vruntime += sched_vslice_add(cfs_rq, se);

	if (!initial) {
		/* sleeps upto a single latency don't count. */
		if (sched_feat(NEW_FAIR_SLEEPERS) && entity_is_task(se))
			vruntime -= sysctl_sched_latency;

		/* ensure we never gain time by being placed backwards. */
		vruntime = max_vruntime(se->vruntime, vruntime);
	}

	se->vruntime = vruntime;
}

static void
account_entity_enqueue(struct cfs_rq *cfs_rq, struct sched_entity *se)
{
	update_load_add(&cfs_rq->load, se->load.weight);
	cfs_rq->nr_running++;
	se->on_rq = 1;
}
HZ

/*


*/
