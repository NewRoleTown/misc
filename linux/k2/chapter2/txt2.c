
进程的页表标记为不可写，而vma为可写是写时复制的关键

long do_fork( unsigned long clone_flags,          //标志，最低字节指定子进程终止发给父进程的信号
                unsigned long stack_start,          //用户态栈的起始地址
                struct pt_regs *regs,               //指向寄存器及和的指针,寄存器的值已经保存在栈上
                unsigned long stack_size,           //初始栈大小，一般默认，填0
                int __user *parent_tidptr,              
                int __user *child_tidptr)
最后两个参数分别指向父子进程的TID


copy_process
分配pid
初始化VFORK完成处理函数
初始化ptrace
wake_up_new_task
若vfork则wait_for_completion


static struct task_struct *copy_process(unsigned long clone_flags,
					unsigned long stack_start,
					struct pt_regs *regs,
					unsigned long stack_size,
					int __user *child_tidptr,
					struct pid *pid)
{
	int retval;
	struct task_struct *p;
	int cgroup_callbacks_done = 0;

	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
		return ERR_PTR(-EINVAL);

	/*
	 * Thread groups must share signals as well, and detached threads
	 * can only be started up within the thread group.
	 */
    //用户线程组使用同一个信号处理
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);

	/*
	 * Shared signal handlers imply shared VM. By way of the above,
	 * thread groups also imply shared VM. Blocking this case allows
	 * for various simplifications in other code.
	 */
    //使用相同信号处理必须使用相同地址空间
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);


	retval = security_task_create(clone_flags);
	if (retval)
		goto fork_out;

	retval = -ENOMEM;
    //简单的深复制
	/* One for us, one for whoever does the "release_task()" (usually parent) */
    //p->usage = 2
    //p->fs_excl = 0
	p = dup_task_struct(current);
	if (!p)
		goto fork_out;

	rt_mutex_init_task(p);

#ifdef CONFIG_TRACE_IRQFLAGS
	DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled);
	DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);
#endif
	retval = -EAGAIN;
	if (atomic_read(&p->user->processes) >=
			p->signal->rlim[RLIMIT_NPROC].rlim_cur) {
		if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_RESOURCE) &&
		    p->user != current->nsproxy->user_ns->root_user)
			goto bad_fork_free;
	}

    //进程所属的用户的统计数据(引用计数+1)
	atomic_inc(&p->user->__count);
	atomic_inc(&p->user->processes);
	get_group_info(p->group_info);

	/*
	 * If multiple threads are within copy_process(), then this check
	 * triggers too late. This doesn't hurt, the check is only there
	 * to stop root fork bombs.
	 */
    //idle线程不算在nr_threads中
	if (nr_threads >= max_threads)
		goto bad_fork_cleanup_count;

	if (!try_module_get(task_thread_info(p)->exec_domain->module))
		goto bad_fork_cleanup_count;

	if (p->binfmt && !try_module_get(p->binfmt->module))
		goto bad_fork_cleanup_put_domain;

    //尚未exec
	p->did_exec = 0;
	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */
    
	//new_flags &= ~PF_SUPERPRIV取消超级用户权限
	//new_flags |= PF_FORKNOEXEC
    //设置ptrace
	copy_flags(clone_flags, p);
	INIT_LIST_HEAD(&p->children);
	INIT_LIST_HEAD(&p->sibling);
    //vfork相关
	p->vfork_done = NULL;
	spin_lock_init(&p->alloc_lock);

	clear_tsk_thread_flag(p, TIF_SIGPENDING);
	init_sigpending(&p->pending);

	p->utime = cputime_zero;
	p->stime = cputime_zero;
	p->gtime = cputime_zero;
	p->utimescaled = cputime_zero;
	p->stimescaled = cputime_zero;
	p->prev_utime = cputime_zero;
	p->prev_stime = cputime_zero;

#ifdef CONFIG_TASK_XACCT
	p->rchar = 0;		/* I/O counter: bytes read */
	p->wchar = 0;		/* I/O counter: bytes written */
	p->syscr = 0;		/* I/O counter: read syscalls */
	p->syscw = 0;		/* I/O counter: write syscalls */
#endif
	task_io_accounting_init(p);
	acct_clear_integrals(p);

	p->it_virt_expires = cputime_zero;
	p->it_prof_expires = cputime_zero;
	p->it_sched_expires = 0;
	INIT_LIST_HEAD(&p->cpu_timers[0]);
	INIT_LIST_HEAD(&p->cpu_timers[1]);
	INIT_LIST_HEAD(&p->cpu_timers[2]);

    //大内核锁-1为未锁
	p->lock_depth = -1;		/* -1 = no lock */
	do_posix_clock_monotonic_gettime(&p->start_time);
	p->real_start_time = p->start_time;
	monotonic_to_bootbased(&p->real_start_time);
#ifdef CONFIG_SECURITY
	p->security = NULL;
#endif
	p->io_context = NULL;
	p->audit_context = NULL;
	cgroup_fork(p);
#ifdef CONFIG_NUMA
 	p->mempolicy = mpol_copy(p->mempolicy);
 	if (IS_ERR(p->mempolicy)) {
 		retval = PTR_ERR(p->mempolicy);
 		p->mempolicy = NULL;
 		goto bad_fork_cleanup_cgroup;
 	}
	mpol_fix_fork_child_flag(p);
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	p->irq_events = 0;
#ifdef __ARCH_WANT_INTERRUPTS_ON_CTXSW
	p->hardirqs_enabled = 1;
#else
	p->hardirqs_enabled = 0;
#endif
	p->hardirq_enable_ip = 0;
	p->hardirq_enable_event = 0;
	p->hardirq_disable_ip = _THIS_IP_;
	p->hardirq_disable_event = 0;
	p->softirqs_enabled = 1;
	p->softirq_enable_ip = _THIS_IP_;
	p->softirq_enable_event = 0;
	p->softirq_disable_ip = 0;
	p->softirq_disable_event = 0;
	p->hardirq_context = 0;
	p->softirq_context = 0;
#endif
#ifdef CONFIG_LOCKDEP
	p->lockdep_depth = 0; /* no locks held yet */
	p->curr_chain_key = 0;
	p->lockdep_recursion = 0;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	p->blocked_on = NULL; /* not blocked yet */
#endif

	/* Perform scheduler related setup. Assign this task to a CPU. */
    //会将preempt_count设置成1
    //负载均衡
    //p->se.vruntime -= old_cfsrq->min_vruntime - new_cfsrq->min_vruntime;
	sched_fork(p, clone_flags);

	if ((retval = security_task_alloc(p)))
		goto bad_fork_cleanup_policy;
	if ((retval = audit_alloc(p)))
		goto bad_fork_cleanup_security;
	/* copy all the process information */
	if ((retval = copy_semundo(clone_flags, p)))
		goto bad_fork_cleanup_audit;
	if ((retval = copy_files(clone_flags, p)))
		goto bad_fork_cleanup_semundo;
	if ((retval = copy_fs(clone_flags, p)))
		goto bad_fork_cleanup_files;
	if ((retval = copy_sighand(clone_flags, p)))
		goto bad_fork_cleanup_fs;
	if ((retval = copy_signal(clone_flags, p)))
		goto bad_fork_cleanup_sighand;
    //如果指定CLONE_VM,p->mm->mm_users++
	if ((retval = copy_mm(clone_flags, p)))
		goto bad_fork_cleanup_signal;
	if ((retval = copy_keys(clone_flags, p)))
		goto bad_fork_cleanup_mm;
	if ((retval = copy_namespaces(clone_flags, p)))
		goto bad_fork_cleanup_keys;
    //复制thread-specific的数据
    //其中,在栈底开辟了sizeof(regs) + 8的空间，然后将regs的内容拷贝过去
    //更新新进程eax,esp,将esp0设置成底部+8的位置，据注释，这里给ss,sp预留位置
    //应为无栈切换时不压这两个东西(硬件压栈后给出一个esp，如果将这个指针强转成context，则最后两个字段会超出界限,使用此方法可以避免)
    //eip设置为ret_from_fork
	retval = copy_thread(0, clone_flags, stack_start, stack_size, p, regs);
	if (retval)
		goto bad_fork_cleanup_namespaces;

	if (pid != &init_struct_pid) {
		retval = -ENOMEM;
		pid = alloc_pid(task_active_pid_ns(p));
		if (!pid)
			goto bad_fork_cleanup_namespaces;

		if (clone_flags & CLONE_NEWPID) {
			retval = pid_ns_prepare_proc(task_active_pid_ns(p));
			if (retval < 0)
				goto bad_fork_free_pid;
		}
	}

	p->pid = pid_nr(pid);
	p->tgid = p->pid;
	if (clone_flags & CLONE_THREAD)
		p->tgid = current->tgid;

    //设置这个标志,则在schedule_tail时,将pid写入child_tipter
	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;
	/*
	 * Clear TID on mm_release()?
	 */
    //设置这个标志，在mm_release时会将0写入child_tidptr这个地址然后调sys_futex(tidptr,FUTEX_WAKE,1,NULL,NULL,0);
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr: NULL;
#ifdef CONFIG_FUTEX
	p->robust_list = NULL;
#ifdef CONFIG_COMPAT
	p->compat_robust_list = NULL;
#endif
	INIT_LIST_HEAD(&p->pi_state_list);
	p->pi_state_cache = NULL;
#endif
	/*
	 * sigaltstack should be cleared when sharing the same VM
	 */
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
		p->sas_ss_sp = p->sas_ss_size = 0;

	/*
	 * Syscall tracing should be turned off in the child regardless
	 * of CLONE_PTRACE.
	 */
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);
#ifdef TIF_SYSCALL_EMU
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);
#endif

	/* Our parent execution domain becomes current domain
	   These must match for thread signalling to apply */
	p->parent_exec_id = p->self_exec_id;

	/* ok, now we should be set up.. */
	p->exit_signal = (clone_flags & CLONE_THREAD) ? -1 : (clone_flags & CSIGNAL);
	p->pdeath_signal = 0;
	p->exit_state = 0;

	/*
	 * Ok, make it visible to the rest of the system.
	 * We dont wake it up yet.
	 */
	p->group_leader = p;
	INIT_LIST_HEAD(&p->thread_group);
	INIT_LIST_HEAD(&p->ptrace_children);
	INIT_LIST_HEAD(&p->ptrace_list);

	/* Now that the task is set up, run cgroup callbacks if
	 * necessary. We need to run them before the task is visible
	 * on the tasklist. */
	cgroup_fork_callbacks(p);
	cgroup_callbacks_done = 1;

	/* Need tasklist lock for parent etc handling! */
	write_lock_irq(&tasklist_lock);

	/* for sys_ioprio_set(IOPRIO_WHO_PGRP) */
	p->ioprio = current->ioprio;

	/*
	 * The task hasn't been attached yet, so its cpus_allowed mask will
	 * not be changed, nor will its assigned CPU.
	 *
	 * The cpus_allowed mask of the parent may have changed after it was
	 * copied first time - so re-copy it here, then check the child's CPU
	 * to ensure it is on a valid CPU (and if not, just force it back to
	 * parent's CPU). This avoids alot of nasty races.
	 */
	p->cpus_allowed = current->cpus_allowed;
	if (unlikely(!cpu_isset(task_cpu(p), p->cpus_allowed) ||
			!cpu_online(task_cpu(p))))
		set_task_cpu(p, smp_processor_id());

	/* CLONE_PARENT re-uses the old parent */
    //如果要求拷贝父亲或者是创建用户线程
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD))
		p->real_parent = current->real_parent;
	else
		p->real_parent = current;
	p->parent = p->real_parent;

	spin_lock(&current->sighand->siglock);

	/*
	 * Process group and session signals need to be delivered to just the
	 * parent before the fork or both the parent and the child after the
	 * fork. Restart if a signal comes in before we add the new process to
	 * it's process group.
	 * A fatal signal pending means that current will exit, so the new
	 * thread can't slip out of an OOM kill (or normal SIGKILL).
 	 */
	recalc_sigpending();
	if (signal_pending(current)) {
		spin_unlock(&current->sighand->siglock);
		write_unlock_irq(&tasklist_lock);
		retval = -ERESTARTNOINTR;
		goto bad_fork_free_pid;
	}

	if (clone_flags & CLONE_THREAD) {
        //将新创建的线程链入链表
		p->group_leader = current->group_leader;
		list_add_tail_rcu(&p->thread_group, &p->group_leader->thread_group);

		if (!cputime_eq(current->signal->it_virt_expires,
				cputime_zero) ||
		    !cputime_eq(current->signal->it_prof_expires,
				cputime_zero) ||
		    current->signal->rlim[RLIMIT_CPU].rlim_cur != RLIM_INFINITY ||
		    !list_empty(&current->signal->cpu_timers[0]) ||
		    !list_empty(&current->signal->cpu_timers[1]) ||
		    !list_empty(&current->signal->cpu_timers[2])) {
			/*
			 * Have child wake up on its first tick to check
			 * for process CPU timers.
			 */
			p->it_prof_expires = jiffies_to_cputime(1);
		}
	}

	if (likely(p->pid)) {
		add_parent(p);
		if (unlikely(p->ptrace & PT_PTRACED))
			__ptrace_link(p, current->parent);

		if (thread_group_leader(p)) {
			if (clone_flags & CLONE_NEWPID)
				p->nsproxy->pid_ns->child_reaper = p;

			p->signal->tty = current->signal->tty;
			set_task_pgrp(p, task_pgrp_nr(current));
			set_task_session(p, task_session_nr(current));
			attach_pid(p, PIDTYPE_PGID, task_pgrp(current));
			attach_pid(p, PIDTYPE_SID, task_session(current));
			list_add_tail_rcu(&p->tasks, &init_task.tasks);
			__get_cpu_var(process_counts)++;
		}
		attach_pid(p, PIDTYPE_PID, pid);
		nr_threads++;
	}

	total_forks++;
	spin_unlock(&current->sighand->siglock);
	write_unlock_irq(&tasklist_lock);
	proc_fork_connector(p);
	cgroup_post_fork(p);
	return p;

bad_fork_free_pid:
	if (pid != &init_struct_pid)
		free_pid(pid);
bad_fork_cleanup_namespaces:
	exit_task_namespaces(p);
bad_fork_cleanup_keys:
	exit_keys(p);
bad_fork_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
bad_fork_cleanup_signal:
	cleanup_signal(p);
bad_fork_cleanup_sighand:
	__cleanup_sighand(p->sighand);
bad_fork_cleanup_fs:
	exit_fs(p); /* blocking */
bad_fork_cleanup_files:
	exit_files(p); /* blocking */
bad_fork_cleanup_semundo:
	exit_sem(p);
bad_fork_cleanup_audit:
	audit_free(p);
bad_fork_cleanup_security:
	security_task_free(p);
bad_fork_cleanup_policy:
#ifdef CONFIG_NUMA
	mpol_free(p->mempolicy);
bad_fork_cleanup_cgroup:
#endif
	cgroup_exit(p, cgroup_callbacks_done);
	delayacct_tsk_free(p);
	if (p->binfmt)
		module_put(p->binfmt->module);
bad_fork_cleanup_put_domain:
	module_put(task_thread_info(p)->exec_domain->module);
bad_fork_cleanup_count:
	put_group_info(p->group_info);
	atomic_dec(&p->user->processes);
	free_uid(p->user);
bad_fork_free:
	free_task(p);
fork_out:
	return ERR_PTR(retval);
}

}

sys_fork( regs ){
    do_fork( SIGCHLD,regs.esp,&regs,0,NULL,NULL );
}


asmlinkage int sys_clone(struct pt_regs regs)
{
	unsigned long clone_flags;
	unsigned long newsp;
	int __user *parent_tidptr, *child_tidptr;

	clone_flags = regs.ebx;
	newsp = regs.ecx;
	parent_tidptr = (int __user *)regs.edx;
	child_tidptr = (int __user *)regs.edi;
	if (!newsp)
		newsp = regs.esp;
	return do_fork(clone_flags, newsp, &regs, 0, parent_tidptr, child_tidptr);
}

//内核线程的创建
int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));
    
    //线程函数地址
	regs.ebx = (unsigned long) fn;
    //参数
	regs.edx = (unsigned long) arg;

	regs.xds = __USER_DS;
	regs.xes = __USER_DS;
    //#define __KERNEL_PERCPU (GDT_ENTRY_PERCPU * 8)
	regs.xfs = __KERNEL_PERCPU;
	regs.orig_eax = -1;
	regs.eip = (unsigned long) kernel_thread_helper;
	regs.xcs = __KERNEL_CS | get_kernel_rpl();
	regs.eflags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;

	/* Ok, create the new process.. */
	return do_fork(flags | CLONE_VM | CLONE_UNTRACED, 0, &regs, 0, NULL, NULL);
}

现在一般由kthread_create()创建并再之后唤醒
似乎有一个内核线程kthreadd_task专门用来生成内核线程

struct pt_regs {
	long ebx;       //0
	long ecx;       //4
	long edx;       //8
	long esi;       //12    C
	long edi;       //16    10
	long ebp;       //20    14
	long eax;       //24    18
	int  xds;       //28    1C
	int  xes;       //32    20
	int  xfs;       //36    24
	/* int  xgs; */
	long orig_eax;
    
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};


#define SAVE_ALL \
	cld; \
	pushl %fs; \
	CFI_ADJUST_CFA_OFFSET 4;\
	/*CFI_REL_OFFSET fs, 0;*/\
	pushl %es; \
	CFI_ADJUST_CFA_OFFSET 4;\
	/*CFI_REL_OFFSET es, 0;*/\
	pushl %ds; \
	CFI_ADJUST_CFA_OFFSET 4;\
	/*CFI_REL_OFFSET ds, 0;*/\
	pushl %eax; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET eax, 0;\
	pushl %ebp; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET ebp, 0;\
	pushl %edi; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET edi, 0;\
	pushl %esi; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET esi, 0;\
	pushl %edx; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET edx, 0;\
	pushl %ecx; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET ecx, 0;\
	pushl %ebx; \
	CFI_ADJUST_CFA_OFFSET 4;\
	CFI_REL_OFFSET ebx, 0;\
	movl $(__USER_DS), %edx; \
	movl %edx, %ds; \
	movl %edx, %es; \
	movl $(__KERNEL_PERCPU), %edx; \
	movl %edx, %fs


struct thread_info {
	struct task_struct	*task;		/* main task structure */
	struct exec_domain	*exec_domain;	/* execution domain */
	unsigned long		flags;		/* low level flags */
    //TIF_SIGPENGING,TIF_NEED_RESCHED等等
	unsigned long		status;		/* thread-synchronous flags */
	__u32			cpu;		/* current CPU */
	int			preempt_count;	/* 0 => preemptable, <0 => BUG */

    //虚拟空间限制
	mm_segment_t		addr_limit;	/* thread address space:
					 	   0-0xBFFFFFFF for user-thead
						   0-0xFFFFFFFF for kernel-thread
						*/
	void			*sysenter_return;
    //信号相关
	struct restart_block    restart_block;

	unsigned long           previous_esp;   /* ESP of the previous stack in case
						   of nested (IRQ) stacks
						*/
	__u8			supervisor_stack[0];
};
