
asmlinkage void __sched schedule(void)
{
	struct task_struct *prev, *next;
	long *switch_count;
	struct rq *rq;
	int cpu;

need_resched:
    //关闭抢占
	preempt_disable();
	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	rcu_qsctr_inc(cpu);
    //prev为当前进程
	prev = rq->curr;
    //指向非暴力的切换数
	switch_count = &prev->nivcsw;

    //释放大内核锁
    //depth >= 0 说明持有锁，释放全局量kernel_sem
	release_kernel_lock(prev);
need_resched_nonpreemptible:

	schedule_debug(prev);

	/*
	 * Do the rq-clock update outside the rq lock:
	 */
    //关中断
	local_irq_disable();
	__update_rq_clock(rq);
	spin_lock(&rq->lock);
    //清TIF_NEED_SCHED
	clear_tsk_need_resched(prev);

    //如果当前状态不是running且不是被抢占
	if (prev->state && !(preempt_count() & PREEMPT_ACTIVE)) {
        //可中断等待态且有信号
		if (unlikely((prev->state & TASK_INTERRUPTIBLE) &&
				unlikely(signal_pending(prev)))) {
			prev->state = TASK_RUNNING;
		} else {
            //出队
			deactivate_task(rq, prev, 1);
		}
        //非暴力,自愿退出
		switch_count = &prev->nvcsw;
	}

	if (unlikely(!rq->nr_running))
		idle_balance(cpu, rq);

	prev->sched_class->put_prev_task(rq, prev);
	next = pick_next_task(rq, prev);

	sched_info_switch(prev, next);

	if (likely(prev != next)) {
        //队列的切换数+1
		rq->nr_switches++;
		rq->curr = next;
		++*switch_count;

		context_switch(rq, prev, next); /* unlocks the rq */
	} else
		spin_unlock_irq(&rq->lock);

	if (unlikely(reacquire_kernel_lock(current) < 0)) {
		cpu = smp_processor_id();
		rq = cpu_rq(cpu);
		goto need_resched_nonpreemptible;
	}
	preempt_enable_no_resched();
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED)))
		goto need_resched;
}

TLB为了加快 MMU 对虚拟地址的转换而增加的缓存，它记录了一个虚拟地址对应的内存页的物理地址。其实就是根据虚拟地址的前 20 位，来建立一个个条目，对应记录通过查找页表来记录的内存页的物理地址。 
既然有缓存，那么被缓存的内容改变时，就涉及到缓存的刷新，就是 TLB 的刷新问题，当一个页表结构发生变化时，使用该页表节构的 CPU 就应该刷新自己的 TLB。
这将带来一些问题，例如，在某一核上 CPU0 刚从一用户进程切换到内核进程，该内核进程沿用该用户进程的地址空间，但它只访问内核空间部分，这不会有问题，然而，如果该用户进程在CPU1 核上被调度，并且在 CPU0 用它的地址空间时，它在 CPU1 上修改了自己内核空间的页表，此时，若 CPU0 如果访问它的地址空间是非常危险的，不管是被缓存的地址还是未被缓存的地址都将可能带来意想不到的严重后果。
        那么，难道这种美好的事情就要被上面的情况的发生扼杀，而每次都要刷新 TLB，重新加载页表么。显然还是有补救办法的，如果在 CPU0 上的内核进程执行期间，它所引用的用户进程的地址空间没有被调度并执行完毕的情况还是非常多的，这种不刷新 TLB 带来的性能提升还是可以利用一下的，谁让 Linux 是一个精打细算的内核呢。
        如何办到这一点，其实很简单，当内核空间页表集在其它 CPU 上更改时，会调用 flush_tlb_all，它会让每个 CPU 去刷新自己的 TLB。

        那么当用户空间的页表集在其它 CPU 上更改时，由于 CPU0 虽然引用了相同的地址空间，但由于它是一个内核进程，它不会去访问用户空间的地址，那么，那些失效和 TLB 项也不会造成危险，也就是它可以不去立即刷新 TLB。所以此时其它的 CPU 往往会发送一个 IPI 给其它引用该地址空间的 CPU，以通知他们自己更改了用户空间的页表，其它  CPU 就会根据自己的状态作出相应的处理，如果是懒惰模式，就不用刷新 TLB。

        这就引入了 TLB 刷新的懒惰模式。

static inline void
context_switch(struct rq *rq, struct task_struct *prev,
	       struct task_struct *next)
{
	struct mm_struct *mm, *oldmm;

	prepare_task_switch(rq, prev, next);
	mm = next->mm;
	oldmm = prev->active_mm;
	/*
	 * For paravirt, this is coupled with an exit in switch_to to
	 * combine the page table reload and the switch backend into
	 * one hypercall.
	 */
	arch_enter_lazy_cpu_mode();

	if (unlikely(!mm)) {
        //切换至内核线程
		next->active_mm = oldmm;
		atomic_inc(&oldmm->mm_count);
        //lazy_tlb
		enter_lazy_tlb(oldmm, next);
	} else
		switch_mm(oldmm, mm, next);

	if (unlikely(!prev->mm)) {
		prev->active_mm = NULL;
		rq->prev_mm = oldmm;
	}
	/*
	 * Since the runqueue lock will be released by the next
	 * task (which is an invalid locking op but in the case
	 * of the scheduler it's an obvious special-case), so we
	 * do an early lockdep release here:
	 */
#ifndef __ARCH_WANT_UNLOCKED_CTXSW
	spin_release(&rq->lock.dep_map, 1, _THIS_IP_);
#endif

	/* Here we just switch the register state and the stack. */
	switch_to(prev, next, prev);

	barrier();
	/*
	 * this_rq must be evaluated again because prev may have moved
	 * CPUs since it called schedule(), thus the 'rq' on its stack
	 * frame will be invalid.
	 */
	finish_task_switch(this_rq(), prev);
}

//压入了下一个进程的eip然后jmp到__switch_to，与是jmp后返回到下一个进程
#define switch_to(prev,next,last) do {					\
	unsigned long esi,edi;						\
	asm volatile("pushfl\n\t"		/* Save flags */	\
		     "pushl %%ebp\n\t"					\
		     "movl %%esp,%0\n\t"	/* save ESP */		\
		     "movl %5,%%esp\n\t"	/* restore ESP */	\
		     "movl $1f,%1\n\t"		/* save EIP */		\
		     "pushl %6\n\t"		/* restore EIP */	\
		     "jmp __switch_to\n"				\
		     "1:\t"						\
		     "popl %%ebp\n\t"					\
		     "popfl"						\
		     :"=m" (prev->thread.esp),"=m" (prev->thread.eip),	\
		      "=a" (last),"=S" (esi),"=D" (edi)			\
		     :"m" (next->thread.esp),"m" (next->thread.eip),	\
		      "2" (prev), "d" (next));				\
} while (0)


static inline void native_load_esp0(struct tss_struct *tss, struct thread_struct *thread)
{
	tss->x86_tss.esp0 = thread->esp0;
	/* This can only happen when SEP is enabled, no need to test "SEP"arately */
    //ss1被用做SYSENTER的cache
	if (unlikely(tss->x86_tss.ss1 != thread->sysenter_cs)) {
		tss->x86_tss.ss1 = thread->sysenter_cs;
		wrmsr(MSR_IA32_SYSENTER_CS, thread->sysenter_cs, 0);
	}
}

struct task_struct fastcall * __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread,
				 *next = &next_p->thread;
	int cpu = smp_processor_id();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);

	/* never put a printk in __switch_to... printk() calls wake_up*() indirectly */

	__unlazy_fpu(prev_p);


	/* we're going to use this soon, after a few expensive things */
	if (next_p->fpu_counter > 5)
		prefetch(&next->i387.fxsave);

	/*
	 * Reload esp0.
	 */
	load_esp0(tss, next);

	/*
	 * Save away %gs. No need to save %fs, as it was saved on the
	 * stack on entry.  No need to save %es and %ds, as those are
	 * always kernel segments while inside the kernel.  Doing this
	 * before setting the new TLS descriptors avoids the situation
	 * where we temporarily have non-reloadable segments in %fs
	 * and %gs.  This could be an issue if the NMI handler ever
	 * used %fs or %gs (it does not today), or if the kernel is
	 * running inside of a hypervisor layer.
	 */
	savesegment(gs, prev->gs);

	/*
	 * Load the per-thread Thread-Local Storage descriptor.
	 */
    //这里会修改gs段的内容，因此切换线程,gs不变，gs内容变
	load_TLS(next, cpu);

	/*
	 * Restore IOPL if needed.  In normal use, the flags restore
	 * in the switch assembly will handle this.  But if the kernel
	 * is running virtualized at a non-zero CPL, the popf will
	 * not restore flags, so it must be done in a separate step.
	 */
	if (get_kernel_rpl() && unlikely(prev->iopl != next->iopl))
		set_iopl_mask(next->iopl);

	/*
	 * Now maybe handle debug registers and/or IO bitmaps
	 */
	if (unlikely(task_thread_info(prev_p)->flags & _TIF_WORK_CTXSW_PREV ||
		     task_thread_info(next_p)->flags & _TIF_WORK_CTXSW_NEXT))
		__switch_to_xtra(prev_p, next_p, tss);

	/*
	 * Leave lazy mode, flushing any hypercalls made here.
	 * This must be done before restoring TLS segments so
	 * the GDT and LDT are properly updated, and must be
	 * done before math_state_restore, so the TS bit is up
	 * to date.
	 */
	arch_leave_lazy_cpu_mode();

	/* If the task has used fpu the last 5 timeslices, just do a full
	 * restore of the math state immediately to avoid the trap; the
	 * chances of needing FPU soon are obviously high now
	 */
	if (next_p->fpu_counter > 5)
		math_state_restore();

	/*
	 * Restore %gs if needed (which is common)
	 */
	if (prev->gs | next->gs)
		loadsegment(gs, next->gs);

	x86_write_percpu(current_task, next_p);

	return prev_p;
}

static inline void switch_mm(struct mm_struct *prev,
			     struct mm_struct *next,
			     struct task_struct *tsk)
{
	int cpu = smp_processor_id();

	if (likely(prev != next)) {
		/* stop flush ipis for the previous mm */
		cpu_clear(cpu, prev->cpu_vm_mask);
#ifdef CONFIG_SMP
		per_cpu(cpu_tlbstate, cpu).state = TLBSTATE_OK;
		per_cpu(cpu_tlbstate, cpu).active_mm = next;
#endif
		cpu_set(cpu, next->cpu_vm_mask);

		/* Re-load page tables */
        //将__pa( next->pgd )写入CR3
		load_cr3(next->pgd);

		/*
		 * load the LDT, if the LDT is different:
		 */
		if (unlikely(prev->context.ldt != next->context.ldt))
			load_LDT_nolock(&next->context);
	}
#ifdef CONFIG_SMP
	else {
		per_cpu(cpu_tlbstate, cpu).state = TLBSTATE_OK;
		BUG_ON(per_cpu(cpu_tlbstate, cpu).active_mm != next);

        //之前是一个内核线程在跑，，用了A进程的mm然后还进了lazy，现在换成A进程
        //如果不换，里面是swaper_dir啥的
		if (!cpu_test_and_set(cpu, next->cpu_vm_mask)) {
			/* We were in lazy tlb mode and leave_mm disabled 
			 * tlb flush IPI delivery. We must reload %cr3.
			 */
			load_cr3(next->pgd);
			load_LDT_nolock(&next->context);
		}
	}
#endif
}

个人理解,mm->cpu_vm_mask表示当前使用这个mm的位掩码，
核间中断的第一次中断还是会执行刷新，但是是调用的leave_mm
