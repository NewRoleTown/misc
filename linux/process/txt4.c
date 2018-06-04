
asmlinkage void __sched schedule(void)
{
	struct task_struct *prev, *next;
	long *switch_count;
	struct rq *rq;
	int cpu;

need_resched:
    //�ر���ռ
	preempt_disable();
	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	rcu_qsctr_inc(cpu);
    //prevΪ��ǰ����
	prev = rq->curr;
    //ָ��Ǳ������л���
	switch_count = &prev->nivcsw;

    //�ͷŴ��ں���
    //depth >= 0 ˵�����������ͷ�ȫ����kernel_sem
	release_kernel_lock(prev);
need_resched_nonpreemptible:

	schedule_debug(prev);

	/*
	 * Do the rq-clock update outside the rq lock:
	 */
    //���ж�
	local_irq_disable();
	__update_rq_clock(rq);
	spin_lock(&rq->lock);
    //��TIF_NEED_SCHED
	clear_tsk_need_resched(prev);

    //�����ǰ״̬����running�Ҳ��Ǳ���ռ
	if (prev->state && !(preempt_count() & PREEMPT_ACTIVE)) {
        //���жϵȴ�̬�����ź�
		if (unlikely((prev->state & TASK_INTERRUPTIBLE) &&
				unlikely(signal_pending(prev)))) {
			prev->state = TASK_RUNNING;
		} else {
            //����
			deactivate_task(rq, prev, 1);
		}
        //�Ǳ���,��Ը�˳�
		switch_count = &prev->nvcsw;
	}

	if (unlikely(!rq->nr_running))
		idle_balance(cpu, rq);

	prev->sched_class->put_prev_task(rq, prev);
	next = pick_next_task(rq, prev);

	sched_info_switch(prev, next);

	if (likely(prev != next)) {
        //���е��л���+1
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

TLBΪ�˼ӿ� MMU �������ַ��ת�������ӵĻ��棬����¼��һ�������ַ��Ӧ���ڴ�ҳ�������ַ����ʵ���Ǹ��������ַ��ǰ 20 λ��������һ������Ŀ����Ӧ��¼ͨ������ҳ������¼���ڴ�ҳ�������ַ�� 
��Ȼ�л��棬��ô����������ݸı�ʱ�����漰�������ˢ�£����� TLB ��ˢ�����⣬��һ��ҳ��ṹ�����仯ʱ��ʹ�ø�ҳ��ڹ��� CPU ��Ӧ��ˢ���Լ��� TLB��
�⽫����һЩ���⣬���磬��ĳһ���� CPU0 �մ�һ�û������л����ں˽��̣����ں˽������ø��û����̵ĵ�ַ�ռ䣬����ֻ�����ں˿ռ䲿�֣��ⲻ�������⣬Ȼ����������û�������CPU1 ���ϱ����ȣ������� CPU0 �����ĵ�ַ�ռ�ʱ������ CPU1 ���޸����Լ��ں˿ռ��ҳ����ʱ���� CPU0 ����������ĵ�ַ�ռ��Ƿǳ�Σ�յģ������Ǳ�����ĵ�ַ����δ������ĵ�ַ�������ܴ������벻�������غ����
        ��ô���ѵ��������õ������Ҫ�����������ķ�����ɱ����ÿ�ζ�Ҫˢ�� TLB�����¼���ҳ��ô����Ȼ�����в��Ȱ취�ģ������ CPU0 �ϵ��ں˽���ִ���ڼ䣬�������õ��û����̵ĵ�ַ�ռ�û�б����Ȳ�ִ����ϵ�������Ƿǳ���ģ����ֲ�ˢ�� TLB �����������������ǿ�������һ�µģ�˭�� Linux ��һ������ϸ����ں��ء�
        ��ΰ쵽��һ�㣬��ʵ�ܼ򵥣����ں˿ռ�ҳ�������� CPU �ϸ���ʱ������� flush_tlb_all��������ÿ�� CPU ȥˢ���Լ��� TLB��

        ��ô���û��ռ��ҳ�������� CPU �ϸ���ʱ������ CPU0 ��Ȼ��������ͬ�ĵ�ַ�ռ䣬����������һ���ں˽��̣�������ȥ�����û��ռ�ĵ�ַ����ô����ЩʧЧ�� TLB ��Ҳ�������Σ�գ�Ҳ���������Բ�ȥ����ˢ�� TLB�����Դ�ʱ������ CPU �����ᷢ��һ�� IPI ���������øõ�ַ�ռ�� CPU����֪ͨ�����Լ��������û��ռ��ҳ������  CPU �ͻ�����Լ���״̬������Ӧ�Ĵ������������ģʽ���Ͳ���ˢ�� TLB��

        ��������� TLB ˢ�µ�����ģʽ��

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
        //�л����ں��߳�
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

//ѹ������һ�����̵�eipȻ��jmp��__switch_to������jmp�󷵻ص���һ������
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
    //ss1������SYSENTER��cache
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
    //������޸�gs�ε����ݣ�����л��߳�,gs���䣬gs���ݱ�
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
        //��__pa( next->pgd )д��CR3
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

        //֮ǰ��һ���ں��߳����ܣ�������A���̵�mmȻ�󻹽���lazy�����ڻ���A����
        //���������������swaper_dirɶ��
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

�������,mm->cpu_vm_mask��ʾ��ǰʹ�����mm��λ���룬
�˼��жϵĵ�һ���жϻ��ǻ�ִ��ˢ�£������ǵ��õ�leave_mm
