/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * error_code:
 *	bit 0 == 0 means no page found, 1 means protection fault
 *	bit 1 == 0 means read, 1 means write
 *	bit 2 == 0 means kernel, 1 means user-mode
 *	bit 3 == 1 means use of reserved bit detected
 *	bit 4 == 1 means fault was an instruction fetch
 */
fastcall void __kprobes do_page_fault(struct pt_regs *regs,
				      unsigned long error_code)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct * vma;
	unsigned long address;
	int write, si_code;
	int fault;

	/*
	 * We can fault from pretty much anywhere, with unknown IRQ state.
	 */
	trace_hardirqs_fixup();

	/* get the address */
    //获取触发异常的地址
        address = read_cr2();

	tsk = current;

	si_code = SEGV_MAPERR;

    //可能在中断中，所以不能上锁
	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 *
	 * This verifies that the fault happens in kernel space
	 * (error_code & 4) == 0, and that the fault was not a
	 * protection error (error_code & 9) == 0.
	 */
	if (unlikely(address >= TASK_SIZE)) {
        //vmalloc延迟分配导致的错误被修复
		if (!(error_code & 0x0000000d) && vmalloc_fault(address) >= 0)
			return;
		if (notify_page_fault(regs))
			return;
		/*
		 * Don't take the mm semaphore here. If we fixup a prefetch
		 * fault we could otherwise deadlock.
		 */
		goto bad_area_nosemaphore;
	}

	if (notify_page_fault(regs))
		return;

	/* It's safe to allow irq's after cr2 has been saved and the vmalloc
	   fault has been handled. */
    //cr2保存后可以开中断了
	if (regs->eflags & (X86_EFLAGS_IF|VM_MASK))
		local_irq_enable();

	mm = tsk->mm;

	/*
	 * If we're in an interrupt, have no user context or are running in an
	 * atomic region then we must not take the fault..
	 */
    //在中断里面
	if (in_atomic() || !mm)
		goto bad_area_nosemaphore;

	/* When running in the kernel we expect faults to occur only to
	 * addresses in user space.  All other faults represent errors in the
	 * kernel and should generate an OOPS.  Unfortunately, in the case of an
	 * erroneous fault occurring in a code path which already holds mmap_sem
	 * we will deadlock attempting to validate the fault against the
	 * address space.  Luckily the kernel only validly references user
	 * space from well defined areas of code, which are listed in the
	 * exceptions table.
	 *
	 * As the vast majority of faults will be valid we will only perform
	 * the source reference check when there is a possibility of a deadlock.
	 * Attempt to lock the address space, if we cannot we then validate the
	 * source.  If this is invalid we can skip the address space check,
	 * thus avoiding the deadlock.
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		if ((error_code & 4) == 0 &&
		    !search_exception_tables(regs->eip))
			goto bad_area_nosemaphore;
		down_read(&mm->mmap_sem);
	}
    //寻找对应的vma
	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
    //既没有包含的vma，也不是栈扩展，则bad
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
    //栈扩展相关
	if (error_code & 4) {
		/*
		 * Accessing the stack below %esp is always a bug.
		 * The large cushion allows instructions like enter
		 * and pusha to work.  ("enter $65535,$31" pushes
		 * 32 pointers and then decrements %esp by 65535.)
		 */
		if (address + 65536 + 32 * sizeof(unsigned long) < regs->esp)
			goto bad_area;
	}
	if (expand_stack(vma, address))
		goto bad_area;
 //*	bit 0 == 0 means no page found, 1 means protection fault
 //*	bit 1 == 0 means read, 1 means write
 //*	bit 2 == 0 means kernel, 1 means user-mode
good_area:
	si_code = SEGV_ACCERR;
	write = 0;
	switch (error_code & 3) {
		default:	/* 3: 写，不缺页 */
				/* fall through */
		case 2:		/* 写，缺页*/
			if (!(vma->vm_flags & VM_WRITE))
				goto bad_area;
			write++;
			break;
		case 1:		/* 读，不缺页 */
			goto bad_area;
		case 0:		/* 读，缺页 */
			if (!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE)))
				goto bad_area;
	}

 survive:
	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
	fault = handle_mm_fault(mm, vma, address, write);
	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}
	if (fault & VM_FAULT_MAJOR)
		tsk->maj_flt++;
	else
		tsk->min_flt++;

	/*
	 * Did it hit the DOS screen memory VA from vm86 mode?
	 */
	if (regs->eflags & VM_MASK) {
		unsigned long bit = (address - 0xA0000) >> PAGE_SHIFT;
		if (bit < 32)
			tsk->thread.screen_bitmap |= 1 << bit;
	}
	up_read(&mm->mmap_sem);
	return;

/*
 * Something tried to access memory that isn't in our memory map..
 * Fix it, but check if it's kernel or user first..
 */
bad_area:
	up_read(&mm->mmap_sem);

bad_area_nosemaphore:
	/* User mode accesses just cause a SIGSEGV */
	if (error_code & 4) {
        //用户模式,段错误杀死
		local_irq_enable();
		/* 
		 * Valid to do another page fault here because this one came 
		 * from user space.
		 */
		if (is_prefetch(regs, address, error_code))
			return;

		if (show_unhandled_signals && unhandled_signal(tsk, SIGSEGV) &&
		    printk_ratelimit()) {
			printk("%s%s[%d]: segfault at %08lx eip %08lx "
			    "esp %08lx error %lx\n",
			    task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
			    tsk->comm, task_pid_nr(tsk), address, regs->eip,
			    regs->esp, error_code);
		}
		tsk->thread.cr2 = address;
		/* Kernel addresses are always protection faults */
		tsk->thread.error_code = error_code | (address >= TASK_SIZE);
		tsk->thread.trap_no = 14;
		force_sig_info_fault(SIGSEGV, si_code, address, tsk);
		return;
	}

#ifdef CONFIG_X86_F00F_BUG
	/*
	 * Pentium F0 0F C7 C8 bug workaround.
	 */
	if (boot_cpu_data.f00f_bug) {
		unsigned long nr;
		
		nr = (address - idt_descr.address) >> 3;

		if (nr == 6) {
			do_invalid_op(regs, 0);
			return;
		}
	}
#endif

no_context:
	/* Are we prepared to handle this kernel fault?  */
	if (fixup_exception(regs))
		return;

	/* 
	 * Valid to do another page fault here, because if this fault
	 * had been triggered by is_prefetch fixup_exception would have 
	 * handled it.
	 */
 	if (is_prefetch(regs, address, error_code))
 		return;

/*
 * Oops. The kernel tried to access some bad page. We'll have to
 * terminate things with extreme prejudice.
 */

	bust_spinlocks(1);

	if (oops_may_print()) {
		__typeof__(pte_val(__pte(0))) page;

#ifdef CONFIG_X86_PAE
		if (error_code & 16) {
			pte_t *pte = lookup_address(address);

			if (pte && pte_present(*pte) && !pte_exec_kernel(*pte))
				printk(KERN_CRIT "kernel tried to execute "
					"NX-protected page - exploit attempt? "
					"(uid: %d)\n", current->uid);
		}
#endif
		if (address < PAGE_SIZE)
			printk(KERN_ALERT "BUG: unable to handle kernel NULL "
					"pointer dereference");
		else
			printk(KERN_ALERT "BUG: unable to handle kernel paging"
					" request");
		printk(" at virtual address %08lx\n",address);
		printk(KERN_ALERT "printing eip: %08lx ", regs->eip);

		page = read_cr3();
		page = ((__typeof__(page) *) __va(page))[address >> PGDIR_SHIFT];
#ifdef CONFIG_X86_PAE
		printk("*pdpt = %016Lx ", page);
		if ((page >> PAGE_SHIFT) < max_low_pfn
		    && page & _PAGE_PRESENT) {
			page &= PAGE_MASK;
			page = ((__typeof__(page) *) __va(page))[(address >> PMD_SHIFT)
			                                         & (PTRS_PER_PMD - 1)];
			printk(KERN_CONT "*pde = %016Lx ", page);
			page &= ~_PAGE_NX;
		}
#else
		printk("*pde = %08lx ", page);
#endif

		/*
		 * We must not directly access the pte in the highpte
		 * case if the page table is located in highmem.
		 * And let's rather not kmap-atomic the pte, just in case
		 * it's allocated already.
		 */
		if ((page >> PAGE_SHIFT) < max_low_pfn
		    && (page & _PAGE_PRESENT)
		    && !(page & _PAGE_PSE)) {
			page &= PAGE_MASK;
			page = ((__typeof__(page) *) __va(page))[(address >> PAGE_SHIFT)
			                                         & (PTRS_PER_PTE - 1)];
			printk("*pte = %0*Lx ", sizeof(page)*2, (u64)page);
		}

		printk("\n");
	}

	tsk->thread.cr2 = address;
	tsk->thread.trap_no = 14;
	tsk->thread.error_code = error_code;
	die("Oops", regs, error_code);
	bust_spinlocks(0);
	do_exit(SIGKILL);

/*
 * We ran out of memory, or some other thing happened to us that made
 * us unable to handle the page fault gracefully.
 */
out_of_memory:
	up_read(&mm->mmap_sem);
	if (is_global_init(tsk)) {
		yield();
		down_read(&mm->mmap_sem);
		goto survive;
	}
	printk("VM: killing process %s\n", tsk->comm);
	if (error_code & 4)
		do_group_exit(SIGKILL);
	goto no_context;

do_sigbus:
	up_read(&mm->mmap_sem);

	/* Kernel mode? Handle exceptions or die */
	if (!(error_code & 4))
		goto no_context;

	/* User space => ok to do another page fault */
	if (is_prefetch(regs, address, error_code))
		return;

	tsk->thread.cr2 = address;
	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = 14;
	force_sig_info_fault(SIGBUS, BUS_ADRERR, address, tsk);
}



int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, int write_access)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	__set_current_state(TASK_RUNNING);

	count_vm_event(PGFAULT);

	pgd = pgd_offset(mm, address);
	pud = pud_alloc(mm, pgd, address);
	if (!pud)
		return VM_FAULT_OOM;
	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		return VM_FAULT_OOM;
	pte = pte_alloc_map(mm, pmd, address);
	if (!pte)
		return VM_FAULT_OOM;

	return handle_pte_fault(mm, vma, address, pte, pmd, write_access);
}


/*
 * These routines also need to handle stuff like marking pages dirty
 * and/or accessed for architectures that don't do it in hardware (most
 * RISC architectures).  The early dirtying is also good on the i386.
 *
 * There is also a hook called "update_mmu_cache()" that architectures
 * with external mmu caches can use to update those (ie the Sparc or
 * PowerPC hashed page tables that act as extended TLBs).
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), and pte mapped but not yet locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static inline int handle_pte_fault(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long address,
		pte_t *pte, pmd_t *pmd, int write_access)
{
	pte_t entry;
	spinlock_t *ptl;

	entry = *pte;
    //如果页不在内存
	if (!pte_present(entry)) {
        //如果空
		if (pte_none(entry)) {
			if (vma->vm_ops) {
				if (vma->vm_ops->fault || vma->vm_ops->nopage)
                    //dirtycow第一次写的流程
	                //unsigned int flags = (write_access ? FAULT_FLAG_WRITE : 0);
                    //之后进__do_fault
					return do_linear_fault(mm, vma, address,
						pte, pmd, write_access, entry);
				if (unlikely(vma->vm_ops->nopfn))
					return do_no_pfn(mm, vma, address, pte,
							 pmd, write_access);
			}
			return do_anonymous_page(mm, vma, address,
						 pte, pmd, write_access);
		}
        //是否非线性映射
        //#define _PAGE_FILE	0x040	/* nonlinear file mapping, saved PTE; unset:swap */
		if (pte_file(entry))
			return do_nonlinear_fault(mm, vma, address,
					pte, pmd, write_access, entry);
		return do_swap_page(mm, vma, address,
					pte, pmd, write_access, entry);
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (unlikely(!pte_same(*pte, entry)))
		goto unlock;
    //写，但是页表项不可写，进cow
	if (write_access) {
		if (!pte_write(entry))
			return do_wp_page(mm, vma, address,
					pte, pmd, ptl, entry);
		entry = pte_mkdirty(entry);
	}
	entry = pte_mkyoung(entry);
	if (ptep_set_access_flags(vma, address, pte, entry, write_access)) {
		update_mmu_cache(vma, address, entry);
	} else {
		/*
		 * This is needed only for protection faults but the arch code
		 * is not yet telling us if this is a protection fault or not.
		 * This still avoids useless tlb flushes for .text page faults
		 * with threads.
		 */
		if (write_access)
			flush_tlb_page(vma, address);
	}
unlock:
	pte_unmap_unlock(pte, ptl);
	return 0;
}



static int __do_fault(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd,
		pgoff_t pgoff, unsigned int flags, pte_t orig_pte)
{
	pte_t *page_table;
	spinlock_t *ptl;
	struct page *page;
	pte_t entry;
	int anon = 0;
	struct page *dirty_page = NULL;
	struct vm_fault vmf;
	int ret;
	int page_mkwrite = 0;

	vmf.virtual_address = (void __user *)(address & PAGE_MASK);
	vmf.pgoff = pgoff;
	vmf.flags = flags;
	vmf.page = NULL;

	BUG_ON(vma->vm_flags & VM_PFNMAP);

    //先读入所需的数据，fault是新函数，如果不支持，兼容用老的nopage
	if (likely(vma->vm_ops->fault)) {
		ret = vma->vm_ops->fault(vma, &vmf);
		if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))
			return ret;
	} else {
		/* Legacy ->nopage path */
		ret = 0;
		vmf.page = vma->vm_ops->nopage(vma, address & PAGE_MASK, &ret);
		/* no page was available -- either SIGBUS or OOM */
		if (unlikely(vmf.page == NOPAGE_SIGBUS))
			return VM_FAULT_SIGBUS;
		else if (unlikely(vmf.page == NOPAGE_OOM))
			return VM_FAULT_OOM;
	}

	/*
	 * For consistency in subsequent calls, make the faulted page always
	 * locked.
	 */
	if (unlikely(!(ret & VM_FAULT_LOCKED)))
		lock_page(vmf.page);
	else
		VM_BUG_ON(!PageLocked(vmf.page));

	/*
	 * Should we do an early C-O-W break?
	 */
	page = vmf.page;
    //如果是写
	if (flags & FAULT_FLAG_WRITE) {
        //非共享页
		if (!(vma->vm_flags & VM_SHARED)) {
			anon = 1;
			if (unlikely(anon_vma_prepare(vma))) {
				ret = VM_FAULT_OOM;
				goto out;
			}
			page = alloc_page_vma(GFP_HIGHUSER_MOVABLE,
						vma, address);
			if (!page) {
				ret = VM_FAULT_OOM;
				goto out;
			}
			copy_user_highpage(page, vmf.page, address, vma);
		} else {
			/*
			 * If the page will be shareable, see if the backing
			 * address space wants to know that the page is about
			 * to become writable
			 */
			if (vma->vm_ops->page_mkwrite) {
				unlock_page(page);
				if (vma->vm_ops->page_mkwrite(vma, page) < 0) {
					ret = VM_FAULT_SIGBUS;
					anon = 1; /* no anon but release vmf.page */
					goto out_unlocked;
				}
				lock_page(page);
				/*
				 * XXX: this is not quite right (racy vs
				 * invalidate) to unlock and relock the page
				 * like this, however a better fix requires
				 * reworking page_mkwrite locking API, which
				 * is better done later.
				 */
				if (!page->mapping) {
					ret = 0;
					anon = 1; /* no anon but release vmf.page */
					goto out;
				}
				page_mkwrite = 1;
			}
		}

	}

	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);

	/*
	 * This silly early PAGE_DIRTY setting removes a race
	 * due to the bad i386 page protection. But it's valid
	 * for other architectures too.
	 *
	 * Note that if write_access is true, we either now have
	 * an exclusive copy of the page, or this is a shared mapping,
	 * so we can make it writable and dirty to avoid having to
	 * handle that later.
	 */
	/* Only go through if we didn't race with anybody else... */
	if (likely(pte_same(*page_table, orig_pte))) {
		flush_icache_page(vma, page);
		entry = mk_pte(page, vma->vm_page_prot);
		if (flags & FAULT_FLAG_WRITE)
            //dirty情形下，此处不设置可写属性
			entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		set_pte_at(mm, address, page_table, entry);
		if (anon) {
                        inc_mm_counter(mm, anon_rss);
                        lru_cache_add_active(page);
                        //新的匿名映射页
                        page_add_new_anon_rmap(page, vma, address);
		} else {
			inc_mm_counter(mm, file_rss);
			page_add_file_rmap(page);
			if (flags & FAULT_FLAG_WRITE) {
				dirty_page = page;
				get_page(dirty_page);
			}
		}

		/* no need to invalidate: a not-present page won't be cached */
		update_mmu_cache(vma, address, entry);
	} else {
		if (anon)
			page_cache_release(page);
		else
			anon = 1; /* no anon but release faulted_page */
	}

	pte_unmap_unlock(page_table, ptl);

out:
	unlock_page(vmf.page);
out_unlocked:
	if (anon)
		page_cache_release(vmf.page);
	else if (dirty_page) {
		if (vma->vm_file)
			file_update_time(vma->vm_file);

		set_page_dirty_balance(dirty_page, page_mkwrite);
		put_page(dirty_page);
	}

	return ret;
}



/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * Note that this routine assumes that the protection checks have been
 * done by the caller (the low-level page fault routine in most cases).
 * Thus we can safely just mark it writable once we've done any necessary
 * COW.
 *
 * We also mark the page dirty at this point even though the page will
 * change only once the write actually happens. This avoids a few races,
 * and potentially makes it more efficient.
 *
 * We enter with non-exclusive mmap_sem (to exclude vma changes,
 * but allow concurrent faults), with pte both mapped and locked.
 * We return with mmap_sem still held, but pte unmapped and unlocked.
 */
static int do_wp_page(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pte_t *page_table, pmd_t *pmd,
		spinlock_t *ptl, pte_t orig_pte)
{
	struct page *old_page, *new_page;
	pte_t entry;
	int reuse = 0, ret = 0;
	int page_mkwrite = 0;
	struct page *dirty_page = NULL;

    //获取页的实例
	old_page = vm_normal_page(vma, address, orig_pte);
	if (!old_page)
		goto gotten;

	/*
	 * Take out anonymous pages first, anonymous shared vmas are
	 * not dirty accountable.
	 */
	if (PageAnon(old_page)) {
		if (!TestSetPageLocked(old_page)) {
			reuse = can_share_swap_page(old_page);
			unlock_page(old_page);
		}
	} else if (unlikely((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
					(VM_WRITE|VM_SHARED))) {
		/*
		 * Only catch write-faults on shared writable pages,
		 * read-only shared pages can get COWed by
		 * get_user_pages(.write=1, .force=1).
		 */
		if (vma->vm_ops && vma->vm_ops->page_mkwrite) {
			/*
			 * Notify the address space that the page is about to
			 * become writable so that it can prohibit this or wait
			 * for the page to get into an appropriate state.
			 *
			 * We do this without the lock held, so that it can
			 * sleep if it needs to.
			 */
			page_cache_get(old_page);
			pte_unmap_unlock(page_table, ptl);

			if (vma->vm_ops->page_mkwrite(vma, old_page) < 0)
				goto unwritable_page;

			/*
			 * Since we dropped the lock we need to revalidate
			 * the PTE as someone else may have changed it.  If
			 * they did, we just return, as we can count on the
			 * MMU to tell us if they didn't also make it writable.
			 */
			page_table = pte_offset_map_lock(mm, pmd, address,
							 &ptl);
			page_cache_release(old_page);
			if (!pte_same(*page_table, orig_pte))
				goto unlock;

			page_mkwrite = 1;
		}
		dirty_page = old_page;
		get_page(dirty_page);
		reuse = 1;
	}

	if (reuse) {
		flush_cache_page(vma, address, pte_pfn(orig_pte));
		entry = pte_mkyoung(orig_pte);
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		if (ptep_set_access_flags(vma, address, page_table, entry,1))
			update_mmu_cache(vma, address, entry);
		ret |= VM_FAULT_WRITE;
		goto unlock;
	}

	/*
	 * Ok, we need to copy. Oh, well..
	 */
	page_cache_get(old_page);
gotten:
	pte_unmap_unlock(page_table, ptl);

    //分配anon_vma链表
	if (unlikely(anon_vma_prepare(vma)))
		goto oom;
	VM_BUG_ON(old_page == ZERO_PAGE(0));
	new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);
	if (!new_page)
		goto oom;
	cow_user_page(new_page, old_page, address, vma);

	/*
	 * Re-check the pte - we dropped the lock
	 */
	page_table = pte_offset_map_lock(mm, pmd, address, &ptl);

	if (likely(pte_same(*page_table, orig_pte))) {
		if (old_page) {
			page_remove_rmap(old_page, vma);
			if (!PageAnon(old_page)) {
				dec_mm_counter(mm, file_rss);
				inc_mm_counter(mm, anon_rss);
			}
		} else
			inc_mm_counter(mm, anon_rss);
		flush_cache_page(vma, address, pte_pfn(orig_pte));
		entry = mk_pte(new_page, vma->vm_page_prot);
		entry = maybe_mkwrite(pte_mkdirty(entry), vma);
		/*
		 * Clear the pte entry and flush it first, before updating the
		 * pte with the new entry. This will avoid a race condition
		 * seen in the presence of one thread doing SMC and another
		 * thread doing COW.
		 */
		ptep_clear_flush(vma, address, page_table);
		set_pte_at(mm, address, page_table, entry);
		update_mmu_cache(vma, address, entry);
		lru_cache_add_active(new_page);
        //这里并没有脱链操作，我的想法是在page_referenced遍历中再判断是否该vma和page匹配
        //真的可怕
		page_add_new_anon_rmap(new_page, vma, address);

		/* Free the old page.. */
		new_page = old_page;
		ret |= VM_FAULT_WRITE;
	}
	if (new_page)
		page_cache_release(new_page);
	if (old_page)
		page_cache_release(old_page);
unlock:
	pte_unmap_unlock(page_table, ptl);
	if (dirty_page) {
		if (vma->vm_file)
			file_update_time(vma->vm_file);

		/*
		 * Yes, Virginia, this is actually required to prevent a race
		 * with clear_page_dirty_for_io() from clearing the page dirty
		 * bit after it clear all dirty ptes, but before a racing
		 * do_wp_page installs a dirty pte.
		 *
		 * do_no_page is protected similarly.
		 */
		wait_on_page_locked(dirty_page);
		set_page_dirty_balance(dirty_page, page_mkwrite);
		put_page(dirty_page);
	}
	return ret;
oom:
	if (old_page)
		page_cache_release(old_page);
	return VM_FAULT_OOM;

unwritable_page:
	page_cache_release(old_page);
	return VM_FAULT_SIGBUS;
}


int anon_vma_prepare(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	might_sleep();
	if (unlikely(!anon_vma)) {
		struct mm_struct *mm = vma->vm_mm;
		struct anon_vma *allocated, *locked;

		anon_vma = find_mergeable_anon_vma(vma);
		if (anon_vma) {
			allocated = NULL;
			locked = anon_vma;
			spin_lock(&locked->lock);
		} else {
			anon_vma = anon_vma_alloc();
			if (unlikely(!anon_vma))
				return -ENOMEM;
			allocated = anon_vma;
			locked = NULL;
		}

		/* page_table_lock to protect against threads */
		spin_lock(&mm->page_table_lock);
		if (likely(!vma->anon_vma)) {
			vma->anon_vma = anon_vma;
			list_add_tail(&vma->anon_vma_node, &anon_vma->head);
			allocated = NULL;
		}
		spin_unlock(&mm->page_table_lock);

		if (locked)
			spin_unlock(&locked->lock);
		if (unlikely(allocated))
			anon_vma_free(allocated);
	}
	return 0;
}
