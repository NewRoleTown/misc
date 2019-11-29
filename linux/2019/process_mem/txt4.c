MAP_PRIVATE创建一个与数据源分离的私有映射，写入不影响文件
MAP_ANONYMOUS创建与数据源无关的映射,malloc用

asmlinkage long sys_mmap2(unsigned long addr, unsigned long len,
			  unsigned long prot, unsigned long flags,
			  unsigned long fd, unsigned long pgoff)
{
	int error = -EBADF;
	struct file *file = NULL;
	struct mm_struct *mm = current->mm;

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);
	if (!(flags & MAP_ANONYMOUS)) {
		file = fget(fd);
		if (!file)
			goto out;
	}

	down_write(&mm->mmap_sem);
	error = do_mmap_pgoff(file, addr, len, prot, flags, pgoff);
	up_write(&mm->mmap_sem);

	if (file)
		fput(file);
out:
	return error;
}

unsigned long do_mmap_pgoff(struct file * file, unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long flags, unsigned long pgoff)
{
	struct mm_struct * mm = current->mm;
	struct inode *inode;
	unsigned int vm_flags;
	int error;
	int accountable = 1;
	unsigned long reqprot = prot;

	//可读表可执行相关设置
	if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
		if (!(file && (file->f_path.mnt->mnt_flags & MNT_NOEXEC)))
			prot |= PROT_EXEC;

	if (!len)
		return -EINVAL;

	if (!(flags & MAP_FIXED))
		addr = round_hint_to_min(addr);

	//一些长度,可映射区域数量判断

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	addr = get_unmapped_area(file, addr, len, pgoff, flags);

	//没对齐的地址
	if (addr & ~PAGE_MASK)
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	if (flags & MAP_LOCKED) {
		if (!can_do_mlock())
			return -EPERM;
		vm_flags |= VM_LOCKED;
	}
	...
	inode = file ? file->f_path.dentry->d_inode : NULL;

	//映射源自文件(非anon)
	if (file) {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			//文件不让写
			if ((prot&PROT_WRITE) && !(file->f_mode&FMODE_WRITE))
				return -EACCES;

			/*
			 * Make sure we don't allow writing to an append-only
			 * file..
			 */
			if (IS_APPEND(inode) && (file->f_mode & FMODE_WRITE))
				return -EACCES;

			/*
			 * Make sure there are no mandatory locks on the file.
			 */
			if (locks_verify_locked(inode))
				return -EAGAIN;

			vm_flags |= VM_SHARED | VM_MAYSHARE;
			if (!(file->f_mode & FMODE_WRITE))
				vm_flags &= ~(VM_MAYWRITE | VM_SHARED);

			/* fall through */
		case MAP_PRIVATE:
			//文件不给读
			if (!(file->f_mode & FMODE_READ))
				return -EACCES;
			//不给执行
			if (file->f_path.mnt->mnt_flags & MNT_NOEXEC) {
				if (vm_flags & VM_EXEC)
					return -EPERM;
				vm_flags &= ~VM_MAYEXEC;
			}
			if (is_file_hugepages(file))
				accountable = 0;

			if (!file->f_op || !file->f_op->mmap)
				return -ENODEV;
			break;

		default:
			return -EINVAL;
		}
	} else {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			vm_flags |= VM_SHARED | VM_MAYSHARE;
			break;
		case MAP_PRIVATE:
			/*
			 * Set pgoff according to addr for anon_vma.
			 */
			pgoff = addr >> PAGE_SHIFT;
			break;
		default:
			return -EINVAL;
		}
	}

	if (error)
		return error;

	return mmap_region(file, addr, len, flags, vm_flags, pgoff,
			   accountable);
}

vma->vm_ops = &generic_file_vm_ops

unsigned long mmap_region(struct file *file, unsigned long addr,
			  unsigned long len, unsigned long flags,
			  unsigned int vm_flags, unsigned long pgoff,
			  int accountable)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev;
	int correct_wcount = 0;
	int error;
	struct rb_node **rb_link, *rb_parent;
	unsigned long charged = 0;
	struct inode *inode =  file ? file->f_path.dentry->d_inode : NULL;

	/* Clear old maps */
	error = -ENOMEM;
munmap_back:
	//vma返回的是首个结束为止大于addr的区域
	vma = find_vma_prepare(mm, addr, &prev, &rb_link, &rb_parent);
	if (vma && vma->vm_start < addr + len) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
		goto munmap_back;
	}

	/* Check against address space limit. */
	if (!may_expand_vm(mm, len >> PAGE_SHIFT))
		return -ENOMEM;

	...
	/*
	 * Can we just expand an old private anonymous mapping?
	 * The VM_SHARED test is necessary because shmem_zero_setup
	 * will create the file object for a shared anonymous map below.
	 */
	if (!file && !(vm_flags & VM_SHARED) &&
	    vma_merge(mm, prev, addr, addr + len, vm_flags,
					NULL, NULL, pgoff, NULL))
		goto out;

	/*
	 * Determine the object being mapped and call the appropriate
	 * specific mapper. the address has already been validated, but
	 * not unmapped, but the maps are removed from the list.
	 */
	vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma) {
		error = -ENOMEM;
		goto unacct_error;
	}

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
	vma->vm_page_prot = vm_get_page_prot(vm_flags);
	vma->vm_pgoff = pgoff;

	if (file) {
		error = -EINVAL;
		if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
			goto free_vma;
		...
		vma->vm_file = file;
		get_file(file);
		error = file->f_op->mmap(file, vma);
		if (error)
			goto unmap_and_free_vma;
	} else if (vm_flags & VM_SHARED) {
		error = shmem_zero_setup(vma);
		if (error)
			goto free_vma;
	}

	...
	//注释
	/* Can addr have changed??
	 *
	 * Answer: Yes, several device drivers can do it in their
	 *         f_op->mmap method. -DaveM
	 */
	addr = vma->vm_start;
	pgoff = vma->vm_pgoff;
	vm_flags = vma->vm_flags;

	if (vma_wants_writenotify(vma))
		vma->vm_page_prot = vm_get_page_prot(vm_flags & ~VM_SHARED);

	if (!file || !vma_merge(mm, prev, addr, vma->vm_end,
			vma->vm_flags, NULL, file, pgoff, vma_policy(vma))) {
		file = vma->vm_file;
		vma_link(mm, vma, prev, rb_link, rb_parent);
		if (correct_wcount)
			atomic_inc(&inode->i_writecount);
	} else {
		//不是文件且合并成功
		if (file) {
			if (correct_wcount)
				atomic_inc(&inode->i_writecount);
			fput(file);
		}
		mpol_free(vma_policy(vma));
		kmem_cache_free(vm_area_cachep, vma);
	}
out:	
	mm->total_vm += len >> PAGE_SHIFT;
	vm_stat_account(mm, vm_flags, file, len >> PAGE_SHIFT);
	if (vm_flags & VM_LOCKED) {
		mm->locked_vm += len >> PAGE_SHIFT;
		make_pages_present(addr, addr + len);
	}
	if ((flags & MAP_POPULATE) && !(flags & MAP_NONBLOCK))
		make_pages_present(addr, addr + len);
	return addr;

unmap_and_free_vma:
	if (correct_wcount)
		atomic_inc(&inode->i_writecount);
	vma->vm_file = NULL;
	fput(file);

	/* Undo any partial mapping done by a device driver. */
	unmap_region(mm, vma, prev, vma->vm_start, vma->vm_end);
	charged = 0;
	...
	return error;
}


int make_pages_present(unsigned long addr, unsigned long end)
{
	...
	ret = get_user_pages(current, current->mm, addr,
			len, write, 0, NULL, NULL);
	...
}

//len以页为单位
int get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, int len, int write, int force,
		struct page **pages, struct vm_area_struct **vmas)
{
	int i;
	unsigned int vm_flags;

	/* 
	 * Require read or write permissions.
	 * If 'force' is set, we only require the "MAY" flags.
	 */
	vm_flags  = write ? (VM_WRITE | VM_MAYWRITE) : (VM_READ | VM_MAYREAD);
	vm_flags &= force ? (VM_MAYREAD | VM_MAYWRITE) : (VM_READ | VM_WRITE);
	i = 0;

	do {
		struct vm_area_struct *vma;
		unsigned int foll_flags;

		vma = find_extend_vma(mm, start);
		if (!vma && in_gate_area(tsk, start)) {
			...
		}

		...

		foll_flags = FOLL_TOUCH;
		if (pages)
			foll_flags |= FOLL_GET;
		if (!write && !(vma->vm_flags & VM_LOCKED) &&
		    (!vma->vm_ops || (!vma->vm_ops->nopage &&
					!vma->vm_ops->fault)))
			foll_flags |= FOLL_ANON;

		do {
			struct page *page;

			/*
			 * If tsk is ooming, cut off its access to large memory
			 * allocations. It has a pending SIGKILL, but it can't
			 * be processed until returning to user space.
			 */
			if (unlikely(test_tsk_thread_flag(tsk, TIF_MEMDIE)))
				return -ENOMEM;

			if (write)
				foll_flags |= FOLL_WRITE;

			cond_resched();
			//*********************************************
			while (!(page = follow_page(vma, start, foll_flags))) {
				int ret;
				ret = handle_mm_fault(mm, vma, start,
						foll_flags & FOLL_WRITE);
				if (ret & VM_FAULT_ERROR) {
					if (ret & VM_FAULT_OOM)
						return i ? i : -ENOMEM;
					else if (ret & VM_FAULT_SIGBUS)
						return i ? i : -EFAULT;
					BUG();
				}
				if (ret & VM_FAULT_MAJOR)
					tsk->maj_flt++;
				else
					tsk->min_flt++;

				/*
				 * The VM_FAULT_WRITE bit tells us that
				 * do_wp_page has broken COW when necessary,
				 * even if maybe_mkwrite decided not to set
				 * pte_write. We can thus safely do subsequent
				 * page lookups as if they were reads.
				 */
				if (ret & VM_FAULT_WRITE)
					foll_flags &= ~FOLL_WRITE;

				cond_resched();
			}
			if (pages) {
				pages[i] = page;

				flush_anon_page(vma, page, start);
				flush_dcache_page(page);
			}
			if (vmas)
				vmas[i] = vma;
			i++;
			start += PAGE_SIZE;
			len--;
		} while (len && start < vma->vm_end);
	} while (len);
	return i;
}


struct page *follow_page(struct vm_area_struct *vma, unsigned long address,
			unsigned int flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

	page = follow_huge_addr(mm, address, flags & FOLL_WRITE);
	if (!IS_ERR(page)) {
		BUG_ON(flags & FOLL_GET);
		goto out;
	}

	page = NULL;
	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		goto no_page_table;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto no_page_table;
	
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		goto no_page_table;

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (!ptep)
		goto out;

	pte = *ptep;
	if (!pte_present(pte))
		goto unlock;
	if ((flags & FOLL_WRITE) && !pte_write(pte))
		goto unlock;
	page = vm_normal_page(vma, address, pte);
	if (unlikely(!page))
		goto unlock;

	if (flags & FOLL_GET)
		get_page(page);
	if (flags & FOLL_TOUCH) {
		if ((flags & FOLL_WRITE) &&
		    !pte_dirty(pte) && !PageDirty(page))
			set_page_dirty(page);
		mark_page_accessed(page);
	}
unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	return page;

no_page_table:
	/*
	 * When core dumping an enormous anonymous area that nobody
	 * has touched so far, we don't want to allocate page tables.
	 */
	if (flags & FOLL_ANON) {
		page = ZERO_PAGE(0);
		if (flags & FOLL_GET)
			get_page(page);
		BUG_ON(flags & FOLL_WRITE);
	}
	return page;
}
