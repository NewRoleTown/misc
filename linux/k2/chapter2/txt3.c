
struct linux_binprm{
    //可执行文件开头128字节
	char buf[BINPRM_BUF_SIZE];
#ifdef CONFIG_MMU
    //栈对应的VMA
	struct vm_area_struct *vma;
#else
# define MAX_ARG_PAGES	32
	struct page *page[MAX_ARG_PAGES];
#endif
	struct mm_struct *mm;
    //在初始化时，设为3G-sizeof(void*)，其vma大小为1页
	unsigned long p; /* current top of mem */
	int sh_bang;
    //待执行文件
	struct file * file;
	int e_uid, e_gid;
	kernel_cap_t cap_inheritable, cap_permitted;
	bool cap_effective;
	void *security;
	int argc, envc;
	char * filename;	/* Name of binary as seen by procps */
	char * interp;		/* Name of the binary really executed. Most
				   of the time same as filename, but could be
				   different for binfmt_{misc,script} */
	unsigned interp_flags;
	unsigned interp_data;
	unsigned long loader, exec;
	unsigned long argv_len;
};


//描述可执行程序类型结构
struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *, struct  pt_regs * regs);
	int (*load_shlib)(struct file *);
	int (*core_dump)(long signr, struct pt_regs *regs, struct file *file, unsigned long limit);
	unsigned long min_coredump;	/* minimal dump size */
	int hasvdso;
};

static struct linux_binfmt elf_format = {
		.module		= THIS_MODULE,
		.load_binary	= load_elf_binary,
		.load_shlib	= load_elf_library,
		.core_dump	= elf_core_dump,
		.min_coredump	= ELF_EXEC_PAGESIZE,
		.hasvdso	= 1
};



elf对应fs/binfmt_elf.c

早期linux-2.4中直接由do_execve实现程序的加载和运行
linux-3.18引入execveat之前do_execve调用do_execve_common来完成程序的加载和运行
linux-3.19~至今引入execveat之后do_execve调用do_execveat_common来完成程序的加载和运行


struct exec
{
	unsigned int a_info;	/* Use macros N_MAGIC, etc for access */
	unsigned a_text;	/* length of text, in bytes */
	unsigned a_data;	/* length of data, in bytes */
	unsigned a_bss;		/* length of uninitialized data area for file, in bytes */
	unsigned a_syms;	/* length of symbol table data in file, in bytes */
	unsigned a_entry;	/* start address */
	unsigned a_trsize;	/* length of relocation info for text, in bytes */
	unsigned a_drsize;	/* length of relocation info for data, in bytes */
};


static int load_elf_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	struct file *interpreter = NULL; /* to shut gcc up */
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * elf_interpreter = NULL;
	unsigned int interpreter_type = INTERPRETER_NONE;
	unsigned char ibcs2_interpreter = 0;
	unsigned long error;
	struct elf_phdr *elf_ppnt, *elf_phdata;
	unsigned long elf_bss, elf_brk;
	int elf_exec_fileno;
	int retval, i;
	unsigned int size;
	unsigned long elf_entry, interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc = 0;
	char passed_fileno[6];
	struct files_struct *files;
	int executable_stack = EXSTACK_DEFAULT;
	unsigned long def_flags = 0;
	struct {
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
  		struct exec interp_ex;
	} *loc;

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}
	
	/* Get the exec-header */
    //将开头部分拷到loc
	loc->elf_ex = *((struct elfhdr *)bprm->buf);

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
    //判断elf魔数
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;
    //可执行或动态库
	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(&loc->elf_ex))
		goto out;
	if (!bprm->file->f_op||!bprm->file->f_op->mmap)
		goto out;

	/* Now read in all of the header information */
	if (loc->elf_ex.e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (loc->elf_ex.e_phnum < 1 ||
	 	loc->elf_ex.e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;
    //程序头表的大小
	size = loc->elf_ex.e_phnum * sizeof(struct elf_phdr);
	retval = -ENOMEM;
	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	retval = kernel_read(bprm->file, loc->elf_ex.e_phoff,
			     (char *)elf_phdata, size);
	if (retval != size) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_ph;
	}

	files = current->files;	/* Refcounted so ok */
	retval = unshare_files();
	if (retval < 0)
		goto out_free_ph;
	if (files == current->files) {
		put_files_struct(files);
		files = NULL;
	}

	/* exec will make our files private anyway, but for the a.out
	   loader stuff we need to do it earlier */
	retval = get_unused_fd();
	if (retval < 0)
		goto out_free_fh;
	get_file(bprm->file);
	fd_install(elf_exec_fileno = retval, bprm->file);

    //程序头表
	elf_ppnt = elf_phdata;
	elf_bss = 0;
	elf_brk = 0;

    //血坑,start_code初始为0xffffffff
	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

    //循环解析程序头表
	for (i = 0; i < loc->elf_ex.e_phnum; i++) {
        //寻找解释器段
		if (elf_ppnt->p_type == PT_INTERP) {

			retval = -ENOEXEC;
			if (elf_ppnt->p_filesz > PATH_MAX || 
			    elf_ppnt->p_filesz < 2)
				goto out_free_file;

			retval = -ENOMEM;
			elf_interpreter = kmalloc(elf_ppnt->p_filesz,
						  GFP_KERNEL);
			if (!elf_interpreter)
				goto out_free_file;
            //将解释器段的内容读入内核缓冲
            //这个段里面只是存了一个字符串,为解释器的路径
			retval = kernel_read(bprm->file, elf_ppnt->p_offset,
					     elf_interpreter,
					     elf_ppnt->p_filesz);
			if (retval != elf_ppnt->p_filesz) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_interp;
			}
			/* make sure path is NULL terminated */
			retval = -ENOEXEC;
			if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0')
				goto out_free_interp;

			/* If the program interpreter is one of these two,
			 * then assume an iBCS2 image. Otherwise assume
			 * a native linux image.
			 */
			if (strcmp(elf_interpreter,"/usr/lib/libc.so.1") == 0 ||
			    strcmp(elf_interpreter,"/usr/lib/ld.so.1") == 0)
				ibcs2_interpreter = 1;

            //似乎和32/64位相关
			SET_PERSONALITY(loc->elf_ex, ibcs2_interpreter);

            //打开解释器
			interpreter = open_exec(elf_interpreter);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter))
				goto out_free_interp;

			/*
			 * If the binary is not readable then enforce
			 * mm->dumpable = 0 regardless of the interpreter's
			 * permissions.
			 */
			if (file_permission(interpreter, MAY_READ) < 0)
				bprm->interp_flags |= BINPRM_FLAGS_ENFORCE_NONDUMP;

            //读取解释器头
			retval = kernel_read(interpreter, 0, bprm->buf,
					     BINPRM_BUF_SIZE);
			if (retval != BINPRM_BUF_SIZE) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_dentry;
			}

			/* Get the exec headers */
			loc->interp_ex = *((struct exec *)bprm->buf);
			loc->interp_elf_ex = *((struct elfhdr *)bprm->buf);
			break;
		}
		elf_ppnt++;
	}

    //解释器头
	elf_ppnt = elf_phdata;
    //是否允许栈上代码执行，DEP?
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
		if (elf_ppnt->p_type == PT_GNU_STACK) {
			if (elf_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;
		}

	/* Some simple consistency checks for the interpreter */
	if (elf_interpreter) {
		static int warn;

        ...
	    interpreter_type = INTERPRETER_ELF;
        ...

		/* Verify the interpreter has a valid arch */
		if ((interpreter_type == INTERPRETER_ELF) &&
		    !elf_check_arch(&loc->interp_elf_ex))
			goto out_free_dentry;
	} else {
		/* Executables without an interpreter also need a personality  */
		SET_PERSONALITY(loc->elf_ex, ibcs2_interpreter);
	}

    ...
	/* Flush all traces of the currently running executable */
    //清除和父进程共用的部分,内存描述MM的解引用等等
	retval = flush_old_exec(bprm);
	if (retval)
		goto out_free_dentry;

	/* Discard our unneeded old files struct */
	if (files) {
		put_files_struct(files);
		files = NULL;
	}

	/* OK, This is the point of no return */
    //FORK后进行EXEC
	current->flags &= ~PF_FORKNOEXEC;
	current->mm->def_flags = def_flags;

	/* Do this immediately, since STACK_TOP as used in setup_arg_pages
	   may depend on the personality.  */
	SET_PERSONALITY(loc->elf_ex, ibcs2_interpreter);
    //老机器读即可执行
	if (elf_read_implies_exec(loc->elf_ex, executable_stack))
		current->personality |= READ_IMPLIES_EXEC;

    //地址随机偏移的启用
    //第二个条件是该配置是否开启
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		current->flags |= PF_RANDOMIZE;
    //选用布局
	arch_pick_mmap_layout(current->mm);

	/* Do this so that we can load the interpreter, if need be.  We will
	   change some of these later */
	current->mm->free_area_cache = current->mm->mmap_base;
	current->mm->cached_hole_size = 0;
    //# define STACK_TOP	TASK_SIZE
	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 executable_stack);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out_free_dentry;
	}
	
	current->mm->start_stack = bprm->p;

	/* Now we do a little grungy work by mmaping the ELF image into
	   the correct location in memory.  At this point, we assume that
	   the image should be loaded at fixed address, not at a variable
	   address. */
    //遍历待加载进程的头表找所有PT_LOAD段
	for(i = 0, elf_ppnt = elf_phdata;
	    i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		int elf_prot = 0, elf_flags;
		unsigned long k, vaddr;

		if (elf_ppnt->p_type != PT_LOAD)
			continue;

        //brk在bss段之后,第一个LOAD段不可能进次分支
		if (unlikely (elf_brk > elf_bss)) {
			unsigned long nbyte;
	            
			/* There was a PT_LOAD segment with p_memsz > p_filesz
			   before this one. Map anonymous pages, if needed,
			   and clear the area.  */
			retval = set_brk (elf_bss + load_bias,
					  elf_brk + load_bias);
			if (retval) {
				send_sig(SIGKILL, current, 0);
				goto out_free_dentry;
			}
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (clear_user((void __user *)elf_bss +
							load_bias, nbyte)) {
					/*
					 * This bss-zeroing can fail if the ELF
					 * file specifies odd protections. So
					 * we don't check the return value
					 */
				}
			}
		}

        //设置读写执行权限
		if (elf_ppnt->p_flags & PF_R)
			elf_prot |= PROT_READ;
		if (elf_ppnt->p_flags & PF_W)
			elf_prot |= PROT_WRITE;
		if (elf_ppnt->p_flags & PF_X)
			elf_prot |= PROT_EXEC;

		elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

		vaddr = elf_ppnt->p_vaddr;
        //如果是可执行文件,FIXED保证map的地址是传入地址，如果被占用，MMAP失败
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
			/* Try and get dynamic programs out of the way of the
			 * default mmap base, as well as whatever program they
			 * might try to exec.  This is because the brk will
			 * follow the loader, and is not movable.  */
            //PAGESTART去掉末尾4096
            //OFFSET留末尾4096
            //ALIGN4096对齐
            //#define ELF_ET_DYN_BASE		(TASK_SIZE / 3 * 2)
            //动态库的基地址
			load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - vaddr);
		}
        
        //映射PT_LOAD段的内容
        //此处实测32位vaddr就是vaddr，64位是RVA
		error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
				elf_prot, elf_flags);
		if (BAD_ADDR(error)) {
			send_sig(SIGKILL, current, 0);
			retval = IS_ERR((void *)error) ?
				PTR_ERR((void*)error) : -EINVAL;
			goto out_free_dentry;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
            //VA - OFFSET,
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (loc->elf_ex.e_type == ET_DYN) {
				load_bias += error -
				             ELF_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
				reloc_func_desc = load_bias;
			}
		}
        //所以elf文件的txt段在data段之前?
		k = elf_ppnt->p_vaddr;
		if (k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (BAD_ADDR(k) || elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
		    elf_ppnt->p_memsz > TASK_SIZE ||
		    TASK_SIZE - elf_ppnt->p_memsz < k) {
            ...
			goto out_free_dentry;
		}

		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;
        //此时的k指向段的结束（文件大小）
		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & PF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;
        //正常的话elf指向data段结束位置

        //elfbss和filesz同步走，即elfbss到brk之间是bss的内容
        //如果某个段的va+pmemsz大于brk,brk更新
		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		if (k > elf_brk)
			elf_brk = k;
    }

	loc->elf_ex.e_entry += load_bias;

	elf_bss += load_bias;
	elf_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	/* Calling set_brk effectively mmaps the pages that we need
	 * for the bss and break sections.  We must do this before
	 * mapping in the interpreter, to make sure it doesn't wind
	 * up getting placed where the bss needs to go.
	 */
    //bss段的内容在这里设置的
	retval = set_brk(elf_bss, elf_brk);
	if (retval) {
		send_sig(SIGKILL, current, 0);
		goto out_free_dentry;
	}
	if (likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
		send_sig(SIGSEGV, current, 0);
		retval = -EFAULT; /* Nobody gets to see this, but.. */
		goto out_free_dentry;
	}

    //如果有解释器，入口va设为解释器入口，否则
    //就是elf头中的va
	if (elf_interpreter) {
            //基本上就是吧解释器映射到地址空间，然后返回解释器实际映射后的入口va
		    //interp_load_addr = map_addr - ELF_PAGESTART(vaddr);
            //map_addr是实际映射的va
            //第一个段映射后得到实力和默认位置的偏移，且之后的映射设置FIXED
			elf_entry = load_elf_interp(&loc->interp_elf_ex,
						    interpreter,
						    &interp_load_addr);
		if (BAD_ADDR(elf_entry)) {
            ...
			goto out_free_dentry;
		}
		reloc_func_desc = interp_load_addr;

		allow_write_access(interpreter);
		fput(interpreter);
		kfree(elf_interpreter);
	} else {
        //如果没有解释器,入口地址就是本身的代码段地址
		elf_entry = loc->elf_ex.e_entry;
		if (BAD_ADDR(elf_entry)) {
			force_sig(SIGSEGV, current);
			retval = -EINVAL;
			goto out_free_dentry;
		}
	}

	kfree(elf_phdata);

	sys_close(elf_exec_fileno);

	set_binfmt(&elf_format);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = arch_setup_additional_pages(bprm, executable_stack);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out;
	}
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */

	compute_creds(bprm);
	current->flags &= ~PF_FORKNOEXEC;
    //do_execve中将参数拷到最高地址处，上面栈随机化时拷贝一次，这里又拷贝一次
    //填写目标文件的参数，环境变量等等
    //似乎将mm_struct中的一个数组赋值然后拷到栈顶
    //且对栈再次随机化,注释的意思似乎是由于L1缓冲
	retval = create_elf_tables(bprm, &loc->elf_ex,
			  (interpreter_type == INTERPRETER_AOUT),
			  load_addr, interp_load_addr);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out;
	}
	current->mm->end_code = end_code;
	current->mm->start_code = start_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_stack = bprm->p;

	if (current->personality & MMAP_PAGE_ZERO) {
		/* Why this, you ask???  Well SVr4 maps page 0 as read-only,
		   and some applications "depend" upon this behavior.
		   Since we do not have the power to recompile these, we
		   emulate the SVr4 behavior. Sigh. */
		down_write(&current->mm->mmap_sem);
		error = do_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE, 0);
		up_write(&current->mm->mmap_sem);
	}

#ifdef ELF_PLAT_INIT
	/*
	 * The ABI may specify that certain registers be set up in special
	 * ways (on i386 %edx is the address of a DT_FINI function, for
	 * example.  In addition, it may also specify (eg, PowerPC64 ELF)
	 * that the e_entry field is the address of the function descriptor
	 * for the startup routine, rather than the address of the startup
	 * routine itself.  This macro performs whatever initialization to
	 * the regs structure is required as well as any relocations to the
	 * function descriptor entries when executing dynamically links apps.
	 */
	ELF_PLAT_INIT(regs, reloc_func_desc);
#endif

    //设置新的ip
	start_thread(regs, elf_entry, bprm->p);
    //ptrace可能跟踪exec
	if (unlikely(current->ptrace & PT_PTRACED)) {
		if (current->ptrace & PT_TRACE_EXEC)
			ptrace_notify ((PTRACE_EVENT_EXEC << 8) | SIGTRAP);
		else
			send_sig(SIGTRAP, current, 0);
	}
	retval = 0;
out:
	kfree(loc);
out_ret:
	return retval;

	/* error cleanup */
out_free_dentry:
	allow_write_access(interpreter);
	if (interpreter)
		fput(interpreter);
out_free_interp:
	kfree(elf_interpreter);
out_free_file:
	sys_close(elf_exec_fileno);
out_free_fh:
	if (files)
		reset_files_struct(current, files);
out_free_ph:
	kfree(elf_phdata);
	goto out;
}


int setup_arg_pages(struct linux_binprm *bprm,
		    unsigned long stack_top,
		    int executable_stack)
{
	unsigned long ret;
	unsigned long stack_shift;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma = bprm->vma;
	struct vm_area_struct *prev = NULL;
	unsigned long vm_flags;
	unsigned long stack_base;

	stack_top = arch_align_stack(stack_top);
	stack_top = PAGE_ALIGN(stack_top);
	stack_shift = vma->vm_end - stack_top;

	bprm->p -= stack_shift;
	mm->arg_start = bprm->p;

	if (bprm->loader)
		bprm->loader -= stack_shift;
	bprm->exec -= stack_shift;

	down_write(&mm->mmap_sem);
	vm_flags = vma->vm_flags;

	if (unlikely(executable_stack == EXSTACK_ENABLE_X))
		vm_flags |= VM_EXEC;
	else if (executable_stack == EXSTACK_DISABLE_X)
		vm_flags &= ~VM_EXEC;
	vm_flags |= mm->def_flags;

	ret = mprotect_fixup(vma, &prev, vma->vm_start, vma->vm_end,
			vm_flags);
	if (ret)
		goto out_unlock;
	BUG_ON(prev != vma);

	/* Move stack pages down in memory. */
	if (stack_shift) {
		ret = shift_arg_pages(vma, stack_shift);
		if (ret) {
			up_write(&mm->mmap_sem);
			return ret;
		}
	}

	stack_base = vma->vm_start - EXTRA_STACK_VM_PAGES * PAGE_SIZE;
	ret = expand_stack(vma, stack_base);
	if (ret)
		ret = -EFAULT;

out_unlock:
	up_write(&mm->mmap_sem);
	return 0;
}


#define start_thread(regs, new_eip, new_esp) do {		\
	__asm__("movl %0,%%gs": :"r" (0));			\
	regs->xfs = 0;						\
	set_fs(USER_DS);					\
	regs->xds = __USER_DS;					\
	regs->xes = __USER_DS;					\
	regs->xss = __USER_DS;					\
	regs->xcs = __USER_CS;					\
	regs->eip = new_eip;					\
	regs->esp = new_esp;					\
} while (0)
