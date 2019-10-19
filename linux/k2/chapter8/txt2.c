struct file_system_type {
	const char *name;
	int fs_flags;
	int (*get_sb) (struct file_system_type *, int,
		       const char *, void *, struct vfsmount *);
	void (*kill_sb) (struct super_block *);     //清理
	struct module *owner;           
	struct file_system_type * next;
	struct list_head fs_supers;     //该文件系统的超级块实例

	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;

	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key i_mutex_dir_key;
	struct lock_class_key i_alloc_sem_key;
};
注册文件系统的时候使用


//共享装载?主从装载？
struct vfsmount {
	struct list_head mnt_hash;      //mount_hashtable的溢出链
	struct vfsmount *mnt_parent;	/* 装载点所在的父文件系统 */
	struct dentry *mnt_mountpoint;	/* 装载点的dentry结构（在父目录中）*/
	struct dentry *mnt_root;	/* root of the mounted tree */
	struct super_block *mnt_sb;	/* 指向超级块 */
	struct list_head mnt_mounts;	/* 子文件系统链表, anchored here */
	struct list_head mnt_child;	/* 链表元素and going through their mnt_child */
	int mnt_flags;
	/* 4 bytes hole on 64bits arches */
	char *mnt_devname;		/* 设备名 e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;      //元素，头是相应namespace->list

	struct list_head mnt_expire;	/* link in fs-specific expiry list */

	struct list_head mnt_share;	/* circular list of shared mounts */

	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct vfsmount *mnt_master;	/* slave is on master->mnt_slave_list */

	struct mnt_namespace *mnt_ns;	/* containing namespace */
	/*
	 * We put mnt_count & mnt_expiry_mark at the end of struct vfsmount
	 * to let these frequently modified fields in a separate cache line
	 * (so that reads of mnt_flags wont ping-pong on SMP machines)
	 */
	atomic_t mnt_count;
	int mnt_expiry_mark;		/*指示是否过期 */
	int mnt_pinned;
};
#define MNT_NOSUID	0x01
#define MNT_NODEV	0x02        //虚拟的
#define MNT_NOEXEC	0x04
#define MNT_NOATIME	0x08
#define MNT_NODIRATIME	0x10
#define MNT_RELATIME	0x20

#define MNT_SHRINKABLE	0x100   //NFS

#define MNT_SHARED	0x1000	/* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE	0x2000	/* if the vfsmount is a unbindable mount */
#define MNT_PNODE_MASK	0x3000	/* propagation flag mask */



asmlinkage long sys_mount(char __user * dev_name, char __user * dir_name,
			  char __user * type, unsigned long flags,
			  void __user * data)
{
	int retval;
	unsigned long data_page;
	unsigned long type_page;
	unsigned long dev_page;
	char *dir_page;

	retval = copy_mount_options(type, &type_page);
	if (retval < 0)
		return retval;

	dir_page = getname(dir_name);
	retval = PTR_ERR(dir_page);
	if (IS_ERR(dir_page))
		goto out1;

	retval = copy_mount_options(dev_name, &dev_page);
	if (retval < 0)
		goto out2;

	retval = copy_mount_options(data, &data_page);
	if (retval < 0)
		goto out3;

	lock_kernel();
	retval = do_mount((char *)dev_page, dir_page, (char *)type_page,
			  flags, (void *)data_page);
	unlock_kernel();
	free_page(data_page);

out3:
	free_page(dev_page);
out2:
	putname(dir_page);
out1:
	free_page(type_page);
	return retval;
}

//用于向查找函数传递参数
struct nameidata {
	struct dentry	*dentry;    //out
	struct vfsmount *mnt;       //out
	struct qstr	last;           //待查名
	unsigned int	flags;      //用于微调查找操作
	int		last_type;
	unsigned	depth;
	char *saved_names[MAX_NESTED_LINKS + 1];

	/* Intent data */
	union {
		struct open_intent open;
	} intent;
};

/* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
static int fastcall do_path_lookup(int dfd, const char *name,
				unsigned int flags, struct nameidata *nd)
{
	int retval = 0;
	int fput_needed;
	struct file *file;
	struct fs_struct *fs = current->fs;

	nd->last_type = LAST_ROOT; /* if there are only slashes... */
	nd->flags = flags;
	nd->depth = 0;

	if (*name=='/') {
		read_lock(&fs->lock);
		if (fs->altroot && !(nd->flags & LOOKUP_NOALT)) {
            ...
		}
		nd->mnt = mntget(fs->rootmnt);
		nd->dentry = dget(fs->root);
		read_unlock(&fs->lock);
	} else if (dfd == AT_FDCWD) {
		read_lock(&fs->lock);
		nd->mnt = mntget(fs->pwdmnt);
		nd->dentry = dget(fs->pwd);
		read_unlock(&fs->lock);
	} else {
        ...
	}

	retval = path_walk(name, nd);
out:
	if (unlikely(!retval && !audit_dummy_context() && nd->dentry &&
				nd->dentry->d_inode))
		audit_inode(name, nd->dentry);
out_fail:
	return retval;

fput_fail:
	fput_light(file, fput_needed);
	goto out_fail;
}


static fastcall int __link_path_walk(const char * name, struct nameidata *nd)
{
	struct path next;
	struct inode *inode;
	int err;
	unsigned int lookup_flags = nd->flags;
	
	while (*name=='/')
		name++;
	if (!*name)
		goto return_reval;

    //目前是根目录的inode项
	inode = nd->dentry->d_inode;
	if (nd->depth)
		lookup_flags = LOOKUP_FOLLOW | (nd->flags & LOOKUP_CONTINUE);

	/* At this point we know we have a real path component. */
	for(;;) {
		unsigned long hash;
		struct qstr this;
		unsigned int c;

		nd->flags |= LOOKUP_CONTINUE;
        //下面一部分和权限判断有关
		err = exec_permission_lite(inode, nd);
		if (err == -EAGAIN)
			err = vfs_permission(nd, MAY_EXEC);
 		if (err)
			break;

		this.name = name;
		c = *(const unsigned char *)name;

		hash = init_name_hash();
		do {
			name++;
			hash = partial_name_hash(c, hash);
			c = *(const unsigned char *)name;
		} while (c && (c != '/'));
		this.len = name - (const char *) this.name;
		this.hash = end_name_hash(hash);

		/* remove trailing slashes? */
		if (!c)
			goto last_component;
		while (*++name == '/');
		if (!*name)
			goto last_with_slashes;

		/*
		 * "." and ".." are special - ".." especially so because it has
		 * to be able to know about the current root directory and
		 * parent relationships.
		 */
		if (this.name[0] == '.') switch (this.len) {
			default:
				break;
			case 2:	
				if (this.name[1] != '.')
					break;
				follow_dotdot(nd);
				inode = nd->dentry->d_inode;
				/* fallthrough */
			case 1:
				continue;
		}
		/*
		 * See if the low-level filesystem might want
		 * to use its own hash..
		 */
		if (nd->dentry->d_op && nd->dentry->d_op->d_hash) {
			err = nd->dentry->d_op->d_hash(nd->dentry, &this);
			if (err < 0)
				break;
		}
		/* This does the actual lookups.. */
		err = do_lookup(nd, &this, &next);
		if (err)
			break;

		err = -ENOENT;
		inode = next.dentry->d_inode;
		if (!inode)
			goto out_dput;
		err = -ENOTDIR; 
		if (!inode->i_op)
			goto out_dput;

		if (inode->i_op->follow_link) {
			err = do_follow_link(&next, nd);
			if (err)
				goto return_err;
			err = -ENOENT;
			inode = nd->dentry->d_inode;
			if (!inode)
				break;
			err = -ENOTDIR; 
			if (!inode->i_op)
				break;
		} else
			path_to_nameidata(&next, nd);
		err = -ENOTDIR; 
		if (!inode->i_op->lookup)
			break;
		continue;
		/* here ends the main loop */

last_with_slashes:
		lookup_flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
last_component:
		/* Clear LOOKUP_CONTINUE iff it was previously unset */
		nd->flags &= lookup_flags | ~LOOKUP_CONTINUE;
		if (lookup_flags & LOOKUP_PARENT)
			goto lookup_parent;
		if (this.name[0] == '.') switch (this.len) {
			default:
				break;
			case 2:	
				if (this.name[1] != '.')
					break;
				follow_dotdot(nd);
				inode = nd->dentry->d_inode;
				/* fallthrough */
			case 1:
				goto return_reval;
		}
		if (nd->dentry->d_op && nd->dentry->d_op->d_hash) {
			err = nd->dentry->d_op->d_hash(nd->dentry, &this);
			if (err < 0)
				break;
		}
		err = do_lookup(nd, &this, &next);
		if (err)
			break;
		inode = next.dentry->d_inode;
		if ((lookup_flags & LOOKUP_FOLLOW)
		    && inode && inode->i_op && inode->i_op->follow_link) {
			err = do_follow_link(&next, nd);
			if (err)
				goto return_err;
			inode = nd->dentry->d_inode;
		} else
			path_to_nameidata(&next, nd);
		err = -ENOENT;
		if (!inode)
			break;
		if (lookup_flags & LOOKUP_DIRECTORY) {
			err = -ENOTDIR; 
			if (!inode->i_op || !inode->i_op->lookup)
				break;
		}
		goto return_base;
lookup_parent:
		nd->last = this;
		nd->last_type = LAST_NORM;
		if (this.name[0] != '.')
			goto return_base;
		if (this.len == 1)
			nd->last_type = LAST_DOT;
		else if (this.len == 2 && this.name[1] == '.')
			nd->last_type = LAST_DOTDOT;
		else
			goto return_base;
return_reval:
		/*
		 * We bypassed the ordinary revalidation routines.
		 * We may need to check the cached dentry for staleness.
		 */
		if (nd->dentry && nd->dentry->d_sb &&
		    (nd->dentry->d_sb->s_type->fs_flags & FS_REVAL_DOT)) {
			err = -ESTALE;
			/* Note: we do not d_invalidate() */
			if (!nd->dentry->d_op->d_revalidate(nd->dentry, nd))
				break;
		}
return_base:
		return 0;
out_dput:
		dput_path(&next, nd);
		break;
	}
	path_release(nd);
return_err:
	return err;
}


open系统调用调path_lookup获取inode，nameidata_to_filp初始化预读结构，将创建的file实例串到超级块上，然后调底层file_operations的open,之后fd_install将file放到task_struct的files->fd中
