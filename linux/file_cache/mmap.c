mmap
MAP_SHARED

MAP_PRIVATE


inode->i_mapping->page_tree->"struct page"
->(prio_tree_root)i_mmap~"struct vm_area_struct"->"struct file"->f_mapping

case MAP_SHARED:
	vm_flags |= VM_SHARED | VM_MAYSHARE;
	if (!(file->f_mode & FMODE_WRITE))
		vm_flags &= ~(VM_MAYWRITE | VM_SHARED);

	/* fall through */
case MAP_PRIVATE:
	if (!(file->f_mode & FMODE_READ))
		return -EACCES;
	if (file->f_path.mnt->mnt_flags & MNT_NOEXEC) {
		if (vm_flags & VM_EXEC)
			return -EPERM;
		vm_flags &= ~VM_MAYEXEC;
	}

	if (!file->f_op || !file->f_op->mmap)
		return -ENODEV;
	break;
