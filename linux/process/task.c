//±éÀú½ø³Ì
struct task_struct *pos;
struct list_head *current_head;

current_head=&(current->tasks);

list_for_each_entry(pos,current_head,tasks)
{
	if( pos->pid == 4605 ){
		printk("----------------in kernel-----------------\n");
		printk("cr2's var is %p\n",(void *)(pos->thread.cr2));
		printk("code_start is %p\n",(void *)(pos->mm->start_code));

		printk("numnum is %d\n",*(int *)trans_vaddr_from_user_to_kernel(pos,addr,1));


	}
	//printk("[process %d]: %s\'s pid is %d\n",count,pos->comm,pos->pid);
}
