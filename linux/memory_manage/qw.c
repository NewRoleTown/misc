#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

MODULE_LICENSE("Dual BSD/GPL");  


unsigned long long get_pgd(struct task_struct *p,unsigned long long addr){
	unsigned long long goal = (unsigned long long)(pgd_offset(p->mm,addr));
	return goal;
}

unsigned long long get_pud(unsigned long long pgd,unsigned long long addr){
	return (unsigned long long)pud_offset((pgd_t *)pgd,addr);
}

unsigned long long get_pmd(unsigned long long pud,unsigned long long addr){
	return (unsigned long long)pmd_offset((pud_t *)pud,addr);
}


//linux标准实现
unsigned long long get_pte(unsigned long long pmd,unsigned long long addr){
	return (unsigned long long)pte_offset_kernel((pmd_t *)pmd,addr);
}


unsigned long long get_pte_self(unsigned long long pmd,unsigned long long addr){
	unsigned long long *table = (unsigned long long *)__va(*(unsigned long long *)pmd);
	table = (unsigned long long *)((unsigned long long)table & 0xffffffffffff0000);

	table += pte_index(addr);

	return (unsigned long long)table;
}

//64位linux,转换用户空间地址到内核空间地址,前提是不存在ZONE_HIGNMEM
unsigned long long int trans_vaddr_from_user_to_kernel(struct task_struct *p,unsigned long long addr,int needprint){
	unsigned long long int pgd = 0;
	unsigned long long int pgdt = 0;
	unsigned long long int pudt = 0;
	unsigned long long int pmdt = 0;
	unsigned long long int ptet = 0;

	unsigned long long int vaddr_in_kernel = 0;
	unsigned long long int offset_in_page;
	offset_in_page = addr & 0x0000000000000fff;



	//获取进程全局页目录的内核虚拟地址
	pgd = (unsigned long long int)p->mm->pgd;

	//获取全局页目录表项的内核虚拟地址
	pgdt = get_pgd(p,addr);

	//获取页上层目录项的内核虚拟地址
	pudt = get_pud(pgdt,addr);

	//获取页中间目录项的内核虚拟地址
	pmdt = get_pmd(pudt,addr);

	//获取页表项的内核虚拟地址
	ptet = get_pte(pmdt,addr);

	//*(unsigned long long int *)ptet = *(unsigned long long int *)ptet & 0xfffffffffffffffd;
	//*(unsigned long long int *)ptet = *(unsigned long long int *)ptet | 0x0000000000000007;

	///////////////////////////////////////////////////////////////
	//最高位为1的问题没有解决0x8000000000000000

	vaddr_in_kernel = (*(unsigned long long *)ptet) & 0x0000fffffffff000;
	vaddr_in_kernel = (unsigned long long)__va(vaddr_in_kernel) + offset_in_page;

	if(needprint){
		printk("pgd : %llx\n",(unsigned long long)__va(pgd));

		printk("pgdt : %llx\n",*(unsigned long long*)pgdt & 0xfffffffffffff000);
		printk("pgdt's attr is %llx\n",*(unsigned long long *)pgdt & 0x0000000000000fff);

		printk("pudt : %llx\n",*(unsigned long long*)pudt & 0xfffffffffffff000);
		printk("pudt's attr is %llx\n",*(unsigned long long *)pudt & 0x0000000000000fff);

		printk("pmdt : %llx\n",*(unsigned long long*)pmdt & 0xfffffffffffff000);
		printk("pmdt's attr is %llx\n",*(unsigned long long *)pmdt & 0x0000000000000fff);

		printk("ptet : %llx\n",*(unsigned long long*)ptet & 0xfffffffffffff000);
		printk("ptet's attr is %llx\n",*(unsigned long long *)ptet & 0x0000000000000fff);
	}


	//

	return vaddr_in_kernel;


}

//获取页表项的内核空间虚拟地址
unsigned long long int get_pte_t_in_kva(struct task_struct *p,unsigned long long addr){
	unsigned long long int pgd = 0;
	unsigned long long int pgdt = 0;
	unsigned long long int pudt = 0;
	unsigned long long int pmdt = 0;
	unsigned long long int ptet = 0;

	pgd = (unsigned long long int)p->mm->pgd;

	pgdt = get_pgd(p,addr);
	pudt = get_pud(pgdt,addr);
	pmdt = get_pmd(pudt,addr);
	ptet = get_pte(pmdt,addr);

	return ptet;
}


int set_read_or_write_mem_bk(struct task_struct *p,unsigned long long addr){

	unsigned long long int ptet = get_pte_t_in_kva(p,addr);
	//9 = 1001
	//1:PWT  
	//0:USER/SUPER 
	//0:READ/WRITE
	//1:PRESENT
	//如果仅设置读写位为0,缺页时触发COW,不会引发段错误
	*(unsigned long long int *)ptet = *(unsigned long long int *)ptet & 0xfffffffffffffff9;

	return 0;
	
}

int clr_read_or_write_mem_bk(struct task_struct *p,unsigned long long addr){

	unsigned long long int ptet = get_pte_t_in_kva(p,addr);
	//7 = 0111
	//0:PWT  
	//1:USER/SUPER 
	//1:READ/WRITE
	//1:PRESENT
	*(unsigned long long int *)ptet = *(unsigned long long int *)ptet | 0x0000000000000007;

	return 0;
}

#define cdevMAJOR	123
#define cdevMINOR	0

#define PEEK_DATA	0x1f
#define POKE_DATA	0x1e
#define PEEK_CR2	0x2f

#define SET_MEM_BK	0x3f
#define CLR_MEM_BK	0x4f

#define SET_HARD_BK	0x5f

#define KSET_INT3	0x6f
#define KCLR_INT3	0x7f


struct mem_bk_s{
	int pid;
	int res;
	unsigned long long int addr;
};

int devno = -1;
struct cdev mem_bk_cdev;

int thc_open(struct inode *pinode,struct file *pfile){

	printk("<in thc_open\tpid : %d,proc : %s>\n",current->pid,current->comm);
	return 0;
}

int thc_release(struct inode *pinode,struct file *pfile){
	printk("<in thc_release\tpid : %d,proc : %s>\n",current->pid,current->comm);
	return 0;
}


struct task_struct *find_task_struct(int pid){
	struct task_struct *pos;
	struct list_head *current_head;

	current_head=&(current->tasks);

	list_for_each_entry(pos,current_head,tasks)
	{
		if( pos->pid == pid ){
			return pos;
		}
	}
	return 0;
}

void continue_eip(){
	unsigned long long int addr;
	unsigned long long int old_eip;

	int judge_int3_or_mem = 1;

	addr = get_kernel_addr();
	old_eip = addr - 1;

	unsigned long long int new_eip = old_eip + 1;

	if(is_mem_bk(new_eip)){
		printk("is a mem_bk\n");
		return;
	}


	is_int3(addr);

	if(!con_running)
		debug_on();

	if(!con_exception)
		debug_on();

	if(!con_runable)
		debug_on();

	set_type3_beak(addr);



	return;
}

long thc_ioctl(struct file *pfile,unsigned int op,unsigned long arg){
	int ret;
	struct mem_bk_s ins;
	unsigned long long int kva;
	struct task_struct *p = NULL;

	printk("<in thc_ioctl\tpid : %d,proc : %s>\n",current->pid,current->comm);

	ret = copy_from_user(&ins,(void *)arg,sizeof(struct mem_bk_s));

	if(ret){
		printk("copy from user error\n");
		return 0;
	}

	p = find_task_struct(ins.pid);

	if(!p){
		printk("no process has this pid\n");
		return 0;	
	}

	if( PEEK_DATA == op){
		printk("<op = PEEK_DATA>\n");
		printk("pid : %d,addr : 0x%llx\n",ins.pid,ins.addr);

		kva = trans_vaddr_from_user_to_kernel(p,ins.addr,1);

		printk("get int %d\n",*(int *)kva);

		return 0;

	}

	if( POKE_DATA == op){
		printk("<op = POKE_DATA>\n");
		printk("pid : %d,addr : 0x%llx\n",ins.pid,ins.addr);

		kva = trans_vaddr_from_user_to_kernel(p,ins.addr,1);

		*(int *)kva = 0xCCCCCCCC;

		return 0;

	}

	if( PEEK_CR2 == op){
		printk("<op = PEEK_CR2>\n");
		printk("cr2 : 0x%lx\n",p->thread.cr2);

		return 0;
	}

	if( SET_MEM_BK == op){
		printk("<op = SET_MEM_BK>\n");
		set_read_or_write_mem_bk(p,ins.addr);
		return 0;
	}

	if( CLR_MEM_BK == op){
		printk("<op = CLR_MEM_BK>\n");
		clr_read_or_write_mem_bk(p,ins.addr);
		return 0;
	}
/*
	if( SET_HARD_BK == op){
		printk("<op = SET_HARD_BK>\n");
		set_hardware_breakpoint();
		return 0;
	}

	if( KSET_INT3 == op){
		printk("<op = KSET_INT3>\n");
		return 0;
	}

	if( KCLR_INT3 == OP){
		printk("<op = KCLR_INT3>\n");

		return 0;
	}
*/
	return 0;
}

struct file_operations fops = {
	.open = &thc_open,
	.release = &thc_release,
	.unlocked_ioctl = &thc_ioctl,
};
#if 1
#endif
static int hello_init(void)
{  

	devno = MKDEV(cdevMAJOR,cdevMINOR);

	if(register_chrdev_region(devno,1,"mem_bk")){
		printk("error in register_chrdev_region\n");
		return 0;
	}

	cdev_init(&mem_bk_cdev,&fops);
	mem_bk_cdev.owner = THIS_MODULE;
	cdev_add(&mem_bk_cdev,devno,1);

	return 0;  
}  

static void hello_exit(void)  
{	
	cdev_del(&mem_bk_cdev);
	unregister_chrdev_region(devno,1);
	printk("bye module!\n");  
}  

module_init(hello_init); 
module_exit(hello_exit); 



#if 0
struct task_struct *pos;
struct list_head *current_head;


unsigned long long addr= 0x564c1d3ef000;

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
#endif
