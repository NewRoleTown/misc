#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("Dual BSD/GPL");  

#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC

#define loop(p,l) for( p = 0 ; p < l ; p ++)

#define MK_ADDR(bus,dev,fun,reg) ((1<<31)+(bus<<16)+(dev<<11)+(fun<<8)+(reg))

void ghc_outb(unsigned short int port,unsigned char var){
	asm volatile("outb %0,%1"::"a"(var),"d"(port):);
}


void ghc_outw(unsigned short int port,unsigned short int var){
	asm volatile("outw %0,%1"::"a"(var),"d"(port):);
}

void ghc_outl(unsigned short int port,unsigned int var){
	asm volatile("outl %0,%1"::"a"(var),"d"(port):);
}

unsigned char ghc_inb(unsigned short int port){
	unsigned char var = 0;
	asm volatile("inb %1,%%al":"=a"(var):"d"(port):);
	return var;
}

unsigned short int ghc_inw(unsigned short int port){
	unsigned short int var = 0;
	asm volatile("inw %1,%%ax":"=a"(var):"d"(port):);
	return var;
}

unsigned int ghc_inl(unsigned short int port){
	unsigned int var = 0;
	asm volatile("inl %1,%%eax":"=a"(var):"d"(port):);
	return var;
}

#define MAX_BUS	256
#define MAX_DEV	32
#define MAX_FUN	8

void print_iomem(int i,int j,int k){
	int max_num = 6;
	int l = 0;
	unsigned int cmd;
	unsigned int data;
	
	for( ; l < max_num ;l++ ){
		cmd = MK_ADDR(i,j,k,0x10 + (l * 4));
		ghc_outl(PCI_CONFIG_ADDR,cmd);
		data = ghc_inl(PCI_CONFIG_DATA);
		if(data % 2)
			printk("base%d:%x\n",l,data);
		else
			printk("base%d:%x\n",l,data);
	}
}



void print_info(int i,int j,int k){

	unsigned int cmd;
	unsigned int data;

	cmd = MK_ADDR(i,j,k,0x3C);
	ghc_outl(PCI_CONFIG_ADDR,cmd);
	data = ghc_inl(PCI_CONFIG_DATA);

	return;
}


void print_interrupt(int i,int j,int k){
	unsigned int data;
	unsigned int cmd;
	cmd = MK_ADDR(i,j,k,0x03c);
	ghc_outl(PCI_CONFIG_ADDR,cmd);
	data = ghc_inl(PCI_CONFIG_DATA);

	printk("info:%x\n",data);
	printk("Pin:%x\n",(data & 0x0000ff00) >> 8);
	printk("Lin:%x\n",(data & 0x000000ff));
	
}

static int hello_init(void)
{

	//int i = 0,j,k;
	//int cmd = 0;
	unsigned long long int addr = 0xe0000000;
	//unsigned int data;
	struct page *p = pfn_to_page(addr >> PAGE_SHIFT);

	printk("------------------------------------\n");
	/*
	loop(i,MAX_BUS){
		loop(j,MAX_DEV){
			loop(k,MAX_FUN){
				cmd = MK_ADDR(i,j,k,0x0);
				ghc_outl(PCI_CONFIG_ADDR,cmd);
				data = ghc_inl(PCI_CONFIG_DATA);
				if( data != 0xffffffff ){
					printk("%d,%d,%d\t",i,j,k);
					printk("vender:%x\n",data & 0x0000ffff);
					printk("device:%x\n",(data >> 16));

					//print_iomem(i,j,k);
					print_interrupt(i,j,k);
				}
			}
		}
	}*/

	

	//printk("%d\n",*(unsigned char *)(addr));
	//
	printk("%d\n",p->flags);
	return 0;  

}  

static void hello_exit(void)  
{	
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
