#include<stdio.h>
#include<errno.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<fcntl.h>
#include<assert.h>
#include<elf.h>
#include<stdint.h>
#include<string.h>
#include<unistd.h>
#include<pthread.h>
#include<link.h>
#include<dlfcn.h>

/*
.comment	版本控制信息
.debug 		调试信息
.dynamic 	动态链接信息
.dynstr 	动态链接字符串
.dynsym 	动态链接符号表
.fini 		终止代码
.got 		全局偏移表
.hash 		符号hash表
.init 		初始化代码
.interp 	解释器路径名
.line 		调试行号
.note 		注释
.plt 		过程链接表
.relname 	重定位信息
.shstrtab 	节区名字符表
.symtab 	符号表
*/

/*
动态链接库信息似乎是放在DT_NEEDED中，需要几个库，就有几个DT_NEEDED
*/


#define PRINT

typedef int (*pfn)(pthread_t *, const pthread_attr_t *,void *(*) (void *), void *);
pfn x;

void *thread_fun(void *context){
	printf("in thread!\n");
	return NULL;
}

unsigned long long vbase;
int fd;
void *pmap;
void init(){
    //读取可执行文件并且映射到内存中
	int fd = open("./elf",O_RDONLY);
	assert(fd != -1);
	pmap = mmap(NULL,40960,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);
	assert(pmap);
	return;
}

void checkelf(){
    //检查elf文件魔数
    //这个程序默认使用elf64的方式来解析，elf32未做

	char *p = (char *)pmap;
	if((p[1] != 'E') || (p[2] != 'L') || (p[3] != 'F'))
		assert(0);
	assert(p[0] == 0x7f );
	if(p[4] == 1){
		//elf32
	}else if(p[4] == 2){
		//elf64
	}else{
		assert(0);
	}
	return;
}


Elf64_Ehdr *pElfhdr;
unsigned strtab_index;
unsigned ph_num;
unsigned sh_num;

void analysis_head(){
    //解析elf头部

	pElfhdr = (Elf64_Ehdr *)pmap;

    //e_entry字段是RVA，需要加上基地址
	printf("entry point = 0x%p\n",pElfhdr->e_entry + vbase);
    //头部大小
	printf("elf head size = %llu\n",pElfhdr->e_ehsize);

    //程序头表的偏移，大小，表项数量
	printf("program header table Off = %llu\n",pElfhdr->e_phoff);
	printf("program header table entry size  = %u\n",pElfhdr->e_phentsize);
	printf("program header table entry count  = %u\n",ph_num = pElfhdr->e_phnum);

    //节表的偏移，大小，表项数量
	printf("section header table Off = %llu\n",pElfhdr->e_shoff);
	printf("section header table entry size  = %u\n",pElfhdr->e_shentsize);
	printf("section header table entry count  = %u\n",sh_num = pElfhdr->e_shnum);


    //字符表在节表中的偏移,重要字段，节表的名称等需要在解析时用到的字符串存在里面
	printf("str table index = %u\n",strtab_index = pElfhdr->e_shstrndx);

	return;
}

Elf64_Shdr *pElfShdr;
//ELF头中所包含的字符表基址
char *strtab;

int dynamicindex = -1;

void analysis_sh_type(Elf64_Word type){

	printf("type:\n");
	switch(type){
		case SHT_NULL:	  
			printf(" Section header table entry unused ");
			break;
		case SHT_PROGBITS:	 		
            //常见，程序数据
			printf(" Program data ");
			break;
		case SHT_SYMTAB:	  	
            //常见，符号表
			printf(" Symbol table ");
			break;
		case SHT_STRTAB:	 		
            //常见，字符表
			printf(" String table ");
			break;
		case SHT_RELA: 	
            //常见，重定位表
			printf(" Relocation entries with addends ");
			break;
		case SHT_HASH:	
            //符号hash表，参与动态链接的都有
			printf(" Symbol hash table ");
			break;
		case SHT_DYNAMIC:	  		
            //包含动态链接信息
			printf(" Dynamic linking information ");
			break;
		case SHT_NOTE:		
			printf(" Notes ");
			break;
		case SHT_NOBITS:	  		
            //不占用文件空间
			printf(" Program space with no data (bss) ");
			break;
		case SHT_REL:	  		
            //无补齐的重定位表
			printf(" Relocation entries, no addends ");
			break;
		case SHT_SHLIB: 		
			printf(" Reserved ");
			break;
		case SHT_DYNSYM:	  		
			printf(" Dynamic linker symbol table ");
			break;
		case SHT_INIT_ARRAY:	  		
			printf(" Array of constructors ");
			break;
		case SHT_FINI_ARRAY:	  		
			printf(" Array of destructors ");
			break;
		case SHT_PREINIT_ARRAY:		
			printf(" Array of pre-constructors ");
			break;
		case SHT_GROUP:	
			printf(" Section group ");
			break;
		case SHT_SYMTAB_SHNDX:		
			printf(" Extended section indeces ");
			break;
		case SHT_NUM:	  	
			printf(" Number of defined types.  ");
			break;
		case SHT_LOOS:	
			printf(" Start OS-specific.  ");
			break;
		case SHT_GNU_ATTRIBUTES: 
			printf(" Object attributes.  ");
			break;
		case SHT_GNU_HASH: 	
			printf(" GNU-style hash table.  ");
			break;
		case SHT_GNU_LIBLIST:	  	
			printf(" Prelink library list ");
			break;
		case SHT_CHECKSUM:	
			printf(" Checksum for DSO content.  ");
			break;
		case SHT_LOSUNW:	  	
			printf(" Sun-specific low bound.  ");
			break;
		case SHT_SUNW_COMDAT:   
		case SHT_SUNW_syminfo : 
		case SHT_GNU_verdef:  	
			printf(" Version definition section.  ");
			break;
		case SHT_GNU_verneed: 
			printf(" Version needs section.  ");
			break;
		case SHT_GNU_versym:  	
			printf(" Version symbol table.  ");
			break;
		case SHT_LOPROC:	  	
			printf(" Start of processor-specific ");
			break;
		case SHT_HIPROC:	  
			printf("End of processor-specific ");
			break;
		case SHT_LOUSER:	  	
			printf(" Start of application-specific ");
			break;
		case SHT_HIUSER:	  	
			printf(" End of application-specific ");
			break;
		default:
			printf("no this type");
	}
	printf("\n");
	return;
}

void analysis_sh_flag(Elf64_Word flag){
	printf("flag:\n");
	if(flag & SHF_WRITE)
        //可写
		printf(" Writable \n");
	if(flag & SHF_ALLOC)
        //占用内存
		printf(" Alloc \n");
	if(flag & SHF_EXECINSTR	  )
        //可执行
		printf(" Executable \n");
	if(flag & SHF_MERGE	)
		printf(" Might be merged \n");
	if(flag & SHF_STRINGS)
		printf(" Contains nul-terminated strings \n");
	if(flag & SHF_INFO_LINK	) 
		printf(" `sh_info' contains SHT index \n");
	if(flag & SHF_LINK_ORDER)
		printf(" Preserve order after combining \n");
	if(flag & SHF_OS_NONCONFORMING )
		printf(" Non-standard OS specific handling required \n");
	if(flag & SHF_GROUP)
		printf(" Section is member of a group.  \n");
	if(flag & SHF_TLS)
		printf(" Section hold thread-local data.  \n");
	if(flag & SHF_COMPRESSED)
		printf(" Section with compressed data. \n");
	if(flag & SHF_MASKOS)
		printf(" OS-specific.  \n");
	if(flag & SHF_MASKPROC	)
		printf(" Processor-specific \n");
	if(flag & SHF_ORDERED)
		printf(" Special ordering requirement (Solaris).  \n");
	if(flag & SHF_EXCLUDE)
		printf(" Section is excluded unless referenced or allocated (Solaris).\n");
	return;
}



/*符号表解析*/
char *type_arr[8] = {"NOTYPE","OBJECT","FUNC","SECTION","FILE","ERR","ERR","ERR"};
char *bind_arr[4] = {"LOCAL","GLOBAL","WEAK","ERR"};
//,"ERR","ERR","ERR","ERR","ERR","ERR","ERR","ERR","ERR","RES","RES","RES"};

//LOCAL局部符号，同名符号可存在于多个文件中互不影响
//GLOBAL全局符号，所有组合在一起的文件可见，一个文件全局符号的定义将弥补另一个文件中
//同名全局符号的未定义引用
//WEAK弱符号与GLOBAL相似，但是优先级比较低

//多个文件中只能存在一个全局符号
//如果存在同名的WEAK，GLOBAL会覆盖WEAK

//(以下未验证)
//链接lib时，会将lib中的GLOBAL，WEAK来弥补为定义GLOBAL，但是不会弥补为定义WEAK

int Sym2Str[64];
void analysis_sym(Elf64_Word strindex,Elf64_Word symindex){

    printf("this sym's strtab idx is %d\n",strindex );
    Sym2Str[symindex] = strindex;

	Elf64_Sym *pElfsym;

    //获取相关字符表的基地址
	char *pstr = (char *)(pmap + (pElfShdr + strindex)->sh_offset);
	pElfsym = (Elf64_Sym *)(pmap + (pElfShdr + symindex)->sh_offset);
	int num = ((pElfShdr + symindex)->sh_size)/((pElfShdr + symindex)->sh_entsize);

	printf("     *****************************************     \n");
	for( int i = 0 ; i < num ; i ++ ){
        //对于value值，不同文件类型的解释不同
        //可重定位文件中，value包含是从st_shndx节头部开始的偏移(未测)
        //可执行/共享目标(obj?)value为虚拟地址(实测RVA)
		printf("%x\t\t",pElfsym->st_value);
		printf("%u\t\t",pElfsym->st_size);
		printf("%s\t\t",type_arr[ELF64_ST_TYPE(pElfsym->st_info)]);
		printf("%s\t\t",bind_arr[ELF64_ST_BIND(pElfsym->st_info)]);
        //absolution绝对取值，不会由重定位改变符号取值
        //common符号标注了一块内存，取值是对齐约束
		if(pElfsym->st_shndx == SHN_ABS)
			printf("ABS\t\t");
		else if( pElfsym->st_shndx == SHN_COMMON )
            printf("SHN_COMMON\t\t");
        else
            printf("%u\t\t",pElfsym->st_shndx);

		printf("%s\n",pstr + pElfsym->st_name);	

		pElfsym++;
	}

	return;
}

char *rel_type[16] = {"NULL","S+A","S+A-P","G+A-P","L+A-P","NULL","S","S","B+A","S+A-GOT","GOT+A-P","UN","UN","UN","UN","UN"};

void analysis_relocation( Elf64_Word strindex,Elf64_Word relindex ){
    Elf64_Rel *pElfrel;

    int num = ((pElfShdr + relindex)->sh_size)/((pElfShdr + relindex)->sh_entsize);

	printf("     **************relocation info************     \n");

    pElfrel = (Elf64_Rel *)( pmap + (pElfShdr + relindex)->sh_offset );

    for( int i = 0; i < num; i++ ){
        printf("r_offset = %llx\t\t",pElfrel->r_offset); 
        //printf("%s\t\t\n",rel_type[ELF64_R_TYPE(pElfrel->r_info)]);
        printf("%s\t\t\n",rel_type[pElfrel->r_info & 0xF ]);
        pElfrel++;
    }

    return;
}

void analysis_relocationa( Elf64_Word symindex,Elf64_Word relindex,Elf64_Word strindex ){
    Elf64_Rela *pElfrela;

    int num = ((pElfShdr + relindex)->sh_size)/((pElfShdr + relindex)->sh_entsize);
    printf("size = %d\n",((pElfShdr + relindex)->sh_size));
    printf("ent_size = %d\n",((pElfShdr + relindex)->sh_entsize));

	printf("     *************relocationa info************     \n");

    pElfrela = (Elf64_Rela *)( pmap + (pElfShdr + relindex)->sh_offset );
    char *str_base = (char *)( pmap + (pElfShdr + Sym2Str[symindex])->sh_offset );

    Elf64_Sym *pElfSym = (Elf64_Sym *)( pmap + (pElfShdr + symindex)->sh_offset );
    //char *pSymStr = (char *)( pmap + (pElfShdr + Sym2Str[symindex])->sh_offset );


    int idx;

    for( int i = 0; i < num; i++ ){
        printf("r_offset = %llx\t\t",pElfrela->r_offset); 
        printf("%s\t\t",rel_type[ELF64_R_TYPE(pElfrela->r_info)]);
        idx = ELF64_R_SYM(pElfrela->r_info);
        if( idx ){
            char *s = str_base + pElfSym[idx].st_name;
            printf("%s\t\t\n",s);
        }else{
            printf("\n");
        }
        //printf("%s\t\t\n",rel_type[pElfrela->r_info & 0xF ]);
        pElfrela++;
    }

    return;
}

void analysis_link_info(int index){
	Elf64_Shdr *p = pElfShdr + index;
	switch(p->sh_type){
		case SHT_DYNAMIC:
            //此节中条目用到的字符表索引
			printf("strtab idx = %u\n",p->sh_link);
			break;
		case SHT_HASH:
            //此hash表所用符号表的索引
			printf("symtab idx = %u\n",p->sh_link);
			break;
		case SHT_REL:
            //相关符号表索引
			printf("symtab idx = %u\n",p->sh_link);
            //重定位所作用的节的索引
			printf("reltab idx = %u\n",p->sh_info);
            printf("UNDO\n");
            //analysis_relocation( p->sh_link,p->sh_info?p->sh_info:index );
            break;
		case SHT_RELA:
            //相关符号表索引
			printf("symtab idx = %u\n",p->sh_link);
            //重定位所作用的节的索引
			printf("reltab idx = %u\n",p->sh_info);
            analysis_relocationa( p->sh_link,index,p->sh_info );
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
            //字符表索引
			printf("strtab idx = %u\n",p->sh_link);
			printf("last local sym idx + 1= %u\n",p->sh_info);
			analysis_sym(p->sh_link,index);
			break;
		default:
			return;
	}
}

int dynstridx;
int gotpltidx;

void print_section(int index){
	Elf64_Shdr *p = &pElfShdr[index];

#ifdef PRINT
	printf("---------------------------------------------------------------\n");
	printf("index:%d\n",index);
    //sh_name是一个偏移，这个偏移相对于字符表第一个字节
	printf("%s\n",strtab + p->sh_name);
#endif
    //动态表/动态链接字符表/全局偏移.延迟加载表
	if(!strcmp(strtab + p->sh_name,".dynamic"))
		dynamicindex = index;
	if(!strcmp(strtab + p->sh_name,".dynstr"))
		dynstridx = index;
	if(!strcmp(strtab + p->sh_name,".got.plt"))
		gotpltidx = index;
#ifdef PRINT
    
    //内存偏移
	printf("virtual address(rva) = 0x%llx\n",p->sh_addr);
    //文件偏移
	printf("file offset = 0x%llx\n",p->sh_offset);
	printf("section size  = 0x%x\n",p->sh_size);
    //如果这个表中又是一个包含其他数据的表，那么entsize表示每个表项的大小
	printf("entsize  = %u\n",p->sh_entsize);
    //分析节类型
	analysis_sh_type(p->sh_type);
    //分析节的标志
	analysis_sh_flag(p->sh_flags);
    //分析节的额外信息，link会根据flag的不同有不同的含义
	analysis_link_info(index);
#endif
	return;
}


void print_section_inmem(int index){
	Elf64_Shdr *p = &pElfShdr[index];
	if( vbase == p->sh_addr + vbase )
		return;
#ifdef PRINT
	printf("--------------------in memory----------------------------------\n");
	printf("index:%d\n",index);
	printf("%s\n",strtab + p->sh_name);
#endif
	if(!strcmp(strtab + p->sh_name,".dynamic"))
		dynamicindex = index;
	if(!strcmp(strtab + p->sh_name,".dynstr"))
		dynstridx = index;
#ifdef PRINT
	printf("virtual address(rva) = 0x%llx\n",p->sh_addr + vbase);
	printf("section size  = 0x%x\n",p->sh_size);
	printf("entsize  = %u\n",p->sh_entsize);
	analysis_sh_type(p->sh_type);
	analysis_sh_flag(p->sh_flags);
	analysis_link_info(index);
#endif
	return;
}

#if 0
#endif

void analysis_section(){
    //节表的解析
    //此偏移是相对于elf映像第一个字节的偏移
	pElfShdr = (Elf64_Shdr *)(pmap + pElfhdr->e_shoff);
    //定位字符表

	Elf64_Shdr *pSstrtab = &pElfShdr[strtab_index];
	strtab = (char *)(pSstrtab->sh_offset + pmap);

	for(int i = 0 ; i < sh_num; i ++ ){
		print_section(i);
		//print_section_inmem(i);
	}
    

	printf("---------------------------------------------------------------\n");
	return;
}

void analysis_dynamic(){
	Elf64_Shdr *pSh = pElfShdr + dynamicindex;
	Elf64_Dyn *p =(Elf64_Dyn *)(pSh->sh_offset + pmap);
	int num = pSh->sh_size/pSh->sh_entsize;

	for( int i = 0 ; i < num; i++ ){
		//printf("%x\n",p->d_tag);
		if(p->d_tag == DT_NULL)
			break;
		if(p->d_tag == DT_SONAME)
			printf("sonameindex = %d\n",p->d_un.d_val);
		p++;
	}
    
    printf("dynamic analysis finish\n");

	return;
}


/*

void test(){
	Elf64_Shdr *pg = pElfShdr + 24;
    
	void *p = (void *)(pmap + pg->sh_offset);
	//printf("%llu\n",*(unsigned*)(p ));
	char *pstr = (char *)(pmap + (pElfShdr + dynstridx)->sh_offset);
	printf("%s\n",++pstr);
    return;
}



void getvbase(const char *p){
	for( int i = 0 ; i < 12; i ++ ){
		int tmp = 0;
		if( (p[i] >= 'a') && (p[i] <= 'z'))
			tmp = p[i] - 'a' + 10;
		else
			tmp = p[i] - '0';
		vbase *= 16;
		vbase += tmp;
	}
}
*/

unsigned long long getselfbase(){
	FILE *pf = fopen("/proc/self/maps","r");
	assert(pf);
	unsigned long long addr;
	fscanf(pf,"%llx",&addr);
	printf("base address is %llx\n",addr);
	vbase = addr;
	fclose(pf);
}


//内存中的形式,文件形式未试
void analysis_link(){
	assert(gotpltidx);
	assert(vbase);

	unsigned long long addr_lkmap = (&pElfShdr[gotpltidx])->sh_addr + vbase;
	printf("_DYNAMIC[]'s addr is %llx\n",*(unsigned long long *)addr_lkmap);
	printf("linkmap's addr is %llx\n",*(unsigned long long *)*(unsigned long long *)(addr_lkmap + 8));
	printf("dl_runtime_resolve's addr is %llx\n",*(unsigned long long *)(addr_lkmap + 16));
	
	struct link_map *plinkmap = (struct link_map *)*(unsigned long long *)(addr_lkmap + 8);
    assert( plinkmap );

	while(plinkmap){
        printf("------------------------\n");
		printf("name = %s\n",plinkmap->l_name);
		printf("addr = %llx\n",plinkmap->l_addr);
		if(!strcmp(plinkmap->l_name,"/lib/x86_64-linux-gnu/libpthread.so.0"))
			break;
		plinkmap = plinkmap->l_next;
	}
	printf("now at lib %s\n",plinkmap->l_name);

	Elf64_Dyn *pd = plinkmap->l_ld;

	
	unsigned long long int straddr = 0;
	unsigned long long int symaddr = 0;

	while(pd->d_tag != DT_NULL){
		if( pd->d_tag == DT_STRTAB )
			straddr = pd->d_un.d_ptr;
		if( pd->d_tag == DT_SYMTAB)
			symaddr = pd->d_un.d_ptr;
		pd++;
	}

	Elf64_Sym *pElfsym = (Elf64_Sym *)symaddr;
	int i = 0;
#if 1
	while( strncmp((char *)(pElfsym[i].st_name + straddr),"pthread_create",14) ){

		//printf("%s\n",(char *)((pElfsym + i)->st_name + straddr));
		i++;
        //if( find_sym("pthread_create") == -1 )
        //    assert(0);
    }
#endif

	printf("symbol name = %s\n",(char *)((pElfsym + i)->st_name + straddr));
	printf("symaddr's addr = %llx\n",(pElfsym + i)->st_value + plinkmap->l_addr);


	x = (pfn)((pElfsym + i)->st_value + plinkmap->l_addr);


	return;
}


void analysis_Dynamic( Elf64_Phdr *ph ){
    Elf64_Dyn *pDyn = (Elf64_Dyn *)( pmap + ph->p_offset );



    return;
}

Elf64_Phdr *pPhdr;

void print_program( int idx ){
     
    Elf64_Phdr *p = pPhdr + idx;
#ifdef PRINT
    printf("*******program head%d**********\n",idx);
    printf("RVA = %llx\n",p->p_vaddr);
    printf("file size = %llu\n",p->p_filesz);
    printf("file offset = %llu\n",p->p_offset);
    printf("memory size = %llu\n",p->p_memsz);
    printf("%c%c%c\n",p->p_flags&PF_R?'R':' ',p->p_flags&PF_W?'W':' ',p->p_flags&PF_X?'X':' ');
    switch( p->p_type ){
        case PT_NULL:
            printf("PT_NULL\n");
            break;
        case PT_LOAD:
            printf("PT_LOAD\n");
            break;
        case PT_DYNAMIC:
            //数组元素给出动态链接信息
            printf("PT_DYNAMIC\n");
            analysis_Dynamic( p );
            break;
        case PT_INTERP:
            //数组元素给出一个NULL结尾字符串位置及长度
            //该字符串为被当作解释器
            //此段仅可执行文件有意义
            printf("PT_INTERP\n");
            break;
        case PT_NOTE:
            printf("PT_NOTE\n");
            break;
        case PT_SHLIB:
            printf("PT_SHLIB\n");
            break;
        case PT_PHDR:
            printf("PT_PHDR\n");
            break;
        case PT_TLS:
            printf("PT_TLS\n");
            break;
        case PT_NUM:
            printf("PT_NUM\n");
            break;
        case PT_LOOS:
            printf("PT_LOOS\n");
            break;
        case PT_GNU_STACK:
            printf("PT_GNU_STACK\n");
            break;
        default:
            printf("ERROR TYPE\n");
            break;
/*
#define	PT_NULL		0		 Program header table entry unused 
#define PT_LOAD		1		 Loadable program segment 
#define PT_DYNAMIC	2		 Dynamic linking information 
#define PT_INTERP	3		 Program interpreter 
#define PT_NOTE		4		 Auxiliary information 
#define PT_SHLIB	5		 Reserved 
#define PT_PHDR		6		 Entry for header table itself 
#define PT_TLS		7		 Thread-local storage segment 
#define	PT_NUM		8		 Number of defined types 
#define PT_LOOS		0x60000000	 Start of OS-specific 
#define PT_GNU_EH_FRAME	0x6474e550	 GCC .eh_frame_hdr segment 
//描述栈的可执行属性(dep)，可由GCC-Wl,zexecstack控制
#define PT_GNU_STACK	0x6474e551	 Indicates stack executability 
#define PT_GNU_RELRO	0x6474e552	 Read-only after relocation 
#define PT_LOSUNW	0x6ffffffa
#define PT_SUNWBSS	0x6ffffffa	 Sun Specific segment
#define PT_SUNWSTACK	0x6ffffffb	 Stack segment 
#define PT_HISUNW	0x6fffffff
#define PT_HIOS		0x6fffffff	 End of OS-specific 
#define PT_LOPROC	0x70000000	 Start of processor-specific 
#define PT_HIPROC	0x7fffffff	 End of processor-specific 
*/

    }
#endif

    return;
}

void analysis_program_header(){
	//printf("program header table entry size  = %u\n",pElfhdr->e_phentsize);
    pPhdr = (Elf64_Phdr *)( pmap + pElfhdr->e_phoff );
    int num = pElfhdr->e_phnum;

    for( int i = 0; i < num; i++ )
        print_program( i );
    return;
}

int main(int argc,char **argv){

	getselfbase();

	printf("%llx\n",vbase);

	init();

	checkelf();

	analysis_head();

	analysis_section();

    analysis_program_header();

	analysis_link();

	//dynstridx = 29;
	//if( -1 != dynamicindex)
	//	analysis_dynamic();
	//test();

	munmap(pmap,18525);
	close(fd);

	pthread_t tid;
	x(&tid,NULL,thread_fun,NULL);


	//printf("addr of pthread_create is %llx\n",pthread_create);

    
	while(1);

	return 0;
}


#if 0 

  [号] 名称              类型             地址              偏移量
       大小              全体大小          旗标   链接   信息   对齐
  [10] .rela.plt         RELA             0000000000000540  00000540
       0000000000000030  0000000000000018  AI       5    24     8
  [11] .init             PROGBITS         0000000000000570  00000570
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         0000000000000590  00000590
       0000000000000030  0000000000000010  AX       0     0     16
  [13] .plt.got          PROGBITS         00000000000005c0  000005c0
       0000000000000008  0000000000000000  AX       0     0     8
  [14] .text             PROGBITS         00000000000005d0  000005d0
       00000000000001e2  0000000000000000  AX       0     0     16
  [22] .dynamic          DYNAMIC          0000000000200df0  00000df0
       00000000000001e0  0000000000000010  WA       6     0     8
  [23] .got              PROGBITS         0000000000200fd0  00000fd0
       0000000000000030  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000201000  00001000
       0000000000000028  0000000000000008  WA       0     0     8


555555554000-555555555000 r-xp 00000000 08:11 26741014                   /home/ghc/ptrace/gotplt/a.out
555555754000-555555755000 r--p 00000000 08:11 26741014                   /home/ghc/ptrace/gotplt/a.out
555555755000-555555756000 rw-p 00001000 08:11 26741014                   /home/ghc/ptrace/gotplt/a.out
基地址0x555555554000



=> 0x0000555555554708 <+8>:	mov    $0x80,%edi
   0x000055555555470d <+13>:	callq  0x5555555545b0 <malloc@plt>
   0x0000555555554712 <+18>:	mov    %rax,-0x8(%rbp)
   0x0000555555554716 <+22>:	lea    0xa7(%rip),%rsi        # 0x5555555547c4
   0x000055555555471d <+29>:	lea    0xa5(%rip),%rdi        # 0x5555555547c9
   0x0000555555554724 <+36>:	mov    $0x0,%eax
   0x0000555555554729 <+41>:	callq  0x5555555545a0 <printf@plt>

590开始是.plt的内容
   0x555555554590:	pushq  0x200a72(%rip)         # 0x555555755008
   0x555555554596:	jmpq   *0x200a74(%rip)        # 0x555555755010
   0x55555555459c:	nopl   0x0(%rax)
   0x5555555545a0 <printf@plt>:	jmpq   *0x200a72(%rip)        # 0x555555755018
   0x5555555545a6 <printf@plt+6>:	pushq  $0x0
   0x5555555545ab <printf@plt+11>:	jmpq   0x555555554590
   0x5555555545b0 <malloc@plt>:	jmpq   *0x200a6a(%rip)        # 0x555555755020
   0x5555555545b6 <malloc@plt+6>:	pushq  $0x1
   0x5555555545bb <malloc@plt+11>:	jmpq   0x555555554590

0x555555755000开始是.got.plt的内容
根据资料,.got.plt段是GLOBAL_OFFSET_TABLE,这个表有3项
.got.plt[0] = _DYNAMIC地址
.got.plt[1] = linkmap地址
.got.plt[2] = dl_runtime_resolve地址

0x555555755000:	0x00200df0	0x00000000	0xf7ffe170	0x00007fff
0x555555755010:	0xf7deeca0	0x00007fff	0x555545a6	0x00005555
0x555555755020:	0x555545b6	0x00005555	0x00000000	0x00000000
0x555555755030:	0x55755030	0x00005555	0x00000000	0x00000000

则上面的跳转跳之下面的那句pushq，最后转至0x555555554590,push linkmap，转至dl_runtime_resolve



struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;		/* Difference between the address in the ELF
				   file and the addresses in memory.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
  };

typedef struct dynamic{
  Elf32_Sword d_tag;
  union{
    Elf32_Sword	d_val;
    Elf32_Addr	d_ptr;
  } d_un;
} Elf32_Dyn;


#endif
