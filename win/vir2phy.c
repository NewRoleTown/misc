#include "ntddk.h"

//3级表,32位地址
unsigned int vir2phy3_32( unsigned int pgd, unsigned int vir ){
	PHYSICAL_ADDRESS phy_pgd = {0};
	PHYSICAL_ADDRESS phy_pud = {0};
	PHYSICAL_ADDRESS phy_pmd = {0};
	PHYSICAL_ADDRESS phy_pt = {0};

	unsigned *ppud = NULL;
	unsigned *ppgd = NULL;
	unsigned *ppmd = NULL;
	unsigned *ppt = NULL;

	unsigned tmp = 0;
	unsigned pgd_offset = 0;
	unsigned pud_offset = 0;
	unsigned pmd_offset = 0;

	phy_pgd.LowPart = pgd;

	ppgd = (unsigned *)MmMapIoSpace( phy_pgd,4 * sizeof(unsigned) * 2,MmNonCached );

	if( !ppgd ){
		DbgPrint("[DDK-->vir2phy:MmMapIoSpace fail0]\n");
		return 0;
	}
	//最高2位
	pgd_offset = (vir >> 30);
	tmp = *(ppgd + pgd_offset * 2);
	DbgPrint("[DDK-->vir2phy:pud %x]\n",tmp);
	tmp = (tmp & 0xfffff000);

	phy_pud.LowPart = tmp;
	

	ppud = (unsigned *)MmMapIoSpace( phy_pud,4096,MmNonCached );

	if( !ppud ){
		DbgPrint("[DDK-->vir2phy:MmMapIoSpace fail1]\n");
		return 0;
	}

	//次高9位
	pud_offset = ((vir >> 21) & 0x1ff);
	tmp = *(ppud + pud_offset * 2);
	DbgPrint("[DDK-->vir2phy:pmd %x]\n",tmp);
	tmp = (tmp & 0xfffff000);

	phy_pmd.LowPart = tmp;
	
	ppmd = (unsigned *)MmMapIoSpace( phy_pmd,4096,MmNonCached );
	
	if( !ppmd ){
		DbgPrint("[DDK-->vir2phy:MmMapIoSpace fail2]\n");
		return 0;
	}
	
	//次高9位
	pmd_offset = ((vir >> 12) & 0x1ff);
	tmp = *(ppmd + pmd_offset * 2);
	DbgPrint("[DDK-->vir2phy:pt %x]\n",tmp);
	tmp = (tmp & 0xfffff000);

	phy_pt.LowPart = tmp;

	return tmp;
	/*
	ppt = (unsigned *)MmMapIoSpace( phy_pt,4096,MmNonCached );

	if( !ppt ){
		DbgPrint("[DDK-->vir2phy:MmMapIoSpace fail3]\n");
		return 0;
	}

	DbgPrint("[DDK-->vir2phy:ret = %x]\n",*(unsigned *)((char *)ppt + (vir & 0xfff)));
	*(unsigned *)((char *)ppt + (vir & 0xfff)) = 0x40100;
	*/
	
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath) 
{


	PEPROCESS process=NULL;
	PEPROCESS firstProcess=NULL;
	PKPROCESS kprocess = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	unsigned int pgd  = 0;

#if 1
	unsigned int _cr3 = 0;
	_asm{
		mov eax,cr3;
		mov _cr3,eax;
	}
#endif

	process = firstProcess = PsGetCurrentProcess();

	DbgPrint("[DDK:In Driver Entry]\n");

	do{
		DbgPrint("%s\t%d\t%x\n",(char *)process + 0x16c,*(int *)((char *)process + 0xb4),*(unsigned *)((char *)process + 0x18) );

		if( 2888 == *(int *)((char *)process + 0xb4) ){
			DbgPrint("FIND TARGET");
			break;
		}

		process = (PEPROCESS)((*(unsigned *)((char *)process + 0xb8)) - 0xb8);
	}while( process != firstProcess  );
	


	kprocess = (PKPROCESS)process;
	pgd = *(unsigned *)((char *)kprocess + 0x18);

	DbgPrint("%x,%x\n",_cr3,pgd);
	vir2phy3_32( pgd,0x402000 );
	

	DbgPrint("[DDK:Leave Driver Entry]\n");
	return status; 
}
