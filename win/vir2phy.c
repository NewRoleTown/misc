#include "ntddk.h"
#include <windef.h>
#include <ntimage.h>

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
		MmUnmapIoSpace( ppgd,4 * sizeof(unsigned) * 2 );
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
		MmUnmapIoSpace( ppgd,4 * sizeof(unsigned) * 2 );
		MmUnmapIoSpace( ppud,4096 );
		DbgPrint("[DDK-->vir2phy:MmMapIoSpace fail2]\n");
		return 0;
	}
	
	//次高9位
	pmd_offset = ((vir >> 12) & 0x1ff);
	tmp = *(ppmd + pmd_offset * 2);
	DbgPrint("[DDK-->vir2phy:pt %x]\n",tmp);
	tmp = (tmp & 0xfffff000);

	phy_pt.LowPart = tmp;

	
	MmUnmapIoSpace( ppgd,4 * sizeof(unsigned) * 2 );
	MmUnmapIoSpace( ppud,4096 );
	MmUnmapIoSpace( ppmd,4096 );

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

PEPROCESS getProcess( unsigned pid ){
	PEPROCESS process=NULL;
	PEPROCESS firstProcess=NULL;
	PKPROCESS kprocess = NULL;
	unsigned int pgd  = 0;

	process = firstProcess = PsGetCurrentProcess();
	do{
		//DbgPrint("%s\t%d\t%x\n",(char *)process + 0x16c,*(int *)((char *)process + 0xb4),*(unsigned *)((char *)process + 0x18) );
		if( pid == *(unsigned *)((char *)process + 0xb4) ){
			DbgPrint("FIND TARGET");
			return process;
		}

		process = (PEPROCESS)((*(unsigned *)((char *)process + 0xb8)) - 0xb8);
	}while( process != firstProcess  );

	return NULL;
	/*
	kprocess = (PKPROCESS)process;
	pgd = *(unsigned *)((char *)kprocess + 0x18);
	DbgPrint("pgd = %x\n",pgd);
	*/
}



typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
	PBYTE Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_MODULE_INFO_LIST
{
	ULONG ulCount;
	SYSTEM_MODULE_INFORMATION smi[1];
} SYSTEM_MODULE_INFO_LIST, *PSYSTEM_MODULE_INFO_LIST;

NTSTATUS __stdcall ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

ULONG OldImageBase=0;
ULONG ImageBase=0;
int NtosVersion = 0xffffffff;

wchar_t NtosVersionName[4][128]={L"\\??\\C:\\WINDOWS\\system32\\ntoskrnl.exe",L"\\??\\C:\\WINDOWS\\system32\\ntkrnlpa.exe",
	L"\\??\\C:\\WINDOWS\\system32\\ntkrnlmp.exe",L"\\??\\C:\\WINDOWS\\system32\\ntkrpamp.exe"};
char NtosVersionNameA[4][128]={"C:\\WINDOWS\\system32\\ntoskrnl.exe","C:\\WINDOWS\\system32\\ntkrnlpa.exe",
	"C:\\WINDOWS\\system32\\ntkrnlmp.exe","C:\\WINDOWS\\system32\\ntkrpamp.exe"};

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

ServiceDescriptorTableEntry_t  *pNewSSDT;



NTSTATUS GetKernelModuleInfo()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSYSTEM_MODULE_INFO_LIST pSysModInfoList = NULL;
	ULONG ulLength = 0;

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysModInfoList, ulLength, &ulLength);
	if(status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return STATUS_UNSUCCESSFUL;
	}

	pSysModInfoList = (PSYSTEM_MODULE_INFO_LIST)ExAllocatePool(NonPagedPool, ulLength);
	if(NULL == pSysModInfoList)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pSysModInfoList, ulLength, &ulLength);
	if(!NT_SUCCESS(status))
	{
		ExFreePool(pSysModInfoList);
		return STATUS_UNSUCCESSFUL;
	}

	OldImageBase=(ULONG)pSysModInfoList->smi[0].Base;

	if(strstr(pSysModInfoList->smi[0].ImageName,"ntoskrnl.exe"))
	{
		NtosVersion=0;
	}
	if(strstr(pSysModInfoList->smi[0].ImageName,"ntkrnlpa.exe"))
	{
		NtosVersion=1;
	}
	if(strstr(pSysModInfoList->smi[0].ImageName,"ntkrnlmp.exe"))
	{
		NtosVersion=2;
	}
	if(strstr(pSysModInfoList->smi[0].ImageName,"ntkrpamp.exe"))
	{
		NtosVersion=3;
	}
	ExFreePool(pSysModInfoList);
	
	DbgPrint("Leave GetKernelModuleInfo [%d]\n",NtosVersion);
	return STATUS_SUCCESS;
}


int IsGetSSDT = 0;
ULONG SSDTNumber=0;
KIRQL Irql;

typedef struct _SSDTInformation
{
	ULONG index;
	ULONG CurrentAddress;
	ULONG OriginalAddress;
	char FunctionName[16];  //函数名
	char KernelMouduleName[64];  //内核模块名
	ULONG KernelMouduleBase;  //内核模块基址
}SSDTInformation,*PSSDTInformation;
PSSDTInformation SSDT = NULL;

VOID SetNewSSDT(PVOID pNewImage)
{

	ULONG              uIndex;
	ULONG              uNewKernelInc,uOffset;
	//新内核地址-老内核地址，得到相对偏移
	uNewKernelInc = (ULONG)pNewImage -OldImageBase;
	
	//老内核的ssdt指针加上相对偏移，得到新内核的ssdt指针
	pNewSSDT = (ServiceDescriptorTableEntry_t *)((ULONG)&KeServiceDescriptorTable + uNewKernelInc);
	
	if (!MmIsAddressValid(pNewSSDT))
	{
		KdPrint(("pNewSSDT is unaviable!"));
		return;
	}
	
	//由于数量是一个数值，因此不必作相对偏移
	pNewSSDT->NumberOfServices = KeServiceDescriptorTable.NumberOfServices;
	//计算相对函数地址
	uOffset = (ULONG)KeServiceDescriptorTable.ServiceTableBase -OldImageBase;
	//得到新的ssdt函数表地址
	pNewSSDT->ServiceTableBase = (unsigned int*)((ULONG)pNewImage + uOffset);

	if (!MmIsAddressValid(pNewSSDT->ServiceTableBase))
	{
		KdPrint(("pNewSSDT->ServiceTableBase: %X",pNewSSDT->ServiceTableBase));
		return;
	}

	//依次遍历
	for (uIndex = 0;uIndex<pNewSSDT->NumberOfServices;uIndex++)
	{  //新的函数地址再加上相对加载地址，得到现在的ssdt函数地址
		pNewSSDT->ServiceTableBase[uIndex] = pNewSSDT->ServiceTableBase[uIndex]-ImageBase+OldImageBase;
		DbgPrint("%d->%08x\n",uIndex,pNewSSDT->ServiceTableBase[uIndex]);  //打印SSDT索引号和地址
	}

	//
	//保存SSDT信息
	//
	SSDT = (PSSDTInformation)ExAllocatePool(NonPagedPool,sizeof(SSDTInformation)*pNewSSDT->NumberOfServices);
	if(SSDT==NULL)
	{
		DbgPrint("申请内存失败\n");
		return;
	}
	else
	{
		IsGetSSDT = 1;
	}
	for (uIndex = 0;uIndex<pNewSSDT->NumberOfServices;uIndex++)
	{ 
		SSDT[uIndex].index = uIndex;  //序号
		SSDT[uIndex].OriginalAddress=pNewSSDT->ServiceTableBase[uIndex];  //原始地址
		SSDT[uIndex].CurrentAddress=KeServiceDescriptorTable.ServiceTableBase[uIndex];
	}

	SSDTNumber=pNewSSDT->NumberOfServices;  //有多少项
	return;
}

HANDLE FileHandle;
IO_STATUS_BLOCK ioStatus;
FILE_STANDARD_INFORMATION FileInformation;
int GetSSDTName()
{
	NTSTATUS Status;
	UNICODE_STRING uniFileName;
	ULONG uFileSize;
	PVOID pBuffer;
	LARGE_INTEGER byteOffset;
	OBJECT_ATTRIBUTES objectAttributes;
	PIMAGE_DOS_HEADER  pDosHeader;
	PIMAGE_NT_HEADERS  pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	ULONG     FileOffset;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	PIMAGE_SECTION_HEADER pOldSectionHeader;
	PUSHORT AddressOfNameOrdinals;
	ULONG uNameOffset;
	ULONG uOffset;
	LPSTR FunName;
	PVOID pFuncAddr;
	ULONG uServerIndex;
	ULONG uAddressOfNames;
	WORD Index;
	PULONG AddressOfFunctions;
	PULONG AddressOfNames;
	ULONG uIndex;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return -1;
	}

	if( 0 == IsGetSSDT ){
		DbgPrint("no SSDT\n");
		return -1;
	}

	//设置NTDLL路径
	RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntdll.dll");

	//初始化打开文件的属性
	InitializeObjectAttributes(&objectAttributes, &uniFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	////创建文件

	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes,
		&ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("IoCreateFile failed！status:0x%08x\n", Status);
		return -1;
	}

	//获取文件信息
	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation,
		sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwQueryInformationFile failed！status:0x%08x\n", Status);
		ZwClose( FileHandle );
		return -1;
	}
	//判断文件大小是否过大
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		DbgPrint("File Size Too High");
		ZwClose(FileHandle);
		return -1;
	}
	
	//取文件大小
	uFileSize = FileInformation.EndOfFile.LowPart;
	//分配内存
	pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize, (ULONG)"NTDLL");
	if (pBuffer == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag() == NULL");
		ZwClose(FileHandle);
		return -1;
	}

	//从头开始读取文件
	
	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwReadFile failed！status:0x%08x\n", Status);
		ZwClose(FileHandle);
		return -1;
	}


	//DLL内存数据转成DOS头结构
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	//取出PE头结构
	pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)pBuffer + pDosHeader->e_lfanew);
	//判断PE头导出表表是否为空
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		DbgPrint("VirtualAddress == 0");
		return -1;
	}
	//取出导出表偏移
	FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//取出节头结构
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	pOldSectionHeader = pSectionHeader;
	//遍历节结构进行地址运算
	for ( Index = 0;Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	//导出表地址
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG)pBuffer + FileOffset);
	//取出导出表函数地址
	FileOffset = pExportDirectory->AddressOfFunctions;
	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;

	for ( Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfFunctions = (PULONG)((ULONG)pBuffer + FileOffset);

	//取出导出表函数名字

	FileOffset = pExportDirectory->AddressOfNameOrdinals;
	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for ( Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfNameOrdinals = (PUSHORT)((ULONG)pBuffer + FileOffset);
	//取出导出表函数序号
	FileOffset = pExportDirectory->AddressOfNames;
	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for ( Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfNames = (PULONG)((ULONG)pBuffer + FileOffset);
	//分析导出表

	for ( uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
	{
		uAddressOfNames = *AddressOfNames;
		pSectionHeader = pOldSectionHeader;
		for ( Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
		{
			if (pSectionHeader->VirtualAddress <= uAddressOfNames &&
				uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			{
				uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			}
		}
		FunName = (LPSTR)((ULONG)pBuffer + uOffset);

		if (FunName[0] == 'Z' && FunName[1] == 'w')
		{
			pSectionHeader = pOldSectionHeader;
			uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
			for ( Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
			{
				if (pSectionHeader->VirtualAddress <=  uOffset&&
					uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
				{
					uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
				}
			}
			pFuncAddr = (PVOID)((ULONG)pBuffer + uNameOffset);
			uServerIndex = *(PULONG)((ULONG)pFuncAddr + 1);
			FunName[0] = 'N';
			FunName[1] = 't';
			//KdPrint(("序列号为：%d,函数名为: %s\n", uServerIndex, FunName));
			RtlCopyMemory(SSDT[uServerIndex].FunctionName,FunName,sizeof(char)*15);  //保存函数名
			SSDT[uServerIndex].KernelMouduleBase=OldImageBase;  //保存内核模块基址
			RtlCopyMemory(SSDT[uServerIndex].KernelMouduleName,NtosVersionNameA[NtosVersion],sizeof(char)*63);  //保存内核模块名

		}

	}
	ExFreePoolWithTag(pBuffer , (ULONG)"NTDLL");
	ZwClose(FileHandle);

	return 0;
}

int LoadKernel()
{
	NTSTATUS          status;
	UNICODE_STRING        uFileName;
	HANDLE            hFile;
	OBJECT_ATTRIBUTES      ObjAttr;
	IO_STATUS_BLOCK        IoStatusBlock;
	LARGE_INTEGER        FileOffset;
	ULONG            retsize;
	PVOID            lpVirtualPointer;
	ULONG            uLoop;
	ULONG            SectionVirtualAddress,SectionSize;
	IMAGE_DOS_HEADER		*ImageDosHeader;
	IMAGE_NT_HEADERS		*ImageNtHeader;
	IMAGE_SECTION_HEADER	*lpImageSectionHeader;
	
	InitializeObjectAttributes( &ObjAttr,&uFileName,OBJ_CASE_INSENSITIVE,NULL,NULL );
	RtlInitUnicodeString( &uFileName,NtosVersionName[NtosVersion] );

	status = ZwCreateFile(&hFile,GENERIC_READ,&ObjAttr,&IoStatusBlock,0,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN,FILE_NON_DIRECTORY_FILE,NULL,0);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("CreateFile Failed!\n"));
		return -1;
	}

	//读取DOS头
	FileOffset.QuadPart = 0;
	ImageDosHeader=(IMAGE_DOS_HEADER *)ExAllocatePool(NonPagedPool, sizeof(IMAGE_DOS_HEADER));  //记得释放
	
	status = ZwReadFile(hFile,NULL,NULL,NULL,&IoStatusBlock,ImageDosHeader,sizeof(IMAGE_DOS_HEADER),&FileOffset,0);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("Read ImageDosHeader Failed!"));
		ZwClose(hFile);
		return -1;
	}

	//读取NT头
	ImageNtHeader=(IMAGE_NT_HEADERS *)ExAllocatePool(NonPagedPool, sizeof(IMAGE_NT_HEADERS));  //记得释放
	FileOffset.QuadPart = ImageDosHeader->e_lfanew;
	status = ZwReadFile(hFile,NULL,NULL,NULL,&IoStatusBlock,ImageNtHeader,sizeof(IMAGE_NT_HEADERS),&FileOffset,0);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("Read ImageNtHeaders Failed!"));
		ZwClose(hFile);
		return -1;
	}

	//image base
	ImageBase=ImageNtHeader->OptionalHeader.ImageBase;

	//读取区表
	lpImageSectionHeader = (IMAGE_SECTION_HEADER *)ExAllocatePool(NonPagedPool,sizeof(IMAGE_SECTION_HEADER)*ImageNtHeader->FileHeader.NumberOfSections);
	FileOffset.QuadPart += sizeof(IMAGE_NT_HEADERS);
	status = ZwReadFile(hFile,NULL,NULL,NULL,&IoStatusBlock,lpImageSectionHeader,sizeof(IMAGE_SECTION_HEADER)*ImageNtHeader->FileHeader.NumberOfSections,&FileOffset,0);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("Read ImageSectionHeader Failed!"));
		ExFreePool(lpImageSectionHeader);
		ZwClose(hFile);
		return -1;
	}
	
	//COPY数据到内存
	lpVirtualPointer = ExAllocatePool(NonPagedPool,ImageNtHeader->OptionalHeader.SizeOfImage);
	if(lpVirtualPointer == 0)
	{
		KdPrint(("lpVirtualPointer Alloc space Failed!"));
		ZwClose(hFile);
		return -1;
	}
	
	memset(lpVirtualPointer,0,ImageNtHeader->OptionalHeader.SizeOfImage);

	//COPY DOS头
	RtlCopyMemory(lpVirtualPointer,ImageDosHeader,sizeof(IMAGE_DOS_HEADER));
	//COPY NT头
	RtlCopyMemory((PVOID)((ULONG)lpVirtualPointer+ImageDosHeader->e_lfanew),ImageNtHeader,sizeof(IMAGE_NT_HEADERS));
	//COPY 区表
	RtlCopyMemory((PVOID)((ULONG)lpVirtualPointer+ImageDosHeader->e_lfanew+sizeof(IMAGE_NT_HEADERS)),
		lpImageSectionHeader,sizeof(IMAGE_SECTION_HEADER)*ImageNtHeader->FileHeader.NumberOfSections);
	
	//依次COPY 各区段数据
	for(uLoop = 0;uLoop < ImageNtHeader->FileHeader.NumberOfSections;uLoop++)
	{
		SectionVirtualAddress = lpImageSectionHeader[uLoop].VirtualAddress;//对应区段相对偏移

		if(lpImageSectionHeader[uLoop].Misc.VirtualSize > lpImageSectionHeader[uLoop].SizeOfRawData)
			SectionSize = lpImageSectionHeader[uLoop].Misc.VirtualSize;//取最大的占用空间
		else
			SectionSize = lpImageSectionHeader[uLoop].SizeOfRawData;

		FileOffset.QuadPart = lpImageSectionHeader[uLoop].PointerToRawData;//对应区段的超始地址
		status = ZwReadFile(hFile,NULL,NULL,NULL,&IoStatusBlock,(PVOID)((ULONG)lpVirtualPointer+SectionVirtualAddress),SectionSize,&FileOffset,0);
		if(!NT_SUCCESS(status))
		{
			KdPrint(("SectionData Read Failed!"));
			ExFreePool(lpImageSectionHeader);
			ExFreePool(lpVirtualPointer);
			ZwClose(hFile);
			return -1;
		}
	}
	
	SetNewSSDT(lpVirtualPointer);
	ExFreePool(lpImageSectionHeader);//释放区段内存空间
	ExFreePool(ImageNtHeader);
	ZwClose(hFile);//关闭句柄
	
	return 0;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath) 
{

	NTSTATUS status = STATUS_SUCCESS;
	int i = 0;
	
	DbgPrint("[DDK:In Driver Entry]\n");

	
	if( !NT_SUCCESS(GetKernelModuleInfo()) ){
		DbgPrint("GetKernelModuleInfo Error\n");
		return status;
	}

	if( LoadKernel() ){
		return status;
	}

	if( GetSSDTName() ){
		return status;
	}

	for(;i<SSDTNumber;i++)
	{
		DbgPrint("id:%d 当前地址:%08x 原始地址:%08x 函数名:%s\n",
			SSDT[i].index,SSDT[i].CurrentAddress,SSDT[i].OriginalAddress,SSDT[i].FunctionName);
	}



	DbgPrint("[DDK:Leave Driver Entry]\n");
	return status; 
}
