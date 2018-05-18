#include<stdio.h>
#include<windows.h>
#include<iostream>
#include<assert.h>
using namespace std;

char buff[40960];

DWORD PE_offset;
DWORD nSections;
DWORD nsizeOptHeader;
DWORD Characteristics; 
DWORD imageBase;
DWORD EntryPoint;	//RVA
DWORD BaseOfCode;	//RVA
DWORD BaseOfData;	//RVA
DWORD SizeOfImage;	//内存对齐 
DWORD SizeOfHeaders;
DWORD NumberOfDict;
DWORD PECheckSum;
DWORD DynamicCharacteristics;
IMAGE_DATA_DIRECTORY *pIDD;

IMAGE_DATA_DIRECTORY *pExport;
IMAGE_DATA_DIRECTORY *pImport;
IMAGE_DATA_DIRECTORY *pReloc;
IMAGE_DATA_DIRECTORY *pIAT;
IMAGE_DATA_DIRECTORY *pDelay;

void getFile(){
	HANDLE hFile = CreateFile("./be.exe",GENERIC_READ,
		0,NULL,OPEN_ALWAYS,0,NULL);
	if( !hFile ){
		cout<<"file open error"<<endl;
		assert(0);
		return;
	}
	DWORD nRead;
	ReadFile( hFile,buff,40960,&nRead,NULL );
	CloseHandle( hFile );
}

void de_DosHead(){
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)buff;
	
	char *MZ = (char *)&(pIDH->e_magic);
	assert( MZ[0] == 'M' );
	assert( MZ[1] == 'Z' );
	
	PE_offset = pIDH->e_lfanew;
	
	return;
}

void de_PeHead(){
	char *PE = (char *)(buff + PE_offset);
	
	assert( PE[0] == 'P' );
	assert( PE[1] == 'E' );
	assert( PE[2] == '\0' );
	assert( PE[3] == '\0' );
	
	IMAGE_FILE_HEADER *pIFH = (IMAGE_FILE_HEADER *)(PE + 4);
	//符号表相关的metadata也在这里
	
	nSections = pIFH->NumberOfSections;
	nsizeOptHeader = pIFH->SizeOfOptionalHeader;
	Characteristics = pIFH->Characteristics; 
	
	cout<<"Characteristics: "<<hex<<Characteristics<<endl;
	return;
}

void de_PeOptHead(){
	
	IMAGE_OPTIONAL_HEADER32 *pIOH = (IMAGE_OPTIONAL_HEADER32 *)
		(buff + PE_offset + 4 + sizeof(IMAGE_FILE_HEADER)); 

	DWORD nsizeCode = pIOH->SizeOfCode;	//文件对齐 
	DWORD nsizeData = pIOH->SizeOfInitializedData;
	DWORD nsizeBss = pIOH->SizeOfUninitializedData;
	
	imageBase = pIOH->ImageBase;
	
	EntryPoint = pIOH->AddressOfEntryPoint;
	BaseOfCode = pIOH->BaseOfCode;
	BaseOfData = pIOH->BaseOfData;
	
	DWORD MemAlign = pIOH->SectionAlignment;
	DWORD FileAlign = pIOH->FileAlignment;

	SizeOfImage = pIOH->SizeOfImage;
	SizeOfHeaders = pIOH->SizeOfHeaders;
	
	NumberOfDict = pIOH->NumberOfRvaAndSizes;
	PECheckSum = pIOH->CheckSum;
	DynamicCharacteristics = pIOH->DllCharacteristics;
	
	pIDD = pIOH->DataDirectory; 
	
	return; 
}

void de_DynmicChar(){
	if(DynamicCharacteristics & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE)
		cout<<"IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE"<<endl;
	if(DynamicCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
		cout<<"WDM Driver"<<endl;
	if(DynamicCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
		cout<<"NO SEH"<<endl;
	if(DynamicCharacteristics & IMAGE_DLL_CHARACTERISTICS_NX_COMPAT)
		cout<<"IMAGE_DLL_CHARACTERISTICS_NX_COMPAT"<<endl;
	return;
}

void de_DataDict(){
	
	IMAGE_DATA_DIRECTORY *p = pIDD;
	for( int i = 0 ; i < NumberOfDict; i++ ){
		cout<<"RVA = 0x"<<hex<<p[i].VirtualAddress<<endl;
		cout<<"SIZE = 0x"<<hex<<p[i].Size<<endl<<endl;
	}
	
	pExport = &pIDD[0];
	pImport = &pIDD[1];
	pReloc = &pIDD[5];
	pIAT = &pIDD[12];
	pDelay = &pIDD[13];
	
	return;
}

void de_Section(){
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)(
		buff + PE_offset + 4 + sizeof(IMAGE_FILE_HEADER)
			+ nsizeOptHeader);
	
	DWORD SectionChara;
	for( int i = 0; i < nSections; i++,pISH++ ){
		cout<<pISH->Name<<endl;
		cout<<"RVA: "<<hex<<pISH->VirtualAddress<<endl;
		cout<<"SizeInFile Align: "<<hex<<pISH->SizeOfRawData<<endl;
		cout<<"OffsetInFile: "<<hex<<pISH->PointerToRawData<<endl;
		
		cout<<"Misc: 0x"<<hex<<pISH->Misc.VirtualSize<<endl;;
		SectionChara = pISH->Characteristics;
		if( SectionChara & IMAGE_SCN_CNT_CODE )
			cout<<"code ";
		if( SectionChara & IMAGE_SCN_CNT_INITIALIZED_DATA )
			cout<<"initData ";
		if( SectionChara & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
			cout<<"unInitData ";
		if( SectionChara & IMAGE_SCN_MEM_DISCARDABLE )
			cout<<"discardable ";
		if( SectionChara & IMAGE_SCN_MEM_WRITE )
			cout<<"write ";
		if( SectionChara & IMAGE_SCN_MEM_READ )
			cout<<"read ";
		if( SectionChara & IMAGE_SCN_MEM_EXECUTE )
			cout<<"exec ";
		if( SectionChara & IMAGE_SCN_MEM_SHARED )
			cout<<"shared ";
		if( SectionChara & IMAGE_SCN_MEM_NOT_PAGED )
			cout<<"notPaged ";
			
		cout<<endl;
		cout<<endl;
	}
	 
	return;
}

DWORD R2F( DWORD rva,int &SectionIdx ){
	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)(
		buff + PE_offset + 4 + sizeof(IMAGE_FILE_HEADER)
			+ nsizeOptHeader);
	for( int i = 0; i < nSections; i++,pISH++ ){
		if( (rva >= pISH->VirtualAddress) && 
			(rva <= pISH->VirtualAddress + pISH->SizeOfRawData)){
				SectionIdx = i;
				return ( pISH->PointerToRawData + rva - pISH->VirtualAddress);
			}
	}
	return 0;
}
 
void de_ImportF(){
	
	DWORD rva = pImport->VirtualAddress;
	DWORD nsize = pImport->Size;
	int idx = -1;
	DWORD fileOffset = R2F( rva,idx );
	
	IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)(buff + fileOffset);
		
	cout<<fileOffset<<endl;
	char *pname;
	while( pIID->Name != 0 ){
		pname = buff + R2F( pIID->Name,idx );

		cout<<pname<<endl;
		
		DWORD OriginalThunk = pIID->OriginalFirstThunk;
		DWORD Thunk = pIID->FirstThunk;
		
		IMAGE_THUNK_DATA *pITA = (IMAGE_THUNK_DATA *)(buff + R2F( OriginalThunk ,idx ));
		DWORD tmp = 0;
		while( (tmp = *(DWORD *)pITA) != 0 ){
			IMAGE_IMPORT_BY_NAME *pIIBN = (IMAGE_IMPORT_BY_NAME *)(buff + R2F( tmp ,idx ));
			cout<<pIIBN->Name<<endl;
			pITA++;
		}
		 
		cout<<endl;
		pIID++;
	}
	
	return;	
}

void de_ImportM(){
	
	DWORD va = pImport->VirtualAddress + imageBase;
	DWORD nsize = pImport->Size;
	
	IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)(va);

	char *pname;
	while( pIID->Name != '\0' ){
		//按名字导入 
		assert( !(pIID->Name & 0x80000000) );
		pname = (char *)(imageBase + pIID->Name);
		cout<<pname<<endl;
 
		DWORD OriginalThunk = pIID->OriginalFirstThunk;
		DWORD Thunk = pIID->FirstThunk;
		DWORD *pIAT = (DWORD *)(imageBase + Thunk);
		IMAGE_THUNK_DATA *pITA = (IMAGE_THUNK_DATA *)
			(imageBase + OriginalThunk);
		DWORD tmp = 0;
 
		while( (tmp = *(DWORD *)pITA) != 0 ){
			IMAGE_IMPORT_BY_NAME *pIIBN = (IMAGE_IMPORT_BY_NAME *)
				(imageBase + tmp);
			cout<<pIIBN->Name<<"\t\t\t";
			cout<<hex<<"0x"<<*pIAT<<endl;
			
			pIAT++;	
			pITA++;
		}

		cout<<endl;
		pIID++;
	}
	return;
}


void de_ldr(){
	unsigned peb = 0xffffabcd;
	unsigned ldr = 0xffffabcd;
	cout<<hex;
	
	//获取peb
    __asm__ __volatile__("movl %%fs:0x30,%0":"=r"(peb):);
  	 
	unsigned aldr = peb + 0xc;
    	
	//获取ldr
	__asm__ __volatile__("movl (%1),%%eax":"=a"(ldr):"r"(aldr));

	/*
		24	加载地址
		28	入口地址
		36	unicode_code fullname 
	*/
	unsigned pLoadOrderFirst = *(unsigned *)(ldr + 0xc);
	cout<<*(unsigned *)(pLoadOrderFirst + 24)<<endl;
	cout<<*(unsigned *)(pLoadOrderFirst + 28)<<endl;
	cout<<*(unsigned short*)(pLoadOrderFirst + 36)<<endl;
	wchar_t *pname = (wchar_t *)*(unsigned *)(pLoadOrderFirst + 40);
	printf("%ws\n",pname);
	cout<<*(unsigned short*)(pLoadOrderFirst + 38)<<endl;
	return;
}



//fs~TEB
int main(){
	 
	getFile();
	de_DosHead();
	de_PeHead();
	de_PeOptHead();
	de_DynmicChar();
	de_DataDict();
	de_Section();
	
	de_ImportF();
	//de_ImportM();

	
	 
	return 0;
}
