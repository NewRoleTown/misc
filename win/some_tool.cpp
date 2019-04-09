
// win32hpDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "win32hp.h"
#include "win32hpDlg.h"
#include "afxdialogex.h"
#include "tlhelp32.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// Cwin32hpDlg 对话框




Cwin32hpDlg::Cwin32hpDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(Cwin32hpDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void Cwin32hpDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(Cwin32hpDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_RM_START, &Cwin32hpDlg::OnBnClickedRmStart)
	ON_BN_CLICKED(IDC_RM_NT, &Cwin32hpDlg::OnBnClickedRmNt)
	ON_BN_CLICKED(IDC_CODE_INJECT, &Cwin32hpDlg::OnBnClickedCodeInject)
	ON_BN_CLICKED(IDC_PE_START, &Cwin32hpDlg::OnBnClickedPeStart)
	ON_BN_CLICKED(IDC_NEW_SEC_INJECT, &Cwin32hpDlg::OnBnClickedNewSecInject)
	ON_BN_CLICKED(IDC_MOD_EMU, &Cwin32hpDlg::OnBnClickedModEmu)
	ON_BN_CLICKED(IDC_BTN_DLLH, &Cwin32hpDlg::OnBnClickedBtnDllh)
	ON_BN_CLICKED(IDC_BTN_GETOEP, &Cwin32hpDlg::OnBnClickedBtnGetoep)
END_MESSAGE_MAP()


// Cwin32hpDlg 消息处理程序

BOOL Cwin32hpDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码




	if( 0 == EnableDebugPrivilege() ){
		MessageBox("提权失败");
	}
	GetDlgItem(IDC_RM_DLL_PATH)->SetWindowText("C:\\Users\\Lenovo\\Desktop\\WaiGuaDll.dll");
	GetDlgItem(IDC_ED_REALDLL)->SetWindowText("C:\\Users\\Lenovo\\Desktop\\lcsetup.dll");


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void Cwin32hpDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR Cwin32hpDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


int Cwin32hpDlg::InjectByNtCreateThreadEx( const char *dllPath, DWORD Pid ){

	HANDLE hThread;
	DWORD pfun_NtCreateThreadEx = (DWORD)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if( !pfun_NtCreateThreadEx ){
		return -1;
	}


	return 0;
}


int Cwin32hpDlg::InjectByRemoteThread( const char *dllPath, DWORD Pid ){
	HANDLE TargetHandle,ThreadHandle;
	char *p;
	DWORD ret;
	LPTHREAD_START_ROUTINE pLoadLibrary;


	TargetHandle = OpenProcess( PROCESS_ALL_ACCESS,0,Pid );
	if( INVALID_HANDLE_VALUE == TargetHandle )
		return -1;

	p = (char *)VirtualAllocEx( TargetHandle,NULL,strlen(dllPath) + 1,MEM_COMMIT,PAGE_READWRITE );
	if( !p )
		return -2;

	ret = WriteProcessMemory( TargetHandle,p,dllPath,strlen(dllPath) + 1,NULL );
	if( !ret ){
		VirtualFreeEx( TargetHandle,p,strlen(dllPath) + 1,MEM_DECOMMIT );
		return -3;
	}

	pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress( GetModuleHandle("kernel32.dll"),"LoadLibraryA" );
	if( INVALID_HANDLE_VALUE == pLoadLibrary )
		return -4;

	ThreadHandle = CreateRemoteThread( TargetHandle,NULL,0,pLoadLibrary,p,0,NULL );
	if( INVALID_HANDLE_VALUE == ThreadHandle ){
		VirtualFreeEx( TargetHandle,p,strlen(dllPath) + 1,MEM_DECOMMIT );
		return -5;
	}

	CloseHandle( TargetHandle );
	return 0;
}

int Cwin32hpDlg::txt2code( unsigned char *dst,const unsigned char *src ){
	int length = strlen((const char *)src);
	unsigned char hi;
	unsigned char lo;
	int ret_len = 0;

	for( int i = 0; i < length; i++ ){
		if( src[i] == ' ' )
			continue;
		hi = (src[i] >= 'A')?(src[i] - 'A' + 10):(src[i] - '0');
		i++;
		lo = (src[i] >= 'A')?(src[i] - 'A' + 10):(src[i] - '0');
		dst[ret_len] = ((hi << 4) | lo);
		ret_len++;
	}
	dst[ret_len] = '\0';
	return ret_len;
}

void Cwin32hpDlg::OnBnClickedRmStart()
{
	char dllPath[128];
	char pid[8];
	int ret = -1;

	DWORD Pid;
	memset( dllPath,0,sizeof(dllPath) );
	memset( pid,0,sizeof(pid) );

	GetDlgItem(IDC_RM_DLL_PATH)->GetWindowText(dllPath,sizeof(dllPath));

	GetFileAttributes(dllPath);
	if( FALSE == IsDllExist(dllPath) ){
		MessageBox("dll文件不存在");
		return;
	}

	GetDlgItem(IDC_RM_PID)->GetWindowText(pid,sizeof(pid));
	Pid = atoi(pid);

	if( ret = InjectByRemoteThread( dllPath, Pid ) ){
		char msg[32];
		sprintf(msg,"注入失败%d",ret );
		MessageBox(msg);
	}
	// TODO: 在此添加控件通知处理程序代码
}


void Cwin32hpDlg::OnBnClickedRmNt()
{
	char dllPath[128];
	char pid[8];
	int ret = -1;

	DWORD Pid;
	memset( dllPath,0,sizeof(dllPath) );
	memset( pid,0,sizeof(pid) );

	GetDlgItem(IDC_RM_DLL_PATH)->GetWindowText(dllPath,sizeof(dllPath));

	GetFileAttributes(dllPath);
	if( FALSE == IsDllExist(dllPath) ){
		MessageBox("dll文件不存在");
		return;
	}

	GetDlgItem(IDC_RM_PID)->GetWindowText(pid,sizeof(pid));
	Pid = atoi(pid);

	if( ret = InjectByNtCreateThreadEx( dllPath, Pid ) ){
		char msg[32];
		sprintf(msg,"注入失败%d",ret );
		MessageBox(msg);
	}
	// TODO: 在此添加控件通知处理程序代码
}


void Cwin32hpDlg::OnBnClickedCodeInject()
{
	char pid[8];
	int ret = -1;

	DWORD Pid;
	memset( pid,0,sizeof(pid) );
	GetDlgItem(IDC_RM_PID)->GetWindowText(pid,sizeof(pid));
	Pid = atoi(pid);

	char txt[256];
	unsigned char code[256];

	memset( txt,0,sizeof(txt) );
	memset( code,0,sizeof(code) );

	GetDlgItem(IDC_CI_CODE)->GetWindowText( txt,sizeof(txt) );

	ret = txt2code( code,(unsigned char *)txt );
	for( int i = 0; i < ret; i++ ){
		TRACE( "%x ",code[i] );
	}
	TRACE("\n");



}


void Cwin32hpDlg::OnBnClickedPeStart()
{
	
	char dllPath[128];
	char pePath[128];

	int ret = -1;

	memset( dllPath,0,sizeof(dllPath) );
	memset( pePath,0,sizeof(pePath) );


	GetDlgItem(IDC_PE_DLL)->GetWindowText(dllPath,sizeof(dllPath));
	if( FALSE == IsDllExist(dllPath) ){
		MessageBox("dll文件不存在");
		return;
	}

	GetDlgItem(IDC_PE_PEFILE)->GetWindowText(pePath,sizeof(pePath));
	if( FALSE == IsDllExist(pePath) ){
		MessageBox("pe文件不存在");
		return;
	}

	InjectPEDLL( pePath,dllPath );
	// TODO: 在此添加控件通知处理程序代码
}




int Cwin32hpDlg::InjectPEDLL( const char *pe, const char *dll ){
	
	HANDLE hFile = CreateFile(pe,GENERIC_READ,0,NULL,OPEN_ALWAYS,0,NULL);
	char buff[81920];

	if( INVALID_HANDLE_VALUE == hFile ){
		MessageBox("file open error");
		return -1;
	}
	
	LARGE_INTEGER size;
	::GetFileSizeEx(hFile,&size);

	DWORD nRead;
	ReadFile( hFile,buff,40960,&nRead,NULL );
	
	if( nRead != size.QuadPart ){
		MessageBox("缓冲区不足");
		return -2;
	}

	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)buff;
	IMAGE_FILE_HEADER *pIFH = (IMAGE_FILE_HEADER *)(buff + pIDH->e_lfanew + 4);

	//节区的数量
	int nSections = pIFH->NumberOfSections;
	TRACE("%d\n",nSections);
	//可选头部的大小
	int nsizeOptHeader = pIFH->SizeOfOptionalHeader;
	TRACE("%d\n",nsizeOptHeader);

	IMAGE_OPTIONAL_HEADER32 *pIOH = (IMAGE_OPTIONAL_HEADER32 *)((char *)pIFH + sizeof(IMAGE_FILE_HEADER)); 


	IMAGE_DATA_DIRECTORY *pIDD = pIOH->DataDirectory; 
	IMAGE_DATA_DIRECTORY *pImport = &pIDD[1];

	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((char *)pIOH + nsizeOptHeader);

	DWORD rva = pImport->VirtualAddress;
	DWORD raw = 0;
	for( int i = 0; i < nSections; i++,pISH++ ){
		if( (rva >= pISH->VirtualAddress) && 
			(rva <= pISH->VirtualAddress + pISH->SizeOfRawData)){
				raw = pISH->PointerToRawData + rva - pISH->VirtualAddress;
				break;
		}
	}

	if( raw == 0 ){
		MessageBox("地址转换失败");
		return -3;
	}

	IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)(buff + raw);

	int dllNum = 0;
	while( 0 != pIID->Name ){
		char *dllName = buff + pIID->Name - rva + raw ;
		TRACE("%s\n",dllName);
		pIID++;
		dllNum++;
	}
	
	pIID -= dllNum;
	//寻找空间
	/*
	if( (DWORD)(pIDH->e_lfanew) - (DWORD)&(((IMAGE_DOS_HEADER *)(0))->e_lfanew) > sizeof(int) * 5 * (dllNum + 4) ){
		TRACE("DOS头夹缝空间%d",(DWORD)(pIDH->e_lfanew) - (DWORD)&(((IMAGE_DOS_HEADER *)(0))->e_lfanew));
		memcpy( buff + pIDH->e_lfanew - (dllNum + 2) * sizeof(int) * 5, pIID, (dllNum + 2) * sizeof(int) * 5 );
		memset( buff + pIDH->e_lfanew - 10 * sizeof(int),0,sizeof(int) * 10 );
		
		pImport->VirtualAddress = pIDH->e_lfanew - (dllNum + 2) * sizeof(int) * 5;
		//IMAGE_IMPORT_DESCRIPTOR *pEvil = (IMAGE_IMPORT_DESCRIPTOR *)(buff + pIDH->e_lfanew - 10 * sizeof(int));
		//memcpy( buff + pIDH->e_lfanew - (dllNum + 4) * sizeof(int) * 5,"GD.dll",sizeof("GD.dll"));
	}*/

	char cp_tmp[4096];
	memset( cp_tmp,0,sizeof(cp_tmp) );
	
	while( 0 != pIID->Name ){
		TRACE("---%s---\n",(char *)(buff + raw + pIID->Name - rva));
		pIID->Name += sizeof(int) * 5;

		DWORD *pfn_arr = (DWORD *)(buff + raw + pIID->FirstThunk - rva);

		while( *pfn_arr ){
			TRACE("%s\n",(char *)(buff + raw + *pfn_arr - rva + 2));
			(*pfn_arr) += sizeof(int) * 5;
			//TRACE("%s\n",(char *)(buff + raw + *pfn_arr - rva + 2));
			pfn_arr++;
		}
		
		pIID->FirstThunk += sizeof(int) * 5;
		pIID++;
	}

	pIID -= dllNum;
	memcpy( cp_tmp,pIID,pImport->Size );
	memcpy( ((char *)pIID)+sizeof(int) * 5,cp_tmp,pImport->Size );
	//pImport->VirtualAddress += sizeof(int) * 5;
	pImport->Size += sizeof(int) * 5;

	DWORD offset = pImport->Size;
	memset( pIID,0,sizeof(int) * 5 );
	memcpy( buff + raw + offset, "GD.dll", strlen("GD.dll") + 1 );
	pImport->Size += (strlen("GD.dll") + 1);
	pIID->Name = rva + offset;

	offset += (strlen("GD.dll") + 1);
	pIID->FirstThunk = rva + offset;

	*(DWORD *)(&buff[raw + offset]) = rva + offset + 8;
	*(DWORD *)(&buff[raw + offset + 4]) = 0;
	offset += 8;

	buff[raw + offset] = 0;
	buff[raw + offset + 1] = 0;
	buff[raw + offset + 2] = 'I';
	buff[raw + offset + 3] = 'n';
	buff[raw + offset + 4] = 'j';
	buff[raw + offset + 5] = 'e';
	buff[raw + offset + 6] = 'c';
	buff[raw + offset + 7] = 't';
	buff[raw + offset + 8] = 'F';
	buff[raw + offset + 9] = 'u';
	buff[raw + offset + 10] = 'n';
	buff[raw + offset + 11] = 'c';
	buff[raw + offset + 12] = 0;
	
	pImport->Size += (sizeof(int) * 3 + 13);

	//C:\Users\Lenovo\Desktop\CRACKME.EXE

	//修正代码段跳转
	pISH = (IMAGE_SECTION_HEADER *)((char *)pIOH + nsizeOptHeader);

	offset = -1;
	for( int i = 0; i < nSections; i++,pISH++ ){
		if( !strcmp(".text",(char *)&(pISH->Name) ) ){
			offset = pISH->PointerToRawData;
			break;
		}
		if( !strcmp("CODE",(char *)&(pISH->Name) ) ){
			offset = pISH->PointerToRawData;
			break;
		}
	}

	if( offset == -1 ){
		MessageBox("无.text段");
		return -4;
	}
	
	for( int i = 0; i < pISH->SizeOfRawData; i++ ){
		DWORD tmp_val = *(DWORD *)(&buff[offset + i]);
		//TODO基地址
		if( tmp_val > rva + pIOH->ImageBase && tmp_val < rva + pIOH->ImageBase +pImport->Size ){
			if( ((unsigned char)buff[i + offset - 2] == 0xff) && ((unsigned char)buff[i + offset - 1] == 0x25) ){
				TRACE("patch addr = %x\n",tmp_val);
				*(DWORD *)(&buff[offset + i]) += (sizeof(int) * 5);
			}
		}
	}

	HANDLE hNew = CreateFile("./tmpxx.exe",GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);
	
	if( INVALID_HANDLE_VALUE == hNew ){
		MessageBox("file open error");
		return -4;
	}

	WriteFile( hNew,buff,nRead,NULL,NULL );

	
	CloseHandle( hNew );
	CloseHandle( hFile );
	
	return 0;
}

int Cwin32hpDlg::InjectPEDLL_NEWSEC( const char *pe, const char *dll ){
	HANDLE hFile = CreateFile(pe,GENERIC_READ,0,NULL,OPEN_ALWAYS,0,NULL);
	char buff[81920];

	if( INVALID_HANDLE_VALUE == hFile ){
		MessageBox("file open error");
		return -1;
	}
	
	LARGE_INTEGER size;
	::GetFileSizeEx(hFile,&size);

	DWORD nRead;
	ReadFile( hFile,buff,40960,&nRead,NULL );
	
	if( nRead != size.QuadPart ){
		MessageBox("缓冲区不足");
		return -2;
	}
	IMAGE_SECTION_HEADER *pSH2 = NULL;
	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)buff;
	IMAGE_FILE_HEADER *pIFH = (IMAGE_FILE_HEADER *)(buff + pIDH->e_lfanew + 4);

	//节区的数量
	int nSections = pIFH->NumberOfSections;
	TRACE("%d\n",nSections);
	//可选头部的大小
	int nsizeOptHeader = pIFH->SizeOfOptionalHeader;
	TRACE("%d\n",nsizeOptHeader);

	IMAGE_OPTIONAL_HEADER32 *pIOH = (IMAGE_OPTIONAL_HEADER32 *)((char *)pIFH + sizeof(IMAGE_FILE_HEADER)); 


	IMAGE_DATA_DIRECTORY *pIDD = pIOH->DataDirectory; 
	IMAGE_DATA_DIRECTORY *pImport = &pIDD[1];

	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((char *)pIOH + nsizeOptHeader);

	DWORD rva = pImport->VirtualAddress;
	DWORD raw = 0;
	for( int i = 0; i < nSections; i++,pISH++ ){
		if( (rva >= pISH->VirtualAddress) && 
			(rva <= pISH->VirtualAddress + pISH->SizeOfRawData)){
				raw = pISH->PointerToRawData + rva - pISH->VirtualAddress;
				break;
		}
	}
	
	if( raw == 0 ){
		MessageBox("地址转换失败");
		return -3;
	}

	IMAGE_IMPORT_DESCRIPTOR *pIID = (IMAGE_IMPORT_DESCRIPTOR *)(buff + raw);

	int dllNum = 0;
	while( 0 != pIID->Name ){
		char *dllName = buff + pIID->Name - rva + raw ;
		TRACE("%s\n",dllName);
		pIID++;
		dllNum++;
	}
	
	pIID -= dllNum;
	
	//首先开辟新区段的空间
	pISH = (IMAGE_SECTION_HEADER *)((char *)pIOH + nsizeOptHeader);
	pISH += nSections;

	memcpy( pISH,pISH - 1,sizeof(IMAGE_SECTION_HEADER) );
	pISH->Name[0] = 'N';

	pIFH->NumberOfSections++;
	pISH->VirtualAddress = 0x8000;
	pISH->SizeOfRawData = 0x800;
	pISH->Characteristics = 0xC0000040;
	pISH->Misc.VirtualSize = 0x1000;
	pISH->PointerToRawData = ( pISH - 1)->PointerToRawData + ( pISH - 1 )->SizeOfRawData;

	pIOH->SizeOfImage += 0x1000;
	HANDLE hNew = CreateFile("./tmpxx.exe",GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);

	TRACE("nRead = %x\n",nRead);
	memcpy( buff + pISH->PointerToRawData,pIID,sizeof(int) * (dllNum + 1) * 5 );
	pImport->VirtualAddress = 0x8000;
	pImport->Size = sizeof(int) * (dllNum ) * 5;

	pSH2 = (IMAGE_SECTION_HEADER *)(pIOH ++ );

	if( INVALID_HANDLE_VALUE == hNew ){
		MessageBox("file open error!");
		return -4;
	}

	WriteFile( hNew,buff,pISH->PointerToRawData + 0x800,NULL,NULL );
	//C:\Users\Lenovo\Desktop\CRACKME.EXE

	CloseHandle( hNew );
	CloseHandle( hFile );
	
	return 0;
}


void Cwin32hpDlg::OnBnClickedNewSecInject()
{
	char dllPath[128];
	char pePath[128];

	int ret = -1;

	memset( dllPath,0,sizeof(dllPath) );
	memset( pePath,0,sizeof(pePath) );


	GetDlgItem(IDC_PE_DLL)->GetWindowText(dllPath,sizeof(dllPath));
	if( FALSE == IsDllExist(dllPath) ){
		MessageBox("dll文件不存在");
		return;
	}
	
	GetDlgItem(IDC_PE_PEFILE)->GetWindowText(pePath,sizeof(pePath));
	if( FALSE == IsDllExist(pePath) ){
		MessageBox("pe文件不存在");
		return;
	}

	InjectPEDLL_NEWSEC(pePath,dllPath);
}

DWORD Cwin32hpDlg::GetProcessTeb( HANDLE TargetHandle,DWORD pid ){

	DWORD base = 0x1000;
	DWORD nRead = 0;

	char buff[0x1000];

	while( base < 0x80000000){
		if( ReadProcessMemory( TargetHandle,(LPCVOID)base,buff,64,&nRead ) ){
			//read success;
			if( (base == *(DWORD*)&buff[0x18]) && (pid == *(DWORD*)&buff[0x20]) ){
				return base;
			}
		}
		base += 0x1000;
	}
	
	return 0;
}

HANDLE TargetHandle;



vector<CString> Cwin32hpDlg::GetModList( DWORD pid ){
	vector<CString> vec;
	HANDLE TargetHandle = OpenProcess( PROCESS_ALL_ACCESS,0,pid );
	if( INVALID_HANDLE_VALUE == TargetHandle )
		return vec;

	DWORD Teb = GetProcessTeb( TargetHandle,pid );
	
	if( !Teb ){
		CloseHandle(TargetHandle);
		return vec;
	}

	char buff[0x1000];
	DWORD nRead;
	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)Teb,buff,64,&nRead ) ){
		CloseHandle(TargetHandle);
		return vec;
	}

	DWORD Peb = *(DWORD *)&buff[0x30];

	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)Peb,buff,64,&nRead ) ){
		CloseHandle(TargetHandle);
		return vec;
	}

	DWORD Ldr = *(DWORD *)&buff[0x0c];

	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)Ldr,buff,64,&nRead ) ){
		CloseHandle(TargetHandle);
		return vec;
	}

	DWORD iter = *(DWORD *)&buff[0x0c];

	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)iter,buff,sizeof(LDR_MODULE),&nRead ) ){
		CloseHandle(TargetHandle);
		return vec;
	}
	
	while( iter != Ldr + 0xc ){
		LDR_MODULE p;
		memcpy( &p,buff,sizeof(LDR_MODULE) );
		DWORD BaseAddress = (DWORD)p.BaseAddress;

		DWORD dllname = (DWORD)(p.BaseDllName.Buffer);
		DWORD len = p.BaseDllName.Length;

		if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)dllname,buff,len,&nRead ) ){
			CloseHandle(TargetHandle);
			return vec;
		}
		buff[len] = '\0';
		buff[len + 1] = '\0';

		CString name_str((wchar_t *)buff);
		vec.push_back( name_str );
		
		iter = (DWORD)(p.InLoadOrderModuleList.Flink);
		if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)iter,buff,sizeof(LDR_MODULE),&nRead ) ){
			CloseHandle(TargetHandle);
			return vec;
		}
		
	}

	CloseHandle(TargetHandle);
	return vec;
}

void Cwin32hpDlg::OnBnClickedModEmu()
{
	char pid[8];
	int ret = -1;

	DWORD Pid;
	memset( pid,0,sizeof(pid) );

	GetDlgItem(IDC_MOD_PID)->GetWindowText(pid,sizeof(pid));
	Pid = atoi(pid);

	vector<CString> vec = GetModList( Pid );
	
	int size = vec.size();

	CString show = "";

	for( int i = 0; i < size; i++ ){
		show += vec[i];
		show += "\r\n";
	}
	GetDlgItem(IDC_MOD_RET)->SetWindowText(show);
}

int Cwin32hpDlg::dllhook(const char *dllpath){
	HANDLE hFile = CreateFile(dllpath,GENERIC_READ,0,NULL,OPEN_ALWAYS,0,NULL);
	char buff[819200];

	if( INVALID_HANDLE_VALUE == hFile ){
		MessageBox("file open error");
		return -1;
	}

	LARGE_INTEGER size;
	::GetFileSizeEx(hFile,&size);

	DWORD nRead;
	ReadFile( hFile,buff,409600,&nRead,NULL );

	if( nRead != size.QuadPart ){
		MessageBox("缓冲区不足");
		CloseHandle(hFile);
		return -2;
	}




	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)buff;
	IMAGE_FILE_HEADER *pIFH = (IMAGE_FILE_HEADER *)(buff + pIDH->e_lfanew + 4);

	//节区的数量
	int nSections = pIFH->NumberOfSections;
	TRACE("dll节区数量 %d\n",nSections);
	//可选头部的大小
	int nsizeOptHeader = pIFH->SizeOfOptionalHeader;
	TRACE("%d\n",nsizeOptHeader);

	IMAGE_OPTIONAL_HEADER32 *pIOH = (IMAGE_OPTIONAL_HEADER32 *)((char *)pIFH + sizeof(IMAGE_FILE_HEADER)); 


	IMAGE_DATA_DIRECTORY *pIDD = pIOH->DataDirectory; 
	IMAGE_DATA_DIRECTORY *pExport = &pIDD[0];

	IMAGE_SECTION_HEADER *pISH = (IMAGE_SECTION_HEADER *)((char *)pIOH + nsizeOptHeader);

	DWORD rva = pExport->VirtualAddress;
	DWORD raw = 0;
	for( int i = 0; i < nSections; i++,pISH++ ){
		if( (rva >= pISH->VirtualAddress) && 
			(rva <= pISH->VirtualAddress + pISH->SizeOfRawData)){
				raw = pISH->PointerToRawData + rva - pISH->VirtualAddress;
				break;
		}
	}

	if( !raw ){
		MessageBox("未找到导出表节区");
		return -3;
	}

	IMAGE_EXPORT_DIRECTORY *pIMD = (IMAGE_EXPORT_DIRECTORY *)( buff + raw );

	TRACE("now start hook dll, name = %s\n",buff + pIMD->Name - rva + raw);
	TRACE("export Base = %d,NumberOfFunctions = %d,NumberOfNames = %d\n",pIMD->Base,pIMD->NumberOfFunctions,pIMD->NumberOfNames );
	
	CString code = "";
	CString initcode = "";
	char tmp[4];

	DWORD *pname = (DWORD *)(buff + pIMD->AddressOfNames - rva + raw);
	
	initcode = initcode + "g_hDll = LoadLibrary(\"\");\n";

	initcode = initcode + "int i = 0;\n";
	for( int i = 0; i < pIMD->NumberOfNames; i++ ){
		initcode = initcode + "g_jmpArr[i++] = (DWORD)GetProcAddress(g_hDll\"";
		initcode = initcode + (*(pname + i) + buff - rva + raw) + "\");\n";
		
		sprintf( tmp,"%d",i * 4 );
		code += "void __declspec(naked) ";
		code += (*(pname + i) + buff - rva + raw);
		code += "(){\n";
		code += "\t__asm\n\t{\n";
		code += "\t\tjmp [g_jmpArr + ";
		code += tmp;
		code += "];\n";
		code += "\t}\n";
		code += "\n}\n\n";
		TRACE("%d:%s\n",i,*(pname + i) + buff - rva + raw);
	}
	
	OutputDebugString(initcode);
	OutputDebugString(code);
	code = initcode + code;
	GetDlgItem(IDC_ED_HRET)->SetWindowText(code);
	CloseHandle(hFile);
}

void Cwin32hpDlg::OnBnClickedBtnDllh()
{
	char dllPath[128];

	memset( dllPath,0,sizeof(dllPath) );

	GetDlgItem(IDC_ED_REALDLL)->GetWindowText(dllPath,sizeof(dllPath));

	GetFileAttributes(dllPath);
	if( FALSE == IsDllExist(dllPath) ){
		MessageBox("dll文件不存在");
		return;
	}

	dllhook( dllPath );

}

DWORD Cwin32hpDlg::getOep( DWORD pid ){
	DWORD oep = 0;

	HANDLE TargetHandle = OpenProcess( PROCESS_ALL_ACCESS,0,pid );
	if( INVALID_HANDLE_VALUE == TargetHandle )
		return 0;

	DWORD Teb = GetProcessTeb( TargetHandle,pid );

	if( !Teb ){
		CloseHandle(TargetHandle);
		return 0;
	}

	char buff[0x1000];
	DWORD nRead;
	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)Teb,buff,64,&nRead ) ){
		CloseHandle(TargetHandle);
		return 0;
	}

	DWORD Peb = *(DWORD *)&buff[0x30];

	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)Peb,buff,64,&nRead ) ){
		CloseHandle(TargetHandle);
		return 0;
	}

	DWORD Ldr = *(DWORD *)&buff[0x0c];

	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)Ldr,buff,64,&nRead ) ){
		CloseHandle(TargetHandle);
		return 0;
	}

	DWORD iter = *(DWORD *)&buff[0x0c];

	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)iter,buff,sizeof(LDR_MODULE),&nRead ) ){
		CloseHandle(TargetHandle);
		return 0;
	}

	LDR_MODULE p;
	memcpy( &p,buff,sizeof(LDR_MODULE) );
	DWORD BaseAddress = (DWORD)p.BaseAddress;

	DWORD dllname = (DWORD)(p.BaseDllName.Buffer);
	DWORD len = p.BaseDllName.Length;

	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)dllname,buff,len,&nRead ) ){
		CloseHandle(TargetHandle);
		return 0;
	}
	buff[len] = '\0';
	buff[len + 1] = '\0';

	if( 0 == ReadProcessMemory( TargetHandle,(LPCVOID)BaseAddress,buff,0x1000,&nRead ) ){
		CloseHandle(TargetHandle);
		return 0;
	}

	IMAGE_DOS_HEADER *pIDH = (IMAGE_DOS_HEADER *)buff;
	IMAGE_FILE_HEADER *pIFH = (IMAGE_FILE_HEADER *)(buff + pIDH->e_lfanew + 4);
	IMAGE_OPTIONAL_HEADER32 *pIOH = (IMAGE_OPTIONAL_HEADER32 *)((char *)pIFH + sizeof(IMAGE_FILE_HEADER));

	BaseAddress += pIOH->AddressOfEntryPoint;

	CloseHandle(TargetHandle);

	char oep_addr[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	sprintf( oep_addr,"%x",BaseAddress );
	GetDlgItem(IDC_ED_OEP)->SetWindowText(oep_addr);

	return BaseAddress;
}

//E8 call
//E9 jmp
unsigned char *Cwin32hpDlg::fixcode( DWORD oldEip,DWORD codeAddr,char *str,int len ){
	if( len%2 ){
		MessageBox("代码格式错误");
		return NULL;
	}

	unsigned char *p = new unsigned char[len/2 + 5];
	unsigned char c,hi,lo;
	DWORD ab_addr;

	int i;
	for( i = 0; i < len; i++ ){
		c = (unsigned char)str[i];

		i++;
		hi = (c>='A')?(c-'A'+10):(c-'0');
		c = (unsigned char)str[i];
		lo = (c>='A')?(c-'A'+10):(c-'0');
		p[i/2] = ((hi << 4) | lo);
	
		if( 3 < i/2 ){
			if( 0xE8 == p[i/2 - 4] ){
				ab_addr = ntohl(*(DWORD *)(&p[i/2 - 3]));
				ab_addr = ab_addr - (codeAddr + i/2 + 1);
				*(DWORD *)(&p[i/2-3]) = ab_addr;
			}

			if( 0xE9 == p[i/2 - 4] ){
				ab_addr = ntohl(*(DWORD *)(&p[i/2 - 3]));
				ab_addr = ab_addr - (codeAddr + i/2 + 1);
				*(DWORD *)(&p[i/2-3]) = ab_addr;
			}
		}
	}
	
	p[len/2] = 0xE9;
	*(DWORD *)&p[len/2 + 1] = oldEip - (codeAddr + len/2 + 5);

	return p;
}

int Cwin32hpDlg::oepInject( DWORD pid,DWORD oep ){
	HANDLE TargetHandle = OpenProcess( PROCESS_ALL_ACCESS,0,pid );
	if( INVALID_HANDLE_VALUE == TargetHandle )
		return -1;
	DWORD nWrite;
	BOOL iSucc;
	DWORD oldFlag;

	HANDLE hThreadSnap= CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,pid);//获取快照句柄
	if(hThreadSnap == INVALID_HANDLE_VALUE){
		MessageBox("获取快照失败");
		return -5;
	}
	HANDLE thandle = INVALID_HANDLE_VALUE;
	THREADENTRY32 pe32 = { sizeof(pe32) };
	if(Thread32First(hThreadSnap, &pe32))
	{
		do
		{
			if ( pe32.th32OwnerProcessID == pid )
			{
				thandle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,pe32.th32ThreadID);
				break;
				/*
				FILETIME createtime,time2,time3,time4;
				::GetThreadTimes(handle,&createtime,&time2,&time3,&time4);
				SYSTEMTIME realtime;
				::FileTimeToSystemTime(&createtime,&realtime);
				if ( createtime.dwHighDateTime < timeRunE.dwHighDateTime
					|| (timeRunE.dwHighDateTime == 0 && timeRunE.dwLowDateTime == 0) )
				{
					m_threadId = pe32.th32ThreadID ;
					timeRunE = createtime;
				} else 
					if ( createtime.dwHighDateTime == timeRunE.dwHighDateTime &&
						createtime.dwLowDateTime < timeRunE.dwLowDateTime )
					{
						m_threadId = pe32.th32ThreadID ;
						timeRunE = createtime;
					}*/
			}
		}while(::Thread32Next(hThreadSnap, &pe32));
	}
	CloseHandle(hThreadSnap);

	SuspendThread(thandle);
	CONTEXT ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_FULL;
	iSucc = GetThreadContext( thandle,&ctx );
	TRACE("%d eip:%x  esp:%x  ebp:%x  flag:%x\n",GetLastError(),ctx.Eip,ctx.Esp,ctx.Ebp,ctx.EFlags);
	/*
	HMODULE hModule = LoadLibrary("NTDLL.DLL");

	if( INVALID_HANDLE_VALUE == hModule ){
		MessageBox("打开ntdll失败");
			return -5;
	}

	DWORD (WINAPI *SUSPENDPROCESS)(HANDLE) = (DWORD (WINAPI *)(HANDLE))GetProcAddress(hModule,"ZwSuspendProcess");
	DWORD (WINAPI *RESUMEPROCESS)(HANDLE) = (DWORD (WINAPI *)(HANDLE))GetProcAddress(hModule,"ZwResumeProcess");;

	if( !SUSPENDPROCESS || !RESUMEPROCESS ){
		MessageBox("函数缺失");
		return -6;
	}
	
	SUSPENDPROCESS(TargetHandle);
	RESUMEPROCESS(TargetHandle);
	*/

	DWORD oldEip = ctx.Eip;
	DWORD MessageBoxAddr = 0x776B7E60;

	/*
	unsigned char newcode[] = { 0x6A,0x00,0x6A,0x00,0x6A,0x00,0x6A,0x00,0xE8,0xAB,0xAB,0xAB,0xAB,0xE9,0xAB,0xAB,0xAB,0xAB };
	*(DWORD *)(newcode + 9) = MessageBoxAddr - (oep + 9 + 4);
	*(DWORD *)(newcode + 14) = oldEip - (oep + 14 + 4);
	*/

	char buff[1024];
	GetDlgItem(IDC_CI_CODE)->GetWindowText(buff,sizeof(buff));

	if( 0 == buff[0] ){
		MessageBox("代码为空");
		return -6;
	}

	int len = strlen(buff);
	unsigned char *pfix = fixcode(oldEip,oep,buff,len );
	//6A0068043040006A006A00E8776B7E60
	/*
	unsigned char newcode[] = { 0x6A,0x00,0x68,0x04,0x30,0x40,0x00,0x6A,0x00,0x6A,0x00,0xE8,0xAB,0xAB,0xAB,0xAB,0xE9,0xAB,0xAB,0xAB,0xAB };
	*(DWORD *)(newcode + 9 + 3) = MessageBoxAddr - (oep + 9 + 4 + 3);
	*(DWORD *)(newcode + 14 + 3) = oldEip - (oep + 14 + 4 + 3);
	*/

	iSucc = VirtualProtectEx( TargetHandle,(LPVOID)oep,len,PAGE_EXECUTE_READWRITE,&oldFlag );
	if( FALSE == iSucc ){
		MessageBox("属性修改失败");
		return -2;
	}

	iSucc = WriteProcessMemory( TargetHandle,(LPVOID)oep,pfix,len,&nWrite );
	if( FALSE == iSucc ){
		MessageBox("写入失败");
		return -3;
	}
	
	iSucc = VirtualProtectEx( TargetHandle,(LPVOID)oep,len,oldFlag,&oldFlag );
	if( FALSE == iSucc ){
		MessageBox("属性修改失败");
		return -4;
	}

	ctx.Eip = oep;
	ctx.ContextFlags = CONTEXT_FULL;
	iSucc = SetThreadContext( thandle,&ctx );
	
	TRACE("Set ctx iSucc = %d\n",iSucc);
	ResumeThread(thandle);
	
	CloseHandle(thandle);
	CloseHandle(TargetHandle);
	return 0;
}

void Cwin32hpDlg::OnBnClickedBtnGetoep()
{
	char pid[8];
	int ret = -1;

	DWORD Pid;

	memset( pid,0,sizeof(pid) );

	GetDlgItem(IDC_ED_OEP_PID)->GetWindowText(pid,sizeof(pid));
	Pid = atoi(pid);

	DWORD oep = getOep( Pid );
	
	if( 0 == oep ){
		MessageBox("无法定位OEP");
		return;
	}

	oepInject( Pid,oep );
}
