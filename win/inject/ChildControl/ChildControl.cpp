#include<iostream>
using namespace std;


extern "C"{
	#include"../common.c"
    #include<assert.h>
}


PROCESS_INFORMATION pi;
STARTUPINFOA Startup;
CONTEXT ctx;

void CreateShellCode(int ret, int str, unsigned char** shellcode, int* shellcodeSize)
{
	unsigned char* retChar = (unsigned char*)&ret;
	unsigned char* strChar = (unsigned char*)&str;
	int api = (int)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	unsigned char* apiChar = (unsigned char*)&api;
	unsigned char sc[] = {
		// Push ret
		0x68, retChar[0], retChar[1], retChar[2], retChar[3],
		// Push all flags
		0x9C,
		// Push all register
		0x60,
		// Push 0x66666666 (later we convert it to the string of "C:\DLLInjectionTest.dll")
		0x68, strChar[0], strChar[1], strChar[2], strChar[3],
		// Mov eax, 0x66666666 (later we convert it to LoadLibrary adress)
		0xB8, apiChar[0], apiChar[1], apiChar[2], apiChar[3],
		// Call eax
		0xFF, 0xD0,
		// Pop all register
		0x61,
		// Pop all flags
		0x9D,
		// Ret
		0xC3
	};

	*shellcodeSize = 22;
	*shellcode = (unsigned char*)malloc(22);
	memcpy(*shellcode, sc, 22);
}


int main(){
    
    char path[32];
    char *p;
    unsigned char *ShellCode;
    int size;
    void *pStartCode;
    
    if( EnableDebugPrivilege() == 0 ){
        cout<<"Privilege Error"<<endl;
        return -1;
    }


    cout<<"input exe's path:";
    cin>>path;

    DWORD ret = CreateProcessA( path,NULL,NULL,NULL,0,CREATE_SUSPENDED,NULL,NULL,&Startup,&pi );
    assert( ret );

    p = (char *)VirtualAllocEx( pi.hProcess,NULL,DLLPATHSIZE,MEM_COMMIT,PAGE_READWRITE );
    assert( p );
    
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext( pi.hThread,&ctx );

    CreateShellCode( ctx.Eip,(int)p, &ShellCode,&size );

    pStartCode = VirtualAllocEx( pi.hProcess,NULL,size,MEM_COMMIT,PAGE_EXECUTE_READWRITE );
    assert( pStartCode );

    ret = WriteProcessMemory( pi.hProcess,p,DLLPATH,DLLPATHSIZE,NULL );
    if( !ret ){
        VirtualFreeEx( pi.hProcess,p,DLLPATHSIZE,MEM_DECOMMIT );
        VirtualFreeEx( pi.hProcess,pStartCode,size,MEM_DECOMMIT );
        assert(ret);
    }

    ret = WriteProcessMemory( pi.hProcess,pStartCode,ShellCode,size,NULL );
    if( !ret ){
        VirtualFreeEx( pi.hProcess,p,DLLPATHSIZE,MEM_DECOMMIT );
        VirtualFreeEx( pi.hProcess,pStartCode,size,MEM_DECOMMIT );
        assert(ret);
    }

    ctx.Eip = (DWORD)pStartCode;
    ctx.ContextFlags = CONTEXT_CONTROL;
    SetThreadContext( pi.hThread,&ctx );

    ResumeThread( pi.hThread );


    while(1);


    return 0;
}
