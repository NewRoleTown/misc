




#include<iostream>
using namespace std;


extern "C"{
	#include"../common.c"
    #include<assert.h>
}


void InjectByRemoteThread( DWORD pid ){
    HANDLE TargetHandle,ThreadHandle;
    char *p;
    DWORD ret;
    LPTHREAD_START_ROUTINE pLoadLibrary;


    TargetHandle = OpenProcess( PROCESS_ALL_ACCESS,0,pid );
    assert( TargetHandle );

    p = (char *)VirtualAllocEx( TargetHandle,NULL,DLLPATHSIZE,MEM_COMMIT,PAGE_READWRITE );
    assert(p);

    ret = WriteProcessMemory( TargetHandle,p,DLLPATH,DLLPATHSIZE,NULL );
    if( !ret ){
        VirtualFreeEx( TargetHandle,p,DLLPATHSIZE,MEM_DECOMMIT );
        assert(ret);
    }

    pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress( GetModuleHandle("kernel32.dll"),"LoadLibraryA" );
    assert( pLoadLibrary );

    ThreadHandle = CreateRemoteThread( TargetHandle,NULL,0,pLoadLibrary,p,0,NULL );
    if( !ThreadHandle ){
        VirtualFreeEx( TargetHandle,p,DLLPATHSIZE,MEM_DECOMMIT );
        assert( ThreadHandle );
    
    }

    CloseHandle( TargetHandle );

}

int main(){
    
    
    if( EnableDebugPrivilege() == 0 ){
        cout<<"Privilege Error"<<endl;
        return -1;
    }

    DWORD targetPID = 0;
    
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress( GetModuleHandle("Kernel32.dll"),"LoadLibraryA" );
    assert( pLoadLibrary );
    
    cout<<"input target pid:";
    cin>>targetPID;
	InjectByRemoteThread(targetPID);


    return 0;
}
