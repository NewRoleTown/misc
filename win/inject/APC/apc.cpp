#include<iostream>
using namespace std;


extern "C"{
	#include"../common.c"
    #include<assert.h>
	#include<TlHelp32.h> 
	WINBASEAPI HANDLE WINAPI OpenThread(DWORD,BOOL,DWORD);
}

WINBASEAPI HANDLE WINAPI OpenThread(DWORD,BOOL,DWORD);
int InjectByApc( DWORD ProcessId )
{
	HANDLE hTargetHandle;
	THREADENTRY32 ThreadEntry32 = { 0 };
	HANDLE hThreadSnap;
	ThreadEntry32.dwSize = sizeof(THREADENTRY32);
	HANDLE hThreadHandle;
	BOOL bStatus;
	DWORD dwReturn;
	DWORD ret;

	hTargetHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	assert(hTargetHandle);

	char *p = (char *)VirtualAllocEx(hTargetHandle, NULL, DLLPATHSIZE,MEM_COMMIT, PAGE_READWRITE);
    assert(p);

	ret = WriteProcessMemory(hTargetHandle, p, (LPVOID)DLLPATH, DLLPATHSIZE, NULL);
    if( !ret ){
		VirtualFreeEx(hTargetHandle, p, DLLPATHSIZE, MEM_DECOMMIT);
        assert( ret );
	}

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		VirtualFreeEx(hTargetHandle, p, DLLPATHSIZE, MEM_DECOMMIT);
		return -1;
	}
	if (!Thread32First(hThreadSnap, &ThreadEntry32))
	{
		VirtualFreeEx(hTargetHandle, p, DLLPATHSIZE, MEM_DECOMMIT);
		return -1;
	}
	do
	{
		if (ThreadEntry32.th32OwnerProcessID == ProcessId)
		{
			printf("TID:%d\n", ThreadEntry32.th32ThreadID);
			hThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadEntry32.th32ThreadID);
			if (hThreadHandle)
			{
				dwReturn = QueueUserAPC(
					(PAPCFUNC)LoadLibraryA,
					hThreadHandle,
					(ULONG_PTR)p);
				if (dwReturn > 0)
				{
					bStatus = TRUE;
				}
				CloseHandle(hThreadHandle);
			}
		}
	} while (Thread32Next(hThreadSnap, &ThreadEntry32));
	VirtualFreeEx(hTargetHandle, p, DLLPATHSIZE, MEM_DECOMMIT);

	CloseHandle(hThreadSnap);
	CloseHandle(hTargetHandle);
	return 0;
}

int main(){
    
    
    if( EnableDebugPrivilege() == 0 ){
        cout<<"Privilege Error"<<endl;
        return -1;
    }

    DWORD targetPID = 0;
    
    cout<<"input target pid:";
    cin>>targetPID;
    InjectByApc( targetPID );


    return 0;
}
