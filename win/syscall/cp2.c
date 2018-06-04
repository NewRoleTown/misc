ReadFIle(kernel32.dll)->NtReadFile(ntdll.dll)->NtReadFile(ntoskrnl.exe)
    sysfuncs.lst指明了系统调用的参数个数


//
// KUSER_SHARED_DATA Offsets
//
#ifdef __ASM__
#define USER_SHARED_DATA                        0xFFDF0000
#endif
#define USER_SHARED_DATA_INTERRUPT_TIME         0x8
#define USER_SHARED_DATA_SYSTEM_TIME            0x14
#define USER_SHARED_DATA_TICK_COUNT             0x320

//
// KUSER_SHARED_DATA Offsets (this stuff is trash)
//
#define KERNEL_USER_SHARED_DATA                 0x7FFE0000
#define KUSER_SHARED_PROCESSOR_FEATURES         KERNEL_USER_SHARED_DATA + 0x274
#define KUSER_SHARED_SYSCALL                    KERNEL_USER_SHARED_DATA + 0x300
#define KUSER_SHARED_SYSCALL_RET                KERNEL_USER_SHARED_DATA + 0x304
#define PROCESSOR_FEATURE_FXSR                  KUSER_SHARED_PROCESSOR_FEATURES + 0x4

这两段地址指向同一块物理内存(64K)
这个东西在初始化时根据是否支持快速系统调用指向_KiFastSystemCall或者_KiIntSystemCall
#define KUSER_SHARED_SYSCALL                    KERNEL_USER_SHARED_DATA + 0x300

_KiIntSystemCall@0:
    //将参数地址保存在edx
    //外层stub函数已经将调用号保存在eax
    //esp是KiIn..返回地址，esp+4是stub返回地址
    lea edx, [esp+8]
    int 0x2E
    ret
.endfunc

_KiFastSystemCall@0:
    mov edx, esp
    sysenter
.endfunc

_KiFastSystemCallRet@0:
    ret
.endfunc
//这俩函数都在ntdll.dll中
//windows系统库在每个进程中的位置是相同的
//对于中断门，在转移过程中把IF置为0，使得在处理程序执行期间屏蔽掉INTR中断(当然，在中断处理程序中可以人为设置IF标志打开中断，以使得在处理程序执行期间允许响应可屏蔽中断)；对于陷阱门，在转移过程中保持IF位不变，即如果IF位原来是1


windows的所有IDT表初始化时都设置这个INT_32_DPL0，难道系统调用都使用中断门?

.func KiSystemService
TRAP_FIXUPS kss_a, kss_t, DoNotFixupV86, DoNotFixupAbios
_KiSystemService:

    /* Enter the shared system call prolog */
    SYSCALL_PROLOG kss_a, kss_t

    /* Jump to the actual handler */
    jmp SharedCode
.endfunc


#ifdef __ASM__
#define RPL_MASK                                0x0003
#define MODE_MASK                               0x0001
#define KGDT_R0_CODE                            (0x8)
#define KGDT_R0_DATA                            (0x10)
#define KGDT_R3_CODE                            (0x18)
#define KGDT_R3_DATA                            (0x20)
#define KGDT_TSS                                (0x28)
#define KGDT_R0_PCR                             (0x30)
#define KGDT_R3_TEB                             (0x38)
#define KGDT_LDT                                (0x48)
#define KGDT_DF_TSS                             (0x50)
#define KGDT_NMI_TSS                            (0x58)
#endif


prev mode
old exceptionlist
fs
di
si
bx
bp
0
ip
cs
flag
sp
ss


.macro SYSCALL_PROLOG Label EndLabel
    /* Create a trap frame */
    push 0
    push ebp
    push ebx
    push esi
    push edi
    push fs

    //内核态下,fs寄存器指向此
    /* Load PCR Selector into fs */
    mov ebx, KGDT_R0_PCR
    .byte 0x66
    mov fs, bx

    //获取当前线程的KTHREAD
    //偏移0x120处是KPRCB结构,+4是CurrentThread
    mov esi, PCR[KPCR_CURRENT_THREAD]

    /* Save the previous exception list */
    push PCR[KPCR_EXCEPTION_LIST]

    /* Set the exception handler chain terminator */
    mov dword ptr PCR[KPCR_EXCEPTION_LIST], -1

    //压入先前是内核态还是用户态
    push [esi+KTHREAD_PREVIOUS_MODE]

    /* Skip the other registers */
    //抬高72
    sub esp, 0x48

    /* Set the new previous mode based on the saved CS selector */
    //0x6C = 108 = 72 + 4 * 9,就是获取了压入的cs，算出mode
    mov ebx, [esp+0x6C]
    and ebx, 1
    mov byte ptr [esi+KTHREAD_PREVIOUS_MODE], bl

    /* Go on the Kernel stack frame */
    mov ebp, esp

    //老栈帧存ebp+0x3c
    mov ebx, [esi+KTHREAD_TRAP_FRAME]
    mov [ebp+KTRAP_FRAME_EDX], ebx

    /* Flush DR7 */
    and dword ptr [ebp+KTRAP_FRAME_DR7], 0

    //检查是否被调试
    test byte ptr [esi+KTHREAD_DEBUG_ACTIVE], 0xFF

    /* Set the thread's trap frame and clear direction flag */
    mov [esi+KTHREAD_TRAP_FRAME], ebp
    cld

    /* Save DR registers if needed */
    jnz Dr_&Label

    /* Set the trap frame debug header */
Dr_&EndLabel:
    //取原ip和bp存入frame
    SET_TF_DEBUG_HEADER

    /* Enable interrupts */
    sti
.endm

.macro SET_TF_DEBUG_HEADER
    /* Get the Debug Trap Frame EBP/EIP */
    mov ebx, [ebp+KTRAP_FRAME_EBP]
    mov edi, [ebp+KTRAP_FRAME_EIP]

    /* Write the debug data */
    mov [ebp+KTRAP_FRAME_DEBUGPOINTER], edx
    mov dword ptr [ebp+KTRAP_FRAME_DEBUGARGMARK], 0xBADB0D00
    mov [ebp+KTRAP_FRAME_DEBUGEBP], ebx
    mov [ebp+KTRAP_FRAME_DEBUGEIP], edi
.endm


SharedCode:

    //整除256
    //ecx变成0或16
    mov edi, eax
    shr edi, SERVICE_TABLE_SHIFT
    and edi, SERVICE_TABLE_MASK
    mov ecx, edi

    //线程的系统调用表
    //2张，取一张
    add edi, [esi+KTHREAD_SERVICE_TABLE]

    /* Get the true syscall ID and check it */
    mov ebx, eax
    and eax, SERVICE_NUMBER_MASK
    cmp eax, [edi+SERVICE_DESCRIPTOR_LIMIT]

    /* Invalid ID, try to load Win32K Table */
    //系统调用号过大
    jnb KiBBTUnexpectedRange

    /* Check if this was Win32K */
    cmp ecx, SERVICE_TABLE_TEST
    jnz NotWin32K
    ...
NotWin32K:
    //系统调用发生数
    inc dword ptr PCR[KPCR_SYSTEM_CALLS]

    /* Users's current stack frame pointer is source */
NoCountTable:
    //edx是用户空间传进来的参数块地址
    mov esi, edx

    /* Allocate room for argument list from kernel stack */
    //获取参数大小
    mov ebx, [edi+SERVICE_DESCRIPTOR_NUMBER]
    xor ecx, ecx
    mov cl, [eax+ebx]

    //获取函数地址
    mov edi, [edi+SERVICE_DESCRIPTOR_BASE]
    mov ebx, [edi+eax*4]

    /* Allocate space on our stack */
    sub esp, ecx

    /* Set the size of the arguments and the destination */
    shr ecx, 2
    mov edi, esp

    //参数块不得高于这个地址
    cmp esi, _MmUserProbeAddress
    //内核调系统调用也会进去，判断一下再出来
    jnb AccessViolation

CopyParams:
    /* Copy the parameters */
    rep movsd

    /* Do the System Call */
    call ebx

SkipCheck:

    /* Deallocate the kernel stack frame  */
    mov esp, ebp

KeReturnFromSystemCall:

    /* Get the Current Thread */
    mov ecx, PCR[KPCR_CURRENT_THREAD]

    /* Restore the old trap frame pointer */
    mov edx, [ebp+KTRAP_FRAME_EDX]
    mov [ecx+KTHREAD_TRAP_FRAME], edx
.endfunc


.func KiServiceExit
_KiServiceExit:
    /* Disable interrupts */
    cli

    /* Check for, and deliver, User-Mode APCs if needed */
    CHECK_FOR_APC_DELIVER 1

    /* Exit and cleanup */
    TRAP_EPILOG FromSystemCall, DoRestorePreviousMode, DoNotRestoreSegments, DoNotRestoreVolatiles, DoRestoreEverything
.endfunc





    #define KSEG0_BASE              0x80000000
   MmSystemRangeStart = (PVOID)KSEG0_BASE;
   MmUserProbeAddress = (ULONG_PTR)MmSystemRangeStart - 0x10000;


    KeServiceDescriptorTable[0].Base = MainSSDT
    KeServiceDescriptorTableShadow[0].Base = MainSSDT
    KeServiceDescriptorTableShadow[1].Base = Win32kSSDT

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
    PULONG_PTR Base;
    PULONG Count;
    ULONG Limit;
#if defined(_IA64_)
    LONG TableBaseGpOffset;
#endif
    //参数长度数组
    PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

//系统调用返回时可能会切换线程(DPC执行结束时间片用完)
//irql不一定是一下降到目标值的
    

快速系统调用:
SYSENTER_CS_MSR->cs
SYSENTER_EIP_MSR->ip
SYSENTER_CS_MSR + 8->ss
SYSENTRT_ESP_MSR->esp
返回时
SYSENTER_CS_MSR+16->cs
SYSENTER_CS_MSR->cs+24->ss
edx->ip
ecx->sp



ULONG_PTR
NTAPI
KiLoadFastSyscallMachineSpecificRegisters(IN ULONG_PTR Context)
{
    /* Set CS and ESP */
    Ke386Wrmsr(0x174, KGDT_R0_CODE, 0);
    Ke386Wrmsr(0x175, (ULONG)KeGetCurrentPrcb()->DpcStack, 0);

    /* Set LSTAR */
    Ke386Wrmsr(0x176, (ULONG)KiFastCallEntry, 0);
    return 0;
}

.macro FASTCALL_PROLOG Label EndLabel

    /* Set user selector */
    mov ecx, KGDT_R3_DATA | RPL_MASK

    /* Set FS to PCR */
    push KGDT_R0_PCR
    pop fs

    /* Set DS/ES to User Selector */
    mov ds, cx
    mov es, cx

    /* Set the current stack to Kernel Stack */
    //获取当前tss的sp0
    mov ecx, PCR[KPCR_TSS]
    mov esp, [ecx+KTSS_ESP0]

    /* Set up a fake INT Stack. */
    push KGDT_R3_DATA + RPL_MASK
    push edx                            /* Ring 3 SS:ESP */
    pushf                               /* Ring 3 EFLAGS */
    push 2                              /* Ring 0 EFLAGS */

    //进FASTCALL的时候有8字节的返回地址要跳过
    add edx, 8                          /* Skip user parameter list */
    popf                                /* Set our EFLAGS */

    or dword ptr [esp], EFLAGS_INTERRUPT_MASK   /* Re-enable IRQs in EFLAGS, to fake INT */
    push KGDT_R3_CODE + RPL_MASK
    //sysexit地址
    push dword ptr ds:KUSER_SHARED_SYSCALL_RET

    /* Setup the Trap Frame stack */
    push 0
    push ebp
    push ebx
    push esi
    push edi
    push KGDT_R3_TEB + RPL_MASK

    /* Save pointer to our PCR */
    mov ebx, PCR[KPCR_SELF]

    /* Get a pointer to the current thread */
    mov esi, [ebx+KPCR_CURRENT_THREAD]

    /* Set the exception handler chain terminator */
    push [ebx+KPCR_EXCEPTION_LIST]
    mov dword ptr [ebx+KPCR_EXCEPTION_LIST], -1

    /* Use the thread's stack */
    mov ebp, [esi+KTHREAD_INITIAL_STACK]
    //这里不理解

    /* Push previous mode */
    push UserMode

    /* Skip the other registers */
    sub esp, 0x48

    /* Make space for us on the stack */
    sub ebp, 0x29C

    /* Write the previous mode */
    mov byte ptr [esi+KTHREAD_PREVIOUS_MODE], UserMode

    /* Sanity check */
    cmp ebp, esp
    jnz BadStack

    /* Flush DR7 */
    and dword ptr [ebp+KTRAP_FRAME_DR7], 0

    /* Check if the thread was being debugged */
    test byte ptr [esi+KTHREAD_DEBUG_ACTIVE], 0xFF

    /* Set the thread's trap frame */
    mov [esi+KTHREAD_TRAP_FRAME], ebp

    /* Save DR registers if needed */
    jnz Dr_&Label

    /* Set the trap frame debug header */
Dr_&EndLabel:
    SET_TF_DEBUG_HEADER

    /* Enable interrupts */
    sti
.endm
