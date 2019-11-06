每个非叶函数至少对应一个runtime_function结构体
runtime_function 在pe dict 异常对应的目录项中(idx = 3);
typedef struct _RUNTIME_FUNCTION {
	ULONG BeginAddress;		//rva
	ULONG EndAddress;		//rva
	ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

typedef struct _UNWIND_INFO {
	UCHAR Version : 3;
	UCHAR Flags : 5;
	UCHAR SizeOfProlog;
	UCHAR CountOfCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];

}UNWIND_INFO,*PUNWIND_INFO;
    #define UNW_FLAG_NHANDLER 0x0
    #define UNW_FLAG_EHANDLER 0x1	//存在catch
    #define UNW_FLAG_UHANDLER 0x2	//存在fainally
    #define UNW_FLAG_CHAININFO 0x4

typedef union _UNWIND_CODE {
	struct {
		UCHAR CodeOffset;			//在这个代码偏移处有回滚操作
		UCHAR UnwindOp : 4;
		UCHAR OpInfo : 4;
	};

	USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

unwindcode
后有exception_handler_0的地址，在之后是scope表
+00	start address		//发生异常的地址地址范围
+04	end_address
+08	finally_address(finally),filter address
+12	0(finally),catch address
