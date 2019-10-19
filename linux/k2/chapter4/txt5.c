内核缺页中断时，除了vmalloc外都启用exception fixup
内核与用户发生数据复制时可能发生缺页,这种可能发生问题的代码都会被记录到
__start_exception_table开始的表格中
表项
struct exception_table_entry
{
    //insn指定位置,fixup指定恢复地址
	unsigned long insn, fixup;
};

//用于搜索异常表
int fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;

#ifdef CONFIG_PNPBIOS
    ...
#endif

	fixup = search_exception_tables(regs->eip);
	if (fixup) {
		regs->eip = fixup->fixup;
		return 1;
	}

	return 0;
}
