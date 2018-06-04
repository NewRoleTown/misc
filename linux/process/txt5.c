�ں�ȱҳ�ж�ʱ������vmalloc�ⶼ����exception fixup
�ں����û��������ݸ���ʱ���ܷ���ȱҳ,���ֿ��ܷ�������Ĵ��붼�ᱻ��¼��
__start_exception_table��ʼ�ı����
����
struct exception_table_entry
{
    //insnָ��λ��,fixupָ���ָ���ַ
	unsigned long insn, fixup;
};

//���������쳣��
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
