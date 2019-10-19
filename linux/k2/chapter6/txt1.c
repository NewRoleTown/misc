udevd用户进程创建新的设备结点
/dev不在磁盘文件系统而在ram

内核检测到设备，创建kobject,借助sysfs导出到用户层,并发送热插拔消息

sys_ioctl
IOCTL

typedef __u32 __kernel_dev_t;
typedef __kernel_dev_t		dev_t;
12位主设备号，20位从设备号
为了兼容过去的16位设备号，内核表示和用户层表示不统一


cdev表示字符设备
bdev表示块设备分区

全局数组bdev_map用于块设备
cdev_map用于字符设备
用散列表实现 major%255用于散列键

static struct kobj_map *cdev_map;
struct kobj_map {
	struct probe {
		struct probe *next;
		dev_t dev;
		unsigned long range;    //从设备号的连续范围
		struct module *owner;       //设备驱动模块
		kobj_probe_t *get;
		int (*lock)(dev_t, void *);
		void *data;
	} *probes[255];
	struct mutex *lock;
};

//第二个字符设备数据库
major_to_index计算散列值
static struct char_device_struct {
	struct char_device_struct *next;
	unsigned int major; //主设备号
	unsigned int baseminor; //minorct个从设备号中最小的
	int minorct;
	char name[64];
	struct file_operations *fops;
	struct cdev *cdev;		/* will die */
} *chrdevs[CHRDEV_MAJOR_HASH_SIZE];

void cdev_init(struct cdev *cdev, const struct file_operations *fops)
{
	memset(cdev, 0, sizeof *cdev);
	INIT_LIST_HEAD(&cdev->list);
	cdev->kobj.ktype = &ktype_cdev_default;
	kobject_init(&cdev->kobj);
	cdev->ops = fops;
}

int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
	p->dev = dev;
	p->count = count;
	return kobj_map(cdev_map, dev, count, NULL, exact_match, exact_lock, p);
}

int kobj_map(struct kobj_map *domain, dev_t dev, unsigned long range,
	     struct module *module, kobj_probe_t *probe,
	     int (*lock)(dev_t, void *), void *data)
{
    //按照代码的理解，输入的range是次设备号，如果超限会增加主设备号
	unsigned n = MAJOR(dev + range - 1) - MAJOR(dev) + 1;
	unsigned index = MAJOR(dev);
	unsigned i;
	struct probe *p;

	if (n > 255)
		n = 255;

	p = kmalloc(sizeof(struct probe) * n, GFP_KERNEL);

	if (p == NULL)
		return -ENOMEM;

	for (i = 0; i < n; i++, p++) {
		p->owner = module;
		p->get = probe;
		p->lock = lock;
		p->dev = dev;
		p->range = range;
		p->data = data;
	}
	mutex_lock(domain->lock);
	for (i = 0, p -= n; i < n; i++, p++, index++) {
		struct probe **s = &domain->probes[index % 255];
		while (*s && (*s)->range < range)
			s = &(*s)->next;
		p->next = *s;
		*s = p;
	}
	mutex_unlock(domain->lock);
	return 0;
}
IEEE1394_VIDEO1394_DEV
