udevd�û����̴����µ��豸���
/dev���ڴ����ļ�ϵͳ����ram

�ں˼�⵽�豸������kobject,����sysfs�������û���,�������Ȳ����Ϣ

sys_ioctl
IOCTL

typedef __u32 __kernel_dev_t;
typedef __kernel_dev_t		dev_t;
12λ���豸�ţ�20λ���豸��
Ϊ�˼��ݹ�ȥ��16λ�豸�ţ��ں˱�ʾ���û����ʾ��ͳһ


cdev��ʾ�ַ��豸
bdev��ʾ���豸����

ȫ������bdev_map���ڿ��豸
cdev_map�����ַ��豸
��ɢ�б�ʵ�� major%255����ɢ�м�

static struct kobj_map *cdev_map;
struct kobj_map {
	struct probe {
		struct probe *next;
		dev_t dev;
		unsigned long range;    //���豸�ŵ�������Χ
		struct module *owner;       //�豸����ģ��
		kobj_probe_t *get;
		int (*lock)(dev_t, void *);
		void *data;
	} *probes[255];
	struct mutex *lock;
};

//�ڶ����ַ��豸���ݿ�
major_to_index����ɢ��ֵ
static struct char_device_struct {
	struct char_device_struct *next;
	unsigned int major; //���豸��
	unsigned int baseminor; //minorct�����豸������С��
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
    //���մ������⣬�����range�Ǵ��豸�ţ�������޻��������豸��
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
