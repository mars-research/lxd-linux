#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/foobar_device.h>
#include <linux/slab.h>
#include <linux/err.h>

int register_foobar(struct foobar_device *dev)
{
	int ret = 0;

	dev->hw_features |= FOOBAR_IRQ_DELAY;
	dev->features |= FOOBAR_SOFTIRQ_ENABLE;
	dev->wanted_features = dev->features & dev->hw_features;

	if (dev->flags & FOO_LOOPBACK)
		dev->hw_features |= FOOBAR_ZERO_COPY;

	if (dev->ext_name)
		printk("%s, ext name: %s\n", __func__, dev->ext_name);

	printk("%s, nr_rqs %d %d\n", __func__, dev->nr_rqs[0], dev->nr_rqs[1]);

	/* Init, if this function is available */
	if (dev->foobardev_ops->init) {
		ret = dev->foobardev_ops->init(dev);
		if (ret) {
			if (ret > 0)
				ret = -EIO;
			goto out;
		}
	}
	if (test_and_set_bit(FOOBAR_REGISTERED, &dev->state))
		printk("WARNING: Foobar already registered\n");

	printk("%s, foobar registered\n", __func__);

out:
	return ret;
}
EXPORT_SYMBOL(register_foobar);

void unregister_foobar(struct foobar_device *dev)
{
	/* uninit, if this function is available */
	if (dev->foobardev_ops->uninit) {
		dev->foobardev_ops->uninit(dev);
	}
	printk("%s, foobar unregistered\n", __func__);
}
EXPORT_SYMBOL(unregister_foobar);

struct foobar_device *alloc_foobardev(int id, const char* name)
{
	struct foobar_device *dev = kmalloc(sizeof(struct foobar_device), GFP_KERNEL);
	strncpy(dev->name, name, sizeof(dev->name));
	dev->id = id;
	return dev;
}
EXPORT_SYMBOL(alloc_foobardev);

void free_foobardev(struct foobar_device *dev)
{
	kfree(dev);
}
EXPORT_SYMBOL(free_foobardev);
