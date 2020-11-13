#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/foobar_device.h>
#include <linux/slab.h>
#include <linux/err.h>

static LIST_HEAD(foobar_dev_list);

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

	spin_lock(&dev->foo_shared_lock);

	if (test_and_set_bit(FOOBAR_REGISTERED, &dev->state))
		printk("WARNING: Foobar already registered\n");

	spin_unlock(&dev->foo_shared_lock);

	list_add_tail(&dev->dev_list, &foobar_dev_list);

	dev->u_field = 0xFEFE;
	dev->public_2 = 0xFEED;

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

struct foobar_device *alloc_foobardev(int id, const char* name, size_t sizeof_priv)
{
	struct foobar_device *dev;
	size_t alloc_size = sizeof(struct foobar_device);

	if (sizeof_priv) {
		/* ensure 32-byte alignment of private area */
		alloc_size = ALIGN(alloc_size, 32);
		alloc_size += sizeof_priv;
	}

	dev = kzalloc(alloc_size, GFP_KERNEL);

	strncpy(dev->name, name, sizeof(dev->name));
	dev->id = id;
	spin_lock_init(&dev->foo_shared_lock);
	return dev;
}
EXPORT_SYMBOL(alloc_foobardev);

void free_foobardev(struct foobar_device *dev)
{
	kfree(dev);
}
EXPORT_SYMBOL(free_foobardev);

void foobar_init_stats(struct foobar_device *dev)
{
	if (dev->dstats) {
		if (dev->flags & FOO_DSTATS_UPDATED) {
			dev->dstats->num_tx_packets = 10;
			dev->dstats->num_rx_packets = 200;
		}
	}
}
EXPORT_SYMBOL(foobar_init_stats);

#define FOOBAR_DEV_IRQ		0xf2

int foobar_state_change(struct foobar_device *dev)
{
	switch (dev->shared_state) {
		case FOO_SHARED_STATE:
			dev->irq = FOOBAR_DEV_IRQ; 
			printk("%s, shared_flags %x\n", __func__, dev->shared_flags);
			break;
		default:
			break;
	}
	return 0;
}
EXPORT_SYMBOL(foobar_state_change);

void foobar_notify(struct foobar_device *dev)
{
	printk("%s, called\n", __func__);
	schedule();
}
EXPORT_SYMBOL(foobar_notify);

void do_foobar_send(int dev_id, unsigned tag, unsigned data) {
	struct foobar_device *dev;
	list_for_each_entry(dev, &foobar_dev_list, dev_list) {
		if (dev->id == dev_id) {
			dev->active = true;
			dev->foobardev_ops->send(dev, tag, data);
			dev->active = false;
		}
	}
}

int do_foobar_open(int dev_id) {
	struct foobar_device *dev;
	list_for_each_entry(dev, &foobar_dev_list, dev_list) {
		if (dev->id == dev_id) {
			/* just update the base address */
			dev->base_addr = 0xFEDD0000;
		}
	}
}

int do_foobar_async_send(int dev_id, unsigned tag, unsigned data) {
	struct foobar_device *dev;
	list_for_each_entry(dev, &foobar_dev_list, dev_list) {
		if (dev->id == dev_id) {
			dev->foobardev_ops->send(dev, tag, data);
		}
	}
}

void foobar_bar(struct foobar_device *dev) {
	unsigned long fields = 0;
	fields |= dev->f1;
	printk("%s, fields %lx\n", __func__, fields);
}
EXPORT_SYMBOL(foobar_bar);

void foobar_bar2(struct foobar_device *dev) {
	unsigned long fields = 0;
	fields |= dev->f3;
	printk("%s, fields %lx\n", __func__, fields);
}
EXPORT_SYMBOL(foobar_bar2);


/* Called from a syscall or irq context */
void foobar_baz(int dev_id, unsigned long field) {
	struct foobar_device *dev;
	list_for_each_entry(dev, &foobar_dev_list, dev_list) {
		if (dev->id == dev_id) {
			if (dev->f2) {
				printk("%s, f2 active\n", __func__);
			}
		}
	}
}
