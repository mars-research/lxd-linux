/* dummy.c: a dummy foobar driver */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/foobar_device.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>

#define DRV_NAME	"foobardummy"
#define DRV_VERSION	"1.0"

static int dummy_dev_init(struct foobar_device *dev)
{
	spin_lock(&dev->foobar_lock);
	dev->dstats = kmalloc(sizeof(struct foo_stats), GFP_KERNEL);
	if (!dev->dstats) {
		spin_unlock(&dev->foobar_lock);
		return -ENOMEM;
	}
	spin_unlock(&dev->foobar_lock);
	return 0;
}

static void dummy_dev_uninit(struct foobar_device *dev)
{
	kfree(dev->dstats);
}

static const struct foobar_device_ops dummy_foobardev_ops = {
	.init		= dummy_dev_init,
	.uninit		= dummy_dev_uninit,
};

int numdummies = 0;
/* Number of dummy devices to be set up by this module. */
module_param(numdummies, int, 0);
MODULE_PARM_DESC(numdummies, "Number of dummy pseudo devices");

struct foobar_device *dev_dummy;

struct foobar_priv {
	int id;
};

static int __init dummy_init_module(void)
{
	int err;

	dev_dummy = alloc_foobardev(0, "dummy0");

	if (!dev_dummy)
		return -ENOMEM;

	dev_dummy->foobardev_ops = &dummy_foobardev_ops;
	dev_dummy->ext_name = kzalloc(16, GFP_KERNEL);

	dev_dummy->priv = kzalloc(sizeof(struct foobar_priv), GFP_KERNEL);

	if (dev_dummy->ext_name) {
		strncpy(dev_dummy->ext_name, "dummy_ext", 16);
	}

	dev_dummy->nr_rqs[0] = 1;
	dev_dummy->nr_rqs[1] = 2;

	dev_dummy->features = FOOBAR_PRIV_ALLOC;
	dev_dummy->flags = FOO_LOOPBACK;

	spin_lock_init(&dev_dummy->foobar_lock);
	err = register_foobar(dev_dummy);

	if (err < 0)
		goto err;
	return 0;

err:
	free_foobardev(dev_dummy);
	return err;
}

static void __exit dummy_cleanup_module(void)
{
	unregister_foobar(dev_dummy);
}

module_init(dummy_init_module);
module_exit(dummy_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
