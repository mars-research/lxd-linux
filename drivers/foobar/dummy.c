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
	dev->dstats = kmalloc(sizeof(struct foo_stats), GFP_KERNEL);
	if (!dev->dstats)
		return -ENOMEM;

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

static int __init dummy_init_module(void)// the entry point to the dummy device driver
{
	int err;

	dev_dummy = alloc_foobardev(0, "dummy0");

	if (!dev_dummy)
		return -ENOMEM;

	dev_dummy->foobardev_ops = &dummy_foobardev_ops;

	dev_dummy->features = FOOBAR_PRIV_ALLOC;
	dev_dummy->flags = FOO_LOOPBACK;

	err = register_foobar(dev_dummy);//the call to dev.c fn to register dummy
	if (err < 0)
		goto err;
	return 0;

err:
	free_foobardev(dev_dummy);// free the foobar device if an error code is received
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
