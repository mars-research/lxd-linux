/**
 * core.c - Main file for the LCD module
 *
 *
 * Authors:
 *   Anton Burtsev   <aburtsev@flux.utah.edu>
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/compat.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/lcd-domains.h>
#include <asm/lcd-vmx.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LCD driver");

static long lcd_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	long r = -EINVAL;
	//struct lcd_pv_kernel_config conf;

	switch (ioctl) {
	case LCD_LOAD_PV_KERNEL:
		//r = copy_from_user(&conf, (int __user *) arg,
		//		   sizeof(struct lcd_pv_kernel_config));
		//if (r) {
		//	r = -EIO;
		//	goto out;
		//}

		/* create LCD with a PV Linux kernel */
		return r;
		break;

	default:
		return -ENOTTY;
	}

//out:
//	return r;
}

static const struct file_operations lcd_chardev_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= lcd_dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= lcd_dev_ioctl,
#endif
	.llseek		= noop_llseek,
};

static struct miscdevice lcd_dev = {
	LCD_MINOR,
	"lcd",
	&lcd_chardev_ops,
};

static int __init lcd_init(void)
{
	int r;

	printk(KERN_ERR "LCD module loaded\n");

	if ((r = lcd_vmx_init())) {
		printk(KERN_ERR "lcd: failed to initialize vmx\n");
		return r;
	}

	r = misc_register(&lcd_dev);
	if (r) {
		printk(KERN_ERR "lcd: misc device register failed\n");
		
	}

	return r;
}

static void __exit lcd_exit(void)
{
	misc_deregister(&lcd_dev);
	lcd_vmx_exit();
}

module_init(lcd_init);
module_exit(lcd_exit);
