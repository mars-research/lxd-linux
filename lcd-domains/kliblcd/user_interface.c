/*
 * This file is meant to support interface with the user-process
 * which attempts to share a piece of memory with the LCD.
 *
 * (C) Abhiram Balasubramanian (abhiram@cs.utah.edu)
 */

/* Includes */
#include <lcd_domains/user_interface.h>

/* Defines */
#define DRV_MAX_DEVS    1

/* Globals */
static struct class *drv_class;
static struct cdev *cdev_local = NULL;
static struct device *dev = NULL;
dev_t dev_no = 0;

/* 
 * Creates a device node in the name of dev_name,
 * registers a set of file operations that is left
 * to the caller's control!
 */
int lcd_setup_chardev(const char* dev_name, const struct file_operations* fops)
{
        int ret = 0;
        
	printk("mod init \n");
        drv_class = class_create(THIS_MODULE, dev_name);
        if (IS_ERR(drv_class)) {
                printk(KERN_ERR "class_create failed \n");
                ret = PTR_ERR(drv_class);
                goto exit_no_class;
        }

        /* Dynamic registration of major number */
        printk("alloc chardev \n");
        ret = alloc_chrdev_region(&dev_no, 0, DRV_MAX_DEVS, dev_name);
        if (ret < 0){
                printk(KERN_ERR "Couldn't alloc chardev region \n");
                goto exit_chrdev_reg;
        }

        printk("cdev alloc \n");
        cdev_local = cdev_alloc();
        if(!cdev_local) {
                ret = -ENOMEM;
                printk("cdev_alloc- not enough memory \n");
                goto exit_cdev_alloc;
        }

        cdev_local->owner = THIS_MODULE;
        cdev_local->ops = fops;

        printk("cdev add \n");
        ret = cdev_add(cdev_local, dev_no, 1);
        if(ret) {
                printk("Cannot add cdev device \n");
                goto exit_dev_add;
        }

        printk("dev create \n");
        dev = device_create(drv_class, NULL, dev_no, NULL, "%s", dev_name);
        if(IS_ERR(dev)) {
                ret = PTR_ERR(dev);
                printk("Cannot create device node entry \n");
                goto exit_dev_create;
        }

        printk("init done \n");
        return 0;

exit_dev_create:

exit_dev_add:
        cdev_del(cdev_local);

exit_cdev_alloc:
        unregister_chrdev_region(dev_no, DRV_MAX_DEVS);

exit_chrdev_reg:
        class_destroy(drv_class);

exit_no_class:
        return ret;

}

void lcd_teardown_chardev(void)
{
        cdev_del(cdev_local);
        device_del(dev);
        unregister_chrdev_region(dev_no, DRV_MAX_DEVS);
        class_destroy(drv_class);
}

EXPORT_SYMBOL(lcd_setup_chardev);
EXPORT_SYMBOL(lcd_teardown_chardev);
