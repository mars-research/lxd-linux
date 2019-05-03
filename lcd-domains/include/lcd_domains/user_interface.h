#ifndef __LCD_USER_IF_H
#define __LCD_USER_IF_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>       /* printk() */
#include <linux/slab.h>         /* kmalloc() */
#include <linux/fs.h>           /* everything... */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mm.h>

int lcd_setup_chardev(const char* dev_name, const struct file_operations* fops);
void lcd_teardown_chardev(void);

#endif /* __LCD_USER_IF_H */

