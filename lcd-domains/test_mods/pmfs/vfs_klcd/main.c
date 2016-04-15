/*
 * main.c - module init/exit for vfs klcd
 */

#include <lcd_config/pre_hook.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <thc.h>

#include "internal.h"

#include <lcd_config/post_hook.h>

/* Don't use e.g. 0.5 * HZ. This will use floating point instructions.
 * I thik floating point in general is bad in the kernel. But it's
 * especially bad with thc/async. */
#define VFS_REGISTER_FREQ (50)

struct fs_info {
	struct thc_channel *chnl;
	struct glue_cspace *cspace;
	cptr_t sync_endpoint;
	struct list_head list;
};
static LIST_HEAD(fs_infos);

int pmfs_ready;

struct fs_info * 
add_fs(struct thc_channel *chnl, struct glue_cspace *cspace,
	cptr_t sync_endpoint)
{
	struct fs_info *fs_info;
	
	fs_info = kmalloc(sizeof(*fs_info), GFP_KERNEL);
	if (!fs_info)
		goto fail1;
	fs_info->chnl = chnl;
	fs_info->cspace = cspace;
	fs_info->sync_endpoint = sync_endpoint;
	INIT_LIST_HEAD(&fs_info->list);
	list_add(&fs_info->list, &fs_infos);

	return fs_info;

fail1:
	return NULL;
}

void remove_fs(struct fs_info *fs)
{
	list_del_init(&fs->list);
	kfree(fs);
}

/* LOOP ------------------------------------------------------------ */

static int async_loop(struct fs_info **fs_out, struct fipc_message **msg_out)
{
	struct fs_info *cursor, *next;
	int ret;

	list_for_each_entry_safe(cursor, next, &fs_infos, list) {

		ret = thc_ipc_poll_recv(cursor->chnl, msg_out);
		if (ret == -EPIPE) {
			/*
			 * fs channel is dead; free the channel,
			 * and remove from list
			 */
			kfree(cursor->chnl);
			remove_fs(cursor);
		} else if (ret == -EWOULDBLOCK) {
			/*
			 * Skip over empty channels
			 */
			continue;
		} else if (ret) {
			/*
			 * Unexpected error
			 */
			LIBLCD_ERR("error ret = %d on async channel");
			return ret;
		} else {
			/*
			 * Got a msg
			 */
			*fs_out = cursor;
			return 0;
		}

	}
	/*
	 * Nothing for us to recv right now
	 */
	return -EWOULDBLOCK;
}

static int do_one_register(cptr_t register_chnl)
{
	int ret;
	cptr_t sync_endpoint, tx, rx;
	/*
	 * Set up cptrs
	 */
	ret = lcd_cptr_alloc(&sync_endpoint);
	if (ret) {
		LIBLCD_ERR("cptr alloc failed");
		goto fail1;
	}
	ret = lcd_cptr_alloc(&tx);
	if (ret) {
		LIBLCD_ERR("cptr alloc failed");
		goto fail2;
	}
	ret = lcd_cptr_alloc(&rx);
	if (ret) {
		LIBLCD_ERR("cptr alloc failed");
		goto fail3;
	}
	/*
	 * Set up regs and poll
	 */
	lcd_set_cr0(sync_endpoint);
	lcd_set_cr1(tx);
	lcd_set_cr2(rx);
	ret = lcd_sync_poll_recv(register_chnl);
	if (ret) {
		if (ret == -EWOULDBLOCK)
			ret = 0;
		goto free_cptrs;
	}
	/*
	 * Dispatch to register handler
	 */
	ret = dispatch_sync_vfs_channel();
	if (ret)
		return ret; /* dispatch fn is responsible for cptr cleanup */

	return 0;

free_cptrs:
	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);
	lcd_set_cr2(CAP_CPTR_NULL);
	lcd_cptr_free(sync_endpoint);
fail3:
	lcd_cptr_free(tx);
fail2:
	lcd_cptr_free(rx);
fail1:
	return ret;
}

static int do_pmfs_test(void)
{
	int ret;
	struct dentry *dentry;
	struct super_block *sb;
	char *data;
	int i;
	unsigned long start, stop;
	struct file_system_type *pmfs_fs_type;

	pmfs_fs_type = get_fs_type("pmfs_lcd");
	if (!pmfs_fs_type) {
		LIBLCD_ERR("couldn't get pmfs fs type");
		ret = -EIO;
		goto fail1;
	}

	PMFS_EX_DEBUG(LIBLCD_MSG("vfs got pmfs fs type"));

	/* 
	 * We can't pass this as a const char *, because pmfs
	 * (indirectly through the vfs glue) needs to modify it
	 * when it calls strsep. This is true even in the regular
	 * world (take a look at how the void *data arg is set up,
	 * and you will see).
	 */
	data = kstrdup("physaddr=0x100000000,init=2G", GFP_KERNEL);
	if (!data) {
		LIBLCD_ERR("strdup failed");
		goto fail2;
	}

	printk(KERN_ERR "Mount timings:\n\n");

	for (i = 0; i < PMFS_EXAMPLE_NUM_ITER; i++) {

		PMFS_EX_DEBUG(LIBLCD_MSG("vfs mounting pmfs, iter %d", i));

		start = pmfs_ex_start_stopwatch();
		dentry = pmfs_fs_type->mount(pmfs_fs_type,
					0,
					"/not/used",
					data);
		stop = pmfs_ex_stop_stopwatch();
		if (!dentry) {
			LIBLCD_ERR("error mounting pmfs?");
			ret = -EIO;
			goto fail3;
		}

		printk(KERN_ERR "%d: %lu\n", i, stop - start);

		PMFS_EX_DEBUG(LIBLCD_MSG("vfs mounted pmfs"));

		sb = dentry->d_sb;
	
		PMFS_EX_DEBUG(LIBLCD_MSG("vfs calling kill_sb"));

		dput(dentry);
		deactivate_locked_super(sb);
		PMFS_EX_DEBUG(LIBLCD_MSG("vfs unmounted pmfs, iter %d", i));

	}

	printk(KERN_ERR "Mount Experiment Done\n");

	kfree(data);

	module_put(pmfs_fs_type->owner); /* release reference */
			
	return 0;

fail3:
	kfree(data);
fail2:
	module_put(pmfs_fs_type->owner); /* release reference */
	pmfs_fs_type = NULL;
fail1:
	return ret;
}

static void loop(cptr_t register_chnl)
{
	unsigned long tics = jiffies + VFS_REGISTER_FREQ;
	struct fipc_message *msg;
	struct fs_info *fs;
	int stop = 0;
	int ret;

	DO_FINISH(

		while (!stop) {

			if (jiffies >= tics) {
				/*
				 * Listen for a register call
				 */
				ret = do_one_register(register_chnl);
				if (ret) {
					LIBLCD_ERR("register error");
					break;
				}
				tics = jiffies + VFS_REGISTER_FREQ;
				continue;
			}

			if (pmfs_ready) {
				pmfs_ready = 0;
				ASYNC(
					stop = do_pmfs_test();
					);
			}

			if (stop)
				break;
			ret = async_loop(&fs, &msg);
			if (!ret) {
				ASYNC(
					ret = dispatch_async_vfs_channel(
						fs->chnl, 
						msg,
						fs->cspace,
						fs->sync_endpoint);
					if (ret) {
						LIBLCD_ERR("fs dispatch err");
						/* (break won't work here) */
						stop = 1;
					}
					);
			} else if (ret != -EWOULDBLOCK) {
				PMFS_EX_DEBUG(LIBLCD_ERR("async loop failed"));
				stop = 1;
				break;
			}

			if (kthread_should_stop()) {
				PMFS_EX_DEBUG(
					LIBLCD_MSG("kthread should stop"));
				stop = 1;
				break;
			}

#ifndef CONFIG_PREEMPT
			/*
			 * Play nice with the rest of the system
			 */
			cond_resched();
#endif
		}

		PMFS_EX_DEBUG(LIBLCD_MSG("vfs exited loop"));

		THCStopAllAwes();

		);

	/* 
	 * NOTE: If the vfs klcd quits / is killed before 
	 * unregister_filesystem runs, it could cause some proc fs
	 * crap to crash (the struct file_system_type is still in
	 * the registered fs list, but e.g. the const char *name just
	 * went bye-bye when we unloaded the vfs's .ko.)
	 */

	PMFS_EX_DEBUG(LIBLCD_MSG("EXITED VFS DO_FINISH"));

	return;
}

/* INIT / EXIT ---------------------------------------- */

static int vfs_klcd_init(void) 
{
	int ret;
	cptr_t vfs_chnl;
	/*
	 * Set up cptr cache, etc.
	 */
	ret = lcd_enter();
	if (ret) {
		LIBLCD_ERR("lcd enter");
		goto fail1;
	}
	/*
	 * XXX: Hack: boot provided us with one cptr for the vfs channel
	 */
	ret = lcd_cptr_alloc(&vfs_chnl);
	if (ret) {
		LIBLCD_ERR("alloc cptr");
		goto fail2;
	}
	/*
	 * Init vfs glue
	 */
	ret = glue_vfs_init();
	if (ret) {
		LIBLCD_ERR("vfs init");
		goto fail3;
	}
	/*
	 * Enter sync/async dispatch loop
	 */
	loop(vfs_chnl);
	/*
	 * Tear down vfs glue
	 */
	glue_vfs_exit();

	lcd_exit(0);
	
	return 0;

fail3:
fail2:
	lcd_exit(ret);
fail1:
	return ret;
}

static int __vfs_klcd_init(void)
{
	int ret;

	LCD_MAIN({

			ret = vfs_klcd_init();

		});

	return ret;
}

/* 
 * make module loader happy (so we can unload). we don't actually call
 * this before unloading the lcd (yet)
 */
static void __exit vfs_klcd_exit(void)
{
	return;
}

module_init(__vfs_klcd_init);
module_exit(vfs_klcd_exit);
MODULE_LICENSE("GPL");
