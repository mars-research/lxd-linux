#include <lcd_config/pre_hook.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <thc.h>
#include "foobar_callee.h"

#include <lcd_config/post_hook.h>

/* mechanism for unloading LCD gracefully */
static bool unload_lcd = false;
module_param_named(unload, unload_lcd, bool, S_IWUSR);

struct channel_info {
	struct thc_channel *chnl;
	struct glue_cspace *cspace;
	cptr_t sync_endpoint;
	struct list_head list;
};
static LIST_HEAD(foobar_infos);

extern int trigger_exit_to_lcd(struct thc_channel *_channel, enum dispatch_t);

struct channel_info *
add_chnl(struct thc_channel *chnl, struct glue_cspace *cspace,
	cptr_t sync_endpoint)
{
	struct channel_info *channel_info;
	
	channel_info = kmalloc(sizeof(*channel_info), GFP_KERNEL);
	if (!channel_info)
		goto fail1;
	channel_info->chnl = chnl;
	channel_info->cspace = cspace;
	channel_info->sync_endpoint = sync_endpoint;

	INIT_LIST_HEAD(&channel_info->list);
	list_add(&channel_info->list, &foobar_infos);

	return channel_info;

fail1:
	return NULL;
}

void remove_chnl(struct channel_info *foobar)
{
	list_del_init(&foobar->list);
	kfree(foobar);
}

static int __get_chnl(struct channel_info **chnl_out)
{
	struct channel_info *first;
	first = list_first_entry_or_null(&foobar_infos, struct channel_info, list);
	if (first)
		*chnl_out = first;
	return first ? 1 : 0;
}

static int async_loop(struct channel_info **fs_out, struct fipc_message **msg_out)
{
	struct channel_info *cursor, *next;
	int ret;

	list_for_each_entry_safe(cursor, next, &foobar_infos, list) {

		ret = thc_ipc_poll_recv(cursor->chnl, msg_out);
		if (ret == -EPIPE) {
			/*
			 * fs channel is dead; free the channel,
			 * and remove from list
			 */
			kfree(cursor->chnl);
			remove_chnl(cursor);
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

/* LOOP -------------------------------------------------- */
static int do_one_register(cptr_t register_chnl)
{
	int ret;
	cptr_t sync_endpoint, tx, rx;
	cptr_t tx_xmit, rx_xmit;
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
	ret = lcd_cptr_alloc(&tx_xmit);
	if (ret) {
		LIBLCD_ERR("cptr alloc failed");
		goto fail2;
	}
	ret = lcd_cptr_alloc(&rx_xmit);
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
	lcd_set_cr3(tx_xmit);
	lcd_set_cr4(rx_xmit);
	ret = lcd_sync_poll_recv(register_chnl);
	if (ret) {
		if (ret == -EWOULDBLOCK)
			ret = 0;
		goto free_cptrs;
	}
	/*
	 * Dispatch to register handler
	 */
	dispatch_sync_loop();

	return 0;

free_cptrs:
	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);
	lcd_set_cr2(CAP_CPTR_NULL);
	lcd_set_cr3(CAP_CPTR_NULL);
	lcd_set_cr4(CAP_CPTR_NULL);
	lcd_cptr_free(sync_endpoint);
fail3:
	lcd_cptr_free(tx);
	lcd_cptr_free(tx_xmit);
fail2:
	lcd_cptr_free(rx);
	lcd_cptr_free(rx_xmit);
fail1:
	return ret;
}
#define REGISTER_FREQ	50
static void loop(cptr_t register_chnl)
{
	unsigned long tics = jiffies + REGISTER_FREQ;
	struct fipc_message *msg;
	struct channel_info *chnl;
	int stop = 0;
	int ret;
	u64 count = 0;

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
				tics = jiffies + REGISTER_FREQ;
				continue;
			}
			if (stop)
				break;
			/*
			 * will be updated by a write into sysfs
			 * from userspace.
			 */
			if (unload_lcd) {
				if (__get_chnl(&chnl)) {
					if (unload_lcd) {
						trigger_exit_to_lcd(chnl->chnl, TRIGGER_EXIT);
						unload_lcd ^= unload_lcd;
					}
				}
			}

			ret = async_loop(&chnl, &msg);
			if (!ret) {
				ASYNC(
					ret = dispatch_async_loop(
						chnl->chnl,
						msg,
						chnl->cspace,
						chnl->sync_endpoint);
					if (ret) {
						LIBLCD_ERR("chnl dispatch err");
						/* (break won't work here) */
						stop = 1;
					}
					);
			} else if (ret != -EWOULDBLOCK) {
				LIBLCD_ERR("async loop failed");
				stop = 1;
				break;
			}

			if (kthread_should_stop()) {
					LIBLCD_MSG("kthread should stop");
				stop = 1;
				break;
			}
			
#ifndef CONFIG_PREEMPT
			cpu_relax();
			/*
			 * Play nice with the rest of the system
			 */
			if ((count++ % 65536) == 0)
				cond_resched();
#endif
		}

		LIBLCD_MSG("foobar layer exited loop");

		);

	LIBLCD_MSG("EXITED DUMMY DO_FINISH");
}

/* INIT / EXIT ---------------------------------------- */
struct cspace *klcd_cspace;
static int foobar_klcd_init(void) 
{
	int ret;
	cptr_t foobar_chnl;
	/*
	 * Set up cptr cache, etc.
	 */
	ret = lcd_enter();
	if (ret) {
		LIBLCD_ERR("lcd enter");
		goto fail1;
	}

	/*
	 * XXX: Hack: boot provided us with one cptr for the net chnl
	 */
	ret = lcd_cptr_alloc(&foobar_chnl);
	if (ret) {
		LIBLCD_ERR("alloc cptr");
		goto fail2;
	}
	LIBLCD_MSG("==========> got cptr %lu\n", foobar_chnl.cptr);
	/* save cspace for future use
	 * when userspace functions call function pointers,
	 * we need to get access to the sync_ep of this klcd
	 * to transfer pointers and data thro sync IPC to the lcd
	 */
	klcd_cspace = get_current_cspace(current);
	/*
	 * Init foobar glue
	 */
	ret = glue_foobar_init();
	LIBLCD_MSG("-===== > glue foobar init called\n");
	if (ret) {
		LIBLCD_ERR("net init");
		goto fail3;
	}

	/*
	 * Enter sync/async dispatch loop
	 */
	LIBLCD_MSG(">>>>> Looping .... \n");
	loop(foobar_chnl);
	/*
	 * Tear down net glue
	 */
	glue_foobar_exit();

	lcd_exit(0);
	
	return 0;

fail3:
fail2:
	lcd_exit(ret);
fail1:
	return ret;
}

static int __foobar_klcd_init(void)
{
	int ret;
	LIBLCD_MSG("%s: entering", __func__);
	LCD_MAIN({

			ret = foobar_klcd_init();

		});
	return ret;
}

/* 
 * make module loader happy (so we can unload). we don't actually call
 * this before unloading the lcd (yet)
 */
static void __exit foobar_klcd_exit(void)
{
	LIBLCD_MSG("%s: exiting", __func__);
	return;
}

module_init(__foobar_klcd_init);
module_exit(foobar_klcd_exit);
MODULE_LICENSE("GPL");
