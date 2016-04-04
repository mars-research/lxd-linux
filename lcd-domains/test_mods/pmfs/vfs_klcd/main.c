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

#include "internal.h"

#include <lcd_config/post_hook.h>

/* LOOP -------------------------------------------------- */

static void loop(struct lcd_sync_channel_group *sync_group,
		struct thc_channel_group *async_group)
{
	struct lcd_sync_channel_group_item *sync_chnl = NULL;
	struct thc_channel_group_item *async_chnl = NULL;
	struct fipc_message *async_msg;
	int ret;
	int count = 0;
	int stop = 0;
	/*
	 * Listen once for PMFS register call. (In the future, we should
	 * periodically poll on the vfs channel for register fs calls
	 * from other isolated file systems. We have the infrastructure
	 * for it - use lcd_sync_channel_group_poll instead - but we don't
	 * use it for now.)
	 */
	count += 1;
	ret = lcd_sync_channel_group_recv(sync_group, sync_chnl, &sync_chnl);
	if (ret) {
		LIBLCD_ERR("lcd sync recv failed");
		return;
	}
	/*
	 * Handle register fs message. This should add an async channel
	 * to the async group.
	 */
	ret = sync_chnl->dispatch_fn(sync_chnl);
	if (ret) {
		LIBLCD_ERR("sync channel dispatch failed");
		return;
	}
	/*
	 * Listen on async group
	 *
	 * We may be able to fix this - but the ASYNC macros need to be
	 * syntactically nested under the DO_FINISH macro (i.e., we can't
	 * call a helper to do the body of the loop). 
	 */
	DO_FINISH(
		/*
		 * We use a variable to control when to abort the
		 * loop. Calling "break" inside an async just 
		 * exits out of the do { } while inside that macro;
		 * it doesn't break out of this loop. Furthermore,
		 * we could have blocked while running the async.
		 */
		while (!stop && count < 5) {
			count += 1;
			/*
			 * Do one async receive
			 */
			ret = thc_poll_recv_group(async_group,
						&async_chnl,
						&async_msg);
			if (ret) {
				if (ret == -EWOULDBLOCK)
					continue;
				else {
					LIBLCD_ERR("async recv failed");
					break;
				}
			}
			/*
			 * Got a message. Dispatch.
			 */
			ASYNC({
					ret = async_chnl->dispatch_fn(async_chnl->channel, 
								async_msg);
					if (ret) {
						LIBLCD_ERR("async dispatch failed");
						stop = 1;
					}
				});

			if (kthread_should_stop()) {
				LIBLCD_ERR("kthread should stop");
				break;
			}
		}
		);

	LIBLCD_MSG("EXITED VFS DO_FINISH");

	return;
}

/* INIT / EXIT ---------------------------------------- */

static struct lcd_sync_channel_group sync_group;
static struct thc_channel_group async_group;

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
	 * Init sync and async channel groups
	 */
	ret = thc_channel_group_init(&async_group);
	if (ret) {
		LIBLCD_ERR("async channel group init failed");
		goto fail3;
	}
	lcd_sync_channel_group_init(&sync_group);
	/*
	 * Init vfs glue
	 */
	ret = glue_vfs_init(vfs_chnl, &sync_group, &async_group);
	if (ret) {
		LIBLCD_ERR("vfs init");
		goto fail4;
	}
	/*
	 * Enter sync/async dispatch loop
	 */
	loop(&sync_group, &async_group);
	/*
	 * Tear down vfs glue
	 */
	glue_vfs_exit(&sync_group, &async_group);

	lcd_exit(0);
	
	return 0;

fail4:
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
