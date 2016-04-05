/*
 * main.c - runs when pmfs lcd boots
 */

#include <lcd_config/pre_hook.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include "internal.h"

#include <lcd_config/post_hook.h>

extern int registered;

/* LOOP ---------------------------------------- */

int init_pmfs_fs(void);
void exit_pmfs_fs(void);

static void main_and_loop(struct thc_channel_group *async_group)
{
	struct thc_channel_group_item *async_chnl = NULL;
	struct fipc_message *async_msg;
	int ret;
	int count = 0;
	int stop = 0;

	DO_FINISH(
			ASYNC({
					/*
					 * Initialize pmfs
					 */
					ret = init_pmfs_fs();
					if (ret) {
						LIBLCD_ERR("pmfs init failed");
						stop = 1;
					}
					LIBLCD_MSG("SUCCESSFULLY REGISTERED PMFS!");
				});
			/*
			 * Handle replies that are part of init sequence,
			 * and then function calls (like mount) ...
			 */
			while (!stop && !registered) {

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
				 *
				 * (Note: as mentioned above, this code will
				 * never fire, but we put it here for
				 * completeness.)
				 */
				ASYNC({
						ret = async_chnl->dispatch_fn(async_chnl->channel, 
									async_msg);
						if (ret) {
							LIBLCD_ERR("async dispatch failed");
							stop = 1;
						}
					});
			}

		);

	if (stop)
		goto out;
	stop = 0;

	DO_FINISH(
			/*
			 * Tear down pmfs
			 */
			ASYNC({
					exit_pmfs_fs();
					LIBLCD_MSG("SUCCESSFULLY UNREGISTERED PMFS!");
				});
			/*
			 * Listen for async replies for pmfs exit
			 */
			count = 0;
			while (!stop && registered) {

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
				 *
				 * (Note: as mentioned above, this code will
				 * never fire, but we put it here for
				 * completeness.)
				 */
				ASYNC({
						ret = async_chnl->dispatch_fn(async_chnl->channel, 
									async_msg);
						if (ret) {
							LIBLCD_ERR("async dispatch failed");
							stop = 1;
						}
					});
			}
		);

out:
	LIBLCD_MSG("EXITED PMFS DO_FINISH");

	return;
}

/* INIT/EXIT -------------------------------------------------- */

/* no sync channels to listen on */
struct thc_channel_group async_group;

static int __noreturn pmfs_lcd_init(void) 
{
	int r = 0;
	cptr_t vfs_chnl;

	r = lcd_enter();
	if (r)
		goto fail1;
	/*
	 * Initialize the async dispatch loop stuff
	 */
	r = thc_channel_group_init(&async_group);
	if (r) {
		LIBLCD_ERR("async group init");
		goto fail2;
	}
	/*
	 * Get the vfs channel cptr from boot info
	 */
	vfs_chnl = lcd_get_boot_info()->cptrs[0];
	/*
	 * Initialize vfs glue
	 */
	r = glue_vfs_init(vfs_chnl, &async_group);
	if (r) {
		LIBLCD_ERR("vfs init");
		goto fail3;
	}

	/* RUN CODE / LOOP ---------------------------------------- */

	main_and_loop(&async_group);

	/* DONE -------------------------------------------------- */

	glue_vfs_exit();

	lcd_exit(0); /* doesn't return */

fail3:
fail2:
fail1:
	lcd_exit(r);
}

static int __pmfs_lcd_init(void)
{
	int ret;

	LCD_MAIN({

			ret = pmfs_lcd_init();

		});

	return ret;
}

static void __exit pmfs_lcd_exit(void)
{
	return;
}

module_init(__pmfs_lcd_init);
module_exit(pmfs_lcd_exit);
MODULE_LICENSE("GPL");
