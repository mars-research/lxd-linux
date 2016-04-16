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

cptr_t vfs_register_channel;
struct thc_channel *vfs_async_chnl;
struct glue_cspace *vfs_cspace;
cptr_t vfs_sync_endpoint;
int pmfs_done;

/* LOOP ---------------------------------------- */

static void main_and_loop(void)
{
	int ret;
	int stop = 0;
	struct fipc_message *msg;

	DO_FINISH(

		ASYNC(
			ret = init_pmfs_fs();
			if (ret) {
				LIBLCD_ERR("pmfs register failed");
				stop = 1;
			} else {
				PMFS_EX_DEBUG(LIBLCD_MSG("SUCCESSFULLY REGISTERED PMFS!"));
			}

			);

		/* By the time we hit this loop, the async channel
		 * will be set up (the awe running init_pmfs_fs above
		 * will not yield until it tries to use the async
		 * channel). */
		while (!stop && !pmfs_done) {
			/*
			 * Do one async receive
			 */
			ret = thc_ipc_poll_recv(vfs_async_chnl, &msg);
			if (ret) {
				if (ret == -EWOULDBLOCK) {
					continue;
				} else {
					LIBLCD_ERR("async recv failed");
					stop = 1; /* stop */
				}
			}
			/*
			 * Got a message. Dispatch.
			 */
			ASYNC(

				ret = dispatch_fs_channel(vfs_async_chnl, msg,
							vfs_cspace, 
							vfs_sync_endpoint);
				if (ret) {
					LIBLCD_ERR("async dispatch failed");
					stop = 1;
				}

				);
		}
		
		PMFS_EX_DEBUG(LIBLCD_MSG("PMFS EXITED DISPATCH LOOP"));

		);

	/*
	 * We don't expect any requests coming back to us, so it's safe
	 * to just run this without a loop (it's effectively polling since
	 * only one awe will run in this do-finish).
	 */
	DO_FINISH(
		ASYNC(
			exit_pmfs_fs();

			PMFS_EX_DEBUG(
				LIBLCD_MSG("SUCCESSFULLY UNREGISTERED PMFS!"));

			);
		);

	PMFS_EX_DEBUG(LIBLCD_MSG("EXITED PMFS DO_FINISH"));

	return;
}

/* INIT/EXIT -------------------------------------------------- */

static int __noreturn pmfs_lcd_init(void) 
{
	int r = 0;

	r = lcd_enter();
	if (r)
		goto fail1;
	/*
	 * Get the vfs channel cptr from boot info
	 */
	vfs_register_channel = lcd_get_boot_info()->cptrs[0];
	/*
	 * Initialize vfs glue
	 */
	r = glue_vfs_init();
	if (r) {
		LIBLCD_ERR("vfs init");
		goto fail2;
	}

	/* RUN CODE / LOOP ---------------------------------------- */

	main_and_loop();

	/* DONE -------------------------------------------------- */

	glue_vfs_exit();

	lcd_exit(0); /* doesn't return */

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
