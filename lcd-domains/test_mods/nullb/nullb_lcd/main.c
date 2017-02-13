/*
 * main.c - runs when dummy lcd boots
 */

#include <lcd_config/pre_hook.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include "./nullb_caller.h"

#include <lcd_config/post_hook.h>

cptr_t blk_register_chnl;
cptr_t blk_sync_endpoint;
struct thc_channel *blk_async_chl;
struct glue_cspace *blk_cspace;
cptr_t blk_sync_ep;
int nullb_done = 0;
int null_init(void);
void null_exit(void);

/* LOOP ---------------------------------------- */

static void main_and_loop(void)
{
	int ret;
	int stop = 0;
	struct fipc_message *msg;
	DO_FINISH(

		ASYNC(
			ret = null_init();
			if (ret) {
				LIBLCD_ERR("nullb init failed");
				stop = 1;
			} else {
				LIBLCD_MSG("SUCCESSFULLY REGISTERED DUMMY!");
			}

			);

		/* By the time we hit this loop, the async channel
		 * will be set up (the awe running init_dummy_fs above
		 * will not yield until it tries to use the async
		 * channel). */
		while (!stop && !nullb_done) {
			/*
			 * Do one async receive
			 */
			ret = thc_ipc_poll_recv(blk_async_chl, &msg);
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

				ret = dispatch_async_loop(blk_async_chl, msg,
							blk_cspace, 
							blk_sync_ep);
				if (ret) {
					LIBLCD_ERR("async dispatch failed");
					stop = 1;
				}

				);
		}
		
		LIBLCD_MSG("NULLB EXITED DISPATCH LOOP");

		);

	/*
	 * We don't expect any requests coming back to us, so it's safe
	 * to just run this without a loop (it's effectively polling since
	 * only one awe will run in this do-finish).
	 */
	if (1) 
	DO_FINISH(
		ASYNC(
			null_exit();

			
				LIBLCD_MSG("SUCCESSFULLY UNREGISTERED NULLNET!");

			);
		);

	LIBLCD_MSG("EXITED PMFS DO_FINISH");

	return;
}

static int __noreturn nullb_lcd_init(void) 
{
	int r = 0;

	printk("LCD enter \n");
	r = lcd_enter();
	if (r)
		goto fail1;
	/*
	 * Get the blk channel cptr from boot info.
	 * Remember - lcd_get_boot_info()->cptrs[0] holds the slot
	 * in the cspace where blk_chnl was granted by the boot module!
	 */
	blk_register_chnl = lcd_get_boot_info()->cptrs[0];
	printk("blk reg channel %lu\n", blk_register_chnl.cptr);
	/*
	 * Initialize nullb glue
	 */
	r = glue_nullb_init();
	if (r) {
		LIBLCD_ERR("nullb init");
		goto fail2;
	}

	/* RUN CODE / LOOP ---------------------------------------- */

	main_and_loop();

	/* DONE -------------------------------------------------- */

	glue_nullb_exit();

	lcd_exit(0); /* doesn't return */
fail2:
fail1:
	lcd_exit(r);
}

static int __nullb_lcd_init(void)
{
	int ret;

	LIBLCD_MSG("%s: entering", __func__);

	LCD_MAIN({

			ret = nullb_lcd_init();

		});

	return ret;
}

static void __exit nullb_lcd_exit(void)
{
	LIBLCD_MSG("%s: exiting", __func__);
	return;
}

module_init(__nullb_lcd_init);
module_exit(nullb_lcd_exit);
MODULE_LICENSE("GPL");

