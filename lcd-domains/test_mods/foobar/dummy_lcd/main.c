/*
 * main.c - runs when dummy lcd boots
 */

#include <lcd_config/pre_hook.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include "./foobar_caller.h"

#include <lcd_config/post_hook.h>

cptr_t foobar_register_channel;
struct thc_channel *foobar_async;
extern struct glue_cspace *foobar_cspace;
cptr_t foobar_sync_endpoint;
int dummy_done = 0;

int dummy_init_module(void);
void dummy_cleanup_module(void);

struct thc_channel_group ch_grp;

static void main_and_loop(void)
{
	int ret;
	int stop = 0;
	struct fipc_message *msg;
	DO_FINISH(

		ASYNC(
			ret = dummy_init_module();
			if (ret) {
				LIBLCD_ERR("dummy register failed");
				stop = 1;
			} else {
				LIBLCD_MSG("SUCCESSFULLY REGISTERED DUMMY!");
			}

			);

		/* By the time we hit this loop, the async channel
		 * will be set up (the awe running init_dummy_fs above
		 * will not yield until it tries to use the async
		 * channel). */
		while (!stop && !dummy_done) {
			struct thc_channel_group_item* curr_item;
			/*
			 * Do one async receive
			 */
			ret = thc_poll_recv_group(&ch_grp, &curr_item, &msg);
			if (likely(ret)) {
				if (ret == -EWOULDBLOCK) {
					cpu_relax();
					continue;
				} else {
					LIBLCD_ERR("async recv failed");
					stop = 1; /* stop */
				}
			}

			ASYNC(

			ret = dispatch_async_loop(curr_item->channel,
					msg,
					foobar_cspace, 
					foobar_sync_endpoint);
	
				if (ret) {
					LIBLCD_ERR("async dispatch failed");
					stop = 1;
				}
			);
		}
		
		LIBLCD_MSG("FOOBAR DUMMY EXITED DISPATCH LOOP");

		);

	LIBLCD_MSG("EXITED DUMMY DO_FINISH");

	return;
}

static int __noreturn dummy_lcd_init(void) 
{
	int r = 0;

	printk("LCD enter \n");
	r = lcd_enter();
	if (r)
		goto fail1;
	/*
	 * Get the foobar channel cptr from boot info
	 */
	foobar_register_channel = lcd_get_boot_info()->cptrs[0];

	printk("foobar reg channel %lu\n", foobar_register_channel.cptr);
	/*
	 * Initialize foobar glue
	 */
	r = glue_foobar_init();
	if (r) {
		LIBLCD_ERR("foobar init");
		goto fail2;
	}

	thc_channel_group_init(&ch_grp);
	/* RUN CODE / LOOP ---------------------------------------- */

	main_and_loop();

	/* DONE -------------------------------------------------- */

	glue_foobar_exit();

	lcd_exit(0); /* doesn't return */
fail2:
fail1:
	lcd_exit(r);
}

static int __dummy_lcd_init(void)
{
	int ret;

	LIBLCD_MSG("%s: entering", __func__);

	LCD_MAIN({

			ret = dummy_lcd_init();

		});

	return ret;
}

static void __exit dummy_lcd_exit(void)
{
	LIBLCD_MSG("%s: exiting", __func__);
	return;
}

module_init(__dummy_lcd_init);
module_exit(dummy_lcd_exit);
MODULE_LICENSE("GPL");

