/*
 * main.c - runs when dummy lcd boots
 */

#include <lcd_config/pre_hook.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include "./nullnet_caller.h"

#include "../rdtsc_helper.h"
#include <lcd_config/post_hook.h>

cptr_t nullnet_register_channel;
cptr_t nullnet_register_channels[NUM_LCDS];
struct thc_channel *net_asyncs[NUM_LCDS];
struct glue_cspace *nullnet_cspace;
cptr_t nullnet_sync_endpoints[NUM_LCDS];
int dummy_done = 0;
int dummy_init_module(void);
void dummy_cleanup_module(void);
struct thc_channel_group ch_grp[NUM_LCDS];

bool tdiff_valid = false;
u64 tdiff_disp = 0ull;
TS_DECL(disp_loop);
/* LOOP ---------------------------------------- */
#define REPORT_LCD_LOAD

void create_async_channel(void);

static void main_and_loop(void)
{
	int ret;
	int stop = 0;
	int once = 1;
#ifdef REPORT_LCD_LOAD
	unsigned long long start_disp, end_disp;
	unsigned long long start_g, end_g, diff_g;
	unsigned long long disp_loop_cycles = 0, percent = 0;
#endif
	struct fipc_message *msg;

	DO_FINISH(

		/* parent LCD initializes the module */
		if (current_lcd_id == 0) {
			ASYNC(
				ret = dummy_init_module();
				if (ret) {
					LIBLCD_ERR("dummy register failed");
					stop = 1;
				} else {
					LIBLCD_MSG("SUCCESSFULLY REGISTERED DUMMY!");
				}

				);
		} else {
			create_async_channel();
		}

		/* By the time we hit this loop, the async channel
		 * will be set up (the awe running init_dummy_fs above
		 * will not yield until it tries to use the async
		 * channel). */
		while (!stop && !dummy_done) {
			struct thc_channel_group_item* curr_item;
			if (once) {
				printk("%s, LCD:%d looping", __func__, current_lcd_id);
				once = 0;

				list_for_each_entry(curr_item, &(ch_grp[current_lcd_id].head), list) {
					printk("%s, curr_item->channel %p is_xmit: %d", __func__,
							curr_item->channel, curr_item->xmit_channel);
				}
			}

#ifdef REPORT_LCD_LOAD
			if (!start_g)
				start_g = lcd_RDTSC_START();

			end_g = lcd_RDTSC_STOP();

			diff_g = end_g - start_g;
			/* if it's greater than or equal to 5 seconds */
			if (diff_g >= 10999820000ULL) {
#ifdef CALC_PERCENTAGE
				if (disp_loop_cycles) {
					unsigned long long _diff_g = diff_g;
					do_div(_diff_g, disp_loop_cycles);
					percent = 100;
					printk("dividend %llu | divisor %llu", percent, _diff_g);
					do_div(percent, _diff_g);
				} else {
					percent = 0;
				}
#endif
				if (disp_loop_cycles) {
					u64 div = diff_g / disp_loop_cycles;
					percent = 100;
					LIBLCD_MSG("total_time: %llu | disp_loop %llu | div: %llu percent: %llu",
						diff_g, disp_loop_cycles, div, percent/div);
				}
				start_g = lcd_RDTSC_START();
				// reset disp_loop_cycles
				disp_loop_cycles = 0;
			}

#endif
			/*
			 * Do RR async receive
			 */
			list_for_each_entry(curr_item, &(ch_grp[current_lcd_id].head), list) {
				if (curr_item->xmit_channel) {
					ret = fipc_nonblocking_recv_start_if(
						thc_channel_to_fipc(
						thc_channel_group_item_channel(curr_item)),
						&msg);
				} else {
					ret = thc_ipc_poll_recv(thc_channel_group_item_channel(curr_item),
						&msg);
				}

				if( !ret )
				{
					start_disp = lcd_RDTSC_START();
					/* message for us */
					if (async_msg_get_fn_type(msg) == NDO_START_XMIT) {

						//printk("%s, got msg on xmit ch: %p", __func__, curr_item->channel);
						if (fipc_get_reg0(msg)) {
						ret = ndo_start_xmit_async_bare_callee(msg,
							curr_item->channel,
							nullnet_cspace,
							nullnet_sync_endpoints[current_lcd_id]);
						} else {
							//printk("%s, LCD:%d got XMIT msg on chnl: %p",
							//		__func__, current_lcd_id, curr_item->channel);
						ret = ndo_start_xmit_noawe_callee(msg,
							curr_item->channel,
							nullnet_cspace,
							nullnet_sync_endpoints[current_lcd_id]);
						}
						if (likely(ret)) {
							LIBLCD_ERR("async dispatch failed");
							stop = 1;
						}

					} else {
					ASYNC(

					ret = dispatch_async_loop(curr_item->channel,
							msg,
							nullnet_cspace,
							nullnet_sync_endpoints[current_lcd_id]);

						if (ret) {
							LIBLCD_ERR("async dispatch failed");
							stop = 1;
						}
					);
					}
#ifdef REPORT_LCD_LOAD
					end_disp = lcd_RDTSC_STOP();
					disp_loop_cycles += (end_disp - start_disp);
#endif
				}
			}

			if (ret == -EWOULDBLOCK) {
				cpu_relax();
				continue;
			}
		}
		
		LIBLCD_MSG("NULLNET EXITED DISPATCH LOOP");

		);

	LIBLCD_MSG("EXITED NULLNET DO_FINISH");

	return;
}

static int __noreturn dummy_lcd_init(void) 
{
	int r = 0;

	printk("LCD %d entering...\n", current_lcd_id);
	r = lcd_enter();
	if (r)
		goto fail1;
	/*
	 * Get the nullnet channel cptr from boot info
	 */
	nullnet_register_channels[current_lcd_id] = lcd_get_boot_info()->cptrs[0];
	printk("[%d] nullnet reg channel %lu\n",
			current_lcd_id,	nullnet_register_channels[current_lcd_id].cptr);
	/*
	 * Initialize nullnet glue
	 */
	if (current_lcd_id == 0) {
		r = glue_nullnet_init();
		if (r) {
			LIBLCD_ERR("nullnet init");
			goto fail2;
		}
	}

	thc_channel_group_init(&ch_grp[current_lcd_id]);

	/* RUN CODE / LOOP ---------------------------------------- */

	if (1)
		main_and_loop();

	/* DONE -------------------------------------------------- */
	if (current_lcd_id == 0)
		glue_nullnet_exit();

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
