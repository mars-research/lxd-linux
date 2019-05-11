/*
 * boot.c - non-isolated kernel module
 *          Launches ixgbe lcd and net klcd modules and waits
 *	    until they are shutdown.
 *
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/liblcd.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>

#include "../ixgbe_common.h"

#include <lcd_config/post_hook.h>


/* for multiple child LCDs */

int num_lcds = NUM_LCDS; /* including the parent LCDs */
int i;
struct lcd_create_ctx **ixgbe_ctxs;
cptr_t *ixgbe_lcds;
cptr_t *ixgbe_chnl_domain_cptrs;

cptr_t net_klcd, ixgbe_lcd;
struct lcd_create_ctx *ixgbe_ctx;
cptr_t net_chnl;
cptr_t net_chnl_domain_cptr, ixgbe_chnl_domain_cptr;

#define BOOT_THREAD

static int boot_main(void)
{
	int ret;
	/*
	 * Enter lcd mode
	 */
	ret = lcd_enter();
	if (ret) {
		LIBLCD_ERR("lcd enter failed");
		goto fail1;
	}

	/* ---------- Create net channel ---------- */

	ret = lcd_create_sync_endpoint(&net_chnl);
	if (ret) {
		LIBLCD_ERR("lcd create sync endpoint");
		goto fail2;
	}

	/* ---------- Create KLCD ---------- */

	ret = lcd_create_module_klcd(LCD_DIR("ixgbe/net_klcd"),
				"lcd_test_mod_ixgbe_net_klcd",
				&net_klcd);

	if (ret) {
		LIBLCD_ERR("failed to create net klcd");
		goto fail3;
	}

	ixgbe_ctxs = kzalloc(sizeof(struct lcd_create_ctx*) * num_lcds, GFP_KERNEL);

	if (!ixgbe_ctxs) {
		LIBLCD_ERR("failed to alloc memory for ixgbe_ctxs");
		goto fail4;
	}
	printk("%s, ixgbe_ctxs %p\n", __func__, ixgbe_ctxs);

	ixgbe_lcds = kzalloc(sizeof(cptr_t*) * num_lcds, GFP_KERNEL);

	if (!ixgbe_lcds) {
		LIBLCD_ERR("failed to alloc memory for ixgbe_lcds");
		goto fail4;
	}

	printk("%s, ixgbe_lcds %p\n", __func__, ixgbe_lcds);

	ixgbe_chnl_domain_cptrs = kzalloc(sizeof(cptr_t*) * num_lcds, GFP_KERNEL);

	if (!ixgbe_chnl_domain_cptrs) {
		LIBLCD_ERR("failed to alloc memory for ixgbe_chnl_domain_cptrs");
		goto fail4;
	}

	/* ---------- Create LCD ---------- */
	ret = lcd_create_module_lcds(LCD_DIR("ixgbe/ixgbe_lcd"),
				"lcd_test_mod_ixgbe_ixgbe_lcd",
				ixgbe_lcds,
				ixgbe_ctxs, num_lcds);
	if (ret) {
		LIBLCD_ERR("failed to create ixgbe lcd");
		goto fail4;
	}

	for (i = 0; i < num_lcds; i++) {

		LIBLCD_MSG("granting domain_chnl_ptr to LCD %d\n", i);

		ret = cptr_alloc(lcd_to_boot_cptr_cache(ixgbe_ctxs[i]),
				&ixgbe_chnl_domain_cptrs[i]);
		if (ret) {
			LIBLCD_ERR("alloc cptr");
			goto fail5;
		}

		ret = lcd_cap_grant(ixgbe_lcds[i], net_chnl, ixgbe_chnl_domain_cptrs[i]);
		if (ret) {
			LIBLCD_ERR("grant");
			goto fail6;
		}
		lcd_to_boot_info(ixgbe_ctxs[i])->cptrs[0] = ixgbe_chnl_domain_cptrs[i];
		/* for udelay calculatio we need lpj inside LCD */
		lcd_to_boot_info(ixgbe_ctxs[i])->cptrs[1].cptr = this_cpu_read(cpu_info.loops_per_jiffy);
	}

	/* ---------- Set up boot info ---------- */
	/* HACK: Just to pass cptr #3 to KLCD module, It should ideally
	 * be passed in a rather clean way. However, there is no harm
	 * in this hack. When KLCD boots and allocates a cptr, cptr #3
	 * will be allocated. If not, the whole thing goes for a toss!
	 */

	net_chnl_domain_cptr = __cptr(3);
	ret = lcd_cap_grant(net_klcd, net_chnl, net_chnl_domain_cptr);
	if (ret) {
		LIBLCD_ERR("grant");
		goto fail7;
	}

	/* ---------- RUN! ---------- */

	LIBLCD_MSG("starting network...");
	ret = lcd_run(net_klcd);
	if (ret) {
		LIBLCD_ERR("failed to start vfs lcd");
		goto fail8;
	}

	msleep_interruptible(3000);

	LIBLCD_MSG("starting ixgbe ethernet...");

	for (i = 0; i < num_lcds; i++) {
		LIBLCD_MSG("Starting LCD %d ", i);
		ret = lcd_run(ixgbe_lcds[i]);
		if (ret) {
			LIBLCD_ERR("failed to start ixgbe lcd");
			goto fail9;
		}
		msleep_interruptible(4000);
	}
#ifdef BOOT_THREAD
	// return
	goto fail1;
#else
	/*
	 * Wait for 4 seconds
	 */
	msleep(100000);
	/*
	 * Tear everything down
	 */
	goto out;
out:
#endif


	/* The destroy's will free up everything ... */
fail9:
fail8:
fail7:
	lcd_cap_delete(ixgbe_lcds[0]);
	lcd_destroy_create_ctx(ixgbe_ctxs[0]);
fail6:
fail5:
fail4:
	//lcd_cap_delete(net_klcd);
	lcd_destroy_module_klcd(net_klcd, "lcd_test_mod_ixgbe_net_klcd");
fail3:
fail2:
	lcd_exit(0); /* will free endpoints */
fail1:
	return ret;
}

#ifdef BOOT_THREAD
static DECLARE_WAIT_QUEUE_HEAD(wq);
static int shutdown = 0;

int boot_lcd_thread(void *data)
{
	static unsigned once = 0;
	int ret;
	while (!kthread_should_stop()) {
		if (!once) {
			LCD_MAIN({
				ret = boot_main();
			});
		}
		once = 1;
		wait_event_interruptible(wq, shutdown != 0);
	}
	LIBLCD_MSG("Exiting thread");

	msleep(2000);

	lcd_destroy_module_klcd(net_klcd, "lcd_test_mod_ixgbe_net_klcd");

	if (current->lcd) {
		for (i = 0; i < num_lcds; i++) {
			lcd_cap_delete(ixgbe_lcds[i]);
		}
		kfree(ixgbe_lcds);
	}

	if (ixgbe_ctxs) {
		for (i = 0; i < num_lcds; i++) {
			lcd_destroy_create_ctx(ixgbe_ctxs[i]);
		}
		kfree(ixgbe_ctxs);
	}
	kfree(ixgbe_chnl_domain_cptrs);


	lcd_exit(0);
	return 0;
}

struct task_struct *boot_task;

static int boot_init(void)
{
	LIBLCD_MSG("%s: entering", __func__);

	boot_task = kthread_create(boot_lcd_thread, NULL, "boot_lcd_thread");

	if (!IS_ERR(boot_task))
		wake_up_process(boot_task);
	return 0;
}

static void boot_exit(void)
{
	/* nothing to do */
	if (!IS_ERR(boot_task)) {
		LIBLCD_MSG("%s: exiting", __func__);
		shutdown = 1;
		wake_up_interruptible(&wq);
		kthread_stop(boot_task);
	}
}
#else
static int boot_init(void)
{
	int ret;
	LIBLCD_MSG("%s: entering", __func__);
	LCD_MAIN( {
		ret = boot_main();
	});
	return ret;
}

static void boot_exit(void)
{
	/* nothing to do */
}
#endif
module_init(boot_init);
module_exit(boot_exit);
