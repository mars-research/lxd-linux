/*
 * boot.c - non-isolated kernel module, does setup
 *          when fake minix and vfs are to be launched
 *          in isolated containers
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/liblcd.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>

#include "../glue_helper.h"

#include <lcd_config/post_hook.h>

cptr_t blk_klcd, nullb_lcd;
struct lcd_create_ctx *dummy_ctx;
struct lcd_create_ctx **dummy_ctxs;
cptr_t blk_chnl_cptr;
cptr_t blk_dest, nullb_dest_cptr;
cptr_t *nullb_lcds;
cptr_t *nullb_dest_cptrs;

static int num_lcds = NUM_LCDS;
module_param(num_lcds, int, 0);
MODULE_PARM_DESC(num_lcds, "Number of LCDs to launch");

static int boot_main(void)
{
	int ret;
	int i;
	/*
	 * Enter lcd mode
	 */
	/* setup memory for LCD, assign in current->lcd 
	 * setup cspace, utcb, endpoint - hardcoded at cptr(1),
	 * comment says it is for CALL EP (not clear though!)
	 * thc_init */
	ret = lcd_enter();
	if (ret) {
		LIBLCD_ERR("lcd enter failed");
		goto fail1;
	}

	/* ---------- Create blk channel ---------- */

	/* how is this EP different from the above? looks
	 * like this one is shared between two LCDs */
	ret = lcd_create_sync_endpoint(&blk_chnl_cptr);
	if (ret) {
		LIBLCD_ERR("lcd create sync endpoint");
		goto fail2;
	}

	/* ---------- Create LCDs ---------- */

	/* Until now the boot module is current. Inside this function,
	 * a new lcd struct is created, a kthread is associated with the newly
	 * allocated lcd struct and the cptr for this lcd is inserted into the
	 * boot's cspace and the cptr is returned outside as blk_klcd */
	ret = lcd_create_module_klcd(LCD_DIR("nullb/blk_klcd"),
				"lcd_test_mod_nullb_blk_klcd",
				&blk_klcd);

	if (ret) {
		LIBLCD_ERR("failed to create net klcd");
		goto fail3;
	}

	dummy_ctxs = kzalloc(sizeof(struct lcd_create_ctx*) * num_lcds, GFP_KERNEL);

	if (!dummy_ctxs) {
		LIBLCD_ERR("failed to alloc memory for dummy_ctxs");
		goto fail4;
	}
	printk("%s, dummy_ctxs %p\n", __func__, dummy_ctxs);

	nullb_lcds = kzalloc(sizeof(cptr_t*) * num_lcds, GFP_KERNEL);

	if (!nullb_lcds) {
		LIBLCD_ERR("failed to alloc memory for nullb_lcds");
		goto fail4;
	}

	printk("%s, nullb_lcds %p\n", __func__, nullb_lcds);

	nullb_dest_cptrs = kzalloc(sizeof(cptr_t*) * num_lcds, GFP_KERNEL);

	if (!nullb_dest_cptrs) {
		LIBLCD_ERR("failed to alloc memory for nullb_dest_cptrs");
		goto fail4;
	}

	ret = lcd_create_module_lcds(LCD_DIR("nullb/nullb_lcd"),
				"lcd_test_mod_nullb_nullb_lcd",
				nullb_lcds,
				dummy_ctxs, num_lcds);
	if (ret) {
		LIBLCD_ERR("failed to create dummy lcd");
		goto fail4;
	}

	LIBLCD_MSG("Created parent and child LCDS");

	for (i = 0; i < num_lcds; i++) {
		LIBLCD_MSG("LCD %d, cptr %lu | ctx %p\n", i,
				nullb_lcds[i].cptr,
				dummy_ctxs[i]);
	}

	for (i = 0; i < num_lcds; i++) {

		ret = cptr_alloc(lcd_to_boot_cptr_cache(dummy_ctxs[i]), 
				&nullb_dest_cptrs[i]);
		if (ret) {
			LIBLCD_ERR("alloc cptr");
			goto fail5;
		}
		
		/* why is this so hard to remember?
		 * blk_chnl_cptr is the slot where the ep exists for the current (klcd) 
		 * we need to grant that to the LCD. This happens through the boot cptr
		 * cache. The capability is granted to the nullb_lcd at nullb_dest_cptr slot */
		ret = lcd_cap_grant(nullb_lcds[i], blk_chnl_cptr, nullb_dest_cptrs[i]);
		if (ret) {
			LIBLCD_ERR("grant");
			goto fail6;
		}
		LIBLCD_MSG("blk_chnl in boot space %d", nullb_dest_cptrs[i]);
		lcd_to_boot_info(dummy_ctxs[i])->cptrs[0] = nullb_dest_cptrs[i];
	}
	
	/* ---------- Set up boot info ---------- */
	/* Looks like the current is represented by the boot module and the klcd
	 * is separate from it. So the EP has to be granted to the blk_klcd as well! */
	blk_dest = __cptr(3);
	ret = lcd_cap_grant(blk_klcd, blk_chnl_cptr, blk_dest);
	if (ret) {
		LIBLCD_ERR("grant");
		goto fail7;
	}

	/* ---------- RUN! ---------- */

	LIBLCD_MSG("starting blk klcd...");
	/* The capability pointer of the kthread that was created in the create_klcd
	 * call will now be woken up here! This will wake up a common kernel thread and
	 * the thread will call klcd_main() which my guess is the module init of klcd
	 * module! */
	ret = lcd_run(blk_klcd);
	if (ret) {
		LIBLCD_ERR("failed to start blk klcd");
		goto fail8;
	}
	
	msleep_interruptible(3000);

	LIBLCD_MSG("starting nullb lcd...");

	for (i = 0; i < num_lcds; i++) {
		LIBLCD_MSG("Starting LCD %d ", i);

		ret = lcd_run(nullb_lcds[i]);
		if (ret) {
			LIBLCD_ERR("failed to start nullb lcd");
			goto fail9;
		}
		msleep_interruptible(3000);
	}

	/*
	 * Wait for 4 seconds
	 */
	//msleep(100000);
	/*
	 * Tear everything down
	 */
	ret = 0;
	// return
	goto fail1;


	/* The destroy's will free up everything ... */
fail9:
fail8:
fail7:
	lcd_cap_delete(nullb_lcd);
	lcd_destroy_create_ctx(dummy_ctx);
fail6:
fail5:
fail4:
	//lcd_cap_delete(blk_klcd);
	lcd_destroy_module_klcd(blk_klcd, "lcd_test_mod_nullb_blk_klcd");
fail3:
fail2:
	lcd_exit(0); /* will free endpoints */
fail1:
	return ret;
}

static DECLARE_WAIT_QUEUE_HEAD(wq);
static int shutdown = 0;

int boot_lcd_thread(void *data)
{
	static unsigned once = 0;
	int ret;
	int i;
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

	//msleep(10000);	
	lcd_destroy_module_klcd(blk_klcd, "lcd_test_mod_nullb_blk_klcd");

	if (current->lcd) {
		for (i = 0; i < num_lcds; i++) {
			lcd_cap_delete(nullb_lcds[i]);
		}
		kfree(nullb_lcds);
	}
	if (dummy_ctxs) {
		for (i = 0; i < num_lcds; i++) {
			lcd_destroy_create_ctx(dummy_ctxs[i]);
		}
		kfree(dummy_ctxs);
	}
	kfree(nullb_dest_cptrs);

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
module_init(boot_init);
module_exit(boot_exit);
MODULE_LICENSE("GPL");
