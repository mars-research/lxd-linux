/**
 * main.c - non-isolated kernel module, does setup
 *
 */

#include <lcd_config/pre_hook.h>

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <libcap.h>
#include <liblcd/liblcd.h>
#include <linux/fs.h>

#include <lcd_config/post_hook.h>


static void force_pmfs_unreg(void)
{
	struct file_system_type *pmfs_fs_type;

	pmfs_fs_type = get_fs_type("pmfs");
	if (!pmfs_fs_type)
		return;

	LIBLCD_MSG("vfs forcing pmfs unregister");

	unregister_filesystem(pmfs_fs_type);
}

static int boot_main(void)
{
	int ret;
	struct lcd_create_ctx *ctx;
	cptr_t lcd;
	cptr_t vfs;
	cptr_t vfs_chnl;
	cptr_t pmfs_dest1;
	cptr_t vfs_dest1;
	/*
	 * Enter lcd mode
	 */
	ret = lcd_enter();
	if (ret) {
		LIBLCD_ERR("enter");
		goto out;
	}
	/*
	 * Create VFS channel
	 */
	ret = lcd_create_sync_endpoint(&vfs_chnl);
	if (ret) {
		LIBLCD_ERR("create vfs endpoint");
		goto lcd_exit;
	}
	
	/* CREATE LCDS -------------------------------------------------- */

	/*
	 * Create vfs klcd
	 */
	ret = lcd_create_module_klcd(LCD_DIR("pmfs/vfs_klcd"),
				"lcd_test_mod_pmfs_vfs",
				&vfs);
	if (ret) {
		LIBLCD_ERR("create vfs klcd");
		goto lcd_exit;
	}
	/*
	 * Create pmfs lcd
	 */
	ret = lcd_create_module_lcd(LCD_DIR("pmfs/pmfs_lcd"),
				"lcd_test_mod_pmfs_lcd",
				&lcd,
				&ctx);
	if (ret) {
		LIBLCD_ERR("create module lcd");
		goto destroy_vfs;
	}

	/* GRANT ENDPOINT TO PMFS ------------------------------ */

	/*
	 * Alloc dest slot
	 */
	ret = cptr_alloc(lcd_to_boot_cptr_cache(ctx), &pmfs_dest1);
	if (ret) {
		LIBLCD_ERR("failed to alloc cptr");
		goto destroy_both;
	}
	/*
	 * Grant
	 */
	ret = lcd_cap_grant(lcd, vfs_chnl, pmfs_dest1);
	if (ret) {
		LIBLCD_ERR("failed to grant vfs endpoint to pmfs");
		goto destroy_both;
	}

	/* GRANT ENDPOINT TO VFS ------------------------------ */

	/* Hack for now */

	vfs_dest1 = __cptr(3);
	ret = lcd_cap_grant(vfs, vfs_chnl, vfs_dest1);
	if (ret) {
		LIBLCD_ERR("failed to grant vfs endpoint to vfs");
		goto destroy_both;
	}

	/* DUMP BOOT INFO FOR PMFS ------------------------------ */

	/*
	 * Set up boot info for pmfs lcd
	 */
	lcd_to_boot_info(ctx)->cptrs[0] = pmfs_dest1;

	/* RUN -------------------------------------------------- */

	/*
	 * Run vfs
	 */
	ret = lcd_run(vfs);
	if (ret) {
		LIBLCD_ERR("run vfs");
		goto destroy_both;
	}
	/*
	 * Run pmfs
	 */
	ret = lcd_run(lcd);
	if (ret) {
		LIBLCD_ERR("run pmfs");
		goto destroy_both;
	}
	/*
	 * Wait for 2 seconds
	 */
	msleep(4000);
	/*
	 * Tear everything down
	 */
	ret = 0;
	goto destroy_both;

destroy_both:
	lcd_cap_delete(lcd);
	lcd_destroy_create_ctx(ctx);
destroy_vfs:
	/*
	 * Ensure the pmfs fs type is unregistered. If we unload
	 * the vfs module before unregistering the pmfs fs, we
	 * will get repeated faults (due to a proc fs thread trying
	 * to read all current file systems).
	 */
	force_pmfs_unreg();
	lcd_destroy_module_klcd(vfs, "lcd_test_mod_pmfs_vfs");
lcd_exit:
	/* frees endpoint */
	lcd_exit(0);
out:
	return ret;
}

static int boot_init(void)
{
	int ret;
	
	LCD_MAIN({

			ret = boot_main();

		});

	return ret;
}

static void boot_exit(void)
{
	/* nothing to do */
}

module_init(boot_init);
module_exit(boot_exit);
