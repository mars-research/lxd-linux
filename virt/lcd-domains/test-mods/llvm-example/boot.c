/**
 * boot.c - non-isolated kernel module, does setup and
 *          send/recv
 *
 */

#include <lcd-domains/kliblcd.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int boot_main(void)
{
	int ret;
	cptr_t endpoint;
	cptr_t lcd;
	struct lcd_info *mi;
	cptr_t dest;
	/*
	 * Enter lcd mode
	 */
	ret = lcd_enter();
	if (ret) {
		LIBLCD_ERR("lcd enter failed");
		goto fail1;
	}
	/*
	 * Create an endpoint
	 */
	ret = lcd_create_sync_endpoint(&endpoint);
	if (ret) {
		LIBLCD_ERR("failed to create endpoint");
		goto fail2;
	}
	/*
	 * Create lcd
	 */
	ret = lcd_create_module_lcd(&lcd, "lcd_test_mod_llvm_example_lcd",
				LCD_CPTR_NULL, &mi);
	if (ret) {
		LIBLCD_ERR("failed to create lcd");
		goto fail3;
	}
	/*
	 * Allocate a cptr for the lcd to hold the endpoint
	 */
	ret = __lcd_alloc_cptr(mi->cache, &dest);
	if (ret) {
		LIBLCD_ERR("failed to alloc dest slot");
		goto fail4;
	}
	/*
	 * Grant access to endpoint
	 */
	ret = lcd_cap_grant(lcd, endpoint, dest);
	if (ret) {
		LIBLCD_ERR("failed to grant endpoint to lcd");
		goto fail5;
	}
	/*
	 * Set up boot info
	 */
	ret = lcd_dump_boot_info(mi);
	if (ret) {
		LIBLCD_ERR("dump boot info");
		goto fail6;
	}
	to_boot_info(mi)->cptrs[0] = dest;
	/*
	 * Run lcd
	 */
	ret = lcd_run(lcd);
	if (ret) {
		LIBLCD_ERR("failed to start lcd");
		goto fail7;
	}

	/* IPC -------------------------------------------------- */

	/*
	 * Do an RPC for FUNC1
	 */
	lcd_set_r0(1);
	lcd_set_r1(2);
	lcd_set_r2(3);
	ret = lcd_call(endpoint);
	if (ret) {
		LIBLCD_ERR("failed to call FUNC1");
		goto fail8;
	}
	
	if (lcd_r0() != 0) {
		LIBLCD_ERR("FUNC1 rpc failed");
		goto fail9;
	}

	/*
	 * Do an RPC for FUNC2
	 */
	lcd_set_r0(2);
	ret = lcd_call(endpoint);
	if (ret) {
		LIBLCD_ERR("failed to call FUNC2");
		goto fail8;
	}
	
	if (lcd_r0() != 0) {
		LIBLCD_ERR("FUNC2 rpc failed");
		goto fail9;
	}

	/*
	 * Hang out for a two seconds for lcd to exit
	 */
	msleep(2000);
	/*
	 * Tear everything down
	 */
	ret = 0;
	goto out;

out:
fail9:
fail8:
fail7:
fail6:
fail5:
	/* 
	 * No need to "ungrant" - everything is taken care of during tear
	 * down
	 */
fail4:
	/* 
	 * This call is necessary because we need to tear down the module
	 * on the host (otherwise, an lcd_cap_delete would be sufficient
	 */
	lcd_destroy_module_lcd(lcd, mi, LCD_CPTR_NULL);
fail3:
fail2:
	lcd_exit(0); /* will free endpoint */
fail1:
	return ret;
}

static void boot_exit(void)
{
	/* nothing to do */
}

module_init(boot_main);
module_exit(boot_exit);
