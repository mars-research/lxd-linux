/*
 * lcd.c - code for isolated LCD in liblcd test
 */

#include <lcd_config/pre_hook.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <liblcd/liblcd.h>

#include <lcd_config/post_hook.h>

cptr_t ep;

static int do_recv(cptr_t endpoint, char **data)
{
	int ret;
	cptr_t page_cptr;
	unsigned long offset;
	gva_t page;
	/*
	 * Prepare to receive a page that contains data
	 */
	ret = lcd_cptr_alloc(&page_cptr);
	if (ret) {
		LIBLCD_ERR("alloc cptr failed");
		goto fail1;
	}
	lcd_set_cr1(page_cptr);
	/*
	 * Listen for message from boot
	 */
	ret = lcd_sync_recv(endpoint);
	if (ret) {
		LIBLCD_ERR("recv failed");
		goto fail2;
	}
	/*
	 * Extract info
	 */
	offset = lcd_r0();
	/*
	 * Map page
	 */
	ret = lcd_map_virt(page_cptr, 0, &page);
	if (ret) {
		LIBLCD_ERR("failed to map page");
		goto fail3;
	}
	/*
	 * Get data
	 *
	 * gva == hva for non-isolated
	 */
	*data = (char *)(gva_val(page) + offset);

	*page_cptr_out = page_cptr;

	return 0;

fail3:
	lcd_cap_delete(page_cptr);
fail2:
	lcd_cptr_free(page_cptr);
fail1:
	return ret;
}

static int do_send(cptr_t endpoint, char *data, int len)
{
	int ret;
	struct lcd_resource_node *n;
	unsigned long offset;
	/*
	 * Get the cptr for the page that contains data
	 */
	ret = lcd_virt_to_resource_node(__gva((unsigned long)data), &n);
	if (ret) {
		LIBLCD_ERR("lcd virt addr to page cptr failed");
		goto fail1;
	}
	offset = ((unsigned long)data) - lcd_resource_node_start(n);
	/*
	 * Set up message for grant
	 */
	lcd_set_cr1(p);
	lcd_set_r0(offset);
	ret = lcd_sync_send(endpoint);
	if (ret) {
		LIBLCD_ERR("send failed");
		goto fail2;
	}

	return 0;

fail2:
fail1:
	return ret;
}

static void do_stuff(void)
{
	int ret;
	char *data1, *data2;
	/*
	 * "recv" the string from boot
	 */
	ret = do_recv(ep, &data1);
	if (ret) {
		LIBLCD_ERR("do first recv failed");
		goto fail1;
	}
	LIBLCD_MSG("first string is %s (should be 'hello')", data1);
	if (strcmp(data1, "hello")) {
		LIBLCD_ERR("bad data, first recv");
		ret = -EINVAL;
		goto fail2;
	}
	/*
	 * send it back to boot
	 */
	ret = do_send(ep, data1, strlen(data1));
	if (ret) {
		LIBLCD_ERR("send failed");
		goto fail3;
	}
	/*
	 * recv it again
	 */
	ret = do_recv(ep, &data2);
	if (ret) {
		LIBLCD_ERR("do second recv failed");
		goto fail4;
	}
	LIBLCD_MSG("first string is %s (should be 'hello')", data2);
	if (strcmp(data2, "hello")) {
		LIBLCD_ERR("bad data, second recv");
		ret = -EINVAL;
		goto fail5;
	}

	LIBLCD_MSG("all ok!");

	return;

fail5:
fail4:
fail3:
fail2:
fail1:
	/* Just die, easier than error handling */
	lcd_exit(ret);
}

static void get_endpoint(void)
{
	ep = lcd_get_boot_info()->cptrs[0];
}

static int __noreturn __init string_lcd_init(void) 
{
	int r;
	r = lcd_enter();
	if (r)
		goto out;
	
	get_endpoint();

	do_stuff();

	goto out;

out:
	lcd_exit(r);
}

static void string_lcd_exit(void)
{
	return;
}

module_init(string_lcd_init);
module_exit(string_lcd_exit);
