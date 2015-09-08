/**
 * Regression tests for the (kliblcd version of) the data store.
 */

#include <lcd-domains/kliblcd.h>
#include <lcd-domains/tests-util.h>
#include "../internal.h"

static int test01(void)
{
	int ret;
	struct dstore *d;

	ret = lcd_enter();
	if (ret) {
		LCD_ERR("enter klcd");
		goto fail1;
	}
	/*
	 * Create and then destroy empty data store.
	 */
	ret = lcd_dstore_init_dstore(&d);
	if (ret) {
		LCD_ERR("create dstore");
		goto fail2;
	}
	lcd_dstore_destroy(d);
	
	ret = 0;
	goto out;

out:
fail2:
	lcd_exit(0);
fail1:
	return ret;
}

void dstore_tests(void)
{
	int n = 0;
	int total = 1;

	RUN_TEST(test01, n);

	if (n < total) {
		LCD_MSG("%d of %d dstore tests failed",
			(total - n), total);
	} else {
		LCD_MSG("all dstore tests passed!");
	}
}

