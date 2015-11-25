
#include <lcd-domains/liblcd-config.h>
#include <lcd-domains/liblcd.h>

#include <lcd-domains/liblcd-hacks.h>

int lcd_enter(void)
{
	int ret;
	/*
	 * Order is important ...
	 *
	 * ------------------------------
	 *
	 * Set up cptr cache
	 */
	ret = lcd_init_cptr();
	if (ret) {
		LIBLCD_ERR("lcd_init_cptr error");
		goto fail;
	}
	LIBLCD_MSG("cptr cache ready");
	/*
         * Create our call endpoint (for call/reply interactions)               
         */
        ret = __lcd_create_sync_endpoint(LCD_CPTR_CALL_ENDPOINT);
        if (ret) {
                LIBLCD_ERR("creating call endpoint");
                goto fail;
        }
        LIBLCD_MSG("call endpoint created and installed");
	/*
	 * Set up page alloc and kmalloc
	 */
	ret = lcd_mem_init();
	if (ret) {
		LIBLCD_ERR("lcd_mem_init error");
		goto fail;
	}
	LIBLCD_MSG("memory subsystem ready");
	/*
	 * Set up dstore subsystem
	 */
	ret = lcd_dstore_init();
	if (ret) {
		LIBLCD_ERR("lcd_dstore_init error");
		goto fail;
	}
	LIBLCD_MSG("data store subystem ready");

	return 0;

fail:
	return ret;
}

void __noreturn lcd_exit(int retval)
{
	/*
	 * For now, don't tear anything down, just exit.
	 */
	LIBLCD_MSG("exiting");
	lcd_set_r0(retval);
	for(;;)
		LCD_DO_SYSCALL(LCD_SYSCALL_EXIT); /* doesn't return */
}
