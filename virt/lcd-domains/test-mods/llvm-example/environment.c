/*
 * environment.c - these are the functions that need to
 *                 be emulated
 */

#include <lcd-domains/liblcd.h>

/* GLOBALS -------------------------------------------------- */

/* struct lcd_boot_info is defined in include/lcd-domains/types.h */
static struct lcd_boot_info lcd_boot_info = {
	.cptrs = { 3 }
};
struct lcd_boot_info * lcd_get_boot_info(void)
{
	return &lcd_boot_info;
}

/* struct lcd_utcb is defined in include/lcd-domains/utcb.h. The utcb
 * is the global message buffer used for IPC. */
static struct lcd_utcb lcd_utcb;

struct lcd_utcb * lcd_get_utcb(void)
{
	return &lcd_utcb;
}

/* IPC EMULATION -------------------------------------------------- */

static int counter1 = 0;
static int counter2 = 0;
int lcd_recv(cptr_t chnl)
{
	/* This is where you can emulate different possible
	 * messages. */

	switch (counter1) {

	case 0: /* first message */

		counter1++;

		__lcd_set_r0(&lcd_utcb, 1); /* FUNC1 */
		__lcd_set_r1(&lcd_utcb, 15); /* arg1 = 15 */
		__lcd_set_r2(&lcd_utcb, 30); /* arg1 = 15 */

		return 0; /* signals successful syscall */

	case 1:

		counter1++;

		__lcd_set_r0(&lcd_utcb, 2); /* FUNC2 */

		return 0; /* signals successful syscall */

	default:

		return -EINVAL; /* stop dispatch loop */

	}
}

int lcd_reply(void)
{
	/* ... and check the responses */

	switch (counter2) {

	case 0: /* first reply */

		counter2++;

		/* Assert on register r0 == 17? */

		return 0; /* signals successful syscall */

	case 1:

		counter2++;

		/* Assert on register r0 == 29? */

		return 0; /* signals successful syscall */

	default:

		return -EINVAL; /* shouldn't execute */

	}
}

/* PRINTF -------------------------------------------------- */

void lcd_printk(char *fmt, ...) 
{
	va_list args;
	char *p;

	va_start(args, fmt);
	/* Just use the libc version, vprintf will remain an undefined
	 * symbol, but that should be OK. Maybe link with libc? */
	vprintf(fmt, args); 
	va_end(args);
}

/* ENTER/EXIT -------------------------------------------------- */

int lcd_enter(void)
{
	/* No-op */
	return 0;
}

void __noreturn lcd_exit(int ret)
{
	/* No-op */
}

