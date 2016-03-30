/*
 * LCD BUG() and oops test. This LCD crashes to generate a
 * kernel oops. 
 *
 * This code *must* be compiled with optimizations turned off, or
 * else it won't do what we want.
 */

#include <lcd_config/pre_hook.h>

#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <liblcd/liblcd.h>

#include <lcd_config/post_hook.h>

void foo5(void) {
        unsigned char stack_array [] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 2, 3, 4};
	register long rax asm ("rax");
	register long rbx asm ("rbx");
	register long rcx asm ("rcx");
	register long rdx asm ("rdx");
	register long rdi asm ("rdi");
	register long rsi asm ("rsi");
	register long r8 asm ("r8");
	register long r9 asm ("r9");
	register long r10 asm ("r10");
	register long r11 asm ("r11");
	register long r12 asm ("r12");
	register long r13 asm ("r13");
	register long r14 asm ("r14");
	register long r15 asm ("r15");

	rax = 1; 
	rbx = 2;
	rcx = 3;
	rdx = 4;
	rsi = 5;
	rdi = 6;
	r8 = 7;
	r9 = 8;
	r10 = 9;
	r11 = 0xa;
	r12 = 0xb;
	r13 = 0xc;
	r14 = 0xd;
	r15 = 0xe;

	jiffies_to_clock_t(100000);

	rax = stack_array[0];

	return;
};

void foo4 (void) {
	foo5();
	return;
}

void foo3 (void) {
	foo4();
	return;
}
void foo2 (void) {
	foo3();
	return;
}

void foo1 (void) {
	foo2();
	return;
}

static int __noreturn test_init(void) 
{
	int r;

	r = lcd_enter();
	if (r)
		goto fail1;

	foo1();
fail1:
	lcd_exit(r);
}

static int __test_init(void)
{
	int ret;

	LCD_MAIN({

			ret = test_init();

		});

	return ret;
}

/* 
 * make module loader happy (so we can unload). we don't actually call
 * this before unloading the lcd (yet)
 */
static void __exit test_exit(void)
{
	return;
}

module_init(__test_init);
module_exit(test_exit);
