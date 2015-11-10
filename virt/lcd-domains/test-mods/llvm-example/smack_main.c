
#include <linux/kernel.h>

int __noreturn llvm_example_lcd_init(void);

int main(void)
{
	/* Fire up container, it will enter the dispatch loop. */
	llvm_example_lcd_init();

	return 0;
}
