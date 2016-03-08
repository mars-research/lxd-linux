/*
 * LCD BUG() and oops test. This LCD crashes to generate a
 * kernel oops. 
 *
 * This code *must* be compiled with optimizations turned off, or
 * else it won't do what we want.
 */

#include <lcd_config/pre_hook.h>

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <liblcd/liblcd.h>

#include <lcd_config/post_hook.h>

bool use_threaded_interrupts = true; 
int devid = 33; 
unsigned int irq_vector = 32;

static irqreturn_t test_irq(int irq, void *data)
{
	irqreturn_t result = 0; 

        printk(KERN_ERR "Test IRQ:\n");
	return result;
}

static irqreturn_t test_irq_check(int irq, void *data)
{
	printk(KERN_ERR "Test IRQ check:\n");
	return IRQ_WAKE_THREAD;
}

int setup_irqs(void) {

	if (use_threaded_interrupts)
		return request_threaded_irq(irq_vector,
					test_irq_check, test_irq,
					IRQF_DISABLED | IRQF_SHARED,
					"test-irq", (void*) &devid);
	return request_irq(irq_vector, test_irq,
				IRQF_DISABLED | IRQF_SHARED, "test-irq", (void*) &devid);
}

static int __noreturn __init test_init(void) 
{
	int r;

	r = lcd_enter();
	if (r)
		goto fail1;

	setup_irqs();
fail1:
	lcd_exit(r);
}

/* 
 * make module loader happy (so we can unload). we don't actually call
 * this before unloading the lcd (yet)
 */
static void __exit test_exit(void)
{
	return;
}

module_init(test_init);
module_exit(test_exit);
