
#include <lcd_config/pre_hook.h>

#include <linux/compiler.h>
#include <linux/spinlock_types.h>
#include <linux/ftrace_event.h>
#include <linux/perf_event.h>
#include <liblcd/liblcd.h>
#include <linux/slab.h>

#include <lcd_config/post_hook.h>

/*
 * Some globals to resolve
 * -----------------------
 *
 * We need a fake task struct for slab, inside kmem_freepages.
 */
struct task_struct fake = {0};
struct task_struct *current_task = &fake;
/*
 * Make sure these cause trouble. This kernel_stack value is non-canonical,
 * so will hopefully cause a GP exception. This phys_base sets bits past
 * what is most likely the highest allowed position (past MAX_PHYS).
 */
unsigned long kernel_stack = 0x800000badbadf00dUL;
unsigned long phys_base = 0x800000badbadf00dUL;
 
unsigned long _copy_from_user(void *to, const void __user *from, unsigned n)
{
	lcd_printk("resolve.c: called dummy _copy_from_user!");
	return 0UL;
}

void warn_slowpath_null(const char *file, int line)
{
	lcd_printk("resolve.c: called dummy warn_slowpath_null!");
	lcd_printk("warn_slowpath_null: file = %s, line = %d",
		file, line);
}

void perf_tp_event(u64 addr, u64 count, void *record,
		int entry_size, struct pt_regs *regs,
		struct hlist_head *head, int rctx,
		struct task_struct *task)
{
	lcd_printk("resolve.c: trying to call dummy perf_tp_event!");
	return;
}
               
void *perf_trace_buf_prepare(int size, unsigned short type,
				struct pt_regs *regs, int *rctxp)
{
	lcd_printk("resolve.c: trying to call dummy perf_trace_buf_prepare!");
	return NULL;
}

void *ring_buffer_event_data(struct ring_buffer_event *event)
{
	lcd_printk("resolve.c: trying to call dummy ring_buffer_event_data!");
	return NULL;
}

long strnlen_user(const char __user *str, long count)
{
	lcd_printk("resolve.c: trying to call dummy strnlen_user!");
	return 0L;
}

void __lockfunc _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, 
					unsigned long flags)
{
	lcd_printk("resolve.c: trying to call dummy _raw_spin_unlock_irqrestore!");
	return;
}

/* MUTEXES ------------------------------------------------------------ */

void __mutex_init(struct mutex *lock, const char *name, 
		struct lock_class_key *key)
{
	return;
}

void mutex_lock(struct mutex *lock)
{
	return;
}

int mutex_lock_interruptible(struct mutex *lock)
{
	return 0;
}

int mutex_trylock(struct mutex *lock)
{
	return 1;
}

void mutex_unlock(struct mutex *lock)
{
	return;
}

/* SCHEDULING ------------------------------------------------------------ */

int _cond_resched(void) { return 0; } /* Never signal reschedule */

/* PRINTK -------------------------------------------------- */

int printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	_lcd_printk(fmt, args);
	va_end(args);
	return 0;
}

/* APIC */
unsigned int apic_verbosity;

/* page_alloc.c */
struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
			struct zonelist *zonelist, nodemask_t *nodemask)
{
	/*
	 * For now, we ignore the node id (not numa aware).
	 */
	return lcd_alloc_pages((unsigned int) gfp_mask, order);
}

void * __alloc_bootmem(unsigned long size, unsigned long align,
					unsigned long goal, unsigned long limit)
{
	printk(KERN_ALERT "__alloc_bootmem of %lu bytes with align:%lu, goal:%lu, limit:%lu\n", 
			size, align, goal, limit);
	BUG(); 
	return kmalloc(size, GFP_KERNEL);
}

/**
 * __alloc_bootmem_nopanic - allocate boot memory without panicking
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * Returns NULL on failure.
 */
void * __init __alloc_bootmem_nopanic(unsigned long size, unsigned long align,
					unsigned long goal)
{
	printk(KERN_ALERT "__alloc_bootmem_nopanic of %lu bytes with align:%lu, goal:%lu\n", 
			size, align, goal);
	BUG(); 
	return kmalloc(size, GFP_KERNEL);
}

