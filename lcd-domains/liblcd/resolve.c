
#include <lcd_config/pre_hook.h>

#include <linux/compiler.h>
#include <linux/spinlock_types.h>
#include <linux/ftrace_event.h>
#include <linux/perf_event.h>
#include <liblcd/liblcd.h>
#include <linux/slab.h>
#include <linux/context_tracking.h>
#include <asm/traps.h>                  /* dotraplinkage, ...           */
#include <liblcd/allocator.h>
#include <asm/apic.h>
#include <linux/hrtimer.h>
#include <asm/processor.h>
#include <linux/kernel_stat.h>

#include <lcd_config/post_hook.h>

//#include <linux/irq.h>
//#include <asm/irq_vectors.h>

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

//void __lockfunc _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, 
//					unsigned long flags)
//{
//	lcd_printk("resolve.c: trying to call dummy _raw_spin_unlock_irqrestore!");
//	return;
//}

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

/**
 * dev_driver_string - Return a device's driver name, if at all possible
 * @dev: struct device to get the name of
 *
 * Will return the device's driver's name if it is bound to a device.  If
 * the device is not bound to a driver, it will return the name of the bus
 * it is attached to.  If it is not attached to a bus either, an empty
 * string will be returned.
 */
const char *dev_driver_string(const struct device *dev)
{
	struct device_driver *drv;

	/* dev->driver can change to NULL underneath us because of unbinding,
	 * so be careful about accessing it.  dev->bus and dev->class should
	 * never change once they are set, so they don't need special care.
	 */
	drv = ACCESS_ONCE(dev->driver);
	return drv ? drv->name :
			(dev->bus ? dev->bus->name :
			(dev->class ? dev->class->name : ""));
}

static int __dev_printk(const char *level, const struct device *dev,
			struct va_format *vaf)
{
	if (!dev)
		return printk("%s(NULL device *): %pV", level, vaf);

	return printk("%s%s %s: %pV", level, 
			dev_driver_string(dev), dev_name(dev), vaf);
}

int dev_printk(const char *level, const struct device *dev,
	       const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int r;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	r = __dev_printk(level, dev, &vaf);

	va_end(args);

	return r;
}

/* APIC */
unsigned int apic_verbosity;
int disable_apic;
struct cpuinfo_x86 boot_cpu_data;
//int first_system_vector = FIRST_SYSTEM_VECTOR;
unsigned long io_apic_irqs;

/* Context tracking */
/* should be per-cpu */
struct context_tracking context_tracking; 

/* Processor that is doing the boot up */
unsigned int boot_cpu_physical_apicid = -1U;

/* entry.S */
typedef u32             compat_uptr_t;
asmlinkage long compat_sys_execve(const char __user *filename, const compat_uptr_t __user *argv,
                      const compat_uptr_t __user *envp) 
{
	printk(KERN_ALERT "LCD unsupported function\n");
	BUG();
	return -1;
};

/* mmzone.h */
struct pglist_data contig_page_data;

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

void __free_pages(struct page *page, unsigned int order) {
	return lcd_free_pages(page, order);
};

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

void __init free_bootmem(unsigned long physaddr, unsigned long size) 
{
	kfree(__va(physaddr));
	return; 
}

/* traps */

/* dumpstack */
void die(const char *str, struct pt_regs *regs, long err) {
	printk(KERN_ALERT "die is not implemented\n");
	BUG(); 
	return;
}

/* exit.c */
void
do_group_exit(int exit_code)
{
	printk(KERN_ALERT "do_group_exit is not implemented, exit code:%i\n", exit_code);
	BUG(); 
	return;
};

dotraplinkage notrace void
do_nmi(struct pt_regs *regs, long error_code)
{
	printk(KERN_ALERT "do_nmi is not implemented\n");
	BUG(); 
	return;
}

dotraplinkage void notrace
do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	printk(KERN_ALERT "do_page_fault is not implemented\n");
	BUG(); 
	return;
}

int __dynamic_pr_debug(struct _ddebug *descriptor, const char *fmt, ...)
{
	printk(KERN_ALERT "__dynamic_pr_debug is not implemented\n");
	BUG(); 
	return -1;
}

void exit_idle(void) {
	printk(KERN_ALERT "exit_idle is not implemented\n");
	BUG(); 
	return;
}

int fixup_exception(struct pt_regs *regs) 
{	
	printk(KERN_ALERT "fixup_exception is not implemented\n");
	BUG(); 
	return -1;
}

void force_sig(int sig, struct task_struct *p)
{
	printk(KERN_ALERT "force_sig is not implemented\n");
	BUG(); 
	return;
}

bool freezing_slow_path(struct task_struct *p)
{
	printk(KERN_ALERT "freezing_slow_path is not implemented\n");
	BUG(); 
	return false;
};

int hard_smp_processor_id(void)
{
	return read_apic_id();
};

void hrtimer_init(struct hrtimer *timer, clockid_t clock_id,
                  enum hrtimer_mode mode)
{
	printk(KERN_ALERT "hrtimer_init is not implemented\n");
	return;
}

void ignore_signals(struct task_struct *t)
{
	printk(KERN_ALERT "ignore_signals is not implemented\n");
	return;
}

void schedule(void) {
	return;
};

void __wake_up(wait_queue_head_t *q, unsigned int mode,
                        int nr_exclusive, void *key)
{
	printk(KERN_ALERT "__wake_up is not implemented\n");
	return;
}

void irq_enter(void) {
	return;
}

void irq_exit(void) {
	return; 
};

void user_enter(void) {
	return;
}

void user_exit(void) {
	return;
}




/* Some per-cpu declarations, that don't work at the moment */

// I should probably init it with a meaningful value
// DEFINE_PER_CPU_SHARED_ALIGNED(struct tss_struct, init_tss) = INIT_TSS;
DECLARE_PER_CPU_SHARED_ALIGNED(struct tss_struct, init_tss); 

/* kstat */
DEFINE_PER_CPU(struct kernel_stat, kstat);

unsigned long loops_per_jiffy = (1<<12);

