#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/irqflags.h>
#include <linux/kthread.h>
#include <asm/uaccess.h>
#include <asm/mwait.h>
#include <asm/page_types.h>
#include <asm/cpufeature.h>
#include <linux/ktime.h>
#include <asm/tsc.h>

#include "ring-chan/ring-channel.h"
#include "betaModule.h"

MODULE_LICENSE("GPL");

static int CPU_NUM;


/* 124 byte message */
static char *msg = "12345678123456781234567812345678123456781234567812345678" \
	"1234567";


static unsigned long start;
static unsigned long end;

#if defined(TIMING)
static u64 *timekeeper;
static unsigned long mwaitcount;
#endif



/* Stolen and slightly modified from http://rosettacode.org/wiki/Rot-13 */
static char *rot13(char *s, int amount)
{
	char *p = s;
	int upper;
	int count = 0;

	while (*p && count < amount) {
		upper = *p;
		if ((upper >= 'a' && upper <= 'm') ||
		    (upper >= 'A' && upper <= 'M'))
			*p += 13;
		else if ((upper >= 'n' && upper <= 'z') ||
			 (upper >= 'A' && upper <= 'Z'))
			*p -= 13;
		++p;
		count++;
	}
	return s;
}

static void assert_expect_and_zero(struct ipc_message *i_msg, int need_rot)
{
	if (need_rot)
		rot13(i_msg->message, BUF_SIZE);

	if (strncmp(i_msg->message, msg, BUF_SIZE) != 0)
		pr_err("STRINGS DIFFERED IN CPU %d\n", CPU_NUM);

	i_msg->monitor = 0;
}


static unsigned int find_target_mwait(void)
{
        unsigned int eax, ebx, ecx, edx;
        unsigned int highest_cstate = 0;
        unsigned int highest_subcstate = 0;
        int i;

        if (boot_cpu_data.cpuid_level < CPUID_MWAIT_LEAF)
                return 0;

        cpuid(CPUID_MWAIT_LEAF, &eax, &ebx, &ecx, &edx);

        if (!(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED) ||
            !(ecx & CPUID5_ECX_INTERRUPT_BREAK))
                return 0;

        edx >>= MWAIT_SUBSTATE_SIZE;
        for (i = 0; i < 7 && edx; i++, edx >>= MWAIT_SUBSTATE_SIZE) {
                if (edx & MWAIT_SUBSTATE_MASK) {
                        highest_cstate = i;
                        highest_subcstate = edx & MWAIT_SUBSTATE_MASK;
                        printk(KERN_DEBUG "Found cstate at %d and highest_subcstate %d\n",
                               i, highest_subcstate);
                        printk(KERN_DEBUG "IF WE WERE TO RETURN NOW IT WOUDL LOOK LIKE %x\n", (highest_cstate << MWAIT_SUBSTATE_SIZE) | (highest_subcstate -1));
                }
        }
        return (highest_cstate << MWAIT_SUBSTATE_SIZE) |
                (highest_subcstate - 1);

}


static inline void monitor_mwait(unsigned long rcx, volatile uint32_t *rax,
				 unsigned long wait_type)
{

	__monitor((void *)rax, 0, 0);
	/* TODO comment for memory barrier, why is this necessary? */
	mb();
	__mwait(wait_type, rcx);
}


	//unsigned long flags;
	//int cpu;
	/* smp is supposed to be used under "lock", however one can use it if
	 * you have pegged your thread to a CPU, which we have.
	 */
	/* we know we're noot ona buggy cpu when we release we'll re-enable this */
	/*cpu = smp_processor_id();

	  if (cpu_has_bug(&cpu_data(cpu), X86_BUG_CLFLUSH_MONITOR)) {
	  mb();
	  clflush(rax);
	  mb();
	  }*/

	//	local_irq_save(flags);
	//	local_irq_restore(flags);


#if defined(WAIT_TAIL)
static inline int trample_imminent(struct ipc_message *loc, unsigned int token,
				   unsigned int write)
{
	/* this "readwrite" is so I don't have to dup functions
	 * When we're the writer we want to check if we're gonna trample on a
	 * unread slot, but we also need to see if we're on the first iteration
	 * to check if we're on the first iteration we see if the slot is 0
	 * if the slot is zero we WONT trample the location as it's free
	 *
	 * However, this function is used for the consumer as well.
	 * The consumer will check if there is something to be read
	 * and the monitor wont match the token, ie nothing is available to read
	 * but, if that is the case there is the possibility that slot we want
	 * to read is zero as well. The 2nd portion will trigger and we will
	 * incorrectly read an empty slot. The fix is to "negate" the second
	 * portion of the boolean statement so only the monitor != token is the
	 * trigger
	 */
	if(write)
		return (loc->monitor != token) && (loc->monitor != 0);

	return (loc->monitor != token);

	//return (loc->monitor != token) && ((loc->monitor != 0) && readwrite);
	//return (loc->monitor != 0xC1346BAD) && (loc->monitor != 0);
}

static int trample_imminent_store(struct ttd_ring_channel *prod,
				  unsigned int prod_loc,
				  struct ipc_message **t_loc,
				  unsigned int token,
				  unsigned int readwrite)
{
	struct ipc_message *imsg;
	imsg = (struct ipc_message *) ttd_ring_channel_get_rec_slow(prod, prod_loc);
	*t_loc = imsg;
	return trample_imminent(imsg, token, readwrite);
}



static int wait_for_slot(struct ttd_ring_channel *chan, unsigned long bucket,
			 struct ipc_message **imsg, unsigned int token,
			 unsigned int readwrite)
{

#if defined(DEBUG_MWAIT_RETRY)
	unsigned long retry_count = 0;
#endif
	unsigned long ecx = 1; /*break of interrupt flag */
	unsigned long cstate_wait = 0x1; /* 4 states, 0x1, 0x10, 0x20, 0x30 */

#if defined(WAIT_TAIL)
	if (trample_imminent_store(chan, bucket, imsg, token, readwrite)) {
#endif
#if defined(WAIT_COUNTERS)
		if (trample_iminent_store(chan, imsg) {
#endif

		do{
			pr_debug("Waiting on CPU %d with %p\n",
				 CPU_NUM, &(*imsg)->monitor);
			mwaitcount++;
			monitor_mwait(ecx, &(*imsg)->monitor, cstate_wait);

#if defined(DEBUG_MWAIT_RETRY)
			if(retry_count > 50) {
				pr_err("RETRY COUNT FAILED! MORE THAN 50 WAITS on CPU %d\n", CPU_NUM);
				return 1;
			}
			retry_count++;
#endif
#if defined(WAIT_TAIL)
		}while(trample_imminent(*imsg, token,readwrite));
#endif
#if defined(WAIT_COUNTERS)
		}while(trample_imminent(chan));
#endif
	}


	/* trample Location is now free for us to write */
#if defined (DEBUG_BOUNDS_CHECK)
	if((unsigned long)*imsg  > end || (unsigned long)*imsg < start) {
		pr_err("OUT OF BOUNDS! with %p\n", imsg);
		return 1;
	}
#endif
#if defined(DEBUG_MWAIT_RETRY)
	retry_count = 0;
#endif
	return 0;
}
#endif


#if defined(WAIT_COUNTERS)
static inline int trample_imminent(struct ttd_ring_channel *chan)
{
	return(ttd_ring_channel_get_cons(chan) == ttd_ring_channel_getprod(chan));

}

static int trample_imminent_store(struct ttd_ring_channel *chan,
				  struct ipc_message **t_loc,
				  unsigned int readwrite)
{
	unsigned long safe_location;
	if(readwrite)
		safe_location = ttd_ring_channel_get_prod(chan);
	else
		safe_location = ttd_ring_chanel_get_cons(chan);

	*t_loc = ttd_ring_channel_get_rec_slow(chan, safe_location);
	return trample_imminent(chan);
}

#endif





static inline u64 rdtsc(void)
{
         unsigned int low, high;

         asm volatile("rdtsc" : "=a" (low), "=d" (high));

         return low | ((u64)high) << 32;
}




static int ipc_thread_func(void *input)
{

 	struct file *filep = input;
	struct ipc_container *container = NULL;

	struct ttd_ring_channel *prod_channel;
	struct ttd_ring_channel *cons_channel;
	int count = 0;
	unsigned int local_prod, local_cons;
	struct ipc_message *imsg;
	u64 start64, end64;
	unsigned int pTok = 0xC1346BAD;
	unsigned int cTok = 0xBADBEEF;

	if (filep == NULL) {
		pr_debug("Thread was sent a null filepointer!\n");
		return -EINVAL;
	}

	container = filep->private_data;

	if (container == NULL && container->channel_tx == NULL) {
		pr_debug("container was null in thread!\n");
		return -EINVAL;
	}

	prod_channel = container->channel_tx;
	cons_channel = container->channel_rx;

	/* PRODUCER */
	local_prod = 1;
	local_cons = 1;
	ttd_ring_channel_set_prod(prod_channel, 1);
	ttd_ring_channel_set_cons(prod_channel, 0);
	/* 10 mil */

	while(count < NUM_LOOPS) {

		/* get slot to write */
#if defined(WAIT_TAIL)
		if (wait_for_slot(prod_channel, local_prod, &imsg, pTok, 1))
			break;
#endif


		pr_debug("Memcpying in CPU0 iter %d count to loc %p\n",
			 count, imsg->message);

		imsg->message[0] = 'b';
		imsg->message[1] = 'e';
		imsg->message[2] = 't';
		imsg->message[3] = '1';

		start64 = rdtsc();

		imsg->monitor = cTok;
		pr_debug("Wrot to volatile var on CPU %d at loc %p\n",
			 CPU_NUM, &imsg->monitor);

		if (wait_for_slot(cons_channel, local_cons, &imsg, cTok, 0))
			break;
		/* ack the msg */
		imsg->monitor = pTok;

		end64 = rdtsc();

#if defined(TIMING)
		timekeeper[count] = (end64 - start64);
#endif

#if defined(DEBUG_VERIFY_MSG)
		assert_expect_and_zero(imsg,1);
#endif

#if defined(WAIT_COUNTERS)
		ttd_ring_channel_inc_prod(prod_channel);
		ttd_ring_channel_inc_cons(cons_channel);
#endif

#if defined(WAIT_TAIL)
		local_prod++;
		local_cons++;
#endif
		count++;
	}

	return 1;
}

static inline unsigned long beta_ret_cpu(unsigned long __arg)
{

	unsigned long __user *arg = (void *) __arg;
	return put_user(CPU_NUM, arg);
}


static unsigned long beta_unpark_thread(struct ipc_container *container)
{
	if (container->thread == NULL)
		return -EINVAL;

	/* FROM THIS POINT FORWARD, ATLEAST ONE OF THE THREADS
	 * IS SITTING IN THE COMM CODE
	 */

	pr_debug("waking up process on CPU %d\n", CPU_NUM);
	kthread_unpark(container->thread);
	if (wake_up_process(container->thread) == 1)
		pr_debug("Woke up process on cpu %d\n", CPU_NUM);

	return 0;
}


static unsigned long beta_connect_mem(struct ipc_container *container,
				      unsigned long __arg)
{

	unsigned long  __user *ubuf = (void *) __arg;
	unsigned long kland_real;
	unsigned long *kland;

	if (get_user(kland_real, ubuf)) {
		pr_debug("get_user failed connect_mem with ptr %p\n", ubuf);
		return -EFAULT;
	}

	kland = (unsigned long *) kland_real;

	if (kland == NULL)
		return -EFAULT;


	/* todo talk about this bootstrap issue while we're beta testing */
	/* perhaps, we can use extern and export syms? */
	container->channel_rx = (struct ttd_ring_channel *) kland;
	return 0;
}

static unsigned long beta_alloc_mem(struct ipc_container *container)
{
	int ret;
	if (container->channel_tx == NULL)
		return -EINVAL;

	ret = ttd_ring_channel_alloc(container->channel_tx,
				     CHAN_NUM_PAGES,
				     sizeof(struct ipc_message));

	if (ret != 0) {
		pr_err("Failed to alloc/Init ring channel\n");
		return -ENOMEM;
	}
	pr_debug("Channel is at %p, recs are %p to %p\n", (void*)container->channel_tx,
		 container->channel_tx->recs,
		 container->channel_tx->recs + (CHAN_NUM_PAGES * PAGE_SIZE));
	start = (unsigned long) container->channel_tx->recs;
	end = (unsigned long) container->channel_tx->recs + (CHAN_NUM_PAGES * PAGE_SIZE);

	memset(container->channel_tx->recs, 0, (CHAN_NUM_PAGES * PAGE_SIZE));

	return 0;
}

static int beta_open(struct inode *nodp, struct file *filep)
{

	struct ipc_container *container;

#if defined(TIMING)
	timekeeper = kzalloc(sizeof(u64) * NUM_LOOPS, GFP_KERNEL);

	if(!timekeeper) {
		pr_err("could not alloc space for time keeping");
		return -ENOMEM;
	}
#endif
	container = kzalloc(sizeof(*container), GFP_KERNEL);

	if (!container) {
		pr_err("Could not alloc space for container\n");
		return -ENOMEM;
	}

	container->channel_tx = kzalloc(sizeof(*container->channel_tx),
					GFP_KERNEL);

	if (!container->channel_tx) {
		pr_err("Could not alloc space for ring channel\n");
		return -ENOMEM;
	}

	container->thread = kthread_create_on_cpu(&ipc_thread_func,
						  (void *)filep, CPU_NUM,
						  "betaIPC.%u");

	if (IS_ERR(container->thread)) {
		pr_err("Error while creating kernel thread\n");
		return PTR_ERR(container->thread);
	}

	filep->private_data = container;
	return 0;
}

static int beta_close(struct inode *nodp, struct file *filep)
{

	struct ipc_container *container;

	//	container = filep->private_data;
	//kfree(container);

	//	if (container->channel_tx)
	//	ttd_ring_channel_free(container->channel_tx);


	return 0;
}

static long beta_return_mem(struct ipc_container *container,
			    unsigned long __arg)
{
	unsigned long __user  *save = (unsigned long *) __arg;

	return put_user((unsigned long)container->channel_tx, save);
}


static void dump_time(void)
{
	int i;
	unsigned long long counter = 0;
        u64 min;
	u64 max;
	if (timekeeper == NULL) {
		pr_err("Time keeper was null, ret");
		return;
	}
	min = timekeeper[0];
	max = min;

	for (i = 0; i < NUM_LOOPS; i++) {
	  counter+= timekeeper[i];
	  if(timekeeper[i] > max)
	    max = timekeeper[i];
	  if(timekeeper[i] < min)
	    min = timekeeper[i];
	}
	pr_err("TIME STATS MIN %u, MAX %u, AVG %u\n", min, max, counter/NUM_LOOPS);
	pr_err("WE ENTERED MWAIT LOOP %lu times on CPU %d\n", mwaitcount, CPU_NUM);

}

static long beta_ioctl(struct file *filep, unsigned int cmd,
		       unsigned long __arg)
{
	struct ipc_container *container = filep->private_data;
	long ret = 0;

	switch (cmd) {
	case BETA_ALLOC_MEM:
		ret = beta_alloc_mem(container);
		break;
	case BETA_GET_CPU_AFFINITY:
		ret = beta_ret_cpu(__arg);
		break;
	case BETA_CONNECT_SHARED_MEM:
		ret = beta_connect_mem(container, __arg);
		break;
	case BETA_UNPARK_THREAD:
		ret = beta_unpark_thread(container);
		break;
	case BETA_GET_MEM:
		ret = beta_return_mem(container, __arg);
		break;
	case BETA_DUMP_TIME:
		dump_time();
		break;
	default:
		pr_debug("No such ioctl %d\n", cmd);
		break;
	}
	return ret;
}

static const struct file_operations betaIPC_fops = {
	.owner	 = THIS_MODULE,
	.open    = beta_open,
	.release  = beta_close,
	.unlocked_ioctl   = beta_ioctl,
};

static struct miscdevice dev = {
	MISC_DYNAMIC_MINOR,
	"betaIPC",
	&betaIPC_fops,
};



static int __init bIPC_init(void)
{
	int ret = 0;

	CPU_NUM = 0;
	if (this_cpu_has(X86_FEATURE_MWAIT))
		printk(KERN_DEBUG "HAS MWAIT\n");

	/* reading through the source of misc.c it looks like register
	   will init everything else for us */
	pr_debug("hello from bIPC with pr_debug\n");
	printk(KERN_DEBUG "Hello from bIPC with printk\n");
	ret = misc_register(&dev);
	if (ret) {
		pr_debug("Failed to register dev for BetaIPC\n");
		return ret;
	}

	return ret;
}
static int __exit bIPC_rmmod(void)
{
	int ret = 0;

	ret = misc_deregister(&dev);
	if (ret) {
		pr_debug("Failed to de-reg dev in eudy!\n");
		return ret;
	}

	return 0;
}

module_init(bIPC_init);
module_exit(bIPC_rmmod);
