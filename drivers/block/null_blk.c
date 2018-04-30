#include <linux/module.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/blk-mq.h>
#include <linux/hrtimer.h>
#include <linux/lightnvm.h>

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include <linux/blk-bench.h>

INIT_BENCHMARK_DATA(queue_rq);

extern struct request_queue *queue_nullb;
struct nullb_cmd {
	struct list_head list;
	struct llist_node ll_list;
	struct call_single_data csd;
	struct request *rq;
	struct bio *bio;
	unsigned int tag;
	struct nullb_queue *nq;
	struct hrtimer timer;
};

struct nullb_queue {
	unsigned long *tag_map;
	wait_queue_head_t wait;
	unsigned int queue_depth;

	struct nullb_cmd *cmds;
};

struct nullb {
	struct list_head list;
	unsigned int index;
	struct request_queue *q;
	struct gendisk *disk;
	struct blk_mq_tag_set tag_set;
	struct hrtimer timer;
	unsigned int queue_depth;
	spinlock_t lock;

	struct nullb_queue *queues;
	unsigned int nr_queues;
	char disk_name[DISK_NAME_LEN];
};

static LIST_HEAD(nullb_list);
static struct mutex lock;
static int null_major;
static int nullb_indexes;
static struct kmem_cache *ppa_cache;

static struct class *drv_class;
static struct cdev *cdev_local = NULL;
static struct device *dev = NULL;
dev_t dev_no = 0;

#define MAX_INFO_ENTRIES 100
struct lcd_user_info {
	struct page *p[MAX_INFO_ENTRIES];
        unsigned int order[MAX_INFO_ENTRIES];
};

enum {
	NULL_IRQ_NONE		= 0,
	NULL_IRQ_SOFTIRQ	= 1,
	NULL_IRQ_TIMER		= 2,
};

enum {
	NULL_Q_BIO		= 0,
	NULL_Q_RQ		= 1,
	NULL_Q_MQ		= 2,
};

static int submit_queues;
module_param(submit_queues, int, S_IRUGO);
MODULE_PARM_DESC(submit_queues, "Number of submission queues");

static int home_node = NUMA_NO_NODE;
module_param(home_node, int, S_IRUGO);
MODULE_PARM_DESC(home_node, "Home node for the device");

static int queue_mode = NULL_Q_MQ;

static int null_param_store_val(const char *str, int *val, int min, int max)
{
	int ret, new_val;

	ret = kstrtoint(str, 10, &new_val);
	if (ret)
		return -EINVAL;

	if (new_val < min || new_val > max)
		return -EINVAL;

	*val = new_val;
	return 0;
}

static int null_set_queue_mode(const char *str, const struct kernel_param *kp)
{
	return null_param_store_val(str, &queue_mode, NULL_Q_BIO, NULL_Q_MQ);
}

static const struct kernel_param_ops null_queue_mode_param_ops = {
	.set	= null_set_queue_mode,
	.get	= param_get_int,
};

device_param_cb(queue_mode, &null_queue_mode_param_ops, &queue_mode, S_IRUGO);
MODULE_PARM_DESC(queue_mode, "Block interface to use (0=bio,1=rq,2=multiqueue)");

static int gb = 250;
module_param(gb, int, S_IRUGO);
MODULE_PARM_DESC(gb, "Size in GB");

static int bs = 512;
module_param(bs, int, S_IRUGO);
MODULE_PARM_DESC(bs, "Block size (in bytes)");

static int nr_devices = 1;
module_param(nr_devices, int, S_IRUGO);
MODULE_PARM_DESC(nr_devices, "Number of devices to register");

static bool use_lightnvm;
module_param(use_lightnvm, bool, S_IRUGO);
MODULE_PARM_DESC(use_lightnvm, "Register as a LightNVM device");

//static int irqmode = NULL_IRQ_SOFTIRQ;
static int irqmode = NULL_IRQ_NONE;

static int null_set_irqmode(const char *str, const struct kernel_param *kp)
{
	return null_param_store_val(str, &irqmode, NULL_IRQ_NONE,
					NULL_IRQ_TIMER);
}

static const struct kernel_param_ops null_irqmode_param_ops = {
	.set	= null_set_irqmode,
	.get	= param_get_int,
};

device_param_cb(irqmode, &null_irqmode_param_ops, &irqmode, S_IRUGO);
MODULE_PARM_DESC(irqmode, "IRQ completion handler. 0-none, 1-softirq, 2-timer");

static unsigned long completion_nsec = 10000;
module_param(completion_nsec, ulong, S_IRUGO);
MODULE_PARM_DESC(completion_nsec, "Time in ns to complete a request in hardware. Default: 10,000ns");

static int hw_queue_depth = 64;
module_param(hw_queue_depth, int, S_IRUGO);
MODULE_PARM_DESC(hw_queue_depth, "Queue depth for each hardware queue. Default: 64");

static bool use_per_node_hctx = false;
module_param(use_per_node_hctx, bool, S_IRUGO);
MODULE_PARM_DESC(use_per_node_hctx, "Use per-node allocation for hardware context queues. Default: false");

static void put_tag(struct nullb_queue *nq, unsigned int tag)
{
	clear_bit_unlock(tag, nq->tag_map);

	if (waitqueue_active(&nq->wait))
		wake_up(&nq->wait);
}

static unsigned int get_tag(struct nullb_queue *nq)
{
	unsigned int tag;

	do {
		tag = find_first_zero_bit(nq->tag_map, nq->queue_depth);
		if (tag >= nq->queue_depth)
			return -1U;
	} while (test_and_set_bit_lock(tag, nq->tag_map));

	return tag;
}

static void free_cmd(struct nullb_cmd *cmd)
{
	put_tag(cmd->nq, cmd->tag);
}

#define DRV_MAX_DEVS    1
int lcd_setup_chardev(const char* dev_name, const struct file_operations* fops)
{
        int ret = 0;

        printk("mod init \n");
        drv_class = class_create(THIS_MODULE, dev_name);
        if (IS_ERR(drv_class)) {
                printk(KERN_ERR "class_create failed \n");
                ret = PTR_ERR(drv_class);
                goto exit_no_class;
        }

        /* Dynamic registration of major number */
        printk("alloc chardev \n");
        ret = alloc_chrdev_region(&dev_no, 0, DRV_MAX_DEVS, dev_name);
        if (ret < 0){
                printk(KERN_ERR "Couldn't alloc chardev region \n");
                goto exit_chrdev_reg;
        }

        printk("cdev alloc \n");
        cdev_local = cdev_alloc();
        if(!cdev_local) {
                ret = -ENOMEM;
                printk("cdev_alloc- not enough memory \n");
                goto exit_cdev_alloc;
        }

        cdev_local->owner = THIS_MODULE;
        cdev_local->ops = fops;

        printk("cdev add \n");
        ret = cdev_add(cdev_local, dev_no, 1);
        if(ret) {
                printk("Cannot add cdev device \n");
                goto exit_dev_add;
        }

        printk("dev create \n");
        dev = device_create(drv_class, NULL, dev_no, NULL, "%s", dev_name);
        if(IS_ERR(dev)) {
                ret = PTR_ERR(dev);
                printk("Cannot create device node entry \n");
                goto exit_dev_create;
        }

        printk("init done \n");
        return 0;

exit_dev_create:

exit_dev_add:
        cdev_del(cdev_local);

exit_cdev_alloc:
        unregister_chrdev_region(dev_no, DRV_MAX_DEVS);

exit_chrdev_reg:
        class_destroy(drv_class);

exit_no_class:
        return ret;

}

void lcd_teardown_chardev(void)
{
        cdev_del(cdev_local);
        device_del(dev);
        unregister_chrdev_region(dev_no, DRV_MAX_DEVS);
        class_destroy(drv_class);
}


static enum hrtimer_restart null_cmd_timer_expired(struct hrtimer *timer);

static struct nullb_cmd *__alloc_cmd(struct nullb_queue *nq)
{
	struct nullb_cmd *cmd;
	unsigned int tag;

	tag = get_tag(nq);
	if (tag != -1U) {
		cmd = &nq->cmds[tag];
		cmd->tag = tag;
		cmd->nq = nq;
		if (irqmode == NULL_IRQ_TIMER) {
			hrtimer_init(&cmd->timer, CLOCK_MONOTONIC,
				     HRTIMER_MODE_REL);
			cmd->timer.function = null_cmd_timer_expired;
		}
		return cmd;
	}

	return NULL;
}

static struct nullb_cmd *alloc_cmd(struct nullb_queue *nq, int can_wait)
{
	struct nullb_cmd *cmd;
	DEFINE_WAIT(wait);

	cmd = __alloc_cmd(nq);
	if (cmd || !can_wait)
		return cmd;

	do {
		prepare_to_wait(&nq->wait, &wait, TASK_UNINTERRUPTIBLE);
		cmd = __alloc_cmd(nq);
		if (cmd)
			break;

		io_schedule();
	} while (1);

	finish_wait(&nq->wait, &wait);
	return cmd;
}

static void end_cmd(struct nullb_cmd *cmd)
{
	struct request_queue *q = NULL;

	if (cmd->rq)
		q = cmd->rq->q;

	switch (queue_mode)  {
	case NULL_Q_MQ:
		//BENCH_BEGIN(queue_rq);
		blk_mq_end_request(cmd->rq, 0);
		//BENCH_END(queue_rq);
		return;
	case NULL_Q_RQ:
		INIT_LIST_HEAD(&cmd->rq->queuelist);
		blk_end_request_all(cmd->rq, 0);
		break;
	case NULL_Q_BIO:
		bio_endio(cmd->bio);
		break;
	}

	free_cmd(cmd);

	/* Restart queue if needed, as we are freeing a tag */
	if (queue_mode == NULL_Q_RQ && blk_queue_stopped(q)) {
		unsigned long flags;

		spin_lock_irqsave(q->queue_lock, flags);
		blk_start_queue_async(q);
		spin_unlock_irqrestore(q->queue_lock, flags);
	}
}

static enum hrtimer_restart null_cmd_timer_expired(struct hrtimer *timer)
{
	end_cmd(container_of(timer, struct nullb_cmd, timer));

	return HRTIMER_NORESTART;
}

static void null_cmd_end_timer(struct nullb_cmd *cmd)
{
	ktime_t kt = ktime_set(0, completion_nsec);

	hrtimer_start(&cmd->timer, kt, HRTIMER_MODE_REL);
}

static void null_softirq_done_fn(struct request *rq)
{
	printk("calling sirq done function \n");
	if (queue_mode == NULL_Q_MQ)
		end_cmd(blk_mq_rq_to_pdu(rq));
	else
		end_cmd(rq->special);
}

static inline void null_handle_cmd(struct nullb_cmd *cmd)
{
	/* Complete IO by inline, softirq or timer */
	switch (irqmode) {
	case NULL_IRQ_SOFTIRQ:
		switch (queue_mode)  {
		case NULL_Q_MQ:
			//printk("calling complete request \n");
			blk_mq_complete_request(cmd->rq, cmd->rq->errors);
			break;
		case NULL_Q_RQ:
			blk_complete_request(cmd->rq);
			break;
		case NULL_Q_BIO:
			/*
			 * XXX: no proper submitting cpu information available.
			 */
			end_cmd(cmd);
			break;
		}
		break;
	case NULL_IRQ_NONE:
		end_cmd(cmd);
		break;
	case NULL_IRQ_TIMER:
		null_cmd_end_timer(cmd);
		break;
	}
}

static struct nullb_queue *nullb_to_queue(struct nullb *nullb)
{
	int index = 0;

	if (nullb->nr_queues != 1)
		index = raw_smp_processor_id() / ((nr_cpu_ids + nullb->nr_queues - 1) / nullb->nr_queues);

	return &nullb->queues[index];
}

static blk_qc_t null_queue_bio(struct request_queue *q, struct bio *bio)
{
	struct nullb *nullb = q->queuedata;
	struct nullb_queue *nq = nullb_to_queue(nullb);
	struct nullb_cmd *cmd;

	cmd = alloc_cmd(nq, 1);
	cmd->bio = bio;

	null_handle_cmd(cmd);
	return BLK_QC_T_NONE;
}

static int null_rq_prep_fn(struct request_queue *q, struct request *req)
{
	struct nullb *nullb = q->queuedata;
	struct nullb_queue *nq = nullb_to_queue(nullb);
	struct nullb_cmd *cmd;

	cmd = alloc_cmd(nq, 0);
	if (cmd) {
		cmd->rq = req;
		req->special = cmd;
		return BLKPREP_OK;
	}
	blk_stop_queue(q);

	return BLKPREP_DEFER;
}

static void null_request_fn(struct request_queue *q)
{
	struct request *rq;

	while ((rq = blk_fetch_request(q)) != NULL) {
		struct nullb_cmd *cmd = rq->special;

		spin_unlock_irq(q->queue_lock);
		null_handle_cmd(cmd);
		spin_lock_irq(q->queue_lock);
	}
}

static int null_queue_rq(struct blk_mq_hw_ctx *hctx,
			 const struct blk_mq_queue_data *bd)
{
	struct nullb_cmd *cmd = blk_mq_rq_to_pdu(bd->rq);
	//static int count = 0;
	
	//count++;
	//if(count == 100) {
	//	printk("**** queue_rq -> current:%p pid: %d name:%s\n",current, current->pid, current->comm);
	//	dump_stack();
	//	count = 0;

	//}
	if (irqmode == NULL_IRQ_TIMER) {
		hrtimer_init(&cmd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cmd->timer.function = null_cmd_timer_expired;
	}
	cmd->rq = bd->rq;
	cmd->nq = hctx->driver_data;

	//BENCH_BEGIN(queue_rq);
	//printk("**** start_req -> name:%p req:%p \n",current->comm, bd->rq);
	blk_mq_start_request(bd->rq);
	//BENCH_END(queue_rq);
	
	null_handle_cmd(cmd);
	//BENCH_END(queue_rq);
	return BLK_MQ_RQ_QUEUE_OK;
}

void queue_rq_async(struct blk_mq_hw_ctx *ctx, struct blk_mq_queue_data_async *bd_async)
{

	//BENCH_BEGIN(queue_rq);
	while(!list_empty(bd_async->rq_list)) {
		struct request *rq;
		struct blk_mq_queue_data bd;
		int ret; 
	
		rq = list_first_entry(bd_async->rq_list, struct request, queuelist);
		list_del_init(&rq->queuelist);

		bd.rq = rq;
		bd.list = bd_async->list;
		bd.last = list_empty(bd_async->rq_list);
	
		//call queue_rq handler
		ret = null_queue_rq(ctx, &bd);

		switch (ret) {
		case BLK_MQ_RQ_QUEUE_OK:
			bd_async->queued++;
			break;
		case BLK_MQ_RQ_QUEUE_BUSY:
			list_add(&rq->queuelist, bd_async->rq_list);
			__blk_mq_requeue_request(rq);
			break;
		default:
			pr_err("blk-mq: bad return on queue: %d\n", ret);
		case BLK_MQ_RQ_QUEUE_ERROR:
			if(rq) {
				rq->errors = -EIO;
				blk_mq_end_request(rq, rq->errors);
			}
			break;
		}

		if (ret == BLK_MQ_RQ_QUEUE_BUSY)
			break;

		/*
		 * We've done the first request. If we have more than 1
		 * left in the list, set dptr to defer issue.
		 */
		if (!bd_async->list && bd_async->rq_list->next != bd_async->rq_list->prev)
			bd_async->list = bd_async->drv_list;

	}
	//BENCH_END(queue_rq);

	return;
}


static void null_init_queue(struct nullb *nullb, struct nullb_queue *nq)
{
	BUG_ON(!nullb);
	BUG_ON(!nq);

	init_waitqueue_head(&nq->wait);
	nq->queue_depth = nullb->queue_depth;
}

static int null_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			  unsigned int index)
{
	struct nullb *nullb = data;
	struct nullb_queue *nq = &nullb->queues[index];

	hctx->driver_data = nq;
	null_init_queue(nullb, nq);
	nullb->nr_queues++;

	return 0;
}

static struct blk_mq_ops null_mq_ops = {
	.queue_rq       = null_queue_rq,
	//.queue_rq_async = queue_rq_async,
	.map_queue      = blk_mq_map_queue,
	.init_hctx	= null_init_hctx,
	.complete	= null_softirq_done_fn,
};

static void cleanup_queue(struct nullb_queue *nq)
{
	kfree(nq->tag_map);
	kfree(nq->cmds);
}

static void cleanup_queues(struct nullb *nullb)
{
	int i;

	for (i = 0; i < nullb->nr_queues; i++)
		cleanup_queue(&nullb->queues[i]);

	kfree(nullb->queues);
}

static void null_del_dev(struct nullb *nullb)
{
	list_del_init(&nullb->list);

	if (use_lightnvm)
		nvm_unregister(nullb->disk_name);
	else
		del_gendisk(nullb->disk);
	blk_cleanup_queue(nullb->q);
	if (queue_mode == NULL_Q_MQ)
		blk_mq_free_tag_set(&nullb->tag_set);
	if (!use_lightnvm)
		put_disk(nullb->disk);
	cleanup_queues(nullb);
	kfree(nullb);
}

#ifdef CONFIG_NVM

static void null_lnvm_end_io(struct request *rq, int error)
{
	struct nvm_rq *rqd = rq->end_io_data;

	nvm_end_io(rqd, error);

	blk_put_request(rq);
}

static int null_lnvm_submit_io(struct nvm_dev *dev, struct nvm_rq *rqd)
{
	struct request_queue *q = dev->q;
	struct request *rq;
	struct bio *bio = rqd->bio;

	rq = blk_mq_alloc_request(q, bio_data_dir(bio), 0);
	if (IS_ERR(rq))
		return -ENOMEM;

	rq->cmd_type = REQ_TYPE_DRV_PRIV;
	rq->__sector = bio->bi_iter.bi_sector;
	rq->ioprio = bio_prio(bio);

	if (bio_has_data(bio))
		rq->nr_phys_segments = bio_phys_segments(q, bio);

	rq->__data_len = bio->bi_iter.bi_size;
	rq->bio = rq->biotail = bio;

	rq->end_io_data = rqd;

	blk_execute_rq_nowait(q, NULL, rq, 0, null_lnvm_end_io);

	return 0;
}

static int null_lnvm_id(struct nvm_dev *dev, struct nvm_id *id)
{
	sector_t size = gb * 1024 * 1024 * 1024ULL;
	sector_t blksize;
	struct nvm_id_group *grp;

	id->ver_id = 0x1;
	id->vmnt = 0;
	id->cgrps = 1;
	id->cap = 0x2;
	id->dom = 0x1;

	id->ppaf.blk_offset = 0;
	id->ppaf.blk_len = 16;
	id->ppaf.pg_offset = 16;
	id->ppaf.pg_len = 16;
	id->ppaf.sect_offset = 32;
	id->ppaf.sect_len = 8;
	id->ppaf.pln_offset = 40;
	id->ppaf.pln_len = 8;
	id->ppaf.lun_offset = 48;
	id->ppaf.lun_len = 8;
	id->ppaf.ch_offset = 56;
	id->ppaf.ch_len = 8;

	sector_div(size, bs); /* convert size to pages */
	size >>= 8; /* concert size to pgs pr blk */
	grp = &id->groups[0];
	grp->mtype = 0;
	grp->fmtype = 0;
	grp->num_ch = 1;
	grp->num_pg = 256;
	blksize = size;
	size >>= 16;
	grp->num_lun = size + 1;
	sector_div(blksize, grp->num_lun);
	grp->num_blk = blksize;
	grp->num_pln = 1;

	grp->fpg_sz = bs;
	grp->csecs = bs;
	grp->trdt = 25000;
	grp->trdm = 25000;
	grp->tprt = 500000;
	grp->tprm = 500000;
	grp->tbet = 1500000;
	grp->tbem = 1500000;
	grp->mpos = 0x010101; /* single plane rwe */
	grp->cpar = hw_queue_depth;

	return 0;
}

static void *null_lnvm_create_dma_pool(struct nvm_dev *dev, char *name)
{
	mempool_t *virtmem_pool;

	virtmem_pool = mempool_create_slab_pool(64, ppa_cache);
	if (!virtmem_pool) {
		pr_err("null_blk: Unable to create virtual memory pool\n");
		return NULL;
	}

	return virtmem_pool;
}

static void null_lnvm_destroy_dma_pool(void *pool)
{
	mempool_destroy(pool);
}

static void *null_lnvm_dev_dma_alloc(struct nvm_dev *dev, void *pool,
				gfp_t mem_flags, dma_addr_t *dma_handler)
{
	return mempool_alloc(pool, mem_flags);
}

static void null_lnvm_dev_dma_free(void *pool, void *entry,
							dma_addr_t dma_handler)
{
	mempool_free(entry, pool);
}

static struct nvm_dev_ops null_lnvm_dev_ops = {
	.identity		= null_lnvm_id,
	.submit_io		= null_lnvm_submit_io,

	.create_dma_pool	= null_lnvm_create_dma_pool,
	.destroy_dma_pool	= null_lnvm_destroy_dma_pool,
	.dev_dma_alloc		= null_lnvm_dev_dma_alloc,
	.dev_dma_free		= null_lnvm_dev_dma_free,

	/* Simulate nvme protocol restriction */
	.max_phys_sect		= 64,
};
#else
static struct nvm_dev_ops null_lnvm_dev_ops;
#endif /* CONFIG_NVM */

static int null_open(struct block_device *bdev, fmode_t mode)
{
	if(strcmp(current->comm, "systemd-udevd") == 0) {
		return -ENODEV;
	}
	printk("^^^^ calling open current %p pid %d name %s \n", current, current->pid, current->comm);
	return 0;
}

static void null_release(struct gendisk *disk, fmode_t mode)
{
	printk("^^^^ calling release current %p pid %d name %s \n", current, current->pid, current->comm);
}

static const struct block_device_operations null_fops = {
	.owner =	THIS_MODULE,
	.open =		null_open,
	.release =	null_release,
};

static int setup_commands(struct nullb_queue *nq)
{
	struct nullb_cmd *cmd;
	int i, tag_size;

	nq->cmds = kzalloc(nq->queue_depth * sizeof(*cmd), GFP_KERNEL);
	if (!nq->cmds)
		return -ENOMEM;

	tag_size = ALIGN(nq->queue_depth, BITS_PER_LONG) / BITS_PER_LONG;
	nq->tag_map = kzalloc(tag_size * sizeof(unsigned long), GFP_KERNEL);
	if (!nq->tag_map) {
		kfree(nq->cmds);
		return -ENOMEM;
	}

	for (i = 0; i < nq->queue_depth; i++) {
		cmd = &nq->cmds[i];
		INIT_LIST_HEAD(&cmd->list);
		cmd->ll_list.next = NULL;
		cmd->tag = -1U;
	}

	return 0;
}

static int setup_queues(struct nullb *nullb)
{
	nullb->queues = kzalloc(submit_queues * sizeof(struct nullb_queue),
								GFP_KERNEL);
	if (!nullb->queues)
		return -ENOMEM;

	nullb->nr_queues = 0;
	nullb->queue_depth = hw_queue_depth;

	return 0;
}

static int init_driver_queues(struct nullb *nullb)
{
	struct nullb_queue *nq;
	int i, ret = 0;

	for (i = 0; i < submit_queues; i++) {
		nq = &nullb->queues[i];

		null_init_queue(nullb, nq);

		ret = setup_commands(nq);
		if (ret)
			return ret;
		nullb->nr_queues++;
	}
	return 0;
}

static int null_add_dev(void)
{
	struct gendisk *disk;
	struct nullb *nullb;
	sector_t size;
	int rv;

	nullb = kzalloc_node(sizeof(*nullb), GFP_KERNEL, home_node);
	if (!nullb) {
		rv = -ENOMEM;
		goto out;
	}

	spin_lock_init(&nullb->lock);

	if (queue_mode == NULL_Q_MQ && use_per_node_hctx)
		submit_queues = nr_online_nodes;

	printk("submit_queues %d, nr_online_nodes %d \n",submit_queues, nr_online_nodes);
	rv = setup_queues(nullb);
	if (rv)
		goto out_free_nullb;

	if (queue_mode == NULL_Q_MQ) {
		nullb->tag_set.ops = &null_mq_ops;
		nullb->tag_set.nr_hw_queues = submit_queues;
		nullb->tag_set.queue_depth = hw_queue_depth;
		nullb->tag_set.numa_node = home_node;
		nullb->tag_set.cmd_size	= sizeof(struct nullb_cmd);
		nullb->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
		nullb->tag_set.driver_data = nullb;

		printk("using block MQ layer \n");
		rv = blk_mq_alloc_tag_set(&nullb->tag_set);
		if (rv)
			goto out_cleanup_queues;

		nullb->q = blk_mq_init_queue(&nullb->tag_set);
		if (IS_ERR(nullb->q)) {
			rv = -ENOMEM;
			goto out_cleanup_tags;
		}
		queue_nullb = nullb->q;
	} else if (queue_mode == NULL_Q_BIO) {
		nullb->q = blk_alloc_queue_node(GFP_KERNEL, home_node);
		if (!nullb->q) {
			rv = -ENOMEM;
			goto out_cleanup_queues;
		}
		blk_queue_make_request(nullb->q, null_queue_bio);
		rv = init_driver_queues(nullb);
		if (rv)
			goto out_cleanup_blk_queue;
	} else {
		nullb->q = blk_init_queue_node(null_request_fn, &nullb->lock, home_node);
		if (!nullb->q) {
			rv = -ENOMEM;
			goto out_cleanup_queues;
		}
		blk_queue_prep_rq(nullb->q, null_rq_prep_fn);
		blk_queue_softirq_done(nullb->q, null_softirq_done_fn);
		rv = init_driver_queues(nullb);
		if (rv)
			goto out_cleanup_blk_queue;
	}

	nullb->q->queuedata = nullb;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, nullb->q);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, nullb->q);

	mutex_lock(&lock);
	nullb->index = nullb_indexes++;
	mutex_unlock(&lock);

	printk("---------------------------> block size: %d \n", bs);
	blk_queue_logical_block_size(nullb->q, bs);
	blk_queue_physical_block_size(nullb->q, bs);

	sprintf(nullb->disk_name, "nullb%d", nullb->index);

	if (use_lightnvm) {
		rv = nvm_register(nullb->q, nullb->disk_name,
							&null_lnvm_dev_ops);
		if (rv)
			goto out_cleanup_blk_queue;
		goto done;
	}

	disk = nullb->disk = alloc_disk_node(1, home_node);
	if (!disk) {
		rv = -ENOMEM;
		goto out_cleanup_lightnvm;
	}
	size = gb * 1024 * 1024 * 1024ULL;
	set_capacity(disk, size >> 9);

	disk->flags |= GENHD_FL_EXT_DEVT | GENHD_FL_SUPPRESS_PARTITION_INFO;
	disk->major		= null_major;
	disk->first_minor	= nullb->index;
	disk->fops		= &null_fops;
	disk->private_data	= nullb;
	disk->queue		= nullb->q;
	strncpy(disk->disk_name, nullb->disk_name, DISK_NAME_LEN);

	add_disk(disk);

done:
	mutex_lock(&lock);
	list_add_tail(&nullb->list, &nullb_list);
	mutex_unlock(&lock);

	return 0;

out_cleanup_lightnvm:
	if (use_lightnvm)
		nvm_unregister(nullb->disk_name);
out_cleanup_blk_queue:
	blk_cleanup_queue(nullb->q);
out_cleanup_tags:
	if (queue_mode == NULL_Q_MQ)
		blk_mq_free_tag_set(&nullb->tag_set);
out_cleanup_queues:
	cleanup_queues(nullb);
out_free_nullb:
	kfree(nullb);
out:
	return rv;
}

static int nullbu_open(struct inode *inode, struct file *filp)
{
        struct lcd_user_info *info;

        printk("dev opened \n");

        info = kzalloc(sizeof(*info), GFP_KERNEL);
        if(!info) {
                printk("cannot create user info \n");
                return -ENOMEM;
        }

        filp->private_data = info;

        return 0;
}

static int nullbu_close (struct inode *inode, struct file *filp)
{
        struct lcd_user_info *info;
        int i = 0;

        info = (struct lcd_user_info *)filp->private_data;

        printk("dev closed \n");

        for (i = 0; i < MAX_INFO_ENTRIES; i++) {
                if (info->p[i]) {
                        free_pages((unsigned long)page_address(info->p[i]), info->order[i]);
                }
        }

        kfree(info);

        return 0;
}

static int nullbu_mmap(struct file *filp, struct vm_area_struct *vma)
{
        int ret = 0;
        struct lcd_user_info *info;
        struct page *p;
        unsigned long size = PAGE_ALIGN(vma->vm_end - vma->vm_start);
        //unsigned long order = ilog2(roundup_pow_of_two(size >> PAGE_SHIFT));
        unsigned long order = get_order(size);
        unsigned long new_order = 0;
        unsigned long rem_order = 0;
        unsigned long vma_start = vma->vm_start;
        //void *addr;
        int i = 0;
        int j = 0;

	printk("**** vma->flags: %x \n", vma->vm_flags);
        info = (struct lcd_user_info *)filp->private_data;
        printk("[MMAP_DEV] begin: %lx end: %lx mmap_size: %ld pgoff: %ld order: %ld\n", vma->vm_start, vma->vm_end, size, vma->vm_pgoff, order);
	
/*	for(i = 0; i < (1 << order); i++) {
		
                printk("Begin mapping\n");
		p = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);
		if(!p) {
			printk("alloc_page failed \n");
			ret = -ENOMEM;
			goto fail_alloc;
		}

		info->p[i] = p;
		info->order[i] = 0;
		
		printk("vma->flags before: %lx \n", vma->vm_flags);
		ret = vm_insert_page(vma, vma->vm_start, p);
		if (ret < 0) {
			printk("insert page failed ***************************** \n");
			goto fail_alloc;
		}
		vma->vm_flags &= ~(VM_IO | VM_PFNMAP);
		vma->vm_start += PAGE_SIZE;
		printk("vma->flags cleared: %lx \n", vma->vm_flags);
                printk("mapping done! \n");
	}

*/	
	if(order >= MAX_ORDER) {
                new_order = MAX_ORDER - 1;
                rem_order = order - new_order;
        } else {
                new_order = order;
                rem_order = 0;
        }

        
	
	for (i = 0; i < (1 << rem_order); i++) {
		
		//unsigned long va = 0;
                
                //Allocate physical pages for the requested size
                printk("alloc_pages \n");
                p = alloc_pages(GFP_KERNEL | __GFP_ZERO, new_order);
                if(!p) {
                        printk("alloc_page failed \n");
                        ret = -ENOMEM;
                        goto fail_alloc;
                }

                info->p[i] = p;
                info->order[i] = new_order;
		//va = (unsigned long) page_to_virt(p);

                printk("remapping range \n");
		for(j = 0; j < (1 << new_order); j++) {

			printk("vma->flags before: %lx \n", vma->vm_flags);

			//va += PAGE_SIZE * j;
			page_ref_inc(p+j);

			ret = vm_insert_page(vma, vma->vm_start, p+j);
			//ret = vm_insert_page(vma, vma->vm_start, virt_to_page(va));
			if (ret < 0) {
				printk("insert page failed ***************************** %d \n", ret);
				goto fail_alloc;
			}
			vma->vm_flags &= ~(VM_IO | VM_PFNMAP);
			vma->vm_start += PAGE_SIZE;
			printk("vma->flags cleared: %lx \n", vma->vm_flags);
			printk("mapping done! \n");
		}

                printk("mapping done! \n");
        }

        vma->vm_start = vma_start;
        printk("[MMAP_DONE] start: %lx end: %lx \n",vma->vm_start, vma->vm_end);
        return 0;

fail_alloc:
	for(i = 0; i < MAX_INFO_ENTRIES; i++) {
        	if(p) {
                	free_pages((unsigned long)page_address(p), order);
        	}
	}
        return ret;
}

struct file_operations nullb_user_fops = {
        .owner  = THIS_MODULE,
        .open   = nullbu_open,
        .release = nullbu_close,
        .mmap = nullbu_mmap,
};

static int __init null_init(void)
{
	int ret = 0;
	unsigned int i;
	struct nullb *nullb;

	if (bs > PAGE_SIZE) {
		pr_warn("null_blk: invalid block size\n");
		pr_warn("null_blk: defaults block size to %lu\n", PAGE_SIZE);
		bs = PAGE_SIZE;
	}

	if (use_lightnvm && bs != 4096) {
		pr_warn("null_blk: LightNVM only supports 4k block size\n");
		pr_warn("null_blk: defaults block size to 4k\n");
		bs = 4096;
	}

	if (use_lightnvm && queue_mode != NULL_Q_MQ) {
		pr_warn("null_blk: LightNVM only supported for blk-mq\n");
		pr_warn("null_blk: defaults queue mode to blk-mq\n");
		queue_mode = NULL_Q_MQ;
	}

	if (queue_mode == NULL_Q_MQ && use_per_node_hctx) {
		if (submit_queues < nr_online_nodes) {
			pr_warn("null_blk: submit_queues param is set to %u.",
							nr_online_nodes);
			submit_queues = nr_online_nodes;
		}
	} else if (submit_queues > nr_cpu_ids)
		submit_queues = nr_cpu_ids;
	else if (!submit_queues)
		submit_queues = 1;

	mutex_init(&lock);

	null_major = register_blkdev(0, "nullb");
	if (null_major < 0)
		return null_major;

	if (use_lightnvm) {
		ppa_cache = kmem_cache_create("ppa_cache", 64 * sizeof(u64),
								0, 0, NULL);
		if (!ppa_cache) {
			pr_err("null_blk: unable to create ppa cache\n");
			ret = -ENOMEM;
			goto err_ppa;
		}
	}

	for (i = 0; i < nr_devices; i++) {
		ret = null_add_dev();
		if (ret)
			goto err_dev;
	}

        /* setup char dev region */
        ret = lcd_setup_chardev("nullb_user", &nullb_user_fops);
        if(ret) {
                printk("setting up chardev failed \n");
                ret = -ENODEV;
                goto fail_setup;
        }


	pr_info("null: module loaded\n");
	return 0;

fail_setup:
err_dev:
	while (!list_empty(&nullb_list)) {
		nullb = list_entry(nullb_list.next, struct nullb, list);
		null_del_dev(nullb);
	}
	kmem_cache_destroy(ppa_cache);
err_ppa:
	unregister_blkdev(null_major, "nullb");
	return ret;
}

static void __exit null_exit(void)
{
	struct nullb *nullb;

	//BENCH_COMPUTE_STAT(queue_rq);
	
	unregister_blkdev(null_major, "nullb");
	lcd_teardown_chardev();
	mutex_lock(&lock);
	while (!list_empty(&nullb_list)) {
		nullb = list_entry(nullb_list.next, struct nullb, list);
		null_del_dev(nullb);
	}
	mutex_unlock(&lock);

	kmem_cache_destroy(ppa_cache);
	queue_nullb = NULL;
}

module_init(null_init);
module_exit(null_exit);

MODULE_AUTHOR("Jens Axboe <jaxboe@fusionio.com>");
MODULE_LICENSE("GPL");
