#ifndef _GLUE_HELPER_H_
#define _GLUE_HELPER_H_

#include <linux/kthread.h>
#include <linux/module.h>

/*Block layer deps */
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <libcap.h>
#include <libfipc.h>
#include <thc_ipc.h>
#include <liblcd/glue_cspace.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>


#define PMFS_ASYNC_RPC_BUFFER_ORDER 20
#define FIPC_MSG_STATUS_AVAILABLE 0xdeaddeadUL
#define FIPC_MSG_STATUS_SENT      0xfeedfeedUL

#define SENDER_DISPATCH_LOOP
#define CONFIG_PREALLOC_CHANNELS

enum dispatch_t {
        BLK_MQ_ALLOC_TAG_SET = 1,
        BLK_MQ_INIT_QUEUE,
        BLK_CLEANUP_QUEUE,
	BLK_MQ_END_REQUEST = 4,
        BLK_MQ_FREE_TAG_SET,
        BLK_MQ_START_REQUEST,
        BLK_MQ_MAP_QUEUE,
        BLK_QUEUE_LOGICAL_BLOCK_SIZE = 8,
        BLK_QUEUE_PHYSICAL_BLOCK_SIZE,
        ALLOC_DISK,
	ADD_DISK,
        PUT_DISK = 12,
        DEL_GENDISK,
        DISK_NODE,
        REGISTER_BLKDEV,
        UNREGISTER_BLKDEV = 16,
        REGISTER_CHARDEV,
	QUEUE_RQ_FN,
        MAP_QUEUE_FN,
        INIT_HCTX_FN = 20,
        SOFTIRQ_DONE_FN,
        OPEN,
	RELEASE,
	OPEN_CHARDEV = 24,
	RELEASE_CHARDEV,
	MMAP_CHARDEV,
        DESTROY_LCD = 27
};

/* CONTAINERS ------------------------------------------------------------ */
struct blk_mq_hw_ctx_container {
        struct blk_mq_hw_ctx blk_mq_hw_ctx;
        cptr_t other_ref;
        cptr_t my_ref;
};
struct blk_mq_ops_container {
        struct blk_mq_ops blk_mq_ops;
        cptr_t other_ref;
        cptr_t my_ref;
};
struct blk_mq_queue_data_container {
        struct blk_mq_queue_data blk_mq_queue_data;
        cptr_t other_ref;
        cptr_t my_ref;
};
struct blk_mq_tag_set_container {
        struct blk_mq_tag_set blk_mq_tag_set;
        cptr_t other_ref;
        cptr_t my_ref;
};
struct block_device_container {
        struct block_device block_device;
        cptr_t other_ref;
        cptr_t my_ref;
};
struct block_device_operations_container {
        struct block_device_operations block_device_operations;
        cptr_t other_ref;
        cptr_t my_ref;
};
struct gendisk_container {
        struct gendisk gendisk;
        cptr_t other_ref;
        cptr_t my_ref;
};
struct module_container {
        struct module module;
        cptr_t other_ref;
        cptr_t my_ref;
};
//struct nullb_container {
//        struct nullb nullb;
 //       cptr_t other_ref;
  //      cptr_t my_ref;
//};
struct request_container {
        struct request request;
        cptr_t other_ref;
        cptr_t my_ref;
};
struct request_queue_container {
        struct request_queue request_queue;
        cptr_t other_ref;
        cptr_t my_ref;
};

#if NUM_LCDS == 1
#define NUM_LCD_CPUS				(NUM_LCDS + 1)
  #define MAX_CHANNELS_PER_LCD           	(NUM_CPUS - NUM_LCD_CPUS)
  #define NUM_THREADS_ON_NODE0			(NUM_CPUS_PER_NODE - NUM_LCD_CPUS)
#elif NUM_LCDS == 2
  #define MAX_CHANNELS_PER_LCD          15
  #define NUM_THREADS_ON_NODE0		5
#elif NUM_LCDS == 4
/* total LCD cores = 5 (lcds=4,klcd=1), free cores = 15 */
#define MAX_CHANNELS_PER_LCD		7
#define NUM_THREADS_ON_NODE0		6
#elif NUM_LCDS == 6
/* total LCD cores = 7 (lcds=6,klcd=1), free cores = 13 */
#define MAX_CHANNELS_PER_LCD		3
#define NUM_THREADS_ON_NODE0		6
#endif

#define MAX_CHNL_PAIRS			MAX_CHANNELS_PER_LCD

/* CSPACES ------------------------------------------------------------ */
int glue_cap_init(void);

int glue_cap_create(struct glue_cspace **cspace);

void glue_cap_destroy(struct glue_cspace *cspace);

void glue_cap_exit(void);

void glue_cap_remove(
        struct glue_cspace *cspace,
        cptr_t c);

int glue_cap_insert_blk_mq_ops_type(struct glue_cspace *cspace, 
                        struct blk_mq_ops_container *blk_mq_ops_container,
                        cptr_t *c_out);

int glue_cap_insert_module_type(struct glue_cspace *cspace,
                        struct module_container *module_container,
                        cptr_t *c_out);

int glue_cap_insert_blk_mq_tag_set_type(struct glue_cspace *cspace,
                        struct blk_mq_tag_set_container *set_container,
                         cptr_t *c_out);

int glue_cap_insert_gendisk_type(struct glue_cspace *cspace,
                        struct gendisk_container *disk_container,
                        cptr_t *c_out);

int glue_cap_insert_blk_mq_hw_ctx_type(struct glue_cspace *cspace,
                        struct blk_mq_hw_ctx_container *ctx_container,
                        cptr_t *c_out);

int glue_cap_insert_blk_dev_ops_type(struct glue_cspace *cspace,
                        struct block_device_operations_container *blo_container,
                        cptr_t *c_out);

int glue_cap_insert_blk_mq_queue_data_type(struct glue_cspace *cspace,
                        struct blk_mq_queue_data_container *bd_container,
                        cptr_t *c_out);

int glue_cap_insert_request_queue_type(struct glue_cspace *cspace,
                        struct request_queue_container *req_queue_container,
                        cptr_t *c_out);

int glue_cap_lookup_blk_mq_ops_type(struct glue_cspace *cspace,
                        cptr_t c,
                         struct blk_mq_ops_container **blk_mq_ops_container);

int glue_cap_lookup_blk_mq_tag_set_type(struct glue_cspace *cspace,
                        cptr_t c,
                        struct blk_mq_tag_set_container **set_container);

int glue_cap_lookup_gendisk_type(struct glue_cspace *cspace,
                        cptr_t c,
                        struct gendisk_container **disk_container);

int glue_cap_lookup_blk_mq_hw_ctx_type(struct glue_cspace *cspace,
                        cptr_t c,
                         struct blk_mq_hw_ctx_container **ctx_container);

int glue_cap_lookup_blk_mq_queue_data_type(struct glue_cspace *cspace,
                        cptr_t c,
                        struct blk_mq_queue_data_container **bd_container);

int glue_cap_lookup_module_type(struct glue_cspace *cspace,
                                cptr_t c,
                                struct module_container **module_container);

int glue_cap_lookup_request_queue_type(struct glue_cspace *cspace,
                        cptr_t c,
                        struct request_queue_container **req_queue_container);

int glue_cap_lookup_blk_dev_ops_type(struct glue_cspace *cspace,
		 	cptr_t c,
			struct block_device_operations_container **blo_container);

void glue_cap_remove(struct glue_cspace *cspace, cptr_t c);


/* ASYNC HELPERS -------------------------------------------------- */

static inline
int
async_msg_get_fn_type(struct fipc_message *msg)
{
        return fipc_get_flags(msg) >> THC_RESERVED_MSG_FLAG_BITS;
}

static inline
void
async_msg_set_fn_type(struct fipc_message *msg, int type)
{
        uint32_t flags = fipc_get_flags(msg);
        /* ensure type is in range */
        type &= (1 << (32 - THC_RESERVED_MSG_FLAG_BITS)) - 1;
        /* erase old type */
        flags &= ((1 << THC_RESERVED_MSG_FLAG_BITS) - 1);
        /* install new type */
        flags |= (type << THC_RESERVED_MSG_FLAG_BITS);
        fipc_set_flags(msg, flags);
}

static inline
int
async_msg_blocking_send_start(struct thc_channel *chnl,
                        struct fipc_message **out)
{
        int ret;
        for (;;) {
                /* Poll until we get a free slot or error */
                ret = fipc_send_msg_start(thc_channel_to_fipc(chnl), out);
                if (!ret || ret != -EWOULDBLOCK)
                        return ret;
                //cpu_relax();
                if (kthread_should_stop())
                        return -EIO;
        }
}
struct ring_stats {
	unsigned long num_available;
	unsigned long num_sent;
	unsigned long num_other;
};

static inline void collect_msg_statuses(struct ring_stats *stats, unsigned long num_slots,
				unsigned long slot,
				struct fipc_message *buffer)
{
	int i;
	for (i = 0; i < num_slots; i++) {
		switch(buffer[(slot + i) % num_slots].msg_status) {
		case FIPC_MSG_STATUS_AVAILABLE:
			stats->num_available++;
			break;
		case FIPC_MSG_STATUS_SENT:
			stats->num_sent++;
			break;
		default:
			stats->num_other++;
			break;
		}
	}
}

static inline void dump_ring_stats(struct thc_channel *chnl)
{
	struct fipc_ring_channel *rc = thc_channel_to_fipc(chnl);
	unsigned long tx_slot = rc->tx.slot;
	unsigned long rx_slot = rc->rx.slot;
	unsigned long num_tx_slots = rc->tx.order_two_mask;
	unsigned long num_rx_slots = rc->rx.order_two_mask;
	struct ring_stats tx_stats = {0}, rx_stats = {0};

	collect_msg_statuses(&tx_stats, num_tx_slots, tx_slot, rc->tx.buffer);
	collect_msg_statuses(&rx_stats, num_rx_slots, tx_slot, rc->rx.buffer);

	printk("========== ring buf stats (Tx) ===========\n");
	printk("[Tx] [%s:%d] Buffer: %p tx_slot: %lu num_slots: %lu\n",
				current->comm, current->pid, rc->tx.buffer, tx_slot,
				num_tx_slots);

	printk("[Tx] current_slot:%lu status: %x\n", tx_slot, rc->tx.buffer[tx_slot].msg_status);

	printk("[Tx] num_available: %lu num_sent: %lu num_other: %lu\n",
				tx_stats.num_available, tx_stats.num_sent, tx_stats.num_other);
	printk("========== ring buf stats (Rx) ===========\n");
	printk("[Rx] [%s:%d] Buffer: %p tx_slot: %lu num_slots: %lu\n",
				current->comm, current->pid, rc->rx.buffer, rx_slot,
				num_rx_slots);

	printk("[Rx] current_slot:%lu status: %x\n", rx_slot, rc->rx.buffer[rx_slot].msg_status);

	printk("[Rx] num_available: %lu num_sent: %lu num_other: %lu\n",
				rx_stats.num_available, rx_stats.num_sent, rx_stats.num_other);
	printk("=====================================\n");

}

#define THRESHOLD		(5 * 1000)	/* 5 seconds */
#define fipc_test_pause()    asm volatile ( "pause\n": : :"memory" );
static inline
int
fipc_msg_blocking_send_start(struct thc_channel *chnl,
                        struct fipc_message **out)
{
        int ret;
	int once = 1;
	ktime_t start = ktime_get();
        for (;;) {
                /* Poll until we get a free slot or error */
                ret = fipc_send_msg_start(thc_channel_to_fipc(chnl), out);
                if (!ret || ret != -EWOULDBLOCK)
                        return ret;
		fipc_test_pause();
		if (ktime_to_ms(ktime_sub(ktime_get(), start)) >= THRESHOLD) {
			if (once) {
				once = 0;
				dump_ring_stats(chnl);
				printk("%s, could not get a slot for more than %d seconds!\n",
						__func__, THRESHOLD / 1000);
			}
		}
        }
}

static inline int 
fipc_msg_blocking_recv_start(struct thc_channel *chnl, 
		struct fipc_message **response)
{
	int ret;
	int once = 1;
	ktime_t start = ktime_get();

retry:
	ret = fipc_recv_msg_start(thc_channel_to_fipc(chnl), response);
	if (ret == 0) {
		/*
		 * Message for us; remove request_cookie from awe mapper
		 */
		return 0;
	} else if (ret == -EWOULDBLOCK) {
		/*
		 * No messages in rx buffer; go to sleep.
		 */
		//cpu_relax();
		fipc_test_pause();
		if (ktime_to_ms(ktime_sub(ktime_get(), start)) >= THRESHOLD) {
			if (once) {
				once = 0;
				dump_ring_stats(chnl);
				printk("%s, could not get a slot for more than %d seconds!\n",
						__func__, THRESHOLD / 1000);
			}
		}

		goto retry;
	} else {
		/*
		 * Error
		 */
		printk(KERN_ERR "thc_ipc_recv_response: fipc returned %d\n",
				ret);
		return ret;
	}
}
#endif /* _GLUE_HELPER_H_ */
