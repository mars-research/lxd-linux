#include <lcd_config/pre_hook.h>

//#include <linux/fs.h>

#include <libcap.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <liblcd/glue_cspace.h>

#include "../nullb_caller.h"
#include <lcd_config/post_hook.h>

extern cptr_t blk_sync_endpoint;
extern cptr_t blk_register_chnl;
static struct glue_cspace *c_cspace;
extern struct thc_channel *blk_async_chl;
int glue_nullb_init(void)
{
	int ret;
	ret = glue_cap_init();
	if (ret) {
		LIBLCD_ERR("cap init");
		goto fail1;
	}
	ret = glue_cap_create(&c_cspace);
	if (ret) {
		LIBLCD_ERR("cap create");
		goto fail2;
	}
	return 0;
fail2:
	glue_cap_exit();
fail1:
	return ret;

}

void glue_nullb_exit(void)
{
	glue_cap_destroy(c_cspace);
	glue_cap_exit();

}

static int setup_async_channel(cptr_t *buf1_cptr_out, cptr_t *buf2_cptr_out,
                        struct thc_channel **chnl_out)
{
        int ret;
        cptr_t buf1_cptr, buf2_cptr;
        gva_t buf1_addr, buf2_addr;
        struct fipc_ring_channel *fchnl;
        struct thc_channel *chnl;
        unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
        /*
         * Allocate buffers
         *
         * (We use the lower level alloc. If we used the heap, even though
         * we may alloc only 1 - 2 pages, we would end up sharing around
         * 4 MB chunks of memory, since the heap uses coarse microkernel
         * allocations.)
         */
        ret = _lcd_alloc_pages(GFP_KERNEL, pg_order, &buf1_cptr);
        if (ret) {
                LIBLCD_ERR("buf1 alloc");
                goto fail1;
        }
        ret = _lcd_alloc_pages(GFP_KERNEL, pg_order, &buf2_cptr);
        if (ret) {
                LIBLCD_ERR("buf2 alloc");
                goto fail2;
        }
        /*
         * Map them somewhere
         */
        ret = lcd_map_virt(buf1_cptr, pg_order, &buf1_addr);
        if (ret) {
                LIBLCD_ERR("error mapping buf1");
                goto fail3;
        }
        ret = lcd_map_virt(buf2_cptr, pg_order, &buf2_addr);
        if (ret) {
                LIBLCD_ERR("error mapping buf2");
                goto fail4;
        }
        /*
         * Prep buffers for rpc
         */
        ret = fipc_prep_buffers(PMFS_ASYNC_RPC_BUFFER_ORDER,
                                (void *)gva_val(buf1_addr),
                                (void *)gva_val(buf2_addr));
        if (ret) {
                LIBLCD_ERR("prep buffers");
                goto fail5;
        }
        /*
         * Alloc and init channel header
         */
        fchnl = kmalloc(sizeof(*fchnl), GFP_KERNEL);
        if (!fchnl) {
                ret = -ENOMEM;
                LIBLCD_ERR("chnl alloc");
                goto fail6;
        }
        ret = fipc_ring_channel_init(fchnl, PMFS_ASYNC_RPC_BUFFER_ORDER,
                                (void *)gva_val(buf1_addr),
                                (void *)gva_val(buf2_addr));
        if (ret) {
                LIBLCD_ERR("ring chnl init");
                goto fail7;
        }
        /*
         * Install async channel in async dispatch loop
         */
        chnl = kzalloc(sizeof(*chnl), GFP_KERNEL);
        if (!chnl) {
                ret = -ENOMEM;
                LIBLCD_ERR("alloc failed");
                goto fail8;
        }
        ret = thc_channel_init(chnl, fchnl);
        if (ret) {
                LIBLCD_ERR("error init'ing async channel group item");
                goto fail9;
        }

        *buf1_cptr_out = buf1_cptr;
        *buf2_cptr_out = buf2_cptr;
        *chnl_out = chnl;

        return 0;

fail9:
        kfree(chnl);
fail8:
fail7:
        kfree(fchnl);
fail6:
fail5:
        lcd_unmap_virt(buf1_addr, pg_order);
fail4:
        lcd_unmap_virt(buf1_addr, pg_order);
fail3:
        lcd_cap_delete(buf2_cptr);
fail2:
        lcd_cap_delete(buf1_cptr);
fail1:
        return ret;
}

static void destroy_async_channel(struct thc_channel *chnl)
{
        unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
        gva_t tx_gva, rx_gva;
        cptr_t tx, rx;
        int ret;
        unsigned long unused1, unused2;
        /*
         * Translate ring buffers to cptrs
         */
        tx_gva = __gva((unsigned long)thc_channel_to_fipc(chnl)->tx.buffer);
        rx_gva = __gva((unsigned long)thc_channel_to_fipc(chnl)->rx.buffer);
        ret = lcd_virt_to_cptr(tx_gva, &tx, &unused1, &unused2);
        if (ret) {
                LIBLCD_ERR("failed to translate tx to cptr");
                goto fail1;
        }
        ret = lcd_virt_to_cptr(rx_gva, &rx, &unused1, &unused2);
        if (ret) {
                LIBLCD_ERR("failed to translate rx to cptr");
                goto fail2;
        }
        /*
         * Unmap and kill tx/rx
         */
        lcd_unmap_virt(tx_gva, pg_order);
        lcd_cap_delete(tx);
        lcd_unmap_virt(rx_gva, pg_order);
        lcd_cap_delete(rx);
        /*
         * Free chnl header
         */
        kfree(thc_channel_to_fipc(chnl));
        /*
         * Free the async channel
         *
         * XXX: This is ok to do because there is no dispatch loop
         * polling on the channel when we free it.
         */
        kfree(chnl);

        return;

fail2:
fail1:
        return;
}

int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
	struct blk_mq_tag_set_container *set_container;
	struct blk_mq_ops_container *ops_container;
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	int func_ret;
//	int sync_ret;
//	unsigned	long driver_data_mem_sz;
//	unsigned 	long driver_data_offset;
//	cptr_t driver_data_cptr;

	set_container = container_of(set, struct blk_mq_tag_set_container, blk_mq_tag_set);
	ops_container = container_of(set->ops, struct blk_mq_ops_container, blk_mq_ops);

	ret = glue_cap_insert_blk_mq_ops_type(c_cspace, ops_container, &ops_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert1;
	}
	
	ret = glue_cap_insert_blk_mq_tag_set_type(c_cspace, set_container, &set_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert2;
	}
	
	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, BLK_MQ_ALLOC_TAG_SET);
	fipc_set_reg0(request, set_container->my_ref.cptr);
	fipc_set_reg1(request, set->nr_hw_queues);
	fipc_set_reg2(request, set->queue_depth);
	fipc_set_reg3(request, set->reserved_tags);
	fipc_set_reg4(request, set->cmd_size);
	fipc_set_reg5(request, set->flags);
	fipc_set_reg6(request, ops_container->my_ref.cptr);
	
	//sync_ret = lcd_virt_to_cptr(__gva((unsigned long)driver_data), &driver_data_cptr, &driver_data_mem_sz, &driver_data_offset);
	//if (sync_ret) {
//		LIBLCD_ERR("virt to cptr failed");
//		lcd_exit(-1);
//	}
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	set_container->other_ref.cptr = fipc_get_reg0(response);
	ops_container->other_ref.cptr = fipc_get_reg1(response);
	func_ret = fipc_get_reg3(response);
	printk("LCD received %d from block_al-tg-set \n",func_ret);
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	return func_ret;

fail_insert1:
fail_insert2:
fail_async:
fail_ipc:
	return func_ret;
}

struct request_queue *blk_mq_init_queue(struct blk_mq_tag_set *set)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct blk_mq_tag_set_container *set_container;
	struct request_queue_container *rq_container;

	/* XXX Scary! request_queue size can vary from inside and outside
	 * LCDs? This is a bit fragile! */
	rq_container = kzalloc((sizeof(*rq_container)), GFP_KERNEL);
	if(!rq_container) {
		LIBLCD_ERR("kzalloc failed");
		goto fail_alloc;
	}
	
	ret = glue_cap_insert_request_queue_type(c_cspace, rq_container, &rq_container->my_ref);
        if (ret) {
		LIBLCD_ERR("lcd insert");
                goto fail_insert;
        }
	
	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	
	set_container = container_of(set, struct blk_mq_tag_set_container, blk_mq_tag_set);

	async_msg_set_fn_type(request, BLK_MQ_INIT_QUEUE);
	fipc_set_reg0(request, set_container->other_ref.cptr);
	fipc_set_reg1(request, rq_container->my_ref.cptr);
	
	printk("making IPC call for blk_mq_init \n");
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	
	rq_container->other_ref.cptr = fipc_get_reg0(response);
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);

	printk("blk_mq_init returns local request queue struct!! \n");	
	return &rq_container->request_queue;
fail_ipc:
fail_async:
	glue_cap_remove(c_cspace, rq_container->my_ref);
fail_insert:
	kfree(rq_container);
fail_alloc:
	return NULL;
}

void blk_cleanup_queue(struct request_queue *q)
{
	struct request_queue_container *rq_container;
	struct fipc_message *request;
	struct fipc_message *response;
	int ret;

	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	
	rq_container = container_of(q, struct request_queue_container,
						request_queue);

	async_msg_set_fn_type(request, BLK_CLEANUP_QUEUE);
	fipc_set_reg0(request, rq_container->other_ref.cptr);
	
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
	 	LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	glue_cap_remove(c_cspace, rq_container->my_ref);
	kfree(rq_container);
	return;

fail_ipc:
fail_async:
	return;
}

#if 0
void blk_mq_end_request(struct request *rq, int error)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, BLK_MQ_END_REQUEST);
	fipc_set_reg2(request, error);
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	return;fail_async:

}
#endif

void blk_mq_free_tag_set(struct blk_mq_tag_set *set)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct blk_mq_tag_set_container *set_container;
	struct blk_mq_ops_container *ops_container;

	set_container = container_of(set, struct blk_mq_tag_set_container, 
						blk_mq_tag_set);

	ops_container = container_of(set->ops, struct blk_mq_ops_container, 
						blk_mq_ops); 

	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, BLK_MQ_FREE_TAG_SET);
	
	fipc_set_reg0(request, set_container->other_ref.cptr);
	fipc_set_reg1(request, ops_container->other_ref.cptr);
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	glue_cap_remove(c_cspace, set_container->my_ref);
	glue_cap_remove(c_cspace, ops_container->my_ref);
	return;

fail_ipc:
fail_async:
	return;
}

#if 0
void blk_mq_start_request(struct request *rq)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, BLK_MQ_START_REQUEST);
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	return;fail_async:

}

struct blk_mq_hw_ctx *blk_mq_map_queue(struct request_queue *rq, int ctx_index)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct blk_mq_hw_ctx *func_ret;
	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, BLK_MQ_MAP_QUEUE);
	fipc_set_reg2(request, ctx_index);
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(response);
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	return func_ret;
fail_async:

}
#endif 

void blk_queue_logical_block_size(struct request_queue *rq, unsigned short size)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct request_queue_container *rq_container;

	rq_container = container_of(rq, struct request_queue_container,
					request_queue);
	
	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(request, BLK_QUEUE_LOGICAL_BLOCK_SIZE);
	
	fipc_set_reg0(request, size);
	fipc_set_reg1(request, rq_container->other_ref.cptr);

	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}

	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);

	return;

fail_async:
fail_ipc:
	return;
}

void blk_queue_physical_block_size(struct request_queue *rq, unsigned int size)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct request_queue_container *rq_container;

	rq_container = container_of(rq, struct request_queue_container,
					request_queue);

	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(request, BLK_QUEUE_PHYSICAL_BLOCK_SIZE);

	fipc_set_reg0(request, size);
	fipc_set_reg1(request, rq_container->other_ref.cptr);

	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	
	return;

fail_async:
fail_ipc:
	return;
}

struct gendisk *alloc_disk_node(int minors, int node_id) 
{
	struct gendisk_container *disk_container;
	struct fipc_message *request;
	struct fipc_message *response;	
	int ret;

	disk_container = kzalloc(sizeof(struct gendisk_container), GFP_KERNEL);
	if(!disk_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	
	ret = glue_cap_insert_gendisk_type(c_cspace, disk_container, &disk_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}

	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	
	fipc_set_reg0(request, minors);
	fipc_set_reg1(request, node_id);
	fipc_set_reg2(request, disk_container->my_ref.cptr);

	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}

	disk_container->other_ref.cptr = fipc_get_reg0(response);

	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);

	return &disk_container->gendisk;

fail_ipc:
fail_async:
	glue_cap_remove(c_cspace, disk_container->my_ref);
fail_insert:
	kfree(disk_container);
fail_alloc:
	return NULL;
}

void device_add_disk(struct device *parent, struct gendisk *disk)
{
	struct gendisk_container *disk_container;
	struct block_device_operations_container *blo_container;
	struct module_container *module_container;
	struct request_queue_container *rq_container;
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;

	disk_container = container_of(disk, struct gendisk_container, gendisk);

	blo_container = container_of(disk->fops, 
			struct block_device_operations_container, block_device_operations);

	module_container = container_of(disk->fops->owner, struct module_container,
				module);

	rq_container = container_of(disk->queue, struct request_queue_container,
				request_queue);

	ret = glue_cap_insert_module_type(c_cspace, module_container, &module_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert1;
	}
	
	ret = glue_cap_insert_gendisk_type(c_cspace, disk_container, &disk_container->my_ref);
	if (ret) {
		 LIBLCD_ERR("lcd insert");
		 goto fail_insert2;
	}

	ret = glue_cap_insert_blk_dev_ops_type(c_cspace, blo_container, &blo_container->my_ref);
	if(ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert3;
	}
	
	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(request, ADD_DISK);
	fipc_set_reg0(request, disk_container->other_ref.cptr);
	fipc_set_reg1(request, blo_container->my_ref.cptr);
	fipc_set_reg2(request, module_container->my_ref.cptr);
	fipc_set_reg3(request, rq_container->other_ref.cptr);
	fipc_set_reg4(request, disk->flags);
	fipc_set_reg5(request, disk->major);
	fipc_set_reg6(request, disk->first_minor);

	/* Ran out of registers to marshall the string, so hardcoding it
	 * in the klcd */

	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	
	blo_container->other_ref.cptr = fipc_get_reg0(response);
	module_container->other_ref.cptr = fipc_get_reg0(response);
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	return;
fail_ipc:
fail_async:
fail_insert3:
fail_insert2:
fail_insert1:
	return;
}

void put_disk(struct gendisk *disk)
{
	int ret;
	struct fipc_message *request;
	struct gendisk_container *disk_container;
	struct module_container *module_container;
	struct block_device_operations_container *blo_container;
	struct fipc_message *response;

	disk_container = container_of(disk, struct gendisk_container, gendisk);

	blo_container = container_of(disk->fops,
			struct block_device_operations_container, block_device_operations);

	module_container = container_of(disk->fops->owner, struct module_container,
			 module);

	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, DEL_GENDISK);

	fipc_set_reg0(request, disk_container->other_ref.cptr);
	fipc_set_reg1(request, blo_container->other_ref.cptr);
	fipc_set_reg2(request, module_container->other_ref.cptr);
	
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	
	glue_cap_remove(c_cspace, disk_container->my_ref);
	glue_cap_remove(c_cspace, blo_container->my_ref);
	glue_cap_remove(c_cspace, module_container->my_ref);
	kfree(disk_container);
	return;

fail_async:
fail_ipc:
	return;
}

void del_gendisk(struct gendisk *gp)
{
	int ret;
	struct fipc_message *request;
	struct gendisk_container *disk_container;
	struct fipc_message *response;

	disk_container = container_of(gp, struct gendisk_container, gendisk);

	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, DEL_GENDISK);

	fipc_set_reg0(request, disk_container->other_ref.cptr);
	
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	
	glue_cap_remove(c_cspace, disk_container->my_ref);
	return;

fail_async:
fail_ipc:
	return;
}

int register_blkdev(unsigned int devno, const char *name)
{
	int ret;
        cptr_t tx, rx;
        struct thc_channel *chnl;

        /*
         * Set up async and sync channels
         */
        ret = lcd_create_sync_endpoint(&blk_sync_endpoint);
        if (ret) {
                LIBLCD_ERR("lcd_create_sync_endpoint");
                goto fail1;
        }
        ret = setup_async_channel(&tx, &rx, &chnl);
        if (ret) {
                LIBLCD_ERR("async chnl setup failed");
                goto fail2;
        }

	/*
         * Do rpc, sending:
         *
         *    -- r1: our ref to fs type
         *    -- r2: our ref to module
         *    -- cr0: cap to pmfs_sync_endpoint
         *    -- cr1: cap to buffer for callee to use for tx (this is our rx)
         *    -- cr2: cap to buffer for callee to use for rx (this is our tx)
         */
        lcd_set_r0(REGISTER_BLKDEV);
        lcd_set_r1((u64)devno);
        lcd_set_cr0(blk_sync_endpoint);
        lcd_set_cr1(rx);
        lcd_set_cr2(tx);
	
	/* TODO find a way to marshall the string! 
	 * for this simple case kstrtou64() should work 
	 * but what is it for other direction. Or else
	 * we have to map a page and copy contents onto it */
        //lcd_set_r2((name);

        ret = lcd_sync_call(blk_register_chnl);
        /*
         * Flush cap registers
         */
        lcd_set_cr0(CAP_CPTR_NULL);
        lcd_set_cr1(CAP_CPTR_NULL);
        lcd_set_cr2(CAP_CPTR_NULL);
        if (ret) {
                LIBLCD_ERR("lcd_call");
                goto fail3;
        }
        /*
         * Reply:
         *
         *    -- r0: register_blkdev return value
         */
        ret = lcd_r0();
        if (ret < 0) {
                LIBLCD_ERR("remote register fs failed");
                goto fail4;
        }

        /*
         * Kick off async recv
         */
        blk_async_chl = chnl;
	return ret;
fail4:
fail3:
        destroy_async_channel(chnl);
fail2:
        lcd_cap_delete(blk_sync_endpoint);
fail1:
	return ret;
}

void unregister_blkdev(unsigned int devno, const char *name)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;

	ret = async_msg_blocking_send_start(blk_async_chl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	
	async_msg_set_fn_type(request, UNREGISTER_BLKDEV);
	
	fipc_set_reg0(request, devno);
	//TODO Not marshalling the string for now! hardcoded in klcd
	ret = thc_ipc_call(blk_async_chl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(blk_async_chl), response);
	return;

fail_async:
fail_ipc:
	return;
}

int queue_rq_fn_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct blk_mq_hw_ctx_container *ctx_container;
	struct blk_mq_queue_data_container *bd_container;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	err = glue_cap_lookup_blk_mq_hw_ctx_type(cspace, __cptr(fipc_get_reg4(request)), &ctx_container);
	if (err) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	err = glue_cap_lookup_blk_mq_queue_data_type(cspace, __cptr(fipc_get_reg8(request)), &bd_container);
	if (err) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long driver_data_offset;
	cptr_t driver_data_cptr;
	gva_t driver_data_gva;
	bd_container->blk_mq_queue_data.rq = kzalloc(*sizeof( bd_container->blk_mq_queue_data.rq ), GFP_KERNEL);
	if (!bd_container->blk_mq_queue_data.rq) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	sync_ret = lcd_cptr_alloc(&driver_data_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		lcd_exit(-1);
	}
	lcd_set_cr0(driver_data_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		lcd_exit(-1);
	}
	mem_order = lcd_r0();
	driver_data_offset = lcd_r1();
	sync_ret = lcd_map_virt(driver_data_cptr, mem_order, &driver_data_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *driver_data");
		lcd_exit(-1);
	}
	func_ret = queue_rq_fn(( &ctx_container->blk_mq_hw_ctx ), ( &bd_container->blk_mq_queue_data ));
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(response, func_ret);
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;
}

int map_queue_fn_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct request_queue_container *req_queue_container;
	int m;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	struct blk_mq_hw_ctx *func_ret;
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	err = glue_cap_lookup_request_queue_type(cspace, __cptr(fipc_get_reg4(request)), &req_queue_container);
	if (err) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	m = fipc_get_reg5(request);
	func_ret = kzalloc(*sizeof( func_ret ), GFP_KERNEL);
	if (!func_ret) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long driver_data_offset;
	cptr_t driver_data_cptr;
	gva_t driver_data_gva;
	func_ret = map_queue_fn(( &req_queue_container->request_queue ), m);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg3(response, func_ret->driver_data);
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif 
	return 0;
}

int init_hctx_fn_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{

	struct blk_mq_hw_ctx_container *ctx_container;
	struct blk_mq_ops_container *ops_container;
	unsigned int index;
	struct fipc_message *response;
	unsigned int request_cookie;
	int ret;
	
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ctx_container = kzalloc(sizeof(*ctx_container), GFP_KERNEL);
	if (!ctx_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	
	ret = glue_cap_insert_blk_mq_hw_ctx_type(c_cspace, ctx_container, &ctx_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	
	ctx_container->other_ref.cptr = fipc_get_reg0(response); 
	index = fipc_get_reg1(request);

	ret = glue_cap_lookup_blk_mq_ops_type(c_cspace,
			__cptr(fipc_get_reg2(request)), &ops_container);
        if (ret) {
                LIBLCD_ERR("lookup");
                goto fail_lookup;
        }
	
	/* Passing NULL to data arg, hack to get nullb's address within the driver */
	ret = ops_container->blk_mq_ops.init_hctx(&ctx_container->blk_mq_hw_ctx, NULL, index);
	if(ret) {
	        LIBLCD_ERR("call to init_hctx failed");
                goto fail_hctx;
	}
	
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		goto fail_async;
	}

	fipc_set_reg0(response, ctx_container->my_ref.cptr);
	fipc_set_reg1(response, ret);
	thc_ipc_reply(channel, request_cookie, response);
	return ret;

fail_async:
fail_hctx:
fail_lookup:
	glue_cap_remove(c_cspace, ctx_container->my_ref);
fail_insert:
	kfree(ctx_container);
fail_alloc:
	return ret;
}

int softirq_done_fn_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct request *request;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	request = kzalloc(*sizeof( request ), GFP_KERNEL);
	if (!request) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	softirq_done_fn(request);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;
}

int open_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct block_device *device;
	int mode;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	device = kzalloc(*sizeof( device ), GFP_KERNEL);
	if (!device) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	mode = fipc_get_reg2(request);
	func_ret = open(device, mode);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(response, func_ret);
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;
}
