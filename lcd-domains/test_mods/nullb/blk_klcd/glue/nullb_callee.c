#include <lcd_config/pre_hook.h>

#include <libcap.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <liblcd/glue_cspace.h>
#include <liblcd/trampoline.h>
#include "../../glue_helper.h"
#include "../nullb_callee.h"
#include <asm/cacheflush.h>

//#include <linux/blkdev.h>
//#include <linux/blk-mq.h>

#include <lcd_config/post_hook.h>

struct trampoline_hidden_args {
	void *struct_container;
	struct glue_cspace *cspace;
	struct lcd_trampoline_handle *t_handle;
	struct thc_channel *async_chnl;
	cptr_t sync_ep;
};

static struct glue_cspace *c_cspace;
int glue_blk_init(void)
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

void glue_blk_exit(void)
{
	glue_cap_destroy(c_cspace);
	glue_cap_exit();

}


int blk_mq_init_queue_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
	struct fipc_message *response;
	unsigned int request_cookie;
	struct request_queue *rq;
	cptr_t set_ref = __cptr(fipc_get_reg0(request));
	int ret = 0;
	struct blk_mq_tag_set_container *set_container;
        struct request_queue_container *rq_container;

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ret = glue_cap_lookup_blk_mq_tag_set_type(c_cspace, set_ref, &set_container);
        if (ret) {
                LIBLCD_ERR("lookup");
                goto fail_lookup;
        }

	printk("in blk glue - calling the real blk_mq_init \n");

	rq = blk_mq_init_queue(&set_container->blk_mq_tag_set);
	if(!rq) {
		LIBLCD_ERR("blk layer returned bad address!");
		goto fail_blk;
	}

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		goto fail_async;
	}
	
        rq_container = container_of(rq, struct request_queue_container,
                                                request_queue);

	printk("inserting cap of rq_container \n");
	ret = glue_cap_insert_request_queue_type(c_cspace, rq_container, &rq_container->my_ref);
        if (ret) {
                LIBLCD_ERR("lcd insert");
                goto fail_insert;
        }
	rq_container->other_ref.cptr = fipc_get_reg1(request);

	thc_ipc_reply(channel, request_cookie, response);
	fipc_set_reg0(response, rq_container->my_ref.cptr);
	printk("blk klcd done! \n");	
	return ret;

fail_async:
fail_blk:	
fail_lookup:
	glue_cap_remove(c_cspace, rq_container->my_ref);	
fail_insert:
	return ret;	
}

int blk_mq_end_request_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct request *rq;
	int error;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	rq = kzalloc(*sizeof( rq ), GFP_KERNEL);
	if (!rq) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	error = fipc_get_reg2(request);
	blk_mq_end_request(rq, error);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;
}

int blk_mq_free_tag_set_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct blk_mq_tag_set *set;
	struct blk_mq_ops_container *ops_container;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	struct trampoline_hidden_args *queue_rq_hidden_args;
	struct trampoline_hidden_args *map_queue_hidden_args;
	struct trampoline_hidden_args *init_hctx_hidden_args;
	struct trampoline_hidden_args *sirq_done_hidden_args;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long driver_data_offset;
	cptr_t driver_data_cptr;
	gva_t driver_data_gva;
	
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	set = kzalloc(*sizeof( set ), GFP_KERNEL);
	if (!set) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
		set->ops = kzalloc(*sizeof( set->ops ), GFP_KERNEL);
	if (!set->ops) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	set->nr_hw_queues = fipc_get_reg2(request);
	set->queue_depth = fipc_get_reg3(request);
	set->reserved_tags = fipc_get_reg4(request);
	set->cmd_size = fipc_get_reg5(request);
	set->flags = fipc_get_reg6(request);
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
	blk_mq_free_tag_set(set);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;
}

int blk_mq_start_request_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct request *rq;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	rq = kzalloc(*sizeof( rq ), GFP_KERNEL);
	if (!rq) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	blk_mq_start_request(rq);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif 
	return 0;

}

int blk_mq_map_queue_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct request_queue *rq;
	int ctx_index;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	struct blk_mq_hw_ctx *func_ret;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long driver_data_offset;
	cptr_t driver_data_cptr;
	gva_t driver_data_gva;

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	rq = kzalloc(*sizeof( rq ), GFP_KERNEL);
	if (!rq) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	ctx_index = fipc_get_reg2(request);
	func_ret = kzalloc(*sizeof( func_ret ), GFP_KERNEL);
	if (!func_ret) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	func_ret = blk_mq_map_queue(rq, ctx_index);
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

int blk_queue_logical_block_size_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
	unsigned short size;
	struct fipc_message *response;
	unsigned int request_cookie;
	struct request_queue_container *rq_container;
	int ret;
	
	request_cookie = thc_get_request_cookie(request);
	
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	
	size = fipc_get_reg0(request);
	ret = glue_cap_lookup_request_queue_type(c_cspace, __cptr(fipc_get_reg1(request)),
					&rq_container);
	if(ret) {
		 LIBLCD_ERR("lookup");
		 goto fail_lookup;
	}	

	blk_queue_logical_block_size(&rq_container->request_queue, size);
	
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		goto fail_async;
	}
	
	thc_ipc_reply(channel, request_cookie, response);
	return ret;

fail_async:
fail_lookup:
	return ret;
}

int blk_queue_physical_block_size_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
	unsigned int size;
	struct fipc_message *response;
	unsigned int request_cookie;
	struct request_queue_container *rq_container;
	int ret;

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	
	size = fipc_get_reg0(request);
	ret = glue_cap_lookup_request_queue_type(c_cspace, __cptr(fipc_get_reg1(request)),
			&rq_container);
	if(ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	blk_queue_physical_block_size(&rq_container->request_queue, size);
	
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		goto fail_async;
	}
	thc_ipc_reply(channel, request_cookie, response);
	
	return ret;

fail_async:
fail_lookup:
	return ret;
}

int add_disk_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct gendisk_container *disk_container;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int err;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long private_data_offset;
	cptr_t private_data_cptr;
	gva_t private_data_gva;

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	disk_container = kzalloc(sizeof( struct gendisk_container   ), GFP_KERNEL);
	if (!disk_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	err = glue_cap_insert_gendisk_type(c_cspace, disk_container, &disk_container->my_ref);
	if (!err) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	disk_container->other_ref.cptr = fipc_get_reg4(response);
	disk->flags = fipc_get_reg1(request);
	disk->major = fipc_get_reg2(request);
	disk->first_minor = fipc_get_reg3(request);
	sync_ret = lcd_cptr_alloc(&private_data_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		lcd_exit(-1);
	}
	lcd_set_cr0(private_data_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		lcd_exit(-1);
	}
	mem_order = lcd_r0();
	private_data_offset = lcd_r1();
	sync_ret = lcd_map_virt(private_data_cptr, mem_order, &private_data_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *private_data");
		lcd_exit(-1);
	}
	add_disk(( &disk_container->gendisk ));
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(response, disk_container->other_ref.cptr);
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;
}

int put_disk_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct gendisk *disk;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long private_data_offset;
	cptr_t private_data_cptr;
	gva_t private_data_gva;

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	disk = kzalloc(*sizeof( disk ), GFP_KERNEL);
	if (!disk) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	disk->flags = fipc_get_reg2(request);
	disk->major = fipc_get_reg3(request);
	disk->first_minor = fipc_get_reg4(request);
	sync_ret = lcd_cptr_alloc(&private_data_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		lcd_exit(-1);
	}
	lcd_set_cr0(private_data_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		lcd_exit(-1);
	}
	mem_order = lcd_r0();
	private_data_offset = lcd_r1();
	sync_ret = lcd_map_virt(private_data_cptr, mem_order, &private_data_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *private_data");
		lcd_exit(-1);
	}
	put_disk(disk);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;
}

int del_gendisk_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	struct gendisk *gp;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long private_data_offset;
	cptr_t private_data_cptr;
	gva_t private_data_gva;

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	gp = kzalloc(*sizeof( gp ), GFP_KERNEL);
	if (!gp) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	gp->flags = fipc_get_reg2(request);
	gp->major = fipc_get_reg3(request);
	gp->first_minor = fipc_get_reg4(request);
	sync_ret = lcd_cptr_alloc(&private_data_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		lcd_exit(-1);
	}
	lcd_set_cr0(private_data_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		lcd_exit(-1);
	}
	mem_order = lcd_r0();
	private_data_offset = lcd_r1();
	sync_ret = lcd_map_virt(private_data_cptr, mem_order, &private_data_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *private_data");
		lcd_exit(-1);
	}
	del_gendisk(gp);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;
}

int disk_node_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	int minors;
	int node_id;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	struct gendisk *func_ret;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long private_data_offset;
	cptr_t private_data_cptr;
	gva_t private_data_gva;

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	minors = fipc_get_reg1(request);
	node_id = fipc_get_reg2(request);
	func_ret = kzalloc(*sizeof( func_ret ), GFP_KERNEL);
	if (!func_ret) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
		func_ret = disk_node(minors, node_id);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg2(response, func_ret->flags);
	fipc_set_reg3(response, func_ret->major);
	fipc_set_reg4(response, func_ret->first_minor);
	fipc_set_reg3(response, func_ret->private_data);
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif
	return 0;

}
static int setup_async_fs_ring_channel(cptr_t tx, cptr_t rx,
                                struct thc_channel **chnl_out)
{
        gva_t tx_gva, rx_gva;
        int ret;
        struct fipc_ring_channel *fchnl;
        struct thc_channel *chnl;
        unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
        /*
         * Map tx and rx buffers (caller has already prep'd buffers)
         */
        ret = lcd_map_virt(tx, pg_order, &tx_gva);
        if (ret) {
                LIBLCD_ERR("failed to map tx");
                goto fail1;
        }
        ret = lcd_map_virt(rx, pg_order, &rx_gva);
        if (ret) {
                LIBLCD_ERR("failed to map rx");
                goto fail2;
        }
        /*
         * Alloc and init channel header
         */
        fchnl = kmalloc(sizeof(*fchnl), GFP_KERNEL);
        if (!fchnl) {
                ret = -ENOMEM;
                LIBLCD_ERR("malloc failed");
                goto fail3;
        }
        ret = fipc_ring_channel_init(fchnl,
                                PMFS_ASYNC_RPC_BUFFER_ORDER,
                                /* (note: gva == hva for non-isolated) */
                                (void *)gva_val(tx_gva),
                                (void *)gva_val(rx_gva));
        if (ret) {
                LIBLCD_ERR("channel init failed");
                goto fail4;
        }
        /*
         * Add to async channel group
         */
        chnl = kzalloc(sizeof(*chnl), GFP_KERNEL);
        if (!chnl) {
                ret = -ENOMEM;
                LIBLCD_ERR("malloc failed");
                goto fail5;
        }
        ret = thc_channel_init(chnl, fchnl);
        if (ret) {
                LIBLCD_ERR("async group item init failed");
                goto fail6;
        }

        *chnl_out = chnl;
        return 0;

fail6:
        kfree(chnl);
fail5:
fail4:
        kfree(fchnl);
fail3:
        lcd_unmap_virt(rx_gva, pg_order);
fail2:
        lcd_unmap_virt(tx_gva, pg_order);
fail1:
        return ret;
}

static void destroy_async_fs_ring_channel(struct thc_channel *chnl)
{
        cptr_t tx, rx;
        gva_t tx_gva, rx_gva;
        unsigned long unused1, unused2;
        int ret;
        unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
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
         * Free the thc channel
         *
         * XXX: We are assuming this is called *from the dispatch loop*
         * (i.e., as part of handling a callee function), so no one
         * else (no other awe) is going to try to use the channel
         * after we kill it. (For the PMFS LCD, this is not possible,
         * because the unregister happens from a *caller context*.)
         */
        kfree(chnl);

        return;

fail2:
fail1:
        return;
}

int register_blkdev_callee(void)
{
        cptr_t tx, rx;
        struct thc_channel *chnl;
        cptr_t sync_endpoint;
        int ret;
        int major;
        struct fs_info *fs_info;

        sync_endpoint = lcd_cr0();
        tx = lcd_cr1(); rx = lcd_cr2();

        /*
         * Set up async ring channel
         */
        ret = setup_async_fs_ring_channel(tx, rx, &chnl);
        if (ret) {
                LIBLCD_ERR("error setting up ring channel");
                goto fail1;
        }
	
        /*
         * Add to dispatch loop
         */
        fs_info = add_fs(chnl, c_cspace, sync_endpoint);
        if (!fs_info) {
                LIBLCD_ERR("error adding to dispatch loop");
                goto fail2;
        }
	
	/* Hardcoded string for now! */
	LIBLCD_MSG("Calling register_blkdev");
	ret = register_blkdev(lcd_r1(), "nullb");
	LIBLCD_MSG("register_blkdev returns %d", ret);
	if(ret < 0) {
		LIBLCD_ERR("Real call to register_blkdev failed!");
		goto fail3;
	} else {
		/* register_blkdev can return the major number of the device,
		 * which can be a large +ve number but the ret value passed
		 * above if found +ve is treated as an error */
		major = ret;
		ret = 0;
	}

	goto out;

fail3:
	remove_fs(fs_info);
fail2:
	destroy_async_fs_ring_channel(chnl);
	//TODO AB - I see a kfree(chnl) in pmfs right after this call,
	//but chnl is already freed inside this function?
fail1:
	
out:
        /*
         * Flush capability registers
         */
        lcd_set_cr0(CAP_CPTR_NULL);
        lcd_set_cr1(CAP_CPTR_NULL);
        lcd_set_cr2(CAP_CPTR_NULL);

        lcd_set_r0(major);

        if (lcd_sync_reply())
                LIBLCD_ERR("double fault?");
        return ret; 
	
}

int unregister_blkdev_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
#if 0
	unsigned 	int devno;
	char *name;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	name = kzalloc(sizeof( char   ), GFP_KERNEL);
	if (!name) {
		LIBLCD_ERR("kzalloc");
		lcd_exit(-1);
	}
	devno = fipc_get_reg1(request);
	name = fipc_get_reg2(request);
	unregister_blkdev(devno, name);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
#endif 
	return 0;
}

int _queue_rq_fn(struct blk_mq_hw_ctx *ctx, struct blk_mq_queue_data *bd, struct trampoline_hidden_args *hidden_args)
{
	struct blk_mq_hw_ctx_container *ctx_container;
	void *ctx_driver_data;
	struct blk_mq_queue_data_container *bd_container;
	struct request *bd_rq;
	int ret;
	//int err;
	struct fipc_message *request;
	struct fipc_message *response;
	int func_ret;
	//int sync_ret;
	//unsigned 	long mem_order;
	//unsigned 	long ctx_driver_data_offset;
	//cptr_t ctx_driver_data_cptr;
	//gva_t ctx_driver_data_gva;
	//unsigned long driver_data_mem_sz;
	//unsigned long driver_data_offset;

	ctx_container = kzalloc(sizeof( struct blk_mq_hw_ctx_container   ), GFP_KERNEL);
	if (!ctx_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	/*AB - commented out for compilation. See the first parameter, it should be c_cspace but hidden_args? */
	//err = glue_cap_insert_blk_mq_hw_ctx_type(hidden_args, ctx_container, &ctx_container->my_ref);
	//if (!err) {
	//	LIBLCD_ERR("lcd insert");
	//	goto fail_insert;
	//}
	ctx_container->blk_mq_hw_ctx.driver_data = ctx_driver_data;
	bd_container = kzalloc(sizeof( struct blk_mq_queue_data_container   ), GFP_KERNEL);
	if (!bd_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	//err = glue_cap_insert_blk_mq_queue_data_type(hidden_args, bd_container, &bd_container->my_ref);
	//if (!err) {
	//	LIBLCD_ERR("lcd insert");
	//	goto fail_insert;
	//}
	bd_rq = kzalloc(sizeof(*bd_rq), GFP_KERNEL);
	if (!bd_rq) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	bd_container->blk_mq_queue_data.rq = bd_rq;
	ret = async_msg_blocking_send_start(hidden_args->async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, QUEUE_RQ_FN);
	fipc_set_reg4(request, ctx_container->my_ref.cptr);
	
	/* TODO AB - this is totally absurd! Sick of changing this! */
	//sync_ret = lcd_virt_to_cptr(__gva((unsigned  long)ctx_container->blk_mq_hw_ctx.driver_data), 
	//					&driver_data_cptr, &driver_data_mem_sz, &driver_data_offset);
	//if (sync_ret) {
	//	LIBLCD_ERR("virt to cptr failed");
	//	lcd_exit(-1);
	//}
	/*TODO reg8 wont work! */
	//fipc_set_reg8(request, bd_container->my_ref.cptr);
	ret = thc_ipc_call(hidden_args->async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl), response);
	return func_ret;
fail_async:
fail_alloc:
fail_ipc:
	return func_ret;
}	

LCD_TRAMPOLINE_DATA(queue_rq_fn_trampoline);
int LCD_TRAMPOLINE_LINKAGE(queue_rq_fn_trampoline)
queue_rq_fn_trampoline(struct blk_mq_hw_ctx *ctx, struct blk_mq_queue_data *bd) 
{
	int ( *volatile queue_rq_fn_fp )(struct blk_mq_hw_ctx *, struct blk_mq_queue_data *, struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args, queue_rq_fn_trampoline);
	queue_rq_fn_fp = _queue_rq_fn;
	return queue_rq_fn_fp(ctx, bd, hidden_args);

}



struct blk_mq_hw_ctx *_map_queue_fn(struct request_queue *rq, int m, struct trampoline_hidden_args *hidden_args)
{
	/* In kernel v4.9, this function is no longer registered
	 * in the ops field. Because the kernel itself handles
	 * the map. All the kernel does is to call blk_mq_map_queue.
	 * So instead of going to the LCD, I am going to call
	 * blk_mq_map_queue here! */
	return blk_mq_map_queue(rq, m);
}

LCD_TRAMPOLINE_DATA(map_queue_fn_trampoline);
struct blk_mq_hw_ctx *LCD_TRAMPOLINE_LINKAGE(map_queue_fn_trampoline) map_queue_fn_trampoline(struct request_queue *req_queue, int m)

{
	struct blk_mq_hw_ctx* ( *volatile map_queue_fn_fp )(struct request_queue *, int , struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args, map_queue_fn_trampoline);
	map_queue_fn_fp = _map_queue_fn;
	return map_queue_fn_fp(req_queue, m, hidden_args);

}


int _init_hctx_fn(struct blk_mq_hw_ctx *ctx, void *data, unsigned int index, struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	int func_ret;
	struct blk_mq_hw_ctx_container *ctx_container;
	struct blk_mq_ops_container *ops_container;

	ctx_container = container_of(ctx, struct blk_mq_hw_ctx_container, blk_mq_hw_ctx); 
	ops_container = (struct blk_mq_ops_container *)hidden_args->struct_container;

	ret = glue_cap_insert_blk_mq_hw_ctx_type(c_cspace, ctx_container, &ctx_container->my_ref);
	if (ret) {
		LIBLCD_ERR("klcd insert");
		goto fail_insert;
	}

	ret = async_msg_blocking_send_start(hidden_args->async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	
	async_msg_set_fn_type(request, INIT_HCTX_FN);
	fipc_set_reg0(request, ctx_container->my_ref.cptr);
	fipc_set_reg1(request, index);
	
	/* ops container is passed to call ops.init_hctx in the LCD glue */
	fipc_set_reg2(request, ops_container->other_ref.cptr);

	printk("calling lcd's glue \n");
	ret = thc_ipc_call(hidden_args->async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}

	ctx_container->other_ref.cptr = fipc_get_reg0(response);
	func_ret = fipc_get_reg1(response);
	
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl), response);
	printk("end of init_hctx procedure \n");
	
	return func_ret;
fail_async:
fail_ipc:
fail_insert:
	return func_ret;

}

LCD_TRAMPOLINE_DATA(init_hctx_fn_trampoline);
int LCD_TRAMPOLINE_LINKAGE(init_hctx_fn_trampoline) init_hctx_fn_trampoline(struct blk_mq_hw_ctx *ctx, void *data, unsigned int index)

{
	int ( *volatile init_hctx_fn_fp )(struct blk_mq_hw_ctx *, void *, unsigned int, struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args, init_hctx_fn_trampoline);
	init_hctx_fn_fp = _init_hctx_fn;
	return init_hctx_fn_fp(ctx, data, index, hidden_args);

}

void _softirq_done_fn(struct request *request, struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *async_request;
	struct fipc_message *async_response;
	ret = async_msg_blocking_send_start(hidden_args->async_chnl, &async_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(async_request, SOFTIRQ_DONE_FN);
	ret = thc_ipc_call(hidden_args->async_chnl, async_request, &async_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl), async_response);
	return;
fail_async:
fail_ipc:
	return;

}

LCD_TRAMPOLINE_DATA(softirq_done_fn_trampoline);
void LCD_TRAMPOLINE_LINKAGE(softirq_done_fn_trampoline) softirq_done_fn_trampoline(struct request *request)

{
	void ( *volatile softirq_done_fn_fp )(struct request *, struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args, softirq_done_fn_trampoline);
	softirq_done_fn_fp = _softirq_done_fn;
	return softirq_done_fn_fp(request, hidden_args);

}

int open(struct block_device *device, int mode, struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	int func_ret;
	ret = async_msg_blocking_send_start(hidden_args->async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, OPEN);
	fipc_set_reg2(request, mode);
	ret = thc_ipc_call(hidden_args->async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl), response);
	return func_ret;
fail_async:
fail_ipc:
	return func_ret;

}

LCD_TRAMPOLINE_DATA(open_trampoline);
int LCD_TRAMPOLINE_LINKAGE(open_trampoline) open_trampoline(struct block_device *device, int mode)

{
	int ( *volatile open_fp )(struct block_device *, int , struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args, open_trampoline);
	open_fp = open;
	return open_fp(device, mode, hidden_args);

}

int blk_mq_alloc_tag_set_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep)
{
	struct blk_mq_tag_set_container *set_container;
	struct blk_mq_ops_container *ops_container;
	struct fipc_message *response;
	unsigned	int request_cookie;
	struct trampoline_hidden_args *queue_rq_hidden_args;
	struct trampoline_hidden_args *map_queue_hidden_args;
	struct trampoline_hidden_args *init_hctx_hidden_args;
	struct trampoline_hidden_args *sirq_done_hidden_args;
	int func_ret;
	int err;
	//int sync_ret;
	//unsigned 	long mem_order;
	//unsigned 	long driver_data_offset;
	//cptr_t driver_data_cptr;
	//gva_t driver_data_gva;

	request_cookie = thc_get_request_cookie(request);

	/* This marks the message as received so sender sees a free slot! */
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/* Allocate tag_set_container struct here */
	set_container = kzalloc(sizeof(struct blk_mq_tag_set_container), GFP_KERNEL);
	if (!set_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc1;
	}
	err = glue_cap_insert_blk_mq_tag_set_type(c_cspace, set_container, &set_container->my_ref);
	if (err) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert1;
	}
	
	/* Store the caller's reference! */
	set_container->other_ref.cptr = fipc_get_reg0(request);
	printk("set_other_ref %ld \n",set_container->other_ref.cptr);

	/* Allocate ops_container */
	ops_container = kzalloc(sizeof(struct blk_mq_ops_container), GFP_KERNEL);
	if (!set_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc2;
	}
	err = glue_cap_insert_blk_mq_ops_type(c_cspace, ops_container, &ops_container->my_ref);
	if (err) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert2;
	}
	ops_container->other_ref.cptr = fipc_get_reg6(request);
	printk("ops_other_ref %ld \n",ops_container->other_ref.cptr);
	
	/* This is required because, the blk_mq_tag_set which is passed to blk layer is this one */
	set_container->blk_mq_tag_set.ops = &ops_container->blk_mq_ops;

	/* Setup function pointers and trampolines - TODO better to move this to a separate fn */
	queue_rq_hidden_args = kzalloc(sizeof(*queue_rq_hidden_args), GFP_KERNEL);
	if (!queue_rq_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc3;
	}
	queue_rq_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(queue_rq_fn_trampoline);
	if (!queue_rq_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup1;
	}
	queue_rq_hidden_args->t_handle->hidden_args = queue_rq_hidden_args;
	queue_rq_hidden_args->struct_container = ops_container;
	queue_rq_hidden_args->cspace = c_cspace;
	queue_rq_hidden_args->async_chnl = channel;
	ops_container->blk_mq_ops.queue_rq = LCD_HANDLE_TO_TRAMPOLINE(queue_rq_hidden_args->t_handle);

        err = set_memory_x(((unsigned long)queue_rq_hidden_args->t_handle) & PAGE_MASK,
                        ALIGN(LCD_TRAMPOLINE_SIZE(queue_rq_fn_trampoline),
                                PAGE_SIZE) >> PAGE_SHIFT);
        if (err) {
                LIBLCD_ERR("set mem nx");
                goto fail_x1;
        }
	
	map_queue_hidden_args = kzalloc(sizeof( *map_queue_hidden_args ), GFP_KERNEL);
	if (!map_queue_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc4;
	}
	map_queue_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(map_queue_fn_trampoline);
	if (!map_queue_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup2;
	}
	map_queue_hidden_args->t_handle->hidden_args = map_queue_hidden_args;
	map_queue_hidden_args->struct_container = ops_container;
	map_queue_hidden_args->cspace = c_cspace;
	map_queue_hidden_args->async_chnl = channel;
	ops_container->blk_mq_ops.map_queue = LCD_HANDLE_TO_TRAMPOLINE(map_queue_hidden_args->t_handle);

        err = set_memory_x(((unsigned long)map_queue_hidden_args->t_handle) & PAGE_MASK,
                        ALIGN(LCD_TRAMPOLINE_SIZE(map_queue_fn_trampoline),
                                PAGE_SIZE) >> PAGE_SHIFT);
        if (err) {
                LIBLCD_ERR("set mem nx");
                goto fail_x2;
        }

	init_hctx_hidden_args = kzalloc(sizeof( *init_hctx_hidden_args ), GFP_KERNEL);
	if (!init_hctx_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc5;
	}
	init_hctx_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(init_hctx_fn_trampoline);
	if (!init_hctx_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup3;
	}
	init_hctx_hidden_args->t_handle->hidden_args = init_hctx_hidden_args;
	init_hctx_hidden_args->struct_container = ops_container;
	init_hctx_hidden_args->cspace = c_cspace;
	init_hctx_hidden_args->async_chnl = channel;
	ops_container->blk_mq_ops.init_hctx = LCD_HANDLE_TO_TRAMPOLINE(init_hctx_hidden_args->t_handle);

        err = set_memory_x(((unsigned long)init_hctx_hidden_args->t_handle) & PAGE_MASK,
                        ALIGN(LCD_TRAMPOLINE_SIZE(init_hctx_fn_trampoline),
                                PAGE_SIZE) >> PAGE_SHIFT);
        if (err) {
                LIBLCD_ERR("set mem nx");
                goto fail_x3;
        }

	sirq_done_hidden_args = kzalloc(sizeof( *sirq_done_hidden_args ), GFP_KERNEL);
	if (!sirq_done_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc6;
	}
	sirq_done_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(softirq_done_fn_trampoline);
	if (!sirq_done_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup4;
	}
	sirq_done_hidden_args->t_handle->hidden_args = sirq_done_hidden_args;
	sirq_done_hidden_args->struct_container = ops_container;
	sirq_done_hidden_args->cspace = c_cspace;
	sirq_done_hidden_args->async_chnl = channel;
	ops_container->blk_mq_ops.complete = LCD_HANDLE_TO_TRAMPOLINE(sirq_done_hidden_args->t_handle);

        err = set_memory_x(((unsigned long)sirq_done_hidden_args->t_handle) & PAGE_MASK,
                        ALIGN(LCD_TRAMPOLINE_SIZE(softirq_done_fn_trampoline),
                                PAGE_SIZE) >> PAGE_SHIFT);
        if (err) {
                LIBLCD_ERR("set mem nx");
                goto fail_x4;
        }

	/* Get the rest of the members from LCD */
	set_container->blk_mq_tag_set.nr_hw_queues = fipc_get_reg1(request);
	set_container->blk_mq_tag_set.queue_depth = fipc_get_reg2(request);
	set_container->blk_mq_tag_set.reserved_tags = fipc_get_reg3(request);
	set_container->blk_mq_tag_set.cmd_size = fipc_get_reg4(request);
	set_container->blk_mq_tag_set.flags = fipc_get_reg5(request);
	//sync_ret = lcd_cptr_alloc(&driver_data_cptr);
	//if (sync_ret) {
	//	LIBLCD_ERR("failed to get cptr");
	//	lcd_exit(-1);
	//}
	//lcd_set_cr0(driver_data_cptr);
	//sync_ret = lcd_sync_recv(sync_ep);
	//lcd_set_cr0(CAP_CPTR_NULL);
	//if (sync_ret) {
	//	LIBLCD_ERR("failed to recv");
	//	lcd_exit(-1);
	//}
	//mem_order = lcd_r0();
	//driver_data_offset = lcd_r1();
	//sync_ret = lcd_map_virt(driver_data_cptr, mem_order, &driver_data_gva);
	//if (sync_ret) {
	//	LIBLCD_ERR("failed to map void *driver_data");
	//	lcd_exit(-1);
	//}
	/* call the real function */
	func_ret = blk_mq_alloc_tag_set((&set_container->blk_mq_tag_set));
	printk("*****block_alloc_tag set returns %d \n",func_ret);
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		goto fail_recv;
	}
	fipc_set_reg0(response, set_container->my_ref.cptr);
	fipc_set_reg1(response, ops_container->my_ref.cptr);
	fipc_set_reg3(response, func_ret);
	thc_ipc_reply(channel, request_cookie, response);
	return func_ret;

fail_recv:
	kfree(sirq_done_hidden_args->t_handle);
fail_x4:
fail_dup4:
	kfree(sirq_done_hidden_args);
fail_alloc6:
	kfree(init_hctx_hidden_args->t_handle);
fail_x3:
fail_dup3:
	kfree(init_hctx_hidden_args);
fail_alloc5:
	kfree(map_queue_hidden_args->t_handle);
fail_x2:
fail_dup2:
	kfree(map_queue_hidden_args);
fail_alloc4:
	kfree(queue_rq_hidden_args->t_handle);
fail_x1:
fail_dup1:
	kfree(queue_rq_hidden_args);
fail_alloc3:
	glue_cap_remove(c_cspace, ops_container->my_ref);
fail_insert2:
	kfree(ops_container);
fail_alloc2:
	glue_cap_remove(c_cspace, set_container->my_ref);
fail_insert1:
	kfree(set_container);
fail_alloc1:
	return func_ret;

}
