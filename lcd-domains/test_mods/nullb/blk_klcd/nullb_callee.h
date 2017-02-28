#ifndef __NULLB_CALLEE_H__
#define __NULLB_CALLEE_H__

#include "../glue_helper.h"

struct fs_info {
	struct thc_channel *chnl;
	struct glue_cspace *cspace;
	cptr_t sync_endpoint;
	struct list_head list;
};
int glue_blk_init(void);

void glue_blk_exit(void);
void blk_exit(struct thc_channel *channel);
int dispatch_sync_loop (void);

struct fs_info * 
add_fs(struct thc_channel *chnl, struct glue_cspace *cspace,
        cptr_t sync_endpoint);

void remove_fs(struct fs_info *fs);

struct fs_info* get_fsinfo(void);

int dispatch_async_loop(struct thc_channel *chnl,
                        struct fipc_message *msg,
                        struct glue_cspace *cspace,
                        cptr_t sync_endpoint);


int blk_mq_alloc_tag_set_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int blk_mq_init_queue_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int blk_mq_end_request_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int blk_mq_free_tag_set_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int blk_mq_start_request_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int blk_mq_map_queue_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int blk_queue_logical_block_size_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int blk_queue_physical_block_size_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int alloc_disk_node_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int add_disk_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int put_disk_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int del_gendisk_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int disk_node_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
//int register_blkdev_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int register_blkdev_callee(void);
int unregister_blkdev_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int dispatch_async_loop(struct thc_channel *channel, struct fipc_message *message, struct glue_cspace *cspace, cptr_t sync_ep);
int blk_cleanup_queue_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int glue_nullb_init(void);
void glue_nullb_exit(void);

#endif /* __NULLB_CALLEE_H__ */
