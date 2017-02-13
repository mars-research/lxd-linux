#ifndef __NULLB_CALLER_H__
#define __NULLB_CALLER_H__

#include "../glue_helper.h"

void dispatch_sync_loop(void);
int dispatch_async_loop(struct thc_channel *channel, struct fipc_message *message, struct glue_cspace *cspace, cptr_t sync_ep);
int glue_nullb_init(void);
void glue_nullb_exit(void);
int queue_rq_fn_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int map_queue_fn_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int init_hctx_fn_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int softirq_done_fn_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);
int open_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, cptr_t sync_ep);

#endif /* __NULLB_CALLER_H__ */
