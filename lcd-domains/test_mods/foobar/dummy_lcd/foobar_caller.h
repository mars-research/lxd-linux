#ifndef __FOOBAR_CALLER_H__
#define __FOOBAR_CALLER_H__

void dispatch_sync_loop(void);
int dispatch_async_loop(struct thc_channel *_channel,
		struct fipc_message *message,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int glue_foobar_init(void);
void glue_foobar_exit(void);
int init_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int uninit_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
