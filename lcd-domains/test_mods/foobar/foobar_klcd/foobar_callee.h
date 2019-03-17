#ifndef __FOOBAR_CALLEE_H__
#define __FOOBAR_CALLEE_H__

#include "../glue_helper.h"
enum dispatch_t {
	REGISTER_FOOBAR,
	UNREGISTER_FOOBAR,
	ALLOC_FOOBARDEV,
	FREE_FOOBARDEV,
	FREE_FOOBARDEV,
	INIT,
	UNINIT,

};
int register_foobar_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int unregister_foobar_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int alloc_foobardev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int free_foobardev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int free_foobardev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
void dispatch_sync_loop(void);
int dispatch_async_loop(struct thc_channel *_channel,
		struct fipc_message *message,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int glue_foobar_init(void);
void glue_foobar_exit(void);
