#ifndef __FOOBAR_H__
#define __FOOBAR_H__

#include "./glue_helper.h"

// -- Foobar callee -- //

void dispatch_sync_loop(void);
int caller_dispatch_async_loop(struct thc_channel *_channel,
		struct fipc_message *message,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int glue_foobar_init(void);
void glue_foobar_exit(void);

// -- Kernel callee -- //

enum dispatch_t_foobar {
	REGISTER_FOOBAR,
	UNREGISTER_FOOBAR,
	ALLOC_FOOBARDEV,
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
int glue_kernel_init(void);
void glue_kernel_exit(void);

// -- Kernel caller -- //

int callee_dispatch_async_loop(struct thc_channel *_channel,
		struct fipc_message *message,
		struct glue_cspace *cspace,
		struct cptr sync_ep);

int glue_kernel_init(void);
void glue_kernel_exit(void);
int init_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);
int uninit_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);

int ndo_start_xmit_noawe_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);

int ndo_start_xmit_async_bare_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);

int ndo_start_xmit_bare_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep);

#endif 
