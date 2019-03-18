#include "../foobar_caller.h"

__maybe_unused static struct cptr c;
struct glue_cspace *foobar_cspace;
extern struct thc_channel *foobar_async;
extern struct lcd_sync_channel_group *ch_grp;

int dummy_dev_init(struct foobar_device *dev);
void dummy_dev_uninit(struct foobar_device *dev);

int glue_foobar_init(void)
{
	int ret;
	ret = glue_cap_init();
	if (ret) {
		LIBLCD_ERR("cap init");
		goto fail1;
	}
	ret = glue_cap_create(&foobar_cspace);
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

void glue_foobar_exit(void)
{
	glue_cap_destroy(foobar_cspace);
	glue_cap_exit();

}

int register_foobar(struct foobar_device *dev)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	ret = async_msg_blocking_send_start(foobar_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			REGISTER_FOOBAR);
	fipc_set_reg4(_request,
			dev->features);
	fipc_set_reg5(_request,
			dev->hw_features);
	fipc_set_reg6(_request,
			dev->flags);
	ret = thc_ipc_call(foobar_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(foobar_async),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;
}

void unregister_foobar(struct foobar_device *dev)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	ret = async_msg_blocking_send_start(foobar_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			UNREGISTER_FOOBAR);
	ret = thc_ipc_call(foobar_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(foobar_async),
			_response);
	return;
fail_async:
fail_ipc:
	return;
}

struct foobar_device *alloc_foobardev(int id,
		const char *name)
{
	struct foobar_device_container *func_ret_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	struct foobar_device *func_ret = NULL;
	func_ret_container = kzalloc(sizeof( struct foobar_device_container   ),
		GFP_KERNEL);
	if (!func_ret_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	func_ret = &func_ret_container->foobar_device;
	ret = glue_cap_insert_foobar_device_type(foobar_cspace,
		func_ret_container,
		&func_ret_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	ret = async_msg_blocking_send_start(foobar_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			ALLOC_FOOBARDEV);
	fipc_set_reg1(_request,
			id);
//	fipc_set_reg2(_request,
//			name);
	fipc_set_reg4(_request,
			func_ret_container->my_ref.cptr);
//	fipc_set_reg5(_request,
//			func_ret->id);
//	fipc_set_reg6(_request,
//			func_ret->name);
	ret = thc_ipc_call(foobar_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret_container->other_ref.cptr = fipc_get_reg2(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(foobar_async),
			_response);
	return func_ret;
fail_alloc:
fail_insert:
fail_async:
fail_ipc:
	return func_ret;
}

void free_foobardev(struct foobar_device *dev)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	ret = async_msg_blocking_send_start(foobar_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			FREE_FOOBARDEV);
	ret = thc_ipc_call(foobar_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(foobar_async),
			_response);
	return;
fail_async:
fail_ipc:
	return;
}

int init_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct foobar_device *dev;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = kzalloc(sizeof( *dev ),
		GFP_KERNEL);
	if (!dev) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	func_ret = dummy_dev_init(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_alloc:
	return ret;
}

int uninit_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct foobar_device *dev;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = kzalloc(sizeof( *dev ),
		GFP_KERNEL);
	if (!dev) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	dummy_dev_uninit(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_alloc:
	return ret;
}
