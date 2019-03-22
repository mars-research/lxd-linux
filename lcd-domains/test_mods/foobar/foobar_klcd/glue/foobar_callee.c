#include "../foobar_callee.h"
#include <liblcd/trampoline.h>

__maybe_unused static struct cptr c;
static struct glue_cspace *c_cspace;

int glue_foobar_init(void)
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

void glue_foobar_exit(void)
{
	glue_cap_destroy(c_cspace);
	glue_cap_exit();

}

int register_foobar_callee(struct fipc_message *_request,
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
	dev->foobardev_ops = kzalloc(sizeof( *dev->foobardev_ops ),
		GFP_KERNEL);
	if (!dev->foobardev_ops) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	dev->features = fipc_get_reg4(_request);
	dev->hw_features = fipc_get_reg5(_request);
	dev->flags = fipc_get_reg6(_request);
	func_ret = register_foobar(dev);
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

int unregister_foobar_callee(struct fipc_message *_request,
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
	unregister_foobar(dev);
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

int alloc_foobardev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	int id;
	char *name;
	int ret = 0;
	struct fipc_message *_response;
	unsigned int request_cookie;
	struct foobar_device_container *func_ret_container;
	struct foobar_device *func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	name = kzalloc(sizeof( char   ),
		GFP_KERNEL);
	if (!name) {
		LIBLCD_ERR("kzalloc");
		lcd_exit(-1);
	}
	id = fipc_get_reg1(_request);
	//name = fipc_get_reg2(_request);
	func_ret_container->other_ref.cptr = fipc_get_reg4(_request);
	func_ret = alloc_foobardev(id,
		name);
	ret = glue_cap_insert_foobar_device_type(c_cspace,
		func_ret_container,
		&func_ret_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg0(_response,
			func_ret_container->other_ref.cptr);
	fipc_set_reg1(_response,
			func_ret->id);
	//fipc_set_reg6(_response,
	//		func_ret->name);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_alloc:
fail_insert:
	return ret;
}

int free_foobardev_callee(struct fipc_message *_request,
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
	free_foobardev(dev);
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

int init_user(struct foobar_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	thc_init();
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			INIT);
	DO_FINISH({
		ASYNC({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	return func_ret;
}

int init(struct foobar_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret = 0;
	if (!current->ptstate) {
		LIBLCD_MSG("Calling from a non-LCD context! creating thc runtime!");
		LCD_MAIN({
			ret = init_user(dev,
		hidden_args);
		}
		);
		return ret;
	}
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			INIT);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return func_ret;
}

LCD_TRAMPOLINE_DATA(init_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(init_trampoline)
init_trampoline(struct foobar_device *dev)
{
	int ( *volatile init_fp )(struct foobar_device *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			init_trampoline);
	init_fp = init;
	return init_fp(dev,
		hidden_args);

}

void uninit_user(struct foobar_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	thc_init();
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			UNINIT);
	DO_FINISH({
		ASYNC({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return;
fail_async:
fail_ipc:
	return;
}

void uninit(struct foobar_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	if (!current->ptstate) {
		LIBLCD_MSG("Calling from a non-LCD context! creating thc runtime!");
		LCD_MAIN({
			uninit_user(dev,
					hidden_args);
		}
		);
		return;
	}
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			UNINIT);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return;
fail_async:
fail_ipc:
	return;
}

LCD_TRAMPOLINE_DATA(uninit_trampoline);
void  LCD_TRAMPOLINE_LINKAGE(uninit_trampoline)
uninit_trampoline(struct foobar_device *dev)
{
	void ( *volatile uninit_fp )(struct foobar_device *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			uninit_trampoline);
	uninit_fp = uninit;
	return uninit_fp(dev,
		hidden_args);

}

int trigger_exit_to_lcd(struct thc_channel *_channel, enum dispatch_t disp)
{
	struct fipc_message *_request;
	int ret;
	unsigned int request_cookie;

	ret = async_msg_blocking_send_start(_channel,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			disp);

	/* No need to wait for a response here */
	ret = thc_ipc_send_request(_channel,
			_request,
			&request_cookie);

	if (ret) {
		LIBLCD_ERR("thc_ipc send");
		goto fail_ipc;
	}
	awe_mapper_remove_id(request_cookie);
fail_async:
fail_ipc:
	return ret;
}

