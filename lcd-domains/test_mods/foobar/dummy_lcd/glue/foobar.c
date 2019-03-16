#include <lcd_config/pre_hook.h>
#include "../../foobar.h"

#include <libcap.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <liblcd/glue_cspace.h>
#include "../../glue_helper.h"

#include <linux/hashtable.h>
#include "../../rdtsc_helper.h"
#include <lcd_config/post_hook.h>

// -- Foobar caller -- //

static struct cptr c;
static struct glue_cspace *c_cspace;
extern u64 tdiff_disp;
static struct lcd_sync_channel_group *foobar_group;
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

// -- Foobar caller dispatch -- //

int caller_dispatch_async_loop(struct thc_channel *_channel,
		struct fipc_message *message,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	int fn_type;
	fn_type = async_msg_get_fn_type(message);
	switch (fn_type) {
		case INIT:
			trace(INIT);
			return init_callee(message,
		_channel,
		cspace,
		sync_ep);

		case UNINIT:
			trace(UNINIT);
			return uninit_callee(message,
		_channel,
		cspace,
		sync_ep);

		default:
			LIBLCD_ERR("unexpected function label: %d",
					fn_type);
			return -EINVAL;

	}
	return 0;
}

// -- Kernel caller -- //


int register_foobar(struct foobar_device *dev)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	ret = async_msg_blocking_send_start(net_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			REGISTER_FOOBAR);
	fipc_set_reg5(_request,
			dev->features);
	fipc_set_reg6(_request,
			dev->hw_features);
	fipc_set_reg7(_request,
			dev->flags);
	ret = thc_ipc_call(net_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(net_async),
			_response);
	return func_ret;
fail_async:
fail_ipc:

}

void unregister_foobar(struct foobar_device *dev)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	ret = async_msg_blocking_send_start(net_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			UNREGISTER_FOOBAR);
	ret = thc_ipc_call(net_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(net_async),
			_response);
	return;
fail_async:
fail_ipc:

}

struct foobar_device *alloc_foobardev(int id,
		char *name)
{
	struct foobar_device_container *func_ret_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	struct foobar_device *func_ret;
	func_ret_container = kzalloc(sizeof( struct foobar_device_container   ),
		GFP_KERNEL);
	if (!func_ret_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	ret = glue_cap_insert_foobar_device_type(c_cspace,
		func_ret_container,
		&func_ret_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	ret = async_msg_blocking_send_start(net_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			ALLOC_FOOBARDEV);
	fipc_set_reg1(_request,
			id);
	fipc_set_reg2(_request,
			name);
	fipc_set_reg4(_request,
			func_ret_container->my_ref.cptr);
	fipc_set_reg5(_request,
			func_ret->id);
	fipc_set_reg6(_request,
			func_ret->name);
	ret = thc_ipc_call(net_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret_container->other_ref.cptr = fipc_get_reg7(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(net_async),
			_response);
	return func_ret;
fail_async:
fail_ipc:

}

void free_foobardev(struct foobar_device *dev)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	ret = async_msg_blocking_send_start(net_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			FREE_FOOBARDEV);
	ret = thc_ipc_call(net_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(net_async),
			_response);
	return;
fail_async:
fail_ipc:

}

void free_foobardev(struct foobar_device *dev)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	ret = async_msg_blocking_send_start(net_async,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			FREE_FOOBARDEV);
	ret = thc_ipc_call(net_async,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(net_async),
			_response);
	return;
fail_async:
fail_ipc:

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
	func_ret = init(dev);
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
	uninit(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;

}


// -- Foobar callee -- //

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

// -- Foobar callee dispatch -- //


int callee_dispatch_async_loop(struct thc_channel *_channel,
		struct fipc_message *message,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	int fn_type;
	fn_type = async_msg_get_fn_type(message);
	switch (fn_type) {
		case REGISTER_FOOBAR:
			trace(REGISTER_FOOBAR);
			return register_foobar_callee(message,
		_channel,
		cspace,
		sync_ep);

		case UNREGISTER_FOOBAR:
			trace(UNREGISTER_FOOBAR);
			return unregister_foobar_callee(message,
		_channel,
		cspace,
		sync_ep);

		case ALLOC_FOOBARDEV:
			trace(ALLOC_FOOBARDEV);
			return alloc_foobardev_callee(message,
		_channel,
		cspace,
		sync_ep);

		case FREE_FOOBARDEV:
			trace(FREE_FOOBARDEV);
			return free_foobardev_callee(message,
		_channel,
		cspace,
		sync_ep);

		case FREE_FOOBARDEV:
			trace(FREE_FOOBARDEV);
			return free_foobardev_callee(message,
		_channel,
		cspace,
		sync_ep);

		default:
			LIBLCD_ERR("unexpected function label: %d",
					fn_type);
			return -EINVAL;

	}
	return 0;

}

// -- Kernel callee -- //

int glue_kernel_init(void)
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

void glue_kernel_exit(void)
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
	dev->foobar_device_ops = kzalloc(sizeof( *dev->foobar_device_ops ),
		GFP_KERNEL);
	if (!dev->foobar_device_ops) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	dev->features = fipc_get_reg5(_request);
	dev->hw_features = fipc_get_reg6(_request);
	dev->flags = fipc_get_reg7(_request);
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
	return ret;

}

int alloc_foobardev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	int id;
	char *name;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	struct foobar_device_container *func_ret_container;
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
	name = fipc_get_reg2(_request);
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
	fipc_set_reg7(_response,
			func_ret_container->other_ref.cptr);
	fipc_set_reg5(_response,
			func_ret->id);
	fipc_set_reg6(_response,
			func_ret->name);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
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

}

int init(struct foobar_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
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



