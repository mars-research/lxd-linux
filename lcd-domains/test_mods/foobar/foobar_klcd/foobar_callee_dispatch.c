#include <lcd_config/pre_hook.h>
#include <liblcd/liblcd.h>
#include "../foobar_callee.h"
#include <lcd_config/post_hook.h>
int dispatch_async_loop(struct thc_channel *_channel,
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

