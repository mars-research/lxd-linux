#include <lcd_config/pre_hook.h>
#include <liblcd/liblcd.h>
#include "../foobar_caller.h"
#include <lcd_config/post_hook.h>

#define trace(x)	LIBLCD_MSG(#x)

int dispatch_async_loop(struct thc_channel *_channel,
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

