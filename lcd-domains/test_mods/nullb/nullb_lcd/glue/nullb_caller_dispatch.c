#include <lcd_config/pre_hook.h>
#include <liblcd/liblcd.h>
#include "../nullb_caller.h"
#include <lcd_config/post_hook.h>

#define trace(x) LIBLCD_MSG("nullb got " #x " msg")

int dispatch_async_loop(struct thc_channel *channel, struct fipc_message *message, struct glue_cspace *cspace, cptr_t sync_ep)
{
	int fn_type;
	fn_type = async_msg_get_fn_type(message);
	switch (fn_type) {
		case QUEUE_RQ_FN:
			trace(QUEUE_RQ_FN);
			return queue_rq_fn_callee(message, channel, cspace, sync_ep);

		case MAP_QUEUE_FN:
			trace(MAP_QUEUE_FN);
			return map_queue_fn_callee(message, channel, cspace, sync_ep);

		case INIT_HCTX_FN:
			trace(INIT_HCTX_FN);
			return init_hctx_fn_callee(message, channel, cspace, sync_ep);

		case SOFTIRQ_DONE_FN:
			trace(SOFTIRQ_DONE_FN);
			return softirq_done_fn_callee(message, channel, cspace, sync_ep);

		case OPEN:
			trace(OPEN);
			return open_callee(message, channel, cspace, sync_ep);

		default:
			LIBLCD_ERR("unexpected function label: %d", fn_type);
			return -EINVAL;

	}
	return 0;

}

