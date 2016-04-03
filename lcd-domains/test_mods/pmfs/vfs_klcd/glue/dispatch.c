/*
 * dispatch.c
 *
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/sync_ipc_poll.h>
#include <liblcd/liblcd.h>
#include "../internal.h"

#include <lcd_config/post_hook.h>

int dispatch_sync_vfs_channel(struct lcd_sync_channel_group_item *channel)
{
	int fn_type = lcd_r0();

	switch (fn_type) {

	case REGISTER_FILESYSTEM:
		return register_filesystem_callee();
		break;

	default:
		LIBLCD_ERR("unexpected function label %d", fn_type);
		return -EINVAL;
	}

	return 0;
}

int dispatch_async_vfs_channel(struct fipc_ring_channel *channel, 
			struct fipc_message *message)
{
	int fn_type = async_msg_get_fn_type(message);
	switch (fn_type) {

	case UNREGISTER_FILESYSTEM:
		return unregister_filesystem_callee(message, channel);
		break;

	case BDI_INIT:
		return bdi_init_callee(message, channel);
		break;

	case BDI_DESTROY:
		return bdi_destroy_callee(message, channel);
		break;

	case IGET_LOCKED:
		return iget_locked_callee(message, channel);
		break;

	case TRUNCATE_INODE_PAGES:
		return truncate_inode_pages_callee(message, channel);
		break;

	case CLEAR_INODE:
		return clear_inode_callee(message, channel);
		break;
		
	case IGET_FAILED:
		return iget_failed_callee(message, channel);
		break;
		
	case UNLOCK_NEW_INODE:
		return unlock_new_inode_callee(message, channel);
		break;

	case D_MAKE_ROOT:
		return d_make_root_callee(message, channel);
		break;

	case MOUNT_NODEV:
		return mount_nodev_callee(message, channel);
		break;

	case SUPER_BLOCK_PUT_SUPER:
		return kill_anon_super_callee(message, channel);
		break;

	default:
		LIBLCD_ERR("unexpected function label %d", fn_type);
		return -EINVAL;
	}

	return 0;
}
