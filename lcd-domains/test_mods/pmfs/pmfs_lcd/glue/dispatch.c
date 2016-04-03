/*
 * dispatch.c
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/liblcd.h>
#include <thc_ipc.h>
#include "../internal.h"

#include <lcd_config/post_hook.h>

int dispatch_fs_channel(struct fipc_ring_channel *channel,
			struct fipc_message *message)
{
	int fn_type = async_msg_get_fn_type(message);
	switch (fn_type) {
	case SUPER_BLOCK_ALLOC_INODE:
		return super_block_alloc_inode_callee(message, channel);
	case SUPER_BLOCK_DESTROY_INODE:
		return super_block_destroy_inode_callee(message, channel);
	case SUPER_BLOCK_EVICT_INODE:
		return super_block_evict_inode_callee(message, channel);
	case SUPER_BLOCK_PUT_SUPER:
		return super_block_put_super_callee(message, channel);
	case MOUNT_NODEV_FILL_SUPER:
		return mount_nodev_fill_super_callee(message, channel);
	case FILE_SYSTEM_TYPE_MOUNT:
		return file_system_type_mount_callee(message, channel);
	case FILE_SYSTEM_TYPE_KILL_SB:
		return file_system_type_kill_sb_callee(message, channel);
	default:
		LIBLCD_ERR("unexpected function tag %d", fn_type);
		return -EINVAL;
	}
}
