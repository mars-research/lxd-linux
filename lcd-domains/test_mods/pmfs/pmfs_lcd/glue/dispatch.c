/*
 * dispatch.c
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/liblcd.h>
#include <thc_ipc.h>
#include "../internal.h"

#include <lcd_config/post_hook.h>

#define trace(x) PMFS_EX_DEBUG(LIBLCD_MSG("pmfs got " #x " msg"))

int dispatch_fs_channel(struct thc_channel *channel,
			struct fipc_message *message,
			struct glue_cspace *cspace,
			cptr_t sync_endpoint)
{
	int fn_type = async_msg_get_fn_type(message);
	switch (fn_type) {
	case SUPER_BLOCK_ALLOC_INODE:
		trace(SUPER_BLOCK_ALLOC_INODE);
		return super_block_alloc_inode_callee(message, channel,
						cspace, sync_endpoint);
	case SUPER_BLOCK_DESTROY_INODE:
		trace(SUPER_BLOCK_DESTROY_INODE);
		return super_block_destroy_inode_callee(message, channel,
							cspace, sync_endpoint);
	case SUPER_BLOCK_EVICT_INODE:
		trace(SUPER_BLOCK_EVICT_INODE);
		return super_block_evict_inode_callee(message, channel,
						cspace, sync_endpoint);
	case SUPER_BLOCK_PUT_SUPER:
		trace(SUPER_BLOCK_PUT_SUPER);
		return super_block_put_super_callee(message, channel,
						cspace, sync_endpoint);
	case MOUNT_NODEV_FILL_SUPER:
		trace(MOUNT_NODEV_FILL_SUPER);
		return mount_nodev_fill_super_callee(message, channel,
						cspace, sync_endpoint);
	case FILE_SYSTEM_TYPE_MOUNT:
		trace(FILE_SYSTEM_TYPE_MOUNT);
		return file_system_type_mount_callee(message, channel,
						cspace, sync_endpoint);
	case FILE_SYSTEM_TYPE_KILL_SB:
		trace(FILE_SYSTEM_TYPE_KILL_SB);
		return file_system_type_kill_sb_callee(message, channel,
						cspace, sync_endpoint);
	default:
		LIBLCD_ERR("unexpected function tag %d", fn_type);
		return -EINVAL;
	}
}
