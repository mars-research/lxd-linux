/*
 * dispatch.c
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include "../internal.h"

#include <lcd_config/post_hook.h>


int dispatch_fs_channel(struct lcd_sync_channel_group_item *chnl)
{
	switch (lcd_r0()) {
	case SUPER_BLOCK_ALLOC_INODE:
		return super_block_alloc_inode_callee();
	case SUPER_BLOCK_DESTROY_INODE:
		return super_block_destroy_inode_callee();
	case SUPER_BLOCK_EVICT_INODE:
		return super_block_evict_inode_callee();
	case SUPER_BLOCK_PUT_SUPER:
		return super_block_put_super_callee();
	case MOUNT_NODEV_FILL_SUPER:
		return mount_nodev_fill_super_callee();
	case FILE_SYSTEM_TYPE_MOUNT:
		return file_system_type_mount_callee();
	default:
		LIBLCD_ERR("unexpected function tag %d", lcd_r0());
		return -EINVAL;
	}
}
