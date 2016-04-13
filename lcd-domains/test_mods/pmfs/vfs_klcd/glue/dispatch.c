/*
 * dispatch.c
 *
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/liblcd.h>
#include "../internal.h"

#include <lcd_config/post_hook.h>

int dispatch_sync_vfs_channel(void)
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

#define trace(x) PMFS_EX_DEBUG(LIBLCD_MSG("vfs got " #x " msg"))

int dispatch_async_vfs_channel(struct thc_channel *channel, 
			struct fipc_message *message,
			struct glue_cspace *cspace,
			cptr_t sync_endpoint)
{
	int fn_type = async_msg_get_fn_type(message);
	switch (fn_type) {

	case UNREGISTER_FILESYSTEM:
		trace(UNREGISTER_FILESYSTEM);
		return unregister_filesystem_callee(message, channel, cspace,
						sync_endpoint);
		break;

	case BDI_INIT:
		trace(BDI_INIT);
		return bdi_init_callee(message, channel, cspace,
				sync_endpoint);
		break;

	case BDI_DESTROY:
		trace(BDI_DESTROY);
		return bdi_destroy_callee(message, channel, cspace,
					sync_endpoint);
		break;

	case IGET_LOCKED:
		trace(IGET_LOCKED);
		return iget_locked_callee(message, channel, cspace,
					sync_endpoint);
		break;

	case TRUNCATE_INODE_PAGES:
		trace(TRUNCATE_INODE_PAGES);
		return truncate_inode_pages_callee(message, channel, cspace,
						sync_endpoint);
		break;

	case CLEAR_INODE:
		trace(CLEAR_INODE);
		return clear_inode_callee(message, channel, cspace,
					sync_endpoint);
		break;
		
	case IGET_FAILED:
		trace(IGET_FAILED);
		return iget_failed_callee(message, channel, cspace,
					sync_endpoint);
		break;
		
	case UNLOCK_NEW_INODE:
		trace(UNLOCK_NEW_INODE);
		return unlock_new_inode_callee(message, channel, cspace,
					sync_endpoint);
		break;

	case D_MAKE_ROOT:
		trace(D_MAKE_ROOT);
		return d_make_root_callee(message, channel, cspace,
					sync_endpoint);
		break;

	case MOUNT_NODEV:
		trace(MOUNT_NODEV);
		return mount_nodev_callee(message, channel, cspace,
					sync_endpoint);
		break;

	case KILL_ANON_SUPER:
		trace(KILL_ANON_SUPER);
		return kill_anon_super_callee(message, channel, cspace,
					sync_endpoint);
		break;

	default:
		LIBLCD_ERR("unexpected function label %d", fn_type);
		return -EINVAL;
	}

	return 0;
}
