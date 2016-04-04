/*
 * internal.h - some internal common defs for vfs klcd
 */
#ifndef VFS_KLCD_INTERNAL_H
#define VFS_KLCD_INTERNAL_H

#include "../pmfs_example_defs.h"

/* GLUE SUPPORT FUNCTIONS ---------------------------------------- */

int glue_vfs_init(cptr_t, struct lcd_sync_channel_group *,
		struct thc_channel_group *);

void glue_vfs_exit(struct lcd_sync_channel_group *,
		struct thc_channel_group *);

int dispatch_sync_vfs_channel(struct lcd_sync_channel_group_item *chnl);

int dispatch_async_vfs_channel(struct fipc_ring_channel *chnl,
			struct fipc_message *msg);

/* CALLEE FUNCTIONS -------------------------------------------------- */

int register_filesystem_callee(void);

int unregister_filesystem_callee(struct fipc_message *,
				struct fipc_ring_channel *);

int bdi_init_callee(struct fipc_message *,
		struct fipc_ring_channel *);

int bdi_destroy_callee(struct fipc_message *,
		struct fipc_ring_channel *);

int iget_locked_callee(struct fipc_message *,
		struct fipc_ring_channel *);

int truncate_inode_pages_callee(struct fipc_message *,
				struct fipc_ring_channel *);

int clear_inode_callee(struct fipc_message *,
		struct fipc_ring_channel *);

int unlock_new_inode_callee(struct fipc_message *,
			struct fipc_ring_channel *);

int iget_failed_callee(struct fipc_message *,
		struct fipc_ring_channel *);

int d_make_root_callee(struct fipc_message *,
		struct fipc_ring_channel *);

int mount_nodev_callee(struct fipc_message *,
		struct fipc_ring_channel *);

int kill_anon_super_callee(struct fipc_message *,
			struct fipc_ring_channel *);

/* TRAMPOLINE STUFF -------------------------------------------------- */

struct trampoline_hidden_args {
	void *struct_container;
	struct glue_cspace *fs_cspace;
	cptr_t fs_sync_endpoint;
	struct fipc_ring_channel *fs_async_chnl;
	struct lcd_trampoline_handle *t_handle;
};

#endif /* VFS_KLCD_INTERNAL_H */
