/*
 * internal.h - some internal common defs for vfs klcd
 */
#ifndef VFS_KLCD_INTERNAL_H
#define VFS_KLCD_INTERNAL_H

#include "../pmfs_example_defs.h"

/* GLUE SUPPORT FUNCTIONS ---------------------------------------- */

int glue_vfs_init(void);

void glue_vfs_exit(void);

int dispatch_sync_vfs_channel(void);

int dispatch_async_vfs_channel(struct thc_channel *chnl,
			struct fipc_message *msg,
			struct glue_cspace *cspace,
			cptr_t sync_endpoint);

struct fs_info* add_fs(struct thc_channel *chnl, struct glue_cspace *cspace,
		cptr_t sync_endpoint);

struct fs_info;
void remove_fs(struct fs_info *fs);

/* CALLEE FUNCTIONS -------------------------------------------------- */

int register_filesystem_callee(void);

int unregister_filesystem_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *,
				cptr_t);

int bdi_init_callee(struct fipc_message *,
		struct thc_channel *,
		struct glue_cspace *,
		cptr_t);

int bdi_destroy_callee(struct fipc_message *,
		struct thc_channel *,
		struct glue_cspace *,
		cptr_t);

int iget_locked_callee(struct fipc_message *,
		struct thc_channel *,
		struct glue_cspace *,
		cptr_t);

int truncate_inode_pages_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *,
				cptr_t);

int clear_inode_callee(struct fipc_message *,
		struct thc_channel *,
		struct glue_cspace *,
		cptr_t);

int unlock_new_inode_callee(struct fipc_message *,
			struct thc_channel *,
			struct glue_cspace *,
			cptr_t);

int iget_failed_callee(struct fipc_message *,
		struct thc_channel *,
		struct glue_cspace *,
		cptr_t);

int d_make_root_callee(struct fipc_message *,
		struct thc_channel *,
		struct glue_cspace *,
		cptr_t);

int mount_nodev_callee(struct fipc_message *,
		struct thc_channel *,
		struct glue_cspace *,
		cptr_t);

int kill_anon_super_callee(struct fipc_message *,
			struct thc_channel *,
			struct glue_cspace *,
			cptr_t);

/* TRAMPOLINE STUFF -------------------------------------------------- */

struct trampoline_hidden_args {
	void *struct_container;
	struct glue_cspace *fs_cspace;
	cptr_t fs_sync_endpoint;
	struct thc_channel *fs_async_chnl;
	struct lcd_trampoline_handle *t_handle;
};

#endif /* VFS_KLCD_INTERNAL_H */
