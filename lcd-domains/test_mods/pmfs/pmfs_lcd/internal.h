/*
 * internal.h - some internal defs for glue code, etc.
 */
#ifndef PMFS_LCD_INTERNAL_H
#define PMFS_LCD_INTERNAL_H

#include "../pmfs_example_defs.h"

/* FUNCTIONS -------------------------------------------------- */

int init_pmfs_fs(void);

void exit_pmfs_fs(void);

int dispatch_fs_channel(struct thc_channel *, struct fipc_message *,
			struct glue_cspace *, cptr_t);

int glue_vfs_init(void);

void glue_vfs_exit(void);

int super_block_alloc_inode_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *, cptr_t);

int super_block_destroy_inode_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *, cptr_t);

int super_block_evict_inode_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *, cptr_t);

int mount_nodev_fill_super_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *, cptr_t);

int file_system_type_mount_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *, cptr_t);

int super_block_put_super_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *, cptr_t);

int file_system_type_kill_sb_callee(struct fipc_message *,
				struct thc_channel *,
				struct glue_cspace *, cptr_t);

#endif /* PMFS_LCD_INTERNAL_H */
