/*
 * internal.h - some internal defs for glue code, etc.
 */
#ifndef PMFS_LCD_INTERNAL_H
#define PMFS_LCD_INTERNAL_H

#include "../pmfs_example_defs.h"

/* FUNCTIONS -------------------------------------------------- */

int dispatch_fs_channel(struct fipc_ring_channel *, struct fipc_message *);

int glue_vfs_init(cptr_t _vfs_channel, struct thc_channel_group *group);

void glue_vfs_exit(void);

int super_block_alloc_inode_callee(struct fipc_message *,
				struct fipc_ring_channel *);

int super_block_destroy_inode_callee(struct fipc_message *,
				struct fipc_ring_channel *);

int super_block_evict_inode_callee(struct fipc_message *,
				struct fipc_ring_channel *);

int mount_nodev_fill_super_callee(struct fipc_message *,
				struct fipc_ring_channel *);

int file_system_type_mount_callee(struct fipc_message *,
				struct fipc_ring_channel *);

int super_block_put_super_callee(struct fipc_message *,
				struct fipc_ring_channel *);

int file_system_type_kill_sb_callee(struct fipc_message *,
				struct fipc_ring_channel *);

#endif /* PMFS_LCD_INTERNAL_H */
