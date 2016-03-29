/*
 * internal.h - some internal common defs for vfs klcd
 */
#ifndef VFS_KLCD_INTERNAL_H
#define VFS_KLCD_INTERNAL_H

#include "../pmfs_example_defs.h"

/* MACROS -------------------------------------------------- */

/* Channel types */
#define VFS_CHANNEL_TYPE 1
#define BDI_CHANNEL_TYPE 2

/* TRAMPOLINE STUFF -------------------------------------------------- */

struct super_block_alloc_inode_hidden_args {
	struct super_block_container *super_block_container;
	struct glue_cspace *cspace;
	cptr_t channel;
	struct lcd_trampoline_handle *t_handle;
};

struct super_block_destroy_inode_hidden_args {
	struct super_block_container *super_block_container;
	struct glue_cspace *cspace;
	cptr_t channel;
	struct lcd_trampoline_handle *t_handle;
};

struct super_block_evict_inode_hidden_args {
	struct super_block_container *super_block_container;
	struct glue_cspace *cspace;
	cptr_t channel;
	struct lcd_trampoline_handle *t_handle;
};

/* FUNCTIONS -------------------------------------------------- */

int dispatch_vfs_channel(struct lcd_sync_channel_group_item *chnl);

int glue_vfs_init(cptr_t, struct lcd_sync_channel_group *);

void glue_vfs_exit(void);

int register_filesystem_callee(void);

int unregister_filesystem_callee(void);

int bdi_init_callee(void);

int bdi_destroy_callee(void);

int iget_locked_callee(void);

int truncate_inode_pages_callee(void);

int clear_inode_callee(void);

int iget_failed_callee(void);

int d_make_root_callee(void);

#endif /* VFS_KLCD_INTERNAL_H */
