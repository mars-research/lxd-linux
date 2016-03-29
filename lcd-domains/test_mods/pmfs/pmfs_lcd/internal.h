/*
 * internal.h - some internal defs for glue code, etc.
 */
#ifndef PMFS_LCD_INTERNAL_H
#define PMFS_LCD_INTERNAL_H

#include "../pmfs_example_defs.h"

/* MACROS/FLAGS -------------------------------------------------- */

/* Channel flags */
#define PMFS_CHANNEL_TYPE 1

/* FUNCTIONS -------------------------------------------------- */

int dispatch_fs_channel(struct lcd_sync_channel_group_item *chnl);

int glue_vfs_init(cptr_t _vfs_channel, struct lcd_sync_channel_group *group);

void glue_vfs_exit(void);

int super_block_alloc_inode_callee(void);

int super_block_destroy_inode_callee(void);

int super_block_evict_inode_callee(void);

int mount_nodev_fill_super_callee(void);

int file_system_type_mount_callee(void);

#endif /* PMFS_LCD_INTERNAL_H */
