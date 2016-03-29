/*
 * pmfs_example_defs.h
 *
 * container defs, etc. for pmfs example
 *
 * (put them all in one place so we don't write the same
 * code twice)
 */
#ifndef PMFS_EXAMPLE_DEFS_H
#define PMFS_EXAMPLE_DEFS_H

#include <linux/fs.h>
#include <linux/backing-dev.h>
#include <linux/module.h>

#include <libcap.h>
#include <liblcd/glue_cspace.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>

/* MACROS/FLAGS -------------------------------------------------- */

/* Function flags */
#define REGISTER_FS 1
#define UNREGISTER_FS 2
#define BDI_INIT 3
#define BDI_DESTROY 4
#define SUPER_BLOCK_ALLOC_INODE 5
#define SUPER_BLOCK_DESTROY_INODE 6
#define IGET_LOCKED 7
#define TRUNCATE_INODE_PAGES 8
#define CLEAR_INODE 9

/* STRUCT DEFS -------------------------------------------------- */

struct file_system_type_container {
	struct file_system_type file_system_type;
	cptr_t my_ref;
	cptr_t their_ref;
	struct lcd_sync_channel_group_item chnl;
};

struct backing_dev_info_container {
	struct backing_dev_info backing_dev_info;
	cptr_t my_ref;
	cptr_t their_ref;
	/* no channel since pmfs doesn't implement function ptrs */
};

struct module_container {
	struct module module;
	cptr_t my_ref;
	cptr_t their_ref;
};

struct super_block_container {
	struct super_block super_block;
	cptr_t my_ref;
	cptr_t their_ref;
};

struct pmfs_inode_vfs_container {
	struct pmfs_inode_vfs pmfs_inode_vfs;
	cptr_t my_ref;
	cptr_t their_ref;
};

/* CSPACES ------------------------------------------------------------ */

int glue_cap_init(void);

int glue_cap_create(struct glue_cspace **cspace);

void glue_cap_destroy(struct glue_cspace *cspace);

void glue_cap_exit(void);

int glue_cap_insert_file_system_type_type(
	struct glue_cspace *cspace, 
	struct file_system_type_container *file_system_type_container,
	cptr_t *c_out);

int glue_cap_insert_backing_dev_info_type(
	struct glue_cspace *cspace, 
	struct backing_dev_info_container *backing_dev_info_container,
	cptr_t *c_out);

int glue_cap_insert_module_type(
	struct glue_cspace *cspace, 
	struct module_container *module_container,
	cptr_t *c_out);

int glue_cap_insert_super_block_type(
	struct glue_cspace *cspace, 
	struct super_block_container *super_block_container,
	cptr_t *c_out);

int glue_cap_insert_pmfs_inode_vfs_type(
	struct glue_cspace *cspace, 
	struct pmfs_vfs_inode_container *pmfs_inode_vfs_container,
	cptr_t *c_out);

int glue_cap_lookup_file_system_type_type(
	struct glue_cspace *cspace, 
	cptr_t c,
	struct file_system_type_container **file_system_type_container);

int glue_cap_lookup_backing_dev_info_type(
	struct glue_cspace *cspace, 
	cptr_t c,
	struct backing_dev_info_container **backing_dev_info_container);

int glue_cap_lookup_module_type(
	struct glue_cspace *cspace, 
	cptr_t c,
	struct module_container **module_container);

int glue_cap_lookup_super_block_type(
	struct glue_cspace *cspace, 
	cptr_t c,
	struct super_block_container **super_block_container);

int glue_cap_lookup_pmfs_inode_vfs_type(
	struct glue_cspace *cspace, 
	cptr_t c,
	struct pmfs_inode_vfs_container **pmfs_inode_vfs_container);

void glue_cap_remove(
	struct glue_cspace *cspace, 
	cptr_t c);

#endif /* PMFS_EXAMPLE_DEFS_H */
