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
#include <linux/kthread.h>

#include <libcap.h>
#include <libfipc.h>
#include <thc_ipc.h>
#include <liblcd/glue_cspace.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>

#include "pmfs_lcd/pmfs/pmfs.h"

/* MACROS/FLAGS -------------------------------------------------- */

/* Function flags */
enum {
	REGISTER_FILESYSTEM,
	UNREGISTER_FILESYSTEM,
	BDI_INIT,
	BDI_DESTROY,
	SUPER_BLOCK_ALLOC_INODE,
	SUPER_BLOCK_DESTROY_INODE,
	SUPER_BLOCK_EVICT_INODE,
	SUPER_BLOCK_PUT_SUPER,
	IGET_LOCKED,
	IGET_FAILED,
	TRUNCATE_INODE_PAGES,
	CLEAR_INODE,
	UNLOCK_NEW_INODE,
	D_MAKE_ROOT,
	MOUNT_NODEV_FILL_SUPER,
	MOUNT_NODEV,
	FILE_SYSTEM_TYPE_MOUNT,
	FILE_SYSTEM_TYPE_KILL_SB,
	KILL_ANON_SUPER,
};

/* async rpc buffers are 2^PMFS_ASYNC_RPC_BUFFER_ORDER bytes */
#define PMFS_ASYNC_RPC_BUFFER_ORDER 12

/* STRUCT DEFS -------------------------------------------------- */

struct fs_info;
struct file_system_type_container {
	struct file_system_type file_system_type;
	cptr_t my_ref;
	cptr_t their_ref;
	/* We need this on the vfs side: */
	struct fs_info *fs_info;
};

struct backing_dev_info_container {
	struct backing_dev_info backing_dev_info;
	cptr_t my_ref;
	cptr_t their_ref;
};

struct module_container {
	struct module module;
	cptr_t my_ref;
	cptr_t their_ref;
};

/* If you modify this, make sure you modify the def in fs/super.c */
struct super_block_container {
	struct super_block super_block;
	cptr_t my_ref;
	cptr_t their_ref;
	cptr_t fs_memory; /* for convenience */
};

struct pmfs_inode_vfs_container {
	struct pmfs_inode_vfs pmfs_inode_vfs;
	cptr_t my_ref;
	cptr_t their_ref;
};

/* If you modify this, make sure you modify the def in fs/dcache.c */
struct dentry_container {
	struct dentry dentry;
	cptr_t my_ref;
	cptr_t their_ref;
};

struct mount_nodev_fill_super_container {
	int (*fill_super)(struct super_block *, void *, int);
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
	struct pmfs_inode_vfs_container *pmfs_inode_vfs_container,
	cptr_t *c_out);

int glue_cap_insert_dentry_type(
	struct glue_cspace *cspace, 
	struct dentry_container *dentry_container,
	cptr_t *c_out);

int glue_cap_insert_mount_nodev_fill_super_type(
	struct glue_cspace *cspace, 
	struct mount_nodev_fill_super_container *fill_sup_container,
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

int glue_cap_lookup_dentry_type(
	struct glue_cspace *cspace, 
	cptr_t c,
	struct dentry_container **dentry_container);

int glue_cap_lookup_mount_nodev_fill_super_type(
	struct glue_cspace *cspace, 
	cptr_t c,
	struct mount_nodev_fill_super_container **fill_sup_container);

void glue_cap_remove(
	struct glue_cspace *cspace, 
	cptr_t c);

/* ASYNC HELPERS -------------------------------------------------- */

static inline
int
async_msg_get_fn_type(struct fipc_message *msg)
{
	return fipc_get_flags(msg) >> THC_RESERVED_MSG_FLAG_BITS;
}

static inline
void
async_msg_set_fn_type(struct fipc_message *msg, int type)
{
	uint32_t flags = fipc_get_flags(msg);
	/* ensure type is in range */
	type &= (1 << (32 - THC_RESERVED_MSG_FLAG_BITS)) - 1;
	/* erase old type */
	flags &= ((1 << THC_RESERVED_MSG_FLAG_BITS) - 1);
	/* install new type */
	flags |= (type << THC_RESERVED_MSG_FLAG_BITS);
	fipc_set_flags(msg, flags);
}

static inline
int
async_msg_blocking_send_start(struct thc_channel *chnl, 
			struct fipc_message **out)
{
	int ret;
	for (;;) {
		/* Poll until we get a free slot or error */
		ret = fipc_send_msg_start(thc_channel_to_fipc(chnl), out);
		if (!ret || ret != -EWOULDBLOCK)
			return ret;
		cpu_relax();
		if (kthread_should_stop())
			return -EIO;
	}
}

#endif /* PMFS_EXAMPLE_DEFS_H */
