/*
 * vfs_caller.c - caller side of vfs interface
 */

#include <lcd_config/pre_hook.h>

#include <linux/fs.h>

#include <libcap.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <liblcd/glue_cspace.h>
#include "../internal.h"

#include <lcd_config/post_hook.h>

/* GLOBALS -------------------------------------------------- */

static cptr_t vfs_chnl;
static struct glue_cspace *vfs_cspace;
static struct lcd_sync_channel_group *group;

/* INIT/EXIT -------------------------------------------------- */

int glue_vfs_init(cptr_t _vfs_channel, struct lcd_sync_channel_group *_group)
{
	int ret;

	/* Store a reference to the dispatch loop context, so we
	 * can dynamically add channels to the loop later. */
	group = _group;

	/* Store reference to vfs channel so we can invoke functions
	 * on it later. */
	vfs_chnl = _vfs_channel;

	/* Initialize cspace system */
	ret = glue_cap_init();
	if (ret) {
		LIBLCD_ERR("cap init");
		return ret;
	}

	/* Initialize glue cspace. */
	ret = glue_cap_create(&vfs_cspace);
	if (ret) {
		LIBLCD_ERR("glue cspace init");
		return ret;
	}

	return 0;
}

void glue_vfs_exit(void)
{
	/*
	 * Free vfs glue cspace and tear down cap system
	 */
	glue_cap_destroy(vfs_cspace);
	glue_cap_exit();
}

/* CALLER FUNCTIONS -------------------------------------------------- */

int register_filesystem(struct file_system_type *fs)
{
	struct file_system_type_container *fs_container;
	struct module_container *module_container;
	int ret;
	cptr_t endpoint;
	/*
	 * Get containers
	 */
	fs_container = container_of(fs, 
				struct file_system_type_container,
				file_system_type);
	module_container = container_of(fs->owner,
					struct module_container,
					module);
	/*
	 * SET UP CHANNEL ----------------------------------------
	 *
	 *
	 * Create the sync endpoint for function calls back to us (pmfs)
	 */
	ret = lcd_create_sync_endpoint(&endpoint);
	if (ret) {
		LIBLCD_ERR("lcd_create_sync_endpoint");
		lcd_exit(ret);
	}
	/*
	 * Install in dispatch loop
	 */
	lcd_sync_channel_group_item_init(&fs_container->chnl, endpoint, 0,
					dispatch_fs_channel);
	lcd_sync_channel_group_add(group, &fs_container->chnl);
	/*
	 * INSERT INTO DATA STORE ------------------------------
	 *
	 */
	ret = glue_cap_insert_file_system_type_type(
		vfs_cspace, 
		fs_container,
		&fs_container->my_ref);
	if (ret) {
		LIBLCD_ERR("insert");
		lcd_exit(ret); /* abort */
	}
	ret = glue_cap_insert_module_type(
		vfs_cspace, 
		module_container,
		&module_container->my_ref);
	if (ret) {
		LIBLCD_ERR("insert");
		lcd_exit(ret); /* abort */
	}

	/*
	 * IPC MARSHALING --------------------------------------------------
	 *
	 */
	lcd_set_r1(cptr_val(fs_container->my_ref));
	lcd_set_r2(cptr_val(module_container->my_ref));
	/*
	 * XXX: We don't even pass the name string (otherwise the callee
	 * needs to keep track of a pesky 5 byte alloc). We just hard
	 * code it on the callee side for now.
	 *
	 * Will grant cap to endpoint
	 */
	lcd_set_cr0(endpoint);
	/*
	 * IPC CALL ----------------------------------------
	 */

	lcd_set_r0(REGISTER_FS);
	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("lcd_call");
		lcd_exit(ret);
	}

	/* IPC UNMARSHALING ---------------------------------------- */

	/*
	 * We expect a remote ref coming back
	 */
	fs_container->their_ref = __cptr(lcd_r1());
	module_container->their_ref = __cptr(lcd_r2());

	/* Clear capability register */
	lcd_set_cr0(CAP_CPTR_NULL);

	/*
	 * Pass back return value
	 */
	return lcd_r0();
}

int unregister_filesystem(struct file_system_type *fs)
{
	int ret;
	struct file_system_type_container *fs_container;
	struct module_container *module_container;

	fs_container = container_of(fs,
				struct file_system_type_container,
				file_system_type);
	module_container = container_of(fs->owner,
					struct module_container,
					module);

	/* IPC MARSHALING ---------------------------------------- */

	/*
	 * Pass remote refs to vfs's copies
	 */
	lcd_set_r1(cptr_val(fs_container->their_ref));
	lcd_set_r2(cptr_val(module_container->their_ref));

	/* IPC CALL ---------------------------------------- */

	lcd_set_r0(UNREGISTER_FS);
	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("lcd_call");
		lcd_exit(ret);
	}

	/* POST-IPC ---------------------------------------- */

	/*
	 * Destroy pmfs channel, remove from dispatch loop
	 */
	lcd_sync_channel_group_remove(group, &fs_container->chnl);

	lcd_cap_delete(fs_container->chnl.channel_cptr);
	/*
	 * Remove fs type and module from data store
	 */
	glue_cap_remove(vfs_cspace, fs_container->my_ref);
	glue_cap_remove(vfs_cspace, module_container->my_ref);
	/*
	 * Pass back return value
	 */
	return lcd_r0();
}

int bdi_init(struct backing_dev_info *bdi)
{
	struct backing_dev_info_container *bdi_container;
	int ret;
	/*
	 * Get container
	 */
	bdi_container = container_of(bdi, 
				struct backing_dev_info_container,
				backing_dev_info);
	/*
	 * INSERT INTO DATA STORE ------------------------------
	 *
	 */
	ret = glue_cap_insert_backing_dev_info_type(
		vfs_cspace, 
		bdi_container,
		&bdi_container->my_ref);
	if (ret) {
		LIBLCD_ERR("insert");
		lcd_exit(ret); /* abort */
	}
	/*
	 * IPC MARSHALING --------------------------------------------------
	 *
	 */
	lcd_set_r1(cptr_val(bdi_container->my_ref));
	lcd_set_r2(bdi_container->backing_dev_info.ra_pages);
	lcd_set_r3(bdi_container->backing_dev_info.capabilities);
	/*
	 * IPC CALL ----------------------------------------
	 */

	lcd_set_r0(BDI_INIT);
	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("lcd_call");
		lcd_exit(ret);
	}

	/* IPC UNMARSHALING ---------------------------------------- */

	/*
	 * We expect a remote ref coming back
	 */
	bdi_container->their_ref = __cptr(lcd_r1());

	/*
	 * Pass back return value
	 */
	return lcd_r0();
}

void bdi_destroy(struct backing_dev_info *bdi)
{
	int ret;
	struct backing_dev_info_container *bdi_container;

	bdi_container = container_of(bdi,
				struct backing_dev_info_container,
				backing_dev_info);

	/* IPC MARSHALING ---------------------------------------- */

	/*
	 * Pass remote ref to bdi's copy
	 */
	lcd_set_r1(cptr_val(bdi_container->their_ref));

	/* IPC CALL ---------------------------------------- */

	lcd_set_r0(BDI_DESTROY);
	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("lcd_call");
		lcd_exit(ret);
	}

	/* POST-IPC ---------------------------------------- */

	/*
	 * Remove bdi from data store
	 */
	glue_cap_remove(vfs_cspace, bdi_container->my_ref);
	/*
	 * (no return value)
	 */
}

struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
	struct super_block_container *sb_container;
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * Marshal arguments and do rpc
	 */
	sb_container = container_of(sb, struct super_block_container,
				super_block);
	lcd_set_r0(IGET_LOCKED);
	lcd_set_r1(sb_container->their_ref);
	lcd_set_r2(ino);

	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("iget locked failed");
		goto fail1;
	}
	/*
	 * Get return values.
	 *
	 * Bind on inode (look up), and unmarshal:
	 *
	 *   -- i_state
	 *   -- i_nlink
	 *   -- i_mode
	 */
	if (cap_cptr_is_null(__cptr(lcd_r0()))) {
		LIBLCD_ERR("got null from iget locked");
		goto fail2;
	}
	ret = glue_cap_lookup_pmfs_inode_vfs_type(vfs_cspace,
						__cptr(lcd_r0()),
						&inode_container);
	if (ret) {
		LIBLCD_ERR("failed to lookup inode");
		goto fail3;
	}
	inode_container->pmfs_inode_vfs.i_state = lcd_r1();
	inode_container->pmfs_inode_vfs.i_nlink = lcd_r2();
	inode_container->pmfs_inode_vfs.i_mode = lcd_r3();
	/*
	 * Done
	 */
	return &inode_container->pmfs_inode_vfs.vfs_inode;

fail3:
	/* It would be nice if we could call iput or something, but we're
	 * sort of sunk since we can't look up our private copy ... */
fail2:
fail1:
	return NULL;
}

void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
	struct address_space_container *a_container;
	int ret;
	/*
	 * Marshal remote reference and lstart, do rpc.
	 */
	a_container = container_of(mapping, struct address_space_container,
				address_space);
	lcd_set_r0(TRUNCATE_INODE_PAGES);
	lcd_set_r1(cptr_val(a_container->their_ref));
	lcd_set_r2(lstart);

	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("truncate inode pages rpc failed");
		goto fail1;
	}
	/*
	 * Nothing else to do
	 */
	goto out;

out:
fail1:
	return;
}

void clear_inode(struct inode *inode)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * Marshal remote ref, and do rpc.
	 */
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	lcd_set_r0(CLEAR_INODE);
	lcd_set_r1(cptr_val(inode_container->their_ref));
	
	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("lcd call failed");
		goto fail1;
	}
	/*
	 * No reply stuff
	 */
	goto out;

out:
fail1:
	return;
}

/* CALLEE FUNCTIONS (FUNCTION POINTERS) ------------------------------ */

int super_block_alloc_inode_callee(void)
{
	struct super_block_container *sb_container;
	struct pmfs_inode_vfs_container *inode_container;
	struct inode *inode;
	cptr_t my_ref = CAP_CPTR_NULL;
	int ret;
	/*
	 * Get our private struct sb
	 */
	ret = glue_cap_lookup_super_block_type(vfs_cspace, __cptr(lcd_r1()),
					&sb_container);
	if (ret) {
		LIBLCD_ERR("error looking up super block");
		goto fail1;
	}
	/*
	 * Invoke the real function
	 */
	inode = sb_container->sb->s_ops->alloc_inode(&sb_container->super_block);
	if (!inode) {
		LIBLCD_ERR("error alloc'ing inode");
		ret = -ENOMEM;
		goto fail2;
	}
	inode_container = container_of(
		container_of(inode, struct pmfs_inode_vfs, vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	inode_container->their_ref = lcd_r2();
	/*
	 * Create a remote reference for the new inode
	 */
	ret = glue_cap_insert_pmfs_inode_vfs_type(vfs_cspace,
						inode_container,
						&my_ref);
	if (ret) {
		LIBLCD_ERR("error creating ref");
		goto fail3;
	}
	inode_container->my_ref = my_ref;
	/*
	 * Respond
	 */
	ret = 0;
	goto reply;

fail3:
	sb_container->sb->s_ops->destroy_inode(inode);
fail2:
fail1:
reply:
	lcd_set_r0(cptr_val(my_ref));
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

int super_block_destroy_inode_callee(void)
{
	struct super_block_container *sb_container;
	struct pmfs_inode_vfs_container *inode_container;
	cptr_t my_ref;
	int ret;
	/*
	 * Get our private struct sb
	 */
	ret = glue_cap_lookup_super_block_type(vfs_cspace, __cptr(lcd_r1()),
					&sb_container);
	if (ret) {
		LIBLCD_ERR("error looking up super block");
		goto fail1;
	}
	/*
	 * Get our private struct inode
	 */
	my_ref = __cptr(lcd_r2());
	ret = glue_cap_lookup_pmfs_inode_vfs_type(vfs_cspace, my_ref,
						&inode_container);
	if (ret) {
		LIBLCD_ERR("error looking up inode");
		goto fail2;
	}
	/*
	 * Invoke the real function
	 */
	sb_container->sb->s_ops->destroy_inode(
		inode_container->inode.vfs_inode);
	/*
	 * Remove our private copy from the cspace
	 */
	glue_cap_remove(vfs_cspace, my_ref);

	ret = 0;
	goto reply;

fail2:
fail1:
reply:
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}
