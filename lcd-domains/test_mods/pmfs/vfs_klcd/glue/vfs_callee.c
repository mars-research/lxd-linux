/*
 * vfs_calle.c - callee side glue code of vfs interface
 *
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/sync_ipc_poll.h>
#include <liblcd/liblcd.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include "../internal.h"

#include <lcd_config/post_hook.h>

/* GLOBALS -------------------------------------------------- */

static struct lcd_sync_channel_group *group;
static struct lcd_sync_channel_group_item vfs_channel;
static struct glue_cspace *pmfs_cspace;

/* INIT/EXIT -------------------------------------------------- */

int glue_vfs_init(cptr_t vfs_chnl, struct lcd_sync_channel_group *_group)
{
	int ret;

	/* Set up ipc channel */
	lcd_sync_channel_group_item_init(&vfs_channel, vfs_chnl, 1,
					dispatch_vfs_channel);

	group = _group;

	/* Add it to dispatch loop */
	lcd_sync_channel_group_add(group, &vfs_channel);

	/* Initialize pmfs data store. (This obviously doesn't generalize
	 * well. In general, the data store should be set up upon receiving
	 * a register call?) */
	ret = glue_cap_init();
	if (ret) {
		LIBLCD_ERR("cap init");
		goto fail1;
	}

	ret = glue_cap_create(&pmfs_cspace);
	if (ret) {
		LIBLCD_ERR("create");
		goto fail2;
	}

	return 0;

fail2:
	glue_cap_exit();
fail1:
	return ret;
}

void glue_vfs_exit(void)
{
	/*
	 * Destroy pmfs data stroe
	 */
	glue_cap_destroy(pmfs_cspace);
	/*
	 * Remove vfs channel from loop
	 */
	lcd_sync_channel_group_remove(group, &vfs_channel);

	glue_cap_exit();
}

/* FUNCTION POINTERS ---------------------------------------- */

struct inode* 
noinline
super_block_alloc_inode(struct super_block *super_block,
			struct super_block_container *super_block_container,
			struct glue_cspace *cspace,
			cptr_t channel)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * Create our own private copy and ref
	 */
	inode_container = kzalloc(sizeof(*inode_container), GFP_NOFS);
	if (!inode_container) {
		LIBLCD_ERR("kzalloc inode failed");
		goto fail1;
	}
	ret = glue_cap_insert_pmfs_inode_vfs_type(
		pmfs_cspace,
		inode_container,
		&inode_container->my_ref);
	if (ret) {
		LIBLCD_ERR("cap insert failed");
		goto fail2;
	}
	/*
	 * Invoke remote alloc inode
	 */
	lcd_set_r0(SUPER_BLOCK_ALLOC_INODE);
	lcd_set_r1(cptr_val(super_block_container->their_ref));
	lcd_set_r2(cptr_val(inode_container->my_ref));
	ret = lcd_sync_call(channel);
	if (ret) {
		LIBLCD_ERR("rpc failed");
		goto fail3;
	}
	/*
	 * Get remote ref from callee
	 */
	if (cap_cptr_is_null(__cptr(lcd_r0()))) {
		LIBLCD_ERR("got null from callee");
		goto fail4;
	}
	inode_container->their_ref = __cptr(lcd_r0());
	/*
	 * HACK: Invoke inode_init_once on our private copy
	 */
	inode_init_once(inode_container->pmfs_inode_vfs.vfs_inode);
	/*
	 * Return inode
	 */
	return &inode_container->pmfs_inode.vfs_inode;

fail4:
fail3:
fail2:
	kfree(inode_container);
fail1:
	return NULL;
}

LCD_TRAMPOLINE_DATA(super_block_alloc_inode_trampoline);
struct inode * 
LCD_TRAMPOLINE_LINKAGE(super_block_alloc_inode_trampoline)
super_block_alloc_inode_trampoline(struct super_block *super_block)
{
	struct inode* (*volatile super_block_alloc_inode_p)(
		struct super_block *,
		struct super_block_container *,
		struct glue_cspace *,
		cptr_t channel)
	struct super_block_alloc_inode_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_alloc_inode_trampoline);

	super_block_alloc_inode_p = super_block_alloc_inode;

	return super_block_alloc_inode_p(super_block,
					hidden_args->super_block_container,
					hidden_args->cspace,
					hidden_args->channel);
}

void
noinline
super_block_destroy_inode(struct inode *inode,
			struct super_block_container *super_block_container,
			struct glue_cspace *cspace,
			cptr_t channel)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * Call remote destroy inode
	 */
	lcd_set_r0(SUPER_BLOCK_DESTROY_INODE);
	lcd_set_r1(cptr_val(super_block_container->their_ref));
	lcd_set_r2(cptr_val(inode_container->their_ref));
	ret = lcd_sync_call(channel);
	if (ret) {
		LIBLCD_ERR("error calling remote destroy inode");
		goto fail1;
	}

	/* Done */
	goto out;

out:
fail1:
	/*
	 * Remove our copy from cspace, and destroy it
	 */
	glue_cap_remove(pmfs_cspace, inode_container->my_ref);
	kfree(inode_container);

	return;
}

LCD_TRAMPOLINE_DATA(super_block_destroy_inode_trampoline);
void
LCD_TRAMPOLINE_LINKAGE(super_block_destroy_inode_trampoline)
super_block_destroy_inode_trampoline(struct inode *inode)
{
	void (*volatile super_block_destroy_inode_p)(
		struct inode *,
		struct super_block_container *,
		struct glue_cspace *,
		cptr_t);
	struct super_block_alloc_inode_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_destroy_inode_trampoline);

	super_block_destroy_inode_p = super_block_destroy_inode;

	super_block_destroy_inode_p(super_block,
				hidden_args->super_block_container,
				hidden_args->cspace,
				hidden_args->channel);
}

/* CALLEE FUNCTIONS -------------------------------------------------- */

int register_filesystem_callee(void)
{
	struct file_system_type_container *fs_container;
	struct module_container *module_container;
	int ret;

	/*
	 * SET UP CONTAINERS ----------------------------------------
	 */
	fs_container = kzalloc(sizeof(*fs_container), GFP_KERNEL);
	if (!fs_container) {
		LIBLCD_ERR("kzalloc fs container");
		ret = -ENOMEM;
		goto fail1;
	}

	ret = glue_cap_insert_file_system_type_type(
		pmfs_cspace,
		fs_container,
		&fs_container->my_ref);
	if (ret) {
		LIBLCD_ERR("dstore insert fs container");
		goto fail2;
	}


	module_container = kzalloc(sizeof(*module_container), GFP_KERNEL);
	if (!module_container) {
		LIBLCD_ERR("kzalloc module container");
		ret = -ENOMEM;
		goto fail3;
	}

	ret = glue_cap_insert_module_type(
		pmfs_cspace,
		module_container,
		&module_container->my_ref);
	if (ret) {
		LIBLCD_ERR("insert");
		goto fail4;
	}

	/* IPC UNMARSHALING ---------------------------------------- */
	
	/*
	 * Refs come first. 
	 *
	 * struct file_system_type
	 * -----------------------
	 *
	 * XXX: We don't bother passing fs name for now. Just hard code
	 * it to "pmfs".
	 */
	fs_container->their_ref = __cptr(lcd_r1());
	fs_container->file_system_type.name = "pmfs";
	/*
	 * Get cptr to pmfs channel (the channel we will use to invoke
	 * functions directed to pmfs - like mount)
	 */
	fs_container->pmfs_channel = lcd_cr0();
	/*
	 * struct module
	 * -------------
	 *
	 * Pull out remote ref, and link with fs type
	 */
	module_container->their_ref = __cptr(lcd_r2());
	fs_container->file_system_type.owner = &module_container->module;

	/*
	 * CALL REAL REGISTER_FILESYSTEM ------------------------------
	 */

	ret = register_filesystem(&fs_container->file_system_type);
	if (ret) {
		LIBLCD_ERR("register fs failed");
		goto fail5;
	}

	/*
	 * MARSHAL RETURN --------------------------------------------------
	 */

	/*
	 * Register fs return value
	 */
	lcd_set_r0(ret);
	/*
	 * Pass back a ref to our copies
	 */
	lcd_set_r1(cptr_val(fs_container->my_ref));
	lcd_set_r2(cptr_val(module_container->my_ref));
	/*
	 * Clear cr1
	 */
	lcd_set_cr0(CAP_CPTR_NULL);

	/* IPC REPLY -------------------------------------------------- */

	ret = lcd_sync_reply();
	if (ret) {
		LIBLCD_ERR("lcd_reply");
		goto fail6;
	}

	return 0;

fail6:
	if (unregister_filesystem(&fs_container->file_system_type) != 0)
		LIBLCD_ERR("double fault");
fail5:
	glue_cap_remove(pmfs_cspace, module_container->my_ref);
fail4:
	kfree(module_container);
fail3:
	glue_cap_remove(pmfs_cspace, fs_container->my_ref);
fail2:
	kfree(fs_container);
fail1:
	/* XXX: For now, we assume the grant was successful, so we need
	 * to delete the cap and free the cptr */
	lcd_cap_delete(lcd_cr0());
	lcd_cptr_free(lcd_cr0());
	/* Clear cr1 */
	lcd_set_cr0(CAP_CPTR_NULL);
	return ret;
}

int unregister_filesystem_callee(void)
{
	struct file_system_type_container *fs_container;
	struct module_container *module_container;
	int ret;
	cptr_t fs_ref, m_ref;

	/* CLEAR UNUSED SLOT ------------------------------ */
	
	/* Unlike register, we don't expect a capability. */

	/* XXX: Really need to update microkernel, otherwise this
	 * could be a vulnerability (caller could grant us something
	 * and fill up the slot). */

	lcd_cptr_free(lcd_cr0());
	lcd_set_cr0(CAP_CPTR_NULL);

	/* IPC UNMARSHALING ---------------------------------------- */

	/*
	 * We expect refs to our copies
	 */

	fs_ref = __cptr(lcd_r1());
	m_ref = __cptr(lcd_r2());

	/* LOOK UP CONTAINERS  ---------------------------------------- */

	ret = glue_cap_lookup_file_system_type_type(
		pmfs_cspace,
		fs_ref,
		&fs_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto out;
	}

	ret = glue_cap_lookup_module_type(
		pmfs_cspace,
		m_ref,
		&module_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto out;
	}

	/* CALL REAL FUNCTION ---------------------------------------- */

	ret = unregister_filesystem(&fs_container->file_system_type);
	if (ret) {
		LIBLCD_ERR("unregister fs");
		goto out;
	}

	/* CONTAINER DESTORY ---------------------------------------- */

	/*
	 * Remove from data store
	 */
	glue_cap_remove(pmfs_cspace, fs_container->my_ref);
	glue_cap_remove(pmfs_cspace, module_container->my_ref);
	/*
	 * Delete cap to pmfs channel
	 */
	lcd_cap_delete(fs_container->pmfs_channel);
	/*
	 * Free containers
	 */
	kfree(fs_container);
	kfree(module_container);

	/* IPC REPLY -------------------------------------------------- */


	ret = 0;
	goto out;

out:
	lcd_set_r0(ret);
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault");
	return ret;
}

int bdi_init_callee(void)
{
	struct backing_dev_info_container *bdi_container;
	int ret;

	/*
	 * SET UP CONTAINER ----------------------------------------
	 */
	bdi_container = kzalloc(sizeof(*bdi_container), GFP_KERNEL);
	if (!bdi_container) {
		LIBLCD_ERR("kzalloc bdi container");
		ret = -ENOMEM;
		goto fail1;
	}

	ret = glue_cap_insert_backing_dev_info_type(
		pmfs_cspace,
		bdi_container,
		&bdi_container->my_ref);
	if (ret) {
		LIBLCD_ERR("dstore insert bdi container");
		goto fail2;
	}

	/* IPC UNMARSHALING ---------------------------------------- */
	
	/*
	 * Ref comes first, followed by two fields.
	 *
	 * XXX: For now, this is tailored for pmfs. (Don't worry about
	 * other unused fields.)
	 *
	 */
	bdi_container->their_ref = __cptr(lcd_r1());
	bdi_container->backing_dev_info.ra_pages = lcd_r2();
	bdi_container->backing_dev_info.capabilities = lcd_r3();

	/*
	 * CALL REAL BDI_INIT ------------------------------
	 */

	ret = bdi_init(&bdi_container->backing_dev_info);
	if (ret) {
		LIBLCD_ERR("bdi init failed");
		goto fail3;
	}

	/*
	 * MARSHAL RETURN --------------------------------------------------
	 */

	/*
	 * Register fs return value
	 */
	lcd_set_r0(ret);
	/*
	 * Pass back a ref to our copy
	 */
	lcd_set_r1(cptr_val(bdi_container->my_ref));

	/* IPC REPLY -------------------------------------------------- */

	ret = lcd_sync_reply();
	if (ret) {
		LIBLCD_ERR("lcd_sync_reply");
		goto fail4;
	}

	return 0;

fail4:
	bdi_destroy(&bdi_container->backing_dev_info);
fail3:
	glue_cap_remove(pmfs_cspace, bdi_container->my_ref);
fail2:
	kfree(bdi_container);
fail1:
	return ret;
}

int bdi_destroy_callee(void)
{
	struct backing_dev_info_container *bdi_container;
	int ret;
	cptr_t ref;

	/* IPC UNMARSHALING ---------------------------------------- */

	/*
	 * We expect one ref to our copy
	 */

	ref = __cptr(lcd_r1());

	/* LOOK UP CONTAINER  ---------------------------------------- */

	ret = glue_cap_lookup_backing_dev_info_type(
		pmfs_cspace,
		ref,
		&bdi_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto out;
	}

	/* CALL REAL FUNCTION ---------------------------------------- */

	bdi_destroy(&bdi_container->backing_dev_info);

	/* CONTAINER DESTORY ---------------------------------------- */

	/*
	 * Remove from data store
	 */
	glue_cap_remove(pmfs_cspace, bdi_container->my_ref);
	/*
	 * Free container
	 */
	kfree(bdi_container);

	/* IPC REPLY -------------------------------------------------- */

	ret = 0;
	goto out;

out:
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault");
	return ret;
}

int iget_locked_callee(void)
{
	int ret;
	struct super_block_container *sb_container;
	struct inode *inode;
	struct pmfs_inode_vfs *inode_container;
	cptr_t their_ref = CAP_CPTR_NULL;
	/*
	 * Look up our private sb
	 */
	ret = glue_cap_lookup_super_block_type(pmfs_cspace,
					__cptr(lcd_r1()),
					&sb_container);
	if (ret) {
		LIBLCD_ERR("super block lookup failed");
		goto fail1;
	}
	/*
	 * Invoke the real function
	 *
	 * XXX: For pmfs, we know it implements alloc_inode, so we
	 * expect the alloc has already been done; so this is "bind"
	 * for pmfs.
	 *
	 * BUT the inode's mapping *is* callee allocated (sort of).
	 */
	inode = iget_locked(&sb_container->super_block, lcd_r2());
	if (!inode) {
		LIBLCD_ERR("iget locked failed");
		goto fail2;
	}
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	their_ref = inode_container->their_ref;
	/*
	 * Reply with remote refs for inode, and the following:
	 *
	 *     -- i_state
	 *     -- i_nlink
	 *     -- i_mode
	 */
	lcd_set_r1(inode->i_state);
	lcd_set_r2(inode->i_nlink);
	lcd_set_r3(inode->i_mode);

	ret = 0;
	goto out;

out:
fail2:
fail1:
	lcd_set_r0(cptr_val(their_ref));

	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");

	return ret;
}

int truncate_inode_pages_callee(void)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * (See notes for caller side)
	 *
	 * Look up our private inode object
	 */
	ret = glue_cap_lookup_address_space_type(pmfs_cspace,
						__cptr(lcd_r1()),
						&inode_container);
	if (ret) {
		LIBLCD_ERR("address space not found");
		goto fail1;
	}
	/*
	 * Invoke real function
	 */
	truncate_inode_pages(&inode_container->pmfs_inode_vfs.vfs_inode.i_data, 
			lcd_r2());
	/*
	 * Reply with nothing
	 */
	ret = 0;
	goto out;

out:
fail1:
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

int clear_inode_callee(void)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * Look up our private copy of the inode object
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(pmfs_cspace,
						__cptr(lcd_r1()),
						&inode_container);
	if (ret) {
		LIBLCD_ERR("error lookup inode");
		goto fail1;
	}
	/*
	 * Invoke real function
	 */
	clear_inode(&inode_container->pmfs_inode_vfs.vfs_inode);
	/*
	 * Nothing to reply with
	 */
	ret = 0;
	goto out;

out:
fail1:
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}
