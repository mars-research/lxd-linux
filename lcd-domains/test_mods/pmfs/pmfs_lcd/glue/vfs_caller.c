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

/* vfs_chnl is only used in register_filesystem for the first rpc
 * to vfs. Thereafter, we use the async channel (setup as part of
 * register_filesystem rpc). For simplicity, we use the same async 
 * channel for rpc's in both directions (to and from vfs). */
extern cptr_t vfs_register_channel;
extern cptr_t vfs_sync_endpoint;
extern struct glue_cspace *vfs_cspace;
extern struct thc_channel *vfs_async_chnl;
extern int pmfs_done;

/* GLUE SUPPORT CODE -------------------------------------------------- */

int glue_vfs_init(void)
{
	int ret;
	/*
	 * Initialize cspace stuff
	 */
	ret = glue_cap_init();
	if (ret) {
		LIBLCD_ERR("cap init");
		goto fail1;
	}
	/*
	 * Create a glue cspace to hold remote refs for vfs
	 */
	ret = glue_cap_create(&vfs_cspace);
	if (ret) {
		LIBLCD_ERR("glue cspace init");
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
	 * Free vfs glue cspace and tear down cap system
	 */
	glue_cap_destroy(vfs_cspace);
	glue_cap_exit();
}

static int setup_async_channel(cptr_t *buf1_cptr_out, cptr_t *buf2_cptr_out,
			struct thc_channel **chnl_out)
{
	int ret;
	cptr_t buf1_cptr, buf2_cptr;
	gva_t buf1_addr, buf2_addr;
	struct fipc_ring_channel *fchnl;
	struct thc_channel *chnl;
	unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
	/*
	 * Allocate buffers
	 *
	 * (We use the lower level alloc. If we used the heap, even though
	 * we may alloc only 1 - 2 pages, we would end up sharing around
	 * 4 MB chunks of memory, since the heap uses coarse microkernel
	 * allocations.)
	 */
	ret = _lcd_alloc_pages(GFP_KERNEL, pg_order, &buf1_cptr);
	if (ret) {
		LIBLCD_ERR("buf1 alloc");
		goto fail1;
	}
	ret = _lcd_alloc_pages(GFP_KERNEL, pg_order, &buf2_cptr);
	if (ret) {
		LIBLCD_ERR("buf2 alloc");
		goto fail2;
	}
	/*
	 * Map them somewhere
	 */
	ret = lcd_map_virt(buf1_cptr, pg_order, &buf1_addr);
	if (ret) {
		LIBLCD_ERR("error mapping buf1");
		goto fail3;
	}
	ret = lcd_map_virt(buf2_cptr, pg_order, &buf2_addr);
	if (ret) {
		LIBLCD_ERR("error mapping buf2");
		goto fail4;
	}
	/*
	 * Prep buffers for rpc
	 */
	ret = fipc_prep_buffers(PMFS_ASYNC_RPC_BUFFER_ORDER,
				(void *)gva_val(buf1_addr),
				(void *)gva_val(buf2_addr));
	if (ret) {
		LIBLCD_ERR("prep buffers");
		goto fail5;
	}
	/*
	 * Alloc and init channel header
	 */
	fchnl = kmalloc(sizeof(*fchnl), GFP_KERNEL);
	if (!fchnl) {
		ret = -ENOMEM;
		LIBLCD_ERR("chnl alloc");
		goto fail6;
	}
	ret = fipc_ring_channel_init(fchnl, PMFS_ASYNC_RPC_BUFFER_ORDER,
				(void *)gva_val(buf1_addr),
				(void *)gva_val(buf2_addr));
	if (ret) {
		LIBLCD_ERR("ring chnl init");
		goto fail7;
	}
	/*
	 * Install async channel in async dispatch loop
	 */
	chnl = kzalloc(sizeof(*chnl), GFP_KERNEL);
	if (!chnl) {
		ret = -ENOMEM;
		LIBLCD_ERR("alloc failed");
		goto fail8;
	}
	ret = thc_channel_init(chnl, fchnl);
	if (ret) {
		LIBLCD_ERR("error init'ing async channel group item");
		goto fail9;
	}

	*buf1_cptr_out = buf1_cptr;
	*buf2_cptr_out = buf2_cptr;
	*chnl_out = chnl;

	return 0;

fail9:
	kfree(chnl);
fail8:
fail7:
	kfree(fchnl);
fail6:
fail5:
	lcd_unmap_virt(buf1_addr, pg_order);
fail4:
	lcd_unmap_virt(buf1_addr, pg_order);
fail3:
	lcd_cap_delete(buf2_cptr);
fail2:
	lcd_cap_delete(buf1_cptr);
fail1:
	return ret; 
}

static void destroy_async_channel(struct thc_channel *chnl)
{
	unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
	gva_t tx_gva, rx_gva;
	cptr_t tx, rx;
	int ret;
	unsigned long unused1, unused2;
	/*
	 * Translate ring buffers to cptrs
	 */
	tx_gva = __gva((unsigned long)thc_channel_to_fipc(chnl)->tx.buffer);
	rx_gva = __gva((unsigned long)thc_channel_to_fipc(chnl)->rx.buffer);
	ret = lcd_virt_to_cptr(tx_gva, &tx, &unused1, &unused2);
	if (ret) {
		LIBLCD_ERR("failed to translate tx to cptr");
		goto fail1;
	}
	ret = lcd_virt_to_cptr(rx_gva, &rx, &unused1, &unused2);
	if (ret) {
		LIBLCD_ERR("failed to translate rx to cptr");
		goto fail2;
	}
	/*
	 * Unmap and kill tx/rx
	 */
	lcd_unmap_virt(tx_gva, pg_order);
	lcd_cap_delete(tx);
	lcd_unmap_virt(rx_gva, pg_order);
	lcd_cap_delete(rx);
	/*
	 * Free chnl header
	 */
	kfree(thc_channel_to_fipc(chnl));
	/*
	 * Remove and free async channel group item
	 */
	thc_channel_mark_dead(chnl);

	return;

fail2:
fail1:
	return;
}

/* CALLER FUNCTIONS -------------------------------------------------- */

int register_filesystem(struct file_system_type *fs)
{
	struct file_system_type_container *fs_container;
	struct module_container *module_container;
	int ret;
	cptr_t tx, rx;
	struct thc_channel *chnl;
	/*
	 * Set up async and sync channels
	 */
	ret = lcd_create_sync_endpoint(&vfs_sync_endpoint);
	if (ret) {
		LIBLCD_ERR("lcd_create_sync_endpoint");
		goto fail1;
	}
	ret = setup_async_channel(&tx, &rx, &chnl);
	if (ret) {
		LIBLCD_ERR("async chnl setup failed");
		goto fail2;
	}
	/*
	 * Insert containers into vfs cspace
	 */
	fs_container = container_of(fs, 
				struct file_system_type_container,
				file_system_type);
	module_container = container_of(fs->owner,
					struct module_container,
					module);
	ret = glue_cap_insert_file_system_type_type(
		vfs_cspace, 
		fs_container,
		&fs_container->my_ref);
	if (ret) {
		LIBLCD_ERR("insert");
		goto fail3;
	}
	ret = glue_cap_insert_module_type(
		vfs_cspace, 
		module_container,
		&module_container->my_ref);
	if (ret) {
		LIBLCD_ERR("insert");
		goto fail4;
	}
	/*
	 * Do rpc, sending:
	 *
	 *    -- r1: our ref to fs type
	 *    -- r2: our ref to module
	 *    -- cr0: cap to pmfs_sync_endpoint
	 *    -- cr1: cap to buffer for callee to use for tx (this is our rx)
	 *    -- cr2: cap to buffer for callee to use for rx (this is our tx)
	 */
	lcd_set_r0(REGISTER_FILESYSTEM);
	lcd_set_r1(cptr_val(fs_container->my_ref));
	lcd_set_r2(cptr_val(module_container->my_ref));
	lcd_set_cr0(vfs_sync_endpoint);
	lcd_set_cr1(rx);
	lcd_set_cr2(tx);

	ret = lcd_sync_call(vfs_register_channel);
	/*
	 * Flush cap registers
	 */
	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);
	lcd_set_cr2(CAP_CPTR_NULL);
	if (ret) {
		LIBLCD_ERR("lcd_call");
		goto fail5;
	}
	/*
	 * Reply:
	 *
	 *    -- r0: register_filesystem return value
	 *    -- r1: ref to their fs type
	 *    -- r2: ref to their module
	 */
	ret = lcd_r0();
	if (ret) {
		LIBLCD_ERR("remote register fs failed");
		goto fail6;
	}
	fs_container->their_ref = __cptr(lcd_r1());
	module_container->their_ref = __cptr(lcd_r2());

	/*
	 * Kick off async recv
	 */
	vfs_async_chnl = chnl;

	return ret;

fail6:
fail5:
	glue_cap_remove(vfs_cspace, module_container->my_ref);
fail4:
	glue_cap_remove(vfs_cspace, fs_container->my_ref);
fail3:
	destroy_async_channel(chnl);
fail2:
	lcd_cap_delete(vfs_sync_endpoint);
fail1:
	return ret;
}

int unregister_filesystem(struct file_system_type *fs)
{
	int ret;
	struct file_system_type_container *fs_container;
	struct module_container *module_container;
	struct fipc_message *request, *response;

	fs_container = container_of(fs,
				struct file_system_type_container,
				file_system_type);
	module_container = container_of(fs->owner,
					struct module_container,
					module);
	/*
	 * Marshal and do rpc.
	 *
	 *   -- fs type ref
	 *   -- module ref
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}
	async_msg_set_fn_type(request, UNREGISTER_FILESYSTEM);
	fipc_set_reg0(request, cptr_val(fs_container->their_ref));
	fipc_set_reg1(request, cptr_val(module_container->their_ref));
	
	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("async call failed");
		goto fail2;
	}
	/*
	 * Just expecting int ret value in response
	 */
	ret = fipc_get_reg0(response);
	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);
	/*
	 * Tear down.
	 *
	 * Destroy sync endpoint and async channel
	 */
	lcd_cap_delete(vfs_sync_endpoint);
	destroy_async_channel(vfs_async_chnl);
	/*
	 * Remove fs type and module from data store
	 */
	glue_cap_remove(vfs_cspace, fs_container->my_ref);
	glue_cap_remove(vfs_cspace, module_container->my_ref);
	/*
	 * Pass back return value
	 */

	return ret;
fail2:
fail1:
	return ret;
}

int bdi_init(struct backing_dev_info *bdi)
{
	struct backing_dev_info_container *bdi_container;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * Insert bdi object into cspace
	 */
	bdi_container = container_of(bdi, 
				struct backing_dev_info_container,
				backing_dev_info);
	ret = glue_cap_insert_backing_dev_info_type(
		vfs_cspace, 
		bdi_container,
		&bdi_container->my_ref);
	if (ret) {
		LIBLCD_ERR("insert");
		goto fail1;
	}
	/*
	 * Marshal and send:
	 *
	 *   -- bdi ref
	 *   -- bdi.ra_pages
	 *   -- bdi.capabilities
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail2;
	}

	async_msg_set_fn_type(request, BDI_INIT);
	fipc_set_reg0(request, cptr_val(bdi_container->my_ref));
	fipc_set_reg1(request, bdi_container->backing_dev_info.ra_pages);
	fipc_set_reg2(request, bdi_container->backing_dev_info.capabilities);

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail3;
	}
	/*
	 * Unmarshal:
	 *
	 *   -- return value
	 *   -- remote ref
	 */
	ret = fipc_get_reg0(response);
	bdi_container->their_ref = __cptr(fipc_get_reg1(response));
	/*
	 * Pass back return value
	 */
	goto out;

fail3:
fail2:
	glue_cap_remove(vfs_cspace, bdi_container->my_ref);
fail1:
out:
	return ret;
}

void bdi_destroy(struct backing_dev_info *bdi)
{
	int ret;
	struct backing_dev_info_container *bdi_container;
	struct fipc_message *request, *response;

	bdi_container = container_of(bdi,
				struct backing_dev_info_container,
				backing_dev_info);
	/*
	 * Marshal:
	 *
	 *   -- ref to bdi obj
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, BDI_DESTROY);
	fipc_set_reg0(request, cptr_val(bdi_container->their_ref));

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail2;
	}
	/*
	 * Nothing is in response
	 */
	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);
	/*
	 * Remove bdi obj from cspace
	 */
	glue_cap_remove(vfs_cspace, bdi_container->my_ref);
	/*
	 * (no return value)
	 */
	return;
fail2:
fail1:
	return;
}

struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
	struct super_block_container *sb_container;
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	struct fipc_message *request, *response;

	sb_container = container_of(sb, struct super_block_container,
				super_block);
	/*
	 * Marshal:
	 *
	 *   -- their ref to sb obj
	 *   -- ref to our sb
	 *   -- ino
	 *
	 * Why do we have to pass ours? Because we call iget_locked
	 * before we have returned our sb ref (from mount_nodev fill_super).
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, IGET_LOCKED);
	fipc_set_reg0(request, cptr_val(sb_container->their_ref));
	fipc_set_reg1(request, cptr_val(sb_container->my_ref));
	fipc_set_reg2(request, ino);

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail2;
	}
	/*
	 * Unmarshal:
	 *
	 *   -- inode ref
	 *   -- i_state
	 *   -- i_nlink
	 *   -- i_mode
	 */
	if (cptr_is_null(__cptr(fipc_get_reg0(response)))) {
		LIBLCD_ERR("got null from iget locked");
		goto fail3;
	}
	ret = glue_cap_lookup_pmfs_inode_vfs_type(vfs_cspace,
						__cptr(fipc_get_reg0(response)),
						&inode_container);
	if (ret) {
		LIBLCD_ERR("failed to lookup inode");
		goto fail4;
	}
	inode_container->pmfs_inode_vfs.vfs_inode.i_state =
		fipc_get_reg1(response);
	inode_container->pmfs_inode_vfs.vfs_inode.__i_nlink = 
		fipc_get_reg2(response);
	inode_container->pmfs_inode_vfs.vfs_inode.i_mode =
		fipc_get_reg3(response);

	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);

	/*
	 * We also know that i_mapping -> i_data, at least for pmfs. (So
	 * although i_mapping is a pointer, the data it points to is embedded
	 * in the struct inode.)
	 */
	inode_container->pmfs_inode_vfs.vfs_inode.i_mapping =
		&inode_container->pmfs_inode_vfs.vfs_inode.i_data;
	/*
	 * We also need to set back pointer to super block (this is normally
	 * done by the callee, but we have to "manually" do it here in the 
	 * glue)
	 */
	inode_container->pmfs_inode_vfs.vfs_inode.i_sb = sb;
	/*
	 * Done
	 */
	return &inode_container->pmfs_inode_vfs.vfs_inode;

fail4:
fail3:

	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);

	/* It would be nice if we could call iput or something, but we're
	 * sort of sunk since we can't look up our private copy ... */
fail2:
fail1:
	return NULL;
}

void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * At least for pmfs, we know that mapping points to
	 * i_data for the corresponding inode. So, we resolve ...
	 */
	inode_container = container_of(
		container_of(
			container_of(mapping, struct inode, i_data),
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	/*
	 * Marshal:
	 *
	 *   -- ref to inode obj
	 *   -- lstart
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, TRUNCATE_INODE_PAGES);
	fipc_set_reg0(request, cptr_val(inode_container->their_ref));
	fipc_set_reg1(request, lstart);

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail2;
	}
	/*
	 * Nothing in response
	 */

	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);

	goto out;
fail2:
fail1:
out:
	return;
}

void clear_inode(struct inode *inode)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * Marshal remote ref, and do rpc.
	 */
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	/*
	 * Marshal:
	 *
	 *   -- ref to inode obj
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, CLEAR_INODE);
	fipc_set_reg0(request, cptr_val(inode_container->their_ref));

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail2;
	}
	/*
	 * Nothing in response
	 */

	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);

	goto out;
fail2:
fail1:
out:
	return;
}

void iget_failed(struct inode *inode)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * Get remote ref, do rpc. (This will ultimately free the inode.)
	 */
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	/*
	 * Marshal:
	 *
	 *   -- ref to inode obj
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, IGET_FAILED);
	fipc_set_reg0(request, cptr_val(inode_container->their_ref));

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail2;
	}
	/*
	 * Nothing in response
	 */

	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);

	goto out;
fail2:
fail1:
out:
	return;
}

void unlock_new_inode(struct inode *inode)
{
	struct pmfs_inode_vfs_container *inode_container;
	struct fipc_message *request, *response;
	int ret;
	/*
	 * Get remote ref, and do rpc.
	 */
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	/*
	 * Marshal:
	 *
	 *   -- ref to inode obj
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, UNLOCK_NEW_INODE);
	fipc_set_reg0(request, cptr_val(inode_container->their_ref));

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail2;
	}
	/*
	 * Get updated i_state
	 */
	inode_container->pmfs_inode_vfs.vfs_inode.i_state = 
		fipc_get_reg0(response);

	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);

	goto out;
fail2:
fail1:
out:
	return;
}

void
inode_init_once(struct inode *inode)
{
	return; /* no-op */
}

void
set_nlink(struct inode *inode, unsigned int link)
{
	inode->__i_nlink = link;
}

struct dentry *
d_make_root(struct inode *inode)
{
	struct pmfs_inode_vfs_container *inode_container;
	struct dentry_container *dentry_container;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * Get inode container
	 */
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	/*
	 * Make our private copy and insert into cspace
	 */
	dentry_container = kzalloc(sizeof(*dentry_container), GFP_KERNEL);
	if (!dentry_container) {
		LIBLCD_ERR("error creating container");
		goto fail1;
	}
	ret = glue_cap_insert_dentry_type(vfs_cspace,
					dentry_container,
					&dentry_container->my_ref);
	if (ret) {
		LIBLCD_ERR("error inserting dentry");
		goto fail2;
	}
	/*
	 * Set up links to other private objects (normally the callee does
	 * this)
	 */
	dentry_container->dentry.d_sb = inode->i_sb;
	dentry_container->dentry.d_inode = inode;
	/*
	 * Marshal:
	 *
	 *   -- inode ref
	 *   -- i_nlinks
	 *   -- dentry ref
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail3;
	}

	async_msg_set_fn_type(request, D_MAKE_ROOT);
	fipc_set_reg0(request, cptr_val(inode_container->their_ref));
	fipc_set_reg1(request, 
		inode_container->pmfs_inode_vfs.vfs_inode.i_nlink);
	fipc_set_reg2(request, cptr_val(dentry_container->my_ref));

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail4;
	}
	/*
	 * Get remote ref to dentry in response
	 */
	if (cptr_is_null(__cptr(fipc_get_reg0(response)))) {
		LIBLCD_ERR("got null from d_make_root");
		goto fail5;
	}
	dentry_container->their_ref = __cptr(fipc_get_reg0(response));

	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);
	
	return &dentry_container->dentry;

fail5:
fail4:
fail3:
	glue_cap_remove(vfs_cspace, dentry_container->my_ref);
fail2:
	kfree(dentry_container);
fail1:
	return NULL;
}

struct dentry *
mount_nodev(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int))
{
	struct file_system_type_container *fs_container;
	struct mount_nodev_fill_super_container *fill_sup_container;
	struct dentry_container *dentry_container;
	int ret;
	cptr_t data_cptr;
	unsigned long data_offset;
	unsigned long mem_sz;
	uint32_t request_cookie;
	struct fipc_message *request, *response;
	
	fs_container = container_of(
		fs_type,
		struct file_system_type_container,
		file_system_type);
	/*
	 * Set up void *data arg passing
	 */
	ret = lcd_virt_to_cptr(__gva((unsigned long)data),
			&data_cptr,
			&mem_sz,
			&data_offset);
	if (ret) {
		LIBLCD_ERR("virt to cptr failed");
		goto fail1;
	}
	/*
	 * Set up fill_super container
	 */
	fill_sup_container = kzalloc(sizeof(*fill_sup_container), GFP_KERNEL);
	if (!fill_sup_container) {
		LIBLCD_ERR("fill_sup alloc failed");
		goto fail2;
	}
	ret = glue_cap_insert_mount_nodev_fill_super_type(vfs_cspace,
							fill_sup_container,
							&fill_sup_container->my_ref);
	if (ret) {
		LIBLCD_ERR("fill_super insert failed");
		goto fail3;
	}
	fill_sup_container->fill_super = fill_super;
	/*
	 * Do async half:
	 *
	 * Marshal:
	 *
	 *   -- fs type ref
	 *   -- flags
	 *   -- fill sup ref
	 *
	 * We will also do a sync send (see below) to transfer
	 * void *data.
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail4;
	}

	async_msg_set_fn_type(request, MOUNT_NODEV);
	fipc_set_reg0(request, cptr_val(fs_container->their_ref));
	fipc_set_reg1(request, flags);
	fipc_set_reg2(request, cptr_val(fill_sup_container->my_ref));

	ret = thc_ipc_send_request(vfs_async_chnl, request, &request_cookie);
	if (ret) {
		LIBLCD_ERR("error sending request");
		goto fail5;
	}
	/*
	 * Do sync half:
	 *
	 * Marshal:
	 *
	 *   -- cptr for memory that contains void *data
	 *   -- memory size (assumes mem_sz is 2^x pages)
	 *   -- void *data offset into memory
	 */
	lcd_set_r0(ilog2(mem_sz >> PAGE_SHIFT));
	lcd_set_r1(data_offset);
	lcd_set_cr0(data_cptr);

	ret = lcd_sync_send(vfs_sync_endpoint);
	lcd_set_cr0(CAP_CPTR_NULL); /* flush cr0 */
	if (ret) {
		LIBLCD_ERR("failed to do sync half of mount_nodev");
		/* The callee will not be sending us a response. This is 
		 * under the assumption that if we fail to do a sync send, 
		 * the callee failed to do a sync receive, and will just 
		 * cancel the "transaction". */
		thc_kill_request_cookie(request_cookie);
		goto fail6;
	}
	/*
	 * Get *async* response
	 */
	ret = thc_ipc_recv_response(vfs_async_chnl, request_cookie, &response);
	if (ret) {
		LIBLCD_ERR("async recv failed");
		goto fail7;
	}
	/*
	 * Unmarshal returned dentry
	 */
	if (cptr_is_null(__cptr(fipc_get_reg0(response)))) {
		LIBLCD_ERR("got null from remote mount_nodev");
		goto fail8;
	}
	ret = glue_cap_lookup_dentry_type(vfs_cspace,
					__cptr(fipc_get_reg0(response)),
					&dentry_container);
	if (ret) {
		LIBLCD_ERR("couldn't find dentry");
		goto fail9;
	}
	/*
	 * Tear down
	 *
	 * Free fill_super container, etc., and unshare void *data memory
	 */
	glue_cap_remove(vfs_cspace, fill_sup_container->my_ref);
	kfree(fill_sup_container);
	lcd_cap_revoke(data_cptr);
	/*
	 * Done
	 */
	return &dentry_container->dentry;

fail9:
fail8:
fail7:
fail6:
fail5:
fail4:
	glue_cap_remove(vfs_cspace, fill_sup_container->my_ref);
fail3:
	kfree(fill_sup_container);
fail2:
fail1:
	return NULL;
}

void kill_anon_super(struct super_block *sb)
{
	struct super_block_container *sb_container;
	int ret;
	struct fipc_message *request, *response;

	sb_container = container_of(sb,
				struct super_block_container,
				super_block);
	/*
	 * Marshal:
	 *
	 *   -- sb ref
	 */
	ret = async_msg_blocking_send_start(vfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, KILL_ANON_SUPER);
	fipc_set_reg0(request, cptr_val(sb_container->their_ref));

	ret = thc_ipc_call(vfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail2;
	}
	/*
	 * Nothing in reply
	 */

	fipc_recv_msg_end(thc_channel_to_fipc(vfs_async_chnl), response);

	goto out;

fail2:
fail1:
out:
	return;
}

/* CALLEE FUNCTIONS (FUNCTION POINTERS) ------------------------------ */

int super_block_alloc_inode_callee(struct fipc_message *request,
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct super_block_container *sb_container;
	struct pmfs_inode_vfs_container *inode_container = NULL;
	struct inode *inode;
	int ret;
	cptr_t sb_ref = __cptr(fipc_get_reg0(request));
	cptr_t inode_ref = __cptr(fipc_get_reg1(request));
	struct fipc_message *response;
	uint32_t request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/*
	 * Get our private struct sb
	 */
	ret = glue_cap_lookup_super_block_type(cspace, sb_ref,
					&sb_container);
	if (ret) {
		LIBLCD_ERR("error looking up super block");
		goto fail1;
	}
	/*
	 * Invoke the real function
	 */
	inode = sb_container->super_block.s_op->alloc_inode(
		&sb_container->super_block);
	if (!inode) {
		LIBLCD_ERR("error alloc'ing inode");
		ret = -ENOMEM;
		goto fail2;
	}
	inode_container = container_of(
		container_of(inode, struct pmfs_inode_vfs, vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	inode_container->their_ref = inode_ref;
	/*
	 * Create a remote reference for the new inode
	 */
	ret = glue_cap_insert_pmfs_inode_vfs_type(cspace,
						inode_container,
						&inode_container->my_ref);
	if (ret) {
		LIBLCD_ERR("error creating ref");
		goto fail3;
	}
	/*
	 * Respond with inode ref
	 */
	ret = 0;
	goto reply;

fail3:
	sb_container->super_block.s_op->destroy_inode(inode);
fail2:
fail1:
reply:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	/*
	 * Return ref to our inode
	 */
	if (inode_container)
		fipc_set_reg0(response, cptr_val(inode_container->my_ref));
	else
		fipc_set_reg0(response, cptr_val(CAP_CPTR_NULL));

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int super_block_destroy_inode_callee(struct fipc_message *request,
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct super_block_container *sb_container;
	struct pmfs_inode_vfs_container *inode_container;
	cptr_t sb_ref = __cptr(fipc_get_reg0(request));
	cptr_t inode_ref = __cptr(fipc_get_reg1(request));
	int ret;
	uint32_t request_cookie = thc_get_request_cookie(request);
	struct fipc_message *response;

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	/*
	 * Get our private struct sb
	 */
	ret = glue_cap_lookup_super_block_type(cspace, sb_ref,
					&sb_container);
	if (ret) {
		LIBLCD_ERR("error looking up super block");
		goto fail1;
	}
	/*
	 * Get our private struct inode
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(cspace, inode_ref,
						&inode_container);
	if (ret) {
		LIBLCD_ERR("error looking up inode");
		goto fail2;
	}
	/*
	 * Remove our private copy from the cspace (before we invoke
	 * the real function that kills it)
	 */
	glue_cap_remove(vfs_cspace, inode_container->my_ref);
	/*
	 * Invoke the real function
	 */
	sb_container->super_block.s_op->destroy_inode(
		&inode_container->pmfs_inode_vfs.vfs_inode);

	ret = 0;
	goto reply;

fail2:
fail1:
reply:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	/* empty reply */

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int super_block_evict_inode_callee(struct fipc_message *request,
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct super_block_container *sb_container;
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	cptr_t sb_ref = __cptr(fipc_get_reg0(request));
	cptr_t inode_ref = __cptr(fipc_get_reg1(request));
	uint32_t request_cookie = thc_get_request_cookie(request);
	struct fipc_message *response;

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/*
	 * Look up private copies of super block and inode
	 */
	ret = glue_cap_lookup_super_block_type(cspace,
					sb_ref,
					&sb_container);
	if (ret) {
		LIBLCD_ERR("super block not found");
		goto fail1;
	}
	ret = glue_cap_lookup_pmfs_inode_vfs_type(cspace,
						inode_ref,
						&inode_container);
	if (ret) {
		LIBLCD_ERR("inode not found");
		goto fail2;
	}
	/*
	 * Invoke real evict inode
	 */
	sb_container->super_block.s_op->evict_inode(
		&inode_container->pmfs_inode_vfs.vfs_inode
		);
	/*
	 * Nothing to reply with
	 */
	ret = 0;
	goto out;

fail2:
fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	/* empty reply */

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

static int sync_mount_nodev_fill_super_callee(cptr_t sync_channel,
					cptr_t *data_cptr,
					unsigned int *mem_order,
					unsigned long *data_offset)
{
	int ret;
	/*
	 * Alloc cptr for data mem
	 */
	ret = lcd_cptr_alloc(data_cptr);
	if (ret) {
		LIBLCD_ERR("alloc cptr");
		goto fail1;
	}
	/*
	 * Set up and do sync receive
	 */
	lcd_set_cr0(*data_cptr);
	ret = lcd_sync_recv(sync_channel);
	lcd_set_cr0(CAP_CPTR_NULL); /* flush cr0 */
	if (ret) {
		LIBLCD_ERR("sync recv failed");
		goto fail2;
	}
	/*
	 * Unmarshal other values
	 */
	*mem_order = lcd_r0();
	*data_offset = lcd_r1();

	return 0;

fail2:		
	lcd_cptr_free(*data_cptr);
fail1:
	return ret;
}

int mount_nodev_fill_super_callee(struct fipc_message *request,
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct mount_nodev_fill_super_container *fill_sup_container;
	struct super_block_container *sb_container;
	struct dentry_container *dentry_container = NULL;
	cptr_t fill_sup_ref = __cptr(fipc_get_reg0(request));
	cptr_t sb_ref = __cptr(fipc_get_reg1(request));
	int flags = fipc_get_reg2(request);
	int silent = fipc_get_reg3(request);
	uint32_t request_cookie = thc_get_request_cookie(request);
	cptr_t data_cptr;
	gva_t data_gva;
	unsigned long data_offset;
	unsigned int mem_order;
	int ret;
	struct fipc_message *response;

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	/*
	 * Do sync part
	 */
	ret = sync_mount_nodev_fill_super_callee(sync_endpoint,
						&data_cptr,
						&mem_order,
						&data_offset);
	if (ret) {
		LIBLCD_ERR("sync mount fill sup failed");
		return ret; /* do not do async reply */
	}
	/*
	 * Bind on fill_super function pointer
	 */
	ret = glue_cap_lookup_mount_nodev_fill_super_type(cspace,
							fill_sup_ref,
							&fill_sup_container);
	if (ret) {
		LIBLCD_ERR("fill super lookup failed");
		goto fail1;
	}
	/*
	 * Callee alloc on super block. Create ref, etc.
	 */
	sb_container = kzalloc(sizeof(*sb_container), GFP_USER);
	if (!sb_container) {
		ret = -ENOMEM;
		LIBLCD_ERR("kzalloc failed");
		goto fail2;
	}
	ret = glue_cap_insert_super_block_type(cspace,
					sb_container,
					&sb_container->my_ref);
	if (ret) {
		LIBLCD_ERR("super block ref");
		goto fail3;
	}
	sb_container->their_ref = sb_ref;
	sb_container->super_block.s_flags = flags;
	/*
	 * Map void *data arg
	 */
	ret = lcd_map_virt(data_cptr, mem_order, &data_gva);
	if (ret) {
		LIBLCD_ERR("error mapping void *data");
		goto fail4;
	}
	/*
	 * Invoke real function
	 */
	ret = fill_sup_container->fill_super(&sb_container->super_block,
					(void *)(gva_val(data_gva) + data_offset),
					silent);
	if (ret) {
		LIBLCD_ERR("fill super failed");
		goto fail5;
	}
	/*
	 * Get the dentry we created in fill sup
	 */
	dentry_container = container_of(sb_container->super_block.s_root,
					struct dentry_container,
					dentry);
	/*
	 * Unmap void *data, and delete from our cspace.
	 */
	lcd_unmap_virt(data_gva, mem_order);
	lcd_cap_delete(data_cptr);
	/*
	 * Reply
	 */
	goto out;

fail5:
	lcd_unmap_virt(data_gva, mem_order);
fail4:
	glue_cap_remove(cspace, sb_container->my_ref);
fail3:
	kfree(sb_container);
fail2:
fail1:
	lcd_cap_delete(data_cptr);
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg0(response, ret);
	/*
	 * Reply with our super_block ref, new s_flags, and
	 * ref to s_root dentry (so caller can set s_root to their
	 * private dentry copy - in the regular world, this is done by the 
	 * callee on the shared memory data).
	 */
	if (dentry_container) {
		fipc_set_reg1(response, cptr_val(sb_container->my_ref));
		fipc_set_reg2(response, sb_container->super_block.s_flags);
		fipc_set_reg3(response, cptr_val(dentry_container->their_ref));
	}

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

static void *update_cmdline(char *old_cmdline, gpa_t new_fs_mem_gpa)
{
	char *new_cmdline;
	/* 
	 * Stolen from pmfs/super.c:get_phys_addr. Looks like they
	 * assume physaddr= is always the first mount option, so we
	 * do too.
	 */
	if (!old_cmdline || strncmp(old_cmdline, "physaddr=", 9) != 0)
		return NULL;
	old_cmdline += 9;
	/*
	 * Skim over old physaddr and comma
	 */
	simple_strtoull(old_cmdline, &old_cmdline, 0);
	old_cmdline++;
	/*
	 * Create new dup of cmdline, but with new physaddr
	 *
	 *   strlen(old_cmdline) for rest of original cmdline
	 *   9  for physaddr=
	 *   18 for 0x.... address
	 *   1  for comma
	 *   1  for nul
	 */
	new_cmdline = kzalloc(strlen(old_cmdline) + 9 + 18 + 1 + 1, 
			GFP_KERNEL);
	if (!new_cmdline) {
		LIBLCD_ERR("kzalloc failed");
		return NULL;
	}
	snprintf(new_cmdline, strlen(old_cmdline) + 9 + 18 + 1 + 1,
		"physaddr=0x%016lx,%s", gpa_val(new_fs_mem_gpa),
		old_cmdline);

	return (void *)new_cmdline;
}

static int sync_file_system_type_mount_callee(cptr_t sync_channel,
					cptr_t *data_cptr,
					unsigned int *mem_order,
					unsigned long *data_offset,
					cptr_t *fs_mem_cptr,
					unsigned int *fs_mem_order)
{
	int ret;
	/*
	 * Alloc cptr's for objects
	 */
	ret = lcd_cptr_alloc(data_cptr);
	if (ret) {
		LIBLCD_ERR("data cptr alloc");
		goto fail1;
	}
	ret = lcd_cptr_alloc(fs_mem_cptr);
	if (ret) {
		LIBLCD_ERR("fs mem cptr alloc");
		goto fail2;
	}
	/*
	 * Set up and do sync receive
	 */
	lcd_set_cr0(*data_cptr);
	lcd_set_cr1(*fs_mem_cptr);
	ret = lcd_sync_recv(sync_channel);
	/*
	 * Flush cptr regs
	 */
	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);
	if (ret) {
		LIBLCD_ERR("sync recv failed");
		goto fail3;
	}
	/*
	 * Read out values
	 */
	*mem_order = lcd_r0();
	*data_offset = lcd_r1();
	*fs_mem_order = lcd_r2();
	
	return 0;

fail3:
	lcd_cptr_free(*fs_mem_cptr);
fail2:
	lcd_cptr_free(*data_cptr);
fail1:
	return ret;
}

int file_system_type_mount_callee(struct fipc_message *request,
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct file_system_type_container *fs_container;
	struct dentry_container *dentry_container = NULL;
	struct dentry *dentry;
	struct fipc_message *response;
	cptr_t fs_ref = __cptr(fipc_get_reg0(request));
	int flags = fipc_get_reg1(request);
	uint32_t request_cookie = thc_get_request_cookie(request);
	cptr_t data_cptr;
	unsigned int mem_order;
	unsigned long data_offset;
	gva_t data_gva;
	void *new_cmdline;
	cptr_t fs_mem_cptr;
	unsigned int fs_mem_order;
	gpa_t fs_mem_gpa;
	int ret;

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/*
	 * Do sync part of mount to get:
	 *
	 *   -- void *data stuff
	 *   -- fs memory stuff
	 */
	ret = sync_file_system_type_mount_callee(sync_endpoint,
						&data_cptr,
						&mem_order,
						&data_offset,
						&fs_mem_cptr,
						&fs_mem_order);
	if (ret) {
		LIBLCD_ERR("failed to do sync part of mount");
		return ret; /* do not do async reply */
	}
	/*
	 * Bind on fs type
	 */
	ret = glue_cap_lookup_file_system_type_type(cspace,
						fs_ref,
						&fs_container);
	if (ret) {
		LIBLCD_ERR("couldn't find fs type");
		goto fail2;
	}
	/*
	 * Map void *data
	 */
	ret = lcd_map_virt(data_cptr, mem_order, &data_gva);
	if (ret) {
		LIBLCD_ERR("couldn't map void *data arg");
		goto fail3;
	}
	/*
	 * Map fs memory
	 */
	ret = lcd_map_phys(fs_mem_cptr, fs_mem_order, &fs_mem_gpa);
	if (ret) {
		LIBLCD_ERR("error mapping fs memory");
		goto fail4;
	}
	/*
	 * Update cmd line args with new gpa
	 */
	new_cmdline = update_cmdline((char *)(gva_val(data_gva) + data_offset),
				fs_mem_gpa);
	if (!new_cmdline) {
		LIBLCD_ERR("failed to update cmdline");
		goto fail5;
	}
	/*
	 * Call real function
	 */
	dentry = fs_container->file_system_type.mount(
		&fs_container->file_system_type,
		flags,
		NULL,
		new_cmdline);
	if (!dentry) {
		LIBLCD_ERR("got null from mount");
		ret = -EINVAL;
		goto fail6;
	}
	dentry_container = container_of(dentry,
					struct dentry_container,
					dentry);
	/*
	 * Kill void *data stuff
	 */
	lcd_unmap_virt(data_gva, mem_order);
	lcd_cap_delete(data_cptr);
	/*
	 * Free new_cmdline
	 */
	kfree(new_cmdline);
	/*
	 * Done
	 */
	ret = 0;
	goto out;

fail6:
	kfree(new_cmdline);
fail5:
	lcd_unmap_phys(fs_mem_gpa, fs_mem_order);
fail4:
	lcd_unmap_virt(data_gva, mem_order);
fail3:
fail2:
	lcd_cap_delete(data_cptr);
	lcd_cap_delete(fs_mem_cptr);
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	/*
	 * Respond with ref to remote's dentry
	 */
	if (dentry_container)
		fipc_set_reg0(response, cptr_val(dentry_container->their_ref));
	else
		fipc_set_reg0(response, cptr_val(CAP_CPTR_NULL));

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int file_system_type_kill_sb_callee(struct fipc_message *request,
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct file_system_type_container *fs_container;
	struct super_block_container *sb_container;
	int ret;
	struct fipc_message *response;
	cptr_t fs_ref = __cptr(fipc_get_reg0(request));
	cptr_t sb_ref = __cptr(fipc_get_reg1(request));
	uint32_t request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	/*
	 * Bind on fs type and super_block
	 */
	ret = glue_cap_lookup_file_system_type_type(cspace,
						fs_ref,
						&fs_container);
	if (ret) {
		LIBLCD_ERR("couldn't find fs type");
		goto fail1;
	}
	ret = glue_cap_lookup_super_block_type(cspace,
					sb_ref,
					&sb_container);
	if (ret) {
		LIBLCD_ERR("couldn't find super_block");
		goto fail2;
	}
	/*
	 * Invoke real function (will call kill_anon_super)
	 */
	fs_container->file_system_type.kill_sb(&sb_container->super_block);
	/*
	 * Remove our sb container from cspace, and free it.
	 */
	glue_cap_remove(cspace, sb_container->my_ref);
	kfree(sb_container);
	/*
	 * Nothing to reply with
	 */
	goto out;

fail2:
fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	/* empty reply */

	thc_ipc_reply(channel, request_cookie, response);

	pmfs_done = 1;

	return ret;
}

/* Stolen from part of pmfs/super.c:pmfs_put_super */
static void do_unmap(void *virt_addr, u64 size)
{
	gpa_t fs_mem_gpa;
	cptr_t fs_mem_cptr;
	int ret;
	unsigned long unused1, unused2;

	if (virt_addr) {
		/*
		 * Translate fs mem gva -> gpa
		 */
		fs_mem_gpa = isolated_lcd_gva2gpa(
			__gva((unsigned long)virt_addr));
		/*
		 * Look up capability for fs mem
		 */
		ret = lcd_phys_to_cptr(fs_mem_gpa, &fs_mem_cptr, &unused1,
				&unused2);
		if (ret) {
			LIBLCD_ERR("failed to resolve phys to cptr");
			fs_mem_cptr = CAP_CPTR_NULL;
		}
		/*
		 * Unmap the memory from our address space
		 */
		lcd_unmap_phys(fs_mem_gpa, ilog2(size >> PAGE_SHIFT));
		/*
		 * Delete our capability
		 */
		if (!cptr_is_null(fs_mem_cptr))
			lcd_cap_delete(fs_mem_cptr);
	}
}

int super_block_put_super_callee(struct fipc_message *request,
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct super_block_container *sb_container;
	int ret;
	struct fipc_message *response;
	cptr_t sb_ref = __cptr(fipc_get_reg0(request));
	uint32_t request_cookie = thc_get_request_cookie(request);
	void *virt_addr;
	u64 size;

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/*
	 * Bind on super_block
	 */
	ret = glue_cap_lookup_super_block_type(cspace,
					sb_ref,
					&sb_container);
	if (ret) {
		LIBLCD_ERR("couldn't find super block");
		goto fail1;
	}
	/*
	 * Get the info we need to do the unmap. These data structures
	 * are going to go bye-bye during put_super.
	 */
	virt_addr = PMFS_SB(&sb_container->super_block)->virt_addr;
	size = le64_to_cpu(pmfs_get_super(&sb_container->super_block)->s_size);
	/*
	 * Invoke real function (this doesn't kill the struct sb yet; not
	 * until fs type -> kill_sb). This will call iounmap, which does
	 * nothing (the real unmap follows).
	 */
	sb_container->super_block.s_op->put_super(&sb_container->super_block);
	/*
	 * Unmap fs memory and delete cap
	 */
	do_unmap(virt_addr, size);
	/*
	 * Nothing to reply with
	 */
	ret = 0;
	goto out;

fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	/* empty reply */

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}
