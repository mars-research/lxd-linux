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
 * register_filesystem rpc). */
static cptr_t vfs_chnl;
static struct glue_cspace *vfs_cspace;
static struct thc_channel_group *group;

/* For simplicity, we use the same async channel for rpc's in both
 * directions (to and from vfs). For this reason, these variables need
 * to be globals. (Yes, for the specific glue code below, we could maybe
 * tuck these away in some container structs that are passed in as arguments.
 * But in general - think of a function that only takes scalar args - the
 * channel for doing rpc's *to* the vfs needs to be a global.) */
static cptr_t pmfs_sync_endpoint;
static struct fipc_ring_channel *pmfs_async_chnl;
static struct thc_channel_group_item *pmfs_async_chnl_group_item;

/* GLUE SUPPORT CODE -------------------------------------------------- */

int glue_vfs_init(cptr_t _vfs_channel, struct thc_channel_group *_group)
{
	int ret;
	/*
	 * Store ref to group and channel so we can access them later,
	 * in register/unregister filesystem.
	 */
	group = _group;
	vfs_chnl = _vfs_channel;
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
			struct fipc_ring_channel **chnl_out,
			struct thc_channel_group_item **chnl_group_item_out)
{
	int ret;
	cptr_t buf1_cptr, buf2_cptr;
	gva_t buf1_addr, buf2_addr;
	struct fipc_ring_channel *chnl;
	struct thc_channel_group_item *chnl_group_item;
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
	ret = fipc_prep_buffers(ASYNC_RPC_EXAMPLE_BUFFER_ORDER,
				(void *)gva_val(buf1_addr),
				(void *)gva_val(buf2_addr));
	if (ret) {
		LIBLCD_ERR("prep buffers");
		goto fail5;
	}
	/*
	 * Alloc and init channel header
	 */
	chnl = kmalloc(sizeof(*chnl), GFP_KERNEL);
	if (!chnl) {
		ret = -ENOMEM;
		LIBLCD_ERR("chnl alloc");
		goto fail6;
	}
	ret = fipc_ring_channel_init(chnl, ASYNC_RPC_EXAMPLE_BUFFER_ORDER,
				(void *)gva_val(buf1_addr),
				(void *)gva_val(buf2_addr));
	if (ret) {
		LIBLCD_ERR("ring chnl init");
		goto fail7;
	}
	/*
	 * Install async channel in async dispatch loop
	 */
	chnl_group_item = kzalloc(sizeof(*chnl_group_item), GFP_KERNEL);
	if (!chnl_group_item) {
		ret = -ENOMEM;
		LIBLCD_ERR("alloc failed");
		goto fail8;
	}
	ret = thc_channel_group_item_add(group,	chnl_group_item);
	if (ret) {
		LIBLCD_ERR("group item add failed");
		goto fail9;
	}

	*buf1_cptr_out = buf1_cptr;
	*buf2_cptr_out = buf2_cptr;
	*chnl_out = chnl;
	*chnl_group_item_out = chnl_group_item;

	return 0;

fail9:
	kfree(chnl_group_item);
fail8:
fail7:
	kfree(chnl);
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

static void destroy_async_channel(struct fipc_ring_channel *chnl,
				struct thc_channel_group_item *chnl_group_item)
{
	unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
	gva_t tx_gva, rx_gva;
	cptr_t tx, rx;
	int ret;
	unsigned long unused1, unused2;
	/*
	 * Translate ring buffers to cptrs
	 */
	tx_gva = __gva((unsigned long)chnl->tx.buffer);
	rx_gva = __gva((unsigned long)chnl->rx.buffer);
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
	kfree(chnl);
	/*
	 * Remove and free async channel group item
	 */
	if (chnl_group_item) {
		thc_channel_group_item_remove(group, chnl_group_item);
		kfree(chnl_group_item);
	}

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
	/*
	 * Set up async and sync channels
	 */
	ret = lcd_create_sync_endpoint(&pmfs_sync_endpoint);
	if (ret) {
		LIBLCD_ERR("lcd_create_sync_endpoint");
		goto fail1;
	}
	ret = setup_async_channel(&tx, &rx, &pmfs_async_chnl, 
				&pmfs_async_chnl_group_item);
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
	lcd_set_r0(REGISTER_FS);
	lcd_set_r1(cptr_val(fs_container->my_ref));
	lcd_set_r2(cptr_val(module_container->my_ref));
	lcd_set_cr0(pmfs_sync_endpoint);
	lcd_set_cr1(rx);
	lcd_set_cr2(tx);

	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("lcd_call");
		goto fail5;
	}
	/*
	 * Flush cap registers
	 */
	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);
	lcd_set_cr2(CAP_CPTR_NULL);
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

	return ret;

fail6:
fail5:
	glue_cap_remove(vfs_cspace, module_container->my_ref);
fail4:
	glue_cap_remove(vfs_cspace, fs_container->my_ref);
fail3:
	destroy_async_channel(pmfs_async_chnl, pmfs_async_chnl_group_item);
fail2:
	lcd_cap_delete(pmfs_sync_endpoint);
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
	ret = async_msg_blocking_send_start(pmfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}
	async_msg_set_fn_type(request, UNREGISTER_FS);
	fipc_set_reg0(request, cptr_val(fs_container->their_ref));
	fipc_set_reg1(request, cptr_val(module_container->their_ref));

	ret = thc_ipc_call(pmfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("async call failed");
		goto fail2;
	}
	/*
	 * Just expecting int ret value in response
	 */
	ret = fipc_get_reg0(response);
	fipc_recv_msg_end(pmfs_async_chnl, response);
	/*
	 * Tear down.
	 *
	 * Destroy sync endpoint and async channel
	 */
	lcd_cap_delete(pmfs_sync_endpoint);
	destroy_async_channel(pmfs_async_chnl);
	/*
	 * Remove fs type and module from data store
	 */
	glue_cap_remove(vfs_cspace, fs_container->my_ref);
	glue_cap_remove(vfs_cspace, module_container->my_ref);
	/*
	 * Pass back return value
	 */
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
	ret = async_msg_blocking_send_start(pmfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail2;
	}

	async_msg_set_fn_type(request, BDI_INIT);
	fipc_set_reg0(request, cptr_val(bdi_container->my_ref));
	fipc_set_reg1(request, bdi_container->backing_dev_info.ra_pages);
	fipc_set_reg2(request, bdi_container->backing_dev_info.capabilities);

	ret = thc_ipc_call(pmfs_async_chnl, request, &response);
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
	fipc_send_msg_end(pmfs_async_chnl, request);
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
	ret = async_msg_blocking_send_start(pmfs_async_chnl, &request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, BDI_DESTROY);
	fipc_set_reg0(request, cptr_val(bdi_container->my_ref));

	ret = thc_ipc_call(pmfs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending msg");
		goto fail2;
	}
	/*
	 * Nothing is in response
	 */
	fipc_recv_msg_end(pmfs_async_chnl, response);
	/*
	 * Remove bdi obj from cspace
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
	inode_container->pmfs_inode_vfs.vfs_inode.i_state = lcd_r1();
	inode_container->pmfs_inode_vfs.vfs_inode.i_nlink = lcd_r2();
	inode_container->pmfs_inode_vfs.vfs_inode.i_mode = lcd_r3();
	/*
	 * We also know that i_mapping -> i_data, at least for pmfs. (So
	 * although i_mapping is a pointer, the data it points to is embedded
	 * in the struct inode.)
	 */
	inode_container->pmfs_inode_vfs.vfs_inode.i_mapping =
		&inode_container->pmfs_inode_vfs.vfs_inode.i_data;
	/*
	 * We also need to set back pointer to super block (this is done
	 * by the callee)
	 */
	inode_container->pmfs_inode_vfs.vfs_inode.i_sb = sb;
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
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * At least for pmfs, we know that mapping points to
	 * i_data for the corresponding inode. So, we resolve ...
	 */
	inode_container = container_of(
		container_of(
			container_of(mapping, struct inode, i_data)
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	/*
	 * We now pass the ref to the inode (instead), and do rpc.
	 */
	lcd_set_r0(TRUNCATE_INODE_PAGES);
	lcd_set_r1(cptr_val(inode_container->their_ref));
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

void iget_failed(struct inode *inode)
{
	struct inode_container *inode_container;
	int ret;
	/*
	 * Get remote ref, do rpc. (This will ultimately free the inode.)
	 */
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);

	lcd_set_r0(IGET_FAILED);
	lcd_set_r1(cptr_val(inode_container->their_ref));
	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("iget_failed failed");
		goto fail1;
	}
	/*
	 * Nothing in reply
	 */
	goto out;

out:
fail1:
	return;
}

void unlock_new_inode(struct inode *inode)
{
	struct pmfs_inode_vfs_container *inode_container;
	/*
	 * Get remote ref, and do rpc.
	 */
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	
	lcd_set_r0(UNLOCK_NEW_INODE);
	lcd_set_r1(cptr_val(inode_container->their_ref));

	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("call failed");
		goto fail1;
	}
	/*
	 * Get updated i_state
	 */
	inode_container->pmfs_inode_vfs.vfs_inode.i_state = lcd_r0();

	goto out;

out:
fail1:
	return;
}

struct dentry *
d_make_root(struct inode *inode)
{
	struct pmfs_inode_vfs_container *inode_container;
	struct dentry_container *dentry_container;
	int ret;
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
	 * Set up links to other private objects
	 */
	dentry_container->dentry.d_sb = inode->i_sb;
	dentry_container->dentry.d_inode = inode;
	/*
	 * Do rpc
	 */
	lcd_set_r0(D_MAKE_ROOT);
	lcd_set_r1(cptr_val(inode_container->their_ref));
	lcd_set_r2(inode_container->pmfs_inode_vfs.vfs_inode.i_nlinks);
	lcd_set_r3(cptr_val(dentry_container->my_ref));
	
	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("call failed");
		goto fail3;
	}
	/*
	 * Get remote ref to dentry in response
	 */
	if (cap_cptr_is_null(__cptr(lcd_r0()))) {
		LIBLCD_ERR("got null from d_make_root");
		goto fail4;
	}
	dentry_container->their_ref = __cptr(lcd_r0());
	
	return &dentry_container->dentry;

fail4:
fail3:
	glue_cap_remove(dentry_container->my_ref);
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
	cptr_t dentry_ref;
	int ret;
	cptr_t data_cptr;
	unsigned long data_offset;
	unsigned long mem_sz;
	struct dentry *dentry = NULL;
	
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
	 * Do rpc
	 */
	lcd_set_r0(MOUNT_NODEV);
	lcd_set_r1(cptr_val(fs_container->their_ref));
	/* Assumes mem_sz is 2^x pages */
	lcd_set_r2(ilog2(mem_sz >> PAGE_SHIFT));
	lcd_set_r3(data_offset);
	lcd_set_cr0(cptr_val(data_cptr));
	lcd_set_r4(flags);
	lcd_set_r5(cptr_val(fill_sup_container->my_ref));

	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("failed to do call");
		goto fail4;
	}
	/*
	 * Unmarshal returned dentry
	 */
	dentry_ref = __cptr(lcd_r0());
	if (cap_cptr_is_null(dentry_ref)) {
		LIBLCD_ERR("got null from remote mount_nodev");
		goto fail5;
	}
	ret = glue_cap_lookup_dentry_type(vfs_cspace,
					dentry_ref,
					&dentry_container);
	if (ret) {
		LIBLCD_ERR("couldn't find dentry");
		goto fail6;
	}
	dentry = &dentry_container->dentry;
	/*
	 * Free fill_super container, etc.
	 */
	glue_cap_remove(vfs_cspace, fill_sup_container->my_ref);
	kfree(fill_sup_container);
	/*
	 * Done
	 */
	goto out;

fail6:
fail5:
fail4:
	glue_cap_remove(vfs_cspace, fill_sup_container->my_ref);
fail3:
	kfree(fill_sup_container);
fail2:
fail1:
out:
	return dentry;
}

void kill_anon_super(struct super_block *sb)
{
	struct super_block_container *sb_container;
	int ret;
	/*
	 * Do rpc, passing remote ref to super_block
	 */
	container_of(sb,
		struct super_block_container,
		super_block);
	lcd_set_r0(KILL_ANON_SUPER);
	lcd_set_r1(cptr_val(sb_container->their_ref));
	
	ret = lcd_sync_call(vfs_chnl);
	if (ret) {
		LIBLCD_ERR("call failed");
		goto fail1;
	}
	/*
	 * Nothing in reply
	 */
	goto out;

fail1:
out:
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

int super_block_evict_inode_callee(void)
{
	struct super_block_container *sb_container;
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * Look up private copies of super block and inode
	 */
	ret = glue_cap_lookup_super_block_type(vfs_cspace,
					__cptr(lcd_r1()),
					&sb_container);
	if (ret) {
		LIBLCD_ERR("super block not found");
		goto fail1;
	}
	ret = glue_cap_lookup_pmfs_inode_vfs_type(vfs_cspace,
					__cptr(lcd_r2()),
					&inode_container);
	if (ret) {
		LIBLCD_ERR("inode not found");
		goto fail2;
	}
	/*
	 * Invoke real evict inode
	 */
	sb_container->super_block->s_op->evict_inode(
		&inode_container->pmfs_inode_vfs.vfs_inode
		);
	/*
	 * Nothing to reply with
	 */
	ret = 0;
	goto out;

out:
fail2:
fail1:
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

int mount_nodev_fill_super_callee(void)
{
	struct mount_nodev_fill_super_container *fill_sup_container;
	struct super_block_container *sb_container;
	struct dentry_container *dentry_container;
	cptr_t data_cptr;
	gva_t data_gva;
	unsigned int mem_order;
	int ret;
	/*
	 * Bind on fill_super function pointer
	 */
	ret = glue_cap_lookup_mount_nodev_fill_super_type(vfs_cspace,
							__cptr(lcd_r1()),
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
	ret = glue_cap_insert_super_block_type(vfs_cspace,
					sb_container,
					&sb_container->my_ref);
	if (ret) {
		LIBLCD_ERR("super block ref");
		goto fail3;
	}
	sb_container->their_ref = __cptr(lcd_r2());
	sb_container->super_block.flags = lcd_r3();
	/*
	 * void *data arg is passed as a string. We expect:
	 *
	 *    -- data mem ctpr in cr0
	 *    -- mem order in r4
	 *    -- data offset in r5
	 */
	data_cptr = lcd_cr0();
	mem_order = lcd_r4();
	ret = lcd_map_virt(data_cptr, mem_order, &data_gva);
	if (ret) {
		LIBLCD_ERR("error mapping void *data");
		goto fail4;
	}
	/*
	 * Invoke real function. ("int silent" arg is in r6.)
	 */
	ret = fill_sup_container->fill_super(&sb_container->super_block,
					(void *)(gva_val(data_gva) + lcd_r5()),
					lcd_r6());
	if (ret) {
		LIBLCD_ERR("fill super failed");
		goto fail5;
	}
	/*
	 * Reply with our super_block ref, new s_flags, and
	 * ref to s_root dentry (so caller can set s_root to their
	 * private dentry copy).
	 */
	dentry_container = container_of(
		&sb_container->super_block.s_root,
		struct dentry_container,
		dentry);
	lcd_set_r1(cptr_val(sb_container->my_ref));
	lcd_set_r2(sb_container->super_block.flags);
	lcd_set_r3(cptr_val(dentry_container->their_ref));
	/*
	 * Unmap void *data, and delete from our cspace.
	 */
	lcd_unmap_virt(data_gva, mem_order);

	ret = 0;
	goto out;


fail5:
	lcd_unmap_virt(data_gva, mem_order);
fail4:
	glue_cap_remove(vfs_cspace,
			sb_container->my_ref);
fail3:
	kfree(sb_container);
fail2:
fail1:
out:
	lcd_cap_delete(data_cptr);

	lcd_set_r0(ret);

	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");

	return ret;
}

static void *update_cmdline(char *old_cmdline, gpa_t new_fs_mem_gpa)
{
	int ret;
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
	 * Skim over old physaddr
	 */
	simple_strtoull(old_cmdline, &old_cmdline, 0);
	/*
	 * Create new dup of cmdline, but with new physaddr
	 */
	new_cmdline = kzalloc(strlen(old_cmdline) + 9 + 18 + 1, GFP_KERNEL);
	if (!new_cmdline) {
		LIBLCD_ERR("kzalloc failed");
		return NULL;
	}
	snprintf(new_cmdline, strlen(old_cmdline) + 9 + 16 + 1,
		"physaddr=0x%016lx,%s", gpa_val(new_fs_mem_gpa),
		old_cmdline);

	return (void *)new_cmdline;
}

int file_system_type_mount_callee(void)
{
	struct file_system_type_container *fs_container;
	struct dentry_container *dentry_container;
	struct dentry *dentry;
	cptr_t data_cptr;
	unsigned int mem_order;
	unsigned long data_offset;
	gva_t data_gva;
	void *new_cmdline;
	int flags;
	cptr_t dentry_ref = CAP_CPTR_NULL;
	cptr_t fs_mem_cptr;
	unsigned int fs_mem_order;
	gpa_t fs_mem_gpa;
	/*
	 * Unmarshal args. We expect:
	 *
	 *       -- fs type ref
	 * XXX:  -- nothing for dev_name (pmfs doesn't use it)
	 *       -- flags
	 *       -- void *data stuff
	 *       -- cap to memory for fs
	 */
	ret = glue_cap_lookup_file_system_type_type(vfs_cspace,
						__cptr(lcd_r1()),
						&fs_container);
	if (ret) {
		LIBLCD_ERR("couldn't find fs type");
		goto fail1;
	}
	flags = lcd_r2();
	/*
	 * Map void *data
	 */
	data_cptr = lcd_cr0();
	mem_order = lcd_r3();
	data_offset = lcd_r4();
	
	ret = lcd_map_virt(data_cptr, mem_order, &data_gva);
	if (ret) {
		LIBLCD_ERR("couldn't map void *data arg");
		goto fail2;
	}
	/*
	 * Map fs memory
	 */
	fs_mem_cptr = lcd_cr1();
	fs_mem_order = lcd_r5();

	ret = lcd_map_phys(fs_mem_cptr, fs_mem_order, &fs_mem_gpa);
	if (ret) {
		LIBLCD_ERR("error mapping fs memory");
		goto fail3;
	}
	/*
	 * Update cmd line args with new gpa
	 */
	new_cmdline = update_cmdline((char *)(gva_val(data_gva) + data_offset),
				fs_mem_gpa);
	if (!new_cmdline) {
		LIBLCD_ERR("failed to update cmdline");
		goto fail4;
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
		goto fail5;
	}
	dentry_container = container_of(dentry,
					struct dentry_container,
					dentry);
	dentry_ref = dentry_container->their_ref;
	/*
	 * Kill void *data stuff
	 */
	lcd_unmap_virt(data_gva, mem_order);
	/*
	 * Free new_cmdline
	 */
	kfree(new_cmdline);
	/*
	 * Done
	 */
	ret = 0;
	goto out;

fail5:
	kfree(new_cmdline);
fail4:
	lcd_unmap_virt(fs_mem_gva, fs_mem_order);
fail3:
	lcd_unmap_virt(data_gva, mem_order);
fail2:
fail1:
out:
	lcd_cap_delete(data_cptr);

	lcd_set_r0(cptr_val(dentry_ref));

	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

int file_system_type_kill_sb_callee(void)
{
	struct file_system_type_container *fs_container;
	struct super_block_container *sb_container;
	int ret;
	/*
	 * Bind on fs type and super_block
	 */
	ret = glue_cap_lookup_file_system_type_type(vfs_cspace,
						__cptr(lcd_r1()),
						&fs_container);
	if (ret) {
		LIBLCD_ERR("couldn't find fs type");
		goto fail1;
	}
	ret = glue_cap_lookup_super_block_type(vfs_cspace,
					__cptr(lcd_r2()),
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
	glue_cap_remove(vfs_cspace, sb_container->my_ref);
	kfree(sb_container);
	/*
	 * Nothing to reply with
	 */
	goto out;

fail2:
fail1:
out:
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

/* Stolen from part of pmfs/super.c:pmfs_put_super */
static void do_unmap(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_super_block *ps = pmfs_get_super(sb);
	u64 size = le64_to_cpu(ps->s_size);
	gpa_t fs_mem_gpa;
	cptr_t fs_mem_cptr;
	int ret;
	unsigned long unused1, unused2;

	if (sbi->virt_addr) {
		/*
		 * Translate fs mem gva -> gpa
		 */
		fs_mem_gpa = isolated_lcd_gva2gpa(
			__gva((unsigned long)sbi->virt_addr));
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
		if (!cap_cptr_is_null(fs_mem_cptr))
			lcd_cap_delete(fs_mem_cptr);
	}
}

int super_block_put_super_callee(void)
{
	struct super_block_container *sb_container;
	int ret;
	/*
	 * Bind on super_block
	 */
	ret = glue_cap_lookup_super_block_type(vfs_cspace,
					__cptr(lcd_r1()),
					&sb_container);
	if (ret) {
		LIBLCD_ERR("couldn't find super block");
		goto fail1;
	}
	/*
	 * Invoke real function
	 */
	sb_container->super_block.s_op->put_super(&sb_container->super_block);
	/*
	 * Unmap fs memory and delete cap
	 */
	do_unmap(&sb_container->super_block);
	/*
	 * Nothing to reply with
	 */
	ret = 0;
	goto out;

fail1:
out:
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");

	return ret;
}
