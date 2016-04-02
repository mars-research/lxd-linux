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

static struct lcd_sync_channel_group_item vfs_channel_group_item;
static struct thc_channel_group *async_channel_group;

/* Right now, we don't have a mechanism for identifying which cspace
 * should be used when we receive a message. Sure, we could attach
 * cspaces to async ipc channels. Or we could use seL4-style badges.
 * Not clear. For now, we just assume only pmfs is interacting with
 * the vfs, and so there is only one cspace. This global is only
 * used in callee functions. For function pointers, we use the cspace
 * stored in the hidden args. */
static struct cspace *pmfs_cspace;

/* GLUE SUPPORT -------------------------------------------------- */

int glue_vfs_init(cptr_t vfs_chnl, 
		struct lcd_sync_channel_group *sync_channel_group,
		struct thc_channel_group *_async_channel_group)
{
	int ret;
	/*
	 * Set up sync ipc endpoint for register_filesystem
	 *
	 * We expect to be granted 3 cptrs:
	 *   -- sync endpoint capability
	 *   -- tx ring buffer memory capability
	 *   -- rx ring buffer memory capability
	 */
	lcd_sync_channel_group_item_init(&vfs_channel_group_item, vfs_chnl, 3,
					dispatch_vfs_channel);
	/*
	 * Store ref to async channel group so we can add async channels
	 * in register_filesystem_callee
	 */
	async_channel_group = _async_channel_group;
	/*
	 * Add it to sync channel group
	 */
	lcd_sync_channel_group_add(sync_channel_group, &vfs_channel_group_item);
	/*
	 * Initialize cap code
	 */
	ret = glue_cap_init();
	if (ret) {
		LIBLCD_ERR("cap init");
		goto fail1;
	}

	return 0;

fail1:
	return ret;
}

void glue_vfs_exit(struct lcd_sync_channel_group *sync_channel_group,
		struct thc_channel_group *_async_channel_group)
{
	/*
	 * Remove vfs channel from loop, and tear down cap code.
	 */
	lcd_sync_channel_group_remove(sync_channel_group, 
				&vfs_channel_group_item);
	glue_cap_exit();
}

static void destroy_async_fs_ring_channel(struct fipc_ring_channel *chnl,
					struct thc_channel_group_item *chnl_group_item)
{
	cptr_t tx, rx;
	gva_t tx_gva, rx_gva;
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
	thc_channel_group_item_remove(async_channel_group, chnl_group_item);
	kfree(chnl_group_item);
}

static int setup_async_fs_ring_channel(cptr_t tx, cptr_t rx, 
				struct fipc_ring_channel **chnl_out,
				struct thc_channel_group_item **chnl_group_item_out)
{
	gva_t tx_gva, rx_gva;
	int ret;
	struct fipc_ring_channel *chnl;
	struct thc_channel_group_item *chnl_group_item;
	unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
	/*
	 * Map tx and rx buffers (caller has already prep'd buffers)
	 */
	ret = lcd_map_virt(tx, pg_order, &tx_gva);
	if (ret) {
		LIBLCD_ERR("failed to map tx");
		goto fail1;
	}
	ret = lcd_map_virt(rx, pg_order, &rx_gva);
	if (ret) {
		LIBLCD_ERR("failed to map rx");
		goto fail2;
	}
	/*
	 * Alloc and init channel header
	 */
	chnl = kmalloc(sizeof(*chnl), GFP_KERNEL);
	if (!chnl) {
		ret = -ENOMEM;
		LIBLCD_ERR("malloc failed");
		goto fail3;
	}
	ret = fipc_ring_channel_init(chnl,
				PMFS_ASYNC_RPC_BUFFER_ORDER,
				/* (note: gva == hva for non-isolated) */
				(void *)gva_val(tx_gva),
				(void *)gva_val(rx_gva));
	if (ret) {
		LIBLCD_ERR("channel init failed");
		goto fail4;
	}
	/*
	 * Add to async channel group
	 */
	chnl_group_item = kzalloc(sizeof(*chnl_group_item), GFP_KERNEL);
	if (!chnl_group_item) {
		ret = -ENOMEM;
		LIBLCD_ERR("malloc failed");
		goto fail5;
	}
	ret = thc_channel_group_item_add(async_channel_group,
					chnl_group_item);
	if (ret) {
		LIBLCD_ERR("group item add failed");
		goto fail6;
	}

	*chnl_out = chnl;
	*chnl_group_item_out = chnl_group_item;
	return 0;

fail6:
	kfree(chnl_group_item);
fail5:
fail4:
	kfree(chnl);
fail3:
	lcd_unmap_virt(rx_gva, pg_order);
fail2:
	lcd_unmap_virt(tx_gva, pg_order);
fail1:
	return 0;
}

static void destroy_sb_trampolines(struct super_operations *s_ops);
static int setup_sb_trampolines(struct super_block_container *sb_container,
				struct glue_cspace *fs_cspace,
				cptr_t fs_sync_endpoint,
				struct fipc_ring_channel *fs_async_chnl);
static void destroy_fs_type_trampolines(
	struct file_system_type_container *fs_container);
static int setup_fs_type_trampolines(
	struct file_system_type_container *fs_container,
	struct glue_cspace *fs_cspace,
	cptr_t fs_sync_endpoint,
	struct fipc_ring_channel *fs_async_chnl);

/* TRAMPOLINES / FUNCTION POINTERS ---------------------------------------- */

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
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
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
	struct super_block_destroy_inode_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_destroy_inode_trampoline);

	super_block_destroy_inode_p = super_block_destroy_inode;

	super_block_destroy_inode_p(super_block,
				hidden_args->super_block_container,
				hidden_args->cspace,
				hidden_args->channel);
}

void
noinline
super_block_evict_inode(struct inode *inode,
			struct super_block_container *super_block_container,
			struct glue_cspace *cspace,
			cptr_t channel)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * Call remote evict inode
	 */
	inode_container = container_of(
		container_of(inode,
			struct pmfs_inode_vfs,
			vfs_inode),
		struct pmfs_inode_vfs_container,
		pmfs_inode_vfs);
	lcd_set_r0(SUPER_BLOCK_EVICT_INODE);
	lcd_set_r1(cptr_val(super_block_container->their_ref));
	lcd_set_r2(cptr_val(inode_container->their_ref));
	ret = lcd_sync_call(channel);
	if (ret) {
		LIBLCD_ERR("error calling remote evict inode");
		goto fail1;
	}

	/* Done */
	goto out;

out:
fail1:

	return;
}

LCD_TRAMPOLINE_DATA(super_block_evict_inode_trampoline);
void
LCD_TRAMPOLINE_LINKAGE(super_block_evict_inode_trampoline)
super_block_evict_inode_trampoline(struct inode *inode)
{
	void (*volatile super_block_evict_inode_p)(
		struct inode *,
		struct super_block_container *,
		struct glue_cspace *,
		cptr_t);
	struct super_block_evict_inode_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_evict_inode_trampoline);

	super_block_evict_inode_p = super_block_evict_inode;

	super_block_evict_inode_p(super_block,
				hidden_args->super_block_container,
				hidden_args->cspace,
				hidden_args->channel);
}

void
noinline
super_block_put_super(struct super_block *sb,
		struct super_block_container *super_block_container,
		struct glue_cspace *cspace,
		cptr_t channel)
{
	int ret;
	/*
	 * Call remote put_super
	 */
	lcd_set_r0(SUPER_BLOCK_PUT_SUPER);
	lcd_set_r1(cptr_val(super_block_container->their_ref));
	ret = lcd_sync_call(channel);
	if (ret) {
		LIBLCD_ERR("error calling remote put_super");
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

LCD_TRAMPOLINE_DATA(super_block_put_super_trampoline);
void
LCD_TRAMPOLINE_LINKAGE(super_block_put_super_trampoline)
super_block_put_super_trampoline(struct super_block *sb)
{
	void (*volatile super_block_put_super_p)(
		struct super_block *,
		struct super_block_container *,
		struct glue_cspace *,
		cptr_t);
	struct super_block_put_super_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_put_super_trampoline);

	super_block_put_super_p = super_block_put_super;

	super_block_put_super_p(super_block,
				hidden_args->super_block_container,
				hidden_args->cspace,
				hidden_args->channel);
}

int
noinline
mount_nodev_fill_super(struct super_block *sb,
		void *data,
		int silent,
		struct mount_nodev_fill_super_container *fill_sup_container,
		struct glue_cspace *cspace,
		cptr_t channel)
{
	struct super_block_container *sb_container;
	struct dentry_container *dentry_container;
	int ret;
	cptr_t data_cptr;
	unsigned long mem_sz;
	unsigned long data_offset;

	sb_container = container_of(
		sb,
		struct super_block_container,
		super_block);

	/*
	 * Set up super block trampolines
	 */
	ret = setup_sb_trampolines(sb_container);
	if (ret) {
		LIBLCD_ERR("error setting up sb trampolines");
		goto fail0;
	}
	/*
	 * Insert super block into cspace
	 */
	ret = glue_cap_insert_super_block_type(pmfs_cspace,
					sb_container,
					&sb_container->my_ref);
	if (ret) {
		LIBLCD_ERR("error inserting super block into cspace");
		goto fail1;
	}					
	/*
	 * Translate void *data into cptr, etc.
	 */
	ret = lcd_virt_to_cptr(__gva((unsigned long)data),
			&data_cptr,
			&mem_sz,
			&data_offset);
	if (ret) {
		LIBLCD_ERR("error resolving data -> cptr");
		goto fail2;
	}
	/*
	 * Marshal arguments
	 */
	lcd_set_r0(MOUNT_NODEV_FILL_SUPER);
	lcd_set_r1(cptr_val(fill_sup_container->their_ref));
	lcd_set_r2(cptr_val(sb_container->my_ref));
	lcd_set_r3(sb_container->super_block.s_flags);
	lcd_set_cr0(data_cptr);
	/* Assumes mem_sz is 2^x pages */
	lcd_set_r4(ilog2(mem_sz >> PAGE_SHIFT));
	lcd_set_r5(data_offset);
	lcd_set_r6(silent);
	/*
	 * Do rpc
	 */
	ret = lcd_sync_call(channel);
	if (ret) {
		LIBLCD_ERR("sync call failed");
		goto fail3;
	}
	/*
	 * Unmarshal response. We expect a remote ref to a dentry.
	 */
	if (lcd_r0()) {
		LIBLCD_ERR("remote fill_super failed");
		goto fail4;
	}
	ret = glue_cap_lookup_dentry_type(pmfs_cspace,
					__cptr(lcd_r3()),
					&dentry_container);
	if (ret) {
		LIBLCD_ERR("couldn't find dentry");
		goto fail5;
	}
	sb_container->their_ref = __cptr(lcd_r1());
	sb_container->super_block.flags = lcd_r2();
	sb_container->super_block.s_root = &dentry_container->dentry;
	/*
	 * Done
	 */
	ret = lcd_r0();
	goto out;

fail5:
	/* nothing we can really undo ... */
fail4:
fail3:
fail2:
fail1:
	destroy_sb_trampolines(sb_container->super_block.s_op);
fail0:
out:
	return ret;
}

LCD_TRAMPOLINE_DATA(mount_nodev_fill_super_trampoline);
int
LCD_TRAMPOLINE_LINKAGE(mount_nodev_fill_super_trampoline)
mount_nodev_fill_super_trampoline(struct super_block *super_block,
				void *data,
				int silent)
{
	int (*volatile mount_nodev_fill_super_p)(
		struct super_block *,
		void *,
		int,
		struct mount_nodev_fill_super_container *,
		struct glue_cspace *,
		cptr_t channel)
	struct mount_nodev_fill_super_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				mount_nodev_fill_super_trampoline);

	mount_nodev_fill_super_p = mount_nodev_fill_super;

	return mount_nodev_fill_super_p(super_block,
					data,
					silent,
					hidden_args->mount_nodev_fill_super_container,
					hidden_args->cspace,
					hidden_args->channel);
}

static int get_phys_addr(char *cmdline, unsigned long *phys_addr)
{
	/*
	 * Taken from pmfs/super.c. Looks like they assume
	 * physaddr is first mount option.
	 */
	if (!cmdline || strncmp(options, "physaddr=", 9) != 0)
		return -EINVAL;
	cmdline += 9;
	*phys_addr = (unsigned long)simple_strtoull(cmdline, &cmdline, 0);
	if ((*phys_addr) & (PAGE_SIZE - 1)) {
		LIBLCD_ERR("phys_addr not page aligned");
		return -EINVAL;
	}

	return 0;
}

/* adapted from pmfs/super.c:pmfs_parse_options */
static int get_size(char *cmdline, unsigned long *size)
{
	char *p, *rest;
	substring_t args[MAX_OPT_ARGS];
	match_table_t tokens = {
		{ 0,	     "init=%s"		  },
		{ 1,         NULL                 },
	};

	while ((p = strsep(&cmdline, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case 0:
			/* memparse() will accept a K/M/G without a digit */
			if (!isdigit(*args[0].from))
				return -EINVAL;
			*size = (unsigned long)memparse(args[0].from, &rest);
			return 0;
		default:
			break;
		}
	}
	/*
	 * No "init=" mount option. Fail.
	 */
	LIBLCD_ERR("no init= mount option?");
	return -EINVAL;
}

static int setup_fs_memory(char *cmdline, cptr_t *fs_mem_cptr,
			unsigned int *fs_mem_order)
{
	unsigned long phys_addr, size;
	unsigned int order;
	int ret;
	/*
	 * Parse cmdline to get phys address and size
	 */
	ret = get_phys_addr(cmdline, &phys_addr);
	if (ret) {
		LIBLCD_ERR("failed to get phys addr");
		goto fail1;
	}
	ret = get_size(cmdline, &size);
	if (ret) {
		LIBLCD_ERR("failed to get size");
		goto fail2;
	}
	size >>= PAGE_SHIFT;
	if (!size) {
		LIBLCD_ERR("size too small");
		ret = -EINVAL;
		goto fail3;
	}
	order = ilog2(size);
	if (size & ((1UL << order) - 1)) {
		LIBLCD_ERR("size not 2^x pages");
		ret = -EINVAL;
		goto fail4;
	}
	/*
	 * Volunteer fs memory
	 */
	*fs_mem_order = order;
	ret = lcd_volunteer_dev_mem(__gpa(phys_addr), order, fs_mem_cptr);
	if (ret) {
		LIBLCD_ERR("failed to volunteer fs mem");
		goto fail5;
	}
	/*
	 * Done
	 */
	return 0;

fail5:
fail4:
fail3:
fail2:
fail1:
	return ret;
}

static int setup_data(void *data, cptr_t *data_cptr, 
		unsigned int *mem_order, unsigned long *data_offset)
{
	int ret;
	struct page *p;
	unsigned long data_len;
	unsigned long mem_len;
	/*
	 * Determine page that contains (start of) data
	 */
	p = virt_to_head_page(data);
	if (!p) {
		LIBLCD_ERR("failed to translate to page");
		ret = -EINVAL;
		goto fail1;
	}
	data_len = strlen(data);
	mem_len = roundup_power_of_two(ALIGN(data + data_len - page_address(p),
								PAGE_SIZE));
	*mem_order = ilog2(mem_len >> PAGE_SHIFT);
	/*
	 * Volunteer memory
	 */
	*data_offset = data - page_address(p);
	ret = lcd_volunteer_pages(p, *mem_order, data_cptr);
	if (ret) {
		LIBLCD_ERR("failed to volunteer memory");
		goto fail2;
	}
	/*
	 * Done
	 */
	return 0;

fail2:
fail1:
	return ret;
}

struct dentry *
noinline
file_system_type_mount(struct file_system_type *fs_type,
		int flags,
		const char *dev_name,
		void *data,
		struct file_system_type_container *fs_container,
		struct glue_cspace *cspace,
		cptr_t channel)
{
	int ret;
	cptr_t dentry_ref;
	struct dentry *dentry = NULL;
	struct dentry_container *dentry_container;
	cptr_t data_cptr;
	unsigned int mem_order;
	unsigned long data_offset;
	cptr_t fs_mem_cptr;
	unsigned int fs_mem_order;
	/*
	 * Volunteer fs memory
	 */
	ret = setup_fs_memory(data, &fs_mem_cptr, &fs_mem_order);
	if (ret) {
		LIBLCD_ERR("failed to volunteer fs memory");
		goto fail0;
	}
	/*
	 * Volunteer memory that contains void *data
	 */
	ret = setup_data(data, &data_cptr, &mem_order, &data_offset);
	if (ret) {
		LIBLCD_ERR("error volunteering void *data arg");
		goto fail1;
	}
	/*
	 * Marshal:
	 *
	 *       -- fs type ref
	 *       -- flags
	 *       -- void *data stuff
	 * XXX:  -- skip dev_name (pmfs doesn't use it)
	 */
	lcd_set_r0(FILE_SYSTEM_TYPE_MOUNT);
	lcd_set_r1(cptr_val(fs_container->their_ref));
	lcd_set_r2(flags);
	lcd_set_cr0(data_cptr);
	lcd_set_r3(mem_order);
	lcd_set_r4(data_offset);
	/*
	 * Do rpc
	 */
	ret = lcd_sync_call(channel);
	if (ret) {
		LIBLCD_ERR("call error");
		goto fail2;
	}
	/*
	 * Unmarshal dentry
	 */
	ret = glue_cap_lookup_dentry_type(pmfs_cspace,
					__cptr(lcd_r0()),
					&dentry_container);
	if (ret) {
		LIBLCD_ERR("couldn't find dentry");
		goto fail3;
	}
	dentry = &dentry_container->dentry;
	/*
	 * Unvolunteer void *data
	 */
	lcd_cap_delete(data_cptr);
	/*
	 * Done
	 */
	goto out;

fail3:
fail2:
	lcd_cap_delete(data_cptr);
fail1:
	lcd_cap_delete(fs_mem_cptr);
fail0:
out:
	return dentry;
}

LCD_TRAMPOLINE_DATA(file_system_type_mount_trampoline);
struct dentry *
LCD_TRAMPOLINE_LINKAGE(file_system_type_mount_trampoline)
file_system_type_mount_trampoline(struct file_system_type *fs_type,
				int flags,
				const char *dev_name,
				void *data)
{
	struct dentry* (*volatile file_system_type_mount_p)(
		struct file_system_type *,
		int,
		const char *,
		void *,
		struct file_system_type_container *,
		struct glue_cspace *,
		cptr_t)
	struct file_system_type_mount_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				file_system_type_mount_trampoline);

	file_system_type_mount_p = file_system_type_mount;

	return file_system_type_mount_p(fs_type,
					flags,
					dev_name,
					data,
					hidden_args->file_system_type_container,
					hidden_args->cspace,
					hidden_args->channel);
}

void
noinline
file_system_type_kill_sb(struct super_block *sb,
		struct file_system_type_container *fs_container,
		struct glue_cspace *cspace,
		cptr_t channel)
{
	struct super_block_container *sb_container;
	struct super_operations *s_ops;
	cptr_t fs_mem_cptr;
	int ret;
	/*
	 * Get ref to s_op and fs mem before we kill the super_block, so we can
	 * tear down the trampolines *after* we call kill_sb. (We can't do
	 * it before, because some of the s_op's will be used in the body/
	 * call graph of kill_sb.)
	 */
	s_ops = sb->s_op;
	fs_mem_cptr = sb_container->fs_mem;
	/*
	 * Marshal refs to fs type and super block, and do rpc.
	 *
	 * sb_container will get freed in the process ...
	 */
	sb_container = container_of(sb,
				struct super_block_container,
				super_block);
	lcd_set_r0(FILE_SYSTEM_TYPE_KILL_SB);
	lcd_set_r1(cptr_val(fs_container->their_ref));
	lcd_set_r2(cptr_val(sb_container->their_ref));

	ret = lcd_sync_call(channel);
	if (ret) {
		LIBLCD_ERR("call failed");
		goto fail1;
	}
	/*
	 * sb_container is now invalid (was freed)
	 */
	sb_container = NULL;
	/*
	 * Destroy trampolines
	 */
	destroy_sb_trampolines(s_ops);
	/*
	 * Unvolunteer fs memory
	 */
	lcd_unvolunteer_dev_mem(fs_mem_cptr);
	/*
	 * Done
	 */
	goto out;

fail1:
out:
	return;
}

LCD_TRAMPOLINE_DATA(file_system_type_mount_trampoline);
struct dentry *
LCD_TRAMPOLINE_LINKAGE(file_system_type_mount_trampoline)
file_system_type_mount_trampoline(struct file_system_type *fs_type,
				int flags,
				const char *dev_name,
				void *data)
{
	struct dentry* (*volatile file_system_type_mount_p)(
		struct file_system_type *,
		int,
		const char *,
		void *,
		struct file_system_type_container *,
		struct glue_cspace *,
		cptr_t)
	struct file_system_type_mount_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				file_system_type_mount_trampoline);

	file_system_type_mount_p = file_system_type_mount;

	return file_system_type_mount_p(fs_type,
					flags,
					dev_name,
					data,
					hidden_args->file_system_type_container,
					hidden_args->cspace,
					hidden_args->channel);
}

/* TRAMPOLINE SETUP / TEARDOWN ---------------------------------------- */

static void setup_rest_of_args(struct trampoline_hidden_args *args,
			void *struct_container,
			struct glue_cspace *fs_cspace,
			cptr_t fs_sync_endpoint,
			struct fipc_ring_channel *fs_async_chnl)
{
	args->t_handle->hidden_args = args;
	args->struct_container = fs_container;
	args->fs_cspace = cspace;
	args->fs_sync_endpoint = fs_sync_endpoint;
	args->fs_async_chnl = fs_async_chnl;
}

static void destroy_sb_trampolines(struct super_operations *s_ops)
{
	struct trampoline_hidden_args *alloc_args,
		*destroy_args, *evict_args, *put_args;
	
	if (!s_ops)
		return;

	if (s_ops->alloc_inode) {
		alloc_args = LCD_TRAMPOLINE_TO_HIDDEN_ARGS(
			s_ops->alloc_inode);
		kfree(alloc_args->t_handle);
		kfree(alloc_args);
	}
	if (s_ops->destroy_inode) {
		destroy_args = LCD_TRAMPOLINE_TO_HIDDEN_ARGS(
			s_ops->destroy_inode);
		kfree(destroy_args->t_handle);
		kfree(destroy_args);
	}
	if (s_ops->evict_inode) {
		evict_args = LCD_TRAMPOLINE_TO_HIDDEN_ARGS(
			s_ops->evict_inode);
		kfree(evict_args->t_handle);
		kfree(evict_args);
	}
	if (s_ops->put_super) {
		put_args = LCD_TRAMPOLINE_TO_HIDDEN_ARGS(
			s_ops->put_super);
		kfree(put_args->t_handle);
		kfree(put_args);
	}

	kfree(s_ops);
}

static int setup_sb_trampolines(struct super_block_container *sb_container,
				struct glue_cspace *fs_cspace,
				cptr_t fs_sync_endpoint,
				struct fipc_ring_channel *fs_async_chnl)
{
	struct super_operations *s_ops;
	struct trampoline_hidden_args *alloc_args, *destroy_args,
		*evict_args, *put_args;
	int ret;
	/*
	 * Alloc struct of function pointers
	 */
	s_ops = kzalloc(sizeof(*s_ops), GFP_KERNEL);
	if (!s_ops) {
		LIBLCD_ERR("s_ops alloc failed");
		ret = -ENOMEM;
		goto fail0;
	}
	/*
	 * alloc_inode trampoline
	 */
	alloc_args = kzalloc(sizeof(*alloc_args), GFP_KERNEL);
	if (!alloc_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail1;
	}
	alloc_args->t_handle = LCD_DUP_TRAMPOLINE(
		super_block_alloc_inode_trampoline);
	if (!alloc_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(alloc_args);
		goto fail2;
	}
	setup_rest_of_args(alloc_args, sb_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	s_ops->alloc_inode =
		LCD_HANDLE_TO_TRAMPOLINE(alloc_args->t_handle);
	/*
	 * destroy_inode trampoline
	 */
	destroy_args = kzalloc(sizeof(*destroy_args), GFP_KERNEL);
	if (!destroy_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail3;
	}
	destroy_args->t_handle = LCD_DUP_TRAMPOLINE(
		super_block_destroy_inode_trampoline);
	if (!destroy_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(destroy_args);
		goto fail4;
	}
	setup_rest_of_args(destroy_args, sb_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	s_ops->destroy_inode =
		LCD_HANDLE_TO_TRAMPOLINE(destroy_args->t_handle);
	/*
	 * evict_inode trampoline
	 */
	evict_args = kzalloc(sizeof(*evict_args), GFP_KERNEL);
	if (!evict_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail5;
	}
	evict_args->t_handle = LCD_DUP_TRAMPOLINE(
		super_block_evict_inode_trampoline);
	if (!evict_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(evict_args);
		goto fail6;
	}
	setup_rest_of_args(evict_args, sb_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	s_ops->evict_inode =
		LCD_HANDLE_TO_TRAMPOLINE(evict_args->t_handle);
	/*
	 * put_super trampoline
	 */
	put_args = kzalloc(sizeof(*put_args), GFP_KERNEL);
	if (!put_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail7;
	}
	put_args->t_handle = LCD_DUP_TRAMPOLINE(
		super_block_put_super_trampoline);
	if (!put_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(put_args);
		goto fail8;
	}
	setup_rest_of_args(put_args, sb_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	s_ops->put_super =
		LCD_HANDLE_TO_TRAMPOLINE(put_args->t_handle);
	/*
	 * Install ops
	 */
	sb_container->super_block.s_op = s_ops;
	
	return 0;

fail8:
fail7:
fail6:
fail5:
fail4:
fail3:
fail2:
fail1:
	destroy_sb_trampolines(sb_container->super_block.s_op);
	return ret;
}

static void destroy_fs_type_trampolines(
	struct file_system_type_container *fs_container)
{
	struct trampoline_hidden_args *mount_args, *kill_sb_args;

	if (fs_container->file_system_type.mount) {
		mount_args = LCD_TRAMPOLINE_TO_HIDDEN_ARGS(
			fs_container->file_system_type.mount);
		kfree(mount_args->t_handle);
		kfree(mount_args);
	}
	if (fs_container->file_system_type.kill_sb) {
		kill_sb_args = LCD_TRAMPOLINE_TO_HIDDEN_ARGS(
			fs_container->file_system_type.kill_sb);
		kfree(kill_sb_args->t_handle);
		kfree(kill_sb_args);
	}
}

static int setup_fs_type_trampolines(
	struct file_system_type_container *fs_container,
	struct glue_cspace *fs_cspace,
	cptr_t fs_sync_endpoint,
	struct fipc_ring_channel *fs_async_chnl)
{
	struct trampoline_hidden_args *mount_args, *kill_sb_args;
	/*
	 * mount trampoline
	 */
	mount_args = kzalloc(sizeof(*mount_args), GFP_KERNEL);
	if (!mount_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail1;
	}
	mount_args->t_handle = LCD_DUP_TRAMPOLINE(
		file_system_type_mount_trampoline);
	if (!mount_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(mount_args);
		goto fail2;
	}
	setup_rest_of_args(mount_args, fs_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	fs_container->file_system_type.mount = 
		LCD_HANDLE_TO_TRAMPOLINE(mount_args->t_handle);
	/*
	 * kill_sb trampoline
	 */
	kill_sb_args = kzalloc(sizeof(*kill_sb_args), GFP_KERNEL);
	if (!kill_sb_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail3;
	}
	kill_sb_args->t_handle = LCD_DUP_TRAMPOLINE(
		file_system_type_kill_sb_trampoline);
	if (!kill_sb_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(kill_sb_args);
		goto fail4;
	}
	setup_rest_of_args(kill_sb_args, fs_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	fs_container->file_system_type.kill_sb = 
		LCD_HANDLE_TO_TRAMPOLINE(kill_sb_args->t_handle);
	/*
	 * Done
	 */
	return 0;

fail4:
fail3:
fail2:
fail1:
	destroy_fs_type_trampolines(fs_container);
	return ret;
}
	
/* CALLEE FUNCTIONS -------------------------------------------------- */

int register_filesystem_callee(void)
{
	struct file_system_type_container *fs_container;
	struct module_container *module_container;
	int ret;
	cptr_t fs_sync_endpoint;
	cptr_t tx, rx;
	struct fipc_ring_channel *chnl;
	struct thc_channel_group_item *chnl_group_item;
	/*
	 * Set up a cspace for fs remote refs
	 */
	ret = glue_cap_create(&pmfs_cspace);
	if (ret) {
		LIBLCD_ERR("failed to create glue cspace");
		goto fail0;
	}
	/*
	 * Set up our containers (callee alloc)
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
	/*
	 * Unmarshal data:
	 *
	 *    -- r1: fs type ref
	 *    -- r2: module ref
	 *    -- cr0: cap to pmfs_sync_endpoint
	 *    -- cr1: our tx ring buffer
	 *    -- cr2: our rx ring buffer
	 *
	 * XXX: We don't bother passing fs name for now. Just hard code
	 * it to "pmfs".
	 */
	fs_container->their_ref = __cptr(lcd_r1());
	fs_container->file_system_type.name = "pmfs";
	module_container->their_ref = __cptr(lcd_r2());
	fs_sync_endpoint = lcd_cr0();
	tx = lcd_cr1();
	rx = lcd_cr2();
	/*
	 * Set up object linkage
	 */
	fs_container->file_system_type.owner = &module_container->module;
	/*
	 * Set up async ring channel
	 */
	ret = setup_async_fs_ring_channel(tx, rx, &chnl, &chnl_group_item);
	if (ret) {
		LIBLCD_ERR("error setting up ring channel");
		goto fail5;
	}
	/*
	 * Store refs to fs-specific data so we can tear stuff down
	 * in unregister_filesystem.
	 */
	fs_container->fs_sync_endpoint = fs_sync_endpoint;
	fs_container->fs_async_chnl = chnl_group_item
	/*
	 * Set up fn pointer trampolines
	 */
	ret = setup_fs_type_trampolines(fs_container,
					pmfs_cspace,
					fs_sync_endpoint,
					chnl);
	if (ret) {
		LIBLCD_ERR("error setting up trampolines");
		goto fail6;
	}
	/*
	 * Call real function
	 */
	ret = register_filesystem(&fs_container->file_system_type);
	if (ret) {
		LIBLCD_ERR("register fs failed");
		goto fail7;
	}
	/*
	 * Reply with:
	 *
	 *   -- r0: register_fileystem return value
	 *   -- r1: ref to our fs type copy
	 *   -- r2: ref to our module
	 */
	lcd_set_r1(cptr_val(fs_container->my_ref));
	lcd_set_r2(cptr_val(module_container->my_ref));
	
	goto out;

fail7:
	destroy_fs_type_trampolines(fs_container);
fail6:
	destroy_async_fs_ring_channel(chnl, chnl_group_item);
fail5:
	glue_cap_remove(pmfs_cspace, module_container->my_ref);
fail4:
	kfree(module_container);
fail3:
	glue_cap_remove(pmfs_cspace, fs_container->my_ref);
fail2:
	kfree(fs_container);
fail1:
	glue_cap_destroy(pmfs_cspace);
fail0:
	lcd_cap_delete(lcd_cr0());
	lcd_cap_delete(lcd_cr1());
	lcd_cap_delete(lcd_cr2());
out:
	/*
	 * Flush capability registers
	 */
	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);
	lcd_set_cr2(CAP_CPTR_NULL);

	lcd_set_r0(ret);

	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

int unregister_filesystem_callee(struct fipc_message *request,
				struct fipc_ring_channel *channel)
{
	struct file_system_type_container *fs_container;
	struct module_container *module_container;
	int ret;
	cptr_t fs_ref, m_ref;
	struct fipc_message *response;
	/*
	 * Unmarshal refs:
	 *
	 *   -- fs ref
	 *   -- module ref
	 */
	fs_ref = __cptr(fipc_get_reg0(msg));
	m_ref = __cptr(fipc_get_reg1(msg));
	ret = fipc_recv_msg_end(channel, request);
	if (ret) {
		LIBLCD_ERR("failed to mark msg as recvd");
		goto fail1;
	}
	/*
	 * Bind
	 */
	ret = glue_cap_lookup_file_system_type_type(
		pmfs_cspace,
		fs_ref,
		&fs_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail2;
	}
	ret = glue_cap_lookup_module_type(
		pmfs_cspace,
		m_ref,
		&module_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail3;
	}
	/*
	 * Invoke real function, get return value
	 */
	ret = unregister_filesystem(&fs_container->file_system_type);
	if (ret) {
		LIBLCD_ERR("unregister fs");
		goto fail4;
	}
	/*
	 * Tear down everything
	 */
	destroy_fs_type_trampolines(fs_container);
	lcd_cap_delete(fs_container->fs_sync_endpoint);
	destroy_async_fs_ring_channel(fs_container->fs_async_chnl->channel,
				fs_container->fs_async_chnl);
	glue_cap_remove(fs_container->pmfs_cspace, fs_container->my_ref);
	glue_cap_remove(fs_container->pmfs_cspace, module_container->my_ref);
	glue_cap_destroy(pmfs_cspace);
	kfree(fs_container);
	kfree(module_container);
	/*
	 * Reply 
	 */
	goto out;

fail4:
fail3:
fail2:
fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg0(response, ret);
	
	fipc_send_msg_end(channel, response);

	return ret;
}

int bdi_init_callee(struct fipc_message *request,
		struct fipc_ring_channel *channel)
{
	struct backing_dev_info_container *bdi_container;
	int ret;
	cptr_t bdi_obj_ref = CAP_CPTR_NULL;
	struct fipc_message *response;
	/*
	 * Set up our own private copy
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
		LIBLCD_ERR("cspace insert bdi container");
		goto fail2;
	}
	/*
	 * Unmarshal:
	 *
	 *   -- bdi object ref
	 *   -- bdi.ra_pages
	 *   -- bdi.capabilities
	 */
	bdi_container->their_ref = __cptr(fipc_get_reg0(request));
	bdi_container->backing_dev_info.ra_pages = fipc_get_reg1(request);
	bdi_container->backing_dev_info.capabilities = fipc_get_reg2(request);
	fipc_recv_msg_end(channel, request);
	/*
	 * Invoke real function
	 */
	ret = bdi_init(&bdi_container->backing_dev_info);
	if (ret) {
		LIBLCD_ERR("bdi init failed");
		goto fail3;
	}
	/*
	 * Reply with return value and our ref
	 */
	bdi_obj_ref = bdi_container->my_ref;
	goto out;

fail3:
	glue_cap_remove(pmfs_cspace, bdi_container->my_ref);
fail2:
	kfree(bdi_container);
fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg0(response, ret);
	fipc_set_reg1(response, cptr_val(bdi_obj_ref));

	fipc_send_msg_end(channel, response);

	return ret;
}

int bdi_destroy_callee(struct fipc_message *request,
		struct fipc_ring_channel *channel)
{
	struct backing_dev_info_container *bdi_container;
	int ret;
	cptr_t ref;
	struct fipc_message *response;
	/*
	 * Unmarshal ref to our bdi obj copy, and bind.
	 */
	ref = __cptr(fipc_get_reg0(request));

	fipc_recv_msg_end(request, channel);

	ret = glue_cap_lookup_backing_dev_info_type(
		pmfs_cspace,
		ref,
		&bdi_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail2;
	}
	/*
	 * Invoke real function
	 */
	bdi_destroy(&bdi_container->backing_dev_info);
	/*
	 * Tear down container
	 */
	glue_cap_remove(pmfs_cspace, bdi_container->my_ref);
	kfree(bdi_container);

	ret = 0;
	goto out;

fail2:
fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	
	/* empty response */

	fipc_send_msg_end(channel, response);

	return ret;
}

int iget_locked_callee(struct fipc_message *request,
		struct fipc_ring_channel *channel)
{
	int ret;
	struct super_block_container *sb_container;
	struct inode *inode;
	struct pmfs_inode_vfs *inode_container = NULL;
	struct fipc_message *response;
	cptr_t sb_ref = __cptr(fipc_get_reg0(request));
	unsigned long ino = fipc_get_reg1(request);

	fipc_recv_msg_end(channel, request);
	/*
	 * Look up our private sb
	 */
	ret = glue_cap_lookup_super_block_type(pmfs_cspace,
					sb_ref,
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
	inode = iget_locked(&sb_container->super_block, ino);
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

	ret = 0;
	goto out;

fail2:
fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	/*
	 * Reply with remote ref for inode, and the following:
	 *
	 *     -- i_state
	 *     -- i_nlink
	 *     -- i_mode
	 */
	if (inode_container) {
		fipc_set_reg0(response, cptr_val(inode_container->their_ref));
		fipc_set_reg1(response, inode_container->inode.i_state);
		fipc_set_reg2(response, inode_container->inode.i_nlink);
		fipc_set_reg3(response, inode_container->inode.i_mode);
	} else {
		fipc_set_reg0(response, cptr_val(CAP_CPTR_NULL));
	}

	fipc_send_msg_end(channel, response);

	return ret;
}

int truncate_inode_pages_callee(struct fipc_message *request,
				struct fipc_ring_channel *channel)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	struct fipc_message *response;
	cptr_t inode_ref = __cptr(fipc_get_reg0(request));
	loff_t lstart = fipc_get_reg1(request);
	
	fipc_recv_msg_end(channel, request);

	/*
	 * (See notes for caller side)
	 *
	 * Look up our private inode object
	 */
	ret = glue_cap_lookup_inode_type(pmfs_cspace,
					inode_ref,
					&inode_container);
	if (ret) {
		LIBLCD_ERR("address space not found");
		goto fail1;
	}
	/*
	 * Invoke real function
	 */
	truncate_inode_pages(&inode_container->pmfs_inode_vfs.vfs_inode.i_data, 
			lstart);
	/*
	 * Reply with nothing
	 */
	ret = 0;
	goto out;

fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	
	/* empty response */

	fipc_send_msg_end(channel, response);

	return ret;
}

int clear_inode_callee(struct fipc_message *request,
		struct fipc_ring_channel *channel)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	cptr_t inode_ref = __cptr(fipc_get_reg0(request));
	struct fipc_message *response;

	fipc_recv_msg_end(channel, request);
	/*
	 * Look up our private copy of the inode object
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(pmfs_cspace,
						inode_ref,
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

fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	
	/* empty response */

	fipc_send_msg_end(channel, response);

	return ret;
}

int iget_failed_callee(struct fipc_message *request,
		struct fipc_ring_channel *channel)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	struct fipc_message *response;
	cptr_t inode_ref = __cptr(fipc_get_reg0(request));

	fipc_recv_msg_end(channel, request);

	/*
	 * Look up our inode obj
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(pmfs_cspace,
						inode_ref,
						&inode_container);
	if (ret) {
		LIBLCD_ERR("error looking up inode");
		goto fail1;
	}
	/*
	 * Invoke real function (this frees our private copy)
	 */
	iget_failed(&inode_container->pmfs_inode_vfs.vfs_inode);
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
	
	/* empty response */

	fipc_send_msg_end(channel, response);

	return ret;
}

int unlock_new_inode_callee(void)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	/*
	 * Look up our inode obj
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(pmfs_cspace,
						__cptr(lcd_r1()),
						&inode_container);
	if (ret) {
		LIBLCD_ERR("couldn't find inode");
		goto fail1;
	}
	/*
	 * Invoke real function
	 */
	unlock_new_inode(&inode_container->pmfs_inode_vfs.vfs_inode);
	/*
	 * Return new i_state
	 */
	lcd_set_r0(inode_container->pmfs_inode_vfs.vfs_inode.i_state);
	/*
	 * Reply
	 */
	ret = 0;
	goto out;

out:
fail1:
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

int d_make_root_callee(void)
{
	struct pmfs_inode_vfs_container *inode_container;
	struct dentry_container *dentry_container;
	struct dentry *dentry;
	int ret;
	cptr_t my_ref = CAP_CPTR_NULL;
	/*
	 * Get our inode obj
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(pmfs_cspace,
						__cptr(lcd_r1()),
						&inode_container);
	if (ret) {
		LIBLCD_ERR("couldn't find inode");
		goto fail1;
	}
	/*
	 * Update nlink
	 */
	inode_container->pmfs_inode_vfs.vfs_inode.i_nlink = lcd_r2();
	/*
	 * Call real function
	 */
	dentry = d_make_root(&inode_container->pmfs_inode_vfs.vfs_inode);
	if (!dentry) {
		LIBLCD_ERR("error making root dentry");
		goto fail2;
	}
	dentry_container = container_of(dentry,
					struct dentry_container,
					dentry);
	/*
	 * Install in cspace, set up refs
	 */
	ret = glue_cap_insert_dentry_type(pmfs_cspace,
					dentry_container,
					&dentry_container->my_ref);
	if (ret) {
		LIBLCD_ERR("error inserting in cspace");
		goto fail3;
	}
	my_ref = dentry_container->my_ref;
	dentry_container->their_ref = __cptr(lcd_r3());
	/*
	 * Reply with ref
	 */
	ret = 0;
	goto out;

out:
fail3:
	dput(dentry);
fail2:
fail1:
	lcd_set_r0(cptr_val(my_ref));
	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

int mount_nodev_callee(void)
{
	struct file_system_type_container *fs_container;
	struct mount_nodev_fill_super_container *fill_sup_container;
	struct mount_nodev_fill_super_hidden_args *fill_sup_args;
	int ret;
	cptr_t data_cptr;
	unsigned int mem_order;
	unsigned long data_offset;
	gva_t data_gva;
	int flags;
	cptr_t fill_sup_their_ref;
	int (*fill_super_p)(struct super_block *, void *, int);
	struct dentry *dentry;
	struct dentry_container *dentry_container;
	cptr_t dentry_ref = CAP_CPTR_NULL;
	/*
	 * Unmarshal args:
	 *
	 *   -- ref to fs type
	 *   -- void * data stuff
	 *   -- flags
	 *   -- fill_sup ref
	 */
	ret = glue_cap_lookup_file_system_type_type(pmfs_cspace,
						__cptr(lcd_r1()),
						&fs_container);
	if (ret) {
		LIBLCD_ERR("couldn't find fs type");
		goto fail1;
	}
	data_cptr = lcd_cr0();
	mem_order = lcd_r2();
	data_offset = lcd_r3();
	flags = lcd_r4();
	fill_sup_their_ref = __cptr(lcd_r5());
	/*
	 * "Map" void *data (technically already accessible)
	 */
	ret = lcd_map_virt(data_cptr, mem_order, &data_gva);
	if (ret) {
		LIBLCD_ERR("failed to 'map' void *data arg");
		goto fail2;
	}
	/*
	 * Set up crap for fill_super function pointer
	 *
	 * Set up our fill_sup container
	 */
	fill_sup_container = kzalloc(sizeof(*fill_sup_container), GFP_KERNEL);
	if (!fill_sup_container) {
		LIBLCD_ERR("failed to alloc fill_sup container");
		ret = -ENOMEM;
		goto fail3;
	}
	fill_sup_container->their_ref = fill_sup_their_ref;
	/*
	 * Set up fill_super trampoline
	 */
	fill_sup_args = kzalloc(sizeof(*fill_sup_args), GFP_KERNEL);
	if (!fill_sup_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail4;
	}
	fill_sup_args->t_handle = LCD_DUP_TRAMPOLINE(
		mount_nodev_fill_super_trampoline);
	if (!fill_sup_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		goto fail5;
	}
	fill_sup_args->t_handle->hidden_args = fill_sup_args;
	fill_sup_args->mount_nodev_fill_super_container = fill_sup_container;
	fill_sup_args->cspace = cspace;
	fill_sup_args->channel = channel;
	/*
	 * Invoke real function
	 */
	fill_super_p = LCD_HANDLE_TO_TRAMPOLINE(fill_sup_args->t_handle);
	dentry = mount_nodev(&fs_container->file_system_type,
			flags,
			/* (gva = hva for non-isolated) */
			(void *)(gva_val(data_gva) + data_offset),
			fill_super_p);
	if (!dentry) {
		LIBLCD_ERR("mount_nodev failed");
		goto fail6;
	}
	/*
	 * Pass back ref to their copy of the dentry (this was set up
	 * in a deeper part of the crisscross call graph)
	 */
	dentry_container = container_of(
		dentry,
		struct dentry_container,
		dentry);
	dentry_ref = dentry_container->their_ref;
	/*
	 * Destroy fill_super trampoline stuff
	 */
	kfree(fill_sup_container);
	kfree(fill_sup_args->t_handle);
	kfree(fill_sup_args);
	/*
	 * Unmap void *data and delete our cap
	 */
	lcd_unmap_virt(data_gva, mem_order);
	/*
	 * Done
	 */
	ret = 0;
	goto out;

fail6:
	kfree(fill_sup_args->t_handle);
fail5:
	kfree(fill_sup_args);
fail4:
	kfree(fill_sup_container);
fail3:
	lcd_unmap_virt(data_gva, mem_order);	
fail2:
fail1:
out:

	lcd_cap_delete(data_cptr);

	if (lcd_sync_reply())
		LIBLCD_ERR("double fault?");
	return ret;
}

int kill_anon_super_callee(void)
{
	struct super_block_container *sb_container;
	int ret;
	/*
	 * Bind on our private super_block
	 */
	ret = glue_cap_lookup_super_block_type(pmfs_cspace,
					__cptr(lcd_r1()),
					&sb_container);
	if (ret) {
		LIBLCD_ERR("couldn't find super block");
		goto fail1;
	}
	/*
	 * super block is going to get freed during call to kill_anon_super;
	 * remove from cspace before
	 */
	glue_cap_remove(pmfs_cspace, sb_container->my_ref);
	/*
	 * Call real function
	 */
	kill_anon_super(&sb_container->super_block);
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
