/*
 * vfs_calle.c - callee side glue code of vfs interface
 *
 */

#include <lcd_config/pre_hook.h>

#include <liblcd/sync_ipc_poll.h>
#include <liblcd/liblcd.h>
#include <liblcd/trampoline.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/ctype.h>
#include <linux/log2.h>
#include "../internal.h"
#include <asm/cacheflush.h>

#include <lcd_config/post_hook.h>

extern int pmfs_ready;

/* GLUE SUPPORT -------------------------------------------------- */

int glue_vfs_init(void)
{
	int ret;
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

void glue_vfs_exit(void)
{
	glue_cap_exit();
}

static void destroy_async_fs_ring_channel(struct thc_channel *chnl)
{
	cptr_t tx, rx;
	gva_t tx_gva, rx_gva;
	unsigned long unused1, unused2;
	int ret;
	unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
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
	 * Free the thc channel
	 *
	 * XXX: We are assuming this is called *from the dispatch loop*
	 * (i.e., as part of handling a callee function), so no one
	 * else (no other awe) is going to try to use the channel
	 * after we kill it. (For the PMFS LCD, this is not possible,
	 * because the unregister happens from a *caller context*.)
	 */
	kfree(chnl);

	return;

fail2:
fail1:
	return;
}

static int setup_async_fs_ring_channel(cptr_t tx, cptr_t rx, 
				struct thc_channel **chnl_out)
{
	gva_t tx_gva, rx_gva;
	int ret;
	struct fipc_ring_channel *fchnl;
	struct thc_channel *chnl;
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
	fchnl = kmalloc(sizeof(*fchnl), GFP_KERNEL);
	if (!fchnl) {
		ret = -ENOMEM;
		LIBLCD_ERR("malloc failed");
		goto fail3;
	}
	ret = fipc_ring_channel_init(fchnl,
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
	chnl = kzalloc(sizeof(*chnl), GFP_KERNEL);
	if (!chnl) {
		ret = -ENOMEM;
		LIBLCD_ERR("malloc failed");
		goto fail5;
	}
	ret = thc_channel_init(chnl, fchnl);
	if (ret) {
		LIBLCD_ERR("async group item init failed");
		goto fail6;
	}

	*chnl_out = chnl;
	return 0;

fail6:
	kfree(chnl);
fail5:
fail4:
	kfree(fchnl);
fail3:
	lcd_unmap_virt(rx_gva, pg_order);
fail2:
	lcd_unmap_virt(tx_gva, pg_order);
fail1:
	return ret;
}

static void destroy_sb_trampolines(struct super_operations *s_ops);
static int setup_sb_trampolines(struct super_block_container *sb_container,
				struct glue_cspace *fs_cspace,
				cptr_t fs_sync_endpoint,
				struct thc_channel *fs_async_chnl);
static void destroy_fs_type_trampolines(
	struct file_system_type_container *fs_container);
static int setup_fs_type_trampolines(
	struct file_system_type_container *fs_container,
	struct glue_cspace *fs_cspace,
	cptr_t fs_sync_endpoint,
	struct thc_channel *fs_async_chnl);

/* TRAMPOLINES / FUNCTION POINTERS ---------------------------------------- */

struct inode* 
noinline
super_block_alloc_inode(struct super_block *super_block,
			struct trampoline_hidden_args *hidden_args)
{
	struct pmfs_inode_vfs_container *inode_container;
	struct super_block_container *sb_container =
		hidden_args->struct_container;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * Create our own private inode copy and ref
	 */
	inode_container = kzalloc(sizeof(*inode_container), GFP_NOFS);
	if (!inode_container) {
		LIBLCD_ERR("kzalloc inode failed");
		goto fail1;
	}
	ret = glue_cap_insert_pmfs_inode_vfs_type(
		hidden_args->fs_cspace,
		inode_container,
		&inode_container->my_ref);
	if (ret) {
		LIBLCD_ERR("cap insert failed");
		goto fail2;
	}
	/*
	 * Marshal:
	 *
	 *   -- sb ref
	 *   -- inode ref (to our copy)
	 */
	ret = async_msg_blocking_send_start(hidden_args->fs_async_chnl,
					&request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail3;
	}

	async_msg_set_fn_type(request, SUPER_BLOCK_ALLOC_INODE);
	fipc_set_reg0(request, cptr_val(sb_container->their_ref));
	fipc_set_reg1(request, cptr_val(inode_container->my_ref));

	ret = thc_ipc_call(hidden_args->fs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending request");
		goto fail4;
	}
	/*
	 * Get remote ref from callee
	 */
	if (cptr_is_null(__cptr(fipc_get_reg0(response)))) {
		LIBLCD_ERR("got null from callee");
		goto fail5;
	}
	inode_container->their_ref = __cptr(fipc_get_reg0(response));

	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->fs_async_chnl), 
			response);

	/*
	 * HACK: Invoke inode_init_once on our private copy
	 */
	inode_init_once(&inode_container->pmfs_inode_vfs.vfs_inode);
	/*
	 * Return inode
	 */
	return &inode_container->pmfs_inode_vfs.vfs_inode;

fail5:
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->fs_async_chnl), 
			response);
fail4:
fail3:
	glue_cap_remove(hidden_args->fs_cspace, inode_container->my_ref);
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
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_alloc_inode_trampoline);

	super_block_alloc_inode_p = super_block_alloc_inode;

	return super_block_alloc_inode_p(super_block, hidden_args);
}

static void glue_destroy_inode(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct pmfs_inode_vfs_container *inode_container =
		container_of(
			container_of(inode,
				struct pmfs_inode_vfs,
				vfs_inode),
			struct pmfs_inode_vfs_container,
			pmfs_inode_vfs);
	kfree(inode_container);
}

void
noinline
super_block_destroy_inode(struct inode *inode,
			struct trampoline_hidden_args *hidden_args)
{
	struct pmfs_inode_vfs_container *inode_container;
	struct super_block_container *sb_container = 
		hidden_args->struct_container;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * Call remote destroy inode
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
	 *   -- sb ref
	 *   -- inode ref
	 */
	ret = async_msg_blocking_send_start(hidden_args->fs_async_chnl,
					&request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, SUPER_BLOCK_DESTROY_INODE);
	fipc_set_reg0(request, cptr_val(sb_container->their_ref));
	fipc_set_reg1(request, cptr_val(inode_container->their_ref));

	ret = thc_ipc_call(hidden_args->fs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending request");
		goto fail2;
	}
	/*
	 * Nothing in reply
	 */
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->fs_async_chnl), 
			response);

	goto out;

fail2:
fail1:
out:
	/*
	 * Remove our copy from cspace, and destroy it
	 */
	glue_cap_remove(hidden_args->fs_cspace, inode_container->my_ref);
	call_rcu(&inode_container->pmfs_inode_vfs.vfs_inode.i_rcu, 
		glue_destroy_inode);
	return;
}

LCD_TRAMPOLINE_DATA(super_block_destroy_inode_trampoline);
void
LCD_TRAMPOLINE_LINKAGE(super_block_destroy_inode_trampoline)
super_block_destroy_inode_trampoline(struct inode *inode)
{
	void (*volatile super_block_destroy_inode_p)(
		struct inode *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_destroy_inode_trampoline);

	super_block_destroy_inode_p = super_block_destroy_inode;

	super_block_destroy_inode_p(inode, hidden_args);
}

void
noinline
super_block_evict_inode(struct inode *inode, 
			struct trampoline_hidden_args *hidden_args)
{
	struct pmfs_inode_vfs_container *inode_container;
	struct super_block_container *sb_container =
		hidden_args->struct_container;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * Call remote evict inode
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
	 *   -- sb ref
	 *   -- inode ref
	 */
	ret = async_msg_blocking_send_start(hidden_args->fs_async_chnl,
					&request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, SUPER_BLOCK_EVICT_INODE);
	fipc_set_reg0(request, cptr_val(sb_container->their_ref));
	fipc_set_reg1(request, cptr_val(inode_container->their_ref));

	ret = thc_ipc_call(hidden_args->fs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending request");
		goto fail2;
	}
	/*
	 * Nothing in reply
	 */
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->fs_async_chnl), 
			response);

	goto out;

fail2:
fail1:
out:
	return;
}

LCD_TRAMPOLINE_DATA(super_block_evict_inode_trampoline);
void
LCD_TRAMPOLINE_LINKAGE(super_block_evict_inode_trampoline)
super_block_evict_inode_trampoline(struct inode *inode)
{
	void (*volatile super_block_evict_inode_p)(
		struct inode *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_evict_inode_trampoline);

	super_block_evict_inode_p = super_block_evict_inode;

	super_block_evict_inode_p(inode, hidden_args);
}

void
noinline
super_block_put_super(struct super_block *sb,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct super_block_container *sb_container =
		hidden_args->struct_container;
	struct fipc_message *request, *response;
	/*
	 * Call remote put_super
	 *
	 * Marshal:
	 *
	 *   -- sb ref
	 */
	ret = async_msg_blocking_send_start(hidden_args->fs_async_chnl,
					&request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, SUPER_BLOCK_PUT_SUPER);
	fipc_set_reg0(request, cptr_val(sb_container->their_ref));

	ret = thc_ipc_call(hidden_args->fs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending request");
		goto fail2;
	}
	/*
	 * Nothing in reply
	 */
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->fs_async_chnl), 
			response);

	goto out;

fail2:
fail1:
out:
	return;
}

LCD_TRAMPOLINE_DATA(super_block_put_super_trampoline);
void
LCD_TRAMPOLINE_LINKAGE(super_block_put_super_trampoline)
super_block_put_super_trampoline(struct super_block *sb)
{
	void (*volatile super_block_put_super_p)(
		struct super_block *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				super_block_put_super_trampoline);

	super_block_put_super_p = super_block_put_super;

	super_block_put_super_p(sb, hidden_args);
}

int
noinline
mount_nodev_fill_super(struct super_block *sb,
		void *data,
		int silent,
		struct trampoline_hidden_args *hidden_args)
{
	struct super_block_container *sb_container;
	struct dentry_container *dentry_container;
	struct mount_nodev_fill_super_container *fill_sup_container =
		hidden_args->struct_container;
	int ret;
	cptr_t data_cptr;
	unsigned long mem_sz;
	unsigned long data_offset;
	uint32_t request_cookie;
	cptr_t dentry_ref;
	cptr_t sb_ref;
	int s_flags;
	struct fipc_message *request, *response;

	sb_container = container_of(
		sb,
		struct super_block_container,
		super_block);
	/*
	 * Set up super block trampolines
	 */
	ret = setup_sb_trampolines(sb_container,
				hidden_args->fs_cspace,
				hidden_args->fs_sync_endpoint,
				hidden_args->fs_async_chnl);
	if (ret) {
		LIBLCD_ERR("error setting up sb trampolines");
		goto fail0;
	}
	/*
	 * Insert super block into cspace
	 */
	ret = glue_cap_insert_super_block_type(hidden_args->fs_cspace,
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
	 * Do async part first:
	 *
	 * Marshal arguments:
	 *
	 *   -- fill sup ref
	 *   -- sb ref (to ours)
	 *   -- s_flags
	 *   -- silent
	 */
	ret = async_msg_blocking_send_start(hidden_args->fs_async_chnl,
					&request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail3;
	}

	async_msg_set_fn_type(request, MOUNT_NODEV_FILL_SUPER);
	fipc_set_reg0(request, cptr_val(fill_sup_container->their_ref));
	fipc_set_reg1(request, cptr_val(sb_container->my_ref));
	fipc_set_reg2(request, sb_container->super_block.s_flags);
	fipc_set_reg3(request, silent);

	ret = thc_ipc_send_request(hidden_args->fs_async_chnl, request, 
				&request_cookie);
	if (ret) {
		LIBLCD_ERR("error sending request");
		goto fail4;
	}
	/*
	 * Do sync part:
	 *
	 *   -- cptr to data memory
	 *   -- data memory order
	 *   -- data offset
	 */
	lcd_set_cr0(data_cptr);
	/* Assumes mem_sz is 2^x pages */
	lcd_set_r0(ilog2(mem_sz >> PAGE_SHIFT));
	lcd_set_r1(data_offset);
	ret = lcd_sync_send(hidden_args->fs_sync_endpoint);
	lcd_set_cr0(CAP_CPTR_NULL); /* flush cr0 after send */
	if (ret) {
		LIBLCD_ERR("sync send failed");
		goto fail5;
	}
	/*
	 * Receive *async* response
	 */
	ret = thc_ipc_recv_response(hidden_args->fs_async_chnl, 
				request_cookie, 
				&response);
	if (ret) {
		LIBLCD_ERR("async recv failed");
		goto fail6;
	}
	/*
	 * Unmarshal response. We expect a remote ref to a dentry.
	 */
	ret = fipc_get_reg0(response);
	sb_ref = __cptr(fipc_get_reg1(response));
	s_flags = fipc_get_reg2(response);
	dentry_ref = __cptr(fipc_get_reg3(response));

	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->fs_async_chnl), 
			response);

	if (ret) {
		LIBLCD_ERR("remote fill_super failed");
		goto fail7;
	}
	ret = glue_cap_lookup_dentry_type(hidden_args->fs_cspace,
					dentry_ref,
					&dentry_container);
	if (ret) {
		LIBLCD_ERR("couldn't find dentry");
		goto fail8;
	}
	sb_container->their_ref = sb_ref;
	sb_container->super_block.s_flags = s_flags;
	sb_container->super_block.s_root = &dentry_container->dentry;
	/*
	 * Done
	 */
	return 0;

fail8:
fail7:
fail6:
fail5:
	thc_kill_request_cookie(request_cookie);
fail4:
fail3:
fail2:
	glue_cap_remove(hidden_args->fs_cspace, sb_container->my_ref);
fail1:
	/* Removing const is safe here */
	destroy_sb_trampolines((struct super_operations *)
			sb_container->super_block.s_op);
fail0:
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
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				mount_nodev_fill_super_trampoline);

	mount_nodev_fill_super_p = mount_nodev_fill_super;

	return mount_nodev_fill_super_p(super_block,
					data,
					silent,
					hidden_args);
}

static int get_phys_addr(char *cmdline, unsigned long *phys_addr)
{
	/*
	 * Taken from pmfs/super.c. Looks like they assume
	 * physaddr is first mount option.
	 */
	if (!cmdline || strncmp(cmdline, "physaddr=", 9) != 0)
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
	int ret;
	char *p, *rest;
	substring_t args[MAX_OPT_ARGS];
	match_table_t tokens = {
		{ 0,	     "init=%s"    	  },
		{ 1,         NULL                 },
	};
	char *dup_cmdline = kstrdup(cmdline, GFP_KERNEL);
	if (!dup_cmdline) {
		LIBLCD_ERR("error dup'ing cmdline");
		return -ENOMEM;
	}

	/* We use a duplicate of the cmdline because strsep inserts
	 * nuls to do the separation. */
	while ((p = strsep(&dup_cmdline, ",")) != NULL) {
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
			ret = 0;
			goto out;
		default:
			break;
		}
	}
	/*
	 * No "init=" mount option. Fail.
	 */
	LIBLCD_ERR("no init= mount option?");
	ret = 0;
	goto out;

out:
	kfree(dup_cmdline);
	return ret;
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
	mem_len = roundup_pow_of_two(ALIGN(data + data_len - page_address(p),
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
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	cptr_t dentry_ref;
	struct file_system_type_container *fs_container;
	struct dentry_container *dentry_container;
	cptr_t data_cptr;
	unsigned int mem_order;
	unsigned long data_offset;
	cptr_t fs_mem_cptr;
	unsigned int fs_mem_order;
	struct fipc_message *request, *response;
	uint32_t request_cookie;

	fs_container = container_of(fs_type,
				struct file_system_type_container,
				file_system_type);
	/*
	 * Volunteer fs memory
	 */
	ret = setup_fs_memory(data, &fs_mem_cptr, &fs_mem_order);
	if (ret) {
		LIBLCD_ERR("failed to volunteer fs memory");
		goto fail0;
	}
	/*
	 * XXX: We store this here for convenience. It's not really
	 * required in order for the example to work. We need it to
	 * do the revoke after the super block is unmounted.
	 */
	fs_container->fs_memory = fs_mem_cptr;
	/*
	 * Volunteer memory that contains void *data
	 */
	ret = setup_data(data, &data_cptr, &mem_order, &data_offset);
	if (ret) {
		LIBLCD_ERR("error volunteering void *data arg");
		goto fail1;
	}
	/*
	 * Do async part:
	 *
	 * Marshal:
	 *
	 *       -- fs type ref
	 *       -- flags
	 * XXX:  -- skip dev_name (pmfs doesn't use it)
	 */
	ret = async_msg_blocking_send_start(hidden_args->fs_async_chnl, 
					&request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail2;
	}

	async_msg_set_fn_type(request, FILE_SYSTEM_TYPE_MOUNT);
	fipc_set_reg0(request, cptr_val(fs_container->their_ref));
	fipc_set_reg1(request, flags);

	ret = thc_ipc_send_request(hidden_args->fs_async_chnl, request, 
				&request_cookie);
	if (ret) {
		LIBLCD_ERR("error sending request");
		goto fail3;
	}
	/*
	 * Do sync part:
	 *
	 * Marshal:
	 *
	 *    -- cptr to data memory
	 *    -- data memory order
	 *    -- data offset
	 *    -- cptr to fs memory
	 *    -- fs memory order
	 */
	lcd_set_cr0(data_cptr);
	lcd_set_r0(mem_order);
	lcd_set_r1(data_offset);
	lcd_set_cr1(fs_mem_cptr);
	lcd_set_r2(fs_mem_order);
	ret = lcd_sync_send(hidden_args->fs_sync_endpoint);
	if (ret) {
		LIBLCD_ERR("call error");
		goto fail4;
	}
	/*
	 * Get *async* response
	 */
	ret = thc_ipc_recv_response(hidden_args->fs_async_chnl, 
				request_cookie, 
				&response);
	if (ret) {
		LIBLCD_ERR("async recv failed");
		goto fail5;
	}
	/*
	 * Unmarshal dentry
	 */
	dentry_ref = __cptr(fipc_get_reg0(response));

	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->fs_async_chnl), 
			response);

	if (cptr_is_null(dentry_ref)) {
		LIBLCD_ERR("dentry from remote is null");
		goto fail6;
	}
	ret = glue_cap_lookup_dentry_type(hidden_args->fs_cspace,
					dentry_ref,
					&dentry_container);
	if (ret) {
		LIBLCD_ERR("couldn't find dentry");
		goto fail7;
	}
	/*
	 * Unvolunteer void *data
	 */
	lcd_cap_revoke(data_cptr);
	lcd_unvolunteer_pages(data_cptr);
	/*
	 * Done
	 */
	return &dentry_container->dentry;

fail7:
fail6:
fail5:
fail4:
	thc_kill_request_cookie(request_cookie);
fail3:
fail2:
	lcd_unvolunteer_pages(data_cptr);
fail1:
	lcd_unvolunteer_dev_mem(fs_mem_cptr);
fail0:
	return NULL;
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
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				file_system_type_mount_trampoline);

	file_system_type_mount_p = file_system_type_mount;

	return file_system_type_mount_p(fs_type,
					flags,
					dev_name,
					data,
					hidden_args);
}

void
noinline
file_system_type_kill_sb(struct super_block *sb,
			struct trampoline_hidden_args *hidden_args)
{
	struct file_system_type_container *fs_container =
		hidden_args->struct_container;
	struct super_block_container *sb_container;
	struct super_operations *s_ops;
	cptr_t fs_mem_cptr = fs_container->fs_memory;
	int ret;
	struct fipc_message *request, *response;
	/*
	 * Get ref to s_op and fs mem before we kill the super_block, so we can
	 * tear down the trampolines *after* we call kill_sb. (We can't do
	 * it before, because some of the s_op's will be used in the body/
	 * call graph of kill_sb.)
	 */
	sb_container = container_of(sb, struct super_block_container, 
				super_block);
	/* It's safe to discard const here */
	s_ops = (struct super_operations *)sb->s_op;
	/*
	 * Marshal refs to fs type and super block, and do rpc.
	 *
	 * sb_container will get freed in the process ...
	 */
	ret = async_msg_blocking_send_start(hidden_args->fs_async_chnl,
					&request);
	if (ret) {
		LIBLCD_ERR("failed to get send slot");
		goto fail1;
	}

	async_msg_set_fn_type(request, FILE_SYSTEM_TYPE_KILL_SB);
	fipc_set_reg0(request, cptr_val(fs_container->their_ref));
	fipc_set_reg1(request, cptr_val(sb_container->their_ref));

	ret = thc_ipc_call(hidden_args->fs_async_chnl, request, &response);
	if (ret) {
		LIBLCD_ERR("error sending request");
		goto fail2;
	}
	/*
	 * Nothing in response
	 */
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->fs_async_chnl), 
			response);
	/*
	 * sb_container is now invalid (was freed)
	 */
	sb_container = NULL;
	/*
	 * Destroy trampolines
	 *
	 * (removing const is safe here)
	 */
	destroy_sb_trampolines((struct super_operations *)s_ops);
	/*
	 * Unvolunteer fs memory
	 */
	lcd_cap_revoke(fs_mem_cptr);
	lcd_unvolunteer_dev_mem(fs_mem_cptr);
	/*
	 * Done
	 */
	goto out;
fail2:
fail1:
out:
	return;
}

LCD_TRAMPOLINE_DATA(file_system_type_kill_sb_trampoline);
void
LCD_TRAMPOLINE_LINKAGE(file_system_type_kill_sb_trampoline)
file_system_type_kill_sb_trampoline(struct super_block *sb)
{
	void (*volatile file_system_type_kill_sb_p)(
		struct super_block *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;

	LCD_TRAMPOLINE_PROLOGUE(hidden_args, 
				file_system_type_kill_sb_trampoline);

	file_system_type_kill_sb_p = file_system_type_kill_sb;

	return file_system_type_kill_sb_p(sb, hidden_args);
}

/* TRAMPOLINE SETUP / TEARDOWN ---------------------------------------- */

static void setup_rest_of_args(struct trampoline_hidden_args *args,
			void *struct_container,
			struct glue_cspace *fs_cspace,
			cptr_t fs_sync_endpoint,
			struct thc_channel *fs_async_chnl)
{
	args->t_handle->hidden_args = args;
	args->struct_container = struct_container;
	args->fs_cspace = fs_cspace;
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
				struct thc_channel *fs_async_chnl)
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
	ret = set_memory_x(((unsigned long)alloc_args->t_handle) & PAGE_MASK,
			ALIGN(LCD_TRAMPOLINE_SIZE(super_block_alloc_inode_trampoline),
				PAGE_SIZE) >> PAGE_SHIFT);
	if (ret) {
		LIBLCD_ERR("set mem nx");
		goto fail3;
	}
	/*
	 * destroy_inode trampoline
	 */
	destroy_args = kzalloc(sizeof(*destroy_args), GFP_KERNEL);
	if (!destroy_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail4;
	}
	destroy_args->t_handle = LCD_DUP_TRAMPOLINE(
		super_block_destroy_inode_trampoline);
	if (!destroy_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(destroy_args);
		goto fail5;
	}
	setup_rest_of_args(destroy_args, sb_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	s_ops->destroy_inode =
		LCD_HANDLE_TO_TRAMPOLINE(destroy_args->t_handle);
	ret = set_memory_x(((unsigned long)destroy_args->t_handle) & PAGE_MASK,
			ALIGN(LCD_TRAMPOLINE_SIZE(super_block_destroy_inode_trampoline),
				PAGE_SIZE) >> PAGE_SHIFT);
	if (ret) {
		LIBLCD_ERR("set mem nx");
		goto fail6;
	}
	/*
	 * evict_inode trampoline
	 */
	evict_args = kzalloc(sizeof(*evict_args), GFP_KERNEL);
	if (!evict_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail7;
	}
	evict_args->t_handle = LCD_DUP_TRAMPOLINE(
		super_block_evict_inode_trampoline);
	if (!evict_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(evict_args);
		goto fail8;
	}
	setup_rest_of_args(evict_args, sb_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	s_ops->evict_inode =
		LCD_HANDLE_TO_TRAMPOLINE(evict_args->t_handle);
	ret = set_memory_x(((unsigned long)evict_args->t_handle) & PAGE_MASK,
			ALIGN(LCD_TRAMPOLINE_SIZE(super_block_evict_inode_trampoline),
				PAGE_SIZE) >> PAGE_SHIFT);
	if (ret) {
		LIBLCD_ERR("set mem nx");
		goto fail9;
	}
	/*
	 * put_super trampoline
	 */
	put_args = kzalloc(sizeof(*put_args), GFP_KERNEL);
	if (!put_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail10;
	}
	put_args->t_handle = LCD_DUP_TRAMPOLINE(
		super_block_put_super_trampoline);
	if (!put_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(put_args);
		goto fail11;
	}
	setup_rest_of_args(put_args, sb_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	s_ops->put_super =
		LCD_HANDLE_TO_TRAMPOLINE(put_args->t_handle);
	ret = set_memory_x(((unsigned long)put_args->t_handle) & PAGE_MASK,
			ALIGN(LCD_TRAMPOLINE_SIZE(super_block_put_super_trampoline),
				PAGE_SIZE) >> PAGE_SHIFT);
	if (ret) {
		LIBLCD_ERR("set mem nx");
		goto fail12;
	}
	/*
	 * Install ops
	 */
	sb_container->super_block.s_op = s_ops;
	
	return 0;

fail12:
fail11:
fail10:
fail9:
fail8:
fail7:
fail6:
fail5:
fail4:
fail3:
fail2:
fail1:
fail0:
	/* Removing const is safe here */
	destroy_sb_trampolines((struct super_operations *)
			sb_container->super_block.s_op);
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
	struct thc_channel *fs_async_chnl)
{
	struct trampoline_hidden_args *mount_args, *kill_sb_args;
	int ret;
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
	ret = set_memory_x(((unsigned long)mount_args->t_handle) & PAGE_MASK,
			ALIGN(LCD_TRAMPOLINE_SIZE(file_system_type_mount_trampoline),
				PAGE_SIZE) >> PAGE_SHIFT);
	if (ret) {
		LIBLCD_ERR("set mem nx");
		goto fail3;
	}
	/*
	 * kill_sb trampoline
	 */
	kill_sb_args = kzalloc(sizeof(*kill_sb_args), GFP_KERNEL);
	if (!kill_sb_args) {
		LIBLCD_ERR("kzalloc hidden args failed");
		ret = -ENOMEM;
		goto fail4;
	}
	kill_sb_args->t_handle = LCD_DUP_TRAMPOLINE(
		file_system_type_kill_sb_trampoline);
	if (!kill_sb_args->t_handle) {
		LIBLCD_ERR("dup trampoline");
		ret = -ENOMEM;
		kfree(kill_sb_args);
		goto fail5;
	}
	setup_rest_of_args(kill_sb_args, fs_container, fs_cspace,
			fs_sync_endpoint, fs_async_chnl);
	fs_container->file_system_type.kill_sb = 
		LCD_HANDLE_TO_TRAMPOLINE(kill_sb_args->t_handle);
	ret = set_memory_x(((unsigned long)kill_sb_args->t_handle) & PAGE_MASK,
			ALIGN(LCD_TRAMPOLINE_SIZE(file_system_type_kill_sb_trampoline),
				PAGE_SIZE) >> PAGE_SHIFT);
	if (ret) {
		LIBLCD_ERR("set mem nx");
		goto fail6;
	}

	/*
	 * Done
	 */
	return 0;

fail6:
fail5:
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
	cptr_t tx, rx;
	struct thc_channel *chnl;
	struct glue_cspace *cspace;
	cptr_t sync_endpoint;
	struct fs_info *fs_info;
	/*
	 * Set up a cspace for fs remote refs
	 */
	ret = glue_cap_create(&cspace);
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
		cspace,
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
	/*
	 * Some special module inits required:
	 *
	 *   -- module refptr (alloc_percpu)
	 *   -- module state = MODULE_STATE_LIVE
	 *   -- module name = "pmfs"
	 *
	 * These are normally done by the module loader. But since we
	 * are creating our own struct module instance, we need to do
	 * the initialization ourselves.
	 *
	 * Rather than have pmfs pass module.state and module.name over,
	 * we just initialize them on this side. Trying to pass refptr
	 * over is difficult and maybe silly.
	 */
	module_container->module.refptr = alloc_percpu(struct module_ref);
	if (!module_container->module.refptr) {
		LIBLCD_ERR("alloc percpu refptr failed");
		ret = -ENOMEM;
		goto fail4;
	}
	module_container->module.state = MODULE_STATE_LIVE;
	strcpy(module_container->module.name, "pmfs");
	ret = glue_cap_insert_module_type(
		cspace,
		module_container,
		&module_container->my_ref);
	if (ret) {
		LIBLCD_ERR("insert");
		goto fail5;
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
	 * it to "pmfs_lcd" (we use "pmfs_lcd" instead of "pmfs" so that
	 * we can use the original pmfs at the same time).
	 */
	fs_container->their_ref = __cptr(lcd_r1());
	fs_container->file_system_type.name = "pmfs_lcd"; 
	module_container->their_ref = __cptr(lcd_r2());
	sync_endpoint = lcd_cr0();
	tx = lcd_cr1();
	rx = lcd_cr2();
	/*
	 * Set up object linkage
	 */
	fs_container->file_system_type.owner = &module_container->module;
	/*
	 * Set up async ring channel
	 */
	ret = setup_async_fs_ring_channel(tx, rx, &chnl);
	if (ret) {
		LIBLCD_ERR("error setting up ring channel");
		goto fail6;
	}
	/*
	 * Add to dispatch loop
	 */
	fs_info = add_fs(chnl, cspace, sync_endpoint);
	if (!fs_info) {
		LIBLCD_ERR("error adding to dispatch loop");
		goto fail7;
	}
	fs_container->fs_info = fs_info;
	/*
	 * Set up fn pointer trampolines
	 */
	ret = setup_fs_type_trampolines(fs_container,
					cspace,
					sync_endpoint,
					chnl);
	if (ret) {
		LIBLCD_ERR("error setting up trampolines");
		goto fail8;
	}
	/*
	 * Call real function
	 */
	ret = register_filesystem(&fs_container->file_system_type);
	if (ret) {
		LIBLCD_ERR("register fs failed");
		goto fail9;
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

fail9:
	destroy_fs_type_trampolines(fs_container);
fail8:
	remove_fs(fs_info);
fail7:
	destroy_async_fs_ring_channel(chnl);
	kfree(chnl);
fail6:
	glue_cap_remove(cspace, module_container->my_ref);
fail5:
	free_percpu(module_container->module.refptr);
fail4:
	kfree(module_container);
fail3:
	glue_cap_remove(cspace, fs_container->my_ref);
fail2:
	kfree(fs_container);
fail1:
	glue_cap_destroy(cspace);
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
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct file_system_type_container *fs_container;
	struct module_container *module_container;
	int ret;
	cptr_t fs_ref, m_ref;
	uint32_t request_cookie = thc_get_request_cookie(request);
	struct fipc_message *response;
	/*
	 * Unmarshal refs:
	 *
	 *   -- fs ref
	 *   -- module ref
	 */
	fs_ref = __cptr(fipc_get_reg0(request));
	m_ref = __cptr(fipc_get_reg1(request));
	ret = fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	if (ret) {
		LIBLCD_ERR("failed to mark msg as recvd");
		goto fail1;
	}
	/*
	 * Bind
	 */
	ret = glue_cap_lookup_file_system_type_type(
		cspace,
		fs_ref,
		&fs_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail2;
	}
	ret = glue_cap_lookup_module_type(
		cspace,
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
	 * Reply with unregister fs return value
	 */
	goto out;

fail4:
fail3:
fail2:
fail1:
out:
	/*
	 * Reply
	 */
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg0(response, ret);

	thc_ipc_reply(channel, request_cookie, response);

	if (!ret) {
		/*
		 * unregister fs was successful; tear everything down
		 */
		destroy_fs_type_trampolines(fs_container);
		lcd_cap_delete(sync_endpoint);
		/* Marks thc_channel as dead; dispatch loop will free it */
		destroy_async_fs_ring_channel(channel);
		remove_fs(fs_container->fs_info);
		glue_cap_remove(cspace, fs_container->my_ref);
		glue_cap_remove(cspace, module_container->my_ref);
		glue_cap_destroy(cspace);
		kfree(fs_container);
		kfree(module_container);
	}

	return ret;
}

int bdi_init_callee(struct fipc_message *request,
		struct thc_channel *channel,
		struct glue_cspace *cspace,
		cptr_t sync_endpoint)
{
	struct backing_dev_info_container *bdi_container;
	int ret;
	cptr_t bdi_obj_ref = CAP_CPTR_NULL;
	struct fipc_message *response;
	uint32_t request_cookie = thc_get_request_cookie(request);
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
		cspace,
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
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
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
	glue_cap_remove(cspace, bdi_container->my_ref);
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

	thc_ipc_reply(channel, request_cookie, response);

	pmfs_ready = 1;

	return ret;
}

int bdi_destroy_callee(struct fipc_message *request,
		struct thc_channel *channel,
		struct glue_cspace *cspace,
		cptr_t sync_endpoint)
{
	struct backing_dev_info_container *bdi_container;
	int ret;
	cptr_t ref;
	struct fipc_message *response;
	uint32_t request_cookie = thc_get_request_cookie(request);
	/*
	 * Unmarshal ref to our bdi obj copy, and bind.
	 */
	ref = __cptr(fipc_get_reg0(request));

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ret = glue_cap_lookup_backing_dev_info_type(
		cspace,
		ref,
		&bdi_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail1;
	}
	/*
	 * Invoke real function
	 */
	bdi_destroy(&bdi_container->backing_dev_info);
	/*
	 * Tear down container
	 */
	glue_cap_remove(cspace, bdi_container->my_ref);
	kfree(bdi_container);

	ret = 0;
	goto out;

fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	
	/* empty response */

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int iget_locked_callee(struct fipc_message *request,
		struct thc_channel *channel,
		struct glue_cspace *cspace,
		cptr_t sync_endpoint)
{
	int ret;
	struct super_block_container *sb_container;
	struct inode *inode;
	struct pmfs_inode_vfs_container *inode_container = NULL;
	struct fipc_message *response;
	cptr_t sb_ref = __cptr(fipc_get_reg0(request));
	cptr_t their_sb_ref = __cptr(fipc_get_reg1(request));
	unsigned long ino = fipc_get_reg2(request);
	uint32_t request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	/*
	 * Look up our private sb
	 */
	ret = glue_cap_lookup_super_block_type(cspace,
					sb_ref,
					&sb_container);
	if (ret) {
		LIBLCD_ERR("super block lookup failed");
		goto fail1;
	}
	sb_container->their_ref = their_sb_ref;
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
		fipc_set_reg1(response, 
			inode_container->pmfs_inode_vfs.vfs_inode.i_state);
		fipc_set_reg2(response, 
			inode_container->pmfs_inode_vfs.vfs_inode.i_nlink);
		fipc_set_reg3(response, 
			inode_container->pmfs_inode_vfs.vfs_inode.i_mode);
	} else {
		fipc_set_reg0(response, cptr_val(CAP_CPTR_NULL));
	}

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int truncate_inode_pages_callee(struct fipc_message *request,
				struct thc_channel *channel,
				struct glue_cspace *cspace,
				cptr_t sync_endpoint)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	struct fipc_message *response;
	cptr_t inode_ref = __cptr(fipc_get_reg0(request));
	loff_t lstart = fipc_get_reg1(request);
	uint32_t request_cookie = thc_get_request_cookie(request);
	
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/*
	 * (See notes for caller side)
	 *
	 * Look up our private inode object
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(cspace,
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

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int clear_inode_callee(struct fipc_message *request,
		struct thc_channel *channel,
		struct glue_cspace *cspace,
		cptr_t sync_endpoint)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	cptr_t inode_ref = __cptr(fipc_get_reg0(request));
	struct fipc_message *response;
	uint32_t request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	/*
	 * Look up our private copy of the inode object
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(cspace,
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
	
	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int iget_failed_callee(struct fipc_message *request,
		struct thc_channel *channel,
		struct glue_cspace *cspace,
		cptr_t sync_endpoint)
{
	struct pmfs_inode_vfs_container *inode_container;
	int ret;
	struct fipc_message *response;
	cptr_t inode_ref = __cptr(fipc_get_reg0(request));
	uint32_t request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/*
	 * Look up our inode obj
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(cspace,
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

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int unlock_new_inode_callee(struct fipc_message *request,
			struct thc_channel *channel,
			struct glue_cspace *cspace,
			cptr_t sync_endpoint)
{
	struct pmfs_inode_vfs_container *inode_container = NULL;
	int ret;
	cptr_t inode_ref = __cptr(fipc_get_reg0(request));
	struct fipc_message *response;
	uint32_t request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/*
	 * Look up our inode obj
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(cspace,
						inode_ref,
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
	 * Reply
	 */
	ret = 0;
	goto out;

fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	/*
	 * Return new i_state
	 */
	if (inode_container)
		fipc_set_reg0(response, 
			inode_container->pmfs_inode_vfs.vfs_inode.i_state);

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int d_make_root_callee(struct fipc_message *request,
		struct thc_channel *channel,
		struct glue_cspace *cspace,
		cptr_t sync_endpoint)
{
	struct pmfs_inode_vfs_container *inode_container;
	struct dentry_container *dentry_container = NULL;
	struct dentry *dentry;
	int ret;
	cptr_t inode_ref = __cptr(fipc_get_reg0(request));
	unsigned int nlink = fipc_get_reg1(request);
	cptr_t dentry_ref = __cptr(fipc_get_reg2(request));
	struct fipc_message *response;
	uint32_t request_cookie = thc_get_request_cookie(request);
	
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	/*
	 * Get our inode obj
	 */
	ret = glue_cap_lookup_pmfs_inode_vfs_type(cspace,
						inode_ref,
						&inode_container);
	if (ret) {
		LIBLCD_ERR("couldn't find inode");
		goto fail1;
	}
	/*
	 * Update nlink
	 */
	set_nlink(&inode_container->pmfs_inode_vfs.vfs_inode,
		nlink);
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
	ret = glue_cap_insert_dentry_type(cspace,
					dentry_container,
					&dentry_container->my_ref);
	if (ret) {
		LIBLCD_ERR("error inserting in cspace");
		goto fail3;
	}
	dentry_container->their_ref = dentry_ref;
	/*
	 * Reply with ref
	 */
	ret = 0;
	goto out;


fail3:
	dput(dentry);
fail2:
fail1:
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	/*
	 * Return new dentry ref
	 */
	if (dentry_container)
		fipc_set_reg0(response, cptr_val(dentry_container->my_ref));
	else
		fipc_set_reg0(response, cptr_val(CAP_CPTR_NULL));

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

static int sync_mount_nodev_callee(cptr_t fs_sync_endpoint,
				cptr_t *data_cptr,
				gva_t *data_gva,
				unsigned long *mem_order,
				unsigned long *data_offset)
{
	int ret;
	/*
	 * Alloc cptr for void *data memory, and do sync receive
	 */
	ret = lcd_cptr_alloc(data_cptr);
	if (ret) {
		LIBLCD_ERR("failed to get cptr");
		goto fail1;
	}
	lcd_set_cr0(*data_cptr);
	ret = lcd_sync_recv(fs_sync_endpoint);
	lcd_set_cr0(CAP_CPTR_NULL); /* flush cr0 */
	if (ret) {
		LIBLCD_ERR("failed to recv");
		goto fail2;
	}
	/*
	 * Receive values
	 */
	*mem_order = lcd_r0();
	*data_offset = lcd_r1();
	/*
	 * Map data
	 */
	ret = lcd_map_virt(*data_cptr, *mem_order, data_gva);
	if (ret) {
		LIBLCD_ERR("failed to 'map' void *data arg");
		lcd_cap_delete(*data_cptr);
		return ret;
	}

	return 0;

fail2:
	lcd_cptr_free(*data_cptr);
fail1:
	return ret;
}

int mount_nodev_callee(struct fipc_message *request,
		struct thc_channel *channel,
		struct glue_cspace *cspace,
		cptr_t sync_endpoint)
{
	struct file_system_type_container *fs_container;
	struct mount_nodev_fill_super_container *fill_sup_container;
	struct trampoline_hidden_args *fill_sup_args;
	int ret;
	cptr_t fs_type_ref = __cptr(fipc_get_reg0(request));
	int flags = fipc_get_reg1(request);
	cptr_t fill_sup_ref = __cptr(fipc_get_reg2(request));
	cptr_t data_cptr;
	gva_t data_gva;
	unsigned long mem_order;
	unsigned long data_offset;
	int (*fill_super_p)(struct super_block *, void *, int);
	struct dentry *dentry;
	struct dentry_container *dentry_container = NULL;
	uint32_t request_cookie = thc_get_request_cookie(request);
	struct fipc_message *response;

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	/*
	 * We also need to do a sync receive in order to get the void *data
	 * argument
	 */
	ret = sync_mount_nodev_callee(sync_endpoint,
				&data_cptr,
				&data_gva,
				&mem_order,
				&data_offset);
	if (ret) {
		LIBLCD_ERR("error doing sync part of mount_nodev");
		return ret; /* do not do async reply */
	}
	/*
	 * Look up fs type
	 */
	ret = glue_cap_lookup_file_system_type_type(cspace,
						fs_type_ref,
						&fs_container);
	if (ret) {
		LIBLCD_ERR("couldn't find fs type");
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
	fill_sup_container->their_ref = fill_sup_ref;
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
	fill_sup_args->struct_container = fill_sup_container;
	fill_sup_args->fs_cspace = cspace;
	fill_sup_args->fs_sync_endpoint = sync_endpoint;
	fill_sup_args->fs_async_chnl = channel;
	ret = set_memory_x(((unsigned long)fill_sup_args->t_handle) & PAGE_MASK,
			ALIGN(LCD_TRAMPOLINE_SIZE(mount_nodev_fill_super_trampoline),
				PAGE_SIZE) >> PAGE_SHIFT);
	if (ret) {
		LIBLCD_ERR("set mem nx");
		goto fail6;
	}
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
		goto fail7;
	}
	/*
	 * Pass back ref to their copy of the dentry (this was set up
	 * in a deeper part of the crisscross call graph)
	 */
	dentry_container = container_of(
		dentry,
		struct dentry_container,
		dentry);
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

fail7:
fail6:
	kfree(fill_sup_args->t_handle);
fail5:
	kfree(fill_sup_args);
fail4:
	kfree(fill_sup_container);
fail3:
fail2:
	lcd_unmap_virt(data_gva, mem_order);
	lcd_cap_delete(data_cptr);
out:
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	/*
	 * Return ref to their dentry
	 */
	if (dentry_container)
		fipc_set_reg0(response, cptr_val(dentry_container->their_ref));
	else
		fipc_set_reg0(response, cptr_val(CAP_CPTR_NULL));

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}

int kill_anon_super_callee(struct fipc_message *request,
			struct thc_channel *channel,
			struct glue_cspace *cspace,
			cptr_t sync_endpoint)
{
	struct super_block_container *sb_container;
	int ret;
	struct fipc_message *response;
	cptr_t sb_ref = __cptr(fipc_get_reg0(request));
	uint32_t request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	/*
	 * Bind on our private super_block
	 */
	ret = glue_cap_lookup_super_block_type(cspace,
					sb_ref,
					&sb_container);
	if (ret) {
		LIBLCD_ERR("couldn't find super block");
		goto fail1;
	}
	/*
	 * super block is going to get freed during call to kill_anon_super;
	 * remove from cspace before
	 */
	glue_cap_remove(cspace, sb_container->my_ref);
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
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	/* Empty response */

	thc_ipc_reply(channel, request_cookie, response);

	return ret;
}
