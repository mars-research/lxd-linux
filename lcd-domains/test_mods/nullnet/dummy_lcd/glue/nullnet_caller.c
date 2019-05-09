#include <lcd_config/pre_hook.h>

#include <libcap.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <liblcd/glue_cspace.h>
#include "../../glue_helper.h"
#include "../nullnet_caller.h"

#include <linux/hashtable.h>
#include "../../rdtsc_helper.h"
#include <lcd_config/post_hook.h>

struct cptr sync_ep;
static struct glue_cspace *c_cspace;
extern struct thc_channel *net_asyncs[NUM_LCDS];
extern struct thc_channel_group ch_grp[NUM_LCDS];
extern cptr_t nullnet_sync_endpoints[NUM_LCDS];
extern cptr_t nullnet_register_channels[NUM_LCDS];

struct rtnl_link_ops *g_rtnl_link_ops;
void *data_pool;
uint64_t con_skb_sum = 0;
struct kmem_cache *skb_c_cache;
struct kmem_cache *skbuff_cache;

extern bool tdiff_valid;
extern u64 tdiff_disp;
//#define LCD_MEASUREMENT
#define LCD_SKB_CONTAINER
#define NOLOOKUP
#define STATIC_SKB

/* XXX: How to determine this? */
#define CPTR_HASH_BITS      5


#ifdef CONFIG_PREALLOC_XMIT_CHANNELS
int prep_xmit_channels_lcd(void);
void prep_xmit_channels_clean_lcd(void);
#endif

static DEFINE_HASHTABLE(cptr_table, CPTR_HASH_BITS);

struct lcd_sk_buff_container {
	struct cptr my_ref, other_ref;
	struct sk_buff skbuff;
	uint64_t tid;
	void *chnl;
	unsigned int cookie;
};

int glue_nullnet_init(void)
{
	int ret;
	ret = glue_cap_init();
	if (ret) {
		LIBLCD_ERR("cap init");
		goto fail1;
	}
	ret = glue_cap_create(&c_cspace);
	if (ret) {
		LIBLCD_ERR("cap create");
		goto fail2;
	}
	hash_init(cptr_table);
	skb_c_cache = kmem_cache_create("skb_c_cache",
#ifdef LCD_SKB_CONTAINER
				sizeof(struct lcd_sk_buff_container),
#else
				sizeof(struct sk_buff_container),
#endif
				0,
				SLAB_HWCACHE_ALIGN|SLAB_PANIC,
				NULL);
	if (!skb_c_cache)
		printk("WARN: skb_container cache not created\n");

	skbuff_cache = kmem_cache_create("skbuff_cache",
				sizeof(struct sk_buff),
				0,
				SLAB_HWCACHE_ALIGN|SLAB_PANIC,
				NULL);
	if (!skbuff_cache)
		printk("WARN: skbuff cache not created\n");
	return 0;
fail2:
	glue_cap_exit();
fail1:
	return ret;

}

void glue_nullnet_exit()
{
	glue_cap_destroy(c_cspace);
	glue_cap_exit();
}

int glue_insert_skbuff(struct hlist_head *htable, struct sk_buff_container *skb_c)
{
        BUG_ON(!skb_c->skb);

        skb_c->my_ref = __cptr((unsigned long)skb_c->skb);

        hash_add(cptr_table, &skb_c->hentry, (unsigned long) skb_c->skb);
        return 0;
}

int glue_lookup_skbuff(struct hlist_head *htable, struct cptr c, struct sk_buff_container **skb_cout)
{
        struct sk_buff_container *skb_c;

        hash_for_each_possible(cptr_table, skb_c, hentry, (unsigned long) cptr_val(c)) {
		if (skb_c->skb == (struct sk_buff*) c.cptr) {
	                *skb_cout = skb_c;
		}
        }
        return 0;
}

void glue_remove_skbuff(struct sk_buff_container *skb_c)
{
	hash_del(&skb_c->hentry);
}

#ifdef ONE_SLOT
static int setup_async_channel_0(cptr_t *buf1_cptr_out, cptr_t *buf2_cptr_out,
			struct thc_channel **chnl_out)
{
	int ret;
	cptr_t buf1_cptr, buf2_cptr;
	gva_t buf1_addr, buf2_addr;
	struct fipc_ring_channel *fchnl;
	struct thc_channel *chnl;

	// we need only one page
	unsigned int pg_order = 0;

	LIBLCD_MSG("%s\n",__func__);
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
	ret = fipc_prep_buffers_0(sizeof(struct fipc_message),
				(void *)gva_val(buf1_addr),
				(void *)gva_val(buf2_addr));
	if (ret) {
		LIBLCD_ERR("prep buffers");
		goto fail5;
	}
	LIBLCD_MSG("==> Prep buffers");
	/*
	 * Alloc and init channel header
	 */
	fchnl = kmalloc(sizeof(*fchnl), GFP_KERNEL);
	if (!fchnl) {
		ret = -ENOMEM;
		LIBLCD_ERR("chnl alloc");
		goto fail6;
	}
	ret = fipc_ring_channel_init_0(fchnl, sizeof(struct fipc_message),
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
	ret = thc_channel_init_0(chnl, fchnl);
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
#endif

static int setup_async_channel(cptr_t *buf1_cptr_out, cptr_t *buf2_cptr_out,
			struct thc_channel **chnl_out)
{
	int ret;
	cptr_t buf1_cptr, buf2_cptr;
	gva_t buf1_addr, buf2_addr;
	struct fipc_ring_channel *fchnl;
	struct thc_channel *chnl;
	unsigned int pg_order = PMFS_ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
	LIBLCD_MSG("%s\n",__func__);
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
	LIBLCD_MSG("==> Prep buffers");
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
	if (0) {
		size_t sz = sizeof(*chnl);
		int idx = kmalloc_index(sz);
		int i = 0;
		for (i = 0; i < sizeof(kmalloc_caches)/sizeof(kmalloc_caches[0]); i++) {
			printk("--> idx %d | cache addr %p", i, kmalloc_caches[i]);
		}
		LIBLCD_MSG("==> Prep buffers 2, size %zu | idx %d  | ptr %p | KMALOC_MIN %d, SHIFT_LOW %d",
			sz, idx, kmalloc_caches[idx], KMALLOC_MIN_SIZE, KMALLOC_SHIFT_LOW);
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
	 * Free the async channel
	 *
	 * XXX: This is ok to do because there is no dispatch loop
	 * polling on the channel when we free it.
	 */
	LIBLCD_MSG("destroying channel %p", chnl);
	kfree(chnl);

	return;

fail2:
fail1:
	return;
}

int create_async_channel(void)
{
	int ret;
	cptr_t tx, rx;
	struct thc_channel *chnl;
	struct thc_channel_group_item *xmit_ch_item;
	/*
	 * Set up async and sync channels
	 */
	ret = lcd_create_sync_endpoint(&nullnet_sync_endpoints[current_lcd_id]);
	if (ret) {
		LIBLCD_ERR("lcd_create_sync_endpoint");
		goto fail1;
	}
	ret = setup_async_channel(&tx, &rx, &chnl);
	if (ret) {
		LIBLCD_ERR("async chnl setup failed");
		goto fail2;
	}
        lcd_set_cr0(nullnet_sync_endpoints[current_lcd_id]);
        lcd_set_cr1(rx);
        lcd_set_cr2(tx);
        lcd_set_cr3(CAP_CPTR_NULL);
        lcd_set_cr4(CAP_CPTR_NULL);
	// for function ID, we pass 0 as we are not calling a function
	lcd_set_r0(0x0);
	// conveys the LCD id the call is coming from
	lcd_set_r1(current_lcd_id);

#ifdef CONFIG_PREALLOC_XMIT_CHANNELS
	prep_xmit_channels_lcd();
#endif

	printk("%s, lcd_sync_call for lcd:%d\n", __func__, current_lcd_id);
        ret = lcd_sync_call(nullnet_register_channels[current_lcd_id]);

        /*
         * Flush cap registers
         */
        lcd_set_cr0(CAP_CPTR_NULL);
        lcd_set_cr1(CAP_CPTR_NULL);
        lcd_set_cr2(CAP_CPTR_NULL);
        lcd_set_cr3(CAP_CPTR_NULL);
        lcd_set_cr4(CAP_CPTR_NULL);

#ifdef CONFIG_PREALLOC_XMIT_CHANNELS
	prep_xmit_channels_clean_lcd();
#endif

        if (ret) {
                LIBLCD_ERR("lcd_call");
                goto fail3;
        }
	net_asyncs[current_lcd_id] = chnl;

	xmit_ch_item = kzalloc(sizeof(*xmit_ch_item), GFP_KERNEL);

	thc_channel_group_item_init(xmit_ch_item, chnl, NULL);

	xmit_ch_item->xmit_channel = true;

	thc_channel_group_item_add(&ch_grp[current_lcd_id], xmit_ch_item);
	printk("%s:%d adding chnl: %p to group: %p", __func__, current_lcd_id,
				xmit_ch_item, &ch_grp[current_lcd_id]);

	return ret;
fail3:
        //glue_cap_remove(c_cspace, ops_container->my_ref);
        //destroy_async_channel(chnl);
fail2:
	lcd_cap_delete(nullnet_sync_endpoints[current_lcd_id]);
fail1:
	return ret;
}

struct thc_channel_group_item *ptrs[NUM_LCDS][32];
static int idx[NUM_LCDS] = {0};

int create_one_async_channel(struct thc_channel **chnl, cptr_t *tx, cptr_t *rx)
{
	int ret;
	struct thc_channel_group_item *xmit_ch_item;
#ifdef ONE_SLOT
	ret = setup_async_channel_0(tx, rx, chnl);
#else
	ret = setup_async_channel(tx, rx, chnl);
#endif
	if (ret) {
		LIBLCD_ERR("async xmit chnl setup failed");
		return -1;
	}

	xmit_ch_item = kzalloc(sizeof(*xmit_ch_item), GFP_KERNEL);

	thc_channel_group_item_init(xmit_ch_item, *chnl, NULL);

	xmit_ch_item->xmit_channel = true;

	thc_channel_group_item_add(&ch_grp[current_lcd_id], xmit_ch_item);

	printk("%s:%d adding chnl: %p to group: %p", __func__, current_lcd_id,
				xmit_ch_item->channel, &ch_grp[current_lcd_id]);

	ptrs[current_lcd_id][idx[current_lcd_id]++%32] = xmit_ch_item;

	return 0;
}

#ifdef CONFIG_PREALLOC_XMIT_CHANNELS
int prep_xmit_channels_lcd(void)
{
	cptr_t tx[MAX_CHNL_PAIRS], rx[MAX_CHNL_PAIRS];
	struct thc_channel *xmit;
	int i, j;

	for (i = 0; i < MAX_CHNL_PAIRS; i++) {
		if (create_one_async_channel(&xmit, &tx[i], &rx[i]))
			LIBLCD_ERR("async channel creation failed\n");
	}

	for (i = 0, j = 5; i < MAX_CHNL_PAIRS && j < LCD_NUM_REGS; i++) {
		lcd_set_cr(j++, rx[i]);
		lcd_set_cr(j++, tx[i]);
	}

	return 0;
}

void prep_xmit_channels_clean_lcd(void)
{
	int i;
	for (i = 0; i < LCD_NUM_REGS; i++)
	       lcd_set_cr(i, CAP_CPTR_NULL);
}
#endif

//DONE
int __rtnl_link_register(struct rtnl_link_ops *ops)
{
	struct rtnl_link_ops_container *ops_container;
	cptr_t tx, rx;
	cptr_t tx_xmit, rx_xmit;
	struct thc_channel *chnl;
	struct thc_channel *xmit_chnl;
	struct thc_channel_group_item *ch_item;
	struct thc_channel_group_item *xmit_ch_item;

	int ret;

	/*
	 * Set up async and sync channels
	 */
	ret = lcd_create_sync_endpoint(&nullnet_sync_endpoints[current_lcd_id]);
	if (ret) {
		LIBLCD_ERR("lcd_create_sync_endpoint");
		goto fail1;
	}
	ret = setup_async_channel(&tx, &rx, &chnl);
	if (ret) {
		LIBLCD_ERR("async chnl setup failed");
		goto fail2;
	}

	ch_item = kzalloc(sizeof(*ch_item), GFP_KERNEL);

	thc_channel_group_item_init(ch_item, chnl, NULL);

	thc_channel_group_item_add(&ch_grp[current_lcd_id], ch_item);

	ret = setup_async_channel(&tx_xmit, &rx_xmit, &xmit_chnl);
	if (ret) {
		LIBLCD_ERR("async chnl setup failed");
		goto fail2;
	}

	xmit_ch_item = kzalloc(sizeof(*xmit_ch_item), GFP_KERNEL);

	thc_channel_group_item_init(xmit_ch_item,
				xmit_chnl, NULL);

	xmit_ch_item->xmit_channel = true;

	thc_channel_group_item_add(&ch_grp[current_lcd_id], xmit_ch_item);

	ops_container = container_of(ops,
			struct rtnl_link_ops_container,
			rtnl_link_ops);
	ret = glue_cap_insert_rtnl_link_ops_type(c_cspace,
			ops_container,
			&ops_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail3;
	}

	lcd_set_r0(__RTNL_LINK_REGISTER);
        lcd_set_r1(cptr_val(ops_container->my_ref));
	lcd_set_r2(current_lcd_id);
        lcd_set_cr0(nullnet_sync_endpoints[current_lcd_id]);
        lcd_set_cr1(rx);
        lcd_set_cr2(tx);
        lcd_set_cr3(rx_xmit);
        lcd_set_cr4(tx_xmit);

#ifdef CONFIG_PREALLOC_XMIT_CHANNELS
	prep_xmit_channels_lcd();
#endif

	g_rtnl_link_ops = ops;

	printk("%s, tx_xmit %lx | rx_xmit %lx", __func__,
				cptr_val(tx_xmit),
				cptr_val(rx_xmit));
        ret = lcd_sync_call(nullnet_register_channels[current_lcd_id]);

        /*
         * Flush cap registers
         */
        lcd_set_cr0(CAP_CPTR_NULL);
        lcd_set_cr1(CAP_CPTR_NULL);
        lcd_set_cr2(CAP_CPTR_NULL);
        lcd_set_cr3(CAP_CPTR_NULL);
        lcd_set_cr4(CAP_CPTR_NULL);

#ifdef CONFIG_PREALLOC_XMIT_CHANNELS
	prep_xmit_channels_clean_lcd();
#endif

        if (ret) {
                LIBLCD_ERR("lcd_call");
                goto fail4;
        }

        ret = lcd_r0();
	printk("%s: Got %d\n", __func__, ret);
        if (ret < 0) {
                LIBLCD_ERR("remote register fs failed");
                goto fail5;
        }

	ops_container->other_ref.cptr = lcd_r1();
	net_asyncs[current_lcd_id] = chnl;
	return ret;

fail5:
fail4:
        //glue_cap_remove(c_cspace, ops_container->my_ref);
fail3:
        //destroy_async_channel(chnl);
fail2:
	lcd_cap_delete(nullnet_sync_endpoints[current_lcd_id]);
fail1:
	return ret;
}

//DONE
void __rtnl_link_unregister(struct rtnl_link_ops *ops)
{
	int ret;
	int err;
	struct fipc_message *request;
	struct fipc_message *response;
	struct rtnl_link_ops_container *ops_container;

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		lcd_exit(-1);
	}
	ops_container = container_of(ops, struct rtnl_link_ops_container, rtnl_link_ops);
	async_msg_set_fn_type(request, __RTNL_LINK_UNREGISTER);
	fipc_set_reg1(request, ops_container->other_ref.cptr);
	err = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);
	if (err) {
		LIBLCD_ERR("thc_ipc_call");
		lcd_exit(-1);
	}
	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);
	return;
}

//DONE
int register_netdevice(struct net_device *dev)
{
	struct net_device_container *dev_container;
	struct net_device_ops_container *netdev_ops_container;
	struct rtnl_link_ops_container *rtnl_link_ops_container;
	int err;
	struct fipc_message *request;
	struct fipc_message *response;
	int ret;
	dev_container = container_of(dev, struct net_device_container, net_device);

	netdev_ops_container = container_of(dev->netdev_ops, struct net_device_ops_container, net_device_ops);

	rtnl_link_ops_container = container_of(dev->rtnl_link_ops, struct rtnl_link_ops_container, rtnl_link_ops);

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		lcd_exit(-1);
	}
	async_msg_set_fn_type(request, REGISTER_NETDEVICE);
	fipc_set_reg1(request, dev_container->other_ref.cptr);
	err = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);
	if (err) {
		LIBLCD_ERR("thc_ipc_call");
		lcd_exit(-1);
	}
	ret = fipc_get_reg4(response);
	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);
	return ret;

}

//DONE
void ether_setup(struct net_device *dev)
{
	int ret;
	int err;
	struct fipc_message *request;
	struct fipc_message *response;
	struct net_device_container *netdev_container;

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, ETHER_SETUP);

	netdev_container = container_of(dev, struct net_device_container, net_device);
	fipc_set_reg1(request, netdev_container->other_ref.cptr);
	LIBLCD_MSG("ndev other ref %lu\n", netdev_container->other_ref.cptr);
	err = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);
	if (err) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);
fail_ipc:
fail_async:
	return;
}

int sync_prep_data(void *data, unsigned long *sz, unsigned long *off, cptr_t *data_cptr)
{
    int ret;
	ret = lcd_virt_to_cptr(__gva((unsigned long)data), data_cptr, sz, off);
	if (ret) {
		LIBLCD_ERR("virt to cptr failed");
	}
	return ret;
}


// DONE
int eth_mac_addr(struct net_device *dev, void *p)
{
	struct fipc_message *request;
	struct fipc_message *response;
	int sync_ret;
	unsigned 	long p_mem_sz;
	unsigned 	long p_offset;
	cptr_t p_cptr;
	int ret;
	struct net_device_container *dev_container;
	uint32_t request_cookie;

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);

	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	dev_container = container_of(dev, struct net_device_container, net_device);

	fipc_set_reg1(request, dev_container->other_ref.cptr);

	async_msg_set_fn_type(request, ETH_MAC_ADDR);

	sync_ret = sync_prep_data(p, &p_mem_sz, &p_offset, &p_cptr);
	if (sync_ret) {
		LIBLCD_ERR("virt to cptr failed");
		lcd_exit(-1);
	}

	ret = thc_ipc_send_request(net_asyncs[current_lcd_id], request, &request_cookie);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}

	lcd_set_r0(p_mem_sz);
	lcd_set_r1(p_offset);
	lcd_set_cr0(p_cptr);
	sync_ret = lcd_sync_send(nullnet_sync_endpoints[current_lcd_id]);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to send");
		goto fail_sync;
	}

	ret = thc_ipc_recv_response(net_asyncs[current_lcd_id],
				request_cookie,
				&response);
	if (ret) {
		LIBLCD_ERR("async recv failed");
		goto fail_ipc_recv;
	}

	ret = fipc_get_reg1(response);
	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);

fail_async:
fail_sync:
fail_ipc_recv:
fail_ipc:
	return ret;
}

//DONE
int eth_validate_addr(struct net_device *dev)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct net_device_container *dev_container;

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(request, ETH_VALIDATE_ADDR);
	
	dev_container = container_of(dev, struct net_device_container, net_device);

	fipc_set_reg1(request, dev_container->other_ref.cptr);

	LIBLCD_MSG("%s, cptr lcd %lu", __func__, dev_container->other_ref.cptr);

	ret = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);

	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}

	ret = fipc_get_reg1(response);
	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);

fail_async:
fail_ipc:
	return ret;
}

//DONE
void free_netdev(struct net_device *dev)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct net_device_container *dev_container;

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, FREE_NETDEV);

	dev_container = container_of(dev, struct net_device_container, net_device);

	fipc_set_reg1(request, dev_container->other_ref.cptr);

	ret = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);

fail_async:
fail_ipc:
	return;
}

//DONE
void netif_carrier_off(struct net_device *dev)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct net_device_container *dev_container;

	dev_container = container_of(dev, struct net_device_container, net_device);

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(request, NETIF_CARRIER_OFF);
	fipc_set_reg1(request, dev_container->other_ref.cptr);
	
	ret = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);
fail_async:
fail_ipc:
	return;
}

//DONE
void netif_carrier_on(struct net_device *dev)
{
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	struct net_device_container *dev_container;

	dev_container = container_of(dev, struct net_device_container, net_device);

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, NETIF_CARRIER_ON);

	fipc_set_reg1(request, dev_container->other_ref.cptr);

	ret = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);

fail_async:
fail_ipc:
	return;
}

// DONE
void rtnl_link_unregister(struct rtnl_link_ops *ops)
{
	struct rtnl_link_ops_container *ops_container;
	int err;
	int ret;
	struct fipc_message *request;
	struct fipc_message *response;
	ops_container = container_of(ops, struct rtnl_link_ops_container, rtnl_link_ops);
	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail1;
	}
	async_msg_set_fn_type(request, RTNL_LINK_UNREGISTER);
	fipc_set_reg2(request, ops_container->other_ref.cptr);

	err = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);
	if (err) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail2;
	}

	glue_cap_remove(c_cspace, ops_container->my_ref);

	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);

	//lcd_cap_delete(nullnet_sync_endpoints[current_lcd_id]);
	if (0)
		destroy_async_channel(net_asyncs[current_lcd_id]);
fail2:
fail1:
	return;
}

// DONE
struct net_device *alloc_netdev_mqs(int sizeof_priv, const char *name, unsigned char name_assign_type, void (*setup)(struct net_device* dev), unsigned int txqs, unsigned int rxqs)
{
	struct setup_container *setup_container;
	int ret;
	int err;
	struct fipc_message *request;
	struct fipc_message *response;
	struct net_device_container *ret1;

	ret1 = kzalloc(sizeof( struct net_device_container   ), GFP_KERNEL);
	if (!ret1) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	setup_container = kzalloc(sizeof(*setup_container), GFP_KERNEL);
	if (!setup_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}

	setup_container->setup = setup;

	ret = glue_cap_insert_setup_type(c_cspace, setup_container, &setup_container->my_ref);

	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}

	ret = glue_cap_insert_net_device_type(c_cspace, ret1, &ret1->my_ref);

	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}

	ret = async_msg_blocking_send_start(net_asyncs[current_lcd_id], &request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(request, ALLOC_NETDEV_MQS);
	fipc_set_reg1(request, sizeof_priv);
	fipc_set_reg2(request, setup_container->my_ref.cptr);
	fipc_set_reg3(request, name_assign_type);
	fipc_set_reg4(request, txqs);
	fipc_set_reg5(request, rxqs);
	fipc_set_reg6(request, ret1->my_ref.cptr);
	printk("%s, netdevice lcd cptr : %lu", __func__, ret1->my_ref.cptr);
	err = thc_ipc_call(net_asyncs[current_lcd_id], request, &response);
	if (err) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}

	//ret1->other_ref.cptr = fipc_get_reg5(response);

	fipc_recv_msg_end(thc_channel_to_fipc(net_asyncs[current_lcd_id]), response);

fail_ipc:
fail_async:
fail_alloc:
fail_insert:
	return &ret1->net_device;
}

TS_DECL(ipc_send);
TS_DECL(hlookup);

void consume_skb(struct sk_buff *skb)
{
	int ret;
	struct fipc_message *request;
	struct lcd_sk_buff_container *skb_c;
	struct thc_channel *channel;

	skb_c = container_of(skb,
			struct lcd_sk_buff_container, skbuff);

#ifdef SENDER_DISPATCH_LOOP
	channel = (struct thc_channel*) skb_c->chnl;
#else
	channel = net_asyncs[current_lcd_id];
#endif
	ret = async_msg_blocking_send_start(channel, &request);

	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(request, CONSUME_SKB);

	thc_set_msg_type(request, msg_type_request);

#ifdef SENDER_DISPATCH_LOOP
	thc_set_msg_id(request, skb_c->cookie);
#endif
	fipc_send_msg_end (thc_channel_to_fipc(channel), request);

fail_async:
	return;
}

// DONE
int ndo_init_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct net_device_container *net_dev_container;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int ret;
	cptr_t netdev_ref = __cptr(fipc_get_reg1(request));

	request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ret = glue_cap_lookup_net_device_type(c_cspace, netdev_ref, &net_dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	ret = net_dev_container->net_device.netdev_ops->ndo_init(&net_dev_container->net_device);

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(response, ret);
	thc_ipc_reply(channel, request_cookie, response);
fail_lookup:
	return ret;
}

// DONE
int ndo_uninit_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	int ret;
	struct fipc_message *response;
	unsigned int request_cookie;
	struct net_device_container *net_dev_container;
	cptr_t netdev_ref = __cptr(fipc_get_reg1(request));

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ret = glue_cap_lookup_net_device_type(c_cspace, netdev_ref, &net_dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	printk("%s called, triggering rpc\n", __func__);

	net_dev_container->net_device.netdev_ops->ndo_uninit(&net_dev_container->net_device);

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(channel, request_cookie, response);
fail_lookup:
	return ret;
}
extern uint64_t st_disp_loop, en_disp_loop;

extern netdev_tx_t dummy_xmit(struct sk_buff *skb, struct net_device *dev);

int prep_channel_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	cptr_t tx, rx;
	struct thc_channel *xmit;
	unsigned 	int request_cookie;
	int ret;
	struct fipc_message *_response;

	request_cookie = thc_get_request_cookie(_request);

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	if (create_one_async_channel(&xmit, &tx, &rx))
		LIBLCD_ERR("async channel creation failed\n");

#if 0
	printk("Creating one for softirq\n");

	if (create_one_async_channel(&xmit_sirq, &tx_sirq, &rx_sirq))
		LIBLCD_ERR("async channel creation failed\n");
#endif
	lcd_set_cr0(tx);
	lcd_set_cr1(rx);

	LIBLCD_MSG("%s: Preparing sync send", __func__);
	ret = lcd_sync_send(nullnet_sync_endpoints[current_lcd_id]);

	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);

	if (ret) {
		LIBLCD_ERR("failed to send");
		lcd_exit(-1);
	}

	if (async_msg_blocking_send_start(_channel, &_response)) {
		LIBLCD_ERR("error getting response msg");
		ret = -EIO;
	}

	thc_ipc_reply(_channel, request_cookie, _response);

	return ret;
}

/* This function is used for testing bare fipc, non-async mtu sized packets */
int ndo_start_xmit_bare_callee(struct fipc_message *_request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct fipc_message *response;
#ifdef MARSHAL
	xmit_type_t xmit_type;
	unsigned long skbh_offset, skb_end;
	__be16 proto;
	u32 len;
	cptr_t skb_ref;

	xmit_type = fipc_get_reg0(_request);

	skb_ref = __cptr(fipc_get_reg2(_request));

	skbh_offset = fipc_get_reg3(_request);

	skb_end = fipc_get_reg4(_request);
	proto = fipc_get_reg5(_request);
	len = fipc_get_reg6(_request);
#endif
	fipc_recv_msg_end(thc_channel_to_fipc(channel), _request);

	if (likely(async_msg_blocking_send_start(channel, &response))) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
#ifdef MARSHAL
	fipc_set_reg1(response, skb_end|skbh_offset| proto | len | cptr_val(skb_ref));
#endif
	fipc_send_msg_end(thc_channel_to_fipc(channel), response);

	return 0;
}

int ndo_start_xmit_noawe_callee(struct fipc_message *_request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct lcd_sk_buff_container static_skb_c;
	struct lcd_sk_buff_container *skb_c = &static_skb_c;
	struct sk_buff *skb = &skb_c->skbuff;
	struct fipc_message *response;
	int ret;
#ifdef COPY
	struct skbuff_members *skb_lcd;
#endif

	unsigned long skbh_offset, skb_end;
	__be16 proto;
	u32 len;
	cptr_t skb_ref;

	skb_ref = __cptr(fipc_get_reg2(_request));

	skbh_offset = fipc_get_reg3(_request);

	skb_end = fipc_get_reg4(_request);
	proto = fipc_get_reg5(_request);
	len = fipc_get_reg6(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel),
				_request);

	skb->head = (char*)data_pool + skbh_offset;
	skb->end = skb_end;
	skb->len = len;
	skb->private = true;

#ifdef COPY
	skb_lcd = SKB_LCD_MEMBERS(skb);

	P(len);
	P(data_len);
	P(queue_mapping);
	P(xmit_more);
	P(tail);
	P(truesize);
	P(ip_summed);
	P(csum_start);
	P(network_header);
	P(csum_offset);
	P(transport_header);

	skb->data = skb->head + skb_lcd->head_data_off;
#endif

	skb_c->chnl = channel;

	ret = dummy_xmit(skb, NULL);

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg1(response, ret);
	thc_set_msg_type(response, msg_type_response);
	fipc_send_msg_end(thc_channel_to_fipc(channel), response);
	//printk("%s, response sent! chnl: %p", __func__, channel);
	return ret;
}

/* xmit_callee for async. This function receives the IPC and
 * sends back a response
 */
int ndo_start_xmit_async_bare_callee(struct fipc_message *_request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct fipc_message *response;
	unsigned 	int request_cookie;
	struct lcd_sk_buff_container static_skb_c;
	struct lcd_sk_buff_container *skb_c = &static_skb_c;
	struct sk_buff *skb = &skb_c->skbuff;
#ifdef COPY
	struct skbuff_members *skb_lcd;
#endif
	unsigned long skbh_offset, skb_end;
	__be16 proto;
	u32 len;
	cptr_t skb_ref;

	request_cookie = thc_get_request_cookie(_request);

	skb_ref = __cptr(fipc_get_reg2(_request));

	skbh_offset = fipc_get_reg3(_request);

	skb_end = fipc_get_reg4(_request);
	proto = fipc_get_reg5(_request);
	len = fipc_get_reg6(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel),
				_request);

	skb->head = (char*)data_pool + skbh_offset;
	skb->end = skb_end;
	skb->len = len;
	skb->private = true;

#ifdef COPY
	skb_lcd = SKB_LCD_MEMBERS(skb);

	P(len);
	P(data_len);
	P(queue_mapping);
	P(xmit_more);
	P(tail);
	P(truesize);
	P(ip_summed);
	P(csum_start);
	P(network_header);
	P(csum_offset);
	P(transport_header);

	skb->data = skb->head + skb_lcd->head_data_off;
#endif

	fipc_recv_msg_end(thc_channel_to_fipc(channel),
				_request);

	skb_c->chnl = channel;

	skb_c->cookie = request_cookie;

	dummy_xmit(skb, NULL);

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	return thc_ipc_reply(channel, request_cookie, response);
}

// DONE
int ndo_validate_addr_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct net_device_container *net_dev_container;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int ret;
	cptr_t netdev_ref = __cptr(fipc_get_reg1(request));

	ret = glue_cap_lookup_net_device_type(c_cspace, netdev_ref, &net_dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	LIBLCD_MSG("%s, cptr lcd %lu", __func__, netdev_ref);
	LIBLCD_MSG("%s, looked up cptr lcd %p |  %lu", __func__, net_dev_container, net_dev_container->other_ref.cptr);

	request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ret = net_dev_container->net_device.netdev_ops->ndo_validate_addr(&net_dev_container->net_device);

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(response, ret);
	thc_ipc_reply(channel, request_cookie, response);

fail_lookup:
	return ret;
}

// DONE
int ndo_set_rx_mode_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	int ret;
	struct net_device_container *net_dev_container;
	struct fipc_message *response;
	unsigned 	int request_cookie;

	ret = glue_cap_lookup_net_device_type(c_cspace, __cptr(fipc_get_reg1(request)), &net_dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	net_dev_container->net_device.netdev_ops->ndo_set_rx_mode(&net_dev_container->net_device);

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	thc_ipc_reply(channel, request_cookie, response);

fail_lookup:
	return ret;
}

// DONE
int ndo_set_mac_address_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct fipc_message *response;
	struct net_device_container *net_dev_container;
	unsigned 	int request_cookie;
	int ret;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long addr_offset;
	cptr_t addr_cptr;
	gva_t addr_gva;
	request_cookie = thc_get_request_cookie(request);

	ret = glue_cap_lookup_net_device_type(c_cspace, __cptr(fipc_get_reg1(request)), &net_dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	sync_ret = lcd_cptr_alloc(&addr_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		goto fail_sync;
	}

	lcd_set_cr0(addr_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		goto fail_sync;
	}
	mem_order = lcd_r0();
	addr_offset = lcd_r1();
	LIBLCD_MSG("%s: cptr %lu | order %lu | offset %lu",
		__func__, addr_cptr.cptr, mem_order, addr_offset);

	sync_ret = lcd_map_virt(addr_cptr, mem_order, &addr_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *addr");
		goto fail_sync;
	}

	ret = net_dev_container->net_device.netdev_ops->ndo_set_mac_address(&net_dev_container->net_device, (void*)(gva_val(addr_gva) + addr_offset));

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg1(response, ret);
	thc_ipc_reply(channel, request_cookie, response);
fail_lookup:
fail_sync:
	return 0;
}

// DONE
int ndo_get_stats64_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct fipc_message *response;
	unsigned 	int request_cookie;
	struct rtnl_link_stats64 stats;
	int ret;
	struct net_device_container *net_dev_container;
	cptr_t netdev_ref = __cptr(fipc_get_reg1(request));

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ret = glue_cap_lookup_net_device_type(c_cspace, netdev_ref,
			&net_dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	net_dev_container->net_device.
		netdev_ops->ndo_get_stats64(
			&net_dev_container->net_device,
			&stats);

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg1(response, stats.tx_packets);
	fipc_set_reg2(response, stats.tx_bytes);

	thc_ipc_reply(channel, request_cookie, response);

fail_lookup:
	return ret;
}

// DONE
int ndo_change_carrier_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int ret;
	struct net_device_container *net_dev_container;
	bool new_carrier = fipc_get_reg2(request);
	
	ret = glue_cap_lookup_net_device_type(c_cspace, __cptr(fipc_get_reg1(request)), &net_dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ret = net_dev_container->net_device.netdev_ops->ndo_change_carrier(&net_dev_container->net_device, new_carrier);

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg1(response, ret);
	thc_ipc_reply(channel, request_cookie, response);

fail_lookup:
	return ret;
}

// DONE
int setup_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	int ret;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	struct net_device_container *net_dev_container;
	struct net_device_ops_container *netdev_ops_container;
	const struct net_device_ops *netdev_ops;
	cptr_t netdev_ref = __cptr(fipc_get_reg1(request));
	cptr_t netdev_ops_ref = __cptr(fipc_get_reg4(request));
	cptr_t netdev_other_ref = __cptr(fipc_get_reg3(request));
	cptr_t pool_cptr;
	gva_t pool_addr;
	unsigned int pool_ord;

	request_cookie = thc_get_request_cookie(request);

	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

	ret = glue_cap_lookup_net_device_type(c_cspace, netdev_ref, &net_dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	// save other ref cptr
	net_dev_container->other_ref = netdev_other_ref;
	LIBLCD_MSG("%s, lcd other ref %p | %lu", __func__, net_dev_container, net_dev_container->other_ref.cptr);

	/* receive shared data pool */
	ret = lcd_cptr_alloc(&pool_cptr);
	if (ret) {
		LIBLCD_ERR("failed to get cptr");
		goto fail_cptr;
	}

	lcd_set_cr0(pool_cptr);

	printk("%s, calling sync recv", __func__);
	ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);

	pool_ord = lcd_r0();

	ret = lcd_map_virt(pool_cptr, pool_ord, &pool_addr);
	if (ret) {
		LIBLCD_ERR("failed to map pool");
		goto fail_pool;
	}

	LIBLCD_MSG("%s, mapping private pool %p | ord %d", __func__,
			gva_val(pool_addr), pool_ord);

	data_pool = (void*)gva_val(pool_addr);

	g_rtnl_link_ops->setup(&net_dev_container->net_device);

	netdev_ops = net_dev_container->net_device.netdev_ops;

	netdev_ops_container = container_of(netdev_ops, struct net_device_ops_container, net_device_ops);

	netdev_ops_container->other_ref = netdev_ops_ref;

	ret = glue_cap_insert_net_device_ops_type(c_cspace, netdev_ops_container, &netdev_ops_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}

	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg1(response, net_dev_container->net_device.flags);
	fipc_set_reg2(response, net_dev_container->net_device.priv_flags);
	fipc_set_reg3(response, net_dev_container->net_device.features);
	fipc_set_reg4(response, net_dev_container->net_device.hw_features);
	fipc_set_reg5(response, net_dev_container->net_device.hw_enc_features);
	fipc_set_reg6(response, netdev_ops_container->my_ref.cptr);

	thc_ipc_reply(channel, request_cookie, response);
fail_lookup:
fail_insert:
fail_pool:
fail_cptr:
	return ret;
}

// TODO:
int validate_callee(struct fipc_message *request, struct thc_channel *channel, struct glue_cspace *cspace, struct cptr sync_ep)
{
	struct nlattr **tb;
	struct nlattr **data;
	struct fipc_message *response;
	unsigned 	int request_cookie;
	int ret = 0;
	request_cookie = thc_get_request_cookie(request);
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);
	tb = kzalloc(sizeof( void  * ), GFP_KERNEL);
	if (!tb) {
		LIBLCD_ERR("kzalloc");
		lcd_exit(-1);
	}
	( *tb ) = kzalloc(sizeof( ( **tb ) ), GFP_KERNEL);
	if (!( *tb )) {
		LIBLCD_ERR("kzalloc");
		lcd_exit(-1);
	}
	data = kzalloc(sizeof( void  * ), GFP_KERNEL);
	if (!data) {
		LIBLCD_ERR("kzalloc");
		lcd_exit(-1);
	}
	( *data ) = kzalloc(sizeof( ( *data ) ), GFP_KERNEL);
	if (!( *data )) {
		LIBLCD_ERR("kzalloc");
		lcd_exit(-1);
	}
//	ret = validate(( *tb ), ( *data ));
	if (async_msg_blocking_send_start(channel, &response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(response, ret);
	thc_ipc_reply(channel, request_cookie, response);
	return ret;
}

int cleanup_channel_group(struct fipc_message *request, struct thc_channel *channel)
{
	fipc_recv_msg_end(thc_channel_to_fipc(channel), request);

#ifndef CONFIG_PREALLOC_XMIT_CHANNELS
	{
	int i;
	for (i = 0; i < 32; i++) {
		if (ptrs[current_lcd_id][i]) {
			thc_channel_group_item_remove(&ch_grp[current_lcd_id], ptrs[current_lcd_id][i]);
			destroy_async_channel(ptrs[current_lcd_id][i]->channel);
			kfree(ptrs[current_lcd_id][i]);
			ptrs[current_lcd_id][i] = NULL;
		} //if
	} //for
	}
#endif
	return 0;
}
