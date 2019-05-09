#include <lcd_config/pre_hook.h>

#include <libcap.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <liblcd/glue_cspace.h>
#include <liblcd/trampoline.h>
#include <linux/aer.h>

#include "../../ixgbe_common.h"
#include "../ixgbe_callee.h"
#include "../../rdtsc_helper.h"

#include <linux/hashtable.h>
#include <asm/cacheflush.h>
#include <asm/lcd_domains/ept.h>
#include <lcd_domains/microkernel.h>

#include <linux/priv_mempool.h>
#include <linux/sort.h>
#include <lcd_config/post_hook.h>

//#define TIMESTAMP
//#define LCD_MEASUREMENT
//#define FREE_TIMESTAMP
//#define SKBC_PRIVATE_POOL
#define STATS

#define NUM_CORES	32
#define NUM_THREADS	NUM_CORES

struct ptstate_t *ptrs[NUM_THREADS] = {0};
u32 thread = 0;
struct glue_cspace *c_cspace = NULL;
struct thc_channel *ixgbe_async;
struct cptr sync_ep;
extern struct cspace *klcd_cspace;
extern struct thc_channel *xmit_chnl;
extern struct thc_channel *xmit_chnl2;
extern struct thc_channel *xmit_irq_chnl;
struct timer_list service_timer;
struct napi_struct *napi_q0;

struct lcd_channels lcds[NUM_LCDS];

#define NUM_PACKETS	(170000)
#define VMALLOC_SZ	(NUM_PACKETS * sizeof(uint64_t))

uint64_t *times_ndo_xmit = NULL;
uint64_t *times_lcd = NULL;
uint64_t *times_free = NULL;

static u64 global_tx_count, global_free_count;
struct rtnl_link_stats64 g_stats;

/* This is the only device we strive for */
#define IXGBE_DEV_ID_82599_SFP_SF2       0x154D
#define IXGBE_DEV_ID_82599_SFP           0x10FB

/* XXX: There's no way to pass arrays across domains for now.
 * May not be in the future too! But agree that this is ugly
 * and move forward. - vik
 */
static const struct pci_device_id ixgbe_pci_tbl[] = {
	/* {PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP_SF2) }, */
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP) },
	{ 0 } /* sentinel */
};

/* XXX: How to determine this? */
#define CPTR_HASH_BITS      5
static DEFINE_HASHTABLE(cptr_table, CPTR_HASH_BITS);

struct pci_dev *g_pdev = NULL;
struct net_device *g_ndev = NULL;
struct kmem_cache *skb_c_cache = NULL;

DEFINE_SPINLOCK(hspin_lock);
static unsigned long pool_pfn_start, pool_pfn_end;
priv_pool_t *pool;
void *pool_base = NULL;
size_t pool_size = 0;
#ifdef SKBC_PRIVATE_POOL
priv_pool_t *skbc_pool;
#endif

#define MAX_POOLS	20

char *base_pools[MAX_POOLS];
int pool_order = 10;
int start_idx[MAX_POOLS/2] = {-1}, end_idx[MAX_POOLS/2] = {-1};
unsigned int best_diff = 0;
int best_idx = -1;
int pool_idx = 0;
struct {
	int start_idx;
	int end_idx;
	size_t size;
	bool valid;
} pools[MAX_POOLS] = { {0} };

int ndo_start_xmit_async_landing(struct sk_buff *first, struct net_device *dev, struct trampoline_hidden_args *hidden_args);

int compare_addr(const void *a, const void *b)
{
	return *(unsigned int *)a - *(unsigned int *)b;
}

int pool_pick(void)
{
	int i;

	/* allocate series of pages */
	for (i = 0; i < MAX_POOLS; i++) {
		base_pools[i] = (char*) __get_free_pages(GFP_KERNEL | __GFP_ZERO,
	                            pool_order);
	}

	/* sort all of base addresses */
	sort(base_pools, MAX_POOLS, sizeof(char*), compare_addr, NULL);

	printk("%s, sorted order:\n", __func__);
	for (i = 0; i < MAX_POOLS; i++) {
		printk("%s, got pool %p\n", __func__, base_pools[i]);
	}

	pools[pool_idx].start_idx = 0;
	pools[pool_idx].end_idx = MAX_POOLS - 1;
	pools[pool_idx].valid = true;

	for (i = 0; i < MAX_POOLS - 1; i++) {
		printk("%s, comparing pool[%d]=%llx and pool[%d]=%llx\n", __func__,
					i+1, (uint64_t)base_pools[i+1], i, (uint64_t) base_pools[i]);
		if (((uint64_t) base_pools[i+1] - (uint64_t) base_pools[i]) != ((1 << pool_order) * PAGE_SIZE)) {
			printk("%s, found discontinuity @ i %d\n", __func__, i);
			pools[pool_idx].valid = true;
			pools[pool_idx++].end_idx = i;
			pools[pool_idx].start_idx = i + 1;
		}
	}
	/* if there is no discontinuity, then we will have a huge chunk until the end */
	pools[pool_idx].valid = true;
	pools[pool_idx].end_idx = MAX_POOLS - 1;

	for (i = 0; i < pool_idx + 1; i++) {
		printk("%s, pool %d: start idx = %d | end idx = %d\n",
				__func__, i, pools[i].start_idx, pools[i].end_idx);
		if (!pools[i].valid)
			continue;
		if ((pools[i].end_idx - pools[i].start_idx + 1) > best_diff) {
			best_idx = i;
			best_diff = pools[i].end_idx - pools[i].start_idx + 1;
		}
	}
	printk("%s, best diff %u | best idx %d | start = %d | end = %d\n",
			__func__, best_diff, best_idx, pools[best_idx].start_idx, pools[best_idx].end_idx);
       	return best_idx;
}

void skb_data_pool_init(void)
{
	printk("%s, init pool for skbdata | size %zu | %lx\n", __func__,
			SKB_DATA_SIZE, SKB_DATA_SIZE);
	// XXX: round it to 2KiB
	//pool = priv_pool_init(SKB_DATA_POOL, 0x20, 2048);
	pool_base = base_pools[pools[pool_pick()].start_idx];
	pool_size = best_diff * ((1 << pool_order) * PAGE_SIZE);
	pool = priv_pool_init((void*) pool_base, pool_size, 2048, "skb_data_pool");
#ifdef SKBC_PRIVATE_POOL
	skbc_pool = priv_pool_init(SKB_CONTAINER_POOL, 0x20,
				SKB_CONTAINER_SIZE * 2);
#endif
}

void skb_data_pool_free(void)
{
	priv_pool_destroy(pool);
#ifdef SKBC_PRIVATE_POOL
	priv_pool_destroy(skbc_pool);
#endif
}

xmit_type_t check_skb_range(struct sk_buff *skb)
{
	unsigned long pfn;
	pfn = ((unsigned long)skb->data) >> PAGE_SHIFT;
	if (pfn >= pool_pfn_start && pfn <= pool_pfn_end) {
		WARN_ON(!skb->private);
		return SHARED_DATA_XMIT;
	} else
		return VOLUNTEER_XMIT;
}

int glue_ixgbe_init(void)
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

	/* initialize our private pool */
	skb_data_pool_init();

	times_ndo_xmit = vzalloc(NUM_PACKETS * sizeof(uint64_t));

	times_lcd = vzalloc(NUM_PACKETS * sizeof(uint64_t));

	times_free = vzalloc(NUM_PACKETS * sizeof(uint64_t));

	skb_c_cache = kmem_cache_create("skb_c_cache",
				sizeof(struct sk_buff_container),
				0,
				SLAB_HWCACHE_ALIGN|SLAB_PANIC,
				NULL);
	if (!skb_c_cache) {
		LIBLCD_ERR("Could not create skb container cache");
		goto fail2;
	}

	return 0;
fail2:
	glue_cap_exit();
fail1:
	return ret;

}

void glue_ixgbe_exit(void)
{
	glue_cap_destroy(c_cspace);
	glue_cap_exit();
	if (skb_c_cache)
		kmem_cache_destroy(skb_c_cache);

	if (times_ndo_xmit)
		vfree(times_ndo_xmit);

	if (times_lcd)
		vfree(times_lcd);

	if (times_free)
		vfree(times_free);
}

int glue_insert_skbuff(struct hlist_head *htable, struct sk_buff_container *skb_c)
{
	BUG_ON(!skb_c->skb);

	skb_c->my_ref = __cptr((unsigned long)skb_c->skb);

	spin_lock(&hspin_lock);
	hash_add(cptr_table, &skb_c->hentry,
			(unsigned long) skb_c->skb);
	spin_unlock(&hspin_lock);
	return 0;
}

int glue_lookup_skbuff(struct hlist_head *htable, struct cptr c, struct sk_buff_container **skb_cout)
{
	struct sk_buff_container *skb_c;

	spin_lock(&hspin_lock);
	hash_for_each_possible(cptr_table, skb_c,
			hentry, (unsigned long) cptr_val(c)) {
		if (skb_c->skb == (struct sk_buff*) c.cptr)
			*skb_cout = skb_c;
	}
	spin_unlock(&hspin_lock);
	return 0;
}

void glue_remove_skbuff(struct sk_buff_container *skb_c)
{
	spin_lock(&hspin_lock);
	hash_del(&skb_c->hentry);
	spin_unlock(&hspin_lock);
}

void destroy_async_net_ring_channel(struct thc_channel *chnl)
{
	cptr_t tx, rx;
	gva_t tx_gva, rx_gva;
	unsigned long unused1, unused2;
	int ret;
	unsigned int pg_order = ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
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

int setup_async_net_ring_channel(cptr_t tx, cptr_t rx, 
				struct thc_channel **chnl_out)
{
	gva_t tx_gva, rx_gva;
	int ret;
	struct fipc_ring_channel *fchnl;
	struct thc_channel *chnl;
	unsigned int pg_order = ASYNC_RPC_BUFFER_ORDER - PAGE_SHIFT;
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
				ASYNC_RPC_BUFFER_ORDER,
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

int sync_setup_memory(void *data, size_t sz, unsigned long *order, cptr_t *data_cptr, unsigned long *data_offset)
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
        data_len = sz;
        mem_len = ALIGN(data + data_len - page_address(p), PAGE_SIZE);
        *order = ilog2(roundup_pow_of_two(mem_len >> PAGE_SHIFT));
        /*
         * Volunteer memory
         */
        *data_offset = data - page_address(p);
        ret = lcd_volunteer_pages(p, *order, data_cptr);
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

int grant_sync_ep(cptr_t *sync_end, cptr_t ha_sync_ep)
{
	int ret;
	struct cspace *curr_cspace = get_current_cspace(current);
	lcd_cptr_alloc(sync_end);
	ret = cap_grant(klcd_cspace, ha_sync_ep,
			curr_cspace, *sync_end);
	current->ptstate->syncep_present = true;
	current->ptstate->sync_ep = sync_end->cptr;
	return ret;
}

LCD_TRAMPOLINE_DATA(probe_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(probe_trampoline)
probe_trampoline(struct pci_dev *dev,
		struct pci_device_id *id)
{
	int ( *volatile probe_fp )(struct pci_dev *,
		struct pci_device_id *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			probe_trampoline);
	probe_fp = probe;
	return probe_fp(dev,
		id,
		hidden_args);

}

LCD_TRAMPOLINE_DATA(remove_trampoline);
void  LCD_TRAMPOLINE_LINKAGE(remove_trampoline)
remove_trampoline(struct pci_dev *dev)
{
	void ( *volatile remove_fp )(struct pci_dev *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			remove_trampoline);
	remove_fp = remove;
	return remove_fp(dev,
		hidden_args);

}

const char driver_name[] = "ixgbe_lcd";

int pci_disable_msix_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev = g_pdev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	pci_disable_msix(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_enable_msix_range_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long p_offset;
	cptr_t p_cptr;
	gva_t p_gva;
	int minvec, maxvec;
	struct msix_entry *entries;

	dev = g_pdev;

	request_cookie = thc_get_request_cookie(_request);
	minvec = fipc_get_reg0(_request);
	maxvec = fipc_get_reg1(_request);

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	sync_ret = lcd_cptr_alloc(&p_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		lcd_exit(-1);
	}
	lcd_set_cr0(p_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		lcd_exit(-1);
	}
	mem_order = lcd_r0();
	p_offset = lcd_r1();
	sync_ret = lcd_map_virt(p_cptr,
		mem_order,
		&p_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *p");
		lcd_exit(-1);
	}

	entries = (struct msix_entry*)(void*)(gva_val(p_gva) + p_offset);

	LIBLCD_MSG("%s, dev->msix_enabled %d | minvec %d | maxvec %d",
			__func__, dev->msix_enabled, minvec, maxvec);

	func_ret = pci_enable_msix_range(dev, entries, minvec, maxvec);

	LIBLCD_MSG("%s, returned %d", __func__, func_ret);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}



int __pci_register_driver_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_driver_container *drv_container;
	struct module_container *owner_container;
	char *name;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	struct trampoline_hidden_args *drv_probe_hidden_args;
	struct trampoline_hidden_args *drv_remove_hidden_args;
	int func_ret = 0;
	int ret = 0;

	request_cookie = thc_get_request_cookie(_request);
	drv_container = kzalloc(sizeof( struct pci_driver_container   ),
		GFP_KERNEL);
	if (!drv_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}

	ret = glue_cap_insert_pci_driver_type(c_cspace,
		drv_container,
		&drv_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	drv_container->other_ref.cptr = fipc_get_reg2(_request);
	owner_container = kzalloc(sizeof( struct module_container   ),
		GFP_KERNEL);
	if (!owner_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	ret = glue_cap_insert_module_type(c_cspace,
		owner_container,
		&owner_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	owner_container->other_ref.cptr = fipc_get_reg3(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	drv_probe_hidden_args = kzalloc(sizeof( *drv_probe_hidden_args ),
		GFP_KERNEL);
	if (!drv_probe_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc1;
	}
	drv_probe_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(probe_trampoline);
	if (!drv_probe_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup1;
	}
	drv_probe_hidden_args->t_handle->hidden_args = drv_probe_hidden_args;
	drv_probe_hidden_args->struct_container = drv_container;
	drv_probe_hidden_args->cspace = c_cspace;
	drv_probe_hidden_args->sync_ep = sync_ep;
	drv_probe_hidden_args->async_chnl = _channel;
	drv_container->pci_driver.probe = LCD_HANDLE_TO_TRAMPOLINE(drv_probe_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )drv_probe_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(probe_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));

	drv_remove_hidden_args = kzalloc(sizeof( *drv_remove_hidden_args ),
		GFP_KERNEL);
	if (!drv_remove_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc2;
	}
	drv_remove_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(remove_trampoline);
	if (!drv_remove_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup2;
	}
	drv_remove_hidden_args->t_handle->hidden_args = drv_remove_hidden_args;
	drv_remove_hidden_args->struct_container = drv_container;
	drv_remove_hidden_args->cspace = c_cspace;
	drv_remove_hidden_args->sync_ep = sync_ep;
	drv_remove_hidden_args->async_chnl = _channel;
	drv_container->pci_driver.remove = LCD_HANDLE_TO_TRAMPOLINE(drv_remove_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )drv_remove_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(remove_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));

	drv_container->pci_driver.name = driver_name;
	drv_container->pci_driver.id_table = ixgbe_pci_tbl;
	name = "ixgbe_lcd";
	/* XXX: We should rather call __pci_register_driver
	 * (at least according to the RPC semantics).
	 * However, kobject subsys is not happy with us on mangling
	 * the module name. If we call pci_register_driver instead,
	 * module pointer is taken from THIS_MODULE and kobject is
	 * happy. So, do _not_ do such crap! kobject is unhappy
	owner_container->module.state = MODULE_STATE_LIVE;
	strcpy(owner_container->module.name, "ixgbe_lcd");
	atomic_inc(&owner_container->module.refcnt);
	*/

	func_ret = pci_register_driver(&drv_container->pci_driver);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("retor getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			drv_container->my_ref.cptr);
	fipc_set_reg2(_response,
			owner_container->my_ref.cptr);
	fipc_set_reg3(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_alloc:
fail_alloc1:
fail_alloc2:
fail_dup1:
fail_dup2:
fail_insert:
	return ret;
}

int alloc_etherdev_mqs_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	int sizeof_priv;
	unsigned 	int txqs;
	unsigned 	int rxqs;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	struct net_device_container *func_ret_container;
	struct net_device *func_ret;
	cptr_t netdev_ref;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	sizeof_priv = fipc_get_reg1(_request);
	txqs = fipc_get_reg2(_request);
	rxqs = fipc_get_reg3(_request);
	netdev_ref.cptr = fipc_get_reg4(_request);

	func_ret = alloc_etherdev_mqs(sizeof_priv,
		txqs,
		rxqs);
	g_ndev = func_ret;
	func_ret_container = container_of(func_ret,
		struct net_device_container, net_device);
	func_ret_container->other_ref = netdev_ref;
	ret = glue_cap_insert_net_device_type(c_cspace,
		func_ret_container,
		&func_ret_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret_container->my_ref.cptr);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_insert:
	return ret;

}

int probe_user(struct pci_dev *dev,
		struct pci_device_id *id,
		struct trampoline_hidden_args *hidden_args)
{
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	int ret;

	/* XXX: we need cptr tree too. This lcd context will be destroyed
	 * rendering any volunteered resource void after this function is
	 * returned. Not the right way to do it. Use lcd_enter instead.
	 */
	thc_init();

	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			PROBE);
	DO_FINISH_(probe_user,{
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, probe_user
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	return ret;
}

extern void ixgbe_service_timer(unsigned long data);

int probe(struct pci_dev *dev,
		struct pci_device_id *id,
		struct trampoline_hidden_args *hidden_args)
{
	struct pci_dev_container *dev_container;
	int ret = 0;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
#ifdef PCI_REGIONS
	uint32_t request_cookie;
	cptr_t res0_cptr;
	unsigned int res0_len;
	struct page *p;
	unsigned int pool_ord;
	cptr_t pool_cptr;
#endif
	struct thc_channel *async_chnl = hidden_args->async_chnl;
	cptr_t sync_end;
	bool nonlcd = false;

	/* assign pdev to a global instance */
	g_pdev = dev;

	LIBLCD_MSG("%s, irq # %d | msix_enabled %d", __func__, dev->irq, dev->msix_enabled);

	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);

		lcd_enter();
		nonlcd = true;
		grant_sync_ep(&sync_end, hidden_args->sync_ep);
		goto normal_probe;
	} else {
		sync_end = hidden_args->sync_ep;
	}

normal_probe:
	dev_container = kzalloc(sizeof( struct pci_dev_container   ),
		GFP_KERNEL);
	if (!dev_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}

	/* pci_dev is used later. So let's insert it into KLCD's cspace */
	ret = glue_cap_insert_pci_dev_type(hidden_args->cspace,
		dev_container,
		&dev_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}

	if (nonlcd)
		ret = fipc_test_blocking_send_start(async_chnl,
				&_request);
	else
		ret = async_msg_blocking_send_start(async_chnl,
				&_request);

	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			PROBE);
	fipc_set_reg1(_request,
			dev_container->my_ref.cptr);
	fipc_set_reg2(_request,
			*dev->dev.dma_mask);

#ifdef PCI_REGIONS
	ret = thc_ipc_send_request(async_chnl,
			_request,
			&request_cookie);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	printk("%s, send request done\n", __func__);
	/*
	 * ixgbe driver just needs res[0]
	 */
	res0_len = pci_resource_len(dev, 0);
	ret = lcd_volunteer_dev_mem(__gpa(pci_resource_start(dev, 0)),
			get_order(res0_len),
			&res0_cptr);
	if (ret) {
		LIBLCD_ERR("volunteer devmem");
		goto fail_vol;
	}

        p = virt_to_head_page(pool->base);

	pool_ord = ilog2(roundup_pow_of_two((1 << pool_order) * best_diff));
        ret = lcd_volunteer_pages(p, pool_ord, &pool_cptr);

	if (ret) {
		LIBLCD_ERR("volunteer shared region");
		goto fail_vol;
	}

	pool_pfn_start = (unsigned long)pool->base >> PAGE_SHIFT;
	pool_pfn_end = pool_pfn_start + ((1 << pool_order) * best_diff);

	lcd_set_cr0(res0_cptr);
	lcd_set_cr1(pool_cptr);
	lcd_set_r0(res0_len);
	lcd_set_r1(pool_ord);

	printk("%s, trying sync send\n", __func__);

	ret = lcd_sync_send(sync_end);
	lcd_set_cr0(CAP_CPTR_NULL);

	if (ret) {
		LIBLCD_ERR("sync send");
		goto fail_sync;
	}

	printk("%s, sync send done. waiting for resp\n", __func__);

	if (nonlcd) {
		DO_FINISH_(_probe_user,{
			ASYNC_({
				ret = thc_ipc_recv_response(async_chnl,
						request_cookie, &_response);
			}, _probe_user);
		});
	} else {
		ret = thc_ipc_recv_response(async_chnl,
				request_cookie,
				&_response);
	}

	if (ret) {
		LIBLCD_ERR("failed to recv ipc");
		goto fail_ipc_rx;
	}
#else
	ret = thc_ipc_call(async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
#endif
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(async_chnl),
			_response);

	setup_timer(&service_timer, &ixgbe_service_timer, (unsigned long) NULL);

	if (nonlcd)
		lcd_exit(0);
	return func_ret;

fail_async:
fail_sync:
fail_ipc:
fail_vol:
fail_insert:
fail_alloc:
fail_ipc_rx:
	return ret;
}

int pci_unregister_driver_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_driver_container *drv_container;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int ret;
	struct trampoline_hidden_args *drv_probe_hidden_args;

	request_cookie = thc_get_request_cookie(_request);

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	ret = glue_cap_lookup_pci_driver_type(cspace,
		__cptr(fipc_get_reg2(_request)),
		&drv_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}

	LIBLCD_MSG("Calling pci_unregister_driver");

	pci_unregister_driver(( &drv_container->pci_driver ));

	/* destroy our skb->data pool */
	skb_data_pool_free();

	LIBLCD_MSG("Called pci_unregister_driver");
	glue_cap_remove(c_cspace,
			drv_container->my_ref);

	/* XXX: Do not do anything like this! read the comments
	 * under pci_unregister_driver
	 * atomic_dec_if_positive(&drv_container->pci_driver.driver.owner->refcnt);
	 */
	drv_probe_hidden_args = LCD_TRAMPOLINE_TO_HIDDEN_ARGS(drv_container->pci_driver.probe);
	kfree(drv_probe_hidden_args->t_handle);
	kfree(drv_probe_hidden_args);
	kfree(drv_container);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("retor getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
	return ret;
}

void remove_user(struct pci_dev *dev,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	thc_init();

	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			REMOVE);
	DO_FINISH_(remove_user,{
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, remove_user
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return;
fail_async:
fail_ipc:
	return;
}

void remove(struct pci_dev *dev,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			remove_user(dev,
					hidden_args);
		}
		);
		return;
	}

	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			REMOVE);

	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	del_timer_sync(&service_timer);
	return;
fail_async:
fail_ipc:
	return;
}

int ndo_open_user(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_OPEN);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	DO_FINISH({
		ASYNC({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	mod_timer(&service_timer, jiffies + msecs_to_jiffies(5000));
	napi_enable(napi_q0);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	return ret;
}

int ndo_open(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ret = ndo_open_user(dev,
		hidden_args);
		}
		);
		return ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_OPEN);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

LCD_TRAMPOLINE_DATA(ndo_open_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(ndo_open_trampoline)
ndo_open_trampoline(struct net_device *dev)
{
	int ( *volatile ndo_open_fp )(struct net_device *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_open_trampoline);
	ndo_open_fp = ndo_open;
	return ndo_open_fp(dev,
		hidden_args);

}

int ndo_stop_user(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_STOP);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	DO_FINISH({
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, ndo_stop
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

int ndo_stop(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ret = ndo_stop_user(dev,
		hidden_args);
		}
		);
		return ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_STOP);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

LCD_TRAMPOLINE_DATA(ndo_stop_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(ndo_stop_trampoline)
ndo_stop_trampoline(struct net_device *dev)
{
	int ( *volatile ndo_stop_fp )(struct net_device *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_stop_trampoline);
	ndo_stop_fp = ndo_stop;
	return ndo_stop_fp(dev,
		hidden_args);

}

int ndo_start_xmit_dofin(struct sk_buff *skb,
		struct net_device *dev,
		struct thc_channel *async_chnl,
		xmit_type_t xmit_type)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	unsigned int request_cookie;
	cptr_t sync_end;
	struct sk_buff_container *skb_c;
	unsigned long skb_ord, skb_off;
	unsigned long skbd_ord, skbd_off;
	cptr_t skb_cptr, skbd_cptr;
	struct skbuff_members *skb_lcd;

	dev_container = container_of(dev,
		struct net_device_container,
		net_device);

	skb_c = kmem_cache_alloc(skb_c_cache, GFP_KERNEL);

	if (!skb_c) {
		LIBLCD_MSG("no memory");
		goto fail_alloc;
	}

	skb_c->skb = skb;
	glue_insert_skbuff(cptr_table, skb_c);

	/* save original head, data */
	skb_c->head = skb->head;
	skb_c->data = skb->data;
	skb_c->skb_ord = skb_ord;

	/* pad to 17 bytes, don't care the ret val */
	skb_put_padto(skb, 17);

	ret = fipc_test_blocking_send_start(async_chnl,	&_request);

	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(_request,
			NDO_START_XMIT);

	fipc_set_reg0(_request, xmit_type);

	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);

	fipc_set_reg2(_request,
			skb_c->my_ref.cptr);

	switch (xmit_type) {
	case VOLUNTEER_XMIT:
		ret = thc_ipc_send_request(async_chnl,
			_request, &request_cookie);

		if (ret) {
			LIBLCD_ERR("thc_ipc_call");
			goto fail_ipc;
		}

		//ret = grant_sync_ep(&sync_end, hidden_args->sync_ep);

		ret = sync_setup_memory(skb, sizeof(struct sk_buff),
				&skb_ord, &skb_cptr, &skb_off);

		ret = sync_setup_memory(skb->head,
			skb_end_offset(skb)
			+ sizeof(struct skb_shared_info),
			&skbd_ord, &skbd_cptr, &skbd_off);

		skb_c->skb_cptr = skb_cptr;
		skb_c->skbh_cptr = skbd_cptr;

		/* sync half */
		lcd_set_cr0(skb_cptr);
		lcd_set_cr1(skbd_cptr);
		lcd_set_r0(skb_ord);
		lcd_set_r1(skb_off);
		lcd_set_r2(skbd_ord);
		lcd_set_r3(skbd_off);
		lcd_set_r4(skb->data - skb->head);

		ret = lcd_sync_send(sync_end);
		lcd_set_cr0(CAP_CPTR_NULL);
		lcd_set_cr1(CAP_CPTR_NULL);
		if (ret) {
			LIBLCD_ERR("failed to send");
			goto fail_sync;
		}

		lcd_cap_delete(sync_end);

		break;

	case SHARED_DATA_XMIT:
		fipc_set_reg3(_request,
				(unsigned long)
				((void*)skb->head - pool->base));

		fipc_set_reg4(_request, skb->end);

		fipc_set_reg5(_request, skb->protocol);

		skb_lcd = SKB_LCD_MEMBERS(skb);

		C(len);
		C(data_len);
		C(queue_mapping);
		C(xmit_more);
		C(tail);
		C(truesize);
		C(ip_summed);
		C(csum_start);
		C(network_header);
		C(csum_offset);
		C(transport_header);

		skb_lcd->head_data_off = skb->data - skb->head;

		ret = thc_ipc_send_request(async_chnl,
			_request, &request_cookie);
		if (ret) {
			LIBLCD_ERR("thc_ipc_call");
			goto fail_ipc;
		}

		break;
	default:
		LIBLCD_ERR("%s, Unknown xmit_type requested",
			__func__);
		break;
	}

	LCD_MAIN({
	DO_FINISH_(__ndo_xmit, {
		ASYNC_({
		ret = thc_ipc_recv_response(async_chnl,
				request_cookie, &_response);
		}, __ndo_xmit);
	});
	});
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}

	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(async_chnl),
			_response);
fail_alloc:
fail_sync:
fail_async:
fail_ipc:
	return func_ret;
}

int ndo_start_xmit_nonlcd(struct sk_buff *skb,
		struct net_device *dev,
		struct thc_channel *async_chnl,
		xmit_type_t xmit_type)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret = 0;
	unsigned int request_cookie;
	cptr_t sync_end;
	struct sk_buff_container *skb_c;
	unsigned long skb_ord, skb_off;
	unsigned long skbd_ord, skbd_off;
	cptr_t skb_cptr, skbd_cptr;
	struct skbuff_members *skb_lcd;
#ifdef SENDER_DISPATCH_LOOP
	bool got_resp = false;
#endif
	u64 tcp_count = global_tx_count;
#ifdef TIMESTAMP
	TS_DECL(mndo_xmit);
#endif

#if defined(TIMESTAMP) || defined(LCD_MEASUREMENT)
	static int iter = 0;
#endif
#ifdef TIMESTAMP
	TS_START(mndo_xmit);
#endif

	dev_container = container_of(dev,
		struct net_device_container,
		net_device);

#ifdef SKBC_PRIVATE_POOL
	skb_c = priv_alloc(SKB_CONTAINER_POOL);
#else
	skb_c = kmem_cache_alloc(skb_c_cache, GFP_KERNEL);
#endif
	if (!skb_c) {
		LIBLCD_MSG("no memory");
		goto fail_alloc;
	}

	skb_c->skb = skb;

	glue_insert_skbuff(cptr_table, skb_c);

	/* save original head, data */
	skb_c->head = skb->head;
	skb_c->data = skb->data;
	skb_c->skb_ord = skb_ord;

	/* pad to 17 bytes, don't care the ret val */
	skb_put_padto(skb, 17);

	ret = fipc_test_blocking_send_start(async_chnl,	&_request);

	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(_request,
			NDO_START_XMIT);

	fipc_set_reg0(_request, xmit_type);

	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);

	fipc_set_reg2(_request,
			skb_c->my_ref.cptr);

	switch (xmit_type) {
	case VOLUNTEER_XMIT:
		ret = thc_ipc_send_request(async_chnl,
			_request, &request_cookie);

		if (ret) {
			LIBLCD_ERR("thc_ipc_call");
			goto fail_ipc;
		}

		//ret = grant_sync_ep(&sync_end, hidden_args->sync_ep);

		ret = sync_setup_memory(skb, sizeof(struct sk_buff),
				&skb_ord, &skb_cptr, &skb_off);

		ret = sync_setup_memory(skb->head,
			skb_end_offset(skb)
			+ sizeof(struct skb_shared_info),
			&skbd_ord, &skbd_cptr, &skbd_off);

		skb_c->skb_cptr = skb_cptr;
		skb_c->skbh_cptr = skbd_cptr;

		/* sync half */
		lcd_set_cr0(skb_cptr);
		lcd_set_cr1(skbd_cptr);
		lcd_set_r0(skb_ord);
		lcd_set_r1(skb_off);
		lcd_set_r2(skbd_ord);
		lcd_set_r3(skbd_off);
		lcd_set_r4(skb->data - skb->head);

		ret = lcd_sync_send(sync_end);
		lcd_set_cr0(CAP_CPTR_NULL);
		lcd_set_cr1(CAP_CPTR_NULL);
		if (ret) {
			LIBLCD_ERR("failed to send");
			goto fail_sync;
		}

		lcd_cap_delete(sync_end);

		break;

	case SHARED_DATA_XMIT:
		fipc_set_reg3(_request,
				(unsigned long)
				((void*)skb->head - pool->base));

		fipc_set_reg4(_request, skb->end);

		fipc_set_reg5(_request, skb->protocol);

		skb_lcd = SKB_LCD_MEMBERS(skb);

		C(len);
		C(data_len);
		C(queue_mapping);
		C(xmit_more);
		C(tail);
		C(truesize);
		C(ip_summed);
		C(csum_start);
		C(network_header);
		C(csum_offset);
		C(transport_header);

		skb_lcd->head_data_off = skb->data - skb->head;
		thc_set_msg_type(_request, msg_type_request);
		fipc_send_msg_end(thc_channel_to_fipc(async_chnl),
					_request);
		break;

	default:
		LIBLCD_ERR("%s, Unknown xmit_type requested",
			__func__);
		break;
	}

	if (skb->data[23] == 0x6) {
		printk("%s, ipc_send | pts %p | reqc 0x%x | seq %llu\n",
			__func__, current->ptstate, request_cookie, tcp_count);
	}
#ifdef SENDER_DISPATCH_LOOP
again:
	async_msg_blocking_recv_start(async_chnl, &_response);

	if (thc_get_msg_type(_response) == msg_type_request) {
		/* TODO: handle request */
		if (async_msg_get_fn_type(_response) == NAPI_CONSUME_SKB) {
			//printk("%s, calling napi_consume_skb\n", __func__);
			dispatch_async_loop(async_chnl, _response,
				c_cspace, sync_end);
		} else {
			printk("%s got unknown msg type! %d\n", __func__,
				async_msg_get_fn_type(_response));
		}
		if (!got_resp)
			goto again;
	} else if (thc_get_msg_type(_response) == msg_type_response) {
		got_resp = true;
		//printk("%s, got response \n", __func__);
		func_ret = fipc_get_reg1(_response);
#ifdef LCD_MEASUREMENT
		times_lcd[iter] = fipc_get_reg2(_response);
		iter = (iter + 1) % NUM_PACKETS;
#endif
		fipc_recv_msg_end(thc_channel_to_fipc(async_chnl),
			_response);
	}
#else /* SENDER_DISPATCH_LOOP */
	async_msg_blocking_recv_start(async_chnl, &_response);

	func_ret = fipc_get_reg1(_response);
#ifdef LCD_MEASUREMENT
	times_lcd[iter] = fipc_get_reg2(_response);
	iter = (iter + 1) % NUM_PACKETS;
#endif
	fipc_recv_msg_end(thc_channel_to_fipc(async_chnl),
		_response);

#endif /* SENDER_DISPATCH_LOOP */
	if (skb->data[23] == 0x6) {
		printk("%s, ipc_recv | pts %p | reqc 0x%x | seq %llu\n",
			__func__, current->ptstate, request_cookie, tcp_count);
	}

	//printk("%s, queue_mapping %d\n", __func__, skb->queue_mapping);
#ifdef TIMESTAMP
	TS_STOP(mndo_xmit);
	times_ndo_xmit[iter] = TS_DIFF(mndo_xmit);
	iter = (iter + 1) % NUM_PACKETS;
#endif
fail_alloc:
fail_sync:
fail_async:
fail_ipc:
	if (func_ret != NETDEV_TX_OK)
		printk("%s, got %d\n", __func__, func_ret);
	return func_ret;
}

extern struct thc_channel *klcd_chnl;

bool post_recv = false;

struct thc_channel *sirq_channels[64];

int prep_channel(struct trampoline_hidden_args *hidden_args, int queue)
{
	cptr_t tx, rx;
#ifdef SOFTIRQ_CHANNELS
	cptr_t tx_softirq, rx_softirq;
	struct thc_channel *chnl_softirq;
#endif
	cptr_t sync_end;
	cptr_t from_sync_end;
	struct thc_channel *chnl;
	struct thc_channel *async_chnl;
	struct fipc_message *_request;
	struct fipc_message *_response;
	unsigned int request_cookie;
	int ret;

	ret = lcd_cptr_alloc(&tx);
	if (ret) {
		LIBLCD_ERR("cptr alloc failed");
		goto fail_cptr;
	}
	ret = lcd_cptr_alloc(&rx);
	if (ret) {
		LIBLCD_ERR("cptr alloc failed");
		goto fail_cptr;
	}

#ifdef SOFTIRQ_CHANNELS
	ret = lcd_cptr_alloc(&tx_softirq);
	if (ret) {
		LIBLCD_ERR("cptr alloc failed");
		goto fail_cptr;
	}
	ret = lcd_cptr_alloc(&rx_softirq);
	if (ret) {
		LIBLCD_ERR("cptr alloc failed");
		goto fail_cptr;
	}
#endif
	if (queue) {
		from_sync_end = lcds[queue].lcd_sync_end;
		async_chnl = lcds[queue].lcd_async_chnl;
	} else {
		from_sync_end = hidden_args->sync_ep;
		async_chnl = hidden_args->async_chnl;
	}

	/* grant sync_ep */
	if ((ret = grant_sync_ep(&sync_end, from_sync_end))) {
		LIBLCD_ERR("%s, grant_syncep failed %d\n",
				__func__, ret);
		goto fail_ep;
	}

	ret = fipc_test_blocking_send_start(async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(_request,
			PREP_CHANNEL);

	/* No need to wait for a response here */
	ret = thc_ipc_send_request(async_chnl,
			_request,
			&request_cookie);
	if (ret) {
		LIBLCD_ERR("thc_ipc send");
		goto fail_ipc;
	}

	lcd_set_cr0(rx);
	lcd_set_cr1(tx);

#ifdef SOFTIRQ_CHANNELS
	lcd_set_cr2(rx_softirq);
	lcd_set_cr3(tx_softirq);
#endif
	printk("[%d]%s[pid=%d] Creating a private channel pair\n",
			smp_processor_id(), current->comm, current->pid);

	ret = lcd_sync_recv(sync_end);
	if (ret) {
		if (ret == -EWOULDBLOCK)
			ret = 0;
		goto fail_ep;
	}
	
	printk("[%d]%s[pid=%d] Received capabilities via sync_recv\n",
			smp_processor_id(), current->comm, current->pid);
	/*
	 * Set up async ring channel
	 */
	ret = setup_async_net_ring_channel(tx, rx, &chnl);
	if (ret) {
		LIBLCD_ERR("error setting up ring channel");
		goto fail_ep;
	}

#ifdef SOFTIRQ_CHANNELS
	printk("[%d]%s[pid=%d] Creating a pair for softirq\n", smp_processor_id(), current->comm, current->pid);
	/*
	 * Set up async ring channel for softirq
	 */
	ret = setup_async_net_ring_channel(tx_softirq, rx_softirq,
				&chnl_softirq);
	if (ret) {
		LIBLCD_ERR("error setting up ring channel");
		goto fail_ep2;
	}
#endif
	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);

#ifdef SOFTIRQ_CHANNELS
	lcd_set_cr2(CAP_CPTR_NULL);
	lcd_set_cr3(CAP_CPTR_NULL);
	sirq_channels[smp_processor_id()] = chnl_softirq;
fail_ep2:
#else
	current->ptstate->thc_chnl = chnl;
	sirq_channels[smp_processor_id()] = chnl;
#endif
	/* technically, we do not need to receive the response */
	ret = thc_ipc_recv_response(
			async_chnl,
			request_cookie,
			&_response);

	printk("%s, ipc recv resp %d | pts %p | reqc 0x%x\n",
				__func__, ret, current->ptstate,
				request_cookie);

	if (ret) {
		LIBLCD_ERR("thc_ipc_recv_response");
		goto fail_ipc;
	}

	fipc_recv_msg_end(thc_channel_to_fipc(
			async_chnl),_response);

	return 0;
fail_async:
fail_ep:
	lcd_cptr_free(rx);
	lcd_cptr_free(tx);
fail_ipc:
fail_cptr:
	return -1;
}

#if 1
DEFINE_SPINLOCK(prep_lock);

int ndo_start_xmit(struct sk_buff *skb,
		struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret = 0;
	struct fipc_message *_request;
	struct fipc_message *_response;
	unsigned int request_cookie;
	int func_ret = 0;
	struct sk_buff_container *skb_c;
	unsigned long skb_ord = 0, skb_off;
	unsigned long skbd_ord, skbd_off;
	cptr_t skb_cptr, skbd_cptr;
	xmit_type_t xmit_type;
	struct skbuff_members *skb_lcd;
	cptr_t sync_end;
	struct thc_channel *async_chnl = NULL;
	u64 tcp_count = 0;
	xmit_type = check_skb_range(skb);

	/* do not entertain packets from swapper */
	if (!strncmp(current->comm, "swapper", strlen("swapper"))
		|| !strncmp(current->comm, "kworker/", strlen("kworker/")))
		return NETDEV_TX_OK;

	if (!strncmp(current->comm, "lcd", strlen("lcd"))) {
		printk("%s Packet send likely from softirq context via %s! disallow\n",
				__func__, current->comm);
		return NETDEV_TX_OK;
	}

	if (unlikely(!current->ptstate)) {
		printk("%s: Calling lcd_enter for pid:%d, comm %s\n", __func__,
				current->pid, current->comm);

		/* step 1. create lcd env */
		lcd_enter();

		ptrs[smp_processor_id()] = current->ptstate;

		/* set nonlcd ctx for future use */
		current->ptstate->nonlcd_ctx = true;

		/*
		 * if it is ksoftirqd, let it use the channel that exist 
		 */
		if (!strncmp(current->comm, "ksoftirqd/",
					strlen("ksoftirqd/"))) {
			//current->ptstate->thc_chnl = xmit_irq_chnl;
			//printk("softirq\n");
		/* step 2. grant sync_ep if needed */
		/* FIXME: always grant sync_ep? */
		//if (grant_sync_ep(&sync_end, hidden_args->sync_ep))
		//	printk("%s, grant_syncep failed %d\n",
		//			__func__, ret);
			if (!sirq_channels[smp_processor_id()]) {
				printk("%s: sirqch empty for %d\n",
					__func__, smp_processor_id());
				current->ptstate->thc_chnl = xmit_irq_chnl;
			}

			current->ptstate->thc_chnl =
				sirq_channels[smp_processor_id()];

			printk("[%d]%s[pid=%d] pts %p softirq channel %p\n",
				smp_processor_id(), current->comm,
				current->pid, current->ptstate,
				sirq_channels[smp_processor_id()]);

		} else if(!strncmp(current->comm, "iperf",
					strlen("iperf")) ||
			!strncmp(current->comm, "lt-iperf3",
					strlen("lt-iperf3")) ||
			!strncmp(current->comm, "memcached", strlen("memcached"))) {
		
			printk("[%d]%s[pid=%d] calling prep_channel\n",
				smp_processor_id(), current->comm,
				current->pid);
			spin_lock(&prep_lock);
			prep_channel(hidden_args, skb->queue_mapping);
			spin_unlock(&prep_lock);
			printk("===================================\n");
			printk("===== Private Channel created on cpu %d for (pid %d)[%s] =====\n",
						smp_processor_id(), current->pid, current->comm);
			printk("===================================\n");

/*			if (!entry)
				current->ptstate->thc_chnl = xmit_chnl;
			else
				current->ptstate->thc_chnl = xmit_chnl2;
			++entry;
*/
		} else {
			printk("===== app %s , giving xmit_chnl\n",
					current->comm);
			current->ptstate->thc_chnl = xmit_irq_chnl;
			current->ptstate->dofin = true;
		/* step 2. grant sync_ep if needed */
		/* FIXME: always grant sync_ep? */
		if (grant_sync_ep(&sync_end, hidden_args->sync_ep))
			printk("%s, grant_syncep failed %d\n",
					__func__, ret);

		}

	} else if (current->ptstate->nonlcd_ctx && current->ptstate->syncep_present) {
		sync_end.cptr = current->ptstate->sync_ep;
	}

	if (xmit_type == VOLUNTEER_XMIT) {
		printk("%s, comm %s | pid %d | skblen %d "
			"| skb->proto %02X\n", __func__,
			current->comm, current->pid, skb->len,
			ntohs(skb->protocol));
		if (!strcmp("netperf", current->comm))
			dump_stack();
		return NETDEV_TX_OK;
	}


	/* if TCP */
	/* 38-41 - Seq no
	 * 42-45 - Ack no
	 */
	if (skb->data[23] == 0x6) {
		unsigned int seq = (skb->data[38] << 24) | (skb->data[39] << 16) | (skb->data[40] << 8) | skb->data[41];
		unsigned int ack = (skb->data[42] << 24) | (skb->data[43] << 16) | (skb->data[44] << 8) | skb->data[45];

		unsigned char flags = (skb->data[46] & 0x0F) | skb->data[47];
		printk("%s, xmit via cpu=%d:%10s[%d] | pts %p | proto %x | IP proto %x | TCP.seq %u | TCP.ack %u | TCP Flags [%s%s%s%s%s]\n",
				__func__, smp_processor_id(), current->comm, current->pid,
				current->ptstate, htons(skb->protocol), skb->data[23], seq, ack,
				(flags & 0x1) ? " FIN " : "",
				(flags & 0x2) ? " SYN " : "",
				(flags & 0x4) ? " RST " : "",
				(flags & 0x8) ? " PSH " : "",
				(flags & 0x10) ? " ACK " : "");

		tcp_count = global_tx_count;
	}


	global_tx_count++;
	//printk("%s, nr_frags %d\n", __func__, skb_shinfo(skb)->nr_frags);
	if (current->ptstate->nonlcd_ctx) {
		async_chnl = (struct thc_channel*) current->ptstate->thc_chnl;
		if (!async_chnl) {
			printk("[%d]%s[pid=%d] pts %p, pts->chnl %p,"
				"softirq channel %p\n",
				smp_processor_id(), current->comm,
				current->pid, current->ptstate,
				current->ptstate->thc_chnl,
				sirq_channels[smp_processor_id()]);
			goto quit;
		}
		if (unlikely(current->ptstate->dofin))
			func_ret = ndo_start_xmit_dofin(skb, dev,
					async_chnl, xmit_type);
		else
			func_ret = ndo_start_xmit_nonlcd(skb, dev,
				async_chnl, xmit_type);
quit:
		return func_ret;
	} else {
		async_chnl = klcd_chnl;
	}

	g_stats.tx_packets++;
	g_stats.tx_bytes += skb->len;

	dev_container = container_of(dev,
		struct net_device_container,
		net_device);

	skb_c = kmem_cache_alloc(skb_c_cache, GFP_KERNEL);

	if (!skb_c) {
		LIBLCD_MSG("no memory");
		goto fail_alloc;
	}

	skb_c->skb = skb;
	skb_c->tsk = current;
	glue_insert_skbuff(cptr_table, skb_c);

	/* save original head, data */
	skb_c->head = skb->head;
	skb_c->data = skb->data;
	skb_c->skb_ord = skb_ord;

	/* pad to 17 bytes, don't care the ret val */
	skb_put_padto(skb, 17);

	ret = fipc_test_blocking_send_start(async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_START_XMIT);

	fipc_set_reg0(_request, xmit_type);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	fipc_set_reg2(_request,
			skb_c->my_ref.cptr);

	switch (xmit_type) {
	case VOLUNTEER_XMIT:
		ret = thc_ipc_send_request(async_chnl,
				_request, &request_cookie);

		if (ret) {
			LIBLCD_ERR("thc_ipc_call");
			goto fail_ipc;
		}

		ret = sync_setup_memory(skb, sizeof(struct sk_buff),
				&skb_ord, &skb_cptr, &skb_off);

		ret = sync_setup_memory(skb->head,
			skb_end_offset(skb)
			+ sizeof(struct skb_shared_info),
				&skbd_ord, &skbd_cptr, &skbd_off);

		skb_c->skb_cptr = skb_cptr;
		skb_c->skbh_cptr = skbd_cptr;

		/* sync half */
		lcd_set_cr0(skb_cptr);
		lcd_set_cr1(skbd_cptr);
		lcd_set_r0(skb_ord);
		lcd_set_r1(skb_off);
		lcd_set_r2(skbd_ord);
		lcd_set_r3(skbd_off);
		lcd_set_r4(skb->data - skb->head);

		/* handle nonlcd case with a granted sync ep */
		if (current->ptstate->nonlcd_ctx)
			ret = lcd_sync_send(sync_end);
		else
			ret = lcd_sync_send(hidden_args->sync_ep);

		lcd_set_cr0(CAP_CPTR_NULL);
		lcd_set_cr1(CAP_CPTR_NULL);

		if (ret) {
			LIBLCD_ERR("failed to send");
			goto fail_sync;
		}

		break;

	case SHARED_DATA_XMIT:
		fipc_set_reg3(_request,
				(unsigned long)
				((void*)skb->head - pool->base));

		fipc_set_reg4(_request, skb->end);
		fipc_set_reg5(_request, skb->protocol);

		skb_lcd = SKB_LCD_MEMBERS(skb);

		C(len);
		C(data_len);
		C(queue_mapping);
		C(xmit_more);
		C(tail);
		C(truesize);
		C(ip_summed);
		C(csum_start);
		C(network_header);
		C(csum_offset);
		C(transport_header);

		skb_lcd->head_data_off = skb->data - skb->head;

		ret = thc_ipc_send_request(async_chnl,
			_request, &request_cookie);

		if (skb->data[23] == 0x6)
		printk("%s, ipc_send | pts %p | reqc 0x%x | seq %llu\n",
				__func__, current->ptstate, request_cookie, tcp_count);

		if (ret) {
			LIBLCD_ERR("thc_ipc_call");
			goto fail_ipc;
		}

		break;
	default:
		LIBLCD_ERR("%s, Unknown xmit_type requested",
			__func__);
		break;
	}

	ret = thc_ipc_recv_response(
			async_chnl,
			request_cookie,
			&_response);

	//printk("%s, queue_mapping %d\n", __func__, skb->queue_mapping);

	if (skb->data[23] == 0x6)
	printk("%s, ipc_recv | pts %p | reqc 0x%x | seq %llu\n",
			__func__, current->ptstate, request_cookie, tcp_count);
	
	//printk("%s, xmit via KLCD | pts %p | cookie %d | proto %x | IP proto %x | TCP flags %x\n",
	//			__func__, current->ptstate, request_cookie, htons(skb->protocol),
	//			skb->data[23], (skb->data[46] & 0x0F) | skb->data[47]);

	if (ret) {
		LIBLCD_ERR("thc_ipc_recv_response");
		goto fail_ipc;
	}

	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(
			async_chnl),_response);

	return func_ret;
fail_alloc:
fail_async:
fail_sync:
fail_ipc:
	return ret;
}
#endif

LCD_TRAMPOLINE_DATA(ndo_start_xmit_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(ndo_start_xmit_trampoline)
ndo_start_xmit_trampoline(struct sk_buff *skb,
		struct net_device *dev)
{
	int ( *volatile ndo_start_xmit_fp )(struct sk_buff *,
		struct net_device *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_start_xmit_trampoline);
	ndo_start_xmit_fp = ndo_start_xmit;
	return ndo_start_xmit_fp(skb,
		dev,
		hidden_args);

}

void ndo_set_rx_mode_user(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_SET_RX_MODE);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	DO_FINISH({
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, ndo_set_rx_mode
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return;
fail_async:
fail_ipc:
	return;

}

void ndo_set_rx_mode(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ndo_set_rx_mode_user(dev,
					hidden_args);
		}
		);
		return;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_SET_RX_MODE);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return;
fail_async:
fail_ipc:
	return;

}

LCD_TRAMPOLINE_DATA(ndo_set_rx_mode_trampoline);
void  LCD_TRAMPOLINE_LINKAGE(ndo_set_rx_mode_trampoline)
ndo_set_rx_mode_trampoline(struct net_device *dev)
{
	void ( *volatile ndo_set_rx_mode_fp )(struct net_device *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_set_rx_mode_trampoline);
	ndo_set_rx_mode_fp = ndo_set_rx_mode;
	return ndo_set_rx_mode_fp(dev,
		hidden_args);

}

int ndo_validate_addr_user(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_VALIDATE_ADDR);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	DO_FINISH({
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, ndo_validate_addr
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	return ret;
}

int ndo_validate_addr(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ret = ndo_validate_addr_user(dev,
		hidden_args);
		}
		);
		return ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_VALIDATE_ADDR);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

LCD_TRAMPOLINE_DATA(ndo_validate_addr_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(ndo_validate_addr_trampoline)
ndo_validate_addr_trampoline(struct net_device *dev)
{
	int ( *volatile ndo_validate_addr_fp )(struct net_device *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_validate_addr_trampoline);
	ndo_validate_addr_fp = ndo_validate_addr;
	return ndo_validate_addr_fp(dev,
		hidden_args);

}

int ndo_set_mac_address_user(struct net_device *dev,
		void *addr,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int sync_ret;
	unsigned 	long addr_mem_sz;
	unsigned 	long addr_offset;
	cptr_t addr_cptr;
	unsigned 	int request_cookie;
	int func_ret;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_SET_MAC_ADDRESS);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	sync_ret = lcd_virt_to_cptr(__gva(( unsigned  long   )addr),
		&addr_cptr,
		&addr_mem_sz,
		&addr_offset);
	if (sync_ret) {
		LIBLCD_ERR("virt to cptr failed");
		lcd_exit(-1);
	}
	ret = thc_ipc_send_request(hidden_args->async_chnl,
		_request,
		&request_cookie);

	if (ret) {
		LIBLCD_ERR("thc_ipc_send_request");
		goto fail_ipc;
	}
	lcd_set_r0(ilog2(( addr_mem_sz ) >> ( PAGE_SHIFT )));
	lcd_set_r1(addr_offset);
	lcd_set_cr0(addr_cptr);
	sync_ret = lcd_sync_send(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to send");
		lcd_exit(-1);
	}
	DO_FINISH({
		ASYNC_({
		ret = thc_ipc_recv_response(hidden_args->async_chnl,
		request_cookie,
		&_response);
		}, ndo_set_mac_addr
		);
	});
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

int ndo_set_mac_address(struct net_device *dev,
		void *addr,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int sync_ret;
	unsigned 	long addr_mem_sz;
	unsigned 	long addr_offset;
	cptr_t addr_cptr;
	unsigned 	int request_cookie;
	int func_ret;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ret = ndo_set_mac_address_user(dev,
		addr,
		hidden_args);
		}
		);
		return ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_SET_MAC_ADDRESS);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	sync_ret = lcd_virt_to_cptr(__gva(( unsigned  long   )addr),
		&addr_cptr,
		&addr_mem_sz,
		&addr_offset);
	if (sync_ret) {
		LIBLCD_ERR("virt to cptr failed");
		lcd_exit(-1);
	}
	ret = thc_ipc_send_request(hidden_args->async_chnl,
		_request,
		&request_cookie);
	if (ret) {
		LIBLCD_ERR("thc_ipc_send_request");
		goto fail_ipc;
	}
	lcd_set_r0(ilog2(( addr_mem_sz ) >> ( PAGE_SHIFT )));
	lcd_set_r1(addr_offset);
	lcd_set_cr0(addr_cptr);
	sync_ret = lcd_sync_send(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to send");
		lcd_exit(-1);
	}
	ret = thc_ipc_recv_response(hidden_args->async_chnl,
		request_cookie,
		&_response);
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

LCD_TRAMPOLINE_DATA(ndo_set_mac_address_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(ndo_set_mac_address_trampoline)
ndo_set_mac_address_trampoline(struct net_device *dev,
		void *addr)
{
	int ( *volatile ndo_set_mac_address_fp )(struct net_device *,
		void *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_set_mac_address_trampoline);
	ndo_set_mac_address_fp = ndo_set_mac_address;
	return ndo_set_mac_address_fp(dev,
		addr,
		hidden_args);

}

int ndo_change_mtu_user(struct net_device *dev,
		int new_mtu,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_CHANGE_MTU);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	fipc_set_reg3(_request,
			new_mtu);
	DO_FINISH({
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, ndo_change_mtu
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

int ndo_change_mtu(struct net_device *dev,
		int new_mtu,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ret = ndo_change_mtu_user(dev,
		new_mtu,
		hidden_args);
		}
		);
		return ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_CHANGE_MTU);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	fipc_set_reg3(_request,
			new_mtu);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

LCD_TRAMPOLINE_DATA(ndo_change_mtu_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(ndo_change_mtu_trampoline)
ndo_change_mtu_trampoline(struct net_device *dev,
		int new_mtu)
{
	int ( *volatile ndo_change_mtu_fp )(struct net_device *,
		int ,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_change_mtu_trampoline);
	ndo_change_mtu_fp = ndo_change_mtu;
	return ndo_change_mtu_fp(dev,
		new_mtu,
		hidden_args);

}

void ndo_tx_timeout_user(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_TX_TIMEOUT);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	DO_FINISH({
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, ndo_tx_timeout
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);

fail_async:
fail_ipc:
	return;

}

void ndo_tx_timeout(struct net_device *dev,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ndo_tx_timeout_user(dev,
		hidden_args);
		}
		);
		return;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_TX_TIMEOUT);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
fail_async:
fail_ipc:
	return;

}

LCD_TRAMPOLINE_DATA(ndo_tx_timeout_trampoline);
void LCD_TRAMPOLINE_LINKAGE(ndo_tx_timeout_trampoline)
ndo_tx_timeout_trampoline(struct net_device *dev)
{
	void ( *volatile ndo_tx_timeout_fp )(struct net_device *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_tx_timeout_trampoline);
	ndo_tx_timeout_fp = ndo_tx_timeout;
	ndo_tx_timeout_fp(dev,
		hidden_args);
	return;
}

int ndo_set_tx_maxrate_user(struct net_device *dev,
		int queue_index,
		unsigned int maxrate,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_SET_TX_MAXRATE);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	fipc_set_reg3(_request,
			queue_index);
	fipc_set_reg4(_request,
			maxrate);
	DO_FINISH({
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, ndo_set_tx_maxrate
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

int ndo_set_tx_maxrate(struct net_device *dev,
		int queue_index,
		unsigned int maxrate,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ret = ndo_set_tx_maxrate_user(dev,
		queue_index,
		maxrate,
		hidden_args);
		}
		);
		return ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_SET_TX_MAXRATE);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	fipc_set_reg3(_request,
			queue_index);
	fipc_set_reg4(_request,
			maxrate);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;

}

LCD_TRAMPOLINE_DATA(ndo_set_tx_maxrate_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(ndo_set_tx_maxrate_trampoline)
ndo_set_tx_maxrate_trampoline(struct net_device *dev,
		int queue_index,
		unsigned int maxrate)
{
	int ( *volatile ndo_set_tx_maxrate_fp )(struct net_device *,
		int ,
		unsigned int ,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_set_tx_maxrate_trampoline);
	ndo_set_tx_maxrate_fp = ndo_set_tx_maxrate;
	return ndo_set_tx_maxrate_fp(dev,
		queue_index,
		maxrate,
		hidden_args);

}

struct rtnl_link_stats64 *ndo_get_stats64_user(struct net_device *dev,
		struct rtnl_link_stats64 *stats,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_GET_STATS64);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	DO_FINISH({
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, ndo_get_stats
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	stats->rx_packets += fipc_get_reg1(_response);
	stats->rx_bytes += fipc_get_reg2(_response);
	stats->tx_packets += fipc_get_reg3(_response);
	stats->tx_bytes += fipc_get_reg4(_response);

	fipc_recv_msg_end(thc_channel_to_fipc(
			hidden_args->async_chnl),
			_response);
fail_async:
fail_ipc:
	lcd_exit(0);
	return stats;
}

struct rtnl_link_stats64 *ndo_get_stats64(struct net_device *dev,
		struct rtnl_link_stats64 *stats,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	struct rtnl_link_stats64 *func_ret = stats;

#ifdef TIMESTAMP
	if (times_ndo_xmit)
		fipc_test_stat_print_info(times_ndo_xmit,
						NUM_PACKETS);
#endif
#ifdef STATS
	printk("---------- counter  ---------------\n");
	printk("%s, global tx = %llu | global free = %llu\n",
			__func__, global_tx_count, global_free_count);
	printk("-----------------------------------\n");
#endif
#ifdef LCD_MEASUREMENT
	printk("---------- LCD ---------------\n");
	if (times_lcd)
		fipc_test_stat_print_info(times_lcd,
						NUM_PACKETS);
#endif
#ifdef FREE_TIMESTAMP
	if (times_free)
		fipc_test_stat_print_info(times_free,
						NUM_PACKETS);
#endif

	if (!current->ptstate) {
		func_ret = &g_stats;
		return func_ret;
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			func_ret = ndo_get_stats64_user(dev,
		stats,
		hidden_args);
		}
		);
		return func_ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			NDO_GET_STATS64);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);

	LIBLCD_MSG("netdev lcd_ref %lu", dev_container->other_ref.cptr);

	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	stats->rx_packets = fipc_get_reg1(_response);
	stats->rx_bytes = fipc_get_reg2(_response);
	stats->tx_packets = fipc_get_reg3(_response);
	stats->tx_bytes = fipc_get_reg4(_response);

	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return func_ret;
}

LCD_TRAMPOLINE_DATA(ndo_get_stats64_trampoline);
struct rtnl_link_stats64  LCD_TRAMPOLINE_LINKAGE(ndo_get_stats64_trampoline)
*ndo_get_stats64_trampoline(struct net_device *dev,
		struct rtnl_link_stats64 *stats)
{
	struct rtnl_link_stats64* ( *volatile ndo_get_stats64_fp )(struct net_device *,
		struct rtnl_link_stats64 *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			ndo_get_stats64_trampoline);
	ndo_get_stats64_fp = ndo_get_stats64;
	return ndo_get_stats64_fp(dev,
		stats,
		hidden_args);

}


void setup_netdev_ops(struct net_device_container *dev_c,
	struct net_device_ops_container *netdev_ops_container, struct thc_channel *_channel,
	struct cptr sync_ep)
{
	struct trampoline_hidden_args *dev_netdev_ops_ndo_open_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_stop_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_start_xmit_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_set_rx_mode_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_validate_addr_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_set_mac_address_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_change_mtu_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_tx_timeout_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_set_tx_maxrate_hidden_args;
	struct trampoline_hidden_args *dev_netdev_ops_ndo_get_stats64_hidden_args;
	int ret;

	dev_netdev_ops_ndo_open_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_open_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc1;
	}
	dev_netdev_ops_ndo_open_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_open_trampoline);
	if (!dev_netdev_ops_ndo_open_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup1;
	}
	dev_netdev_ops_ndo_open_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_open_hidden_args;
	dev_netdev_ops_ndo_open_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_open_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_open_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_open_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_open = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_open_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_open_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_open_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	dev_netdev_ops_ndo_stop_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_stop_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc2;
	}
	dev_netdev_ops_ndo_stop_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_stop_trampoline);
	if (!dev_netdev_ops_ndo_stop_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup2;
	}
	dev_netdev_ops_ndo_stop_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_stop_hidden_args;
	dev_netdev_ops_ndo_stop_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_stop_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_stop_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_stop_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_stop = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_stop_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_stop_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_stop_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	dev_netdev_ops_ndo_start_xmit_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_start_xmit_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc3;
	}
	dev_netdev_ops_ndo_start_xmit_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_start_xmit_trampoline);
	if (!dev_netdev_ops_ndo_start_xmit_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup3;
	}
	dev_netdev_ops_ndo_start_xmit_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_start_xmit_hidden_args;
	dev_netdev_ops_ndo_start_xmit_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_start_xmit_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_start_xmit_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_start_xmit_hidden_args->async_chnl = xmit_chnl;
	netdev_ops_container->net_device_ops.ndo_start_xmit = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_start_xmit_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_start_xmit_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_start_xmit_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));

	dev_netdev_ops_ndo_set_rx_mode_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_set_rx_mode_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc5;
	}
	dev_netdev_ops_ndo_set_rx_mode_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_set_rx_mode_trampoline);
	if (!dev_netdev_ops_ndo_set_rx_mode_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup5;
	}
	dev_netdev_ops_ndo_set_rx_mode_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_set_rx_mode_hidden_args;
	dev_netdev_ops_ndo_set_rx_mode_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_set_rx_mode_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_set_rx_mode_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_set_rx_mode_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_set_rx_mode = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_set_rx_mode_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_set_rx_mode_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_set_rx_mode_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	dev_netdev_ops_ndo_validate_addr_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_validate_addr_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc6;
	}
	dev_netdev_ops_ndo_validate_addr_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_validate_addr_trampoline);
	if (!dev_netdev_ops_ndo_validate_addr_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup6;
	}
	dev_netdev_ops_ndo_validate_addr_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_validate_addr_hidden_args;
	dev_netdev_ops_ndo_validate_addr_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_validate_addr_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_validate_addr_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_validate_addr_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_validate_addr = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_validate_addr_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_validate_addr_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_validate_addr_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	dev_netdev_ops_ndo_set_mac_address_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_set_mac_address_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc7;
	}
	dev_netdev_ops_ndo_set_mac_address_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_set_mac_address_trampoline);
	if (!dev_netdev_ops_ndo_set_mac_address_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup7;
	}
	dev_netdev_ops_ndo_set_mac_address_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_set_mac_address_hidden_args;
	dev_netdev_ops_ndo_set_mac_address_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_set_mac_address_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_set_mac_address_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_set_mac_address_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_set_mac_address = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_set_mac_address_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_set_mac_address_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_set_mac_address_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	dev_netdev_ops_ndo_change_mtu_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_change_mtu_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc8;
	}
	dev_netdev_ops_ndo_change_mtu_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_change_mtu_trampoline);
	if (!dev_netdev_ops_ndo_change_mtu_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup8;
	}
	dev_netdev_ops_ndo_change_mtu_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_change_mtu_hidden_args;
	dev_netdev_ops_ndo_change_mtu_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_change_mtu_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_change_mtu_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_change_mtu_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_change_mtu = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_change_mtu_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_change_mtu_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_change_mtu_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	dev_netdev_ops_ndo_tx_timeout_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_tx_timeout_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc9;
	}
	dev_netdev_ops_ndo_tx_timeout_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_tx_timeout_trampoline);
	if (!dev_netdev_ops_ndo_tx_timeout_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup9;
	}
	dev_netdev_ops_ndo_tx_timeout_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_tx_timeout_hidden_args;
	dev_netdev_ops_ndo_tx_timeout_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_tx_timeout_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_tx_timeout_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_tx_timeout_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_tx_timeout = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_tx_timeout_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_tx_timeout_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_tx_timeout_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	dev_netdev_ops_ndo_set_tx_maxrate_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_set_tx_maxrate_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc10;
	}
	dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_set_tx_maxrate_trampoline);
	if (!dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup10;
	}
	dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_set_tx_maxrate_hidden_args;
	dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_set_tx_maxrate = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_set_tx_maxrate_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_set_tx_maxrate_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	dev_netdev_ops_ndo_get_stats64_hidden_args = kzalloc(sizeof( struct trampoline_hidden_args ),
		GFP_KERNEL);
	if (!dev_netdev_ops_ndo_get_stats64_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc11;
	}
	dev_netdev_ops_ndo_get_stats64_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(ndo_get_stats64_trampoline);
	if (!dev_netdev_ops_ndo_get_stats64_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup11;
	}
	dev_netdev_ops_ndo_get_stats64_hidden_args->t_handle->hidden_args = dev_netdev_ops_ndo_get_stats64_hidden_args;
	dev_netdev_ops_ndo_get_stats64_hidden_args->struct_container = netdev_ops_container;
	dev_netdev_ops_ndo_get_stats64_hidden_args->cspace = c_cspace;
	dev_netdev_ops_ndo_get_stats64_hidden_args->sync_ep = sync_ep;
	dev_netdev_ops_ndo_get_stats64_hidden_args->async_chnl = _channel;
	netdev_ops_container->net_device_ops.ndo_get_stats64 = LCD_HANDLE_TO_TRAMPOLINE(dev_netdev_ops_ndo_get_stats64_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )dev_netdev_ops_ndo_get_stats64_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(ndo_get_stats64_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
fail_alloc1:
fail_dup1:
fail_alloc2:
fail_dup2:
fail_alloc3:
fail_dup3:
fail_alloc5:
fail_dup5:
fail_alloc6:
fail_dup6:
fail_alloc7:
fail_dup7:
fail_alloc8:
fail_dup8:
fail_alloc9:
fail_dup9:
fail_alloc10:
fail_dup10:
fail_alloc11:
fail_dup11:
	return;
}

int register_netdev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	struct net_device_ops_container *netdev_ops_container;
	struct net_device *dev;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	//node-0 90:e2:ba:b3:75:a1
	u8 mac_addr[] = {0x90, 0xe2, 0xba, 0xb3, 0x75, 0xa1};

	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg0(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	netdev_ops_container = kzalloc(sizeof( struct net_device_ops_container   ),
		GFP_KERNEL);
	if (!netdev_ops_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	ret = glue_cap_insert_net_device_ops_type(c_cspace,
		netdev_ops_container,
		&netdev_ops_container->my_ref);
	if (ret) {
		LIBLCD_ERR("lcd insert");
		goto fail_insert;
	}
	dev_container->net_device.netdev_ops = &netdev_ops_container->net_device_ops;
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = &dev_container->net_device;
	dev->flags = fipc_get_reg1(_request);
	dev->priv_flags = fipc_get_reg2(_request);
	dev->features = fipc_get_reg3(_request);
	dev->hw_features = fipc_get_reg4(_request);
	dev->hw_enc_features = fipc_get_reg5(_request);
	dev->mpls_features = fipc_get_reg6(_request);

	memcpy(dev->dev_addr, mac_addr, ETH_ALEN);
	/* setup netdev_ops */
	setup_netdev_ops(dev_container, netdev_ops_container, _channel, sync_ep);

	func_ret = register_netdev(( &dev_container->net_device ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	fipc_set_reg2(_response,
			dev->reg_state);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);

fail_lookup:
fail_insert:
fail_alloc:
	return ret;
}

int ether_setup_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	ether_setup(( &dev_container->net_device ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;

}

int eth_mac_addr_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long p_offset;
	cptr_t p_cptr;
	gva_t p_gva;

	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	sync_ret = lcd_cptr_alloc(&p_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		lcd_exit(-1);
	}
	lcd_set_cr0(p_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		lcd_exit(-1);
	}
	mem_order = lcd_r0();
	p_offset = lcd_r1();
	sync_ret = lcd_map_virt(p_cptr,
		mem_order,
		&p_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *p");
		lcd_exit(-1);
	}
	func_ret = eth_mac_addr(( &dev_container->net_device ),
		( void  * )( ( gva_val(p_gva) ) + ( p_offset ) ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;

}

int eth_validate_addr_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	func_ret = eth_validate_addr(( &dev_container->net_device ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;

}

int free_netdev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	free_netdev(( &dev_container->net_device ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;

}

int netif_carrier_off_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	netif_carrier_off(( &dev_container->net_device ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response, dev_container->net_device.state);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;

}

int netif_carrier_on_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	netif_carrier_on(( &dev_container->net_device ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response, dev_container->net_device.state);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;

}

int netif_device_attach_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	netif_device_attach(( &dev_container->net_device ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response, dev_container->net_device.state);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
	return ret;
}

int netif_device_detach_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	netif_device_detach(( &dev_container->net_device ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response, dev_container->net_device.state);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
	return ret;
}

int netif_set_real_num_rx_queues_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	unsigned 	int rxq;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	rxq = fipc_get_reg3(_request);
	func_ret = netif_set_real_num_rx_queues(( &dev_container->net_device ),
		rxq);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
	return ret;

}

int netif_set_real_num_tx_queues_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	unsigned 	int txq;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	txq = fipc_get_reg3(_request);

	LIBLCD_MSG("%s, txq %d | num_tx_queues %d", __func__, txq, dev_container->net_device.num_tx_queues);

	func_ret = netif_set_real_num_tx_queues(( &dev_container->net_device ),
		txq);
	LIBLCD_MSG("netif_set_real_num_tx_queues returns %d", func_ret);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
	return ret;

}

int napi_consume_skb_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct sk_buff *skb;
	struct sk_buff_container *skb_c;
	int ret = 0;
#ifndef NAPI_CONSUME_SEND_ONLY
	struct fipc_message *_response;
#endif
	unsigned 	int request_cookie;
	cptr_t skb_cptr, skbh_cptr;
	int budget;
	bool revoke = false;

#ifdef FREE_TIMESTAMP
	static int iter = 0;
	TS_DECL(free);

#endif
	request_cookie = thc_get_request_cookie(_request);

	budget = fipc_get_reg1(_request);

	glue_lookup_skbuff(cptr_table,
		__cptr(fipc_get_reg0(_request)),
		&skb_c);
	skb = skb_c->skb;

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	if (!skb->private) {
		/* restore */
		skb->head = skb_c->head;
		skb->data = skb_c->data;

		skb_cptr = skb_c->skb_cptr;
		skbh_cptr = skb_c->skbh_cptr;
		revoke = true;
	}

#ifdef FREE_TIMESTAMP
	TS_START(free);
#endif

	if (check_skb_range(skb) == VOLUNTEER_XMIT)
		printk("%s, skb possibly corrupted %p\n", __func__, skb);
	
	global_free_count++;

	napi_consume_skb(skb, budget);

#ifdef FREE_TIMESTAMP
	TS_STOP(free);
	times_free[iter] = TS_DIFF(free);
	iter = (iter + 1) % NUM_PACKETS;
#endif

	if (skb_c->tsk == current && revoke) {
		lcd_cap_revoke(skb_cptr);
		lcd_cap_revoke(skbh_cptr);
		lcd_unvolunteer_pages(skb_cptr);
		lcd_unvolunteer_pages(skbh_cptr);
	}

	glue_remove_skbuff(skb_c);

#ifdef SKBC_PRIVATE_POOL
	WARN_ON(!skb_c);
	if(skb_c)
		priv_free(skb_c, SKB_CONTAINER_POOL);
#else
	kmem_cache_free(skb_c_cache, skb_c);
#endif

#ifndef NAPI_CONSUME_SEND_ONLY
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
#endif
	return ret;
}

int consume_skb_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct sk_buff *skb;
	struct sk_buff_container *skb_c;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);

	glue_lookup_skbuff(cptr_table,
		__cptr(fipc_get_reg0(_request)),
		&skb_c);
	skb = skb_c->skb;
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	/* restore */
	skb->head = skb_c->head;
	skb->data = skb_c->data;

	consume_skb(skb);

	glue_remove_skbuff(skb_c);
	kfree(skb_c);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int unregister_netdev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg0(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	unregister_netdev(&dev_container->net_device);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;
}

int eth_platform_get_mac_address_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct device *dev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned int request_cookie;
	int func_ret;
	union mac {
		u8 mac_addr[ETH_ALEN];
		unsigned long mac_addr_l;
	} m = { {0} };
	u8 mac_addr[ETH_ALEN];

	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = &g_pdev->dev;

	func_ret = eth_platform_get_mac_address(dev, mac_addr);

	LIBLCD_MSG("%s returned %d", __func__, func_ret);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	/* pass on mac addr only if the function gets a
	 * valid address
	 */
	if (!func_ret) {
		memcpy(m.mac_addr, mac_addr, ETH_ALEN);
		fipc_set_reg2(_response,
			m.mac_addr_l);
	}

	fipc_set_reg1(_response,
			func_ret);

	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int dev_addr_add_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device *dev;
	struct net_device_container *dev_container;
	unsigned 	char addr_type;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long addr_offset;
	cptr_t addr_cptr;
	gva_t addr_gva;

	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	dev = &dev_container->net_device;
	addr_type = fipc_get_reg3(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	sync_ret = lcd_cptr_alloc(&addr_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		lcd_exit(-1);
	}
	lcd_set_cr0(addr_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		lcd_exit(-1);
	}
	mem_order = lcd_r0();
	addr_offset = lcd_r1();
	sync_ret = lcd_map_virt(addr_cptr,
		mem_order,
		&addr_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *addr");
		lcd_exit(-1);
	}
	rtnl_lock();
	func_ret = dev_addr_add(dev,
		( void  * )( ( gva_val(addr_gva) ) + ( addr_offset ) ),
		addr_type);
	rtnl_unlock();
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;

}

int dev_addr_del_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device *dev;
	struct net_device_container *dev_container;
	unsigned 	char addr_type;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	int sync_ret;
	unsigned 	long mem_order;
	unsigned 	long addr_offset;
	cptr_t addr_cptr;
	gva_t addr_gva;

	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	dev = &dev_container->net_device;
	addr_type = fipc_get_reg3(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	sync_ret = lcd_cptr_alloc(&addr_cptr);
	if (sync_ret) {
		LIBLCD_ERR("failed to get cptr");
		lcd_exit(-1);
	}
	lcd_set_cr0(addr_cptr);
	sync_ret = lcd_sync_recv(sync_ep);
	lcd_set_cr0(CAP_CPTR_NULL);
	if (sync_ret) {
		LIBLCD_ERR("failed to recv");
		lcd_exit(-1);
	}
	mem_order = lcd_r0();
	addr_offset = lcd_r1();
	sync_ret = lcd_map_virt(addr_cptr,
		mem_order,
		&addr_gva);
	if (sync_ret) {
		LIBLCD_ERR("failed to map void *addr");
		lcd_exit(-1);
	}
	rtnl_lock();
	func_ret = dev_addr_del(dev,
		( void  * )( ( gva_val(addr_gva) ) + ( addr_offset ) ),
		addr_type);
	rtnl_unlock();
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;

}

int device_set_wakeup_enable_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct device *dev;
	bool enable;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = &g_pdev->dev;
	enable = fipc_get_reg1(_request);
	func_ret = device_set_wakeup_enable(dev,
		enable);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int netif_tx_stop_all_queues_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *ndev_container;
	struct net_device *dev;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg0(_request)),
		&ndev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	dev = &ndev_container->net_device;
	netif_tx_stop_all_queues(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
	return ret;
}

int _netif_tx_wake_all_queues_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_queue_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	struct net_device *dev;
	int num_qs;

	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_queue_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	num_qs = fipc_get_reg2(_request);

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	dev = &dev_queue_container->net_device;
	dev->num_tx_queues = num_qs;

	netif_tx_wake_all_queues(dev);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
	return ret;
}

int pci_disable_pcie_error_reporting_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	func_ret = pci_disable_pcie_error_reporting(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_bus_read_config_word_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_bus *bus = g_pdev->bus;
	unsigned 	int devfn;
	int where;
	unsigned short val;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	devfn = fipc_get_reg1(_request);
	where = fipc_get_reg2(_request);
	func_ret = pci_bus_read_config_word(bus,
		devfn,
		where,
		&val);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			val);
	fipc_set_reg2(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_bus_write_config_word_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_bus *bus;
	unsigned 	int devfn;
	int where;
	unsigned 	short val;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	bus = g_pdev->bus;
	devfn = fipc_get_reg3(_request);
	where = fipc_get_reg4(_request);
	val = fipc_get_reg5(_request);
	func_ret = pci_bus_write_config_word(bus,
		devfn,
		where,
		val);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_cleanup_aer_uncorrect_error_status_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	func_ret = pci_cleanup_aer_uncorrect_error_status(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_disable_device_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	pci_disable_device(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_enable_pcie_error_reporting_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev = g_pdev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	func_ret = pci_enable_pcie_error_reporting(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pcie_capability_read_word_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	int pos;
	unsigned short val;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	pos = fipc_get_reg1(_request);
	val = fipc_get_reg2(_request);
	func_ret = pcie_capability_read_word(dev,
		pos,
		&val);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	fipc_set_reg2(_response,
			val);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pcie_get_minimum_link_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	enum pci_bus_speed speed;
	enum pcie_link_width width;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	speed = fipc_get_reg1(_request);
	width = fipc_get_reg2(_request);

	func_ret = pcie_get_minimum_link(dev,
		&speed,
		&width);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_enable_device_mem_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev = g_pdev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	func_ret = pci_enable_device_mem(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_request_selected_regions_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	int type;
	int ret = 0;
	struct fipc_message *_response;
	unsigned int request_cookie;
	int func_ret;
	struct pci_dev *dev = g_pdev;

	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	type = fipc_get_reg1(_request);
	func_ret = pci_request_selected_regions(dev,
		type,
		driver_name);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_request_selected_regions_exclusive_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	int type;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	type = fipc_get_reg1(_request);
	func_ret = pci_request_selected_regions_exclusive(dev,
		type,
		driver_name);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_set_master_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev = g_pdev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	pci_set_master(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_save_state_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev = g_pdev;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	func_ret = pci_save_state(dev);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_release_selected_regions_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	int r;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	r = fipc_get_reg1(_request);
	pci_release_selected_regions(dev,
			r);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_select_bars_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	unsigned 	long flags;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	flags = fipc_get_reg1(_request);
	func_ret = pci_select_bars(dev,
		flags);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int pci_wake_from_d3_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct pci_dev *dev;
	bool enable;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	dev = g_pdev;
	enable = fipc_get_reg1(_request);
	func_ret = pci_wake_from_d3(dev,
		enable);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int trigger_exit_to_lcd(struct thc_channel *_channel, enum dispatch_t disp)
{
	struct fipc_message *_request;
	int ret, i;
	unsigned int request_cookie;

	ret = async_msg_blocking_send_start(_channel,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			disp);

	/* No need to wait for a response here */
	ret = thc_ipc_send_request(_channel,
			_request,
			&request_cookie);

	if (disp == TRIGGER_CLEAN) {
	thread = 0;
	for (i = 0; i < NUM_CORES; i++) {
		if (ptrs[i]) {
			if (ptrs[i]->exited) {
				kfree(ptrs[i]);
				ptrs[i] = NULL;
				continue;
			}
		}
	}
	}

	if (ret) {
		LIBLCD_ERR("thc_ipc send");
		goto fail_ipc;
	}
	awe_mapper_remove_id(request_cookie);

fail_async:
fail_ipc:
	return ret;
}

int ixgbe_trigger_dump(struct thc_channel *_channel)
{
	struct fipc_message *_request;
	unsigned int request_cookie;
	int ret;
	struct net_device_container *dev_container;
	bool cleanup = false;

	if (!current->ptstate) {
		cleanup = true;
		thc_init();
	}

	ret = fipc_test_blocking_send_start(_channel,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			TRIGGER_DUMP);
	dev_container = container_of(g_ndev,
		struct net_device_container, net_device);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);

	/* No need to wait for a response here */
	ret = thc_ipc_send_request(_channel,
			_request,
			&request_cookie);
	if (ret) {
		LIBLCD_ERR("thc_ipc send");
		goto fail_ipc;
	}

fail_async:
fail_ipc:
	if (cleanup)
		lcd_exit(0);
	return ret;
}

int ixgbe_service_event_sched(struct thc_channel *_channel)
{
	struct fipc_message *_request;
	unsigned int request_cookie;
	int ret;
	struct net_device_container *dev_container;
	bool cleanup = false;

	if (!current->ptstate) {
		cleanup = true;
		thc_init();
	}

	ret = fipc_test_blocking_send_start(_channel,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			SERVICE_EVENT_SCHED);
	dev_container = container_of(g_ndev,
		struct net_device_container, net_device);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);

	/* No need to wait for a response here */
	ret = thc_ipc_send_request(_channel,
			_request,
			&request_cookie);
	if (ret) {
		LIBLCD_ERR("thc_ipc send");
		goto fail_ipc;
	}
	thc_kill_request_cookie(request_cookie);
fail_async:
fail_ipc:
	if (cleanup)
		lcd_exit(0);
	return ret;
}

int sync_user(struct net_device *dev,
		unsigned char *mac,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	union __mac {
		u8 mac_addr[ETH_ALEN];
		unsigned long mac_addr_l;
	} m = { {0} };


	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			SYNC);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	if (mac) {
		memcpy(m.mac_addr, mac, ETH_ALEN);
		MAC_ADDR_DUMP(m.mac_addr);
		fipc_set_reg3(_request, m.mac_addr_l);
	}

	DO_FINISH_(sync_user, {
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, sync_user
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	lcd_exit(0);
	return ret;
}

int sync(struct net_device *dev,
		unsigned char *mac,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	union __mac {
		u8 mac_addr[ETH_ALEN];
		unsigned long mac_addr_l;
	} m = { {0} };

	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ret = sync_user(dev,
		mac,
		hidden_args);
		}
		);
		return ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	if (mac) {
		memcpy(m.mac_addr, mac, ETH_ALEN);
		MAC_ADDR_DUMP(m.mac_addr);
		fipc_set_reg3(_request, m.mac_addr_l);
	}
	async_msg_set_fn_type(_request,
			SYNC);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;
}

LCD_TRAMPOLINE_DATA(sync_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(sync_trampoline)
sync_trampoline(struct net_device *dev,
		unsigned char *mac)
{
	int ( *volatile sync_fp )(struct net_device *,
		unsigned char *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			sync_trampoline);
	sync_fp = sync;
	return sync_fp(dev,
		mac,
		hidden_args);

}

int unsync_user(struct net_device *dev,
		unsigned char *mac,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	union __mac {
		u8 mac_addr[ETH_ALEN];
		unsigned long mac_addr_l;
	} m = { {0} };

	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	thc_init();
	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			UNSYNC);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	if (mac) {
		memcpy(m.mac_addr, mac, ETH_ALEN);
		MAC_ADDR_DUMP(m.mac_addr);
		fipc_set_reg3(_request, m.mac_addr_l);
	}

	DO_FINISH_(unsync_user, {
		ASYNC_({
			ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
		}, unsync_user
		);
	}
	);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	lcd_exit(0);
	return func_ret;
fail_async:
fail_ipc:
	lcd_exit(0);
	return ret;
}


int unsync(struct net_device *dev,
		unsigned char *mac,
		struct trampoline_hidden_args *hidden_args)
{
	struct net_device_container *dev_container;
	int ret;
	struct fipc_message *_request;
	struct fipc_message *_response;
	int func_ret;
	union __mac {
		u8 mac_addr[ETH_ALEN];
		unsigned long mac_addr_l;
	} m = { {0} };

	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from non-LCD (%s) context! creating thc runtime", __func__, current->comm);
		LCD_MAIN({
			ret = unsync_user(dev,
		mac,
		hidden_args);
		}
		);
		return ret;
	}
	dev_container = container_of(dev,
		struct net_device_container,
		net_device);
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			UNSYNC);
	fipc_set_reg1(_request,
			dev_container->other_ref.cptr);
	if (mac) {
		memcpy(m.mac_addr, mac, ETH_ALEN);
		MAC_ADDR_DUMP(m.mac_addr);
		fipc_set_reg3(_request, m.mac_addr_l);
	}

	ret = thc_ipc_call(hidden_args->async_chnl,
		_request,
		&_response);
	if (ret) {
		LIBLCD_ERR("thc_ipc_call");
		goto fail_ipc;
	}
	func_ret = fipc_get_reg1(_response);
	fipc_recv_msg_end(thc_channel_to_fipc(hidden_args->async_chnl),
			_response);
	return func_ret;
fail_async:
fail_ipc:
	return ret;
}

LCD_TRAMPOLINE_DATA(unsync_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(unsync_trampoline)
unsync_trampoline(struct net_device *dev,
		unsigned char *mac)
{
	int ( *volatile unsync_fp )(struct net_device *,
		unsigned char *,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			unsync_trampoline);
	unsync_fp = unsync;
	return unsync_fp(dev,
		mac,
		hidden_args);

}

struct trampoline_hidden_args *unsync_hidden_args;
struct unsync_container *unsync_container;

int __hw_addr_sync_dev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev1_container;
	struct sync_container *sync_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	addr_list _type;
	struct trampoline_hidden_args *sync_hidden_args;

	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev1_container);
	_type = fipc_get_reg2(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	sync_container = kzalloc(sizeof( struct sync_container   ),
		GFP_KERNEL);
	if (!sync_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}

	sync_hidden_args = kzalloc(sizeof( *sync_hidden_args ),
		GFP_KERNEL);
	if (!sync_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc1;
	}
	sync_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(sync_trampoline);
	if (!sync_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup1;
	}
	sync_hidden_args->t_handle->hidden_args = sync_hidden_args;
	sync_hidden_args->struct_container = sync_container;
	sync_hidden_args->cspace = c_cspace;
	sync_hidden_args->sync_ep = sync_ep;
	sync_hidden_args->async_chnl = _channel;

	sync_container->sync = LCD_HANDLE_TO_TRAMPOLINE(sync_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )sync_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(sync_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));


	unsync_container = kzalloc(sizeof( struct unsync_container   ),
		GFP_KERNEL);
	if (!unsync_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	unsync_hidden_args = kzalloc(sizeof( *unsync_hidden_args ),
		GFP_KERNEL);
	if (!unsync_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc2;
	}
	unsync_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(unsync_trampoline);
	if (!unsync_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup2;
	}
	unsync_hidden_args->t_handle->hidden_args = unsync_hidden_args;
	unsync_hidden_args->struct_container = unsync_container;
	unsync_hidden_args->cspace = c_cspace;
	unsync_hidden_args->sync_ep = sync_ep;
	unsync_hidden_args->async_chnl = _channel;

	unsync_container->unsync = LCD_HANDLE_TO_TRAMPOLINE(unsync_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )unsync_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(unsync_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));

	func_ret = __hw_addr_sync_dev(
		_type == UC_LIST ? &dev1_container->net_device.uc :
			&dev1_container->net_device.mc,
		( &dev1_container->net_device ),
		( sync_container->sync ),
		( unsync_container->unsync ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
fail_alloc:
fail_alloc1:
fail_dup1:
fail_alloc2:
fail_dup2:
	return ret;
}

int __hw_addr_unsync_dev_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev1_container;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	addr_list _type;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev1_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	_type = fipc_get_reg2(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	__hw_addr_unsync_dev(
		_type == UC_LIST ? &dev1_container->net_device.uc :
			&dev1_container->net_device.mc,
		( &dev1_container->net_device ),
		( unsync_container->unsync ));
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
	return ret;
}

#ifdef HOST_IRQ
extern irqreturn_t msix_clean_rings_host(int irq, void *data);

int _request_irq_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	int ret = 0;
	int func_ret = 0;
	int irq;
	unsigned long flags;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	irq = fipc_get_reg1(_request);
	flags = fipc_get_reg2(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	LIBLCD_MSG("%s, request irq for %d", __func__, irq);

	func_ret = request_irq(irq, msix_clean_rings_host, flags, "ixgbe_lcd_msix_clean_rings", NULL);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

int _free_irq_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	unsigned 	int irq;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	irq = fipc_get_reg1(_request);
	LIBLCD_MSG("%s, freeing irq %d", __func__, irq);
	free_irq(irq, NULL);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;

}
#endif /* HOST_IRQ */

int poll_once(struct napi_struct *napi,
		int budget,
		struct trampoline_hidden_args *hidden_args)
{
	struct fipc_message *_request;
	unsigned int request_cookie;
	static int once = 0;
	int ret;

	if (once)
		goto exit;

	thc_init();

	ret = fipc_test_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}

	async_msg_set_fn_type(_request,
			POLL);

	fipc_set_reg0(_request, true);
	/* No need to wait for a response here */
	ret = thc_ipc_send_request(hidden_args->async_chnl,
			_request,
			&request_cookie);
	if (ret) {
		LIBLCD_ERR("thc_ipc send");
		goto fail_ipc;
	}
fail_ipc:
fail_async:
	if (!once) {
		once = 1;
		printk("%s trying to call lcd_exit with lcd %p\n", __func__, current->lcd);
		thc_done();
	}
exit:
	return 0;
}

int poll(struct napi_struct *napi,
		int budget,
		struct trampoline_hidden_args *hidden_args)
{
	int ret;
	struct fipc_message *_request;
	unsigned int request_cookie;

	printk("%s, poll - budget %d\n", __func__, budget);

	if (!current->ptstate) {
		LIBLCD_MSG("%s, Calling from a non-LCD (%s) context! creating thc runtime!",
				__func__, current->comm);
		ret = poll_once(napi,
			budget, hidden_args);
		return ret;
	}
	ret = async_msg_blocking_send_start(hidden_args->async_chnl,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			POLL);
	fipc_set_reg0(_request,
			budget);

	/* No need to wait for a response here */
	ret = thc_ipc_send_request(hidden_args->async_chnl,
			_request,
			&request_cookie);
	if (ret) {
		LIBLCD_ERR("thc_ipc send");
		goto fail_ipc;
	}

fail_async:
fail_ipc:
	return ret;
}

LCD_TRAMPOLINE_DATA(poll_trampoline);
int  LCD_TRAMPOLINE_LINKAGE(poll_trampoline)
poll_trampoline(struct napi_struct *napi,
		int budget)
{
	int ( *volatile poll_fp )(struct napi_struct *,
		int ,
		struct trampoline_hidden_args *);
	struct trampoline_hidden_args *hidden_args;
	LCD_TRAMPOLINE_PROLOGUE(hidden_args,
			poll_trampoline);
	poll_fp = poll;
	return poll_fp(napi,
		budget,
		hidden_args);

}

int netif_napi_add_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	struct poll_container *poll_container;
	int weight;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	struct trampoline_hidden_args *poll_hidden_args;

	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	poll_container = kzalloc(sizeof( struct poll_container   ),
		GFP_KERNEL);
	if (!poll_container) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}
	weight = fipc_get_reg3(_request);

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	poll_hidden_args = kzalloc(sizeof( *poll_hidden_args ),
		GFP_KERNEL);
	if (!poll_hidden_args) {
		LIBLCD_ERR("kzalloc hidden args");
		goto fail_alloc1;
	}
	poll_hidden_args->t_handle = LCD_DUP_TRAMPOLINE(poll_trampoline);
	if (!poll_hidden_args->t_handle) {
		LIBLCD_ERR("duplicate trampoline");
		goto fail_dup1;
	}
	poll_hidden_args->t_handle->hidden_args = poll_hidden_args;
	poll_hidden_args->struct_container = poll_container;
	poll_hidden_args->cspace = c_cspace;
	poll_hidden_args->sync_ep = sync_ep;
	poll_hidden_args->async_chnl = _channel;

	poll_container->poll = LCD_HANDLE_TO_TRAMPOLINE(poll_hidden_args->t_handle);
	ret = set_memory_x(( ( unsigned  long   )poll_hidden_args->t_handle ) & ( PAGE_MASK ),
		( ALIGN(LCD_TRAMPOLINE_SIZE(poll_trampoline),
		PAGE_SIZE) ) >> ( PAGE_SHIFT ));
	napi_q0 = kzalloc(sizeof( *napi_q0 ),
		GFP_KERNEL);
	if (!napi_q0) {
		LIBLCD_ERR("kzalloc");
		goto fail_alloc;
	}

	netif_napi_add(( &dev_container->net_device ),
			napi_q0,
			( poll_container->poll ),
			weight);

	LIBLCD_MSG("%s, napi %p | napi->dev %p",
		__func__, napi_q0, napi_q0->dev);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
fail_lookup:
fail_alloc:
fail_alloc1:
fail_dup1:
	return ret;
}

int poll_stop(struct thc_channel *_channel)
{
	struct fipc_message *_request;
	int ret;
	unsigned int request_cookie;

	ret = async_msg_blocking_send_start(_channel,
		&_request);
	if (ret) {
		LIBLCD_ERR("failed to get a send slot");
		goto fail_async;
	}
	async_msg_set_fn_type(_request,
			POLL);

	fipc_set_reg0(_request, false);
	/* No need to wait for a response here */
	ret = thc_ipc_send_request(_channel,
			_request,
			&request_cookie);

	if (ret) {
		LIBLCD_ERR("thc_ipc send");
		goto fail_ipc;
	}

fail_async:
fail_ipc:
	return ret;
}


int netif_napi_del_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	netif_napi_del(napi_q0);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return 0;
}

int netif_wake_subqueue_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct net_device_container *dev_container;
	unsigned 	short queue_index;
	int ret;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	request_cookie = thc_get_request_cookie(_request);
	ret = glue_cap_lookup_net_device_type(cspace,
		__cptr(fipc_get_reg1(_request)),
		&dev_container);
	if (ret) {
		LIBLCD_ERR("lookup");
		goto fail_lookup;
	}
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	queue_index = fipc_get_reg3(_request);
	netif_wake_subqueue(( &dev_container->net_device ),
			queue_index);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
fail_lookup:
	return ret;
}

int netif_receive_skb_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct sk_buff *skb;
	struct sk_buff_container *skb_c;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	cptr_t skb_ref;

	request_cookie = thc_get_request_cookie(_request);
	skb_ref = __cptr(fipc_get_reg0(_request));

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	glue_lookup_skbuff(cptr_table, skb_ref, &skb_c);

	skb = skb_c->skb;
	skb->head = skb_c->head;
	skb->data = skb_c->data;

	LIBLCD_MSG("%s, skb->dev %p", __func__, skb->dev);
	func_ret = netif_receive_skb(skb);
	LIBLCD_MSG("%s ret %d", __func__, func_ret);

	glue_remove_skbuff(skb_c);
	kfree(skb_c);
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

extern struct lcd *iommu_lcd;

#ifndef LOCAL_SKB
int napi_gro_receive_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct napi_struct *napi;
	struct sk_buff *skb;
	struct sk_buff_container *skb_c;
	int ret = 0;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	int func_ret;
	cptr_t skb_ref;
	cptr_t skb_cptr, skbh_cptr;
	unsigned 	long page = 0ul;
	struct lcd *lcd_struct;
	hva_t hva_out;
	struct skb_shared_info *shinfo;
	struct page *p = NULL;
	unsigned int old_pcount;

	request_cookie = thc_get_request_cookie(_request);

	skb_ref = __cptr(fipc_get_reg0(_request));

	page = fipc_get_reg1(_request);

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	napi = napi_q0;
	glue_lookup_skbuff(cptr_table, skb_ref, &skb_c);

	skb = skb_c->skb;
	skb->head = skb_c->head;
	skb->data = skb_c->data;
	skb_cptr = skb_c->skb_cptr;
	skbh_cptr = skb_c->skbh_cptr;

	skb->dev = napi->dev;
	shinfo = skb_shinfo(skb);

	if (shinfo->nr_frags) {
		skb_frag_t *frag = &shinfo->frags[0];

		lcd_struct = iommu_lcd;

		ret = lcd_arch_ept_gpa_to_hva(lcd_struct->lcd_arch,
			__gpa(page), &hva_out);
		if (ret) {
			LIBLCD_WARN("getting gpa:hpa mapping %p:%llx",
				(void*)page, hva_val(hva_out));
			ret = 0;
			goto skip;
		}

		/* set frag page */
		p = frag->page.p = virt_to_page(hva_val(hva_out));
		old_pcount = page_count(skb_frag_page(frag));

		set_page_count(skb_frag_page(frag), 2);

		if (0)
		printk("%s, Frag #%d | page %p | refc %d\n", __func__,
				shinfo->nr_frags,
				frag->page.p,
				page_count(frag->page.p));
	}
skip:

	post_recv = true;

	//skb_pull_inline(skb, ETH_HLEN);
	skb->data += ETH_HLEN;

	func_ret = napi_gro_receive(napi, skb);

	if (p)
		set_page_count(p, 1);

	if (skb_c->tsk == current) {
		lcd_cap_revoke(skb_cptr);
		lcd_cap_revoke(skbh_cptr);
		lcd_unvolunteer_pages(skb_cptr);
		lcd_unvolunteer_pages(skbh_cptr);
	}

	glue_remove_skbuff(skb_c);
	kfree(skb_c);

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}
	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;
}

#else
void ixgbe_pull_tail(struct sk_buff *skb)
{
	struct skb_frag_struct *frag = &skb_shinfo(skb)->frags[0];
	unsigned char *va;
	unsigned int pull_len;

	/*
	 * it is valid to use page_address instead of kmap since we are
	 * working with pages allocated out of the lomem pool per
	 * alloc_page(GFP_ATOMIC)
	 */
	va = skb_frag_address(frag);

	/*
	 * we need the header to contain the greater of either ETH_HLEN or
	 * 60 bytes if the skb->len is less than 60 for skb_pad.
	 */

#define IXGBE_RX_HDR_SIZE	256

	pull_len = eth_get_headlen(va, IXGBE_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	skb_copy_to_linear_data(skb, va, ALIGN(pull_len, sizeof(long)));

	//printk("%s, pull len %d\n", __func__, pull_len);
	/* update all of the pointers */
	skb_frag_size_sub(frag, pull_len);
	frag->page_offset += pull_len;
	skb->data_len -= pull_len;
	skb->tail += pull_len;
}

int napi_gro_receive_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct napi_struct *napi;
	struct sk_buff *skb;
	int ret = 0;
#ifndef NAPI_RX_SEND_ONLY
	struct fipc_message *_response;
	unsigned int request_cookie;
#endif
	int func_ret;
	unsigned long page = 0ul;
	struct lcd *lcd_struct;
	hva_t hva_out = {0};
	struct skb_shared_info *shinfo;
	struct page *p = NULL;
	unsigned int old_pcount;
	__be16 prot;
	u64 off_sz,
		truesize,
		csum_ipsum,
		hash_l4sw,
		nr_frags_tail;
	unsigned int pull_len;
	unsigned char nr_frags;
	unsigned char buffer[300] = {0};
	bool tcp = false;

	u32 frag_off = 0, frag_size = 0;
#ifndef NAPI_RX_SEND_ONLY
	request_cookie = thc_get_request_cookie(_request);
#endif
	nr_frags_tail = fipc_get_reg0(_request);

	nr_frags = nr_frags_tail & 0xff;
	/* this is the amount of data copied to the skb->data
	 * by copy_to_linear_data. We have to do it again with
	 * the skb allocated here
	 */
	pull_len = nr_frags_tail >> 8;

	if (nr_frags) {
		page = fipc_get_reg1(_request);
		off_sz = fipc_get_reg3(_request);
		frag_size = off_sz >> 32;
		frag_off = off_sz;
		/* reverse the effects of pull_tail done at LCD end */
		frag_size += pull_len;
		frag_off -= pull_len;
	}

	prot = fipc_get_reg2(_request);
	truesize = fipc_get_reg5(_request);
	hash_l4sw = fipc_get_reg4(_request);
	csum_ipsum = fipc_get_reg6(_request);

	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);

	WARN_ON(nr_frags > 1);
	napi = napi_q0;

#define IXGBE_HDR_SIZE	256

	skb = napi_alloc_skb(napi, IXGBE_HDR_SIZE);

	skb->dev = napi->dev;

	shinfo = skb_shinfo(skb);

	if (nr_frags) {
		skb_frag_t *frag;

		lcd_struct = iommu_lcd;

		ret = lcd_arch_ept_gpa_to_hva(lcd_struct->lcd_arch,
			__gpa(page), &hva_out);
		if (ret) {
			LIBLCD_WARN("getting gpa:hpa mapping %p:%llx",
				(void*)page, hva_val(hva_out));
			ret = 0;
			goto skip;
		}

		p = virt_to_page(hva_val(hva_out));

		/* add frag */
		skb_add_rx_frag(skb, shinfo->nr_frags, p, frag_off,
					frag_size,
					truesize); 

		frag = &shinfo->frags[0];

		old_pcount = page_count(skb_frag_page(frag));

		set_page_count(skb_frag_page(frag), 2);
	}

	if (skb_is_nonlinear(skb))
		ixgbe_pull_tail(skb);

	skb->protocol = prot;

	eth_skb_pad(skb);

	skb->queue_mapping = csum_ipsum & 0xffff;
	skb->csum_level = (csum_ipsum >> 16)& 0x3;
	skb->ip_summed = (csum_ipsum >> 18) & 0x3;
	skb->queue_mapping = (csum_ipsum >> 2) & 0x3;

	skb->napi_id = napi->napi_id;
	skb->hash = hash_l4sw;
	skb->l4_hash = (hash_l4sw >> 32) & 0x1;
	skb->sw_hash = (hash_l4sw >> 33) & 0x1;

	skb_pull_inline(skb, ETH_HLEN);

	/* if TCP */
	if (skb->data[9] == 0x6) {
		unsigned char flags = (skb->data[32] & 0x0F) | skb->data[33];
		unsigned int seq = (skb->data[24] << 24) | (skb->data[25] << 16) | (skb->data[26] << 8) | skb->data[27];
		unsigned int ack = (skb->data[28] << 24) | (skb->data[29] << 16) | (skb->data[30] << 8) | skb->data[31];

		sprintf(buffer, "%s, recv cpu=%d:%10s[%d] | pts %p | proto %x | IP proto %x | TCP.seq %u | TCP.ack %u | TCP Flags [%s%s%s%s%s] ",
				__func__, smp_processor_id(), current->comm, current->pid,
				current->ptstate, htons(skb->protocol), skb->data[9], seq, ack,
					(flags & 0x1) ? " FIN " : "",
					(flags & 0x2) ? " SYN " : "",
					(flags & 0x4) ? " RST " : "",
					(flags & 0x8) ? " PSH " : "",
					(flags & 0x10) ? " ACK " : "");
		tcp = true;
	} else {
		sprintf(buffer, "%s, recv cpu=%d:%10s[%d] | pts %p | proto %x | IP proto %x",
				__func__, smp_processor_id(), current->comm, current->pid,
				current->ptstate, htons(skb->protocol), skb->data[9]);
	}

	//printk("%s context {\n", buffer);

	func_ret = napi_gro_receive(napi, skb);

	//printk("} ==> ret_val = %d\n", func_ret);

	if (p)
		set_page_count(p, old_pcount);
skip:
#ifndef NAPI_RX_SEND_ONLY
	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	fipc_set_reg1(_response,
			func_ret);
	thc_ipc_reply(_channel,
			request_cookie,
			_response);
#endif
	return ret;
}
#endif

int __napi_alloc_skb_callee(struct fipc_message *_request,
		struct thc_channel *_channel,
		struct glue_cspace *cspace,
		struct cptr sync_ep)
{
	struct napi_struct *napi;
	unsigned 	int len;
	gfp_t gfp_mask;
	int ret = 0;
	struct sk_buff *skb;
	struct sk_buff_container *skb_c;
	struct fipc_message *_response;
	unsigned 	int request_cookie;
	unsigned long skb_ord, skbd_ord;
	unsigned long skb_off, skbd_off;
	cptr_t skb_cptr, skbd_cptr;

	request_cookie = thc_get_request_cookie(_request);
	fipc_recv_msg_end(thc_channel_to_fipc(_channel),
			_request);
	napi = napi_q0;

	len = fipc_get_reg1(_request);

	gfp_mask = fipc_get_reg2(_request);

	skb = __napi_alloc_skb(napi,
			len,
			gfp_mask);

	skb_c = kzalloc(sizeof(*skb_c), GFP_KERNEL);

	if (!skb_c) {
		LIBLCD_MSG("skb_c allocation failed");
		goto fail_alloc;
	}
	skb_c->tsk = current;
	skb_c->skb = skb;
	skb_c->head = skb->head;
	skb_c->data = skb->data;

	glue_insert_skbuff(cptr_table, skb_c);

	ret = sync_setup_memory(skb, sizeof(struct sk_buff),
			&skb_ord, &skb_cptr, &skb_off);

	ret = sync_setup_memory(skb->head,
		skb_end_offset(skb) + sizeof(struct skb_shared_info),
			&skbd_ord, &skbd_cptr, &skbd_off);

	skb_c->skb_ord = skb_ord;
	skb_c->skbd_ord = skbd_ord;
	skb_c->skb_cptr = skb_cptr;
	skb_c->skbh_cptr = skbd_cptr;

	/* sync half */
	lcd_set_cr0(skb_cptr);
	lcd_set_cr1(skbd_cptr);
	lcd_set_r0(skb_ord);
	lcd_set_r1(skb_off);
	lcd_set_r2(skbd_ord);
	lcd_set_r3(skbd_off);
	lcd_set_r4(skb->data - skb->head);
	lcd_set_r5(skb_c->my_ref.cptr);

	ret = lcd_sync_send(sync_ep);

	lcd_set_cr0(CAP_CPTR_NULL);
	lcd_set_cr1(CAP_CPTR_NULL);

	if (ret) {
		LIBLCD_ERR("failed to send");
		goto fail_sync;
	}

	if (async_msg_blocking_send_start(_channel,
		&_response)) {
		LIBLCD_ERR("error getting response msg");
		return -EIO;
	}

	thc_ipc_reply(_channel,
			request_cookie,
			_response);
	return ret;

fail_alloc:
fail_sync:
	return ret;
}
