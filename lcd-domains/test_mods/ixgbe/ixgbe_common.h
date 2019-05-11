#ifndef __IXGBE_COMMON_H__
#define __IXGBE_COMMON_H__

#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>

#include <libcap.h>
#include <libfipc.h>
#include <thc_ipc.h>
#include <liblcd/glue_cspace.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <linux/priv_mempool.h>

#include "ixgbe_glue_helper.h"

#define PCI_REGIONS
#define IOMMU_ASSIGN
#define HOST_IRQ
#define NAPI_CONSUME_SEND_ONLY
#define LOCAL_SKB
#define NAPI_RX_SEND_ONLY
#define SENDER_DISPATCH_LOOP
#define CONFIG_PREALLOC_XMIT_CHANNELS

enum dispatch_t {
	__PCI_REGISTER_DRIVER = 1,
	PCI_UNREGISTER_DRIVER,
	ALLOC_ETHERDEV_MQS,
	REGISTER_NETDEV,
	PREP_CHANNEL,
	ETHER_SETUP,
	ETH_MAC_ADDR,
	ETH_VALIDATE_ADDR,
	FREE_NETDEV,
	NETIF_CARRIER_OFF,
	NETIF_CARRIER_ON,
	NETIF_DEVICE_ATTACH,
	NETIF_DEVICE_DETACH,
	NETIF_SET_REAL_NUM_RX_QUEUES,
	NETIF_SET_REAL_NUM_TX_QUEUES,
	CONSUME_SKB,
	NAPI_CONSUME_SKB,
	UNREGISTER_NETDEV,
	ETH_PLATFORM_GET_MAC_ADDRESS,
	DEV_ADDR_ADD,
	DEV_ADDR_DEL,
	DEVICE_SET_WAKEUP_ENABLE,
	NETIF_TX_STOP_ALL_QUEUES,
	NETIF_TX_WAKE_ALL_QUEUES,
	NETIF_NAPI_ADD,
	NETIF_NAPI_DEL,
	NETIF_WAKE_SUBQUEUE,
	NETIF_RECEIVE_SKB,
	NAPI_GRO_RECEIVE,
	__NAPI_ALLOC_SKB,
	ETH_TYPE_TRANS,
	SKB_ADD_RX_FRAG,
	ETH_GET_HEADLEN,
	PCI_DISABLE_PCIE_ERROR_REPORTING,
	PCI_BUS_READ_CONFIG_WORD,
	PCI_BUS_WRITE_CONFIG_WORD,
	PCI_CLEANUP_AER_UNCORRECT_ERROR_STATUS,
	PCI_DISABLE_DEVICE,
	PCI_DISABLE_MSIX,
	PCI_ENABLE_MSIX_RANGE,
	PCI_ENABLE_PCIE_ERROR_REPORTING,
	PCIE_CAPABILITY_READ_WORD,
	PCIE_GET_MINIMUM_LINK,
	PCI_ENABLE_DEVICE_MEM,
	PCI_REQUEST_SELECTED_REGIONS,
	PCI_REQUEST_SELECTED_REGIONS_EXCLUSIVE,
	PCI_SET_MASTER,
	PCI_SAVE_STATE,
	PCI_RESTORE_STATE,
	PCI_RELEASE_SELECTED_REGIONS,
	PCI_SELECT_BARS,
	PCI_WAKE_FROM_D3,
	__HW_ADDR_SYNC_DEV,
	__HW_ADDR_UNSYNC_DEV,
	NDO_OPEN,
	NDO_STOP,
	NDO_START_XMIT,
	NDO_SELECT_QUEUE,
	NDO_SET_RX_MODE,
	NDO_VALIDATE_ADDR,
	NDO_SET_MAC_ADDRESS,
	NDO_CHANGE_MTU,
	NDO_TX_TIMEOUT,
	NDO_SET_TX_MAXRATE,
	NDO_GET_STATS64,
	PROBE,
	REMOVE,
	SYNC,
	UNSYNC,
	POLL,
	REQUEST_IRQ,
	_FREE_IRQ,
	TRIGGER_EXIT,
	SERVICE_EVENT_SCHED,
	TRIGGER_DUMP,
	TRIGGER_CLEAN,
};

typedef enum {
	MC_LIST = 1,
	UC_LIST = 2,
} addr_list;

typedef enum {
	VOLUNTEER_XMIT = 0x1,
	SHARED_DATA_XMIT = 0x2,
} xmit_type_t;

typedef enum {
	IXGBE_POLL_RUNNING,
	IXGBE_POLL_STOPPED,
} ixgbe_poll_state_t;

#define MAC_ADDR_DUMP(addr)	\
	do { \
	int _i; \
	for (_i = 0; _i < ETH_ALEN - 1; _i++) \
		printk("%02x:", addr[_i]); \
	printk("%02x\n", addr[_i]); \
	} while(0)

#define ASYNC_RPC_BUFFER_ORDER 15

struct pcidev_info {
	unsigned int domain, bus, slot, fn;
};

struct skbuff_members {
	unsigned int        len, data_len;
	__u16               queue_mapping;
	__u8                xmit_more:1,
			ip_summed:2;
	__u16		network_header;
	__u16			transport_header;
	union {
		__wsum		csum;
		struct {
			__u16	csum_start;
			__u16	csum_offset;
		};
	};
	sk_buff_data_t      tail;
	sk_buff_data_t      end;
	unsigned int 	head_data_off;
	unsigned int        truesize;
} __attribute__((aligned));

#define SKB_LCD_MEMBERS(SKB)	((struct skbuff_members*)((char*)skb_end_pointer(SKB) - (char*)SKB_LCD_MEMBERS_SZ))

#define C(x)	skb_lcd->x = skb->x
#define P(x)	skb->x = skb_lcd->x

#if NUM_LCDS == 1
/* total LCD cores = 2 (lcds=1,klcd=1), free cores = 18 */
#define MAX_CHANNELS_PER_LCD           	18
#define NUM_THREADS_ON_NODE0		8
#elif NUM_LCDS == 2
/* total LCD cores = 3 (lcds=2,klcd=1), free cores = 17 */
#define MAX_CHANNELS_PER_LCD           	9
#define NUM_THREADS_ON_NODE0		8
#elif NUM_LCDS == 4
/* total LCD cores = 5 (lcds=4,klcd=1), free cores = 15 */
#define MAX_CHANNELS_PER_LCD		4
#define NUM_THREADS_ON_NODE0		7
#elif NUM_LCDS == 6
/* total LCD cores = 7 (lcds=6,klcd=1), free cores = 13 */
#define MAX_CHANNELS_PER_LCD		3
#define NUM_THREADS_ON_NODE0		6
#endif

#define MAX_CHNL_PAIRS			MAX_CHANNELS_PER_LCD

/* CSPACES ------------------------------------------------------------ */
int glue_cap_init(void);

int glue_cap_create(struct glue_cspace **cspace);

void glue_cap_destroy(struct glue_cspace *cspace);

void glue_cap_exit(void);

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

static inline
int
fipc_test_blocking_send_start(struct thc_channel *chnl,
			struct fipc_message **out)
{
	int ret;
	for (;;) {
		/* Poll until we get a free slot or error */
		ret = fipc_send_msg_start(thc_channel_to_fipc(chnl), out);
		if (!ret || ret != -EWOULDBLOCK)
			return ret;
		cpu_relax();
	}
}

static inline
int
async_msg_blocking_recv_start(struct thc_channel *chnl,
			struct fipc_message** out)
{
	int ret;

	for (;;) {
		/* Poll until we get a message or error */
		ret = fipc_recv_msg_start(thc_channel_to_fipc(chnl),
						out);
		if ( !ret || ret != -EWOULDBLOCK )
			return ret;
		cpu_relax();
	}
}
#endif /* __IXGBE_COMMON_H__ */
