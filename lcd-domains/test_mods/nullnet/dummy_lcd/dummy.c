/* dummy.c: a dummy net driver

	The purpose of this driver is to provide a device to point a
	route through, but not to actually transmit packets.

	Why?  If you have a machine whose only connection is an occasional
	PPP/SLIP/PLIP link, you can only connect to your own hostname
	when the link is up.  Otherwise you have to use localhost.
	This isn't very consistent.

	One solution is to set up a dummy link using PPP/SLIP/PLIP,
	but this seems (to me) too much overhead for too little gain.
	This driver provides a small alternative. Thus you can do

	[when not running slip]
		ifconfig dummy slip.addr.ess.here up
	[to go to slip]
		ifconfig dummy down
		dip whatever

	This was written by looking at Donald Becker's skeleton driver
	and the loopback driver.  I then threw away anything that didn't
	apply!	Thanks to Alan Cox for the key clue on what to do with
	misguided packets.

			Nick Holloway, 27th May 1994
	[I tweaked this explanation a little but that's all]
			Alan Cox, 30th May 1994
*/
#ifdef LCD_ISOLATE
#include <lcd_config/pre_hook.h>
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/rtnetlink.h>
#include <net/rtnetlink.h>
#include <linux/u64_stats_sync.h>

#include "../glue_helper.h"

#ifdef LCD_ISOLATE
#include <lcd_config/post_hook.h>
#endif

#define DRV_NAME	"dummy"
#define DRV_VERSION	"1.0"

static int numdummies = 1;

/* fake multicast ability */
static void set_multicast_list(struct net_device *dev)
{
}

struct pcpu_dstats {
	u64			tx_packets;
	u64			tx_bytes;
	struct u64_stats_sync	syncp;
};

struct pcpu_dstats g_dstats;

static struct rtnl_link_stats64 *dummy_get_stats64(struct net_device *dev,
						   struct rtnl_link_stats64 *stats)
{
#ifndef LCD_ISOLATE
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_dstats *dstats;
		u64 tbytes, tpackets;
		unsigned int start;

		dstats = per_cpu_ptr(dev->dstats, i);
		do {
			start = u64_stats_fetch_begin_irq(&dstats->syncp);
			tbytes = dstats->tx_bytes;
			tpackets = dstats->tx_packets;
		} while (u64_stats_fetch_retry_irq(&dstats->syncp, start));
		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
	}
#else
	stats->tx_bytes = g_dstats.tx_bytes;
	stats->tx_packets = g_dstats.tx_packets;
#endif
	return stats;
}

netdev_tx_t dummy_xmit(struct sk_buff *skb, struct net_device *dev)
{
#ifndef LCD_ISOLATE
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);
#else
	/* XXX: Touching global variable brings down the bandwidth
	 * Do not do it for now
	 */
#if 0
	g_dstats.tx_packets++;
	g_dstats.tx_bytes += skb->len;
#endif
#endif

#ifdef SENDER_DISPATCH_LOOP
	dev_kfree_skb(skb);
#endif
	return NETDEV_TX_OK;
}

static int dummy_dev_init(struct net_device *dev)
{
#ifndef LCD_ISOLATE
	dev->dstats = netdev_alloc_pcpu_stats(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;
#endif
	return 0;
}

static void dummy_dev_uninit(struct net_device *dev)
{
#ifndef LCD_ISOLATE
	free_percpu(dev->dstats);
#endif
}

static int dummy_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

#ifdef LCD_ISOLATE
static const struct net_device_ops_container dummy_netdev_ops_container = {
	.net_device_ops = {
		.ndo_init		= dummy_dev_init,
		.ndo_uninit		= dummy_dev_uninit,
		.ndo_start_xmit		= dummy_xmit,
		.ndo_validate_addr	= eth_validate_addr,
		.ndo_set_rx_mode	= set_multicast_list,
		.ndo_set_mac_address	= eth_mac_addr,
		.ndo_get_stats64	= dummy_get_stats64,
		.ndo_change_carrier	= dummy_change_carrier,
	}
};
#else
static const struct net_device_ops dummy_netdev_ops = {
	.ndo_init		= dummy_dev_init,
	.ndo_uninit		= dummy_dev_uninit,
	.ndo_start_xmit		= dummy_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_rx_mode	= set_multicast_list,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_get_stats64	= dummy_get_stats64,
	.ndo_change_carrier	= dummy_change_carrier,
};
#endif
static void dummy_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static const struct ethtool_ops dummy_ethtool_ops = {
	.get_drvinfo            = dummy_get_drvinfo,
};

extern int dummy_done;

static void dummy_setup(struct net_device *dev)
{
	printk("%s, called\n", __func__);
	ether_setup(dev);

	/* Initialize the device structure. */
	dev->netdev_ops = &dummy_netdev_ops_container.net_device_ops;
	dev->ethtool_ops = &dummy_ethtool_ops;
	dev->destructor = free_netdev;

	/* Fill in device structure with ethernet-generic values. */
	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	dev->features	|= NETIF_F_SG | NETIF_F_FRAGLIST;
	dev->features	|= NETIF_F_ALL_TSO | NETIF_F_UFO;
	dev->features	|= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX | NETIF_F_PRIV_DATA_POOL;
	dev->features	|= NETIF_F_GSO_ENCAP_ALL | NETIF_F_CHAIN_SKB;
	dev->hw_features |= dev->features;
	dev->hw_enc_features |= dev->features;

	dev->dev_addr = kmalloc(MAX_ADDR_LEN, GFP_KERNEL);

	if (!dev->dev_addr)
		LIBLCD_ERR("kmalloc failed");

	eth_hw_addr_random(dev);
}

static int dummy_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}

#ifdef LCD_ISOLATE
static struct rtnl_link_ops_container dummy_link_ops_container __read_mostly = {
	.rtnl_link_ops = {
		.kind		= DRV_NAME,
		.setup		= dummy_setup,
		.validate	= dummy_validate,
	}
};
#else
static struct rtnl_link_ops dummy_link_ops __read_mostly = {
	.kind		= DRV_NAME,
	.setup		= dummy_setup,
	.validate	= dummy_validate,
};
/* Number of dummy devices to be set up by this module. */
module_param(numdummies, int, 0);
MODULE_PARM_DESC(numdummies, "Number of dummy pseudo devices");
#endif

#ifdef LCD_ISOLATE
static int dummy_init_one(void)
#else
static int __init dummy_init_one(void)
#endif
{
	struct net_device *dev_dummy;
	int err;

	/*
	 * we need alloc_netdev to allocate more memory for us
	 * due to alignment this might be larger that the size of net_device_container
	 */
	dev_dummy = alloc_netdev(0
			, "dummy%d", NET_NAME_UNKNOWN, dummy_setup);
	if (!dev_dummy)
		return -ENOMEM;

	dev_dummy->rtnl_link_ops = &dummy_link_ops_container.rtnl_link_ops;
	printk("Dummy allocated");
	err = register_netdevice(dev_dummy);
	printk("Register net dev returned %d", err);
	if (err < 0)
		goto err;
	return 0;

err:
	free_netdev(dev_dummy);
	return err;
}

extern int dummy_done;

#ifndef LCD_ISOLATE
static int __init dummy_init_module(void)
#else
int dummy_init_module(void)
#endif
{
	int i;
	int err = 0;

	rtnl_lock();
	err = __rtnl_link_register(&dummy_link_ops_container.rtnl_link_ops);
	if (err < 0)
		goto out;

	for (i = 0; i < numdummies && !err; i++) {
		err = dummy_init_one();
		cond_resched();
	}

	if (err < 0)
		__rtnl_link_unregister(&dummy_link_ops_container.rtnl_link_ops);

out:
	rtnl_unlock();
	return err;
}

#ifndef LCD_ISOLATE
static void __exit dummy_cleanup_module(void)
#else
void dummy_cleanup_module(void)
#endif
{
	rtnl_link_unregister(&dummy_link_ops_container.rtnl_link_ops);
}

#ifndef LCD_ISOLATE
module_init(dummy_init_module);
module_exit(dummy_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
MODULE_VERSION(DRV_VERSION);
#endif
