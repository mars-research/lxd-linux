#ifndef _FOOBAR_DEVICE_H
#define _FOOBAR_DEVICE_H

#include <linux/spinlock.h>

typedef u64 foobar_features_t;

/* features */
#define FOOBAR_IRQ_DELAY	(1 << 10)
#define FOOBAR_SOFTIRQ_ENABLE	(1 << 11)
#define FOOBAR_ZERO_COPY	(1 << 12)
#define FOOBAR_PRIV_ALLOC	(1 << 13)

/* flags */
#define FOO_LOOPBACK		4

struct foobar_device;

enum {
	FOOBAR_REGISTERED,
};

struct foobar_device_ops {
	int			(*init)(struct foobar_device *dev);
	void			(*uninit)(struct foobar_device *dev);
};

struct foo_stats {
	unsigned num_tx_packets;
	unsigned num_rx_packets;
};

struct foobar_device {
	char			name[32];
	unsigned long		id;
	unsigned long		mem_end;
	unsigned long		mem_start;
	unsigned long		base_addr;
	int			irq;

	unsigned long		state;

	unsigned int		flags;
	unsigned int		priv_flags;

	struct foo_stats	*dstats;
	foobar_features_t	features;
	foobar_features_t	hw_features;
	foobar_features_t	wanted_features;

	spinlock_t		foobar_lock;

	const struct foobar_device_ops *foobardev_ops;
};

int register_foobar(struct foobar_device *dev);
void unregister_foobar(struct foobar_device *dev);
struct foobar_device *alloc_foobardev(int id, const char* name);
void free_foobardev(struct foobar_device *dev);

#endif /* _FOOBAR_DEVICE_H */
