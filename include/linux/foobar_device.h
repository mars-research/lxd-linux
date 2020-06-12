#ifndef _FOOBAR_DEVICE_H
#define _FOOBAR_DEVICE_H

#include <linux/spinlock.h>

typedef u64 foobar_features_t;

/* features */
#define FOOBAR_IRQ_DELAY	0x1
#define FOOBAR_SOFTIRQ_ENABLE	0x2
#define FOOBAR_ZERO_COPY	0x4
#define FOOBAR_PRIV_ALLOC	0x8
#define FOOBAR_MUTEX		0x10

/* flags */
#define FOO_LOOPBACK		0x1
#define FOO_DSTATS_UPDATED	0x2
#define FOO_SHARED_LIVE		0x4

struct foobar_device;

enum {
	FOOBAR_REGISTERED = 0x1,
	FOO_SHARED_STATE = 0x2,
};

struct foobar_device_ops {
	int			(*init)(struct foobar_device *dev);
	void			(*uninit)(struct foobar_device *dev);
	int			(*send)(struct foobar_device *dev, unsigned tag, unsigned data);
};

struct foo_stats {
	unsigned num_tx_packets;
	unsigned num_rx_packets;
};

struct foobar_device {
	char			name[32];
	char			*ext_name;
	int			nr_rqs[2];
	void			*priv;
	unsigned long		id;
	unsigned long		mem_end;
	unsigned long		mem_start;
	unsigned long		base_addr;
	int			irq;

	unsigned long		irq_count;
	unsigned long		state;
	unsigned long		shared_state;
	bool			active;

	unsigned int		flags;
	unsigned int		shared_flags;

	unsigned int		priv_flags;

	struct foo_stats	*dstats;
	foobar_features_t	features;
	foobar_features_t	hw_features;
	foobar_features_t	wanted_features;

	spinlock_t		foobar_lock;
	spinlock_t		foo_shared_lock;

	const struct foobar_device_ops *foobardev_ops;
	struct list_head	dev_list;
};

int register_foobar(struct foobar_device *dev);
void unregister_foobar(struct foobar_device *dev);
struct foobar_device *alloc_foobardev(int id, const char* name, size_t sizeof_priv);
void free_foobardev(struct foobar_device *dev);
void foobar_init_stats(struct foobar_device *dev);
int foobar_state_change(struct foobar_device *dev);
void foobar_notify(struct foobar_device *dev);


static inline void *foobardev_priv(const struct foobar_device *dev)
{
	return (char *)dev + ALIGN(sizeof(struct foobar_device), 32);
}
#endif /* _FOOBAR_DEVICE_H */
