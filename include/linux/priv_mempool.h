#ifndef PRIV_MEMPOOL_H
#define PRIV_MEMPOOL_H

#define MTU                     1470
#define HEADERS			42
#define SKB_LCD_MEMBERS_SZ	48
#define SKB_SHARED_INFO         (sizeof(struct skb_shared_info))
#define DATA_ALIGNED_SZ		(SKB_DATA_ALIGN(MTU + HEADERS + SKB_LCD_MEMBERS_SZ))
#define SKB_DATA_SIZE		(DATA_ALIGNED_SZ + SKB_DATA_ALIGN(SKB_SHARED_INFO))

struct object {
	struct object *next;
};

struct bundle {
	struct object *list;
	struct bundle *next;
};

struct atom {
	struct bundle *head;
	long version;
} __attribute__((aligned(16)));

typedef struct {
	unsigned int total_pages;
	unsigned int obj_size;
	unsigned int total_objs;
	unsigned int num_objs_percpu;
	void *base;
	struct atom stack;
	spinlock_t pool_spin_lock;
	bool dump_once;
	struct dentry *pstats;

	struct object __percpu **head;
	struct object __percpu **marker;
	int __percpu *cached;
} priv_pool_t;


void *priv_alloc(priv_pool_t *pool);
void priv_free(priv_pool_t *pool, void *obj);

priv_pool_t *priv_pool_init(void *pool_base, size_t pool_size,
		unsigned int obj_size, const char* name);

void priv_pool_destroy(priv_pool_t *p);

#endif /* PRIV_MEMPOOL_H */
