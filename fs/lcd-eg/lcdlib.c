/*
 * To be filled by stubs.
 */

/* include/linux/fs.h */

const char *bdevname(struct block_device *bdev, char *buffer)
{
	return NULL;
}

int inode_change_ok(const struct inode *inode, struct iattr *attr)
{
	return 0;
}

int inode_newsize_ok(const struct inode *inode, loff_t offset)
{
	return 0;
}

void setattr_copy(struct inode *inode, const struct iattr *attr)
{
}

void iget_failed(struct inode *inode)
{
}

int sb_set_blocksize(struct super_block *, int)
{
	return 0;
}

int register_filesystem(struct file_system_type *)
{
	return 0;
}

int unregister_filesystem(struct file_system_type *)
{	
	return 0;
}

void __mark_inode_dirty(struct inode *, int)
{
}

void clear_inode(struct inode *)
{
}

void drop_nlink(struct inode *inode)
{
}

void inc_nlink(struct inode *inode)
{
}

struct inode * iget_locked(struct super_block *, unsigned long)
{
	return NULL;
}

void ihold(struct inode * inode)
{
}

void iput(struct inode *)
{
}

void init_special_inode(struct inode *, umode_t, dev_t)
{
}

void inode_init_once(struct inode *)
{
}

void inode_init_owner(struct inode *inode, const struct inode *dir,
		      umode_t mode)
{
}

void __insert_inode_hash(struct inode *, unsigned long hashval)
{
}

struct inode *new_inode(struct super_block *sb)
{
	return NULL;
}

void set_nlink(struct inode *inode, unsigned int nlink)
{
}

void unlock_new_inode(struct inode *)
{
}

int generic_file_fsync(struct file *, loff_t, loff_t, int)
{
	return 0;
}

ssize_t generic_read_dir(struct file *, char __user *, size_t, loff_t *)
{
	return 0;
}

int generic_readlink(struct dentry *, char __user *, int)
{
	return 0;
}

void *page_follow_link_light(struct dentry *, struct nameidata *)
{
}

void page_put_link(struct dentry *, struct nameidata *, void *)
{
}

int page_symlink(struct inode *inode, const char *symname, int len)
{
	return 0;
}

ssize_t do_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	return 0;
}

ssize_t do_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	return 0;
}

loff_t generic_file_llseek(struct file *file, loff_t offset, int whence)
{
	return 0;
}

ssize_t generic_file_splice_read(struct file *, loff_t *,
				 struct pipe_inode_info *, size_t, unsigned int)
{
	return 0;
}

void generic_fillattr(struct inode *, struct kstat *)
{
}

void kill_block_super(struct super_block *sb)
{
}

struct dentry *mount_bdev(struct file_system_type *fs_type,
			  int flags, const char *dev_name, void *data,
			  int (*fill_super)(struct super_block *, void *, int))
{
	return NULL;
}

ssize_t generic_file_aio_read(struct kiocb *, const struct iovec *, unsigned long, loff_t)
{
	return 0;
}

ssize_t generic_file_aio_write(struct kiocb *, const struct iovec *, unsigned long, loff_t)
{
	return 0;
}

int generic_file_mmap(struct file *, struct vm_area_struct *)
{
	return 0;
}


/* include/linux/buffer_head.h */

void __lock_buffer(struct buffer_head *bh)
{
}

void mark_buffer_dirty(struct buffer_head *bh)
{
}

void mark_buffer_dirty_inode(struct buffer_head *bh, struct inode *inode)
{
}

int sync_dirty_buffer(struct buffer_head *bh)
{
	return 0;
}

void __bforget(struct buffer_head *)
{
}

int block_read_full_page(struct page*, get_block_t*)
{
	return 0;
}

int block_truncate_page(struct address_space *, loff_t, get_block_t *)
{
	return 0;
}

int block_write_begin(struct address_space *mapping, loff_t pos, unsigned len,
		      unsigned flags, struct page **pagep, get_block_t *get_block)
{
	return 0;
}

int __block_write_begin(struct page *page, loff_t pos, unsigned len,
			get_block_t *get_block)
{
	return 0;
}

int block_write_end(struct file *, struct address_space *,
		    loff_t, unsigned, unsigned,
		    struct page *, void *)
{
	return 0;
}

int block_write_full_page(struct page *page, get_block_t *get_block,
			  struct writeback_control *wbc)
{
	return 0;
}

struct buffer_head *__bread(struct block_device *, sector_t block, unsigned size)
{
	return NULL;
}

void __brelse(struct buffer_head *)
{
}

sector_t generic_block_bmap(struct address_space *, sector_t, get_block_t *)
{
	return 0;
}

int generic_write_end(struct file *, struct address_space *,
		      loff_t, unsigned, unsigned,
		      struct page *, void *)
{
	return 0;
}

struct buffer_head *__getblk(struct block_device *bdev, sector_t block,
			     unsigned size)
{
	return NULL;
}

inline void invalidate_inode_buffers(struct inode *inode)
{
}

void unlock_buffer(struct buffer_head *bh)
{
}


/* include/linux/dcache.h */

void d_instantiate(struct dentry *, struct inode *)
{
}

struct dentry * d_make_root(struct inode *)
{
	return NULL;
}

void d_rehash(struct dentry *)
{
}

/* GCC -fstack-protector */
void __stack_chk_fail(void)
{
}

/* include/linux/printk.h */

int printk(const char *s, ...)
{
	return 0;
}

int printk_ratelimit(void)
{
	return 0;
}


/* include/linux/rcuupdate.h */
void call_rcu(struct rcu_head *head,
	      void (*func)(struct rcu_head *head))
{
}

/* include/linux/rcutree.h */
void rcu_barrier(void)
{
}


/* include/linux/sched.h */
int _cond_resched(void)
{
}

/* include/linux/rwlock_api_smp.h */
void __lockfunc _raw_read_lock(rwlock_t *lock)
{
}

void __lockfunc _raw_write_lock(rwlock_t *lock)
{
}

/* include/linux/spinlock_api_smp.h */
void __lockfunc _raw_spin_lock(raw_spinlock_t *lock)
{
}

/* include/linux/highuid.h */
int fs_overflowuid = DEFAULT_FS_OVERFLOWUID; /* 65534 */
int fs_overflowgid = DEFAULT_FS_OVERFLOWUID;

/* include/linux/time.h */
unsigned long get_seconds(void)
{
	return 0;
}

/* include/linux/pagemap.h */
struct page * find_or_create_page(struct address_space *mapping,
				  pgoff_t index, gfp_t gfp_mask)
{
	return NULL;
}

void __lock_page(struct page *page)
{
}

void unlock_page(struct page *page)
{
}

struct page * read_cache_page(struct address_space *mapping,
			      pgoff_t index, filler_t *filler, void *data)
{
	return NULL;
}

/* include/linux/mm.h */
int write_one_page(struct page *page, int wait)
{
	return 0;
}

void put_page(struct page *page)
{
}

void truncate_pagecache(struct inode *inode, loff_t old, loff_t new)
{
}

void truncate_setsize(struct inode *inode, loff_t newsize)
{
}

int truncate_inode_page(struct address_space *mapping, struct page *page)
{
	return 0;
}

/* include/linux/slab.h */
struct kmem_cache *kmalloc_caches[KMALLOC_SHIFT_HIGH + 1];

void kfree(const void *)
{
}

void *__kmalloc(size_t size, gfp_t flags)
{
	return NULL;
}

void *kmem_cache_alloc(struct kmem_cache *, gfp_t)
{
	return NULL;
}

void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
	return NULL;
}

struct kmem_cache *kmem_cache_create(const char *, size_t, size_t,
				     unsigned long,
				     void (*)(void *))
{
	return NULL;
}

void kmem_cache_destroy(struct kmem_cache *)
{
}

void kmem_cache_free(struct kmem_cache *, void *)
{
}

/*
 * Implementations
 */

/* include/asm-generic/bitops/find.h */
/* ffz in asm-generic/bitops/ffz.h */
unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) | (~0UL << size);
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found:
	return result + ffz(tmp);
}

/* include/linux/bitops.h */
unsigned int __sw_hweight32(unsigned int w)
{
#ifdef ARCH_HAS_FAST_MULTIPLIER
	w -= (w >> 1) & 0x55555555;
	w =  (w & 0x33333333) + ((w >> 2) & 0x33333333);
	w =  (w + (w >> 4)) & 0x0f0f0f0f;
	return (w * 0x01010101) >> 24;
#else
	unsigned int res = w - ((w >> 1) & 0x55555555);
	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res + (res >> 4)) & 0x0F0F0F0F;
	res = res + (res >> 8);
	return (res + (res >> 16)) & 0x000000FF;
#endif
}

/* include/linux/string.h */
void *memcpy(void *dest, const void *src, size_t count)
{
	char *tmp = dest;
	const char *s = src;

	while (count--)
		*tmp++ = *s++;
	return dest;
}

int memcmp(const void *cs, const void *ct, size_t count)
{
	const unsigned char *su1, *su2;
	int res = 0;

	for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
	return res;
}

void *memset(void *s, int c, size_t count)
{
	char *xs = s;

	while (count--)
		*xs++ = c;
	return s;
}

size_t strlen(const char *s)
{
	const char *sc;

	for (sc = s; *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}

size_t strnlen(const char *s, size_t count)
{
	const char *sc;

	for (sc = s; count-- && *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}
