/* 
 * liblcd.h - header for liblcd/
 *
 * Author: Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 * This is the minimal environment inside an lcd.
 *
 * This is x86_64 specific.
 */
#ifndef LCD_DOMAINS_LIBLCD_H
#define LCD_DOMAINS_LIBLCD_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>

#include <lcd-domains/types.h>
#include <lcd-domains/syscall.h>
#include <lcd-domains/utcb.h>


/* LCD REG ACCESS -------------------------------------------------- */

#ifdef CONFIG_LCD_COMPILE_FOR_SMACK

struct lcd_utcb *lcd_get_utcb(void);

#else /* !CONFIG_LCD_COMPILE_FOR_SMACK */

static inline struct lcd_utcb * lcd_get_utcb(void)
{
	struct lcd_utcb *out;
	/*
	 * The utcb is in the bottom of the stack page. All we have to
	 * do is mask off the low 12 bits to get the address.
	 */
	asm volatile(
		"movq %%rsp, %0 \n\t"
		"andq $0xFFFFFFFFFFFFF000, %0 \n\t"
		: "=g" (out)
		::);
	return out;
}

#endif /* CONFIG_LCD_COMPILE_FOR_SMACK */

#define LCD_MK_REG_ACCESS(idx)						\
static inline u64 lcd_r##idx(void)					\
{									\
	return __lcd_r##idx(lcd_get_utcb());				\
}									\
static inline void lcd_set_r##idx(u64 val)				\
{									\
	__lcd_set_r##idx(lcd_get_utcb(), val);				\
}									\
static inline cptr_t lcd_cr##idx(void)					\
{									\
        return __lcd_cr##idx(lcd_get_utcb());				\
}								        \
static inline void lcd_set_cr##idx(cptr_t val)				\
{									\
	__lcd_set_cr##idx(lcd_get_utcb(), val);				\
}									
LCD_MK_REG_ACCESS(0)
LCD_MK_REG_ACCESS(1)
LCD_MK_REG_ACCESS(2)
LCD_MK_REG_ACCESS(3)
LCD_MK_REG_ACCESS(4)
LCD_MK_REG_ACCESS(5)
LCD_MK_REG_ACCESS(6)
LCD_MK_REG_ACCESS(7)

static inline u64 lcd_debug_reg(struct lcd_utcb *utcb)			\
{									\
	return __lcd_debug_reg(lcd_get_utcb());				\
}									\
static inline void lcd_set_debug_reg(u64 val)				\
{									\
	__lcd_set_debug_reg(lcd_get_utcb(), val);			\
}									\

/* LOW LEVEL SYSCALLS -------------------------------------------------- */

/**
 * Low level syscall routines.
 */

#define __LCD_MK_SYSCALL(num)						\
static inline int lcd_syscall_##num(void)	                        \
{									\
        long ret;							\
	asm volatile(							\
		"movq $" #num ", %%rax \n\t" /* move syscall into rax */\
		"vmcall \n\t"                /* do vmcall (exit vm)   */\
		"movq %%rax, %0 \n\t"        /* get return value      */\
		: "=g" (ret)						\
		:							\
		: "rax");						\
	return (int)ret;						\
}									

#define LCD_MK_SYSCALL(name) __LCD_MK_SYSCALL(name)

LCD_MK_SYSCALL(LCD_SYSCALL_EXIT)
LCD_MK_SYSCALL(LCD_SYSCALL_SEND)
LCD_MK_SYSCALL(LCD_SYSCALL_RECV)
LCD_MK_SYSCALL(LCD_SYSCALL_CALL)
LCD_MK_SYSCALL(LCD_SYSCALL_REPLY)
LCD_MK_SYSCALL(LCD_SYSCALL_PUTCHAR)
LCD_MK_SYSCALL(LCD_SYSCALL_PAGE_ALLOC)
LCD_MK_SYSCALL(LCD_SYSCALL_PAGE_MAP)
LCD_MK_SYSCALL(LCD_SYSCALL_PAGE_UNMAP)
LCD_MK_SYSCALL(LCD_SYSCALL_CAP_DELETE)
LCD_MK_SYSCALL(LCD_SYSCALL_SYNC_EP)

#define __LCD_DO_SYSCALL(num) lcd_syscall_##num()
#define LCD_DO_SYSCALL(name) __LCD_DO_SYSCALL(name)


/* ENTER / EXIT FROM LCD -------------------------------------------------- */

/**
 * This should be called right when a thread starts executing inside an lcd.
 */
int lcd_enter(void);

/**
 * Exit from lcd with return value. Doesn't return.
 */
void __noreturn lcd_exit(int retval);


/* LOW LEVEL PAGE ALLOC -------------------------------------------------- */

/**
 * Initialize the memory subsystem.
 *
 * This should be called when the lcd boots.
 */
int lcd_mem_init(void);
/**
 * Allocate a zero'd out page, and put the capability in slot_out.
 */
int lcd_page_alloc(cptr_t *slot_out);
/**
 * Map page at guest physical address gpa.
 */
int lcd_page_map(cptr_t page, gpa_t gpa);
/**
 * Unmap page at guest physical address gpa.
 */
int lcd_page_unmap(cptr_t page, gpa_t gpa);
/**
 * Maps pages in guest virtual *and* physical address spaces.
 */
int lcd_map_pages(cptr_t *pages, gva_t *base_out, unsigned order);
/**
 * Maps page in gv and gp address spaces.
 */
int lcd_map_page(cptr_t page_cptr, gva_t *gva_out);
/**
 * Unmaps pages in gv and gp address spaces.
 */
void lcd_unmap_pages(cptr_t *pages, gva_t base, unsigned order);
/**
 * Unmaps page in gv and gp address spaces.
 */
void lcd_unmap_page(cptr_t page_cptr, gva_t page);
/**
 * Allocates 2^order pages. These will be properly mapped in gv and gp
 * address spaces (so you're done). Returns gv address of first page
 * in base_out.
 */
int lcd_alloc_pages(unsigned order, gva_t *base_out);
/**
 * One page alloc.
 */
int lcd_alloc_page(gva_t *page_out);
/**
 * Frees 2^order pages. Undoes what lcd_alloc_pages did.
 */
void lcd_free_pages(gva_t base, unsigned order);
/**
 * Frees one page.
 */
void lcd_free_page(gva_t page);
/**
 * Return struct page associated with addr. Similar to Linux's
 * virt_to_head_page (but we don't ever use compound pages).
 *
 * Necessary to satisfy slab dependency.
 */
struct page * lcd_virt_to_head_page(const void *addr);
/**
 * Return guest virtual address (as void *) associated with
 * struct page. Similar to Linux's virt_to_page.
 *
 * Necessary to satisfy slab dependency.
 */
void *lcd_page_address(const struct page *);
/**
 * Wrapper around lcd_alloc_pages.
 *
 * Necessary to satisfy slab dependency.
 */
struct page * lcd_alloc_pages_exact_node(int nid, gfp_t gfp_mask,
					unsigned order);
/**
 * Wrapper around lcd_free_pages.
 *
 * Necessary to satisfy slab dependency.
 */
void lcd_free_memcg_kmem_pages(unsigned long addr, unsigned int order);

/* IPC -------------------------------------------------- */

/**
 * Create a synchronous endpoint, capability stored in slot_out.
 */
int lcd_create_sync_endpoint(cptr_t *slot_out);
int __lcd_create_sync_endpoint(cptr_t slot);
/**
 * Synchronous send. Set message registers using lcd_set_r0(), lcd_set_r1(), 
 * etc. before calling.
 */
int lcd_send(cptr_t endpoint);
/**
 * Synchronous recv. Set cptr registers (for receiving granted caps) using 
 * lcd_set_cr0(), lcd_set_cr1(), etc. before calling.
 */
int lcd_recv(cptr_t endpoint);
/**
 * Synchronous call. Blocks until callee replies on lcd's reply
 * endpoint.
 *
 * (Internally, this is a send followed by a receive.)
 */
int lcd_call(cptr_t endpoint);
/**
 * Reply to a synchronous call.
 */
int lcd_reply(void);

/* CAPABILITIES -------------------------------------------------- */

/**
 * Delete the capability in slot from caller's cspace.
 */
void lcd_cap_delete(cptr_t slot);

/* CPTR CACHE -------------------------------------------------- */

/**
 * Initialize the cptr cache.
 *
 * This should be called when an lcd boots.
 */
int lcd_init_cptr(void);
/**
 * Find an unused cptr in the lcd's cptr cache (a cptr that refers to an 
 * unused cnode).
 */
int lcd_alloc_cptr(cptr_t *free_slot);
/**
 * Return a cptr (after deleting a capability).
 */
void lcd_free_cptr(cptr_t c);

/* MISC -------------------------------------------------- */

/**
 * Print a message to the host kernel log. Almost all printk escapes are
 * supported.
 */
void lcd_printk(char *fmt, ...);

#define LIBLCD_ERR(msg...) do {						\
		lcd_printk("error @ %s:%d: ", __FILE__, __LINE__);	\
		lcd_printk(msg);					\
		lcd_printk("end of error");				\
	} while (0)
#define LIBLCD_MSG(msg...) do {						\
		lcd_printk("msg @ %s:%d: ", __FILE__, __LINE__);	\
		lcd_printk(msg);					\
		lcd_printk("end of msg");				\
	} while (0)
#define LIBLCD_WARN(msg...) do {					\
		lcd_printk("warn @ %s:%d: ", __FILE__, __LINE__);	\
		lcd_printk(msg);					\
		lcd_printk("end of warn");				\
	} while (0)

/* BOOT INFO -------------------------------------------------- */

#ifdef CONFIG_LCD_COMPILE_FOR_SMACK

struct lcd_boot_info * lcd_get_boot_info(void);

#else /* !CONFIG_LCD_COMPILE_FOR_SMACK */

static inline struct lcd_boot_info * lcd_get_boot_info(void)
{
	return (struct lcd_boot_info *)gva_val(LCD_BOOT_PAGES_GVA);
}

#endif /* CONFIG_LCD_COMPILE_FOR_SMACK */

/* DATA STORE -------------------------------------------------- */

/* 
 * Adapted from cptrs / capabilities. I'm leaving in some of the
 * locks, though they are elided for now, in case we decide to make
 * this multithreaded in the future.
 */

/* 
 * Adapted from cptrs / capabilities.
 */
struct dstore;
struct dstore_node;

/**
 * These tags are reserved.
 */
#define LCD_DSTORE_TAG_NULL 0
#define LCD_DSTORE_TAG_DSTORE_NODE 1

/**
 * Initializes caches, etc. in data store subsystem. Should be called when
 * LCD boots, but after the slab allocator is initialized.
 */
int lcd_dstore_init(void);
/**
 * Tears down caches, etc. in data store subsystem. Should be called before
 * LCD exits (not critical right now).
 */
void lcd_dstore_exit(void);
/**
 * Sets up a data store.
 */
int lcd_dstore_init_dstore(struct dstore **out);
/**
 * Inserts object into data store. The caller can associate
 * an arbitrary integer tag with the object so that it can do basic
 * type checking. Tags 0 and 1 are reserved.
 *
 * Returns dptr where object is stored in out.
 */
int lcd_dstore_insert(struct dstore *dstore, void *object, int tag, 
		dptr_t *out);
/**
 * Removes object from data store. Unlike capabilities, does not free object
 * or do anything else; the caller is responsible for tracking that.
 *
 * Silently fails if no object is stored at d, or if d is invalid.
 */
void lcd_dstore_delete(struct dstore *dstore, dptr_t d);
/**
 * Tears down data store and frees it (so the pointer arg is invalid
 * after this call).
 */
void lcd_dstore_destroy(struct dstore *dstore);
/**
 * Look up object in dstore at d. Ensure it has tag. Returns dstore node
 * containing object in out.
 *
 * ** THIS LOCKS THE DSTORE NODE. CALL A MATCHING lcd_dstore_put TO RELEASE **
 *
 * This can be used to synchronize multiple threads that are trying to
 * look up the object and modify it.
 *
 * Returns non-zero if object not found, or if object found but has wrong
 * tag.
 */
int lcd_dstore_get(struct dstore *dstore, dptr_t d, int tag, 
		struct dstore_node **out);
/**
 * Extracts object from dstore node.
 */
void *lcd_dstore_node_object(struct dstore_node *n);
/**
 * Release the lock on the dstore object stored at d.
 */
void lcd_dstore_put(struct dstore_node *n);


/* TESTING -------------------------------------------------- */

/**
 * Runs liblcd regression tests (in liblcd/lcd/test.c).
 */
int lcd_run_tests(void);

#endif  /* LCD_DOMAINS_LIBLCD_H */
