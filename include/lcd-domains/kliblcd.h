/* 
 * kliblcd.h - header for kliblcd.ko
 *
 * Author: Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 * This is the non-isolated code interface to the microkernel. The
 * implementation is in virt/lcd-domains/kliblcd.c.
 *
 * An LCD that runs in non-isolated code is called a klcd.
 */
#ifndef LCD_DOMAINS_KLIBLCD_H
#define LCD_DOMAINS_KLIBLCD_H

#include <lcd-domains/types.h>
#include <lcd-domains/utcb.h>
#include <linux/sched.h>

/* KLIBLCD INTERNALS -------------------------------------------------- */

struct lcd_info;

int __klcd_alloc_cptr(struct cptr_cache *cptr_cache, cptr_t *free_cptr);
void __klcd_free_cptr(struct cptr_cache *cptr_cache, cptr_t c);
int klcd_init_cptr(struct cptr_cache **c_out);
void klcd_destroy_cptr(struct cptr_cache *c);
int klcd_alloc_cptr(cptr_t *free_slot);
void klcd_free_cptr(cptr_t c);
int klcd_add_page(struct page *p, cptr_t *slot_out);
void klcd_rm_page(cptr_t slot);
int klcd_enter(void);
void klcd_exit(int retval);
int klcd_page_alloc(cptr_t *slot_out, gpa_t gpa);
int klcd_pages_alloc(cptr_t *slots_out, hpa_t *hp_base_out, 
		hva_t *hv_base_out, unsigned order);
int klcd_gfp(cptr_t *slot_out, gpa_t *gpa_out, gva_t *gva_out);
int klcd_create_sync_endpoint(cptr_t *slot_out);
int klcd_send(cptr_t endpoint);
int klcd_recv(cptr_t endpoint);
int klcd_call(cptr_t endpoint);
int klcd_reply(void);
int klcd_create(cptr_t *slot_out, gpa_t stack);
int klcd_config(cptr_t lcd, gva_t pc, gva_t sp, gpa_t gva_root);
int klcd_run(cptr_t lcd);
int klcd_cap_grant(cptr_t lcd, cptr_t src, cptr_t dest);
int klcd_cap_page_grant_map(cptr_t lcd, cptr_t page, cptr_t dest, gpa_t gpa);
void klcd_cap_delete(cptr_t slot);
int klcd_cap_revoke(cptr_t slot);
int klcd_load_module(char *mname, cptr_t mloader_endpoint, 
		struct lcd_info **mi);
void klcd_unload_module(struct lcd_info *mi, cptr_t mloader_endpoint);
int klcd_create_module_lcd(cptr_t *slot_out, char *mname, 
			cptr_t mloader_endpoint, struct lcd_info **mi);
void klcd_destroy_module_lcd(cptr_t lcd, struct lcd_info *mi,
			cptr_t mloader_endpoint);
int klcd_dump_boot_info(struct lcd_info *mi);


/* DEBUG ------------------------------------------------------------ */

#define LIBLCD_ERR(msg...) __kliblcd_err(__FILE__, __LINE__, msg)
static inline void __kliblcd_err(char *file, int lineno, char *fmt, ...)
{
	va_list args;
	printk(KERN_ERR "error in klcd (kthread 0x%p): %s:%d: error: ", 
		current, file, lineno);
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}
#define LIBLCD_MSG(msg...) __kliblcd_msg(__FILE__, __LINE__, msg)
static inline void __kliblcd_msg(char *file, int lineno, char *fmt, ...)
{
	va_list args;
	printk(KERN_ERR "msg in klcd (kthread 0x%p): %s:%d: note: ", 
		current, file, lineno);
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}
#define LIBLCD_WARN(msg...) __kliblcd_warn(__FILE__, __LINE__, msg)
static inline void __kliblcd_warn(char *file, int lineno, char *fmt, ...)
{
	va_list args;
	printk(KERN_ERR "warn in klcd (kthread 0x%p): %s:%d: warning: ", 
		current, file, lineno);
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);
}

/* KLCD-SPECIFIC STUFF -------------------------------------------------- */

struct lcd;

#define KLCD_MK_REG_ACCESS(idx)						\
extern u64 __klcd_r##idx(struct lcd *lcd);			        \
extern void __klcd_set_r##idx(struct lcd *lcd, u64 val);		\
extern cptr_t __klcd_cr##idx(struct lcd *lcd);				\
extern void __klcd_set_cr##idx(struct lcd *lcd, cptr_t val);		\
static inline u64 lcd_r##idx(void)					\
{									\
        return __klcd_r##idx(current->lcd);				\
}									\
static inline void lcd_set_r##idx(u64 val)				\
{									\
	__klcd_set_r##idx(current->lcd, val);				\
}									\
static inline cptr_t lcd_cr##idx(void)					\
{									\
        return __klcd_cr##idx(current->lcd);				\
}								        \
static inline void lcd_set_cr##idx(cptr_t val)				\
{									\
	__klcd_set_cr##idx(current->lcd, val);				\
}									
KLCD_MK_REG_ACCESS(0)
KLCD_MK_REG_ACCESS(1)
KLCD_MK_REG_ACCESS(2)
KLCD_MK_REG_ACCESS(3)
KLCD_MK_REG_ACCESS(4)
KLCD_MK_REG_ACCESS(5)
KLCD_MK_REG_ACCESS(6)
KLCD_MK_REG_ACCESS(7)

/* KLCD SPECIFICS -------------------------------------------------- */

/**
 * Put a kernel page in the caller's cspace at slot_out. The microkernel will 
 * not free such pages when the last capability to them goes away - the caller
 * is responsible for freeing them.
 *
 * (This is used for adding module pages.)
 */
int klcd_add_page(struct page *p, cptr_t *slot_out);
/**
 * Remove a kernel page from the caller's cspace at slot. This will
 * automatically revoke any capabilities that were derived. Doesn't free page.
 */
void klcd_rm_page(cptr_t slot);


/* LCD ENTER / EXIT -------------------------------------------------- */


/**
 * Thread enter lcd mode. This is required before invoking anything.
 */
static inline int lcd_enter(void)
{
	return klcd_enter();
}
/**
 * Thread exit lcd mode. This will tear down the thread's cspace, etc.
 *
 * For klcd's, the kernel thread won't die, and retval is ignored (for now).
 */
static inline void lcd_exit(int retval)
{
	return klcd_exit(retval);
}


/* LOW LEVEL PAGE ALLOC -------------------------------------------------- */


/**
 * Allocate a zero'd out page, and put the capability in slot_out. Map it
 * at gpa in the guest physical address space.
 */
static inline int lcd_page_alloc(cptr_t *slot_out, gpa_t gpa)
{
	return klcd_page_alloc(slot_out, gpa);
}
/**
 * Allocate 2**order zero'd out pages, and put capabilities in slots_out.
 * slots_out should be an array with at least 2**order slots. Returns
 * guest physical and virtual addresses of first page. (For KLCDs, the
 * guest physical and virtual will be == to the host physical and virtual.)
 */
static inline int lcd_pages_alloc(cptr_t *slots_out, gpa_t *gp_base_out, 
				gva_t *gv_base_out, unsigned order)
{
	hpa_t hp_base_out;
	hva_t hv_base_out;
	int ret;

	ret = klcd_pages_alloc(slots_out, &hp_base_out, &hv_base_out, order);
	if (ret)
		return ret;
	/*
	 * For KLCDs, gpa = hpa, gva = hva.
	 */
	*gp_base_out = __gpa(hpa_val(hp_base_out));
	*gv_base_out = __gva(hva_val(hv_base_out));

	return ret;
}

/**
 * Higher level routine to get a free page. Maps it in guest physical
 * and virtual address spaces. Returns slot and addresses.
 */
static inline int lcd_gfp(cptr_t *slot_out, gpa_t *gpa_out, gva_t *gva_out)
{
	return klcd_gfp(slot_out, gpa_out, gva_out);
}

/* IPC -------------------------------------------------- */

/**
 * Create a synchronous endpoint, capability stored in slot_out.
 */
static inline int lcd_create_sync_endpoint(cptr_t *slot_out)
{
	return klcd_create_sync_endpoint(slot_out);
}
/**
 * Synchronous send. Set message registers using lcd_set_r0(), lcd_set_r1(), 
 * etc. before calling.
 */
static inline int lcd_send(cptr_t endpoint)
{
	return klcd_send(endpoint);
}
/**
 * Synchronous recv. Set cptr registers (for receiving granted caps) using 
 * lcd_set_cr0(), lcd_set_cr1(), etc. before calling.
 */
static inline int lcd_recv(cptr_t endpoint)
{
	return klcd_recv(endpoint);
}
/**
 * Synchronous call. Blocks until callee replies on lcd's reply
 * endpoint.
 *
 * (Internally, this is a send followed by a receive.)
 */
static inline int lcd_call(cptr_t endpoint)
{
	return klcd_call(endpoint);
}
/**
 * Reply to a synchronous call.
 */
static inline int lcd_reply(void)
{
	return klcd_reply();
}

/* LCD CREATE / SETUP -------------------------------------------------- */


/**
 * Allocates lcd and does minimal initialization of hardware virtual
 * machine and lcd's cspace. Returns non-zero on error. Stack should be
 * the guest physical address where stack/utcb should be mapped (the 
 * microkernel will allocate a page for the stack/utcb - it can't trust
 * the caller, and the microkernel needs safe access to the utcb during
 * ipc).
 */
static inline int lcd_create(cptr_t *slot_out, gpa_t stack)
{
	return klcd_create(slot_out, stack);
}
/**
 * Configure lcd environment.
 *
 * For now, we assume lcd will boot with a guest virtual address space.
 *
 * Set program counter, stack pointer, and root of guest virtual page table
 * hierarchy.
 *
 * The lcd's guest physical address space is set up using 
 * lcd_cap_page_grant_map.
 *
 * The lcd's cspace is configured using lcd_cap_grant.
 */
static inline int lcd_config(cptr_t lcd, gva_t pc, gva_t sp, gpa_t gva_root)
{
	return klcd_config(lcd, pc, sp, gva_root);
}
/**
 * Runs / resumes an lcd.
 */
static inline int lcd_run(cptr_t lcd)
{
	return klcd_run(lcd);
}


/* CAPABILITIES -------------------------------------------------- */


/**
 * Grant a capability to an lcd we have created.
 *
 * Use lcd_cap_page_grant_map for granting caps to pages.
 *
 * Yes, I'm breaking from seL4 here by allowing grant to happen outside
 * of ipc.

 * It's for one special case: When the caller is
 * setting up an lcd and needs to map pages inside it, we need to put
 * capabilities to those pages in the lcd's cspace. Why? Because the microkernel
 * needs to know how to unmap those pages when they are destroyed, or rights
 * are revoked somewhere. If we didn't add capabilities to the pages when
 * setting up the new lcd, the pages could be freed, but still mapped in the 
 * lcd's guest physical address space without the microkernel being aware.
 *
 * The alternative (discussed with Anton) is to have the creator pass the
 * capabilities when the lcd is booted. This works for endpoint capabilities,
 * etc., but the microkernel can't rely on the creator for pages.
 */
static inline int lcd_cap_grant(cptr_t lcd, cptr_t src, cptr_t dest)
{
	return klcd_cap_grant(lcd, src, dest);
}
/**
 * Grant a capability to page to lcd, and map page in the lcd's guest physical
 * address space at gpa.
 */
static inline int lcd_cap_page_grant_map(cptr_t lcd, cptr_t page, cptr_t dest, 
					gpa_t gpa)
{
	return klcd_cap_page_grant_map(lcd, page, dest, gpa);
}
/**
 * Delete the capability in slot from caller's cspace.
 *
 * This may change the state of the caller. (For example, if the caller is
 * a regular lcd, and if the capability is to a page, the page will be unmapped
 * from the caller's address space.)
 *
 * If this is the last capability to the object, the object will be destroyed,
 * unless it is a kernel page. See klcd_add_page and klcd_rm_page.
 */
static inline void lcd_cap_delete(cptr_t slot)
{
	return klcd_cap_delete(slot);
}
/**
 * Revoke all derived capabilities.
 *
 * Does not delete the caller's capability.
 *
 * This may change the state of the lcd's whose capabilities are revoked (see
 * comment lcd_cap_delete).
 */
static inline int lcd_cap_revoke(cptr_t slot)
{
	return klcd_cap_revoke(slot);
}

/* CPTR CACHE -------------------------------------------------- */

/**
 * Initialize the cptr cache.
 *
 * This should be called when an lcd boots.
 */
static inline int lcd_init_cptr(void)
{
	return klcd_init_cptr(&current->cptr_cache);
}
/**
 * This should be called before an lcd exits.
 */
static inline void lcd_destroy_cptr(void)
{
	klcd_destroy_cptr(current->cptr_cache);
}
/**
 * Find an unused cptr (a cptr that refers to an unused cnode).
 */
static inline int lcd_alloc_cptr(cptr_t *free_slot)
{
	return klcd_alloc_cptr(free_slot);
}
/**
 * Return a cptr (after deleting a cnode).
 */
static inline void lcd_free_cptr(cptr_t c)
{
	return klcd_free_cptr(c);
}
/**
 * This is needed when an lcd is creating another lcd (it needs to set up
 * the other lcd's cptr cache).
 */
static inline int __lcd_alloc_cptr(struct cptr_cache *cache, 
				cptr_t *free_slot)
{
	return __klcd_alloc_cptr(cache, free_slot);
}
/**
 * Same comment as __lcd_alloc_cptr.
 */
static inline void __lcd_free_cptr(struct cptr_cache *cache, cptr_t c)
{
	return __klcd_free_cptr(cache, c);
}

/* EXTRAS -------------------------------------------------- */


/**
 * When provided with an endpoint connected to a module loader, this routine
 * will communicate with the module loader and load the module with name and
 * get capabilities to the pages that contain the module. It returns a
 * list of lcd_module_pages inside the doubly-linked list head. (The pages
 * are in this order: init pages followed by core pages.)
 *
 * The caller is responsible for freeing the list of lcd_module_page structs
 * (e.g., via lcd_unload_module).
 *
 * (For klcd's, for now anyway, the endpoint is ignored, so the null cptr
 * can be passed. The non-isolated module loading code is used.)
 */
struct lcd_module_page {
	/*
	 * cptr to page
	 */
	cptr_t cptr;
	/*
	 * guest virtual address where module page should be mapped inside
	 * lcd in order for module to work correctly without relinking
	 */
	gva_t gva;
	/*
	 * linked list of module pages
	 */
	struct list_head list;
};

struct lcd_page_info_list_elem {
	gpa_t page_gpa;
	cptr_t my_cptr;
	struct list_head list;
};

#define LCD_MODULE_NAME_MAX (64 - sizeof(unsigned long))
struct lcd_info {
	/*
	 * Module name
	 */
	char mname[LCD_MODULE_NAME_MAX];
	/*
	 * Where to point the program counter to run init
	 */
	gva_t init;
	/*
	 * List of lcd_module_pages
	 */
	struct list_head mpages_list;
	/*
	 * cptr cache
	 */
	struct cptr_cache *cache;
	/*
	 * Boot page
	 */
	char *boot_page_base;
	/*
	 * The creating lcd has a cptr to the boot page
	 */
	cptr_t boot_page_cptrs[1 << LCD_BOOT_PAGES_ORDER];
	/*
	 * Boot mem page infos
	 */
	struct list_head boot_mem_list;
	/*
	 * Paging mem page infos
	 */
	struct list_head paging_mem_list;
	/*
	 * Free mem page infos
	 */
	struct list_head free_mem_list;
};

static inline struct lcd_boot_info * to_boot_info(struct lcd_info *mi)
{
	return (struct lcd_boot_info *)mi->boot_page_base;
}

static inline int lcd_load_module(char *mname, cptr_t mloader_endpoint, 
				struct lcd_info **mi)
{
	return klcd_load_module(mname, mloader_endpoint, mi);
}
/**
 * Deletes capabilities to pages that contain module (passed as doubly-linked
 * list of lcd_module_page's). (If the caller is a klcd, this will never
 * lead to freeing the module pages.)
 *
 * Tells module loader we are done with the module. (If the caller is a klcd,
 * this is a call to the regular module loading code to delete the module.)
 */
static inline void lcd_unload_module(struct lcd_info *mi, 
				cptr_t mloader_endpoint)
{
	return klcd_unload_module(mi, mloader_endpoint);
}
/**
 * Big routine to automatically create an lcd, load a module inside it,
 * and configure it per the address space layout below. Uses lcd_load_module
 * to do so (so a klcd can pass a null cptr for the module loader endpoint),
 * and lcd_config to set up program counter, stack pointer, etc.
 *
 * Puts the new lcd in slot.
 *
 * Returns an lcd_info that contains the module's name and the list of 
 * lcd_module_pages. Call lcd_destroy_module_lcd to tear it down. So long as 
 * you don't pass the capability to any other lcd, etc., this will stop and 
 * destroy the lcd.
 *
 * Guest Physical Memory Layout
 * ============================
 *
 * No gdt/tss/idt for now (easier). See Documentation/lcd-domains/vmx.txt.
 *
 * From bottom to top,
 *
 *   -- The bottom 1 MB is unmapped / reserved in case the module is expecting 
 *      the standard physical memory layout of a PC. (Of course, it or its 
 *      creator would need to map something there to emulate that memory.) No
 *      memory mapped here for the gcc stack protector, so make sure you have
 *      that turned off when building the code for the lcd.
 *
 *   -- Guest virtual page tables come next, 4 MBs. This puts a (big) upper 
 *      limit on the size of the module that can be mapped. The page tables
 *      in the hierarchy are allocated on demand as the module is mapped.
 *
 *   -- The stack/UTCB used by the initial thread when the lcd boots. (The
 *      microkernel manages this page.)
 *
 *   -- The module itself.
 *
 *   -- A huge chunk of free/unmapped guest physical memory available to the
 *      module.
 *
 *   -- The upper part is unusable (see Intel SDM V3 28.2.2). The last
 *      usable byte is at 0x0000 FFFF FFFF FFFF.
 *
 *                   +---------------------------+ 0xFFFF FFFF FFFF FFFF
 *                   |         Unusable          |
 *                   +---------------------------+ 0x0000 FFFF FFFF FFFF
 *                   |                           |
 *                   :           Free            :
 *                   |                           |
 *                   +---------------------------+ (variable)
 *                   |                           |
 *                   :          Module           :
 *                   |                           |
 *                   +---------------------------+ 0x0000 0000 0050 2000
 *                   |        Stack/UTCB         |
 *                   |          (4 KBs)          |
 *                   +---------------------------+ 0x0000 0000 0050 1000
 *                   |        Boot Info          |
 *                   |          (4 KBs)          |
 *                   +---------------------------+ 0x0000 0000 0050 0000
 *                   | Guest Virtual Page Tables | 
 *                   |        (4 MBs max)        |
 *                   +---------------------------+ 0x0000 0000 0010 0000
 *                   |       Free / Unmapped     | 
 *                   |          (1 MB)           |
 *                   +---------------------------+ 0x0000 0000 0000 0000
 *
 * Guest Virtual Memory Layout
 * ===========================
 *
 * The lower part has the same layout as the guest physical.
 *
 * The module is mapped per the guest virtual addresses in the lcd_module_page
 * list returned from the module loader, so that relinking is unnecessary.
 * 
 *                   +---------------------------+ 0xFFFF FFFF FFFF FFFF
 *  The module       |                           |
 *  gets mapped      |        Upper Part         |
 *  somewhere in     :       (mostly free)       :
 *  here  -------->  |                           |
 *                   |                           |
 *                   +---------------------------+ 0x0000 0000 0050 1000
 *                   |        Stack/UTCB         |
 *                   |          (4 KBs)          |
 *                   +---------------------------+ 0x0000 0000 0050 2000
 *                   |        Boot info          |
 *                   |          (4 KBs)          |
 *                   +---------------------------+ 0x0000 0000 0050 0000
 *                   | Guest Virtual Page Tables | 
 *                   |        (4 MBs max)        |
 *                   +---------------------------+ 0x0000 0000 0010 0000
 *                   |       Free / Unmapped     | 
 *                   |          (1 MB)           |
 *                   +---------------------------+ 0x0000 0000 0000 0000
 *
 * Initial CSPACE
 * ==============
 *
 * The lcd's cspace will contain capabilities to the module pages and
 * guest virtual paging pages.
 */

/* Moved macros to types.h to share with liblcd code. */


static inline int lcd_create_module_lcd(cptr_t *slot_out, char *mname, 
					cptr_t mloader_endpoint, 
					struct lcd_info **mi)
{
	return klcd_create_module_lcd(slot_out, mname, mloader_endpoint,
				mi);
}

static inline void lcd_destroy_module_lcd(cptr_t lcd, struct lcd_info *mi,
					cptr_t mloader_endpoint)
{
	return klcd_destroy_module_lcd(lcd, mi, mloader_endpoint);
}

static inline int lcd_dump_boot_info(struct lcd_info *mi)
{
	return klcd_dump_boot_info(mi);
}

#endif  /* LCD_DOMAINS_KLIBLCD_H */
