/* 
 * types.h
 *
 * Author: Charles Jacobsen <charlesj@cs.utah.edu>
 * Copyright: University of Utah
 *
 */
#ifndef LCD_DOMAINS_TYPES_H
#define LCD_DOMAINS_TYPES_H

#include <linux/kernel.h>
#include <asm/page.h>

/* CPTRs -------------------------------------------------- */

typedef struct { unsigned long cptr; } cptr_t;

static inline cptr_t __cptr(unsigned long cptr)
{
	return (cptr_t){ cptr };
}
static inline unsigned long cptr_val(cptr_t c)
{
	return c.cptr;
}

/*
 * Reserved cnodes:
 *
 * cptr = 0 is always null
 * cptr = 1 is the lcd's call endpoint
 * cptr = 2 points to an endpoint if the lcd did a receive, and the sender did
 *          a call (so the lcd can do a reply)
 *
 * So, if lcd A does a call on endpoint #1 and lcd B does a receive on endpoint
 * #1, the endpoint at LCD_CAP_CALL_ENDPOINT in A's cspace will be granted
 * to lcd B in B's cspace at cptr LCD_CAP_REPLY_ENDPOINT. lcd B can do a reply
 * (one time and then it's revoked).
 */
#define LCD_CPTR_NULL __cptr(0)
#define LCD_CPTR_CALL_ENDPOINT __cptr(1)
#define LCD_CPTR_REPLY_ENDPOINT __cptr(2)

static inline int cptr_is_null(cptr_t c)
{
	return cptr_val(c) == cptr_val(LCD_CPTR_NULL);
}

#define LCD_CPTR_DEPTH_BITS  2    /* max depth of 3, zero indexed         */
#define LCD_CPTR_FANOUT_BITS 2    /* each level fans out by a factor of 4 */
#define LCD_CPTR_SLOT_BITS   2    /* each node contains 4 cap slots       */
#define LCD_CNODE_TABLE_NUM_SLOTS ((1 << LCD_CPTR_SLOT_BITS) + \
					(1 << LCD_CPTR_FANOUT_BITS))
#define LCD_CPTR_LEVEL_SHIFT (((1 << LCD_CPTR_DEPTH_BITS) - 1) * \
				LCD_CPTR_FANOUT_BITS + LCD_CPTR_SLOT_BITS)

static inline unsigned long lcd_cptr_slot(cptr_t c)
{
	/*
	 * Mask off low bits
	 */ 
	return cptr_val(c) & ((1 << LCD_CPTR_SLOT_BITS) - 1);
}

/* 
 * Gives fanout index for going *from* lvl to lvl + 1, where 
 * 0 <= lvl < 2^LCD_CPTR_DEPTH_BITS - 1 (i.e., we can't go anywhere
 * if lvl = 2^LCD_CPTR_DEPTH_BITS - 1, because we are at the deepest
 * level).
 */
static inline unsigned long lcd_cptr_fanout(cptr_t c, int lvl)
{
	unsigned long i;

	i = cptr_val(c);
	/*
	 * Shift and mask off bits at correct section
	 */
	i >>= (lvl * LCD_CPTR_FANOUT_BITS + LCD_CPTR_SLOT_BITS);
	i &= ((1 << LCD_CPTR_FANOUT_BITS) - 1);

	return i;
}
/*
 * Gives depth/level of cptr, zero indexed (0 means the root cnode table)
 */
static inline unsigned long lcd_cptr_level(cptr_t c)
{
	unsigned long i;

	i = cptr_val(c);
	/*
	 * Shift and mask
	 */
	i >>= LCD_CPTR_LEVEL_SHIFT;
	i &= ((1 << LCD_CPTR_DEPTH_BITS) - 1);

	return i;
}

/* CPTR CACHE -------------------------------------------------- */

struct cptr_cache {
	unsigned long *bmaps[1 << LCD_CPTR_DEPTH_BITS];
};

/* ADDRESS SPACE TYPES ---------------------------------------- */

/* XXX: Assumes host and guest run in 64-bit mode */

typedef struct { unsigned long gva; } gva_t;
typedef struct { unsigned long hva; } hva_t;
typedef struct { unsigned long gpa; } gpa_t;
typedef struct { unsigned long hpa; } hpa_t;

static inline gva_t __gva(unsigned long gva)
{
	return (gva_t){ gva };
}
static inline unsigned long gva_val(gva_t gva)
{
	return gva.gva;
}
static inline unsigned long * gva_ptr(gva_t * gva)
{
	return &(gva->gva);
}
static inline gva_t gva_add(gva_t gva, unsigned long off)
{
	return __gva(gva_val(gva) + off);
}
static inline hva_t __hva(unsigned long hva)
{
	return (hva_t){ hva };
}
static inline unsigned long hva_val(hva_t hva)
{
	return hva.hva;
}
static inline unsigned long * hva_ptr(hva_t * hva)
{
	return &(hva->hva);
}
static inline hva_t hva_add(hva_t hva, unsigned long off)
{
	return __hva(hva_val(hva) + off);
}
static inline gpa_t __gpa(unsigned long gpa)
{
	return (gpa_t){ gpa };
}
static inline unsigned long gpa_val(gpa_t gpa)
{
	return gpa.gpa;
}
static inline unsigned long * gpa_ptr(gpa_t * gpa)
{
	return &(gpa->gpa);
}
static inline gpa_t gpa_add(gpa_t gpa, unsigned long off)
{
	return __gpa(gpa_val(gpa) + off);
}
static inline hpa_t __hpa(unsigned long hpa)
{
	return (hpa_t){ hpa };
}
static inline unsigned long hpa_val(hpa_t hpa)
{
	return hpa.hpa;
}
static inline unsigned long * hpa_ptr(hpa_t * hpa)
{
	return &(hpa->hpa);
}
static inline hpa_t hpa_add(hpa_t hpa, unsigned long off)
{
	return __hpa(hpa_val(hpa) + off);
}
static inline hpa_t pa2hpa(unsigned long pa)
{
	return (hpa_t){ pa };
}
static inline hpa_t va2hpa(void *va)
{
	return (hpa_t){ __pa(va) };
}
static inline void * hpa2va(hpa_t hpa)
{
	return __va(hpa_val(hpa));
}
static inline hva_t hpa2hva(hpa_t hpa)
{
	return (hva_t){ (unsigned long)__va(hpa.hpa) };
}
static inline void * hva2va(hva_t hva)
{
	return (void *)hva_val(hva);
}
static inline hva_t va2hva(void *va)
{
	return __hva((unsigned long)va);
}
static inline hpa_t hva2hpa(hva_t hva)
{
	return (hpa_t){ (unsigned long)__pa(hva2va(hva)) };
}

/* BOOT ADDRESS SPACE & INFO ------------------------------------------- */

#define LCD_BOOT_PAGES_ORDER 2

#define LCD_GV_PAGING_MEM_GPA __gpa(1 << 20)
#define LCD_GV_PAGING_MEM_SIZE (4 << 20)
#define LCD_BOOT_PAGES_GPA gpa_add(LCD_GV_PAGING_MEM_GPA, \
					LCD_GV_PAGING_MEM_SIZE)
#define LCD_BOOT_PAGES_SIZE ((1 << LCD_BOOT_PAGES_ORDER) * (4 << 10))
#define LCD_STACK_GPA gpa_add(LCD_BOOT_PAGES_GPA, LCD_BOOT_PAGES_SIZE)
#define LCD_STACK_SIZE (4 << 10)
#define LCD_MODULE_GPA gpa_add(LCD_STACK_GPA, LCD_STACK_SIZE)
#define LCD_GV_PAGING_MEM_GVA __gva(gpa_val(LCD_GV_PAGING_MEM_GPA))
#define LCD_BOOT_PAGES_GVA __gva(gpa_val(LCD_BOOT_PAGES_GPA))
#define LCD_STACK_GVA __gva(gpa_val(LCD_STACK_GPA))

#define LCD_NUM_BOOT_CPTRS 8

struct lcd_boot_info_for_page {
	cptr_t my_cptr;
	gpa_t page_gpa;
};

/* 
 * Hack for now to make boot easier, used in liblcd/lcd/cap.c for cptr
 * cache.
 */

#define LCD_BMAP0_SIZE (1 << (LCD_CPTR_SLOT_BITS + 0 * LCD_CPTR_FANOUT_BITS))
#define LCD_BMAP1_SIZE (1 << (LCD_CPTR_SLOT_BITS + 1 * LCD_CPTR_FANOUT_BITS))
#define LCD_BMAP2_SIZE (1 << (LCD_CPTR_SLOT_BITS + 2 * LCD_CPTR_FANOUT_BITS))
#define LCD_BMAP3_SIZE (1 << (LCD_CPTR_SLOT_BITS + 3 * LCD_CPTR_FANOUT_BITS))

#define LCD_BMAP0_NUM_LONGS BITS_TO_LONGS(LCD_BMAP0_SIZE)
#define LCD_BMAP1_NUM_LONGS BITS_TO_LONGS(LCD_BMAP1_SIZE)
#define LCD_BMAP2_NUM_LONGS BITS_TO_LONGS(LCD_BMAP2_SIZE)
#define LCD_BMAP3_NUM_LONGS BITS_TO_LONGS(LCD_BMAP3_SIZE)

struct lcd_boot_info {
	/*
	 * Bootstrap cptr cache --------------------
	 *
	 * level 0
	 */
	unsigned long bmap0[LCD_BMAP0_NUM_LONGS];
	/* level 1 */
	unsigned long bmap1[LCD_BMAP1_NUM_LONGS];
	/* level 2 */
	unsigned long bmap2[LCD_BMAP2_NUM_LONGS];
	/* level 3 */
	unsigned long bmap3[LCD_BMAP3_NUM_LONGS];
	/*
	 * Bootstrap page info --------------------
	 */
	unsigned num_boot_mem_pi;
	unsigned num_paging_mem_pi;
	unsigned num_free_mem_pi;
	struct lcd_boot_info_for_page *boot_mem_pi_start;
	struct lcd_boot_info_for_page *paging_mem_pi_start;
	struct lcd_boot_info_for_page *free_mem_pi_start;
	/*
	 * Other capabilities (e.g., endpoints)
	 */
	cptr_t cptrs[LCD_NUM_BOOT_CPTRS];
};

#endif   /* LCD_DOMAINS_TYPES_H */
