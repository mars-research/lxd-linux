#ifndef LCD_DOMAINS_LCD_DOMAINS_H
#define LCD_DOMAINS_LCD_DOMAINS_H

#include <asm/lcd-domains-arch.h>
#include <lcd-domains/utcb.h>

struct lcd {
	/*
	 * Arch-dependent state of lcd
	 */
	struct lcd_arch *lcd_arch;
	/*
	 * User thread control block. This is the data accessible
	 * inside the lcd (ipc registers, ...). Points to memory allocated by
	 * arch-dep code (inside struct lcd_arch).
	 */
	struct lcd_utcb *utcb;
	/*
	 * Guest virtual paging.
	 */
	struct {
		/*
		 * Host physical address of the root of the lcd's
		 * (initial) guest virtual paging hierarchy.
		 */
		u64 root_hpa;
		/*
		 * Pointer to start of guest physical address space 
		 * used for paging.
		 */
		u64 paging_mem_bot;
		/*
		 * Pointer to next free page in guest physical
		 * address space that can be used for a page table.
		 */
		u64 paging_mem_brk;
		/*
		 * Top of region in guest physical address space
		 * for page tables.
		 */
		u64 paging_mem_top;
	} gv;
};

#endif /* LCD_DOMAINS_LCD_DOMAINS_H */
