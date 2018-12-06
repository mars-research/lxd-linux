/*
 * vmm.h
 *
 * Functions for creating and entering minimal VT-x hypervisor
 *
 */
#ifndef ASM_X86_LCD_DOMAINS_VMM_H
#define ASM_X86_LCD_DOMAINS_VMM_H

#include <lcd_domains/types.h>
#include <asm/lcd_domains/types.h>
#include <linux/slab.h>

int vmm_lcd_arch_create(struct lcd_arch **out);

#endif /* ASM_X86_LCD_DOMAINS_VMM_H */
