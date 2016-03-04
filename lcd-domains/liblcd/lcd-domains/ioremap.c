
/* Temporary staging for Abhi's ioremap */

#define LCD_IOREMAP_GPA_BASE __gpa(0xc9UL << 40)
#define LCD_IOREMAP_GPA_SIZE (1UL << 24) /* 16 MB set aside for ioremap */
#define LCD_IOREMAP_GVA __gva(gpa_val(LCD_IOREMAP_GPA))

/* Bit-map to track free space in ioremap'ble address space */
#define LCD_IOREMAP_BMAP_SIZE (LCD_IOREMAP_GPA_SIZE >> PAGE_SHIFT)
static DECLARE_BITMAP(ioremap_gpa_bmap, LCD_IOREMAP_BMAP_SIZE);
static cptr_t ioremap_gpa_phys2cptr[LCD_FREE_MEM_BMAP_SIZE];

int gp_ioremap(cptr_t phys_addr, unsigned long size, gpa_t *base) 
{
	
	unsigned int slots = 0;
	unsigned int index = 0;
	int ret = 0;

	slots = size >> PAGE_SHIFT;
	index = find_first_zero_bits(ioremap_gpa_bmap, LCD_IOREMAP_BMAP_SIZE, slots);
	if(index >= LCD_IOREMAP_BMAP_SIZE) {
		lcd_printk("gpa_ioremap: exhausted memory space in GPA \n");
		return -ENOMEM;		
	}
 	
	/* Size required for mapping is figured out by the microkernel as capabilities 
 	 * are associated with their size */
	*base = gpa_add(LCD_IOREMAP_GPA_BASE, index << PAGE_SHIFT);
	ret = lcd_page_map(phys_addr, *base);
        if (ret) {
                lcd_printk("gpa_ioremap: cannot map physical address to GPA \n");
                return ret;
        }

	set_bits(index, ioremap_gpa_bmap, slots);
	ioremap_gpa_phys2cptr[index] = phys_addr;
	return ret;
}

int gp_iounmap(gpa_t phys_addr, unsigned long size)
{
	unsigned int slots = 0;
	unsigned index = 0;
	int ret = 0;

	slots = size >> PAGE_SHIFT;
	index = (gpa_val(phys_addr) - gpa_val(LCD_IOREMAP_GPA_BASE)) >> PAGE_SHIFT;
	
	if(!(gpa_val(phys_addr) >= gpa_val(LCD_IOREMAP_GPA_BASE) &&
		gpa_val(gpa_add(phys_addr, index << PAGE_SHIFT)) < 
		gpa_val(gpa_add(LCD_IOREMAP_GPA_BASE, LCD_IOREMAP_GPA_SIZE)))) {

		lcd_printk("gp_iounmap: Trying to unmap invalid region of memory \n");
		return -EFAULT;
	}	
	
	ret = lcd_page_unmap(ioremap_gpa_phys2cptr[index], phys_addr);
	if(ret) {
		lcd_printk("gp_iounmap: unmap failed \n");
	}
	clear_bits(index, ioremap_gpa_bmap, slots);	
	ioremap_gpa_phys2cptr[index] = LCD_CPTR_NULL;
	return ret; 
}
