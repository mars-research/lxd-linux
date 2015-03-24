/**
 * Regression tests for lcd arch code.
 */

static int test01(void)
{
	struct lcd_arch_vmcs *vmcs;
	vmcs = vmx_alloc_vmcs(raw_smp_processor_id());
	if (!vmcs) {
		LCD_ARCH_ERR("failed");
		return -1;
	}
	vmx_free_vmcs(vmcs);
	return 0;
}

static int test02(void)
{
	struct lcd_arch *lcd;
	int i;
	char *buf;
	int ret = -1;

	ret = lcd_arch_create(&lcd);
	if (ret) {
		LCD_ARCH_ERR("failed to alloc lcd");
		goto fail_alloc;
	}

	buf = (char *)lcd->ept.root;
	for (i = 0; i < PAGE_SIZE; i++) {
		if (buf[i]) {
			LCD_ARCH_ERR("nonzero in ept");
			goto out;
		}
	}		

	ret = 0;

out:
	lcd_arch_destroy(lcd);
fail_alloc:
	return ret;
}

static int test03_help(struct lcd_arch *lcd, gpa_t base)
{
	hpa_t actual;
	unsigned long off;

	for (off = 0; off < 0x40000; off += PAGE_SIZE) {
		if (lcd_arch_ept_gpa_to_hpa(lcd, gpa_add(base, off), &actual)) {
			LCD_ARCH_ERR("failed lookup at %lx",
				gpa_val(gpa_add(base, off)));
			return -1;
		}
		if (hpa_val(actual) != gpa_val(gpa_add(base, off))) {
			LCD_ARCH_ERR("expected hpa %lx got %lx\n",
				gpa_val(gpa_add(base, off)),
				hpa_val(actual));
			return -1;
		}
	}
	return 0;
}

static int test03(void)
{
	struct lcd_arch *lcd;
	gpa_t base;
	int ret = -1;

	ret = lcd_arch_create(&lcd);
	if (ret) {
		LCD_ARCH_ERR("failed to alloc lcd");
		goto fail1;
	}

	/*
	 * Map 0x0 - 0x400000 (first 4 MBs, takes two page tables)
	 */
	if (lcd_arch_ept_map_range(lcd, __gpa(0), __hpa(0), 1024)) {
		LCD_ARCH_ERR("failed to map first 4 MBs");
		goto fail3;
	}

	/*
	 * Map 0x40000000 - 0x40400000 (1GB -- 1GB + 4MBs)
	 */
	if (lcd_arch_ept_map_range(lcd, __gpa(1 << 30), __hpa(1 << 30), 1024)) {
		LCD_ARCH_ERR("failed to map 2nd 4 MBs");
		goto fail4;
	}

	/*
	 * Map 0x8000000000 - 0x8000400000 (512GB -- 512GB + 4MBs)
	 */
	if (lcd_arch_ept_map_range(lcd, __gpa(1UL << 39), 
					__hpa(1UL << 39), 1024)) {
		LCD_ARCH_ERR("failed to map 3rd 4 MBs");
		goto fail5;
	}

	/*
	 * CHECK
	 */

	base = __gpa(0);
	if (test03_help(lcd, base))
		goto fail6;
	base = __gpa(1 << 30);
	if (test03_help(lcd, base))
		goto fail6;
	base = __gpa(1UL << 39);
	if (test03_help(lcd, base))
		goto fail6;

	ret = 0;
	goto done;

done:
fail6:
	lcd_arch_ept_unmap_range(lcd, __gpa(1UL << 39), 1024);
fail5:
	lcd_arch_ept_unmap_range(lcd, __gpa(1 << 30), 1024);
fail4:
	lcd_arch_ept_unmap_range(lcd, __gpa(0), 1024);
fail3:
	lcd_arch_destroy(lcd);
fail1:
	return ret;
}

static int test04(void)
{
	struct lcd_arch *lcd;
	hva_t pgd;
	int ret = -1;
	
	/*
	 * Init lcd
	 */
	ret = lcd_arch_create(&lcd);
	if (ret) {
		LCD_ARCH_ERR("failed to create lcd");
		goto fail1;
	}
	if (lcd->vpid == 0) {
		LCD_ARCH_ERR("bad vpid");
		goto fail2;
	}
	/*
	 * Map a dummy page in the lcd's guest physical address space
	 */
	pgd = __hva(__get_free_page(GFP_KERNEL));
	if (!hva_val(pgd)) {
		LCD_ARCH_ERR("failed to alloc page");
		goto fail3;
	}
	ret = lcd_arch_ept_map(lcd, __gpa(0), hva2hpa(pgd), 1, 0);
	if (ret) {
		LCD_ARCH_ERR("error mapping pgd");
		goto fail4;
	}
	/*
	 * Set up its runtime environment
	 */
	ret = lcd_arch_set_gva_root(lcd, __gpa(0));
	if (ret) {
		LCD_ARCH_ERR("error setting gva root");
		goto fail5;
	}
	ret = lcd_arch_set_pc(lcd, __gva(0));
	if (ret) {
		LCD_ARCH_ERR("error setting pc");
		goto fail6;
	}
	ret = lcd_arch_set_sp(lcd, __gva(0));
	if (ret) {
		LCD_ARCH_ERR("error setting sp");
		goto fail7;
	}

	if (lcd_arch_check(lcd)) {
		LCD_ARCH_ERR("failed a check\n");
		goto fail8;
	}

	ret = 0;
	goto done;

done:
fail8:
fail7:
fail6:
fail5:
	lcd_arch_ept_unmap(lcd, __gpa(0));
fail4:
	free_page(hva_val(pgd));
fail3:
	lcd_arch_destroy(lcd);
fail2:
fail1:
	return ret;
}

static int test05(void)
{
	if (!vmx_addr_is_canonical(0UL)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}
	if (vmx_addr_is_canonical(1UL << 63)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}
	if (vmx_addr_is_canonical(0xFFFFUL << 48)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}
	if (!vmx_addr_is_canonical(0xFFFF8UL << 44)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}
	if (!vmx_addr_is_canonical(0x00007UL << 44)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}
	
	return 0;
}

static int test06(void)
{
	u32 width;

	width = cpuid_eax(0x80000008) & 0xff;

	if (vmx_bad_phys_addr(0xff)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}
	
	if (vmx_bad_phys_addr(1UL << (width - 1))) {
		LCD_ARCH_ERR("failed");
		return -1;
	}
	
	if (!vmx_bad_phys_addr(1UL << width)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}

	if (!vmx_bad_phys_addr(-1ULL)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}

	if (width >= 40 && vmx_bad_phys_addr(0x30682f000)) {
		LCD_ARCH_ERR("failed");
		return -1;
	}

	return 0;
}

static int main_tests(void)
{
	if (test01())
		return -1;
	if (test02())
		return -1;
	if (test03())
		return -1;
	if (test04())
		return -1;
	if (test05())
		return -1;
	if (test06())
		return -1;
	LCD_ARCH_MSG("all lcd arch main tests passed!");
	return 0;
}
