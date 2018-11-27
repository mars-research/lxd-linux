/*
 * vmm.c
 *
 * Code for deprivileging the host and running a simple hypervisor
 * 
 */

#include <linux/tboot.h>
#include <asm/vmx.h>
#include <asm/virtext.h>

#include <lcd_domains/types.h>
#include <asm/lcd_domains/microkernel.h>
#include <lcd_domains/microkernel.h>

#define VMM_STACK_SIZE 4096

int lcd_arch_run(struct lcd_arch *lcd_arch)
{
	int ret;

	/*
	 * Load the lcd and invalidate any cached mappings.
	 *
	 * *preemption disabled*
	 */
	vmx_get_cpu(lcd_arch);

	/*
	 * Interrupts off
	 *
	 * This is important - see Documentation/lcd-domains/vmx.txt.
	 */
	local_irq_disable();

	/*
	 * Enter lcd
	 */
	vmx_enter(lcd_arch);

	/*
	 * Check/handle nmi's, exceptions, and external interrupts *before*
	 * we re-enable interrupts.
	 */
	ret = vmx_handle_exception_interrupt(lcd_arch);
	
	/*
	 * Now turn interrupts back on.
	 */
	local_irq_enable();

	if (ret) {
		/*
		 * We exited due to an exception, nmi, or external interrupt.
		 * All done.
		 */
		goto out;
	}

	/*
	 * Handle all other exit reasons
	 *
	 * Intel SDM V3 Appendix C
	 */
	ret = vmx_handle_other_exits(lcd_arch);

out:
	/*
	 * Preemption enabled
	 */
	vmx_put_cpu(lcd_arch);	

	/*
	 * If there was an error, dump the lcd's state.
	 */
	if (ret < 0)
		lcd_arch_dump_lcd(lcd_arch);

	return ret;
}

/* RUN LOOP -------------------------------------------------- */
int icount = 0;
static int vmm_run_once(struct lcd_vmm *vmm, int *vmm_ret)
{
	int ret;

	ret = vmm_arch_run(vmm->lcd_arch);
	if (ret < 0) {
		LCD_ERR("running lcd %p", lcd);
		goto out;
	}

	switch(ret) {
	case LCD_ARCH_STATUS_PAGE_FAULT:
		LCD_ERR("page fault for vmm on CPU %d", raw_smp_processor_id());
		ret = -ENOSYS;
		goto out;
		break;
	case LCD_ARCH_STATUS_EXT_INTR:
		/*
		 * Continue
		 */
		ret = 0;
		icount++;
		goto out;
	case LCD_ARCH_STATUS_EPT_FAULT:
		LCD_ERR("ept fault");
		ret = -ENOSYS;
		goto out;
	case LCD_ARCH_STATUS_CR3_ACCESS:
		/*
		 * Continue
		 */
		ret = 0;
		goto out;
	case LCD_ARCH_STATUS_SYSCALL:
		ret = -ENOSYS; 
		goto out;
	}
	
out:
	return ret;
}

static int should_stop(struct lcd *lcd)
{
	int ret;

	/*
	 * Check our status
	 */
	switch(get_lcd_status(lcd)) {

	case LCD_STATUS_DEAD:
		/*
		 * We're dead; return 1 to signal to caller.
		 * (kthread_should_stop would also become true at some
		 * later point)
		 */
		ret = 1;
		goto out;
	case LCD_STATUS_RUNNING:
		/*
		 * The lcd should start or continue running; return 0
		 * to signal that
		 */
		ret = 0;
		goto out;
	default:
		BUG(); /* shouldn't be in any other state */
		ret = 1;
		goto out;
	}
out:
	return ret;
}

void vmm_loop(void)
{
	int ret;
	int vmm_ret = 0;
	struct lcd_vmm *vmm =  __this_cpu_read(vmm);

	/*
	 * Enter run loop, check after each iteration if we should stop
	 */
	for (;;) {
		ret = vmm_run_once(vmm, &vmm->ret);
		if (ret < 0 || should_stop(vmm)) {
			lcd_arch_dump_vmm(vmm->lcd_arch);
			vmm->ret = ret;
			return; 
		} else if (ret == 1) {
			LCD_MSG("icount is %d", icount);
			/* lcd exited */
			return;
		} else {
			/* ret = 0; continue */
#ifndef CONFIG_PREEMPT
			/*
			 * Sleep if we don't have full preemption turned on, 
			 * and someone else should have a turn.
			 */
			cond_resched();
#endif
			continue;
		}
	}
	
	/* unreachable */
}

// SWIZZLE_DEF:
//  - _NAME: name of the function
//  - _NS:   new stack, address just above top of commited region
//  - _FN:   (nested) function to call:  void _FN(void)

#define SWIZZLE_DEF_(_NAME,_NS,_FN)                                     \
  noinline void _NAME(void) {                                           \
    __asm__ volatile("movq %0, %%rdi      \n\t" /* put NS to %rdi   */  \
                     "subq $8, %%rdi      \n\t" /* fix NS address   */  \
                     "movq %%rsp, (%%rdi) \n\t" /* store sp to NS   */  \
                     "movq %%rdi, %%rsp   \n\t" /* set sp to NS     */  \
                     "call " _FN "        \n\t" /* call _FN         */  \
                     "popq %%rsp          \n\t" /* restore old sp   */  \
                     :                                                  \
                     : "m" (_NS)                                        \
                     : "memory", "cc", "rsi", "rdi");                   \
  }


/* Start executing the minimal hypervisor on a new stack */
static void __vmm_enter(void * new_stack) {

	/* Define function to enter _nested on a new stack */               
	//auto void _swizzle(void) __asm__(SWIZZLE_FN_STRING(_C));            
	SWIZZLE_DEF_(__vmm_loop, _new_stack, vmm_loop);

	/* Swizzle to continue execution of vmm_loop on 
	 * the new stack */
	__vmm_loop(); 
}

/* Prepare the EPT for the monolithic Linux kernel to 
 * run it in the VT-x non-root */
static int vmm_prepare_ept(struct lcd_vmm *vmm) {

};

/* Prepare the stack for the execution of the hypervisor
 * (VT-x root)
 */
static int vmm_alloc_stack(struct lcd_vmm *vmm) {

	vmm->stack = kmalloc(VMM_STACK_SIZE, GFP_KERNEL);
	if (!vmm->stack) {
		D_ERR("VMM stack allocation failed, cpu:%d\n", );
		return -1; 
 	}

	// Note that sizeof(void) = 1 not 8.
	vmm->stack += VMM_STACK_SIZE;
	return 0;
};

static void vmm_free_stack(struct lcd_vmm *vmm) {
	assert(vmm->stack); 
	vmm->stack -= VMM_STACK_SIZE;
    	kfree(vmm->stack);
	return; 
}

/* Enter the VT-x root mode */
static int vmm_enter(void *unused)
{
	int ret;
	struct lcd_vmm *vmm;

	vmm = __this_cpu_read(vmm);

	ret = vmm_prepare_ept(vmm); 
	if (ret) 
		goto failed; 

	ret = vmm_alloc_stack(vmm); 
	if (ret) 
		goto failed; 

	__vmm_enter(vmm->stack); 

	LCD_MSG("Entered VMM on CPU %d\n", raw_smp_processor_id());

	return vmm->ret;
failed: 
	atomic_inc(&vmm_enter_failed);
	LCD_ERR("failed to enter VMM, err = %d\n", ret);
	return -1; 
}
