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
	 * Enter lcd
	 */
	vmx_enter(lcd_arch);

	/*
	 * Check/handle nmi's, exceptions, and external interrupts *before*
	 * we re-enable interrupts.
	 */
	ret = vmx_handle_exception_interrupt(lcd_arch);
	

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

static int should_stop(struct lcd_vmm *vmm)
{
	int ret;

	/*
	 * Check our status
	 */
	switch(get_vmm_status(lcd)) {

	case LCD_STATUS_EXIT:
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

void vmm_set_entry_point(struct lcd_vmm *vmm) {

	
	return; 
};


void vmm_loop(struct lcd_vmm *vmm)
{
	int ret;
	int vmm_ret = 0;


	/* Set entry point for the host using vmm->cont */
	vmm_set_entry_point(vmm); 

	/*
	 * Load vmcs pointer on this cpu
	 */
	//vmcs_load(vmm->lcd_arch->vmcs);
	
	/*
	 * Load the lcd and invalidate any cached mappings.
	 *
	 * *preemption disabled*
	 */
	vmx_get_cpu(vmm->lcd_arch);

	/*
	 * Interrupts off
	 *
	 * This is important - see Documentation/lcd-domains/vmx.txt.
	 */
	local_irq_disable();


	/*
	 * Enter run loop, check after each iteration if we should stop
	 */
	for (;;) {
		ret = vmm_run_once(vmm, &vmm->ret);
		if (ret < 0 || vmm_should_stop(vmm)) {
			lcd_arch_dump_vmm(vmm->lcd_arch);
			vmm->ret = ret;
			goto out; 
		} else if (ret == 1) {
			LCD_MSG("icount is %d", icount);
			/* lcd exited */
			goto out;
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

out:
	/*
	 * Now turn interrupts back on.
	 */
	local_irq_enable();

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

#define SAVE_CALLEE_REGS()						\
  __asm__ volatile ("" : : : "rbx", "r12", "r13", "r14", "r15",         \
		    "memory", "cc")
struct cont_t {
  // Fields representing the code to run when the AWE is executed.
  void  *eip;
  void  *ebp;
  void  *esp;
}

/*
         static void vmm_on_alt_stack_0(void *stack,   // rdi
                                        void *fn,      // rsi
                                        void *args)    // rdx
*/
__asm__ ("      .text \n\t"
         "      .align  16                  \n\t"
         "vmm_on_alt_stack_0:               \n\t"
         " sub $8, %rdi                     \n\t"
         " mov %rsp, (%rdi)                 \n\t" // Save old ESP on new stack
         " mov %rdi, %rsp                   \n\t" // Set up new stack pointer
         " mov %rdx, %rdi                   \n\t" // Move args into rdi
         " call *%rsi                       \n\t" // Call callee (args in rdi)
         " pop %rsp                         \n\t" // Restore old ESP
         " ret                              \n\t");



typedef void (*cont_fn_t)(void *cont, void *args);


/*
 *  Create continuation saving it in cont and call the function 
 *  that is passed to us as a pointer
 *
 *  void _vmm_call_cont_direct(cont_t *cont,   // rdi
 *                             void *args,     //rsi
 *                             cont_fn_t fn)   // rdx
*/

__asm__ ("      .text \n\t"
         "      .align  16           \n\t"
         "      .globl  _vmm_call_cont_direct \n\t"
         "      .type   _vmm_call_cont_direct, @function \n\t"
         "_vmm_callcont_direct:             \n\t"
         " mov  0(%rsp), %rax        \n\t" // return address into RAX
         " mov  %rax,  0(%rdi)       \n\t" // EIP (our return address)
         " mov  %rbp,  8(%rdi)       \n\t" // EBP
         " mov  %rsp, 16(%rdi)       \n\t" // ESP+8 (after return)
         " addq $8,   16(%rdi)       \n\t"
         // cont now initialized.  Call the function
         // rdi : cont , rsi : args , rdx : fn
         " jmpq  %rdx                \n\t"
         " int3\n\t");


void vmm_enter_switch_stack(void *cont, void *args) {

	struct lcd_vmm * vmm = (struct lcd_vmm *)args;
	vmm->cont = (cont_t*) cont;

	/* Execute vmm_loop() on the new stack  
	 *
	 * _vmm_on_alt_stack_0() calls vmm_loop() on the new stack --- this stack will be 
	 * used by the hypervisor. 
	 *
	 * Inside the guest, i.e., inside dprivileged kernel we 
	 * return to the continuation we created before */

	vmm_on_alt_stack_0(vmm->stack, vmm_loop, vmm);
	return; 
};

#define CALL_CONT(_CONT,_FN,_ARG) 				\
	do { 							\
		SAVE_CALLEE_REGS();  				\
		_vmm_callcont_direct(_CONT, _ARG, _FN);		\
      	} while (0)


/* Start executing the minimal hypervisor on a new stack */
void __vmm_enter(void * new_stack) {


	/* We enter VMM in two steps
	 *
	 * First, _vmm_callcont_direct() creates a continuation allowing 
	 * the VMM to come back to guest and continue its execution at 
	 * the point after _vmm_callcont_direct() returns. 
	 *
	 * Second, inside vmm_enter_swotch_stack() we use __vmm_loop() 
	 * to switch execution to the new stack. 
	 */

	CALL_CONT(&vmm->cont, (void*) vmm, vmm_enter_switch_stack); 
	return; 
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

/* Enter the VT-x root mode. We enter the VT-x root mode on a new stack. 
 * The hypervisor will keep spinning until the kernel asks it to exit 
 * by updating the vmm data structure (setting vmm->status to EXIT), and triggering 
 * an exit into the hypervisor. */
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

	/* We enter the hypervisor and continue in the guest at vmm_enter_ack */
	__vmm_enter(vmm->stack);	

	LCD_MSG("Entered VMM on CPU %d\n", raw_smp_processor_id());

	return 0; 

failed: 
	atomic_inc(&vmm_enter_failed);
	LCD_ERR("failed to enter VMM, err = %d\n", ret);
	return -1; 
}

