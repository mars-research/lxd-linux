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

typedef enum {
	EXCEPTION_BENIGN,
	EXCEPTION_CONTRIBUTORY,
	EXCEPTION_PAGE_FAULT,
} except_class_t;


static inline except_class_t exception_class(u8 vec)
{
	switch (vec) {
	case X86_TRAP_PF:
		return EXCEPTION_PAGE_FAULT;
	case X86_TRAP_DE:
	case X86_TRAP_TS:
	case X86_TRAP_NP:
	case X86_TRAP_SS:
	case X86_TRAP_GP:
		return EXCEPTION_CONTRIBUTORY;
	}

	return EXCEPTION_BENIGN;
}

static inline void vmm_pack_irq(struct pending_irq *pirq, u32 instr_len, u16 intr_type,
				 u8 vector, bool has_err, u32 ec)
{
	u32 irq = vector | intr_type | INTR_INFO_VALID_MASK;
	if (has_err)
		irq |= INTR_INFO_DELIVER_CODE_MASK;

	pirq->pending = true;
	pirq->err = ec;
	pirq->instr_len = instr_len;
	pirq->bits = irq & ~INTR_INFO_RESVD_BITS_MASK;
}

/* AB: borrow inject IRQ code from KSM */
static inline void vmm_inject_irq(struct lcd_arch *lcd_arch, u32 instr_len, u16 intr_type,
				   u8 vector, bool has_err, u32 ec)
{
	/*
	 * Queue the IRQ, no injection happens here.
	 * In case we have contributory exceptions that follow, then
	 * we overwrite the previous with the appropriate IRQ.
	 */
	if (lcd_arch->pending_irq.pending) {
		u8 prev_vec = (u8)lcd_arch->pending_irq.bits;
		BUG(prev_vec == X86_TRAP_DF);	/* FIXME: Triple fault  */

		except_class_t lhs = exception_class(prev_vec);
		except_class_t rhs = exception_class(vector);
		if ((lhs == EXCEPTION_CONTRIBUTORY && rhs == EXCEPTION_CONTRIBUTORY) ||
		    (lhs == EXCEPTION_PAGE_FAULT && rhs != EXCEPTION_BENIGN))
			return vmm_pack_irq(lcd_arch->pending_irq, 
					instr_len, 
					INTR_TYPE_HARD_EXCEPTION,
					X86_TRAP_DF, true, 0);
	}

	return vmm_pack_irq(lcd_arch->pending_irq, instr_len, intr_type, vector, has_err, ec);
}

static int vmm_handle_exception_nmi(struct lcd_arch *lcd_arch)
{
	u32 intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	u16 intr_type = intr_info & INTR_INFO_INTR_TYPE_MASK;
	u8 vector = intr_info & INTR_INFO_VECTOR_MASK;

	u32 instr_len = 0;
	if (intr_type & INTR_TYPE_HARD_EXCEPTION && vector == X86_TRAP_PF)
		__writecr2(vmcs_read(EXIT_QUALIFICATION));
	else
		instr_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);

	bool has_err = intr_info & INTR_INFO_DELIVER_CODE_MASK;
	u32 err = vmcs_read32(IDT_VECTORING_ERROR_CODE);
	vcpu_inject_irq(lcd_arch, instr_len, intr_type, vector, has_err, err);

	return 0;
}

static int vmm_handle_exit(struct lcd_arch *lcd_arch)
{
	int ret;
	int type;

	switch (lcd_arch->exit_reasn) {
	case EXIT_REASON_EXCEPTION_NMI:
		ret = vcpu_handle_exception_nmi(lcd_arch);
		break;
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		ret = vcpu_hadnle_external_int(); 
		break; 
	case EXIT_REASON_TRIPLE_FAULT: 
		ret = vcpu_handle_triplefault(); 
	case EXIT_REASON_INIT_SIGNAL:
		ret = vcpu_nop();
		break; 
	case EXIT_REASON_STARTUP_IPI:
		ret = vcpu_nop();
		break; 
	case EXIT_REASON_SMI_INTERRUPT:
	       	ret = vcpu_nop();
		break; 
	case EXIT_REASON_OTHER_SMI:
		ret = vcpu_nop(); 
		break; 
	case EXIT_REASON_PENDING_INTERRUPT:
		ret = vcpu_nop();
		break; 
	case EXIT_REASON_NMI_WINDOW:
	       	ret = vcpu_nop(); 
		break; 
	case EXIT_REASON_TASK_SWITCH
		ret = vcpu_handle_taskswitch();
		break; 
	case EXIT_REASON_CPUID:
		ret = vcpu_handle_cpuid();
		break; 
	case EXIT_REASON_GETSEC 
		ret = vcpu_nop();
		break; 
	case EXIT_REASON_HLT:
		ret = vcpu_handle_hlt();
		break;
	case EXIT_REASON_INVD:
		ret = vcpu_handle_invd();
		break; 
	case EXIT_REASON_INVLPG:
		ret = vcpu_handle_invlpg(); 
		break; 
	case EXIT_REASON_RDPMC:
		ret = vcpu_nop();
		break;
	case EXIT_REASON_RDTSC:
		ret = vcpu_handle_rdtsc(); 
		break;
	case EXIT_REASON_RSM:
		ret = vcpu_nop(); 

	case EXIT_REASON_VMCALL:
		ret = vcpu_handle_vmcall();
		break;

	case EXIT_REASON_VMCLEAR:
		ret = vcpu_handle_vmx(); 
		break

	case EXIT_REASON_VMLAUNCH:
		ret = vcpu_handle_vmx(); 
		break;

	case EXIT_REASON_VMPTRLD:
		ret = vcpu_handle_vmx()
		break;

	case EXIT_REASON_VMPTRST:
		ret = vcpu_handle_vmx(); 
		break;

	case EXIT_REASON_VMREAD:
		ret = vcpu_handle_vmx();
		break;

	case EXIT_REASON_VMRESUME: 
		ret = vcpu_handle_vmx(); 
		break;

	case EXIT_REASON_VMWRITE:
		ret = vcpu_handle_vmx();
		break;

	case EXIT_REASON_VMOFF:
		ret = vcpu_handle_vmx();
		break;

	case EXIT_REASON_VMON:
		ret = vcpu_handle_vmx(); 
		break;

	case EXIT_REASON_INVEPT:
		ret = vcpu_handle_vmx(); 
		break;

	case EXIT_REASON_INVVPID:
		ret = vcpu_handle_vmx(); 
		break;

	case EXIT_REASON_CR_ACCESS:
		ret = vcpu_handle_cr_access(); 
		break;

	case EXIT_REASON_DR_ACCESS:
		ret = vcpu_handle_dr_access(); 
		break;

	case EXIT_REASON_IO_INSTRUCTION:
		ret = vcpu_handle_io_instr(); 
		break;

	case EXIT_REASON_MSR_READ:
		ret = vcpu_handle_rdmsr(); 
		break;

	case EXIT_REASON_MSR_WRITE:
		ret = vcpu_handle_wrmsr(); 
		break;

	case EXIT_REASON_INVALID_STATE:
		ret = vcpu_handle_invalid_state(); 
		break;

	case EXIT_REASON_MSR_LOAD_FAIL:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_UNKNOWN35:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_MWAIT_INSTRUCTION:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_MONITOR_TRAP_FLAG: 
		ret = vcpu_handle_mtf();
		break;

	case EXIT_REASON_UNKNOWN38: 
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_MONITOR_INSTRUCTION:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_PAUSE_INSTRUCTION: 
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_MCE_DURING_VMENTRY:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_UNKNOWN42: 
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_TPR_BELOW_THRESHOLD: 
		ret = vcpu_handle_tpr_threshold(); 
		break;

	case EXIT_REASON_APIC_ACCESS: 
		ret = vcpu_handle_apic_access(); 
		break;

	case EXIT_REASON_EOI_INDUCED: 
		ret = vcpu_handle_eoi_induced(); 
		break;

	case EXIT_REASON_GDT_IDT_ACCESS:
		ret = vcpu_handle_gdt_idt_access(); 
		break;

	case EXIT_REASON_LDT_TR_ACCESS:
		ret = vcpu_handle_ldt_tr_access(); 
		break;

	case EXIT_REASON_EPT_VIOLATION:
		ret = vcpu_handle_ept_violation();
		break;

	case EXIT_REASON_EPT_MISCONFIG:
		ret = vcpu_handle_ept_misconfig(); 
		break;

	case EXIT_REASON_RDTSCP:
		ret = vcpu_handle_rdtscp(); 
		break;

	case EXIT_REASON_PREEMPTION_TIMER:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_WBINVD:
		ret = vcpu_handle_wbinvd(); 
		break;

	case EXIT_REASON_XSETBV:
		ret = vcpu_handle_xsetbv(); 
		break;

	case EXIT_REASON_APIC_WRITE:
		ret = vcpu_handle_apic_write(); 
		break;

	case EXIT_REASON_RDRAND:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_INVPCID:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_VMFUNC:
		ret = vcpu_handle_vmfunc(); 
		break;

	case EXIT_REASON_ENCLS:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_RDSEED:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_PML_FULL:
		ret = vcpu_handle_pml_full(); 
		break;

	case EXIT_REASON_XSAVES: 
		ret = vcpu_nop();
		break;

	case EXIT_REASON_XRSTORS:
		ret = vcpu_nop(); 
		break;

	case EXIT_REASON_PCOMMIT:
		ret = vcpu_nop(); 
		break;
	default:
		LCD_ERR("unhandled exit reason %d", lcd_arch->exit_reason);
		ret = -EIO;
		break;
	}


	/* AB: I borrow injection code from KSM */
	if (lcd_arch->pending_irq.pending) {
		bool injected = false;

		if (ilcd_arch->pending_irq.bits & INTR_INFO_DELIVER_CODE_MASK)
			injected = vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, lcd_arch->pending_irq.err) == 0;

		injected &= vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, lcd_arch->pending_irq.bits) == 0;
		if (lcd_arch->pending_irq.instr_len)
			injected &= vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, lcd_arch->pending_irq.instr_len) == 0;

		lcd_arch->pending_irq.pending = !injected;
	}

	return ret;
}

int lcd_vmm_arch_run(struct lcd_arch *lcd_arch)
{
	int ret;


	/*
	 * Enter lcd with vmlaunch/vmresume
	 */
	vmx_enter(lcd_arch);

	/*
	 * Check/handle nmi's, exceptions, and external interrupts 
	 */
	ret = vmm_handle_exit(lcd_arch);
	if (ret) {
		/*
		 * We exited due to an exception, nmi, or external interrupt.
		 * All done.
		 */
		return 0; 
	}

	/*
	 * Handle all other exit reasons
	 *
	 * Intel SDM V3 Appendix C
	 */
	//ret = vmx_handle_other_exits(lcd_arch);

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

