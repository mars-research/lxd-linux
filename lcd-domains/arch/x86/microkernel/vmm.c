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

/* EPT Memory type  */
#define EPT_MT_UNCACHABLE		0
#define EPT_MT_WRITECOMBINING		1
#define EPT_MT_WRITETHROUGH		4
#define EPT_MT_WRITEPROTECTED		5
#define EPT_MT_WRITEBACK		6
#define EPT_MT_UNCACHED			7

/* EPT Access bits  */
#define EPT_ACCESS_NONE			0
#define EPT_ACCESS_READ			0x1
#define EPT_ACCESS_WRITE		0x2
#define EPT_ACCESS_RW			(EPT_ACCESS_READ | EPT_ACCESS_WRITE)
#define EPT_ACCESS_EXEC			0x4
#define EPT_ACCESS_RX			(EPT_ACCESS_READ | EPT_ACCESS_EXEC)
#define EPT_ACCESS_RWX			(EPT_ACCESS_RW | EPT_ACCESS_EXEC)
#define EPT_ACCESS_ALL			EPT_ACCESS_RWX

/* Accessed dirty flags  */
#define EPT_ACCESSED			0x100
#define EPT_DIRTY			0x200


#if 0
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

#endif

static char *vmm_exit_to_str(struct lcd_arch *lcd_arch) {
	switch (lcd_arch->exit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		return "EXIT_REASON_EXCEPTION_NMI";
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		return "EXIT_REASON_EXTERNAL_INTERRUPT";
	case EXIT_REASON_TRIPLE_FAULT:
		return "EXIT_REASON_TRIPLE_FAULT"; 
	case EXIT_REASON_INIT_SIGNAL:
		return "EXIT_REASON_INIT_SIGNAL";
	case EXIT_REASON_STARTUP_IPI:
		return "EXIT_REASON_STARTUP_IPI";
	case EXIT_REASON_SMI_INTERRUPT:
		return "EXIT_REASON_SMI_INTERRUPT";
	case EXIT_REASON_OTHER_SMI:
		return "EXIT_REASON_OTHER_SMI";
	case EXIT_REASON_PENDING_INTERRUPT:
		return "EXIT_REASON_PENDING_INTERRUPT";
	case EXIT_REASON_NMI_WINDOW:
		return "EXIT_REASON_NMI_WINDOW";
	case EXIT_REASON_TASK_SWITCH:
		return "EXIT_REASON_TASK_SWITCH"; 
	case EXIT_REASON_CPUID:
		return "EXIT_REASON_CPUID";
	case EXIT_REASON_GETSEC:
		return "EXIT_REASON_GETSEC";	
	case EXIT_REASON_HLT:
		return "EXIT_REASON_HLT";
	case EXIT_REASON_INVD:
		return "EXIT_REASON_INVD";
	case EXIT_REASON_INVLPG:
		return "EXIT_REASON_INVLPG";
	case EXIT_REASON_RDPMC:
		return "EXIT_REASON_RDPMC";
	case EXIT_REASON_RDTSC:
		return "EXIT_REASON_RDTSC";
	case EXIT_REASON_RSM:
		return "EXIT_REASON_RSM";
	case EXIT_REASON_VMCALL:
		return "EXIT_REASON_VMCALL";
	case EXIT_REASON_VMCLEAR:
		return "EXIT_REASON_VMCLEAR";
	case EXIT_REASON_VMLAUNCH:
		return "EXIT_REASON_VMLAUNCH";
	case EXIT_REASON_VMPTRLD:
		return "EXIT_REASON_VMPTRLD";
	case EXIT_REASON_VMPTRST:
		return "EXIT_REASON_VMPTRST";
	case EXIT_REASON_VMREAD:
		return "EXIT_REASON_VMREAD";
	case EXIT_REASON_VMRESUME:
		return "EXIT_REASON_VMRESUME"; 
	case EXIT_REASON_VMWRITE:
		return "EXIT_REASON_VMWRITE";
	case EXIT_REASON_VMOFF:
		return "EXIT_REASON_VMOFF";
	case EXIT_REASON_VMON:
		return "EXIT_REASON_VMON";
	case EXIT_REASON_INVEPT:
		return "EXIT_REASON_INVEPT";
	case EXIT_REASON_INVVPID:
		return "EXIT_REASON_INVVPID";
	case EXIT_REASON_CR_ACCESS:
		return "EXIT_REASON_CR_ACCESS";
	case EXIT_REASON_DR_ACCESS:
		return "EXIT_REASON_DR_ACCESS";
	case EXIT_REASON_IO_INSTRUCTION:
		return "EXIT_REASON_IO_INSTRUCTION";
	case EXIT_REASON_MSR_READ:
		return "EXIT_REASON_MSR_READ";
	case EXIT_REASON_MSR_WRITE:
		return "EXIT_REASON_MSR_WRITE";
	case EXIT_REASON_INVALID_STATE:
		return "EXIT_REASON_INVALID_STATE";
	case EXIT_REASON_MSR_LOAD_FAIL:
		return "EXIT_REASON_MSR_LOAD_FAIL";
	case EXIT_REASON_UNKNOWN35:
		return "EXIT_REASON_UNKNOWN35";
	case EXIT_REASON_MWAIT_INSTRUCTION:
		return "EXIT_REASON_MWAIT_INSTRUCTION";
	case EXIT_REASON_MONITOR_TRAP_FLAG:
		return "EXIT_REASON_MONITOR_TRAP_FLAG"; 
	case EXIT_REASON_UNKNOWN38:
		return "EXIT_REASON_UNKNOWN38"; 
	case EXIT_REASON_MONITOR_INSTRUCTION:
		return "EXIT_REASON_MONITOR_INSTRUCTION";
	case EXIT_REASON_PAUSE_INSTRUCTION:
		return "EXIT_REASON_PAUSE_INSTRUCTION"; 
	case EXIT_REASON_MCE_DURING_VMENTRY:
		return "EXIT_REASON_MCE_DURING_VMENTRY";
	case EXIT_REASON_UNKNOWN42:
		return "EXIT_REASON_UNKNOWN42"; 
	case EXIT_REASON_TPR_BELOW_THRESHOLD:
		return "EXIT_REASON_TPR_BELOW_THRESHOLD"; 
	case EXIT_REASON_APIC_ACCESS:
		return "EXIT_REASON_APIC_ACCESS"; 
	case EXIT_REASON_EOI_INDUCED:
		return "EXIT_REASON_EOI_INDUCED"; 
	case EXIT_REASON_GDT_IDT_ACCESS:
		return "EXIT_REASON_GDT_IDT_ACCESS";
	case EXIT_REASON_LDT_TR_ACCESS:
		return "EXIT_REASON_LDT_TR_ACCESS";
	case EXIT_REASON_EPT_VIOLATION:
		return "EXIT_REASON_EPT_VIOLATION";
	case EXIT_REASON_EPT_MISCONFIG:
		return "EXIT_REASON_EPT_MISCONFIG";
	case EXIT_REASON_RDTSCP:
		return "EXIT_REASON_RDTSCP";
	case EXIT_REASON_PREEMPTION_TIMER:
		return "EXIT_REASON_PREEMPTION_TIMER";
	case EXIT_REASON_WBINVD:
		return "EXIT_REASON_WBINVD";
	case EXIT_REASON_XSETBV:
		return "EXIT_REASON_XSETBV";
	case EXIT_REASON_APIC_WRITE:
		return "EXIT_REASON_APIC_WRITE";
	case EXIT_REASON_RDRAND:
		return "EXIT_REASON_RDRAND";
	case EXIT_REASON_INVPCID:
		return "EXIT_REASON_INVPCID";
	case EXIT_REASON_VMFUNC:
		return "EXIT_REASON_VMFUNC";
	case EXIT_REASON_ENCLS:
		return "EXIT_REASON_ENCLS";
	case EXIT_REASON_RDSEED:
		return "EXIT_REASON_RDSEED";
	case EXIT_REASON_PML_FULL:
		return "EXIT_REASON_PML_FULL";
	case EXIT_REASON_XSAVES:
		return "EXIT_REASON_XSAVES"; 
	case EXIT_REASON_XRSTORS:
		return "EXIT_REASON_XRSTORS";
	case EXIT_REASON_PCOMMIT:
		return "EXIT_REASON_PCOMMIT";
	default:
		return "unknown";
	}

	return "shouldn't happen";
};

static int vcpu_nop(struct lcd_arch *lcd_arch)
{
	LCD_ERR("Unhandled VT-x exit:%d (%s)\n", 
			lcd_arch->exit_reason, vmm_exit_to_str(lcd_arch));
	return -1;
}

static inline void vcpu_advance_rip(struct lcd_arch *lcd_arch)
{
/*	if (lcd_arch->eflags & X86_EFLAGS_TF) {
		vcpu_inject_hardirq_noerr(vcpu, X86_TRAP_DB);
		if (vcpu_probe_cpl(0)) {
			__writedr(6, __readdr(6) | DR6_BS | DR6_RTM);
			__writedr(7, __readdr(7) & ~DR7_GD);

			u64 dbg = vmcs_read64(GUEST_IA32_DEBUGCTL);
			vmcs_write64(GUEST_IA32_DEBUGCTL, dbg & ~DEBUGCTLMSR_LBR);
		}
	}
*/

	lcd_arch->regs.rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs_writel(GUEST_RIP, lcd_arch->regs.rip);

/*	
	size_t interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO,
		   interruptibility & ~(GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI));
*/		   
}


static int vmm_handle_cpuid(struct lcd_arch *lcd_arch)
{
	int cpuid[4];
	int func = (int)lcd_arch->regs.rax;
	int subf = (int)lcd_arch->regs.rcx;

	__cpuidex(cpuid, func, subf);

	lcd_arch->regs.rax = cpuid[0];
	lcd_arch->regs.rbx = cpuid[1];
	lcd_arch->regs.rcx = cpuid[2];
	lcd_arch->regs.rdx = cpuid[3];

	vmm_advance_rip(lcd_arch);

	return 0;
}

static int vcpu_handle_vmx(struct lcd_arch *lcd_arch)
{
	/* Handle VMX similar to SimpleVizor */

	/* Set the CF flag, which is how VMX instructions indicate failure */
	lcd_arch->regs.rflags |= 0x1; // VM_FAIL_INVALID

	/* RFLAGs is actually restored from the VMCS, so update it here */

	vmcs_writel(GUEST_RFLAGS, lcd_arch->regs.rflags);
	
	vmm_advance_rip(lcd_arch);
	return 0;
}

static int vmm_handle_wbinvd(struct lcd_arch *lcd_arch)
{
	__wbinvd();
	vmm_advance_rip(lcd_arch);
	return 0;
}

static int vmm_handle_xsetbv(struct lcd_arch *lcd_arch)
{
	u32 ext = ksm_read_reg32(vcpu, STACK_REG_CX);
	u64 val = ksm_combine_reg64(vcpu, STACK_REG_AX, STACK_REG_DX);

	/* Simply issue the XSETBV instruction on the native logical processor */
	_xsetbv((u32)lcd_arch->regs.rcx, 
		lcd_arch->regs.rdx << 32 | lcd_arch->regs.rax);

	vmm_advance_rip(lcd_arch);
	return true;
}

static int vmm_handle_exit(struct lcd_arch *lcd_arch)
{
	int ret;
	int type;

	switch (lcd_arch->exit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		//ret = vcpu_handle_exception_nmi(lcd_arch);
		ret = vcpu_nop(lcd_arch);
		break;
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		//ret = vcpu_hadnle_external_int(); 
		ret = vcpu_nop(lcd_arch);
		break; 
	case EXIT_REASON_TRIPLE_FAULT: 
		//ret = vcpu_handle_triplefault(); 
		ret = vcpu_nop(lcd_arch);
	case EXIT_REASON_INIT_SIGNAL:
		ret = vcpu_nop(lcd_arch);
		break; 
	case EXIT_REASON_STARTUP_IPI:
		ret = vcpu_nop(lcd_arch);
		break; 
	case EXIT_REASON_SMI_INTERRUPT:
	       	ret = vcpu_nop(lcd_arch);
		break; 
	case EXIT_REASON_OTHER_SMI:
		ret = vcpu_nop(lcd_arch); 
		break; 
	case EXIT_REASON_PENDING_INTERRUPT:
		ret = vcpu_nop(lcd_arch);
		break; 
	case EXIT_REASON_NMI_WINDOW:
	       	ret = vcpu_nop(lcd_arch); 
		break; 
	case EXIT_REASON_TASK_SWITCH
		//ret = vcpu_handle_taskswitch();
		ret = vcpu_nop(lcd_arch); 

		break; 
	case EXIT_REASON_CPUID:
		ret = vmm_handle_cpuid();
		break; 
	case EXIT_REASON_GETSEC 
		ret = vcpu_nop(lcd_arch);
		break; 
	case EXIT_REASON_HLT:
		//ret = vcpu_handle_hlt();
		ret = vcpu_nop(lcd_arch); 

		break;
	case EXIT_REASON_INVD:
		ret = vmm_handle_invd();
		break; 
	case EXIT_REASON_INVLPG:
		// ret = vcpu_handle_invlpg(); 
		ret = vcpu_nop(lcd_arch); 
		break; 
	case EXIT_REASON_RDPMC:
		ret = vcpu_nop(lcd_arch);
		break;
	case EXIT_REASON_RDTSC:
		ret = vcpu_handle_rdtsc(); 
		break;
	case EXIT_REASON_RSM:
		ret = vcpu_nop(lcd_arch); 

	case EXIT_REASON_VMCALL:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME: 
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMOFF:
	case EXIT_REASON_VMON:
		ret = vmm_handle_vmx(); 
		break;

	case EXIT_REASON_INVEPT:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_INVVPID:
		ret =  vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_CR_ACCESS:
		//ret = vcpu_handle_cr_access(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_DR_ACCESS:
		//ret = vcpu_handle_dr_access(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_IO_INSTRUCTION:
		//ret = vcpu_handle_io_instr(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_MSR_READ:
		//ret = vcpu_handle_rdmsr(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_MSR_WRITE:
		//ret = vcpu_handle_wrmsr(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_INVALID_STATE:
		//ret = vcpu_handle_invalid_state(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_MSR_LOAD_FAIL:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_UNKNOWN35:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_MWAIT_INSTRUCTION:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_MONITOR_TRAP_FLAG: 
		//ret = vcpu_handle_mtf();
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_UNKNOWN38: 
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_MONITOR_INSTRUCTION:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_PAUSE_INSTRUCTION: 
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_MCE_DURING_VMENTRY:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_UNKNOWN42: 
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_TPR_BELOW_THRESHOLD: 
		//ret = vcpu_handle_tpr_threshold(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_APIC_ACCESS: 
		//ret = vcpu_handle_apic_access(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_EOI_INDUCED: 
		//ret = vcpu_handle_eoi_induced();
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_GDT_IDT_ACCESS:
		//ret = vcpu_handle_gdt_idt_access(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_LDT_TR_ACCESS:
		//ret = vcpu_handle_ldt_tr_access(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_EPT_VIOLATION:
		//ret = vcpu_handle_ept_violation();
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_EPT_MISCONFIG:
		//ret = vcpu_handle_ept_misconfig(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_RDTSCP:
		//ret = vcpu_handle_rdtscp(); 
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_PREEMPTION_TIMER:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_WBINVD:
		ret = vcpu_handle_wbinvd(); 
		break;

	case EXIT_REASON_XSETBV:
		ret = vcpu_handle_xsetbv(); 
		break;

	case EXIT_REASON_APIC_WRITE:
		//ret = vcpu_handle_apic_write(); 
		break;

	case EXIT_REASON_RDRAND:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_INVPCID:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_VMFUNC:
		ret = vcpu_handle_vmfunc(); 
		break;

	case EXIT_REASON_ENCLS:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_RDSEED:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_PML_FULL:
		//ret = vcpu_handle_pml_full(); 
		ret = vcpu_nop(lcd_arch); 

		break;

	case EXIT_REASON_XSAVES: 
		ret = vcpu_nop(lcd_arch);
		break;

	case EXIT_REASON_XRSTORS:
		ret = vcpu_nop(lcd_arch); 
		break;

	case EXIT_REASON_PCOMMIT:
		ret = vcpu_nop(lcd_arch); 
		break;
	default:
		LCD_ERR("unhandled exit reason %d", lcd_arch->exit_reason);
		ret = -EIO;
		break;
	}

#if 0
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
#endif
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


static int should_stop(struct lcd_vmm *vmm)
{
	if (vmm->should_stop)
		return 1;
	return 0;
}

void vmm_set_entry_point(struct lcd_vmm *vmm) {

	lcd_arch->regs.rsp = lcd_arch->

	return; 
};


void vmm_loop(struct lcd_vmm *vmm)
{
	int ret;
	int vmm_ret = 0;
	int entry_count = 0;


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

	vmx_setup_vmcs(lcd_arch);
	vmx_enable_ept_switching(lcd_arch);

	/*
	 * Interrupts off
	 *
	 * This is important - see Documentation/lcd-domains/vmx.txt.
	 */
	local_irq_disable();


	/*
	 * Enter the infinite loop, check after each iteration if we should stop
	 */
	for (;;) {

		ret = vmm_arch_run(vmm->lcd_arch);
		if (ret < 0 || vmm_should_stop(vmm)) {
			lcd_arch_dump_vmm(vmm->lcd_arch);
			break; 
		}

		entry_count ++; 
	}
	
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

	struct lcd_arch * lcd_arch = (struct lcd_arch *)args;
	lcd_arch->cont = (cont_t*) cont;

	/* Execute vmm_loop() on the new stack  
	 *
	 * _vmm_on_alt_stack_0() calls vmm_loop() on the new stack --- this stack will be 
	 * used by the hypervisor. 
	 *
	 * Inside the guest, i.e., inside dprivileged kernel we 
	 * return to the continuation we created before */

	vmm_on_alt_stack_0(lcd_arch->vmm_stack, vmm_loop, lcd_arch);
	return; 
};

#define CALL_CONT(_CONT,_FN,_ARG) 				\
	do { 							\
		SAVE_CALLEE_REGS();  				\
		_vmm_callcont_direct(_CONT, _ARG, _FN);		\
      	} while (0)


/* Start executing the minimal hypervisor on a new stack */
void __vmm_enter(struct lcd_arch * lcd_arch) {


	/* We enter VMM in two steps
	 *
	 * First, _vmm_callcont_direct() creates a continuation allowing 
	 * the VMM to come back to guest and continue its execution at 
	 * the point after _vmm_callcont_direct() returns. 
	 *
	 * Second, inside vmm_enter_swotch_stack() we use __vmm_loop() 
	 * to switch execution to the new stack. 
	 */

	CALL_CONT(&lcd_arch->cont, (void*) lcd_arch, vmm_enter_switch_stack); 
	return; 
}

static inline u64 mkepte(int access, u64 hpa)
{
	return (access & EPT_AR_MASK) | (hpa & PAGE_PA_MASK);
}

static inline u64 *ept_page_addr(u64 *pte)
{
	if (!pte || !(*pte & EPT_ACCESS_RWX))
		return 0;

	return __va(PAGE_PA(*pte));
}

static inline bool in_bounds(u64 gpa, u64 start, u64 end)
{
	return gpa >= start && gpa < end;
}


u8 ept_memory_type(struct lcd_vmm *vmm, u64 gpa)
{
	/* AB: lift this piece from KSM */
	/*
	 * KSM verbatim: 
	 *
	 * Alex Ionescue reports on Intel KabyLake, without the 
	 * correct memory type for a mapping, he gets an MCE, 
	 * which is always an L2 Data Cache Read in one of the 
	 * processor's banks.
	 *
	 * Some memory ranges require that the memory type is 
	 * uncachable or write-through or even write-protected 
	 * (this is the case for most fixed range MTRRs.
	 *
	 * See also: mm_cache_mtrr_ranges() in mm.c
	 */
	int i;
	struct mtrr_range *mttr_range;
	u8 type = vmm->mtrr_def;

	for (i = 0; i < vmm->mtrr_count; ++i) {
		mttr_range = &k->mtrr_ranges[i];
		if (!in_bounds(gpa, mttr_range->start, mttr_range->end))
			continue;

		if (mttr_range->fixed || mttr_range->type == EPT_MT_UNCACHABLE)
			return mttr_range->type;

		if (mttr_range->type == EPT_MT_WRITETHROUGH && type == EPT_MT_WRITEBACK)
			type = EPT_MT_WRITETHROUGH;
		else
			type = mttr_range->type;
	}

	return type;
}

u64 *ept_alloc_page(u64 *pml4, int access, int mtype, u64 gpa, u64 hpa)
{
	/* PML4 (512 GB) */
	u64 *pml4e = &pml4[PGD_INDEX_P(gpa)];
	u64 *pdpt = ept_page_addr(pml4e);

	if (!pdpt) {
		pdpt = mm_alloc_page();
		if (!pdpt)
			return NULL;

		*pml4e = mkepte(EPT_ACCESS_ALL, __pa(pdpt));
	}

	/* PDPT (1 GB)  */
	u64 *pdpte = &pdpt[PUD_INDEX_P(gpa)];
	u64 *pdt = ept_page_addr(pdpte);
	if (!pdt) {
		pdt = mm_alloc_page();
		if (!pdt)
			return NULL;

		*pdpte = mkepte(EPT_ACCESS_ALL, __pa(pdt));
	}

	/* PDT (2 MB)  */
	u64 *pdte = &pdt[PMD_INDEX_P(gpa)];
	u64 *pt = ept_page_addr(pdte);
	if (!pt) {
		pt = mm_alloc_page();
		if (!pt)
			return NULL;

		*pdte = mkepte(EPT_ACCESS_ALL, __pa(pt));
	}

	/* PT (4 KB)  */
	u64 *page = &pt[PTE_INDEX_P(gpa)];
	*page = mkepte(access, hpa);
	*page |= mtype << VMX_EPT_MT_EPTE_SHIFT;
	return page;
}


/* Prepare the EPT for the monolithic Linux kernel to 
 * run it in the VT-x non-root */
static int vmm_arch_ept_init(struct vmm *vmm) {
	u8 mtrr_def;
	u64 addr;
	u8 mt; 
	int i; 

	ret = mm_cache_ram_ranges(&vmm->ranges, &vmm->range_count);
	if (ret < 0)
		return -1; 

	/* MTRR   */
	mm_cache_mtrr_ranges(&vmm->mttr_ranges, &vmm->mtrr_count, &mtrr_def);
	KSM_DEBUG("Detected %d MTRR ranges (default type:%d)\n", 
		vmm->mtrr_count, vmm->mtrr_def);
	for (i = 0; i < vmm->mtrr_count; i++) {
		KSM_DEBUG("MTRR Range: 0x%016llX -> 0x%016llX fixed: %d type: %d\n",
			  vmm->mttr_ranges[i].start, vmm->mttr_ranges[i].end, 
			  vmm->mttr_ranges[i].fixed, vmm->mttr_ranges[i].type);
	}

	LCD_INFO("detected %d physical memory ranges\n", vmm->range_count);

	for (i = 0; i < range_count; i ++ ) {
		LCD_INFO("range: 0x%016llX -> 0x%016llX\n", vmm->ranges[i].start, vmm->ranges[i].end);

		for (addr = vmm->ranges[i].start; addr < vmm->ranges[i].end; addr += PAGE_SIZE) {
			mt = ept_memory_type(vmm, addr);
			if (!ept_alloc_page(EPT4(vmm->ept, eptp), r, mt, addr, addr))
				return -1;
		}
	}


	/* Allocate APIC page  */
	apic = __readmsr(MSR_IA32_APICBASE) & MSR_IA32_APICBASE_BASE;
	mt = ept_memory_type(vmm, apic);
	if (!ept_alloc_page(EPT4(vmm->ept, eptp), EPT_ACCESS_ALL, mt, apic, apic))
		return false;

	return 0; 
out:


};

/* Prepare the stack for the execution of the hypervisor
 * (VT-x root)
 */
static int vmm_alloc_stack(struct lcd_arch *lcd_arch) {

	lcd_arch->vmm_stack = kmalloc(VMM_STACK_SIZE, GFP_KERNEL);
	if (!lcd_arch->vmm_stack) {
		LCD_ERR("VMM stack allocation failed, cpu:%d\n", 
			raw_smp_processor_id());
		return -1; 
 	}

	// Note that sizeof(void) = 1 not 8.
	lcd_arch->vmm_stack += VMM_STACK_SIZE;
	return 0;
};

static void vmm_free_stack(struct lcd_arch *lcd_arch) {
	assert(lcd_arch->vmm_stack); 
	lcd_arch->vmm_stack -= VMM_STACK_SIZE;
    	kfree(lcd_arch->vmm_stack);
	return; 
}

int vmm_lcd_arch_create(struct lcd_arch **out)
{
	struct lcd_arch *lcd_arch;
	int ret;
	/*
	 * Alloc lcd_arch
	 */
	lcd_arch = kmem_cache_zalloc(lcd_arch_cache, GFP_KERNEL);
	if (!lcd_arch) {
		LCD_ERR("failed to alloc lcd_arch");
		ret = -ENOMEM;
		goto fail_alloc;
	}
	/*
	 * Set up ept
	 */
	ret = vmm_arch_ept_init(lcd_arch);
	if (ret) {
		LCD_ERR("setting up etp");
		goto fail_ept;
	}
	
	/*
	 * Alloc vmcs
	 */
	lcd_arch->vmcs = lcd_arch_alloc_vmcs(raw_smp_processor_id());
	if (!lcd_arch->vmcs) {
		LCD_ERR("failed to alloc vmcs\n");
		ret = -ENOMEM;
		goto fail_vmcs;
	}

	ret = vmx_allocate_vpid(lcd_arch);
	if (ret) {
		LCD_ERR("failed to alloc vpid\n");
		goto fail_vpid;
	}

	/*
	 * Not loaded on a cpu right now
	 */
	lcd_arch->cpu = -1;
	
	*out = lcd_arch;
	
	return 0;

fail_vpid:
	lcd_arch_free_vmcs(lcd_arch->vmcs);
fail_vmcs:
	lcd_arch_ept_free(lcd_arch);
fail_ept:
	kmem_cache_free(lcd_arch_cache, lcd_arch);
fail_alloc:
	return ret;
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

	ret = vmm_alloc_stack(lcd_arch); 
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

