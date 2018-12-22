/*
 * vmm.c
 *
 * Code for deprivileging the host and running a simple hypervisor
 * 
 */

#include <linux/tboot.h>
#include <asm/vmx.h>
#include <asm/virtext.h>
#include <asm/tlbflush.h>


#include <lcd_domains/types.h>
#include <asm/lcd_domains/microkernel.h>
#include <asm/lcd_domains/check.h>

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

#define PAGE_PA_MASK            (0xFFFFFFFFFULL << PAGE_SHIFT)
#define PAGE_PA(page)           ((page) & PAGE_PA_MASK)

#define EPT_AR_MASK                     0x7


#define MSR_MTRR_PHYS_MASK              0x00000201 
#define MSR_MTRR_PHYS_BASE              0x00000200

#define PGD_SHIFT_P             39
#define PUD_SHIFT_P             30
#define PMD_SHIFT_P             21
#define PTE_SHIFT_P             12

#ifndef PTX_MASK
#define PTX_MASK                0x1FF
#endif

#define PGD_INDEX_P(addr)               (((addr) >> PGD_SHIFT_P) & PTX_MASK)
#define PUD_INDEX_P(addr)               (((addr) >> PUD_SHIFT_P) & PTX_MASK)
#define PMD_INDEX_P(addr)               (((addr) >> PMD_SHIFT_P) & PTX_MASK)
#define PTE_INDEX_P(addr)               (((addr) >> PTE_SHIFT_P) & PTX_MASK)


#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT_SIGNAL 	3
#define EXIT_REASON_STARTUP_IPI 	4
#define EXIT_REASON_SMI_INTERRUPT 	5
#define EXIT_REASON_OTHER_SMI 		6
#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_NMI_WINDOW          8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC 		11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM 		17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMOFF               26
#define EXIT_REASON_VMON                27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_STATE       33
#define EXIT_REASON_MSR_LOAD_FAIL       34
#define EXIT_REASON_UNKNOWN35 		35
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_UNKNOWN38 		38
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_UNKNOWN42 		42
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_EOI_INDUCED         45
#define EXIT_REASON_GDT_IDT_ACCESS	46
#define EXIT_REASON_LDT_TR_ACCESS	47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_PREEMPTION_TIMER    52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_RDRAND 		57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_VMFUNC 		59
#define EXIT_REASON_ENCLS 		60
#define EXIT_REASON_RDSEED 		61
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64
#define EXIT_REASON_PCOMMIT             65

//#define MSR_IA32_FS_BASE                0xC0000100
//#define MSR_IA32_GS_BASE                0xC0000101


#define __sidt(idt)     __asm __volatile("sidt %0" : "=m" (*idt));
#define __lidt(idt)     __asm __volatile("lidt %0" :: "m" (*idt));
#define __sgdt(gdt)     __asm __volatile("sgdt %0" : "=m" (*gdt));
#define __lgdt(gdt)     __asm __volatile("lgdt %0" :: "m" (*gdt));

#define __readeflags()  ({                                                      \
        u64 rflags;                                                             \
        __asm __volatile("pushfq\n\tpopq %0" : "=r" (rflags));                  \
        rflags;                                                                 \
})

#define __readdr(dr) __extension__ ({                   \
        unsigned long long val;                         \
	__asm __volatile("movq %%dr" #dr ", %0"         \
                         : "=r" (val));                 \
        val;                                            \
})

void vmm_execute_cont(struct cont *cont); 

struct gdtr {
        u16 limit;
        uintptr_t base;
} __packed;

unsigned long __segmentlimit(unsigned long selector)
{
        unsigned long limit;
        __asm __volatile("lsl %1, %0" : "=r" (limit) : "r" (selector));
        return limit;
}

static inline u64 __lar(u64 sel)
{       
        u64 ar;
        __asm __volatile("lar %1, %0"
                         : "=r" (ar)
                         : "r" (sel));
        return ar;
}


static inline u32 __accessright(u16 selector)
{
        if (selector)
                return (__lar(selector) >> 8) & 0xF0FF;

        /* unusable  */
        return 0x10000;
}
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
static inline void _xsetbv(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	__asm __volatile(".byte 0x0f,0x01,0xd1"
			 :: "a" (eax), "d" (edx), "c" (index));
}

static inline void __cpuidex(int *ret, int func, int subf)
{
	__asm __volatile("xchgq %%rbx, %%rdi\n\t"
			 "cpuid\n\t"
			 "xchgq %%rbx, %%rdi\n\t"
			 : "=a" (ret[0]), "=D" (ret[1]), "=c" (ret[2]), "=d"(ret[3])
			 : "a" (func), "c" (subf));
}


static inline unsigned long long __readmsr(u32 msr)
{
	unsigned long long x;
	rdmsrl(msr, x);
	return x;
}



static void iter_resource(struct pmem_range *ranges,
			  struct resource *resource,
			  const char *match,
			  int *curr)
{
	struct resource *tmp;
	if (*curr >= MAX_RANGES)
		return;

	for (tmp = resource; tmp && *curr < MAX_RANGES; tmp = tmp->child) {
		if (strcmp(tmp->name, match) == 0) {
			ranges[*curr].start = tmp->start;
			ranges[*curr].end = tmp->end;
			++*curr;
		}

		if (tmp->sibling)
			iter_resource(ranges, tmp->sibling, match, curr);
	}
}

int mm_cache_ram_ranges(struct pmem_range *ranges, int *range_count)
{
	iter_resource(ranges, &iomem_resource, "System RAM", range_count);
	return 0;
}

static inline void make_mtrr_range(struct mtrr_range *range, bool fixed, u8 type,
				   u64 start, u64 end)
{
	range->fixed = fixed;
	range->type = type;
	range->start = start;
	range->end = end;
}

void mm_cache_mtrr_ranges(struct mtrr_range *ranges, int *range_count, u8 *def_type)
{
	u64 def, cap;
	u64 msr;
	u32 val;
	u64 base;
	u64 offset;
	int num_var;
	int idx = 0;
	int i;
	u64 len;

	def = __readmsr(MSR_MTRRdefType);
	*def_type = def & 0xFF;

	cap = __readmsr(MSR_MTRRcap);
	num_var = cap & 0xFF;

	if ((cap >> 8) & 1 && (def >> 10) & 1) {
		/* Read fixed range MTRRs.  */
		for (msr = __readmsr(MSR_MTRRfix64K_00000), offset = 0x10000, base = 0;
		     msr != 0; msr >>= 8, base += offset)
			make_mtrr_range(&ranges[idx++], true, msr & 0xff, base, base + 0x10000);

		for (val = MSR_MTRRfix16K_80000, offset = 0x4000; val <= MSR_MTRRfix16K_A0000; ++val)
			for (msr = __readmsr(val), base = 0x80000;
			     msr != 0; msr >>= 8, base += offset)
				make_mtrr_range(&ranges[idx++], true, msr & 0xff, base, base + 0x4000);

		for (val = MSR_MTRRfix4K_C0000, offset = 0x1000; val <= MSR_MTRRfix4K_F8000; ++val)
			for (msr = __readmsr(val), base = 0xC0000;
			     msr != 0; msr >>= 8, base += offset)
				make_mtrr_range(&ranges[idx++], true, msr & 0xff, base, base + 0x1000);
	}

	for (i = 0; i < num_var; i++) {
		msr = __readmsr(MSR_MTRR_PHYS_MASK + i * 2);
		if (!((msr >> 11) & 1))
			continue;

		len = 1ull << __ffs64(msr & PAGE_PA_MASK);
		base = __readmsr(MSR_MTRR_PHYS_BASE + i * 2);
		make_mtrr_range(&ranges[idx++], false,
				base & 0xff,
				base & PAGE_PA_MASK,
				(base & PAGE_PA_MASK) + len);
	}

	*range_count = idx;
}
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

static int vmm_nop(struct lcd_arch *lcd_arch)
{
	LCD_ERR("Unhandled VT-x exit:%d (%s)\n", 
			lcd_arch->exit_reason, vmm_exit_to_str(lcd_arch));
	return -1;
}

static inline void vmm_advance_rip(struct lcd_arch *lcd_arch)
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

static int vmm_handle_vmx(struct lcd_arch *lcd_arch)
{
	/* Handle VMX similar to SimpleVizor */

	/* Set the CF flag, which is how VMX instructions indicate failure */
	lcd_arch->regs.rflags |= 0x1; // VM_FAIL_INVALID

	/* RFLAGs is actually restored from the VMCS, so update it here */

	vmcs_writel(GUEST_RFLAGS, lcd_arch->regs.rflags);
	
	vmm_advance_rip(lcd_arch);
	return 0;
}

int vmm_handle_wbinvd(struct lcd_arch *lcd_arch)
{
	//__wbinvd();
	__asm __volatile("wbinvd");

	vmm_advance_rip(lcd_arch);
	return 0;
}

int vmm_handle_xsetbv(struct lcd_arch *lcd_arch)
{

	/* Simply issue the XSETBV instruction on the native logical processor */
	_xsetbv((u32)lcd_arch->regs.rcx, 
		lcd_arch->regs.rdx << 32 | lcd_arch->regs.rax);

	vmm_advance_rip(lcd_arch);
	return true;
}

static int vmm_handle_exit(struct lcd_arch *lcd_arch)
{
	int ret;

	LCD_MSG("Handling exit 0x%llx", lcd_arch->exit_reason);

	switch (lcd_arch->exit_reason) {
	case EXIT_REASON_EXCEPTION_NMI:
		//ret = vcpu_handle_exception_nmi(lcd_arch);
		ret = vmm_nop(lcd_arch);
		break;
	case EXIT_REASON_EXTERNAL_INTERRUPT:
		//ret = vcpu_hadnle_external_int(); 
		ret = vmm_nop(lcd_arch);
		break; 
	case EXIT_REASON_TRIPLE_FAULT: 
		//ret = vcpu_handle_triplefault(); 
		ret = vmm_nop(lcd_arch);
	case EXIT_REASON_INIT_SIGNAL:
		ret = vmm_nop(lcd_arch);
		break; 
	case EXIT_REASON_STARTUP_IPI:
		ret = vmm_nop(lcd_arch);
		break; 
	case EXIT_REASON_SMI_INTERRUPT:
	       	ret = vmm_nop(lcd_arch);
		break; 
	case EXIT_REASON_OTHER_SMI:
		ret = vmm_nop(lcd_arch); 
		break; 
	case EXIT_REASON_PENDING_INTERRUPT:
		ret = vmm_nop(lcd_arch);
		break; 
	case EXIT_REASON_NMI_WINDOW:
	       	ret = vmm_nop(lcd_arch); 
		break; 
	case EXIT_REASON_TASK_SWITCH:
		//ret = vcpu_handle_taskswitch();
		ret = vmm_nop(lcd_arch); 

		break; 
	case EXIT_REASON_CPUID:
		ret = vmm_handle_cpuid(lcd_arch);
		break; 
	case EXIT_REASON_GETSEC: 
		ret = vmm_nop(lcd_arch);
		break; 
	case EXIT_REASON_HLT:
		//ret = vcpu_handle_hlt();
		ret = vmm_nop(lcd_arch); 

		break;
	case EXIT_REASON_INVD:
		//ret = vmm_handle_invd(lcd_arch);
		ret = vmm_nop(lcd_arch); 
		break; 
	case EXIT_REASON_INVLPG:
		// ret = vcpu_handle_invlpg(); 
		ret = vmm_nop(lcd_arch); 
		break; 
	case EXIT_REASON_RDPMC:
		ret = vmm_nop(lcd_arch);
		break;
	case EXIT_REASON_RDTSC:
		//ret = vcpu_handle_rdtsc(); 
		ret = vmm_nop(lcd_arch); 
		break;
	case EXIT_REASON_RSM:
		ret = vmm_nop(lcd_arch); 

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
		ret = vmm_handle_vmx(lcd_arch); 
		break;

	case EXIT_REASON_INVEPT:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_INVVPID:
		ret =  vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_CR_ACCESS:
		//ret = vcpu_handle_cr_access(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_DR_ACCESS:
		//ret = vcpu_handle_dr_access(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_IO_INSTRUCTION:
		//ret = vcpu_handle_io_instr(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_MSR_READ:
		//ret = vcpu_handle_rdmsr(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_MSR_WRITE:
		//ret = vcpu_handle_wrmsr(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_INVALID_STATE:
		//ret = vcpu_handle_invalid_state(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_MSR_LOAD_FAIL:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_UNKNOWN35:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_MWAIT_INSTRUCTION:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_MONITOR_TRAP_FLAG: 
		//ret = vcpu_handle_mtf();
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_UNKNOWN38: 
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_MONITOR_INSTRUCTION:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_PAUSE_INSTRUCTION: 
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_MCE_DURING_VMENTRY:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_UNKNOWN42: 
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_TPR_BELOW_THRESHOLD: 
		//ret = vcpu_handle_tpr_threshold(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_APIC_ACCESS: 
		//ret = vcpu_handle_apic_access(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_EOI_INDUCED: 
		//ret = vcpu_handle_eoi_induced();
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_GDT_IDT_ACCESS:
		//ret = vcpu_handle_gdt_idt_access(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_LDT_TR_ACCESS:
		//ret = vcpu_handle_ldt_tr_access(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_EPT_VIOLATION:
		//ret = vcpu_handle_ept_violation();
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_EPT_MISCONFIG:
		//ret = vcpu_handle_ept_misconfig(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_RDTSCP:
		//ret = vcpu_handle_rdtscp(); 
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_PREEMPTION_TIMER:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_WBINVD:
		//ret = vcpu_handle_wbinvd(); 
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_XSETBV:
		//ret = vcpu_handle_xsetbv(); 
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_APIC_WRITE:
		//ret = vcpu_handle_apic_write(); 
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_RDRAND:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_INVPCID:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_VMFUNC:
		//ret = vcpu_handle_vmfunc(); 
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_ENCLS:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_RDSEED:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_PML_FULL:
		//ret = vcpu_handle_pml_full(); 
		ret = vmm_nop(lcd_arch); 

		break;

	case EXIT_REASON_XSAVES: 
		ret = vmm_nop(lcd_arch);
		break;

	case EXIT_REASON_XRSTORS:
		ret = vmm_nop(lcd_arch); 
		break;

	case EXIT_REASON_PCOMMIT:
		ret = vmm_nop(lcd_arch); 
		break;
	default:
		/* Exit reasons SDM 24.9.1 */
		LCD_ERR("Unhandled exit reason 0x%llx", lcd_arch->exit_reason);
		LCD_MSG("instr len:%d, qualification:0x%llx, idt vectoring:0x%x,"
			" error code: 0x%x, exit interrupt info: 0x%x, vec_no:%d\n", 
			lcd_arch->exit_reason, lcd_arch->exit_instr_len, 
			lcd_arch->exit_qualification, lcd_arch->idt_vectoring_info, 
			lcd_arch->error_code, lcd_arch->exit_intr_info, lcd_arch->vec_no); 
	       
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

int vmm_arch_run(struct lcd_arch *lcd_arch)
{
	int ret;


	/*
	 * Enter lcd with vmlaunch/vmresume
	 */
	vmm_vmx_enter(lcd_arch);

	/*
	 * Check/handle nmi's, exceptions, and external interrupts 
	 */
	ret = vmm_handle_exit(lcd_arch);

	/*
	 * Handle all other exit reasons
	 *
	 * Intel SDM V3 Appendix C
	 */
	//ret = vmx_handle_other_exits(lcd_arch);

	return ret; 	
}


static int vmm_should_stop(struct lcd_vmm *vmm)
{
	if (vmm->should_stop)
		return 1;
	return 0;
}

void vmm_set_entry_point(struct lcd_arch *lcd_arch) {

	lcd_arch->regs.rsp = lcd_arch->cont.rsp;
	vmcs_writel(GUEST_RSP, lcd_arch->regs.rsp);
	lcd_arch->regs.rbp = lcd_arch->cont.rbp; 
	lcd_arch->regs.rip = lcd_arch->cont.rip; 
	vmcs_writel(GUEST_RIP, lcd_arch->regs.rip);

	return; 
};

/**
 * Sets up VMCS settings--execution control, control register
 * access, exception handling.
 *
 * We need the lcd_arch so we can set up it's ept.
 */
static void vmm_setup_vmcs_guest_settings(struct lcd_arch *lcd_arch)
{
	/*
	 * VPID
	 */
	vmcs_write16(VIRTUAL_PROCESSOR_ID, lcd_arch->vpid);
	/*
	 * No VMCS Shadow (Intel SDM V3 24.4.2)
	 */
	vmcs_write64(VMCS_LINK_POINTER, -1ull);
	/*
	 * Execution controls
	 */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		lcd_global_vmcs_config.pin_based_exec_controls);
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
		lcd_global_vmcs_config.primary_proc_based_exec_controls);
	vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
		lcd_global_vmcs_config.secondary_proc_based_exec_controls);
	/*
	 * Entry / Exit controls
	 */
	vmcs_write32(VM_ENTRY_CONTROLS, 
		lcd_global_vmcs_config.vmentry_controls);
	vmcs_write32(VM_EXIT_CONTROLS, 
		lcd_global_vmcs_config.vmexit_controls);
	/*
	 * EPT
	 */
	vmcs_write64(EPT_POINTER, lcd_arch->ept.vmcs_ptr);
	/*
	 * LCDs normally exit on every exception, in the 
	 * first implementation of the VMM we try not 
	 * to exit at all. 
	 *
	 * Exit on any kind of page fault (Intel SDM V3 25.2)
	 */
	//vmcs_write32(EXCEPTION_BITMAP, 0xffffffff);
	//vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	//vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	/* Never exit on a pagefault (Intel SDM V3 25.2) */
	vmcs_write32(EXCEPTION_BITMAP, 0x1 << 14);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0xffffffff);

	/*
	 * No %cr3 targets (Intel SDM V3 24.6.7)
	 * 
	 * It looks like CR3 wil always cause an exit, no? 
	 */
	vmcs_write32(CR3_TARGET_COUNT, 0);
	/* 
	 * Intel SDM V3 24.6.6
	 *
	 * %cr0 and %cr4 guest accesses always cause vm exit: all bits 1s
	 * %cr0 and %cr4 are accessible to the guest (no exits): all bits 0
	 *
	 */
	vmcs_writel(CR0_GUEST_HOST_MASK, 0);
	vmcs_writel(CR4_GUEST_HOST_MASK, 0);
}

/**
 * Sets up initial guest register values in VMCS.
 *
 * Most of the guest state is set here and in 
 * vmx_setup_vmcs_guest_settings. The processor
 * is picky about what goes into the guest state; if
 * it doesn't like it, vmentry will fail. See Intel
 * SDM V3 26.3.1.
 *
 * vmx_setup_vmcs_guest_regs
 *   - %cr0, %cr4
 *   - EFER MSR (part of setting guest to use 64-bit mode)
 *   - %rsp (for now! should be accessible by arch-indep
 *     code through interface)
 *   - %rflags
 *   - segment registers -- %cs, %ds, %ss, %es, %fs, %gs
 *     - we have to do more setup here since the processor
 *       doesn't set defaults (access rights, limits, etc.)
 *   - misc fields -- activity state, debug controls, etc.
 *
 * vmx_setup_vmcs_guest_settings
 *   - vpid
 *   - execution, exit, and entry controls
 *   - ept pointer (so you must init ept before!)
 *   - exception handling
 *   - %cr0, %cr4 access masks
 *
 * lcd_arch_set_pc
 *   - %rip (to be set by arch-indep code)

 * lcd_arch_set_gva_root
 *   - %cr3 (to be set by arch-indep code)
 */
static void vmm_setup_vmcs_guest_regs(struct lcd_arch *lcd_arch)
{

	struct desc_struct *gdt;
	hva_t host_tss;
	unsigned long tmpl;
	u32 low32;
	u32 high32;
	u16 tmps;

	struct gdtr gdtr;
	struct gdtr idtr;
	gate_desc *idt;

	/*
	 * Guest %cr0, %cr4, %cr3
	 *
	 * -- ensure TS (Task Switched) in %cr0 is 0
	 *
	 * Intel SDM V3 2.5
	 */
	vmcs_writel(GUEST_CR0, read_cr0());
	vmcs_writel(CR0_READ_SHADOW, read_cr0());
	vmcs_writel(CR0_GUEST_HOST_MASK, 0);


	vmcs_writel(GUEST_CR4, __read_cr4());
	vmcs_writel(CR4_READ_SHADOW, __read_cr4());
	vmcs_writel(CR4_GUEST_HOST_MASK, 0);

	vmcs_writel(GUEST_CR3, read_cr3());

	/*
	 * MSR EFER (extended feature enable register)
	 *
	 * -- 64-bit mode (long mode enabled and active)
	 */
	vmcs_writel(GUEST_IA32_EFER, EFER_LME | EFER_LMA);

	/*
 	 * IA32 MSR - setup PAT entry	 
 	 */
	vmx_setup_pat_msr(0, PAT_WB);
	vmx_setup_pat_msr(1, PAT_UC);

	/*
	 * Sysenter info (%cs, %eip, and %esp)
	 *
	 * Even though the guest cannot access the sysenter msr,
	 * the processor loads the values in these fields on exit,
	 * so we need to have the correct values there.
	 *
	 * %esp is set when the vmcs is loaded on a cpu (since
	 * each cpu has its own sysenter stack? following dune and
	 * kvm here ...). This happens in __vmx_setup_cpu.
	 *
	 * See Intel SDM V3 27.5.1
	 */
	rdmsr(MSR_IA32_SYSENTER_CS, low32, high32);
	vmcs_write32(GUEST_SYSENTER_CS, low32);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	vmcs_writel(GUEST_SYSENTER_EIP, tmpl);

	/*
	 * Sysenter %esp (per cpu? so has to go in here? following
	 * dune and kvm...)
	 */
	rdmsrl(MSR_IA32_SYSENTER_ESP, tmpl);
	vmcs_writel(GUEST_SYSENTER_ESP, tmpl);

	/*
	 * Linux uses per-cpu TSS and GDT, so we need to set these
	 * in the host part of the vmcs when switching cpu's.
	 */
	gdt = vmx_host_gdt();
	vmx_host_tss(&host_tss);
	vmcs_writel(GUEST_TR_BASE, hva_val(host_tss));
	vmcs_writel(GUEST_GDTR_BASE, (unsigned long)gdt);

	/* No need to handle LDT, I assume Linux doesn't use it */
	/* -- ldtr unusable (bit 16 = 1) */
	//vmcs_writel(GUEST_LDTR_BASE, __segmentbase(gdtr.base, ldt));
	vmcs_writel(GUEST_LDTR_AR_BYTES, (1 << 16));

	/*
	 * %fs and %gs are also per-cpu
	 *
	 * (MSRs are used to load / store %fs and %gs in 64-bit mode.
	 * See Intel SDM V3 3.2.4 and 3.4.4.)
	 */
	rdmsrl(MSR_FS_BASE, tmpl);
	vmcs_writel(GUEST_FS_BASE, tmpl);
	rdmsrl(MSR_GS_BASE, tmpl);
	vmcs_writel(GUEST_GS_BASE, tmpl);

	/*
	 * %rsp, %rip -- to be set by arch-independent code when guest address 
	 * space set up (see lcd_arch_set_sp and lcd_arch_set_pc).
	 */
	//see comment about set_sp and set_pc above

	/*
	 * %rflags
	 */
	vmcs_writel(GUEST_RFLAGS, __readeflags());

	/*
	 *===--- Segment and descriptor table registers ---===
	 *
	 * See Intel SDM V3 26.3.1.2, 26.3.1.3 for register requirements
	 */

	/* 
	 * Bases for segment and desc table registers.
	 *
	 * Note: MSR's for %fs and %gs will be loaded with
	 * the values in %fs.base and %gs.base; see Intel SDM V3 26.3.2.1.
	 */
	
	/*
	 * Guest segment selectors
	 *
	 * Even though %es, %ds, and %ss are ignored in 64-bit
	 * mode, we still set them. See x86/include/asm/segment.h and
	 * Intel SDM V3 3.4.4.
	 */


	savesegment(cs, tmps);
	vmcs_write16(GUEST_CS_SELECTOR, tmps);
	vmcs_writel(GUEST_CS_LIMIT, __segmentlimit(tmps));
	vmcs_writel(GUEST_CS_AR_BYTES, __accessright(tmps));
	vmcs_writel(GUEST_CS_BASE, 0);


	savesegment(ds, tmps);
	vmcs_write16(GUEST_DS_SELECTOR, tmps);
	vmcs_writel(GUEST_DS_LIMIT, __segmentlimit(tmps));
	vmcs_writel(GUEST_DS_AR_BYTES, __accessright(tmps));
	vmcs_writel(GUEST_DS_BASE, 0);

	savesegment(es, tmps);
	vmcs_write16(GUEST_ES_SELECTOR, tmps);
	vmcs_writel(GUEST_ES_LIMIT, __segmentlimit(tmps));
	vmcs_writel(GUEST_ES_AR_BYTES, __accessright(tmps));
	vmcs_writel(GUEST_ES_BASE, 0);

	savesegment(ss, tmps);
	vmcs_write16(GUEST_SS_SELECTOR, tmps);
	vmcs_writel(GUEST_SS_LIMIT, __segmentlimit(tmps));
	vmcs_writel(GUEST_SS_AR_BYTES, __accessright(tmps));

	savesegment(fs, tmps);
	LCD_MSG("FS selector:0x%x\n", tmps);

	vmcs_write16(GUEST_FS_SELECTOR, tmps);
	vmcs_writel(GUEST_FS_LIMIT, __segmentlimit(tmps));
	vmcs_writel(GUEST_FS_AR_BYTES, __accessright(tmps));
	vmcs_writel(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	LCD_MSG("FS base:0x%x\n", __readmsr(MSR_FS_BASE));

	savesegment(gs, tmps);
	LCD_MSG("GS selector:0x%x\n", tmps);

	vmcs_write16(GUEST_GS_SELECTOR, tmps);
	vmcs_writel(GUEST_GS_LIMIT, __segmentlimit(tmps));
	vmcs_writel(GUEST_GS_AR_BYTES, __accessright(tmps));
	vmcs_writel(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
	LCD_MSG("GS base:0x%x\n", __readmsr(MSR_GS_BASE));

	store_tr(tmps);
	vmcs_write16(GUEST_TR_SELECTOR, tmps);
	vmcs_writel(GUEST_TR_LIMIT, __segmentlimit(tmps));
	vmcs_writel(GUEST_TR_AR_BYTES, __accessright(tmps));

	vmm_execute_cont(&lcd_arch->cont); 

	/* IDT and GDT */
	__sgdt(&gdtr);
	__sidt(&idtr);

	vmcs_write32(GUEST_GDTR_LIMIT, gdtr.limit);
	vmcs_write32(GUEST_IDTR_LIMIT, idtr.limit);
	
	/*
	 * idtr
	 */
	idt = vmx_host_idt();
	vmcs_writel(GUEST_IDTR_BASE, (unsigned long)idt);

	vmcs_writel(GUEST_DR7, __readdr(7));
	
	//err |= vmcs_write(GUEST_RSP, gsp);
	//err |= vmcs_write(GUEST_RIP, gip);
		



	/*
	 * Guest activity state = active
	 *
	 * Intel SDM V3 24.4.2
	 */
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);

	/*
	 * Guest interruptibility state = 0 (interruptible)
	 *
	 * Intel SDM V3 24.4.2
	 */
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);

	/*
	 * Clear the interrupt event injection field (valid bit is 0)
	 *
	 * Intel SDM V3 24.8.3
	 */
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);

	/*
	 * No pending debug exceptions
	 *
	 * Intel SDM V3 24.4.2
	 */
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	/*
	 * This might not be needed in 64-bit mode
	 *
	 * Intel SDM V3 26.3.1.5
	 */
	vmcs_write64(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTLMSR));

}

/**
 * Front-end for setting up VMCS. Calls helper routines
 * to set up guest and host states of VMCS.
 */
void vmm_setup_vmcs(struct lcd_arch *lcd_arch)
{
	/*
	 * Set up guest part of vmcs, and guest exec
	 */
	vmm_setup_vmcs_guest_settings(lcd_arch);
	vmm_setup_vmcs_guest_regs(lcd_arch);
	/*
	 * Set up MSR bitmap and autoloading
	 */
	vmx_setup_vmcs_msr(lcd_arch);
	/*
	 * Set up host part of vmcs
	 */
	vmx_setup_vmcs_host(lcd_arch);
}


void vmm_loop(struct lcd_arch *lcd_arch)
{
	int ret;
	int entry_count = 0;
	int local_entry_count = 0; 

	LCD_MSG("Entering VMM loop, setting entry point: rsp: 0x%llx, rip: 0x%llx, rbp: 0x%llx\n", 
		lcd_arch->cont.rsp, lcd_arch->cont.rip, lcd_arch->cont.rbp);

	
	/*
	 * Load vmcs pointer on this cpu
	 */
	//vmcs_load(vmm->lcd_arch->vmcs);
	
	/*
	 * Load the lcd and invalidate any cached mappings.
	 *
	 * *preemption disabled*
	 */
	vmx_get_cpu(lcd_arch);

	vmm_setup_vmcs(lcd_arch);
	vmx_enable_ept_switching(lcd_arch);

	/* Set entry point for the host using vmm->cont */
	vmm_set_entry_point(lcd_arch); 

	/*
	 * Make sure lcd_arch has valid state
	 */
	ret = lcd_arch_check(lcd_arch);
	if (ret) {
		LCD_ERR("bad lcd_arch state");
		return; 
	}


	LCD_MSG("Ready to disable IRQs and enter the runloop\n"); 

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

		ret = vmm_arch_run(lcd_arch);
		if (ret < 0 || vmm_should_stop(lcd_arch->vmm)) {
			lcd_arch_dump_lcd(lcd_arch);
			break; 
		}

		entry_count ++;
		local_entry_count ++; 

		if (local_entry_count > 1000) {
			LCD_MSG("Exiting VMM, handled exits: %d\n", entry_count);
			local_entry_count = 0; 
		}
	}
	
	/*
	 * Now turn interrupts back on.
	 */
	local_irq_enable();

	/*
	 * Preemption enabled
	 */
	vmx_put_cpu(lcd_arch);	

	LCD_MSG("Exiting VMM, handled exits: %d\n", entry_count); 

	/*
	 * If there was an error, dump the lcd's state.
	 */
	if (ret < 0)
		lcd_arch_dump_lcd(lcd_arch);

	return;
}

#define SAVE_CALLEE_REGS()						\
  __asm__ volatile ("" : : : "rbx", "r12", "r13", "r14", "r15",         \
		    "memory", "cc")

/*
            static void vmm_execute_cont(cont_t *cont)    // rdi
*/
__asm__ ("      .text \n\t"
         "      .align  16                 \n\t"
         "      .globl  vmm_execute_cont \n\t"
         "      .type   vmm_execute_cont, @function \n\t"
         "vmm_execute_cont:                \n\t"
         " mov 8(%rdi), %rbp               \n\t"
         " mov 16(%rdi), %rsp              \n\t"
         " jmp *0(%rdi)                    \n\t");


/*
         static void vmm_on_alt_stack_0(void *stack,   // rdi
                                        void *fn,      // rsi
                                        void *args)    // rdx
*/

void vmm_on_alt_stack_0(void *stack,   // rdi
				void *fn,     // rsi
				void *args);  // rdx

__asm__ ("      .text \n\t"
         "      .align  16                  \n\t"
         "vmm_on_alt_stack_0:               \n\t"
         " sub $8, %rdi                     \n\t"
         " mov %rsp, (%rdi)                 \n\t" // Save old ESP on new stack
         " mov %rdi, %rsp                   \n\t" // Set up new stack pointer
         " mov %rdx, %rdi                   \n\t" // Move args into rdi
         " call *%rsi                    \n\t" // Call callee (args in rdi)
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
void _vmm_call_cont_direct(struct cont *cont,   // rdi
			void *args,     //rsi
			cont_fn_t fn);   // rdx

__asm__ ("      .text \n\t"
         "      .align  16           \n\t"
         "      .globl  _vmm_call_cont_direct \n\t"
         "      .type   _vmm_call_cont_direct, @function \n\t"
         "_vmm_call_cont_direct:             \n\t"
         " mov  0(%rsp), %rax        \n\t" // return address into RAX
         " mov  %rax,  0(%rdi)       \n\t" // EIP (our return address)
         " mov  %rbp,  8(%rdi)       \n\t" // EBP
         " mov  %rsp, 16(%rdi)       \n\t" // ESP+8 (after return)
         " addq $8,   16(%rdi)       \n\t"
         // cont now initialized.  Call the function
         // rdi : cont , rsi : args , rdx : fn
         " jmpq  *%rdx            \n\t"
         " int3\n\t");


void vmm_enter_switch_stack(void *cont, void *args) {

	struct lcd_arch * lcd_arch = (struct lcd_arch *)args;
	lcd_arch->cont = *(struct cont*) cont;

	/* Execute vmm_loop() on the new stack  
	 *
	 * _vmm_on_alt_stack_0() calls vmm_loop() on the new stack --- this stack will be 
	 * used by the hypervisor. 
	 *
	 * Inside the guest, i.e., inside dprivileged kernel we 
	 * return to the continuation we created before */
	LCD_MSG("Switching stacks: rsp: 0x%llx, rip: 0x%llx, rbp: 0x%llx\n", 
		lcd_arch->cont.rsp, lcd_arch->cont.rip, lcd_arch->cont.rbp);

	LCD_MSG("stack: 0x%llx, func: 0x%llx, lcd_arch: 0x%llx\n", 
		lcd_arch->vmm_stack, vmm_loop, lcd_arch);

	vmm_on_alt_stack_0(lcd_arch->vmm_stack, vmm_loop, lcd_arch);
	return; 
};

#define CALL_CONT(_CONT,_ARG,_FN) 				\
	do { 							\
		SAVE_CALLEE_REGS();  				\
		_vmm_call_cont_direct(_CONT, _ARG, _FN);	\
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

	//LCD_MSG("CALL CONT: &lcd_arch->cont: 0x%llx, lcd_arch: 0x%llx, vmm_enter_switch_stack: 0x%llx\n", 
	//	&lcd_arch->cont, (void *)lcd_arch, vmm_enter_switch_stack);


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
		mttr_range = &vmm->mtrr_ranges[i];
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
	u64 *pdpte;
	u64 *pdt;
	u64 *pdte;
	u64 *pt;
	u64 *page;

	if (!pdpt) {
		pdpt = (void *)get_zeroed_page(GFP_KERNEL | GFP_ATOMIC);
		if (!pdpt)
			return NULL;

		*pml4e = mkepte(EPT_ACCESS_ALL, __pa(pdpt));
	}

	/* PDPT (1 GB)  */
	pdpte = &pdpt[PUD_INDEX_P(gpa)];
	pdt = ept_page_addr(pdpte);
	if (!pdt) {
		pdt = (void *)get_zeroed_page(GFP_KERNEL | GFP_ATOMIC); 
		if (!pdt)
			return NULL;

		*pdpte = mkepte(EPT_ACCESS_ALL, __pa(pdt));
	}

	/* PDT (2 MB)  */
	pdte = &pdt[PMD_INDEX_P(gpa)];
	pt = ept_page_addr(pdte);
	if (!pt) {
		pt = (void *)get_zeroed_page(GFP_KERNEL | GFP_ATOMIC); 
		if (!pt)
			return NULL;

		*pdte = mkepte(EPT_ACCESS_ALL, __pa(pt));
	}

	/* PT (4 KB)  */
	page = &pt[PTE_INDEX_P(gpa)];
	*page = mkepte(access, hpa);
	*page |= mtype << VMX_EPT_MT_EPTE_SHIFT;
	return page;
}

int vmm_detect_memory_regions(struct lcd_vmm *vmm) {
	u8 mtrr_def;
	int i, ret;  

	ret = mm_cache_ram_ranges(vmm->ranges, &vmm->range_count);
	if (ret < 0) {
		LCD_ERR("Failed to detect cache regions\n");
		return -1;
	}	

	LCD_MSG("detected %d physical memory ranges\n", vmm->range_count);

	for (i = 0; i < vmm->range_count; i ++ ) {
		LCD_MSG("range: 0x%016llX -> 0x%016llX\n", vmm->ranges[i].start, vmm->ranges[i].end);
	}

	/* MTRR   */
	mm_cache_mtrr_ranges(vmm->mtrr_ranges, &vmm->mtrr_count, &mtrr_def);
	//if (ret < 0) {
	//	LCD_ERR("Failed to detect MTTR ranges\n");
	//	return -1;
	//}	


	LCD_MSG("Detected %d MTRR ranges (default type:%d)\n", 
		vmm->mtrr_count, vmm->mtrr_def);

	for (i = 0; i < vmm->mtrr_count; i++) {
		LCD_MSG("MTRR Range: 0x%016llX -> 0x%016llX fixed: %d type: %d\n",
			  vmm->mtrr_ranges[i].start, vmm->mtrr_ranges[i].end, 
			  vmm->mtrr_ranges[i].fixed, vmm->mtrr_ranges[i].type);
	}

	return 0; 
}

/* Prepare the EPT for the monolithic Linux kernel to 
 * run it in the VT-x non-root */
static int vmm_arch_ept_init(struct lcd_arch *lcd_arch) {
	u64 addr;
	u8 mt; 
	int i; 
	struct lcd_vmm * vmm = lcd_arch->vmm; 
	hva_t page;
	u64 eptp;
	
	/*
	 * Alloc the root global page directory page
	 */
	page = __hva(get_zeroed_page(GFP_KERNEL));
	if (!hva_val(page)) {
		LCD_ERR("failed to alloc page\n");
		return -ENOMEM;
	}
	lcd_arch->ept.root = (lcd_arch_epte_t *)hva2va(page);

	/*
	 * Init the VMCS EPT pointer
	 *
	 * -- default memory type (write-back)
	 * -- default ept page walk length (4, pointer stores
	 *    length - 1)
	 * -- use access/dirty bits, if available
	 *
	 * See Intel SDM V3 24.6.11 and Figure 28-1.
	 */

	eptp = VMX_EPT_DEFAULT_MT |
		(LCD_ARCH_EPT_WALK_LENGTH - 1) << LCD_ARCH_EPTP_WALK_SHIFT;
	if (cpu_has_vmx_ept_ad_bits()) {
		lcd_arch->ept.access_dirty_enabled = true;
		eptp |= VMX_EPT_AD_ENABLE_BIT;
	}
	eptp |= hpa_val(va2hpa(lcd_arch->ept.root)) & PAGE_MASK;
	lcd_arch->ept.vmcs_ptr = eptp;

	for (i = 0; i < vmm->range_count; i ++ ) {
		LCD_MSG("range: 0x%016llX -> 0x%016llX\n", 
				vmm->ranges[i].start, vmm->ranges[i].end);

		for (addr = vmm->ranges[i].start; addr < vmm->ranges[i].end; addr += PAGE_SIZE) {
			mt = ept_memory_type(vmm, addr);
			if (!ept_alloc_page(lcd_arch->ept.root, 
						EPT_ACCESS_ALL, mt, addr, addr))
				return -1;
		}
	}

	/* Allocate APIC page  */
	addr = __readmsr(MSR_IA32_APICBASE) & MSR_IA32_APICBASE_BASE;
	mt = ept_memory_type(vmm, addr);
	if (!ept_alloc_page(lcd_arch->ept.root, EPT_ACCESS_ALL, mt, addr, addr))
		return false;

	return 0; 
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

void vmm_free_stack(struct lcd_arch *lcd_arch) {
	BUG_ON(lcd_arch->vmm_stack); 
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
	 * This is used in vmx_get_cpu()
	 */
	lcd_arch->cpu = -1;
	
	*out = lcd_arch;
	
	return 0;

fail_vpid:
	lcd_arch_free_vmcs(lcd_arch->vmcs);
fail_vmcs:
	lcd_arch_ept_free(lcd_arch);
	kmem_cache_free(lcd_arch_cache, lcd_arch);
fail_alloc:
	return ret;
}

/* Enter the VT-x root mode. Create a new stack, prepare an EPT and enter 
 * the VT-x root mode on a new stack. 
 *
 * The hypervisor will keep spinning until the kernel asks it to exit by 
 * setting the vmm->should_stop flag. 
 *
 */
void vmm_enter(void *unused)
{
	int ret;
	struct lcd_arch *lcd_arch;

	lcd_arch = __this_cpu_read(vmm_lcd_arch);

	ret = vmm_arch_ept_init(lcd_arch); 
	if (ret) 
		goto failed; 

	ret = vmm_alloc_stack(lcd_arch); 
	if (ret) 
		goto failed; 

	LCD_MSG("Entering VMM on a new stack:0x%llx\n", lcd_arch->vmm_stack);

	/* We enter the hypervisor and continue in the guest at vmm_enter_ack */
	__vmm_enter(lcd_arch);	

	LCD_MSG("Entered VMM on CPU %d\n", raw_smp_processor_id());

	return; 

failed: 
	LCD_ERR("failed to enter VMM, err = %d\n", ret);
	return; 
}

/* 
 * lcd_arch_init() 
 *    
 *    - cpu_has_vmx()
 *
 *    - setup_vmcs_config (lcd_global_vmcs_config)
 *        -- pin based controls in a global var
 *
 *    - msr bitmap
 *
 *    - foreach cpu
 *        vmxon_buf -- alloc()
 *
 *    - lcd_vmm_init()
 *
 *    - on each cpu
 *        vmm_enter()
 *
 *
 *  lcd_vmm_init()
 *
 *    - vmm_detect_memory_regions()
 *
 *    - foreach cpu
 *        - vmm_lcd_arch_create()
 *
 *  vmm_lcd_arch_create()
 *
 *    - lcd_arch = alloc ()
 *    - lcd_arch->vmcs = lcd_arch_alloc_vmcs()
 *    - vmx_allocate_vpid()
 *
 * vmm_enter()
 * 
 *    - vmm_arch_ept_init()
 *    - vmm_alloc_stack()
 *    - __vmm_enter()
 *
 * __vmm_enter()
 *
 *    - CALL_CONT (vmm_enter_switch_stack())
 *
 * vmm_enter_switch_stack()
 *    
 *    - vmm_loop() 
 *
 * vmm_loop()
 *
 *   - vmm_set_entry_point() 
 *   - vmx_get_cpu()
 *   - vmm_setup_vmcs()
 *   - vmx_enable_ept_switching()
 *   - local_irq_disable()
 *
 *   - for(;;)
 *       -- vmm_arch_run()
 *
 *
 * vmx_get_cpu()
 *
 *   - vmcs_load()
 *   - __vmx_setup_cpu()
 *
 *
 * __vmx_setup_cpu()
 *
 *   // Re-load CPU-specific VMCS data when LCD migrates
 *   // HOST_TR_BASE
 *   // HOST_GDTR_BASE
 *   // MSR_IA32_SYSENTER_ESP
 *   // HOST_FS_BASE
 *   // HOST_GS_BASE
 *
 *
 * vmm_setup_vmcs()
 *   - vmm_setup_vmcs_guest_settings()
 *   - vmm_setup_vmcs_guest_regs()
 *   - vmx_setup_vmcs_msr()
 *   - vmx_setup_vmcs_host()
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 * 
 *
 *
 *
 *
 *
 */

