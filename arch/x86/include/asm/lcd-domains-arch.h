#ifndef LCD_DOMAINS_ARCH_H
#define LCD_DOMAINS_ARCH_H

#include <asm/vmx.h>
#include <linux/spinlock.h>
#include <lcd-domains/ipc.h>

struct lcd_arch_vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

int lcd_arch_autoload_msrs[] = {
	/* NONE */
};
#define LCD_ARCH_NUM_AUTOLOAD_MSRS 0

enum lcd_arch_reg {
	LCD_ARCH_REGS_RAX = 0,
	LCD_ARCH_REGS_RCX = 1,
	LCD_ARCH_REGS_RDX = 2,
	LCD_ARCH_REGS_RBX = 3,
	LCD_ARCH_REGS_RSP = 4,
	LCD_ARCH_REGS_RBP = 5,
	LCD_ARCH_REGS_RSI = 6,
	LCD_ARCH_REGS_RDI = 7,
	LCD_ARCH_REGS_R8 = 8,
	LCD_ARCH_REGS_R9 = 9,
	LCD_ARCH_REGS_R10 = 10,
	LCD_ARCH_REGS_R11 = 11,
	LCD_ARCH_REGS_R12 = 12,
	LCD_ARCH_REGS_R13 = 13,
	LCD_ARCH_REGS_R14 = 14,
	LCD_ARCH_REGS_R15 = 15,
	LCD_ARCH_REGS_RIP,
	LCD_ARCH_NUM_REGS
};

#define LCD_ARCH_EPT_WALK_LENGTH 4
#define LCD_ARCH_EPTP_WALK_SHIFT 3
#define LCD_ARCH_PTRS_PER_EPTE   (1 << 9)

struct lcd_arch_ept {
	spinlock_t lock;
	unsigned long root_hpa;
	unsigned long vmcs_ptr;
	bool access_dirty_enabled;
};

typedef epte_t lcd_arch_epte_t;

struct lcd_arch_tss {
	/*
	 * Intel SDM V3 7.7
	 *
	 * Base TSS before I/O bitmap, etc.
	 */
	struct x86_hw_tss base_tss;
	/*
	 * I/O bitmap must be at least 8 bits to contain
	 * required 8 bits that are set.
	 *
	 * Intel SDM V1 16.5.2
	 */
	u8 io_bitmap[1];
} __attribute__((packed));

struct lcd_arch {
	/*
	 * Public Data
	 */
	struct {
		u64 gva;
		u64 gpa;
	} run_info;

	/*
	 * Private Data
	 */
	int cpu;
	int launched;
	int vpid;
	struct lcd_arch_vmcs *vmcs;

	struct lcd_arch_ept ept;
	struct desc_struct  *gdt;
	struct lcd_arch_tss *tss;
	struct lcd_ipc_regs *ipc_regs;

	u8  fail;
	u64 exit_reason;
	u64 exit_qualification;
	u32 idt_vectoring_info;
	u32 exit_intr_info;
	u32 error_code;
	u32 vec_no;
	u64 host_rsp;
	u64 regs[LCD_ARCH_NUM_REGS];
	u64 cr2;
	int shutdown;
	int ret_code;

	struct msr_autoload {
#if LCD_ARCH_NUM_AUTOLOAD_MSRS > 0
		struct vmx_msr_entry guest[LCD_ARCH_NUM_AUTOLOAD_MSRS];
		struct vmx_msr_entry host[LCD_ARCH_NUM_AUTOLOAD_MSRS];
#else
		struct vmx_msr_entry *guest;
		struct vmx_msr_entry *host;
#endif
	} msr_autoload;
};

/**
 * Initializes the arch-dependent code for LCD (detects required
 * features, turns on VMX on *all* cpu's).
 */
int lcd_arch_init(void);
/**
 * Turns off VMX on *all* cpu's and tears down arch-dependent code.
 * 
 * Important: All LCDs should be destroyed before calling this
 * routine (otherwise, memory will leak).
 */
void lcd_arch_exit(void);
/**
 * Creates the arch-dependent part of an LCD, and initializes 
 * the settings and most register values.
 */
struct lcd_arch *lcd_arch_create(void);
/**
 * Tears down arch-dep part of LCD. (If LCD is launched on
 * some cpu, it will become inactive.)
 */
void lcd_arch_destroy(struct lcd_arch *vcpu);
/**
 * Runs the LCD on the calling cpu. (If the LCD is active on
 * a different cpu, it will become inactive there.) Kernel
 * preemption is disabled while the LCD is launched, but
 * external interrupts are not disabled and will be handled.
 *
 * Unless the caller does otherwise, kernel preemption is
 * enabled before returning.
 *
 * Returns status code (e.g., LCD_ARCH_STATUS_PAGE_FAULT)
 * so that caller knows why lcd exited and can respond.
 */
int lcd_arch_run(struct lcd_arch *vcpu);

/**
 * Status codes for running LCDs.
 */
enum lcd_arch_status {
	LCD_ARCH_STATUS_PAGE_FAULT = 0,
	LCD_ARCH_STATUS_EXT_INTR   = 1,
	LCD_ARCH_STATUS_EPT_FAULT  = 2,
	LCD_ARCH_STATUS_CR3_ACCESS = 3,
	LCD_ARCH_STATUS_IPC        = 4,
};

/**
 * Lookup ept entry for guest physical address gpa.
 *
 * Set create = 1 to allocate ept page table data structures
 * along the path as needed.
 */
int lcd_arch_ept_walk(struct lcd_arch *vcpu, u64 gpa, int create,
		lcd_arch_epte_t **epte_out);
/**
 * Set the guest physical => host physical mapping in the ept entry.
 */
int lcd_arch_ept_set(lcd_arch_epte_t *epte, u64 hpa);
/**
 * Read the host physical address stored in epte.
 */
u64 lcd_arch_ept_hpa(lcd_arch_epte_t *epte);
/**
 * Simple routine combining ept walk and set.
 *
 * overwrite = 0  => do not overwrite if ept entry is already present
 * overwrite = 1  => overwrite any existing ept entry
 */
int lcd_arch_ept_map_gpa_to_hpa(struct lcd_arch *vcpu, u64 gpa, u64 hpa,
				int create, int overwrite);

/*
 * GDT Layout
 * ==========
 * 0 = NULL
 * 1 = Code segment
 * 2 = Data segment  (%fs, default not present)
 * 3 = Data segment  (%gs, default not present)
 * 4 = Task segment
 *
 * See Intel SDM V3 26.3.1.2, 26.3.1.3 for register requirements.
 * See Intel SDM V3 3.4.2, 3.4.3 for segment register layout
 * See Intel SDM V3 2.4.1 - 2.4.4 for gdtr, ldtr, idtr, tr
 */
#define LCD_ARCH_FS_BASE     0x0UL
#define LCD_ARCH_FS_LIMIT    0xFFFFFFFF
#define LCD_ARCH_GS_BASE     0x0UL
#define LCD_ARCH_GS_LIMIT    0xFFFFFFFF
#define LCD_ARCH_GDTR_BASE   0x0000000000002000UL
#define LCD_ARCH_GDTR_LIMIT  ~(PAGE_SIZE - 1)
#define LCD_ARCH_TSS_BASE    0x0000000000003000UL
/* tss base + limit = address of last byte in tss, hence -1 */
#define LCD_ARCH_TSS_LIMIT   (sizeof(struct lcd_arch_tss) - 1)
#define LCD_ARCH_IDTR_BASE   0x0UL
#define LCD_ARCH_IDTR_LIMIT  0x0 /* no idt right now */

#define LCD_ARCH_CS_SELECTOR   (1 << 3)
#define LCD_ARCH_FS_SELECTOR   (2 << 3)
#define LCD_ARCH_GS_SELECTOR   (3 << 3)
#define LCD_ARCH_TR_SELECTOR   (4 << 3) /* TI must be 0 */
#define LCD_ARCH_LDTR_SELECTOR (0 << 3) /* unusable */

/*
 * Guest Physical Memory Layout
 * ============================
 *
 *                         +---------------------------+ 0xFFFF FFFF FFFF FFFF
 *                         |                           |
 *                         :                           :
 *                         :      Free / Unmapped      :
 *                         :                           :
 *                         |                           |
 * LCD_ARCH_STACK_TOP,---> +---------------------------+ 0x0000 0000 0000 4000
 * LCD_ARCH_FREE           |                           |
 *                         |          Stack            |
 *                         :       (grows down)        : (4 KBs)
 *                         :                           :
 *                         |                           |
 *                         |   IPC Message Registers   |
 * LCD_ARCH_IPC_REGS-----> +---------------------------+ 0x0000 0000 0000 3000
 *                         |           TSS             |
 *                         |    only sizeof(tss) is    | (4 KBs)
 *                         |           used            |
 * LCD_ARCH_TSS_BASE-----> +---------------------------+ 0x0000 0000 0000 2000
 *                         |           GDT             | (4 KBs)
 * LCD_ARCH_GDT_BASE-----> +---------------------------+ 0x0000 0000 0000 1000
 *                         |         Reserved          |
 *                         |       (not mapped)        | (4 KBs)
 *                         +---------------------------+ 0x0000 0000 0000 0000
 */
#define LCD_ARCH_IPC_REGS    0x0000000000003000UL
#define LCD_ARCH_STACK_TOP   0x0000000000004000UL
#define LCD_ARCH_FREE        LCD_ARCH_STACK_TOP


/*
 * Accessor Macros for IPC
 * =======================
 *
 * Based on x86 seL4 message register design.
 *
 * See seL4 manual, 4.1.
 */
#define LCD_ARCH_GET_CAP_REG(vcpu) (vcpu->regs[LCD_ARCH_REGS_RAX])
#define LCD_ARCH_GET_BDG_REG(vcpu) (vcpu->regs[LCD_ARCH_REGS_RBX])
#define LCD_ARCH_GET_TAG_REG(vcpu) (vcpu->regs[LCD_ARCH_REGS_RSI])
#define LCD_ARCH_GET_MSG_REG(vcpu, idx) (__lcd_arch_get_msg_reg(vcpu, idx))
static inline u64 __lcd_arch_get_msg_reg(lcd_arch *vcpu, unsigned int idx)
{
	/*
	 * Message regs 0 and 1 are fast (use machine registers)
	 *
	 * Message regs 2, ... always use the mr's in struct lcd_ipc_regs.
	 *
	 * (The first two mr's in struct lcd_ipc_regs are reserved for
	 * mr's 0 and 1. If the caller wishes to explicitly use those mr's,
	 * they should do so by manually accessing struct lcd_ipc_regs.)
	 */
	if (idx == 0)
		return vcpu->regs[LCD_ARCH_REGS_EDI];
	else if (idx == 1)
		return vcpu->regs[LCD_ARCH_REGS_EBP];
	else
		return vcpu->ipc_regs->mr[idx];
}

#define LCD_ARCH_SET_CAP_REG(vcpu, val) ({                    \
			vcpu->regs[LCD_ARCH_REGS_RAX] = val;  \
		})
#define LCD_ARCH_SET_BDG_REG(vcpu, val) ({                    \
			vcpu->regs[LCD_ARCH_REGS_RBX] = val;  \
		})
#define LCD_ARCH_SET_TAG_REG(vcpu, val) ({                    \
			vcpu->regs[LCD_ARCH_REGS_RSI] = val;  \
		})
#define LCD_ARCH_SET_MSG_REG(vcpu, idx, val) ({                 \
			__lcd_arch_set_msg_reg(vcpu, val, idx);	\
		})
static inline void __lcd_arch_set_msg_reg(lcd_arch *vcpu, unsigned int idx,
					u64 val)
{
	/*
	 * Message regs 0 and 1 are fast (use machine registers)
	 *
	 * Message regs 2, ... always use the mr's in struct lcd_ipc_regs.
	 *
	 * (The first two mr's in struct lcd_ipc_regs are reserved for
	 * mr's 0 and 1. If the caller wishes to explicitly use those mr's,
	 * they should do so by manually accessing struct lcd_ipc_regs.)
	 */
	if (idx == 0)
		vcpu->regs[LCD_ARCH_REGS_EDI] = val;
	else if (idx == 1)
		vcpu->regs[LCD_ARCH_REGS_EBP] = val;
	else
		vcpu->ipc_regs->mr[idx] = val;
}

#endif  /* LCD_DOMAINS_ARCH_H */
