/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HYPSEC_CONSTANTS_H
#define HYPSEC_CONSTANTS_H

#define V_INVALID	0xFFFFFFFF
#define INVALID64	0xFFFFFFFFFFFFFFFF
#define INVALID_MEM	-1

#define PT_POOL_START 0x10000
#define PT_POOL_PER_VM STAGE2_VM_POOL_SIZE
#define MAX_VM_NUM 56 
#define MAX_CTXT_NUM 1024
#define MAX_LOAD_INFO_NUM 5
/*
#define KVM_PHYS_SIZE 4096UL
#define PAGE_SIZE 4096UL
#define PAGE_GUEST 0UL
#define PAGE_NONE 0UL
#define PAGE_S2_KERNEL 0UL
#define PAGE_S2_DEVICE 0UL
#define PAGE_HYP 0UL
#define PAGE_S2 0UL
#define PTE_S2_RDWR 0UL
#define PMD_S2_RDWR 0UL
#define PTE_S2_XN 0UL
#define PMD_S2_XN 0UL

#define PHYS_MASK 1UL
#define PAGE_MASK 1UL
#define S2_PGDIR_SHIFT 1UL
#define PTRS_PER_PGD 1UL
#define S2_PMD_SHIFT 1UL
#define PTRS_PER_PMD 1UL
#define PTRS_PER_PTE 1UL
#define PUD_TYPE_TABLE 1UL
#define PMD_TYPE_TABLE 1UL
#define VTTBR_VMID_SHIFT 1UL
#define S2_PGD_PAGES_NUM 1UL
#define MEMBLOCK_NOMAP 1UL
*/
#define MAX_MMIO_ADDR 0x40000000
#define S2_RDWR PTE_S2_RDWR 
#define PMD_PAGE_MASK PMD_MASK 

#define S2_PTE_SHIFT PAGE_SHIFT
#define PMD_TABLE_SHIFT PMD_SHIFT 

#define COREVISOR EL2_MAX_VMID
#define HOSTVISOR 0
#define MAX_SHARE_COUNT 100
#define UNUSED 0
//#define READY 1
//#define VERIFIED 2
//#define ACTIVE 3

//Boot
#define SHARED_KVM_START 1
#define SHARED_VCPU_START 1
#define VCPU_PER_VM	8

//#define SHADOW_SYS_REGS_SIZE 1
#define V_SP		31
#define V_PC		32
#define V_PSTATE 	33
#define	V_SP_EL1	34
#define V_ELR_EL1	35
#define V_SPSR_EL1	36
#define V_SPSR_ABT	37
#define V_SPSR_UND	38
#define V_SPSR_IRQ	39
#define V_SPSR_FIQ	40
#define V_FAR_EL2	41
#define V_HPFAR_EL2	42
#define V_HCR_EL2	43
#define V_EC		44
#define V_DIRTY		45
#define V_FLAGS		46
#define SYSREGS_START	47

// Do we need the 32 bit registers?
#define V_ESR_EL1	41 + ESR_EL1
#define V_SPSR_0 8
#define V_HPFAR_MASK 65535UL

/*
#define PENDING_FSC_FAULT 1UL //????????????
#define ARM_EXCEPTION_TRAP 0UL
#define PENDING_EXCEPT_INJECT_FLAG 2UL //????????
#define DIRTY_PC_FLAG 4UL //??????????????
#define ESR_ELx_EC_MASK 63UL
#define ESR_ELx_EC_SHIFT 67108864UL // (1 << 26)
#define PSCI_0_2_FN64_CPU_ON 4UL //?????????
#define PSCI_0_2_FN_AFFINITY_INFO 5UL //?????????
#define PSCI_0_2_FN64_AFFINITY_INFO 6UL //?????????
#define PSCI_0_2_FN_SYSTEM_OFF 7UL //?????????
#define ESR_ELx_EC_WFx 8UL //?????????????????
#define ESR_ELx_EC_HVC32 9UL
#define ESR_ELx_EC_HVC64 10UL
#define ESR_ELx_EC_IABT_LOW 11UL
#define ESR_ELx_EC_DABT_LOW 12UL
*/
#define PSTATE_FAULT_BITS_64 11UL

// Micros

#define PT_POOL_SIZE (STAGE2_PAGES_SIZE)
#define phys_page(addr) ((addr) & PHYS_MASK & PAGE_MASK)
#define pgd_idx(addr)	stage2_pgd_index(addr)
#define pud_idx(addr)	pud_index(addr)
#define pmd_idx(addr)	pmd_index(addr)
#define pte_idx(addr)	pte_index(addr)
#define v_pmd_table(pmd)	(pmd & PMD_TYPE_MASK)
#define writable(pte) (((pte) >> 2UL) & 1UL)

#define SMMU_HOST_OFFSET 1000000000UL
#define PMD_PAGE_NUM	512
#endif //HYPSEC_CONSTANTS_H
