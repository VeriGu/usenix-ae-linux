/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM_VERIFIED_MMIO__
#define __ARM_VERIFIED_MMIO__

typedef u64 arm_lpae_iopte;

/* Configuration registers */
#define ARM_SMMU_GR0_sCR0		0x0
#define ARM_SMMU_GR0_sCR2		0x8

/* Stream mapping registers */
#define ARM_SMMU_GR0_SMR(n)		(0x800 + ((n) << 2))

/* Stream to Context registers */
#define ARM_SMMU_GR0_S2CR(n)		(0xc00 + ((n) << 2))

/* Context bank attribute registers */
#define ARM_SMMU_GR1_CBAR(n)		(0x0 + ((n) << 2))

/* Translation context bank */
#define ARM_SMMU_CB_BASE(smmu)		(SMMU_BASE(smmu) + (SMMU_SIZE(smmu) >> 1))
#define ARM_SMMU_CB(pgshift, n)		((n) * (1 << pgshift))

#define ARM_SMMU_CB_TTBR0		0x20
#define ARM_SMMU_CB_TTBR1		0x28
#define ARM_SMMU_CB_TTBCR		0x30
#define ARM_SMMU_CB_CONTEXTIDR		0x34

#define for_each_smmu_cfg(i) \
	for ((i) = 0; i < EL2_SMMU_CFG_SIZE; (i)++)

/* Page table bits */
#define ARM_LPAE_PTE_TYPE_SHIFT		0
#define ARM_LPAE_PTE_TYPE_MASK		0x3

#define ARM_LPAE_MAX_ADDR_BITS		48
#define ARM_LPAE_PGD_S2_SHIFT		30
#define ARM_LPAE_PUD_S2_SHIFT		0
#define ARM_LPAE_PMD_S2_SHIFT		21
#define ARM_LPAE_PTE_S2_SHIFT		12

#define ARM_LPAE_PTE_TYPE_BLOCK		1
#define ARM_LPAE_PTE_TYPE_TABLE		3
#define ARM_LPAE_PTE_TYPE_PAGE		3

#define ARM_LPAE_PTE_NSTABLE		(((arm_lpae_iopte)1) << 63)
#define ARM_LPAE_PTE_XN			(((arm_lpae_iopte)3) << 53)
#define ARM_LPAE_PTE_AF			(((arm_lpae_iopte)1) << 10)
#define ARM_LPAE_PTE_SH_NS		(((arm_lpae_iopte)0) << 8)
#define ARM_LPAE_PTE_SH_OS		(((arm_lpae_iopte)2) << 8)
#define ARM_LPAE_PTE_SH_IS		(((arm_lpae_iopte)3) << 8)
#define ARM_LPAE_PTE_NS			(((arm_lpae_iopte)1) << 5)
#define ARM_LPAE_PTE_VALID		(((arm_lpae_iopte)1) << 0)

#define ARM_LPAE_START_LVL	1
#define ARM_LPAE_MAX_LEVELS	4
#define ARM_LPAE_GRANULE	12

#define iopte_deref(pte)					\
	(__el2_va((pte) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1)	\
	& ~(ARM_LPAE_GRANULE - 1ULL)))

#define iopte_type(pte)					\
	(((pte) >> ARM_LPAE_PTE_TYPE_SHIFT) & ARM_LPAE_PTE_TYPE_MASK)

#define ARM_LPAE_PTE_S2_IDX(iova) \
	((iova >> ARM_LPAE_PTE_S2_SHIFT) & 0x1ff)

#define ARM_LPAE_PMD_S2_IDX(iova) \
	((iova >> ARM_LPAE_PMD_S2_SHIFT) & 0x1ff)

#define ARM_LPAE_PUD_S2_IDX(iova) \
	(iova >> ARM_LPAE_PUD_S2_SHIFT)

#define ARM_LPAE_PGD_S2_IDX(iova) \
	((iova >> ARM_LPAE_PGD_S2_SHIFT) & 0x3ff)

#define ARM_LPAE_MAX_ADDR_BITS		48
#define iopte_to_pfn(pte) \
	(((pte) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1)) >> 12)

#define pfn_to_iopte(pfn)					\
	(((pfn) << 12) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1))

#define CBAR_VMID_SHIFT			0
#define CBAR_VMID_MASK			0xff
#define CBAR_TYPE_SHIFT			16
#define CBAR_TYPE_MASK			0x3
#define CBAR_TYPE_S2_TRANS		(0 << CBAR_TYPE_SHIFT)

#define CBA2R_VMID_SHIFT		16
#define CBA2R_VMID_MASK			0xffff

#define sCR0_SMCFCFG_SHIFT		21

#define	get_cbndx(offset, base)		(offset - base) >> 2

#define ARM_SMMU_PGSHIFT	12U
//(1 << ARM_SMMU_PGSHIFT) - 1
#define ARM_SMMU_PGSHIFT_MASK	4095U
//1 << ARM_SMMU_PGSHIFT
#define ARM_SMMU_GR1_BASE	4096U
//ARM_SMMU_GR1_BASE + 0x800
#define ARM_SMMU_GR1_END	6144U

#define ARM_SMMU_SIZE		65536U
#define ARM_SMMU_OFFSET_MASK	65535U
#define ARM_SMMU_GLOBAL_BASE	32768U


static inline u32 host_dabt_get_as(u32 hsr)
{
	return 1 << ((hsr & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT);
}

static inline bool host_dabt_is_write(u32 hsr)
{
	return !!(hsr & ESR_ELx_WNR);
}

static inline u64 host_get_fault_ipa(phys_addr_t addr)
{
	//return (addr | (read_sysreg_el2(far) & ((1 << 12) - 1)));
	return (addr | (read_sysreg_el2(far) & ARM_SMMU_OFFSET_MASK));
}

static inline int host_dabt_get_rd(u32 hsr)
{
	return (hsr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
}

static inline void __hyp_text host_skip_instr(void)
{
	u64 val = read_sysreg(elr_el2);
	write_sysreg(val + 4, elr_el2);
}

#endif /* __ARM_VERIFIED_MMIO__ */
