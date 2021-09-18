#ifndef __ARM_STAGE2_MMIO__
#define __ARM_STAGE2_MMIO__

/* We map a smmu_cfg to each context bank on the hardware.
 * We hardcode the value here since we have 8 ctxtbnk on Seattle.
 */

#define SMMU_NUM_CTXT_BANKS	8
#define SMMU_NUM		2
#define EL2_SMMU_CFG_SIZE	SMMU_NUM_CTXT_BANKS * SMMU_NUM

/* FIXME: Hardcoded SMMU addresses now.. */
#define SMMU_BASE(smmu)		smmu.phys_base
#define SMMU_SIZE(smmu)		smmu.size

/* Maximum number of context banks per SMMU */
#define ARM_SMMU_MAX_CBS		128

struct el2_smmu_cfg {
	u32 vmid;
	u64 hw_ttbr;
};


struct el2_arm_smmu_device {
	u64				phys_base;
	u64				size;
	unsigned long			pgshift;

	#define ARM_SMMU_FEAT_COHERENT_WALK	(1 << 0)
	#define ARM_SMMU_FEAT_STREAM_MATCH	(1 << 1)
	#define ARM_SMMU_FEAT_TRANS_S1		(1 << 2)
	#define ARM_SMMU_FEAT_TRANS_S2		(1 << 3)
	#define ARM_SMMU_FEAT_TRANS_NESTED	(1 << 4)

	u32				features;
#define ARM_SMMU_OPT_SECURE_CFG_ACCESS (1 << 0)
	u32				options;
	u32				num_context_banks;
	u32				num_s2_context_banks;

	u32				num_mapping_groups;

	unsigned long			va_size;
	unsigned long			ipa_size;
	unsigned long			pa_size;

	u32				num_global_irqs;
	u32				num_context_irqs;
	bool				exists;

	unsigned long			hyp_base;
	u32				index;
};

struct el2_smmu_cfg* alloc_smmu_cfg(struct el2_data *el2_data);
#endif /* __ARM_STAGE2_MMIO__ */
