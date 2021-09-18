#include "hypsec.h"

/*
 * MmioSPTWalk
 */

void __hyp_text clear_smmu_pt(u32 cbndx, u32 index) 
{
	smmu_pt_clear(cbndx, index);
}

u64 __hyp_text walk_smmu_pt(u32 cbndx, u32 num, u64 addr)
{
	u64 ttbr, pgd, pmd, ret;

	ttbr = get_smmu_cfg_hw_ttbr(cbndx, num);
	pgd = walk_smmu_pgd(ttbr, addr, 0U);
	pmd = walk_smmu_pmd(pgd, addr, 0U);
	ret = walk_smmu_pte(pmd, addr);
	return ret;
}

void __hyp_text set_smmu_pt(u32 cbndx, u32 num, u64 addr, u64 pte)
{
	u64 ttbr, pgd, pmd;

	ttbr = get_smmu_cfg_hw_ttbr(cbndx, num);
	if (ttbr == 0UL)
	{
		print_string("\rset smmu pt: vttbr = 0\n");
		v_panic();
	}
	else 
	{
		pgd = walk_smmu_pgd(ttbr, addr, 1U);
		pmd = walk_smmu_pmd(pgd, addr, 1U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
		{
			set_smmu_pte(pmd, addr, pte);
		}
		else
		{
			v_panic();
		}
	}
}
