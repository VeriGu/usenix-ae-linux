#include "hypsec.h"

/*
 * MmioPTWalk
 */

u64 __hyp_text walk_smmu_pgd(u64 ttbr, u64 addr, u32 alloc)
{
	u64 ttbr_pa, ret, pgd_idx, pgd, pgd_pa;

	ret = 0UL;
	ttbr_pa = phys_page(ttbr);
	pgd_idx = stage2_pgd_index(addr);
	pgd = smmu_pt_load(ttbr_pa | (pgd_idx * 8UL));
	if (pgd == 0UL && alloc == 1U)
	{
		pgd_pa = alloc_smmu_pgd_page();
		pgd = pgd_pa | PMD_TYPE_TABLE;
		smmu_pt_store(ttbr_pa | pgd_idx * 8UL, pgd);
	}
	ret = pgd;
	return check64(ret);
}

u64 __hyp_text walk_smmu_pmd(u64 pgd, u64 addr, u32 alloc)
{
	u64 pgd_pa, ret, pmd_idx, pmd, pmd_pa;

	ret = 0UL;
	if (pgd != 0UL)
	{
		pgd_pa = phys_page(pgd);
		pmd_idx = pmd_index(addr);
		pmd = smmu_pt_load(pgd_pa | (pmd_idx * 8));
		pmd_pa = phys_page(pmd);
		if (pmd_pa == 0UL && alloc == 1U)
		{
			pmd_pa = alloc_smmu_pmd_page();
			pmd = pmd_pa | PMD_TYPE_TABLE;
			smmu_pt_store(pgd_pa | (pmd_idx * 8UL), pmd);
		}
		ret = pmd;
	}
	return check64(ret);
}

u64 __hyp_text walk_smmu_pte(u64 pmd, u64 addr)
{
	u64 pmd_pa, ret, pte_idx;

	ret = 0UL;
	if (pmd != 0UL)
	{
		pmd_pa = phys_page(pmd);
		pte_idx = pte_index(addr);
		ret = smmu_pt_load(pmd_pa | (pte_idx * 8UL));
	}
	return check64(ret);
}

void __hyp_text set_smmu_pte(u64 pmd, u64 addr, u64 pte)
{
	u64 pmd_pa, pte_idx;

	pmd_pa = phys_page(pmd);
	pte_idx = pte_index(addr);
	smmu_pt_store(pmd_pa | (pte_idx * 8UL), pte);
}
