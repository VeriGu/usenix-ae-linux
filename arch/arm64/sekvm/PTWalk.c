/* SPDX-License-Identifier: GPL-2.0 */
#include "hypsec.h"
#include "MmioOps.h"

/*
 * PTWalk
 */

u64 __hyp_text walk_pgd(u32 vmid, u64 vttbr, u64 addr, u32 alloc)
{
	u64 vttbr_pa, ret, pgd_idx, pgd, pgd_pa;

	ret = 0UL;
	vttbr_pa = phys_page(vttbr);

	if (vmid == COREVISOR)
	{
		pgd_idx = pgd_index(addr);
	}
	else
	{
		pgd_idx = pgd_idx(addr);
	}

	pgd = pt_load(vmid, vttbr_pa | (pgd_idx * 8UL));
	if (pgd == 0UL && alloc == 1U)
	{
		pgd_pa = alloc_s2pt_pgd(vmid);
		pgd = pgd_pa | PUD_TYPE_TABLE;
		pt_store(vmid, vttbr_pa | (pgd_idx * 8UL), pgd);
	}

	ret = pgd;
	return check64(ret);
}

u64 __hyp_text walk_pud(u32 vmid, u64 pgd, u64 addr, u32 alloc)
{
	u64 pgd_pa, ret, pud_idx, pud, pud_pa;

	ret = 0UL;

	if (pgd != 0UL)
	{
		pgd_pa = phys_page(pgd);
		pud_idx = pud_idx(addr);
		pud = pt_load(vmid, pgd_pa | (pud_idx * 8UL));
		if (pud == 0UL && alloc == 1U)
		{
			pud_pa = alloc_s2pt_pud(vmid);
			pud = pud_pa | PUD_TYPE_TABLE;
			pt_store(vmid, pgd_pa | (pud_idx * 8UL), pud);
		}
		ret = pud;
	}
	return check64(ret);
}

u64 __hyp_text walk_pmd(u32 vmid, u64 pud, u64 addr, u32 alloc)
{
	u64 pud_pa, ret, pmd_idx, pmd, pmd_pa;

	ret = 0UL;
	if (pud != 0UL)
	{
		pud_pa = phys_page(pud);
		pmd_idx = pmd_idx(addr);
		pmd = pt_load(vmid, pud_pa | (pmd_idx * 8));

		if (pmd == 0UL && alloc == 1U)
		{
			pmd_pa = alloc_s2pt_pmd(vmid);
			pmd = pmd_pa | PMD_TYPE_TABLE;
			pt_store(vmid, pud_pa | (pmd_idx * 8UL), pmd);
		}
		ret = pmd;
	}
	return check64(ret);
}

u64 __hyp_text walk_pte(u32 vmid, u64 pmd, u64 addr)
{
	u64 pmd_pa, ret, pte_idx;

	ret = 0UL;
	if (pmd != 0UL)
	{
		pmd_pa = phys_page(pmd);
		pte_idx = pte_idx(addr);
		ret = pt_load(vmid, pmd_pa | (pte_idx * 8UL));
	}
	return check64(ret);
}

void __hyp_text v_set_pmd(u32 vmid, u64 pud, u64 addr, u64 pmd)
{
	u64 pud_pa, pmd_idx;

	pud_pa = phys_page(pud);
	pmd_idx = pmd_idx(addr);
	pmd |= PMD_MARK;
	pt_store(vmid, pud_pa | (pmd_idx * 8UL), pmd);
}

void __hyp_text v_set_pte(u32 vmid, u64 pmd, u64 addr, u64 pte)
{
	u64 pmd_pa, pte_idx;
	pmd_pa = phys_page(pmd);
	pte_idx = pte_idx(addr);
	pte |= PTE_MARK;
	pt_store(vmid, pmd_pa | (pte_idx * 8UL), pte);
}
