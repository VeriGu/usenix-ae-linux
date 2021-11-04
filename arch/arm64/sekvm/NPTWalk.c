/* SPDX-License-Identifier: GPL-2.0 */
#include "hypsec.h"

/*
 * NPTWalk
 */

u32 __hyp_text get_npt_level(u32 vmid, u64 addr)
{
	u64 vttbr, pgd, pud, pmd;u32 ret;

	vttbr = get_pt_vttbr(vmid);
	pgd = walk_pgd(vmid, vttbr, addr, 0U);

	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 0U);
	}
	else
	{
		pud = pgd;
	}

	pmd = walk_pmd(vmid, pud, addr, 0U);

	if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
	{
		u64 pte = walk_pte(vmid, pmd, addr);
		if (phys_page(pte) == 0UL)
		{
			ret = 0U;
		}
		else
		{
			ret = 3U;
		}
	}
	else
	{
		if (phys_page(pmd) == 0UL)
		{
			ret = 0U;
		}
		else
		{
			ret = 2U;
		}
	}

	return check(ret);
}

u64 __hyp_text walk_npt(u32 vmid, u64 addr)
{
	u64 vttbr, pgd, pud, pmd, ret, pte;

	vttbr = get_pt_vttbr(vmid);
	pgd = walk_pgd(vmid, vttbr, addr, 0U);

	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 0U);
	}
	else
	{
		pud = pgd;
	}

	pmd = walk_pmd(vmid, pud, addr, 0U);

	if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
	{
		pte = walk_pte(vmid, pmd, addr);
		ret = pte;
	}
	else
	{
		ret = pmd;
	}

	return check64(ret);
}

void __hyp_text set_npt(u32 vmid, u64 addr, u32 level, u64 pte)
{
	u64 vttbr, pgd, pud, pmd;

	vttbr = get_pt_vttbr(vmid);	
	pgd = walk_pgd(vmid, vttbr, addr, 1U);
	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 1U);
	}
	else
	{
		pud = pgd;
	}

	if (level == 2U)
	{
		pmd = walk_pmd(vmid, pud, addr, 0U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
		{
			print_string("\rset existing npt: pmd\n");
			v_panic();
		}
		else
		{
			v_set_pmd(vmid, pud, addr, pte);
		}
	}
	else
	{
		pmd = walk_pmd(vmid, pud, addr, 1U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
		{
			v_set_pte(vmid, pmd, addr, pte);
		}
		else
		{
			print_string("\rset existing npt: pte\n");
			v_panic();
		}
	}
}

void mem_load_ref(u64 gfn, u32 reg)
{
	mem_load_raw(gfn, reg);
}

void mem_store_ref(u64 gfn, u32 reg)
{
	mem_store_raw(gfn, reg);
}
