/* SPDX-License-Identifier: GPL-2.0 */
#include "hypsec.h"
#include "MmioOps.h"

u64 __hyp_text host_get_mmio_data(u32 hsr)
{
	int rt;

	rt = host_dabt_get_rd(hsr);
	return get_host_regs(rt);
}

u64 __hyp_text smmu_init_pte(u64 prot, u64 paddr)
{
	u64 val;

	val = prot;
	val |= ARM_LPAE_PTE_AF | ARM_LPAE_PTE_SH_IS;
	val |= pfn_to_iopte(paddr >> 12);
	val |= ARM_LPAE_PTE_TYPE_PAGE;

	return val;
}

u64 __hyp_text smmu_get_cbndx(u64 offset)
{
	u64 cbndx = 0;
	offset -= ARM_SMMU_GLOBAL_BASE;
	cbndx = offset >> ARM_SMMU_PGSHIFT;
	return cbndx;
}
