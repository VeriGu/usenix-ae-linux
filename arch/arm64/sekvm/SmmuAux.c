#include "hypsec.h"
#include "MmioOps.h"

u32 __hyp_text is_smmu_range(u64 addr)
{
	u32 total_smmu, i, res;
	u64 base, size;

	total_smmu = get_smmu_num();
	i = 0U;
	res = V_INVALID;

	while (i < total_smmu)
	{
		base = get_smmu_base(i);
		size = get_smmu_size(i);
		if ((base <= addr) && (addr < base + size))
		{
			res = i;
		}
		i = i + 1U;
	}
	return res;
}

//FIXME: handle_host_mmio(u64 addr, u32 index, u32 hsr)
void __hyp_text handle_host_mmio(u64 index, u32 hsr)
{
	u64 base_addr;
	u64 fault_ipa;
	u32 is_write, len;

	/* Following three lines are maco */
	base_addr = get_smmu_hyp_base(index);
	fault_ipa = host_get_fault_ipa(base_addr); 
	len = host_dabt_get_as(hsr);
	is_write = host_dabt_is_write(hsr);

	if (is_write == 0U)
	{
		handle_smmu_read(hsr, fault_ipa, len);
		host_skip_instr();
	}
	else
	{
		handle_smmu_write(hsr, fault_ipa, len, index);
		host_skip_instr();
	}
}
