/* SPDX-License-Identifier: GPL-2.0 */
#include "hypsec.h"
#include "MmioOps.h"

void __hyp_text handle_smmu_write(u32 hsr, u64 fault_ipa, u32 len, u32 index)
{
	u64 offset, val, cbndx;
	u32 ret, write_val;

	offset = read_sysreg_el2(far) & ARM_SMMU_OFFSET_MASK;
	write_val = 0U;

	if (offset < ARM_SMMU_GLOBAL_BASE)
	{
		ret = handle_smmu_global_access(hsr, offset, index);
		if (ret == 0U)
		{
			print_string("\rsmmu invalid write: global access\n");
			v_panic();
		}
		else
		{
			__handle_smmu_write(hsr, fault_ipa, len, 0UL, write_val);
		}
	}
	else {
		ret = handle_smmu_cb_access(offset);
		if (ret == 0U)
		{
			print_string("\rsmmu invalid write: cb access\n");
			v_panic();	
		}
		else
		{
			if (ret == 2)
			{
				cbndx = smmu_get_cbndx(offset);
				val = get_smmu_cfg_hw_ttbr(cbndx, index);
				write_val = 1U;
				__handle_smmu_write(hsr, fault_ipa, len, val, write_val);
				/*print_string("\rwrite TTBR0\n");
				print_string("\roffset\n");
				printhex_ul(offset);
				print_string("\rcbndx\n");
				printhex_ul(cbndx);
				print_string("\rindex\n");
				printhex_ul(index);
				print_string("\rTTBR0\n");
				printhex_ul(val);
				u64 data = host_get_mmio_data(hsr);
				print_string("\rHOST TTBR0\n");
				printhex_ul(data);*/
			}
			//else if (ret == 3)
			//{
			//	u64 data = host_get_mmio_data(hsr);
			//	print_string("\rHOST TTBCR\n");
			//	printhex_ul(data);
			//	__handle_smmu_write(hsr, fault_ipa, len, 0UL, write_val);
			//}
			else
			{
				__handle_smmu_write(hsr, fault_ipa, len, 0UL, write_val);
			}
		}
	}
}

void __hyp_text handle_smmu_read(u32 hsr, u64 fault_ipa, u32 len)
{
	u64 offset;

	offset = fault_ipa & ARM_SMMU_OFFSET_MASK;
	if (offset < ARM_SMMU_GLOBAL_BASE)
	{
		__handle_smmu_read(hsr, fault_ipa, len);
	}
	else
	{
		__handle_smmu_read(hsr, fault_ipa, len);
	}	
}
