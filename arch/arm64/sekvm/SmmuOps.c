/* SPDX-License-Identifier: GPL-2.0 */
#include "hypsec.h"
#include "MmioOps.h"

u32 __hyp_text emulate_mmio(u64 addr, u32 hsr)
{
	u32 ret;

	acquire_lock_smmu();
	ret = is_smmu_range(addr);
	if (ret != V_INVALID)
	{
		handle_host_mmio(ret, hsr);
	}
	release_lock_smmu();
	return ret;
}

void __hyp_text  __el2_free_smmu_pgd(u32 cbndx, u32 index)
{
	u32 vmid, power;

	acquire_lock_smmu();
	vmid = get_smmu_cfg_vmid(cbndx, index);
	if (vmid != V_INVALID)
	{
		power = get_vm_poweron(vmid);
		if (power == 0U)
		{
			set_smmu_cfg_vmid(cbndx, index, V_INVALID);
		}
		else
		{
			v_panic();
		}
	}
	release_lock_smmu();
}

void __hyp_text  __el2_alloc_smmu_pgd(u32 cbndx, u32 vmid, u32 index)
{
	u32 target_vmid, num_context_banks;

	acquire_lock_smmu();
	num_context_banks = get_smmu_num_context_banks(index);
	if (cbndx < num_context_banks)
	{
		target_vmid = get_smmu_cfg_vmid(cbndx, index);
		if (target_vmid == V_INVALID)
		{
			set_smmu_cfg_vmid(cbndx, index, vmid);
			alloc_smmu(vmid, cbndx, index);
		}
	}
	else
	{
		print_string("\rsmmu pgd alloc panic\n");
		v_panic();
	}
	release_lock_smmu();
}

void __hyp_text smmu_assign_page(u32 cbndx, u32 index, u64 pfn, u64 gfn)
{
	u32 vmid;

	acquire_lock_smmu();
	vmid = get_smmu_cfg_vmid(cbndx, index);
	if (vmid != V_INVALID)
	{
		assign_smmu(vmid, pfn, gfn);
	}
	release_lock_smmu();
}

void __hyp_text smmu_map_page(u32 cbndx, u32 index, u64 iova, u64 pte)
{
	u32 vmid;

	acquire_lock_smmu();
	vmid = get_smmu_cfg_vmid(cbndx, index);
	if (vmid != V_INVALID)
	{
		map_smmu(vmid, cbndx, index, iova, pte);
	}
	release_lock_smmu();
}

u64 __hyp_text __el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 index)
{
	u64 pte, ret;

	pte = walk_spt(cbndx, index, iova);
	ret = phys_page(pte) + (iova & (PAGE_SIZE - 1));
	return ret;
}

void __hyp_text __el2_arm_lpae_clear(u64 iova, u32 cbndx, u32 index)
{
	u32 vmid;

	acquire_lock_smmu();
	vmid = get_smmu_cfg_vmid(cbndx, index);
	if (vmid != V_INVALID)
	{
		clear_smmu(vmid, cbndx, index, iova);
	}
	release_lock_smmu();	
}
