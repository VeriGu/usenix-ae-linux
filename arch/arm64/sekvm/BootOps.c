/* SPDX-License-Identifier: GPL-2.0 */
#include "hypsec.h"

/*
 * BootOps
 */

u64 __hyp_text search_load_info(u32 vmid, u64 addr)
{
	u32 num, load_idx;
	u64 ret, base, size, remap_addr; 
	acquire_lock_vm(vmid);
	num = get_vm_next_load_idx(vmid);
	load_idx = 0U;
	ret = 0UL;
	while (num)
	{
		base = get_vm_load_addr(vmid, load_idx);
		size = get_vm_load_size(vmid, load_idx);
		remap_addr = get_vm_remap_addr(vmid, load_idx);
		if (addr >= base && addr < base + size)
		{
			ret = (addr - base) + remap_addr;
		}
		load_idx += 1U;
		num -= 1U;
	}
	release_lock_vm(vmid);
	return ret;
} 

void __hyp_text set_vcpu_active(u32 vmid, u32 vcpuid)
{
	u32 vm_state, vcpu_state;
	acquire_lock_vm(vmid);
	vm_state = get_vm_state(vmid);
	vcpu_state = get_vcpu_state(vmid, vcpuid);
	if (vm_state == VERIFIED && vcpu_state == READY)
	{
		set_vcpu_state(vmid, vcpuid, ACTIVE);
	}
	else
	{
		print_string("\rset vcpu active\n");
		v_panic();
	}
	release_lock_vm(vmid);
}

void __hyp_text set_vcpu_inactive(u32 vmid, u32 vcpuid)
{
	u32 vcpu_state;
	acquire_lock_vm(vmid);
	vcpu_state = get_vcpu_state(vmid, vcpuid);
	if (vcpu_state == ACTIVE)
	{
		set_vcpu_state(vmid, vcpuid, READY);
	}
	else
	{
		print_string("\rset vcpu inactive\n");
		v_panic();
	}
	release_lock_vm(vmid);
}

void __hyp_text register_vcpu(u32 vmid, u32 vcpuid)
{
	u32 vm_state, vcpu_state;
	u64 vcpu;
	acquire_lock_vm(vmid);
	vm_state = get_vm_state(vmid);
	vcpu_state = get_vcpu_state(vmid, vcpuid);
	if (vm_state == READY || vcpu_state == UNUSED)
	{
		vcpu = get_shared_vcpu(vmid, vcpuid);
		set_vm_vcpu(vmid, vcpuid, vcpu);
		set_vcpu_state(vmid, vcpuid, READY);
		set_shadow_ctxt(vmid, vcpuid, V_DIRTY, INVALID64);
	}
	else
	{
		print_string("\rregister vcpu\n");
		v_panic(); 
	}
	release_lock_vm(vmid);
}

u32 __hyp_text register_kvm()
{
	u32 vmid, state;
	u64 kvm;

	vmid = gen_vmid();
	acquire_lock_vm(vmid);
	state = get_vm_state(vmid);
	if (state == UNUSED)
	{
		set_vm_inc_exe(vmid, 0U);
		kvm = get_shared_kvm(vmid);
		set_vm_kvm(vmid, kvm);
		set_vm_state(vmid, READY);
		set_vm_public_key(vmid);
	}
	else
	{
		print_string("\rregister kvm\n");
		v_panic();        
	}
	release_lock_vm(vmid);
	return check(vmid);
}

u32 __hyp_text set_boot_info(u32 vmid, u64 load_addr, u64 size)
{
	u32 state, load_idx;
	u64 page_count, remap_addr;

	acquire_lock_vm(vmid);
	state = get_vm_state(vmid);
	load_idx = 0U;
	if (state == READY)
	{
		load_idx = get_vm_next_load_idx(vmid);
		if (load_idx < MAX_LOAD_INFO_NUM)
		{
			set_vm_next_load_idx(vmid, load_idx + 1U);
			page_count = (size + PAGE_SIZE - 1UL) / PAGE_SIZE;
			remap_addr = alloc_remap_addr(page_count);
			set_vm_load_addr(vmid, load_idx, load_addr);
			set_vm_load_size(vmid, load_idx, size);
			set_vm_remap_addr(vmid, load_idx, remap_addr);
			set_vm_mapped_pages(vmid, load_idx, 0U);
			set_vm_load_signature(vmid, load_idx);
		}
	}
	else
	{
		v_panic();
	}
	release_lock_vm(vmid);
	return check(load_idx);
}

void __hyp_text remap_vm_image(u32 vmid, u64 pfn, u32 load_idx)
{
	u32 state, load_info_cnt;
	u64 size, page_count, mapped, remap_addr, target;

	acquire_lock_vm(vmid);
	state = get_vm_state(vmid);
	if (state == READY)
	{
		load_info_cnt = get_vm_next_load_idx(vmid);
		if (load_idx < load_info_cnt)
		{
			size = get_vm_load_size(vmid, load_idx);
			page_count = (size + PAGE_SIZE - 1UL) / PAGE_SIZE;
			mapped = get_vm_mapped_pages(vmid, load_idx);
			remap_addr = get_vm_remap_addr(vmid, load_idx);
			target = remap_addr + mapped * PAGE_SIZE;
			if (mapped < page_count)
			{
				mmap_s2pt(COREVISOR, target, 3UL,
					pfn * PAGE_SIZE + pgprot_val(PAGE_HYP));
				set_vm_mapped_pages(vmid, load_idx, mapped + 1UL);
			}
		}
	}
	else
	{
		print_string("\remap vm image\n");
		v_panic();
	}
	release_lock_vm(vmid);
}

void __hyp_text verify_and_load_images(u32 vmid)
{
	u32 state, load_info_cnt, load_idx, valid;
	u64 load_addr, remap_addr, mapped;

	acquire_lock_vm(vmid);
	state = get_vm_state(vmid);
	if (state == READY)
	{
		load_info_cnt = get_vm_next_load_idx(vmid);
		load_idx = 0U;
		while (load_idx < load_info_cnt)
		{
			load_addr = get_vm_load_addr(vmid, load_idx);
			remap_addr = get_vm_remap_addr(vmid, load_idx);
			mapped = get_vm_mapped_pages(vmid, load_idx);
			unmap_and_load_vm_image(vmid, load_addr, remap_addr, mapped);
			valid = verify_image(vmid, load_idx, remap_addr);
			if (valid == 0U)
			{
				v_panic();
			}
			load_idx += 1U;
		}
		set_vm_state(vmid, VERIFIED);
	}
	else
	{
		v_panic();
	}
	release_lock_vm(vmid);
}

void __hyp_text alloc_smmu(u32 vmid, u32 cbndx, u32 index) 
{
	u32 state;

	acquire_lock_vm(vmid);
	if (HOSTVISOR < vmid && vmid < COREVISOR) 
	{
		state = get_vm_state(vmid);
		if (state == VERIFIED) 
		{
			print_string("\rpanic: alloc_smmu\n");
			v_panic();
		}
	}
	init_spt(cbndx, index);
	release_lock_vm(vmid);
}

void __hyp_text assign_smmu(u32 vmid, u32 pfn, u32 gfn) 
{
	u32 state;

	acquire_lock_vm(vmid);
	if (HOSTVISOR < vmid && vmid < COREVISOR) 
	{
		state = get_vm_state(vmid);
		if (state == VERIFIED) 
		{
			print_string("\rpanic: assign_smmu\n");
			v_panic();
		}
		assign_pfn_to_smmu(vmid, gfn, pfn);
	}
	release_lock_vm(vmid);
}

void __hyp_text map_smmu(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte)
{
	u32 state;
	acquire_lock_vm(vmid);
	if (HOSTVISOR < vmid && vmid < COREVISOR) 
	{
		state = get_vm_state(vmid);
		if (state == VERIFIED) 
		{
			print_string("\rpanic: map_smmu\n");
			v_panic();
		}
	}
	update_smmu_page(vmid, cbndx, index, iova, pte);
	release_lock_vm(vmid);
}

void __hyp_text clear_smmu(u32 vmid, u32 cbndx, u32 index, u64 iova) 
{
	u32 state;

	acquire_lock_vm(vmid);
	if (HOSTVISOR < vmid && vmid < COREVISOR) 
	{
		state = get_vm_state(vmid);
		if (state == VERIFIED && get_vm_power(vmid))
		{
			print_string("\rpanic: clear_smmu\n");
			v_panic();
		}
	}
	unmap_smmu_page(cbndx, index, iova);
	release_lock_vm(vmid);
}

void __hyp_text map_io(u32 vmid, u64 gpa, u64 pa)
{
	u32 state;

	acquire_lock_vm(vmid);
	state = get_vm_state(vmid);
	if (state == READY) 
	{
		map_vm_io(vmid, gpa, pa);
	}
	else
	{
		print_string("\rpanic: map_io\n");
		v_panic();
	}
	release_lock_vm(vmid);
}

 u32 __hyp_text vm_is_inc_exe(u32 vmid)
{
	u32 inc_exe;
	acquire_lock_vm(vmid);
	inc_exe = get_vm_inc_exe(vmid);
	release_lock_vm(vmid);
	return check(inc_exe);
}

void __hyp_text __save_encrypted_vcpu(u32 vmid, u32 vcpu_id)
{
	encrypt_gp_regs(vmid, vcpu_id);
	encrypt_sys_regs(vmid, vcpu_id);
}

void __hyp_text __load_encrypted_vcpu(u32 vmid, u32 vcpu_id)
{
	u32 inc_exe;

	acquire_lock_vm(vmid);
	if (get_vcpu_first_run(vmid, vcpu_id) != 0)
	{
		v_panic();
	}
	else
	{
		decrypt_gp_regs(vmid, vcpu_id);
		decrypt_sys_regs(vmid, vcpu_id);
		inc_exe = get_vm_inc_exe(vmid);
		if (inc_exe == false)
		{
			set_vm_inc_exe(vmid, true);
		}
	}
	release_lock_vm(vmid);
}

void __hyp_text __el2_encrypt_buf(u32 vmid, u64 buf, u64 out_buf)
{
        phys_addr_t hpa = (phys_addr_t)buf;
	u64 tmp_pa;
	u64 pfn = (u64)buf >> PAGE_SHIFT;
	u64 pfn_out = (u64)out_buf >> PAGE_SHIFT;

	acquire_lock_s2page();

	if (get_pfn_owner(pfn) != vmid || get_pfn_owner(pfn_out) != HOSTVISOR)
	{
		v_panic();
	}
	else
	{
		tmp_pa = get_tmp_buf();
        	encrypt_buf(vmid, (u64)__el2_va(hpa), (u64)tmp_pa, PAGE_SIZE);
        	el2_memcpy(__el2_va(out_buf), (void*)tmp_pa, PAGE_SIZE);
	}

	release_lock_s2page();
}

void __hyp_text __el2_decrypt_buf(u32 vmid, void *buf, u32 len)
{
	u64 pfn = (u64)buf >> PAGE_SHIFT;
        u64 tmp_pa;
	u32 vm_state;

	acquire_lock_vm(vmid);

	vm_state = get_vm_state(vmid);
	if (vm_state != READY)
	{
		v_panic();
	}
	else
	{
		acquire_lock_s2page();

		tmp_pa = get_tmp_buf();
		set_pfn_owner(pfn, vmid);
		set_pfn_map(pfn, INVALID64);
		clear_pfn_host(pfn);

		decrypt_buf(vmid, (u64)__el2_va(buf), (u64)tmp_pa, len);
		el2_memcpy(__el2_va(buf), (void*)tmp_pa, PAGE_SIZE);

		release_lock_s2page();
	}

	release_lock_vm(vmid);
}
