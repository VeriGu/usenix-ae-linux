/* SPDX-License-Identifier: GPL-2.0 */
#include "hypsec.h"

/*
 * VCPUOps
 */

void __hyp_text save_shadow_kvm_regs()
{
	u64 ec, hsr, hsr_ec;
	u32 vmid, vcpuid;

	vmid = get_cur_vmid();
	vcpuid = get_cur_vcpu_id();
	ec = get_shadow_ctxt(vmid, vcpuid, V_EC);

	if (ec == ARM_EXCEPTION_TRAP)
	{
		hsr = get_shadow_esr(vmid, vcpuid);
		hsr_ec = ESR_ELx_EC(hsr);

		if (hsr_ec == ESR_ELx_EC_WFx)
		{
			prep_wfx(vmid, vcpuid);
		}
		else if (hsr_ec == ESR_ELx_EC_HVC32)
		{
			prep_hvc(vmid, vcpuid);
		}
		else if (hsr_ec == ESR_ELx_EC_HVC64)
		{
			prep_hvc(vmid, vcpuid);
		}
		else if (hsr_ec == ESR_ELx_EC_IABT_LOW)
		{
			prep_abort(vmid, vcpuid);
		}
		else if (hsr_ec == ESR_ELx_EC_DABT_LOW)
		{
			prep_abort(vmid, vcpuid);
		}
		else if (hsr_ec == ESR_ELx_EC_BRK64)
		{
			prep_wfx(vmid, vcpuid);
		}
		else
		{
			print_string("\runknown exception\n");
			v_panic();
		}
	}
}

void __hyp_text restore_shadow_kvm_regs()
{
	u64 dirty, ec, pc, addr;
	u32 vmid, vcpuid;

	vmid = get_cur_vmid();
	vcpuid = get_cur_vcpu_id();
	dirty = get_shadow_ctxt(vmid, vcpuid, V_DIRTY);

	if (dirty == INVALID64)
	{
		if (vm_is_inc_exe(vmid) == 0U)
		{
			reset_gp_regs(vmid, vcpuid);
			reset_sys_regs(vmid, vcpuid);
		}

		set_shadow_dirty_bit(vmid, vcpuid, 0UL);
    	}
	else
	{
	        ec = get_shadow_ctxt(vmid, vcpuid, V_EC);
		if (ec == ARM_EXCEPTION_TRAP && dirty)
		{
			sync_dirty_to_shadow(vmid, vcpuid);
		}

		if (dirty & PENDING_EXCEPT_INJECT_FLAG)
		{
			v_update_exception_gp_regs(vmid, vcpuid);

		}

		if (dirty & DIRTY_PC_FLAG)
		{
			pc = get_shadow_ctxt(vmid, vcpuid, V_PC);
			set_shadow_ctxt(vmid, vcpuid, V_PC, pc + 4UL);
		}

		set_shadow_dirty_bit(vmid, vcpuid, 0UL);
		set_shadow_ctxt(vmid, vcpuid, V_FAR_EL2, 0UL);
		addr = get_vm_fault_addr(vmid, vcpuid);

		if (get_shadow_ctxt(vmid, vcpuid, V_FLAGS) & PENDING_FSC_FAULT)
		{
			post_handle_shadow_s2pt_fault(vmid, vcpuid, addr);
		}

		set_shadow_ctxt(vmid, vcpuid, V_FLAGS, 0UL);
	}
}
