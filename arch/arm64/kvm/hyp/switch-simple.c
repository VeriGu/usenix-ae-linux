/*
 * This file is a simplified version of switch.c for verfication.
 * We currently do not support 32-bit VM, debugging support, RAS extn,
 * PMU, VHE, and SVE.
 */

#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <uapi/linux/psci.h>

#include <kvm/arm_psci.h>

#include <asm/cpufeature.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/hypsec_host.h>
#include <asm/hypsec_constant.h>

#include "switch-simple.h"

static void __hyp_text __activate_traps_common(struct kvm_vcpu *vcpu)
{
	/*
	 * Make sure we trap PMU access from EL0 to EL2. Also sanitize
	 * PMSELR_EL0 to make sure it never contains the cycle
	 * counter, which could make a PMXEVCNTR_EL0 access UNDEF at
	 * EL1 instead of being trapped to EL2.
	 */
	set_pmselr_el0(0);
	set_pmuserenr_el0(ARMV8_PMU_USERENR_MASK);

	set_mdcr_el2(0);
}

static void __hyp_text __deactivate_traps_common(void)
{
	set_pmuserenr_el0(0);
}

static void __hyp_text __activate_traps_nvhe(struct kvm_vcpu *vcpu)
{
	u64 val;

	__activate_traps_common(vcpu);

	val = CPTR_EL2_DEFAULT;
	val |= CPTR_EL2_TTA | CPTR_EL2_TZ;

	set_cptr_el2(val);
}

static void __hyp_text __activate_traps(struct kvm_vcpu *vcpu)
{
	u64 hcr = HCR_HYPSEC_VM_FLAGS;

	if (vcpu->arch.hcr_el2 & HCR_VI)
		hcr |= HCR_VI;

	if (vcpu->arch.hcr_el2 & HCR_VF)
		hcr |= HCR_VF;

	set_hcr_el2(hcr);

	/* We don't support RAS_EXTN for now in HypSec */

	__activate_traps_nvhe(vcpu);
}

static void __hyp_text __deactivate_traps_nvhe(void)
{
	__deactivate_traps_common();
	/*
	 * Don't trap host access to debug related registers
	 * but clear all available counters.
	 */
	set_mdcr_el2(0);

	set_cptr_el2(CPTR_EL2_DEFAULT);
}

static void __hyp_text __deactivate_traps(struct kvm_vcpu *vcpu)
{
	__deactivate_traps_nvhe();
}

void activate_traps_vhe_load(struct kvm_vcpu *vcpu)
{
}

void deactivate_traps_vhe_put(void)
{
}

static void __hyp_text __activate_vm(u64 vmid)
{
	//u64 shadow_vttbr = get_shadow_vttbr((u32)vmid);
	u64 shadow_vttbr = get_pt_vttbr((u32)vmid);
	set_vttbr_el2(shadow_vttbr);
}

static void __hyp_text __deactivate_vm(struct kvm_vcpu *vcpu)
{
}

/* Save VGICv3 state on non-VHE systems */
static void __hyp_text __hyp_vgic_save_state(struct kvm_vcpu *vcpu)
{
}

/* Restore VGICv3 state on non_VEH systems */
static void __hyp_text __hyp_vgic_restore_state(struct kvm_vcpu *vcpu)
{
}

static bool __hyp_text __check_arm_834220(void)
{
	/*
	 * We return true here since AMD Seattle uses Cortex-A57 CPUs.
	 * This needs to be updated if the hardware has different type
	 * of CPUs.
	 */
	return true;
}

static bool __hyp_text __translate_far_to_hpfar(u64 far, u64 *hpfar)
{
	u64 par, tmp;

	/*
	 * Resolve the IPA the hard way using the guest VA.
	 *
	 * Stage-1 translation already validated the memory access
	 * rights. As such, we can use the EL1 translation regime, and
	 * don't have to distinguish between EL0 and EL1 access.
	 *
	 * We do need to save/restore PAR_EL1 though, as we haven't
	 * saved the guest context yet, and we may return early...
	 */
	par = read_sysreg(par_el1);
	asm volatile("at s1e1r, %0" : : "r" (far));
	isb();

	tmp = read_sysreg(par_el1);
	write_sysreg(par, par_el1);

	if (unlikely(tmp & 1))
		return false; /* Translation failed, back to guest */

	/* Convert PAR to HPFAR format */
	*hpfar = ((tmp >> 12) & ((1UL << 36) - 1)) << 4;
	return true;
}

static bool __hyp_text __populate_fault_info(struct kvm_vcpu *vcpu, u64 esr,
					     struct shadow_vcpu_context *shadow_ctxt)
{
	u64 hpfar, far = get_far_el2();

	/*
	 * The HPFAR can be invalid if the stage 2 fault did not
	 * happen during a stage 1 page table walk (the ESR_EL2.S1PTW
	 * bit is clear) and one of the two following cases are true:
	 *   1. The fault was due to a permission fault
	 *   2. The processor carries errata 834220
	 *
	 * Therefore, for all non S1PTW faults where we either have a
	 * permission fault or the errata workaround is enabled, we
	 * resolve the IPA using the AT instruction.
	 */
	if (!(esr & ESR_ELx_S1PTW) &&
	    (__check_arm_834220() || (esr & ESR_ELx_FSC_TYPE) == FSC_PERM)) {
		if (!__translate_far_to_hpfar(far, &hpfar))
			return false;
	} else {
		hpfar = get_hpfar_el2();
	}

	vcpu->arch.fault.far_el2 = far;
	vcpu->arch.fault.hpfar_el2 = hpfar;
	shadow_ctxt->far_el2 = far;
	shadow_ctxt->hpfar = hpfar;

	if ((esr & ESR_ELx_FSC_TYPE) == FSC_FAULT) {
		/*
		 * Here we'd like to avoid calling handle_shadow_s2pt_fault
		 * twice if it's GPA belongs to MMIO region. Since no mapping
		 * should be built anyway.
		 */
		if (!is_mmio_gpa((hpfar & HPFAR_MASK) << 8)) {
			el2_memset(&vcpu->arch.walk_result, 0, sizeof(struct s2_trans));
			shadow_ctxt->flags |= PENDING_FSC_FAULT;
		}
	}

	return true;
}

/*
 * Return true when we were able to fixup the guest exit and should return to
 * the guest, false when we should restore the host state and return to the
 * main run loop. We try to handle VM exit early here.
 */
static bool __hyp_text fixup_guest_exit(struct kvm_vcpu *vcpu, u64 *exit_code,
					u32 vmid, u32 vcpuid)
{
	u32 esr_el2 = 0;
	u8 ec;
	struct shadow_vcpu_context *shadow_ctxt;

	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpuid);
	if (ARM_EXCEPTION_CODE(*exit_code) != ARM_EXCEPTION_IRQ) {
		esr_el2 = get_esr_el2();
		vcpu->arch.fault.esr_el2 = esr_el2;
		shadow_ctxt->esr = esr_el2;
	}

	/*
	 * We're using the raw exception code in order to only process
	 * the trap if no SError is pending. We will come back to the
	 * same PC once the SError has been injected, and replay the
	 * trapping instruction.
	 */
	if (*exit_code != ARM_EXCEPTION_TRAP)
		goto exit;

	ec = ESR_ELx_EC(esr_el2);
	if (ec == ESR_ELx_EC_HVC64) {
		if (handle_pvops(vmid, vcpuid) > 0)
			return true;
		else
			return false;
	} else if (ec == ESR_ELx_EC_DABT_LOW || ec == ESR_ELx_EC_IABT_LOW) {
		if (!__populate_fault_info(vcpu, esr_el2, shadow_ctxt))
			return true;
	} else if (ec == ESR_ELx_EC_SYS64) {
		u64 elr = read_sysreg(elr_el2);
		write_sysreg(elr + 4, elr_el2);
		return true;
	}

exit:
	/* Return to the host kernel and handle the exit */
	return false;
}

static void __hyp_text __host_el2_restore_state(struct el2_data *el2_data)
{
	set_vttbr_el2(el2_data->host_vttbr);
	set_hcr_el2(HCR_HOST_NVHE_FLAGS);
	set_tpidr_el2(0);
}

int kvm_vcpu_run_vhe(struct kvm_vcpu *vcpu)
{
	return 0;
}

/* Switch to the guest for legacy non-VHE systems */
int __hyp_text __kvm_vcpu_run_nvhe(u32 vmid, int vcpu_id)
{
	u64 exit_code;
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *shadow_ctxt;
	struct kvm_cpu_context core_ctxt;
	struct el2_data *el2_data;
	struct kvm_vcpu *vcpu;
	struct shadow_vcpu_context *prot_ctxt;

	/* check if vm is verified and vcpu is already active. */
	hypsec_set_vcpu_active(vmid, vcpu_id);
	set_per_cpu(vmid, vcpu_id);

	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	prot_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	host_ctxt->__hyp_running_vcpu = vcpu;
	shadow_ctxt = (struct kvm_cpu_context *)prot_ctxt;

	__sysreg_save_state_nvhe(host_ctxt);

	set_tpidr_el2((u64)shadow_ctxt);
	//__restore_shadow_kvm_regs(vcpu, prot_ctxt);
	restore_shadow_kvm_regs();

	__activate_traps(vcpu);
	__activate_vm(vmid & 0xff);
	if (vcpu->arch.was_preempted) {
		hypsec_tlb_flush_local_vmid();
		vcpu->arch.was_preempted = false;
	}

	__hyp_vgic_restore_state(vcpu);
	__timer_enable_traps(vcpu);

	/*
	 * We must restore the 32-bit state before the sysregs, thanks
	 * to erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 */
	__sysreg32_restore_state(vcpu);
	__vm_sysreg_restore_state_nvhe_opt(prot_ctxt);

	__fpsimd_save_state(&host_ctxt->gp_regs.fp_regs);
	__fpsimd_restore_state(&prot_ctxt->gp_regs.fp_regs);

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(shadow_ctxt, &core_ctxt);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code, vmid, vcpu_id));

	//print_string("\rpc\n");
	//printhex_ul(read_sysreg(elr_el2));
	//print_string("\resr\n");
	//printhex_ul(read_sysreg(esr_el2));

	__vm_sysreg_save_state_nvhe_opt(prot_ctxt);
	__sysreg32_save_state(vcpu);
	__timer_disable_traps(vcpu);
	__hyp_vgic_save_state(vcpu);

	__deactivate_traps(vcpu);
	__deactivate_vm(vcpu);
	__host_el2_restore_state(el2_data);

	__sysreg_restore_state_nvhe(host_ctxt);

	__fpsimd_save_state(&prot_ctxt->gp_regs.fp_regs);
	__fpsimd_restore_state(&host_ctxt->gp_regs.fp_regs);

	//__save_shadow_kvm_regs(vcpu, prot_ctxt, exit_code);
	set_shadow_ctxt(vmid, vcpu_id, V_EC, exit_code);
	save_shadow_kvm_regs();

	set_per_cpu(0, read_cpuid_mpidr() & MPIDR_HWID_BITMASK);
	hypsec_set_vcpu_state(vmid, vcpu_id, READY);

	return exit_code;
}

void __hyp_text __noreturn hyp_panic(struct kvm_cpu_context *host_ctxt)
{
	/* For simplicity, we just hang in here. */
	unreachable();
}
