/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#ifdef CONFIG_STAGE2_KERNEL
#include <asm/hypsec_host.h>
#endif

/* Check whether the FP regs were dirtied while in the host-side run loop: */
static bool __hyp_text update_fp_enabled(struct kvm_vcpu *vcpu)
{
#ifndef CONFIG_STAGE2_KERNEL
	if (vcpu->arch.host_thread_info->flags & _TIF_FOREIGN_FPSTATE)
		vcpu->arch.flags &= ~(KVM_ARM64_FP_ENABLED |
				      KVM_ARM64_FP_HOST);
#endif

	return !!(vcpu->arch.flags & KVM_ARM64_FP_ENABLED);
}

/* Save the 32-bit only FPSIMD system register state */
static void __hyp_text __fpsimd_save_fpexc32(struct kvm_vcpu *vcpu)
{
	if (!vcpu_el1_is_32bit(vcpu))
		return;
#ifndef CONFIG_STAGE2_KERNEL
	vcpu->arch.ctxt.sys_regs[FPEXC32_EL2] = read_sysreg(fpexc32_el2);
#else
	vcpu->arch.shadow_vcpu_ctxt->sys_regs[FPEXC32_EL2] =
						read_sysreg(fpexc32_el2);
#endif
}

static void __hyp_text __activate_traps_fpsimd32(struct kvm_vcpu *vcpu)
{
	/*
	 * We are about to set CPTR_EL2.TFP to trap all floating point
	 * register accesses to EL2, however, the ARM ARM clearly states that
	 * traps are only taken to EL2 if the operation would not otherwise
	 * trap to EL1.  Therefore, always make sure that for 32-bit guests,
	 * we set FPEXC.EN to prevent traps to EL1, when setting the TFP bit.
	 * If FP/ASIMD is not implemented, FPEXC is UNDEFINED and any access to
	 * it will cause an exception.
	 */
	if (vcpu_el1_is_32bit(vcpu) && system_supports_fpsimd()) {
		write_sysreg(1 << 30, fpexc32_el2);
		isb();
	}
}

static void __hyp_text __activate_traps_common(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_STAGE2_KERNEL
	u64 mdcr_el2 = read_sysreg(mdcr_el2);
#endif
	/* Trap on AArch32 cp15 c15 (impdef sysregs) accesses (EL1 or EL0) */
	write_sysreg(1 << 15, hstr_el2);

	/*
	 * Make sure we trap PMU access from EL0 to EL2. Also sanitize
	 * PMSELR_EL0 to make sure it never contains the cycle
	 * counter, which could make a PMXEVCNTR_EL0 access UNDEF at
	 * EL1 instead of being trapped to EL2.
	 */
	write_sysreg(0, pmselr_el0);
	write_sysreg(ARMV8_PMU_USERENR_MASK, pmuserenr_el0);
#ifdef CONFIG_STAGE2_KERNEL
	mdcr_el2 &= MDCR_EL2_HPMN_MASK;
	mdcr_el2 |= (MDCR_EL2_TPM |
		     MDCR_EL2_TPMS |
		     MDCR_EL2_TPMCR |
		     MDCR_EL2_TDRA |
		     MDCR_EL2_TDOSA |
		     MDCR_EL2_TDA |
		     MDCR_EL2_TDE);
	write_sysreg(mdcr_el2, mdcr_el2);
#else
	write_sysreg(vcpu->arch.mdcr_el2, mdcr_el2);
#endif
}

static void __hyp_text __deactivate_traps_common(void)
{
	write_sysreg(0, hstr_el2);
	write_sysreg(0, pmuserenr_el0);
}

static void activate_traps_vhe(struct kvm_vcpu *vcpu)
{
	u64 val;

	val = read_sysreg(cpacr_el1);
	val |= CPACR_EL1_TTA;
	val &= ~CPACR_EL1_ZEN;
	if (!update_fp_enabled(vcpu))
		val &= ~CPACR_EL1_FPEN;

	write_sysreg(val, cpacr_el1);

	write_sysreg(kvm_get_hyp_vector(), vbar_el1);
}

static void __hyp_text __activate_traps_nvhe(struct kvm_vcpu *vcpu)
{
	u64 val;

	__activate_traps_common(vcpu);

	val = CPTR_EL2_DEFAULT;
	val |= CPTR_EL2_TTA | CPTR_EL2_TZ;
	if (!update_fp_enabled(vcpu))
		val |= CPTR_EL2_TFP;

	write_sysreg(val, cptr_el2);
}

static void __hyp_text __activate_traps(struct kvm_vcpu *vcpu)
{
	u64 hcr = vcpu->arch.hcr_el2;
#ifdef CONFIG_STAGE2_KERNEL
	hcr |= HCR_HYPSEC_VM_FLAGS;
	hcr &= ~HCR_TGE;
#endif

	write_sysreg(hcr, hcr_el2);

	if (cpus_have_const_cap(ARM64_HAS_RAS_EXTN) && (hcr & HCR_VSE))
		write_sysreg_s(vcpu->arch.vsesr_el2, SYS_VSESR_EL2);

	__activate_traps_fpsimd32(vcpu);
	if (has_vhe())
		activate_traps_vhe(vcpu);
	else
		__activate_traps_nvhe(vcpu);
}

static void deactivate_traps_vhe(void)
{
	extern char vectors[];	/* kernel exception vectors */
	write_sysreg(HCR_HOST_VHE_FLAGS, hcr_el2);
	write_sysreg(CPACR_EL1_DEFAULT, cpacr_el1);
	write_sysreg(vectors, vbar_el1);
}

static void __hyp_text __deactivate_traps_nvhe(void)
{
	u64 mdcr_el2 = read_sysreg(mdcr_el2);

	__deactivate_traps_common();

	mdcr_el2 &= MDCR_EL2_HPMN_MASK;
	mdcr_el2 |= MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT;

	write_sysreg(mdcr_el2, mdcr_el2);
#ifndef CONFIG_STAGE2_KERNEL
	write_sysreg(HCR_RW, hcr_el2);
#endif
	write_sysreg(CPTR_EL2_DEFAULT, cptr_el2);
}

static void __hyp_text __deactivate_traps(struct kvm_vcpu *vcpu)
{
	/*
	 * If we pended a virtual abort, preserve it until it gets
	 * cleared. See D1.14.3 (Virtual Interrupts) for details, but
	 * the crucial bit is "On taking a vSError interrupt,
	 * HCR_EL2.VSE is cleared to 0."
	 */
	if (vcpu->arch.hcr_el2 & HCR_VSE)
		vcpu->arch.hcr_el2 = read_sysreg(hcr_el2);

	if (has_vhe())
		deactivate_traps_vhe();
	else
		__deactivate_traps_nvhe();
}

void activate_traps_vhe_load(struct kvm_vcpu *vcpu)
{
	__activate_traps_common(vcpu);
}

void deactivate_traps_vhe_put(void)
{
	u64 mdcr_el2 = read_sysreg(mdcr_el2);

	mdcr_el2 &= MDCR_EL2_HPMN_MASK |
		    MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT |
		    MDCR_EL2_TPMS;

	write_sysreg(mdcr_el2, mdcr_el2);

	__deactivate_traps_common();
}

#ifndef CONFIG_STAGE2_KERNEL
static void __hyp_text __activate_vm(struct kvm *kvm)
{
	write_sysreg(kvm->arch.vttbr, vttbr_el2);
}
#else
static void __hyp_text __activate_vm(u64 vmid)
{
	u64 shadow_vttbr = get_shadow_vttbr((u32)vmid);
	write_sysreg(shadow_vttbr, vttbr_el2);
}
#endif

static void __hyp_text __deactivate_vm(struct kvm_vcpu *vcpu)
{
#ifndef CONFIG_STAGE2_KERNEL
	write_sysreg(0, vttbr_el2);
#endif
}

/* Save VGICv3 state on non-VHE systems */
static void __hyp_text __hyp_vgic_save_state(struct kvm_vcpu *vcpu)
{
	if (static_branch_unlikely(&kvm_vgic_global_state.gicv3_cpuif)) {
		__vgic_v3_save_state(vcpu);
		__vgic_v3_deactivate_traps(vcpu);
	}
}

/* Restore VGICv3 state on non_VEH systems */
static void __hyp_text __hyp_vgic_restore_state(struct kvm_vcpu *vcpu)
{
	if (static_branch_unlikely(&kvm_vgic_global_state.gicv3_cpuif)) {
		__vgic_v3_activate_traps(vcpu);
		__vgic_v3_restore_state(vcpu);
	}
}

static bool __hyp_text __true_value(void)
{
	return true;
}

static bool __hyp_text __false_value(void)
{
	return false;
}

static hyp_alternate_select(__check_arm_834220,
			    __false_value, __true_value,
			    ARM64_WORKAROUND_834220);

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

#ifndef CONFIG_STAGE2_KERNEL
static bool __hyp_text __populate_fault_info(struct kvm_vcpu *vcpu)
#else
static bool __hyp_text __populate_fault_info(struct kvm_vcpu *vcpu, u64 esr)
#endif
{
	u8 ec;
	u64 hpfar, far;
#ifndef CONFIG_STAGE2_KERNEL
	u64 esr;

	esr = vcpu->arch.fault.esr_el2;
#endif
	ec = ESR_ELx_EC(esr);

	if (ec != ESR_ELx_EC_DABT_LOW && ec != ESR_ELx_EC_IABT_LOW)
		return true;

	far = read_sysreg_el2(far);

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
	    (__check_arm_834220()() || (esr & ESR_ELx_FSC_TYPE) == FSC_PERM)) {
		if (!__translate_far_to_hpfar(far, &hpfar))
			return false;
	} else {
		hpfar = read_sysreg(hpfar_el2);
	}

	vcpu->arch.fault.far_el2 = far;
	vcpu->arch.fault.hpfar_el2 = hpfar;
#ifdef CONFIG_STAGE2_KERNEL
	if ((esr & ESR_ELx_FSC_TYPE) == FSC_FAULT) {
		if (pre_handle_shadow_s2pt_fault(vcpu, hpfar) > 0)
			return false;
		/*
		 * Here we'd like to avoid calling handle_shadow_s2pt_fault
		 * twice if it's GPA belongs to MMIO region. Since no mapping
		 * should be built anyway.
		 */
		else if (!is_mmio_gpa((hpfar & HPFAR_MASK) << 8)) {
			vcpu->arch.shadow_vcpu_ctxt->hpfar = hpfar;
			el2_memset(&vcpu->arch.walk_result, 0,
					sizeof(struct s2_trans));
		}
	}
#endif

	return true;
}

/* Skip an instruction which has been emulated. Returns true if
 * execution can continue or false if we need to exit hyp mode because
 * single-step was in effect.
 */
static bool __hyp_text __skip_instr(struct kvm_vcpu *vcpu)
{
#ifndef CONFIG_STAGE2_KERNEL
	*vcpu_pc(vcpu) = read_sysreg_el2(elr);

	if (vcpu_mode_is_32bit(vcpu)) {
		vcpu->arch.ctxt.gp_regs.regs.pstate = read_sysreg_el2(spsr);
		kvm_skip_instr32(vcpu, kvm_vcpu_trap_il_is32bit(vcpu));
		write_sysreg_el2(vcpu->arch.ctxt.gp_regs.regs.pstate, spsr);
	} else {
		*vcpu_pc(vcpu) += 4;
	}

	write_sysreg_el2(*vcpu_pc(vcpu), elr);
#else
	*shadow_vcpu_pc(vcpu) = read_sysreg_el2(elr);

	if (shadow_vcpu_mode_is_32bit(vcpu)) {
		vcpu->arch.shadow_vcpu_ctxt->gp_regs.regs.pstate = read_sysreg_el2(spsr);
		kvm_skip_instr32(vcpu, kvm_vcpu_trap_il_is32bit(vcpu));
		write_sysreg_el2(vcpu->arch.shadow_vcpu_ctxt->gp_regs.regs.pstate, spsr);
	} else {
		*shadow_vcpu_pc(vcpu) += 4;
	}

	write_sysreg_el2(*shadow_vcpu_pc(vcpu), elr);
#endif

	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP) {
		vcpu->arch.fault.esr_el2 =
			(ESR_ELx_EC_SOFTSTP_LOW << ESR_ELx_EC_SHIFT) | 0x22;
		return false;
	} else {
		return true;
	}
}

static bool __hyp_text __hyp_switch_fpsimd(struct kvm_vcpu *vcpu)
{
#ifndef CONFIG_STAGE2_KERNEL
	struct user_fpsimd_state *host_fpsimd = vcpu->arch.host_fpsimd_state;
#else
	struct kvm_cpu_context *host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	struct user_fpsimd_state *host_fpsimd = &host_ctxt->gp_regs.fp_regs;
#endif

	if (has_vhe())
		write_sysreg(read_sysreg(cpacr_el1) | CPACR_EL1_FPEN,
			     cpacr_el1);
	else
		write_sysreg(read_sysreg(cptr_el2) & ~(u64)CPTR_EL2_TFP,
			     cptr_el2);

	isb();

	if (vcpu->arch.flags & KVM_ARM64_FP_HOST) {
		/*
		 * In the SVE case, VHE is assumed: it is enforced by
		 * Kconfig and kvm_arch_init().
		 */
		if (system_supports_sve() &&
		    (vcpu->arch.flags & KVM_ARM64_HOST_SVE_IN_USE)) {
			struct thread_struct *thread = container_of(
				host_fpsimd,
				struct thread_struct, uw.fpsimd_state);

			sve_save_state(sve_pffr(thread), &host_fpsimd->fpsr);
		} else {
			__fpsimd_save_state(host_fpsimd);
		}

		vcpu->arch.flags &= ~KVM_ARM64_FP_HOST;
	}
#ifndef CONFIG_STAGE2_KERNEL
	__fpsimd_restore_state(&vcpu->arch.ctxt.gp_regs.fp_regs);
#else
	__fpsimd_restore_state(&vcpu->arch.shadow_vcpu_ctxt->gp_regs.fp_regs);
#endif
	/* Skip restoring fpexc32 for AArch64 guests */
	if (!(read_sysreg(hcr_el2) & HCR_RW))
#ifndef CONFIG_STAGE2_KERNEL
		write_sysreg(vcpu->arch.ctxt.sys_regs[FPEXC32_EL2],
#else
		write_sysreg(vcpu->arch.shadow_vcpu_ctxt->sys_regs[FPEXC32_EL2],
#endif
			     fpexc32_el2);

	vcpu->arch.flags |= KVM_ARM64_FP_ENABLED;

	return true;
}

/*
 * Return true when we were able to fixup the guest exit and should return to
 * the guest, false when we should restore the host state and return to the
 * main run loop.
 */
static bool __hyp_text fixup_guest_exit(struct kvm_vcpu *vcpu, u64 *exit_code)
{
#ifdef CONFIG_STAGE2_KERNEL
	u32 esr_el2 = 0;
#endif
	if (ARM_EXCEPTION_CODE(*exit_code) != ARM_EXCEPTION_IRQ) {
#ifndef CONFIG_STAGE2_KERNEL
		vcpu->arch.fault.esr_el2 = read_sysreg_el2(esr);
#else
		esr_el2 = read_sysreg_el2(esr);
		vcpu->arch.fault.esr_el2 = esr_el2;
		vcpu->arch.shadow_vcpu_ctxt->esr = esr_el2;
#endif
	}

	/*
	 * We're using the raw exception code in order to only process
	 * the trap if no SError is pending. We will come back to the
	 * same PC once the SError has been injected, and replay the
	 * trapping instruction.
	 */
	if (*exit_code != ARM_EXCEPTION_TRAP)
		goto exit;

	/*
	 * We trap the first access to the FP/SIMD to save the host context
	 * and restore the guest context lazily.
	 * If FP/SIMD is not implemented, handle the trap and inject an
	 * undefined instruction exception to the guest.
	 */
	if (system_supports_fpsimd() &&
#ifndef CONFIG_STAGE2_KERNEL
	    kvm_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_FP_ASIMD)
#else
	    hypsec_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_FP_ASIMD)
#endif
		return __hyp_switch_fpsimd(vcpu);

#ifndef CONFIG_STAGE2_KERNEL
	if (!__populate_fault_info(vcpu))
#else
	if (!__populate_fault_info(vcpu, esr_el2))
#endif
		return true;

#ifdef CONFIG_STAGE2_KERNEL
	if (*exit_code == ARM_EXCEPTION_TRAP &&
	   hypsec_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_HVC64) {
		if (handle_pvops(vcpu) > 0)
			return true;
	}
#endif

	if (static_branch_unlikely(&vgic_v2_cpuif_trap)) {
		bool valid;

#ifndef CONFIG_STAGE2_KERNEL
		valid = kvm_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_DABT_LOW &&
			kvm_vcpu_trap_get_fault_type(vcpu) == FSC_FAULT &&
			kvm_vcpu_dabt_isvalid(vcpu) &&
			!kvm_vcpu_dabt_isextabt(vcpu) &&
			!kvm_vcpu_dabt_iss1tw(vcpu);
#else
		valid = hypsec_is_vgic_v2_cpuif_trap(vcpu, esr_el2);
#endif

		if (valid) {
			int ret = __vgic_v2_perform_cpuif_access(vcpu);

			if (ret ==  1 && __skip_instr(vcpu))
				return true;

			if (ret == -1) {
				/* Promote an illegal access to an
				 * SError. If we would be returning
				 * due to single-step clear the SS
				 * bit so handle_exit knows what to
				 * do after dealing with the error.
				 */
				if (!__skip_instr(vcpu))
#ifndef CONFIG_STAGE2_KERNEL
					*vcpu_cpsr(vcpu) &= ~DBG_SPSR_SS;
#else
					*shadow_vcpu_cpsr(vcpu) &= ~DBG_SPSR_SS;
#endif
				*exit_code = ARM_EXCEPTION_EL1_SERROR;
			}

			goto exit;
		}
	}

	if (static_branch_unlikely(&vgic_v3_cpuif_trap) &&
#ifndef CONFIG_STAGE2_KERNEL
	    (kvm_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_SYS64 ||
	     kvm_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_CP15_32)) {
#else
	    (hypsec_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_SYS64 ||
	     hypsec_vcpu_trap_get_class(vcpu) == ESR_ELx_EC_CP15_32)) {
#endif
		int ret = __vgic_v3_perform_cpuif_access(vcpu);

		if (ret == 1 && __skip_instr(vcpu))
			return true;
	}

exit:
	/* Return to the host kernel and handle the exit */
	return false;
}

static inline bool __hyp_text __needs_ssbd_off(struct kvm_vcpu *vcpu)
{
	if (!cpus_have_const_cap(ARM64_SSBD))
		return false;

	return !(vcpu->arch.workaround_flags & VCPU_WORKAROUND_2_FLAG);
}

static void __hyp_text __set_guest_arch_workaround_state(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_ARM64_SSBD
	/*
	 * The host runs with the workaround always present. If the
	 * guest wants it disabled, so be it...
	 */
	if (__needs_ssbd_off(vcpu) &&
	    __hyp_this_cpu_read(arm64_ssbd_callback_required))
		arm_smccc_1_1_smc(ARM_SMCCC_ARCH_WORKAROUND_2, 0, NULL);
#endif
}

static void __hyp_text __set_host_arch_workaround_state(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_ARM64_SSBD
	/*
	 * If the guest has disabled the workaround, bring it back on.
	 */
	if (__needs_ssbd_off(vcpu) &&
	    __hyp_this_cpu_read(arm64_ssbd_callback_required))
		arm_smccc_1_1_smc(ARM_SMCCC_ARCH_WORKAROUND_2, 1, NULL);
#endif
}

#ifdef CONFIG_STAGE2_KERNEL
static void __hyp_text __host_el2_restore_state(struct el2_data *el2_data)
{
	write_sysreg(el2_data->host_vttbr, vttbr_el2);
	write_sysreg(HCR_HOST_NVHE_FLAGS, hcr_el2);
	write_sysreg(0, tpidr_el2);
}
#endif

/* Switch to the guest for VHE systems running in EL2 */
int kvm_vcpu_run_vhe(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	u64 exit_code;

	host_ctxt = vcpu->arch.host_cpu_context;
	host_ctxt->__hyp_running_vcpu = vcpu;
	guest_ctxt = &vcpu->arch.ctxt;

	sysreg_save_host_state_vhe(host_ctxt);

	__activate_traps(vcpu);
#ifndef CONFIG_STAGE2_KERNEL
	__activate_vm(vcpu->kvm);
#endif

	sysreg_restore_guest_state_vhe(guest_ctxt);
	__debug_switch_to_guest(vcpu);

	__set_guest_arch_workaround_state(vcpu);

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(vcpu, host_ctxt);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));

	__set_host_arch_workaround_state(vcpu);

	sysreg_save_guest_state_vhe(guest_ctxt);

	__deactivate_traps(vcpu);

	sysreg_restore_host_state_vhe(host_ctxt);

	if (vcpu->arch.flags & KVM_ARM64_FP_ENABLED)
		__fpsimd_save_fpexc32(vcpu);

	__debug_switch_to_host(vcpu);

	return exit_code;
}

/* Switch to the guest for legacy non-VHE systems */
#ifndef CONFIG_STAGE2_KERNEL
int __hyp_text __kvm_vcpu_run_nvhe(struct kvm_vcpu *vcpu)
#else
int __hyp_text __kvm_vcpu_run_nvhe(struct kvm_vcpu *vcpu,
				   struct shadow_vcpu_context *prot_ctxt)
#endif
{
	u64 exit_code;
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
#ifdef CONFIG_STAGE2_KERNEL
	struct kvm_cpu_context *shadow_ctxt;
	struct el2_data *el2_data;
	u32 vmid = vcpu->arch.vmid;
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
#endif

#ifndef CONFIG_STAGE2_KERNEL
	vcpu = kern_hyp_va(vcpu);
#endif

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	host_ctxt->__hyp_running_vcpu = vcpu;
	guest_ctxt = &vcpu->arch.ctxt;
#ifdef CONFIG_STAGE2_KERNEL
	shadow_ctxt =
		(struct kvm_cpu_context *)prot_ctxt;
#endif

	__sysreg_save_state_nvhe(host_ctxt);

#ifdef CONFIG_STAGE2_KERNEL
	write_sysreg(vcpu->arch.tpidr_el2, tpidr_el2);
	__restore_shadow_kvm_regs(vcpu);
#endif
	__activate_traps(vcpu);
#ifndef CONFIG_STAGE2_KERNEL
	__activate_vm(kern_hyp_va(vcpu->kvm));
#else
	__activate_vm(vmid & 0xff);
#endif

	__hyp_vgic_restore_state(vcpu);
	__timer_enable_traps(vcpu);

	/*
	 * We must restore the 32-bit state before the sysregs, thanks
	 * to erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 */
	__sysreg32_restore_state(vcpu);
#ifndef CONFIG_STAGE2_KERNEL
	__sysreg_restore_state_nvhe(guest_ctxt);
	__debug_switch_to_guest(vcpu);
#else
	__sysreg_restore_state_nvhe(shadow_ctxt);
#endif

	__set_guest_arch_workaround_state(vcpu);

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(vcpu, host_ctxt);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));

	__set_host_arch_workaround_state(vcpu);

#ifndef CONFIG_STAGE2_KERNEL
	__sysreg_save_state_nvhe(guest_ctxt);
#else
	__sysreg_save_state_nvhe(shadow_ctxt);
#endif
	__sysreg32_save_state(vcpu);
	__timer_disable_traps(vcpu);
	__hyp_vgic_save_state(vcpu);

	__deactivate_traps(vcpu);
	__deactivate_vm(vcpu);
#ifdef CONFIG_STAGE2_KERNEL
	__host_el2_restore_state(el2_data);
#endif

	__sysreg_restore_state_nvhe(host_ctxt);

	if (vcpu->arch.flags & KVM_ARM64_FP_ENABLED) {
		__fpsimd_save_fpexc32(vcpu);
#ifdef CONFIG_STAGE2_KERNEL
		__fpsimd_save_state(&shadow_ctxt->gp_regs.fp_regs);
		__fpsimd_restore_state(&host_ctxt->gp_regs.fp_regs);
		vcpu->arch.flags &= ~KVM_ARM64_FP_ENABLED;
		vcpu->arch.flags |= KVM_ARM64_FP_HOST;
#endif
	}

#ifdef CONFIG_STAGE2_KERNEL
	__save_shadow_kvm_regs(vcpu, exit_code);
#endif

	/*
	 * This must come after restoring the host sysregs, since a non-VHE
	 * system may enable SPE here and make use of the TTBRs.
	 */
#ifndef CONFIG_STAGE2_KERNEL
	__debug_switch_to_host(vcpu);
#endif

	return exit_code;
}

static const char __hyp_panic_string[] = "HYP panic:\nPS:%08llx PC:%016llx ESR:%08llx\nFAR:%016llx HPFAR:%016llx PAR:%016llx\nVCPU:%p\n";

static void __hyp_text __hyp_call_panic_nvhe(u64 spsr, u64 elr, u64 par,
					     struct kvm_cpu_context *__host_ctxt)
{
	struct kvm_vcpu *vcpu;
	unsigned long str_va;
#ifdef CONFIG_STAGE2_KERNEL
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
#endif

	vcpu = __host_ctxt->__hyp_running_vcpu;

	if (read_sysreg(vttbr_el2)) {
		__timer_disable_traps(vcpu);
		__deactivate_traps(vcpu);
		__deactivate_vm(vcpu);
		__sysreg_restore_state_nvhe(__host_ctxt);
#ifdef CONFIG_STAGE2_KERNEL
		__host_el2_restore_state(el2_data);
#endif
	}

	/*
	 * Force the panic string to be loaded from the literal pool,
	 * making sure it is a kernel address and not a PC-relative
	 * reference.
	 */
	asm volatile("ldr %0, =__hyp_panic_string" : "=r" (str_va));

	__hyp_do_panic(str_va,
		       spsr,  elr,
		       read_sysreg(esr_el2),   read_sysreg_el2(far),
		       read_sysreg(hpfar_el2), par, vcpu);
}

static void __hyp_call_panic_vhe(u64 spsr, u64 elr, u64 par,
				 struct kvm_cpu_context *host_ctxt)
{
	struct kvm_vcpu *vcpu;
	vcpu = host_ctxt->__hyp_running_vcpu;

	__deactivate_traps(vcpu);
	sysreg_restore_host_state_vhe(host_ctxt);

	panic(__hyp_panic_string,
	      spsr,  elr,
	      read_sysreg_el2(esr),   read_sysreg_el2(far),
	      read_sysreg(hpfar_el2), par, vcpu);
}

void __hyp_text __noreturn hyp_panic(struct kvm_cpu_context *host_ctxt)
{
	u64 spsr = read_sysreg_el2(spsr);
	u64 elr = read_sysreg_el2(elr);
	u64 par = read_sysreg(par_el1);

	if (!has_vhe())
		__hyp_call_panic_nvhe(spsr, elr, par, host_ctxt);
	else
		__hyp_call_panic_vhe(spsr, elr, par, host_ctxt);

	unreachable();
}
