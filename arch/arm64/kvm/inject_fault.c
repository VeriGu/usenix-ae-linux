/*
 * Fault injection for both 32 and 64bit guests.
 *
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * Based on arch/arm/kvm/emulate.c
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 *
 * This program is free software: you can redistribute it and/or modify
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

#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/esr.h>
#ifdef CONFIG_STAGE2_KERNEL
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/hypsec_vcpu.h>
#endif

#define PSTATE_FAULT_BITS_64 	(PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | \
				 PSR_I_BIT | PSR_D_BIT)

#define CURRENT_EL_SP_EL0_VECTOR	0x0
#define CURRENT_EL_SP_ELx_VECTOR	0x200
#define LOWER_EL_AArch64_VECTOR		0x400
#define LOWER_EL_AArch32_VECTOR		0x600

enum exception_type {
	except_type_sync	= 0,
	except_type_irq		= 0x80,
	except_type_fiq		= 0x100,
	except_type_serror	= 0x180,
};

static u64 get_except_vector(struct kvm_vcpu *vcpu, enum exception_type type)
{
	u64 exc_offset;

	switch (*vcpu_cpsr(vcpu) & (PSR_MODE_MASK | PSR_MODE32_BIT)) {
	case PSR_MODE_EL1t:
		exc_offset = CURRENT_EL_SP_EL0_VECTOR;
		break;
	case PSR_MODE_EL1h:
		exc_offset = CURRENT_EL_SP_ELx_VECTOR;
		break;
	case PSR_MODE_EL0t:
		exc_offset = LOWER_EL_AArch64_VECTOR;
		break;
	default:
		exc_offset = LOWER_EL_AArch32_VECTOR;
	}

	return vcpu_read_sys_reg(vcpu, VBAR_EL1) + exc_offset + type;
}
#ifdef CONFIG_STAGE2_KERNEL
static u64 __hyp_text hypsec_get_except_vector(struct shadow_vcpu_context *shadow_ctxt,
					enum exception_type type)
{
	u64 exc_offset;

	switch (*shadow_vcpu_cpsr(shadow_ctxt) & (PSR_MODE_MASK | PSR_MODE32_BIT)) {
	case PSR_MODE_EL1t:
		exc_offset = CURRENT_EL_SP_EL0_VECTOR;
		break;
	case PSR_MODE_EL1h:
		exc_offset = CURRENT_EL_SP_ELx_VECTOR;
		break;
	case PSR_MODE_EL0t:
		exc_offset = LOWER_EL_AArch64_VECTOR;
		break;
	default:
		exc_offset = LOWER_EL_AArch32_VECTOR;
	}

	return shadow_ctxt->sys_regs[VBAR_EL1] + exc_offset + type;
}
#endif

#ifdef CONFIG_STAGE2_KERNEL
/* We only inject UNDEF fault to VM now. */
void __hyp_text update_exception_gp_regs(struct shadow_vcpu_context *shadow_ctxt)
{
	struct kvm_regs *gp_regs;
	unsigned long cpsr;
	u64 flag;
	u32 esr = 0;
	bool is_aarch32;

	flag = shadow_ctxt->dirty;
	if (flag & PENDING_UNDEF_INJECT)
		esr = (ESR_ELx_EC_UNKNOWN << ESR_ELx_EC_SHIFT);
	else
		BUG();

	gp_regs = &shadow_ctxt->gp_regs;
	cpsr = gp_regs->regs.pstate;
	is_aarch32 = (cpsr & PSR_MODE32_BIT);

	*__shadow_vcpu_elr_el1(shadow_ctxt) = gp_regs->regs.pc;

	/* Setup cpsr temporarily before calling get_except_vector */
	*shadow_vcpu_cpsr(shadow_ctxt) = cpsr;
	gp_regs->regs.pc = hypsec_get_except_vector(shadow_ctxt, 0);
	*shadow_vcpu_cpsr(shadow_ctxt) = 0;

	gp_regs->regs.pstate = PSTATE_FAULT_BITS_64;
	shadow_vcpu_write_spsr(shadow_ctxt, cpsr);

	shadow_ctxt->sys_regs[ESR_EL1] = esr;
}

void __hyp_text hypsec_inject_undef(struct shadow_vcpu_context *shadow_ctxt)
{
	/* We currently support injecting UNDEF to 64-bit VM */
	shadow_ctxt->dirty |= PENDING_UNDEF_INJECT;
}
#endif

static void inject_abt64(struct kvm_vcpu *vcpu, bool is_iabt, unsigned long addr)
{
	unsigned long cpsr = *vcpu_cpsr(vcpu);
	bool is_aarch32 = vcpu_mode_is_32bit(vcpu);
	u32 esr = 0;

	vcpu_write_elr_el1(vcpu, *vcpu_pc(vcpu));
	*vcpu_pc(vcpu) = get_except_vector(vcpu, except_type_sync);

	*vcpu_cpsr(vcpu) = PSTATE_FAULT_BITS_64;
	vcpu_write_spsr(vcpu, cpsr);

	vcpu_write_sys_reg(vcpu, addr, FAR_EL1);

	/*
	 * Build an {i,d}abort, depending on the level and the
	 * instruction set. Report an external synchronous abort.
	 */
	if (kvm_vcpu_trap_il_is32bit(vcpu))
		esr |= ESR_ELx_IL;

	/*
	 * Here, the guest runs in AArch64 mode when in EL1. If we get
	 * an AArch32 fault, it means we managed to trap an EL0 fault.
	 */
	if (is_aarch32 || (cpsr & PSR_MODE_MASK) == PSR_MODE_EL0t)
		esr |= (ESR_ELx_EC_IABT_LOW << ESR_ELx_EC_SHIFT);
	else
		esr |= (ESR_ELx_EC_IABT_CUR << ESR_ELx_EC_SHIFT);

	if (!is_iabt)
		esr |= ESR_ELx_EC_DABT_LOW << ESR_ELx_EC_SHIFT;

	vcpu_write_sys_reg(vcpu, esr | ESR_ELx_FSC_EXTABT, ESR_EL1);
}

static void inject_undef64(struct kvm_vcpu *vcpu)
{
	unsigned long cpsr = *vcpu_cpsr(vcpu);
	u32 esr = (ESR_ELx_EC_UNKNOWN << ESR_ELx_EC_SHIFT);

	vcpu_write_elr_el1(vcpu, *vcpu_pc(vcpu));
	*vcpu_pc(vcpu) = get_except_vector(vcpu, except_type_sync);

	*vcpu_cpsr(vcpu) = PSTATE_FAULT_BITS_64;
	vcpu_write_spsr(vcpu, cpsr);

	/*
	 * Build an unknown exception, depending on the instruction
	 * set.
	 */
	if (kvm_vcpu_trap_il_is32bit(vcpu))
		esr |= ESR_ELx_IL;

	vcpu_write_sys_reg(vcpu, esr, ESR_EL1);
}

/**
 * kvm_inject_dabt - inject a data abort into the guest
 * @vcpu: The VCPU to receive the undefined exception
 * @addr: The address to report in the DFAR
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
void kvm_inject_dabt(struct kvm_vcpu *vcpu, unsigned long addr)
{
	if (vcpu_el1_is_32bit(vcpu))
		kvm_inject_dabt32(vcpu, addr);
	else
		inject_abt64(vcpu, false, addr);
}

/**
 * kvm_inject_pabt - inject a prefetch abort into the guest
 * @vcpu: The VCPU to receive the undefined exception
 * @addr: The address to report in the DFAR
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
void kvm_inject_pabt(struct kvm_vcpu *vcpu, unsigned long addr)
{
	if (vcpu_el1_is_32bit(vcpu))
		kvm_inject_pabt32(vcpu, addr);
	else
		inject_abt64(vcpu, true, addr);
}

/**
 * kvm_inject_undefined - inject an undefined instruction into the guest
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 */
void kvm_inject_undefined(struct kvm_vcpu *vcpu)
{
	if (vcpu_el1_is_32bit(vcpu))
		kvm_inject_undef32(vcpu);
	else
		inject_undef64(vcpu);
}

static void pend_guest_serror(struct kvm_vcpu *vcpu, u64 esr)
{
	vcpu_set_vsesr(vcpu, esr);
	*vcpu_hcr(vcpu) |= HCR_VSE;
}

/**
 * kvm_inject_vabt - inject an async abort / SError into the guest
 * @vcpu: The VCPU to receive the exception
 *
 * It is assumed that this code is called from the VCPU thread and that the
 * VCPU therefore is not currently executing guest code.
 *
 * Systems with the RAS Extensions specify an imp-def ESR (ISV/IDS = 1) with
 * the remaining ISS all-zeros so that this error is not interpreted as an
 * uncategorized RAS error. Without the RAS Extensions we can't specify an ESR
 * value, so the CPU generates an imp-def value.
 */
void kvm_inject_vabt(struct kvm_vcpu *vcpu)
{
	pend_guest_serror(vcpu, ESR_ELx_ISV);
}

#ifdef CONFIG_STAGE2_KERNEL
static u64 __hyp_text stage2_get_exception_vector(u64 pstate)
{
	u64 exc_offset;

	switch (pstate & (PSR_MODE_MASK | PSR_MODE32_BIT)) {
	case PSR_MODE_EL1t:
		exc_offset = CURRENT_EL_SP_EL0_VECTOR;
		break;
	case PSR_MODE_EL1h:
		exc_offset = CURRENT_EL_SP_ELx_VECTOR;
		break;
	case PSR_MODE_EL0t:
		exc_offset = LOWER_EL_AArch64_VECTOR;
		break;
	default:
		exc_offset = LOWER_EL_AArch32_VECTOR;
	}

	return read_sysreg(vbar_el1) + exc_offset;
}

/* Currently, we do not handle lower level fault from 32bit host */
void __hyp_text stage2_inject_el1_fault(unsigned long addr)
{
	u64 pstate = read_sysreg(spsr_el2);
	u32 esr = 0, esr_el2;
	bool is_iabt = false;

	write_sysreg(read_sysreg(elr_el2), elr_el1);
	write_sysreg(stage2_get_exception_vector(pstate), elr_el2);

	write_sysreg(addr, far_el1);
	write_sysreg(PSTATE_FAULT_BITS_64, spsr_el2);
	write_sysreg(pstate, spsr_el1);

	esr_el2 = read_sysreg(esr_el2);
	if ((esr_el2 << ESR_ELx_EC_SHIFT) == ESR_ELx_EC_IABT_LOW)
		is_iabt = true;

	/* To get fancier debug info that includes LR from the guest Linux,
	 * we can intentionally comment out the EC_LOW_ABT case and always
	 * inject the CUR mode exception.
	 */
	if ((pstate & PSR_MODE_MASK) == PSR_MODE_EL0t)
		esr |= (ESR_ELx_EC_IABT_LOW << ESR_ELx_EC_SHIFT);
	else
		esr |= (ESR_ELx_EC_IABT_CUR << ESR_ELx_EC_SHIFT);

	if (!is_iabt)
		esr |= ESR_ELx_EC_DABT_LOW << ESR_ELx_EC_SHIFT;

	esr |= ESR_ELx_FSC_EXTABT;
	write_sysreg(esr, esr_el1);
}
#endif
