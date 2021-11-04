/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>

#include <asm/hypsec_host.h>
#include <asm/hypsec_constant.h>

#define OFF SYSREGS_START 
static void __hyp_text __vm_sysreg_save_common_state(struct shadow_vcpu_context *ctxt)
{
	ctxt->sys_regs[MDSCR_EL1] = read_sysreg(mdscr_el1);

	/*
	 * The host arm64 Linux uses sp_el0 to point to 'current' and it must
	 * therefore be saved/restored on every entry/exit to/from the guest.
	 */
	ctxt->gp_regs.regs.sp = read_sysreg(sp_el0);
}

static void __hyp_text __vm_sysreg_save_user_state(struct shadow_vcpu_context *ctxt)
{
	ctxt->sys_regs[TPIDR_EL0] = read_sysreg(tpidr_el0);
	ctxt->sys_regs[TPIDRRO_EL0] = read_sysreg(tpidrro_el0);
}

static void __hyp_text __vm_sysreg_save_el1_state(struct shadow_vcpu_context *ctxt)
{
	ctxt->sys_regs[MPIDR_EL1] = read_sysreg(vmpidr_el2);
	ctxt->sys_regs[CSSELR_EL1] = read_sysreg(csselr_el1);
	ctxt->sys_regs[SCTLR_EL1] = read_sysreg_el1(sctlr);
	ctxt->sys_regs[ACTLR_EL1] = read_sysreg(actlr_el1);
	ctxt->sys_regs[CPACR_EL1] = read_sysreg_el1(cpacr);
	ctxt->sys_regs[TTBR0_EL1] = read_sysreg_el1(ttbr0);
	ctxt->sys_regs[TTBR1_EL1] = read_sysreg_el1(ttbr1);
	ctxt->sys_regs[TCR_EL1] = read_sysreg_el1(tcr);
	ctxt->sys_regs[ESR_EL1] = read_sysreg_el1(esr);
	ctxt->sys_regs[AFSR0_EL1] = read_sysreg_el1(afsr0);
	ctxt->sys_regs[AFSR1_EL1] = read_sysreg_el1(afsr1);
	ctxt->sys_regs[FAR_EL1] = read_sysreg_el1(far);
	ctxt->sys_regs[MAIR_EL1] = read_sysreg_el1(mair);
	ctxt->sys_regs[VBAR_EL1] = read_sysreg_el1(vbar);
	ctxt->sys_regs[CONTEXTIDR_EL1] = read_sysreg_el1(contextidr);
	ctxt->sys_regs[AMAIR_EL1] = read_sysreg_el1(amair);
	ctxt->sys_regs[CNTKCTL_EL1] = read_sysreg_el1(cntkctl);
	ctxt->sys_regs[PAR_EL1] = read_sysreg(par_el1);
	ctxt->sys_regs[TPIDR_EL1] = read_sysreg(tpidr_el1);

	ctxt->gp_regs.sp_el1 = read_sysreg(sp_el1);
	ctxt->gp_regs.elr_el1 = read_sysreg_el1(elr);
	ctxt->gp_regs.spsr[0] = read_sysreg_el1(spsr);	
}

static void __hyp_text __vm_sysreg_save_el2_return_state(struct shadow_vcpu_context *ctxt)
{
	ctxt->gp_regs.regs.pc = read_sysreg_el2(elr);
	ctxt->gp_regs.regs.pstate = read_sysreg_el2(spsr);
}

static void __hyp_text __vm_sysreg_restore_el1_state(struct shadow_vcpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[MPIDR_EL1],	vmpidr_el2);
	write_sysreg(ctxt->sys_regs[CSSELR_EL1], csselr_el1);
	write_sysreg_el1(ctxt->sys_regs[SCTLR_EL1], sctlr);
	write_sysreg(ctxt->sys_regs[ACTLR_EL1],	actlr_el1);
	write_sysreg_el1(ctxt->sys_regs[CPACR_EL1], cpacr);
	write_sysreg_el1(ctxt->sys_regs[TTBR0_EL1], ttbr0);
	write_sysreg_el1(ctxt->sys_regs[TTBR1_EL1], ttbr1);
	write_sysreg_el1(ctxt->sys_regs[TCR_EL1], tcr);
	write_sysreg_el1(ctxt->sys_regs[ESR_EL1], esr);
	write_sysreg_el1(ctxt->sys_regs[AFSR0_EL1], afsr0);
	write_sysreg_el1(ctxt->sys_regs[AFSR1_EL1], afsr1);
	write_sysreg_el1(ctxt->sys_regs[FAR_EL1], far);
	write_sysreg_el1(ctxt->sys_regs[MAIR_EL1], mair);
	write_sysreg_el1(ctxt->sys_regs[VBAR_EL1], vbar);
	write_sysreg_el1(ctxt->sys_regs[CONTEXTIDR_EL1], contextidr);
	write_sysreg_el1(ctxt->sys_regs[AMAIR_EL1], amair);
	write_sysreg_el1(ctxt->sys_regs[CNTKCTL_EL1], cntkctl);
	write_sysreg(ctxt->sys_regs[PAR_EL1], par_el1);
	write_sysreg(ctxt->sys_regs[TPIDR_EL1],	tpidr_el1);

	write_sysreg(ctxt->gp_regs.sp_el1, sp_el1);
	write_sysreg_el1(ctxt->gp_regs.elr_el1,	elr);
	write_sysreg_el1(ctxt->gp_regs.spsr[0], spsr);
}

static void __hyp_text __vm_sysreg_restore_common_state(struct shadow_vcpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[MDSCR_EL1], mdscr_el1);

	/*
	 * The host arm64 Linux uses sp_el0 to point to 'current' and it must
	 * therefore be saved/restored on every entry/exit to/from the guest.
	 */
	write_sysreg(ctxt->gp_regs.regs.sp, sp_el0);
}

static void __hyp_text
__vm_sysreg_restore_el2_return_state(struct shadow_vcpu_context *ctxt)
{
	write_sysreg_el2(ctxt->gp_regs.regs.pc, elr);
	write_sysreg_el2(ctxt->gp_regs.regs.pstate, spsr);
}

static void __hyp_text
__vm_sysreg_restore_user_state(struct shadow_vcpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[TPIDR_EL0], tpidr_el0);
	write_sysreg(ctxt->sys_regs[TPIDRRO_EL0], tpidrro_el0);
}

void __hyp_text __vm_sysreg_restore_state_nvhe_opt(struct shadow_vcpu_context *ctxt)
{
	__vm_sysreg_restore_el1_state(ctxt);
	__vm_sysreg_restore_common_state(ctxt);
	__vm_sysreg_restore_user_state(ctxt);
	__vm_sysreg_restore_el2_return_state(ctxt);
}

void __hyp_text __vm_sysreg_save_state_nvhe_opt(struct shadow_vcpu_context *ctxt)
{
	__vm_sysreg_save_el1_state(ctxt);
	__vm_sysreg_save_common_state(ctxt);
	__vm_sysreg_save_user_state(ctxt);
	__vm_sysreg_save_el2_return_state(ctxt);
}
