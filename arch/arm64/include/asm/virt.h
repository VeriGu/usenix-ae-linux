/*
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
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

#ifndef __ASM__VIRT_H
#define __ASM__VIRT_H

/*
 * The arm64 hcall implementation uses x0 to specify the hcall
 * number. A value less than HVC_STUB_HCALL_NR indicates a special
 * hcall, such as set vector. Any other value is handled in a
 * hypervisor specific way.
 *
 * The hypercall is allowed to clobber any of the caller-saved
 * registers (x0-x18), so it is advisable to use it through the
 * indirection of a function call (as implemented in hyp-stub.S).
 */

/*
 * HVC_SET_VECTORS - Set the value of the vbar_el2 register.
 *
 * @x1: Physical address of the new vector table.
 */
#define HVC_SET_VECTORS 0

/*
 * HVC_SOFT_RESTART - CPU soft reset, used by the cpu_soft_restart routine.
 */
#define HVC_SOFT_RESTART 1

/*
 * HVC_RESET_VECTORS - Restore the vectors to the original HYP stubs
 */
#define HVC_RESET_VECTORS 2

/* Max number of HYP stub hypercalls */
#define HVC_STUB_HCALL_NR 3

#define HVC_GET_VECTORS	5

#ifdef CONFIG_VERIFIED_KVM
#define HVC_ENABLE_S2_TRANS 6
#define HVC_TIMER_SET_CNTVOFF 7
#define HVC_VCPU_RUN 8
#define HVC_CLEAR_VM_S2_RANGE 9
/* VM BOOT */
#define HVC_SET_BOOT_INFO 10
#define HVC_REMAP_VM_IMAGE 11
#define HVC_VERIFY_VM_IMAGES 12
/* VM INIT */
#define HVC_REGISTER_KVM 13
#define HVC_REGISTER_VCPU 14
/* VM MGMT */
#define HVC_BOOT_FROM_SAVED_VM 19
#define HVC_ENCRYPT_BUF 20
#define HVC_DECRYPT_BUF 21
#define HVC_SAVE_CRYPT_VCPU 22
#define HVC_LOAD_CRYPT_VCPU 29
/* SMMU */
#define HVC_SMMU_FREE_PGD 23
#define HVC_SMMU_ALLOC_PGD 24
#define HVC_SMMU_LPAE_MAP 25
#define HVC_SMMU_LPAE_IOVA_TO_PHYS 26
#define HVC_SMMU_CLEAR 27
#define	HVC_PHYS_ADDR_IOREMAP 28
#endif

/* Error returned when an invalid stub number is passed into x0 */
#define HVC_STUB_ERR	0xbadca11

#define BOOT_CPU_MODE_EL1	(0xe11)
#define BOOT_CPU_MODE_EL2	(0xe12)

#ifndef __ASSEMBLY__

#include <asm/ptrace.h>
#include <asm/sections.h>
#include <asm/sysreg.h>
#include <asm/cpufeature.h>

/*
 * __boot_cpu_mode records what mode CPUs were booted in.
 * A correctly-implemented bootloader must start all CPUs in the same mode:
 * In this case, both 32bit halves of __boot_cpu_mode will contain the
 * same value (either 0 if booted in EL1, BOOT_CPU_MODE_EL2 if booted in EL2).
 *
 * Should the bootloader fail to do this, the two values will be different.
 * This allows the kernel to flag an error when the secondaries have come up.
 */
extern u32 __boot_cpu_mode[2];

void __hyp_set_vectors(phys_addr_t phys_vector_base);
void __hyp_reset_vectors(void);
phys_addr_t __hyp_get_vectors(void);
#ifdef CONFIG_VERIFIED_KVM
void enable_stage2_translation(phys_addr_t vttbr_base);
#endif

/* Reports the availability of HYP mode */
static inline bool is_hyp_mode_available(void)
{
	return (__boot_cpu_mode[0] == BOOT_CPU_MODE_EL2 &&
		__boot_cpu_mode[1] == BOOT_CPU_MODE_EL2);
}

/* Check if the bootloader has booted CPUs in different modes */
static inline bool is_hyp_mode_mismatched(void)
{
	return __boot_cpu_mode[0] != __boot_cpu_mode[1];
}

static inline bool is_kernel_in_hyp_mode(void)
{
	return read_sysreg(CurrentEL) == CurrentEL_EL2;
}

static inline bool has_vhe(void)
{
	if (cpus_have_const_cap(ARM64_HAS_VIRT_HOST_EXTN))
		return true;

	return false;
}

#endif /* __ASSEMBLY__ */

#endif /* ! __ASM__VIRT_H */
