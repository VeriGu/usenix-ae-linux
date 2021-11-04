/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM_STAGE2_BOOT__
#define __ARM_STAGE2_BOOT__

#define VM_LOADER_START		0x40000000
#define KERNEL64_LOAD_ADDR	0x00080000

#define EL2_MAX_VMID		65
//Hostvisor:0 + 32 VMIDs + 1 COREVISOR
#define EL2_VM_INFO_SIZE	EL2_MAX_VMID + 1

#define HYPSEC_MAX_VCPUS	4
#define HYPSEC_MAX_CPUS		16	
#define HYPSEC_MAX_LOAD_IMG	5

/* Below is copied from QEMU  */
typedef enum {
	FIXUP_NONE = 0,   /* do nothing */
	FIXUP_TERMINATOR, /* end of insns */
	FIXUP_BOARDID,    /* overwrite with board ID number */
	FIXUP_ARGPTR,     /* overwrite with pointer to kernel args */
	FIXUP_ENTRYPOINT, /* overwrite with kernel entry point */
	FIXUP_GIC_CPU_IF, /* overwrite with GIC CPU interface address */
	FIXUP_BOOTREG,    /* overwrite with boot register address */
	FIXUP_DSB,        /* overwrite with correct DSB insn for cpu */
	FIXUP_MAX,
} FixupType;

typedef struct ARMInsnFixup {
	uint32_t insn;
	FixupType fixup;
} ARMInsnFixup;

extern int el2_set_boot_info(u32 vmid, unsigned long load_addr,
			unsigned long size, int image_type);
extern int el2_remap_vm_image(u32 vmid, unsigned long pfn, int id);
extern int el2_verify_and_load_images(u32 vmid);
extern int hypsec_get_vm_state(u32 vmid);
extern void hypsec_set_vcpu_state(u32 vmid, int vcpu_id, int state);
extern void hypsec_set_vcpu_active(u32 vmid, int vcpu_id);

extern bool is_valid_vm(struct kvm_vcpu *vcpu);
extern arch_spinlock_t* get_shadow_pt_lock(u32 vmid);

int __el2_set_boot_info(u32 vmid, unsigned long load_addr,
			 unsigned long size, int image_type);
void __el2_remap_vm_image(u32 vmid, unsigned long pfn, int id);
bool __el2_verify_and_load_images(u32 vmid);
void __el2_boot_from_inc_exe(u32 vmid);

struct kvm* hypsec_vmid_to_kvm(u32 vmid);
struct kvm_vcpu* hypsec_vcpu_id_to_vcpu(u32 vmid, int vcpu_id);
struct shadow_vcpu_context* hypsec_vcpu_id_to_shadow_ctxt( u32 vmid, int vcpu_id);
#endif /* __ARM_STAGE2_BOOT__ */
