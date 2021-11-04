/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HYPSEC_HYPSEC_H
#define HYPSEC_HYPSEC_H

#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_mmio.h>
#include <asm/kvm_emulate.h>
#include <asm/virt.h>
#include <asm/kernel-pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

#include <asm/hypsec_constant.h>

typedef unsigned long long u64;
typedef unsigned u32;
typedef u64 phys_addr_t;

/*
 * AbstractMachine
 */

static u32 inline check(u32 val) {
	return val;
};

static u64 inline check64(u64 val) {
	return val;
};

void    v_panic(void);
void    clear_phys_mem(u64 pfn);
//u64     get_shared_kvm(u32 vmid);
//u64     get_shared_vcpu(u32 vmid, u32 vcpuid);
u32     verify_image(u32 vmid, u32 load_idx, u64 addr);
///u64     get_sys_reg_desc_val(u32 index);
u64     get_exception_vector(u64 pstate);

static u64 inline get_shared_kvm(u32 vmid) {
    //return SHARED_KVM_START + vmid * sizeof(struct kvm);
    u64 shared_kvm_start = (u64)kvm_ksym_ref(shared_data_start);
    return shared_kvm_start + vmid * sizeof(struct kvm);
}

static u64 inline get_shared_vcpu(u32 vmid, u32 vcpuid) {
    u64 vcpu_off = sizeof(struct kvm) * EL2_MAX_VMID;
    u64 shared_vcpu_start = (u64)kvm_ksym_ref(shared_data_start) + vcpu_off;
    return shared_vcpu_start + (vmid * VCPU_PER_VM + vcpuid) * sizeof(struct kvm_vcpu);
}

static u64 inline get_sys_reg_desc_val(u32 index) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->s2_sys_reg_descs[index].val;
}

static void inline fetch_from_doracle(u32 vmid, u64 pfn, u64 pgnum) {
	return;
}
extern void reset_fp_regs(u32 vmid, int vcpu_id);

static u64 inline get_vm_fault_addr(u32 vmid, u32 vcpuid) {
	u64 hpfar;
	hpfar = get_shadow_ctxt(vmid, vcpuid, V_HPFAR_EL2);
	return ((hpfar & HPFAR_MASK) * 256UL);
}

static void inline mem_load_raw(u64 gfn, u32 reg) {
}

static void inline mem_store_raw(u64 gfn, u32 reg) {
}
/*
void    acquire_lock_pt(u32 vmid);
void    release_lock_pt(u32 vmid);
u64	pool_start(u32 vmid);
u64	pool_end(u32 vmid);
u64     pt_load(u32 vmid, u64 addr);
void    pt_store(u32 vmid, u64 addr, u64 value);
u64     get_pt_vttbr(u32 vmid);
void    set_pt_vttbr(u32 vmid, u64 vttbr);
*/

static void inline acquire_lock_pt(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_lock(&el2_data->vm_info[vmid].shadow_pt_lock);
};

static void inline release_lock_pt(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_unlock(&el2_data->vm_info[vmid].shadow_pt_lock);
};

static u64 inline pt_load(u32 vmid, u64 addr) {
	unsigned long *ptr = __el2_va(addr);
	return (u64)*ptr;
};

static void inline pt_store(u32 vmid, u64 addr, u64 value) {
	unsigned long *ptr = __el2_va(addr);
	*ptr = value;
};

/* for split PT pool */
#define PGD_BASE (PAGE_SIZE * 2)
#define PUD_BASE (PGD_BASE + (PAGE_SIZE * 16))
#define PMD_BASE SZ_2M
static u64 inline get_pgd_next(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->vm_info[vmid].pgd_pool;
};

static void inline set_pgd_next(u32 vmid, u64 next) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_data->vm_info[vmid].pgd_pool = next;
};

static u64 inline get_pud_next(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->vm_info[vmid].pud_pool;
};

static void inline set_pud_next(u32 vmid, u64 next) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_data->vm_info[vmid].pud_pool = next;
};

static u64 inline get_pmd_next(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->vm_info[vmid].pmd_pool;
};

static void inline set_pmd_next(u32 vmid, u64 next) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_data->vm_info[vmid].pmd_pool = next;
};

#define HOST_PUD_BASE (PGD_BASE + PAGE_SIZE * 128)
#define HOST_PMD_BASE (SZ_2M * 2)

static u64 inline pgd_pool_end(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 pool_start = el2_data->vm_info[vmid].page_pool_start;
	return pool_start + PUD_BASE;
}

static u64 inline pud_pool_end(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 pool_start = el2_data->vm_info[vmid].page_pool_start;
	if (vmid == HOSTVISOR)
		return pool_start + HOST_PMD_BASE;
	else
		return pool_start + PMD_BASE;
}

static u64 inline pmd_pool_end(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 pool_start = el2_data->vm_info[vmid].page_pool_start;
	if (vmid == COREVISOR)
		return pool_start + STAGE2_CORE_PAGES_SIZE;
	else if (vmid == HOSTVISOR)
		return pool_start + STAGE2_HOST_POOL_SIZE;
	return pool_start + PT_POOL_PER_VM;
}

/*
u32     get_mem_region_cnt(void);
u64     get_mem_region_base(u32 index);
u64     get_mem_region_size(u32 index);
u64     get_mem_region_index(u32 index);
u64     get_mem_region_flag(u32 index);
*/
static u32 inline get_mem_region_cnt(void) {
    	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	return el2_data->regions_cnt;
}

static u64 inline get_mem_region_base(u32 index) {
    	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	return el2_data->regions[index].base;
}
static u64 inline get_mem_region_size(u32 index) {
    	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	return el2_data->regions[index].size;
}

static u64 inline get_mem_region_index(u32 index) {
    	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	return el2_data->s2_memblock_info[index].index;
}

static u64 inline get_mem_region_flag(u32 index) {
    	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	return el2_data->regions[index].flags;
}

/*
void    acquire_lock_s2page(void);
void    release_lock_s2page(void);
u32     get_s2_page_vmid(u64 index);
void    set_s2_page_vmid(u64 index, u32 vmid);
u32     get_s2_page_count(u64 index);
void    set_s2_page_count(u64 index, u32 count);
*/

static void inline acquire_lock_s2page(void) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_lock(&el2_data->s2pages_lock);
}

static void inline release_lock_s2page(void) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_unlock(&el2_data->s2pages_lock);
}

static u32 inline get_s2_page_vmid(u64 index) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->s2_pages[index].vmid;
}

static void inline set_s2_page_vmid(u64 index, u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->s2_pages[index].vmid = vmid;
}

static u32 inline get_s2_page_count(u64 index) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->s2_pages[index].count;
}

static void inline set_s2_page_count(u64 index, u32 count) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->s2_pages[index].count = count;
}

static u64 inline get_s2_page_gfn(u64 index) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->s2_pages[index].gfn;
}

static void inline set_s2_page_gfn(u64 index, u64 gfn) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->s2_pages[index].gfn = gfn;
}

/*
void    acquire_lock_vm(u32 vmid);
void    release_lock_vm(u32 vmid);
u32     get_vm_state(u32 vmid);
void    set_vm_state(u32 vmid, u32 state);
u32     get_vcpu_state(u32 vmid, u32 vcpuid);
void    set_vcpu_state(u32 vmid, u32 vcpuid, u32 state);
u32     get_vm_power(u32 vmid);
void    set_vm_power(u32 vmid, u32 power);
u32     get_vm_inc_exe(u32 vmid);
void    set_vm_inc_exe(u32 vmid, u32 inc_exe);
u64     get_vm_kvm(u32 vmid);
void    set_vm_kvm(u32 vmid, u64 kvm);
u64     get_vm_vcpu(u32 vmid, u32 vcpuid);
void    set_vm_vcpu(u32 vmid, u32 vcpuid, u64 vcpu);
u32     get_vm_next_load_idx(u32 vmid);
void    set_vm_next_load_idx(u32 vmid, u32 load_idx);
u64     get_vm_load_addr(u32 vmid, u32 load_idx);
void    set_vm_load_addr(u32 vmid, u32 load_idx, u64 load_addr);
u64     get_vm_load_size(u32 vmid, u32 load_idx);
void    set_vm_load_size(u32 vmid, u32 load_idx, u64 size);
u64     get_vm_remap_addr(u32 vmid, u32 load_idx);
void    set_vm_remap_addr(u32 vmid, u32 load_idx, u64 remap_addr);
u64     get_vm_mapped_pages(u32 vmid, u32 load_idx);
void    set_vm_mapped_pages(u32 vmid, u32 load_idx, u64 mapped);
*/
static void inline acquire_lock_vm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_lock(&el2_data->vm_info[vmid].vm_lock);
}

static void inline release_lock_vm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_unlock(&el2_data->vm_info[vmid].vm_lock);
}

static u32 inline get_vm_state(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->vm_info[vmid].state;
}

static void inline set_vm_state(u32 vmid, u32 state) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->vm_info[vmid].state = state;
}

static u32 inline get_vcpu_first_run(u32 vmid, u32 vcpuid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->vm_info[vmid].int_vcpus[vcpuid].first_run;
}

static void inline set_vcpu_first_run(u32 vmid, u32 vcpuid, u32 state) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->vm_info[vmid].int_vcpus[vcpuid].first_run = state;
}

static u32 inline get_vcpu_state(u32 vmid, u32 vcpuid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->vm_info[vmid].int_vcpus[vcpuid].state;
}

static void inline set_vcpu_state(u32 vmid, u32 vcpuid, u32 state) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->vm_info[vmid].int_vcpus[vcpuid].state = state;
}

static void inline set_vm_power(u32 vmid, u32 power) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->vm_info[vmid].powered_on = power;
}

static u32 inline get_vm_power(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->vm_info[vmid].powered_on;
}

static u32 inline get_vm_inc_exe(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->vm_info[vmid].inc_exe;
}

static void inline set_vm_inc_exe(u32 vmid, u32 inc_exe) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->vm_info[vmid].inc_exe = inc_exe;
}

static u64 inline get_vm_kvm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return (u64)el2_data->vm_info[vmid].kvm;
}

static void inline set_vm_kvm(u32 vmid, u64 kvm) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->vm_info[vmid].kvm = (struct kvm*)kvm;
}

static u64 inline get_vm_vcpu(u32 vmid, u32 vcpuid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return (u64)el2_data->vm_info[vmid].int_vcpus[vcpuid].vcpu;
}

static void inline set_vm_vcpu(u32 vmid, u32 vcpuid, u64 vcpu) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    el2_data->vm_info[vmid].int_vcpus[vcpuid].vcpu = (struct kvm_vcpu*)vcpu;
}

static u32 inline get_vm_next_load_idx(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    return el2_data->vm_info[vmid].load_info_cnt;
}

static void inline set_vm_next_load_idx(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info_cnt = load_idx;
}

static u64 inline get_vm_load_addr(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].load_addr;
}

static void inline set_vm_load_addr(u32 vmid, u32 load_idx, u64 load_addr) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].load_addr = load_addr;
}

static u64 inline get_vm_load_size(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].size;
}

static void inline set_vm_load_size(u32 vmid, u32 load_idx, u64 size) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].size = size;
}

static u64 inline get_vm_remap_addr(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].el2_remap_addr;
}

static void inline set_vm_remap_addr(u32 vmid, u32 load_idx, u64 remap_addr) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].el2_remap_addr = remap_addr;
}

static u64 inline get_vm_mapped_pages(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].el2_mapped_pages;
}

static void inline set_vm_mapped_pages(u32 vmid, u32 load_idx, u64 mapped) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].el2_mapped_pages = mapped;
}

/*
void    acquire_lock_core(void);
void    release_lock_core(void);
u32     get_next_vmid(void);
void    set_next_vmid(u32 vmid);
u64     get_next_remap_ptr(void);
void    set_next_remap_ptr(u64 remap);
*/
static void inline acquire_lock_core(void) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_lock(&el2_data->abs_lock);
}

static void inline release_lock_core(void) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_unlock(&el2_data->abs_lock);
}

static u32 inline get_next_vmid(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->next_vmid;
}

static void inline set_next_vmid(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->next_vmid = vmid;
}

static u64 inline get_next_remap_ptr(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->last_remap_ptr + EL2_REMAP_START;
}

static void inline set_next_remap_ptr(u64 remap) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->last_remap_ptr = remap;
}

//int     get_cur_vmid(void);
//int     get_cur_vcpuid(void);
//u64     get_int_gpr(u32 vmid, u32 vcpuid, u32 index);
//u64     get_int_pc(u32 vmid, u32 vcpuid);
//u64     get_int_pstate(u32 vmid, u32 vcpuid);
static u64 inline get_int_gpr(u32 vmid, u32 vcpuid, u32 index) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	if (index >= 32)
		__hyp_panic();
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.ctxt.gp_regs.regs.regs[index];
}

static u64 inline get_int_pc(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.ctxt.gp_regs.regs.pc;
}

static u64 inline get_int_pstate(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.ctxt.gp_regs.regs.pstate;
}

//void	set_int_gpr(u32 vmid, u32 vcpuid, u32 index, u64 value);
static void inline set_int_gpr(u32 vmid, u32 vcpuid, u32 index, u64 value) {
       struct shared_data *shared_data;
       int offset = VCPU_IDX(vmid, vcpuid);
       struct kvm_vcpu *vcpu;
       if (index >= 32)
               __hyp_panic();
       shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
       vcpu = &shared_data->vcpu_pool[offset];
       vcpu->arch.ctxt.gp_regs.regs.regs[index] = value;
}

void	set_int_pstate(u32 vmid, u32 vcpuid, u64 value);
void    clear_shadow_gp_regs(u32 vmid, u32 vcpuid);
void    int_to_shadow_fp_regs(u32 vmid, u32 vcpuid);
void    int_to_shadow_decrypt(u32 vmid, u32 vcpuid);
void    shadow_to_int_encrypt(u32 vmid, u32 vcpuid);
//u32     get_shadow_dirty_bit(u32 vmid, u32 vcpuid);
//void    set_shadow_dirty_bit(u32 vmid, u32 vcpuid, u64 value);
static u32 inline get_shadow_dirty_bit(u32 vmid, u32 vcpuid) {
    	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	int offset = VCPU_IDX(vmid, vcpuid);
	return el2_data->shadow_vcpu_ctxt[offset].dirty;
}

static void inline set_shadow_dirty_bit(u32 vmid, u32 vcpuid, u64 value) {
    	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	int offset = VCPU_IDX(vmid, vcpuid);
	if (value)
		el2_data->shadow_vcpu_ctxt[offset].dirty |= value;
	else
		el2_data->shadow_vcpu_ctxt[offset].dirty = 0;
}
//u64     get_int_new_pte(u32 vmid, u32 vcpuid);
//u32     get_int_new_level(u32 vmid, u32 vcpuid);
//bool	get_int_writable(u32 vmid, u32 vcpuid);
static bool inline get_int_writable(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.writable;
}

static u64 inline get_int_new_pte(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.output;
}

static u32 inline get_int_new_level(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.level;
}

//u32     get_shadow_esr(u32 vmid, u32 vcpuid);
//u32     get_int_esr(u32 vmid, u32 vcpuid);

static u32 inline get_shadow_esr(u32 vmid, u32 vcpuid) {
    	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	int offset = VCPU_IDX(vmid, vcpuid);
	return el2_data->shadow_vcpu_ctxt[offset].esr;
}

static u32 inline get_int_esr(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.fault.esr_el2;
}

extern void test_aes(struct el2_data *el2_data);

//for image verification
uint8_t* get_vm_public_key(u32 vmid);
void set_vm_public_key(u32 vmid);
uint8_t* get_vm_load_signature(u32 vmid, u32 load_idx);
void set_vm_load_signature(u32 vmid, u32 load_idx);

//for SMMU
#define SMMU_POOL_START 65536UL
#define SMMU_PGD_START 131072UL
#define SMMU_PMD_START 196608UL
#define SMMU_POOL_END  SMMU_PAGES_SIZE	

#define SMMU_PMD_BASE	(PAGE_SIZE * 256)
static void inline acquire_lock_smmu(void) {
	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	stage2_spin_lock(&el2_data->smmu_lock);
};
static void inline release_lock_smmu(void) {
	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	stage2_spin_unlock(&el2_data->smmu_lock);
};

static u64 inline get_smmu_pgd_next(void) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->smmu_pgd_pool;
};

static void inline set_smmu_pgd_next(u64 next) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_data->smmu_pgd_pool = next;
};

static u64 inline smmu_pgd_end(void)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 pool_start = el2_data->smmu_page_pool_start;
	return pool_start + SMMU_PMD_BASE;
};

static u64 inline get_smmu_pmd_next(void) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->smmu_pmd_pool;
};

static void inline set_smmu_pmd_next(u64 next) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_data->smmu_pmd_pool = next;
};

static u64 inline smmu_pmd_end(void)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 pool_start = el2_data->smmu_page_pool_start;
	return pool_start + SMMU_POOL_END;
}

static u64 inline smmu_pt_load(u64 addr) {
	unsigned long *ptr = __el2_va(addr);
	return (u64)*ptr;
};

static void inline smmu_pt_store(u64 addr, u64 value) {
	unsigned long *ptr = __el2_va(addr);
	*ptr = value;
};

extern void smmu_pt_clear(u32 cbndx, u32 num);

u32 get_smmu_cfg_vmid(u32 cbndx, u32 num);
void set_smmu_cfg_vmid(u32 cbndx, u32 num, u32 vmid);
u64 get_smmu_cfg_hw_ttbr(u32 cbndx, u32 num);
void set_smmu_cfg_hw_ttbr(u32 cbndx, u32 num, u64 hw_ttbr);
u32 get_smmu_num_context_banks(u32 num);
u32 get_smmu_pgshift(u32 num);
u32 get_smmu_num(void);
u64 get_smmu_size(u32 num);

static u64 inline get_smmu_base(u32 num)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->smmus[num].phys_base;
}

static u64 inline get_smmu_hyp_base(u32 num)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->smmus[num].hyp_base;
}

void set_per_cpu_host_regs(u64 hr); 
void set_host_regs(int nr, u64 value);
u64 get_host_regs(int nr);

static u64 inline get_phys_mem_size(void)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->phys_mem_size;
}

static u64 inline get_phys_mem_start_pfn(void)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->phys_mem_start >> PAGE_SHIFT;
}

static u64 inline get_phys_mem_start(void)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->phys_mem_start;
}

static void inline acquire_lock_spt(void) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_lock(&el2_data->spt_lock);
};

static void inline release_lock_spt(void) {
    struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
    stage2_spin_unlock(&el2_data->spt_lock);
};

void encrypt_buf(u32 vmid, u64 in_buf, u64 out_buf, uint32_t len);
void decrypt_buf(u32 vmid, u64 in_buf, u64 out_buf, uint32_t len);

static u64 inline get_tmp_buf(void) {
	u64 ret = (u64)kern_hyp_va((void*)&stage2_tmp_pgs_start);
	return ret;
};

/*
 * PTAlloc
 */

u64 alloc_s2pt_pgd(u32 vmid);
u64 alloc_s2pt_pud(u32 vmid);
u64 alloc_s2pt_pmd(u32 vmid);
//u64 alloc_smmu_pgd_page(void);
//u64 alloc_smmu_pmd_page(void);

/*
 * PTWalk
 */

u64 walk_pgd(u32 vmid, u64 vttbr, u64 addr, u32 alloc);
u64 walk_pud(u32 vmid, u64 pgd, u64 addr, u32 alloc);
u64 walk_pmd(u32 vmid, u64 pud, u64 addr, u32 alloc);
u64 walk_pte(u32 vmid, u64 pmd, u64 addr);
void v_set_pmd(u32 vmid, u64 pud, u64 addr, u64 pmd);
void v_set_pte(u32 vmid, u64 pmd, u64 addr, u64 pte);
u64 walk_smmu_pgd(u64 ttbr, u64 addr, u32 alloc);
u64 walk_smmu_pmd(u64 pgd, u64 addr, u32 alloc);
u64 walk_smmu_pte(u64 pmd, u64 addr);
void set_smmu_pte(u64 pmd, u64 addr, u64 pte);

/*
 * NPTWalk
 */

u32 get_npt_level(u32 vmid, u64 addr);
u64 walk_npt(u32 vmid, u64 addr);
void set_npt(u32 vmid, u64 addr, u32 level, u64 pte);

/*
 * NPTOps
 */

u32 get_level_s2pt(u32 vmid, u64 addr);
u64 walk_s2pt(u32 vmid, u64 addr);
void mmap_s2pt(u32 vmid, u64 addr, u32 level, u64 pte);
void clear_pfn_host(u64 pfn);
extern void kvm_tlb_flush_vmid_ipa_host(phys_addr_t ipa);

/*
 * MemRegion
 */

u32 mem_region_search(u64 addr);

/*
 * PageIndex
 */

u64 get_s2_page_index(u64 addr);

/*
 * PageManager
 */

u32 get_pfn_owner(u64 pfn);
void set_pfn_owner(u64 pfn, u32 vmid);
u32 get_pfn_count(u64 pfn);
void set_pfn_count(u64 pfn, u32 count);
u64 get_pfn_map(u64 pfn);
void set_pfn_map(u64 pfn, u64 gfn);

/*
 * VMPower
 */

void set_vm_poweroff(u32 vmid);
u32 get_vm_poweron(u32 vmid);

/*
 * MemManagerAux
 */
u32 check_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn, u64 pgnum);
void set_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn, u64 pgnum);

/*
 * MemManager
 */

void map_page_host(u64 addr);
void clear_vm_page(u32 vmid, u64 pfn);
void assign_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn);
void assign_pfn_to_smmu(u32 vmid, u64 gfn, u64 pfn);
void map_pfn_vm(u32 vmid, u64 addr, u64 pte, u32 level);
void grant_vm_page(u32 vmid, u64 pfn);
void revoke_vm_page(u32 vmid, u64 pfn);
void clear_phys_page(unsigned long pfn);
void update_smmu_page(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte);
void unmap_smmu_page(u32 cbndx, u32 index, u64 iova);

/*
 * MemoryOps
 */

void clear_vm_stage2_range(u32 vmid, u64 start, u64 size);
void prot_and_map_vm_s2pt(u32 vmid, u64 addr, u64 pte, u32 level);
//void grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);
//void revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);
void map_vm_io(u32 vmid, u64 gpa, u64 pa);
void clear_vm_range(u32 vmid, u64 pfn, u64 num);

/*
 * BootCore
 */

u32 gen_vmid(void);
u64 alloc_remap_addr(u64 pgnum);

/*
 * BootAux
 */

void unmap_and_load_vm_image(u32 vmid, u64 target_addr, u64 remap_addr, u64 num);

/*
 * BootOps
 */

u32 vm_is_inc_exe(u32 vmid);
void boot_from_inc_exe(u32 vmid);
u64 search_load_info(u32 vmid, u64 addr);
void set_vcpu_active(u32 vmid, u32 vcpuid);
void set_vcpu_inactive(u32 vmid, u32 vcpuid);
void register_vcpu(u32 vmid, u32 vcpuid);
u32 register_kvm(void);
u32 set_boot_info(u32 vmid, u64 load_addr, u64 size);
void remap_vm_image(u32 vmid, u64 pfn, u32 load_idx);
void verify_and_load_images(u32 vmid);

void alloc_smmu(u32 vmid, u32 cbndx, u32 index); 
void assign_smmu(u32 vmid, u32 pfn, u32 gfn); 
void map_smmu(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte);
void clear_smmu(u32 vmid, u32 cbndx, u32 index, u64 iova);
void map_io(u32 vmid, u64 gpa, u64 pa);


/*
 * VCPUOpsAux
 */

void reset_gp_regs(u32 vmid, u32 vcpuid);
void reset_sys_regs(u32 vmid, u32 vcpuid);
//void save_sys_regs(u32 vmid, u32 vcpuid);
//void restore_sys_regs(u32 vmid, u32 vcpuid);
void sync_dirty_to_shadow(u32 vmid, u32 vcpuid);
void prep_wfx(u32 vmid, u32 vcpuid);
void prep_hvc(u32 vmid, u32 vcpuid);
void prep_abort(u32 vmid, u32 vcpuid);
void v_hypsec_inject_undef(u32 vmid, u32 vcpuid);
void v_update_exception_gp_regs(u32 vmid, u32 vcpuid);
void post_handle_shadow_s2pt_fault(u32 vmid, u32 vcpuid, u64 addr);


/*
 * VCPUOps
 */

void save_shadow_kvm_regs(void);
void restore_shadow_kvm_regs(void);
void __save_encrypted_vcpu(u32 vmid, u32 vcpu_id);
void __load_encrypted_vcpu(u32 vmid, u32 vcpu_id);

/*
 * MmioOps
 */
u32 emulate_mmio(u64 addr, u32 hsr);
void   __el2_free_smmu_pgd(u32 cbndx, u32 index);
void   __el2_alloc_smmu_pgd(u32 cbndx, u32 vmid, u32 index);
void  __el2_arm_lpae_map(u64 iova, u64 paddr, u64 prot, u32 cbndx, u32 index);
u64 __el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 index);
void __el2_arm_lpae_clear(u64 iova, u32 cbndx, u32 index);
void smmu_assign_page(u32 cbndx, u32 index, u64 pfn, u64 gfn);
void smmu_map_page(u32 cbndx, u32 index, u64 iova, u64 pte);
u64 el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 index);

/*
 * MmioOpsAux
 */
void handle_host_mmio(u64 index, u32 hsr);
u32 is_smmu_range(u64 addr);

/*
 * MmioCore
 */
void mmap_smmu(u32 vmid, u64 ttbr, u64 addr, u64 pte);
u64 walk_smmu(u32 vmid, u64 ttbr, u64 addr);
void handle_smmu_write(u32 hsr, u64 fault_ipa, u32 len, u32 index);
void handle_smmu_read(u32 hsr, u64 fault_ipa, u32 len);

/*
 * MmioCoreAux
 */
u32 handle_smmu_global_access(u32 hsr, u64 offset, u32 smmu_index);
u32 handle_smmu_cb_access(u64 offset);
void __handle_smmu_write(u32 hsr, u64 fault_ipa, u32 len, u64 val, u32 write_val);
void __handle_smmu_read(u32 hsr, u64 fault_ipa, u32 len);

u64 host_get_mmio_data(u32 hsr);
u64 smmu_init_pte(u64 prot, u64 paddr);
u64 smmu_get_cbndx(u64 offset);

/*
 * MemHandler
 */
void __hyp_text el2_clear_vm_stage2_range(u32 vmid, u64 start, u64 size);
void el2_arm_lpae_map(u64 iova, u64 paddr, u64 prot, u32 cbndx, u32 index);
void el2_kvm_phys_addr_ioremap(u32 vmid, u64 gpa, u64 pa, u64 size);

/*
 * MmioPTAlloc
 */
u64 alloc_smmu_pgd_page(void);
u64 alloc_smmu_pmd_page(void);

/*
 * MmioSPTOps
 */
void init_spt(u32 cbndx, u32 index);
u64 walk_spt(u32 cbndx, u32 index, u64 addr);
void map_spt(u32 cbndx, u32 index, u64 addr, u64 pte);
u64 unmap_spt(u32 cbndx, u32 index, u64 addr); 

/*
 * MmioPTWalk
 */
u64 walk_smmu_pgd(u64 ttbr, u64 addr, u32 alloc);
u64 walk_smmu_pmd(u64 pgd, u64 addr, u32 alloc);
u64 walk_smmu_pte(u64 pmd, u64 addr);
void set_smmu_pte(u64 pmd, u64 addr, u64 pte);

/*
 * MmioSPTWalk
 */
void clear_smmu_pt(u32 cbndx, u32 index);
u64 unmap_smmu_pt(u32 cbndx, u32 index, u64 addr);
u64 walk_smmu_pt(u32 cbndx, u32 num, u64 addr);
void set_smmu_pt(u32 cbndx, u32 num, u64 addr, u64 pte);

/*
 * Management
 */
void __el2_encrypt_buf(u32 vmid, u64 buf, u64 out_buf);
void __el2_decrypt_buf(u32 vmid, void *buf, u32 len);
extern void decrypt_gp_regs(u32 vmid, u32 vcpu_id);
extern void encrypt_gp_regs(u32 vmid, u32 vcpu_id);
extern void decrypt_sys_regs(u32 vmid, u32 vcpu_id);
extern void encrypt_sys_regs(u32 vmid, u32 vcpu_id);
#endif //HYPSEC_HYPSEC_H
