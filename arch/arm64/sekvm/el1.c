/* SPDX-License-Identifier: GPL-2.0 */
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
#include <asm/hypsec_constant.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

#include "hypsec.h"

u64 mach_phys_mem_start;
u64 mach_phys_mem_size;

//hypsec_host.c
#define Op0(_x) 	.Op0 = _x
#define Op1(_x) 	.Op1 = _x
#define CRn(_x)		.CRn = _x
#define CRm(_x) 	.CRm = _x
#define Op2(_x) 	.Op2 = _x

#define SYS_DESC(reg)					\
	Op0(sys_reg_Op0(reg)), Op1(sys_reg_Op1(reg)),	\
	CRn(sys_reg_CRn(reg)), CRm(sys_reg_CRm(reg)),	\
	Op2(sys_reg_Op2(reg))

static struct s2_sys_reg_desc host_sys_reg_descs[] = {
	/* TTBR0_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b000),
	  TTBR0_EL1, 0x1de7ec7edbadc0deULL },
	/* TTBR1_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b001),
	  TTBR1_EL1, 0x1de7ec7edbadc0deULL },
	/* VBAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1100), CRm(0b0000), Op2(0b000),
	  VBAR_EL1, 0 },
	/* SCTLR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b000),
	  SCTLR_EL1, 0x00C50078 },
	/* ESR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0010), Op2(0b000),
	  ESR_EL1, 0x1de7ec7edbadc0deULL },
	/* FAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0110), CRm(0b0000), Op2(0b000),
	  FAR_EL1, 0x1de7ec7edbadc0deULL },
	/* TPIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1101), CRm(0b0000), Op2(0b100),
	  TPIDR_EL1, 0x1de7ec7edbadc0deULL },
	/* TPIDRRO_EL0 */
	{ Op0(0b11), Op1(0b011), CRn(0b1101), CRm(0b0000), Op2(0b011),
	  TPIDRRO_EL0, 0x1de7ec7edbadc0deULL },
	/* TPIDR_EL0 */
	{ Op0(0b11), Op1(0b011), CRn(0b1101), CRm(0b0000), Op2(0b010),
	  TPIDR_EL0, 0x1de7ec7edbadc0deULL },
	/* CONTEXTIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1101), CRm(0b0000), Op2(0b001),
	  CONTEXTIDR_EL1, 0 },
	/* PAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0111), CRm(0b0100), Op2(0b000),
	  PAR_EL1, 0x1de7ec7edbadc0deULL },
	/* MPIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0000), CRm(0b0000), Op2(0b101),
	  MPIDR_EL1, 0 },
	/* CSSELR_EL1 */
	{ Op0(0b11), Op1(0b010), CRn(0b0000), CRm(0b0000), Op2(0b000),
	  CSSELR_EL1, 0x1de7ec7edbadc0deULL },
	/* ACTLR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b001),
	  ACTLR_EL1, 0 },
	/* CPACR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b010),
	  CPACR_EL1, 0x1de7ec7edbadc0deULL },
	/* TCR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b010),
	  TCR_EL1, 0 },
	/* AFSR0_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0001), Op2(0b000),
	  AFSR0_EL1, 0x1de7ec7edbadc0deULL },
	/* AFSR1_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0001), Op2(0b001),
	  AFSR1_EL1, 0x1de7ec7edbadc0deULL },
	/* MAIR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1010), CRm(0b0010), Op2(0b000),
	  MAIR_EL1, 0x1de7ec7edbadc0deULL },
	/* AMAIR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1010), CRm(0b0011), Op2(0b000),
	  AMAIR_EL1, 0x1de7ec7edbadc0deULL },
	/* CNTKCTL_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1110), CRm(0b0001), Op2(0b000),
	  CNTKCTL_EL1, 0 },
	{ SYS_DESC(SYS_MDSCR_EL1), MDSCR_EL1, 0 },
	{ SYS_DESC(SYS_MDCCINT_EL1), MDCCINT_EL1, 0 },
	{ SYS_DESC(SYS_DISR_EL1), DISR_EL1, 0 },
	/* DACR32_EL2 */
	{ Op0(0b11), Op1(0b100), CRn(0b0011), CRm(0b0000), Op2(0b000),
	  DACR32_EL2, 0x1de7ec7edbadc0deULL },
	/* IFSR32_EL2 */
	{ Op0(0b11), Op1(0b100), CRn(0b0101), CRm(0b0000), Op2(0b001),
	  IFSR32_EL2, 0x1de7ec7edbadc0deULL },
	/* FPEXC32_EL2 */
	{ Op0(0b11), Op1(0b100), CRn(0b0101), CRm(0b0011), Op2(0b000),
	  FPEXC32_EL2, 0x70 }
};


void el2_shared_data_init(void)
{
	struct el2_shared_data *shared_data;

	shared_data = (void *)kvm_ksym_ref(shared_data_start);
	memset(shared_data, 0, sizeof(struct shared_data));
	printk("[EL2] cleared %lx byte data size %lx\n",
		sizeof(struct shared_data), PAGE_SIZE * PAGE_SIZE);
}

#define CORE_PUD_BASE PAGE_SIZE
#define CORE_PMD_BASE (CORE_PUD_BASE + (PAGE_SIZE * 16))
#define CORE_PTE_BASE SZ_2M
#define CORE_PGD_START	(10 * PAGE_SIZE * PAGE_SIZE) 
void init_el2_data_page(void)
{
	int i = 0, index = 0;
	struct el2_data *el2_data;
	struct memblock_region *r;
	u64 pool_start, vmid64, vttbr;
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	WARN_ON(sizeof(struct el2_data) >= CORE_DATA_SIZE);

	printk("[EL2] stage2: el2_data struct size %lx reserved core data size %lx\n",
		sizeof(struct el2_data), CORE_DATA_SIZE);


	memset((void *)kvm_ksym_ref(stage2_pgs_start), 0, STAGE2_PAGES_SIZE);
	__flush_dcache_area((void *)kvm_ksym_ref(stage2_pgs_start), STAGE2_PAGES_SIZE);

	el2_data = (void *)kvm_ksym_ref(el2_data_start);
	el2_data->installed = false;

	/* We copied memblock_regions to the EL2 data structure*/
	for_each_memblock(memory, r) {
		el2_data->regions[i] = *r;
		if (!(r->flags & MEMBLOCK_NOMAP)) {
			el2_data->s2_memblock_info[i].index = index;
			index += (r->size >> PAGE_SHIFT);
		} else
			el2_data->s2_memblock_info[i].index = S2_PFN_SIZE;
		el2_data->phys_mem_size += el2_data->regions[i].size; 
		i++;
	}
	el2_data->regions_cnt = i;
	el2_data->phys_mem_start = el2_data->regions[0].base;

	smp_wmb();

	mach_phys_mem_start = el2_data->phys_mem_start;
	mach_phys_mem_size = el2_data->phys_mem_size;

	printk("EL2 system phys mem start %llx end %llx\n",
		el2_data->phys_mem_start, el2_data->phys_mem_size);

	el2_data->used_pages = 0;
	el2_data->used_tmp_pages = 0;
	el2_data->page_pool_start = (u64)__pa(stage2_pgs_start);

	el2_data->s2pages_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->abs_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->el2_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->console_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->smmu_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->spt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	memset(&el2_data->arch, 0, sizeof(struct s2_cpu_arch));

	memset(el2_data->s2_pages, 0, sizeof(struct s2_page) * S2_PFN_SIZE);
	el2_data->ram_start_pfn = el2_data->regions[0].base >> PAGE_SHIFT;

	memset(el2_data->shadow_vcpu_ctxt, 0,
	       sizeof(struct shadow_vcpu_context) * NUM_SHADOW_VCPU_CTXT);
	el2_data->used_shadow_vcpu_ctxt = 0;

	/* This guarantees all locks are initially zero. */
	memset(el2_data->vm_info, 0,
		sizeof(struct el2_vm_info) * EL2_VM_INFO_SIZE);
	el2_data->last_remap_ptr = 0;

	pool_start = el2_data->page_pool_start + STAGE2_CORE_PAGES_SIZE + STAGE2_HOST_POOL_SIZE;
	for (i = 1; i < EL2_VM_INFO_SIZE - 1; i++) {
		el2_data->vm_info[i].page_pool_start =
			pool_start + (STAGE2_VM_POOL_SIZE * (i - 1));
		el2_data->vm_info[i].pgd_pool =
			el2_data->vm_info[i].page_pool_start + PGD_BASE;
		el2_data->vm_info[i].pud_pool =
			el2_data->vm_info[i].page_pool_start + PUD_BASE;
		el2_data->vm_info[i].pmd_pool =
			el2_data->vm_info[i].page_pool_start + PMD_BASE;
		memset(__va(el2_data->vm_info[i].page_pool_start), 0, STAGE2_VM_POOL_SIZE);

		vmid64 = (u64)i;
		vmid64 = vmid64 << VTTBR_VMID_SHIFT;
		vttbr = el2_data->vm_info[i].page_pool_start;
		el2_data->vm_info[i].vttbr = (vttbr | vmid64);

		el2_data->vm_info[i].shadow_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	}

	el2_data->vm_info[HOSTVISOR].page_pool_start =
		el2_data->page_pool_start + STAGE2_CORE_PAGES_SIZE;
	el2_data->vm_info[HOSTVISOR].pgd_pool =
		el2_data->vm_info[HOSTVISOR].page_pool_start + PGD_BASE;
	el2_data->vm_info[HOSTVISOR].pud_pool =
		el2_data->vm_info[HOSTVISOR].page_pool_start + HOST_PUD_BASE;
	el2_data->vm_info[HOSTVISOR].pmd_pool =
		el2_data->vm_info[HOSTVISOR].page_pool_start + HOST_PMD_BASE;

	el2_data->host_vttbr = el2_data->vm_info[HOSTVISOR].page_pool_start;
	el2_data->vm_info[HOSTVISOR].vttbr = el2_data->host_vttbr;
	el2_data->vm_info[HOSTVISOR].shadow_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	/* CORE POOL -> HOSTVISOR POOL -> VM POOL */
	el2_data->vm_info[COREVISOR].page_pool_start =
		el2_data->page_pool_start + CORE_PGD_START;
	el2_data->vm_info[COREVISOR].pgd_pool =
		el2_data->vm_info[COREVISOR].page_pool_start + CORE_PUD_BASE;
	el2_data->vm_info[COREVISOR].pud_pool =
		el2_data->vm_info[COREVISOR].page_pool_start + CORE_PMD_BASE;
	el2_data->vm_info[COREVISOR].pmd_pool =
		el2_data->vm_info[COREVISOR].page_pool_start + CORE_PTE_BASE;

	el2_data->vm_info[COREVISOR].used_pages = 0;
	el2_data->vm_info[COREVISOR].shadow_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	/* FIXME: hardcode this for now */
	el2_data->smmu_page_pool_start = (u64)__pa(smmu_pgs_start);
	el2_data->smmu_pgd_pool = el2_data->smmu_page_pool_start;
	el2_data->smmu_pmd_pool = el2_data->smmu_page_pool_start + SMMU_PMD_BASE;

	for (i = 0; i < SHADOW_SYS_REGS_DESC_SIZE; i++)
		el2_data->s2_sys_reg_descs[i] = host_sys_reg_descs[i];

	el2_data->next_vmid = 1;

	/* We init intermediate data structure here. */
	el2_shared_data_init();

	BUG_ON(num_online_cpus() > HYPSEC_MAX_CPUS);
	for (i = 0; i < num_online_cpus(); i++) {
		el2_data->per_cpu_data[i].vmid = 0;
		el2_data->per_cpu_data[i].vcpu_id = i;
	}

	el2_data->core_start = __pa_symbol(stage2_pgs_start);
	el2_data->core_end = __pa_symbol(el2_data_end);

	init_hacl_hash(el2_data);
	//test_aes(el2_data);

	for (i = 0; i < EL2_SMMU_CFG_SIZE; i++) {
		el2_data->smmu_cfg[i].hw_ttbr = host_alloc_stage2_page(2);
		el2_data->smmu_cfg[i].vmid = V_INVALID;
	}

	el2_memcpy(el2_data->key, key, 16);
	el2_memcpy(el2_data->iv, iv, 16);

	return;
}

void init_hypsec_io(void)
{
	int i = 0, err;
	struct el2_data *el2_data;
	struct el2_arm_smmu_device *smmu;

	el2_data = (void *)kvm_ksym_ref(el2_data_start);

#ifdef CONFIG_SERIAL_8250_CONSOLE
	// for prints on m400
	err = create_hypsec_io_mappings((phys_addr_t)0x1c021000,
					 PAGE_SIZE,
					 &el2_data->uart_8250_base);
	if (err) {
		kvm_err("Cannot map uart 8250\n");
		goto out_err;
	}
#endif

	err = create_hypsec_io_mappings((phys_addr_t)el2_data->pl011_base,
					 PAGE_SIZE,
					 &el2_data->pl011_base);
	if (err) {
		kvm_err("Cannot map pl011\n");
		goto out_err;
	}

	for (i = 0; i < el2_data->el2_smmu_num; i++) {
		smmu = &el2_data->smmus[i];
		err = create_hypsec_io_mappings(smmu->phys_base, smmu->size,
						&smmu->hyp_base);
		if (err) {
			kvm_err("Cannot map smmu %d from %llx\n", i, smmu->phys_base);
			goto out_err;
		}
	}

out_err:
	return;
}

//hypsec_mmu.c
phys_addr_t host_alloc_stage2_page(unsigned int num)
{
	u64 p_addr, start, unaligned, append, used_pages;
	struct el2_data *el2_data;

	if (!num)
		return 0;

	el2_data = kvm_ksym_ref(el2_data_start);
	stage2_spin_lock(&el2_data->abs_lock);

	/* Check if we're out of memory in the reserved area */
	BUG_ON(el2_data->vm_info[COREVISOR].used_pages >= (CORE_PGD_START >> PAGE_SHIFT));

	/* Start allocating memory from the normal page pool */
	start = el2_data->page_pool_start;
	used_pages = el2_data->vm_info[COREVISOR].used_pages;
	p_addr = (u64)start + (PAGE_SIZE * used_pages);

	unaligned = p_addr % (PAGE_SIZE * num);
	/* Append to make p_addr aligned with (PAGE_SIZE * num) */
	if (unaligned) {
		append = num - (unaligned >> PAGE_SHIFT);
		p_addr += append * PAGE_SIZE;
		num += append;
	}

	el2_data->vm_info[COREVISOR].used_pages += num;

	stage2_spin_unlock(&el2_data->abs_lock);
	return (phys_addr_t)p_addr;
}

phys_addr_t host_alloc_pgd(unsigned int num)
{
	u64 p_addr;
	struct el2_data *el2_data;

	el2_data = kvm_ksym_ref(el2_data_start);
	stage2_spin_lock(&el2_data->abs_lock);	
	p_addr = el2_data->vm_info[COREVISOR].page_pool_start;
	stage2_spin_unlock(&el2_data->abs_lock);

	return (phys_addr_t)p_addr;
}

phys_addr_t host_alloc_pud(unsigned int num)
{
	u64 p_addr, start;
	struct el2_data *el2_data;

	el2_data = kvm_ksym_ref(el2_data_start);
	stage2_spin_lock(&el2_data->abs_lock);

	start = el2_data->vm_info[COREVISOR].page_pool_start;
	p_addr = el2_data->vm_info[COREVISOR].pgd_pool;
	smp_wmb();
	el2_data->vm_info[COREVISOR].pgd_pool += PAGE_SIZE;

	stage2_spin_unlock(&el2_data->abs_lock);
	if (p_addr >= (start + CORE_PMD_BASE)) {
		printk("BUG: pud [start %lx paddr %lx pud_pool_end %lx\n",
			(unsigned long)el2_data->vm_info[COREVISOR].page_pool_start,
			(unsigned long)p_addr, (unsigned long)(start + CORE_PMD_BASE)
			);
		BUG();
	}

	return (phys_addr_t)p_addr;
}


phys_addr_t host_alloc_pmd(unsigned int num)
{
	u64 p_addr, start;
	struct el2_data *el2_data;

	el2_data = kvm_ksym_ref(el2_data_start);
	stage2_spin_lock(&el2_data->abs_lock);

	start = el2_data->vm_info[COREVISOR].page_pool_start;
	p_addr = el2_data->vm_info[COREVISOR].pud_pool;
	smp_wmb();
	el2_data->vm_info[COREVISOR].pud_pool += PAGE_SIZE;

	stage2_spin_unlock(&el2_data->abs_lock);
	if (p_addr >= (start + CORE_PTE_BASE)) {
		printk("BUG: pmd [start %lx paddr %lx pmd_pool_end %lx\n",
			(unsigned long)el2_data->vm_info[COREVISOR].page_pool_start,
			(unsigned long)p_addr, (unsigned long)(start + CORE_PTE_BASE)
			);
		BUG();
	}

	return (phys_addr_t)p_addr;
}

phys_addr_t host_alloc_pte(unsigned int num)
{
	u64 p_addr, start;
	struct el2_data *el2_data;

	el2_data = kvm_ksym_ref(el2_data_start);
	stage2_spin_lock(&el2_data->abs_lock);

	start = el2_data->vm_info[COREVISOR].page_pool_start;
	p_addr = el2_data->vm_info[COREVISOR].pmd_pool;
	smp_wmb();
	el2_data->vm_info[COREVISOR].pmd_pool += PAGE_SIZE;

	stage2_spin_unlock(&el2_data->abs_lock);
	if (p_addr >= el2_data->host_vttbr) {
		printk("BUG: pte [start %lx paddr %lx host_vttbr %lx\n",
			(unsigned long)el2_data->vm_info[COREVISOR].page_pool_start,
			(unsigned long)p_addr, (unsigned long)el2_data->host_vttbr
			);
		BUG();
	}	

	return (phys_addr_t)p_addr;
}

struct kvm* hypsec_alloc_vm(u32 vmid)
{
	struct shared_data *shared_data;
	shared_data = kvm_ksym_ref(shared_data_start);
	if (vmid >= EL2_MAX_VMID)
		BUG();
	return &shared_data->kvm_pool[vmid];
}

struct kvm_vcpu* hypsec_alloc_vcpu(u32 vmid, int vcpu_id)
{
	struct shared_data *shared_data;
	int index;
	shared_data = kvm_ksym_ref(shared_data_start);
	if (vmid >= EL2_MAX_VMID || vcpu_id >= HYPSEC_MAX_VCPUS)
		BUG();
	index = (vmid * HYPSEC_MAX_VCPUS) + vcpu_id;
	return &shared_data->vcpu_pool[index];
}

int el2_set_boot_info(u32 vmid, unsigned long load_addr,
			unsigned long size, int type)
{
	return kvm_call_core(HVC_SET_BOOT_INFO, vmid, load_addr, size, type);
}

int el2_remap_vm_image(u32 vmid, unsigned long pfn, int id)
{
	return kvm_call_core(HVC_REMAP_VM_IMAGE, vmid, pfn, id);
}

int el2_verify_and_load_images(u32 vmid)
{
	return kvm_call_core(HVC_VERIFY_VM_IMAGES, vmid);
}

void el2_boot_from_inc_exe(u32 vmid)
{
	kvm_call_core(HVC_BOOT_FROM_SAVED_VM, vmid);
}

void save_encrypted_vcpu(struct kvm_vcpu *vcpu)
{
	kvm_call_core((void *)HVC_SAVE_CRYPT_VCPU,
			vcpu->kvm->arch.vmid, vcpu->vcpu_id);
}

void load_encrypted_vcpu(u32 vmid, u32 vcpu_id)
{
	kvm_call_core((void *)HVC_LOAD_CRYPT_VCPU, vmid, vcpu_id);
}

void clear_vm_stage2_range(u32 vmid, phys_addr_t start, u64 size)
{
	kvm_call_core(HVC_CLEAR_VM_S2_RANGE, vmid, start, size);
}

void el2_encrypt_buf(u32 vmid, u64 buf, u64 out_buf)
{
	kvm_call_core(HVC_ENCRYPT_BUF, vmid, buf, out_buf);
}

void el2_decrypt_buf(u32 vmid, void *buf, uint32_t len)
{
	kvm_call_core(HVC_DECRYPT_BUF, vmid, buf, len);
}

int hypsec_register_kvm(void)
{
	return kvm_call_core(HVC_REGISTER_KVM);
}

int hypsec_register_vcpu(u32 vmid, int vcpu_id)
{
	return kvm_call_core((void *)HVC_REGISTER_VCPU, vmid, vcpu_id);
}

/* DMA Protection */
void el2_smmu_free_pgd(u32 cbndx, u32 num)
{
	kvm_call_core(HVC_SMMU_FREE_PGD, cbndx, num);
}

void el2_smmu_alloc_pgd(u32 cbndx, u32 vmid, u32 num)
{
	kvm_call_core(HVC_SMMU_ALLOC_PGD, cbndx, vmid, num);
}

void el2_arm_lpae_map(u64 iova, phys_addr_t paddr, u64 prot, u32 cbndx, u32 num)
{
	kvm_call_core(HVC_SMMU_LPAE_MAP, iova, paddr, prot, cbndx, num);
}

phys_addr_t el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 num)
{
	return kvm_call_core(HVC_SMMU_LPAE_IOVA_TO_PHYS, iova, cbndx, num);
}

void el2_smmu_clear(u64 iova, u32 cbndx, u32 num)
{
	kvm_call_core(HVC_SMMU_CLEAR, iova, cbndx, num);
}

void hypsec_phys_addr_ioremap(u32 vmid, u64 gpa, u64 pa, u64 size)
{
	kvm_call_core(HVC_PHYS_ADDR_IOREMAP, vmid, gpa, pa, size);
}
