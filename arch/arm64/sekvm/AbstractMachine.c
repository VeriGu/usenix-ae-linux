#include "hypsec.h"
#include "hacl-20/Hacl_Ed25519.h"
#include "hacl-20/Hacl_AES.h"

void __hyp_text v_panic(void)
{
	//__hyp_panic();
	u32 vmid = get_cur_vmid();
	u32 vcpuid = get_cur_vcpu_id();
	if (vmid) {
		print_string("\rvm\n");
		printhex_ul(get_shadow_ctxt(vmid, vcpuid, V_PC));
	} else {
		print_string("\rhost\n");
		printhex_ul(read_sysreg(elr_el2));
	}
	printhex_ul(ESR_ELx_EC(read_sysreg(esr_el2)));
}

void __hyp_text clear_phys_mem(u64 pfn)
{
    el2_memset((void *)kern_hyp_va(pfn << PAGE_SHIFT), 0, PAGE_SIZE);
}

u64 __hyp_text get_exception_vector(u64 pstate)
{
	return 0;
}

uint8_t* __hyp_text get_vm_public_key(u32 vmid)
{
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].public_key;
}

void __hyp_text set_vm_public_key(u32 vmid)
{
    unsigned char *public_key_hex = "2ef2440a2b5766436353d07705b602bfab55526831460acb94798241f2104f3a";
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_hex2bin(el2_data->vm_info[vmid].public_key, public_key_hex, 32);
}

uint8_t* __hyp_text get_vm_load_signature(u32 vmid, u32 load_idx)
{
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].signature;
}

void __hyp_text set_vm_load_signature(u32 vmid, u32 load_idx)
{
    unsigned char *signature_hex = "35e9848eb618e7150566716662b2f7d8944f0a4e8582ddeb2b209d2bae6b63d5f51ebf1dc54742227e45f7bbb9d4ba1d1f83b52b87a4ce99180aa9a548e7dd05";
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_hex2bin(el2_data->vm_info[vmid].load_info[load_idx].signature,
		signature_hex, 64);
}

//make sure we only use get_int_ctxt to access general purposes regs
void __hyp_text clear_shadow_gp_regs(u32 vmid, u32 vcpuid)
{
	struct el2_data *el2_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_memset(&el2_data->shadow_vcpu_ctxt[offset].gp_regs, 0, sizeof(struct kvm_regs));
}

void __hyp_text int_to_shadow_fp_regs(u32 vmid, u32 vcpuid)
{

}

void __hyp_text clear_phys_page(unsigned long pfn)
{
	u64 addr = (u64)__el2_va(pfn << PAGE_SHIFT);
	el2_memset((void *)addr, 0, PAGE_SIZE);
}

u32 __hyp_text verify_image(u32 vmid, u32 load_idx, u64 addr)
{
    uint8_t* signature;
    uint8_t* public_key;
    int result = 0;
    u64 size;

    size = get_vm_load_size(vmid, load_idx);
    public_key = get_vm_public_key(vmid);
    signature = get_vm_load_signature(vmid, load_idx);
    print_string("\rverifying image:\n");
    //printhex_ul(size);
    result = Hacl_Ed25519_verify(public_key, size, (uint8_t *)addr, signature);
    //result = Hacl_Ed25519_verify(key, size, (char *)addr, signature1);
    print_string("\r[result]\n");
    printhex_ul(result);
    return 1;
}

void dump_output(char *str, uint8_t *out, int len)
{
	int i;
	unsigned s = 0;
	printk("%s\n", str);
	for (i = 0; i < len; i++) {
		s = out[i];
		printk("%x", s);
	}
	printk("\n");
}

void __hyp_text dump_output_el2(uint8_t *out, int len)
{
	int i;
	unsigned long s = 0;
	for (i = 0; i < len; i++) {
		s = out[i];
		printhex_ul(s);
	}
}

void __hyp_text test_aes(struct el2_data *el2_data)
{
	uint8_t sbox[256];
	uint8_t input[32] = { 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
	uint8_t out[32], out1[32];

	el2_memset(out, 0, sizeof(uint8_t) * 32);
	el2_memset(out1, 0, sizeof(uint8_t) * 32);
	//dump_output_el2(input, 16);
	dump_output("plain", input, 32);
	AES_encrypt_buffer(out, input, el2_data->key, 32);
	//dump_output_el2(out, 16);
	dump_output("crypt", out, 32);

	el2_memset(sbox, 0, sizeof(uint8_t) * 32);
	AES_decrypt_buffer(out1, out, el2_data->key, 32);
	//dump_output_el2(out1, 16);
	dump_output("decrypt", out1, 32);
}

void __hyp_text encrypt_buf(u32 vmid, u64 in_buf, u64 out_buf, uint32_t len)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	AES_encrypt_buffer((uint8_t*)out_buf, (uint8_t*)in_buf, el2_data->key, len); 
}

void __hyp_text decrypt_buf(u32 vmid, u64 in_buf, u64 out_buf, uint32_t len)
{
        struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	AES_decrypt_buffer((uint8_t*)out_buf, (uint8_t*)in_buf, el2_data->key, len);
}

#if 0
void    int_to_shadow_decrypt(u32 vmid, u32 vcpuid);
void    shadow_to_int_encrypt(u32 vmid, u32 vcpuid);
#endif

void __hyp_text set_per_cpu_host_regs(u64 hr)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int pcpuid = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	el2_data->per_cpu_data[pcpuid].host_regs = (struct s2_host_regs *)hr;
};

void __hyp_text set_host_regs(int nr, u64 value)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int pcpuid = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	el2_data->per_cpu_data[pcpuid].host_regs->regs[nr] = value;
};

u64 __hyp_text get_host_regs(int nr)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int pcpuid = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	return el2_data->per_cpu_data[pcpuid].host_regs->regs[nr];
};

//MMIOOps
u32 __hyp_text get_smmu_cfg_vmid(u32 cbndx, u32 num)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u32 index;
	index = SMMU_NUM_CTXT_BANKS * num + cbndx;
	return el2_data->smmu_cfg[index].vmid;
}

void __hyp_text set_smmu_cfg_vmid(u32 cbndx, u32 num, u32 vmid)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u32 index;
	index = SMMU_NUM_CTXT_BANKS * num + cbndx;
	el2_data->smmu_cfg[index].vmid = vmid;
}

u64 __hyp_text get_smmu_cfg_hw_ttbr(u32 cbndx, u32 num)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u32 index;
	index = SMMU_NUM_CTXT_BANKS * num + cbndx;
	return el2_data->smmu_cfg[index].hw_ttbr;
}

void __hyp_text set_smmu_cfg_hw_ttbr(u32 cbndx, u32 num, u64 hw_ttbr)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u32 index;
	index = SMMU_NUM_CTXT_BANKS * num + cbndx;
	el2_data->smmu_cfg[index].hw_ttbr = hw_ttbr;
}

//MMIOAux
u32 __hyp_text get_smmu_num(void)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->el2_smmu_num;
}	

u64 __hyp_text get_smmu_size(u32 num)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->smmus[num].size;
}

u32 __hyp_text get_smmu_num_context_banks(u32 num)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->smmus[num].num_context_banks;
}

u32 __hyp_text get_smmu_pgshift(u32 num)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->smmus[num].pgshift;
}

void __hyp_text smmu_pt_clear(u32 cbndx, u32 num) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u32 index;
	u64 va;
	index = SMMU_NUM_CTXT_BANKS * num + cbndx;
	va = (u64)__el2_va(el2_data->smmu_cfg[index].hw_ttbr); 
	el2_memset((void *)va, 0, PAGE_SIZE * 2);
};

void __hyp_text reset_fp_regs(u32 vmid, int vcpu_id)
{
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	struct kvm_vcpu *vcpu = vcpu;
	struct kvm_regs *kvm_regs;

	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	kvm_regs = &vcpu->arch.ctxt.gp_regs;
	el2_memcpy(&shadow_ctxt->gp_regs.fp_regs, &kvm_regs->fp_regs,
					sizeof(struct user_fpsimd_state));
}

//Management
static void __hyp_text get_crypt_buf(__u64 *buf,
		struct kvm_regs *kvm_regs)
{
	buf[0] = kvm_regs->regs.pc;
	buf[1] = kvm_regs->sp_el1;
	buf[2] = kvm_regs->elr_el1;
	buf[3] = kvm_regs->spsr[0];
	buf[4] = kvm_regs->spsr[1];
	buf[5] = kvm_regs->spsr[2];
	buf[6] = kvm_regs->spsr[3];
	buf[7] = kvm_regs->spsr[4];
}

static void __hyp_text put_crypt_buf(__u64 *buf,
		struct kvm_regs *kvm_regs)
{
	kvm_regs->regs.pc = buf[0];
	kvm_regs->sp_el1  = buf[1];
	kvm_regs->elr_el1 = buf[2];
	kvm_regs->spsr[0] = buf[3];
	kvm_regs->spsr[1] = buf[4];
	kvm_regs->spsr[2] = buf[5];
	kvm_regs->spsr[3] = buf[6];
	kvm_regs->spsr[4] = buf[7];
}

static void __hyp_text encrypt_kvm_regs(u32 vmid,
		struct kvm_regs *kvm_regs)
{
	struct user_pt_regs *regs = &kvm_regs->regs;
	__u64 buf[8];
	__u64 out_buf[8];
	struct user_fpsimd_state fpsimd;
	__u64 out_gpr[32];

	//old_encrypt_buf(vmid, regs, sizeof(__u64) * 32);
	encrypt_buf(vmid, (u64)regs, (u64)out_gpr, sizeof(__u64) * 32);
	el2_memcpy(regs->regs, out_gpr, sizeof(__u64) * 32);

	get_crypt_buf(buf, kvm_regs);
	//old_encrypt_buf(vmid, buf, sizeof(__u64) * 8);
	encrypt_buf(vmid, (u64)buf, (u64)out_buf, sizeof(__u64) * 8);
	//put_crypt_buf(buf, kvm_regs);
	put_crypt_buf(out_buf, kvm_regs);

	encrypt_buf(vmid, (u64)&kvm_regs->fp_regs, (u64)&fpsimd, sizeof(struct user_fpsimd_state));
	el2_memcpy(&kvm_regs->fp_regs, &fpsimd, sizeof(struct user_fpsimd_state));
	//old_encrypt_buf(vmid, &kvm_regs->fp_regs, sizeof(struct user_fpsimd_state));
}

static void __hyp_text decrypt_kvm_regs(u32 vmid, struct kvm_regs *kvm_regs)
{
	struct user_pt_regs *regs = &kvm_regs->regs;
	__u64 buf[8];
	__u64 out_buf[8];
	struct user_fpsimd_state fpsimd;
	__u64 out_gpr[32];

	// sizeof(regs[31] + sp + pc), all in __u64
	decrypt_buf(vmid, (u64)regs, (u64)out_gpr, sizeof(__u64) * 32);
	el2_memcpy(regs->regs, out_gpr, sizeof(__u64) * 32);
	//old_decrypt_buf(vmid, regs, sizeof(__u64) * 32);

	get_crypt_buf(buf, kvm_regs);
	decrypt_buf(vmid, (u64)buf, (u64)out_buf, sizeof(__u64) * 8);
	//old_decrypt_buf(vmid, buf, sizeof(__u64) * 8);
	put_crypt_buf(out_buf, kvm_regs);

	decrypt_buf(vmid, (u64)&kvm_regs->fp_regs, (u64)&fpsimd, sizeof(struct user_fpsimd_state));
	el2_memcpy(&kvm_regs->fp_regs, &fpsimd, sizeof(struct user_fpsimd_state));
	//old_decrypt_buf(vmid, &kvm_regs->fp_regs, sizeof(struct user_fpsimd_state));
}

#define SHADOW_SYS_REGS_LEN 	8 * (SHADOW_SYS_REGS_SIZE)
void __hyp_text encrypt_gp_regs(u32 vmid, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	struct kvm_regs gp_local;
	int i;
	uint64_t *p;
	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	el2_memcpy(&gp_local, &shadow_ctxt->gp_regs, sizeof(struct kvm_regs));
	encrypt_kvm_regs(vmid, &gp_local);
	//gp_local.regs.pstate = shadow_ctxt->regs[V_PSTATE];
	//gp_local.regs.pstate = shadow_ctxt->gp_regs.regs.pstate;
	el2_memcpy(&vcpu->arch.ctxt.gp_regs, &gp_local, sizeof(struct kvm_regs));
	for (i = 0; i < 31; i++)
		printhex_ul(shadow_ctxt->gp_regs.regs.regs[i]);
	printhex_ul(shadow_ctxt->gp_regs.regs.sp);
	printhex_ul(shadow_ctxt->gp_regs.regs.pc);
	printhex_ul(shadow_ctxt->gp_regs.regs.pstate);
	printhex_ul(shadow_ctxt->gp_regs.sp_el1);
	printhex_ul(shadow_ctxt->gp_regs.elr_el1);
	for (i = 0; i < 5; i++)
		printhex_ul(shadow_ctxt->gp_regs.spsr[i]);
	p = (uint64_t *)&vcpu->arch.ctxt.gp_regs.fp_regs;
	for (i = 0; i < 66; i++)
		printhex_ul(*p++);
}

void __hyp_text decrypt_gp_regs(u32 vmid, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	struct kvm_regs gp_local;
	int i;
	uint64_t *p;
	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	el2_memcpy(&gp_local, &vcpu->arch.ctxt.gp_regs, sizeof(struct kvm_regs));
	decrypt_kvm_regs(vmid, &gp_local);
	//gp_local.regs.pstate = vcpu->arch.ctxt.gp_regs.regs.pstate;
	el2_memcpy(&shadow_ctxt->gp_regs, &gp_local, sizeof(struct kvm_regs));
	el2_memset(&vcpu->arch.ctxt.gp_regs, 0, sizeof(struct kvm_regs));
	for (i = 0; i < 31; i++)
		printhex_ul(shadow_ctxt->gp_regs.regs.regs[i]);
	printhex_ul(shadow_ctxt->gp_regs.regs.sp);
	printhex_ul(shadow_ctxt->gp_regs.regs.pc);
	printhex_ul(shadow_ctxt->gp_regs.regs.pstate);
	printhex_ul(shadow_ctxt->gp_regs.sp_el1);
	printhex_ul(shadow_ctxt->gp_regs.elr_el1);
	for (i = 0; i < 5; i++)
		printhex_ul(shadow_ctxt->gp_regs.spsr[i]);

	p = (uint64_t *)&shadow_ctxt->gp_regs.fp_regs;
	for (i = 0; i < 66; i++)
		printhex_ul(*p++);
}

void __hyp_text encrypt_sys_regs(u32 vmid, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	int i;
	u64 sr_local[SHADOW_SYS_REGS_SIZE + 1];
	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	encrypt_buf(vmid, (u64)&shadow_ctxt->sys_regs[1], (u64)sr_local, SHADOW_SYS_REGS_LEN);
	el2_memcpy(&vcpu->arch.ctxt.sys_regs[1], sr_local, SHADOW_SYS_REGS_LEN);
	//el2_memcpy(&vcpu->arch.ctxt.sys_regs, &shadow_ctxt->sys_regs, SHADOW_SYS_REGS_LEN);
	for (i = 0; i < SHADOW_SYS_REGS_SIZE + 1; i++) {
		//printhex_ul(vcpu->arch.ctxt.sys_regs[i]);
		//printhex_ul(shadow_ctxt->sys_regs[i]);
	}
}

void __hyp_text decrypt_sys_regs(u32 vmid, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	u64 sr_local[SHADOW_SYS_REGS_SIZE + 1];
	int i;
	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	decrypt_buf(vmid, (u64)&vcpu->arch.ctxt.sys_regs[1], (u64)sr_local, SHADOW_SYS_REGS_LEN);
	el2_memcpy(&shadow_ctxt->sys_regs[1], sr_local, SHADOW_SYS_REGS_LEN);
	//el2_memcpy(&shadow_ctxt->sys_regs, &vcpu->arch.ctxt.sys_regs, SHADOW_SYS_REGS_LEN);
	for (i = 0; i < SHADOW_SYS_REGS_SIZE + 1; i++) {
		//printhex_ul(vcpu->arch.ctxt.sys_regs[i]);
		//printhex_ul(shadow_ctxt->sys_regs[i]);
	}
	el2_memset(&vcpu->arch.ctxt.sys_regs[1], 0, SHADOW_SYS_REGS_LEN);
}
