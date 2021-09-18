struct kvm* __hyp_text hypsec_vmid_to_kvm(u32 vmid);
struct kvm_vcpu* __hyp_text hypsec_vcpu_id_to_vcpu(u32 vmid, int vcpu_id);
struct shadow_vcpu_context* __hyp_text hypsec_vcpu_id_to_shadow_ctxt(u32 vmid, int vcpu_id);

void __restore_shadow_kvm_regs(struct kvm_vcpu *vcpu,
			       struct shadow_vcpu_context *shadow_ctxt) {};

void update_exception_gp_regs(struct shadow_vcpu_context *shadow_ctxt);
extern int sec_el2_handle_sys_reg(u32 esr);
void __save_shadow_kvm_regs(struct kvm_vcpu *vcpu,
			    struct shadow_vcpu_context *shadow_ctxt, u64 ec) {};

void __hyp_text hypsec_set_vcpu_state(u32 vmid, int vcpu_id, int state);

void el2_memset(void *b, int c, int len);
void el2_memcpy(void *dest, void *src, size_t len);

void reset_fp_regs(u32 vmid, int vcpu_id);
