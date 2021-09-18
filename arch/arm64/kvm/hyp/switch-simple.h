static bool inline hypsec_supports_fpsimd(void)
{
	return true;
}
/*
static u64 __hyp_text get_pmuserenr_el0(void)
{
	return read_sysreg(pmuserenr_el0);
}
*/
static void __hyp_text set_pmuserenr_el0(u64 val)
{
	write_sysreg(val, pmuserenr_el0);
}
/*
static u64 __hyp_text get_pmselr_el0(void)
{
	return read_sysreg(pmselr_el0);
}
*/
static void __hyp_text set_pmselr_el0(u64 val)
{
	write_sysreg(val, pmselr_el0);
}
/*
static u64 __hyp_text get_hstr_el2(void)
{
	return read_sysreg(hstr_el2);
}

static void __hyp_text set_hstr_el2(u64 val)
{
	write_sysreg(val, hstr_el2);
}

static u64 __hyp_text get_cptr_el2(void)
{
	return read_sysreg(cptr_el2);
}
*/
static void __hyp_text set_cptr_el2(u64 val)
{
	write_sysreg(val, cptr_el2);
}
/*
static u64 __hyp_text get_mdcr_el2(void)
{
	return read_sysreg(mdcr_el2);
}
*/
static void __hyp_text set_mdcr_el2(u64 val)
{
	write_sysreg(val, mdcr_el2);
}
/*
static u64 __hyp_text get_hcr_el2(void)
{
	return read_sysreg(hcr_el2);
}
*/
static void __hyp_text set_hcr_el2(u64 val)
{
	write_sysreg(val, hcr_el2);
}

static u64 __hyp_text get_esr_el2(void)
{
	return read_sysreg(esr_el2);
}

/*
static void __hyp_text set_esr_el2(u64 val)
{
	write_sysreg(val, esr_el2);
}

static u64 __hyp_text get_vttbr_el2(void)
{
	return read_sysreg(vttbr_el2);
}
*/
static void __hyp_text set_vttbr_el2(u64 val)
{
	write_sysreg(val, vttbr_el2);
}
/*
static u64 __hyp_text get_tpidr_el2(void)
{
	return read_sysreg(tpidr_el2);
}
*/
static void __hyp_text set_tpidr_el2(u64 val)
{
	write_sysreg(val, tpidr_el2);
}

static u64 __hyp_text get_far_el2(void)
{
	return read_sysreg(far_el2);
}
/*
static void __hyp_text set_far_el2(u64 val)
{
	write_sysreg(val, far_el2);
}
*/
static u64 __hyp_text get_hpfar_el2(void)
{
	return read_sysreg(hpfar_el2);
}
/*
static void __hyp_text set_hpfar_el2(u64 val)
{
	write_sysreg(val, hpfar_el2);
}
*/
