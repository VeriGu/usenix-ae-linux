#include "hypsec.h"

/*
 * PageManager
 */

u32 __hyp_text get_pfn_owner(u64 pfn)
{
	u64 index;
	u32 ret;

	index = get_s2_page_index(pfn * PAGE_SIZE);
	if (index != INVALID64)
	{
		ret = get_s2_page_vmid(index);
	}
	else
	{
		ret = INVALID_MEM;
	}
	return check(ret);
}

void __hyp_text set_pfn_owner(u64 pfn, u32 vmid)
{
	u64 index;

	index = get_s2_page_index(pfn * PAGE_SIZE);
	if (index != INVALID64)
	{
		set_s2_page_vmid(index, vmid);
	}
}

u32 __hyp_text get_pfn_count(u64 pfn)
{
	u64 index;
	u32 ret;

	index = get_s2_page_index(pfn * PAGE_SIZE);
	if (index != INVALID64)
	{
		ret = get_s2_page_count(index);
	}
	else
	{
		ret = INVALID_MEM;
	}
	return ret;
}

void __hyp_text set_pfn_count(u64 pfn, u32 count)
{
	u64 index;

	index = get_s2_page_index(pfn * PAGE_SIZE);
	if (index != INVALID64)
	{
		set_s2_page_count(index, count);
	}
}

u64 __hyp_text get_pfn_map(u64 pfn)
{
	u64 index;
	u64 ret;

	index = get_s2_page_index(pfn * PAGE_SIZE);
	if (index != INVALID64)
	{
		ret = get_s2_page_gfn(index);
	}
	else
	{
		ret = INVALID_MEM;
	}
	return ret;
}

void __hyp_text set_pfn_map(u64 pfn, u64 gfn)
{
	u64 index;

	index = get_s2_page_index(pfn * PAGE_SIZE);
	if (index != INVALID64)
	{
		set_s2_page_gfn(index, gfn);
	}
}
