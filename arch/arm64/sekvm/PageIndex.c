#include "hypsec.h"

/*
 * PageIndex
 */

/*
*/
u64 __hyp_text get_s2_page_index(u64 addr)
{
	u64 ret, start, end, phys_mem_size, page_index;

	start = get_phys_mem_start();
	phys_mem_size = get_phys_mem_size();
	end = start + phys_mem_size;

	if (addr >= start && addr < end)
	{
		page_index = (addr - start) >> PAGE_SHIFT;
		ret = page_index;
	}
	else
	{
		ret = INVALID64;
	}

	return ret;
}

u64 __hyp_text __get_s2_page_index(u64 addr)
{
	u64 ret, p_index, base;
	u32 r_index;

	r_index = mem_region_search(addr);
	ret = INVALID64;
	if (r_index != INVALID_MEM)
	{
		p_index = get_mem_region_index(r_index);
		if (p_index != INVALID64)
		{
			base = get_mem_region_base(r_index);
			ret = p_index + (addr - base) / PAGE_SIZE;
		}
	}
	return check64(ret);
}
