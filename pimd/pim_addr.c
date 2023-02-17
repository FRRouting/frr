// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM address generalizations
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 */

#include <zebra.h>

#include "pim_addr.h"
#include "printfrr.h"
#include "prefix.h"


printfrr_ext_autoreg_p("PA", printfrr_pimaddr);
static ssize_t printfrr_pimaddr(struct fbuf *buf, struct printfrr_eargs *ea,
				const void *vptr)
{
	const pim_addr *addr = vptr;
	bool use_star = false;

	if (ea->fmt[0] == 's') {
		use_star = true;
		ea->fmt++;
	}

	if (!addr)
		return bputs(buf, "(null)");

	if (use_star && pim_addr_is_any(*addr))
		return bputch(buf, '*');

#if PIM_IPV == 4
	return bprintfrr(buf, "%pI4", addr);
#else
	return bprintfrr(buf, "%pI6", addr);
#endif
}

printfrr_ext_autoreg_p("SG", printfrr_sgaddr);
static ssize_t printfrr_sgaddr(struct fbuf *buf, struct printfrr_eargs *ea,
			       const void *vptr)
{
	const pim_sgaddr *sga = vptr;

	if (!sga)
		return bputs(buf, "(null)");

	return bprintfrr(buf, "(%pPAs,%pPAs)", &sga->src, &sga->grp);
}
