/*
 * PIM address generalizations
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
