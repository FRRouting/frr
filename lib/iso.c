/*
 * ISO Network functions - iso_net.c
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2023 Orange http://www.orange.com
 *
 * This file is part of Free Range Routing (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "compiler.h"

#include <string.h>
#include <ctype.h>
#include <time.h>

#include "printfrr.h"
#include "iso.h"

/**
 * Print ISO System ID as 0000.0000.0000
 *
 * @param	Print buffer
 * @param	Print argument
 * @param	Pointer to the System ID to be printed
 *
 * @return	Number of printed characters
 */
printfrr_ext_autoreg_p("SY", printfrr_iso_sysid);
static ssize_t printfrr_iso_sysid(struct fbuf *buf, struct printfrr_eargs *ea,
				  const void *vptr)
{
	const uint8_t *id = vptr;

	if (!id)
		return bputs(buf, "(null)");

	return bprintfrr(buf, "%02x%02x.%02x%02x.%02x%02x",
			 id[0], id[1], id[2], id[3], id[4], id[5]);
}

/**
 * Print ISO Pseudo Node system ID as 0000.0000.0000.00
 *
 * @param	Print buffer
 * @param	Print argument
 * @param	Pointer to the System ID to be printed
 *
 * @return	Number of printed characters
 */
printfrr_ext_autoreg_p("PN", printfrr_iso_pseudo);
static ssize_t printfrr_iso_pseudo(struct fbuf *buf, struct printfrr_eargs *ea,
				   const void *vptr)
{
	const uint8_t *id = vptr;

	if (!id)
		return bputs(buf, "(null)");

	return bprintfrr(buf, "%02x%02x.%02x%02x.%02x%02x.%02x",
			 id[0], id[1], id[2], id[3], id[4], id[5], id[6]);
}

/**
 * Print ISO LSP Fragment System ID as 0000.0000.0000.00-00
 *
 * @param	Print buffer
 * @param	Print argument
 * @param	Pointer to the System ID to be printed
 *
 * @return	Number of printed characters
 */
printfrr_ext_autoreg_p("LS", printfrr_iso_frag_id);
static ssize_t printfrr_iso_frag_id(struct fbuf *buf, struct printfrr_eargs *ea,
				    const void *vptr)
{
	const uint8_t *id = vptr;

	if (!id)
		return bputs(buf, "(null)");

	return bprintfrr(buf, "%02x%02x.%02x%02x.%02x%02x.%02x-%02x",
			 id[0], id[1], id[2], id[3], id[4], id[5], id[6],
			 id[7]);
}

/**
 * Print ISO Network address as 00.0000.0000.0000 ... with the System ID
 * as 0000.0000.0000.00 when long 'l' option is added to '%pIS'
 *
 * @param	Print buffer
 * @param	Print argument
 * @param	Pointer to the ISO Network address
 *
 * @return	Number of printed characters
 */
printfrr_ext_autoreg_p("IS", printfrr_iso_addr);
static ssize_t printfrr_iso_addr(struct fbuf *buf, struct printfrr_eargs *ea,
				 const void *vptr)
{
	const struct iso_address *ia = vptr;
	uint8_t len = 0;
	int i = 0;
	ssize_t ret = 0;

	if (ea->fmt[0] == 'l') {
		len = 7; /* ISO SYSTEM ID + 1 */
		ea->fmt++;
	}

	if (!ia)
		return bputs(buf, "(null)");

	len += ia->addr_len;
	while (i < len) {
		/* No dot for odd index and at the end of address */
		if ((i & 1) || (i == (len - 1)))
			ret += bprintfrr(buf, "%02x", ia->area_addr[i]);
		else
			ret += bprintfrr(buf, "%02x.", ia->area_addr[i]);
		i++;
	}

	return ret;
}

