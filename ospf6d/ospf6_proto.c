/*
 * Copyright (C) 2003 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"

#include "ospf6_proto.h"

void ospf6_prefix_in6_addr(struct in6_addr *in6, const void *prefix_buf,
			   const struct ospf6_prefix *p)
{
	ptrdiff_t in6_off = (caddr_t)p->addr - (caddr_t)prefix_buf;

	memset(in6, 0, sizeof(struct in6_addr));
	memcpy(in6, (uint8_t *)prefix_buf + in6_off,
	       OSPF6_PREFIX_SPACE(p->prefix_length));
}

void ospf6_prefix_apply_mask(struct ospf6_prefix *op)
{
	uint8_t *pnt, mask;
	int index, offset;

	pnt = (uint8_t *)((caddr_t)op + sizeof(struct ospf6_prefix));
	index = op->prefix_length / 8;
	offset = op->prefix_length % 8;
	mask = 0xff << (8 - offset);

	if (index > 16) {
		zlog_warn("Prefix length too long: %d", op->prefix_length);
		return;
	}

	/* nonzero mask means no check for this byte because if it contains
	 * prefix bits it must be there for us to write */
	if (mask)
		pnt[index++] &= mask;

	while (index < OSPF6_PREFIX_SPACE(op->prefix_length))
		pnt[index++] = 0;
}

void ospf6_prefix_options_printbuf(uint8_t prefix_options, char *buf, int size)
{
	snprintf(buf, size, "xxx");
}

void ospf6_capability_printbuf(char capability, char *buf, int size)
{
	char w, v, e, b;
	w = (capability & OSPF6_ROUTER_BIT_W ? 'W' : '-');
	v = (capability & OSPF6_ROUTER_BIT_V ? 'V' : '-');
	e = (capability & OSPF6_ROUTER_BIT_E ? 'E' : '-');
	b = (capability & OSPF6_ROUTER_BIT_B ? 'B' : '-');
	snprintf(buf, size, "----%c%c%c%c", w, v, e, b);
}

void ospf6_options_printbuf(uint8_t *options, char *buf, int size)
{
	const char *dc, *r, *n, *mc, *e, *v6;
	dc = (OSPF6_OPT_ISSET(options, OSPF6_OPT_DC) ? "DC" : "--");
	r = (OSPF6_OPT_ISSET(options, OSPF6_OPT_R) ? "R" : "-");
	n = (OSPF6_OPT_ISSET(options, OSPF6_OPT_N) ? "N" : "-");
	mc = (OSPF6_OPT_ISSET(options, OSPF6_OPT_MC) ? "MC" : "--");
	e = (OSPF6_OPT_ISSET(options, OSPF6_OPT_E) ? "E" : "-");
	v6 = (OSPF6_OPT_ISSET(options, OSPF6_OPT_V6) ? "V6" : "--");
	snprintf(buf, size, "%s|%s|%s|%s|%s|%s", dc, r, n, mc, e, v6);
}
