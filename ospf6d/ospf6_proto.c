// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
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
	const char *dn, *p, *mc, *la, *nu;

	dn = (CHECK_FLAG(prefix_options, OSPF6_PREFIX_OPTION_DN) ? "DN" : "--");
	p = (CHECK_FLAG(prefix_options, OSPF6_PREFIX_OPTION_P) ? "P" : "--");
	mc = (CHECK_FLAG(prefix_options, OSPF6_PREFIX_OPTION_MC) ? "MC" : "--");
	la = (CHECK_FLAG(prefix_options, OSPF6_PREFIX_OPTION_LA) ? "LA" : "--");
	nu = (CHECK_FLAG(prefix_options, OSPF6_PREFIX_OPTION_NU) ? "NU" : "--");
	snprintf(buf, size, "%s|%s|%s|%s|%s", dn, p, mc, la, nu);
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
	const char *dc, *r, *n, *mc, *e, *v6, *af, *at, *l;
	dc = (OSPF6_OPT_ISSET(options, OSPF6_OPT_DC) ? "DC" : "--");
	r = (OSPF6_OPT_ISSET(options, OSPF6_OPT_R) ? "R" : "-");
	n = (OSPF6_OPT_ISSET(options, OSPF6_OPT_N) ? "N" : "-");
	mc = (OSPF6_OPT_ISSET(options, OSPF6_OPT_MC) ? "MC" : "--");
	e = (OSPF6_OPT_ISSET(options, OSPF6_OPT_E) ? "E" : "-");
	v6 = (OSPF6_OPT_ISSET(options, OSPF6_OPT_V6) ? "V6" : "--");
	af = (OSPF6_OPT_ISSET_EXT(options, OSPF6_OPT_AF) ? "AF" : "--");
	at = (OSPF6_OPT_ISSET_EXT(options, OSPF6_OPT_AT) ? "AT" : "--");
	l = (OSPF6_OPT_ISSET_EXT(options, OSPF6_OPT_L) ? "L" : "-");
	snprintf(buf, size, "%s|%s|%s|-|-|%s|%s|%s|%s|%s|%s", at, l, af, dc, r,
		 n, mc, e, v6);
}
