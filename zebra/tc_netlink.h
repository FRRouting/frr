/*
 * Zebra Traffic Control (TC) interaction with the kernel using netlink.
 *
 * Copyright (C) 2022 Shichu Yang
 *
 * This file is part of FRR.
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_TC_NETLINK_H
#define _ZEBRA_TC_NETLINK_H

#ifdef HAVE_NETLINK

#ifdef __cplusplus
extern "C" {
#endif

/* Represent a prefixed address in flower filter */

struct inet_prefix {
	uint16_t flags;
	uint16_t bytelen;
	uint16_t bitlen;
	uint16_t family;
	uint32_t data[64];
};

enum {
	PREFIXLEN_SPECIFIED = (1 << 0),
	ADDRTYPE_INET = (1 << 1),
	ADDRTYPE_UNSPEC = (1 << 2),
	ADDRTYPE_MULTI = (1 << 3),

	ADDRTYPE_INET_UNSPEC = ADDRTYPE_INET | ADDRTYPE_UNSPEC,
	ADDRTYPE_INET_MULTI = ADDRTYPE_INET | ADDRTYPE_MULTI
};

extern enum netlink_msg_status
netlink_put_tc_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_TC_NETLINK_H */
