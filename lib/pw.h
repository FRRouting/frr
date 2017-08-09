/* Pseudowire definitions
 * Copyright (C) 2016 Volta Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#ifndef _FRR_PW_H
#define _FRR_PW_H

/* L2VPN name length. */
#define L2VPN_NAME_LEN		32

/* Pseudowire type - LDP and BGP use the same values. */
#define PW_TYPE_ETHERNET_TAGGED	0x0004	/* RFC 4446 */
#define PW_TYPE_ETHERNET	0x0005	/* RFC 4446 */
#define PW_TYPE_WILDCARD	0x7FFF	/* RFC 4863, RFC 6668 */

/* Pseudowire flags. */
#define F_PSEUDOWIRE_CWORD	0x01

/* Pseudowire status. */
#define PW_STATUS_DOWN		0
#define PW_STATUS_UP		1

/*
 * Protocol-specific information about the pseudowire.
 */
union pw_protocol_fields {
	struct {
		struct in_addr lsr_id;
		uint32_t pwid;
		char vpn_name[L2VPN_NAME_LEN];
	} ldp;
	struct {
		/* TODO */
	} bgp;
};

#endif /* _FRR_PW_H */
