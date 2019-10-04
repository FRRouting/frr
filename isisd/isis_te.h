/*
 * IS-IS Rout(e)ing protocol - isis_te.c
 *
 * This is an implementation of RFC5305, RFC 5307 and RFC 7810
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2014 - 2019 Orange Labs http://www.orange.com
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

#ifndef _ZEBRA_ISIS_MPLS_TE_H
#define _ZEBRA_ISIS_MPLS_TE_H

/*
 * Traffic Engineering information are transport through LSP:
 *  - Extended IS Reachability          TLV = 22
 *  - Traffic Engineering Router ID     TLV = 134
 *  - Extended IP Reachability          TLV = 135
 *  - Inter-AS Reachability Information TLV = 141
 *
 *  and support following sub-TLV:
 *
 * Name                           Value   Status
 * _________________________________________________
 * Administartive group (color)       3   RFC5305
 * Link Local/Remote Identifiers      4   RFC5307
 * IPv4 interface address             6   RFC5305
 * IPv4 neighbor address              8   RFC5305
 * Maximum link bandwidth             9   RFC5305
 * Reservable link bandwidth         10   RFC5305
 * Unreserved bandwidth              11   RFC5305
 * TE Default metric                 18   RFC5305
 * Link Protection Type              20   RFC5307
 * Interface Switching Capability    21   RFC5307
 * Remote AS number                  24   RFC5316
 * IPv4 Remote ASBR identifier       25   RFC5316
 *
 * NOTE: RFC5316 is not fully supported in this version
 * only subTLVs decoding is provided
 */

/* Following define the type of TE link regarding the various RFC */
#define STD_TE			0x01
#define GMPLS			0x02
#define INTER_AS 		0x04
#define FLOOD_L1		0x10
#define FLOOD_L2		0x20
#define FLOOD_AS                0x40
#define EMULATED		0x80

#define IS_STD_TE(x) 		(x & STD_TE)
#define IS_INTER_AS(x) 		(x & INTER_AS)
#define IS_EMULATED(x)		(x & EMULATED)
#define IS_FLOOD_L1(x)		(x & FLOOD_L1)
#define IS_FLOOD_L2(x)		(x & FLOOD_L2)
#define IS_FLOOD_AS(x)          (x & FLOOD_AS)
#define IS_INTER_AS_EMU(x) 	(x & INTER_AS & EMULATED)
#define IS_INTER_AS_AS(x)	(x & INTER_AS & FLOOD_AS)

/*
 * Note (since release 7.2), subTLVs definition, serialization
 * and de-serialization have mode to isis_tlvs.[c,h]
 */

/* Following declaration concerns the MPLS-TE and LINk-TE management */
typedef enum _status_t { disable, enable, learn } status_t;

/* Mode for Inter-AS LSP */ /* TODO: Check how if LSP is flooded in RFC5316 */
typedef enum _interas_mode_t { off, region, as, emulate } interas_mode_t;

#define IS_EXT_TE(e)    (e && e->status != 0			\
			   && e->status != EXT_ADJ_SID		\
			   && e->status != EXT_LAN_ADJ_SID)
#define IS_MPLS_TE(a)	(a && a->status == enable)

/* Per area MPLS-TE parameters */
struct mpls_te_area {
	/* Status of MPLS-TE: enable or disable */
	status_t status;

	/* L1, L1-L2, L2-Only */
	uint8_t level;

	/* RFC5316 */
	interas_mode_t inter_as;
	struct in_addr interas_areaid;

	/* MPLS_TE router ID */
	struct in_addr router_id;
};

/* Prototypes. */
void isis_mpls_te_init(void);
void isis_link_params_update(struct isis_circuit *, struct interface *);
int isis_mpls_te_update(struct interface *);

#endif /* _ZEBRA_ISIS_MPLS_TE_H */
