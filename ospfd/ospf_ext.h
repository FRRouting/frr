/*
 * This is an implementation of RFC7684 OSPFv2 Prefix/Link Attribute
 * Advertisement
 *
 * Module name: Extended Prefix/Link Opaque LSA header definition
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Author: Anselme Sawadogo <anselmesawadogo@gmail.com>
 *
 * Copyright (C) 2016 - 2018 Orange Labs http://www.orange.com
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

#ifndef _FRR_OSPF_EXT_PREF_H_
#define _FRR_OSPF_EXT_PREF_H_

/*
 * Opaque LSA's link state ID for Extended Prefix/Link is
 * structured as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * |  7/8   |........|........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<------- Instance ------->|
 *
 *
 * Type:      IANA has assigned '7' for Extended Prefix Opaque LSA
 *            and '8' for Extended Link Opaque LSA
 * Instance:  User may select arbitrary 24-bit values to identify
 *            different instances of Extended Prefix/Link Opaque LSA
 *
 */

/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |   LS age        |Options |  10,11 |  A
 * +--------+--------+--------+--------+  |  Standard (Opaque) LSA header;
 * |   7/8  |        Instance          |  |
 * +--------+--------+--------+--------+  |  Type 10 or 11 are used for Extended
 * |        Advertising router         |  |  Prefix Opaque LSA
 * +--------+--------+--------+--------+  |
 * |        LS sequence number         |  |  Type 10 only is used for Extended
 * +--------+--------+--------+--------+  |  Link Opaque LSA
 * |   LS checksum   |     Length      |  V
 * +--------+--------+--------+--------+ ---
 * |      Type       |     Length      |  A
 * +--------+--------+--------+--------+  |  TLV part for Extended Prefix/Link
 * |                                   |  |  Opaque LSA;
 * ~              Values ...           ~  |  Values might be structured as a set
 * |                                   |  V  of sub-TLVs.
 * +--------+--------+--------+--------+ ---
 */

/* Global use constant numbers */

#define MAX_LEGAL_EXT_INSTANCE_NUM	(0xffff)
#define LEGAL_EXT_INSTANCE_RANGE(i)	(0 <= (i) && (i) <= 0xffff)

/* Flags to manage Extended Link/Prefix Opaque LSA */
#define EXT_LPFLG_LSA_INACTIVE          0x00
#define EXT_LPFLG_LSA_ACTIVE            0x01
#define EXT_LPFLG_LSA_ENGAGED           0x02
#define EXT_LPFLG_LSA_LOOKUP_DONE       0x04
#define EXT_LPFLG_LSA_FORCED_REFRESH    0x08
#define EXT_LPFLG_FIB_ENTRY_SET         0x10

/*
 * Following section defines TLV (tag, length, value) structures,
 * used in Extended Prefix/Link Opaque LSA.
 */

/* Extended Prefix TLV Route Types */
#define EXT_TLV_PREF_ROUTE_UNSPEC	0
#define EXT_TLV_PREF_ROUTE_INTRA_AREA	1
#define EXT_TLV_PREF_ROUTE_INTER_AREA	3
#define EXT_TLV_PREF_ROUTE_AS_EXT	5
#define EXT_TLV_PREF_ROUTE_NSSA_EXT	7

/*
 * Extended Prefix and Extended Prefix Range TLVs'
 * Address family flag for IPv4
 */
#define EXT_TLV_PREF_AF_IPV4		0

/* Extended Prefix TLV Flags */
#define EXT_TLV_PREF_AFLG		0x80
#define EXT_TLV_PREF_NFLG		0x40

/* Extended Prefix Range TLV Flags */
#define EXT_TLV_PREF_RANGE_IAFLG	0x80

/* ERO subtlvs Flags */
#define EXT_SUBTLV_ERO_LFLG		0x80

/* Extended Prefix TLV see RFC 7684 section 2.1 */
#define EXT_TLV_PREFIX			1
#define EXT_TLV_PREFIX_SIZE		8
struct ext_tlv_prefix {
	struct tlv_header header;
	uint8_t route_type;
	uint8_t pref_length;
	uint8_t af;
	uint8_t flags;
	struct in_addr address;
};

/* Extended Link TLV see RFC 7684 section 3.1 */
#define EXT_TLV_LINK			1
#define EXT_TLV_LINK_SIZE		12
struct ext_tlv_link {
	struct tlv_header header;
	uint8_t link_type;
	uint8_t reserved[3];
	struct in_addr link_id;
	struct in_addr link_data;
};

/* Remote Interface Address Sub-TLV, Cisco experimental use Sub-TLV */
#define EXT_SUBTLV_RMT_ITF_ADDR         32768
#define EXT_SUBTLV_RMT_ITF_ADDR_SIZE	4
struct ext_subtlv_rmt_itf_addr {
	struct tlv_header header;
	struct in_addr value;
};

/* Internal structure to manage Extended Link/Prefix Opaque LSA */
struct ospf_ext_lp {
	bool enabled;

	/* Flags to manage this Extended Prefix/Link Opaque LSA */
	uint32_t flags;

	/*
	 * Scope is area Opaque Type 10 or AS Opaque LSA Type 11 for
	 * Extended Prefix and area Opaque Type 10 for Extended Link
	 */
	uint8_t scope;

	/* area pointer if flooding is Type 10 Null if flooding is AS scope */
	struct ospf_area *area;
	struct in_addr area_id;

	/* List of interface with Segment Routing enable */
	struct list *iflist;
};

/* Structure to aggregate interfaces information for Extended Prefix/Link */
struct ext_itf {
	/* 24-bit Opaque-ID field value according to RFC 7684 specification */
	uint32_t instance;
	uint8_t type; /* Extended Prefix (7) or Link (8) */

	/* Reference pointer to a Zebra-interface. */
	struct interface *ifp;

	/* Area info in which this SR link belongs to. */
	struct ospf_area *area;

	/* Flags to manage this link parameters. */
	uint32_t flags;

	/* SID type: Node, Adjacency or LAN Adjacency */
	enum sid_type stype;

	/* extended link/prefix TLV information */
	struct ext_tlv_prefix prefix;
	struct ext_subtlv_prefix_sid node_sid;
	struct ext_tlv_link link;
	struct ext_subtlv_adj_sid adj_sid[2];
	struct ext_subtlv_lan_adj_sid lan_sid[2];

	/* cisco experimental subtlv */
	struct ext_subtlv_rmt_itf_addr rmt_itf_addr;
};

/* Prototypes. */
extern int ospf_ext_init(void);
extern void ospf_ext_term(void);
extern void ospf_ext_finish(void);
extern void ospf_ext_update_sr(bool enable);
extern uint32_t ospf_ext_schedule_prefix_index(struct interface *ifp,
					  uint32_t index,
					  struct prefix_ipv4 *p,
					  uint8_t flags);
#endif /* _FRR_OSPF_EXT_PREF_H_ */
