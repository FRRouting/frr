/*
 * This is an implementation of rfc2370.
 * Copyright (C) 2001 KDD R&D Laboratories, Inc.
 * http://www.kddlabs.co.jp/
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

#ifndef _ZEBRA_OSPF_OPAQUE_H
#define _ZEBRA_OSPF_OPAQUE_H

#include "vty.h"

#define IS_OPAQUE_LSA(type)                                                    \
	((type) == OSPF_OPAQUE_LINK_LSA || (type) == OSPF_OPAQUE_AREA_LSA      \
	 || (type) == OSPF_OPAQUE_AS_LSA)

/*
 * Opaque LSA's link state ID is redefined as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * |tttttttt|........|........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<------- Opaque ID ------>|
 */
#define LSID_OPAQUE_TYPE_MASK	0xff000000	/*  8 bits */
#define LSID_OPAQUE_ID_MASK	0x00ffffff	/* 24 bits */

#define GET_OPAQUE_TYPE(lsid) (((uint32_t)(lsid)&LSID_OPAQUE_TYPE_MASK) >> 24)

#define GET_OPAQUE_ID(lsid) ((uint32_t)(lsid)&LSID_OPAQUE_ID_MASK)

#define SET_OPAQUE_LSID(type, id)                                              \
	((((unsigned)(type) << 24) & LSID_OPAQUE_TYPE_MASK)                    \
	 | ((id)&LSID_OPAQUE_ID_MASK))

/*
 * Opaque LSA types will be assigned by IANA.
 * <http://www.iana.org/assignments/ospf-opaque-types>
 */
#define OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA		1
#define OPAQUE_TYPE_SYCAMORE_OPTICAL_TOPOLOGY_DESC	2
#define OPAQUE_TYPE_GRACE_LSA				3
#define OPAQUE_TYPE_L1VPN_LSA                          5
#define OPAQUE_TYPE_ROUTER_INFORMATION_LSA             4
#define OPAQUE_TYPE_INTER_AS_LSA                       6
#define OPAQUE_TYPE_EXTENDED_PREFIX_LSA                7
#define OPAQUE_TYPE_EXTENDED_LINK_LSA                  8
#define OPAQUE_TYPE_MAX                                8

/* Followings types are proposed in internet-draft documents. */
#define OPAQUE_TYPE_8021_QOSPF				129
#define OPAQUE_TYPE_SECONDARY_NEIGHBOR_DISCOVERY	224
#define OPAQUE_TYPE_FLOODGATE                           225

/* Ugly hack to make use of an unallocated value for wildcard matching! */
#define OPAQUE_TYPE_WILDCARD				0

#define OPAQUE_TYPE_RANGE_UNASSIGNED(type)                                     \
	(OPAQUE_TYPE_MAX <= (type) && (type) <= 127)

#define OPAQUE_TYPE_RANGE_RESERVED(type) (127 < (type) && (type) <= 255)

#define VALID_OPAQUE_INFO_LEN(lsahdr)                                          \
	((ntohs((lsahdr)->length) >= sizeof(struct lsa_header))                \
	 && ((ntohs((lsahdr)->length) % sizeof(uint32_t)) == 0))

/*
 * Following section defines generic TLV (type, length, value) macros,
 * used for various LSA opaque usage e.g. Traffic Engineering.
 */
struct tlv_header {
	uint16_t type;   /* Type of Value */
	uint16_t length; /* Length of Value portion only, in bytes */
};

#define TLV_HDR_SIZE	(sizeof(struct tlv_header))

#define TLV_BODY_SIZE(tlvh) (ROUNDUP(ntohs((tlvh)->length), sizeof(uint32_t)))

#define TLV_SIZE(tlvh)	(TLV_HDR_SIZE + TLV_BODY_SIZE(tlvh))

#define TLV_HDR_TOP(lsah)                                                      \
	(struct tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE)

#define TLV_HDR_NEXT(tlvh)                                                     \
	(struct tlv_header *)((char *)(tlvh) + TLV_SIZE(tlvh))

#define TLV_HDR_SUBTLV(tlvh)                                                   \
	(struct tlv_header *)((char *)(tlvh) + TLV_HDR_SIZE)

#define TLV_DATA(tlvh)	(void *)((char *)(tlvh) + TLV_HDR_SIZE)

#define TLV_TYPE(tlvh)	tlvh.header.type
#define TLV_LEN(tlvh)	tlvh.header.length
#define TLV_HDR(tlvh)	tlvh.header

/* Following declaration concerns the Opaque LSA management */
enum lsa_opcode { REORIGINATE_THIS_LSA, REFRESH_THIS_LSA, FLUSH_THIS_LSA };

/* Prototypes. */

extern void ospf_opaque_init(void);
extern void ospf_opaque_term(void);
extern void ospf_opaque_finish(void);
extern int ospf_opaque_type9_lsa_init(struct ospf_interface *oi);
extern void ospf_opaque_type9_lsa_term(struct ospf_interface *oi);
extern int ospf_opaque_type10_lsa_init(struct ospf_area *area);
extern void ospf_opaque_type10_lsa_term(struct ospf_area *area);
extern int ospf_opaque_type11_lsa_init(struct ospf *ospf);
extern void ospf_opaque_type11_lsa_term(struct ospf *ospf);

extern int ospf_register_opaque_functab(
	uint8_t lsa_type, uint8_t opaque_type,
	int (*new_if_hook)(struct interface *ifp),
	int (*del_if_hook)(struct interface *ifp),
	void (*ism_change_hook)(struct ospf_interface *oi, int old_status),
	void (*nsm_change_hook)(struct ospf_neighbor *nbr, int old_status),
	void (*config_write_router)(struct vty *vty),
	void (*config_write_if)(struct vty *vty, struct interface *ifp),
	void (*config_write_debug)(struct vty *vty),
	void (*show_opaque_info)(struct vty *vty, struct ospf_lsa *lsa),
	int (*lsa_originator)(void *arg),
	struct ospf_lsa *(*lsa_refresher)(struct ospf_lsa *lsa),
	int (*new_lsa_hook)(struct ospf_lsa *lsa),
	int (*del_lsa_hook)(struct ospf_lsa *lsa));
extern void ospf_delete_opaque_functab(uint8_t lsa_type, uint8_t opaque_type);

extern int ospf_opaque_new_if(struct interface *ifp);
extern int ospf_opaque_del_if(struct interface *ifp);
extern void ospf_opaque_ism_change(struct ospf_interface *oi, int old_status);
extern void ospf_opaque_nsm_change(struct ospf_neighbor *nbr, int old_status);
extern void ospf_opaque_config_write_router(struct vty *vty, struct ospf *ospf);
extern void ospf_opaque_config_write_if(struct vty *vty, struct interface *ifp);
extern void ospf_opaque_config_write_debug(struct vty *vty);
extern void show_opaque_info_detail(struct vty *vty, struct ospf_lsa *lsa);
extern void ospf_opaque_lsa_dump(struct stream *s, uint16_t length);

extern void ospf_opaque_lsa_originate_schedule(struct ospf_interface *oi,
					       int *init_delay);
extern struct ospf_lsa *ospf_opaque_lsa_install(struct ospf_lsa *lsa,
						int rt_recalc);
extern struct ospf_lsa *ospf_opaque_lsa_refresh(struct ospf_lsa *lsa);

extern void ospf_opaque_lsa_reoriginate_schedule(void *lsa_type_dependent,
						 uint8_t lsa_type,
						 uint8_t opaque_type);
extern void ospf_opaque_lsa_refresh_schedule(struct ospf_lsa *lsa);
extern void ospf_opaque_lsa_flush_schedule(struct ospf_lsa *lsa);

extern void ospf_opaque_self_originated_lsa_received(struct ospf_neighbor *nbr,
						     struct ospf_lsa *lsa);
extern struct ospf *oi_to_top(struct ospf_interface *oi);

#endif /* _ZEBRA_OSPF_OPAQUE_H */
