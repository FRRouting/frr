/*
 * This is an implementation of RFC4970 Router Information
 * with support of RFC5088 PCE Capabilites announcement
 *
 * Module name: Router Information
 * Version:     0.99.22
 * Created:     2012-02-01 by Olivier Dugeon
 * Copyright (C) 2012 Orange Labs http://www.orange.com/
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_OSPF_ROUTER_INFO_H
#define _ZEBRA_OSPF_ROUTER_INFO_H

/*
 * Opaque LSA's link state ID for Router Information is
 * structured as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * |    1   |  MBZ   |........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<Resv'd>|<-- Instance --->|
 *
 *
 * Type:      IANA has assigned '4' for Router Information.
 * MBZ:       Reserved, must be set to zero.
 * Instance:  User may select an arbitrary 16-bit value.
 *
 */

/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |   LS age        |Options | 9,10,11|  A
 * +--------+--------+--------+--------+  |
 * |    4   |   0    |    Instance     |  |
 * +--------+--------+--------+--------+  |
 * |        Advertising router         |  |  Standard (Opaque) LSA header;
 * +--------+--------+--------+--------+  |  Type 9,10 or 11 are used.
 * |        LS sequence number         |  |
 * +--------+--------+--------+--------+  |
 * |   LS checksum   |     Length      |  V
 * +--------+--------+--------+--------+ ---
 * |      Type       |     Length      |  A
 * +--------+--------+--------+--------+  |  TLV part for Router Information; Values might be
 * |              Values ...           |  V  structured as a set of sub-TLVs.
 * +--------+--------+--------+--------+ ---
 */

/*
 * Following section defines TLV (tag, length, value) structures,
 * used for Router Information.
 */
struct ri_tlv_header
{
  u_int16_t type;               /* RI_TLV_XXX (see below) */
  u_int16_t length;             /* Value portion only, in byte */
};

#define RI_TLV_HDR_SIZE (sizeof (struct ri_tlv_header))
#define RI_TLV_BODY_SIZE(tlvh) (ROUNDUP (ntohs ((tlvh)->length), sizeof (u_int32_t)))
#define RI_TLV_SIZE(tlvh) (RI_TLV_HDR_SIZE + RI_TLV_BODY_SIZE(tlvh))
#define RI_TLV_HDR_TOP(lsah) (struct ri_tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE)
#define RI_TLV_HDR_NEXT(tlvh) (struct ri_tlv_header *)((char *)(tlvh) + RI_TLV_SIZE(tlvh))

/*
 * Following section defines TLV body parts.
 */

/* Up to now, 8 code point have been assigned to Router Information */
/* Only type 1 Router Capabilities and 6 PCE are supported with this code */
#define RI_IANA_MAX_TYPE		8

/* RFC4970: Router Information Capabilities TLV */ /* Mandatory */
#define RI_TLV_CAPABILITIES		1

struct ri_tlv_router_cap
{
  struct ri_tlv_header header;  /* Value length is 4 bytes. */
  u_int32_t value;
};

#define RI_GRACE_RESTART	0x01
#define RI_GRACE_HELPER		0x02
#define RI_STUB_SUPPORT		0x04
#define RI_TE_SUPPORT		0x08
#define RI_P2P_OVER_LAN		0x10
#define RI_TE_EXPERIMENTAL	0x20

#define RI_TLV_LENGTH		4

/* RFC5088: PCE Capabilities TLV */ /* Optional */
/* RI PCE TLV */
#define RI_TLV_PCE			6

struct ri_tlv_pce
{
  struct ri_tlv_header header;
/* A set of PCE-sub-TLVs will follow. */
};

/* PCE Address Sub-TLV */ /* Mandatory */
#define	RI_PCE_SUBTLV_ADDRESS		1
struct ri_pce_subtlv_address
{
  struct ri_tlv_header header;  /* Type = 1; Length is 8 (IPv4) or 20 (IPv6) bytes. */
#define	PCE_ADDRESS_LENGTH_IPV4		8
#define	PCE_ADDRESS_LENGTH_IPV6		20
  struct
  {
    u_int16_t type;             /* Address type: 1 = IPv4, 2 = IPv6 */
#define	PCE_ADDRESS_TYPE_IPV4		1
#define	PCE_ADDRESS_TYPE_IPV6		2
    u_int16_t reserved;
    struct in_addr value;      /* PCE address */
  } address;
};

/* PCE Path-Scope Sub-TLV */ /* Mandatory */
#define	RI_PCE_SUBTLV_PATH_SCOPE	2
struct ri_pce_subtlv_path_scope
{
  struct ri_tlv_header header; /* Type = 2; Length = 4 bytes. */
  u_int32_t value;              /* L, R, Rd, S, Sd, Y, PrefL, PrefR, PrefS and PrefY bits see RFC5088 page 9 */
};

/* PCE Domain Sub-TLV */ /* Optional */
#define	RI_PCE_SUBTLV_DOMAIN		3

#define	PCE_DOMAIN_TYPE_AREA		1
#define	PCE_DOMAIN_TYPE_AS			2

struct ri_pce_subtlv_domain
{
  struct ri_tlv_header header;  /* Type = 3; Length = 8 bytes. */
  u_int16_t type;               /* Domain type: 1 = OSPF Area ID, 2 = AS Number */
  u_int16_t reserved;
  u_int32_t value;
};

/* PCE Neighbor Sub-TLV */ /* Mandatory if R or S bit is set */
#define RI_PCE_SUBTLV_NEIGHBOR		4
struct ri_pce_subtlv_neighbor
{
  struct ri_tlv_header header;  /* Type = 4; Length = 8 bytes. */
  u_int16_t type;               /* Domain type: 1 = OSPF Area ID, 2 = AS Number */
  u_int16_t reserved;
  u_int32_t value;
};

/* PCE Capabilities Flags Sub-TLV */ /* Optional */
#define RI_PCE_SUBTLV_CAP_FLAG		5

#define PCE_CAP_GMPLS_LINK		0x0001
#define PCE_CAP_BIDIRECTIONAL	0x0002
#define PCE_CAP_DIVERSE_PATH	0x0004
#define PCE_CAP_LOAD_BALANCE	0x0008
#define PCE_CAP_SYNCHRONIZED	0x0010
#define PCE_CAP_OBJECTIVES		0x0020
#define PCE_CAP_ADDITIVE		0x0040
#define PCE_CAP_PRIORIZATION	0x0080
#define PCE_CAP_MULTIPLE_REQ	0x0100

struct ri_pce_subtlv_cap_flag
{
  struct ri_tlv_header header;  /* Type = 5; Length = n x 4 bytes. */
  u_int32_t value;
};

/* Prototypes. */
extern int ospf_router_info_init (void);
extern void ospf_router_info_term (void);

#endif /* _ZEBRA_OSPF_ROUTER_INFO_H */
