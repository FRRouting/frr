// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_MSG_H
#define PIM_MSG_H

#include <netinet/in.h>
#if PIM_IPV == 6
#include <netinet/ip6.h>
#endif

#include "pim_jp_agg.h"

#define PIM_HDR_LEN  sizeof(struct pim_msg_header)
/*
  Number       Description
  ----------   ------------------
  0            Reserved
  1            IP (IP version 4)
  2            IP6 (IP version 6)

  From:
  http://www.iana.org/assignments/address-family-numbers
*/
enum pim_msg_address_family {
	PIM_MSG_ADDRESS_FAMILY_RESERVED,
	PIM_MSG_ADDRESS_FAMILY_IPV4,
	PIM_MSG_ADDRESS_FAMILY_IPV6,
};

/*
 * pim_msg_hdr
 * =========================
 *  PIM Header definition as per RFC 5059. N bit introduced to indicate
 *  do-not-forward option in PIM Boot strap Message.
 *    0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |PIM Ver| Type  |N|  Reserved   |           Checksum            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct pim_msg_header {
#if (BYTE_ORDER == LITTLE_ENDIAN)
	uint8_t type : 4;
	uint8_t ver : 4;
	uint8_t reserved : 7;
	uint8_t Nbit : 1; /* No Fwd Bit */
#elif (BYTE_ORDER == BIG_ENDIAN)
	uint8_t ver : 4;
	uint8_t type : 4;
	uint8_t Nbit : 1; /* No Fwd Bit */
	uint8_t reserved : 7;
#else
#error"Please set byte order"
#endif
	uint16_t checksum;
} __attribute__((packed));

struct pim_encoded_ipv4_unicast {
	uint8_t family;
	uint8_t reserved;
	struct in_addr addr;
} __attribute__((packed));

struct pim_encoded_ipv6_unicast {
	uint8_t family;
	uint8_t reserved;
	struct in6_addr addr;
} __attribute__((packed));

/*
 *  Encoded Group format. RFC 4601 Sec 4.9.1
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Addr Family  | Encoding Type |B| Reserved  |Z|  Mask Len     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                Group multicast Address
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
 */
struct pim_encoded_group_ipv4 {
	uint8_t family;
	uint8_t ne;
#if (BYTE_ORDER == LITTLE_ENDIAN)
	uint8_t sz : 1;	/* scope zone bit */
	uint8_t reserved : 6;	/* Reserved */
	uint8_t bidir : 1;	/* Bidir bit */
#elif (BYTE_ORDER == BIG_ENDIAN)
	uint8_t bidir : 1;	/* Bidir bit */
	uint8_t reserved : 6;	/* Reserved */
	uint8_t sz : 1;		/* scope zone bit */
#else
#error"Please set byte order"
#endif
	uint8_t mask;
	struct in_addr addr;
} __attribute__((packed));

struct pim_encoded_group_ipv6 {
	uint8_t family;
	uint8_t ne;
#if (BYTE_ORDER == LITTLE_ENDIAN)
	uint8_t sz : 1;	      /* scope zone bit */
	uint8_t reserved : 6; /* Reserved */
	uint8_t bidir : 1;    /* Bidir bit */
#elif (BYTE_ORDER == BIG_ENDIAN)
	uint8_t bidir : 1;	/* Bidir bit */
	uint8_t reserved : 6;	/* Reserved */
	uint8_t sz : 1;		/* scope zone bit */
#else
#error "Please set byte order"
#endif
	uint8_t mask;
	struct in6_addr addr;
} __attribute__((packed));

/*
 *  Encoded Source format. RFC 4601 Sec 4.9.1
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Addr Family   | Encoding Type | Rsrvd   |S|W|R|  Mask Len     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Source Address
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
 */
struct pim_encoded_source_ipv4 {
	uint8_t family;
	uint8_t ne;
	uint8_t bits;
	uint8_t mask;
	struct in_addr addr;
} __attribute__((packed));

struct pim_encoded_source_ipv6 {
	uint8_t family;
	uint8_t ne;
	uint8_t bits;
	uint8_t mask;
	struct in6_addr addr;
} __attribute__((packed));

/* clang-format off */
#if PIM_IPV == 4
typedef struct pim_encoded_ipv4_unicast pim_encoded_unicast;
typedef struct pim_encoded_group_ipv4   pim_encoded_group;
typedef struct pim_encoded_source_ipv4  pim_encoded_source;
#define PIM_MSG_ADDRESS_FAMILY		PIM_MSG_ADDRESS_FAMILY_IPV4
typedef struct ip 			ipv_hdr;
#define IPV_SRC(ip_hdr)			((ip_hdr))->ip_src
#define IPV_DST(ip_hdr)			((ip_hdr))->ip_dst
#define IPV_LEN(ip_hdr)			((ip_hdr))->ip_len
#else
typedef struct pim_encoded_ipv6_unicast pim_encoded_unicast;
typedef struct pim_encoded_group_ipv6   pim_encoded_group;
typedef struct pim_encoded_source_ipv6  pim_encoded_source;
#define PIM_MSG_ADDRESS_FAMILY		PIM_MSG_ADDRESS_FAMILY_IPV6
typedef struct ip6_hdr 			ipv_hdr;
#define IPV_SRC(ip_hdr)			((ip_hdr))->ip6_src
#define IPV_DST(ip_hdr)			((ip_hdr))->ip6_dst
#define IPV_LEN(ip_hdr)			((ip_hdr))->ip6_plen
#endif
/* clang-format on */

struct pim_jp_groups {
	pim_encoded_group g;
	uint16_t joins;
	uint16_t prunes;
	pim_encoded_source s[1];
} __attribute__((packed));

struct pim_jp {
	struct pim_msg_header header;
	pim_encoded_unicast addr;
	uint8_t reserved;
	uint8_t num_groups;
	uint16_t holdtime;
	struct pim_jp_groups groups[1];
} __attribute__((packed));

#if PIM_IPV == 4
static inline pim_sgaddr pim_sgaddr_from_iphdr(const void *iphdr)
{
	const struct ip *ipv4_hdr = iphdr;
	pim_sgaddr sg;

	sg.src = ipv4_hdr->ip_src;
	sg.grp = ipv4_hdr->ip_dst;

	return sg;
}
#else
static inline pim_sgaddr pim_sgaddr_from_iphdr(const void *iphdr)
{
	const struct ip6_hdr *ipv6_hdr = iphdr;
	pim_sgaddr sg;

	sg.src = ipv6_hdr->ip6_src;
	sg.grp = ipv6_hdr->ip6_dst;

	return sg;
}
#endif

void pim_msg_build_header(pim_addr src, pim_addr dst, uint8_t *pim_msg,
			  size_t pim_msg_size, uint8_t pim_msg_type,
			  bool no_fwd);
uint8_t *pim_msg_addr_encode_ipv4_ucast(uint8_t *buf, struct in_addr addr);
uint8_t *pim_msg_addr_encode_ipv4_group(uint8_t *buf, struct in_addr addr);

#define PIM_ENCODE_SPARSE_BIT      0x04
#define PIM_ENCODE_WC_BIT          0x02
#define PIM_ENCODE_RPT_BIT         0x01
uint8_t *pim_msg_addr_encode_ipv4_source(uint8_t *buf, struct in_addr addr,
					 uint8_t bits);

uint8_t *pim_msg_addr_encode_ipv6_ucast(uint8_t *buf, struct in6_addr addr);
uint8_t *pim_msg_addr_encode_ipv6_group(uint8_t *buf, struct in6_addr addr);
uint8_t *pim_msg_addr_encode_ipv6_source(uint8_t *buf, struct in6_addr addr,
					 uint8_t bits);

uint8_t *pim_msg_addr_encode_ucast(uint8_t *buf, pim_addr addr);
uint8_t *pim_msg_addr_encode_group(uint8_t *buf, pim_addr addr);
uint8_t *pim_msg_addr_encode_source(uint8_t *buf, pim_addr addr, uint8_t bits);

size_t pim_msg_get_jp_group_size(struct list *sources);
size_t pim_msg_build_jp_groups(struct pim_jp_groups *grp,
			       struct pim_jp_agg_group *sgs, size_t size);
#endif /* PIM_MSG_H */
