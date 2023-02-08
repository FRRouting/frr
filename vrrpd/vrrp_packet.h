// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP packet crafting.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
 */
#ifndef __VRRP_PACKET_H__
#define __VRRP_PACKET_H__

#include <zebra.h>

#include "lib/ipaddr.h"
#include "lib/memory.h"
#include "lib/prefix.h"

#define VRRP_TYPE_ADVERTISEMENT 1

/*
 * Shared header for VRRPv2/v3 packets.
 */
struct vrrp_hdr {
	/*
	 * H  L H  L
	 * 0000 0000
	 * ver  type
	 */
	uint8_t vertype;
	uint8_t vrid;
	uint8_t priority;
	uint8_t naddr;
	union {
		struct {
			uint8_t auth_type;
			/* advertisement interval (in sec) */
			uint8_t adver_int;
		} v2;
		struct {
			/*
			 * advertisement interval (in centiseconds)
			 * H  L H          L
			 * 0000 000000000000
			 * rsvd adver_int
			 */
			uint16_t adver_int;
		} v3;
	};
	uint16_t chksum;
} __attribute__((packed));

#define VRRP_HDR_SIZE sizeof(struct vrrp_hdr)

struct vrrp_pkt {
	struct vrrp_hdr hdr;
	/*
	 * When used, this is actually an array of one or the other, not an
	 * array of union. If N v4 addresses are stored then
	 * sizeof(addrs) == N * sizeof(struct in_addr).
	 *
	 * Under v2, the last 2 entries in this array are the authentication
	 * data fields. We don't support auth in v2 so these are always just 8
	 * bytes of 0x00.
	 */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addrs[];
} __attribute__((packed));

#define VRRP_PKT_SIZE(_f, _ver, _naddr)                                        \
	({                                                                     \
		size_t _asz = ((_f) == AF_INET) ? sizeof(struct in_addr)       \
						: sizeof(struct in6_addr);     \
		size_t _auth = 2 * sizeof(uint32_t) * (3 - (_ver));            \
		sizeof(struct vrrp_hdr) + (_asz * (_naddr)) + _auth;           \
	})

#define VRRP_MIN_PKT_SIZE_V4 VRRP_PKT_SIZE(AF_INET, 3, 1)
#define VRRP_MAX_PKT_SIZE_V4 VRRP_PKT_SIZE(AF_INET, 2, 255)
#define VRRP_MIN_PKT_SIZE_V6 VRRP_PKT_SIZE(AF_INET6, 3, 1)
#define VRRP_MAX_PKT_SIZE_V6 VRRP_PKT_SIZE(AF_INET6, 3, 255)

#define VRRP_MIN_PKT_SIZE VRRP_MIN_PKT_SIZE_V4
#define VRRP_MAX_PKT_SIZE VRRP_MAX_PKT_SIZE_V6

/*
 * Builds a VRRP ADVERTISEMENT packet.
 *
 * pkt
 *    Pointer to store pointer to result buffer in
 *
 * src
 *    Source address packet will be transmitted from. This is needed to compute
 *    the VRRP checksum. The returned packet must be sent in an IP datagram with
 *    the source address equal to this field, or the checksum will be invalid.
 *
 * version
 *    VRRP version; must be 2 or 3
 *
 * vrid
 *    Virtual Router Identifier
 *
 * prio
 *    Virtual Router Priority
 *
 * max_adver_int
 *    time between ADVERTISEMENTs
 *
 * v6
 *    whether 'ips' is an array of v4 or v6 addresses
 *
 * numip
 *    number of IPvX addresses in 'ips'
 *
 * ips
 *    array of pointer to either struct in_addr (v6 = false) or struct in6_addr
 *    (v6 = true)
 */
ssize_t vrrp_pkt_adver_build(struct vrrp_pkt **pkt, struct ipaddr *src,
			     uint8_t version, uint8_t vrid, uint8_t prio,
			     uint16_t max_adver_int, uint8_t numip,
			     struct ipaddr **ips, bool ipv4_ph);

/* free memory allocated by vrrp_pkt_adver_build's pkt arg */
void vrrp_pkt_free(struct vrrp_pkt *pkt);

/*
 * Dumps a VRRP ADVERTISEMENT packet to a string.
 *
 * Currently only dumps the header.
 *
 * buf
 *    Buffer to store string representation
 *
 * buflen
 *    Size of buf
 *
 * pkt
 *    Packet to dump to a string
 *
 * Returns:
 *    # bytes written to buf
 */
size_t vrrp_pkt_adver_dump(char *buf, size_t buflen, struct vrrp_pkt *pkt);


/*
 * Parses a VRRP packet, checking for illegal or invalid data.
 *
 * This function parses both VRRPv2 and VRRPv3 packets. Which version is
 * expected is determined by the version argument. For example, if version is 3
 * and the received packet has version field 2 it will fail to parse.
 *
 * Note that this function only checks whether the packet itself is a valid
 * VRRP packet. It is up to the caller to validate whether the VRID is correct,
 * priority and timer values are correct, etc.
 *
 * family
 *    Address family of received packet
 *
 * version
 *   VRRP version to use for validation
 *
 * m
 *    msghdr containing results of recvmsg() on VRRP router socket
 *
 * read
 *    Return value of recvmsg() on VRRP router socket; must be non-negative
 *
 * src
 *    Pointer to struct ipaddr to store address of datagram sender
 *
 * pkt
 *    Pointer to pointer to set to location of VRRP packet within buf
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error; may be
 *    NULL, in which case no message will be stored
 *
 * errmsg_len
 *    Size of errmsg
 *
 * Returns:
 *    Size of VRRP packet, or -1 upon error
 */
ssize_t vrrp_pkt_parse_datagram(int family, int version, bool ipv4_ph,
				struct msghdr *m, size_t read,
				struct ipaddr *src, struct vrrp_pkt **pkt,
				char *errmsg, size_t errmsg_len);

#endif /* __VRRP_PACKET_H__ */
