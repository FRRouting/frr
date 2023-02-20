// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RD definitions for BGP-based VPNs (IP/EVPN)
 * -- brought over from bgpd/bgp_mplsvpn.h
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

#ifndef _QUAGGA_BGP_RD_H
#define _QUAGGA_BGP_RD_H

/* RD types */
#define RD_TYPE_AS      0
#define RD_TYPE_IP      1
#define RD_TYPE_AS4     2

#ifdef ENABLE_BGP_VNC
#define RD_TYPE_VNC_ETH	0xff00  /* VNC L2VPN */
#endif

#define RD_ADDRSTRLEN  28
#define RD_BYTES  8

struct rd_as {
	uint16_t type;
	as_t as;
	uint32_t val;
};

struct rd_ip {
	uint16_t type;
	struct in_addr ip;
	uint16_t val;
};

#ifdef ENABLE_BGP_VNC
struct rd_vnc_eth {
	uint16_t type;
	uint8_t local_nve_id;
	struct ethaddr macaddr;
};
#endif

extern uint16_t decode_rd_type(const uint8_t *pnt);
extern void encode_rd_type(uint16_t, uint8_t *);

extern void decode_rd_as(const uint8_t *pnt, struct rd_as *rd_as);
extern void decode_rd_as4(const uint8_t *pnt, struct rd_as *rd_as);
extern void decode_rd_ip(const uint8_t *pnt, struct rd_ip *rd_ip);
#ifdef ENABLE_BGP_VNC
extern void decode_rd_vnc_eth(const uint8_t *pnt,
			      struct rd_vnc_eth *rd_vnc_eth);
#endif

extern int str2prefix_rd(const char *, struct prefix_rd *);
extern char *prefix_rd2str(const struct prefix_rd *, char *, size_t);
extern void form_auto_rd(struct in_addr router_id, uint16_t rd_id,
			 struct prefix_rd *prd);

#endif /* _QUAGGA_BGP_RD_H */
