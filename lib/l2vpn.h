// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * L2VPN Pseudowire/EVPN definitions
 *
 * Copyright (C) 2016 Volta Networks, Inc.
 * Copyright 2026 6WIND S.A.
 */

#ifndef _FRR_L2VPN_H
#define _FRR_L2VPN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lib/prefix.h"

typedef enum { L2VPN_TYPE_VPWS = 1, L2VPN_TYPE_VPLS = 2 } l2vpn_types;

extern void l2vpn_cli_init(void);
extern const struct frr_yang_module_info frr_l2vpn;
extern const struct frr_yang_module_info frr_l2vpn_cli_info;

/* L2VPN name length. */
#define L2VPN_NAME_LEN	  32
#define DEFAULT_L2VPN_MTU 1500
#define MIN_L2VPN_MTU	  512
#define MAX_L2VPN_MTU	  0xffff

/* Pseudowire type - LDP and BGP use the same values. */
#define PW_TYPE_ETHERNET_TAGGED 0x0004 /* RFC 4446 */
#define PW_TYPE_ETHERNET	0x0005 /* RFC 4446 */
#define PW_TYPE_WILDCARD	0x7FFF /* RFC 4863, RFC 6668 */
#define DEFAULT_PW_TYPE PW_TYPE_ETHERNET

/* Pseudowire flags. */
#define F_PSEUDOWIRE_CWORD 0x01

/* Pseudowire status TLV */
#define PW_FORWARDING	  0
#define PW_NOT_FORWARDING (1 << 0)
#define PW_LOCAL_RX_FAULT (1 << 1)
#define PW_LOCAL_TX_FAULT (1 << 2)
#define PW_PSN_RX_FAULT	  (1 << 3)
#define PW_PSN_TX_FAULT	  (1 << 4)

/* L2VPN EVPN status */
#define EVPN_FORWARDING     PW_FORWARDING
#define EVPN_NOT_FORWARDING PW_NOT_FORWARDING
#define EVPN_LOCAL_RX_FAULT PW_LOCAL_RX_FAULT
#define EVPN_LOCAL_TX_FAULT PW_LOCAL_TX_FAULT

/*
 * Protocol-specific information about the L2VPN.
 */
union l2vpn_protocol_fields {
	struct {
		struct in_addr lsr_id;
		uint32_t pwid;
		char vpn_name[L2VPN_NAME_LEN];
	} ldp;
	struct {
		char vpn_name[L2VPN_NAME_LEN];
		char local_ac[IFNAMSIZ];
		uint32_t vni;
		esi_t esi;
	} bgp;
};

#ifdef __cplusplus
}
#endif

#endif /* _FRR_L2VPN_H */
