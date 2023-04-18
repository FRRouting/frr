// SPDX-License-Identifier: GPL-2.0-or-later
/* Pseudowire definitions
 * Copyright (C) 2016 Volta Networks, Inc.
 */

#ifndef _FRR_PW_H
#define _FRR_PW_H

#ifdef __cplusplus
extern "C" {
#endif

/* L2VPN name length. */
#define L2VPN_NAME_LEN		32

/* Pseudowire type - LDP and BGP use the same values. */
#define PW_TYPE_ETHERNET_TAGGED	0x0004	/* RFC 4446 */
#define PW_TYPE_ETHERNET	0x0005	/* RFC 4446 */
#define PW_TYPE_WILDCARD	0x7FFF	/* RFC 4863, RFC 6668 */

/* Pseudowire flags. */
#define F_PSEUDOWIRE_CWORD	0x01

/* Pseudowire status TLV */
#define PW_FORWARDING 0
#define PW_NOT_FORWARDING (1 << 0)
#define PW_LOCAL_RX_FAULT (1 << 1)
#define PW_LOCAL_TX_FAULT (1 << 2)
#define PW_PSN_RX_FAULT (1 << 3)
#define PW_PSN_TX_FAULT (1 << 4)

/*
 * Protocol-specific information about the pseudowire.
 */
union pw_protocol_fields {
	struct {
		struct in_addr lsr_id;
		uint32_t pwid;
		char vpn_name[L2VPN_NAME_LEN];
	} ldp;
};

#ifdef __cplusplus
}
#endif

#endif /* _FRR_PW_H */
