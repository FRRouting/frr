/*
 * Copyright (C) 2021 Abhinay Ramesh
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

#ifndef __OSPF6_AUTH_TRAILER_H__
#define __OSPF6_AUTH_TRAILER_H__

#include "lib/keychain.h"
#include "ospf6_message.h"

#define OSPF6_AUTH_HDR_MIN_SIZE 16
#define OSPF6_AUTH_HDR_FULL     KEYCHAIN_MAX_HASH_SIZE + OSPF6_AUTH_HDR_MIN_SIZE

#define OSPF6_AUTHENTICATION_NULL                 0
#define OSPF6_AUTHENTICATION_CRYPTOGRAPHIC        1
static const uint16_t CPID = 1;

/* Auth debug options */
extern unsigned char conf_debug_ospf6_auth[2];
#define OSPF6_AUTH_TX 0
#define OSPF6_AUTH_RX 1
#define OSPF6_DEBUG_AUTH_TX_ON() (conf_debug_ospf6_auth[OSPF6_AUTH_TX] = 1)
#define OSPF6_DEBUG_AUTH_TX_OFF() (conf_debug_ospf6_auth[OSPF6_AUTH_TX] = 0)
#define OSPF6_DEBUG_AUTH_RX_ON() (conf_debug_ospf6_auth[OSPF6_AUTH_RX] = 1)
#define OSPF6_DEBUG_AUTH_RX_OFF() (conf_debug_ospf6_auth[OSPF6_AUTH_RX] = 0)
#define IS_OSPF6_DEBUG_AUTH_TX (conf_debug_ospf6_auth[OSPF6_AUTH_TX])
#define IS_OSPF6_DEBUG_AUTH_RX (conf_debug_ospf6_auth[OSPF6_AUTH_RX])

#define OSPF6_AUTH_TRAILER_KEYCHAIN (1 << 0)
#define OSPF6_AUTH_TRAILER_MANUAL_KEY (1 << 1)
#define OSPF6_AUTH_TRAILER_KEYCHAIN_VALID (1 << 2)

/* According to sesion 4.1 of RFC7166 defining the trailer struct */
struct ospf6_auth_hdr {
	uint16_t type;
	uint16_t length;
	uint16_t reserved;
	uint16_t id;
	uint32_t seqnum_h;
	uint32_t seqnum_l;
	unsigned char data[KEYCHAIN_MAX_HASH_SIZE];
};

void ospf6_auth_hdr_dump_send(struct ospf6_header *ospfh, uint16_t length);
void ospf6_auth_hdr_dump_recv(struct ospf6_header *ospfh, uint16_t length);
unsigned char *ospf6_hash_message_xor(unsigned char *mes1, unsigned char *mes2,
				      uint32_t len);
unsigned int ospf6_auth_len_get(struct ospf6_interface *oi);
int ospf6_auth_validate_pkt(struct ospf6_interface *oi, unsigned int *pkt_len,
			    struct ospf6_header *oh, unsigned int *at_len);
int ospf6_auth_check_digest(struct ospf6_header *oh, struct ospf6_interface *oi,
			    struct in6_addr *src);
void ospf6_auth_update_digest(struct ospf6_interface *oi,
			      struct ospf6_header *oh,
			      struct ospf6_auth_hdr *ospf6_auth, char *auth_str,
			      uint16_t auth_len, uint32_t pkt_len,
			      enum keychain_hash_algo algo);
void ospf6_auth_digest_send(struct in6_addr *src, struct ospf6_interface *oi,
			    struct ospf6_header *oh, uint16_t auth_len,
			    uint32_t pkt_len);
void install_element_ospf6_debug_auth(void);
int config_write_ospf6_debug_auth(struct vty *vty);
void install_element_ospf6_clear_intf_auth(void);
#endif /* __OSPF6_AUTH_TRAILER_H__ */
