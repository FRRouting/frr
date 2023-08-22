// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Abhinay Ramesh
 */

#ifndef __OSPF6_AUTH_TRAILER_H__
#define __OSPF6_AUTH_TRAILER_H__

#include "lib/keychain.h"
#include "ospf6_message.h"

#define OSPF6_AUTH_HDR_MIN_SIZE 16
#define OSPF6_AUTH_HDR_FULL     KEYCHAIN_MAX_HASH_SIZE + OSPF6_AUTH_HDR_MIN_SIZE

#define OSPF6_AUTHENTICATION_NULL 0
#define OSPF6_AUTHENTICATION_CRYPTOGRAPHIC 1

#define OSPFV3_CRYPTO_PROTO_ID 1

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

enum ospf6_auth_err {
	OSPF6_AUTH_VALIDATE_SUCCESS = 0,
	OSPF6_AUTH_VALIDATE_FAILURE,
	OSPF6_AUTH_PROCESS_NORMAL,
	OSPF6_AUTH_FILE_EXIST,
	OSPF6_AUTH_FILE_DO_NOT_EXIST
};

void ospf6_auth_hdr_dump_send(struct ospf6_header *ospfh, uint16_t length);
void ospf6_auth_hdr_dump_recv(struct ospf6_header *ospfh, uint16_t length,
			      unsigned int lls_len);
unsigned char *ospf6_hash_message_xor(unsigned char *mes1, unsigned char *mes2,
				      uint32_t len);
uint16_t ospf6_auth_len_get(struct ospf6_interface *oi);
int ospf6_auth_validate_pkt(struct ospf6_interface *oi, unsigned int *pkt_len,
			    struct ospf6_header *oh, unsigned int *at_len,
			    unsigned int *lls_block_len);
int ospf6_auth_check_digest(struct ospf6_header *oh, struct ospf6_interface *oi,
			    struct in6_addr *src, unsigned int lls_len);
void ospf6_auth_update_digest(struct ospf6_interface *oi,
			      struct ospf6_header *oh,
			      struct ospf6_auth_hdr *ospf6_auth, char *auth_str,
			      uint32_t pkt_len, enum keychain_hash_algo algo);
void ospf6_auth_digest_send(struct in6_addr *src, struct ospf6_interface *oi,
			    struct ospf6_header *oh, uint16_t auth_len,
			    uint32_t pkt_len);
void install_element_ospf6_debug_auth(void);
int config_write_ospf6_debug_auth(struct vty *vty);
void install_element_ospf6_clear_intf_auth(void);
enum ospf6_auth_err ospf6_auth_nvm_file_exist(void);
void ospf6_auth_seqno_nvm_update(struct ospf6 *ospf6);
void ospf6_auth_seqno_nvm_delete(struct ospf6 *ospf6);
void ospf6_auth_seqno_nvm_read(struct ospf6 *ospf6);
#endif /* __OSPF6_AUTH_TRAILER_H__ */
