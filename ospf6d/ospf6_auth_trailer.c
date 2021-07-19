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

#include "memory.h"
#include "zebra.h"
#include "ospf6d.h"
#include "vty.h"
#include "command.h"
#include "md5.h"
#include "sha256.h"
#include "lib/zlog.h"
#include "ospf6_message.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_proto.h"
#include "ospf6_auth_trailer.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"
#include "lib/keychain.h"

unsigned char conf_debug_ospf6_auth[2];
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_AUTH_PKT, "OSPF6 auth packet");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_AUTH_HASH, "OSPF6 auth hash");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_AUTH_HASH_XOR, "OSPF6 auth hash xor");
DECLARE_MTYPE(OSPF6_AUTH_MANUAL_KEY);

/*Apad is the hexadecimal value 0x878FE1F3. */
const uint8_t ospf6_hash_apad_max[KEYCHAIN_MAX_HASH_SIZE] = {
	0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1,
	0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f,
	0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87,
	0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3,
	0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1,
	0xf3, 0x87, 0x8f, 0xe1, 0xf3, 0x87, 0x8f, 0xe1, 0xf3,
};

const uint8_t ospf6_hash_ipad_max[KEYCHAIN_ALGO_MAX_INTERNAL_BLK_SIZE] = {
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
};

const uint8_t ospf6_hash_opad_max[KEYCHAIN_ALGO_MAX_INTERNAL_BLK_SIZE] = {
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
};

void ospf6_auth_hdr_dump_send(struct ospf6_header *ospfh, uint16_t length)
{
	struct ospf6_auth_hdr *ospf6_at_hdr;
	int at_len, oh_len, at_hdr_len, hash_len;
	unsigned char temp[KEYCHAIN_MAX_HASH_SIZE+1];

	oh_len = htons(ospfh->length);
	at_len = length - oh_len;
	if (at_len > 0) {
		ospf6_at_hdr = (struct ospf6_auth_hdr *)
					((uint8_t *)ospfh + oh_len);
		at_hdr_len = htons(ospf6_at_hdr->length);
		hash_len = at_hdr_len - OSPF6_AUTH_HDR_MIN_SIZE;
		memcpy(temp, ospf6_at_hdr->data, hash_len);
		temp[hash_len] = '\0';
		zlog_debug("OSPF6 Authentication Trailer");
		zlog_debug("  Type %d", htons(ospf6_at_hdr->type));
		zlog_debug("  Length %d", at_hdr_len);
		zlog_debug("  Reserved %d", ospf6_at_hdr->reserved);
		zlog_debug("  SA ID %d", htons(ospf6_at_hdr->id));
		zlog_debug("  seqnum high 0x%08x",
			   htonl(ospf6_at_hdr->seqnum_h));
		zlog_debug("  seqnum high 0x%08x",
			   htonl(ospf6_at_hdr->seqnum_l));
		zlog_debug("  Data %s", temp);
	}
}

void ospf6_auth_hdr_dump_recv(struct ospf6_header *ospfh, uint16_t length)
{
	struct ospf6_auth_hdr *ospf6_at_hdr;
	int at_len, oh_len, at_hdr_len, hash_len;
	unsigned char temp[KEYCHAIN_MAX_HASH_SIZE+1];

	oh_len = ntohs(ospfh->length);
	at_len = length - oh_len;
	if (at_len > 0) {
		ospf6_at_hdr = (struct ospf6_auth_hdr *)
					((uint8_t *)ospfh + oh_len);
		at_hdr_len = ntohs(ospf6_at_hdr->length);
		hash_len = at_hdr_len - OSPF6_AUTH_HDR_MIN_SIZE;
		memcpy(temp, ospf6_at_hdr->data, hash_len);
		temp[hash_len] = '\0';
		zlog_debug("OSPF6 Authentication Trailer");
		zlog_debug("  Type %d", ntohs(ospf6_at_hdr->type));
		zlog_debug("  Length %d", at_hdr_len);
		zlog_debug("  Reserved %d", ospf6_at_hdr->reserved);
		zlog_debug("  SA ID %d", ntohs(ospf6_at_hdr->id));
		zlog_debug("  seqnum high 0x%08x",
			   ntohl(ospf6_at_hdr->seqnum_h));
		zlog_debug("  seqnum high 0x%08x",
			   ntohl(ospf6_at_hdr->seqnum_l));
		zlog_debug("  Data %s", temp);
	}
}

unsigned char *ospf6_hash_message_xor(unsigned char *mes1,
				      unsigned char *mes2,
				      uint32_t len)
{
	unsigned char *result;
	uint32_t i;

	result = XCALLOC(MTYPE_OSPF6_AUTH_HASH_XOR, len + 1);
	if (!result)
		return NULL;

	for (i = 0; i < len; i++)
		result[i] = mes1[i] ^ mes2[i];

	result[len] = '\0';
	return result;
}

static void md5_digest(unsigned char *mes, uint32_t len,
		       unsigned char *digest)
{
#ifdef CRYPTO_OPENSSL
	unsigned int size = KEYCHAIN_MD5_HASH_SIZE;
	EVP_MD_CTX *ctx;
#elif CRYPTO_INTERNAL
	MD5_CTX ctx;
#endif

#ifdef CRYPTO_OPENSSL
	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_md5());
	EVP_DigestUpdate(ctx, mes, len);
	EVP_DigestFinal(ctx, digest, &size);
	EVP_MD_CTX_free(ctx);
#elif CRYPTO_INTERNAL
	memset(&ctx, 0, sizeof(ctx));
	MD5Init(&ctx);
	MD5Update(&ctx, mes, len);
	MD5Final(digest, &ctx);
#endif
}

static void sha256_digest(unsigned char *mes, uint32_t len,
			  unsigned char *digest)
{
#ifdef CRYPTO_OPENSSL
	unsigned int size = KEYCHAIN_HMAC_SHA256_HASH_SIZE;
	EVP_MD_CTX *ctx;
#elif CRYPTO_INTERNAL
	SHA256_CTX ctx;
#endif

#ifdef CRYPTO_OPENSSL
	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_sha256());
	EVP_DigestUpdate(ctx, mes, len);
	EVP_DigestFinal(ctx, digest, &size);
	EVP_MD_CTX_free(ctx);
#elif CRYPTO_INTERNAL
	memset(&ctx, 0, sizeof(ctx));
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, mes, len);
	SHA256_Final(digest, &ctx);
#endif
}

#ifdef CRYPTO_OPENSSL
static void sha1_digest(unsigned char *mes, uint32_t len,
			unsigned char *digest)
{
	EVP_MD_CTX *ctx;
	unsigned int size = KEYCHAIN_HMAC_SHA1_HASH_SIZE;

	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_sha1());
	EVP_DigestUpdate(ctx, mes, len);
	EVP_DigestFinal(ctx, digest, &size);
	EVP_MD_CTX_free(ctx);
}

static void sha384_digest(unsigned char *mes, uint32_t len,
			  unsigned char *digest)
{
	EVP_MD_CTX *ctx;
	unsigned int size = KEYCHAIN_HMAC_SHA384_HASH_SIZE;

	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_sha384());
	EVP_DigestUpdate(ctx, mes, len);
	EVP_DigestFinal(ctx, digest, &size);
	EVP_MD_CTX_free(ctx);
}

static void sha512_digest(unsigned char *mes, uint32_t len,
			  unsigned char *digest)
{
	EVP_MD_CTX *ctx;
	unsigned int size = KEYCHAIN_HMAC_SHA512_HASH_SIZE;

	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_sha512());
	EVP_DigestUpdate(ctx, mes, len);
	EVP_DigestFinal(ctx, digest, &size);
	EVP_MD_CTX_free(ctx);
}
#endif /* CRYPTO_OPENSSL */

static void ospf6_hash_hmac_sha_digest(enum keychain_hash_algo key,
				       unsigned char *mes, uint32_t len,
				       unsigned char *digest)
{
	if ((key <= KEYCHAIN_ALGO_NULL) || (key >= KEYCHAIN_ALGO_MAX))
		return;

	switch (key) {
	case KEYCHAIN_ALGO_MD5:
		md5_digest(mes, len, digest);
		break;
	case KEYCHAIN_ALGO_HMAC_SHA1:
#ifdef CRYPTO_OPENSSL
		sha1_digest(mes, len, digest);
#endif
		break;
	case KEYCHAIN_ALGO_HMAC_SHA256:
		sha256_digest(mes, len, digest);
		break;
	case KEYCHAIN_ALGO_HMAC_SHA384:
#ifdef CRYPTO_OPENSSL
		sha384_digest(mes, len, digest);
#endif
		break;
	case KEYCHAIN_ALGO_HMAC_SHA512:
#ifdef CRYPTO_OPENSSL
		sha512_digest(mes, len, digest);
#endif
		break;
	case KEYCHAIN_ALGO_NULL:
	case KEYCHAIN_ALGO_MAX:
	default:
		/* no action */
		break;
	}
}

unsigned int ospf6_auth_len_get(struct ospf6_interface *oi)
{
	unsigned int at_len = 0;
	char *keychain_name = NULL;
	struct keychain *keychain = NULL;
	struct key *key = NULL;

	if (CHECK_FLAG(oi->at_cfg.flags, OSPF6_AUTH_TRAILER_KEYCHAIN)) {
		if (CHECK_FLAG(oi->at_cfg.flags,
			       OSPF6_AUTH_TRAILER_KEYCHAIN_VALID)) {
			at_len = OSPF6_AUTH_HDR_MIN_SIZE
				 + keychain_get_hash_len(oi->at_cfg.hash_algo);
		} else {
			keychain_name = oi->at_cfg.keychain;
			keychain = keychain_lookup(keychain_name);
			if (keychain) {
				key = key_lookup_for_send(keychain);
				if (key && key->string
				    && key->hash_algo != KEYCHAIN_ALGO_NULL) {
					at_len = OSPF6_AUTH_HDR_MIN_SIZE
						 + keychain_get_hash_len(
							   key->hash_algo);
				}
			}
		}
	} else if (CHECK_FLAG(oi->at_cfg.flags,
			      OSPF6_AUTH_TRAILER_MANUAL_KEY)) {
		at_len = OSPF6_AUTH_HDR_MIN_SIZE
			 + keychain_get_hash_len(oi->at_cfg.hash_algo);
	}

	return at_len;
}

int ospf6_auth_validate_pkt(struct ospf6_interface *oi, unsigned int *pkt_len,
			    struct ospf6_header *oh, unsigned int *at_len)
{
	struct ospf6_hello *hello = NULL;
	struct ospf6_dbdesc *dbdesc = NULL;
	struct ospf6_neighbor *on = NULL;
	struct ospf6_auth_hdr ospf6_auth_info;
	uint16_t hdr_len = 0;
	uint32_t oh_seqnum_h = 0;
	uint32_t oh_seqnum_l = 0;

	on = ospf6_neighbor_lookup(oh->router_id, oi);
	hdr_len = ntohs(oh->length);
	if (*pkt_len < hdr_len) {
		if (IS_OSPF6_DEBUG_AUTH_RX)
			zlog_warn("RECV[%s] Wrong %s packet auth length",
				  oi->interface->name,
				  lookup_msg(ospf6_message_type_str, oh->type,
					     NULL));
		oi->at_cfg.rx_drop++;
		return -1;
	} else if (*pkt_len == hdr_len) {
		/* no auth data in packet
		 */
		return -1;
	}

	switch (oh->type) {
	case OSPF6_MESSAGE_TYPE_HELLO:
		hello = (struct ospf6_hello *)((uint8_t *)oh
					       + sizeof(struct ospf6_header));
		if (OSPF6_OPT_ISSET_EXT(hello->options, OSPF6_OPT_AT)) {
			if (on)
				on->auth_present = true;
		} else {
			if (on)
				on->auth_present = false;

			if (oi->at_cfg.flags != 0) {
				if (IS_OSPF6_DEBUG_AUTH_RX)
					zlog_warn("RECV[%s] : Auth option miss-match in hello pkt",
						  oi->interface->name);
				oi->at_cfg.rx_drop++;
			}

			return -1;
		}
		break;
	case OSPF6_MESSAGE_TYPE_DBDESC:
		dbdesc = (struct ospf6_dbdesc *)((uint8_t *)oh
						 + sizeof(struct ospf6_header));

		if (OSPF6_OPT_ISSET_EXT(dbdesc->options, OSPF6_OPT_AT)) {
			if (on)
				on->auth_present = true;
		} else {
			if (on)
				on->auth_present = false;

			if (oi->at_cfg.flags != 0) {
				if (IS_OSPF6_DEBUG_AUTH_RX)
					zlog_warn("RECV[%s] : Auth option miss-match in DB desc pkt",
						  oi->interface->name);
				oi->at_cfg.rx_drop++;
			}

			return -1;
		}
		break;
	case OSPF6_MESSAGE_TYPE_LSREQ:
	case OSPF6_MESSAGE_TYPE_LSUPDATE:
	case OSPF6_MESSAGE_TYPE_LSACK:
		if ((on && on->auth_present == false)
		    && (oi->at_cfg.flags != 0)) {
			if (IS_OSPF6_DEBUG_AUTH_RX)
				zlog_warn("RECV[%s] : Auth config miss-match in %s",
					  oi->interface->name,
					  lookup_msg(ospf6_message_type_str,
						     oh->type, NULL));
			oi->at_cfg.rx_drop++;
			return -1;
		}
		break;
	default:
		if (IS_OSPF6_DEBUG_AUTH_RX)
			zlog_warn("RECV[%s] : Wrong packet type %d",
				  oi->interface->name, oh->type);
		return -1;
	}

	memset(&ospf6_auth_info, 0, sizeof(struct ospf6_auth_hdr));
	memcpy(&ospf6_auth_info, (uint8_t *)oh + hdr_len, *pkt_len - hdr_len);
	if (ntohs(ospf6_auth_info.length) > OSPF6_AUTH_HDR_FULL) {
		if (IS_OSPF6_DEBUG_AUTH_RX)
			zlog_warn("RECV[%s] : Auth config miss-match in %s",
				  oi->interface->name,
				  lookup_msg(ospf6_message_type_str, oh->type,
					     NULL));
		oi->at_cfg.rx_drop++;
		return -1;
	}

	/* after authentication header validation is done
	 * reduce the auth hdr size from the packet length
	 */
	*at_len = ntohs(ospf6_auth_info.length);
	*pkt_len = *pkt_len - *at_len;

	if (on) {
		oh_seqnum_h = ntohl(ospf6_auth_info.seqnum_h);
		oh_seqnum_l = ntohl(ospf6_auth_info.seqnum_l);
		if ((oh_seqnum_h >= on->seqnum_h) &&
		     (oh_seqnum_l > on->seqnum_l)) {
			/* valid sequence number received */
			on->seqnum_h = oh_seqnum_h;
			on->seqnum_l = oh_seqnum_l;
		} else {
			if (IS_OSPF6_DEBUG_AUTH_RX) {
				zlog_warn("RECV[%s] : Nbr(%s) Auth Sequence number mismatch",
					  oi->interface->name, on->name);
				zlog_warn("nbr_seq_l %u, nbr_seq_h %u, hdr_seq_l %u, hdr_seq_h %u",
					  on->seqnum_l, on->seqnum_h,
					  oh_seqnum_l, oh_seqnum_h);
			}

			oi->at_cfg.rx_drop++;
			return -1;
		}
	}

	return 0;
}

/* Starting point of packet process function. */
int ospf6_auth_check_digest(struct ospf6_header *oh, struct ospf6_interface *oi,
			    struct in6_addr *src)
{
	uint32_t hash_len = KEYCHAIN_MAX_HASH_SIZE;
	unsigned char apad[hash_len];
	unsigned char temp_hash[hash_len];
	struct ospf6_auth_hdr *ospf6_auth;
	uint32_t ipv6_addr_size = sizeof(struct in6_addr);
	struct keychain *keychain = NULL;
	struct key *key = NULL;
	char *auth_str = NULL;
	uint16_t auth_len = 0;
	uint8_t hash_algo = 0;
	uint16_t oh_len = ntohs(oh->length);

	if (oi->at_cfg.flags == 0)
		return -2;

	ospf6_auth = (struct ospf6_auth_hdr *)((uint8_t *)oh + oh_len);
	if (CHECK_FLAG(oi->at_cfg.flags, OSPF6_AUTH_TRAILER_KEYCHAIN)) {
		keychain = keychain_lookup(oi->at_cfg.keychain);
		if (!keychain) {
			if (IS_OSPF6_DEBUG_AUTH_RX)
				zlog_warn("RECV[%s]: Keychain does't exist for %s",
					  oi->interface->name,
					  lookup_msg(ospf6_message_type_str,
						     oh->type, NULL));
			oi->at_cfg.rx_drop++;
			return -1;
		}

		key = key_lookup_for_accept(keychain, ntohs(ospf6_auth->id));
		if (!key) {
			if (IS_OSPF6_DEBUG_AUTH_RX)
				zlog_warn("RECV[%s]: Auth, Invalid SA for %s",
					  oi->interface->name,
					  lookup_msg(ospf6_message_type_str,
						     oh->type, NULL));
			oi->at_cfg.rx_drop++;
			return -1;
		}

		if (key && key->string
		    && key->hash_algo != KEYCHAIN_ALGO_NULL) {
			auth_str = key->string;
			hash_algo = key->hash_algo;
		} else {
			if (IS_OSPF6_DEBUG_AUTH_RX)
				zlog_warn("RECV[%s]: Incomplete keychain config for %s",
					  oi->interface->name,
					  lookup_msg(ospf6_message_type_str,
						     oh->type, NULL));
			oi->at_cfg.rx_drop++;
			return -1;
		}
	} else if (CHECK_FLAG(oi->at_cfg.flags,
			      OSPF6_AUTH_TRAILER_MANUAL_KEY)) {
		auth_str = oi->at_cfg.auth_key;
		hash_algo = oi->at_cfg.hash_algo;
	}

	hash_len = keychain_get_hash_len(hash_algo);
	memset(apad, 0, sizeof(hash_len));
	memset(temp_hash, 0, sizeof(hash_len));

	/* start digest verification */
	memcpy(apad, src, ipv6_addr_size);
	memcpy(apad + ipv6_addr_size, ospf6_hash_apad_max,
	       (hash_len - ipv6_addr_size));

	auth_len = ntohs(ospf6_auth->length);

	memcpy(temp_hash, ospf6_auth->data, hash_len);
	memcpy(ospf6_auth->data, apad, hash_len);

	ospf6_auth_update_digest(oi, oh, ospf6_auth, auth_str, auth_len,
				 (oh_len + auth_len), hash_algo);

	return !(memcmp(temp_hash, ospf6_auth->data, hash_len));
}

void ospf6_auth_digest_send(struct in6_addr *src, struct ospf6_interface *oi,
			    struct ospf6_header *oh, uint16_t auth_len,
			    uint32_t pkt_len)
{
	struct ospf6_auth_hdr *ospf6_auth;
	char *keychain_name = NULL;
	struct keychain *keychain = NULL;
	struct key *key = NULL;
	char *auth_str = NULL;
	uint16_t key_id = 0;
	enum keychain_hash_algo hash_algo = KEYCHAIN_ALGO_NULL;
	uint32_t hash_len = KEYCHAIN_MAX_HASH_SIZE;
	unsigned char apad[hash_len];
	int ipv6_addr_size = sizeof(struct in6_addr);

	if (CHECK_FLAG(oi->at_cfg.flags, OSPF6_AUTH_TRAILER_KEYCHAIN)) {
		if (CHECK_FLAG(oi->at_cfg.flags,
			       OSPF6_AUTH_TRAILER_KEYCHAIN_VALID)) {
			auth_str = oi->at_cfg.auth_key;
			hash_algo = oi->at_cfg.hash_algo;
			key_id = oi->at_cfg.key_id;
		} else {
			keychain_name = oi->at_cfg.keychain;
			keychain = keychain_lookup(keychain_name);
			if (keychain) {
				key = key_lookup_for_send(keychain);
				if (key && key->string
				    && key->hash_algo != KEYCHAIN_ALGO_NULL) {
					auth_str = key->string;
					hash_algo = key->hash_algo;
					key_id = key->index;
				}
			}
		}
	} else if (CHECK_FLAG(oi->at_cfg.flags,
			      OSPF6_AUTH_TRAILER_MANUAL_KEY)) {
		auth_str = oi->at_cfg.auth_key;
		hash_algo = oi->at_cfg.hash_algo;
		key_id = oi->at_cfg.key_id;
	} else {
		if (IS_OSPF6_DEBUG_AUTH_TX)
			zlog_warn("SEND[%s]: Authentication not configured for %s",
				  oi->interface->name,
				  lookup_msg(ospf6_message_type_str,
					     oh->type, NULL));
		return;
	}

	hash_len = keychain_get_hash_len(hash_algo);
	oi->at_cfg.seqnum_l++;

	if (oi->at_cfg.seqnum_l == 0xFFFFFFFF) {
		oi->at_cfg.seqnum_h++;
		oi->at_cfg.seqnum_l = 0;
	}

	/* Key must be reset. which is not handled as of now. */
	if ((oi->at_cfg.seqnum_l == 0xFFFFFFFF)
	    && (oi->at_cfg.seqnum_h == 0xFFFFFFFF)) {
		oi->at_cfg.seqnum_l = 0;
		oi->at_cfg.seqnum_h = 0;
	}

	memset(apad, 0, hash_len);

	if (src)
		memcpy(apad, src, ipv6_addr_size);

	memcpy(apad + ipv6_addr_size, ospf6_hash_apad_max,
	       (hash_len - ipv6_addr_size));

	ospf6_auth =
		(struct ospf6_auth_hdr *)((uint8_t *)oh + ntohs(oh->length));
	ospf6_auth->type = htons(OSPF6_AUTHENTICATION_CRYPTOGRAPHIC);
	ospf6_auth->length = htons(auth_len);
	ospf6_auth->reserved = 0;
	ospf6_auth->id = htons(key_id);
	ospf6_auth->seqnum_h = htonl(oi->at_cfg.seqnum_h);
	ospf6_auth->seqnum_l = htonl(oi->at_cfg.seqnum_l);
	memcpy(ospf6_auth->data, apad, hash_len);

	ospf6_auth_update_digest(oi, oh, ospf6_auth, auth_str, auth_len,
				 pkt_len, hash_algo);

	if (CHECK_FLAG(oi->at_cfg.flags, OSPF6_AUTH_TRAILER_KEYCHAIN_VALID)) {
		oi->at_cfg.hash_algo = KEYCHAIN_ALGO_NULL;
		if (oi->at_cfg.auth_key) {
			XFREE(MTYPE_OSPF6_AUTH_MANUAL_KEY, oi->at_cfg.auth_key);
			oi->at_cfg.auth_key = NULL;
		}

		oi->at_cfg.key_id = 0;
		UNSET_FLAG(oi->at_cfg.flags, OSPF6_AUTH_TRAILER_KEYCHAIN_VALID);
	}
}

void ospf6_auth_update_digest(struct ospf6_interface *oi,
			      struct ospf6_header *oh,
			      struct ospf6_auth_hdr *ospf6_auth, char *auth_str,
			      uint16_t auth_len, uint32_t pkt_len,
			      enum keychain_hash_algo algo)
{
	uint32_t hash_len = keychain_get_hash_len(algo);
	uint32_t block_s = keychain_get_block_size(algo);
	uint32_t k_len = strlen(auth_str);
	uint32_t ks_len = strlen(auth_str) + sizeof(CPID);
	unsigned char ipad[block_s];
	unsigned char opad[block_s];
	unsigned char ko[block_s], ks[ks_len], tmp[hash_len];
	unsigned char *first = NULL;
	unsigned char *second = NULL;
	unsigned char *first_mes, *second_mes;
	unsigned char *first_hash, *second_hash;

	memset(ko, 0, block_s);
	memcpy(ks, auth_str, k_len);
	memcpy(ks + k_len, &CPID, sizeof(CPID));
	if (ks_len > hash_len) {
		ospf6_hash_hmac_sha_digest(algo, ks, ks_len, tmp);
		memcpy(ko, tmp, hash_len);
	} else
		memcpy(ko, ks, ks_len);

	memcpy(ipad, ospf6_hash_ipad_max, block_s);
	memcpy(opad, ospf6_hash_opad_max, block_s);

	first = ospf6_hash_message_xor((unsigned char *)&ipad, ko, block_s);
	second = ospf6_hash_message_xor((unsigned char *)&opad, ko, block_s);

	first_mes = XMALLOC(MTYPE_OSPF6_AUTH_PKT, (block_s + pkt_len));
	if (first_mes == NULL) {
		XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, first);
		XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, second);
		zlog_err("Memory allocation for first message failed.");
		return;
	}

	memcpy(first_mes, first, block_s);
	memcpy(first_mes + block_s, oh, pkt_len);

	first_hash = XMALLOC(MTYPE_OSPF6_AUTH_HASH, hash_len);
	if (first_hash == NULL) {
		XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, first);
		XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, second);
		XFREE(MTYPE_OSPF6_AUTH_PKT, first_mes);
		zlog_err("Memory allocation for first hash failed.");
		return;
	}

	ospf6_hash_hmac_sha_digest(algo, first_mes, (block_s + pkt_len),
				   first_hash);

	second_mes = XMALLOC(MTYPE_OSPF6_AUTH_PKT, (block_s + hash_len));
	if (second_mes == NULL) {
		XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, first);
		XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, second);
		XFREE(MTYPE_OSPF6_AUTH_PKT, first_mes);
		XFREE(MTYPE_OSPF6_AUTH_HASH, first_hash);
		zlog_err("Memory allocation for second message failed.");
		return;
	}

	memcpy(second_mes, second, block_s);
	memcpy(second_mes + block_s, first_hash, hash_len);

	second_hash = XMALLOC(MTYPE_OSPF6_AUTH_HASH, hash_len);
	if (second_hash == NULL) {
		XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, first);
		XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, second);
		XFREE(MTYPE_OSPF6_AUTH_PKT, first_mes);
		XFREE(MTYPE_OSPF6_AUTH_HASH, first_hash);
		XFREE(MTYPE_OSPF6_AUTH_PKT, second_mes);
		zlog_err("Memory allocation for second hash failed.");
		return;
	}

	ospf6_hash_hmac_sha_digest(algo, second_mes, (block_s + hash_len),
				   second_hash);

	memcpy(ospf6_auth->data, second_hash, hash_len);
	XFREE(MTYPE_OSPF6_AUTH_PKT, first_mes);
	XFREE(MTYPE_OSPF6_AUTH_PKT, second_mes);
	XFREE(MTYPE_OSPF6_AUTH_HASH, first_hash);
	XFREE(MTYPE_OSPF6_AUTH_HASH, second_hash);
	XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, first);
	XFREE(MTYPE_OSPF6_AUTH_HASH_XOR, second);
}

DEFUN (debug_ospf6_auth,
       debug_ospf6_auth_cmd,
       "debug ospf6 authentication [<tx|rx>]",
       DEBUG_STR
       OSPF6_STR
       "debug OSPF6 authentication\n"
       "debug authentication tx\n"
       "debug authentication rx\n")
{
	int auth_opt_idx = 3;

	if (argc == 4) {
		if (!strncmp(argv[auth_opt_idx]->arg, "t", 1))
			OSPF6_DEBUG_AUTH_TX_ON();
		else if (!strncmp(argv[auth_opt_idx]->arg, "r", 1))
			OSPF6_DEBUG_AUTH_RX_ON();
	} else {
		OSPF6_DEBUG_AUTH_TX_ON();
		OSPF6_DEBUG_AUTH_RX_ON();
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_auth,
       no_debug_ospf6_auth_cmd,
       "no debug ospf6 authentication [<tx|rx>]",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "debug OSPF6 authentication\n"
       "debug authentication tx\n"
       "debug authentication rx\n")
{
	int auth_opt_idx = 3;

	if (argc == 5) {
		if (!strncmp(argv[auth_opt_idx]->arg, "t", 1))
			OSPF6_DEBUG_AUTH_TX_OFF();
		else if (!strncmp(argv[auth_opt_idx]->arg, "r", 1))
			OSPF6_DEBUG_AUTH_RX_OFF();
	} else {
		OSPF6_DEBUG_AUTH_TX_OFF();
		OSPF6_DEBUG_AUTH_RX_OFF();
	}

	return CMD_SUCCESS;
}

int config_write_ospf6_debug_auth(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_AUTH_TX)
		vty_out(vty, "debug ospf6 authentication tx\n");
	if (IS_OSPF6_DEBUG_AUTH_RX)
		vty_out(vty, "debug ospf6 authentication rx\n");
	return 0;
}

void install_element_ospf6_debug_auth(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_auth_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_auth_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_auth_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_auth_cmd);
}

/* Clear the specified interface structure */
static void ospf6_intf_auth_clear(struct vty *vty, struct interface *ifp)
{
	struct ospf6_interface *oi;

	if (!if_is_operative(ifp))
		return;

	if (ifp->info == NULL)
		return;

	oi = (struct ospf6_interface *)ifp->info;

	if (IS_OSPF6_DEBUG_INTERFACE)
		zlog_debug(
			"Interface %s: clear authentication rx/tx drop counters",
			ifp->name);

	/* Reset the interface rx/tx drop counters */
	oi->at_cfg.tx_drop = 0;
	oi->at_cfg.rx_drop = 0;
}

/* Clear interface */
DEFUN(clear_ipv6_ospf6_intf_auth,
      clear_ipv6_ospf6_intf_auth_cmd,
      "clear ipv6 ospf6 auth-counters interface [IFNAME]",
      CLEAR_STR
      IP6_STR
      OSPF6_STR
      "authentication rx/tx drop counters\n"
      INTERFACE_STR
      IFNAME_STR)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	int idx_ifname = 5;
	struct interface *ifp;

	if (argc == 5) { /* Clear all the ospfv3 interfaces. */
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf6_intf_auth_clear(vty, ifp);
	} else { /* Interface name is specified. */
		ifp = if_lookup_by_name(argv[idx_ifname]->arg, VRF_DEFAULT);
		if (ifp  == NULL) {
			vty_out(vty, "Error: No such Interface: %s\n",
				argv[idx_ifname]->arg);
			return CMD_WARNING;
		}
		ospf6_intf_auth_clear(vty, ifp);
	}

	return CMD_SUCCESS;
}

void install_element_ospf6_clear_intf_auth(void)
{
	install_element(ENABLE_NODE, &clear_ipv6_ospf6_intf_auth_cmd);
}
