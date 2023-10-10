// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 Amnesh Inc.
 *                    Mahdi Varasteh
 */

#include <zebra.h>

#include "linklist.h"
#include "if.h"
#include "checksum.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_auth.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_gr.h"
#ifdef CRYPTO_INTERNAL
#include "sha256.h"
#include "md5.h"
#endif

const uint8_t ospf_auth_apad[KEYCHAIN_MAX_HASH_SIZE] = {
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1,
	0xF3, 0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F,
	0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3, 0x87,
	0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1,
	0xF3, 0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3
};

static int ospf_check_sum(struct ospf_header *ospfh)
{
	uint32_t ret;
	uint16_t sum;

	/* clear auth_data for checksum. */
	memset(ospfh->u.auth_data, 0, OSPF_AUTH_SIMPLE_SIZE);

	/* keep checksum and clear. */
	sum = ospfh->checksum;
	memset(&ospfh->checksum, 0, sizeof(uint16_t));

	/* calculate checksum. */
	ret = in_cksum(ospfh, ntohs(ospfh->length));

	if (ret != sum) {
		zlog_info("%s: checksum mismatch, my %X, his %X", __func__, ret,
			  sum);
		return 0;
	}

	return 1;
}

#ifdef CRYPTO_OPENSSL
static const EVP_MD *ospf_auth_get_openssl_evp_md_from_key(struct key *key)
{
	if (key->hash_algo == KEYCHAIN_ALGO_HMAC_SHA1)
		return EVP_get_digestbyname("sha1");
	else if (key->hash_algo == KEYCHAIN_ALGO_HMAC_SHA256)
		return EVP_get_digestbyname("sha256");
	else if (key->hash_algo == KEYCHAIN_ALGO_HMAC_SHA384)
		return EVP_get_digestbyname("sha384");
	else if (key->hash_algo == KEYCHAIN_ALGO_HMAC_SHA512)
		return EVP_get_digestbyname("sha512");
	return NULL;
}
#endif

static int ospf_auth_check_hmac_sha_digest(struct ospf_interface *oi,
					   struct ospf_header *ospfh,
					   struct ip *iph,
					   struct key *key)
{
	unsigned char digest[KEYCHAIN_MAX_HASH_SIZE];
	struct ospf_neighbor *nbr;
	uint16_t length = ntohs(ospfh->length);
	uint16_t hash_length = keychain_get_hash_len(key->hash_algo);
#ifdef CRYPTO_OPENSSL
	uint32_t openssl_hash_length = hash_length;
	HMAC_CTX *ctx;
	const EVP_MD *md_alg = ospf_auth_get_openssl_evp_md_from_key(key);

	if (!md_alg) {
		flog_warn(EC_OSPF_AUTH,
			  "interface %s: invalid HMAC algorithm, Router-ID: %pI4",
			  IF_NAME(oi), &ospfh->router_id);
		return 0;
	}
#elif CRYPTO_INTERNAL
	HMAC_SHA256_CTX ctx;

	if (key->hash_algo != KEYCHAIN_ALGO_HMAC_SHA256) {
		flog_warn(EC_OSPF_AUTH,
			  "interface %s: HMAC algorithm not supported, Router-ID: %pI4",
			  IF_NAME(oi), &ospfh->router_id);
		return 0;
	}
#endif
	/* check crypto seqnum. */
	nbr = ospf_nbr_lookup(oi, iph, ospfh);

	if (nbr &&
	    ntohl(nbr->crypt_seqnum) > ntohl(ospfh->u.crypt.crypt_seqnum)) {
		flog_warn(EC_OSPF_AUTH,
			  "interface %s: ospf_check_hmac_sha bad sequence %u (expect %d), Router-ID: %pI4",
			  IF_NAME(oi), ntohl(ospfh->u.crypt.crypt_seqnum),
			  ntohl(nbr->crypt_seqnum), &ospfh->router_id);
		return 0;
	}
#ifdef CRYPTO_OPENSSL
	ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key->string, strlen(key->string), md_alg, NULL);
	HMAC_Update(ctx, (const unsigned char *)ospfh, length);
	HMAC_Update(ctx, (const unsigned char *)ospf_auth_apad, hash_length);
	HMAC_Final(ctx, digest, &openssl_hash_length);
	HMAC_CTX_free(ctx);
#elif CRYPTO_INTERNAL
	memset(&ctx, 0, sizeof(ctx));
	HMAC__SHA256_Init(&ctx, key->string, strlen(key->string));
	HMAC__SHA256_Update(&ctx, ospfh, length);
	HMAC__SHA256_Update(&ctx, ospf_auth_apad, hash_length);
	HMAC__SHA256_Final(digest, &ctx);
#endif
	if (memcmp((caddr_t)ospfh + length, digest, hash_length)) {
		flog_warn(EC_OSPF_AUTH,
			  "interface %s: ospf_check_hmac_sha checksum mismatch %u, Router-ID: %pI4",
			  IF_NAME(oi), length, &ospfh->router_id);
		return 0;
	}
	if (nbr)
		nbr->crypt_seqnum = ospfh->u.crypt.crypt_seqnum;
	return 1;
}

static int ospf_auth_check_md5_digest(struct ospf_interface *oi,
				      struct ospf_header *ospfh, struct ip *iph, struct key *key)
{
#ifdef CRYPTO_OPENSSL
	EVP_MD_CTX *ctx;
#elif CRYPTO_INTERNAL
	MD5_CTX ctx;
#endif
	char auth_key[OSPF_AUTH_MD5_SIZE + 1];
	unsigned char digest[OSPF_AUTH_MD5_SIZE];
	struct ospf_neighbor *nbr;
	struct crypt_key *ck = NULL;
	uint16_t length = ntohs(ospfh->length);

	if (length < sizeof(struct ospf_header)) {/* for coverity's sake */
		flog_warn(EC_OSPF_AUTH,
			  "%s: Invalid packet length of %u received on interface %s, Router-ID: %pI4",
			  __func__, length, IF_NAME(oi), &ospfh->router_id);
		return 0;
	}

	if (key == NULL) {
		ck = ospf_crypt_key_lookup(OSPF_IF_PARAM(oi, auth_crypt),
				   ospfh->u.crypt.key_id);
		if (ck == NULL) {
			flog_warn(
				EC_OSPF_AUTH,
				"interface %s: %s no key %d, Router-ID: %pI4",
				IF_NAME(oi), __func__, ospfh->u.crypt.key_id, &ospfh->router_id);
			return 0;
		}
	}
	/* check crypto seqnum. */
	nbr = ospf_nbr_lookup(oi, iph, ospfh);

	if (nbr &&
	    ntohl(nbr->crypt_seqnum) > ntohl(ospfh->u.crypt.crypt_seqnum)) {
		flog_warn(EC_OSPF_AUTH,
			  "interface %s: %s bad sequence %d (expect %d), Router-ID: %pI4",
			  IF_NAME(oi), __func__, ntohl(ospfh->u.crypt.crypt_seqnum),
			  ntohl(nbr->crypt_seqnum), &ospfh->router_id);
		return 0;
	}

	memset(auth_key, 0, OSPF_AUTH_MD5_SIZE + 1);
	if (ck == NULL)
		strlcpy(auth_key, key->string, OSPF_AUTH_MD5_SIZE + 1);
	else
		strlcpy(auth_key, (char *)ck->auth_key, OSPF_AUTH_MD5_SIZE + 1);
	/* Generate a digest for the ospf packet - their digest + our digest. */
#ifdef CRYPTO_OPENSSL
	uint32_t md5_size = OSPF_AUTH_MD5_SIZE;

	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_md5());
	EVP_DigestUpdate(ctx, ospfh, length);
	EVP_DigestUpdate(ctx, auth_key, OSPF_AUTH_MD5_SIZE);
	EVP_DigestFinal(ctx, digest, &md5_size);
	EVP_MD_CTX_free(ctx);
#elif CRYPTO_INTERNAL
	memset(&ctx, 0, sizeof(ctx));
	MD5Init(&ctx);
	MD5Update(&ctx, ospfh, length);
	MD5Update(&ctx, auth_key, OSPF_AUTH_MD5_SIZE);
	MD5Final(digest, &ctx);
#endif

	/* compare the two */
	if (memcmp((caddr_t)ospfh + length, digest, OSPF_AUTH_MD5_SIZE)) {
		flog_warn(EC_OSPF_AUTH,
			  "interface %s: ospf_check_md5 checksum mismatch, Router-ID: %pI4",
			  IF_NAME(oi), &ospfh->router_id);
		return 0;
	}

	/* save neighbor's crypt_seqnum */
	if (nbr)
		nbr->crypt_seqnum = ospfh->u.crypt.crypt_seqnum;
	return 1;
}

static int ospf_auth_make_md5_digest(struct ospf_interface *oi,
				     struct ospf_packet *op, struct key *key)
{
	void *ibuf = STREAM_DATA(op->s);
	struct ospf_header *ospfh = (struct ospf_header *)ibuf;
	unsigned char digest[OSPF_AUTH_MD5_SIZE];
	uint16_t length = ntohs(ospfh->length);
#ifdef CRYPTO_OPENSSL
	EVP_MD_CTX *ctx;
#elif CRYPTO_INTERNAL
	MD5_CTX ctx;
#endif
	char auth_key[OSPF_AUTH_MD5_SIZE + 1];

	if ((length < (sizeof(struct ospf_header))) || (length > op->length)) { /* for coverity's sake */
		flog_warn(EC_OSPF_AUTH,
			  "%s: Invalid packet length of %u received on interface %s, Router-ID: %pI4",
			  __func__, length, IF_NAME(oi), &ospfh->router_id);
		return 0;
	}

	memset(auth_key, 0, OSPF_AUTH_MD5_SIZE + 1);
	strlcpy(auth_key, key->string, OSPF_AUTH_MD5_SIZE + 1);
	/* Generate a digest for the ospf packet - their digest + our digest. */
#ifdef CRYPTO_OPENSSL
	uint32_t md5_size = OSPF_AUTH_MD5_SIZE;

	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_md5());
	EVP_DigestUpdate(ctx, ospfh, length);
	EVP_DigestUpdate(ctx, auth_key, OSPF_AUTH_MD5_SIZE);
	EVP_DigestFinal(ctx, digest, &md5_size);
	EVP_MD_CTX_free(ctx);
#elif CRYPTO_INTERNAL
	memset(&ctx, 0, sizeof(ctx));
	MD5Init(&ctx);
	MD5Update(&ctx, ospfh, length);
	MD5Update(&ctx, auth_key, OSPF_AUTH_MD5_SIZE);
	MD5Final(digest, &ctx);
#endif

	stream_put(op->s, digest, OSPF_AUTH_MD5_SIZE);

	op->length = ntohs(ospfh->length) + OSPF_AUTH_MD5_SIZE;

	if (stream_get_endp(op->s) != op->length)
		/* XXX size_t */
		flog_warn(EC_OSPF_AUTH,
			  "%s: length mismatch stream %lu ospf_packet %u, Router-ID %pI4",
			  __func__, (unsigned long)stream_get_endp(op->s),
			  op->length, &ospfh->router_id);

	return OSPF_AUTH_MD5_SIZE;
}

static int ospf_auth_make_hmac_sha_digest(struct ospf_interface *oi,
					  struct ospf_packet *op,
					  struct key *key)
{
	void *ibuf;
	struct ospf_header *ospfh;
	unsigned char digest[KEYCHAIN_MAX_HASH_SIZE] = { 0 };
	uint16_t hash_length = keychain_get_hash_len(key->hash_algo);

	ibuf = STREAM_DATA(op->s);
	ospfh = (struct ospf_header *)ibuf;
#ifdef CRYPTO_OPENSSL
	uint32_t openssl_hash_length = hash_length;
	HMAC_CTX *ctx;
	const EVP_MD *md_alg = ospf_auth_get_openssl_evp_md_from_key(key);

	if (!md_alg) {
		flog_warn(EC_OSPF_AUTH,
			  "interface %s: invalid HMAC algorithm, Router-ID: %pI4",
			  IF_NAME(oi), &ospfh->router_id);
		return 0;
	}
#elif CRYPTO_INTERNAL
	HMAC_SHA256_CTX ctx;

	if (key->hash_algo != KEYCHAIN_ALGO_HMAC_SHA256) {
		flog_warn(EC_OSPF_AUTH,
			  "interface %s: HMAC algorithm not supported, Router-ID: %pI4",
			  IF_NAME(oi), &ospfh->router_id);
		return 0;
	}
#endif
#ifdef CRYPTO_OPENSSL
	ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key->string, strlen(key->string), md_alg, NULL);
	HMAC_Update(ctx, (const unsigned char *)ospfh, ntohs(ospfh->length));
	HMAC_Update(ctx, (const unsigned char *)ospf_auth_apad, hash_length);
	HMAC_Final(ctx, digest, &openssl_hash_length);
	HMAC_CTX_free(ctx);
#elif CRYPTO_INTERNAL
	memset(&ctx, 0, sizeof(ctx));
	HMAC__SHA256_Init(&ctx, key->string, strlen(key->string));
	HMAC__SHA256_Update(&ctx, ospfh, ntohs(ospfh->length));
	HMAC__SHA256_Update(&ctx, ospf_auth_apad, hash_length);
	HMAC__SHA256_Final(digest, &ctx);
#endif
	stream_put(op->s, digest, hash_length);

	op->length = ntohs(ospfh->length) + hash_length;

	if (stream_get_endp(op->s) != op->length)
		/* XXX size_t */
		flog_warn(EC_OSPF_AUTH,
			  "%s: length mismatch stream %lu ospf_packet %u, Router-ID %pI4",
			  __func__, (unsigned long)stream_get_endp(op->s),
			  op->length, &ospfh->router_id);

	return hash_length;
}

int ospf_auth_check_digest(struct ospf_interface *oi, struct ip *iph, struct ospf_header *ospfh)
{
	struct keychain *keychain = NULL;
	struct key *key = NULL;
	int key_id = ospfh->u.crypt.key_id;
	uint8_t auth_data_len = ospfh->u.crypt.auth_data_len;

	if (!OSPF_IF_PARAM(oi, keychain_name))
		return ospf_auth_check_md5_digest(oi, ospfh, iph, NULL);

	keychain = keychain_lookup(OSPF_IF_PARAM(oi, keychain_name));
	if (!keychain) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
			flog_warn(EC_OSPF_AUTH,
				  "interface %s: Keychain %s is not available, Router-ID %pI4",
				  IF_NAME(oi), OSPF_IF_PARAM(oi, keychain_name),
				  &ospfh->router_id);
		return 0;
	}

	key = key_lookup_for_accept(keychain, key_id);
	if (!key) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
			flog_warn(EC_OSPF_AUTH,
				  "interface %s: Key ID %d not found in keychain %s, Router-ID %pI4",
				  IF_NAME(oi), key_id, keychain->name,
				  &ospfh->router_id);
		return 0;
	}

	if (key->string == NULL || key->hash_algo == KEYCHAIN_ALGO_NULL) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
			flog_warn(EC_OSPF_AUTH,
				  "interface %s: Key ID %d in keychain %s is incomplete, Router-ID %pI4",
				  IF_NAME(oi), key_id, keychain->name,
				  &ospfh->router_id);
		return 0;
	}

	if (keychain_get_hash_len(key->hash_algo) != auth_data_len) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
			flog_warn(EC_OSPF_AUTH,
				  "interface %s: Key ID %d in keychain %s hash length mismatch, Router-ID %pI4",
				  IF_NAME(oi), key_id, keychain->name,
				  &ospfh->router_id);
		return 0;
	}

	/* Backward compatibility with RFC 2328 keyed-MD5 authentication */
	if (key->hash_algo == KEYCHAIN_ALGO_MD5)
		return ospf_auth_check_md5_digest(oi, ospfh, iph, key);

	return ospf_auth_check_hmac_sha_digest(oi, ospfh, iph, key);
}

int ospf_auth_make_digest(struct ospf_interface *oi, struct ospf_packet *op)
{
	struct ospf_header *ospfh;
	void *ibuf;
	struct keychain *keychain = NULL;
	struct key *key = NULL;
	int key_id;

	ibuf = STREAM_DATA(op->s);
	ospfh = (struct ospf_header *)ibuf;

	key_id = ospfh->u.crypt.key_id;

	if (!OSPF_IF_PARAM(oi, keychain_name)) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
			flog_warn(EC_OSPF_AUTH,
				  "interface %s: Keychain is not set, Router-ID %pI4",
				  IF_NAME(oi), &ospfh->router_id);
		return 0;
	}

	keychain = oi->keychain;
	if (!keychain) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, SEND))
			flog_warn(EC_OSPF_AUTH,
				  "interface %s: Keychain %s is not available to send, Router-ID %pI4",
				  IF_NAME(oi), OSPF_IF_PARAM(oi, keychain_name),
				  &ospfh->router_id);
		return 0;
	}

	key = oi->key;
	if (!key) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, SEND))
			flog_warn(EC_OSPF_AUTH,
				  "interface %s: Key ID %d not found in keychain %s, Router-ID %pI4",
				  IF_NAME(oi), key_id, keychain->name,
				  &ospfh->router_id);
		return 0;
	}

	if (key->string == NULL || key->hash_algo == KEYCHAIN_ALGO_NULL) {
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, SEND))
			flog_warn(EC_OSPF_AUTH,
				  "interface %s: Key ID %d in keychain %s is incomplete, Router-ID %pI4",
				  IF_NAME(oi), key_id, keychain->name,
				  &ospfh->router_id);
		return 0;
	}

	/* Backward compatibility with RFC 2328 keyed-MD5 authentication */
	if (key->hash_algo == KEYCHAIN_ALGO_MD5)
		return ospf_auth_make_md5_digest(oi, op, key);
	else
		return ospf_auth_make_hmac_sha_digest(oi, op, key);
}

/* This function is called from ospf_write(), it will detect the
 * authentication scheme and if it is MD5, it will change the sequence
 * and update the MD5 digest.
 */

int ospf_auth_make(struct ospf_interface *oi, struct ospf_packet *op)
{
	struct ospf_header *ospfh;
	unsigned char digest[OSPF_AUTH_MD5_SIZE] = {0};
#ifdef CRYPTO_OPENSSL
	EVP_MD_CTX *ctx;
#elif CRYPTO_INTERNAL
	MD5_CTX ctx;
#endif
	void *ibuf;
	uint32_t t;
	struct crypt_key *ck;
	const uint8_t *auth_key = NULL;

	ibuf = STREAM_DATA(op->s);
	ospfh = (struct ospf_header *)ibuf;

	if (ntohs(ospfh->auth_type) != OSPF_AUTH_CRYPTOGRAPHIC)
		return 0;

	/* We do this here so when we dup a packet, we don't have to
	 * waste CPU rewriting other headers.

	   Note that frr_time /deliberately/ is not used here.
	*/
	t = (time(NULL) & 0xFFFFFFFF);
	if (t > oi->crypt_seqnum)
		oi->crypt_seqnum = t;
	else
		oi->crypt_seqnum++;

	ospfh->u.crypt.crypt_seqnum = htonl(oi->crypt_seqnum);

	/* Get MD5 Authentication key from auth_key list. */
	if (list_isempty(OSPF_IF_PARAM(oi, auth_crypt)) && OSPF_IF_PARAM(oi, keychain_name) == NULL)
		auth_key = (const uint8_t *)digest;
	else if (!list_isempty(OSPF_IF_PARAM(oi, auth_crypt))) {
		ck = listgetdata(listtail(OSPF_IF_PARAM(oi, auth_crypt)));
		auth_key = ck->auth_key;
	}

	if (auth_key) {
		/* Generate a digest for the entire packet + our secret key. */
#ifdef CRYPTO_OPENSSL
		uint32_t md5_size = OSPF_AUTH_MD5_SIZE;

		ctx = EVP_MD_CTX_new();
		EVP_DigestInit(ctx, EVP_md5());
		EVP_DigestUpdate(ctx, ibuf, ntohs(ospfh->length));
		EVP_DigestUpdate(ctx, auth_key, OSPF_AUTH_MD5_SIZE);
		EVP_DigestFinal(ctx, digest, &md5_size);
		EVP_MD_CTX_free(ctx);
#elif CRYPTO_INTERNAL
		memset(&ctx, 0, sizeof(ctx));
		MD5Init(&ctx);
		MD5Update(&ctx, ibuf, ntohs(ospfh->length));
		MD5Update(&ctx, auth_key, OSPF_AUTH_MD5_SIZE);
		MD5Final(digest, &ctx);
#endif

		/* Append md5 digest to the end of the stream. */
		stream_put(op->s, digest, OSPF_AUTH_MD5_SIZE);

		/* We do *NOT* increment the OSPF header length. */
		op->length = ntohs(ospfh->length) + OSPF_AUTH_MD5_SIZE;

		if (stream_get_endp(op->s) != op->length)
			/* XXX size_t */
			flog_warn(
				EC_OSPF_AUTH,
				"%s: length mismatch stream %lu ospf_packet %u, Router-ID %pI4",
				__func__, (unsigned long)stream_get_endp(op->s),
				op->length, &ospfh->router_id);

		return OSPF_AUTH_MD5_SIZE;
	} else
		return ospf_auth_make_digest(oi, op);
}

/* Return 1, if the packet is properly authenticated and checksummed,
 * 0 otherwise. In particular, check that AuType header field is valid and
 * matches the locally configured AuType, and that D.5 requirements are met.
 */
int ospf_auth_check(struct ospf_interface *oi, struct ip *iph,
			struct ospf_header *ospfh)
{
	uint16_t iface_auth_type;
	uint16_t pkt_auth_type = ntohs(ospfh->auth_type);

	iface_auth_type = ospf_auth_type(oi);

	switch (pkt_auth_type) {
	case OSPF_AUTH_NULL: /* RFC2328 D.5.1 */
		if (iface_auth_type != OSPF_AUTH_NULL) {
			if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
				flog_warn(
					EC_OSPF_PACKET,
					"interface %s: auth-type mismatch, local %s, rcvd Null, Router-ID %pI4",
					IF_NAME(oi),
					lookup_msg(ospf_auth_type_str,
						   iface_auth_type, NULL),
					&ospfh->router_id);
			return 0;
		}
		if (!ospf_check_sum(ospfh)) {
			if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
				flog_warn(
					EC_OSPF_PACKET,
					"interface %s: Null auth OK, but checksum error, Router-ID %pI4",
					IF_NAME(oi),
					&ospfh->router_id);
			return 0;
		}
		return 1;
	case OSPF_AUTH_SIMPLE: /* RFC2328 D.5.2 */
		if (iface_auth_type != OSPF_AUTH_SIMPLE) {
			if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
				flog_warn(
					EC_OSPF_PACKET,
					"interface %s: auth-type mismatch, local %s, rcvd Simple, Router-ID %pI4",
					IF_NAME(oi),
					lookup_msg(ospf_auth_type_str,
						   iface_auth_type, NULL),
					&ospfh->router_id);
			return 0;
		}
		if (memcmp(OSPF_IF_PARAM(oi, auth_simple), ospfh->u.auth_data,
			   OSPF_AUTH_SIMPLE_SIZE)) {
			if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
				flog_warn(
					EC_OSPF_PACKET,
					"interface %s: Simple auth failed, Router-ID %pI4",
					IF_NAME(oi), &ospfh->router_id);
			return 0;
		}
		if (!ospf_check_sum(ospfh)) {
			if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
				flog_warn(
					EC_OSPF_PACKET,
					"interface %s: Simple auth OK, checksum error, Router-ID %pI4",
					IF_NAME(oi),
					&ospfh->router_id);
			return 0;
		}
		return 1;
	case OSPF_AUTH_CRYPTOGRAPHIC: /* RFC2328 D.5.3 */
		if (iface_auth_type != OSPF_AUTH_CRYPTOGRAPHIC) {
			if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
				flog_warn(
					EC_OSPF_PACKET,
					"interface %s: auth-type mismatch, local %s, rcvd Cryptographic, Router-ID %pI4",
					IF_NAME(oi),
					lookup_msg(ospf_auth_type_str,
						   iface_auth_type, NULL),
					&ospfh->router_id);
			return 0;
		}
		if (ospfh->checksum) {
			if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
				flog_warn(
					EC_OSPF_PACKET,
					"interface %s: OSPF header checksum is not 0, Router-ID %pI4",
					IF_NAME(oi), &ospfh->router_id);
			return 0;
		}
		/* If `authentication message-digest` key is not set, we try keychain crypto */
		if (OSPF_IF_PARAM(oi, keychain_name) || !list_isempty(OSPF_IF_PARAM(oi, auth_crypt)))
			return ospf_auth_check_digest(oi, iph, ospfh);
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
			flog_warn(
				EC_OSPF_AUTH,
				"interface %s: MD5 auth failed, Router-ID %pI4",
				IF_NAME(oi), &ospfh->router_id);
		return 0;
	default:
		if (IS_DEBUG_OSPF_PACKET(ospfh->type - 1, RECV))
			flog_warn(
				EC_OSPF_PACKET,
				"interface %s: invalid packet auth-type (%02x), Router-ID %pI4",
				IF_NAME(oi), pkt_auth_type, &ospfh->router_id);
		return 0;
	}
}

/* OSPF authentication checking function */
int ospf_auth_type(struct ospf_interface *oi)
{
	int auth_type;

	if (OSPF_IF_PARAM(oi, auth_type) == OSPF_AUTH_NOTSET)
		auth_type = oi->area->auth_type;
	else
		auth_type = OSPF_IF_PARAM(oi, auth_type);

	/* Handle case where MD5 key list, or a key-chain, is not configured aka Cisco */
	if (auth_type == OSPF_AUTH_CRYPTOGRAPHIC
	    && (list_isempty(OSPF_IF_PARAM(oi, auth_crypt))
		&& OSPF_IF_PARAM(oi, keychain_name) == NULL))
		return OSPF_AUTH_NULL;

	return auth_type;
}

/* Make Authentication Data. */
int ospf_auth_make_data(struct ospf_interface *oi, struct ospf_header *ospfh)
{
	struct crypt_key *ck;

	switch (ospf_auth_type(oi)) {
	case OSPF_AUTH_NULL:
		/* memset (ospfh->u.auth_data, 0, sizeof(ospfh->u.auth_data));
		 */
		break;
	case OSPF_AUTH_SIMPLE:
		memcpy(ospfh->u.auth_data, OSPF_IF_PARAM(oi, auth_simple),
		       OSPF_AUTH_SIMPLE_SIZE);
		break;
	case OSPF_AUTH_CRYPTOGRAPHIC:
		if (OSPF_IF_PARAM(oi, keychain_name)) {
			oi->keychain = keychain_lookup(OSPF_IF_PARAM(oi, keychain_name));
			if (oi->keychain)
				oi->key = key_lookup_for_send(oi->keychain);
			if (oi->key) {
				ospfh->u.crypt.zero = 0;
				ospfh->u.crypt.key_id = oi->key->index;
				ospfh->u.crypt.auth_data_len = keychain_get_hash_len(oi->key->hash_algo);
			} else {
				/* If key is not set, then set 0. */
				ospfh->u.crypt.zero = 0;
				ospfh->u.crypt.key_id = 0;
				ospfh->u.crypt.auth_data_len = OSPF_AUTH_MD5_SIZE;
			}
		} else {
			/* If key is not set, then set 0. */
			if (list_isempty(OSPF_IF_PARAM(oi, auth_crypt))) {
				ospfh->u.crypt.zero = 0;
				ospfh->u.crypt.key_id = 0;
				ospfh->u.crypt.auth_data_len = OSPF_AUTH_MD5_SIZE;
			} else {
				ck = listgetdata(
					listtail(OSPF_IF_PARAM(oi, auth_crypt)));
				ospfh->u.crypt.zero = 0;
				ospfh->u.crypt.key_id = ck->key_id;
				ospfh->u.crypt.auth_data_len = OSPF_AUTH_MD5_SIZE;
			}
		}
		/* note: the seq is done in ospf_auth_make() */
		break;
	default:
		/* memset (ospfh->u.auth_data, 0, sizeof(ospfh->u.auth_data));
		 */
		break;
	}

	return 0;
}
