// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 5310 generic cryptographic authentication and the RFC 7602 Extended
 * Sequence Number TLV.
 *
 * The expected digests were computed independently with Python's hmac
 * module: HMAC over the PDU with the digest set to Apad (0x878FE1F3...) and,
 * for the LSP, the remaining lifetime and checksum set to zero.
 */
#include <zebra.h>

#include "keychain.h"
#include "memory.h"
#include "sbuf.h"
#include "stream.h"

#include "isisd/isis_circuit.h"
#include "isisd/isis_tlvs.h"

#include "test_common.h"

/* Any 27 bytes, with a non-zero remaining lifetime (offset 10) and checksum
 * (offset 24) for the LSP cases
 */
static const uint8_t pdu_header[27] = {
	0x83, 0x1b, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0xb0, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0xab, 0xcd, 0x03,
};

/* Offset of the digest: the header, the TLV header, the type and Key ID */
#define DIGEST_OFFSET (sizeof(pdu_header) + 2 + 1 + 2)

static struct keychain *keychain;

static struct key *add_key(uint32_t index, enum keychain_hash_algo algo, const char *string)
{
	struct key *key = key_get(keychain, index);

	key->hash_algo = algo;
	XFREE(MTYPE_KEY, key->string);
	if (string)
		key->string = XSTRDUP(MTYPE_KEY, string);
	return key;
}

static void clear_keys(void)
{
	struct listnode *node, *nnode;
	struct key *key;

	for (ALL_LIST_ELEMENTS(keychain->key, node, nnode, key))
		key_delete(keychain, key);
}

/* Whether the tests sign and verify with strict-rfc5310 */
static bool strict_rfc5310;

static struct isis_passwd passwd(const char *keychain_name)
{
	struct isis_passwd pw = { .type = ISIS_PASSWD_TYPE_CRYPTO_AUTH };

	pw.len = strlcpy((char *)pw.passwd, keychain_name, sizeof(pw.passwd));
	pw.strict_rfc5310 = strict_rfc5310;
	return pw;
}

/* The header and a hostname TLV, signed with the key chain */
static struct stream *sign(bool is_lsp)
{
	struct isis_passwd pw = passwd("kc");
	struct isis_tlvs *tlvs = isis_alloc_tlvs();
	struct stream *s = stream_new(1500);

	assert(isis_tlvs_add_auth(tlvs, &pw));
	isis_tlvs_set_dynamic_hostname(tlvs, "r1");
	stream_put(s, pdu_header, sizeof(pdu_header));
	assert(!isis_pack_tlvs(tlvs, s, (size_t)-1, false, is_lsp));
	isis_free_tlvs(tlvs);
	return s;
}

static int verify(struct stream *s, const char *keychain_name, bool is_lsp)
{
	struct isis_passwd pw = passwd(keychain_name);
	struct isis_tlvs *tlvs;
	const char *log;
	int rv;

	stream_set_getp(s, sizeof(pdu_header));
	assert(!isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log));
	rv = isis_tlvs_auth_is_valid(tlvs, &pw, s, is_lsp);
	isis_free_tlvs(tlvs);
	return rv;
}

static void hex2bin(const char *hex, uint8_t *bin, size_t len)
{
	for (size_t i = 0; i < len; i++)
		assert(sscanf(hex + 2 * i, "%2hhx", &bin[i]) == 1);
}

/* Sign with one key, check the digest, and verify the PDU */
static void test_digest(const char *name, enum keychain_hash_algo algo, const char *key,
			bool is_lsp, const char *expected)
{
	size_t hash_len = keychain_get_hash_len(algo);
	uint8_t want[KEYCHAIN_MAX_HASH_SIZE];
	struct stream *s;

	clear_keys();
	add_key(7, algo, key);
	s = sign(is_lsp);

	assert(strlen(expected) == 2 * hash_len);
	hex2bin(expected, want, hash_len);
	assert(stream_getw_from(s, DIGEST_OFFSET - 2) == 7);
	if (memcmp(STREAM_DATA(s) + DIGEST_OFFSET, want, hash_len)) {
		printf("%s: digest mismatch\n", name);
		zlog_hexdump(STREAM_DATA(s), stream_get_endp(s));
		assert(0);
	}
	/* signing an LSP must leave its lifetime and checksum in place */
	assert(!memcmp(STREAM_DATA(s), pdu_header, sizeof(pdu_header)));
	assert(verify(s, "kc", is_lsp) == ISIS_AUTH_OK);

	printf("%s: ok\n", name);
	stream_free(s);
}

static void test_digests(void)
{
	/* a key shorter than the hash */
	test_digest("hmac-sha-256, 4-byte key", KEYCHAIN_ALGO_HMAC_SHA256, "isis", false,
		    "2c055ae57cd8e41c680c10f5f31fcf2500449e318b9b3591c27bd83464da51f1");
	/* longer than the hash, not than the block: used as is, as plain HMAC
	 * and every implementation tested does, not hashed as RFC 5310 3.3 (1)
	 * reads
	 */
	test_digest("hmac-sha-256, 40-byte key", KEYCHAIN_ALGO_HMAC_SHA256,
		    "0123456789012345678901234567890123456789", false,
		    "f8529ebb6743efcf28e603f1ff6200d10a7c0f93ca2b45bb1436a912bab2d595");
	/* longer than the block: hashed */
	test_digest("hmac-sha-256, 100-byte key", KEYCHAIN_ALGO_HMAC_SHA256,
		    "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
		    false, "cfde3c67ecdfaaf020ebbacaae29dfaa29cad14a2aee2590ca3a14d4e7e0041d");
	/* an LSP: the digest covers zero lifetime and checksum */
	test_digest("hmac-sha-256, LSP", KEYCHAIN_ALGO_HMAC_SHA256, "isis", true,
		    "d372eba98376528228113eeae64b5949ac4fdfe3ccc584af8a374a74cce744ed");
#ifdef CRYPTO_OPENSSL
	test_digest("hmac-sha-1, 25-byte key", KEYCHAIN_ALGO_HMAC_SHA1,
		    "0123456789012345678901234", false, "c3d161562584d49b6a051244cbd3d4c1c1b9e86d");
	test_digest("hmac-sha-384, 100-byte key", KEYCHAIN_ALGO_HMAC_SHA384,
		    "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
		    false,
		    "0cb3c37cc05fc122b9f1019aa056b436316f684635d8eb88c75eb5788971de1a9adcc230c67b0fb54613cf834d4c070f");
	test_digest("hmac-sha-512, LSP", KEYCHAIN_ALGO_HMAC_SHA512, "isis", true,
		    "0f3b4e38e43236dd81857b8562b0031dc09efe265b84162c28b3f086d3cd04ddbde5e58f5b92c1d656f9df526dcc109cc656fb0cdab4264d07a15e5b2af6cfd9");
#endif
}

/* RFC 5310 section 3.3 (1): keys longer than the hash are hashed */
static void test_strict_rfc5310(void)
{
	static const char key40[] = "0123456789012345678901234567890123456789";
	struct stream *s;

	strict_rfc5310 = true;
	test_digest("strict-rfc5310, 40-byte key", KEYCHAIN_ALGO_HMAC_SHA256, key40, false,
		    "e55177659aa69452edda71701f71ee740fb29cd475d6130e9052fa676717a98a");
	/* shorter than the hash: the same as plain HMAC */
	test_digest("strict-rfc5310, 4-byte key", KEYCHAIN_ALGO_HMAC_SHA256, "isis", false,
		    "2c055ae57cd8e41c680c10f5f31fcf2500449e318b9b3591c27bd83464da51f1");
#ifdef CRYPTO_OPENSSL
	test_digest("strict-rfc5310, hmac-sha-384, 60-byte key", KEYCHAIN_ALGO_HMAC_SHA384,
		    "012345678901234567890123456789012345678901234567890123456789", false,
		    "a27e977eae7d876a0a3c2c793c13d550e2fc07b79b3a356ce6cd4b6a5b64f94a1bd6b23a29a16901a683f6e4f153f1c4");
#endif

	/* with such a key, the two do not verify each other */
	clear_keys();
	add_key(7, KEYCHAIN_ALGO_HMAC_SHA256, key40);
	s = sign(false);
	strict_rfc5310 = false;
	assert(verify(s, "kc", false) == ISIS_AUTH_FAILURE);
	stream_free(s);
	printf("strict-rfc5310 against plain HMAC: ok\n");
}

static void test_verify_failures(void)
{
	struct stream *s;
	struct key *key;

	clear_keys();
	key = add_key(7, KEYCHAIN_ALGO_HMAC_SHA256, "isis");
	s = sign(false);
	assert(verify(s, "kc", false) == ISIS_AUTH_OK);

	/* a byte of the PDU changed */
	STREAM_DATA(s)[stream_get_endp(s) - 1] ^= 0x01;
	assert(verify(s, "kc", false) == ISIS_AUTH_FAILURE);
	STREAM_DATA(s)[stream_get_endp(s) - 1] ^= 0x01;
	assert(verify(s, "kc", false) == ISIS_AUTH_OK);

	/* another key string */
	XFREE(MTYPE_KEY, key->string);
	key->string = XSTRDUP(MTYPE_KEY, "isjs");
	assert(verify(s, "kc", false) == ISIS_AUTH_FAILURE);

	/* no key with the Key ID */
	clear_keys();
	add_key(8, KEYCHAIN_ALGO_HMAC_SHA256, "isis");
	assert(verify(s, "kc", false) == ISIS_AUTH_FAILURE);

	/* the key, but no longer valid for accepting */
	clear_keys();
	key = add_key(7, KEYCHAIN_ALGO_HMAC_SHA256, "isis");
	key->accept.start = 1;
	key->accept.end = 2;
	assert(verify(s, "kc", false) == ISIS_AUTH_FAILURE);

	/* a key chain that does not exist */
	assert(verify(s, "none", false) == ISIS_AUTH_FAILURE);
	stream_free(s);
	printf("verification failures: ok\n");

	/* a PDU without authentication */
	struct isis_tlvs *tlvs = isis_alloc_tlvs();

	s = stream_new(1500);
	stream_put(s, pdu_header, sizeof(pdu_header));
	isis_tlvs_set_dynamic_hostname(tlvs, "r1");
	assert(!isis_pack_tlvs(tlvs, s, (size_t)-1, false, false));
	isis_free_tlvs(tlvs);
	assert(verify(s, "kc", false) == ISIS_AUTH_TYPE_FAILURE);
	stream_free(s);
	printf("missing authentication: ok\n");
}

static void test_truncated_key_id(void)
{
	/* an authentication TLV of type 3 with only one byte of Key ID */
	static const uint8_t tlv[] = { 0x0a, 0x02, 0x03, 0x00 };
	struct stream *s = stream_new(sizeof(tlv));
	struct isis_tlvs *tlvs;
	const char *log;

	stream_put(s, tlv, sizeof(tlv));
	assert(isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log));
	isis_free_tlvs(tlvs);
	stream_free(s);
	printf("truncated Key ID: ok\n");
}

/* The header, then an RFC 5310 authentication TLV with Key ID 7 */
static struct stream *pdu_with_digest(const uint8_t *digest, uint8_t len)
{
	struct stream *s = stream_new(1500);

	stream_put(s, pdu_header, sizeof(pdu_header));
	stream_putc(s, ISIS_TLV_AUTH);
	stream_putc(s, 1 + 2 + len);
	stream_putc(s, ISIS_PASSWD_TYPE_CRYPTO_AUTH);
	stream_putw(s, 7);
	stream_put(s, digest, len);
	return s;
}

static void test_digest_length(void)
{
	static const uint8_t digest[KEYCHAIN_MAX_HASH_SIZE];
	const char *formatted;
	struct isis_tlvs *tlvs;
	struct stream *s;
	const char *log;

	clear_keys();
	add_key(7, KEYCHAIN_ALGO_HMAC_SHA256, "isis");

	/* a Key ID and no digest: it formats as such, and does not verify */
	s = pdu_with_digest(digest, 0);
	stream_set_getp(s, sizeof(pdu_header));
	assert(!isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log));
	formatted = strstr(isis_format_tlvs(tlvs, NULL), "Crypto Auth: Key ID 7, ");
	assert(formatted && formatted[strlen("Crypto Auth: Key ID 7, ")] == '\n');
	isis_free_tlvs(tlvs);
	assert(verify(s, "kc", false) == ISIS_AUTH_FAILURE);
	stream_free(s);

	/* a digest of the length of another algorithm */
	s = pdu_with_digest(digest, 20);
	assert(verify(s, "kc", false) == ISIS_AUTH_FAILURE);
	stream_free(s);
	printf("digest length: ok\n");
}

static uint16_t send_key_id(void)
{
	struct isis_passwd pw = passwd("kc");
	struct isis_tlvs *tlvs = isis_alloc_tlvs();
	uint16_t key_id = 0;

	if (isis_tlvs_add_auth(tlvs, &pw))
		key_id = ((struct isis_auth *)tlvs->isis_auth.head)->key_id;
	else
		assert(!tlvs->isis_auth.count);
	isis_free_tlvs(tlvs);
	return key_id;
}

static void test_send_key(void)
{
	time_t now = time(NULL);
	struct key *key;

	clear_keys();
	/* no longer valid for sending */
	key = add_key(1, KEYCHAIN_ALGO_HMAC_SHA256, "isis");
	key->send.start = 1;
	key->send.end = 2;
	/* no key string */
	add_key(2, KEYCHAIN_ALGO_HMAC_SHA256, NULL);
	/* not an RFC 5310 algorithm */
	add_key(3, KEYCHAIN_ALGO_MD5, "isis");
	/* a Key ID larger than the 16-bit field */
	add_key(70000, KEYCHAIN_ALGO_HMAC_SHA256, "isis");
	assert(send_key_id() == 0);

	/* the first usable key, in Key ID order */
	add_key(5, KEYCHAIN_ALGO_HMAC_SHA256, "isis");
	add_key(4, KEYCHAIN_ALGO_HMAC_SHA256, "isis");
	assert(send_key_id() == 4);

	/* valid for sending from tomorrow */
	key = key_lookup(keychain, 4);
	key->send.start = now + 86400;
	key->send.end = -1;
	assert(send_key_id() == 5);
	printf("send key selection: ok\n");

	/* the next send lifetime change: key 4 starts tomorrow, key 1 ended */
	assert(isis_keychain_next_send_change("kc", now) == now + 86400);
	key = key_lookup(keychain, 5);
	key->send.start = now - 10;
	key->send.end = now + 60;
	assert(isis_keychain_next_send_change("kc", now) == now + 61);
	assert(isis_keychain_next_send_change("none", now) == 0);
	printf("send lifetime changes: ok\n");
}

static struct isis_tlvs *unpack(const uint8_t *data, size_t len)
{
	struct stream *s = stream_new(len);
	struct isis_tlvs *tlvs;
	const char *log;

	stream_put(s, data, len);
	assert(!isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log));
	stream_free(s);
	return tlvs;
}

static void test_esn(void)
{
	/* two ESN TLVs */
	static const uint8_t two[] = {
		0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05,
		0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
	};
	/* one with a wrong length */
	static const uint8_t bad[] = {
		0x0b, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	};
	/* a valid one and an empty one, in both orders */
	/* clang-format off */
	static const uint8_t valid_empty[] = {
		0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05,
		0x0b, 0x00,
	};
	static const uint8_t empty_valid[] = {
		0x0b, 0x00,
		0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05,
	};
	/* clang-format on */
	struct isis_tlvs *tlvs = isis_alloc_tlvs();
	struct stream *s = stream_new(64);
	const char *log;

	isis_tlvs_set_esn(tlvs, 0x0102030405060708ULL, 0x0a0b0c0d);
	assert(!isis_pack_tlvs(tlvs, s, (size_t)-1, false, false));
	isis_free_tlvs(tlvs);

	static const uint8_t want[] = {
		0x0b, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c, 0x0d,
	};
	assert(stream_get_endp(s) == sizeof(want));
	assert(!memcmp(STREAM_DATA(s), want, sizeof(want)));

	stream_set_getp(s, 0);
	assert(!isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log));
	assert(tlvs->esn && tlvs->esn->essn == 0x0102030405060708ULL &&
	       tlvs->esn->psn == 0x0a0b0c0d && !tlvs->esn->invalid);
	isis_free_tlvs(tlvs);
	stream_free(s);

	tlvs = unpack(two, sizeof(two));
	assert(tlvs->esn && tlvs->esn->invalid);
	isis_free_tlvs(tlvs);

	tlvs = unpack(bad, sizeof(bad));
	assert(tlvs->esn && tlvs->esn->invalid);
	isis_free_tlvs(tlvs);

	tlvs = unpack(valid_empty, sizeof(valid_empty));
	assert(tlvs->esn && tlvs->esn->invalid);
	isis_free_tlvs(tlvs);

	tlvs = unpack(empty_valid, sizeof(empty_valid));
	assert(tlvs->esn && tlvs->esn->invalid);
	isis_free_tlvs(tlvs);
	printf("extended sequence number TLV: ok\n");
}

int main(int argc, char **argv)
{
	keychain_init_new(true);
	keychain = keychain_get("kc");

	test_digests();
	test_strict_rfc5310();
	test_verify_failures();
	test_truncated_key_id();
	test_digest_length();
	test_send_key();
	test_esn();

	keychain_terminate();
	isis_tlvs_terminate();
	return 0;
}
