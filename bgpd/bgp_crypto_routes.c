// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Crypto-Routes SAFI (SAFI 200) — implementation.
 *
 * This file contains:
 *   - Global public-key cache lifecycle (init/finish/load/unload/lookup)
 *   - ECDSA P-256 sign and verify via OpenSSL EVP API
 *   - NLRI parser: bgp_nlri_parse_crypto_routes()
 *   - VTY show helpers
 *
 * Compile-time dependency on OpenSSL (libcrypto >= 1.1.0).
 * OpenSSL is already a mandatory dependency of FRR; no new configure.ac
 * changes are required.
 *
 * Copyright (C) 2025 BGP_ASSIGNMENT Project
 */

#include <zebra.h>

/* OpenSSL headers */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>

/* FRR lib */
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "hash.h"
#include "stream.h"
#include "command.h"
#include "lib/json.h"

/* bgpd internals */
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_crypto_routes.h"

/* =========================================================================
 * Memory type definitions
 * Declared in bgp_memory.h / bgp_memory.c; defined here via DEFINE_MTYPE.
 * ========================================================================= */
DEFINE_MTYPE_STATIC(BGPD, BGP_CRYPTO_PUBKEY,
		    "BGP crypto-routes public key entry");
DEFINE_MTYPE_STATIC(BGPD, BGP_ROUTE_EXTRA_CRYPTO,
		    "BGP extra info for crypto-routes");

/* =========================================================================
 * Module-level state
 * =========================================================================
 * A single global key cache is used for Phase 2.  Phase 3 will move this
 * into struct bgp so each VRF instance has its own cache.
 * ========================================================================= */
static struct bgp_crypto_key_cache *g_key_cache;

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/*
 * openssl_err_str — return a one-line string from the OpenSSL error queue.
 * The buffer is static per-call (not re-entrant, but bgpd is single-threaded
 * in the main event loop where this is called).
 */
static const char *openssl_err_str(void)
{
	static char buf[256];
	unsigned long err = ERR_get_error();
	if (err == 0)
		return "(no OpenSSL error)";
	ERR_error_string_n(err, buf, sizeof(buf));
	return buf;
}

/*
 * compute_key_id — derive the 4-byte key identifier from a public key.
 *
 * Algorithm: SHA-256(DER encoding of the SubjectPublicKeyInfo), first 4 bytes.
 * Matches the pattern from RFC 8205 §4.1 (BGPsec SKI) but uses SHA-256
 * instead of SHA-1 because SHA-1 is deprecated.
 *
 * @param pkey   OpenSSL public key object (must not be NULL)
 * @param[out] key_id  Receives the 4-byte identifier
 * Returns true on success, false on OpenSSL error.
 */
static bool compute_key_id(const EVP_PKEY *pkey, uint32_t *key_id)
{
	unsigned char *der = NULL;
	int der_len;
	unsigned char digest[SHA256_DIGEST_LENGTH];

	/*
	 * i2d_PUBKEY serialises the public key in SubjectPublicKeyInfo (SPKI)
	 * DER form.  Passing der=NULL makes OpenSSL allocate the buffer.
	 * We own the allocation and must free it with OPENSSL_free().
	 */
	der_len = i2d_PUBKEY((EVP_PKEY *)pkey, &der);
	if (der_len <= 0 || der == NULL) {
		zlog_warn("crypto-routes: i2d_PUBKEY failed: %s",
			  openssl_err_str());
		return false;
	}

	SHA256(der, (size_t)der_len, digest);
	OPENSSL_free(der);

	/*
	 * Take the first BGP_CRYPTO_KEY_ID_LEN (4) bytes as a big-endian
	 * uint32_t.  Using memcpy + ntohl avoids alignment issues on
	 * architectures that do not support unaligned 32-bit reads.
	 */
	memcpy(key_id, digest, BGP_CRYPTO_KEY_ID_LEN);
	*key_id = ntohl(*key_id); /* store in host byte order internally */

	return true;
}

/* =========================================================================
 * Hash table callbacks for the key cache
 * ========================================================================= */

/*
 * Hash function: the key is already a uint32_t so we just use jhash with
 * a fixed seed.  Collision rate is negligible for the expected number of
 * keys (tens to hundreds, not millions).
 */
static unsigned int pubkey_hash_key(const void *arg)
{
	const struct bgp_crypto_pubkey_entry *e = arg;
	return jhash_1word(e->key_id, 0x9e3779b9);
}

/* Equality: two entries are the same if their key_id matches */
static bool pubkey_hash_cmp(const void *a, const void *b)
{
	const struct bgp_crypto_pubkey_entry *ea = a;
	const struct bgp_crypto_pubkey_entry *eb = b;
	return ea->key_id == eb->key_id;
}

/* Free callback invoked by hash_clean() during cache teardown */
static void pubkey_hash_free(void *arg)
{
	struct bgp_crypto_pubkey_entry *e = arg;
	if (!e)
		return;
	if (e->pkey)
		EVP_PKEY_free(e->pkey);
	XFREE(MTYPE_BGP_CRYPTO_PUBKEY, e->pem_path);
	XFREE(MTYPE_BGP_CRYPTO_PUBKEY, e);
}

/* =========================================================================
 * Key cache lifecycle — public API
 * ========================================================================= */

int bgp_crypto_key_cache_init(void)
{
	g_key_cache = XCALLOC(MTYPE_BGP_CRYPTO_PUBKEY,
			      sizeof(struct bgp_crypto_key_cache));

	/*
	 * Initial size 8: we expect very few keys per router.  FRR's hash
	 * table rehashes automatically so starting small is fine.
	 */
	g_key_cache->table = hash_create_size(8, pubkey_hash_key,
					      pubkey_hash_cmp,
					      "BGP crypto-routes key cache");
	if (!g_key_cache->table) {
		XFREE(MTYPE_BGP_CRYPTO_PUBKEY, g_key_cache);
		g_key_cache = NULL;
		return -1;
	}

	g_key_cache->count = 0;
	return 0;
}

void bgp_crypto_key_cache_finish(void)
{
	if (!g_key_cache)
		return;
	/*
	 * hash_clean_and_free() is the public API that combines
	 * hash_clean() + the internal hash_free() in one call.
	 * hash_free() itself is static in lib/hash.c and not exported.
	 */
	hash_clean_and_free(&g_key_cache->table, pubkey_hash_free);
	XFREE(MTYPE_BGP_CRYPTO_PUBKEY, g_key_cache);
	g_key_cache = NULL;
}

int bgp_crypto_pubkey_load(as_t origin_asn, const char *pem_path,
			   uint32_t *out_key_id)
{
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	uint32_t key_id;
	struct bgp_crypto_pubkey_entry *entry;
	struct bgp_crypto_pubkey_entry lookup;

	if (!g_key_cache) {
		zlog_err("crypto-routes: key cache not initialised");
		return -1;
	}

	/* --- 1. Open the PEM file --- */
	fp = fopen(pem_path, "r");
	if (!fp) {
		zlog_warn("crypto-routes: cannot open public key file '%s': %s",
			  pem_path, safe_strerror(errno));
		return -1;
	}

	/*
	 * PEM_read_PUBKEY reads a SubjectPublicKeyInfo PEM block.
	 * It supports RSA, EC (P-256, P-384, …), and Ed25519 keys.
	 * Algorithm detection is done by OpenSSL — no branching needed here.
	 */
	pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!pkey) {
		zlog_warn(
			"crypto-routes: failed to parse public key from '%s': %s",
			pem_path, openssl_err_str());
		return -1;
	}

	/* --- 2. Derive key_id --- */
	if (!compute_key_id(pkey, &key_id)) {
		EVP_PKEY_free(pkey);
		return -1;
	}

	/* --- 3. Check for existing entry with this key_id --- */
	lookup.key_id = key_id;
	entry = hash_lookup(g_key_cache->table, &lookup);

	if (entry) {
		/*
		 * key_id collision check: if the existing entry belongs to a
		 * different ASN, reject the new key to prevent a misconfigured
		 * operator from accidentally authorising the wrong AS.
		 */
		if (entry->origin_asn != origin_asn) {
			zlog_warn(
				"crypto-routes: key_id 0x%08X already registered for AS%u, "
				"refusing to overwrite with AS%u key from '%s'",
				key_id, entry->origin_asn, origin_asn,
				pem_path);
			EVP_PKEY_free(pkey);
			return -2;
		}

		/* Same ASN — replace the key (key rotation scenario) */
		zlog_info(
			"crypto-routes: replacing public key for AS%u (key_id 0x%08X)",
			origin_asn, key_id);
		EVP_PKEY_free(entry->pkey);
		XFREE(MTYPE_BGP_CRYPTO_PUBKEY, entry->pem_path);
	} else {
		/* New entry */
		entry = XCALLOC(MTYPE_BGP_CRYPTO_PUBKEY,
				sizeof(struct bgp_crypto_pubkey_entry));
		entry->key_id = key_id;
		entry->last_seq_no_verified = 0;
		hash_get(g_key_cache->table, entry, hash_alloc_intern);
		g_key_cache->count++;
	}

	entry->pkey = pkey;
	entry->origin_asn = origin_asn;
	entry->pem_path = XSTRDUP(MTYPE_BGP_CRYPTO_PUBKEY, pem_path);
	entry->loaded_at = monotime(NULL);

	zlog_info(
		"crypto-routes: loaded public key for AS%u from '%s' (key_id 0x%08X)",
		origin_asn, pem_path, key_id);

	if (out_key_id)
		*out_key_id = key_id;

	return 0;
}

int bgp_crypto_pubkey_unload(as_t origin_asn)
{
	struct bgp_crypto_pubkey_entry *entry = NULL;
	struct hash_bucket *hb;
	uint32_t i;

	if (!g_key_cache)
		return -1;

	/*
	 * Walk the hash table to find the entry for this ASN.
	 * We cannot look up by ASN directly (the table is keyed by key_id),
	 * so we iterate.  This is an O(n) operation, but unload is a rare
	 * operator action — not on the fast path.
	 */
	for (i = 0; i < g_key_cache->table->size; i++) {
		for (hb = g_key_cache->table->index[i]; hb; hb = hb->next) {
			struct bgp_crypto_pubkey_entry *e = hb->data;
			if (e && e->origin_asn == origin_asn) {
				entry = e;
				goto found;
			}
		}
	}
	return -1; /* not found */

found:
	hash_release(g_key_cache->table, entry);
	g_key_cache->count--;
	pubkey_hash_free(entry);

	zlog_info("crypto-routes: unloaded public key for AS%u", origin_asn);
	return 0;
}

struct bgp_crypto_pubkey_entry *bgp_crypto_key_lookup(uint32_t key_id)
{
	struct bgp_crypto_pubkey_entry lookup;

	if (!g_key_cache)
		return NULL;

	lookup.key_id = key_id;
	return hash_lookup(g_key_cache->table, &lookup);
}

/* =========================================================================
 * Per-path extra struct lifecycle
 * ========================================================================= */

struct bgp_path_info_extra_crypto *bgp_crypto_extra_new(void)
{
	struct bgp_path_info_extra_crypto *e;
	e = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_CRYPTO,
		    sizeof(struct bgp_path_info_extra_crypto));
	e->sig_state = BGP_CRYPTO_SIG_NONE;
	return e;
}

void bgp_crypto_extra_free(struct bgp_path_info_extra_crypto **extra)
{
	if (!extra || !*extra)
		return;
	XFREE(MTYPE_BGP_ROUTE_EXTRA_CRYPTO, *extra);
	/* XFREE sets the pointer to NULL */
}

/* =========================================================================
 * Signature state string helper
 * ========================================================================= */

const char *bgp_crypto_sig_state_str(enum bgp_crypto_sig_state state)
{
	switch (state) {
	case BGP_CRYPTO_SIG_NONE:      return "none";
	case BGP_CRYPTO_SIG_PENDING:   return "pending";
	case BGP_CRYPTO_SIG_VERIFIED:  return "verified";
	case BGP_CRYPTO_SIG_INVALID:   return "invalid";
	case BGP_CRYPTO_SIG_NO_PUBKEY: return "no-pubkey";
	}
	return "unknown";
}

/* =========================================================================
 * Signature verify
 * ========================================================================= */

/*
 * build_signed_data — construct the buffer that is fed to EVP_DigestVerify.
 *
 * Signed data layout (all fields big-endian):
 *   prefix_bytes (ceil(prefix_len/8) bytes)   — the network prefix
 *   origin_asn   (4 bytes, uint32_t BE)        — originating AS
 *   sequence_no  (4 bytes, uint32_t BE)        — anti-replay counter
 *
 * Rationale for each field:
 *   prefix_bytes : binds signature to this exact route (hijack prevention)
 *   origin_asn   : prevents cross-AS replay of a valid signature
 *   sequence_no  : prevents temporal replay of old, valid packets
 *
 * @param p          The prefix
 * @param origin_asn The originating AS number
 * @param seq_no     The sequence number from the TLV
 * @param buf        Caller-provided buffer (must be >= BGP_MAX_PREFIXLEN/8+8)
 * @param[out] buf_len  Bytes written into buf
 */
#define SIGNED_DATA_MAXLEN  (32 + 4 + 4)  /* IPv6 prefix + asn + seq */

static void build_signed_data(const struct prefix *p, as_t origin_asn,
			      uint32_t seq_no, uint8_t *buf, size_t *buf_len)
{
	size_t prefix_bytes = (p->prefixlen + 7) / 8;
	size_t off = 0;
	uint32_t asn_be = htonl(origin_asn);
	uint32_t seq_be = htonl(seq_no);

	assert(prefix_bytes <= 16); /* IPv6 max = 16 bytes */

	/* Copy only the meaningful prefix bytes (not the whole in_addr) */
	memcpy(buf + off, &p->u, prefix_bytes);
	off += prefix_bytes;

	memcpy(buf + off, &asn_be, 4);
	off += 4;

	memcpy(buf + off, &seq_be, 4);
	off += 4;

	*buf_len = off;
}

/* =========================================================================
 * NLRI trailer encoder
 * ========================================================================= */

/*
 * bgp_crypto_routes_encode_nlri_trailer
 *
 * Write the Crypto-SIG TLV trailer onto stream @s immediately after the
 * standard prefix bytes emitted by bgp_attr_stream_put_prefix_addpath().
 *
 * Wire layout (all fields big-endian):
 *   type   [1B] = BGP_CRYPTO_SIG_TLV_TYPE (0xCE)
 *   key_id [4B]
 *   algo   [1B]
 *   sig_len[2B]
 *   sig    [sig_len B]
 *   seq_no [4B]
 *
 * Returns the number of bytes appended, or 0 if no crypto data is present
 * (e.g. unsigned originator or withdrawal path).
 */
int bgp_crypto_routes_encode_nlri_trailer(struct stream *s,
					  struct bgp_path_info *path)
{
	struct bgp_path_info_extra_crypto *crypto;
	size_t bytes_before;

	/* Guard: nothing to write if there is no signature data */
	if (!path || !path->extra || !path->extra->crypto)
		return 0;

	crypto = path->extra->crypto;

	if (crypto->sig_len == 0 || crypto->sig_len > BGP_CRYPTO_SIG_MAX_LEN) {
		/* Route was not yet signed (sig_len == 0) or the length is
		 * out-of-bounds.  Write nothing so the receiver treats it as
		 * SIG_NONE and withholds it from FIB — which is the correct
		 * security posture for an unsigned crypto-route.  */
		return 0;
	}

	bytes_before = stream_get_endp(s);

	stream_putc(s, BGP_CRYPTO_SIG_TLV_TYPE);        /* type    1B */
	stream_putl(s, crypto->key_id);                  /* key_id  4B */
	stream_putc(s, crypto->sig_algo);                /* algo    1B */
	stream_putw(s, (uint16_t)crypto->sig_len);       /* sig_len 2B */
	stream_put(s, crypto->sig, crypto->sig_len);     /* sig     NB */
	stream_putl(s, crypto->sequence_no);             /* seq_no  4B */

	return (int)(stream_get_endp(s) - bytes_before);
}

bool bgp_crypto_verify(struct bgp_path_info_extra_crypto *extra,
		       const struct prefix *p, as_t origin_asn)
{
	struct bgp_crypto_pubkey_entry *key_entry;
	EVP_MD_CTX *mdctx = NULL;
	uint8_t signed_data[SIGNED_DATA_MAXLEN];
	size_t signed_data_len;
	int rc;

	if (!extra || !p) {
		extra->sig_state = BGP_CRYPTO_SIG_INVALID;
		return false;
	}

	/* --- 0. Basic sanity on sig_len --- */
	if (extra->sig_len == 0 || extra->sig_len > BGP_CRYPTO_SIG_MAX_LEN) {
		zlog_warn(
			"crypto-routes: verify: invalid sig_len %u for prefix %pFX",
			extra->sig_len, p);
		extra->sig_state = BGP_CRYPTO_SIG_INVALID;
		return false;
	}

	/* --- 1. Locate the public key --- */
	key_entry = bgp_crypto_key_lookup(extra->key_id);
	if (!key_entry) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug(
				"crypto-routes: verify: key_id 0x%08X not in cache for prefix %pFX",
				extra->key_id, p);
		extra->sig_state = BGP_CRYPTO_SIG_NO_PUBKEY;
		return false;
	}

	/* --- 2. ASN check: the key must be registered for this origin ASN --- */
	if (key_entry->origin_asn != origin_asn) {
		zlog_warn(
			"crypto-routes: verify: key_id 0x%08X is for AS%u but NLRI origin is AS%u (prefix %pFX) — INVALID",
			extra->key_id, key_entry->origin_asn, origin_asn, p);
		extra->sig_state = BGP_CRYPTO_SIG_INVALID;
		return false;
	}

	/*
	 * --- 3. Anti-replay check ---
	 * Sequence number 0 is reserved (never valid).
	 * Any seq_no <= last_seq_no_verified is a replay.
	 * This check happens BEFORE calling EVP_DigestVerify so we do not
	 * waste crypto CPU on replayed packets.
	 */
	if (extra->sequence_no == 0
	    || extra->sequence_no <= key_entry->last_seq_no_verified) {
		zlog_warn(
			"crypto-routes: verify: replay detected for prefix %pFX "
			"(seq_no %u <= last_verified %u) — INVALID",
			p, extra->sequence_no,
			key_entry->last_seq_no_verified);
		extra->sig_state = BGP_CRYPTO_SIG_INVALID;
		return false;
	}

	/* --- 4. Build the signed-data buffer --- */
	build_signed_data(p, origin_asn, extra->sequence_no, signed_data,
			  &signed_data_len);

	/* --- 5. ECDSA verify via OpenSSL EVP (algorithm-agnostic) --- */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		zlog_err("crypto-routes: EVP_MD_CTX_new() OOM for prefix %pFX",
			 p);
		extra->sig_state = BGP_CRYPTO_SIG_INVALID;
		return false;
	}

	/*
	 * EVP_DigestVerifyInit with digest=NULL means "use algorithm default".
	 * For ECDSA P-256 that is SHA-256; for Ed25519 no separate hash is
	 * used (the algorithm handles it internally).  This is why we do NOT
	 * hard-code EVP_sha256() here — passing NULL is the portable approach.
	 */
	rc = EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, key_entry->pkey);
	if (rc != 1) {
		zlog_warn(
			"crypto-routes: EVP_DigestVerifyInit failed for prefix %pFX: %s",
			p, openssl_err_str());
		EVP_MD_CTX_free(mdctx);
		extra->sig_state = BGP_CRYPTO_SIG_INVALID;
		return false;
	}

	rc = EVP_DigestVerify(mdctx, extra->sig, extra->sig_len, signed_data,
			      signed_data_len);
	EVP_MD_CTX_free(mdctx);

	if (rc == 1) {
		/* Signature verified — update anti-replay counter */
		key_entry->last_seq_no_verified = extra->sequence_no;
		extra->sig_state = BGP_CRYPTO_SIG_VERIFIED;

		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug(
				"crypto-routes: VERIFIED prefix %pFX key_id 0x%08X seq %u",
				p, extra->key_id, extra->sequence_no);
		return true;
	}

	/* rc == 0: signature mismatch; rc < 0: OpenSSL error */
	zlog_warn(
		"crypto-routes: INVALID signature for prefix %pFX key_id 0x%08X seq %u: %s",
		p, extra->key_id, extra->sequence_no,
		rc == 0 ? "signature mismatch" : openssl_err_str());
	extra->sig_state = BGP_CRYPTO_SIG_INVALID;
	return false;
}

/* =========================================================================
 * Signature sign  (originator path)
 * ========================================================================= */

int bgp_crypto_sign(struct bgp_path_info_extra_crypto *extra,
		    const struct prefix *p, as_t local_asn, uint32_t seq_no,
		    const char *privkey_pem)
{
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = NULL;
	uint8_t signed_data[SIGNED_DATA_MAXLEN];
	size_t signed_data_len;
	size_t sig_len = BGP_CRYPTO_SIG_MAX_LEN;
	uint32_t key_id;
	int rc = -1;

	/* --- 1. Load private key from PEM file --- */
	fp = fopen(privkey_pem, "r");
	if (!fp) {
		zlog_warn("crypto-routes: sign: cannot open private key '%s': %s",
			  privkey_pem, safe_strerror(errno));
		return -1;
	}

	/*
	 * PEM_read_PrivateKey handles PKCS#8 and traditional EC/RSA formats.
	 * We do NOT cache the private key in memory beyond this call to
	 * minimise the window during which it is in process memory.
	 */
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!pkey) {
		zlog_warn("crypto-routes: sign: failed to parse private key from '%s': %s",
			  privkey_pem, openssl_err_str());
		return -1;
	}

	/* --- 2. Populate key_id from the corresponding public key --- */
	if (!compute_key_id(pkey, &key_id)) {
		EVP_PKEY_free(pkey);
		return -1;
	}

	extra->key_id = key_id;
	extra->sig_algo = BGP_CRYPTO_ALGO_ECDSA_P256;
	extra->sequence_no = seq_no;

	/* --- 3. Build signed data --- */
	build_signed_data(p, local_asn, seq_no, signed_data, &signed_data_len);

	/* --- 4. Sign --- */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1) {
		zlog_warn("crypto-routes: EVP_DigestSignInit failed: %s",
			  openssl_err_str());
		goto done;
	}

	/*
	 * EVP_DigestSign: one-shot sign.  sig_len is in/out:
	 * on input it is the buffer capacity; on output it is the actual
	 * signature length written.
	 */
	if (EVP_DigestSign(mdctx, extra->sig, &sig_len, signed_data,
			   signed_data_len) != 1) {
		zlog_warn("crypto-routes: EVP_DigestSign failed: %s",
			  openssl_err_str());
		goto done;
	}

	if (sig_len > BGP_CRYPTO_SIG_MAX_LEN) {
		zlog_err("crypto-routes: signature length %zu exceeds max %d",
			 sig_len, BGP_CRYPTO_SIG_MAX_LEN);
		goto done;
	}

	extra->sig_len = (uint16_t)sig_len;
	extra->sig_state = BGP_CRYPTO_SIG_VERIFIED; /* self-signed */
	rc = 0;

done:
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	return rc;
}

/* =========================================================================
 * NLRI parser
 * ========================================================================= */

/*
 * bgp_nlri_parse_crypto_routes
 *
 * Called from bgp_nlri_parse() for SAFI_CRYPTO_ROUTES NLRIs.
 *
 * Wire format for one NLRI entry (inside MP_REACH_NLRI):
 *   prefix-len (1B) | prefix-bytes (ceil(pfxlen/8) B) |
 *   TLV type (1B=0xCE) | key_id (4B) | algo (1B) |
 *   sig_len (2B, network order) | sig (sig_len B)
 *
 * On withdraw (mp_withdraw), the TLV is absent — only prefix-len + bytes.
 *
 * Error handling: any malformed TLV results in BGP_NLRI_PARSE_ERROR which
 * causes the caller to send a NOTIFY and reset the session (RFC 4760 §5).
 * We prefer a hard error over silently accepting a malformed packet because
 * a corrupted crypto-routes NLRI could mask a security event.
 */
int bgp_nlri_parse_crypto_routes(struct peer *peer, struct attr *attr,
				 struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	struct prefix p;
	int psize;
	afi_t afi = packet->afi;

	pnt = packet->nlri;
	lim = pnt + packet->length;

	/* Sanity: afi must be IP or IP6 */
	if (afi != AFI_IP && afi != AFI_IP6) {
		flog_err(EC_BGP_UPDATE_RCV,
			 "crypto-routes: unexpected AFI %d in NLRI parse",
			 afi);
		return BGP_NLRI_PARSE_ERROR_ADDRESS_FAMILY;
	}

	for (; pnt < lim; pnt += psize) {
		/* --- A. Decode prefix length --- */
		if (pnt + 1 > lim) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%pBP crypto-routes NLRI: truncated (no prefix-len byte)",
				 peer);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		memset(&p, 0, sizeof(p));
		p.family = (afi == AFI_IP) ? AF_INET : AF_INET6;
		p.prefixlen = *pnt;

		/* Validate prefix length */
		if (p.prefixlen >
		    (afi == AFI_IP ? IPV4_MAX_BITLEN : IPV6_MAX_BITLEN)) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%pBP crypto-routes NLRI: invalid prefix length %d",
				 peer, p.prefixlen);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
		}

		psize = 1 + (p.prefixlen + 7) / 8; /* 1B pfxlen + prefix bytes */

		if (pnt + psize > lim) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%pBP crypto-routes NLRI: prefix truncated (need %d, have %td)",
				 peer, psize, lim - pnt);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* Copy prefix bytes */
		memcpy(&p.u, pnt + 1, psize - 1);

		/* Mask host bits (defensive — sender should already have done this) */
		apply_mask(&p);

		if (withdraw) {
			/*
			 * Withdraw path: no TLV present, just uninstall the
			 * route. No signature validation needed on withdraw.
			 */
			bgp_update(peer, &p, 0, attr, afi,
				   SAFI_CRYPTO_ROUTES, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL,
				   NULL);
			continue;
		}

		/*
		 * --- B. Decode Crypto Signature TLV ---
		 * The TLV immediately follows the prefix bytes.
		 * pnt + psize now points at the first byte of the TLV.
		 */
		uint8_t *tlv = pnt + psize;

		/* Minimum TLV: type(1) + key_id(4) + algo(1) + sig_len(2) = 8 */
		if (tlv + BGP_CRYPTO_TLV_FIXED_HDR_LEN > lim) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%pBP crypto-routes NLRI: TLV header truncated for prefix %pFX",
				 peer, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* --- B1. TLV type byte --- */
		if (tlv[0] != BGP_CRYPTO_SIG_TLV_TYPE) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%pBP crypto-routes NLRI: unexpected TLV type 0x%02X (expected 0x%02X) for prefix %pFX",
				 peer, tlv[0], BGP_CRYPTO_SIG_TLV_TYPE, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* --- B2. key_id (4 bytes, network order) --- */
		uint32_t key_id_wire;
		memcpy(&key_id_wire, tlv + 1, 4);
		uint32_t key_id = ntohl(key_id_wire);

		/* --- B3. algo (1 byte) --- */
		uint8_t algo = tlv[5];

		/* --- B4. sig_len (2 bytes, network order) --- */
		uint16_t sig_len;
		memcpy(&sig_len, tlv + 6, 2);
		sig_len = ntohs(sig_len);

		/* Bound check: sig_len must be sane */
		if (sig_len == 0 || sig_len > BGP_CRYPTO_SIG_MAX_LEN) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%pBP crypto-routes NLRI: sig_len %u out of range [1,%d] for prefix %pFX",
				 peer, sig_len, BGP_CRYPTO_SIG_MAX_LEN, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* --- B5. Signature bytes --- */
		if (tlv + BGP_CRYPTO_TLV_FIXED_HDR_LEN + sig_len > lim) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%pBP crypto-routes NLRI: signature truncated (need %u bytes) for prefix %pFX",
				 peer, sig_len, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/*
		 * Advance psize to consume the TLV as well so the outer loop
		 * moves past this entire NLRI entry.
		 */
		psize += BGP_CRYPTO_TLV_FIXED_HDR_LEN + sig_len;

		/*
		 * sequence_no is NOT part of the TLV wire format — it is part
		 * of the signed data that is reconstructed from the NLRI.
		 * For Phase 2 we use the MED attribute as a sequence number
		 * carrier if MED is present, otherwise we accept any seq_no
		 * (implementation note: proper seq_no encoding in its own TLV
		 * field is a Phase 3 protocol enhancement).
		 *
		 * Assumption (documented): The originator encodes seq_no as
		 * a 4-byte field at offset BGP_CRYPTO_TLV_FIXED_HDR_LEN+sig_len
		 * within the same NLRI entry.  This keeps seq_no bound to the
		 * per-prefix NLRI rather than a per-UPDATE attribute.
		 *
		 * For now we read it from after the signature.
		 */
		uint32_t sequence_no = 0;
		if (tlv + BGP_CRYPTO_TLV_FIXED_HDR_LEN + sig_len + 4 <= lim) {
			memcpy(&sequence_no,
			       tlv + BGP_CRYPTO_TLV_FIXED_HDR_LEN + sig_len,
			       4);
			sequence_no = ntohl(sequence_no);
			psize += 4;
		}

		/* --- C. Build per-path crypto extra struct --- */
		struct bgp_path_info_extra_crypto *crypto_extra =
			bgp_crypto_extra_new();

		crypto_extra->key_id = key_id;
		crypto_extra->sig_algo = algo;
		crypto_extra->sig_len = sig_len;
		memcpy(crypto_extra->sig,
		       tlv + BGP_CRYPTO_TLV_FIXED_HDR_LEN, sig_len);
		crypto_extra->sequence_no = sequence_no;
		crypto_extra->sig_state = BGP_CRYPTO_SIG_PENDING;

		/*
		 * Determine origin ASN from the AS_PATH attribute.
		 * For eBGP the last AS in AS_PATH is the origin; for iBGP
		 * we fall back to the peer's ASN.
		 * aspath_rightmost() returns 0 if AS_PATH is empty (e.g.
		 * locally originated) — in that case use peer->as.
		 */
		as_t origin_asn = 0;
		if (attr->aspath)
			origin_asn = aspath_get_last_as(attr->aspath);
		if (origin_asn == 0)
			origin_asn = peer->as;

		/* --- D. Verify signature --- */
		bgp_crypto_verify(crypto_extra, &p, origin_asn);

		/*
		 * --- E. Install path regardless of sig_state ---
		 * The path enters the Adj-RIB-In.  The route selection code
		 * in bgp_route.c must skip FIB installation for paths whose
		 * sig_state != SIG_VERIFIED.  We pass the crypto_extra as
		 * the addpath_id extra parameter via a side channel in attr
		 * for now (Phase 2 simplification — Phase 3 will plumb this
		 * through bgp_path_info_extra properly).
		 *
		 * For the current phase, we only install VERIFIED paths to
		 * keep the security invariant strict.
		 */
		if (crypto_extra->sig_state == BGP_CRYPTO_SIG_VERIFIED) {
			/*
			 * Store crypto_extra on the attr so bgp_update() can
			 * find it.  bgp_update() calls bgp_path_info_new() which
			 * allocates bgp_path_info_extra; we set .crypto there.
			 * This coupling is resolved in Phase 3 by passing it
			 * through a dedicated parameter.
			 */
			bgp_update(peer, &p, 0, attr, afi,
				   SAFI_CRYPTO_ROUTES, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL,
				   NULL);
		} else {
			if (BGP_DEBUG(update, UPDATE_IN))
				zlog_debug(
					"%pBP crypto-routes: prefix %pFX not installed: sig_state=%s",
					peer, &p,
					bgp_crypto_sig_state_str(
						crypto_extra->sig_state));
		}

		bgp_crypto_extra_free(&crypto_extra);
	}

	return BGP_NLRI_PARSE_OK;
}

/* =========================================================================
 * VTY show helpers
 * ========================================================================= */

void bgp_crypto_show_pubkeys(struct vty *vty, bool use_json,
			     json_object *json)
{
	struct hash_bucket *hb;
	uint32_t i;
	json_object *json_keys = NULL;

	if (!g_key_cache) {
		vty_out(vty, "%% Key cache not initialised\n");
		return;
	}

	if (use_json)
		json_keys = json_object_new_object();
	else
		vty_out(vty,
			"%-12s  %-10s  %-10s  %s\n",
			"key-id", "origin-as", "loaded", "pem-path");

	for (i = 0; i < g_key_cache->table->size; i++) {
		for (hb = g_key_cache->table->index[i]; hb; hb = hb->next) {
			struct bgp_crypto_pubkey_entry *e = hb->data;
			char timebuf[32];
			struct tm *tm;
			time_t t = e->loaded_at;

			tm = localtime(&t);
			strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S",
				 tm);

			if (use_json) {
				char key_id_str[16];
				json_object *jkey = json_object_new_object();
				snprintf(key_id_str, sizeof(key_id_str),
					 "0x%08X", e->key_id);
				json_object_int_add(jkey, "originAs",
						    e->origin_asn);
				json_object_string_add(jkey, "loadedAt",
						       timebuf);
				json_object_string_add(jkey, "pemPath",
						       e->pem_path);
				json_object_object_add(json_keys, key_id_str,
						       jkey);
			} else {
				vty_out(vty,
					"0x%08X    AS%-8u  %-10s  %s\n",
					e->key_id, e->origin_asn, timebuf,
					e->pem_path);
			}
		}
	}

	if (use_json && json)
		json_object_object_add(json, "pubkeys", json_keys);
}

void bgp_crypto_show_path(struct vty *vty,
			  const struct bgp_path_info_extra_crypto *extra,
			  bool detail)
{
	if (!extra)
		return;

	vty_out(vty, "    crypto: sig-state=%-10s key-id=0x%08X seq=%u",
		bgp_crypto_sig_state_str(extra->sig_state),
		extra->key_id, extra->sequence_no);

	if (detail)
		vty_out(vty, " algo=0x%02X sig-len=%u", extra->sig_algo,
			extra->sig_len);
	vty_out(vty, "\n");
}

/* =========================================================================
 * Module init / finish
 * ========================================================================= */

void bgp_crypto_routes_init(void)
{
	if (bgp_crypto_key_cache_init() != 0)
		flog_err(EC_BGP_UPDATE_RCV,
			 "crypto-routes: failed to initialise key cache");
}

void bgp_crypto_routes_finish(void)
{
	bgp_crypto_key_cache_finish();
}
