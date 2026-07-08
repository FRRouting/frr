// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Crypto-Routes SAFI (SAFI 200) — per-path signature metadata and
 * originator public-key cache.
 *
 * Design notes
 * ============
 * This header is the single source of truth for all types, constants, and
 * function declarations related to SAFI_CRYPTO_ROUTES.  Every other file
 * that needs to interact with this SAFI includes this header.
 *
 * The wire format of a crypto-routes NLRI inside MP_REACH_NLRI is:
 *
 *   [std IPv4/IPv6 prefix bytes (prefix-len + ceil(prefix-len/8) octets)]
 *   [Crypto Signature TLV]
 *     type    : 1 octet  = BGP_CRYPTO_SIG_TLV_TYPE (0xCE)
 *     key_id  : 4 octets = SHA-256(pub_key_DER)[0:4]
 *     algo    : 1 octet  = BGP_CRYPTO_ALGO_*
 *     sig_len : 2 octets = length of following signature bytes
 *     sig     : sig_len octets = DER-encoded ECDSA signature
 *
 * Signed data = prefix_bytes || origin_asn (4B big-endian) || seq_no (4B BE)
 * This binding prevents prefix hijacking, AS impersonation, and replay.
 *
 * RFC references
 * ==============
 *  RFC 4760  — MP_REACH_NLRI framework
 *  RFC 8205  — BGPsec: algorithm suite + SKI derivation pattern
 *  RFC 6487  — RPKI: SHA-256 key identifier pattern
 *  RFC 5492  — Capability Advertisement (SAFI negotiation)
 *
 * Copyright (C) 2025 BGP_ASSIGNMENT Project
 */

#ifndef _FRR_BGP_CRYPTO_ROUTES_H
#define _FRR_BGP_CRYPTO_ROUTES_H

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "prefix.h"
#include "hash.h"
#include "lib/json.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Wire-format constants
 * ========================================================================= */

/*
 * TLV type byte value embedded in the NLRI after the prefix bytes.
 * 0xCE is in the private/experimental range — no IANA registration needed.
 */
#define BGP_CRYPTO_SIG_TLV_TYPE  0xCE

/*
 * Signature algorithm selector byte.
 * Using an explicit byte (not inferred from key type) so the wire format
 * is self-describing and future-proof.
 */
#define BGP_CRYPTO_ALGO_ECDSA_P256  0x01  /* ECDSA P-256 with SHA-256  */
#define BGP_CRYPTO_ALGO_ED25519     0x02  /* EdDSA Ed25519              */
#define BGP_CRYPTO_ALGO_DILITHIUM   0x03  /* CRYSTALS-Dilithium (PQC)  */

/*
 * Maximum signature byte length accepted on receive.
 * 128 B covers ECDSA P-256 (64 B) and Ed25519 (64 B) with room to spare.
 * If post-quantum algorithms are added in Phase 3, this constant is bumped
 * and the fixed array replaced with a heap pointer — all callers use
 * BGP_CRYPTO_SIG_MAX_LEN as the bound so the change stays localised.
 */
#define BGP_CRYPTO_SIG_MAX_LEN  128

/*
 * Fixed overhead bytes added to each prefix in a crypto-routes NLRI:
 *   type(1) + key_id(4) + algo(1) + sig_len(2) + sig(sig_len)
 * The 8 fixed bytes are defined separately for clarity in length checks.
 */
#define BGP_CRYPTO_TLV_FIXED_HDR_LEN  8   /* type+key_id+algo+sig_len */

/*
 * Maximum byte size a Crypto-SIG TLV trailer can occupy in a crypto-routes
 * NLRI.  Used by bgp_packet_mpattr_prefix_size() to pre-reserve stream space
 * so that the subsequent stream_put() calls in bgp_packet_mpattr_prefix()
 * never overflow.
 *
 *   type   (1) + key_id (4) + algo (1) + sig_len (2)   = 8   (fixed hdr)
 *   sig    (BGP_CRYPTO_SIG_MAX_LEN = 128)               = 128 (max sig body)
 *   seq_no (4)                                          = 4
 *   ---------------------------------------------------------------
 *   total                                               = 140
 *
 * If path->extra->crypto is NULL (e.g. originator has not yet signed the
 * route) bgp_crypto_routes_encode_nlri_trailer() writes nothing, so the
 * reserved space is unused but harmless.
 */
#define BGP_CRYPTO_SIG_TLV_MAX_SIZE  140

/*
 * key_id derivation: first 4 bytes of SHA-256 of the public key in DER form.
 * Using SHA-256 (not SHA-1 as in RFC 6487) because SHA-1 is deprecated.
 */
#define BGP_CRYPTO_KEY_ID_LEN  4


/* =========================================================================
 * Signature state — mirrors rpki_states in bgp_rpki.h
 * ========================================================================= */

enum bgp_crypto_sig_state {
	/*
	 * SIG_NONE: path does not carry a Crypto Signature TLV.
	 * Used as the zero-value so zero-initialised structs are safe.
	 */
	BGP_CRYPTO_SIG_NONE = 0,

	/*
	 * SIG_PENDING: TLV present and decoded but verification has not
	 * been attempted yet (e.g. key-id not yet in the key cache).
	 * The path is held in the Adj-RIB-In but NOT installed to FIB.
	 */
	BGP_CRYPTO_SIG_PENDING,

	/*
	 * SIG_VERIFIED: EVP_DigestVerify() returned success.
	 * The path is eligible for Loc-RIB installation and FIB.
	 */
	BGP_CRYPTO_SIG_VERIFIED,

	/*
	 * SIG_INVALID: EVP_DigestVerify() returned failure, OR
	 * the sequence number was not greater than last_seq_no_verified
	 * (replay detected).  The path is retained in the Adj-RIB-In
	 * for diagnostic purposes but MUST NOT be installed to FIB.
	 */
	BGP_CRYPTO_SIG_INVALID,

	/*
	 * SIG_NO_PUBKEY: key_id not found in the local key cache.
	 * The path is held; when the operator provisions the key via
	 * "bgp crypto-routes pubkey", bgpd re-verifies all paths with
	 * this state for the matching key_id.
	 */
	BGP_CRYPTO_SIG_NO_PUBKEY,
};

/* Human-readable string for logging and show output */
extern const char *bgp_crypto_sig_state_str(enum bgp_crypto_sig_state state);


/* =========================================================================
 * Per-path extra information (hangs off bgp_path_info_extra.crypto)
 * ========================================================================= */

/*
 * bgp_path_info_extra_crypto
 *
 * Lazily allocated — NULL for all non-SAFI_CRYPTO_ROUTES paths.
 * Allocated in bgp_path_info_extra_get() and freed in
 * bgp_path_info_extra_free().
 *
 * Memory cost: sizeof(bgp_path_info_extra_crypto) = ~152 bytes.
 * With 1000 crypto-routes prefixes: ~152 KB — negligible.
 */
struct bgp_path_info_extra_crypto {
	/* --- decoded from NLRI Crypto Signature TLV on receive --- */

	/* 4-byte key identifier (SHA-256(pub_key_DER)[0:4]) */
	uint32_t key_id;

	/* algorithm selector byte as received on the wire */
	uint8_t sig_algo;

	/* byte length of sig[] that is valid */
	uint16_t sig_len;

	/*
	 * Raw signature bytes.
	 * Fixed-size array avoids per-path heap allocation for ECDSA P-256.
	 * sig_len carries the actual used length; bytes beyond sig_len are
	 * not meaningful.  No memcpy beyond sig_len is ever performed.
	 */
	uint8_t sig[BGP_CRYPTO_SIG_MAX_LEN];

	/* --- signed-data binding fields (reconstructed on verify) --- */

	/*
	 * Monotonically increasing counter from the originator.
	 * Checked against bgp_crypto_pubkey_entry.last_seq_no_verified
	 * before calling EVP_DigestVerify to reject replays cheaply.
	 */
	uint32_t sequence_no;

	/* --- verification result --- */
	enum bgp_crypto_sig_state sig_state;
};

/* Allocate and zero-initialise a bgp_path_info_extra_crypto */
extern struct bgp_path_info_extra_crypto *bgp_crypto_extra_new(void);

/* Free a bgp_path_info_extra_crypto (safe to call with NULL) */
extern void bgp_crypto_extra_free(struct bgp_path_info_extra_crypto **extra);


/* =========================================================================
 * Public key cache (per BGP instance)
 * ========================================================================= */

/*
 * bgp_crypto_pubkey_entry
 *
 * One entry per provisioned originator public key.
 * Keyed in the hash table by key_id (uint32_t).
 *
 * last_seq_no_verified tracks the highest sequence number successfully
 * verified for this key.  Any UPDATE with seq_no <= last_seq_no_verified
 * is rejected as a replay without calling EVP_DigestVerify (saves CPU).
 *
 * Note: last_seq_no_verified is initialised to 0.  Originators MUST
 * start their sequence counter at 1 so the first packet is never
 * rejected.  Sequence number 0 is reserved/invalid.
 */
struct bgp_crypto_pubkey_entry {
	/* Hash table linkage — must be first member */
	struct bgp_crypto_pubkey_entry *next; /* hash chaining */

	/* key identifier = SHA-256(pub_key_DER)[0:4] */
	uint32_t key_id;

	/* ASN this public key is authorised to sign for */
	as_t origin_asn;

	/*
	 * OpenSSL public key object.  Loaded once at config time from a PEM
	 * file. Freed when the entry is removed from the cache.
	 * The EVP_PKEY is thread-safe for concurrent reads (ref-counted
	 * internally by OpenSSL); bgpd's single-threaded event loop means
	 * we never have concurrent writes to the same entry.
	 */
	EVP_PKEY *pkey;

	/*
	 * Filesystem path of the PEM file this key was loaded from.
	 * Stored so "show bgp ipv4 crypto-routes pubkeys" can display it
	 * and so config_write can re-emit it correctly.
	 * Heap-allocated, freed with key entry.
	 */
	char *pem_path;

	/*
	 * Highest sequence number for which EVP_DigestVerify() succeeded.
	 * Reject any incoming seq_no <= this value (anti-replay).
	 */
	uint32_t last_seq_no_verified;

	/* Timestamp when key was loaded (for show output) */
	time_t loaded_at;
};

/*
 * bgp_crypto_key_cache
 *
 * One per BGP instance.  Embedded in struct bgp (added in Phase 3 when
 * VRF support is needed); for Phase 2 a single global instance is used.
 */
struct bgp_crypto_key_cache {
	/* FRR hash table — key: key_id (uint32_t), value: pubkey_entry * */
	struct hash *table;

	/* Total number of keys currently in the cache */
	uint32_t count;
};


/* =========================================================================
 * Key cache lifecycle
 * ========================================================================= */

/*
 * Initialise the global key cache.  Called once from bgp_init().
 * Returns 0 on success, -1 on failure (OOM).
 */
extern int bgp_crypto_key_cache_init(void);

/*
 * Destroy the global key cache and free all EVP_PKEY objects.
 * Called from bgp_finish().
 */
extern void bgp_crypto_key_cache_finish(void);

/*
 * Load a public key from a PEM file and add it to the global cache.
 *
 * @param origin_asn  ASN this key is authorised for (checked on verify)
 * @param pem_path    NUL-terminated filesystem path to the PEM public key file
 * @param[out] key_id Receives the computed key_id on success (may be NULL)
 *
 * Returns:
 *   0  — key loaded and added (or replaced) successfully
 *  -1  — file open / PEM parse error (error logged via zlog_warn)
 *  -2  — key_id collision with different ASN (logged, existing entry kept)
 *
 * Idempotent: calling with the same (origin_asn, pem_path) replaces the
 * existing entry and triggers re-verification of SIG_NO_PUBKEY paths.
 */
extern int bgp_crypto_pubkey_load(as_t origin_asn, const char *pem_path,
				  uint32_t *key_id);

/*
 * Remove a public key entry from the cache by origin ASN.
 * All paths whose key_id matched this entry are moved to SIG_NO_PUBKEY.
 *
 * Returns 0 if found and removed, -1 if not found.
 */
extern int bgp_crypto_pubkey_unload(as_t origin_asn);

/*
 * Look up a pubkey entry by key_id.
 * Returns the entry pointer, or NULL if not found.
 * Caller must NOT free the returned pointer.
 */
extern struct bgp_crypto_pubkey_entry *
bgp_crypto_key_lookup(uint32_t key_id);


/* =========================================================================
 * NLRI parse and build
 * ========================================================================= */

/*
 * bgp_nlri_parse_crypto_routes
 *
 * Top-level NLRI parser for SAFI_CRYPTO_ROUTES.  Called from
 * bgp_nlri_parse() in bgp_packet.c when nlri->safi == SAFI_CRYPTO_ROUTES.
 *
 * Reads one or more prefix+TLV entries from the NLRI stream, calls
 * bgp_crypto_verify_and_install() for each, and returns the standard
 * BGP_NLRI_PARSE_* error codes.
 *
 * @param peer      Originating peer
 * @param attr      Decoded path attributes
 * @param nlri      NLRI descriptor (afi, safi, raw byte buffer)
 * @param withdraw  true if this is from MP_UNREACH_NLRI
 */
extern int bgp_nlri_parse_crypto_routes(struct peer *peer, struct attr *attr,
					struct bgp_nlri *nlri, bool withdraw);

/*
 * bgp_crypto_routes_encode_nlri_trailer
 *
 * Append the Crypto-SIG TLV trailer for one prefix to an outgoing
 * MP_REACH_NLRI stream.  The caller (bgp_packet_mpattr_prefix in
 * bgp_attr.c) has already written the standard prefix length + bytes;
 * this function writes the trailer that immediately follows:
 *
 *   type   (1 octet  = BGP_CRYPTO_SIG_TLV_TYPE 0xCE)
 *   key_id (4 octets, big-endian)
 *   algo   (1 octet)
 *   sig_len(2 octets, big-endian)
 *   sig    (sig_len octets)
 *   seq_no (4 octets, big-endian)
 *
 * If path is NULL, path->extra is NULL, or path->extra->crypto is NULL
 * (route not yet signed, or a withdrawal placeholder) the function
 * writes nothing and returns 0.  This is intentional: unsigned prefixes
 * must still be encodable so the caller does not assert; the receiving
 * router will set sig_state = SIG_NONE and not install the route into FIB
 * (per the crypto-routes security policy).
 *
 * @param s     Output stream, positioned immediately after the prefix bytes.
 * @param path  bgp_path_info whose extra->crypto holds the signature data.
 *
 * Returns the number of bytes written (0 if no signature data available).
 */
extern int bgp_crypto_routes_encode_nlri_trailer(struct stream *s,
						 struct bgp_path_info *path);


/* =========================================================================
 * Signature verify / sign
 * ========================================================================= */

/*
 * bgp_crypto_verify
 *
 * Verify the ECDSA signature in a bgp_path_info_extra_crypto struct.
 * Constructs the signed-data buffer (prefix_bytes || asn || seq_no) and
 * calls OpenSSL EVP_DigestVerify.
 *
 * Sets extra->sig_state to SIG_VERIFIED, SIG_INVALID, or SIG_NO_PUBKEY.
 * Returns true if the signature is valid (sig_state == SIG_VERIFIED).
 *
 * Assumptions:
 *   - extra->key_id, sig_algo, sig_len, sig[], sequence_no are already
 *     populated (i.e. the TLV has been parsed).
 *   - origin_asn is the AS_PATH origin AS extracted from the received attr.
 *   - p is the prefix this NLRI carries.
 */
extern bool bgp_crypto_verify(struct bgp_path_info_extra_crypto *extra,
			      const struct prefix *p, as_t origin_asn);

/*
 * bgp_crypto_sign
 *
 * Sign a prefix for transmission.  Loads the private key from the path
 * stored in bgp->crypto_privkey_path, constructs the signed-data buffer,
 * and writes the resulting signature into extra->sig / extra->sig_len.
 *
 * Called when originating a new crypto-routes prefix announcement.
 *
 * @param extra       Per-path crypto struct to fill in (key_id, sig, etc.)
 * @param p           Prefix being announced
 * @param local_asn   This router's ASN (used as origin_asn in signed data)
 * @param seq_no      Monotonically increasing counter for this prefix
 * @param privkey_pem NUL-terminated path to the PEM private key file
 *
 * Returns 0 on success, -1 on error (key file not found, sign failure).
 */
extern int bgp_crypto_sign(struct bgp_path_info_extra_crypto *extra,
			   const struct prefix *p, as_t local_asn,
			   uint32_t seq_no, const char *privkey_pem);


/* =========================================================================
 * VTY show helpers
 * ========================================================================= */

/*
 * Show the contents of the public key cache.
 * Called from "show bgp crypto-routes pubkeys".
 */
extern void bgp_crypto_show_pubkeys(struct vty *vty, bool use_json,
				    json_object *json);

/*
 * Show per-path crypto signature state (one line per path).
 * Called from the show bgp ipv4/ipv6 crypto-routes VTY command.
 */
extern void bgp_crypto_show_path(struct vty *vty,
				 const struct bgp_path_info_extra_crypto *extra,
				 bool detail);


/* =========================================================================
 * Init / cleanup (called from bgp_init / bgp_finish in bgpd.c)
 * ========================================================================= */

extern void bgp_crypto_routes_init(void);
extern void bgp_crypto_routes_finish(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_CRYPTO_ROUTES_H */
