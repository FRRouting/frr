// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP crypto-routes experimental AFI/SAFI.
 */

#ifndef _FRR_BGP_CRYPTO_H
#define _FRR_BGP_CRYPTO_H

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"

struct attr;
struct bgp_nlri;
struct prefix;
struct stream;
struct vty;

#define BGP_CRYPTO_VERSION 1
#define BGP_CRYPTO_ROUTE_TYPE_PEER_METADATA 1

/*
 * v1 crypto-routes NLRI:
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | NLRI Length                   | Version                       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Route Type    | Peer-ID Len   | Peer-ID ...                   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | TLVs ...                                                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The NLRI Length excludes the optional AddPath Path Identifier and excludes
 * the NLRI Length field itself.
 */
#define BGP_CRYPTO_NLRI_LEN_SIZE 2
#define BGP_CRYPTO_NLRI_FIXED_SIZE 4
#define BGP_CRYPTO_TLV_HDR_SIZE 4
#define BGP_CRYPTO_NLRI_MAX_SIZE 512

enum bgp_crypto_tlv_type {
	BGP_CRYPTO_TLV_ALGORITHM = 1,
	BGP_CRYPTO_TLV_CERTIFICATE_ID = 2,
	BGP_CRYPTO_TLV_PUBLIC_KEY_ID = 3,
	BGP_CRYPTO_TLV_CAPABILITY_BITMAP = 4,
	BGP_CRYPTO_TLV_TRUST_LEVEL = 5,
};

enum bgp_crypto_capability_bit {
	BGP_CRYPTO_CAPABILITY_SIGN = 1ULL << 0,
	BGP_CRYPTO_CAPABILITY_VERIFY = 1ULL << 1,
	BGP_CRYPTO_CAPABILITY_ENCRYPT = 1ULL << 2,
};

int bgp_nlri_parse_crypto(struct peer *peer, struct attr *attr,
			  struct bgp_nlri *packet, bool withdraw);

void bgp_crypto_encode_nlri(struct stream *s, const struct prefix *p,
			    bool addpath_capable, uint32_t addpath_tx_id,
			    const struct bgp_path_info *path);
size_t bgp_crypto_nlri_size(const struct prefix *p);

int bgp_crypto_route_add(struct peer *peer, struct attr *attr,
			 const struct bgp_path_info_extra_crypto *crypto);
int bgp_crypto_route_delete(struct bgp *bgp, struct peer *peer,
			    const char *peer_id);

void bgp_crypto_config_write(struct vty *vty, struct bgp *bgp);
void bgp_crypto_vty_init(void);

const char *bgp_crypto_capability_str(uint64_t bitmap, char *buf, size_t len);

#endif /* _FRR_BGP_CRYPTO_H */
