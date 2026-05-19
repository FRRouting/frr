// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State (RFC 9552) - Core Constants and Structures
 * Copyright (C) 2025 Carmine Scarpitta
 */

#ifndef _FRR_BGP_LS_H
#define _FRR_BGP_LS_H

#include <typesafe.h>
#include "bgpd/bgpd.h"
#include "bgpd/bgp_ls_nlri.h"

PREDECL_DLIST(bgp_ls_endx_sid_list);

struct bgp_ls {
	/* Back-pointer to parent BGP instance */
	struct bgp *bgp;

	/* Hash table for BGP-LS NLRIs (nodes, links, prefixes) */
	struct bgp_ls_nlri_hash_head nlri_hash;

	/* Hash table for BGP-LS Attributes */
	struct bgp_ls_attr_hash_head ls_attr_hash;

	/* Traffic Engineering Database */
	struct ls_ted *ted;

	/* NLRI ID allocator */
	struct id_alloc *allocator;

	/* Link-state database registration status */
	bool registered_ls_db;

	bool enable_distribution;

	/* BGP-fabric link-state instance ID */
	uint64_t instance_id;

	/* Static End.X/uA SIDs associated to BGP links. */
	struct bgp_ls_endx_sid_list_head static_endx_sids;

	/* Number of active SRv6 locator Prefix NLRIs originated by BGP-LS. */
	uint32_t srv6_locator_nlri_count;
};

/* Function prototypes */

/*
 * ===========================================================================
 * RIB Operations
 * ===========================================================================
 */

/*
 * Install or update BGP-LS route in RIB
 *
 * This function handles locally originated BGP-LS routes from IGP.
 * It creates a synthetic prefix in the standard BGP RIB and stores
 * the full NLRI in bgp_path_info_extra->ls_nlri.
 *
 * @param bgp - BGP instance
 * @param nlri - Decoded BGP-LS NLRI
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_update(struct bgp *bgp, struct bgp_ls_nlri *nlri, struct bgp_ls_attr *ls_attr);

/*
 * Remove BGP-LS route from RIB
 *
 * This function handles withdrawal of locally originated BGP-LS routes.
 * It marks the route as removed and triggers BGP processing for
 * withdrawal advertisement to peers.
 *
 * @param bgp - BGP instance
 * @param nlri - Decoded BGP-LS NLRI
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_withdraw(struct bgp *bgp, struct bgp_ls_nlri *nlri);

/* BGP-LS NLRI parsing */
extern int bgp_nlri_parse_ls(struct peer *peer, struct attr *attr, struct bgp_nlri *packet);

/* BGP-LS registration with link-state database */
extern bool bgp_ls_register(struct bgp *bgp);
extern bool bgp_ls_unregister(struct bgp *bgp);
extern bool bgp_ls_is_registered(struct bgp *bgp);

/* BGP-LS NLRI lookup helpers */
extern struct bgp_dest *bgp_ls_lookup_nlri_by_str(struct bgp *bgp, const char *nlri_str);

/* BGP-LS NLRI helpers */
extern struct json_object *bgp_ls_nlri_to_json(struct bgp_ls_nlri *nlri);
extern void bgp_ls_nlri_format(struct bgp_ls_nlri *nlri, char *buf, size_t buf_len);

/* Module initialization and cleanup */
extern void bgp_ls_init(struct bgp *bgp);
extern void bgp_ls_cleanup(struct bgp *bgp);

/*
 * ===========================================================================
 * BGP Topology Export (BGP-only fabrics)
 * ===========================================================================
 */

/*
 * Export BGP topology as BGP-LS NLRIs
 *
 * Iterates through all BGP peers and generates Node and Link NLRIs
 * representing the BGP topology. Used for BGP-only fabrics per
 * draft-ietf-idr-bgp-ls-bgp-only-fabric.
 *
 * @param bgp - BGP instance
 * @return 0 on success, -1 on error
 */
extern int bgp_ls_export_bgp_topology(struct bgp *bgp);
void bgp_ls_withdraw_all(struct bgp *bgp);
int bgp_ls_withdraw_bgp_link(struct bgp *bgp, struct peer *peer);
int bgp_ls_withdraw_bgp_prefix(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *dest,
			       struct bgp_path_info *path);

extern int bgp_ls_upsert_bgp_link_srv6_endx_sid(struct bgp *bgp, const struct in6_addr *sid,
						uint8_t prefixlen, uint32_t action,
						const struct seg6local_context *ctx);
extern int bgp_ls_delete_bgp_link_srv6_endx_sid(struct bgp *bgp, const struct in6_addr *sid,
						uint8_t prefixlen);
extern int bgp_ls_originate_static_srv6_sid_from_seg6local(struct bgp *bgp,
							   const struct in6_addr *sid,
							   uint8_t prefixlen, uint32_t action,
							   const struct seg6local_context *ctx);
extern int bgp_ls_withdraw_static_srv6_sid(struct bgp *bgp, const struct in6_addr *sid,
					   uint8_t prefixlen);
extern void bgp_ls_handle_srv6_localsid_update(struct bgp *bgp, const struct prefix *p, afi_t afi,
					       uint8_t type, unsigned short instance,
					       uint32_t seg6local_action,
					       const struct seg6local_context *seg6local_ctx,
					       bool is_add);
extern int bgp_ls_originate_srv6_locator_prefix(struct bgp *bgp,
						const struct srv6_locator *locator);
extern int bgp_ls_withdraw_srv6_locator_prefix(struct bgp *bgp, const struct srv6_locator *locator);

/*
 * BGP-LS route handlers - abstraction layer for route redistribution
 *
 * These functions handle BGP-LS concerns (including SRv6 localsid) from
 * route redistribution events. Route code calls these handlers instead of
 * directly invoking SRv6-specific functions.
 */
extern int bgp_ls_handle_route_add(struct bgp *bgp, const struct prefix *p, afi_t afi,
				   uint8_t type, unsigned short instance, uint32_t seg6local_action,
				   const struct seg6local_context *seg6local_ctx);

extern int bgp_ls_handle_route_delete(struct bgp *bgp, const struct prefix *p, afi_t afi,
				      uint8_t type, unsigned short instance);

/*
 * ===========================================================================
 * Link State Message Processing
 * ===========================================================================
 */

extern int bgp_ls_originate_bgp_node(struct bgp *bgp);
extern int bgp_ls_originate_bgp_link(struct bgp *bgp, struct peer *peer);
extern int bgp_ls_originate_bgp_prefix(struct bgp *bgp, afi_t afi, safi_t safi,
				       struct bgp_dest *dest, struct bgp_path_info *path);

/*
 * ===========================================================================
 * Protocol-ID Predicate Helpers
 * ===========================================================================
 */
static inline bool bgp_ls_protocol_is_isis(enum bgp_ls_protocol_id protocol_id)
{
	return protocol_id == BGP_LS_PROTO_ISIS_L1 || protocol_id == BGP_LS_PROTO_ISIS_L2;
}

static inline bool bgp_ls_protocol_is_direct_static(enum bgp_ls_protocol_id protocol_id)
{
	return protocol_id == BGP_LS_PROTO_DIRECT || protocol_id == BGP_LS_PROTO_STATIC;
}

static inline bool bgp_ls_protocol_is_ospf(enum bgp_ls_protocol_id protocol_id)
{
	return protocol_id == BGP_LS_PROTO_OSPFV2 || protocol_id == BGP_LS_PROTO_OSPFV3;
}

#endif /* _FRR_BGP_LS_H */
