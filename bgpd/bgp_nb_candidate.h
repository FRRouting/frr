// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound candidate-tree helpers
 * Copyright (C) 2026 FRRouting
 */

#ifndef _FRR_BGP_NB_CANDIDATE_H_
#define _FRR_BGP_NB_CANDIDATE_H_

#include <stdbool.h>
#include <stddef.h>
#include "lib/compiler.h"
#include "lib/lib_errors.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/yang.h"
#include "bgpd/bgpd.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * P0-01: Derive instance type, logical name (NULL for default, VRF/view name
 * otherwise) and YANG vrf key from any node at or under a BGP
 * control-plane-protocol entry. Returns false if @dnode is not under a BGP
 * instance.
 */
bool bgp_nb_cand_instance_key(const struct lyd_node *dnode, enum bgp_instance_type *inst_type,
			      const char **name, const char **vrf);

/*
 * Return the active candidate tree root if inside a northbound transaction,
 * else the root of @dnode's tree (if non-NULL), else running_config->dnode.
 */
const struct lyd_node *bgp_nb_cand_root(const struct lyd_node *dnode);

/*
 * True if @cpp is a control-plane-protocol list entry with type frr-bgp:bgp.
 */
bool bgp_nb_cand_cpp_is_bgp(const struct lyd_node *cpp);

/*
 * P0-02: Iterate all BGP instances (frr-bgp:bgp nodes) in the candidate tree
 * (or in @tree_dnode's tree for the _in_tree variant). Stops early and returns
 * false if @cb returns false; otherwise returns true.
 */
typedef bool (*bgp_nb_cand_inst_cb)(const struct lyd_node *bgp_dnode, void *arg);
bool bgp_nb_cand_each_instance_in_tree(const struct lyd_node *tree_dnode, bgp_nb_cand_inst_cb cb,
				       void *arg);
bool bgp_nb_cand_each_instance(bgp_nb_cand_inst_cb cb, void *arg);

/*
 * P0-03: Candidate EVPN underlay helpers.
 * - bgp_nb_cand_evpn_enabled: true if the BGP instance containing @dnode has
 *   l2vpn-evpn/advertise-all-vni enabled in its tree.
 * - bgp_nb_cand_evpn_underlay: return the frr-bgp:bgp node that acts as the
 *   EVPN underlay in the candidate tree (the instance with advertise-all-vni
 *   enabled, else the default instance, else NULL).
 */
bool bgp_nb_cand_evpn_enabled(const struct lyd_node *dnode);
const struct lyd_node *bgp_nb_cand_evpn_underlay(const struct lyd_node *dnode);

/*
 * P0-04: Candidate peer-group membership helpers in both directions.
 */
const struct lyd_node *bgp_nb_cand_peer_node(const struct lyd_node *dnode);
const struct lyd_node *bgp_nb_cand_peer_group_by_name(const struct lyd_node *dnode,
						      const char *name);
const struct lyd_node *bgp_nb_cand_peer_group(const struct lyd_node *peer_dnode);

typedef bool (*bgp_nb_cand_member_cb)(const struct lyd_node *member_dnode, void *arg);
bool bgp_nb_cand_group_members(const struct lyd_node *group_dnode, bgp_nb_cand_member_cb cb,
			       void *arg);
bool bgp_nb_cand_group_members_match_sort(const struct lyd_node *group_dnode,
					  enum bgp_peer_sort req_sort, bool require_equal);

/*
 * P0-05: Deterministic candidate peer sort (IBGP / EBGP / CONFED / INTERNAL /
 * UNSPECIFIED), mirroring peer_calc_sort() using candidate YANG data only
 * (local-as, group-inherited remote-as/local-as, confederation identifier &
 * member-as, remote-as auto). Never reads daemon runtime state.
 */
enum bgp_peer_sort bgp_nb_cand_peer_sort(const struct lyd_node *peer_dnode);

/*
 * P0-06: Effective candidate AF activation helpers, including implicit
 * activation from global/default-afi-safi and peer-group inheritance.
 */
int bgp_nb_cand_parse_default_afi_safi(const char *afi_safi, afi_t *afi, safi_t *safi,
				       char *errmsg, size_t errmsg_len);
bool bgp_nb_cand_default_af(const struct lyd_node *dnode, afi_t afi, safi_t safi);
bool bgp_nb_cand_peer_af_enabled(const struct lyd_node *peer_dnode, afi_t afi, safi_t safi);
void bgp_nb_cand_enabled_afs(const struct lyd_node *peer_dnode, bool enabled[AFI_MAX][SAFI_MAX]);

/*
 * P0-07: Internal-inconsistency guard for NB_EV_APPLY.
 * Logs an error and returns false if @ptr is NULL so APPLY callers can return
 * NB_OK instead of NB_ERR_NOT_FOUND / NB_ERR_INCONSISTENCY.
 */
static inline bool _bgp_nb_assert_applied(const void *ptr, const char *what, const char *func,
					  int line)
{
	if (likely(ptr != NULL))
		return true;
	flog_err(EC_LIB_NB_CB_CONFIG_APPLY, "%s:%d: expected %s missing during NB APPLY", func,
		 line, what);
	return false;
}

#define bgp_nb_assert_applied(ptr, what) _bgp_nb_assert_applied((ptr), (what), __func__, __LINE__)

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_CANDIDATE_H_ */
