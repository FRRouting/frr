/*
 * This is an implementation of Segment Routing for IS-IS as per RFC 8667
 *
 * Copyright (C) 2019 Orange http://www.orange.com
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Contributor: Renato Westphal <renato@opensourcerouting.org> for NetDEF
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "log.h"
#include "command.h"
#include "termtable.h"
#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "zclient.h"
#include "lib/lib_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_route.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_errors.h"

/* Local variables and functions */
DEFINE_MTYPE_STATIC(ISISD, ISIS_SR_INFO, "ISIS segment routing information")

static void sr_prefix_uninstall(struct sr_prefix *srp);
static void sr_prefix_reinstall(struct sr_prefix *srp, bool make_before_break);
static void sr_local_block_delete(struct isis_area *area);
static int sr_local_block_init(struct isis_area *area);
static void sr_adj_sid_update(struct sr_adjacency *sra,
			      struct sr_local_block *srlb);

/* --- RB-Tree Management functions ----------------------------------------- */

/**
 * SR Prefix comparison for RB-Tree.
 *
 * @param a	First SR prefix
 * @param b	Second SR prefix
 *
 * @return	-1 (a < b), 0 (a == b) or +1 (a > b)
 */
static inline int sr_prefix_sid_compare(const struct sr_prefix *a,
					const struct sr_prefix *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}
DECLARE_RBTREE_UNIQ(srdb_node_prefix, struct sr_prefix, node_entry,
		    sr_prefix_sid_compare)
DECLARE_RBTREE_UNIQ(srdb_area_prefix, struct sr_prefix, area_entry,
		    sr_prefix_sid_compare)

/**
 * Configured SR Prefix comparison for RB-Tree.
 *
 * @param a	First SR prefix
 * @param b	Second SR prefix
 *
 * @return	-1 (a < b), 0 (a == b) or +1 (a > b)
 */
static inline int sr_prefix_sid_cfg_compare(const struct sr_prefix_cfg *a,
					    const struct sr_prefix_cfg *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}
DECLARE_RBTREE_UNIQ(srdb_prefix_cfg, struct sr_prefix_cfg, entry,
		    sr_prefix_sid_cfg_compare)

/**
 * SR Node comparison for RB-Tree.
 *
 * @param a	First SR node
 * @param b	Second SR node
 *
 * @return	-1 (a < b), 0 (a == b) or +1 (a > b)
 */
static inline int sr_node_compare(const struct sr_node *a,
				  const struct sr_node *b)
{
	return memcmp(a->sysid, b->sysid, ISIS_SYS_ID_LEN);
}
DECLARE_RBTREE_UNIQ(srdb_node, struct sr_node, entry, sr_node_compare)

/* --- Functions used for Yang model and CLI to configure Segment Routing --- */

/**
 * Check if prefix correspond to a Node SID.
 *
 * @param ifp	  Interface
 * @param prefix  Prefix to be checked
 *
 * @return	  True if the interface/address pair corresponds to a Node-SID
 */
static bool sr_prefix_is_node_sid(const struct interface *ifp,
				  const struct prefix *prefix)
{
	return (if_is_loopback(ifp) && is_host_route(prefix));
}

/**
 * Update local SRGB configuration. SRGB is reserved though Label Manager.
 * This function trigger the update of local Prefix-SID installation.
 *
 * @param area		IS-IS area
 * @param lower_bound	Lower bound of SRGB
 * @param upper_bound	Upper bound of SRGB
 *
 * @return		0 on success, -1 otherwise
 */
int isis_sr_cfg_srgb_update(struct isis_area *area, uint32_t lower_bound,
			    uint32_t upper_bound)
{
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("ISIS-Sr (%s): Update SRGB with new range [%u/%u]",
		 area->area_tag, lower_bound, upper_bound);

	/* Just store new SRGB values if Label Manager is not available.
	 * SRGB will be configured later when SR start */
	if (!isis_zebra_label_manager_ready()) {
		srdb->config.srgb_lower_bound = lower_bound;
		srdb->config.srgb_upper_bound = upper_bound;
		return 0;
	}

	/* Label Manager is ready, start by releasing the old SRGB. */
	if (srdb->srgb_active) {
	        isis_zebra_release_label_range(srdb->config.srgb_lower_bound,
					       srdb->config.srgb_upper_bound);
	        srdb->srgb_active = false;
	}

	srdb->config.srgb_lower_bound = lower_bound;
	srdb->config.srgb_upper_bound = upper_bound;

	if (srdb->enabled) {
		struct sr_prefix *srp;

		/* then request new SRGB if SR is enabled. */
		if (isis_zebra_request_label_range(
			    srdb->config.srgb_lower_bound,
			    srdb->config.srgb_upper_bound
				    - srdb->config.srgb_lower_bound + 1) < 0) {
			srdb->srgb_active = false;
			return -1;
		} else
			srdb->srgb_active = true;


		sr_debug("  |- Got new SRGB [%u/%u]",
			 srdb->config.srgb_lower_bound,
			 srdb->config.srgb_upper_bound);

		/* Reinstall local Prefix-SIDs to update their input labels. */
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			frr_each (srdb_area_prefix,
				  &area->srdb.prefix_sids[level - 1], srp) {
				sr_prefix_reinstall(srp, false);
			}
		}

		lsp_regenerate_schedule(area, area->is_type, 0);
	} else if (srdb->config.enabled) {
		/* Try to enable SR again using the new SRGB. */
		isis_sr_start(area);
	}

	return 0;
}

/**
 * Update Segment Routing Local Block range which is reserved though the
 * Label Manager. This function trigger the update of local Adjacency-SID
 * installation.
 *
 * @param area		IS-IS area
 * @param lower_bound	Lower bound of SRLB
 * @param upper_bound	Upper bound of SRLB
 *
 * @return		0 on success, -1 otherwise
 */
int isis_sr_cfg_srlb_update(struct isis_area *area, uint32_t lower_bound,
			    uint32_t upper_bound)
{
	struct isis_sr_db *srdb = &area->srdb;
	struct listnode *node;
	struct sr_adjacency *sra;

	sr_debug("ISIS-Sr (%s): Update SRLB with new range [%u/%u]",
		 area->area_tag, lower_bound, upper_bound);

	/* Just store new SRLB values if Label Manager is not available.
	 * SRLB will be configured later when SR start */
	if (!isis_zebra_label_manager_ready()) {
		srdb->config.srlb_lower_bound = lower_bound;
		srdb->config.srlb_upper_bound = upper_bound;
		return 0;
	}

	/* LM is ready, start by deleting the old SRLB */
	sr_local_block_delete(area);

	srdb->config.srlb_lower_bound = lower_bound;
	srdb->config.srlb_upper_bound = upper_bound;

	if (srdb->enabled) {
		/* Initialize new SRLB */
		if (sr_local_block_init(area) != 0)
			return -1;

		/* Reinstall local Adjacency-SIDs with new labels. */
		for (ALL_LIST_ELEMENTS_RO(area->srdb.adj_sids, node, sra))
			sr_adj_sid_update(sra, &srdb->srlb);

		/* Update and Flood LSP */
		lsp_regenerate_schedule(area, area->is_type, 0);
	} else if (srdb->config.enabled) {
		/* Try to enable SR again using the new SRLB. */
		isis_sr_start(area);
	}

	return 0;
}

/**
 * Add new Prefix-SID configuration to the SRDB.
 *
 * @param area	  IS-IS area
 * @param prefix  Prefix to be added
 *
 * @return	  Newly added Prefix-SID configuration structure
 */
struct sr_prefix_cfg *isis_sr_cfg_prefix_add(struct isis_area *area,
					     const struct prefix *prefix)
{
	struct sr_prefix_cfg *pcfg;
	struct interface *ifp;

	sr_debug("ISIS-Sr (%s): Add local prefix %pFX", area->area_tag, prefix);

	pcfg = XCALLOC(MTYPE_ISIS_SR_INFO, sizeof(*pcfg));
	pcfg->prefix = *prefix;
	pcfg->area = area;

	/* Pull defaults from the YANG module. */
	pcfg->sid_type = yang_get_default_enum(
		"%s/prefix-sid-map/prefix-sid/sid-value-type", ISIS_SR);
	pcfg->last_hop_behavior = yang_get_default_enum(
		"%s/prefix-sid-map/prefix-sid/last-hop-behavior", ISIS_SR);

	/* Set the N-flag when appropriate. */
	ifp = if_lookup_prefix(prefix, VRF_DEFAULT);
	if (ifp && sr_prefix_is_node_sid(ifp, prefix))
		pcfg->node_sid = true;

	/* Save prefix-sid configuration. */
	srdb_prefix_cfg_add(&area->srdb.config.prefix_sids, pcfg);

	return pcfg;
}

/**
 * Removal of locally configured Prefix-SID.
 *
 * @param pcfg	Configured Prefix-SID
 */
void isis_sr_cfg_prefix_del(struct sr_prefix_cfg *pcfg)
{
	struct isis_area *area = pcfg->area;

	sr_debug("ISIS-Sr (%s): Delete local Prefix-SID %pFX %s %u",
		 area->area_tag, &pcfg->prefix,
		 pcfg->sid_type == SR_SID_VALUE_TYPE_INDEX ? "index" : "label",
		 pcfg->sid);

	srdb_prefix_cfg_del(&area->srdb.config.prefix_sids, pcfg);
	XFREE(MTYPE_ISIS_SR_INFO, pcfg);
}

/**
 * Lookup for Prefix-SID in the local configuration.
 *
 * @param area	  IS-IS area
 * @param prefix  Prefix to lookup
 *
 * @return	  Configured Prefix-SID structure if found, NULL otherwise
 */
struct sr_prefix_cfg *isis_sr_cfg_prefix_find(struct isis_area *area,
					      union prefixconstptr prefix)
{
	struct sr_prefix_cfg pcfg = {};

	prefix_copy(&pcfg.prefix, prefix.p);
	return srdb_prefix_cfg_find(&area->srdb.config.prefix_sids, &pcfg);
}

/**
 * Fill in Prefix-SID Sub-TLV according to the corresponding configuration.
 *
 * @param pcfg	    Prefix-SID configuration
 * @param external  False if prefix is locally configured, true otherwise
 * @param psid	    Prefix-SID sub-TLV to be updated
 */
void isis_sr_prefix_cfg2subtlv(const struct sr_prefix_cfg *pcfg, bool external,
			       struct isis_prefix_sid *psid)
{
	/* Set SID algorithm. */
	psid->algorithm = SR_ALGORITHM_SPF;

	/* Set SID flags. */
	psid->flags = 0;
	switch (pcfg->last_hop_behavior) {
	case SR_LAST_HOP_BEHAVIOR_EXP_NULL:
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_NO_PHP);
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_EXPLICIT_NULL);
		break;
	case SR_LAST_HOP_BEHAVIOR_NO_PHP:
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_NO_PHP);
		UNSET_FLAG(psid->flags, ISIS_PREFIX_SID_EXPLICIT_NULL);
		break;
	case SR_LAST_HOP_BEHAVIOR_PHP:
		UNSET_FLAG(psid->flags, ISIS_PREFIX_SID_NO_PHP);
		UNSET_FLAG(psid->flags, ISIS_PREFIX_SID_EXPLICIT_NULL);
		break;
	}
	if (external)
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_READVERTISED);
	if (pcfg->node_sid)
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_NODE);

	/* Set SID value. */
	psid->value = pcfg->sid;
	if (pcfg->sid_type == SR_SID_VALUE_TYPE_ABSOLUTE) {
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_VALUE);
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_LOCAL);
	}
}

/* --- Segment Routing Prefix Management functions -------------------------- */

/**
 * Add Segment Routing Prefix to a given Segment Routing Node.
 *
 * @param area	  IS-IS area
 * @param srn	  Segment Routing Node
 * @param prefix  Prefix to be added
 * @param local	  True if prefix is locally configured, false otherwise
 * @param psid	  Prefix-SID sub-TLVs
 *
 * @return	  New Segment Routing Prefix structure
 */
static struct sr_prefix *sr_prefix_add(struct isis_area *area,
				       struct sr_node *srn,
				       union prefixconstptr prefix, bool local,
				       const struct isis_prefix_sid *psid)
{
	struct sr_prefix *srp;

	srp = XCALLOC(MTYPE_ISIS_SR_INFO, sizeof(*srp));
	prefix_copy(&srp->prefix, prefix.p);
	srp->sid = *psid;
	srp->input_label = MPLS_INVALID_LABEL;
	if (local) {
		srp->type = ISIS_SR_PREFIX_LOCAL;
		isis_sr_nexthop_reset(&srp->u.local.info);
	} else {
		srp->type = ISIS_SR_PREFIX_REMOTE;
		srp->u.remote.rinfo = NULL;
	}
	srp->srn = srn;
	srdb_node_prefix_add(&srn->prefix_sids, srp);
	/* TODO: this might fail if we have Anycast SIDs in the IS-IS area. */
	srdb_area_prefix_add(&area->srdb.prefix_sids[srn->level - 1], srp);

	sr_debug("  |- Added new SR Prefix-SID %pFX %s %u to SR Node %s",
		 &srp->prefix, IS_SID_VALUE(srp->sid.flags) ? "label" : "index",
		 srp->sid.value, sysid_print(srn->sysid));

	return srp;
}

/**
 * Remove given Segment Prefix from given Segment Routing Node.
 * Prefix-SID is un-installed first.
 *
 * @param area	IS-IS area
 * @param srn	Segment Routing Node
 * @param srp	Segment Routing Prefix
 */
static void sr_prefix_del(struct isis_area *area, struct sr_node *srn,
			  struct sr_prefix *srp)
{
	sr_debug("  |- Delete SR Prefix-SID %pFX %s %u to SR Node %s",
		 &srp->prefix, IS_SID_VALUE(srp->sid.flags) ? "label" : "index",
		 srp->sid.value, sysid_print(srn->sysid));

	sr_prefix_uninstall(srp);
	srdb_node_prefix_del(&srn->prefix_sids, srp);
	srdb_area_prefix_del(&area->srdb.prefix_sids[srn->level - 1], srp);
	XFREE(MTYPE_ISIS_SR_INFO, srp);
}

/**
 * Find Segment Routing Prefix by Area.
 *
 * @param area	  IS-IS area
 * @param level	  IS-IS level
 * @param prefix  Prefix to lookup
 *
 * @return	  Segment Routing Prefix structure if found, NULL otherwise
 */
static struct sr_prefix *sr_prefix_find_by_area(struct isis_area *area,
						int level,
						union prefixconstptr prefix)
{
	struct sr_prefix srp = {};

	prefix_copy(&srp.prefix, prefix.p);
	return srdb_area_prefix_find(&area->srdb.prefix_sids[level - 1], &srp);
}

/**
 * Find Segment Routing Prefix by Segment Routing Node.
 *
 * @param srn	  Segment Routing Node
 * @param prefix  Prefix to lookup
 *
 * @return	  Segment Routing Prefix structure if found, NULL otherwise
 */
static struct sr_prefix *sr_prefix_find_by_node(struct sr_node *srn,
						union prefixconstptr prefix)
{
	struct sr_prefix srp = {};

	prefix_copy(&srp.prefix, prefix.p);
	return srdb_node_prefix_find(&srn->prefix_sids, &srp);
}

/* --- Segment Routing Node Management functions ---------------------------- */

/**
 * Add Segment Routing Node to the Segment Routing Data Base.
 *
 * @param area	 IS-IS area
 * @param level	 IS-IS level
 * @param sysid	 Node System ID
 * @param cap	 Segment Routing Capability sub-TLVs
 *
 * @return	 New Segment Routing Node structure
 */
static struct sr_node *sr_node_add(struct isis_area *area, int level,
				   const uint8_t *sysid)
{
	struct sr_node *srn;

	srn = XCALLOC(MTYPE_ISIS_SR_INFO, sizeof(*srn));
	srn->level = level;
	memcpy(srn->sysid, sysid, ISIS_SYS_ID_LEN);
	srn->area = area;
	srdb_node_prefix_init(&srn->prefix_sids);
	srdb_node_add(&area->srdb.sr_nodes[level - 1], srn);

	sr_debug("  |- Added new SR Node %s", sysid_print(srn->sysid));

	return srn;
}

static void sr_node_del(struct isis_area *area, int level, struct sr_node *srn)
/**
 * Remove Segment Routing Node from the Segment Routing Data Base.
 * All Prefix-SID attached to this Segment Routing Node are removed first.
 *
 * @param area	 IS-IS area
 * @param level	 IS-IS level
 * @param srn	 Segment Routing Node to be deleted
 */
{

	sr_debug("  |- Delete SR Node %s", sysid_print(srn->sysid));

	/* Remove and uninstall Prefix-SIDs. */
	while (srdb_node_prefix_count(&srn->prefix_sids) > 0) {
		struct sr_prefix *srp;

		srp = srdb_node_prefix_first(&srn->prefix_sids);
		sr_prefix_del(area, srn, srp);
	}

	srdb_node_del(&area->srdb.sr_nodes[level - 1], srn);
	XFREE(MTYPE_ISIS_SR_INFO, srn);
}

/**
 * Find Segment Routing Node in the Segment Routing Data Base per system ID.
 *
 * @param area	 IS-IS area
 * @param level	 IS-IS level
 * @param sysid	 Node System ID to lookup
 *
 * @return	 Segment Routing Node structure if found, NULL otherwise
 */
static struct sr_node *sr_node_find(struct isis_area *area, int level,
				    const uint8_t *sysid)
{
	struct sr_node srn = {};

	memcpy(srn.sysid, sysid, ISIS_SYS_ID_LEN);
	return srdb_node_find(&area->srdb.sr_nodes[level - 1], &srn);
}

/**
 * Update Segment Routing Node following an SRGB update. This function
 * is called when a neighbor SR Node has updated its SRGB.
 *
 * @param area	 IS-IS area
 * @param level	 IS-IS level
 * @param sysid	 Segment Routing Node system ID
 */
static void sr_node_srgb_update(struct isis_area *area, int level,
				uint8_t *sysid)
{
	struct sr_prefix *srp;

	sr_debug("ISIS-Sr (%s): Update neighbors SR Node with new SRGB",
		 area->area_tag);

	frr_each (srdb_area_prefix, &area->srdb.prefix_sids[level - 1], srp) {
		struct listnode *node;
		struct isis_nexthop *nh;

		if (srp->type == ISIS_SR_PREFIX_LOCAL)
			continue;

		if (srp->u.remote.rinfo == NULL)
			continue;

		for (ALL_LIST_ELEMENTS_RO(srp->u.remote.rinfo->nexthops, node,
					  nh)) {
			if (memcmp(nh->sysid, sysid, ISIS_SYS_ID_LEN) != 0)
				continue;

			/*
			 * The Prefix-SID input label hasn't changed. We could
			 * re-install all Prefix-SID with "Make Before Break"
			 * option. Zebra layer will update output label(s) by
			 * adding new entry before removing the old one(s).
			 */
			sr_prefix_reinstall(srp, true);
			break;
		}
	}
}

/* --- Segment Routing Nexthop information Management functions ------------- */

/**
 * Update Segment Routing Nexthop.
 *
 * @param srnh	 Segment Routing next hop
 * @param label	 Output MPLS label
 */
void isis_sr_nexthop_update(struct sr_nexthop_info *srnh, mpls_label_t label)
{
	srnh->label = label;
	if (srnh->uptime == 0)
		srnh->uptime = time(NULL);
}

/**
 * Reset Segment Routing Nexthop.
 *
 * @param srnh	Segment Routing Nexthop
 */
void isis_sr_nexthop_reset(struct sr_nexthop_info *srnh)
{
	srnh->label = MPLS_INVALID_LABEL;
	srnh->uptime = 0;
}

/* --- Segment Routing Prefix-SID Management functions to configure LFIB ---- */

/**
 * Lookup IS-IS route in the Shortest Path Tree.
 *
 * @param area	   IS-IS area
 * @param tree_id  Shortest Path Tree identifier
 * @param srp	   Segment Routing Prefix to lookup
 *
 * @return	   Route Information for this prefix if found, NULL otherwise
 */
static struct isis_route_info *sr_prefix_lookup_route(struct isis_area *area,
						      enum spf_tree_id tree_id,
						      struct sr_prefix *srp)
{
	struct route_node *rn;
	int level = srp->srn->level;

	rn = route_node_lookup(area->spftree[tree_id][level - 1]->route_table,
			       &srp->prefix);
	if (rn) {
		route_unlock_node(rn);
		if (rn->info)
			return rn->info;
	}

	return NULL;
}

/**
 * Compute input label for the given Prefix-SID.
 *
 * @param srp	Segment Routing Prefix
 *
 * @return	MPLS label or MPLS_INVALID_LABEL in case of SRGB overflow
 */
static mpls_label_t sr_prefix_in_label(const struct sr_prefix *srp)
{
	const struct sr_node *srn = srp->srn;
	struct isis_area *area = srn->area;

	/* Return SID value as MPLS label if it is an Absolute SID */
	if (CHECK_FLAG(srp->sid.flags,
		       ISIS_PREFIX_SID_VALUE | ISIS_PREFIX_SID_LOCAL))
		return srp->sid.value;

	/* Check that SID index falls inside the SRGB */
	if (srp->sid.value >= (area->srdb.config.srgb_upper_bound
			       - area->srdb.config.srgb_lower_bound + 1)) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			  "%s: SID index %u falls outside local SRGB range",
			  __func__, srp->sid.value);
		return MPLS_INVALID_LABEL;
	}

	/* Return MPLS label as SID index + SRGB_lower_bound as per RFC 8667 */
	return (area->srdb.config.srgb_lower_bound + srp->sid.value);
}

/**
 * Compute output label for the given Prefix-SID.
 *
 * @param srp		Segment Routing Prefix
 * @param srn_nexthop	Segment Routing nexthop node
 * @param sysid		System ID of the SR node which advertised the Prefix-SID
 *
 * @return		MPLS label or MPLS_INVALID_LABEL in case of error
 */
static mpls_label_t sr_prefix_out_label(const struct sr_prefix *srp,
					const struct sr_node *srn_nexthop,
					const uint8_t *sysid)
{
	const struct sr_node *srn = srp->srn;

	/* Check if the nexthop SR Node is the last hop? */
	if (memcmp(sysid, srn->sysid, ISIS_SYS_ID_LEN) == 0) {
		/* SR-Node doesn't request NO-PHP. Return Implicit NULL label */
		if (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP))
			return MPLS_LABEL_IMPLICIT_NULL;

		/* SR-Node requests Implicit NULL Label */
		if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_EXPLICIT_NULL)) {
			if (srp->prefix.family == AF_INET)
				return MPLS_LABEL_IPV4_EXPLICIT_NULL;
			else
				return MPLS_LABEL_IPV6_EXPLICIT_NULL;
		}
		/* Fallthrough */
	}

	/* Return SID value as MPLS label if it is an Absolute SID */
	if (CHECK_FLAG(srp->sid.flags,
		       ISIS_PREFIX_SID_VALUE | ISIS_PREFIX_SID_LOCAL)) {
		/*
		 * V/L SIDs have local significance, so only adjacent routers
		 * can use them (RFC8667 section #2.1.1.1)
		 */
		if (srp->srn != srn_nexthop)
			return MPLS_INVALID_LABEL;
		return srp->sid.value;
	}

	/* Check that SID index falls inside the SRGB */
	if (srp->sid.value >= srn_nexthop->cap.srgb.range_size) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			  "%s: SID index %u falls outside remote SRGB range",
			  __func__, srp->sid.value);
		return MPLS_INVALID_LABEL;
	}

	/* Return MPLS label as SID index + SRGB_lower_bound as per RFC 8667 */
	return (srn_nexthop->cap.srgb.lower_bound + srp->sid.value);
}

/**
 * Process local Prefix-SID and install it if possible. Input label is
 * computed before installing it in LFIB.
 *
 * @param srp	Segment Routing Prefix
 *
 * @return	0 on success, -1 otherwise
 */
static int sr_prefix_install_local(struct sr_prefix *srp)
{
	mpls_label_t input_label;
	const struct sr_node *srn = srp->srn;

	/*
	 * No need to install Label for local Prefix-SID unless the
	 * no-PHP option is configured.
	 */
	if (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP)
	    || CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_EXPLICIT_NULL))
		return -1;

	sr_debug("  |- Installing Prefix-SID %pFX %s %u (%s) with nexthop self",
		 &srp->prefix, IS_SID_VALUE(srp->sid.flags) ? "label" : "index",
		 srp->sid.value, circuit_t2string(srn->level));

	/* Compute input label and check that is valid. */
	input_label = sr_prefix_in_label(srp);
	if (input_label == MPLS_INVALID_LABEL)
		return -1;

	/* Update internal state. */
	srp->input_label = input_label;
	isis_sr_nexthop_update(&srp->u.local.info, MPLS_LABEL_IMPLICIT_NULL);

	/* Install Prefix-SID in the forwarding plane. */
	isis_zebra_send_prefix_sid(ZEBRA_MPLS_LABELS_REPLACE, srp);

	return 0;
}

/**
 * Process remote Prefix-SID and install it if possible. Input and Output
 * labels are computed before installing them in LFIB.
 *
 * @param srp	Segment Routing Prefix
 *
 * @return	0 on success, -1 otherwise
 */
static int sr_prefix_install_remote(struct sr_prefix *srp)
{
	const struct sr_node *srn = srp->srn;
	struct isis_area *area = srn->area;
	enum spf_tree_id tree_id;
	struct listnode *node;
	struct isis_nexthop *nexthop;
	mpls_label_t input_label;
	size_t nexthop_num = 0;

	/* Lookup to associated IS-IS route. */
	tree_id = (srp->prefix.family == AF_INET) ? SPFTREE_IPV4 : SPFTREE_IPV6;
	srp->u.remote.rinfo = sr_prefix_lookup_route(area, tree_id, srp);
	if (!srp->u.remote.rinfo)
		/* SPF hasn't converged for this route yet. */
		return -1;

	/* Compute input label and check that is valid. */
	input_label = sr_prefix_in_label(srp);
	if (input_label == MPLS_INVALID_LABEL)
		return -1;

	sr_debug("  |- Installing Prefix-SID %pFX %s %u (%s)", &srp->prefix,
		 IS_SID_VALUE(srp->sid.flags) ? "label" : "index",
		 srp->sid.value, circuit_t2string(srn->level));

	/* Process all SPF nexthops */
	for (ALL_LIST_ELEMENTS_RO(srp->u.remote.rinfo->nexthops, node,
				  nexthop)) {
		struct sr_node *srn_nexthop;
		mpls_label_t output_label;

		/* Check if the nexthop advertised a SRGB. */
		srn_nexthop = sr_node_find(area, srn->level, nexthop->sysid);
		if (!srn_nexthop)
			goto next;

		/*
		 * Check if the nexthop can handle SR-MPLS encapsulated IPv4 or
		 * IPv6 packets.
		 */
		if ((nexthop->family == AF_INET
		     && !IS_SR_IPV4(srn_nexthop->cap.srgb))
		    || (nexthop->family == AF_INET6
			&& !IS_SR_IPV6(srn_nexthop->cap.srgb)))
			goto next;

		/* Compute output label and check if it is valid */
		output_label =
			sr_prefix_out_label(srp, srn_nexthop, nexthop->sysid);
		if (output_label == MPLS_INVALID_LABEL)
			goto next;

		if (IS_DEBUG_SR) {
			static char buf[INET6_ADDRSTRLEN];

			inet_ntop(nexthop->family, &nexthop->ip, buf,
				  sizeof(buf));
			zlog_debug("    |- nexthop %s label %u", buf,
				   output_label);
		}

		isis_sr_nexthop_update(&nexthop->sr, output_label);
		nexthop_num++;
		continue;
	next:
		isis_sr_nexthop_reset(&nexthop->sr);
	}

	/* Check that we found at least one valid nexthop */
	if (nexthop_num == 0) {
		sr_debug("    |- no valid nexthops");
		return -1;
	}

	/* Update internal state. */
	srp->input_label = input_label;

	/* Install Prefix-SID in the forwarding plane. */
	isis_zebra_send_prefix_sid(ZEBRA_MPLS_LABELS_REPLACE, srp);

	return 0;
}

/**
 * Process local or remote Prefix-SID and install it if possible.
 *
 * @param srp	Segment Routing Prefix
 */
static void sr_prefix_install(struct sr_prefix *srp)
{
	const struct sr_node *srn = srp->srn;
	struct isis_area *area = srn->area;
	int ret;

	sr_debug("ISIS-Sr (%s): Install Prefix-SID %pFX %s %u", area->area_tag,
		 &srp->prefix, IS_SID_VALUE(srp->sid.flags) ? "label" : "index",
		 srp->sid.value);

	/* L1 routes are preferred over the L2 ones. */
	if (area->is_type == IS_LEVEL_1_AND_2) {
		struct sr_prefix *srp_l1, *srp_l2;

		switch (srn->level) {
		case ISIS_LEVEL1:
			srp_l2 = sr_prefix_find_by_area(area, ISIS_LEVEL2,
							&srp->prefix);
			if (srp_l2)
				sr_prefix_uninstall(srp_l2);
			break;
		case ISIS_LEVEL2:
			srp_l1 = sr_prefix_find_by_area(area, ISIS_LEVEL1,
							&srp->prefix);
			if (srp_l1)
				return;
			break;
		default:
			break;
		}
	}

	/* Install corresponding LFIB entry */
	if (srp->type == ISIS_SR_PREFIX_LOCAL)
		ret = sr_prefix_install_local(srp);
	else
		ret = sr_prefix_install_remote(srp);
	if (ret != 0)
		sr_prefix_uninstall(srp);
}

/**
 * Uninstall local or remote Prefix-SID.
 *
 * @param srp	Segment Routing Prefix
 */
static void sr_prefix_uninstall(struct sr_prefix *srp)
{
	struct listnode *node;
	struct isis_nexthop *nexthop;

	/* Check that Input Label is valid */
	if (srp->input_label == MPLS_INVALID_LABEL)
		return;

	sr_debug("ISIS-Sr: Un-install Prefix-SID %pFX %s %u", &srp->prefix,
		 IS_SID_VALUE(srp->sid.flags) ? "label" : "index",
		 srp->sid.value);

	/* Uninstall Prefix-SID from the forwarding plane. */
	isis_zebra_send_prefix_sid(ZEBRA_MPLS_LABELS_DELETE, srp);

	/* Reset internal state. */
	srp->input_label = MPLS_INVALID_LABEL;
	switch (srp->type) {
	case ISIS_SR_PREFIX_LOCAL:
		isis_sr_nexthop_reset(&srp->u.local.info);
		break;
	case ISIS_SR_PREFIX_REMOTE:
		if (srp->u.remote.rinfo) {
			for (ALL_LIST_ELEMENTS_RO(srp->u.remote.rinfo->nexthops,
						  node, nexthop))
				isis_sr_nexthop_reset(&nexthop->sr);
		}
		break;
	}
}

/**
 * Reinstall local or remote Prefix-SID.
 *
 * @param srp	Segment Routing Prefix
 */
static inline void sr_prefix_reinstall(struct sr_prefix *srp,
				       bool make_before_break)
{
	/*
	 * Make Before Break can be used only when we know for sure that
	 * the Prefix-SID input label hasn't changed. Otherwise we need to
	 * uninstall the Prefix-SID first using the old input label before
	 * reinstalling it.
	 */
	if (!make_before_break)
		sr_prefix_uninstall(srp);

	/* New input label is computed in sr_prefix_install() function */
	sr_prefix_install(srp);
}

/* --- IS-IS LSP Parse functions -------------------------------------------- */

/**
 * Compare Router Capabilities. Only Flags, SRGB and Algorithm are used for the
 * comparison. MSD and SRLB modification must not trigger and SR-Prefix update.
 *
 * @param r1	First Router Capabilities to compare
 * @param r2	Second Router Capabilities to compare
 * @return	0 if r1 and r2 are equal or -1 otherwise
 */
static int router_cap_cmp(const struct isis_router_cap *r1,
			  const struct isis_router_cap *r2)
{
	if (r1->flags == r2->flags
	    && r1->srgb.lower_bound == r2->srgb.lower_bound
	    && r1->srgb.range_size == r2->srgb.range_size
	    && r1->algo[0] == r2->algo[0])
		return 0;
	else
		return -1;
}

/**
 * Parse all SR-related information from the given Router Capabilities TLV.
 *
 * @param area		IS-IS area
 * @param level		IS-IS level
 * @param sysid		System ID of the LSP
 * @param router_cap	Router Capability subTLVs
 *
 * @return		Segment Routing Node structure for this System ID
 */
static struct sr_node *
parse_router_cap_tlv(struct isis_area *area, int level, const uint8_t *sysid,
		     const struct isis_router_cap *router_cap)
{
	struct sr_node *srn;

	if (!router_cap || router_cap->srgb.range_size == 0)
		return NULL;

	sr_debug("ISIS-Sr (%s): Parse Router Capability TLV", area->area_tag);

	srn = sr_node_find(area, level, sysid);
	if (srn) {
		if (router_cap_cmp(&srn->cap, router_cap) != 0) {
			srn->state = SRDB_STATE_MODIFIED;
		} else
			srn->state = SRDB_STATE_UNCHANGED;
		sr_debug("  |- Found %s SR Node %s",
			 srn->state == SRDB_STATE_MODIFIED ? "Modified"
							   : "Unchanged",
			 sysid_print(srn->sysid));
	} else {
		srn = sr_node_add(area, level, sysid);
		srn->state = SRDB_STATE_NEW;
	}

	/*
	 * Update Router Capabilities in any case as SRLB or MSD
	 * modification are not take into account for comparison.
	 */
	srn->cap = *router_cap;

	return srn;
}

/**
 * Parse list of Prefix-SID Sub-TLVs.
 *
 * @param srn		Segment Routing Node
 * @param prefix	Prefix to be parsed
 * @param local		True if prefix comes from own LSP, false otherwise
 * @param prefix_sids	Prefix SID subTLVs
 */
static void parse_prefix_sid_subtlvs(struct sr_node *srn,
				     union prefixconstptr prefix, bool local,
				     struct isis_item_list *prefix_sids)
{
	struct isis_area *area = srn->area;
	struct isis_item *i;

	sr_debug("ISIS-Sr (%s): Parse Prefix SID TLV", area->area_tag);

	/* Parse list of Prefix SID subTLVs */
	for (i = prefix_sids->head; i; i = i->next) {
		struct isis_prefix_sid *psid = (struct isis_prefix_sid *)i;
		struct sr_prefix *srp;

		/* Only SPF algorithm is supported right now */
		if (psid->algorithm != SR_ALGORITHM_SPF)
			continue;

		/* Compute corresponding Segment Routing Prefix */
		srp = sr_prefix_find_by_node(srn, prefix);
		if (srp) {
			if (srp->sid.flags != psid->flags
			    || srp->sid.algorithm != psid->algorithm
			    || srp->sid.value != psid->value) {
				srp->sid = *psid;
				srp->state = SRDB_STATE_MODIFIED;
			} else if (srp->state == SRDB_STATE_VALIDATED)
				srp->state = SRDB_STATE_UNCHANGED;
			sr_debug("  |- Found %s Prefix-SID %pFX",
				 srp->state == SRDB_STATE_MODIFIED
					 ? "Modified"
					 : "Unchanged",
				 &srp->prefix);

		} else {
			srp = sr_prefix_add(area, srn, prefix, local, psid);
			srp->state = SRDB_STATE_NEW;
		}
		/*
		 * Stop the Prefix-SID iteration since we only support the SPF
		 * algorithm for now.
		 */
		break;
	}
}

/**
 * Parse all SR-related information from the given LSP.
 *
 * @param area	IS-IS area
 * @param level	IS-IS level
 * @param srn	Segment Routing Node
 * @param lsp	IS-IS LSP
 */
static void parse_lsp(struct isis_area *area, int level, struct sr_node **srn,
		      struct isis_lsp *lsp)
{
	struct isis_item_list *items;
	struct isis_item *i;
	bool local = lsp->own_lsp;

	/* Check LSP sequence number */
	if (lsp->hdr.seqno == 0) {
		zlog_warn("%s: lsp with 0 seq_num - ignore", __func__);
		return;
	}

	sr_debug("ISIS-Sr (%s): Parse LSP from node %s", area->area_tag,
		 sysid_print(lsp->hdr.lsp_id));

	/* Parse the Router Capability TLV. */
	if (*srn == NULL) {
		*srn = parse_router_cap_tlv(area, level, lsp->hdr.lsp_id,
					    lsp->tlvs->router_cap);
		if (!*srn)
			return;
	}

	/* Parse the Extended IP Reachability TLV. */
	items = &lsp->tlvs->extended_ip_reach;
	for (i = items->head; i; i = i->next) {
		struct isis_extended_ip_reach *ir;

		ir = (struct isis_extended_ip_reach *)i;
		if (!ir->subtlvs)
			continue;

		parse_prefix_sid_subtlvs(*srn, &ir->prefix, local,
					 &ir->subtlvs->prefix_sids);
	}

	/* Parse Multi Topology Reachable IPv6 Prefixes TLV. */
	items = isis_lookup_mt_items(&lsp->tlvs->mt_ipv6_reach,
				     ISIS_MT_IPV6_UNICAST);
	for (i = items ? items->head : NULL; i; i = i->next) {
		struct isis_ipv6_reach *ir;

		ir = (struct isis_ipv6_reach *)i;
		if (!ir->subtlvs)
			continue;

		parse_prefix_sid_subtlvs(*srn, &ir->prefix, local,
					 &ir->subtlvs->prefix_sids);
	}
}

/**
 * Parse all SR-related information from the entire LSPDB.
 *
 * @param area	IS-IS area
 */
static void parse_lspdb(struct isis_area *area)
{
	struct isis_lsp *lsp;

	sr_debug("ISIS-Sr (%s): Parse LSP Data Base", area->area_tag);

	/* Process all LSP from Level 1 & 2 */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		frr_each (lspdb, &area->lspdb[level - 1], lsp) {
			struct isis_lsp *frag;
			struct listnode *node;
			struct sr_node *srn = NULL;

			/* Skip Pseudo ID LSP and LSP without TLVs */
			if (LSP_PSEUDO_ID(lsp->hdr.lsp_id))
				continue;
			if (!lsp->tlvs)
				continue;

			/* Parse LSP, then fragment */
			parse_lsp(area, level, &srn, lsp);
			for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag))
				parse_lsp(area, level, &srn, frag);
		}
	}
}

/**
 * Process any new/deleted/modified Prefix-SID in the LSPDB.
 *
 * @param srn	Segment Routing Node
 * @param srp	Segment Routing Prefix
 */
static void process_prefix_changes(struct sr_node *srn, struct sr_prefix *srp)
{
	struct isis_area *area = srn->area;

	/* Install/reinstall/uninstall Prefix-SID if necessary. */
	switch (srp->state) {
	case SRDB_STATE_NEW:
		sr_debug("ISIS-Sr (%s): Created Prefix-SID %pFX for SR node %s",
			 area->area_tag, &srp->prefix, sysid_print(srn->sysid));
		sr_prefix_install(srp);
		break;
	case SRDB_STATE_MODIFIED:
		sr_debug(
			"ISIS-Sr (%s): Modified Prefix-SID %pFX for SR node %s",
			area->area_tag, &srp->prefix, sysid_print(srn->sysid));
		sr_prefix_reinstall(srp, false);
		break;
	case SRDB_STATE_UNCHANGED:
		break;
	default:
		sr_debug("ISIS-Sr (%s): Removed Prefix-SID %pFX for SR node %s",
			 area->area_tag, &srp->prefix, sysid_print(srn->sysid));
		sr_prefix_del(area, srn, srp);
		return;
	}

	/* Validate SRDB State for next LSPDB parsing */
	srp->state = SRDB_STATE_VALIDATED;
}

/**
 * Process any new/deleted/modified SRGB in the LSPDB.
 *
 * @param area	IS-IS area
 * @param level	IS-IS level
 * @param srn	Segment Routing Node
 */
static void process_node_changes(struct isis_area *area, int level,
				 struct sr_node *srn)
{
	struct sr_prefix *srp;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	bool adjacent;

	memcpy(sysid, srn->sysid, sizeof(sysid));

	/*
	 * If an neighbor router's SRGB was changed or created, then reinstall
	 * all Prefix-SIDs from all nodes that use this neighbor as nexthop.
	 */
	adjacent = !!isis_adj_find(area, level, sysid);
	switch (srn->state) {
	case SRDB_STATE_NEW:
	case SRDB_STATE_MODIFIED:
		sr_debug("ISIS-Sr (%s): Create/Update SR node %s",
			 area->area_tag, sysid_print(srn->sysid));
		if (adjacent)
			sr_node_srgb_update(area, level, sysid);
		break;
	case SRDB_STATE_UNCHANGED:
		break;
	default:
		/* SR capabilities have been removed. Delete SR-Node */
		sr_debug("ISIS-Sr (%s): Remove SR node %s", area->area_tag,
			 sysid_print(srn->sysid));

		sr_node_del(area, level, srn);
		/* and Update remaining Prefix-SID from all remaining SR Node */
		if (adjacent)
			sr_node_srgb_update(area, level, sysid);
		return;
	}

	/* Validate SRDB State for next LSPDB parsing */
	srn->state = SRDB_STATE_VALIDATED;

	/* Finally, process all Prefix-SID of this SR Node */
	frr_each_safe (srdb_node_prefix, &srn->prefix_sids, srp)
		process_prefix_changes(srn, srp);
}

/**
 * Parse and process all SR-related Sub-TLVs after running the SPF algorithm.
 *
 * @param area	IS-IS area
 */
void isis_area_verify_sr(struct isis_area *area)
{
	struct sr_node *srn;

	if (!area->srdb.enabled)
		return;

	/* Parse LSPDB to detect new/deleted/modified SR (sub-)TLVs. */
	parse_lspdb(area);

	/* Process possible SR-related changes in the LDPSB. */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		frr_each_safe (srdb_node, &area->srdb.sr_nodes[level - 1], srn)
			process_node_changes(area, level, srn);
	}
}

/**
 * Once a route is updated in the SPT, reinstall or uninstall its corresponding
 * Prefix-SID (if any).
 *
 * @param area		IS-IS area
 * @param prefix	Prefix to be updated
 * @param route_info	New Route Information
 *
 * @return		0
 */
static int sr_route_update(struct isis_area *area, struct prefix *prefix,
			   struct isis_route_info *route_info)
{
	struct sr_prefix *srp;

	if (!area->srdb.enabled)
		return 0;

	sr_debug("ISIS-Sr (%s): Update route for prefix %pFX", area->area_tag,
		 prefix);

	/* Lookup to Segment Routing Prefix for this prefix */
	switch (area->is_type) {
	case IS_LEVEL_1:
		srp = sr_prefix_find_by_area(area, ISIS_LEVEL1, prefix);
		break;
	case IS_LEVEL_2:
		srp = sr_prefix_find_by_area(area, ISIS_LEVEL2, prefix);
		break;
	case IS_LEVEL_1_AND_2:
		srp = sr_prefix_find_by_area(area, ISIS_LEVEL1, prefix);
		if (!srp)
			srp = sr_prefix_find_by_area(area, ISIS_LEVEL2, prefix);
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown area level",
			 __func__);
		exit(1);
	}

	/* Skip NULL or local Segment Routing Prefix */
	if (!srp || srp->type == ISIS_SR_PREFIX_LOCAL)
		return 0;

	/* Install or unintall Prefix-SID if route is Active or not */
	if (CHECK_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ACTIVE)) {
		/*
		 * The Prefix-SID input label hasn't changed. We could use the
		 * "Make Before Break" option. Zebra layer will update output
		 * label by adding new label(s) before removing old one(s).
		 */
		sr_prefix_reinstall(srp, true);
		srp->u.remote.rinfo = route_info;
	} else {
		sr_prefix_uninstall(srp);
		srp->u.remote.rinfo = NULL;
	}

	return 0;
}

/* --- Segment Routing Local Block management functions --------------------- */

/**
 * Initialize Segment Routing Local Block from SRDB configuration and reserve
 * block of bits to manage label allocation.
 *
 * @param area	IS-IS area
 */
static int sr_local_block_init(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;
	struct sr_local_block *srlb = &srdb->srlb;

	/* Check if SRLB is not already configured */
	if (srlb->active)
		return 0;

	/*
	 * Request SRLB to the label manager. If the allocation fails, return
	 * an error to disable SR until a new SRLB is successfully allocated.
	 */
	if (isis_zebra_request_label_range(
		    srdb->config.srlb_lower_bound,
		    srdb->config.srlb_upper_bound
			    - srdb->config.srlb_lower_bound + 1)) {
		srlb->active = false;
		return -1;
	}

	sr_debug("ISIS-Sr (%s): Got new SRLB [%u/%u]", area->area_tag,
		 srdb->config.srlb_lower_bound, srdb->config.srlb_upper_bound);

	/* Initialize the SRLB */
	srlb->start = srdb->config.srlb_lower_bound;
	srlb->end = srdb->config.srlb_upper_bound;
	srlb->current = 0;
	/* Compute the needed Used Mark number and allocate them */
	srlb->max_block = (srlb->end - srlb->start + 1) / SRLB_BLOCK_SIZE;
	if (((srlb->end - srlb->start + 1) % SRLB_BLOCK_SIZE) != 0)
		srlb->max_block++;
	srlb->used_mark = XCALLOC(MTYPE_ISIS_SR_INFO,
				  srlb->max_block * SRLB_BLOCK_SIZE);
	srlb->active = true;

	return 0;
}

/**
 * Remove Segment Routing Local Block.
 *
 * @param area	IS-IS area
 */
static void sr_local_block_delete(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;
	struct sr_local_block *srlb = &srdb->srlb;

	/* Check if SRLB is not already delete */
	if (!srlb->active)
		return;

	sr_debug("ISIS-Sr (%s): Remove SRLB [%u/%u]", area->area_tag,
		 srlb->start, srlb->end);

	/* First release the label block */
	isis_zebra_release_label_range(srdb->config.srlb_lower_bound,
				       srdb->config.srlb_upper_bound);

	/* Then reset SRLB structure */
	if (srlb->used_mark != NULL)
		XFREE(MTYPE_ISIS_SR_INFO, srlb->used_mark);
	srlb->active = false;
}

/**
 * Request a label from the Segment Routing Local Block.
 *
 * @param srlb	Segment Routing Local Block
 *
 * @return	First available label on success or MPLS_INVALID_LABEL if the
 * 		block of labels is full
 */
static mpls_label_t sr_local_block_request_label(struct sr_local_block *srlb)
{

	mpls_label_t label;
	uint32_t index;
	uint32_t pos;

	/* Check if we ran out of available labels */
	if (srlb->current >= srlb->end)
		return MPLS_INVALID_LABEL;

	/* Get first available label and mark it used */
	label = srlb->current + srlb->start;
	index = srlb->current / SRLB_BLOCK_SIZE;
	pos = 1ULL << (srlb->current % SRLB_BLOCK_SIZE);
	srlb->used_mark[index] |= pos;

	/* Jump to the next free position */
	srlb->current++;
	pos = srlb->current % SRLB_BLOCK_SIZE;
	while (srlb->current < srlb->end) {
		if (pos == 0)
			index++;
		if (!((1ULL << pos) & srlb->used_mark[index]))
			break;
		else {
			srlb->current++;
			pos = srlb->current % SRLB_BLOCK_SIZE;
		}
	}

	return label;
}

/**
 * Release label in the Segment Routing Local Block.
 *
 * @param srlb	Segment Routing Local Block
 * @param label	Label to be release
 *
 * @return	0 on success or -1 if label falls outside SRLB
 */
static int sr_local_block_release_label(struct sr_local_block *srlb,
					mpls_label_t label)
{
	uint32_t index;
	uint32_t pos;

	/* Check that label falls inside the SRLB */
	if ((label < srlb->start) || (label > srlb->end)) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			"%s: Returning label %u is outside SRLB [%u/%u]",
			__func__, label, srlb->start, srlb->end);
		return -1;
	}

	index = (label - srlb->start) / SRLB_BLOCK_SIZE;
	pos = 1ULL << ((label - srlb->start) % SRLB_BLOCK_SIZE);
	srlb->used_mark[index] &= ~pos;
	/* Reset current to the first available position */
	for (index = 0; index < srlb->max_block; index++) {
		if (srlb->used_mark[index] != 0xFFFFFFFFFFFFFFFF) {
			for (pos = 0; pos < SRLB_BLOCK_SIZE; pos++)
				if (!((1ULL << pos) & srlb->used_mark[index])) {
					srlb->current =
						index * SRLB_BLOCK_SIZE + pos;
					break;
				}
			break;
		}
	}

	return 0;
}

/* --- Segment Routing Adjacency-SID management functions ------------------- */

/**
 * Add new local Adjacency-SID.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 * @param backup  True to initialize backup Adjacency SID
 */
static void sr_adj_sid_add_single(struct isis_adjacency *adj, int family,
				  bool backup)
{
	struct isis_circuit *circuit = adj->circuit;
	struct isis_area *area = circuit->area;
	struct sr_adjacency *sra;
	struct isis_adj_sid *adj_sid;
	struct isis_lan_adj_sid *ladj_sid;
	union g_addr nexthop = {};
	uint8_t flags;
	mpls_label_t input_label;

	sr_debug("ISIS-Sr (%s): Add %s Adjacency SID", area->area_tag,
		 backup ? "Backup" : "Primary");

	/* Determine nexthop IP address */
	switch (family) {
	case AF_INET:
		if (!circuit->ip_router || !adj->ipv4_address_count)
			return;

		nexthop.ipv4 = adj->ipv4_addresses[0];
		break;
	case AF_INET6:
		if (!circuit->ipv6_router || !adj->ipv6_address_count)
			return;

		nexthop.ipv6 = adj->ipv6_addresses[0];
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT,
			 "%s: unexpected address-family: %u", __func__, family);
		exit(1);
	}

	/* Prepare Segment Routing Adjacency as per RFC8667 section #2.2 */
	flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
	if (family == AF_INET6)
		SET_FLAG(flags, EXT_SUBTLV_LINK_ADJ_SID_FFLG);
	if (backup)
		SET_FLAG(flags, EXT_SUBTLV_LINK_ADJ_SID_BFLG);

	/* Get a label from the SRLB for this Adjacency */
	input_label = sr_local_block_request_label(&area->srdb.srlb);
	if (input_label == MPLS_INVALID_LABEL)
		return;

	if (circuit->ext == NULL)
		circuit->ext = isis_alloc_ext_subtlvs();

	sra = XCALLOC(MTYPE_ISIS_SR_INFO, sizeof(*sra));
	sra->type = backup ? ISIS_SR_LAN_BACKUP : ISIS_SR_ADJ_NORMAL;
	sra->nexthop.family = family;
	sra->nexthop.address = nexthop;
	sra->nexthop.label = input_label;
	switch (circuit->circ_type) {
	/* LAN Adjacency-SID for Broadcast interface section #2.2.2 */
	case CIRCUIT_T_BROADCAST:
		ladj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*ladj_sid));
		ladj_sid->family = family;
		ladj_sid->flags = flags;
		ladj_sid->weight = 0;
		memcpy(ladj_sid->neighbor_id, adj->sysid,
		       sizeof(ladj_sid->neighbor_id));
		ladj_sid->sid = input_label;
		isis_tlvs_add_lan_adj_sid(circuit->ext, ladj_sid);
		sra->u.ladj_sid = ladj_sid;
		break;
	/* Adjacency-SID for Point to Point interface section #2.2.1 */
	case CIRCUIT_T_P2P:
		adj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*adj_sid));
		adj_sid->family = family;
		adj_sid->flags = flags;
		adj_sid->weight = 0;
		adj_sid->sid = input_label;
		isis_tlvs_add_adj_sid(circuit->ext, adj_sid);
		sra->u.adj_sid = adj_sid;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}

	/* Add Adjacency-SID in SRDB */
	sra->adj = adj;
	listnode_add(area->srdb.adj_sids, sra);
	listnode_add(adj->adj_sids, sra);

	isis_zebra_send_adjacency_sid(ZEBRA_MPLS_LABELS_ADD, sra);
}

/**
 * Add Primary and Backup local Adjacency SID.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 */
static void sr_adj_sid_add(struct isis_adjacency *adj, int family)
{
	sr_adj_sid_add_single(adj, family, false);
	sr_adj_sid_add_single(adj, family, true);
}

static void sr_adj_sid_update(struct sr_adjacency *sra,
			      struct sr_local_block *srlb)
{
	struct isis_circuit *circuit = sra->adj->circuit;

	/* First remove the old MPLS Label */
	isis_zebra_send_adjacency_sid(ZEBRA_MPLS_LABELS_DELETE, sra);

	/* Got new label in the new SRLB */
	sra->nexthop.label = sr_local_block_request_label(srlb);
	if (sra->nexthop.label == MPLS_INVALID_LABEL)
		return;

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		sra->u.ladj_sid->sid = sra->nexthop.label;
		break;
	case CIRCUIT_T_P2P:
		sra->u.adj_sid->sid = sra->nexthop.label;
		break;
	default:
		flog_warn(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			  __func__, circuit->circ_type);
		break;
	}

	/* Finally configure the new MPLS Label */
	isis_zebra_send_adjacency_sid(ZEBRA_MPLS_LABELS_ADD, sra);
}

/**
 * Delete local Adj-SID.
 *
 * @param sra	Segment Routing Adjacency
 */
static void sr_adj_sid_del(struct sr_adjacency *sra)
{
	struct isis_circuit *circuit = sra->adj->circuit;
	struct isis_area *area = circuit->area;

	sr_debug("ISIS-Sr (%s): Delete Adjacency SID", area->area_tag);

	isis_zebra_send_adjacency_sid(ZEBRA_MPLS_LABELS_DELETE, sra);

	/* Release dynamic label and remove subTLVs */
	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		sr_local_block_release_label(&area->srdb.srlb,
					     sra->u.ladj_sid->sid);
		isis_tlvs_del_lan_adj_sid(circuit->ext, sra->u.ladj_sid);
		break;
	case CIRCUIT_T_P2P:
		sr_local_block_release_label(&area->srdb.srlb,
					     sra->u.adj_sid->sid);
		isis_tlvs_del_adj_sid(circuit->ext, sra->u.adj_sid);
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}

	/* Remove Adjacency-SID from the SRDB */
	listnode_delete(area->srdb.adj_sids, sra);
	listnode_delete(sra->adj->adj_sids, sra);
	XFREE(MTYPE_ISIS_SR_INFO, sra);
}

/**
 * Remove all Adjacency-SIDs associated to an adjacency that is going down.
 *
 * @param adj	IS-IS Adjacency
 *
 * @return	0
 */
static int sr_adj_state_change(struct isis_adjacency *adj)
{
	struct sr_adjacency *sra;
	struct listnode *node, *nnode;

	if (!adj->circuit->area->srdb.enabled)
		return 0;

	if (adj->adj_state == ISIS_ADJ_UP)
		return 0;

	for (ALL_LIST_ELEMENTS(adj->adj_sids, node, nnode, sra))
		sr_adj_sid_del(sra);

	return 0;
}

/**
 * When IS-IS Adjacency got one or more IPv4/IPv6 addresses, add new IPv4 or
 * IPv6 address to corresponding Adjacency-SID accordingly.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 *
 * @return	  0
 */
static int sr_adj_ip_enabled(struct isis_adjacency *adj, int family)
{
	if (!adj->circuit->area->srdb.enabled)
		return 0;

	sr_adj_sid_add(adj, family);

	return 0;
}

/**
 * When IS-IS Adjacency doesn't have any IPv4 or IPv6 addresses anymore,
 * delete the corresponding Adjacency-SID(s) accordingly.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 *
 * @return	  0
 */
static int sr_adj_ip_disabled(struct isis_adjacency *adj, int family)
{
	struct sr_adjacency *sra;
	struct listnode *node, *nnode;

	if (!adj->circuit->area->srdb.enabled)
		return 0;

	for (ALL_LIST_ELEMENTS(adj->adj_sids, node, nnode, sra))
		if (sra->nexthop.family == family)
			sr_adj_sid_del(sra);

	return 0;
}

/**
 * Activate local Prefix-SID when loopback interface goes up for IS-IS.
 *
 * @param ifp	Loopback Interface
 *
 * @return	0
 */
static int sr_if_new_hook(struct interface *ifp)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct connected *connected;
	struct listnode *node;

	/* Get corresponding circuit */
	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return 0;

	area = circuit->area;
	if (!area)
		return 0;

	/*
	 * Update the Node-SID flag of the configured Prefix-SID mappings if
	 * necessary. This needs to be done here since isisd reads the startup
	 * configuration before receiving interface information from zebra.
	 */
	FOR_ALL_INTERFACES_ADDRESSES (ifp, connected, node) {
		struct sr_prefix_cfg *pcfg;

		pcfg = isis_sr_cfg_prefix_find(area, connected->address);
		if (!pcfg)
			continue;

		if (sr_prefix_is_node_sid(ifp, &pcfg->prefix)
		    && !pcfg->node_sid) {
			pcfg->node_sid = true;
			lsp_regenerate_schedule(area, area->is_type, 0);
		}
	}

	return 0;
}

/* --- Segment Routing Show information functions --------------------------- */

/**
 * Show LFIB operation in human readable format.
 *
 * @param buf	      Buffer to store string output. Must be pre-allocate
 * @param size	      Size of the buffer
 * @param label_in    Input Label
 * @param label_out   Output Label
 * @param label_stack Output Label Stack (TI-LFA)
 *
 * @return	     String containing LFIB operation in human readable format
 */
static char *sr_op2str(char *buf, size_t size, mpls_label_t label_in,
		       mpls_label_t label_out,
		       const struct mpls_label_stack *label_stack)
{
	if (size < 24)
		return NULL;

	if (label_in == MPLS_INVALID_LABEL) {
		snprintf(buf, size, "no-op.");
		return buf;
	}

	if (label_stack) {
		char buf_labels[256];

		mpls_label2str(label_stack->num_labels, &label_stack->label[0],
			       buf_labels, sizeof(buf_labels), 1);

		snprintf(buf, size, "Swap(%u, %s)", label_in, buf_labels);
		return buf;
	}

	switch (label_out) {
	case MPLS_LABEL_IMPLICIT_NULL:
		snprintf(buf, size, "Pop(%u)", label_in);
		break;
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
	case MPLS_LABEL_IPV6_EXPLICIT_NULL:
		snprintf(buf, size, "Swap(%u, null)", label_in);
		break;
	case MPLS_INVALID_LABEL:
		snprintf(buf, size, "no-op.");
		break;
	default:
		snprintf(buf, size, "Swap(%u, %u)", label_in, label_out);
		break;
	}
	return buf;
}

/**
 * Show Local Prefix-SID.
 *
 * @param vty	VTY output
 * @param tt	Table format
 * @param area	IS-IS area
 * @param srp	Segment Routing Prefix
 */
static void show_prefix_sid_local(struct vty *vty, struct ttable *tt,
				  const struct isis_area *area,
				  const struct sr_prefix *srp)
{
	const struct sr_nexthop_info *srnh = &srp->u.local.info;
	char buf_prefix[BUFSIZ];
	char buf_oper[BUFSIZ];
	char buf_iface[BUFSIZ];
	char buf_uptime[BUFSIZ];

	if (srnh->label != MPLS_INVALID_LABEL) {
		struct interface *ifp;
		ifp = if_lookup_prefix(&srp->prefix, VRF_DEFAULT);
		if (ifp)
			strlcpy(buf_iface, ifp->name, sizeof(buf_iface));
		else
			snprintf(buf_iface, sizeof(buf_iface), "-");
		log_uptime(srnh->uptime, buf_uptime, sizeof(buf_uptime));
	} else {
		snprintf(buf_iface, sizeof(buf_iface), "-");
		snprintf(buf_uptime, sizeof(buf_uptime), "-");
	}
	sr_op2str(buf_oper, sizeof(buf_oper), srp->input_label,
		  MPLS_LABEL_IMPLICIT_NULL, NULL);

	ttable_add_row(tt, "%s|%u|%s|-|%s|%s",
		       prefix2str(&srp->prefix, buf_prefix, sizeof(buf_prefix)),
		       srp->sid.value, buf_oper, buf_iface, buf_uptime);
}

/**
 * Show Remote Prefix-SID.
 *
 * @param vty	VTY output
 * @param tt	Table format
 * @param area	IS-IS area
 * @param srp	Segment Routing Prefix
 */
static void show_prefix_sid_remote(struct vty *vty, struct ttable *tt,
				   const struct isis_area *area,
				   const struct sr_prefix *srp, bool backup)
{
	struct isis_nexthop *nexthop;
	struct listnode *node;
	char buf_prefix[BUFSIZ];
	char buf_oper[BUFSIZ];
	char buf_nhop[BUFSIZ];
	char buf_iface[BUFSIZ];
	char buf_uptime[BUFSIZ];
	bool first = true;
	struct isis_route_info *rinfo;

	(void)prefix2str(&srp->prefix, buf_prefix, sizeof(buf_prefix));

	rinfo = srp->u.remote.rinfo;
	if (rinfo && backup)
		rinfo = rinfo->backup;
	if (!rinfo) {
		ttable_add_row(tt, "%s|%u|%s|-|-|-", buf_prefix, srp->sid.value,
			       sr_op2str(buf_oper, sizeof(buf_oper),
					 srp->input_label,
					 MPLS_LABEL_IMPLICIT_NULL, NULL));
		return;
	}

	for (ALL_LIST_ELEMENTS_RO(rinfo->nexthops, node, nexthop)) {
		struct interface *ifp;

		inet_ntop(nexthop->family, &nexthop->ip, buf_nhop,
			  sizeof(buf_nhop));
		ifp = if_lookup_by_index(nexthop->ifindex, VRF_DEFAULT);
		if (ifp)
			strlcpy(buf_iface, ifp->name, sizeof(buf_iface));
		else
			snprintf(buf_iface, sizeof(buf_iface), "ifindex %u",
				 nexthop->ifindex);
		if (nexthop->sr.label == MPLS_INVALID_LABEL)
			snprintf(buf_uptime, sizeof(buf_uptime), "-");
		else
			log_uptime(nexthop->sr.uptime, buf_uptime,
				   sizeof(buf_uptime));
		sr_op2str(buf_oper, sizeof(buf_oper), srp->input_label,
			  nexthop->sr.label, nexthop->label_stack);

		if (first)
			ttable_add_row(tt, "%s|%u|%s|%s|%s|%s", buf_prefix,
				       srp->sid.value, buf_oper, buf_nhop,
				       buf_iface, buf_uptime);
		else
			ttable_add_row(tt, "|||%s|%s|%s|%s", buf_oper, buf_nhop,
				       buf_iface, buf_uptime);
		first = false;
	}
}

/**
 * Show Prefix-SIDs.
 *
 * @param vty	VTY output
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
static void show_prefix_sids(struct vty *vty, struct isis_area *area, int level,
			     bool backup)
{
	struct sr_prefix *srp;
	struct ttable *tt;

	if (srdb_area_prefix_count(&area->srdb.prefix_sids[level - 1]) == 0)
		return;

	vty_out(vty, " IS-IS %s Prefix-SIDs:\n\n", circuit_t2string(level));

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Prefix|SID|Label Op.|Nexthop|Interface|Uptime");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	/* Process all Prefix-SID from the SRDB */
	frr_each (srdb_area_prefix, &area->srdb.prefix_sids[level - 1], srp) {
		switch (srp->type) {
		case ISIS_SR_PREFIX_LOCAL:
			show_prefix_sid_local(vty, tt, area, srp);
			break;
		case ISIS_SR_PREFIX_REMOTE:
			show_prefix_sid_remote(vty, tt, area, srp, backup);
			break;
		}
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	}
	ttable_del(tt);
}

/**
 * Declaration of new show commands.
 */
DEFUN(show_sr_prefix_sids, show_sr_prefix_sids_cmd,
      "show isis [vrf <NAME|all>] segment-routing prefix-sids [backup]",
      SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
      "All VRFs\n"
      "Segment-Routing\n"
      "Segment-Routing Prefix-SIDs\n"
      "Show backup Prefix-SIDs\n")
{
	struct listnode *node, *inode;
	struct isis_area *area;
	struct isis *isis = NULL;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	bool backup = false;
	int idx = 0;

	ISIS_FIND_VRF_ARGS(argv, argc, idx, vrf_name, all_vrf);
	if (argv_find(argv, argc, "backup", &idx))
		backup = true;

	if (vrf_name) {
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
				for (ALL_LIST_ELEMENTS_RO(isis->area_list, node,
							  area)) {
					vty_out(vty, "Area %s:\n",
						area->area_tag ? area->area_tag
							       : "null");
					for (int level = ISIS_LEVEL1;
					     level <= ISIS_LEVELS; level++)
						show_prefix_sids(vty, area,
								 level, backup);
				}
			}
			return 0;
		}
		isis = isis_lookup_by_vrfname(vrf_name);
		if (isis != NULL) {
			for (ALL_LIST_ELEMENTS_RO(isis->area_list, node,
						  area)) {
				vty_out(vty, "Area %s:\n",
					area->area_tag ? area->area_tag
						       : "null");
				for (int level = ISIS_LEVEL1;
				     level <= ISIS_LEVELS; level++)
					show_prefix_sids(vty, area, level,
							 backup);
			}
		}
	}

	return CMD_SUCCESS;
}

/**
 * Show Segment Routing Node.
 *
 * @param vty	VTY output
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
static void show_node(struct vty *vty, struct isis_area *area, int level)
{
	struct sr_node *srn;
	struct ttable *tt;

	if (srdb_area_prefix_count(&area->srdb.prefix_sids[level - 1]) == 0)
		return;

	vty_out(vty, " IS-IS %s SR-Node:\n\n", circuit_t2string(level));

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "System ID|SRGB|SRLB|Algorithm|MSD");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	/* Process all SR-Node from the SRDB */
	frr_each (srdb_node, &area->srdb.sr_nodes[level - 1], srn) {
		ttable_add_row(
			tt, "%s|%u - %u|%u - %u|%s|%u",
			sysid_print(srn->sysid),
			srn->cap.srgb.lower_bound,
			srn->cap.srgb.lower_bound + srn->cap.srgb.range_size
				- 1,
			srn->cap.srlb.lower_bound,
			srn->cap.srlb.lower_bound + srn->cap.srlb.range_size
				- 1,
			srn->cap.algo[0] == SR_ALGORITHM_SPF ? "SPF" : "S-SPF",
			srn->cap.msd);
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	}
	ttable_del(tt);
}

DEFUN(show_sr_node, show_sr_node_cmd,
      "show isis segment-routing node",
      SHOW_STR PROTO_HELP
      "Segment-Routing\n"
      "Segment-Routing node\n")
{
	struct listnode *node, *inode;
	struct isis_area *area;
	struct isis *isis;

	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			vty_out(vty, "Area %s:\n",
				area->area_tag ? area->area_tag : "null");

			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++)
				show_node(vty, area, level);
		}
	}

	return CMD_SUCCESS;
}


/* --- IS-IS Segment Routing Management function ---------------------------- */

/**
 * Thread function to re-attempt connection to the Label Manager and thus be
 * able to start Segment Routing.
 *
 * @param start		Thread structure that contains area as argument
 *
 * @return		1 on success
 */
static int sr_start_label_manager(struct thread *start)
{
	struct isis_area *area;

	area = THREAD_ARG(start);

	/* re-attempt to start SR & Label Manager connection */
	isis_sr_start(area);

	return 1;
}

/**
 * Enable SR on the given IS-IS area.
 *
 * @param area	IS-IS area
 *
 * @return	0 on success, -1 otherwise
 */
int isis_sr_start(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;
	struct isis_adjacency *adj;
	struct listnode *node;

	/* First start Label Manager if not ready */
	if (!isis_zebra_label_manager_ready())
		if (isis_zebra_label_manager_connect() < 0) {
			/* Re-attempt to connect to Label Manager in 1 sec. */
			thread_add_timer(master, sr_start_label_manager, area,
					 1, &srdb->t_start_lm);
			return -1;
		}

	/* Label Manager is ready, initialize the SRLB */
	if (sr_local_block_init(area) < 0)
		return -1;

	/*
	 * Request SGRB to the label manager if not already active. If the
	 * allocation fails, return an error to disable SR until a new SRGB
	 * is successfully allocated.
	 */
	if (!srdb->srgb_active) {
		if (isis_zebra_request_label_range(
			    srdb->config.srgb_lower_bound,
			    srdb->config.srgb_upper_bound
				    - srdb->config.srgb_lower_bound + 1)
		    < 0) {
			srdb->srgb_active = false;
			return -1;
		} else
			srdb->srgb_active = true;
	}

	sr_debug("ISIS-Sr: Starting Segment Routing for area %s",
		 area->area_tag);

	/* Create Adjacency-SIDs from existing IS-IS Adjacencies. */
	for (ALL_LIST_ELEMENTS_RO(area->adjacency_list, node, adj)) {
		if (adj->ipv4_address_count > 0)
			sr_adj_sid_add(adj, AF_INET);
		if (adj->ipv6_address_count > 0)
			sr_adj_sid_add(adj, AF_INET6);
	}

	area->srdb.enabled = true;

	/* Regenerate LSPs to advertise Segment Routing capabilities. */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return 0;
}

/**
 * Disable SR on the given IS-IS area.
 *
 * @param area	IS-IS area
 */
void isis_sr_stop(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;
	struct sr_adjacency *sra;
	struct listnode *node, *nnode;

	sr_debug("ISIS-Sr: Stopping Segment Routing for area %s",
		 area->area_tag);

	/* Disable any re-attempt to connect to Label Manager */
	THREAD_TIMER_OFF(srdb->t_start_lm);

	/* Uninstall all local Adjacency-SIDs. */
	for (ALL_LIST_ELEMENTS(area->srdb.adj_sids, node, nnode, sra))
		sr_adj_sid_del(sra);

	/* Uninstall all Prefix-SIDs from all SR Node. */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		while (srdb_node_count(&srdb->sr_nodes[level - 1]) > 0) {
			struct sr_node *srn;

			srn = srdb_node_first(&srdb->sr_nodes[level - 1]);
			sr_node_del(area, level, srn);
		}
	}

	/* Release SRGB if active. */
	if (srdb->srgb_active) {
		isis_zebra_release_label_range(srdb->config.srgb_lower_bound,
					       srdb->config.srgb_upper_bound);
		srdb->srgb_active = false;
	}

	/* Delete SRLB */
	sr_local_block_delete(area);

	area->srdb.enabled = false;

	/* Regenerate LSPs to advertise that the Node is no more SR enable. */
	lsp_regenerate_schedule(area, area->is_type, 0);
}

/**
 * IS-IS Segment Routing initialization for given area.
 *
 * @param area	IS-IS area
 */
void isis_sr_area_init(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("ISIS-Sr (%s): Initialize Segment Routing SRDB",
		 area->area_tag);

	/* Initialize Segment Routing Data Base */
	memset(srdb, 0, sizeof(*srdb));
	srdb->adj_sids = list_new();

	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		srdb_node_init(&srdb->sr_nodes[level - 1]);
		srdb_area_prefix_init(&srdb->prefix_sids[level - 1]);
	}

	/* Pull defaults from the YANG module. */
#ifndef FABRICD
	srdb->config.enabled = yang_get_default_bool("%s/enabled", ISIS_SR);
	srdb->config.srgb_lower_bound =
		yang_get_default_uint32("%s/srgb/lower-bound", ISIS_SR);
	srdb->config.srgb_upper_bound =
		yang_get_default_uint32("%s/srgb/upper-bound", ISIS_SR);
	srdb->config.srlb_lower_bound =
		yang_get_default_uint32("%s/srlb/lower-bound", ISIS_SR);
	srdb->config.srlb_upper_bound =
		yang_get_default_uint32("%s/srlb/upper-bound", ISIS_SR);
#else
	srdb->config.enabled = false;
	srdb->config.srgb_lower_bound = SRGB_LOWER_BOUND;
	srdb->config.srgb_upper_bound = SRGB_UPPER_BOUND;
	srdb->config.srlb_lower_bound = SRLB_LOWER_BOUND;
	srdb->config.srlb_upper_bound = SRLB_UPPER_BOUND;
#endif
	srdb->config.msd = 0;
	srdb_prefix_cfg_init(&srdb->config.prefix_sids);
}

/**
 * Terminate IS-IS Segment Routing for the given area.
 *
 * @param area	IS-IS area
 */
void isis_sr_area_term(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;

	/* Stop Segment Routing */
	if (area->srdb.enabled)
		isis_sr_stop(area);

	/* Clear Prefix-SID configuration. */
	while (srdb_prefix_cfg_count(&srdb->config.prefix_sids) > 0) {
		struct sr_prefix_cfg *pcfg;

		pcfg = srdb_prefix_cfg_first(&srdb->config.prefix_sids);
		isis_sr_cfg_prefix_del(pcfg);
	}
}

/**
 * IS-IS Segment Routing global initialization.
 */
void isis_sr_init(void)
{
	install_element(VIEW_NODE, &show_sr_prefix_sids_cmd);
	install_element(VIEW_NODE, &show_sr_node_cmd);

	/* Register hooks. */
	hook_register(isis_adj_state_change_hook, sr_adj_state_change);
	hook_register(isis_adj_ip_enabled_hook, sr_adj_ip_enabled);
	hook_register(isis_adj_ip_disabled_hook, sr_adj_ip_disabled);
	hook_register(isis_route_update_hook, sr_route_update);
	hook_register(isis_if_new_hook, sr_if_new_hook);
}

/**
 * IS-IS Segment Routing global terminate.
 */
void isis_sr_term(void)
{
	/* Unregister hooks. */
	hook_unregister(isis_adj_state_change_hook, sr_adj_state_change);
	hook_unregister(isis_adj_ip_enabled_hook, sr_adj_ip_enabled);
	hook_unregister(isis_adj_ip_disabled_hook, sr_adj_ip_disabled);
	hook_unregister(isis_route_update_hook, sr_route_update);
	hook_unregister(isis_if_new_hook, sr_if_new_hook);
}
