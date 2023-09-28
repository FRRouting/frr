// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of Segment Routing for IS-IS as per RFC 8667
 *
 * Copyright (C) 2019 Orange http://www.orange.com
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Contributor: Renato Westphal <renato@opensourcerouting.org> for NetDEF
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
#include "srcdest_table.h"
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
DEFINE_MTYPE_STATIC(ISISD, ISIS_SR_INFO, "ISIS segment routing information");

static void sr_local_block_delete(struct isis_area *area);
static int sr_local_block_init(struct isis_area *area);
static void sr_adj_sid_update(struct sr_adjacency *sra,
			      struct sr_local_block *srlb);
static void sr_adj_sid_del(struct sr_adjacency *sra);

/* --- RB-Tree Management functions ----------------------------------------- */

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
	int ret;

	ret = prefix_cmp(&a->prefix, &b->prefix);
	if (ret != 0)
		return ret;

	ret = a->algorithm - b->algorithm;
	if (ret != 0)
		return ret;

	return 0;
}
DECLARE_RBTREE_UNIQ(srdb_prefix_cfg, struct sr_prefix_cfg, entry,
		    sr_prefix_sid_cfg_compare);

/**
 * Find SRGB associated to a System ID.
 *
 * @param area	IS-IS LSP database
 * @param sysid	System ID to lookup
 *
 * @return	Pointer to SRGB if found, NULL otherwise
 */
struct isis_sr_block *isis_sr_find_srgb(struct lspdb_head *lspdb,
					const uint8_t *sysid)
{
	struct isis_lsp *lsp;

	lsp = isis_root_system_lsp(lspdb, sysid);
	if (!lsp)
		return NULL;

	if (!lsp->tlvs->router_cap
	    || lsp->tlvs->router_cap->srgb.range_size == 0)
		return NULL;

	return &lsp->tlvs->router_cap->srgb;
}

/**
 * Compute input label for the given Prefix-SID.
 *
 * @param area	  IS-IS area
 * @param psid	  IS-IS Prefix-SID Sub-TLV
 * @param local	  Indicates whether the Prefix-SID is local or not
 *
 * @return	MPLS label or MPLS_INVALID_LABEL in case of SRGB overflow
 */
mpls_label_t sr_prefix_in_label(struct isis_area *area,
				struct isis_prefix_sid *psid, bool local)
{
	/*
	 * No need to assign a label for local Prefix-SIDs unless the no-PHP
	 * flag is set.
	 */
	if (local
	    && (!CHECK_FLAG(psid->flags, ISIS_PREFIX_SID_NO_PHP)
		|| CHECK_FLAG(psid->flags, ISIS_PREFIX_SID_EXPLICIT_NULL)))
		return MPLS_INVALID_LABEL;

	/* Return SID value as MPLS label if it is an Absolute SID */
	if (CHECK_FLAG(psid->flags,
		       ISIS_PREFIX_SID_VALUE | ISIS_PREFIX_SID_LOCAL))
		return psid->value;

	/* Check that SID index falls inside the SRGB */
	if (psid->value >= (area->srdb.config.srgb_upper_bound
			    - area->srdb.config.srgb_lower_bound + 1)) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			  "%s: SID index %u falls outside local SRGB range",
			  __func__, psid->value);
		return MPLS_INVALID_LABEL;
	}

	/* Return MPLS label as SID index + SRGB_lower_bound as per RFC 8667 */
	return (area->srdb.config.srgb_lower_bound + psid->value);
}

/**
 * Compute output label for the given Prefix-SID.
 *
 * @param lspdb		IS-IS LSP database
 * @param family	Prefix-SID address family
 * @param psid		Prefix-SID Sub-TLV
 * @param nh_sysid	System ID of the nexthop node
 * @param last_hop	Indicates whether the nexthop node is the last hop
 *
 * @return		MPLS label or MPLS_INVALID_LABEL in case of error
 */
mpls_label_t sr_prefix_out_label(struct lspdb_head *lspdb, int family,
				 struct isis_prefix_sid *psid,
				 const uint8_t *nh_sysid, bool last_hop)
{
	struct isis_sr_block *nh_srgb;

	if (last_hop) {
		if (!CHECK_FLAG(psid->flags, ISIS_PREFIX_SID_NO_PHP))
			return MPLS_LABEL_IMPLICIT_NULL;

		if (CHECK_FLAG(psid->flags, ISIS_PREFIX_SID_EXPLICIT_NULL)) {
			if (family == AF_INET)
				return MPLS_LABEL_IPV4_EXPLICIT_NULL;
			else
				return MPLS_LABEL_IPV6_EXPLICIT_NULL;
		}
		/* Fallthrough */
	}

	/* Return SID value as MPLS label if it is an Absolute SID */
	if (CHECK_FLAG(psid->flags,
		       ISIS_PREFIX_SID_VALUE | ISIS_PREFIX_SID_LOCAL)) {
		/*
		 * V/L SIDs have local significance, so only adjacent routers
		 * can use them (RFC8667 section #2.1.1.1)
		 */
		if (!last_hop)
			return MPLS_INVALID_LABEL;
		return psid->value;
	}

	/* Check that SID index falls inside the SRGB */
	nh_srgb = isis_sr_find_srgb(lspdb, nh_sysid);
	if (!nh_srgb)
		return MPLS_INVALID_LABEL;

	/*
	 * Check if the nexthop can handle SR-MPLS encapsulated IPv4 or
	 * IPv6 packets.
	 */
	if ((family == AF_INET && !IS_SR_IPV4(nh_srgb))
	    || (family == AF_INET6 && !IS_SR_IPV6(nh_srgb)))
		return MPLS_INVALID_LABEL;

	if (psid->value >= nh_srgb->range_size) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			  "%s: SID index %u falls outside remote SRGB range",
			  __func__, psid->value);
		return MPLS_INVALID_LABEL;
	}

	/* Return MPLS label as SID index + SRGB_lower_bound as per RFC 8667 */
	return (nh_srgb->lower_bound + psid->value);
}

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
					     const struct prefix *prefix,
					     uint8_t algorithm)
{
	struct sr_prefix_cfg *pcfg;
	struct interface *ifp;

	sr_debug("ISIS-Sr (%s): Add local prefix %pFX", area->area_tag, prefix);

	pcfg = XCALLOC(MTYPE_ISIS_SR_INFO, sizeof(*pcfg));
	pcfg->prefix = *prefix;
	pcfg->area = area;
	pcfg->algorithm = algorithm;

	/* Pull defaults from the YANG module. */
	pcfg->sid_type = yang_get_default_enum(
		"%s/prefix-sid-map/prefix-sid/sid-value-type", ISIS_SR);
	pcfg->last_hop_behavior = yang_get_default_enum(
		"%s/prefix-sid-map/prefix-sid/last-hop-behavior", ISIS_SR);

	/* Mark as node Sid if the prefix is host and configured in loopback */
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
					      union prefixconstptr prefix,
					      uint8_t algorithm)
{
	struct sr_prefix_cfg pcfg = {};

	prefix_copy(&pcfg.prefix, prefix.p);
	pcfg.algorithm = algorithm;
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
	psid->algorithm = pcfg->algorithm;

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
	if (pcfg->node_sid && !pcfg->n_flag_clear)
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_NODE);

	/* Set SID value. */
	psid->value = pcfg->sid;
	if (pcfg->sid_type == SR_SID_VALUE_TYPE_ABSOLUTE) {
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_VALUE);
		SET_FLAG(psid->flags, ISIS_PREFIX_SID_LOCAL);
	}
}

/**
 * Delete all backup Adj-SIDs.
 *
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
void isis_area_delete_backup_adj_sids(struct isis_area *area, int level)
{
	struct sr_adjacency *sra;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(area->srdb.adj_sids, node, nnode, sra))
		if (sra->type == ISIS_SR_LAN_BACKUP
		    && (sra->adj->level & level))
			sr_adj_sid_del(sra);
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
	uint32_t size = srlb->end - srlb->start + 1;

	/* Check if we ran out of available labels */
	if (srlb->current >= size)
		return MPLS_INVALID_LABEL;

	/* Get first available label and mark it used */
	label = srlb->current + srlb->start;
	index = srlb->current / SRLB_BLOCK_SIZE;
	pos = 1ULL << (srlb->current % SRLB_BLOCK_SIZE);
	srlb->used_mark[index] |= pos;

	/* Jump to the next free position */
	srlb->current++;
	pos = srlb->current % SRLB_BLOCK_SIZE;
	while (srlb->current < size) {
		if (pos == 0)
			index++;
		if (!((1ULL << pos) & srlb->used_mark[index]))
			break;
		else {
			srlb->current++;
			pos = srlb->current % SRLB_BLOCK_SIZE;
		}
	}

	if (srlb->current == size)
		zlog_warn(
			"SR: Warning, SRLB is depleted and next label request will fail");

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
 * @param adj	   IS-IS Adjacency
 * @param family   Inet Family (IPv4 or IPv6)
 * @param backup   True to initialize backup Adjacency SID
 * @param nexthops List of backup nexthops (for backup Adj-SIDs only)
 */
void sr_adj_sid_add_single(struct isis_adjacency *adj, int family, bool backup,
			   struct list *nexthops)
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
		if (!circuit->ipv6_router || !adj->ll_ipv6_count)
			return;

		nexthop.ipv6 = adj->ll_ipv6_addrs[0];
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
	sra->input_label = input_label;
	sra->nexthop.family = family;
	sra->nexthop.address = nexthop;

	if (backup && nexthops) {
		struct isis_vertex_adj *vadj;
		struct listnode *node;

		sra->backup_nexthops = list_new();
		for (ALL_LIST_ELEMENTS_RO(nexthops, node, vadj)) {
			struct isis_adjacency *adj = vadj->sadj->adj;
			struct mpls_label_stack *label_stack;

			label_stack = vadj->label_stack;
			adjinfo2nexthop(family, sra->backup_nexthops, adj, NULL,
					label_stack);
		}
	}

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
	sr_adj_sid_add_single(adj, family, false, NULL);
}

static void sr_adj_sid_update(struct sr_adjacency *sra,
			      struct sr_local_block *srlb)
{
	struct isis_circuit *circuit = sra->adj->circuit;

	/* First remove the old MPLS Label */
	isis_zebra_send_adjacency_sid(ZEBRA_MPLS_LABELS_DELETE, sra);

	/* Got new label in the new SRLB */
	sra->input_label = sr_local_block_request_label(srlb);
	if (sra->input_label == MPLS_INVALID_LABEL)
		return;

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		sra->u.ladj_sid->sid = sra->input_label;
		break;
	case CIRCUIT_T_P2P:
		sra->u.adj_sid->sid = sra->input_label;
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

	if (sra->type == ISIS_SR_LAN_BACKUP && sra->backup_nexthops) {
		sra->backup_nexthops->del =
			(void (*)(void *))isis_nexthop_delete;
		list_delete(&sra->backup_nexthops);
	}

	/* Remove Adjacency-SID from the SRDB */
	listnode_delete(area->srdb.adj_sids, sra);
	listnode_delete(sra->adj->adj_sids, sra);
	XFREE(MTYPE_ISIS_SR_INFO, sra);
}

/**
 * Lookup Segment Routing Adj-SID by family and type.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 * @param type    Adjacency SID type
 */
struct sr_adjacency *isis_sr_adj_sid_find(struct isis_adjacency *adj,
					  int family, enum sr_adj_type type)
{
	struct sr_adjacency *sra;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(adj->adj_sids, node, sra))
		if (sra->nexthop.family == family && sra->type == type)
			return sra;

	return NULL;
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
 * @param global  Indicate if it concerns the Local or Global IPv6 addresses
 *
 * @return	  0
 */
static int sr_adj_ip_enabled(struct isis_adjacency *adj, int family,
			     bool global)
{
	if (!adj->circuit->area->srdb.enabled || global)
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
 * @param global  Indicate if it concerns the Local or Global IPv6 addresses
 *
 * @return	  0
 */
static int sr_adj_ip_disabled(struct isis_adjacency *adj, int family,
			      bool global)
{
	struct sr_adjacency *sra;
	struct listnode *node, *nnode;

	if (!adj->circuit->area->srdb.enabled || global)
		return 0;

	for (ALL_LIST_ELEMENTS(adj->adj_sids, node, nnode, sra))
		if (sra->nexthop.family == family)
			sr_adj_sid_del(sra);

	return 0;
}

/**
 * Update the Node-SID flag of the configured Prefix-SID mappings in response
 * to an address addition or removal event.
 *
 * @param ifp	Interface
 *
 * @return	0
 */
int sr_if_addr_update(struct interface *ifp)
{
	struct sr_prefix_cfg *pcfgs[SR_ALGORITHM_COUNT] = {NULL};
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct connected *connected;
	struct listnode *node;
	bool need_lsp_regenerate = false;

	/* Get corresponding circuit */
	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return 0;

	area = circuit->area;
	if (!area)
		return 0;

	FOR_ALL_INTERFACES_ADDRESSES (ifp, connected, node) {
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
			pcfgs[i] = isis_sr_cfg_prefix_find(
				area, connected->address, i);

			if (!pcfgs[i])
				continue;

			if (sr_prefix_is_node_sid(ifp, &pcfgs[i]->prefix)) {
				pcfgs[i]->node_sid = true;
				need_lsp_regenerate = true;
			}
		}
	}

	if (need_lsp_regenerate)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return 0;
}

/**
 * Show LFIB operation in human readable format.
 *
 * @param buf	      Buffer to store string output. Must be pre-allocate
 * @param size	      Size of the buffer
 * @param label_in    Input Label
 * @param label_out   Output Label
 *
 * @return	     String containing LFIB operation in human readable format
 */
char *sr_op2str(char *buf, size_t size, mpls_label_t label_in,
		mpls_label_t label_out)
{
	if (size < 24)
		return NULL;

	if (label_in == MPLS_INVALID_LABEL) {
		snprintf(buf, size, "no-op.");
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
 * Show Segment Routing Node.
 *
 * @param vty	VTY output
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
static void show_node(struct vty *vty, struct isis_area *area, int level,
		      uint8_t algo)
{
	struct isis_lsp *lsp;
	struct ttable *tt;
	char buf[128];

	vty_out(vty, " IS-IS %s SR-Nodes:\n\n", circuit_t2string(level));

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "System ID|SRGB|SRLB|Algorithm|MSD");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	frr_each (lspdb, &area->lspdb[level - 1], lsp) {
		struct isis_router_cap *cap;

		if (!lsp->tlvs)
			continue;
		cap = lsp->tlvs->router_cap;
		if (!cap)
			continue;
		if (cap->algo[algo] == SR_ALGORITHM_UNSET)
			continue;

		if (cap->algo[algo] == SR_ALGORITHM_SPF)
			snprintf(buf, sizeof(buf), "SPF");
		else if (cap->algo[algo] == SR_ALGORITHM_STRICT_SPF)
			snprintf(buf, sizeof(buf), "S-SPF");
#ifndef FABRICD
		else
			snprintf(buf, sizeof(buf), "Flex-Algo %d", algo);
#endif /* ifndef FABRICD */

		ttable_add_row(tt, "%pSY|%u - %u|%u - %u|%s|%u",
			       lsp->hdr.lsp_id, cap->srgb.lower_bound,
			       cap->srgb.lower_bound + cap->srgb.range_size - 1,
			       cap->srlb.lower_bound,
			       cap->srlb.lower_bound + cap->srlb.range_size - 1,
			       buf, cap->msd);
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
      "show " PROTO_NAME
      " segment-routing node"
#ifndef FABRICD
      " [algorithm (128-255)]"
#endif /* ifndef FABRICD */
      ,
      SHOW_STR PROTO_HELP
      "Segment-Routing\n"
      "Segment-Routing node\n"
#ifndef FABRICD
      "Show Flex-algo nodes\n"
      "Algorithm number\n"
#endif /* ifndef FABRICD */
)
{
	struct listnode *node, *inode;
	struct isis_area *area;
	uint8_t algorithm = SR_ALGORITHM_SPF;
	struct isis *isis;
#ifndef FABRICD
	int idx = 0;

	if (argv_find(argv, argc, "algorithm", &idx))
		algorithm = (uint8_t)strtoul(argv[idx + 1]->arg, NULL, 10);
#endif /* ifndef FABRICD */

	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			vty_out(vty, "Area %s:\n",
				area->area_tag ? area->area_tag : "null");
			if (!area->srdb.enabled) {
				vty_out(vty, " Segment Routing is disabled\n");
				continue;
			}
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++)
				show_node(vty, area, level, algorithm);
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
static void sr_start_label_manager(struct event *start)
{
	struct isis_area *area;

	area = EVENT_ARG(start);

	/* re-attempt to start SR & Label Manager connection */
	isis_sr_start(area);
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
			event_add_timer(master, sr_start_label_manager, area, 1,
					&srdb->t_start_lm);
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
		if (adj->ll_ipv6_count > 0)
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
	EVENT_OFF(srdb->t_start_lm);

	/* Uninstall all local Adjacency-SIDs. */
	for (ALL_LIST_ELEMENTS(area->srdb.adj_sids, node, nnode, sra))
		sr_adj_sid_del(sra);

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

	/* Pull defaults from the YANG module. */
#ifndef FABRICD
	srdb->config.enabled = yang_get_default_bool("%s/enabled", ISIS_SR);
	srdb->config.srgb_lower_bound = yang_get_default_uint32(
		"%s/label-blocks/srgb/lower-bound", ISIS_SR);
	srdb->config.srgb_upper_bound = yang_get_default_uint32(
		"%s/label-blocks/srgb/upper-bound", ISIS_SR);
	srdb->config.srlb_lower_bound = yang_get_default_uint32(
		"%s/label-blocks/srlb/lower-bound", ISIS_SR);
	srdb->config.srlb_upper_bound = yang_get_default_uint32(
		"%s/label-blocks/srlb/upper-bound", ISIS_SR);
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

	/* Free Adjacency SID list */
	list_delete(&srdb->adj_sids);

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
	install_element(VIEW_NODE, &show_sr_node_cmd);

	/* Register hooks. */
	hook_register(isis_adj_state_change_hook, sr_adj_state_change);
	hook_register(isis_adj_ip_enabled_hook, sr_adj_ip_enabled);
	hook_register(isis_adj_ip_disabled_hook, sr_adj_ip_disabled);
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
}
