// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State (RFC 9552) - Core Implementation
 * Copyright (C) 2025 Carmine Scarpitta
 */

#include <zebra.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_ls_ted.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_zebra.h"
#define UNKNOWN LS_UNKNOWN
#include "lib/link_state.h"
#undef UNKNOWN

DEFINE_MTYPE_STATIC(BGPD, BGP_LS, "BGP-LS instance");

/*
 * ===========================================================================
 * RIB Operations
 * ===========================================================================
 */

/*
 * Install or update BGP-LS route in RIB (RFC 9552 Section 6)
 *
 * This function handles locally originated BGP-LS routes from IGP.
 * It creates a synthetic prefix in the standard BGP RIB using AF_UNSPEC
 * and stores the full NLRI in bgp_path_info_extra->ls_nlri.
 *
 * The function uses a dual-storage approach:
 * 1. BGP-LS hash table - for fast NLRI lookups and ID allocation
 * 2. Standard BGP RIB - for integration with existing BGP processing
 *
 * @param bgp - BGP instance
 * @param nlri - BGP-LS NLRI to install
 * @return 0 on success, -1 on error
 */
int bgp_ls_update(struct bgp *bgp, struct bgp_ls_nlri *nlri)
{
	struct bgp_path_info *bpi;
	struct bgp_path_info *new;
	struct attr attr;
	struct attr *attr_new;
	struct bgp_dest *dest;
	struct bgp_ls_nlri *ls_entry;
	struct prefix p;

	if (!bgp || !nlri) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid parameters to %s", __func__);
		return -1;
	}

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) || bgp->peer_self == NULL)
		return 0;

	if (!bgp->ls_info) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: ls_info not initialized");
		return -1;
	}

	/* Lookup or insert NLRI in hash table */
	ls_entry = bgp_ls_nlri_intern(nlri);

	/* Make BGP-LS NLRI prefix */
	memset(&p, 0, sizeof(p));
	p.family = AF_UNSPEC;
	p.prefixlen = 32;
	p.u.val32[0] = ls_entry->id;

	dest = bgp_afi_node_get(bgp->rib[AFI_BGP_LS][SAFI_BGP_LS], AFI_BGP_LS, SAFI_BGP_LS, &p,
				NULL);

	/* Make default attribute. */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_INCOMPLETE);

	attr_new = bgp_attr_intern(&attr);

	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next)
		if (bpi->peer == bgp->peer_self)
			break;

	if (bpi) {
		if (!CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED) && attrhash_cmp(bpi->attr, attr_new)) {
			/* The attribute is not changed. */
			bgp_attr_unintern(&attr_new);
			aspath_unintern(&attr.aspath);
			bgp_dest_unlock_node(dest);
		} else {
			/* The attribute is changed. */
			bgp_path_info_set_flag(dest, bpi, BGP_PATH_ATTR_CHANGED);

			/* Rewrite BGP route information. */
			// if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
			//bgp_path_info_restore(dest, bpi);


			UNSET_FLAG(bpi->flags, BGP_PATH_REMOVED);
			/* unset of previous already took care of pcount */
			SET_FLAG(bpi->flags, BGP_PATH_VALID);


			bgp_attr_unintern(&bpi->attr);
			bpi->attr = attr_new;
			bpi->uptime = monotime(NULL);

			/* Process change. */
			// bgp_aggregate_increment(bgp, p, bpi, AFI_BGP_LS,
			//		SAFI_BGP_LS);
			bgp_process(bgp, dest, bpi, AFI_BGP_LS, SAFI_BGP_LS);
			bgp_dest_unlock_node(dest);
			aspath_unintern(&attr.aspath);
		}

		return 0;
	}

	/* Make new BGP info. */
	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_REDISTRIBUTE, 0, bgp->peer_self, attr_new, dest);
	SET_FLAG(new->flags, BGP_PATH_VALID);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);

	/* Allocate extra for BGP-LS specific data */
	if (!new->extra)
		new->extra = bgp_path_info_extra_get(new);

	new->extra->ls_nlri = ls_entry;

	/* Process change */
	bgp_process(bgp, dest, new, AFI_BGP_LS, SAFI_BGP_LS);

	/* route_node_get unlock */
	bgp_dest_unlock_node(dest);

	/* Unintern original */
	aspath_unintern(&attr.aspath);

	return 0;
}


/*
 * Remove BGP-LS route from RIB (RFC 9552 Section 6)
 *
 * This function handles withdrawal of locally originated BGP-LS routes.
 * It marks the route as removed and triggers BGP processing for
 * withdrawal advertisement to peers.
 *
 * @param bgp - BGP instance
 * @param nlri - BGP-LS NLRI to withdraw
 * @return 0 on success, -1 on error
 */
int bgp_ls_withdraw(struct bgp *bgp, struct bgp_ls_nlri *nlri)
{
	struct bgp_path_info *bpi;
	struct bgp_dest *dest;
	struct prefix p;
	struct bgp_ls_nlri *ls_nlri;

	if (!bgp || !nlri) {
		flog_err(EC_BGP_LS_PACKET, "BGP-LS: Invalid parameters to %s", __func__);
		return -1;
	}

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS) || bgp->peer_self == NULL)
		return 0;

	if (!bgp->ls_info) {
		if (BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: No BGP-LS info exists for withdraw", __func__);

		return 0;
	}

	/* Lookup NLRI in hash table */
	ls_nlri = bgp_ls_nlri_lookup(&bgp->ls_info->nlri_hash, nlri);
	if (!ls_nlri) {
		if (BGP_DEBUG(linkstate, LINKSTATE)) {
			zlog_debug("%s: BGP-LS WITHDRAW for non-existent NLRI type=%u", __func__,
				   nlri->nlri_type);
		}
		return 0; /* Not an error - may have been withdrawn already */
	}

	/* Make synthetic prefix using hash table ID */
	memset(&p, 0, sizeof(p));
	p.family = AF_UNSPEC;
	p.prefixlen = 32;
	p.u.val32[0] = ls_nlri->id;

	dest = bgp_afi_node_get(bgp->rib[AFI_BGP_LS][SAFI_BGP_LS], AFI_BGP_LS, SAFI_BGP_LS, &p,
				NULL);

	/* Find path from local peer */
	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next)
		if (bpi->peer == bgp->peer_self)
			break;

	if (bpi) {
		if (BGP_DEBUG(linkstate, LINKSTATE)) {
			zlog_debug("%s: Withdrawing BGP-LS route type=%u", __func__,
				   nlri->nlri_type);
		}

		/* Mark for deletion */
		SET_FLAG(bpi->flags, BGP_PATH_REMOVED);
		UNSET_FLAG(bpi->flags, BGP_PATH_VALID);

		/* Process change - triggers withdrawal to peers */
		bgp_process(bgp, dest, bpi, AFI_BGP_LS, SAFI_BGP_LS);
	} else {
		if (BGP_DEBUG(linkstate, LINKSTATE))
			zlog_debug("%s: No path found for NLRI type=%u", __func__, nlri->nlri_type);
	}

	/* Unlock node from bgp_afi_node_get */
	bgp_dest_unlock_node(dest);

	return 0;
}

/*
 * ===========================================================================
 * BGP-LS Link State Database Registration
 * ===========================================================================
 */

/*
 * Register BGP with zebra link-state database to receive updates from IGPs
 *
 * @return true on success, false on failure
 */
bool bgp_ls_register(struct bgp *bgp)
{
	/* Already registered */
	if (bgp_ls_is_registered(bgp))
		return true;

	if (ls_register(bgp_zclient, false) != 0) {
		zlog_err("BGP-LS: Failed to register with Link State database");
		return false;
	}

	bgp->ls_info->registered_ls_db = true;

	zlog_info("BGP-LS: Registered with Link State database for BGP instance %s",
		  bgp->name_pretty);
	return true;
}

/*
 * Unregister BGP from zebra link-state database
 *
 * @return true on success, false on failure
 */
bool bgp_ls_unregister(struct bgp *bgp)
{
	/* Not registered */
	if (!bgp_ls_is_registered(bgp))
		return true;

	if (ls_unregister(bgp_zclient, false) != 0) {
		zlog_err("BGP-LS: Failed to unregister from Link State database");
		return false;
	}

	bgp->ls_info->registered_ls_db = false;

	zlog_info("BGP-LS: Unregistered from Link State database for BGP instance %s",
		  bgp->name_pretty);
	return true;
}

/*
 * Check if BGP is registered with zebra link-state database
 * Returns true if registered, false otherwise
 */
bool bgp_ls_is_registered(struct bgp *bgp)
{
	if (!bgp || !bgp->ls_info)
		return false;

	return bgp->ls_info->registered_ls_db;
}

/*
 * ===========================================================================
 * Module Initialization and Cleanup
 * ===========================================================================
 */

/*
 * Initialize BGP-LS module for a BGP instance
 * Called from bgp_create() for the default BGP instance only
 */
void bgp_ls_init(struct bgp *bgp)
{
	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return;

	bgp->ls_info = XCALLOC(MTYPE_BGP_LS, sizeof(struct bgp_ls));
	bgp->ls_info->bgp = bgp;
	bgp->ls_info->allocator = idalloc_new("BGP-LS NLRI ID Allocator");
	bgp_ls_nlri_hash_init(&bgp->ls_info->nlri_hash);

	bgp->ls_info->ted = ls_ted_new(bgp->as, "BGP-LS TED", bgp->as);

	zlog_info("BGP-LS: Module initialized for instance %s", bgp->name_pretty);
}

/*
 * Cleanup BGP-LS module for a BGP instance
 * Called from bgp_free() for the default BGP instance only
 */
void bgp_ls_cleanup(struct bgp *bgp)
{
	struct bgp_ls_nlri *entry;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return;

	bgp_ls_unregister(bgp);

	frr_each_safe (bgp_ls_nlri_hash, &bgp->ls_info->nlri_hash, entry) {
		bgp_ls_nlri_hash_del(&bgp->ls_info->nlri_hash, entry);
		bgp_ls_nlri_free(entry);
	}
	bgp_ls_nlri_hash_fini(&bgp->ls_info->nlri_hash);

	ls_ted_del_all(&bgp->ls_info->ted);

	idalloc_destroy(bgp->ls_info->allocator);

	XFREE(MTYPE_BGP_LS, bgp->ls_info);

	zlog_info("BGP-LS: Module terminated for instance %s", bgp->name_pretty);
}
