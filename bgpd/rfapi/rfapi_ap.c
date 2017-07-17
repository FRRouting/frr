/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <errno.h>

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/vty.h"
#include "lib/memory.h"
#include "lib/routemap.h"
#include "lib/log.h"
#include "lib/linklist.h"
#include "lib/command.h"
#include "lib/stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_attr.h"

#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_backend.h"

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_advertise.h"

#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp_p.h"
#include "bgpd/rfapi/vnc_zebra.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/rfapi_rib.h"

#include "bgpd/rfapi/rfapi_ap.h"
#include "bgpd/rfapi/vnc_debug.h"

/*
 * Per-NVE Advertised prefixes
 *
 * We maintain a list of prefixes advertised by each NVE.
 * There are two indices: by prefix and by lifetime.
 *
 * BY-PREFIX skiplist
 *
 *  key:	ptr to struct prefix (when storing, point to prefix that
 *		is part of rfapi_adb).
 *
 *  value:	ptr to struct rfapi_adb
 *
 * BY-LIFETIME skiplist
 *
 *  key:	ptr to struct rfapi_adb
 *  value:	ptr to struct rfapi_adb
 *
 */

/*
 * Skiplist sort function that sorts first according to lifetime
 * and then according to adb pointer value. The adb pointer
 * is used to spread out the sort for adbs with the same lifetime
 * and thereby make the skip list operations more efficient.
 */
static int sl_adb_lifetime_cmp(void *adb1, void *adb2)
{
	struct rfapi_adb *a1 = adb1;
	struct rfapi_adb *a2 = adb2;

	if (a1->lifetime < a2->lifetime)
		return -1;
	if (a1->lifetime > a2->lifetime)
		return 1;

	if (a1 < a2)
		return -1;
	if (a1 > a2)
		return 1;

	return 0;
}

void rfapiApInit(struct rfapi_advertised_prefixes *ap)
{
	ap->ipN_by_prefix = skiplist_new(0, rfapi_rib_key_cmp, NULL);
	ap->ip0_by_ether = skiplist_new(0, rfapi_rib_key_cmp, NULL);
	ap->by_lifetime = skiplist_new(0, sl_adb_lifetime_cmp, NULL);
}

void rfapiApRelease(struct rfapi_advertised_prefixes *ap)
{
	struct rfapi_adb *adb;

	/* Free ADBs and lifetime items */
	while (0 == skiplist_first(ap->by_lifetime, NULL, (void **)&adb)) {
		rfapiAdbFree(adb);
		skiplist_delete_first(ap->by_lifetime);
	}

	while (0 == skiplist_delete_first(ap->ipN_by_prefix))
		;
	while (0 == skiplist_delete_first(ap->ip0_by_ether))
		;

	/* Free lists */
	skiplist_free(ap->ipN_by_prefix);
	skiplist_free(ap->ip0_by_ether);
	skiplist_free(ap->by_lifetime);

	ap->ipN_by_prefix = NULL;
	ap->ip0_by_ether = NULL;
	ap->by_lifetime = NULL;
}

int rfapiApCount(struct rfapi_descriptor *rfd)
{
	if (!rfd->advertised.by_lifetime)
		return 0;

	return skiplist_count(rfd->advertised.by_lifetime);
}

int rfapiApCountAll(struct bgp *bgp)
{
	struct rfapi *h;
	struct listnode *node;
	struct rfapi_descriptor *rfd;
	int total = 0;

	h = bgp->rfapi;
	if (h) {
		for (ALL_LIST_ELEMENTS_RO(&h->descriptors, node, rfd)) {
			total += rfapiApCount(rfd);
		}
	}
	return total;
}


void rfapiApReadvertiseAll(struct bgp *bgp, struct rfapi_descriptor *rfd)
{
	struct rfapi_adb *adb;
	void *cursor = NULL;
	int rc;

	for (rc = skiplist_next(rfd->advertised.by_lifetime, NULL,
				(void **)&adb, &cursor);
	     rc == 0; rc = skiplist_next(rfd->advertised.by_lifetime, NULL,
					 (void **)&adb, &cursor)) {

		struct prefix_rd prd;
		uint32_t local_pref = rfp_cost_to_localpref(adb->cost);

		prd = rfd->rd;
		prd.family = AF_UNSPEC;
		prd.prefixlen = 64;

		/*
		 * TBD this is not quite right. When pfx_ip is 0/32 or 0/128,
		 * we need to substitute the VN address as the prefix
		 */
		add_vnc_route(rfd, bgp, SAFI_MPLS_VPN, &adb->u.s.prefix_ip,
			      &prd,	  /* RD to use (0 for ENCAP) */
			      &rfd->vn_addr, /* nexthop */
			      &local_pref, &adb->lifetime, NULL,
			      NULL, /* struct rfapi_un_option */
			      NULL, /* struct rfapi_vn_option */
			      rfd->rt_export_list, NULL, /* med */
			      NULL, ZEBRA_ROUTE_BGP, BGP_ROUTE_RFP, 0);
	}
}

void rfapiApWithdrawAll(struct bgp *bgp, struct rfapi_descriptor *rfd)
{
	struct rfapi_adb *adb;
	void *cursor;
	int rc;


	cursor = NULL;
	for (rc = skiplist_next(rfd->advertised.by_lifetime, NULL,
				(void **)&adb, &cursor);
	     rc == 0; rc = skiplist_next(rfd->advertised.by_lifetime, NULL,
					 (void **)&adb, &cursor)) {

		struct prefix pfx_vn_buf;
		struct prefix *pfx_ip;

		if (!(RFAPI_0_PREFIX(&adb->u.s.prefix_ip)
		      && RFAPI_HOST_PREFIX(&adb->u.s.prefix_ip))) {

			pfx_ip = &adb->u.s.prefix_ip;

		} else {

			pfx_ip = NULL;

			/*
			 * 0/32 or 0/128 => mac advertisement
			 */
			if (rfapiRaddr2Qprefix(&rfd->vn_addr, &pfx_vn_buf)) {
				/*
				 * Bad: it means we can't delete the route
				 */
				vnc_zlog_debug_verbose(
					"%s: BAD: handle has bad vn_addr: skipping",
					__func__);
				continue;
			}
		}

		del_vnc_route(rfd, rfd->peer, bgp, SAFI_MPLS_VPN,
			      pfx_ip ? pfx_ip : &pfx_vn_buf,
			      &adb->u.s.prd, /* RD to use (0 for ENCAP) */
			      ZEBRA_ROUTE_BGP, BGP_ROUTE_RFP, NULL, 0);
	}
}

/*
 * returns nonzero if tunnel readvertisement is needed, 0 otherwise
 */
static int rfapiApAdjustLifetimeStats(
	struct rfapi_descriptor *rfd,
	uint32_t *old_lifetime, /* set if removing/replacing */
	uint32_t *new_lifetime) /* set if replacing/adding */
{
	int advertise = 0;
	int find_max = 0;
	int find_min = 0;

	vnc_zlog_debug_verbose("%s: rfd=%p, pOldLife=%p, pNewLife=%p", __func__,
			       rfd, old_lifetime, new_lifetime);
	if (old_lifetime)
		vnc_zlog_debug_verbose("%s: OldLife=%d", __func__,
				       *old_lifetime);
	if (new_lifetime)
		vnc_zlog_debug_verbose("%s: NewLife=%d", __func__,
				       *new_lifetime);

	if (new_lifetime) {
		/*
		 * Adding new lifetime
		 */
		if (old_lifetime) {
			/*
			 * replacing existing lifetime
			 */


			/* old and new are same */
			if (*old_lifetime == *new_lifetime)
				return 0;

			if (*old_lifetime == rfd->min_prefix_lifetime) {
				find_min = 1;
			}
			if (*old_lifetime == rfd->max_prefix_lifetime) {
				find_max = 1;
			}

			/* no need to search if new value is at or equals
			 * min|max  */
			if (*new_lifetime <= rfd->min_prefix_lifetime) {
				rfd->min_prefix_lifetime = *new_lifetime;
				find_min = 0;
			}
			if (*new_lifetime >= rfd->max_prefix_lifetime) {
				rfd->max_prefix_lifetime = *new_lifetime;
				advertise = 1;
				find_max = 0;
			}

		} else {
			/*
			 * Just adding new lifetime
			 */
			if (*new_lifetime < rfd->min_prefix_lifetime) {
				rfd->min_prefix_lifetime = *new_lifetime;
			}
			if (*new_lifetime > rfd->max_prefix_lifetime) {
				advertise = 1;
				rfd->max_prefix_lifetime = *new_lifetime;
			}
		}
	} else {
		/*
		 * Deleting
		 */

		/*
		 * See if the max prefix lifetime for this NVE has decreased.
		 * The easy optimization: track min & max; walk the table only
		 * if they are different.
		 * The general optimization: index the advertised_prefixes
		 * table by lifetime.
		 *
		 * Note: for a given nve_descriptor, only one of the
		 * advertised_prefixes[] tables will be used: viz., the
		 * address family that matches the VN address.
		 *
		 */
		if (rfd->max_prefix_lifetime == rfd->min_prefix_lifetime) {

			/*
			 * Common case: all lifetimes are the same. Only
			 * thing we need to do here is check if there are
			 * no exported routes left. In that case, reinitialize
			 * the max and min values.
			 */
			if (!rfapiApCount(rfd)) {
				rfd->max_prefix_lifetime = 0;
				rfd->min_prefix_lifetime = UINT32_MAX;
			}


		} else {
			if (old_lifetime) {
				if (*old_lifetime == rfd->min_prefix_lifetime) {
					find_min = 1;
				}
				if (*old_lifetime == rfd->max_prefix_lifetime) {
					find_max = 1;
				}
			}
		}
	}

	if (find_min || find_max) {
		uint32_t min = UINT32_MAX;
		uint32_t max = 0;

		struct rfapi_adb *adb_min;
		struct rfapi_adb *adb_max;

		if (!skiplist_first(rfd->advertised.by_lifetime,
				    (void **)&adb_min, NULL)
		    && !skiplist_last(rfd->advertised.by_lifetime,
				      (void **)&adb_max, NULL)) {

			/*
			 * This should always work
			 */
			min = adb_min->lifetime;
			max = adb_max->lifetime;

		} else {

			void *cursor;
			struct rfapi_rib_key rk;
			struct rfapi_adb *adb;
			int rc;

			vnc_zlog_debug_verbose(
				"%s: walking to find new min/max", __func__);

			cursor = NULL;
			for (rc = skiplist_next(rfd->advertised.ipN_by_prefix,
						(void **)&rk, (void **)&adb,
						&cursor);
			     !rc;
			     rc = skiplist_next(rfd->advertised.ipN_by_prefix,
						(void **)&rk, (void **)&adb,
						&cursor)) {

				uint32_t lt = adb->lifetime;

				if (lt > max)
					max = lt;
				if (lt < min)
					min = lt;
			}
			cursor = NULL;
			for (rc = skiplist_next(rfd->advertised.ip0_by_ether,
						(void **)&rk, (void **)&adb,
						&cursor);
			     !rc;
			     rc = skiplist_next(rfd->advertised.ip0_by_ether,
						(void **)&rk, (void **)&adb,
						&cursor)) {

				uint32_t lt = adb->lifetime;

				if (lt > max)
					max = lt;
				if (lt < min)
					min = lt;
			}
		}

		/*
		 * trigger tunnel route update
		 * but only if we found a VPN route and it had
		 * a lifetime greater than 0
		 */
		if (max && rfd->max_prefix_lifetime != max)
			advertise = 1;
		rfd->max_prefix_lifetime = max;
		rfd->min_prefix_lifetime = min;
	}

	vnc_zlog_debug_verbose("%s: returning advertise=%d, min=%d, max=%d",
			       __func__, advertise, rfd->min_prefix_lifetime,
			       rfd->max_prefix_lifetime);

	return (advertise != 0);
}

/*
 * Return Value
 *
 *	0	No need to advertise tunnel route
 *	non-0	advertise tunnel route
 */
int rfapiApAdd(struct bgp *bgp, struct rfapi_descriptor *rfd,
	       struct prefix *pfx_ip, struct prefix *pfx_eth,
	       struct prefix_rd *prd, uint32_t lifetime, uint8_t cost,
	       struct rfapi_l2address_option *l2o) /* other options TBD */
{
	int rc;
	struct rfapi_adb *adb;
	uint32_t old_lifetime = 0;
	int use_ip0 = 0;
	struct rfapi_rib_key rk;

	rfapi_rib_key_init(pfx_ip, prd, pfx_eth, &rk);
	if (RFAPI_0_PREFIX(pfx_ip) && RFAPI_HOST_PREFIX(pfx_ip)) {
		use_ip0 = 1;
		assert(pfx_eth);
		rc = skiplist_search(rfd->advertised.ip0_by_ether, &rk,
				     (void **)&adb);

	} else {

		/* find prefix in advertised prefixes list */
		rc = skiplist_search(rfd->advertised.ipN_by_prefix, &rk,
				     (void **)&adb);
	}


	if (rc) {
		/* Not found */
		adb = XCALLOC(MTYPE_RFAPI_ADB, sizeof(struct rfapi_adb));
		assert(adb);
		adb->lifetime = lifetime;
		adb->u.key = rk;

		if (use_ip0) {
			assert(pfx_eth);
			skiplist_insert(rfd->advertised.ip0_by_ether,
					&adb->u.key, adb);
		} else {
			skiplist_insert(rfd->advertised.ipN_by_prefix,
					&adb->u.key, adb);
		}

		skiplist_insert(rfd->advertised.by_lifetime, adb, adb);
	} else {
		old_lifetime = adb->lifetime;
		if (old_lifetime != lifetime) {
			assert(!skiplist_delete(rfd->advertised.by_lifetime,
						adb, NULL));
			adb->lifetime = lifetime;
			assert(!skiplist_insert(rfd->advertised.by_lifetime,
						adb, adb));
		}
	}
	adb->cost = cost;
	if (l2o)
		adb->l2o = *l2o;
	else
		memset(&adb->l2o, 0, sizeof(struct rfapi_l2address_option));

	if (rfapiApAdjustLifetimeStats(rfd, (rc ? NULL : &old_lifetime),
				       &lifetime))
		return 1;

	return 0;
}

/*
 * After this function returns successfully, caller should call
 * rfapiAdjustLifetimeStats() and possibly rfapiTunnelRouteAnnounce()
 */
int rfapiApDelete(struct bgp *bgp, struct rfapi_descriptor *rfd,
		  struct prefix *pfx_ip, struct prefix *pfx_eth,
		  struct prefix_rd *prd, int *advertise_tunnel) /* out */
{
	int rc;
	struct rfapi_adb *adb;
	uint32_t old_lifetime;
	int use_ip0 = 0;
	struct rfapi_rib_key rk;

	if (advertise_tunnel)
		*advertise_tunnel = 0;

	rfapi_rib_key_init(pfx_ip, prd, pfx_eth, &rk);
	/* find prefix in advertised prefixes list */
	if (RFAPI_0_PREFIX(pfx_ip) && RFAPI_HOST_PREFIX(pfx_ip)) {
		use_ip0 = 1;
		assert(pfx_eth);

		rc = skiplist_search(rfd->advertised.ip0_by_ether, &rk,
				     (void **)&adb);

	} else {

		/* find prefix in advertised prefixes list */
		rc = skiplist_search(rfd->advertised.ipN_by_prefix, &rk,
				     (void **)&adb);
	}

	if (rc) {
		return ENOENT;
	}

	old_lifetime = adb->lifetime;

	if (use_ip0) {
		rc = skiplist_delete(rfd->advertised.ip0_by_ether, &rk, NULL);
	} else {
		rc = skiplist_delete(rfd->advertised.ipN_by_prefix, &rk, NULL);
	}
	assert(!rc);

	rc = skiplist_delete(rfd->advertised.by_lifetime, adb, NULL);
	assert(!rc);

	rfapiAdbFree(adb);

	if (rfapiApAdjustLifetimeStats(rfd, &old_lifetime, NULL)) {
		if (advertise_tunnel)
			*advertise_tunnel = 1;
	}

	return 0;
}
