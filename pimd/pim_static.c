// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga: add the ability to configure multicast static routes
 * Copyright (C) 2014  Nathan Bahr, ATCorp
 */

#include <zebra.h>

#include "vty.h"
#include "if.h"
#include "log.h"
#include "memory.h"
#include "linklist.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_oil.h"
#include "pim_static.h"
#include "pim_time.h"
#include "pim_str.h"
#include "pim_iface.h"

void pim_static_route_free(struct static_route *s_route)
{
	XFREE(MTYPE_PIM_STATIC_ROUTE, s_route);
}

static struct static_route *static_route_alloc(void)
{
	return XCALLOC(MTYPE_PIM_STATIC_ROUTE, sizeof(struct static_route));
}

static struct static_route *static_route_new(ifindex_t iif, ifindex_t oif,
					     pim_addr group,
					     pim_addr source)
{
	struct static_route *s_route;
	s_route = static_route_alloc();

	s_route->group = group;
	s_route->source = source;
	s_route->iif = iif;
	s_route->oif_ttls[oif] = 1;
	s_route->c_oil.oil_ref_count = 1;
	*oil_origin(&s_route->c_oil) = source;
	*oil_mcastgrp(&s_route->c_oil) = group;
	*oil_incoming_vif(&s_route->c_oil) = iif;
	oil_if_set(&s_route->c_oil, oif, 1);
	s_route->c_oil.oif_creation[oif] = pim_time_monotonic_sec();

	return s_route;
}


int pim_static_add(struct pim_instance *pim, struct interface *iif,
		   struct interface *oif, pim_addr group, pim_addr source)
{
	struct listnode *node = NULL;
	struct static_route *s_route = NULL;
	struct static_route *original_s_route = NULL;
	struct pim_interface *pim_iif = iif ? iif->info : NULL;
	struct pim_interface *pim_oif = oif ? oif->info : NULL;
	ifindex_t iif_index = pim_iif ? pim_iif->mroute_vif_index : 0;
	ifindex_t oif_index = pim_oif ? pim_oif->mroute_vif_index : 0;

	if (!iif_index || !oif_index || iif_index == -1 || oif_index == -1) {
		zlog_warn(
			"%s %s: Unable to add static route: Invalid interface index(iif=%d,oif=%d)",
			__FILE__, __func__, iif_index, oif_index);
		return -2;
	}

#ifdef PIM_ENFORCE_LOOPFREE_MFC
	if (iif_index == oif_index) {
		/* looped MFC entry */
		zlog_warn(
			"%s %s: Unable to add static route: Looped MFC entry(iif=%d,oif=%d)",
			__FILE__, __func__, iif_index, oif_index);
		return -4;
	}
#endif
	if (iif->vrf->vrf_id != oif->vrf->vrf_id) {
		return -3;
	}

	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, s_route)) {
		if (!pim_addr_cmp(s_route->group, group) &&
		    !pim_addr_cmp(s_route->source, source) &&
		    (s_route->iif == iif_index)) {

			if (s_route->oif_ttls[oif_index]) {
				zlog_warn(
					"%s %s: Unable to add static route: Route already exists (iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
					__FILE__, __func__, iif_index,
					oif_index, &group, &source);
				return -3;
			}

			/* Ok, from here on out we will be making changes to the
			 * s_route structure, but if
			 * for some reason we fail to commit these changes to
			 * the kernel, we want to be able
			 * restore the state of the list. So copy the node data
			 * and if need be, we can copy
			 * back if it fails.
			 */
			original_s_route = static_route_alloc();
			memcpy(original_s_route, s_route,
			       sizeof(struct static_route));

			/* Route exists and has the same input interface, but
			 * adding a new output interface */
			s_route->oif_ttls[oif_index] = 1;
			oil_if_set(&s_route->c_oil, oif_index, 1);
			s_route->c_oil.oif_creation[oif_index] =
				pim_time_monotonic_sec();
			++s_route->c_oil.oil_ref_count;
			break;
		}
	}

	/* If node is null then we reached the end of the list without finding a
	 * match */
	if (!node) {
		s_route = static_route_new(iif_index, oif_index, group, source);
		listnode_add(pim->static_routes, s_route);
	}

	s_route->c_oil.pim = pim;

	if (pim_static_mroute_add(&s_route->c_oil, __func__)) {
		zlog_warn(
			"%s %s: Unable to add static route(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
			__FILE__, __func__, iif_index, oif_index, &group,
			&source);

		/* Need to put s_route back to the way it was */
		if (original_s_route) {
			memcpy(s_route, original_s_route,
			       sizeof(struct static_route));
		} else {
			/* we never stored off a copy, so it must have been a
			 * fresh new route */
			listnode_delete(pim->static_routes, s_route);
			pim_static_route_free(s_route);
		}

		if (original_s_route) {
			pim_static_route_free(original_s_route);
		}

		return -1;
	}

	/* Make sure we free the memory for the route copy if used */
	if (original_s_route) {
		pim_static_route_free(original_s_route);
	}

	if (PIM_DEBUG_STATIC) {
		zlog_debug(
			"%s: Static route added(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
			__func__, iif_index, oif_index, &group,
			&source);
	}

	return 0;
}

int pim_static_del(struct pim_instance *pim, struct interface *iif,
		   struct interface *oif, pim_addr group, pim_addr source)
{
	struct listnode *node = NULL;
	struct listnode *nextnode = NULL;
	struct static_route *s_route = NULL;
	struct pim_interface *pim_iif = iif ? iif->info : 0;
	struct pim_interface *pim_oif = oif ? oif->info : 0;
	ifindex_t iif_index = pim_iif ? pim_iif->mroute_vif_index : 0;
	ifindex_t oif_index = pim_oif ? pim_oif->mroute_vif_index : 0;

	if (!iif_index || !oif_index) {
		zlog_warn(
			"%s %s: Unable to remove static route: Invalid interface index(iif=%d,oif=%d)",
			__FILE__, __func__, iif_index, oif_index);
		return -2;
	}

	for (ALL_LIST_ELEMENTS(pim->static_routes, node, nextnode, s_route)) {
		if (s_route->iif == iif_index
		    && !pim_addr_cmp(s_route->group, group)
		    && !pim_addr_cmp(s_route->source, source)
		    && s_route->oif_ttls[oif_index]) {
			s_route->oif_ttls[oif_index] = 0;
			oil_if_set(&s_route->c_oil, oif_index, 0);
			--s_route->c_oil.oil_ref_count;

			/* If there are no more outputs then delete the whole
			 * route, otherwise set the route with the new outputs
			 */
			if (s_route->c_oil.oil_ref_count <= 0
				    ? pim_mroute_del(&s_route->c_oil, __func__)
				    : pim_static_mroute_add(&s_route->c_oil,
							    __func__)) {
				zlog_warn(
					"%s %s: Unable to remove static route(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
					__FILE__, __func__, iif_index,
					oif_index, &group, &source);

				s_route->oif_ttls[oif_index] = 1;
				oil_if_set(&s_route->c_oil, oif_index, 1);
				++s_route->c_oil.oil_ref_count;

				return -1;
			}

			s_route->c_oil.oif_creation[oif_index] = 0;

			if (s_route->c_oil.oil_ref_count <= 0) {
				listnode_delete(pim->static_routes, s_route);
				pim_static_route_free(s_route);
			}

			if (PIM_DEBUG_STATIC) {
				zlog_debug(
					"%s: Static route removed(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
					__func__, iif_index, oif_index,
					&group, &source);
			}

			break;
		}
	}

	if (!node) {
		zlog_warn(
			"%s %s: Unable to remove static route: Route does not exist(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
			__FILE__, __func__, iif_index, oif_index, &group,
			&source);
		return -3;
	}

	return 0;
}

int pim_static_write_mroute(struct pim_instance *pim, struct vty *vty,
			    struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct listnode *node;
	struct static_route *sroute;
	int count = 0;

	if (!pim_ifp)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, sroute)) {
		if (sroute->iif == pim_ifp->mroute_vif_index) {
			int i;
			for (i = 0; i < MAXVIFS; i++)
				if (sroute->oif_ttls[i]) {
					struct interface *oifp =
						pim_if_find_by_vif_index(pim,
									 i);
					if (pim_addr_is_any(sroute->source))
						vty_out(vty,
							" " PIM_AF_NAME " mroute %s %pPA\n",
							oifp->name, &sroute->group);
					else
						vty_out(vty,
							" " PIM_AF_NAME " mroute %s %pPA %pPA\n",
							oifp->name, &sroute->group,
							&sroute->source);
					count++;
				}
		}
	}

	return count;
}
