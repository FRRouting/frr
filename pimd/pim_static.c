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
#include "pim_memory.h"

DEFINE_MTYPE_STATIC(PIMD, PIM_STATIC_ROUTE_CFG, "PIM Static Route config");

void pim_static_route_free(struct static_route *s_route)
{
	XFREE(MTYPE_PIM_STATIC_ROUTE, s_route);
}

void pim_static_route_config_free(struct static_route_config *cfg)
{
	XFREE(MTYPE_PIM_STATIC_ROUTE_CFG, cfg);
}

static struct static_route *static_route_alloc(void)
{
	return XCALLOC(MTYPE_PIM_STATIC_ROUTE, sizeof(struct static_route));
}

static struct static_route *static_route_new(ifindex_t iif, ifindex_t oif, pim_addr group,
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

static bool pim_static_if_vif_ready(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	if (!ifp || !ifp->info)
		return false;

	pim_ifp = ifp->info;
	return pim_ifp->mroute_vif_index > 0;
}

/*
 * Deferred-configuration queue helpers.
 *
 * Static mroutes configured before their interfaces have valid VIF indices
 * (e.g. while applying the startup config at boot) are queued here, keyed by
 * interface name, and installed by pim_static_reconcile() once the VIFs are
 * ready.  Pending entries are also emitted in the running-config so they
 * survive a reload.
 */
static struct static_route_config *static_route_config_find(struct pim_instance *pim,
							    const char *iifname,
							    const char *oifname, pim_addr group,
							    pim_addr source)
{
	struct static_route_config *cfg;

	frr_each (pim_static_route_cfgs, &pim->static_route_configs, cfg) {
		if (strcmp(cfg->iifname, iifname))
			continue;
		if (strcmp(cfg->oifname, oifname))
			continue;
		if (pim_addr_cmp(cfg->group, group))
			continue;
		if (pim_addr_cmp(cfg->source, source))
			continue;
		return cfg;
	}

	return NULL;
}

static int static_route_config_add(struct pim_instance *pim, const char *iifname,
				   const char *oifname, pim_addr group, pim_addr source)
{
	struct static_route_config *cfg;

	if (static_route_config_find(pim, iifname, oifname, group, source))
		return -3;

	cfg = XCALLOC(MTYPE_PIM_STATIC_ROUTE_CFG, sizeof(*cfg));
	strlcpy(cfg->iifname, iifname, sizeof(cfg->iifname));
	strlcpy(cfg->oifname, oifname, sizeof(cfg->oifname));
	cfg->group = group;
	cfg->source = source;
	pim_static_route_cfgs_add_tail(&pim->static_route_configs, cfg);

	if (PIM_DEBUG_STATIC)
		zlog_debug("%s: deferred static route (iif=%s,oif=%s,group=%pPAs,source=%pPAs)",
			   __func__, iifname, oifname, &group, &source);

	return 0;
}

static int static_route_config_del(struct pim_instance *pim, const char *iifname,
				   const char *oifname, pim_addr group, pim_addr source)
{
	struct static_route_config *cfg;

	cfg = static_route_config_find(pim, iifname, oifname, group, source);
	if (!cfg)
		return -1;

	pim_static_route_cfgs_del(&pim->static_route_configs, cfg);
	pim_static_route_config_free(cfg);

	if (PIM_DEBUG_STATIC)
		zlog_debug("%s: removed deferred static route (iif=%s,oif=%s,group=%pPAs,source=%pPAs)",
			   __func__, iifname, oifname, &group, &source);

	return 0;
}

/*
 * Install a static mroute into the kernel.  Both interfaces are guaranteed by
 * the caller to have valid VIF indices.
 */
static int pim_static_add_install(struct pim_instance *pim, struct interface *iif,
				  struct interface *oif, pim_addr group, pim_addr source)
{
	struct listnode *node = NULL;
	struct static_route *s_route = NULL;
	struct static_route *original_s_route = NULL;
	struct pim_interface *pim_iif = iif->info;
	struct pim_interface *pim_oif = oif->info;
	ifindex_t iif_index = pim_iif->mroute_vif_index;
	ifindex_t oif_index = pim_oif->mroute_vif_index;

#ifdef PIM_ENFORCE_LOOPFREE_MFC
	if (iif_index == oif_index) {
		zlog_warn("%s %s: Unable to add static route: Looped MFC entry(iif=%d,oif=%d)",
			  __FILE__, __func__, iif_index, oif_index);
		return -4;
	}
#endif

	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, s_route)) {
		if (!pim_addr_cmp(s_route->group, group) &&
		    !pim_addr_cmp(s_route->source, source) && (s_route->iif == iif_index)) {
			if (s_route->oif_ttls[oif_index]) {
				zlog_warn("%s %s: Unable to add static route: Route already exists (iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
					  __FILE__, __func__, iif_index, oif_index, &group,
					  &source);
				return -3;
			}

			/*
			 * Making changes to the s_route structure; if we fail
			 * to commit them to the kernel we want to be able to
			 * restore the previous state, so save a copy.
			 */
			original_s_route = static_route_alloc();
			memcpy(original_s_route, s_route, sizeof(struct static_route));

			/* Adding a new output interface to an existing route. */
			s_route->oif_ttls[oif_index] = 1;
			oil_if_set(&s_route->c_oil, oif_index, 1);
			s_route->c_oil.oif_creation[oif_index] = pim_time_monotonic_sec();
			++s_route->c_oil.oil_ref_count;
			break;
		}
	}

	/* No existing route matched, create a fresh one. */
	if (!node) {
		s_route = static_route_new(iif_index, oif_index, group, source);
		listnode_add(pim->static_routes, s_route);
	}

	s_route->c_oil.pim = pim;

	if (pim_static_mroute_add(&s_route->c_oil, __func__)) {
		zlog_warn("%s %s: Unable to add static route(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
			  __FILE__, __func__, iif_index, oif_index, &group, &source);

		/* Restore the previous state. */
		if (original_s_route) {
			memcpy(s_route, original_s_route, sizeof(struct static_route));
			pim_static_route_free(original_s_route);
		} else {
			listnode_delete(pim->static_routes, s_route);
			pim_static_route_free(s_route);
		}

		return -1;
	}

	if (original_s_route)
		pim_static_route_free(original_s_route);

	if (PIM_DEBUG_STATIC)
		zlog_debug("%s: Static route added(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
			   __func__, iif_index, oif_index, &group, &source);

	return 0;
}

int pim_static_add(struct pim_instance *pim, struct interface *iif, struct interface *oif,
		   const char *oifname, pim_addr group, pim_addr source)
{
	if (!iif || !iif->info || !oifname || !oifname[0])
		return -2;

	if (oif && iif->vrf->vrf_id != oif->vrf->vrf_id)
		return -3;

#ifdef PIM_ENFORCE_LOOPFREE_MFC
	if (oif && iif->ifindex == oif->ifindex)
		return -4;
#endif

	/* Both VIFs ready: install now. Otherwise defer until reconcile. */
	if (pim_static_if_vif_ready(iif) && oif && pim_static_if_vif_ready(oif))
		return pim_static_add_install(pim, iif, oif, group, source);

	return static_route_config_add(pim, iif->name, oif ? oif->name : oifname, group, source);
}

/*
 * Remove one output interface from an installed static route, matched by VIF
 * index. Both interfaces are guaranteed by the caller to have valid VIFs.
 */
static int pim_static_del_install(struct pim_instance *pim, struct interface *iif,
				  struct interface *oif, pim_addr group, pim_addr source)
{
	struct listnode *node = NULL;
	struct listnode *nextnode = NULL;
	struct static_route *s_route = NULL;
	struct pim_interface *pim_iif = iif->info;
	struct pim_interface *pim_oif = oif->info;
	ifindex_t iif_index = pim_iif->mroute_vif_index;
	ifindex_t oif_index = pim_oif->mroute_vif_index;

	for (ALL_LIST_ELEMENTS(pim->static_routes, node, nextnode, s_route)) {
		if (s_route->iif != iif_index || pim_addr_cmp(s_route->group, group) ||
		    pim_addr_cmp(s_route->source, source) || !s_route->oif_ttls[oif_index])
			continue;

		s_route->oif_ttls[oif_index] = 0;
		oil_if_set(&s_route->c_oil, oif_index, 0);
		--s_route->c_oil.oil_ref_count;

		/*
		 * If there are no more outputs then delete the whole route,
		 * otherwise update the route with the remaining outputs.
		 */
		if (s_route->c_oil.oil_ref_count <= 0
			    ? pim_mroute_del(&s_route->c_oil, __func__)
			    : pim_static_mroute_add(&s_route->c_oil, __func__)) {
			zlog_warn("%s %s: Unable to remove static route(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
				  __FILE__, __func__, iif_index, oif_index, &group, &source);

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

		if (PIM_DEBUG_STATIC)
			zlog_debug("%s: Static route removed(iif=%d,oif=%d,group=%pPAs,source=%pPAs)",
				   __func__, iif_index, oif_index, &group, &source);

		return 0;
	}

	return -3;
}

int pim_static_del(struct pim_instance *pim, struct interface *iif, struct interface *oif,
		   const char *oifname, pim_addr group, pim_addr source)
{
	const char *oname;

	if (!iif || !iif->info || !oifname || !oifname[0])
		return -2;

	oname = oif ? oif->name : oifname;

	/* A still-pending (never installed) route is removed from the queue. */
	if (!static_route_config_del(pim, iif->name, oname, group, source))
		return 0;

	/* Otherwise it must be installed; delete it by VIF index. */
	if (oif && pim_static_if_vif_ready(iif) && pim_static_if_vif_ready(oif))
		return pim_static_del_install(pim, iif, oif, group, source);

	zlog_warn("%s %s: Unable to remove static route: route does not exist (iif=%s,oif=%s,group=%pPAs,source=%pPAs)",
		  __FILE__, __func__, iif->name, oname, &group, &source);

	return -3;
}

void pim_static_route_configs_fini(struct pim_instance *pim)
{
	struct static_route_config *cfg;

	frr_each_safe (pim_static_route_cfgs, &pim->static_route_configs, cfg) {
		pim_static_route_cfgs_del(&pim->static_route_configs, cfg);
		pim_static_route_config_free(cfg);
	}

	/* Generated _fini asserts the list is empty in debug builds. */
	pim_static_route_cfgs_fini(&pim->static_route_configs);
}

/*
 * Called whenever a new VIF becomes available. Walk the deferred queue and
 * install any route whose input and output interfaces are now both ready.
 */
void pim_static_reconcile(struct pim_instance *pim)
{
	struct static_route_config *cfg;

	frr_each_safe (pim_static_route_cfgs, &pim->static_route_configs, cfg) {
		struct interface *iif, *oif;
		int ret;

		iif = if_lookup_by_name(cfg->iifname, pim->vrf->vrf_id);
		oif = if_lookup_by_name(cfg->oifname, pim->vrf->vrf_id);
		if (!iif || !oif)
			continue;
		if (!pim_static_if_vif_ready(iif) || !pim_static_if_vif_ready(oif))
			continue;

		pim_static_route_cfgs_del(&pim->static_route_configs, cfg);

		ret = pim_static_add_install(pim, iif, oif, cfg->group, cfg->source);
		if (ret == -1) {
			/* Transient kernel failure: re-queue and retry later. */
			pim_static_route_cfgs_add_tail(&pim->static_route_configs, cfg);
			continue;
		}

		if (ret && PIM_DEBUG_STATIC)
			zlog_debug("%s: dropping deferred static route (iif=%s,oif=%s,group=%pPAs,source=%pPAs): install returned %d",
				   __func__, cfg->iifname, cfg->oifname, &cfg->group, &cfg->source,
				   ret);

		pim_static_route_config_free(cfg);
	}
}

int pim_static_write_mroute(struct pim_instance *pim, struct vty *vty, struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct listnode *node;
	struct static_route *sroute;
	struct static_route_config *cfg;
	int count = 0;

	if (!pim_ifp)
		return 0;

	/* Installed routes. */
	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, sroute)) {
		if (sroute->iif != pim_ifp->mroute_vif_index)
			continue;

		for (int i = 0; i < MAXVIFS; i++) {
			struct interface *oifp;

			if (!sroute->oif_ttls[i])
				continue;

			oifp = pim_if_find_by_vif_index(pim, i);
			if (!oifp)
				continue;

			if (pim_addr_is_any(sroute->source))
				vty_out(vty, " " PIM_AF_NAME " mroute %s %pPA\n", oifp->name,
					&sroute->group);
			else
				vty_out(vty, " " PIM_AF_NAME " mroute %s %pPA %pPA\n", oifp->name,
					&sroute->group, &sroute->source);
			count++;
		}
	}

	/* Still-pending (deferred) routes, so they survive a reload. */
	frr_each (pim_static_route_cfgs, &pim->static_route_configs, cfg) {
		if (strcmp(cfg->iifname, ifp->name))
			continue;

		if (pim_addr_is_any(cfg->source))
			vty_out(vty, " " PIM_AF_NAME " mroute %s %pPA\n", cfg->oifname,
				&cfg->group);
		else
			vty_out(vty, " " PIM_AF_NAME " mroute %s %pPA %pPA\n", cfg->oifname,
				&cfg->group, &cfg->source);
		count++;
	}

	return count;
}
