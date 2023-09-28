// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for FRR - J/P Aggregation
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Donald Sharp
 */
#include <zebra.h>

#include "linklist.h"
#include "log.h"
#include "vrf.h"
#include "if.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_msg.h"
#include "pim_jp_agg.h"
#include "pim_join.h"
#include "pim_iface.h"

void pim_jp_agg_group_list_free(struct pim_jp_agg_group *jag)
{
	list_delete(&jag->sources);

	XFREE(MTYPE_PIM_JP_AGG_GROUP, jag);
}

static void pim_jp_agg_src_free(struct pim_jp_sources *js)
{
	struct pim_upstream *up = js->up;

	/*
	 * When we are being called here, we know
	 * that the neighbor is going away start
	 * the normal j/p timer so that it can
	 * pick this shit back up when the
	 * nbr comes back alive
	 */
	if (up)
		join_timer_start(js->up);
	XFREE(MTYPE_PIM_JP_AGG_SOURCE, js);
}

int pim_jp_agg_group_list_cmp(void *arg1, void *arg2)
{
	const struct pim_jp_agg_group *jag1 =
		(const struct pim_jp_agg_group *)arg1;
	const struct pim_jp_agg_group *jag2 =
		(const struct pim_jp_agg_group *)arg2;

	return pim_addr_cmp(jag1->group, jag2->group);
}

static int pim_jp_agg_src_cmp(void *arg1, void *arg2)
{
	const struct pim_jp_sources *js1 = (const struct pim_jp_sources *)arg1;
	const struct pim_jp_sources *js2 = (const struct pim_jp_sources *)arg2;

	if (js1->is_join && !js2->is_join)
		return -1;

	if (!js1->is_join && js2->is_join)
		return 1;

	return pim_addr_cmp(js1->up->sg.src, js2->up->sg.src);
}

/*
 * This function is used by scan_oil to clear
 * the created jp_agg_group created when
 * figuring out where to send prunes
 * and joins.
 */
void pim_jp_agg_clear_group(struct list *group)
{
	struct listnode *gnode, *gnnode;
	struct listnode *snode, *snnode;
	struct pim_jp_agg_group *jag;
	struct pim_jp_sources *js;

	for (ALL_LIST_ELEMENTS(group, gnode, gnnode, jag)) {
		for (ALL_LIST_ELEMENTS(jag->sources, snode, snnode, js)) {
			listnode_delete(jag->sources, js);
			js->up = NULL;
			XFREE(MTYPE_PIM_JP_AGG_SOURCE, js);
		}
		list_delete(&jag->sources);
		listnode_delete(group, jag);
		XFREE(MTYPE_PIM_JP_AGG_GROUP, jag);
	}
}

static struct pim_iface_upstream_switch *
pim_jp_agg_get_interface_upstream_switch_list(struct pim_rpf *rpf)
{
	struct interface *ifp = rpf->source_nexthop.interface;
	struct pim_interface *pim_ifp;
	struct pim_iface_upstream_switch *pius;
	struct listnode *node, *nnode;

	if (!ifp)
		return NULL;

	pim_ifp = ifp->info;

	/* Old interface is pim disabled */
	if (!pim_ifp)
		return NULL;

	for (ALL_LIST_ELEMENTS(pim_ifp->upstream_switch_list, node, nnode,
			       pius)) {
		if (!pim_addr_cmp(pius->address, rpf->rpf_addr))
			break;
	}

	if (!pius) {
		pius = XCALLOC(MTYPE_PIM_JP_AGG_GROUP,
			       sizeof(struct pim_iface_upstream_switch));
		pius->address = rpf->rpf_addr;
		pius->us = list_new();
		listnode_add_sort(pim_ifp->upstream_switch_list, pius);
	}

	return pius;
}

void pim_jp_agg_remove_group(struct list *group, struct pim_upstream *up,
		struct pim_neighbor *nbr)
{
	struct listnode *node, *nnode;
	struct pim_jp_agg_group *jag = NULL;
	struct pim_jp_sources *js = NULL;

	for (ALL_LIST_ELEMENTS(group, node, nnode, jag)) {
		if (!pim_addr_cmp(jag->group, up->sg.grp))
			break;
	}

	if (!jag)
		return;

	for (ALL_LIST_ELEMENTS(jag->sources, node, nnode, js)) {
		if (js->up == up)
			break;
	}

	if (nbr) {
		if (PIM_DEBUG_TRACE)
			zlog_debug("up %s remove from nbr %s/%pPAs jp-agg-list",
				   up->sg_str, nbr->interface->name,
				   &nbr->source_addr);
	}

	if (js) {
		js->up = NULL;
		listnode_delete(jag->sources, js);
		XFREE(MTYPE_PIM_JP_AGG_SOURCE, js);
	}

	if (jag->sources->count == 0) {
		list_delete(&jag->sources);
		listnode_delete(group, jag);
		XFREE(MTYPE_PIM_JP_AGG_GROUP, jag);
	}
}

int pim_jp_agg_is_in_list(struct list *group, struct pim_upstream *up)
{
	struct listnode *node, *nnode;
	struct pim_jp_agg_group *jag = NULL;
	struct pim_jp_sources *js = NULL;

	for (ALL_LIST_ELEMENTS(group, node, nnode, jag)) {
		if (!pim_addr_cmp(jag->group, up->sg.grp))
			break;
	}

	if (!jag)
		return 0;

	for (ALL_LIST_ELEMENTS(jag->sources, node, nnode, js)) {
		if (js->up == up)
			return 1;
	}

	return 0;
}

//#define PIM_JP_AGG_DEBUG 1
/*
 * For the given upstream, check all the neighbor
 * jp_agg lists and ensure that it is not
 * in another list
 *
 * *IF* ignore is true we can skip
 * up->rpf.source_nexthop.interface particular interface for checking
 *
 * This is a debugging function, Probably
 * can be safely compiled out in real
 * builds
 */
void pim_jp_agg_upstream_verification(struct pim_upstream *up, bool ignore)
{
#ifdef PIM_JP_AGG_DEBUG
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;

	if (!up->rpf.source_nexthop.interface) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);
		return;
	}

	pim_ifp = up->rpf.source_nexthop.interface->info;
	pim = pim_ifp->pim;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		struct listnode *nnode;

		if (ignore && ifp == up->rpf.source_nexthop.interface)
			continue;

		if (pim_ifp) {
			struct pim_neighbor *neigh;
			for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list,
						  nnode, neigh)) {
				assert(!pim_jp_agg_is_in_list(
					neigh->upstream_jp_agg, up));
			}
		}
	}
#else
	return;
#endif
}

void pim_jp_agg_add_group(struct list *group, struct pim_upstream *up,
			  bool is_join, struct pim_neighbor *nbr)
{
	struct listnode *node, *nnode;
	struct pim_jp_agg_group *jag = NULL;
	struct pim_jp_sources *js = NULL;

	for (ALL_LIST_ELEMENTS(group, node, nnode, jag)) {
		if (!pim_addr_cmp(jag->group, up->sg.grp))
			break;
	}

	if (!jag) {
		jag = XCALLOC(MTYPE_PIM_JP_AGG_GROUP,
			      sizeof(struct pim_jp_agg_group));
		jag->group = up->sg.grp;
		jag->sources = list_new();
		jag->sources->cmp = pim_jp_agg_src_cmp;
		jag->sources->del = (void (*)(void *))pim_jp_agg_src_free;
		listnode_add_sort(group, jag);
	}

	for (ALL_LIST_ELEMENTS(jag->sources, node, nnode, js)) {
		if (js->up == up)
			break;
	}

	if (nbr) {
		if (PIM_DEBUG_TRACE)
			zlog_debug("up %s add to nbr %s/%pPAs jp-agg-list",
				   up->sg_str,
				   up->rpf.source_nexthop.interface->name,
				   &nbr->source_addr);
	}

	if (!js) {
		js = XCALLOC(MTYPE_PIM_JP_AGG_SOURCE,
			     sizeof(struct pim_jp_sources));
		js->up = up;
		js->is_join = is_join;
		listnode_add_sort(jag->sources, js);
	} else {
		if (js->is_join != is_join) {
			listnode_delete(jag->sources, js);
			js->is_join = is_join;
			listnode_add_sort(jag->sources, js);
		}
	}
}

void pim_jp_agg_switch_interface(struct pim_rpf *orpf, struct pim_rpf *nrpf,
				 struct pim_upstream *up)
{
	struct pim_iface_upstream_switch *opius;
	struct pim_iface_upstream_switch *npius;

	opius = pim_jp_agg_get_interface_upstream_switch_list(orpf);
	npius = pim_jp_agg_get_interface_upstream_switch_list(nrpf);

	/*
	 * RFC 4601: 4.5.7.  Sending (S,G) Join/Prune Messages
	 *
	 * Transitions from Joined State
	 *
	 * RPF'(S,G) changes not due to an Assert
	 *
	 * The upstream (S,G) state machine remains in Joined
	 * state. Send Join(S,G) to the new upstream neighbor, which is
	 * the new value of RPF'(S,G).  Send Prune(S,G) to the old
	 * upstream neighbor, which is the old value of RPF'(S,G).  Set
	 * the Join Timer (JT) to expire after t_periodic seconds.
	 */

	/* send Prune(S,G) to the old upstream neighbor */
	if (opius)
		pim_jp_agg_add_group(opius->us, up, false, NULL);

	/* send Join(S,G) to the current upstream neighbor */
	if (npius)
		pim_jp_agg_add_group(npius->us, up, true, NULL);
}


void pim_jp_agg_single_upstream_send(struct pim_rpf *rpf,
				     struct pim_upstream *up, bool is_join)
{
	struct list groups, sources;
	struct pim_jp_agg_group jag;
	struct pim_jp_sources js;

	/* skip JP upstream messages if source is directly connected */
	if (!up || !rpf->source_nexthop.interface ||
		pim_if_connected_to_source(rpf->source_nexthop.interface,
			up->sg.src) ||
		if_is_loopback(rpf->source_nexthop.interface))
		return;

	memset(&groups, 0, sizeof(groups));
	memset(&sources, 0, sizeof(sources));
	jag.sources = &sources;

	listnode_add(&groups, &jag);
	listnode_add(jag.sources, &js);

	jag.group = up->sg.grp;
	js.up = up;
	js.is_join = is_join;

	pim_joinprune_send(rpf, &groups);

	list_delete_all_node(jag.sources);
	list_delete_all_node(&groups);
}
