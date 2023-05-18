// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_bsm.c: PIM BSM handling routines
 *
 * Copyright (C) 2018-19 Vmware, Inc.
 * Saravanan K
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "if.h"
#include "pimd.h"
#include "pim_iface.h"
#include "pim_instance.h"
#include "pim_neighbor.h"
#include "pim_rpf.h"
#include "pim_hello.h"
#include "pim_pim.h"
#include "pim_nht.h"
#include "pim_bsm.h"
#include "pim_time.h"
#include "pim_zebra.h"
#include "pim_util.h"

/* Functions forward declaration */
static void pim_bs_timer_start(struct bsm_scope *scope, int bs_timeout);
static void pim_g2rp_timer_start(struct bsm_rpinfo *bsrp, int hold_time);
static inline void pim_g2rp_timer_restart(struct bsm_rpinfo *bsrp,
					  int hold_time);

/* Memory Types */
DEFINE_MTYPE_STATIC(PIMD, PIM_BSGRP_NODE, "PIM BSR advertised grp info");
DEFINE_MTYPE_STATIC(PIMD, PIM_BSRP_INFO, "PIM BSR advertised RP info");
DEFINE_MTYPE_STATIC(PIMD, PIM_BSM_FRAG, "PIM BSM fragment");
DEFINE_MTYPE_STATIC(PIMD, PIM_BSM_PKT_VAR_MEM, "PIM BSM Packet");

/* All bsm packets forwarded shall be fit within ip mtu less iphdr(max) */
#define MAX_IP_HDR_LEN 24

/* pim_bsm_write_config - Write the interface pim bsm configuration.*/
void pim_bsm_write_config(struct vty *vty, struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (pim_ifp) {
		if (!pim_ifp->bsm_enable)
			vty_out(vty, " no " PIM_AF_NAME " pim bsm\n");
		if (!pim_ifp->ucast_bsm_accept)
			vty_out(vty, " no " PIM_AF_NAME " pim unicast-bsm\n");
	}
}

static void pim_bsm_rpinfo_free(struct bsm_rpinfo *bsrp_info)
{
	EVENT_OFF(bsrp_info->g2rp_timer);
	XFREE(MTYPE_PIM_BSRP_INFO, bsrp_info);
}

static void pim_bsm_rpinfos_free(struct bsm_rpinfos_head *head)
{
	struct bsm_rpinfo *bsrp_info;

	while ((bsrp_info = bsm_rpinfos_pop(head)))
		pim_bsm_rpinfo_free(bsrp_info);
}

static void pim_free_bsgrp_data(struct bsgrp_node *bsgrp_node)
{
	pim_bsm_rpinfos_free(bsgrp_node->bsrp_list);
	pim_bsm_rpinfos_free(bsgrp_node->partial_bsrp_list);
	XFREE(MTYPE_PIM_BSGRP_NODE, bsgrp_node);
}

static void pim_free_bsgrp_node(struct route_table *rt, struct prefix *grp)
{
	struct route_node *rn;

	rn = route_node_lookup(rt, grp);
	if (rn) {
		rn->info = NULL;
		route_unlock_node(rn);
		route_unlock_node(rn);
	}
}

static void pim_bsm_frag_free(struct bsm_frag *bsfrag)
{
	XFREE(MTYPE_PIM_BSM_FRAG, bsfrag);
}

static void pim_bsm_frags_free(struct bsm_scope *scope)
{
	struct bsm_frag *bsfrag;

	while ((bsfrag = bsm_frags_pop(scope->bsm_frags)))
		pim_bsm_frag_free(bsfrag);
}

int pim_bsm_rpinfo_cmp(const struct bsm_rpinfo *node1,
		       const struct bsm_rpinfo *node2)
{
	/* RP election Algo :
	 * Step-1 : Loweset Rp priority  will have higher precedance.
	 * Step-2 : If priority same then higher hash val will have
	 *	    higher precedance.
	 * Step-3 : If Hash val is same then highest rp address will
	 *	    become elected RP.
	 */
	if (node1->rp_prio < node2->rp_prio)
		return -1;
	if (node1->rp_prio > node2->rp_prio)
		return 1;
	if (node1->hash < node2->hash)
		return 1;
	if (node1->hash > node2->hash)
		return -1;
	return pim_addr_cmp(node2->rp_address, node1->rp_address);
}

static struct bsgrp_node *pim_bsm_new_bsgrp_node(struct route_table *rt,
						 struct prefix *grp)
{
	struct route_node *rn;
	struct bsgrp_node *bsgrp;

	rn = route_node_get(rt, grp);
	if (!rn) {
		zlog_warn("%s: route node creation failed", __func__);
		return NULL;
	}
	bsgrp = XCALLOC(MTYPE_PIM_BSGRP_NODE, sizeof(struct bsgrp_node));

	rn->info = bsgrp;
	bsm_rpinfos_init(bsgrp->bsrp_list);
	bsm_rpinfos_init(bsgrp->partial_bsrp_list);

	prefix_copy(&bsgrp->group, grp);
	return bsgrp;
}

static void pim_on_bs_timer(struct event *t)
{
	struct route_node *rn;
	struct bsm_scope *scope;
	struct bsgrp_node *bsgrp_node;
	struct bsm_rpinfo *bsrp;

	scope = EVENT_ARG(t);
	EVENT_OFF(scope->bs_timer);

	if (PIM_DEBUG_BSM)
		zlog_debug("%s: Bootstrap Timer expired for scope: %d",
			   __func__, scope->sz_id);

	pim_nht_bsr_del(scope->pim, scope->current_bsr);
	/* Reset scope zone data */
	scope->state = ACCEPT_ANY;
	scope->current_bsr = PIMADDR_ANY;
	scope->current_bsr_prio = 0;
	scope->current_bsr_first_ts = 0;
	scope->current_bsr_last_ts = 0;
	scope->bsm_frag_tag = 0;
	pim_bsm_frags_free(scope);

	for (rn = route_top(scope->bsrp_table); rn; rn = route_next(rn)) {

		bsgrp_node = (struct bsgrp_node *)rn->info;
		if (!bsgrp_node) {
			if (PIM_DEBUG_BSM)
				zlog_debug("%s: bsgrp_node is null", __func__);
			continue;
		}
		/* Give grace time for rp to continue for another hold time */
		bsrp = bsm_rpinfos_first(bsgrp_node->bsrp_list);
		if (bsrp)
			pim_g2rp_timer_restart(bsrp, bsrp->rp_holdtime);

		/* clear pending list */
		pim_bsm_rpinfos_free(bsgrp_node->partial_bsrp_list);
		bsgrp_node->pend_rp_cnt = 0;
	}
}

static void pim_bs_timer_stop(struct bsm_scope *scope)
{
	if (PIM_DEBUG_BSM)
		zlog_debug("%s : BS timer being stopped of sz: %d", __func__,
			   scope->sz_id);
	EVENT_OFF(scope->bs_timer);
}

static void pim_bs_timer_start(struct bsm_scope *scope, int bs_timeout)
{
	if (!scope) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Invalid scope(NULL).", __func__);
		return;
	}
	EVENT_OFF(scope->bs_timer);
	if (PIM_DEBUG_BSM)
		zlog_debug(
			"%s : starting bs timer for scope %d with timeout %d secs",
			__func__, scope->sz_id, bs_timeout);
	event_add_timer(router->master, pim_on_bs_timer, scope, bs_timeout,
			&scope->bs_timer);
}

static inline void pim_bs_timer_restart(struct bsm_scope *scope, int bs_timeout)
{
	pim_bs_timer_start(scope, bs_timeout);
}

void pim_bsm_proc_init(struct pim_instance *pim)
{
	memset(&pim->global_scope, 0, sizeof(struct bsm_scope));

	pim->global_scope.sz_id = PIM_GBL_SZ_ID;
	pim->global_scope.bsrp_table = route_table_init();
	pim->global_scope.accept_nofwd_bsm = true;
	pim->global_scope.state = NO_INFO;
	pim->global_scope.pim = pim;
	bsm_frags_init(pim->global_scope.bsm_frags);
	pim_bs_timer_start(&pim->global_scope, PIM_BS_TIME);
}

void pim_bsm_proc_free(struct pim_instance *pim)
{
	struct route_node *rn;
	struct bsgrp_node *bsgrp;

	pim_bs_timer_stop(&pim->global_scope);
	pim_bsm_frags_free(&pim->global_scope);

	for (rn = route_top(pim->global_scope.bsrp_table); rn;
	     rn = route_next(rn)) {
		bsgrp = rn->info;
		if (!bsgrp)
			continue;
		pim_free_bsgrp_data(bsgrp);
	}

	route_table_finish(pim->global_scope.bsrp_table);
}

static bool is_hold_time_elapsed(void *data)
{
	struct bsm_rpinfo *bsrp;

	bsrp = data;

	if (bsrp->elapse_time < bsrp->rp_holdtime)
		return false;
	else
		return true;
}

static void pim_on_g2rp_timer(struct event *t)
{
	struct bsm_rpinfo *bsrp;
	struct bsm_rpinfo *bsrp_node;
	struct bsgrp_node *bsgrp_node;
	struct pim_instance *pim;
	struct rp_info *rp_info;
	struct route_node *rn;
	uint16_t elapse;
	pim_addr bsrp_addr;

	bsrp = EVENT_ARG(t);
	EVENT_OFF(bsrp->g2rp_timer);
	bsgrp_node = bsrp->bsgrp_node;

	/* elapse time is the hold time of expired node */
	elapse = bsrp->rp_holdtime;
	bsrp_addr = bsrp->rp_address;

	/* update elapse for all bsrp nodes */
	frr_each_safe (bsm_rpinfos, bsgrp_node->bsrp_list, bsrp_node) {
		bsrp_node->elapse_time += elapse;

		if (is_hold_time_elapsed(bsrp_node)) {
			bsm_rpinfos_del(bsgrp_node->bsrp_list, bsrp_node);
			pim_bsm_rpinfo_free(bsrp_node);
		}
	}

	/* Get the next elected rp node */
	bsrp = bsm_rpinfos_first(bsgrp_node->bsrp_list);
	pim = bsgrp_node->scope->pim;
	rn = route_node_lookup(pim->rp_table, &bsgrp_node->group);

	if (!rn) {
		zlog_warn("%s: Route node doesn't exist", __func__);
		return;
	}

	rp_info = (struct rp_info *)rn->info;

	if (!rp_info) {
		route_unlock_node(rn);
		return;
	}

	if (rp_info->rp_src != RP_SRC_STATIC) {
		/* If new rp available, change it else delete the existing */
		if (bsrp) {
			pim_g2rp_timer_start(
				bsrp, (bsrp->rp_holdtime - bsrp->elapse_time));
			pim_rp_change(pim, bsrp->rp_address, bsgrp_node->group,
				      RP_SRC_BSR);
		} else {
			pim_rp_del(pim, bsrp_addr, bsgrp_node->group, NULL,
				   RP_SRC_BSR);
		}
	}

	if (!bsm_rpinfos_count(bsgrp_node->bsrp_list)
	    && !bsm_rpinfos_count(bsgrp_node->partial_bsrp_list)) {
		pim_free_bsgrp_node(pim->global_scope.bsrp_table,
				    &bsgrp_node->group);
		pim_free_bsgrp_data(bsgrp_node);
	}
}

static void pim_g2rp_timer_start(struct bsm_rpinfo *bsrp, int hold_time)
{
	if (!bsrp) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Invalid brsp(NULL).", __func__);
		return;
	}
	EVENT_OFF(bsrp->g2rp_timer);
	if (PIM_DEBUG_BSM)
		zlog_debug(
			"%s : starting g2rp timer for grp: %pFX - rp: %pPAs with timeout  %d secs(Actual Hold time : %d secs)",
			__func__, &bsrp->bsgrp_node->group, &bsrp->rp_address,
			hold_time, bsrp->rp_holdtime);

	event_add_timer(router->master, pim_on_g2rp_timer, bsrp, hold_time,
			&bsrp->g2rp_timer);
}

static inline void pim_g2rp_timer_restart(struct bsm_rpinfo *bsrp,
					  int hold_time)
{
	pim_g2rp_timer_start(bsrp, hold_time);
}

static void pim_g2rp_timer_stop(struct bsm_rpinfo *bsrp)
{
	if (!bsrp)
		return;

	if (PIM_DEBUG_BSM)
		zlog_debug("%s : stopping g2rp timer for grp: %pFX - rp: %pPAs",
			   __func__, &bsrp->bsgrp_node->group,
			   &bsrp->rp_address);

	EVENT_OFF(bsrp->g2rp_timer);
}

static bool is_hold_time_zero(void *data)
{
	struct bsm_rpinfo *bsrp;

	bsrp = data;

	if (bsrp->rp_holdtime)
		return false;
	else
		return true;
}

static void pim_instate_pend_list(struct bsgrp_node *bsgrp_node)
{
	struct bsm_rpinfo *active;
	struct bsm_rpinfo *pend;
	struct rp_info *rp_info;
	struct route_node *rn;
	struct pim_instance *pim;
	struct rp_info *rp_all;
	struct prefix group_all;
	bool had_rp_node = true;

	pim = bsgrp_node->scope->pim;
	active = bsm_rpinfos_first(bsgrp_node->bsrp_list);

	/* Remove nodes with hold time 0 & check if list still has a head */
	frr_each_safe (bsm_rpinfos, bsgrp_node->partial_bsrp_list, pend) {
		if (is_hold_time_zero(pend)) {
			bsm_rpinfos_del(bsgrp_node->partial_bsrp_list, pend);
			pim_bsm_rpinfo_free(pend);
		}
	}

	pend = bsm_rpinfos_first(bsgrp_node->partial_bsrp_list);

	if (!pim_get_all_mcast_group(&group_all))
		return;

	rp_all = pim_rp_find_match_group(pim, &group_all);
	rn = route_node_lookup(pim->rp_table, &bsgrp_node->group);

	if (pend)
		pim_g2rp_timer_start(pend, pend->rp_holdtime);

	/* if rp node doesn't exist or exist but not configured(rp_all),
	 * install the rp from head(if exists) of partial list. List is
	 * is sorted such that head is the elected RP for the group.
	 */
	if (!rn || (prefix_same(&rp_all->group, &bsgrp_node->group) &&
		    pim_rpf_addr_is_inaddr_any(&rp_all->rp))) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: Route node doesn't exist", __func__);
		if (pend)
			pim_rp_new(pim, pend->rp_address, bsgrp_node->group,
				   NULL, RP_SRC_BSR);
		had_rp_node = false;
	} else {
		rp_info = (struct rp_info *)rn->info;
		if (!rp_info) {
			route_unlock_node(rn);
			if (pend)
				pim_rp_new(pim, pend->rp_address,
					   bsgrp_node->group, NULL, RP_SRC_BSR);
			had_rp_node = false;
		}
	}

	/* We didn't have rp node and pending list is empty(unlikely), cleanup*/
	if ((!had_rp_node) && (!pend)) {
		pim_free_bsgrp_node(bsgrp_node->scope->bsrp_table,
				    &bsgrp_node->group);
		pim_free_bsgrp_data(bsgrp_node);
		return;
	}

	if ((had_rp_node) && (rp_info->rp_src != RP_SRC_STATIC)) {
		/* This means we searched and got rp node, needs unlock */
		route_unlock_node(rn);

		if (active && pend) {
			if (pim_addr_cmp(active->rp_address, pend->rp_address))
				pim_rp_change(pim, pend->rp_address,
					      bsgrp_node->group, RP_SRC_BSR);
		}

		/* Possible when the first BSM has group with 0 rp count */
		if ((!active) && (!pend)) {
			if (PIM_DEBUG_BSM) {
				zlog_debug(
					"%s: Both bsrp and partial list are empty",
					__func__);
			}
			pim_free_bsgrp_node(bsgrp_node->scope->bsrp_table,
					    &bsgrp_node->group);
			pim_free_bsgrp_data(bsgrp_node);
			return;
		}

		/* Possible when a group with 0 rp count received in BSM */
		if ((active) && (!pend)) {
			pim_rp_del(pim, active->rp_address, bsgrp_node->group,
				   NULL, RP_SRC_BSR);
			pim_free_bsgrp_node(bsgrp_node->scope->bsrp_table,
					    &bsgrp_node->group);
			if (PIM_DEBUG_BSM) {
				zlog_debug("%s:Pend List is null,del grp node",
					   __func__);
			}
			pim_free_bsgrp_data(bsgrp_node);
			return;
		}
	}

	if ((had_rp_node) && (rp_info->rp_src == RP_SRC_STATIC)) {
		/* We need to unlock rn this case */
		route_unlock_node(rn);
		/* there is a chance that static rp exist and bsrp cleaned
		 * so clean bsgrp node if pending list empty
		 */
		if (!pend) {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s: Partial list is empty, static rp exists",
					__func__);
			pim_free_bsgrp_node(bsgrp_node->scope->bsrp_table,
					    &bsgrp_node->group);
			pim_free_bsgrp_data(bsgrp_node);
			return;
		}
	}

	/* swap the list & delete all nodes in partial list (old bsrp_list)
	 * before swap
	 *    active is head of bsrp list
	 *    pend is head of partial list
	 * After swap
	 *    active is head of partial list
	 *    pend is head of bsrp list
	 * So check appriate head after swap and clean the new partial list
	 */
	bsm_rpinfos_swap_all(bsgrp_node->bsrp_list,
			     bsgrp_node->partial_bsrp_list);

	if (active)
		pim_g2rp_timer_stop(active);
	pim_bsm_rpinfos_free(bsgrp_node->partial_bsrp_list);
}

static bool is_preferred_bsr(struct pim_instance *pim, pim_addr bsr,
			     uint32_t bsr_prio)
{
	if (!pim_addr_cmp(bsr, pim->global_scope.current_bsr))
		return true;

	if (bsr_prio > pim->global_scope.current_bsr_prio)
		return true;

	else if (bsr_prio == pim->global_scope.current_bsr_prio) {
		if (pim_addr_cmp(bsr, pim->global_scope.current_bsr) >= 0)
			return true;
		else
			return false;
	} else
		return false;
}

static void pim_bsm_update(struct pim_instance *pim, pim_addr bsr,
			   uint32_t bsr_prio)
{
	if (pim_addr_cmp(bsr, pim->global_scope.current_bsr)) {
		pim_nht_bsr_del(pim, pim->global_scope.current_bsr);
		pim_nht_bsr_add(pim, bsr);

		pim->global_scope.current_bsr = bsr;
		pim->global_scope.current_bsr_first_ts =
			pim_time_monotonic_sec();
		pim->global_scope.state = ACCEPT_PREFERRED;
	}
	pim->global_scope.current_bsr_prio = bsr_prio;
	pim->global_scope.current_bsr_last_ts = pim_time_monotonic_sec();
}

void pim_bsm_clear(struct pim_instance *pim)
{
	struct route_node *rn;
	struct route_node *rpnode;
	struct bsgrp_node *bsgrp;
	pim_addr nht_p;
	struct prefix g_all;
	struct rp_info *rp_all;
	struct pim_upstream *up;
	struct rp_info *rp_info;
	bool upstream_updated = false;

	pim_nht_bsr_del(pim, pim->global_scope.current_bsr);

	/* Reset scope zone data */
	pim->global_scope.accept_nofwd_bsm = false;
	pim->global_scope.state = ACCEPT_ANY;
	pim->global_scope.current_bsr = PIMADDR_ANY;
	pim->global_scope.current_bsr_prio = 0;
	pim->global_scope.current_bsr_first_ts = 0;
	pim->global_scope.current_bsr_last_ts = 0;
	pim->global_scope.bsm_frag_tag = 0;
	pim_bsm_frags_free(&pim->global_scope);

	pim_bs_timer_stop(&pim->global_scope);

	for (rn = route_top(pim->global_scope.bsrp_table); rn;
	     rn = route_next(rn)) {
		bsgrp = rn->info;
		if (!bsgrp)
			continue;

		rpnode = route_node_lookup(pim->rp_table, &bsgrp->group);

		if (!rpnode) {
			pim_free_bsgrp_node(bsgrp->scope->bsrp_table,
					    &bsgrp->group);
			pim_free_bsgrp_data(bsgrp);
			continue;
		}

		rp_info = (struct rp_info *)rpnode->info;

		if ((!rp_info) || (rp_info->rp_src != RP_SRC_BSR)) {
			pim_free_bsgrp_node(bsgrp->scope->bsrp_table,
					    &bsgrp->group);
			pim_free_bsgrp_data(bsgrp);
			continue;
		}

		/* Deregister addr with Zebra NHT */
		nht_p = rp_info->rp.rpf_addr;

		if (PIM_DEBUG_PIM_NHT_RP) {
			zlog_debug("%s: Deregister RP addr %pPA with Zebra ",
				   __func__, &nht_p);
		}

		pim_delete_tracked_nexthop(pim, nht_p, NULL, rp_info);

		if (!pim_get_all_mcast_group(&g_all))
			return;

		rp_all = pim_rp_find_match_group(pim, &g_all);

		if (rp_all == rp_info) {
			rp_all->rp.rpf_addr = PIMADDR_ANY;
			rp_all->i_am_rp = 0;
		} else {
			/* Delete the rp_info from rp-list */
			listnode_delete(pim->rp_list, rp_info);

			/* Delete the rp node from rp_table */
			rpnode->info = NULL;
			route_unlock_node(rpnode);
			route_unlock_node(rpnode);
			XFREE(MTYPE_PIM_RP, rp_info);
		}

		pim_free_bsgrp_node(bsgrp->scope->bsrp_table, &bsgrp->group);
		pim_free_bsgrp_data(bsgrp);
	}
	pim_rp_refresh_group_to_rp_mapping(pim);


	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		/* Find the upstream (*, G) whose upstream address is same as
		 * the RP
		 */
		if (!pim_addr_is_any(up->sg.src))
			continue;

		struct prefix grp;
		struct rp_info *trp_info;

		pim_addr_to_prefix(&grp, up->sg.grp);
		trp_info = pim_rp_find_match_group(pim, &grp);

		/* RP not found for the group grp */
		if (pim_rpf_addr_is_inaddr_any(&trp_info->rp)) {
			pim_upstream_rpf_clear(pim, up);
			pim_rp_set_upstream_addr(pim, &up->upstream_addr,
						 up->sg.src, up->sg.grp);
		} else {
			/* RP found for the group grp */
			pim_upstream_update(pim, up);
			upstream_updated = true;
		}
	}

	if (upstream_updated)
		pim_zebra_update_all_interfaces(pim);
}

static bool pim_bsm_send_intf(uint8_t *buf, int len, struct interface *ifp,
			      pim_addr dst_addr)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;

	if (!pim_ifp) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: Pim interface not available for %s",
				   __func__, ifp->name);
		return false;
	}

	if (pim_ifp->pim_sock_fd == -1) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: Pim sock not available for %s",
				   __func__, ifp->name);
		return false;
	}

	if (pim_msg_send(pim_ifp->pim_sock_fd, pim_ifp->primary_address,
			 dst_addr, buf, len, ifp)) {
		zlog_warn("%s: Could not send BSM message on interface: %s",
			  __func__, ifp->name);
		return false;
	}

	if (!pim_ifp->pim_passive_enable)
		pim_ifp->pim_ifstat_bsm_tx++;

	pim_ifp->pim->bsm_sent++;
	return true;
}

static bool pim_bsm_frag_send(uint8_t *buf, uint32_t len, struct interface *ifp,
			      uint32_t pim_mtu, pim_addr dst_addr, bool no_fwd)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct bsmmsg_grpinfo *grpinfo, *curgrp;
	uint8_t *firstgrp_ptr;
	uint8_t *pkt;
	uint8_t *pak_start;
	uint32_t parsed_len = 0;
	uint32_t this_pkt_rem;
	uint32_t copy_byte_count;
	uint32_t this_pkt_len;
	uint8_t total_rp_cnt;
	uint8_t this_rp_cnt;
	uint8_t frag_rp_cnt;
	uint8_t rp_fit_cnt;
	bool pak_pending = false;

	/* MTU  passed here is PIM MTU (IP MTU less IP Hdr) */
	if (pim_mtu < (PIM_MIN_BSM_LEN)) {
		zlog_warn(
			"%s: mtu(pim mtu: %d) size less than minimum bootstrap len",
			__func__, pim_mtu);
		if (PIM_DEBUG_BSM)
			zlog_debug(
				"%s: mtu (pim mtu:%d) less than minimum bootstrap len",
				__func__, pim_mtu);
		return false;
	}

	pak_start = XCALLOC(MTYPE_PIM_BSM_PKT_VAR_MEM, pim_mtu);

	pkt = pak_start;

	/* Fill PIM header later before sending packet to calc checksum */
	pkt += PIM_MSG_HEADER_LEN;
	buf += PIM_MSG_HEADER_LEN;

	/* copy bsm header to new packet at offset of pim hdr */
	memcpy(pkt, buf, PIM_BSM_HDR_LEN);
	pkt += PIM_BSM_HDR_LEN;
	buf += PIM_BSM_HDR_LEN;
	parsed_len += (PIM_MSG_HEADER_LEN + PIM_BSM_HDR_LEN);

	/* Store the position of first grp ptr, which can be reused for
	 * next packet to start filling group. old bsm header and pim hdr
	 * remains. So need not be filled again for next packet onwards.
	 */
	firstgrp_ptr = pkt;

	/* we received mtu excluding IP hdr len as param
	 * now this_pkt_rem is mtu excluding
	 * PIM_BSM_HDR_LEN + PIM_MSG_HEADER_LEN
	 */
	this_pkt_rem = pim_mtu - (PIM_BSM_HDR_LEN + PIM_MSG_HEADER_LEN);

	/* For each group till the packet length parsed */
	while (parsed_len < len) {
		/* pkt            ---> fragment's current pointer
		 * buf            ---> input buffer's current pointer
		 * mtu            ---> size of the pim packet - PIM header
		 * curgrp         ---> current group on the fragment
		 * grpinfo        ---> current group on the input buffer
		 * this_pkt_rem   ---> bytes remaing on the current fragment
		 * rp_fit_cnt     ---> num of rp for current grp that
		 *                     fits this frag
		 * total_rp_cnt   ---> total rp present for the group in the buf
		 * frag_rp_cnt    ---> no of rp for the group to be fit in
		 *                     the frag
		 * this_rp_cnt    ---> how many rp have we parsed
		 */
		grpinfo = (struct bsmmsg_grpinfo *)buf;
		memcpy(pkt, buf, PIM_BSM_GRP_LEN);
		curgrp = (struct bsmmsg_grpinfo *)pkt;
		parsed_len += PIM_BSM_GRP_LEN;
		pkt += PIM_BSM_GRP_LEN;
		buf += PIM_BSM_GRP_LEN;
		this_pkt_rem -= PIM_BSM_GRP_LEN;

		/* initialize rp count and total_rp_cnt before the rp loop */
		this_rp_cnt = 0;
		total_rp_cnt = grpinfo->frag_rp_count;

		/* Loop till all RPs for the group parsed */
		while (this_rp_cnt < total_rp_cnt) {
			/* All RP from a group processed here.
			 * group is pointed by grpinfo.
			 * At this point make sure buf pointing to a RP
			 * within a group
			 */
			rp_fit_cnt = this_pkt_rem / PIM_BSM_RP_LEN;

			/* calculate how many rp am i going to copy in
			 * this frag
			 */
			if (rp_fit_cnt > (total_rp_cnt - this_rp_cnt))
				frag_rp_cnt = total_rp_cnt - this_rp_cnt;
			else
				frag_rp_cnt = rp_fit_cnt;

			/* populate the frag rp count for the current grp */
			curgrp->frag_rp_count = frag_rp_cnt;
			copy_byte_count = frag_rp_cnt * PIM_BSM_RP_LEN;

			/* copy all the rp that we are fitting in this
			 * frag for the grp
			 */
			memcpy(pkt, buf, copy_byte_count);
			this_rp_cnt += frag_rp_cnt;
			buf += copy_byte_count;
			pkt += copy_byte_count;
			parsed_len += copy_byte_count;
			this_pkt_rem -= copy_byte_count;

			/* Either we couldn't fit all rp for the group or the
			 * mtu reached
			 */
			if ((this_rp_cnt < total_rp_cnt)
			    || (this_pkt_rem
				< (PIM_BSM_GRP_LEN + PIM_BSM_RP_LEN))) {
				/* No space to fit in more rp, send this pkt */
				this_pkt_len = pim_mtu - this_pkt_rem;
				pim_msg_build_header(
					pim_ifp->primary_address, dst_addr,
					pak_start, this_pkt_len,
					PIM_MSG_TYPE_BOOTSTRAP, no_fwd);
				pim_bsm_send_intf(pak_start, this_pkt_len, ifp,
						  dst_addr);

				/* Construct next fragment. Reuse old packet */
				pkt = firstgrp_ptr;
				this_pkt_rem = pim_mtu - (PIM_BSM_HDR_LEN
							  + PIM_MSG_HEADER_LEN);

				/* If pkt can't accommodate next group + at
				 * least one rp, we must break out of this inner
				 * loop and process next RP
				 */
				if (total_rp_cnt == this_rp_cnt)
					break;

				/* If some more RPs for the same group pending,
				 * fill grp hdr
				 */
				memcpy(pkt, (uint8_t *)grpinfo,
				       PIM_BSM_GRP_LEN);
				curgrp = (struct bsmmsg_grpinfo *)pkt;
				pkt += PIM_BSM_GRP_LEN;
				this_pkt_rem -= PIM_BSM_GRP_LEN;
				pak_pending = false;
			} else {
				/* We filled something but not yet sent out */
				pak_pending = true;
			}
		} /* while RP count */
	}	 /*while parsed len */

	/* Send if we have any unsent packet */
	if (pak_pending) {
		this_pkt_len = pim_mtu - this_pkt_rem;
		pim_msg_build_header(pim_ifp->primary_address, dst_addr,
				     pak_start, this_pkt_len,
				     PIM_MSG_TYPE_BOOTSTRAP, no_fwd);
		pim_bsm_send_intf(pak_start, (pim_mtu - this_pkt_rem), ifp,
				  dst_addr);
	}
	XFREE(MTYPE_PIM_BSM_PKT_VAR_MEM, pak_start);
	return true;
}

static void pim_bsm_fwd_whole_sz(struct pim_instance *pim, uint8_t *buf,
				 uint32_t len, int sz)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	pim_addr dst_addr;
	uint32_t pim_mtu;
	bool no_fwd = false;
	bool ret = false;

	/* For now only global scope zone is supported, so send on all
	 * pim interfaces in the vrf
	 */
	dst_addr = qpim_all_pim_routers_addr;
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if ((!pim_ifp) || (!pim_ifp->bsm_enable))
			continue;

		/*
		 * RFC 5059 Sec 3.4:
		 * When a Bootstrap message is forwarded, it is forwarded out
		 * of every multicast-capable interface that has PIM neighbors.
		 *
		 * So skipping pim interfaces with no neighbors.
		 */
		if (listcount(pim_ifp->pim_neighbor_list) == 0)
			continue;

		pim_hello_require(ifp);
		pim_mtu = ifp->mtu - MAX_IP_HDR_LEN;
		if (pim_mtu < len) {
			ret = pim_bsm_frag_send(buf, len, ifp, pim_mtu,
						dst_addr, no_fwd);
			if (PIM_DEBUG_BSM)
				zlog_debug("%s: pim_bsm_frag_send returned %s",
					   __func__, ret ? "TRUE" : "FALSE");
		} else {
			pim_msg_build_header(pim_ifp->primary_address, dst_addr,
					     buf, len, PIM_MSG_TYPE_BOOTSTRAP,
					     no_fwd);
			if (!pim_bsm_send_intf(buf, len, ifp, dst_addr)) {
				if (PIM_DEBUG_BSM)
					zlog_debug(
						"%s: pim_bsm_send_intf returned false",
						__func__);
			}
		}
	}
}

bool pim_bsm_new_nbr_fwd(struct pim_neighbor *neigh, struct interface *ifp)
{
	pim_addr dst_addr;
	struct pim_interface *pim_ifp;
	struct bsm_scope *scope;
	struct bsm_frag *bsfrag;
	uint32_t pim_mtu;
	bool no_fwd = true;
	bool ret = false;

	if (PIM_DEBUG_BSM)
		zlog_debug("%s: New neighbor %pPA seen on %s", __func__,
			   &neigh->source_addr, ifp->name);

	pim_ifp = ifp->info;

	/* DR only forwards BSM packet */
	if (!pim_addr_cmp(pim_ifp->pim_dr_addr, pim_ifp->primary_address)) {
		if (PIM_DEBUG_BSM)
			zlog_debug(
				"%s: It is not DR, so don't forward BSM packet",
				__func__);
	}

	if (!pim_ifp->bsm_enable) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: BSM proc not enabled on %s", __func__,
				   ifp->name);
		return ret;
	}

	scope = &pim_ifp->pim->global_scope;

	if (!bsm_frags_count(scope->bsm_frags)) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: BSM list for the scope is empty",
				   __func__);
		return ret;
	}

	if (!pim_ifp->ucast_bsm_accept) {
		dst_addr = qpim_all_pim_routers_addr;
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: Sending BSM mcast to %pPA", __func__,
				   &neigh->source_addr);
	} else {
		dst_addr = neigh->source_addr;
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: Sending BSM ucast to %pPA", __func__,
				   &neigh->source_addr);
	}
	pim_mtu = ifp->mtu - MAX_IP_HDR_LEN;
	pim_hello_require(ifp);

	frr_each (bsm_frags, scope->bsm_frags, bsfrag) {
		if (pim_mtu < bsfrag->size) {
			ret = pim_bsm_frag_send(bsfrag->data, bsfrag->size, ifp,
						pim_mtu, dst_addr, no_fwd);
			if (!ret) {
				if (PIM_DEBUG_BSM)
					zlog_debug(
						"%s: pim_bsm_frag_send failed",
						__func__);
			}
		} else {
			/* Pim header needs to be constructed */
			pim_msg_build_header(pim_ifp->primary_address, dst_addr,
					     bsfrag->data, bsfrag->size,
					     PIM_MSG_TYPE_BOOTSTRAP, no_fwd);
			ret = pim_bsm_send_intf(bsfrag->data, bsfrag->size, ifp,
						dst_addr);
			if (!ret) {
				if (PIM_DEBUG_BSM)
					zlog_debug(
						"%s: pim_bsm_frag_send failed",
						__func__);
			}
		}
	}
	return ret;
}

struct bsgrp_node *pim_bsm_get_bsgrp_node(struct bsm_scope *scope,
					  struct prefix *grp)
{
	struct route_node *rn;
	struct bsgrp_node *bsgrp;

	rn = route_node_lookup(scope->bsrp_table, grp);
	if (!rn) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: Route node doesn't exist for the group",
				   __func__);
		return NULL;
	}
	bsgrp = rn->info;
	route_unlock_node(rn);

	return bsgrp;
}

static uint32_t hash_calc_on_grp_rp(struct prefix group, pim_addr rp,
				    uint8_t hashmasklen)
{
	uint64_t temp;
	uint32_t hash;
	uint32_t grpaddr;
	uint32_t rp_add;
	uint32_t mask = 0xffffffff;

	/* mask to be made zero if hashmasklen is 0 because mask << 32
	 * may not give 0. hashmasklen can be 0 to 32.
	 */
	if (hashmasklen == 0)
		mask = 0;

	/* in_addr stores ip in big endian, hence network byte order
	 * convert to uint32 before processing hash
	 */
#if PIM_IPV == 4
	grpaddr = ntohl(group.u.prefix4.s_addr);
#else
	grpaddr = group.u.prefix6.s6_addr32[0] ^ group.u.prefix6.s6_addr32[1] ^
		  group.u.prefix6.s6_addr32[2] ^ group.u.prefix6.s6_addr32[3];
#endif
	/* Avoid shifting by 32 bit on a 32 bit register */
	if (hashmasklen)
		grpaddr = grpaddr & ((mask << (32 - hashmasklen)));
	else
		grpaddr = grpaddr & mask;

#if PIM_IPV == 4
	rp_add = ntohl(rp.s_addr);
#else
	rp_add = rp.s6_addr32[0] ^ rp.s6_addr32[1] ^ rp.s6_addr32[2] ^
		 rp.s6_addr32[3];
#endif
	temp = 1103515245 * ((1103515245 * (uint64_t)grpaddr + 12345) ^ rp_add)
	       + 12345;
	hash = temp & (0x7fffffff);
	return hash;
}

static bool pim_install_bsm_grp_rp(struct pim_instance *pim,
				   struct bsgrp_node *grpnode,
				   struct bsmmsg_rpinfo *rp)
{
	struct bsm_rpinfo *bsm_rpinfo;
	uint8_t hashMask_len = pim->global_scope.hashMasklen;

	/*memory allocation for bsm_rpinfo */
	bsm_rpinfo = XCALLOC(MTYPE_PIM_BSRP_INFO, sizeof(*bsm_rpinfo));

	bsm_rpinfo->rp_prio = rp->rp_pri;
	bsm_rpinfo->rp_holdtime = rp->rp_holdtime;
	bsm_rpinfo->rp_address = rp->rpaddr.addr;
	bsm_rpinfo->elapse_time = 0;

	/* Back pointer to the group node. */
	bsm_rpinfo->bsgrp_node = grpnode;

	/* update hash for this rp node */
	bsm_rpinfo->hash = hash_calc_on_grp_rp(grpnode->group, rp->rpaddr.addr,
					       hashMask_len);
	if (bsm_rpinfos_add(grpnode->partial_bsrp_list, bsm_rpinfo) == NULL) {
		if (PIM_DEBUG_BSM)
			zlog_debug(
				"%s, bs_rpinfo node added to the partial bs_rplist.",
				__func__);
		return true;
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("%s: list node not added", __func__);

	XFREE(MTYPE_PIM_BSRP_INFO, bsm_rpinfo);
	return false;
}

static void pim_update_pending_rp_cnt(struct bsm_scope *sz,
				      struct bsgrp_node *bsgrp,
				      uint16_t bsm_frag_tag,
				      uint32_t total_rp_count)
{
	if (bsgrp->pend_rp_cnt) {
		/* received bsm is different packet ,
		 * it is not same fragment.
		 */
		if (bsm_frag_tag != bsgrp->frag_tag) {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s,Received a new BSM ,so clear the pending bs_rpinfo list.",
					__func__);
			pim_bsm_rpinfos_free(bsgrp->partial_bsrp_list);
			bsgrp->pend_rp_cnt = total_rp_count;
		}
	} else
		bsgrp->pend_rp_cnt = total_rp_count;

	bsgrp->frag_tag = bsm_frag_tag;
}

/* Parsing BSR packet and adding to partial list of corresponding bsgrp node */
static bool pim_bsm_parse_install_g2rp(struct bsm_scope *scope, uint8_t *buf,
				       int buflen, uint16_t bsm_frag_tag)
{
	struct bsmmsg_grpinfo grpinfo;
	struct bsmmsg_rpinfo rpinfo;
	struct prefix group;
	struct bsgrp_node *bsgrp = NULL;
	int frag_rp_cnt = 0;
	int offset = 0;
	int ins_count = 0;
	pim_addr grp_addr;

	while (buflen > offset) {
		if (offset + (int)sizeof(struct bsmmsg_grpinfo) > buflen) {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s: buflen received %d is less than the internal data structure of the packet would suggest",
					__func__, buflen);
			return false;
		}
		/* Extract Group tlv from BSM */
		memcpy(&grpinfo, buf, sizeof(struct bsmmsg_grpinfo));
		grp_addr = grpinfo.group.addr;

		if (PIM_DEBUG_BSM)
			zlog_debug(
				"%s, Group %pPAs  Rpcount:%d Fragment-Rp-count:%d",
				__func__, &grp_addr, grpinfo.rp_count,
				grpinfo.frag_rp_count);

		buf += sizeof(struct bsmmsg_grpinfo);
		offset += sizeof(struct bsmmsg_grpinfo);

		group.family = PIM_AF;
		if (grpinfo.group.mask > PIM_MAX_BITLEN) {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s, prefix length specified: %d is too long",
					__func__, grpinfo.group.mask);
			return false;
		}

		pim_addr_to_prefix(&group, grp_addr);
		group.prefixlen = grpinfo.group.mask;

		/* Get the Group node for the BSM rp table */
		bsgrp = pim_bsm_get_bsgrp_node(scope, &group);

		if (grpinfo.rp_count == 0) {
			struct bsm_rpinfo *old_rpinfo;

			/* BSR explicitly no longer has RPs for this group */
			if (!bsgrp)
				continue;

			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s, Rp count is zero for group: %pPAs",
					__func__, &grp_addr);

			old_rpinfo = bsm_rpinfos_first(bsgrp->bsrp_list);
			if (old_rpinfo)
				pim_rp_del(scope->pim, old_rpinfo->rp_address,
					   group, NULL, RP_SRC_BSR);

			pim_free_bsgrp_node(scope->bsrp_table, &bsgrp->group);
			pim_free_bsgrp_data(bsgrp);
			continue;
		}

		if (!bsgrp) {
			if (PIM_DEBUG_BSM)
				zlog_debug("%s, Create new  BSM Group node.",
					   __func__);

			/* create a new node to be added to the tree. */
			bsgrp = pim_bsm_new_bsgrp_node(scope->bsrp_table,
						       &group);

			if (!bsgrp) {
				zlog_debug(
					"%s, Failed to get the BSM group node.",
					__func__);
				continue;
			}

			bsgrp->scope = scope;
		}

		pim_update_pending_rp_cnt(scope, bsgrp, bsm_frag_tag,
					  grpinfo.rp_count);
		frag_rp_cnt = grpinfo.frag_rp_count;
		ins_count = 0;

		while (frag_rp_cnt--) {
			if (offset + (int)sizeof(struct bsmmsg_rpinfo)
			    > buflen) {
				if (PIM_DEBUG_BSM)
					zlog_debug(
						"%s, buflen received: %u is less than the internal data structure of the packet would suggest",
						__func__, buflen);
				return false;
			}

			/* Extract RP address tlv from BSM */
			memcpy(&rpinfo, buf, sizeof(struct bsmmsg_rpinfo));
			rpinfo.rp_holdtime = ntohs(rpinfo.rp_holdtime);
			buf += sizeof(struct bsmmsg_rpinfo);
			offset += sizeof(struct bsmmsg_rpinfo);

			if (PIM_DEBUG_BSM) {
				pim_addr rp_addr;

				rp_addr = rpinfo.rpaddr.addr;
				zlog_debug(
					"%s, Rp address - %pPAs; pri:%d hold:%d",
					__func__, &rp_addr, rpinfo.rp_pri,
					rpinfo.rp_holdtime);
			}

			/* Call Install api to update grp-rp mappings */
			if (pim_install_bsm_grp_rp(scope->pim, bsgrp, &rpinfo))
				ins_count++;
		}

		bsgrp->pend_rp_cnt -= ins_count;

		if (!bsgrp->pend_rp_cnt) {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s, Recvd all the rps for this group, so bsrp list with penidng rp list.",
					__func__);
			/* replace the bsrp_list with pending list */
			pim_instate_pend_list(bsgrp);
		}
	}
	return true;
}

int pim_bsm_process(struct interface *ifp, pim_sgaddr *sg, uint8_t *buf,
		    uint32_t buf_size, bool no_fwd)
{
	struct bsm_hdr *bshdr;
	int sz = PIM_GBL_SZ_ID;
	struct bsmmsg_grpinfo *msg_grp;
	struct pim_interface *pim_ifp = NULL;
	struct bsm_frag *bsfrag;
	struct pim_instance *pim;
	uint16_t frag_tag;
	pim_addr bsr_addr;
	bool empty_bsm = false;

	/* BSM Packet acceptance validation */
	pim_ifp = ifp->info;
	if (!pim_ifp) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s: multicast not enabled on interface %s",
				   __func__, ifp->name);
		return -1;
	}

	if (pim_ifp->pim_passive_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"skip receiving PIM message on passive interface %s",
				ifp->name);
		return 0;
	}

	pim_ifp->pim_ifstat_bsm_rx++;
	pim = pim_ifp->pim;
	pim->bsm_rcvd++;

	/* Drop if bsm processing is disabled on interface */
	if (!pim_ifp->bsm_enable) {
		zlog_warn("%s: BSM not enabled on interface %s", __func__,
			  ifp->name);
		pim_ifp->pim_ifstat_bsm_cfg_miss++;
		pim->bsm_dropped++;
		return -1;
	}

	if (buf_size < (PIM_MSG_HEADER_LEN + sizeof(struct bsm_hdr))) {
		if (PIM_DEBUG_BSM)
			zlog_debug(
				"%s: received buffer length of %d which is too small to properly decode",
				__func__, buf_size);
		return -1;
	}

	bshdr = (struct bsm_hdr *)(buf + PIM_MSG_HEADER_LEN);
	if (bshdr->hm_len > PIM_MAX_BITLEN) {
		zlog_warn(
			"Bad hashmask length for %s; got %hhu, expected value in range 0-32",
			PIM_AF_NAME, bshdr->hm_len);
		pim->bsm_dropped++;
		return -1;
	}
	pim->global_scope.hashMasklen = bshdr->hm_len;
	frag_tag = ntohs(bshdr->frag_tag);
	/* NB: bshdr->bsr_addr.addr is packed/unaligned => memcpy */
	memcpy(&bsr_addr, &bshdr->bsr_addr.addr, sizeof(bsr_addr));

	/* Identify empty BSM */
	if ((buf_size - PIM_BSM_HDR_LEN - PIM_MSG_HEADER_LEN) < PIM_BSM_GRP_LEN)
		empty_bsm = true;

	if (!empty_bsm) {
		msg_grp = (struct bsmmsg_grpinfo *)(buf + PIM_MSG_HEADER_LEN
						    + PIM_BSM_HDR_LEN);
		/* Currently we don't support scope zoned BSM */
		if (msg_grp->group.sz) {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s : Administratively scoped range BSM received",
					__func__);
			pim_ifp->pim_ifstat_bsm_invalid_sz++;
			pim->bsm_dropped++;
			return -1;
		}
	}

	/* Drop if bsr is not preferred bsr */
	if (!is_preferred_bsr(pim, bsr_addr, bshdr->bsr_prio)) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Received a non-preferred BSM",
				   __func__);
		pim->bsm_dropped++;
		return -1;
	}

	if (no_fwd) {
		/* only accept no-forward BSM if quick refresh on startup */
		if ((pim->global_scope.accept_nofwd_bsm)
		    || (frag_tag == pim->global_scope.bsm_frag_tag)) {
			pim->global_scope.accept_nofwd_bsm = false;
		} else {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s : nofwd_bsm received on %pPAs when accpt_nofwd_bsm false",
					__func__, &bsr_addr);
			pim->bsm_dropped++;
			pim_ifp->pim_ifstat_ucast_bsm_cfg_miss++;
			return -1;
		}
	}

	/* BSM packet is seen, so resetting accept_nofwd_bsm to false */
	if (pim->global_scope.accept_nofwd_bsm)
		pim->global_scope.accept_nofwd_bsm = false;

	if (!pim_addr_cmp(sg->grp, qpim_all_pim_routers_addr)) {
		/* Multicast BSMs are only accepted if source interface & IP
		 * match RPF towards the BSR's IP address, or they have
		 * no-forward set
		 */
		if (!no_fwd &&
		    !pim_nht_bsr_rpf_check(pim, bsr_addr, ifp, sg->src)) {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"BSM check: RPF to BSR %pPAs is not %pPA%%%s",
					&bsr_addr, &sg->src, ifp->name);
			pim->bsm_dropped++;
			return -1;
		}
	} else if (if_address_is_local(&sg->grp, PIM_AF, pim->vrf->vrf_id)) {
		/* Unicast BSM received - if ucast bsm not enabled on
		 * the interface, drop it
		 */
		if (!pim_ifp->ucast_bsm_accept) {
			if (PIM_DEBUG_BSM)
				zlog_debug(
					"%s : Unicast BSM not enabled on interface %s",
					__func__, ifp->name);
			pim_ifp->pim_ifstat_ucast_bsm_cfg_miss++;
			pim->bsm_dropped++;
			return -1;
		}

	} else {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Invalid destination address",
				   __func__);
		pim->bsm_dropped++;
		return -1;
	}

	if (empty_bsm) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Empty Pref BSM received", __func__);
	}
	/* Parse Update bsm rp table and install/uninstall rp if required */
	if (!pim_bsm_parse_install_g2rp(
		    &pim_ifp->pim->global_scope,
		    (buf + PIM_BSM_HDR_LEN + PIM_MSG_HEADER_LEN),
		    (buf_size - PIM_BSM_HDR_LEN - PIM_MSG_HEADER_LEN),
		    frag_tag)) {
		if (PIM_DEBUG_BSM) {
			zlog_debug("%s, Parsing BSM failed.", __func__);
		}
		pim->bsm_dropped++;
		return -1;
	}
	/* Restart the bootstrap timer */
	pim_bs_timer_restart(&pim_ifp->pim->global_scope,
			     PIM_BSR_DEFAULT_TIMEOUT);

	/* If new BSM received, clear the old bsm database */
	if (pim_ifp->pim->global_scope.bsm_frag_tag != frag_tag) {
		if (PIM_DEBUG_BSM) {
			zlog_debug("%s: Current frag tag: %d Frag teg rcvd: %d",
				   __func__,
				   pim_ifp->pim->global_scope.bsm_frag_tag,
				   frag_tag);
		}
		pim_bsm_frags_free(&pim_ifp->pim->global_scope);
		pim_ifp->pim->global_scope.bsm_frag_tag = frag_tag;
	}

	/* update the scope information from bsm */
	pim_bsm_update(pim, bsr_addr, bshdr->bsr_prio);

	if (!no_fwd) {
		pim_bsm_fwd_whole_sz(pim_ifp->pim, buf, buf_size, sz);
		bsfrag = XCALLOC(MTYPE_PIM_BSM_FRAG,
				 sizeof(struct bsm_frag) + buf_size);

		bsfrag->size = buf_size;
		memcpy(bsfrag->data, buf, buf_size);
		bsm_frags_add_tail(pim_ifp->pim->global_scope.bsm_frags,
				   bsfrag);
	}

	return 0;
}
