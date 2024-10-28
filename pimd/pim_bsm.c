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

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <lib/network.h>
#include <lib/iana_afi.h>
#include <lib/sockunion.h>
#include <lib/sockopt.h>

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
#include "pim_sock.h"

/* Functions forward declaration */
static void pim_bs_timer_start(struct bsm_scope *scope, int bs_timeout);
static void pim_g2rp_timer_start(struct bsm_rpinfo *bsrp, int hold_time);
static inline void pim_g2rp_timer_restart(struct bsm_rpinfo *bsrp,
					  int hold_time);
static void pim_bsm_accept_any(struct bsm_scope *scope);
static void pim_cand_bsr_trigger(struct bsm_scope *scope, bool verbose);
static void pim_cand_bsr_pending(struct bsm_scope *scope);

/* Memory Types */
DEFINE_MTYPE_STATIC(PIMD, PIM_BSGRP_NODE, "PIM BSR advertised grp info");
DEFINE_MTYPE_STATIC(PIMD, PIM_BSRP_INFO, "PIM BSR advertised RP info");
DEFINE_MTYPE(PIMD, PIM_BSM_FRAG, "PIM BSM fragment");
DEFINE_MTYPE_STATIC(PIMD, PIM_BSM_PKT_VAR_MEM, "PIM BSM Packet");
DEFINE_MTYPE_STATIC(PIMD, PIM_CAND_RP_GRP, "PIM Candidate RP group");

static int cand_rp_group_cmp(const struct cand_rp_group *a,
			     const struct cand_rp_group *b)
{
	return prefix_cmp(&a->p, &b->p);
}

DECLARE_RBTREE_UNIQ(cand_rp_groups, struct cand_rp_group, item,
		    cand_rp_group_cmp);

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

void pim_bsm_frags_free(struct bsm_scope *scope)
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

/* BS timer for NO_INFO, ACCEPT_ANY & ACCEPT_PREFERRED.
 * Candidate BSR handling is separate further below
 */
static void pim_on_bs_timer(struct event *t)
{
	struct bsm_scope *scope;

	scope = EVENT_ARG(t);
	EVENT_OFF(scope->bs_timer);

	if (PIM_DEBUG_BSM)
		zlog_debug("%s: Bootstrap Timer expired for scope: %d",
			   __func__, scope->sz_id);

	assertf(scope->state <= ACCEPT_PREFERRED, "state=%d", scope->state);
	pim_nht_bsr_del(scope->pim, scope->current_bsr);

	pim_bsm_accept_any(scope);
}

static void pim_bsm_accept_any(struct bsm_scope *scope)
{
	struct route_node *rn;
	struct bsgrp_node *bsgrp_node;
	struct bsm_rpinfo *bsrp;

	EVENT_OFF(scope->t_ebsr_regen_bsm);

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

	/* we're leaving ACCEPT_PREFERRED, which doubles as C-BSR if we're
	 * configured to be a Candidate BSR.  See if we're P-BSR now.
	 */
	pim_cand_bsr_trigger(scope, false);
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

static void bsm_unicast_sock_read(struct event *t)
{
	struct bsm_scope *scope = EVENT_ARG(t);

	pim_sock_read_helper(scope->unicast_sock, scope->pim, false);

	event_add_read(router->master, bsm_unicast_sock_read, scope,
		       scope->unicast_sock, &scope->unicast_read);
}

void pim_bsm_proc_init(struct pim_instance *pim)
{
	struct bsm_scope *scope = &pim->global_scope;

	memset(scope, 0, sizeof(*scope));

	scope->sz_id = PIM_GBL_SZ_ID;
	scope->bsrp_table = route_table_init();
	scope->accept_nofwd_bsm = true;
	scope->state = NO_INFO;
	scope->pim = pim;
	bsm_frags_init(scope->bsm_frags);
	pim_bs_timer_start(scope, PIM_BS_TIME);

	scope->cand_rp_interval = PIM_CRP_ADV_INTERVAL;
	cand_rp_groups_init(scope->cand_rp_groups);

	scope->unicast_sock = pim_socket_raw(IPPROTO_PIM);
	set_nonblocking(scope->unicast_sock);
	sockopt_reuseaddr(scope->unicast_sock);

	if (setsockopt_ifindex(PIM_AF, scope->unicast_sock, 1) == -1)
		zlog_warn("%s: Without IP_PKTINFO, src interface can't be determined",
			  __func__);

	pim_socket_ip_hdr(scope->unicast_sock);

	frr_with_privs (&pimd_privs) {
		vrf_bind(pim->vrf->vrf_id, scope->unicast_sock, NULL);
	}

	event_add_read(router->master, bsm_unicast_sock_read, scope,
		       scope->unicast_sock, &scope->unicast_read);
}

void pim_bsm_proc_free(struct pim_instance *pim)
{
	struct bsm_scope *scope = &pim->global_scope;
	struct route_node *rn;
	struct bsgrp_node *bsgrp;
	struct cand_rp_group *crpgrp;

	EVENT_OFF(scope->unicast_read);
	close(scope->unicast_sock);

	pim_bs_timer_stop(scope);
	pim_bsm_frags_free(scope);

	for (rn = route_top(scope->bsrp_table); rn; rn = route_next(rn)) {
		bsgrp = rn->info;
		if (!bsgrp)
			continue;
		pim_free_bsgrp_data(bsgrp);
	}

	while ((crpgrp = cand_rp_groups_pop(scope->cand_rp_groups)))
		XFREE(MTYPE_PIM_CAND_RP_GRP, crpgrp);

	cand_rp_groups_fini(scope->cand_rp_groups);

	route_table_finish(scope->bsrp_table);
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
	if (bsr_prio > pim->global_scope.current_bsr_prio)
		return true;

	else if (bsr_prio == pim->global_scope.current_bsr_prio) {
		if (pim_addr_cmp(bsr, pim->global_scope.current_bsr) >= 0)
			return true;
		else
			return false;
	} else if (!pim_addr_cmp(bsr, pim->global_scope.current_bsr)) {
		/* BSR config changed, lower prio now.  local BSR check
		 * is handled separately in pim_bsm_update()
		 */
		return true;
	} else
		return false;
}

static void pim_bsm_update(struct pim_instance *pim, pim_addr bsr,
			   uint32_t bsr_prio)
{
	pim->global_scope.current_bsr_prio = bsr_prio;
	pim->global_scope.current_bsr_last_ts = pim_time_monotonic_sec();

	if (pim->global_scope.bsr_addrsel.run &&
	    pim->global_scope.cand_bsr_prio > bsr_prio &&
	    pim->global_scope.state < BSR_PENDING) {
		/* current BSR is now less preferred than ourselves */
		pim_cand_bsr_pending(&pim->global_scope);
		return;
	}

	if (!pim_addr_cmp(bsr, pim->global_scope.current_bsr))
		return;

	switch (pim->global_scope.state) {
	case BSR_PENDING:
		if (PIM_DEBUG_BSM)
			zlog_debug("Candidate BSR dropping out of BSR election, better BSR (%u, %pPA)",
				   bsr_prio, &bsr);
		break;

	case BSR_ELECTED:
		if (PIM_DEBUG_BSM)
			zlog_debug("Lost BSR status, better BSR (%u, %pPA)",
				   bsr_prio, &bsr);
		break;

	case NO_INFO:
	case ACCEPT_ANY:
	case ACCEPT_PREFERRED:
		break;
	}

	EVENT_OFF(pim->global_scope.t_ebsr_regen_bsm);

	if (pim->global_scope.state == BSR_ELECTED)
		pim_crp_db_clear(&pim->global_scope);
	else
		pim_nht_bsr_del(pim, pim->global_scope.current_bsr);
	pim_nht_bsr_add(pim, bsr);

	pim->global_scope.current_bsr = bsr;
	pim->global_scope.current_bsr_first_ts = pim_time_monotonic_sec();
	pim->global_scope.state = ACCEPT_PREFERRED;

	pim_cand_rp_trigger(&pim->global_scope);
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

	EVENT_OFF(pim->global_scope.t_ebsr_regen_bsm);

	if (pim->global_scope.state == BSR_ELECTED)
		pim_crp_db_clear(&pim->global_scope);
	else
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
bool pim_bsm_parse_install_g2rp(struct bsm_scope *scope, uint8_t *buf,
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

	/* when the BSR restarts, it can get its own BSR advertisement thrown
	 * back at it, and without this we'll go into ACCEPT_PREFERRED with
	 * ourselves as the BSR when we should be in BSR_ELECTED.
	 */
	if (if_address_is_local(&bshdr->bsr_addr.addr, PIM_AF,
				pim->vrf->vrf_id)) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Dropping BSM from ourselves", __func__);
		pim->bsm_dropped++;
		return -1;
	}

	/* Drop if bsr is not preferred bsr */
	if (!is_preferred_bsr(pim, bsr_addr, bshdr->bsr_prio)) {
		if (pim->global_scope.state == BSR_PENDING && !no_fwd) {
			/* in P-BSR state, non-preferred BSMs are forwarded, but
			 * content is ignored.
			 */
			if (PIM_DEBUG_BSM)
				zlog_debug("%s : Forwarding non-preferred BSM during Pending-BSR state",
					   __func__);

			pim_bsm_fwd_whole_sz(pim_ifp->pim, buf, buf_size, sz);
			return -1;
		}
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Received a non-preferred BSM",
				   __func__);
		pim->bsm_dropped++;
		return -1;
	}

	if (no_fwd) {
		/* only accept no-forward BSM if quick refresh on startup */
		if ((pim->global_scope.accept_nofwd_bsm) ||
		    (frag_tag == pim->global_scope.bsm_frag_tag)) {
			pim->global_scope.accept_nofwd_bsm = false;
		} else {
			if (PIM_DEBUG_BSM)
				zlog_debug("%s : nofwd_bsm received on %pPAs when accpt_nofwd_bsm false",
					   __func__, &bsr_addr);
			pim->bsm_dropped++;
			pim_ifp->pim_ifstat_ucast_bsm_cfg_miss++;
			return -1;
		}
	}

	/* BSM packet is seen, so resetting accept_nofwd_bsm to false */
	if (pim->global_scope.accept_nofwd_bsm)
		pim->global_scope.accept_nofwd_bsm = false;

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
		zlog_warn("BSM from %pPA failed to parse",
			  (pim_addr *)&bshdr->bsr_addr.addr);
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

static void pim_elec_bsr_timer(struct event *t)
{
	struct bsm_scope *scope = EVENT_ARG(t);
	struct bsm_frag *frag;
	struct bsm_hdr *hdr;

	assert(scope->state == BSR_ELECTED);

	scope->bsm_frag_tag++;
	frag = bsm_frags_first(scope->bsm_frags);
	assert(frag);

	hdr = (struct bsm_hdr *)(frag->data + PIM_MSG_HEADER_LEN);
	hdr->frag_tag = htons(scope->bsm_frag_tag);

	unsigned int timer = PIM_BS_TIME;

	if (scope->changed_bsm_trigger) {
		if (PIM_DEBUG_BSM)
			zlog_debug("Sending triggered BSM");
		scope->changed_bsm_trigger--;
		timer = 5;
	} else {
		if (PIM_DEBUG_BSM)
			zlog_debug("Sending scheduled BSM");
		pim_bsm_sent(scope);
	}

	pim_bsm_fwd_whole_sz(scope->pim, frag->data, frag->size, scope->sz_id);
	scope->current_bsr_last_ts = pim_time_monotonic_sec();

	event_add_timer(router->master, pim_elec_bsr_timer, scope, timer,
			&scope->bs_timer);
}

void pim_bsm_changed(struct bsm_scope *scope)
{
	struct event t;

	EVENT_OFF(scope->bs_timer);
	scope->changed_bsm_trigger = 2;

	t.arg = scope;
	pim_elec_bsr_timer(&t);
}

static void pim_cand_bsr_pending_expire(struct event *t)
{
	struct bsm_scope *scope = EVENT_ARG(t);

	assertf(scope->state == BSR_PENDING, "state=%d", scope->state);

	if (!pim_addr_is_any(scope->current_bsr)) {
		assertf(scope->cand_bsr_prio >= scope->current_bsr_prio,
			"cand_bsr %pPA prio %u is less than current_bsr %pPA prio %u",
			&scope->bsr_addrsel.run_addr, scope->current_bsr_prio, &scope->current_bsr,
			scope->cand_bsr_prio);

		if (scope->cand_bsr_prio == scope->current_bsr_prio)
			assertf(pim_addr_cmp(scope->bsr_addrsel.run_addr, scope->current_bsr) > 0,
				"cand_bsr %pPA  < current_bsr %pPA", &scope->bsr_addrsel.run_addr,
				&scope->current_bsr);
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("Elected BSR, wait expired without preferable BSMs");

	scope->state = BSR_ELECTED;
	scope->current_bsr_prio = scope->cand_bsr_prio;
	scope->current_bsr = scope->bsr_addrsel.run_addr;

	scope->bsm_frag_tag = frr_weak_random();
	scope->current_bsr_first_ts = pim_time_monotonic_sec();

	pim_cand_rp_trigger(scope);
	pim_bsm_generate(scope);
}

#if PIM_IPV == 6
static float bsr_addr_delay(pim_addr best, pim_addr local)
{
	unsigned int pos;
	uint32_t best_4b, local_4b;
	float delay_log;

	for (pos = 0; pos < 12; pos++) {
		if (best.s6_addr[pos] != local.s6_addr[pos])
			break;
	}

	memcpy(&best_4b, &best.s6_addr[pos], 4);
	memcpy(&local_4b, &local.s6_addr[pos], 4);

	delay_log = log2(1 + ntohl(best_4b) - ntohl(local_4b));
	delay_log += (12 - pos) * 8;
	return delay_log / 64.;
}
#endif

static void pim_cand_bsr_pending(struct bsm_scope *scope)
{
	unsigned int bs_rand_override;
	uint8_t best_prio;
	pim_addr best_addr;
	float prio_delay, addr_delay;

	EVENT_OFF(scope->bs_timer);
	EVENT_OFF(scope->t_ebsr_regen_bsm);
	scope->state = BSR_PENDING;

	best_prio = MAX(scope->cand_bsr_prio, scope->current_bsr_prio);
	best_addr = pim_addr_cmp(scope->bsr_addrsel.run_addr,
				 scope->current_bsr) > 0
			    ? scope->bsr_addrsel.run_addr
			    : scope->current_bsr;

	/* RFC5059 sec.5 */
#if PIM_IPV == 4
	if (scope->cand_bsr_prio == best_prio) {
		prio_delay = 0.; /* log2(1) = 0 */
		addr_delay = log2(1 + ntohl(best_addr.s_addr) -
				  ntohl(scope->bsr_addrsel.run_addr.s_addr)) /
			     16.;
	} else {
		prio_delay = 2. * log2(1 + best_prio - scope->cand_bsr_prio);
		addr_delay = 2 - (ntohl(scope->bsr_addrsel.run_addr.s_addr) /
				  (float)(1 << 31));
	}
#else
	if (scope->cand_bsr_prio == best_prio) {
		prio_delay = 0.; /* log2(1) = 0 */
		addr_delay = bsr_addr_delay(best_addr,
					    scope->bsr_addrsel.run_addr);
	} else {
		prio_delay = 2. * log2(1 + best_prio - scope->cand_bsr_prio);
		addr_delay = 2 -
			     (ntohl(scope->bsr_addrsel.run_addr.s6_addr32[0]) /
			      (float)(1 << 31));
	}
#endif

	bs_rand_override = 5000 + (int)((prio_delay + addr_delay) * 1000.);

	if (PIM_DEBUG_BSM)
		zlog_debug("Pending-BSR (%u, %pPA), waiting %ums",
			   scope->cand_bsr_prio, &scope->bsr_addrsel.run_addr,
			   bs_rand_override);

	event_add_timer_msec(router->master, pim_cand_bsr_pending_expire, scope,
			     bs_rand_override, &scope->bs_timer);
}

static inline pim_addr if_highest_addr(pim_addr cur, struct interface *ifp)
{
	struct connected *connected;

	frr_each (if_connected, ifp->connected, connected) {
		pim_addr conn_addr;

		if (connected->address->family != PIM_AF)
			continue;

		conn_addr = pim_addr_from_prefix(connected->address);
		/* highest address */
		if (pim_addr_cmp(conn_addr, cur) > 0)
			cur = conn_addr;
	}
	return cur;
}

static void cand_addrsel_clear(struct cand_addrsel *asel)
{
	asel->run = false;
	asel->run_addr = PIMADDR_ANY;
}

/* returns whether address or active changed */
static bool cand_addrsel_update(struct cand_addrsel *asel, struct vrf *vrf)
{
	bool is_any = false, prev_run = asel->run;
	struct interface *ifp = NULL;
	pim_addr new_addr = PIMADDR_ANY;

	if (!asel->cfg_enable)
		goto out_disable;

	switch (asel->cfg_mode) {
	case CAND_ADDR_EXPLICIT:
		new_addr = asel->cfg_addr;
		ifp = if_lookup_address_local(&asel->cfg_addr, PIM_AF,
					      vrf->vrf_id);
		break;

	case CAND_ADDR_IFACE:
		ifp = if_lookup_by_name_vrf(asel->cfg_ifname, vrf);

		if (ifp)
			new_addr = if_highest_addr(PIMADDR_ANY, ifp);
		break;

	case CAND_ADDR_ANY:
		is_any = true;
		/* fallthru */
	case CAND_ADDR_LO:
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (!if_is_up(ifp))
				continue;
			if (is_any || if_is_loopback(ifp) || if_is_vrf(ifp))
				new_addr = if_highest_addr(new_addr, ifp);
		}
		break;
	}

	if (ifp && !if_is_up(ifp))
		goto out_disable;

	if (pim_addr_is_any(new_addr))
		goto out_disable;

	/* nothing changed re. address (don't care about interface changes) */
	if (asel->run && !pim_addr_cmp(asel->run_addr, new_addr))
		return !prev_run;

	asel->run = true;
	asel->run_addr = new_addr;
	return true;

out_disable:
	asel->run = false;
	asel->run_addr = PIMADDR_ANY;

	return prev_run;
}

static void pim_cand_bsr_stop(struct bsm_scope *scope, bool verbose)
{
	cand_addrsel_clear(&scope->bsr_addrsel);

	switch (scope->state) {
	case NO_INFO:
	case ACCEPT_ANY:
	case ACCEPT_PREFERRED:
		return;
	case BSR_PENDING:
	case BSR_ELECTED:
		break;
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("Candidate BSR ceasing operation");

	EVENT_OFF(scope->t_ebsr_regen_bsm);
	EVENT_OFF(scope->bs_timer);
	pim_crp_db_clear(scope);
	pim_bsm_accept_any(scope);
}

static void pim_cand_bsr_trigger(struct bsm_scope *scope, bool verbose)
{
	/* this is called on all state changes even if we aren't configured
	 * to be C-BSR at all.
	 */
	if (!scope->bsr_addrsel.run)
		return;

	if (scope->current_bsr_prio > scope->cand_bsr_prio) {
		assert(scope->state == ACCEPT_PREFERRED);
		if (!verbose)
			return;

		if (PIM_DEBUG_BSM)
			zlog_debug("Candidate BSR: known better BSR %pPA (higher priority %u > %u)",
				   &scope->current_bsr, scope->current_bsr_prio,
				   scope->cand_bsr_prio);
		return;
	} else if (scope->current_bsr_prio == scope->cand_bsr_prio &&
		   pim_addr_cmp(scope->current_bsr,
				scope->bsr_addrsel.run_addr) > 0) {
		assert(scope->state == ACCEPT_PREFERRED);
		if (!verbose)
			return;

		if (PIM_DEBUG_BSM)
			zlog_debug("Candidate BSR: known better BSR %pPA (higher address > %pPA)",
				   &scope->current_bsr,
				   &scope->bsr_addrsel.run_addr);
		return;
	}

	if (!pim_addr_cmp(scope->current_bsr, scope->bsr_addrsel.run_addr))
		return;

	pim_cand_bsr_pending(scope);
}

void pim_cand_bsr_apply(struct bsm_scope *scope)
{
	if (!cand_addrsel_update(&scope->bsr_addrsel, scope->pim->vrf))
		return;

	if (!scope->bsr_addrsel.run) {
		pim_cand_bsr_stop(scope, true);
		return;
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("Candidate BSR: %pPA, priority %u",
			   &scope->bsr_addrsel.run_addr, scope->cand_bsr_prio);

	pim_cand_bsr_trigger(scope, true);
}

static void pim_cand_rp_adv_stop_maybe(struct bsm_scope *scope)
{
	/* actual check whether stop should be sent - covers address
	 * changes as well as run_addr = 0.0.0.0 (C-RP shutdown)
	 */
	if (pim_addr_is_any(scope->cand_rp_prev_addr) ||
	    !pim_addr_cmp(scope->cand_rp_prev_addr,
			  scope->cand_rp_addrsel.run_addr))
		return;

	switch (scope->state) {
	case ACCEPT_PREFERRED:
	case BSR_ELECTED:
		break;

	case NO_INFO:
	case ACCEPT_ANY:
	case BSR_PENDING:
	default:
		return;
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("Candidate-RP (-, %pPA) deregistering self to %pPA",
			   &scope->cand_rp_prev_addr, &scope->current_bsr);

	struct cand_rp_msg *msg;
	uint8_t buf[PIM_MSG_HEADER_LEN + sizeof(*msg) + sizeof(pim_encoded_group)];

	msg = (struct cand_rp_msg *)(&buf[PIM_MSG_HEADER_LEN]);
	msg->prefix_cnt = 0;
	msg->rp_prio = 255;
	msg->rp_holdtime = 0;
	msg->rp_addr.family = PIM_IANA_AFI;
	msg->rp_addr.reserved = 0;
	msg->rp_addr.addr = scope->cand_rp_prev_addr;

	pim_msg_build_header(PIMADDR_ANY, scope->current_bsr, buf, sizeof(buf),
			     PIM_MSG_TYPE_CANDIDATE, false);

	if (pim_msg_send(scope->unicast_sock, PIMADDR_ANY, scope->current_bsr,
			 buf, sizeof(buf), NULL)) {
		zlog_warn("failed to send Cand-RP message: %m");
	}

	scope->cand_rp_prev_addr = PIMADDR_ANY;
}

static void pim_cand_rp_adv(struct event *t)
{
	struct bsm_scope *scope = EVENT_ARG(t);
	int next_msec;

	pim_cand_rp_adv_stop_maybe(scope);

	if (!scope->cand_rp_addrsel.run) {
		scope->cand_rp_adv_trigger = 0;
		return;
	}

	switch (scope->state) {
	case ACCEPT_PREFERRED:
	case BSR_ELECTED:
		break;

	case ACCEPT_ANY:
	case BSR_PENDING:
	case NO_INFO:
	default:
		/* state change will retrigger */
		scope->cand_rp_adv_trigger = 0;

		zlog_warn("Candidate-RP advertisement not sent in state %d",
			  scope->state);
		return;
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("Candidate-RP (%u, %pPA) advertising %zu groups to %pPA",
			   scope->cand_rp_prio, &scope->cand_rp_addrsel.run_addr,
			   cand_rp_groups_count(scope->cand_rp_groups),
			   &scope->current_bsr);

	struct cand_rp_group *grp;
	struct cand_rp_msg *msg;
	uint8_t buf[PIM_MSG_HEADER_LEN + sizeof(*msg) +
		    sizeof(pim_encoded_group) *
			    cand_rp_groups_count(scope->cand_rp_groups)];
	size_t i = 0;


	msg = (struct cand_rp_msg *)(&buf[PIM_MSG_HEADER_LEN]);
	msg->prefix_cnt = cand_rp_groups_count(scope->cand_rp_groups);
	msg->rp_prio = scope->cand_rp_prio;
	msg->rp_holdtime =
		htons(MAX(151, (scope->cand_rp_interval * 5 + 1) / 2));
	msg->rp_addr.family = PIM_IANA_AFI;
	msg->rp_addr.reserved = 0;
	msg->rp_addr.addr = scope->cand_rp_addrsel.run_addr;

	frr_each (cand_rp_groups, scope->cand_rp_groups, grp) {
		memset(&msg->groups[i], 0, sizeof(msg->groups[i]));

		msg->groups[i].family = PIM_IANA_AFI;
		msg->groups[i].mask = grp->p.prefixlen;
		msg->groups[i].addr = grp->p.prefix;
		i++;
	}

	scope->cand_rp_prev_addr = scope->cand_rp_addrsel.run_addr;

	pim_msg_build_header(scope->cand_rp_addrsel.run_addr, scope->current_bsr,
			     buf, sizeof(buf), PIM_MSG_TYPE_CANDIDATE, false);

	if (pim_msg_send(scope->unicast_sock, scope->cand_rp_addrsel.run_addr,
			 scope->current_bsr, buf, sizeof(buf), NULL)) {
		zlog_warn("failed to send Cand-RP message: %m");
	}

	/* -1s...+1s */
	next_msec = (frr_weak_random() & 2047) - 1024;

	if (scope->cand_rp_adv_trigger) {
		scope->cand_rp_adv_trigger--;
		next_msec += 2000;
	} else
		next_msec += scope->cand_rp_interval * 1000;

	event_add_timer_msec(router->master, pim_cand_rp_adv, scope, next_msec,
			     &scope->cand_rp_adv_timer);
}

void pim_cand_rp_trigger(struct bsm_scope *scope)
{
	if (scope->cand_rp_adv_trigger && scope->cand_rp_addrsel.run) {
		scope->cand_rp_adv_trigger = PIM_CRP_ADV_TRIGCOUNT;

		/* already scheduled to send triggered advertisements, don't
		 * reschedule so burst changes don't result in an advertisement
		 * burst
		 */
		return;
	}

	EVENT_OFF(scope->cand_rp_adv_timer);

	if (!scope->cand_rp_addrsel.run)
		return;

	scope->cand_rp_adv_trigger = PIM_CRP_ADV_TRIGCOUNT;

	struct event t;

	t.arg = scope;
	pim_cand_rp_adv(&t);
}

void pim_cand_rp_apply(struct bsm_scope *scope)
{
	if (!cand_addrsel_update(&scope->cand_rp_addrsel, scope->pim->vrf))
		return;

	if (!scope->cand_rp_addrsel.run) {
		if (PIM_DEBUG_BSM)
			zlog_debug("Candidate RP ceasing operation");

		cand_addrsel_clear(&scope->cand_rp_addrsel);
		EVENT_OFF(scope->cand_rp_adv_timer);
		pim_cand_rp_adv_stop_maybe(scope);
		scope->cand_rp_adv_trigger = 0;
		return;
	}

	if (PIM_DEBUG_BSM)
		zlog_debug("Candidate RP: %pPA, priority %u",
			   &scope->cand_rp_addrsel.run_addr,
			   scope->cand_rp_prio);

	pim_cand_rp_trigger(scope);
}

void pim_cand_rp_grp_add(struct bsm_scope *scope, const prefix_pim *p)
{
	struct cand_rp_group *grp, ref;

	ref.p = *p;
	grp = cand_rp_groups_find(scope->cand_rp_groups, &ref);
	if (grp)
		return;

	grp = XCALLOC(MTYPE_PIM_CAND_RP_GRP, sizeof(*grp));
	grp->p = *p;
	cand_rp_groups_add(scope->cand_rp_groups, grp);

	pim_cand_rp_trigger(scope);
}

void pim_cand_rp_grp_del(struct bsm_scope *scope, const prefix_pim *p)
{
	struct cand_rp_group *grp, ref;

	ref.p = *p;
	grp = cand_rp_groups_find(scope->cand_rp_groups, &ref);
	if (!grp)
		return;

	cand_rp_groups_del(scope->cand_rp_groups, grp);
	XFREE(MTYPE_PIM_CAND_RP_GRP, grp);

	pim_cand_rp_trigger(scope);
}

static struct event *t_cand_addrs_reapply;

static void pim_cand_addrs_reapply(struct event *t)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		struct pim_instance *pi = vrf->info;

		if (!pi)
			continue;

		/* these call cand_addrsel_update() and apply changes */
		pim_cand_bsr_apply(&pi->global_scope);
		pim_cand_rp_apply(&pi->global_scope);
	}
}

void pim_cand_addrs_changed(void)
{
	EVENT_OFF(t_cand_addrs_reapply);
	event_add_timer_msec(router->master, pim_cand_addrs_reapply, NULL, 1,
			     &t_cand_addrs_reapply);
}

static void cand_addrsel_config_write(struct vty *vty,
				      struct cand_addrsel *addrsel)
{
	switch (addrsel->cfg_mode) {
	case CAND_ADDR_LO:
		break;
	case CAND_ADDR_ANY:
		vty_out(vty, " source any");
		break;
	case CAND_ADDR_IFACE:
		vty_out(vty, " source interface %s", addrsel->cfg_ifname);
		break;
	case CAND_ADDR_EXPLICIT:
		vty_out(vty, " source address %pPA", &addrsel->cfg_addr);
		break;
	}
}

int pim_cand_config_write(struct pim_instance *pim, struct vty *vty)
{
	struct bsm_scope *scope = &pim->global_scope;
	int ret = 0;

	if (scope->cand_rp_addrsel.cfg_enable) {
		vty_out(vty, " bsr candidate-rp");
		if (scope->cand_rp_prio != 192)
			vty_out(vty, " priority %u", scope->cand_rp_prio);
		if (scope->cand_rp_interval != PIM_CRP_ADV_INTERVAL)
			vty_out(vty, " interval %u", scope->cand_rp_interval);
		cand_addrsel_config_write(vty, &scope->cand_rp_addrsel);
		vty_out(vty, "\n");
		ret++;

		struct cand_rp_group *group;

		frr_each (cand_rp_groups, scope->cand_rp_groups, group) {
			vty_out(vty, " bsr candidate-rp group %pFX\n",
				&group->p);
			ret++;
		}
	}

	if (scope->bsr_addrsel.cfg_enable) {
		vty_out(vty, " bsr candidate-bsr");
		if (scope->cand_bsr_prio != 64)
			vty_out(vty, " priority %u", scope->cand_bsr_prio);
		cand_addrsel_config_write(vty, &scope->bsr_addrsel);
		vty_out(vty, "\n");
		ret++;
	}
	return ret;
}
