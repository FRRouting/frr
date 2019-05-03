/*
 * pim_bsm.c: PIM BSM handling routines
 *
 * Copyright (C) 2018-19 Vmware, Inc.
 * Saravanan K
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#include "if.h"
#include "pimd.h"
#include "pim_iface.h"
#include "pim_instance.h"
#include "pim_rpf.h"
#include "pim_hello.h"
#include "pim_pim.h"
#include "pim_nht.h"
#include "pim_bsm.h"
#include "pim_time.h"

/* Functions forward declaration */
static void pim_bs_timer_start(struct bsm_scope *scope, int bs_timeout);
static void pim_g2rp_timer_start(struct bsm_rpinfo *bsrp, int hold_time);
static inline void pim_g2rp_timer_restart(struct bsm_rpinfo *bsrp,
					  int hold_time);

/* Memory Types */
DEFINE_MTYPE_STATIC(PIMD, PIM_BSGRP_NODE, "PIM BSR advertised grp info")
DEFINE_MTYPE_STATIC(PIMD, PIM_BSRP_NODE, "PIM BSR advertised RP info")
DEFINE_MTYPE_STATIC(PIMD, PIM_BSM_INFO, "PIM BSM Info")
DEFINE_MTYPE_STATIC(PIMD, PIM_BSM_PKT_VAR_MEM, "PIM BSM Packet")

/* pim_bsm_write_config - Write the interface pim bsm configuration.*/
void pim_bsm_write_config(struct vty *vty, struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (pim_ifp) {
		if (!pim_ifp->bsm_enable)
			vty_out(vty, " no ip pim bsm\n");
		if (!pim_ifp->ucast_bsm_accept)
			vty_out(vty, " no ip pim unicast-bsm\n");
	}
}

static void pim_free_bsgrp_data(struct bsgrp_node *bsgrp_node)
{
	if (bsgrp_node->bsrp_list)
		list_delete(&bsgrp_node->bsrp_list);
	if (bsgrp_node->partial_bsrp_list)
		list_delete(&bsgrp_node->partial_bsrp_list);
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

static void pim_bsm_node_free(struct bsm_info *bsm)
{
	if (bsm->bsm)
		XFREE(MTYPE_PIM_BSM_PKT_VAR_MEM, bsm->bsm);
	XFREE(MTYPE_PIM_BSM_INFO, bsm);
}

static int pim_on_bs_timer(struct thread *t)
{
	return 0;
}

static void pim_bs_timer_stop(struct bsm_scope *scope)
{
	if (PIM_DEBUG_BSM)
		zlog_debug("%s : BS timer being stopped of sz: %d",
			   __PRETTY_FUNCTION__, scope->sz_id);
	THREAD_OFF(scope->bs_timer);
}

static void pim_bs_timer_start(struct bsm_scope *scope, int bs_timeout)
{
	if (!scope) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Invalid scope(NULL).",
				   __PRETTY_FUNCTION__);
		return;
	}
	THREAD_OFF(scope->bs_timer);
	if (PIM_DEBUG_BSM)
		zlog_debug("%s : starting bs timer for scope %d with timeout %d secs",
			   __PRETTY_FUNCTION__, scope->sz_id, bs_timeout);
	thread_add_timer(router->master, pim_on_bs_timer, scope, bs_timeout,
			 &scope->bs_timer);
}

void pim_bsm_proc_init(struct pim_instance *pim)
{
	memset(&pim->global_scope, 0, sizeof(struct bsm_scope));

	pim->global_scope.sz_id = PIM_GBL_SZ_ID;
	pim->global_scope.bsrp_table = route_table_init();
	pim->global_scope.accept_nofwd_bsm = true;
	pim->global_scope.state = NO_INFO;
	pim->global_scope.pim = pim;
	pim->global_scope.bsm_list = list_new();
	pim->global_scope.bsm_list->del = (void (*)(void *))pim_bsm_node_free;
	pim_bs_timer_start(&pim->global_scope, PIM_BS_TIME);
}

void pim_bsm_proc_free(struct pim_instance *pim)
{
	struct route_node *rn;
	struct bsgrp_node *bsgrp;

	pim_bs_timer_stop(&pim->global_scope);

	if (pim->global_scope.bsm_list)
		list_delete(&pim->global_scope.bsm_list);

	for (rn = route_top(pim->global_scope.bsrp_table); rn;
	     rn = route_next(rn)) {
		bsgrp = rn->info;
		if (!bsgrp)
			continue;
		pim_free_bsgrp_data(bsgrp);
	}

	if (pim->global_scope.bsrp_table)
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

static int pim_on_g2rp_timer(struct thread *t)
{
	struct bsm_rpinfo *bsrp;
	struct bsm_rpinfo *bsrp_node;
	struct bsgrp_node *bsgrp_node;
	struct listnode *bsrp_ln;
	struct pim_instance *pim;
	struct rp_info *rp_info;
	struct route_node *rn;
	uint16_t elapse;
	struct in_addr bsrp_addr;

	bsrp = THREAD_ARG(t);
	THREAD_OFF(bsrp->g2rp_timer);
	bsgrp_node = bsrp->bsgrp_node;

	/* elapse time is the hold time of expired node */
	elapse = bsrp->rp_holdtime;
	bsrp_addr = bsrp->rp_address;

	/* update elapse for all bsrp nodes */
	for (ALL_LIST_ELEMENTS_RO(bsgrp_node->bsrp_list, bsrp_ln, bsrp_node))
		bsrp_node->elapse_time += elapse;

	/* remove the expired nodes from the list */
	list_filter_out_nodes(bsgrp_node->bsrp_list, is_hold_time_elapsed);

	/* Get the next elected rp node */
	bsrp = listnode_head(bsgrp_node->bsrp_list);
	pim = bsgrp_node->scope->pim;
	rn = route_node_lookup(pim->rp_table, &bsgrp_node->group);

	if (!rn) {
		zlog_warn("%s: Route node doesn't exist", __PRETTY_FUNCTION__);
		return 0;
	}

	rp_info = (struct rp_info *)rn->info;

	if (!rp_info) {
		route_unlock_node(rn);
		return 0;
	}

	if (rp_info->rp_src != RP_SRC_STATIC) {
		/* If new rp available, change it else delete the existing */
		if (bsrp) {
			bsrp_addr = bsrp->rp_address;
			pim_g2rp_timer_start(
				bsrp, (bsrp->rp_holdtime - bsrp->elapse_time));
			pim_rp_change(pim, bsrp_addr, bsgrp_node->group,
				      RP_SRC_BSR);
		} else {
			pim_rp_del(pim, bsrp_addr, bsgrp_node->group, NULL,
				   RP_SRC_BSR);
		}
	}

	if ((!bsgrp_node->bsrp_list->count)
	    && (!bsgrp_node->partial_bsrp_list->count)) {
		pim_free_bsgrp_node(pim->global_scope.bsrp_table,
				    &bsgrp_node->group);
		pim_free_bsgrp_data(bsgrp_node);
	}

	return 0;
}

static void pim_g2rp_timer_start(struct bsm_rpinfo *bsrp, int hold_time)
{
	if (!bsrp) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Invalid brsp(NULL).",
				   __PRETTY_FUNCTION__);
		return;
	}
	THREAD_OFF(bsrp->g2rp_timer);
	if (PIM_DEBUG_BSM) {
		char buf[48];

		zlog_debug(
			"%s : starting g2rp timer for grp: %s - rp: %s with timeout  %d secs(Actual Hold time : %d secs)",
			__PRETTY_FUNCTION__,
			prefix2str(&bsrp->bsgrp_node->group, buf, 48),
			inet_ntoa(bsrp->rp_address), hold_time,
			bsrp->rp_holdtime);
	}

	thread_add_timer(router->master, pim_on_g2rp_timer, bsrp, hold_time,
			 &bsrp->g2rp_timer);
}

static inline void pim_g2rp_timer_restart(struct bsm_rpinfo *bsrp,
					  int hold_time)
{
	pim_g2rp_timer_start(bsrp, hold_time);
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
				   __PRETTY_FUNCTION__);
		return NULL;
	}
	bsgrp = rn->info;
	route_unlock_node(rn);

	return bsgrp;
}
