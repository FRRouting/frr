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
static int pim_on_bs_timer(struct thread *t);
static void pim_bs_timer_stop(struct bsm_scope *scope);

/* pim_bsm_write_config - Write the interface pim bsm configuration.*/
void
pim_bsm_write_config(struct vty *vty, struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (pim_ifp) {
		if (!pim_ifp->bsm_enable)
			vty_out(vty, " no ip pim bsm\n");
		if (!pim_ifp->ucast_bsm_accept)
			vty_out(vty, " no ip pim unicast-bsm\n");
	}
}

static void pim_free_bsgrp_data(struct bsgrp_node * bsgrp_node)
{
	if (bsgrp_node->bsrp_list)
		list_delete(&bsgrp_node->bsrp_list);
	if (bsgrp_node->partial_bsrp_list)
		list_delete(&bsgrp_node->partial_bsrp_list);

	XFREE(MTYPE_PIM_BSGRP_NODE, bsgrp_node);
}

static void pim_bsm_node_free(struct bsm_info *bsm)
{
	if (bsm->bsm)
		XFREE(MTYPE_PIM_BSM_PKT_VAR_MEM, bsm->bsm);
	XFREE(MTYPE_PIM_BSM_INFO, bsm);
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

	for(rn = route_top(pim->global_scope.bsrp_table);
			rn; rn = route_next(rn)) {
		bsgrp = rn->info;
		if (!bsgrp)
			continue;
		pim_free_bsgrp_data(bsgrp);
	}

	if (pim->global_scope.bsrp_table)
		route_table_finish(pim->global_scope.bsrp_table);
}

static int pim_on_bs_timer(struct thread *t)
{
	return 0;
}

static void pim_bs_timer_stop(struct bsm_scope *scope)
{
	if (PIM_DEBUG_BSM)
		zlog_debug("%s : BS timer being stopped of sz: %d",
			__PRETTY_FUNCTION__,
			scope->sz_id);
	THREAD_OFF(scope->bs_timer);
}

static void pim_bs_timer_start(struct bsm_scope *scope, int bs_timeout)
{
	if (!scope) {
		if (PIM_DEBUG_BSM)
			zlog_debug("%s : Invalid scope(NULL).",
					__PRETTY_FUNCTION__);
	}

	THREAD_OFF(scope->bs_timer);

	if (PIM_DEBUG_BSM)
		zlog_debug("%s : starting bs timer for scope %d with timeout %d secs",
				__PRETTY_FUNCTION__, scope->sz_id, bs_timeout);
	thread_add_timer(router->master, pim_on_bs_timer, scope, bs_timeout,
			&scope->bs_timer);
}

