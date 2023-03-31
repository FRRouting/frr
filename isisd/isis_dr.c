// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_dr.c
 *                             IS-IS designated router related routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */


#include <zebra.h>

#include "log.h"
#include "hash.h"
#include "frrevent.h"
#include "linklist.h"
#include "vty.h"
#include "stream.h"
#include "if.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_dr.h"
#include "isisd/isis_events.h"

const char *isis_disflag2string(int disflag)
{

	switch (disflag) {
	case ISIS_IS_NOT_DIS:
		return "is not DIS";
	case ISIS_IS_DIS:
		return "is DIS";
	case ISIS_WAS_DIS:
		return "was DIS";
	default:
		return "unknown DIS state";
	}
	return NULL; /* not reached */
}

void isis_run_dr(struct event *thread)
{
	struct isis_circuit_arg *arg = EVENT_ARG(thread);

	assert(arg);

	struct isis_circuit *circuit = arg->circuit;
	int level = arg->level;

	assert(circuit);

	if (circuit->circ_type != CIRCUIT_T_BROADCAST) {
		zlog_warn("%s: scheduled for non broadcast circuit from %s:%d",
			  __func__, thread->xref->xref.file,
			  thread->xref->xref.line);
		return;
	}

	if (circuit->u.bc.run_dr_elect[level - 1])
		zlog_warn("%s: run_dr_elect already set for l%d", __func__,
			  level);

	circuit->u.bc.t_run_dr[level - 1] = NULL;
	circuit->u.bc.run_dr_elect[level - 1] = 1;
}

static int isis_check_dr_change(struct isis_adjacency *adj, int level)
{
	int i;

	if (adj->dis_record[level - 1].dis
	    != adj->dis_record[(1 * ISIS_LEVELS) + level - 1].dis)
	/* was there a DIS state transition ? */
	{
		adj->dischanges[level - 1]++;
		adj->circuit->desig_changes[level - 1]++;
		/* ok rotate the history list through */
		for (i = DIS_RECORDS - 1; i > 0; i--) {
			adj->dis_record[(i * ISIS_LEVELS) + level - 1].dis =
				adj->dis_record[((i - 1) * ISIS_LEVELS) + level
						- 1]
					.dis;
			adj->dis_record[(i * ISIS_LEVELS) + level - 1]
				.last_dis_change =
				adj->dis_record[((i - 1) * ISIS_LEVELS) + level
						- 1]
					.last_dis_change;
		}
	}
	return ISIS_OK;
}

int isis_dr_elect(struct isis_circuit *circuit, int level)
{
	struct list *adjdb;
	struct listnode *node;
	struct isis_adjacency *adj, *adj_dr = NULL;
	struct list *list = list_new();
	uint8_t own_prio;
	int biggest_prio = -1;
	int cmp_res, retval = ISIS_OK;

	own_prio = circuit->priority[level - 1];
	adjdb = circuit->u.bc.adjdb[level - 1];

	if (!adjdb) {
		zlog_warn("%s adjdb == NULL", __func__);
		list_delete(&list);
		return ISIS_WARNING;
	}
	isis_adj_build_up_list(adjdb, list);

	/*
	 * Loop the adjacencies and find the one with the biggest priority
	 */
	for (ALL_LIST_ELEMENTS_RO(list, node, adj)) {
		/* clear flag for show output */
		adj->dis_record[level - 1].dis = ISIS_IS_NOT_DIS;
		adj->dis_record[level - 1].last_dis_change = time(NULL);

		if (adj->prio[level - 1] > biggest_prio) {
			biggest_prio = adj->prio[level - 1];
			adj_dr = adj;
		} else if (adj->prio[level - 1] == biggest_prio) {
			/*
			 * Comparison of MACs breaks a tie
			 */
			if (adj_dr) {
				cmp_res = memcmp(adj_dr->snpa, adj->snpa,
						 ETH_ALEN);
				if (cmp_res < 0) {
					adj_dr = adj;
				}
				if (cmp_res == 0)
					zlog_warn(
						"%s: multiple adjacencies with same SNPA",
						__func__);
			} else {
				adj_dr = adj;
			}
		}
	}

	if (!adj_dr) {
		/*
		 * Could not find the DR - means we are alone. Resign if we were
		 * DR.
		 */
		if (circuit->u.bc.is_dr[level - 1])
			retval = isis_dr_resign(circuit, level);
		list_delete(&list);
		return retval;
	}

	/*
	 * Now we have the DR adjacency, compare it to self
	 */
	if (adj_dr->prio[level - 1] < own_prio
	    || (adj_dr->prio[level - 1] == own_prio
		&& memcmp(adj_dr->snpa, circuit->u.bc.snpa, ETH_ALEN) < 0)) {
		adj_dr->dis_record[level - 1].dis = ISIS_IS_NOT_DIS;
		adj_dr->dis_record[level - 1].last_dis_change = time(NULL);

		/* rotate the history log */
		for (ALL_LIST_ELEMENTS_RO(list, node, adj))
			isis_check_dr_change(adj, level);

		/* We are the DR, commence DR */
		if (circuit->u.bc.is_dr[level - 1] == 0 && listcount(list) > 0)
			retval = isis_dr_commence(circuit, level);
	} else {
		/* ok we have found the DIS - lets mark the adjacency */
		/* set flag for show output */
		adj_dr->dis_record[level - 1].dis = ISIS_IS_DIS;
		adj_dr->dis_record[level - 1].last_dis_change = time(NULL);

		/* now loop through a second time to check if there has been a
		 * DIS change
		 * if yes rotate the history log
		 */

		for (ALL_LIST_ELEMENTS_RO(list, node, adj))
			isis_check_dr_change(adj, level);

		/*
		 * We are not DR - if we were -> resign
		 */
		if (circuit->u.bc.is_dr[level - 1])
			retval = isis_dr_resign(circuit, level);
	}
	list_delete(&list);
	return retval;
}

int isis_dr_resign(struct isis_circuit *circuit, int level)
{
	uint8_t id[ISIS_SYS_ID_LEN + 2];

	if (IS_DEBUG_EVENTS)
		zlog_debug("%s l%d", __func__, level);

	circuit->u.bc.is_dr[level - 1] = 0;
	circuit->u.bc.run_dr_elect[level - 1] = 0;
	EVENT_OFF(circuit->u.bc.t_run_dr[level - 1]);
	EVENT_OFF(circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);
	circuit->lsp_regenerate_pending[level - 1] = 0;

	memcpy(id, circuit->isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(id) = circuit->circuit_id;
	LSP_FRAGMENT(id) = 0;
	lsp_purge_pseudo(id, circuit, level);

	if (level == 1) {
		memset(circuit->u.bc.l1_desig_is, 0, ISIS_SYS_ID_LEN + 1);

		event_add_timer(master, send_l1_psnp, circuit,
				isis_jitter(circuit->psnp_interval[level - 1],
					    PSNP_JITTER),
				&circuit->t_send_psnp[0]);
	} else {
		memset(circuit->u.bc.l2_desig_is, 0, ISIS_SYS_ID_LEN + 1);

		event_add_timer(master, send_l2_psnp, circuit,
				isis_jitter(circuit->psnp_interval[level - 1],
					    PSNP_JITTER),
				&circuit->t_send_psnp[1]);
	}

	EVENT_OFF(circuit->t_send_csnp[level - 1]);

	event_add_timer(master, isis_run_dr, &circuit->level_arg[level - 1],
			2 * circuit->hello_interval[level - 1],
			&circuit->u.bc.t_run_dr[level - 1]);


	event_add_event(master, isis_event_dis_status_change, circuit, 0, NULL);

	return ISIS_OK;
}

int isis_dr_commence(struct isis_circuit *circuit, int level)
{
	uint8_t old_dr[ISIS_SYS_ID_LEN + 2];

	if (IS_DEBUG_EVENTS)
		zlog_debug("%s l%d", __func__, level);

	/* Lets keep a pause in DR election */
	circuit->u.bc.run_dr_elect[level - 1] = 0;
	circuit->u.bc.is_dr[level - 1] = 1;

	if (level == 1) {
		memcpy(old_dr, circuit->u.bc.l1_desig_is, ISIS_SYS_ID_LEN + 1);
		LSP_FRAGMENT(old_dr) = 0;
		if (LSP_PSEUDO_ID(old_dr)) {
			/* there was a dr elected, purge its LSPs from the db */
			lsp_purge_pseudo(old_dr, circuit, level);
		}
		memcpy(circuit->u.bc.l1_desig_is, circuit->isis->sysid,
		       ISIS_SYS_ID_LEN);
		*(circuit->u.bc.l1_desig_is + ISIS_SYS_ID_LEN) =
			circuit->circuit_id;

		assert(circuit->circuit_id); /* must be non-zero */
		lsp_generate_pseudo(circuit, 1);

		event_add_timer(master, send_l1_csnp, circuit,
				isis_jitter(circuit->csnp_interval[level - 1],
					    CSNP_JITTER),
				&circuit->t_send_csnp[0]);

	} else {
		memcpy(old_dr, circuit->u.bc.l2_desig_is, ISIS_SYS_ID_LEN + 1);
		LSP_FRAGMENT(old_dr) = 0;
		if (LSP_PSEUDO_ID(old_dr)) {
			/* there was a dr elected, purge its LSPs from the db */
			lsp_purge_pseudo(old_dr, circuit, level);
		}
		memcpy(circuit->u.bc.l2_desig_is, circuit->isis->sysid,
		       ISIS_SYS_ID_LEN);
		*(circuit->u.bc.l2_desig_is + ISIS_SYS_ID_LEN) =
			circuit->circuit_id;

		assert(circuit->circuit_id); /* must be non-zero */
		lsp_generate_pseudo(circuit, 2);

		event_add_timer(master, send_l2_csnp, circuit,
				isis_jitter(circuit->csnp_interval[level - 1],
					    CSNP_JITTER),
				&circuit->t_send_csnp[1]);
	}

	event_add_timer(master, isis_run_dr, &circuit->level_arg[level - 1],
			2 * circuit->hello_interval[level - 1],
			&circuit->u.bc.t_run_dr[level - 1]);
	event_add_event(master, isis_event_dis_status_change, circuit, 0, NULL);

	return ISIS_OK;
}
