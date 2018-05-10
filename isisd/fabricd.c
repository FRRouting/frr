/*
 * IS-IS Rout(e)ing protocol - OpenFabric extensions
 *
 * Copyright (C) 2018 Christian Franke
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "isisd/fabricd.h"
#include "isisd/isisd.h"
#include "isisd/isis_memory.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_tx_queue.h"

DEFINE_MTYPE_STATIC(ISISD, FABRICD_STATE, "ISIS OpenFabric")

/* Tracks initial synchronization as per section 2.4
 *
 * We declare the sync complete once we have seen at least one
 * CSNP and there are no more LSPs with SSN or SRM set.
 */
enum fabricd_sync_state {
	FABRICD_SYNC_PENDING,
	FABRICD_SYNC_STARTED,
	FABRICD_SYNC_COMPLETE
};

struct fabricd {
	struct isis_area *area;

	enum fabricd_sync_state initial_sync_state;
	time_t initial_sync_start;
	struct isis_circuit *initial_sync_circuit;
	struct thread *initial_sync_timeout;

	struct isis_spftree *spftree;

	uint8_t tier;
	uint8_t tier_config;
	uint8_t tier_pending;
	struct thread *tier_calculation_timer;
	struct thread *tier_set_timer;
};

struct fabricd *fabricd_new(struct isis_area *area)
{
	struct fabricd *rv = XCALLOC(MTYPE_FABRICD_STATE, sizeof(*rv));

	rv->area = area;
	rv->initial_sync_state = FABRICD_SYNC_PENDING;
	rv->spftree = isis_spftree_new(area);
	rv->tier = rv->tier_config = ISIS_TIER_UNDEFINED;
	return rv;
};

void fabricd_finish(struct fabricd *f)
{
	if (f->initial_sync_timeout)
		thread_cancel(f->initial_sync_timeout);

	if (f->tier_calculation_timer)
		thread_cancel(f->tier_calculation_timer);

	if (f->tier_set_timer)
		thread_cancel(f->tier_set_timer);

	isis_spftree_del(f->spftree);
}

static int fabricd_initial_sync_timeout(struct thread *thread)
{
	struct fabricd *f = THREAD_ARG(thread);

	zlog_info("OpenFabric: Initial synchronization on %s timed out!",
		  f->initial_sync_circuit->interface->name);
	f->initial_sync_state = FABRICD_SYNC_PENDING;
	f->initial_sync_circuit = NULL;
	f->initial_sync_timeout = NULL;
	return 0;
}

void fabricd_initial_sync_hello(struct isis_circuit *circuit)
{
	struct fabricd *f = circuit->area->fabricd;

	if (!f)
		return;

	if (f->initial_sync_state > FABRICD_SYNC_PENDING)
		return;

	f->initial_sync_state = FABRICD_SYNC_STARTED;

	long timeout = 2 * circuit->hello_interval[1] * circuit->hello_multiplier[1];

	f->initial_sync_circuit = circuit;
	if (f->initial_sync_timeout)
		return;

	thread_add_timer(master, fabricd_initial_sync_timeout, f,
			 timeout, &f->initial_sync_timeout);
	f->initial_sync_start = monotime(NULL);

	zlog_info("OpenFabric: Started initial synchronization with %s on %s",
		  sysid_print(circuit->u.p2p.neighbor->sysid),
		  circuit->interface->name);
}

bool fabricd_initial_sync_is_in_progress(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return false;

	if (f->initial_sync_state > FABRICD_SYNC_PENDING
	    && f->initial_sync_state < FABRICD_SYNC_COMPLETE)
		return true;

	return false;
}

struct isis_circuit *fabricd_initial_sync_circuit(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;
	if (!f)
		return NULL;

	return f->initial_sync_circuit;
}

void fabricd_initial_sync_finish(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return;

	if (monotime(NULL) - f->initial_sync_start < 5)
		return;

	zlog_info("OpenFabric: Initial synchronization on %s complete.",
		  f->initial_sync_circuit->interface->name);
	f->initial_sync_state = FABRICD_SYNC_COMPLETE;
	f->initial_sync_circuit = NULL;
	thread_cancel(f->initial_sync_timeout);
	f->initial_sync_timeout = NULL;
}

static void fabricd_bump_tier_calculation_timer(struct fabricd *f);
static void fabricd_set_tier(struct fabricd *f, uint8_t tier);

static uint8_t fabricd_calculate_fabric_tier(struct isis_area *area)
{
	struct isis_spftree *local_tree = fabricd_spftree(area);
	struct listnode *node;

	struct isis_vertex *furthest_t0 = NULL,
			   *second_furthest_t0 = NULL;

	struct isis_vertex *v;

	for (ALL_QUEUE_ELEMENTS_RO(&local_tree->paths, node, v)) {
		struct isis_lsp *lsp = lsp_for_vertex(local_tree, v);

		if (!lsp || !lsp->tlvs
		    || !lsp->tlvs->spine_leaf
		    || !lsp->tlvs->spine_leaf->has_tier
		    || lsp->tlvs->spine_leaf->tier != 0)
			continue;

		second_furthest_t0 = furthest_t0;
		furthest_t0 = v;
	}

	if (!second_furthest_t0) {
		zlog_info("OpenFabric: Could not find two T0 routers");
		return ISIS_TIER_UNDEFINED;
	}

	zlog_info("OpenFabric: Found %s as furthest t0 from local system, dist == %"
		  PRIu32, rawlspid_print(furthest_t0->N.id), furthest_t0->d_N);

	struct isis_spftree *remote_tree =
		isis_run_hopcount_spf(area, furthest_t0->N.id, NULL);

	struct isis_vertex *furthest_from_remote =
		isis_vertex_queue_last(&remote_tree->paths);

	if (!furthest_from_remote) {
		zlog_info("OpenFabric: Found no furthest node in remote spf");
		isis_spftree_del(remote_tree);
		return ISIS_TIER_UNDEFINED;
	} else {
		zlog_info("OpenFabric: Found %s as furthest from remote dist == %"
			  PRIu32, rawlspid_print(furthest_from_remote->N.id),
			  furthest_from_remote->d_N);
	}

	int64_t tier = furthest_from_remote->d_N - furthest_t0->d_N;
	isis_spftree_del(remote_tree);

	if (tier < 0 || tier >= ISIS_TIER_UNDEFINED) {
		zlog_info("OpenFabric: Calculated tier %" PRId64 " seems implausible",
			  tier);
		return ISIS_TIER_UNDEFINED;
	}

	zlog_info("OpenFabric: Calculated %" PRId64 " as tier", tier);
	return tier;
}

static int fabricd_tier_set_timer(struct thread *thread)
{
	struct fabricd *f = THREAD_ARG(thread);
	f->tier_set_timer = NULL;

	fabricd_set_tier(f, f->tier_pending);
	return 0;
}

static int fabricd_tier_calculation_cb(struct thread *thread)
{
	struct fabricd *f = THREAD_ARG(thread);
	uint8_t tier = ISIS_TIER_UNDEFINED;
	f->tier_calculation_timer = NULL;

	tier = fabricd_calculate_fabric_tier(f->area);
	if (tier == ISIS_TIER_UNDEFINED)
		return 0;

	zlog_info("OpenFabric: Got tier %" PRIu8 " from algorithm. Arming timer.",
		  tier);
	f->tier_pending = tier;
	thread_add_timer(master, fabricd_tier_set_timer, f,
			 f->area->lsp_gen_interval[ISIS_LEVEL2 - 1],
			 &f->tier_set_timer);

	return 0;
}

static void fabricd_bump_tier_calculation_timer(struct fabricd *f)
{
	/* Cancel timer if we already know our tier */
	if (f->tier != ISIS_TIER_UNDEFINED
	    || f->tier_set_timer) {
		if (f->tier_calculation_timer) {
			thread_cancel(f->tier_calculation_timer);
			f->tier_calculation_timer = NULL;
		}
		return;
	}

	/* If we need to calculate the tier, wait some
	 * time for the topology to settle before running
	 * the calculation */
	if (f->tier_calculation_timer) {
		thread_cancel(f->tier_calculation_timer);
		f->tier_calculation_timer = NULL;
	}

	thread_add_timer(master, fabricd_tier_calculation_cb, f,
			 2 * f->area->lsp_gen_interval[ISIS_LEVEL2 - 1],
			 &f->tier_calculation_timer);
}

static void fabricd_set_tier(struct fabricd *f, uint8_t tier)
{
	if (f->tier == tier)
		return;

	zlog_info("OpenFabric: Set own tier to %" PRIu8, tier);
	f->tier = tier;

	fabricd_bump_tier_calculation_timer(f);
	lsp_regenerate_schedule(f->area, ISIS_LEVEL2, 0);
}

void fabricd_run_spf(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return;

	isis_run_hopcount_spf(area, isis->sysid, f->spftree);
	fabricd_bump_tier_calculation_timer(f);
}

struct isis_spftree *fabricd_spftree(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return NULL;

	return f->spftree;
}

void fabricd_configure_tier(struct isis_area *area, uint8_t tier)
{
	struct fabricd *f = area->fabricd;

	if (!f || f->tier_config == tier)
		return;

	f->tier_config = tier;
	fabricd_set_tier(f, tier);
}

uint8_t fabricd_tier(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return ISIS_TIER_UNDEFINED;

	return f->tier;
}

int fabricd_write_settings(struct isis_area *area, struct vty *vty)
{
	struct fabricd *f = area->fabricd;
	int written = 0;

	if (!f)
		return written;

	if (f->tier_config != ISIS_TIER_UNDEFINED) {
		vty_out(vty, " fabric-tier %" PRIu8 "\n", f->tier_config);
		written++;
	}

	return written;
}
