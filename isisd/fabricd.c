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
	enum fabricd_sync_state initial_sync_state;
	time_t initial_sync_start;
	struct isis_circuit *initial_sync_circuit;
	struct thread *initial_sync_timeout;

	struct isis_spftree *spftree;
};

struct fabricd *fabricd_new(struct isis_area *area)
{
	struct fabricd *rv = XCALLOC(MTYPE_FABRICD_STATE, sizeof(*rv));

	rv->initial_sync_state = FABRICD_SYNC_PENDING;
	rv->spftree = isis_spftree_new(area);
	return rv;
};

void fabricd_finish(struct fabricd *f)
{
	if (f->initial_sync_timeout)
		thread_cancel(f->initial_sync_timeout);

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

void fabricd_run_spf(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return;

	isis_run_hopcount_spf(area, isis->sysid, f->spftree);
}

struct isis_spftree *fabricd_spftree(struct isis_area *area)
{
	struct fabricd *f = area->fabricd;

	if (!f)
		return NULL;

	return f->spftree;
}
