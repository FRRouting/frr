// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra system manager interface module
 * Copyright (C) 2026 Donald Sharp <sharpd@nvidia.com> NVIDIA Corporation
 */

#include <zebra.h>

#include "lib/frr_pthread.h"
#include "frrevent.h"

#include "zebra/zebra_sysmgr.h"

static struct zebra_sysmgr_globals {
	_Atomic uint32_t run;
	struct frr_pthread *pthread;
	struct event_loop *master;
	struct event *t_work;
} zsysmgr;

static void sysmgr_thread_loop(struct event *event)
{
	if (!atomic_load_explicit(&zsysmgr.run, memory_order_relaxed))
		return;

	/* Placeholder until work queues are introduced. */
}

void zebra_sysmgr_init(void)
{
	memset(&zsysmgr, 0, sizeof(zsysmgr));
}

void zebra_sysmgr_start(void)
{
	struct frr_pthread_attr pattr = { .start = frr_pthread_attr_default.start,
					  .stop = frr_pthread_attr_default.stop };

	zsysmgr.pthread = frr_pthread_new(&pattr, "Zebra System Manager thread", "zebra_sysmgr");

	zsysmgr.master = zsysmgr.pthread->master;

	atomic_store_explicit(&zsysmgr.run, 1, memory_order_relaxed);

	event_add_event(zsysmgr.master, sysmgr_thread_loop, NULL, 0, &zsysmgr.t_work);

	frr_pthread_run(zsysmgr.pthread, NULL);
}

void zebra_sysmgr_stop(void)
{
	if (!zsysmgr.pthread)
		return;

	atomic_store_explicit(&zsysmgr.run, 0, memory_order_relaxed);

	frr_pthread_stop(zsysmgr.pthread, NULL);
	frr_pthread_destroy(zsysmgr.pthread);
	zsysmgr.pthread = NULL;
	zsysmgr.master = NULL;
}

void zebra_sysmgr_finish(void)
{
	/* Nothing to free yet; queues will be torn down here later. */
}
