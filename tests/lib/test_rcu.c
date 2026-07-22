// SPDX-License-Identifier: ISC
/*
 * RCU external-thread registration / teardown tests
 *
 * Copyright (C) 2026 ATCorp
 * Jafar Al-Gharaibeh
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include "frrcu.h"
#include "seqlock.h"
#include "printfrr.h"

#define NWORKERS 8

enum worker_mode {
	/* Tokio-style: explicit unprepare(NULL), including a second call */
	MODE_EXPLICIT_UNPREPARE,
	/* rely on pthread_key destructor at thread exit */
	MODE_DESTRUCTOR,
};

struct worker_arg {
	enum worker_mode mode;
	int id;
};

static void *worker(void *arg)
{
	struct worker_arg *wa = arg;
	struct rcu_thread *rt;
	struct rcu_local_state st;

	rt = rcu_thread_new(NULL);
	assert(rt);
	rcu_thread_start(rt);

	/* rcu_thread_new(NULL) must leave the thread holding an epoch */
	st = rcu_local_state();
	assert(st.seq_local & SEQLOCK_HELD);

	rcu_assert_read_locked();
	rcu_read_lock();
	rcu_assert_read_locked();
	rcu_read_unlock();
	rcu_assert_read_locked();

	if (wa->mode == MODE_EXPLICIT_UNPREPARE) {
		rcu_thread_unprepare(NULL);
		/* second call must be a no-op (no abort / double-free) */
		rcu_thread_unprepare(NULL);
	}

	return NULL;
}

static void run_workers(enum worker_mode mode, const char *label)
{
	pthread_t thr[NWORKERS];
	struct worker_arg args[NWORKERS];
	int i, err;

	printfrr("rcu: %s (%d workers)...\n", label, NWORKERS);

	for (i = 0; i < NWORKERS; i++) {
		args[i].mode = mode;
		args[i].id = i;
		err = pthread_create(&thr[i], NULL, worker, &args[i]);
		assert(err == 0);
	}

	for (i = 0; i < NWORKERS; i++) {
		err = pthread_join(thr[i], NULL);
		assert(err == 0);
	}
}

static void test_prepare_failed_create(void)
{
	struct rcu_thread *rt;

	printfrr("rcu: prepare + unprepare without start...\n");

	/* main thread is RCU-held from rcu_preinit() */
	rcu_assert_read_locked();
	rt = rcu_thread_prepare();
	assert(rt);
	/* simulate pthread_create() failure */
	rcu_thread_unprepare(rt);
}

int main(int argc, char **argv)
{
	struct rcu_stats stats;

	test_prepare_failed_create();
	run_workers(MODE_EXPLICIT_UNPREPARE, "explicit unprepare(NULL)");
	run_workers(MODE_DESTRUCTOR, "destructor cleanup");

	/* all external threads gone; shutdown must see only main */
	rcu_stats(&stats);
	assert(stats.rcu_active);
	assert(stats.holding >= 1);

	printfrr("rcu: rcu_shutdown...\n");
	rcu_shutdown();

	printfrr("rcu: OK\n");
	return 0;
}
