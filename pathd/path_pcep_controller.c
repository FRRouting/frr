/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "version.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"

#include "pathd/pathd.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_pcc.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"

#define POLL_INTERVAL 1
#define MAX_RECONNECT_DELAY 120

#define min(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a <= _b ? _a : _b;                                            \
	})


/* Event handling data structures */
enum pcep_ctrl_event_type {
	EV_INITIALIZE = 1,
	EV_UPDATE_PCC_OPTS,
	EV_UPDATE_PCE_OPTS,
	EV_DISCONNECT_PCC,
	EV_PATHD_EVENT,
	EV_SYNC_PATH,
	EV_SYNC_DONE
};

struct pcep_ctrl_event_data {
	struct ctrl_state *ctrl_state;
	enum pcep_ctrl_event_type type;
	uint32_t sub_type;
	int pcc_id;
	void *payload;
};

struct pcep_main_event_data {
	pcep_main_event_handler_t handler;
	int pcc_id;
	enum pcep_main_event_type type;
	void *payload;
};

/* Timer handling data structures */

enum pcep_ctrl_timer_type { TM_POLL = 1, TM_RECONNECT_PCC };

struct pcep_ctrl_timer_data {
	struct ctrl_state *ctrl_state;
	enum pcep_ctrl_timer_type type;
	int pcc_id;
	void *payload;
};

/* Synchronous call arguments */

struct get_counters_args {
	struct ctrl_state *ctrl_state;
	int pcc_id;
	struct counters_group *counters;
};


/* Internal Functions Called From Main Thread */
static int pcep_ctrl_halt_cb(struct frr_pthread *fpt, void **res);

/* Internal Functions Called From Controller Thread */
static int pcep_thread_finish_event_handler(struct thread *thread);
static void pcep_thread_schedule_poll(struct ctrl_state *ctrl_state);
static int pcep_thread_get_counters_callback(struct thread *t);

/* Controller Thread Timer Handler */
static int schedule_thread(struct ctrl_state *ctrl_state, int pcc_id,
			   enum pcep_ctrl_timer_type type, uint32_t delay,
			   void *payload, struct thread **thread);
static int pcep_thread_timer_handler(struct thread *thread);
static int pcep_thread_timer_poll(struct ctrl_state *ctrl_state);

/* Controller Thread Event Handler */
static int send_to_thread(struct ctrl_state *ctrl_state, int pcc_id,
			  enum pcep_ctrl_event_type type, uint32_t sub_type,
			  void *payload);
static int pcep_thread_event_handler(struct thread *thread);
static int pcep_thread_event_update_pcc_options(struct ctrl_state *ctrl_state,
						struct pcc_opts *opts);
static int pcep_thread_event_update_pce_options(struct ctrl_state *ctrl_state,
						int pcc_id,
						struct pce_opts *opts);
static int pcep_thread_event_disconnect_pcc(struct ctrl_state *ctrl_state,
					    int pcc_id);
static int pcep_thread_event_sync_path(struct ctrl_state *ctrl_state,
				       int pcc_id, struct path *path);
static int pcep_thread_event_sync_done(struct ctrl_state *ctrl_state,
				       int pcc_id);
static int pcep_thread_event_pathd_event(struct ctrl_state *ctrl_state,
					 enum pcep_pathd_event_type type,
					 struct path *path);

/* Main Thread Event Handler */
static int send_to_main(struct ctrl_state *ctrl_state, int pcc_id,
			enum pcep_main_event_type type, void *payload);
static int pcep_main_event_handler(struct thread *thread);

/* Helper functions */
static void set_ctrl_state(struct frr_pthread *fpt,
			   struct ctrl_state *ctrl_state);
static struct ctrl_state *get_ctrl_state(struct frr_pthread *fpt);
static struct pcc_state *get_pcc_state(struct ctrl_state *ctrl_state,
				       int pcc_id);
static void set_pcc_state(struct ctrl_state *ctrl_state,
			  struct pcc_state *pcc_state);
static uint32_t backoff_delay(uint32_t max, uint32_t base, uint32_t attempt);


/* ------------ API Functions Called from Main Thread ------------ */

int pcep_ctrl_initialize(struct thread_master *main_thread,
			 struct frr_pthread **fpt,
			 pcep_main_event_handler_t event_handler)
{
	assert(NULL != fpt);

	int ret = 0;
	struct ctrl_state *ctrl_state;
	struct frr_pthread_attr attr = {
		.start = frr_pthread_attr_default.start,
		.stop = pcep_ctrl_halt_cb,
	};

	PCEP_DEBUG("Initializing pcep module controller");

	/* Create and start the FRR pthread */
	*fpt = frr_pthread_new(&attr, "PCEP thread", "pcep");
	if (NULL == *fpt) {
		flog_err(EC_PATH_SYSTEM_CALL,
			 "failed to initialize PCEP thread");
		return 1;
	}
	ret = frr_pthread_run(*fpt, NULL);
	if (ret < 0) {
		flog_err(EC_PATH_SYSTEM_CALL, "failed to create PCEP thread");
		return ret;
	}
	frr_pthread_wait_running(*fpt);

	/* Initialise the thread state */
	ctrl_state = XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state));
	ctrl_state->main = main_thread;
	ctrl_state->self = (*fpt)->master;
	ctrl_state->main_event_handler = event_handler;
	ctrl_state->t_poll = NULL;
	ctrl_state->pcc_count = 0;
	ctrl_state->pcc_opts =
		XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state->pcc_opts));
	ctrl_state->pcc_opts->addr.s_addr = INADDR_ANY;
	ctrl_state->pcc_opts->port = PCEP_DEFAULT_PORT;

	/* Keep the state reference for events */
	set_ctrl_state(*fpt, ctrl_state);

	/* Initialize the PCEP thread */
	send_to_thread(ctrl_state, 0, EV_INITIALIZE, 0, NULL);

	return ret;
}

int pcep_ctrl_finalize(struct frr_pthread **fpt)
{
	assert(NULL != fpt);

	int ret = 0;

	PCEP_DEBUG("Finalizing pcep module controller");

	if (NULL != *fpt) {
		frr_pthread_stop(*fpt, NULL);
		*fpt = NULL;
	}

	return ret;
}

int pcep_ctrl_update_pcc_options(struct frr_pthread *fpt, struct pcc_opts *opts)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_UPDATE_PCC_OPTS, 0, opts);
}

int pcep_ctrl_update_pce_options(struct frr_pthread *fpt, int pcc_id,
				 struct pce_opts *opts)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, pcc_id, EV_UPDATE_PCE_OPTS, 0, opts);
}

int pcep_ctrl_disconnect_pcc(struct frr_pthread *fpt, int pcc_id)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, pcc_id, EV_DISCONNECT_PCC, 0, NULL);
}

int pcep_ctrl_pathd_event(struct frr_pthread *fpt,
			  enum pcep_pathd_event_type type, struct path *path)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_PATHD_EVENT, type, path);
}

int pcep_ctrl_sync_path(struct frr_pthread *fpt, int pcc_id, struct path *path)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, pcc_id, EV_SYNC_PATH, 0, path);
}

int pcep_ctrl_sync_done(struct frr_pthread *fpt, int pcc_id)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, pcc_id, EV_SYNC_DONE, 0, NULL);
}

struct counters_group *pcep_ctrl_get_counters(struct frr_pthread *fpt,
					      int pcc_id)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	struct get_counters_args args = {
		.ctrl_state = ctrl_state, .pcc_id = pcc_id, .counters = NULL};
	thread_execute(ctrl_state->self, pcep_thread_get_counters_callback,
		       &args, 0);
	return args.counters;
}


/* ------------ Internal Functions Called from Main Thread ------------ */

int pcep_ctrl_halt_cb(struct frr_pthread *fpt, void **res)
{
	thread_add_event(fpt->master, pcep_thread_finish_event_handler,
			 (void *)fpt, 0, NULL);
	pthread_join(fpt->thread, res);

	return 0;
}


/* ------------ API Functions Called From Controller Thread ------------ */

void pcep_thread_start_sync(struct ctrl_state *ctrl_state, int pcc_id)
{
	send_to_main(ctrl_state, pcc_id, PCEP_MAIN_EVENT_START_SYNC, NULL);
}

void pcep_thread_update_path(struct ctrl_state *ctrl_state, int pcc_id,
			     struct path *path)
{
	send_to_main(ctrl_state, pcc_id, PCEP_MAIN_EVENT_UPDATE_CANDIDATE,
		     path);
}

void pcep_thread_schedule_reconnect(struct ctrl_state *ctrl_state, int pcc_id,
				    int retry_count, struct thread **thread)
{
	uint32_t delay = backoff_delay(MAX_RECONNECT_DELAY, 1, retry_count);
	PCEP_DEBUG("Schedule reconnection in %us (retry %u)", delay,
		   retry_count);
	schedule_thread(ctrl_state, pcc_id, TM_RECONNECT_PCC, delay, NULL,
			thread);
}


/* ------------ Internal Functions Called From Controller Thread ------------ */

int pcep_thread_finish_event_handler(struct thread *thread)
{
	int i;
	struct frr_pthread *fpt = THREAD_ARG(thread);
	struct ctrl_state *ctrl_state = fpt->data;

	assert(NULL != ctrl_state);

	if (NULL != ctrl_state->t_poll) {
		thread_cancel(ctrl_state->t_poll);
	}

	for (i = 0; i < ctrl_state->pcc_count; i++) {
		pcep_pcc_finalize(ctrl_state, ctrl_state->pcc[i]);
		ctrl_state->pcc[i] = NULL;
	}

	XFREE(MTYPE_PCEP, ctrl_state->pcc_opts);
	XFREE(MTYPE_PCEP, ctrl_state);
	fpt->data = NULL;

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
	return 0;
}

void pcep_thread_schedule_poll(struct ctrl_state *ctrl_state)
{
	assert(NULL == ctrl_state->t_poll);
	schedule_thread(ctrl_state, 0, TM_POLL, POLL_INTERVAL, NULL,
			&ctrl_state->t_poll);
}

int pcep_thread_get_counters_callback(struct thread *t)
{
	struct get_counters_args *args = THREAD_ARG(t);
	assert(NULL != args);
	struct ctrl_state *ctrl_state = args->ctrl_state;
	assert(NULL != ctrl_state);
	struct pcc_state *pcc_state;

	if (args->pcc_id <= ctrl_state->pcc_count) {
		pcc_state = get_pcc_state(ctrl_state, args->pcc_id);
		args->counters = pcep_lib_copy_counters(pcc_state->sess);
		return 0;
	}

	args->counters = NULL;
	return 0;
}


/* ------------ Controller Thread Timer Handler ------------ */

int schedule_thread(struct ctrl_state *ctrl_state, int pcc_id,
		    enum pcep_ctrl_timer_type type, uint32_t delay,
		    void *payload, struct thread **thread)
{
	assert(NULL != thread);

	struct pcep_ctrl_timer_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->type = type;
	data->pcc_id = pcc_id;
	data->payload = payload;

	thread_add_timer(ctrl_state->self, pcep_thread_timer_handler,
			 (void *)data, delay, thread);

	return 0;
}

int pcep_thread_timer_handler(struct thread *thread)
{
	/* data unpacking */
	struct pcep_ctrl_timer_data *data = THREAD_ARG(thread);
	assert(NULL != data);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	assert(NULL != ctrl_state);
	enum pcep_ctrl_timer_type type = data->type;
	int pcc_id = data->pcc_id;
	XFREE(MTYPE_PCEP, data);

	int ret = 0;
	struct pcc_state *pcc_state = NULL;

	switch (type) {
	case TM_POLL:
		ret = pcep_thread_timer_poll(ctrl_state);
		break;
	case TM_RECONNECT_PCC:
		pcc_state = get_pcc_state(ctrl_state, pcc_id);
		pcep_pcc_reconnect(ctrl_state, pcc_state);
		break;
	default:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unknown controller timer triggered: %u", type);
		break;
	}

	return ret;
}


int pcep_thread_timer_poll(struct ctrl_state *ctrl_state)
{
	int i;
	pcep_event *event;

	assert(NULL == ctrl_state->t_poll);

	while (NULL != (event = event_queue_get_event())) {
		for (i = 0; i < ctrl_state->pcc_count; i++) {
			struct pcc_state *pcc_state = ctrl_state->pcc[i];
			if (pcc_state->sess != event->session)
				continue;
			pcep_pcc_pcep_event_handler(ctrl_state, pcc_state,
						    event);
			break;
		}
		destroy_pcep_event(event);
	}

	pcep_thread_schedule_poll(ctrl_state);

	return 0;
}


/* ------------ Controller Thread Event Handler ------------ */

int send_to_thread(struct ctrl_state *ctrl_state, int pcc_id,
		   enum pcep_ctrl_event_type type, uint32_t sub_type,
		   void *payload)
{
	struct pcep_ctrl_event_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->type = type;
	data->sub_type = sub_type;
	data->pcc_id = pcc_id;
	data->payload = payload;

	thread_add_event(ctrl_state->self, pcep_thread_event_handler,
			 (void *)data, 0, NULL);
	return 0;
}

int pcep_thread_event_handler(struct thread *thread)
{
	/* data unpacking */
	struct pcep_ctrl_event_data *data = THREAD_ARG(thread);
	assert(NULL != data);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	assert(NULL != ctrl_state);
	enum pcep_ctrl_event_type type = data->type;
	uint32_t sub_type = data->sub_type;
	int pcc_id = data->pcc_id;
	void *payload = data->payload;
	XFREE(MTYPE_PCEP, data);

	int ret = 0;

	/* Possible sub-type values */
	enum pcep_pathd_event_type path_event_type = PCEP_PATH_UNDEFINED;

	/* Possible payload values */
	struct path *path = NULL;
	struct pcc_opts *pcc_opts = NULL;
	struct pce_opts *pce_opts = NULL;

	switch (type) {
	case EV_INITIALIZE:
		pcep_thread_schedule_poll(ctrl_state);
		break;
	case EV_UPDATE_PCC_OPTS:
		assert(NULL != payload);
		pcc_opts = (struct pcc_opts *)payload;
		ret = pcep_thread_event_update_pcc_options(ctrl_state,
							   pcc_opts);
		break;
	case EV_UPDATE_PCE_OPTS:
		assert(NULL != payload);
		pce_opts = (struct pce_opts *)payload;
		ret = pcep_thread_event_update_pce_options(ctrl_state, pcc_id,
							   pce_opts);
		break;
	case EV_DISCONNECT_PCC:
		ret = pcep_thread_event_disconnect_pcc(ctrl_state, pcc_id);
		break;
	case EV_PATHD_EVENT:
		assert(NULL != payload);
		path_event_type = (enum pcep_pathd_event_type)sub_type;
		path = (struct path *)payload;
		ret = pcep_thread_event_pathd_event(ctrl_state, path_event_type,
						    path);
		break;
	case EV_SYNC_PATH:
		assert(NULL != payload);
		path = (struct path *)payload;
		ret = pcep_thread_event_sync_path(ctrl_state, pcc_id, path);
		break;
	case EV_SYNC_DONE:
		ret = pcep_thread_event_sync_done(ctrl_state, pcc_id);
		break;
	default:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unexpected event received in controller thread: %u",
			  type);
		break;
	}

	return ret;
}

int pcep_thread_event_update_pcc_options(struct ctrl_state *ctrl_state,
					 struct pcc_opts *opts)
{
	assert(NULL != opts);
	if (NULL != ctrl_state->pcc_opts) {
		XFREE(MTYPE_PCEP, ctrl_state->pcc_opts);
	}
	ctrl_state->pcc_opts = opts;
	return 0;
}

int pcep_thread_event_update_pce_options(struct ctrl_state *ctrl_state,
					 int pcc_id, struct pce_opts *pce_opts)
{
	struct pcc_state *pcc_state;
	struct pcc_opts *pcc_opts;

	if (pcc_id > ctrl_state->pcc_count) {
		pcc_state = pcep_pcc_initialize(ctrl_state, pcc_id);
		set_pcc_state(ctrl_state, pcc_state);
	} else {
		pcc_state = get_pcc_state(ctrl_state, pcc_id);
	}

	/* Copy the pcc options to delegate it to the update function */
	pcc_opts = XCALLOC(MTYPE_PCEP, sizeof(*pcc_opts));
	memcpy(pcc_opts, ctrl_state->pcc_opts, sizeof(*pcc_opts));

	if (pcep_pcc_update(ctrl_state, pcc_state, pcc_opts, pce_opts)) {
		flog_err(EC_PATH_PCEP_PCC_CONF_UPDATE,
			 "failed to update PCC configuration");
	}

	return 0;
}

int pcep_thread_event_disconnect_pcc(struct ctrl_state *ctrl_state, int pcc_id)
{
	struct pcc_state *pcc_state;

	if (pcc_id <= ctrl_state->pcc_count) {
		pcc_state = get_pcc_state(ctrl_state, pcc_id);
		pcep_pcc_disable(ctrl_state, pcc_state);
	}

	return 0;
}

int pcep_thread_event_sync_path(struct ctrl_state *ctrl_state, int pcc_id,
				struct path *path)
{
	struct pcc_state *pcc_state = get_pcc_state(ctrl_state, pcc_id);
	pcep_pcc_sync_path(ctrl_state, pcc_state, path);
	pcep_free_path(path);
	return 0;
}

int pcep_thread_event_sync_done(struct ctrl_state *ctrl_state, int pcc_id)
{
	struct pcc_state *pcc_state = get_pcc_state(ctrl_state, pcc_id);
	pcep_pcc_sync_done(ctrl_state, pcc_state);
	return 0;
}

int pcep_thread_event_pathd_event(struct ctrl_state *ctrl_state,
				  enum pcep_pathd_event_type type,
				  struct path *path)
{
	int i;

	for (i = 0; i < ctrl_state->pcc_count; i++) {
		struct pcc_state *pcc_state = ctrl_state->pcc[i];
		pcep_pcc_pathd_event_handler(ctrl_state, pcc_state, type, path);
	}

	pcep_free_path(path);

	return 0;
}


/* ------------ Main Thread Event Handler ------------ */

int send_to_main(struct ctrl_state *ctrl_state, int pcc_id,
		 enum pcep_main_event_type type, void *payload)
{
	struct pcep_main_event_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->handler = ctrl_state->main_event_handler;
	data->type = type;
	data->pcc_id = pcc_id;
	data->payload = payload;

	thread_add_event(ctrl_state->main, pcep_main_event_handler,
			 (void *)data, 0, NULL);
	return 0;
}

int pcep_main_event_handler(struct thread *thread)
{
	/* data unpacking */
	struct pcep_main_event_data *data = THREAD_ARG(thread);
	assert(NULL != data);
	pcep_main_event_handler_t handler = data->handler;
	enum pcep_main_event_type type = data->type;
	int pcc_id = data->pcc_id;
	void *payload = data->payload;
	XFREE(MTYPE_PCEP, data);

	return handler(type, pcc_id, payload);
}


/* ------------ Helper functions ------------ */

void set_ctrl_state(struct frr_pthread *fpt, struct ctrl_state *ctrl_state)
{
	assert(NULL != fpt);
	fpt->data = ctrl_state;
}

struct ctrl_state *get_ctrl_state(struct frr_pthread *fpt)
{
	assert(NULL != fpt);
	assert(NULL != fpt->data);

	struct ctrl_state *ctrl_state;
	ctrl_state = (struct ctrl_state *)fpt->data;
	assert(NULL != ctrl_state);
	return ctrl_state;
}

struct pcc_state *get_pcc_state(struct ctrl_state *ctrl_state, int pcc_id)
{
	assert(NULL != ctrl_state);
	assert(0 < pcc_id);
	assert(pcc_id <= MAX_PCC);
	assert(pcc_id <= ctrl_state->pcc_count);

	struct pcc_state *pcc_state;
	pcc_state = ctrl_state->pcc[pcc_id - 1];
	assert(NULL != pcc_state);
	return pcc_state;
}

void set_pcc_state(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	assert(NULL != ctrl_state);
	assert(0 < pcc_state->id);
	assert(pcc_state->id <= MAX_PCC);
	assert(pcc_state->id > ctrl_state->pcc_count);
	assert(NULL == ctrl_state->pcc[pcc_state->id - 1]);

	ctrl_state->pcc[pcc_state->id - 1] = pcc_state;
	ctrl_state->pcc_count = pcc_state->id;
}

uint32_t backoff_delay(uint32_t max, uint32_t base, uint32_t retry_count)
{
	uint32_t a = min(max, base * (1 << retry_count));
	uint64_t r = rand(), m = RAND_MAX;
	uint32_t b = (a / 2) + (r * (a / 2)) / m;
	return b;
}
