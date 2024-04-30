// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#include <zebra.h>

#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"
#include "network.h"

#include "pathd/pathd.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_pcc.h"
#include "pathd/path_pcep_config.h"
#include "pathd/path_pcep_debug.h"

#define MAX_RECONNECT_DELAY 120

/* Event handling data structures */
enum pcep_ctrl_event_type {
	EV_UPDATE_PCC_OPTS = 1,
	EV_UPDATE_PCE_OPTS,
	EV_REMOVE_PCC,
	EV_PATHD_EVENT,
	EV_SYNC_PATH,
	EV_SYNC_DONE,
	EV_PCEPLIB_EVENT,
	EV_RESET_PCC_SESSION,
	EV_SEND_REPORT,
	EV_SEND_ERROR,
	EV_PATH_REFINED
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

struct pcep_refine_path_event_data {
	struct ctrl_state *ctrl_state;
	int pcc_id;
	pcep_refine_callback_t continue_lsp_update_handler;
	struct path *path;
	void *payload;
};

/* Synchronous call arguments */

struct get_counters_args {
	struct ctrl_state *ctrl_state;
	int pcc_id;
	struct counters_group *counters;
};

struct get_pcep_session_args {
	struct ctrl_state *ctrl_state;
	int pcc_id;
	pcep_session *pcep_session;
};

/* Internal Functions Called From Main Thread */
static int pcep_ctrl_halt_cb(struct frr_pthread *fpt, void **res);
static void pcep_refine_path_event_cb(struct event *thread);

/* Internal Functions Called From Controller Thread */
static void pcep_thread_finish_event_handler(struct event *thread);

/* Controller Thread Timer Handler */
static int schedule_thread_timer(struct ctrl_state *ctrl_state, int pcc_id,
				 enum pcep_ctrl_timer_type timer_type,
				 enum pcep_ctrl_timeout_type timeout_type,
				 uint32_t delay, void *payload,
				 struct event **thread);
static int schedule_thread_timer_with_cb(
	struct ctrl_state *ctrl_state, int pcc_id,
	enum pcep_ctrl_timer_type timer_type,
	enum pcep_ctrl_timeout_type timeout_type, uint32_t delay, void *payload,
	struct event **thread, pcep_ctrl_thread_callback timer_cb);
static void pcep_thread_timer_handler(struct event *thread);

/* Controller Thread Socket read/write Handler */
static int schedule_thread_socket(struct ctrl_state *ctrl_state, int pcc_id,
				  enum pcep_ctrl_socket_type type, bool is_read,
				  void *payload, int fd, struct event **thread,
				  pcep_ctrl_thread_callback cb);

/* Controller Thread Event Handler */
static int send_to_thread(struct ctrl_state *ctrl_state, int pcc_id,
			  enum pcep_ctrl_event_type type, uint32_t sub_type,
			  void *payload);
static int send_to_thread_with_cb(struct ctrl_state *ctrl_state, int pcc_id,
				  enum pcep_ctrl_event_type type,
				  uint32_t sub_type, void *payload,
				  pcep_ctrl_thread_callback event_cb);
static void pcep_thread_event_handler(struct event *thread);
static int pcep_thread_event_update_pcc_options(struct ctrl_state *ctrl_state,
						struct pcc_opts *opts);
static int pcep_thread_event_update_pce_options(struct ctrl_state *ctrl_state,
						int pcc_id,
						struct pce_opts *opts);
static int pcep_thread_event_remove_pcc_by_id(struct ctrl_state *ctrl_state,
					      int pcc_id);
static int pcep_thread_event_remove_pcc_all(struct ctrl_state *ctrl_state);
static int pcep_thread_event_remove_pcc(struct ctrl_state *ctrl_state,
					struct pce_opts *pce_opts);
static int pcep_thread_event_sync_path(struct ctrl_state *ctrl_state,
				       int pcc_id, struct path *path);
static int pcep_thread_event_sync_done(struct ctrl_state *ctrl_state,
				       int pcc_id);
static int pcep_thread_event_pathd_event(struct ctrl_state *ctrl_state,
					 enum pcep_pathd_event_type type,
					 struct path *path);
static void
pcep_thread_path_refined_event(struct ctrl_state *ctrl_state,
			       struct pcep_refine_path_event_data *data);

/* Main Thread Event Handler */
static int send_to_main(struct ctrl_state *ctrl_state, int pcc_id,
			enum pcep_main_event_type type, void *payload);
static void pcep_main_event_handler(struct event *thread);

/* Helper functions */
static void set_ctrl_state(struct frr_pthread *fpt,
			   struct ctrl_state *ctrl_state);
static struct ctrl_state *get_ctrl_state(struct frr_pthread *fpt);
int get_next_id(struct ctrl_state *ctrl_state);
int set_pcc_state(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state);
void remove_pcc_state(struct ctrl_state *ctrl_state,
		      struct pcc_state *pcc_state);
static uint32_t backoff_delay(uint32_t max, uint32_t base, uint32_t attempt);
static const char *timer_type_name(enum pcep_ctrl_timer_type type);
static const char *timeout_type_name(enum pcep_ctrl_timeout_type type);


/* ------------ API Functions Called from Main Thread ------------ */

int pcep_ctrl_initialize(struct event_loop *main_thread,
			 struct frr_pthread **fpt,
			 pcep_main_event_handler_t event_handler)
{
	assert(fpt != NULL);

	int ret = 0;
	struct ctrl_state *ctrl_state;
	struct frr_pthread_attr attr = {
		.start = frr_pthread_attr_default.start,
		.stop = pcep_ctrl_halt_cb,
	};

	PCEP_DEBUG("Initializing pcep module controller");

	/* Create and start the FRR pthread */
	*fpt = frr_pthread_new(&attr, "PCEP thread", "pcep_controller");
	if (*fpt == NULL) {
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

	/* Initialize the thread state */
	ctrl_state = XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state));
	ctrl_state->main = main_thread;
	ctrl_state->self = (*fpt)->master;
	ctrl_state->main_event_handler = event_handler;
	ctrl_state->pcc_count = 0;
	ctrl_state->pcc_last_id = 0;
	ctrl_state->pcc_opts =
		XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state->pcc_opts));
	/* Default to no PCC address defined */
	ctrl_state->pcc_opts->addr.ipa_type = IPADDR_NONE;
	ctrl_state->pcc_opts->port = PCEP_DEFAULT_PORT;

	/* Keep the state reference for events */
	set_ctrl_state(*fpt, ctrl_state);

	return ret;
}

int pcep_ctrl_finalize(struct frr_pthread **fpt)
{
	assert(fpt != NULL);

	int ret = 0;

	PCEP_DEBUG("Finalizing pcep module controller");

	if (*fpt != NULL) {
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

int pcep_ctrl_update_pce_options(struct frr_pthread *fpt, struct pce_opts *opts)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_UPDATE_PCE_OPTS, 0, opts);
}

int pcep_ctrl_remove_pcc(struct frr_pthread *fpt, struct pce_opts *pce_opts)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_REMOVE_PCC, 0, pce_opts);
}

int pcep_ctrl_reset_pcc_session(struct frr_pthread *fpt, char *pce_name)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_RESET_PCC_SESSION, 0, pce_name);
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
	struct counters_group *counters = NULL;
	struct pcc_state *pcc_state;
	pcc_state = pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
	if (pcc_state) {
		counters = pcep_lib_copy_counters(pcc_state->sess);
	}
	return counters;
}

pcep_session *pcep_ctrl_get_pcep_session(struct frr_pthread *fpt, int pcc_id)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	struct pcc_state *pcc_state;
	pcep_session *session = NULL;

	pcc_state = pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
	if (pcc_state) {
		session = pcep_lib_copy_pcep_session(pcc_state->sess);
	}
	return session;
}

struct pcep_pcc_info *pcep_ctrl_get_pcc_info(struct frr_pthread *fpt,
					     const char *pce_name)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	struct pcep_pcc_info *pcc_info = XCALLOC(MTYPE_PCEP, sizeof(*pcc_info));
	if( pcc_info && ctrl_state){
		strlcpy(pcc_info->pce_name, pce_name, sizeof(pcc_info->pce_name));
		pcep_pcc_copy_pcc_info(ctrl_state->pcc, pcc_info);
	}

	return pcc_info;
}

int pcep_ctrl_send_report(struct frr_pthread *fpt, int pcc_id,
			  struct path *path, bool is_stable)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, pcc_id, EV_SEND_REPORT, is_stable,
			      path);
}


int pcep_ctrl_send_error(struct frr_pthread *fpt, int pcc_id,
			 struct pcep_error *error)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, pcc_id, EV_SEND_ERROR, 0, error);
}


/* ------------ Internal Functions Called from Main Thread ------------ */

int pcep_ctrl_halt_cb(struct frr_pthread *fpt, void **res)
{
	event_add_event(fpt->master, pcep_thread_finish_event_handler,
			(void *)fpt, 0, NULL);
	pthread_join(fpt->thread, res);

	return 0;
}

void pcep_refine_path_event_cb(struct event *thread)
{
	struct pcep_refine_path_event_data *data = EVENT_ARG(thread);
	assert(data != NULL);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	struct path *path = data->path;
	assert(path != NULL);
	int pcc_id = data->pcc_id;


	path_pcep_refine_path(path);
	send_to_thread(ctrl_state, pcc_id, EV_PATH_REFINED, 0, data);
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

void pcep_thread_initiate_path(struct ctrl_state *ctrl_state, int pcc_id,
			       struct path *path)
{
	send_to_main(ctrl_state, pcc_id, PCEP_MAIN_EVENT_INITIATE_CANDIDATE,
		     path);
}

void pcep_thread_remove_candidate_path_segments(struct ctrl_state *ctrl_state,
						struct pcc_state *pcc_state)
{
	if (!pcc_state)
		return;
	/* Will be deleted when the event is handled */
	char *originator = XSTRDUP(MTYPE_PCEP, pcc_state->originator);
	PCEP_DEBUG("schedule candidate path segments removal for originator %s",
		   originator);
	send_to_main(ctrl_state, pcep_pcc_get_pcc_id(pcc_state),
		     PCEP_MAIN_EVENT_REMOVE_CANDIDATE_LSP, originator);
}

void pcep_thread_schedule_sync_best_pce(struct ctrl_state *ctrl_state,
					int pcc_id, int delay,
					struct event **thread)
{

	schedule_thread_timer(ctrl_state, pcc_id, TM_CALCULATE_BEST_PCE,
			      TO_UNDEFINED, delay, NULL, thread);
}

void pcep_thread_cancel_timer(struct event **thread)
{
	if (thread == NULL || *thread == NULL) {
		return;
	}

	struct pcep_ctrl_timer_data *data = EVENT_ARG(*thread);
	PCEP_DEBUG("Timer %s / %s canceled", timer_type_name(data->timer_type),
		   timeout_type_name(data->timeout_type));
	if (data != NULL) {
		XFREE(MTYPE_PCEP, data);
	}

	if ((*thread)->master->owner == pthread_self()) {
		event_cancel(thread);
	} else {
		event_cancel_async((*thread)->master, thread, NULL);
	}
}

void pcep_thread_schedule_reconnect(struct ctrl_state *ctrl_state, int pcc_id,
				    int retry_count, struct event **thread)
{
	uint32_t delay = backoff_delay(MAX_RECONNECT_DELAY, 1, retry_count);
	PCEP_DEBUG("Schedule RECONNECT_PCC for %us (retry %u)", delay,
		   retry_count);
	schedule_thread_timer(ctrl_state, pcc_id, TM_RECONNECT_PCC,
			      TO_UNDEFINED, delay, NULL, thread);
}

void pcep_thread_schedule_timeout(struct ctrl_state *ctrl_state, int pcc_id,
				  enum pcep_ctrl_timeout_type timeout_type,
				  uint32_t delay, void *param,
				  struct event **thread)
{
	assert(timeout_type > TO_UNDEFINED);
	assert(timeout_type < TO_MAX);
	PCEP_DEBUG("Schedule timeout %s for %us",
		   timeout_type_name(timeout_type), delay);
	schedule_thread_timer(ctrl_state, pcc_id, TM_TIMEOUT, timeout_type,
			      delay, param, thread);
}

void pcep_thread_schedule_pceplib_timer(struct ctrl_state *ctrl_state,
					int delay, void *payload,
					struct event **thread,
					pcep_ctrl_thread_callback timer_cb)
{
	PCEP_DEBUG("Schedule PCEPLIB_TIMER for %us", delay);
	schedule_thread_timer_with_cb(ctrl_state, 0, TM_PCEPLIB_TIMER,
				      TO_UNDEFINED, delay, payload, thread,
				      timer_cb);
}

void pcep_thread_schedule_session_timeout(struct ctrl_state *ctrl_state,
					  int pcc_id, int delay,
					  struct event **thread)
{
	PCEP_DEBUG("Schedule session_timeout interval for %us", delay);
	schedule_thread_timer(ctrl_state, pcc_id, TM_SESSION_TIMEOUT_PCC,
			      TO_UNDEFINED, delay, NULL, thread);
}

int pcep_thread_pcc_count(struct ctrl_state *ctrl_state)
{
	if (ctrl_state == NULL) {
		return 0;
	}

	return ctrl_state->pcc_count;
}

int pcep_thread_refine_path(struct ctrl_state *ctrl_state, int pcc_id,
			    pcep_refine_callback_t cb, struct path *path,
			    void *payload)
{
	struct pcep_refine_path_event_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->path = path;
	data->pcc_id = pcc_id;
	data->continue_lsp_update_handler = cb;
	data->payload = payload;

	event_add_event(ctrl_state->main, pcep_refine_path_event_cb,
			(void *)data, 0, NULL);
	return 0;
}

void pcep_thread_path_refined_event(struct ctrl_state *ctrl_state,
				    struct pcep_refine_path_event_data *data)
{
	assert(data != NULL);
	int pcc_id = data->pcc_id;
	pcep_refine_callback_t continue_lsp_update_handler = data->continue_lsp_update_handler;
	assert(continue_lsp_update_handler != NULL);
	struct path *path = data->path;
	void *payload = data->payload;
	struct pcc_state *pcc_state = NULL;
	XFREE(MTYPE_PCEP, data);

	pcc_state = pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
	continue_lsp_update_handler(ctrl_state, pcc_state, path, payload);
}


/* ------------ Internal Functions Called From Controller Thread ------------ */

void pcep_thread_finish_event_handler(struct event *thread)
{
	int i;
	struct frr_pthread *fpt = EVENT_ARG(thread);
	struct ctrl_state *ctrl_state = fpt->data;

	assert(ctrl_state != NULL);

	for (i = 0; i < MAX_PCC; i++) {
		if (ctrl_state->pcc[i]) {
			pcep_pcc_finalize(ctrl_state, ctrl_state->pcc[i]);
			ctrl_state->pcc[i] = NULL;
		}
	}

	XFREE(MTYPE_PCEP, ctrl_state->pcc_opts);
	XFREE(MTYPE_PCEP, ctrl_state);
	fpt->data = NULL;

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
}

/* ------------ Controller Thread Timer Handler ------------ */

int schedule_thread_timer_with_cb(struct ctrl_state *ctrl_state, int pcc_id,
				  enum pcep_ctrl_timer_type timer_type,
				  enum pcep_ctrl_timeout_type timeout_type,
				  uint32_t delay, void *payload,
				  struct event **thread,
				  pcep_ctrl_thread_callback timer_cb)
{
	assert(thread != NULL);

	struct pcep_ctrl_timer_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->timer_type = timer_type;
	data->timeout_type = timeout_type;
	data->pcc_id = pcc_id;
	data->payload = payload;

	event_add_timer(ctrl_state->self, timer_cb, (void *)data, delay,
			thread);

	return 0;
}

int schedule_thread_timer(struct ctrl_state *ctrl_state, int pcc_id,
			  enum pcep_ctrl_timer_type timer_type,
			  enum pcep_ctrl_timeout_type timeout_type,
			  uint32_t delay, void *payload, struct event **thread)
{
	return schedule_thread_timer_with_cb(ctrl_state, pcc_id, timer_type,
					     timeout_type, delay, payload,
					     thread, pcep_thread_timer_handler);
}

void pcep_thread_timer_handler(struct event *thread)
{
	/* data unpacking */
	struct pcep_ctrl_timer_data *data = EVENT_ARG(thread);
	assert(data != NULL);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	assert(ctrl_state != NULL);
	enum pcep_ctrl_timer_type timer_type = data->timer_type;
	enum pcep_ctrl_timeout_type timeout_type = data->timeout_type;
	int pcc_id = data->pcc_id;
	void *param = data->payload;
	XFREE(MTYPE_PCEP, data);

	struct pcc_state *pcc_state = NULL;

	switch (timer_type) {
	case TM_RECONNECT_PCC:
		pcc_state = pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
		if (!pcc_state)
			return;
		pcep_pcc_reconnect(ctrl_state, pcc_state);
		break;
	case TM_TIMEOUT:
		pcc_state = pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
		if (!pcc_state)
			return;
		pcep_pcc_timeout_handler(ctrl_state, pcc_state, timeout_type,
					 param);
		break;
	case TM_CALCULATE_BEST_PCE:
		/* Previous best disconnect so new best should be synced */
		pcep_pcc_timer_update_best_pce(ctrl_state, pcc_id);
		break;
	case TM_SESSION_TIMEOUT_PCC:
		pcc_state = pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
		pcep_thread_remove_candidate_path_segments(ctrl_state,
							   pcc_state);
		break;
	case TM_PCEPLIB_TIMER:
	case TM_UNDEFINED:
	case TM_MAX:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unknown controller timer triggered: %u", timer_type);
		break;
	}
}

void pcep_thread_pcep_event(struct event *thread)
{
	struct pcep_ctrl_event_data *data = EVENT_ARG(thread);
	assert(data != NULL);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	pcep_event *event = data->payload;
	XFREE(MTYPE_PCEP, data);
	int i;

	for (i = 0; i < MAX_PCC; i++) {
		if (ctrl_state->pcc[i]) {
			struct pcc_state *pcc_state = ctrl_state->pcc[i];
			if (pcc_state->sess != event->session)
				continue;
			pcep_pcc_pcep_event_handler(ctrl_state, pcc_state,
						    event);
			break;
		}
	}
	destroy_pcep_event(event);
}

/* ------------ Controller Thread Socket Functions ------------ */

int schedule_thread_socket(struct ctrl_state *ctrl_state, int pcc_id,
			   enum pcep_ctrl_socket_type type, bool is_read,
			   void *payload, int fd, struct event **thread,
			   pcep_ctrl_thread_callback socket_cb)
{
	assert(thread != NULL);

	struct pcep_ctrl_socket_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->type = type;
	data->is_read = is_read;
	data->fd = fd;
	data->pcc_id = pcc_id;
	data->payload = payload;

	if (is_read) {
		event_add_read(ctrl_state->self, socket_cb, (void *)data, fd,
			       thread);
	} else {
		event_add_write(ctrl_state->self, socket_cb, (void *)data, fd,
				thread);
	}

	return 0;
}

int pcep_thread_socket_write(void *fpt, void **thread, int fd, void *payload,
			     pcep_ctrl_thread_callback socket_cb)
{
	struct ctrl_state *ctrl_state = ((struct frr_pthread *)fpt)->data;

	return schedule_thread_socket(ctrl_state, 0, SOCK_PCEPLIB, false,
				      payload, fd, (struct event **)thread,
				      socket_cb);
}

int pcep_thread_socket_read(void *fpt, void **thread, int fd, void *payload,
			    pcep_ctrl_thread_callback socket_cb)
{
	struct ctrl_state *ctrl_state = ((struct frr_pthread *)fpt)->data;

	return schedule_thread_socket(ctrl_state, 0, SOCK_PCEPLIB, true,
				      payload, fd, (struct event **)thread,
				      socket_cb);
}

int pcep_thread_send_ctrl_event(void *fpt, void *payload,
				pcep_ctrl_thread_callback cb)
{
	struct ctrl_state *ctrl_state = ((struct frr_pthread *)fpt)->data;

	return send_to_thread_with_cb(ctrl_state, 0, EV_PCEPLIB_EVENT, 0,
				      payload, cb);
}

/* ------------ Controller Thread Event Handler ------------ */

int send_to_thread(struct ctrl_state *ctrl_state, int pcc_id,
		   enum pcep_ctrl_event_type type, uint32_t sub_type,
		   void *payload)
{
	return send_to_thread_with_cb(ctrl_state, pcc_id, type, sub_type,
				      payload, pcep_thread_event_handler);
}

int send_to_thread_with_cb(struct ctrl_state *ctrl_state, int pcc_id,
			   enum pcep_ctrl_event_type type, uint32_t sub_type,
			   void *payload, pcep_ctrl_thread_callback event_cb)
{
	struct pcep_ctrl_event_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->type = type;
	data->sub_type = sub_type;
	data->pcc_id = pcc_id;
	data->payload = payload;

	event_add_event(ctrl_state->self, event_cb, (void *)data, 0, NULL);

	return 0;
}

void pcep_thread_event_handler(struct event *thread)
{
	/* data unpacking */
	struct pcep_ctrl_event_data *data = EVENT_ARG(thread);
	assert(data != NULL);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	assert(ctrl_state != NULL);
	enum pcep_ctrl_event_type type = data->type;
	uint32_t sub_type = data->sub_type;
	int pcc_id = data->pcc_id;
	void *payload = data->payload;
	XFREE(MTYPE_PCEP, data);

	/* Possible sub-type values */
	enum pcep_pathd_event_type path_event_type = PCEP_PATH_UNDEFINED;

	/* Possible payload values, maybe an union would be better... */
	struct path *path = NULL;
	struct pcc_opts *pcc_opts = NULL;
	struct pce_opts *pce_opts = NULL;
	struct pcc_state *pcc_state = NULL;
	struct pcep_refine_path_event_data *refine_data = NULL;

	struct path *path_copy = NULL;
	struct pcep_error *error = NULL;

	switch (type) {
	case EV_UPDATE_PCC_OPTS:
		assert(payload != NULL);
		pcc_opts = (struct pcc_opts *)payload;
		pcep_thread_event_update_pcc_options(ctrl_state, pcc_opts);
		break;
	case EV_UPDATE_PCE_OPTS:
		assert(payload != NULL);
		pce_opts = (struct pce_opts *)payload;
		pcep_thread_event_update_pce_options(ctrl_state, pcc_id,
						     pce_opts);
		break;
	case EV_REMOVE_PCC:
		pce_opts = (struct pce_opts *)payload;
		if (pcep_thread_event_remove_pcc(ctrl_state, pce_opts) == 0)
			pcep_pcc_multi_pce_remove_pcc(ctrl_state,
						      ctrl_state->pcc);
		break;
	case EV_PATHD_EVENT:
		assert(payload != NULL);
		path_event_type = (enum pcep_pathd_event_type)sub_type;
		path = (struct path *)payload;
		pcep_thread_event_pathd_event(ctrl_state, path_event_type,
					      path);
		break;
	case EV_SYNC_PATH:
		assert(payload != NULL);
		path = (struct path *)payload;
		pcep_pcc_multi_pce_sync_path(ctrl_state, pcc_id,
					     ctrl_state->pcc);
		pcep_thread_event_sync_path(ctrl_state, pcc_id, path);
		break;
	case EV_SYNC_DONE:
		pcep_thread_event_sync_done(ctrl_state, pcc_id);
		break;
	case EV_RESET_PCC_SESSION:
		pcc_state = pcep_pcc_get_pcc_by_name(ctrl_state->pcc,
						     (const char *)payload);
		if (pcc_state) {
			pcep_pcc_disable(ctrl_state, pcc_state);
			pcep_pcc_enable(ctrl_state, pcc_state);
		} else {
			flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
				  "Cannot reset state for PCE: %s",
				  (const char *)payload);
		}
		break;
	case EV_SEND_REPORT:
		assert(payload != NULL);
		path = (struct path *)payload;
		if (pcc_id == 0) {
			for (int i = 0; i < MAX_PCC; i++) {
				if (ctrl_state->pcc[i]) {
					path_copy = pcep_copy_path(path);
					pcep_pcc_send_report(
						ctrl_state, ctrl_state->pcc[i],
						path_copy, (bool)sub_type);
				}
			}
		} else {
			pcc_state =
				pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
			pcep_pcc_send_report(ctrl_state, pcc_state, path,
					     (bool)sub_type);
		}
		break;
	case EV_PATH_REFINED:
		assert(payload != NULL);
		refine_data = (struct pcep_refine_path_event_data *)payload;
		pcep_thread_path_refined_event(ctrl_state, refine_data);
		break;
	case EV_SEND_ERROR:
		assert(payload != NULL);
		error = (struct pcep_error *)payload;
		pcc_state = pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
		pcep_pcc_send_error(ctrl_state, pcc_state, error,
				    (bool)sub_type);
		break;
	case EV_PCEPLIB_EVENT:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unexpected event received in controller thread: %u",
			  type);
		break;
	}
}

int pcep_thread_event_update_pcc_options(struct ctrl_state *ctrl_state,
					 struct pcc_opts *opts)
{
	assert(opts != NULL);
	if (ctrl_state->pcc_opts != NULL) {
		XFREE(MTYPE_PCEP, ctrl_state->pcc_opts);
	}
	ctrl_state->pcc_opts = opts;
	return 0;
}

int pcep_thread_event_update_pce_options(struct ctrl_state *ctrl_state,
					 int pcc_id, struct pce_opts *pce_opts)
{
	if (!pce_opts || !ctrl_state) {
		return 0;
	}
	struct pcc_state *pcc_state;
	struct pcc_opts *pcc_opts;

	int current_pcc_id =
		pcep_pcc_get_pcc_id_by_ip_port(ctrl_state->pcc, pce_opts);
	if (current_pcc_id) {
		pcc_state =
			pcep_pcc_get_pcc_by_id(ctrl_state->pcc, current_pcc_id);
	} else {
		pcc_state = pcep_pcc_initialize(ctrl_state,
						get_next_id(ctrl_state));
		if (set_pcc_state(ctrl_state, pcc_state)) {
			XFREE(MTYPE_PCEP, pcc_state);
			return 0;
		}
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

int pcep_thread_event_remove_pcc_by_id(struct ctrl_state *ctrl_state,
				       int pcc_id)
{
	if (pcc_id) {
		struct pcc_state *pcc_state =
			pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
		if (pcc_state) {
			remove_pcc_state(ctrl_state, pcc_state);
			pcep_pcc_finalize(ctrl_state, pcc_state);
		}
	}
	return 0;
}

int pcep_thread_event_remove_pcc_all(struct ctrl_state *ctrl_state)
{
	assert(ctrl_state != NULL);

	for (int i = 0; i < MAX_PCC; i++) {
		pcep_thread_event_remove_pcc_by_id(
			ctrl_state,
			pcep_pcc_get_pcc_id_by_idx(ctrl_state->pcc, i));
	}
	return 0;
}

int pcep_thread_event_remove_pcc(struct ctrl_state *ctrl_state,
				 struct pce_opts *pce_opts)
{
	assert(ctrl_state != NULL);

	if (pce_opts) {
		int pcc_id = pcep_pcc_get_pcc_id_by_ip_port(ctrl_state->pcc,
							    pce_opts);
		if (pcc_id) {
			pcep_thread_event_remove_pcc_by_id(ctrl_state, pcc_id);
		} else {
			return -1;
		}
		XFREE(MTYPE_PCEP, pce_opts);
	} else {
		pcep_thread_event_remove_pcc_all(ctrl_state);
	}

	return 0;
}

int pcep_thread_event_sync_path(struct ctrl_state *ctrl_state, int pcc_id,
				struct path *path)
{
	struct pcc_state *pcc_state =
		pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
	pcep_pcc_sync_path(ctrl_state, pcc_state, path);
	pcep_free_path(path);
	return 0;
}

int pcep_thread_event_sync_done(struct ctrl_state *ctrl_state, int pcc_id)
{
	struct pcc_state *pcc_state =
		pcep_pcc_get_pcc_by_id(ctrl_state->pcc, pcc_id);
	pcep_pcc_sync_done(ctrl_state, pcc_state);
	return 0;
}

int pcep_thread_event_pathd_event(struct ctrl_state *ctrl_state,
				  enum pcep_pathd_event_type type,
				  struct path *path)
{
	int i;

	for (i = 0; i < MAX_PCC; i++) {
		if (ctrl_state->pcc[i]) {
			struct pcc_state *pcc_state = ctrl_state->pcc[i];
			pcep_pcc_pathd_event_handler(ctrl_state, pcc_state,
						     type, path);
		}
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

	event_add_event(ctrl_state->main, pcep_main_event_handler, (void *)data,
			0, NULL);
	return 0;
}

void pcep_main_event_handler(struct event *thread)
{
	/* data unpacking */
	struct pcep_main_event_data *data = EVENT_ARG(thread);
	assert(data != NULL);
	pcep_main_event_handler_t handler = data->handler;
	enum pcep_main_event_type type = data->type;
	int pcc_id = data->pcc_id;
	void *payload = data->payload;
	XFREE(MTYPE_PCEP, data);

	handler(type, pcc_id, payload);
}


/* ------------ Helper functions ------------ */

void set_ctrl_state(struct frr_pthread *fpt, struct ctrl_state *ctrl_state)
{
	assert(fpt != NULL);
	fpt->data = ctrl_state;
}

struct ctrl_state *get_ctrl_state(struct frr_pthread *fpt)
{
	assert(fpt != NULL);
	assert(fpt->data != NULL);

	struct ctrl_state *ctrl_state;
	ctrl_state = (struct ctrl_state *)fpt->data;
	assert(ctrl_state != NULL);
	return ctrl_state;
}

int get_next_id(struct ctrl_state *ctrl_state)
{
	return ++ctrl_state->pcc_last_id;
}

int set_pcc_state(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	assert(ctrl_state != NULL);
	assert(pcep_pcc_get_pcc_id(pcc_state) != 0);

	int current_pcc_idx = pcep_pcc_get_free_pcc_idx(ctrl_state->pcc);
	if (current_pcc_idx >= 0) {
		ctrl_state->pcc[current_pcc_idx] = pcc_state;
		ctrl_state->pcc_count++;
		PCEP_DEBUG("added pce pcc_id (%d) idx (%d)",
			   pcep_pcc_get_pcc_id(pcc_state), current_pcc_idx);
		return 0;
	} else {
		PCEP_DEBUG("Max number of pce ");
		return 1;
	}
}

void remove_pcc_state(struct ctrl_state *ctrl_state,
		      struct pcc_state *pcc_state)
{
	assert(ctrl_state != NULL);
	assert(pcep_pcc_get_pcc_id(pcc_state) != 0);

	int idx = 0;
	idx = pcep_pcc_get_pcc_idx_by_id(ctrl_state->pcc,
					 pcep_pcc_get_pcc_id(pcc_state));
	if (idx != -1) {
		ctrl_state->pcc[idx] = NULL;
		ctrl_state->pcc_count--;
		PCEP_DEBUG("removed pce pcc_id (%d)",
			   pcep_pcc_get_pcc_id(pcc_state));
	}
}

uint32_t backoff_delay(uint32_t max, uint32_t base, uint32_t retry_count)
{
	uint32_t a = MIN(max, base * (1 << retry_count));
	uint64_t r = frr_weak_random(), m = RAND_MAX;
	uint32_t b = (a / 2) + (r * (a / 2)) / m;
	return b;
}

const char *timer_type_name(enum pcep_ctrl_timer_type type)
{
	switch (type) {
	case TM_UNDEFINED:
		return "UNDEFINED";
	case TM_RECONNECT_PCC:
		return "RECONNECT_PCC";
	case TM_PCEPLIB_TIMER:
		return "PCEPLIB_TIMER";
	case TM_TIMEOUT:
		return "TIMEOUT";
	case TM_CALCULATE_BEST_PCE:
		return "BEST_PCE";
	case TM_SESSION_TIMEOUT_PCC:
		return "TIMEOUT_PCC";
	case TM_MAX:
		return "UNKNOWN";
	}

	assert(!"Reached end of function where we did not expect to");
}

const char *timeout_type_name(enum pcep_ctrl_timeout_type type)
{
	switch (type) {
	case TO_UNDEFINED:
		return "UNDEFINED";
	case TO_COMPUTATION_REQUEST:
		return "COMPUTATION_REQUEST";
	case TO_MAX:
		return "UNKNOWN";
	}

	assert(!"Reached end of function where we did not expect to");
}
