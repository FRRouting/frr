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

#include "pathd/path_errors.h"
#include "pathd/path_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"

#define PCEP_DEFAULT_PORT 4189
#define POLL_INTERVAL 1
#define CMP_RETURN(A, B) if (A != B) return (A < B) ? -1 : 1

DEFINE_MTYPE(PATHD, PCEP, "PCEP module")

/*
 * Globals.
 */
static pcep_glob_t pcep_glob_space = { .dbg = {0, "pathd module: pcep"} };
pcep_glob_t *pcep_g = &pcep_glob_space;

/* PCC Functions */
static pcc_state_t* pcep_pcc_initialize(ctrl_state_t *ctrl_state, int index);
static void pcep_pcc_finalize(ctrl_state_t *ctrl_state, pcc_state_t *pcc_state);
static int pcep_pcc_update(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state,
			   pcc_opts_t *opts);
static int pcep_pcc_enable(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state);
static int pcep_pcc_disable(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state);
static void pcep_pcc_handle_pcep_event(ctrl_state_t *ctrl_state,
				       pcc_state_t * pcc_state,
				       pcep_event *event);
static void pcep_pcc_handle_message(ctrl_state_t *ctrl_state,
				    pcc_state_t * pcc_state, pcep_message *msg);
static void pcep_pcc_lsp_update(ctrl_state_t *ctrl_state,
				pcc_state_t * pcc_state, pcep_message *msg);
static void pcep_pcc_lsp_initiate(ctrl_state_t *ctrl_state,
				  pcc_state_t * pcc_state, pcep_message *msg);
static void pcep_pcc_send(ctrl_state_t *ctrl_state,
			  pcc_state_t * pcc_state, pcep_message *msg);
static void pcep_pcc_schedule_reconnect(ctrl_state_t *ctrl_state,
                                        pcc_state_t *pcc_state);
static void pcep_pcc_lookup_plspid(pcc_state_t *pcc_state, path_t *path);
static void pcep_pcc_lookup_nbkey(pcc_state_t *pcc_state, path_t * path);

/* Controller Functions Called from Main */
static int pcep_controller_initialize(void);
static int pcep_controller_finalize(void);
static int pcep_controller_pcc_update_options(int index, pcc_opts_t *opts);
static void pcep_controller_pcc_disconnect(int index);
static void pcep_controller_pcc_report(int index, path_t *path);
static int pcep_halt_cb(struct frr_pthread *fpt, void **res);

/* Controller Functions Called From Thread */
static void pcep_thread_start_sync(ctrl_state_t *ctrl_state,
                                   pcc_state_t * pcc_state);
static void pcep_thread_update_path(ctrl_state_t *ctrl_state,
                                    pcc_state_t *pcc_state, path_t *path);
static void pcep_thread_schedule_poll(ctrl_state_t *ctrl_state);
static int pcep_thread_init_event(struct thread *thread);
static int pcep_thread_finish_event(struct thread *thread);
static int pcep_thread_poll_timer(struct thread *thread);
static int pcep_thread_pcc_update_options_event(struct thread *thread);
static int pcep_thread_pcc_disconnect_event(struct thread *thread);
static int pcep_thread_pcc_report_event(struct thread *thread);
static int pcep_thread_pcc_cb_event(struct thread *thread);

/* Main Thread Functions */
static int pcep_main_start_sync_event(struct thread *thread);
static int pcep_main_start_sync_event_cb(path_t *path, void *arg);
static int pcep_main_update_path_event(struct thread *thread);

/* CLI Functions */
static int pcep_cli_debug_config_write(struct vty *vty);
static int pcep_cli_debug_set_all(uint32_t flags, bool set);
static void pcep_cli_init(void);

/* Module Functions */
static int pcep_module_finish(void);
static int pcep_module_late_init(struct thread_master *tm);
static int pcep_module_init(void);

/* Data Structure Functions */
static int plspid_map_cmp(const plspid_map_t *a, const plspid_map_t *b);
static uint32_t plspid_map_hash(const plspid_map_t *e);
static int nbkey_map_cmp(const nbkey_map_t *a, const nbkey_map_t *b);
static uint32_t nbkey_map_hash(const nbkey_map_t *e);

DECLARE_HASH(plspid_map, plspid_map_t, mi, plspid_map_cmp, plspid_map_hash)
DECLARE_HASH(nbkey_map, nbkey_map_t, mi, nbkey_map_cmp, nbkey_map_hash)


/* ------------ Data Structure Functions ------------ */

static int plspid_map_cmp(const plspid_map_t *a, const plspid_map_t *b)
{
	CMP_RETURN(a->nbkey.color, b->nbkey.color);
	int cmp = ipaddr_cmp(&a->nbkey.endpoint, &b->nbkey.endpoint);
	if (cmp != 0) return cmp;
	CMP_RETURN(a->nbkey.preference, b->nbkey.preference);
	return 0;
}

static uint32_t plspid_map_hash(const plspid_map_t *e)
{
	uint32_t hash;
	hash = jhash_2words(e->nbkey.color, e->nbkey.preference, 0x55aa5a5a);
	switch (e->nbkey.endpoint.ipa_type) {
		case IPADDR_V4:
			return jhash(&e->nbkey.endpoint.ipaddr_v4,
			             sizeof(e->nbkey.endpoint.ipaddr_v4), hash);
		case IPADDR_V6:
			return jhash(&e->nbkey.endpoint.ipaddr_v6,
			             sizeof(e->nbkey.endpoint.ipaddr_v6), hash);
		default:
			return hash;
	}
}

static int nbkey_map_cmp(const nbkey_map_t *a, const nbkey_map_t *b)
{
	CMP_RETURN(a->plspid, b->plspid);
	return 0;
}

static uint32_t nbkey_map_hash(const nbkey_map_t *e)
{
	return e->plspid;
}


/* ------------ PCC Functions ------------ */

pcc_state_t* pcep_pcc_initialize(ctrl_state_t *ctrl_state, int index)
{
	assert(NULL != ctrl_state);

	pcc_state_t *pcc_state = XCALLOC(MTYPE_PCEP, sizeof(*pcc_state));

	PCEP_DEBUG("PCC initializing...");

	pcc_state->id = index;
	pcc_state->status = DISCONNECTED;
	pcc_state->next_plspid = 1;

	return pcc_state;
}

void pcep_pcc_finalize(ctrl_state_t *ctrl_state, pcc_state_t *pcc_state)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	PCEP_DEBUG("PCC finalizing...");

	pcep_pcc_disable(ctrl_state, pcc_state);

	if (NULL != pcc_state->opts) {
		XFREE(MTYPE_PCEP, pcc_state->opts);
		pcc_state->opts = NULL;
	}
	XFREE(MTYPE_PCEP, pcc_state);
}

int pcep_pcc_update(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state, pcc_opts_t *opts)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	int ret = 0;

	//TODO: check if the options changed ?

	if ((ret = pcep_pcc_disable(ctrl_state, pcc_state))) return ret;

	if (NULL != pcc_state->opts) {
		XFREE(MTYPE_PCEP, pcc_state->opts);
		pcc_state->opts = NULL;
	}

	pcc_state->opts = opts;

	return pcep_pcc_enable(ctrl_state, pcc_state);
}

int pcep_pcc_enable(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state)
{
	assert(DISCONNECTED == pcc_state->status);

	int ret = 0;

	PCEP_DEBUG("PCC connecting to %pI4:%d",
	           &pcc_state->opts->addr, pcc_state->opts->port);

	if ((ret = pcep_lib_connect(pcc_state))) {
		flog_err(EC_PATH_PCEP_LIB_CONNECT,
			 "failed to connect to PCE %pI4:%d (%d)",
			 &pcc_state->opts->addr, pcc_state->opts->port, ret);
		pcep_pcc_schedule_reconnect(ctrl_state, pcc_state);
		return ret;
	}

	pcc_state->status = CONNECTING;

	return ret;
}

int pcep_pcc_disable(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	switch (pcc_state->status) {
		case DISCONNECTED:
			return 0;
		case CONNECTING:
		case SYNCHRONIZING:
		case OPERATING:
			PCEP_DEBUG("Disconnecting PCC...");
			pcep_lib_disconnect(pcc_state);
			pcc_state->status = DISCONNECTED;
			return 0;
		default:
			return 1;
	}
}

void pcep_pcc_handle_pcep_event(ctrl_state_t *ctrl_state,
				pcc_state_t * pcc_state, pcep_event *event)
{
	PCEP_DEBUG("Received PCEP event: %s", format_pcep_event(event));
	switch (event->event_type) {
		case PCC_CONNECTED_TO_PCE:
			assert(CONNECTING == pcc_state->status);
			PCEP_DEBUG("Connection established to PCE %pI4:%i",
				   &pcc_state->opts->addr,
				   pcc_state->opts->port);
			pcc_state->status = SYNCHRONIZING;
			pcc_state->retry_count = 0;
			pcep_thread_start_sync(ctrl_state, pcc_state);
			break;
		case PCE_CLOSED_SOCKET:
		case PCE_SENT_PCEP_CLOSE:
		case PCE_DEAD_TIMER_EXPIRED:
		case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
		case PCC_PCEP_SESSION_CLOSED:
		case PCC_RCVD_INVALID_OPEN:
		case PCC_RCVD_MAX_INVALID_MSGS:
		case PCC_RCVD_MAX_UNKOWN_MSGS:
			pcep_pcc_disable(ctrl_state, pcc_state);
			pcep_pcc_schedule_reconnect(ctrl_state, pcc_state);
			break;
		case MESSAGE_RECEIVED:
			if (CONNECTING == pcc_state->status) {
				assert(PCEP_TYPE_OPEN == event->message->header->type);
				break;
			}
			assert(SYNCHRONIZING == pcc_state->status
			       || OPERATING == pcc_state->status);
			pcep_pcc_handle_message(ctrl_state, pcc_state,
						event->message);
			break;
		default:
			//TODO: Log something ???
			break;
	}
}

void pcep_pcc_handle_message(ctrl_state_t *ctrl_state,
			     pcc_state_t * pcc_state, pcep_message *msg)
{
	switch (msg->header->type) {
		case PCEP_TYPE_INITIATE:
			pcep_pcc_lsp_initiate(ctrl_state, pcc_state, msg);
			break;
		case PCEP_TYPE_UPDATE:
			pcep_pcc_lsp_update(ctrl_state, pcc_state, msg);
			break;
		default:
			break;
	}
}

void pcep_pcc_lsp_update(ctrl_state_t *ctrl_state,
			 pcc_state_t * pcc_state, pcep_message *msg)
{
	path_t *path;
	path = pcep_lib_parse_path(msg->obj_list);
	path->sender.ipa_type = IPADDR_V4;
	path->sender.ipaddr_v4 = pcc_state->opts->addr;
	pcep_pcc_lookup_nbkey(pcc_state, path);
	pcep_thread_update_path(ctrl_state, pcc_state, path);
}

void pcep_pcc_lsp_initiate(ctrl_state_t *ctrl_state,
			   pcc_state_t *pcc_state, pcep_message *msg)
{
	PCEP_DEBUG("Received LSP initiate, not supported yet");
}

void pcep_pcc_send(ctrl_state_t *ctrl_state,
		   pcc_state_t *pcc_state, pcep_message *msg)
{
	PCEP_DEBUG("Sending PCEP message: %s", format_pcep_message(msg));
	send_message(pcc_state->sess, msg, true);
}

void pcep_pcc_schedule_reconnect(ctrl_state_t *ctrl_state,
                                 pcc_state_t *pcc_state)
{
	uint32_t delay;
	event_pcc_cb_t *event;

	pcc_state->retry_count++;
	/* TODO: Add exponential backoff */
	delay = 2;

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->pcc_id = pcc_state->id;
	event->cb = pcep_pcc_enable;

	thread_add_timer(ctrl_state->self, pcep_thread_pcc_cb_event,
		         (void*)event, delay, &pcc_state->t_reconnect);
}

void pcep_pcc_lookup_plspid(pcc_state_t *pcc_state, path_t *path)
{
	plspid_map_t key, *plspid_mapping;
	nbkey_map_t *nbkey_mapping;

	if (0 != path->nbkey.color) {
		key.nbkey = path->nbkey;
		plspid_mapping = plspid_map_find(&pcc_state->plspid_map, &key);
		if (NULL == plspid_mapping) {
			plspid_mapping = XCALLOC(MTYPE_PCEP,
			                         sizeof(*plspid_mapping));
			plspid_mapping->nbkey = key.nbkey;
			plspid_mapping->plspid = pcc_state->next_plspid;
			plspid_map_add(&pcc_state->plspid_map, plspid_mapping);
			nbkey_mapping = XCALLOC(MTYPE_PCEP,
			                        sizeof(*nbkey_mapping));
			nbkey_mapping->nbkey = key.nbkey;
			nbkey_mapping->plspid = pcc_state->next_plspid;
			nbkey_map_add(&pcc_state->nbkey_map, nbkey_mapping);
			pcc_state->next_plspid++;
			//FIXME: Send some error to the PCE isntead of crashing
			assert(1048576 > pcc_state->next_plspid);

		}
		path->plsp_id = plspid_mapping->plspid;
	}
}

void pcep_pcc_lookup_nbkey(pcc_state_t *pcc_state, path_t * path)
{
	nbkey_map_t key, *mapping;
	//TODO: Should give an error to the PCE instead of crashing
	assert(0 != path->plsp_id);
	key.plspid = path->plsp_id;
	mapping = nbkey_map_find(&pcc_state->nbkey_map, &key);
	assert(NULL != mapping);
	path->nbkey = mapping->nbkey;
}

/* ------------ Controller Functions Called from Main ------------ */

int pcep_controller_initialize(void)
{
	int ret;
	ctrl_state_t *ctrl_state;
	struct frr_pthread *fpt;
	struct frr_pthread_attr attr = {
		.start = frr_pthread_attr_default.start,
		.stop = pcep_halt_cb,
	};

	assert(NULL == pcep_g->fpt);
	assert(!pcep_g->fpt);

	if (!initialize_pcc()) {
		flog_err(EC_PATH_PCEP_PCC_INIT,
			 "failed to initialize PCC");
		return 1;
	}

	/* Create and start the FRR pthread */
	fpt = frr_pthread_new(&attr, "PCEP thread", "pcep");
	if (NULL == fpt) {
		flog_err(EC_PATH_SYSTEM_CALL,
			 "failed to initialize PCEP thread");
		return 1;
	}
	ret = frr_pthread_run(fpt, NULL);
	if (ret < 0) {
		flog_err(EC_PATH_SYSTEM_CALL,
			 "failed to create PCEP thread");
		return ret;
	}
	frr_pthread_wait_running(fpt);

	/* Initialise the thread state */
	ctrl_state = XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state));
	ctrl_state->main = pcep_g->master;
	ctrl_state->self = fpt->master;
	ctrl_state->t_poll = NULL;
	ctrl_state->pcc_count = 0;

	/* Keep the state reference for events */
	fpt->data = ctrl_state;
	pcep_g->fpt = fpt;

	/* Initialize the PCEP thread */
	thread_add_event(ctrl_state->self,
			 pcep_thread_init_event,
			 (void*)ctrl_state, 0, NULL);

	return 0;
}

int pcep_controller_finalize(void)
{
	int ret = 0;

	if (NULL != pcep_g->fpt) {
		frr_pthread_stop(pcep_g->fpt, NULL);
		pcep_g->fpt = NULL;

		if (!destroy_pcc())
		{
			flog_err(EC_PATH_PCEP_PCC_FINI,
				 "failed to finalize PCC");
		}
	}

	return ret;
}

int pcep_controller_pcc_update_options(int index, pcc_opts_t *opts)
{
	ctrl_state_t *ctrl_state;
	event_pcc_update_t *event;

	assert(NULL != opts);
	assert(index < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (ctrl_state_t*)pcep_g->fpt->data;
	assert(index <= ctrl_state->pcc_count);

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->pcc_opts = opts;
	event->pcc_id = index;
	thread_add_event(ctrl_state->self,
			 pcep_thread_pcc_update_options_event,
			 (void*)event, 0, NULL);

	return 0;
}

void pcep_controller_pcc_disconnect(int index)
{
	ctrl_state_t *ctrl_state;

	assert(index < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (ctrl_state_t*)pcep_g->fpt->data;
	assert(index < ctrl_state->pcc_count);

	thread_add_event(ctrl_state->self,
			 pcep_thread_pcc_disconnect_event,
			 (void*)ctrl_state, index, NULL);

}

void pcep_controller_pcc_report(int pcc_id, path_t *path)
{
	ctrl_state_t *ctrl_state;
	event_pcc_path_t *event;

	assert(pcc_id < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (ctrl_state_t*)pcep_g->fpt->data;
	assert(pcc_id < ctrl_state->pcc_count);

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->path = path;
	event->pcc_id = pcc_id;
	thread_add_event(ctrl_state->self,
			 pcep_thread_pcc_report_event,
			 (void*)event, 0, NULL);
}

int pcep_halt_cb(struct frr_pthread *fpt, void **res)
{
	thread_add_event(fpt->master,
			 pcep_thread_finish_event, (void*)fpt, 0, NULL);
	pthread_join(fpt->thread, res);

	return 0;
}


/* ------------ Controller Functions Called From Thread ------------ */

/* Notifies the main thread to start sending LSP to synchronize with PCE */
void pcep_thread_start_sync(ctrl_state_t *ctrl_state, pcc_state_t * pcc_state)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	thread_add_event(ctrl_state->main,
			 pcep_main_start_sync_event,
			 NULL, pcc_state->id, NULL);
}

void pcep_thread_update_path(ctrl_state_t *ctrl_state,
                             pcc_state_t *pcc_state,
                             path_t *path)
{
	event_pcc_path_t *event;

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->path = path;
	event->pcc_id = pcc_state->id;
	thread_add_event(ctrl_state->self,
			 pcep_main_update_path_event,
			 (void*)event, 0, NULL);
}


void pcep_thread_schedule_poll(ctrl_state_t *ctrl_state)
{
	assert(NULL == ctrl_state->t_poll);
	thread_add_timer(ctrl_state->self, pcep_thread_poll_timer,
			 (void*)ctrl_state, POLL_INTERVAL,
			 &ctrl_state->t_poll);
}

int pcep_thread_init_event(struct thread *thread)
{
	ctrl_state_t *ctrl_state = THREAD_ARG(thread);
	int ret = 0;

	pcep_thread_schedule_poll(ctrl_state);

	return ret;
}

int pcep_thread_finish_event(struct thread *thread)
{
	int i;
	struct frr_pthread *fpt = THREAD_ARG(thread);
	ctrl_state_t *ctrl_state = fpt->data;

	assert(NULL != ctrl_state);

	if (NULL != ctrl_state->t_poll) {
		thread_cancel(ctrl_state->t_poll);
	}

	for (i = 0; i < ctrl_state->pcc_count; i++) {
		pcep_pcc_finalize(ctrl_state, ctrl_state->pcc[i]);
		ctrl_state->pcc[i] = NULL;
	}

	XFREE(MTYPE_PCEP, ctrl_state);
	fpt->data = NULL;

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
	return 0;
}

int pcep_thread_poll_timer(struct thread *thread)
{
	int i;
	ctrl_state_t *ctrl_state = THREAD_ARG(thread);
	pcep_event *event;

	assert(NULL != ctrl_state);
	assert(NULL == ctrl_state->t_poll);

	while (NULL != (event = event_queue_get_event())) {
		for (i = 0; i < ctrl_state->pcc_count; i++) {
			pcc_state_t *pcc_state = ctrl_state->pcc[i];
			if (pcc_state->sess != event->session) continue;
			pcep_pcc_handle_pcep_event(ctrl_state, pcc_state, event);
			break;
		}
		destroy_pcep_event(event);
	}

	pcep_thread_schedule_poll(ctrl_state);

	return 0;
}

int pcep_thread_pcc_update_options_event(struct thread *thread)
{
	event_pcc_update_t *event = THREAD_ARG(thread);
	ctrl_state_t *ctrl_state = event->ctrl_state;
	int pcc_id = event->pcc_id;
	pcc_opts_t *pcc_opts = event->pcc_opts;
	pcc_state_t *pcc_state;

	XFREE(MTYPE_PCEP, event);

	if (pcc_id == ctrl_state->pcc_count) {
		pcc_state = pcep_pcc_initialize(ctrl_state, pcc_id);
		ctrl_state->pcc_count = pcc_id + 1;
		ctrl_state->pcc[pcc_id] = pcc_state;
	} else {
		pcc_state = ctrl_state->pcc[pcc_id];
	}

	if (pcep_pcc_update(ctrl_state, pcc_state, pcc_opts)) {
		flog_err(EC_PATH_PCEP_PCC_CONF_UPDATE,
			 "failed to update PCC configuration");
	}

	return 0;
}

int pcep_thread_pcc_disconnect_event(struct thread *thread)
{
	ctrl_state_t *ctrl_state = THREAD_ARG(thread);
	pcc_state_t *pcc_state;
	int pcc_id = THREAD_VAL(thread);

	if (pcc_id < ctrl_state->pcc_count) {
		pcc_state = ctrl_state->pcc[pcc_id];
		pcep_pcc_disable(ctrl_state, pcc_state);
	}

	return 0;
}

int pcep_thread_pcc_report_event(struct thread *thread)
{
	pcep_message *report;
	double_linked_list *objs;
	event_pcc_path_t *event = THREAD_ARG(thread);
	ctrl_state_t *ctrl_state = event->ctrl_state;
	int pcc_id = event->pcc_id;
	path_t *path = event->path;
	pcc_state_t *pcc_state = ctrl_state->pcc[pcc_id];
	pcc_status_t status = pcc_state->status;

	XFREE(MTYPE_PCEP, event);

	assert(NULL != path);
	assert(!((SYNCHRONIZING != status) && path->is_synching));

	if (!path->is_synching && (SYNCHRONIZING == status)) {
		status = OPERATING;
	}

	pcep_pcc_lookup_plspid(pcc_state, path);

	PCEP_DEBUG("Sending path: %s", format_path(path));

	objs = pcep_lib_format_path(path);
	report = pcep_msg_create_report(objs);
	pcep_pcc_send(ctrl_state, pcc_state, report);
	dll_destroy_with_data(objs);
	pcep_lib_free_path(path);

	pcc_state->status = status;

	return 0;
}

int pcep_thread_pcc_cb_event(struct thread *thread)
{
	event_pcc_cb_t *event = THREAD_ARG(thread);
	ctrl_state_t *ctrl_state = event->ctrl_state;
	int pcc_id = event->pcc_id;
	pcc_cb_t callback = event->cb;
	pcc_state_t *pcc_state = ctrl_state->pcc[pcc_id];

	XFREE(MTYPE_PCEP, event);

	return callback(ctrl_state, pcc_state);
}


/* ------------ Main Thread Functions ------------ */

int pcep_main_start_sync_event(struct thread *thread)
{
	int pcc_id = THREAD_VAL(thread);
	path_t *path;

	path_nb_list_path(pcep_main_start_sync_event_cb, &pcc_id);

	/* Final sync report */
	path = XCALLOC(MTYPE_PCEP, sizeof(*path));
	*path = (path_t) {
		.name = NULL,
		.srp_id = 0,
		.plsp_id = 0,
		.status = PCEP_LSP_OPERATIONAL_DOWN,
		.do_remove = false,
		.go_active = false,
		.was_created = false,
		.was_removed = false,
		.is_synching = false,
		.is_delegated = false,
		.first = NULL
	};
	pcep_controller_pcc_report(pcc_id, path);

	return 0;
}

int pcep_main_start_sync_event_cb(path_t *path, void *arg)
{
	int *pcc_id = (int*)arg;
	pcep_controller_pcc_report(*pcc_id, path);
	return 1;
}

int pcep_main_update_path_event(struct thread *thread)
{
	event_pcc_path_t *event = THREAD_ARG(thread);
	int pcc_id = event->pcc_id;
	path_t *path = event->path;

	XFREE(MTYPE_PCEP, event);

	path_nb_update_path(path);

	pcep_controller_pcc_report(pcc_id, path);

	return 0;
}


/* ------------ CLI Functions ------------ */

DEFUN (pcep_cli_pce_ip,
       pcep_cli_pce_ip_cmd,
	"pce ip A.B.C.D [port (1024-65535)]",
	"PCE remote ip and port\n"
	"Remote PCE server ip A.B.C.D\n"
	"Remote PCE server port")
{
	struct in_addr pce_addr;
	uint32_t pce_port = PCEP_DEFAULT_PORT;
	pcc_opts_t *opts;

	int ip_idx = 2;
	int port_idx = 4;

	if (!inet_pton(AF_INET, argv[ip_idx]->arg, &(pce_addr.s_addr)))
		return CMD_ERR_INCOMPLETE;

	if (argc > port_idx)
		pce_port = atoi(argv[port_idx]->arg);

	opts = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	opts->addr = pce_addr;
	opts->port = pce_port;

	if (pcep_controller_pcc_update_options(0, opts))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN (pcep_cli_no_pce,
       pcep_cli_no_pce_cmd,
	"no pce",
	NO_STR
	"Disable pce\n")
{
	pcep_controller_pcc_disconnect(0);
	return CMD_SUCCESS;
}

DEFUN (pcep_cli_debug,
       pcep_cli_debug_cmd,
       "[no] debug pathd pcep",
       NO_STR
       DEBUG_STR
       "Pathd debugging\n"
       "pcep\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");

	DEBUG_MODE_SET(&pcep_g->dbg, mode, !no);

	return CMD_SUCCESS;
}

int pcep_cli_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_CONF))
		vty_out(vty, "debug pathd pcep\n");

	return 0;
}

int pcep_cli_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&pcep_g->dbg, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&pcep_g->dbg);

	return 0;
}

void pcep_cli_init(void)
{
	hook_register(nb_client_debug_config_write,
		      pcep_cli_debug_config_write);
	hook_register(nb_client_debug_set_all,
		      pcep_cli_debug_set_all);

	install_element(ENABLE_NODE, &pcep_cli_debug_cmd);
	install_element(CONFIG_NODE, &pcep_cli_debug_cmd);
	install_element(CONFIG_NODE, &pcep_cli_pce_ip_cmd);
	install_element(CONFIG_NODE, &pcep_cli_no_pce_cmd);

}

/* ------------ Module Functions ------------ */

int pcep_module_late_init(struct thread_master *tm)
{
	pcep_g->master = tm;

	if (pcep_controller_initialize()) return 1;

	hook_register(frr_fini, pcep_module_finish);
	pcep_cli_init();

	return 0;
}

int pcep_module_finish(void)
{
	pcep_controller_finalize();

	return 0;
}

int pcep_module_init(void)
{
	hook_register(frr_late_init, pcep_module_late_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "frr_pathd_pcep", .version = FRR_VERSION,
		 .description = "FRR pathd PCEP module",
		 .init = pcep_module_init)
