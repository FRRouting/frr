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

/* TODOS:
	- Delete mapping from NB keys to PLSPID when an LSP is deleted either
	  by the PCE or by NB.
	- Revert the hacks to work around ODL requiring a report with
	  operational status DOWN when an LSP is activated.
	- Enforce only the PCE a policy has been delegated to can update it.
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
#include "pathd/path_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"

#define PCEP_DEFAULT_PORT 4189
#define POLL_INTERVAL 1
#define CMP_RETURN(A, B)                                                       \
	if (A != B)                                                            \
	return (A < B) ? -1 : 1

DEFINE_MTYPE(PATHD, PCEP, "PCEP module")

/*
 * Globals.
 */
static struct pcep_glob pcep_glob_space = {.dbg = {0, "pathd module: pcep"}};
struct pcep_glob *pcep_g = &pcep_glob_space;

/* PCC Functions */
static struct pcc_state *pcep_pcc_initialize(struct ctrl_state *ctrl_state,
					     int index);
static void pcep_pcc_finalize(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state);
static int pcep_pcc_update(struct ctrl_state *ctrl_state,
			   struct pcc_state *pcc_state,
			   struct pcc_opts *pcc_opts,
			   struct pce_opts *pce_opts);
static int pcep_pcc_enable(struct ctrl_state *ctrl_state,
			   struct pcc_state *pcc_state);
static int pcep_pcc_disable(struct ctrl_state *ctrl_state,
			    struct pcc_state *pcc_state);
static void pcep_pcc_handle_pcep_event(struct ctrl_state *ctrl_state,
				       struct pcc_state *pcc_state,
				       pcep_event *event);
static void pcep_pcc_handle_message(struct ctrl_state *ctrl_state,
				    struct pcc_state *pcc_state,
				    struct pcep_message *msg);
static void pcep_pcc_lsp_update(struct ctrl_state *ctrl_state,
				struct pcc_state *pcc_state,
				struct pcep_message *msg);
static void pcep_pcc_lsp_initiate(struct ctrl_state *ctrl_state,
				  struct pcc_state *pcc_state,
				  struct pcep_message *msg);
static void pcep_pcc_send(struct ctrl_state *ctrl_state,
			  struct pcc_state *pcc_state,
			  struct pcep_message *msg);
static void pcep_pcc_schedule_reconnect(struct ctrl_state *ctrl_state,
					struct pcc_state *pcc_state);
static void pcep_pcc_lookup_plspid(struct pcc_state *pcc_state,
				   struct path *path);
static void pcep_pcc_lookup_nbkey(struct pcc_state *pcc_state,
				  struct path *path);
static void pcep_pcc_push_srpid(struct pcc_state *pcc_state, struct path *path);
static void pcep_pcc_pop_srpid(struct pcc_state *pcc_state, struct path *path);
static void pcep_pcc_send_report(struct ctrl_state *ctrl_state,
				 struct pcc_state *pcc_state,
				 struct path *path);
static void pcep_pcc_handle_pathd_event(struct ctrl_state *ctrl_state,
					struct pcc_state *pcc_state,
					enum pathd_event_type type,
					struct path *path);

/* pceplib logging callback */
static int pceplib_logging_cb(int level, const char *fmt, va_list args);

/* Controller Functions Called from Main */
static int pcep_controller_initialize(void);
static int pcep_controller_finalize(void);
static int pcep_controller_pcc_update_options(struct pcc_opts *opts);
static int pcep_controller_pce_update_options(int index, struct pce_opts *opts);
static void pcep_controller_pcc_disconnect(int index);
static void pcep_controller_pcc_report(int index, struct path *path);
static void pcep_controller_pcc_sync_done(int index);
static int pcep_halt_cb(struct frr_pthread *fpt, void **res);

/* Controller Functions Called From Thread */
static void pcep_thread_start_sync(struct ctrl_state *ctrl_state,
				   struct pcc_state *pcc_state);
static void pcep_thread_update_path(struct ctrl_state *ctrl_state,
				    struct pcc_state *pcc_state,
				    struct path *path);
static void pcep_thread_schedule_poll(struct ctrl_state *ctrl_state);
static int pcep_thread_init_event(struct thread *thread);
static int pcep_thread_finish_event(struct thread *thread);
static int pcep_thread_poll_timer(struct thread *thread);
static int pcep_thread_pcc_update_options_event(struct thread *thread);
static int pcep_thread_pce_update_options_event(struct thread *thread);
static int pcep_thread_pcc_disconnect_event(struct thread *thread);
static int pcep_thread_pcc_report_event(struct thread *thread);
static int pcep_thread_pcc_sync_done_event(struct thread *thread);
static int pcep_thread_pcc_cb_event(struct thread *thread);
static int pcep_thread_pcc_pathd_event(struct thread *thread);

/* Main Thread Functions */
static int pcep_main_start_sync_event(struct thread *thread);
static int pcep_main_start_sync_event_cb(struct path *path, void *arg);
static int pcep_main_update_path_event(struct thread *thread);

/* Hook Handlers called from the Main Thread */
static int pathd_candidate_created_handler(struct srte_candidate *candidate);
static int pathd_candidate_updated_handler(struct srte_candidate *candidate);
static int pathd_candidate_removed_handler(struct srte_candidate *candidate);
static void pathd_candidate_send_pathd_event(enum pathd_event_type type,
					     struct path *path);

/* CLI Functions */
static int pcep_cli_debug_config_write(struct vty *vty);
static int pcep_cli_debug_set_all(uint32_t flags, bool set);
static void pcep_cli_init(void);

/* Module Functions */
static int pcep_module_finish(void);
static int pcep_module_late_init(struct thread_master *tm);
static int pcep_module_init(void);

/* Data Structure Functions */
static int plspid_map_cmp(const struct plspid_map_data *a,
			  const struct plspid_map_data *b);
static uint32_t plspid_map_hash(const struct plspid_map_data *e);
static int nbkey_map_cmp(const struct nbkey_map_data *a,
			 const struct nbkey_map_data *b);
static uint32_t nbkey_map_hash(const struct nbkey_map_data *e);
static int srpid_map_cmp(const struct srpid_map_data *a,
			 const struct srpid_map_data *b);
static uint32_t srpid_map_hash(const struct srpid_map_data *e);

DECLARE_HASH(plspid_map, struct plspid_map_data, mi, plspid_map_cmp,
	     plspid_map_hash)
DECLARE_HASH(nbkey_map, struct nbkey_map_data, mi, nbkey_map_cmp,
	     nbkey_map_hash)
DECLARE_HASH(srpid_map, struct srpid_map_data, mi, srpid_map_cmp,
	     srpid_map_hash)

static struct cmd_node pcc_node = {
        .name = "pcc",
        .node = PCC_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(config-pcc)# ",
};

/* ------------ Data Structure Functions ------------ */

static int plspid_map_cmp(const struct plspid_map_data *a,
			  const struct plspid_map_data *b)
{
	CMP_RETURN(a->nbkey.color, b->nbkey.color);
	int cmp = ipaddr_cmp(&a->nbkey.endpoint, &b->nbkey.endpoint);
	if (cmp != 0)
		return cmp;
	CMP_RETURN(a->nbkey.preference, b->nbkey.preference);
	return 0;
}

static uint32_t plspid_map_hash(const struct plspid_map_data *e)
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

static int nbkey_map_cmp(const struct nbkey_map_data *a,
			 const struct nbkey_map_data *b)
{
	CMP_RETURN(a->plspid, b->plspid);
	return 0;
}

static uint32_t nbkey_map_hash(const struct nbkey_map_data *e)
{
	return e->plspid;
}


static int srpid_map_cmp(const struct srpid_map_data *a,
			 const struct srpid_map_data *b)
{
	CMP_RETURN(a->plspid, b->plspid);
	return 0;
}

static uint32_t srpid_map_hash(const struct srpid_map_data *e)
{
	return e->plspid;
}


/* ------------ PCC Functions ------------ */

struct pcc_state *pcep_pcc_initialize(struct ctrl_state *ctrl_state, int index)
{
	assert(NULL != ctrl_state);

	struct pcc_state *pcc_state = XCALLOC(MTYPE_PCEP, sizeof(*pcc_state));

	PCEP_DEBUG("PCC initializing...");

	pcc_state->id = index;
	pcc_state->status = DISCONNECTED;
	pcc_state->next_plspid = 1;

	return pcc_state;
}

void pcep_pcc_finalize(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	PCEP_DEBUG("PCC finalizing...");

	pcep_pcc_disable(ctrl_state, pcc_state);

	if (NULL != pcc_state->pcc_opts) {
		XFREE(MTYPE_PCEP, pcc_state->pcc_opts);
		pcc_state->pcc_opts = NULL;
	}
	if (NULL != pcc_state->pce_opts) {
		XFREE(MTYPE_PCEP, pcc_state->pce_opts);
		pcc_state->pce_opts = NULL;
	}
	XFREE(MTYPE_PCEP, pcc_state);
}

int pcep_pcc_update(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state,
		    struct pcc_opts *pcc_opts, struct pce_opts *pce_opts)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	int ret = 0;

	// TODO: check if the options changed ?

	if ((ret = pcep_pcc_disable(ctrl_state, pcc_state))) {
		XFREE(MTYPE_PCEP, pcc_opts);
		XFREE(MTYPE_PCEP, pce_opts);
		return ret;
	}

	if (NULL != pcc_state->pcc_opts) {
		XFREE(MTYPE_PCEP, pcc_state->pcc_opts);
	}
	if (NULL != pcc_state->pce_opts) {
		XFREE(MTYPE_PCEP, pcc_state->pce_opts);
	}

	pcc_state->pcc_opts = pcc_opts;
	pcc_state->pce_opts = pce_opts;

	return pcep_pcc_enable(ctrl_state, pcc_state);
}

int pcep_pcc_enable(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	assert(DISCONNECTED == pcc_state->status);

	int ret;

	PCEP_DEBUG("PCC connecting to %pI4:%d", &pcc_state->pce_opts->addr,
		   pcc_state->pce_opts->port);

	if ((ret = pcep_lib_connect(pcc_state))) {
		flog_warn(EC_PATH_PCEP_LIB_CONNECT,
			  "failed to connect to PCE %pI4:%d from %pI4:%d (%d)",
			  &pcc_state->pce_opts->addr, pcc_state->pce_opts->port,
			  &pcc_state->pcc_opts->addr, pcc_state->pcc_opts->port,
			  ret);
		pcep_pcc_schedule_reconnect(ctrl_state, pcc_state);
		return 0;
	}

	pcc_state->status = CONNECTING;

	return 0;
}

int pcep_pcc_disable(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
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

void pcep_pcc_handle_pcep_event(struct ctrl_state *ctrl_state,
				struct pcc_state *pcc_state, pcep_event *event)
{
	PCEP_DEBUG("Received PCEP event: %s",
		   pcep_event_type_name(event->event_type));
	switch (event->event_type) {
	case PCC_CONNECTED_TO_PCE:
		assert(CONNECTING == pcc_state->status);
		PCEP_DEBUG("Connection established to PCE %pI4:%i",
			   &pcc_state->pce_opts->addr,
			   pcc_state->pce_opts->port);
		pcc_state->status = SYNCHRONIZING;
		pcc_state->retry_count = 0;
		pcc_state->synchronized = false;
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
		PCEP_DEBUG("Received PCEP message");
		PCEP_DEBUG_PCEP("%s", format_pcep_message(event->message));
		if (CONNECTING == pcc_state->status) {
			assert(PCEP_TYPE_OPEN
			       == event->message->msg_header->type);
			break;
		}
		assert(SYNCHRONIZING == pcc_state->status
		       || OPERATING == pcc_state->status);
		pcep_pcc_handle_message(ctrl_state, pcc_state, event->message);
		break;
	default:
		flog_warn(EC_PATH_PCEP_UNEXPECTED_EVENT,
			  "Unexpected event from pceplib: %s",
			  format_pcep_event(event));
		break;
	}
}

void pcep_pcc_handle_message(struct ctrl_state *ctrl_state,
			     struct pcc_state *pcc_state,
			     struct pcep_message *msg)
{
	switch (msg->msg_header->type) {
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

void pcep_pcc_lsp_update(struct ctrl_state *ctrl_state,
			 struct pcc_state *pcc_state, struct pcep_message *msg)
{
	struct path *path;
	path = pcep_lib_parse_path(msg->obj_list);
	path->sender.ipa_type = IPADDR_V4;
	path->sender.ipaddr_v4 = pcc_state->pce_opts->addr;
	pcep_pcc_lookup_nbkey(pcc_state, path);

	pcep_pcc_push_srpid(pcc_state, path);

	PCEP_DEBUG("Received LSP update");
	PCEP_DEBUG_PATH("%s", format_path(path));

	pcep_thread_update_path(ctrl_state, pcc_state, path);
}

void pcep_pcc_lsp_initiate(struct ctrl_state *ctrl_state,
			   struct pcc_state *pcc_state,
			   struct pcep_message *msg)
{
	PCEP_DEBUG("Received LSP initiate, not supported yet");
}

void pcep_pcc_send(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state,
		   struct pcep_message *msg)
{
	PCEP_DEBUG("Sending PCEP message");
	PCEP_DEBUG_PCEP("%s", format_pcep_message(msg));
	send_message(pcc_state->sess, msg, true);
}

void pcep_pcc_schedule_reconnect(struct ctrl_state *ctrl_state,
				 struct pcc_state *pcc_state)
{
	uint32_t delay;
	struct event_pcc_cb *event;

	pcc_state->retry_count++;
	/* TODO: Add exponential backoff */
	delay = 2;

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->pcc_id = pcc_state->id;
	event->cb = pcep_pcc_enable;

	thread_add_timer(ctrl_state->self, pcep_thread_pcc_cb_event,
			 (void *)event, delay, &pcc_state->t_reconnect);
}

void pcep_pcc_lookup_plspid(struct pcc_state *pcc_state, struct path *path)
{
	struct plspid_map_data key, *plspid_mapping;
	struct nbkey_map_data *nbkey_mapping;

	if (0 != path->nbkey.color) {
		key.nbkey = path->nbkey;
		plspid_mapping = plspid_map_find(&pcc_state->plspid_map, &key);
		if (NULL == plspid_mapping) {
			plspid_mapping =
				XCALLOC(MTYPE_PCEP, sizeof(*plspid_mapping));
			plspid_mapping->nbkey = key.nbkey;
			plspid_mapping->plspid = pcc_state->next_plspid;
			plspid_map_add(&pcc_state->plspid_map, plspid_mapping);
			nbkey_mapping =
				XCALLOC(MTYPE_PCEP, sizeof(*nbkey_mapping));
			nbkey_mapping->nbkey = key.nbkey;
			nbkey_mapping->plspid = pcc_state->next_plspid;
			nbkey_map_add(&pcc_state->nbkey_map, nbkey_mapping);
			pcc_state->next_plspid++;
			// FIXME: Send some error to the PCE isntead of crashing
			assert(1048576 > pcc_state->next_plspid);
		}
		path->plsp_id = plspid_mapping->plspid;
	}
}

void pcep_pcc_lookup_nbkey(struct pcc_state *pcc_state, struct path *path)
{
	struct nbkey_map_data key, *mapping;
	// TODO: Should give an error to the PCE instead of crashing
	assert(0 != path->plsp_id);
	key.plspid = path->plsp_id;
	mapping = nbkey_map_find(&pcc_state->nbkey_map, &key);
	assert(NULL != mapping);
	path->nbkey = mapping->nbkey;
}

void pcep_pcc_push_srpid(struct pcc_state *pcc_state, struct path *path)
{
	struct srpid_map_data *srpid_mapping;

	if (0 == path->srp_id)
		return;

	srpid_mapping = XCALLOC(MTYPE_PCEP, sizeof(*srpid_mapping));
	srpid_mapping->plspid = path->plsp_id;
	srpid_mapping->srpid = path->srp_id;

	/* FIXME: When we have correlation between NB commits and hooks call,
	   multiple concurent calls from the PCE should be supported */
	assert(NULL == srpid_map_find(&pcc_state->srpid_map, srpid_mapping));

	srpid_map_add(&pcc_state->srpid_map, srpid_mapping);
}

void pcep_pcc_pop_srpid(struct pcc_state *pcc_state, struct path *path)
{
	struct srpid_map_data key, *srpid_mapping;

	key.plspid = path->plsp_id;

	srpid_mapping = srpid_map_find(&pcc_state->srpid_map, &key);
	if (NULL == srpid_mapping)
		return;

	path->srp_id = srpid_mapping->srpid;
	srpid_map_del(&pcc_state->srpid_map, srpid_mapping);
	XFREE(MTYPE_PCEP, srpid_mapping);
}

void pcep_pcc_send_report(struct ctrl_state *ctrl_state,
			  struct pcc_state *pcc_state, struct path *path)
{
	double_linked_list *objs;
	struct pcep_message *report;
	enum pcep_lsp_operational_status orig_status;

	pcep_pcc_lookup_plspid(pcc_state, path);
	pcep_pcc_pop_srpid(pcc_state, path);

	/* FIXME: Remove this back when ODL is not expecting a DOWN status
	anymore when installing an LSP */
	if ((0 != path->srp_id)
	    && (PCEP_LSP_OPERATIONAL_DOWN != path->status)) {
		orig_status = path->status;
		path->status = PCEP_LSP_OPERATIONAL_DOWN;
		PCEP_DEBUG("Sending path (ODL FIX)");
		PCEP_DEBUG_PATH("%s", format_path(path));
		objs = pcep_lib_format_path(path);
		report = pcep_msg_create_report(objs);
		pcep_pcc_send(ctrl_state, pcc_state, report);
		path->status = orig_status;
		path->srp_id = 0;
	}

	PCEP_DEBUG("Sending path");
	PCEP_DEBUG_PATH("%s", format_path(path));
	objs = pcep_lib_format_path(path);
	report = pcep_msg_create_report(objs);
	pcep_pcc_send(ctrl_state, pcc_state, report);
}

void pcep_pcc_handle_pathd_event(struct ctrl_state *ctrl_state,
				 struct pcc_state *pcc_state,
				 enum pathd_event_type type, struct path *path)
{
	if (!pcc_state->synchronized)
		return;
	switch (type) {
	case CANDIDATE_CREATED:
		PCEP_DEBUG("Candidate path %s created", path->name);
		pcep_pcc_send_report(ctrl_state, pcc_state, path);
		break;
	case CANDIDATE_UPDATED:
		PCEP_DEBUG("Candidate path %s updated", path->name);
		pcep_pcc_send_report(ctrl_state, pcc_state, path);
		break;
	case CANDIDATE_REMOVED:
		PCEP_DEBUG("Candidate path %s removed", path->name);
		path->was_removed = true;
		pcep_pcc_send_report(ctrl_state, pcc_state, path);
		break;
	}
}

/* ------------ pceplib logging callback ------------ */

int pceplib_logging_cb(int priority, const char *fmt, va_list args)
{
	char buffer[1024];
	snprintf(buffer, sizeof(buffer), fmt, args);
	PCEP_DEBUG_PCEPLIB(priority, "pceplib: %s", buffer);
	return 0;
}


/* ------------ Controller Functions Called from Main ------------ */

int pcep_controller_initialize(void)
{
	int ret;
	struct ctrl_state *ctrl_state;
	struct frr_pthread *fpt;
	struct frr_pthread_attr attr = {
		.start = frr_pthread_attr_default.start,
		.stop = pcep_halt_cb,
	};

	assert(NULL == pcep_g->fpt);
	assert(!pcep_g->fpt);

	if (!initialize_pcc()) {
		flog_err(EC_PATH_PCEP_PCC_INIT, "failed to initialize PCC");
		return 1;
	}

	/* Register pceplib logging callback */
	register_logger(pceplib_logging_cb);

	/* Create and start the FRR pthread */
	fpt = frr_pthread_new(&attr, "PCEP thread", "pcep");
	if (NULL == fpt) {
		flog_err(EC_PATH_SYSTEM_CALL,
			 "failed to initialize PCEP thread");
		return 1;
	}
	ret = frr_pthread_run(fpt, NULL);
	if (ret < 0) {
		flog_err(EC_PATH_SYSTEM_CALL, "failed to create PCEP thread");
		return ret;
	}
	frr_pthread_wait_running(fpt);

	/* Initialise the thread state */
	ctrl_state = XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state));
	ctrl_state->main = pcep_g->master;
	ctrl_state->self = fpt->master;
	ctrl_state->t_poll = NULL;
	ctrl_state->pcc_count = 0;
	ctrl_state->pcc_opts =
		XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state->pcc_opts));
	ctrl_state->pcc_opts->addr.s_addr = INADDR_ANY;
	ctrl_state->pcc_opts->port = PCEP_DEFAULT_PORT;

	/* Keep the state reference for events */
	fpt->data = ctrl_state;
	pcep_g->fpt = fpt;

	/* Initialize the PCEP thread */
	thread_add_event(ctrl_state->self, pcep_thread_init_event,
			 (void *)ctrl_state, 0, NULL);

	hook_register(pathd_candidate_created, pathd_candidate_created_handler);
	hook_register(pathd_candidate_updated, pathd_candidate_updated_handler);
	hook_register(pathd_candidate_removed, pathd_candidate_removed_handler);

	return 0;
}

int pcep_controller_finalize(void)
{
	int ret = 0;

	if (NULL != pcep_g->fpt) {
		frr_pthread_stop(pcep_g->fpt, NULL);
		pcep_g->fpt = NULL;

		if (!destroy_pcc()) {
			flog_err(EC_PATH_PCEP_PCC_FINI,
				 "failed to finalize PCC");
		}
	}

	return ret;
}

int pcep_controller_pcc_update_options(struct pcc_opts *opts)
{
	struct ctrl_state *ctrl_state;
	struct event_pcc_update *event;

	assert(NULL != opts);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (struct ctrl_state *)pcep_g->fpt->data;

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->pcc_opts = opts;
	thread_add_event(ctrl_state->self, pcep_thread_pcc_update_options_event,
			 (void *)event, 0, NULL);

	return 0;
}

int pcep_controller_pce_update_options(int index, struct pce_opts *opts)
{
	struct ctrl_state *ctrl_state;
	struct event_pce_update *event;

	assert(NULL != opts);
	assert(index < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (struct ctrl_state *)pcep_g->fpt->data;
	assert(index <= ctrl_state->pcc_count);

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->pce_opts = opts;
	event->pcc_id = index;
	thread_add_event(ctrl_state->self, pcep_thread_pce_update_options_event,
			 (void *)event, 0, NULL);

	return 0;
}

void pcep_controller_pcc_disconnect(int index)
{
	struct ctrl_state *ctrl_state;

	assert(index < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (struct ctrl_state *)pcep_g->fpt->data;
	assert(index < ctrl_state->pcc_count);

	thread_add_event(ctrl_state->self, pcep_thread_pcc_disconnect_event,
			 (void *)ctrl_state, index, NULL);
}

void pcep_controller_pcc_report(int pcc_id, struct path *path)
{
	struct ctrl_state *ctrl_state;
	struct event_pcc_path *event;

	assert(pcc_id < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (struct ctrl_state *)pcep_g->fpt->data;
	assert(pcc_id < ctrl_state->pcc_count);

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->path = path;
	event->pcc_id = pcc_id;
	thread_add_event(ctrl_state->self, pcep_thread_pcc_report_event,
			 (void *)event, 0, NULL);
}

void pcep_controller_pcc_sync_done(int index)
{
	struct ctrl_state *ctrl_state;

	assert(index < MAX_PCC);
	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (struct ctrl_state *)pcep_g->fpt->data;
	assert(index < ctrl_state->pcc_count);

	thread_add_event(ctrl_state->self, pcep_thread_pcc_sync_done_event,
			 (void *)ctrl_state, index, NULL);
}

int pcep_halt_cb(struct frr_pthread *fpt, void **res)
{
	thread_add_event(fpt->master, pcep_thread_finish_event, (void *)fpt, 0,
			 NULL);
	pthread_join(fpt->thread, res);

	return 0;
}


/* ------------ Hook Handlers Functions Called From Main Thread ------------ */

int pathd_candidate_created_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	pathd_candidate_send_pathd_event(CANDIDATE_CREATED, path);
	return 0;
}

int pathd_candidate_updated_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	pathd_candidate_send_pathd_event(CANDIDATE_UPDATED, path);
	return 0;
}

int pathd_candidate_removed_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	pathd_candidate_send_pathd_event(CANDIDATE_REMOVED, path);
	return 0;
}

void pathd_candidate_send_pathd_event(enum pathd_event_type type,
				      struct path *path)
{
	struct ctrl_state *ctrl_state;
	struct event_pathd *event;

	assert(NULL != pcep_g->fpt);
	assert(NULL != pcep_g->fpt->data);
	ctrl_state = (struct ctrl_state *)pcep_g->fpt->data;

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->type = type;
	event->path = path;
	thread_add_event(ctrl_state->self, pcep_thread_pcc_pathd_event,
			 (void *)event, 0, NULL);
}


/* ------------ Controller Functions Called From Thread ------------ */

/* Notifies the main thread to start sending LSP to synchronize with PCE */
void pcep_thread_start_sync(struct ctrl_state *ctrl_state,
			    struct pcc_state *pcc_state)
{
	assert(NULL != ctrl_state);
	assert(NULL != pcc_state);

	thread_add_event(ctrl_state->main, pcep_main_start_sync_event, NULL,
			 pcc_state->id, NULL);
}

void pcep_thread_update_path(struct ctrl_state *ctrl_state,
			     struct pcc_state *pcc_state, struct path *path)
{
	struct event_pcc_path *event;

	event = XCALLOC(MTYPE_PCEP, sizeof(*event));
	event->ctrl_state = ctrl_state;
	event->path = path;
	event->pcc_id = pcc_state->id;
	thread_add_event(ctrl_state->self, pcep_main_update_path_event,
			 (void *)event, 0, NULL);
}


void pcep_thread_schedule_poll(struct ctrl_state *ctrl_state)
{
	assert(NULL == ctrl_state->t_poll);
	thread_add_timer(ctrl_state->self, pcep_thread_poll_timer,
			 (void *)ctrl_state, POLL_INTERVAL,
			 &ctrl_state->t_poll);
}

int pcep_thread_init_event(struct thread *thread)
{
	struct ctrl_state *ctrl_state = THREAD_ARG(thread);
	int ret = 0;

	pcep_thread_schedule_poll(ctrl_state);

	return ret;
}

int pcep_thread_finish_event(struct thread *thread)
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

int pcep_thread_poll_timer(struct thread *thread)
{
	int i;
	struct ctrl_state *ctrl_state = THREAD_ARG(thread);
	pcep_event *event;

	assert(NULL != ctrl_state);
	assert(NULL == ctrl_state->t_poll);

	while (NULL != (event = event_queue_get_event())) {
		for (i = 0; i < ctrl_state->pcc_count; i++) {
			struct pcc_state *pcc_state = ctrl_state->pcc[i];
			if (pcc_state->sess != event->session)
				continue;
			pcep_pcc_handle_pcep_event(ctrl_state, pcc_state,
						   event);
			break;
		}
		destroy_pcep_event(event);
	}

	pcep_thread_schedule_poll(ctrl_state);

	return 0;
}

int pcep_thread_pcc_update_options_event(struct thread *thread)
{
	struct event_pcc_update *event = THREAD_ARG(thread);
	struct ctrl_state *ctrl_state = event->ctrl_state;
	struct pcc_opts *pcc_opts = event->pcc_opts;

	XFREE(MTYPE_PCEP, event);

	if (NULL != ctrl_state->pcc_opts) {
		XFREE(MTYPE_PCEP, ctrl_state->pcc_opts);
	}

	ctrl_state->pcc_opts = pcc_opts;

	return 0;
}

int pcep_thread_pce_update_options_event(struct thread *thread)
{
	struct event_pce_update *event = THREAD_ARG(thread);
	struct ctrl_state *ctrl_state = event->ctrl_state;
	int pcc_id = event->pcc_id;
	struct pce_opts *pce_opts = event->pce_opts;
	struct pcc_opts *pcc_opts;
	struct pcc_state *pcc_state;

	XFREE(MTYPE_PCEP, event);

	if (pcc_id == ctrl_state->pcc_count) {
		pcc_state = pcep_pcc_initialize(ctrl_state, pcc_id);
		ctrl_state->pcc_count = pcc_id + 1;
		ctrl_state->pcc[pcc_id] = pcc_state;
	} else {
		pcc_state = ctrl_state->pcc[pcc_id];
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

int pcep_thread_pcc_disconnect_event(struct thread *thread)
{
	struct ctrl_state *ctrl_state = THREAD_ARG(thread);
	struct pcc_state *pcc_state;
	int pcc_id = THREAD_VAL(thread);

	if (pcc_id < ctrl_state->pcc_count) {
		pcc_state = ctrl_state->pcc[pcc_id];
		pcep_pcc_disable(ctrl_state, pcc_state);
	}

	return 0;
}

int pcep_thread_pcc_report_event(struct thread *thread)
{
	struct event_pcc_path *event = THREAD_ARG(thread);
	struct ctrl_state *ctrl_state = event->ctrl_state;
	int pcc_id = event->pcc_id;
	struct path *path = event->path;
	struct pcc_state *pcc_state = ctrl_state->pcc[pcc_id];
	enum pcc_status status = pcc_state->status;

	XFREE(MTYPE_PCEP, event);

	assert(NULL != path);
	assert(!((SYNCHRONIZING != status) && path->is_synching));

	if (!path->is_synching && (SYNCHRONIZING == status)) {
		status = OPERATING;
	}

	pcep_pcc_send_report(ctrl_state, pcc_state, path);
	pcep_lib_free_path(path);

	pcc_state->status = status;

	return 0;
}

int pcep_thread_pcc_sync_done_event(struct thread *thread)
{
	struct ctrl_state *ctrl_state = THREAD_ARG(thread);
	struct pcc_state *pcc_state;
	int pcc_id = THREAD_VAL(thread);

	if (pcc_id < ctrl_state->pcc_count) {
		pcc_state = ctrl_state->pcc[pcc_id];
		pcc_state->synchronized = true;
	}

	return 0;
}


int pcep_thread_pcc_cb_event(struct thread *thread)
{
	struct event_pcc_cb *event = THREAD_ARG(thread);
	struct ctrl_state *ctrl_state = event->ctrl_state;
	int pcc_id = event->pcc_id;
	pcc_cb_t callback = event->cb;
	struct pcc_state *pcc_state = ctrl_state->pcc[pcc_id];

	XFREE(MTYPE_PCEP, event);

	return callback(ctrl_state, pcc_state);
}

int pcep_thread_pcc_pathd_event(struct thread *thread)
{
	int i;
	struct event_pathd *event = THREAD_ARG(thread);
	struct ctrl_state *ctrl_state = event->ctrl_state;
	enum pathd_event_type type = event->type;
	struct path *path = event->path;

	XFREE(MTYPE_PCEP, event);

	for (i = 0; i < ctrl_state->pcc_count; i++) {
		struct pcc_state *pcc_state = ctrl_state->pcc[i];
		if (!pcc_state->synchronized)
			continue;
		pcep_pcc_handle_pathd_event(ctrl_state, pcc_state, type, path);
	}

	pcep_lib_free_path(path);

	return 0;
}


/* ------------ Main Thread Functions ------------ */

int pcep_main_start_sync_event(struct thread *thread)
{
	int pcc_id = THREAD_VAL(thread);
	struct path *path;

	path_nb_list_path(pcep_main_start_sync_event_cb, &pcc_id);

	/* Final sync report */
	path = XCALLOC(MTYPE_PCEP, sizeof(*path));
	*path = (struct path){.name = NULL,
			      .srp_id = 0,
			      .plsp_id = 0,
			      .status = PCEP_LSP_OPERATIONAL_DOWN,
			      .do_remove = false,
			      .go_active = false,
			      .was_created = false,
			      .was_removed = false,
			      .is_synching = false,
			      .is_delegated = false,
			      .first = NULL};
	pcep_controller_pcc_report(pcc_id, path);
	pcep_controller_pcc_sync_done(pcc_id);

	return 0;
}

int pcep_main_start_sync_event_cb(struct path *path, void *arg)
{
	int *pcc_id = (int *)arg;
	path->is_synching = true;
	pcep_controller_pcc_report(*pcc_id, path);
	return 1;
}

int pcep_main_update_path_event(struct thread *thread)
{
	struct event_pcc_path *event = THREAD_ARG(thread);
	struct path *path = event->path;

	XFREE(MTYPE_PCEP, event);

	path_nb_update_path(path);

	return 0;
}


/* ------------ CLI Functions ------------ */

DEFUN_NOSH(pcep_cli_pcc, pcep_cli_pcc_cmd,
	   "pcc [ip A.B.C.D] [port (1024-65535)]",
	   "PCC source ip and port\n"
	   "PCC source ip A.B.C.D\n"
	   "PCC source port port")
{
	struct in_addr pcc_addr;
	uint32_t pcc_port = PCEP_DEFAULT_PORT;
	struct pcc_opts *opts;

	pcc_addr.s_addr = INADDR_ANY;

	if (2 < argc) {
		if (0 == strcmp("ip", argv[1]->arg)) {
			if (!inet_pton(AF_INET, argv[2]->arg, &pcc_addr.s_addr))
				return CMD_ERR_INCOMPLETE;
		} else {
			pcc_port = atoi(argv[2]->arg);
		}
		if (4 < argc) {
			if (0 == strcmp("port", argv[3]->arg)) {
				pcc_port = atoi(argv[4]->arg);
			}
		}
	}

	opts = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	opts->addr = pcc_addr;
	opts->port = pcc_port;

	if (pcep_controller_pcc_update_options(opts))
		return CMD_WARNING;

	VTY_PUSH_CONTEXT_NULL(PCC_NODE);

	return CMD_SUCCESS;
}

DEFUN(pcep_cli_pce_opts, pcep_cli_pce_opts_cmd,
      "pce ip A.B.C.D [port (1024-65535)]",
      "PCE remote ip and port\n"
      "Remote PCE server ip A.B.C.D\n"
      "Remote PCE server port")
{
	struct in_addr pce_addr;
	uint32_t pce_port = PCEP_DEFAULT_PORT;
	struct pce_opts *pce_opts;

	int ip_idx = 2;
	int port_idx = 4;

	if (!inet_pton(AF_INET, argv[ip_idx]->arg, &pce_addr.s_addr))
		return CMD_ERR_INCOMPLETE;

	if (argc > port_idx)
		pce_port = atoi(argv[port_idx]->arg);

	pce_opts = XCALLOC(MTYPE_PCEP, sizeof(*pce_opts));
	pce_opts->addr = pce_addr;
	pce_opts->port = pce_port;

	if (pcep_controller_pce_update_options(0, pce_opts))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(pcep_cli_no_pce, pcep_cli_no_pce_cmd, "no pce", NO_STR "Disable pce\n")
{
	pcep_controller_pcc_disconnect(0);
	return CMD_SUCCESS;
}

DEFUN(pcep_cli_debug, pcep_cli_debug_cmd,
      "[no] debug pathd pcep [path] [message] [pceplib]",
      NO_STR DEBUG_STR
      "pathd debugging\n"
      "pcep basic debugging\n"
      "path structures debugging\n"
      "pcep message debugging\n"
      "pceplib debugging\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");
	int i;

	DEBUG_MODE_SET(&pcep_g->dbg, mode, !no);
	DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC, !no);
	DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH, false);
	DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP, false);
	DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB, false);

	if (no)
		return CMD_SUCCESS;

	if (3 < argc) {
		for (i = (3 + no); i < argc; i++) {
			zlog_debug("ARG: %s", argv[i]->arg);
			if (0 == strcmp("path", argv[i]->arg)) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PATH, true);
			} else if (0 == strcmp("message", argv[i]->arg)) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PCEP, true);
			} else if (0 == strcmp("pceplib", argv[i]->arg)) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PCEPLIB, true);
			}
		}
	}

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
	hook_register(nb_client_debug_set_all, pcep_cli_debug_set_all);

	install_node(&pcc_node);
	install_default(PCC_NODE);
	install_element(CONFIG_NODE, &pcep_cli_debug_cmd);
	install_element(ENABLE_NODE, &pcep_cli_debug_cmd);
	install_element(CONFIG_NODE, &pcep_cli_pcc_cmd);
	install_element(PCC_NODE, &pcep_cli_pce_opts_cmd);
	install_element(PCC_NODE, &pcep_cli_no_pce_cmd);
}

/* ------------ Module Functions ------------ */

int pcep_module_late_init(struct thread_master *tm)
{
	pcep_g->master = tm;

	if (pcep_controller_initialize())
		return 1;

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
