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
#include "pathd/path_pcep_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"


/* PCEP Event Handler */
static void handle_pcep_open(struct ctrl_state *ctrl_state,
			     struct pcc_state *pcc_state,
			     struct pcep_message *msg);
static void handle_pcep_message(struct ctrl_state *ctrl_state,
				struct pcc_state *pcc_state,
				struct pcep_message *msg);
static void handle_pcep_lsp_update(struct ctrl_state *ctrl_state,
				   struct pcc_state *pcc_state,
				   struct pcep_message *msg);
static void handle_pcep_lsp_initiate(struct ctrl_state *ctrl_state,
				     struct pcc_state *pcc_state,
				     struct pcep_message *msg);
static void handle_pcep_comp_reply(struct ctrl_state *ctrl_state,
				   struct pcc_state *pcc_state,
				   struct pcep_message *msg);

/* Internal Functions */
static void update_tag(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state);
static void schedule_reconnect(struct ctrl_state *ctrl_state,
			       struct pcc_state *pcc_state);
static void send_pcep_message(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state,
			      struct pcep_message *msg);
static void send_report(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state, struct path *path);
static void send_comp_request(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state,
			      struct lsp_nb_key *nb_key);

/* Data Structure Helper Functions */
static void lookup_plspid(struct pcc_state *pcc_state, struct path *path);
static void lookup_nbkey(struct pcc_state *pcc_state, struct path *path);
static uint32_t push_req(struct pcc_state *pcc_state, struct lsp_nb_key *nbkey);
static bool pop_req(struct pcc_state *pcc_state, struct path *path);

/* Data Structure Callbacks */
static int plspid_map_cmp(const struct plspid_map_data *a,
			  const struct plspid_map_data *b);
static uint32_t plspid_map_hash(const struct plspid_map_data *e);
static int nbkey_map_cmp(const struct nbkey_map_data *a,
			 const struct nbkey_map_data *b);
static uint32_t nbkey_map_hash(const struct nbkey_map_data *e);
static int req_map_cmp(const struct req_map_data *a,
		       const struct req_map_data *b);
static uint32_t req_map_hash(const struct req_map_data *e);

/* Data Structure Declarations */
DECLARE_HASH(plspid_map, struct plspid_map_data, mi, plspid_map_cmp,
	     plspid_map_hash)
DECLARE_HASH(nbkey_map, struct nbkey_map_data, mi, nbkey_map_cmp,
	     nbkey_map_hash)
DECLARE_HASH(req_map, struct req_map_data, mi, req_map_cmp, req_map_hash)


/* ------------ API Functions ------------ */

struct pcc_state *pcep_pcc_initialize(struct ctrl_state *ctrl_state, int index)
{
	struct pcc_state *pcc_state = XCALLOC(MTYPE_PCEP, sizeof(*pcc_state));

	pcc_state->id = index;
	pcc_state->status = PCEP_PCC_DISCONNECTED;
	pcc_state->next_reqid = 1;
	pcc_state->next_plspid = 524293;
	pcc_state->next_tid = 5;
	pcc_state->next_lspid = 2;

	update_tag(ctrl_state, pcc_state);

	PCEP_DEBUG("%s PCC initialized", pcc_state->tag);

	return pcc_state;
}

void pcep_pcc_finalize(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state)
{
	PCEP_DEBUG("%s PCC finalizing...", pcc_state->tag);

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

	update_tag(ctrl_state, pcc_state);

	return pcep_pcc_enable(ctrl_state, pcc_state);
}

void pcep_pcc_reconnect(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	pcep_pcc_enable(ctrl_state, pcc_state);
}

int pcep_pcc_enable(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	assert(PCEP_PCC_DISCONNECTED == pcc_state->status);
	assert(NULL == pcc_state->sess);

	if (NULL != pcc_state->t_reconnect) {
		thread_cancel(pcc_state->t_reconnect);
		pcc_state->t_reconnect = NULL;
	}

	PCEP_DEBUG("%s PCC connecting", pcc_state->tag);

	pcc_state->sess =
		pcep_lib_connect(pcc_state->pcc_opts, pcc_state->pce_opts);

	if (NULL == pcc_state->sess) {
		if (IS_IPADDR_V6(&pcc_state->pce_opts->addr)) {
			flog_warn(
				EC_PATH_PCEP_LIB_CONNECT,
				"failed to connect to PCE %pI6:%d from %pI6:%d",
				&pcc_state->pce_opts->addr.ipaddr_v6,
				pcc_state->pce_opts->port,
				&pcc_state->pcc_opts->addr.ipaddr_v6,
				pcc_state->pcc_opts->port);
		} else {
			flog_warn(
				EC_PATH_PCEP_LIB_CONNECT,
				"failed to connect to PCE %pI4:%d from %pI4:%d",
				&pcc_state->pce_opts->addr.ipaddr_v4,
				pcc_state->pce_opts->port,
				&pcc_state->pcc_opts->addr.ipaddr_v4,
				pcc_state->pcc_opts->port);
		}
		schedule_reconnect(ctrl_state, pcc_state);
		return 0;
	}

	pcc_state->status = PCEP_PCC_CONNECTING;

	return 0;
}

int pcep_pcc_disable(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	switch (pcc_state->status) {
	case PCEP_PCC_DISCONNECTED:
		return 0;
	case PCEP_PCC_CONNECTING:
	case PCEP_PCC_SYNCHRONIZING:
	case PCEP_PCC_OPERATING:
		PCEP_DEBUG("%s Disconnecting PCC...", pcc_state->tag);
		pcep_lib_disconnect(pcc_state->sess);
		pcc_state->sess = NULL;
		pcc_state->status = PCEP_PCC_DISCONNECTED;
		return 0;
	default:
		return 1;
	}
}

void pcep_pcc_sync_path(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state, struct path *path)
{
	assert(PCEP_PCC_SYNCHRONIZING == pcc_state->status);
	assert(path->is_synching);

	if (pcc_state->caps.is_stateful) {
		/* PCE supports LSP updates, just sync all the path */
		PCEP_DEBUG("%s Synchronizing path %s", pcc_state->tag,
			   path->name);
		send_report(ctrl_state, pcc_state, path);
	} else if (path->is_delegated) {
		/* PCE doesn't supports LSP updates, trigger computation
		 * request instead of synchronizing if the path is to be
		 * delegated.
		 */
		send_comp_request(ctrl_state, pcc_state, &path->nbkey);
	}
}

void pcep_pcc_sync_done(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	if (pcc_state->caps.is_stateful) {
		struct path *path = pcep_new_path();
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
		send_report(ctrl_state, pcc_state, path);
		pcep_free_path(path);
	}

	pcc_state->synchronized = true;
	pcc_state->status = PCEP_PCC_OPERATING;

	PCEP_DEBUG("%s Synchronization done", pcc_state->tag);
}


/* ------------ Pathd event handler ------------ */

void pcep_pcc_pathd_event_handler(struct ctrl_state *ctrl_state,
				  struct pcc_state *pcc_state,
				  enum pcep_pathd_event_type type,
				  struct path *path)
{
	if (!pcc_state->synchronized)
		return;

	switch (type) {
	case PCEP_PATH_CREATED:
		PCEP_DEBUG("%s Candidate path %s created", pcc_state->tag,
			   path->name);
		if (pcc_state->caps.is_stateful)
			send_report(ctrl_state, pcc_state, path);
		else if (path->is_delegated)
			send_comp_request(ctrl_state, pcc_state, &path->nbkey);
		return;
	case PCEP_PATH_UPDATED:
		PCEP_DEBUG("%s Candidate path %s updated", pcc_state->tag,
			   path->name);
		if (pcc_state->caps.is_stateful)
			send_report(ctrl_state, pcc_state, path);
		return;
	case PCEP_PATH_REMOVED:
		PCEP_DEBUG("%s Candidate path %s removed", pcc_state->tag,
			   path->name);
		path->was_removed = true;
		if (pcc_state->caps.is_stateful)
			send_report(ctrl_state, pcc_state, path);
		return;
	default:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unexpected pathd event received by pcc %s: %u",
			  pcc_state->tag, type);
		return;
	}
}


/* ------------ PCEP event handler ------------ */

void pcep_pcc_pcep_event_handler(struct ctrl_state *ctrl_state,
				 struct pcc_state *pcc_state, pcep_event *event)
{
	PCEP_DEBUG("%s Received PCEP event: %s", pcc_state->tag,
		   pcep_event_type_name(event->event_type));
	switch (event->event_type) {
	case PCC_CONNECTED_TO_PCE:
		assert(PCEP_PCC_CONNECTING == pcc_state->status);
		PCEP_DEBUG("%s Connection established", pcc_state->tag);
		pcc_state->status = PCEP_PCC_SYNCHRONIZING;
		pcc_state->retry_count = 0;
		pcc_state->synchronized = false;
		PCEP_DEBUG("%s Starting PCE synchronization", pcc_state->tag);
		pcep_thread_start_sync(ctrl_state, pcc_state->id);
		break;
	case PCC_RCVD_INVALID_OPEN:
		PCEP_DEBUG("%s Received invalid OPEN message", pcc_state->tag);
		PCEP_DEBUG_PCEP("%s PCEP message: %s", pcc_state->tag,
				format_pcep_message(event->message));
		break;
	case PCE_CLOSED_SOCKET:
	case PCE_SENT_PCEP_CLOSE:
	case PCE_DEAD_TIMER_EXPIRED:
	case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
	case PCC_PCEP_SESSION_CLOSED:
	case PCC_RCVD_MAX_INVALID_MSGS:
	case PCC_RCVD_MAX_UNKOWN_MSGS:
		pcep_pcc_disable(ctrl_state, pcc_state);
		schedule_reconnect(ctrl_state, pcc_state);
		break;
	case MESSAGE_RECEIVED:
		PCEP_DEBUG_PCEP("%s Received PCEP message: %s", pcc_state->tag,
				format_pcep_message(event->message));
		if (PCEP_PCC_CONNECTING == pcc_state->status) {
			handle_pcep_open(ctrl_state, pcc_state, event->message);
			break;
		}
		assert(PCEP_PCC_SYNCHRONIZING == pcc_state->status
		       || PCEP_PCC_OPERATING == pcc_state->status);
		handle_pcep_message(ctrl_state, pcc_state, event->message);
		break;
	default:
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEPLIB_EVENT,
			  "Unexpected event from pceplib: %s",
			  format_pcep_event(event));
		break;
	}
}

void handle_pcep_open(struct ctrl_state *ctrl_state,
		      struct pcc_state *pcc_state, struct pcep_message *msg)
{
	assert(PCEP_TYPE_OPEN == msg->msg_header->type);
	pcep_lib_parse_capabilities(msg, &pcc_state->caps);
	if (pcc_state->pcc_opts->force_stateless)
		pcc_state->caps.is_stateful = false;
}

void handle_pcep_message(struct ctrl_state *ctrl_state,
			 struct pcc_state *pcc_state, struct pcep_message *msg)
{
	switch (msg->msg_header->type) {
	case PCEP_TYPE_INITIATE:
		handle_pcep_lsp_initiate(ctrl_state, pcc_state, msg);
		break;
	case PCEP_TYPE_UPDATE:
		handle_pcep_lsp_update(ctrl_state, pcc_state, msg);
		break;
	case PCEP_TYPE_PCREP:
		handle_pcep_comp_reply(ctrl_state, pcc_state, msg);
		break;
	default:
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_MESSAGE,
			  "Unexpected pcep message from pceplib: %s",
			  format_pcep_message(msg));
		break;
	}
}

void handle_pcep_lsp_update(struct ctrl_state *ctrl_state,
			    struct pcc_state *pcc_state,
			    struct pcep_message *msg)
{
	struct path *path;
	path = pcep_lib_parse_path(msg);
	if (IS_IPADDR_V6(&pcc_state->pce_opts->addr)) {
		path->sender.ipa_type = IPADDR_V6;
		memcpy(&path->sender.ipaddr_v6,
		       &pcc_state->pce_opts->addr.ipaddr_v6,
		       sizeof(struct in6_addr));
	} else {
		path->sender.ipa_type = IPADDR_V4;
		path->sender.ipaddr_v4 = pcc_state->pce_opts->addr.ipaddr_v4;
	}
	lookup_nbkey(pcc_state, path);

	PCEP_DEBUG("%s Received LSP update", pcc_state->tag);
	PCEP_DEBUG_PATH("%s", format_path(path));

	pcep_thread_update_path(ctrl_state, pcc_state->id, path);
}

void handle_pcep_lsp_initiate(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state,
			      struct pcep_message *msg)
{
	PCEP_DEBUG("%s Received LSP initiate, not supported yet",
		   pcc_state->tag);
}

void handle_pcep_comp_reply(struct ctrl_state *ctrl_state,
			    struct pcc_state *pcc_state,
			    struct pcep_message *msg)
{
	struct path *path;
	path = pcep_lib_parse_path(msg);
	if (!pop_req(pcc_state, path)) {
		/* TODO: check the rate of bad computation reply and close
		 * the connection if more that a given rate.
		 */
		return;
	}

	PCEP_DEBUG("%s Received computation reply", pcc_state->tag);
	PCEP_DEBUG_PATH("%s", format_path(path));

	pcep_thread_update_path(ctrl_state, pcc_state->id, path);
}


/* ------------ Internal Functions ------------ */

void update_tag(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	if (NULL != pcc_state->pce_opts) {
		snprintfrr(pcc_state->tag, sizeof(pcc_state->tag),
			   "%pI4:%i (%u)", &pcc_state->pce_opts->addr,
			   pcc_state->pce_opts->port, pcc_state->id);
	} else {
		snprintfrr(pcc_state->tag, sizeof(pcc_state->tag), "(%u)",
			   pcc_state->id);
	}
}

void schedule_reconnect(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	pcc_state->retry_count++;
	pcep_thread_schedule_reconnect(ctrl_state, pcc_state->id,
				       pcc_state->retry_count,
				       &pcc_state->t_reconnect);
}

void send_pcep_message(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state, struct pcep_message *msg)
{
	PCEP_DEBUG_PCEP("%s Sending PCEP message: %s", pcc_state->tag,
			format_pcep_message(msg));
	send_message(pcc_state->sess, msg, true);
}

void send_report(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state,
		 struct path *path)
{
	struct pcep_message *report;

	if (IS_IPADDR_V6(&pcc_state->pcc_opts->addr)) {
		path->sender.ipa_type = IPADDR_V6;
		memcpy(&path->sender.ipaddr_v6,
		       &pcc_state->pcc_opts->addr.ipaddr_v6,
		       sizeof(struct in6_addr));

	} else {
		path->sender.ipa_type = IPADDR_V4;
		path->sender.ipaddr_v4 = pcc_state->pcc_opts->addr.ipaddr_v4;
	}

	lookup_plspid(pcc_state, path);

	PCEP_DEBUG_PATH("%s Sending path %s: %s", pcc_state->tag, path->name,
			format_path(path));
	report = pcep_lib_format_report(path);
	send_pcep_message(ctrl_state, pcc_state, report);
}

void send_comp_request(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state, struct lsp_nb_key *nbkey)
{
	uint32_t reqid;
	struct pcep_message *msg;
	struct ipaddr src;

	/* The source address need to be defined explicitly for now */
	if (IS_IPADDR_V6(&pcc_state->pcc_opts->addr)) {
		assert(0
		       != memcmp(&in6addr_any,
				 &pcc_state->pcc_opts->addr.ipaddr_v6,
				 sizeof(struct in6_addr)));
	} else {
		assert(INADDR_ANY
		       != pcc_state->pcc_opts->addr.ipaddr_v4.s_addr);
	}

	reqid = push_req(pcc_state, nbkey);
	/* TODO: Add a timer to retry the computation request */

	PCEP_DEBUG("%s Sending computation request for path from %pI4 to %pI4",
		   pcc_state->tag, &pcc_state->pcc_opts->addr.ipaddr_v4,
		   &nbkey->endpoint.ipaddr_v4);

	src.ipa_type = pcc_state->pcc_opts->addr.ipa_type;
	if (IS_IPADDR_V6(&pcc_state->pcc_opts->addr)) {
		memcpy(&src.ipaddr_v6, &pcc_state->pcc_opts->addr.ipaddr_v6,
		       sizeof(struct in6_addr));
	} else {
		src.ipaddr_v4.s_addr =
			pcc_state->pcc_opts->addr.ipaddr_v4.s_addr;
	}

	msg = pcep_lib_format_request(reqid, &src, &nbkey->endpoint);
	send_pcep_message(ctrl_state, pcc_state, msg);
}


/* ------------ Data Structure Helper Functions ------------ */

void lookup_plspid(struct pcc_state *pcc_state, struct path *path)
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
			plspid_mapping->lspid = pcc_state->next_lspid;
			plspid_mapping->tid = pcc_state->next_tid;
			plspid_map_add(&pcc_state->plspid_map, plspid_mapping);
			nbkey_mapping =
				XCALLOC(MTYPE_PCEP, sizeof(*nbkey_mapping));
			nbkey_mapping->nbkey = key.nbkey;
			nbkey_mapping->plspid = pcc_state->next_plspid;
			nbkey_mapping->lspid = pcc_state->next_lspid;
			nbkey_mapping->tid = pcc_state->next_tid;
			nbkey_map_add(&pcc_state->nbkey_map, nbkey_mapping);
			pcc_state->next_plspid++;
			pcc_state->next_tid++;
			pcc_state->next_lspid++;
			// FIXME: Send some error to the PCE isntead of crashing
			assert(1048576 > pcc_state->next_plspid);
		}
		path->plsp_id = plspid_mapping->plspid;
		path->lsp_id = plspid_mapping->lspid;
		path->tunnel_id = plspid_mapping->tid;
	}
}

void lookup_nbkey(struct pcc_state *pcc_state, struct path *path)
{
	struct nbkey_map_data key, *mapping;
	// TODO: Should give an error to the PCE instead of crashing
	assert(0 != path->plsp_id);
	key.plspid = path->plsp_id;
	mapping = nbkey_map_find(&pcc_state->nbkey_map, &key);
	assert(NULL != mapping);
	path->nbkey = mapping->nbkey;
	path->tunnel_id = mapping->tid;
}

uint32_t push_req(struct pcc_state *pcc_state, struct lsp_nb_key *nbkey)
{
	struct req_map_data *req_mapping;
	uint32_t reqid = pcc_state->next_reqid;

	req_mapping = XCALLOC(MTYPE_PCEP, sizeof(*req_mapping));
	req_mapping->reqid = reqid;
	req_mapping->nbkey = *nbkey;

	assert(NULL == req_map_find(&pcc_state->req_map, req_mapping));
	req_map_add(&pcc_state->req_map, req_mapping);

	pcc_state->next_reqid += 1;
	/* Wrapping is allowed, but 0 is not a valid id */
	if (0 == pcc_state->next_reqid)
		pcc_state->next_reqid = 1;

	return reqid;
}

bool pop_req(struct pcc_state *pcc_state, struct path *path)
{
	struct req_map_data key, *req_mapping;

	key.reqid = path->req_id;

	req_mapping = req_map_find(&pcc_state->req_map, &key);
	if (NULL == req_mapping)
		return false;

	req_map_del(&pcc_state->req_map, req_mapping);

	path->nbkey = req_mapping->nbkey;

	XFREE(MTYPE_PCEP, req_mapping);
	return true;
}


/* ------------ Data Structure Callbacks ------------ */

#define CMP_RETURN(A, B)                                                       \
	if (A != B)                                                            \
	return (A < B) ? -1 : 1

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

static int req_map_cmp(const struct req_map_data *a,
		       const struct req_map_data *b)
{
	CMP_RETURN(a->reqid, b->reqid);
	return 0;
}

static uint32_t req_map_hash(const struct req_map_data *e)
{
	return e->reqid;
}
