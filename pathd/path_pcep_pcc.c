// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

/* TODOS AND KNOWN ISSUES:
	- Delete mapping from NB keys to PLSPID when an LSP is deleted either
	  by the PCE or by NB.
	- Revert the hacks to work around ODL requiring a report with
	  operational status DOWN when an LSP is activated.
	- Enforce only the PCE a policy has been delegated to can update it.
	- If the router-id is used because the PCC IP is not specified
	  (either IPv4 or IPv6), the connection to the PCE is not reset
	  when the router-id changes.
*/

#include <zebra.h>

#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"

#include "pathd/pathd.h"
#include "pathd/path_zebra.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_config.h"
#include "pathd/path_pcep_debug.h"


/* The number of time we will skip connecting if we are missing the PCC
 * address for an inet family different from the selected transport one*/
#define OTHER_FAMILY_MAX_RETRIES 4
#define MAX_ERROR_MSG_SIZE 256
#define MAX_COMPREQ_TRIES 3

pthread_mutex_t g_pcc_info_mtx = PTHREAD_MUTEX_INITIALIZER;

/* PCEP Event Handler */
static void handle_pcep_open(struct ctrl_state *ctrl_state,
			     struct pcc_state *pcc_state,
			     struct pcep_message *msg);
static void handle_pcep_message(struct ctrl_state *ctrl_state,
				struct pcc_state *pcc_state,
				struct pcep_message *msg);
static void handle_pcep_lsp_initiate(struct ctrl_state *ctrl_state,
				     struct pcc_state *pcc_state,
				     struct pcep_message *msg);
static void handle_pcep_lsp_update(struct ctrl_state *ctrl_state,
				   struct pcc_state *pcc_state,
				   struct pcep_message *msg);
static void continue_pcep_lsp_update(struct ctrl_state *ctrl_state,
				     struct pcc_state *pcc_state,
				     struct path *path, void *payload);
static void handle_pcep_comp_reply(struct ctrl_state *ctrl_state,
				   struct pcc_state *pcc_state,
				   struct pcep_message *msg);

/* Internal Functions */
static const char *ipaddr_type_name(struct ipaddr *addr);
static bool filter_path(struct pcc_state *pcc_state, struct path *path);
static void select_pcc_addresses(struct pcc_state *pcc_state);
static void select_transport_address(struct pcc_state *pcc_state);
static void update_tag(struct pcc_state *pcc_state);
static void update_originator(struct pcc_state *pcc_state);
static void schedule_reconnect(struct ctrl_state *ctrl_state,
			       struct pcc_state *pcc_state);
static void schedule_session_timeout(struct ctrl_state *ctrl_state,
				     struct pcc_state *pcc_state);
static void cancel_session_timeout(struct ctrl_state *ctrl_state,
				   struct pcc_state *pcc_state);
static void send_pcep_message(struct pcc_state *pcc_state,
			      struct pcep_message *msg);
static void send_pcep_error(struct pcc_state *pcc_state,
			    enum pcep_error_type error_type,
			    enum pcep_error_value error_value,
			    struct path *trigger_path);
static void send_report(struct pcc_state *pcc_state, struct path *path);
static void send_comp_request(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state,
			      struct req_entry *req);
static void cancel_comp_requests(struct ctrl_state *ctrl_state,
				 struct pcc_state *pcc_state);
static void cancel_comp_request(struct ctrl_state *ctrl_state,
				struct pcc_state *pcc_state,
				struct req_entry *req);
static void specialize_outgoing_path(struct pcc_state *pcc_state,
				     struct path *path);
static void specialize_incoming_path(struct pcc_state *pcc_state,
				     struct path *path);
static bool validate_incoming_path(struct pcc_state *pcc_state,
				   struct path *path, char *errbuff,
				   size_t buffsize);
static void set_pcc_address(struct pcc_state *pcc_state,
			    struct lsp_nb_key *nbkey, struct ipaddr *addr);
static int compare_pcc_opts(struct pcc_opts *lhs, struct pcc_opts *rhs);
static int compare_pce_opts(struct pce_opts *lhs, struct pce_opts *rhs);
static int get_previous_best_pce(struct pcc_state **pcc);
static int get_best_pce(struct pcc_state **pcc);
static int get_pce_count_connected(struct pcc_state **pcc);
static bool update_best_pce(struct pcc_state **pcc, int best);

/* Data Structure Helper Functions */
static void lookup_plspid(struct pcc_state *pcc_state, struct path *path);
static void lookup_nbkey(struct pcc_state *pcc_state, struct path *path);
static void free_req_entry(struct req_entry *req);
static struct req_entry *push_new_req(struct pcc_state *pcc_state,
				      struct path *path);
static void repush_req(struct pcc_state *pcc_state, struct req_entry *req);
static struct req_entry *pop_req(struct pcc_state *pcc_state, uint32_t reqid);
static struct req_entry *pop_req_no_reqid(struct pcc_state *pcc_state,
					  uint32_t reqid);
static bool add_reqid_mapping(struct pcc_state *pcc_state, struct path *path);
static void remove_reqid_mapping(struct pcc_state *pcc_state,
				 struct path *path);
static uint32_t lookup_reqid(struct pcc_state *pcc_state, struct path *path);
static bool has_pending_req_for(struct pcc_state *pcc_state, struct path *path);

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
	     plspid_map_hash);
DECLARE_HASH(nbkey_map, struct nbkey_map_data, mi, nbkey_map_cmp,
	     nbkey_map_hash);
DECLARE_HASH(req_map, struct req_map_data, mi, req_map_cmp, req_map_hash);

static inline int req_entry_compare(const struct req_entry *a,
				    const struct req_entry *b)
{
	return a->path->req_id - b->path->req_id;
}
RB_GENERATE(req_entry_head, req_entry, entry, req_entry_compare)


/* ------------ API Functions ------------ */

struct pcc_state *pcep_pcc_initialize(struct ctrl_state *ctrl_state, int index)
{
	struct pcc_state *pcc_state = XCALLOC(MTYPE_PCEP, sizeof(*pcc_state));

	pcc_state->id = index;
	pcc_state->status = PCEP_PCC_DISCONNECTED;
	pcc_state->next_reqid = 1;
	pcc_state->next_plspid = 1;

	RB_INIT(req_entry_head, &pcc_state->requests);

	update_tag(pcc_state);
	update_originator(pcc_state);

	PCEP_DEBUG("%s PCC initialized", pcc_state->tag);

	return pcc_state;
}

void pcep_pcc_finalize(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state)
{
	PCEP_DEBUG("%s PCC finalizing...", pcc_state->tag);

	pcep_pcc_disable(ctrl_state, pcc_state);

	if (pcc_state->pcc_opts != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->pcc_opts);
		pcc_state->pcc_opts = NULL;
	}
	if (pcc_state->pce_opts != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->pce_opts);
		pcc_state->pce_opts = NULL;
	}
	if (pcc_state->originator != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->originator);
		pcc_state->originator = NULL;
	}

	if (pcc_state->t_reconnect != NULL) {
		event_cancel(&pcc_state->t_reconnect);
		pcc_state->t_reconnect = NULL;
	}

	if (pcc_state->t_update_best != NULL) {
		event_cancel(&pcc_state->t_update_best);
		pcc_state->t_update_best = NULL;
	}

	if (pcc_state->t_session_timeout != NULL) {
		event_cancel(&pcc_state->t_session_timeout);
		pcc_state->t_session_timeout = NULL;
	}

	XFREE(MTYPE_PCEP, pcc_state);
}

int compare_pcc_opts(struct pcc_opts *lhs, struct pcc_opts *rhs)
{
	int retval;

	if (lhs == NULL) {
		return 1;
	}

	if (rhs == NULL) {
		return -1;
	}

	retval = lhs->port - rhs->port;
	if (retval != 0) {
		return retval;
	}

	retval = lhs->msd - rhs->msd;
	if (retval != 0) {
		return retval;
	}

	if (IS_IPADDR_V4(&lhs->addr)) {
		retval = memcmp(&lhs->addr.ipaddr_v4, &rhs->addr.ipaddr_v4,
				sizeof(lhs->addr.ipaddr_v4));
		if (retval != 0) {
			return retval;
		}
	} else if (IS_IPADDR_V6(&lhs->addr)) {
		retval = memcmp(&lhs->addr.ipaddr_v6, &rhs->addr.ipaddr_v6,
				sizeof(lhs->addr.ipaddr_v6));
		if (retval != 0) {
			return retval;
		}
	}

	return 0;
}

int compare_pce_opts(struct pce_opts *lhs, struct pce_opts *rhs)
{
	if (lhs == NULL) {
		return 1;
	}

	if (rhs == NULL) {
		return -1;
	}

	int retval = lhs->port - rhs->port;
	if (retval != 0) {
		return retval;
	}

	retval = strcmp(lhs->pce_name, rhs->pce_name);
	if (retval != 0) {
		return retval;
	}

	retval = lhs->precedence - rhs->precedence;
	if (retval != 0) {
		return retval;
	}

	retval = memcmp(&lhs->addr, &rhs->addr, sizeof(lhs->addr));
	if (retval != 0) {
		return retval;
	}

	return 0;
}

int pcep_pcc_update(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state,
		    struct pcc_opts *pcc_opts, struct pce_opts *pce_opts)
{
	int ret = 0;

	// If the options did not change, then there is nothing to do
	if ((compare_pce_opts(pce_opts, pcc_state->pce_opts) == 0)
	    && (compare_pcc_opts(pcc_opts, pcc_state->pcc_opts) == 0)) {
		return ret;
	}

	if ((ret = pcep_pcc_disable(ctrl_state, pcc_state))) {
		XFREE(MTYPE_PCEP, pcc_opts);
		XFREE(MTYPE_PCEP, pce_opts);
		return ret;
	}

	if (pcc_state->pcc_opts != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->pcc_opts);
	}
	if (pcc_state->pce_opts != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->pce_opts);
	}

	pcc_state->pcc_opts = pcc_opts;
	pcc_state->pce_opts = pce_opts;

	if (IS_IPADDR_V4(&pcc_opts->addr)) {
		pcc_state->pcc_addr_v4 = pcc_opts->addr.ipaddr_v4;
		SET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4);
	} else {
		UNSET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4);
	}

	if (IS_IPADDR_V6(&pcc_opts->addr)) {
		memcpy(&pcc_state->pcc_addr_v6, &pcc_opts->addr.ipaddr_v6,
		       sizeof(struct in6_addr));
		SET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6);
	} else {
		UNSET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6);
	}

	update_tag(pcc_state);
	update_originator(pcc_state);

	return pcep_pcc_enable(ctrl_state, pcc_state);
}

void pcep_pcc_reconnect(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	if (pcc_state->status == PCEP_PCC_DISCONNECTED)
		pcep_pcc_enable(ctrl_state, pcc_state);
}

int pcep_pcc_enable(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	assert(pcc_state->status == PCEP_PCC_DISCONNECTED);
	assert(pcc_state->sess == NULL);

	if (pcc_state->t_reconnect != NULL) {
		event_cancel(&pcc_state->t_reconnect);
		pcc_state->t_reconnect = NULL;
	}

	select_transport_address(pcc_state);

	/* Even though we are connecting using IPv6. we want to have an IPv4
	 * address so we can handle candidate path with IPv4 endpoints */
	if (!CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4)) {
		if (pcc_state->retry_count < OTHER_FAMILY_MAX_RETRIES) {
			flog_warn(EC_PATH_PCEP_MISSING_SOURCE_ADDRESS,
				  "skipping connection to PCE %pIA:%d due to missing PCC IPv4 address",
				  &pcc_state->pce_opts->addr,
				  pcc_state->pce_opts->port);
			schedule_reconnect(ctrl_state, pcc_state);
			return 0;
		} else {
			flog_warn(EC_PATH_PCEP_MISSING_SOURCE_ADDRESS,
				  "missing IPv4 PCC address, IPv4 candidate paths will be ignored");
		}
	}

	/* Even though we are connecting using IPv4. we want to have an IPv6
	 * address so we can handle candidate path with IPv6 endpoints */
	if (!CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6)) {
		if (pcc_state->retry_count < OTHER_FAMILY_MAX_RETRIES) {
			flog_warn(EC_PATH_PCEP_MISSING_SOURCE_ADDRESS,
				  "skipping connection to PCE %pIA:%d due to missing PCC IPv6 address",
				  &pcc_state->pce_opts->addr,
				  pcc_state->pce_opts->port);
			schedule_reconnect(ctrl_state, pcc_state);
			return 0;
		} else {
			flog_warn(EC_PATH_PCEP_MISSING_SOURCE_ADDRESS,
				  "missing IPv6 PCC address, IPv6 candidate paths will be ignored");
		}
	}

	/* Even if the maximum retries to try to have all the familly addresses
	 * have been spent, we still need the one for the transport familly */
	if (pcc_state->pcc_addr_tr.ipa_type == IPADDR_NONE) {
		flog_warn(EC_PATH_PCEP_MISSING_SOURCE_ADDRESS,
			  "skipping connection to PCE %pIA:%d due to missing PCC address",
			  &pcc_state->pce_opts->addr,
			  pcc_state->pce_opts->port);
		schedule_reconnect(ctrl_state, pcc_state);
		return 0;
	}

	PCEP_DEBUG("%s PCC connecting", pcc_state->tag);
	pcc_state->sess = pcep_lib_connect(
		&pcc_state->pcc_addr_tr, pcc_state->pcc_opts->port,
		&pcc_state->pce_opts->addr, pcc_state->pce_opts->port,
		pcc_state->pcc_opts->msd, &pcc_state->pce_opts->config_opts);

	if (pcc_state->sess == NULL) {
		flog_warn(EC_PATH_PCEP_LIB_CONNECT,
			  "failed to connect to PCE %pIA:%d from %pIA:%d",
			  &pcc_state->pce_opts->addr,
			  pcc_state->pce_opts->port,
			  &pcc_state->pcc_addr_tr,
			  pcc_state->pcc_opts->port);
		schedule_reconnect(ctrl_state, pcc_state);
		return 0;
	}

	// In case some best pce alternative were waiting to activate
	if (pcc_state->t_update_best != NULL) {
		event_cancel(&pcc_state->t_update_best);
		pcc_state->t_update_best = NULL;
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
		cancel_comp_requests(ctrl_state, pcc_state);
		pcep_lib_disconnect(pcc_state->sess);
		/* No need to remove if any PCEs is connected */
		if (get_pce_count_connected(ctrl_state->pcc) == 0) {
			pcep_thread_remove_candidate_path_segments(ctrl_state,
								   pcc_state);
		}
		pcc_state->sess = NULL;
		pcc_state->status = PCEP_PCC_DISCONNECTED;
		return 0;
	case PCEP_PCC_INITIALIZED:
		return 1;
	}

	assert(!"Reached end of function where we are not expecting to");
}

void pcep_pcc_sync_path(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state, struct path *path)
{
	if (pcc_state->status == PCEP_PCC_SYNCHRONIZING) {
		path->is_synching = true;
	} else if (pcc_state->status == PCEP_PCC_OPERATING)
		path->is_synching = false;
	else
		return;

	path->go_active = true;

	/* Accumulate the dynamic paths without any LSP so computation
	 * requests can be performed after synchronization */
	if ((path->type == SRTE_CANDIDATE_TYPE_DYNAMIC)
	    && (path->first_hop == NULL)
	    && !has_pending_req_for(pcc_state, path)) {
		PCEP_DEBUG("%s Scheduling computation request for path %s",
			   pcc_state->tag, path->name);
		push_new_req(pcc_state, path);
		return;
	}

	/* Synchronize the path if the PCE supports LSP updates and the
	 * endpoint address familly is supported */
	if (pcc_state->caps.is_stateful) {
		if (filter_path(pcc_state, path)) {
			PCEP_DEBUG("%s Synchronizing path %s", pcc_state->tag,
				   path->name);
			send_report(pcc_state, path);
		} else {
			PCEP_DEBUG(
				"%s Skipping %s candidate path %s synchronization",
				pcc_state->tag,
				ipaddr_type_name(&path->nbkey.endpoint),
				path->name);
		}
	}
}

void pcep_pcc_sync_done(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	struct req_entry *req;

	if (pcc_state->status != PCEP_PCC_SYNCHRONIZING
	    && pcc_state->status != PCEP_PCC_OPERATING)
		return;

	if (pcc_state->caps.is_stateful
	    && pcc_state->status == PCEP_PCC_SYNCHRONIZING) {
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
				      .first_hop = NULL,
				      .first_metric = NULL};
		send_report(pcc_state, path);
		pcep_free_path(path);
	}

	pcc_state->synchronized = true;
	pcc_state->status = PCEP_PCC_OPERATING;

	PCEP_DEBUG("%s Synchronization done", pcc_state->tag);

	/* Start the computation request accumulated during synchronization */
	RB_FOREACH (req, req_entry_head, &pcc_state->requests) {
		send_comp_request(ctrl_state, pcc_state, req);
	}
}

void pcep_pcc_send_report(struct ctrl_state *ctrl_state,
			  struct pcc_state *pcc_state, struct path *path,
			  bool is_stable)
{
	if ((pcc_state->status != PCEP_PCC_OPERATING)
	    || (!pcc_state->caps.is_stateful)) {
		pcep_free_path(path);
		return;
	}

	PCEP_DEBUG("(%s)%s Send report for candidate path %s", __func__,
		   pcc_state->tag, path->name);

	/* ODL and Cisco requires the first reported
	 * LSP to have a DOWN status, the later status changes
	 * will be comunicated through hook calls.
	 */
	enum pcep_lsp_operational_status real_status = path->status;
	path->status = PCEP_LSP_OPERATIONAL_DOWN;
	send_report(pcc_state, path);

	/* If no update is expected and the real status wasn't down, we need to
	 * send a second report with the real status */
	if (is_stable && (real_status != PCEP_LSP_OPERATIONAL_DOWN)) {
		PCEP_DEBUG("(%s)%s Send report for candidate path (!DOWN) %s",
			   __func__, pcc_state->tag, path->name);
		path->status = real_status;
		send_report(pcc_state, path);
	}

	pcep_free_path(path);
}


void pcep_pcc_send_error(struct ctrl_state *ctrl_state,
			 struct pcc_state *pcc_state, struct pcep_error *error,
			 bool sub_type)
{

	PCEP_DEBUG("(%s) Send error after PcInitiated ", __func__);


	send_pcep_error(pcc_state, error->error_type, error->error_value,
			error->path);
	pcep_free_path(error->path);
	XFREE(MTYPE_PCEP, error);
}
/* ------------ Timeout handler ------------ */

void pcep_pcc_timeout_handler(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state,
			      enum pcep_ctrl_timeout_type type, void *param)
{
	struct req_entry *req;

	switch (type) {
	case TO_COMPUTATION_REQUEST:
		assert(param != NULL);
		req = (struct req_entry *)param;
		pop_req(pcc_state, req->path->req_id);
		flog_warn(EC_PATH_PCEP_COMPUTATION_REQUEST_TIMEOUT,
			  "Computation request %d timeout", req->path->req_id);
		cancel_comp_request(ctrl_state, pcc_state, req);
		if (req->retry_count++ < MAX_COMPREQ_TRIES) {
			repush_req(pcc_state, req);
			send_comp_request(ctrl_state, pcc_state, req);
			return;
		}
		if (pcc_state->caps.is_stateful) {
			struct path *path;
			PCEP_DEBUG(
				"%s Delegating undefined dynamic path %s to PCE %s",
				pcc_state->tag, req->path->name,
				pcc_state->originator);
			path = pcep_copy_path(req->path);
			path->is_delegated = true;
			send_report(pcc_state, path);
			free_req_entry(req);
		}
		break;
	case TO_UNDEFINED:
	case TO_MAX:
		break;
	}
}


/* ------------ Pathd event handler ------------ */

void pcep_pcc_pathd_event_handler(struct ctrl_state *ctrl_state,
				  struct pcc_state *pcc_state,
				  enum pcep_pathd_event_type type,
				  struct path *path)
{
	struct req_entry *req;

	if (pcc_state->status != PCEP_PCC_OPERATING)
		return;

	/* Skipping candidate path with endpoint that do not match the
	 * configured or deduced PCC IP version */
	if (!filter_path(pcc_state, path)) {
		PCEP_DEBUG("%s Skipping %s candidate path %s event",
			   pcc_state->tag,
			   ipaddr_type_name(&path->nbkey.endpoint), path->name);
		return;
	}

	switch (type) {
	case PCEP_PATH_CREATED:
		if (has_pending_req_for(pcc_state, path)) {
			PCEP_DEBUG(
				"%s Candidate path %s created, computation request already sent",
				pcc_state->tag, path->name);
			return;
		}
		PCEP_DEBUG("%s Candidate path %s created", pcc_state->tag,
			   path->name);
		if ((path->first_hop == NULL)
		    && (path->type == SRTE_CANDIDATE_TYPE_DYNAMIC)) {
			req = push_new_req(pcc_state, path);
			send_comp_request(ctrl_state, pcc_state, req);
		} else if (pcc_state->caps.is_stateful)
			send_report(pcc_state, path);
		return;
	case PCEP_PATH_UPDATED:
		PCEP_DEBUG("%s Candidate path %s updated", pcc_state->tag,
			   path->name);
		if (pcc_state->caps.is_stateful)
			send_report(pcc_state, path);
		return;
	case PCEP_PATH_REMOVED:
		PCEP_DEBUG("%s Candidate path %s removed", pcc_state->tag,
			   path->name);
		path->was_removed = true;
		/* Removed as response to a PcInitiated 'R'emove*/
		/* RFC 8281 #5.4 LSP Deletion*/
		path->do_remove = path->was_removed;
		if (pcc_state->caps.is_stateful)
			send_report(pcc_state, path);
		return;
	case PCEP_PATH_UNDEFINED:
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
		cancel_session_timeout(ctrl_state, pcc_state);
		pcep_pcc_calculate_best_pce(ctrl_state->pcc);
		pcep_thread_start_sync(ctrl_state, pcc_state->id);
		break;
	case PCC_SENT_INVALID_OPEN:
		PCEP_DEBUG("%s Sent invalid OPEN message", pcc_state->tag);
		PCEP_DEBUG(
			"%s Reconciling values: keep alive (%d) dead timer (%d) seconds ",
			pcc_state->tag,
			pcc_state->sess->pcc_config
				.keep_alive_pce_negotiated_timer_seconds,
			pcc_state->sess->pcc_config
				.dead_timer_pce_negotiated_seconds);
		pcc_state->pce_opts->config_opts.keep_alive_seconds =
			pcc_state->sess->pcc_config
				.keep_alive_pce_negotiated_timer_seconds;
		pcc_state->pce_opts->config_opts.dead_timer_seconds =
			pcc_state->sess->pcc_config
				.dead_timer_pce_negotiated_seconds;
		break;

	case PCC_RCVD_INVALID_OPEN:
		PCEP_DEBUG("%s Received invalid OPEN message", pcc_state->tag);
		PCEP_DEBUG_PCEP("%s PCEP message: %s", pcc_state->tag,
				format_pcep_message(event->message));
		break;
	case PCE_DEAD_TIMER_EXPIRED:
	case PCE_CLOSED_SOCKET:
	case PCE_SENT_PCEP_CLOSE:
	case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
	case PCC_PCEP_SESSION_CLOSED:
	case PCC_RCVD_MAX_INVALID_MSGS:
	case PCC_RCVD_MAX_UNKOWN_MSGS:
		pcep_pcc_disable(ctrl_state, pcc_state);
		schedule_reconnect(ctrl_state, pcc_state);
		schedule_session_timeout(ctrl_state, pcc_state);
		break;
	case MESSAGE_RECEIVED:
		PCEP_DEBUG_PCEP("%s Received PCEP message: %s", pcc_state->tag,
				format_pcep_message(event->message));
		if (pcc_state->status == PCEP_PCC_CONNECTING) {
			if (event->message->msg_header->type == PCEP_TYPE_OPEN)
				handle_pcep_open(ctrl_state, pcc_state,
						 event->message);
			break;
		}
		assert(pcc_state->status == PCEP_PCC_SYNCHRONIZING
		       || pcc_state->status == PCEP_PCC_OPERATING);
		handle_pcep_message(ctrl_state, pcc_state, event->message);
		break;
	case PCC_CONNECTION_FAILURE:
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEPLIB_EVENT,
			  "Unexpected event from pceplib: %s",
			  format_pcep_event(event));
		break;
	}
}


/*------------------ Multi-PCE --------------------- */

/* Internal util function, returns true if sync is necessary, false otherwise */
bool update_best_pce(struct pcc_state **pcc, int best)
{
	PCEP_DEBUG(" recalculating pce precedence ");
	if (best) {
		struct pcc_state *best_pcc_state =
			pcep_pcc_get_pcc_by_id(pcc, best);
		if (best_pcc_state->previous_best != best_pcc_state->is_best) {
			PCEP_DEBUG(" %s Resynch best (%i) previous best (%i)",
				   best_pcc_state->tag, best_pcc_state->id,
				   best_pcc_state->previous_best);
			return true;
		} else {
			PCEP_DEBUG(
				" %s No Resynch best (%i) previous best (%i)",
				best_pcc_state->tag, best_pcc_state->id,
				best_pcc_state->previous_best);
		}
	} else {
		PCEP_DEBUG(" No best pce available, all pce seem disconnected");
	}

	return false;
}

int get_best_pce(struct pcc_state **pcc)
{
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts) {
			if (pcc[i]->is_best == true) {
				return pcc[i]->id;
			}
		}
	}
	return 0;
}

int get_pce_count_connected(struct pcc_state **pcc)
{
	int count = 0;
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts
		    && pcc[i]->status != PCEP_PCC_DISCONNECTED) {
			count++;
		}
	}
	return count;
}

int get_previous_best_pce(struct pcc_state **pcc)
{
	int previous_best_pce = -1;

	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts && pcc[i]->previous_best == true
		    && pcc[i]->status != PCEP_PCC_DISCONNECTED) {
			previous_best_pce = i;
			break;
		}
	}
	return previous_best_pce != -1 ? pcc[previous_best_pce]->id : 0;
}

/* Called by path_pcep_controller EV_REMOVE_PCC
 * Event handler when a PCC is removed. */
int pcep_pcc_multi_pce_remove_pcc(struct ctrl_state *ctrl_state,
				  struct pcc_state **pcc)
{
	int new_best_pcc_id = -1;
	new_best_pcc_id = pcep_pcc_calculate_best_pce(pcc);
	if (new_best_pcc_id) {
		if (update_best_pce(ctrl_state->pcc, new_best_pcc_id) == true) {
			pcep_thread_start_sync(ctrl_state, new_best_pcc_id);
		}
	}

	return 0;
}

/* Called by path_pcep_controller EV_SYNC_PATH
 * Event handler when a path is sync'd. */
int pcep_pcc_multi_pce_sync_path(struct ctrl_state *ctrl_state, int pcc_id,
				 struct pcc_state **pcc)
{
	int previous_best_pcc_id = -1;

	if (pcc_id == get_best_pce(pcc)) {
		previous_best_pcc_id = get_previous_best_pce(pcc);
		if (previous_best_pcc_id != 0) {
			/* while adding new pce, path has to resync to the
			 * previous best. pcep_thread_start_sync() will be
			 * called by the calling function */
			if (update_best_pce(ctrl_state->pcc,
					    previous_best_pcc_id)
			    == true) {
				cancel_comp_requests(
					ctrl_state,
					pcep_pcc_get_pcc_by_id(
						pcc, previous_best_pcc_id));
				pcep_thread_start_sync(ctrl_state,
						       previous_best_pcc_id);
			}
		}
	}

	return 0;
}

/* Called by path_pcep_controller when the TM_CALCULATE_BEST_PCE
 * timer expires */
int pcep_pcc_timer_update_best_pce(struct ctrl_state *ctrl_state, int pcc_id)
{
	int ret = 0;
	/* resync whatever was the new best */
	int prev_best = get_best_pce(ctrl_state->pcc);
	int best_id = pcep_pcc_calculate_best_pce(ctrl_state->pcc);
	if (best_id && prev_best != best_id) { // Avoid Multiple call
		struct pcc_state *pcc_state =
			pcep_pcc_get_pcc_by_id(ctrl_state->pcc, best_id);
		if (update_best_pce(ctrl_state->pcc, pcc_state->id) == true) {
			pcep_thread_start_sync(ctrl_state, pcc_state->id);
		}
	}

	return ret;
}

/* Called by path_pcep_controller::pcep_thread_event_update_pce_options()
 * Returns the best PCE id */
int pcep_pcc_calculate_best_pce(struct pcc_state **pcc)
{
	int best_precedence = 255; // DEFAULT_PCE_PRECEDENCE;
	int best_pce = -1;
	int one_connected_pce = -1;
	int previous_best_pce = -1;
	int step_0_best = -1;
	int step_0_previous = -1;
	int pcc_count = 0;

	// Get state
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts) {
			zlog_debug(
				"multi-pce: calculate all : i (%i) is_best (%i) previous_best (%i)   ",
				i, pcc[i]->is_best, pcc[i]->previous_best);
			pcc_count++;

			if (pcc[i]->is_best == true) {
				step_0_best = i;
			}
			if (pcc[i]->previous_best == true) {
				step_0_previous = i;
			}
		}
	}

	if (!pcc_count) {
		return 0;
	}

	// Calculate best
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts
		    && pcc[i]->status != PCEP_PCC_DISCONNECTED) {
			one_connected_pce = i; // In case none better
			if (pcc[i]->pce_opts->precedence <= best_precedence) {
				if (best_pce != -1
				    && pcc[best_pce]->pce_opts->precedence
					       == pcc[i]->pce_opts
							  ->precedence) {
					if (ipaddr_cmp(
						    &pcc[i]->pce_opts->addr,
						    &pcc[best_pce]
							     ->pce_opts->addr)
					    > 0)
						// collide of precedences so
						// compare ip
						best_pce = i;
				} else {
					if (!pcc[i]->previous_best) {
						best_precedence =
							pcc[i]->pce_opts
								->precedence;
						best_pce = i;
					}
				}
			}
		}
	}

	zlog_debug(
		"multi-pce: calculate data : sb (%i) sp (%i) oc (%i) b (%i)  ",
		step_0_best, step_0_previous, one_connected_pce, best_pce);

	// Changed of state so ...
	if (step_0_best != best_pce) {
		pthread_mutex_lock(&g_pcc_info_mtx);
		// Calculate previous
		previous_best_pce = step_0_best;
		// Clean state
		if (step_0_best != -1) {
			pcc[step_0_best]->is_best = false;
		}
		if (step_0_previous != -1) {
			pcc[step_0_previous]->previous_best = false;
		}

		// Set previous
		if (previous_best_pce != -1
		    && pcc[previous_best_pce]->status
			       == PCEP_PCC_DISCONNECTED) {
			pcc[previous_best_pce]->previous_best = true;
			zlog_debug("multi-pce: previous best pce (%i) ",
				   previous_best_pce + 1);
		}


		// Set best
		if (best_pce != -1) {
			pcc[best_pce]->is_best = true;
			zlog_debug("multi-pce: best pce (%i) ", best_pce + 1);
		} else {
			if (one_connected_pce != -1) {
				best_pce = one_connected_pce;
				pcc[one_connected_pce]->is_best = true;
				zlog_debug(
					"multi-pce: one connected best pce (default) (%i) ",
					one_connected_pce + 1);
			} else {
				for (int i = 0; i < MAX_PCC; i++) {
					if (pcc[i] && pcc[i]->pce_opts) {
						best_pce = i;
						pcc[i]->is_best = true;
						zlog_debug(
							"(disconnected) best pce (default) (%i) ",
							i + 1);
						break;
					}
				}
			}
		}
		pthread_mutex_unlock(&g_pcc_info_mtx);
	}

	return ((best_pce == -1) ? 0 : pcc[best_pce]->id);
}

int pcep_pcc_get_pcc_id_by_ip_port(struct pcc_state **pcc,
				   struct pce_opts *pce_opts)
{
	if (pcc == NULL) {
		return 0;
	}

	for (int idx = 0; idx < MAX_PCC; idx++) {
		if (pcc[idx]) {
			if ((ipaddr_cmp((const struct ipaddr *)&pcc[idx]
						->pce_opts->addr,
					(const struct ipaddr *)&pce_opts->addr)
			     == 0)
			    && pcc[idx]->pce_opts->port == pce_opts->port) {
				zlog_debug("found pcc_id (%d) idx (%d)",
					   pcc[idx]->id, idx);
				return pcc[idx]->id;
			}
		}
	}
	return 0;
}

int pcep_pcc_get_pcc_id_by_idx(struct pcc_state **pcc, int idx)
{
	if (pcc == NULL || idx < 0) {
		return 0;
	}

	return pcc[idx] ? pcc[idx]->id : 0;
}

struct pcc_state *pcep_pcc_get_pcc_by_id(struct pcc_state **pcc, int id)
{
	if (pcc == NULL || id < 0) {
		return NULL;
	}

	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i]) {
			if (pcc[i]->id == id) {
				zlog_debug("found id (%d) pcc_idx (%d)",
					   pcc[i]->id, i);
				return pcc[i];
			}
		}
	}

	return NULL;
}

struct pcc_state *pcep_pcc_get_pcc_by_name(struct pcc_state **pcc,
					   const char *pce_name)
{
	if (pcc == NULL || pce_name == NULL) {
		return NULL;
	}

	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] == NULL) {
			continue;
		}

		if (strcmp(pcc[i]->pce_opts->pce_name, pce_name) == 0) {
			return pcc[i];
		}
	}

	return NULL;
}

int pcep_pcc_get_pcc_idx_by_id(struct pcc_state **pcc, int id)
{
	if (pcc == NULL) {
		return -1;
	}

	for (int idx = 0; idx < MAX_PCC; idx++) {
		if (pcc[idx]) {
			if (pcc[idx]->id == id) {
				zlog_debug("found pcc_id (%d) array_idx (%d)",
					   pcc[idx]->id, idx);
				return idx;
			}
		}
	}

	return -1;
}

int pcep_pcc_get_free_pcc_idx(struct pcc_state **pcc)
{
	assert(pcc != NULL);

	for (int idx = 0; idx < MAX_PCC; idx++) {
		if (pcc[idx] == NULL) {
			zlog_debug("new pcc_idx (%d)", idx);
			return idx;
		}
	}

	return -1;
}

int pcep_pcc_get_pcc_id(struct pcc_state *pcc)
{
	return ((pcc == NULL) ? 0 : pcc->id);
}

void pcep_pcc_copy_pcc_info(struct pcc_state **pcc,
			    struct pcep_pcc_info *pcc_info)
{
	struct pcc_state *pcc_state =
		pcep_pcc_get_pcc_by_name(pcc, pcc_info->pce_name);
	if (!pcc_state) {
		return;
	}

	pcc_info->ctrl_state = NULL;
	if(pcc_state->pcc_opts){
		pcc_info->msd = pcc_state->pcc_opts->msd;
		pcc_info->pcc_port = pcc_state->pcc_opts->port;
	}
	pcc_info->next_plspid = pcc_state->next_plspid;
	pcc_info->next_reqid = pcc_state->next_reqid;
	pcc_info->status = pcc_state->status;
	pcc_info->pcc_id = pcc_state->id;
	pthread_mutex_lock(&g_pcc_info_mtx);
	pcc_info->is_best_multi_pce = pcc_state->is_best;
	pcc_info->previous_best = pcc_state->previous_best;
	pthread_mutex_unlock(&g_pcc_info_mtx);
	pcc_info->precedence =
		pcc_state->pce_opts ? pcc_state->pce_opts->precedence : 0;
	if(pcc_state->pcc_addr_tr.ipa_type != IPADDR_NONE){
		memcpy(&pcc_info->pcc_addr, &pcc_state->pcc_addr_tr,
		       sizeof(struct ipaddr));
	}
}


/*------------------ PCEP Message handlers --------------------- */

void handle_pcep_open(struct ctrl_state *ctrl_state,
		      struct pcc_state *pcc_state, struct pcep_message *msg)
{
	assert(msg->msg_header->type == PCEP_TYPE_OPEN);
	pcep_lib_parse_capabilities(msg, &pcc_state->caps);
	PCEP_DEBUG("PCE capabilities: %s, %s%s",
		   pcc_state->caps.is_stateful ? "stateful" : "stateless",
		   pcc_state->caps.supported_ofs_are_known
			   ? (pcc_state->caps.supported_ofs == 0
				      ? "no objective functions supported"
				      : "supported objective functions are ")
			   : "supported objective functions are unknown",
		   format_objfun_set(pcc_state->caps.supported_ofs));
}

void handle_pcep_message(struct ctrl_state *ctrl_state,
			 struct pcc_state *pcc_state, struct pcep_message *msg)
{
	if (pcc_state->status != PCEP_PCC_OPERATING)
		return;

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
	case PCEP_TYPE_OPEN:
	case PCEP_TYPE_KEEPALIVE:
	case PCEP_TYPE_PCREQ:
	case PCEP_TYPE_PCNOTF:
	case PCEP_TYPE_ERROR:
	case PCEP_TYPE_CLOSE:
	case PCEP_TYPE_REPORT:
	case PCEP_TYPE_START_TLS:
	case PCEP_TYPE_MAX:
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
	lookup_nbkey(pcc_state, path);
	pcep_thread_refine_path(ctrl_state, pcc_state->id,
				&continue_pcep_lsp_update, path, NULL);
}

void continue_pcep_lsp_update(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state, struct path *path,
			      void *payload)
{
	char err[MAX_ERROR_MSG_SIZE] = {0};

	specialize_incoming_path(pcc_state, path);
	PCEP_DEBUG("%s Received LSP update", pcc_state->tag);
	PCEP_DEBUG_PATH("%s", format_path(path));

	if (validate_incoming_path(pcc_state, path, err, sizeof(err)))
		pcep_thread_update_path(ctrl_state, pcc_state->id, path);
	else {
		/* FIXME: Monitor the amount of errors from the PCE and
		 * possibly disconnect and blacklist */
		flog_warn(EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
			  "Unsupported PCEP protocol feature: %s", err);
		pcep_free_path(path);
	}
}

void handle_pcep_lsp_initiate(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state,
			      struct pcep_message *msg)
{
	char err[MAX_ERROR_MSG_SIZE] = "";
	struct path *path;

	path = pcep_lib_parse_path(msg);

	if (!pcc_state->pce_opts->config_opts.pce_initiated) {
		/* PCE Initiated is not enabled */
		flog_warn(EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
			  "Not allowed PCE initiated path received: %s",
			  format_pcep_message(msg));
		send_pcep_error(pcc_state, PCEP_ERRT_LSP_INSTANTIATE_ERROR,
				PCEP_ERRV_UNACCEPTABLE_INSTANTIATE_ERROR, path);
		return;
	}

	if (path->do_remove) {
		// lookup in nbkey sequential as no endpoint
		struct nbkey_map_data *key;
		char endpoint[46];

		frr_each (nbkey_map, &pcc_state->nbkey_map, key) {
			ipaddr2str(&key->nbkey.endpoint, endpoint,
				   sizeof(endpoint));
			flog_warn(
				EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
				"FOR_EACH nbkey [color (%d) endpoint (%s)] path [plsp_id (%d)] ",
				key->nbkey.color, endpoint, path->plsp_id);
			if (path->plsp_id == key->plspid) {
				flog_warn(
					EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
					"FOR_EACH MATCH nbkey [color (%d) endpoint (%s)] path [plsp_id (%d)] ",
					key->nbkey.color, endpoint,
					path->plsp_id);
				path->nbkey = key->nbkey;
				break;
			}
		}
	} else {
		if (path->first_hop == NULL /*ero sets first_hop*/) {
			/* If the PCC receives a PCInitiate message without an
			 * ERO and the R flag in the SRP object != zero, then it
			 * MUST send a PCErr message with Error-type=6
			 * (Mandatory Object missing) and Error-value=9 (ERO
			 * object missing). */
			flog_warn(EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
				  "ERO object missing or incomplete : %s",
				  format_pcep_message(msg));
			send_pcep_error(pcc_state,
					PCEP_ERRT_LSP_INSTANTIATE_ERROR,
					PCEP_ERRV_INTERNAL_ERROR, path);
			return;
		}

		if (path->plsp_id != 0) {
			/* If the PCC receives a PCInitiate message with a
			 * non-zero PLSP-ID and the R flag in the SRP object set
			 * to zero, then it MUST send a PCErr message with
			 * Error-type=19 (Invalid Operation) and Error-value=8
			 * (Non-zero PLSP-ID in the LSP Initiate Request) */
			flog_warn(
				EC_PATH_PCEP_PROTOCOL_ERROR,
				"PCE initiated path with non-zero PLSP ID: %s",
				format_pcep_message(msg));
			send_pcep_error(pcc_state, PCEP_ERRT_INVALID_OPERATION,
					PCEP_ERRV_LSP_INIT_NON_ZERO_PLSP_ID,
					path);
			return;
		}

		if (path->name == NULL) {
			/* If the PCC receives a PCInitiate message without a
			 * SYMBOLIC-PATH-NAME TLV, then it MUST send a PCErr
			 * message with Error-type=10 (Reception of an invalid
			 * object) and Error-value=8 (SYMBOLIC-PATH-NAME TLV
			 * missing) */
			flog_warn(
				EC_PATH_PCEP_PROTOCOL_ERROR,
				"PCE initiated path without symbolic name: %s",
				format_pcep_message(msg));
			send_pcep_error(
				pcc_state, PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
				PCEP_ERRV_SYMBOLIC_PATH_NAME_TLV_MISSING, path);
			return;
		}
	}

	/* TODO: If there is a conflict with the symbolic path name of an
	 * existing LSP, the PCC MUST send a PCErr message with Error-type=23
	 * (Bad Parameter value) and Error-value=1 (SYMBOLIC-PATH-NAME in
	 * use) */

	specialize_incoming_path(pcc_state, path);
	/* TODO: Validate the PCC address received from the PCE is valid */
	PCEP_DEBUG("%s Received LSP initiate", pcc_state->tag);
	PCEP_DEBUG_PATH("%s", format_path(path));

	if (validate_incoming_path(pcc_state, path, err, sizeof(err))) {
		pcep_thread_initiate_path(ctrl_state, pcc_state->id, path);
	} else {
		/* FIXME: Monitor the amount of errors from the PCE and
		 * possibly disconnect and blacklist */
		flog_warn(EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
			  "Unsupported PCEP protocol feature: %s", err);
		send_pcep_error(pcc_state, PCEP_ERRT_INVALID_OPERATION,
				PCEP_ERRV_LSP_NOT_PCE_INITIATED, path);
		pcep_free_path(path);
	}
}

void handle_pcep_comp_reply(struct ctrl_state *ctrl_state,
			    struct pcc_state *pcc_state,
			    struct pcep_message *msg)
{
	char err[MAX_ERROR_MSG_SIZE] = "";
	struct req_entry *req;
	struct path *path;

	path = pcep_lib_parse_path(msg);
	if (path->no_path) {
		req = pop_req_no_reqid(pcc_state, path->req_id);
	} else {
		req = pop_req(pcc_state, path->req_id);
	}
	if (req == NULL) {
		/* TODO: check the rate of bad computation reply and close
		 * the connection if more that a given rate.
		 */
		PCEP_DEBUG(
			"%s Received computation reply for unknown request %d",
			pcc_state->tag, path->req_id);
		PCEP_DEBUG_PATH("%s", format_path(path));
		send_pcep_error(pcc_state, PCEP_ERRT_UNKNOWN_REQ_REF,
				PCEP_ERRV_UNASSIGNED, NULL);
		return;
	}

	/* Cancel the computation request timeout */
	pcep_thread_cancel_timer(&req->t_retry);

	/* Transfer relevent metadata from the request to the response */
	path->nbkey = req->path->nbkey;
	path->plsp_id = req->path->plsp_id;
	path->type = req->path->type;
	path->name = XSTRDUP(MTYPE_PCEP, req->path->name);
	specialize_incoming_path(pcc_state, path);

	PCEP_DEBUG("%s Received computation reply %d (no-path: %s)",
		   pcc_state->tag, path->req_id,
		   path->no_path ? "true" : "false");
	PCEP_DEBUG_PATH("%s", format_path(path));

	if (path->no_path) {
		PCEP_DEBUG("%s Computation for path %s did not find any result",
			   pcc_state->tag, path->name);
		free_req_entry(req);
		pcep_free_path(path);
		return;
	} else if (validate_incoming_path(pcc_state, path, err, sizeof(err))) {
		/* Updating a dynamic path will automatically delegate it */
		pcep_thread_update_path(ctrl_state, pcc_state->id, path);
		free_req_entry(req);
		return;
	} else {
		/* FIXME: Monitor the amount of errors from the PCE and
		 * possibly disconnect and blacklist */
		flog_warn(EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
			  "Unsupported PCEP protocol feature: %s", err);
	}

	pcep_free_path(path);

	/* Delegate the path regardless of the outcome */
	/* TODO: For now we are using the path from the request, when
	 * pathd API is thread safe, we could get a new path */
	if (pcc_state->caps.is_stateful) {
		PCEP_DEBUG("%s Delegating undefined dynamic path %s to PCE %s",
			   pcc_state->tag, req->path->name,
			   pcc_state->originator);
		path = pcep_copy_path(req->path);
		path->is_delegated = true;
		send_report(pcc_state, path);
		pcep_free_path(path);
	}

	free_req_entry(req);
}


/* ------------ Internal Functions ------------ */

const char *ipaddr_type_name(struct ipaddr *addr)
{
	if (IS_IPADDR_V4(addr))
		return "IPv4";
	if (IS_IPADDR_V6(addr))
		return "IPv6";
	return "undefined";
}

bool filter_path(struct pcc_state *pcc_state, struct path *path)
{
	return (IS_IPADDR_V4(&path->nbkey.endpoint)
		&& CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4))
	       || (IS_IPADDR_V6(&path->nbkey.endpoint)
		   && CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6));
}

void select_pcc_addresses(struct pcc_state *pcc_state)
{
	/* If no IPv4 address was specified, try to get one from zebra */
	if (!CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4)) {
		if (get_ipv4_router_id(&pcc_state->pcc_addr_v4)) {
			SET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4);
		}
	}

	/* If no IPv6 address was specified, try to get one from zebra */
	if (!CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6)) {
		if (get_ipv6_router_id(&pcc_state->pcc_addr_v6)) {
			SET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6);
		}
	}
}

void select_transport_address(struct pcc_state *pcc_state)
{
	struct ipaddr *taddr = &pcc_state->pcc_addr_tr;

	select_pcc_addresses(pcc_state);

	taddr->ipa_type = IPADDR_NONE;

	/* Select a transport source address in function of the configured PCE
	 * address */
	if (IS_IPADDR_V4(&pcc_state->pce_opts->addr)) {
		if (CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4)) {
			taddr->ipaddr_v4 = pcc_state->pcc_addr_v4;
			taddr->ipa_type = IPADDR_V4;
		}
	} else {
		if (CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6)) {
			taddr->ipaddr_v6 = pcc_state->pcc_addr_v6;
			taddr->ipa_type = IPADDR_V6;
		}
	}
}

void update_tag(struct pcc_state *pcc_state)
{
	if (pcc_state->pce_opts != NULL) {
		assert(!IS_IPADDR_NONE(&pcc_state->pce_opts->addr));
		if (IS_IPADDR_V6(&pcc_state->pce_opts->addr)) {
			snprintfrr(pcc_state->tag, sizeof(pcc_state->tag),
				   "%pI6:%i (%u)",
				   &pcc_state->pce_opts->addr.ipaddr_v6,
				   pcc_state->pce_opts->port, pcc_state->id);
		} else {
			snprintfrr(pcc_state->tag, sizeof(pcc_state->tag),
				   "%pI4:%i (%u)",
				   &pcc_state->pce_opts->addr.ipaddr_v4,
				   pcc_state->pce_opts->port, pcc_state->id);
		}
	} else {
		snprintfrr(pcc_state->tag, sizeof(pcc_state->tag), "(%u)",
			   pcc_state->id);
	}
}

void update_originator(struct pcc_state *pcc_state)
{
	char *originator;
	if (pcc_state->originator != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->originator);
		pcc_state->originator = NULL;
	}
	if (pcc_state->pce_opts == NULL)
		return;
	originator = XCALLOC(MTYPE_PCEP, 52);
	assert(!IS_IPADDR_NONE(&pcc_state->pce_opts->addr));
	if (IS_IPADDR_V6(&pcc_state->pce_opts->addr)) {
		snprintfrr(originator, 52, "%pI6:%i",
			   &pcc_state->pce_opts->addr.ipaddr_v6,
			   pcc_state->pce_opts->port);
	} else {
		snprintfrr(originator, 52, "%pI4:%i",
			   &pcc_state->pce_opts->addr.ipaddr_v4,
			   pcc_state->pce_opts->port);
	}
	pcc_state->originator = originator;
}

void schedule_reconnect(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	pcc_state->retry_count++;
	pcep_thread_schedule_reconnect(ctrl_state, pcc_state->id,
				       pcc_state->retry_count,
				       &pcc_state->t_reconnect);
	if (pcc_state->retry_count == 1) {
		pcep_thread_schedule_sync_best_pce(
			ctrl_state, pcc_state->id,
			pcc_state->pce_opts->config_opts
				.delegation_timeout_seconds,
			&pcc_state->t_update_best);
	}
}

void schedule_session_timeout(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state)
{
	/* No need to schedule timeout if multiple PCEs are connected */
	if (get_pce_count_connected(ctrl_state->pcc)) {
		PCEP_DEBUG_PCEP(
			"schedule_session_timeout not setting timer for multi-pce mode");

		return;
	}

	pcep_thread_schedule_session_timeout(
		ctrl_state, pcep_pcc_get_pcc_id(pcc_state),
		pcc_state->pce_opts->config_opts
			.session_timeout_inteval_seconds,
		&pcc_state->t_session_timeout);
}

void cancel_session_timeout(struct ctrl_state *ctrl_state,
			    struct pcc_state *pcc_state)
{
	/* No need to schedule timeout if multiple PCEs are connected */
	if (pcc_state->t_session_timeout == NULL) {
		PCEP_DEBUG_PCEP("cancel_session_timeout timer thread NULL");
		return;
	}

	PCEP_DEBUG_PCEP("Cancel session_timeout timer");
	pcep_thread_cancel_timer(&pcc_state->t_session_timeout);
	pcc_state->t_session_timeout = NULL;
}

void send_pcep_message(struct pcc_state *pcc_state, struct pcep_message *msg)
{
	if (pcc_state->sess != NULL) {
		PCEP_DEBUG_PCEP("%s Sending PCEP message: %s", pcc_state->tag,
				format_pcep_message(msg));
		send_message(pcc_state->sess, msg, true);
	}
}

void send_pcep_error(struct pcc_state *pcc_state,
		     enum pcep_error_type error_type,
		     enum pcep_error_value error_value,
		     struct path *trigger_path)
{
	struct pcep_message *msg;
	PCEP_DEBUG("%s Sending PCEP error type %s (%d) value %s (%d)",
		   pcc_state->tag, pcep_error_type_name(error_type), error_type,
		   pcep_error_value_name(error_type, error_value), error_value);
	msg = pcep_lib_format_error(error_type, error_value, trigger_path);
	send_pcep_message(pcc_state, msg);
}

void send_report(struct pcc_state *pcc_state, struct path *path)
{
	struct pcep_message *report;

	path->req_id = 0;
	specialize_outgoing_path(pcc_state, path);
	PCEP_DEBUG_PATH("%s Sending path %s: %s", pcc_state->tag, path->name,
			format_path(path));
	report = pcep_lib_format_report(&pcc_state->caps, path);
	send_pcep_message(pcc_state, report);
}

/* Updates the path for the PCE, updating the delegation and creation flags */
void specialize_outgoing_path(struct pcc_state *pcc_state, struct path *path)
{
	bool is_delegated = false;
	bool was_created = false;

	lookup_plspid(pcc_state, path);

	set_pcc_address(pcc_state, &path->nbkey, &path->pcc_addr);
	path->sender = pcc_state->pcc_addr_tr;

	/* TODO: When the pathd API have a way to mark a path as
	 * delegated, use it instead of considering all dynamic path
	 * delegated. We need to disable the originator check for now,
	 * because path could be delegated without having any originator yet */
	// if ((path->originator == NULL)
	//     || (strcmp(path->originator, pcc_state->originator) == 0)) {
	// 	is_delegated = (path->type == SRTE_CANDIDATE_TYPE_DYNAMIC)
	// 			&& (path->first_hop != NULL);
	// 	/* it seems the PCE consider updating an LSP a creation ?!?
	// 	at least Cisco does... */
	// 	was_created = path->update_origin == SRTE_ORIGIN_PCEP;
	// }
	is_delegated = (path->type == SRTE_CANDIDATE_TYPE_DYNAMIC);
	was_created = path->update_origin == SRTE_ORIGIN_PCEP;

	path->pcc_id = pcc_state->id;
	path->go_active = is_delegated && pcc_state->is_best;
	path->is_delegated = is_delegated && pcc_state->is_best;
	path->was_created = was_created;
}

/* Updates the path for the PCC */
void specialize_incoming_path(struct pcc_state *pcc_state, struct path *path)
{
	if (IS_IPADDR_NONE(&path->pcc_addr))
		set_pcc_address(pcc_state, &path->nbkey, &path->pcc_addr);
	path->sender = pcc_state->pce_opts->addr;
	path->pcc_id = pcc_state->id;
	path->update_origin = SRTE_ORIGIN_PCEP;
	path->originator = XSTRDUP(MTYPE_PCEP, pcc_state->originator);
}

/* Ensure the path can be handled by the PCC and if not, sends an error */
bool validate_incoming_path(struct pcc_state *pcc_state, struct path *path,
			    char *errbuff, size_t buffsize)
{
	struct path_hop *hop;
	enum pcep_error_type err_type = 0;
	enum pcep_error_value err_value = PCEP_ERRV_UNASSIGNED;

	for (hop = path->first_hop; hop != NULL; hop = hop->next) {
		/* Hops without SID are not supported */
		if (!hop->has_sid) {
			snprintfrr(errbuff, buffsize, "SR segment without SID");
			err_type = PCEP_ERRT_RECEPTION_OF_INV_OBJECT;
			err_value = PCEP_ERRV_DISJOINTED_CONF_TLV_MISSING;
			break;
		}
		/* Hops with non-MPLS SID are not supported */
		if (!hop->is_mpls) {
			snprintfrr(errbuff, buffsize,
				   "SR segment with non-MPLS SID");
			err_type = PCEP_ERRT_RECEPTION_OF_INV_OBJECT;
			err_value = PCEP_ERRV_UNSUPPORTED_NAI;
			break;
		}
	}

	if (err_type != 0) {
		send_pcep_error(pcc_state, err_type, err_value, NULL);
		return false;
	}

	return true;
}

void send_comp_request(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state, struct req_entry *req)
{
	assert(req != NULL);

	if (req->t_retry)
		return;

	assert(req->path != NULL);
	assert(req->path->req_id > 0);
	assert(RB_FIND(req_entry_head, &pcc_state->requests, req) == req);
	assert(lookup_reqid(pcc_state, req->path) == req->path->req_id);

	int timeout;
	struct pcep_message *msg;

	if (!pcc_state->is_best) {
		return;
	}

	specialize_outgoing_path(pcc_state, req->path);

	PCEP_DEBUG(
		"%s Sending computation request %d for path %s to %pIA (retry %d)",
		pcc_state->tag, req->path->req_id, req->path->name,
		&req->path->nbkey.endpoint, req->retry_count);
	PCEP_DEBUG_PATH("%s Computation request path %s: %s", pcc_state->tag,
			req->path->name, format_path(req->path));

	msg = pcep_lib_format_request(&pcc_state->caps, req->path);
	send_pcep_message(pcc_state, msg);
	req->was_sent = true;

	timeout = pcc_state->pce_opts->config_opts.pcep_request_time_seconds;
	pcep_thread_schedule_timeout(ctrl_state, pcc_state->id,
				     TO_COMPUTATION_REQUEST, timeout,
				     (void *)req, &req->t_retry);
}

void cancel_comp_requests(struct ctrl_state *ctrl_state,
			  struct pcc_state *pcc_state)
{
	struct req_entry *req, *safe_req;

	RB_FOREACH_SAFE (req, req_entry_head, &pcc_state->requests, safe_req) {
		cancel_comp_request(ctrl_state, pcc_state, req);
		RB_REMOVE(req_entry_head, &pcc_state->requests, req);
		remove_reqid_mapping(pcc_state, req->path);
		free_req_entry(req);
	}
}

void cancel_comp_request(struct ctrl_state *ctrl_state,
			 struct pcc_state *pcc_state, struct req_entry *req)
{
	struct pcep_message *msg;

	if (req->was_sent) {
		/* TODO: Send a computation request cancelation
		 * notification to the PCE */
		pcep_thread_cancel_timer(&req->t_retry);
	}

	PCEP_DEBUG(
		"%s Canceling computation request %d for path %s to %pIA (retry %d)",
		pcc_state->tag, req->path->req_id, req->path->name,
		&req->path->nbkey.endpoint, req->retry_count);
	PCEP_DEBUG_PATH("%s Canceled computation request path %s: %s",
			pcc_state->tag, req->path->name,
			format_path(req->path));

	msg = pcep_lib_format_request_cancelled(req->path->req_id);
	send_pcep_message(pcc_state, msg);
}

void set_pcc_address(struct pcc_state *pcc_state, struct lsp_nb_key *nbkey,
		     struct ipaddr *addr)
{
	select_pcc_addresses(pcc_state);
	if (IS_IPADDR_V6(&nbkey->endpoint)) {
		assert(CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6));
		addr->ipa_type = IPADDR_V6;
		addr->ipaddr_v6 = pcc_state->pcc_addr_v6;
	} else if (IS_IPADDR_V4(&nbkey->endpoint)) {
		assert(CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4));
		addr->ipa_type = IPADDR_V4;
		addr->ipaddr_v4 = pcc_state->pcc_addr_v4;
	} else {
		addr->ipa_type = IPADDR_NONE;
	}
}

/* ------------ Data Structure Helper Functions ------------ */

void lookup_plspid(struct pcc_state *pcc_state, struct path *path)
{
	struct plspid_map_data key, *plspid_mapping;
	struct nbkey_map_data *nbkey_mapping;

	if (path->nbkey.color != 0) {
		key.nbkey = path->nbkey;
		plspid_mapping = plspid_map_find(&pcc_state->plspid_map, &key);
		if (plspid_mapping == NULL) {
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
			assert(pcc_state->next_plspid <= 1048576);
		}
		path->plsp_id = plspid_mapping->plspid;
	}
}

void lookup_nbkey(struct pcc_state *pcc_state, struct path *path)
{
	struct nbkey_map_data key, *mapping;
	// TODO: Should give an error to the PCE instead of crashing
	assert(path->plsp_id != 0);
	key.plspid = path->plsp_id;
	mapping = nbkey_map_find(&pcc_state->nbkey_map, &key);
	assert(mapping != NULL);
	path->nbkey = mapping->nbkey;
}

void free_req_entry(struct req_entry *req)
{
	pcep_free_path(req->path);
	XFREE(MTYPE_PCEP, req);
}

struct req_entry *push_new_req(struct pcc_state *pcc_state, struct path *path)
{
	struct req_entry *req;

	req = XCALLOC(MTYPE_PCEP, sizeof(*req));
	req->retry_count = 0;
	req->path = pcep_copy_path(path);
	repush_req(pcc_state, req);

	return req;
}

void repush_req(struct pcc_state *pcc_state, struct req_entry *req)
{
	uint32_t reqid = pcc_state->next_reqid;
	void *res;

	req->was_sent = false;
	req->path->req_id = reqid;
	res = RB_INSERT(req_entry_head, &pcc_state->requests, req);
	assert(res == NULL);
	assert(add_reqid_mapping(pcc_state, req->path) == true);

	pcc_state->next_reqid += 1;
	/* Wrapping is allowed, but 0 is not a valid id */
	if (pcc_state->next_reqid == 0)
		pcc_state->next_reqid = 1;
}

struct req_entry *pop_req(struct pcc_state *pcc_state, uint32_t reqid)
{
	struct path path = {.req_id = reqid};
	struct req_entry key = {.path = &path};
	struct req_entry *req;

	req = RB_FIND(req_entry_head, &pcc_state->requests, &key);
	if (req == NULL)
		return NULL;
	RB_REMOVE(req_entry_head, &pcc_state->requests, req);
	remove_reqid_mapping(pcc_state, req->path);

	return req;
}

struct req_entry *pop_req_no_reqid(struct pcc_state *pcc_state, uint32_t reqid)
{
	struct path path = {.req_id = reqid};
	struct req_entry key = {.path = &path};
	struct req_entry *req;

	req = RB_FIND(req_entry_head, &pcc_state->requests, &key);
	if (req == NULL)
		return NULL;
	RB_REMOVE(req_entry_head, &pcc_state->requests, req);

	return req;
}

bool add_reqid_mapping(struct pcc_state *pcc_state, struct path *path)
{
	struct req_map_data *mapping;
	mapping = XCALLOC(MTYPE_PCEP, sizeof(*mapping));
	mapping->nbkey = path->nbkey;
	mapping->reqid = path->req_id;
	if (req_map_add(&pcc_state->req_map, mapping) != NULL) {
		XFREE(MTYPE_PCEP, mapping);
		return false;
	}
	return true;
}

void remove_reqid_mapping(struct pcc_state *pcc_state, struct path *path)
{
	struct req_map_data key, *mapping;
	key.nbkey = path->nbkey;
	mapping = req_map_find(&pcc_state->req_map, &key);
	if (mapping != NULL) {
		req_map_del(&pcc_state->req_map, mapping);
		XFREE(MTYPE_PCEP, mapping);
	}
}

uint32_t lookup_reqid(struct pcc_state *pcc_state, struct path *path)
{
	struct req_map_data key, *mapping;
	key.nbkey = path->nbkey;
	mapping = req_map_find(&pcc_state->req_map, &key);
	if (mapping != NULL)
		return mapping->reqid;
	return 0;
}

bool has_pending_req_for(struct pcc_state *pcc_state, struct path *path)
{
	struct req_entry key = {.path = path};
	struct req_entry *req;


	PCEP_DEBUG_PATH("(%s) %s", format_path(path), __func__);
	/* Looking for request without result */
	if (path->no_path || !path->first_hop) {
		PCEP_DEBUG_PATH("%s Path : no_path|!first_hop", __func__);
		/* ...and already was handle */
		req = RB_FIND(req_entry_head, &pcc_state->requests, &key);
		if (!req) {
			/* we must purge remaining reqid */
			PCEP_DEBUG_PATH("%s Purge pending reqid: no_path(%s)",
					__func__,
					path->no_path ? "TRUE" : "FALSE");
			if (lookup_reqid(pcc_state, path) != 0) {
				PCEP_DEBUG_PATH("%s Purge pending reqid: DONE ",
						__func__);
				remove_reqid_mapping(pcc_state, path);
				return true;
			} else {
				return false;
			}
		}
	}


	return lookup_reqid(pcc_state, path) != 0;
}


/* ------------ Data Structure Callbacks ------------ */

#define CMP_RETURN(A, B)                                                       \
	if (A != B)                                                            \
	return (A < B) ? -1 : 1

static uint32_t hash_nbkey(const struct lsp_nb_key *nbkey)
{
	uint32_t hash;
	hash = jhash_2words(nbkey->color, nbkey->preference, 0x55aa5a5a);
	switch (nbkey->endpoint.ipa_type) {
	case IPADDR_V4:
		return jhash(&nbkey->endpoint.ipaddr_v4,
			     sizeof(nbkey->endpoint.ipaddr_v4), hash);
	case IPADDR_V6:
		return jhash(&nbkey->endpoint.ipaddr_v6,
			     sizeof(nbkey->endpoint.ipaddr_v6), hash);
	case IPADDR_NONE:
		return hash;
	}

	assert(!"Reached end of function where we were not expecting to");
}

static int cmp_nbkey(const struct lsp_nb_key *a, const struct lsp_nb_key *b)
{
	CMP_RETURN(a->color, b->color);
	int cmp = ipaddr_cmp(&a->endpoint, &b->endpoint);
	if (cmp != 0)
		return cmp;
	CMP_RETURN(a->preference, b->preference);
	return 0;
}

int plspid_map_cmp(const struct plspid_map_data *a,
		   const struct plspid_map_data *b)
{
	return cmp_nbkey(&a->nbkey, &b->nbkey);
}

uint32_t plspid_map_hash(const struct plspid_map_data *e)
{
	return hash_nbkey(&e->nbkey);
}

int nbkey_map_cmp(const struct nbkey_map_data *a,
		  const struct nbkey_map_data *b)
{
	CMP_RETURN(a->plspid, b->plspid);
	return 0;
}

uint32_t nbkey_map_hash(const struct nbkey_map_data *e)
{
	return e->plspid;
}

int req_map_cmp(const struct req_map_data *a, const struct req_map_data *b)
{
	return cmp_nbkey(&a->nbkey, &b->nbkey);
}

uint32_t req_map_hash(const struct req_map_data *e)
{
	return hash_nbkey(&e->nbkey);
}
