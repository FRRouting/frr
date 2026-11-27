// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#include <zebra.h>
#include "pceplib/pcep_utils_counters.h"

#include "memory.h"
#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "lib/version.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"
#include "termtable.h"

#include "pathd/pathd.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_cli.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_config.h"
#include "pathd/path_pcep_debug.h"

DEFINE_MTYPE(PATHD, PCEP, "PCEP module");

/*
 * Globals.
 */
static struct pcep_glob pcep_glob_space = {
	.dbg_basic = { 0, "debug pathd pcep basic", "PCEP basic" },
	.dbg_path = { 0, "debug pathd pcep path", "PCEP path" },
	.dbg_msg = { 0, "debug pathd pcep message", "PCEP message" },
	.dbg_lib = { 0, "debug pathd pcep pceplib", "PCEP lib" },
};
struct pcep_glob *pcep_g = &pcep_glob_space;

/* PCCs whose session timeout is running, at most one slot per PCC */
static struct {
	int pcc_id;
	char originator[64];
} pcep_orphaned[MAX_PCC];

static void pcep_orphaned_set(int pcc_id, const char *originator);

/* Main Thread Even Handler */
static int pcep_main_event_handler(enum pcep_main_event_type type, int pcc_id,
				   void *payload);
static int pcep_main_event_start_sync(int pcc_id);
static int pcep_main_event_start_sync_cb(struct path *path, void *arg);
static int pcep_main_event_initiate_candidate(struct path *path);
static int pcep_main_event_update_candidate(struct path *path);
static int pcep_main_event_remove_candidate_segments(const char *originator);

/* Hook Handlers called from the Main Thread */
static int pathd_candidate_created_handler(struct srte_candidate *candidate);
static int pathd_candidate_updated_handler(struct srte_candidate *candidate);
static int pathd_candidate_removed_handler(struct srte_candidate *candidate);

/* Path manipulation functions */
static struct path_metric *pcep_copy_metrics(struct path_metric *metric);
static struct path_hop *pcep_copy_hops(struct path_hop *hop);

/* Other static functions */
static void notify_status(struct path *path, bool not_changed);

/* Module Functions */
static int pcep_module_finish(void);
static int pcep_module_late_init(struct event_loop *tm);
static int pcep_module_init(void);

/* ------------ Path Helper Functions ------------ */

struct path *pcep_new_path(void)
{
	struct path *path;
	path = XCALLOC(MTYPE_PCEP, sizeof(*path));
	path->binding_sid = MPLS_LABEL_NONE;
	path->enforce_bandwidth = true;
	return path;
}

struct path_hop *pcep_new_hop(void)
{
	struct path_hop *hop;
	hop = XCALLOC(MTYPE_PCEP, sizeof(*hop));
	return hop;
}

struct path_metric *pcep_new_metric(void)
{
	struct path_metric *metric;
	metric = XCALLOC(MTYPE_PCEP, sizeof(*metric));
	return metric;
}

struct path_metric *pcep_copy_metrics(struct path_metric *metric)
{
	if (metric == NULL)
		return NULL;
	struct path_metric *new_metric = pcep_new_metric();
	*new_metric = *metric;
	new_metric->next = pcep_copy_metrics(metric->next);
	return new_metric;
}

struct path_hop *pcep_copy_hops(struct path_hop *hop)
{
	if (hop == NULL)
		return NULL;
	struct path_hop *new_hop = pcep_new_hop();
	*new_hop = *hop;
	new_hop->next = pcep_copy_hops(hop->next);
	return new_hop;
}

struct path *pcep_copy_path(struct path *path)
{
	struct path *new_path = pcep_new_path();

	*new_path = *path;
	new_path->first_metric = pcep_copy_metrics(path->first_metric);
	new_path->first_hop = pcep_copy_hops(path->first_hop);
	if (path->name != NULL)
		new_path->name = XSTRDUP(MTYPE_PCEP, path->name);
	if (path->originator != NULL)
		new_path->originator = XSTRDUP(MTYPE_PCEP, path->originator);
	return new_path;
}

void pcep_free_path(struct path *path)
{
	struct path_hop *hop;
	struct path_metric *metric;
	char *tmp;

	metric = path->first_metric;
	while (metric != NULL) {
		struct path_metric *next = metric->next;
		XFREE(MTYPE_PCEP, metric);
		metric = next;
	}
	hop = path->first_hop;
	while (hop != NULL) {
		struct path_hop *next = hop->next;
		XFREE(MTYPE_PCEP, hop);
		hop = next;
	}
	if (path->originator != NULL) {
		/* The path own the memory, it is const so it is clear it
		shouldn't be modified. XFREE macro do not support type casting
		so we need a temporary variable */
		tmp = (char *)path->originator;
		XFREE(MTYPE_PCEP, tmp);
		path->originator = NULL;
	}
	if (path->name != NULL) {
		/* The path own the memory, it is const so it is clear it
		shouldn't be modified. XFREE macro do not support type casting
		so we need a temporary variable */
		tmp = (char *)path->name;
		XFREE(MTYPE_PCEP, tmp);
		path->name = NULL;
	}
	XFREE(MTYPE_PCEP, path);
}

/* ------------ Other Static Functions ------------ */

void notify_status(struct path *path, bool not_changed)
{
	struct path *resp = NULL;

	if ((resp = path_pcep_config_get_path(&path->nbkey))) {
		resp->srp_id = path->srp_id;
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "(%s) Send report for candidate path %s", __func__,
			  path->name);
		pcep_ctrl_send_report(pcep_g->fpt, path->pcc_id, resp,
				      not_changed);
	}
}

/* ------------ Main Thread Even Handler ------------ */

int pcep_main_event_handler(enum pcep_main_event_type type, int pcc_id,
			    void *payload)
{
	int ret = 0;

	switch (type) {
	case PCEP_MAIN_EVENT_START_SYNC:
		ret = pcep_main_event_start_sync(pcc_id);
		break;
	case PCEP_MAIN_EVENT_INITIATE_CANDIDATE:
		assert(payload != NULL);
		ret = pcep_main_event_initiate_candidate(
			(struct path *)payload);
		break;
	case PCEP_MAIN_EVENT_UPDATE_CANDIDATE:
		assert(payload != NULL);
		ret = pcep_main_event_update_candidate((struct path *)payload);
		break;
	case PCEP_MAIN_EVENT_REMOVE_CANDIDATE_LSP:
		pcep_orphaned_set(pcc_id, NULL);
		ret = pcep_main_event_remove_candidate_segments((const char *)payload);
		break;
	case PCEP_MAIN_EVENT_SESSION_DOWN:
		pcep_orphaned_set(pcc_id, payload);
		XFREE(MTYPE_PCEP, payload);
		break;
	case PCEP_MAIN_EVENT_SESSION_UP:
		pcep_orphaned_set(pcc_id, NULL);
		break;
	case PCEP_MAIN_EVENT_UNDEFINED:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unexpected event received in the main thread: %u",
			  type);
		break;
	}

	return ret;
}

int pcep_main_event_start_sync(int pcc_id)
{
	path_pcep_config_list_path(pcep_main_event_start_sync_cb, &pcc_id);
	pcep_ctrl_sync_done(pcep_g->fpt, pcc_id);
	return 0;
}

int pcep_main_event_start_sync_cb(struct path *path, void *arg)
{
	int *pcc_id = (int *)arg;
	pcep_ctrl_sync_path(pcep_g->fpt, *pcc_id, path);
	return 1;
}

int pcep_main_event_initiate_candidate(struct path *path)
{
	int ret = 0;

	ret = path_pcep_config_initiate_path(path);
	if (path->do_remove) {
		struct pcep_error *error;
		error = XCALLOC(MTYPE_PCEP, sizeof(*error));
		error->path = path;
		error->error_type = PCEP_ERRT_INVALID_OPERATION;
		switch (ret) {
		case ERROR_19_1:
			error->error_value =
				PCEP_ERRV_LSP_UPDATE_FOR_NON_DELEGATED_LSP;
			break;
		case ERROR_19_3:
			error->error_value =
				PCEP_ERRV_LSP_UPDATE_UNKNOWN_PLSP_ID;
			break;
		case ERROR_19_9:
			error->error_value = PCEP_ERRV_LSP_NOT_PCE_INITIATED;
			break;
		default:
			zlog_warn("(%s)PCE tried to REMOVE unknown error!",
				  __func__);
			XFREE(MTYPE_PCEP, error);
			pcep_free_path(path);
			return ret;
			break;
		}
		/*
		 * On error, the path object (linked by error->path) is
		 * freed after the error message is sent.
		 */
		pcep_ctrl_send_error(pcep_g->fpt, path->pcc_id, error);
	} else if (ret == ERROR_23_1) {
		/* RFC 8281: a duplicate symbolic path name requires the PCC
		 * to send a PCErr message (Error-type=23, Error-value=1).
		 */
		struct pcep_error *error;

		error = XCALLOC(MTYPE_PCEP, sizeof(*error));
		error->path = path;
		error->error_type = PCEP_ERRT_BAD_PARAMETER_VALUE;
		error->error_value = PCEP_ERRV_SYMBOLIC_PATH_NAME_IN_USE;

		/* Error frees the path object after message is sent. */
		pcep_ctrl_send_error(pcep_g->fpt, path->pcc_id, error);
	} else if (ret == ERROR_19_8) {
		/* RFC 8281: a non-zero PLSP-ID that is not an orphan */
		struct pcep_error *error;

		error = XCALLOC(MTYPE_PCEP, sizeof(*error));
		error->path = path;
		error->error_type = PCEP_ERRT_INVALID_OPERATION;
		error->error_value = PCEP_ERRV_LSP_INIT_NON_ZERO_PLSP_ID;

		/* Error frees the path object after message is sent. */
		pcep_ctrl_send_error(pcep_g->fpt, path->pcc_id, error);
	} else if (ret == ERROR_24_1 || ret == ERROR_24_2) {
		/* RFC 8281: 24/1 for unacceptable parameters (name too long or
		 * its segment list name taken), 24/2 for an internal error.
		 */
		struct pcep_error *error;

		error = XCALLOC(MTYPE_PCEP, sizeof(*error));
		error->path = path;
		error->error_type = PCEP_ERRT_LSP_INSTANTIATE_ERROR;
		error->error_value = ret == ERROR_24_1 ? PCEP_ERRV_UNACCEPTABLE_INSTANTIATE_ERROR
						       : PCEP_ERRV_INTERNAL_ERROR;

		/* Error frees the path object after message is sent. */
		pcep_ctrl_send_error(pcep_g->fpt, path->pcc_id, error);
	} else {
		if (ret != PATH_NB_ERR && path->srp_id != 0)
			notify_status(path, ret == PATH_NB_NO_CHANGE);
		/*
		 * The path was parsed from the PCInitiate message and its
		 * content copied into the candidate, now clean up the path.
		 */
		pcep_free_path(path);
	}
	return ret;
}

int pcep_main_event_update_candidate(struct path *path)
{
	int ret = 0;

	ret = path_pcep_config_update_path(path);
	if (ret == ERROR_24_1 || ret == ERROR_24_2) {
		struct path *resp = path_pcep_config_get_path(&path->nbkey);

		if (resp) {
			resp->srp_id = path->srp_id;
			resp->lsp_error_code = ret == ERROR_24_1
						       ? PCEP_TLV_LSP_ERROR_CODE_UNACCEPTABLE_PARAMS
						       : PCEP_TLV_LSP_ERROR_CODE_INTERNAL_ERROR;
			pcep_ctrl_send_report(pcep_g->fpt, path->pcc_id, resp, true);
		}
		pcep_free_path(path);
		return ret;
	}
	if (ret != PATH_NB_ERR && path->srp_id != 0)
		notify_status(path, ret == PATH_NB_NO_CHANGE);
	/* Same ownership as the initiate case: the parsed path is ours. */
	pcep_free_path(path);
	return ret;
}

/* The paths of this originator are orphans (RFC 8281 section 6) */
bool pcep_originator_orphaned(const char *originator)
{
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcep_orphaned[i].pcc_id != 0 &&
		    strcmp(pcep_orphaned[i].originator, originator) == 0)
			return true;
	}
	return false;
}

/* Record the originator of a PCC, or forget it when NULL */
void pcep_orphaned_set(int pcc_id, const char *originator)
{
	int slot = -1;

	for (int i = 0; i < MAX_PCC; i++) {
		if (pcep_orphaned[i].pcc_id == pcc_id) {
			slot = i;
			break;
		}
		if (slot < 0 && pcep_orphaned[i].pcc_id == 0)
			slot = i;
	}
	if (slot < 0)
		return;

	if (originator == NULL) {
		if (pcep_orphaned[slot].pcc_id == pcc_id)
			pcep_orphaned[slot].pcc_id = 0;
		return;
	}
	pcep_orphaned[slot].pcc_id = pcc_id;
	strlcpy(pcep_orphaned[slot].originator, originator, sizeof(pcep_orphaned[slot].originator));
}

int pcep_main_event_remove_candidate_segments(const char *originator)
{
	srte_candidate_unset_segment_list(originator);
	/* Avoid compiler warnings about const char* */
	void *free_ptr = (void *)originator;
	XFREE(MTYPE_PCEP, free_ptr);

	srte_apply_changes();

	return 0;
}

/* ------------ Hook Handlers Functions Called From Main Thread ------------ */

int pathd_candidate_created_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	int ret = pcep_ctrl_pathd_event(pcep_g->fpt, PCEP_PATH_CREATED, path);
	return ret;
}

int pathd_candidate_updated_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	int ret = pcep_ctrl_pathd_event(pcep_g->fpt, PCEP_PATH_UPDATED, path);
	return ret;
}

int pathd_candidate_removed_handler(struct srte_candidate *candidate)
{
	struct path *path = candidate_to_path(candidate);
	int ret = pcep_ctrl_pathd_event(pcep_g->fpt, PCEP_PATH_REMOVED, path);
	return ret;
}


/* ------------ Module Functions ------------ */

/* this creates threads, therefore must run after fork().  but it must also
 * run before config load, so the CLI commands don't try to touch things that
 * aren't set up yet...
 */
static int pcep_module_config_pre(struct event_loop *tm)
{
	assert(pcep_g->fpt == NULL);
	assert(pcep_g->master == NULL);

	struct frr_pthread *fpt;

	if (pcep_ctrl_initialize(tm, &fpt, pcep_main_event_handler))
		return 1;

	if (pcep_lib_initialize(fpt))
		return 1;

	pcep_g->master = tm;
	pcep_g->fpt = fpt;

	return 0;
}

static int pcep_module_late_init(struct event_loop *tm)
{
	hook_register(pathd_candidate_created, pathd_candidate_created_handler);
	hook_register(pathd_candidate_updated, pathd_candidate_updated_handler);
	hook_register(pathd_candidate_removed, pathd_candidate_removed_handler);

	hook_register(frr_config_pre, pcep_module_config_pre);
	hook_register(frr_fini, pcep_module_finish);

	pcep_cli_init();

	return 0;
}

int pcep_module_finish(void)
{
	pcep_ctrl_finalize(&pcep_g->fpt);
	pcep_lib_finalize();

	for (int i = 0; i < MAX_PCC; i++)
		if (pcep_g->pce_opts_cli[i] != NULL)
			XFREE(MTYPE_PCEP, pcep_g->pce_opts_cli[i]);

	for (int i = 0; i < MAX_PCE; i++)
		if (pcep_g->config_group_opts[i] != NULL)
			XFREE(MTYPE_PCEP, pcep_g->config_group_opts[i]);

	return 0;
}

int pcep_module_init(void)
{
	pcep_g->num_pce_opts_cli = 0;
	for (int i = 0; i < MAX_PCE; i++)
		pcep_g->pce_opts_cli[i] = NULL;
	pcep_g->num_config_group_opts = 0;
	for (int i = 0; i < MAX_PCE; i++)
		pcep_g->config_group_opts[i] = NULL;

	hook_register(frr_late_init, pcep_module_late_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "frr_pathd_pcep", .version = FRR_VERSION,
		 .description = "FRR pathd PCEP module",
		 .init = pcep_module_init,
);
