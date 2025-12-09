// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * November 15 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */

#include <zebra.h>
#include <libyang/libyang.h>
#include <libyang/version.h>
#include "lib/debug.h"
#include "lib/command.h"
#include "lib/lib_vty.h"
#include "lib/northbound_cli.h"
#include "lib/vty.h"
#include "mgmtd/mgmt.h"

#define _dbg		    debug_fe_client
#define _log_err	    log_err_fe_client
#define _log_warn(fmt, ...) zlog_warn("FE-CLIENT: %s: WARNING: " fmt, __func__, ##__VA_ARGS__)

/* static */ struct mgmt_fe_client *mgmt_fe_client;
static bool mgmt_fe_connected;

static uint64_t mgmt_client_id_next;

char const *const mgmt_daemons[] = {
	"zebra",
#ifdef HAVE_RIPD
	"ripd",
#endif
#ifdef HAVE_RIPNGD
	"ripngd",
#endif
#ifdef HAVE_STATICD
	"staticd",
#endif
};
uint mgmt_daemons_count = array_size(mgmt_daemons);


/* ================= */
/* Utility Functions */
/* ================= */

static bool vty_mgmt_fe_enabled(void)
{
	return mgmt_fe_client && mgmt_fe_connected;
}

static void fe_client_set_vty_callbacks(bool connected);
static int vty_mgmt_send_lockds_req(struct vty *vty, enum mgmt_ds_id ds_id, bool lock, bool scok);

static int vty_mgmt_lock_candidate_inline(struct vty *vty)
{
	assert(!vty->mgmt_locked_candidate_ds);
	(void)vty_mgmt_send_lockds_req(vty, MGMTD_DS_CANDIDATE, true, true);
	return vty->mgmt_locked_candidate_ds ? 0 : -1;
}

static int vty_mgmt_unlock_candidate_inline(struct vty *vty)
{
	assert(vty->mgmt_locked_candidate_ds);
	(void)vty_mgmt_send_lockds_req(vty, MGMTD_DS_CANDIDATE, false, true);
	return vty->mgmt_locked_candidate_ds ? -1 : 0;
}

static int vty_mgmt_lock_running_inline(struct vty *vty)
{
	assert(!vty->mgmt_locked_running_ds);
	(void)vty_mgmt_send_lockds_req(vty, MGMTD_DS_RUNNING, true, true);
	return vty->mgmt_locked_running_ds ? 0 : -1;
}

static int vty_mgmt_unlock_running_inline(struct vty *vty)
{
	assert(vty->mgmt_locked_running_ds);
	(void)vty_mgmt_send_lockds_req(vty, MGMTD_DS_RUNNING, false, true);
	return vty->mgmt_locked_running_ds ? -1 : 0;
}

void vty_mgmt_resume_response(struct vty *vty, int ret)
{
	if (!vty->mgmt_req_pending_cmd) {
		zlog_err("vty resume response called without mgmt_req_pending_cmd");
		return;
	}

	debug_fe_client("resuming CLI cmd after %s on vty session-id: %" PRIu64 " with '%s'",
			vty->mgmt_req_pending_cmd, vty->mgmt_session_id,
			ret == CMD_SUCCESS ? "success" : "failed");

	vty->mgmt_req_pending_cmd = NULL;

	vty_resume_response(vty, ret);
}

/* ======================================================= */
/* Startup Read Config Files for all mgmt-enabled daemons. */
/* ======================================================= */

static bool mgmt_vty_read_configs(void)
{
	char path[PATH_MAX];
	struct vty *vty;
	FILE *confp;
	uint line_num = 0;
	uint count = 0;
	uint index;

	vty = vty_new();
	vty->wfd = STDERR_FILENO;
	vty->type = VTY_FILE; /* We don't send these changes to backends */
	vty->node = CONFIG_NODE;
	vty->config = true;
	vty->pending_allowed = true;

	vty->candidate_config = vty_shared_candidate_config;

	vty_mgmt_lock_candidate_inline(vty);
	vty_mgmt_lock_running_inline(vty);

	for (index = 0; index < array_size(mgmt_daemons); index++) {
		snprintf(path, sizeof(path), "%s/%s.conf", frr_sysconfdir, mgmt_daemons[index]);

		confp = vty_open_config(path, config_default);
		if (!confp)
			continue;

		zlog_info("mgmtd: reading config file: %s", path);

		/* Execute configuration file */
		line_num = 0;
		(void)config_from_file(vty, confp, &line_num);
		count++;

		fclose(confp);
	}

	snprintf(path, sizeof(path), "%s/mgmtd.conf", frr_sysconfdir);
	confp = vty_open_config(path, config_default);
	if (confp) {
		zlog_info("mgmtd: reading config file: %s", path);

		line_num = 0;
		(void)config_from_file(vty, confp, &line_num);
		count++;

		fclose(confp);
	}

	/* Conditionally unlock as the config file may have "exit"d early which
	 * would then have unlocked things.
	 */
	if (vty->mgmt_locked_running_ds)
		vty_mgmt_unlock_running_inline(vty);
	if (vty->mgmt_locked_candidate_ds)
		vty_mgmt_unlock_candidate_inline(vty);

	vty->pending_allowed = false;

	if (!count)
		vty_close(vty);
	else
		vty_read_file_finish(vty, NULL);

	zlog_info("mgmtd: finished reading config files");

	return true;
}


/*
 * This is analogous to frr_config_read_in() in libfrr.c, but customized for
 * mgmtd. It reads in all the mgmt-enabled daemon config files, this method is
 * now deprecrated in favor of integrated config via vtysh.
 */
static void mgmt_config_read_in(struct event *event)
{
	if (vty_mgmt_fe_enabled())
		mgmt_vty_read_configs();
	else {
		zlog_warn("%s: no connection to front-end server, retry in 1s", __func__);
		event_add_timer(mm->master, mgmt_config_read_in, NULL, 1,
				&mgmt_daemon_info->read_in);
	}
}

static ssize_t vty_mgmt_libyang_print(void *user_data, const void *buf, size_t count)
{
	struct vty *vty = user_data;

	vty_out(vty, "%.*s", (int)count, (const char *)buf);
	return count;
}

static void vty_out_yang_error(struct vty *vty, LYD_FORMAT format, const struct ly_err_item *ei)
{
#if (LY_VERSION_MAJOR < 3)
#define data_path path
#else
#define data_path data_path
#endif
	bool have_apptag = ei->apptag && ei->apptag[0] != 0;
	bool have_path = ei->data_path && ei->data_path[0] != 0;
	bool have_msg = ei->msg && ei->msg[0] != 0;
	const char *severity = NULL;
	const char *evalid = NULL;
	const char *ecode = NULL;
#if (LY_VERSION_MAJOR < 3)
	LY_ERR err = ei->no;
#else
	LY_ERR err = ei->err;
#endif

	if (ei->level == LY_LLERR)
		severity = "error";
	else if (ei->level == LY_LLWRN)
		severity = "warning";

	ecode = yang_ly_strerrcode(err);
	if (err == LY_EVALID && ei->vecode != LYVE_SUCCESS)
		evalid = yang_ly_strvecode(ei->vecode);

	switch (format) {
	case LYD_XML:
		vty_out(vty, "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">");
		vty_out(vty, "<error-type>application</error-type>");
		if (severity)
			vty_out(vty, "<error-severity>%s</error-severity>", severity);
		if (ecode)
			vty_out(vty, "<error-code>%s</error-code>", ecode);
		if (evalid)
			vty_out(vty, "<error-validation>%s</error-validation>\n", evalid);
		if (have_path)
			vty_out(vty, "<error-path>%s</error-path>\n", ei->data_path);
		if (have_apptag)
			vty_out(vty, "<error-app-tag>%s</error-app-tag>\n", ei->apptag);
		if (have_msg)
			vty_out(vty, "<error-message>%s</error-message>\n", ei->msg);

		vty_out(vty, "</rpc-error>");
		break;
	case LYD_JSON:
		vty_out(vty, "{ \"error-type\": \"application\"");
		if (severity)
			vty_out(vty, ", \"error-severity\": \"%s\"", severity);
		if (ecode)
			vty_out(vty, ", \"error-code\": \"%s\"", ecode);
		if (evalid)
			vty_out(vty, ", \"error-validation\": \"%s\"", evalid);
		if (have_path)
			vty_out(vty, ", \"error-path\": \"%s\"", ei->data_path);
		if (have_apptag)
			vty_out(vty, ", \"error-app-tag\": \"%s\"", ei->apptag);
		if (have_msg)
			vty_out(vty, ", \"error-message\": \"%s\"", ei->msg);

		vty_out(vty, "}");
		break;
	case LYD_UNKNOWN:
	case LYD_LYB:
	default:
		vty_out(vty, "%% error");
		if (severity)
			vty_out(vty, " severity: %s", severity);
		if (evalid)
			vty_out(vty, " invalid: %s", evalid);
		if (have_path)
			vty_out(vty, " path: %s", ei->data_path);
		if (have_apptag)
			vty_out(vty, " app-tag: %s", ei->apptag);
		if (have_msg)
			vty_out(vty, " msg: %s", ei->msg);
		break;
	}
#undef data_path
}

static uint vty_out_yang_errors(struct vty *vty, LYD_FORMAT format)
{
	const struct ly_err_item *ei = ly_err_first(ly_native_ctx);
	uint count;

	if (!ei)
		return 0;

	if (format == LYD_JSON)
		vty_out(vty, "\"ietf-restconf:errors\": [ ");

	for (count = 0; ei; count++, ei = ei->next) {
		if (count)
			vty_out(vty, ", ");
		vty_out_yang_error(vty, format, ei);
	}

	if (format == LYD_JSON)
		vty_out(vty, " ]");

	ly_err_clean(ly_native_ctx, NULL);

	return count;
}


static int vty_mgmt_handle_error_reply(struct mgmt_fe_client *client, uintptr_t user_data,
				   uint64_t client_id, uint64_t session_id, uintptr_t session_ctx,
				   uint64_t req_id, int error, const char *errstr)
{
	struct vty *vty = (struct vty *)session_ctx;
	const char *cname = mgmt_fe_client_name(client);

	if (!vty->mgmt_req_pending_cmd) {
		debug_fe_client("Error with no pending command: %d returned for client %s 0x%Lx session-id %Lu req-id %Lu error-str %s",
				error, cname, client_id, session_id, req_id, errstr);
		vty_out(vty, "%% Error %d from MGMTD for %s with no pending command: %s\n", error,
			cname, errstr);
		return CMD_WARNING;
	}

	debug_fe_client("Error %d returned for client %s 0x%" PRIx64 " session-id %" PRIu64
			" req-id %" PRIu64 "error-str %s",
			error, cname, client_id, session_id, req_id, errstr);

	vty_out(vty, "%% %s (for %s, client %s)\n", errstr, vty->mgmt_req_pending_cmd, cname);

	vty_mgmt_resume_response(vty, error ? CMD_WARNING : CMD_SUCCESS);

	return 0;
}

/* =================================== */
/* Mgmtd Frontend Client Functionality */
/* =================================== */

/* ------- */
/* Locking */
/* ------- */

static int vty_mgmt_send_lockds_req(struct vty *vty, enum mgmt_ds_id ds_id, bool lock, bool scok)
{
	assert(mgmt_fe_client);
	assert(vty->mgmt_session_id);

	vty->mgmt_req_id++;
	if (mgmt_fe_send_lockds_req(mgmt_fe_client, vty->mgmt_session_id, vty->mgmt_req_id, ds_id,
				    lock, scok)) {
		zlog_err("Failed sending %sLOCK-DS-REQ req-id %" PRIu64, lock ? "" : "UN",
			 vty->mgmt_req_id);
		vty_out(vty, "Failed to send %sLOCK-DS-REQ to MGMTD!\n", lock ? "" : "UN");
		return -1;
	}

	if (!scok)
		vty->mgmt_req_pending_cmd = "MESSAGE_LOCKDS_REQ";

	return 0;
}

static void vty_mgmt_handle_lock_ds_reply(struct mgmt_fe_client *client, uintptr_t usr_data,
					  uint64_t client_id, uintptr_t session_id,
					  uintptr_t session_ctx, uint64_t req_id, bool lock_ds,
					  bool success, enum mgmt_ds_id ds_id, char *errmsg_if_any)
{
	struct vty *vty;
	bool is_short_circuit = mgmt_fe_client_current_msg_short_circuit(client);

	vty = (struct vty *)session_ctx;

	assert(ds_id == MGMTD_DS_CANDIDATE || ds_id == MGMTD_DS_RUNNING);
	if (!success)
		zlog_err("%socking for DS %u failed, Err: '%s' vty %p", lock_ds ? "L" : "Unl",
			 ds_id, errmsg_if_any, vty);
	else {
		debug_fe_client("%socked DS %u successfully", lock_ds ? "L" : "Unl", ds_id);
		if (ds_id == MGMTD_DS_CANDIDATE)
			vty->mgmt_locked_candidate_ds = lock_ds;
		else
			vty->mgmt_locked_running_ds = lock_ds;
	}

	if (!is_short_circuit && vty->mgmt_req_pending_cmd) {
		assert(!strcmp(vty->mgmt_req_pending_cmd, "MESSAGE_LOCKDS_REQ"));
		vty_mgmt_resume_response(vty, success ? CMD_SUCCESS : CMD_WARNING);
	}
}

/* ------------------------------------------------ */
/* "Send" Config Data -- actually just edits inline */
/* ------------------------------------------------ */

int vty_mgmt_send_config_data(struct vty *vty, const char *xpath_base, bool implicit_commit)
{
	char err_buf[BUFSIZ];
	bool error = false;

	if (implicit_commit) {
		assert(vty->mgmt_client_id && vty->mgmt_session_id);
		if (vty_mgmt_lock_candidate_inline(vty)) {
			vty_out(vty, "%% could not lock candidate DS\n");
			return CMD_WARNING_CONFIG_FAILED;
		} else if (vty_mgmt_lock_running_inline(vty)) {
			vty_out(vty, "%% could not lock running DS\n");
			vty_mgmt_unlock_candidate_inline(vty);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (!vty->mgmt_locked_candidate_ds)
		vty_out(vty, "%% WARNING: changing candidate datastore without lock.\n");

	nb_candidate_edit_config_changes(vty->candidate_config, vty->cfg_changes,
					 vty->num_cfg_changes, xpath_base, false, err_buf,
					 sizeof(err_buf), &error);
	if (error) {
		/*
		 * Failure to edit the candidate configuration should never
		 * happen in practice, unless there's a bug in the code. When
		 * that happens, log the error but otherwise ignore it.
		 */
		vty_out(vty, "%% Couldn't apply changes: %s", err_buf);
error:
		if (implicit_commit) {
			vty_mgmt_unlock_running_inline(vty);
			vty_mgmt_unlock_candidate_inline(vty);
		}
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!implicit_commit)
		return CMD_SUCCESS;

	assert(vty->mgmt_client_id && vty->mgmt_session_id);
	if (vty_mgmt_send_commit_config(vty, false, false, true) < 0)
		goto error;

	return CMD_SUCCESS;
}

/* ------------- */
/* Commit Config */
/* ------------- */

int vty_mgmt_send_commit_config(struct vty *vty, bool validate_only, bool abort, bool unlock)
{
	if (mgmt_fe_client && vty->mgmt_session_id) {
		vty->mgmt_req_id++;
		if (mgmt_fe_send_commit_req(mgmt_fe_client, vty->mgmt_session_id, vty->mgmt_req_id,
					    MGMTD_DS_CANDIDATE, MGMTD_DS_RUNNING, validate_only,
					    abort, unlock)) {
			zlog_err("Failed sending COMMIT-REQ req-id %" PRIu64, vty->mgmt_req_id);
			vty_out(vty, "Failed to send COMMIT-REQ to MGMTD!\n");
			return -1;
		}

		vty->mgmt_req_pending_cmd = "MESSAGE_COMMCFG_REQ";
		vty->mgmt_num_pending_setcfg = 0;
	}

	return 0;
}

static void vty_mgmt_handle_commit_config_reply(struct mgmt_fe_client *client, uintptr_t usr_data,
						uint64_t client_id, uintptr_t session_id,
						uintptr_t session_ctx, uint64_t req_id,
						bool success, enum mgmt_ds_id src_ds_id,
						enum mgmt_ds_id dst_ds_id, bool validate_only,
						bool unlock, char *errmsg_if_any)
{
	struct vty *vty;

	vty = (struct vty *)session_ctx;

	if (!success) {
		zlog_err("COMMIT_CONFIG request for client 0x%" PRIx64 " failed, Error: '%s'",
			 client_id, errmsg_if_any ? errmsg_if_any : "Unknown");
		vty_out(vty, "%% Configuration failed.\n\n");
		if (errmsg_if_any)
			vty_out(vty, "%s\n", errmsg_if_any);
	} else {
		debug_fe_client("COMMIT_CONFIG request for client 0x%" PRIx64 " req-id %" PRIu64
				" was successfull%s%s",
				client_id, req_id, errmsg_if_any ? ": " : "", errmsg_if_any ?: "");
		if (!unlock && errmsg_if_any)
			vty_out(vty, "MGMTD: %s\n", errmsg_if_any);
	}

	if (unlock) {
		/* we locked these when we sent the commit, unlock now */
		vty_mgmt_unlock_candidate_inline(vty);
		vty_mgmt_unlock_running_inline(vty);
	}

	vty_mgmt_resume_response(vty, success ? CMD_SUCCESS : CMD_WARNING_CONFIG_FAILED);
}

/* -------- */
/* Get Data */
/* -------- */

int vty_mgmt_send_get_data_req(struct vty *vty, uint8_t datastore, LYD_FORMAT result_type,
			       uint8_t flags, uint8_t defaults, const char *xpath)
{
	LYD_FORMAT intern_format = result_type;

	vty->mgmt_req_id++;

	if (mgmt_fe_send_get_data_req(mgmt_fe_client, vty->mgmt_session_id, vty->mgmt_req_id,
				      datastore, intern_format, flags, defaults, xpath)) {
		zlog_err("Failed to send GET-DATA to MGMTD session-id: %" PRIu64 " req-id %" PRIu64
			 ".",
			 vty->mgmt_session_id, vty->mgmt_req_id);
		vty_out(vty, "Failed to send GET-DATA to MGMTD!\n");
		return -1;
	}

	vty->mgmt_req_pending_cmd = "MESSAGE_GET_DATA_REQ";
	vty->mgmt_req_pending_data = result_type;

	return 0;
}

static int vty_mgmt_handle_get_tree_reply(struct mgmt_fe_client *client, uintptr_t user_data,
					  uint64_t client_id, uint64_t session_id,
					  uintptr_t session_ctx, uint64_t req_id,
					  enum mgmt_ds_id ds_id, LYD_FORMAT result_type,
					  void *result, size_t len, int partial_error)
{
	struct vty *vty;
	struct lyd_node *dnode;
	int ret = CMD_SUCCESS;
	LY_ERR err;

	vty = (struct vty *)session_ctx;

	debug_fe_client("GET_TREE request %ssucceeded, client 0x%" PRIx64 " req-id %" PRIu64,
			partial_error ? "partially " : "", client_id, req_id);

	assert(result_type == LYD_LYB || result_type == vty->mgmt_req_pending_data);

	if (vty->mgmt_req_pending_data == LYD_XML && partial_error)
		vty_out(vty, "<!-- some errors occurred gathering results -->\n");

	if (result_type == LYD_LYB) {
		/*
		 * parse binary into tree and print in the specified format
		 */
		result_type = vty->mgmt_req_pending_data;

		err = lyd_parse_data_mem(ly_native_ctx, result, LYD_LYB, 0, 0, &dnode);
		if (!err)
			err = lyd_print_clb(vty_mgmt_libyang_print, vty, dnode, result_type,
					    LYD_PRINT_WITHSIBLINGS);
		lyd_free_all(dnode);

		if (vty_out_yang_errors(vty, result_type) || err)
			ret = CMD_WARNING;
	} else {
		/*
		 * Print the in-format result
		 */
		assert(result_type == LYD_XML || result_type == LYD_JSON);
		vty_out(vty, "%.*s\n", (int)len - 1, (const char *)result);
	}

	vty_mgmt_resume_response(vty, ret);

	return 0;
}


/* ----------- */
/* Edit Config */
/* ----------- */

int vty_mgmt_send_edit_req(struct vty *vty, uint8_t datastore, LYD_FORMAT request_type,
			   uint8_t flags, uint8_t operation, const char *xpath, const char *data)
{
	vty->mgmt_req_id++;

	if (mgmt_fe_send_edit_req(mgmt_fe_client, vty->mgmt_session_id, vty->mgmt_req_id,
				  datastore, request_type, flags, operation, xpath, data)) {
		zlog_err("Failed to send EDIT to MGMTD session-id: %" PRIu64 " req-id %" PRIu64 ".",
			 vty->mgmt_session_id, vty->mgmt_req_id);
		vty_out(vty, "Failed to send EDIT to MGMTD!\n");
		return -1;
	}

	vty->mgmt_req_pending_cmd = "MESSAGE_EDIT_REQ";

	return 0;
}

static int vty_mgmt_handle_edit_reply(struct mgmt_fe_client *client, uintptr_t user_data,
				      uint64_t client_id, uint64_t session_id,
				      uintptr_t session_ctx, uint64_t req_id, const char *xpath)
{
	struct vty *vty = (struct vty *)session_ctx;

	debug_fe_client("EDIT request for client 0x%" PRIx64 " req-id %" PRIu64
			" was successful, xpath: %s",
			client_id, req_id, xpath);

	vty_mgmt_resume_response(vty, CMD_SUCCESS);

	return 0;
}


/* =========== */
/* Execute RPC */
/* =========== */

int vty_mgmt_send_rpc_req(struct vty *vty, LYD_FORMAT request_type, const char *xpath,
			  const char *data)
{
	vty->mgmt_req_id++;

	if (mgmt_fe_send_rpc_req(mgmt_fe_client, vty->mgmt_session_id, vty->mgmt_req_id,
				 request_type, xpath, data)) {
		zlog_err("Failed to send RPC to MGMTD session-id: %" PRIu64 " req-id %" PRIu64 ".",
			 vty->mgmt_session_id, vty->mgmt_req_id);
		vty_out(vty, "Failed to send RPC to MGMTD!\n");
		return -1;
	}

	vty->mgmt_req_pending_cmd = "MESSAGE_RPC_REQ";

	return 0;
}

static int vty_mgmt_handle_rpc_reply(struct mgmt_fe_client *client, uintptr_t user_data,
				     uint64_t client_id, uint64_t session_id,
				     uintptr_t session_ctx, uint64_t req_id, const char *result)
{
	struct vty *vty = (struct vty *)session_ctx;

	debug_fe_client("RPC request for client 0x%" PRIx64 " req-id %" PRIu64 " was successful",
			client_id, req_id);

	if (result)
		vty_out(vty, "%s\n", result);

	vty_mgmt_resume_response(vty, CMD_SUCCESS);

	return 0;
}


/* ==================================== */
/* VTY Augmenting/Hooking Functionality */
/* ==================================== */

static void vty_new_mgmt(struct vty *new)
{
	if (!mgmt_fe_client)
		return;
	if (!mgmt_client_id_next)
		mgmt_client_id_next++;
	new->mgmt_client_id = mgmt_client_id_next++;
	new->mgmt_session_id = 0;
	mgmt_fe_create_client_session(mgmt_fe_client, new->mgmt_client_id, (uintptr_t)new);

	/* we short-circuit create the session so it must be set now */
	assertf(new->mgmt_session_id != 0, "Failed to create client session for VTY");
}

static void vty_close_mgmt(struct vty *vty)
{
	if (!mgmt_fe_client || !vty->mgmt_client_id)
		return;

	debug_fe_client("closing vty session");
	mgmt_fe_destroy_client_session(mgmt_fe_client, vty->mgmt_client_id);
	vty->mgmt_session_id = 0;
}

static int vty_config_enter_mgmt(struct vty *vty, bool private_config, bool exclusive,
				 bool file_lock)
{
	/* if no file lock requested, nothing to do */
	if (!file_lock)
		return CMD_SUCCESS;

	/* Working on a private config is outside normal mgmtd actions */
	if (private_config)
		return CMD_SUCCESS;

	/* Exclude is actually what we are doing with file-lock so it's no-op */

	/*
	 * We only need to do a lock when reading a config file as we will be
	 * sending a batch of setcfg changes followed by a single commit
	 * message. For user interactive mode we are doing implicit commits
	 * those will obtain the lock (or not) when they try and commit.
	 */
	if (vty_mgmt_lock_candidate_inline(vty)) {
		vty_out(vty,
			"%% Can't enter config; candidate datastore locked by another session\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (vty_mgmt_lock_running_inline(vty)) {
		vty_out(vty,
			"%% Can't enter config; running datastore locked by another session\n");
		vty_mgmt_unlock_candidate_inline(vty);
		return CMD_WARNING_CONFIG_FAILED;
	}
	assert(vty->mgmt_locked_candidate_ds);
	assert(vty->mgmt_locked_running_ds);

	/*
	 * As datastores are locked explicitly, we don't need implicit commits
	 * and should allow pending changes.
	 */
	vty->pending_allowed = true;

	return CMD_SUCCESS;
}

static void vty_config_node_exit_mgmt(struct vty *vty)
{
	if (vty->mgmt_locked_running_ds)
		vty_mgmt_unlock_running_inline(vty);

	if (vty->mgmt_locked_candidate_ds)
		vty_mgmt_unlock_candidate_inline(vty);
}

static void vty_end_config_mgmt(struct vty *vty)
{
	/*
	 * If we have made changes with vty_mgmt_send_config_data(), but without
	 * implicit commit then we need to do a commit now to apply all those
	 * pending changes.
	 */
	if (vty->mgmt_num_pending_setcfg)
		vty_mgmt_send_commit_config(vty, false, false, false);
}

static int nb_cli_apply_changes_mgmt(struct vty *vty, const char *xpath_base_abs)
{
	bool implicit_commit;

	VTY_CHECK_XPATH;

	assert(vty->type != VTY_FILE && vty_mgmt_fe_enabled());
	/*
	 * The legacy user wanted to clear pending (i.e., perform a
	 * commit immediately) due to some non-yang compatible
	 * functionality. This new mgmtd code however, continues to send
	 * changes putting off the commit until XFRR_end is received
	 * (i.e., end-of-config-file). This should be fine b/c all
	 * conversions to mgmtd require full proper implementations.
	 */
	if (!vty->num_cfg_changes)
		return CMD_SUCCESS;

	implicit_commit = frr_get_cli_mode() == FRR_CLI_CLASSIC && !vty->pending_allowed;
	if (vty_mgmt_send_config_data(vty, xpath_base_abs,
			implicit_commit) != CMD_SUCCESS) {
		vty_out(vty, "%% Failed to apply configuration data.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!implicit_commit)
		++vty->mgmt_num_pending_setcfg;
	return CMD_SUCCESS;
}

static int nb_cli_rpc_mgmt(struct vty *vty, const char *xpath, const struct lyd_node *input)
{
	char *data = NULL;
	LY_ERR err;
	int ret;

	err = lyd_print_mem(&data, input, LYD_JSON, LYD_PRINT_SHRINK);
	assert(err == LY_SUCCESS);

	ret = vty_mgmt_send_rpc_req(vty, LYD_JSON, xpath, data);

	free(data);
	if (ret < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

static void fe_client_set_vty_callbacks(bool connected)
{
	if (connected) {
		/* only call when connected */
		vty_config_enter_mgmt_cb = vty_config_enter_mgmt;
		vty_config_node_exit_mgmt_cb = vty_config_node_exit_mgmt;
		cmd_init_config_callbacks(NULL, vty_end_config_mgmt);
		nb_cli_apply_changes_mgmt_cb = nb_cli_apply_changes_mgmt;
		nb_cli_rpc_mgmt_cb = nb_cli_rpc_mgmt;
	} else {
		vty_config_enter_mgmt_cb = NULL;
		vty_config_node_exit_mgmt_cb = NULL;
		cmd_init_config_callbacks(NULL, NULL);
		nb_cli_apply_changes_mgmt_cb = NULL;
		nb_cli_rpc_mgmt_cb = NULL;
	}
}

/* ====================== */
/* Initialize and Cleanup */
/* ====================== */

static void vty_mgmt_client_connect_notified(struct mgmt_fe_client *client, uintptr_t usr_data,
					     bool connected)
{
	debug_fe_client("Got %sconnected %s MGMTD Frontend Server", !connected ? "dis: " : "",
			!connected ? "from" : "to");

	/*
	 * We should not have any sessions for connecting or disconnecting case.
	 * The  fe client library will delete all session on disconnect before
	 * calling us.
	 */
	assert(mgmt_fe_client_session_count(client) == 0);

	mgmt_fe_connected = connected;
	fe_client_set_vty_callbacks(connected);

	/* Start or stop listening for vty connections */
	if (connected)
		frr_vty_serv_start(true);
	else
		frr_vty_serv_stop();
}

/*
 * A session has successfully been created for a vty.
 */
static void vty_mgmt_client_session_notified(struct mgmt_fe_client *client, uintptr_t usr_data,
					     uint64_t client_id, bool create, bool success,
					     uintptr_t session_id, uintptr_t session_ctx)
{
	struct vty *vty;

	vty = (struct vty *)session_ctx;

	if (!success) {
		zlog_err("%s session for client %" PRIu64 " failed!",
			 create ? "Creating" : "Destroying", client_id);
		return;
	}

	debug_fe_client("%s session for client %" PRIu64 " successfully",
			create ? "Created" : "Destroyed", client_id);

	if (create) {
		assert(session_id != 0);
		vty->mgmt_session_id = session_id;
	} else {
		vty->mgmt_session_id = 0;
		/* We may come here by way of vty_close() and short-circuits */
		if (vty->status != VTY_CLOSE)
			vty_close(vty);
	}
}


static struct mgmt_fe_client_cbs mgmt_cbs = {
	.client_connect_notify = vty_mgmt_client_connect_notified,
	.client_session_notify = vty_mgmt_client_session_notified,
	.lock_ds_notify = vty_mgmt_handle_lock_ds_reply,
	.commit_config_notify = vty_mgmt_handle_commit_config_reply,
	.get_tree_notify = vty_mgmt_handle_get_tree_reply,
	.edit_notify = vty_mgmt_handle_edit_reply,
	.rpc_notify = vty_mgmt_handle_rpc_reply,
	.error_notify = vty_mgmt_handle_error_reply,

};

void vty_mgmt_init(void)
{
	char name[40];

	assert(mm->master);
	assert(!mgmt_fe_client);
	snprintf(name, sizeof(name), "vty-%s-%ld", frr_get_progname(), (long)getpid());
	mgmt_fe_client = mgmt_fe_client_create(name, &mgmt_cbs, 0, mm->master);
	vty_new_mgmt_cb = vty_new_mgmt;
	vty_close_mgmt_cb = vty_close_mgmt;
	assert(mgmt_fe_client);

	event_add_event(mm->master, mgmt_config_read_in, NULL, 0, &mgmt_daemon_info->read_in);
}

void vty_mgmt_terminate(void)
{
	if (mgmt_fe_client) {
		mgmt_fe_client_destroy(mgmt_fe_client);
		mgmt_fe_client = NULL;
		vty_new_mgmt_cb = NULL;
		vty_close_mgmt_cb = NULL;
	}
}
