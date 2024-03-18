// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "log.h"
#include "lib_errors.h"
#include "command.h"
#include "debug.h"
#include "memory.h"
#include "libfrr.h"
#include "lib/version.h"
#include "northbound.h"

#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/xpath.h>

static struct debug nb_dbg_client_sysrepo = {0, "Northbound client: Sysrepo"};

static struct event_loop *master;
static sr_session_ctx_t *session;
static sr_conn_ctx_t *connection;
static struct nb_transaction *transaction;

static void frr_sr_read_cb(struct event *thread);
static int frr_sr_finish(void);

/* Convert FRR YANG data value to sysrepo YANG data value. */
static int yang_data_frr2sr(struct yang_data *frr_data, sr_val_t *sr_data)
{
	struct nb_node *nb_node;
	const struct lysc_node *snode;
	struct lysc_node_container *scontainer;
	struct lysc_node_leaf *sleaf;
	struct lysc_node_leaflist *sleaflist;
	LY_DATA_TYPE type;

	sr_val_set_xpath(sr_data, frr_data->xpath);

	nb_node = nb_node_find(frr_data->xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__,
			  frr_data->xpath);
		return -1;
	}

	snode = nb_node->snode;
	switch (snode->nodetype) {
	case LYS_CONTAINER:
		scontainer = (struct lysc_node_container *)snode;
		if (!CHECK_FLAG(scontainer->flags, LYS_PRESENCE))
			return -1;
		sr_data->type = SR_CONTAINER_PRESENCE_T;
		return 0;
	case LYS_LIST:
		sr_data->type = SR_LIST_T;
		return 0;
	case LYS_LEAF:
		sleaf = (struct lysc_node_leaf *)snode;
		type = sleaf->type->basetype;
		break;
	case LYS_LEAFLIST:
		sleaflist = (struct lysc_node_leaflist *)snode;
		type = sleaflist->type->basetype;
		break;
	default:
		return -1;
	}

	switch (type) {
	case LY_TYPE_BINARY:
		sr_val_set_str_data(sr_data, SR_BINARY_T, frr_data->value);
		break;
	case LY_TYPE_BITS:
		sr_val_set_str_data(sr_data, SR_BITS_T, frr_data->value);
		break;
	case LY_TYPE_BOOL:
		sr_data->type = SR_BOOL_T;
		sr_data->data.bool_val = yang_str2bool(frr_data->value);
		break;
	case LY_TYPE_DEC64:
		sr_data->type = SR_DECIMAL64_T;
		sr_data->data.decimal64_val =
			yang_str2dec64(frr_data->xpath, frr_data->value);
		break;
	case LY_TYPE_EMPTY:
		sr_data->type = SR_LEAF_EMPTY_T;
		break;
	case LY_TYPE_ENUM:
		sr_val_set_str_data(sr_data, SR_ENUM_T, frr_data->value);
		break;
	case LY_TYPE_IDENT:
		sr_val_set_str_data(sr_data, SR_IDENTITYREF_T, frr_data->value);
		break;
	case LY_TYPE_INST:
		sr_val_set_str_data(sr_data, SR_INSTANCEID_T, frr_data->value);
		break;
	case LY_TYPE_INT8:
		sr_data->type = SR_INT8_T;
		sr_data->data.int8_val = yang_str2int8(frr_data->value);
		break;
	case LY_TYPE_INT16:
		sr_data->type = SR_INT16_T;
		sr_data->data.int16_val = yang_str2int16(frr_data->value);
		break;
	case LY_TYPE_INT32:
		sr_data->type = SR_INT32_T;
		sr_data->data.int32_val = yang_str2int32(frr_data->value);
		break;
	case LY_TYPE_INT64:
		sr_data->type = SR_INT64_T;
		sr_data->data.int64_val = yang_str2int64(frr_data->value);
		break;
	case LY_TYPE_LEAFREF:
		sr_val_set_str_data(sr_data, SR_STRING_T, frr_data->value);
		break;
	case LY_TYPE_STRING:
		sr_val_set_str_data(sr_data, SR_STRING_T, frr_data->value);
		break;
	case LY_TYPE_UINT8:
		sr_data->type = SR_UINT8_T;
		sr_data->data.uint8_val = yang_str2uint8(frr_data->value);
		break;
	case LY_TYPE_UINT16:
		sr_data->type = SR_UINT16_T;
		sr_data->data.uint16_val = yang_str2uint16(frr_data->value);
		break;
	case LY_TYPE_UINT32:
		sr_data->type = SR_UINT32_T;
		sr_data->data.uint32_val = yang_str2uint32(frr_data->value);
		break;
	case LY_TYPE_UINT64:
		sr_data->type = SR_UINT64_T;
		sr_data->data.uint64_val = yang_str2uint64(frr_data->value);
		break;
	case LY_TYPE_UNION:
		/* No way to deal with this using un-typed yang_data object */
		sr_val_set_str_data(sr_data, SR_STRING_T, frr_data->value);
		break;
	case LY_TYPE_UNKNOWN:
	default:
		return -1;
	}

	return 0;
}

static int frr_sr_process_change(struct nb_config *candidate,
				 sr_change_oper_t sr_op, sr_val_t *sr_old_val,
				 sr_val_t *sr_new_val)
{
	struct nb_node *nb_node;
	enum nb_operation nb_op;
	sr_val_t *sr_data;
	const char *xpath;
	char value_str[YANG_VALUE_MAXLEN];
	struct yang_data *data;
	int ret;

	sr_data = sr_new_val ? sr_new_val : sr_old_val;
	assert(sr_data);

	xpath = sr_data->xpath;

	DEBUGD(&nb_dbg_client_sysrepo, "sysrepo: processing change [xpath %s]",
	       xpath);

	/* Non-presence container - nothing to do. */
	if (sr_data->type == SR_CONTAINER_T)
		return NB_OK;

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		return NB_ERR;
	}

	/* Map operation values. */
	switch (sr_op) {
	case SR_OP_CREATED:
		nb_op = NB_OP_CREATE;
		break;
	case SR_OP_MODIFIED:
		if (nb_is_operation_allowed(nb_node, NB_OP_MODIFY))
			nb_op = NB_OP_MODIFY;
		else
			/* Ignore list keys modifications. */
			return NB_OK;
		break;
	case SR_OP_DELETED:
		/*
		 * When a list is deleted or one of its keys is changed, we are
		 * notified about the removal of all of its leafs, even the ones
		 * that are non-optional. We need to ignore these notifications.
		 */
		if (!nb_is_operation_allowed(nb_node, NB_OP_DESTROY))
			return NB_OK;

		nb_op = NB_OP_DESTROY;
		break;
	case SR_OP_MOVED:
		nb_op = NB_OP_MOVE;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT,
			 "%s: unexpected operation %u [xpath %s]", __func__,
			 sr_op, xpath);
		return NB_ERR;
	}

	sr_val_to_buff(sr_data, value_str, sizeof(value_str));
	data = yang_data_new(xpath, value_str);

	ret = nb_candidate_edit(candidate, nb_node, nb_op, xpath, NULL, data);
	yang_data_free(data);
	if (ret != NB_OK) {
		flog_warn(
			EC_LIB_NB_CANDIDATE_EDIT_ERROR,
			"%s: failed to edit candidate configuration: operation [%s] xpath [%s]",
			__func__, nb_operation_name(nb_op), xpath);
		return NB_ERR;
	}

	return NB_OK;
}

static int frr_sr_config_change_cb_prepare(sr_session_ctx_t *session,
					   const char *module_name)
{
	sr_change_iter_t *it;
	int ret;
	sr_change_oper_t sr_op;
	sr_val_t *sr_old_val, *sr_new_val;
	struct nb_context context = {};
	struct nb_config *candidate;
	char errmsg[BUFSIZ] = {0};

	ret = sr_get_changes_iter(session, "//*", &it);
	if (ret != SR_ERR_OK) {
		flog_err(EC_LIB_LIBSYSREPO,
			 "%s: sr_get_changes_iter() failed for \"%s\"",
			 __func__, module_name);
		return ret;
	}

	candidate = nb_config_dup(running_config);

	while ((ret = sr_get_change_next(session, it, &sr_op, &sr_old_val,
					 &sr_new_val))
	       == SR_ERR_OK) {
		ret = frr_sr_process_change(candidate, sr_op, sr_old_val,
					    sr_new_val);
		sr_free_val(sr_old_val);
		sr_free_val(sr_new_val);
		if (ret != NB_OK)
			break;
	}

	sr_free_change_iter(it);
	if (ret != NB_OK && ret != SR_ERR_NOT_FOUND) {
		nb_config_free(candidate);
		return SR_ERR_INTERNAL;
	}

	transaction = NULL;
	context.client = NB_CLIENT_SYSREPO;
	/*
	 * Validate the configuration changes and allocate all resources
	 * required to apply them.
	 */
	ret = nb_candidate_commit_prepare(context, candidate, NULL,
					  &transaction, false, false, errmsg,
					  sizeof(errmsg));
	if (ret != NB_OK && ret != NB_ERR_NO_CHANGES) {
		flog_warn(EC_LIB_LIBSYSREPO,
			  "%s: failed to prepare configuration transaction: %s (%s)",
			  __func__, nb_err_name(ret), errmsg);
		sr_session_set_error_message(session, errmsg);
	}

	if (!transaction)
		nb_config_free(candidate);

	/* Map northbound return code to sysrepo return code. */
	switch (ret) {
	case NB_OK:
		return SR_ERR_OK;
	case NB_ERR_NO_CHANGES:
		return SR_ERR_OK;
	case NB_ERR_LOCKED:
		return SR_ERR_LOCKED;
	case NB_ERR_RESOURCE:
		return SR_ERR_NO_MEMORY;
	default:
		return SR_ERR_VALIDATION_FAILED;
	}
}

static int frr_sr_config_change_cb_apply(sr_session_ctx_t *session,
					 const char *module_name)
{
	/* Apply the transaction. */
	if (transaction) {
		struct nb_config *candidate = transaction->config;
		char errmsg[BUFSIZ] = {0};

		nb_candidate_commit_apply(transaction, true, NULL, errmsg,
					  sizeof(errmsg));
		nb_config_free(candidate);
	}

	return SR_ERR_OK;
}

static int frr_sr_config_change_cb_abort(sr_session_ctx_t *session,
					 const char *module_name)
{
	/* Abort the transaction. */
	if (transaction) {
		struct nb_config *candidate = transaction->config;
		char errmsg[BUFSIZ] = {0};

		nb_candidate_commit_abort(transaction, errmsg, sizeof(errmsg));
		nb_config_free(candidate);
	}

	return SR_ERR_OK;
}

/* Callback for changes in the running configuration. */
static int frr_sr_config_change_cb(sr_session_ctx_t *session, uint32_t sub_id,
				   const char *module_name, const char *xpath,
				   sr_event_t sr_ev, uint32_t request_id,
				   void *private_data)
{
	switch (sr_ev) {
	case SR_EV_ENABLED:
	case SR_EV_CHANGE:
		return frr_sr_config_change_cb_prepare(session, module_name);
	case SR_EV_DONE:
		return frr_sr_config_change_cb_apply(session, module_name);
	case SR_EV_ABORT:
		return frr_sr_config_change_cb_abort(session, module_name);
	case SR_EV_RPC:
	case SR_EV_UPDATE:
	default:
		flog_err(EC_LIB_LIBSYSREPO, "%s: unexpected sysrepo event: %u",
			 __func__, sr_ev);
		return SR_ERR_INTERNAL;
	}
}

/* Callback for state retrieval. */
static int frr_sr_state_cb(sr_session_ctx_t *session, uint32_t sub_id,
			   const char *module_name, const char *xpath,
			   const char *request_xpath, uint32_t request_id,
			   struct lyd_node **parent, void *private_ctx)
{
	struct lyd_node *dnode = NULL;

	dnode = *parent;
	if (nb_oper_iterate_legacy(request_xpath, NULL, 0, NULL, NULL, &dnode)) {
		flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
			  "%s: failed to obtain operational data [xpath %s]",
			  __func__, xpath);
		return SR_ERR_INTERNAL;
	}

	*parent = dnode;

	return SR_ERR_OK;
}
static int frr_sr_config_rpc_cb(sr_session_ctx_t *session, uint32_t sub_id,
				const char *xpath, const struct lyd_node *input,
				sr_event_t sr_ev, uint32_t request_id,
				struct lyd_node *output, void *private_ctx)
{
	struct nb_node *nb_node;
	int ret = SR_ERR_OK;
	char errmsg[BUFSIZ] = {0};

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		return SR_ERR_INTERNAL;
	}

	/* Execute callback registered for this XPath. */
	if (nb_callback_rpc(nb_node, xpath, input, output, errmsg,
			    sizeof(errmsg))
	    != NB_OK) {
		flog_warn(EC_LIB_NB_CB_RPC, "%s: rpc callback failed: %s",
			  __func__, xpath);
		ret = SR_ERR_OPERATION_FAILED;
	}

	return ret;
}

static int frr_sr_notification_send(const char *xpath, struct list *arguments)
{
	sr_val_t *values = NULL;
	size_t values_cnt = 0;
	int ret;

	if (arguments && listcount(arguments) > 0) {
		struct yang_data *data;
		struct listnode *node;
		int i = 0;

		values_cnt = listcount(arguments);
		ret = sr_new_values(values_cnt, &values);
		if (ret != SR_ERR_OK) {
			flog_err(EC_LIB_LIBSYSREPO, "%s: sr_new_values(): %s",
				 __func__, sr_strerror(ret));
			return NB_ERR;
		}

		for (ALL_LIST_ELEMENTS_RO(arguments, node, data)) {
			if (yang_data_frr2sr(data, &values[i++]) != 0) {
				flog_err(
					EC_LIB_SYSREPO_DATA_CONVERT,
					"%s: failed to convert data to sysrepo format",
					__func__);
				sr_free_values(values, values_cnt);
				return NB_ERR;
			}
		}
	}

	ret = sr_notif_send(session, xpath, values, values_cnt, 0, 0);
	if (ret != SR_ERR_OK) {
		flog_err(EC_LIB_LIBSYSREPO,
			 "%s: sr_event_notif_send() failed for xpath %s",
			 __func__, xpath);
		return NB_ERR;
	}

	return NB_OK;
}

static void frr_sr_read_cb(struct event *thread)
{
	struct yang_module *module = EVENT_ARG(thread);
	int fd = EVENT_FD(thread);
	int ret;

	ret = sr_subscription_process_events(module->sr_subscription, session,
					     NULL);
	if (ret != SR_ERR_OK) {
		flog_err(EC_LIB_LIBSYSREPO, "%s: sr_fd_event_process(): %s",
			 __func__, sr_strerror(ret));
		return;
	}

	event_add_read(master, frr_sr_read_cb, module, fd, &module->sr_thread);
}

static void frr_sr_subscribe_config(struct yang_module *module)
{
	int ret;

	DEBUGD(&nb_dbg_client_sysrepo,
	       "sysrepo: subscribing for configuration changes made in the '%s' module",
	       module->name);

	ret = sr_module_change_subscribe(
		session, module->name, NULL, frr_sr_config_change_cb, NULL, 0,
		SR_SUBSCR_DEFAULT | SR_SUBSCR_ENABLED | SR_SUBSCR_NO_THREAD,
		&module->sr_subscription);
	if (ret != SR_ERR_OK)
		flog_err(EC_LIB_LIBSYSREPO, "sr_module_change_subscribe(): %s",
			 sr_strerror(ret));
}

static int frr_sr_subscribe_state(const struct lysc_node *snode, void *arg)
{
	struct yang_module *module = arg;
	struct nb_node *nb_node;
	int ret;

	if (!CHECK_FLAG(snode->flags, LYS_CONFIG_R))
		return YANG_ITER_CONTINUE;
	/* We only need to subscribe to the root of the state subtrees. */
	if (snode->parent && CHECK_FLAG(snode->parent->flags, LYS_CONFIG_R))
		return YANG_ITER_CONTINUE;

	nb_node = snode->priv;
	if (!nb_node)
		return YANG_ITER_CONTINUE;

	DEBUGD(&nb_dbg_client_sysrepo, "sysrepo: providing data to '%s'",
	       nb_node->xpath);

	ret = sr_oper_get_subscribe(session, snode->module->name,
				    nb_node->xpath, frr_sr_state_cb, NULL, 0,
				    &module->sr_subscription);
	if (ret != SR_ERR_OK)
		flog_err(EC_LIB_LIBSYSREPO, "sr_oper_get_items_subscribe(): %s",
			 sr_strerror(ret));

	return YANG_ITER_CONTINUE;
}

static int frr_sr_subscribe_rpc(const struct lysc_node *snode, void *arg)
{
	struct yang_module *module = arg;
	struct nb_node *nb_node;
	int ret;

	if (snode->nodetype != LYS_RPC)
		return YANG_ITER_CONTINUE;

	nb_node = snode->priv;
	if (!nb_node)
		return YANG_ITER_CONTINUE;

	DEBUGD(&nb_dbg_client_sysrepo, "sysrepo: providing RPC to '%s'",
	       nb_node->xpath);

	ret = sr_rpc_subscribe_tree(session, nb_node->xpath,
				    frr_sr_config_rpc_cb, NULL, 0, 0,
				    &module->sr_subscription);
	if (ret != SR_ERR_OK)
		flog_err(EC_LIB_LIBSYSREPO, "sr_rpc_subscribe(): %s",
			 sr_strerror(ret));

	return YANG_ITER_CONTINUE;
}

/* CLI commands. */
DEFUN (debug_nb_sr,
       debug_nb_sr_cmd,
       "[no] debug northbound client sysrepo",
       NO_STR
       DEBUG_STR
       "Northbound debugging\n"
       "Northbound client\n"
       "Sysrepo\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");

	DEBUG_MODE_SET(&nb_dbg_client_sysrepo, mode, !no);

	return CMD_SUCCESS;
}

static int frr_sr_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&nb_dbg_client_sysrepo, DEBUG_MODE_CONF))
		vty_out(vty, "debug northbound client sysrepo\n");

	return 0;
}

static int frr_sr_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&nb_dbg_client_sysrepo, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&nb_dbg_client_sysrepo, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&nb_dbg_client_sysrepo);

	return 0;
}

static void frr_sr_cli_init(void)
{
	hook_register(nb_client_debug_config_write, frr_sr_debug_config_write);
	hook_register(nb_client_debug_set_all, frr_sr_debug_set_all);

	install_element(ENABLE_NODE, &debug_nb_sr_cmd);
	install_element(CONFIG_NODE, &debug_nb_sr_cmd);
}

/* FRR's Sysrepo initialization. */
static int frr_sr_init(void)
{
	struct yang_module *module;
	int ret;

	/* Connect to Sysrepo. */
	ret = sr_connect(SR_CONN_DEFAULT, &connection);
	if (ret != SR_ERR_OK) {
		flog_err(EC_LIB_SYSREPO_INIT, "%s: sr_connect(): %s", __func__,
			 sr_strerror(ret));
		goto cleanup;
	}

	/* Start session. */
	ret = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (ret != SR_ERR_OK) {
		flog_err(EC_LIB_SYSREPO_INIT, "%s: sr_session_start(): %s",
			 __func__, sr_strerror(ret));
		goto cleanup;
	}

	/* Perform subscriptions. */
	RB_FOREACH (module, yang_modules, &yang_modules) {
		int event_pipe;

		frr_sr_subscribe_config(module);
		yang_snodes_iterate(module->info, frr_sr_subscribe_state, 0,
				    module);
		yang_snodes_iterate(module->info, frr_sr_subscribe_rpc, 0,
				    module);

		/* Watch subscriptions. */
		ret = sr_get_event_pipe(module->sr_subscription, &event_pipe);
		if (ret != SR_ERR_OK) {
			flog_err(EC_LIB_SYSREPO_INIT,
				 "%s: sr_get_event_pipe(): %s", __func__,
				 sr_strerror(ret));
			goto cleanup;
		}
		event_add_read(master, frr_sr_read_cb, module, event_pipe,
			       &module->sr_thread);
	}

	hook_register(nb_notification_send, frr_sr_notification_send);

	return 0;

cleanup:
	frr_sr_finish();

	return -1;
}

static int frr_sr_finish(void)
{
	struct yang_module *module;

	RB_FOREACH (module, yang_modules, &yang_modules) {
		if (!module->sr_subscription)
			continue;
		sr_unsubscribe(module->sr_subscription);
		EVENT_OFF(module->sr_thread);
	}

	if (session)
		sr_session_stop(session);
	if (connection)
		sr_disconnect(connection);

	return 0;
}

static int frr_sr_module_config_loaded(struct event_loop *tm)
{
	master = tm;

	if (frr_sr_init() < 0) {
		flog_err(EC_LIB_SYSREPO_INIT,
			 "failed to initialize the Sysrepo module");
		return -1;
	}

	hook_register(frr_fini, frr_sr_finish);

	return 0;
}

static int frr_sr_module_late_init(struct event_loop *tm)
{
	frr_sr_cli_init();

	return 0;
}

static int frr_sr_module_init(void)
{
	hook_register(frr_late_init, frr_sr_module_late_init);
	hook_register(frr_config_post, frr_sr_module_config_loaded);

	return 0;
}

FRR_MODULE_SETUP(.name = "frr_sysrepo", .version = FRR_VERSION,
		 .description = "FRR sysrepo integration module",
		 .init = frr_sr_module_init,
);
