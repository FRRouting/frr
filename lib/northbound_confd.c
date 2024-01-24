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
#include "libfrr.h"
#include "lib/version.h"
#include "northbound.h"

#include <confd_lib.h>
#include <confd_cdb.h>
#include <confd_dp.h>
#include <confd_maapi.h>

DEFINE_MTYPE_STATIC(LIB, CONFD, "ConfD module");

static struct debug nb_dbg_client_confd = {0, "Northbound client: ConfD"};

static struct event_loop *master;
static struct sockaddr confd_addr;
static int cdb_sub_sock, dp_ctl_sock, dp_worker_sock;
static struct event *t_cdb_sub, *t_dp_ctl, *t_dp_worker;
static struct confd_daemon_ctx *dctx;
static struct confd_notification_ctx *live_ctx;
static bool confd_connected;
static struct list *confd_spoints;
static struct nb_transaction *transaction;

static void frr_confd_finish_cdb(void);
static void frr_confd_finish_dp(void);
static int frr_confd_finish(void);

#define flog_err_confd(funcname)                                               \
	flog_err(EC_LIB_LIBCONFD, "%s: %s() failed: %s (%d): %s", __func__,    \
		 (funcname), confd_strerror(confd_errno), confd_errno,         \
		 confd_lasterr())


/* ------------ Utils ------------ */

/* Get XPath string from ConfD hashed keypath. */
static void frr_confd_get_xpath(const confd_hkeypath_t *kp, char *xpath,
				size_t len)
{
	char *p;

	confd_xpath_pp_kpath(xpath, len, 0, kp);

	/*
	 * Replace double quotes by single quotes (the format accepted by the
	 * northbound API).
	 */
	p = xpath;
	while ((p = strchr(p, '"')) != NULL)
		*p++ = '\'';
}

/* Convert ConfD binary value to a string. */
static int frr_confd_val2str(const char *xpath, const confd_value_t *value,
			     char *string, size_t string_size)
{
	struct confd_cs_node *csp;

	csp = confd_cs_node_cd(NULL, xpath);
	if (!csp) {
		flog_err_confd("confd_cs_node_cd");
		return -1;
	}
	if (confd_val2str(csp->info.type, value, string, string_size)
	    == CONFD_ERR) {
		flog_err_confd("confd_val2str");
		return -1;
	}

	return 0;
}

/* Obtain list entry from ConfD hashed keypath. */
static int frr_confd_hkeypath_get_list_entry(const confd_hkeypath_t *kp,
					     struct nb_node *nb_node,
					     const void **list_entry)
{
	struct nb_node *nb_node_list;
	int parent_lists = 0;
	int curr_list = 0;

	*list_entry = NULL;

	/*
	 * Count the number of YANG lists in the path, disconsidering the
	 * last element.
	 */
	nb_node_list = nb_node;
	while (nb_node_list->parent_list) {
		nb_node_list = nb_node_list->parent_list;
		parent_lists++;
	}
	if (nb_node->snode->nodetype != LYS_LIST && parent_lists == 0)
		return 0;

	/* Start from the beginning and move down the tree. */
	for (int i = kp->len; i >= 0; i--) {
		struct yang_list_keys keys;

		/* Not a YANG list. */
		if (kp->v[i][0].type != C_BUF)
			continue;

		/* Obtain list keys. */
		memset(&keys, 0, sizeof(keys));
		for (int j = 0; kp->v[i][j].type != C_NOEXISTS; j++) {
			strlcpy(keys.key[keys.num],
				(char *)kp->v[i][j].val.buf.ptr,
				sizeof(keys.key[keys.num]));
			keys.num++;
		}

		/* Obtain northbound node associated to the YANG list. */
		nb_node_list = nb_node;
		for (int j = curr_list; j < parent_lists; j++)
			nb_node_list = nb_node_list->parent_list;

		/* Obtain list entry. */
		if (!CHECK_FLAG(nb_node_list->flags, F_NB_NODE_KEYLESS_LIST)) {
			*list_entry = nb_callback_lookup_entry(
				nb_node, *list_entry, &keys);
			if (*list_entry == NULL)
				return -1;
		} else {
			unsigned long ptr_ulong;

			/* Retrieve list entry from pseudo-key (string). */
			if (sscanf(keys.key[0], "%lu", &ptr_ulong) != 1)
				return -1;
			*list_entry = (const void *)ptr_ulong;
		}

		curr_list++;
	}

	return 0;
}

/* Fill the current date and time into a confd_datetime structure. */
static void getdatetime(struct confd_datetime *datetime)
{
	struct tm tm;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	gmtime_r(&tv.tv_sec, &tm);

	memset(datetime, 0, sizeof(*datetime));
	datetime->year = 1900 + tm.tm_year;
	datetime->month = tm.tm_mon + 1;
	datetime->day = tm.tm_mday;
	datetime->sec = tm.tm_sec;
	datetime->micro = tv.tv_usec;
	datetime->timezone = 0;
	datetime->timezone_minutes = 0;
	datetime->hour = tm.tm_hour;
	datetime->min = tm.tm_min;
}

/* ------------ CDB code ------------ */

struct cdb_iter_args {
	struct nb_config *candidate;
	bool error;
};

static enum cdb_iter_ret
frr_confd_cdb_diff_iter(confd_hkeypath_t *kp, enum cdb_iter_op cdb_op,
			confd_value_t *oldv, confd_value_t *newv, void *args)
{
	char xpath[XPATH_MAXLEN];
	struct nb_node *nb_node;
	enum nb_operation nb_op;
	struct cdb_iter_args *iter_args = args;
	char value_str[YANG_VALUE_MAXLEN];
	struct yang_data *data;
	char *sb1, *sb2;
	int ret;

	frr_confd_get_xpath(kp, xpath, sizeof(xpath));

	/*
	 * HACK: obtain value of leaf-list elements from the XPath due to
	 * a bug in the ConfD API.
	 */
	value_str[0] = '\0';
	sb1 = strrchr(xpath, '[');
	sb2 = strrchr(xpath, ']');
	if (sb1 && sb2 && !strchr(sb1, '=')) {
		*sb2 = '\0';
		strlcpy(value_str, sb1 + 1, sizeof(value_str));
		*sb1 = '\0';
	}

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		iter_args->error = true;
		return ITER_STOP;
	}

	/* Map operation values. */
	switch (cdb_op) {
	case MOP_CREATED:
		nb_op = NB_OP_CREATE;
		break;
	case MOP_DELETED:
		nb_op = NB_OP_DESTROY;
		break;
	case MOP_VALUE_SET:
		if (nb_is_operation_allowed(nb_node, NB_OP_MODIFY))
			nb_op = NB_OP_MODIFY;
		else
			/* Ignore list keys modifications. */
			return ITER_RECURSE;
		break;
	case MOP_MOVED_AFTER:
		nb_op = NB_OP_MOVE;
		break;
	case MOP_MODIFIED:
		/* We're not interested on this. */
		return ITER_RECURSE;
	default:
		flog_err(EC_LIB_DEVELOPMENT,
			 "%s: unexpected operation %u [xpath %s]", __func__,
			 cdb_op, xpath);
		iter_args->error = true;
		return ITER_STOP;
	}

	/* Convert ConfD value to a string. */
	if (nb_node->snode->nodetype != LYS_LEAFLIST && newv
	    && frr_confd_val2str(nb_node->xpath, newv, value_str,
				 sizeof(value_str))
		       != 0) {
		flog_err(EC_LIB_CONFD_DATA_CONVERT,
			 "%s: failed to convert ConfD value to a string",
			 __func__);
		iter_args->error = true;
		return ITER_STOP;
	}

	/* Edit the candidate configuration. */
	data = yang_data_new(xpath, value_str);
	ret = nb_candidate_edit(iter_args->candidate, nb_node, nb_op, xpath,
				NULL, data);
	yang_data_free(data);
	if (ret != NB_OK) {
		flog_warn(
			EC_LIB_NB_CANDIDATE_EDIT_ERROR,
			"%s: failed to edit candidate configuration: operation [%s] xpath [%s]",
			__func__, nb_operation_name(nb_op), xpath);
		iter_args->error = true;
		return ITER_STOP;
	}

	return ITER_RECURSE;
}

static void frr_confd_cdb_read_cb_prepare(int fd, int *subp, int reslen)
{
	struct nb_context context = {};
	struct nb_config *candidate;
	struct cdb_iter_args iter_args;
	char errmsg[BUFSIZ] = {0};
	int ret;

	candidate = nb_config_dup(running_config);

	/* Iterate over all configuration changes. */
	iter_args.candidate = candidate;
	iter_args.error = false;
	for (int i = 0; i < reslen; i++) {
		if (cdb_diff_iterate(fd, subp[i], frr_confd_cdb_diff_iter,
				     ITER_WANT_PREV, &iter_args)
		    != CONFD_OK) {
			flog_err_confd("cdb_diff_iterate");
		}
	}
	free(subp);

	if (iter_args.error) {
		nb_config_free(candidate);

		if (cdb_sub_abort_trans(
			    cdb_sub_sock, CONFD_ERRCODE_APPLICATION_INTERNAL, 0,
			    0, "Couldn't apply configuration changes")
		    != CONFD_OK) {
			flog_err_confd("cdb_sub_abort_trans");
			return;
		}
		return;
	}

	/*
	 * Validate the configuration changes and allocate all resources
	 * required to apply them.
	 */
	transaction = NULL;
	context.client = NB_CLIENT_CONFD;
	ret = nb_candidate_commit_prepare(context, candidate, NULL,
					  &transaction, false, false, errmsg,
					  sizeof(errmsg));
	if (ret != NB_OK && ret != NB_ERR_NO_CHANGES) {
		enum confd_errcode errcode;

		switch (ret) {
		case NB_ERR_LOCKED:
			errcode = CONFD_ERRCODE_IN_USE;
			break;
		case NB_ERR_RESOURCE:
			errcode = CONFD_ERRCODE_RESOURCE_DENIED;
			break;
		default:
			errcode = CONFD_ERRCODE_APPLICATION;
			break;
		}

		/* Reject the configuration changes. */
		if (cdb_sub_abort_trans(cdb_sub_sock, errcode, 0, 0, "%s",
					errmsg)
		    != CONFD_OK) {
			flog_err_confd("cdb_sub_abort_trans");
			return;
		}
	} else {
		/* Acknowledge the notification. */
		if (cdb_sync_subscription_socket(fd, CDB_DONE_PRIORITY)
		    != CONFD_OK) {
			flog_err_confd("cdb_sync_subscription_socket");
			return;
		}

		/* No configuration changes. */
		if (!transaction)
			nb_config_free(candidate);
	}
}

static void frr_confd_cdb_read_cb_commit(int fd, int *subp, int reslen)
{
	/*
	 * No need to process the configuration changes again as we're already
	 * keeping track of them in the "transaction" variable.
	 */
	free(subp);

	/* Apply the transaction. */
	if (transaction) {
		struct nb_config *candidate = transaction->config;
		char errmsg[BUFSIZ] = {0};

		nb_candidate_commit_apply(transaction, true, NULL, errmsg,
					  sizeof(errmsg));
		nb_config_free(candidate);
	}

	/* Acknowledge the notification. */
	if (cdb_sync_subscription_socket(fd, CDB_DONE_PRIORITY) != CONFD_OK) {
		flog_err_confd("cdb_sync_subscription_socket");
		return;
	}
}

static int frr_confd_cdb_read_cb_abort(int fd, int *subp, int reslen)
{
	/*
	 * No need to process the configuration changes again as we're already
	 * keeping track of them in the "transaction" variable.
	 */
	free(subp);

	/* Abort the transaction. */
	if (transaction) {
		struct nb_config *candidate = transaction->config;
		char errmsg[BUFSIZ] = {0};

		nb_candidate_commit_abort(transaction, errmsg, sizeof(errmsg));
		nb_config_free(candidate);
	}

	/* Acknowledge the notification. */
	if (cdb_sync_subscription_socket(fd, CDB_DONE_PRIORITY) != CONFD_OK) {
		flog_err_confd("cdb_sync_subscription_socket");
		return -1;
	}

	return 0;
}

static void frr_confd_cdb_read_cb(struct event *thread)
{
	int fd = EVENT_FD(thread);
	enum cdb_sub_notification cdb_ev;
	int flags;
	int *subp = NULL;
	int reslen = 0;

	event_add_read(master, frr_confd_cdb_read_cb, NULL, fd, &t_cdb_sub);

	if (cdb_read_subscription_socket2(fd, &cdb_ev, &flags, &subp, &reslen)
	    != CONFD_OK) {
		flog_err_confd("cdb_read_subscription_socket2");
		return;
	}

	switch (cdb_ev) {
	case CDB_SUB_PREPARE:
		frr_confd_cdb_read_cb_prepare(fd, subp, reslen);
		break;
	case CDB_SUB_COMMIT:
		frr_confd_cdb_read_cb_commit(fd, subp, reslen);
		break;
	case CDB_SUB_ABORT:
		frr_confd_cdb_read_cb_abort(fd, subp, reslen);
		break;
	default:
		flog_err_confd("unknown CDB event");
		break;
	}
}

/* Trigger CDB subscriptions to read the startup configuration. */
static void *thread_cdb_trigger_subscriptions(void *data)
{
	int sock;
	int *sub_points = NULL, len = 0;
	struct listnode *node;
	int *spoint;
	int i = 0;

	/* Create CDB data socket. */
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		flog_err(EC_LIB_SOCKET, "%s: failed to create socket: %s",
			 __func__, safe_strerror(errno));
		return NULL;
	}

	if (cdb_connect(sock, CDB_DATA_SOCKET, &confd_addr,
			sizeof(struct sockaddr_in))
	    != CONFD_OK) {
		flog_err_confd("cdb_connect");
		return NULL;
	}

	/*
	 * Fill array containing the subscription point of all loaded YANG
	 * modules.
	 */
	len = listcount(confd_spoints);
	sub_points = XCALLOC(MTYPE_CONFD, len * sizeof(int));
	for (ALL_LIST_ELEMENTS_RO(confd_spoints, node, spoint))
		sub_points[i++] = *spoint;

	if (cdb_trigger_subscriptions(sock, sub_points, len) != CONFD_OK) {
		flog_err_confd("cdb_trigger_subscriptions");
		return NULL;
	}

	/* Cleanup and exit thread. */
	XFREE(MTYPE_CONFD, sub_points);
	cdb_close(sock);

	return NULL;
}

static int frr_confd_subscribe(const struct lysc_node *snode, void *arg)
{
	struct yang_module *module = arg;
	struct nb_node *nb_node;
	int *spoint;
	int ret;

	switch (snode->nodetype) {
	case LYS_CONTAINER:
	case LYS_LEAF:
	case LYS_LEAFLIST:
	case LYS_LIST:
		break;
	default:
		return YANG_ITER_CONTINUE;
	}

	if (CHECK_FLAG(snode->flags, LYS_CONFIG_R))
		return YANG_ITER_CONTINUE;

	nb_node = snode->priv;
	if (!nb_node)
		return YANG_ITER_CONTINUE;

	DEBUGD(&nb_dbg_client_confd, "%s: subscribing to '%s'", __func__,
	       nb_node->xpath);

	spoint = XMALLOC(MTYPE_CONFD, sizeof(*spoint));
	ret = cdb_subscribe2(cdb_sub_sock, CDB_SUB_RUNNING_TWOPHASE,
			     CDB_SUB_WANT_ABORT_ON_ABORT, 3, spoint,
			     module->confd_hash, nb_node->xpath);
	if (ret != CONFD_OK) {
		flog_err_confd("cdb_subscribe2");
		XFREE(MTYPE_CONFD, spoint);
		return YANG_ITER_CONTINUE;
	}

	listnode_add(confd_spoints, spoint);
	return YANG_ITER_CONTINUE;
}

static int frr_confd_init_cdb(void)
{
	struct yang_module *module;
	pthread_t cdb_trigger_thread;

	/* Create CDB subscription socket. */
	cdb_sub_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (cdb_sub_sock < 0) {
		flog_err(EC_LIB_SOCKET, "%s: failed to create socket: %s",
			 __func__, safe_strerror(errno));
		return -1;
	}

	if (cdb_connect(cdb_sub_sock, CDB_SUBSCRIPTION_SOCKET, &confd_addr,
			sizeof(struct sockaddr_in))
	    != CONFD_OK) {
		flog_err_confd("cdb_connect");
		goto error;
	}

	/* Subscribe to all loaded YANG data modules. */
	confd_spoints = list_new();
	RB_FOREACH (module, yang_modules, &yang_modules) {
		module->confd_hash = confd_str2hash(module->info->ns);
		if (module->confd_hash == 0) {
			flog_err(
				EC_LIB_LIBCONFD,
				"%s: failed to find hash value for namespace %s",
				__func__, module->info->ns);
			goto error;
		}

		/*
		 * The CDB API doesn't provide a mechanism to subscribe to an
		 * entire YANG module. So we have to find the top level
		 * nodes ourselves and subscribe to their paths.
		 */
		yang_snodes_iterate(module->info, frr_confd_subscribe, 0,
				    module);
	}

	if (cdb_subscribe_done(cdb_sub_sock) != CONFD_OK) {
		flog_err_confd("cdb_subscribe_done");
		goto error;
	}

	/* Create short lived pthread to trigger the CDB subscriptions. */
	if (pthread_create(&cdb_trigger_thread, NULL,
			   thread_cdb_trigger_subscriptions, NULL)) {
		flog_err(EC_LIB_SYSTEM_CALL, "%s: error creating pthread: %s",
			 __func__, safe_strerror(errno));
		goto error;
	}
	pthread_detach(cdb_trigger_thread);

	event_add_read(master, frr_confd_cdb_read_cb, NULL, cdb_sub_sock,
		       &t_cdb_sub);

	return 0;

error:
	frr_confd_finish_cdb();

	return -1;
}

static void frr_confd_finish_cdb(void)
{
	if (cdb_sub_sock > 0) {
		EVENT_OFF(t_cdb_sub);
		cdb_close(cdb_sub_sock);
	}
}

/* ------------ DP code ------------ */

static int frr_confd_transaction_init(struct confd_trans_ctx *tctx)
{
	confd_trans_set_fd(tctx, dp_worker_sock);

	return CONFD_OK;
}

#define CONFD_MAX_CHILD_NODES 32

static int frr_confd_data_get_elem(struct confd_trans_ctx *tctx,
				   confd_hkeypath_t *kp)
{
	struct nb_node *nb_node;
	char xpath[XPATH_MAXLEN];
	struct yang_data *data;
	confd_value_t v;
	const void *list_entry = NULL;

	frr_confd_get_xpath(kp, xpath, sizeof(xpath));

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		confd_data_reply_not_found(tctx);
		return CONFD_OK;
	}

	if (frr_confd_hkeypath_get_list_entry(kp, nb_node, &list_entry) != 0) {
		confd_data_reply_not_found(tctx);
		return CONFD_OK;
	}

	data = nb_callback_get_elem(nb_node, xpath, list_entry);
	if (data) {
		if (data->value) {
			CONFD_SET_STR(&v, data->value);
			confd_data_reply_value(tctx, &v);
		} else
			confd_data_reply_found(tctx);
		yang_data_free(data);
	} else
		confd_data_reply_not_found(tctx);

	return CONFD_OK;
}

static int frr_confd_data_get_next(struct confd_trans_ctx *tctx,
				   confd_hkeypath_t *kp, long next)
{
	struct nb_node *nb_node;
	char xpath[XPATH_MAXLEN];
	struct yang_data *data;
	const void *parent_list_entry, *nb_next;
	confd_value_t v[LIST_MAXKEYS];

	frr_confd_get_xpath(kp, xpath, sizeof(xpath));

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		confd_data_reply_next_key(tctx, NULL, -1, -1);
		return CONFD_OK;
	}

	if (frr_confd_hkeypath_get_list_entry(kp, nb_node, &parent_list_entry)
	    != 0) {
		/* List entry doesn't exist anymore. */
		confd_data_reply_next_key(tctx, NULL, -1, -1);
		return CONFD_OK;
	}

	nb_next = nb_callback_get_next(nb_node, parent_list_entry,
				       (next == -1) ? NULL : (void *)next);
	if (!nb_next) {
		/* End of the list or leaf-list. */
		confd_data_reply_next_key(tctx, NULL, -1, -1);
		return CONFD_OK;
	}

	switch (nb_node->snode->nodetype) {
	case LYS_LIST:
		if (!CHECK_FLAG(nb_node->flags, F_NB_NODE_KEYLESS_LIST)) {
			struct yang_list_keys keys;

			memset(&keys, 0, sizeof(keys));
			if (nb_callback_get_keys(nb_node, nb_next, &keys)
			    != NB_OK) {
				flog_warn(EC_LIB_NB_CB_STATE,
					  "%s: failed to get list keys",
					  __func__);
				confd_data_reply_next_key(tctx, NULL, -1, -1);
				return CONFD_OK;
			}

			/* Feed keys to ConfD. */
			for (size_t i = 0; i < keys.num; i++)
				CONFD_SET_STR(&v[i], keys.key[i]);
			confd_data_reply_next_key(tctx, v, keys.num,
						  (long)nb_next);
		} else {
			char pointer_str[32];

			/*
			 * ConfD 6.6 user guide, chapter 6.11 (Operational data
			 * lists without keys):
			 * "To support this without having completely separate
			 * APIs, we use a "pseudo" key in the ConfD APIs for
			 * this type of list. This key is not part of the data
			 * model, and completely hidden in the northbound agent
			 * interfaces, but is used with e.g. the get_next() and
			 * get_elem() callbacks as if it were a normal key. This
			 * "pseudo" key is always a single signed 64-bit
			 * integer, i.e. the confd_value_t type is C_INT64. The
			 * values can be chosen arbitrarily by the application,
			 * as long as a key value returned by get_next() can be
			 * used to get the data for the corresponding list entry
			 * with get_elem() or get_object() as usual. It could
			 * e.g. be an index into an array that holds the data,
			 * or even a memory address in integer form".
			 *
			 * Since we're using the CONFD_DAEMON_FLAG_STRINGSONLY
			 * option, we must convert our pseudo-key (a void
			 * pointer) to a string before sending it to confd.
			 */
			snprintf(pointer_str, sizeof(pointer_str), "%lu",
				 (unsigned long)nb_next);
			CONFD_SET_STR(&v[0], pointer_str);
			confd_data_reply_next_key(tctx, v, 1, (long)nb_next);
		}
		break;
	case LYS_LEAFLIST:
		data = nb_callback_get_elem(nb_node, xpath, nb_next);
		if (data) {
			if (data->value) {
				CONFD_SET_STR(&v[0], data->value);
				confd_data_reply_next_key(tctx, v, 1,
							  (long)nb_next);
			}
			yang_data_free(data);
		} else
			confd_data_reply_next_key(tctx, NULL, -1, -1);
		break;
	default:
		break;
	}

	return CONFD_OK;
}

/*
 * Optional callback - implemented for performance reasons.
 */
static int frr_confd_data_get_object(struct confd_trans_ctx *tctx,
				     confd_hkeypath_t *kp)
{
	struct nb_node *nb_node;
	const struct lysc_node *child;
	char xpath[XPATH_MAXLEN];
	char xpath_child[XPATH_MAXLEN * 2];
	struct list *elements;
	struct yang_data *data;
	const void *list_entry;
	confd_value_t values[CONFD_MAX_CHILD_NODES];
	size_t nvalues = 0;

	frr_confd_get_xpath(kp, xpath, sizeof(xpath));

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		confd_data_reply_not_found(tctx);
		return CONFD_ERR;
	}

	if (frr_confd_hkeypath_get_list_entry(kp, nb_node, &list_entry) != 0) {
		confd_data_reply_not_found(tctx);
		return CONFD_OK;
	}

	elements = yang_data_list_new();

	/* Loop through list child nodes. */
	LY_LIST_FOR (lysc_node_child(nb_node->snode), child) {
		struct nb_node *nb_node_child = child->priv;
		confd_value_t *v;

		if (nvalues > CONFD_MAX_CHILD_NODES)
			break;

		v = &values[nvalues++];

		/* Non-presence containers, lists and leaf-lists. */
		if (!nb_node_child->cbs.get_elem) {
			CONFD_SET_NOEXISTS(v);
			continue;
		}

		snprintf(xpath_child, sizeof(xpath_child), "%s/%s", xpath,
			 child->name);
		data = nb_callback_get_elem(nb_node_child, xpath_child,
					    list_entry);
		if (data) {
			if (data->value)
				CONFD_SET_STR(v, data->value);
			else {
				/* Presence containers and empty leafs. */
				CONFD_SET_XMLTAG(
					v, nb_node_child->confd_hash,
					confd_str2hash(nb_node_child->snode
							       ->module->ns));
			}
			listnode_add(elements, data);
		} else
			CONFD_SET_NOEXISTS(v);
	}

	confd_data_reply_value_array(tctx, values, nvalues);

	/* Release memory. */
	list_delete(&elements);

	return CONFD_OK;
}

/*
 * Optional callback - implemented for performance reasons.
 */
static int frr_confd_data_get_next_object(struct confd_trans_ctx *tctx,
					  confd_hkeypath_t *kp, long next)
{
	char xpath[XPATH_MAXLEN];
	struct nb_node *nb_node;
	struct list *elements;
	const void *parent_list_entry;
	const void *nb_next;
#define CONFD_OBJECTS_PER_TIME 100
	struct confd_next_object objects[CONFD_OBJECTS_PER_TIME + 1];
	char pseudo_keys[CONFD_OBJECTS_PER_TIME][32];
	int nobjects = 0;

	frr_confd_get_xpath(kp, xpath, sizeof(xpath));

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		confd_data_reply_next_object_array(tctx, NULL, 0, 0);
		return CONFD_OK;
	}

	if (frr_confd_hkeypath_get_list_entry(kp, nb_node, &parent_list_entry)
	    != 0) {
		confd_data_reply_next_object_array(tctx, NULL, 0, 0);
		return CONFD_OK;
	}

	elements = yang_data_list_new();
	nb_next = (next == -1) ? NULL : (void *)next;

	memset(objects, 0, sizeof(objects));
	for (int j = 0; j < CONFD_OBJECTS_PER_TIME; j++) {
		struct confd_next_object *object;
		const struct lysc_node *child;
		struct yang_data *data;
		size_t nvalues = 0;

		object = &objects[j];

		nb_next = nb_callback_get_next(nb_node, parent_list_entry,
					       nb_next);
		if (!nb_next)
			/* End of the list. */
			break;

		object->next = (long)nb_next;

		/* Leaf-lists require special handling. */
		if (nb_node->snode->nodetype == LYS_LEAFLIST) {
			object->v = XMALLOC(MTYPE_CONFD, sizeof(confd_value_t));
			data = nb_callback_get_elem(nb_node, xpath, nb_next);
			assert(data && data->value);
			CONFD_SET_STR(object->v, data->value);
			nvalues++;
			listnode_add(elements, data);
			goto next;
		}

		object->v =
			XMALLOC(MTYPE_CONFD,
				CONFD_MAX_CHILD_NODES * sizeof(confd_value_t));

		/*
		 * ConfD 6.6 user guide, chapter 6.11 (Operational data lists
		 * without keys):
		 * "In the response to the get_next_object() callback, the data
		 * provider is expected to provide the key values along with the
		 * other leafs in an array that is populated according to the
		 * data model. This must be done also for this type of list,
		 * even though the key isn't actually in the data model. The
		 * "pseudo" key must always be the first element in the array".
		 */
		if (CHECK_FLAG(nb_node->flags, F_NB_NODE_KEYLESS_LIST)) {
			confd_value_t *v;

			snprintf(pseudo_keys[j], sizeof(pseudo_keys[j]), "%lu",
				 (unsigned long)nb_next);

			v = &object->v[nvalues++];
			CONFD_SET_STR(v, pseudo_keys[j]);
		}

		/* Loop through list child nodes. */
		LY_LIST_FOR (lysc_node_child(nb_node->snode), child) {
			struct nb_node *nb_node_child = child->priv;
			char xpath_child[XPATH_MAXLEN * 2];
			confd_value_t *v;

			if (nvalues > CONFD_MAX_CHILD_NODES)
				break;

			v = &object->v[nvalues++];

			/* Non-presence containers, lists and leaf-lists. */
			if (!nb_node_child->cbs.get_elem) {
				CONFD_SET_NOEXISTS(v);
				continue;
			}

			snprintf(xpath_child, sizeof(xpath_child), "%s/%s",
				 xpath, child->name);
			data = nb_callback_get_elem(nb_node_child, xpath_child,
						    nb_next);
			if (data) {
				if (data->value)
					CONFD_SET_STR(v, data->value);
				else {
					/*
					 * Presence containers and empty leafs.
					 */
					CONFD_SET_XMLTAG(
						v, nb_node_child->confd_hash,
						confd_str2hash(
							nb_node_child->snode
								->module->ns));
				}
				listnode_add(elements, data);
			} else
				CONFD_SET_NOEXISTS(v);
		}
	next:
		object->n = nvalues;
		nobjects++;
	}

	if (nobjects == 0) {
		confd_data_reply_next_object_array(tctx, NULL, 0, 0);
		list_delete(&elements);
		return CONFD_OK;
	}

	/* Detect end of the list. */
	if (!nb_next) {
		nobjects++;
		objects[nobjects].v = NULL;
	}

	/* Reply to ConfD. */
	confd_data_reply_next_object_arrays(tctx, objects, nobjects, 0);
	if (!nb_next)
		nobjects--;

	/* Release memory. */
	list_delete(&elements);
	for (int j = 0; j < nobjects; j++) {
		struct confd_next_object *object;

		object = &objects[j];
		XFREE(MTYPE_CONFD, object->v);
	}

	return CONFD_OK;
}

static int frr_confd_notification_send(const char *xpath,
				       struct list *arguments)
{
	struct nb_node *nb_node;
	struct yang_module *module;
	struct confd_datetime now;
	confd_tag_value_t *values;
	int nvalues;
	int i = 0;
	struct yang_data *data;
	struct listnode *node;
	int ret;

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		return -1;
	}
	module = yang_module_find(nb_node->snode->module->name);
	assert(module);

	nvalues = 2;
	if (arguments)
		nvalues += listcount(arguments);

	values = XMALLOC(MTYPE_CONFD, nvalues * sizeof(*values));

	CONFD_SET_TAG_XMLBEGIN(&values[i++], nb_node->confd_hash,
			       module->confd_hash);
	for (ALL_LIST_ELEMENTS_RO(arguments, node, data)) {
		struct nb_node *nb_node_arg;

		nb_node_arg = nb_node_find(data->xpath);
		if (!nb_node_arg) {
			flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
				  "%s: unknown data path: %s", __func__,
				  data->xpath);
			XFREE(MTYPE_CONFD, values);
			return NB_ERR;
		}

		CONFD_SET_TAG_STR(&values[i++], nb_node_arg->confd_hash,
				  data->value);
	}
	CONFD_SET_TAG_XMLEND(&values[i++], nb_node->confd_hash,
			     module->confd_hash);

	getdatetime(&now);
	ret = confd_notification_send(live_ctx, &now, values, nvalues);

	/* Release memory. */
	XFREE(MTYPE_CONFD, values);

	/* Map ConfD return code to northbound return code. */
	switch (ret) {
	case CONFD_OK:
		return NB_OK;
	default:
		return NB_ERR;
	}
}

static int frr_confd_action_init(struct confd_user_info *uinfo)
{
	confd_action_set_fd(uinfo, dp_worker_sock);

	return CONFD_OK;
}

static int frr_confd_action_execute(struct confd_user_info *uinfo,
				    struct xml_tag *name, confd_hkeypath_t *kp,
				    confd_tag_value_t *params, int nparams)
{
	char xpath[XPATH_MAXLEN];
	struct nb_node *nb_node;
	struct list *input;
	struct list *output;
	struct yang_data *data;
	confd_tag_value_t *reply;
	int ret = CONFD_OK;
	char errmsg[BUFSIZ] = {0};

	/* Getting the XPath is tricky. */
	if (kp) {
		/* This is a YANG RPC. */
		frr_confd_get_xpath(kp, xpath, sizeof(xpath));
		strlcat(xpath, "/", sizeof(xpath));
		strlcat(xpath, confd_hash2str(name->tag), sizeof(xpath));
	} else {
		/* This is a YANG action. */
		snprintf(xpath, sizeof(xpath), "/%s:%s",
			 confd_ns2prefix(name->ns), confd_hash2str(name->tag));
	}

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		return CONFD_ERR;
	}

	input = yang_data_list_new();
	output = yang_data_list_new();

	/* Process input nodes. */
	for (int i = 0; i < nparams; i++) {
		char xpath_input[XPATH_MAXLEN * 2];
		char value_str[YANG_VALUE_MAXLEN];

		snprintf(xpath_input, sizeof(xpath_input), "%s/%s", xpath,
			 confd_hash2str(params[i].tag.tag));

		if (frr_confd_val2str(xpath_input, &params[i].v, value_str,
				      sizeof(value_str))
		    != 0) {
			flog_err(
				EC_LIB_CONFD_DATA_CONVERT,
				"%s: failed to convert ConfD value to a string",
				__func__);
			ret = CONFD_ERR;
			goto exit;
		}

		data = yang_data_new(xpath_input, value_str);
		listnode_add(input, data);
	}

	/* Execute callback registered for this XPath. */
	if (nb_callback_rpc(nb_node, xpath, input, output, errmsg,
			    sizeof(errmsg))
	    != NB_OK) {
		flog_warn(EC_LIB_NB_CB_RPC, "%s: rpc callback failed: %s",
			  __func__, xpath);
		ret = CONFD_ERR;
		goto exit;
	}

	/* Process output nodes. */
	if (listcount(output) > 0) {
		struct listnode *node;
		int i = 0;

		reply = XMALLOC(MTYPE_CONFD,
				listcount(output) * sizeof(*reply));

		for (ALL_LIST_ELEMENTS_RO(output, node, data)) {
			struct nb_node *nb_node_output;
			int hash;

			nb_node_output = nb_node_find(data->xpath);
			if (!nb_node_output) {
				flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
					  "%s: unknown data path: %s", __func__,
					  data->xpath);
				goto exit;
			}

			hash = confd_str2hash(nb_node_output->snode->name);
			CONFD_SET_TAG_STR(&reply[i++], hash, data->value);
		}
		confd_action_reply_values(uinfo, reply, listcount(output));
		XFREE(MTYPE_CONFD, reply);
	}

exit:
	/* Release memory. */
	list_delete(&input);
	list_delete(&output);

	return ret;
}


static int frr_confd_dp_read(struct confd_daemon_ctx *dctx, int fd)
{
	int ret;

	ret = confd_fd_ready(dctx, fd);
	if (ret == CONFD_EOF) {
		flog_err_confd("confd_fd_ready");
		frr_confd_finish();
		return -1;
	} else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
		flog_err_confd("confd_fd_ready");
		frr_confd_finish();
		return -1;
	}

	return 0;
}

static void frr_confd_dp_ctl_read(struct event *thread)
{
	struct confd_daemon_ctx *dctx = EVENT_ARG(thread);
	int fd = EVENT_FD(thread);

	event_add_read(master, frr_confd_dp_ctl_read, dctx, fd, &t_dp_ctl);

	frr_confd_dp_read(dctx, fd);
}

static void frr_confd_dp_worker_read(struct event *thread)
{
	struct confd_daemon_ctx *dctx = EVENT_ARG(thread);
	int fd = EVENT_FD(thread);

	event_add_read(master, frr_confd_dp_worker_read, dctx, fd,
		       &t_dp_worker);

	frr_confd_dp_read(dctx, fd);
}

static int frr_confd_subscribe_state(const struct lysc_node *snode, void *arg)
{
	struct nb_node *nb_node = snode->priv;
	struct confd_data_cbs *data_cbs = arg;

	if (!nb_node || !CHECK_FLAG(snode->flags, LYS_CONFIG_R))
		return YANG_ITER_CONTINUE;
	/* We only need to subscribe to the root of the state subtrees. */
	if (snode->parent && CHECK_FLAG(snode->parent->flags, LYS_CONFIG_R))
		return YANG_ITER_CONTINUE;

	DEBUGD(&nb_dbg_client_confd,
	       "%s: providing data to '%s' (callpoint %s)", __func__,
	       nb_node->xpath, snode->name);

	strlcpy(data_cbs->callpoint, snode->name, sizeof(data_cbs->callpoint));
	if (confd_register_data_cb(dctx, data_cbs) != CONFD_OK)
		flog_err_confd("confd_register_data_cb");

	return YANG_ITER_CONTINUE;
}

static int frr_confd_init_dp(const char *program_name)
{
	struct confd_trans_cbs trans_cbs;
	struct confd_data_cbs data_cbs;
	struct confd_notification_stream_cbs ncbs;
	struct confd_action_cbs acbs;

	/* Initialize daemon context. */
	dctx = confd_init_daemon(program_name);
	if (!dctx) {
		flog_err_confd("confd_init_daemon");
		goto error;
	}

	/*
	 * Inform we want to receive YANG values as raw strings, and that we
	 * want to provide only strings in the reply functions, regardless of
	 * the YANG type.
	 */
	confd_set_daemon_flags(dctx, CONFD_DAEMON_FLAG_STRINGSONLY);

	/* Establish a control socket. */
	dp_ctl_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (dp_ctl_sock < 0) {
		flog_err(EC_LIB_SOCKET, "%s: failed to create socket: %s",
			 __func__, safe_strerror(errno));
		goto error;
	}

	if (confd_connect(dctx, dp_ctl_sock, CONTROL_SOCKET, &confd_addr,
			  sizeof(struct sockaddr_in))
	    != CONFD_OK) {
		flog_err_confd("confd_connect");
		goto error;
	}

	/*
	 * Establish a worker socket (only one since this plugin runs on a
	 * single thread).
	 */
	dp_worker_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (dp_worker_sock < 0) {
		flog_err(EC_LIB_SOCKET, "%s: failed to create socket: %s",
			 __func__, safe_strerror(errno));
		goto error;
	}
	if (confd_connect(dctx, dp_worker_sock, WORKER_SOCKET, &confd_addr,
			  sizeof(struct sockaddr_in))
	    != CONFD_OK) {
		flog_err_confd("confd_connect");
		goto error;
	}

	/* Register transaction callback functions. */
	memset(&trans_cbs, 0, sizeof(trans_cbs));
	trans_cbs.init = frr_confd_transaction_init;
	confd_register_trans_cb(dctx, &trans_cbs);

	/* Register our read/write callbacks. */
	memset(&data_cbs, 0, sizeof(data_cbs));
	data_cbs.get_elem = frr_confd_data_get_elem;
	data_cbs.exists_optional = frr_confd_data_get_elem;
	data_cbs.get_next = frr_confd_data_get_next;
	data_cbs.get_object = frr_confd_data_get_object;
	data_cbs.get_next_object = frr_confd_data_get_next_object;

	/*
	 * Iterate over all loaded YANG modules and subscribe to the paths
	 * referent to state data.
	 */
	yang_snodes_iterate(NULL, frr_confd_subscribe_state, 0, &data_cbs);

	/* Register notification stream. */
	memset(&ncbs, 0, sizeof(ncbs));
	ncbs.fd = dp_worker_sock;
	/*
	 * RFC 5277 - Section 3.2.3:
	 * A NETCONF server implementation supporting the notification
	 * capability MUST support the "NETCONF" notification event
	 * stream. This stream contains all NETCONF XML event notifications
	 * supported by the NETCONF server.
	 */
	strlcpy(ncbs.streamname, "NETCONF", sizeof(ncbs.streamname));
	if (confd_register_notification_stream(dctx, &ncbs, &live_ctx)
	    != CONFD_OK) {
		flog_err_confd("confd_register_notification_stream");
		goto error;
	}

	/* Register the action handler callback. */
	memset(&acbs, 0, sizeof(acbs));
	strlcpy(acbs.actionpoint, "actionpoint", sizeof(acbs.actionpoint));
	acbs.init = frr_confd_action_init;
	acbs.action = frr_confd_action_execute;
	if (confd_register_action_cbs(dctx, &acbs) != CONFD_OK) {
		flog_err_confd("confd_register_action_cbs");
		goto error;
	}

	/* Notify we registered all callbacks we wanted. */
	if (confd_register_done(dctx) != CONFD_OK) {
		flog_err_confd("confd_register_done");
		goto error;
	}

	event_add_read(master, frr_confd_dp_ctl_read, dctx, dp_ctl_sock,
		       &t_dp_ctl);
	event_add_read(master, frr_confd_dp_worker_read, dctx, dp_worker_sock,
		       &t_dp_worker);

	return 0;

error:
	frr_confd_finish_dp();

	return -1;
}

static void frr_confd_finish_dp(void)
{
	if (dp_worker_sock > 0) {
		EVENT_OFF(t_dp_worker);
		close(dp_worker_sock);
	}
	if (dp_ctl_sock > 0) {
		EVENT_OFF(t_dp_ctl);
		close(dp_ctl_sock);
	}
	if (dctx != NULL)
		confd_release_daemon(dctx);
}

/* ------------ CLI ------------ */

DEFUN (debug_nb_confd,
       debug_nb_confd_cmd,
       "[no] debug northbound client confd",
       NO_STR
       DEBUG_STR
       "Northbound debugging\n"
       "Client\n"
       "ConfD\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, "no");

	DEBUG_MODE_SET(&nb_dbg_client_confd, mode, !no);

	return CMD_SUCCESS;
}

static int frr_confd_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&nb_dbg_client_confd, DEBUG_MODE_CONF))
		vty_out(vty, "debug northbound client confd\n");

	return 0;
}

static int frr_confd_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&nb_dbg_client_confd, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&nb_dbg_client_confd, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&nb_dbg_client_confd);

	return 0;
}

static void frr_confd_cli_init(void)
{
	hook_register(nb_client_debug_config_write,
		      frr_confd_debug_config_write);
	hook_register(nb_client_debug_set_all, frr_confd_debug_set_all);

	install_element(ENABLE_NODE, &debug_nb_confd_cmd);
	install_element(CONFIG_NODE, &debug_nb_confd_cmd);
}

/* ------------ Main ------------ */

static int frr_confd_calculate_snode_hash(const struct lysc_node *snode,
					  void *arg)
{
	struct nb_node *nb_node = snode->priv;

	if (nb_node)
		nb_node->confd_hash = confd_str2hash(snode->name);

	return YANG_ITER_CONTINUE;
}

static int frr_confd_init(const char *program_name)
{
	struct sockaddr_in *confd_addr4 = (struct sockaddr_in *)&confd_addr;
	int debuglevel = CONFD_SILENT;
	int ret = -1;

	/* Initialize ConfD library. */
	confd_init(program_name, stderr, debuglevel);

	confd_addr4->sin_family = AF_INET;
	confd_addr4->sin_addr.s_addr = inet_addr("127.0.0.1");
	confd_addr4->sin_port = htons(CONFD_PORT);
	if (confd_load_schemas(&confd_addr, sizeof(struct sockaddr_in))
	    != CONFD_OK) {
		flog_err_confd("confd_load_schemas");
		return -1;
	}

	ret = frr_confd_init_cdb();
	if (ret != 0)
		goto error;

	ret = frr_confd_init_dp(program_name);
	if (ret != 0) {
		frr_confd_finish_cdb();
		goto error;
	}

	yang_snodes_iterate(NULL, frr_confd_calculate_snode_hash, 0, NULL);

	hook_register(nb_notification_send, frr_confd_notification_send);

	confd_connected = true;
	return 0;

error:
	confd_free_schemas();

	return ret;
}

static int frr_confd_finish(void)
{
	if (!confd_connected)
		return 0;

	frr_confd_finish_cdb();
	frr_confd_finish_dp();

	confd_free_schemas();

	confd_connected = false;

	return 0;
}

static int frr_confd_module_late_init(struct event_loop *tm)
{
	master = tm;

	if (frr_confd_init(frr_get_progname()) < 0) {
		flog_err(EC_LIB_CONFD_INIT,
			 "failed to initialize the ConfD module");
		return -1;
	}

	hook_register(frr_fini, frr_confd_finish);
	frr_confd_cli_init();

	return 0;
}

static int frr_confd_module_init(void)
{
	hook_register(frr_late_init, frr_confd_module_late_init);

	return 0;
}

FRR_MODULE_SETUP(.name = "frr_confd", .version = FRR_VERSION,
		 .description = "FRR ConfD integration module",
		 .init = frr_confd_module_init,
);
