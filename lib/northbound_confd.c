/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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
#include "lib_errors.h"
#include "command.h"
#include "libfrr.h"
#include "version.h"
#include "northbound.h"

#include <confd_lib.h>
#include <confd_cdb.h>
#include <confd_dp.h>
#include <confd_maapi.h>

DEFINE_MTYPE_STATIC(LIB, CONFD, "ConfD module")

static struct thread_master *master;
static struct sockaddr confd_addr;
static int cdb_sub_sock, dp_ctl_sock, dp_worker_sock;
static struct thread *t_cdb_sub, *t_dp_ctl, *t_dp_worker;
static struct confd_daemon_ctx *dctx;
static struct confd_notification_ctx *live_ctx;
static bool confd_connected;
static struct list *confd_spoints;

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

/* Obtain list keys from ConfD hashed keypath. */
static void frr_confd_hkeypath_get_keys(const confd_hkeypath_t *kp,
					struct yang_list_keys *keys)
{
	memset(keys, 0, sizeof(*keys));
	for (int i = 0; i < kp->len; i++) {
		if (kp->v[i][0].type != C_BUF)
			continue;

		for (int j = 0; kp->v[i][j].type != C_NOEXISTS; j++) {
			strlcpy(keys->key[keys->num],
				(char *)kp->v[i][j].val.buf.ptr,
				sizeof(keys->key[keys->num]));
			keys->num++;
		}
	}
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
		nb_op = NB_OP_DELETE;
		break;
	case MOP_VALUE_SET:
		if (nb_operation_is_valid(NB_OP_MODIFY, nb_node->snode))
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

static int frr_confd_cdb_read_cb(struct thread *thread)
{
	int fd = THREAD_FD(thread);
	int *subp = NULL;
	enum cdb_sub_notification cdb_ev;
	int flags;
	int reslen = 0;
	struct nb_config *candidate;
	struct cdb_iter_args iter_args;
	int ret;

	thread = NULL;
	thread_add_read(master, frr_confd_cdb_read_cb, NULL, fd, &thread);

	if (cdb_read_subscription_socket2(fd, &cdb_ev, &flags, &subp, &reslen)
	    != CONFD_OK) {
		flog_err_confd("cdb_read_subscription_socket2");
		return -1;
	}

	/*
	 * Ignore CDB_SUB_ABORT and CDB_SUB_COMMIT. We'll leverage the
	 * northbound layer itself to abort or apply the configuration changes
	 * when a transaction is created.
	 */
	if (cdb_ev != CDB_SUB_PREPARE) {
		free(subp);
		if (cdb_sync_subscription_socket(fd, CDB_DONE_PRIORITY)
		    != CONFD_OK) {
			flog_err_confd("cdb_sync_subscription_socket");
			return -1;
		}
		return 0;
	}

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
			return -1;
		}
		return 0;
	}

	ret = nb_candidate_commit(candidate, NB_CLIENT_CONFD, true, NULL, NULL);
	nb_config_free(candidate);
	if (ret != NB_OK && ret != NB_ERR_NO_CHANGES) {
		enum confd_errcode errcode;
		const char *errmsg;

		switch (ret) {
		case NB_ERR_LOCKED:
			errcode = CONFD_ERRCODE_IN_USE;
			errmsg = "Configuration is locked by another process";
			break;
		case NB_ERR_RESOURCE:
			errcode = CONFD_ERRCODE_RESOURCE_DENIED;
			errmsg = "Failed do allocate resources";
			break;
		default:
			errcode = CONFD_ERRCODE_INTERNAL;
			errmsg = "Internal error";
			break;
		}

		if (cdb_sub_abort_trans(cdb_sub_sock, errcode, 0, 0, "%s",
					errmsg)
		    != CONFD_OK) {
			flog_err_confd("cdb_sub_abort_trans");
			return -1;
		}
	} else {
		if (cdb_sync_subscription_socket(fd, CDB_DONE_PRIORITY)
		    != CONFD_OK) {
			flog_err_confd("cdb_sync_subscription_socket");
			return -1;
		}
	}

	return 0;
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
		struct lys_node *snode;

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
		LY_TREE_FOR (module->info->data, snode) {
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
				continue;
			}

			nb_node = snode->priv;
			if (debug_northbound)
				zlog_debug("%s: subscribing to '%s'", __func__,
					   nb_node->xpath);

			spoint = XMALLOC(MTYPE_CONFD, sizeof(*spoint));
			ret = cdb_subscribe2(
				cdb_sub_sock, CDB_SUB_RUNNING_TWOPHASE,
				CDB_SUB_WANT_ABORT_ON_ABORT, 3, spoint,
				module->confd_hash, nb_node->xpath);
			if (ret != CONFD_OK) {
				flog_err_confd("cdb_subscribe2");
				XFREE(MTYPE_CONFD, spoint);
			}
			listnode_add(confd_spoints, spoint);
		}
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

	thread_add_read(master, frr_confd_cdb_read_cb, NULL, cdb_sub_sock,
			&t_cdb_sub);

	return 0;

error:
	frr_confd_finish_cdb();

	return -1;
}

static void frr_confd_finish_cdb(void)
{
	if (cdb_sub_sock > 0) {
		THREAD_OFF(t_cdb_sub);
		cdb_close(cdb_sub_sock);
	}
}

/* ------------ DP code ------------ */

static int frr_confd_transaction_init(struct confd_trans_ctx *tctx)
{
	confd_trans_set_fd(tctx, dp_worker_sock);

	return CONFD_OK;
}

static int frr_confd_data_get_elem(struct confd_trans_ctx *tctx,
				   confd_hkeypath_t *kp)
{
	struct nb_node *nb_node, *parent_list;
	char xpath[BUFSIZ];
	struct yang_list_keys keys;
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

	parent_list = nb_node->parent_list;
	if (parent_list) {
		frr_confd_hkeypath_get_keys(kp, &keys);
		list_entry = parent_list->cbs.lookup_entry(&keys);
		if (!list_entry) {
			flog_warn(EC_LIB_NB_CB_STATE,
				  "%s: list entry not found: %s", __func__,
				  xpath);
			confd_data_reply_not_found(tctx);
			return CONFD_OK;
		}
	}

	data = nb_node->cbs.get_elem(xpath, list_entry);
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
	char xpath[BUFSIZ];
	struct yang_list_keys keys;
	const void *nb_next;
	confd_value_t v[LIST_MAXKEYS];

	frr_confd_get_xpath(kp, xpath, sizeof(xpath));

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		confd_data_reply_next_key(tctx, NULL, -1, -1);
		return CONFD_OK;
	}

	nb_next = nb_node->cbs.get_next(xpath,
					(next == -1) ? NULL : (void *)next);
	if (!nb_next) {
		/* End of the list. */
		confd_data_reply_next_key(tctx, NULL, -1, -1);
		return CONFD_OK;
	}
	if (nb_node->cbs.get_keys(nb_next, &keys) != NB_OK) {
		flog_warn(EC_LIB_NB_CB_STATE, "%s: failed to get list keys",
			  __func__);
		confd_data_reply_next_key(tctx, NULL, -1, -1);
		return CONFD_OK;
	}

	/* Feed keys to ConfD. */
	for (size_t i = 0; i < keys.num; i++)
		CONFD_SET_STR(&v[i], keys.key[i]);
	confd_data_reply_next_key(tctx, v, keys.num, (long)nb_next);

	return CONFD_OK;
}

/*
 * Optional callback - implemented for performance reasons.
 */
static int frr_confd_data_get_object(struct confd_trans_ctx *tctx,
				     confd_hkeypath_t *kp)
{
	struct nb_node *nb_node;
	char xpath[BUFSIZ];
	char xpath_children[XPATH_MAXLEN];
	char xpath_child[XPATH_MAXLEN];
	struct yang_list_keys keys;
	struct list *elements;
	struct yang_data *data;
	const void *list_entry;
	struct ly_set *set;
	confd_value_t *values;

	frr_confd_get_xpath(kp, xpath, sizeof(xpath));

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		confd_data_reply_not_found(tctx);
		return CONFD_OK;
	}

	frr_confd_hkeypath_get_keys(kp, &keys);
	list_entry = nb_node->cbs.lookup_entry(&keys);
	if (!list_entry) {
		flog_warn(EC_LIB_NB_CB_STATE, "%s: list entry not found: %s",
			  __func__, xpath);
		confd_data_reply_not_found(tctx);
		return CONFD_OK;
	}

	/* Find list child nodes. */
	snprintf(xpath_children, sizeof(xpath_children), "%s/*", xpath);
	set = lys_find_path(nb_node->snode->module, NULL, xpath_children);
	if (!set) {
		flog_warn(EC_LIB_LIBYANG, "%s: lys_find_path() failed",
			  __func__);
		return CONFD_ERR;
	}

	elements = yang_data_list_new();
	values = XMALLOC(MTYPE_CONFD, set->number * sizeof(*values));

	/* Loop through list child nodes. */
	for (size_t i = 0; i < set->number; i++) {
		struct lys_node *child;
		struct nb_node *nb_node_child;

		child = set->set.s[i];
		nb_node_child = child->priv;

		snprintf(xpath_child, sizeof(xpath_child), "%s/%s", xpath,
			 child->name);

		data = nb_node_child->cbs.get_elem(xpath_child, list_entry);
		if (data) {
			if (data->value)
				CONFD_SET_STR(&values[i], data->value);
			else
				CONFD_SET_NOEXISTS(&values[i]);
			listnode_add(elements, data);
		} else
			CONFD_SET_NOEXISTS(&values[i]);
	}

	confd_data_reply_value_array(tctx, values, set->number);

	/* Release memory. */
	ly_set_free(set);
	XFREE(MTYPE_CONFD, values);
	list_delete(&elements);

	return CONFD_OK;
}

/*
 * Optional callback - implemented for performance reasons.
 */
static int frr_confd_data_get_next_object(struct confd_trans_ctx *tctx,
					  confd_hkeypath_t *kp, long next)
{
	char xpath[BUFSIZ];
	char xpath_children[XPATH_MAXLEN];
	struct nb_node *nb_node;
	struct ly_set *set;
	struct list *elements;
	const void *nb_next;
#define CONFD_OBJECTS_PER_TIME 100
	struct confd_next_object objects[CONFD_OBJECTS_PER_TIME + 1];
	int nobjects = 0;

	frr_confd_get_xpath(kp, xpath, sizeof(xpath));

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		confd_data_reply_next_object_array(tctx, NULL, 0, 0);
		return CONFD_OK;
	}

	/* Find list child nodes. */
	snprintf(xpath_children, sizeof(xpath_children), "%s/*", xpath);
	set = lys_find_path(nb_node->snode->module, NULL, xpath_children);
	if (!set) {
		flog_warn(EC_LIB_LIBYANG, "%s: lys_find_path() failed",
			  __func__);
		return CONFD_ERR;
	}

	elements = yang_data_list_new();
	nb_next = (next == -1) ? NULL : (void *)next;

	memset(objects, 0, sizeof(objects));
	for (int j = 0; j < CONFD_OBJECTS_PER_TIME; j++) {
		struct confd_next_object *object;
		struct yang_list_keys keys;
		struct yang_data *data;
		const void *list_entry;

		object = &objects[j];

		nb_next = nb_node->cbs.get_next(xpath, nb_next);
		if (!nb_next)
			/* End of the list. */
			break;

		if (nb_node->cbs.get_keys(nb_next, &keys) != NB_OK) {
			flog_warn(EC_LIB_NB_CB_STATE,
				  "%s: failed to get list keys", __func__);
			continue;
		}
		object->next = (long)nb_next;

		list_entry = nb_node->cbs.lookup_entry(&keys);
		if (!list_entry) {
			flog_warn(EC_LIB_NB_CB_STATE,
				  "%s: failed to lookup list entry", __func__);
			continue;
		}

		object->v = XMALLOC(MTYPE_CONFD,
				    set->number * sizeof(confd_value_t));

		/* Loop through list child nodes. */
		for (unsigned int i = 0; i < set->number; i++) {
			struct lys_node *child;
			struct nb_node *nb_node_child;
			char xpath_child[XPATH_MAXLEN];
			confd_value_t *v = &object->v[i];

			child = set->set.s[i];
			nb_node_child = child->priv;

			snprintf(xpath_child, sizeof(xpath_child), "%s/%s",
				 xpath, child->name);

			data = nb_node_child->cbs.get_elem(xpath_child,
							   list_entry);
			if (data) {
				if (data->value)
					CONFD_SET_STR(v, data->value);
				else
					CONFD_SET_NOEXISTS(v);
				listnode_add(elements, data);
			} else
				CONFD_SET_NOEXISTS(v);
		}
		object->n = set->number;
		nobjects++;
	}
	ly_set_free(set);

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
	char xpath[BUFSIZ];
	struct nb_node *nb_node;
	struct list *input;
	struct list *output;
	struct yang_data *data;
	confd_tag_value_t *reply;
	int ret = CONFD_OK;

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
		char xpath_input[BUFSIZ];
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
	if (nb_node->cbs.rpc(xpath, input, output) != NB_OK) {
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


static int frr_confd_dp_read(struct thread *thread)
{
	struct confd_daemon_ctx *dctx = THREAD_ARG(thread);
	int fd = THREAD_FD(thread);
	int ret;

	thread = NULL;
	thread_add_read(master, frr_confd_dp_read, dctx, fd, &thread);

	ret = confd_fd_ready(dctx, fd);
	if (ret == CONFD_EOF) {
		flog_err_confd("confd_fd_ready");
		return -1;
	} else if (ret == CONFD_ERR && confd_errno != CONFD_ERR_EXTERNAL) {
		flog_err_confd("confd_fd_ready");
		return -1;
	}

	return 0;
}

static int frr_confd_subscribe_state(const struct lys_node *snode, void *arg)
{
	struct nb_node *nb_node = snode->priv;
	struct confd_data_cbs *data_cbs = arg;

	if (!CHECK_FLAG(snode->flags, LYS_CONFIG_R))
		return YANG_ITER_CONTINUE;
	/* We only need to subscribe to the root of the state subtrees. */
	if (snode->parent && CHECK_FLAG(snode->parent->flags, LYS_CONFIG_R))
		return YANG_ITER_CONTINUE;

	if (debug_northbound)
		zlog_debug("%s: providing data to '%s' (callpoint %s)",
			   __func__, nb_node->xpath, snode->name);

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
	yang_snodes_iterate_all(frr_confd_subscribe_state, 0, &data_cbs);

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

	thread_add_read(master, frr_confd_dp_read, dctx, dp_ctl_sock,
			&t_dp_ctl);
	thread_add_read(master, frr_confd_dp_read, dctx, dp_worker_sock,
			&t_dp_worker);

	return 0;

error:
	frr_confd_finish_dp();

	return -1;
}

static void frr_confd_finish_dp(void)
{
	if (dp_worker_sock > 0) {
		THREAD_OFF(t_dp_worker);
		close(dp_worker_sock);
	}
	if (dp_ctl_sock > 0) {
		THREAD_OFF(t_dp_ctl);
		close(dp_ctl_sock);
	}
	if (dctx != NULL)
		confd_release_daemon(dctx);
}

/* ------------ Main ------------ */

static int frr_confd_calculate_snode_hash(const struct lys_node *snode,
					  void *arg)
{
	struct nb_node *nb_node = snode->priv;

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

	yang_snodes_iterate_all(frr_confd_calculate_snode_hash, 0, NULL);

	hook_register(nb_notification_send, frr_confd_notification_send);

	confd_connected = true;
	return 0;

error:
	confd_free_schemas();

	return ret;
}

static int frr_confd_finish(void)
{
	if (confd_connected == false)
		return 0;

	frr_confd_finish_cdb();
	frr_confd_finish_dp();

	confd_free_schemas();

	confd_connected = false;

	return 0;
}

static int frr_confd_module_late_init(struct thread_master *tm)
{
	master = tm;

	if (frr_confd_init(frr_get_progname()) < 0) {
		flog_err(EC_LIB_CONFD_INIT,
			 "failed to initialize the ConfD module");
		return -1;
	}

	hook_register(frr_fini, frr_confd_finish);

	return 0;
}

static int frr_confd_module_init(void)
{
	hook_register(frr_late_init, frr_confd_module_late_init);

	return 0;
}

FRR_MODULE_SETUP(.name = "frr_confd", .version = FRR_VERSION,
		 .description = "FRR ConfD integration module",
		 .init = frr_confd_module_init, )
