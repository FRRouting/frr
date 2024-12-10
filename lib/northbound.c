// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

<<<<<<< HEAD
=======
#include "darr.h"
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
#include "libfrr.h"
#include "log.h"
#include "lib_errors.h"
#include "hash.h"
#include "command.h"
#include "debug.h"
#include "db.h"
#include "frr_pthread.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "northbound_db.h"
#include "frrstr.h"

DEFINE_MTYPE_STATIC(LIB, NB_NODE, "Northbound Node");
DEFINE_MTYPE_STATIC(LIB, NB_CONFIG, "Northbound Configuration");
DEFINE_MTYPE_STATIC(LIB, NB_CONFIG_ENTRY, "Northbound Configuration Entry");

/* Running configuration - shouldn't be modified directly. */
struct nb_config *running_config;

/* Hash table of user pointers associated with configuration entries. */
static struct hash *running_config_entries;

/* Management lock for the running configuration. */
static struct {
	/* Mutex protecting this structure. */
	pthread_mutex_t mtx;

	/* Actual lock. */
	bool locked;

	/* Northbound client who owns this lock. */
	enum nb_client owner_client;

	/* Northbound user who owns this lock. */
	const void *owner_user;
} running_config_mgmt_lock;

/* Knob to record config transaction */
static bool nb_db_enabled;
/*
 * Global lock used to prevent multiple configuration transactions from
 * happening concurrently.
 */
static bool transaction_in_progress;

static int nb_callback_pre_validate(struct nb_context *context,
				    const struct nb_node *nb_node,
				    const struct lyd_node *dnode, char *errmsg,
				    size_t errmsg_len);
static int nb_callback_configuration(struct nb_context *context,
				     const enum nb_event event,
				     struct nb_config_change *change,
				     char *errmsg, size_t errmsg_len);
static struct nb_transaction *
nb_transaction_new(struct nb_context context, struct nb_config *config,
		   struct nb_config_cbs *changes, const char *comment,
		   char *errmsg, size_t errmsg_len);
static void nb_transaction_free(struct nb_transaction *transaction);
static int nb_transaction_process(enum nb_event event,
				  struct nb_transaction *transaction,
				  char *errmsg, size_t errmsg_len);
static void nb_transaction_apply_finish(struct nb_transaction *transaction,
					char *errmsg, size_t errmsg_len);
<<<<<<< HEAD
static int nb_oper_data_iter_node(const struct lysc_node *snode,
				  const char *xpath, const void *list_entry,
				  const struct yang_list_keys *list_keys,
				  struct yang_translator *translator,
				  bool first, uint32_t flags,
				  nb_oper_data_cb cb, void *arg);
=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

static int nb_node_check_config_only(const struct lysc_node *snode, void *arg)
{
	bool *config_only = arg;

	if (CHECK_FLAG(snode->flags, LYS_CONFIG_R)) {
		*config_only = false;
		return YANG_ITER_STOP;
	}

	return YANG_ITER_CONTINUE;
}

static int nb_node_new_cb(const struct lysc_node *snode, void *arg)
{
	struct nb_node *nb_node;
	struct lysc_node *sparent, *sparent_list;
	struct frr_yang_module_info *module;

	module = (struct frr_yang_module_info *)arg;
	nb_node = XCALLOC(MTYPE_NB_NODE, sizeof(*nb_node));
	yang_snode_get_path(snode, YANG_PATH_DATA, nb_node->xpath,
			    sizeof(nb_node->xpath));
	nb_node->priority = NB_DFLT_PRIORITY;
	sparent = yang_snode_real_parent(snode);
	if (sparent)
		nb_node->parent = sparent->priv;
	sparent_list = yang_snode_parent_list(snode);
	if (sparent_list)
		nb_node->parent_list = sparent_list->priv;

	/* Set flags. */
	if (CHECK_FLAG(snode->nodetype, LYS_CONTAINER | LYS_LIST)) {
		bool config_only = true;

		(void)yang_snodes_iterate_subtree(snode, NULL,
						  nb_node_check_config_only, 0,
						  &config_only);
		if (config_only)
			SET_FLAG(nb_node->flags, F_NB_NODE_CONFIG_ONLY);
	}
	if (CHECK_FLAG(snode->nodetype, LYS_LIST)) {
		if (yang_snode_num_keys(snode) == 0)
			SET_FLAG(nb_node->flags, F_NB_NODE_KEYLESS_LIST);
	}

	/*
	 * Link the northbound node and the libyang schema node with one
	 * another.
	 */
	nb_node->snode = snode;
	assert(snode->priv == NULL);
	((struct lysc_node *)snode)->priv = nb_node;

<<<<<<< HEAD
	if (module && module->ignore_cbs)
		SET_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS);
=======
	if (module && module->ignore_cfg_cbs)
		SET_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	return YANG_ITER_CONTINUE;
}

static int nb_node_del_cb(const struct lysc_node *snode, void *arg)
{
	struct nb_node *nb_node;

	nb_node = snode->priv;
	if (nb_node) {
		((struct lysc_node *)snode)->priv = NULL;
		XFREE(MTYPE_NB_NODE, nb_node);
	}

	return YANG_ITER_CONTINUE;
}

void nb_nodes_create(void)
{
	yang_snodes_iterate(NULL, nb_node_new_cb, 0, NULL);
}

void nb_nodes_delete(void)
{
	yang_snodes_iterate(NULL, nb_node_del_cb, 0, NULL);
}

struct nb_node *nb_node_find(const char *path)
{
	const struct lysc_node *snode;
<<<<<<< HEAD

	/*
	 * Use libyang to find the schema node associated to the path and get
	 * the northbound node from there (snode private pointer).
	 */
	snode = yang_find_snode(ly_native_ctx, path, 0);
=======
	uint32_t llopts = 0;

	/*
	 * Use libyang to find the schema node associated to the path and get
	 * the northbound node from there (snode private pointer). We need to
	 * disable logging temporarily to avoid libyang from logging an error
	 * message when the node is not found.
	 */
	ly_temp_log_options(&llopts);

	snode = yang_find_snode(ly_native_ctx, path, 0);

	ly_temp_log_options(NULL);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	if (!snode)
		return NULL;

	return snode->priv;
}

<<<<<<< HEAD
=======
struct nb_node **nb_nodes_find(const char *xpath)
{
	const struct lysc_node **snodes = NULL;
	struct nb_node **nb_nodes = NULL;
	bool simple;
	LY_ERR err;
	uint i;

	err = yang_resolve_snode_xpath(ly_native_ctx, xpath, &snodes, &simple);
	if (err)
		return NULL;

	darr_ensure_i(nb_nodes, darr_lasti(snodes));
	darr_foreach_i (snodes, i)
		nb_nodes[i] = snodes[i]->priv;
	darr_free(snodes);
	return nb_nodes;
}


>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
void nb_node_set_dependency_cbs(const char *dependency_xpath,
				const char *dependant_xpath,
				struct nb_dependency_callbacks *cbs)
{
	struct nb_node *dependency = nb_node_find(dependency_xpath);
	struct nb_node *dependant = nb_node_find(dependant_xpath);

	if (!dependency || !dependant)
		return;

	dependency->dep_cbs.get_dependant_xpath = cbs->get_dependant_xpath;
	dependant->dep_cbs.get_dependency_xpath = cbs->get_dependency_xpath;
}

bool nb_node_has_dependency(struct nb_node *node)
{
	return node->dep_cbs.get_dependency_xpath != NULL;
}

static int nb_node_validate_cb(const struct nb_node *nb_node,
<<<<<<< HEAD
			       enum nb_operation operation,
=======
			       enum nb_cb_operation operation,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			       int callback_implemented, bool optional)
{
	bool valid;

<<<<<<< HEAD
	valid = nb_operation_is_valid(operation, nb_node->snode);
=======
	valid = nb_cb_operation_is_valid(operation, nb_node->snode);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	/*
	 * Add an exception for operational data callbacks. A rw list usually
	 * doesn't need any associated operational data callbacks. But if this
	 * rw list is augmented by another module which adds state nodes under
	 * it, then this list will need to have the 'get_next()', 'get_keys()'
	 * and 'lookup_entry()' callbacks. As such, never log a warning when
	 * these callbacks are implemented when they are not needed, since this
	 * depends on context (e.g. some daemons might augment "frr-interface"
	 * while others don't).
	 */
<<<<<<< HEAD
	if (!valid && callback_implemented && operation != NB_OP_GET_NEXT
	    && operation != NB_OP_GET_KEYS && operation != NB_OP_LOOKUP_ENTRY)
		flog_warn(EC_LIB_NB_CB_UNNEEDED,
			  "unneeded '%s' callback for '%s'",
			  nb_operation_name(operation), nb_node->xpath);

	if (!optional && valid && !callback_implemented) {
		flog_err(EC_LIB_NB_CB_MISSING, "missing '%s' callback for '%s'",
			 nb_operation_name(operation), nb_node->xpath);
=======
	if (!valid && callback_implemented && operation != NB_CB_GET_NEXT
	    && operation != NB_CB_GET_KEYS && operation != NB_CB_LOOKUP_ENTRY)
		flog_warn(EC_LIB_NB_CB_UNNEEDED,
			  "unneeded '%s' callback for '%s'",
			  nb_cb_operation_name(operation), nb_node->xpath);

	if (!optional && valid && !callback_implemented) {
		flog_err(EC_LIB_NB_CB_MISSING, "missing '%s' callback for '%s'",
			 nb_cb_operation_name(operation), nb_node->xpath);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return 1;
	}

	return 0;
}

/*
 * Check if the required callbacks were implemented for the given northbound
 * node.
 */
static unsigned int nb_node_validate_cbs(const struct nb_node *nb_node)

{
	unsigned int error = 0;

<<<<<<< HEAD
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
		return error;

	error += nb_node_validate_cb(nb_node, NB_OP_CREATE,
				     !!nb_node->cbs.create, false);
	error += nb_node_validate_cb(nb_node, NB_OP_MODIFY,
				     !!nb_node->cbs.modify, false);
	error += nb_node_validate_cb(nb_node, NB_OP_DESTROY,
				     !!nb_node->cbs.destroy, false);
	error += nb_node_validate_cb(nb_node, NB_OP_MOVE, !!nb_node->cbs.move,
				     false);
	error += nb_node_validate_cb(nb_node, NB_OP_PRE_VALIDATE,
				     !!nb_node->cbs.pre_validate, true);
	error += nb_node_validate_cb(nb_node, NB_OP_APPLY_FINISH,
				     !!nb_node->cbs.apply_finish, true);
	error += nb_node_validate_cb(nb_node, NB_OP_GET_ELEM,
				     !!nb_node->cbs.get_elem, false);
	error += nb_node_validate_cb(nb_node, NB_OP_GET_NEXT,
				     !!nb_node->cbs.get_next, false);
	error += nb_node_validate_cb(nb_node, NB_OP_GET_KEYS,
				     !!nb_node->cbs.get_keys, false);
	error += nb_node_validate_cb(nb_node, NB_OP_LOOKUP_ENTRY,
				     !!nb_node->cbs.lookup_entry, false);
	error += nb_node_validate_cb(nb_node, NB_OP_RPC, !!nb_node->cbs.rpc,
				     false);
=======
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
		return error;

	error += nb_node_validate_cb(nb_node, NB_CB_CREATE,
				     !!nb_node->cbs.create, false);
	error += nb_node_validate_cb(nb_node, NB_CB_MODIFY,
				     !!nb_node->cbs.modify, false);
	error += nb_node_validate_cb(nb_node, NB_CB_DESTROY,
				     !!nb_node->cbs.destroy, false);
	error += nb_node_validate_cb(nb_node, NB_CB_MOVE, !!nb_node->cbs.move,
				     false);
	error += nb_node_validate_cb(nb_node, NB_CB_PRE_VALIDATE,
				     !!nb_node->cbs.pre_validate, true);
	error += nb_node_validate_cb(nb_node, NB_CB_APPLY_FINISH,
				     !!nb_node->cbs.apply_finish, true);
	error += nb_node_validate_cb(nb_node, NB_CB_GET_ELEM,
				     !!nb_node->cbs.get_elem, false);
	error += nb_node_validate_cb(nb_node, NB_CB_GET_NEXT,
				     !!nb_node->cbs.get_next, false);
	error += nb_node_validate_cb(nb_node, NB_CB_GET_KEYS,
				     !!nb_node->cbs.get_keys, false);
	error += nb_node_validate_cb(nb_node, NB_CB_LOOKUP_ENTRY,
				     !!nb_node->cbs.lookup_entry, false);
	error += nb_node_validate_cb(nb_node, NB_CB_RPC, !!nb_node->cbs.rpc,
				     false);
	error += nb_node_validate_cb(nb_node, NB_CB_NOTIFY,
				     !!nb_node->cbs.notify, true);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	return error;
}

static unsigned int nb_node_validate_priority(const struct nb_node *nb_node)
{
	/* Top-level nodes can have any priority. */
	if (!nb_node->parent)
		return 0;

	if (nb_node->priority < nb_node->parent->priority) {
		flog_err(EC_LIB_NB_CB_INVALID_PRIO,
			 "node has higher priority than its parent [xpath %s]",
			 nb_node->xpath);
		return 1;
	}

	return 0;
}

static int nb_node_validate(const struct lysc_node *snode, void *arg)
{
	struct nb_node *nb_node = snode->priv;
	unsigned int *errors = arg;

	/* Validate callbacks and priority. */
	if (nb_node) {
		*errors += nb_node_validate_cbs(nb_node);
		*errors += nb_node_validate_priority(nb_node);
	}

	return YANG_ITER_CONTINUE;
}

struct nb_config *nb_config_new(struct lyd_node *dnode)
{
	struct nb_config *config;

	config = XCALLOC(MTYPE_NB_CONFIG, sizeof(*config));
	if (dnode)
		config->dnode = dnode;
	else
		config->dnode = yang_dnode_new(ly_native_ctx, true);
	config->version = 0;

<<<<<<< HEAD
	RB_INIT(nb_config_cbs, &config->cfg_chgs);

=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	return config;
}

void nb_config_free(struct nb_config *config)
{
	if (config->dnode)
		yang_dnode_free(config->dnode);
<<<<<<< HEAD
	nb_config_diff_del_changes(&config->cfg_chgs);
=======

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	XFREE(MTYPE_NB_CONFIG, config);
}

struct nb_config *nb_config_dup(const struct nb_config *config)
{
	struct nb_config *dup;

	dup = XCALLOC(MTYPE_NB_CONFIG, sizeof(*dup));
	dup->dnode = yang_dnode_dup(config->dnode);
	dup->version = config->version;

<<<<<<< HEAD
	RB_INIT(nb_config_cbs, &dup->cfg_chgs);

=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	return dup;
}

int nb_config_merge(struct nb_config *config_dst, struct nb_config *config_src,
		    bool preserve_source)
{
	int ret;

	ret = lyd_merge_siblings(&config_dst->dnode, config_src->dnode, 0);
	if (ret != 0)
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_merge() failed", __func__);

	if (!preserve_source)
		nb_config_free(config_src);

	return (ret == 0) ? NB_OK : NB_ERR;
}

void nb_config_replace(struct nb_config *config_dst,
		       struct nb_config *config_src, bool preserve_source)
{
	/* Update version. */
	if (config_src->version != 0)
		config_dst->version = config_src->version;

	/* Update dnode. */
	if (config_dst->dnode)
		yang_dnode_free(config_dst->dnode);
	if (preserve_source) {
		config_dst->dnode = yang_dnode_dup(config_src->dnode);
	} else {
		config_dst->dnode = config_src->dnode;
		config_src->dnode = NULL;
		nb_config_free(config_src);
	}
}

/* Generate the nb_config_cbs tree. */
static inline int nb_config_cb_compare(const struct nb_config_cb *a,
				       const struct nb_config_cb *b)
{
<<<<<<< HEAD
	/* Sort by priority first. */
	if (a->nb_node->priority < b->nb_node->priority)
		return -1;
	if (a->nb_node->priority > b->nb_node->priority)
		return 1;

	/*
=======
	bool a_destroy = a->operation == NB_CB_DESTROY;
	bool b_destroy = b->operation == NB_CB_DESTROY;

	/*
	 * Sort by operation first. All "destroys" must come first, to correctly
	 * process the change of a "case" inside a "choice". The old "case" must
	 * be deleted before the new "case" is created.
	 */
	if (a_destroy && !b_destroy)
		return -1;
	if (!a_destroy && b_destroy)
		return 1;

	/*
	 * Then sort by priority. If the operation is "destroy", reverse the
	 * order, so that the dependants are deleted before the dependencies.
	 */
	if (a->nb_node->priority < b->nb_node->priority)
		return !a_destroy ? -1 : 1;
	if (a->nb_node->priority > b->nb_node->priority)
		return !a_destroy ? 1 : -1;

	/*
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	 * Preserve the order of the configuration changes as told by libyang.
	 */
	if (a->seq < b->seq)
		return -1;
	if (a->seq > b->seq)
		return 1;

	/*
	 * All 'apply_finish' callbacks have their sequence number set to zero.
	 * In this case, compare them using their dnode pointers (the order
	 * doesn't matter for callbacks that have the same priority).
	 */
	if (a->dnode < b->dnode)
		return -1;
	if (a->dnode > b->dnode)
		return 1;

	return 0;
}
RB_GENERATE(nb_config_cbs, nb_config_cb, entry, nb_config_cb_compare);

<<<<<<< HEAD
static void nb_config_diff_add_change(struct nb_config_cbs *changes,
				      enum nb_operation operation,
				      uint32_t *seq,
				      const struct lyd_node *dnode)
=======
void nb_config_diff_add_change(struct nb_config_cbs *changes,
			       enum nb_cb_operation operation, uint32_t *seq,
			       const struct lyd_node *dnode)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
{
	struct nb_config_change *change;

	/* Ignore unimplemented nodes. */
	if (!dnode->schema->priv)
		return;

	change = XCALLOC(MTYPE_TMP, sizeof(*change));
	change->cb.operation = operation;
	change->cb.seq = *seq;
	*seq = *seq + 1;
	change->cb.nb_node = dnode->schema->priv;
	change->cb.dnode = dnode;

	RB_INSERT(nb_config_cbs, changes, &change->cb);
}

void nb_config_diff_del_changes(struct nb_config_cbs *changes)
{
	while (!RB_EMPTY(nb_config_cbs, changes)) {
		struct nb_config_change *change;

		change = (struct nb_config_change *)RB_ROOT(nb_config_cbs,
							    changes);
		RB_REMOVE(nb_config_cbs, changes, &change->cb);
		XFREE(MTYPE_TMP, change);
	}
}

/*
 * Helper function used when calculating the delta between two different
 * configurations. Given a new subtree, calculate all new YANG data nodes,
 * excluding default leafs and leaf-lists. This is a recursive function.
 */
void nb_config_diff_created(const struct lyd_node *dnode, uint32_t *seq,
			    struct nb_config_cbs *changes)
{
<<<<<<< HEAD
	enum nb_operation operation;
=======
	enum nb_cb_operation operation;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	struct lyd_node *child;

	/* Ignore unimplemented nodes. */
	if (!dnode->schema->priv)
		return;

	switch (dnode->schema->nodetype) {
	case LYS_LEAF:
	case LYS_LEAFLIST:
		if (lyd_is_default(dnode))
			break;

<<<<<<< HEAD
		if (nb_operation_is_valid(NB_OP_CREATE, dnode->schema))
			operation = NB_OP_CREATE;
		else if (nb_operation_is_valid(NB_OP_MODIFY, dnode->schema))
			operation = NB_OP_MODIFY;
=======
		if (nb_cb_operation_is_valid(NB_CB_CREATE, dnode->schema))
			operation = NB_CB_CREATE;
		else if (nb_cb_operation_is_valid(NB_CB_MODIFY, dnode->schema))
			operation = NB_CB_MODIFY;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		else
			return;

		nb_config_diff_add_change(changes, operation, seq, dnode);
		break;
	case LYS_CONTAINER:
	case LYS_LIST:
<<<<<<< HEAD
		if (nb_operation_is_valid(NB_OP_CREATE, dnode->schema))
			nb_config_diff_add_change(changes, NB_OP_CREATE, seq,
=======
		if (nb_cb_operation_is_valid(NB_CB_CREATE, dnode->schema))
			nb_config_diff_add_change(changes, NB_CB_CREATE, seq,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
						  dnode);

		/* Process child nodes recursively. */
		LY_LIST_FOR (lyd_child(dnode), child) {
			nb_config_diff_created(child, seq, changes);
		}
		break;
	default:
		break;
	}
}

static void nb_config_diff_deleted(const struct lyd_node *dnode, uint32_t *seq,
				   struct nb_config_cbs *changes)
{
	/* Ignore unimplemented nodes. */
	if (!dnode->schema->priv)
		return;

<<<<<<< HEAD
	if (nb_operation_is_valid(NB_OP_DESTROY, dnode->schema))
		nb_config_diff_add_change(changes, NB_OP_DESTROY, seq, dnode);
=======
	if (nb_cb_operation_is_valid(NB_CB_DESTROY, dnode->schema))
		nb_config_diff_add_change(changes, NB_CB_DESTROY, seq, dnode);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	else if (CHECK_FLAG(dnode->schema->nodetype, LYS_CONTAINER)) {
		struct lyd_node *child;

		/*
		 * Non-presence containers need special handling since they
		 * don't have "destroy" callbacks. In this case, what we need to
		 * do is to call the "destroy" callbacks of their child nodes
		 * when applicable (i.e. optional nodes).
		 */
		LY_LIST_FOR (lyd_child(dnode), child) {
			nb_config_diff_deleted(child, seq, changes);
		}
	}
}

static int nb_lyd_diff_get_op(const struct lyd_node *dnode)
{
	const struct lyd_meta *meta;
	LY_LIST_FOR (dnode->meta, meta) {
		if (strcmp(meta->name, "operation")
		    || strcmp(meta->annotation->module->name, "yang"))
			continue;
		return lyd_get_meta_value(meta)[0];
	}
	return 'n';
}

#if 0 /* Used below in nb_config_diff inside normally disabled code */
static inline void nb_config_diff_dnode_log_path(const char *context,
						 const char *path,
						 const struct lyd_node *dnode)
{
	if (dnode->schema->nodetype & LYD_NODE_TERM)
		zlog_debug("nb_config_diff: %s: %s: %s", context, path,
			   lyd_get_value(dnode));
	else
		zlog_debug("nb_config_diff: %s: %s", context, path);
}

static inline void nb_config_diff_dnode_log(const char *context,
					    const struct lyd_node *dnode)
{
	if (!dnode) {
		zlog_debug("nb_config_diff: %s: NULL", context);
		return;
	}

	char *path = lyd_path(dnode, LYD_PATH_STD, NULL, 0);
	nb_config_diff_dnode_log_path(context, path, dnode);
	free(path);
}
#endif

/*
 * Calculate the delta between two different configurations.
 *
 * NOTE: 'config1' is the reference DB, while 'config2' is
 * the DB being compared against 'config1'. Typically 'config1'
 * should be the Running DB and 'config2' is the Candidate DB.
 */
void nb_config_diff(const struct nb_config *config1,
		    const struct nb_config *config2,
		    struct nb_config_cbs *changes)
{
	struct lyd_node *diff = NULL;
	const struct lyd_node *root, *dnode;
	struct lyd_node *target;
	int op;
	LY_ERR err;
	char *path;

#if 0 /* Useful (noisy) when debugging diff code, and for improving later */
	if (DEBUG_MODE_CHECK(&nb_dbg_cbs_config, DEBUG_MODE_ALL)) {
		LY_LIST_FOR(config1->dnode, root) {
			LYD_TREE_DFS_BEGIN(root, dnode) {
				nb_config_diff_dnode_log("from", dnode);
				LYD_TREE_DFS_END(root, dnode);
			}
		}
		LY_LIST_FOR(config2->dnode, root) {
			LYD_TREE_DFS_BEGIN(root, dnode) {
				nb_config_diff_dnode_log("to", dnode);
				LYD_TREE_DFS_END(root, dnode);
			}
		}
	}
#endif

	err = lyd_diff_siblings(config1->dnode, config2->dnode,
				LYD_DIFF_DEFAULTS, &diff);
	assert(!err);

	if (diff && DEBUG_MODE_CHECK(&nb_dbg_cbs_config, DEBUG_MODE_ALL)) {
		char *s;

		if (!lyd_print_mem(&s, diff, LYD_JSON,
				   LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL)) {
			zlog_debug("%s: %s", __func__, s);
			free(s);
		}
	}

	uint32_t seq = 0;

	LY_LIST_FOR (diff, root) {
		LYD_TREE_DFS_BEGIN (root, dnode) {
			op = nb_lyd_diff_get_op(dnode);

			path = lyd_path(dnode, LYD_PATH_STD, NULL, 0);

#if 0 /* Useful (noisy) when debugging diff code, and for improving later */
			if (DEBUG_MODE_CHECK(&nb_dbg_cbs_config, DEBUG_MODE_ALL)) {
				char context[80];
				snprintf(context, sizeof(context),
					 "iterating diff: oper: %c seq: %u", op, seq);
				nb_config_diff_dnode_log_path(context, path, dnode);
			}
#endif
			switch (op) {
			case 'c': /* create */
				  /*
				   * This is rather inefficient, but when we use
				   * dnode from the diff instead of the
				   * candidate config node we get failures when
				   * looking up default values, etc, based on
				   * the diff tree.
				   */
				target = yang_dnode_get(config2->dnode, path);
				assert(target);
				nb_config_diff_created(target, &seq, changes);

				/* Skip rest of sub-tree, move to next sibling
				 */
				LYD_TREE_DFS_continue = 1;
				break;
			case 'd': /* delete */
				target = yang_dnode_get(config1->dnode, path);
				assert(target);
				nb_config_diff_deleted(target, &seq, changes);

				/* Skip rest of sub-tree, move to next sibling
				 */
				LYD_TREE_DFS_continue = 1;
				break;
			case 'r': /* replace */
				/* either moving an entry or changing a value */
				target = yang_dnode_get(config2->dnode, path);
				assert(target);
<<<<<<< HEAD
				nb_config_diff_add_change(changes, NB_OP_MODIFY,
=======
				nb_config_diff_add_change(changes, NB_CB_MODIFY,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
							  &seq, target);
				break;
			case 'n': /* none */
			default:
				break;
			}
			free(path);
			LYD_TREE_DFS_END(root, dnode);
		}
	}

	lyd_free_all(diff);
}

<<<<<<< HEAD
int nb_candidate_edit(struct nb_config *candidate,
		      const struct nb_node *nb_node,
=======
static int dnode_create(struct nb_config *candidate, const char *xpath,
			const char *value, uint32_t options,
			struct lyd_node **new_dnode)
{
	struct lyd_node *dnode;
	LY_ERR err;

	err = lyd_new_path(candidate->dnode, ly_native_ctx, xpath, value,
			   options, &dnode);
	if (err) {
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_new_path(%s) failed: %d",
			  __func__, xpath, err);
		return NB_ERR;
	} else if (dnode) {
		err = lyd_new_implicit_tree(dnode, LYD_IMPLICIT_NO_STATE, NULL);
		if (err) {
			flog_warn(EC_LIB_LIBYANG,
				  "%s: lyd_new_implicit_all failed: %d",
				  __func__, err);
		}
	}
	if (new_dnode)
		*new_dnode = dnode;
	return NB_OK;
}

int nb_candidate_edit(struct nb_config *candidate, const struct nb_node *nb_node,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		      enum nb_operation operation, const char *xpath,
		      const struct yang_data *previous,
		      const struct yang_data *data)
{
<<<<<<< HEAD
	struct lyd_node *dnode, *dep_dnode;
	char xpath_edit[XPATH_MAXLEN];
	char dep_xpath[XPATH_MAXLEN];
	LY_ERR err;

	/* Use special notation for leaf-lists (RFC 6020, section 9.13.5). */
	if (nb_node->snode->nodetype == LYS_LEAFLIST)
		snprintf(xpath_edit, sizeof(xpath_edit), "%s[.='%s']", xpath,
			 data->value);
	else
		strlcpy(xpath_edit, xpath, sizeof(xpath_edit));

	switch (operation) {
	case NB_OP_CREATE:
	case NB_OP_MODIFY:
		err = lyd_new_path(candidate->dnode, ly_native_ctx, xpath_edit,
				   (void *)data->value, LYD_NEW_PATH_UPDATE,
				   &dnode);
		if (err) {
			flog_warn(EC_LIB_LIBYANG,
				  "%s: lyd_new_path(%s) failed: %d", __func__,
				  xpath_edit, err);
			return NB_ERR;
		} else if (dnode) {
			/* Create default nodes */
			LY_ERR err = lyd_new_implicit_tree(
				dnode, LYD_IMPLICIT_NO_STATE, NULL);
			if (err) {
				flog_warn(EC_LIB_LIBYANG,
					  "%s: lyd_new_implicit_all failed: %d",
					  __func__, err);
			}
=======
	struct lyd_node *dnode, *dep_dnode, *old_dnode;
	char dep_xpath[XPATH_MAXLEN];
	struct lyd_node *parent = NULL;
	uint32_t options = 0;
	LY_ERR err;

	switch (operation) {
	case NB_OP_CREATE:
	case NB_OP_MODIFY:
		options = LYD_NEW_PATH_UPDATE;
		fallthrough;
	case NB_OP_CREATE_EXCL:
		err = dnode_create(candidate, xpath, data->value, options,
				   &dnode);
		if (err) {
			return err;
		} else if (dnode) {
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			/*
			 * create dependency
			 *
			 * dnode returned by the lyd_new_path may be from a
			 * different schema, so we need to update the nb_node
			 */
			nb_node = dnode->schema->priv;
			if (nb_node->dep_cbs.get_dependency_xpath) {
				nb_node->dep_cbs.get_dependency_xpath(
					dnode, dep_xpath);

<<<<<<< HEAD
				err = lyd_new_path(candidate->dnode,
						   ly_native_ctx, dep_xpath,
						   NULL, LYD_NEW_PATH_UPDATE,
						   &dep_dnode);
				/* Create default nodes */
				if (!err && dep_dnode)
					err = lyd_new_implicit_tree(
						dep_dnode,
						LYD_IMPLICIT_NO_STATE, NULL);
				if (err) {
					flog_warn(
						EC_LIB_LIBYANG,
						"%s: dependency: lyd_new_path(%s) failed: %d",
						__func__, dep_xpath, err);
					return NB_ERR;
=======
				err = dnode_create(candidate, dep_xpath, NULL,
						   LYD_NEW_PATH_UPDATE, NULL);
				if (err) {
					lyd_free_tree(dnode);
					return err;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
				}
			}
		}
		break;
	case NB_OP_DESTROY:
<<<<<<< HEAD
		dnode = yang_dnode_get(candidate->dnode, xpath_edit);
		if (!dnode)
			/*
			 * Return a special error code so the caller can choose
			 * whether to ignore it or not.
			 */
			return NB_ERR_NOT_FOUND;
=======
	case NB_OP_DELETE:
		dnode = yang_dnode_get(candidate->dnode, xpath);
		if (!dnode) {
			if (operation == NB_OP_DELETE)
				return NB_ERR;
			else
				return NB_OK;
		}
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		/* destroy dependant */
		if (nb_node->dep_cbs.get_dependant_xpath) {
			nb_node->dep_cbs.get_dependant_xpath(dnode, dep_xpath);

			dep_dnode = yang_dnode_get(candidate->dnode, dep_xpath);
			if (dep_dnode)
				lyd_free_tree(dep_dnode);
		}
		lyd_free_tree(dnode);
		break;
<<<<<<< HEAD
	case NB_OP_MOVE:
		/* TODO: update configuration. */
		break;
	case NB_OP_PRE_VALIDATE:
	case NB_OP_APPLY_FINISH:
	case NB_OP_GET_ELEM:
	case NB_OP_GET_NEXT:
	case NB_OP_GET_KEYS:
	case NB_OP_LOOKUP_ENTRY:
	case NB_OP_RPC:
		flog_warn(EC_LIB_DEVELOPMENT,
			  "%s: unknown operation (%u) [xpath %s]", __func__,
			  operation, xpath_edit);
		return NB_ERR;
=======
	case NB_OP_REPLACE:
		old_dnode = yang_dnode_get(candidate->dnode, xpath);
		if (old_dnode) {
			parent = lyd_parent(old_dnode);
			lyd_unlink_tree(old_dnode);
		}
		err = dnode_create(candidate, xpath, data->value, options,
				   &dnode);
		if (!err && dnode && !old_dnode) {
			/* create dependency if the node didn't exist */
			nb_node = dnode->schema->priv;
			if (nb_node->dep_cbs.get_dependency_xpath) {
				nb_node->dep_cbs.get_dependency_xpath(
					dnode, dep_xpath);

				err = dnode_create(candidate, dep_xpath, NULL,
						   LYD_NEW_PATH_UPDATE, NULL);
				if (err)
					lyd_free_tree(dnode);
			}
		}
		if (old_dnode) {
			/* restore original node on error, free it otherwise */
			if (err) {
				if (parent)
					lyd_insert_child(parent, old_dnode);
				else
					lyd_insert_sibling(candidate->dnode,
							   old_dnode, NULL);
				return err;
			}

			lyd_free_tree(old_dnode);
		}
		break;
	case NB_OP_MOVE:
		/* TODO: update configuration. */
		break;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	}

	return NB_OK;
}

<<<<<<< HEAD
static void nb_update_candidate_changes(struct nb_config *candidate,
					struct nb_cfg_change *change,
					uint32_t *seq)
{
	enum nb_operation oper = change->operation;
	char *xpath = change->xpath;
	struct lyd_node *root = NULL;
	struct lyd_node *dnode;
	struct nb_config_cbs *cfg_chgs = &candidate->cfg_chgs;
	int op;

	switch (oper) {
	case NB_OP_CREATE:
	case NB_OP_MODIFY:
		root = yang_dnode_get(candidate->dnode, xpath);
		break;
	case NB_OP_DESTROY:
		root = yang_dnode_get(running_config->dnode, xpath);
		/* code */
		break;
	case NB_OP_MOVE:
	case NB_OP_PRE_VALIDATE:
	case NB_OP_APPLY_FINISH:
	case NB_OP_GET_ELEM:
	case NB_OP_GET_NEXT:
	case NB_OP_GET_KEYS:
	case NB_OP_LOOKUP_ENTRY:
	case NB_OP_RPC:
		break;
	default:
		assert(!"non-enum value, invalid");
	}

	if (!root)
		return;

	LYD_TREE_DFS_BEGIN (root, dnode) {
		op = nb_lyd_diff_get_op(dnode);
		switch (op) {
		case 'c': /* create */
			nb_config_diff_created(dnode, seq, cfg_chgs);
			LYD_TREE_DFS_continue = 1;
			break;
		case 'd': /* delete */
			nb_config_diff_deleted(dnode, seq, cfg_chgs);
			LYD_TREE_DFS_continue = 1;
			break;
		case 'r': /* replace */
			nb_config_diff_add_change(cfg_chgs, NB_OP_MODIFY, seq,
						  dnode);
			break;
		case 'n': /* none */
		default:
			break;
		}
		LYD_TREE_DFS_END(root, dnode);
	}
}

static bool nb_is_operation_allowed(struct nb_node *nb_node,
				    struct nb_cfg_change *change)
{
	enum nb_operation oper = change->operation;

	if (lysc_is_key(nb_node->snode)) {
		if (oper == NB_OP_MODIFY || oper == NB_OP_DESTROY)
=======
static int nb_candidate_edit_tree_add(struct nb_config *candidate,
				      enum nb_operation operation,
				      LYD_FORMAT format, const char *xpath,
				      const char *data, bool *created,
				      char *xpath_created, char *errmsg,
				      size_t errmsg_len)
{
	struct lyd_node *tree = NULL;
	struct lyd_node *parent = NULL;
	struct lyd_node *dnode = NULL;
	struct lyd_node *existing = NULL;
	struct lyd_node *ex_parent = NULL;
	char *parent_xpath = NULL;
	struct ly_in *in;
	LY_ERR err;
	bool root;
	int ret;

	ly_in_new_memory(data, &in);

	root = xpath[0] == 0 || (xpath[0] == '/' && xpath[1] == 0);

	/* get parent xpath if xpath is not root */
	if (!root) {
		/* NB_OP_CREATE_EXCT already expects parent xpath */
		parent_xpath = XSTRDUP(MTYPE_TMP, xpath);

		/* for other operations - pop one level */
		if (operation != NB_OP_CREATE_EXCL) {
			ret = yang_xpath_pop_node(parent_xpath);
			if (ret) {
				snprintf(errmsg, errmsg_len, "Invalid xpath");
				goto done;
			}

			/* root is not actually a parent */
			if (parent_xpath[0] == 0)
				XFREE(MTYPE_TMP, parent_xpath);
		}
	}

	/*
	 * Create parent if it's not root. We're creating a new tree here to be
	 * merged later with candidate.
	 */
	if (parent_xpath) {
		err = lyd_new_path2(NULL, ly_native_ctx, parent_xpath, NULL, 0,
				    0, 0, &tree, &parent);
		if (err) {
			yang_print_errors(ly_native_ctx, errmsg, errmsg_len);
			ret = NB_ERR;
			goto done;
		}
		assert(parent);
	}

	/* parse data */
	err = yang_lyd_parse_data(ly_native_ctx, parent, in, format,
				  LYD_PARSE_ONLY | LYD_PARSE_STRICT |
					  LYD_PARSE_NO_STATE,
				  0, &dnode);
	if (err) {
		yang_print_errors(ly_native_ctx, errmsg, errmsg_len);
		ret = NB_ERR;
		goto done;
	}

	/* set the tree if we created a top-level node */
	if (!parent)
		tree = dnode;

	/* save xpath of the created node */
	lyd_path(dnode, LYD_PATH_STD, xpath_created, XPATH_MAXLEN);

	/* verify that list keys are the same in the xpath and the data tree */
	if (!root && (operation == NB_OP_REPLACE || operation == NB_OP_MODIFY)) {
		if (lyd_find_path(tree, xpath, 0, NULL)) {
			snprintf(errmsg, errmsg_len,
				 "List keys in xpath and data tree are different");
			ret = NB_ERR;
			goto done;
		}
	}

	/* check if the node already exists in candidate */
	if (operation == NB_OP_CREATE || operation == NB_OP_MODIFY)
		existing = yang_dnode_get(candidate->dnode, xpath_created);
	else if (operation == NB_OP_CREATE_EXCL || operation == NB_OP_REPLACE) {
		existing = yang_dnode_get(candidate->dnode, xpath_created);

		/* if the existing node is implicit default, ignore */
		/* Q: Is this correct for CREATE_EXCL which is supposed to error
		 * if the resouurce already exists? This is used by RESTCONF
		 * when processing the POST command, for example. RFC8040
		 * doesn't say POST fails if resource exists "unless it was a
		 * default".
		 */
		if (existing && (existing->flags & LYD_DEFAULT))
			existing = NULL;

		if (existing) {
			if (operation == NB_OP_CREATE_EXCL) {
				snprintf(errmsg, errmsg_len,
					 "Data already exists");
				ret = NB_ERR_EXISTS;
				goto done;
			}

			if (root) {
				candidate->dnode = NULL;
			} else {
				/* if it's the first top-level node, update candidate */
				if (candidate->dnode == existing)
					candidate->dnode =
						candidate->dnode->next;

				ex_parent = lyd_parent(existing);
				lyd_unlink_tree(existing);
			}
		}
	}

	err = lyd_merge_siblings(&candidate->dnode, tree,
				 LYD_MERGE_DESTRUCT | LYD_MERGE_WITH_FLAGS);
	if (err) {
		/* if replace failed, restore the original node */
		if (existing && operation == NB_OP_REPLACE) {
			if (root) {
				/* Restoring the whole config. */
				candidate->dnode = existing;
			} else if (ex_parent) {
				/*
				 * Restoring a nested node. Insert it as a
				 * child.
				 */
				lyd_insert_child(ex_parent, existing);
			} else {
				/*
				 * Restoring a top-level node. Insert it as a
				 * sibling to candidate->dnode to make sure
				 * the linkage is correct.
				 */
				lyd_insert_sibling(candidate->dnode, existing,
						   &candidate->dnode);
			}
		}
		yang_print_errors(ly_native_ctx, errmsg, errmsg_len);
		ret = NB_ERR;
		goto done;
	} else {
		if (!existing)
			*created = true;
		/*
		 * Free existing node after replace.
		 * We're using `lyd_free_siblings` here to free the whole
		 * tree if we replaced the root node. It won't affect other
		 * siblings if it wasn't root, because the existing node
		 * was unlinked from the tree.
		 */
		if (existing && operation == NB_OP_REPLACE)
			lyd_free_siblings(existing);

		tree = NULL; /* LYD_MERGE_DESTRUCT deleted the tree */
	}

	ret = NB_OK;
done:
	if (tree)
		lyd_free_all(tree);
	XFREE(MTYPE_TMP, parent_xpath);
	ly_in_free(in, 0);

	return ret;
}

static int nb_candidate_edit_tree_del(struct nb_config *candidate,
				      enum nb_operation operation,
				      const char *xpath, char *errmsg,
				      size_t errmsg_len)
{
	struct lyd_node *dnode;

	/* deleting root - remove the whole config */
	if (xpath[0] == 0 || (xpath[0] == '/' && xpath[1] == 0)) {
		lyd_free_all(candidate->dnode);
		candidate->dnode = NULL;
		return NB_OK;
	}

	dnode = yang_dnode_get(candidate->dnode, xpath);
	if (!dnode || (dnode->flags & LYD_DEFAULT)) {
		if (operation == NB_OP_DELETE) {
			snprintf(errmsg, errmsg_len, "Data missing");
			return NB_ERR_NOT_FOUND;
		} else
			return NB_OK;
	}

	/* if it's the first top-level node, update candidate */
	if (candidate->dnode == dnode)
		candidate->dnode = candidate->dnode->next;

	lyd_free_tree(dnode);

	return NB_OK;
}

int nb_candidate_edit_tree(struct nb_config *candidate,
			   enum nb_operation operation, LYD_FORMAT format,
			   const char *xpath, const char *data, bool *created,
			   char *xpath_created, char *errmsg, size_t errmsg_len)
{
	int ret = NB_ERR;

	switch (operation) {
	case NB_OP_CREATE_EXCL:
	case NB_OP_CREATE:
	case NB_OP_MODIFY:
	case NB_OP_REPLACE:
		ret = nb_candidate_edit_tree_add(candidate, operation, format,
						 xpath, data, created,
						 xpath_created, errmsg,
						 errmsg_len);
		break;
	case NB_OP_DESTROY:
	case NB_OP_DELETE:
		ret = nb_candidate_edit_tree_del(candidate, operation, xpath,
						 errmsg, errmsg_len);
		break;
	case NB_OP_MOVE:
		/* not supported yet */
		break;
	}

	return ret;
}

const char *nb_operation_name(enum nb_operation operation)
{
	switch (operation) {
	case NB_OP_CREATE_EXCL:
		return "create exclusive";
	case NB_OP_CREATE:
		return "create";
	case NB_OP_MODIFY:
		return "modify";
	case NB_OP_DESTROY:
		return "destroy";
	case NB_OP_DELETE:
		return "delete";
	case NB_OP_REPLACE:
		return "replace";
	case NB_OP_MOVE:
		return "move";
	}

	assert(!"Reached end of function we should never hit");
}

bool nb_is_operation_allowed(struct nb_node *nb_node, enum nb_operation oper)
{
	if (lysc_is_key(nb_node->snode)) {
		if (oper == NB_OP_MODIFY || oper == NB_OP_DESTROY
		    || oper == NB_OP_DELETE || oper == NB_OP_REPLACE)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			return false;
	}
	return true;
}

<<<<<<< HEAD
void nb_candidate_edit_config_changes(
	struct nb_config *candidate_config, struct nb_cfg_change cfg_changes[],
	size_t num_cfg_changes, const char *xpath_base, const char *curr_xpath,
	int xpath_index, char *err_buf, int err_bufsize, bool *error)
{
	uint32_t seq = 0;

=======
void nb_candidate_edit_config_changes(struct nb_config *candidate_config,
				      struct nb_cfg_change cfg_changes[],
				      size_t num_cfg_changes,
				      const char *xpath_base, bool in_backend,
				      char *err_buf, int err_bufsize,
				      bool *error)
{
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	if (error)
		*error = false;

	if (xpath_base == NULL)
		xpath_base = "";

	/* Edit candidate configuration. */
	for (size_t i = 0; i < num_cfg_changes; i++) {
		struct nb_cfg_change *change = &cfg_changes[i];
		struct nb_node *nb_node;
<<<<<<< HEAD
=======
		char *change_xpath = change->xpath;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		char xpath[XPATH_MAXLEN];
		const char *value;
		struct yang_data *data;
		int ret;

<<<<<<< HEAD
		/* Handle relative XPaths. */
		memset(xpath, 0, sizeof(xpath));
		if (xpath_index > 0 &&
		    (xpath_base[0] == '.' || change->xpath[0] == '.'))
			strlcpy(xpath, curr_xpath, sizeof(xpath));
		if (xpath_base[0]) {
			if (xpath_base[0] == '.')
				strlcat(xpath, xpath_base + 1, sizeof(xpath));
			else
				strlcat(xpath, xpath_base, sizeof(xpath));
		}
		if (change->xpath[0] == '.')
			strlcat(xpath, change->xpath + 1, sizeof(xpath));
		else
			strlcpy(xpath, change->xpath, sizeof(xpath));
=======
		memset(xpath, 0, sizeof(xpath));
		/* If change xpath is relative, prepend base xpath. */
		if (change_xpath[0] == '.') {
			strlcpy(xpath, xpath_base, sizeof(xpath));
			change_xpath++; /* skip '.' */
		}
		strlcat(xpath, change_xpath, sizeof(xpath));
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

		/* Find the northbound node associated to the data path. */
		nb_node = nb_node_find(xpath);
		if (!nb_node) {
<<<<<<< HEAD
			flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
				  "%s: unknown data path: %s", __func__, xpath);
			if (error)
				*error = true;
			continue;
		}
		/* Find if the node to be edited is not a key node */
		if (!nb_is_operation_allowed(nb_node, change)) {
=======
			if (in_backend)
				DEBUGD(&nb_dbg_cbs_config,
				       "%s: ignoring non-handled path: %s",
				       __func__, xpath);
			else {
				flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
					  "%s: unknown data path: %s", __func__,
					  xpath);
				if (error)
					*error = true;
			}
			continue;
		}
		/* Find if the node to be edited is not a key node */
		if (!nb_is_operation_allowed(nb_node, change->operation)) {
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			zlog_err(" Xpath %s points to key node", xpath);
			if (error)
				*error = true;
			break;
		}

		/* If the value is not set, get the default if it exists. */
		value = change->value;
		if (value == NULL)
			value = yang_snode_get_default(nb_node->snode);
		data = yang_data_new(xpath, value);

		/*
		 * Ignore "not found" errors when editing the candidate
		 * configuration.
		 */
		ret = nb_candidate_edit(candidate_config, nb_node,
					change->operation, xpath, NULL, data);
		yang_data_free(data);
<<<<<<< HEAD
		if (ret != NB_OK && ret != NB_ERR_NOT_FOUND) {
=======
		if (ret != NB_OK) {
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			flog_warn(
				EC_LIB_NB_CANDIDATE_EDIT_ERROR,
				"%s: failed to edit candidate configuration: operation [%s] xpath [%s]",
				__func__, nb_operation_name(change->operation),
				xpath);
			if (error)
				*error = true;
			continue;
		}
<<<<<<< HEAD
		nb_update_candidate_changes(candidate_config, change, &seq);
=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	}

	if (error && *error) {
		char buf[BUFSIZ];

<<<<<<< HEAD
		/*
		 * Failure to edit the candidate configuration should never
		 * happen in practice, unless there's a bug in the code. When
		 * that happens, log the error but otherwise ignore it.
		 */
=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		snprintf(err_buf, err_bufsize,
			 "%% Failed to edit configuration.\n\n%s",
			 yang_print_errors(ly_native_ctx, buf, sizeof(buf)));
	}
}

bool nb_candidate_needs_update(const struct nb_config *candidate)
{
	if (candidate->version < running_config->version)
		return true;

	return false;
}

int nb_candidate_update(struct nb_config *candidate)
{
	struct nb_config *updated_config;

	updated_config = nb_config_dup(running_config);
	if (nb_config_merge(updated_config, candidate, true) != NB_OK)
		return NB_ERR;

	nb_config_replace(candidate, updated_config, false);

	return NB_OK;
}

/*
 * Perform YANG syntactic and semantic validation.
 *
 * WARNING: lyd_validate() can change the configuration as part of the
 * validation process.
 */
int nb_candidate_validate_yang(struct nb_config *candidate, bool no_state,
			       char *errmsg, size_t errmsg_len)
{
<<<<<<< HEAD
	if (lyd_validate_all(&candidate->dnode, ly_native_ctx,
			     no_state ? LYD_VALIDATE_NO_STATE
				      : LYD_VALIDATE_PRESENT,
=======
	uint32_t options = 0;

#ifdef LYD_VALIDATE_MULTI_ERROR
	/* libyang 2.1.36+ */
	options |= LYD_VALIDATE_MULTI_ERROR;
#endif

	if (no_state)
		SET_FLAG(options, LYD_VALIDATE_NO_STATE);
	else
		SET_FLAG(options, LYD_VALIDATE_PRESENT);

	if (lyd_validate_all(&candidate->dnode, ly_native_ctx, options,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			     NULL) != 0) {
		yang_print_errors(ly_native_ctx, errmsg, errmsg_len);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/* Perform code-level validation using the northbound callbacks. */
int nb_candidate_validate_code(struct nb_context *context,
			       struct nb_config *candidate,
			       struct nb_config_cbs *changes, char *errmsg,
			       size_t errmsg_len)
{
	struct nb_config_cb *cb;
	struct lyd_node *root, *child;
	int ret;

	/* First validate the candidate as a whole. */
	LY_LIST_FOR (candidate->dnode, root) {
		LYD_TREE_DFS_BEGIN (root, child) {
			struct nb_node *nb_node;

			nb_node = child->schema->priv;
			if (!nb_node || !nb_node->cbs.pre_validate)
				goto next;

			ret = nb_callback_pre_validate(context, nb_node, child,
						       errmsg, errmsg_len);
			if (ret != NB_OK)
				return NB_ERR_VALIDATION;

		next:
			LYD_TREE_DFS_END(root, child);
		}
	}

	/* Now validate the configuration changes. */
	RB_FOREACH (cb, nb_config_cbs, changes) {
		struct nb_config_change *change = (struct nb_config_change *)cb;

		ret = nb_callback_configuration(context, NB_EV_VALIDATE, change,
						errmsg, errmsg_len);
		if (ret != NB_OK)
			return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

int nb_candidate_diff_and_validate_yang(struct nb_context *context,
					struct nb_config *candidate,
					struct nb_config_cbs *changes,
					char *errmsg, size_t errmsg_len)
{
	if (nb_candidate_validate_yang(candidate, true, errmsg,
				       sizeof(errmsg_len)) != NB_OK)
		return NB_ERR_VALIDATION;

	RB_INIT(nb_config_cbs, changes);
	nb_config_diff(running_config, candidate, changes);

	return NB_OK;
}

int nb_candidate_validate(struct nb_context *context,
			  struct nb_config *candidate, char *errmsg,
			  size_t errmsg_len)
{
	struct nb_config_cbs changes;
	int ret;

	ret = nb_candidate_diff_and_validate_yang(context, candidate, &changes,
						  errmsg, errmsg_len);
	if (ret != NB_OK)
		return ret;

	ret = nb_candidate_validate_code(context, candidate, &changes, errmsg,
					 errmsg_len);
	nb_config_diff_del_changes(&changes);

	return ret;
}

int nb_candidate_commit_prepare(struct nb_context context,
				struct nb_config *candidate,
				const char *comment,
				struct nb_transaction **transaction,
				bool skip_validate, bool ignore_zero_change,
				char *errmsg, size_t errmsg_len)
{
	struct nb_config_cbs changes;

	if (!skip_validate &&
	    nb_candidate_validate_yang(candidate, true, errmsg, errmsg_len) !=
		    NB_OK) {
		flog_warn(EC_LIB_NB_CANDIDATE_INVALID,
			  "%s: failed to validate candidate configuration",
			  __func__);
		return NB_ERR_VALIDATION;
	}

	RB_INIT(nb_config_cbs, &changes);
	nb_config_diff(running_config, candidate, &changes);
	if (!ignore_zero_change && RB_EMPTY(nb_config_cbs, &changes)) {
		snprintf(
			errmsg, errmsg_len,
			"No changes to apply were found during preparation phase");
		return NB_ERR_NO_CHANGES;
	}

	if (!skip_validate &&
	    nb_candidate_validate_code(&context, candidate, &changes, errmsg,
				       errmsg_len) != NB_OK) {
		flog_warn(EC_LIB_NB_CANDIDATE_INVALID,
			  "%s: failed to validate candidate configuration",
			  __func__);
		nb_config_diff_del_changes(&changes);
		return NB_ERR_VALIDATION;
	}

	/*
	 * Re-use an existing transaction if provided. Else allocate a new one.
	 */
	if (!*transaction)
		*transaction = nb_transaction_new(context, candidate, &changes,
						  comment, errmsg, errmsg_len);
	if (*transaction == NULL) {
		flog_warn(EC_LIB_NB_TRANSACTION_CREATION_FAILED,
			  "%s: failed to create transaction: %s", __func__,
			  errmsg);
		nb_config_diff_del_changes(&changes);
		return NB_ERR_LOCKED;
	}

	return nb_transaction_process(NB_EV_PREPARE, *transaction, errmsg,
				      errmsg_len);
}

void nb_candidate_commit_abort(struct nb_transaction *transaction, char *errmsg,
			       size_t errmsg_len)
{
	(void)nb_transaction_process(NB_EV_ABORT, transaction, errmsg,
				     errmsg_len);
	nb_transaction_free(transaction);
}

void nb_candidate_commit_apply(struct nb_transaction *transaction,
			       bool save_transaction, uint32_t *transaction_id,
			       char *errmsg, size_t errmsg_len)
{
	(void)nb_transaction_process(NB_EV_APPLY, transaction, errmsg,
				     errmsg_len);
	nb_transaction_apply_finish(transaction, errmsg, errmsg_len);

	/* Replace running by candidate. */
	transaction->config->version++;
	nb_config_replace(running_config, transaction->config, true);

	/* Record transaction. */
	if (save_transaction && nb_db_enabled
	    && nb_db_transaction_save(transaction, transaction_id) != NB_OK)
		flog_warn(EC_LIB_NB_TRANSACTION_RECORD_FAILED,
			  "%s: failed to record transaction", __func__);

	nb_transaction_free(transaction);
}

int nb_candidate_commit(struct nb_context context, struct nb_config *candidate,
			bool save_transaction, const char *comment,
			uint32_t *transaction_id, char *errmsg,
			size_t errmsg_len)
{
	struct nb_transaction *transaction = NULL;
	int ret;

	ret = nb_candidate_commit_prepare(context, candidate, comment,
					  &transaction, false, false, errmsg,
					  errmsg_len);
	/*
	 * Apply the changes if the preparation phase succeeded. Otherwise abort
	 * the transaction.
	 */
	if (ret == NB_OK)
		nb_candidate_commit_apply(transaction, save_transaction,
					  transaction_id, errmsg, errmsg_len);
	else if (transaction != NULL)
		nb_candidate_commit_abort(transaction, errmsg, errmsg_len);

	return ret;
}

int nb_running_lock(enum nb_client client, const void *user)
{
	int ret = -1;

	frr_with_mutex (&running_config_mgmt_lock.mtx) {
		if (!running_config_mgmt_lock.locked) {
			running_config_mgmt_lock.locked = true;
			running_config_mgmt_lock.owner_client = client;
			running_config_mgmt_lock.owner_user = user;
			ret = 0;
		}
	}

	return ret;
}

int nb_running_unlock(enum nb_client client, const void *user)
{
	int ret = -1;

	frr_with_mutex (&running_config_mgmt_lock.mtx) {
		if (running_config_mgmt_lock.locked
		    && running_config_mgmt_lock.owner_client == client
		    && running_config_mgmt_lock.owner_user == user) {
			running_config_mgmt_lock.locked = false;
			running_config_mgmt_lock.owner_client = NB_CLIENT_NONE;
			running_config_mgmt_lock.owner_user = NULL;
			ret = 0;
		}
	}

	return ret;
}

int nb_running_lock_check(enum nb_client client, const void *user)
{
	int ret = -1;

	frr_with_mutex (&running_config_mgmt_lock.mtx) {
		if (!running_config_mgmt_lock.locked
		    || (running_config_mgmt_lock.owner_client == client
			&& running_config_mgmt_lock.owner_user == user))
			ret = 0;
	}

	return ret;
}

static void nb_log_config_callback(const enum nb_event event,
<<<<<<< HEAD
				   enum nb_operation operation,
=======
				   enum nb_cb_operation operation,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
				   const struct lyd_node *dnode)
{
	const char *value;
	char xpath[XPATH_MAXLEN];

	if (!DEBUG_MODE_CHECK(&nb_dbg_cbs_config, DEBUG_MODE_ALL))
		return;

	yang_dnode_get_path(dnode, xpath, sizeof(xpath));
	if (yang_snode_is_typeless_data(dnode->schema))
		value = "(none)";
	else
		value = yang_dnode_get_string(dnode, NULL);

	zlog_debug(
		"northbound callback: event [%s] op [%s] xpath [%s] value [%s]",
<<<<<<< HEAD
		nb_event_name(event), nb_operation_name(operation), xpath,
=======
		nb_event_name(event), nb_cb_operation_name(operation), xpath,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		value);
}

static int nb_callback_create(struct nb_context *context,
			      const struct nb_node *nb_node,
			      enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource, char *errmsg,
			      size_t errmsg_len)
{
	struct nb_cb_create_args args = {};
	bool unexpected_error = false;
	int ret;

<<<<<<< HEAD
	assert(!CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS));

	nb_log_config_callback(event, NB_OP_CREATE, dnode);
=======
	assert(!CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS));

	nb_log_config_callback(event, NB_CB_CREATE, dnode);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	args.context = context;
	args.event = event;
	args.dnode = dnode;
	args.resource = resource;
	args.errmsg = errmsg;
	args.errmsg_len = errmsg_len;
	ret = nb_node->cbs.create(&args);

	/* Detect and log unexpected errors. */
	switch (ret) {
	case NB_OK:
	case NB_ERR:
		break;
	case NB_ERR_VALIDATION:
		if (event != NB_EV_VALIDATE)
			unexpected_error = true;
		break;
	case NB_ERR_RESOURCE:
		if (event != NB_EV_PREPARE)
			unexpected_error = true;
		break;
	case NB_ERR_INCONSISTENCY:
		if (event == NB_EV_VALIDATE)
			unexpected_error = true;
		break;
	default:
		unexpected_error = true;
		break;
	}
	if (unexpected_error)
		DEBUGD(&nb_dbg_cbs_config,
		       "northbound callback: unexpected return value: %s",
		       nb_err_name(ret));

	return ret;
}

static int nb_callback_modify(struct nb_context *context,
			      const struct nb_node *nb_node,
			      enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource, char *errmsg,
			      size_t errmsg_len)
{
	struct nb_cb_modify_args args = {};
	bool unexpected_error = false;
	int ret;

<<<<<<< HEAD
	assert(!CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS));

	nb_log_config_callback(event, NB_OP_MODIFY, dnode);
=======
	assert(!CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS));

	nb_log_config_callback(event, NB_CB_MODIFY, dnode);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	args.context = context;
	args.event = event;
	args.dnode = dnode;
	args.resource = resource;
	args.errmsg = errmsg;
	args.errmsg_len = errmsg_len;
	ret = nb_node->cbs.modify(&args);

	/* Detect and log unexpected errors. */
	switch (ret) {
	case NB_OK:
	case NB_ERR:
		break;
	case NB_ERR_VALIDATION:
		if (event != NB_EV_VALIDATE)
			unexpected_error = true;
		break;
	case NB_ERR_RESOURCE:
		if (event != NB_EV_PREPARE)
			unexpected_error = true;
		break;
	case NB_ERR_INCONSISTENCY:
		if (event == NB_EV_VALIDATE)
			unexpected_error = true;
		break;
	default:
		unexpected_error = true;
		break;
	}
	if (unexpected_error)
		DEBUGD(&nb_dbg_cbs_config,
		       "northbound callback: unexpected return value: %s",
		       nb_err_name(ret));

	return ret;
}

static int nb_callback_destroy(struct nb_context *context,
			       const struct nb_node *nb_node,
			       enum nb_event event,
			       const struct lyd_node *dnode, char *errmsg,
			       size_t errmsg_len)
{
	struct nb_cb_destroy_args args = {};
	bool unexpected_error = false;
	int ret;

<<<<<<< HEAD
	assert(!CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS));

	nb_log_config_callback(event, NB_OP_DESTROY, dnode);
=======
	assert(!CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS));

	nb_log_config_callback(event, NB_CB_DESTROY, dnode);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	args.context = context;
	args.event = event;
	args.dnode = dnode;
	args.errmsg = errmsg;
	args.errmsg_len = errmsg_len;
	ret = nb_node->cbs.destroy(&args);

	/* Detect and log unexpected errors. */
	switch (ret) {
	case NB_OK:
	case NB_ERR:
		break;
	case NB_ERR_VALIDATION:
		if (event != NB_EV_VALIDATE)
			unexpected_error = true;
		break;
	case NB_ERR_INCONSISTENCY:
		if (event == NB_EV_VALIDATE)
			unexpected_error = true;
		break;
	default:
		unexpected_error = true;
		break;
	}
	if (unexpected_error)
		DEBUGD(&nb_dbg_cbs_config,
		       "northbound callback: unexpected return value: %s",
		       nb_err_name(ret));

	return ret;
}

static int nb_callback_move(struct nb_context *context,
			    const struct nb_node *nb_node, enum nb_event event,
			    const struct lyd_node *dnode, char *errmsg,
			    size_t errmsg_len)
{
	struct nb_cb_move_args args = {};
	bool unexpected_error = false;
	int ret;

<<<<<<< HEAD
	assert(!CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS));

	nb_log_config_callback(event, NB_OP_MOVE, dnode);
=======
	assert(!CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS));

	nb_log_config_callback(event, NB_CB_MOVE, dnode);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	args.context = context;
	args.event = event;
	args.dnode = dnode;
	args.errmsg = errmsg;
	args.errmsg_len = errmsg_len;
	ret = nb_node->cbs.move(&args);

	/* Detect and log unexpected errors. */
	switch (ret) {
	case NB_OK:
	case NB_ERR:
		break;
	case NB_ERR_VALIDATION:
		if (event != NB_EV_VALIDATE)
			unexpected_error = true;
		break;
	case NB_ERR_INCONSISTENCY:
		if (event == NB_EV_VALIDATE)
			unexpected_error = true;
		break;
	default:
		unexpected_error = true;
		break;
	}
	if (unexpected_error)
		DEBUGD(&nb_dbg_cbs_config,
		       "northbound callback: unexpected return value: %s",
		       nb_err_name(ret));

	return ret;
}

static int nb_callback_pre_validate(struct nb_context *context,
				    const struct nb_node *nb_node,
				    const struct lyd_node *dnode, char *errmsg,
				    size_t errmsg_len)
{
	struct nb_cb_pre_validate_args args = {};
	bool unexpected_error = false;
	int ret;

<<<<<<< HEAD
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
		return 0;

	nb_log_config_callback(NB_EV_VALIDATE, NB_OP_PRE_VALIDATE, dnode);
=======
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
		return 0;

	nb_log_config_callback(NB_EV_VALIDATE, NB_CB_PRE_VALIDATE, dnode);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	args.dnode = dnode;
	args.errmsg = errmsg;
	args.errmsg_len = errmsg_len;
	ret = nb_node->cbs.pre_validate(&args);

	/* Detect and log unexpected errors. */
	switch (ret) {
	case NB_OK:
	case NB_ERR_VALIDATION:
		break;
	default:
		unexpected_error = true;
		break;
	}
	if (unexpected_error)
		DEBUGD(&nb_dbg_cbs_config,
		       "northbound callback: unexpected return value: %s",
		       nb_err_name(ret));

	return ret;
}

static void nb_callback_apply_finish(struct nb_context *context,
				     const struct nb_node *nb_node,
				     const struct lyd_node *dnode, char *errmsg,
				     size_t errmsg_len)
{
	struct nb_cb_apply_finish_args args = {};

<<<<<<< HEAD
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
		return;

	nb_log_config_callback(NB_EV_APPLY, NB_OP_APPLY_FINISH, dnode);
=======
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
		return;

	nb_log_config_callback(NB_EV_APPLY, NB_CB_APPLY_FINISH, dnode);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	args.context = context;
	args.dnode = dnode;
	args.errmsg = errmsg;
	args.errmsg_len = errmsg_len;
	nb_node->cbs.apply_finish(&args);
}

struct yang_data *nb_callback_get_elem(const struct nb_node *nb_node,
				       const char *xpath,
				       const void *list_entry)
{
	struct nb_cb_get_elem_args args = {};

<<<<<<< HEAD
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
=======
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return NULL;

	DEBUGD(&nb_dbg_cbs_state,
	       "northbound callback (get_elem): xpath [%s] list_entry [%p]",
	       xpath, list_entry);

	args.xpath = xpath;
	args.list_entry = list_entry;
	return nb_node->cbs.get_elem(&args);
}

const void *nb_callback_get_next(const struct nb_node *nb_node,
				 const void *parent_list_entry,
				 const void *list_entry)
{
	struct nb_cb_get_next_args args = {};

<<<<<<< HEAD
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
=======
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return NULL;

	DEBUGD(&nb_dbg_cbs_state,
	       "northbound callback (get_next): node [%s] parent_list_entry [%p] list_entry [%p]",
	       nb_node->xpath, parent_list_entry, list_entry);

	args.parent_list_entry = parent_list_entry;
	args.list_entry = list_entry;
	return nb_node->cbs.get_next(&args);
}

int nb_callback_get_keys(const struct nb_node *nb_node, const void *list_entry,
			 struct yang_list_keys *keys)
{
	struct nb_cb_get_keys_args args = {};

<<<<<<< HEAD
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
=======
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return 0;

	DEBUGD(&nb_dbg_cbs_state,
	       "northbound callback (get_keys): node [%s] list_entry [%p]",
	       nb_node->xpath, list_entry);

	args.list_entry = list_entry;
	args.keys = keys;
	return nb_node->cbs.get_keys(&args);
}

const void *nb_callback_lookup_entry(const struct nb_node *nb_node,
				     const void *parent_list_entry,
				     const struct yang_list_keys *keys)
{
	struct nb_cb_lookup_entry_args args = {};

<<<<<<< HEAD
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
=======
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return NULL;

	DEBUGD(&nb_dbg_cbs_state,
	       "northbound callback (lookup_entry): node [%s] parent_list_entry [%p]",
	       nb_node->xpath, parent_list_entry);

	args.parent_list_entry = parent_list_entry;
	args.keys = keys;
	return nb_node->cbs.lookup_entry(&args);
}

<<<<<<< HEAD
int nb_callback_rpc(const struct nb_node *nb_node, const char *xpath,
		    const struct list *input, struct list *output, char *errmsg,
		    size_t errmsg_len)
{
	struct nb_cb_rpc_args args = {};

	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
		return 0;

=======
const void *nb_callback_lookup_node_entry(struct lyd_node *node,
					  const void *parent_list_entry)
{
	struct yang_list_keys keys;
	struct nb_cb_lookup_entry_args args = {};
	const struct nb_node *nb_node = node->schema->priv;

	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
		return NULL;

	if (yang_get_node_keys(node, &keys)) {
		flog_warn(EC_LIB_LIBYANG,
			  "%s: can't get keys for lookup from existing data node %s",
			  __func__, node->schema->name);
		return NULL;
	}

	DEBUGD(&nb_dbg_cbs_state,
	       "northbound callback (lookup_node_entry): node [%s] parent_list_entry [%p]",
	       nb_node->xpath, parent_list_entry);

	args.parent_list_entry = parent_list_entry;
	args.keys = &keys;
	return nb_node->cbs.lookup_entry(&args);
}

const void *nb_callback_lookup_next(const struct nb_node *nb_node,
				    const void *parent_list_entry,
				    const struct yang_list_keys *keys)
{
	struct nb_cb_lookup_entry_args args = {};

	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
		return NULL;

	DEBUGD(&nb_dbg_cbs_state,
	       "northbound callback (lookup_entry): node [%s] parent_list_entry [%p]",
	       nb_node->xpath, parent_list_entry);

	args.parent_list_entry = parent_list_entry;
	args.keys = keys;
	return nb_node->cbs.lookup_next(&args);
}

int nb_callback_rpc(const struct nb_node *nb_node, const char *xpath,
		    const struct lyd_node *input, struct lyd_node *output,
		    char *errmsg, size_t errmsg_len)
{
	struct nb_cb_rpc_args args = {};

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	DEBUGD(&nb_dbg_cbs_rpc, "northbound RPC: %s", xpath);

	args.xpath = xpath;
	args.input = input;
	args.output = output;
	args.errmsg = errmsg;
	args.errmsg_len = errmsg_len;
	return nb_node->cbs.rpc(&args);
}

<<<<<<< HEAD
=======
void nb_callback_notify(const struct nb_node *nb_node, const char *xpath,
			struct lyd_node *dnode)
{
	struct nb_cb_notify_args args = {};

	DEBUGD(&nb_dbg_cbs_notify, "northbound notify: %s", xpath);

	args.xpath = xpath;
	args.dnode = dnode;
	nb_node->cbs.notify(&args);
}

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
/*
 * Call the northbound configuration callback associated to a given
 * configuration change.
 */
static int nb_callback_configuration(struct nb_context *context,
				     const enum nb_event event,
				     struct nb_config_change *change,
				     char *errmsg, size_t errmsg_len)
{
<<<<<<< HEAD
	enum nb_operation operation = change->cb.operation;
=======
	enum nb_cb_operation operation = change->cb.operation;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	char xpath[XPATH_MAXLEN];
	const struct nb_node *nb_node = change->cb.nb_node;
	const struct lyd_node *dnode = change->cb.dnode;
	union nb_resource *resource;
	int ret = NB_ERR;

<<<<<<< HEAD
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CBS))
=======
	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_IGNORE_CFG_CBS))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return NB_OK;

	if (event == NB_EV_VALIDATE)
		resource = NULL;
	else
		resource = &change->resource;

	switch (operation) {
<<<<<<< HEAD
	case NB_OP_CREATE:
		ret = nb_callback_create(context, nb_node, event, dnode,
					 resource, errmsg, errmsg_len);
		break;
	case NB_OP_MODIFY:
		ret = nb_callback_modify(context, nb_node, event, dnode,
					 resource, errmsg, errmsg_len);
		break;
	case NB_OP_DESTROY:
		ret = nb_callback_destroy(context, nb_node, event, dnode,
					  errmsg, errmsg_len);
		break;
	case NB_OP_MOVE:
		ret = nb_callback_move(context, nb_node, event, dnode, errmsg,
				       errmsg_len);
		break;
	case NB_OP_PRE_VALIDATE:
	case NB_OP_APPLY_FINISH:
	case NB_OP_GET_ELEM:
	case NB_OP_GET_NEXT:
	case NB_OP_GET_KEYS:
	case NB_OP_LOOKUP_ENTRY:
	case NB_OP_RPC:
=======
	case NB_CB_CREATE:
		ret = nb_callback_create(context, nb_node, event, dnode,
					 resource, errmsg, errmsg_len);
		break;
	case NB_CB_MODIFY:
		ret = nb_callback_modify(context, nb_node, event, dnode,
					 resource, errmsg, errmsg_len);
		break;
	case NB_CB_DESTROY:
		ret = nb_callback_destroy(context, nb_node, event, dnode,
					  errmsg, errmsg_len);
		break;
	case NB_CB_MOVE:
		ret = nb_callback_move(context, nb_node, event, dnode, errmsg,
				       errmsg_len);
		break;
	case NB_CB_PRE_VALIDATE:
	case NB_CB_APPLY_FINISH:
	case NB_CB_GET_ELEM:
	case NB_CB_GET_NEXT:
	case NB_CB_GET_KEYS:
	case NB_CB_LOOKUP_ENTRY:
	case NB_CB_RPC:
	case NB_CB_NOTIFY:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		yang_dnode_get_path(dnode, xpath, sizeof(xpath));
		flog_err(EC_LIB_DEVELOPMENT,
			 "%s: unknown operation (%u) [xpath %s]", __func__,
			 operation, xpath);
		exit(1);
	}

	if (ret != NB_OK) {
		yang_dnode_get_path(dnode, xpath, sizeof(xpath));

		switch (event) {
		case NB_EV_VALIDATE:
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "error processing configuration change: error [%s] event [%s] operation [%s] xpath [%s]%s%s",
				  nb_err_name(ret), nb_event_name(event),
<<<<<<< HEAD
				  nb_operation_name(operation), xpath,
=======
				  nb_cb_operation_name(operation), xpath,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
				  errmsg[0] ? " message: " : "", errmsg);
			break;
		case NB_EV_PREPARE:
			flog_warn(EC_LIB_NB_CB_CONFIG_PREPARE,
				  "error processing configuration change: error [%s] event [%s] operation [%s] xpath [%s]%s%s",
				  nb_err_name(ret), nb_event_name(event),
<<<<<<< HEAD
				  nb_operation_name(operation), xpath,
=======
				  nb_cb_operation_name(operation), xpath,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
				  errmsg[0] ? " message: " : "", errmsg);
			break;
		case NB_EV_ABORT:
			flog_warn(EC_LIB_NB_CB_CONFIG_ABORT,
				  "error processing configuration change: error [%s] event [%s] operation [%s] xpath [%s]%s%s",
				  nb_err_name(ret), nb_event_name(event),
<<<<<<< HEAD
				  nb_operation_name(operation), xpath,
=======
				  nb_cb_operation_name(operation), xpath,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
				  errmsg[0] ? " message: " : "", errmsg);
			break;
		case NB_EV_APPLY:
			flog_err(EC_LIB_NB_CB_CONFIG_APPLY,
				 "error processing configuration change: error [%s] event [%s] operation [%s] xpath [%s]%s%s",
				 nb_err_name(ret), nb_event_name(event),
<<<<<<< HEAD
				 nb_operation_name(operation), xpath,
=======
				 nb_cb_operation_name(operation), xpath,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
				 errmsg[0] ? " message: " : "", errmsg);
			break;
		default:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown event (%u) [xpath %s]", __func__,
				 event, xpath);
			exit(1);
		}
	}

	return ret;
}

static struct nb_transaction *
nb_transaction_new(struct nb_context context, struct nb_config *config,
		   struct nb_config_cbs *changes, const char *comment,
		   char *errmsg, size_t errmsg_len)
{
	struct nb_transaction *transaction;

	if (nb_running_lock_check(context.client, context.user)) {
		strlcpy(errmsg,
			"running configuration is locked by another client",
			errmsg_len);
		return NULL;
	}

	if (transaction_in_progress) {
		strlcpy(errmsg,
			"there's already another transaction in progress",
			errmsg_len);
		return NULL;
	}
	transaction_in_progress = true;

	transaction = XCALLOC(MTYPE_TMP, sizeof(*transaction));
	transaction->context = context;
	if (comment)
		strlcpy(transaction->comment, comment,
			sizeof(transaction->comment));
	transaction->config = config;
	transaction->changes = *changes;

	return transaction;
}

static void nb_transaction_free(struct nb_transaction *transaction)
{
	nb_config_diff_del_changes(&transaction->changes);
	XFREE(MTYPE_TMP, transaction);
	transaction_in_progress = false;
}

/* Process all configuration changes associated to a transaction. */
static int nb_transaction_process(enum nb_event event,
				  struct nb_transaction *transaction,
				  char *errmsg, size_t errmsg_len)
{
	struct nb_config_cb *cb;

	RB_FOREACH (cb, nb_config_cbs, &transaction->changes) {
		struct nb_config_change *change = (struct nb_config_change *)cb;
		int ret;

		/*
		 * Only try to release resources that were allocated
		 * successfully.
		 */
		if (event == NB_EV_ABORT && !change->prepare_ok)
			break;

		/* Call the appropriate callback. */
		ret = nb_callback_configuration(&transaction->context, event,
						change, errmsg, errmsg_len);
		switch (event) {
		case NB_EV_PREPARE:
			if (ret != NB_OK)
				return ret;
			change->prepare_ok = true;
			break;
		case NB_EV_ABORT:
		case NB_EV_APPLY:
			/*
			 * At this point it's not possible to reject the
			 * transaction anymore, so any failure here can lead to
			 * inconsistencies and should be treated as a bug.
			 * Operations prone to errors, like validations and
			 * resource allocations, should be performed during the
			 * 'prepare' phase.
			 */
			break;
		case NB_EV_VALIDATE:
			break;
		}
	}

	return NB_OK;
}

static struct nb_config_cb *
nb_apply_finish_cb_new(struct nb_config_cbs *cbs, const struct nb_node *nb_node,
		       const struct lyd_node *dnode)
{
	struct nb_config_cb *cb;

	cb = XCALLOC(MTYPE_TMP, sizeof(*cb));
<<<<<<< HEAD
=======
	cb->operation = NB_CB_APPLY_FINISH;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	cb->nb_node = nb_node;
	cb->dnode = dnode;
	RB_INSERT(nb_config_cbs, cbs, cb);

	return cb;
}

static struct nb_config_cb *
nb_apply_finish_cb_find(struct nb_config_cbs *cbs,
			const struct nb_node *nb_node,
			const struct lyd_node *dnode)
{
	struct nb_config_cb s;

<<<<<<< HEAD
=======
	s.operation = NB_CB_APPLY_FINISH;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	s.seq = 0;
	s.nb_node = nb_node;
	s.dnode = dnode;
	return RB_FIND(nb_config_cbs, cbs, &s);
}

/* Call the 'apply_finish' callbacks. */
static void nb_transaction_apply_finish(struct nb_transaction *transaction,
					char *errmsg, size_t errmsg_len)
{
	struct nb_config_cbs cbs;
	struct nb_config_cb *cb;

	/* Initialize tree of 'apply_finish' callbacks. */
	RB_INIT(nb_config_cbs, &cbs);

	/* Identify the 'apply_finish' callbacks that need to be called. */
	RB_FOREACH (cb, nb_config_cbs, &transaction->changes) {
		struct nb_config_change *change = (struct nb_config_change *)cb;
		const struct lyd_node *dnode = change->cb.dnode;

		/*
		 * Iterate up to the root of the data tree. When a node is being
		 * deleted, skip its 'apply_finish' callback if one is defined
		 * (the 'apply_finish' callbacks from the node ancestors should
		 * be called though).
		 */
<<<<<<< HEAD
		if (change->cb.operation == NB_OP_DESTROY) {
=======
		if (change->cb.operation == NB_CB_DESTROY) {
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			char xpath[XPATH_MAXLEN];

			dnode = lyd_parent(dnode);
			if (!dnode)
<<<<<<< HEAD
				break;
=======
				continue;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

			/*
			 * The dnode from 'delete' callbacks point to elements
			 * from the running configuration. Use yang_dnode_get()
			 * to get the corresponding dnode from the candidate
			 * configuration that is being committed.
			 */
			yang_dnode_get_path(dnode, xpath, sizeof(xpath));
			dnode = yang_dnode_get(transaction->config->dnode,
					       xpath);
		}
		while (dnode) {
			struct nb_node *nb_node;

			nb_node = dnode->schema->priv;
			if (!nb_node || !nb_node->cbs.apply_finish)
				goto next;

			/*
			 * Don't call the callback more than once for the same
			 * data node.
			 */
			if (nb_apply_finish_cb_find(&cbs, nb_node, dnode))
				goto next;

			nb_apply_finish_cb_new(&cbs, nb_node, dnode);

		next:
			dnode = lyd_parent(dnode);
		}
	}

	/* Call the 'apply_finish' callbacks, sorted by their priorities. */
	RB_FOREACH (cb, nb_config_cbs, &cbs)
		nb_callback_apply_finish(&transaction->context, cb->nb_node,
					 cb->dnode, errmsg, errmsg_len);

	/* Release memory. */
	while (!RB_EMPTY(nb_config_cbs, &cbs)) {
		cb = RB_ROOT(nb_config_cbs, &cbs);
		RB_REMOVE(nb_config_cbs, &cbs, cb);
		XFREE(MTYPE_TMP, cb);
	}
}

<<<<<<< HEAD
static int nb_oper_data_iter_children(const struct lysc_node *snode,
				      const char *xpath, const void *list_entry,
				      const struct yang_list_keys *list_keys,
				      struct yang_translator *translator,
				      bool first, uint32_t flags,
				      nb_oper_data_cb cb, void *arg)
{
	const struct lysc_node *child;

	LY_LIST_FOR (lysc_node_child(snode), child) {
		int ret;

		ret = nb_oper_data_iter_node(child, xpath, list_entry,
					     list_keys, translator, false,
					     flags, cb, arg);
		if (ret != NB_OK)
			return ret;
	}

	return NB_OK;
}

static int nb_oper_data_iter_leaf(const struct nb_node *nb_node,
				  const char *xpath, const void *list_entry,
				  const struct yang_list_keys *list_keys,
				  struct yang_translator *translator,
				  uint32_t flags, nb_oper_data_cb cb, void *arg)
{
	struct yang_data *data;

	if (CHECK_FLAG(nb_node->snode->flags, LYS_CONFIG_W))
		return NB_OK;

	/* Ignore list keys. */
	if (lysc_is_key(nb_node->snode))
		return NB_OK;

	data = nb_callback_get_elem(nb_node, xpath, list_entry);
	if (data == NULL)
		/* Leaf of type "empty" is not present. */
		return NB_OK;

	return (*cb)(nb_node->snode, translator, data, arg);
}

static int nb_oper_data_iter_container(const struct nb_node *nb_node,
				       const char *xpath,
				       const void *list_entry,
				       const struct yang_list_keys *list_keys,
				       struct yang_translator *translator,
				       uint32_t flags, nb_oper_data_cb cb,
				       void *arg)
{
	const struct lysc_node *snode = nb_node->snode;

	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_CONFIG_ONLY))
		return NB_OK;

	/* Read-only presence containers. */
	if (nb_node->cbs.get_elem) {
		struct yang_data *data;
		int ret;

		data = nb_callback_get_elem(nb_node, xpath, list_entry);
		if (data == NULL)
			/* Presence container is not present. */
			return NB_OK;

		ret = (*cb)(snode, translator, data, arg);
		if (ret != NB_OK)
			return ret;
	}

	/* Read-write presence containers. */
	if (CHECK_FLAG(snode->flags, LYS_CONFIG_W)) {
		struct lysc_node_container *scontainer;

		scontainer = (struct lysc_node_container *)snode;
		if (CHECK_FLAG(scontainer->flags, LYS_PRESENCE)
		    && !yang_dnode_get(running_config->dnode, xpath))
			return NB_OK;
	}

	/* Iterate over the child nodes. */
	return nb_oper_data_iter_children(snode, xpath, list_entry, list_keys,
					  translator, false, flags, cb, arg);
}

static int
nb_oper_data_iter_leaflist(const struct nb_node *nb_node, const char *xpath,
			   const void *parent_list_entry,
			   const struct yang_list_keys *parent_list_keys,
			   struct yang_translator *translator, uint32_t flags,
			   nb_oper_data_cb cb, void *arg)
{
	const void *list_entry = NULL;

	if (CHECK_FLAG(nb_node->snode->flags, LYS_CONFIG_W))
		return NB_OK;

	do {
		struct yang_data *data;
		int ret;

		list_entry = nb_callback_get_next(nb_node, parent_list_entry,
						  list_entry);
		if (!list_entry)
			/* End of the list. */
			break;

		data = nb_callback_get_elem(nb_node, xpath, list_entry);
		if (data == NULL)
			continue;

		ret = (*cb)(nb_node->snode, translator, data, arg);
		if (ret != NB_OK)
			return ret;
	} while (list_entry);

	return NB_OK;
}

static int nb_oper_data_iter_list(const struct nb_node *nb_node,
				  const char *xpath_list,
				  const void *parent_list_entry,
				  const struct yang_list_keys *parent_list_keys,
				  struct yang_translator *translator,
				  uint32_t flags, nb_oper_data_cb cb, void *arg)
{
	const struct lysc_node *snode = nb_node->snode;
	const void *list_entry = NULL;
	uint32_t position = 1;

	if (CHECK_FLAG(nb_node->flags, F_NB_NODE_CONFIG_ONLY))
		return NB_OK;

	/* Iterate over all list entries. */
	do {
		const struct lysc_node_leaf *skey;
		struct yang_list_keys list_keys = {};
		char xpath[XPATH_MAXLEN * 2];
		int ret;

		/* Obtain list entry. */
		list_entry = nb_callback_get_next(nb_node, parent_list_entry,
						  list_entry);
		if (!list_entry)
			/* End of the list. */
			break;

		if (!CHECK_FLAG(nb_node->flags, F_NB_NODE_KEYLESS_LIST)) {
			/* Obtain the list entry keys. */
			if (nb_callback_get_keys(nb_node, list_entry,
						 &list_keys)
			    != NB_OK) {
				flog_warn(EC_LIB_NB_CB_STATE,
					  "%s: failed to get list keys",
					  __func__);
				return NB_ERR;
			}

			/* Build XPath of the list entry. */
			strlcpy(xpath, xpath_list, sizeof(xpath));
			unsigned int i = 0;
			LY_FOR_KEYS (snode, skey) {
				assert(i < list_keys.num);
				snprintf(xpath + strlen(xpath),
					 sizeof(xpath) - strlen(xpath),
					 "[%s='%s']", skey->name,
					 list_keys.key[i]);
				i++;
			}
			assert(i == list_keys.num);
		} else {
			/*
			 * Keyless list - build XPath using a positional index.
			 */
			snprintf(xpath, sizeof(xpath), "%s[%u]", xpath_list,
				 position);
			position++;
		}

		/* Iterate over the child nodes. */
		ret = nb_oper_data_iter_children(
			nb_node->snode, xpath, list_entry, &list_keys,
			translator, false, flags, cb, arg);
		if (ret != NB_OK)
			return ret;
	} while (list_entry);

	return NB_OK;
}

static int nb_oper_data_iter_node(const struct lysc_node *snode,
				  const char *xpath_parent,
				  const void *list_entry,
				  const struct yang_list_keys *list_keys,
				  struct yang_translator *translator,
				  bool first, uint32_t flags,
				  nb_oper_data_cb cb, void *arg)
{
	struct nb_node *nb_node;
	char xpath[XPATH_MAXLEN];
	int ret = NB_OK;

	if (!first && CHECK_FLAG(flags, NB_OPER_DATA_ITER_NORECURSE)
	    && CHECK_FLAG(snode->nodetype, LYS_CONTAINER | LYS_LIST))
		return NB_OK;

	/* Update XPath. */
	strlcpy(xpath, xpath_parent, sizeof(xpath));
	if (!first && snode->nodetype != LYS_USES) {
		struct lysc_node *parent;

		/* Get the real parent. */
		parent = snode->parent;

		/*
		 * When necessary, include the namespace of the augmenting
		 * module.
		 */
		if (parent && parent->module != snode->module)
			snprintf(xpath + strlen(xpath),
				 sizeof(xpath) - strlen(xpath), "/%s:%s",
				 snode->module->name, snode->name);
		else
			snprintf(xpath + strlen(xpath),
				 sizeof(xpath) - strlen(xpath), "/%s",
				 snode->name);
	}

	nb_node = snode->priv;
	switch (snode->nodetype) {
	case LYS_CONTAINER:
		ret = nb_oper_data_iter_container(nb_node, xpath, list_entry,
						  list_keys, translator, flags,
						  cb, arg);
		break;
	case LYS_LEAF:
		ret = nb_oper_data_iter_leaf(nb_node, xpath, list_entry,
					     list_keys, translator, flags, cb,
					     arg);
		break;
	case LYS_LEAFLIST:
		ret = nb_oper_data_iter_leaflist(nb_node, xpath, list_entry,
						 list_keys, translator, flags,
						 cb, arg);
		break;
	case LYS_LIST:
		ret = nb_oper_data_iter_list(nb_node, xpath, list_entry,
					     list_keys, translator, flags, cb,
					     arg);
		break;
	case LYS_USES:
		ret = nb_oper_data_iter_children(snode, xpath, list_entry,
						 list_keys, translator, false,
						 flags, cb, arg);
		break;
	default:
		break;
	}

	return ret;
}

int nb_oper_data_iterate(const char *xpath, struct yang_translator *translator,
			 uint32_t flags, nb_oper_data_cb cb, void *arg)
{
	struct nb_node *nb_node;
	const void *list_entry = NULL;
	struct yang_list_keys list_keys;
	struct list *list_dnodes;
	struct lyd_node *dnode, *dn;
	struct listnode *ln;
	int ret;

	nb_node = nb_node_find(xpath);
	if (!nb_node) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, xpath);
		return NB_ERR;
	}

	/* For now this function works only with containers and lists. */
	if (!CHECK_FLAG(nb_node->snode->nodetype, LYS_CONTAINER | LYS_LIST)) {
		flog_warn(
			EC_LIB_NB_OPERATIONAL_DATA,
			"%s: can't iterate over YANG leaf or leaf-list [xpath %s]",
			__func__, xpath);
		return NB_ERR;
	}

	/*
	 * Create a data tree from the XPath so that we can parse the keys of
	 * all YANG lists (if any).
	 */

	LY_ERR err = lyd_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, 0,
				   LYD_NEW_PATH_UPDATE, NULL, &dnode);
	if (err || !dnode) {
		const char *errmsg =
			err ? ly_errmsg(ly_native_ctx) : "node not found";
		flog_warn(EC_LIB_LIBYANG, "%s: lyd_new_path() failed %s",
			  __func__, errmsg);
		return NB_ERR;
	}

	/*
	 * Create a linked list to sort the data nodes starting from the root.
	 */
	list_dnodes = list_new();
	for (dn = dnode; dn; dn = lyd_parent(dn)) {
		if (dn->schema->nodetype != LYS_LIST || !lyd_child(dn))
			continue;
		listnode_add_head(list_dnodes, dn);
	}
	/*
	 * Use the northbound callbacks to find list entry pointer corresponding
	 * to the given XPath.
	 */
	for (ALL_LIST_ELEMENTS_RO(list_dnodes, ln, dn)) {
		struct lyd_node *child;
		struct nb_node *nn;
		unsigned int n = 0;

		/* Obtain the list entry keys. */
		memset(&list_keys, 0, sizeof(list_keys));
		LY_LIST_FOR (lyd_child(dn), child) {
			if (!lysc_is_key(child->schema))
				break;
			strlcpy(list_keys.key[n],
				yang_dnode_get_string(child, NULL),
				sizeof(list_keys.key[n]));
			n++;
		}
		list_keys.num = n;
		if (list_keys.num != yang_snode_num_keys(dn->schema)) {
			list_delete(&list_dnodes);
			yang_dnode_free(dnode);
			return NB_ERR_NOT_FOUND;
		}

		/* Find the list entry pointer. */
		nn = dn->schema->priv;
		if (!nn->cbs.lookup_entry) {
			flog_warn(
				EC_LIB_NB_OPERATIONAL_DATA,
				"%s: data path doesn't support iteration over operational data: %s",
				__func__, xpath);
			list_delete(&list_dnodes);
			yang_dnode_free(dnode);
			return NB_ERR;
		}

		list_entry =
			nb_callback_lookup_entry(nn, list_entry, &list_keys);
		if (list_entry == NULL) {
			list_delete(&list_dnodes);
			yang_dnode_free(dnode);
			return NB_ERR_NOT_FOUND;
		}
	}

	/* If a list entry was given, iterate over that list entry only. */
	if (dnode->schema->nodetype == LYS_LIST && lyd_child(dnode))
		ret = nb_oper_data_iter_children(
			nb_node->snode, xpath, list_entry, &list_keys,
			translator, true, flags, cb, arg);
	else
		ret = nb_oper_data_iter_node(nb_node->snode, xpath, list_entry,
					     &list_keys, translator, true,
					     flags, cb, arg);

	list_delete(&list_dnodes);
	yang_dnode_free(dnode);

	return ret;
}

bool nb_operation_is_valid(enum nb_operation operation,
			   const struct lysc_node *snode)
=======
bool nb_cb_operation_is_valid(enum nb_cb_operation operation,
			      const struct lysc_node *snode)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
{
	struct nb_node *nb_node = snode->priv;
	struct lysc_node_container *scontainer;
	struct lysc_node_leaf *sleaf;

	switch (operation) {
<<<<<<< HEAD
	case NB_OP_CREATE:
=======
	case NB_CB_CREATE:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		if (!CHECK_FLAG(snode->flags, LYS_CONFIG_W))
			return false;

		switch (snode->nodetype) {
		case LYS_LEAF:
			sleaf = (struct lysc_node_leaf *)snode;
			if (sleaf->type->basetype != LY_TYPE_EMPTY)
				return false;
			break;
		case LYS_CONTAINER:
<<<<<<< HEAD
=======
			if (snode->parent && snode->parent->nodetype == LYS_CASE)
				return true;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			scontainer = (struct lysc_node_container *)snode;
			if (!CHECK_FLAG(scontainer->flags, LYS_PRESENCE))
				return false;
			break;
		case LYS_LIST:
		case LYS_LEAFLIST:
			break;
		default:
			return false;
		}
		return true;
<<<<<<< HEAD
	case NB_OP_MODIFY:
=======
	case NB_CB_MODIFY:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		if (!CHECK_FLAG(snode->flags, LYS_CONFIG_W))
			return false;

		switch (snode->nodetype) {
		case LYS_LEAF:
			sleaf = (struct lysc_node_leaf *)snode;
			if (sleaf->type->basetype == LY_TYPE_EMPTY)
				return false;

			/* List keys can't be modified. */
			if (lysc_is_key(sleaf))
				return false;
			break;
		default:
			return false;
		}
		return true;
<<<<<<< HEAD
	case NB_OP_DESTROY:
=======
	case NB_CB_DESTROY:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		if (!CHECK_FLAG(snode->flags, LYS_CONFIG_W))
			return false;

		switch (snode->nodetype) {
		case LYS_LEAF:
			sleaf = (struct lysc_node_leaf *)snode;

			/* List keys can't be deleted. */
			if (lysc_is_key(sleaf))
				return false;

			/*
			 * Only optional leafs can be deleted, or leafs whose
			 * parent is a case statement.
			 */
			if (snode->parent->nodetype == LYS_CASE)
				return true;
			if (sleaf->when)
				return true;
			if (CHECK_FLAG(sleaf->flags, LYS_MAND_TRUE)
			    || sleaf->dflt)
				return false;
			break;
		case LYS_CONTAINER:
<<<<<<< HEAD
=======
			if (snode->parent && snode->parent->nodetype == LYS_CASE)
				return true;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			scontainer = (struct lysc_node_container *)snode;
			if (!CHECK_FLAG(scontainer->flags, LYS_PRESENCE))
				return false;
			break;
		case LYS_LIST:
		case LYS_LEAFLIST:
			break;
		default:
			return false;
		}
		return true;
<<<<<<< HEAD
	case NB_OP_MOVE:
=======
	case NB_CB_MOVE:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		if (!CHECK_FLAG(snode->flags, LYS_CONFIG_W))
			return false;

		switch (snode->nodetype) {
		case LYS_LIST:
		case LYS_LEAFLIST:
			if (!CHECK_FLAG(snode->flags, LYS_ORDBY_USER))
				return false;
			break;
		default:
			return false;
		}
		return true;
<<<<<<< HEAD
	case NB_OP_PRE_VALIDATE:
	case NB_OP_APPLY_FINISH:
		if (!CHECK_FLAG(snode->flags, LYS_CONFIG_W))
			return false;
		return true;
	case NB_OP_GET_ELEM:
=======
	case NB_CB_PRE_VALIDATE:
	case NB_CB_APPLY_FINISH:
		if (!CHECK_FLAG(snode->flags, LYS_CONFIG_W))
			return false;
		return true;
	case NB_CB_GET_ELEM:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		if (!CHECK_FLAG(snode->flags, LYS_CONFIG_R))
			return false;

		switch (snode->nodetype) {
		case LYS_LEAF:
		case LYS_LEAFLIST:
			break;
		case LYS_CONTAINER:
			scontainer = (struct lysc_node_container *)snode;
			if (!CHECK_FLAG(scontainer->flags, LYS_PRESENCE))
				return false;
			break;
		default:
			return false;
		}
		return true;
<<<<<<< HEAD
	case NB_OP_GET_NEXT:
=======
	case NB_CB_GET_NEXT:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		switch (snode->nodetype) {
		case LYS_LIST:
			if (CHECK_FLAG(nb_node->flags, F_NB_NODE_CONFIG_ONLY))
				return false;
			break;
		case LYS_LEAFLIST:
			if (CHECK_FLAG(snode->flags, LYS_CONFIG_W))
				return false;
			break;
		default:
			return false;
		}
		return true;
<<<<<<< HEAD
	case NB_OP_GET_KEYS:
	case NB_OP_LOOKUP_ENTRY:
=======
	case NB_CB_GET_KEYS:
	case NB_CB_LOOKUP_ENTRY:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		switch (snode->nodetype) {
		case LYS_LIST:
			if (CHECK_FLAG(nb_node->flags, F_NB_NODE_CONFIG_ONLY))
				return false;
			if (CHECK_FLAG(nb_node->flags, F_NB_NODE_KEYLESS_LIST))
				return false;
			break;
		default:
			return false;
		}
		return true;
<<<<<<< HEAD
	case NB_OP_RPC:
=======
	case NB_CB_RPC:
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		if (CHECK_FLAG(snode->flags, LYS_CONFIG_W | LYS_CONFIG_R))
			return false;

		switch (snode->nodetype) {
		case LYS_RPC:
		case LYS_ACTION:
			break;
		default:
			return false;
		}
		return true;
<<<<<<< HEAD
=======
	case NB_CB_NOTIFY:
		if (snode->nodetype != LYS_NOTIF)
			return false;
		return true;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	default:
		return false;
	}
}

DEFINE_HOOK(nb_notification_send, (const char *xpath, struct list *arguments),
	    (xpath, arguments));

int nb_notification_send(const char *xpath, struct list *arguments)
{
<<<<<<< HEAD
=======
	struct lyd_node *root = NULL;
	struct lyd_node *dnode;
	struct yang_data *data;
	struct listnode *ln;
	LY_ERR err;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	int ret;

	DEBUGD(&nb_dbg_notif, "northbound notification: %s", xpath);

<<<<<<< HEAD
	ret = hook_call(nb_notification_send, xpath, arguments);
=======
	/*
	 * Call old hook functions
	 */
	ret = hook_call(nb_notification_send, xpath, arguments);

	if (!hook_have_hooks(nb_notification_tree_send))
		goto done;
	/*
	 * Convert yang data arguments list to a libyang data tree for new hook
	 * functions.
	 */
	for (ALL_LIST_ELEMENTS_RO(arguments, ln, data)) {
		err = lyd_new_path(root, ly_native_ctx, data->xpath,
				   data->value, LYD_NEW_PATH_UPDATE, &dnode);
		if (err != LY_SUCCESS)
			goto lyerr;
		if (!root) {
			root = dnode;
			while (root->parent)
				root = lyd_parent(root);
		}
	}

	if (!root) {
		err = lyd_new_path(NULL, ly_native_ctx, xpath, "", 0, &root);
		if (err) {
lyerr:
			flog_err(EC_LIB_LIBYANG,
				 "%s: error creating notification data: %s",
				 __func__, ly_strerrcode(err));
			ret += 1;
			goto done;
		}
	}

	/*
	 * Call new hook functions
	 */
	ret += nb_notification_tree_send(xpath, root);

done:
	if (root)
		lyd_free_all(root);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	if (arguments)
		list_delete(&arguments);

	return ret;
}

<<<<<<< HEAD
=======
DEFINE_HOOK(nb_notification_tree_send,
	    (const char *xpath, const struct lyd_node *tree), (xpath, tree));

int nb_notification_tree_send(const char *xpath, const struct lyd_node *tree)
{
	int ret;

	assert(tree);

	DEBUGD(&nb_dbg_notif, "northbound tree notification: %s",
	       tree->schema->name);

	ret = hook_call(nb_notification_tree_send, xpath, tree);

	return ret;
}

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
/* Running configuration user pointers management. */
struct nb_config_entry {
	char xpath[XPATH_MAXLEN];
	void *entry;
};

static bool running_config_entry_cmp(const void *value1, const void *value2)
{
	const struct nb_config_entry *c1 = value1;
	const struct nb_config_entry *c2 = value2;

	return strmatch(c1->xpath, c2->xpath);
}

static unsigned int running_config_entry_key_make(const void *value)
{
	return string_hash_make(value);
}

static void *running_config_entry_alloc(void *p)
{
	struct nb_config_entry *new, *key = p;

	new = XCALLOC(MTYPE_NB_CONFIG_ENTRY, sizeof(*new));
	strlcpy(new->xpath, key->xpath, sizeof(new->xpath));

	return new;
}

static void running_config_entry_free(void *arg)
{
	XFREE(MTYPE_NB_CONFIG_ENTRY, arg);
}

void nb_running_set_entry(const struct lyd_node *dnode, void *entry)
{
	struct nb_config_entry *config, s;

	yang_dnode_get_path(dnode, s.xpath, sizeof(s.xpath));
	config = hash_get(running_config_entries, &s,
			  running_config_entry_alloc);
	config->entry = entry;
}

void nb_running_move_tree(const char *xpath_from, const char *xpath_to)
{
	struct nb_config_entry *entry;
	struct list *entries = hash_to_list(running_config_entries);
	struct listnode *ln;

	for (ALL_LIST_ELEMENTS_RO(entries, ln, entry)) {
		if (!frrstr_startswith(entry->xpath, xpath_from))
			continue;

		hash_release(running_config_entries, entry);

		char *newpath =
			frrstr_replace(entry->xpath, xpath_from, xpath_to);
		strlcpy(entry->xpath, newpath, sizeof(entry->xpath));
		XFREE(MTYPE_TMP, newpath);

		(void)hash_get(running_config_entries, entry,
			       hash_alloc_intern);
	}

	list_delete(&entries);
}

static void *nb_running_unset_entry_helper(const struct lyd_node *dnode)
{
	struct nb_config_entry *config, s;
	struct lyd_node *child;
	void *entry = NULL;

	yang_dnode_get_path(dnode, s.xpath, sizeof(s.xpath));
	config = hash_release(running_config_entries, &s);
	if (config) {
		entry = config->entry;
		running_config_entry_free(config);
	}

	/* Unset user pointers from the child nodes. */
	if (CHECK_FLAG(dnode->schema->nodetype, LYS_LIST | LYS_CONTAINER)) {
		LY_LIST_FOR (lyd_child(dnode), child) {
			(void)nb_running_unset_entry_helper(child);
		}
	}

	return entry;
}

void *nb_running_unset_entry(const struct lyd_node *dnode)
{
	void *entry;

	entry = nb_running_unset_entry_helper(dnode);
	assert(entry);

	return entry;
}

static void *nb_running_get_entry_worker(const struct lyd_node *dnode,
					 const char *xpath,
					 bool abort_if_not_found,
					 bool rec_search)
{
	const struct lyd_node *orig_dnode = dnode;
	char xpath_buf[XPATH_MAXLEN];
	bool rec_flag = true;

	assert(dnode || xpath);

	if (!dnode)
		dnode = yang_dnode_get(running_config->dnode, xpath);

	while (rec_flag && dnode) {
		struct nb_config_entry *config, s;

		yang_dnode_get_path(dnode, s.xpath, sizeof(s.xpath));
		config = hash_lookup(running_config_entries, &s);
		if (config)
			return config->entry;

		rec_flag = rec_search;

		dnode = lyd_parent(dnode);
	}

	if (!abort_if_not_found)
		return NULL;

	yang_dnode_get_path(orig_dnode, xpath_buf, sizeof(xpath_buf));
	flog_err(EC_LIB_YANG_DNODE_NOT_FOUND,
		 "%s: failed to find entry [xpath %s]", __func__, xpath_buf);
	zlog_backtrace(LOG_ERR);
	abort();
}

void *nb_running_get_entry(const struct lyd_node *dnode, const char *xpath,
			   bool abort_if_not_found)
{
	return nb_running_get_entry_worker(dnode, xpath, abort_if_not_found,
					   true);
}

void *nb_running_get_entry_non_rec(const struct lyd_node *dnode,
				   const char *xpath, bool abort_if_not_found)
{
	return nb_running_get_entry_worker(dnode, xpath, abort_if_not_found,
					   false);
}

/* Logging functions. */
const char *nb_event_name(enum nb_event event)
{
	switch (event) {
	case NB_EV_VALIDATE:
		return "validate";
	case NB_EV_PREPARE:
		return "prepare";
	case NB_EV_ABORT:
		return "abort";
	case NB_EV_APPLY:
		return "apply";
	}

	assert(!"Reached end of function we should never hit");
}

<<<<<<< HEAD
const char *nb_operation_name(enum nb_operation operation)
{
	switch (operation) {
	case NB_OP_CREATE:
		return "create";
	case NB_OP_MODIFY:
		return "modify";
	case NB_OP_DESTROY:
		return "destroy";
	case NB_OP_MOVE:
		return "move";
	case NB_OP_PRE_VALIDATE:
		return "pre_validate";
	case NB_OP_APPLY_FINISH:
		return "apply_finish";
	case NB_OP_GET_ELEM:
		return "get_elem";
	case NB_OP_GET_NEXT:
		return "get_next";
	case NB_OP_GET_KEYS:
		return "get_keys";
	case NB_OP_LOOKUP_ENTRY:
		return "lookup_entry";
	case NB_OP_RPC:
		return "rpc";
=======
const char *nb_cb_operation_name(enum nb_cb_operation operation)
{
	switch (operation) {
	case NB_CB_CREATE:
		return "create";
	case NB_CB_MODIFY:
		return "modify";
	case NB_CB_DESTROY:
		return "destroy";
	case NB_CB_MOVE:
		return "move";
	case NB_CB_PRE_VALIDATE:
		return "pre_validate";
	case NB_CB_APPLY_FINISH:
		return "apply_finish";
	case NB_CB_GET_ELEM:
		return "get_elem";
	case NB_CB_GET_NEXT:
		return "get_next";
	case NB_CB_GET_KEYS:
		return "get_keys";
	case NB_CB_LOOKUP_ENTRY:
		return "lookup_entry";
	case NB_CB_RPC:
		return "rpc";
	case NB_CB_NOTIFY:
		return "notify";
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	}

	assert(!"Reached end of function we should never hit");
}

const char *nb_err_name(enum nb_error error)
{
	switch (error) {
	case NB_OK:
		return "ok";
	case NB_ERR:
		return "generic error";
	case NB_ERR_NO_CHANGES:
		return "no changes";
	case NB_ERR_NOT_FOUND:
		return "element not found";
<<<<<<< HEAD
=======
	case NB_ERR_EXISTS:
		return "element already exists";
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	case NB_ERR_LOCKED:
		return "resource is locked";
	case NB_ERR_VALIDATION:
		return "validation";
	case NB_ERR_RESOURCE:
		return "failed to allocate resource";
	case NB_ERR_INCONSISTENCY:
		return "internal inconsistency";
<<<<<<< HEAD
=======
	case NB_YIELD:
		return "should yield";
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	}

	assert(!"Reached end of function we should never hit");
}

const char *nb_client_name(enum nb_client client)
{
	switch (client) {
	case NB_CLIENT_CLI:
		return "CLI";
<<<<<<< HEAD
	case NB_CLIENT_CONFD:
		return "ConfD";
=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	case NB_CLIENT_SYSREPO:
		return "Sysrepo";
	case NB_CLIENT_GRPC:
		return "gRPC";
	case NB_CLIENT_PCEP:
		return "Pcep";
	case NB_CLIENT_MGMTD_SERVER:
		return "MGMTD Server";
	case NB_CLIENT_MGMTD_BE:
		return "MGMT Backend";
	case NB_CLIENT_NONE:
		return "None";
	}

	assert(!"Reached end of function we should never hit");
}

static void nb_load_callbacks(const struct frr_yang_module_info *module)
{
<<<<<<< HEAD

	if (module->ignore_cbs)
		return;

=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	for (size_t i = 0; module->nodes[i].xpath; i++) {
		struct nb_node *nb_node;
		uint32_t priority;

		if (i > YANG_MODULE_MAX_NODES) {
			zlog_err(
				"%s: %s.yang has more than %u nodes. Please increase YANG_MODULE_MAX_NODES to fix this problem.",
				__func__, module->name, YANG_MODULE_MAX_NODES);
			exit(1);
		}

		nb_node = nb_node_find(module->nodes[i].xpath);
		if (!nb_node) {
			flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
				  "%s: unknown data path: %s", __func__,
				  module->nodes[i].xpath);
			continue;
		}

		nb_node->cbs = module->nodes[i].cbs;
		priority = module->nodes[i].priority;
		if (priority != 0)
			nb_node->priority = priority;
	}
}

void nb_validate_callbacks(void)
{
	unsigned int errors = 0;

	yang_snodes_iterate(NULL, nb_node_validate, 0, &errors);
	if (errors > 0) {
		flog_err(
			EC_LIB_NB_CBS_VALIDATION,
			"%s: failed to validate northbound callbacks: %u error(s)",
			__func__, errors);
		exit(1);
	}
}


void nb_init(struct event_loop *tm,
	     const struct frr_yang_module_info *const modules[],
<<<<<<< HEAD
	     size_t nmodules, bool db_enabled)
=======
	     size_t nmodules, bool db_enabled, bool load_library)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
{
	struct yang_module *loaded[nmodules], **loadedp = loaded;

	/*
	 * Currently using this explicit compile feature in libyang2 leads to
	 * incorrect behavior in FRR. The functionality suppresses the compiling
	 * of modules until they have all been loaded into the context. This
	 * avoids multiple recompiles of the same modules as they are
	 * imported/augmented etc.
	 * (Done as a #define to make coverity happy)
	 */
#define explicit_compile false

	nb_db_enabled = db_enabled;

<<<<<<< HEAD
	yang_init(true, explicit_compile);
=======
	yang_init(true, explicit_compile, load_library);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	/* Load YANG modules and their corresponding northbound callbacks. */
	for (size_t i = 0; i < nmodules; i++) {
		DEBUGD(&nb_dbg_events, "northbound: loading %s.yang",
		       modules[i]->name);
<<<<<<< HEAD
		*loadedp++ = yang_module_load(modules[i]->name);
=======
		*loadedp++ = yang_module_load(modules[i]->name,
					      modules[i]->features);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	}

	if (explicit_compile)
		yang_init_loading_complete();

	/* Initialize the compiled nodes with northbound data */
	for (size_t i = 0; i < nmodules; i++) {
		yang_snodes_iterate(loaded[i]->info, nb_node_new_cb, 0,
				    (void *)modules[i]);
		nb_load_callbacks(modules[i]);
	}

	/* Validate northbound callbacks. */
	nb_validate_callbacks();

	/* Create an empty running configuration. */
	running_config = nb_config_new(NULL);
	running_config_entries = hash_create(running_config_entry_key_make,
					     running_config_entry_cmp,
					     "Running Configuration Entries");
	pthread_mutex_init(&running_config_mgmt_lock.mtx, NULL);

	/* Initialize the northbound CLI. */
	nb_cli_init(tm);
<<<<<<< HEAD
=======

	/* Initialize oper-state */
	nb_oper_init(tm);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
}

void nb_terminate(void)
{
<<<<<<< HEAD
=======
	nb_oper_terminate();

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	/* Terminate the northbound CLI. */
	nb_cli_terminate();

	/* Delete all nb_node's from all YANG modules. */
	nb_nodes_delete();

	/* Delete the running configuration. */
	hash_clean_and_free(&running_config_entries, running_config_entry_free);
	nb_config_free(running_config);
	pthread_mutex_destroy(&running_config_mgmt_lock.mtx);
}
