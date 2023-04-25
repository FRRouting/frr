// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#ifndef _FRR_NORTHBOUND_H_
#define _FRR_NORTHBOUND_H_

#include "frrevent.h"
#include "hook.h"
#include "linklist.h"
#include "openbsd-tree.h"
#include "yang.h"
#include "yang_translator.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration(s). */
struct vty;
struct debug;

struct nb_yang_xpath_tag {
	uint32_t ns;
	uint32_t id;
};

struct nb_yang_value {
	struct lyd_value value;
	LY_DATA_TYPE value_type;
	uint8_t value_flags;
};

struct nb_yang_xpath_elem {
	struct nb_yang_xpath_tag tag;
	struct nb_yang_value val;
};

#define NB_MAX_NUM_KEYS UINT8_MAX
#define NB_MAX_NUM_XPATH_TAGS UINT8_MAX

struct nb_yang_xpath {
	uint8_t length;
	struct {
		uint8_t num_keys;
		struct nb_yang_xpath_elem keys[NB_MAX_NUM_KEYS];
	} tags[NB_MAX_NUM_XPATH_TAGS];
};

#define NB_YANG_XPATH_KEY(__xpath, __indx1, __indx2)                           \
	((__xpath->num_tags > __indx1) &&                                      \
			 (__xpath->tags[__indx1].num_keys > __indx2)           \
		 ? &__xpath->tags[__indx1].keys[__indx2]                       \
		 : NULL)

/* Northbound events. */
enum nb_event {
	/*
	 * The configuration callback is supposed to verify that the changes are
	 * valid and can be applied.
	 */
	NB_EV_VALIDATE,

	/*
	 * The configuration callback is supposed to prepare all resources
	 * required to apply the changes.
	 */
	NB_EV_PREPARE,

	/*
	 * Transaction has failed, the configuration callback needs to release
	 * all resources previously allocated.
	 */
	NB_EV_ABORT,

	/*
	 * The configuration changes need to be applied. The changes can't be
	 * rejected at this point (errors are logged and ignored).
	 */
	NB_EV_APPLY,
};

/*
 * Northbound operations.
 *
 * Refer to the documentation comments of nb_callbacks for more details.
 */
enum nb_operation {
	NB_OP_CREATE,
	NB_OP_MODIFY,
	NB_OP_DESTROY,
	NB_OP_MOVE,
	NB_OP_PRE_VALIDATE,
	NB_OP_APPLY_FINISH,
	NB_OP_GET_ELEM,
	NB_OP_GET_NEXT,
	NB_OP_GET_KEYS,
	NB_OP_LOOKUP_ENTRY,
	NB_OP_RPC,
};

struct nb_cfg_change {
	char xpath[XPATH_MAXLEN];
	enum nb_operation operation;
	const char *value;
};

union nb_resource {
	int fd;
	void *ptr;
};

/*
 * Northbound callbacks parameters.
 */

struct nb_cb_create_args {
	/* Context of the configuration transaction. */
	struct nb_context *context;

	/*
	 * The transaction phase. Refer to the documentation comments of
	 * nb_event for more details.
	 */
	enum nb_event event;

	/* libyang data node that is being created. */
	const struct lyd_node *dnode;

	/*
	 * Pointer to store resource(s) allocated during the NB_EV_PREPARE
	 * phase. The same pointer can be used during the NB_EV_ABORT and
	 * NB_EV_APPLY phases to either release or make use of the allocated
	 * resource(s). It's set to NULL when the event is NB_EV_VALIDATE.
	 */
	union nb_resource *resource;

	/* Buffer to store human-readable error message in case of error. */
	char *errmsg;

	/* Size of errmsg. */
	size_t errmsg_len;
};

struct nb_cb_modify_args {
	/* Context of the configuration transaction. */
	struct nb_context *context;

	/*
	 * The transaction phase. Refer to the documentation comments of
	 * nb_event for more details.
	 */
	enum nb_event event;

	/* libyang data node that is being modified. */
	const struct lyd_node *dnode;

	/*
	 * Pointer to store resource(s) allocated during the NB_EV_PREPARE
	 * phase. The same pointer can be used during the NB_EV_ABORT and
	 * NB_EV_APPLY phases to either release or make use of the allocated
	 * resource(s). It's set to NULL when the event is NB_EV_VALIDATE.
	 */
	union nb_resource *resource;

	/* Buffer to store human-readable error message in case of error. */
	char *errmsg;

	/* Size of errmsg. */
	size_t errmsg_len;
};

struct nb_cb_destroy_args {
	/* Context of the configuration transaction. */
	struct nb_context *context;

	/*
	 * The transaction phase. Refer to the documentation comments of
	 * nb_event for more details.
	 */
	enum nb_event event;

	/* libyang data node that is being deleted. */
	const struct lyd_node *dnode;

	/* Buffer to store human-readable error message in case of error. */
	char *errmsg;

	/* Size of errmsg. */
	size_t errmsg_len;
};

struct nb_cb_move_args {
	/* Context of the configuration transaction. */
	struct nb_context *context;

	/*
	 * The transaction phase. Refer to the documentation comments of
	 * nb_event for more details.
	 */
	enum nb_event event;

	/* libyang data node that is being moved. */
	const struct lyd_node *dnode;

	/* Buffer to store human-readable error message in case of error. */
	char *errmsg;

	/* Size of errmsg. */
	size_t errmsg_len;
};

struct nb_cb_pre_validate_args {
	/* Context of the configuration transaction. */
	struct nb_context *context;

	/* libyang data node associated with the 'pre_validate' callback. */
	const struct lyd_node *dnode;

	/* Buffer to store human-readable error message in case of error. */
	char *errmsg;

	/* Size of errmsg. */
	size_t errmsg_len;
};

struct nb_cb_apply_finish_args {
	/* Context of the configuration transaction. */
	struct nb_context *context;

	/* libyang data node associated with the 'apply_finish' callback. */
	const struct lyd_node *dnode;

	/* Buffer to store human-readable error message in case of error. */
	char *errmsg;

	/* Size of errmsg. */
	size_t errmsg_len;
};

struct nb_cb_get_elem_args {
	/* YANG data path of the data we want to get. */
	const char *xpath;

	/* Pointer to list entry (might be NULL). */
	const void *list_entry;
};

struct nb_cb_get_next_args {
	/* Pointer to parent list entry. */
	const void *parent_list_entry;

	/* Pointer to (leaf-)list entry. */
	const void *list_entry;
};

struct nb_cb_get_keys_args {
	/* Pointer to list entry. */
	const void *list_entry;

	/*
	 * Structure to be filled based on the attributes of the provided list
	 * entry.
	 */
	struct yang_list_keys *keys;
};

struct nb_cb_lookup_entry_args {
	/* Pointer to parent list entry. */
	const void *parent_list_entry;

	/* Structure containing the keys of the list entry. */
	const struct yang_list_keys *keys;
};

struct nb_cb_rpc_args {
	/* XPath of the YANG RPC or action. */
	const char *xpath;

	/* Read-only list of input parameters. */
	const struct list *input;

	/* List of output parameters to be populated by the callback. */
	struct list *output;

	/* Buffer to store human-readable error message in case of error. */
	char *errmsg;

	/* Size of errmsg. */
	size_t errmsg_len;
};

/*
 * Set of configuration callbacks that can be associated to a northbound node.
 */
struct nb_callbacks {
	/*
	 * Configuration callback.
	 *
	 * A presence container, list entry, leaf-list entry or leaf of type
	 * empty has been created.
	 *
	 * For presence-containers and list entries, the callback is supposed to
	 * initialize the default values of its children (if any) from the YANG
	 * models.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_create_args for
	 *    details.
	 *
	 * Returns:
	 *    - NB_OK on success.
	 *    - NB_ERR_VALIDATION when a validation error occurred.
	 *    - NB_ERR_RESOURCE when the callback failed to allocate a resource.
	 *    - NB_ERR_INCONSISTENCY when an inconsistency was detected.
	 *    - NB_ERR for other errors.
	 */
	int (*create)(struct nb_cb_create_args *args);

	/*
	 * Configuration callback.
	 *
	 * The value of a leaf has been modified.
	 *
	 * List keys don't need to implement this callback. When a list key is
	 * modified, the northbound treats this as if the list was deleted and a
	 * new one created with the updated key value.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_modify_args for
	 *    details.
	 *
	 * Returns:
	 *    - NB_OK on success.
	 *    - NB_ERR_VALIDATION when a validation error occurred.
	 *    - NB_ERR_RESOURCE when the callback failed to allocate a resource.
	 *    - NB_ERR_INCONSISTENCY when an inconsistency was detected.
	 *    - NB_ERR for other errors.
	 */
	int (*modify)(struct nb_cb_modify_args *args);

	/*
	 * Configuration callback.
	 *
	 * A presence container, list entry, leaf-list entry or optional leaf
	 * has been deleted.
	 *
	 * The callback is supposed to delete the entire configuration object,
	 * including its children when they exist.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_destroy_args for
	 *    details.
	 *
	 * Returns:
	 *    - NB_OK on success.
	 *    - NB_ERR_VALIDATION when a validation error occurred.
	 *    - NB_ERR_INCONSISTENCY when an inconsistency was detected.
	 *    - NB_ERR for other errors.
	 */
	int (*destroy)(struct nb_cb_destroy_args *args);

	/*
	 * Configuration callback.
	 *
	 * A list entry or leaf-list entry has been moved. Only applicable when
	 * the "ordered-by user" statement is present.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_move_args for
	 *    details.
	 *
	 * Returns:
	 *    - NB_OK on success.
	 *    - NB_ERR_VALIDATION when a validation error occurred.
	 *    - NB_ERR_INCONSISTENCY when an inconsistency was detected.
	 *    - NB_ERR for other errors.
	 */
	int (*move)(struct nb_cb_move_args *args);

	/*
	 * Optional configuration callback.
	 *
	 * This callback can be used to validate subsections of the
	 * configuration being committed before validating the configuration
	 * changes themselves. It's useful to perform more complex validations
	 * that depend on the relationship between multiple nodes.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_pre_validate_args for
	 *    details.
	 *
	 * Returns:
	 *    - NB_OK on success.
	 *    - NB_ERR_VALIDATION when a validation error occurred.
	 */
	int (*pre_validate)(struct nb_cb_pre_validate_args *args);

	/*
	 * Optional configuration callback.
	 *
	 * The 'apply_finish' callbacks are called after all other callbacks
	 * during the apply phase (NB_EV_APPLY). These callbacks are called only
	 * under one of the following two cases:
	 * - The data node has been created or modified (but not deleted);
	 * - Any change was made within the descendants of the data node (e.g. a
	 *   child leaf was modified, created or deleted).
	 *
	 * In the second case above, the 'apply_finish' callback is called only
	 * once even if multiple changes occurred within the descendants of the
	 * data node.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_apply_finish_args for
	 *    details.
	 */
	void (*apply_finish)(struct nb_cb_apply_finish_args *args);

	/*
	 * Operational data callback.
	 *
	 * The callback function should return the value of a specific leaf,
	 * leaf-list entry or inform if a typeless value (presence containers or
	 * leafs of type empty) exists or not.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_get_elem_args for
	 *    details.
	 *
	 * Returns:
	 *    Pointer to newly created yang_data structure, or NULL to indicate
	 *    the absence of data.
	 */
	struct yang_data *(*get_elem)(struct nb_cb_get_elem_args *args);

	/*
	 * Operational data callback for YANG lists and leaf-lists.
	 *
	 * The callback function should return the next entry in the list or
	 * leaf-list. The 'list_entry' parameter will be NULL on the first
	 * invocation.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_get_next_args for
	 *    details.
	 *
	 * Returns:
	 *    Pointer to the next entry in the (leaf-)list, or NULL to signal
	 *    that the end of the (leaf-)list was reached.
	 */
	const void *(*get_next)(struct nb_cb_get_next_args *args);

	/*
	 * Operational data callback for YANG lists.
	 *
	 * The callback function should fill the 'keys' parameter based on the
	 * given list_entry. Keyless lists don't need to implement this
	 * callback.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_get_keys_args for
	 *    details.
	 *
	 * Returns:
	 *    NB_OK on success, NB_ERR otherwise.
	 */
	int (*get_keys)(struct nb_cb_get_keys_args *args);

	/*
	 * Operational data callback for YANG lists.
	 *
	 * The callback function should return a list entry based on the list
	 * keys given as a parameter. Keyless lists don't need to implement this
	 * callback.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_lookup_entry_args for
	 *    details.
	 *
	 * Returns:
	 *    Pointer to the list entry if found, or NULL if not found.
	 */
	const void *(*lookup_entry)(struct nb_cb_lookup_entry_args *args);

	/*
	 * RPC and action callback.
	 *
	 * Both 'input' and 'output' are lists of 'yang_data' structures. The
	 * callback should fetch all the input parameters from the 'input' list,
	 * and add output parameters to the 'output' list if necessary.
	 *
	 * args
	 *    Refer to the documentation comments of nb_cb_rpc_args for details.
	 *
	 * Returns:
	 *    NB_OK on success, NB_ERR otherwise.
	 */
	int (*rpc)(struct nb_cb_rpc_args *args);

	/*
	 * Optional callback to compare the data nodes when printing
	 * the CLI commands associated with them.
	 *
	 * dnode1
	 *    The first data node to compare.
	 *
	 * dnode2
	 *    The second data node to compare.
	 *
	 * Returns:
	 *    <0 when the CLI command for the dnode1 should be printed first
	 *    >0 when the CLI command for the dnode2 should be printed first
	 *     0 when there is no difference
	 */
	int (*cli_cmp)(const struct lyd_node *dnode1,
		       const struct lyd_node *dnode2);

	/*
	 * Optional callback to show the CLI command associated to the given
	 * YANG data node.
	 *
	 * vty
	 *    The vty terminal to dump the configuration to.
	 *
	 * dnode
	 *    libyang data node that should be shown in the form of a CLI
	 *    command.
	 *
	 * show_defaults
	 *    Specify whether to display default configuration values or not.
	 *    This parameter can be ignored most of the time since the
	 *    northbound doesn't call this callback for default leaves or
	 *    non-presence containers that contain only default child nodes.
	 *    The exception are commands associated to multiple configuration
	 *    nodes, in which case it might be desirable to hide one or more
	 *    parts of the command when this parameter is set to false.
	 */
	void (*cli_show)(struct vty *vty, const struct lyd_node *dnode,
			 bool show_defaults);

	/*
	 * Optional callback to show the CLI node end for lists or containers.
	 *
	 * vty
	 *    The vty terminal to dump the configuration to.
	 *
	 * dnode
	 *    libyang data node that should be shown in the form of a CLI
	 *    command.
	 */
	void (*cli_show_end)(struct vty *vty, const struct lyd_node *dnode);
};

struct nb_dependency_callbacks {
	void (*get_dependant_xpath)(const struct lyd_node *dnode, char *xpath);
	void (*get_dependency_xpath)(const struct lyd_node *dnode, char *xpath);
};

/*
 * Northbound-specific data that is allocated for each schema node of the native
 * YANG modules.
 */
struct nb_node {
	/* Back pointer to the libyang schema node. */
	const struct lysc_node *snode;

	/* Data path of this YANG node. */
	char xpath[XPATH_MAXLEN];

	/* Priority - lower priorities are processed first. */
	uint32_t priority;

	struct nb_dependency_callbacks dep_cbs;

	/* Callbacks implemented for this node. */
	struct nb_callbacks cbs;

	/*
	 * Pointer to the parent node (disconsidering non-presence containers).
	 */
	struct nb_node *parent;

	/* Pointer to the nearest parent list, if any. */
	struct nb_node *parent_list;

	/* Flags. */
	uint8_t flags;

#ifdef HAVE_CONFD
	/* ConfD hash value corresponding to this YANG path. */
	int confd_hash;
#endif
};
/* The YANG container or list contains only config data. */
#define F_NB_NODE_CONFIG_ONLY 0x01
/* The YANG list doesn't contain key leafs. */
#define F_NB_NODE_KEYLESS_LIST 0x02
/* Ignore callbacks for this node */
#define F_NB_NODE_IGNORE_CBS 0x04

/*
 * HACK: old gcc versions (< 5.x) have a bug that prevents C99 flexible arrays
 * from working properly on shared libraries. For those compilers, use a fixed
 * size array to work around the problem.
 */
#define YANG_MODULE_MAX_NODES 2000

struct frr_yang_module_info {
	/* YANG module name. */
	const char *name;

	/*
	 * Ignore callbacks for this module. Set this to true to
	 * load module without any callbacks.
	 */
	bool ignore_cbs;

	/* Northbound callbacks. */
	const struct {
		/* Data path of this YANG node. */
		const char *xpath;

		/* Callbacks implemented for this node. */
		struct nb_callbacks cbs;

		/* Priority - lower priorities are processed first. */
		uint32_t priority;
#if defined(__GNUC__) && ((__GNUC__ - 0) < 5) && !defined(__clang__)
	} nodes[YANG_MODULE_MAX_NODES + 1];
#else
	} nodes[];
#endif
};

/* Northbound error codes. */
enum nb_error {
	NB_OK = 0,
	NB_ERR,
	NB_ERR_NO_CHANGES,
	NB_ERR_NOT_FOUND,
	NB_ERR_LOCKED,
	NB_ERR_VALIDATION,
	NB_ERR_RESOURCE,
	NB_ERR_INCONSISTENCY,
};

/* Default priority. */
#define NB_DFLT_PRIORITY (UINT32_MAX / 2)

/* Default maximum of configuration rollbacks to store. */
#define NB_DLFT_MAX_CONFIG_ROLLBACKS 20

/* Northbound clients. */
enum nb_client {
	NB_CLIENT_NONE = 0,
	NB_CLIENT_CLI,
	NB_CLIENT_CONFD,
	NB_CLIENT_SYSREPO,
	NB_CLIENT_GRPC,
	NB_CLIENT_PCEP,
	NB_CLIENT_MGMTD_SERVER,
	NB_CLIENT_MGMTD_BE,
};

/* Northbound context. */
struct nb_context {
	/* Northbound client. */
	enum nb_client client;

	/* Northbound user (can be NULL). */
	const void *user;
};

/* Northbound configuration callback. */
struct nb_config_cb {
	RB_ENTRY(nb_config_cb) entry;
	enum nb_operation operation;
	uint32_t seq;
	const struct nb_node *nb_node;
	const struct lyd_node *dnode;
};
RB_HEAD(nb_config_cbs, nb_config_cb);
RB_PROTOTYPE(nb_config_cbs, nb_config_cb, entry, nb_config_cb_compare);

/* Northbound configuration change. */
struct nb_config_change {
	struct nb_config_cb cb;
	union nb_resource resource;
	bool prepare_ok;
};

/* Northbound configuration transaction. */
struct nb_transaction {
	struct nb_context context;
	char comment[80];
	struct nb_config *config;
	struct nb_config_cbs changes;
};

/* Northbound configuration. */
struct nb_config {
	struct lyd_node *dnode;
	uint32_t version;
	struct nb_config_cbs cfg_chgs;
};

/* Callback function used by nb_oper_data_iterate(). */
typedef int (*nb_oper_data_cb)(const struct lysc_node *snode,
			       struct yang_translator *translator,
			       struct yang_data *data, void *arg);

/* Iterate over direct child nodes only. */
#define NB_OPER_DATA_ITER_NORECURSE 0x0001

/* Hooks. */
DECLARE_HOOK(nb_notification_send, (const char *xpath, struct list *arguments),
	     (xpath, arguments));
DECLARE_HOOK(nb_client_debug_config_write, (struct vty *vty), (vty));
DECLARE_HOOK(nb_client_debug_set_all, (uint32_t flags, bool set), (flags, set));

/* Northbound debugging records */
extern struct debug nb_dbg_cbs_config;
extern struct debug nb_dbg_cbs_state;
extern struct debug nb_dbg_cbs_rpc;
extern struct debug nb_dbg_notif;
extern struct debug nb_dbg_events;
extern struct debug nb_dbg_libyang;

/* Global running configuration. */
extern struct nb_config *running_config;

/* Wrappers for the northbound callbacks. */
extern struct yang_data *nb_callback_get_elem(const struct nb_node *nb_node,
					      const char *xpath,
					      const void *list_entry);
extern const void *nb_callback_get_next(const struct nb_node *nb_node,
					const void *parent_list_entry,
					const void *list_entry);
extern int nb_callback_get_keys(const struct nb_node *nb_node,
				const void *list_entry,
				struct yang_list_keys *keys);
extern const void *nb_callback_lookup_entry(const struct nb_node *nb_node,
					    const void *parent_list_entry,
					    const struct yang_list_keys *keys);
extern int nb_callback_rpc(const struct nb_node *nb_node, const char *xpath,
			   const struct list *input, struct list *output,
			   char *errmsg, size_t errmsg_len);

/*
 * Create a northbound node for all YANG schema nodes.
 */
void nb_nodes_create(void);

/*
 * Delete all northbound nodes from all YANG schema nodes.
 */
void nb_nodes_delete(void);

/*
 * Find the northbound node corresponding to a YANG data path.
 *
 * xpath
 *    XPath to search for (with or without predicates).
 *
 * Returns:
 *    Pointer to northbound node if found, NULL otherwise.
 */
extern struct nb_node *nb_node_find(const char *xpath);

extern void nb_node_set_dependency_cbs(const char *dependency_xpath,
				       const char *dependant_xpath,
				       struct nb_dependency_callbacks *cbs);

bool nb_node_has_dependency(struct nb_node *node);

/*
 * Create a new northbound configuration.
 *
 * dnode
 *    Pointer to a libyang data node containing the configuration data. If NULL
 *    is given, an empty configuration will be created.
 *
 * Returns:
 *    Pointer to newly created northbound configuration.
 */
extern struct nb_config *nb_config_new(struct lyd_node *dnode);

/*
 * Delete a northbound configuration.
 *
 * config
 *    Pointer to the config that is going to be deleted.
 */
extern void nb_config_free(struct nb_config *config);

/*
 * Duplicate a northbound configuration.
 *
 * config
 *    Northbound configuration to duplicate.
 *
 * Returns:
 *    Pointer to duplicated configuration.
 */
extern struct nb_config *nb_config_dup(const struct nb_config *config);

/*
 * Merge one configuration into another.
 *
 * config_dst
 *    Configuration to merge to.
 *
 * config_src
 *    Configuration to merge config_dst with.
 *
 * preserve_source
 *    Specify whether config_src should be deleted or not after the merge
 *    operation.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
extern int nb_config_merge(struct nb_config *config_dst,
			   struct nb_config *config_src, bool preserve_source);

/*
 * Replace one configuration by another.
 *
 * config_dst
 *    Configuration to be replaced.
 *
 * config_src
 *    Configuration to replace config_dst.
 *
 * preserve_source
 *    Specify whether config_src should be deleted or not after the replace
 *    operation.
 */
extern void nb_config_replace(struct nb_config *config_dst,
			      struct nb_config *config_src,
			      bool preserve_source);

/*
 * Edit a candidate configuration.
 *
 * candidate
 *    Candidate configuration to edit.
 *
 * nb_node
 *    Northbound node associated to the configuration being edited.
 *
 * operation
 *    Operation to apply.
 *
 * xpath
 *    XPath of the configuration node being edited.
 *
 * previous
 *    Previous value of the configuration node. Should be used only when the
 *    operation is NB_OP_MOVE, otherwise this parameter is ignored.
 *
 * data
 *    New value of the configuration node.
 *
 * Returns:
 *    - NB_OK on success.
 *    - NB_ERR_NOT_FOUND when the element to be deleted was not found.
 *    - NB_ERR for other errors.
 */
extern int nb_candidate_edit(struct nb_config *candidate,
			     const struct nb_node *nb_node,
			     enum nb_operation operation, const char *xpath,
			     const struct yang_data *previous,
			     const struct yang_data *data);

/*
 * Create diff for configuration.
 *
 * dnode
 *    Pointer to a libyang data node containing the configuration data. If NULL
 *    is given, an empty configuration will be created.
 *
 * seq
 *    Returns sequence number assigned to the specific change.
 *
 * changes
 *    Northbound config callback head.
 */
extern void nb_config_diff_created(const struct lyd_node *dnode, uint32_t *seq,
				   struct nb_config_cbs *changes);

/*
 * Check if a candidate configuration is outdated and needs to be updated.
 *
 * candidate
 *    Candidate configuration to check.
 *
 * Returns:
 *    true if the candidate is outdated, false otherwise.
 */
extern bool nb_candidate_needs_update(const struct nb_config *candidate);

/*
 * Edit candidate configuration changes.
 *
 * candidate_config
 *    Candidate configuration to edit.
 *
 * cfg_changes
 *    Northbound config changes.
 *
 * num_cfg_changes
 *    Number of config changes.
 *
 * xpath_base
 *    Base xpath for config.
 *
 * curr_xpath
 *    Current xpath for config.
 *
 * xpath_index
 *    Index of xpath being processed.
 *
 * err_buf
 *    Buffer to store human-readable error message in case of error.
 *
 * err_bufsize
 *    Size of err_buf.
 *
 * error
 *    TRUE on error, FALSE on success
 */
extern void nb_candidate_edit_config_changes(
	struct nb_config *candidate_config, struct nb_cfg_change cfg_changes[],
	size_t num_cfg_changes, const char *xpath_base, const char *curr_xpath,
	int xpath_index, char *err_buf, int err_bufsize, bool *error);

/*
 * Delete candidate configuration changes.
 *
 * changes
 *    Northbound config changes.
 */
extern void nb_config_diff_del_changes(struct nb_config_cbs *changes);

/*
 * Create candidate diff and validate on yang tree
 *
 * context
 *    Context of the northbound transaction.
 *
 * candidate
 *    Candidate DB configuration.
 *
 * changes
 *    Northbound config changes.
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error.
 *
 * errmsg_len
 *    Size of errmsg.
 *
 * Returns:
 *    NB_OK on success, NB_ERR_VALIDATION otherwise
 */
extern int nb_candidate_diff_and_validate_yang(struct nb_context *context,
					       struct nb_config *candidate,
					       struct nb_config_cbs *changes,
					       char *errmsg, size_t errmsg_len);

/*
 * Calculate the delta between two different configurations.
 *
 * reference
 *    Running DB config changes to be compared against.
 *
 * incremental
 *    Candidate DB config changes that will be compared against reference.
 *
 * changes
 *    Will hold the final diff generated.
 *
 */
extern void nb_config_diff(const struct nb_config *reference,
			   const struct nb_config *incremental,
			   struct nb_config_cbs *changes);

/*
 * Perform YANG syntactic and semantic validation.
 *
 * WARNING: lyd_validate() can change the configuration as part of the
 * validation process.
 *
 * candidate
 *    Candidate DB configuration.
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error.
 *
 * errmsg_len
 *    Size of errmsg.
 *
 * Returns:
 *    NB_OK on success, NB_ERR_VALIDATION otherwise
 */
extern int nb_candidate_validate_yang(struct nb_config *candidate,
				      bool no_state, char *errmsg,
				      size_t errmsg_len);

/*
 * Perform code-level validation using the northbound callbacks.
 *
 * context
 *    Context of the northbound transaction.
 *
 * candidate
 *    Candidate DB configuration.
 *
 * changes
 *    Northbound config changes.
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error.
 *
 * errmsg_len
 *    Size of errmsg.
 *
 * Returns:
 *    NB_OK on success, NB_ERR_VALIDATION otherwise
 */
extern int nb_candidate_validate_code(struct nb_context *context,
				      struct nb_config *candidate,
				      struct nb_config_cbs *changes,
				      char *errmsg, size_t errmsg_len);

/*
 * Update a candidate configuration by rebasing the changes on top of the latest
 * running configuration. Resolve conflicts automatically by giving preference
 * to the changes done in the candidate configuration.
 *
 * candidate
 *    Candidate configuration to update.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
extern int nb_candidate_update(struct nb_config *candidate);

/*
 * Validate a candidate configuration. Perform both YANG syntactic/semantic
 * validation and code-level validation using the northbound callbacks.
 *
 * WARNING: the candidate can be modified as part of the validation process
 * (e.g. add default nodes).
 *
 * context
 *    Context of the northbound transaction.
 *
 * candidate
 *    Candidate configuration to validate.
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error.
 *
 * errmsg_len
 *    Size of errmsg.
 *
 * Returns:
 *    NB_OK on success, NB_ERR_VALIDATION otherwise.
 */
extern int nb_candidate_validate(struct nb_context *context,
				 struct nb_config *candidate, char *errmsg,
				 size_t errmsg_len);

/*
 * Create a new configuration transaction but do not commit it yet. Only
 * validate the candidate and prepare all resources required to apply the
 * configuration changes.
 *
 * context
 *    Context of the northbound transaction.
 *
 * candidate
 *    Candidate configuration to commit.
 *
 * comment
 *    Optional comment describing the commit.
 *
 * transaction
 *    Output parameter providing the created transaction when one is created
 *    successfully. In this case, it must be either aborted using
 *    nb_candidate_commit_abort() or committed using
 *    nb_candidate_commit_apply().
 *
 * skip_validate
 *    TRUE to skip commit validation, FALSE otherwise.
 *
 * ignore_zero_change
 *    TRUE to ignore if zero changes, FALSE otherwise.
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error.
 *
 * errmsg_len
 *    Size of errmsg.
 *
 * Returns:
 *    - NB_OK on success.
 *    - NB_ERR_NO_CHANGES when the candidate is identical to the running
 *      configuration.
 *    - NB_ERR_LOCKED when there's already another transaction in progress.
 *    - NB_ERR_VALIDATION when the candidate fails the validation checks.
 *    - NB_ERR_RESOURCE when the system fails to allocate resources to apply
 *      the candidate configuration.
 *    - NB_ERR for other errors.
 */
extern int nb_candidate_commit_prepare(struct nb_context context,
				       struct nb_config *candidate,
				       const char *comment,
				       struct nb_transaction **transaction,
				       bool skip_validate,
				       bool ignore_zero_change, char *errmsg,
				       size_t errmsg_len);

/*
 * Abort a previously created configuration transaction, releasing all resources
 * allocated during the preparation phase.
 *
 * transaction
 *    Candidate configuration to abort. It's consumed by this function.
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error.
 *
 * errmsg_len
 *    Size of errmsg.
 */
extern void nb_candidate_commit_abort(struct nb_transaction *transaction,
				      char *errmsg, size_t errmsg_len);

/*
 * Commit a previously created configuration transaction.
 *
 * transaction
 *    Configuration transaction to commit. It's consumed by this function.
 *
 * save_transaction
 *    Specify whether the transaction should be recorded in the transactions log
 *    or not.
 *
 * transaction_id
 *    Optional output parameter providing the ID of the committed transaction.
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error.
 *
 * errmsg_len
 *    Size of errmsg.
 */
extern void nb_candidate_commit_apply(struct nb_transaction *transaction,
				      bool save_transaction,
				      uint32_t *transaction_id, char *errmsg,
				      size_t errmsg_len);

/*
 * Create a new transaction to commit a candidate configuration. This is a
 * convenience function that performs the two-phase commit protocol
 * transparently to the user. The cost is reduced flexibility, since
 * network-wide and multi-daemon transactions require the network manager to
 * take into account the results of the preparation phase of multiple managed
 * entities.
 *
 * context
 *    Context of the northbound transaction.
 *
 * candidate
 *    Candidate configuration to commit. It's preserved regardless if the commit
 *    operation fails or not.
 *
 * save_transaction
 *    Specify whether the transaction should be recorded in the transactions log
 *    or not.
 *
 * comment
 *    Optional comment describing the commit.
 *
 * transaction_id
 *    Optional output parameter providing the ID of the committed transaction.
 *
 * errmsg
 *    Buffer to store human-readable error message in case of error.
 *
 * errmsg_len
 *    Size of errmsg.
 *
 * Returns:
 *    - NB_OK on success.
 *    - NB_ERR_NO_CHANGES when the candidate is identical to the running
 *      configuration.
 *    - NB_ERR_LOCKED when there's already another transaction in progress.
 *    - NB_ERR_VALIDATION when the candidate fails the validation checks.
 *    - NB_ERR_RESOURCE when the system fails to allocate resources to apply
 *      the candidate configuration.
 *    - NB_ERR for other errors.
 */
extern int nb_candidate_commit(struct nb_context context,
			       struct nb_config *candidate,
			       bool save_transaction, const char *comment,
			       uint32_t *transaction_id, char *errmsg,
			       size_t errmsg_len);

/*
 * Lock the running configuration.
 *
 * client
 *    Northbound client.
 *
 * user
 *    Northbound user (can be NULL).
 *
 * Returns:
 *    0 on success, -1 when the running configuration is already locked.
 */
extern int nb_running_lock(enum nb_client client, const void *user);

/*
 * Unlock the running configuration.
 *
 * client
 *    Northbound client.
 *
 * user
 *    Northbound user (can be NULL).
 *
 * Returns:
 *    0 on success, -1 when the running configuration is already unlocked or
 *    locked by another client/user.
 */
extern int nb_running_unlock(enum nb_client client, const void *user);

/*
 * Check if the running configuration is locked or not for the given
 * client/user.
 *
 * client
 *    Northbound client.
 *
 * user
 *    Northbound user (can be NULL).
 *
 * Returns:
 *    0 if the running configuration is unlocked or if the client/user owns the
 *    lock, -1 otherwise.
 */
extern int nb_running_lock_check(enum nb_client client, const void *user);

/*
 * Iterate over operational data.
 *
 * xpath
 *    Data path of the YANG data we want to iterate over.
 *
 * translator
 *    YANG module translator (might be NULL).
 *
 * flags
 *    NB_OPER_DATA_ITER_ flags to control how the iteration is performed.
 *
 * cb
 *    Function to call with each data node.
 *
 * arg
 *    Arbitrary argument passed as the fourth parameter in each call to 'cb'.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
extern int nb_oper_data_iterate(const char *xpath,
				struct yang_translator *translator,
				uint32_t flags, nb_oper_data_cb cb, void *arg);

/*
 * Validate if the northbound operation is valid for the given node.
 *
 * operation
 *    Operation we want to check.
 *
 * snode
 *    libyang schema node we want to check.
 *
 * Returns:
 *    true if the operation is valid, false otherwise.
 */
extern bool nb_operation_is_valid(enum nb_operation operation,
				  const struct lysc_node *snode);

/*
 * Send a YANG notification. This is a no-op unless the 'nb_notification_send'
 * hook was registered by a northbound plugin.
 *
 * xpath
 *    XPath of the YANG notification.
 *
 * arguments
 *    Linked list containing the arguments that should be sent. This list is
 *    deleted after being used.
 *
 * Returns:
 *    NB_OK on success, NB_ERR otherwise.
 */
extern int nb_notification_send(const char *xpath, struct list *arguments);

/*
 * Associate a user pointer to a configuration node.
 *
 * This should be called by northbound 'create' callbacks in the NB_EV_APPLY
 * phase only.
 *
 * dnode
 *    libyang data node - only its XPath is used.
 *
 * entry
 *    Arbitrary user-specified pointer.
 */
extern void nb_running_set_entry(const struct lyd_node *dnode, void *entry);

/*
 * Move an entire tree of user pointer nodes.
 *
 * Suppose we have xpath A/B/C/D, with user pointers associated to C and D. We
 * need to move B to be under Z, so the new xpath is Z/B/C/D. Because user
 * pointers are indexed with their absolute path, We need to move all user
 * pointers at and below B to their new absolute paths; this function does
 * that.
 *
 * xpath_from
 *    base xpath of tree to move (A/B)
 *
 * xpath_to
 *    base xpath of new location of tree (Z/B)
 */
extern void nb_running_move_tree(const char *xpath_from, const char *xpath_to);

/*
 * Unset the user pointer associated to a configuration node.
 *
 * This should be called by northbound 'destroy' callbacks in the NB_EV_APPLY
 * phase only.
 *
 * dnode
 *    libyang data node - only its XPath is used.
 *
 * Returns:
 *    The user pointer that was unset.
 */
extern void *nb_running_unset_entry(const struct lyd_node *dnode);

/*
 * Find the user pointer (if any) associated to a configuration node.
 *
 * The XPath associated to the configuration node can be provided directly or
 * indirectly through a libyang data node.
 *
 * If an user point is not found, this function follows the parent nodes in the
 * running configuration until an user pointer is found or until the root node
 * is reached.
 *
 * dnode
 *    libyang data node - only its XPath is used (can be NULL if 'xpath' is
 *    provided).
 *
 * xpath
 *    XPath of the configuration node (can be NULL if 'dnode' is provided).
 *
 * abort_if_not_found
 *    When set to true, abort the program if no user pointer is found.
 *
 *    As a rule of thumb, this parameter should be set to true in the following
 *    scenarios:
 *    - Calling this function from any northbound configuration callback during
 *      the NB_EV_APPLY phase.
 *    - Calling this function from a 'delete' northbound configuration callback
 *      during any phase.
 *
 *    In both the above cases, the given configuration node should contain an
 *    user pointer except when there's a bug in the code, in which case it's
 *    better to abort the program right away and eliminate the need for
 *    unnecessary NULL checks.
 *
 *    In all other cases, this parameter should be set to false and the caller
 *    should check if the function returned NULL or not.
 *
 * Returns:
 *    User pointer if found, NULL otherwise.
 */
extern void *nb_running_get_entry(const struct lyd_node *dnode,
				  const char *xpath, bool abort_if_not_found);

/*
 * Same as 'nb_running_get_entry', but doesn't search within parent nodes
 * recursively if an user point is not found.
 */
extern void *nb_running_get_entry_non_rec(const struct lyd_node *dnode,
					  const char *xpath,
					  bool abort_if_not_found);

/*
 * Return a human-readable string representing a northbound event.
 *
 * event
 *    Northbound event.
 *
 * Returns:
 *    String representation of the given northbound event.
 */
extern const char *nb_event_name(enum nb_event event);

/*
 * Return a human-readable string representing a northbound operation.
 *
 * operation
 *    Northbound operation.
 *
 * Returns:
 *    String representation of the given northbound operation.
 */
extern const char *nb_operation_name(enum nb_operation operation);

/*
 * Return a human-readable string representing a northbound error.
 *
 * error
 *    Northbound error.
 *
 * Returns:
 *    String representation of the given northbound error.
 */
extern const char *nb_err_name(enum nb_error error);

/*
 * Return a human-readable string representing a northbound client.
 *
 * client
 *    Northbound client.
 *
 * Returns:
 *    String representation of the given northbound client.
 */
extern const char *nb_client_name(enum nb_client client);

/*
 * Validate all northbound callbacks.
 *
 * Some errors, like missing callbacks or invalid priorities, are fatal and
 * can't be recovered from. Other errors, like unneeded callbacks, are logged
 * but otherwise ignored.
 *
 * Whenever a YANG module is loaded after startup, *all* northbound callbacks
 * need to be validated and not only the callbacks from the newly loaded module.
 * This is because augmentations can change the properties of the augmented
 * module, making mandatory the implementation of additional callbacks.
 */
void nb_validate_callbacks(void);

/*
 * Initialize the northbound layer. Should be called only once during the
 * daemon initialization process.
 *
 * modules
 *    Array of YANG modules to parse and initialize.
 *
 * nmodules
 *    Size of the modules array.
 *
 * db_enabled
 *    Set this to record the transactions in the transaction log.
 */
extern void nb_init(struct event_loop *tm,
		    const struct frr_yang_module_info *const modules[],
		    size_t nmodules, bool db_enabled);

/*
 * Finish the northbound layer gracefully. Should be called only when the daemon
 * is exiting.
 */
extern void nb_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_NORTHBOUND_H_ */
