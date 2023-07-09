// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#ifndef _FRR_YANG_H_
#define _FRR_YANG_H_

#include "memory.h"

#include <libyang/libyang.h>
#ifdef HAVE_SYSREPO
#include <sysrepo.h>
#endif

#include "yang_wrappers.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum XPath length. */
#define XPATH_MAXLEN 1024

/* Maximum list key length. */
#define LIST_MAXKEYS 8

/* Maximum list key length. */
#define LIST_MAXKEYLEN 128

/* Maximum string length of an YANG value. */
#define YANG_VALUE_MAXLEN 1024

struct yang_module_embed {
	struct yang_module_embed *next;
	const char *mod_name, *mod_rev;
	const char *sub_mod_name;
	const char *sub_mod_rev;
	const char *data;
	LYS_INFORMAT format;
};

struct yang_module {
	RB_ENTRY(yang_module) entry;
	const char *name;
	const struct lys_module *info;
#ifdef HAVE_CONFD
	int confd_hash;
#endif
#ifdef HAVE_SYSREPO
	sr_subscription_ctx_t *sr_subscription;
	struct event *sr_thread;
#endif
};
RB_HEAD(yang_modules, yang_module);
RB_PROTOTYPE(yang_modules, yang_module, entry, yang_module_compare);

struct yang_data {
	/* XPath identifier of the data element. */
	char xpath[XPATH_MAXLEN];

	/* Value encoded as a raw string. */
	char *value;
};

struct yang_list_keys {
	/* Number os keys (max: LIST_MAXKEYS). */
	uint8_t num;

	/* Value encoded as a raw string. */
	char key[LIST_MAXKEYS][LIST_MAXKEYLEN];
};

enum yang_path_type {
	YANG_PATH_SCHEMA = 0,
	YANG_PATH_DATA,
};

enum yang_iter_flags {
	/* Filter non-presence containers. */
	YANG_ITER_FILTER_NPCONTAINERS = (1<<0),

	/* Filter list keys (leafs). */
	YANG_ITER_FILTER_LIST_KEYS = (1<<1),

	/* Filter RPC input/output nodes. */
	YANG_ITER_FILTER_INPUT_OUTPUT = (1<<2),
};

/* Callback used by the yang_snodes_iterate_*() family of functions. */
typedef int (*yang_iterate_cb)(const struct lysc_node *snode, void *arg);

/* Callback used by the yang_dnode_iterate() function. */
typedef int (*yang_dnode_iter_cb)(const struct lyd_node *dnode, void *arg);

/* Return values of the 'yang_iterate_cb' callback. */
#define YANG_ITER_CONTINUE 0
#define YANG_ITER_STOP -1

/* Global libyang context for native FRR models. */
extern struct ly_ctx *ly_native_ctx;

/* Tree of all loaded YANG modules. */
extern struct yang_modules yang_modules;

/*
 * Create a new YANG module and load it using libyang. If the YANG module is not
 * found in the YANG_MODELS_PATH directory, the program will exit with an error.
 * Once loaded, a YANG module can't be unloaded anymore.
 *
 * module_name
 *    Name of the YANG module.
 *
 * Returns:
 *    Pointer to newly created YANG module.
 */
extern struct yang_module *yang_module_load(const char *module_name);

/*
 * Load all FRR native YANG models.
 */
extern void yang_module_load_all(void);

/*
 * Find a YANG module by its name.
 *
 * module_name
 *    Name of the YANG module.
 *
 * Returns:
 *    Pointer to YANG module if found, NULL otherwise.
 */
extern struct yang_module *yang_module_find(const char *module_name);

/*
 * Register a YANG module embedded in the binary file.  Should be called
 * from a constructor function.
 *
 * embed
 *    YANG module embedding structure to register.  (static global provided
 *    by caller.)
 */
extern void yang_module_embed(struct yang_module_embed *embed);

/*
 * Iterate recursively over all children of a schema node.
 *
 * snode
 *    YANG schema node to operate on.
 *
 * module
 *    When set, iterate over all nodes of the specified module only.
 *
 * cb
 *    Function to call with each schema node.
 *
 * flags
 *    YANG_ITER_* flags to control how the iteration is performed.
 *
 * arg
 *    Arbitrary argument passed as the second parameter in each call to 'cb'.
 *
 * Returns:
 *    The return value of the last called callback.
 */
extern int yang_snodes_iterate_subtree(const struct lysc_node *snode,
				       const struct lys_module *module,
				       yang_iterate_cb cb, uint16_t flags,
				       void *arg);

/*
 * Iterate over all libyang schema nodes from all loaded modules of the
 * given YANG module.
 *
 * module
 *    When set, iterate over all nodes of the specified module only.
 *
 * cb
 *    Function to call with each schema node.
 *
 * flags
 *    YANG_ITER_* flags to control how the iteration is performed.
 *
 * arg
 *    Arbitrary argument passed as the second parameter in each call to 'cb'.
 *
 * Returns:
 *    The return value of the last called callback.
 */
extern int yang_snodes_iterate(const struct lys_module *module,
			       yang_iterate_cb cb, uint16_t flags, void *arg);

/*
 * Build schema path or data path of the schema node.
 *
 * snode
 *    libyang schema node to be processed.
 *
 * type
 *    Specify whether a schema path or a data path should be built.
 *
 * xpath
 *    Pointer to previously allocated buffer.
 *
 * xpath_len
 *    Size of the xpath buffer.
 */
extern void yang_snode_get_path(const struct lysc_node *snode,
				enum yang_path_type type, char *xpath,
				size_t xpath_len);


/*
 * Find libyang schema node for the given xpath. Uses `lys_find_xpath`,
 * returning only the first of a set of nodes -- normally there should only
 * be one.
 *
 * ly_ctx
 *    libyang context to operate on.
 *
 * xpath
 *    XPath expression (absolute or relative) to find the schema node for.
 *
 * options
 *    Libyang findxpathoptions value (see lys_find_xpath).
 *
 * Returns:
 *    The libyang schema node if found, or NULL if not found.
 */
extern struct lysc_node *yang_find_snode(struct ly_ctx *ly_ctx,
					 const char *xpath, uint32_t options);

/*
 * Find first parent schema node which is a presence-container or a list
 * (non-presence containers are ignored).
 *
 * snode
 *    libyang schema node to operate on.
 *
 * Returns:
 *    The parent libyang schema node if found, or NULL if not found.
 */
extern struct lysc_node *yang_snode_real_parent(const struct lysc_node *snode);

/*
 * Find first parent schema node which is a list.
 *
 * snode
 *    libyang schema node to operate on.
 *
 * Returns:
 *    The parent libyang schema node (list) if found, or NULL if not found.
 */
extern struct lysc_node *yang_snode_parent_list(const struct lysc_node *snode);

/*
 * Check if the libyang schema node represents typeless data (e.g. containers,
 * leafs of type empty, etc).
 *
 * snode
 *    libyang schema node to operate on.
 *
 * Returns:
 *    true if the schema node represents typeless data, false otherwise.
 */
extern bool yang_snode_is_typeless_data(const struct lysc_node *snode);

/*
 * Get the default value associated to a YANG leaf or leaf-list.
 *
 * snode
 *    libyang schema node to operate on.
 *
 * Returns:
 *    The default value if it exists, NULL otherwise.
 */
extern const char *yang_snode_get_default(const struct lysc_node *snode);

/*
 * Get the type structure of a leaf of leaf-list. If the type is a leafref, the
 * final (if there is a chain of leafrefs) target's type is found.
 *
 * snode
 *    libyang schema node to operate on.
 *
 * Returns:
 *    The found type if the schema node represents a leaf or a leaf-list, NULL
 *    otherwise.
 */
extern const struct lysc_type *
yang_snode_get_type(const struct lysc_node *snode);

/*
 * Get the number of key nodes for the given list.
 *
 * snode
 *    libyang (LYS_LIST) schema node to operate on.
 *
 * Returns:
 *    The number of key LYS_LEAFs as children of this list node.
 */
extern unsigned int yang_snode_num_keys(const struct lysc_node *snode);

#define LY_FOR_KEYS(snode, skey)                                               \
	for ((skey) = (const struct lysc_node_leaf *)lysc_node_child((snode)); \
	     (skey); (skey) = (const struct lysc_node_leaf *)((skey)->next))   \
		if (!lysc_is_key(skey)) {                                      \
			break;                                                 \
		} else


/*
 * Build data path of the data node.
 *
 * dnode
 *    libyang data node to be processed.
 *
 * xpath
 *    Pointer to previously allocated buffer.
 *
 * xpath_len
 *    Size of the xpath buffer.
 */
extern void yang_dnode_get_path(const struct lyd_node *dnode, char *xpath,
				size_t xpath_len);

/*
 * Return the schema name of the given libyang data node.
 *
 * dnode
 *    libyang data node.
 *
 * xpath_fmt
 *    Optional XPath expression (absolute or relative) to specify a different
 *    data node to operate on in the same data tree.
 *
 * Returns:
 *    Schema name of the libyang data node.
 */
extern const char *yang_dnode_get_schema_name(const struct lyd_node *dnode,
					      const char *xpath_fmt, ...)
	PRINTFRR(2, 3);

/*
 * Find a libyang data node by its YANG data path.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath
 *    Limited XPath (absolute or relative) string. See Path in libyang
 *    documentation for restrictions.
 *
 * Returns:
 *    The libyang data node if found, or NULL if not found.
 */
extern struct lyd_node *yang_dnode_get(const struct lyd_node *dnode,
				       const char *xpath);

/*
 * Find a libyang data node by its YANG data path.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath_fmt
 *    Limited XPath (absolute or relative) format string. See Path in libyang
 *    documentation for restrictions.
 *
 * ...
 *    any parameters for xpath_fmt.
 *
 * Returns:
 *    The libyang data node if found, or NULL if not found.
 */
extern struct lyd_node *yang_dnode_getf(const struct lyd_node *dnode,
					const char *path_fmt, ...)
	PRINTFRR(2, 3);

/*
 * Check if a libyang data node exists.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath
 *    Limited XPath (absolute or relative) string. See Path in libyang
 *    documentation for restrictions.
 *
 * Returns:
 *    true if a libyang data node was found, false otherwise.
 */
extern bool yang_dnode_exists(const struct lyd_node *dnode, const char *xpath);

/*
 * Check if a libyang data node exists.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath_fmt
 *    Limited XPath (absolute or relative) format string. See Path in
 *    libyang documentation for restrictions.
 *
 * ...
 *    any parameters for xpath_fmt.
 *
 * Returns:
 *    true if a libyang data node was found, false otherwise.
 */
extern bool yang_dnode_existsf(const struct lyd_node *dnode,
			       const char *xpath_fmt, ...) PRINTFRR(2, 3);

/*
 * Iterate over all libyang data nodes that satisfy an XPath query.
 *
 * cb
 *    Function to call with each data node.
 *
 * arg
 *    Arbitrary argument passed as the second parameter in each call to 'cb'.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath_fmt
 *    XPath expression (absolute or relative).
 *
 * ...
 *    any parameters for xpath_fmt.
 */
void yang_dnode_iterate(yang_dnode_iter_cb cb, void *arg,
			const struct lyd_node *dnode, const char *xpath_fmt,
			...) PRINTFRR(4, 5);

/*
 * Check if the libyang data node contains a default value. Non-presence
 * containers are assumed to always contain a default value.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath
 *    Optional XPath expression (absolute or relative) to specify a different
 *    data node to operate on in the same data tree.
 *
 * Returns:
 *    true if the data node contains the default value, false otherwise.
 */
extern bool yang_dnode_is_default(const struct lyd_node *dnode,
				  const char *xpath);

/*
 * Check if the libyang data node contains a default value. Non-presence
 * containers are assumed to always contain a default value.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath
 *    Optional limited XPath (absolute or relative) format string. See Path in
 *    libyang documentation for restrictions.
 *
 * ...
 *    any parameters for xpath_fmt.
 *
 * Returns:
 *    true if the data node contains the default value, false otherwise.
 */
extern bool yang_dnode_is_defaultf(const struct lyd_node *dnode,
				   const char *xpath_fmt, ...) PRINTFRR(2, 3);

/*
 * Check if the libyang data node and all of its children contain default
 * values. Non-presence containers are assumed to always contain a default
 * value.
 *
 * dnode
 *    libyang data node to operate on.
 *
 * Returns:
 *    true if the data node and all of its children contain default values,
 *    false otherwise.
 */
extern bool yang_dnode_is_default_recursive(const struct lyd_node *dnode);

/*
 * Change the value of a libyang leaf node.
 *
 * dnode
 *    libyang data node to operate on.
 *
 * value
 *    String representing the new value.
 */
extern void yang_dnode_change_leaf(struct lyd_node *dnode, const char *value);

/*
 * Create a new libyang data node.
 *
 * ly_ctx
 *    libyang context to operate on.
 *
 * config
 *    Specify whether the data node will contain only configuration data (true)
 *    or both configuration data and state data (false).
 *
 * Returns:
 *    Pointer to newly created libyang data node.
 */
extern struct lyd_node *yang_dnode_new(struct ly_ctx *ly_ctx, bool config_only);

/*
 * Duplicate a libyang data node.
 *
 * dnode
 *    libyang data node to duplicate.
 *
 * Returns:
 *    Pointer to duplicated libyang data node.
 */
extern struct lyd_node *yang_dnode_dup(const struct lyd_node *dnode);

/*
 * Delete a libyang data node.
 *
 * dnode
 *    Pointer to the libyang data node that is going to be deleted along with
 *    the entire tree it belongs to.
 */
extern void yang_dnode_free(struct lyd_node *dnode);

/*
 * Create a new yang_data structure.
 *
 * xpath
 *    Data path of the YANG data.
 *
 * value
 *    String representing the value of the YANG data.
 *
 * Returns:
 *    Pointer to newly created yang_data structure.
 */
extern struct yang_data *yang_data_new(const char *xpath, const char *value);

/*
 * Delete a yang_data structure.
 *
 * data
 *    yang_data to delete.
 */
extern void yang_data_free(struct yang_data *data);

/*
 * Create a new linked list of yang_data structures. The list 'del' callback is
 * initialized appropriately so that the entire list can be deleted safely with
 * list_delete_and_null().
 *
 * Returns:
 *    Pointer to newly created linked list.
 */
extern struct list *yang_data_list_new(void);

/*
 * Find the yang_data structure corresponding to an XPath in a list.
 *
 * list
 *    list of yang_data structures to operate on.
 *
 * xpath_fmt
 *    XPath to search for (format string).
 *
 * Returns:
 *    Pointer to yang_data if found, NULL otherwise.
 */
extern struct yang_data *yang_data_list_find(const struct list *list,
					     const char *xpath_fmt, ...)
	PRINTFRR(2, 3);

/*
 * Create and set up a libyang context (for use by the translator)
 *
 * embedded_modules
 *    Specify whether libyang should attempt to look for embedded YANG modules.
 *
 * explicit_compile
 *    True if the caller will later call ly_ctx_compile to compile all loaded
 *    modules at once.
 */
extern struct ly_ctx *yang_ctx_new_setup(bool embedded_modules,
					 bool explicit_compile);

/*
 * Enable or disable libyang verbose debugging.
 *
 * enable
 *    When set to true, enable libyang verbose debugging, otherwise disable it.
 */
extern void yang_debugging_set(bool enable);


/*
 * "Print" the yang tree in `root` into dynamic sized array.
 *
 * Args:
 *	root: root of the subtree to "print" along with siblings.
 *	format: LYD_FORMAT of output (see lyd_print_mem)
 *	options: printing options (see lyd_print_mem)
 *
 * Return:
 *	A darr dynamic array with the "printed" output or NULL on failure.
 */
extern uint8_t *yang_print_tree(const struct lyd_node *root, LYD_FORMAT format,
				uint32_t options);

/*
 * "Print" the yang tree in `root` into an existing dynamic sized array.
 *
 * This function does not initialize or free the dynamic array, the array can
 * already existing data, the tree will be appended to this data.
 *
 * Args:
 *	darr: existing `uint8_t *`, dynamic array.
 *	root: root of the subtree to "print" along with siblings.
 *	format: LYD_FORMAT of output (see lyd_print_mem)
 *	options: printing options (see lyd_print_mem)
 *
 * Return:
 *	LY_ERR from underlying calls.
 */
extern LY_ERR yang_print_tree_append(uint8_t **darr, const struct lyd_node *root,
				     LYD_FORMAT format, uint32_t options);

/*
 * Print libyang error messages into the provided buffer.
 *
 * ly_ctx
 *    libyang context to operate on.
 *
 * buf
 *    Buffer to store the libyang error messages.
 *
 * buf_len
 *    Size of buf.
 *
 * Returns:
 *    The provided buffer.
 */
extern const char *yang_print_errors(struct ly_ctx *ly_ctx, char *buf,
				     size_t buf_len);

/*
 * Initialize the YANG subsystem. Should be called only once during the
 * daemon initialization process.
 *
 * embedded_modules
 *    Specify whether libyang should attempt to look for embedded YANG modules.
 * defer_compile
 *    Hold off on compiling modules until yang_init_loading_complete is called.
 */
extern void yang_init(bool embedded_modules, bool defer_compile);

/*
 * Should be called after yang_init and all yang_module_load()s have been done,
 * compiles all modules loaded into the yang context.
 */
extern void yang_init_loading_complete(void);

/*
 * Finish the YANG subsystem gracefully. Should be called only when the daemon
 * is exiting.
 */
extern void yang_terminate(void);

/*
 * API to return the parent dnode having a given schema-node name
 * Use case: One has to access the parent dnode's private pointer
 * for a given child node.
 * For that there is a need to find parent dnode first.
 *
 * dnode The starting node to work on
 *
 * name  The name of container/list schema-node
 *
 * Returns The dnode matched with the given name
 */
extern const struct lyd_node *
yang_dnode_get_parent(const struct lyd_node *dnode, const char *name);


/*
 * In some cases there is a need to auto delete the parent nodes
 * if the given node is last in the list.
 * It tries to delete all the parents in a given tree in a given module.
 * The use case is with static routes and route maps
 * example : ip route 1.1.1.1/32 ens33
 *           ip route 1.1.1.1/32 ens34
 * After this no ip route 1.1.1.1/32 ens34 came, now staticd
 * has to find out upto which level it has to delete the dnodes.
 * For this case it has to send delete nexthop
 * After this no ip route 1.1.1.1/32 ens33 came, now staticd has to
 * clear nexthop, path and route nodes.
 * The same scheme is required for routemaps also
 * dnode The starting node to work on
 *
 * Returns The final parent node selected for deletion
 */
extern const struct lyd_node *
yang_get_subtree_with_no_sibling(const struct lyd_node *dnode);

/* To get the relative position of a node in list */
extern uint32_t yang_get_list_pos(const struct lyd_node *node);

/* To get the number of elements in a list
 *
 * dnode : The head of list
 * Returns : The number of dnodes present in the list
 */
extern uint32_t yang_get_list_elements_count(const struct lyd_node *node);

/* API to check if the given node is last node in the list */
bool yang_is_last_list_dnode(const struct lyd_node *dnode);

/* API to check if the given node is last node in the data tree level */
bool yang_is_last_level_dnode(const struct lyd_node *dnode);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_YANG_H_ */
