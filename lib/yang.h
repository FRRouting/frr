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
#define XPATH_MAXLEN 256

/* Maximum list key length. */
#define LIST_MAXKEYS 8

/* Maximum list key length. */
#define LIST_MAXKEYLEN 128

/* Maximum string length of an YANG value. */
#define YANG_VALUE_MAXLEN 1024

struct yang_module_embed {
	struct yang_module_embed *next;
	const char *mod_name, *mod_rev;
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

	/* Filter implicitely created nodes. */
	YANG_ITER_FILTER_IMPLICIT = (1<<3),

	/* Allow iteration over augmentations. */
	YANG_ITER_ALLOW_AUGMENTATIONS = (1<<4),
};

/* Callback used by the yang_snodes_iterate_*() family of functions. */
typedef int (*yang_iterate_cb)(const struct lys_node *snode, void *arg);

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
extern int yang_snodes_iterate_subtree(const struct lys_node *snode,
				       yang_iterate_cb cb, uint16_t flags,
				       void *arg);

/*
 * Iterate over all libyang schema nodes from the given YANG module.
 *
 * module
 *    YANG module to operate on.
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
extern int yang_snodes_iterate_module(const struct lys_module *module,
				      yang_iterate_cb cb, uint16_t flags,
				      void *arg);

/*
 * Iterate over all libyang schema nodes from all loaded YANG modules.
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
extern int yang_snodes_iterate_all(yang_iterate_cb cb, uint16_t flags,
				   void *arg);

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
extern void yang_snode_get_path(const struct lys_node *snode,
				enum yang_path_type type, char *xpath,
				size_t xpath_len);

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
extern struct lys_node *yang_snode_real_parent(const struct lys_node *snode);

/*
 * Find first parent schema node which is a list.
 *
 * snode
 *    libyang schema node to operate on.
 *
 * Returns:
 *    The parent libyang schema node (list) if found, or NULL if not found.
 */
extern struct lys_node *yang_snode_parent_list(const struct lys_node *snode);

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
extern bool yang_snode_is_typeless_data(const struct lys_node *snode);

/*
 * Get the default value associated to a YANG leaf or leaf-list.
 *
 * snode
 *    libyang schema node to operate on.
 *
 * Returns:
 *    The default value if it exists, NULL otherwise.
 */
extern const char *yang_snode_get_default(const struct lys_node *snode);

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
extern const struct lys_type *yang_snode_get_type(const struct lys_node *snode);

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
					      const char *xpath_fmt, ...);

/*
 * Find a libyang data node by its YANG data path.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath_fmt
 *    XPath expression (absolute or relative).
 *
 * Returns:
 *    The libyang data node if found, or NULL if not found.
 */
extern struct lyd_node *yang_dnode_get(const struct lyd_node *dnode,
				       const char *xpath_fmt, ...);

/*
 * Check if a libyang data node exists.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath_fmt
 *    XPath expression (absolute or relative).
 *
 * Returns:
 *    true if the libyang data node was found, false otherwise.
 */
extern bool yang_dnode_exists(const struct lyd_node *dnode,
			      const char *xpath_fmt, ...);

/*
 * Check if the libyang data node contains a default value. Non-presence
 * containers are assumed to always contain a default value.
 *
 * dnode
 *    Base libyang data node to operate on.
 *
 * xpath_fmt
 *    Optional XPath expression (absolute or relative) to specify a different
 *    data node to operate on in the same data tree.
 *
 * Returns:
 *    true if the data node contains the default value, false otherwise.
 */
extern bool yang_dnode_is_default(const struct lyd_node *dnode,
				  const char *xpath_fmt, ...);

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
 *    Pointer to the libyang data node that is going to be deleted.
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
					     const char *xpath_fmt, ...);

/*
 * Create and set up a libyang context (for use by the translator)
 */
extern struct ly_ctx *yang_ctx_new_setup(void);

/*
 * Enable or disable libyang verbose debugging.
 *
 * enable
 *    When set to true, enable libyang verbose debugging, otherwise disable it.
 */
extern void yang_debugging_set(bool enable);

/*
 * Initialize the YANG subsystem. Should be called only once during the
 * daemon initialization process.
 */
extern void yang_init(void);

/*
 * Finish the YANG subsystem gracefully. Should be called only when the daemon
 * is exiting.
 */
extern void yang_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_YANG_H_ */
