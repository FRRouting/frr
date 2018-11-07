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
#include "log_int.h"
#include "lib_errors.h"
#include "yang.h"
#include "yang_translator.h"
#include "northbound.h"

DEFINE_MTYPE(LIB, YANG_MODULE, "YANG module")
DEFINE_MTYPE(LIB, YANG_DATA, "YANG data structure")

/* libyang container. */
struct ly_ctx *ly_native_ctx;

/* Generate the yang_modules tree. */
static inline int yang_module_compare(const struct yang_module *a,
				      const struct yang_module *b)
{
	return strcmp(a->name, b->name);
}
RB_GENERATE(yang_modules, yang_module, entry, yang_module_compare)

struct yang_modules yang_modules = RB_INITIALIZER(&yang_modules);

struct yang_module *yang_module_load(const char *module_name)
{
	struct yang_module *module;
	const struct lys_module *module_info;

	module_info = ly_ctx_load_module(ly_native_ctx, module_name, NULL);
	if (!module_info) {
		flog_err(EC_LIB_YANG_MODULE_LOAD,
			 "%s: failed to load data model: %s", __func__,
			 module_name);
		exit(1);
	}

	module = XCALLOC(MTYPE_YANG_MODULE, sizeof(*module));
	module->name = module_name;
	module->info = module_info;

	if (RB_INSERT(yang_modules, &yang_modules, module) != NULL) {
		flog_err(EC_LIB_YANG_MODULE_LOADED_ALREADY,
			 "%s: YANG module is loaded already: %s", __func__,
			 module_name);
		exit(1);
	}

	return module;
}

struct yang_module *yang_module_find(const char *module_name)
{
	struct yang_module s;

	s.name = module_name;
	return RB_FIND(yang_modules, &yang_modules, &s);
}

/*
 * Helper function for yang_module_snodes_iterate() and
 * yang_all_snodes_iterate(). This is a recursive function.
 */
static void yang_snodes_iterate(const struct lys_node *snode,
				void (*func)(const struct lys_node *, void *,
					     void *),
				uint16_t flags, void *arg1, void *arg2)
{
	struct lys_node *child;

	if (CHECK_FLAG(flags, YANG_ITER_FILTER_IMPLICIT)) {
		switch (snode->nodetype) {
		case LYS_CASE:
		case LYS_INPUT:
		case LYS_OUTPUT:
			if (snode->flags & LYS_IMPLICIT)
				goto next;
			break;
		default:
			break;
		}
	}

	switch (snode->nodetype) {
	case LYS_CONTAINER:
		if (CHECK_FLAG(flags, YANG_ITER_FILTER_NPCONTAINERS)) {
			struct lys_node_container *scontainer;

			scontainer = (struct lys_node_container *)snode;
			if (!scontainer->presence)
				goto next;
		}
		break;
	case LYS_LEAF:
		if (CHECK_FLAG(flags, YANG_ITER_FILTER_LIST_KEYS)) {
			struct lys_node_leaf *sleaf;

			/* Ignore list keys. */
			sleaf = (struct lys_node_leaf *)snode;
			if (lys_is_key(sleaf, NULL))
				goto next;
		}
		break;
	case LYS_GROUPING:
		/* Return since we're not interested in the grouping subtree. */
		return;
	case LYS_USES:
	case LYS_AUGMENT:
		/* Always ignore nodes of these types. */
		goto next;
	case LYS_INPUT:
	case LYS_OUTPUT:
		if (CHECK_FLAG(flags, YANG_ITER_FILTER_INPUT_OUTPUT))
			goto next;
		break;
	default:
		break;
	}

	(*func)(snode, arg1, arg2);

next:
	/*
	 * YANG leafs and leaf-lists can't have child nodes, and trying to
	 * access snode->child is undefined behavior.
	 */
	if (snode->nodetype & (LYS_LEAF | LYS_LEAFLIST))
		return;

	LY_TREE_FOR (snode->child, child) {
		if (child->parent != snode)
			continue;
		yang_snodes_iterate(child, func, flags, arg1, arg2);
	}
}

void yang_module_snodes_iterate(const struct lys_module *module,
				void (*func)(const struct lys_node *, void *,
					     void *),
				uint16_t flags, void *arg1, void *arg2)
{
	struct lys_node *snode;

	LY_TREE_FOR (module->data, snode) {
		yang_snodes_iterate(snode, func, flags, arg1, arg2);
	}

	for (uint8_t i = 0; i < module->augment_size; i++) {
		yang_snodes_iterate(
			(const struct lys_node *)&module->augment[i], func,
			flags, arg1, arg2);
	}
}

void yang_all_snodes_iterate(void (*func)(const struct lys_node *, void *,
					  void *),
			     uint16_t flags, void *arg1, void *arg2)
{
	struct yang_module *module;

	RB_FOREACH (module, yang_modules, &yang_modules)
		yang_module_snodes_iterate(module->info, func, flags, arg1,
					   arg2);
}

void yang_snode_get_path(const struct lys_node *snode, enum yang_path_type type,
			 char *xpath, size_t xpath_len)
{
	char *xpath_ptr;

	switch (type) {
	case YANG_PATH_SCHEMA:
		xpath_ptr = lys_path(snode, 0);
		break;
	case YANG_PATH_DATA:
		xpath_ptr = lys_data_path(snode);
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown yang path type: %u",
			 __func__, type);
		exit(1);
	}
	strlcpy(xpath, xpath_ptr, xpath_len);
	free(xpath_ptr);
}

struct lys_node *yang_snode_real_parent(const struct lys_node *snode)
{
	struct lys_node *parent = snode->parent;

	while (parent) {
		struct lys_node_container *scontainer;

		switch (parent->nodetype) {
		case LYS_CONTAINER:
			scontainer = (struct lys_node_container *)parent;
			if (scontainer->presence)
				return parent;
			break;
		case LYS_LIST:
			return parent;
		default:
			break;
		}
		parent = parent->parent;
	}

	return NULL;
}

struct lys_node *yang_snode_parent_list(const struct lys_node *snode)
{
	struct lys_node *parent = snode->parent;

	while (parent) {
		switch (parent->nodetype) {
		case LYS_LIST:
			return parent;
		default:
			break;
		}
		parent = parent->parent;
	}

	return NULL;
}

bool yang_snode_is_typeless_data(const struct lys_node *snode)
{
	struct lys_node_leaf *sleaf;

	switch (snode->nodetype) {
	case LYS_LEAF:
		sleaf = (struct lys_node_leaf *)snode;
		if (sleaf->type.base == LY_TYPE_EMPTY)
			return true;
		return false;
	case LYS_LEAFLIST:
		return false;
	default:
		return true;
	}
}

const char *yang_snode_get_default(const struct lys_node *snode)
{
	struct lys_node_leaf *sleaf;

	switch (snode->nodetype) {
	case LYS_LEAF:
		sleaf = (struct lys_node_leaf *)snode;

		/* NOTE: this might be null. */
		return sleaf->dflt;
	case LYS_LEAFLIST:
		/* TODO: check leaf-list default values */
		return NULL;
	default:
		return NULL;
	}
}

const struct lys_type *yang_snode_get_type(const struct lys_node *snode)
{
	struct lys_node_leaf *sleaf = (struct lys_node_leaf *)snode;
	struct lys_type *type;

	if (!(sleaf->nodetype & (LYS_LEAF | LYS_LEAFLIST)))
		return NULL;

	type = &sleaf->type;
	while (type->base == LY_TYPE_LEAFREF)
		type = &type->info.lref.target->type;

	return type;
}

void yang_dnode_get_path(const struct lyd_node *dnode, char *xpath,
			 size_t xpath_len)
{
	char *xpath_ptr;

	xpath_ptr = lyd_path(dnode);
	strlcpy(xpath, xpath_ptr, xpath_len);
	free(xpath_ptr);
}

struct lyd_node *yang_dnode_get(const struct lyd_node *dnode,
				const char *xpath_fmt, ...)
{
	va_list ap;
	char xpath[XPATH_MAXLEN];
	struct ly_set *set;
	struct lyd_node *dnode_ret = NULL;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	set = lyd_find_path(dnode, xpath);
	assert(set);
	if (set->number == 0)
		goto exit;

	if (set->number > 1) {
		flog_warn(EC_LIB_YANG_DNODE_NOT_FOUND,
			  "%s: found %u elements (expected 0 or 1) [xpath %s]",
			  __func__, set->number, xpath);
		goto exit;
	}

	dnode_ret = set->set.d[0];

exit:
	ly_set_free(set);

	return dnode_ret;
}

bool yang_dnode_exists(const struct lyd_node *dnode, const char *xpath_fmt, ...)
{
	va_list ap;
	char xpath[XPATH_MAXLEN];
	struct ly_set *set;
	bool found;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	set = lyd_find_path(dnode, xpath);
	assert(set);
	found = (set->number > 0);
	ly_set_free(set);

	return found;
}

bool yang_dnode_is_default(const struct lyd_node *dnode, const char *xpath_fmt,
			   ...)
{
	struct lys_node *snode;
	struct lys_node_leaf *sleaf;
	struct lys_node_container *scontainer;

	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);

		dnode = yang_dnode_get(dnode, xpath);
	}

	assert(dnode);
	snode = dnode->schema;
	switch (snode->nodetype) {
	case LYS_LEAF:
		sleaf = (struct lys_node_leaf *)snode;
		if (sleaf->type.base == LY_TYPE_EMPTY)
			return false;
		return lyd_wd_default((struct lyd_node_leaf_list *)dnode);
	case LYS_LEAFLIST:
		/* TODO: check leaf-list default values */
		return false;
	case LYS_CONTAINER:
		scontainer = (struct lys_node_container *)snode;
		if (scontainer->presence)
			return false;
		return true;
	default:
		return false;
	}
}

bool yang_dnode_is_default_recursive(const struct lyd_node *dnode)
{
	struct lys_node *snode;
	struct lyd_node *root, *next, *dnode_iter;

	snode = dnode->schema;
	if (snode->nodetype & (LYS_LEAF | LYS_LEAFLIST))
		return yang_dnode_is_default(dnode, NULL);

	if (!yang_dnode_is_default(dnode, NULL))
		return false;

	LY_TREE_FOR (dnode->child, root) {
		LY_TREE_DFS_BEGIN (root, next, dnode_iter) {
			if (!yang_dnode_is_default(dnode_iter, NULL))
				return false;

			LY_TREE_DFS_END(root, next, dnode_iter);
		}
	}

	return true;
}

void yang_dnode_change_leaf(struct lyd_node *dnode, const char *value)
{
	assert(dnode->schema->nodetype == LYS_LEAF);
	lyd_change_leaf((struct lyd_node_leaf_list *)dnode, value);
}

void yang_dnode_set_entry(const struct lyd_node *dnode, void *entry)
{
	assert(dnode->schema->nodetype & (LYS_LIST | LYS_CONTAINER));
	lyd_set_private(dnode, entry);
}

void *yang_dnode_get_entry(const struct lyd_node *dnode)
{
	const struct lyd_node *orig_dnode = dnode;
	char xpath[XPATH_MAXLEN];

	while (dnode) {
		switch (dnode->schema->nodetype) {
		case LYS_CONTAINER:
		case LYS_LIST:
			if (dnode->priv)
				return dnode->priv;
			break;
		default:
			break;
		}

		dnode = dnode->parent;
	}

	yang_dnode_get_path(orig_dnode, xpath, sizeof(xpath));
	flog_err(EC_LIB_YANG_DNODE_NOT_FOUND,
		 "%s: failed to find entry [xpath %s]", __func__, xpath);
	zlog_backtrace(LOG_ERR);
	abort();
}

struct lyd_node *yang_dnode_new(struct ly_ctx *ly_ctx)
{
	struct lyd_node *dnode;

	dnode = NULL;
	if (lyd_validate(&dnode, LYD_OPT_CONFIG, ly_ctx) != 0) {
		/* Should never happen. */
		flog_err(EC_LIB_LIBYANG, "%s: lyd_validate() failed", __func__);
		exit(1);
	}

	return dnode;
}

struct lyd_node *yang_dnode_dup(const struct lyd_node *dnode)
{
	return lyd_dup_withsiblings(dnode, 1);
}

void yang_dnode_free(struct lyd_node *dnode)
{
	lyd_free_withsiblings(dnode);
}

struct yang_data *yang_data_new(const char *xpath, const char *value)
{
	const struct lys_node *snode;
	struct yang_data *data;

	snode = ly_ctx_get_node(ly_native_ctx, NULL, xpath, 0);
	if (!snode)
		snode = ly_ctx_get_node(ly_native_ctx, NULL, xpath, 1);
	if (!snode) {
		flog_err(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			 "%s: unknown data path: %s", __func__, xpath);
		zlog_backtrace(LOG_ERR);
		abort();
	}

	data = XCALLOC(MTYPE_YANG_DATA, sizeof(*data));
	strlcpy(data->xpath, xpath, sizeof(data->xpath));
	data->snode = snode;
	if (value)
		data->value = strdup(value);

	return data;
}

void yang_data_free(struct yang_data *data)
{
	if (data->value)
		free(data->value);
	XFREE(MTYPE_YANG_DATA, data);
}

struct list *yang_data_list_new(void)
{
	struct list *list;

	list = list_new();
	list->del = (void (*)(void *))yang_data_free;

	return list;
}

static void *ly_dup_cb(const void *priv)
{
	/* Make a shallow copy of the priv pointer. */
	return (void *)priv;
}

/* Make libyang log its errors using FRR logging infrastructure. */
static void ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
	int priority;

	switch (level) {
	case LY_LLERR:
		priority = LOG_ERR;
		break;
	case LY_LLWRN:
		priority = LOG_WARNING;
		break;
	case LY_LLVRB:
		priority = LOG_DEBUG;
		break;
	default:
		return;
	}

	if (path)
		zlog(priority, "libyang: %s (%s)", msg, path);
	else
		zlog(priority, "libyang: %s", msg);
}

void yang_init(void)
{
	static char ly_plugin_dir[PATH_MAX];
	const char *const *ly_loaded_plugins;
	const char *ly_plugin;
	bool found_ly_frr_types = false;

	/* Tell libyang where to find its plugins. */
	snprintf(ly_plugin_dir, sizeof(ly_plugin_dir), "%s=%s",
		 "LIBYANG_USER_TYPES_PLUGINS_DIR", LIBYANG_PLUGINS_PATH);
	putenv(ly_plugin_dir);

	/* Initialize libyang global parameters that affect all containers. */
	ly_set_log_clb(ly_log_cb, 1);
	ly_log_options(LY_LOLOG | LY_LOSTORE);

	/* Initialize libyang container for native models. */
	ly_native_ctx = ly_ctx_new(NULL, LY_CTX_DISABLE_SEARCHDIR_CWD);
	if (!ly_native_ctx) {
		flog_err(EC_LIB_LIBYANG, "%s: ly_ctx_new() failed", __func__);
		exit(1);
	}
	ly_ctx_set_searchdir(ly_native_ctx, YANG_MODELS_PATH);
	ly_ctx_set_priv_dup_clb(ly_native_ctx, ly_dup_cb);

	/* Detect if the required libyang plugin(s) were loaded successfully. */
	ly_loaded_plugins = ly_get_loaded_plugins();
	for (size_t i = 0; (ly_plugin = ly_loaded_plugins[i]); i++) {
		if (strmatch(ly_plugin, "frr_user_types")) {
			found_ly_frr_types = true;
			break;
		}
	}
	if (!found_ly_frr_types) {
		flog_err(EC_LIB_LIBYANG_PLUGIN_LOAD,
			 "%s: failed to load frr_user_types.so", __func__);
		exit(1);
	}

	yang_translator_init();
}

void yang_terminate(void)
{
	struct yang_module *module;

	yang_translator_terminate();

	while (!RB_EMPTY(yang_modules, &yang_modules)) {
		module = RB_ROOT(yang_modules, &yang_modules);

		/*
		 * We shouldn't call ly_ctx_remove_module() here because this
		 * function also removes other modules that depend on it.
		 *
		 * ly_ctx_destroy() will release all memory for us.
		 */
		RB_REMOVE(yang_modules, &yang_modules, module);
		XFREE(MTYPE_YANG_MODULE, module);
	}

	ly_ctx_destroy(ly_native_ctx, NULL);
}
