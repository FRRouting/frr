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
#include "yang.h"
#include "yang_translator.h"
#include "northbound.h"

#include <libyang/user_types.h>

DEFINE_MTYPE_STATIC(LIB, YANG_MODULE, "YANG module")
DEFINE_MTYPE_STATIC(LIB, YANG_DATA, "YANG data structure")

/* libyang container. */
struct ly_ctx *ly_native_ctx;

static struct yang_module_embed *embeds, **embedupd = &embeds;

void yang_module_embed(struct yang_module_embed *embed)
{
	embed->next = NULL;
	*embedupd = embed;
	embedupd = &embed->next;
}

static const char *yang_module_imp_clb(const char *mod_name,
				       const char *mod_rev,
				       const char *submod_name,
				       const char *submod_rev,
				       void *user_data,
				       LYS_INFORMAT *format,
				       void (**free_module_data)
						(void *, void*))
{
	struct yang_module_embed *e;

	for (e = embeds; e; e = e->next) {
		if (e->sub_mod_name && submod_name) {
			if (strcmp(e->sub_mod_name, submod_name))
				continue;

			if (submod_rev && strcmp(e->sub_mod_rev, submod_rev))
				continue;
		} else {
			if (strcmp(e->mod_name, mod_name))
				continue;

			if (mod_rev && strcmp(e->mod_rev, mod_rev))
				continue;
		}

		*format = e->format;
		return e->data;
	}

	flog_warn(
		EC_LIB_YANG_MODULE_LOAD,
		"YANG model \"%s@%s\" \"%s@%s\"not embedded, trying external file",
		mod_name, mod_rev ? mod_rev : "*",
		submod_name ? submod_name : "*", submod_rev ? submod_rev : "*");
	return NULL;
}

/* clang-format off */
static const char *const frr_native_modules[] = {
	"frr-interface",
	"frr-vrf",
	"frr-routing",
	"frr-route-map",
	"frr-nexthop",
	"frr-ripd",
	"frr-ripngd",
	"frr-isisd",
	"frr-vrrpd",
	"frr-zebra",
};
/* clang-format on */

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

void yang_module_load_all(void)
{
	for (size_t i = 0; i < array_size(frr_native_modules); i++)
		yang_module_load(frr_native_modules[i]);
}

struct yang_module *yang_module_find(const char *module_name)
{
	struct yang_module s;

	s.name = module_name;
	return RB_FIND(yang_modules, &yang_modules, &s);
}

int yang_snodes_iterate_subtree(const struct lys_node *snode,
				const struct lys_module *module,
				yang_iterate_cb cb, uint16_t flags, void *arg)
{
	struct lys_node *child;
	int ret = YANG_ITER_CONTINUE;

	if (module && snode->module != module)
		goto next;

	if (CHECK_FLAG(flags, YANG_ITER_FILTER_IMPLICIT)) {
		switch (snode->nodetype) {
		case LYS_CASE:
		case LYS_INPUT:
		case LYS_OUTPUT:
			if (CHECK_FLAG(snode->flags, LYS_IMPLICIT))
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
		return YANG_ITER_CONTINUE;
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

	ret = (*cb)(snode, arg);
	if (ret == YANG_ITER_STOP)
		return ret;

next:
	/*
	 * YANG leafs and leaf-lists can't have child nodes, and trying to
	 * access snode->child is undefined behavior.
	 */
	if (CHECK_FLAG(snode->nodetype, LYS_LEAF | LYS_LEAFLIST))
		return YANG_ITER_CONTINUE;

	LY_TREE_FOR (snode->child, child) {
		ret = yang_snodes_iterate_subtree(child, module, cb, flags,
						  arg);
		if (ret == YANG_ITER_STOP)
			return ret;
	}

	return ret;
}

int yang_snodes_iterate_module(const struct lys_module *module,
			       yang_iterate_cb cb, uint16_t flags, void *arg)
{
	struct lys_node *snode;
	int ret = YANG_ITER_CONTINUE;

	LY_TREE_FOR (module->data, snode) {
		ret = yang_snodes_iterate_subtree(snode, module, cb, flags,
						  arg);
		if (ret == YANG_ITER_STOP)
			return ret;
	}

	for (uint8_t i = 0; i < module->augment_size; i++) {
		ret = yang_snodes_iterate_subtree(
			(const struct lys_node *)&module->augment[i], module,
			cb, flags, arg);
		if (ret == YANG_ITER_STOP)
			return ret;
	}

	return ret;
}

int yang_snodes_iterate_all(yang_iterate_cb cb, uint16_t flags, void *arg)
{
	struct yang_module *module;
	int ret = YANG_ITER_CONTINUE;

	RB_FOREACH (module, yang_modules, &yang_modules) {
		struct lys_node *snode;

		LY_TREE_FOR (module->info->data, snode) {
			ret = yang_snodes_iterate_subtree(snode, NULL, cb,
							  flags, arg);
			if (ret == YANG_ITER_STOP)
				return ret;
		}
	}

	return ret;
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

	if (!CHECK_FLAG(sleaf->nodetype, LYS_LEAF | LYS_LEAFLIST))
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

const char *yang_dnode_get_schema_name(const struct lyd_node *dnode,
				       const char *xpath_fmt, ...)
{
	if (xpath_fmt) {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);

		dnode = yang_dnode_get(dnode, xpath);
		if (!dnode) {
			flog_err(EC_LIB_YANG_DNODE_NOT_FOUND,
				 "%s: couldn't find %s", __func__, xpath);
			zlog_backtrace(LOG_ERR);
			abort();
		}
	}

	return dnode->schema->name;
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

void yang_dnode_iterate(yang_dnode_iter_cb cb, void *arg,
			const struct lyd_node *dnode, const char *xpath_fmt,
			...)
{
	va_list ap;
	char xpath[XPATH_MAXLEN];
	struct ly_set *set;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	set = lyd_find_path(dnode, xpath);
	assert(set);
	for (unsigned int i = 0; i < set->number; i++) {
		int ret;

		dnode = set->set.d[i];
		ret = (*cb)(dnode, arg);
		if (ret == YANG_ITER_STOP)
			return;
	}

	ly_set_free(set);
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
	if (CHECK_FLAG(snode->nodetype, LYS_LEAF | LYS_LEAFLIST))
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

struct lyd_node *yang_dnode_new(struct ly_ctx *ly_ctx, bool config_only)
{
	struct lyd_node *dnode;
	int options;

	if (config_only)
		options = LYD_OPT_CONFIG;
	else
		options = LYD_OPT_DATA | LYD_OPT_DATA_NO_YANGLIB;

	dnode = NULL;
	if (lyd_validate(&dnode, options, ly_ctx) != 0) {
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
	while (dnode->parent)
		dnode = dnode->parent;
	lyd_free_withsiblings(dnode);
}

struct yang_data *yang_data_new(const char *xpath, const char *value)
{
	struct yang_data *data;

	data = XCALLOC(MTYPE_YANG_DATA, sizeof(*data));
	strlcpy(data->xpath, xpath, sizeof(data->xpath));
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

struct yang_data *yang_data_list_find(const struct list *list,
				      const char *xpath_fmt, ...)
{
	char xpath[XPATH_MAXLEN];
	struct yang_data *data;
	struct listnode *node;
	va_list ap;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	for (ALL_LIST_ELEMENTS_RO(list, node, data))
		if (strmatch(data->xpath, xpath))
			return data;

	return NULL;
}

/* Make libyang log its errors using FRR logging infrastructure. */
static void ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
	int priority = LOG_ERR;

	switch (level) {
	case LY_LLERR:
		priority = LOG_ERR;
		break;
	case LY_LLWRN:
		priority = LOG_WARNING;
		break;
	case LY_LLVRB:
	case LY_LLDBG:
		priority = LOG_DEBUG;
		break;
	}

	if (path)
		zlog(priority, "libyang: %s (%s)", msg, path);
	else
		zlog(priority, "libyang: %s", msg);
}

const char *yang_print_errors(struct ly_ctx *ly_ctx, char *buf, size_t buf_len)
{
	struct ly_err_item *ei;
	const char *path;

	ei = ly_err_first(ly_ctx);
	if (!ei)
		return "";

	strlcpy(buf, "YANG error(s):\n", buf_len);
	for (; ei; ei = ei->next) {
		strlcat(buf, " ", buf_len);
		strlcat(buf, ei->msg, buf_len);
		strlcat(buf, "\n", buf_len);
	}

	path = ly_errpath(ly_ctx);
	if (path) {
		strlcat(buf, " YANG path: ", buf_len);
		strlcat(buf, path, buf_len);
		strlcat(buf, "\n", buf_len);
	}

	ly_err_clean(ly_ctx, NULL);

	return buf;
}

void yang_debugging_set(bool enable)
{
	if (enable) {
		ly_verb(LY_LLDBG);
		ly_verb_dbg(0xFF);
	} else {
		ly_verb(LY_LLERR);
		ly_verb_dbg(0);
	}
}

struct ly_ctx *yang_ctx_new_setup(bool embedded_modules)
{
	struct ly_ctx *ctx;
	const char *yang_models_path = YANG_MODELS_PATH;

	if (access(yang_models_path, R_OK | X_OK)) {
		yang_models_path = NULL;
		if (errno == ENOENT)
			zlog_info("yang model directory \"%s\" does not exist",
				  YANG_MODELS_PATH);
		else
			flog_err_sys(EC_LIB_LIBYANG,
				     "cannot access yang model directory \"%s\"",
				     YANG_MODELS_PATH);
	}

	ctx = ly_ctx_new(yang_models_path, LY_CTX_DISABLE_SEARCHDIR_CWD);
	if (!ctx)
		return NULL;

	if (embedded_modules)
		ly_ctx_set_module_imp_clb(ctx, yang_module_imp_clb, NULL);

	return ctx;
}

void yang_init(bool embedded_modules)
{
	/* Initialize libyang global parameters that affect all containers. */
	ly_set_log_clb(ly_log_cb, 1);
	ly_log_options(LY_LOLOG | LY_LOSTORE);

	/* Initialize libyang container for native models. */
	ly_native_ctx = yang_ctx_new_setup(embedded_modules);
	if (!ly_native_ctx) {
		flog_err(EC_LIB_LIBYANG, "%s: ly_ctx_new() failed", __func__);
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

const struct lyd_node *yang_dnode_get_parent(const struct lyd_node *dnode,
					     const char *name)
{
	const struct lyd_node *orig_dnode = dnode;

	while (orig_dnode) {
		switch (orig_dnode->schema->nodetype) {
		case LYS_LIST:
		case LYS_CONTAINER:
			if (!strcmp(orig_dnode->schema->name, name))
				return orig_dnode;
			break;
		default:
			break;
		}

		orig_dnode = orig_dnode->parent;
	}

	return NULL;
}

bool yang_is_last_list_dnode(const struct lyd_node *dnode)
{
	return (((dnode->next == NULL)
	     || (dnode->next
		 && (strcmp(dnode->next->schema->name, dnode->schema->name)
		     != 0)))
	    && dnode->prev
	    && ((dnode->prev == dnode)
		|| (strcmp(dnode->prev->schema->name, dnode->schema->name)
		    != 0)));
}

bool yang_is_last_level_dnode(const struct lyd_node *dnode)
{
	const struct lyd_node *parent;
	const struct lys_node_list *snode;
	const struct lyd_node *key_leaf;
	uint8_t keys_size;

	switch (dnode->schema->nodetype) {
	case LYS_LIST:
		assert(dnode->parent);
		parent = dnode->parent;
		snode = (struct lys_node_list *)parent->schema;
		key_leaf = dnode->prev;
		for (keys_size = 1; keys_size < snode->keys_size; keys_size++)
			key_leaf = key_leaf->prev;
		if (key_leaf->prev == dnode)
			return true;
		break;
	case LYS_CONTAINER:
		return true;
	default:
		break;
	}

	return false;
}


const struct lyd_node *
yang_get_subtree_with_no_sibling(const struct lyd_node *dnode)
{
	bool parent = true;
	const struct lyd_node *node;
	const struct lys_node_container *snode;

	node = dnode;
	if (node->schema->nodetype != LYS_LIST)
		return node;

	while (parent) {
		switch (node->schema->nodetype) {
		case LYS_CONTAINER:
			snode = (struct lys_node_container *)node->schema;
			if ((!snode->presence)
			    && yang_is_last_level_dnode(node)) {
				if (node->parent
				    && (node->parent->schema->module
					== dnode->schema->module))
					node = node->parent;
				else
					parent = false;
			} else
				parent = false;
			break;
		case LYS_LIST:
			if (yang_is_last_list_dnode(node)
			    && yang_is_last_level_dnode(node)) {
				if (node->parent
				    && (node->parent->schema->module
					== dnode->schema->module))
					node = node->parent;
				else
					parent = false;
			} else
				parent = false;
			break;
		default:
			parent = false;
			break;
		}
	}
	return node;
}

uint32_t yang_get_list_pos(const struct lyd_node *node)
{
	return lyd_list_pos(node);
}

uint32_t yang_get_list_elements_count(const struct lyd_node *node)
{
	unsigned int count;
	struct lys_node *schema;

	if (!node
	    || ((node->schema->nodetype != LYS_LIST)
		&& (node->schema->nodetype != LYS_LEAFLIST))) {
		return 0;
	}

	schema = node->schema;
	count = 0;
	do {
		if (node->schema == schema)
			++count;
		node = node->next;
	} while (node);
	return count;
}


const struct lyd_node *yang_dnode_get_child(const struct lyd_node *dnode)
{
	if (dnode)
		return dnode->child;
	return NULL;
}
