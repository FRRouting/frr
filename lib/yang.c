// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "darr.h"
#include "log.h"
#include "lib_errors.h"
#include "yang.h"
#include "yang_translator.h"
#include "northbound.h"

#include "lib/config_paths.h"

DEFINE_MTYPE_STATIC(LIB, YANG_MODULE, "YANG module");
DEFINE_MTYPE_STATIC(LIB, YANG_DATA, "YANG data structure");

/* libyang container. */
struct ly_ctx *ly_native_ctx;

static struct yang_module_embed *embeds, **embedupd = &embeds;

void yang_module_embed(struct yang_module_embed *embed)
{
	embed->next = NULL;
	*embedupd = embed;
	embedupd = &embed->next;
}

static LY_ERR yang_module_imp_clb(const char *mod_name, const char *mod_rev,
				  const char *submod_name,
				  const char *submod_rev, void *user_data,
				  LYS_INFORMAT *format,
				  const char **module_data,
				  void (**free_module_data)(void *, void *))
{
	struct yang_module_embed *e;

	if (!strcmp(mod_name, "ietf-inet-types") ||
	    !strcmp(mod_name, "ietf-yang-types") ||
	    !strcmp(mod_name, "ietf-yang-metadata"))
		/* libyang has these built in, don't try finding them here */
		return LY_ENOTFOUND;

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
		*module_data = e->data;
		return LY_SUCCESS;
	}

	/* We get here for indirect modules like ietf-inet-types */
	zlog_debug(
		"YANG model \"%s@%s\" \"%s@%s\"not embedded, trying external file",
		mod_name, mod_rev ? mod_rev : "*",
		submod_name ? submod_name : "*", submod_rev ? submod_rev : "*");

	return LY_ENOTFOUND;
}

/* clang-format off */
static const char *const frr_native_modules[] = {
	"frr-interface",
	"frr-vrf",
	"frr-routing",
	"frr-affinity-map",
	"frr-route-map",
	"frr-nexthop",
	"frr-ripd",
	"frr-ripngd",
	"frr-isisd",
	"frr-vrrpd",
	"frr-zebra",
	"frr-pathd",
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

struct yang_module *yang_module_load(const char *module_name,
				     const char **features)
{
	struct yang_module *module;
	const struct lys_module *module_info;

	module_info = ly_ctx_load_module(ly_native_ctx, module_name, NULL,
					 features);
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
	static const char * const all_features[] = { "*", NULL };

	for (size_t i = 0; i < array_size(frr_native_modules); i++)
		yang_module_load(frr_native_modules[i], (const char **)all_features);
}

struct yang_module *yang_module_find(const char *module_name)
{
	struct yang_module s;

	s.name = module_name;
	return RB_FIND(yang_modules, &yang_modules, &s);
}

int yang_snodes_iterate_subtree(const struct lysc_node *snode,
				const struct lys_module *module,
				yang_iterate_cb cb, uint16_t flags, void *arg)
{
	const struct lysc_node *child;
	int ret = YANG_ITER_CONTINUE;

	if (module && snode->module != module)
		goto next;

	switch (snode->nodetype) {
	case LYS_CONTAINER:
		if (CHECK_FLAG(flags, YANG_ITER_FILTER_NPCONTAINERS)) {
			if (!CHECK_FLAG(snode->flags, LYS_PRESENCE))
				goto next;
		}
		break;
	case LYS_LEAF:
		if (CHECK_FLAG(flags, YANG_ITER_FILTER_LIST_KEYS)) {
			/* Ignore list keys. */
			if (lysc_is_key(snode))
				goto next;
		}
		break;
	case LYS_INPUT:
	case LYS_OUTPUT:
		if (CHECK_FLAG(flags, YANG_ITER_FILTER_INPUT_OUTPUT))
			goto next;
		break;
	default:
		assert(snode->nodetype != LYS_AUGMENT
		       && snode->nodetype != LYS_GROUPING
		       && snode->nodetype != LYS_USES);
		break;
	}

	ret = (*cb)(snode, arg);
	if (ret == YANG_ITER_STOP)
		return ret;

next:
	/*
	 * YANG leafs and leaf-lists can't have child nodes.
	 */
	if (CHECK_FLAG(snode->nodetype, LYS_LEAF | LYS_LEAFLIST))
		return YANG_ITER_CONTINUE;

	LY_LIST_FOR (lysc_node_child(snode), child) {
		ret = yang_snodes_iterate_subtree(child, module, cb, flags,
						  arg);
		if (ret == YANG_ITER_STOP)
			return ret;
	}
	LY_LIST_FOR ((const struct lysc_node *)lysc_node_notifs(snode), child) {
		ret = yang_snodes_iterate_subtree(child, module, cb, flags, arg);
		if (ret == YANG_ITER_STOP)
			return ret;
	}
	LY_LIST_FOR ((const struct lysc_node *)lysc_node_actions(snode), child) {
		ret = yang_snodes_iterate_subtree(child, module, cb, flags, arg);
		if (ret == YANG_ITER_STOP)
			return ret;
	}
	return ret;
}

int yang_snodes_iterate(const struct lys_module *module, yang_iterate_cb cb,
			uint16_t flags, void *arg)
{
	const struct lys_module *module_iter;
	uint32_t idx = 0;
	int ret = YANG_ITER_CONTINUE;

	idx = ly_ctx_internal_modules_count(ly_native_ctx);
	while ((module_iter = ly_ctx_get_module_iter(ly_native_ctx, &idx))) {
		struct lysc_node *snode;

		if (!module_iter->implemented)
			continue;

		LY_LIST_FOR (module_iter->compiled->data, snode) {
			ret = yang_snodes_iterate_subtree(snode, module, cb,
							  flags, arg);
			if (ret == YANG_ITER_STOP)
				return ret;
		}
		LY_LIST_FOR (&module_iter->compiled->rpcs->node, snode) {
			ret = yang_snodes_iterate_subtree(snode, module, cb,
							  flags, arg);
			if (ret == YANG_ITER_STOP)
				return ret;
		}
		LY_LIST_FOR (&module_iter->compiled->notifs->node, snode) {
			ret = yang_snodes_iterate_subtree(snode, module, cb,
							  flags, arg);
			if (ret == YANG_ITER_STOP)
				return ret;
		}
	}

	return ret;
}

void yang_snode_get_path(const struct lysc_node *snode,
			 enum yang_path_type type, char *xpath,
			 size_t xpath_len)
{
	switch (type) {
	case YANG_PATH_SCHEMA:
		(void)lysc_path(snode, LYSC_PATH_LOG, xpath, xpath_len);
		break;
	case YANG_PATH_DATA:
		(void)lysc_path(snode, LYSC_PATH_DATA, xpath, xpath_len);
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown yang path type: %u",
			 __func__, type);
		exit(1);
	}
}

LY_ERR yang_resolve_snode_xpath(struct ly_ctx *ly_ctx, const char *xpath,
				struct lysc_node ***snodes, bool *simple)
{
	struct lysc_node *snode;
	struct ly_set *set;
	LY_ERR err;

	/* lys_find_path will not resolve complex xpaths */
	snode = (struct lysc_node *)lys_find_path(ly_ctx, NULL, xpath, 0);
	if (snode) {
		*darr_append(*snodes) = snode;
		*simple = true;
		return LY_SUCCESS;
	}

	/* Try again to catch complex query cases */
	err = lys_find_xpath(ly_native_ctx, NULL, xpath, 0, &set);
	if (err)
		return err;
	if (!set->count) {
		ly_set_free(set, NULL);
		return LY_ENOTFOUND;
	}

	*simple = false;
	darr_ensure_i(*snodes, set->count - 1);
	memcpy(*snodes, set->snodes, set->count * sizeof(set->snodes[0]));
	ly_set_free(set, NULL);
	return LY_SUCCESS;
}


struct lysc_node *yang_find_snode(struct ly_ctx *ly_ctx, const char *xpath,
				  uint32_t options)
{
	struct lysc_node *snode;

	snode = (struct lysc_node *)lys_find_path(ly_ctx, NULL, xpath, 0);

	return snode;
}

struct lysc_node *yang_snode_real_parent(const struct lysc_node *snode)
{
	struct lysc_node *parent = snode->parent;

	while (parent) {
		switch (parent->nodetype) {
		case LYS_CONTAINER:
			if (CHECK_FLAG(parent->flags, LYS_PRESENCE))
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

struct lysc_node *yang_snode_parent_list(const struct lysc_node *snode)
{
	struct lysc_node *parent = snode->parent;

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

bool yang_snode_is_typeless_data(const struct lysc_node *snode)
{
	const struct lysc_node_leaf *sleaf;

	switch (snode->nodetype) {
	case LYS_LEAF:
		sleaf = (struct lysc_node_leaf *)snode;
		if (sleaf->type->basetype == LY_TYPE_EMPTY)
			return true;
		return false;
	case LYS_LEAFLIST:
		return false;
	default:
		return true;
	}
}

const char *yang_snode_get_default(const struct lysc_node *snode)
{
	const struct lysc_node_leaf *sleaf;

	switch (snode->nodetype) {
	case LYS_LEAF:
		sleaf = (const struct lysc_node_leaf *)snode;
		return sleaf->dflt ? lyd_value_get_canonical(sleaf->module->ctx,
							     sleaf->dflt)
				   : NULL;
	case LYS_LEAFLIST:
		/* TODO: check leaf-list default values */
		return NULL;
	default:
		return NULL;
	}
}

const struct lysc_type *yang_snode_get_type(const struct lysc_node *snode)
{
	struct lysc_node_leaf *sleaf = (struct lysc_node_leaf *)snode;
	struct lysc_type *type;

	if (!CHECK_FLAG(sleaf->nodetype, LYS_LEAF | LYS_LEAFLIST))
		return NULL;

	type = sleaf->type;
	while (type->basetype == LY_TYPE_LEAFREF)
		type = ((struct lysc_type_leafref *)type)->realtype;

	return type;
}

unsigned int yang_snode_num_keys(const struct lysc_node *snode)
{
	const struct lysc_node_leaf *skey;
	uint count = 0;

	if (!CHECK_FLAG(snode->nodetype, LYS_LIST))
		return 0;

	/* Walk list of children */
	LY_FOR_KEYS (snode, skey) {
		count++;
	}
	return count;
}

char *yang_dnode_get_path(const struct lyd_node *dnode, char *xpath,
			  size_t xpath_len)
{
	return lyd_path(dnode, LYD_PATH_STD, xpath, xpath_len);
}

struct lyd_node *yang_dnode_get(const struct lyd_node *dnode, const char *xpath)
{
	struct ly_set *set = NULL;
	struct lyd_node *dnode_ret = NULL;

	/*
	 * XXX a lot of the code uses this for style I guess. It shouldn't, as
	 * it adds to the xpath parsing complexity in libyang.
	 */
	if (xpath[0] == '.' && xpath[1] == '/')
		xpath += 2;

	if (lyd_find_xpath(dnode, xpath, &set)) {
		/*
		 * Commenting out the below assert failure as it crashes mgmtd
		 * when bad xpath is passed.
		 *
		 * assert(0);  XXX replicates old libyang1 base code
		 */
		goto exit;
	}
	if (set->count == 0)
		goto exit;

	if (set->count > 1) {
		flog_warn(EC_LIB_YANG_DNODE_NOT_FOUND,
			  "%s: found %u elements (expected 0 or 1) [xpath %s]",
			  __func__, set->count, xpath);
		goto exit;
	}

	dnode_ret = set->dnodes[0];

exit:
	ly_set_free(set, NULL);

	return dnode_ret;
}

struct lyd_node *yang_dnode_getf(const struct lyd_node *dnode,
				 const char *xpath_fmt, ...)
{
	va_list ap;
	char xpath[XPATH_MAXLEN];

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	return yang_dnode_get(dnode, xpath);
}

bool yang_dnode_exists(const struct lyd_node *dnode, const char *xpath)
{
	struct ly_set *set = NULL;
	bool exists = false;

	if (xpath[0] == '.' && xpath[1] == '/')
		xpath += 2;
	if (lyd_find_xpath(dnode, xpath, &set))
		return false;
	exists = set->count > 0;
	ly_set_free(set, NULL);
	return exists;
}

bool yang_dnode_existsf(const struct lyd_node *dnode, const char *xpath_fmt,
			...)
{
	va_list ap;
	char xpath[XPATH_MAXLEN];

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	return yang_dnode_exists(dnode, xpath);
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

	if (lyd_find_xpath(dnode, xpath, &set)) {
		assert(0); /* XXX libyang2: ly1 code asserted success */
		return;
	}
	for (unsigned int i = 0; i < set->count; i++) {
		int ret;

		ret = (*cb)(set->dnodes[i], arg);
		if (ret == YANG_ITER_STOP)
			break;
	}

	ly_set_free(set, NULL);
}

uint32_t yang_dnode_count(const struct lyd_node *dnode, const char *xpath_fmt,
			  ...)
{
	va_list ap;
	char xpath[XPATH_MAXLEN];
	struct ly_set *set;
	uint32_t count;

	va_start(ap, xpath_fmt);
	vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
	va_end(ap);

	if (lyd_find_xpath(dnode, xpath, &set)) {
		assert(0);
		return 0;
	}

	count = set->count;

	ly_set_free(set, NULL);

	return count;
}

bool yang_dnode_is_default(const struct lyd_node *dnode, const char *xpath)
{
	const struct lysc_node *snode;
	struct lysc_node_leaf *sleaf;

	if (xpath)
		dnode = yang_dnode_get(dnode, xpath);

	assert(dnode);
	snode = dnode->schema;
	switch (snode->nodetype) {
	case LYS_LEAF:
		sleaf = (struct lysc_node_leaf *)snode;
		if (sleaf->type->basetype == LY_TYPE_EMPTY)
			return false;
		return lyd_is_default(dnode);
	case LYS_LEAFLIST:
		/* TODO: check leaf-list default values */
		return false;
	case LYS_CONTAINER:
		if (CHECK_FLAG(snode->flags, LYS_PRESENCE))
			return false;
		return true;
	default:
		return false;
	}
}

bool yang_dnode_is_defaultf(const struct lyd_node *dnode, const char *xpath_fmt,
			    ...)
{
	if (!xpath_fmt)
		return yang_dnode_is_default(dnode, NULL);
	else {
		va_list ap;
		char xpath[XPATH_MAXLEN];

		va_start(ap, xpath_fmt);
		vsnprintf(xpath, sizeof(xpath), xpath_fmt, ap);
		va_end(ap);

		return yang_dnode_is_default(dnode, xpath);
	}
}

bool yang_dnode_is_default_recursive(const struct lyd_node *dnode)
{
	struct lyd_node *root, *dnode_iter;

	if (!yang_dnode_is_default(dnode, NULL))
		return false;

	if (CHECK_FLAG(dnode->schema->nodetype, LYS_LEAF | LYS_LEAFLIST))
		return true;

	LY_LIST_FOR (lyd_child(dnode), root) {
		LYD_TREE_DFS_BEGIN (root, dnode_iter) {
			if (!yang_dnode_is_default(dnode_iter, NULL))
				return false;

			LYD_TREE_DFS_END(root, dnode_iter);
		}
	}

	return true;
}

void yang_dnode_change_leaf(struct lyd_node *dnode, const char *value)
{
	assert(dnode->schema->nodetype == LYS_LEAF);
	lyd_change_term(dnode, value);
}

struct lyd_node *yang_dnode_new(struct ly_ctx *ly_ctx, bool config_only)
{
	struct lyd_node *dnode = NULL;
	int options = config_only ? LYD_VALIDATE_NO_STATE : 0;

	if (lyd_validate_all(&dnode, ly_ctx, options, NULL) != 0) {
		/* Should never happen. */
		flog_err(EC_LIB_LIBYANG, "%s: lyd_validate() failed", __func__);
		exit(1);
	}

	return dnode;
}

struct lyd_node *yang_dnode_dup(const struct lyd_node *dnode)
{
	struct lyd_node *dup = NULL;
	LY_ERR err;
	err = lyd_dup_siblings(dnode, NULL,
			       LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &dup);
	assert(!err);
	return dup;
}

void yang_dnode_free(struct lyd_node *dnode)
{
	while (dnode->parent)
		dnode = lyd_parent(dnode);
	lyd_free_all(dnode);
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

LY_ERR yang_parse_notification(const char *xpath, LYD_FORMAT format,
			       const char *data, struct lyd_node **notif)
{
	struct lyd_node *tree;
	struct ly_set *set = NULL;
	struct ly_in *in = NULL;
	LY_ERR err;

	err = ly_in_new_memory(data, &in);
	if (err) {
		zlog_err("Failed to initialize ly_in: %s", ly_last_errmsg());
		return err;
	}

	err = lyd_parse_op(ly_native_ctx, NULL, in, format, LYD_TYPE_NOTIF_YANG,
			   &tree, NULL);
	ly_in_free(in, 0);
	if (err) {
		zlog_err("Failed to parse notification: %s", ly_last_errmsg());
		return err;
	}

	err = lyd_find_xpath3(NULL, tree, xpath, NULL, &set);
	if (err) {
		zlog_err("Failed to parse notification: %s", ly_last_errmsg());
		lyd_free_all(tree);
		return err;
	}
	if (set->count == 0) {
		zlog_err("Notification not found in the parsed tree: %s", xpath);
		ly_set_free(set, NULL);
		lyd_free_all(tree);
		return LY_ENOTFOUND;
	}
	*notif = set->dnodes[0];
	ly_set_free(set, NULL);
	return LY_SUCCESS;
}

static ssize_t yang_print_darr(void *arg, const void *buf, size_t count)
{
	uint8_t *dst = darr_append_n(*(uint8_t **)arg, count);

	memcpy(dst, buf, count);
	return count;
}

LY_ERR yang_print_tree_append(uint8_t **darr, const struct lyd_node *root,
			      LYD_FORMAT format, uint32_t options)
{
	LY_ERR err;

	err = lyd_print_clb(yang_print_darr, darr, root, format, options);
	if (err)
		zlog_err("Failed to save yang tree: %s", ly_last_errmsg());
	else if (format != LYD_LYB)
		*darr_append(*darr) = 0;
	return err;
}

uint8_t *yang_print_tree(const struct lyd_node *root, LYD_FORMAT format,
			 uint32_t options)
{
	uint8_t *darr = NULL;

	if (yang_print_tree_append(&darr, root, format, options))
		return NULL;
	return darr;
}

char *yang_convert_lyd_format(const char *data, size_t data_len,
			      LYD_FORMAT in_format, LYD_FORMAT out_format,
			      bool shrink)
{
	struct lyd_node *tree = NULL;
	uint32_t options = LYD_PRINT_WD_EXPLICIT | LYD_PRINT_WITHSIBLINGS;
	uint8_t *result = NULL;
	LY_ERR err;

	assert(out_format != LYD_LYB);

	if (in_format != LYD_LYB && !MGMT_MSG_VALIDATE_NUL_TERM(data, data_len)) {
		zlog_err("Corrupt input data, no NUL terminating byte");
		return NULL;
	}

	if (in_format == out_format)
		return darr_strdup((const char *)data);

	err = lyd_parse_data_mem(ly_native_ctx, (const char *)data, in_format,
				 LYD_PARSE_ONLY, 0, &tree);

	if (err) {
		flog_err_sys(EC_LIB_LIBYANG,
			     "cannot parse input data to convert: %s",
			     ly_last_errmsg());
		return NULL;
	}

	if (shrink)
		options |= LYD_PRINT_SHRINK;

	/* Take a guess at the initial capacity based on input data size */
	darr_ensure_cap(result, data_len);
	err = yang_print_tree_append(&result, tree, out_format, options);
	lyd_free_all(tree);
	if (err) {
		darr_free(result);
		return NULL;
	}
	return (char *)result;
}

const char *yang_print_errors(struct ly_ctx *ly_ctx, char *buf, size_t buf_len)
{
	struct ly_err_item *ei;

	ei = ly_err_first(ly_ctx);
	if (!ei)
		return "";

	strlcpy(buf, "YANG error(s):\n", buf_len);
	for (; ei; ei = ei->next) {
		if (ei->path) {
			strlcat(buf, " Path: ", buf_len);
			strlcat(buf, ei->path, buf_len);
			strlcat(buf, "\n", buf_len);
		}
		strlcat(buf, " Error: ", buf_len);
		strlcat(buf, ei->msg, buf_len);
		strlcat(buf, "\n", buf_len);
	}

	ly_err_clean(ly_ctx, NULL);

	return buf;
}

void yang_debugging_set(bool enable)
{
	if (enable) {
		ly_log_level(LY_LLDBG);
		ly_log_dbg_groups(0xFF);
	} else {
		ly_log_level(LY_LLERR);
		ly_log_dbg_groups(0);
	}
}

struct ly_ctx *yang_ctx_new_setup(bool embedded_modules, bool explicit_compile)
{
	struct ly_ctx *ctx = NULL;
	const char *yang_models_path = YANG_MODELS_PATH;
	uint options;
	LY_ERR err;

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

	options = LY_CTX_NO_YANGLIBRARY | LY_CTX_DISABLE_SEARCHDIR_CWD;
	if (explicit_compile)
		options |= LY_CTX_EXPLICIT_COMPILE;
	err = ly_ctx_new(yang_models_path, options, &ctx);
	if (err)
		return NULL;

	if (embedded_modules)
		ly_ctx_set_module_imp_clb(ctx, yang_module_imp_clb, NULL);

	return ctx;
}

void yang_init(bool embedded_modules, bool defer_compile)
{
	/* Initialize libyang global parameters that affect all containers. */
	ly_set_log_clb(ly_log_cb, 1);
	ly_log_options(LY_LOLOG | LY_LOSTORE);

	/* Initialize libyang container for native models. */
	ly_native_ctx = yang_ctx_new_setup(embedded_modules, defer_compile);
	if (!ly_native_ctx) {
		flog_err(EC_LIB_LIBYANG, "%s: ly_ctx_new() failed", __func__);
		exit(1);
	}

	yang_translator_init();
}

void yang_init_loading_complete(void)
{
	/* Compile everything */
	if (ly_ctx_compile(ly_native_ctx) != LY_SUCCESS) {
		flog_err(EC_LIB_YANG_MODULE_LOAD,
			 "%s: failed to compile loaded modules: %s", __func__,
			 ly_errmsg(ly_native_ctx));
		exit(1);
	}
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

	ly_ctx_destroy(ly_native_ctx);
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

		orig_dnode = lyd_parent(orig_dnode);
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
	const struct lyd_node *key_leaf;
	uint8_t keys_size;

	switch (dnode->schema->nodetype) {
	case LYS_LIST:
		assert(dnode->parent);
		parent = lyd_parent(dnode);
		uint snode_num_keys = yang_snode_num_keys(parent->schema);
		/* XXX libyang2: q: really don't understand this code. */
		key_leaf = dnode->prev;
		for (keys_size = 1; keys_size < snode_num_keys; keys_size++)
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

	node = dnode;
	if (node->schema->nodetype != LYS_LIST)
		return node;

	while (parent) {
		switch (node->schema->nodetype) {
		case LYS_CONTAINER:
			if (!CHECK_FLAG(node->schema->flags, LYS_PRESENCE)) {
				if (node->parent
				    && (node->parent->schema->module
					== dnode->schema->module))
					node = lyd_parent(node);
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
					node = lyd_parent(node);
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
	const struct lysc_node *schema;

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

int yang_get_key_preds(char *s, const struct lysc_node *snode,
		       struct yang_list_keys *keys, ssize_t space)
{
	const struct lysc_node_leaf *skey;
	ssize_t len2, len = 0;
	ssize_t i = 0;

	LY_FOR_KEYS (snode, skey) {
		assert(i < keys->num);
		len2 = snprintf(s + len, space - len, "[%s='%s']", skey->name,
				keys->key[i]);
		if (len2 > space - len)
			len = space;
		else
			len += len2;
		i++;
	}

	assert(i == keys->num);
	return i;
}

int yang_get_node_keys(struct lyd_node *node, struct yang_list_keys *keys)
{
	struct lyd_node *child = lyd_child(node);

	keys->num = 0;
	for (; child && lysc_is_key(child->schema); child = child->next) {
		const char *value = lyd_get_value(child);

		if (!value)
			return NB_ERR;
		strlcpy(keys->key[keys->num], value,
			sizeof(keys->key[keys->num]));
		keys->num++;
	}
	return NB_OK;
}

/*
 * ------------------------
 * Libyang Future Functions
 * ------------------------
 *
 * All these functions are implemented in libyang versions (perhaps unreleased)
 * beyond what we require currently so we must supply the functionality.
 */

/*
 * Safe to remove after libyang v2.1.xxx is required (.144 has a bug so
 * something > .144) https://github.com/CESNET/libyang/issues/2149
 */
LY_ERR yang_lyd_new_list(struct lyd_node_inner *parent,
			 const struct lysc_node *snode,
			 const struct yang_list_keys *list_keys,
			 struct lyd_node **node)
{
#if defined(HAVE_LYD_NEW_LIST3) && 0
	LY_ERR err;
	const char *keys[LIST_MAXKEYS];

	assert(list_keys->num <= LIST_MAXKEYS);
	for (int i = 0; i < list_keys->num; i++)
		keys[i] = list_keys->key[i];

	err = lyd_new_list3(&parent->node, snode->module, snode->name, keys,
			    NULL, 0, node);
	return err;
#else
	struct lyd_node *pnode = &parent->node;
	const char(*keys)[LIST_MAXKEYLEN] = list_keys->key;

	assert(list_keys->num <= 8);
	switch (list_keys->num) {
	case 0:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node);
	case 1:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node, keys[0]);
	case 2:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node, keys[0], keys[1]);
	case 3:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node, keys[0], keys[1], keys[2]);
	case 4:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node, keys[0], keys[1], keys[2], keys[3]);
	case 5:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node, keys[0], keys[1], keys[2], keys[3],
				    keys[4]);
	case 6:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node, keys[0], keys[1], keys[2], keys[3],
				    keys[4], keys[5]);
	case 7:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node, keys[0], keys[1], keys[2], keys[3],
				    keys[4], keys[5], keys[6]);
	case 8:
		return lyd_new_list(pnode, snode->module, snode->name, false,
				    node, keys[0], keys[1], keys[2], keys[3],
				    keys[4], keys[5], keys[6], keys[7]);
	}
	_Static_assert(LIST_MAXKEYS == 8, "max key mismatch in switch unroll");
	/*NOTREACHED*/
	return LY_EINVAL;
#endif
}


/*
 * Safe to remove after libyang v2.1.144 is required
 */
LY_ERR yang_lyd_trim_xpath(struct lyd_node **root, const char *xpath)
{
	LY_ERR err;
#ifdef HAVE_LYD_TRIM_XPATH
	err = lyd_trim_xpath(root, xpath, NULL);
	if (err) {
		flog_err_sys(EC_LIB_LIBYANG,
			     "cannot obtain specific result for xpath \"%s\": %s",
			     xpath, yang_ly_strerrcode(err));
		return err;
	}
	return LY_SUCCESS;
#else
	struct lyd_node *node, *sib;
	struct lyd_node **remove = NULL;
	struct ly_set *set = NULL;
	uint32_t i;

	*root = lyd_first_sibling(*root);

	err = lyd_find_xpath3(NULL, *root, xpath, NULL, &set);
	if (err) {
		flog_err_sys(EC_LIB_LIBYANG,
			     "cannot obtain specific result for xpath \"%s\": %s",
			     xpath, yang_ly_strerrcode(err));
		return err;
	}
	/*
	 * Mark keepers and sweep deleting non-keepers.
	 *
	 * NOTE: We assume the data-nodes have NULL priv pointers and use that
	 * for our mark.
	 */

	/* Mark */
	for (i = 0; i < set->count; i++) {
		for (node = set->dnodes[i]; node; node = &node->parent->node) {
			if (node->priv)
				break;
			if (node == set->dnodes[i])
				node->priv = (void *)2;
			else
				node->priv = (void *)1;
		}
	}

	darr_ensure_cap(remove, 128);
	LY_LIST_FOR(*root, sib) {
		LYD_TREE_DFS_BEGIN (sib, node) {
			/*
			 * If this is a direct matching node then include its
			 * subtree which won't be marked and would otherwise
			 * be removed.
			 */
			if (node->priv == (void *)2)
				LYD_TREE_DFS_continue = 1;
			else if (!node->priv) {
				*darr_append(remove) = node;
				LYD_TREE_DFS_continue = 1;
			}
			LYD_TREE_DFS_END(sib, node);
		}
	}
	darr_foreach_i (remove, i) {
		if (remove[i] == *root)
			*root = (*root)->next;
		lyd_free_tree(remove[i]);
	}
	darr_free(remove);

	ly_set_free(set, NULL);

	return LY_SUCCESS;
#endif
}

/*
 * Safe to remove after libyang v2.1.128 is required
 */
const char *yang_ly_strerrcode(LY_ERR err)
{
#ifdef HAVE_LY_STRERRCODE
	return ly_strerrcode(err);
#else
	switch (err) {
	case LY_SUCCESS:
		return "ok";
	case LY_EMEM:
		return "out of memory";
	case LY_ESYS:
		return "system error";
	case LY_EINVAL:
		return "invalid value given";
	case LY_EEXIST:
		return "item exists";
	case LY_ENOTFOUND:
		return "item not found";
	case LY_EINT:
		return "operation interrupted";
	case LY_EVALID:
		return "validation failed";
	case LY_EDENIED:
		return "access denied";
	case LY_EINCOMPLETE:
		return "incomplete";
	case LY_ERECOMPILE:
		return "compile error";
	case LY_ENOT:
		return "not";
	case LY_EPLUGIN:
	case LY_EOTHER:
		return "other";
	default:
		return "unknown";
	}
#endif
}

/*
 * Safe to remove after libyang v2.1.128 is required
 */
const char *yang_ly_strvecode(LY_VECODE vecode)
{
#ifdef HAVE_LY_STRVECODE
	return ly_strvecode(vecode);
#else
	switch (vecode) {
	case LYVE_SUCCESS:
		return "";
	case LYVE_SYNTAX:
		return "syntax";
	case LYVE_SYNTAX_YANG:
		return "yang-syntax";
	case LYVE_SYNTAX_YIN:
		return "yin-syntax";
	case LYVE_REFERENCE:
		return "reference";
	case LYVE_XPATH:
		return "xpath";
	case LYVE_SEMANTICS:
		return "semantics";
	case LYVE_SYNTAX_XML:
		return "xml-syntax";
	case LYVE_SYNTAX_JSON:
		return "json-syntax";
	case LYVE_DATA:
		return "data";
	case LYVE_OTHER:
		return "other";
	default:
		return "unknown";
	}
#endif
}
