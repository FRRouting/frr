// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "log.h"
#include "lib_errors.h"
#include "hash.h"
#include "yang.h"
#include "yang_translator.h"
#include "frrstr.h"

DEFINE_MTYPE_STATIC(LIB, YANG_TRANSLATOR, "YANG Translator");
DEFINE_MTYPE_STATIC(LIB, YANG_TRANSLATOR_MODULE, "YANG Translator Module");
DEFINE_MTYPE_STATIC(LIB, YANG_TRANSLATOR_MAPPING, "YANG Translator Mapping");

/* Generate the yang_translators tree. */
static inline int yang_translator_compare(const struct yang_translator *a,
					  const struct yang_translator *b)
{
	return strcmp(a->family, b->family);
}
RB_GENERATE(yang_translators, yang_translator, entry, yang_translator_compare)

struct yang_translators yang_translators = RB_INITIALIZER(&yang_translators);

/* Separate libyang context for the translator module. */
static struct ly_ctx *ly_translator_ctx;

static unsigned int
yang_translator_validate(struct yang_translator *translator);
static unsigned int yang_module_nodes_count(const struct lys_module *module);

struct yang_mapping_node {
	char xpath_from_canonical[XPATH_MAXLEN];
	char xpath_from_fmt[XPATH_MAXLEN];
	char xpath_to_fmt[XPATH_MAXLEN];
};

static bool yang_mapping_hash_cmp(const void *value1, const void *value2)
{
	const struct yang_mapping_node *c1 = value1;
	const struct yang_mapping_node *c2 = value2;

	return strmatch(c1->xpath_from_canonical, c2->xpath_from_canonical);
}

static unsigned int yang_mapping_hash_key(const void *value)
{
	return string_hash_make(value);
}

static void *yang_mapping_hash_alloc(void *p)
{
	struct yang_mapping_node *new, *key = p;

	new = XCALLOC(MTYPE_YANG_TRANSLATOR_MAPPING, sizeof(*new));
	strlcpy(new->xpath_from_canonical, key->xpath_from_canonical,
		sizeof(new->xpath_from_canonical));

	return new;
}

static void yang_mapping_hash_free(void *arg)
{
	XFREE(MTYPE_YANG_TRANSLATOR_MAPPING, arg);
}

static struct yang_mapping_node *
yang_mapping_lookup(const struct yang_translator *translator, int dir,
		    const char *xpath)
{
	struct yang_mapping_node s;

	strlcpy(s.xpath_from_canonical, xpath, sizeof(s.xpath_from_canonical));
	return hash_lookup(translator->mappings[dir], &s);
}

static void yang_mapping_add(struct yang_translator *translator, int dir,
			     const struct lysc_node *snode,
			     const char *xpath_from_fmt,
			     const char *xpath_to_fmt)
{
	struct yang_mapping_node *mapping, s;

	yang_snode_get_path(snode, YANG_PATH_DATA, s.xpath_from_canonical,
			    sizeof(s.xpath_from_canonical));
	mapping = hash_get(translator->mappings[dir], &s,
			   yang_mapping_hash_alloc);
	strlcpy(mapping->xpath_from_fmt, xpath_from_fmt,
		sizeof(mapping->xpath_from_fmt));
	strlcpy(mapping->xpath_to_fmt, xpath_to_fmt,
		sizeof(mapping->xpath_to_fmt));

	const char *keys[] = {"KEY1", "KEY2", "KEY3", "KEY4"};
	char *xpfmt;

	for (unsigned int i = 0; i < array_size(keys); i++) {
		xpfmt = frrstr_replace(mapping->xpath_from_fmt, keys[i],
				       "%[^']");
		strlcpy(mapping->xpath_from_fmt, xpfmt,
			sizeof(mapping->xpath_from_fmt));
		XFREE(MTYPE_TMP, xpfmt);
	}

	for (unsigned int i = 0; i < array_size(keys); i++) {
		xpfmt = frrstr_replace(mapping->xpath_to_fmt, keys[i], "%s");
		strlcpy(mapping->xpath_to_fmt, xpfmt,
			sizeof(mapping->xpath_to_fmt));
		XFREE(MTYPE_TMP, xpfmt);
	}
}

static void yang_tmodule_delete(struct yang_tmodule *tmodule)
{
	XFREE(MTYPE_YANG_TRANSLATOR_MODULE, tmodule);
}

struct yang_translator *yang_translator_load(const char *path)
{
	struct yang_translator *translator;
	struct yang_tmodule *tmodule = NULL;
	const char *family;
	struct lyd_node *dnode;
	struct ly_set *set;
	struct listnode *ln;
	LY_ERR err;

	/* Load module translator (JSON file). */
	err = lyd_parse_data_path(ly_translator_ctx, path, LYD_JSON,
				  LYD_PARSE_NO_STATE, LYD_VALIDATE_NO_STATE,
				  &dnode);
	if (err) {
		flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
			  "%s: lyd_parse_path() failed: %d", __func__, err);
		return NULL;
	}
	dnode = yang_dnode_get(dnode,
			       "/frr-module-translator:frr-module-translator");
	/*
	 * libyang guarantees the "frr-module-translator" top-level container is
	 * always present since it contains mandatory child nodes.
	 */
	assert(dnode);

	family = yang_dnode_get_string(dnode, "family");
	translator = yang_translator_find(family);
	if (translator != NULL) {
		flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
			  "%s: module translator \"%s\" is loaded already",
			  __func__, family);
		yang_dnode_free(dnode);
		return NULL;
	}

	translator = XCALLOC(MTYPE_YANG_TRANSLATOR, sizeof(*translator));
	strlcpy(translator->family, family, sizeof(translator->family));
	translator->modules = list_new();
	for (size_t i = 0; i < YANG_TRANSLATE_MAX; i++)
		translator->mappings[i] = hash_create(yang_mapping_hash_key,
						      yang_mapping_hash_cmp,
						      "YANG translation table");
	RB_INSERT(yang_translators, &yang_translators, translator);

	/* Initialize the translator libyang context. */
	translator->ly_ctx = yang_ctx_new_setup(false, false, false);
	if (!translator->ly_ctx) {
		flog_warn(EC_LIB_LIBYANG, "%s: ly_ctx_new() failed", __func__);
		goto error;
	}

	/* Load modules */
	if (lyd_find_xpath(dnode, "./module", &set) != LY_SUCCESS)
		assert(0); /* XXX libyang2: old ly1 code asserted success */

	for (size_t i = 0; i < set->count; i++) {
		const char *module_name;

		tmodule =
			XCALLOC(MTYPE_YANG_TRANSLATOR_MODULE, sizeof(*tmodule));

		module_name = yang_dnode_get_string(set->dnodes[i], "name");
		tmodule->module = ly_ctx_load_module(translator->ly_ctx,
						     module_name, NULL, NULL);
		if (!tmodule->module) {
			flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
				  "%s: failed to load module: %s", __func__,
				  module_name);
			ly_set_free(set, NULL);
			goto error;
		}
	}

	/* Count nodes in modules. */
	for (ALL_LIST_ELEMENTS_RO(translator->modules, ln, tmodule)) {
		tmodule->nodes_before_deviations =
			yang_module_nodes_count(tmodule->module);
	}

	/* Load the deviations and count nodes again */
	for (ALL_LIST_ELEMENTS_RO(translator->modules, ln, tmodule)) {
		const char *module_name = tmodule->module->name;
		tmodule->deviations = ly_ctx_load_module(
			translator->ly_ctx, module_name, NULL, NULL);
		if (!tmodule->deviations) {
			flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
				  "%s: failed to load module: %s", __func__,
				  module_name);
			ly_set_free(set, NULL);
			goto error;
		}

		tmodule->nodes_after_deviations =
			yang_module_nodes_count(tmodule->module);
	}
	ly_set_free(set, NULL);

	/* Calculate the coverage. */
	for (ALL_LIST_ELEMENTS_RO(translator->modules, ln, tmodule)) {
		tmodule->coverage = ((double)tmodule->nodes_after_deviations
				     / (double)tmodule->nodes_before_deviations)
				    * 100;
	}

	/* Load mappings. */
	if (lyd_find_xpath(dnode, "./module/mappings", &set) != LY_SUCCESS)
		assert(0); /* XXX libyang2: old ly1 code asserted success */
	for (size_t i = 0; i < set->count; i++) {
		const char *xpath_custom, *xpath_native;
		const struct lysc_node *snode_custom, *snode_native;

		xpath_custom =
			yang_dnode_get_string(set->dnodes[i], "custom");

		snode_custom =
			yang_find_snode(translator->ly_ctx, xpath_custom, 0);
		if (!snode_custom) {
			flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
				  "%s: unknown data path: %s", __func__,
				  xpath_custom);
			ly_set_free(set, NULL);
			goto error;
		}

		xpath_native =
			yang_dnode_get_string(set->dnodes[i], "native");
		snode_native = yang_find_snode(ly_native_ctx, xpath_native, 0);
		if (!snode_native) {
			flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
				  "%s: unknown data path: %s", __func__,
				  xpath_native);
			ly_set_free(set, NULL);
			goto error;
		}

		yang_mapping_add(translator, YANG_TRANSLATE_TO_NATIVE,
				 snode_custom, xpath_custom, xpath_native);
		yang_mapping_add(translator, YANG_TRANSLATE_FROM_NATIVE,
				 snode_native, xpath_native, xpath_custom);
	}
	ly_set_free(set, NULL);

	/* Validate mappings. */
	if (yang_translator_validate(translator) != 0)
		goto error;

	yang_dnode_free(dnode);

	return translator;

error:
	yang_dnode_free(dnode);
	yang_translator_unload(translator);
	yang_tmodule_delete(tmodule);

	return NULL;
}

void yang_translator_unload(struct yang_translator *translator)
{
	for (size_t i = 0; i < YANG_TRANSLATE_MAX; i++)
		hash_clean(translator->mappings[i], yang_mapping_hash_free);
	translator->modules->del = (void (*)(void *))yang_tmodule_delete;
	list_delete(&translator->modules);
	ly_ctx_destroy(translator->ly_ctx);
	RB_REMOVE(yang_translators, &yang_translators, translator);
	XFREE(MTYPE_YANG_TRANSLATOR, translator);
}

struct yang_translator *yang_translator_find(const char *family)
{
	struct yang_translator s;

	strlcpy(s.family, family, sizeof(s.family));
	return RB_FIND(yang_translators, &yang_translators, &s);
}

enum yang_translate_result
yang_translate_xpath(const struct yang_translator *translator, int dir,
		     char *xpath, size_t xpath_len)
{
	struct ly_ctx *ly_ctx;
	const struct lysc_node *snode;
	struct yang_mapping_node *mapping;
	char xpath_canonical[XPATH_MAXLEN];
	char keys[4][LIST_MAXKEYLEN];
	int n;

	if (dir == YANG_TRANSLATE_TO_NATIVE)
		ly_ctx = translator->ly_ctx;
	else
		ly_ctx = ly_native_ctx;

	snode = yang_find_snode(ly_ctx, xpath, 0);
	if (!snode) {
		flog_warn(EC_LIB_YANG_TRANSLATION_ERROR,
			  "%s: unknown data path: %s", __func__, xpath);
		return YANG_TRANSLATE_FAILURE;
	}

	yang_snode_get_path(snode, YANG_PATH_DATA, xpath_canonical,
			    sizeof(xpath_canonical));
	mapping = yang_mapping_lookup(translator, dir, xpath_canonical);
	if (!mapping)
		return YANG_TRANSLATE_NOTFOUND;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	/* processing format strings from mapping node... */
	n = sscanf(xpath, mapping->xpath_from_fmt, keys[0], keys[1], keys[2],
		   keys[3]);
#pragma GCC diagnostic pop
	if (n < 0) {
		flog_warn(EC_LIB_YANG_TRANSLATION_ERROR,
			  "%s: sscanf() failed: %s", __func__,
			  safe_strerror(errno));
		return YANG_TRANSLATE_FAILURE;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	/* processing format strings from mapping node... */
	snprintf(xpath, xpath_len, mapping->xpath_to_fmt, keys[0], keys[1],
		 keys[2], keys[3]);
#pragma GCC diagnostic pop

	return YANG_TRANSLATE_SUCCESS;
}

int yang_translate_dnode(const struct yang_translator *translator, int dir,
			 struct lyd_node **dnode)
{
	struct ly_ctx *ly_ctx;
	struct lyd_node *new;
	struct lyd_node *root, *dnode_iter;

	/* Create new libyang data node to hold the translated data. */
	if (dir == YANG_TRANSLATE_TO_NATIVE)
		ly_ctx = ly_native_ctx;
	else
		ly_ctx = translator->ly_ctx;
	new = yang_dnode_new(ly_ctx, false);

	/* Iterate over all nodes from the data tree. */
	LY_LIST_FOR (*dnode, root) {
		LYD_TREE_DFS_BEGIN (root, dnode_iter) {
			char xpath[XPATH_MAXLEN];
			enum yang_translate_result ret;

			yang_dnode_get_path(dnode_iter, xpath, sizeof(xpath));
			ret = yang_translate_xpath(translator, dir, xpath,
						   sizeof(xpath));
			switch (ret) {
			case YANG_TRANSLATE_SUCCESS:
				break;
			case YANG_TRANSLATE_NOTFOUND:
				goto next;
			case YANG_TRANSLATE_FAILURE:
				goto error;
			}

			/* Create new node in the tree of translated data. */
			if (lyd_new_path(new, ly_ctx, xpath,
					 (void *)yang_dnode_get_string(
						 dnode_iter, NULL),
					 LYD_NEW_PATH_UPDATE, NULL)) {
				flog_err(EC_LIB_LIBYANG,
					 "%s: lyd_new_path() failed", __func__);
				goto error;
			}

		next:
			LYD_TREE_DFS_END(root, dnode_iter);
		}
	}

	/* Replace dnode by the new translated dnode. */
	yang_dnode_free(*dnode);
	*dnode = new;

	return YANG_TRANSLATE_SUCCESS;

error:
	yang_dnode_free(new);

	return YANG_TRANSLATE_FAILURE;
}

struct translator_validate_args {
	struct yang_translator *translator;
	unsigned int errors;
};

static int yang_translator_validate_cb(const struct lysc_node *snode_custom,
				       void *arg)
{
	struct translator_validate_args *args = arg;
	struct yang_mapping_node *mapping;
	const struct lysc_node *snode_native;
	const struct lysc_type *stype_custom, *stype_native;
	char xpath[XPATH_MAXLEN];

	yang_snode_get_path(snode_custom, YANG_PATH_DATA, xpath, sizeof(xpath));
	mapping = yang_mapping_lookup(args->translator,
				      YANG_TRANSLATE_TO_NATIVE, xpath);
	if (!mapping) {
		flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
			  "%s: missing mapping for \"%s\"", __func__, xpath);
		args->errors += 1;
		return YANG_ITER_CONTINUE;
	}

	snode_native =
		lys_find_path(ly_native_ctx, NULL, mapping->xpath_to_fmt, 0);
	assert(snode_native);

	/* Check if the YANG types are compatible. */
	stype_custom = yang_snode_get_type(snode_custom);
	stype_native = yang_snode_get_type(snode_native);
	if (stype_custom && stype_native) {
		if (stype_custom->basetype != stype_native->basetype) {
			flog_warn(
				EC_LIB_YANG_TRANSLATOR_LOAD,
				"%s: YANG types are incompatible (xpath: \"%s\")",
				__func__, xpath);
			args->errors += 1;
			return YANG_ITER_CONTINUE;
		}

		/* TODO: check if the value spaces are identical. */
	}

	return YANG_ITER_CONTINUE;
}

/*
 * Check if the modules from the translator have a mapping for all of their
 * schema nodes (after loading the deviations).
 */
static unsigned int yang_translator_validate(struct yang_translator *translator)
{
	struct yang_tmodule *tmodule;
	struct listnode *ln;
	struct translator_validate_args args;

	args.translator = translator;
	args.errors = 0;

	for (ALL_LIST_ELEMENTS_RO(translator->modules, ln, tmodule)) {
		yang_snodes_iterate(tmodule->module,
				    yang_translator_validate_cb,
				    YANG_ITER_FILTER_NPCONTAINERS
					    | YANG_ITER_FILTER_LIST_KEYS
					    | YANG_ITER_FILTER_INPUT_OUTPUT,
				    &args);
	}

	if (args.errors)
		flog_warn(
			EC_LIB_YANG_TRANSLATOR_LOAD,
			"%s: failed to validate \"%s\" module translator: %u error(s)",
			__func__, translator->family, args.errors);

	return args.errors;
}

static int yang_module_nodes_count_cb(const struct lysc_node *snode, void *arg)
{
	unsigned int *total = arg;

	*total += 1;

	return YANG_ITER_CONTINUE;
}

/* Calculate the number of nodes for the given module. */
static unsigned int yang_module_nodes_count(const struct lys_module *module)
{
	unsigned int total = 0;

	yang_snodes_iterate(module, yang_module_nodes_count_cb,
			    YANG_ITER_FILTER_NPCONTAINERS
				    | YANG_ITER_FILTER_LIST_KEYS
				    | YANG_ITER_FILTER_INPUT_OUTPUT,
			    &total);

	return total;
}

void yang_translator_init(void)
{
	ly_translator_ctx = yang_ctx_new_setup(true, false, false);
	if (!ly_translator_ctx) {
		flog_err(EC_LIB_LIBYANG, "%s: ly_ctx_new() failed", __func__);
		exit(1);
	}

	if (!ly_ctx_load_module(ly_translator_ctx, "frr-module-translator",
				NULL, NULL)) {
		flog_err(
			EC_LIB_YANG_MODULE_LOAD,
			"%s: failed to load the \"frr-module-translator\" module",
			__func__);
		exit(1);
	}
}

void yang_translator_terminate(void)
{
	while (!RB_EMPTY(yang_translators, &yang_translators)) {
		struct yang_translator *translator;

		translator = RB_ROOT(yang_translators, &yang_translators);
		yang_translator_unload(translator);
	}

	ly_ctx_destroy(ly_translator_ctx);
}
