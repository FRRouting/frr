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
#include "hash.h"
#include "yang.h"
#include "yang_translator.h"

DEFINE_MTYPE_STATIC(LIB, YANG_TRANSLATOR, "YANG Translator")
DEFINE_MTYPE_STATIC(LIB, YANG_TRANSLATOR_MODULE, "YANG Translator Module")
DEFINE_MTYPE_STATIC(LIB, YANG_TRANSLATOR_MAPPING, "YANG Translator Mapping")

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
static void str_replace(char *o_string, const char *s_string,
			const char *r_string);

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

static unsigned int yang_mapping_hash_key(void *value)
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
			     const struct lys_node *snode,
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
	str_replace(mapping->xpath_from_fmt, "KEY1", "%[^']");
	str_replace(mapping->xpath_from_fmt, "KEY2", "%[^']");
	str_replace(mapping->xpath_from_fmt, "KEY3", "%[^']");
	str_replace(mapping->xpath_from_fmt, "KEY4", "%[^']");
	str_replace(mapping->xpath_to_fmt, "KEY1", "%s");
	str_replace(mapping->xpath_to_fmt, "KEY2", "%s");
	str_replace(mapping->xpath_to_fmt, "KEY3", "%s");
	str_replace(mapping->xpath_to_fmt, "KEY4", "%s");
}

struct yang_translator *yang_translator_load(const char *path)
{
	struct yang_translator *translator;
	struct yang_tmodule *tmodule;
	const char *family;
	struct lyd_node *dnode;
	struct ly_set *set;
	struct listnode *ln;

	/* Load module translator (JSON file). */
	dnode = lyd_parse_path(ly_translator_ctx, path, LYD_JSON,
			       LYD_OPT_CONFIG);
	if (!dnode) {
		flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
			  "%s: lyd_parse_path() failed", __func__);
		return NULL;
	}
	dnode = yang_dnode_get(dnode,
			       "/frr-module-translator:frr-module-translator");
	/*
	 * libyang guarantees the "frr-module-translator" top-level container is
	 * always present since it contains mandatory child nodes.
	 */
	assert(dnode);

	family = yang_dnode_get_string(dnode, "./family");
	translator = yang_translator_find(family);
	if (translator != NULL) {
		flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
			  "%s: module translator \"%s\" is loaded already",
			  __func__, family);
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
	translator->ly_ctx =
		ly_ctx_new(YANG_MODELS_PATH, LY_CTX_DISABLE_SEARCHDIR_CWD);
	if (!translator->ly_ctx) {
		flog_warn(EC_LIB_LIBYANG, "%s: ly_ctx_new() failed", __func__);
		goto error;
	}

	/* Load modules and deviations. */
	set = lyd_find_path(dnode, "./module");
	assert(set);
	for (size_t i = 0; i < set->number; i++) {
		const char *module_name;

		tmodule =
			XCALLOC(MTYPE_YANG_TRANSLATOR_MODULE, sizeof(*tmodule));

		module_name = yang_dnode_get_string(set->set.d[i], "./name");
		tmodule->module = ly_ctx_load_module(translator->ly_ctx,
						     module_name, NULL);
		if (!tmodule->module) {
			flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
				  "%s: failed to load module: %s", __func__,
				  module_name);
			ly_set_free(set);
			goto error;
		}

		module_name =
			yang_dnode_get_string(set->set.d[i], "./deviations");
		tmodule->deviations = ly_ctx_load_module(translator->ly_ctx,
							 module_name, NULL);
		if (!tmodule->deviations) {
			flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
				  "%s: failed to load module: %s", __func__,
				  module_name);
			ly_set_free(set);
			goto error;
		}
		lys_set_disabled(tmodule->deviations);

		listnode_add(translator->modules, tmodule);
	}
	ly_set_free(set);

	/* Calculate the coverage. */
	for (ALL_LIST_ELEMENTS_RO(translator->modules, ln, tmodule)) {
		tmodule->nodes_before_deviations =
			yang_module_nodes_count(tmodule->module);

		lys_set_enabled(tmodule->deviations);

		tmodule->nodes_after_deviations =
			yang_module_nodes_count(tmodule->module);
		tmodule->coverage = ((double)tmodule->nodes_after_deviations
				     / (double)tmodule->nodes_before_deviations)
				    * 100;
	}

	/* Load mappings. */
	set = lyd_find_path(dnode, "./module/mappings");
	assert(set);
	for (size_t i = 0; i < set->number; i++) {
		const char *xpath_custom, *xpath_native;
		const struct lys_node *snode_custom, *snode_native;

		xpath_custom = yang_dnode_get_string(set->set.d[i], "./custom");
		snode_custom = ly_ctx_get_node(translator->ly_ctx, NULL,
					       xpath_custom, 0);
		if (!snode_custom) {
			flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
				  "%s: unknown data path: %s", __func__,
				  xpath_custom);
			ly_set_free(set);
			goto error;
		}

		xpath_native = yang_dnode_get_string(set->set.d[i], "./native");
		snode_native =
			ly_ctx_get_node(ly_native_ctx, NULL, xpath_native, 0);
		if (!snode_native) {
			flog_warn(EC_LIB_YANG_TRANSLATOR_LOAD,
				  "%s: unknown data path: %s", __func__,
				  xpath_native);
			ly_set_free(set);
			goto error;
		}

		yang_mapping_add(translator, YANG_TRANSLATE_TO_NATIVE,
				 snode_custom, xpath_custom, xpath_native);
		yang_mapping_add(translator, YANG_TRANSLATE_FROM_NATIVE,
				 snode_native, xpath_native, xpath_custom);
	}
	ly_set_free(set);

	/* Validate mappings. */
	if (yang_translator_validate(translator) != 0)
		goto error;

	yang_dnode_free(dnode);

	return translator;

error:
	yang_dnode_free(dnode);
	yang_translator_unload(translator);

	return NULL;
}

static void yang_tmodule_delete(struct yang_tmodule *tmodule)
{
	XFREE(MTYPE_YANG_TRANSLATOR_MODULE, tmodule);
}

void yang_translator_unload(struct yang_translator *translator)
{
	for (size_t i = 0; i < YANG_TRANSLATE_MAX; i++)
		hash_clean(translator->mappings[i], yang_mapping_hash_free);
	translator->modules->del = (void (*)(void *))yang_tmodule_delete;
	list_delete(&translator->modules);
	ly_ctx_destroy(translator->ly_ctx, NULL);
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
	const struct lys_node *snode;
	struct yang_mapping_node *mapping;
	char xpath_canonical[XPATH_MAXLEN];
	char keys[4][LIST_MAXKEYLEN];
	int n;

	if (dir == YANG_TRANSLATE_TO_NATIVE)
		ly_ctx = translator->ly_ctx;
	else
		ly_ctx = ly_native_ctx;

	snode = ly_ctx_get_node(ly_ctx, NULL, xpath, 0);
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

	n = sscanf(xpath, mapping->xpath_from_fmt, keys[0], keys[1], keys[2],
		   keys[3]);
	if (n < 0) {
		flog_warn(EC_LIB_YANG_TRANSLATION_ERROR,
			  "%s: sscanf() failed: %s", __func__,
			  safe_strerror(errno));
		return YANG_TRANSLATE_FAILURE;
	}

	snprintf(xpath, xpath_len, mapping->xpath_to_fmt, keys[0], keys[1],
		 keys[2], keys[3]);

	return YANG_TRANSLATE_SUCCESS;
}

int yang_translate_dnode(const struct yang_translator *translator, int dir,
			 struct lyd_node **dnode)
{
	struct ly_ctx *ly_ctx;
	struct lyd_node *new;
	struct lyd_node *root, *next, *dnode_iter;

	/* Create new libyang data node to hold the translated data. */
	if (dir == YANG_TRANSLATE_TO_NATIVE)
		ly_ctx = ly_native_ctx;
	else
		ly_ctx = translator->ly_ctx;
	new = yang_dnode_new(ly_ctx, false);

	/* Iterate over all nodes from the data tree. */
	LY_TREE_FOR (*dnode, root) {
		LY_TREE_DFS_BEGIN (root, next, dnode_iter) {
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
			ly_errno = 0;
			if (!lyd_new_path(new, ly_ctx, xpath,
					  (void *)yang_dnode_get_string(
						  dnode_iter, NULL),
					  0, LYD_PATH_OPT_UPDATE)
			    && ly_errno) {
				flog_err(EC_LIB_LIBYANG,
					 "%s: lyd_new_path() failed", __func__);
				goto error;
			}

		next:
			LY_TREE_DFS_END(root, next, dnode_iter);
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

static int yang_translator_validate_cb(const struct lys_node *snode_custom,
				       void *arg)
{
	struct translator_validate_args *args = arg;
	struct yang_mapping_node *mapping;
	const struct lys_node *snode_native;
	const struct lys_type *stype_custom, *stype_native;
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
		ly_ctx_get_node(ly_native_ctx, NULL, mapping->xpath_to_fmt, 0);
	assert(snode_native);

	/* Check if the YANG types are compatible. */
	stype_custom = yang_snode_get_type(snode_custom);
	stype_native = yang_snode_get_type(snode_native);
	if (stype_custom && stype_native) {
		if (stype_custom->base != stype_native->base) {
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
		yang_snodes_iterate_module(
			tmodule->module, yang_translator_validate_cb,
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

static int yang_module_nodes_count_cb(const struct lys_node *snode, void *arg)
{
	unsigned int *total = arg;

	*total += 1;

	return YANG_ITER_CONTINUE;
}

/* Calculate the number of nodes for the given module. */
static unsigned int yang_module_nodes_count(const struct lys_module *module)
{
	unsigned int total = 0;

	yang_snodes_iterate_module(module, yang_module_nodes_count_cb,
				   YANG_ITER_FILTER_NPCONTAINERS
					   | YANG_ITER_FILTER_LIST_KEYS
					   | YANG_ITER_FILTER_INPUT_OUTPUT,
				   &total);

	return total;
}

/* TODO: rewrite this function. */
static void str_replace(char *o_string, const char *s_string,
			const char *r_string)
{
	char buffer[BUFSIZ];
	char *ch;

	ch = strstr(o_string, s_string);
	if (!ch)
		return;

	strncpy(buffer, o_string, ch - o_string);
	buffer[ch - o_string] = 0;

	sprintf(buffer + (ch - o_string), "%s%s", r_string,
		ch + strlen(s_string));

	o_string[0] = 0;
	strcpy(o_string, buffer);
	return str_replace(o_string, s_string, r_string);
}

void yang_translator_init(void)
{
	ly_translator_ctx =
		ly_ctx_new(YANG_MODELS_PATH, LY_CTX_DISABLE_SEARCHDIR_CWD);
	if (!ly_translator_ctx) {
		flog_err(EC_LIB_LIBYANG, "%s: ly_ctx_new() failed", __func__);
		exit(1);
	}

	if (!ly_ctx_load_module(ly_translator_ctx, "frr-module-translator",
				NULL)) {
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

	ly_ctx_destroy(ly_translator_ctx, NULL);
}
