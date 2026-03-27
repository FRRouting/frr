// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Mgmtd internal API for in-process callers (e.g. gRPC when running in mgmtd).
 *
 * Copyright (C) 2026  FRRouting
 */

#include <stdbool.h>
#include <zebra.h>
#include "darr.h"
#include "libyang/libyang.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_grpc_internal.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmt_msg_native.h"
#include "northbound.h"
#include "yang.h"

/* Validate request: CONFIG only, Running/Candidate only, LYB output only. */
static bool get_tree_validate_request(uint8_t flags, enum mgmt_ds_id ds_id,
				      uint8_t result_type)
{
	if (!CHECK_FLAG(flags, GET_DATA_FLAG_CONFIG))
		return false;
	if (ds_id != MGMTD_DS_RUNNING && ds_id != MGMTD_DS_CANDIDATE)
		return false;
	if (result_type != LYD_LYB)
		return false;
	return true;
}

/*
 * Duplicate the requested subtree from the config tree (we must not hand out
 * pointers into the live datastore). For path "/" duplicates the root;
 * otherwise resolves xpath and duplicates the matching node(s). Returns root
 * of the duplicate tree or NULL on error (caller frees with yang_dnode_free).
 */
static struct lyd_node *get_tree_dup_subtree(struct nb_config *config,
					     const char *path, LY_ERR *err_out)
{
	struct ly_set *set = NULL;
	struct lyd_node *result = NULL;
	LY_ERR err;

	*err_out = LY_SUCCESS;

	if (path[0] == '/' && path[1] == '\0') {
		/* Full tree: lyd_find_xpath may not return the root. */
		err = lyd_dup_single(config->dnode, NULL,
				     LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
				     &result);
		if (!err && result)
			while (result->parent)
				result = lyd_parent(result);
	} else {
		err = lyd_find_xpath(config->dnode, path, &set);
		if (err) {
			ly_set_free(set, NULL);
			*err_out = err;
			return NULL;
		}
		if (set->count == 1) {
			err = lyd_dup_single(set->dnodes[0], NULL,
					     LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS
						     | LYD_DUP_RECURSIVE,
					     &result);
			if (!err && result)
				while (result->parent)
					result = lyd_parent(result);
		} else if (set->count > 1) {
			err = lyd_dup_siblings(config->dnode, NULL,
					       LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
					       &result);
		}
		ly_set_free(set, NULL);
	}

	*err_out = err;
	return result;
}

/* Optional EXACT filter: replace result with duplicate of exact node at path. */
static int get_tree_apply_exact(struct lyd_node **result, const char *path)
{
	struct lyd_node *exact = yang_dnode_get(*result, path);
	struct lyd_node *dup = NULL;
	LY_ERR err;

	if (!exact)
		return 0;

	err = lyd_dup_single(exact, NULL,
			     LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS
				     | LYD_DUP_RECURSIVE,
			     &dup);
	yang_dnode_free(*result);
	*result = dup;
	if (err || !*result)
		return -1;
	while ((*result)->parent)
		*result = lyd_parent(*result);
	return 0;
}

/* Serialize lyd tree to LYB and copy into caller-owned buffer. Frees result. */
static int get_tree_serialize_lyb(struct lyd_node *result, uint32_t wd_options,
				  uint8_t result_type, uint8_t **out_lyb,
				  size_t *out_len)
{
	uint8_t *darr = NULL;

	wd_options |= LYD_PRINT_WITHSIBLINGS;
	darr = yang_print_tree(result, (LYD_FORMAT)result_type, wd_options);
	yang_dnode_free(result);
	if (!darr)
		return -1;

	*out_len = darr_len(darr);
	*out_lyb = XCALLOC(MTYPE_TMP, *out_len);
	if (!*out_lyb) {
		darr_free(darr);
		return -1;
	}
	memcpy(*out_lyb, darr, *out_len);
	darr_free(darr);
	return 0;
}

/*
 * Get config tree from mgmtd datastore (sync). Only CONFIG from Running or
 * Candidate is supported; Operational (STATE) requires backend and is not
 * implemented here.
 */
int mgmt_grpc_get_tree_internal(struct mgmt_master *master, enum mgmt_ds_id ds_id,
				const char *xpath, uint8_t flags, uint32_t wd_options,
				uint8_t result_type, uint8_t **out_lyb, size_t *out_len)
{
	struct mgmt_ds_ctx *ds;
	struct nb_config *config;
	struct lyd_node *result = NULL;
	const char *path = (xpath && xpath[0]) ? xpath : "/";
	LY_ERR err;

	*out_lyb = NULL;
	*out_len = 0;

	if (!get_tree_validate_request(flags, ds_id, result_type))
		return -1;

	ds = mgmt_ds_get_ctx_by_id(master, ds_id);
	if (!ds)
		return -1;

	config = mgmt_ds_get_nb_config(ds);
	if (!config || !config->dnode)
		return -1;

	result = get_tree_dup_subtree(config, path, &err);
	if (!result)
		return -1;

	if (CHECK_FLAG(flags, GET_DATA_FLAG_EXACT) && get_tree_apply_exact(&result, path) != 0) {
		if (result)
			yang_dnode_free(result);
		return -1;
	}

	return get_tree_serialize_lyb(result, wd_options, result_type, out_lyb,
				      out_len);
}
