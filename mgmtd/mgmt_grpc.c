// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mgmtd gRPC northbound integration.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "libfrr.h"
#include "northbound.h"
#include "yang.h"

#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"

static int mgmt_grpc_config_get_dispatch(const char *xpath,
					 struct lyd_node **result,
					 char *errmsg, size_t errmsg_len)
{
	struct mgmt_ds_ctx *ds;
	struct nb_config *config;
	const char *query = xpath;
	LY_ERR err;

	*result = NULL;

	ds = mgmt_ds_get_ctx_by_id(mm, MGMTD_DS_RUNNING);
	config = mgmt_ds_get_nb_config(ds);
	if (!config || !config->dnode) {
		snprintf(errmsg, errmsg_len, "No running configuration");
		return -ENOENT;
	}

	if (!query || !query[0] || strmatch(query, "/"))
		query = NULL;

	if (!query) {
		err = lyd_dup_siblings(config->dnode, NULL,
				       LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
				       result);
	} else if (yang_dnode_exists(config->dnode, query)) {
		struct lyd_node *dnode = yang_dnode_get(config->dnode, query);

		if (!dnode) {
			snprintf(errmsg, errmsg_len, "Data path not found");
			return -ENOENT;
		}

		err = lyd_dup_single(dnode, NULL,
				     LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS |
					     LYD_DUP_RECURSIVE,
				     result);
	} else {
		snprintf(errmsg, errmsg_len, "Data path not found");
		return -ENOENT;
	}

	if (err) {
		snprintf(errmsg, errmsg_len, "Cannot copy configuration");
		return -EINVAL;
	}
	if (!*result) {
		snprintf(errmsg, errmsg_len, "Data path not found");
		return -ENOENT;
	}

	while ((*result)->parent)
		*result = lyd_parent(*result);

	return 0;
}

void mgmt_grpc_init(void)
{
	nb_config_get_dispatch_set(mgmt_grpc_config_get_dispatch);
}

void mgmt_grpc_terminate(void)
{
	nb_config_get_dispatch_set(NULL);
}
