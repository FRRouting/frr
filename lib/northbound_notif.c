// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * December 1 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2024, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "debug.h"
#include "typesafe.h"
#include "northbound.h"

#define __dbg(fmt, ...)	    DEBUGD(&nb_dbg_notif, "NB_OP_CHANGE: %s: " fmt, __func__, ##__VA_ARGS__)
#define __log_err(fmt, ...) zlog_err("NB_OP_CHANGE: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)

static void nb_notif_add(const char *path)
{
}


static void nb_notif_delete(const char *path)
{
}

struct lyd_node *nb_op_update(struct lyd_node *tree, const char *path, const char *value)
{
	struct lyd_node *dnode;
	const char *abs_path = NULL;


	__dbg("updating path: %s with value: %s", path, value);

	dnode = yang_state_new(tree, path, value);

	if (path[0] == '/')
		abs_path = path;
	else {
		abs_path = lyd_path(dnode, LYD_PATH_STD, NULL, 0);
	}

	nb_notif_add(abs_path);

	if (abs_path != path)
		free((char *)abs_path);

	return dnode;
}

void nb_op_update_delete(struct lyd_node *tree, const char *path)
{
	char *abs_path = NULL;

	__dbg("deleting path: %s", path);

	if (path && path[0] == '/')
		abs_path = (char *)path;
	else {
		assert(tree);
		abs_path = lyd_path(tree, LYD_PATH_STD, NULL, 0);
		assert(abs_path);
		if (path) {
			char *tmp = darr_strdup(abs_path);
			free(abs_path);
			abs_path = tmp;
			if (*darr_last(abs_path) != '/')
				darr_in_strcat(abs_path, "/");
			assert(abs_path); /* silence bad CLANG NULL warning */
			darr_in_strcat(abs_path, path);
		}
	}

	yang_state_delete(tree, path);

	nb_notif_delete(abs_path);

	if (abs_path != path) {
		if (path)
			darr_free(abs_path);
		else
			free(abs_path);
	}
}

PRINTFRR(2, 0)
struct lyd_node *nb_op_update_vpathf(struct lyd_node *tree, const char *path_fmt, const char *value,
				     va_list ap)
{
	struct lyd_node *dnode;
	char *path;

	path = darr_vsprintf(path_fmt, ap);
	dnode = nb_op_update(tree, path, value);
	darr_free(path);

	return dnode;
}

struct lyd_node *nb_op_update_pathf(struct lyd_node *tree, const char *path_fmt, const char *value,
				    ...)
{
	struct lyd_node *dnode;
	va_list ap;

	va_start(ap, value);
	dnode = nb_op_update_vpathf(tree, path_fmt, value, ap);
	va_end(ap);

	return dnode;
}

PRINTFRR(2, 0)
void nb_op_update_delete_vpathf(struct lyd_node *tree, const char *path_fmt, va_list ap)
{
	char *path;

	path = darr_vsprintf(path_fmt, ap);
	nb_op_update_delete(tree, path);
	darr_free(path);
}

void nb_op_update_delete_pathf(struct lyd_node *tree, const char *path_fmt, ...)
{
	va_list ap;

	va_start(ap, path_fmt);
	nb_op_update_delete_vpathf(tree, path_fmt, ap);
	va_end(ap);
}


PRINTFRR(3, 0)
struct lyd_node *nb_op_vupdatef(struct lyd_node *tree, const char *path, const char *val_fmt,
				va_list ap)
{
	struct lyd_node *dnode;
	char *value;

	value = darr_vsprintf(val_fmt, ap);
	dnode = nb_op_update(tree, path, value);
	darr_free(value);

	return dnode;
}


struct lyd_node *nb_op_updatef(struct lyd_node *tree, const char *path, const char *val_fmt, ...)
{
	struct lyd_node *dnode;
	va_list ap;

	va_start(ap, val_fmt);
	dnode = nb_op_vupdatef(tree, path, val_fmt, ap);
	va_end(ap);

	return dnode;
}
