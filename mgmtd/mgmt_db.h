/*
 * MGMTD Databases
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
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

#ifndef _FRR_MGMTD_DB_H_
#define _FRR_MGMTD_DB_H_

#include "mgmtd/mgmt_defines.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_fe_adapter.h"

#define MGMTD_MAX_NUM_DBNODES_PER_BATCH 128

#define MGMTD_DB_NAME_MAX_LEN 32
#define MGMTD_DB_NAME_NONE "none"
#define MGMTD_DB_NAME_RUNNING "running"
#define MGMTD_DB_NAME_CANDIDATE "candidate"
#define MGMTD_DB_NAME_OPERATIONAL "operational"

#define MGMTD_STARTUP_DB_FILE_PATH DAEMON_DB_DIR "/frr_startup.json"

#define FOREACH_MGMTD_DB_ID(id)                                                \
	for ((id) = MGMTD_DB_NONE; (id) < MGMTD_DB_MAX_ID; (id)++)

#define MGMTD_MAX_COMMIT_LIST 10
#define MGMTD_MD5_HASH_LEN 16
#define MGMTD_MD5_HASH_STR_HEX_LEN 33

#define MGMTD_COMMIT_FILE_PATH DAEMON_DB_DIR "/commit-%s.json"
#define MGMTD_COMMIT_INDEX_FILE_NAME DAEMON_DB_DIR "/commit-index.dat"
#define MGMTD_COMMIT_TIME_STR_LEN 100

extern struct nb_config *running_config;

struct mgmt_db_ctx;

PREDECL_DLIST(mgmt_cmt_infos);

/***************************************************************
 * Global data exported
 ***************************************************************/

extern const char *mgmt_db_names[MGMTD_DB_MAX_ID + 1];

/*
 * Convert database ID to database name.
 *
 * id
 *    Database ID.
 *
 * Returns:
 *    Database name.
 */
static inline const char *mgmt_db_id2name(Mgmtd__DatabaseId id)
{
	if (id > MGMTD_DB_MAX_ID)
		id = MGMTD_DB_MAX_ID;
	return mgmt_db_names[id];
}

/*
 * Convert database name to database ID.
 *
 * id
 *    Database name.
 *
 * Returns:
 *    Database ID.
 */
static inline Mgmtd__DatabaseId mgmt_db_name2id(const char *name)
{
	Mgmtd__DatabaseId id;

	FOREACH_MGMTD_DB_ID (id) {
		if (!strncmp(mgmt_db_names[id], name, MGMTD_DB_NAME_MAX_LEN))
			return id;
	}

	return MGMTD_DB_NONE;
}

/*
 * Convert database ID to database name.
 *
 * similar to above funtion.
 */
static inline Mgmtd__DatabaseId mgmt_get_db_id_by_name(const char *db_name)
{
	if (!strncmp(db_name, "candidate", sizeof("candidate")))
		return MGMTD_DB_CANDIDATE;
	else if (!strncmp(db_name, "running", sizeof("running")))
		return MGMTD_DB_RUNNING;
	else if (!strncmp(db_name, "operational", sizeof("operational")))
		return MGMTD_DB_OPERATIONAL;
	return MGMTD_DB_NONE;
}

/*
 * Appends trail wildcard '/' '*' to a given xpath.
 *
 * xpath
 *     YANG xpath.
 *
 * path_len
 *     xpath length.
 */
static inline void mgmt_xpath_append_trail_wildcard(char *xpath,
						    size_t *xpath_len)
{
	if (!xpath || !xpath_len)
		return;

	if (!*xpath_len)
		*xpath_len = strlen(xpath);

	if (*xpath_len > 2 && *xpath_len < MGMTD_MAX_XPATH_LEN - 2) {
		if (xpath[*xpath_len - 1] == '/') {
			xpath[*xpath_len] = '*';
			xpath[*xpath_len + 1] = 0;
			(*xpath_len)++;
		} else if (xpath[*xpath_len - 1] != '*') {
			xpath[*xpath_len] = '/';
			xpath[*xpath_len + 1] = '*';
			xpath[*xpath_len + 2] = 0;
			(*xpath_len) += 2;
		}
	}
}

/*
 * Removes trail wildcard '/' '*' from a given xpath.
 *
 * xpath
 *     YANG xpath.
 *
 * path_len
 *     xpath length.
 */
static inline void mgmt_xpath_remove_trail_wildcard(char *xpath,
						    size_t *xpath_len)
{
	if (!xpath || !xpath_len)
		return;

	if (!*xpath_len)
		*xpath_len = strlen(xpath);

	if (*xpath_len > 2 && xpath[*xpath_len - 2] == '/'
	    && xpath[*xpath_len - 1] == '*') {
		xpath[*xpath_len - 2] = 0;
		(*xpath_len) -= 2;
	}
}

/* Initialise database */
extern int mgmt_db_init(struct mgmt_master *cm);

/* Destroy database */
extern void mgmt_db_destroy(void);

/*
 * Get database handler by ID
 *
 * mm
 *    Management master structure.
 *
 * db_id
 *    Database ID.
 *
 * Returns:
 *    Database context (Holds info about ID, lock, root node etc).
 */
extern struct mgmt_db_ctx *mgmt_db_get_ctx_by_id(struct mgmt_master *mm,
						   Mgmtd__DatabaseId db_id);

/*
 * Check if a given database is config db
 */
extern bool mgmt_db_is_config(struct mgmt_db_ctx *db_ctx);

/*
 * Acquire read lock to a db given a db_handle
 */
extern int mgmt_db_read_lock(struct mgmt_db_ctx *db_ctx);

/*
 * Acquire write lock to a db given a db_handle
 */
extern int mgmt_db_write_lock(struct mgmt_db_ctx *db_ctx);

/*
 * Remove a lock from db given a db_handle
 */
extern int mgmt_db_unlock(struct mgmt_db_ctx *db_ctx);

/*
 * Merge two databases.
 *
 * src_db
 *    Source database handle.
 *
 * dst_db
 *    Destination database handle.
 *
 * update_cmd_rec
 *    TRUE if need to update commit record, FALSE otherwise.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_db_merge_dbs(struct mgmt_db_ctx *src_db_ctx,
			     struct mgmt_db_ctx *dst_db_ctx,
			     bool update_cmt_rec);

/*
 * Copy from source to destination database.
 *
 * src_db
 *    Source database handle (db to be copied from).
 *
 * dst_db
 *    Destination database handle (db to be copied to).
 *
 * update_cmd_rec
 *    TRUE if need to update commit record, FALSE otherwise.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_db_copy_dbs(struct mgmt_db_ctx *src_db_ctx,
			    struct mgmt_db_ctx *dst_db_ctx,
			    bool update_cmt_rec);

/*
 * Fetch northbound configuration for a given database context.
 */
extern struct nb_config *mgmt_db_get_nb_config(struct mgmt_db_ctx *db_ctx);

/*
 * Lookup YANG data nodes.
 *
 * db_ctx
 *    Database context.
 *
 * xpath
 *    YANG base xpath.
 *
 * dxpaths
 *    Out param - array of YANG data xpaths.
 *
 * num_nodes
 *    In-out param - number of YANG data xpaths.
 *    Note - Caller should init this to the size of the array
 *    provided in dxpaths.
 *    On return this will have the actual number of xpaths
 *    being returned.
 *
 * get_childs_as_well
 *    TRUE if child nodes needs to be fetched as well, FALSE otherwise.
 *
 * alloc_xp_copy
 *    TRUE if the caller is interested in getting a copy of the xpath.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_db_lookup_data_nodes(struct mgmt_db_ctx *db_ctx,
				     const char *xpath, char *dxpaths[],
				     int *num_nodes, bool get_childs_as_well,
				     bool alloc_xp_copy);

/*
 * Find YANG data node given a database handle YANG xpath.
 */
extern struct lyd_node *
mgmt_db_find_data_node_by_xpath(struct mgmt_db_ctx *db_ctx,
				const char *xpath);

/*
 * Delete YANG data node given a database handle and YANG xpath.
 */
extern int mgmt_db_delete_data_nodes(struct mgmt_db_ctx *db_ctx,
				     const char *xpath);

/*
 * Iterate over database data.
 *
 * db_ctx
 *    Database context.
 *
 * base_xpath
 *    Base YANG xpath from where needs to be iterated.
 *
 * iter_fn
 *    function that will be called during each iteration.
 *
 * ctx
 *    User defined opaque value normally used to pass
 *    reference to some user private context that will
 *    be passed to the iterator function provided in
 *    'iter_fn'.
 *
 * alloc_xp_copy
 *    TRUE if the caller is interested in getting a copy of the xpath.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_db_iter_data(
	struct mgmt_db_ctx *db_ctx, char *base_xpath,
	void (*mgmt_db_node_iter_fn)(struct mgmt_db_ctx *db_ctx, char *xpath,
				     struct lyd_node *node,
				     struct nb_node *nb_node, void *ctx),
	void *ctx, bool alloc_xp_copy);

/*
 * Load config to database from a file.
 *
 * db_ctx
 *    Database context.
 *
 * file_path
 *    File path of the configuration file.
 *
 * merge
 *    TRUE if you want to merge with existing config,
 *    FALSE if you want to replace with existing config
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_db_load_config_from_file(struct mgmt_db_ctx *db_ctx,
					 const char *file_path, bool merge);

/*
 * Dump the data tree to a file with JSON/XML format.
 *
 * vty
 *    VTY context.
 *
 * db_ctx
 *    Database context.
 *
 * xpath
 *    Base YANG xpath from where data needs to be dumped.
 *
 * f
 *    File pointer to where data to be dumped.
 *
 * format
 *    JSON/XML
 */
extern void mgmt_db_dump_tree(struct vty *vty, struct mgmt_db_ctx *db_ctx,
			      const char *xpath, FILE *f, LYD_FORMAT format);

/*
 * Dump the complete data tree to a file with JSON format.
 *
 * file_name
 *    File path to where data to be dumped.
 *
 * db
 *    Database context.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_db_dump_db_to_file(char *file_name,
				   struct mgmt_db_ctx *db_ctx);

/*
 * Rollback specific commit from commit history.
 *
 * vty
 *    VTY context.
 *
 * cmtid_str
 *    Specific commit id from commit history.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_db_rollback_by_cmtid(struct vty *vty, const char *cmtid_str);

/*
 * Rollback n commits from commit history.
 *
 * vty
 *    VTY context.
 *
 * num_cmts
 *    Number of commits to be rolled back.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_db_rollback_commits(struct vty *vty, int num_cmts);

/*
 * Dump information about specific database.
 */
extern void mgmt_db_status_write_one(struct vty *vty,
				     struct mgmt_db_ctx *db_ctx);

/*
 * Dump information about all the databases.
 */
extern void mgmt_db_status_write(struct vty *vty);

/*
 * Show mgmt commit history.
 */
extern void show_mgmt_cmt_history(struct vty *vty);

#endif /* _FRR_MGMTD_DB_H_ */
