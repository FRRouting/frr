// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Datastores
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#ifndef _FRR_MGMTD_DS_H_
#define _FRR_MGMTD_DS_H_

#include "mgmt_fe_client.h"
#include "northbound.h"
#include "mgmt_defines.h"

#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_fe_adapter.h"

#define MGMTD_MAX_NUM_DSNODES_PER_BATCH 128

#define MGMTD_DS_NAME_MAX_LEN 32
#define MGMTD_DS_NAME_NONE "none"
#define MGMTD_DS_NAME_RUNNING "running"
#define MGMTD_DS_NAME_CANDIDATE "candidate"
#define MGMTD_DS_NAME_OPERATIONAL "operational"

#define FOREACH_MGMTD_DS_ID(id)                                                \
	for ((id) = MGMTD_DS_NONE; (id) < MGMTD_DS_MAX_ID; (id)++)

#define MGMTD_MAX_COMMIT_LIST 10

#define MGMTD_COMMIT_FILE_PATH(id)   "%s/commit-%s.json", frr_libstatedir, id
#define MGMTD_COMMIT_INDEX_FILE_PATH "%s/commit-index.dat", frr_libstatedir

extern struct nb_config *running_config;

struct mgmt_ds_ctx;

/***************************************************************
 * Global data exported
 ***************************************************************/

extern const char *mgmt_ds_names[MGMTD_DS_MAX_ID + 1];

/*
 * Convert datastore ID to datastore name.
 *
 * id
 *    Datastore ID.
 *
 * Returns:
 *    Datastore name.
 */
static inline const char *mgmt_ds_id2name(Mgmtd__DatastoreId id)
{
	if (id > MGMTD_DS_MAX_ID)
		id = MGMTD_DS_MAX_ID;
	return mgmt_ds_names[id];
}

/*
 * Convert datastore name to datastore ID.
 *
 * id
 *    Datastore name.
 *
 * Returns:
 *    Datastore ID.
 */
static inline Mgmtd__DatastoreId mgmt_ds_name2id(const char *name)
{
	Mgmtd__DatastoreId id;

	FOREACH_MGMTD_DS_ID (id) {
		if (!strncmp(mgmt_ds_names[id], name, MGMTD_DS_NAME_MAX_LEN))
			return id;
	}

	return MGMTD_DS_NONE;
}

/*
 * Convert datastore ID to datastore name.
 *
 * similar to above funtion.
 */
static inline Mgmtd__DatastoreId mgmt_get_ds_id_by_name(const char *ds_name)
{
	if (!strncmp(ds_name, "candidate", sizeof("candidate")))
		return MGMTD_DS_CANDIDATE;
	else if (!strncmp(ds_name, "running", sizeof("running")))
		return MGMTD_DS_RUNNING;
	else if (!strncmp(ds_name, "operational", sizeof("operational")))
		return MGMTD_DS_OPERATIONAL;
	return MGMTD_DS_NONE;
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

/* Initialise datastore */
extern int mgmt_ds_init(struct mgmt_master *cm);

/* Destroy datastore */
extern void mgmt_ds_destroy(void);

/*
 * Get datastore handler by ID
 *
 * mm
 *    Management master structure.
 *
 * ds_id
 *    Datastore ID.
 *
 * Returns:
 *    Datastore context (Holds info about ID, lock, root node etc).
 */
extern struct mgmt_ds_ctx *mgmt_ds_get_ctx_by_id(struct mgmt_master *mm,
						   Mgmtd__DatastoreId ds_id);

/*
 * Check if a given datastore is config ds
 */
extern bool mgmt_ds_is_config(struct mgmt_ds_ctx *ds_ctx);

/*
 * Check if a given datastore is locked by a given session
 */
extern bool mgmt_ds_is_locked(struct mgmt_ds_ctx *ds_ctx, uint64_t session_id);

/*
 * Acquire write lock to a ds given a ds_handle
 */
extern int mgmt_ds_lock(struct mgmt_ds_ctx *ds_ctx, uint64_t session_id);

/*
 * Remove a lock from ds given a ds_handle
 */
extern void mgmt_ds_unlock(struct mgmt_ds_ctx *ds_ctx);

/*
 * Copy from source to destination datastore.
 *
 * src_ds
 *    Source datastore handle (ds to be copied from).
 *
 * dst_ds
 *    Destination datastore handle (ds to be copied to).
 *
 * update_cmd_rec
 *    TRUE if need to update commit record, FALSE otherwise.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_ds_copy_dss(struct mgmt_ds_ctx *src_ds_ctx,
			    struct mgmt_ds_ctx *dst_ds_ctx,
			    bool update_cmt_rec);

/*
 * Fetch northbound configuration for a given datastore context.
 */
extern struct nb_config *mgmt_ds_get_nb_config(struct mgmt_ds_ctx *ds_ctx);

/*
 * Find YANG data node given a datastore handle YANG xpath.
 */
extern struct lyd_node *
mgmt_ds_find_data_node_by_xpath(struct mgmt_ds_ctx *ds_ctx,
				const char *xpath);

/*
 * Delete YANG data node given a datastore handle and YANG xpath.
 */
extern int mgmt_ds_delete_data_nodes(struct mgmt_ds_ctx *ds_ctx,
				     const char *xpath);

/*
 * Iterate over datastore data.
 *
 * ds_id
 *    Datastore ID..
 *
 * root
 *    The root of the tree to iterate over.
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
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_ds_iter_data(
	Mgmtd__DatastoreId ds_id, struct nb_config *root,
	const char *base_xpath,
	void (*mgmt_ds_node_iter_fn)(const char *xpath, struct lyd_node *node,
				     struct nb_node *nb_node, void *ctx),
	void *ctx);

/*
 * Load config to datastore from a file.
 *
 * ds_ctx
 *    Datastore context.
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
extern int mgmt_ds_load_config_from_file(struct mgmt_ds_ctx *ds_ctx,
					 const char *file_path, bool merge);

/*
 * Dump the data tree to a file with JSON/XML format.
 *
 * vty
 *    VTY context.
 *
 * ds_ctx
 *    Datastore context.
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
extern void mgmt_ds_dump_tree(struct vty *vty, struct mgmt_ds_ctx *ds_ctx,
			      const char *xpath, FILE *f, LYD_FORMAT format);

/*
 * Dump the complete data tree to a file with JSON format.
 *
 * file_name
 *    File path to where data to be dumped.
 *
 * ds
 *    Datastore context.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_ds_dump_ds_to_file(char *file_name,
				   struct mgmt_ds_ctx *ds_ctx);

/*
 * Dump information about specific datastore.
 */
extern void mgmt_ds_status_write_one(struct vty *vty,
				     struct mgmt_ds_ctx *ds_ctx);

/*
 * Dump information about all the datastores.
 */
extern void mgmt_ds_status_write(struct vty *vty);


/*
 * Reset the candidate DS to empty state
 */
void mgmt_ds_reset_candidate(void);

#endif /* _FRR_MGMTD_DS_H_ */
