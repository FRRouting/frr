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

#include "lib/typesafe.h"
#include "mgmtd/mgmt_defines.h"
#include "lib/mgmt_pb.h"
#include "libyang/tree_data.h"
#include "mgmtd/mgmt_bcknd_adapter.h"
#include "mgmtd/mgmt_frntnd_adapter.h"
#include "lib/mgmt_frntnd_client.h"
#include "mgmtd/mgmt.h"

#define MGMTD_MAX_NUM_DBNODES_PER_BATCH 128

#define MGMTD_DB_NAME_MAX_LEN 32
#define MGMTD_DB_NAME_NONE "none"
#define MGMTD_DB_NAME_RUNNING "running"
#define MGMTD_DB_NAME_CANDIDATE "candidate"
#define MGMTD_DB_NAME_OPERATIONAL "operational"

#define MGMTD_STARTUP_DB_FILE_PATH "/etc/frr/frr_startup.json"

#define FOREACH_MGMTD_DB_ID(id)                                                \
	for ((id) = MGMTD_DB_NONE; (id) < MGMTD_DB_MAX_ID; (id)++)

#define MGMTD_MAX_COMMIT_LIST 10
#define MGMTD_MD5_HASH_LEN 16
#define MGMTD_MD5_HASH_STR_HEX_LEN 33

#define MGMTD_MAX_COMMIT_FILE_PATH_LEN 55
#define MGMTD_COMMIT_FILE_PATH "/etc/frr/commit-%s.json"
#define MGMTD_COMMIT_INDEX_FILE_NAME "/etc/frr/commit-index.dat"
#define MGMTD_COMMIT_TIME_STR_LEN 30

extern struct nb_config *running_config;

typedef void (*mgmt_db_node_iter_fn)(uint64_t db_hndl, char *xpath,
				     struct lyd_node *node,
				     struct nb_node *nb_node, void *ctxt);

PREDECL_DLIST(mgmt_cmt_info_dlist);

/***************************************************************
 * Global data exported
 ***************************************************************/

extern const char *mgmt_db_names[MGMTD_DB_MAX_ID + 1];

static inline const char *mgmt_db_id2name(Mgmtd__DatabaseId id)
{
	if (id > MGMTD_DB_MAX_ID)
		id = MGMTD_DB_MAX_ID;
	return mgmt_db_names[id];
}

static inline Mgmtd__DatabaseId mgmt_db_name2id(const char *name)
{
	Mgmtd__DatabaseId id;

	FOREACH_MGMTD_DB_ID(id)
	{
		if (!strncmp(mgmt_db_names[id], name, MGMTD_DB_NAME_MAX_LEN))
			return id;
	}

	return MGMTD_DB_NONE;
}

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

extern int mgmt_db_init(struct mgmt_master *cm);

extern void mgmt_db_destroy(void);

extern uint64_t mgmt_db_get_hndl_by_id(struct mgmt_master *cm,
				       Mgmtd__DatabaseId db_id);

extern bool mgmt_db_is_config(uint64_t db_hndl);

extern int mgmt_db_read_lock(uint64_t db_hndl);

extern int mgmt_db_write_lock(uint64_t db_hndl);

extern int mgmt_db_unlock(uint64_t db_hndl);

extern int mgmt_db_merge_dbs(uint64_t src_db, uint64_t dst_db,
			     bool update_cmt_rec);

extern int mgmt_db_copy_dbs(uint64_t src_db, uint64_t dst_db,
			    bool update_cmt_rec);

extern struct nb_config *mgmt_db_get_nb_config(uint64_t db_hndl);

extern int mgmt_db_lookup_data_nodes(uint64_t db_hndl, const char *xpath,
				     char *dxpaths[], int *num_nodes,
				     bool get_childs_as_well,
				     bool alloc_xp_copy);

extern struct lyd_node *mgmt_db_find_data_node_by_xpath(uint64_t db_hndl,
							const char *xpath);

extern int mgmt_db_delete_data_nodes(uint64_t db_hndl, const char *xpath);

extern int mgmt_db_iter_data(uint64_t db_hndl, char *base_xpath,
			     mgmt_db_node_iter_fn iter_fn, void *ctxt,
			     bool alloc_xp_copy);

extern int mgmt_db_load_config_from_file(uint64_t db_hndl,
					 const char *file_path, bool merge);

extern void mgmt_db_dump_tree(struct vty *vty, uint64_t db_hndl,
			      const char *xpath, FILE *f, LYD_FORMAT format);

extern int mgmt_db_dump_db_to_file(char *file_name, uint64_t db);

extern int mgmt_db_rollback_by_cmtid(struct vty *vty, const char *cmtid_str);

extern int mgmt_db_rollback_commits(struct vty *vty, int num_cmts);

extern void mgmt_db_status_write_one(struct vty *vty, uint64_t db_hndl);

extern void mgmt_db_status_write(struct vty *vty);

extern void show_mgmt_cmt_history(struct vty *vty);

#endif /* _FRR_MGMTD_DB_H_ */
