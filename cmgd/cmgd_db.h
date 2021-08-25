/*
 * CMGD Databases
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

#ifndef _FRR_CMGD_DB_H_
#define _FRR_CMGD_DB_H_

#include "lib/typesafe.h"
#include "cmgd/cmgd_defines.h"
#include "lib/cmgd_pb.h"
#include "libyang/tree_data.h"
#include "cmgd/cmgd_bcknd_adapter.h"
#include "cmgd/cmgd_frntnd_adapter.h"
#include "lib/cmgd_frntnd_client.h"
#include "cmgd/cmgd.h"

#define CMGD_MAX_NUM_DBNODES_PER_BATCH		128

#define CMGD_DB_NAME_MAX_LEN    32
#define CMGD_DB_NAME_NONE                       "none"
#define CMGD_DB_NAME_RUNNING                    "running"
#define CMGD_DB_NAME_CANDIDATE                  "candidate"
#define CMGD_DB_NAME_OPERATION                  "operational"

#define FOREACH_CMGD_DB_ID(id)			                \
	for ((id) = CMGD_DB_NONE; (id) < CMGD_DB_MAX_ID; (id)++)

typedef uintptr_t cmgd_db_hndl_t;

typedef void (*cmgd_db_node_iter_fn)(cmgd_db_hndl_t db_hndl, 
        char *xpath, struct lyd_node *node, struct nb_node *nb_node,
	void *ctxt);


/***************************************************************
 * Global data exported
 ***************************************************************/

extern const char *cmgd_db_names[CMGD_DB_MAX_ID+1];

static inline const char *cmgd_db_id2name(cmgd_database_id_t id)
{
	if (id > CMGD_DB_MAX_ID)
		id = CMGD_DB_MAX_ID;
	return cmgd_db_names[id];
}

static inline cmgd_database_id_t cmgd_db_name2id(const char* name)
{
	cmgd_database_id_t id;

	FOREACH_CMGD_DB_ID(id) {
		if (!strncmp(cmgd_db_names[id], name,
			CMGD_DB_NAME_MAX_LEN))
			return id;
	}

	return CMGD_DB_NONE;
}

static inline cmgd_database_id_t cmgd_get_db_id_by_name(const char *db_name)
{
        if (!strncmp(db_name, "candidate", sizeof("candidate")))
		return CMGD_DB_CANDIDATE;
	else if (!strncmp(db_name, "running", sizeof("running")))
		return CMGD_DB_RUNNING;
	else if (!strncmp(db_name, "operational", sizeof("operational")))
		return CMGD_DB_OPERATIONAL;
	return CMGD_DB_NONE;
}
static inline void cmgd_xpath_append_trail_wildcard(
	char *xpath, size_t *xpath_len)
{
	if (!xpath || !xpath_len)
		return;

	if (!*xpath_len)
		*xpath_len = strlen(xpath);

	if (*xpath_len > 2 && *xpath_len < CMGD_MAX_XPATH_LEN-2) { 
		if (xpath[*xpath_len-1] == '/') {
			xpath[*xpath_len] = '*';
			xpath[*xpath_len+1] = 0;
                        (*xpath_len)++;
		} else if (xpath[*xpath_len-1] != '*') {
			xpath[*xpath_len] = '/';
			xpath[*xpath_len+1] = '*';
			xpath[*xpath_len+2] = 0;
                        (*xpath_len) += 2;
		}
	}
}

static inline void cmgd_xpath_remove_trail_wildcard(
	char *xpath, size_t *xpath_len)
{
	if (!xpath || !xpath_len)
		return;

	if (!*xpath_len)
		*xpath_len = strlen(xpath);

	if (*xpath_len > 2 && xpath[*xpath_len-2] == '/' &&
		xpath[*xpath_len-1] == '*') {
		xpath[*xpath_len-2] = 0;
                (*xpath_len) -= 2;
        }
}

extern int cmgd_db_init(struct cmgd_master *cm);

extern cmgd_db_hndl_t cmgd_db_get_hndl_by_id(
        struct cmgd_master *cm, cmgd_database_id_t db_id);

extern bool cmgd_db_is_config(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_read_lock(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_write_lock(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_unlock(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_merge_dbs(cmgd_db_hndl_t src_db, cmgd_db_hndl_t dst_db);

extern int cmgd_db_copy_dbs(cmgd_db_hndl_t src_db, cmgd_db_hndl_t dst_db);

extern struct nb_config *cmgd_db_get_nb_config(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_lookup_data_nodes(
        cmgd_db_hndl_t db_hndl, const char *xpath, char *dxpaths[],
        struct lyd_node *dnodes[], struct nb_node *nbnodes[],
	int *num_nodes, bool get_childs_as_well, bool donot_free_alloced);

extern struct lyd_node *cmgd_db_find_data_node_by_xpath(cmgd_db_hndl_t db_hndl,
	const char *xpath);

extern int cmgd_db_delete_data_nodes(
        cmgd_db_hndl_t db_hndl, const char *xpath);

extern int cmgd_db_iter_data(
        cmgd_db_hndl_t db_hndl, char *base_xpath,
        cmgd_db_node_iter_fn iter_fn, void *ctxt, bool donot_free_alloced);

extern int cmgd_db_hndl_send_get_data_req(
        cmgd_db_hndl_t db_hndl, cmgd_database_id_t db_id,
        cmgd_yang_getdata_req_t *data_req, int num_reqs);
extern void cmgd_db_dump_tree(
		struct vty *vty, cmgd_db_hndl_t db_hndl, const char* xpath,
		FILE *f, LYD_FORMAT format);

extern void cmgd_db_status_write_one(
        struct vty *vty, cmgd_db_hndl_t db_hndl);

extern void cmgd_db_status_write(struct vty *vty);

#endif /* _FRR_CMGD_DB_H_ */
