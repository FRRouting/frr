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

typedef uintptr_t cmgd_db_hndl_t;

typedef void (*cmgd_db_node_iter_fn)(cmgd_db_hndl_t db_hndl, 
        struct lyd_node *node, struct nb_node *nb_node);

extern int cmgd_db_init(struct cmgd_master *cm);

extern cmgd_db_hndl_t cmgd_db_get_hndl_by_id(
        struct cmgd_master *cm, cmgd_database_id_t db_id);

extern bool cmgd_db_is_config(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_read_lock(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_write_lock(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_unlock(cmgd_db_hndl_t db_hndl);

extern struct nb_config *cmgd_db_get_nb_config(cmgd_db_hndl_t db_hndl);

extern int cmgd_db_lookup_data_nodes(
        cmgd_db_hndl_t db_hndl, const char *xpath,
        struct lyd_node *dnodes[], struct nb_node *nbnodes[],
	int *num_nodes, bool get_childs_as_well);

extern int cmgd_db_delete_data_nodes(
        cmgd_db_hndl_t db_hndl, const char *xpath);

extern int cmgd_db_iter_data(
        cmgd_db_hndl_t db_hndl, char *base_xpath,
        cmgd_db_node_iter_fn iter_fn);

extern int cmgd_db_hndl_send_get_data_req(
        cmgd_db_hndl_t db_hndl, cmgd_database_id_t db_id,
        cmgd_yang_getdata_req_t *data_req, int num_reqs);

extern void cmgd_db_status_write(struct vty *vty);

#endif /* _FRR_CMGD_DB_H_ */
