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

#include <pthread.h>

#include "thread.h"
#include "sockunion.h"
#include "prefix.h"
#include "network.h"
#include "lib/libfrr.h"
#include "lib/thread.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_memory.h"
#include "lib/cmgd_pb.h"
#include "lib/vty.h"
#include "cmgd/cmgd_db.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_DB_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_DB_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_DB_DBG(fmt, ...)				\
	zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_DB_ERR(fmt, ...)				\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

typedef struct cmgd_db_ctxt_ {
        cmgd_database_id_t db_id;
		pthread_rwlock_t rw_lock;

        struct nb_config *root;
} cmgd_db_ctxt_t;

int cmgd_db_init(struct cmgd_master *cm)
{
	cmgd_db_ctxt_t running, candidate, oper;

	// db_id to be added
	running.root = nb_config_new(NULL);
	candidate.root = nb_config_new(NULL);
	oper.root = nb_config_new(NULL);

	cm->running_db = (cmgd_db_hndl_t)&running;
	cm->cnadidate_db = (cmgd_db_hndl_t)&candidate;
	cm->oper_db = (cmgd_db_hndl_t)&oper;

	return 0;
}

int cmgd_db_read_lock(cmgd_db_hndl_t db_hndl)
{
	cmgd_db_ctxt_t *db_ctxt;
	int lock_status;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return -1;

	lock_status = pthread_rwlock_tryrdlock(&db_ctxt->rw_lock);
	return lock_status;

}

int cmgd_db_write_lock(cmgd_db_hndl_t db_hndl)
{
	cmgd_db_ctxt_t *db_ctxt;
	int lock_status;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return -1;

	lock_status = pthread_rwlock_trywrlock(&db_ctxt->rw_lock);
	return lock_status;
}

int cmgd_db_unlock(cmgd_db_hndl_t db_hndl)
{
	cmgd_db_ctxt_t *db_ctxt;
	int lock_status;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return -1;

	lock_status =  pthread_rwlock_unlock(&db_ctxt->rw_lock);
	return lock_status;
}

int cmgd_db_lookup_data_nodes(
        cmgd_db_hndl_t db_hndl, const char *xpath,
        struct lyd_node *dnodes[], int *num_nodes)
{
	cmgd_db_ctxt_t *db_ctxt;
	struct ly_set *set = NULL;
	uint32_t i;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return -1;

	if (xpath[0] == '.' && xpath[1] == '/')
		xpath += 2;

	lyd_find_xpath(db_ctxt->root->dnode, xpath, &set);
	for(i = 0; i < set->count; i++)
		dnodes[i] = set->dnodes[i];

	*num_nodes = set->count;

	ly_set_free(set, NULL);

	return 0;
}

int cmgd_db_delete_data_nodes(
        cmgd_db_hndl_t db_hndl, const char *xpath)
{
	cmgd_db_ctxt_t *db_ctxt;
	struct nb_node *nb_node;
	struct lyd_node *dnode, *dep_dnode;
	char dep_xpath[XPATH_MAXLEN];

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return -1;

	nb_node = nb_node_find(xpath);

	dnode = yang_dnode_get(db_ctxt->root->dnode, xpath);
	if (!dnode)
		/*
			* Return a special error code so the caller can choose
			* whether to ignore it or not.
			*/
		return NB_ERR_NOT_FOUND;
	/* destroy dependant */
	if (nb_node->dep_cbs.get_dependant_xpath) {
		nb_node->dep_cbs.get_dependant_xpath(dnode, dep_xpath);

		dep_dnode = yang_dnode_get(db_ctxt->root->dnode, dep_xpath);
		if (dep_dnode)
			lyd_free_tree(dep_dnode);
	}
	lyd_free_tree(dnode);

	return 0;
}

int cmgd_db_iter_data(
        cmgd_db_hndl_t db_hndl, char *base_xpath,
        cmgd_db_node_iter_fn iter_fn)
{
	cmgd_db_ctxt_t *db_ctxt;
	int i, count;
	struct lyd_node **dnodes = NULL;
	struct lyd_node *dnode_iter;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return -1;

	cmgd_db_lookup_data_nodes(db_hndl, base_xpath, dnodes, &count);

	for(i = 0; i < count; i++) {
		LYD_TREE_DFS_BEGIN (dnodes[i], dnode_iter) {
			iter_fn(db_hndl, dnode_iter);

			LYD_TREE_DFS_END (dnodes[i], dnode_iter);
		}
	}

	return 0;
}

int cmgd_db_hndl_send_get_data_req(
        cmgd_db_hndl_t db_hndl, cmgd_database_id_t db_id,
        cmgd_yang_getdata_req_t *data_req, int num_reqs)
{
	cmgd_db_ctxt_t *db_ctxt;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return -1;

	return 0;
}

void cmgd_db_hndl_status_write(
        struct vty *vty, cmgd_db_hndl_t db_hndl)
{
	cmgd_db_ctxt_t *db_ctxt;

	// vty_out(vty, "CMGD Transactions\n");

	// FOREACH_TRXN_IN_LIST(cmgd_trxn_cm, trxn) {
	// 	vty_out(vty, "  Trxn-Id: \t\t\t%p\n", trxn);
	// 	vty_out(vty, "    Session-Id: \t\t\t%lx\n", trxn->session_id);
	// }
	// vty_out(vty, "  Total: %d\n", 
	// 	(int) cmgd_trxn_list_count(&cmgd_trxn_cm->cmgd_trxns));
}
