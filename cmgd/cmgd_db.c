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
#include "lib/md5.h"
#include "lib/typesafe.h"
#include "lib/thread.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_memory.h"
#include "lib/cmgd_pb.h"
#include "lib/vty.h"
#include "cmgd/cmgd_db.h"
#include "libyang/libyang.h"
#include "cmgd/cmgd_trxn.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_DB_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_DB_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_DB_DBG(fmt, ...)					\
	if (cmgd_debug_db)					\
		zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_DB_ERR(fmt, ...)					\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_CMT_REC(cm, itr_cmt_info)                                  \
        frr_each_safe(cmgd_cmt_info_dlist, &cm->cmt_dlist, itr_cmt_info)

typedef struct cmgd_db_ctxt_ {
	cmgd_database_id_t db_id;
	pthread_rwlock_t rw_lock;

	bool config_db;

	union {
		struct nb_config *cfg_root;
		struct lyd_node *dnode_root;
	} root;
} cmgd_db_ctxt_t;

const char *cmgd_db_names[CMGD_DB_MAX_ID+1] = {
	CMGD_DB_NAME_NONE, 		/* CMGD_DB_NONE */
	CMGD_DB_NAME_RUNNING, 		/* CMGD_DB_RUNNING */
	CMGD_DB_NAME_CANDIDATE, 	/* CMGD_DB_RUNNING */
	CMGD_DB_NAME_OPERATIONAL, 	/* CMGD_DB_OPERATIONAL */
	"Unknown/Invalid", 		/* CMGD_DB_ID_MAX */
};

static struct cmgd_master *cmgd_db_cm = NULL;
static cmgd_db_ctxt_t running, candidate, oper;

extern struct nb_config *running_config;

/* Dump the data tree of the specified format in the file pointed by the path */
static int cmgd_db_dump_in_memory(
		cmgd_db_ctxt_t *db_ctxt, const char *base_xpath,
		LYD_FORMAT format, struct ly_out *out)
{
	struct lyd_node *root;
	uint32_t options = 0;

	if (base_xpath[0] == '\0')
		root = db_ctxt->config_db ? db_ctxt->root.cfg_root->dnode
					  : db_ctxt->root.dnode_root;
	else
		root = yang_dnode_get(db_ctxt->config_db
					      ? db_ctxt->root.cfg_root->dnode
					      : db_ctxt->root.dnode_root,
				      base_xpath);
	if (!root)
		return -1;

	if (base_xpath[0] == '\0')
		lyd_print_all(out, root, format, options);
	else
		lyd_print_tree(out, root, format, options);

	return 0;
}

static int cmgd_db_replace_dst_with_src_db(
        cmgd_db_ctxt_t *src, cmgd_db_ctxt_t *dst)
{
	struct lyd_node *dst_dnode, *src_dnode;
	struct ly_out *out;

	if (!src || !dst)
		return -1;
	CMGD_DB_DBG("Replacing %d with %d", dst->db_id, src->db_id);

	src_dnode = src->config_db ? src->root.cfg_root->dnode :
				dst->root.dnode_root;
	dst_dnode = dst->config_db ? dst->root.cfg_root->dnode :
				dst->root.dnode_root;

	if (dst_dnode)
		yang_dnode_free(dst_dnode);

	/* Not using nb_config_replace as the oper db does not contain nb_config */
	dst_dnode = yang_dnode_dup(src_dnode);
	if (dst->config_db)
		dst->root.cfg_root->dnode = dst_dnode;
	else
		dst->root.dnode_root = dst_dnode;

	if (src->db_id == CMGD_DB_CANDIDATE) {
		/*
		 * Drop the changes in scratch-buffer.
		 */
		CMGD_DB_DBG("Emptying Candidate Scratch buffer!");
		nb_config_diff_del_changes(&src->root.cfg_root->cfg_chgs);
	}

	if (dst->db_id == CMGD_DB_RUNNING) {
		if (ly_out_new_filepath(CMGD_STARTUP_DB_FILE_PATH, &out) == LY_SUCCESS)
			cmgd_db_dump_in_memory(dst, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	// TODO: Update the versions if nb_config present

	return 0;
}

static int cmgd_db_merge_src_with_dst_db(
        cmgd_db_ctxt_t *src, cmgd_db_ctxt_t *dst)
{
	int ret;
	struct lyd_node **dst_dnode, *src_dnode;
	struct ly_out *out;

	if (!src || !dst)
		return -1;

	CMGD_DB_DBG("Merging DB %d with %d", dst->db_id, src->db_id);

	src_dnode = src->config_db ? src->root.cfg_root->dnode :
				dst->root.dnode_root;
	dst_dnode = dst->config_db ? &dst->root.cfg_root->dnode :
				&dst->root.dnode_root;
	ret = lyd_merge_siblings(dst_dnode, src_dnode, 0);
	if (ret != 0) {
		CMGD_DB_ERR("lyd_merge() failed with err %d", ret);
		return ret;
	}

	if (src->db_id == CMGD_DB_CANDIDATE) {
		/*
		 * Drop the changes in scratch-buffer.
		 */
		CMGD_DB_DBG("Emptying Candidate Scratch buffer!");
		nb_config_diff_del_changes(&src->root.cfg_root->cfg_chgs);
	}

	if (dst->db_id == CMGD_DB_RUNNING) {
		if (ly_out_new_filepath(CMGD_STARTUP_DB_FILE_PATH, &out) == LY_SUCCESS)
			cmgd_db_dump_in_memory(dst, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	return 0;
}

static int cmgd_db_load_cfg_from_file(const char *filepath, struct lyd_node **dnode)
{
	LY_ERR ret;

	*dnode = NULL;
	ret = lyd_parse_data_path(ly_native_ctx, filepath, LYD_JSON, LYD_PARSE_STRICT, 0, dnode);

	if (ret != LY_SUCCESS) {
		if (*dnode)
			yang_dnode_free(*dnode);
		return -1;
	}

	return 0;
}

int cmgd_db_init(struct cmgd_master *cm)
{
	struct lyd_node *root;

	if (cmgd_db_cm || cm->running_db || cm->candidate_db || cm->oper_db)
		assert(!"Call cmgd_db_init() only once!");

	// Use Running DB from NB module???
	if (!running_config)
		assert(!"Call cmgd_db_init() after frr_init() only!");

	if (cmgd_db_load_cfg_from_file(CMGD_STARTUP_DB_FILE_PATH, &root) == 0) {
		nb_config_free(running_config);
		running_config = nb_config_new(root);
	}

	running.root.cfg_root = running_config;
	running.config_db = true;
	running.db_id = CMGD_DB_RUNNING;

	candidate.root.cfg_root = nb_config_dup(running.root.cfg_root);
	candidate.config_db = true;
	candidate.db_id = CMGD_DB_CANDIDATE;

	/*
	 * Redirect lib/vty candidate-config database to the global candidate
	 * config Db on the CMGD process.
	 */
	vty_cmgd_candidate_config = candidate.root.cfg_root;

	oper.root.dnode_root = yang_dnode_new(ly_native_ctx, true);
	oper.config_db = false;
	oper.db_id = CMGD_DB_OPERATIONAL;

	cm->running_db = (cmgd_db_hndl_t)&running;
	cm->candidate_db = (cmgd_db_hndl_t)&candidate;
	cm->oper_db = (cmgd_db_hndl_t)&oper;
	cmgd_db_cm = cm;

	return 0;
}

cmgd_db_hndl_t cmgd_db_get_hndl_by_id(
        struct cmgd_master *cm, cmgd_database_id_t db_id)
{
	switch (db_id) {
	case CMGD_DB_CANDIDATE:
		return (cm->candidate_db);
	case CMGD_DB_RUNNING:
		return (cm->running_db);
	case CMGD_DB_OPERATIONAL:
		return (cm->oper_db);
	default:
		break;
	}

	return 0;
}

bool cmgd_db_is_config(cmgd_db_hndl_t db_hndl)
{
	cmgd_db_ctxt_t *db_ctxt;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return false;

	return db_ctxt->config_db;
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

int cmgd_db_merge_dbs(
        cmgd_db_hndl_t src_db, cmgd_db_hndl_t dst_db)
{
	cmgd_db_ctxt_t *src, *dst;

	src = (cmgd_db_ctxt_t *)src_db;
	dst = (cmgd_db_ctxt_t *)dst_db;

	return cmgd_db_merge_src_with_dst_db(src, dst);
}

int cmgd_db_copy_dbs(
        cmgd_db_hndl_t src_db, cmgd_db_hndl_t dst_db)
{
	cmgd_db_ctxt_t *src, *dst;

	src = (cmgd_db_ctxt_t *)src_db;
	dst = (cmgd_db_ctxt_t *)dst_db;

	return cmgd_db_replace_dst_with_src_db(src, dst);
}

int cmgd_db_dump_db_to_file(char *file_name, cmgd_db_hndl_t db)
{
	cmgd_db_ctxt_t *db_ctxt;
	struct ly_out *out;
	int ret = 0;

	db_ctxt = (cmgd_db_ctxt_t *)db;

	if (ly_out_new_filepath(file_name, &out) == LY_SUCCESS) {
		ret = cmgd_db_dump_in_memory(db_ctxt,
			"", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	return ret;
}

struct nb_config *cmgd_db_get_nb_config(cmgd_db_hndl_t db_hndl)
{
	cmgd_db_ctxt_t *db_ctxt;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return NULL;

	return (db_ctxt->config_db ? db_ctxt->root.cfg_root : NULL);
}

static int cmgd_walk_db_nodes(cmgd_db_ctxt_t *db_ctxt, 
	char *base_xpath, struct lyd_node *base_dnode,
	cmgd_db_node_iter_fn iter_fn, void *ctxt,
	char *xpaths[], struct lyd_node *dnodes[],
	struct nb_node *nbnodes[], int *num_nodes,
	bool childs_as_well, bool donot_free_alloced)
{
	uint32_t indx;
	char *xpath;
	int ret, num_left = 0, num_found = 0;
	struct lyd_node *dnode;
	struct nb_node *nbnode;
	bool alloc_xp = false;

	if (xpaths || dnodes || nbnodes)
		assert(num_nodes);

	if (num_nodes && !*num_nodes)
		return 0;

	if (num_nodes) {
		num_left = *num_nodes;
		CMGD_DB_DBG(" -- START: num_left:%d", num_left);
		*num_nodes = 0;
	}

	CMGD_DB_DBG(" -- START: Base: %s", base_xpath);

	if (!base_dnode)
		base_dnode = yang_dnode_get(db_ctxt->config_db ?
				db_ctxt->root.cfg_root->dnode :
				db_ctxt->root.dnode_root, base_xpath);
	if (!base_dnode)
		return -1;

	/* If the base_xpath points to leaf node, we can skip the tree walk */
	if(base_dnode->schema->nodetype & LYD_NODE_TERM) {
		if (donot_free_alloced) {
			if (xpaths && xpaths[*num_nodes]) {
				xpath = xpaths[*num_nodes];
				(*num_nodes)++;
			} else {
				xpath = (char *)calloc(1, CMGD_MAX_XPATH_LEN);
			}
			strncpy(xpath, base_xpath, CMGD_MAX_XPATH_LEN);
		} else {
			xpath = base_xpath;
		}

		/*
		 * NOTE: With this a node is iterated if and only if its a leaf-node.
		 */
		// (*iter_fn)((cmgd_db_hndl_t) db_ctxt, xpath, base_dnode,
		// 	base_dnode->schema->priv, ctxt);
		return 0;
	}

	indx = 0;
	LY_LIST_FOR(lyd_child(base_dnode), dnode) {

	
		assert(dnode->schema && dnode->schema->priv);
		nbnode = (struct nb_node *) dnode->schema->priv;
		if (nbnodes)
			nbnodes[indx] = nbnode;

		xpath = NULL;
		if (xpaths) {
			if (!xpaths[*num_nodes])
				alloc_xp = true;

			xpath = lyd_path(dnode, LYD_PATH_STD,
					xpaths[*num_nodes],
					xpaths[*num_nodes] ?
					CMGD_MAX_XPATH_LEN : 0);
			xpaths[*num_nodes] = xpath;
		} else {
			alloc_xp = true;
			xpath = (char *)calloc(1, CMGD_MAX_XPATH_LEN);
			xpath = lyd_path(dnode, LYD_PATH_STD, xpath, CMGD_MAX_XPATH_LEN);
		}

		assert(xpath);
		CMGD_DB_DBG(" -- XPATH: %s", xpath);

		if (iter_fn) {
			(*iter_fn)((cmgd_db_hndl_t) db_ctxt, xpath,
				dnode, nbnode, ctxt);
		}

		if (num_nodes) {
			(*num_nodes)++;
			num_left--;
		}

		if (!childs_as_well)
			continue;

		if (num_nodes)
			num_found = num_left;

		ret = cmgd_walk_db_nodes(db_ctxt, xpath, dnode, iter_fn,
			ctxt, xpaths ? &xpaths[*num_nodes] : NULL,
			dnodes ? &dnodes[*num_nodes] : NULL,
			nbnodes ? &nbnodes[*num_nodes] : NULL,
			num_nodes ? &num_found : NULL, childs_as_well,
			donot_free_alloced);

		if (num_nodes) {
			num_left -= num_found;
			(*num_nodes) += num_found;
		}

		if (ret != 0) {
			break;
		}

		if (alloc_xp && !donot_free_alloced)
			free(xpath);
		indx++;
	}


	if (num_nodes) {
		CMGD_DB_DBG(" -- END: *num_nodes:%d, num_left:%d",
			*num_nodes, num_left);
	}

	return 0;
}

int cmgd_db_lookup_data_nodes(
        cmgd_db_hndl_t db_hndl, const char *xpath, char *dxpaths[],
        struct lyd_node *dnodes[], struct nb_node *nbnodes[],
	int *num_nodes, bool get_childs_as_well, bool donot_free_alloced)
{
	cmgd_db_ctxt_t *db_ctxt;
	char base_xpath[CMGD_MAX_XPATH_LEN];

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt || !num_nodes)
		return -1;

	if (xpath[0] == '.' && xpath[1] == '/')
		xpath += 2;

	strncpy(base_xpath, xpath, sizeof(base_xpath));
	cmgd_remove_trailing_separator(base_xpath, '/');

	return (cmgd_walk_db_nodes(db_ctxt, base_xpath, NULL, NULL, NULL,
			dxpaths, dnodes, nbnodes, num_nodes,
			get_childs_as_well, donot_free_alloced));
}

struct lyd_node *cmgd_db_find_data_node_by_xpath(cmgd_db_hndl_t db_hndl,
	const char *xpath)
{
	cmgd_db_ctxt_t *db_ctxt;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return NULL;
	
	return yang_dnode_get(db_ctxt->config_db ?
			db_ctxt->root.cfg_root->dnode :
			db_ctxt->root.dnode_root, xpath);
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

	dnode = yang_dnode_get(db_ctxt->config_db ?
			db_ctxt->root.cfg_root->dnode :
			db_ctxt->root.dnode_root, xpath);

	if (!dnode)
		/*
		 * Return a special error code so the caller can choose
		 * whether to ignore it or not.
		 */
		return NB_ERR_NOT_FOUND;
	/* destroy dependant */
	if (nb_node->dep_cbs.get_dependant_xpath) {
		nb_node->dep_cbs.get_dependant_xpath(dnode, dep_xpath);

		dep_dnode = yang_dnode_get(db_ctxt->config_db ?
				db_ctxt->root.cfg_root->dnode :
				db_ctxt->root.dnode_root, dep_xpath);
		if (dep_dnode)
			lyd_free_tree(dep_dnode);
	}
	lyd_free_tree(dnode);

	return 0;
}

int cmgd_db_load_config_from_file(cmgd_db_hndl_t db_hndl,
	const char * file_path, bool merge)
{
	struct lyd_node *iter;
	cmgd_db_ctxt_t *dst;
	cmgd_db_ctxt_t parsed;

	dst = (cmgd_db_ctxt_t *)db_hndl;
	if (!dst)
		return -1;

	if (cmgd_db_load_cfg_from_file(file_path, &iter) != 0) {
		CMGD_DB_ERR("Failed to load config from the file %s", file_path);
		return -1;
	}

	parsed.root.cfg_root = nb_config_new(iter);
	parsed.config_db = true;
	parsed.db_id = ((cmgd_db_ctxt_t *)db_hndl)->db_id;

	if (merge)
		cmgd_db_merge_src_with_dst_db(&parsed, dst);
	else
		cmgd_db_replace_dst_with_src_db(&parsed, dst);

	nb_config_free(parsed.root.cfg_root);

	return 0;
}

int cmgd_db_iter_data(
        cmgd_db_hndl_t db_hndl, char *base_xpath,
        cmgd_db_node_iter_fn iter_fn, void *ctxt, bool donot_free_alloced)
{
	cmgd_db_ctxt_t *db_ctxt;
	int ret;
	char xpath[CMGD_MAX_XPATH_LEN];
	struct lyd_node *base_dnode = NULL;
	struct lyd_node *node;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt)
		return -1;

	cmgd_remove_trailing_separator(base_xpath, '/');

	strncpy(xpath, base_xpath, sizeof(xpath));

	CMGD_DB_DBG(" -- START DB walk for DBid: %d", db_ctxt->db_id);

	/* If the base_xpath is empty then crawl the sibblings */
	if (xpath[0] == '\0') {
		base_dnode = db_ctxt->config_db ?
				db_ctxt->root.cfg_root->dnode :
				db_ctxt->root.dnode_root;

		/* get first top-level sibling */
		while (base_dnode->parent) {
			base_dnode = lyd_parent(base_dnode);
		}
		while (base_dnode->prev->next) {
			base_dnode = base_dnode->prev;
		}

		LY_LIST_FOR(base_dnode, node) {
			ret = cmgd_walk_db_nodes(db_ctxt, xpath, node, iter_fn, ctxt,
				NULL, NULL, NULL, NULL, true, donot_free_alloced);
		}
	} else
		ret = cmgd_walk_db_nodes(db_ctxt, xpath, base_dnode, iter_fn, ctxt,
			NULL, NULL, NULL, NULL, true, donot_free_alloced);

	return ret;
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

void cmgd_db_dump_tree(
		struct vty *vty, cmgd_db_hndl_t db_hndl, const char* xpath,
		FILE *f, LYD_FORMAT format)
{
	cmgd_db_ctxt_t *db_ctxt;
	struct ly_out *out;
	char *str;
	char base_xpath[CMGD_MAX_XPATH_LEN] = {0};

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt) {
		vty_out(vty, "    >>>>> Database Not Initialized!\n");
		return;
	}

	if (xpath) {
		strncpy(base_xpath, xpath, CMGD_MAX_XPATH_LEN);
		cmgd_remove_trailing_separator(base_xpath, '/');
	}

	if (f)
		ly_out_new_file(f, &out);
	else
		ly_out_new_memory(&str, 0, &out);

	cmgd_db_dump_in_memory(db_ctxt, base_xpath, format, out);

	if (!f)
		vty_out(vty, "%s", str);

	ly_out_free(out, NULL, 0);
}

void cmgd_db_status_write_one(
        struct vty *vty, cmgd_db_hndl_t db_hndl)
{
	cmgd_db_ctxt_t *db_ctxt;

	db_ctxt = (cmgd_db_ctxt_t *)db_hndl;
	if (!db_ctxt) {
		vty_out(vty, "    >>>>> Database Not Initialized!\n");
		return;
	}
	
	vty_out(vty, "  DB: %s\n", cmgd_db_id2name(db_ctxt->db_id));
	vty_out(vty, "    DB-Hndl: \t\t\t0x%p\n", db_ctxt);
	vty_out(vty, "    Config: \t\t\t%s\n", db_ctxt->config_db ? "True" : "False");
}

void cmgd_db_status_write(struct vty *vty)
{
	vty_out(vty, "CMGD Databases\n");

	cmgd_db_status_write_one(vty, cmgd_db_cm->running_db);

	cmgd_db_status_write_one(vty, cmgd_db_cm->candidate_db);

	cmgd_db_status_write_one(vty, cmgd_db_cm->oper_db);
}

static void cmgd_del_file(char *name)
{
	if (remove(name) == 0)
		zlog_debug("Old commit info deleted succeeded");
	else
		zlog_err("Old commit info deletion failed");
}

static void cmgd_compute_hash(const char *input_str, char *hash)
{
	int i;
	unsigned char digest[CMGD_MD5_HASH_LEN];
	MD5_CTX ctx;

	memset(&ctx, 0, sizeof(ctx));
	MD5Init(&ctx);
	MD5Update(&ctx, input_str, strlen(input_str));
	MD5Final(digest, &ctx);

	for(i = 0; i < CMGD_MD5_HASH_LEN; i++)
		sprintf(&hash[i*2], "%02x", (unsigned int)digest[i]);
}

struct cmgd_cmt_info_t *cmgd_create_new_cmt_record(void)
{
	struct cmgd_cmt_info_t *new;
	struct cmgd_cmt_info_t *itr_cmt_info;
	struct cmgd_cmt_info_t *last_cmt_info = NULL;
	struct timeval cmt_recd_tv;

	new = XCALLOC(MTYPE_CMGD_CMT_INFO, sizeof(struct cmgd_cmt_info_t));
	cmgd_get_realtime(&cmt_recd_tv);
	cmgd_realtime_to_string(&cmt_recd_tv, new->time_str, sizeof(new->time_str));
	cmgd_compute_hash(new->time_str, new->cmt_str);
	snprintf(new->cmt_json_file, CMGD_MAX_COMMIT_FILE_PATH_LEN,
		CMGD_COMMIT_FILE_PATH, new->cmt_str);

	if (cmgd_cmt_info_dlist_count(&cm->cmt_dlist)
		== CMGD_MAX_COMMIT_LIST) {
		FOREACH_CMT_REC(cm, itr_cmt_info) {
			last_cmt_info = itr_cmt_info;
		}

		cmgd_del_file(last_cmt_info->cmt_json_file);
		cmgd_cmt_info_dlist_del(&cm->cmt_dlist, last_cmt_info);
		XFREE(MTYPE_CMGD_CMT_INFO, last_cmt_info);
	}

	cmgd_cmt_info_dlist_add_head(&cm->cmt_dlist, new);
	return new;
}

static struct cmgd_cmt_info_t *cmgd_find_cmt_record(char *cmt_str)
{
	struct cmgd_cmt_info_t *itr_cmt_info;

	FOREACH_CMT_REC(cm, itr_cmt_info) {
		if (strcmp(itr_cmt_info->cmt_str, cmt_str) == 0)
			return itr_cmt_info;
	}

	return NULL;
}

static int cmgd_cmt_rollback_apply(struct vty *vty,
	struct cmgd_cmt_info_t *itr_cmt_info)
{
	cmgd_db_hndl_t src_db_hndl;
	cmgd_db_hndl_t dst_db_hndl;
	int ret = 0;

	src_db_hndl = cmgd_db_get_hndl_by_id(cm, CMGD_DB_CANDIDATE);
	if (!src_db_hndl) {
		vty_out(vty, "ERROR: Couldnot access Candidate database!\n");
		return -1;
	}

	ret = cmgd_db_write_lock(src_db_hndl);
	if (ret != 0) {
		vty_out(vty, "Failed to lock the DB %u for rollback, Reason: %s!",
			CMGD_DB_CANDIDATE, strerror(ret));
		return -1;
	}

	dst_db_hndl = cmgd_db_get_hndl_by_id(cm, CMGD_DB_RUNNING);
	if (!dst_db_hndl) {
		cmgd_db_unlock(src_db_hndl);
		vty_out(vty, "ERROR: Couldnot access Running database!\n");
		return -1;
	}

	ret = cmgd_db_write_lock(dst_db_hndl);
	if (ret != 0) {
		cmgd_db_unlock(src_db_hndl);
		vty_out(vty, "Failed to lock the DB %u for rollback Reason: %s!",
			CMGD_DB_RUNNING, strerror(ret));
		return -1;
	}

	ret = cmgd_db_load_config_from_file(src_db_hndl,
			itr_cmt_info->cmt_json_file, false);
	if (ret != 0) {
		cmgd_db_unlock(src_db_hndl);
		cmgd_db_unlock(dst_db_hndl);
		vty_out(vty, "Error with parsing the file with error code %d\n", ret);
		return ret;
	}

	//Internally trigger a commit-request.
	ret = cmgd_cmt_rollback_trigger_cfg_apply(src_db_hndl, dst_db_hndl);
	if (ret != 0) {
		cmgd_db_unlock(src_db_hndl);
		cmgd_db_unlock(dst_db_hndl);
		vty_out(vty, "Error with creating commit apply trxn with error code %d\n", ret);
		return ret;
	}

	return 0;
}

static int cmgd_cmt_rollback_by_id(struct vty *vty, char *cmt_str)
{
	int ret = 0;
	struct cmgd_cmt_info_t *itr_cmt_info;

	FOREACH_CMT_REC(cm, itr_cmt_info) {
		if (strcmp(itr_cmt_info->cmt_str, cmt_str) == 0) {
			ret = cmgd_cmt_rollback_apply(vty, itr_cmt_info);
			return ret;
		}

		cmgd_del_file(itr_cmt_info->cmt_json_file);
		cmgd_cmt_info_dlist_del(&cm->cmt_dlist, itr_cmt_info);
	}

	return 0;
}

static int cmgd_cmt_rollback_commits(struct vty *vty, int last_n_cmts)
{
	int ret = 0;
	int cnt = 0;
	struct cmgd_cmt_info_t *itr_cmt_info;

	FOREACH_CMT_REC(cm, itr_cmt_info) {
		if (cnt == last_n_cmts) {
			ret = cmgd_cmt_rollback_apply(vty, itr_cmt_info);
			return ret;
		}

		cnt++;
		cmgd_del_file(itr_cmt_info->cmt_json_file);
		cmgd_cmt_info_dlist_del(&cm->cmt_dlist, itr_cmt_info);
	}

	return 0;
}

int cmgd_cmt_rollback(struct vty *vty, char *cmt_str, int last_n_cmts,
	bool cmd_id_based)
{
	int ret = 0;

	if (cmgd_cmt_info_dlist_count(&cm->cmt_dlist) == 0)
		return 0;

	if (cmd_id_based && !cmgd_find_cmt_record(cmt_str)) {
		vty_out(vty, "Invalid commit Id\n");
		return -1;
	}

	if (cmd_id_based) {
		ret = cmgd_cmt_rollback_by_id(vty, cmt_str);
	} else {
		if (!last_n_cmts)
			last_n_cmts = 1;
		ret = cmgd_cmt_rollback_commits(vty, last_n_cmts);
	}

	cmgd_cmt_record_create_index_file();
	return ret;
}

void show_cmgd_cmt_history(struct vty *vty)
{
	struct cmgd_cmt_info_t *itr_cmt_info;
	int slno = 0;

	vty_out(vty, "Last 10 commit history:\n");
	vty_out(vty, "  sl.no\tCommit-ID(HEX)\t\t\t  Commit-Record-Time\n");
	FOREACH_CMT_REC(cm, itr_cmt_info) {
		vty_out(vty, "  %d\t%s  %s\n", slno, itr_cmt_info->cmt_str,
				itr_cmt_info->time_str);
		slno++;
	}
}

static bool cmgd_cmt_record_file_exist(char *file_path)
{
	int exist;

	exist = access(file_path, F_OK);
	if (exist == 0)
		return true;
	else
		return false;
}

bool cmgd_cmt_record_create_index_file(void)
{
	FILE *fp;
	int ret = 0;
	struct cmgd_cmt_info_t *itr_cmt_info;
	struct cmgd_cmt_info_t cmt_info_set[10];
	int cnt = 0;

	cmgd_del_file((char *)CMGD_COMMIT_INDEX_FILE_NAME);
	fp = fopen(CMGD_COMMIT_INDEX_FILE_NAME, "ab");
	if (!fp) {
		zlog_err("Failed to open file %s ab mode",
			CMGD_COMMIT_INDEX_FILE_NAME);
		return false;
	}

	FOREACH_CMT_REC(cm, itr_cmt_info) {
		memcpy(&cmt_info_set[cnt], itr_cmt_info,
			sizeof(struct cmgd_cmt_info_t));
		cnt++;
	}

	if (!cnt) {
		fclose(fp);
		return false;
	}

	ret = fwrite(&cmt_info_set,
			sizeof(struct cmgd_cmt_info_t), cnt, fp);
	fclose(fp);
	if (ret != cnt) {
		zlog_err("Write record failed");
		return false;
	} else {
		return true;
	}
}

bool cmgd_cmt_record_read_index_file(void)
{
	FILE *fp;
	struct cmgd_cmt_info_t itr_cmt_info;
	struct cmgd_cmt_info_t *new;
	int cnt = 0;

	fp = fopen(CMGD_COMMIT_INDEX_FILE_NAME, "rb");
	if (!fp) {
		zlog_err("Failed to open file %s rb mode",
			CMGD_COMMIT_INDEX_FILE_NAME);
		return false;
	}

	while ((fread(&itr_cmt_info,
		sizeof(itr_cmt_info), 1, fp)) > 0) {
		if (cnt < CMGD_MAX_COMMIT_LIST) {
			if (!cmgd_cmt_record_file_exist(
				itr_cmt_info.cmt_json_file)) {
				zlog_err("Commit record present in index_file, but commit filei %s missing",
						itr_cmt_info.cmt_json_file);
				continue;
			}

			new = XCALLOC(MTYPE_CMGD_CMT_INFO,
					sizeof(struct cmgd_cmt_info_t));
			memcpy(new, &itr_cmt_info,
					sizeof(struct cmgd_cmt_info_t));
			cmgd_cmt_info_dlist_add_tail(&cm->cmt_dlist,
				new);
		} else {
			zlog_err("More records found in index file %s",
				CMGD_COMMIT_INDEX_FILE_NAME);
			return false;
		}

		cnt++;
	}

	fclose(fp);
	return true;
}
