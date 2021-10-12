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

#include <pthread.h>

#include "thread.h"
#include "sockunion.h"
#include "prefix.h"
#include "network.h"
#include "lib/libfrr.h"
#include "lib/md5.h"
#include "lib/typesafe.h"
#include "lib/thread.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "lib/vty.h"
#include "mgmtd/mgmt_db.h"
#include "libyang/libyang.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_DB_DBG(fmt, ...)                                                 \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_DB_ERR(fmt, ...)                                                 \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_DB_DBG(fmt, ...)                                                 \
	do {                                                                   \
		if (mgmt_debug_db)                                             \
			zlog_debug("%s: " fmt, __func__, ##__VA_ARGS__);       \
	} while (0)
#define MGMTD_DB_ERR(fmt, ...)                                                 \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

struct mgmt_db_ctxt {
	enum mgmt_database_id db_id;
	pthread_rwlock_t rw_lock;

	bool config_db;

	union {
		struct nb_config *cfg_root;
		struct lyd_node *dnode_root;
	} root;
};

const char *mgmt_db_names[MGMTD_DB_MAX_ID + 1] = {
	MGMTD_DB_NAME_NONE,	/* MGMTD_DB_NONE */
	MGMTD_DB_NAME_RUNNING,     /* MGMTD_DB_RUNNING */
	MGMTD_DB_NAME_CANDIDATE,   /* MGMTD_DB_RUNNING */
	MGMTD_DB_NAME_OPERATIONAL, /* MGMTD_DB_OPERATIONAL */
	"Unknown/Invalid",	 /* MGMTD_DB_ID_MAX */
};

static struct mgmt_master *mgmt_db_mm;
static struct mgmt_db_ctxt running, candidate, oper;

/* Dump the data tree of the specified format in the file pointed by the path */
static int mgmt_db_dump_in_memory(struct mgmt_db_ctxt *db_ctxt,
				  const char *base_xpath, LYD_FORMAT format,
				  struct ly_out *out)
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

static int mgmt_db_replace_dst_with_src_db(struct mgmt_db_ctxt *src,
					   struct mgmt_db_ctxt *dst)
{
	struct lyd_node *dst_dnode, *src_dnode;
	struct ly_out *out;

	if (!src || !dst)
		return -1;
	MGMTD_DB_DBG("Replacing %d with %d", dst->db_id, src->db_id);

	src_dnode = src->config_db ? src->root.cfg_root->dnode
				   : dst->root.dnode_root;
	dst_dnode = dst->config_db ? dst->root.cfg_root->dnode
				   : dst->root.dnode_root;

	if (dst_dnode)
		yang_dnode_free(dst_dnode);

	/* Not using nb_config_replace as the oper db does not contain nb_config
	 */
	dst_dnode = yang_dnode_dup(src_dnode);
	if (dst->config_db)
		dst->root.cfg_root->dnode = dst_dnode;
	else
		dst->root.dnode_root = dst_dnode;

	if (dst->db_id == MGMTD_DB_RUNNING) {
		if (ly_out_new_filepath(MGMTD_STARTUP_DB_FILE_PATH, &out)
		    == LY_SUCCESS)
			mgmt_db_dump_in_memory(dst, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	/* TODO: Update the versions if nb_config present */

	return 0;
}

static int mgmt_db_merge_src_with_dst_db(struct mgmt_db_ctxt *src,
					 struct mgmt_db_ctxt *dst)
{
	int ret;
	struct lyd_node **dst_dnode, *src_dnode;
	struct ly_out *out;

	if (!src || !dst)
		return -1;

	MGMTD_DB_DBG("Merging DB %d with %d", dst->db_id, src->db_id);

	src_dnode = src->config_db ? src->root.cfg_root->dnode
				   : dst->root.dnode_root;
	dst_dnode = dst->config_db ? &dst->root.cfg_root->dnode
				   : &dst->root.dnode_root;
	ret = lyd_merge_siblings(dst_dnode, src_dnode, 0);
	if (ret != 0) {
		MGMTD_DB_ERR("lyd_merge() failed with err %d", ret);
		return ret;
	}

	if (dst->db_id == MGMTD_DB_RUNNING) {
		if (ly_out_new_filepath(MGMTD_STARTUP_DB_FILE_PATH, &out)
		    == LY_SUCCESS)
			mgmt_db_dump_in_memory(dst, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	return 0;
}

static int mgmt_db_load_cfg_from_file(const char *filepath,
				      struct lyd_node **dnode)
{
	LY_ERR ret;

	*dnode = NULL;
	ret = lyd_parse_data_path(ly_native_ctx, filepath, LYD_JSON,
				  LYD_PARSE_STRICT, 0, dnode);

	if (ret != LY_SUCCESS) {
		if (*dnode)
			yang_dnode_free(*dnode);
		return -1;
	}

	return 0;
}

int mgmt_db_init(struct mgmt_master *mm)
{
	struct lyd_node *root;

	if (mgmt_db_mm || mm->running_db || mm->candidate_db || mm->oper_db)
		assert(!"MGMTD: Call db_init only once!");

	/* Use Running DB from NB module??? */
	if (!running_config)
		assert(!"MGMTD: Call db_init after frr_init only!");

	if (mgmt_db_load_cfg_from_file(MGMTD_STARTUP_DB_FILE_PATH, &root)
	    == 0) {
		nb_config_free(running_config);
		running_config = nb_config_new(root);
	}

	running.root.cfg_root = running_config;
	running.config_db = true;
	running.db_id = MGMTD_DB_RUNNING;

	candidate.root.cfg_root = nb_config_dup(running.root.cfg_root);
	candidate.config_db = true;
	candidate.db_id = MGMTD_DB_CANDIDATE;

	oper.root.dnode_root = yang_dnode_new(ly_native_ctx, true);
	oper.config_db = false;
	oper.db_id = MGMTD_DB_OPERATIONAL;

	mm->running_db = (uint64_t)&running;
	mm->candidate_db = (uint64_t)&candidate;
	mm->oper_db = (uint64_t)&oper;
	mgmt_db_mm = mm;

	return 0;
}

void mgmt_db_destroy(void)
{

	/*
	 * TODO: Free the databases.
	 */

}

uint64_t mgmt_db_get_hndl_by_id(struct mgmt_master *cm,
				enum mgmt_database_id db_id)
{
	switch (db_id) {
	case MGMTD_DB_CANDIDATE:
		return (mm->candidate_db);
	case MGMTD_DB_RUNNING:
		return (mm->running_db);
	case MGMTD_DB_OPERATIONAL:
		return (mm->oper_db);
	default:
		break;
	}

	return 0;
}

bool mgmt_db_is_config(uint64_t db_hndl)
{
	struct mgmt_db_ctxt *db_ctxt;

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt)
		return false;

	return db_ctxt->config_db;
}

int mgmt_db_read_lock(uint64_t db_hndl)
{
	struct mgmt_db_ctxt *db_ctxt;
	int lock_status;

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt)
		return -1;

	lock_status = pthread_rwlock_tryrdlock(&db_ctxt->rw_lock);
	return lock_status;
}

int mgmt_db_write_lock(uint64_t db_hndl)
{
	struct mgmt_db_ctxt *db_ctxt;
	int lock_status;

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt)
		return -1;

	lock_status = pthread_rwlock_trywrlock(&db_ctxt->rw_lock);
	return lock_status;
}

int mgmt_db_unlock(uint64_t db_hndl)
{
	struct mgmt_db_ctxt *db_ctxt;
	int lock_status;

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt)
		return -1;

	lock_status = pthread_rwlock_unlock(&db_ctxt->rw_lock);
	return lock_status;
}

int mgmt_db_merge_dbs(uint64_t src_db, uint64_t dst_db, bool updt_cmt_rec)
{
	struct mgmt_db_ctxt *src, *dst;

	src = (struct mgmt_db_ctxt *)src_db;
	dst = (struct mgmt_db_ctxt *)dst_db;

	if (mgmt_db_merge_src_with_dst_db(src, dst) != 0)
		return -1;

	return 0;
}

int mgmt_db_copy_dbs(uint64_t src_db, uint64_t dst_db, bool updt_cmt_rec)
{
	struct mgmt_db_ctxt *src, *dst;

	src = (struct mgmt_db_ctxt *)src_db;
	dst = (struct mgmt_db_ctxt *)dst_db;

	if (mgmt_db_replace_dst_with_src_db(src, dst) != 0)
		return -1;

	return 0;
}

int mgmt_db_dump_db_to_file(char *file_name, uint64_t db)
{
	struct mgmt_db_ctxt *db_ctxt;
	struct ly_out *out;
	int ret = 0;

	db_ctxt = (struct mgmt_db_ctxt *)db;

	if (ly_out_new_filepath(file_name, &out) == LY_SUCCESS) {
		ret = mgmt_db_dump_in_memory(db_ctxt, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	return ret;
}

struct nb_config *mgmt_db_get_nb_config(uint64_t db_hndl)
{
	struct mgmt_db_ctxt *db_ctxt;

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt)
		return NULL;

	return db_ctxt->config_db ? db_ctxt->root.cfg_root : NULL;
}

static int mgmt_walk_db_nodes(struct mgmt_db_ctxt *db_ctxt, char *base_xpath,
			      struct lyd_node *base_dnode,
			      mgmt_db_node_iter_fn iter_fn, void *ctxt,
			      char *xpaths[], int *num_nodes,
			      bool childs_as_well, bool alloc_xp_copy)
{
	uint32_t indx;
	char *xpath, *xpath_buf, *iter_xp;
	int ret, num_left = 0, num_found = 0;
	struct lyd_node *dnode;
	struct nb_node *nbnode;
	bool alloc_xp = false;

	if (xpaths)
		assert(num_nodes);

	if (num_nodes && !*num_nodes)
		return 0;

	if (num_nodes) {
		num_left = *num_nodes;
		MGMTD_DB_DBG(" -- START: num_left:%d", num_left);
		*num_nodes = 0;
	}

	MGMTD_DB_DBG(" -- START: Base: %s", base_xpath);

	if (!base_dnode)
		base_dnode = yang_dnode_get(
			db_ctxt->config_db ? db_ctxt->root.cfg_root->dnode
					   : db_ctxt->root.dnode_root,
			base_xpath);
	if (!base_dnode)
		return -1;

	/* If the base_xpath points to leaf node, we can skip the tree walk */
	if (base_dnode->schema->nodetype & LYD_NODE_TERM)
		return 0;

	indx = 0;
	LY_LIST_FOR (lyd_child(base_dnode), dnode) {
		assert(dnode->schema && dnode->schema->priv);
		nbnode = (struct nb_node *)dnode->schema->priv;

		xpath = NULL;
		if (xpaths) {
			if (!xpaths[*num_nodes]) {
				alloc_xp = true;
				xpaths[*num_nodes] =
					(char *)calloc(1, MGMTD_MAX_XPATH_LEN);
			}
			xpath = lyd_path(dnode, LYD_PATH_STD,
					 xpaths[*num_nodes],
					 MGMTD_MAX_XPATH_LEN);
		} else {
			alloc_xp = true;
			xpath_buf = (char *)calloc(1, MGMTD_MAX_XPATH_LEN);
			xpath = lyd_path(dnode, LYD_PATH_STD, xpath_buf,
					 MGMTD_MAX_XPATH_LEN);
		}

		assert(xpath);
		MGMTD_DB_DBG(" -- XPATH: %s", xpath);

		if (iter_fn) {
			/*
			 * In case the caller is interested in getting a copy
			 * of the xpath for themselves (by setting
			 * 'alloc_xp_copy' to 'true') we make a copy for the
			 * caller and pass it. Else we pass the original xpath
			 * buffer.
			 *
			 * NOTE: In such case caller will have to take care of
			 * the copy later.
			 */
			iter_xp = alloc_xp_copy ? strdup(xpath) : xpath;

			(*iter_fn)((uint64_t)db_ctxt, iter_xp, dnode, nbnode,
				   ctxt);
		}

		if (num_nodes) {
			(*num_nodes)++;
			num_left--;
		}

		if (!childs_as_well)
			continue;

		if (num_nodes)
			num_found = num_left;

		ret = mgmt_walk_db_nodes(db_ctxt, xpath, dnode, iter_fn, ctxt,
					 xpaths ? &xpaths[*num_nodes] : NULL,
					 num_nodes ? &num_found : NULL,
					 childs_as_well, alloc_xp_copy);

		if (num_nodes) {
			num_left -= num_found;
			(*num_nodes) += num_found;
		}

		if (ret != 0)
			break;

		if (alloc_xp)
			free(xpath);
		indx++;
	}


	if (num_nodes) {
		MGMTD_DB_DBG(" -- END: *num_nodes:%d, num_left:%d", *num_nodes,
			     num_left);
	}

	return 0;
}

int mgmt_db_lookup_data_nodes(uint64_t db_hndl, const char *xpath,
			      char *dxpaths[], int *num_nodes,
			      bool get_childs_as_well, bool alloc_xp_copy)
{
	struct mgmt_db_ctxt *db_ctxt;
	char base_xpath[MGMTD_MAX_XPATH_LEN];

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt || !num_nodes)
		return -1;

	if (xpath[0] == '.' && xpath[1] == '/')
		xpath += 2;

	strlcpy(base_xpath, xpath, sizeof(base_xpath));
	mgmt_remove_trailing_separator(base_xpath, '/');

	return (mgmt_walk_db_nodes(db_ctxt, base_xpath, NULL, NULL, NULL,
				   dxpaths, num_nodes, get_childs_as_well,
				   alloc_xp_copy));
}

struct lyd_node *mgmt_db_find_data_node_by_xpath(uint64_t db_hndl,
						 const char *xpath)
{
	struct mgmt_db_ctxt *db_ctxt;

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt)
		return NULL;

	return yang_dnode_get(db_ctxt->config_db ? db_ctxt->root.cfg_root->dnode
						 : db_ctxt->root.dnode_root,
			      xpath);
}

int mgmt_db_delete_data_nodes(uint64_t db_hndl, const char *xpath)
{
	struct mgmt_db_ctxt *db_ctxt;
	struct nb_node *nb_node;
	struct lyd_node *dnode, *dep_dnode;
	char dep_xpath[XPATH_MAXLEN];

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt)
		return -1;

	nb_node = nb_node_find(xpath);

	dnode = yang_dnode_get(db_ctxt->config_db
				       ? db_ctxt->root.cfg_root->dnode
				       : db_ctxt->root.dnode_root,
			       xpath);

	if (!dnode)
		/*
		 * Return a special error code so the caller can choose
		 * whether to ignore it or not.
		 */
		return NB_ERR_NOT_FOUND;
	/* destroy dependant */
	if (nb_node->dep_cbs.get_dependant_xpath) {
		nb_node->dep_cbs.get_dependant_xpath(dnode, dep_xpath);

		dep_dnode = yang_dnode_get(
			db_ctxt->config_db ? db_ctxt->root.cfg_root->dnode
					   : db_ctxt->root.dnode_root,
			dep_xpath);
		if (dep_dnode)
			lyd_free_tree(dep_dnode);
	}
	lyd_free_tree(dnode);

	return 0;
}

int mgmt_db_load_config_from_file(uint64_t db_hndl, const char *file_path,
				  bool merge)
{
	struct lyd_node *iter;
	struct mgmt_db_ctxt *dst;
	struct mgmt_db_ctxt parsed;

	dst = (struct mgmt_db_ctxt *)db_hndl;
	if (!dst)
		return -1;

	if (mgmt_db_load_cfg_from_file(file_path, &iter) != 0) {
		MGMTD_DB_ERR("Failed to load config from the file %s",
			     file_path);
		return -1;
	}

	parsed.root.cfg_root = nb_config_new(iter);
	parsed.config_db = true;
	parsed.db_id = ((struct mgmt_db_ctxt *)db_hndl)->db_id;

	if (merge)
		mgmt_db_merge_src_with_dst_db(&parsed, dst);
	else
		mgmt_db_replace_dst_with_src_db(&parsed, dst);

	nb_config_free(parsed.root.cfg_root);

	return 0;
}

int mgmt_db_iter_data(uint64_t db_hndl, char *base_xpath,
		      mgmt_db_node_iter_fn iter_fn, void *ctxt,
		      bool alloc_xp_copy)
{
	struct mgmt_db_ctxt *db_ctxt;
	int ret;
	char xpath[MGMTD_MAX_XPATH_LEN];
	struct lyd_node *base_dnode = NULL;
	struct lyd_node *node;

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt)
		return -1;

	mgmt_remove_trailing_separator(base_xpath, '/');

	strlcpy(xpath, base_xpath, sizeof(xpath));

	MGMTD_DB_DBG(" -- START DB walk for DBid: %d", db_ctxt->db_id);

	/* If the base_xpath is empty then crawl the sibblings */
	if (xpath[0] == '\0') {
		base_dnode = db_ctxt->config_db ? db_ctxt->root.cfg_root->dnode
						: db_ctxt->root.dnode_root;

		/* get first top-level sibling */
		while (base_dnode->parent)
			base_dnode = lyd_parent(base_dnode);

		while (base_dnode->prev->next)
			base_dnode = base_dnode->prev;


		LY_LIST_FOR (base_dnode, node) {
			ret = mgmt_walk_db_nodes(db_ctxt, xpath, node, iter_fn,
						 ctxt, NULL, NULL, true,
						 alloc_xp_copy);
		}
	} else
		ret = mgmt_walk_db_nodes(db_ctxt, xpath, base_dnode, iter_fn,
					 ctxt, NULL, NULL, true, alloc_xp_copy);

	return ret;
}

void mgmt_db_dump_tree(struct vty *vty, uint64_t db_hndl, const char *xpath,
		       FILE *f, LYD_FORMAT format)
{
	struct mgmt_db_ctxt *db_ctxt;
	struct ly_out *out;
	char *str;
	char base_xpath[MGMTD_MAX_XPATH_LEN] = {0};

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt) {
		vty_out(vty, "    >>>>> Database Not Initialized!\n");
		return;
	}

	if (xpath) {
		strlcpy(base_xpath, xpath, MGMTD_MAX_XPATH_LEN);
		mgmt_remove_trailing_separator(base_xpath, '/');
	}

	if (f)
		ly_out_new_file(f, &out);
	else
		ly_out_new_memory(&str, 0, &out);

	mgmt_db_dump_in_memory(db_ctxt, base_xpath, format, out);

	if (!f)
		vty_out(vty, "%s\n", str);

	ly_out_free(out, NULL, 0);
}

void mgmt_db_status_write_one(struct vty *vty, uint64_t db_hndl)
{
	struct mgmt_db_ctxt *db_ctxt;

	db_ctxt = (struct mgmt_db_ctxt *)db_hndl;
	if (!db_ctxt) {
		vty_out(vty, "    >>>>> Database Not Initialized!\n");
		return;
	}

	vty_out(vty, "  DB: %s\n", mgmt_db_id2name(db_ctxt->db_id));
	vty_out(vty, "    DB-Hndl: \t\t\t%p\n", db_ctxt);
	vty_out(vty, "    Config: \t\t\t%s\n",
		db_ctxt->config_db ? "True" : "False");
}

void mgmt_db_status_write(struct vty *vty)
{
	vty_out(vty, "MGMTD Databases\n");

	mgmt_db_status_write_one(vty, mgmt_db_mm->running_db);

	mgmt_db_status_write_one(vty, mgmt_db_mm->candidate_db);

	mgmt_db_status_write_one(vty, mgmt_db_mm->oper_db);
}
