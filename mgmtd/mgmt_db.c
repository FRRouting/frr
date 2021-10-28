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

#include <zebra.h>
#include "md5.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_db.h"
#include "mgmtd/mgmt_txn.h"
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
			zlog_err("%s: " fmt, __func__, ##__VA_ARGS__);         \
	} while (0)
#define MGMTD_DB_ERR(fmt, ...)                                                 \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

struct mgmt_db_ctx {
	Mgmtd__DatabaseId db_id;
	pthread_rwlock_t rw_lock;

	bool config_db;

	union {
		struct nb_config *cfg_root;
		struct lyd_node *dnode_root;
	} root;
};

struct mgmt_cmt_info_t {
	struct mgmt_cmt_info_dlist_item cmt_dlist;

	char cmtid_str[MGMTD_MD5_HASH_STR_HEX_LEN];
	char time_str[MGMTD_COMMIT_TIME_STR_LEN];
	char cmt_json_file[MGMTD_MAX_COMMIT_FILE_PATH_LEN];
};

DECLARE_DLIST(mgmt_cmt_info_dlist, struct mgmt_cmt_info_t, cmt_dlist);

#define FOREACH_CMT_REC(mm, cmt_info)                                          \
	frr_each_safe(mgmt_cmt_info_dlist, &mm->cmt_dlist, cmt_info)

const char *mgmt_db_names[MGMTD_DB_MAX_ID + 1] = {
	MGMTD_DB_NAME_NONE,	/* MGMTD_DB_NONE */
	MGMTD_DB_NAME_RUNNING,     /* MGMTD_DB_RUNNING */
	MGMTD_DB_NAME_CANDIDATE,   /* MGMTD_DB_RUNNING */
	MGMTD_DB_NAME_OPERATIONAL, /* MGMTD_DB_OPERATIONAL */
	"Unknown/Invalid",	 /* MGMTD_DB_ID_MAX */
};

static struct mgmt_master *mgmt_db_mm;
static struct mgmt_db_ctx running, candidate, oper;

/* Dump the data tree of the specified format in the file pointed by the path */
static int mgmt_db_dump_in_memory(struct mgmt_db_ctx *db_ctx,
				  const char *base_xpath, LYD_FORMAT format,
				  struct ly_out *out)
{
	struct lyd_node *root;
	uint32_t options = 0;

	if (base_xpath[0] == '\0')
		root = db_ctx->config_db ? db_ctx->root.cfg_root->dnode
					  : db_ctx->root.dnode_root;
	else
		root = yang_dnode_get(db_ctx->config_db
					      ? db_ctx->root.cfg_root->dnode
					      : db_ctx->root.dnode_root,
				      base_xpath);
	if (!root)
		return -1;

	options = db_ctx->config_db ? LYD_PRINT_WD_TRIM :
		LYD_PRINT_WD_EXPLICIT;

	if (base_xpath[0] == '\0')
		lyd_print_all(out, root, format, options);
	else
		lyd_print_tree(out, root, format, options);

	return 0;
}

static int mgmt_db_replace_dst_with_src_db(struct mgmt_db_ctx *src,
					   struct mgmt_db_ctx *dst)
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

	if (src->db_id == MGMTD_DB_CANDIDATE) {
		/*
		 * Drop the changes in scratch-buffer.
		 */
		MGMTD_DB_DBG("Emptying Candidate Scratch buffer!");
		nb_config_diff_del_changes(&src->root.cfg_root->cfg_chgs);
	}

	if (dst->db_id == MGMTD_DB_RUNNING) {
		if (ly_out_new_filepath(MGMTD_STARTUP_DB_FILE_PATH, &out)
		    == LY_SUCCESS)
			mgmt_db_dump_in_memory(dst, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	/* TODO: Update the versions if nb_config present */

	return 0;
}

static int mgmt_db_merge_src_with_dst_db(struct mgmt_db_ctx *src,
					 struct mgmt_db_ctx *dst)
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

	if (src->db_id == MGMTD_DB_CANDIDATE) {
		/*
		 * Drop the changes in scratch-buffer.
		 */
		MGMTD_DB_DBG("Emptying Candidate Scratch buffer!");
		nb_config_diff_del_changes(&src->root.cfg_root->cfg_chgs);
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

static bool mgmt_db_cmt_rec_exists(char *file_path)
{
	int exist;

	exist = access(file_path, F_OK);
	if (exist == 0)
		return true;
	else
		return false;
}

static void mgmt_db_remove_cmt_file(char *name)
{
	if (remove(name) == 0)
		zlog_debug("Old commit info deletion succeeded");
	else
		zlog_err("Old commit info deletion failed");
}

static void mgmt_db_compute_cmt_hash(const char *input_str, char *hash)
{
	int i;
	unsigned char digest[MGMTD_MD5_HASH_LEN];
	MD5_CTX ctx;

	memset(&ctx, 0, sizeof(ctx));
	MD5Init(&ctx);
	MD5Update(&ctx, input_str, strlen(input_str));
	MD5Final(digest, &ctx);

	for (i = 0; i < MGMTD_MD5_HASH_LEN; i++)
		snprintf(&hash[i * 2], MGMTD_MD5_HASH_STR_HEX_LEN, "%02x",
			 (unsigned int)digest[i]);
}

static struct mgmt_cmt_info_t *mgmt_db_create_cmt_rec(void)
{
	struct mgmt_cmt_info_t *new;
	struct mgmt_cmt_info_t *cmt_info;
	struct mgmt_cmt_info_t *last_cmt_info = NULL;
	struct timeval cmt_recd_tv;

	new = XCALLOC(MTYPE_MGMTD_CMT_INFO, sizeof(struct mgmt_cmt_info_t));
	gettimeofday(&cmt_recd_tv, NULL);
	mgmt_realtime_to_string(&cmt_recd_tv, new->time_str,
				sizeof(new->time_str));
	mgmt_db_compute_cmt_hash(new->time_str, new->cmtid_str);
	snprintf(new->cmt_json_file, MGMTD_MAX_COMMIT_FILE_PATH_LEN,
		 MGMTD_COMMIT_FILE_PATH, new->cmtid_str);

	if (mgmt_cmt_info_dlist_count(&mm->cmt_dlist)
	    == MGMTD_MAX_COMMIT_LIST) {
		FOREACH_CMT_REC (mm, cmt_info)
			last_cmt_info = cmt_info;

		if (last_cmt_info) {
			mgmt_db_remove_cmt_file(last_cmt_info->cmt_json_file);
			mgmt_cmt_info_dlist_del(&mm->cmt_dlist, last_cmt_info);
			XFREE(MTYPE_MGMTD_CMT_INFO, last_cmt_info);
		}
	}

	mgmt_cmt_info_dlist_add_head(&mm->cmt_dlist, new);
	return new;
}

static struct mgmt_cmt_info_t *mgmt_db_find_cmt_record(const char *cmtid_str)
{
	struct mgmt_cmt_info_t *cmt_info;

	FOREACH_CMT_REC (mm, cmt_info) {
		if (strncmp(cmt_info->cmtid_str, cmtid_str,
			    MGMTD_MD5_HASH_STR_HEX_LEN)
		    == 0)
			return cmt_info;
	}

	return NULL;
}

static bool mgmt_db_read_cmt_record_index(void)
{
	FILE *fp;
	struct mgmt_cmt_info_t cmt_info;
	struct mgmt_cmt_info_t *new;
	int cnt = 0;

	fp = fopen(MGMTD_COMMIT_INDEX_FILE_NAME, "rb");
	if (!fp) {
		zlog_err("Failed to open file %s rb mode",
			 MGMTD_COMMIT_INDEX_FILE_NAME);
		return false;
	}

	while ((fread(&cmt_info, sizeof(cmt_info), 1, fp)) > 0) {
		if (cnt < MGMTD_MAX_COMMIT_LIST) {
			if (!mgmt_db_cmt_rec_exists(cmt_info.cmt_json_file)) {
				zlog_err(
					"Commit record present in index_file, but commit file %s missing",
					cmt_info.cmt_json_file);
				continue;
			}

			new = XCALLOC(MTYPE_MGMTD_CMT_INFO,
				      sizeof(struct mgmt_cmt_info_t));
			memcpy(new, &cmt_info, sizeof(struct mgmt_cmt_info_t));
			mgmt_cmt_info_dlist_add_tail(&mm->cmt_dlist, new);
		} else {
			zlog_err("More records found in index file %s",
				 MGMTD_COMMIT_INDEX_FILE_NAME);
			return false;
		}

		cnt++;
	}

	fclose(fp);
	return true;
}

static bool mgmt_db_dump_cmt_record_index(void)
{
	FILE *fp;
	int ret = 0;
	struct mgmt_cmt_info_t *cmt_info;
	struct mgmt_cmt_info_t cmt_info_set[10];
	int cnt = 0;

	mgmt_db_remove_cmt_file((char *)MGMTD_COMMIT_INDEX_FILE_NAME);
	fp = fopen(MGMTD_COMMIT_INDEX_FILE_NAME, "ab");
	if (!fp) {
		zlog_err("Failed to open file %s ab mode",
			 MGMTD_COMMIT_INDEX_FILE_NAME);
		return false;
	}

	FOREACH_CMT_REC (mm, cmt_info) {
		memcpy(&cmt_info_set[cnt], cmt_info,
		       sizeof(struct mgmt_cmt_info_t));
		cnt++;
	}

	if (!cnt) {
		fclose(fp);
		return false;
	}

	ret = fwrite(&cmt_info_set, sizeof(struct mgmt_cmt_info_t), cnt, fp);
	fclose(fp);
	if (ret != cnt) {
		zlog_err("Write record failed");
		return false;
	} else {
		return true;
	}
}

static int mgmt_db_reset(struct mgmt_db_ctx *db_ctx)
{
	struct lyd_node *dnode;

	if (!db_ctx)
		return -1;

	dnode = db_ctx->config_db ? db_ctx->root.cfg_root->dnode
				   : db_ctx->root.dnode_root;

	if (dnode)
		yang_dnode_free(dnode);

	dnode = yang_dnode_new(ly_native_ctx, true);

	if (db_ctx->config_db)
		db_ctx->root.cfg_root->dnode = dnode;
	else
		db_ctx->root.dnode_root = dnode;

	return 0;
}

static int mgmt_db_rollback_to_cmt(struct vty *vty,
				   struct mgmt_cmt_info_t *cmt_info,
				   bool skip_file_load)
{
	struct mgmt_db_ctx *src_db_ctx;
	struct mgmt_db_ctx *dst_db_ctx;
	int ret = 0;

	src_db_ctx = mgmt_db_get_ctx_by_id(mm, MGMTD_DB_CANDIDATE);
	if (!src_db_ctx) {
		vty_out(vty, "ERROR: Couldnot access Candidate database!\n");
		return -1;
	}

	/*
	 * Note: Write lock on src_db is not required. This is already
	 * taken in 'conf te'.
	 */
	dst_db_ctx = mgmt_db_get_ctx_by_id(mm, MGMTD_DB_RUNNING);
	if (!dst_db_ctx) {
		vty_out(vty, "ERROR: Couldnot access Running database!\n");
		return -1;
	}

	ret = mgmt_db_write_lock(dst_db_ctx);
	if (ret != 0) {
		vty_out(vty,
			"Failed to lock the DB %u for rollback Reason: %s!\n",
			MGMTD_DB_RUNNING, strerror(ret));
		return -1;
	}

	if (!skip_file_load) {
		ret = mgmt_db_load_config_from_file(
			src_db_ctx, cmt_info->cmt_json_file, false);
		if (ret != 0) {
			mgmt_db_unlock(dst_db_ctx);
			vty_out(vty,
				"Error with parsing the file with error code %d\n",
				ret);
			return ret;
		}
	}

	/* Internally trigger a commit-request. */
	ret = mgmt_txn_rollback_trigger_cfg_apply(src_db_ctx, dst_db_ctx);
	if (ret != 0) {
		mgmt_db_unlock(dst_db_ctx);
		vty_out(vty,
			"Error with creating commit apply txn with error code %d\n",
			ret);
		return ret;
	}

	mgmt_db_dump_cmt_record_index();
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

	/*
	 * Redirect lib/vty candidate-config database to the global candidate
	 * config Db on the MGMTD process.
	 */
	vty_mgmt_candidate_config = candidate.root.cfg_root;

	oper.root.dnode_root = yang_dnode_new(ly_native_ctx, true);
	oper.config_db = false;
	oper.db_id = MGMTD_DB_OPERATIONAL;

	mm->running_db = &running;
	mm->candidate_db = &candidate;
	mm->oper_db = &oper;
	mgmt_db_mm = mm;

	/* Create commit record for previously stored commit-apply */
	mgmt_cmt_info_dlist_init(&mgmt_db_mm->cmt_dlist);
	mgmt_db_read_cmt_record_index();

	return 0;
}

void mgmt_db_destroy(void)
{
	struct mgmt_cmt_info_t *cmt_info;

	/*
	 * TODO: Free the databases.
	 */

	FOREACH_CMT_REC (mgmt_db_mm, cmt_info) {
		mgmt_cmt_info_dlist_del(&mgmt_db_mm->cmt_dlist, cmt_info);
		XFREE(MTYPE_MGMTD_CMT_INFO, cmt_info);
	}

	mgmt_cmt_info_dlist_fini(&mgmt_db_mm->cmt_dlist);
}

struct mgmt_db_ctx *mgmt_db_get_ctx_by_id(struct mgmt_master *mm,
					    Mgmtd__DatabaseId db_id)
{
	switch (db_id) {
	case MGMTD_DB_CANDIDATE:
		return (mm->candidate_db);
	case MGMTD_DB_RUNNING:
		return (mm->running_db);
	case MGMTD_DB_OPERATIONAL:
		return (mm->oper_db);
	case MGMTD_DB_NONE:
	case MGMTD__DATABASE_ID__STARTUP_DB:
	case _MGMTD__DATABASE_ID_IS_INT_SIZE:
		return 0;
	}

	return 0;
}

bool mgmt_db_is_config(struct mgmt_db_ctx *db_ctx)
{
	if (!db_ctx)
		return false;

	return db_ctx->config_db;
}

int mgmt_db_read_lock(struct mgmt_db_ctx *db_ctx)
{
	int lock_status;

	if (!db_ctx)
		return -1;

	lock_status = pthread_rwlock_tryrdlock(&db_ctx->rw_lock);
	return lock_status;
}

int mgmt_db_write_lock(struct mgmt_db_ctx *db_ctx)
{
	int lock_status;

	if (!db_ctx)
		return -1;

	lock_status = pthread_rwlock_trywrlock(&db_ctx->rw_lock);
	return lock_status;
}

int mgmt_db_unlock(struct mgmt_db_ctx *db_ctx)
{
	int lock_status;

	if (!db_ctx)
		return -1;

	lock_status = pthread_rwlock_unlock(&db_ctx->rw_lock);
	return lock_status;
}

int mgmt_db_merge_dbs(struct mgmt_db_ctx *src_db_ctx,
		      struct mgmt_db_ctx *dst_db_ctx, bool updt_cmt_rec)
{
	struct mgmt_cmt_info_t *cmt_info;

	if (mgmt_db_merge_src_with_dst_db(src_db_ctx, dst_db_ctx) != 0)
		return -1;

	if (updt_cmt_rec && dst_db_ctx->db_id == MGMTD_DB_RUNNING) {
		cmt_info = mgmt_db_create_cmt_rec();
		mgmt_db_dump_db_to_file(cmt_info->cmt_json_file, dst_db_ctx);
		mgmt_db_dump_cmt_record_index();
	}

	return 0;
}

int mgmt_db_copy_dbs(struct mgmt_db_ctx *src_db_ctx,
		     struct mgmt_db_ctx *dst_db_ctx, bool updt_cmt_rec)
{
	struct mgmt_cmt_info_t *cmt_info;

	if (mgmt_db_replace_dst_with_src_db(src_db_ctx, dst_db_ctx) != 0)
		return -1;

	if (updt_cmt_rec && dst_db_ctx->db_id == MGMTD_DB_RUNNING) {
		cmt_info = mgmt_db_create_cmt_rec();
		mgmt_db_dump_db_to_file(cmt_info->cmt_json_file, dst_db_ctx);
		mgmt_db_dump_cmt_record_index();
	}

	return 0;
}

int mgmt_db_dump_db_to_file(char *file_name, struct mgmt_db_ctx *db_ctx)
{
	struct ly_out *out;
	int ret = 0;

	if (ly_out_new_filepath(file_name, &out) == LY_SUCCESS) {
		ret = mgmt_db_dump_in_memory(db_ctx, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	return ret;
}

struct nb_config *mgmt_db_get_nb_config(struct mgmt_db_ctx *db_ctx)
{
	if (!db_ctx)
		return NULL;

	return db_ctx->config_db ? db_ctx->root.cfg_root : NULL;
}

static int mgmt_walk_db_nodes(
	struct mgmt_db_ctx *db_ctx, char *base_xpath,
	struct lyd_node *base_dnode,
	void (*mgmt_db_node_iter_fn)(struct mgmt_db_ctx *db_ctx, char *xpath,
				     struct lyd_node *node,
				     struct nb_node *nb_node, void *ctx),
	void *ctx, char *xpaths[], int *num_nodes, bool childs_as_well,
	bool alloc_xp_copy)
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
			db_ctx->config_db ? db_ctx->root.cfg_root->dnode
					   : db_ctx->root.dnode_root,
			base_xpath);
	if (!base_dnode)
		return -1;

	if (mgmt_db_node_iter_fn) {
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
		iter_xp = alloc_xp_copy ? strdup(base_xpath) : base_xpath;

		nbnode = (struct nb_node *)base_dnode->schema->priv;
		(*mgmt_db_node_iter_fn)(db_ctx, iter_xp, base_dnode, nbnode,
					ctx);
	}

	if (num_nodes) {
		(*num_nodes)++;
		num_left--;
	}

	/*
	 * If the base_xpath points to a leaf node, or we don't need to
	 * visit any children we can skip the tree walk.
	 */
	if (!childs_as_well || base_dnode->schema->nodetype & LYD_NODE_TERM)
		return 0;

	indx = 0;
	LY_LIST_FOR (lyd_child(base_dnode), dnode) {
		assert(dnode->schema && dnode->schema->priv);

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
			(void) lyd_path(dnode, LYD_PATH_STD, xpath_buf,
					 MGMTD_MAX_XPATH_LEN);
			xpath = xpath_buf;
		}

		assert(xpath);
		MGMTD_DB_DBG(" -- XPATH: %s", xpath);

		if (num_nodes)
			num_found = num_left;

		ret = mgmt_walk_db_nodes(db_ctx, xpath, dnode,
					 mgmt_db_node_iter_fn, ctx,
					 xpaths ? &xpaths[*num_nodes] : NULL,
					 num_nodes ? &num_found : NULL,
					 childs_as_well, alloc_xp_copy);

		if (num_nodes) {
			num_left -= num_found;
			(*num_nodes) += num_found;
		}

		if (alloc_xp)
			free(xpath);

		if (ret != 0)
			break;

		indx++;
	}


	if (num_nodes) {
		MGMTD_DB_DBG(" -- END: *num_nodes:%d, num_left:%d", *num_nodes,
			     num_left);
	}

	return 0;
}

int mgmt_db_lookup_data_nodes(struct mgmt_db_ctx *db_ctx, const char *xpath,
			      char *dxpaths[], int *num_nodes,
			      bool get_childs_as_well, bool alloc_xp_copy)
{
	char base_xpath[MGMTD_MAX_XPATH_LEN];

	if (!db_ctx || !num_nodes)
		return -1;

	if (xpath[0] == '.' && xpath[1] == '/')
		xpath += 2;

	strlcpy(base_xpath, xpath, sizeof(base_xpath));
	mgmt_remove_trailing_separator(base_xpath, '/');

	return (mgmt_walk_db_nodes(db_ctx, base_xpath, NULL, NULL, NULL,
				   dxpaths, num_nodes, get_childs_as_well,
				   alloc_xp_copy));
}

struct lyd_node *mgmt_db_find_data_node_by_xpath(struct mgmt_db_ctx *db_ctx,
						 const char *xpath)
{
	if (!db_ctx)
		return NULL;

	return yang_dnode_get(db_ctx->config_db ? db_ctx->root.cfg_root->dnode
						 : db_ctx->root.dnode_root,
			      xpath);
}

int mgmt_db_delete_data_nodes(struct mgmt_db_ctx *db_ctx, const char *xpath)
{
	struct nb_node *nb_node;
	struct lyd_node *dnode, *dep_dnode;
	char dep_xpath[XPATH_MAXLEN];

	if (!db_ctx)
		return -1;

	nb_node = nb_node_find(xpath);

	dnode = yang_dnode_get(db_ctx->config_db
				       ? db_ctx->root.cfg_root->dnode
				       : db_ctx->root.dnode_root,
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
			db_ctx->config_db ? db_ctx->root.cfg_root->dnode
					   : db_ctx->root.dnode_root,
			dep_xpath);
		if (dep_dnode)
			lyd_free_tree(dep_dnode);
	}
	lyd_free_tree(dnode);

	return 0;
}

int mgmt_db_load_config_from_file(struct mgmt_db_ctx *dst,
				  const char *file_path, bool merge)
{
	struct lyd_node *iter;
	struct mgmt_db_ctx parsed;

	if (!dst)
		return -1;

	if (mgmt_db_load_cfg_from_file(file_path, &iter) != 0) {
		MGMTD_DB_ERR("Failed to load config from the file %s",
			     file_path);
		return -1;
	}

	parsed.root.cfg_root = nb_config_new(iter);
	parsed.config_db = true;
	parsed.db_id = dst->db_id;

	if (merge)
		mgmt_db_merge_src_with_dst_db(&parsed, dst);
	else
		mgmt_db_replace_dst_with_src_db(&parsed, dst);

	nb_config_free(parsed.root.cfg_root);

	return 0;
}

int mgmt_db_iter_data(struct mgmt_db_ctx *db_ctx, char *base_xpath,
		      void (*mgmt_db_node_iter_fn)(struct mgmt_db_ctx *db_ctx,
						   char *xpath,
						   struct lyd_node *node,
						   struct nb_node *nb_node,
						   void *ctx),
		      void *ctx, bool alloc_xp_copy)
{
	int ret;
	char xpath[MGMTD_MAX_XPATH_LEN];
	struct lyd_node *base_dnode = NULL;
	struct lyd_node *node;

	if (!db_ctx)
		return -1;

	mgmt_remove_trailing_separator(base_xpath, '/');

	strlcpy(xpath, base_xpath, sizeof(xpath));

	MGMTD_DB_DBG(" -- START DB walk for DBid: %d", db_ctx->db_id);

	/* If the base_xpath is empty then crawl the sibblings */
	if (xpath[0] == '\0') {
		base_dnode = db_ctx->config_db ? db_ctx->root.cfg_root->dnode
						: db_ctx->root.dnode_root;

		/* get first top-level sibling */
		while (base_dnode->parent)
			base_dnode = lyd_parent(base_dnode);

		while (base_dnode->prev->next)
			base_dnode = base_dnode->prev;

		LY_LIST_FOR (base_dnode, node) {
			ret = mgmt_walk_db_nodes(
				db_ctx, xpath, node, mgmt_db_node_iter_fn,
				ctx, NULL, NULL, true, alloc_xp_copy);
		}
	} else
		ret = mgmt_walk_db_nodes(db_ctx, xpath, base_dnode,
					 mgmt_db_node_iter_fn, ctx, NULL, NULL,
					 true, alloc_xp_copy);

	return ret;
}

void mgmt_db_dump_tree(struct vty *vty, struct mgmt_db_ctx *db_ctx,
		       const char *xpath, FILE *f, LYD_FORMAT format)
{
	struct ly_out *out;
	char *str;
	char base_xpath[MGMTD_MAX_XPATH_LEN] = {0};

	if (!db_ctx) {
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

	mgmt_db_dump_in_memory(db_ctx, base_xpath, format, out);

	if (!f)
		vty_out(vty, "%s\n", str);

	ly_out_free(out, NULL, 0);
}

void mgmt_db_status_write_one(struct vty *vty, struct mgmt_db_ctx *db_ctx)
{
	if (!db_ctx) {
		vty_out(vty, "    >>>>> Database Not Initialized!\n");
		return;
	}

	vty_out(vty, "  DB: %s\n", mgmt_db_id2name(db_ctx->db_id));
	vty_out(vty, "    DB-Hndl: \t\t\t%p\n", db_ctx);
	vty_out(vty, "    Config: \t\t\t%s\n",
		db_ctx->config_db ? "True" : "False");
}

void mgmt_db_status_write(struct vty *vty)
{
	vty_out(vty, "MGMTD Databases\n");

	mgmt_db_status_write_one(vty, mgmt_db_mm->running_db);

	mgmt_db_status_write_one(vty, mgmt_db_mm->candidate_db);

	mgmt_db_status_write_one(vty, mgmt_db_mm->oper_db);
}

int mgmt_db_rollback_by_cmtid(struct vty *vty, const char *cmtid_str)
{
	int ret = 0;
	struct mgmt_cmt_info_t *cmt_info;

	if (!mgmt_cmt_info_dlist_count(&mm->cmt_dlist)
	    || !mgmt_db_find_cmt_record(cmtid_str)) {
		vty_out(vty, "Invalid commit Id\n");
		return -1;
	}

	FOREACH_CMT_REC (mm, cmt_info) {
		if (strncmp(cmt_info->cmtid_str, cmtid_str,
			    MGMTD_MD5_HASH_STR_HEX_LEN)
		    == 0) {
			ret = mgmt_db_rollback_to_cmt(vty, cmt_info, false);
			return ret;
		}

		mgmt_db_remove_cmt_file(cmt_info->cmt_json_file);
		mgmt_cmt_info_dlist_del(&mm->cmt_dlist, cmt_info);
		XFREE(MTYPE_MGMTD_CMT_INFO, cmt_info);
	}

	return 0;
}

int mgmt_db_rollback_commits(struct vty *vty, int num_cmts)
{
	int ret = 0;
	int cnt = 0;
	struct mgmt_cmt_info_t *cmt_info;
	size_t cmts;

	if (!num_cmts)
		num_cmts = 1;

	cmts = mgmt_cmt_info_dlist_count(&mm->cmt_dlist);
	if ((int)cmts < num_cmts) {
		vty_out(vty,
			"Number of commits found (%d) less than required to rollback\n",
			(int)cmts);
		return -1;
	}

	if ((int)cmts == 1 || (int)cmts == num_cmts) {
		vty_out(vty,
			"Number of commits found (%d), Rollback of last commit is not supported\n",
			(int)cmts);
		return -1;
	}

	FOREACH_CMT_REC (mm, cmt_info) {
		if (cnt == num_cmts) {
			ret = mgmt_db_rollback_to_cmt(vty, cmt_info, false);
			return ret;
		}

		cnt++;
		mgmt_db_remove_cmt_file(cmt_info->cmt_json_file);
		mgmt_cmt_info_dlist_del(&mm->cmt_dlist, cmt_info);
		XFREE(MTYPE_MGMTD_CMT_INFO, cmt_info);
	}

	if (!mgmt_cmt_info_dlist_count(&mm->cmt_dlist)) {
		ret = mgmt_db_reset((struct mgmt_db_ctx *)mm->candidate_db);
		if (ret < 0)
			return ret;
		ret = mgmt_db_rollback_to_cmt(vty, cmt_info, true);
	}

	return ret;
}

void show_mgmt_cmt_history(struct vty *vty)
{
	struct mgmt_cmt_info_t *cmt_info;
	int slno = 0;

	vty_out(vty, "Last 10 commit history:\n");
	vty_out(vty, "  Sl.No\tCommit-ID(HEX)\t\t\t  Commit-Record-Time\n");
	FOREACH_CMT_REC (mm, cmt_info) {
		vty_out(vty, "  %d\t%s  %s\n", slno, cmt_info->cmtid_str,
			cmt_info->time_str);
		slno++;
	}
}
