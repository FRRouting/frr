// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Datastores
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "md5.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_history.h"
#include "mgmtd/mgmt_txn.h"
#include "libyang/libyang.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_DS_DBG(fmt, ...)                                                 \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_DS_ERR(fmt, ...)                                                 \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_DS_DBG(fmt, ...)                                                 \
	do {                                                                   \
		if (mgmt_debug_ds)                                             \
			zlog_err("%s: " fmt, __func__, ##__VA_ARGS__);         \
	} while (0)
#define MGMTD_DS_ERR(fmt, ...)                                                 \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

struct mgmt_ds_ctx {
	Mgmtd__DatastoreId ds_id;
	int lock; /* 0 unlocked, >0 read locked < write locked */

	bool config_ds;

	union {
		struct nb_config *cfg_root;
		struct lyd_node *dnode_root;
	} root;
};

const char *mgmt_ds_names[MGMTD_DS_MAX_ID + 1] = {
	MGMTD_DS_NAME_NONE,	/* MGMTD_DS_NONE */
	MGMTD_DS_NAME_RUNNING,     /* MGMTD_DS_RUNNING */
	MGMTD_DS_NAME_CANDIDATE,   /* MGMTD_DS_CANDIDATE */
	MGMTD_DS_NAME_OPERATIONAL, /* MGMTD_DS_OPERATIONAL */
	"Unknown/Invalid",	 /* MGMTD_DS_ID_MAX */
};

static struct mgmt_master *mgmt_ds_mm;
static struct mgmt_ds_ctx running, candidate, oper;

/* Dump the data tree of the specified format in the file pointed by the path */
static int mgmt_ds_dump_in_memory(struct mgmt_ds_ctx *ds_ctx,
				  const char *base_xpath, LYD_FORMAT format,
				  struct ly_out *out)
{
	struct lyd_node *root;
	uint32_t options = 0;

	if (base_xpath[0] == '\0')
		root = ds_ctx->config_ds ? ds_ctx->root.cfg_root->dnode
					  : ds_ctx->root.dnode_root;
	else
		root = yang_dnode_get(ds_ctx->config_ds
					      ? ds_ctx->root.cfg_root->dnode
					      : ds_ctx->root.dnode_root,
				      base_xpath);
	if (!root)
		return -1;

	options = ds_ctx->config_ds ? LYD_PRINT_WD_TRIM :
		LYD_PRINT_WD_EXPLICIT;

	if (base_xpath[0] == '\0')
		lyd_print_all(out, root, format, options);
	else
		lyd_print_tree(out, root, format, options);

	return 0;
}

static int mgmt_ds_replace_dst_with_src_ds(struct mgmt_ds_ctx *src,
					   struct mgmt_ds_ctx *dst)
{
	struct lyd_node *dst_dnode, *src_dnode;
	struct ly_out *out;

	if (!src || !dst)
		return -1;
	MGMTD_DS_DBG("Replacing %d with %d", dst->ds_id, src->ds_id);

	src_dnode = src->config_ds ? src->root.cfg_root->dnode
				   : dst->root.dnode_root;
	dst_dnode = dst->config_ds ? dst->root.cfg_root->dnode
				   : dst->root.dnode_root;

	if (dst_dnode)
		yang_dnode_free(dst_dnode);

	/* Not using nb_config_replace as the oper ds does not contain nb_config
	 */
	dst_dnode = yang_dnode_dup(src_dnode);
	if (dst->config_ds)
		dst->root.cfg_root->dnode = dst_dnode;
	else
		dst->root.dnode_root = dst_dnode;

	if (src->ds_id == MGMTD_DS_CANDIDATE) {
		/*
		 * Drop the changes in scratch-buffer.
		 */
		MGMTD_DS_DBG("Emptying Candidate Scratch buffer!");
		nb_config_diff_del_changes(&src->root.cfg_root->cfg_chgs);
	}

	if (dst->ds_id == MGMTD_DS_RUNNING) {
		if (ly_out_new_filepath(MGMTD_STARTUP_DS_FILE_PATH, &out)
		    == LY_SUCCESS)
			mgmt_ds_dump_in_memory(dst, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	/* TODO: Update the versions if nb_config present */

	return 0;
}

static int mgmt_ds_merge_src_with_dst_ds(struct mgmt_ds_ctx *src,
					 struct mgmt_ds_ctx *dst)
{
	int ret;
	struct lyd_node **dst_dnode, *src_dnode;
	struct ly_out *out;

	if (!src || !dst)
		return -1;

	MGMTD_DS_DBG("Merging DS %d with %d", dst->ds_id, src->ds_id);

	src_dnode = src->config_ds ? src->root.cfg_root->dnode
				   : dst->root.dnode_root;
	dst_dnode = dst->config_ds ? &dst->root.cfg_root->dnode
				   : &dst->root.dnode_root;
	ret = lyd_merge_siblings(dst_dnode, src_dnode, 0);
	if (ret != 0) {
		MGMTD_DS_ERR("lyd_merge() failed with err %d", ret);
		return ret;
	}

	if (src->ds_id == MGMTD_DS_CANDIDATE) {
		/*
		 * Drop the changes in scratch-buffer.
		 */
		MGMTD_DS_DBG("Emptying Candidate Scratch buffer!");
		nb_config_diff_del_changes(&src->root.cfg_root->cfg_chgs);
	}

	if (dst->ds_id == MGMTD_DS_RUNNING) {
		if (ly_out_new_filepath(MGMTD_STARTUP_DS_FILE_PATH, &out)
		    == LY_SUCCESS)
			mgmt_ds_dump_in_memory(dst, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	return 0;
}

static int mgmt_ds_load_cfg_from_file(const char *filepath,
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

void mgmt_ds_reset_candidate(void)
{
	struct lyd_node *dnode = mm->candidate_ds->root.cfg_root->dnode;
	if (dnode)
		yang_dnode_free(dnode);

	dnode = yang_dnode_new(ly_native_ctx, true);
	mm->candidate_ds->root.cfg_root->dnode = dnode;
}


int mgmt_ds_init(struct mgmt_master *mm)
{
	struct lyd_node *root;

	if (mgmt_ds_mm || mm->running_ds || mm->candidate_ds || mm->oper_ds)
		assert(!"MGMTD: Call ds_init only once!");

	/* Use Running DS from NB module??? */
	if (!running_config)
		assert(!"MGMTD: Call ds_init after frr_init only!");

	if (mgmt_ds_load_cfg_from_file(MGMTD_STARTUP_DS_FILE_PATH, &root)
	    == 0) {
		nb_config_free(running_config);
		running_config = nb_config_new(root);
	}

	running.root.cfg_root = running_config;
	running.config_ds = true;
	running.ds_id = MGMTD_DS_RUNNING;

	candidate.root.cfg_root = nb_config_dup(running.root.cfg_root);
	candidate.config_ds = true;
	candidate.ds_id = MGMTD_DS_CANDIDATE;

	/*
	 * Redirect lib/vty candidate-config datastore to the global candidate
	 * config Ds on the MGMTD process.
	 */
	vty_mgmt_candidate_config = candidate.root.cfg_root;

	oper.root.dnode_root = yang_dnode_new(ly_native_ctx, true);
	oper.config_ds = false;
	oper.ds_id = MGMTD_DS_OPERATIONAL;

	mm->running_ds = &running;
	mm->candidate_ds = &candidate;
	mm->oper_ds = &oper;
	mgmt_ds_mm = mm;

	return 0;
}

void mgmt_ds_destroy(void)
{
	/*
	 * TODO: Free the datastores.
	 */
}

struct mgmt_ds_ctx *mgmt_ds_get_ctx_by_id(struct mgmt_master *mm,
					  Mgmtd__DatastoreId ds_id)
{
	switch (ds_id) {
	case MGMTD_DS_CANDIDATE:
		return (mm->candidate_ds);
	case MGMTD_DS_RUNNING:
		return (mm->running_ds);
	case MGMTD_DS_OPERATIONAL:
		return (mm->oper_ds);
	case MGMTD_DS_NONE:
	case MGMTD__DATASTORE_ID__STARTUP_DS:
	case _MGMTD__DATASTORE_ID_IS_INT_SIZE:
		return 0;
	}

	return 0;
}

bool mgmt_ds_is_config(struct mgmt_ds_ctx *ds_ctx)
{
	if (!ds_ctx)
		return false;

	return ds_ctx->config_ds;
}

int mgmt_ds_read_lock(struct mgmt_ds_ctx *ds_ctx)
{
	if (!ds_ctx)
		return EINVAL;
	if (ds_ctx->lock < 0)
		return EBUSY;
	++ds_ctx->lock;
	return 0;
}

int mgmt_ds_write_lock(struct mgmt_ds_ctx *ds_ctx)
{
	if (!ds_ctx)
		return EINVAL;
	if (ds_ctx->lock != 0)
		return EBUSY;
	ds_ctx->lock = -1;
	return 0;
}

int mgmt_ds_unlock(struct mgmt_ds_ctx *ds_ctx)
{
	if (!ds_ctx)
		return EINVAL;
	if (ds_ctx->lock > 0)
		--ds_ctx->lock;
	else if (ds_ctx->lock < 0) {
		assert(ds_ctx->lock == -1);
		ds_ctx->lock = 0;
	} else {
		assert(ds_ctx->lock != 0);
		return EINVAL;
	}
	return 0;
}

int mgmt_ds_copy_dss(struct mgmt_ds_ctx *src_ds_ctx,
		     struct mgmt_ds_ctx *dst_ds_ctx, bool updt_cmt_rec)
{
	if (mgmt_ds_replace_dst_with_src_ds(src_ds_ctx, dst_ds_ctx) != 0)
		return -1;

	if (updt_cmt_rec && dst_ds_ctx->ds_id == MGMTD_DS_RUNNING)
		mgmt_history_new_record(dst_ds_ctx);

	return 0;
}

int mgmt_ds_dump_ds_to_file(char *file_name, struct mgmt_ds_ctx *ds_ctx)
{
	struct ly_out *out;
	int ret = 0;

	if (ly_out_new_filepath(file_name, &out) == LY_SUCCESS) {
		ret = mgmt_ds_dump_in_memory(ds_ctx, "", LYD_JSON, out);
		ly_out_free(out, NULL, 0);
	}

	return ret;
}

struct nb_config *mgmt_ds_get_nb_config(struct mgmt_ds_ctx *ds_ctx)
{
	if (!ds_ctx)
		return NULL;

	return ds_ctx->config_ds ? ds_ctx->root.cfg_root : NULL;
}

static int mgmt_walk_ds_nodes(
	struct mgmt_ds_ctx *ds_ctx, char *base_xpath,
	struct lyd_node *base_dnode,
	void (*mgmt_ds_node_iter_fn)(struct mgmt_ds_ctx *ds_ctx, char *xpath,
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
		MGMTD_DS_DBG(" -- START: num_left:%d", num_left);
		*num_nodes = 0;
	}

	MGMTD_DS_DBG(" -- START: Base: %s", base_xpath);

	if (!base_dnode)
		base_dnode = yang_dnode_get(
			ds_ctx->config_ds ? ds_ctx->root.cfg_root->dnode
					   : ds_ctx->root.dnode_root,
			base_xpath);
	if (!base_dnode)
		return -1;

	if (mgmt_ds_node_iter_fn) {
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
		(*mgmt_ds_node_iter_fn)(ds_ctx, iter_xp, base_dnode, nbnode,
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
		MGMTD_DS_DBG(" -- XPATH: %s", xpath);

		if (num_nodes)
			num_found = num_left;

		ret = mgmt_walk_ds_nodes(ds_ctx, xpath, dnode,
					 mgmt_ds_node_iter_fn, ctx,
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
		MGMTD_DS_DBG(" -- END: *num_nodes:%d, num_left:%d", *num_nodes,
			     num_left);
	}

	return 0;
}

int mgmt_ds_lookup_data_nodes(struct mgmt_ds_ctx *ds_ctx, const char *xpath,
			      char *dxpaths[], int *num_nodes,
			      bool get_childs_as_well, bool alloc_xp_copy)
{
	char base_xpath[MGMTD_MAX_XPATH_LEN];

	if (!ds_ctx || !num_nodes)
		return -1;

	if (xpath[0] == '.' && xpath[1] == '/')
		xpath += 2;

	strlcpy(base_xpath, xpath, sizeof(base_xpath));
	mgmt_remove_trailing_separator(base_xpath, '/');

	return (mgmt_walk_ds_nodes(ds_ctx, base_xpath, NULL, NULL, NULL,
				   dxpaths, num_nodes, get_childs_as_well,
				   alloc_xp_copy));
}

struct lyd_node *mgmt_ds_find_data_node_by_xpath(struct mgmt_ds_ctx *ds_ctx,
						 const char *xpath)
{
	if (!ds_ctx)
		return NULL;

	return yang_dnode_get(ds_ctx->config_ds ? ds_ctx->root.cfg_root->dnode
						 : ds_ctx->root.dnode_root,
			      xpath);
}

int mgmt_ds_delete_data_nodes(struct mgmt_ds_ctx *ds_ctx, const char *xpath)
{
	struct nb_node *nb_node;
	struct lyd_node *dnode, *dep_dnode;
	char dep_xpath[XPATH_MAXLEN];

	if (!ds_ctx)
		return -1;

	nb_node = nb_node_find(xpath);

	dnode = yang_dnode_get(ds_ctx->config_ds
				       ? ds_ctx->root.cfg_root->dnode
				       : ds_ctx->root.dnode_root,
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
			ds_ctx->config_ds ? ds_ctx->root.cfg_root->dnode
					   : ds_ctx->root.dnode_root,
			dep_xpath);
		if (dep_dnode)
			lyd_free_tree(dep_dnode);
	}
	lyd_free_tree(dnode);

	return 0;
}

int mgmt_ds_load_config_from_file(struct mgmt_ds_ctx *dst,
				  const char *file_path, bool merge)
{
	struct lyd_node *iter;
	struct mgmt_ds_ctx parsed;

	if (!dst)
		return -1;

	if (mgmt_ds_load_cfg_from_file(file_path, &iter) != 0) {
		MGMTD_DS_ERR("Failed to load config from the file %s",
			     file_path);
		return -1;
	}

	parsed.root.cfg_root = nb_config_new(iter);
	parsed.config_ds = true;
	parsed.ds_id = dst->ds_id;

	if (merge)
		mgmt_ds_merge_src_with_dst_ds(&parsed, dst);
	else
		mgmt_ds_replace_dst_with_src_ds(&parsed, dst);

	nb_config_free(parsed.root.cfg_root);

	return 0;
}

int mgmt_ds_iter_data(struct mgmt_ds_ctx *ds_ctx, char *base_xpath,
		      void (*mgmt_ds_node_iter_fn)(struct mgmt_ds_ctx *ds_ctx,
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

	if (!ds_ctx)
		return -1;

	mgmt_remove_trailing_separator(base_xpath, '/');

	strlcpy(xpath, base_xpath, sizeof(xpath));

	MGMTD_DS_DBG(" -- START DS walk for DSid: %d", ds_ctx->ds_id);

	/* If the base_xpath is empty then crawl the sibblings */
	if (xpath[0] == '\0') {
		base_dnode = ds_ctx->config_ds ? ds_ctx->root.cfg_root->dnode
						: ds_ctx->root.dnode_root;

		/* get first top-level sibling */
		while (base_dnode->parent)
			base_dnode = lyd_parent(base_dnode);

		while (base_dnode->prev->next)
			base_dnode = base_dnode->prev;

		LY_LIST_FOR (base_dnode, node) {
			ret = mgmt_walk_ds_nodes(
				ds_ctx, xpath, node, mgmt_ds_node_iter_fn,
				ctx, NULL, NULL, true, alloc_xp_copy);
		}
	} else
		ret = mgmt_walk_ds_nodes(ds_ctx, xpath, base_dnode,
					 mgmt_ds_node_iter_fn, ctx, NULL, NULL,
					 true, alloc_xp_copy);

	return ret;
}

void mgmt_ds_dump_tree(struct vty *vty, struct mgmt_ds_ctx *ds_ctx,
		       const char *xpath, FILE *f, LYD_FORMAT format)
{
	struct ly_out *out;
	char *str;
	char base_xpath[MGMTD_MAX_XPATH_LEN] = {0};

	if (!ds_ctx) {
		vty_out(vty, "    >>>>> Datastore Not Initialized!\n");
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

	mgmt_ds_dump_in_memory(ds_ctx, base_xpath, format, out);

	if (!f)
		vty_out(vty, "%s\n", str);

	ly_out_free(out, NULL, 0);
}

void mgmt_ds_status_write_one(struct vty *vty, struct mgmt_ds_ctx *ds_ctx)
{
	if (!ds_ctx) {
		vty_out(vty, "    >>>>> Datastore Not Initialized!\n");
		return;
	}

	vty_out(vty, "  DS: %s\n", mgmt_ds_id2name(ds_ctx->ds_id));
	vty_out(vty, "    DS-Hndl: \t\t\t%p\n", ds_ctx);
	vty_out(vty, "    Config: \t\t\t%s\n",
		ds_ctx->config_ds ? "True" : "False");
}

void mgmt_ds_status_write(struct vty *vty)
{
	vty_out(vty, "MGMTD Datastores\n");

	mgmt_ds_status_write_one(vty, mgmt_ds_mm->running_ds);

	mgmt_ds_status_write_one(vty, mgmt_ds_mm->candidate_ds);

	mgmt_ds_status_write_one(vty, mgmt_ds_mm->oper_ds);
}
