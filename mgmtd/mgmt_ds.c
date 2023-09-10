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
#include "mgmt_util.h"

#define MGMTD_DS_DBG(fmt, ...)                                                 \
	DEBUGD(&mgmt_debug_ds, "DS: %s: " fmt, __func__, ##__VA_ARGS__)
#define MGMTD_DS_ERR(fmt, ...)                                                 \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

struct mgmt_ds_ctx {
	Mgmtd__DatastoreId ds_id;

	bool locked;
	uint64_t vty_session_id; /* Owner of the lock or 0 */

	bool config_ds;

	union {
		struct nb_config *cfg_root;
		struct lyd_node *dnode_root;
	} root;
};

struct mgmt_ds_iter_ctx {
	struct mgmt_ds_ctx *ds_ctx;
	void (*ds_iter_fn)(struct mgmt_ds_ctx *ds_ctx,
			   const char *xpath,
			   struct lyd_node *node,
			   struct nb_node *nb_node,
			   void *ctx);
	void *usr_ctx;
};

struct mgmt_ds_child_collect_ctx {
	char **child_xpath;
	void **child_ctx;
	int max_child;
	int num_child;
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

/*
 * Iterate over datastore nodes till leaf node or desired depth
 * is reached.
 */
static int mgmt_walk_ds_nodes(struct mgmt_ds_ctx *ds_ctx,
			      const char *base_xpath,
			      struct lyd_node *base_dnode,
			      void (*mgmt_ds_node_iter_fn)(
					struct mgmt_ds_ctx *ds_ctx,
					const char *xpath,
					struct lyd_node *node,
					struct nb_node *nb_node, void *ctx),
			      void *ctx, int tree_depth, bool iter_base)
{
	/* this is 1k per recursion... */
	char xpath[MGMTD_MAX_XPATH_LEN];
	struct lyd_node *dnode;
	struct nb_node *nbnode;
	int ret = 0;
	bool same_as_base;

	assert(mgmt_ds_node_iter_fn);

	MGMTD_DS_DBG(" -- START: Base: %s, Tree-Depth: %d, Iter-Base: %d",
		     base_xpath, tree_depth, iter_base);

	if (!base_dnode)
		/*
		 * This function only returns the first node of a possible set
		 * of matches issuing a warning if more than 1 matches
		 */
		base_dnode = yang_dnode_get(
			ds_ctx->config_ds ? ds_ctx->root.cfg_root->dnode
					   : ds_ctx->root.dnode_root,
			base_xpath);
	if (!base_dnode)
		return -1;

	if (iter_base && mgmt_ds_node_iter_fn) {
		MGMTD_DS_DBG("           search base schema: '%s'",
			     lysc_path(base_dnode->schema, LYSC_PATH_LOG,
				       xpath, sizeof(xpath)));

		nbnode = (struct nb_node *)base_dnode->schema->priv;
		(*mgmt_ds_node_iter_fn)(ds_ctx, base_xpath, base_dnode, nbnode,
					ctx);
	}

	/*
	 * If the base_xpath points to leaf node, or this is the bottom of the
	 * tree depth desired we can skip the rest of the tree walk
	 */
	if (base_dnode->schema->nodetype & LYD_NODE_TERM || !tree_depth)
		return 0;

	LY_LIST_FOR (lyd_child(base_dnode), dnode) {
		assert(dnode->schema && dnode->schema->priv);
		nbnode = (struct nb_node *)dnode->schema->priv;

		(void)lyd_path(dnode, LYD_PATH_STD, xpath, sizeof(xpath));

		same_as_base = strncmp(xpath, base_xpath, strlen(xpath))
				? false : true;
		MGMTD_DS_DBG(" -- Child XPATH: %s, Same-as-Base: %d",
			     xpath, same_as_base);

		ret = mgmt_walk_ds_nodes(ds_ctx, xpath, dnode,
					 mgmt_ds_node_iter_fn, ctx,
					 same_as_base ?
						tree_depth : tree_depth - 1,
						!same_as_base);

		if (ret != 0)
			break;
	}

	return 0;
}

/*
 * Stores the child node xpath and node in the given xpath context.
 * This function is called from mgmt_ds_get_child_nodes() which in
 * turn is supplied as 'get_child_fn' parameter of
 * mgmt_xpath_resolve_wildcard().
 */
static void mgmt_ds_collect_child_node(struct mgmt_ds_ctx *ds_ctx,
				       const char *xpath,
				       struct lyd_node *node,
				       struct nb_node *nb_node, void *ctx)
{
	struct mgmt_ds_child_collect_ctx *coll_ctx;

	coll_ctx = (struct mgmt_ds_child_collect_ctx *) ctx;

	if (coll_ctx->num_child >= coll_ctx->max_child) {
		MGMTD_DS_ERR("Number of child %d exceeded maximum %d",
			     coll_ctx->num_child, coll_ctx->max_child);
		return;
	}

	/*
	 * Let's allocate a string for the Xpath and add it to
	 * the results. The same should be freed up from
	 * mgmt_xpath_resolve_wildcard().
	 */
	coll_ctx->child_xpath[coll_ctx->num_child] =
		calloc(1, MGMTD_MAX_XPATH_LEN);
	strlcpy(coll_ctx->child_xpath[coll_ctx->num_child], xpath,
		MGMTD_MAX_XPATH_LEN);
	coll_ctx->child_ctx[coll_ctx->num_child] = node;
	MGMTD_DS_DBG("   -- [%d] Child XPATH: %s", coll_ctx->num_child+1,
		     coll_ctx->child_xpath[coll_ctx->num_child]);
	coll_ctx->num_child++;
}

/*
 * Iterates over the datastore nodes to get child nodes for the xpath.
 * This function is supplied as 'get_child_fn' parameter of
 * mgmt_xpath_resolve_wildcard()
 */
static int mgmt_ds_get_child_nodes(const char *base_xpath,
				   char *child_xpath[],
				   void *child_ctx[], int *num_child,
				   void *ctx, char *xpath_key)
{
	struct mgmt_ds_iter_ctx *iter_ctx;
	struct mgmt_ds_ctx *ds_ctx;
	int max_child;
	struct mgmt_ds_child_collect_ctx coll_ctx = { 0 };

	iter_ctx = (struct mgmt_ds_iter_ctx *)ctx;
	ds_ctx = iter_ctx->ds_ctx;
	max_child = *num_child;
	*num_child = 0;
	coll_ctx.child_ctx = child_ctx;
	coll_ctx.child_xpath = child_xpath;
	coll_ctx.max_child = max_child;
	mgmt_walk_ds_nodes(ds_ctx, base_xpath, NULL,
			   mgmt_ds_collect_child_node, &coll_ctx,
			   1, false);
	*num_child = coll_ctx.num_child;

	return 0;
}

/*
 * Iterate over the data nodes.
 */
static int mgmt_ds_iter_data_nodes(const char *node_xpath, void *node_ctx,
				   void *ctx)
{
	struct mgmt_ds_iter_ctx *iter_ctx;
	struct mgmt_ds_ctx *ds_ctx;
	struct lyd_node *dnode;

	iter_ctx = (struct mgmt_ds_iter_ctx *)ctx;
	ds_ctx = iter_ctx->ds_ctx;
	dnode = (struct lyd_node *)node_ctx;

	if (!dnode) {
		dnode = yang_dnode_get(ds_ctx->config_ds ?
					ds_ctx->root.cfg_root->dnode :
					ds_ctx->root.dnode_root,
					node_xpath);
		if (!dnode)
			return -1;
	}

	return mgmt_walk_ds_nodes(ds_ctx, node_xpath, dnode,
				  iter_ctx->ds_iter_fn,
				  iter_ctx->usr_ctx,
				  -1, true);
}

static int mgmt_ds_replace_dst_with_src_ds(struct mgmt_ds_ctx *src,
					   struct mgmt_ds_ctx *dst)
{
	if (!src || !dst)
		return -1;

	MGMTD_DS_DBG("Replacing %s with %s", mgmt_ds_id2name(dst->ds_id),
		     mgmt_ds_id2name(src->ds_id));

	if (src->config_ds && dst->config_ds)
		nb_config_replace(dst->root.cfg_root, src->root.cfg_root, true);
	else {
		assert(!src->config_ds && !dst->config_ds);
		if (dst->root.dnode_root)
			yang_dnode_free(dst->root.dnode_root);
		dst->root.dnode_root = yang_dnode_dup(src->root.dnode_root);
	}

	if (src->ds_id == MGMTD_DS_CANDIDATE) {
		/*
		 * Drop the changes in scratch-buffer.
		 */
		MGMTD_DS_DBG("Emptying Candidate Scratch buffer!");
		nb_config_diff_del_changes(&src->root.cfg_root->cfg_chgs);
	}

	return 0;
}

static int mgmt_ds_merge_src_with_dst_ds(struct mgmt_ds_ctx *src,
					 struct mgmt_ds_ctx *dst)
{
	int ret;

	if (!src || !dst)
		return -1;

	MGMTD_DS_DBG("Merging DS %d with %d", dst->ds_id, src->ds_id);
	if (src->config_ds && dst->config_ds)
		ret = nb_config_merge(dst->root.cfg_root, src->root.cfg_root,
				      true);
	else {
		assert(!src->config_ds && !dst->config_ds);
		ret = lyd_merge_siblings(&dst->root.dnode_root,
					 src->root.dnode_root, 0);
	}
	if (ret != 0) {
		MGMTD_DS_ERR("merge failed with err: %d", ret);
		return ret;
	}

	if (src->ds_id == MGMTD_DS_CANDIDATE) {
		/*
		 * Drop the changes in scratch-buffer.
		 */
		MGMTD_DS_DBG("Emptying Candidate Scratch buffer!");
		nb_config_diff_del_changes(&src->root.cfg_root->cfg_chgs);
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
	if (mgmt_ds_mm || mm->running_ds || mm->candidate_ds || mm->oper_ds)
		assert(!"MGMTD: Call ds_init only once!");

	/* Use Running DS from NB module??? */
	if (!running_config)
		assert(!"MGMTD: Call ds_init after frr_init only!");

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
	nb_config_free(candidate.root.cfg_root);
	candidate.root.cfg_root = NULL;

	yang_dnode_free(oper.root.dnode_root);
	oper.root.dnode_root = NULL;
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

bool mgmt_ds_is_locked(struct mgmt_ds_ctx *ds_ctx, uint64_t session_id)
{
	assert(ds_ctx);
	return (ds_ctx->locked && ds_ctx->vty_session_id == session_id);
}

int mgmt_ds_lock(struct mgmt_ds_ctx *ds_ctx, uint64_t session_id)
{
	assert(ds_ctx);

	if (ds_ctx->locked)
		return EBUSY;

	ds_ctx->locked = true;
	ds_ctx->vty_session_id = session_id;
	return 0;
}

void mgmt_ds_unlock(struct mgmt_ds_ctx *ds_ctx)
{
	assert(ds_ctx);
	if (!ds_ctx->locked)
		zlog_warn(
			"%s: WARNING: unlock on unlocked in DS:%s last session-id %" PRIu64,
			__func__, mgmt_ds_id2name(ds_ctx->ds_id),
			ds_ctx->vty_session_id);
	ds_ctx->locked = 0;
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
	if (nb_node && nb_node->dep_cbs.get_dependant_xpath) {
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

int mgmt_ds_iter_data(Mgmtd__DatastoreId ds_id, struct nb_config *root,
		      const char *base_xpath,
		      void (*mgmt_ds_node_iter_fn)(struct mgmt_ds_ctx *ds_ctx,
						   const char *xpath,
						   struct lyd_node *node,
						   struct nb_node *nb_node,
						   void *ctx),
		      void *ctx)
{
	int ret = 0;
	char xpath[MGMTD_MAX_XPATH_LEN];
	struct lyd_node *base_dnode = NULL;
	struct lyd_node *node;
	struct mgmt_ds_ctx *ds_ctx = { 0 };
	struct mgmt_ds_iter_ctx iter_ctx =  { 0 };

	if (!root)
		return -1;

	strlcpy(xpath, base_xpath, sizeof(xpath));
	mgmt_remove_trailing_separator(xpath, '*');
	mgmt_remove_trailing_separator(xpath, '/');

	/*
	 * mgmt_ds_iter_data is the only user of mgmt_walk_ds_nodes other than
	 * mgmt_walk_ds_nodes itself, so we can modify the API if we would like.
	 * Oper-state should be kept in mind though for the prefix walk
	 */

	MGMTD_DS_DBG(" -- START DS walk for DSid: %d", ds_id);

	/* If the base_xpath is empty then crawl the sibblings */
	if (xpath[0] == 0) {
		base_dnode = root ? root->dnode :
				ds_ctx->config_ds ?
					ds_ctx->root.cfg_root->dnode
					: ds_ctx->root.dnode_root;

		/* get first top-level sibling */
		while (base_dnode->parent)
			base_dnode = lyd_parent(base_dnode);

		while (base_dnode->prev->next)
			base_dnode = base_dnode->prev;

		LY_LIST_FOR (base_dnode, node) {
			lyd_path(node, LYD_PATH_STD, xpath, sizeof(xpath));
			ret = mgmt_ds_iter_data(ds_id, root, xpath,
						mgmt_ds_node_iter_fn, ctx);
		}
	} else {
		ds_ctx = mgmt_ds_get_ctx_by_id(mgmt_ds_mm, ds_id);
		assert(ds_ctx);
		iter_ctx.ds_ctx = ds_ctx;
		iter_ctx.ds_iter_fn = mgmt_ds_node_iter_fn;
		iter_ctx.usr_ctx = ctx;
		ret = mgmt_xpath_resolve_wildcard(xpath, 0,
					mgmt_ds_get_child_nodes,
					mgmt_ds_iter_data_nodes,
					(void *)&iter_ctx, 0);
	}

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
