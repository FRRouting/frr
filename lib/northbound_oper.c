// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * October 14 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */

#include <zebra.h>
#include "darr.h"
#include "debug.h"
#include "frrevent.h"
#include "frrstr.h"
#include "lib_errors.h"
#include "monotime.h"
#include "northbound.h"

/*
 * YANG model yielding design restrictions:
 *
 * In order to be able to yield and guarantee we have a valid data tree at the
 * point of yielding we must know that each parent has all it's siblings
 * collected to represent a complete element.
 *
 * Basically, there should be a only single branch in the schema tree that
 * supports yielding. In practice this means:
 *
 * list node schema with lookup next:
 * - must not have any lookup-next list node sibling schema
 * - must not have any list or container node siblings with lookup-next descendants.
 * - any parent list nodes must also be lookup-next list nodes
 *
 * We must also process containers with lookup-next descendants last.
 */

DEFINE_MTYPE_STATIC(LIB, NB_YIELD_STATE, "NB Yield State");
DEFINE_MTYPE_STATIC(LIB, NB_NODE_INFOS, "NB Node Infos");

/* Amount of time allowed to spend constructing oper-state prior to yielding */
#define NB_OP_WALK_INTERVAL_MS 50
#define NB_OP_WALK_INTERVAL_US (NB_OP_WALK_INTERVAL_MS * 1000)

/* ---------- */
/* Data Types */
/* ---------- */
PREDECL_LIST(nb_op_walks);

/*
 * This is our information about a node on the branch we are looking at
 */
struct nb_op_node_info {
	struct lyd_node *inner;
	const struct lysc_node *schema; /* inner schema in case we rm inner */
	struct yang_list_keys keys;	/* if list, keys to locate element */
	const void *list_entry;		/* opaque entry from user or NULL */
	uint xpath_len;		  /* length of the xpath string for this node */
	uint niters;		  /* # list elems create this iteration */
	uint nents;		  /* # list elems create so far */
	bool query_specific_entry : 1; /* this info is specific specified */
	bool has_lookup_next : 1; /* if this node support lookup next */
	bool lookup_next_ok : 1;  /* if this and all previous support */
};

/**
 * struct nb_op_yield_state - tracking required state for yielding.
 *
 * @xpath: current xpath representing the node_info stack.
 * @xpath_orig: the original query string from the user
 * @node_infos: the container stack for the walk from root to current
 * @schema_path: the schema nodes along the path indicated by the query string.
 *               this will include the choice and case nodes which are not
 *               present in the query string.
 * @query_tokstr: the query string tokenized with NUL bytes.
 * @query_tokens: the string pointers to each query token (node).
 * @non_specific_predicate: tracks if a query_token is non-specific predicate.
 * @walk_root_level: The topmost specific node, +1 is where we start walking.
 * @walk_start_level: @walk_root_level + 1.
 * @query_base_level: the level the query string stops at and full walks
 *                    commence below that.
 */
struct nb_op_yield_state {
	/* Walking state */
	char *xpath;
	char *xpath_orig;
	struct nb_op_node_info *node_infos;
	const struct lysc_node **schema_path;
	char *query_tokstr;
	char **query_tokens;
	uint8_t *non_specific_predicate;
	int walk_root_level;
	int walk_start_level;
	int query_base_level;
	bool query_list_entry; /* XXX query was for a specific list entry */

	/* Yielding state */
	bool query_did_entry;  /* currently processing the entry */
	bool should_batch;
	struct timeval start_time;
	struct yang_translator *translator;
	uint32_t flags;
	nb_oper_data_cb cb;
	void *cb_arg;
	nb_oper_data_finish_cb finish;
	void *finish_arg;
	struct event *walk_ev;
	struct nb_op_walks_item link;
};

DECLARE_LIST(nb_op_walks, struct nb_op_yield_state, link);

/* ---------------- */
/* Global Variables */
/* ---------------- */

static struct event_loop *event_loop;
static struct nb_op_walks_head nb_op_walks;

/* --------------------- */
/* Function Declarations */
/* --------------------- */

static enum nb_error nb_op_yield(struct nb_op_yield_state *ys);
static struct lyd_node *ys_root_node(struct nb_op_yield_state *ys);

/* -------------------- */
/* Function Definitions */
/* -------------------- */

static inline struct nb_op_yield_state *
nb_op_create_yield_state(const char *xpath, struct yang_translator *translator,
			 uint32_t flags, bool should_batch, nb_oper_data_cb cb,
			 void *cb_arg, nb_oper_data_finish_cb finish,
			 void *finish_arg)
{
	struct nb_op_yield_state *ys;

	ys = XCALLOC(MTYPE_NB_YIELD_STATE, sizeof(*ys));
	ys->xpath = darr_strdup_cap(xpath, (size_t)XPATH_MAXLEN);
	ys->xpath_orig = darr_strdup(xpath);
	ys->translator = translator;
	ys->flags = flags;
	ys->should_batch = should_batch;
	ys->cb = cb;
	ys->cb_arg = cb_arg;
	ys->finish = finish;
	ys->finish_arg = finish_arg;

	nb_op_walks_add_tail(&nb_op_walks, ys);

	return ys;
}

static inline void nb_op_free_yield_state(struct nb_op_yield_state *ys,
					  bool nofree_tree)
{
	if (ys) {
		EVENT_OFF(ys->walk_ev);
		nb_op_walks_del(&nb_op_walks, ys);
		/* if we have a branch then free up it's libyang tree */
		if (!nofree_tree && ys_root_node(ys))
			lyd_free_all(ys_root_node(ys));
		darr_free(ys->query_tokens);
		darr_free(ys->non_specific_predicate);
		darr_free(ys->query_tokstr);
		darr_free(ys->schema_path);
		darr_free(ys->node_infos);
		darr_free(ys->xpath_orig);
		darr_free(ys->xpath);
		XFREE(MTYPE_NB_YIELD_STATE, ys);
	}
}

static const struct lysc_node *ys_get_walk_stem_tip(struct nb_op_yield_state *ys)
{
	if (ys->walk_start_level <= 0)
		return NULL;
	return ys->node_infos[ys->walk_start_level - 1].schema;
}

static struct lyd_node *ys_root_node(struct nb_op_yield_state *ys)
{
	if (!darr_len(ys->node_infos))
		return NULL;
	return ys->node_infos[0].inner;
}

static void ys_trim_xpath(struct nb_op_yield_state *ys)
{
	uint len = darr_len(ys->node_infos);

	if (len == 0)
		darr_setlen(ys->xpath, 1);
	else
		darr_setlen(ys->xpath, darr_last(ys->node_infos)->xpath_len + 1);
	ys->xpath[darr_len(ys->xpath) - 1] = 0;
}

static void ys_pop_inner(struct nb_op_yield_state *ys)
{
	uint len = darr_len(ys->node_infos);

	assert(len);
	darr_setlen(ys->node_infos, len - 1);
	ys_trim_xpath(ys);
}

static void ys_free_inner(struct nb_op_yield_state *ys,
			  struct nb_op_node_info *ni)
{
	if (!CHECK_FLAG(ni->schema->nodetype, LYS_CASE | LYS_CHOICE))
		lyd_free_tree(ni->inner);
	ni->inner = NULL;
}

static void nb_op_get_keys(struct lyd_node_inner *list_node,
			   struct yang_list_keys *keys)
{
	struct lyd_node *child;
	uint n = 0;

	keys->num = 0;
	LY_LIST_FOR (list_node->child, child) {
		if (!lysc_is_key(child->schema))
			break;
		strlcpy(keys->key[n], yang_dnode_get_string(child, NULL),
			sizeof(keys->key[n]));
		n++;
	}

	keys->num = n;
}

/**
 * __move_back_to_next() - move back to the next lookup-next schema
 */
static bool __move_back_to_next(struct nb_op_yield_state *ys, int i)
{
	struct nb_op_node_info *ni;
	int j;

	/*
	 * We will free the subtree we are trimming back to, or we will be done
	 * with the walk and will free the root on cleanup.
	 */

	/* pop any node_info we dropped below on entry */
	for (j = darr_ilen(ys->node_infos) - 1; j > i; j--)
		ys_pop_inner(ys);

	for (; i >= ys->walk_root_level; i--) {
		if (ys->node_infos[i].has_lookup_next)
			break;
		ys_pop_inner(ys);
	}

	if (i < ys->walk_root_level)
		return false;

	ni = &ys->node_infos[i];

	/*
	 * The i'th node has been lost after a yield so trim it from the tree
	 * now.
	 */
	ys_free_inner(ys, ni);
	ni->list_entry = NULL;

	/*
	 * Leave the empty-of-data node_info on top, __walk will deal with
	 * this, by doing a lookup-next with the keys which we still have.
	 */

	return true;
}

static void nb_op_resume_data_tree(struct nb_op_yield_state *ys)
{
	struct nb_op_node_info *ni;
	struct nb_node *nn;
	const void *parent_entry;
	const void *list_entry;
	uint i;

	/*
	 * IMPORTANT: On yielding: we always yield during list iteration and
	 * after the initial list element has been created and handled, so the
	 * top of the yield stack will always point at a list node.
	 *
	 * Additionally, that list node has been processed and was in the
	 * process of being "get_next"d when we yielded. We process the
	 * lookup-next list node last so all the rest of the data (to the left)
	 * has been gotten. NOTE: To keep this simple we will require only a
	 * single lookup-next sibling in any parents list of children.
	 *
	 * Walk the rightmost branch (the node info stack) from base to tip
	 * verifying all list nodes are still present. If not we backup to the
	 * node which has a lookup next, and we prune the branch to this node.
	 * If the list node that went away is the topmost we will be using
	 * lookup_next, but if it's a parent then the list_entry will have been
	 * restored.
	 */
	darr_foreach_i (ys->node_infos, i) {
		ni = &ys->node_infos[i];
		nn = ni->schema->priv;

		if (!CHECK_FLAG(ni->schema->nodetype, LYS_LIST))
			continue;

		assert(ni->list_entry != NULL ||
		       ni == darr_last(ys->node_infos));

		/* Verify the entry is still present */
		parent_entry = (i == 0 ? NULL : ni[-1].list_entry);
		list_entry = nb_callback_lookup_entry(nn, parent_entry,
						      &ni->keys);
		if (!list_entry || list_entry != ni->list_entry) {
			/* May be NULL or a different pointer
			 * move back to first of
			 * container with last lookup_next list node
			 * (which may be this one) and get next.
			 */
			if (!__move_back_to_next(ys, i))
				DEBUGD(&nb_dbg_events,
				       "%s: Nothing to resume after delete during walk (yield)",
				       __func__);
			return;
		}
	}
}

/*
 * Can only yield if all list nodes to root have lookup_next() callbacks
 *
 * In order to support lookup_next() the list_node get_next() callback
 * needs to return ordered (i.e., sorted) results.
 */

/* ======================= */
/* Start of walk init code */
/* ======================= */

/**
 * __xpath_pop_node() - remove the last node from xpath string
 * @xpath: an xpath string
 *
 * Return: NB_OK or NB_ERR_NOT_FOUND if nothing left to pop.
 */
static int __xpath_pop_node(char *xpath)
{
	int len = strlen(xpath);
	bool abs = xpath[0] == '/';
	char *slash;

	/* "//" or "/" => NULL */
	if (abs && (len == 1 || (len == 2 && xpath[1] == '/')))
		return NB_ERR_NOT_FOUND;

	slash = (char *)frrstr_back_to_char(xpath, '/');
	/* "/foo/bar/" or "/foo/bar//" => "/foo " */
	if (slash && slash == &xpath[len - 1]) {
		xpath[--len] = 0;
		slash = (char *)frrstr_back_to_char(xpath, '/');
		if (slash && slash == &xpath[len - 1]) {
			xpath[--len] = 0;
			slash = (char *)frrstr_back_to_char(xpath, '/');
		}
	}
	if (!slash)
		return NB_ERR_NOT_FOUND;
	*slash = 0;
	return NB_OK;
}

/**
 * nb_op_xpath_to_trunk() - generate a lyd_node tree (trunk) using an xpath.
 * @xpath_in: xpath query string to build trunk from.
 * @dnode: resulting tree (trunk)
 *
 * Use the longest prefix of @xpath_in as possible to resolve to a tree (trunk).
 * This is logically as if we walked along the xpath string resolving each
 * nodename reference (in particular list nodes) until we could not.
 *
 * Return: error if any, if no error then @dnode contains the tree (trunk).
 */
static enum nb_error nb_op_xpath_to_trunk(const char *xpath_in,
					  struct lyd_node **trunk)
{
	char *xpath = NULL;
	enum nb_error ret = NB_OK;
	LY_ERR err;

	darr_in_strdup(xpath, xpath_in);
	for (;;) {
		err = lyd_new_path2(NULL, ly_native_ctx, xpath, NULL, 0, 0,
				    LYD_NEW_PATH_UPDATE, NULL, trunk);
		if (err == LY_SUCCESS)
			break;

		ret = __xpath_pop_node(xpath);
		if (ret != NB_OK)
			break;
	}
	darr_free(xpath);
	return ret;
}

/*
 * Finish initializing the node info based on the xpath string, and previous
 * node_infos on the stack. If this node is a list node, obtain the specific
 * list-entry object.
 */
static enum nb_error nb_op_ys_finalize_node_info(struct nb_op_yield_state *ys,
						 uint index)
{
	struct nb_op_node_info *ni = &ys->node_infos[index];
	struct lyd_node *inner = ni->inner;
	struct nb_node *nn = ni->schema->priv;
	bool yield_ok = ys->finish != NULL;

	ni->has_lookup_next = nn->cbs.lookup_next != NULL;

	/* track the last list_entry until updated by new list node */
	ni->list_entry = index == 0 ? NULL : ni[-1].list_entry;

	/* Assert that we are walking the rightmost branch */
	assert(!inner->parent || inner == inner->parent->child->prev);

	if (CHECK_FLAG(inner->schema->nodetype,
		       LYS_CASE | LYS_CHOICE | LYS_CONTAINER)) {
		/* containers have only zero or one child on a branch of a tree */
		inner = ((struct lyd_node_inner *)inner)->child;
		assert(!inner || inner->prev == inner);
		ni->lookup_next_ok = yield_ok &&
				     (index == 0 || ni[-1].lookup_next_ok);
		return NB_OK;
	}

	assert(CHECK_FLAG(inner->schema->nodetype, LYS_LIST));

	ni->lookup_next_ok = yield_ok && ni->has_lookup_next &&
			     (index == 0 || ni[-1].lookup_next_ok);

	nb_op_get_keys((struct lyd_node_inner *)inner, &ni->keys);

	/* A list entry cannot be present in a tree w/o it's keys */
	assert(ni->keys.num == yang_snode_num_keys(inner->schema));

	/*
	 * Get this nodes opaque list_entry object
	 */

	if (!nn->cbs.lookup_entry) {
		flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
			  "%s: data path doesn't support iteration over operational data: %s",
			  __func__, ys->xpath);
		return NB_ERR_NOT_FOUND;
	}

	/* ni->list_entry starts as the parent entry of this node */
	ni->list_entry = nb_callback_lookup_entry(nn, ni->list_entry, &ni->keys);
	if (ni->list_entry == NULL) {
		flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
			  "%s: list entry lookup failed", __func__);
		return NB_ERR_NOT_FOUND;
	}

	/*
	 * By definition any list element we can get a specific list_entry for
	 * is specific.
	 */
	ni->query_specific_entry = true;

	return NB_OK;
}

/**
 * nb_op_ys_init_node_infos() - initialize the node info stack from the query.
 * @ys: the yield state for this tree walk.
 *
 * On starting a walk we initialize the node_info stack as deeply as possible
 * based on specific node references in the query string. We will stop at the
 * point in the query string that is not specific (e.g., a list element without
 * it's keys predicate)
 *
 * Return: northbound return value (enum nb_error)
 */
static enum nb_error nb_op_ys_init_node_infos(struct nb_op_yield_state *ys)
{
	struct nb_op_node_info *ni;
	struct lyd_node *inner;
	struct lyd_node *node = NULL;
	enum nb_error ret;
	uint i, len;
	char *tmp;

	/*
	 * Obtain the trunk of the data node tree of the query.
	 *
	 * These are the nodes from the root that could be specifically
	 * identified with the query string. The trunk ends when a no specific
	 * node could be identified (e.g., a list-node name with no keys).
	 */

	ret = nb_op_xpath_to_trunk(ys->xpath, &node);
	if (ret || !node) {
		flog_warn(EC_LIB_LIBYANG,
			  "%s: can't instantiate concrete path using xpath: %s",
			  __func__, ys->xpath);
		if (!ret)
			ret = NB_ERR_NOT_FOUND;
		return ret;
	}

	/* Move up to the container if on a leaf currently. */
	if (node &&
	    !CHECK_FLAG(node->schema->nodetype, LYS_CONTAINER | LYS_LIST)) {
		struct lyd_node *leaf = node;

		node = &node->parent->node;

		/*
		 * If the leaf is not a key, delete it, because it has a wrong
		 *  empty value.
		 */
		if (!lysc_is_key(leaf->schema))
			lyd_free_tree(leaf);
	}
	assert(!node ||
	       CHECK_FLAG(node->schema->nodetype, LYS_CONTAINER | LYS_LIST));
	if (!node)
		return NB_ERR_NOT_FOUND;

	inner = node;
	for (len = 1; inner->parent; len++)
		inner = &inner->parent->node;

	darr_append_nz_mt(ys->node_infos, len, MTYPE_NB_NODE_INFOS);

	/*
	 * For each node find the prefix of the xpath query that identified it
	 * -- save the prefix length.
	 */
	inner = node;
	for (i = len; i > 0; i--, inner = &inner->parent->node) {
		ni = &ys->node_infos[i - 1];
		ni->inner = inner;
		ni->schema = inner->schema;
		/*
		 * NOTE: we could build this by hand with a litte more effort,
		 * but this simple implementation works and won't be expensive
		 * since the number of nodes is small and only done once per
		 * query.
		 */
		tmp = yang_dnode_get_path(inner, NULL, 0);
		ni->xpath_len = strlen(tmp);

		/* Replace users supplied xpath with the libyang returned value */
		if (i == len)
			darr_in_strdup(ys->xpath, tmp);

		/* The prefix must match the prefix of the stored xpath */
		assert(!strncmp(tmp, ys->xpath, ni->xpath_len));
		free(tmp);
	}

	/*
	 * Obtain the specific list-entry objects for each list node on the
	 * trunk and finish initializing the node_info structs.
	 */

	darr_foreach_i (ys->node_infos, i) {
		ret = nb_op_ys_finalize_node_info(ys, i);
		if (ret != NB_OK) {
			if (ys->node_infos[0].inner)
				lyd_free_all(ys->node_infos[0].inner);
			darr_free(ys->node_infos);
			return ret;
		}
	}

	ys->walk_start_level = darr_len(ys->node_infos);

	ys->walk_root_level = (int)ys->walk_start_level - 1;

	return NB_OK;
}

/* ================ */
/* End of init code */
/* ================ */

/**
 * nb_op_add_leaf() - Add leaf data to the get tree results
 * @ys - the yield state for this tree walk.
 * @nb_node - the northbound node representing this leaf.
 * @xpath - the xpath (with key predicates) to this leaf value.
 *
 * Return: northbound return value (enum nb_error)
 */
static enum nb_error nb_op_iter_leaf(struct nb_op_yield_state *ys,
				     const struct nb_node *nb_node,
				     const char *xpath)
{
	const struct lysc_node *snode = nb_node->snode;
	struct nb_op_node_info *ni = darr_last(ys->node_infos);
	struct yang_data *data;
	enum nb_error ret = NB_OK;
	LY_ERR err;

	if (CHECK_FLAG(snode->flags, LYS_CONFIG_W))
		return NB_OK;

	/* Ignore list keys. */
	if (lysc_is_key(snode))
		return NB_OK;

	data = nb_callback_get_elem(nb_node, xpath, ni->list_entry);
	if (data == NULL)
		return NB_OK;

	/* Add a dnode to our tree */
	err = lyd_new_term(ni->inner, snode->module, snode->name, data->value,
			   false, NULL);
	if (err) {
		yang_data_free(data);
		return NB_ERR_RESOURCE;
	}

	if (ys->cb)
		ret = (*ys->cb)(nb_node->snode, ys->translator, data,
				ys->cb_arg);
	yang_data_free(data);

	return ret;
}

static enum nb_error nb_op_iter_leaflist(struct nb_op_yield_state *ys,
					 const struct nb_node *nb_node,
					 const char *xpath)
{
	const struct lysc_node *snode = nb_node->snode;
	struct nb_op_node_info *ni = darr_last(ys->node_infos);
	const void *list_entry = NULL;
	enum nb_error ret = NB_OK;
	LY_ERR err;

	if (CHECK_FLAG(snode->flags, LYS_CONFIG_W))
		return NB_OK;

	do {
		struct yang_data *data;

		list_entry = nb_callback_get_next(nb_node, ni->list_entry,
						  list_entry);
		if (!list_entry)
			/* End of the list. */
			break;

		data = nb_callback_get_elem(nb_node, xpath, list_entry);
		if (data == NULL)
			continue;

		/* Add a dnode to our tree */
		err = lyd_new_term(ni->inner, snode->module, snode->name,
				   data->value, false, NULL);
		if (err) {
			yang_data_free(data);
			return NB_ERR_RESOURCE;
		}

		if (ys->cb)
			ret = (*ys->cb)(nb_node->snode, ys->translator, data,
					ys->cb_arg);
		yang_data_free(data);
	} while (ret == NB_OK && list_entry);

	return ret;
}


static bool nb_op_schema_path_has_predicate(struct nb_op_yield_state *ys,
					    int level)
{
	if (level > darr_lasti(ys->query_tokens))
		return false;
	return strchr(ys->query_tokens[level], '[') != NULL;
}

/**
 * nb_op_empty_container_ok() - determine if should keep empty container node.
 *
 * Return: true if the empty container should be kept.
 */
static bool nb_op_empty_container_ok(const struct lysc_node *snode,
				     const char *xpath, const void *list_entry)
{
	struct nb_node *nn = snode->priv;
	struct yang_data *data;

	if (!CHECK_FLAG(snode->flags, LYS_PRESENCE))
		return false;

	if (!nn->cbs.get_elem)
		return false;

	data = nb_callback_get_elem(nn, xpath, list_entry);
	if (data) {
		yang_data_free(data);
		return true;
	}
	return false;
}

/**
 * nb_op_get_child_path() - add child node name to the xpath.
 * @xpath_parent - a darr string for the parent node.
 * @schild - the child schema node.
 * @xpath_child - a previous return value from this function to reuse.
 */
static char *nb_op_get_child_path(const char *xpath_parent,
				  const struct lysc_node *schild,
				  char *xpath_child)
{
	/* "/childname" */
	uint space, extra = strlen(schild->name) + 1;
	bool new_mod = (!schild->parent ||
			schild->parent->module != schild->module);
	int n;

	if (new_mod)
		/* "modulename:" */
		extra += strlen(schild->module->name) + 1;
	space = darr_len(xpath_parent) + extra;

	if (xpath_parent == xpath_child)
		darr_ensure_cap(xpath_child, space);
	else
		darr_in_strdup_cap(xpath_child, xpath_parent, space);
	if (new_mod)
		n = snprintf(darr_strnul(xpath_child), extra + 1, "/%s:%s",
			     schild->module->name, schild->name);
	else
		n = snprintf(darr_strnul(xpath_child), extra + 1, "/%s",
			     schild->name);
	assert(n == (int)extra);
	_darr_len(xpath_child) += extra;
	return xpath_child;
}

static bool __is_yielding_node(const struct lysc_node *snode)
{
	struct nb_node *nn = snode->priv;

	return nn->cbs.lookup_next != NULL;
}

static const struct lysc_node *__sib_next(bool yn, const struct lysc_node *sib)
{
	for (; sib; sib = sib->next) {
		/* Always skip keys. */
		if (lysc_is_key(sib))
			continue;
		if (yn == __is_yielding_node(sib))
			return sib;
	}
	return NULL;
}

/**
 * nb_op_sib_next() - Return the next sibling to walk to
 * @ys: the yield state for this tree walk.
 * @sib: the currently being visited sibling
 *
 * Return: the next sibling to walk to, walking non-yielding before yielding.
 */
static const struct lysc_node *nb_op_sib_next(struct nb_op_yield_state *ys,
					      const struct lysc_node *sib)
{
	struct lysc_node *parent = sib->parent;
	bool yn = __is_yielding_node(sib);

	/*
	 * If the node info stack is shorter than the schema path then we are
	 * doign specific query still on the node from the schema path (should
	 * match) so just return NULL (i.e., don't process siblings)
	 */
	if (darr_len(ys->schema_path) > darr_len(ys->node_infos))
		return NULL;
	/*
	 * If sib is on top of the node info stack then
	 * 1) it's a container node -or-
	 * 2) it's a list node that we were walking and we've reach the last entry
	 * 3) if sib is a list and the list was empty we never would have
	 * pushed sib on the stack so the top of the stack is the parent
	 *
	 * If the query string included this node then we do not process any
	 * siblings as we are not walking all the parent's children just this
	 * specified one give by the query string.
	 */
	if (sib == darr_last(ys->node_infos)->schema &&
	    darr_len(ys->schema_path) >= darr_len(ys->node_infos))
		return NULL;
	/* case (3) */
	else if (sib->nodetype == LYS_LIST &&
		 parent == darr_last(ys->node_infos)->schema &&
		 darr_len(ys->schema_path) > darr_len(ys->node_infos))
		return NULL;

	sib = __sib_next(yn, sib->next);
	if (sib)
		return sib;
	if (yn)
		return NULL;
	return __sib_next(true, lysc_node_child(parent));
}
/*
 * sib_walk((struct lyd_node *)ni->inner->node.parent->parent->parent->parent->parent->parent->parent)
 */

/**
 * nb_op_sib_first() - obtain the first child to walk to
 * @ys: the yield state for this tree walk.
 * @parent: the parent whose child we seek
 * @skip_keys: if should skip over keys
 *
 * Return: the first child to continue the walk to, starting with non-yielding
 * siblings then yielding ones. There should be no more than 1 yielding sibling.
 */
static const struct lysc_node *nb_op_sib_first(struct nb_op_yield_state *ys,
					       const struct lysc_node *parent)
{
	const struct lysc_node *sib = lysc_node_child(parent);
	const struct lysc_node *first_sib;

	/*
	 * NOTE: when we want to handle root level walks we will need to use
	 * lys_getnext() to walk root level of each module and
	 * ly_ctx_get_module_iter() to walk the modules.
	 */
	assert(darr_len(ys->node_infos) > 0);

	/*
	 * The top of the node stack points at @parent.
	 *
	 * If the schema path (original query) is longer than our current node
	 * info stack (current xpath location), we are building back up to the
	 * base of the user query, return the next schema node from the query
	 * string (schema_path).
	 */
	if (darr_last(ys->node_infos) != NULL &&
	    !CHECK_FLAG(darr_last(ys->node_infos)->schema->nodetype,
			LYS_CASE | LYS_CHOICE))
		assert(darr_last(ys->node_infos)->schema == parent);
	if (darr_lasti(ys->node_infos) < ys->query_base_level)
		return ys->schema_path[darr_lasti(ys->node_infos) + 1];

	/* We always skip keys. */
	while (sib && lysc_is_key(sib))
		sib = sib->next;
	if (!sib)
		return NULL;

	/* Return non-yielding node's first */
	first_sib = sib;
	if (__is_yielding_node(sib)) {
		sib = __sib_next(false, sib);
		if (sib)
			return sib;
	}
	return first_sib;
}

/*
 * "3-dimensional" walk from base of the tree to the tip in-order.
 *
 * The actual tree is only 2-dimensional as list nodes are organized as adjacent
 * siblings under a common parent perhaps with other siblings to each side;
 * however, using 3d view here is easier to diagram.
 *
 * - A list node is yielding if it has a lookup_next callback.
 * - All other node types are not yielding.
 * - There's only one yielding node in a list of children (i.e., siblings).
 *
 * We visit all non-yielding children prior to the yielding child.
 * That way we have the fullest tree possible even when something is deleted
 * during a yield.
 *                             --- child/parent descendant poinilnters
 *                             ... next/prev sibling pointers
 *                             o.o list entries pointers
 *                             ~~~ diagram extension connector
 *          1
 *         / \
 *        /   \         o~~~~12
 *       /     \      .      / \
 *      2.......5   o~~~9  13...14
 *     / \      | .    / \
 *    3...4     6    10...11      Cont Nodes: 1,2,5
 *             / \                List Nodes: 6,9,12
 *            7...8               Leaf Nodes: 3,4,7,8,10,11,13,14
 *                             Schema Leaf A: 3
 *                             Schema Leaf B: 4
 *                             Schema Leaf C: 7,10,13
 *                             Schema Leaf D: 8,11,14
 */
static enum nb_error __walk(struct nb_op_yield_state *ys, bool is_resume)
{
	const struct lysc_node *walk_stem_tip = ys_get_walk_stem_tip(ys);
	const struct lysc_node *sib;
	const void *parent_list_entry = NULL;
	const void *list_entry = NULL;
	struct nb_op_node_info *ni, *pni;
	struct lyd_node *node;
	struct nb_node *nn;
	char *xpath_child = NULL;
	// bool at_query_base;
	bool at_root_level, list_start, is_specific_node;
	enum nb_error ret = NB_OK;
	LY_ERR err;
	int at_clevel;
	uint len;


	monotime(&ys->start_time);

	/* Don't currently support walking all root nodes */
	if (!walk_stem_tip)
		return NB_ERR_NOT_FOUND;

	if (ys->schema_path[0]->nodetype == LYS_CHOICE) {
		flog_err(EC_LIB_NB_OPERATIONAL_DATA,
			 "%s: unable to walk root level choice node from module: %s",
			 __func__, ys->schema_path[0]->module->name);
		return NB_ERR;
	}

	/*
	 * If we are resuming then start with the list container on top.
	 * Otherwise get the first child of the container we are walking,
	 * starting with non-yielding children.
	 */
	if (is_resume)
		sib = darr_last(ys->node_infos)->schema;
	else {
		/*
		 * Start with non-yielding children first.
		 *
		 * When adding root level walks, the sibling list are the root
		 * level nodes of all modules
		 */
		sib = nb_op_sib_first(ys, walk_stem_tip);
		if (!sib)
			return NB_ERR_NOT_FOUND;
	}


	while (true) {
		/* Grab the top container/list node info on the stack */
		at_clevel = darr_lasti(ys->node_infos);
		ni = &ys->node_infos[at_clevel];

		/*
		 * This is the level of the last specific node at init
		 * time. +1 would be the first non-specific list or
		 * non-container if present in the container node.
		 */
		at_root_level = at_clevel == ys->walk_root_level;

		if (!sib) {
			/*
			 * We've reached the end of the siblings inside a
			 * containing node; either a container, case, choice, or
			 * a specific list node entry.
			 *
			 * We handle case/choice/container node inline; however,
			 * for lists we are only done with a specific entry and
			 * need to move to the next element on the list so we
			 * drop down into the switch for that case.
			 */

			/* Grab the containing node. */
			sib = ni->schema;

			if (CHECK_FLAG(sib->nodetype,
				       LYS_CASE | LYS_CHOICE | LYS_CONTAINER)) {
				/* If we added an empty container node (no
				 * children) and it's not a presence container
				 * or it's not backed by the get_elem callback,
				 * remove the node from the tree.
				 */
				if (sib->nodetype == LYS_CONTAINER &&
				    !lyd_child(ni->inner) &&
				    !nb_op_empty_container_ok(sib, ys->xpath,
							      ni->list_entry))
					ys_free_inner(ys, ni);

				/* If we have returned to our original walk base,
				 * then we are done with the walk.
				 */
				if (at_root_level) {
					ret = NB_OK;
					goto done;
				}
				/*
				 * Grab the sibling of the container we are
				 * about to pop, so we will be mid-walk on the
				 * parent containers children.
				 */
				sib = nb_op_sib_next(ys, sib);

				/* Pop container node to the parent container */
				ys_pop_inner(ys);

				/*
				 * If are were working on a user narrowed path
				 * then we are done with these siblings.
				 */
				if (darr_len(ys->schema_path) >
				    darr_len(ys->node_infos))
					sib = NULL;

				/* Start over */
				continue;
			}
			/*
			 * If we are here we have reached the end of the
			 * children of a list entry node. sib points
			 * at the list node info.
			 */
		}

		if (CHECK_FLAG(sib->nodetype,
			       LYS_LEAF | LYS_LEAFLIST | LYS_CONTAINER))
			xpath_child = nb_op_get_child_path(ys->xpath, sib,
							   xpath_child);
		else if (CHECK_FLAG(sib->nodetype, LYS_CASE | LYS_CHOICE))
			darr_in_strdup(xpath_child, ys->xpath);

		nn = sib->priv;

		switch (sib->nodetype) {
		case LYS_LEAF:
			/*
			 * If we have a non-specific walk to a specific leaf
			 * (e.g., "..../route-entry/metric") and the leaf value
			 * is not present, then we are left with the data nodes
			 * of the stem of the branch to the missing leaf data.
			 * For containers this will get cleaned up by the
			 * container code above that looks for no children;
			 * however, this doesn't work for lists.
			 *
			 * (FN:A) We need a similar check for empty list
			 * elements. Empty list elements below the
			 * query_base_level (i.e., the schema path length)
			 * should be cleaned up as they don't support anything
			 * the user is querying for, if they are above the
			 * query_base_level then they are part of the walk and
			 * should be kept.
			 */
			ret = nb_op_iter_leaf(ys, nn, xpath_child);
			if (ret != NB_OK)
				goto done;
			sib = nb_op_sib_next(ys, sib);
			continue;
		case LYS_LEAFLIST:
			ret = nb_op_iter_leaflist(ys, nn, xpath_child);
			if (ret != NB_OK)
				goto done;
			sib = nb_op_sib_next(ys, sib);
			continue;
		case LYS_CASE:
		case LYS_CHOICE:
		case LYS_CONTAINER:
			if (CHECK_FLAG(nn->flags, F_NB_NODE_CONFIG_ONLY)) {
				sib = nb_op_sib_next(ys, sib);
				continue;
			}

			if (sib->nodetype != LYS_CONTAINER) {
				/* Case/choice use parent inner. */
				/* TODO: thus we don't support root level choice */
				node = ni->inner;
			} else {
				err = lyd_new_inner(ni->inner, sib->module,
						    sib->name, false, &node);
				if (err) {
					ret = NB_ERR_RESOURCE;
					goto done;
				}
			}

			/* push this choice/container node on top of the stack */
			ni = darr_appendz(ys->node_infos);
			ni->inner = node;
			ni->schema = sib;
			ni->lookup_next_ok = ni[-1].lookup_next_ok;
			ni->list_entry = ni[-1].list_entry;

			darr_in_strdup(ys->xpath, xpath_child);
			ni->xpath_len = darr_strlen(ys->xpath);

			sib = nb_op_sib_first(ys, sib);
			continue;
		case LYS_LIST:

			/*
			 * Notes:
			 *
			 * NOTE: ni->inner may be NULL here if we resumed and it
			 * was gone. ni->schema and ni->keys will still be
			 * valid.
			 *
			 * NOTE: At this point sib is never NULL; however, if it
			 * was NULL at the top of the loop, then we were done
			 * working on a list element's children and will be
			 * attempting to get the next list element here so sib
			 * == ni->schema (i.e., !list_start).
			 *
			 * (FN:A): Before doing this let's remove empty list
			 * elements that are "inside" the query string as they
			 * represent a stem which didn't lead to actual data
			 * being requested by the user -- for example,
			 * ".../route-entry/metric" if metric is not present we
			 * don't want to return an empty route-entry to the
			 * user.
			 */

			node = NULL;
			list_start = ni->schema != sib;
			if (list_start) {
				/*
				 * List iteration: First Element
				 * -----------------------------
				 *
				 * Our node info wasn't on top (wasn't an entry
				 * for sib) so this is a new list iteration, we
				 * will push our node info below. The top is our
				 * parent.
				 */
				if (CHECK_FLAG(nn->flags,
					       F_NB_NODE_CONFIG_ONLY)) {
					sib = nb_op_sib_next(ys, sib);
					continue;
				}
				/* we are now at one level higher */
				at_clevel += 1;
				pni = ni;
				ni = NULL;
			} else {
				/*
				 * List iteration: Next Element
				 * ----------------------------
				 *
				 * This is the case where `sib == NULL` at the
				 * top of the loop, so, we just completed the
				 * walking the children of a list entry, i.e.,
				 * we are done with that list entry.
				 *
				 * `sib` was reset to point at the our list node
				 * at the top of node_infos.
				 *
				 * Within this node_info, `ys->xpath`, `inner`,
				 * `list_entry`, and `xpath_len` are for the
				 * previous list entry, and need to be updated.
				 */
				pni = darr_len(ys->node_infos) > 1 ? &ni[-1]
								   : NULL;
			}

			parent_list_entry = pni ? pni->list_entry : NULL;
			list_entry = ni ? ni->list_entry : NULL;

			/*
			 * Before yielding we check to see if we are doing a
			 * specific list entry instead of a full list iteration.
			 * We do not want to yield during specific list entry
			 * processing.
			 */

			/*
			 * If we are at a list start check to see if the node
			 * has a predicate. If so we will try and fetch the data
			 * node now that we've built part of the tree, if the
			 * predicates are keys or only depend on the tree already
			 * built, it should create the element for us.
			 */
			is_specific_node = false;
			if (list_start &&
			    at_clevel <= darr_lasti(ys->query_tokens) &&
			    !ys->non_specific_predicate[at_clevel] &&
			    nb_op_schema_path_has_predicate(ys, at_clevel)) {
				err = lyd_new_path(pni->inner, NULL,
						   ys->query_tokens[at_clevel],
						   NULL, 0, &node);
				if (!err)
					is_specific_node = true;
				else if (err == LY_EVALID)
					ys->non_specific_predicate[at_clevel] = true;
				else {
					flog_err(EC_LIB_NB_OPERATIONAL_DATA,
						  "%s: unable to create node for specific query string: %s: %s",
						  __func__,
						  ys->query_tokens[at_clevel],
						  yang_ly_strerrcode(err));
					ret = NB_ERR;
					goto done;
				}
			}

			if (list_entry && ni->query_specific_entry) {
				/*
				 * Ending specific list entry processing.
				 */
				assert(!list_start);
				is_specific_node = true;
				list_entry = NULL;
			}

			/*
			 * Should we yield?
			 *
			 * Don't yield if we have a specific entry.
			 */
			if (!is_specific_node && ni && ni->lookup_next_ok &&
			    // make sure we advance, if the interval is
			    // fast and we are very slow.
			    ((monotime_since(&ys->start_time, NULL) >
				      NB_OP_WALK_INTERVAL_US &&
			      ni->niters) ||
			     (ni->niters + 1) % 10000 == 0)) {
				/* This is a yield supporting list node and
				 * we've been running at least our yield
				 * interval, so yield.
				 *
				 * NOTE: we never yield on list_start, and we
				 * are always about to be doing a get_next.
				 */
				DEBUGD(&nb_dbg_events,
				       "%s: yielding after %u iterations",
				       __func__, ni->niters);

				ni->niters = 0;
				ret = NB_YIELD;
				goto done;
			}

			/*
			 * Now get the backend list_entry opaque object for
			 * this list entry from the backend.
			 */

			if (is_specific_node) {
				/*
				 * Specific List Entry:
				 * --------------------
				 */
				if (list_start) {
					list_entry =
						nb_callback_lookup_node_entry(
							node, parent_list_entry);
					/*
					 * If the node we created from a
					 * specific predicate entry is not
					 * actually there we need to delete the
					 * node from our data tree
					 */
					if (!list_entry) {
						lyd_free_tree(node);
						node = NULL;
					}
				}
			} else if (!list_start && !list_entry &&
				   ni->has_lookup_next) {
				/*
				 * After Yield:
				 * ------------
				 * After a yield the list_entry may have become
				 * invalid, so use lookup_next callback with
				 * parent and keys instead to find next element.
				 */
				list_entry =
					nb_callback_lookup_next(nn,
								parent_list_entry,
								&ni->keys);
			} else {
				/*
				 * Normal List Iteration:
				 * ----------------------
				 * Start (list_entry == NULL) or continue
				 * (list_entry != NULL) the list iteration.
				 */
				/* Obtain [next] list entry. */
				list_entry =
					nb_callback_get_next(nn,
							     parent_list_entry,
							     list_entry);
			}

			/*
			 * (FN:A) Reap empty list element? Check to see if we
			 * should reap an empty list element. We do this if the
			 * empty list element exists at or below the query base
			 * (i.e., it's not part of the walk, but a failed find
			 * on a more specific query e.g., for below the
			 * `route-entry` element for a query
			 * `.../route-entry/metric` where the list element had
			 * no metric value.
			 *
			 * However, if the user query is for a key of a list
			 * element, then when we reach that list element it will
			 * have no non-key children, check for this condition
			 * and do not reap if true.
			 */
			if (!list_start && ni->inner &&
			    !lyd_child_no_keys(ni->inner) &&
			    /* not the top element with a key match */
			    !((darr_ilen(ys->node_infos) ==
			       darr_ilen(ys->schema_path) - 1) &&
			      lysc_is_key((*darr_last(ys->schema_path)))) &&
			    /* is this at or below the base? */
			    darr_ilen(ys->node_infos) <= ys->query_base_level)
				ys_free_inner(ys, ni);


			if (!list_entry) {
				/*
				 * List Iteration Done
				 * -------------------
				 */

				/*
				 * Grab next sibling of the list node
				 */
				if (is_specific_node)
					sib = NULL;
				else
					sib = nb_op_sib_next(ys, sib);

				/*
				 * If we are at the walk root (base) level then
				 * that specifies a list and we are done iterating
				 * the list, so we are done with the walk entirely.
				 */
				if (!sib && at_clevel == ys->walk_root_level) {
					ret = NB_OK;
					goto done;
				}

				/*
				 * Pop the our list node info back to our
				 * parent.
				 *
				 * We only do this if we've already pushed a
				 * node for the current list schema. For
				 * `list_start` this hasn't happened yet, as
				 * would have happened below. So when list_start
				 * is true but list_entry if NULL we
				 * are processing an empty list.
				 */
				if (!list_start)
					ys_pop_inner(ys);

				/*
				 * We should never be below the walk root
				 */
				assert(darr_lasti(ys->node_infos) >=
				       ys->walk_root_level);

				/* Move on to the sibling of the list node */
				continue;
			}

			/*
			 * From here on, we have selected a new top node_info
			 * list entry (either newly pushed or replacing the
			 * previous entry in the walk), and we are filling in
			 * the details.
			 */

			if (list_start) {
				/*
				 * Starting iteration of a list type or
				 * processing a specific entry, push the list
				 * node_info on stack.
				 */
				ni = darr_appendz(ys->node_infos);
				pni = &ni[-1]; /* memory may have moved */
				ni->has_lookup_next = nn->cbs.lookup_next !=
						      NULL;
				ni->lookup_next_ok = ((!pni && ys->finish) ||
						      pni->lookup_next_ok) &&
						     ni->has_lookup_next;
				ni->query_specific_entry = is_specific_node;
				ni->niters = 0;
				ni->nents = 0;

				/* this will be our predicate-less xpath */
				ys->xpath = nb_op_get_child_path(ys->xpath, sib,
								 ys->xpath);
			} else {
				/*
				 * Reset our xpath to the list node (i.e.,
				 * remove the entry predicates)
				 */
				if (ni->query_specific_entry) {
					flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
						  "%s: unexpected state",
						  __func__);
				}
				assert(!ni->query_specific_entry);
				len = strlen(sib->name) + 1; /* "/sibname" */
				if (pni)
					len += pni->xpath_len;
				darr_setlen(ys->xpath, len + 1);
				ys->xpath[len] = 0;
				ni->xpath_len = len;
			}

			/* Need to get keys. */

			if (!CHECK_FLAG(nn->flags, F_NB_NODE_KEYLESS_LIST)) {
				ret = nb_callback_get_keys(nn, list_entry,
							   &ni->keys);
				if (ret) {
					darr_pop(ys->node_infos);
					ret = NB_ERR_RESOURCE;
					goto done;
				}
			}
			/*
			 * Append predicates to xpath.
			 */
			len = darr_strlen(ys->xpath);
			if (ni->keys.num) {
				yang_get_key_preds(ys->xpath + len, sib,
						   &ni->keys,
						   darr_cap(ys->xpath) - len);
			} else {
				/* add a position predicate (1s based?) */
				darr_ensure_avail(ys->xpath, 10);
				snprintf(ys->xpath + len,
					 darr_cap(ys->xpath) - len + 1, "[%u]",
					 ni->nents + 1);
			}
			darr_setlen(ys->xpath,
				    strlen(ys->xpath + len) + len + 1);
			ni->xpath_len = darr_strlen(ys->xpath);

			/*
			 * Create the new list entry node.
			 */

			if (!node) {
				err = yang_lyd_new_list((struct lyd_node_inner *)
								ni[-1]
									.inner,
							sib, &ni->keys, &node);
				if (err) {
					darr_pop(ys->node_infos);
					ret = NB_ERR_RESOURCE;
					goto done;
				}
			}

			/*
			 * Save the new list entry with the list node info
			 */
			ni->inner = node;
			ni->schema = node->schema;
			ni->list_entry = list_entry;
			ni->niters += 1;
			ni->nents += 1;

			/* Skip over the key children, they've been created. */
			sib = nb_op_sib_first(ys, sib);
			continue;

		default:
			/*FALLTHROUGH*/
		case LYS_ANYXML:
		case LYS_ANYDATA:
			/* These schema types are not currently handled */
			flog_warn(EC_LIB_NB_OPERATIONAL_DATA,
				  "%s: unsupported schema node type: %s",
				  __func__, lys_nodetype2str(sib->nodetype));
			sib = nb_op_sib_next(ys, sib);
			continue;
		}
	}

done:
	darr_free(xpath_child);
	return ret;
}

static void nb_op_walk_continue(struct event *thread)
{
	struct nb_op_yield_state *ys = EVENT_ARG(thread);
	enum nb_error ret = NB_OK;

	DEBUGD(&nb_dbg_cbs_state, "northbound oper-state: resuming %s",
	       ys->xpath);

	nb_op_resume_data_tree(ys);

	/* if we've popped past the walk start level we're done */
	if (darr_lasti(ys->node_infos) < ys->walk_root_level)
		goto finish;

	/* otherwise we are at a resumable node */
	assert(darr_last(ys->node_infos)->has_lookup_next);

	ret = __walk(ys, true);
	if (ret == NB_YIELD) {
		if (nb_op_yield(ys) != NB_OK) {
			if (ys->should_batch)
				goto stopped;
			else
				goto finish;
		}
		return;
	}
finish:
	(*ys->finish)(ys_root_node(ys), ys->finish_arg, ret);
stopped:
	nb_op_free_yield_state(ys, false);
}

static void __free_siblings(struct lyd_node *this)
{
	struct lyd_node *next, *sib;
	uint count = 0;

	LY_LIST_FOR_SAFE(lyd_first_sibling(this), next, sib)
	{
		if (lysc_is_key(sib->schema))
			continue;
		if (sib == this)
			continue;
		lyd_free_tree(sib);
		count++;
	}
	DEBUGD(&nb_dbg_events, "NB oper-state: deleted %u siblings", count);
}

/*
 * Trim Algorithm:
 *
 * Delete final lookup-next list node and subtree, leave stack slot with keys.
 *
 * Then walking up the stack, delete all siblings except:
 * 1. right-most container or list node (must be lookup-next by design)
 * 2. keys supporting existing parent list node.
 *
 * NOTE the topmost node on the stack will be the final lookup-nexxt list node,
 * as we only yield on lookup-next list nodes.
 *
 */
static void nb_op_trim_yield_state(struct nb_op_yield_state *ys)
{
	struct nb_op_node_info *ni;
	int i = darr_lasti(ys->node_infos);

	assert(i >= 0);

	DEBUGD(&nb_dbg_events, "NB oper-state: start trimming: top: %d", i);

	ni = &ys->node_infos[i];
	assert(ni->has_lookup_next);

	DEBUGD(&nb_dbg_events, "NB oper-state: deleting tree at level %d", i);
	__free_siblings(ni->inner);
	ys_free_inner(ys, ni);

	while (--i > 0) {
		DEBUGD(&nb_dbg_events,
		       "NB oper-state: deleting siblings at level: %d", i);
		__free_siblings(ys->node_infos[i].inner);
	}
	DEBUGD(&nb_dbg_events, "NB oper-state: stop trimming: new top: %d",
	       (int)darr_lasti(ys->node_infos));
}

static enum nb_error nb_op_yield(struct nb_op_yield_state *ys)
{
	enum nb_error ret;
	unsigned long min_us = MAX(1, NB_OP_WALK_INTERVAL_US / 50000);
	struct timeval tv = { .tv_sec = 0, .tv_usec = min_us };

	DEBUGD(&nb_dbg_events, "NB oper-state: yielding %s for %lus (should_batch %d)",
	       ys->xpath, tv.tv_usec, ys->should_batch);

	if (ys->should_batch) {
		/*
		 * TODO: add ability of finish to influence the timer.
		 * This will allow, for example, flow control based on how long
		 * it takes finish to process the batch.
		 */
		ret = (*ys->finish)(ys_root_node(ys), ys->finish_arg, NB_YIELD);
		if (ret != NB_OK)
			return ret;
		/* now trim out that data we just "finished" */
		nb_op_trim_yield_state(ys);

	}

	event_add_timer_tv(event_loop, nb_op_walk_continue, ys, &tv,
			   &ys->walk_ev);
	return NB_OK;
}

static enum nb_error nb_op_ys_init_schema_path(struct nb_op_yield_state *ys,
					       struct nb_node **last)
{
	struct nb_node **nb_nodes = NULL;
	const struct lysc_node *sn;
	struct nb_node *nblast;
	char *s, *s2;
	int count;
	uint i;

	/*
	 * Get the schema node stack for the entire query string
	 *
	 * The user might pass in something like "//metric" which may resolve to
	 * more than one schema node ("trunks"). nb_node_find() returns a single
	 * node though. We should expand the functionality to get the set of
	 * nodes that matches the xpath (not path) query and save that set in
	 * the yield state. Then we should do a walk using the users query
	 * string over each schema trunk in the set.
	 */
	nblast = nb_node_find(ys->xpath);
	if (!nblast) {
		nb_nodes = nb_nodes_find(ys->xpath);
		nblast = darr_len(nb_nodes) ? nb_nodes[0] : NULL;
		darr_free(nb_nodes);
	}
	if (!nblast) {
		flog_warn(EC_LIB_YANG_UNKNOWN_DATA_PATH,
			  "%s: unknown data path: %s", __func__, ys->xpath);
		return NB_ERR;
	}
	*last = nblast;

	/*
	 * Create a stack of schema nodes one element per node in the query
	 * path, only the top (last) element may be a non-container type.
	 *
	 * NOTE: appears to be a bug in nb_node linkage where parent can be NULL,
	 * or I'm misunderstanding the code, in any case we use the libyang
	 * linkage to walk which works fine.
	 *
	 * XXX: we don't actually support choice/case yet, they are container
	 * types in the libyang schema, but won't be in data so our length
	 * checking gets messed up.
	 */
	for (sn = nblast->snode, count = 0; sn; count++, sn = sn->parent)
		if (sn != nblast->snode)
			assert(CHECK_FLAG(sn->nodetype,
					  LYS_CONTAINER | LYS_LIST |
						  LYS_CHOICE | LYS_CASE));
	/* create our arrays */
	darr_append_n(ys->schema_path, count);
	darr_append_n(ys->query_tokens, count);
	darr_append_nz(ys->non_specific_predicate, count);
	for (sn = nblast->snode; sn; sn = sn->parent)
		ys->schema_path[--count] = sn;

	/*
	 * Now tokenize the query string and get pointers to each token
	 */

	/* Get copy of query string start after initial '/'s */
	s = ys->xpath;
	while (*s && *s == '/')
		s++;
	ys->query_tokstr = darr_strdup(s);
	s = ys->query_tokstr;

	darr_foreach_i (ys->schema_path, i) {
		const char *modname = ys->schema_path[i]->module->name;
		const char *name = ys->schema_path[i]->name;
		int nlen = strlen(name);
		int mnlen = 0;

		/*
		 * Technically the query_token for choice/case should probably be pointing at
		 * the child (leaf) rather than the parent (container), however,
		 * we only use these for processing list nodes so KISS.
		 */
		if (CHECK_FLAG(ys->schema_path[i]->nodetype,
			       LYS_CASE | LYS_CHOICE)) {
			ys->query_tokens[i] = ys->query_tokens[i - 1];
			continue;
		}

		while (true) {
			s2 = strstr(s, name);
			if (!s2)
				goto error;

			if (s2[-1] == ':') {
				mnlen = strlen(modname) + 1;
				if (ys->query_tokstr > s2 - mnlen ||
				    strncmp(s2 - mnlen, modname, mnlen - 1))
					goto error;
				s2 -= mnlen;
				nlen += mnlen;
			}

			s = s2;
			if ((i == 0 || s[-1] == '/') &&
			    (s[nlen] == 0 || s[nlen] == '[' || s[nlen] == '/'))
				break;
			/*
			 * Advance past the incorrect match, must have been
			 * part of previous predicate.
			 */
			s += nlen;
		}

		/* NUL terminate previous token and save this one */
		if (i > 0)
			s[-1] = 0;
		ys->query_tokens[i] = s;
		s += nlen;
	}

	/* NOTE: need to subtract choice/case nodes when these are supported */
	ys->query_base_level = darr_lasti(ys->schema_path);

	return NB_OK;

error:
	darr_free(ys->query_tokstr);
	darr_free(ys->schema_path);
	darr_free(ys->query_tokens);
	darr_free(ys->non_specific_predicate);
	return NB_ERR;
}


/**
 * nb_op_walk_start() - Start walking oper-state directed by query string.
 * @ys: partially initialized yield state for this walk.
 *
 */
static enum nb_error nb_op_walk_start(struct nb_op_yield_state *ys)
{
	struct nb_node *nblast;
	enum nb_error ret;

	/*
	 * Get nb_node path (stack) corresponding to the xpath query
	 */
	ret = nb_op_ys_init_schema_path(ys, &nblast);
	if (ret != NB_OK)
		return ret;


	/*
	 * Get the node_info path (stack) corresponding to the uniquely
	 * resolvable data nodes from the beginning of the xpath query.
	 */
	ret = nb_op_ys_init_node_infos(ys);
	if (ret != NB_OK)
		return ret;

	return __walk(ys, false);
}


void *nb_oper_walk(const char *xpath, struct yang_translator *translator,
		   uint32_t flags, bool should_batch, nb_oper_data_cb cb,
		   void *cb_arg, nb_oper_data_finish_cb finish, void *finish_arg)
{
	struct nb_op_yield_state *ys;
	enum nb_error ret;

	ys = nb_op_create_yield_state(xpath, translator, flags, should_batch,
				      cb, cb_arg, finish, finish_arg);

	ret = nb_op_walk_start(ys);
	if (ret == NB_YIELD) {
		if (nb_op_yield(ys) != NB_OK) {
			if (ys->should_batch)
				goto stopped;
			else
				goto finish;
		}
		return ys;
	}
finish:
	(void)(*ys->finish)(ys_root_node(ys), ys->finish_arg, ret);
stopped:
	nb_op_free_yield_state(ys, false);
	return NULL;
}


void nb_oper_cancel_walk(void *walk)
{
	if (walk)
		nb_op_free_yield_state(walk, false);
}


void nb_oper_cancel_all_walks(void)
{
	struct nb_op_yield_state *ys;

	frr_each_safe (nb_op_walks, &nb_op_walks, ys)
		nb_oper_cancel_walk(ys);
}


/*
 * The old API -- remove when we've update the users to yielding.
 */
enum nb_error nb_oper_iterate_legacy(const char *xpath,
				     struct yang_translator *translator,
				     uint32_t flags, nb_oper_data_cb cb,
				     void *cb_arg, struct lyd_node **tree)
{
	struct nb_op_yield_state *ys;
	enum nb_error ret;

	ys = nb_op_create_yield_state(xpath, translator, flags, false, cb,
				      cb_arg, NULL, NULL);

	ret = nb_op_walk_start(ys);
	assert(ret != NB_YIELD);

	if (tree && ret == NB_OK)
		*tree = ys_root_node(ys);
	else {
		if (ys_root_node(ys))
			yang_dnode_free(ys_root_node(ys));
		if (tree)
			*tree = NULL;
	}

	nb_op_free_yield_state(ys, true);
	return ret;
}

void nb_oper_init(struct event_loop *loop)
{
	event_loop = loop;
	nb_op_walks_init(&nb_op_walks);
}

void nb_oper_terminate(void)
{
	nb_oper_cancel_all_walks();
}
