// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol                  - isis_spf.c
 *                                              The SPT algorithm
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2017        Christian Franke <chris@opensourcerouting.org>
 */

#include <zebra.h>

#include "frrevent.h"
#include "linklist.h"
#include "vty.h"
#include "log.h"
#include "command.h"
#include "termtable.h"
#include "memory.h"
#include "prefix.h"
#include "filter.h"
#include "if.h"
#include "hash.h"
#include "table.h"
#include "spf_backoff.h"
#include "srcdest_table.h"
#include "vrf.h"
#include "lib/json.h"

#include "isis_errors.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_pdu.h"
#include "isis_lsp.h"
#include "isis_dynhn.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_csm.h"
#include "isis_mt.h"
#include "isis_tlvs.h"
#include "isis_flex_algo.h"
#include "isis_zebra.h"
#include "fabricd.h"
#include "isis_spf_private.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_SPFTREE,    "ISIS SPFtree");
DEFINE_MTYPE_STATIC(ISISD, ISIS_SPF_RUN,    "ISIS SPF Run Info");
DEFINE_MTYPE_STATIC(ISISD, ISIS_SPF_ADJ,    "ISIS SPF Adjacency");
DEFINE_MTYPE_STATIC(ISISD, ISIS_VERTEX,     "ISIS vertex");
DEFINE_MTYPE_STATIC(ISISD, ISIS_VERTEX_ADJ, "ISIS SPF Vertex Adjacency");

static void spf_adj_list_parse_lsp(struct isis_spftree *spftree,
				   struct list *adj_list, struct isis_lsp *lsp,
				   const uint8_t *pseudo_nodeid,
				   uint32_t pseudo_metric);

/*
 *  supports the given af ?
 */
static bool speaks(uint8_t *protocols, uint8_t count, int family)
{
	for (uint8_t i = 0; i < count; i++) {
		if (family == AF_INET && protocols[i] == NLPID_IP)
			return true;
		if (family == AF_INET6 && protocols[i] == NLPID_IPV6)
			return true;
	}
	return false;
}

struct isis_spf_run {
	struct isis_area *area;
	int level;
};

/* 7.2.7 */
static void remove_excess_adjs(struct list *adjs)
{
	struct listnode *node, *excess = NULL;
	struct isis_vertex_adj *vadj, *candidate = NULL;
	int comp;

	for (ALL_LIST_ELEMENTS_RO(adjs, node, vadj)) {
		struct isis_adjacency *adj, *candidate_adj;

		adj = vadj->sadj->adj;
		assert(adj);

		if (excess == NULL)
			excess = node;
		candidate = listgetdata(excess);
		candidate_adj = candidate->sadj->adj;

		if (candidate_adj->sys_type < adj->sys_type) {
			excess = node;
			continue;
		}
		if (candidate_adj->sys_type > adj->sys_type)
			continue;

		comp = memcmp(candidate_adj->sysid, adj->sysid,
			      ISIS_SYS_ID_LEN);
		if (comp > 0) {
			excess = node;
			continue;
		}
		if (comp < 0)
			continue;

		if (candidate_adj->circuit->idx > adj->circuit->idx) {
			excess = node;
			continue;
		}

		if (candidate_adj->circuit->idx < adj->circuit->idx)
			continue;

		comp = memcmp(candidate_adj->snpa, adj->snpa, ETH_ALEN);
		if (comp > 0) {
			excess = node;
			continue;
		}
	}

	list_delete_node(adjs, excess);

	return;
}

const char *vtype2string(enum vertextype vtype)
{
	switch (vtype) {
	case VTYPE_PSEUDO_IS:
		return "pseudo_IS";
	case VTYPE_PSEUDO_TE_IS:
		return "pseudo_TE-IS";
	case VTYPE_NONPSEUDO_IS:
		return "IS";
	case VTYPE_NONPSEUDO_TE_IS:
		return "TE-IS";
	case VTYPE_ES:
		return "ES";
	case VTYPE_IPREACH_INTERNAL:
		return "IP internal";
	case VTYPE_IPREACH_EXTERNAL:
		return "IP external";
	case VTYPE_IPREACH_TE:
		return "IP TE";
	case VTYPE_IP6REACH_INTERNAL:
		return "IP6 internal";
	case VTYPE_IP6REACH_EXTERNAL:
		return "IP6 external";
	default:
		return "UNKNOWN";
	}
	return NULL; /* Not reached */
}

const char *vid2string(const struct isis_vertex *vertex, char *buff, int size)
{
	if (VTYPE_IS(vertex->type) || VTYPE_ES(vertex->type)) {
		const char *hostname = print_sys_hostname(vertex->N.id);
		strlcpy(buff, hostname, size);
		return buff;
	}

	if (VTYPE_IP(vertex->type)) {
		srcdest2str(&vertex->N.ip.p.dest, &vertex->N.ip.p.src, buff,
			    size);
		return buff;
	}

	return "UNKNOWN";
}

static bool prefix_sid_cmp(const void *value1, const void *value2)
{
	const struct isis_vertex *c1 = value1;
	const struct isis_vertex *c2 = value2;

	if (CHECK_FLAG(c1->N.ip.sr.sid.flags,
		       ISIS_PREFIX_SID_VALUE | ISIS_PREFIX_SID_LOCAL)
	    != CHECK_FLAG(c2->N.ip.sr.sid.flags,
			  ISIS_PREFIX_SID_VALUE | ISIS_PREFIX_SID_LOCAL))
		return false;

	return c1->N.ip.sr.sid.value == c2->N.ip.sr.sid.value;
}

static unsigned int prefix_sid_key_make(const void *value)
{
	const struct isis_vertex *vertex = value;

	return jhash_1word(vertex->N.ip.sr.sid.value, 0);
}

struct isis_vertex *isis_spf_prefix_sid_lookup(struct isis_spftree *spftree,
					       struct isis_prefix_sid *psid)
{
	struct isis_vertex lookup = {};

	lookup.N.ip.sr.sid = *psid;
	return hash_lookup(spftree->prefix_sids, &lookup);
}

void isis_vertex_adj_free(void *arg)
{
	struct isis_vertex_adj *vadj = arg;

	XFREE(MTYPE_ISIS_VERTEX_ADJ, vadj);
}

static struct isis_vertex *isis_vertex_new(struct isis_spftree *spftree,
					   void *id,
					   enum vertextype vtype)
{
	struct isis_vertex *vertex;

	vertex = XCALLOC(MTYPE_ISIS_VERTEX, sizeof(struct isis_vertex));

	isis_vertex_id_init(vertex, id, vtype);

	vertex->Adj_N = list_new();
	vertex->Adj_N->del = isis_vertex_adj_free;
	vertex->parents = list_new();

	if (CHECK_FLAG(spftree->flags, F_SPFTREE_HOPCOUNT_METRIC)) {
		vertex->firsthops = hash_create(isis_vertex_queue_hash_key,
						isis_vertex_queue_hash_cmp,
						NULL);
	}

	return vertex;
}

void isis_vertex_del(struct isis_vertex *vertex)
{
	list_delete(&vertex->Adj_N);
	list_delete(&vertex->parents);
	hash_clean_and_free(&vertex->firsthops, NULL);

	memset(vertex, 0, sizeof(struct isis_vertex));
	XFREE(MTYPE_ISIS_VERTEX, vertex);
}

struct isis_vertex_adj *
isis_vertex_adj_add(struct isis_spftree *spftree, struct isis_vertex *vertex,
		    struct list *vadj_list, struct isis_spf_adj *sadj,
		    struct isis_prefix_sid *psid, bool last_hop)
{
	struct isis_vertex_adj *vadj;

	vadj = XCALLOC(MTYPE_ISIS_VERTEX_ADJ, sizeof(*vadj));
	vadj->sadj = sadj;
	if (spftree->area->srdb.enabled && psid) {
		if (vertex->N.ip.sr.present
		    && vertex->N.ip.sr.sid.value != psid->value)
			zlog_warn(
				"ISIS-SPF: ignoring different Prefix-SID for route %pFX",
				&vertex->N.ip.p.dest);
		else {
			vadj->sr.sid = *psid;
			vadj->sr.label = sr_prefix_out_label(
				spftree->lspdb, vertex->N.ip.p.dest.family,
				psid, sadj->id, last_hop);
			if (vadj->sr.label != MPLS_INVALID_LABEL)
				vadj->sr.present = true;
		}
	}
	listnode_add(vadj_list, vadj);

	return vadj;
}

static void isis_vertex_adj_del(struct isis_vertex *vertex,
				struct isis_adjacency *adj)
{
	struct isis_vertex_adj *vadj;
	struct listnode *node, *nextnode;

	if (!vertex)
		return;

	for (ALL_LIST_ELEMENTS(vertex->Adj_N, node, nextnode, vadj)) {
		if (vadj->sadj->adj == adj) {
			listnode_delete(vertex->Adj_N, vadj);
			isis_vertex_adj_free(vadj);
		}
	}
	return;
}

bool isis_vertex_adj_exists(const struct isis_spftree *spftree,
			    const struct isis_vertex *vertex,
			    const struct isis_spf_adj *sadj)
{
	struct isis_vertex_adj *tmp;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(vertex->Adj_N, node, tmp)) {
		if (CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ADJACENCIES)) {
			if (memcmp(sadj->id, tmp->sadj->id, sizeof(sadj->id))
			    == 0)
				return true;
		} else {
			if (sadj->adj == tmp->sadj->adj)
				return true;
		}
	}

	return false;
}

static void isis_spf_adj_free(void *arg)
{
	struct isis_spf_adj *sadj = arg;

	XFREE(MTYPE_ISIS_SPF_ADJ, sadj);
}

static void _isis_spftree_init(struct isis_spftree *tree)
{
	isis_vertex_queue_init(&tree->tents, "IS-IS SPF tents", true);
	isis_vertex_queue_init(&tree->paths, "IS-IS SPF paths", false);
	tree->route_table = srcdest_table_init();
	tree->route_table->cleanup = isis_route_node_cleanup;
	tree->route_table->info = isis_route_table_info_alloc(tree->algorithm);
	tree->route_table_backup = srcdest_table_init();
	tree->route_table_backup->info =
		isis_route_table_info_alloc(tree->algorithm);
	tree->route_table_backup->cleanup = isis_route_node_cleanup;
	tree->prefix_sids = hash_create(prefix_sid_key_make, prefix_sid_cmp,
					"SR Prefix-SID Entries");
	tree->sadj_list = list_new();
	tree->sadj_list->del = isis_spf_adj_free;
	isis_rlfa_list_init(tree);
	tree->lfa.remote.pc_spftrees = list_new();
	tree->lfa.remote.pc_spftrees->del = (void (*)(void *))isis_spftree_del;
	if (tree->type == SPF_TYPE_RLFA || tree->type == SPF_TYPE_TI_LFA) {
		isis_spf_node_list_init(&tree->lfa.p_space);
		isis_spf_node_list_init(&tree->lfa.q_space);
	}
}

struct isis_spftree *
isis_spftree_new(struct isis_area *area, struct lspdb_head *lspdb,
		 const uint8_t *sysid, int level, enum spf_tree_id tree_id,
		 enum spf_type type, uint8_t flags, uint8_t algorithm)
{
	struct isis_spftree *tree;

	tree = XCALLOC(MTYPE_ISIS_SPFTREE, sizeof(struct isis_spftree));

	tree->area = area;
	tree->lspdb = lspdb;
	tree->last_run_timestamp = 0;
	tree->last_run_monotime = 0;
	tree->last_run_duration = 0;
	tree->runcount = 0;
	tree->type = type;
	memcpy(tree->sysid, sysid, ISIS_SYS_ID_LEN);
	tree->level = level;
	tree->tree_id = tree_id;
	tree->family = (tree->tree_id == SPFTREE_IPV4) ? AF_INET : AF_INET6;
	tree->flags = flags;
	tree->algorithm = algorithm;

	_isis_spftree_init(tree);

	return tree;
}

static void _isis_spftree_del(struct isis_spftree *spftree)
{
	void *info, *backup_info;

	hash_clean_and_free(&spftree->prefix_sids, NULL);
	isis_zebra_rlfa_unregister_all(spftree);
	isis_rlfa_list_clear(spftree);
	list_delete(&spftree->lfa.remote.pc_spftrees);
	if (spftree->type == SPF_TYPE_RLFA
	    || spftree->type == SPF_TYPE_TI_LFA) {
		isis_spf_node_list_clear(&spftree->lfa.q_space);
		isis_spf_node_list_clear(&spftree->lfa.p_space);
	}
	isis_spf_node_list_clear(&spftree->adj_nodes);
	list_delete(&spftree->sadj_list);
	isis_vertex_queue_free(&spftree->tents);
	isis_vertex_queue_free(&spftree->paths);
	info =  spftree->route_table->info;
	backup_info = spftree->route_table_backup->info;
	route_table_finish(spftree->route_table);
	route_table_finish(spftree->route_table_backup);
	isis_route_table_info_free(info);
	isis_route_table_info_free(backup_info);
}

void isis_spftree_del(struct isis_spftree *spftree)
{
	_isis_spftree_del(spftree);

	spftree->route_table = NULL;

	XFREE(MTYPE_ISIS_SPFTREE, spftree);
	return;
}

#ifndef FABRICD
static void isis_spftree_clear(struct isis_spftree *spftree)
{
	_isis_spftree_del(spftree);
	_isis_spftree_init(spftree);
}
#endif /* ifndef FABRICD */

static void isis_spftree_adj_del(struct isis_spftree *spftree,
				 struct isis_adjacency *adj)
{
	struct listnode *node;
	struct isis_vertex *v;
	if (!adj)
		return;
	assert(!isis_vertex_queue_count(&spftree->tents));
	for (ALL_QUEUE_ELEMENTS_RO(&spftree->paths, node, v))
		isis_vertex_adj_del(v, adj);
	return;
}

void spftree_area_init(struct isis_area *area)
{
	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			if (!(area->is_type & level))
				continue;
			if (area->spftree[tree][level - 1])
				continue;

			area->spftree[tree][level - 1] = isis_spftree_new(
				area, &area->lspdb[level - 1],
				area->isis->sysid, level, tree,
				SPF_TYPE_FORWARD, 0, SR_ALGORITHM_SPF);
		}
	}
}

void spftree_area_del(struct isis_area *area)
{
	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			if (!(area->is_type & level))
				continue;
			if (!area->spftree[tree][level - 1])
				continue;

			isis_spftree_del(area->spftree[tree][level - 1]);
		}
	}
}

static int spf_adj_state_change(struct isis_adjacency *adj)
{
	struct isis_area *area = adj->circuit->area;

	if (adj->adj_state == ISIS_ADJ_UP)
		return 0;

	/* Remove adjacency from all SPF trees. */
	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			if (!(area->is_type & level))
				continue;
			if (!area->spftree[tree][level - 1])
				continue;
			isis_spftree_adj_del(area->spftree[tree][level - 1],
					     adj);
		}
	}

	if (fabricd_spftree(area) != NULL)
		isis_spftree_adj_del(fabricd_spftree(area), adj);

	return 0;
}

/*
 * Find the system LSP: returns the LSP in our LSP database
 * associated with the given system ID.
 */
struct isis_lsp *isis_root_system_lsp(struct lspdb_head *lspdb,
				      const uint8_t *sysid)
{
	struct isis_lsp *lsp;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2];

	memcpy(lspid, sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(lspid) = 0;
	LSP_FRAGMENT(lspid) = 0;
	lsp = lsp_search(lspdb, lspid);
	if (lsp && lsp->hdr.rem_lifetime != 0)
		return lsp;
	return NULL;
}

/*
 * Add this IS to the root of SPT
 */
static struct isis_vertex *isis_spf_add_root(struct isis_spftree *spftree)
{
	struct isis_vertex *vertex;
#ifdef EXTREME_DEBUG
	char buff[VID2STR_BUFFER];
#endif /* EXTREME_DEBUG */

	vertex = isis_vertex_new(spftree, spftree->sysid,
				 spftree->area->oldmetric
					 ? VTYPE_NONPSEUDO_IS
					 : VTYPE_NONPSEUDO_TE_IS);
	isis_vertex_queue_append(&spftree->paths, vertex);

#ifdef EXTREME_DEBUG
	if (IS_DEBUG_SPF_EVENTS)
		zlog_debug(
			"ISIS-SPF: A:%hhu added this IS %s %s depth %d dist %d to PATHS",
			spftree->algorithm, vtype2string(vertex->type),
			vid2string(vertex, buff, sizeof(buff)), vertex->depth,
			vertex->d_N);
#endif /* EXTREME_DEBUG */

	return vertex;
}

static void vertex_add_parent_firsthop(struct hash_bucket *bucket, void *arg)
{
	struct isis_vertex *vertex = arg;
	struct isis_vertex *hop = bucket->data;

	(void)hash_get(vertex->firsthops, hop, hash_alloc_intern);
}

static void vertex_update_firsthops(struct isis_vertex *vertex,
				    struct isis_vertex *parent)
{
	if (vertex->d_N <= 2)
		(void)hash_get(vertex->firsthops, vertex, hash_alloc_intern);

	if (vertex->d_N < 2 || !parent)
		return;

	hash_iterate(parent->firsthops, vertex_add_parent_firsthop, vertex);
}

/*
 * Add a vertex to TENT sorted by cost and by vertextype on tie break situation
 */
static struct isis_vertex *
isis_spf_add2tent(struct isis_spftree *spftree, enum vertextype vtype, void *id,
		  uint32_t cost, int depth, struct isis_spf_adj *sadj,
		  struct isis_prefix_sid *psid, struct isis_vertex *parent)
{
	struct isis_vertex *vertex;
	struct listnode *node;
	bool last_hop;
	char buff[VID2STR_BUFFER];

	vertex = isis_find_vertex(&spftree->paths, id, vtype);
	if (vertex != NULL) {
		zlog_err(
			"%s: vertex %s of type %s already in PATH; check for sysId collisions with established neighbors",
			__func__, vid2string(vertex, buff, sizeof(buff)),
			vtype2string(vertex->type));
		return NULL;
	}
	vertex = isis_find_vertex(&spftree->tents, id, vtype);
	if (vertex != NULL) {
		zlog_err(
			"%s: vertex %s of type %s already in TENT; check for sysId collisions with established neighbors",
			__func__, vid2string(vertex, buff, sizeof(buff)),
			vtype2string(vertex->type));
		return NULL;
	}

	vertex = isis_vertex_new(spftree, id, vtype);
	vertex->d_N = cost;
	vertex->depth = depth;
	if (VTYPE_IP(vtype) && spftree->area->srdb.enabled && psid) {
		struct isis_area *area = spftree->area;
		struct isis_vertex *vertex_psid;

		/*
		 * Check if the Prefix-SID is already in use by another prefix.
		 */
		vertex_psid = isis_spf_prefix_sid_lookup(spftree, psid);
		if (vertex_psid
		    && !prefix_same(&vertex_psid->N.ip.p.dest,
				    &vertex->N.ip.p.dest)) {
			flog_warn(
				EC_ISIS_SID_COLLISION,
				"ISIS-Sr (%s): collision detected, prefixes %pFX and %pFX share the same SID %s (%u)",
				area->area_tag, &vertex->N.ip.p.dest,
				&vertex_psid->N.ip.p.dest,
				CHECK_FLAG(psid->flags, ISIS_PREFIX_SID_VALUE)
					? "label"
					: "index",
				psid->value);
			psid = NULL;
		} else {
			bool local;

			local = (vertex->depth == 1);
			vertex->N.ip.sr.sid = *psid;
			vertex->N.ip.sr.label =
				sr_prefix_in_label(area, psid, local);
			vertex->N.ip.sr.algorithm = psid->algorithm;

			if (vertex->N.ip.sr.label != MPLS_INVALID_LABEL)
				vertex->N.ip.sr.present = true;

#ifndef FABRICD
			if (flex_algo_id_valid(spftree->algorithm) &&
			    !isis_flex_algo_elected_supported(
				    spftree->algorithm, spftree->area)) {
				vertex->N.ip.sr.present = false;
				vertex->N.ip.sr.label = MPLS_INVALID_LABEL;
			}
#endif /* ifndef FABRICD */

			(void)hash_get(spftree->prefix_sids, vertex,
				       hash_alloc_intern);
		}
	}

	if (parent) {
		listnode_add(vertex->parents, parent);
	}

	if (CHECK_FLAG(spftree->flags, F_SPFTREE_HOPCOUNT_METRIC))
		vertex_update_firsthops(vertex, parent);

	last_hop = (vertex->depth == 2);
	if (parent && parent->Adj_N && listcount(parent->Adj_N) > 0) {
		struct isis_vertex_adj *parent_vadj;

		for (ALL_LIST_ELEMENTS_RO(parent->Adj_N, node, parent_vadj))
			isis_vertex_adj_add(spftree, vertex, vertex->Adj_N,
					    parent_vadj->sadj, psid, last_hop);
	} else if (sadj) {
		isis_vertex_adj_add(spftree, vertex, vertex->Adj_N, sadj, psid,
				    last_hop);
	}

#ifdef EXTREME_DEBUG
	if (IS_DEBUG_SPF_EVENTS)
		zlog_debug(
			"ISIS-SPF: A:%hhu add to TENT %s %s %s depth %d dist %d adjcount %d",
			spftree->algorithm, print_sys_hostname(vertex->N.id),
			vtype2string(vertex->type),
			vid2string(vertex, buff, sizeof(buff)), vertex->depth,
			vertex->d_N, listcount(vertex->Adj_N));
#endif /* EXTREME_DEBUG */

	isis_vertex_queue_insert(&spftree->tents, vertex);
	return vertex;
}

static void isis_spf_add_local(struct isis_spftree *spftree,
			       enum vertextype vtype, void *id,
			       struct isis_spf_adj *sadj, uint32_t cost,
			       struct isis_prefix_sid *psid,
			       struct isis_vertex *parent)
{
	struct isis_vertex *vertex;

	vertex = isis_find_vertex(&spftree->tents, id, vtype);

	if (vertex) {
		/* C.2.5   c) */
		if (vertex->d_N == cost) {
			if (sadj) {
				bool last_hop = (vertex->depth == 2);

				isis_vertex_adj_add(spftree, vertex,
						    vertex->Adj_N, sadj, psid,
						    last_hop);
			}
			/*       d) */
			if (!CHECK_FLAG(spftree->flags,
					F_SPFTREE_NO_ADJACENCIES)
			    && listcount(vertex->Adj_N) > ISIS_MAX_PATH_SPLITS)
				remove_excess_adjs(vertex->Adj_N);
			if (parent && (listnode_lookup(vertex->parents, parent)
				       == NULL))
				listnode_add(vertex->parents, parent);
			return;
		} else if (vertex->d_N < cost) {
			/*       e) do nothing */
			return;
		} else { /* vertex->d_N > cost */
			/*         f) */
			isis_vertex_queue_delete(&spftree->tents, vertex);
			hash_release(spftree->prefix_sids, vertex);
			isis_vertex_del(vertex);
		}
	}

	isis_spf_add2tent(spftree, vtype, id, cost, 1, sadj, psid, parent);
	return;
}

static void process_N(struct isis_spftree *spftree, enum vertextype vtype,
		      void *id, uint32_t dist, uint16_t depth,
		      struct isis_prefix_sid *psid, struct isis_vertex *parent)
{
	struct isis_vertex *vertex;
#ifdef EXTREME_DEBUG
	char buff[VID2STR_BUFFER];
#endif

	assert(spftree && parent);

	if (CHECK_FLAG(spftree->flags, F_SPFTREE_HOPCOUNT_METRIC)
	    && !VTYPE_IS(vtype))
		return;

	struct prefix_pair p;
	if (vtype >= VTYPE_IPREACH_INTERNAL) {
		memcpy(&p, id, sizeof(p));
		apply_mask(&p.dest);
		apply_mask(&p.src);
		id = &p;
	}

	/* RFC3787 section 5.1 */
	if (spftree->area->newmetric == 1) {
		if (dist > MAX_WIDE_PATH_METRIC)
			return;
	}
	/* C.2.6 b)    */
	else if (spftree->area->oldmetric == 1) {
		if (dist > MAX_NARROW_PATH_METRIC)
			return;
	}

	/*       c)    */
	vertex = isis_find_vertex(&spftree->paths, id, vtype);
	if (vertex) {
#ifdef EXTREME_DEBUG
		if (IS_DEBUG_SPF_EVENTS)
			zlog_debug(
				"ISIS-SPF: A:%hhu process_N %s %s %s dist %d already found from PATH",
				spftree->algorithm,
				print_sys_hostname(vertex->N.id),
				vtype2string(vtype),
				vid2string(vertex, buff, sizeof(buff)), dist);
#endif /* EXTREME_DEBUG */
		assert(dist >= vertex->d_N);
		return;
	}

	vertex = isis_find_vertex(&spftree->tents, id, vtype);
	/*       d)    */
	if (vertex) {
/*        1) */
#ifdef EXTREME_DEBUG
		if (IS_DEBUG_SPF_EVENTS)
			zlog_debug(
				"ISIS-SPF: A:%hhu process_N %s %s %s dist %d parent %s adjcount %d",
				spftree->algorithm,
				print_sys_hostname(vertex->N.id),
				vtype2string(vtype),
				vid2string(vertex, buff, sizeof(buff)), dist,
				(parent ? print_sys_hostname(parent->N.id)
					: "null"),
				(parent ? listcount(parent->Adj_N) : 0));
#endif /* EXTREME_DEBUG */
		if (vertex->d_N == dist) {
			struct listnode *node;
			struct isis_vertex_adj *parent_vadj;
			for (ALL_LIST_ELEMENTS_RO(parent->Adj_N, node,
						  parent_vadj))
				if (!isis_vertex_adj_exists(
					    spftree, vertex,
					    parent_vadj->sadj)) {
					bool last_hop = (vertex->depth == 2);

					isis_vertex_adj_add(spftree, vertex,
							    vertex->Adj_N,
							    parent_vadj->sadj,
							    psid, last_hop);
				}
			if (CHECK_FLAG(spftree->flags,
				       F_SPFTREE_HOPCOUNT_METRIC))
				vertex_update_firsthops(vertex, parent);
			/*      2) */
			if (!CHECK_FLAG(spftree->flags,
					F_SPFTREE_NO_ADJACENCIES)
			    && listcount(vertex->Adj_N) > ISIS_MAX_PATH_SPLITS)
				remove_excess_adjs(vertex->Adj_N);
			if (listnode_lookup(vertex->parents, parent) == NULL)
				listnode_add(vertex->parents, parent);
			return;
		} else if (vertex->d_N < dist) {
			return;
			/*      4) */
		} else {
			isis_vertex_queue_delete(&spftree->tents, vertex);
			hash_release(spftree->prefix_sids, vertex);
			isis_vertex_del(vertex);
		}
	}

#ifdef EXTREME_DEBUG
	if (IS_DEBUG_SPF_EVENTS)
		zlog_debug(
			"ISIS-SPF: A:%hhu process_N add2tent %s %s dist %d parent %s",
			spftree->algorithm, print_sys_hostname(id),
			vtype2string(vtype), dist,
			(parent ? print_sys_hostname(parent->N.id) : "null"));
#endif /* EXTREME_DEBUG */

	isis_spf_add2tent(spftree, vtype, id, dist, depth, NULL, psid, parent);
	return;
}

/*
 * C.2.6 Step 1
 */
static int isis_spf_process_lsp(struct isis_spftree *spftree,
				struct isis_lsp *lsp, uint32_t cost,
				uint16_t depth, uint8_t *root_sysid,
				struct isis_vertex *parent)
{
	bool pseudo_lsp = LSP_PSEUDO_ID(lsp->hdr.lsp_id);
	struct listnode *fragnode = NULL;
	uint32_t dist;
	enum vertextype vtype;
	static const uint8_t null_sysid[ISIS_SYS_ID_LEN];
	struct isis_mt_router_info *mt_router_info = NULL;
	struct prefix_pair ip_info;
	bool has_valid_psid;
	bool loc_is_in_ipv6_reach = false;

	if (isis_lfa_excise_node_check(spftree, lsp->hdr.lsp_id)) {
		if (IS_DEBUG_LFA)
			zlog_debug("ISIS-LFA: excising node %s",
				   print_sys_hostname(lsp->hdr.lsp_id));
		return ISIS_OK;
	}

	if (!lsp->tlvs)
		return ISIS_OK;

	if (spftree->mtid != ISIS_MT_IPV4_UNICAST)
		mt_router_info = isis_tlvs_lookup_mt_router_info(lsp->tlvs,
								 spftree->mtid);

	if (!pseudo_lsp && (spftree->mtid == ISIS_MT_IPV4_UNICAST
			    && !speaks(lsp->tlvs->protocols_supported.protocols,
				       lsp->tlvs->protocols_supported.count,
				       spftree->family))
	    && !mt_router_info)
		return ISIS_OK;

	/* RFC3787 section 4 SHOULD ignore overload bit in pseudo LSPs */
	bool no_overload = (pseudo_lsp
			    || (spftree->mtid == ISIS_MT_IPV4_UNICAST
				&& !ISIS_MASK_LSP_OL_BIT(lsp->hdr.lsp_bits))
			    || (mt_router_info && !mt_router_info->overload));

lspfragloop:
	if (!lsp->tlvs)
		return ISIS_OK;

	if (lsp->hdr.seqno == 0) {
		zlog_warn("%s: lsp with 0 seq_num - ignore", __func__);
		return ISIS_WARNING;
	}

#ifdef EXTREME_DEBUG
	if (IS_DEBUG_SPF_EVENTS)
		zlog_debug("ISIS-SPF: A:%hhu process_lsp %s",
			   spftree->algorithm,
			   print_sys_hostname(lsp->hdr.lsp_id));
#endif /* EXTREME_DEBUG */

	if (no_overload) {
		if ((pseudo_lsp || spftree->mtid == ISIS_MT_IPV4_UNICAST)
		    && spftree->area->oldmetric) {
			struct isis_oldstyle_reach *r;
			for (r = (struct isis_oldstyle_reach *)
					 lsp->tlvs->oldstyle_reach.head;
			     r; r = r->next) {
				if (fabricd)
					continue;

				/* C.2.6 a) */
				/* Two way connectivity */
				if (!LSP_PSEUDO_ID(r->id)
				    && !memcmp(r->id, root_sysid,
					       ISIS_SYS_ID_LEN))
					continue;
				if (!pseudo_lsp
				    && !memcmp(r->id, null_sysid,
					       ISIS_SYS_ID_LEN))
					continue;
				dist = cost + r->metric;
				process_N(spftree,
					  LSP_PSEUDO_ID(r->id)
						  ? VTYPE_PSEUDO_IS
						  : VTYPE_NONPSEUDO_IS,
					  (void *)r->id, dist, depth + 1, NULL,
					  parent);
			}
		}

		if (spftree->area->newmetric) {
			struct isis_item_list *te_neighs = NULL;
			if (pseudo_lsp || spftree->mtid == ISIS_MT_IPV4_UNICAST)
				te_neighs = &lsp->tlvs->extended_reach;
			else
				te_neighs = isis_lookup_mt_items(
					&lsp->tlvs->mt_reach, spftree->mtid);

			struct isis_extended_reach *er;
			for (er = te_neighs ? (struct isis_extended_reach *)
						      te_neighs->head
					    : NULL;
			     er; er = er->next) {
				/* C.2.6 a) */
				/* Two way connectivity */
				if (!LSP_PSEUDO_ID(er->id)
				    && !memcmp(er->id, root_sysid,
					       ISIS_SYS_ID_LEN))
					continue;
				if (!pseudo_lsp
				    && !memcmp(er->id, null_sysid,
					       ISIS_SYS_ID_LEN))
					continue;
#ifndef FABRICD

				if (flex_algo_id_valid(spftree->algorithm) &&
				    (!sr_algorithm_participated(
					     lsp, spftree->algorithm) ||
				     isis_flex_algo_constraint_drop(spftree,
								    lsp, er)))
					continue;
#endif /* ifndef FABRICD */

				dist = cost
				       + (CHECK_FLAG(spftree->flags,
						     F_SPFTREE_HOPCOUNT_METRIC)
						  ? 1
						  : er->metric);
				process_N(spftree,
					  LSP_PSEUDO_ID(er->id)
						  ? VTYPE_PSEUDO_TE_IS
						  : VTYPE_NONPSEUDO_TE_IS,
					  (void *)er->id, dist, depth + 1, NULL,
					  parent);
			}
		}
	}

	if (!fabricd && !pseudo_lsp && spftree->family == AF_INET
	    && spftree->mtid == ISIS_MT_IPV4_UNICAST
	    && spftree->area->oldmetric) {
		struct isis_item_list *reachs[] = {
			&lsp->tlvs->oldstyle_ip_reach,
			&lsp->tlvs->oldstyle_ip_reach_ext};

		for (unsigned int i = 0; i < array_size(reachs); i++) {
			vtype = i ? VTYPE_IPREACH_EXTERNAL
				  : VTYPE_IPREACH_INTERNAL;

			memset(&ip_info, 0, sizeof(ip_info));
			ip_info.dest.family = AF_INET;

			struct isis_oldstyle_ip_reach *r;
			for (r = (struct isis_oldstyle_ip_reach *)reachs[i]
					 ->head;
			     r; r = r->next) {
				dist = cost + r->metric;
				ip_info.dest.u.prefix4 = r->prefix.prefix;
				ip_info.dest.prefixlen = r->prefix.prefixlen;
				process_N(spftree, vtype, &ip_info,
					  dist, depth + 1, NULL, parent);
			}
		}
	}

	/* we can skip all the rest if we're using metric style narrow */
	if (!spftree->area->newmetric)
		goto end;

	if (!pseudo_lsp && spftree->family == AF_INET) {
		struct isis_item_list *ipv4_reachs;
		if (spftree->mtid == ISIS_MT_IPV4_UNICAST)
			ipv4_reachs = &lsp->tlvs->extended_ip_reach;
		else
			ipv4_reachs = isis_lookup_mt_items(
				&lsp->tlvs->mt_ip_reach, spftree->mtid);

		memset(&ip_info, 0, sizeof(ip_info));
		ip_info.dest.family = AF_INET;

		struct isis_extended_ip_reach *r;
		for (r = ipv4_reachs
				 ? (struct isis_extended_ip_reach *)
					   ipv4_reachs->head
				 : NULL;
		     r; r = r->next) {
			dist = cost + r->metric;
			ip_info.dest.u.prefix4 = r->prefix.prefix;
			ip_info.dest.prefixlen = r->prefix.prefixlen;

			/* Parse list of Prefix-SID subTLVs if SR is enabled */
			has_valid_psid = false;
			if (spftree->area->srdb.enabled && r->subtlvs) {
				for (struct isis_item *i =
					     r->subtlvs->prefix_sids.head;
				     i; i = i->next) {
					struct isis_prefix_sid *psid =
						(struct isis_prefix_sid *)i;

					if (psid->algorithm !=
					    spftree->algorithm)
						continue;

#ifndef FABRICD
					if (flex_algo_id_valid(
						    spftree->algorithm) &&
					    (!sr_algorithm_participated(
						     lsp, spftree->algorithm) ||
					     !isis_flex_algo_elected_supported(
						     spftree->algorithm,
						     spftree->area)))
						continue;
#endif /* ifndef FABRICD */

					has_valid_psid = true;
					process_N(spftree, VTYPE_IPREACH_TE,
						  &ip_info, dist, depth + 1,
						  psid, parent);
					/*
					 * Stop the Prefix-SID iteration since
					 * we only support the SPF algorithm for
					 * now.
					 */
					break;
				}
			}
			if (!has_valid_psid)
				process_N(spftree, VTYPE_IPREACH_TE, &ip_info,
					  dist, depth + 1, NULL, parent);
		}
	}

	if (!pseudo_lsp && spftree->family == AF_INET6) {
		struct isis_item_list *ipv6_reachs;
		if (spftree->mtid == ISIS_MT_IPV4_UNICAST)
			ipv6_reachs = &lsp->tlvs->ipv6_reach;
		else
			ipv6_reachs = isis_lookup_mt_items(
				&lsp->tlvs->mt_ipv6_reach, spftree->mtid);

		struct isis_ipv6_reach *r;
		for (r = ipv6_reachs
				 ? (struct isis_ipv6_reach *)ipv6_reachs->head
				 : NULL;
		     r; r = r->next) {
			dist = cost + r->metric;
			vtype = r->external ? VTYPE_IP6REACH_EXTERNAL
					    : VTYPE_IP6REACH_INTERNAL;
			memset(&ip_info, 0, sizeof(ip_info));
			ip_info.dest.family = AF_INET6;
			ip_info.dest.u.prefix6 = r->prefix.prefix;
			ip_info.dest.prefixlen = r->prefix.prefixlen;

			if (spftree->area->srdb.enabled && r->subtlvs &&
			    r->subtlvs->source_prefix &&
			    r->subtlvs->source_prefix->prefixlen) {
				if (spftree->tree_id != SPFTREE_DSTSRC) {
					char buff[VID2STR_BUFFER];
					zlog_warn("Ignoring dest-src route %s in non dest-src topology",
						srcdest2str(
							&ip_info.dest,
							r->subtlvs->source_prefix,
							buff, sizeof(buff)
						)
					);
					continue;
				}
				ip_info.src = *r->subtlvs->source_prefix;
			}

			/* Parse list of Prefix-SID subTLVs */
			has_valid_psid = false;
			if (r->subtlvs) {
				for (struct isis_item *i =
					     r->subtlvs->prefix_sids.head;
				     i; i = i->next) {
					struct isis_prefix_sid *psid =
						(struct isis_prefix_sid *)i;

					if (psid->algorithm !=
					    spftree->algorithm)
						continue;

#ifndef FABRICD
					if (flex_algo_id_valid(
						    spftree->algorithm) &&
					    (!sr_algorithm_participated(
						     lsp, spftree->algorithm) ||
					     !isis_flex_algo_elected_supported(
						     spftree->algorithm,
						     spftree->area)))
						continue;
#endif /* ifndef FABRICD */

					has_valid_psid = true;
					process_N(spftree, vtype, &ip_info,
						  dist, depth + 1, psid,
						  parent);
					/*
					 * Stop the Prefix-SID iteration since
					 * we only support the SPF algorithm for
					 * now.
					 */
					break;
				}
			}
			if (!has_valid_psid)
				process_N(spftree, vtype, &ip_info, dist,
					  depth + 1, NULL, parent);
		}

		/* Process SRv6 Locator TLVs */

		struct isis_item_list *srv6_locators = isis_lookup_mt_items(
			&lsp->tlvs->srv6_locator, spftree->mtid);

		struct isis_srv6_locator_tlv *loc;
		for (loc = srv6_locators ? (struct isis_srv6_locator_tlv *)
						   srv6_locators->head
					 : NULL;
		     loc; loc = loc->next) {

			if (loc->algorithm != SR_ALGORITHM_SPF)
				continue;

			dist = cost + loc->metric;
			vtype = VTYPE_IP6REACH_INTERNAL;
			memset(&ip_info, 0, sizeof(ip_info));
			ip_info.dest.family = AF_INET6;
			ip_info.dest.u.prefix6 = loc->prefix.prefix;
			ip_info.dest.prefixlen = loc->prefix.prefixlen;

			/* An SRv6 Locator can be received in both a Prefix
			Reachability TLV and an SRv6 Locator TLV (as per RFC
			9352 section #5). We go through the Prefix Reachability
			TLVs and check if the SRv6 Locator is present in some of
			them. If we find the SRv6 Locator in some Prefix
			Reachbility TLV then it means that we have already
			processed it before and we can skip it. */
			for (r = ipv6_reachs ? (struct isis_ipv6_reach *)
						       ipv6_reachs->head
					     : NULL;
			     r; r = r->next) {
				if (prefix_same((struct prefix *)&r->prefix,
						(struct prefix *)&loc->prefix))
					loc_is_in_ipv6_reach = true;
			}

			/* SRv6 locator not present in Prefix Reachability TLV,
			 * let's process it */
			if (!loc_is_in_ipv6_reach)
				process_N(spftree, vtype, &ip_info, dist,
					  depth + 1, NULL, parent);
		}
	}

end:

	/* if attach bit set in LSP, attached-bit receive ignore is
	 * not configured, we are a level-1 area and we have no other
	 * level-2 | level1-2 areas then add a default route toward
	 * this neighbor
	 */
	if ((lsp->hdr.lsp_bits & LSPBIT_ATT) == LSPBIT_ATT
	    && !spftree->area->attached_bit_rcv_ignore
	    && (spftree->area->is_type & IS_LEVEL_1)
	    && !isis_level2_adj_up(spftree->area)) {
		struct prefix_pair ip_info = { {0} };
		if (IS_DEBUG_RTE_EVENTS)
			zlog_debug("ISIS-Spf (%pLS): add default %s route",
				   lsp->hdr.lsp_id,
				   spftree->family == AF_INET ? "ipv4"
							      : "ipv6");

		if (spftree->family == AF_INET) {
			ip_info.dest.family = AF_INET;
			vtype = VTYPE_IPREACH_INTERNAL;
		} else {
			ip_info.dest.family = AF_INET6;
			vtype = VTYPE_IP6REACH_INTERNAL;
		}
		process_N(spftree, vtype, &ip_info, cost, depth + 1, NULL,
			  parent);
	}

	if (fragnode == NULL)
		fragnode = listhead(lsp->lspu.frags);
	else
		fragnode = listnextnode(fragnode);

	if (fragnode) {
		lsp = listgetdata(fragnode);
		goto lspfragloop;
	}

	return ISIS_OK;
}

static struct isis_adjacency *adj_find(struct list *adj_list, const uint8_t *id,
				       int level, uint16_t mtid, int family)
{
	struct isis_adjacency *adj;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(adj_list, node, adj)) {
		if (!(adj->level & level))
			continue;
		if (memcmp(adj->sysid, id, ISIS_SYS_ID_LEN) != 0)
			continue;
		if (adj->adj_state != ISIS_ADJ_UP)
			continue;
		if (!adj_has_mt(adj, mtid))
			continue;
		if (mtid == ISIS_MT_IPV4_UNICAST
		    && !speaks(adj->nlpids.nlpids, adj->nlpids.count, family))
			continue;
		return adj;
	}

	return NULL;
}

struct spf_preload_tent_ip_reach_args {
	struct isis_spftree *spftree;
	struct isis_vertex *parent;
};

static int isis_spf_preload_tent_ip_reach_cb(const struct prefix *prefix,
					     uint32_t metric, bool external,
					     struct isis_subtlvs *subtlvs,
					     void *arg)
{
	struct spf_preload_tent_ip_reach_args *args = arg;
	struct isis_spftree *spftree = args->spftree;
	struct isis_vertex *parent = args->parent;
	struct prefix_pair ip_info;
	enum vertextype vtype;
	bool has_valid_psid = false;

	if (external)
		return LSP_ITER_CONTINUE;

	assert(spftree->family == prefix->family);
	memset(&ip_info, 0, sizeof(ip_info));
	prefix_copy(&ip_info.dest, prefix);
	apply_mask(&ip_info.dest);

	if (prefix->family == AF_INET)
		vtype = VTYPE_IPREACH_INTERNAL;
	else
		vtype = VTYPE_IP6REACH_INTERNAL;

	/* Parse list of Prefix-SID subTLVs if SR is enabled */
	if (spftree->area->srdb.enabled && subtlvs) {
		for (struct isis_item *i = subtlvs->prefix_sids.head; i;
		     i = i->next) {
			struct isis_prefix_sid *psid =
				(struct isis_prefix_sid *)i;

			if (psid->algorithm != spftree->algorithm)
				continue;

			has_valid_psid = true;
			isis_spf_add_local(spftree, vtype, &ip_info, NULL, 0,
					   psid, parent);

			/*
			 * Stop the Prefix-SID iteration since we only support
			 * the SPF algorithm for now.
			 */
			break;
		}
	}
	if (!has_valid_psid)
		isis_spf_add_local(spftree, vtype, &ip_info, NULL, 0, NULL,
				   parent);

	return LSP_ITER_CONTINUE;
}

static void isis_spf_preload_tent(struct isis_spftree *spftree,
				  uint8_t *root_sysid,
				  struct isis_lsp *root_lsp,
				  struct isis_vertex *parent)
{
	struct spf_preload_tent_ip_reach_args ip_reach_args;
	struct isis_spf_adj *sadj;
	struct listnode *node;

	if (!CHECK_FLAG(spftree->flags, F_SPFTREE_HOPCOUNT_METRIC)) {
		ip_reach_args.spftree = spftree;
		ip_reach_args.parent = parent;
		isis_lsp_iterate_ip_reach(
			root_lsp, spftree->family, spftree->mtid,
			isis_spf_preload_tent_ip_reach_cb, &ip_reach_args);
	}

	/* Iterate over adjacencies. */
	for (ALL_LIST_ELEMENTS_RO(spftree->sadj_list, node, sadj)) {
		const uint8_t *adj_id;
		uint32_t metric;

		if (CHECK_FLAG(sadj->flags, F_ISIS_SPF_ADJ_BROADCAST))
			adj_id = sadj->lan.desig_is_id;
		else
			adj_id = sadj->id;

		if (isis_lfa_excise_adj_check(spftree, adj_id)) {
			if (IS_DEBUG_LFA)
				zlog_debug("ISIS-SPF: excising adjacency %pPN",
					   sadj->id);
			continue;
		}

		metric = CHECK_FLAG(spftree->flags, F_SPFTREE_HOPCOUNT_METRIC)
				 ? 1
				 : sadj->metric;
		if (!LSP_PSEUDO_ID(sadj->id)) {
			isis_spf_add_local(spftree,
					   CHECK_FLAG(sadj->flags,
						      F_ISIS_SPF_ADJ_OLDMETRIC)
						   ? VTYPE_NONPSEUDO_IS
						   : VTYPE_NONPSEUDO_TE_IS,
					   sadj->id, sadj, metric, NULL,
					   parent);
		} else if (sadj->lsp) {
			isis_spf_process_lsp(spftree, sadj->lsp, metric, 0,
					     spftree->sysid, parent);
		}
	}
}

struct spf_adj_find_reverse_metric_args {
	const uint8_t *id_self;
	uint32_t reverse_metric;
};

static int spf_adj_find_reverse_metric_cb(const uint8_t *id, uint32_t metric,
					  bool oldmetric,
					  struct isis_ext_subtlvs *subtlvs,
					  void *arg)
{
	struct spf_adj_find_reverse_metric_args *args = arg;

	if (memcmp(id, args->id_self, ISIS_SYS_ID_LEN))
		return LSP_ITER_CONTINUE;

	args->reverse_metric = metric;

	return LSP_ITER_STOP;
}

/*
 * Change all SPF adjacencies to use the link cost in the direction from the
 * next hop back towards root in place of the link cost in the direction away
 * from root towards the next hop.
 */
static void spf_adj_get_reverse_metrics(struct isis_spftree *spftree)
{
	struct isis_spf_adj *sadj;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(spftree->sadj_list, node, nnode, sadj)) {
		uint8_t lspid[ISIS_SYS_ID_LEN + 2];
		struct isis_lsp *lsp_adj;
		const uint8_t *id_self;
		struct spf_adj_find_reverse_metric_args args;

		/* Skip pseudonodes. */
		if (LSP_PSEUDO_ID(sadj->id))
			continue;

		/* Find LSP of the corresponding adjacency. */
		memcpy(lspid, sadj->id, ISIS_SYS_ID_LEN);
		LSP_PSEUDO_ID(lspid) = 0;
		LSP_FRAGMENT(lspid) = 0;
		lsp_adj = lsp_search(spftree->lspdb, lspid);
		if (lsp_adj == NULL || lsp_adj->hdr.rem_lifetime == 0) {
			/* Delete one-way adjacency. */
			listnode_delete(spftree->sadj_list, sadj);
			isis_spf_adj_free(sadj);
			continue;
		}

		/* Find root node in the LSP of the adjacent router. */
		if (CHECK_FLAG(sadj->flags, F_ISIS_SPF_ADJ_BROADCAST))
			id_self = sadj->lan.desig_is_id;
		else
			id_self = spftree->sysid;
		args.id_self = id_self;
		args.reverse_metric = UINT32_MAX;
		isis_lsp_iterate_is_reach(lsp_adj, spftree->mtid,
					  spf_adj_find_reverse_metric_cb,
					  &args);
		if (args.reverse_metric == UINT32_MAX) {
			/* Delete one-way adjacency. */
			listnode_delete(spftree->sadj_list, sadj);
			isis_spf_adj_free(sadj);
			continue;
		}
		sadj->metric = args.reverse_metric;
	}
}

static void spf_adj_list_parse_tlv(struct isis_spftree *spftree,
				   struct list *adj_list, const uint8_t *id,
				   const uint8_t *desig_is_id,
				   uint32_t pseudo_metric, uint32_t metric,
				   bool oldmetric,
				   struct isis_ext_subtlvs *subtlvs)
{
	struct isis_spf_adj *sadj;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2];
	struct isis_lsp *lsp;
	uint8_t flags = 0;

	/* Skip self in the pseudonode. */
	if (desig_is_id && !memcmp(id, spftree->sysid, ISIS_SYS_ID_LEN))
		return;

	/* Find LSP from the adjacency. */
	memcpy(lspid, id, ISIS_SYS_ID_LEN + 1);
	LSP_FRAGMENT(lspid) = 0;
	lsp = lsp_search(spftree->lspdb, lspid);
	if (lsp == NULL || lsp->hdr.rem_lifetime == 0) {
		zlog_warn("ISIS-SPF: No LSP found from root to L%d %pLS",
			  spftree->level, lspid);
		return;
	}

	sadj = XCALLOC(MTYPE_ISIS_SPF_ADJ, sizeof(*sadj));
	memcpy(sadj->id, id, sizeof(sadj->id));
	if (desig_is_id) {
		memcpy(sadj->lan.desig_is_id, desig_is_id,
		       sizeof(sadj->lan.desig_is_id));
		SET_FLAG(flags, F_ISIS_SPF_ADJ_BROADCAST);
		sadj->metric = pseudo_metric;
	} else
		sadj->metric = metric;
	if (oldmetric)
		SET_FLAG(flags, F_ISIS_SPF_ADJ_OLDMETRIC);
	if ((oldmetric && sadj->metric == ISIS_NARROW_METRIC_INFINITY) ||
	    (!oldmetric && sadj->metric == ISIS_WIDE_METRIC_INFINITY))
		SET_FLAG(flags, F_ISIS_SPF_ADJ_METRIC_INFINITY);
	sadj->lsp = lsp;
	sadj->subtlvs = subtlvs;
	sadj->flags = flags;

	/* Set real adjacency. */
	if (!CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ADJACENCIES)
	    && !LSP_PSEUDO_ID(id)) {
		struct isis_adjacency *adj;

		adj = adj_find(adj_list, id, spftree->level, spftree->mtid,
			       spftree->family);
		if (!adj) {
			XFREE(MTYPE_ISIS_SPF_ADJ, sadj);
			return;
		}

		listnode_delete(adj_list, adj);
		sadj->adj = adj;
	}

	/* Add adjacency to the list. */
	listnode_add(spftree->sadj_list, sadj);

	if (!LSP_PSEUDO_ID(id)) {
		struct isis_spf_node *node;

		node = isis_spf_node_find(&spftree->adj_nodes, id);
		if (!node)
			node = isis_spf_node_new(&spftree->adj_nodes, id);
		if (node->best_metric == 0 || sadj->metric < node->best_metric)
			node->best_metric = sadj->metric;
		listnode_add(node->adjacencies, sadj);
	}

	/* Parse pseudonode LSP too. */
	if (LSP_PSEUDO_ID(id))
		spf_adj_list_parse_lsp(spftree, adj_list, lsp, id, metric);
}

static void spf_adj_list_parse_lsp(struct isis_spftree *spftree,
				   struct list *adj_list, struct isis_lsp *lsp,
				   const uint8_t *pseudo_nodeid,
				   uint32_t pseudo_metric)
{
	bool pseudo_lsp = LSP_PSEUDO_ID(lsp->hdr.lsp_id);
	struct isis_lsp *frag;
	struct listnode *node;
	struct isis_item *head;
	struct isis_item_list *te_neighs;

	if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
		return;

	/* Parse LSP. */
	if (lsp->tlvs) {
		if (pseudo_lsp || spftree->mtid == ISIS_MT_IPV4_UNICAST) {
			head = lsp->tlvs->oldstyle_reach.head;
			for (struct isis_oldstyle_reach *reach =
				     (struct isis_oldstyle_reach *)head;
			     reach; reach = reach->next) {
				spf_adj_list_parse_tlv(
					spftree, adj_list, reach->id,
					pseudo_nodeid, pseudo_metric,
					reach->metric, true, NULL);
			}
		}

		if (pseudo_lsp || spftree->mtid == ISIS_MT_IPV4_UNICAST)
			te_neighs = &lsp->tlvs->extended_reach;
		else
			te_neighs = isis_get_mt_items(&lsp->tlvs->mt_reach,
						      spftree->mtid);
		if (te_neighs) {
			head = te_neighs->head;
			for (struct isis_extended_reach *reach =
				     (struct isis_extended_reach *)head;
			     reach; reach = reach->next) {
#ifndef FABRICD
				/*
				 * cutting out adjacency by flex-algo link
				 * affinity attribute
				 */
				if (flex_algo_id_valid(spftree->algorithm) &&
				    (!sr_algorithm_participated(
					     lsp, spftree->algorithm) ||
				     isis_flex_algo_constraint_drop(
					     spftree, lsp, reach)))
					continue;
#endif /* ifndef FABRICD */

				spf_adj_list_parse_tlv(
					spftree, adj_list, reach->id,
					pseudo_nodeid, pseudo_metric,
					reach->metric, false, reach->subtlvs);
			}
		}
	}

	if (LSP_FRAGMENT(lsp->hdr.lsp_id))
		return;

	/* Parse LSP fragments. */
	for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag)) {
		if (!frag->tlvs)
			continue;

		spf_adj_list_parse_lsp(spftree, adj_list, frag, pseudo_nodeid,
				       pseudo_metric);
	}
}

static void isis_spf_build_adj_list(struct isis_spftree *spftree,
				    struct isis_lsp *lsp)
{
	struct list *adj_list = NULL;

	if (!CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ADJACENCIES))
		adj_list = list_dup(spftree->area->adjacency_list);

	spf_adj_list_parse_lsp(spftree, adj_list, lsp, NULL, 0);

	if (!CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ADJACENCIES))
		list_delete(&adj_list);

	if (spftree->type == SPF_TYPE_REVERSE)
		spf_adj_get_reverse_metrics(spftree);
}

/*
 * The parent(s) for vertex is set when added to TENT list
 * now we just put the child pointer(s) in place
 */
static void add_to_paths(struct isis_spftree *spftree,
			 struct isis_vertex *vertex)
{
#ifdef EXTREME_DEBUG
	char buff[VID2STR_BUFFER];
#endif /* EXTREME_DEBUG */

	if (isis_find_vertex(&spftree->paths, &vertex->N, vertex->type))
		return;
	isis_vertex_queue_append(&spftree->paths, vertex);

#ifdef EXTREME_DEBUG
	if (IS_DEBUG_SPF_EVENTS)
		zlog_debug(
			"ISIS-SPF: A:%hhu S:%p added %s %s %s depth %d dist %d to PATHS",
			spftree->algorithm, spftree,
			print_sys_hostname(vertex->N.id),
			vtype2string(vertex->type),
			vid2string(vertex, buff, sizeof(buff)), vertex->depth,
			vertex->d_N);
#endif /* EXTREME_DEBUG */
}

static void init_spt(struct isis_spftree *spftree, int mtid)
{
	/* Clear data from previous run. */
	hash_clean(spftree->prefix_sids, NULL);
	isis_spf_node_list_clear(&spftree->adj_nodes);
	list_delete_all_node(spftree->sadj_list);
	isis_vertex_queue_clear(&spftree->tents);
	isis_vertex_queue_clear(&spftree->paths);
	isis_zebra_rlfa_unregister_all(spftree);
	isis_rlfa_list_clear(spftree);
	list_delete_all_node(spftree->lfa.remote.pc_spftrees);
	memset(&spftree->lfa.protection_counters, 0,
	       sizeof(spftree->lfa.protection_counters));

	spftree->mtid = mtid;
}

static enum spf_prefix_priority
spf_prefix_priority(struct isis_spftree *spftree, struct isis_vertex *vertex)
{
	struct isis_area *area = spftree->area;
	struct prefix *prefix = &vertex->N.ip.p.dest;

	for (int priority = SPF_PREFIX_PRIO_CRITICAL;
	     priority <= SPF_PREFIX_PRIO_MEDIUM; priority++) {
		struct spf_prefix_priority_acl *ppa;
		enum filter_type ret = FILTER_PERMIT;

		ppa = &area->spf_prefix_priorities[priority];
		switch (spftree->family) {
		case AF_INET:
			ret = access_list_apply(ppa->list_v4, prefix);
			break;
		case AF_INET6:
			ret = access_list_apply(ppa->list_v6, prefix);
			break;
		default:
			break;
		}

		if (ret == FILTER_PERMIT)
			return priority;
	}

	/* Assign medium priority to loopback prefixes by default. */
	if (is_host_route(prefix))
		return SPF_PREFIX_PRIO_MEDIUM;

	return SPF_PREFIX_PRIO_LOW;
}

static void spf_path_process(struct isis_spftree *spftree,
			     struct isis_vertex *vertex)
{
	struct isis_area *area = spftree->area;
	int level = spftree->level;
	char buff[VID2STR_BUFFER];

	if (spftree->type == SPF_TYPE_TI_LFA && VTYPE_IS(vertex->type)
	    && !CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ADJACENCIES)) {
		if (listcount(vertex->Adj_N) > 0) {
			struct isis_adjacency *adj;

			if (isis_tilfa_check(spftree, vertex) != 0)
				return;

			adj = isis_adj_find(area, level, vertex->N.id);
			if (adj)
				sr_adj_sid_add_single(adj, spftree->family,
						      true, vertex->Adj_N);
		} else if (IS_DEBUG_SPF_EVENTS)
			zlog_debug(
				"ISIS-SPF: no adjacencies, do not install backup Adj-SID for %s depth %d dist %d",
				vid2string(vertex, buff, sizeof(buff)),
				vertex->depth, vertex->d_N);
	}

	if (VTYPE_IP(vertex->type)
	    && !CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ROUTES)) {
		enum spf_prefix_priority priority;

		priority = spf_prefix_priority(spftree, vertex);
		vertex->N.ip.priority = priority;
		if (vertex->depth == 1 || listcount(vertex->Adj_N) > 0) {
			struct isis_spftree *pre_spftree;
			struct route_table *route_table = NULL;
			bool allow_ecmp = false;

			switch (spftree->type) {
			case SPF_TYPE_RLFA:
			case SPF_TYPE_TI_LFA:
				if (priority
				    > area->lfa_priority_limit[level - 1]) {
					if (IS_DEBUG_LFA)
						zlog_debug(
							"ISIS-LFA: skipping %s %s (low prefix priority)",
							vtype2string(
								vertex->type),
							vid2string(
								vertex, buff,
								sizeof(buff)));
					return;
				}
				break;
			case SPF_TYPE_FORWARD:
			case SPF_TYPE_REVERSE:
				break;
			}

			switch (spftree->type) {
			case SPF_TYPE_RLFA:
				isis_rlfa_check(spftree, vertex);
				return;
			case SPF_TYPE_TI_LFA:
				if (isis_tilfa_check(spftree, vertex) != 0)
					return;

				pre_spftree = spftree->lfa.old.spftree;
				route_table = pre_spftree->route_table_backup;
				allow_ecmp = area->lfa_load_sharing[level - 1];
				pre_spftree->lfa.protection_counters
					.tilfa[vertex->N.ip.priority] += 1;
				break;
			case SPF_TYPE_FORWARD:
			case SPF_TYPE_REVERSE:
				route_table = spftree->route_table;
				allow_ecmp = true;

				/*
				 * Update LFA protection counters (ignore local
				 * routes).
				 */
				if (vertex->depth > 1) {
					spftree->lfa.protection_counters
						.total[priority] += 1;
					if (listcount(vertex->Adj_N) > 1)
						spftree->lfa.protection_counters
							.ecmp[priority] += 1;
				}
				break;
			}

#ifdef EXTREME_DEBUG
			struct isis_route_info *ri =
#endif /* EXTREME_DEBUG */
				isis_route_create(&vertex->N.ip.p.dest,
						  &vertex->N.ip.p.src,
						  vertex->d_N, vertex->depth,
						  &vertex->N.ip.sr,
						  vertex->Adj_N, allow_ecmp,
						  area, route_table);

#ifdef EXTREME_DEBUG
			zlog_debug(
				"ISIS-SPF: A:%hhu create route pfx %pFX dist %d, sr.algo %d, table %p, rv %p",
				spftree->algorithm, &vertex->N.ip.p.dest,
				vertex->d_N, vertex->N.ip.sr.algorithm,
				route_table, ri);
#endif /* EXTREME_DEBUG */
		} else if (IS_DEBUG_SPF_EVENTS)
			zlog_debug(
				"ISIS-SPF: no adjacencies, do not install route for %s depth %d dist %d",
				vid2string(vertex, buff, sizeof(buff)),
				vertex->depth, vertex->d_N);
	}
}

static void isis_spf_loop(struct isis_spftree *spftree,
			  uint8_t *root_sysid)
{
	struct isis_vertex *vertex;
	struct isis_lsp *lsp;
	struct listnode *node;

	while (isis_vertex_queue_count(&spftree->tents)) {
		vertex = isis_vertex_queue_pop(&spftree->tents);

#ifdef EXTREME_DEBUG
		zlog_debug(
			"ISIS-SPF: A:%hhu get TENT node %s %s depth %d dist %d to PATHS",
			spftree->algorithm, print_sys_hostname(vertex->N.id),
			vtype2string(vertex->type), vertex->depth, vertex->d_N);
#endif /* EXTREME_DEBUG */

		add_to_paths(spftree, vertex);
		if (!VTYPE_IS(vertex->type))
			continue;

		lsp = lsp_for_vertex(spftree, vertex);
		if (!lsp) {
			zlog_warn("ISIS-SPF: No LSP found for %pPN",
				  vertex->N.id);
			continue;
		}

		isis_spf_process_lsp(spftree, lsp, vertex->d_N, vertex->depth,
				     root_sysid, vertex);
	}

	/* Generate routes once the SPT is formed. */
	for (ALL_QUEUE_ELEMENTS_RO(&spftree->paths, node, vertex)) {
		/* New-style TLVs take precedence over the old-style TLVs. */
		switch (vertex->type) {
		case VTYPE_IPREACH_INTERNAL:
		case VTYPE_IPREACH_EXTERNAL:
			if (isis_find_vertex(&spftree->paths, &vertex->N,
					     VTYPE_IPREACH_TE))
				continue;
			break;
		case VTYPE_PSEUDO_IS:
		case VTYPE_PSEUDO_TE_IS:
		case VTYPE_NONPSEUDO_IS:
		case VTYPE_NONPSEUDO_TE_IS:
		case VTYPE_ES:
		case VTYPE_IPREACH_TE:
		case VTYPE_IP6REACH_INTERNAL:
		case VTYPE_IP6REACH_EXTERNAL:
			break;
		}

		spf_path_process(spftree, vertex);
	}
}

struct isis_spftree *isis_run_hopcount_spf(struct isis_area *area,
					   uint8_t *sysid,
					   struct isis_spftree *spftree)
{
	if (!spftree)
		spftree = isis_spftree_new(
			area, &area->lspdb[IS_LEVEL_2 - 1], sysid, ISIS_LEVEL2,
			SPFTREE_IPV4, SPF_TYPE_FORWARD,
			F_SPFTREE_HOPCOUNT_METRIC, SR_ALGORITHM_SPF);

	init_spt(spftree, ISIS_MT_IPV4_UNICAST);
	if (!memcmp(sysid, area->isis->sysid, ISIS_SYS_ID_LEN)) {
		struct isis_lsp *root_lsp;
		struct isis_vertex *root_vertex;

		root_lsp = isis_root_system_lsp(spftree->lspdb, spftree->sysid);
		if (root_lsp) {
			/*
			 * If we are running locally, initialize with
			 * information from adjacencies
			 */
			root_vertex = isis_spf_add_root(spftree);

			isis_spf_preload_tent(spftree, sysid, root_lsp,
					      root_vertex);
		}
	} else {
		isis_vertex_queue_insert(
			&spftree->tents,
			isis_vertex_new(spftree, sysid, VTYPE_NONPSEUDO_TE_IS));
	}

	isis_spf_loop(spftree, sysid);

	return spftree;
}

void isis_run_spf(struct isis_spftree *spftree)
{
	struct isis_lsp *root_lsp;
	struct isis_vertex *root_vertex;
	struct timeval time_start;
	struct timeval time_end;
	struct isis_mt_router_info *mt_router_info;
	uint16_t mtid = 0;
#ifndef FABRICD
	bool flex_algo_enabled;
#endif /* ifndef FABRICD */

	/* Get time that can't roll backwards. */
	monotime(&time_start);

	root_lsp = isis_root_system_lsp(spftree->lspdb, spftree->sysid);
	if (root_lsp == NULL) {
		zlog_err("ISIS-SPF: could not find own l%d LSP!",
			 spftree->level);
		return;
	}

	/* Get Multi-Topology ID. */
	switch (spftree->tree_id) {
	case SPFTREE_IPV4:
		mtid = ISIS_MT_IPV4_UNICAST;
		break;
	case SPFTREE_IPV6:
		mt_router_info = isis_tlvs_lookup_mt_router_info(
			root_lsp->tlvs, ISIS_MT_IPV6_UNICAST);
		if (mt_router_info)
			mtid = ISIS_MT_IPV6_UNICAST;
		else
			mtid = ISIS_MT_IPV4_UNICAST;
		break;
	case SPFTREE_DSTSRC:
		mtid = ISIS_MT_IPV6_DSTSRC;
		break;
	case SPFTREE_COUNT:
		zlog_err(
			"%s should never be called with SPFTREE_COUNT as argument!",
			__func__);
		exit(1);
	}

#ifndef FABRICD
	/* If a node is configured to participate in a particular Flexible-
	 * Algorithm, but there is no valid Flex-Algorithm definition available
	 * for it, or the selected Flex-Algorithm definition includes
	 * calculation-type, metric-type, constraint, flag, or Sub-TLV that is
	 * not supported by the node, it MUST stop participating in such
	 * Flexible-Algorithm.
	 */
	if (flex_algo_id_valid(spftree->algorithm)) {
		flex_algo_enabled = isis_flex_algo_elected_supported(
			spftree->algorithm, spftree->area);
		if (flex_algo_enabled !=
		    flex_algo_get_state(spftree->area->flex_algos,
					spftree->algorithm)) {
			/* actual state is inconsistent with local LSP */
			lsp_regenerate_schedule(spftree->area,
						spftree->area->is_type, 0);
			goto out;
		}
		if (!flex_algo_enabled) {
			if (!CHECK_FLAG(spftree->flags, F_SPFTREE_DISABLED)) {
				isis_spftree_clear(spftree);
				SET_FLAG(spftree->flags, F_SPFTREE_DISABLED);
				lsp_regenerate_schedule(spftree->area,
							spftree->area->is_type,
							0);
			}
			goto out;
		}
	}
#endif /* ifndef FABRICD */

	/*
	 * C.2.5 Step 0
	 */
	init_spt(spftree, mtid);
	/*              a) */
	root_vertex = isis_spf_add_root(spftree);
	/*              b) */
	isis_spf_build_adj_list(spftree, root_lsp);
	isis_spf_preload_tent(spftree, spftree->sysid, root_lsp, root_vertex);

	/*
	 * C.2.7 Step 2
	 */
	if (!isis_vertex_queue_count(&spftree->tents)
	    && (IS_DEBUG_SPF_EVENTS)) {
		zlog_warn("ISIS-SPF: TENT is empty SPF-root:%s",
			  print_sys_hostname(spftree->sysid));
	}

	isis_spf_loop(spftree, spftree->sysid);


#ifndef FABRICD
	/* flex-algo */
	if (CHECK_FLAG(spftree->flags, F_SPFTREE_DISABLED)) {
		UNSET_FLAG(spftree->flags, F_SPFTREE_DISABLED);
		lsp_regenerate_schedule(spftree->area, spftree->area->is_type,
					0);
	}

out:
#endif /* ifndef FABRICD */
	spftree->runcount++;
	spftree->last_run_timestamp = time(NULL);
	spftree->last_run_monotime = monotime(&time_end);
	spftree->last_run_duration =
		((time_end.tv_sec - time_start.tv_sec) * 1000000)
		+ (time_end.tv_usec - time_start.tv_usec);
}

static void isis_run_spf_with_protection(struct isis_area *area,
					 struct isis_spftree *spftree)
{
	/* Run forward SPF locally. */
	memcpy(spftree->sysid, area->isis->sysid, ISIS_SYS_ID_LEN);
	isis_run_spf(spftree);

	/* Run LFA protection if configured. */
	if (area->lfa_protected_links[spftree->level - 1] > 0
	    || area->tilfa_protected_links[spftree->level - 1] > 0)
		isis_spf_run_lfa(area, spftree);
}

void isis_spf_verify_routes(struct isis_area *area, struct isis_spftree **trees,
			    int tree)
{
	if (area->is_type == IS_LEVEL_1) {
		isis_route_verify_table(area, trees[0]->route_table,
					trees[0]->route_table_backup, tree);
	} else if (area->is_type == IS_LEVEL_2) {
		isis_route_verify_table(area, trees[1]->route_table,
					trees[1]->route_table_backup, tree);
	} else {
		isis_route_verify_merge(area, trees[0]->route_table,
					trees[0]->route_table_backup,
					trees[1]->route_table,
					trees[1]->route_table_backup, tree);
	}
}

void isis_spf_invalidate_routes(struct isis_spftree *tree)
{
	struct isis_route_table_info *backup_info;

	isis_route_invalidate_table(tree->area, tree->route_table);

	/* Delete backup routes. */

	backup_info = tree->route_table_backup->info;
	route_table_finish(tree->route_table_backup);
	isis_route_table_info_free(backup_info);
	tree->route_table_backup = srcdest_table_init();
	tree->route_table_backup->info =
		isis_route_table_info_alloc(tree->algorithm);
	tree->route_table_backup->cleanup = isis_route_node_cleanup;
}

void isis_spf_switchover_routes(struct isis_area *area,
				struct isis_spftree **trees, int family,
				union g_addr *nexthop_ip, ifindex_t ifindex,
				int level)
{
	isis_route_switchover_nexthop(area, trees[level - 1]->route_table,
				      family, nexthop_ip, ifindex);
}

static void isis_run_spf_cb(struct event *thread)
{
	struct isis_spf_run *run = EVENT_ARG(thread);
	struct isis_area *area = run->area;
	int level = run->level;
	int have_run = 0;
	struct listnode *node;
	struct isis_circuit *circuit;
#ifndef FABRICD
	struct flex_algo *fa;
	struct isis_flex_algo_data *data;
#endif /* ifndef FABRICD */

	XFREE(MTYPE_ISIS_SPF_RUN, run);

	if (!(area->is_type & level)) {
		if (IS_DEBUG_SPF_EVENTS)
			zlog_warn("ISIS-SPF (%s) area does not share level",
				  area->area_tag);
		return;
	}

	isis_area_delete_backup_adj_sids(area, level);
	isis_area_invalidate_routes(area, level);

	if (IS_DEBUG_SPF_EVENTS)
		zlog_debug("ISIS-SPF (%s) L%d SPF needed, periodic SPF",
			   area->area_tag, level);

	if (area->ip_circuits) {
		isis_run_spf_with_protection(
			area, area->spftree[SPFTREE_IPV4][level - 1]);
#ifndef FABRICD
		for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos, node,
					  fa)) {
			data = fa->data;
			isis_run_spf_with_protection(
				area, data->spftree[SPFTREE_IPV4][level - 1]);
		}
#endif /* ifndef FABRICD */
		have_run = 1;
	}
	if (area->ipv6_circuits) {
		isis_run_spf_with_protection(
			area, area->spftree[SPFTREE_IPV6][level - 1]);
#ifndef FABRICD
		for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos, node,
					  fa)) {
			data = fa->data;
			isis_run_spf_with_protection(
				area, data->spftree[SPFTREE_IPV6][level - 1]);
		}
#endif /* ifndef FABRICD */
		have_run = 1;
	}
	if (area->ipv6_circuits && isis_area_ipv6_dstsrc_enabled(area)) {
		isis_run_spf_with_protection(
			area, area->spftree[SPFTREE_DSTSRC][level - 1]);
		have_run = 1;
	}

	if (have_run)
		area->spf_run_count[level]++;

	isis_area_verify_routes(area);

	/* walk all circuits and reset any spf specific flags */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
		UNSET_FLAG(circuit->flags, ISIS_CIRCUIT_FLAPPED_AFTER_SPF);

	fabricd_run_spf(area);
}

static struct isis_spf_run *isis_run_spf_arg(struct isis_area *area, int level)
{
	struct isis_spf_run *run = XMALLOC(MTYPE_ISIS_SPF_RUN, sizeof(*run));

	run->area = area;
	run->level = level;

	return run;
}

void isis_spf_timer_free(void *run)
{
	XFREE(MTYPE_ISIS_SPF_RUN, run);
}

int _isis_spf_schedule(struct isis_area *area, int level,
		       const char *func, const char *file, int line)
{
	struct isis_spftree *spftree;
	time_t now;
	long tree_diff, diff;
	int tree;

	now = monotime(NULL);
	diff = 0;
	for (tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		spftree = area->spftree[tree][level - 1];
		tree_diff = difftime(now - spftree->last_run_monotime, 0);
		if (tree_diff != now && (diff == 0 || tree_diff < diff))
			diff = tree_diff;
	}

	if (CHECK_FLAG(im->options, F_ISIS_UNIT_TEST))
		return 0;

	assert(diff >= 0);
	assert(area->is_type & level);

	if (IS_DEBUG_SPF_EVENTS) {
		zlog_debug(
			"ISIS-SPF (%s) L%d SPF schedule called, lastrun %ld sec ago Caller: %s %s:%d",
			area->area_tag, level, diff, func, file, line);
	}

	EVENT_OFF(area->t_rlfa_rib_update);
	if (area->spf_delay_ietf[level - 1]) {
		/* Need to call schedule function also if spf delay is running
		 * to
		 * restart holdoff timer - compare
		 * draft-ietf-rtgwg-backoff-algo-04 */
		long delay =
			spf_backoff_schedule(area->spf_delay_ietf[level - 1]);
		if (area->spf_timer[level - 1])
			return ISIS_OK;

		event_add_timer_msec(master, isis_run_spf_cb,
				     isis_run_spf_arg(area, level), delay,
				     &area->spf_timer[level - 1]);
		return ISIS_OK;
	}

	if (area->spf_timer[level - 1])
		return ISIS_OK;

	/* wait configured min_spf_interval before doing the SPF */
	long timer;
	if (diff >= area->min_spf_interval[level - 1]
	    || area->bfd_force_spf_refresh) {
		/*
		 * Last run is more than min interval ago or BFD signalled a
		 * 'down' message, schedule immediate run
		 */
		timer = 0;

		if (area->bfd_force_spf_refresh) {
			zlog_debug(
				"ISIS-SPF (%s) L%d SPF scheduled immediately due to BFD 'down' message",
				area->area_tag, level);
			area->bfd_force_spf_refresh = false;
		}
	} else {
		timer = area->min_spf_interval[level - 1] - diff;
	}

	event_add_timer(master, isis_run_spf_cb, isis_run_spf_arg(area, level),
			timer, &area->spf_timer[level - 1]);

	if (IS_DEBUG_SPF_EVENTS)
		zlog_debug("ISIS-SPF (%s) L%d SPF scheduled %ld sec from now",
			   area->area_tag, level, timer);

	return ISIS_OK;
}

static void isis_print_paths(struct vty *vty, struct isis_vertex_queue *queue,
			     uint8_t *root_sysid, struct json_object **json)
{
	struct listnode *node;
	struct isis_vertex *vertex;
	char buff[VID2STR_BUFFER];
	char vertex_name[VID2STR_BUFFER];
	char vertex_typestr[VID2STR_BUFFER];
	char vertex_interface[VID2STR_BUFFER];
	char vertex_parent[VID2STR_BUFFER + 11];
	char vertex_nexthop[VID2STR_BUFFER];
	char vertex_metricstr[20];
	struct ttable *tt;
	char *table;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Vertex|Type|Metric|Next-Hop|Interface|Parent");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	for (ALL_QUEUE_ELEMENTS_RO(queue, node, vertex)) {
		if (VTYPE_IS(vertex->type)
		    && memcmp(vertex->N.id, root_sysid, ISIS_SYS_ID_LEN) == 0) {
			/* display here */
			ttable_add_row(tt, "%s|%s|%s|%s|%s|%s",
				       print_sys_hostname(root_sysid), "", "",
				       "", "", "");
			continue;
		}

		int rows = 0;
		struct listnode *anode = listhead(vertex->Adj_N);
		struct listnode *pnode = listhead(vertex->parents);
		struct isis_vertex_adj *vadj;
		struct isis_vertex *pvertex;

		snprintf(vertex_name, sizeof(vertex_name), "%s",
			 vid2string(vertex, buff, sizeof(buff)));
		snprintf(vertex_typestr, sizeof(vertex_typestr), "%s",
			 vtype2string(vertex->type));
		snprintf(vertex_metricstr, sizeof(vertex_metricstr), "%u",
			 vertex->d_N);
		for (unsigned int i = 0;
		     i < MAX(vertex->Adj_N ? listcount(vertex->Adj_N) : 0,
			     vertex->parents ? listcount(vertex->parents) : 0);
		     i++) {
			if (anode) {
				vadj = listgetdata(anode);
				anode = anode->next;
			} else {
				vadj = NULL;
			}

			if (pnode) {
				pvertex = listgetdata(pnode);
				pnode = pnode->next;
			} else {
				pvertex = NULL;
			}

			if (rows) {
				/* display here */
				ttable_add_row(tt, "%s|%s|%s|%s|%s|%s",
					       vertex_name, vertex_typestr,
					       vertex_metricstr, vertex_nexthop,
					       vertex_interface, vertex_parent);

				/* store the first 3 elements */
				vertex_name[0] = '\0';
				vertex_typestr[0] = '\0';
				vertex_metricstr[0] = '\0';
			}

			if (vadj) {
				struct isis_spf_adj *sadj = vadj->sadj;

				snprintf(vertex_nexthop, sizeof(vertex_nexthop),
					 "%s", print_sys_hostname(sadj->id));
				snprintf(vertex_interface,
					 sizeof(vertex_interface), "%s",
					 sadj->adj ? sadj->adj->circuit
							     ->interface->name
						   : "-");
			}

			if (pvertex) {
				if (!vadj) {
					vertex_nexthop[0] = '\0';
					vertex_interface[0] = '\0';
				}
				snprintf(vertex_parent, sizeof(vertex_parent),
					 "%s(%d)",
					 vid2string(pvertex, buff, sizeof(buff)),
					 pvertex->type);
			}

			++rows;
		}
		ttable_add_row(tt, "%s|%s|%s|%s|%s|%s", vertex_name,
			       vertex_typestr, vertex_metricstr, vertex_nexthop,
			       vertex_interface, vertex_parent);
	}
	if (json == NULL) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP_TTABLE, table);
	} else
		*json = ttable_json_with_json_text(
			tt, "ssdsss",
			"vertex|type|metric|nextHop|interface|parent");
	ttable_del(tt);
}

void isis_print_spftree(struct vty *vty, struct isis_spftree *spftree,
			struct json_object **json)
{
	const char *tree_id_text = NULL;

	if (!spftree || !isis_vertex_queue_count(&spftree->paths))
		return;

	switch (spftree->tree_id) {
	case SPFTREE_IPV4:
		tree_id_text = "that speak IP";
		break;
	case SPFTREE_IPV6:
		tree_id_text = "that speak IPv6";
		break;
	case SPFTREE_DSTSRC:
		tree_id_text = "that support IPv6 dst-src routing";
		break;
	case SPFTREE_COUNT:
		assert(!"isis_print_spftree shouldn't be called with SPFTREE_COUNT as type");
		return;
	}

	if (!json)
		vty_out(vty, "IS-IS paths to level-%d routers %s\n",
			spftree->level, tree_id_text);

	isis_print_paths(vty, &spftree->paths, spftree->sysid, json);
	if (!json)
		vty_out(vty, "\n");
}

static void show_isis_topology_common(struct vty *vty, int levels,
				      struct isis *isis, uint8_t algo,
				      json_object **json)
{
#ifndef FABRICD
	struct isis_flex_algo_data *fa_data;
	struct flex_algo *fa;
#endif /* ifndef FABRICD */
	struct isis_spftree *spftree;
	struct listnode *node;
	struct isis_area *area;
	json_object *json_level = NULL, *jstr = NULL, *json_val;
	char key[18];

	if (!isis->area_list || isis->area_list->count == 0)
		return;

	if (json)
		*json = json_object_new_object();

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
#ifndef FABRICD
		/*
		 * The shapes of the flex algo spftree 2-dimensional array
		 * and the area spftree 2-dimensional array are not guaranteed
		 * to be identical.
		 */
		fa = NULL;
		if (flex_algo_id_valid(algo)) {
			fa = flex_algo_lookup(area->flex_algos, algo);
			if (!fa)
				continue;
			fa_data = (struct isis_flex_algo_data *)fa->data;
		} else
			fa_data = NULL;
#endif /* ifndef FABRICD */

		if (json) {
			jstr = json_object_new_string(
				area->area_tag ? area->area_tag : "null");
			json_object_object_add(*json, "area", jstr);
			json_object_int_add(*json, "algorithm", algo);
		} else {
			vty_out(vty, "Area %s:",
				area->area_tag ? area->area_tag : "null");

#ifndef FABRICD
			if (algo != SR_ALGORITHM_SPF)
				vty_out(vty, " Algorithm %hhu\n", algo);
			else
#endif /* ifndef FABRICD */
				vty_out(vty, "\n");
		}

		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((level & levels) == 0)
				continue;

			if (json) {
				json_level = json_object_new_object();
				jstr = json_object_new_string(
					area->area_tag ? area->area_tag
						       : "null");
				json_object_object_add(json_level, "area", jstr);
			}

			if (area->ip_circuits > 0) {
				json_val = NULL;
#ifndef FABRICD
				if (fa_data)
					spftree = fa_data->spftree[SPFTREE_IPV4]
								  [level - 1];
				else
#endif /* ifndef FABRICD */
					spftree = area->spftree[SPFTREE_IPV4]
							       [level - 1];

				isis_print_spftree(vty, spftree,
						   json ? &json_val : NULL);
				if (json && json_val) {
					json_object_object_add(json_level,
							       "ipv4-paths",
							       json_val);
				}
			}
			if (area->ipv6_circuits > 0) {
				json_val = NULL;
#ifndef FABRICD
				if (fa_data)
					spftree = fa_data->spftree[SPFTREE_IPV6]
								  [level - 1];
				else
#endif /* ifndef FABRICD */
					spftree = area->spftree[SPFTREE_IPV6]
							       [level - 1];
				isis_print_spftree(vty, spftree,
						   json ? &json_val : NULL);
				if (json && json_val) {
					json_object_object_add(json_level,
							       "ipv6-paths",
							       json_val);
				}
			}
			if (isis_area_ipv6_dstsrc_enabled(area)) {
				json_val = NULL;
#ifndef FABRICD
				if (fa_data)
					spftree =
						fa_data->spftree[SPFTREE_DSTSRC]
								[level - 1];
				else
#endif /* ifndef FABRICD */
					spftree = area->spftree[SPFTREE_DSTSRC]
							       [level - 1];
				isis_print_spftree(vty, spftree,
						   json ? &json_val : NULL);
				if (json && json_val) {
					json_object_object_add(json_level,
							       "ipv6-dstsrc-paths",
							       json_val);
				}
			}
			if (json) {
				snprintf(key, sizeof(key), "level-%d", level);
				json_object_object_add(*json, key, json_level);
			}
		}

		if (fabricd_spftree(area)) {
			json_val = NULL;

			vty_out(vty,
				"IS-IS paths to level-2 routers with hop-by-hop metric\n");
			isis_print_paths(vty, &fabricd_spftree(area)->paths,
					 isis->sysid, json ? &json_val : NULL);
			if (json && json_val)
				json_object_object_add(json_level,
						       "fabricd-paths",
						       json_val);
			else
				vty_out(vty, "\n");
		}
		if (!json)
			vty_out(vty, "\n");
	}
}

DEFUN(show_isis_topology, show_isis_topology_cmd,
      "show " PROTO_NAME
      " [vrf <NAME|all>] topology"
#ifndef FABRICD
      " [<level-1|level-2>]"
      " [algorithm [(128-255)]]"
#endif /* ifndef FABRICD */
      " [json$uj]"
      ,
      SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
      "All VRFs\n"
      "IS-IS paths to Intermediate Systems\n"
#ifndef FABRICD
      "Paths to all level-1 routers in the area\n"
      "Paths to all level-2 routers in the domain\n"
      "Show Flex-algo routes\n"
      "Algorithm number\n"
#endif /* ifndef FABRICD */
      JSON_STR
)
{
	int levels = ISIS_LEVELS;
	struct listnode *node;
	struct isis *isis = NULL;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	bool all_algorithm = false;
	int idx_vrf = 0;
	uint16_t algorithm = SR_ALGORITHM_SPF;
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *json_vrf = NULL;

#ifndef FABRICD
	int idx = 0;

	levels = ISIS_LEVEL1 | ISIS_LEVEL2;
	if (argv_find(argv, argc, "level-1", &idx))
		levels = ISIS_LEVEL1;
	if (argv_find(argv, argc, "level-2", &idx))
		levels = ISIS_LEVEL2;
	if (argv_find(argv, argc, "algorithm", &idx)) {
		if (argv_find(argv, argc, "(128-255)", &idx))
			algorithm = (uint16_t)strtoul(argv[idx]->arg, NULL, 10);
		else
			all_algorithm = true;
	}
#endif /* ifndef FABRICD */

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}
	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (uj)
		json = json_object_new_array();

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
			if (all_algorithm) {
				for (algorithm = SR_ALGORITHM_FLEX_MIN;
				     algorithm <= SR_ALGORITHM_FLEX_MAX;
				     algorithm++)
					show_isis_topology_common(vty, levels,
								  isis,
								  (uint8_t)algorithm,
								  uj ? &json_vrf
								     : NULL);
			} else {
				show_isis_topology_common(vty, levels, isis,
							  (uint8_t)algorithm,
							  uj ? &json_vrf : NULL);
			}
			if (uj) {
				json_object_object_add(json_vrf, "vrf_id",
						       json_object_new_int(
							       isis->vrf_id));
				json_object_array_add(json, json_vrf);
			}
		}
		goto out;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis == NULL)
		return CMD_SUCCESS;
	if (all_algorithm) {
		for (algorithm = SR_ALGORITHM_FLEX_MIN;
		     algorithm <= SR_ALGORITHM_FLEX_MAX; algorithm++) {
			show_isis_topology_common(vty, levels, isis,
						  (uint8_t)algorithm,
						  uj ? &json_vrf : NULL);
		}
	} else
		show_isis_topology_common(vty, levels, isis, (uint8_t)algorithm,
					  uj ? &json_vrf : NULL);
	if (uj) {
		json_object_object_add(json_vrf, "vrf_id",
				       json_object_new_int(isis->vrf_id));
		json_object_array_add(json, json_vrf);
	}
out:
	if (uj) {
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(json,
						       JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

#ifndef FABRICD
static void show_isis_flex_algo_display_eag(struct vty *vty, char *buf,
					    int indent,
					    struct admin_group *admin_group)
{
	if (admin_group_zero(admin_group))
		vty_out(vty, "not-set\n");
	else {
		vty_out(vty, "%s\n",
			admin_group_string(buf, ADMIN_GROUP_PRINT_MAX_SIZE,
					   indent, admin_group));
		admin_group_print(buf, indent, admin_group);
		if (buf[0] != '\0')
			vty_out(vty, "            Bit positions: %s\n", buf);
	}
}

static void show_isis_flex_algo_common(struct vty *vty, struct isis *isis,
				       uint8_t algorithm)
{
	struct isis_router_cap_fad *router_fad;
	char buf[ADMIN_GROUP_PRINT_MAX_SIZE];
	struct admin_group *admin_group;
	struct isis_area *area;
	struct listnode *node;
	struct flex_algo *fa;
	int indent, algo;
	bool fad_identical, fad_supported;

	if (!isis->area_list || isis->area_list->count == 0)
		return;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		/*
		 * The shapes of the flex algo spftree 2-dimensional array
		 * and the area spftree 2-dimensional array are not guaranteed
		 * to be identical.
		 */

		for (algo = 0; algo < SR_ALGORITHM_COUNT; algo++) {
			if (algorithm != SR_ALGORITHM_UNSET &&
			    algorithm != algo)
				continue;

			fa = flex_algo_lookup(area->flex_algos, algo);
			if (!fa)
				continue;

			vty_out(vty, "Area %s:",
				area->area_tag ? area->area_tag : "null");

			vty_out(vty, " Algorithm %d\n", algo);
			vty_out(vty, "\n");

			vty_out(vty, " Enabled Data-Planes:");
			if (fa->dataplanes == 0) {
				vty_out(vty, " None\n\n");
				continue;
			}
			if (CHECK_FLAG(fa->dataplanes, FLEX_ALGO_SR_MPLS))
				vty_out(vty, " SR-MPLS");
			if (CHECK_FLAG(fa->dataplanes, FLEX_ALGO_SRV6))
				vty_out(vty, " SRv6");
			if (CHECK_FLAG(fa->dataplanes, FLEX_ALGO_IP))
				vty_out(vty, " IP");
			vty_out(vty, "\n\n");


			router_fad = isis_flex_algo_elected(algo, area);
			vty_out(vty,
				" Elected and running Flexible-Algorithm Definition:\n");
			if (router_fad)
				vty_out(vty, "  Source: %pSY\n",
					router_fad->sysid);
			else
				vty_out(vty, "  Source: Not found\n");

			if (!router_fad) {
				vty_out(vty, "\n");
				continue;
			}

			fad_identical =
				flex_algo_definition_cmp(fa, &router_fad->fad);
			fad_supported =
				isis_flex_algo_supported(&router_fad->fad);
			vty_out(vty, "  Priority: %d\n",
				router_fad->fad.priority);
			vty_out(vty, "  Equal to local: %s\n",
				fad_identical ? "yes" : "no");
			vty_out(vty, "  Local state: %s\n",
				fad_supported
					? "enabled"
					: "disabled (unsupported definition)");
			vty_out(vty, "  Calculation type: ");
			if (router_fad->fad.calc_type == 0)
				vty_out(vty, "spf\n");
			else
				vty_out(vty, "%d\n", router_fad->fad.calc_type);
			vty_out(vty, "  Metric type: %s\n",
				flex_algo_metric_type_print(
					buf, sizeof(buf),
					router_fad->fad.metric_type));
			vty_out(vty, "  Prefix-metric: %s\n",
				CHECK_FLAG(router_fad->fad.flags, FAD_FLAG_M)
					? "enabled"
					: "disabled");
			if (router_fad->fad.flags != 0 &&
			    router_fad->fad.flags != FAD_FLAG_M)
				vty_out(vty, "  Flags: 0x%x\n",
					router_fad->fad.flags);
			vty_out(vty, "  Exclude SRLG: %s\n",
				router_fad->fad.exclude_srlg ? "enabled"
							     : "disabled");

			admin_group = &router_fad->fad.admin_group_exclude_any;
			indent = vty_out(vty, "  Exclude-any admin-group: ");
			show_isis_flex_algo_display_eag(vty, buf, indent,
							admin_group);

			admin_group = &router_fad->fad.admin_group_include_all;
			indent = vty_out(vty, "  Include-all admin-group: ");
			show_isis_flex_algo_display_eag(vty, buf, indent,
							admin_group);

			admin_group = &router_fad->fad.admin_group_include_any;
			indent = vty_out(vty, "  Include-any admin-group: ");
			show_isis_flex_algo_display_eag(vty, buf, indent,
							admin_group);

			if (router_fad->fad.unsupported_subtlv)
				vty_out(vty,
					"  Unsupported sub-TLV: Present (see logs)");

			vty_out(vty, "\n");
		}
	}
}

DEFUN(show_isis_flex_algo, show_isis_flex_algo_cmd,
      "show " PROTO_NAME
      " [vrf <NAME|all>] flex-algo"
      " [(128-255)]",
      SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
      "All VRFs\n"
      "IS-IS Flex-algo information\n"
      "Algorithm number\n")
{
	struct isis *isis;
	struct listnode *node;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx = 0;
	int idx_vrf = 0;
	uint8_t flex_algo;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (argv_find(argv, argc, "flex-algo", &idx) && (idx + 1) < argc)
		flex_algo = (uint8_t)strtoul(argv[idx + 1]->arg, NULL, 10);
	else
		flex_algo = SR_ALGORITHM_UNSET;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis))
			show_isis_flex_algo_common(vty, isis, flex_algo);
		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL)
		show_isis_flex_algo_common(vty, isis, flex_algo);

	return CMD_SUCCESS;
}
#endif /* ifndef FABRICD */

static void isis_print_route(struct ttable *tt, const struct prefix *prefix,
			     struct isis_route_info *rinfo, bool prefix_sid,
			     bool no_adjacencies, bool json)
{
	struct isis_nexthop *nexthop;
	struct listnode *node;
	bool first = true;
	char buf_prefix[BUFSIZ];

	(void)prefix2str(prefix, buf_prefix, sizeof(buf_prefix));
	for (int alg = 0; alg < SR_ALGORITHM_COUNT; alg++) {
		for (ALL_LIST_ELEMENTS_RO(rinfo->sr_algo[alg].nexthops, node,
					  nexthop)) {
			struct interface *ifp;
			char buf_iface[BUFSIZ];
			char buf_nhop[BUFSIZ];

			if (!no_adjacencies) {
				inet_ntop(nexthop->family, &nexthop->ip,
					  buf_nhop, sizeof(buf_nhop));
				ifp = if_lookup_by_index(nexthop->ifindex,
							 VRF_DEFAULT);
				if (ifp)
					strlcpy(buf_iface, ifp->name,
						sizeof(buf_iface));
				else
					snprintf(buf_iface, sizeof(buf_iface),
						 "ifindex %u",
						 nexthop->ifindex);
			} else {
				strlcpy(buf_nhop,
					print_sys_hostname(nexthop->sysid),
					sizeof(buf_nhop));
				strlcpy(buf_iface, "-", sizeof(buf_iface));
			}

			if (prefix_sid) {
				char buf_sid[BUFSIZ] = {};
				char buf_lblop[BUFSIZ] = {};

				if (rinfo->sr_algo[alg].present) {
					snprintf(buf_sid, sizeof(buf_sid), "%u",
						 rinfo->sr_algo[alg].sid.value);
					sr_op2str(buf_lblop, sizeof(buf_lblop),
						  rinfo->sr_algo[alg].label,
						  nexthop->sr.label);
				} else if (alg == SR_ALGORITHM_SPF) {
					strlcpy(buf_sid, "-", sizeof(buf_sid));
					strlcpy(buf_lblop, "-",
						sizeof(buf_lblop));
				} else {
					continue;
				}

				if (first || json) {
					ttable_add_row(tt,
						       "%s|%u|%s|%s|%s|%s|%d",
						       buf_prefix, rinfo->cost,
						       buf_iface, buf_nhop,
						       buf_sid, buf_lblop, alg);
					first = false;
				} else
					ttable_add_row(tt, "||%s|%s|%s|%s|%d",
						       buf_iface, buf_nhop,
						       buf_sid, buf_lblop, alg);
			} else {
				char buf_labels[BUFSIZ] = {};

				if (nexthop->label_stack) {
					for (int i = 0;
					     i <
					     nexthop->label_stack->num_labels;
					     i++) {
						char buf_label[BUFSIZ];

						label2str(nexthop->label_stack
								  ->label[i],
							  0, buf_label,
							  sizeof(buf_label));
						if (i != 0)
							strlcat(buf_labels, "/",
								sizeof(buf_labels));
						strlcat(buf_labels, buf_label,
							sizeof(buf_labels));
					}
				} else if (nexthop->sr.present)
					label2str(nexthop->sr.label, 0,
						  buf_labels,
						  sizeof(buf_labels));
				else
					strlcpy(buf_labels, "-",
						sizeof(buf_labels));

				if (first || json) {
					ttable_add_row(tt, "%s|%u|%s|%s|%s",
						       buf_prefix, rinfo->cost,
						       buf_iface, buf_nhop,
						       buf_labels);
					first = false;
				} else
					ttable_add_row(tt, "||%s|%s|%s",
						       buf_iface, buf_nhop,
						       buf_labels);
			}
		}
	}

	if (list_isempty(rinfo->nexthops)) {
		if (prefix_sid) {
			char buf_sid[BUFSIZ] = {};
			char buf_lblop[BUFSIZ] = {};

			if (rinfo->sr_algo[SR_ALGORITHM_SPF].present) {
				snprintf(buf_sid, sizeof(buf_sid), "%u",
					 rinfo->sr_algo[SR_ALGORITHM_SPF]
						 .sid.value);
				sr_op2str(
					buf_lblop, sizeof(buf_lblop),
					rinfo->sr_algo[SR_ALGORITHM_SPF].label,
					MPLS_LABEL_IMPLICIT_NULL);
			} else {
				strlcpy(buf_sid, "-", sizeof(buf_sid));
				strlcpy(buf_lblop, "-", sizeof(buf_lblop));
			}

			ttable_add_row(tt, "%s|%u|%s|%s|%s|%s", buf_prefix,
				       rinfo->cost, "-", "-", buf_sid,
				       buf_lblop);
		} else
			ttable_add_row(tt, "%s|%u|%s|%s|%s", buf_prefix,
				       rinfo->cost, "-", "-", "-");
	}
}

void isis_print_routes(struct vty *vty, struct isis_spftree *spftree,
		       struct json_object **json, bool prefix_sid, bool backup)
{
	struct route_table *route_table;
	struct ttable *tt;
	struct route_node *rn;
	bool no_adjacencies = false;
	const char *tree_id_text = NULL;

	if (!spftree)
		return;

	switch (spftree->tree_id) {
	case SPFTREE_IPV4:
		tree_id_text = "IPv4";
		break;
	case SPFTREE_IPV6:
		tree_id_text = "IPv6";
		break;
	case SPFTREE_DSTSRC:
		tree_id_text = "IPv6 (dst-src routing)";
		break;
	case SPFTREE_COUNT:
		assert(!"isis_print_routes shouldn't be called with SPFTREE_COUNT as type");
		return;
	}

	if (json == NULL)
		vty_out(vty, "IS-IS %s %s routing table:\n\n",
			circuit_t2string(spftree->level), tree_id_text);

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	if (prefix_sid)
		ttable_add_row(
			tt,
			"Prefix|Metric|Interface|Nexthop|SID|Label Op.|Algo");
	else
		ttable_add_row(tt, "Prefix|Metric|Interface|Nexthop|Label(s)");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	if (CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ADJACENCIES))
		no_adjacencies = true;

	route_table =
		(backup) ? spftree->route_table_backup : spftree->route_table;
	for (rn = route_top(route_table); rn; rn = route_next(rn)) {
		struct isis_route_info *rinfo;

		rinfo = rn->info;
		if (!rinfo)
			continue;

		isis_print_route(tt, &rn->p, rinfo, prefix_sid, no_adjacencies,
				 json != NULL);
	}

	/* Dump the generated table. */
	if (json == NULL && tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP_TTABLE, table);
	} else if (json) {
		*json = ttable_json_with_json_text(
			tt, prefix_sid ? "sdssdsdd" : "sdsss",
			prefix_sid
				? "prefix|metric|interface|nextHop|segmentIdentifier|labelOperation|Algorithm"
				: "prefix|metric|interface|nextHop|label(s)");
	}
	ttable_del(tt);
}

static void show_isis_route_common(struct vty *vty, int levels,
				   struct isis *isis, bool prefix_sid,
				   bool backup, uint8_t algo,
				   json_object **json)
{
	json_object *json_level = NULL, *jstr = NULL, *json_val;
#ifndef FABRICD
	struct isis_flex_algo_data *fa_data;
	struct flex_algo *fa;
#endif /* ifndef FABRICD */
	struct isis_spftree *spftree;
	struct listnode *node;
	struct isis_area *area;
	char key[18];

	if (!isis->area_list || isis->area_list->count == 0)
		return;

	if (json)
		*json = json_object_new_object();

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
#ifndef FABRICD
		/*
		 * The shapes of the flex algo spftree 2-dimensional array
		 * and the area spftree 2-dimensional array are not guaranteed
		 * to be identical.
		 */
		fa = NULL;
		if (flex_algo_id_valid(algo)) {
			fa = flex_algo_lookup(area->flex_algos, algo);
			if (!fa)
				continue;
			fa_data = (struct isis_flex_algo_data *)fa->data;
		} else {
			fa_data = NULL;
		}
#endif /* ifndef FABRICD */

		if (json) {
			jstr = json_object_new_string(
				area->area_tag ? area->area_tag : "null");
			json_object_object_add(*json, "area", jstr);
			json_object_int_add(*json, "algorithm", algo);
		} else {
			vty_out(vty, "Area %s:",
				area->area_tag ? area->area_tag : "null");
#ifndef FABRICD
			if (algo != SR_ALGORITHM_SPF)
				vty_out(vty, " Algorithm %hhu\n", algo);
			else
#endif /* ifndef FABRICD */
				vty_out(vty, "\n");
		}

		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((level & levels) == 0)
				continue;

			if (json) {
				json_level = json_object_new_object();
				jstr = json_object_new_string(
					area->area_tag ? area->area_tag
						       : "null");
				json_object_object_add(json_level, "area",
						       jstr);
			}

			if (area->ip_circuits > 0) {
				json_val = NULL;
#ifndef FABRICD
				if (fa_data)
					spftree = fa_data->spftree[SPFTREE_IPV4]
								  [level - 1];
				else
#endif /* ifndef FABRICD */
					spftree = area->spftree[SPFTREE_IPV4]
							       [level - 1];

				isis_print_spftree(vty, spftree,
						   json ? &json_val : NULL);
				if (json && json_val) {
					json_object_object_add(json_level,
							       "ipv4-paths",
							       json_val);
					json_val = NULL;
				}

				isis_print_routes(vty, spftree,
						  json ? &json_val : NULL,
						  prefix_sid, backup);
				if (json && json_val) {
					json_object_object_add(
						json_level, "ipv4", json_val);
				}
			}
			if (area->ipv6_circuits > 0) {
				json_val = NULL;
#ifndef FABRICD
				if (fa_data)
					spftree = fa_data->spftree[SPFTREE_IPV6]
								  [level - 1];
				else
#endif /* ifndef FABRICD */
					spftree = area->spftree[SPFTREE_IPV6]
							       [level - 1];

				isis_print_spftree(vty, spftree,
						   json ? &json_val : NULL);
				if (json && json_val) {
					json_object_object_add(json_level,
							       "ipv6-paths",
							       json_val);
					json_val = NULL;
				}

				isis_print_routes(vty, spftree,
						  json ? &json_val : NULL,
						  prefix_sid, backup);
				if (json && json_val) {
					json_object_object_add(
						json_level, "ipv6", json_val);
				}
			}
			if (isis_area_ipv6_dstsrc_enabled(area)) {
				json_val = NULL;
#ifndef FABRICD
				if (fa_data)
					spftree =
						fa_data->spftree[SPFTREE_DSTSRC]
								[level - 1];
				else
#endif /* ifndef FABRICD */
					spftree = area->spftree[SPFTREE_DSTSRC]
							       [level - 1];

				isis_print_spftree(vty, spftree,
						   json ? &json_val : NULL);
				if (json && json_val) {
					json_object_object_add(json_level,
							       "ipv6-dstsrc-paths",
							       json_val);
					json_val = NULL;
				}
				isis_print_routes(vty, spftree,
						  json ? &json_val : NULL,
						  prefix_sid, backup);
				if (json && json_val) {
					json_object_object_add(json_level,
							       "ipv6-dstsrc",
							       json_val);
				}
			}
			if (json) {
				snprintf(key, sizeof(key), "level-%d", level);
				json_object_object_add(*json, key, json_level);
			}
		}
	}
}

static void show_isis_route_all_algos(struct vty *vty, int levels,
				      struct isis *isis, bool prefix_sid,
				      bool backup, json_object **json)
{
	uint16_t algo;

	json_object *json_algo = NULL, *json_algos = NULL;

	if (json) {
		*json = json_object_new_object();
		json_algos = json_object_new_array();
	}

	for (algo = SR_ALGORITHM_FLEX_MIN; algo <= SR_ALGORITHM_FLEX_MAX;
	     algo++) {
		show_isis_route_common(vty, levels, isis, prefix_sid, backup,
				       (uint8_t)algo, json ? &json_algo : NULL);
		if (!json)
			continue;
		if (json_object_object_length(json_algo) == 0) {
			json_object_free(json_algo);
			continue;
		}
		json_object_object_add(json_algo, "algorithm",
				       json_object_new_int(algo));
		json_object_array_add(json_algos, json_algo);
	}

	if (json)
		json_object_object_add(*json, "algorithms", json_algos);
}


DEFUN(show_isis_route, show_isis_route_cmd,
      "show " PROTO_NAME
      " [vrf <NAME|all>] route"
#ifndef FABRICD
      " [<level-1|level-2>]"
#endif /* ifndef FABRICD */
      " [prefix-sid] [backup]"
#ifndef FABRICD
      " [algorithm [(128-255)]]"
#endif /* ifndef FABRICD */
      " [json$uj]",
      SHOW_STR PROTO_HELP VRF_FULL_CMD_HELP_STR
      "IS-IS routing table\n"
#ifndef FABRICD
      "level-1 routes\n"
      "level-2 routes\n"
#endif /* ifndef FABRICD */
      "Show Prefix-SID information\n"
      "Show backup routes\n"
#ifndef FABRICD
      "Show Flex-algo routes\n"
      "Algorithm number\n"
#endif /* ifndef FABRICD */
      JSON_STR)
{
	int levels;
	struct isis *isis;
	struct listnode *node;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	bool all_algorithm = false;
	bool prefix_sid = false;
	bool backup = false;
	bool uj = use_json(argc, argv);
	int idx = 0;
	json_object *json = NULL, *json_vrf = NULL;
	uint8_t algorithm = SR_ALGORITHM_SPF;

	if (argv_find(argv, argc, "level-1", &idx))
		levels = ISIS_LEVEL1;
	else if (argv_find(argv, argc, "level-2", &idx))
		levels = ISIS_LEVEL2;
	else
		levels = ISIS_LEVEL1 | ISIS_LEVEL2;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}
	ISIS_FIND_VRF_ARGS(argv, argc, idx, vrf_name, all_vrf);

	if (argv_find(argv, argc, "prefix-sid", &idx))
		prefix_sid = true;
	if (argv_find(argv, argc, "backup", &idx))
		backup = true;

#ifndef FABRICD
	if (argv_find(argv, argc, "algorithm", &idx)) {
		if (argv_find(argv, argc, "(128-255)", &idx))
			algorithm = (uint8_t)strtoul(argv[idx]->arg, NULL, 10);
		else
			all_algorithm = true;
	}
#endif /* ifndef FABRICD */

	if (uj)
		json = json_object_new_array();

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
			if (all_algorithm)
				show_isis_route_all_algos(vty, levels, isis,
							  prefix_sid, backup,
							  uj ? &json_vrf : NULL);
			else
				show_isis_route_common(vty, levels, isis,
						       prefix_sid, backup,
						       algorithm,
						       uj ? &json_vrf : NULL);
			if (uj) {
				json_object_object_add(json_vrf, "vrf_id",
						       json_object_new_int(
							       isis->vrf_id));
				json_object_array_add(json, json_vrf);
			}
		}
		goto out;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL) {
		if (all_algorithm)
			show_isis_route_all_algos(vty, levels, isis, prefix_sid,
						  backup, uj ? &json_vrf : NULL);
		else
			show_isis_route_common(vty, levels, isis, prefix_sid,
					       backup, algorithm,
					       uj ? &json_vrf : NULL);
		if (uj) {
			json_object_object_add(json_vrf, "vrf_id",
					       json_object_new_int(isis->vrf_id));
			json_object_array_add(json, json_vrf);
		}
	}

out:
	if (uj) {
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return CMD_SUCCESS;
}

static void isis_print_frr_summary_line(struct ttable *tt,
					const char *protection,
					uint32_t counters[SPF_PREFIX_PRIO_MAX])
{
	uint32_t critical, high, medium, low, total;

	critical = counters[SPF_PREFIX_PRIO_CRITICAL];
	high = counters[SPF_PREFIX_PRIO_HIGH];
	medium = counters[SPF_PREFIX_PRIO_MEDIUM];
	low = counters[SPF_PREFIX_PRIO_LOW];
	total = critical + high + medium + low;

	ttable_add_row(tt, "%s|%u|%u|%u|%u|%u", protection, critical, high,
		       medium, low, total);
}

static void
isis_print_frr_summary_line_coverage(struct ttable *tt, const char *protection,
				     double counters[SPF_PREFIX_PRIO_MAX],
				     double total)
{
	double critical, high, medium, low;

	critical = counters[SPF_PREFIX_PRIO_CRITICAL] * 100;
	high = counters[SPF_PREFIX_PRIO_HIGH] * 100;
	medium = counters[SPF_PREFIX_PRIO_MEDIUM] * 100;
	low = counters[SPF_PREFIX_PRIO_LOW] * 100;
	total *= 100;

	ttable_add_row(tt, "%s|%.2f%%|%.2f%%|%.2f%%|%.2f%%|%.2f%%", protection,
		       critical, high, medium, low, total);
}

static void isis_print_frr_summary(struct vty *vty,
				   struct isis_spftree *spftree)
{
	struct ttable *tt;
	char *table;
	const char *tree_id_text = NULL;
	uint32_t protectd[SPF_PREFIX_PRIO_MAX] = {0};
	uint32_t unprotected[SPF_PREFIX_PRIO_MAX] = {0};
	double coverage[SPF_PREFIX_PRIO_MAX] = {0};
	uint32_t protected_total = 0, grand_total = 0;
	double coverage_total;

	if (!spftree)
		return;

	switch (spftree->tree_id) {
	case SPFTREE_IPV4:
		tree_id_text = "IPv4";
		break;
	case SPFTREE_IPV6:
		tree_id_text = "IPv6";
		break;
	case SPFTREE_DSTSRC:
		tree_id_text = "IPv6 (dst-src routing)";
		break;
	case SPFTREE_COUNT:
		assert(!"isis_print_frr_summary shouldn't be called with SPFTREE_COUNT as type");
		return;
	}

	vty_out(vty, " IS-IS %s %s Fast ReRoute summary:\n\n",
		circuit_t2string(spftree->level), tree_id_text);

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(
		tt,
		"Protection \\ Priority|Critical|High    |Medium  |Low     |Total");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	/* Compute unprotected and coverage totals. */
	for (int priority = SPF_PREFIX_PRIO_CRITICAL;
	     priority < SPF_PREFIX_PRIO_MAX; priority++) {
		uint32_t *lfa = spftree->lfa.protection_counters.lfa;
		uint32_t *rlfa = spftree->lfa.protection_counters.rlfa;
		uint32_t *tilfa = spftree->lfa.protection_counters.tilfa;
		uint32_t *ecmp = spftree->lfa.protection_counters.ecmp;
		uint32_t *total = spftree->lfa.protection_counters.total;

		protectd[priority] = lfa[priority] + rlfa[priority]
				     + tilfa[priority] + ecmp[priority];
		/* Safeguard to protect against possible inconsistencies. */
		if (protectd[priority] > total[priority])
			protectd[priority] = total[priority];
		unprotected[priority] = total[priority] - protectd[priority];
		protected_total += protectd[priority];
		grand_total += total[priority];

		if (!total[priority])
			coverage[priority] = 0;
		else
			coverage[priority] =
				protectd[priority] / (double)total[priority];
	}

	if (!grand_total)
		coverage_total = 0;
	else
		coverage_total = protected_total / (double)grand_total;

	/* Add rows. */
	isis_print_frr_summary_line(tt, "Classic LFA",
				    spftree->lfa.protection_counters.lfa);
	isis_print_frr_summary_line(tt, "Remote LFA",
				    spftree->lfa.protection_counters.rlfa);
	isis_print_frr_summary_line(tt, "Topology Independent LFA",
				    spftree->lfa.protection_counters.tilfa);
	isis_print_frr_summary_line(tt, "ECMP",
				    spftree->lfa.protection_counters.ecmp);
	isis_print_frr_summary_line(tt, "Unprotected", unprotected);
	isis_print_frr_summary_line_coverage(tt, "Protection coverage",
					     coverage, coverage_total);

	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP_TTABLE, table);
	ttable_del(tt);
}

static void show_isis_frr_summary_common(struct vty *vty, int levels,
					 struct isis *isis)
{
	struct listnode *node;
	struct isis_area *area;

	if (!isis->area_list || isis->area_list->count == 0)
		return;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((level & levels) == 0)
				continue;

			if (area->ip_circuits > 0) {
				isis_print_frr_summary(
					vty,
					area->spftree[SPFTREE_IPV4][level - 1]);
			}
			if (area->ipv6_circuits > 0) {
				isis_print_frr_summary(
					vty,
					area->spftree[SPFTREE_IPV6][level - 1]);
			}
			if (isis_area_ipv6_dstsrc_enabled(area)) {
				isis_print_frr_summary(
					vty, area->spftree[SPFTREE_DSTSRC]
							  [level - 1]);
			}
		}
	}
}

DEFUN(show_isis_frr_summary, show_isis_frr_summary_cmd,
      "show " PROTO_NAME
      " [vrf <NAME|all>] fast-reroute summary"
#ifndef FABRICD
      " [<level-1|level-2>]"
#endif
      ,
      SHOW_STR PROTO_HELP VRF_FULL_CMD_HELP_STR
      "IS-IS FRR information\n"
      "FRR summary\n"
#ifndef FABRICD
      "level-1 routes\n"
      "level-2 routes\n"
#endif
)
{
	int levels;
	struct isis *isis;
	struct listnode *node;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx = 0;

	if (argv_find(argv, argc, "level-1", &idx))
		levels = ISIS_LEVEL1;
	else if (argv_find(argv, argc, "level-2", &idx))
		levels = ISIS_LEVEL2;
	else
		levels = ISIS_LEVEL1 | ISIS_LEVEL2;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}
	ISIS_FIND_VRF_ARGS(argv, argc, idx, vrf_name, all_vrf);

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis))
			show_isis_frr_summary_common(vty, levels, isis);
		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL)
		show_isis_frr_summary_common(vty, levels, isis);

	return CMD_SUCCESS;
}

void isis_spf_init(void)
{
#ifndef FABRICD
	install_element(VIEW_NODE, &show_isis_flex_algo_cmd);
#endif /* ifndef FABRICD */
	install_element(VIEW_NODE, &show_isis_topology_cmd);
	install_element(VIEW_NODE, &show_isis_route_cmd);
	install_element(VIEW_NODE, &show_isis_frr_summary_cmd);

	/* Register hook(s). */
	hook_register(isis_adj_state_change_hook, spf_adj_state_change);
}

void isis_spf_print(struct isis_spftree *spftree, struct vty *vty)
{
	uint64_t last_run_duration = spftree->last_run_duration;

	vty_out(vty, "      last run elapsed  : ");
	vty_out_timestr(vty, spftree->last_run_timestamp);
	vty_out(vty, "\n");

	vty_out(vty, "      last run duration : %" PRIu64 " usec\n",
		last_run_duration);

	vty_out(vty, "      run count         : %u\n", spftree->runcount);
}
void isis_spf_print_json(struct isis_spftree *spftree, struct json_object *json)
{
	char uptime[MONOTIME_STRLEN];
	time_t cur;
	cur = time(NULL);
	cur -= spftree->last_run_timestamp;
	frrtime_to_interval(cur, uptime, sizeof(uptime));
	json_object_string_add(json, "last-run-elapsed", uptime);
	json_object_int_add(json, "last-run-duration-usec",
			    spftree->last_run_duration);
	json_object_int_add(json, "last-run-count", spftree->runcount);
}
