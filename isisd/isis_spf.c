/*
 * IS-IS Rout(e)ing protocol                  - isis_spf.c
 *                                              The SPT algorithm
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2017        Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "log.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "if.h"
#include "table.h"
#include "spf_backoff.h"
#include "jhash.h"
#include "skiplist.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "dict.h"
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

DEFINE_MTYPE_STATIC(ISISD, ISIS_SPF_RUN, "ISIS SPF Run Info");

enum vertextype {
	VTYPE_PSEUDO_IS = 1,
	VTYPE_PSEUDO_TE_IS,
	VTYPE_NONPSEUDO_IS,
	VTYPE_NONPSEUDO_TE_IS,
	VTYPE_ES,
	VTYPE_IPREACH_INTERNAL,
	VTYPE_IPREACH_EXTERNAL,
	VTYPE_IPREACH_TE,
	VTYPE_IP6REACH_INTERNAL,
	VTYPE_IP6REACH_EXTERNAL
};

#define VTYPE_IS(t) ((t) >= VTYPE_PSEUDO_IS && (t) <= VTYPE_NONPSEUDO_TE_IS)
#define VTYPE_ES(t) ((t) == VTYPE_ES)
#define VTYPE_IP(t) ((t) >= VTYPE_IPREACH_INTERNAL && (t) <= VTYPE_IP6REACH_EXTERNAL)

/*
 * Triple <N, d(N), {Adj(N)}>
 */
union isis_N {
	uint8_t id[ISIS_SYS_ID_LEN + 1];
	struct prefix prefix;
};
struct isis_vertex {
	enum vertextype type;
	union isis_N N;
	uint32_t d_N;	  /* d(N) Distance from this IS      */
	uint16_t depth;	/* The depth in the imaginary tree */
	struct list *Adj_N;    /* {Adj(N)} next hop or neighbor list */
	struct list *parents;  /* list of parents for ECMP */
	uint64_t insert_counter;
};

/* Vertex Queue and associated functions */

struct isis_vertex_queue {
	union {
		struct skiplist *slist;
		struct list *list;
	} l;
	struct hash *hash;
	uint64_t insert_counter;
};

static unsigned isis_vertex_queue_hash_key(void *vp)
{
	struct isis_vertex *vertex = vp;

	if (VTYPE_IP(vertex->type))
		return prefix_hash_key(&vertex->N.prefix);

	return jhash(vertex->N.id, ISIS_SYS_ID_LEN + 1, 0x55aa5a5a);
}

static int isis_vertex_queue_hash_cmp(const void *a, const void *b)
{
	const struct isis_vertex *va = a, *vb = b;

	if (va->type != vb->type)
		return 0;

	if (VTYPE_IP(va->type))
		return prefix_cmp(&va->N.prefix, &vb->N.prefix) == 0;

	return memcmp(va->N.id, vb->N.id, ISIS_SYS_ID_LEN + 1) == 0;
}

/*
 * Compares vertizes for sorting in the TENT list. Returns true
 * if candidate should be considered before current, false otherwise.
 */
static int isis_vertex_queue_tent_cmp(void *a, void *b)
{
	struct isis_vertex *va = a;
	struct isis_vertex *vb = b;

	if (va->d_N < vb->d_N)
		return -1;

	if (va->d_N > vb->d_N)
		return 1;

	if (va->type < vb->type)
		return -1;

	if (va->type > vb->type)
		return 1;

	if (va->insert_counter < vb->insert_counter)
		return -1;

	if (va->insert_counter > vb->insert_counter)
		return 1;

	return 0;
}

static struct skiplist *isis_vertex_queue_skiplist(void)
{
	return skiplist_new(0, isis_vertex_queue_tent_cmp, NULL);
}

static void isis_vertex_queue_init(struct isis_vertex_queue *queue,
				   const char *name, bool ordered)
{
	if (ordered) {
		queue->insert_counter = 1;
		queue->l.slist = isis_vertex_queue_skiplist();
	} else {
		queue->insert_counter = 0;
		queue->l.list = list_new();
	}
	queue->hash = hash_create(isis_vertex_queue_hash_key,
				  isis_vertex_queue_hash_cmp, name);
}

static void isis_vertex_del(struct isis_vertex *vertex);

static void isis_vertex_queue_clear(struct isis_vertex_queue *queue)
{
	hash_clean(queue->hash, NULL);

	if (queue->insert_counter) {
		struct isis_vertex *vertex;
		while (0 == skiplist_first(queue->l.slist, NULL,
					   (void **)&vertex)) {
			isis_vertex_del(vertex);
			skiplist_delete_first(queue->l.slist);
		}
		queue->insert_counter = 1;
	} else {
		queue->l.list->del = (void (*)(void *))isis_vertex_del;
		list_delete_all_node(queue->l.list);
		queue->l.list->del = NULL;
	}
}

static void isis_vertex_queue_free(struct isis_vertex_queue *queue)
{
	isis_vertex_queue_clear(queue);

	hash_free(queue->hash);
	queue->hash = NULL;

	if (queue->insert_counter) {
		skiplist_free(queue->l.slist);
		queue->l.slist = NULL;
	} else
		list_delete_and_null(&queue->l.list);
}

static unsigned int isis_vertex_queue_count(struct isis_vertex_queue *queue)
{
	return hashcount(queue->hash);
}

static void isis_vertex_queue_append(struct isis_vertex_queue *queue,
				     struct isis_vertex *vertex)
{
	assert(!queue->insert_counter);

	listnode_add(queue->l.list, vertex);

	struct isis_vertex *inserted;

	inserted = hash_get(queue->hash, vertex, hash_alloc_intern);
	assert(inserted == vertex);
}

static void isis_vertex_queue_insert(struct isis_vertex_queue *queue,
				     struct isis_vertex *vertex)
{
	assert(queue->insert_counter);
	vertex->insert_counter = queue->insert_counter++;
	assert(queue->insert_counter != (uint64_t)-1);

	skiplist_insert(queue->l.slist, vertex, vertex);

	struct isis_vertex *inserted;
	inserted = hash_get(queue->hash, vertex, hash_alloc_intern);
	assert(inserted == vertex);
}

static struct isis_vertex *
isis_vertex_queue_pop(struct isis_vertex_queue *queue)
{
	assert(queue->insert_counter);

	struct isis_vertex *rv;

	if (skiplist_first(queue->l.slist, NULL, (void **)&rv))
		return NULL;

	skiplist_delete_first(queue->l.slist);
	hash_release(queue->hash, rv);

	return rv;
}

static void isis_vertex_queue_delete(struct isis_vertex_queue *queue,
				     struct isis_vertex *vertex)
{
	assert(queue->insert_counter);

	skiplist_delete(queue->l.slist, vertex, vertex);
	hash_release(queue->hash, vertex);
}

#define ALL_QUEUE_ELEMENTS_RO(queue, node, data)                               \
	ALL_LIST_ELEMENTS_RO((queue)->l.list, node, data)


/* End of vertex queue definitions */

struct isis_spftree {
	struct isis_vertex_queue paths; /* the SPT */
	struct isis_vertex_queue tents; /* TENT */
	struct isis_area *area;    /* back pointer to area */
	unsigned int runcount;     /* number of runs since uptime */
	time_t last_run_timestamp; /* last run timestamp as wall time for display */
	time_t last_run_monotime;  /* last run as monotime for scheduling */
	time_t last_run_duration;  /* last run duration in msec */

	uint16_t mtid;
	int family;
	int level;
};


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
	struct isis_adjacency *adj, *candidate = NULL;
	int comp;

	for (ALL_LIST_ELEMENTS_RO(adjs, node, adj)) {
		if (excess == NULL)
			excess = node;
		candidate = listgetdata(excess);

		if (candidate->sys_type < adj->sys_type) {
			excess = node;
			continue;
		}
		if (candidate->sys_type > adj->sys_type)
			continue;

		comp = memcmp(candidate->sysid, adj->sysid, ISIS_SYS_ID_LEN);
		if (comp > 0) {
			excess = node;
			continue;
		}
		if (comp < 0)
			continue;

		if (candidate->circuit->idx > adj->circuit->idx) {
			excess = node;
			continue;
		}

		if (candidate->circuit->idx < adj->circuit->idx)
			continue;

		comp = memcmp(candidate->snpa, adj->snpa, ETH_ALEN);
		if (comp > 0) {
			excess = node;
			continue;
		}
	}

	list_delete_node(adjs, excess);

	return;
}

static const char *vtype2string(enum vertextype vtype)
{
	switch (vtype) {
	case VTYPE_PSEUDO_IS:
		return "pseudo_IS";
		break;
	case VTYPE_PSEUDO_TE_IS:
		return "pseudo_TE-IS";
		break;
	case VTYPE_NONPSEUDO_IS:
		return "IS";
		break;
	case VTYPE_NONPSEUDO_TE_IS:
		return "TE-IS";
		break;
	case VTYPE_ES:
		return "ES";
		break;
	case VTYPE_IPREACH_INTERNAL:
		return "IP internal";
		break;
	case VTYPE_IPREACH_EXTERNAL:
		return "IP external";
		break;
	case VTYPE_IPREACH_TE:
		return "IP TE";
		break;
	case VTYPE_IP6REACH_INTERNAL:
		return "IP6 internal";
		break;
	case VTYPE_IP6REACH_EXTERNAL:
		return "IP6 external";
		break;
	default:
		return "UNKNOWN";
	}
	return NULL; /* Not reached */
}

static const char *vid2string(struct isis_vertex *vertex, char *buff, int size)
{
	if (VTYPE_IS(vertex->type) || VTYPE_ES(vertex->type)) {
		return print_sys_hostname(vertex->N.id);
	}

	if (VTYPE_IP(vertex->type)) {
		prefix2str((struct prefix *)&vertex->N.prefix, buff, size);
		return buff;
	}

	return "UNKNOWN";
}

static void isis_vertex_id_init(struct isis_vertex *vertex, union isis_N *n,
				enum vertextype vtype)
{
	vertex->type = vtype;

	if (VTYPE_IS(vtype) || VTYPE_ES(vtype)) {
		memcpy(vertex->N.id, n->id, ISIS_SYS_ID_LEN + 1);
	} else if (VTYPE_IP(vtype)) {
		memcpy(&vertex->N.prefix, &n->prefix, sizeof(struct prefix));
	} else {
		zlog_err("WTF!");
	}
}

static struct isis_vertex *isis_vertex_new(union isis_N *n,
					   enum vertextype vtype)
{
	struct isis_vertex *vertex;

	vertex = XCALLOC(MTYPE_ISIS_VERTEX, sizeof(struct isis_vertex));

	isis_vertex_id_init(vertex, n, vtype);

	vertex->Adj_N = list_new();
	vertex->parents = list_new();

	return vertex;
}

static void isis_vertex_del(struct isis_vertex *vertex)
{
	list_delete_and_null(&vertex->Adj_N);
	list_delete_and_null(&vertex->parents);

	memset(vertex, 0, sizeof(struct isis_vertex));
	XFREE(MTYPE_ISIS_VERTEX, vertex);

	return;
}

static void isis_vertex_adj_del(struct isis_vertex *vertex,
				struct isis_adjacency *adj)
{
	struct listnode *node, *nextnode;
	if (!vertex)
		return;
	for (node = listhead(vertex->Adj_N); node; node = nextnode) {
		nextnode = listnextnode(node);
		if (listgetdata(node) == adj)
			list_delete_node(vertex->Adj_N, node);
	}
	return;
}

struct isis_spftree *isis_spftree_new(struct isis_area *area)
{
	struct isis_spftree *tree;

	tree = XCALLOC(MTYPE_ISIS_SPFTREE, sizeof(struct isis_spftree));
	if (tree == NULL) {
		zlog_err("ISIS-Spf: isis_spftree_new Out of memory!");
		return NULL;
	}

	isis_vertex_queue_init(&tree->tents, "IS-IS SPF tents", true);
	isis_vertex_queue_init(&tree->paths, "IS-IS SPF paths", false);
	tree->area = area;
	tree->last_run_timestamp = 0;
	tree->last_run_monotime = 0;
	tree->last_run_duration = 0;
	tree->runcount = 0;
	return tree;
}

void isis_spftree_del(struct isis_spftree *spftree)
{
	isis_vertex_queue_free(&spftree->tents);
	isis_vertex_queue_free(&spftree->paths);
	XFREE(MTYPE_ISIS_SPFTREE, spftree);

	return;
}

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
	if (area->is_type & IS_LEVEL_1) {
		if (area->spftree[0] == NULL)
			area->spftree[0] = isis_spftree_new(area);
		if (area->spftree6[0] == NULL)
			area->spftree6[0] = isis_spftree_new(area);
	}

	if (area->is_type & IS_LEVEL_2) {
		if (area->spftree[1] == NULL)
			area->spftree[1] = isis_spftree_new(area);
		if (area->spftree6[1] == NULL)
			area->spftree6[1] = isis_spftree_new(area);
	}

	return;
}

void spftree_area_del(struct isis_area *area)
{
	if (area->is_type & IS_LEVEL_1) {
		if (area->spftree[0] != NULL) {
			isis_spftree_del(area->spftree[0]);
			area->spftree[0] = NULL;
		}
		if (area->spftree6[0]) {
			isis_spftree_del(area->spftree6[0]);
			area->spftree6[0] = NULL;
		}
	}

	if (area->is_type & IS_LEVEL_2) {
		if (area->spftree[1] != NULL) {
			isis_spftree_del(area->spftree[1]);
			area->spftree[1] = NULL;
		}
		if (area->spftree6[1] != NULL) {
			isis_spftree_del(area->spftree6[1]);
			area->spftree6[1] = NULL;
		}
	}

	return;
}

void spftree_area_adj_del(struct isis_area *area, struct isis_adjacency *adj)
{
	if (area->is_type & IS_LEVEL_1) {
		if (area->spftree[0] != NULL)
			isis_spftree_adj_del(area->spftree[0], adj);
		if (area->spftree6[0] != NULL)
			isis_spftree_adj_del(area->spftree6[0], adj);
	}

	if (area->is_type & IS_LEVEL_2) {
		if (area->spftree[1] != NULL)
			isis_spftree_adj_del(area->spftree[1], adj);
		if (area->spftree6[1] != NULL)
			isis_spftree_adj_del(area->spftree6[1], adj);
	}

	return;
}

/*
 * Find the system LSP: returns the LSP in our LSP database
 * associated with the given system ID.
 */
static struct isis_lsp *isis_root_system_lsp(struct isis_area *area, int level,
					     uint8_t *sysid)
{
	struct isis_lsp *lsp;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2];

	memcpy(lspid, sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(lspid) = 0;
	LSP_FRAGMENT(lspid) = 0;
	lsp = lsp_search(lspid, area->lspdb[level - 1]);
	if (lsp && lsp->hdr.rem_lifetime != 0)
		return lsp;
	return NULL;
}

/*
 * Add this IS to the root of SPT
 */
static struct isis_vertex *isis_spf_add_root(struct isis_spftree *spftree,
					     uint8_t *sysid)
{
	struct isis_vertex *vertex;
	struct isis_lsp *lsp;
#ifdef EXTREME_DEBUG
	char buff[PREFIX2STR_BUFFER];
#endif /* EXTREME_DEBUG */
	union isis_N n;

	memcpy(n.id, sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(n.id) = 0;

	lsp = isis_root_system_lsp(spftree->area, spftree->level, sysid);
	if (lsp == NULL)
		zlog_warn("ISIS-Spf: could not find own l%d LSP!",
			  spftree->level);

	vertex = isis_vertex_new(&n,
				 spftree->area->oldmetric
					 ? VTYPE_NONPSEUDO_IS
					 : VTYPE_NONPSEUDO_TE_IS);
	isis_vertex_queue_append(&spftree->paths, vertex);

#ifdef EXTREME_DEBUG
	zlog_debug("ISIS-Spf: added this IS  %s %s depth %d dist %d to PATHS",
		   vtype2string(vertex->type),
		   vid2string(vertex, buff, sizeof(buff)), vertex->depth,
		   vertex->d_N);
#endif /* EXTREME_DEBUG */

	return vertex;
}

static struct isis_vertex *isis_find_vertex(struct isis_vertex_queue *queue,
					    union isis_N *n,
					    enum vertextype vtype)
{
	struct isis_vertex querier;

	isis_vertex_id_init(&querier, n, vtype);
	return hash_lookup(queue->hash, &querier);
}

/*
 * Add a vertex to TENT sorted by cost and by vertextype on tie break situation
 */
static struct isis_vertex *isis_spf_add2tent(struct isis_spftree *spftree,
					     enum vertextype vtype, void *id,
					     uint32_t cost, int depth,
					     struct isis_adjacency *adj,
					     struct isis_vertex *parent)
{
	struct isis_vertex *vertex;
	struct listnode *node;
	struct isis_adjacency *parent_adj;
#ifdef EXTREME_DEBUG
	char buff[PREFIX2STR_BUFFER];
#endif

	assert(isis_find_vertex(&spftree->paths, id, vtype) == NULL);
	assert(isis_find_vertex(&spftree->tents, id, vtype) == NULL);
	vertex = isis_vertex_new(id, vtype);
	vertex->d_N = cost;
	vertex->depth = depth;

	if (parent) {
		listnode_add(vertex->parents, parent);
	}

	if (parent && parent->Adj_N && listcount(parent->Adj_N) > 0) {
		for (ALL_LIST_ELEMENTS_RO(parent->Adj_N, node, parent_adj))
			listnode_add(vertex->Adj_N, parent_adj);
	} else if (adj) {
		listnode_add(vertex->Adj_N, adj);
	}

#ifdef EXTREME_DEBUG
	zlog_debug(
		"ISIS-Spf: add to TENT %s %s %s depth %d dist %d adjcount %d",
		print_sys_hostname(vertex->N.id), vtype2string(vertex->type),
		vid2string(vertex, buff, sizeof(buff)), vertex->depth,
		vertex->d_N, listcount(vertex->Adj_N));
#endif /* EXTREME_DEBUG */

	isis_vertex_queue_insert(&spftree->tents, vertex);
	return vertex;
}

static void isis_spf_add_local(struct isis_spftree *spftree,
			       enum vertextype vtype, void *id,
			       struct isis_adjacency *adj, uint32_t cost,
			       struct isis_vertex *parent)
{
	struct isis_vertex *vertex;

	vertex = isis_find_vertex(&spftree->tents, id, vtype);

	if (vertex) {
		/* C.2.5   c) */
		if (vertex->d_N == cost) {
			if (adj)
				listnode_add(vertex->Adj_N, adj);
			/*       d) */
			if (listcount(vertex->Adj_N) > ISIS_MAX_PATH_SPLITS)
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
			isis_vertex_del(vertex);
		}
	}

	isis_spf_add2tent(spftree, vtype, id, cost, 1, adj, parent);
	return;
}

static void process_N(struct isis_spftree *spftree, enum vertextype vtype,
		      void *id, uint32_t dist, uint16_t depth,
		      struct isis_vertex *parent)
{
	struct isis_vertex *vertex;
#ifdef EXTREME_DEBUG
	char buff[PREFIX2STR_BUFFER];
#endif

	assert(spftree && parent);

	struct prefix p;
	if (vtype >= VTYPE_IPREACH_INTERNAL) {
		prefix_copy(&p, id);
		apply_mask(&p);
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
		zlog_debug(
			"ISIS-Spf: process_N %s %s %s dist %d already found from PATH",
			print_sys_hostname(vertex->N.id), vtype2string(vtype),
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
		zlog_debug(
			"ISIS-Spf: process_N %s %s %s dist %d parent %s adjcount %d",
			print_sys_hostname(vertex->N.id), vtype2string(vtype),
			vid2string(vertex, buff, sizeof(buff)), dist,
			(parent ? print_sys_hostname(parent->N.id) : "null"),
			(parent ? listcount(parent->Adj_N) : 0));
#endif /* EXTREME_DEBUG */
		if (vertex->d_N == dist) {
			struct listnode *node;
			struct isis_adjacency *parent_adj;
			for (ALL_LIST_ELEMENTS_RO(parent->Adj_N, node,
						  parent_adj))
				if (listnode_lookup(vertex->Adj_N, parent_adj)
				    == NULL)
					listnode_add(vertex->Adj_N, parent_adj);
			/*      2) */
			if (listcount(vertex->Adj_N) > ISIS_MAX_PATH_SPLITS)
				remove_excess_adjs(vertex->Adj_N);
			if (listnode_lookup(vertex->parents, parent) == NULL)
				listnode_add(vertex->parents, parent);
			return;
		} else if (vertex->d_N < dist) {
			return;
			/*      4) */
		} else {
			isis_vertex_queue_delete(&spftree->tents, vertex);
			isis_vertex_del(vertex);
		}
	}

#ifdef EXTREME_DEBUG
	zlog_debug("ISIS-Spf: process_N add2tent %s %s dist %d parent %s",
		   print_sys_hostname(id), vtype2string(vtype), dist,
		   (parent ? print_sys_hostname(parent->N.id) : "null"));
#endif /* EXTREME_DEBUG */

	isis_spf_add2tent(spftree, vtype, id, dist, depth, NULL, parent);
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
	if (lsp->hdr.seqno == 0) {
		zlog_warn(
			"isis_spf_process_lsp(): lsp with 0 seq_num - ignore");
		return ISIS_WARNING;
	}

#ifdef EXTREME_DEBUG
	zlog_debug("ISIS-Spf: process_lsp %s",
		   print_sys_hostname(lsp->hdr.lsp_id));
#endif /* EXTREME_DEBUG */

	if (no_overload) {
		if (pseudo_lsp || spftree->mtid == ISIS_MT_IPV4_UNICAST) {
			struct isis_oldstyle_reach *r;
			for (r = (struct isis_oldstyle_reach *)
					 lsp->tlvs->oldstyle_reach.head;
			     r; r = r->next) {
				/* C.2.6 a) */
				/* Two way connectivity */
				if (!memcmp(r->id, root_sysid, ISIS_SYS_ID_LEN))
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
					  (void *)r->id, dist, depth + 1,
					  parent);
			}
		}

		struct isis_item_list *te_neighs = NULL;
		if (pseudo_lsp || spftree->mtid == ISIS_MT_IPV4_UNICAST)
			te_neighs = &lsp->tlvs->extended_reach;
		else
			te_neighs = isis_lookup_mt_items(&lsp->tlvs->mt_reach,
							 spftree->mtid);

		struct isis_extended_reach *er;
		for (er = te_neighs
				  ? (struct isis_extended_reach *)
					    te_neighs->head
				  : NULL;
		     er; er = er->next) {
			if (!memcmp(er->id, root_sysid, ISIS_SYS_ID_LEN))
				continue;
			if (!pseudo_lsp
			    && !memcmp(er->id, null_sysid, ISIS_SYS_ID_LEN))
				continue;
			dist = cost + er->metric;
			process_N(spftree,
				  LSP_PSEUDO_ID(er->id) ? VTYPE_PSEUDO_TE_IS
							: VTYPE_NONPSEUDO_TE_IS,
				  (void *)er->id, dist, depth + 1, parent);
		}
	}

	if (!pseudo_lsp && spftree->family == AF_INET
	    && spftree->mtid == ISIS_MT_IPV4_UNICAST) {
		struct isis_item_list *reachs[] = {
			&lsp->tlvs->oldstyle_ip_reach,
			&lsp->tlvs->oldstyle_ip_reach_ext};

		for (unsigned int i = 0; i < array_size(reachs); i++) {
			vtype = i ? VTYPE_IPREACH_EXTERNAL
				  : VTYPE_IPREACH_INTERNAL;

			struct isis_oldstyle_ip_reach *r;
			for (r = (struct isis_oldstyle_ip_reach *)reachs[i]
					 ->head;
			     r; r = r->next) {
				dist = cost + r->metric;
				process_N(spftree, vtype, (void *)&r->prefix,
					  dist, depth + 1, parent);
			}
		}
	}

	if (!pseudo_lsp && spftree->family == AF_INET) {
		struct isis_item_list *ipv4_reachs;
		if (spftree->mtid == ISIS_MT_IPV4_UNICAST)
			ipv4_reachs = &lsp->tlvs->extended_ip_reach;
		else
			ipv4_reachs = isis_lookup_mt_items(
				&lsp->tlvs->mt_ip_reach, spftree->mtid);

		struct isis_extended_ip_reach *r;
		for (r = ipv4_reachs
				 ? (struct isis_extended_ip_reach *)
					   ipv4_reachs->head
				 : NULL;
		     r; r = r->next) {
			dist = cost + r->metric;
			process_N(spftree, VTYPE_IPREACH_TE, (void *)&r->prefix,
				  dist, depth + 1, parent);
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
			process_N(spftree, vtype, (void *)&r->prefix, dist,
				  depth + 1, parent);
		}
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

static int isis_spf_preload_tent(struct isis_spftree *spftree,
				 uint8_t *root_sysid,
				 struct isis_vertex *parent)
{
	struct isis_circuit *circuit;
	struct listnode *cnode, *anode, *ipnode;
	struct isis_adjacency *adj;
	struct isis_lsp *lsp;
	struct list *adj_list;
	struct list *adjdb;
	struct prefix_ipv4 *ipv4;
	struct prefix prefix;
	int retval = ISIS_OK;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];
	static uint8_t null_lsp_id[ISIS_SYS_ID_LEN + 2];
	struct prefix_ipv6 *ipv6;
	struct isis_circuit_mt_setting *circuit_mt;

	for (ALL_LIST_ELEMENTS_RO(spftree->area->circuit_list, cnode,
				  circuit)) {
		circuit_mt = circuit_lookup_mt_setting(circuit, spftree->mtid);
		if (circuit_mt && !circuit_mt->enabled)
			continue;
		if (circuit->state != C_STATE_UP)
			continue;
		if (!(circuit->is_type & spftree->level))
			continue;
		if (spftree->family == AF_INET && !circuit->ip_router)
			continue;
		if (spftree->family == AF_INET6 && !circuit->ipv6_router)
			continue;
		/*
		 * Add IP(v6) addresses of this circuit
		 */
		if (spftree->family == AF_INET) {
			prefix.family = AF_INET;
			for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, ipnode,
						  ipv4)) {
				prefix.u.prefix4 = ipv4->prefix;
				prefix.prefixlen = ipv4->prefixlen;
				apply_mask(&prefix);
				isis_spf_add_local(spftree,
						   VTYPE_IPREACH_INTERNAL,
						   &prefix, NULL, 0, parent);
			}
		}
		if (spftree->family == AF_INET6) {
			prefix.family = AF_INET6;
			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link,
						  ipnode, ipv6)) {
				prefix.prefixlen = ipv6->prefixlen;
				prefix.u.prefix6 = ipv6->prefix;
				apply_mask(&prefix);
				isis_spf_add_local(spftree,
						   VTYPE_IP6REACH_INTERNAL,
						   &prefix, NULL, 0, parent);
			}
		}
		if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			/*
			 * Add the adjacencies
			 */
			adj_list = list_new();
			adjdb = circuit->u.bc.adjdb[spftree->level - 1];
			isis_adj_build_up_list(adjdb, adj_list);
			if (listcount(adj_list) == 0) {
				list_delete_and_null(&adj_list);
				if (isis->debugs & DEBUG_SPF_EVENTS)
					zlog_debug(
						"ISIS-Spf: no L%d adjacencies on circuit %s",
						spftree->level,
						circuit->interface->name);
				continue;
			}
			for (ALL_LIST_ELEMENTS_RO(adj_list, anode, adj)) {
				if (!adj_has_mt(adj, spftree->mtid))
					continue;
				if (spftree->mtid == ISIS_MT_IPV4_UNICAST
				    && !speaks(adj->nlpids.nlpids,
					       adj->nlpids.count,
					       spftree->family))
					continue;
				switch (adj->sys_type) {
				case ISIS_SYSTYPE_ES:
					memcpy(lsp_id, adj->sysid,
					       ISIS_SYS_ID_LEN);
					LSP_PSEUDO_ID(lsp_id) = 0;
					isis_spf_add_local(
						spftree, VTYPE_ES, lsp_id, adj,
						circuit->te_metric
							[spftree->level - 1],
						parent);
					break;
				case ISIS_SYSTYPE_IS:
				case ISIS_SYSTYPE_L1_IS:
				case ISIS_SYSTYPE_L2_IS:
					memcpy(lsp_id, adj->sysid,
					       ISIS_SYS_ID_LEN);
					LSP_PSEUDO_ID(lsp_id) = 0;
					LSP_FRAGMENT(lsp_id) = 0;
					isis_spf_add_local(
						spftree,
						spftree->area->oldmetric
							? VTYPE_NONPSEUDO_IS
							: VTYPE_NONPSEUDO_TE_IS,
						lsp_id, adj,
						circuit->te_metric
							[spftree->level - 1],
						parent);
					lsp = lsp_search(
						lsp_id,
						spftree->area
							->lspdb[spftree->level
								- 1]);
					if (lsp == NULL
					    || lsp->hdr.rem_lifetime == 0)
						zlog_warn(
							"ISIS-Spf: No LSP %s found for IS adjacency "
							"L%d on %s (ID %u)",
							rawlspid_print(lsp_id),
							spftree->level,
							circuit->interface->name,
							circuit->circuit_id);
					break;
				case ISIS_SYSTYPE_UNKNOWN:
				default:
					zlog_warn(
						"isis_spf_preload_tent unknow adj type");
				}
			}
			list_delete_and_null(&adj_list);
			/*
			 * Add the pseudonode
			 */
			if (spftree->level == 1)
				memcpy(lsp_id, circuit->u.bc.l1_desig_is,
				       ISIS_SYS_ID_LEN + 1);
			else
				memcpy(lsp_id, circuit->u.bc.l2_desig_is,
				       ISIS_SYS_ID_LEN + 1);
			/* can happen during DR reboot */
			if (memcmp(lsp_id, null_lsp_id, ISIS_SYS_ID_LEN + 1)
			    == 0) {
				if (isis->debugs & DEBUG_SPF_EVENTS)
					zlog_debug(
						"ISIS-Spf: No L%d DR on %s (ID %d)",
						spftree->level,
						circuit->interface->name,
						circuit->circuit_id);
				continue;
			}
			adj = isis_adj_lookup(lsp_id, adjdb);
			/* if no adj, we are the dis or error */
			if (!adj && !circuit->u.bc.is_dr[spftree->level - 1]) {
				zlog_warn(
					"ISIS-Spf: No adjacency found from root "
					"to L%d DR %s on %s (ID %d)",
					spftree->level, rawlspid_print(lsp_id),
					circuit->interface->name,
					circuit->circuit_id);
				continue;
			}
			lsp = lsp_search(
				lsp_id,
				spftree->area->lspdb[spftree->level - 1]);
			if (lsp == NULL || lsp->hdr.rem_lifetime == 0) {
				zlog_warn(
					"ISIS-Spf: No lsp (%p) found from root "
					"to L%d DR %s on %s (ID %d)",
					(void *)lsp, spftree->level,
					rawlspid_print(lsp_id),
					circuit->interface->name,
					circuit->circuit_id);
				continue;
			}
			isis_spf_process_lsp(
				spftree, lsp,
				circuit->te_metric[spftree->level - 1], 0,
				root_sysid, parent);
		} else if (circuit->circ_type == CIRCUIT_T_P2P) {
			adj = circuit->u.p2p.neighbor;
			if (!adj || adj->adj_state != ISIS_ADJ_UP)
				continue;
			if (!adj_has_mt(adj, spftree->mtid))
				continue;
			switch (adj->sys_type) {
			case ISIS_SYSTYPE_ES:
				memcpy(lsp_id, adj->sysid, ISIS_SYS_ID_LEN);
				LSP_PSEUDO_ID(lsp_id) = 0;
				isis_spf_add_local(
					spftree, VTYPE_ES, lsp_id, adj,
					circuit->te_metric[spftree->level - 1],
					parent);
				break;
			case ISIS_SYSTYPE_IS:
			case ISIS_SYSTYPE_L1_IS:
			case ISIS_SYSTYPE_L2_IS:
				memcpy(lsp_id, adj->sysid, ISIS_SYS_ID_LEN);
				LSP_PSEUDO_ID(lsp_id) = 0;
				LSP_FRAGMENT(lsp_id) = 0;
				if (spftree->mtid != ISIS_MT_IPV4_UNICAST
				    || speaks(adj->nlpids.nlpids,
					      adj->nlpids.count,
					      spftree->family))
					isis_spf_add_local(
						spftree,
						spftree->area->oldmetric
							? VTYPE_NONPSEUDO_IS
							: VTYPE_NONPSEUDO_TE_IS,
						lsp_id, adj,
						circuit->te_metric
							[spftree->level - 1],
						parent);
				break;
			case ISIS_SYSTYPE_UNKNOWN:
			default:
				zlog_warn(
					"isis_spf_preload_tent unknown adj type");
				break;
			}
		} else if (circuit->circ_type == CIRCUIT_T_LOOPBACK) {
			continue;
		} else {
			zlog_warn("isis_spf_preload_tent unsupported media");
			retval = ISIS_WARNING;
		}
	}

	return retval;
}

/*
 * The parent(s) for vertex is set when added to TENT list
 * now we just put the child pointer(s) in place
 */
static void add_to_paths(struct isis_spftree *spftree,
			 struct isis_vertex *vertex)
{
	char buff[PREFIX2STR_BUFFER];

	if (isis_find_vertex(&spftree->paths, &vertex->N, vertex->type))
		return;
	isis_vertex_queue_append(&spftree->paths, vertex);

#ifdef EXTREME_DEBUG
	zlog_debug("ISIS-Spf: added %s %s %s depth %d dist %d to PATHS",
		   print_sys_hostname(vertex->N.id), vtype2string(vertex->type),
		   vid2string(vertex, buff, sizeof(buff)), vertex->depth,
		   vertex->d_N);
#endif /* EXTREME_DEBUG */

	if (VTYPE_IP(vertex->type)) {
		if (listcount(vertex->Adj_N) > 0)
			isis_route_create((struct prefix *)&vertex->N.prefix,
					  vertex->d_N, vertex->depth,
					  vertex->Adj_N, spftree->area,
					  spftree->level);
		else if (isis->debugs & DEBUG_SPF_EVENTS)
			zlog_debug(
				"ISIS-Spf: no adjacencies do not install route for "
				"%s depth %d dist %d",
				vid2string(vertex, buff, sizeof(buff)),
				vertex->depth, vertex->d_N);
	}

	return;
}

static void init_spt(struct isis_spftree *spftree, int mtid, int level,
		     int family)
{
	isis_vertex_queue_clear(&spftree->tents);
	isis_vertex_queue_clear(&spftree->paths);

	spftree->mtid = mtid;
	spftree->level = level;
	spftree->family = family;
	return;
}

static int isis_run_spf(struct isis_area *area, int level, int family,
			uint8_t *sysid, struct timeval *nowtv)
{
	int retval = ISIS_OK;
	struct isis_vertex *vertex;
	struct isis_vertex *root_vertex;
	struct isis_spftree *spftree = NULL;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];
	struct isis_lsp *lsp;
	struct route_table *table = NULL;
	struct timeval time_now;
	unsigned long long start_time, end_time;
	uint16_t mtid;

	/* Get time that can't roll backwards. */
	start_time = nowtv->tv_sec;
	start_time = (start_time * 1000000) + nowtv->tv_usec;

	if (family == AF_INET)
		spftree = area->spftree[level - 1];
	else if (family == AF_INET6)
		spftree = area->spftree6[level - 1];
	assert(spftree);
	assert(sysid);

	/* Make all routes in current route table inactive. */
	if (family == AF_INET)
		table = area->route_table[level - 1];
	else if (family == AF_INET6)
		table = area->route_table6[level - 1];

	isis_route_invalidate_table(area, table);

	/* We only support ipv4-unicast and ipv6-unicast as topologies for now
	 */
	if (family == AF_INET6)
		mtid = isis_area_ipv6_topology(area);
	else
		mtid = ISIS_MT_IPV4_UNICAST;

	/*
	 * C.2.5 Step 0
	 */
	init_spt(spftree, mtid, level, family);
	/*              a) */
	root_vertex = isis_spf_add_root(spftree, sysid);
	/*              b) */
	retval = isis_spf_preload_tent(spftree, sysid, root_vertex);
	if (retval != ISIS_OK) {
		zlog_warn("ISIS-Spf: failed to load TENT SPF-root:%s",
			  print_sys_hostname(sysid));
		goto out;
	}

	/*
	 * C.2.7 Step 2
	 */
	if (!isis_vertex_queue_count(&spftree->tents)
	    && (isis->debugs & DEBUG_SPF_EVENTS)) {
		zlog_warn("ISIS-Spf: TENT is empty SPF-root:%s",
			  print_sys_hostname(sysid));
	}

	while (isis_vertex_queue_count(&spftree->tents)) {
		vertex = isis_vertex_queue_pop(&spftree->tents);

#ifdef EXTREME_DEBUG
		zlog_debug(
			"ISIS-Spf: get TENT node %s %s depth %d dist %d to PATHS",
			print_sys_hostname(vertex->N.id),
			vtype2string(vertex->type), vertex->depth, vertex->d_N);
#endif /* EXTREME_DEBUG */

		add_to_paths(spftree, vertex);
		if (VTYPE_IS(vertex->type)) {
			memcpy(lsp_id, vertex->N.id, ISIS_SYS_ID_LEN + 1);
			LSP_FRAGMENT(lsp_id) = 0;
			lsp = lsp_search(lsp_id, area->lspdb[level - 1]);
			if (lsp && lsp->hdr.rem_lifetime != 0) {
				isis_spf_process_lsp(spftree, lsp, vertex->d_N,
						     vertex->depth, sysid,
						     vertex);
			} else {
				zlog_warn("ISIS-Spf: No LSP found for %s",
					  rawlspid_print(lsp_id));
			}
		}
	}

out:
	isis_route_validate(area);
	spftree->runcount++;
	spftree->last_run_timestamp = time(NULL);
	spftree->last_run_monotime = monotime(&time_now);
	end_time = time_now.tv_sec;
	end_time = (end_time * 1000000) + time_now.tv_usec;
	spftree->last_run_duration = end_time - start_time;

	return retval;
}

static int isis_run_spf_cb(struct thread *thread)
{
	struct isis_spf_run *run = THREAD_ARG(thread);
	struct isis_area *area = run->area;
	int level = run->level;
	int retval = ISIS_OK;

	XFREE(MTYPE_ISIS_SPF_RUN, run);
	area->spf_timer[level - 1] = NULL;

	if (!(area->is_type & level)) {
		if (isis->debugs & DEBUG_SPF_EVENTS)
			zlog_warn("ISIS-SPF (%s) area does not share level",
				  area->area_tag);
		return ISIS_WARNING;
	}

	if (isis->debugs & DEBUG_SPF_EVENTS)
		zlog_debug("ISIS-Spf (%s) L%d SPF needed, periodic SPF",
			   area->area_tag, level);

	if (area->ip_circuits)
		retval = isis_run_spf(area, level, AF_INET, isis->sysid,
				      &thread->real);
	if (area->ipv6_circuits)
		retval = isis_run_spf(area, level, AF_INET6, isis->sysid,
				      &thread->real);

	return retval;
}

static struct isis_spf_run *isis_run_spf_arg(struct isis_area *area, int level)
{
	struct isis_spf_run *run = XMALLOC(MTYPE_ISIS_SPF_RUN, sizeof(*run));

	run->area = area;
	run->level = level;

	return run;
}

int isis_spf_schedule(struct isis_area *area, int level)
{
	struct isis_spftree *spftree = area->spftree[level - 1];
	time_t now = monotime(NULL);
	int diff = now - spftree->last_run_monotime;

	assert(diff >= 0);
	assert(area->is_type & level);

	if (isis->debugs & DEBUG_SPF_EVENTS)
		zlog_debug(
			"ISIS-Spf (%s) L%d SPF schedule called, lastrun %d sec ago",
			area->area_tag, level, diff);

	if (area->spf_delay_ietf[level - 1]) {
		/* Need to call schedule function also if spf delay is running
		 * to
		 * restart holdoff timer - compare
		 * draft-ietf-rtgwg-backoff-algo-04 */
		long delay =
			spf_backoff_schedule(area->spf_delay_ietf[level - 1]);
		if (area->spf_timer[level - 1])
			return ISIS_OK;

		thread_add_timer_msec(master, isis_run_spf_cb,
				      isis_run_spf_arg(area, level), delay,
				      &area->spf_timer[level - 1]);
		return ISIS_OK;
	}

	if (area->spf_timer[level - 1])
		return ISIS_OK;

	/* wait configured min_spf_interval before doing the SPF */
	long timer;
	if (diff >= area->min_spf_interval[level - 1]) {
		/* Last run is more than min interval ago, schedule immediate run */
		timer = 0;
	} else {
		timer = area->min_spf_interval[level - 1] - diff;
	}

	thread_add_timer(master, isis_run_spf_cb, isis_run_spf_arg(area, level),
			 timer, &area->spf_timer[level - 1]);

	if (isis->debugs & DEBUG_SPF_EVENTS)
		zlog_debug("ISIS-Spf (%s) L%d SPF scheduled %ld sec from now",
			   area->area_tag, level, timer);

	return ISIS_OK;
}

static void isis_print_paths(struct vty *vty, struct isis_vertex_queue *queue,
			     uint8_t *root_sysid)
{
	struct listnode *node;
	struct isis_vertex *vertex;
	char buff[PREFIX2STR_BUFFER];

	vty_out(vty,
		"Vertex               Type         Metric Next-Hop             Interface Parent\n");

	for (ALL_QUEUE_ELEMENTS_RO(queue, node, vertex)) {
		if (memcmp(vertex->N.id, root_sysid, ISIS_SYS_ID_LEN) == 0) {
			vty_out(vty, "%-20s %-12s %-6s",
				print_sys_hostname(root_sysid), "", "");
			vty_out(vty, "%-30s\n", "");
			continue;
		}

		int rows = 0;
		struct listnode *anode = listhead(vertex->Adj_N);
		struct listnode *pnode = listhead(vertex->parents);
		struct isis_adjacency *adj;
		struct isis_vertex *pvertex;

		vty_out(vty, "%-20s %-12s %-6u ",
			vid2string(vertex, buff, sizeof(buff)),
			vtype2string(vertex->type), vertex->d_N);
		for (unsigned int i = 0;
		     i < MAX(vertex->Adj_N ? listcount(vertex->Adj_N) : 0,
			     vertex->parents ? listcount(vertex->parents) : 0);
		     i++) {
			if (anode) {
				adj = listgetdata(anode);
				anode = anode->next;
			} else {
				adj = NULL;
			}

			if (pnode) {
				pvertex = listgetdata(pnode);
				pnode = pnode->next;
			} else {
				pvertex = NULL;
			}

			if (rows) {
				vty_out(vty, "\n");
				vty_out(vty, "%-20s %-12s %-6s ", "", "", "");
			}

			if (adj) {
				vty_out(vty, "%-20s %-9s ",
					print_sys_hostname(adj->sysid),
					adj->circuit->interface->name);
			}

			if (pvertex) {
				if (!adj)
					vty_out(vty, "%-20s %-9s ", "", "");

				vty_out(vty, "%s(%d)",
					vid2string(pvertex, buff, sizeof(buff)),
					pvertex->type);
			}

			++rows;
		}
		vty_out(vty, "\n");
	}
}

DEFUN (show_isis_topology,
       show_isis_topology_cmd,
       "show isis topology [<level-1|level-2>]",
       SHOW_STR
       "IS-IS information\n"
       "IS-IS paths to Intermediate Systems\n"
       "Paths to all level-1 routers in the area\n"
       "Paths to all level-2 routers in the domain\n")
{
	int levels;
	struct listnode *node;
	struct isis_area *area;

	if (argc < 4)
		levels = ISIS_LEVEL1 | ISIS_LEVEL2;
	else if (strmatch(argv[3]->text, "level-1"))
		levels = ISIS_LEVEL1;
	else
		levels = ISIS_LEVEL2;

	if (!isis->area_list || isis->area_list->count == 0)
		return CMD_SUCCESS;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			if ((level & levels) == 0)
				continue;

			if (area->ip_circuits > 0 && area->spftree[level - 1]
			    && isis_vertex_queue_count(&area->spftree[level - 1]->paths) > 0) {
				vty_out(vty,
					"IS-IS paths to level-%d routers that speak IP\n",
					level);
				isis_print_paths(
					vty, &area->spftree[level - 1]->paths,
					isis->sysid);
				vty_out(vty, "\n");
			}
			if (area->ipv6_circuits > 0 && area->spftree6[level - 1]
			    && isis_vertex_queue_count(&area->spftree6[level - 1]->paths) > 0) {
				vty_out(vty,
					"IS-IS paths to level-%d routers that speak IPv6\n",
					level);
				isis_print_paths(
					vty, &area->spftree6[level - 1]->paths,
					isis->sysid);
				vty_out(vty, "\n");
			}
		}

		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

void isis_spf_cmds_init()
{
	install_element(VIEW_NODE, &show_isis_topology_cmd);
}

void isis_spf_print(struct isis_spftree *spftree, struct vty *vty)
{
	vty_out(vty, "      last run elapsed  : ");
	vty_out_timestr(vty, spftree->last_run_timestamp);
	vty_out(vty, "\n");

	vty_out(vty, "      last run duration : %u usec\n",
		(uint32_t)spftree->last_run_duration);

	vty_out(vty, "      run count         : %u\n", spftree->runcount);
}
