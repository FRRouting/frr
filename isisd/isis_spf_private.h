/*
 * IS-IS Rout(e)ing protocol                  - isis_spf_private.h
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
#ifndef ISIS_SPF_PRIVATE_H
#define ISIS_SPF_PRIVATE_H

#include "hash.h"
#include "jhash.h"
#include "skiplist.h"
#include "lib_errors.h"

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

struct prefix_pair {
	struct prefix dest;
	struct prefix_ipv6 src;
};

struct isis_vertex_adj {
	struct isis_spf_adj *sadj;
	struct isis_sr_psid_info sr;
	struct mpls_label_stack *label_stack;
	uint32_t lfa_metric;
};

/*
 * Triple <N, d(N), {Adj(N)}>
 */
struct isis_vertex {
	enum vertextype type;
	union {
		uint8_t id[ISIS_SYS_ID_LEN + 1];
		struct {
			struct prefix_pair p;
			struct isis_sr_psid_info sr;
			enum spf_prefix_priority priority;
		} ip;
	} N;
	uint32_t d_N;	  /* d(N) Distance from this IS      */
	uint16_t depth;	/* The depth in the imaginary tree */
	struct list *Adj_N;    /* {Adj(N)} next hop or neighbor list */
	struct list *parents;  /* list of parents for ECMP */
	struct hash *firsthops; /* first two hops to neighbor */
	uint64_t insert_counter;
	uint8_t flags;
};
#define F_ISIS_VERTEX_LFA_PROTECTED	0x01

/* Vertex Queue and associated functions */

struct isis_vertex_queue {
	union {
		struct skiplist *slist;
		struct list *list;
	} l;
	struct hash *hash;
	uint64_t insert_counter;
};

__attribute__((__unused__))
static unsigned isis_vertex_queue_hash_key(const void *vp)
{
	const struct isis_vertex *vertex = vp;

	if (VTYPE_IP(vertex->type)) {
		uint32_t key;

		key = prefix_hash_key(&vertex->N.ip.p.dest);
		key = jhash_1word(prefix_hash_key(&vertex->N.ip.p.src), key);
		return key;
	}

	return jhash(vertex->N.id, ISIS_SYS_ID_LEN + 1, 0x55aa5a5a);
}

__attribute__((__unused__))
static bool isis_vertex_queue_hash_cmp(const void *a, const void *b)
{
	const struct isis_vertex *va = a, *vb = b;

	if (va->type != vb->type)
		return false;

	if (VTYPE_IP(va->type)) {
		if (prefix_cmp(&va->N.ip.p.dest, &vb->N.ip.p.dest))
			return false;

		return prefix_cmp((const struct prefix *)&va->N.ip.p.src,
				  (const struct prefix *)&vb->N.ip.p.src)
		       == 0;
	}

	return memcmp(va->N.id, vb->N.id, ISIS_SYS_ID_LEN + 1) == 0;
}

/*
 * Compares vertizes for sorting in the TENT list. Returns true
 * if candidate should be considered before current, false otherwise.
 */
__attribute__((__unused__)) static int isis_vertex_queue_tent_cmp(const void *a,
								  const void *b)
{
	const struct isis_vertex *va = a;
	const struct isis_vertex *vb = b;

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

__attribute__((__unused__))
static struct skiplist *isis_vertex_queue_skiplist(void)
{
	return skiplist_new(0, isis_vertex_queue_tent_cmp, NULL);
}

__attribute__((__unused__))
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

void isis_vertex_del(struct isis_vertex *vertex);

bool isis_vertex_adj_exists(const struct isis_spftree *spftree,
			    const struct isis_vertex *vertex,
			    const struct isis_spf_adj *sadj);
void isis_vertex_adj_free(void *arg);
struct isis_vertex_adj *
isis_vertex_adj_add(struct isis_spftree *spftree, struct isis_vertex *vertex,
		    struct list *vadj_list, struct isis_spf_adj *sadj,
		    struct isis_prefix_sid *psid, bool last_hop);

__attribute__((__unused__))
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

__attribute__((__unused__))
static void isis_vertex_queue_free(struct isis_vertex_queue *queue)
{
	isis_vertex_queue_clear(queue);

	hash_free(queue->hash);
	queue->hash = NULL;

	if (queue->insert_counter) {
		skiplist_free(queue->l.slist);
		queue->l.slist = NULL;
	} else
		list_delete(&queue->l.list);
}

__attribute__((__unused__))
static unsigned int isis_vertex_queue_count(struct isis_vertex_queue *queue)
{
	return hashcount(queue->hash);
}

__attribute__((__unused__))
static void isis_vertex_queue_append(struct isis_vertex_queue *queue,
				     struct isis_vertex *vertex)
{
	assert(!queue->insert_counter);

	listnode_add(queue->l.list, vertex);

	struct isis_vertex *inserted;

	inserted = hash_get(queue->hash, vertex, hash_alloc_intern);
	assert(inserted == vertex);
}

__attribute__((__unused__))
static struct isis_vertex *isis_vertex_queue_last(struct isis_vertex_queue *queue)
{
	struct listnode *tail;

	assert(!queue->insert_counter);
	tail = listtail(queue->l.list);
	assert(tail);
	return listgetdata(tail);
}

__attribute__((__unused__))
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

__attribute__((__unused__))
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

__attribute__((__unused__))
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
	struct route_table *route_table;
	struct route_table *route_table_backup;
	struct lspdb_head *lspdb; /* link-state db */
	struct hash *prefix_sids; /* SR Prefix-SIDs. */
	struct list *sadj_list;
	struct isis_spf_nodes adj_nodes;
	struct isis_area *area;    /* back pointer to area */
	unsigned int runcount;     /* number of runs since uptime */
	time_t last_run_timestamp; /* last run timestamp as wall time for display */
	time_t last_run_monotime;  /* last run as monotime for scheduling */
	time_t last_run_duration;  /* last run duration in msec */

	enum spf_type type;
	uint8_t sysid[ISIS_SYS_ID_LEN];
	uint16_t mtid;
	int family;
	int level;
	enum spf_tree_id tree_id;
	struct {
		/* Original pre-failure local SPTs. */
		struct {
			struct isis_spftree *spftree;
			struct isis_spftree *spftree_reverse;
		} old;

		/* Protected resource. */
		struct lfa_protected_resource protected_resource;

		/* P-space and Q-space. */
		struct isis_spf_nodes p_space;
		struct isis_spf_nodes q_space;

		/* Remote LFA related information. */
		struct {
			/* List of RLFAs eligible to be installed. */
			struct rlfa_tree_head rlfas;

			/*
			 * RLFA post-convergence SPTs (needed to activate RLFAs
			 * once label information is received from LDP).
			 */
			struct list *pc_spftrees;

			/* RLFA maximum metric (or zero if absent). */
			uint32_t max_metric;
		} remote;

		/* Protection counters. */
		struct {
			uint32_t lfa[SPF_PREFIX_PRIO_MAX];
			uint32_t rlfa[SPF_PREFIX_PRIO_MAX];
			uint32_t tilfa[SPF_PREFIX_PRIO_MAX];
			uint32_t ecmp[SPF_PREFIX_PRIO_MAX];
			uint32_t total[SPF_PREFIX_PRIO_MAX];
		} protection_counters;
	} lfa;
	uint8_t flags;
};
#define F_SPFTREE_HOPCOUNT_METRIC 0x01
#define F_SPFTREE_NO_ROUTES 0x02
#define F_SPFTREE_NO_ADJACENCIES 0x04

__attribute__((__unused__))
static void isis_vertex_id_init(struct isis_vertex *vertex, const void *id,
				enum vertextype vtype)
{
	vertex->type = vtype;

	if (VTYPE_IS(vtype) || VTYPE_ES(vtype)) {
		memcpy(vertex->N.id, id, ISIS_SYS_ID_LEN + 1);
	} else if (VTYPE_IP(vtype)) {
		memcpy(&vertex->N.ip.p, id, sizeof(vertex->N.ip.p));
	} else {
		flog_err(EC_LIB_DEVELOPMENT, "Unknown Vertex Type");
	}
}

__attribute__((__unused__))
static struct isis_vertex *isis_find_vertex(struct isis_vertex_queue *queue,
					    const void *id,
					    enum vertextype vtype)
{
	struct isis_vertex querier;

	isis_vertex_id_init(&querier, id, vtype);
	return hash_lookup(queue->hash, &querier);
}

__attribute__((__unused__))
static struct isis_lsp *lsp_for_vertex(struct isis_spftree *spftree,
				       struct isis_vertex *vertex)
{
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];

	assert(VTYPE_IS(vertex->type));

	memcpy(lsp_id, vertex->N.id, ISIS_SYS_ID_LEN + 1);
	LSP_FRAGMENT(lsp_id) = 0;

	struct isis_lsp *lsp = lsp_search(spftree->lspdb, lsp_id);

	if (lsp && lsp->hdr.rem_lifetime != 0)
		return lsp;

	return NULL;
}

#define VID2STR_BUFFER SRCDEST2STR_BUFFER
const char *vtype2string(enum vertextype vtype);
const char *vid2string(const struct isis_vertex *vertex, char *buff, int size);

#endif
