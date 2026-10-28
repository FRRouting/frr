// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Distributed Flooding Reduction (draft-ietf-lsr-distoptflood)
 *
 * Topology snapshot and per-LSP flooding decision (section 1.2.3).
 */

#include <zebra.h>

#include "memory.h"
#include "linklist.h"

#include "isisd/isisd.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_flood_reduction.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_FR_GRAPH, "ISIS flood reduction graph");
DEFINE_MTYPE_STATIC(ISISD, ISIS_FR_DATA, "ISIS flood reduction data");

#define FR_INF	UINT_MAX
#define FR_NONE UINT_MAX

struct isis_fr_graph {
	/* Number of (non-pseudonode) intermediate systems. */
	unsigned int n;
	/* System IDs, sorted; the index into this array is the node ID. */
	uint8_t (*sysid)[ISIS_SYS_ID_LEN];
	/* Two-way links in CSR form: neighbors of i are
	 * adj[adj_off[i]] .. adj[adj_off[i + 1] - 1], sorted.
	 */
	unsigned int *adj_off;
	unsigned int *adj;
	/* Per-root hop-count distance arrays, computed on demand. */
	unsigned int **dist;

	/* Scratch space reused by isis_fr_decide(). */
	unsigned int *queue;
	uint8_t *mark;
	uint8_t *visited;
	uint8_t *need;
};

/*
 * Graph construction
 */

/* Raw vertex: one per LSP originator, pseudonodes included. */
struct fr_vertex {
	uint8_t id[ISIS_SYS_ID_LEN + 1];
	unsigned int *out;
	unsigned int out_count;
	unsigned int out_alloc;
	unsigned int node; /* index in the final graph, FR_NONE for P-nodes */
};

struct fr_build {
	struct fr_vertex *v;
	unsigned int count;
};

static int fr_uint_cmp(const void *a, const void *b)
{
	unsigned int x = *(const unsigned int *)a;
	unsigned int y = *(const unsigned int *)b;

	return (x > y) - (x < y);
}

static int fr_vertex_key_cmp(const void *key, const void *elem)
{
	const struct fr_vertex *v = elem;

	return memcmp(key, v->id, sizeof(v->id));
}

static unsigned int fr_vertex_find(const struct fr_build *b, const uint8_t *id)
{
	const struct fr_vertex *v;

	v = bsearch(id, b->v, b->count, sizeof(*b->v), fr_vertex_key_cmp);
	return v ? (unsigned int)(v - b->v) : FR_NONE;
}

static void fr_vertex_add_out(struct fr_vertex *v, unsigned int target)
{
	if (v->out_count == v->out_alloc) {
		v->out_alloc = v->out_alloc ? v->out_alloc * 2 : 8;
		v->out = XREALLOC(MTYPE_ISIS_FR_DATA, v->out, v->out_alloc * sizeof(*v->out));
	}
	v->out[v->out_count++] = target;
}

/* Sort an index array in place and drop duplicates; returns new count. */
static unsigned int fr_sort_uniq(unsigned int *arr, unsigned int count)
{
	unsigned int i, j;

	if (count < 2)
		return count;

	qsort(arr, count, sizeof(*arr), fr_uint_cmp);
	for (i = 1, j = 1; i < count; i++) {
		if (arr[i] != arr[j - 1])
			arr[j++] = arr[i];
	}
	return j;
}

static bool fr_sorted_contains(const unsigned int *arr, unsigned int count, unsigned int value)
{
	return bsearch(&value, arr, count, sizeof(*arr), fr_uint_cmp) != NULL;
}

static bool fr_lsp_usable(const struct isis_lsp *lsp)
{
	return lsp->tlvs && lsp->hdr.rem_lifetime && lsp->hdr.seqno;
}

static void fr_add_reach(struct fr_build *b, unsigned int self, const uint8_t *id)
{
	unsigned int target;

	target = fr_vertex_find(b, id);
	if (target == FR_NONE || target == self)
		return;
	fr_vertex_add_out(&b->v[self], target);
}

static void fr_collect_reach(struct fr_build *b, unsigned int self, const struct isis_tlvs *tlvs)
{
	struct isis_oldstyle_reach *oreach;
	struct isis_extended_reach *er;
	struct isis_item_list *l;

	for (oreach = (struct isis_oldstyle_reach *)tlvs->oldstyle_reach.head; oreach;
	     oreach = oreach->next)
		fr_add_reach(b, self, oreach->id);

	for (er = (struct isis_extended_reach *)tlvs->extended_reach.head; er; er = er->next)
		fr_add_reach(b, self, er->id);

	/* Links in all topologies are used (RFC 5120). */
	for (l = isis_mt_items_first((struct isis_mt_item_list *)&tlvs->mt_reach); l;
	     l = isis_mt_items_next(l)) {
		for (er = (struct isis_extended_reach *)l->head; er; er = er->next)
			fr_add_reach(b, self, er->id);
	}
}

struct isis_fr_graph *isis_fr_graph_build(struct lspdb_head *lspdb)
{
	struct isis_fr_graph *g;
	struct fr_build b = {};
	struct isis_lsp *lsp;
	unsigned int i, j, k, n = 0, edges = 0;
	unsigned int **nadj;
	unsigned int *nadj_count, *nadj_alloc;

	g = XCALLOC(MTYPE_ISIS_FR_GRAPH, sizeof(*g));

	/* Pass 1: one vertex per usable fragment zero. The LSPDB is sorted
	 * by LSP ID, so the vertex array comes out sorted as well.
	 */
	frr_each (lspdb, lspdb, lsp) {
		if (LSP_FRAGMENT(lsp->hdr.lsp_id) == 0 && fr_lsp_usable(lsp))
			b.count++;
	}
	b.v = XCALLOC(MTYPE_ISIS_FR_DATA, (b.count ? b.count : 1) * sizeof(*b.v));
	i = 0;
	frr_each (lspdb, lspdb, lsp) {
		if (LSP_FRAGMENT(lsp->hdr.lsp_id) != 0 || !fr_lsp_usable(lsp))
			continue;
		memcpy(b.v[i].id, lsp->hdr.lsp_id, sizeof(b.v[i].id));
		b.v[i].node = FR_NONE;
		if (LSP_PSEUDO_ID(b.v[i].id) == 0)
			b.v[i].node = n++;
		i++;
	}

	/* Pass 2: directed reachability, from all fragments. */
	frr_each (lspdb, lspdb, lsp) {
		struct listnode *node;
		struct isis_lsp *frag;
		unsigned int self;

		if (LSP_FRAGMENT(lsp->hdr.lsp_id) != 0 || !fr_lsp_usable(lsp))
			continue;

		self = fr_vertex_find(&b, lsp->hdr.lsp_id);
		fr_collect_reach(&b, self, lsp->tlvs);
		if (lsp->lspu.frags) {
			for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag)) {
				if (fr_lsp_usable(frag))
					fr_collect_reach(&b, self, frag->tlvs);
			}
		}
	}
	for (i = 0; i < b.count; i++)
		b.v[i].out_count = fr_sort_uniq(b.v[i].out, b.v[i].out_count);

	/* Pass 3: two-way checked IS-to-IS links, with P-nodes collapsed
	 * so that an adjacency via a P-node counts as a single hop.
	 */
	nadj = XCALLOC(MTYPE_ISIS_FR_DATA, (n ? n : 1) * sizeof(*nadj));
	nadj_count = XCALLOC(MTYPE_ISIS_FR_DATA, (n ? n : 1) * sizeof(*nadj_count));
	nadj_alloc = XCALLOC(MTYPE_ISIS_FR_DATA, (n ? n : 1) * sizeof(*nadj_alloc));

	for (i = 0; i < b.count; i++) {
		struct fr_vertex *a = &b.v[i];

		if (a->node == FR_NONE)
			continue;

		for (j = 0; j < a->out_count; j++) {
			struct fr_vertex *t = &b.v[a->out[j]];

			if (!fr_sorted_contains(t->out, t->out_count, i))
				continue;

			for (k = 0; k < (t->node == FR_NONE ? t->out_count : 1); k++) {
				struct fr_vertex *u;
				unsigned int ui;

				if (t->node != FR_NONE) {
					u = t;
				} else {
					/* Member of a P-node: must point back at it. */
					ui = t->out[k];
					u = &b.v[ui];
					if (u == a || u->node == FR_NONE ||
					    !fr_sorted_contains(u->out, u->out_count, a->out[j]))
						continue;
				}

				if (nadj_count[a->node] == nadj_alloc[a->node]) {
					nadj_alloc[a->node] = nadj_alloc[a->node]
								      ? nadj_alloc[a->node] * 2
								      : 8;
					nadj[a->node] =
						XREALLOC(MTYPE_ISIS_FR_DATA, nadj[a->node],
							 nadj_alloc[a->node] * sizeof(**nadj));
				}
				nadj[a->node][nadj_count[a->node]++] = u->node;
			}
		}
	}

	/* Pack into the final graph. */
	g->n = n;
	g->sysid = XCALLOC(MTYPE_ISIS_FR_DATA, (n ? n : 1) * sizeof(*g->sysid));
	g->adj_off = XCALLOC(MTYPE_ISIS_FR_DATA, (n + 1) * sizeof(*g->adj_off));
	for (i = 0; i < b.count; i++) {
		if (b.v[i].node != FR_NONE)
			memcpy(g->sysid[b.v[i].node], b.v[i].id, ISIS_SYS_ID_LEN);
	}
	for (i = 0; i < n; i++) {
		nadj_count[i] = fr_sort_uniq(nadj[i], nadj_count[i]);
		edges += nadj_count[i];
	}
	g->adj = XCALLOC(MTYPE_ISIS_FR_DATA, (edges ? edges : 1) * sizeof(*g->adj));
	for (i = 0, k = 0; i < n; i++) {
		g->adj_off[i] = k;
		if (nadj_count[i])
			memcpy(&g->adj[k], nadj[i], nadj_count[i] * sizeof(*g->adj));
		k += nadj_count[i];
		XFREE(MTYPE_ISIS_FR_DATA, nadj[i]);
	}
	g->adj_off[n] = k;

	g->dist = XCALLOC(MTYPE_ISIS_FR_DATA, (n ? n : 1) * sizeof(*g->dist));
	g->queue = XCALLOC(MTYPE_ISIS_FR_DATA, (n ? n : 1) * sizeof(*g->queue));
	g->mark = XCALLOC(MTYPE_ISIS_FR_DATA, n ? n : 1);
	g->visited = XCALLOC(MTYPE_ISIS_FR_DATA, n ? n : 1);
	g->need = XCALLOC(MTYPE_ISIS_FR_DATA, n ? n : 1);

	XFREE(MTYPE_ISIS_FR_DATA, nadj);
	XFREE(MTYPE_ISIS_FR_DATA, nadj_count);
	XFREE(MTYPE_ISIS_FR_DATA, nadj_alloc);
	for (i = 0; i < b.count; i++)
		XFREE(MTYPE_ISIS_FR_DATA, b.v[i].out);
	XFREE(MTYPE_ISIS_FR_DATA, b.v);

	return g;
}

void isis_fr_graph_free(struct isis_fr_graph **graph)
{
	struct isis_fr_graph *g = *graph;

	if (!g)
		return;

	for (unsigned int i = 0; i < g->n; i++)
		XFREE(MTYPE_ISIS_FR_DATA, g->dist[i]);
	XFREE(MTYPE_ISIS_FR_DATA, g->dist);
	XFREE(MTYPE_ISIS_FR_DATA, g->sysid);
	XFREE(MTYPE_ISIS_FR_DATA, g->adj_off);
	XFREE(MTYPE_ISIS_FR_DATA, g->adj);
	XFREE(MTYPE_ISIS_FR_DATA, g->queue);
	XFREE(MTYPE_ISIS_FR_DATA, g->mark);
	XFREE(MTYPE_ISIS_FR_DATA, g->visited);
	XFREE(MTYPE_ISIS_FR_DATA, g->need);
	XFREE(MTYPE_ISIS_FR_GRAPH, *graph);
}

unsigned int isis_fr_graph_node_count(const struct isis_fr_graph *graph)
{
	return graph->n;
}

/*
 * Graph queries
 */

static int fr_sysid_key_cmp(const void *key, const void *elem)
{
	return memcmp(key, elem, ISIS_SYS_ID_LEN);
}

static unsigned int fr_node_find(const struct isis_fr_graph *g, const uint8_t *sysid)
{
	const uint8_t(*p)[ISIS_SYS_ID_LEN];

	p = bsearch(sysid, g->sysid, g->n, sizeof(*g->sysid), fr_sysid_key_cmp);
	return p ? (unsigned int)(p - g->sysid) : FR_NONE;
}

static bool fr_adjacent(const struct isis_fr_graph *g, unsigned int a, unsigned int b)
{
	return fr_sorted_contains(&g->adj[g->adj_off[a]], g->adj_off[a + 1] - g->adj_off[a], b);
}

/* Hop-count distances from root, cached until the graph is rebuilt. */
static const unsigned int *fr_dist(struct isis_fr_graph *g, unsigned int root)
{
	unsigned int *dist, head = 0, tail = 0;

	if (g->dist[root])
		return g->dist[root];

	dist = XMALLOC(MTYPE_ISIS_FR_DATA, g->n * sizeof(*dist));
	for (unsigned int i = 0; i < g->n; i++)
		dist[i] = FR_INF;

	dist[root] = 0;
	g->queue[tail++] = root;
	while (head < tail) {
		unsigned int u = g->queue[head++];

		for (unsigned int e = g->adj_off[u]; e < g->adj_off[u + 1]; e++) {
			unsigned int v = g->adj[e];

			if (dist[v] == FR_INF) {
				dist[v] = dist[u] + 1;
				g->queue[tail++] = v;
			}
		}
	}

	g->dist[root] = dist;
	return dist;
}

/*
 * Set mark[x] for every node x at the given depth that lies on *any*
 * shortest path from the root of dist to target. Walks the ECMP DAG
 * backwards from target.
 */
static void fr_mark_on_shortest_paths(struct isis_fr_graph *g, const unsigned int *dist,
				      unsigned int target, unsigned int depth, uint8_t *mark)
{
	unsigned int head = 0, tail = 0;

	if (dist[target] == FR_INF || dist[target] < depth)
		return;

	g->visited[target] = 1;
	g->queue[tail++] = target;
	while (head < tail) {
		unsigned int u = g->queue[head++];

		if (dist[u] == depth) {
			mark[u] = 1;
			continue;
		}

		for (unsigned int e = g->adj_off[u]; e < g->adj_off[u + 1]; e++) {
			unsigned int v = g->adj[e];

			if (dist[v] == dist[u] - 1 && !g->visited[v]) {
				g->visited[v] = 1;
				g->queue[tail++] = v;
			}
		}
	}

	for (unsigned int i = 0; i < tail; i++)
		g->visited[g->queue[i]] = 0;
}

/*
 * Flooding decision
 */

uint16_t isis_fr_lsp_hash(const uint8_t *lsp_id)
{
	uint8_t buf[ISIS_SYS_ID_LEN + 2];
	uint32_t c0 = 0, c1 = 0;

	memcpy(buf, lsp_id, sizeof(buf));
	LSP_FRAGMENT(buf) >>= 3;

	for (size_t i = 0; i < sizeof(buf); i++) {
		c0 += buf[i];
		c0 = (c0 & 0xff) + (c0 >> 8);
		c1 += c0;
		c1 = (c1 & 0xff) + (c1 >> 8);
	}

	return (uint16_t)((c1 << 8) | c0);
}

enum isis_fr_verdict isis_fr_decide(struct isis_fr_graph *g, const uint8_t *local,
				    const uint8_t *tn, const uint8_t *lsp_id,
				    unsigned int redundancy, const uint8_t nbrs[][ISIS_SYS_ID_LEN],
				    size_t n_nbrs, bool *flood, struct isis_fr_decision *decision)
{
	unsigned int li, ti, oi, step, rnl_count = 0, remaining = 0;
	const unsigned int *dtn, *dl;
	unsigned int *rnl;

	memset(decision, 0, sizeof(*decision));
	decision->verdict = ISIS_FR_FLOOD_ALL;
	for (size_t i = 0; i < n_nbrs; i++)
		flood[i] = true;

	if (redundancy == 0)
		redundancy = 1;
	if (redundancy > ISIS_FR_MAX_REDUNDANCY)
		redundancy = ISIS_FR_MAX_REDUNDANCY;

	li = fr_node_find(g, local);
	ti = fr_node_find(g, tn);
	oi = fr_node_find(g, lsp_id);
	if (li == FR_NONE || ti == FR_NONE || li == ti || !fr_adjacent(g, li, ti))
		return ISIS_FR_FLOOD_ALL;
	/* Our own LSPs follow standard procedures. */
	if (oi == li)
		return ISIS_FR_FLOOD_ALL;

	dtn = fr_dist(g, ti);
	dl = fr_dist(g, li);

	/*
	 * Step 1: Two-Hop List. Nodes on *any* shortest path from TN to
	 * the originator are excluded (step 1C.iii); they are strictly
	 * closer to the originator than TN and receive the LSP from
	 * that direction.
	 */
	if (oi != FR_NONE)
		fr_mark_on_shortest_paths(g, dtn, oi, 2, g->mark);
	for (unsigned int x = 0; x < g->n; x++) {
		if (dtn[x] != 2)
			continue;
		if (x == oi)
			continue;
		if (oi != FR_NONE && fr_adjacent(g, x, oi))
			continue;
		if (g->mark[x])
			continue;
		g->need[x] = redundancy;
		remaining++;
	}
	decision->thl_count = remaining;
	memset(g->mark, 0, g->n);

	/* Step 1D and 2: Remote Neighbor List, sorted by system ID (node
	 * indices are already in system ID order).
	 */
	rnl = g->queue;
	for (unsigned int x = 0; x < g->n; x++) {
		if (dtn[x] == 1)
			rnl[rnl_count++] = x;
	}
	decision->rnl_count = rnl_count;

	/* Step 3 */
	decision->start_index = isis_fr_lsp_hash(lsp_id) % rnl_count;

	/* Step 4 */
	for (step = 0; step < rnl_count && remaining; step++) {
		unsigned int m = rnl[(decision->start_index + step) % rnl_count];

		if (m == li) {
			decision->selected = true;
			break;
		}

		/*
		 * Step 4C (skip members running another flooding reduction
		 * extension) is intentionally not implemented: without it,
		 * mixed deployments rely on the partial flooding recovery
		 * mechanism to fill any gaps.
		 */

		for (unsigned int e = g->adj_off[m]; e < g->adj_off[m + 1]; e++) {
			unsigned int v = g->adj[e];

			if (g->need[v] && --g->need[v] == 0)
				remaining--;
		}
	}

	/* Stage 2: never flood towards the originator along any of our
	 * own shortest paths to it.
	 */
	if (oi != FR_NONE)
		fr_mark_on_shortest_paths(g, dl, oi, 1, g->mark);

	for (size_t i = 0; i < n_nbrs; i++) {
		unsigned int ni = fr_node_find(g, nbrs[i]);

		if (ni == FR_NONE || !fr_adjacent(g, li, ni)) {
			/* Not in the snapshot: can't reason about it. */
			flood[i] = true;
		} else if (ni == ti) {
			/* The LSP came from here: nothing is withheld. */
			flood[i] = false;
			continue;
		} else if (g->mark[ni]) {
			flood[i] = false;
		} else {
			/* Step 4B, tight scope: only the THL members we
			 * are adjacent to that are still uncovered.
			 */
			flood[i] = decision->selected && g->need[ni];
		}

		if (!flood[i])
			decision->suppressed++;
	}

	memset(g->mark, 0, g->n);
	memset(g->need, 0, g->n);

	decision->verdict = ISIS_FR_REDUCED;
	return ISIS_FR_REDUCED;
}
