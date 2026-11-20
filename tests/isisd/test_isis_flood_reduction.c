// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for IS-IS Distributed Flooding Reduction
 * (draft-ietf-lsr-distoptflood).
 */

#include <zebra.h>

#include "isisd/isisd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_flood_reduction.h"

#include "test_common.h"

#define MAX_TEST_NODES 64

static struct isis_area test_area = { .lsp_mtu = 1500 };

/* Test topology: plain adjacency matrix, turned into an LSPDB. */
struct topo {
	unsigned int n;
	uint8_t sysid[MAX_TEST_NODES][ISIS_SYS_ID_LEN];
	bool link[MAX_TEST_NODES][MAX_TEST_NODES];
};

static void topo_init(struct topo *t, unsigned int n)
{
	memset(t, 0, sizeof(*t));
	t->n = n;
	for (unsigned int i = 0; i < n; i++) {
		/* System IDs in the same order as node indices. */
		t->sysid[i][4] = (i + 1) >> 8;
		t->sysid[i][5] = (i + 1) & 0xff;
	}
}

static void topo_link(struct topo *t, unsigned int a, unsigned int b)
{
	t->link[a][b] = t->link[b][a] = true;
}

static struct isis_lsp *lspdb_add_lsp(struct lspdb_head *db, const uint8_t *sysid, uint8_t pnode,
				      uint8_t frag, struct isis_lsp *lsp0)
{
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2] = {};
	struct isis_lsp *lsp;

	memcpy(lsp_id, sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(lsp_id) = pnode;
	LSP_FRAGMENT(lsp_id) = frag;
	lsp = lsp_new(&test_area, lsp_id, 6000, 1, 0, 0, lsp0, ISIS_LEVEL2);
	lsp->tlvs = isis_alloc_tlvs();
	lspdb_add(db, lsp);
	return lsp;
}

static void lsp_add_is_reach(struct isis_lsp *lsp, const uint8_t *sysid, uint8_t pnode)
{
	uint8_t id[ISIS_SYS_ID_LEN + 1];

	memcpy(id, sysid, ISIS_SYS_ID_LEN);
	id[ISIS_SYS_ID_LEN] = pnode;
	isis_tlvs_add_extended_reach(lsp->tlvs, ISIS_MT_IPV4_UNICAST, id, 10, NULL);
}

static void topo_to_lspdb(const struct topo *t, struct lspdb_head *db)
{
	lsp_db_init(db);
	for (unsigned int i = 0; i < t->n; i++) {
		struct isis_lsp *lsp = lspdb_add_lsp(db, t->sysid[i], 0, 0, NULL);

		for (unsigned int j = 0; j < t->n; j++) {
			if (t->link[i][j])
				lsp_add_is_reach(lsp, t->sysid[j], 0);
		}
	}
}

/*
 * Flooding simulation: originator floods a new LSP to all neighbors,
 * every other node applies the decision on first receipt. Returns
 * the number of nodes that never received the LSP, and fills in the
 * total number of copies received.
 */
static unsigned int simulate(const struct topo *t, struct isis_fr_graph *g, unsigned int origin,
			     uint8_t frag, bool reduce, unsigned int redundancy, unsigned int seed,
			     unsigned int *copies)
{
	struct msg {
		unsigned int from, to;
	} *q;
	size_t qcap = MAX_TEST_NODES * MAX_TEST_NODES * 4, head = 0, tail = 0;
	bool have[MAX_TEST_NODES] = {};
	static bool sent[MAX_TEST_NODES][MAX_TEST_NODES];
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2] = {};
	unsigned int missing = 0;

	qcap *= 4;
	q = calloc(qcap, sizeof(*q));
	memcpy(lsp_id, t->sysid[origin], ISIS_SYS_ID_LEN);
	LSP_FRAGMENT(lsp_id) = frag;
	*copies = 0;

	memset(sent, 0, sizeof(sent));
	have[origin] = true;
	for (unsigned int j = 0; j < t->n; j++) {
		if (t->link[origin][j])
			q[tail++] = (struct msg){ origin, j };
	}

	srandom(seed);
	while (head < tail) {
		struct msg m;
		uint8_t nbrs[MAX_TEST_NODES][ISIS_SYS_ID_LEN];
		unsigned int nidx[MAX_TEST_NODES];
		bool flood[MAX_TEST_NODES];
		struct isis_fr_decision dec;
		size_t nn = 0;

		/* With a non-zero seed, deliver messages in random order
		 * to emulate asynchronous arrival.
		 */
		if (seed) {
			size_t pick = head + (size_t)random() % (tail - head);
			struct msg tmp = q[head];

			q[head] = q[pick];
			q[pick] = tmp;
		}
		m = q[head++];

		(*copies)++;
		sent[m.from][m.to] = sent[m.to][m.from] = true;
		if (have[m.to])
			continue;
		have[m.to] = true;

		for (unsigned int j = 0; j < t->n; j++) {
			if (t->link[m.to][j]) {
				memcpy(nbrs[nn], t->sysid[j], ISIS_SYS_ID_LEN);
				nidx[nn++] = j;
			}
		}

		if (reduce)
			isis_fr_decide(g, t->sysid[m.to], t->sysid[m.from], lsp_id, redundancy,
				       (const uint8_t(*)[ISIS_SYS_ID_LEN])nbrs, nn, flood, &dec);
		if (!reduce || dec.verdict == ISIS_FR_FLOOD_ALL) {
			for (size_t i = 0; i < nn; i++)
				flood[i] = true;
		}

		for (size_t i = 0; i < nn; i++) {
			if (flood[i] && nidx[i] != m.from && !sent[m.to][nidx[i]]) {
				sent[m.to][nidx[i]] = true;
				assert(tail < qcap);
				q[tail++] = (struct msg){ m.to, nidx[i] };
			}
		}
	}

	for (unsigned int i = 0; i < t->n; i++)
		if (!have[i])
			missing++;

	free(q);
	return missing;
}

/*
 * Section 1.2.3, Figure 2: reference checksums.
 */
static void test_hash(void)
{
	static const struct {
		uint8_t lsp_id[8];
		uint16_t hash;
		uint8_t mods[5];
	} vec[] = {
		{ { 1, 2, 3, 4, 5, 6, 0x00, 0x00 }, 0x6215, { 1, 2, 1, 4, 5 } },
		{ { 1, 2, 3, 4, 5, 6, 0x00, 0x07 }, 0x6215, { 1, 2, 1, 4, 5 } },
		{ { 1, 2, 3, 4, 5, 6, 0x00, 0x0F }, 0x6316, { 0, 1, 2, 1, 4 } },
		{ { 0, 1, 2, 3, 4, 5, 0x00, 0x01 }, 0x410F, { 1, 2, 3, 0, 5 } },
	};

	for (size_t i = 0; i < array_size(vec); i++) {
		uint16_t h = isis_fr_lsp_hash(vec[i].lsp_id);

		printfrr("hash %pLS = 0x%04x (expected 0x%04x)\n", vec[i].lsp_id, h, vec[i].hash);
		assert(h == vec[i].hash);
		for (unsigned int m = 2; m <= 6; m++)
			assert(h % m == vec[i].mods[m - 2]);
	}

	/* Fragments 0-7 hash together, 8 starts a new group. */
	{
		uint8_t id[8] = { 9, 8, 7, 6, 5, 4, 0, 0 };
		uint16_t h0 = isis_fr_lsp_hash(id);

		for (id[7] = 1; id[7] < 8; id[7]++)
			assert(isis_fr_lsp_hash(id) == h0);
	}
}

/*
 * Section 1.2.1 butterfly: 5 tiers of 6, each node connected to every
 * node in the adjacent tiers. Node index = tier * 6 + column.
 */
static void build_butterfly(struct topo *t, unsigned int width)
{
	topo_init(t, 5 * width);
	for (unsigned int tier = 0; tier < 4; tier++)
		for (unsigned int a = 0; a < width; a++)
			for (unsigned int b = 0; b < width; b++)
				topo_link(t, tier * width + a, (tier + 1) * width + b);
}

#define BF(tier, col) (((tier) - 1) * 6 + (col))

/* Appendix A: 5A floods to 4A-4F. */
static void test_appendix_a(void)
{
	struct topo t;
	struct lspdb_head db;
	struct isis_fr_graph *g;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2] = {};
	unsigned int selected = 0;

	build_butterfly(&t, 6);
	topo_to_lspdb(&t, &db);
	g = isis_fr_graph_build(&db);
	assert(isis_fr_graph_node_count(g) == 30);

	memcpy(lsp_id, t.sysid[BF(5, 0)], ISIS_SYS_ID_LEN);

	for (unsigned int c = 0; c < 6; c++) {
		unsigned int local = BF(4, c);
		uint8_t nbrs[MAX_TEST_NODES][ISIS_SYS_ID_LEN];
		unsigned int nidx[MAX_TEST_NODES];
		bool flood[MAX_TEST_NODES];
		struct isis_fr_decision dec;
		size_t nn = 0;

		for (unsigned int j = 0; j < t.n; j++) {
			if (t.link[local][j]) {
				memcpy(nbrs[nn], t.sysid[j], ISIS_SYS_ID_LEN);
				nidx[nn++] = j;
			}
		}

		isis_fr_decide(g, t.sysid[local], t.sysid[BF(5, 0)], lsp_id, 1,
			       (const uint8_t(*)[ISIS_SYS_ID_LEN])nbrs, nn, flood, &dec);

		assert(dec.verdict == ISIS_FR_REDUCED);
		/* THL: 3A-3F and 5B-5F; RNL: 4A-4F. */
		assert(dec.thl_count == 11);
		assert(dec.rnl_count == 6);

		printf("4%c: N=%u selected=%d suppressed=%u/%zu\n", 'A' + c, dec.start_index,
		       dec.selected, dec.suppressed, nn);

		if (dec.selected) {
			selected++;
			/* Exactly the RNL member at index N refloods... */
			assert(dec.start_index == c);
			/* ...to every THL member, and never back to 5A. */
			for (size_t i = 0; i < nn; i++)
				assert(flood[i] == (nidx[i] != BF(5, 0)));
		} else {
			for (size_t i = 0; i < nn; i++)
				assert(!flood[i]);
		}
	}
	assert(selected == 1);

	isis_fr_graph_free(&g);
	/* LSPs are not freed: lsp_destroy() needs a fully set up area. */
}

static void run_simulations(const char *name, const struct topo *t, unsigned int redundancy)
{
	struct lspdb_head db;
	struct isis_fr_graph *g;
	unsigned long full_total = 0, red_total = 0, rand_total = 0;
	unsigned int receivers = 0;
	unsigned long async_runs = 0, async_runs_with_holes = 0, async_missing = 0;

	topo_to_lspdb(t, &db);
	g = isis_fr_graph_build(&db);

	for (unsigned int o = 0; o < t->n; o++) {
		for (uint8_t frag = 0; frag < 32; frag += 8) {
			unsigned int copies;

			assert(simulate(t, g, o, frag, false, 1, 0, &copies) == 0);
			full_total += copies;

			if (simulate(t, g, o, frag, true, redundancy, 0, &copies) != 0) {
				printf("%s: incomplete flooding from node %u frag %u\n", name, o,
				       frag);
				assert(0);
			}
			red_total += copies;

			/* Asynchronous arrival order. */
			for (unsigned int seed = 1; seed <= 4; seed++) {
				unsigned int miss;

				miss = simulate(t, g, o, frag, true, redundancy, seed, &copies);
				if (miss) {
					async_runs_with_holes++;
					async_missing += miss;
				}
				rand_total += copies;
				async_runs++;
			}
			receivers += t->n - 1;
		}
	}

	printf("%s (redundancy %u): copies/node: standard %.2f, reduced %.2f, async %.2f\n",
	       name, redundancy, (double)full_total / receivers, (double)red_total / receivers,
	       (double)rand_total / (receivers * 4));
	printf("    async: %lu/%lu runs left %lu nodes without the LSP (recovered by PSNP/CSNP)\n",
	       async_runs_with_holes, async_runs, async_missing);
	assert(red_total < full_total);

	isis_fr_graph_free(&g);
	/* LSPs are not freed: lsp_destroy() needs a fully set up area. */
}

static void test_simulations(void)
{
	struct topo t;

	build_butterfly(&t, 6);
	run_simulations("butterfly 5x6", &t, 1);
	run_simulations("butterfly 5x6", &t, 2);

	/* Ring with chords: lots of ECMP, odd distances. */
	topo_init(&t, 24);
	for (unsigned int i = 0; i < 24; i++) {
		topo_link(&t, i, (i + 1) % 24);
		if (i % 3 == 0)
			topo_link(&t, i, (i + 7) % 24);
	}
	run_simulations("ring+chords 24", &t, 1);

	/* 4x4 grid torus. */
	topo_init(&t, 16);
	for (unsigned int r = 0; r < 4; r++)
		for (unsigned int c = 0; c < 4; c++) {
			topo_link(&t, r * 4 + c, r * 4 + (c + 1) % 4);
			topo_link(&t, r * 4 + c, ((r + 1) % 4) * 4 + c);
		}
	run_simulations("torus 4x4", &t, 1);

	/* Random connected graphs. */
	for (unsigned int seed = 1; seed <= 20; seed++) {
		char name[32];

		srandom(seed * 7919);
		topo_init(&t, 40);
		for (unsigned int i = 1; i < 40; i++)
			topo_link(&t, i, (unsigned int)random() % i);
		for (unsigned int e = 0; e < 60; e++) {
			unsigned int a = (unsigned int)random() % 40;
			unsigned int b = (unsigned int)random() % 40;

			if (a != b)
				topo_link(&t, a, b);
		}
		snprintfrr(name, sizeof(name), "random-%u", seed);
		run_simulations(name, &t, 1);
	}
}

/* Topology snapshot: P-node collapsing, two-way check, fragments. */
static void test_graph_build(void)
{
	struct lspdb_head db;
	struct isis_fr_graph *g;
	uint8_t s[5][ISIS_SYS_ID_LEN] = {};
	struct isis_lsp *l[5], *frag;
	uint8_t nbrs[4][ISIS_SYS_ID_LEN];
	bool flood[4];
	struct isis_fr_decision dec;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2] = {};

	for (int i = 0; i < 5; i++)
		s[i][5] = i + 1;

	/*
	 * S1, S2, S3 on a LAN with P-node S1.01.
	 * S3 - S4 point-to-point, listed in a non-zero fragment of S3.
	 * S4 -> S5 one-way only (S5 does not list S4).
	 */
	lsp_db_init(&db);
	for (int i = 0; i < 5; i++)
		l[i] = lspdb_add_lsp(&db, s[i], 0, 0, NULL);
	{
		struct isis_lsp *pn = lspdb_add_lsp(&db, s[0], 1, 0, NULL);

		for (int i = 0; i < 3; i++) {
			lsp_add_is_reach(l[i], s[0], 1);
			lsp_add_is_reach(pn, s[i], 0);
		}
	}
	frag = lspdb_add_lsp(&db, s[2], 0, 1, l[2]);
	lsp_add_is_reach(frag, s[3], 0);
	lsp_add_is_reach(l[3], s[2], 0);
	lsp_add_is_reach(l[3], s[4], 0);

	g = isis_fr_graph_build(&db);
	assert(isis_fr_graph_node_count(g) == 5);

	/*
	 * S3 receives an LSP originated by S1 from S2 (TN). From S2's
	 * view, S1 and S3 are one hop away (via the P-node) and S4 is two
	 * hops away. S5 is not connected (one-way link), so S4 is the
	 * only THL member and S3 the only RNL member that can cover it.
	 */
	memcpy(lsp_id, s[0], ISIS_SYS_ID_LEN);
	memcpy(nbrs[0], s[0], ISIS_SYS_ID_LEN);
	memcpy(nbrs[1], s[1], ISIS_SYS_ID_LEN);
	memcpy(nbrs[2], s[3], ISIS_SYS_ID_LEN);
	isis_fr_decide(g, s[2], s[1], lsp_id, 1, (const uint8_t(*)[ISIS_SYS_ID_LEN])nbrs, 3, flood,
		       &dec);
	assert(dec.verdict == ISIS_FR_REDUCED);
	assert(dec.rnl_count == 2); /* S1 and S3 */
	/* S4 is adjacent to neither S1 (originator) nor on a shortest
	 * path S2 -> S1, so it is in the THL.
	 */
	assert(dec.thl_count == 1);
	/* S1 is RNL index 0 but is not adjacent to S4, so the walk
	 * always reaches S3.
	 */
	assert(dec.selected);
	assert(!flood[0]); /* S1: originator, reverse path */
	assert(!flood[1]); /* S2: transmitting neighbor */
	assert(flood[2]);  /* S4 */

	/* An adjacency the snapshot does not know about is flooded to. */
	{
		uint8_t unknown[ISIS_SYS_ID_LEN] = { 0, 0, 0, 0, 0, 0x99 };

		memcpy(nbrs[3], unknown, ISIS_SYS_ID_LEN);
		isis_fr_decide(g, s[2], s[1], lsp_id, 1, (const uint8_t(*)[ISIS_SYS_ID_LEN])nbrs,
			       4, flood, &dec);
		assert(dec.verdict == ISIS_FR_REDUCED);
		assert(flood[3]);
	}

	/* Unknown TN: fall back to standard flooding. */
	isis_fr_decide(g, s[2], s[4], lsp_id, 1, (const uint8_t(*)[ISIS_SYS_ID_LEN])nbrs, 3, flood,
		       &dec);
	assert(dec.verdict == ISIS_FR_FLOOD_ALL);

	isis_fr_graph_free(&g);
	/* LSPs are not freed: lsp_destroy() needs a fully set up area. */
}

int main(int argc, char **argv)
{
	test_area.isis = calloc(1, sizeof(*test_area.isis));
	isis_circuit_list_init(&test_area.circuit_list);

	test_hash();
	test_graph_build();
	test_appendix_a();
	test_simulations();

	free(test_area.isis);
	printf("All tests passed.\n");
	return 0;
}
