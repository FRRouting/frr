// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Join/Prune group encoding tests.
 *
 * A PIM Join/Prune group record carries a joined source count, a pruned
 * source count and then all joined sources followed by all pruned
 * sources.  These tests encode a group with pim_jp_groups_fill() and
 * decode it the same way a receiving router does, making sure every
 * source ends up on the list (join or prune) it was meant for.
 */
#include <zebra.h>

#include "pimd/pim_join.c"

/* pimd globals not linked into this test */
static struct pim_router test_router;
struct pim_router *router = &test_router;
const pim_addr qpim_all_pim_routers_addr;

static struct pim_instance test_pim;
static struct pim_rpf test_rp_rpf;

/* Stubs for pimd functions pim_join.c references */
struct pim_rpf *pim_rp_g(struct pim_instance *pim, pim_addr group)
{
	return &test_rp_rpf;
}

bool pim_is_grp_dm(struct pim_instance *pim, pim_addr group_addr)
{
	return false;
}

void delete_on_noinfo(struct pim_ifchannel *ch)
{
}

bool pim_addr_is_multicast(pim_addr addr)
{
	return true;
}

void pim_channel_del_inherited_oif(struct channel_oil *c_oil, struct interface *oif,
				   const char *caller)
{
}

void pim_dm_recv_graft(struct interface *ifp, pim_sgaddr *sg)
{
}

void pim_dm_recv_prune(struct interface *ifp, struct pim_neighbor *neigh, uint16_t holdtime,
		       pim_addr upstream, pim_sgaddr *sg, uint8_t source_flags)
{
}

bool pim_filter_match(const struct pim_filter_ref *ref, const struct prefix_sg *sg,
		      struct interface *interface, struct interface *source_interface)
{
	return true;
}

void pim_sg_to_prefix(const pim_sgaddr *sg, struct prefix_sg *prefix)
{
}

void pim_hello_require(struct interface *ifp)
{
}

bool pim_iface_grp_dm(struct pim_interface *pim_ifp, pim_addr group_addr)
{
	return false;
}

void pim_ifchannel_find(struct interface *ifp, pim_sgaddr *sg, struct pim_ifchannel **ch,
			struct pim_ifchannel **chrpt)
{
	*ch = NULL;
	*chrpt = NULL;
}

void pim_ifchannel_join_add(struct interface *ifp, pim_addr neigh_addr, pim_addr upstream,
			    pim_sgaddr *sg, uint8_t source_flags, uint16_t holdtime)
{
}

void pim_ifchannel_prune(struct interface *ifp, pim_addr upstream, pim_sgaddr *sg,
			 uint8_t source_flags, uint16_t holdtime)
{
}

void pim_ifchannel_set_star_g_join_state(struct pim_ifchannel *ch, int eom, uint8_t join)
{
}

int pim_if_jp_hold(const struct pim_interface *pim_interface)
{
	return 0;
}

bool pim_is_group_filtered(struct pim_interface *pim_ifp, pim_addr *grp, pim_addr *src)
{
	return false;
}

int pim_is_grp_ssm(struct pim_instance *pim, pim_addr group_addr)
{
	return 0;
}

bool pim_is_rp_allowed(struct pim_interface *pim_ifp, pim_addr *rp)
{
	return true;
}

int pim_msg_send(int fd, pim_addr src, pim_addr dst, uint8_t *pim_msg, int pim_msg_size,
		 struct interface *ifp)
{
	return 0;
}

int pim_rpf_is_same(struct pim_rpf *rpf1, struct pim_rpf *rpf2)
{
	return 0;
}

int pim_upstream_empty_inherited_olist(struct pim_upstream *up)
{
	return 0;
}

struct pim_upstream *pim_upstream_find(struct pim_instance *pim, pim_sgaddr *sg)
{
	return NULL;
}

/* Test scaffolding */
#define GROUP_ADDR "226.1.1.2"
#define RP_ADDR    "1.0.2.2"
#define S_JOIN	   "10.0.4.2" /* (S,G) joined on the SPT */
#define S_JOIN2	    "10.0.4.3" /* another (S,G) joined on the SPT */
#define S_RPT_PRUNE "10.0.5.2" /* (S,G,rpt) pruned off the RPT */
#define S_PRUNE	   "10.0.6.2" /* explicit (S,G) prune */

struct decoded_source {
	pim_addr src;
	uint8_t flags;
	bool is_join;
	size_t record;
};

static int failures;

static pim_addr addr(const char *str)
{
	pim_addr a;

	assert(inet_pton(PIM_AF, str, &a) == 1);
	return a;
}

static void upstream_init(struct pim_upstream *up, const char *src)
{
	memset(up, 0, sizeof(*up));
	up->pim = &test_pim;
	up->sg.grp = addr(GROUP_ADDR);
	if (src)
		up->sg.src = addr(src);
}

static void jp_source_add(struct list *sources, struct pim_jp_sources *js, struct pim_upstream *up,
			  bool is_join)
{
	js->up = up;
	js->is_join = is_join;
	listnode_add(sources, js);
}

/*
 * Decode one group record exactly like pim_joinprune_recv(): the first
 * `joins` sources are joins and the next `prunes` sources are prunes.
 */
static size_t decode_group(const uint8_t *buf, size_t len, struct decoded_source *out,
			   size_t out_count)
{
	pim_sgaddr sg = {};
	uint16_t joins, prunes;
	int off, n;
	size_t i;

	off = pim_parse_addr_group(&sg, buf, len);
	assert(off > 0);

	memcpy(&joins, buf + off, sizeof(joins));
	memcpy(&prunes, buf + off + 2, sizeof(prunes));
	joins = ntohs(joins);
	prunes = ntohs(prunes);
	off += 4;

	assert(out_count + joins + prunes <= 8);
	for (i = 0; i < (size_t)(joins + prunes); i++) {
		struct decoded_source *ds = &out[out_count + i];

		n = pim_parse_addr_source(&sg, &ds->flags, buf + off, len - off);
		assert(n > 0);
		off += n;
		ds->src = sg.src;
		ds->is_join = i < joins;
	}
	assert((size_t)off == len);

	return out_count + joins + prunes;
}

/*
 * Encode the group with at most `max_sources` sources per group record,
 * the way pim_jp_send() splits a group over several packets, and decode
 * every record.
 */
static size_t encode_and_decode(struct pim_jp_agg_group *sgs, size_t max_sources,
				struct decoded_source *out)
{
	struct listnode *last_source = NULL;
	uint8_t buf[512];
	struct pim_jp_groups *grp = (struct pim_jp_groups *)buf;
	size_t bytes_left = sizeof(pim_encoded_group) + 4 +
			    max_sources * sizeof(pim_encoded_source);
	size_t count = 0, written, record = 0, first, i;

	do {
		written = pim_jp_groups_fill(grp, sgs, bytes_left, true, &last_source);
		assert(written > 0);

		grp->joins = htons(grp->joins);
		grp->prunes = htons(grp->prunes);
		first = count;
		count = decode_group(buf, written, out, count);
		for (i = first; i < count; i++)
			out[i].record = record;
		record++;
	} while (last_source);

	return count;
}

static void expect(const char *name, struct decoded_source *ds, size_t count, const char *src,
		   bool is_join, uint8_t flags)
{
	pim_addr want = src ? addr(src) : addr(RP_ADDR);
	size_t found = 0;
	size_t i;

	for (i = 0; i < count; i++) {
		if (pim_addr_cmp(ds[i].src, want))
			continue;
		found++;
		if (ds[i].is_join != is_join || ds[i].flags != flags) {
			printf("%s: %s decoded as %s flags 0x%02x, expected %s flags 0x%02x\n",
			       name, src ? src : "(*,G)", ds[i].is_join ? "join" : "prune",
			       ds[i].flags, is_join ? "join" : "prune", flags);
			failures++;
		}
	}

	if (found != 1) {
		printf("%s: %s encoded %zu times, expected once\n", name, src ? src : "(*,G)",
		       found);
		failures++;
	}
}

/*
 * Group 226.1.1.2 on c1 in multicast_pim_sm_topo2: a (*,G) join, an
 * (S,G) join for one source and an (S,G,rpt) prune for another source.
 * Optionally also carry an explicit (S,G) prune.
 */
static void run_case(const char *name, bool with_prune, size_t max_sources)
{
	struct pim_upstream star, s_join, s_rpt_prune, s_prune;
	struct pim_jp_sources js_star, js_join, js_prune;
	struct pim_jp_agg_group sgs = {};
	struct decoded_source ds[8] = {};
	size_t count, expected = with_prune ? 4 : 3;
	int before = failures;

	upstream_init(&star, NULL);
	upstream_init(&s_join, S_JOIN);
	upstream_init(&s_rpt_prune, S_RPT_PRUNE);
	upstream_init(&s_prune, S_PRUNE);

	star.sources = list_new();
	listnode_add(star.sources, &s_join);
	listnode_add(star.sources, &s_rpt_prune);
	PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(s_rpt_prune.flags);

	/* pim_jp_agg keeps joins sorted before prunes, (*,G) first */
	sgs.group = addr(GROUP_ADDR);
	sgs.sources = list_new();
	jp_source_add(sgs.sources, &js_star, &star, true);
	jp_source_add(sgs.sources, &js_join, &s_join, true);
	if (with_prune)
		jp_source_add(sgs.sources, &js_prune, &s_prune, false);

	count = encode_and_decode(&sgs, max_sources, ds);

	if (count != expected) {
		printf("%s: decoded %zu sources, expected %zu\n", name, count, expected);
		failures++;
	}

	expect(name, ds, count, NULL, true,
	       PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_WC_BIT | PIM_ENCODE_RPT_BIT);
	expect(name, ds, count, S_JOIN, true, PIM_ENCODE_SPARSE_BIT);
	expect(name, ds, count, S_RPT_PRUNE, false, PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_RPT_BIT);
	if (with_prune)
		expect(name, ds, count, S_PRUNE, false, PIM_ENCODE_SPARSE_BIT);

	printf("%s %s\n", name, failures == before ? "OK" : "failed");

	list_delete(&sgs.sources);
	list_delete(&star.sources);
}

/* Record holding `src` (NULL for the (*,G) join) or -1 if not encoded */
static ssize_t record_of(struct decoded_source *ds, size_t count, const char *src)
{
	pim_addr want = src ? addr(src) : addr(RP_ADDR);
	size_t i;

	for (i = 0; i < count; i++)
		if (!pim_addr_cmp(ds[i].src, want))
			return ds[i].record;

	return -1;
}

/*
 * A (*,G) join, two (S,G) joins and an (S,G,rpt) prune with room for three
 * sources per record. RFC 7761 section 4.9.5.2: the (S,G,rpt) prunes must
 * be sent in the same message as the (*,G) join, so the (S,G) join that
 * doesn't fit must go to the next record instead of the (S,G,rpt) prune.
 */
static void run_same_record_case(void)
{
	const char *name = "sgrpt_prune_same_record_as_starg_join";
	struct pim_upstream star, s_join, s_join2, s_rpt_prune;
	struct pim_jp_sources js_star, js_join, js_join2;
	struct pim_jp_agg_group sgs = {};
	struct decoded_source ds[8] = {};
	int before = failures;
	ssize_t starg_record, rpt_record;
	size_t count;

	upstream_init(&star, NULL);
	upstream_init(&s_join, S_JOIN);
	upstream_init(&s_join2, S_JOIN2);
	upstream_init(&s_rpt_prune, S_RPT_PRUNE);

	star.sources = list_new();
	listnode_add(star.sources, &s_join);
	listnode_add(star.sources, &s_join2);
	listnode_add(star.sources, &s_rpt_prune);
	PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(s_rpt_prune.flags);

	sgs.group = addr(GROUP_ADDR);
	sgs.sources = list_new();
	jp_source_add(sgs.sources, &js_star, &star, true);
	jp_source_add(sgs.sources, &js_join, &s_join, true);
	jp_source_add(sgs.sources, &js_join2, &s_join2, true);

	count = encode_and_decode(&sgs, 3, ds);

	expect(name, ds, count, NULL, true,
	       PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_WC_BIT | PIM_ENCODE_RPT_BIT);
	expect(name, ds, count, S_JOIN, true, PIM_ENCODE_SPARSE_BIT);
	expect(name, ds, count, S_JOIN2, true, PIM_ENCODE_SPARSE_BIT);
	expect(name, ds, count, S_RPT_PRUNE, false, PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_RPT_BIT);

	starg_record = record_of(ds, count, NULL);
	rpt_record = record_of(ds, count, S_RPT_PRUNE);
	if (rpt_record != starg_record) {
		printf("%s: (S,G,rpt) prune in record %zd, (*,G) join in record %zd\n", name,
		       rpt_record, starg_record);
		failures++;
	}

	printf("%s %s\n", name, failures == before ? "OK" : "failed");

	list_delete(&sgs.sources);
	list_delete(&star.sources);
}

/*
 * A (*,G) join with three (S,G,rpt) prunes (children list not sorted by
 * address) and room for two sources per record. RFC 7761 section 4.9.5.2:
 * the (S,G,rpt) prunes MUST NOT be split in multiple messages, only the
 * numerically smallest one that fits is sent and the rest are ignored.
 */
static void run_overflow_case(void)
{
	static const char *const rpt_prunes[] = { "10.0.7.3", "10.0.7.2", "10.0.7.1" };
	const char *name = "sgrpt_prune_overflow";
	struct pim_upstream star, children[array_size(rpt_prunes)];
	struct pim_jp_sources js_star;
	struct pim_jp_agg_group sgs = {};
	struct decoded_source ds[8] = {};
	char buf[INET6_ADDRSTRLEN];
	int before = failures;
	ssize_t starg_record;
	size_t count, i;

	upstream_init(&star, NULL);
	star.sources = list_new();
	for (i = 0; i < array_size(rpt_prunes); i++) {
		upstream_init(&children[i], rpt_prunes[i]);
		PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(children[i].flags);
		listnode_add(star.sources, &children[i]);
	}

	sgs.group = addr(GROUP_ADDR);
	sgs.sources = list_new();
	jp_source_add(sgs.sources, &js_star, &star, true);

	count = encode_and_decode(&sgs, 2, ds);

	starg_record = record_of(ds, count, NULL);
	for (i = 0; i < count; i++) {
		if ((ds[i].flags & PIM_ENCODE_WC_BIT) || ds[i].record == (size_t)starg_record)
			continue;

		inet_ntop(PIM_AF, &ds[i].src, buf, sizeof(buf));
		printf("%s: (S,G,rpt) prune %s sent in record %zu without the (*,G) join\n", name,
		       buf, ds[i].record);
		failures++;
	}

	if (record_of(ds, count, "10.0.7.1") != starg_record) {
		printf("%s: numerically smallest (S,G,rpt) prune 10.0.7.1 not sent with the (*,G) join\n",
		       name);
		failures++;
	}

	printf("%s %s\n", name, failures == before ? "OK" : "failed");

	list_delete(&sgs.sources);
	list_delete(&star.sources);
}

int main(int argc, char **argv)
{
	test_rp_rpf.rpf_addr = addr(RP_ADDR);

	run_case("sgrpt_prune_with_sg_join", false, 16);
	run_case("sgrpt_prune_with_sg_join_and_prune", true, 16);
	/* A record needs room for a (*,G) join and at least one (S,G,rpt) prune */
	run_case("sgrpt_prune_split_records", true, 2);
	run_case("sgrpt_prune_split_after_joins", true, 3);
	run_same_record_case();
	run_overflow_case();

	return failures ? 1 : 0;
}
