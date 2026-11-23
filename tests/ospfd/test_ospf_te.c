// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF MPLS-TE: Traffic Engineering Database update from received LSAs.
 *
 * With "mpls-te on", ospf_mpls_te_lsa_update() is the new-LSA hook for every
 * installed LSA: ospf_opaque_lsa_update_hook() runs the type-10 funclist for
 * all LSA types, so AS-scope (type 11) opaque LSAs reach it as well. Those
 * have lsa->area == NULL (ospf_packet.c, ospf_ls_upd), and an LSA advertised
 * by router 0.0.0.0 has no valid Link State vertex key (ls_vertex_add()
 * returns NULL). The parse/delete functions must reject or handle both
 * without dereferencing NULL.
 *
 * Each case runs a short sequence of LSA updates and deletes, then checks
 * the TED contents (vertices, subnets, node flags and area, prefix SID and
 * owner). It then frees the TED and checks that no Link State Database
 * memory is left, so a leaked node fails the case without LeakSanitizer.
 *
 * ospf_te.c is included so the static hooks can be called directly. Each
 * case runs in a child process so that a crash fails only that case.
 */

#include <zebra.h>

#include <sys/wait.h>

#include "frrevent.h"
#include "lib/command.h"
#include "lib/link_state.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/privs.h"
#include "lib/vrf.h"

#include "ospfd/ospf_te.c"

struct event_loop *master;

/* Referenced by ospfd objects that are linked in but not exercised here. */
struct zebra_privs_t ospfd_privs;

enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

/*
 * Result of the last step. Child exit codes are distinct from ASan/UBSan's
 * error exit code (1) so that a sanitizer report is never mistaken for one.
 */
enum result {
	HANDLED = 10,  /* hook returns 0 */
	REJECTED = 11, /* hook returns non-zero, no crash */
	MISMATCH = 12, /* TED contents or memory differ from the row */
};

static const char *result2str(int code)
{
	switch (code) {
	case HANDLED:
		return "handled";
	case REJECTED:
		return "rejected";
	case MISMATCH:
		return "mismatch";
	}
	return "abnormal exit";
}

enum lsa_body {
	BODY_ROUTER,	 /* Router LSA, no links */
	BODY_RI_CAPS,	 /* RI: Router Informational Capabilities TLV (RFC 7770) */
	BODY_RI_SR,	 /* RI: SR-Algorithm TLV, SPF */
	BODY_EXT_PREFIX, /* Extended Prefix 10.1.0.0/24, Prefix-SID index 10 */
	BODY_EXT_LINK,	 /* Extended Link, p2p to 10.0.0.2 */
	BODY_HDR_ONLY,	 /* LSA header, no body */
};

enum op {
	OP_NONE,
	OP_UPDATE,	  /* ospf_mpls_te_lsa_update() */
	OP_DELETE,	  /* ospf_mpls_te_lsa_delete() */
	OP_LS_SUBNET_ADD, /* ls_subnet_add() for 10.1.0.0/24 directly */
};

struct step {
	enum op op;
	uint8_t lsa_type; /* OSPF_ROUTER_LSA / OSPF_OPAQUE_AREA_LSA / OSPF_OPAQUE_AS_LSA */
	uint8_t opaque_type;
	enum lsa_body body;
	const char *adv_router;
	const char *area; /* NULL: lsa->area = NULL, as for received AS-scope LSAs */
};

/* TED contents after the last step */
struct want {
	enum result result; /* of the last step */
	size_t vertices;
	size_t subnets;
	uint16_t node_flags;   /* LS_NODE_TYPE | LS_NODE_SR on the advertising router */
	const char *node_area; /* its node's area ID; NULL: no vertex expected */
	int sid;	       /* SR SID on 10.1.0.0/24; -1: none */
};

#define MAX_STEPS 3

struct tcase {
	const char *description;
	enum kind kind;
	struct step steps[MAX_STEPS];
	struct want expected;
};

#define NODE_FLAGS (LS_NODE_TYPE | LS_NODE_SR)

/* Steps */
#define UPD(t, o, b, adv, a)   { OP_UPDATE, t, o, b, adv, a }
#define DEL(t, o, b, adv, a)   { OP_DELETE, t, o, b, adv, a }
#define ROUTER(adv, a)	       UPD(OSPF_ROUTER_LSA, 0, BODY_ROUTER, adv, a)
#define RI(sc, b, adv, a)      UPD(sc, OPAQUE_TYPE_ROUTER_INFORMATION_LSA, b, adv, a)
#define EXT_PREFIX(sc, adv, a) UPD(sc, OPAQUE_TYPE_EXTENDED_PREFIX_LSA, BODY_EXT_PREFIX, adv, a)
#define SUBNET_ADD(adv)	       { OP_LS_SUBNET_ADD, 0, 0, 0, adv, NULL }

#define AREA OSPF_OPAQUE_AREA_LSA
#define AS   OSPF_OPAQUE_AS_LSA

static const struct tcase tcases[] = {
	{ "area router LSA from 10.0.0.1 updates the TED",
	  POSITIVE,
	  { ROUTER("10.0.0.1", "0.0.0.1") },
	  { HANDLED, 1, 0, LS_NODE_TYPE, "0.0.0.1", -1 } },
	{ "area RI LSA from 10.0.0.1 updates the TED",
	  POSITIVE,
	  { RI(AREA, BODY_RI_SR, "10.0.0.1", "0.0.0.1") },
	  { HANDLED, 1, 0, LS_NODE_SR, "0.0.0.1", -1 } },
	{ "area Ext-Prefix LSA from 10.0.0.1 updates the TED",
	  POSITIVE,
	  { EXT_PREFIX(AREA, "10.0.0.1", "0.0.0.1") },
	  { HANDLED, 1, 1, 0, "0.0.0.1", 10 } },
	{ "ls_subnet_add() from 10.0.0.1 adds the subnet and its vertex",
	  POSITIVE,
	  { SUBNET_ADD("10.0.0.1") },
	  { HANDLED, 1, 1, 0, "0.0.0.0", -1 } },
	{ "AS-scope RI LSA with only a capabilities TLV is ignored",
	  NEGATIVE,
	  { RI(AS, BODY_RI_CAPS, "10.0.0.1", NULL) },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "AS-scope RI LSA with SR-Algorithm is ignored",
	  NEGATIVE,
	  { RI(AS, BODY_RI_SR, "10.0.0.1", NULL) },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "AS-scope Ext-Prefix LSA is handled",
	  NEGATIVE,
	  { EXT_PREFIX(AS, "10.0.0.1", NULL) },
	  { HANDLED, 1, 1, 0, "0.0.0.0", 10 } },
	{ "AS-scope Ext-Link LSA is rejected",
	  NEGATIVE,
	  { UPD(AS, OPAQUE_TYPE_EXTENDED_LINK_LSA, BODY_EXT_LINK, "10.0.0.1", NULL) },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "router LSA from 0.0.0.0 is rejected",
	  BOUNDARY,
	  { ROUTER("0.0.0.0", "0.0.0.1") },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "area RI LSA from 0.0.0.0 is rejected",
	  BOUNDARY,
	  { RI(AREA, BODY_RI_SR, "0.0.0.0", "0.0.0.1") },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "area Ext-Prefix LSA from 0.0.0.0 is rejected",
	  BOUNDARY,
	  { EXT_PREFIX(AREA, "0.0.0.0", "0.0.0.1") },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "ls_subnet_add() from 0.0.0.0 returns NULL",
	  BOUNDARY,
	  { SUBNET_ADD("0.0.0.0") },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "AS-scope RI LSA with header only is rejected, no vertex",
	  BOUNDARY,
	  { RI(AS, BODY_HDR_ONLY, "10.0.0.1", NULL) },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "area RI LSA with header only is rejected, no vertex",
	  BOUNDARY,
	  { RI(AREA, BODY_HDR_ONLY, "10.0.0.1", "0.0.0.1") },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "AS-scope RI LSA from an area router leaves its vertex unchanged",
	  CORNER,
	  { ROUTER("10.0.0.1", "0.0.0.1"), RI(AS, BODY_RI_SR, "10.0.0.1", NULL) },
	  { REJECTED, 1, 0, LS_NODE_TYPE, "0.0.0.1", -1 } },
	{ "deleting an AS-scope RI LSA keeps area SR information",
	  CORNER,
	  { RI(AREA, BODY_RI_SR, "10.0.0.1", "0.0.0.1"), RI(AS, BODY_RI_CAPS, "10.0.0.1", NULL),
	    DEL(AS, OPAQUE_TYPE_ROUTER_INFORMATION_LSA, BODY_RI_CAPS, "10.0.0.1", NULL) },
	  { REJECTED, 1, 0, LS_NODE_SR, "0.0.0.1", -1 } },
	{ "deleting an installed AS-scope Ext-Prefix LSA clears its SID",
	  CORNER,
	  { EXT_PREFIX(AS, "10.0.0.1", NULL),
	    DEL(AS, OPAQUE_TYPE_EXTENDED_PREFIX_LSA, BODY_EXT_PREFIX, "10.0.0.1", NULL) },
	  { HANDLED, 1, 1, 0, "0.0.0.0", -1 } },
	{ "deleting an unknown AS-scope RI LSA is rejected",
	  CORNER,
	  { DEL(AS, OPAQUE_TYPE_ROUTER_INFORMATION_LSA, BODY_RI_SR, "10.0.0.1", NULL) },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
	{ "deleting an unknown area RI LSA is rejected",
	  CORNER,
	  { DEL(AREA, OPAQUE_TYPE_ROUTER_INFORMATION_LSA, BODY_RI_SR, "10.0.0.1", "0.0.0.1") },
	  { REJECTED, 0, 0, 0, NULL, -1 } },
};

static struct list *areas;

static void put16(uint8_t *p, uint16_t v)
{
	v = htons(v);
	memcpy(p, &v, sizeof(v));
}

/* Build the LSA body after the 20-byte header; returns the total LSA size. */
static size_t build_body(uint8_t *buf, enum lsa_body body)
{
	uint8_t *p = buf + OSPF_LSA_HEADER_SIZE;

	switch (body) {
	case BODY_ROUTER:
		/* flags, zero, #links = 0 */
		return OSPF_LSA_HEADER_SIZE + 4;
	case BODY_RI_CAPS:
		/* Router Informational Capabilities: graceful restart capable */
		put16(p, RI_TLV_CAPABILITIES);
		put16(p + 2, RI_TLV_CAPABILITIES_SIZE);
		p[4] = 0x80;
		return OSPF_LSA_HEADER_SIZE + 8;
	case BODY_RI_SR:
		/* SR-Algorithm TLV: SPF (0), padded to 4 octets */
		put16(p, RI_SR_TLV_SR_ALGORITHM);
		put16(p + 2, 1);
		p[4] = SR_ALGORITHM_SPF;
		return OSPF_LSA_HEADER_SIZE + 8;
	case BODY_EXT_PREFIX:
		/* Extended Prefix TLV 10.1.0.0/24 + Prefix-SID sub-TLV, index 10 */
		put16(p, EXT_TLV_PREFIX);
		put16(p + 2, EXT_TLV_PREFIX_SIZE + TLV_HDR_SIZE + EXT_SUBTLV_PREFIX_SID_SIZE);
		p[4] = 1;  /* route type: intra-area */
		p[5] = 24; /* prefix length */
		p[8] = 10;
		p[9] = 1;
		put16(p + 12, EXT_SUBTLV_PREFIX_SID);
		put16(p + 14, EXT_SUBTLV_PREFIX_SID_SIZE);
		p[23] = 10;
		return OSPF_LSA_HEADER_SIZE + 24;
	case BODY_EXT_LINK:
		/* Extended Link TLV: p2p link to 10.0.0.2 over 10.9.0.1 */
		put16(p, EXT_TLV_LINK);
		put16(p + 2, EXT_TLV_LINK_SIZE);
		p[4] = 1;
		p[8] = 10;
		p[11] = 2;
		p[12] = 10;
		p[13] = 9;
		p[15] = 1;
		return OSPF_LSA_HEADER_SIZE + 4 + EXT_TLV_LINK_SIZE;
	case BODY_HDR_ONLY:
		return OSPF_LSA_HEADER_SIZE;
	}
	return OSPF_LSA_HEADER_SIZE;
}

static struct ospf_area *find_area(const char *id)
{
	struct ospf_area *area;
	struct listnode *node;
	struct in_addr addr;

	inet_pton(AF_INET, id, &addr);
	for (ALL_LIST_ELEMENTS_RO(areas, node, area))
		if (area->area_id.s_addr == addr.s_addr)
			return area;
	return NULL;
}

static struct ospf_lsa *make_lsa(const struct step *s)
{
	uint8_t buf[OSPF_MAX_LSA_SIZE] = {};
	struct ospf_lsa *lsa;
	size_t size;

	size = build_body(buf, s->body);
	lsa = ospf_lsa_new_and_data(size);
	memcpy(lsa->data, buf, size);
	lsa->data->type = s->lsa_type;
	lsa->data->length = htons(size);
	if (s->lsa_type != OSPF_ROUTER_LSA)
		lsa->data->id.s_addr = htonl(SET_OPAQUE_LSID(s->opaque_type, 0));
	else
		inet_pton(AF_INET, s->adv_router, &lsa->data->id);
	inet_pton(AF_INET, s->adv_router, &lsa->data->adv_router);
	lsa->area = s->area ? find_area(s->area) : NULL;
	return lsa;
}

static struct prefix test_prefix(void)
{
	struct prefix p = {};

	str2prefix("10.1.0.0/24", &p);
	return p;
}

static int run_step(const struct step *s)
{
	struct ospf_lsa *lsa;
	struct ls_node_id lnid = { .origin = OSPFv2 };
	struct ls_prefix *ls_pref;
	struct prefix p;
	int rc;

	if (s->op == OP_LS_SUBNET_ADD) {
		p = test_prefix();
		inet_pton(AF_INET, s->adv_router, &lnid.id.ip.addr);
		ls_pref = ls_prefix_new(lnid, &p);
		if (ls_subnet_add(OspfMplsTE.ted, ls_pref))
			return HANDLED;
		ls_prefix_del(ls_pref);
		return REJECTED;
	}

	lsa = make_lsa(s);
	rc = s->op == OP_DELETE ? ospf_mpls_te_lsa_delete(lsa) : ospf_mpls_te_lsa_update(lsa);
	ospf_lsa_discard(lsa);
	return rc == 0 ? HANDLED : REJECTED;
}

static int ls_db_walk(void *arg, struct memgroup *mg, struct memtype *mt)
{
	if (mt && !strcmp(mt->name, "Link State Database"))
		*(size_t *)arg = mt->n_alloc;
	return 0;
}

static size_t ls_db_allocs(void)
{
	size_t n = 0;

	qmem_walk(ls_db_walk, &n);
	return n;
}

/* Compare the TED with the row; write any difference to why. */
static bool check_ted(const struct tcase *tc, char *why, size_t len)
{
	const struct want *w = &tc->expected;
	struct ls_ted *ted = OspfMplsTE.ted;
	struct ls_node_id lnid = { .origin = OSPFv2 };
	struct ls_vertex *vertex;
	struct ls_subnet *subnet;
	struct in_addr area;
	struct prefix p = test_prefix();
	int sid = -1;

	if (vertices_count(&ted->vertices) != w->vertices ||
	    subnets_count(&ted->subnets) != w->subnets) {
		snprintfrr(why, len, "%zu vertices, %zu subnets", vertices_count(&ted->vertices),
			   subnets_count(&ted->subnets));
		return false;
	}

	inet_pton(AF_INET, tc->steps[0].adv_router, &lnid.id.ip.addr);
	vertex = ls_find_vertex_by_id(ted, lnid);
	if (!w->node_area) {
		if (vertex) {
			snprintfrr(why, len, "unexpected vertex %pI4", &lnid.id.ip.addr);
			return false;
		}
	} else {
		inet_pton(AF_INET, w->node_area, &area);
		if (!vertex) {
			snprintfrr(why, len, "no vertex %pI4", &lnid.id.ip.addr);
			return false;
		}
		if ((vertex->node->flags & NODE_FLAGS) != w->node_flags) {
			snprintfrr(why, len, "node flags 0x%x", vertex->node->flags & NODE_FLAGS);
			return false;
		}
		if (CHECK_FLAG(w->node_flags, LS_NODE_SR) &&
		    vertex->node->algo[0] != SR_ALGORITHM_SPF) {
			snprintfrr(why, len, "algo[0] %u", vertex->node->algo[0]);
			return false;
		}
		if (vertex->node->adv.id.ip.area_id.s_addr != area.s_addr) {
			snprintfrr(why, len, "node area %pI4", &vertex->node->adv.id.ip.area_id);
			return false;
		}
	}

	subnet = ls_find_subnet(ted, &p);
	if (subnet) {
		if (subnet->vertex != vertex) {
			snprintfrr(why, len, "subnet not owned by %pI4", &lnid.id.ip.addr);
			return false;
		}
		if (CHECK_FLAG(subnet->ls_pref->flags, LS_PREF_SR))
			sid = subnet->ls_pref->sr.sid;
	}
	if (sid != w->sid) {
		snprintfrr(why, len, "SID %d", sid);
		return false;
	}
	return true;
}

static int run_case(const struct tcase *tc, int fd)
{
	char why[96] = "";
	size_t before;
	int result = REJECTED;

	before = ls_db_allocs();
	OspfMplsTE.ted = ls_ted_new(1, "OSPF", 0);
	OspfMplsTE.enabled = true;

	for (int i = 0; i < MAX_STEPS && tc->steps[i].op != OP_NONE; i++)
		result = run_step(&tc->steps[i]);

	if (result == (int)tc->expected.result && !check_ted(tc, why, sizeof(why)))
		result = MISMATCH;

	ls_ted_del_all(&OspfMplsTE.ted);
	if (!why[0] && ls_db_allocs() != before) {
		snprintfrr(why, sizeof(why), "%zu Link State allocations left",
			   ls_db_allocs() - before);
		result = MISMATCH;
	}

	if (why[0] && write(fd, why, strlen(why)) < 0)
		return MISMATCH;
	return result;
}

int main(int argc, char **argv)
{
	struct ospf *ospf;
	struct in_addr id;
	int failures = 0;

	master = event_master_create(NULL);
	cmd_init(1);
	zlog_aux_init("NONE: ", ZLOG_DISABLED);

	ospf = ospf_new_alloc(0, VRF_DEFAULT_NAME);
	areas = ospf->areas;
	inet_pton(AF_INET, "0.0.0.0", &id);
	listnode_add_sort(areas, ospf_area_new(ospf, id));
	inet_pton(AF_INET, "0.0.0.1", &id);
	listnode_add_sort(areas, ospf_area_new(ospf, id));

	printf("OSPF MPLS-TE TED update tests\n\n");

	for (size_t i = 0; i < array_size(tcases); i++) {
		const struct tcase *tc = &tcases[i];
		char detail[96] = "";
		char why[160] = "";
		int status, fds[2];
		ssize_t n;
		pid_t pid;

		fflush(stdout);
		if (pipe(fds) < 0) {
			perror("pipe");
			return 1;
		}
		pid = fork();
		if (pid == 0) {
			close(fds[0]);
			_exit(run_case(tc, fds[1]));
		}
		close(fds[1]);
		n = read(fds[0], detail, sizeof(detail) - 1);
		close(fds[0]);
		if (n > 0)
			detail[n] = '\0';

		waitpid(pid, &status, 0);
		if (WIFSIGNALED(status))
			snprintfrr(why, sizeof(why), " (crashed: signal %d)", WTERMSIG(status));
		else if (WEXITSTATUS(status) == MISMATCH)
			snprintfrr(why, sizeof(why), " (TED: %s)", detail);
		else if (WEXITSTATUS(status) != (int)tc->expected.result)
			snprintfrr(why, sizeof(why), " (got %s %d, expected %s)",
				   result2str(WEXITSTATUS(status)), WEXITSTATUS(status),
				   result2str(tc->expected.result));

		printf("[%-8s] %s ... %s%s\n", kind2str[tc->kind], tc->description,
		       why[0] ? "failed" : "OK", why);
		if (why[0])
			failures++;
	}

	printf("\n%d of %zu cases failed\n", failures, array_size(tcases));
	return failures ? 1 : 0;
}
