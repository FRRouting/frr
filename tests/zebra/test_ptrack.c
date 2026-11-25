// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra prefix tracking (ptrack) tests
 *
 * Copyright (C) 2026 Nokia
 */

#include <zebra.h>

#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/stream.h"
#include "lib/memory.h"
#include "lib/frrevent.h"
#include "lib/hook.h"
#include "lib/log.h"
#include "lib/zlog.h"
#include "lib/vrf.h"
#include "lib/zclient.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_ptrack.h"

/* ---- shims for what zebra_ptrack.o needs from the rest of zebra ---- */

DEFINE_MGROUP(ZEBRA, "zebra");
DEFINE_KOOH(zserv_client_close, (struct zserv * client), (client));

struct zebra_router zrouter;

static bool startup_done = true;

bool zebra_rib_startup_done(void)
{
	return startup_done;
}

/* The messages zebra sent to the clients */
#define MAX_SENT 64
static struct stream *sent[MAX_SENT];
static struct zserv *sent_client[MAX_SENT];
static int sent_n;

int zserv_send_message(struct zserv *client, struct stream *msg)
{
	assert(sent_n < MAX_SENT);
	sent[sent_n] = msg;
	sent_client[sent_n] = client;
	sent_n++;

	return 0;
}

static void sent_clear(void)
{
	while (sent_n > 0)
		stream_free(sent[--sent_n]);
}

/* The VRFs zebra knows. Only a present one is found by its name. */
struct fake_vrf {
	bool present;
	struct vrf vrf;
	struct zebra_vrf zvrf;
};

#define FV_VRF1 0
#define FV_VRF2 1
#define FV_VRFX 2
static struct fake_vrf fv[3];
static const char *const fv_names[3] = { "Vrf1", "Vrf2", "VrfX" };

struct zebra_vrf *zebra_vrf_lookup_by_name(const char *name)
{
	int i;

	for (i = 0; i < 3; i++)
		if (fv[i].present && !strcmp(fv[i].vrf.name, name))
			return &fv[i].zvrf;

	return NULL;
}

/* ---- checks ---- */

static int failed;
static int case_failed_before;
static int case_no;
static const char *case_name;

#define CHECK(cond)                                                           \
	do {                                                                      \ 
		if (!(cond)) {                                                 		  \
			printf("  FAIL line %d: %s\n", __LINE__, #cond);       		      \
			failed++;                                              			  \
		}                                                                     \
	} while (0)

static void case_begin(int no, const char *name)
{
	case_no = no;
	case_name = name;
	case_failed_before = failed;
}

static void case_end(void)
{
	printf("case %02d: %s: %s\n", case_no, case_name,
	       failed == case_failed_before ? "ok" : "FAILED");
}

/* ---- fixtures ---- */

static struct zserv cl_a = { .proto = ZEBRA_ROUTE_SHARP };
static struct zserv cl_b = { .proto = ZEBRA_ROUTE_SHARP };
static struct zserv cl_c = { .proto = ZEBRA_ROUTE_SHARP };

static const uint64_t c1[] = { 1 };
static const uint64_t c2[] = { 2 };
static const uint64_t c3[] = { 3 };
static const uint64_t c7[] = { 7 };
static const uint64_t c9[] = { 9 };
static const uint64_t c12[] = { 1, 2 };
static const uint64_t c123[] = { 1, 2, 3 };
static const uint64_t c233[] = { 2, 3, 3 };
static const uint64_t cnone[] = { 0 };

static struct prefix pfx(const char *s)
{
	struct prefix p;

	memset(&p, 0, sizeof(p));
	if (!str2prefix(s, &p))
		abort();

	return p;
}

static bool pfx_is(const struct prefix *p, const char *s)
{
	struct prefix want = pfx(s);

	return prefix_same(p, &want);
}

/* A request as a client builds it, the prefix is not masked */
static struct zapi_ptrack req;

static struct zapi_ptrack *mkreq(const char *vrf, const char *p,
				 const uint64_t *cookies, uint16_t count)
{
	memset(&req, 0, offsetof(struct zapi_ptrack, cookies));
	strlcpy(req.vrf_name, vrf, sizeof(req.vrf_name));
	req.prefix = pfx(p);
	req.cookie_count = count;
	if (count)
		memcpy(req.cookies, cookies, count * sizeof(*cookies));

	return &req;
}

static void reg(struct zserv *client, const char *vrf, const char *p,
		const uint64_t *cookies, uint16_t count)
{
	zebra_ptrack_register(client, mkreq(vrf, p, cookies, count));
}

static void unreg(struct zserv *client, const char *vrf, const char *p,
		  const uint64_t *cookies, uint16_t count)
{
	zebra_ptrack_unregister(client, mkreq(vrf, p, cookies, count));
}

/* Decode a message that zebra sent as an UPDATE */
static struct zapi_ptrack upd;

static bool sent_decode(int i, struct zapi_ptrack *out)
{
	struct stream *s = sent[i];

	if (stream_getw_from(s, 0) != stream_get_endp(s))
		return false;
	if (stream_getl_from(s, 4) != VRF_DEFAULT)
		return false;
	if (stream_getw_from(s, 8) != ZEBRA_PREFIX_TRACK_UPDATE)
		return false;

	stream_set_getp(s, ZEBRA_HEADER_SIZE);

	return zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_UPDATE, s, out);
}

/* The number of messages that went to a client */
static int sent_to(struct zserv *client)
{
	int i, n = 0;

	for (i = 0; i < sent_n; i++)
		if (sent_client[i] == client)
			n++;

	return n;
}

/* The first message that went to a client, decoded into upd */
static bool sent_first(struct zserv *client)
{
	int i;

	for (i = 0; i < sent_n; i++)
		if (sent_client[i] == client)
			return sent_decode(i, &upd);

	return false;
}

/* Every message must decode, and be an UPDATE of this state and prefix */
static bool sent_all_are(enum zapi_ptrack_state state, const char *p)
{
	int i;

	for (i = 0; i < sent_n; i++) {
		if (!sent_decode(i, &upd) || upd.state != state ||
		    !pfx_is(&upd.prefix, p))
			return false;
	}

	return true;
}

/* The stored state of a prefix, -1 if it is not tracked */
static int ent_state(const char *vrf, const char *p)
{
	struct ptrack_vrf_ctx *ctx = zebra_ptrack_ctx_lookup(vrf);
	struct prefix pf = pfx(p);
	struct ptrack_entry *e;

	if (!ctx)
		return -1;

	e = zebra_ptrack_entry_lookup(ctx, &pf);
	if (!e)
		return -1;

	return zebra_ptrack_entry_get_state(e);
}

/* Routes: a real dest with real route entries on the unicast table of a VRF */
static struct route_node *rn_hold(struct zebra_vrf *zvrf, afi_t afi,
				  const char *p)
{
	struct prefix pf = pfx(p);

	return route_node_get(zvrf->table[afi][SAFI_UNICAST], &pf);
}

static void rn_add_route(struct route_node *rn, uint32_t status)
{
	rib_dest_t *dest = rn->info;
	struct route_entry *re;

	if (!dest) {
		dest = XCALLOC(MTYPE_TMP, sizeof(*dest));
		re_list_init(&dest->routes);
		rn->info = dest;
		/* The lock of the dest, as the RIB takes it */
		route_lock_node(rn);
	}

	re = XCALLOC(MTYPE_TMP, sizeof(*re));
	re->status = status;
	re_list_add_tail(&dest->routes, re);
}

static void rn_set_status(struct route_node *rn, uint32_t status)
{
	rib_dest_t *dest = rn->info;
	struct route_entry *re;

	frr_each (re_list, &dest->routes, re)
		re->status = status;
}

/* The dest is freed, like the RIB does when the last route is gone */
static void rn_free_dest(struct route_node *rn)
{
	rib_dest_t *dest = rn->info;
	struct route_entry *re;

	if (!dest)
		return;

	while ((re = re_list_pop(&dest->routes)))
		XFREE(MTYPE_TMP, re);
	re_list_fini(&dest->routes);
	XFREE(MTYPE_TMP, dest);

	rn->info = NULL;
	route_unlock_node(rn);
}

static void table_clear(struct route_table *table)
{
	struct route_node *rn;

	if (!table)
		return;

	for (rn = route_top(table); rn; rn = route_next(rn))
		rn_free_dest(rn);

	route_table_finish(table);
}

static void fv_down(int i);

/* The VRF exists and is active, with empty tables */
static void fv_up(int i)
{
	struct fake_vrf *f = &fv[i];

	if (f->present)
		fv_down(i);

	memset(&f->zvrf, 0, sizeof(f->zvrf));
	strlcpy(f->vrf.name, fv_names[i], sizeof(f->vrf.name));
	f->vrf.status = VRF_ACTIVE;
	f->zvrf.vrf = &f->vrf;
	f->zvrf.table[AFI_IP][SAFI_UNICAST] = route_table_init();
	f->zvrf.table[AFI_IP6][SAFI_UNICAST] = route_table_init();
	f->present = true;
}

/* The VRF is deleted, zebra frees the zebra_vrf and its tables */
static void fv_down(int i)
{
	struct fake_vrf *f = &fv[i];

	table_clear(f->zvrf.table[AFI_IP][SAFI_UNICAST]);
	table_clear(f->zvrf.table[AFI_IP6][SAFI_UNICAST]);
	memset(&f->zvrf, 0, sizeof(f->zvrf));
	f->vrf.status = 0;
	f->present = false;
}

/* Back to nothing tracked and nothing sent, the gate open */
static void reset(void)
{
	int i;

	zebra_ptrack_terminate();
	sent_clear();
	startup_done = true;

	for (i = 0; i < 3; i++)
		fv[i].zvrf.ptrack = NULL;
}

/* An event of ours, to know if the module scheduled one before it */
static bool sentinel_ran;

static void sentinel_cb(struct event *event)
{
	sentinel_ran = true;
}

static void run_one_event(void)
{
	struct event ev;

	if (event_fetch(zrouter.master, &ev))
		event_call(&ev);
}

/* True if nothing of the module was scheduled before our event */
static bool nothing_scheduled(void)
{
	sentinel_ran = false;
	event_add_event(zrouter.master, sentinel_cb, NULL, 0, NULL);
	run_one_event();

	if (!sentinel_ran)
		run_one_event();

	return sentinel_ran;
}

/* ---- A: the codec ---- */

static void test_codec(void)
{
	struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	static struct zapi_ptrack d;
	struct zapi_ptrack *a;
	struct stream *t;
	size_t endp, i;
	/* header, name, family, length, 3 prefix bytes, count */
	const size_t count_pos = ZEBRA_HEADER_SIZE + VRF_NAMSIZ + 1 + 1 + 3;

	case_begin(1, "codec round trip");
	a = mkreq("Vrf1", "10.0.0.5/24", c123, 3);
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_REGISTER, s, a) == 0);
	CHECK(stream_get_endp(s) ==
	      count_pos + 2 + 3 * sizeof(uint64_t));
	CHECK(stream_getw_from(s, 0) == stream_get_endp(s));
	CHECK(stream_getw_from(s, 8) == ZEBRA_PREFIX_TRACK_REGISTER);
	stream_set_getp(s, ZEBRA_HEADER_SIZE);
	CHECK(zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_REGISTER, s, &d));
	CHECK(!strcmp(d.vrf_name, "Vrf1"));
	CHECK(d.prefix.family == AF_INET && d.prefix.prefixlen == 24);
	CHECK(pfx_is(&d.prefix, "10.0.0.0/24"));
	CHECK(d.state == ZAPI_PTRACK_UNREACHABLE);
	CHECK(d.cookie_count == 3 && d.cookies[0] == 1 && d.cookies[1] == 2 &&
	      d.cookies[2] == 3);

	a = mkreq("Vrf1", "2001:db8::/64", c12, 2);
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_UNREGISTER, s, a) == 0);
	stream_set_getp(s, ZEBRA_HEADER_SIZE);
	CHECK(zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_UNREGISTER, s, &d));
	CHECK(d.prefix.family == AF_INET6 && d.prefix.prefixlen == 64);
	CHECK(pfx_is(&d.prefix, "2001:db8::/64"));
	CHECK(d.cookie_count == 2 && d.cookies[1] == 2);

	a = mkreq("Vrf1", "10.0.0.0/24", c7, 1);
	a->state = ZAPI_PTRACK_REACHABLE;
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_UPDATE, s, a) == 0);
	CHECK(stream_get_endp(s) == count_pos + 1 + 2 + sizeof(uint64_t));
	stream_set_getp(s, ZEBRA_HEADER_SIZE);
	CHECK(zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_UPDATE, s, &d));
	CHECK(d.state == ZAPI_PTRACK_REACHABLE && d.cookie_count == 1 &&
	      d.cookies[0] == 7);
	case_end();

	case_begin(2, "codec rejects invalid encode input");
	a = mkreq("Vrf1", "10.0.0.0/24", c1, 1);
	CHECK(zapi_ptrack_encode(99, s, a) == -1);
	a = mkreq("", "10.0.0.0/24", c1, 1);
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_REGISTER, s, a) == -1);
	a = mkreq("Vrf1", "10.0.0.0/24", c1, 1);
	memset(a->vrf_name, 'x', sizeof(a->vrf_name));
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_REGISTER, s, a) == -1);
	a = mkreq("Vrf1", "10.0.0.0/24", c1, 1);
	a->prefix.prefixlen = 33;
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_REGISTER, s, a) == -1);
	a = mkreq("Vrf1", "10.0.0.0/24", c1, 1);
	a->prefix.family = AF_UNIX;
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_REGISTER, s, a) == -1);
	a = mkreq("Vrf1", "10.0.0.0/24", c1, 1);
	a->state = 7;
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_UPDATE, s, a) == -1);
	a = mkreq("Vrf1", "10.0.0.0/24", c1, 1);
	a->cookie_count = ZAPI_PTRACK_MAX_COOKIES + 1;
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_REGISTER, s, a) == -1);
	case_end();

	case_begin(3, "codec rejects malformed messages");
	a = mkreq("Vrf1", "10.0.0.5/24", c12, 2);
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_REGISTER, s, a) == 0);
	endp = stream_get_endp(s);

	/* truncated at every length */
	for (i = endp - 1; i >= ZEBRA_HEADER_SIZE; i--) {
		t = stream_dup(s);
		stream_set_endp(t, i);
		stream_set_getp(t, ZEBRA_HEADER_SIZE);
		CHECK(!zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_REGISTER, t, &d));
		stream_free(t);
	}

	/* bad family */
	t = stream_dup(s);
	stream_putc_at(t, ZEBRA_HEADER_SIZE + VRF_NAMSIZ, AF_UNIX);
	stream_set_getp(t, ZEBRA_HEADER_SIZE);
	CHECK(!zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_REGISTER, t, &d));
	stream_free(t);

	/* bad prefix length */
	t = stream_dup(s);
	stream_putc_at(t, ZEBRA_HEADER_SIZE + VRF_NAMSIZ + 1, 33);
	stream_set_getp(t, ZEBRA_HEADER_SIZE);
	CHECK(!zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_REGISTER, t, &d));
	stream_free(t);

	/* name not terminated */
	t = stream_dup(s);
	for (i = 0; i < VRF_NAMSIZ; i++)
		stream_putc_at(t, ZEBRA_HEADER_SIZE + i, 'x');
	stream_set_getp(t, ZEBRA_HEADER_SIZE);
	CHECK(!zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_REGISTER, t, &d));
	stream_free(t);

	/* name empty */
	t = stream_dup(s);
	stream_putc_at(t, ZEBRA_HEADER_SIZE, 0);
	stream_set_getp(t, ZEBRA_HEADER_SIZE);
	CHECK(!zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_REGISTER, t, &d));
	stream_free(t);

	/* too many cookies */
	t = stream_dup(s);
	stream_putw_at(t, count_pos, ZAPI_PTRACK_MAX_COOKIES + 1);
	stream_set_getp(t, ZEBRA_HEADER_SIZE);
	CHECK(!zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_REGISTER, t, &d));
	stream_free(t);

	/* bad state of an UPDATE */
	a = mkreq("Vrf1", "10.0.0.5/24", c12, 2);
	a->state = ZAPI_PTRACK_REACHABLE;
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_UPDATE, s, a) == 0);
	stream_putc_at(s, count_pos, 7);
	stream_set_getp(s, ZEBRA_HEADER_SIZE);
	CHECK(!zapi_ptrack_decode(ZEBRA_PREFIX_TRACK_UPDATE, s, &d));
	case_end();

	case_begin(4, "codec largest message fits in one packet");
	a = mkreq("Vrf1", "2001:db8::/128", c1, 1);
	a->state = ZAPI_PTRACK_REACHABLE;
	a->cookie_count = ZAPI_PTRACK_MAX_COOKIES;
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_UPDATE, s, a) == 0);
	CHECK(stream_get_endp(s) <= ZEBRA_MAX_PACKET_SIZ);
	a->cookie_count = ZAPI_PTRACK_MAX_COOKIES + 1;
	CHECK(zapi_ptrack_encode(ZEBRA_PREFIX_TRACK_UPDATE, s, a) == -1);
	case_end();

	stream_free(s);
}

/* ---- B: the core structures ---- */

static void test_core(void)
{
	struct ptrack_vrf_ctx *ctx, *ctx2;
	struct ptrack_entry *e, *e2;
	struct prefix p4 = pfx("10.0.0.5/24");
	struct prefix p4m = pfx("10.0.0.0/24");
	struct prefix p6 = pfx("2001:db8::1/64");
	struct prefix bad;
	uint64_t big[2000];
	uint64_t next;
	uint32_t i, left;
	char longname[64];

	case_begin(5, "core context lookup and get");
	reset();
	memset(longname, 'x', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	CHECK(zebra_ptrack_ctx_get(NULL) == NULL);
	CHECK(zebra_ptrack_ctx_get("") == NULL);
	CHECK(zebra_ptrack_ctx_get(longname) == NULL);
	CHECK(zebra_ptrack_ctx_lookup(longname) == NULL);
	CHECK(zebra_ptrack_ctx_lookup("Vrf1") == NULL);
	ctx = zebra_ptrack_ctx_get("Vrf1");
	CHECK(ctx != NULL);
	CHECK(zebra_ptrack_ctx_get("Vrf1") == ctx);
	CHECK(zebra_ptrack_ctx_lookup("Vrf1") == ctx);
	ctx2 = zebra_ptrack_ctx_get("Vrf2");
	CHECK(ctx2 != NULL && ctx2 != ctx);
	CHECK(zebra_ptrack_ctx_lookup("Vrf2") == ctx2);
	case_end();

	case_begin(6, "core add creates entry and counters");
	reset();
	ctx = zebra_ptrack_ctx_get("Vrf1");
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, c12, 2, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(e != NULL);
	CHECK(zebra_ptrack_entry_get_state(e) == ZAPI_PTRACK_UNREACHABLE);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 2);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_b) == 0);
	zebra_ptrack_entry_set_state(e, ZAPI_PTRACK_REACHABLE);
	CHECK(zebra_ptrack_entry_get_state(e) == ZAPI_PTRACK_REACHABLE);
	case_end();

	case_begin(7, "core masks the prefix");
	CHECK(zebra_ptrack_entry_lookup(ctx, &p4m) == e);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p4) == e);
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_b, &p4m, c7, 1, &e2) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(e2 == e);
	case_end();

	case_begin(8, "core counts duplicates once");
	reset();
	ctx = zebra_ptrack_ctx_get("Vrf1");
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, c12, 2, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, c12, 2, &e2) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(e2 == e);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 2);
	/* cookie 2 exists, 3 is new and repeated in the message */
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, c233, 3, &e2) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 3);
	case_end();

	case_begin(9, "core two clients and two families");
	reset();
	ctx = zebra_ptrack_ctx_get("Vrf1");
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, c12, 2, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_b, &p4, c7, 1, &e2) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(e2 == e);
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p6, c3, 1, &e2) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(e2 != NULL && e2 != e);
	/* IPv4 and IPv6 share the counter of the client */
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 3);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_b) == 1);
	case_end();

	case_begin(10, "core bad family and empty add");
	memset(&bad, 0, sizeof(bad));
	bad.family = AF_UNIX;
	e = NULL;
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &bad, c3, 1, &e) ==
	      ZEBRA_PTRACK_INVALID);
	CHECK(e == NULL);
	p4m = pfx("192.0.2.0/24");
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4m, cnone, 0, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(e == NULL);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p4m) == NULL);
	p4m = pfx("10.0.0.0/24");
	case_end();

	case_begin(11, "core cookie limit");
	reset();
	ctx = zebra_ptrack_ctx_get("Vrf1");
	p4 = pfx("172.16.0.0/16");
	next = 1000;
	left = ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT;
	while (left) {
		uint32_t k = left > 2000 ? 2000 : left;

		for (i = 0; i < k; i++)
			big[i] = next++;
		CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, big, k, &e) ==
		      ZEBRA_PTRACK_SUCCESS);
		left -= k;
	}
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) ==
	      ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT);

	/* one more is dropped and nothing changes */
	big[0] = 99999999;
	e = NULL;
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, big, 1, &e) ==
	      ZEBRA_PTRACK_LIMIT);
	CHECK(e == NULL);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) ==
	      ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT);

	/* a new prefix does not get an entry either */
	p6 = pfx("198.51.100.0/24");
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p6, c123, 3, &e) ==
	      ZEBRA_PTRACK_LIMIT);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p6) == NULL);

	/* an existing cookie is not new */
	big[0] = 1000;
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, big, 1, &e) ==
	      ZEBRA_PTRACK_SUCCESS);

	/* another client has its own limit */
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_b, &p4, big, 1, &e) ==
	      ZEBRA_PTRACK_SUCCESS);

	/* after removals there is room again, 1001 is one of the cookies */
	big[0] = 1001;
	zebra_ptrack_del_cookies(ctx, &cl_a, &p4, big, 1);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) ==
	      ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT - 1);
	big[0] = 99999999;
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, big, 1, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	case_end();

	case_begin(12, "core delete frees in order");
	reset();
	ctx = zebra_ptrack_ctx_get("Vrf1");
	p4 = pfx("10.0.0.5/24");
	p4m = pfx("10.0.0.0/24");
	p6 = pfx("2001:db8::1/64");
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, c123, 3, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_b, &p4, c7, 1, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p6, c3, 1, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	/* cookies that are not there are skipped, 3 is only on the v6 one */
	zebra_ptrack_del_cookies(ctx, &cl_a, &p4m, c7, 1);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 4);
	zebra_ptrack_del_cookies(ctx, &cl_a, &p4m, c123, 3);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 1);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p4m) != NULL);	/* B stays */
	zebra_ptrack_del_cookies(ctx, &cl_b, &p4, c7, 1);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p4m) == NULL);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_b) == 0);
	CHECK(!zebra_ptrack_ctx_free_if_unused(ctx));	/* A has the v6 one */
	zebra_ptrack_del_cookies(ctx, &cl_a, &p6, c3, 1);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 0);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p6) == NULL);
	CHECK(zebra_ptrack_ctx_free_if_unused(ctx));
	CHECK(zebra_ptrack_ctx_lookup("Vrf1") == NULL);
	case_end();

	case_begin(13, "core terminate frees what is left");
	ctx = zebra_ptrack_ctx_get("Vrf1");
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &p4, c12, 2, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	CHECK(zebra_ptrack_add_cookies(ctx, &cl_b, &p6, c7, 1, &e) ==
	      ZEBRA_PTRACK_SUCCESS);
	ctx2 = zebra_ptrack_ctx_get("Vrf2");
	CHECK(ctx2 != NULL);
	zebra_ptrack_terminate();
	CHECK(zebra_ptrack_ctx_lookup("Vrf1") == NULL);
	CHECK(zebra_ptrack_ctx_lookup("Vrf2") == NULL);
	case_end();
}

/* ---- C: register and unregister ---- */

static void test_register(void)
{
	struct ptrack_vrf_ctx *ctx;
	struct route_node *rn;
	uint64_t big[2000];
	uint64_t next;
	struct prefix p4 = pfx("10.0.0.0/24");
	struct prefix q = pfx("172.16.0.0/16");
	struct ptrack_entry *e;
	uint32_t i, left;

	case_begin(14, "register for a VRF that does not exist yet");
	reset();
	CHECK(!fv[FV_VRFX].present);
	reg(&cl_a, "VrfX", "10.0.0.5/24", c12, 2);
	reg(&cl_a, "VrfX", "10.8.8.0/24", c3, 1);
	/* kept, but nothing is answered and nothing is attached */
	CHECK(sent_n == 0);
	ctx = zebra_ptrack_ctx_lookup("VrfX");
	CHECK(ctx != NULL);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 3);
	CHECK(ent_state("VrfX", "10.0.0.0/24") == ZAPI_PTRACK_UNREACHABLE);

	/* the VRF appears, with a route for one prefix only */
	fv_up(FV_VRFX);
	rn = rn_hold(&fv[FV_VRFX].zvrf, AFI_IP, "10.0.0.0/24");
	rn_add_route(rn, 0);
	zebra_ptrack_vrf_enable(&fv[FV_VRFX].zvrf);
	CHECK(fv[FV_VRFX].zvrf.ptrack == ctx);
	/* the flip is told, the prefix that stays UNREACHABLE says nothing */
	CHECK(sent_n == 1);
	CHECK(sent_first(&cl_a));
	CHECK(upd.state == ZAPI_PTRACK_REACHABLE);
	CHECK(pfx_is(&upd.prefix, "10.0.0.0/24"));
	CHECK(upd.cookie_count == 2 && upd.cookies[0] == 1 &&
	      upd.cookies[1] == 2);
	CHECK(ent_state("VrfX", "10.8.8.0/24") == ZAPI_PTRACK_UNREACHABLE);
	route_unlock_node(rn);
	fv_down(FV_VRFX);
	case_end();

	case_begin(15, "register without a route answers UNREACHABLE");
	reset();
	fv_up(FV_VRF1);
	reg(&cl_a, "Vrf1", "10.0.0.5/24", c12, 2);
	CHECK(sent_n == 1);
	CHECK(sent_first(&cl_a));
	CHECK(upd.state == ZAPI_PTRACK_UNREACHABLE);
	CHECK(!strcmp(upd.vrf_name, "Vrf1"));
	/* the masked prefix, and every cookie of the request */
	CHECK(pfx_is(&upd.prefix, "10.0.0.0/24"));
	CHECK(upd.cookie_count == 2 && upd.cookies[0] == 1 &&
	      upd.cookies[1] == 2);
	ctx = zebra_ptrack_ctx_lookup("Vrf1");
	CHECK(ctx != NULL && fv[FV_VRF1].zvrf.ptrack == ctx);
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_UNREACHABLE);
	case_end();

	case_begin(16, "register state follows the RIB and the VRF");
	reset();
	fv_up(FV_VRF1);
	rn = rn_hold(&fv[FV_VRF1].zvrf, AFI_IP, "10.0.0.0/24");
	rn_add_route(rn, 0);
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c1, 1);
	CHECK(sent_n == 1 && sent_all_are(ZAPI_PTRACK_REACHABLE, "10.0.0.0/24"));
	sent_clear();

	/* only a route that is being removed: UNREACHABLE */
	rn_set_status(rn, ROUTE_ENTRY_REMOVED);
	reg(&cl_b, "Vrf1", "10.0.0.0/24", c2, 1);
	CHECK(sent_n == 1 && sent_all_are(ZAPI_PTRACK_UNREACHABLE, "10.0.0.0/24"));
	sent_clear();
	rn_set_status(rn, 0);

	/* an inactive VRF: UNREACHABLE even with a route */
	fv[FV_VRF1].vrf.status = 0;
	reg(&cl_c, "Vrf1", "10.0.0.0/24", c3, 1);
	CHECK(sent_n == 1 && sent_all_are(ZAPI_PTRACK_UNREACHABLE, "10.0.0.0/24"));
	fv[FV_VRF1].vrf.status = VRF_ACTIVE;

	/* IPv6 with no route */
	sent_clear();
	reg(&cl_a, "Vrf1", "2001:db8::1/64", c1, 1);
	CHECK(sent_n == 1 && sent_all_are(ZAPI_PTRACK_UNREACHABLE, "2001:db8::/64"));
	route_unlock_node(rn);
	case_end();

	case_begin(17, "register of an existing cookie answers again");
	reset();
	fv_up(FV_VRF1);
	rn = rn_hold(&fv[FV_VRF1].zvrf, AFI_IP, "10.0.0.0/24");
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	sent_clear();
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c1, 1);
	CHECK(sent_n == 1 && sent_first(&cl_a));
	CHECK(upd.cookie_count == 1 && upd.cookies[0] == 1);
	ctx = zebra_ptrack_ctx_lookup("Vrf1");
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 2);
	route_unlock_node(rn);
	case_end();

	case_begin(18, "register over the limit is dropped");
	reset();
	ctx = zebra_ptrack_ctx_get("Vrf1");
	next = 1000;
	left = ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT;
	while (left) {
		uint32_t k = left > 2000 ? 2000 : left;

		for (i = 0; i < k; i++)
			big[i] = next++;
		CHECK(zebra_ptrack_add_cookies(ctx, &cl_a, &q, big, k, &e) ==
		      ZEBRA_PTRACK_SUCCESS);
		left -= k;
	}
	big[0] = 99999999;
	reg(&cl_a, "Vrf1", "172.16.0.0/16", big, 1);
	CHECK(sent_n == 0);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) ==
	      ZEBRA_PTRACK_DEFAULT_COOKIE_LIMIT);
	/* another client is not affected */
	reg(&cl_b, "Vrf1", "172.16.0.0/16", c1, 1);
	CHECK(sent_n == 1);
	case_end();

	case_begin(19, "register without cookies tracks nothing");
	reset();
	fv_up(FV_VRF2);
	reg(&cl_a, "Vrf2", "10.0.0.0/24", cnone, 0);
	CHECK(sent_n == 0);
	CHECK(zebra_ptrack_ctx_lookup("Vrf2") == NULL);
	CHECK(fv[FV_VRF2].zvrf.ptrack == NULL);
	case_end();

	case_begin(20, "unregister");
	reset();
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	reg(&cl_b, "Vrf1", "10.0.0.0/24", c7, 1);
	sent_clear();
	ctx = zebra_ptrack_ctx_lookup("Vrf1");
	unreg(&cl_a, "Vrf1", "10.0.0.5/24", c123, 3);	/* 3 is not there */
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 0);
	CHECK(ent_state("Vrf1", "10.0.0.0/24") != -1);
	CHECK(fv[FV_VRF1].zvrf.ptrack == ctx);
	/* the last one frees the context, and the pointer goes first */
	unreg(&cl_b, "Vrf1", "10.0.0.0/24", c7, 1);
	CHECK(zebra_ptrack_ctx_lookup("Vrf1") == NULL);
	CHECK(fv[FV_VRF1].zvrf.ptrack == NULL);
	/* nothing tracked: harmless */
	unreg(&cl_b, "Vrf1", "10.0.0.0/24", c7, 1);
	CHECK(sent_n == 0);

	/* the VRF is gone: it still works */
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	sent_clear();
	fv_down(FV_VRF1);
	unreg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	CHECK(zebra_ptrack_ctx_lookup("Vrf1") == NULL);
	fv_up(FV_VRF1);
	case_end();

	case_begin(21, "a new zebra_vrf gets the context back");
	reset();
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	ctx = zebra_ptrack_ctx_lookup("Vrf1");
	CHECK(fv[FV_VRF1].zvrf.ptrack == ctx);
	sent_clear();

	/* by the enable of the VRF */
	fv_down(FV_VRF1);
	fv_up(FV_VRF1);
	CHECK(fv[FV_VRF1].zvrf.ptrack == NULL);
	zebra_ptrack_vrf_enable(&fv[FV_VRF1].zvrf);
	CHECK(fv[FV_VRF1].zvrf.ptrack == ctx);

	/* or by the next register */
	fv_down(FV_VRF1);
	fv_up(FV_VRF1);
	reg(&cl_b, "Vrf1", "10.0.0.0/24", c7, 1);
	CHECK(fv[FV_VRF1].zvrf.ptrack == ctx);
	case_end();

	(void)p4;
}

/* ---- D: route changes ---- */

static void test_evaluate(void)
{
	struct route_node *rn, *rno, *rx;
	struct route_table *other;
	struct ptrack_vrf_ctx *ctx;
	uint64_t cb[2000];
	uint64_t next;
	int i, k, total;
	bool seen[6000];
	bool ok;

	case_begin(22, "evaluate flips and notifies every client");
	reset();
	fv_up(FV_VRF1);
	rn = rn_hold(&fv[FV_VRF1].zvrf, AFI_IP, "10.0.0.0/24");
	rn_add_route(rn, 0);
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	reg(&cl_b, "Vrf1", "10.0.0.0/24", c7, 1);
	sent_clear();
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_REACHABLE);

	/* nothing changed */
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 0);

	/* the route is removed, every client gets its own cookies */
	rn_set_status(rn, ROUTE_ENTRY_REMOVED);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 2);
	CHECK(sent_to(&cl_a) == 1 && sent_to(&cl_b) == 1);
	CHECK(sent_first(&cl_a));
	CHECK(upd.state == ZAPI_PTRACK_UNREACHABLE && upd.cookie_count == 2 &&
	      upd.cookies[0] == 1 && upd.cookies[1] == 2);
	CHECK(sent_first(&cl_b));
	CHECK(upd.state == ZAPI_PTRACK_UNREACHABLE && upd.cookie_count == 1 &&
	      upd.cookies[0] == 7);
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_UNREACHABLE);
	sent_clear();

	/* same state again */
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 0);

	/* the dest is freed: still UNREACHABLE */
	rn_free_dest(rn);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 0);

	/* the route is back */
	rn_add_route(rn, 0);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 2);
	CHECK(sent_all_are(ZAPI_PTRACK_REACHABLE, "10.0.0.0/24"));
	sent_clear();
	case_end();

	case_begin(23, "evaluate ignores what is not tracked");
	/* a prefix nobody tracks */
	rno = rn_hold(&fv[FV_VRF1].zvrf, AFI_IP, "192.0.2.0/24");
	rn_add_route(rno, 0);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rno);
	CHECK(sent_n == 0);

	/* the same prefix in a table that is not the unicast one of the VRF */
	other = route_table_init();
	{
		struct prefix pf = pfx("10.0.0.0/24");

		rx = route_node_get(other, &pf);
	}
	rn_set_status(rn, ROUTE_ENTRY_REMOVED);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rx);
	CHECK(sent_n == 0);
	rn_set_status(rn, 0);
	route_unlock_node(rx);
	route_table_finish(other);

	/* a VRF that tracks nothing */
	zebra_ptrack_evaluate(&fv[FV_VRF2].zvrf, rn);
	CHECK(sent_n == 0);
	route_unlock_node(rno);
	case_end();

	case_begin(24, "evaluate splits many cookies");
	reset();
	rn_set_status(rn, 0);
	next = 5000;
	for (k = 0; k < 3; k++) {
		for (i = 0; i < 2000; i++)
			cb[i] = next++;
		reg(&cl_c, "Vrf1", "10.0.0.0/24", cb, 2000);
		sent_clear();
	}
	ctx = zebra_ptrack_ctx_lookup("Vrf1");
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_c) == 6000);
	rn_set_status(rn, ROUTE_ENTRY_REMOVED);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	memset(seen, 0, sizeof(seen));
	ok = true;
	total = 0;
	for (k = 0; k < sent_n; k++) {
		ok &= sent_decode(k, &upd) &&
		      upd.state == ZAPI_PTRACK_UNREACHABLE;
		ok &= upd.cookie_count <= ZAPI_PTRACK_MAX_COOKIES;
		for (i = 0; ok && i < upd.cookie_count; i++) {
			ok &= upd.cookies[i] >= 5000 &&
			      upd.cookies[i] < 11000 &&
			      !seen[upd.cookies[i] - 5000];
			if (ok)
				seen[upd.cookies[i] - 5000] = true;
		}
		total += upd.cookie_count;
	}
	CHECK(ok);
	CHECK(sent_n == 3);
	CHECK(total == 6000);
	route_unlock_node(rn);
	case_end();
}

/* ---- E: the life of the VRF ---- */

static void test_vrf(void)
{
	struct ptrack_vrf_ctx *ctx;
	struct route_node *rn;
	struct fake_vrf *f = &fv[FV_VRF1];
	uint64_t cb[2000];
	int i, k, n, msgs, total;

	case_begin(25, "vrf disable forces UNREACHABLE");
	reset();
	fv_up(FV_VRF1);

	/* nothing tracked: nothing happens */
	zebra_ptrack_vrf_enable(&f->zvrf);
	CHECK(f->zvrf.ptrack == NULL && sent_n == 0);
	zebra_ptrack_vrf_disable(&f->zvrf);
	CHECK(sent_n == 0);

	rn = rn_hold(&f->zvrf, AFI_IP, "10.0.0.0/24");
	rn_add_route(rn, 0);
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	reg(&cl_b, "Vrf1", "10.0.0.0/24", c7, 1);
	reg(&cl_a, "Vrf1", "2001:db8::/64", c3, 1);
	sent_clear();
	ctx = zebra_ptrack_ctx_lookup("Vrf1");
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_REACHABLE);
	CHECK(ent_state("Vrf1", "2001:db8::/64") == ZAPI_PTRACK_UNREACHABLE);

	/* the routes are retained: only the reachable prefix flips */
	f->vrf.status = 0;
	zebra_ptrack_vrf_disable(&f->zvrf);
	CHECK(sent_n == 2);
	CHECK(sent_all_are(ZAPI_PTRACK_UNREACHABLE, "10.0.0.0/24"));
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_UNREACHABLE);
	sent_clear();
	/* the subscriptions stay */
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 3);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_b) == 1);
	/* a second time, and route events while it is down */
	zebra_ptrack_vrf_disable(&f->zvrf);
	zebra_ptrack_evaluate(&f->zvrf, rn);
	CHECK(sent_n == 0);
	case_end();

	case_begin(26, "vrf enable attaches by name and looks at all prefixes");
	f->zvrf.ptrack = NULL;
	f->vrf.status = VRF_ACTIVE;
	zebra_ptrack_vrf_enable(&f->zvrf);
	CHECK(f->zvrf.ptrack == ctx);
	CHECK(sent_n == 2);
	CHECK(sent_all_are(ZAPI_PTRACK_REACHABLE, "10.0.0.0/24"));
	sent_clear();
	/* a second enable changes nothing */
	zebra_ptrack_vrf_enable(&f->zvrf);
	CHECK(sent_n == 0);
	case_end();

	case_begin(27, "vrf deleted and added again");
	f->vrf.status = 0;
	zebra_ptrack_vrf_disable(&f->zvrf);
	sent_clear();
	route_unlock_node(rn);
	fv_down(FV_VRF1);
	fv_up(FV_VRF1);
	zebra_ptrack_vrf_enable(&f->zvrf);
	CHECK(f->zvrf.ptrack == ctx);
	CHECK(sent_n == 0);	/* no route yet, still UNREACHABLE */
	/* the subscriptions survived: a route reaches the old clients */
	rn = rn_hold(&f->zvrf, AFI_IP, "10.0.0.0/24");
	rn_add_route(rn, 0);
	zebra_ptrack_evaluate(&f->zvrf, rn);
	CHECK(sent_n == 2);
	CHECK(sent_all_are(ZAPI_PTRACK_REACHABLE, "10.0.0.0/24"));
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 3);
	sent_clear();
	case_end();

	case_begin(28, "vrf disable splits many cookies");
	reset();
	if (!f->present)
		fv_up(FV_VRF1);
	/* reset() dropped the contexts, the pointers and the route stay */
	rn_set_status(rn, 0);
	for (k = 0; k < 3; k++) {
		for (i = 0; i < 2000; i++)
			cb[i] = 20000 + k * 2000 + i;
		reg(&cl_c, "Vrf1", "10.0.0.0/24", cb, 2000);
		sent_clear();
	}
	f->vrf.status = 0;
	zebra_ptrack_vrf_disable(&f->zvrf);
	msgs = 0;
	total = 0;
	for (n = 0; n < sent_n; n++) {
		CHECK(sent_decode(n, &upd));
		CHECK(upd.state == ZAPI_PTRACK_UNREACHABLE);
		CHECK(upd.cookie_count <= ZAPI_PTRACK_MAX_COOKIES);
		msgs++;
		total += upd.cookie_count;
	}
	CHECK(msgs == 3 && total == 6000);
	f->vrf.status = VRF_ACTIVE;
	route_unlock_node(rn);
	case_end();
}

/* ---- F: a client goes away ---- */

static void test_close(void)
{
	struct ptrack_vrf_ctx *ctx;
	struct prefix p4 = pfx("10.0.0.0/24");
	struct prefix p6 = pfx("2001:db8::/64");

	case_begin(29, "client close removes only that client");
	reset();
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	reg(&cl_b, "Vrf1", "10.0.0.0/24", c7, 1);
	reg(&cl_a, "Vrf1", "2001:db8::/64", c3, 1);
	reg(&cl_c, "Vrf1", "2001:db8::/64", c9, 1);
	sent_clear();
	ctx = zebra_ptrack_ctx_lookup("Vrf1");
	CHECK(ctx != NULL && fv[FV_VRF1].zvrf.ptrack == ctx);

	/* A leaves: B stays on the v4 prefix, C on the v6 one */
	hook_call(zserv_client_close, &cl_a);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_a) == 0);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_b) == 1);
	CHECK(zebra_ptrack_client_cookie_count(ctx, &cl_c) == 1);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p4) != NULL);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p6) != NULL);
	CHECK(fv[FV_VRF1].zvrf.ptrack == ctx);

	/* B leaves: the v4 prefix has nobody */
	hook_call(zserv_client_close, &cl_b);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p4) == NULL);
	CHECK(zebra_ptrack_entry_lookup(ctx, &p6) != NULL);

	/* C was the last: the context goes, and the pointer first */
	hook_call(zserv_client_close, &cl_c);
	CHECK(zebra_ptrack_ctx_lookup("Vrf1") == NULL);
	CHECK(fv[FV_VRF1].zvrf.ptrack == NULL);

	/* a client with nothing, and a second close: harmless */
	hook_call(zserv_client_close, &cl_c);
	hook_call(zserv_client_close, &cl_a);
	/* a close sends nothing */
	CHECK(sent_n == 0);
	case_end();
}

/* ---- G: the startup gate ---- */

static void test_gate(void)
{
	struct route_node *rn;
	struct ptrack_vrf_ctx *ctx;
	uint64_t cb[2000];
	int i, k, n, total;
	int a4 = 0, b4 = 0, c4 = 0, a6 = 0;

	case_begin(30, "sweep with nothing held schedules nothing");
	reset();
	/* the gate is open, as after a graceful restart */
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	CHECK(sent_n == 1);
	sent_clear();
	zebra_ptrack_rib_sweep();
	CHECK(nothing_scheduled());
	case_end();

	case_begin(31, "gate closed holds the answers and keeps the state");
	reset();
	startup_done = false;
	rn = rn_hold(&fv[FV_VRF1].zvrf, AFI_IP, "10.0.0.0/24");
	rn_add_route(rn, 0);
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	CHECK(sent_n == 0);
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_REACHABLE);
	/* flips are held too, the state is updated */
	rn_set_status(rn, ROUTE_ENTRY_REMOVED);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 0);
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_UNREACHABLE);
	rn_set_status(rn, 0);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 0);
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_REACHABLE);
	case_end();

	case_begin(32, "release sends the current state to every client");
	reset();
	startup_done = false;
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	reg(&cl_b, "Vrf1", "10.0.0.0/24", c7, 1);
	reg(&cl_a, "Vrf1", "2001:db8::/64", c3, 1);
	CHECK(sent_n == 0);
	/* the stale route was REACHABLE for the stored state, the sweep removed it */
	rn_set_status(rn, ROUTE_ENTRY_REMOVED);

	/* the sweep started: the gate is open, then the release is scheduled */
	startup_done = true;
	zebra_ptrack_rib_sweep();
	CHECK(sent_n == 0);

	/* a client that registers before the event runs is answered at once */
	reg(&cl_c, "Vrf1", "10.0.0.0/24", c1, 1);
	CHECK(sent_n == 1 && sent_first(&cl_c));
	CHECK(upd.state == ZAPI_PTRACK_UNREACHABLE);
	sent_clear();

	run_one_event();
	CHECK(sent_n == 4);	/* A, B, C on the v4 prefix and A on the v6 one */
	for (n = 0; n < sent_n; n++) {
		CHECK(sent_decode(n, &upd));
		CHECK(upd.state == ZAPI_PTRACK_UNREACHABLE);
		if (upd.prefix.family == AF_INET6)
			a6 += sent_client[n] == &cl_a && upd.cookie_count == 1 &&
			      upd.cookies[0] == 3;
		else if (sent_client[n] == &cl_a)
			a4 += upd.cookie_count == 2 && upd.cookies[0] == 1 &&
			      upd.cookies[1] == 2;
		else if (sent_client[n] == &cl_b)
			b4 += upd.cookie_count == 1 && upd.cookies[0] == 7;
		else if (sent_client[n] == &cl_c)
			c4 += upd.cookie_count == 1 && upd.cookies[0] == 1;
	}
	CHECK(a4 == 1 && b4 == 1 && c4 == 1 && a6 == 1);
	CHECK(ent_state("Vrf1", "10.0.0.0/24") == ZAPI_PTRACK_UNREACHABLE);
	sent_clear();

	/* the RIB processes the node later: same state, no duplicate */
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 0);

	/* released once: another sweep notification schedules nothing */
	zebra_ptrack_rib_sweep();
	CHECK(nothing_scheduled());

	/* and messages flow again */
	rn_set_status(rn, 0);
	zebra_ptrack_evaluate(&fv[FV_VRF1].zvrf, rn);
	CHECK(sent_n == 3);	/* A, B and C on the v4 prefix */
	sent_clear();
	case_end();

	case_begin(33, "release splits many cookies and tells about a VRF that is gone");
	reset();
	startup_done = false;
	for (k = 0; k < 3; k++) {
		for (i = 0; i < 2000; i++)
			cb[i] = 40000 + k * 2000 + i;
		reg(&cl_c, "Vrf1", "10.0.0.0/24", cb, 2000);
	}
	CHECK(sent_n == 0);
	/* the VRF is deleted while the answers are held */
	route_unlock_node(rn);
	fv_down(FV_VRF1);
	startup_done = true;
	zebra_ptrack_rib_sweep();
	run_one_event();
	total = 0;
	CHECK(sent_n == 3);
	for (n = 0; n < sent_n; n++) {
		CHECK(sent_decode(n, &upd));
		CHECK(upd.state == ZAPI_PTRACK_UNREACHABLE);
		CHECK(upd.cookie_count <= ZAPI_PTRACK_MAX_COOKIES);
		total += upd.cookie_count;
	}
	CHECK(total == 6000);
	ctx = zebra_ptrack_ctx_lookup("Vrf1");
	CHECK(ctx != NULL);
	sent_clear();
	fv_up(FV_VRF1);
	case_end();

	case_begin(34, "terminate cancels a scheduled release");
	reset();
	startup_done = false;
	reg(&cl_a, "Vrf1", "10.0.0.0/24", c12, 2);
	startup_done = true;
	zebra_ptrack_rib_sweep();
	zebra_ptrack_terminate();
	CHECK(nothing_scheduled());
	CHECK(sent_n == 0);
	case_end();
}

int main(int argc, char **argv)
{
	int i;

	zlog_aux_init("NONE: ", ZLOG_DISABLED);

	zrouter.master = event_master_create("ptrack test");

	zebra_ptrack_init();

	fv_up(FV_VRF1);
	fv_up(FV_VRF2);

	test_codec();
	test_core();
	test_register();
	test_evaluate();
	test_vrf();
	test_close();
	test_gate();

	/* nothing may be left behind */
	zebra_ptrack_terminate();
	sent_clear();
	for (i = 0; i < 3; i++)
		if (fv[i].present)
			fv_down(i);

	printf("%s\n", failed ? "FAILED" : "all ok");

	return failed ? 1 : 0;
}
