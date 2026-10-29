// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Lua attr encode/decode/apply unit tests
 * Copyright (C) 2026
 */

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "queue.h"
#include "filter.h"
#include "frr_pthread.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_script.h"
#include "lib/asn.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static int failed;

#define CHECK(cond)                                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			failed++;                                              \
		}                                                              \
	} while (0)

static void test_metric_localpref_aspath_roundtrip(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct attr dst = {};
	struct aspath *asp;

	asp = aspath_str2aspath("65001 65002", ASNOTATION_PLAIN);
	CHECK(asp != NULL);
	orig.aspath = asp;
	SET_FLAG(orig.flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));
	bgp_attr_set_med(&orig, 100);
	SET_FLAG(orig.flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
	orig.local_pref = 200;
	orig.nh_ifindex = 7;

	lua_pushattr(L, &orig);
	CHECK(lua_istable(L, -1));

	lua_getfield(L, -1, "metric");
	CHECK(lua_tointeger(L, -1) == 100);
	lua_pop(L, 1);
	lua_getfield(L, -1, "localpref");
	CHECK(lua_tointeger(L, -1) == 200);
	lua_pop(L, 1);
	lua_getfield(L, -1, "aspath");
	CHECK(strcmp(lua_tostring(L, -1), "65001 65002") == 0);
	lua_pop(L, 1);

	/* Mutate in Lua */
	lua_pushinteger(L, 150);
	lua_setfield(L, -2, "metric");
	lua_pushinteger(L, 250);
	lua_setfield(L, -2, "localpref");
	lua_pushstring(L, "65009");
	lua_setfield(L, -2, "aspath");

	working = orig;
	lua_decode_attr(L, -1, &working);

	CHECK(working.med == 150);
	CHECK(bgp_attr_exists(&working, BGP_ATTR_MULTI_EXIT_DISC));
	CHECK(working.local_pref == 250);
	CHECK(working.aspath != orig.aspath);
	CHECK(working.aspath && working.aspath->str
	      && strcmp(working.aspath->str, "65009") == 0);
	/* original interned/uninterned aspath untouched */
	CHECK(orig.aspath && strcmp(orig.aspath->str, "65001 65002") == 0);

	bgp_attr_script_apply(&dst, &working);
	CHECK(dst.med == 150);
	CHECK(dst.local_pref == 250);
	CHECK(dst.aspath && strcmp(dst.aspath->str, "65009") == 0);
	CHECK(working.aspath == NULL); /* moved */

	bgp_attr_script_discard(&working, &orig);
	aspath_free(dst.aspath);
	aspath_free(orig.aspath);
	lua_close(L);
}

static void test_optional_nil_clears_presence(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct attr dst = {};

	bgp_attr_set_med(&orig, 42);
	SET_FLAG(orig.flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
	orig.local_pref = 99;

	lua_pushattr(L, &orig);
	lua_pushnil(L);
	lua_setfield(L, -2, "metric");
	lua_pushnil(L);
	lua_setfield(L, -2, "localpref");

	working = orig;
	lua_decode_attr(L, -1, &working);
	bgp_attr_script_apply(&dst, &working);

	CHECK(!bgp_attr_exists(&dst, BGP_ATTR_MULTI_EXIT_DISC));
	CHECK(!bgp_attr_exists(&dst, BGP_ATTR_LOCAL_PREF));
	CHECK(dst.med == 0);
	CHECK(dst.local_pref == 0);

	bgp_attr_script_discard(&working, &orig);
	lua_close(L);
}

static void test_origin_weight_community_roundtrip(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct attr dst = {};
	struct community *com;

	orig.origin = BGP_ORIGIN_EGP;
	orig.weight = 500;
	com = community_str2com("65000:1");
	CHECK(com != NULL);
	bgp_attr_set_community(&orig, com);

	lua_pushattr(L, &orig);
	lua_getfield(L, -1, "origin");
	CHECK(strcmp(lua_tostring(L, -1), "egp") == 0);
	lua_pop(L, 1);
	lua_getfield(L, -1, "weight");
	CHECK(lua_tointeger(L, -1) == 500);
	lua_pop(L, 1);

	lua_pushstring(L, "igp");
	lua_setfield(L, -2, "origin");
	lua_pushinteger(L, 600);
	lua_setfield(L, -2, "weight");
	lua_pushstring(L, "65000:2");
	lua_setfield(L, -2, "community");

	working = orig;
	lua_decode_attr(L, -1, &working);
	bgp_attr_script_apply(&dst, &working);

	CHECK(dst.origin == BGP_ORIGIN_IGP);
	CHECK(dst.weight == 600);
	CHECK(bgp_attr_get_community(&dst) != NULL);

	bgp_attr_script_discard(&working, &orig);
	if (bgp_attr_get_community(&dst)
	    && bgp_attr_get_community(&dst)->refcnt == 0) {
		struct community *c = bgp_attr_get_community(&dst);

		community_free(&c);
	}
	if (com && com->refcnt == 0)
		community_free(&com);
	lua_close(L);
}

static void test_nexthop_roundtrip(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct attr dst = {};

	inet_pton(AF_INET, "10.1.2.3", &orig.nexthop);
	SET_FLAG(orig.flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));

	lua_pushattr(L, &orig);
	lua_getfield(L, -1, "nexthop");
	CHECK(lua_istable(L, -1));
	lua_getfield(L, -1, "ipv4");
	CHECK(strcmp(lua_tostring(L, -1), "10.1.2.3") == 0);
	lua_pop(L, 2);

	lua_getfield(L, -1, "nexthop");
	lua_pushstring(L, "10.9.8.7");
	lua_setfield(L, -2, "ipv4");
	lua_pop(L, 1);

	working = orig;
	lua_decode_attr(L, -1, &working);
	bgp_attr_script_apply(&dst, &working);

	CHECK(bgp_attr_exists(&dst, BGP_ATTR_NEXT_HOP));
	CHECK(dst.nexthop.s_addr == working.nexthop.s_addr);
	CHECK(CHECK_FLAG(dst.rmap_change_flags, BATTR_RMAP_IPV4_NHOP_CHANGED));

	bgp_attr_script_discard(&working, &orig);
	lua_close(L);
}

static void test_ipv6_local_keeps_mp_len(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct attr dst = {};

	inet_pton(AF_INET6, "2001:db8::1", &orig.mp_nexthop_global);
	orig.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;

	lua_pushattr(L, &orig);
	lua_getfield(L, -1, "nexthop");
	lua_pushstring(L, "fe80::1");
	lua_setfield(L, -2, "ipv6_local");
	lua_pop(L, 1);

	working = orig;
	lua_decode_attr(L, -1, &working);
	bgp_attr_script_apply(&dst, &working);

	CHECK(dst.mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL);
	CHECK(CHECK_FLAG(dst.rmap_change_flags, BATTR_RMAP_IPV6_LL_NHOP_CHANGED));

	bgp_attr_script_discard(&working, &orig);
	lua_close(L);
}

static void test_evpn_esi_overlay_preserved(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working = {};
	struct bgp_route_evpn *bre;

	bre = XCALLOC(MTYPE_BGP_EVPN_OVERLAY, sizeof(*bre));
	bre->type = OVERLAY_INDEX_ESI;
	bgp_attr_set_evpn_overlay(&orig, bre);

	lua_pushattr(L, &orig);
	lua_pushinteger(L, 9);
	lua_setfield(L, -2, "metric");

	bgp_attr_dup_into(&working, &orig);
	lua_decode_attr(L, -1, &working);

	CHECK(bgp_attr_get_evpn_overlay(&working) != NULL);
	CHECK(bgp_attr_get_evpn_overlay(&working)->type == OVERLAY_INDEX_ESI);

	bgp_attr_script_discard(&working, &orig);
	bgp_attr_extra_discard(&working);
	if (bre->refcnt == 0)
		evpn_overlay_free(bre);
	bgp_attr_extra_discard(&orig);
	lua_close(L);
}

static void test_evpn_flags_applied_without_overlay_change(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct attr dst = {};

	/* No gateway-IP overlay set, so the overlay pointer stays NULL
	 * (unchanged) across the round-trip; only the flags sub-table
	 * is mutated by the script.
	 */
	lua_pushattr(L, &orig);
	lua_getfield(L, -1, "evpn");
	lua_getfield(L, -1, "flags");
	lua_pushboolean(L, true);
	lua_setfield(L, -2, "sticky");
	lua_pushboolean(L, true);
	lua_setfield(L, -2, "router");
	lua_pop(L, 2); /* flags, evpn */

	working = orig;
	lua_decode_attr(L, -1, &working);
	CHECK(CHECK_FLAG(working.evpn_flags, ATTR_EVPN_FLAG_STICKY));
	CHECK(CHECK_FLAG(working.evpn_flags, ATTR_EVPN_FLAG_ROUTER));
	CHECK(bgp_attr_get_evpn_overlay(&working) == bgp_attr_get_evpn_overlay(&orig));

	bgp_attr_script_apply(&dst, &working);
	CHECK(CHECK_FLAG(dst.evpn_flags, ATTR_EVPN_FLAG_STICKY));
	CHECK(CHECK_FLAG(dst.evpn_flags, ATTR_EVPN_FLAG_ROUTER));

	bgp_attr_script_discard(&working, &orig);
	lua_close(L);
}

static void test_aspath_unchanged_and_parse_failure(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct aspath *asp;

	asp = aspath_str2aspath("65001 65002", ASNOTATION_PLAIN);
	CHECK(asp != NULL);
	orig.aspath = asp;
	SET_FLAG(orig.flag, ATTR_FLAG_BIT(BGP_ATTR_AS_PATH));

	lua_pushattr(L, &orig);
	lua_pushvalue(L, -1);
	working = orig;
	lua_decode_attr(L, -1, &working);
	CHECK(working.aspath == orig.aspath);

	lua_pushstring(L, "not-an-aspath-!!!");
	lua_setfield(L, -2, "aspath");
	lua_decode_attr(L, -1, &working);
	CHECK(working.aspath == orig.aspath);
	CHECK(strcmp(orig.aspath->str, "65001 65002") == 0);

	bgp_attr_script_discard(&working, &orig);
	aspath_free(orig.aspath);
	lua_close(L);
}

static void test_community_parse_failure_keeps_original(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct community *com;

	com = community_str2com("65000:1");
	CHECK(com != NULL);
	bgp_attr_set_community(&orig, com);

	lua_pushattr(L, &orig);
	lua_pushstring(L, "not a community");
	lua_setfield(L, -2, "community");

	working = orig;
	lua_decode_attr(L, -1, &working);
	CHECK(bgp_attr_get_community(&working) == com);

	bgp_attr_script_discard(&working, &orig);
	if (com && com->refcnt == 0)
		community_free(&com);
	lua_close(L);
}

static void test_label_index_nil_and_zero_clear_prefix_sid(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct attr dst = {};

	orig.label_index = 10;
	SET_FLAG(orig.flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID));

	/* nil clears presence, consistent with other optional numeric
	 * attributes (metric, localpref, aigp_metric).
	 */
	lua_pushattr(L, &orig);
	lua_pushnil(L);
	lua_setfield(L, -2, "label_index");

	working = orig;
	lua_decode_attr(L, -1, &working);
	CHECK(!bgp_attr_exists(&working, BGP_ATTR_PREFIX_SID));
	CHECK(working.label_index == 0);

	bgp_attr_script_apply(&dst, &working);
	CHECK(!bgp_attr_exists(&dst, BGP_ATTR_PREFIX_SID));
	CHECK(dst.label_index == 0);

	bgp_attr_script_discard(&working, &orig);

	/* An explicit 0 clears presence too. */
	working = orig;
	lua_pushattr(L, &orig);
	lua_pushinteger(L, 0);
	lua_setfield(L, -2, "label_index");
	lua_decode_attr(L, -1, &working);
	CHECK(!bgp_attr_exists(&working, BGP_ATTR_PREFIX_SID));
	CHECK(working.label_index == 0);

	bgp_attr_script_discard(&working, &orig);
	lua_close(L);
}

static void test_origin_integer_decode(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;

	orig.origin = BGP_ORIGIN_EGP;

	lua_pushattr(L, &orig);
	lua_pushinteger(L, BGP_ORIGIN_IGP);
	lua_setfield(L, -2, "origin");

	working = orig;
	lua_decode_attr(L, -1, &working);
	CHECK(working.origin == BGP_ORIGIN_IGP);

	bgp_attr_script_discard(&working, &orig);
	lua_close(L);
}

static void test_extcommunity_roundtrip(void)
{
	lua_State *L = luaL_newstate();
	struct attr orig = {};
	struct attr working;
	struct attr dst = {};
	struct ecommunity *ecom;
	const char *encoded;

	ecom = ecommunity_str2com("rt 65000:1", 0, 1);
	CHECK(ecom != NULL);
	bgp_attr_set_ecommunity(&orig, ecom);

	lua_pushattr(L, &orig);
	lua_getfield(L, -1, "extcommunity");
	encoded = lua_tostring(L, -1);
	CHECK(encoded != NULL);
	CHECK(strncmp(encoded, "rt ", 3) == 0);
	lua_pop(L, 1);

	/* Match-and-change that only touches MED must not drop RT/SoO. */
	lua_pushinteger(L, 50);
	lua_setfield(L, -2, "metric");

	working = orig;
	lua_decode_attr(L, -1, &working);
	bgp_attr_script_apply(&dst, &working);

	CHECK(bgp_attr_get_ecommunity(&dst) != NULL);
	CHECK(bgp_attr_get_ecommunity(&dst)->size == ecom->size);

	bgp_attr_script_discard(&working, &orig);
	if (bgp_attr_get_ecommunity(&dst)
	    && bgp_attr_get_ecommunity(&dst)->refcnt == 0) {
		struct ecommunity *c = bgp_attr_get_ecommunity(&dst);

		ecommunity_free(&c);
	} else
		ecommunity_free(&ecom);
	lua_close(L);
}

int main(int argc, char **argv)
{
	printf("Scripting");
	failed = 0;
	test_metric_localpref_aspath_roundtrip();
	test_optional_nil_clears_presence();
	test_origin_weight_community_roundtrip();
	test_nexthop_roundtrip();
	test_ipv6_local_keeps_mp_len();
	test_evpn_esi_overlay_preserved();
	test_evpn_flags_applied_without_overlay_change();
	test_aspath_unchanged_and_parse_failure();
	test_community_parse_failure_keeps_original();
	test_label_index_nil_and_zero_clear_prefix_sid();
	test_origin_integer_decode();
	test_extcommunity_roundtrip();

	printf("%s\n", failed ? "FAILED" : "OK");
	return failed ? 1 : 0;
}

#else /* !HAVE_SCRIPTING */

int main(int argc, char **argv)
{
	printf("Scripting\nOK\n");
	return 0;
}

#endif /* HAVE_SCRIPTING */
