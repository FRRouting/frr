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
#include "bgpd/bgp_script.h"
#include "lib/asn.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master = NULL;

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
	CHECK(CHECK_FLAG(working.flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)));
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

	CHECK(!CHECK_FLAG(dst.flag, ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)));
	CHECK(!CHECK_FLAG(dst.flag, ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)));
	CHECK(dst.med == 0);
	CHECK(dst.local_pref == 0);

	bgp_attr_script_discard(&working, &orig);
	lua_close(L);
}

int main(int argc, char **argv)
{
	failed = 0;
	test_metric_localpref_aspath_roundtrip();
	test_optional_nil_clears_presence();

	printf("%s\n", failed ? "FAILED" : "OK");
	return failed ? 1 : 0;
}

#else /* !HAVE_SCRIPTING */

int main(int argc, char **argv)
{
	printf("SKIPPED (no scripting)\n");
	return 0;
}

#endif /* HAVE_SCRIPTING */
