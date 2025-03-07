// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * frrlua unit tests
 * Copyright (C) 2021  Donald Lee
 */

#include <zebra.h>
#include "string.h"
#include "stdio.h"
#include "lib/frrlua.h"

static void test_encode_decode(void)
{
	lua_State *L = luaL_newstate();

	luaL_openlibs(L);

	int a = 123;
	int b = a;

	lua_pushintegerp(L, &a);
	lua_decode_integerp(L, -1, &a);
	assert(a == b);
	assert(lua_gettop(L) == 0);

	long long ll_a = 123L;
	long long ll_b = a;

	lua_pushlonglongp(L, &ll_a);
	lua_decode_longlongp(L, -1, &ll_a);
	assert(ll_a == ll_b);
	assert(lua_gettop(L) == 0);

	time_t time_a = 100;
	time_t time_b;

	lua_pushinteger(L, time_a);
	time_b = lua_tointeger(L, -1);
	lua_pop(L, 1);
	assert(time_a == time_b);
	assert(lua_gettop(L) == 0);

	char str_b[] = "Hello", str_a[6];

	strlcpy(str_a, str_b, sizeof(str_b));
	lua_pushstring_wrapper(L, str_a);
	lua_decode_stringp(L, -1, str_a);
	assert(strncmp(str_a, str_b, sizeof(str_b)) == 0);
	assert(lua_gettop(L) == 0);

	char p_b_str[] = "10.0.0.0/24", p_a_str[12];
	struct prefix p_a;

	strlcpy(p_a_str, p_b_str, sizeof(p_b_str));
	str2prefix(p_a_str, &p_a);
	lua_pushprefix(L, &p_a);
	lua_decode_prefix(L, -1, &p_a);
	prefix2str(&p_a, p_a_str, sizeof(p_b_str));
	assert(strncmp(p_a_str, p_b_str, sizeof(p_b_str)) == 0);
	assert(lua_gettop(L) == 0);

	struct interface ifp_a = {};
	struct interface ifp_b = ifp_a;

	lua_pushinterface(L, &ifp_a);
	lua_decode_interface(L, -1, &ifp_a);
	assert(strncmp(ifp_a.name, ifp_b.name, sizeof(ifp_b.name)) == 0);
	assert(ifp_a.ifindex == ifp_b.ifindex);
	assert(ifp_a.status == ifp_b.status);
	assert(ifp_a.flags == ifp_b.flags);
	assert(ifp_a.metric == ifp_b.metric);
	assert(ifp_a.speed == ifp_b.speed);
	assert(ifp_a.mtu == ifp_b.mtu);
	assert(ifp_a.mtu6 == ifp_b.mtu6);
	assert(ifp_a.bandwidth == ifp_b.bandwidth);
	assert(ifp_a.link_ifindex == ifp_b.link_ifindex);
	assert(ifp_a.ll_type == ifp_b.ll_type);
	assert(lua_gettop(L) == 0);

	struct in_addr addr_a = {};
	struct in_addr addr_b = addr_a;

	lua_pushinaddr(L, &addr_a);
	lua_decode_inaddr(L, -1, &addr_a);
	assert(addr_a.s_addr == addr_b.s_addr);
	assert(lua_gettop(L) == 0);

	struct in6_addr in6addr_a = {};
	struct in6_addr in6addr_b = in6addr_a;

	lua_pushin6addr(L, &in6addr_a);
	lua_decode_in6addr(L, -1, &in6addr_a);
	assert(memcmp(&in6addr_a, &in6addr_b, sizeof(struct in6_addr)) == 0);
	assert(lua_gettop(L) == 0);

	union sockunion su_a, su_b;

	memset(&su_a, 0, sizeof(union sockunion));
	memset(&su_b, 0, sizeof(union sockunion));
	lua_pushsockunion(L, &su_a);
	lua_decode_sockunion(L, -1, &su_a);
	assert(sockunion_cmp(&su_a, &su_b) == 0);
	assert(lua_gettop(L) == 0);

	/* Test if built-in functions (string() in this case) are working */
	const char *result;

	lua_getglobal(L, "string");
	lua_getfield(L, -1, "upper");
	lua_pushstring(L, "testas");
	lua_pcall(L, 1, 1, 0);

	result = lua_tostring(L, -1);
	assert(strmatch(result, "TESTAS"));
	lua_pop(L, 1);
	lua_close(L);
	/* End of built-in functions test */
}

int main(int argc, char **argv)
{
	test_encode_decode();
}
