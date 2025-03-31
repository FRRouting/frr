// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file defines the lua interface into
 * FRRouting.
 *
 * Copyright (C) 2016-2019 Cumulus Networks, Inc.
 * Donald Sharp, Quentin Young
 */

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include "prefix.h"
#include "frrlua.h"
#include "log.h"
#include "buffer.h"

DEFINE_MTYPE(LIB, SCRIPT_RES, "Scripting results");

/* Lua stuff */

/*
 * FRR convenience functions.
 *
 * This section has convenience functions used to make interacting with the Lua
 * stack easier.
 */

int frrlua_table_get_integer(lua_State *L, const char *key)
{
	int result;

	lua_pushstring(L, key);
	lua_gettable(L, -2);

	result = lua_tointeger(L, -1);
	lua_pop(L, 1);

	return result;
}

/*
 * This section has functions that convert internal FRR datatypes into Lua
 * datatypes: one encoder function and two decoder functions for each type.
 *
 */

void lua_pushprefix(lua_State *L, const struct prefix *prefix)
{
	char buffer[PREFIX_STRLEN];

	lua_newtable(L);
	lua_pushstring(L, prefix2str(prefix, buffer, PREFIX_STRLEN));
	lua_setfield(L, -2, "network");
	lua_pushinteger(L, prefix->prefixlen);
	lua_setfield(L, -2, "length");
	lua_pushinteger(L, prefix->family);
	lua_setfield(L, -2, "family");
}

void lua_decode_prefix(lua_State *L, int idx, struct prefix *prefix)
{
	lua_getfield(L, idx, "network");
	(void)str2prefix(lua_tostring(L, -1), prefix);
	lua_pop(L, 1);
	/* pop the table */
	lua_pop(L, 1);
}

void *lua_toprefix(lua_State *L, int idx)
{
	struct prefix *p = XCALLOC(MTYPE_SCRIPT_RES, sizeof(struct prefix));
	lua_decode_prefix(L, idx, p);
	return p;
}

void lua_pushinterface(lua_State *L, const struct interface *ifp)
{
	lua_newtable(L);
	lua_pushstring(L, ifp->name);
	lua_setfield(L, -2, "name");
	lua_pushinteger(L, ifp->ifindex);
	lua_setfield(L, -2, "ifindex");
	lua_pushinteger(L, ifp->status);
	lua_setfield(L, -2, "status");
	lua_pushinteger(L, ifp->flags);
	lua_setfield(L, -2, "flags");
	lua_pushinteger(L, ifp->metric);
	lua_setfield(L, -2, "metric");
	lua_pushinteger(L, ifp->speed);
	lua_setfield(L, -2, "speed");
	lua_pushinteger(L, ifp->mtu);
	lua_setfield(L, -2, "mtu");
	lua_pushinteger(L, ifp->mtu6);
	lua_setfield(L, -2, "mtu6");
	lua_pushinteger(L, ifp->bandwidth);
	lua_setfield(L, -2, "bandwidth");
	lua_pushinteger(L, ifp->link_ifindex);
	lua_setfield(L, -2, "link_ifindex");
	lua_pushinteger(L, ifp->ll_type);
	lua_setfield(L, -2, "linklayer_type");
}

void lua_decode_interface(lua_State *L, int idx, struct interface *ifp)
{
	lua_getfield(L, idx, "name");
	strlcpy(ifp->name, lua_tostring(L, -1), sizeof(ifp->name));
	lua_pop(L, 1);
	lua_getfield(L, idx, "ifindex");
	ifp->ifindex = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "status");
	ifp->status = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "flags");
	ifp->flags = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "metric");
	ifp->metric = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "speed");
	ifp->speed = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "mtu");
	ifp->mtu = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "mtu6");
	ifp->mtu6 = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "bandwidth");
	ifp->bandwidth = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "link_ifindex");
	ifp->link_ifindex = lua_tointeger(L, -1);
	lua_pop(L, 1);
	lua_getfield(L, idx, "linklayer_type");
	ifp->ll_type = lua_tointeger(L, -1);
	lua_pop(L, 1);
	/* pop the table */
	lua_pop(L, 1);
}
void *lua_tointerface(lua_State *L, int idx)
{
	struct interface *ifp =
		XCALLOC(MTYPE_SCRIPT_RES, sizeof(struct interface));

	lua_decode_interface(L, idx, ifp);
	return ifp;
}

void lua_pushinaddr(lua_State *L, const struct in_addr *addr)
{
	char buf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, addr, buf, sizeof(buf));

	lua_newtable(L);
	lua_pushinteger(L, addr->s_addr);
	lua_setfield(L, -2, "value");
	lua_pushstring(L, buf);
	lua_setfield(L, -2, "string");
}

void lua_decode_inaddr(lua_State *L, int idx, struct in_addr *inaddr)
{
	lua_getfield(L, idx, "value");
	inaddr->s_addr = lua_tointeger(L, -1);
	lua_pop(L, 1);
	/* pop the table */
	lua_pop(L, 1);
}

void *lua_toinaddr(lua_State *L, int idx)
{
	struct in_addr *inaddr =
		XCALLOC(MTYPE_SCRIPT_RES, sizeof(struct in_addr));
	lua_decode_inaddr(L, idx, inaddr);
	return inaddr;
}


void lua_pushin6addr(lua_State *L, const struct in6_addr *addr)
{
	char buf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, buf, sizeof(buf));

	lua_newtable(L);
	lua_pushlstring(L, (const char *)addr->s6_addr, 16);
	lua_setfield(L, -2, "value");
	lua_pushstring(L, buf);
	lua_setfield(L, -2, "string");
}

void lua_decode_in6addr(lua_State *L, int idx, struct in6_addr *in6addr)
{
	lua_getfield(L, idx, "string");
	inet_pton(AF_INET6, lua_tostring(L, -1), in6addr);
	lua_pop(L, 1);
	/* pop the table */
	lua_pop(L, 1);
}

void *lua_toin6addr(lua_State *L, int idx)
{
	struct in6_addr *in6addr =
		XCALLOC(MTYPE_SCRIPT_RES, sizeof(struct in6_addr));
	lua_decode_in6addr(L, idx, in6addr);
	return in6addr;
}

void lua_pushipaddr(lua_State *L, const struct ipaddr *addr)
{
	if (IS_IPADDR_V4(addr))
		lua_pushinaddr(L, &addr->ipaddr_v4);
	else
		lua_pushin6addr(L, &addr->ipaddr_v6);
}

void lua_pushethaddr(lua_State *L, const struct ethaddr *addr)
{
	lua_newtable(L);
	lua_pushinteger(L, *(addr->octet));
	lua_setfield(L, -2, "octet");
}

void lua_pushsockunion(lua_State *L, const union sockunion *su)
{
	char buf[SU_ADDRSTRLEN];

	sockunion2str(su, buf, sizeof(buf));

	lua_newtable(L);
	lua_pushlstring(L, (const char *)sockunion_get_addr(su),
			sockunion_get_addrlen(su));
	lua_setfield(L, -2, "value");
	lua_pushstring(L, buf);
	lua_setfield(L, -2, "string");
}

void lua_decode_sockunion(lua_State *L, int idx, union sockunion *su)
{
	lua_getfield(L, idx, "string");
	if (str2sockunion(lua_tostring(L, -1), su) < 0)
		zlog_err("Lua hook call: Failed to decode sockunion");

	lua_pop(L, 1);
	/* pop the table */
	lua_pop(L, 1);
}

void *lua_tosockunion(lua_State *L, int idx)
{
	union sockunion *su =
		XCALLOC(MTYPE_SCRIPT_RES, sizeof(union sockunion));

	lua_decode_sockunion(L, idx, su);
	return su;
}

void lua_pushintegerp(lua_State *L, const int *num)
{
	lua_pushinteger(L, *num);
}

void lua_decode_integerp(lua_State *L, int idx, int *num)
{
	int isnum;
	*num = lua_tonumberx(L, idx, &isnum);
	lua_pop(L, 1);
	assert(isnum);
}

void *lua_tointegerp(lua_State *L, int idx)
{
	int *num = XCALLOC(MTYPE_SCRIPT_RES, sizeof(int));

	lua_decode_integerp(L, idx, num);
	return num;
}

void lua_pushnexthop(lua_State *L, const struct nexthop *nexthop)
{
	lua_newtable(L);
	lua_pushinteger(L, nexthop->vrf_id);
	lua_setfield(L, -2, "vrf_id");
	lua_pushinteger(L, nexthop->ifindex);
	lua_setfield(L, -2, "ifindex");
	lua_pushinteger(L, nexthop->type);
	lua_setfield(L, -2, "type");
	lua_pushinteger(L, nexthop->flags);
	lua_setfield(L, -2, "flags");
	if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE) {
		lua_pushinteger(L, nexthop->bh_type);
		lua_setfield(L, -2, "bh_type");
	} else if (nexthop->type == NEXTHOP_TYPE_IPV4) {
		lua_pushinaddr(L, &nexthop->gate.ipv4);
		lua_setfield(L, -2, "gate");
	} else if (nexthop->type == NEXTHOP_TYPE_IPV6) {
		lua_pushin6addr(L, &nexthop->gate.ipv6);
		lua_setfield(L, -2, "gate");
	}
	lua_pushinteger(L, nexthop->nh_label_type);
	lua_setfield(L, -2, "nh_label_type");
	lua_pushinteger(L, nexthop->weight);
	lua_setfield(L, -2, "weight");
	lua_pushinteger(L, nexthop->backup_num);
	lua_setfield(L, -2, "backup_num");
	lua_pushinteger(L, *(nexthop->backup_idx));
	lua_setfield(L, -2, "backup_idx");
	if (nexthop->nh_encap_type == NET_VXLAN) {
		lua_pushinteger(L, nexthop->nh_encap.vni);
		lua_setfield(L, -2, "vni");
	}
	lua_pushinteger(L, nexthop->nh_encap_type);
	lua_setfield(L, -2, "nh_encap_type");
	lua_pushinteger(L, nexthop->srte_color);
	lua_setfield(L, -2, "srte_color");
}

void lua_pushnexthop_group(lua_State *L, const struct nexthop_group *ng)
{
	lua_newtable(L);
	struct nexthop *nexthop;
	int i = 1;

	for (ALL_NEXTHOPS_PTR(ng, nexthop)) {
		lua_pushnexthop(L, nexthop);
		lua_seti(L, -2, i);
		i++;
	}
}

void lua_pushlonglongp(lua_State *L, const long long *num)
{
	/* lua library function; this can take a long long */
	lua_pushinteger(L, *num);
}

void lua_decode_longlongp(lua_State *L, int idx, long long *num)
{
	int isnum;
	*num = lua_tonumberx(L, idx, &isnum);
	lua_pop(L, 1);
	assert(isnum);
}

void *lua_tolonglongp(lua_State *L, int idx)
{
	long long *num = XCALLOC(MTYPE_SCRIPT_RES, sizeof(long long));

	lua_decode_longlongp(L, idx, num);
	return num;
}

void lua_decode_stringp(lua_State *L, int idx, char *str)
{
	strlcpy(str, lua_tostring(L, idx), strlen(str) + 1);
	lua_pop(L, 1);
}

void *lua_tostringp(lua_State *L, int idx)
{
	char *string = XSTRDUP(MTYPE_SCRIPT_RES, lua_tostring(L, idx));

	return string;
}

/*
 * Logging.
 *
 * Lua-compatible wrappers for FRR logging functions.
 */
static const char *frrlua_log_thunk(lua_State *L)
{
	int nargs;

	nargs = lua_gettop(L);
	assert(nargs == 1);

	return lua_tostring(L, 1);
}

static int frrlua_log_trace(lua_State *L)
{
	zlog_debug("%s", frrlua_stackdump(L));
	return 0;
}

static int frrlua_log_debug(lua_State *L)
{
	zlog_debug("%s", frrlua_log_thunk(L));
	return 0;
}

static int frrlua_log_info(lua_State *L)
{
	zlog_info("%s", frrlua_log_thunk(L));
	return 0;
}

static int frrlua_log_notice(lua_State *L)
{
	zlog_notice("%s", frrlua_log_thunk(L));
	return 0;
}

static int frrlua_log_warn(lua_State *L)
{
	zlog_warn("%s", frrlua_log_thunk(L));
	return 0;
}

static int frrlua_log_error(lua_State *L)
{
	zlog_err("%s", frrlua_log_thunk(L));
	return 0;
}

static const luaL_Reg log_funcs[] = {
	{ "trace", frrlua_log_trace },
	{ "debug", frrlua_log_debug },
	{ "info", frrlua_log_info },
	{ "notice", frrlua_log_notice },
	{ "warn", frrlua_log_warn },
	{ "error", frrlua_log_error },
	{},
};

void frrlua_export_logging(lua_State *L)
{
	lua_newtable(L);
	luaL_setfuncs(L, log_funcs, 0);
	lua_setglobal(L, "log");
}

/*
 * Debugging.
 */

void lua_table_dump(lua_State *L, int index, struct buffer *buf, int level)
{
	char tmpbuf[64] = {};

	lua_pushnil(L);

	while (lua_next(L, index) != 0) {
		int key_type;
		int value_type;

		for (int i = 0; i < level; i++)
			buffer_putstr(buf, "  ");

		key_type = lua_type(L, -2);
		if (key_type == LUA_TSTRING) {
			const char *key = lua_tostring(L, -2);

			buffer_putstr(buf, key);
			buffer_putstr(buf, ": ");
		} else if (key_type == LUA_TNUMBER) {
			snprintf(tmpbuf, sizeof(tmpbuf), "%g",
				 lua_tonumber(L, -2));
			buffer_putstr(buf, tmpbuf);
			buffer_putstr(buf, ": ");
		}

		value_type = lua_type(L, -1);
		switch (value_type) {
		case LUA_TSTRING:
			snprintf(tmpbuf, sizeof(tmpbuf), "\"%s\"\n",
				 lua_tostring(L, -1));
			buffer_putstr(buf, tmpbuf);
			break;
		case LUA_TBOOLEAN:
			snprintf(tmpbuf, sizeof(tmpbuf), "%s\n",
				 lua_toboolean(L, -1) ? "true" : "false");
			buffer_putstr(buf, tmpbuf);
			break;
		case LUA_TNUMBER:
			snprintf(tmpbuf, sizeof(tmpbuf), "%g\n",
				 lua_tonumber(L, -1));
			buffer_putstr(buf, tmpbuf);
			break;
		case LUA_TTABLE:
			buffer_putstr(buf, "{\n");
			lua_table_dump(L, lua_gettop(L), buf, level + 1);
			for (int i = 0; i < level; i++)
				buffer_putstr(buf, "  ");
			buffer_putstr(buf, "}\n");
			break;
		default:
			snprintf(tmpbuf, sizeof(tmpbuf), "%s\n",
				 lua_typename(L, value_type));
			buffer_putstr(buf, tmpbuf);
			break;
		}

		lua_pop(L, 1);
	}
}

char *frrlua_stackdump(lua_State *L)
{
	int top = lua_gettop(L);

	char tmpbuf[64];
	struct buffer *buf = buffer_new(4098);

	for (int i = 1; i <= top; i++) {
		int t = lua_type(L, i);

		switch (t) {
		case LUA_TSTRING: /* strings */
			snprintf(tmpbuf, sizeof(tmpbuf), "\"%s\"\n",
				 lua_tostring(L, i));
			buffer_putstr(buf, tmpbuf);
			break;
		case LUA_TBOOLEAN: /* booleans */
			snprintf(tmpbuf, sizeof(tmpbuf), "%s\n",
				 lua_toboolean(L, i) ? "true" : "false");
			buffer_putstr(buf, tmpbuf);
			break;
		case LUA_TNUMBER: /* numbers */
			snprintf(tmpbuf, sizeof(tmpbuf), "%g\n",
				 lua_tonumber(L, i));
			buffer_putstr(buf, tmpbuf);
			break;
		case LUA_TTABLE: /* tables */
			buffer_putstr(buf, "{\n");
			lua_table_dump(L, i, buf, 1);
			buffer_putstr(buf, "}\n");
			break;
		default: /* other values */
			snprintf(tmpbuf, sizeof(tmpbuf), "%s\n",
				 lua_typename(L, t));
			buffer_putstr(buf, tmpbuf);
			break;
		}
	}

	char *result = XSTRDUP(MTYPE_TMP, buffer_getstr(buf));

	buffer_free(buf);

	return result;
}

#endif /* HAVE_SCRIPTING */
