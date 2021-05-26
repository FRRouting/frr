/*
 * This file defines the lua interface into
 * FRRouting.
 *
 * Copyright (C) 2016-2019 Cumulus Networks, Inc.
 * Donald Sharp, Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include "prefix.h"
#include "frrlua.h"
#include "log.h"
#include "buffer.h"

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
 * Encoders.
 *
 * This section has functions that convert internal FRR datatypes into Lua
 * datatypes.
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

void *lua_toprefix(lua_State *L, int idx)
{
	struct prefix *p = XCALLOC(MTYPE_TMP, sizeof(struct prefix));

	lua_getfield(L, idx, "network");
	(void)str2prefix(lua_tostring(L, -1), p);
	lua_pop(L, 1);

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

void *lua_tointerface(lua_State *L, int idx)
{
	struct interface *ifp = XCALLOC(MTYPE_TMP, sizeof(struct interface));

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

void *lua_toinaddr(lua_State *L, int idx)
{
	struct in_addr *inaddr = XCALLOC(MTYPE_TMP, sizeof(struct in_addr));

	lua_getfield(L, idx, "value");
	inaddr->s_addr = lua_tointeger(L, -1);
	lua_pop(L, 1);

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

void *lua_toin6addr(lua_State *L, int idx)
{
	struct in6_addr *in6addr = XCALLOC(MTYPE_TMP, sizeof(struct in6_addr));

	lua_getfield(L, idx, "string");
	inet_pton(AF_INET6, lua_tostring(L, -1), in6addr);
	lua_pop(L, 1);

	return in6addr;
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

void *lua_tosockunion(lua_State *L, int idx)
{
	union sockunion *su = XCALLOC(MTYPE_TMP, sizeof(union sockunion));

	lua_getfield(L, idx, "string");
	str2sockunion(lua_tostring(L, -1), su);

	return su;
}

void lua_pushtimet(lua_State *L, const time_t *time)
{
	lua_pushinteger(L, *time);
}

void *lua_totimet(lua_State *L, int idx)
{
	time_t *t = XCALLOC(MTYPE_TMP, sizeof(time_t));

	*t = lua_tointeger(L, idx);

	return t;
}

void lua_pushintegerp(lua_State *L, const long long *num)
{
	lua_pushinteger(L, *num);
}

void *lua_tointegerp(lua_State *L, int idx)
{
	int isnum;
	long long *num = XCALLOC(MTYPE_TMP, sizeof(long long));

	*num = lua_tonumberx(L, idx, &isnum);
	assert(isnum);

	return num;
}

void *lua_tostringp(lua_State *L, int idx)
{
	char *string = XSTRDUP(MTYPE_TMP, lua_tostring(L, idx));

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
	{"debug", frrlua_log_debug},
	{"info", frrlua_log_info},
	{"notice", frrlua_log_notice},
	{"warn", frrlua_log_warn},
	{"error", frrlua_log_error},
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
