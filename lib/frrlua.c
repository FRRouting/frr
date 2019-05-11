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

#if defined(HAVE_LUA)
#include "prefix.h"
#include "frrlua.h"
#include "log.h"

/*
 * Lua -> FRR function bindings.
 *
 * This section defines functions exportable into Lua environments.
 */

static int lua_zlog_debug(lua_State *L)
{
	int debug_lua = 1;
	const char *string = lua_tostring(L, 1);

	if (debug_lua)
		zlog_debug("%s", string);

	return 0;
}

/*
 * FRR convenience functions.
 *
 * This section has convenience functions used to make interacting with the Lua
 * stack easier.
 */

const char *frrlua_table_get_string(lua_State *L, const char *key)
{
	const char *str;

	lua_pushstring(L, key);
	lua_gettable(L, -2);

	str = (const char *)lua_tostring(L, -1);
	lua_pop(L, 1);

	return str;
}

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

void frrlua_newtable_prefix(lua_State *L, const struct prefix *prefix)
{
	char buffer[100];

	zlog_debug("frrlua: pushing prefix table");

	lua_newtable(L);
	lua_pushstring(L, prefix2str(prefix, buffer, 100));
	lua_setfield(L, -2, "route");
	lua_pushinteger(L, prefix->family);
	lua_setfield(L, -2, "family");
	lua_setglobal(L, "prefix");
}

/*
 * Experimental.
 *
 * This section has experimental Lua functionality that doesn't belong
 * elsewhere.
 */

enum frrlua_rm_status frrlua_run_rm_rule(lua_State *L, const char *rule)
{
	int status;

	lua_getglobal(L, rule);
	status = lua_pcall(L, 0, 1, 0);
	if (status) {
		zlog_debug("Executing Failure with function: %s: %d",
			   rule, status);
		return LUA_RM_FAILURE;
	}

	status = lua_tonumber(L, -1);
	return status;
}

/* Initialization */

static void *frrlua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	(void)ud;
	(void)osize; /* not used */

	if (nsize == 0) {
		free(ptr);
		return NULL;
	} else
		return realloc(ptr, nsize);
}

lua_State *frrlua_initialize(const char *file)
{
	int status;
	lua_State *L = lua_newstate(frrlua_alloc, NULL);

	zlog_debug("Newstate: %p", L);
	luaL_openlibs(L);
	zlog_debug("Opened lib");
	if (file) {
		status = luaL_loadfile(L, file);
		if (status) {
			zlog_debug("Failure to open %s %d", file, status);
			lua_close(L);
			return NULL;
		}
		lua_pcall(L, 0, LUA_MULTRET, 0);
	}

	zlog_debug("Setting global function");
	lua_pushcfunction(L, lua_zlog_debug);
	lua_setglobal(L, "zlog_debug");

	return L;
}

#endif
