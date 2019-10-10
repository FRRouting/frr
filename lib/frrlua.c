/*
 * This file defines the lua interface into
 * FRRouting.
 *
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This file is part of FreeRangeRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with FRR; see the file COPYING.  If not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <zebra.h>

#if defined(HAVE_LUA)
#include "prefix.h"
#include "frrlua.h"
#include "log.h"

static int lua_zlog_debug(lua_State *L)
{
	int debug_lua = 1;
	const char *string = lua_tostring(L, 1);

	if (debug_lua)
		zlog_debug("%s", string);

	return 0;
}

const char *get_string(lua_State *L, const char *key)
{
	const char *str;

	lua_pushstring(L, key);
	lua_gettable(L, -2);

	str = (const char *)lua_tostring(L, -1);
	lua_pop(L, 1);

	return str;
}

int get_integer(lua_State *L, const char *key)
{
	int result;

	lua_pushstring(L, key);
	lua_gettable(L, -2);

	result = lua_tointeger(L, -1);
	lua_pop(L, 1);

	return result;
}

static void *lua_alloc(void *ud, void *ptr, size_t osize,
		       size_t nsize)
{
	(void)ud;  (void)osize;  /* not used */
	if (nsize == 0) {
		free(ptr);
		return NULL;
	} else
		return realloc(ptr, nsize);
}

lua_State *lua_initialize(const char *file)
{
	int status;
	lua_State *L = lua_newstate(lua_alloc, NULL);

	zlog_debug("Newstate: %p", L);
	luaL_openlibs(L);
	zlog_debug("Opened lib");
	status = luaL_loadfile(L, file);
	if (status) {
		zlog_debug("Failure to open %s %d", file, status);
		lua_close(L);
		return NULL;
	}

	lua_pcall(L, 0, LUA_MULTRET, 0);
	zlog_debug("Setting global function");
	lua_pushcfunction(L, lua_zlog_debug);
	lua_setglobal(L, "zlog_debug");

	return L;
}

void lua_setup_prefix_table(lua_State *L, const struct prefix *prefix)
{
	char buffer[100];

	lua_newtable(L);
	lua_pushstring(L, prefix2str(prefix, buffer, 100));
	lua_setfield(L, -2, "route");
	lua_pushinteger(L, prefix->family);
	lua_setfield(L, -2, "family");
	lua_setglobal(L, "prefix");
}

enum lua_rm_status lua_run_rm_rule(lua_State *L, const char *rule)
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
#endif
