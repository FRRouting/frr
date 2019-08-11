/*
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
#ifndef __FRRLUA_H__
#define __FRRLUA_H__

#if defined(HAVE_LUA)

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Status enum for Lua routemap processing results
 */
enum frrlua_rm_status {
	/*
	 * Script function run failure.  This will translate into a
	 * deny
	 */
	LUA_RM_FAILURE = 0,
	/*
	 * No Match was found for the route map function
	 */
	LUA_RM_NOMATCH,
	/*
	 * Match was found but no changes were made to the
	 * incoming data.
	 */
	LUA_RM_MATCH,
	/*
	 * Match was found and data was modified, so
	 * figure out what changed
	 */
	LUA_RM_MATCH_AND_CHANGE,
};

/*
 * Pushes a new table containing relevant fields from a prefix structure.
 *
 * Additionally sets the global variable "prefix" to point at this table.
 */
void frrlua_newtable_prefix(lua_State *L, const struct prefix *prefix);

/*
 * Pushes a new table containing relevant fields from an interface structure.
 */
void frrlua_newtable_interface(lua_State *L, const struct interface *ifp);

/*
 * Runs a routemap rule or something
 */
enum frrlua_rm_status frrlua_run_rm_rule(lua_State *L, const char *rule);

/*
 * Retrieve a string from table on the top of the stack.
 *
 * key
 *    Key of string value in table
 */
const char *frrlua_table_get_string(lua_State *L, const char *key);

/*
 * Retrieve an integer from table on the top of the stack.
 *
 * key
 *    Key of string value in table
 */
int frrlua_table_get_integer(lua_State *L, const char *key);

/*
 * Exports a new table containing bindings to FRR zlog functions into the
 * global namespace.
 *
 * From Lua, these functions may be accessed as:
 *
 * - log.debug()
 * - log.info()
 * - log.warn()
 * - log.error()
 *
 * They take a single string argument.
 */
void frrlua_export_logging(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_LUA */
#endif /* __FRRLUA_H__ */
