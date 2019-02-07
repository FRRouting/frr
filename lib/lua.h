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
#ifndef __LUA_H__
#define __LUA_H__

#if defined(HAVE_LUA)

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These functions are helper functions that
 * try to glom some of the lua_XXX functionality
 * into what we actually need, instead of having
 * to make multiple calls to set up what
 * we want
 */
enum lua_rm_status {
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
 * Open up the lua.scr file and parse
 * initial global values, if any.
 */
lua_State *lua_initialize(const char *file);

void lua_setup_prefix_table(lua_State *L, const struct prefix *prefix);

enum lua_rm_status lua_run_rm_rule(lua_State *L, const char *rule);

/*
 * Get particular string/integer information
 * from a table.  It is *assumed* that
 * the table has already been selected
 */
const char *get_string(lua_State *L, const char *key);
int get_integer(lua_State *L, const char *key);

#ifdef __cplusplus
}
#endif

#endif
#endif
