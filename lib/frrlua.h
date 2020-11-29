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

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "prefix.h"
#include "frrscript.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pushes a new table containing relevant fields from a prefix structure.
 */
void lua_pushprefix(lua_State *L, const struct prefix *prefix);

/*
 * Pushes a new table containing relevant fields from an interface structure.
 */
void lua_pushinterface(lua_State *L, const struct interface *ifp);

/*
 * Pushes a new table containing both numeric and string representations of an
 * in_addr to the stack.
 */
void lua_pushinaddr(lua_State *L, const struct in_addr *addr);

/*
 * Pushes a new table containing both numeric and string representations of an
 * in6_addr to the stack.
 */
void lua_pushin6addr(lua_State *L, const struct in6_addr *addr);

/*
 * Pushes a time_t to the stack.
 */
void lua_pushtimet(lua_State *L, const time_t *time);

/*
 * Pushes a table representing a sockunion to the stack.
 */
void lua_pushsockunion(lua_State *L, const union sockunion *su);

/*
 * Push integer. This just wraps lua_pushinteger(), but it takes a pointer, so
 * as to be compatible with the encoder_func signature.
 */
void lua_pushintegerp(lua_State *L, const int *num);

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

/*
 * Dump Lua stack to a string.
 *
 * Return value must be freed with XFREE(MTYPE_TMP, ...);
 */
char *frrlua_stackdump(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_LUA */
#endif /* __FRRLUA_H__ */
