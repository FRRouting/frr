// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016-2019 Cumulus Networks, Inc.
 * Donald Sharp, Quentin Young
 */
#ifndef __FRRLUA_H__
#define __FRRLUA_H__

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "prefix.h"
#include "frrscript.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MTYPE(SCRIPT_RES);

/*
 * gcc-10 is complaining about the wrapper function
 * not being compatible with lua_pushstring returning
 * a char *.  Let's wrapper it here to make our life
 * easier
 */
static inline void lua_pushstring_wrapper(lua_State *L, const char *str)
{
	(void)lua_pushstring(L, str);
}

/*
 * Converts a prefix to a Lua value and pushes it on the stack.
 */
void lua_pushprefix(lua_State *L, const struct prefix *prefix);

void lua_decode_prefix(lua_State *L, int idx, struct prefix *prefix);

/*
 * Converts the Lua value at idx to a prefix.
 *
 * Returns:
 *    struct prefix allocated with MTYPE_TMP
 */
void *lua_toprefix(lua_State *L, int idx);

/*
 * Converts an interface to a Lua value and pushes it on the stack.
 */
void lua_pushinterface(lua_State *L, const struct interface *ifp);

void lua_decode_interface(lua_State *L, int idx, struct interface *ifp);

/*
 * Converts the Lua value at idx to an interface.
 *
 * Returns:
 *    struct interface allocated with MTYPE_TMP. This interface is not hooked
 *    to anything, nor is it inserted in the global interface tree.
 */
void *lua_tointerface(lua_State *L, int idx);

/*
 * Converts an in_addr to a Lua value and pushes it on the stack.
 */
void lua_pushinaddr(lua_State *L, const struct in_addr *addr);

void lua_decode_inaddr(lua_State *L, int idx, struct in_addr *addr);

/*
 * Converts the Lua value at idx to an in_addr.
 *
 * Returns:
 *    struct in_addr allocated with MTYPE_TMP.
 */
void *lua_toinaddr(lua_State *L, int idx);

/*
 * Converts an in6_addr to a Lua value and pushes it on the stack.
 */
void lua_pushin6addr(lua_State *L, const struct in6_addr *addr);

void lua_decode_in6addr(lua_State *L, int idx, struct in6_addr *addr);

void lua_pushipaddr(lua_State *L, const struct ipaddr *addr);

void lua_pushethaddr(lua_State *L, const struct ethaddr *addr);

/*
 * Converts the Lua value at idx to an in6_addr.
 *
 * Returns:
 *    struct in6_addr allocated with MTYPE_TMP.
 */
void *lua_toin6addr(lua_State *L, int idx);

/*
 * Converts a sockunion to a Lua value and pushes it on the stack.
 */
void lua_pushsockunion(lua_State *L, const union sockunion *su);

void lua_decode_sockunion(lua_State *L, int idx, union sockunion *su);

/*
 * Converts the Lua value at idx to a sockunion.
 *
 * Returns:
 *    sockunion allocated with MTYPE_TMP.
 */
void *lua_tosockunion(lua_State *L, int idx);

void lua_pushnexthop_group(lua_State *L, const struct nexthop_group *ng);

void lua_pushnexthop(lua_State *L, const struct nexthop *nexthop);

/*
 * Converts an int to a Lua value and pushes it on the stack.
 */
void lua_pushintegerp(lua_State *L, const int *num);

void lua_decode_integerp(lua_State *L, int idx, int *num);

/*
 * Converts the Lua value at idx to an int.
 *
 * Returns:
 *    int allocated with MTYPE_TMP.
 */
void *lua_tointegerp(lua_State *L, int idx);

/*
 * Converts a long long to a Lua value and pushes it on the stack.
 */
void lua_pushlonglongp(lua_State *L, const long long *num);

void lua_decode_longlongp(lua_State *L, int idx, long long *num);

/*
 * Converts the Lua value at idx to a long long.
 *
 * Returns:
 *    long long allocated with MTYPE_TMP.
 */
void *lua_tolonglongp(lua_State *L, int idx);

void lua_decode_stringp(lua_State *L, int idx, char *str);

/*
 * Pop string.
 *
 * Sets *string to a copy of the string at the top of the stack. The copy is
 * allocated with MTYPE_TMP and the caller is responsible for freeing it.
 */
void *lua_tostringp(lua_State *L, int idx);

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

#endif /* HAVE_SCRIPTING */

#endif /* __FRRLUA_H__ */
