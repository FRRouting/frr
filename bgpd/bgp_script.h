// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP scripting foo
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
 */
#ifndef __BGP_SCRIPT__
#define __BGP_SCRIPT__

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include <lua.h>

/*
 * Initialize scripting stuff.
 */
void bgp_script_init(void);

/*
 * Note that the common lib/frrscript.h has forward-refs to some of these
 * apis; if these change, please ensure those refs are updated too.
 */

/* Forward references */
struct peer;
struct attr;
struct bgp_path_info;

void lua_pushpeer(lua_State *L, const struct peer *peer);

void lua_pushattr(lua_State *L, const struct attr *attr);

void lua_decode_attr(lua_State *L, int idx, struct attr *attr);

void *lua_toattr(lua_State *L, int idx);

void lua_push_bgp_path_info(lua_State *L, const struct bgp_path_info *path);

void lua_decode_bgp_path_info(lua_State *L, int idx, struct bgp_path_info *path);

/*
 * Transfer script-supported fields from a working attr (src) onto dst.
 * Pointer fields that change are moved (src pointer cleared) so the
 * caller can discard src safely afterwards.
 */
void bgp_attr_script_apply(struct attr *dst, struct attr *src);

/*
 * Discard uninterned pointer values on a working attr copy that were
 * allocated during Lua decode and not applied onto the original.
 * orig is the attr the working copy was shallow-copied from.
 */
void bgp_attr_script_discard(struct attr *working, const struct attr *orig);

#endif /* HAVE_SCRIPTING */

#endif /* __BGP_SCRIPT__ */
