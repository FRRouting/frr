// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP scripting foo
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
 */
#ifndef __BGP_SCRIPT__
#define __BGP_SCRIPT__

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include "frrlua.h"

/*
 * Initialize scripting stuff.
 */
void bgp_script_init(void);

/* Forward references */
struct peer;
struct attr;

void lua_pushpeer(lua_State *L, const struct peer *peer);

void lua_pushattr(lua_State *L, const struct attr *attr);

void lua_decode_attr(lua_State *L, int idx, struct attr *attr);

void *lua_toattr(lua_State *L, int idx);

#endif /* HAVE_SCRIPTING */

#endif /* __BGP_SCRIPT__ */
