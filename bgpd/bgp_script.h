/* BGP scripting foo
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#ifndef __BGP_SCRIPT__
#define __BGP_SCRIPT__

#include <zebra.h>
#include "bgpd.h"

#ifdef HAVE_SCRIPTING

#include "frrlua.h"

/*
 * Initialize scripting stuff.
 */
void bgp_script_init(void);

void lua_pushpeer(lua_State *L, const struct peer *peer);

void lua_pushattr(lua_State *L, const struct attr *attr);

void lua_decode_attr(lua_State *L, int idx, struct attr *attr);

void *lua_toattr(lua_State *L, int idx);

#endif /* HAVE_SCRIPTING */

#endif /* __BGP_SCRIPT__ */
