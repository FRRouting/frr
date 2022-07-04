/*
 * frrscript encoders and decoders for data structures in Zebra
 * Copyright (C) 2021 Donald Lee
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

#ifndef _ZEBRA_SCRIPT_H
#define _ZEBRA_SCRIPT_H

#include "zebra.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_pbr.h"

#ifdef HAVE_SCRIPTING

#include "frrlua.h"

void zebra_script_init(void);

void zebra_script_destroy(void);

void lua_pushnh_grp(lua_State *L, const struct nh_grp *nh_grp);

void lua_pushzebra_dplane_ctx(lua_State *L, const struct zebra_dplane_ctx *ctx);

#endif /* HAVE_SCRIPTING */

#endif /* _ZEBRA_SCRIPT_H */
