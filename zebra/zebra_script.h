// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * frrscript encoders and decoders for data structures in Zebra
 * Copyright (C) 2021 Donald Lee
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
