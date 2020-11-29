/* Scripting foo
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
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
#ifndef __FRRSCRIPT_H__
#define __FRRSCRIPT_H__

#include "frrlua.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FRRSCRIPT_PATH "/etc/frr/scripts"

typedef int (*encoder_func)(struct lua_State *, const void *);

struct frrscript {
	/* Script name */
	char *name;

	/* Lua state */
	struct lua_State *L;
};


/*
 * Create new FRR script.
 */
struct frrscript *frrscript_load(const char *name,
				 int (*load_cb)(struct frrscript *));

/*
 * Destroy FRR script.
 */
void frrscript_unload(struct frrscript *fs);

/*
 * Register a Lua encoder for a type.
 *
 * tname
 *    Name of type; e.g., "peer", "ospf_interface", etc. Chosen at will.
 *
 * encoder
 *    Function pointer to encoder function. Encoder function should push a Lua
 *    table representing the passed argument - which will have the C type
 *    associated with the chosen 'tname' to the provided stack.
 *
 */
void frrscript_register_type_encoder(const char *tname, encoder_func encoder);

/*
 * Initialize scripting subsystem. Call this before anything else.
 */
void frrscript_init(void);

/*
 * Forward decl for frrscript_lua_call
 */
int frrscript_lua_call(struct frrscript *fs, ...);

/*
 * Call FRR script.
 *
 * Call it like this:
 *
 *   frrscript_call(fs, FRRSCRIPT_ARGS("cool_prefix", "prefix", p),
 *                  FRRSCRIPT_RESULTS("result1", "result2"))
 */
#define frrscript_call(fs, ...) frrscript_lua_call((fs), __VA_ARGS__)

/*
 * Macro that defines the arguments to a script.
 *
 * For each argument you want to pass to a script, pass *three* arguments to
 * this function. The first should be name of the variable to bind the argument
 * to in the script's environment. The second should be the type, as registered
 * by frrscript_register_type_encoder(). The third should be the argument
 * itself.
 *
 * This macro itself should be used as the second argument to frrscript_call().
 */
#define FRRSCRIPT_ARGS(...) PP_NARG(__VA_ARGS__), ##__VA_ARGS__

/*
 * Macro that defines the results from a script.
 *
 * Similar to FRRSCRIPT_ARGS, except this defines the results from a script.
 *
 * The first argument should be the name to bind the first result to and will
 * be used after the script finishes to get that particular result value.
 *
 * This macro itself should be used as the third argument to frrscript_call().
 * It may not be omitted.
 */
#define FRRSCRIPT_RESULTS(...) PP_NARG(__VA_ARGS__), ##__VA_ARGS__

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FRRSCRIPT_H__ */
