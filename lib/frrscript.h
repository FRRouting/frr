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

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include <lua.h>
#include "frrlua.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*encoder_func)(lua_State *, const void *);
typedef void *(*decoder_func)(lua_State *, int);

struct frrscript_codec {
	const char *typename;
	encoder_func encoder;
	decoder_func decoder;
};

struct frrscript {
	/* Script name */
	char *name;

	/* Lua state */
	struct lua_State *L;
};

struct frrscript_env {
	/* Value type */
	const char *typename;

	/* Binding name */
	const char *name;

	/* Value */
	const void *val;
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
 * Register a Lua codec for a type.
 *
 * tname
 *    Name of type; e.g., "peer", "ospf_interface", etc. Chosen at will.
 *
 * codec(s)
 *    Function pointer to codec struct. Encoder function should push a Lua
 *    table representing the passed argument - which will have the C type
 *    associated with the chosen 'tname' to the provided stack. The decoder
 *    function should pop a value from the top of the stack and return a heap
 *    chunk containing that value. Allocations should be made with MTYPE_TMP.
 *
 *    If using the plural function variant, pass a NULL-terminated array.
 *
 */
void frrscript_register_type_codec(struct frrscript_codec *codec);
void frrscript_register_type_codecs(struct frrscript_codec *codecs);

/*
 * Initialize scripting subsystem. Call this before anything else.
 *
 * scriptdir
 *    Directory in which to look for scripts
 */
void frrscript_init(const char *scriptdir);


/*
 * Call script.
 *
 * fs
 *    The script to call; this is obtained from frrscript_load().
 *
 * env
 *    The script's environment. Specify this as an array of frrscript_env.
 *
 * Returns:
 *    0 if the script ran successfully, nonzero otherwise.
 */
int frrscript_call(struct frrscript *fs, struct frrscript_env *env);


/*
 * Get result from finished script.
 *
 * fs
 *    The script. This script must have been run already.
 *
 * result
 *    The result to extract from the script.
 *    This reuses the frrscript_env type, but only the typename and name fields
 *    need to be set. The value is returned directly.
 *
 * Returns:
 *    The script result of the specified name and type, or NULL.
 */
void *frrscript_get_result(struct frrscript *fs,
			   const struct frrscript_env *result);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HAVE_SCRIPTING */

#endif /* __FRRSCRIPT_H__ */
