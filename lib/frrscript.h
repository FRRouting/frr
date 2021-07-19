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
#include "bgpd/bgp_script.h"

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

#define ENCODE_ARGS(name, value)                                               \
	do {                                                                   \
		ENCODE_ARGS_WITH_STATE(L, value);                              \
		lua_setglobal(L, name);                                        \
	} while (0)

#define DECODE_ARGS(name, value)                                               \
	do {                                                                   \
		lua_getglobal(L, name);                                        \
		DECODE_ARGS_WITH_STATE(L, value);                              \
	} while (0)

/*
 * Fully polymorphic noop function. Used below where we need a noop decoder
 * for any type.
 */
#define _lua_noop(v)                                                           \
	({                                                                     \
		void _(lua_State *L, int idx, typeof(v) _v)                    \
		{                                                              \
		}                                                              \
		_;                                                             \
	})

/*
 * Maps the type of value to its encoder/decoder.
 * Add new mappings here.
 *
 * L
 *    Lua state
 * scriptdir
 *    Directory in which to look for scripts
 */
#define ENCODE_ARGS_WITH_STATE(L, value)                                       \
	_Generic((value), \
int : lua_pushinteger,                                          \
int * : lua_pushintegerp,                                        \
long long : lua_pushinteger,                                    \
long long * : lua_pushlonglongp,                                \
struct prefix * : lua_pushprefix,                               \
struct interface * : lua_pushinterface,                         \
struct in_addr * : lua_pushinaddr,                              \
struct in6_addr * : lua_pushin6addr,                            \
union sockunion * : lua_pushsockunion,                          \
time_t * : lua_pushtimet,                                       \
char * : lua_pushstring_wrapper,                                \
struct attr * : lua_pushattr,                                   \
struct peer * : lua_pushpeer,                                   \
const struct prefix * : lua_pushprefix                          \
)(L, value)

#define DECODE_ARGS_WITH_STATE(L, value)                                       \
	_Generic((value), \
int * : lua_decode_integerp,                                    \
long long * : lua_decode_longlongp,                             \
struct prefix * : lua_decode_prefix,                            \
struct interface * : lua_decode_interface,                      \
struct in_addr * : lua_decode_inaddr,                           \
struct in6_addr * : lua_decode_in6addr,                         \
union sockunion * : lua_decode_sockunion,                       \
time_t * : lua_decode_timet,                                    \
char * : lua_decode_stringp,                                    \
struct attr * : lua_decode_attr,                                \
default : _lua_noop(value)                                      \
)(L, -1, value)

/*
 * Call script.
 *
 * fs
 *    The script to call; this is obtained from frrscript_load().
 *
 * Returns:
 *    0 if the script ran successfully, nonzero otherwise.
 */
int _frrscript_call(struct frrscript *fs);

/*
 * Wrapper for call script. Maps values passed in to their encoder
 * and decoder types.
 *
 * fs
 *    The script to call; this is obtained from frrscript_load().
 *
 * Returns:
 *    0 if the script ran successfully, nonzero otherwise.
 */
#define frrscript_call(fs, ...)                                                \
	({                                                                     \
		lua_State *L = fs->L;                                          \
		MAP_LISTS(ENCODE_ARGS, ##__VA_ARGS__);                         \
		int ret = _frrscript_call(fs);                                 \
		if (ret == 0) {                                                \
			MAP_LISTS(DECODE_ARGS, ##__VA_ARGS__);                 \
		}                                                              \
		ret;                                                           \
	})

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
