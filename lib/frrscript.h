// SPDX-License-Identifier: GPL-2.0-or-later
/* Scripting foo
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
 */
#ifndef __FRRSCRIPT_H__
#define __FRRSCRIPT_H__

#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include <lua.h>
#include <nexthop.h>
#include <nexthop_group.h>
#include "frrlua.h"
#include "bgpd/bgp_script.h" // for peer and attr encoders/decoders

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct zebra_dplane_ctx;
extern void lua_pushzebra_dplane_ctx(lua_State *L,
				     const struct zebra_dplane_ctx *ctx);
extern void lua_decode_zebra_dplane_ctx(lua_State *L, int idx,
					struct zebra_dplane_ctx *ctx);

/*
 * Script name hash
 */
PREDECL_HASH(frrscript_names);

struct frrscript_names_entry {
	/* Name of a Lua hook call */
	char function_name[MAXPATHLEN];

	/* Lua script in which to look for it */
	char script_name[MAXPATHLEN];

	struct frrscript_names_item item;
};

extern struct frrscript_names_head frrscript_names_hash;

extern void frrscript_names_config_write(struct vty *vty);

int frrscript_names_hash_cmp(const struct frrscript_names_entry *snhe1,
			     const struct frrscript_names_entry *snhe2);
uint32_t frrscript_names_hash_key(const struct frrscript_names_entry *snhe);

DECLARE_HASH(frrscript_names, struct frrscript_names_entry, item,
	     frrscript_names_hash_cmp, frrscript_names_hash_key);

int frrscript_names_add_function_name(const char *function_name);
void frrscript_names_destroy(void);
int frrscript_names_set_script_name(const char *function_name,
				    const char *script_name);
char *frrscript_names_get_script_name(const char *function_name);

typedef void (*encoder_func)(lua_State *, const void *);
typedef void *(*decoder_func)(lua_State *, int);

struct frrscript_codec {
	const char *typename;
	encoder_func encoder;
	decoder_func decoder;
};

struct lua_function_state {
	const char *name;
	lua_State *L;
};

struct frrscript {
	/* Script name */
	char *name;

	/* Hash of Lua function name to Lua function state */
	struct hash *lua_function_hash;
};


/*
 * Hash related functions for lua_function_hash
 */

void *lua_function_alloc(void *arg);

unsigned int lua_function_hash_key(const void *data);

bool lua_function_hash_cmp(const void *d1, const void *d2);

struct frrscript_env {
	/* Value type */
	const char *typename;

	/* Binding name */
	const char *name;

	/* Value */
	const void *val;
};

/*
 * Create new struct frrscript for a Lua script.
 * This will hold the states for the Lua functions in this script.
 *
 * scriptname
 *     Name of the Lua script file, without the .lua
 */
struct frrscript *frrscript_new(const char *scriptname);

/*
 * Load a function into frrscript, run callback if any
 */
int frrscript_load(struct frrscript *fs, const char *function_name,
		   int (*load_cb)(struct frrscript *));

/*
 * Delete Lua function states and frrscript
 */
void frrscript_delete(struct frrscript *fs);

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
 * On shutdown clean up memory associated with the scripting subsystem
 */
void frrscript_fini(void);

/*
 * This macro is mapped to every (name, value) in frrscript_call,
 * so this in turn maps them onto their encoders
 */
#define ENCODE_ARGS(name, value) ENCODE_ARGS_WITH_STATE(lfs->L, (value))

/*
 * This macro is also mapped to every (name, value) in frrscript_call, but
 * not every value can be mapped to its decoder - only those that appear
 * in the returned table will. To find out if they appear in the returned
 * table, first pop the value and check if its nil. Only call the decoder
 * if non-nil.
 *
 * At the end, the only thing left on the stack should be the
 * returned table.
 */
#define DECODE_ARGS(name, value)                                               \
	do {                                                                   \
		lua_getfield(lfs->L, 1, (name));                               \
		if (lua_isnil(lfs->L, 2)) {                                    \
			lua_pop(lfs->L, 1);                                    \
		} else {                                                       \
			DECODE_ARGS_WITH_STATE(lfs->L, (value));               \
		}                                                              \
		assert(lua_gettop(lfs->L) == 1);                               \
	} while (0)

/*
 * Noop function. Used below where we need a noop decoder for any type.
 */
void _lua_decode_noop(lua_State *, ...);

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
int * : lua_pushintegerp,                                       \
long long : lua_pushinteger,                                    \
long long * : lua_pushlonglongp,                                \
struct prefix * : lua_pushprefix,                               \
struct interface * : lua_pushinterface,                         \
struct in_addr * : lua_pushinaddr,                              \
struct in6_addr * : lua_pushin6addr,                            \
union sockunion * : lua_pushsockunion,                          \
char * : lua_pushstring_wrapper,                                \
struct attr * : lua_pushattr,                                   \
struct peer * : lua_pushpeer,                                   \
const struct prefix * : lua_pushprefix,                         \
const struct ipaddr * : lua_pushipaddr,                         \
const struct ethaddr * : lua_pushethaddr,                       \
const struct nexthop_group * : lua_pushnexthop_group,           \
const struct nexthop * : lua_pushnexthop,                       \
struct zebra_dplane_ctx * : lua_pushzebra_dplane_ctx            \
)((L), (value))

#define DECODE_ARGS_WITH_STATE(L, value)                                       \
	_Generic((value), \
int * : lua_decode_integerp,                                    \
long long * : lua_decode_longlongp,                             \
struct prefix * : lua_decode_prefix,                            \
struct interface * : lua_decode_interface,                      \
struct in_addr * : lua_decode_inaddr,                           \
struct in6_addr * : lua_decode_in6addr,                         \
union sockunion * : lua_decode_sockunion,                       \
char * : lua_decode_stringp,                                    \
struct attr * : lua_decode_attr,                                \
default : _lua_decode_noop                                      \
)((L), -1, (value))

/*
 * Call Lua function state (abstraction for a single Lua function)
 *
 * lfs
 *    The Lua function to call; this should have been loaded in by
 *    frrscript_load(). nargs Number of arguments the function accepts
 *
 * Returns:
 *    0 if the script ran successfully, nonzero otherwise.
 */
int _frrscript_call_lua(struct lua_function_state *lfs, int nargs);

/*
 * Wrapper for calling Lua function state.
 *
 * The Lua function name (f) to run should have already been checked by
 * frrscript_load. So this wrapper will:
 * 1) Find the Lua function state, which contains the Lua state
 * 2) Clear the Lua state (there may be leftovers items from previous call)
 * 3) Push the Lua function (f)
 * 4) Map frrscript_call arguments onto their encoder and decoders, push those
 * 5) Call _frrscript_call_lua (Lua execution takes place)
 * 6) Write back to frrscript_call arguments using their decoders
 *
 * This wrapper can be called multiple times (after one frrscript_load).
 *
 * fs
 *    The struct frrscript in which the Lua fuction was loaded into
 * f
 *    Name of the Lua function.
 *
 * Returns:
 *    0 if the script ran successfully, nonzero otherwise.
 */
#define frrscript_call(fs, f, ...)                                                                                                                                 \
	({                                                                                                                                                         \
		struct lua_function_state lookup = {.name = (f)};                                                                                                  \
		struct lua_function_state *lfs;                                                                                                                    \
		lfs = hash_lookup((fs)->lua_function_hash, &lookup);                                                                                               \
		lfs == NULL ? ({                                                                                                                                   \
			zlog_err(                                                                                                                                  \
				"frrscript: '%s.lua': '%s': tried to call this function but it was not loaded",                                                    \
				(fs)->name, (f));                                                                                                                  \
			1;                                                                                                                                         \
		})                                                                                                                                                 \
			    : ({                                                                                                                                   \
				      lua_settop(lfs->L, 0);                                                                                                       \
				      lua_getglobal(lfs->L, f);                                                                                                    \
				      MAP_LISTS(ENCODE_ARGS, ##__VA_ARGS__);                                                                                       \
				      _frrscript_call_lua(                                                                                                         \
					      lfs, PP_NARG(__VA_ARGS__));                                                                                          \
			      }) != 0                                                                                                                              \
				      ? ({                                                                                                                         \
						zlog_err(                                                                                                          \
							"frrscript: '%s.lua': '%s': this function called but returned non-zero exit code. No variables modified.", \
							(fs)->name, (f));                                                                                          \
						1;                                                                                                                 \
					})                                                                                                                         \
				      : ({                                                                                                                         \
						MAP_LISTS(DECODE_ARGS,                                                                                             \
							  ##__VA_ARGS__);                                                                                          \
						0;                                                                                                                 \
					});                                                                                                                        \
	})

/*
 * Get result from finished function
 *
 * fs
 *    The script. This script must have been run already.
 * function_name
 *    Name of the Lua function.
 * name
 *    Name of the result.
 *    This will be used as a string key to retrieve from the table that the
 *    Lua function returns.
 *    The name here should *not* appear in frrscript_call.
 * lua_to
 *    Function pointer to a lua_to decoder function.
 *    This function should allocate and decode a value from the Lua state.
 *
 * Returns:
 *    A pointer to the decoded value from the Lua state, or NULL if no such
 *    value.
 */
void *frrscript_get_result(struct frrscript *fs, const char *function_name,
			   const char *name,
			   void *(*lua_to)(lua_State *L, int idx));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HAVE_SCRIPTING */

#endif /* __FRRSCRIPT_H__ */
