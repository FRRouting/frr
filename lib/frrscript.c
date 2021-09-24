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
#include <zebra.h>

#ifdef HAVE_SCRIPTING

#include <stdarg.h>
#include <lua.h>

#include "frrscript.h"
#include "frrlua.h"
#include "memory.h"
#include "hash.h"
#include "log.h"


DEFINE_MTYPE_STATIC(LIB, SCRIPT, "Scripting");

/* Codecs */

struct frrscript_codec frrscript_codecs_lib[] = {
	{.typename = "integer",
	 .encoder = (encoder_func)lua_pushintegerp,
	 .decoder = lua_tointegerp},
	{.typename = "string",
	 .encoder = (encoder_func)lua_pushstring_wrapper,
	 .decoder = lua_tostringp},
	{.typename = "prefix",
	 .encoder = (encoder_func)lua_pushprefix,
	 .decoder = lua_toprefix},
	{.typename = "interface",
	 .encoder = (encoder_func)lua_pushinterface,
	 .decoder = lua_tointerface},
	{.typename = "in_addr",
	 .encoder = (encoder_func)lua_pushinaddr,
	 .decoder = lua_toinaddr},
	{.typename = "in6_addr",
	 .encoder = (encoder_func)lua_pushin6addr,
	 .decoder = lua_toin6addr},
	{.typename = "sockunion",
	 .encoder = (encoder_func)lua_pushsockunion,
	 .decoder = lua_tosockunion},
	{.typename = "time_t",
	 .encoder = (encoder_func)lua_pushtimet,
	 .decoder = lua_totimet},
	{}};

/* Type codecs */

struct hash *codec_hash;
char scriptdir[MAXPATHLEN];

static unsigned int codec_hash_key(const void *data)
{
	const struct frrscript_codec *c = data;

	return string_hash_make(c->typename);
}

static bool codec_hash_cmp(const void *d1, const void *d2)
{
	const struct frrscript_codec *e1 = d1;
	const struct frrscript_codec *e2 = d2;

	return strmatch(e1->typename, e2->typename);
}

static void *codec_alloc(void *arg)
{
	struct frrscript_codec *tmp = arg;

	struct frrscript_codec *e =
		XCALLOC(MTYPE_SCRIPT, sizeof(struct frrscript_codec));
	e->typename = XSTRDUP(MTYPE_SCRIPT, tmp->typename);
	e->encoder = tmp->encoder;
	e->decoder = tmp->decoder;

	return e;
}

#if 0
static void codec_free(struct codec *c)
{
	XFREE(MTYPE_TMP, c->typename);
	XFREE(MTYPE_TMP, c);
}
#endif

/* Lua function hash utils */

unsigned int lua_function_hash_key(const void *data)
{
	const struct lua_function_state *lfs = data;

	return string_hash_make(lfs->name);
}

bool lua_function_hash_cmp(const void *d1, const void *d2)
{
	const struct lua_function_state *lfs1 = d1;
	const struct lua_function_state *lfs2 = d2;

	return strmatch(lfs1->name, lfs2->name);
}

void *lua_function_alloc(void *arg)
{
	struct lua_function_state *tmp = arg;

	struct lua_function_state *lfs =
		XCALLOC(MTYPE_SCRIPT, sizeof(struct lua_function_state));
	lfs->name = tmp->name;
	lfs->L = tmp->L;
	return lfs;
}

static void lua_function_free(struct hash_bucket *b, void *data)
{
	struct lua_function_state *lfs = (struct lua_function_state *)b->data;
	lua_close(lfs->L);
	XFREE(MTYPE_SCRIPT, lfs);
}

/* internal frrscript APIs */

int _frrscript_call_lua(struct lua_function_state *lfs, int nargs)
{

	int ret;
	ret = lua_pcall(lfs->L, nargs, 1, 0);

	switch (ret) {
	case LUA_OK:
		break;
	case LUA_ERRRUN:
		zlog_err("Lua hook call '%s' : runtime error: %s", lfs->name,
			 lua_tostring(lfs->L, -1));
		break;
	case LUA_ERRMEM:
		zlog_err("Lua hook call '%s' : memory error: %s", lfs->name,
			 lua_tostring(lfs->L, -1));
		break;
	case LUA_ERRERR:
		zlog_err("Lua hook call '%s' : error handler error: %s",
			 lfs->name, lua_tostring(lfs->L, -1));
		break;
	case LUA_ERRGCMM:
		zlog_err("Lua hook call '%s' : garbage collector error: %s",
			 lfs->name, lua_tostring(lfs->L, -1));
		break;
	default:
		zlog_err("Lua hook call '%s' : unknown error: %s", lfs->name,
			 lua_tostring(lfs->L, -1));
		break;
	}

	if (ret != LUA_OK) {
		lua_pop(lfs->L, 1);
		goto done;
	}

	if (lua_gettop(lfs->L) != 1) {
		zlog_err(
			"Lua hook call '%s': Lua function should return only 1 result",
			lfs->name);
		ret = 1;
		goto done;
	}

	if (lua_istable(lfs->L, 1) != 1) {
		zlog_err(
			"Lua hook call '%s': Lua function should return a Lua table",
			lfs->name);
		ret = 1;
	}

done:
	/* LUA_OK is 0, so we can just return lua_pcall's result directly */
	return ret;
}

void *frrscript_get_result(struct frrscript *fs, const char *function_name,
			   const char *name,
			   void *(*lua_to)(lua_State *L, int idx))
{
	void *p;
	struct lua_function_state *lfs;
	struct lua_function_state lookup = {.name = function_name};

	lfs = hash_lookup(fs->lua_function_hash, &lookup);

	if (lfs == NULL)
		return NULL;

	/* At this point, the Lua state should have only the returned table.
	 * We will then search the table for the key/value we're interested in.
	 * Then if the value is present (i.e. non-nil), call the lua_to*
	 * decoder.
	 */
	assert(lua_gettop(lfs->L) == 1);
	assert(lua_istable(lfs->L, -1) == 1);
	lua_getfield(lfs->L, -1, name);
	if (lua_isnil(lfs->L, -1)) {
		lua_pop(lfs->L, 1);
		zlog_warn(
			"frrscript: '%s.lua': '%s': tried to decode '%s' as result but failed",
			fs->name, function_name, name);
		return NULL;
	}
	p = lua_to(lfs->L, 2);

	/* At the end, the Lua state should be same as it was at the start
	 * i.e. containing soley the returned table.
	 */
	assert(lua_gettop(lfs->L) == 1);
	assert(lua_istable(lfs->L, -1) == 1);

	return p;
}

void frrscript_register_type_codec(struct frrscript_codec *codec)
{
	struct frrscript_codec c = *codec;

	if (hash_lookup(codec_hash, &c)) {
		zlog_backtrace(LOG_ERR);
		assert(!"Type codec double-registered.");
	}

	assert(hash_get(codec_hash, &c, codec_alloc));
}

void frrscript_register_type_codecs(struct frrscript_codec *codecs)
{
	for (int i = 0; codecs[i].typename != NULL; i++)
		frrscript_register_type_codec(&codecs[i]);
}

struct frrscript *frrscript_new(const char *name)
{
	struct frrscript *fs = XCALLOC(MTYPE_SCRIPT, sizeof(struct frrscript));

	fs->name = XSTRDUP(MTYPE_SCRIPT, name);
	fs->lua_function_hash =
		hash_create(lua_function_hash_key, lua_function_hash_cmp,
			    "Lua function state hash");
	return fs;
}

int frrscript_load(struct frrscript *fs, const char *function_name,
		   int (*load_cb)(struct frrscript *))
{

	/* Set up the Lua script */
	lua_State *L = luaL_newstate();

	frrlua_export_logging(L);

	char script_name[MAXPATHLEN];

	if (snprintf(script_name, sizeof(script_name), "%s/%s.lua", scriptdir,
		     fs->name)
	    >= (int)sizeof(script_name)) {
		zlog_err("frrscript: path to script %s/%s.lua is too long",
			 scriptdir, fs->name);
		goto fail;
	}

	if (luaL_dofile(L, script_name) != 0) {
		zlog_err("frrscript: failed loading script '%s.lua': error: %s",
			 script_name, lua_tostring(L, -1));
		goto fail;
	}

	/* To check the Lua function, we get it from the global table */
	lua_getglobal(L, function_name);
	if (lua_isfunction(L, lua_gettop(L)) == 0) {
		zlog_err("frrscript: loaded script '%s.lua' but %s not found",
			 script_name, function_name);
		goto fail;
	}
	/* Then pop the function (frrscript_call will push it when it needs it)
	 */
	lua_pop(L, 1);

	if (load_cb && (*load_cb)(fs) != 0) {
		zlog_err(
			"frrscript: '%s.lua': %s: loaded but callback returned non-zero exit code",
			script_name, function_name);
		goto fail;
	}

	/* Add the Lua function state to frrscript */
	struct lua_function_state key = {.name = function_name, .L = L};

	hash_get(fs->lua_function_hash, &key, lua_function_alloc);

	return 0;
fail:
	lua_close(L);
	return 1;
}

void frrscript_delete(struct frrscript *fs)
{
	hash_iterate(fs->lua_function_hash, lua_function_free, NULL);
	XFREE(MTYPE_SCRIPT, fs->name);
	XFREE(MTYPE_SCRIPT, fs);
}

void frrscript_init(const char *sd)
{
	codec_hash = hash_create(codec_hash_key, codec_hash_cmp,
				 "Lua type encoders");

	strlcpy(scriptdir, sd, sizeof(scriptdir));

	/* Register core library types */
	frrscript_register_type_codecs(frrscript_codecs_lib);
}

#endif /* HAVE_SCRIPTING */
