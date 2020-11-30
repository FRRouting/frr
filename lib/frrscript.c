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
#include <stdarg.h>

#include "frrscript.h"
#include "memory.h"
#include "hash.h"
#include "log.h"

#include "frrlua.h"

/* Codecs */

struct frrscript_codec frrscript_codecs_lib[] = {
	{.typename = "integer",
	 .encoder = (encoder_func)lua_pushintegerp,
	 .decoder = lua_tointegerp},
	{.typename = "string",
	 .encoder = (encoder_func)lua_pushstring,
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
		XCALLOC(MTYPE_TMP, sizeof(struct frrscript_codec));
	e->typename = XSTRDUP(MTYPE_TMP, tmp->typename);
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

/* Generic script APIs */

int frrscript_call(struct frrscript *fs, struct frrscript_env *env)
{
	struct frrscript_codec c = {};
	const void *arg;
	const char *bindname;

	/* Encode script arguments */
	for (int i = 0; env && env[i].val != NULL; i++) {
		bindname = env[i].name;
		c.typename = env[i].typename;
		arg = env[i].val;

		zlog_debug("Script argument | Bind name: %s | Type: %s",
			   bindname, c.typename);

		struct frrscript_codec *codec = hash_lookup(codec_hash, &c);
		assert(codec
		       && "No encoder for type; rerun with debug logs to see more");
		codec->encoder(fs->L, arg);

		lua_setglobal(fs->L, bindname);
	}

	int ret = lua_pcall(fs->L, 0, 0, 0);

	switch (ret) {
	case LUA_OK:
		break;
	case LUA_ERRRUN:
		zlog_err("Script '%s' runtime error: %s", fs->name,
			 lua_tostring(fs->L, -1));
		break;
	case LUA_ERRMEM:
		zlog_err("Script '%s' memory error: %s", fs->name,
			 lua_tostring(fs->L, -1));
		break;
	case LUA_ERRERR:
		zlog_err("Script '%s' error handler error: %s", fs->name,
			 lua_tostring(fs->L, -1));
		break;
	case LUA_ERRGCMM:
		zlog_err("Script '%s' garbage collector error: %s", fs->name,
			 lua_tostring(fs->L, -1));
		break;
	default:
		zlog_err("Script '%s' unknown error: %s", fs->name,
			 lua_tostring(fs->L, -1));
		break;
	}

	if (ret != LUA_OK) {
		lua_pop(fs->L, 1);
		goto done;
	}

done:
	/* LUA_OK is 0, so we can just return lua_pcall's result directly */
	return ret;
}

void *frrscript_get_result(struct frrscript *fs,
			   const struct frrscript_env *result)
{
	void *r;
	struct frrscript_codec c = {.typename = result->typename};

	struct frrscript_codec *codec = hash_lookup(codec_hash, &c);

	lua_getglobal(fs->L, result->name);
	r = codec->decoder(fs->L, -1);
	lua_pop(fs->L, 1);

	return r;
}

void frrscript_register_type_codec(struct frrscript_codec *codec)
{
	struct frrscript_codec c = *codec;

	zlog_debug("Registering codec for '%s'", codec->typename);

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

struct frrscript *frrscript_load(const char *name,
				 int (*load_cb)(struct frrscript *))
{
	struct frrscript *fs = XCALLOC(MTYPE_TMP, sizeof(struct frrscript));

	fs->name = XSTRDUP(MTYPE_TMP, name);
	fs->L = luaL_newstate();
	frrlua_export_logging(fs->L);

	char fname[MAXPATHLEN];
	snprintf(fname, sizeof(fname), FRRSCRIPT_PATH "/%s.lua", fs->name);

	int ret = luaL_loadfile(fs->L, fname);

	switch (ret) {
	case LUA_OK:
		break;
	case LUA_ERRSYNTAX:
		zlog_err("Failed loading script '%s': syntax error: %s", fname,
			 lua_tostring(fs->L, -1));
		break;
	case LUA_ERRMEM:
		zlog_err("Failed loading script '%s': out-of-memory error: %s",
			 fname, lua_tostring(fs->L, -1));
		break;
	case LUA_ERRGCMM:
		zlog_err(
			"Failed loading script '%s': garbage collector error: %s",
			fname, lua_tostring(fs->L, -1));
		break;
	case LUA_ERRFILE:
		zlog_err("Failed loading script '%s': file read error: %s",
			 fname, lua_tostring(fs->L, -1));
		break;
	default:
		zlog_err("Failed loading script '%s': unknown error: %s", fname,
			 lua_tostring(fs->L, -1));
		break;
	}

	if (ret != LUA_OK)
		goto fail;

	if (load_cb && (*load_cb)(fs) != 0)
		goto fail;

	return fs;
fail:
	frrscript_unload(fs);
	return NULL;
}

void frrscript_unload(struct frrscript *fs)
{
	lua_close(fs->L);
	XFREE(MTYPE_TMP, fs->name);
	XFREE(MTYPE_TMP, fs);
}

void frrscript_init()
{
	codec_hash = hash_create(codec_hash_key, codec_hash_cmp,
				 "Lua type encoders");

	/* Register core library types */
	frrscript_register_type_codecs(frrscript_codecs_lib);
}
