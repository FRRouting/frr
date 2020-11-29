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

/* Type encoders */

struct encoder {
	char *typename;
	encoder_func encoder;
};

struct hash *encoder_hash;

static unsigned int encoder_hash_key(const void *data)
{
	const struct encoder *e = data;

	return string_hash_make(e->typename);
}

static bool encoder_hash_cmp(const void *d1, const void *d2)
{
	const struct encoder *e1 = d1;
	const struct encoder *e2 = d2;

	return strmatch(e1->typename, e2->typename);
}

static void *encoder_alloc(void *arg)
{
	struct encoder *tmp = arg;

	struct encoder *e = XCALLOC(MTYPE_TMP, sizeof(struct encoder));
	e->typename = XSTRDUP(MTYPE_TMP, tmp->typename);
	e->encoder = tmp->encoder;

	return e;
}

#if 0
static void encoder_free(struct encoder *e)
{
	XFREE(MTYPE_TMP, e->typename);
	XFREE(MTYPE_TMP, e);
}
#endif

/* Generic script APIs */

int frrscript_lua_call(struct frrscript *fs, ...)
{
	va_list vl;
	va_start(vl, fs);

	int nargs = va_arg(vl, int);
	assert(nargs % 3 == 0);

	zlog_debug("%s: Script '%s' called with # args: %d", __func__, fs->name,
		   nargs);

	struct encoder e = {};
	void *arg;
	const char *bindname;

	/* Encode script arguments */
	for (int i = 0; i < nargs; i += 3) {
		bindname = va_arg(vl, const char *);
		e.typename = va_arg(vl, char *);
		arg = va_arg(vl, void *);

		zlog_debug("Script argument | Bind name: %s | Type: %s",
			   bindname, e.typename);

		struct encoder *enc = hash_lookup(encoder_hash, &e);
		assert(enc
		       && "No encoder for type; rerun with debug logs to see more");
		enc->encoder(fs->L, arg);

		lua_setglobal(fs->L, bindname);
	}

	int nresults = va_arg(vl, int);
	zlog_debug("Expected script results: %d", nresults);

	int ret = lua_pcall(fs->L, 0, nresults, 0);

	switch (ret) {
	case LUA_OK:
		break;
	case LUA_ERRRUN:
		zlog_err("Script '%s' runtime error: %s", fs->name, lua_tostring(fs->L, -1));
		break;
	case LUA_ERRMEM:
		zlog_err("Script '%s' memory error: %s", fs->name, lua_tostring(fs->L, -1));
		break;
	case LUA_ERRERR:
		zlog_err("Script '%s' error handler error: %s", fs->name, lua_tostring(fs->L, -1));
		break;
	case LUA_ERRGCMM:
		zlog_err("Script '%s' garbage collector error: %s", fs->name, lua_tostring(fs->L, -1));
		break;
	default:
		zlog_err("Script '%s' unknown error: %s", fs->name, lua_tostring(fs->L, -1));
		break;
	}

	if (ret != LUA_OK)
		lua_pop(fs->L, 1);

	/* After script returns, decode results */
	for (int i = 0; i < nresults; i++) {
		const char *resultname = va_arg(vl, const char *);
		fprintf(stderr, "result: %s\n", resultname);
	}

	/* LUA_OK is 0, so we can just return lua_pcall's result directly */
	return ret;
}

void frrscript_register_type_encoder(const char *typename, encoder_func encoder)
{
	struct encoder e = {.typename = (char *)typename, .encoder = encoder};

	if (hash_lookup(encoder_hash, &e)) {
		zlog_backtrace(LOG_ERR);
		assert(!"Type encoder double-registered.");
	}

	assert(hash_get(encoder_hash, &e, encoder_alloc));
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
	encoder_hash = hash_create(encoder_hash_key, encoder_hash_cmp,
				   "Lua type encoders");

	/* Register core library types */
	frrscript_register_type_encoder("integer", (encoder_func) lua_pushintegerp);
	frrscript_register_type_encoder("string", (encoder_func) lua_pushstring);
	frrscript_register_type_encoder("prefix", (encoder_func)lua_pushprefix);
	frrscript_register_type_encoder("interface",
					(encoder_func)lua_pushinterface);
	frrscript_register_type_encoder("sockunion", (encoder_func) lua_pushsockunion);
	frrscript_register_type_encoder("in_addr", (encoder_func) lua_pushinaddr);
	frrscript_register_type_encoder("in6_addr", (encoder_func) lua_pushin6addr);
	frrscript_register_type_encoder("time_t", (encoder_func) lua_pushtimet);
}
