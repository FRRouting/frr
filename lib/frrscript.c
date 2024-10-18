// SPDX-License-Identifier: GPL-2.0-or-later
/* Scripting foo
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
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

/*
 * Script name hash utilities
 */

struct frrscript_names_head frrscript_names_hash;

void _lua_decode_noop(lua_State *L, ...) {}

void frrscript_names_config_write(struct vty *vty)
{
	struct frrscript_names_entry *lua_script_entry;

	frr_each (frrscript_names, &frrscript_names_hash, lua_script_entry)
		if (lua_script_entry->script_name[0] != '\0')
			vty_out(vty, "zebra on-rib-process script %s\n",
				lua_script_entry->script_name);
}

/*
 * Wrapper for frrscript_names_add
 * Use this to register hook calls when a daemon starts up
 */
int frrscript_names_add_function_name(const char *function_name)
{
	struct frrscript_names_entry *insert =
		XCALLOC(MTYPE_SCRIPT, sizeof(*insert));
	strlcpy(insert->function_name, function_name,
		sizeof(insert->function_name));

	if (frrscript_names_add(&frrscript_names_hash, insert)) {
		zlog_warn(
			"Failed to add hook call function name to script_names");
		return 1;
	}
	return 0;
}

void frrscript_names_destroy(void)
{
	struct frrscript_names_entry *ne;

	while ((ne = frrscript_names_pop(&frrscript_names_hash)))
		XFREE(MTYPE_SCRIPT, ne);
}

/*
 * Given a function_name, set its script_name. function_names and script_names
 * are one-to-one. Each set will wipe the previous script_name.
 * Return 0 if set was successful, else 1.
 *
 * script_name is the base name of the file, without .lua.
 */
int frrscript_names_set_script_name(const char *function_name,
				    const char *script_name)
{
	struct frrscript_names_entry lookup;

	strlcpy(lookup.function_name, function_name,
		sizeof(lookup.function_name));
	struct frrscript_names_entry *snhe =
		frrscript_names_find(&frrscript_names_hash, &lookup);
	if (!snhe)
		return 1;
	strlcpy(snhe->script_name, script_name, sizeof(snhe->script_name));
	return 0;
}

/*
 * Given a function_name, get its script_name.
 * Return NULL if function_name not found.
 *
 * script_name is the base name of the file, without .lua.
 */
char *frrscript_names_get_script_name(const char *function_name)
{
	struct frrscript_names_entry lookup;

	strlcpy(lookup.function_name, function_name,
		sizeof(lookup.function_name));
	struct frrscript_names_entry *snhe =
		frrscript_names_find(&frrscript_names_hash, &lookup);
	if (!snhe)
		return NULL;

	if (snhe->script_name[0] == '\0')
		return NULL;

	return snhe->script_name;
}

uint32_t frrscript_names_hash_key(const struct frrscript_names_entry *snhe)
{
	return string_hash_make(snhe->function_name);
}

int frrscript_names_hash_cmp(const struct frrscript_names_entry *snhe1,
			     const struct frrscript_names_entry *snhe2)
{
	return strncmp(snhe1->function_name, snhe2->function_name,
		       sizeof(snhe1->function_name));
}

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

static void codec_free(void *data)
{
	struct frrscript_codec *c = data;
	char *constworkaroundandihateit = (char *)c->typename;

	XFREE(MTYPE_SCRIPT, constworkaroundandihateit);
	XFREE(MTYPE_SCRIPT, c);
}

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

static void lua_function_free(void *data)
{
	struct lua_function_state *lfs = data;

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
	 * i.e. containing solely the returned table.
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

	(void)hash_get(codec_hash, &c, codec_alloc);
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

	/* Load basic built-in Lua functions, e.g. ipairs, string, etc. */
	luaL_openlibs(L);

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
		zlog_err("frrscript: failed loading script '%s': error: %s",
			 script_name, lua_tostring(L, -1));
		goto fail;
	}

	/* To check the Lua function, we get it from the global table */
	lua_getglobal(L, function_name);
	if (lua_isfunction(L, lua_gettop(L)) == 0) {
		zlog_err("frrscript: loaded script '%s' but %s not found",
			 script_name, function_name);
		goto fail;
	}
	/* Then pop the function (frrscript_call will push it when it needs it)
	 */
	lua_pop(L, 1);

	if (load_cb && (*load_cb)(fs) != 0) {
		zlog_err(
			"frrscript: '%s': %s: loaded but callback returned non-zero exit code",
			script_name, function_name);
		goto fail;
	}

	/* Add the Lua function state to frrscript */
	struct lua_function_state key = {.name = function_name, .L = L};

	(void)hash_get(fs->lua_function_hash, &key, lua_function_alloc);

	return 0;
fail:
	lua_close(L);
	return 1;
}

void frrscript_delete(struct frrscript *fs)
{
	hash_clean_and_free(&fs->lua_function_hash, lua_function_free);
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

void frrscript_fini(void)
{
	hash_clean_and_free(&codec_hash, codec_free);

	frrscript_names_destroy();
}
#endif /* HAVE_SCRIPTING */
