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
	return !strcmp(d1, d2);
}

static void *encoder_alloc(void *arg)
{
	struct encoder *tmp = arg;

	struct encoder *e = XCALLOC(MTYPE_TMP, sizeof(struct encoder));
	e->typename = XSTRDUP(MTYPE_TMP, tmp->typename);

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
	/* Process arguments according to argspec in fs */
	/* ... */

	int ret = lua_pcall(fs->L, 0, 0, 0);

	/* Process stack result according to argspec in fs */
	/* ... */

	/* LUA_OK is 0, so we can just return lua_pcall's result directly */
	return ret;
}

void frrscript_register_type_encoder(const char *typename,
				     encoder_func encoder)
{
	struct encoder e = {
		.typename = (char *) typename,
		.encoder = NULL
	};

	if (hash_lookup(encoder_hash, &e)) {
		zlog_backtrace(LOG_ERR);
		assert(!"Type encoder double-registered.");
	}

	hash_get(encoder_hash, &e, encoder_alloc);
}


struct frrscript *frrscript_load(const char *name,
				 int (*load_cb)(struct frrscript *))
{
	struct frrscript *fs = XCALLOC(MTYPE_TMP, sizeof(struct frrscript));

	fs->name = XSTRDUP(MTYPE_TMP, name);
	fs->L = luaL_newstate();

	char fname[MAXPATHLEN];
	snprintf(fname, sizeof(fname), FRRSCRIPT_PATH "/%s.lua", fs->name);

	if (luaL_loadfile(fs->L, fname) != LUA_OK)
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
	XFREE(MTYPE_TMP, fs->name);
	XFREE(MTYPE_TMP, fs);
}

void frrscript_init()
{
	encoder_hash = hash_create(encoder_hash_key, encoder_hash_cmp, "Lua type encoders");
}
