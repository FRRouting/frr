/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <dlfcn.h>

#include "module.h"
#include "memory.h"
#include "version.h"

DEFINE_MTYPE_STATIC(LIB, MODULE_LOADNAME, "Module loading name")
DEFINE_MTYPE_STATIC(LIB, MODULE_LOADARGS, "Module loading arguments")

static struct frrmod_info frrmod_default_info = {
	.name = "libfrr",
	.version = FRR_VERSION,
	.description = "libfrr core module",
};
union _frrmod_runtime_u frrmod_default = {
	.r =
		{
			.info = &frrmod_default_info,
			.finished_loading = 1,
		},
};

// if defined(HAVE_SYS_WEAK_ALIAS_ATTRIBUTE)
// union _frrmod_runtime_u _frrmod_this_module
//	__attribute__((weak, alias("frrmod_default")));
// elif defined(HAVE_SYS_WEAK_ALIAS_PRAGMA)
#pragma weak _frrmod_this_module = frrmod_default
// else
// error need weak symbol support
// endif

struct frrmod_runtime *frrmod_list = &frrmod_default.r;
static struct frrmod_runtime **frrmod_last = &frrmod_default.r.next;
static const char *execname = NULL;

void frrmod_init(struct frrmod_runtime *modinfo)
{
	modinfo->finished_loading = 1;
	*frrmod_last = modinfo;
	frrmod_last = &modinfo->next;

	execname = modinfo->info->name;
}

struct frrmod_runtime *frrmod_load(const char *spec, const char *dir, char *err,
				   size_t err_len)
{
	void *handle = NULL;
	char name[PATH_MAX], fullpath[PATH_MAX * 2], *args;
	struct frrmod_runtime *rtinfo, **rtinfop;
	const struct frrmod_info *info;

	snprintf(name, sizeof(name), "%s", spec);
	args = strchr(name, ':');
	if (args)
		*args++ = '\0';

	if (!strchr(name, '/')) {
		if (execname) {
			snprintf(fullpath, sizeof(fullpath), "%s/%s_%s.so", dir,
				 execname, name);
			handle = dlopen(fullpath, RTLD_NOW | RTLD_GLOBAL);
		}
		if (!handle) {
			snprintf(fullpath, sizeof(fullpath), "%s/%s.so", dir,
				 name);
			handle = dlopen(fullpath, RTLD_NOW | RTLD_GLOBAL);
		}
	}
	if (!handle) {
		snprintf(fullpath, sizeof(fullpath), "%s", name);
		handle = dlopen(fullpath, RTLD_NOW | RTLD_GLOBAL);
	}
	if (!handle) {
		if (err)
			snprintf(err, err_len,
				 "loading module \"%s\" failed: %s", name,
				 dlerror());
		return NULL;
	}

	rtinfop = dlsym(handle, "frr_module");
	if (!rtinfop) {
		dlclose(handle);
		if (err)
			snprintf(err, err_len,
				 "\"%s\" is not an FRR module: %s", name,
				 dlerror());
		return NULL;
	}
	rtinfo = *rtinfop;
	rtinfo->load_name = XSTRDUP(MTYPE_MODULE_LOADNAME, name);
	rtinfo->dl_handle = handle;
	if (args)
		rtinfo->load_args = XSTRDUP(MTYPE_MODULE_LOADARGS, args);
	info = rtinfo->info;

	if (rtinfo->finished_loading) {
		dlclose(handle);
		if (err)
			snprintf(err, err_len, "module \"%s\" already loaded",
				 name);
		goto out_fail;
	}

	if (info->init && info->init()) {
		dlclose(handle);
		if (err)
			snprintf(err, err_len,
				 "module \"%s\" initialisation failed", name);
		goto out_fail;
	}

	rtinfo->finished_loading = 1;

	*frrmod_last = rtinfo;
	frrmod_last = &rtinfo->next;
	return rtinfo;

out_fail:
	XFREE(MTYPE_MODULE_LOADARGS, rtinfo->load_args);
	XFREE(MTYPE_MODULE_LOADNAME, rtinfo->load_name);
	return NULL;
}

#if 0
void frrmod_unload(struct frrmod_runtime *module)
{
}
#endif
