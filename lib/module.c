// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
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
#include "lib/version.h"
#include "printfrr.h"

DEFINE_MTYPE_STATIC(LIB, MODULE_LOADNAME, "Module loading name");
DEFINE_MTYPE_STATIC(LIB, MODULE_LOADARGS, "Module loading arguments");
DEFINE_MTYPE_STATIC(LIB, MODULE_LOAD_ERR, "Module loading error");

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

XREF_SETUP();

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
	modinfo->finished_loading = true;
	*frrmod_last = modinfo;
	frrmod_last = &modinfo->next;

	execname = modinfo->info->name;
}

/*
 * If caller wants error strings, it should define non-NULL pFerrlog
 * which will be called with 0-terminated error messages. These
 * messages will NOT contain newlines, and the (*pFerrlog)() function
 * could be called multiple times for a single call to frrmod_load().
 *
 * The (*pFerrlog)() function may copy these strings if needed, but
 * should expect them to be freed by frrmod_load() before frrmod_load()
 * returns.
 *
 * frrmod_load() is coded such that (*pFerrlog)() will be called only
 * in the case where frrmod_load() returns an error.
 */
struct frrmod_runtime *frrmod_load(const char *spec, const char *dir,
				   void (*pFerrlog)(const void *, const char *),
				   const void *pErrlogCookie)
{
	void *handle = NULL;
	char name[PATH_MAX], fullpath[PATH_MAX * 2], *args;
	struct frrmod_runtime *rtinfo, **rtinfop;
	const struct frrmod_info *info;

#define FRRMOD_LOAD_N_ERRSTR 10
	char *aErr[FRRMOD_LOAD_N_ERRSTR];
	unsigned int iErr = 0;

	memset(aErr, 0, sizeof(aErr));

#define ERR_RECORD(...)                                                        \
	do {                                                                   \
		if (pFerrlog && (iErr < FRRMOD_LOAD_N_ERRSTR)) {               \
			aErr[iErr++] = asprintfrr(MTYPE_MODULE_LOAD_ERR,       \
						  __VA_ARGS__);                \
		}                                                              \
	} while (0)

#define ERR_REPORT                                                             \
	do {                                                                   \
		if (pFerrlog) {                                                \
			unsigned int i;                                        \
                                                                               \
			for (i = 0; i < iErr; ++i) {                           \
				(*pFerrlog)(pErrlogCookie, aErr[i]);           \
			}                                                      \
		}                                                              \
	} while (0)

#define ERR_FREE                                                               \
	do {                                                                   \
		unsigned int i;                                                \
                                                                               \
		for (i = 0; i < iErr; ++i) {                                   \
			XFREE(MTYPE_MODULE_LOAD_ERR, aErr[i]);                 \
			aErr[i] = 0;                                           \
		}                                                              \
		iErr = 0;                                                      \
	} while (0)

	snprintf(name, sizeof(name), "%s", spec);
	args = strchr(name, ':');
	if (args)
		*args++ = '\0';

	if (!strchr(name, '/')) {
		if (execname) {
			snprintf(fullpath, sizeof(fullpath), "%s/%s_%s.so", dir,
				 execname, name);
			handle = dlopen(fullpath, RTLD_NOW | RTLD_GLOBAL);
			if (!handle)
				ERR_RECORD("loader error: dlopen(%s): %s",
					   fullpath, dlerror());
		}
		if (!handle) {
			snprintf(fullpath, sizeof(fullpath), "%s/%s.so", dir,
				 name);
			handle = dlopen(fullpath, RTLD_NOW | RTLD_GLOBAL);
			if (!handle)
				ERR_RECORD("loader error: dlopen(%s): %s",
					   fullpath, dlerror());
		}
	}
	if (!handle) {
		snprintf(fullpath, sizeof(fullpath), "%s", name);
		handle = dlopen(fullpath, RTLD_NOW | RTLD_GLOBAL);
		if (!handle)
			ERR_RECORD("loader error: dlopen(%s): %s", fullpath,
				   dlerror());
	}
	if (!handle) {
		ERR_REPORT;
		ERR_FREE;
		return NULL;
	}

	/* previous dlopen() errors are no longer relevant */
	ERR_FREE;

	rtinfop = dlsym(handle, "frr_module");
	if (!rtinfop) {
		dlclose(handle);
		ERR_RECORD("\"%s\" is not an FRR module: %s", name, dlerror());
		ERR_REPORT;
		ERR_FREE;
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
		ERR_RECORD("module \"%s\" already loaded", name);
		goto out_fail;
	}

	if (info->init && info->init()) {
		dlclose(handle);
		ERR_RECORD("module \"%s\" initialisation failed", name);
		goto out_fail;
	}

	rtinfo->finished_loading = true;

	*frrmod_last = rtinfo;
	frrmod_last = &rtinfo->next;
	ERR_FREE;
	return rtinfo;

out_fail:
	XFREE(MTYPE_MODULE_LOADARGS, rtinfo->load_args);
	XFREE(MTYPE_MODULE_LOADNAME, rtinfo->load_name);
	ERR_REPORT;
	ERR_FREE;
	return NULL;
}

#if 0
void frrmod_unload(struct frrmod_runtime *module)
{
}
#endif

void frrmod_terminate(void)
{
	struct frrmod_runtime *rtinfo = frrmod_list;

	while (rtinfo) {
		XFREE(MTYPE_MODULE_LOADNAME, rtinfo->load_name);
		XFREE(MTYPE_MODULE_LOADARGS, rtinfo->load_args);

		rtinfo = rtinfo->next;
	}
}
