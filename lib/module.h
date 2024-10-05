// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_MODULE_H
#define _FRR_MODULE_H

#include <stdint.h>
#include <stdbool.h>

#include "compiler.h"
#include "xref.h"

#ifdef __cplusplus
extern "C" {
#endif

struct frrmod_runtime;

struct frrmod_info {
	/* single-line few-word title */
	const char *name;
	/* human-readable version number, should not contain spaces */
	const char *version;
	/* one-paragraph description */
	const char *description;

	int (*init)(void);
};

/* primary entry point structure to be present in loadable module under
 * "_frrmod_this_module" dlsym() name
 *
 * note space for future extensions is reserved below, so other modules
 * (e.g. memory management, hooks) can add fields
 *
 * const members/info are in frrmod_info.
 */
struct frrmod_runtime {
	struct frrmod_runtime *next;

	const struct frrmod_info *info;
	void *dl_handle;
	bool finished_loading;

	char *load_name;
	char *load_args;
};

/* space-reserving foo */
struct _frrmod_runtime_size {
	struct frrmod_runtime r;
	/* this will barf if frrmod_runtime exceeds 1024 bytes ... */
	uint8_t space[1024 - sizeof(struct frrmod_runtime)];
};
union _frrmod_runtime_u {
	struct frrmod_runtime r;
	struct _frrmod_runtime_size s;
};

extern union _frrmod_runtime_u _frrmod_this_module;
#define THIS_MODULE (&_frrmod_this_module.r)

#define FRR_COREMOD_SETUP(...)                                                 \
	static const struct frrmod_info _frrmod_info = {__VA_ARGS__};          \
	DSO_LOCAL union _frrmod_runtime_u _frrmod_this_module = {{             \
		NULL,                                                          \
		&_frrmod_info,                                                 \
	}};                                                                    \
	XREF_SETUP();                                                          \
	MACRO_REQUIRE_SEMICOLON() /* end */

#define FRR_MODULE_SETUP(...)                                                  \
	FRR_COREMOD_SETUP(__VA_ARGS__);                                        \
	DSO_SELF struct frrmod_runtime *frr_module = &_frrmod_this_module.r;   \
	MACRO_REQUIRE_SEMICOLON() /* end */

extern struct frrmod_runtime *frrmod_list;

extern void frrmod_init(struct frrmod_runtime *modinfo);
extern void frrmod_terminate(void);
extern struct frrmod_runtime *frrmod_load(const char *spec, const char *dir,
					  void (*pFerrlog)(const void *,
							   const char *),
					  const void *pErrlogCookie);
#if 0
/* not implemented yet */
extern void frrmod_unload(struct frrmod_runtime *module);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MODULE_H */
