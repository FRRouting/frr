/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef _FRR_MODULE_H
#define _FRR_MODULE_H

#include <stdint.h>
#include <stdbool.h>

#if !defined(__GNUC__)
#error module code needs GCC visibility extensions
#elif __GNUC__ < 4
#error module code needs GCC visibility extensions
#else
# define DSO_PUBLIC __attribute__ ((visibility ("default")))
# define DSO_SELF   __attribute__ ((visibility ("protected")))
# define DSO_LOCAL  __attribute__ ((visibility ("hidden")))
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
	DSO_LOCAL union _frrmod_runtime_u _frrmod_this_module = {              \
		.r.info = &_frrmod_info,                                       \
	};
#define FRR_MODULE_SETUP(...)                                                  \
	FRR_COREMOD_SETUP(__VA_ARGS__)                                         \
	DSO_SELF struct frrmod_runtime *frr_module = &_frrmod_this_module.r;

extern struct frrmod_runtime *frrmod_list;

extern void frrmod_init(struct frrmod_runtime *modinfo);
extern struct frrmod_runtime *frrmod_load(const char *spec, const char *dir,
					  char *err, size_t err_len);
#if 0
/* not implemented yet */
extern void frrmod_unload(struct frrmod_runtime *module);
#endif

#endif /* _FRR_MODULE_H */
