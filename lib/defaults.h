/*
 * FRR switchable defaults.
 * Copyright (C) 2017-2019  David Lamparter for NetDEF, Inc.
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

#ifndef _FRR_DEFAULTS_H
#define _FRR_DEFAULTS_H

#include <stdbool.h>

#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/* frr_default wraps information about a default that has different
 * values depending on FRR version or default-set
 *
 * frr_default_entry describes one match rule and the resulting value;
 * entries are evaluated in order and the first matching is used.
 *
 * If both match_version and match_profile are specified, they must both
 * match.  A NULL value matches everything.
 */
struct frr_default_entry {
	/* syntax: "(<|<=|==|>=|>) [whitespace] version", e.g.
	 *   ">= 6.1-dev" "<6.0"
	 */
	const char *match_version;
	/* exact profile string to compare against */
	const char *match_profile;

	/* value to use */
	bool val_bool;
	const char *val_str;
	long val_long;
	unsigned long val_ulong;
	float val_float;
};

/* one struct frr_default exists for each malleable default value */
struct frr_default {
	struct frr_default *next;

	/* for UI/debug use */
	const char *name;

	/* the following two sets of variables differ because the written
	 * config always targets the *current* FRR version
	 *
	 * e.g. if you load a config that has "frr version 5.0" on 6.0
	 *   *dflt_long => set to the default value in 5.0
	 *   *save_long => set to the default value in 6.0
	 * config save will write "frr version 6.0" with 6.0 defaults
	 */

	/* variable holding the default value for reading/use */
	bool *dflt_bool;
	const char **dflt_str;
	long *dflt_long;
	unsigned long *dflt_ulong;
	float *dflt_float;

	/* variable to use when comparing for config save */
	bool *save_bool;
	const char **save_str;
	long *save_long;
	unsigned long *save_ulong;
	float *save_float;

	struct frr_default_entry entries[];
};

#define _FRR_CFG_DEFAULT(type, typname, varname, ...) \
	static type DFLT_##varname;                                            \
	static type SAVE_##varname;                                            \
	static struct frr_default _dflt_##varname = {                          \
		.name = #varname,                                              \
		.dflt_##typname = &DFLT_##varname,                             \
		.save_##typname = &SAVE_##varname,                             \
		.entries = { __VA_ARGS__ },                                    \
	};                                                                     \
	static void _dfltinit_##varname(void)                                  \
		__attribute__((_CONSTRUCTOR(1000)));                           \
	static void _dfltinit_##varname(void)                                  \
	{                                                                      \
		frr_default_add(&_dflt_##varname);                             \
	}                                                                      \
	MACRO_REQUIRE_SEMICOLON() /* end */

/* use:
 *   FRR_CFG_DEFAULT_LONG(SHARP_BLUNTNESS,
 *	{ .val_long = 2, .match_version = ">= 10.0" },
 *	{ .val_long = 1, .match_profile = "datacenter" },
 *	{ .val_long = 0 },
 *   )
 *
 * This will create DFLT_SHARP_BLUNTNESS and SAVE_SHARP_BLUNTNESS variables.
 *
 * Note: preprocessor defines cannot be used as variable names because they
 * will be expanded and blow up with a compile error.  Use an enum or add an
 * extra _ at the beginning (e.g. _SHARP_BLUNTNESS => DFLT__SHARP_BLUNTNESS)
 */
#define FRR_CFG_DEFAULT_BOOL(varname, ...) \
	_FRR_CFG_DEFAULT(bool, bool, varname, ## __VA_ARGS__)
#define FRR_CFG_DEFAULT_LONG(varname, ...) \
	_FRR_CFG_DEFAULT(long, long, varname, ## __VA_ARGS__)
#define FRR_CFG_DEFAULT_ULONG(varname, ...) \
	_FRR_CFG_DEFAULT(unsigned long, ulong, varname, ## __VA_ARGS__)
#define FRR_CFG_DEFAULT_FLOAT(varname, ...) \
	_FRR_CFG_DEFAULT(float, float, varname, ## __VA_ARGS__)
#define FRR_CFG_DEFAULT_STR(varname, ...) \
	_FRR_CFG_DEFAULT(const char *, str, varname, ## __VA_ARGS__)


/* daemons don't need to call any of these, libfrr handles that */
extern void frr_default_add(struct frr_default *dflt);
extern void frr_defaults_version_set(const char *version);
extern void frr_defaults_profile_set(const char *profile);
extern const char *frr_defaults_version(void);
extern const char *frr_defaults_profile(void);
extern void frr_defaults_apply(void);

extern const char *frr_defaults_profiles[];
extern bool frr_defaults_profile_valid(const char *profile);

/* like strcmp(), but with version ordering */
extern int frr_version_cmp(const char *aa, const char *bb);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_DEFAULTS_H */
