/*
 * FRR switchable defaults.
 * Copyright (C) 2017-2018  David Lamparter for NetDEF, Inc.
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_DEFAULTS_H
#define _FRR_DEFAULTS_H

#include "config.h"

#ifdef HAVE_DATACENTER

#define DFLT_OSPF_LOG_ADJACENCY_CHANGES		1
#define DFLT_OSPF6_LOG_ADJACENCY_CHANGES	1

#else  /* !HAVE_DATACENTER */

#define DFLT_OSPF_LOG_ADJACENCY_CHANGES		0
#define DFLT_OSPF6_LOG_ADJACENCY_CHANGES	0

#endif /* !HAVE_DATACENTER */

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
	const char *val_str;
	long val_long;
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
	const char **dflt_str;
	long *dflt_long;
	float *dflt_float;

	/* variable to use when comparing for config save */
	const char **save_str;
	long *save_long;
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
	}

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
#define FRR_CFG_DEFAULT_LONG(varname, ...) \
	_FRR_CFG_DEFAULT(long, long, varname, ## __VA_ARGS__)
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

#endif /* _FRR_DEFAULTS_H */
