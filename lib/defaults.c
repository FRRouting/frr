/*
 * FRR defaults management
 *
 * Copyright (C) 2018  David Lamparter for NetDEF, Inc.
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

#include "defaults.h"
#include "libfrr.h"
#include "version.h"

static char df_version[128] = FRR_VER_SHORT, df_profile[128] = DFLT_NAME;
static struct frr_default *dflt_first = NULL, **dflt_next = &dflt_first;

/* these are global for all FRR daemons.  they have to be, since we write an
 * integrated config with the same value for all daemons. */
const char *frr_defaults_profiles[] = {
	"traditional",
	"datacenter",
	NULL,
};

void frr_default_add(struct frr_default *dflt)
{
	dflt->next = NULL;
	*dflt_next = dflt;
	dflt_next = &dflt->next;
}

static bool frr_match_version(const char *name, const char *vspec,
			      const char *version)
{
	int cmp;
	static struct spec {
		const char *str;
		bool dir, eq;
	} *s, specs[] = {
		{"<=", -1, 1},
		{">=", 1, 1},
		{"==", 0, 1},
		{"<", -1, 0},
		{">", 1, 0},
		{"=", 0, 1},
		{NULL, 0, 0},
	};

	if (!vspec)
		/* NULL = all versions */
		return true;

	for (s = specs; s->str; s++)
		if (!strncmp(s->str, vspec, strlen(s->str)))
			break;
	if (!s->str) {
		zlog_err("invalid version specifier for %s: %s", name, vspec);
		/* invalid version spec, never matches */
		return false;
	}

	vspec += strlen(s->str);
	while (isspace(*vspec))
		vspec++;

	cmp = frr_version_cmp(version, vspec);
	if (cmp == s->dir || (s->eq && cmp == 0))
		return true;

	return false;
}

static void frr_default_apply_one(struct frr_default *dflt)
{
	struct frr_default_entry *entry = dflt->entries;
	struct frr_default_entry *dfltentry = NULL, *saveentry = NULL;

	for (; entry->match_version || entry->match_profile; entry++) {
		if (entry->match_profile
			&& strcmp(entry->match_profile, df_profile))
			continue;

		if (!dfltentry && frr_match_version(dflt->name,
				entry->match_version, df_version))
			dfltentry = entry;
		if (!saveentry && frr_match_version(dflt->name,
				entry->match_version, FRR_VER_SHORT))
			saveentry = entry;

		if (dfltentry && saveentry)
			break;
	}
	/* found default or arrived at last entry that has NULL,NULL spec */

	if (!dfltentry)
		dfltentry = entry;
	if (!saveentry)
		saveentry = entry;

	if (dflt->dflt_str)
		*dflt->dflt_str = dfltentry->val_str;
	if (dflt->dflt_long)
		*dflt->dflt_long = dfltentry->val_long;
	if (dflt->dflt_float)
		*dflt->dflt_float = dfltentry->val_float;
	if (dflt->save_str)
		*dflt->save_str = saveentry->val_str;
	if (dflt->save_long)
		*dflt->save_long = saveentry->val_long;
	if (dflt->save_float)
		*dflt->save_float = saveentry->val_float;
}

void frr_defaults_apply(void)
{
	struct frr_default *dflt;

	for (dflt = dflt_first; dflt; dflt = dflt->next)
		frr_default_apply_one(dflt);
}

bool frr_defaults_profile_valid(const char *profile)
{
	const char **p;

	for (p = frr_defaults_profiles; *p; p++)
		if (!strcmp(profile, *p))
			return true;
	return false;
}

const char *frr_defaults_version(void)
{
	return df_version;
}

const char *frr_defaults_profile(void)
{
	return df_profile;
}

void frr_defaults_version_set(const char *version)
{
	strlcpy(df_version, version, sizeof(df_version));
	frr_defaults_apply();
}

void frr_defaults_profile_set(const char *profile)
{
	strlcpy(df_profile, profile, sizeof(df_profile));
	frr_defaults_apply();
}
