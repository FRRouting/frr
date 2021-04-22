/*
 * FRR switchable defaults.
 * Copyright (c) 2017-2019  David Lamparter, for NetDEF, Inc.
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

#include <zebra.h>

#include "defaults.h"
#include "lib/version.h"

static char df_version[128] = FRR_VER_SHORT, df_profile[128] = DFLT_NAME;
static struct frr_default *dflt_first = NULL, **dflt_next = &dflt_first;

/* these are global for all FRR daemons.  they have to be, since we write an
 * integrated config with the same value for all daemons.
 */
const char *frr_defaults_profiles[] = {
	"traditional",
	"datacenter",
	NULL,
};

static int version_value(int ch)
{
	/* non-ASCII shouldn't happen */
	if (ch < 0 || ch >= 128)
		return 2;

	/* ~foo sorts older than nothing */
	if (ch == '~')
		return 0;
	if (ch == '\0')
		return 1;
	if (isalpha(ch))
		return 0x100 + tolower(ch);

	/* punctuation and digits (and everything else) */
	return 0x200 + ch;
}

int frr_version_cmp(const char *aa, const char *bb)
{
	const char *apos = aa, *bpos = bb;

	/* || is correct, we won't scan past the end of a string since that
	 * doesn't compare equal to anything else */
	while (apos[0] || bpos[0]) {
		if (isdigit((unsigned char)apos[0]) &&
		    isdigit((unsigned char)bpos[0])) {
			unsigned long av, bv;
			char *aend = NULL, *bend = NULL;

			av = strtoul(apos, &aend, 10);
			bv = strtoul(bpos, &bend, 10);
			if (av < bv)
				return -1;
			if (av > bv)
				return 1;

			apos = aend;
			bpos = bend;
			continue;
		}

		int a = version_value(*apos++);
		int b = version_value(*bpos++);

		if (a < b)
			return -1;
		if (a > b)
			return 1;
	}
	return 0;
}

static void frr_default_apply_one(struct frr_default *dflt, bool check);

void frr_default_add(struct frr_default *dflt)
{
	dflt->next = NULL;
	*dflt_next = dflt;
	dflt_next = &dflt->next;

	frr_default_apply_one(dflt, true);
}

static bool frr_match_version(const char *name, const char *vspec,
			      const char *version, bool check)
{
	int cmp;
	static const struct spec {
		const char *str;
		int dir, eq;
	} specs[] = {
		{"<=", -1, 1},
		{">=", 1, 1},
		{"==", 0, 1},
		{"<", -1, 0},
		{">", 1, 0},
		{"=", 0, 1},
		{NULL, 0, 0},
	};
	const struct spec *s;

	if (!vspec)
		/* NULL = all versions */
		return true;

	for (s = specs; s->str; s++)
		if (!strncmp(s->str, vspec, strlen(s->str)))
			break;
	if (!s->str) {
		if (check)
			fprintf(stderr, "invalid version specifier for %s: %s",
				name, vspec);
		/* invalid version spec, never matches */
		return false;
	}

	vspec += strlen(s->str);
	while (isspace((unsigned char)*vspec))
		vspec++;

	cmp = frr_version_cmp(version, vspec);
	if (cmp == s->dir || (s->eq && cmp == 0))
		return true;

	return false;
}

static void frr_default_apply_one(struct frr_default *dflt, bool check)
{
	struct frr_default_entry *entry = dflt->entries;
	struct frr_default_entry *dfltentry = NULL, *saveentry = NULL;

	for (; entry->match_version || entry->match_profile; entry++) {
		if (entry->match_profile
			&& strcmp(entry->match_profile, df_profile))
			continue;

		if (!dfltentry && frr_match_version(dflt->name,
				entry->match_version, df_version, check))
			dfltentry = entry;
		if (!saveentry && frr_match_version(dflt->name,
				entry->match_version, FRR_VER_SHORT, check))
			saveentry = entry;

		if (dfltentry && saveentry && !check)
			break;
	}
	/* found default or arrived at last entry that has NULL,NULL spec */

	if (!dfltentry)
		dfltentry = entry;
	if (!saveentry)
		saveentry = entry;

	if (dflt->dflt_bool)
		*dflt->dflt_bool = dfltentry->val_bool;
	if (dflt->dflt_str)
		*dflt->dflt_str = dfltentry->val_str;
	if (dflt->dflt_long)
		*dflt->dflt_long = dfltentry->val_long;
	if (dflt->dflt_ulong)
		*dflt->dflt_ulong = dfltentry->val_ulong;
	if (dflt->dflt_float)
		*dflt->dflt_float = dfltentry->val_float;
	if (dflt->save_bool)
		*dflt->save_bool = saveentry->val_bool;
	if (dflt->save_str)
		*dflt->save_str = saveentry->val_str;
	if (dflt->save_long)
		*dflt->save_long = saveentry->val_long;
	if (dflt->save_ulong)
		*dflt->save_ulong = saveentry->val_ulong;
	if (dflt->save_float)
		*dflt->save_float = saveentry->val_float;
}

void frr_defaults_apply(void)
{
	struct frr_default *dflt;

	for (dflt = dflt_first; dflt; dflt = dflt->next)
		frr_default_apply_one(dflt, false);
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
