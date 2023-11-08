// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR string processing utilities.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#include "zebra.h"

#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#ifdef HAVE_LIBPCRE2_POSIX
#ifndef _FRR_PCRE2_POSIX
#define _FRR_PCRE2_POSIX
#include <pcre2posix.h>
#endif /* _FRR_PCRE2_POSIX */
#elif defined(HAVE_LIBPCREPOSIX)
#include <pcreposix.h>
#else
#include <regex.h>
#endif /* HAVE_LIBPCRE2_POSIX */

#include "frrstr.h"
#include "memory.h"
#include "vector.h"

void frrstr_split(const char *string, const char *delimiter, char ***result,
		  int *argc)
{
	if (!string)
		return;

	unsigned int sz = 4, idx = 0;
	char *copy, *copystart;
	*result = XCALLOC(MTYPE_TMP, sizeof(char *) * sz);
	copystart = copy = XSTRDUP(MTYPE_TMP, string);
	*argc = 0;

	const char *tok = NULL;

	while (copy) {
		tok = strsep(&copy, delimiter);
		(*result)[idx] = XSTRDUP(MTYPE_TMP, tok);
		if (++idx == sz)
			*result = XREALLOC(MTYPE_TMP, *result,
					   (sz *= 2) * sizeof(char *));
		(*argc)++;
	}

	XFREE(MTYPE_TMP, copystart);
}

vector frrstr_split_vec(const char *string, const char *delimiter)
{
	char **result;
	int argc;

	if (!string)
		return NULL;

	frrstr_split(string, delimiter, &result, &argc);

	vector v = array_to_vector((void **)result, argc);

	XFREE(MTYPE_TMP, result);

	return v;
}

char *frrstr_join(const char **parts, int argc, const char *join)
{
	int i;
	char *str;
	char *p;
	size_t len = 0;
	size_t joinlen = join ? strlen(join) : 0;

	if (!argc)
		return NULL;

	for (i = 0; i < argc; i++)
		len += strlen(parts[i]);
	len += argc * joinlen + 1;

	if (!len)
		return NULL;

	p = str = XMALLOC(MTYPE_TMP, len);

	for (i = 0; i < argc; i++) {
		size_t arglen = strlen(parts[i]);

		memcpy(p, parts[i], arglen);
		p += arglen;
		if (i + 1 != argc && join) {
			memcpy(p, join, joinlen);
			p += joinlen;
		}
	}

	*p = '\0';

	return str;
}

char *frrstr_join_vec(vector v, const char *join)
{
	char **argv;
	int argc;

	vector_to_array(v, (void ***)&argv, &argc);

	char *ret = frrstr_join((const char **)argv, argc, join);

	XFREE(MTYPE_TMP, argv);

	return ret;
}

void frrstr_filter_vec(vector v, regex_t *filter)
{
	regmatch_t ignored[1];

	for (unsigned int i = 0; i < vector_active(v); i++) {
		if (regexec(filter, vector_slot(v, i), 0, ignored, 0)) {
			XFREE(MTYPE_TMP, vector_slot(v, i));
			vector_unset(v, i);
		}
	}
}

void frrstr_strvec_free(vector v)
{
	unsigned int i;
	char *cp;

	if (!v)
		return;

	for (i = 0; i < vector_active(v); i++) {
		cp = vector_slot(v, i);
		XFREE(MTYPE_TMP, cp);
	}

	vector_free(v);
}

char *frrstr_replace(const char *str, const char *find, const char *replace)
{
	char *ch;
	char *nustr = XSTRDUP(MTYPE_TMP, str);

	size_t findlen = strlen(find);
	size_t repllen = strlen(replace);

	while ((ch = strstr(nustr, find))) {
		if (repllen > findlen) {
			size_t nusz = strlen(nustr) + repllen - findlen + 1;
			nustr = XREALLOC(MTYPE_TMP, nustr, nusz);
			ch = strstr(nustr, find);
		}

		size_t nustrlen = strlen(nustr);
		size_t taillen = (nustr + nustrlen) - (ch + findlen);

		memmove(ch + findlen + (repllen - findlen), ch + findlen,
			taillen + 1);
		memcpy(ch, replace, repllen);
	}

	return nustr;
}

bool frrstr_startswith(const char *str, const char *prefix)
{
	if (!str || !prefix)
		return false;

	size_t lenstr = strlen(str);
	size_t lenprefix = strlen(prefix);

	if (lenprefix > lenstr)
		return false;

	return strncmp(str, prefix, lenprefix) == 0;
}

bool frrstr_endswith(const char *str, const char *suffix)
{
	if (!str || !suffix)
		return false;

	size_t lenstr = strlen(str);
	size_t lensuffix = strlen(suffix);

	if (lensuffix > lenstr)
		return false;

	return strncmp(&str[lenstr - lensuffix], suffix, lensuffix) == 0;
}

int all_digit(const char *str)
{
	for (; *str != '\0'; str++)
		if (!isdigit((unsigned char)*str))
			return 0;
	return 1;
}


char *frrstr_hex(char *buff, size_t bufsiz, const uint8_t *str, size_t num)
{
	if (bufsiz == 0)
		return buff;

	char tmp[3];

	buff[0] = '\0';

	for (size_t i = 0; i < num; i++) {
		snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
		strlcat(buff, tmp, bufsiz);
	}

	return buff;
}

const char *frrstr_skip_over_char(const char *s, int skipc)
{
	int c, quote = 0;

	while ((c = *s++)) {
		if (c == '\\') {
			if (!*s++)
				return NULL;
			continue;
		}
		if (quote) {
			if (c == quote)
				quote = 0;
			continue;
		}
		if (c == skipc)
			return s;
		if (c == '"' || c == '\'')
			quote = c;
	}
	return NULL;
}
