// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR string processing utilities.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#ifndef _FRRSTR_H_
#define _FRRSTR_H_

#include <sys/types.h>
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
#include <stdbool.h>

#include "vector.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tokenizes a string, storing tokens in a vector. Whitespace is ignored.
 * Delimiter characters are not included.
 *
 * string
 *    The string to split
 *
 * delimiter
 *    Delimiter string, as used in strsep()
 *
 * Returns:
 *    The split string. Each token is allocated with MTYPE_TMP.
 */
void frrstr_split(const char *string, const char *delimiter, char ***result,
		  int *argc);
vector frrstr_split_vec(const char *string, const char *delimiter);

/*
 * Concatenate string array into a single string.
 *
 * argv
 *    array of string pointers to concatenate
 *
 * argc
 *    array length
 *
 * join
 *    string to insert between each part, or NULL for nothing
 *
 * Returns:
 *    the joined string, allocated with MTYPE_TMP
 */
char *frrstr_join(const char **parts, int argc, const char *join);
char *frrstr_join_vec(vector v, const char *join);

/*
 * Filter string vector.
 * Removes lines that do not contain a match for the provided regex.
 *
 * v
 *    The vector to filter.
 *
 * filter
 *    Regex to filter with.
 */
void frrstr_filter_vec(vector v, regex_t *filter);

/*
 * Free allocated string vector.
 * Assumes each item is allocated with MTYPE_TMP.
 *
 * v
 *    the vector to free
 */
void frrstr_strvec_free(vector v);

/*
 * Given a string, replaces all occurrences of a substring with a different
 * string. The result is a new string. The original string is not modified.
 *
 * If 'replace' is longer than 'find', this function performs N+1 allocations,
 * where N is the number of times 'find' occurs in 'str'. If 'replace' is equal
 * in length or shorter than 'find', only 1 allocation is performed.
 *
 * str
 *    String to perform replacement on.
 *
 * find
 *    Substring to replace.
 *
 * replace
 *    String to replace 'find' with.
 *
 * Returns:
 *    A new string, allocated with MTYPE_TMP, that is the result of performing
 *    the replacement on 'str'. This must be freed by the caller.
 */
char *frrstr_replace(const char *str, const char *find, const char *replace);

/*
 * Prefix match for string.
 *
 * str
 *    string to check for prefix match
 *
 * prefix
 *    prefix to look for
 *
 * Returns:
 *   true if str starts with prefix, false otherwise
 */
bool frrstr_startswith(const char *str, const char *prefix);

/*
 * Suffix match for string.
 *
 * str
 *    string to check for suffix match
 *
 * suffix
 *    suffix to look for
 *
 * Returns:
 *   true if str ends with suffix, false otherwise
 */
bool frrstr_endswith(const char *str, const char *suffix);

/*
 * Check the string only contains digit characters.
 *
 * str
 *    string to check for digits
 *
 * Returns:
 *    1 str only contains digit characters, 0 otherwise
 */
int all_digit(const char *str);

/*
 * Copy the hexadecimal representation of the string to a buffer.
 *
 * buff
 *    Buffer to copy result into with size of at least (2 * num) + 1.
 *
 * bufsiz
 *    Size of destination buffer.
 *
 * str
 *    String to represent as hexadecimal.
 *
 * num
 *    Number of characters to copy.
 *
 * Returns:
 *    Pointer to buffer containing resulting hexadecimal representation.
 */
char *frrstr_hex(char *buff, size_t bufsiz, const uint8_t *str, size_t num);

/*
 * Advance past a given char `skipc` in a string, while honoring quoting and
 * backslash escapes (i.e., ignore `skipc` which occur in quoted sections).
 */
const char *frrstr_skip_over_char(const char *s, int skipc);

/*
 * Advance back from end to a given char `toc` in a string, while honoring
 * quoting and backslash escapes. `toc` chars inside quote or escaped are
 * ignored.
 */
const char *frrstr_back_to_char(const char *s, int toc);

#ifdef __cplusplus
}
#endif

#endif /* _FRRSTR_H_ */
