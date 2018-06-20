/*
 * FRR string processing utilities.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
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

#ifndef _FRRSTR_H_
#define _FRRSTR_H_

#include <sys/types.h>
#include <regex.h>
#include <stdbool.h>

#include "vector.h"

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
 * Prefix match for string.
 *
 * str
 *    string to check for prefix match
 *
 * prefix
 *    prefix to look for
 *
 * Returns:
 *   true str starts with prefix, false otherwise
 */
bool begins_with(const char *str, const char *prefix);

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

#endif /* _FRRSTR_H_ */
