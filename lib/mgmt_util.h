/* FRR Management Daemon (MGMTD) program
 * Copyright (C) 2022  Vmware, Inc.
 *		       Pushpasis Sarkar
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
#include "mgmtd/mgmt.h"

static inline int mgmt_xpath_find_prev_separator(const char *base_xpath, int start_index)
{
	bool key_val = false;
	int last_sep = -1;

	while (start_index) {
		switch(base_xpath[start_index]) {
		case '[':
			if (key_val) {
				last_sep = -1;
				key_val = false;
			}
			break;
		case ']':
			if (last_sep >= 0)
				return last_sep;
			key_val = true;
			break;
		case '/':
			if (last_sep < 0)
				last_sep = start_index;
			else
				return last_sep;
			break;
		default:
			break;
		}

		// printf("Indx: %d, Char: '%c', K: %d, Last-Sep: %d\n",
		// 	start_index, base_xpath[start_index], key_val, last_sep);
		start_index--;
	}

	return last_sep;
}

static inline int mgmt_xpath_find_next_separator(const char *base_xpath, int start_index)
{
	bool key_val = false;
	int last_sep = -1;

	while (1) {
		switch(base_xpath[start_index]) {
		case '\0':
			return last_sep;
		case ']':
			if (key_val) {
				last_sep = -1;
				key_val = false;
			}
			break;
		case '[':
			if (last_sep >= 0)
				return last_sep;
			key_val = true;
			break;
		case '/':
			if (last_sep < 0)
				last_sep = start_index;
			else
				return last_sep;
			break;
		default:
			break;
		}

		// printf("Indx: %d, Char: '%c', K: %d, Last-Sep: %d\n",
		// 	start_index, base_xpath[start_index], key_val, last_sep);
		start_index++;
	}

	return last_sep;
}

/*
 * Appends trail wildcard '/' '*' to a given xpath.
 *
 * xpath
 *     YANG xpath.
 *
 * path_len
 *     xpath length.
 */
static inline void mgmt_xpath_append_trail_wildcard(char *xpath,
						    size_t *xpath_len)
{
	if (!xpath || !xpath_len)
		return;

	if (!*xpath_len)
		*xpath_len = strlen(xpath);

	if (*xpath_len > 2 && *xpath_len < MGMTD_MAX_XPATH_LEN - 2) {
		if (xpath[*xpath_len - 1] == '/') {
			xpath[*xpath_len] = '*';
			xpath[*xpath_len + 1] = 0;
			(*xpath_len)++;
		} else if (xpath[*xpath_len - 1] != '*') {
			xpath[*xpath_len] = '/';
			xpath[*xpath_len + 1] = '*';
			xpath[*xpath_len + 2] = 0;
			(*xpath_len) += 2;
		}
	}
}

/*
 * Removes trail wildcard '/' '*' from a given xpath.
 *
 * xpath
 *     YANG xpath.
 *
 * path_len
 *     xpath length.
 */
static inline void mgmt_xpath_remove_trail_wildcard(char *xpath,
						    size_t *xpath_len)
{
	if (!xpath || !xpath_len)
		return;

	if (!*xpath_len)
		*xpath_len = strlen(xpath);

	if (*xpath_len > 2 && xpath[*xpath_len - 2] == '/'
	    && xpath[*xpath_len - 1] == '*') {
		xpath[*xpath_len - 2] = 0;
		(*xpath_len) -= 2;
	}
}

static inline int mgmt_xpath_find_character(char *xpath, int s, char c)
{
	int i = s;

	while (xpath[i] != '\0') {
		if (xpath[i] == c)
			return i;
		i++;
	}
	return -1;
}

extern int mgmt_xpath_eval_regexp_match(const char *xpath_regexp,
					const char *xpath,
					bool get_match_xpath,
					char **xpath_match,
					int *xpath_match_len,
					bool full_match_only);

extern int mgmt_xpath_find_first_wildcard(const char *xpath, int *key_end);

extern int mgmt_xpath_resolve_wildcard(char *xpath, int start_indx,
				       int (*get_child_fn)(char *base_xpath,
							char *child_xpath[],
						        void *child_ctxt[],
							int *num_child,
							void *ctxt, char* xpath_key),
				       int (*iter_fn)(char *child_xpath,
						      void *child_ctxt,
						      void *ctxt),
				       void *ctxt, int level);
