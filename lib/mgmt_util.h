// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Utilities
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "debug.h"

#define MGMTD_MAX_NUM_DSNODES_PER_BATCH 128

extern struct debug mgmt_dbg_util;

#define MGMTD_UTIL_DBG(fmt, ...)                                          \
	DEBUGD(&mgmt_dbg_util, "UTIL: %s: " fmt, __func__,                \
	       ##__VA_ARGS__)
#define MGMTD_UTIL_ERR(fmt, ...)                                          \
	zlog_err("UTIL: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#define MGMTD_DBG_UTIL_CHECK()                                            \
	DEBUG_MODE_CHECK(&mgmt_dbg_util, DEBUG_MODE_ALL)

/*
 * Returns position of the previous separator ['/','[' or ']') in a given xpath
 * with respect to a specific position in the xpath.
 *
 * Args:
 * - base_xpath - The Xpath to look for a separator.
 * - start_index - The position before which to search for the separator.
 *
 * Returns: The position of the previous separator if foumd, else -1.
 */
static inline int mgmt_xpath_find_prev_separator(const char *base_xpath, int start_index)
{
	bool key_val = false;
	int last_sep = -1;

	while (start_index) {
		switch (base_xpath[start_index]) {
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

		MGMTD_UTIL_DBG("Indx: %d, Char: '%c', K: %d, Last-Sep: %d\n",
			       start_index, base_xpath[start_index], key_val, last_sep);
		start_index--;
	}

	return last_sep;
}

/*
 * Returns position of the next separator ['/','[' or ']') in a given xpath
 * with respect to a specific position in the xpath.
 *
 * Args:
 * - base_xpath: The Xpath to look for a separator.
 * - start_index: The position after which to search for the separator.
 *
 * Returns: The position of the previous separator if foumd, else -1.
 */
static inline int mgmt_xpath_find_next_separator(const char *base_xpath, int start_index)
{
	bool key_val = false;
	int last_sep = -1;

	while (1) {
		switch (base_xpath[start_index]) {
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

		MGMTD_UTIL_DBG("Indx: %d, Char: '%c', K: %d, Last-Sep: %d\n",
			       start_index, base_xpath[start_index], key_val, last_sep);
		start_index++;
	}

	return last_sep;
}

/*
 * Appends trailing wildcard '/' '*' to a given xpath.
 *
 * Args:
 * - xpath: The specific xpath to append to.
 * - xpath_len: Length of the xpath string.
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
 * Removes trailng wildcard '/' and '*' from a given xpath.
 *
 * Args:
 * - xpath: The specific xpath to remove from.
 * - xpath_len: Length of the xpath string.
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

/*
 * Returns the index of the specific character in a given xpath.
 *
 * Args:
 * - xpath: The specific xpath to search in.
 * - start: The position to start the search from.
 * - c: The specific character to look for.
 */
static inline int mgmt_xpath_find_character(char *xpath, int start, char c)
{
	int i = start;

	while (xpath[i] != '\0') {
		if (xpath[i] == c)
			return i;
		i++;
	}
	return -1;
}

/*
 * Evaluates the regular expression match in the given xpath.
 *
 * xpath_regexp
 *     YANG regular expression.
 *
 * xpath
 *     YANG xpath.
 *
 * get_match_xpath
 *     Get the matching xpath.
 *
 * xpath_match
 *     YANG xpath which is matched.
 *
 * xpath_match_len
 *     xpath matched length.
 *
 * full_match_only
 *     True if full match between regex and xpath needed.
 *
 * Returns
 *	The number of tokens that matched between the regex and the
 *	actual xpath.
 *
 * Examples of type of XPATH regexps that this function can
 * support are:
 * - /
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='*'][table-id='*']/
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='ipv4-*'][table-id='*']/
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='*'][table-id='254']/
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='*'][table-id='*']/route[prefix='*']/
 *    route-entry[protocol='*']/
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='*'][table-id='*']/route[prefix='192.168.*']/
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='*'][table-id='*']/route[prefix='192.168.1.1/32']/
 *    route-entry[protocol='*']/
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='*'][table-id='*']/route[prefix='*']/
 *    route-entry[protocol='static']/
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='*'][table-id='*']/route[prefix='192.168.*']/
 *    route-entry[protocol='*']/
 * - /frr-vrf:lib/vrf[name='default']/frr-zebra:zebra/ribs/
 *    rib[afi-safi-name='*'][table-id='*']/route[prefix='*']/
 *    route-entry[protocol='*']/distance
 */
extern int mgmt_xpath_eval_regexp_match(const char *xpath_regexp,
					const char *xpath,
					bool get_match_xpath,
					char **xpath_match,
					int *xpath_match_len,
					bool full_match_only);

/*
 * Returns the index of the first wildcard in a given xpath.
 *
 * xpath
 *     YANG xpath.
 *
 * key_end
 *     xpath end index.
 */
extern int mgmt_xpath_find_first_wildcard(const char *xpath, int *key_end);

/*
 * Resolve wildcard entry in a given xpath.
 *
 * xpath
 *     YANG xpath.
 *
 * start_indx
 *     xpath start index.
 *
 * get_child_fn
 *     child xpath resolve function.
 *
 * iter_fn
 *     xpath iterator function.
 *
 * ctxt
 *     iterator context.
 *
 * level
 *     recursive resolution level.
 */
extern int mgmt_xpath_resolve_wildcard(char *xpath, int start_indx,
				       void (*get_child_fn)(char *base_xpath,
							const char *child_xpath[],
						        void *child_ctxt[],
							int *num_child,
							void *ctxt, char* xpath_key),
				       int (*iter_fn)(const char *child_xpath,
						      void *child_ctxt,
						      void *ctxt),
				       void *ctxt, int level);

/*
 * Show mgmt debug utility.
 *
 * vty
 *    vty context.
 */
extern void mgmt_debug_util_show_debug(struct vty *vty);

/*
 * Initialize mgmt debug utility.
 */
extern void mgmt_util_vty_init(void);
