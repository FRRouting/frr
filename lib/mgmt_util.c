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
#include "mgmt_util.h"

int mgmt_xpath_eval_regexp_match(const char *xpath_regexp,
				 const char *xpath,
				 bool get_match_xpath,
				 char **xpath_match,
				 int *xpath_match_len,
				 bool full_match_only)
{
	int match_len = 0, re_indx = 0, xp_indx = 0;
	int rexp_len, xpath_len;
	bool match = true, re_wild = false, xp_wild = false;
	bool delim = false, enter_wild_match = false;
	char wild_delim = 0;
	char *xp_next = NULL;

	rexp_len = strlen(xpath_regexp);
	xpath_len = strlen(xpath);
	zlog_debug("RE: %s / %d, XP: %s / %d", xpath_regexp, rexp_len, xpath, xpath_len);

	/*
	 * Remove the trailing wildcard from the regexp and Xpath.
	 */
	if (rexp_len && xpath_regexp[rexp_len-1] == '*')
		rexp_len--;
	if (xpath_len && xpath[xpath_len-1] == '*')
		xpath_len--;

	if (!rexp_len || !xpath_len)
		return 0;

	if (get_match_xpath) {
		/*
		 * Allocate a new Xpath if not provided.
		 */
		if (!*xpath_match)
			*xpath_match = calloc(1, MGMTD_MAX_XPATH_LEN);
		xp_next = *xpath_match;
		*xp_next = '\0';
		if (xpath_match_len)
			*xpath_match_len = 0;
	}

	for (re_indx = 0, xp_indx = 0;
	     match && re_indx < rexp_len && xp_indx < xpath_len;) {
		match = (xpath_regexp[re_indx] == xpath[xp_indx]);

		/*
		 * Check if we need to enter wildcard matching.
		 */
		if (!enter_wild_match && !match &&
			(xpath_regexp[re_indx] == '*'
			 || xpath[xp_indx] == '*')) {
			/*
			 * Found wildcard
			 */
			enter_wild_match =
				(xpath_regexp[re_indx-1] == '/'
				 || xpath_regexp[re_indx-1] == '\''
				 || xpath[xp_indx-1] == '/'
				 || xpath[xp_indx-1] == '\'');
			if (enter_wild_match) {
				if (xpath_regexp[re_indx] == '*') {
					/*
					 * Begin RE wildcard match.
					 */
					re_wild = true;
					wild_delim = xpath_regexp[re_indx-1];
				} else if (xpath[xp_indx] == '*') {
					/*
					 * Begin XP wildcard match.
					 */
					xp_wild = true;
					wild_delim = xpath[xp_indx-1];
				}
			}
		}

		/*
		 * Check if we need to exit wildcard matching.
		 */
		if (enter_wild_match) {
			if (re_wild && xpath[xp_indx] == wild_delim) {
				/*
				 * End RE wildcard matching.
				 */
				re_wild = false;
				if (re_indx < rexp_len-1)
					re_indx++;
				enter_wild_match = false;
			} else if (xp_wild
				   && xpath_regexp[re_indx] == wild_delim) {
				/*
				 * End XP wildcard matching.
				 */
				xp_wild = false;
				if (xp_indx < xpath_len-1)
					xp_indx++;
				enter_wild_match = false;
			}
		}

		match = (xp_wild || re_wild
			 || xpath_regexp[re_indx] == xpath[xp_indx]);

		/*
		 * Check if we found a delimiter in both the Xpaths
		 */
		if ((xpath_regexp[re_indx] == '/'
			&& xpath[xp_indx] == '/')
			|| (xpath_regexp[re_indx] == ']'
				&& xpath[xp_indx] == ']')
			|| (xpath_regexp[re_indx] == '['
				&& xpath[xp_indx] == '[')) {
			/*
			 * Increment the match count if we have a
			 * new delimiter.
			 */
			if (match && !delim)
				match_len++;
			delim = true;
		} else {
			delim = false;
		}

		if (get_match_xpath) {
			/*
			 * Copy the next character for the xpath match
			 * from the appropriate Xpath.
			 */
			if (xp_wild)
				*xp_next++ = xpath_regexp[re_indx];
			else
				*xp_next++ = xpath[xp_indx];

			if (xpath_match_len)
				(*xpath_match_len)++;
		}

		// zlog_debug("RE %c [indx: %d/%d, w: %d] XP %c [indx: %d/%d, w: %d] XM:%c W: %d Match: %d Len: %d",
		// 	xpath_regexp[re_indx], re_indx, rexp_len, re_wild, xpath[xp_indx],
		// 	xp_indx, xpath_len, xp_wild, *(xp_next-1), enter_wild_match, match, match_len);

		/*
		 * Proceed to the next character in the RE/XP string as
		 * necessary.
		 */
		if (!re_wild)
			re_indx++;
		if (!xp_wild)
			xp_indx++;
	}

	/*
	 * If we finished matching and the last token was a full match
	 * increment the match count appropriately.
	 */
	if (match && !delim)
		match_len++;

	if (get_match_xpath) {
		/*
		* Copy rest of the XPath length from the bigger XPath.
		*/
		if (match && !full_match_only && (rexp_len - re_indx) > (xpath_len - xp_indx)) {
			for (; re_indx < rexp_len; re_indx++) {
				*xp_next++ = xpath_regexp[re_indx];
				if (xpath_match_len)
					(*xpath_match_len)++;
			}
		}

		if ((xpath_len - xp_indx) > (rexp_len - re_indx)) {
			for (; xp_indx < xpath_len; xp_indx++) {
				*xp_next++ = xpath[xp_indx];
				if (xpath_match_len)
					(*xpath_match_len)++;
			}
		}

		*xp_next++ = '\0';
	}

	return (!full_match_only || match ? match_len : 0);
}

int mgmt_xpath_find_first_wildcard(const char *xpath, int *key_end)
{
	bool key_val = false, wc_found = false;
	int indx, last_sep = -1, key_start = -1;
	
	if (key_end)
		*key_end = -1;

	for (indx = 0; ; indx++) {
		switch(xpath[indx]) {
		case '\0':
			/*
			 * End of the xpath string. Return the wildcard keyset
			 * if we found one.
			 */
			if (wc_found && key_end)
				*key_end = indx;
			return (wc_found ? key_start : -1);
		case ']':
			if (key_val) {
				last_sep = -1;
				key_val = false;
			}
			break;
		case '[':
			/*
			 * This could be the start of the wildcard keyset we
			 * are looking for.
			 */
			if (last_sep >= 0)
				key_start = last_sep + 1;
			key_val = true;
			break;
		case '*':
			if (key_val)
				wc_found = true;
			break;
		case '/':
			if (!key_val) {
				/* First separator found */
				last_sep = indx;

				if (wc_found) {
					/* Found end of the wildcard keyset */
					if (key_end)
						*key_end = indx;
					return key_start;
				}
			};
			break;
		default:
			break;
		}

		// zlog_debug("Indx: %d, Char: '%c', K: %d, WC: %d, Last-Sep: %d, KS: %d, KE:%d ",
		// 	indx, xpath[indx], key_val, wc_found, last_sep, key_start, key_end ? *key_end : -1);
	}

	return -1;
}

int mgmt_xpath_resolve_wildcard(char *xpath, int start_indx,
				int (*get_child_fn)(char *base_xpath,
						     char *child_xpath[],
						     void *child_ctxt[],
						     int *num_child,
						     void *ctxt, char* xpath_key),
				int (*iter_fn)(char *child_xpath,
						void *child_ctxt,
						void *ctxt),
				void *ctxt, int level)
{
	int wc_key_start, wc_key_end, indx, indx1, match, max_match, xp_match_len, num_dn_match;
	char orig;
	char xpath_key[MGMTD_MAX_XPATH_LEN];
	char *dnode_matched[MGMTD_MAX_NUM_DBNODES_PER_BATCH] = { 0 };
	void *dnode_ctxt[MGMTD_MAX_NUM_DBNODES_PER_BATCH] = { 0 };
	char *xp_matched[MGMTD_MAX_NUM_DBNODES_PER_BATCH] = { 0 };
	char *chld_xpath[MGMTD_MAX_NUM_DBNODES_PER_BATCH] = { 0 };
	void *chld_ctxt[MGMTD_MAX_NUM_DBNODES_PER_BATCH] = { 0 };
	int num_child, ret;

	wc_key_start = mgmt_xpath_find_first_wildcard(&xpath[start_indx], &wc_key_end);

	zlog_debug("%s: [%d] - SI: %d, KS:%d, KE:%d, Xpath: %s",
		   __func__, level, start_indx, wc_key_start, wc_key_end, xpath);

	if (wc_key_start < 0) {
		ret = 0;
		if (iter_fn) {
			zlog_debug("start of one db_iter ");
			ret = (*iter_fn)(xpath, NULL, ctxt);
		}
		zlog_debug("End of one xpath ");
		return ret;
	}

	strncpy(xpath_key, xpath, sizeof(xpath_key));
	if (wc_key_end >= 0) {
		xpath_key[start_indx + wc_key_end] = '\0';
		zlog_debug("%s: [%d] -- Truncated Xpath: %s",
			   __func__, level, xpath_key);
	}

	/* Get the exact set of children under base xpath. */
	if (wc_key_start >= 0) {
		orig = xpath[start_indx + wc_key_start - 1];
		xpath[start_indx + wc_key_start - 1] = '\0';
	}
	num_child = array_size(chld_xpath);
	ret = (*get_child_fn)(xpath, chld_xpath, chld_ctxt, &num_child, ctxt, xpath_key);
	if (ret) {
		zlog_debug("%s Value of get child function %d", __func__, ret);
		return ret;
	}
	if (wc_key_start >= 0)
		xpath[start_indx + wc_key_start - 1] = orig;

	/* Find the child nodes that match the wildcard key combination */
	num_dn_match = 0;
	max_match = 0;
	for (indx = 0; indx < num_child; indx++) {
		if (!xp_matched[num_dn_match])
			xp_matched[num_dn_match] = calloc(1, MGMTD_MAX_XPATH_LEN);
		match = mgmt_xpath_eval_regexp_match(xpath_key, chld_xpath[indx],
						     true, &xp_matched[num_dn_match],
						     &xp_match_len, true);
		zlog_debug("%s: [%d] -- DNODE: %s, Match: %d/%d/%d, %s",
			   __func__, level, chld_xpath[indx], match, max_match,
			   xp_match_len, xp_matched[num_dn_match]);
		if (!match || match < max_match) {
			free(chld_xpath[indx]);
			continue;
		}

		if (match > max_match) {
			max_match = match;
			if (num_dn_match) {
				if (xp_matched[0]) {
					free(xp_matched[0]);
					xp_matched[0] = NULL;
				}
				xp_matched[0] = xp_matched[num_dn_match];
				xp_matched[num_dn_match] = NULL;
			}
			for (indx1 = 1; indx1 < num_dn_match; indx1++) {
				if (xp_matched[0]) {
					free(xp_matched[0]);
					xp_matched[0] = NULL;
				}
			}
			num_dn_match = 0;
		}

		dnode_matched[num_dn_match] = chld_xpath[indx];
		dnode_ctxt[num_dn_match] = chld_ctxt[indx];
		zlog_debug("%s: [%d], XP_MATCH: %s", __func__, num_dn_match+1,
			   xp_matched[num_dn_match]);
		num_dn_match++;
	}

	ret = 0;
	for (indx = 0; indx < num_dn_match; indx++) {
		if (wc_key_start >= 0 && wc_key_end >= 0) {
			int len = strlen(xp_matched[indx]);
			zlog_debug("%s: [%d] --- Merge XPATH: [%s] + [%s]",
				   __func__, level, xp_matched[indx],
				   &xpath[start_indx+wc_key_end+1]);
			strncat(xp_matched[indx], &xpath[start_indx+wc_key_end], MGMTD_MAX_XPATH_LEN - xp_match_len);
			zlog_debug("%s: [%d] --- Next XPATH: %s",
				   __func__, level, xp_matched[indx]);
			mgmt_xpath_resolve_wildcard(xp_matched[indx], len,
						    get_child_fn, iter_fn, ctxt, level+1);
		} else {
			zlog_debug("%s: [%d] ===> XPATH: %s", __func__, level,
				   dnode_matched[indx]);

			if (!ret && iter_fn) {
				zlog_debug("start of second db_iter");
 				ret = (*iter_fn)(dnode_matched[indx],
 						 dnode_ctxt[indx], ctxt);
				zlog_debug("End of second xpath");
			}
		}

		free(xp_matched[indx]);
	}

	return ret;
}
