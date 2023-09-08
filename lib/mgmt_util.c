// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Utilities
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "mgmt_util.h"

#include "lib/mgmt_util_clippy.c"

struct debug mgmt_dbg_util = {0, "Management common utilities"};

/*
 * Evaluates the regular expression match in the given xpath.
 */
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
	bool ignore_wild_match = false, inside_keyval = false;
	char *xp_next = NULL;

	rexp_len = strlen(xpath_regexp);
	xpath_len = strlen(xpath);
	MGMTD_UTIL_DBG("RE: %s / %d, XP: %s / %d", xpath_regexp, rexp_len,
		       xpath, xpath_len);

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
		 * Check if we have a key on the Xpath and not on the
		 * corresponding token on regex. If so we need to ignore
		 * rest of the token on the Xpath.
		 */
		if (xpath_regexp[re_indx] == '/') {
			if (xpath[xp_indx] == '[') {
				ignore_wild_match = true;
				re_wild = true;
			} else if (xpath[xp_indx] == '/') {
				ignore_wild_match = false;
				re_wild = false;
			}
		}

		/*
		 * Check if we have a key on the regex and not on the
		 * corresponding token on Xpath. If so we need to ignore
		 * rest of the token on the regex.
		 */
		if (xpath[xp_indx] == '/') {
			if (xpath_regexp[re_indx] == '[') {
				ignore_wild_match = true;
				xp_wild = true;
			} else if (xp_wild && xpath_regexp[re_indx] == '/') {
				ignore_wild_match = false;
				xp_wild = false;
			}
		}

		/*
		 * Check if we have entered a key-value.
		 */
		if (re_indx && xp_indx
			&& xpath_regexp[re_indx-1] == '='
			&& xpath_regexp[re_indx] == '\''
			&& xpath[xp_indx-1] == '='
			&& xpath[xp_indx] == '\'')
			/*
			 * We have "='" on both the regexp and xpath.
			 * Entering a key-value.
			 */
			inside_keyval = true;

		/*
		 * Check if we need to enter wildcard matching.
		 */
		if (inside_keyval && !ignore_wild_match && !enter_wild_match
			&& !match &&
			(xpath_regexp[re_indx] == '*'
			 || xpath[xp_indx] == '*')) {
			/*
			 * Found wildcard
			 */
			enter_wild_match = true;
			if (xpath_regexp[re_indx] == '*') {
				/*
				 * Begin RE wildcard match.
				 */
				re_wild = true;
			} else if (xpath[xp_indx] == '*') {
				/*
				 * Begin XP wildcard match.
				 */
				xp_wild = true;
			}
		}

		/*
		 * Check if we need to exit wildcard matching.
		 */
		if (inside_keyval && !ignore_wild_match && enter_wild_match) {
			if (re_wild &&
				xpath[xp_indx] == xpath_regexp[re_indx+1]) {
				/*
				 * End RE wildcard matching.
				 */
				re_wild = false;
				re_indx++;
				enter_wild_match = false;
			} else if (xp_wild &&
				(xpath_regexp[re_indx] == xpath[xp_indx+1])) {
				/*
				 * End XP wildcard matching.
				 */
				xp_wild = false;
				xp_indx++;
				enter_wild_match = false;
			}
		}

		/*
		 * Check if we are exiting a key-value.
		 */
		if (inside_keyval
			&& xpath_regexp[re_indx] == '\''
			&& xpath_regexp[re_indx+1] == ']'
			&& xpath[xp_indx] == '\''
			&& xpath[xp_indx+1] == ']')
			/*
			 * We are already inside a key-value and we
			 * have "']" on both the regexp and xpath.
			 * Exiting the key-value.
			 */
			inside_keyval = false;

		match = (xp_wild || re_wild
			 || xpath_regexp[re_indx] == xpath[xp_indx]);

		/*
		 * Check if we found a delimiter in both the Xpaths
		 */
		delim = false;
		if (!inside_keyval
			&& (((xpath[xp_indx] == '/'
				|| xpath[xp_indx] == ']')
				&& (re_wild
				|| xpath_regexp[re_indx] == xpath[xp_indx]))
			|| ((xpath_regexp[re_indx] == '/'
				|| xpath_regexp[re_indx] == ']')
				&& (xp_wild
				|| xpath_regexp[re_indx] == xpath[xp_indx]))))
			delim = true;

		if (delim && re_indx && xp_indx)
			/*
			 * Increment the match count if we have a new
			 * delimiter.
			 */
			match_len++;

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

		MGMTD_UTIL_DBG("RE %c [indx: %d/%d, w: %d] XP %c [indx: %d/%d, w: %d] XM:%c IK:%d, W: %d Match: %d Len: %d",
			       xpath_regexp[re_indx], re_indx, rexp_len,
			       re_wild, xpath[xp_indx], xp_indx, xpath_len,
			       xp_wild, get_match_xpath ? *(xp_next-1) : '\0',
			       inside_keyval, enter_wild_match, match,
			       match_len);

		if (re_wild && xp_wild)
			/*
			 * Ideally this should never happen.
			 */
			break;

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

/*
 * Returns the index of the first wildcard in a given xpath.
 */
int mgmt_xpath_find_first_wildcard(const char *xpath, int *key_end)
{
	bool key_val = false, wc_found = false;
	int indx, last_sep = -1, key_start = -1;

	if (key_end)
		*key_end = -1;

	for (indx = 0; ; indx++) {
		switch (xpath[indx]) {
		case '\0':
			/*
			 * End of the xpath string. Return the wildcard keyset
			 * if we found one.
			 */
			if (wc_found && key_end)
				*key_end = indx;
			return wc_found ? key_start : -1;
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

		MGMTD_UTIL_DBG("Indx: %d, Char: '%c', K: %d, WC: %d, Last-Sep: %d, KS: %d, KE:%d ",
			       indx, xpath[indx], key_val, wc_found, last_sep,
			       key_start, key_end ? *key_end : -1);
	}

	return -1;
}

/*
 * Resolve wildcard entry in a given xpath.
 */
int mgmt_xpath_resolve_wildcard(char *xpath, int start_indx,
				void (*get_child_fn)(char *base_xpath,
						     const char *child_xpath[],
						     void *child_ctxt[],
						     int *num_child,
						     void *ctxt, char* xpath_key),
				int (*iter_fn)(const char *child_xpath,
					       void *child_ctxt,
					       void *ctxt),
				void *ctxt, int level)
{
	int wc_key_start, wc_key_end, indx, indx1, match, max_match;
	int xp_match_len, num_dn_match;
	char orig;
	char xpath_key[MGMTD_MAX_XPATH_LEN];
	char *dnode_matched[MGMTD_MAX_NUM_DSNODES_PER_BATCH] = { 0 };
	void *dnode_ctxt[MGMTD_MAX_NUM_DSNODES_PER_BATCH] = { 0 };
	char *xp_matched[MGMTD_MAX_NUM_DSNODES_PER_BATCH] = { 0 };
	char *chld_xpath[MGMTD_MAX_NUM_DSNODES_PER_BATCH] = { 0 };
	void *chld_ctxt[MGMTD_MAX_NUM_DSNODES_PER_BATCH] = { 0 };
	int num_child, ret;

	wc_key_start = mgmt_xpath_find_first_wildcard(&xpath[start_indx], &wc_key_end);

	MGMTD_UTIL_DBG(" [%d] - SI: %d, KS:%d, KE:%d, Xpath: %s",
			level, start_indx, wc_key_start, wc_key_end, xpath);

	if (wc_key_start < 0) {
		ret = 0;
		if (iter_fn) {
			MGMTD_UTIL_DBG("start of one ds_iter ");
			ret = (*iter_fn)(xpath, NULL, ctxt);
		}
		MGMTD_UTIL_DBG("End of one xpath ");
		return ret;
	}

	strlcpy(xpath_key, xpath, sizeof(xpath_key));
	if (wc_key_end >= 0) {
		xpath_key[start_indx + wc_key_end] = '\0';
		MGMTD_UTIL_DBG(" [%d] -- Truncated Xpath: %s",
				level, xpath_key);
	}

	/* Get the exact set of children under base xpath. */
	if (wc_key_start >= 0) {
		orig = xpath[start_indx + wc_key_start - 1];
		xpath[start_indx + wc_key_start - 1] = '\0';
	}
	num_child = array_size(chld_xpath);
	(*get_child_fn)(xpath, (const char**)chld_xpath, chld_ctxt,
			&num_child, ctxt, xpath_key);
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
		MGMTD_UTIL_DBG(" [%d] -- DNODE: %s, Match: %d/%d/%d, %s",
			       level, chld_xpath[indx], match, max_match,
			       xp_match_len, xp_matched[num_dn_match]);
		if (!match || match < max_match) {
			/*
			 * Not at par with previous best match.
			 */
			if (chld_xpath[indx]) {
				/* Discard the child */
				free(chld_xpath[indx]);
				chld_xpath[indx] = NULL;
			}
			if (xp_matched[num_dn_match]) {
				/* Discard the resolved xpath as well */
				free(xp_matched[num_dn_match]);
				xp_matched[num_dn_match] = NULL;
			}
			continue;
		}

		if (match > max_match) {
			/*
			 * Better match than all previous best matches
			 */
			max_match = match;
			if (num_dn_match) {
				/*
				 * There seems to be previous best matches.
				 * Let's drop them all first.
				 */
				for (indx1 = 0; indx1 < num_dn_match; indx1++) {
					if (xp_matched[indx1]) {
						free(xp_matched[indx1]);
						xp_matched[indx1] = NULL;
					}
				}
				/*
				 * And move the current one to the  beginning of the
				 * best match.
				 */
				xp_matched[0] = xp_matched[num_dn_match];
				xp_matched[num_dn_match] = NULL;
			}
			num_dn_match = 0;
		}

		/*
		 * Current child xpath is either the best match or is at
		 * par with the previous best matches.
		 */
		dnode_matched[num_dn_match] = chld_xpath[indx];
		chld_xpath[indx] = NULL;
		dnode_ctxt[num_dn_match] = chld_ctxt[indx];
		MGMTD_UTIL_DBG(" [%d], XP_MATCH: %s", num_dn_match+1,
			       xp_matched[num_dn_match]);
		num_dn_match++;
	}

	ret = 0;
	for (indx = 0; indx < num_dn_match; indx++) {
		if (wc_key_start >= 0 && wc_key_end >= 0) {
			int len = strlen(xp_matched[indx]);

			MGMTD_UTIL_DBG(" [%d] --- Merge XPATH: [%s] + [%s]",
				       level, xp_matched[indx],
				       &xpath[start_indx+wc_key_end+1]);
			strlcat(xp_matched[indx], &xpath[start_indx+wc_key_end], MGMTD_MAX_XPATH_LEN - xp_match_len);
			MGMTD_UTIL_DBG(" [%d] --- Next XPATH: %s",
				       level, xp_matched[indx]);
			mgmt_xpath_resolve_wildcard(xp_matched[indx], len,
						    get_child_fn, iter_fn, ctxt, level+1);
		} else {
			MGMTD_UTIL_DBG(" [%d] ===> XPATH: %s", level,
				       dnode_matched[indx]);

			if (!ret && iter_fn) {
				MGMTD_UTIL_DBG("start of second ds_iter");
				ret = (*iter_fn)(dnode_matched[indx],
						 dnode_ctxt[indx], ctxt);
				MGMTD_UTIL_DBG("End of second xpath");
			}
		}

		free(xp_matched[indx]);
		free(dnode_matched[indx]);
	}

	return ret;
}

/*
 * debug utilities command for mgmtd.
 */
DEFPY(debug_mgmt_util, debug_mgmt_util_cmd,
      "[no] debug mgmt utilities",
      NO_STR DEBUG_STR MGMTD_STR
      "Common utilities\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	DEBUG_MODE_SET(&mgmt_dbg_util, mode, !no);

	return CMD_SUCCESS;
}

/*
 * Enable all debug utilities for mgmtd.
 */
static void mgmt_debug_util_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&mgmt_dbg_util, flags, set);
}

/*
 * Check debug mode config for mgmtd utility.
 */
static int mgmt_debug_util_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&mgmt_dbg_util, DEBUG_MODE_CONF))
		vty_out(vty, "debug mgmt utilities\n");

	return CMD_SUCCESS;
}

/*
 * Show mgmtd debug utility.
 */
void mgmt_debug_util_show_debug(struct vty *vty)
{
	if (MGMTD_DBG_UTIL_CHECK())
		vty_out(vty, "debug mgmt utilities\n");
}

static struct debug_callbacks mgmt_dbg_util_cbs = {
	.debug_set_all = mgmt_debug_util_set_all};

static struct cmd_node mgmt_dbg_util_node = {
	.name = "mgmt utilities",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = mgmt_debug_util_config_write,
};

/*
 * Initialize mgmt debug utility.
 */
void mgmt_util_vty_init(void)
{
	static bool mgmt_util_vty_initialized;

	if (mgmt_util_vty_initialized)
		return;

	debug_init(&mgmt_dbg_util_cbs);
	install_node(&mgmt_dbg_util_node);
	install_element(ENABLE_NODE, &debug_mgmt_util_cmd);
	install_element(CONFIG_NODE, &debug_mgmt_util_cmd);
	mgmt_util_vty_initialized = true;
}
