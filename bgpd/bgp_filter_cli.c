// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Filter CLI Implementation
 * Copyright (C) 2024 FRRouting
 *
 * DEFPY_YANG commands for community-list, large-community-list,
 * extcommunity-list, and as-path-list defined in frr-bgp-filter.yang
 */

#include <zebra.h>

#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "lib/printfrr.h"
#include "libyang/tree_data.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_filter_cli.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"

#include "bgpd/bgp_filter_cli_clippy.c"

#define COMMUNITY_LIST_STR    "Add a community list entry\n"
#define LCOMMUNITY_LIST_STR   "Add a large community list entry\n"
#define LCOMMUNITY_VAL_STR    "Large community in aa:bb:cc format\n"
#define EXTCOMMUNITY_LIST_STR "Add an extended community list entry\n"
#define EXTCOMMUNITY_VAL_STR                                                                      \
	"Extended community: 'rt|soo ASN:NN', 'rt|soo A.B.C.D:NN', 'nt A.B.C.D:0' or 'color CO:NN'\n"
#define ASPATH_LIST_STR "BGP autonomous system path filter\n"
#define ASPATH_REGEX_STR                                                                          \
	"A regular-expression (1234567890_^|[,{}() ]$*+.?-\\\\) to match the BGP AS paths\n"

/*
 * Validate AS-path regex characters.
 * This is a local copy for mgmtd which doesn't link bgp_filter.c
 */
static bool aspath_regex_validate(const char *regstr)
{
	char valid_chars[] = "1234567890_^|[,{}() ]$*+.?-\\";

	if (strspn(regstr, valid_chars) == strlen(regstr))
		return true;
	return false;
}

/*
 * Helper function to get next sequence number for community-list entries.
 */
static int clist_get_seq_cb(const struct lyd_node *dnode, void *arg)
{
	int64_t *seq = arg;
	int64_t cur_seq = yang_dnode_get_uint32(dnode, "sequence");

	if (cur_seq > *seq)
		*seq = cur_seq;

	return YANG_ITER_CONTINUE;
}

static int64_t clist_get_seq(struct vty *vty, const char *xpath)
{
	int64_t seq = 0;

	yang_dnode_iterate(clist_get_seq_cb, &seq, vty->candidate_config->dnode, "%s/entry", xpath);

	seq += 5;
	if (seq > UINT32_MAX) {
		vty_out(vty, "%% Sequence number out of range\n");
		return -1;
	}
	return seq;
}

struct bgp_filter_join {
	char buf[4096];
	bool first;
};

static int bgp_filter_join_value(const struct lyd_node *dnode, void *arg)
{
	struct bgp_filter_join *join = arg;
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (!val)
		return YANG_ITER_CONTINUE;
	if (!join->first)
		strlcat(join->buf, " ", sizeof(join->buf));
	strlcat(join->buf, val, sizeof(join->buf));
	join->first = false;
	return YANG_ITER_CONTINUE;
}

static bool bgp_filter_entry_matches(const struct lyd_node *entry, const char *value_leaf,
				     bool leaf_list, const char *want)
{
	struct bgp_filter_join join = { .first = true };

	if (!want)
		return false;
	if (leaf_list) {
		yang_dnode_iterate(bgp_filter_join_value, &join, entry, "%s", value_leaf);
		return strmatch(join.buf, want);
	}
	if (!yang_dnode_existsf(entry, "%s", value_leaf))
		return false;
	return strmatch(yang_dnode_get_string(entry, "%s", value_leaf), want);
}

/*
 * Classic extcommunity-list entries mix types: "rt A soo B nt C color D".
 * Keywords may be repeated or omitted between values of the same type.
 * Compare the parsed extended communities, which is how the old unset
 * decided two lines were the same entry.
 */
static const char *const bgp_extcommunity_keywords[] = { "rt", "soo", "nt", "color" };
static const char *const bgp_extcommunity_leaves[] = {
	"extcommunity-rt",
	"extcommunity-soo",
	"extcommunity-nt",
	"extcommunity-color",
};

static int bgp_extcommunity_keyword(const char *arg)
{
	size_t i;

	for (i = 0; i < array_size(bgp_extcommunity_keywords); i++) {
		if (strmatch(arg, bgp_extcommunity_keywords[i]))
			return (int)i;
	}
	return -1;
}

static bool bgp_filter_append_word(char *buf, size_t buflen, bool *first, const char *word)
{
	size_t n;

	if (!*first) {
		n = strlcat(buf, " ", buflen);
		if (n >= buflen)
			return false;
	}
	n = strlcat(buf, word, buflen);
	*first = false;
	return n < buflen;
}

/* "rt A rt B soo C" from the entry's leaf-lists. False on overflow. */
static bool bgp_filter_extcommunity_from_entry(const struct lyd_node *entry, char *buf,
					       size_t buflen)
{
	size_t part;
	bool first = true;

	buf[0] = '\0';
	for (part = 0; part < array_size(bgp_extcommunity_leaves); part++) {
		struct bgp_filter_join join = { .first = true };
		char *value;
		const char *keyword = bgp_extcommunity_keywords[part];

		yang_dnode_iterate(bgp_filter_join_value, &join, entry, "%s",
				   bgp_extcommunity_leaves[part]);
		if (join.first)
			continue;
		for (value = join.buf; value && *value;) {
			char *sp = strchr(value, ' ');

			if (sp)
				*sp = '\0';
			if (!bgp_filter_append_word(buf, buflen, &first, keyword) ||
			    !bgp_filter_append_word(buf, buflen, &first, value))
				return false;
			value = sp ? sp + 1 : NULL;
		}
	}
	return buf[0] != '\0';
}

/* Same form from CLI tokens. A keyword applies to each following value. */
static bool bgp_filter_extcommunity_from_argv(struct cmd_token **argv, int argc, int idx,
					      char *buf, size_t buflen)
{
	int kind = -1;
	bool need_value = false;
	bool first = true;
	int i;

	buf[0] = '\0';
	if (idx < 0)
		return false;
	for (i = idx; i < argc; i++) {
		int next = bgp_extcommunity_keyword(argv[i]->arg);

		if (next >= 0) {
			if (need_value)
				return false;
			kind = next;
			need_value = true;
			continue;
		}
		if (kind < 0)
			return false;
		if (!bgp_filter_append_word(buf, buflen, &first, bgp_extcommunity_keywords[kind]) ||
		    !bgp_filter_append_word(buf, buflen, &first, argv[i]->arg))
			return false;
		need_value = false;
	}
	return !need_value && buf[0] != '\0';
}

static bool bgp_filter_extcommunity_matches(const struct lyd_node *entry, struct cmd_token **argv,
					    int argc, int idx)
{
	char want[4096];
	char got[4096];
	struct ecommunity *want_ecom = NULL;
	struct ecommunity *got_ecom = NULL;
	bool match;

	if (!bgp_filter_extcommunity_from_argv(argv, argc, idx, want, sizeof(want)))
		return false;
	if (!bgp_filter_extcommunity_from_entry(entry, got, sizeof(got)))
		return false;

	want_ecom = ecommunity_str2com(want, 0, 1);
	got_ecom = ecommunity_str2com(got, 0, 1);
	match = want_ecom && got_ecom && ecommunity_cmp(want_ecom, got_ecom);
	ecommunity_free(&want_ecom);
	ecommunity_free(&got_ecom);
	return match;
}

/*
 * Delete the one list entry whose action and value match. Classic
 * community_list_unset() matches the value and ignores sequence; a missing
 * sequence must not destroy the list (the separate "all" command does that).
 *
 * extcommunity is true for a standard extcommunity-list line. val_idx then
 * points at the first type keyword, and every type on the entry must match.
 */
static int bgp_filter_destroy_matching_entry(struct vty *vty, const char *list_xpath,
					     const char *seq_str, const char *action,
					     const char *value_leaf, bool leaf_list,
					     bool extcommunity, struct cmd_token **argv, int argc,
					     int val_idx)
{
	char xpath_entry[XPATH_MAXLEN + 256];
	char *want = NULL;
	struct ly_set *set = NULL;
	const struct lyd_node *content = NULL;
	const struct lyd_node *seq_hit = NULL;
	const struct lyd_node *match;
	char *entry_path;
	uint32_t i;
	int ret;

	if (!extcommunity) {
		want = argv_concat(argv, argc, val_idx);
		if (!want || want[0] == '\0') {
			vty_out(vty, "%% No community string specified\n");
			XFREE(MTYPE_TMP, want);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (!vty->candidate_config || !vty->candidate_config->dnode) {
		XFREE(MTYPE_TMP, want);
		return CMD_SUCCESS;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[action='%s']", list_xpath, action);
	if (lyd_find_xpath(vty->candidate_config->dnode, xpath_entry, &set) != LY_SUCCESS ||
	    !set || set->count == 0) {
		ly_set_free(set, NULL);
		XFREE(MTYPE_TMP, want);
		return CMD_SUCCESS;
	}

	for (i = 0; i < set->count; i++) {
		const struct lyd_node *entry = set->dnodes[i];
		const char *got;

		if (extcommunity) {
			if (!bgp_filter_extcommunity_matches(entry, argv, argc, val_idx))
				continue;
		} else if (!bgp_filter_entry_matches(entry, value_leaf, leaf_list, want))
			continue;
		if (!content)
			content = entry;
		if (!seq_str)
			break;
		got = yang_dnode_get_string(entry, "sequence");
		if (got && strmatch(got, seq_str)) {
			seq_hit = entry;
			break;
		}
	}
	match = seq_hit ? seq_hit : content;
	ly_set_free(set, NULL);
	XFREE(MTYPE_TMP, want);

	if (!match)
		return CMD_SUCCESS;

	entry_path = lyd_path(match, LYD_PATH_STD, NULL, 0);
	if (!entry_path)
		return CMD_WARNING_CONFIG_FAILED;
	nb_cli_enqueue_change(vty, entry_path, NB_OP_DESTROY, NULL);
	free(entry_path);
	ret = nb_cli_apply_changes(vty, NULL);
	return ret;
}

/*
 * A repeated sequence replaces the entry. NB_OP_CREATE on a leaf-list only
 * adds, so drop the values already stored before enqueueing the new ones.
 * community_list_entry_add() replaces by sequence.
 */
static void bgp_filter_clear_entry_leaflists(struct vty *vty, const char *entry_xpath)
{
	const struct lyd_node *entry, *child;
	char leaf[XPATH_MAXLEN];

	if (!vty->candidate_config || !vty->candidate_config->dnode)
		return;

	entry = yang_dnode_get(vty->candidate_config->dnode, entry_xpath);
	if (!entry)
		return;

	for (child = lyd_child(entry); child; child = child->next) {
		if (!child->schema || child->schema->nodetype != LYS_LEAFLIST)
			continue;
		snprintfrr(leaf, sizeof(leaf), "./%s[.='%s']", child->schema->name,
			   yang_dnode_get_string(child, NULL));
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
}

/*
 * Community list commands
 */

/* Standard community-list: numbers 1-99 or 'standard NAME' */
DEFPY_YANG(
	bgp_community_list_standard_cli,
	bgp_community_list_standard_cli_cmd,
	"bgp community-list <(1-99)$num|standard COMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	BGP_STR
	COMMUNITY_LIST_STR
	"Community list number (standard)\n"
	"Add a standard community-list entry\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	COMMUNITY_VAL_STR)
{
	int idx = 0;
	int i;
	char xpath[XPATH_MAXLEN + 64];
	char xpath_entry[XPATH_MAXLEN + 128];
	char xpath_leaf[XPATH_MAXLEN + 128];
	const char *list_name;
	int64_t sseq;

	/* Get list name from either number or name */
	list_name = num_str ? num_str : name;

	/* Build base xpath */
	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:community-list[name='%s']", list_name);

	/* Get or generate sequence number */
	if (seq_str) {
		sseq = seq;
	} else {
		sseq = clist_get_seq(vty, xpath);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%" PRId64 "']", xpath,
		   sseq);

	/* Find first community value argument */
	if (!argv_find(argv, argc, "AA:NN", &idx)) {
		vty_out(vty, "%% No community string specified\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Reject malformed values before YANG edit (classic parity). */
	for (i = idx; i < argc; i++) {
		struct community *com;

		com = community_str2com(argv[i]->arg);
		if (!com) {
			vty_out(vty, "%% Malformed community-list value\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		community_free(&com);
	}

	/* Create list and entry */
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, "community-list-standard");

	bgp_filter_clear_entry_leaflists(vty, xpath_entry);

	/* Add each community value as a separate leaf-list entry */
	for (i = idx; i < argc; i++) {
		snprintfrr(xpath_leaf, sizeof(xpath_leaf), "./standard-community-string[.='%s']",
			   argv[i]->arg);
		nb_cli_enqueue_change(vty, xpath_leaf, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_bgp_community_list_standard_cli,
	no_bgp_community_list_standard_cli_cmd,
	"no bgp community-list <(1-99)$num|standard COMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	NO_STR
	BGP_STR
	COMMUNITY_LIST_STR
	"Community list number (standard)\n"
	"Add a standard community-list entry\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	COMMUNITY_VAL_STR)
{
	char xpath[XPATH_MAXLEN];
	const char *list_name;
	int idx = 0;

	list_name = num_str ? num_str : name;
	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:community-list[name='%s']", list_name);
	if (argv_find(argv, argc, action, &idx))
		idx++;
	return bgp_filter_destroy_matching_entry(vty, xpath, seq_str, action,
						 "standard-community-string", true, false, argv,
						 argc, idx);
}

DEFPY_YANG(
	no_bgp_community_list_standard_all_cli,
	no_bgp_community_list_standard_all_cli_cmd,
	"no bgp community-list <(1-99)$num|standard COMMUNITY_LIST_NAME$name>",
	NO_STR
	BGP_STR
	COMMUNITY_LIST_STR
	"Community list number (standard)\n"
	"Add a standard community-list entry\n"
	"Community list name\n")
{
	char xpath[XPATH_MAXLEN + 64];
	const char *list_name;

	list_name = num_str ? num_str : name;

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:community-list[name='%s']", list_name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Expanded community-list: numbers 100-500 or 'expanded NAME' */
DEFPY_YANG(
	bgp_community_list_expanded_cli,
	bgp_community_list_expanded_cli_cmd,
	"bgp community-list <(100-500)$num|expanded COMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	BGP_STR
	COMMUNITY_LIST_STR
	"Community list number (expanded)\n"
	"Add an expanded community-list entry\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	"An ordered list as a regular-expression\n")
{
	int idx = 0;
	char xpath[XPATH_MAXLEN + 64];
	char xpath_entry[XPATH_MAXLEN + 128];
	const char *list_name;
	int64_t sseq;
	char *regex_str;

	list_name = num_str ? num_str : name;

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:community-list[name='%s']", list_name);

	if (seq_str) {
		sseq = seq;
	} else {
		sseq = clist_get_seq(vty, xpath);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%" PRId64 "']", xpath,
		   sseq);

	argv_find(argv, argc, "LINE", &idx);
	regex_str = argv_concat(argv, argc, idx);
	if (!regex_str) {
		vty_out(vty, "%% No community regex specified\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, "community-list-extended");
	nb_cli_enqueue_change(vty, "./expanded-community-string", NB_OP_MODIFY, regex_str);

	/* regex_str must remain valid until after nb_cli_apply_changes */
	int ret = nb_cli_apply_changes(vty, "%s", xpath_entry);

	XFREE(MTYPE_TMP, regex_str);
	return ret;
}

DEFPY_YANG(
	no_bgp_community_list_expanded_cli,
	no_bgp_community_list_expanded_cli_cmd,
	"no bgp community-list <(100-500)$num|expanded COMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	NO_STR
	BGP_STR
	COMMUNITY_LIST_STR
	"Community list number (expanded)\n"
	"Add an expanded community-list entry\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	"An ordered list as a regular-expression\n")
{
	char xpath[XPATH_MAXLEN];
	const char *list_name;
	int idx = 0;

	list_name = num_str ? num_str : name;
	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:community-list[name='%s']", list_name);
	if (argv_find(argv, argc, action, &idx))
		idx++;
	return bgp_filter_destroy_matching_entry(vty, xpath, seq_str, action,
						 "expanded-community-string", false, false, argv,
						 argc, idx);
}

DEFPY_YANG(
	no_bgp_community_list_expanded_all_cli,
	no_bgp_community_list_expanded_all_cli_cmd,
	"no bgp community-list <(100-500)$num|expanded COMMUNITY_LIST_NAME$name>",
	NO_STR
	BGP_STR
	COMMUNITY_LIST_STR
	"Community list number (expanded)\n"
	"Add an expanded community-list entry\n"
	"Community list name\n")
{
	char xpath[XPATH_MAXLEN + 64];
	const char *list_name;

	list_name = num_str ? num_str : name;

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:community-list[name='%s']", list_name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Large community list commands
 */
DEFPY_YANG(
	bgp_lcommunity_list_standard_cli,
	bgp_lcommunity_list_standard_cli_cmd,
	"bgp large-community-list <(1-99)$num|standard LCOMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action AA:BB:CC...",
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large community list number (standard)\n"
	"Add a standard large-community-list entry\n"
	"Large community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	LCOMMUNITY_VAL_STR)
{
	int idx = 0;
	int i;
	char xpath[XPATH_MAXLEN + 64];
	char xpath_entry[XPATH_MAXLEN + 128];
	char xpath_leaf[XPATH_MAXLEN + 128];
	const char *list_name;
	const char *type_str;
	int64_t sseq;

	list_name = num_str ? num_str : name;

	/* Type based on whether number or name was used */
	if (num_str)
		type_str = "large-community-list-standard-id";
	else
		type_str = "large-community-list-standard-name";

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:large-community-list[name='%s']", list_name);

	if (seq_str) {
		sseq = seq;
	} else {
		sseq = clist_get_seq(vty, xpath);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%" PRId64 "']", xpath,
		   sseq);

	/* Find first large community value argument */
	argv_find(argv, argc, "AA:BB:CC", &idx);
	if (idx >= argc) {
		vty_out(vty, "%% No large community string specified\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (i = idx; i < argc; i++) {
		struct lcommunity *lcom;

		lcom = lcommunity_str2com(argv[i]->arg);
		if (!lcom) {
			vty_out(vty, "%% Malformed large-community-list value\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		lcommunity_free(&lcom);
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, type_str);

	bgp_filter_clear_entry_leaflists(vty, xpath_entry);

	/* Add each large community value as a separate leaf-list entry */
	for (i = idx; i < argc; i++) {
		snprintfrr(xpath_leaf, sizeof(xpath_leaf),
			   "./standard-large-community-string[.='%s']", argv[i]->arg);
		nb_cli_enqueue_change(vty, xpath_leaf, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_bgp_lcommunity_list_standard_cli,
	no_bgp_lcommunity_list_standard_cli_cmd,
	"no bgp large-community-list <(1-99)$num|standard LCOMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action AA:BB:CC...",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large community list number (standard)\n"
	"Add a standard large-community-list entry\n"
	"Large community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	LCOMMUNITY_VAL_STR)
{
	char xpath[XPATH_MAXLEN];
	const char *list_name;
	int idx = 0;

	list_name = num_str ? num_str : name;
	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:large-community-list[name='%s']", list_name);
	if (argv_find(argv, argc, action, &idx))
		idx++;
	return bgp_filter_destroy_matching_entry(vty, xpath, seq_str, action,
						 "standard-large-community-string", true, false,
						 argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_lcommunity_list_standard_all_cli,
	no_bgp_lcommunity_list_standard_all_cli_cmd,
	"no bgp large-community-list <(1-99)$num|standard LCOMMUNITY_LIST_NAME$name>",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large community list number (standard)\n"
	"Add a standard large-community-list entry\n"
	"Large community list name\n")
{
	char xpath[XPATH_MAXLEN + 64];
	const char *list_name;

	list_name = num_str ? num_str : name;

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:large-community-list[name='%s']", list_name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_lcommunity_list_expanded_cli,
	bgp_lcommunity_list_expanded_cli_cmd,
	"bgp large-community-list <(100-500)$num|expanded LCOMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large community list number (expanded)\n"
	"Add an expanded large-community-list entry\n"
	"Large community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	"An ordered list as a regular-expression\n")
{
	int idx = 0;
	char xpath[XPATH_MAXLEN + 64];
	char xpath_entry[XPATH_MAXLEN + 128];
	const char *list_name;
	const char *type_str;
	int64_t sseq;
	char *regex_str;

	list_name = num_str ? num_str : name;

	if (num_str)
		type_str = "large-community-list-extended-id";
	else
		type_str = "large-community-list-extended-name";

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:large-community-list[name='%s']", list_name);

	if (seq_str) {
		sseq = seq;
	} else {
		sseq = clist_get_seq(vty, xpath);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%" PRId64 "']", xpath,
		   sseq);

	argv_find(argv, argc, "LINE", &idx);
	regex_str = argv_concat(argv, argc, idx);
	if (!regex_str) {
		vty_out(vty, "%% No large community regex specified\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, type_str);
	nb_cli_enqueue_change(vty, "./expanded-large-community-string", NB_OP_MODIFY, regex_str);

	/* regex_str must remain valid until after nb_cli_apply_changes */
	int ret = nb_cli_apply_changes(vty, "%s", xpath_entry);

	XFREE(MTYPE_TMP, regex_str);
	return ret;
}

DEFPY_YANG(
	no_bgp_lcommunity_list_expanded_cli,
	no_bgp_lcommunity_list_expanded_cli_cmd,
	"no bgp large-community-list <(100-500)$num|expanded LCOMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large community list number (expanded)\n"
	"Add an expanded large-community-list entry\n"
	"Large community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	"An ordered list as a regular-expression\n")
{
	char xpath[XPATH_MAXLEN];
	const char *list_name;
	int idx = 0;

	list_name = num_str ? num_str : name;
	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:large-community-list[name='%s']", list_name);
	if (argv_find(argv, argc, action, &idx))
		idx++;
	return bgp_filter_destroy_matching_entry(vty, xpath, seq_str, action,
						 "expanded-large-community-string", false, false,
						 argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_lcommunity_list_expanded_all_cli,
	no_bgp_lcommunity_list_expanded_all_cli_cmd,
	"no bgp large-community-list <(100-500)$num|expanded LCOMMUNITY_LIST_NAME$name>",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large community list number (expanded)\n"
	"Add an expanded large-community-list entry\n"
	"Large community list name\n")
{
	char xpath[XPATH_MAXLEN + 64];
	const char *list_name;

	list_name = num_str ? num_str : name;

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:large-community-list[name='%s']", list_name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Extcommunity list commands
 */

DEFPY_YANG(
	no_bgp_lcommunity_list_name_all_cli,
	no_bgp_lcommunity_list_name_all_cli_cmd,
	"no bgp large-community-list LCOMMUNITY_LIST_NAME$name",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large community list name\n")
{
	char xpath[XPATH_MAXLEN + 64];

	/*
	 * Numbered lists are deleted by the (1-99) and (100-500) commands.
	 * A range token outranks this name, so a number does not land here.
	 */
	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:large-community-list[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_extcommunity_list_standard_cli,
	bgp_extcommunity_list_standard_cli_cmd,
	"bgp extcommunity-list <(1-99)$num|standard EXTCOMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Extcommunity list number (standard)\n"
	"Add a standard extcommunity-list entry\n"
	"Extcommunity list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify extended community to reject\n"
	"Specify extended community to accept\n"
	EXTCOMMUNITY_VAL_STR)
{
	int idx = 0;
	int i;
	char xpath[XPATH_MAXLEN + 64];
	char xpath_entry[XPATH_MAXLEN + 128];
	char xpath_leaf[XPATH_MAXLEN + 128];
	const char *list_name;
	const char *yang_type_str;
	const char *rt_or_soo_leaf;
	int64_t sseq;

	list_name = num_str ? num_str : name;

	if (num_str)
		yang_type_str = "extcommunity-list-standard-id";
	else
		yang_type_str = "extcommunity-list-standard-name";

	rt_or_soo_leaf = NULL;

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:extcommunity-list[name='%s']", list_name);

	if (seq_str) {
		sseq = seq;
	} else {
		sseq = clist_get_seq(vty, xpath);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%" PRId64 "']", xpath,
		   sseq);

	/* Start at the first token after permit/deny so type keywords count. */
	if (!argv_find(argv, argc, action, &idx) || idx + 1 >= argc) {
		vty_out(vty, "%% No extended community string specified\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	idx++;

	/*
	 * Classic CLI is "permit rt 65001:1 soo 65001:2". Type keywords may
	 * repeat. A value with no keyword in front of it is malformed.
	 * Check before enqueueing so a rejected line leaves no pending change.
	 */
	{
		const char *check_leaf = NULL;
		bool saw_value = false;

		for (i = idx; i < argc; i++) {
			if (strmatch(argv[i]->arg, "rt") || strmatch(argv[i]->arg, "soo") ||
			    strmatch(argv[i]->arg, "nt") || strmatch(argv[i]->arg, "color")) {
				check_leaf = argv[i]->arg;
				continue;
			}
			if (!check_leaf) {
				vty_out(vty, "%% Malformed community-list value\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			saw_value = true;
		}
		if (!saw_value) {
			vty_out(vty, "%% Malformed community-list value\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, yang_type_str);

	bgp_filter_clear_entry_leaflists(vty, xpath_entry);

	/*
	 * Classic CLI is "permit rt 65001:1 soo 65001:2". Type keywords may
	 * repeat among the AA:NN tokens. Each value is stored on the leaf-list
	 * for the keyword in front of it. Those lists are kept together.
	 */
	for (i = idx; i < argc; i++) {
		if (strmatch(argv[i]->arg, "rt")) {
			rt_or_soo_leaf = "extcommunity-rt";
			continue;
		}
		if (strmatch(argv[i]->arg, "soo")) {
			rt_or_soo_leaf = "extcommunity-soo";
			continue;
		}
		if (strmatch(argv[i]->arg, "nt")) {
			rt_or_soo_leaf = "extcommunity-nt";
			continue;
		}
		if (strmatch(argv[i]->arg, "color")) {
			rt_or_soo_leaf = "extcommunity-color";
			continue;
		}
		snprintfrr(xpath_leaf, sizeof(xpath_leaf), "./%s[.='%s']", rt_or_soo_leaf,
			   argv[i]->arg);
		nb_cli_enqueue_change(vty, xpath_leaf, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

DEFPY_YANG(
	no_bgp_extcommunity_list_standard_cli,
	no_bgp_extcommunity_list_standard_cli_cmd,
	"no bgp extcommunity-list <(1-99)$num|standard EXTCOMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	NO_STR
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Extcommunity list number (standard)\n"
	"Add a standard extcommunity-list entry\n"
	"Extcommunity list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify extended community to reject\n"
	"Specify extended community to accept\n"
	EXTCOMMUNITY_VAL_STR)
{
	char xpath[XPATH_MAXLEN];
	const char *list_name;
	int idx = 0;

	list_name = num_str ? num_str : name;
	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:extcommunity-list[name='%s']", list_name);
	/* Stay on the first token after the action so type keywords count. */
	if (!argv_find(argv, argc, action, &idx) || idx + 1 >= argc) {
		vty_out(vty, "%% No extended community string specified\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	idx++;
	return bgp_filter_destroy_matching_entry(vty, xpath, seq_str, action, NULL, false, true,
						 argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_extcommunity_list_standard_all_cli,
	no_bgp_extcommunity_list_standard_all_cli_cmd,
	"no bgp extcommunity-list <(1-99)$num|standard EXTCOMMUNITY_LIST_NAME$name>",
	NO_STR
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Extcommunity list number (standard)\n"
	"Add a standard extcommunity-list entry\n"
	"Extcommunity list name\n")
{
	char xpath[XPATH_MAXLEN + 64];
	const char *list_name;

	list_name = num_str ? num_str : name;

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:extcommunity-list[name='%s']", list_name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bgp_extcommunity_list_expanded_cli,
	bgp_extcommunity_list_expanded_cli_cmd,
	"bgp extcommunity-list <(100-500)$num|expanded EXTCOMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Extcommunity list number (expanded)\n"
	"Add an expanded extcommunity-list entry\n"
	"Extcommunity list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify extended community to reject\n"
	"Specify extended community to accept\n"
	"An ordered list as a regular-expression\n")
{
	int idx = 0;
	char xpath[XPATH_MAXLEN + 64];
	char xpath_entry[XPATH_MAXLEN + 128];
	const char *list_name;
	const char *yang_type_str;
	int64_t sseq;
	char *regex_str;

	list_name = num_str ? num_str : name;

	if (num_str)
		yang_type_str = "extcommunity-list-extended-id";
	else
		yang_type_str = "extcommunity-list-extended-name";

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:extcommunity-list[name='%s']", list_name);

	if (seq_str) {
		sseq = seq;
	} else {
		sseq = clist_get_seq(vty, xpath);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%" PRId64 "']", xpath,
		   sseq);

	argv_find(argv, argc, "LINE", &idx);
	regex_str = argv_concat(argv, argc, idx);
	if (!regex_str) {
		vty_out(vty, "%% No extcommunity regex specified\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nb_cli_enqueue_change(vty, "./type", NB_OP_MODIFY, yang_type_str);
	nb_cli_enqueue_change(vty, "./expanded-extcommunity-string", NB_OP_MODIFY, regex_str);

	/* regex_str must remain valid until after nb_cli_apply_changes */
	int ret = nb_cli_apply_changes(vty, "%s", xpath_entry);

	XFREE(MTYPE_TMP, regex_str);
	return ret;
}

DEFPY_YANG(
	no_bgp_extcommunity_list_expanded_cli,
	no_bgp_extcommunity_list_expanded_cli_cmd,
	"no bgp extcommunity-list <(100-500)$num|expanded EXTCOMMUNITY_LIST_NAME$name> [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	NO_STR
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Extcommunity list number (expanded)\n"
	"Add an expanded extcommunity-list entry\n"
	"Extcommunity list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify extended community to reject\n"
	"Specify extended community to accept\n"
	"An ordered list as a regular-expression\n")
{
	char xpath[XPATH_MAXLEN];
	const char *list_name;
	int idx = 0;

	list_name = num_str ? num_str : name;
	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:extcommunity-list[name='%s']", list_name);
	if (argv_find(argv, argc, action, &idx))
		idx++;
	return bgp_filter_destroy_matching_entry(vty, xpath, seq_str, action,
						 "expanded-extcommunity-string", false, false,
						 argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_extcommunity_list_expanded_all_cli,
	no_bgp_extcommunity_list_expanded_all_cli_cmd,
	"no bgp extcommunity-list <(100-500)$num|expanded EXTCOMMUNITY_LIST_NAME$name>",
	NO_STR
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Extcommunity list number (expanded)\n"
	"Add an expanded extcommunity-list entry\n"
	"Extcommunity list name\n")
{
	char xpath[XPATH_MAXLEN + 64];
	const char *list_name;

	list_name = num_str ? num_str : name;

	snprintfrr(xpath, sizeof(xpath),
		   "/frr-filter:lib/frr-bgp-filter:extcommunity-list[name='%s']", list_name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * AS-path access list commands
 */
DEFPY_YANG(
	bgp_as_path_access_list_cli,
	bgp_as_path_access_list_cli_cmd,
	"bgp as-path access-list AS_PATH_FILTER_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	BGP_STR
	ASPATH_LIST_STR
	"Specify an access list name\n"
	"Regular expression access list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify packets to reject\n"
	"Specify packets to forward\n"
	ASPATH_REGEX_STR)
{
	int idx = 0;
	char xpath[XPATH_MAXLEN + 64];
	char xpath_entry[XPATH_MAXLEN + 128];
	int64_t sseq;
	char *regex_str;

	snprintfrr(xpath, sizeof(xpath), "/frr-filter:lib/frr-bgp-filter:as-path-list[name='%s']",
		   name);

	if (seq_str) {
		sseq = seq;
	} else {
		sseq = clist_get_seq(vty, xpath);
		if (sseq < 0)
			return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%" PRId64 "']", xpath,
		   sseq);

	/* Find the action (deny/permit), LINE follows it */
	idx = 0;
	if (argv_find(argv, argc, "deny", &idx) || argv_find(argv, argc, "permit", &idx)) {
		/* LINE starts after deny/permit */
		idx++;
	}
	regex_str = argv_concat(argv, argc, idx);
	if (!regex_str || regex_str[0] == '\0') {
		vty_out(vty, "%% No AS-path regex specified\n");
		XFREE(MTYPE_TMP, regex_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Validate the regex characters */
	if (!aspath_regex_validate(regex_str)) {
		vty_out(vty, "%% Invalid character in as-path access-list %s\n", regex_str);
		XFREE(MTYPE_TMP, regex_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nb_cli_enqueue_change(vty, "./as-path", NB_OP_MODIFY, regex_str);

	/* Note: regex_str must remain valid until after nb_cli_apply_changes
	 * because nb_cli_enqueue_change stores a pointer, not a copy.
	 */
	int ret = nb_cli_apply_changes(vty, "%s", xpath_entry);

	XFREE(MTYPE_TMP, regex_str);
	return ret;
}

DEFPY_YANG(
	no_bgp_as_path_access_list_cli,
	no_bgp_as_path_access_list_cli_cmd,
	"no bgp as-path access-list AS_PATH_FILTER_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	NO_STR
	BGP_STR
	ASPATH_LIST_STR
	"Specify an access list name\n"
	"Regular expression access list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify packets to reject\n"
	"Specify packets to forward\n"
	ASPATH_REGEX_STR)
{
	char xpath[XPATH_MAXLEN + 64];
	char xpath_entry[XPATH_MAXLEN + 256];
	char *regex_str = NULL;
	struct ly_set *set = NULL;
	int idx = 0;
	int ret;

	snprintfrr(xpath, sizeof(xpath), "/frr-filter:lib/frr-bgp-filter:as-path-list[name='%s']",
		   name);

	if (seq_str) {
		/* Explicit seq: destroy that entry directly. */
		snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%s']", xpath,
			   seq_str);
		nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* No seq given. Match on (action, regex) like baseline's
	 * DEFUN(no_as_path) — delete only the single matching entry, not the
	 * whole list. Destroying the whole list while a route-map still
	 * references it via `set as-path exclude as-path-access-list NAME`
	 * leaves a dangling reference in the YANG tree and corrupts libyang's
	 * teardown during the candidate->running swap.
	 */
	if (argv_find(argv, argc, "deny", &idx) || argv_find(argv, argc, "permit", &idx))
		idx++;
	regex_str = argv_concat(argv, argc, idx);
	if (!regex_str || regex_str[0] == '\0') {
		vty_out(vty, "%% No AS-path regex specified\n");
		XFREE(MTYPE_TMP, regex_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!vty->candidate_config || !vty->candidate_config->dnode) {
		XFREE(MTYPE_TMP, regex_str);
		return CMD_SUCCESS;
	}

	snprintfrr(xpath_entry, sizeof(xpath_entry), "%s/entry[action='%s'][as-path='%s']", xpath,
		   action, regex_str);

	if (lyd_find_xpath(vty->candidate_config->dnode, xpath_entry, &set) != LY_SUCCESS ||
	    !set || set->count == 0) {
		/* No matching entry — match baseline's "not found" behavior:
		 * quiet no-op. The commit will be empty.
		 */
		ly_set_free(set, NULL);
		XFREE(MTYPE_TMP, regex_str);
		return CMD_SUCCESS;
	}

	/* Destroy each matching entry (typically just one). */
	for (uint32_t i = 0; i < set->count; i++) {
		char *entry_path = lyd_path(set->dnodes[i], LYD_PATH_STD, NULL, 0);

		if (!entry_path)
			continue;
		nb_cli_enqueue_change(vty, entry_path, NB_OP_DESTROY, NULL);
		free(entry_path);
	}
	ly_set_free(set, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, regex_str);
	return ret;
}

DEFPY_YANG(
	no_bgp_as_path_access_list_all_cli,
	no_bgp_as_path_access_list_all_cli_cmd,
	"no bgp as-path access-list AS_PATH_FILTER_NAME$name",
	NO_STR
	BGP_STR
	ASPATH_LIST_STR
	"Specify an access list name\n"
	"Regular expression access list name\n")
{
	char xpath[XPATH_MAXLEN + 64];

	snprintfrr(xpath, sizeof(xpath), "/frr-filter:lib/frr-bgp-filter:as-path-list[name='%s']",
		   name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void bgp_filter_cli_init(void)
{
	/* Community list commands */
	install_element(CONFIG_NODE, &bgp_community_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_standard_all_cli_cmd);
	install_element(CONFIG_NODE, &bgp_community_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_expanded_all_cli_cmd);

	/* Large community list commands */
	install_element(CONFIG_NODE, &bgp_lcommunity_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_standard_all_cli_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_expanded_all_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_name_all_cli_cmd);

	/* Extcommunity list commands */
	install_element(CONFIG_NODE, &bgp_extcommunity_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_standard_all_cli_cmd);
	install_element(CONFIG_NODE, &bgp_extcommunity_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_expanded_all_cli_cmd);

	/* AS-path access list commands */
	install_element(CONFIG_NODE, &bgp_as_path_access_list_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_as_path_access_list_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_as_path_access_list_all_cli_cmd);
}
