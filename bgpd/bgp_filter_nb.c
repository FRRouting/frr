// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Filter Northbound Implementation
 * Copyright (C) 2024 FRRouting
 *
 * Northbound callbacks for community-list, large-community-list,
 * extcommunity-list, and as-path-list defined in frr-bgp-filter.yang
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "log.h"
#include "lib/command.h"
#include "lib/filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_filter_nb.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_regex.h"
#include "frrstr.h"

/*
 * Join a leaf-list into the string community_list_set() expects.
 *
 * keyword is NULL for plain values ("A:B C:D"). For extcommunity it is
 * repeated on every value ("rt A:B soo C:D") so ecommunity_str2com() with
 * keyword_included set accepts more than one value and more than one type.
 * The buffer is sized from those values; expanded expressions are not joined
 * and are not copied.
 */
struct bgp_filter_join {
	size_t len;
	char *buf;
	char *p;
	const char *keyword;
	bool first;
};

static int bgp_filter_join_measure(const struct lyd_node *dnode, void *arg)
{
	struct bgp_filter_join *join = arg;
	const char *val = lyd_get_value(dnode);
	size_t add = strlen(val);

	if (!join->first)
		add++;
	if (join->keyword)
		add += strlen(join->keyword) + 1;
	join->len += add;
	join->first = false;
	return YANG_ITER_CONTINUE;
}

static int bgp_filter_join_copy(const struct lyd_node *dnode, void *arg)
{
	struct bgp_filter_join *join = arg;
	const char *val = lyd_get_value(dnode);
	size_t vlen = strlen(val);

	if (!join->first)
		*join->p++ = ' ';
	if (join->keyword) {
		size_t klen = strlen(join->keyword);

		memcpy(join->p, join->keyword, klen);
		join->p += klen;
		*join->p++ = ' ';
	}
	memcpy(join->p, val, vlen);
	join->p += vlen;
	join->first = false;
	return YANG_ITER_CONTINUE;
}

/* MTYPE_TMP string, or NULL when the leaf-list is absent. */
static char *bgp_filter_join_leaflist(const struct lyd_node *entry, const char *name,
				      const char *keyword)
{
	struct bgp_filter_join join = {
		.keyword = keyword,
		.first = true,
	};
	const struct lyd_node *child;

	LY_LIST_FOR (lyd_child(entry), child) {
		if (!child->schema || !strmatch(child->schema->name, name))
			continue;
		bgp_filter_join_measure(child, &join);
	}
	if (join.first)
		return NULL;

	join.buf = XMALLOC(MTYPE_TMP, join.len + 1);
	join.p = join.buf;
	join.first = true;
	LY_LIST_FOR (lyd_child(entry), child) {
		if (!child->schema || !strmatch(child->schema->name, name))
			continue;
		bgp_filter_join_copy(child, &join);
	}
	*join.p = '\0';
	return join.buf;
}

/*
 * Standard extcommunity types are one entry, not alternatives. Join every
 * list that is present so "rt A soo B" survives install and show running.
 * Order is rt, soo, nt, color; ecommunity_str2com() sorts the values.
 */
static const struct {
	const char *leaf;
	const char *keyword;
} bgp_extcommunity_parts[] = {
	{ "extcommunity-rt", "rt" },
	{ "extcommunity-soo", "soo" },
	{ "extcommunity-nt", "nt" },
	{ "extcommunity-color", "color" },
};

/* MTYPE_TMP string, or NULL when no standard extcommunity value is present. */
static char *bgp_filter_join_extcommunity(const struct lyd_node *entry)
{
	struct bgp_filter_join join = {
		.first = true,
	};
	const struct lyd_node *child;
	size_t i;
	bool any = false;

	for (i = 0; i < array_size(bgp_extcommunity_parts); i++) {
		join.keyword = bgp_extcommunity_parts[i].keyword;
		LY_LIST_FOR (lyd_child(entry), child) {
			if (!child->schema ||
			    !strmatch(child->schema->name, bgp_extcommunity_parts[i].leaf))
				continue;
			bgp_filter_join_measure(child, &join);
			any = true;
		}
	}
	if (!any)
		return NULL;

	join.buf = XMALLOC(MTYPE_TMP, join.len + 1);
	join.p = join.buf;
	join.first = true;
	for (i = 0; i < array_size(bgp_extcommunity_parts); i++) {
		join.keyword = bgp_extcommunity_parts[i].keyword;
		LY_LIST_FOR (lyd_child(entry), child) {
			if (!child->schema ||
			    !strmatch(child->schema->name, bgp_extcommunity_parts[i].leaf))
				continue;
			bgp_filter_join_copy(child, &join);
		}
	}
	*join.p = '\0';
	return join.buf;
}

/*
 * Community text for this entry.
 *
 * An expanded expression is the candidate string itself. A truncated copy
 * can compile to a different regex and, once written back, is what a restart
 * installs. Standard values are joined into *owned (MTYPE_TMP). *owned is
 * NULL when the caller must not free the returned pointer.
 */
static const char *bgp_filter_entry_text(const struct lyd_node *entry, int master, bool expanded,
					 char **owned)
{
	const char *leaf = NULL;

	*owned = NULL;

	if (expanded) {
		if (master == LARGE_COMMUNITY_LIST_MASTER) {
			if (!yang_dnode_exists(entry, "expanded-large-community-string"))
				return "";
			return yang_dnode_get_string(entry, "expanded-large-community-string");
		}
		if (master == EXTCOMMUNITY_LIST_MASTER) {
			if (!yang_dnode_exists(entry, "expanded-extcommunity-string"))
				return "";
			return yang_dnode_get_string(entry, "expanded-extcommunity-string");
		}
		if (!yang_dnode_exists(entry, "expanded-community-string"))
			return "";
		return yang_dnode_get_string(entry, "expanded-community-string");
	}

	if (master == COMMUNITY_LIST_MASTER)
		leaf = "standard-community-string";
	else if (master == LARGE_COMMUNITY_LIST_MASTER)
		leaf = "standard-large-community-string";
	else {
		*owned = bgp_filter_join_extcommunity(entry);
		return *owned ? *owned : "";
	}

	*owned = bgp_filter_join_leaflist(entry, leaf, NULL);
	return *owned ? *owned : "";
}

/* Shared helpers for community / large / extcommunity list cli_show. */
static void bgp_filter_cli_show_style_line(struct vty *vty, const char *kind, const char *name,
					   bool numbered, bool standard, uint32_t seq,
					   const char *action, const char *value)
{
	if (numbered)
		vty_out(vty, "bgp %s %s seq %u %s %s\n", kind, name, seq, action, value);
	else
		vty_out(vty, "bgp %s %s %s seq %u %s %s\n", kind,
			standard ? "standard" : "expanded", name, seq, action, value);
}

static void lib_community_list_entry_cli_show(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	const char *name;
	uint32_t seq;
	const char *action;
	const char *type_str;
	const char *comm_str;
	char *owned = NULL;
	bool standard;

	name = yang_dnode_get_string(dnode, "../name");
	seq = yang_dnode_get_uint32(dnode, "sequence");
	action = yang_dnode_get_string(dnode, "action");
	type_str = yang_dnode_get_string(dnode, "type");
	standard = strmatch(type_str, "community-list-standard");

	comm_str = bgp_filter_entry_text(dnode, COMMUNITY_LIST_MASTER, !standard, &owned);
	if (comm_str[0])
		bgp_filter_cli_show_style_line(vty, "community-list", name, all_digit(name),
					       standard, seq, action, comm_str);
	XFREE(MTYPE_TMP, owned);
}

static void lib_large_community_list_entry_cli_show(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	const char *name;
	uint32_t seq;
	const char *action;
	const char *type_str;
	const char *comm_str;
	char *owned = NULL;
	bool standard;

	name = yang_dnode_get_string(dnode, "../name");
	seq = yang_dnode_get_uint32(dnode, "sequence");
	action = yang_dnode_get_string(dnode, "action");
	type_str = yang_dnode_get_string(dnode, "type");
	standard = strstr(type_str, "standard") != NULL;

	comm_str = bgp_filter_entry_text(dnode, LARGE_COMMUNITY_LIST_MASTER, !standard, &owned);
	if (comm_str[0])
		bgp_filter_cli_show_style_line(vty, "large-community-list", name, all_digit(name),
					       standard, seq, action, comm_str);
	XFREE(MTYPE_TMP, owned);
}

static void lib_extcommunity_list_entry_cli_show(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	const char *name;
	uint32_t seq;
	const char *action;
	const char *type_str;
	const char *comm_str;
	char *owned = NULL;
	bool standard;

	name = yang_dnode_get_string(dnode, "../name");
	seq = yang_dnode_get_uint32(dnode, "sequence");
	action = yang_dnode_get_string(dnode, "action");
	type_str = yang_dnode_get_string(dnode, "type");
	standard = strstr(type_str, "standard") != NULL;

	comm_str = bgp_filter_entry_text(dnode, EXTCOMMUNITY_LIST_MASTER, !standard, &owned);
	if (comm_str[0])
		bgp_filter_cli_show_style_line(vty, "extcommunity-list", name, all_digit(name),
					       standard, seq, action, comm_str);
	XFREE(MTYPE_TMP, owned);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:community-list
 *
 * Community lists are created on-demand when entries are added,
 * so we just track the name here.
 */
int lib_community_list_create(struct nb_cb_create_args *args)
{
	/* Lists are created implicitly when entries are added */
	return NB_OK;
}

int lib_community_list_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");

	/* Delete all entries by calling unset with NULL str */
	community_list_unset(bgp_clist, name, NULL, NULL, 0, COMMUNITY_LIST_STANDARD);

	return NB_OK;
}

/*
 * Expressions and list style are checked before APPLY. NB_EV_APPLY cannot
 * reject a transaction, so a failure inside community_list_set() would leave
 * the candidate rule in the configuration without installing it.
 *
 * Style is compared against other candidate entries and against operational
 * entries that this commit keeps. Deletes are ignored: they run before the
 * install, so community_list_set() will not see them.
 */
struct bgp_filter_style_walk {
	const struct lyd_node *self;
	int master;
	int style;
	int other;
};

struct bgp_filter_seq_walk {
	uint32_t seq;
	bool found;
};

static bool bgp_filter_type_expanded(const char *type)
{
	return strmatch(type, "community-list-extended") ||
	       strmatch(type, "large-community-list-extended-id") ||
	       strmatch(type, "large-community-list-extended-name") ||
	       strmatch(type, "extcommunity-list-extended-id") ||
	       strmatch(type, "extcommunity-list-extended-name");
}

static int bgp_filter_type_style(int master, const char *type)
{
	bool expanded = bgp_filter_type_expanded(type);

	switch (master) {
	case LARGE_COMMUNITY_LIST_MASTER:
		return expanded ? LARGE_COMMUNITY_LIST_EXPANDED : LARGE_COMMUNITY_LIST_STANDARD;
	case EXTCOMMUNITY_LIST_MASTER:
		return expanded ? EXTCOMMUNITY_LIST_EXPANDED : EXTCOMMUNITY_LIST_STANDARD;
	default:
		return expanded ? COMMUNITY_LIST_EXPANDED : COMMUNITY_LIST_STANDARD;
	}
}

static bool bgp_filter_style_expanded(int style)
{
	return style == COMMUNITY_LIST_EXPANDED || style == LARGE_COMMUNITY_LIST_EXPANDED ||
	       style == EXTCOMMUNITY_LIST_EXPANDED;
}

static bool bgp_filter_style_standard(int style)
{
	return style == COMMUNITY_LIST_STANDARD || style == LARGE_COMMUNITY_LIST_STANDARD ||
	       style == EXTCOMMUNITY_LIST_STANDARD;
}

static void bgp_filter_style_errmsg(char *errmsg, size_t errmsg_len, int existing)
{
	if (bgp_filter_style_standard(existing))
		snprintfrr(errmsg, errmsg_len,
			   "Community name conflict, previously defined as standard community");
	else
		snprintfrr(errmsg, errmsg_len,
			   "Community name conflict, previously defined as expanded community");
}

static int bgp_filter_style_walk_cb(const struct lyd_node *dnode, void *arg)
{
	struct bgp_filter_style_walk *walk = arg;
	int style;

	if (dnode == walk->self || !yang_dnode_exists(dnode, "type"))
		return YANG_ITER_CONTINUE;

	style = bgp_filter_type_style(walk->master, yang_dnode_get_string(dnode, "type"));
	if (style != walk->style) {
		walk->other = style;
		return YANG_ITER_STOP;
	}
	return YANG_ITER_CONTINUE;
}

static int bgp_filter_seq_walk_cb(const struct lyd_node *dnode, void *arg)
{
	struct bgp_filter_seq_walk *walk = arg;

	if (yang_dnode_get_uint32(dnode, "sequence") == walk->seq) {
		walk->found = true;
		return YANG_ITER_STOP;
	}
	return YANG_ITER_CONTINUE;
}

static int bgp_filter_style_conflict(const struct lyd_node *entry, int master, int style,
				     char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *list = lyd_parent(entry);
	struct community_list *clist;
	struct community_entry *centry;
	struct bgp_filter_style_walk walk = {
		.self = entry,
		.master = master,
		.style = style,
		.other = -1,
	};
	const char *name;

	if (!list)
		return NB_OK;

	yang_dnode_iterate(bgp_filter_style_walk_cb, &walk, list, "entry");
	if (walk.other >= 0) {
		bgp_filter_style_errmsg(errmsg, errmsg_len, walk.other);
		return NB_ERR_VALIDATION;
	}

	name = yang_dnode_get_string(list, "name");
	clist = community_list_lookup(bgp_clist, name, 0, master);
	if (!clist)
		return NB_OK;

	for (centry = clist->head; centry; centry = centry->next) {
		struct bgp_filter_seq_walk seq = { .seq = (uint32_t)centry->seq };

		if (centry->seq < 0)
			continue;
		yang_dnode_iterate(bgp_filter_seq_walk_cb, &seq, list, "entry");
		if (!seq.found)
			continue;
		if (centry->style != style) {
			bgp_filter_style_errmsg(errmsg, errmsg_len, centry->style);
			return NB_ERR_VALIDATION;
		}
		/*
		 * community_list_set() compares against the first entry that
		 * will still be present when APPLY runs.
		 */
		break;
	}
	return NB_OK;
}

/*
 * Text community_list_set() or lcommunity_list_set() will compile.
 * Standard extcommunity values are checked on each rt/soo/nt/color leaf.
 */
static int bgp_filter_value_check(int master, int style, const char *value, char *errmsg,
				  size_t errmsg_len)
{
	if (!value || value[0] == '\0') {
		/*
		 * A standard extcommunity entry with no rt/soo/nt/color is
		 * left uninstalled on purpose; each of those leaves is
		 * validated on its own. Every other empty value fails in
		 * APPLY, which cannot roll the configuration back.
		 */
		if (master == EXTCOMMUNITY_LIST_MASTER && !bgp_filter_style_expanded(style))
			return NB_OK;
		snprintfrr(errmsg, errmsg_len, "Malformed community-list value");
		return NB_ERR_VALIDATION;
	}

	if (bgp_filter_style_expanded(style)) {
		struct frregex *regex;

		regex = bgp_regcomp(value);
		if (!regex) {
			snprintfrr(errmsg, errmsg_len, "Malformed community-list value");
			return NB_ERR_VALIDATION;
		}
		bgp_regex_free(regex);
		return NB_OK;
	}

	if (master == COMMUNITY_LIST_MASTER) {
		struct community *com;

		com = community_str2com(value);
		if (!com) {
			snprintfrr(errmsg, errmsg_len, "Malformed community-list value");
			return NB_ERR_VALIDATION;
		}
		community_free(&com);
		return NB_OK;
	}

	if (master == LARGE_COMMUNITY_LIST_MASTER) {
		struct lcommunity *lcom;

		lcom = lcommunity_str2com(value);
		if (!lcom) {
			snprintfrr(errmsg, errmsg_len, "Malformed community-list value");
			return NB_ERR_VALIDATION;
		}
		lcommunity_free(&lcom);
		return NB_OK;
	}

	return NB_OK;
}

static int bgp_filter_entry_validate(const struct lyd_node *entry, int master, char *errmsg,
				     size_t errmsg_len)
{
	int style;
	int ret;
	const char *value;
	char *owned = NULL;

	if (!entry || !yang_dnode_exists(entry, "type"))
		return NB_OK;

	style = bgp_filter_type_style(master, yang_dnode_get_string(entry, "type"));
	ret = bgp_filter_style_conflict(entry, master, style, errmsg, errmsg_len);
	if (ret != NB_OK)
		return ret;

	value = bgp_filter_entry_text(entry, master, bgp_filter_style_expanded(style), &owned);
	ret = bgp_filter_value_check(master, style, value, errmsg, errmsg_len);
	XFREE(MTYPE_TMP, owned);
	return ret;
}

/* Leaf callbacks receive the leaf. Walk up to the list entry. */
static const struct lyd_node *bgp_filter_entry_node(const struct lyd_node *dnode)
{
	const struct lyd_node *node;

	for (node = dnode; node; node = lyd_parent(node)) {
		if (node->schema && strmatch(node->schema->name, "entry"))
			return node;
	}
	return dnode;
}

static int bgp_filter_nb_validate(enum nb_event event, const struct lyd_node *dnode, int master,
				  char *errmsg, size_t errmsg_len)
{
	if (event != NB_EV_VALIDATE)
		return NB_OK;
	if (!dnode)
		return NB_OK;
	return bgp_filter_entry_validate(bgp_filter_entry_node(dnode), master, errmsg, errmsg_len);
}

static int bgp_as_path_entry_validate(const struct lyd_node *entry, char *errmsg, size_t errmsg_len)
{
	const char *expr;
	struct frregex *regex;

	if (!entry || !yang_dnode_exists(entry, "as-path")) {
		snprintfrr(errmsg, errmsg_len, "No AS-path regex specified");
		return NB_ERR_VALIDATION;
	}

	expr = yang_dnode_get_string(entry, "as-path");
	if (!config_bgp_aspath_validate(expr)) {
		snprintfrr(errmsg, errmsg_len, "Invalid character in as-path access-list %s", expr);
		return NB_ERR_VALIDATION;
	}

	regex = bgp_regcomp(expr);
	if (!regex) {
		snprintfrr(errmsg, errmsg_len, "can't compile regexp %s", expr);
		return NB_ERR_VALIDATION;
	}
	bgp_regex_free(regex);
	return NB_OK;
}

static int bgp_as_path_nb_validate(enum nb_event event, const struct lyd_node *dnode, char *errmsg,
				   size_t errmsg_len)
{
	if (event != NB_EV_VALIDATE)
		return NB_OK;
	if (!dnode)
		return NB_OK;
	return bgp_as_path_entry_validate(bgp_filter_entry_node(dnode), errmsg, errmsg_len);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:community-list/entry
 *
 * Install (or refresh) a community-list entry from the candidate dnode.
 * community_list_set() replaces an existing entry with the same sequence,
 * so a leaf edit rebuilds the running rule. Used from create APPLY and
 * apply_finish.
 */
static int lib_community_list_entry_install(const struct lyd_node *dnode)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *comm_str;
	char *owned = NULL;
	int direct;
	int style;
	int ret;

	/* Get parent list name */
	name = yang_dnode_get_string(dnode, "../name");

	/* Get sequence */
	seq_str = yang_dnode_get_string(dnode, "sequence");

	/* Get action (permit/deny) */
	action_str = yang_dnode_get_string(dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	style = bgp_filter_type_style(COMMUNITY_LIST_MASTER, yang_dnode_get_string(dnode, "type"));
	comm_str = bgp_filter_entry_text(dnode, COMMUNITY_LIST_MASTER,
					 bgp_filter_style_expanded(style), &owned);
	if (comm_str[0] == '\0') {
		zlog_warn("community-list %s: no community string specified", name);
		XFREE(MTYPE_TMP, owned);
		/* APPLY cannot reject the transaction. */
		return NB_OK;
	}

	ret = community_list_set(bgp_clist, name, comm_str, seq_str, direct, style);
	XFREE(MTYPE_TMP, owned);
	if (ret < 0) {
		zlog_warn("community-list %s: failed to set entry: %d", name, ret);
		return NB_OK;
	}

	return NB_OK;
}

int lib_community_list_entry_create(struct nb_cb_create_args *args)
{
	int ret;

	ret = bgp_filter_nb_validate(args->event, args->dnode, COMMUNITY_LIST_MASTER, args->errmsg,
				     args->errmsg_len);
	if (ret != NB_OK)
		return ret;
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return lib_community_list_entry_install(args->dnode);
}

static void lib_community_list_entry_apply_finish(struct nb_cb_apply_finish_args *args)
{
	lib_community_list_entry_install(args->dnode);
}

int lib_community_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *comm_str;
	char *owned = NULL;
	int direct;
	int style;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	style = bgp_filter_type_style(COMMUNITY_LIST_MASTER,
				      yang_dnode_get_string(args->dnode, "type"));
	comm_str = bgp_filter_entry_text(args->dnode, COMMUNITY_LIST_MASTER,
					 bgp_filter_style_expanded(style), &owned);
	community_list_unset(bgp_clist, name, comm_str[0] ? comm_str : NULL, seq_str, direct,
			     style);
	XFREE(MTYPE_TMP, owned);

	return NB_OK;
}

/*
 * Leaf callbacks for community-list/entry.
 * Leaf edits do not recreate the entry. apply_finish rebuilds it.
 */
int lib_community_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	/* Rebuilt by community-list entry apply_finish */
	return NB_OK;
}

int lib_community_list_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	/* Handled by entry destroy */
	return NB_OK;
}

int lib_community_list_entry_type_modify(struct nb_cb_modify_args *args)
{
	/* Leaf edits do not recreate the entry. Reject a bad style or expression here. */
	return bgp_filter_nb_validate(args->event, args->dnode, COMMUNITY_LIST_MASTER,
				      args->errmsg, args->errmsg_len);
}

int lib_community_list_entry_standard_community_string_create(struct nb_cb_create_args *args)
{
	return bgp_filter_nb_validate(args->event, args->dnode, COMMUNITY_LIST_MASTER,
				      args->errmsg, args->errmsg_len);
}

int lib_community_list_entry_standard_community_string_destroy(struct nb_cb_destroy_args *args)
{
	/* Handled by entry destroy */
	return NB_OK;
}

int lib_community_list_entry_expanded_community_string_modify(struct nb_cb_modify_args *args)
{
	return bgp_filter_nb_validate(args->event, args->dnode, COMMUNITY_LIST_MASTER,
				      args->errmsg, args->errmsg_len);
}

int lib_community_list_entry_expanded_community_string_destroy(struct nb_cb_destroy_args *args)
{
	/* Handled by entry destroy */
	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:large-community-list
 */
int lib_large_community_list_create(struct nb_cb_create_args *args)
{
	/* Lists are created implicitly when entries are added */
	return NB_OK;
}

int lib_large_community_list_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");

	/* Delete all entries */
	lcommunity_list_unset(bgp_clist, name, NULL, NULL, 0, LARGE_COMMUNITY_LIST_STANDARD);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:large-community-list/entry
 *
 * Same refresh path as community-list: lcommunity_list_set() replaces the
 * entry that already uses this sequence.
 */
static int lib_large_community_list_entry_install(const struct lyd_node *dnode)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *comm_str;
	char *owned = NULL;
	int direct;
	int style;
	int ret;

	name = yang_dnode_get_string(dnode, "../name");
	seq_str = yang_dnode_get_string(dnode, "sequence");

	action_str = yang_dnode_get_string(dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	style = bgp_filter_type_style(LARGE_COMMUNITY_LIST_MASTER,
				      yang_dnode_get_string(dnode, "type"));
	comm_str = bgp_filter_entry_text(dnode, LARGE_COMMUNITY_LIST_MASTER,
					 bgp_filter_style_expanded(style), &owned);
	if (comm_str[0] == '\0') {
		zlog_warn("large-community-list %s: no community string specified", name);
		XFREE(MTYPE_TMP, owned);
		/* APPLY cannot reject the transaction. */
		return NB_OK;
	}

	ret = lcommunity_list_set(bgp_clist, name, comm_str, seq_str, direct, style);
	XFREE(MTYPE_TMP, owned);
	if (ret < 0) {
		zlog_warn("large-community-list %s: failed to set entry: %d", name, ret);
		return NB_OK;
	}

	return NB_OK;
}

int lib_large_community_list_entry_create(struct nb_cb_create_args *args)
{
	int ret;

	ret = bgp_filter_nb_validate(args->event, args->dnode, LARGE_COMMUNITY_LIST_MASTER,
				     args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return lib_large_community_list_entry_install(args->dnode);
}

static void lib_large_community_list_entry_apply_finish(struct nb_cb_apply_finish_args *args)
{
	lib_large_community_list_entry_install(args->dnode);
}

int lib_large_community_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *comm_str;
	char *owned = NULL;
	int direct;
	int style;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	style = bgp_filter_type_style(LARGE_COMMUNITY_LIST_MASTER,
				      yang_dnode_get_string(args->dnode, "type"));
	comm_str = bgp_filter_entry_text(args->dnode, LARGE_COMMUNITY_LIST_MASTER,
					 bgp_filter_style_expanded(style), &owned);
	lcommunity_list_unset(bgp_clist, name, comm_str[0] ? comm_str : NULL, seq_str, direct,
			      style);
	XFREE(MTYPE_TMP, owned);

	return NB_OK;
}

/*
 * Leaf callbacks for large-community-list/entry.
 * Leaf edits do not recreate the entry. apply_finish rebuilds it.
 */
int lib_large_community_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	/* Rebuilt by large-community-list entry apply_finish */
	return NB_OK;
}

int lib_large_community_list_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_large_community_list_entry_type_modify(struct nb_cb_modify_args *args)
{
	return bgp_filter_nb_validate(args->event, args->dnode, LARGE_COMMUNITY_LIST_MASTER,
				      args->errmsg, args->errmsg_len);
}

int lib_large_community_list_entry_standard_large_community_string_create(
	struct nb_cb_create_args *args)
{
	return bgp_filter_nb_validate(args->event, args->dnode, LARGE_COMMUNITY_LIST_MASTER,
				      args->errmsg, args->errmsg_len);
}

int lib_large_community_list_entry_standard_large_community_string_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_large_community_list_entry_expanded_large_community_string_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_filter_nb_validate(args->event, args->dnode, LARGE_COMMUNITY_LIST_MASTER,
				      args->errmsg, args->errmsg_len);
}

int lib_large_community_list_entry_expanded_large_community_string_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:extcommunity-list
 */
int lib_extcommunity_list_create(struct nb_cb_create_args *args)
{
	/* Lists are created implicitly when entries are added */
	return NB_OK;
}

int lib_extcommunity_list_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");

	/* Delete all entries */
	extcommunity_list_unset(bgp_clist, name, NULL, NULL, 0, EXTCOMMUNITY_LIST_STANDARD);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:extcommunity-list/entry
 */
/*
 * Install (or refresh) an extcommunity-list entry from the full candidate
 * dnode. Used from create APPLY and apply_finish so RT/SOO leaflist children
 * are present even when their create callbacks are no-ops.
 */
static int lib_extcommunity_list_entry_install(const struct lyd_node *dnode)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *comm_str;
	char *owned = NULL;
	int direct;
	int style;
	int ret;

	name = yang_dnode_get_string(dnode, "../name");
	seq_str = yang_dnode_get_string(dnode, "sequence");

	action_str = yang_dnode_get_string(dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	style = bgp_filter_type_style(EXTCOMMUNITY_LIST_MASTER,
				      yang_dnode_get_string(dnode, "type"));
	comm_str = bgp_filter_entry_text(dnode, EXTCOMMUNITY_LIST_MASTER,
					 bgp_filter_style_expanded(style), &owned);
	if (comm_str[0] == '\0') {
		XFREE(MTYPE_TMP, owned);
		return NB_OK;
	}

	ret = extcommunity_list_set(bgp_clist, name, comm_str, seq_str, direct, style);
	XFREE(MTYPE_TMP, owned);
	if (ret < 0) {
		zlog_warn("extcommunity-list %s: failed to set entry: %d", name, ret);
		/* APPLY cannot reject the transaction. */
		return NB_OK;
	}

	return NB_OK;
}

int lib_extcommunity_list_entry_create(struct nb_cb_create_args *args)
{
	int ret;

	ret = bgp_filter_nb_validate(args->event, args->dnode, EXTCOMMUNITY_LIST_MASTER,
				     args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return lib_extcommunity_list_entry_install(args->dnode);
}

static void lib_extcommunity_list_entry_apply_finish(struct nb_cb_apply_finish_args *args)
{
	lib_extcommunity_list_entry_install(args->dnode);
}

int lib_extcommunity_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *comm_str;
	char *owned = NULL;
	int direct;
	int style;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	direct = (strcmp(action_str, "permit") == 0) ? COMMUNITY_PERMIT : COMMUNITY_DENY;

	style = bgp_filter_type_style(EXTCOMMUNITY_LIST_MASTER,
				      yang_dnode_get_string(args->dnode, "type"));
	comm_str = bgp_filter_entry_text(args->dnode, EXTCOMMUNITY_LIST_MASTER,
					 bgp_filter_style_expanded(style), &owned);
	extcommunity_list_unset(bgp_clist, name, comm_str[0] ? comm_str : NULL, seq_str, direct,
				style);
	XFREE(MTYPE_TMP, owned);

	return NB_OK;
}

/*
 * Leaf callbacks for extcommunity-list/entry
 *
 * rt, soo, nt, and color are plain strings. The CLI accepts any word, and
 * the route-target pattern would reject a word with no colon before this
 * callback could see it. ecommunity_str2com() is what accepts or rejects
 * the word, as the classic extcommunity-list parser did.
 */
static int lib_extcommunity_list_value_validate(struct nb_cb_create_args *args, int sub_type)
{
	struct ecommunity *ecom;

	if (args->event != NB_EV_VALIDATE)
		return NB_OK;

	ecom = ecommunity_str2com(yang_dnode_get_string(args->dnode, NULL), sub_type, 0);
	if (!ecom) {
		snprintfrr(args->errmsg, args->errmsg_len, "Malformed community-list value");
		return NB_ERR_VALIDATION;
	}
	ecommunity_free(&ecom);
	return NB_OK;
}

int lib_extcommunity_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_type_modify(struct nb_cb_modify_args *args)
{
	return bgp_filter_nb_validate(args->event, args->dnode, EXTCOMMUNITY_LIST_MASTER,
				      args->errmsg, args->errmsg_len);
}

int lib_extcommunity_list_entry_rt_create(struct nb_cb_create_args *args)
{
	return lib_extcommunity_list_value_validate(args, ECOMMUNITY_ROUTE_TARGET);
}

int lib_extcommunity_list_entry_rt_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_soo_create(struct nb_cb_create_args *args)
{
	return lib_extcommunity_list_value_validate(args, ECOMMUNITY_SITE_ORIGIN);
}

int lib_extcommunity_list_entry_soo_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_nt_create(struct nb_cb_create_args *args)
{
	return lib_extcommunity_list_value_validate(args, ECOMMUNITY_NODE_TARGET);
}

int lib_extcommunity_list_entry_nt_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_color_create(struct nb_cb_create_args *args)
{
	return lib_extcommunity_list_value_validate(args, ECOMMUNITY_COLOR);
}

int lib_extcommunity_list_entry_color_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_extcommunity_list_entry_expanded_extcommunity_string_modify(struct nb_cb_modify_args *args)
{
	return bgp_filter_nb_validate(args->event, args->dnode, EXTCOMMUNITY_LIST_MASTER,
				      args->errmsg, args->errmsg_len);
}

int lib_extcommunity_list_entry_expanded_extcommunity_string_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:as-path-list
 *
 * AS-path access lists use a different API in bgp_filter.c
 * For now, provide stub implementations that will be enhanced later
 */
int lib_as_path_list_create(struct nb_cb_create_args *args)
{
	/* Lists are created implicitly when entries are added */
	return NB_OK;
}

int lib_as_path_list_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	as_list_delete_by_name(name);

	return NB_OK;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:as-path-list/entry
 */
int lib_as_path_list_entry_create(struct nb_cb_create_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *aspath_regex;
	enum as_filter_type type;
	int ret;

	ret = bgp_as_path_nb_validate(args->event, args->dnode, args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Get parent list name */
	name = yang_dnode_get_string(args->dnode, "../name");

	/* Get sequence */
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	/* Get action (permit/deny) */
	action_str = yang_dnode_get_string(args->dnode, "action");
	type = (strcmp(action_str, "permit") == 0) ? AS_FILTER_PERMIT : AS_FILTER_DENY;

	/* Get as-path regex */
	aspath_regex = yang_dnode_get_string(args->dnode, "as-path");

	ret = as_list_entry_set(name, seq_str, aspath_regex, type);
	if (ret < 0) {
		zlog_warn("as-path-list %s: failed to set entry with regex '%s'", name,
			  aspath_regex);
		/* APPLY cannot reject the transaction. */
		return NB_OK;
	}

	return NB_OK;
}

int lib_as_path_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *aspath_regex;
	enum as_filter_type type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "../name");
	seq_str = yang_dnode_get_string(args->dnode, "sequence");

	action_str = yang_dnode_get_string(args->dnode, "action");
	type = (strcmp(action_str, "permit") == 0) ? AS_FILTER_PERMIT : AS_FILTER_DENY;

	aspath_regex = yang_dnode_get_string(args->dnode, "as-path");

	as_list_entry_unset(name, seq_str, aspath_regex, type);

	return NB_OK;
}

/*
 * Leaf callbacks for as-path-list/entry
 *
 * When a leaf value is modified on an existing entry, we need to
 * update the as-path-list. We do this by calling as_list_entry_set()
 * which handles both creation and replacement of entries.
 */
int lib_as_path_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *aspath_regex;
	enum as_filter_type type;
	int ret;

	ret = bgp_as_path_nb_validate(args->event, args->dnode, args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Get parent list name - go up to entry, then to as-path-list */
	name = yang_dnode_get_string(args->dnode, "../../name");
	seq_str = yang_dnode_get_string(args->dnode, "../sequence");
	action_str = yang_dnode_get_string(args->dnode, NULL);
	type = (strcmp(action_str, "permit") == 0) ? AS_FILTER_PERMIT : AS_FILTER_DENY;
	aspath_regex = yang_dnode_get_string(args->dnode, "../as-path");

	ret = as_list_entry_set(name, seq_str, aspath_regex, type);
	if (ret < 0) {
		zlog_warn("as-path-list %s: failed to update entry action", name);
		/* APPLY cannot reject the transaction. */
		return NB_OK;
	}

	return NB_OK;
}

int lib_as_path_list_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int lib_as_path_list_entry_as_path_modify(struct nb_cb_modify_args *args)
{
	const char *name;
	const char *seq_str;
	const char *action_str;
	const char *aspath_regex;
	enum as_filter_type type;
	int ret;

	ret = bgp_as_path_nb_validate(args->event, args->dnode, args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Get parent list name - go up to entry, then to as-path-list */
	name = yang_dnode_get_string(args->dnode, "../../name");
	seq_str = yang_dnode_get_string(args->dnode, "../sequence");
	action_str = yang_dnode_get_string(args->dnode, "../action");
	type = (strcmp(action_str, "permit") == 0) ? AS_FILTER_PERMIT : AS_FILTER_DENY;
	aspath_regex = yang_dnode_get_string(args->dnode, NULL);

	ret = as_list_entry_set(name, seq_str, aspath_regex, type);
	if (ret < 0) {
		zlog_warn("as-path-list %s: failed to update entry as-path", name);
		/* APPLY cannot reject the transaction. */
		return NB_OK;
	}

	return NB_OK;
}

int lib_as_path_list_entry_as_path_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

static void lib_as_path_list_entry_cli_show(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	const char *name;
	uint32_t seq;
	const char *action;
	const char *aspath;

	name = yang_dnode_get_string(dnode, "../name");
	seq = yang_dnode_get_uint32(dnode, "sequence");
	action = yang_dnode_get_string(dnode, "action");
	aspath = yang_dnode_get_string(dnode, "as-path");

	vty_out(vty, "bgp as-path access-list %s seq %u %s %s\n", name, seq, action, aspath);
}

/* ========================================================================
 * Operational State Callbacks for RESTCONF GET
 * ========================================================================
 */

/*
 * Helper: Iterate through both numbered and string community lists
 */
struct clist_iter {
	struct community_list *current;
	bool in_str_list; /* false = still in num list, true = in str list */
	int master_type;  /* COMMUNITY_LIST_MASTER, etc. */
};

static struct community_list *clist_iter_first(int master_type, struct clist_iter *iter)
{
	struct community_list_master *cm;

	iter->master_type = master_type;
	cm = community_list_master_lookup(bgp_clist, master_type);
	if (!cm)
		return NULL;

	/* Try numbered list first */
	iter->in_str_list = false;
	if (cm->num.head) {
		iter->current = cm->num.head;
		return iter->current;
	}

	/* Fall back to string list */
	iter->in_str_list = true;
	iter->current = cm->str.head;
	return iter->current;
}

static struct community_list *clist_iter_next(struct clist_iter *iter)
{
	struct community_list_master *cm;

	if (!iter->current)
		return NULL;

	/* Move to next in current list */
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter->current;
	}

	/* If in numbered list, try string list */
	if (!iter->in_str_list) {
		cm = community_list_master_lookup(bgp_clist, iter->master_type);
		if (cm && cm->str.head) {
			iter->in_str_list = true;
			iter->current = cm->str.head;
			return iter->current;
		}
	}

	/* No more entries */
	iter->current = NULL;
	return NULL;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:community-list
 * Operational state callbacks
 */
static const void *lib_community_list_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *iter;
	struct community_list *clist;

	if (args->list_entry == NULL) {
		/* First call - allocate iterator */
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		clist = clist_iter_first(COMMUNITY_LIST_MASTER, iter);
		if (!clist) {
			XFREE(MTYPE_TMP, iter);
			return NULL;
		}
		/* Store iterator in opaque pointer - we'll retrieve it via list_entry */
		return iter;
	}

	iter = (struct clist_iter *)args->list_entry;
	clist = clist_iter_next(iter);
	if (!clist) {
		XFREE(MTYPE_TMP, iter);
		return NULL;
	}
	return iter;
}

static int lib_community_list_get_keys(struct nb_cb_get_keys_args *args)
{
	struct clist_iter *iter = (struct clist_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], iter->current->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_community_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct community_list *clist;
	struct clist_iter *iter;

	clist = community_list_lookup(bgp_clist, name, 0, COMMUNITY_LIST_MASTER);
	if (!clist)
		return NULL;

	/* Allocate iterator and set current */
	iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
	iter->current = clist;
	iter->master_type = COMMUNITY_LIST_MASTER;
	iter->in_str_list = true; /* Doesn't matter for lookup */
	return iter;
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:community-list/entry
 */
struct centry_iter {
	struct community_list *parent;
	struct community_entry *current;
};

static const void *lib_community_list_entry_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *parent_iter;
	struct centry_iter *iter;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	if (args->list_entry == NULL) {
		/* First call */
		if (!parent_iter->current->head)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->parent = parent_iter->current;
		iter->current = parent_iter->current->head;
		return iter;
	}

	iter = (struct centry_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_community_list_entry_get_keys(struct nb_cb_get_keys_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	char seq_buf[32];

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	snprintfrr(seq_buf, sizeof(seq_buf), "%ld", (long)iter->current->seq);
	strlcpy(args->keys->key[0], seq_buf, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_community_list_entry_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct clist_iter *parent_iter;
	struct community_entry *entry;
	struct centry_iter *iter;
	int64_t seq;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	seq = strtoll(args->keys->key[0], NULL, 10);

	for (entry = parent_iter->current->head; entry; entry = entry->next) {
		if (entry->seq == seq) {
			iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
			iter->parent = parent_iter->current;
			iter->current = entry;
			return iter;
		}
	}
	return NULL;
}

/*
 * Leaf get_elem callbacks for community-list/entry
 */
static __attribute__((unused)) struct yang_data *
lib_community_list_entry_sequence_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)iter->current->seq);
}

static __attribute__((unused)) struct yang_data *
lib_community_list_entry_action_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* list-action enum: deny=0, permit=1 */
	return yang_data_new_enum(args->xpath, iter->current->direct == COMMUNITY_PERMIT ? 1 : 0);
}

static __attribute__((unused)) struct yang_data *
lib_community_list_entry_type_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* community-list type enum: standard=0, extended=1 */
	return yang_data_new_enum(args->xpath,
				  iter->current->style == COMMUNITY_LIST_STANDARD ? 0 : 1);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:large-community-list
 */
static const void *lib_large_community_list_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *iter;
	struct community_list *clist;

	if (args->list_entry == NULL) {
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		clist = clist_iter_first(LARGE_COMMUNITY_LIST_MASTER, iter);
		if (!clist) {
			XFREE(MTYPE_TMP, iter);
			return NULL;
		}
		return iter;
	}

	iter = (struct clist_iter *)args->list_entry;
	clist = clist_iter_next(iter);
	if (!clist) {
		XFREE(MTYPE_TMP, iter);
		return NULL;
	}
	return iter;
}

static int lib_large_community_list_get_keys(struct nb_cb_get_keys_args *args)
{
	struct clist_iter *iter = (struct clist_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], iter->current->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_large_community_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct community_list *clist;
	struct clist_iter *iter;

	clist = community_list_lookup(bgp_clist, name, 0, LARGE_COMMUNITY_LIST_MASTER);
	if (!clist)
		return NULL;

	iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
	iter->current = clist;
	iter->master_type = LARGE_COMMUNITY_LIST_MASTER;
	iter->in_str_list = true;
	return iter;
}

/*
 * Large community list entry callbacks - reuse centry_iter structure
 */
static const void *lib_large_community_list_entry_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *parent_iter;
	struct centry_iter *iter;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	if (args->list_entry == NULL) {
		if (!parent_iter->current->head)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->parent = parent_iter->current;
		iter->current = parent_iter->current->head;
		return iter;
	}

	iter = (struct centry_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_large_community_list_entry_get_keys(struct nb_cb_get_keys_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	char seq_buf[32];

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	snprintfrr(seq_buf, sizeof(seq_buf), "%ld", (long)iter->current->seq);
	strlcpy(args->keys->key[0], seq_buf, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_large_community_list_entry_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct clist_iter *parent_iter;
	struct community_entry *entry;
	struct centry_iter *iter;
	int64_t seq;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	seq = strtoll(args->keys->key[0], NULL, 10);

	for (entry = parent_iter->current->head; entry; entry = entry->next) {
		if (entry->seq == seq) {
			iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
			iter->parent = parent_iter->current;
			iter->current = entry;
			return iter;
		}
	}
	return NULL;
}

static __attribute__((unused)) struct yang_data *
lib_large_community_list_entry_sequence_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)iter->current->seq);
}

static __attribute__((unused)) struct yang_data *
lib_large_community_list_entry_action_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* list-action enum: deny=0, permit=1 */
	return yang_data_new_enum(args->xpath, iter->current->direct == COMMUNITY_PERMIT ? 1 : 0);
}

static __attribute__((unused)) struct yang_data *
lib_large_community_list_entry_type_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	int type_val;

	if (!iter || !iter->current)
		return NULL;

	/* large-community-list type: standard-id=0, extended-id=1, standard-name=2, extended-name=3 */
	switch (iter->current->style) {
	case LARGE_COMMUNITY_LIST_STANDARD:
		type_val = 2; /* standard-name */
		break;
	case LARGE_COMMUNITY_LIST_EXPANDED:
	default:
		type_val = 3; /* extended-name */
		break;
	}
	return yang_data_new_enum(args->xpath, type_val);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:extcommunity-list
 */
static const void *lib_extcommunity_list_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *iter;
	struct community_list *clist;

	if (args->list_entry == NULL) {
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		clist = clist_iter_first(EXTCOMMUNITY_LIST_MASTER, iter);
		if (!clist) {
			XFREE(MTYPE_TMP, iter);
			return NULL;
		}
		return iter;
	}

	iter = (struct clist_iter *)args->list_entry;
	clist = clist_iter_next(iter);
	if (!clist) {
		XFREE(MTYPE_TMP, iter);
		return NULL;
	}
	return iter;
}

static int lib_extcommunity_list_get_keys(struct nb_cb_get_keys_args *args)
{
	struct clist_iter *iter = (struct clist_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], iter->current->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_extcommunity_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct community_list *clist;
	struct clist_iter *iter;

	clist = community_list_lookup(bgp_clist, name, 0, EXTCOMMUNITY_LIST_MASTER);
	if (!clist)
		return NULL;

	iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
	iter->current = clist;
	iter->master_type = EXTCOMMUNITY_LIST_MASTER;
	iter->in_str_list = true;
	return iter;
}

/*
 * Extcommunity list entry callbacks
 */
static const void *lib_extcommunity_list_entry_get_next(struct nb_cb_get_next_args *args)
{
	struct clist_iter *parent_iter;
	struct centry_iter *iter;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	if (args->list_entry == NULL) {
		if (!parent_iter->current->head)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->parent = parent_iter->current;
		iter->current = parent_iter->current->head;
		return iter;
	}

	iter = (struct centry_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_extcommunity_list_entry_get_keys(struct nb_cb_get_keys_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	char seq_buf[32];

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	snprintfrr(seq_buf, sizeof(seq_buf), "%ld", (long)iter->current->seq);
	strlcpy(args->keys->key[0], seq_buf, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_extcommunity_list_entry_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct clist_iter *parent_iter;
	struct community_entry *entry;
	struct centry_iter *iter;
	int64_t seq;

	parent_iter = (struct clist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	seq = strtoll(args->keys->key[0], NULL, 10);

	for (entry = parent_iter->current->head; entry; entry = entry->next) {
		if (entry->seq == seq) {
			iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
			iter->parent = parent_iter->current;
			iter->current = entry;
			return iter;
		}
	}
	return NULL;
}

static __attribute__((unused)) struct yang_data *
lib_extcommunity_list_entry_sequence_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)iter->current->seq);
}

static __attribute__((unused)) struct yang_data *
lib_extcommunity_list_entry_action_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* list-action enum: deny=0, permit=1 */
	return yang_data_new_enum(args->xpath, iter->current->direct == COMMUNITY_PERMIT ? 1 : 0);
}

static __attribute__((unused)) struct yang_data *
lib_extcommunity_list_entry_type_get_elem(struct nb_cb_get_elem_args *args)
{
	struct centry_iter *iter = (struct centry_iter *)args->list_entry;
	int type_val;

	if (!iter || !iter->current)
		return NULL;

	/* extcommunity-list type: standard-id=0, extended-id=1, standard-name=2, extended-name=3 */
	switch (iter->current->style) {
	case EXTCOMMUNITY_LIST_STANDARD:
		type_val = 2; /* standard-name */
		break;
	case EXTCOMMUNITY_LIST_EXPANDED:
	default:
		type_val = 3; /* extended-name */
		break;
	}
	return yang_data_new_enum(args->xpath, type_val);
}

/*
 * XPath: /frr-filter:lib/frr-bgp-filter:as-path-list
 */
struct aslist_iter {
	struct as_list *current;
};

static const void *lib_as_path_list_get_next(struct nb_cb_get_next_args *args)
{
	struct aslist_iter *iter;
	struct as_list *aslist;

	if (args->list_entry == NULL) {
		aslist = as_list_first();
		if (!aslist)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->current = aslist;
		return iter;
	}

	iter = (struct aslist_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_as_path_list_get_keys(struct nb_cb_get_keys_args *args)
{
	struct aslist_iter *iter = (struct aslist_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], iter->current->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_as_path_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *name = args->keys->key[0];
	struct as_list *aslist;
	struct aslist_iter *iter;

	aslist = as_list_lookup(name);
	if (!aslist)
		return NULL;

	iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
	iter->current = aslist;
	return iter;
}

/*
 * AS-path list entry callbacks
 */
struct asfilter_iter {
	struct as_list *parent;
	struct as_filter *current;
};

static const void *lib_as_path_list_entry_get_next(struct nb_cb_get_next_args *args)
{
	struct aslist_iter *parent_iter;
	struct asfilter_iter *iter;

	parent_iter = (struct aslist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	if (args->list_entry == NULL) {
		if (!parent_iter->current->head)
			return NULL;
		iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
		iter->parent = parent_iter->current;
		iter->current = parent_iter->current->head;
		return iter;
	}

	iter = (struct asfilter_iter *)args->list_entry;
	if (iter->current->next) {
		iter->current = iter->current->next;
		return iter;
	}

	XFREE(MTYPE_TMP, iter);
	return NULL;
}

static int lib_as_path_list_entry_get_keys(struct nb_cb_get_keys_args *args)
{
	struct asfilter_iter *iter = (struct asfilter_iter *)args->list_entry;
	char seq_buf[32];

	if (!iter || !iter->current)
		return NB_ERR;

	args->keys->num = 1;
	snprintfrr(seq_buf, sizeof(seq_buf), "%ld", (long)iter->current->seq);
	strlcpy(args->keys->key[0], seq_buf, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_as_path_list_entry_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct aslist_iter *parent_iter;
	struct as_filter *filter;
	struct asfilter_iter *iter;
	int64_t seq;

	parent_iter = (struct aslist_iter *)args->parent_list_entry;
	if (!parent_iter || !parent_iter->current)
		return NULL;

	seq = strtoll(args->keys->key[0], NULL, 10);

	for (filter = parent_iter->current->head; filter; filter = filter->next) {
		if (filter->seq == seq) {
			iter = XCALLOC(MTYPE_TMP, sizeof(*iter));
			iter->parent = parent_iter->current;
			iter->current = filter;
			return iter;
		}
	}
	return NULL;
}

static __attribute__((unused)) struct yang_data *
lib_as_path_list_entry_sequence_get_elem(struct nb_cb_get_elem_args *args)
{
	struct asfilter_iter *iter = (struct asfilter_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	return yang_data_new_uint32(args->xpath, (uint32_t)iter->current->seq);
}

static __attribute__((unused)) struct yang_data *
lib_as_path_list_entry_action_get_elem(struct nb_cb_get_elem_args *args)
{
	struct asfilter_iter *iter = (struct asfilter_iter *)args->list_entry;

	if (!iter || !iter->current)
		return NULL;

	/* list-action enum: deny=0, permit=1 */
	return yang_data_new_enum(args->xpath, iter->current->type == AS_FILTER_PERMIT ? 1 : 0);
}

static __attribute__((unused)) struct yang_data *
lib_as_path_list_entry_as_path_get_elem(struct nb_cb_get_elem_args *args)
{
	struct asfilter_iter *iter = (struct asfilter_iter *)args->list_entry;

	if (!iter || !iter->current || !iter->current->reg_str)
		return NULL;

	return yang_data_new_string(args->xpath, iter->current->reg_str);
}

/* clang-format off */
const struct frr_yang_module_info frr_bgp_filter_info = {
	.name = "frr-bgp-filter",
	.nodes = {
		/* community-list */
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list",
			.cbs = {
				.create = lib_community_list_create,
				.destroy = lib_community_list_destroy,
				.get_next = lib_community_list_get_next,
				.get_keys = lib_community_list_get_keys,
				.lookup_entry = lib_community_list_lookup_entry,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry",
			.cbs = {
				.create = lib_community_list_entry_create,
				.destroy = lib_community_list_entry_destroy,
				.get_next = lib_community_list_entry_get_next,
				.get_keys = lib_community_list_entry_get_keys,
				.lookup_entry = lib_community_list_entry_lookup_entry,
				.cli_show = lib_community_list_entry_cli_show,
				.apply_finish = lib_community_list_entry_apply_finish,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry/action",
			.cbs = {
				.modify = lib_community_list_entry_action_modify,
				.destroy = lib_community_list_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry/type",
			.cbs = {
				.modify = lib_community_list_entry_type_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry/standard-community-string",
			.cbs = {
				.create = lib_community_list_entry_standard_community_string_create,
				.destroy = lib_community_list_entry_standard_community_string_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:community-list/entry/expanded-community-string",
			.cbs = {
				.modify = lib_community_list_entry_expanded_community_string_modify,
				.destroy = lib_community_list_entry_expanded_community_string_destroy,
			}
		},
		/* large-community-list */
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list",
			.cbs = {
				.create = lib_large_community_list_create,
				.destroy = lib_large_community_list_destroy,
				.get_next = lib_large_community_list_get_next,
				.get_keys = lib_large_community_list_get_keys,
				.lookup_entry = lib_large_community_list_lookup_entry,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry",
			.cbs = {
				.create = lib_large_community_list_entry_create,
				.destroy = lib_large_community_list_entry_destroy,
				.get_next = lib_large_community_list_entry_get_next,
				.get_keys = lib_large_community_list_entry_get_keys,
				.lookup_entry = lib_large_community_list_entry_lookup_entry,
				.cli_show = lib_large_community_list_entry_cli_show,
				.apply_finish = lib_large_community_list_entry_apply_finish,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry/action",
			.cbs = {
				.modify = lib_large_community_list_entry_action_modify,
				.destroy = lib_large_community_list_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry/type",
			.cbs = {
				.modify = lib_large_community_list_entry_type_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry/standard-large-community-string",
			.cbs = {
				.create = lib_large_community_list_entry_standard_large_community_string_create,
				.destroy = lib_large_community_list_entry_standard_large_community_string_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:large-community-list/entry/expanded-large-community-string",
			.cbs = {
				.modify = lib_large_community_list_entry_expanded_large_community_string_modify,
				.destroy = lib_large_community_list_entry_expanded_large_community_string_destroy,
			}
		},
		/* extcommunity-list */
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list",
			.cbs = {
				.create = lib_extcommunity_list_create,
				.destroy = lib_extcommunity_list_destroy,
				.get_next = lib_extcommunity_list_get_next,
				.get_keys = lib_extcommunity_list_get_keys,
				.lookup_entry = lib_extcommunity_list_lookup_entry,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry",
			.cbs = {
				.create = lib_extcommunity_list_entry_create,
				.destroy = lib_extcommunity_list_entry_destroy,
				.get_next = lib_extcommunity_list_entry_get_next,
				.get_keys = lib_extcommunity_list_entry_get_keys,
				.lookup_entry = lib_extcommunity_list_entry_lookup_entry,
				.cli_show = lib_extcommunity_list_entry_cli_show,
				.apply_finish = lib_extcommunity_list_entry_apply_finish,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/action",
			.cbs = {
				.modify = lib_extcommunity_list_entry_action_modify,
				.destroy = lib_extcommunity_list_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/type",
			.cbs = {
				.modify = lib_extcommunity_list_entry_type_modify,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/extcommunity-rt",
			.cbs = {
				.create = lib_extcommunity_list_entry_rt_create,
				.destroy = lib_extcommunity_list_entry_rt_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/extcommunity-soo",
			.cbs = {
				.create = lib_extcommunity_list_entry_soo_create,
				.destroy = lib_extcommunity_list_entry_soo_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/extcommunity-nt",
			.cbs = {
				.create = lib_extcommunity_list_entry_nt_create,
				.destroy = lib_extcommunity_list_entry_nt_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/extcommunity-color",
			.cbs = {
				.create = lib_extcommunity_list_entry_color_create,
				.destroy = lib_extcommunity_list_entry_color_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:extcommunity-list/entry/expanded-extcommunity-string",
			.cbs = {
				.modify = lib_extcommunity_list_entry_expanded_extcommunity_string_modify,
				.destroy = lib_extcommunity_list_entry_expanded_extcommunity_string_destroy,
			}
		},
		/* as-path-list */
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:as-path-list",
			.cbs = {
				.create = lib_as_path_list_create,
				.destroy = lib_as_path_list_destroy,
				.get_next = lib_as_path_list_get_next,
				.get_keys = lib_as_path_list_get_keys,
				.lookup_entry = lib_as_path_list_lookup_entry,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:as-path-list/entry",
			.cbs = {
				.create = lib_as_path_list_entry_create,
				.destroy = lib_as_path_list_entry_destroy,
				.get_next = lib_as_path_list_entry_get_next,
				.get_keys = lib_as_path_list_entry_get_keys,
				.lookup_entry = lib_as_path_list_entry_lookup_entry,
				.cli_show = lib_as_path_list_entry_cli_show,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:as-path-list/entry/action",
			.cbs = {
				.modify = lib_as_path_list_entry_action_modify,
				.destroy = lib_as_path_list_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-filter:lib/frr-bgp-filter:as-path-list/entry/as-path",
			.cbs = {
				.modify = lib_as_path_list_entry_as_path_modify,
				.destroy = lib_as_path_list_entry_as_path_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */
