// SPDX-License-Identifier: GPL-2.0-or-later
/* AS path filter list.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "command.h"
#include "log.h"
#include "memory.h"
#include "buffer.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"

/* List of AS filter list. */
struct as_list_list {
	struct as_list *head;
	struct as_list *tail;
};

/* AS path filter master. */
struct as_list_master {
	/* List of access_list which name is string. */
	struct as_list_list str;

	/* Hook function which is executed when new access_list is added. */
	void (*add_hook)(char *);

	/* Hook function which is executed when access_list is deleted. */
	void (*delete_hook)(const char *);
};



/* Calculate new sequential number. */
static int64_t bgp_alist_new_seq_get(struct as_list *list)
{
	int64_t maxseq;
	int64_t newseq;
	struct as_filter *entry;

	maxseq = 0;

	for (entry = list->head; entry; entry = entry->next) {
		if (maxseq < entry->seq)
			maxseq = entry->seq;
	}

	newseq = ((maxseq / 5) * 5) + 5;

	return (newseq > UINT_MAX) ? UINT_MAX : newseq;
}

/* Return as-list entry which has same seq number. */
static struct as_filter *bgp_aslist_seq_check(struct as_list *list, int64_t seq)
{
	struct as_filter *entry;

	for (entry = list->head; entry; entry = entry->next)
		if (entry->seq == seq)
			return entry;

	return NULL;
}

/* as-path access-list 10 permit AS1. */

static struct as_list_master as_list_master = {{NULL, NULL},
					       NULL,
					       NULL};

/* Allocate new AS filter. */
static struct as_filter *as_filter_new(void)
{
	return XCALLOC(MTYPE_AS_FILTER, sizeof(struct as_filter));
}

/* Free allocated AS filter. */
static void as_filter_free(struct as_filter *asfilter)
{
	if (asfilter->reg)
		bgp_regex_free(asfilter->reg);
	XFREE(MTYPE_AS_FILTER_STR, asfilter->reg_str);
	XFREE(MTYPE_AS_FILTER, asfilter);
}

/* Make new AS filter. */
static struct as_filter *as_filter_make(regex_t *reg, const char *reg_str,
					enum as_filter_type type)
{
	struct as_filter *asfilter;

	asfilter = as_filter_new();
	asfilter->reg = reg;
	asfilter->type = type;
	asfilter->reg_str = XSTRDUP(MTYPE_AS_FILTER_STR, reg_str);

	return asfilter;
}

static struct as_filter *as_filter_lookup(struct as_list *aslist,
					  const char *reg_str,
					  enum as_filter_type type)
{
	struct as_filter *asfilter;

	for (asfilter = aslist->head; asfilter; asfilter = asfilter->next)
		if (strcmp(reg_str, asfilter->reg_str) == 0)
			return asfilter;
	return NULL;
}

static void as_filter_entry_replace(struct as_list *list,
				    struct as_filter *replace,
				    struct as_filter *entry)
{
	if (replace->next) {
		entry->next = replace->next;
		replace->next->prev = entry;
	} else {
		entry->next = NULL;
		list->tail = entry;
	}

	if (replace->prev) {
		entry->prev = replace->prev;
		replace->prev->next = entry;
	} else {
		entry->prev = NULL;
		list->head = entry;
	}

	as_filter_free(replace);
}

static void as_list_filter_add(struct as_list *aslist,
			       struct as_filter *asfilter)
{
	struct as_filter *point;
	struct as_filter *replace;

	if (aslist->tail && asfilter->seq > aslist->tail->seq)
		point = NULL;
	else {
		replace = bgp_aslist_seq_check(aslist, asfilter->seq);
		if (replace) {
			as_filter_entry_replace(aslist, replace, asfilter);
			goto hook;
		}

		/* Check insert point. */
		for (point = aslist->head; point; point = point->next)
			if (point->seq >= asfilter->seq)
				break;
	}

	asfilter->next = point;

	if (point) {
		if (point->prev)
			point->prev->next = asfilter;
		else
			aslist->head = asfilter;

		asfilter->prev = point->prev;
		point->prev = asfilter;
	} else {
		if (aslist->tail)
			aslist->tail->next = asfilter;
		else
			aslist->head = asfilter;

		asfilter->prev = aslist->tail;
		aslist->tail = asfilter;
	}

hook:
	/* Run hook function. */
	if (as_list_master.add_hook)
		(*as_list_master.add_hook)(aslist->name);
}

/* Lookup as_list from list of as_list by name. */
struct as_list *as_list_lookup(const char *name)
{
	struct as_list *aslist;

	if (name == NULL)
		return NULL;

	for (aslist = as_list_master.str.head; aslist; aslist = aslist->next)
		if (strcmp(aslist->name, name) == 0)
			return aslist;
	return NULL;
}

static struct as_list *as_list_new(void)
{
	return XCALLOC(MTYPE_AS_LIST, sizeof(struct as_list));
}

static void as_list_free(struct as_list *aslist)
{
	struct aspath_exclude_list *cur_bp = aslist->exclude_list;
	struct aspath_exclude_list *next_bp = NULL;

	while (cur_bp) {
		next_bp = cur_bp->next;
		XFREE(MTYPE_ROUTE_MAP_COMPILED, cur_bp);
		cur_bp = next_bp;
	}

	XFREE (MTYPE_AS_STR, aslist->name);
	XFREE (MTYPE_AS_LIST, aslist);
}

/* Insert new AS list to list of as_list.  Each as_list is sorted by
   the name. */
static struct as_list *as_list_insert(const char *name)
{
	struct as_list *aslist;
	struct as_list *point;
	struct as_list_list *list;

	/* Allocate new access_list and copy given name. */
	aslist = as_list_new();
	aslist->name = XSTRDUP(MTYPE_AS_STR, name);
	assert(aslist->name);

	/* Set access_list to string list. */
	list = &as_list_master.str;

	/* Set point to insertion point. */
	for (point = list->head; point; point = point->next)
		if (strcmp(point->name, name) >= 0)
			break;

	/* In case of this is the first element of master. */
	if (list->head == NULL) {
		list->head = list->tail = aslist;
		return aslist;
	}

	/* In case of insertion is made at the tail of access_list. */
	if (point == NULL) {
		aslist->prev = list->tail;
		list->tail->next = aslist;
		list->tail = aslist;
		return aslist;
	}

	/* In case of insertion is made at the head of access_list. */
	if (point == list->head) {
		aslist->next = list->head;
		list->head->prev = aslist;
		list->head = aslist;
		return aslist;
	}

	/* Insertion is made at middle of the access_list. */
	aslist->next = point;
	aslist->prev = point->prev;

	if (point->prev)
		point->prev->next = aslist;
	point->prev = aslist;

	return aslist;
}

static struct as_list *as_list_get(const char *name)
{
	struct as_list *aslist;

	aslist = as_list_lookup(name);
	if (aslist == NULL)
		aslist = as_list_insert(name);

	return aslist;
}

static const char *filter_type_str(enum as_filter_type type)
{
	switch (type) {
	case AS_FILTER_PERMIT:
		return "permit";
	case AS_FILTER_DENY:
		return "deny";
	default:
		return "";
	}
}

static void as_list_delete(struct as_list *aslist)
{
	struct as_list_list *list;
	struct as_filter *filter, *next;
	struct aspath_exclude_list *cur_bp;

	for (filter = aslist->head; filter; filter = next) {
		next = filter->next;
		as_filter_free(filter);
	}

	list = &as_list_master.str;

	if (aslist->next)
		aslist->next->prev = aslist->prev;
	else
		list->tail = aslist->prev;

	if (aslist->prev)
		aslist->prev->next = aslist->next;
	else
		list->head = aslist->next;

	cur_bp = aslist->exclude_list;
	while (cur_bp) {
		cur_bp->bp_as_excl->exclude_aspath_acl = NULL;
		cur_bp = cur_bp->next;
	}

	as_list_free(aslist);
}

static bool as_list_empty(struct as_list *aslist)
{
	return aslist->head == NULL && aslist->tail == NULL;
}

static void as_list_filter_delete(struct as_list *aslist,
				  struct as_filter *asfilter)
{
	char *name = XSTRDUP(MTYPE_AS_STR, aslist->name);

	if (asfilter->next)
		asfilter->next->prev = asfilter->prev;
	else
		aslist->tail = asfilter->prev;

	if (asfilter->prev)
		asfilter->prev->next = asfilter->next;
	else
		aslist->head = asfilter->next;

	as_filter_free(asfilter);

	/* If access_list becomes empty delete it from access_master. */
	if (as_list_empty(aslist))
		as_list_delete(aslist);

	/* Run hook function. */
	if (as_list_master.delete_hook)
		(*as_list_master.delete_hook)(name);
	XFREE(MTYPE_AS_STR, name);
}

static bool as_filter_match(struct as_filter *asfilter, struct aspath *aspath)
{
	return bgp_regexec(asfilter->reg, aspath) != REG_NOMATCH;
}

/* Apply AS path filter to AS. */
enum as_filter_type as_list_apply(struct as_list *aslist, void *object)
{
	struct as_filter *asfilter;
	struct aspath *aspath;

	aspath = (struct aspath *)object;

	if (aslist == NULL)
		return AS_FILTER_DENY;

	for (asfilter = aslist->head; asfilter; asfilter = asfilter->next) {
		if (as_filter_match(asfilter, aspath))
			return asfilter->type;
	}
	return AS_FILTER_DENY;
}

/* Add hook function. */
void as_list_add_hook(void (*func)(char *))
{
	as_list_master.add_hook = func;
}

/* Delete hook function. */
void as_list_delete_hook(void (*func)(const char *))
{
	as_list_master.delete_hook = func;
}

static bool as_list_dup_check(struct as_list *aslist, struct as_filter *new)
{
	struct as_filter *asfilter;

	for (asfilter = aslist->head; asfilter; asfilter = asfilter->next) {
		if (asfilter->type == new->type
		    && strcmp(asfilter->reg_str, new->reg_str) == 0)
			return true;
	}
	return false;
}

bool config_bgp_aspath_validate(const char *regstr)
{
	char valid_chars[] = "1234567890_^|[,{}() ]$*+.?-\\";

	if (strspn(regstr, valid_chars) == strlen(regstr))
		return true;
	return false;
}

DEFUN(as_path, bgp_as_path_cmd,
      "bgp as-path access-list AS_PATH_FILTER_NAME [seq (0-4294967295)] <deny|permit> LINE...",
      BGP_STR
      "BGP autonomous system path filter\n"
      "Specify an access list name\n"
      "Regular expression access list name\n"
      "Sequence number of an entry\n"
      "Sequence number\n"
      "Specify packets to reject\n"
      "Specify packets to forward\n"
      "A regular-expression (1234567890_^|[,{}() ]$*+.?-\\) to match the BGP AS paths\n")
{
	int idx = 0;
	enum as_filter_type type;
	struct as_filter *asfilter;
	struct as_list *aslist;
	regex_t *regex;
	char *regstr;
	int64_t seqnum = ASPATH_SEQ_NUMBER_AUTO;

	/* Retrieve access list name */
	argv_find(argv, argc, "AS_PATH_FILTER_NAME", &idx);
	char *alname = argv[idx]->arg;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seqnum = (int64_t)atol(argv[idx]->arg);

	/* Check the filter type. */
	type = argv_find(argv, argc, "deny", &idx) ? AS_FILTER_DENY
						   : AS_FILTER_PERMIT;

	/* Check AS path regex. */
	argv_find(argv, argc, "LINE", &idx);
	regstr = argv_concat(argv, argc, idx);

	regex = bgp_regcomp(regstr);
	if (!regex) {
		vty_out(vty, "can't compile regexp %s\n", regstr);
		XFREE(MTYPE_TMP, regstr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!config_bgp_aspath_validate(regstr)) {
		vty_out(vty, "Invalid character in as-path access-list %s\n",
			regstr);
		XFREE(MTYPE_TMP, regstr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	asfilter = as_filter_make(regex, regstr, type);

	XFREE(MTYPE_TMP, regstr);

	/* Install new filter to the access_list. */
	aslist = as_list_get(alname);

	if (seqnum == ASPATH_SEQ_NUMBER_AUTO)
		seqnum = bgp_alist_new_seq_get(aslist);

	asfilter->seq = seqnum;

	/* Duplicate insertion check. */;
	if (as_list_dup_check(aslist, asfilter))
		as_filter_free(asfilter);
	else
		as_list_filter_add(aslist, asfilter);

	return CMD_SUCCESS;
}

DEFUN(no_as_path, no_bgp_as_path_cmd,
      "no bgp as-path access-list AS_PATH_FILTER_NAME [seq (0-4294967295)] <deny|permit> LINE...",
      NO_STR
      BGP_STR
      "BGP autonomous system path filter\n"
      "Specify an access list name\n"
      "Regular expression access list name\n"
      "Sequence number of an entry\n"
      "Sequence number\n"
      "Specify packets to reject\n"
      "Specify packets to forward\n"
      "A regular-expression (1234567890_^|[,{}() ]$*+.?-\\) to match the BGP AS paths\n")
{
	int idx = 0;
	enum as_filter_type type;
	struct as_filter *asfilter;
	struct as_list *aslist;
	char *regstr;
	regex_t *regex;

	char *aslistname =
		argv_find(argv, argc, "AS_PATH_FILTER_NAME", &idx) ? argv[idx]->arg : NULL;

	/* Lookup AS list from AS path list. */
	aslist = as_list_lookup(aslistname);
	if (aslist == NULL) {
		vty_out(vty, "bgp as-path access-list %s doesn't exist\n",
			aslistname);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check the filter type. */
	if (argv_find(argv, argc, "permit", &idx))
		type = AS_FILTER_PERMIT;
	else if (argv_find(argv, argc, "deny", &idx))
		type = AS_FILTER_DENY;
	else {
		vty_out(vty, "filter type must be [permit|deny]\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Compile AS path. */
	argv_find(argv, argc, "LINE", &idx);
	regstr = argv_concat(argv, argc, idx);

	if (!config_bgp_aspath_validate(regstr)) {
		vty_out(vty, "Invalid character in as-path access-list %s\n",
			regstr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	regex = bgp_regcomp(regstr);
	if (!regex) {
		vty_out(vty, "can't compile regexp %s\n", regstr);
		XFREE(MTYPE_TMP, regstr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Lookup asfilter. */
	asfilter = as_filter_lookup(aslist, regstr, type);

	bgp_regex_free(regex);

	if (asfilter == NULL) {
		vty_out(vty, "Regex entered %s does not exist\n", regstr);
		XFREE(MTYPE_TMP, regstr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	XFREE(MTYPE_TMP, regstr);

	as_list_filter_delete(aslist, asfilter);

	return CMD_SUCCESS;
}

DEFUN (no_as_path_all,
       no_bgp_as_path_all_cmd,
       "no bgp as-path access-list AS_PATH_FILTER_NAME",
       NO_STR
       BGP_STR
       "BGP autonomous system path filter\n"
       "Specify an access list name\n"
       "Regular expression access list name\n")
{
	int idx_word = 4;
	struct as_list *aslist;

	aslist = as_list_lookup(argv[idx_word]->arg);
	if (aslist == NULL) {
		vty_out(vty, "bgp as-path access-list %s doesn't exist\n",
			argv[idx_word]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	as_list_delete(aslist);

	/* Run hook function. */
	if (as_list_master.delete_hook)
		(*as_list_master.delete_hook)(argv[idx_word]->arg);

	return CMD_SUCCESS;
}

static void as_list_show(struct vty *vty, struct as_list *aslist,
			 json_object *json)
{
	struct as_filter *asfilter;
	json_object *json_aslist = NULL;

	if (json) {
		json_aslist = json_object_new_array();
		json_object_object_add(json, aslist->name, json_aslist);
	} else
		vty_out(vty, "AS path access list %s\n", aslist->name);

	for (asfilter = aslist->head; asfilter; asfilter = asfilter->next) {
		if (json) {
			json_object *json_asfilter = json_object_new_object();

			json_object_int_add(json_asfilter, "sequenceNumber",
					    asfilter->seq);
			json_object_string_add(json_asfilter, "type",
					       filter_type_str(asfilter->type));
			json_object_string_add(json_asfilter, "regExp",
					       asfilter->reg_str);

			json_object_array_add(json_aslist, json_asfilter);
		} else
			vty_out(vty, "    %s %s\n",
				filter_type_str(asfilter->type),
				asfilter->reg_str);
	}
}

static void as_list_show_all(struct vty *vty, json_object *json)
{
	struct as_list *aslist;

	for (aslist = as_list_master.str.head; aslist; aslist = aslist->next)
		as_list_show(vty, aslist, json);
}

DEFUN (show_as_path_access_list,
       show_bgp_as_path_access_list_cmd,
       "show bgp as-path-access-list AS_PATH_FILTER_NAME [json]",
       SHOW_STR
       BGP_STR
       "List AS path access lists\n"
       "AS path access list name\n"
       JSON_STR)
{
	int idx_word = 3;
	struct as_list *aslist;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	aslist = as_list_lookup(argv[idx_word]->arg);
	if (aslist)
		as_list_show(vty, aslist, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

ALIAS (show_as_path_access_list,
       show_ip_as_path_access_list_cmd,
       "show ip as-path-access-list AS_PATH_FILTER_NAME [json]",
       SHOW_STR
       IP_STR
       "List AS path access lists\n"
       "AS path access list name\n"
       JSON_STR)

DEFUN (show_as_path_access_list_all,
       show_bgp_as_path_access_list_all_cmd,
       "show bgp as-path-access-list [json]",
       SHOW_STR
       BGP_STR
       "List AS path access lists\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	as_list_show_all(vty, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

ALIAS (show_as_path_access_list_all,
       show_ip_as_path_access_list_all_cmd,
       "show ip as-path-access-list [json]",
       SHOW_STR
       IP_STR
       "List AS path access lists\n"
       JSON_STR)

static int config_write_as_list(struct vty *vty)
{
	struct as_list *aslist;
	struct as_filter *asfilter;
	int write = 0;

	for (aslist = as_list_master.str.head; aslist; aslist = aslist->next)
		for (asfilter = aslist->head; asfilter;
		     asfilter = asfilter->next) {
			vty_out(vty,
				"bgp as-path access-list %s seq %" PRId64
				" %s %s\n",
				aslist->name, asfilter->seq,
				filter_type_str(asfilter->type),
				asfilter->reg_str);
			write++;
		}
	return write;
}

static int config_write_as_list(struct vty *vty);
static struct cmd_node as_list_node = {
	.name = "as list",
	.node = AS_LIST_NODE,
	.prompt = "",
	.config_write = config_write_as_list,
};

static void bgp_aspath_filter_cmd_completion(vector comps,
					     struct cmd_token *token)
{
	struct as_list *aslist;

	for (aslist = as_list_master.str.head; aslist; aslist = aslist->next)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, aslist->name));
}

static const struct cmd_variable_handler aspath_filter_handlers[] = {
	{.tokenname = "AS_PATH_FILTER_NAME",
	 .completions = bgp_aspath_filter_cmd_completion},
	{.completions = NULL}};

/* Register functions. */
void bgp_filter_init(void)
{
	install_node(&as_list_node);

	install_element(CONFIG_NODE, &bgp_as_path_cmd);
	install_element(CONFIG_NODE, &no_bgp_as_path_cmd);
	install_element(CONFIG_NODE, &no_bgp_as_path_all_cmd);

	install_element(VIEW_NODE, &show_bgp_as_path_access_list_cmd);
	install_element(VIEW_NODE, &show_ip_as_path_access_list_cmd);
	install_element(VIEW_NODE, &show_bgp_as_path_access_list_all_cmd);
	install_element(VIEW_NODE, &show_ip_as_path_access_list_all_cmd);

	cmd_variable_handler_register(aspath_filter_handlers);
}

void bgp_filter_reset(void)
{
	struct as_list *aslist;
	struct as_list *next;

	for (aslist = as_list_master.str.head; aslist; aslist = next) {
		next = aslist->next;
		as_list_delete(aslist);
	}

	assert(as_list_master.str.head == NULL);
	assert(as_list_master.str.tail == NULL);
}
