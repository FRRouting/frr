// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP community-list and extcommunity-list.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"
#include "stream.h"
#include "jhash.h"
#include "frrstr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"

/* Calculate new sequential number. */
static int64_t bgp_clist_new_seq_get(struct community_list *list)
{
	int64_t maxseq;
	int64_t newseq;
	struct community_entry *entry;

	maxseq = 0;

	for (entry = list->head; entry; entry = entry->next) {
		if (maxseq < entry->seq)
			maxseq = entry->seq;
	}

	newseq = ((maxseq / 5) * 5) + 5;

	return (newseq > UINT_MAX) ? UINT_MAX : newseq;
}

/* Return community-list entry which has same seq number. */
static struct community_entry *bgp_clist_seq_check(struct community_list *list,
						   int64_t seq)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next)
		if (entry->seq == seq)
			return entry;
	return NULL;
}

static uint32_t bgp_clist_hash_key_community_list(const void *data)
{
	struct community_list *cl = (struct community_list *) data;

	if (cl->name_hash)
		return cl->name_hash;

	cl->name_hash = bgp_clist_hash_key(cl->name);
	return cl->name_hash;
}

static bool bgp_clist_hash_cmp_community_list(const void *a1, const void *a2)
{
	const struct community_list *cl1 = a1;
	const struct community_list *cl2 = a2;

	if (cl1->name_hash != cl2->name_hash)
		return false;

	if (strcmp(cl1->name, cl2->name) == 0)
		return true;

	return false;
}

/* Lookup master structure for community-list or
   extcommunity-list.  */
struct community_list_master *
community_list_master_lookup(struct community_list_handler *ch, int master)
{
	if (ch)
		switch (master) {
		case COMMUNITY_LIST_MASTER:
			return &ch->community_list;
		case EXTCOMMUNITY_LIST_MASTER:
			return &ch->extcommunity_list;
		case LARGE_COMMUNITY_LIST_MASTER:
			return &ch->lcommunity_list;
		}
	return NULL;
}

/* Allocate a new community list entry.  */
static struct community_entry *community_entry_new(void)
{
	return XCALLOC(MTYPE_COMMUNITY_LIST_ENTRY,
		       sizeof(struct community_entry));
}

/* Free community list entry.  */
static void community_entry_free(struct community_entry *entry)
{
	switch (entry->style) {
	case COMMUNITY_LIST_STANDARD:
		if (entry->u.com)
			community_free(&entry->u.com);
		break;
	case LARGE_COMMUNITY_LIST_STANDARD:
		if (entry->u.lcom)
			lcommunity_free(&entry->u.lcom);
		break;
	case EXTCOMMUNITY_LIST_STANDARD:
		/* In case of standard extcommunity-list, configuration string
		   is made by ecommunity_ecom2str().  */
		XFREE(MTYPE_ECOMMUNITY_STR, entry->config);
		if (entry->u.ecom)
			ecommunity_free(&entry->u.ecom);
		break;
	case COMMUNITY_LIST_EXPANDED:
	case EXTCOMMUNITY_LIST_EXPANDED:
	case LARGE_COMMUNITY_LIST_EXPANDED:
		XFREE(MTYPE_COMMUNITY_LIST_CONFIG, entry->config);
		if (entry->reg)
			bgp_regex_free(entry->reg);
		break;
	default:
		break;
	}
	XFREE(MTYPE_COMMUNITY_LIST_ENTRY, entry);
}

/* Allocate a new community-list.  */
static struct community_list *community_list_new(void)
{
	return XCALLOC(MTYPE_COMMUNITY_LIST, sizeof(struct community_list));
}

/* Free community-list.  */
static void community_list_free(struct community_list *list)
{
	XFREE(MTYPE_COMMUNITY_LIST_NAME, list->name);
	XFREE(MTYPE_COMMUNITY_LIST, list);
}

static struct community_list *
community_list_insert(struct community_list_handler *ch, const char *name,
		      int master)
{
	size_t i;
	long number;
	struct community_list *new;
	struct community_list *point;
	struct community_list_list *list;
	struct community_list_master *cm;

	/* Lookup community-list master.  */
	cm = community_list_master_lookup(ch, master);
	if (!cm)
		return NULL;

	/* Allocate new community_list and copy given name. */
	new = community_list_new();
	new->name = XSTRDUP(MTYPE_COMMUNITY_LIST_NAME, name);
	new->name_hash = bgp_clist_hash_key_community_list(new);

	/* Save for later */
	(void)hash_get(cm->hash, new, hash_alloc_intern);

	/* If name is made by all digit character.  We treat it as
	   number. */
	for (number = 0, i = 0; i < strlen(name); i++) {
		if (isdigit((unsigned char)name[i]))
			number = (number * 10) + (name[i] - '0');
		else
			break;
	}

	/* In case of name is all digit character */
	if (i == strlen(name) && number <= COMMUNITY_LIST_NUMBER_MAX) {
		new->sort = COMMUNITY_LIST_NUMBER;

		/* Set access_list to number list. */
		list = &cm->num;

		for (point = list->head; point; point = point->next)
			if (atol(point->name) >= number)
				break;
	} else {
		new->sort = COMMUNITY_LIST_STRING;

		/* Set access_list to string list. */
		list = &cm->str;

		/* Set point to insertion point. */
		for (point = list->head; point; point = point->next)
			if (strcmp(point->name, name) >= 0)
				break;
	}

	/* Link to upper list.  */
	new->parent = list;

	/* In case of this is the first element of master. */
	if (list->head == NULL) {
		list->head = list->tail = new;
		return new;
	}

	/* In case of insertion is made at the tail of access_list. */
	if (point == NULL) {
		new->prev = list->tail;
		list->tail->next = new;
		list->tail = new;
		return new;
	}

	/* In case of insertion is made at the head of access_list. */
	if (point == list->head) {
		new->next = list->head;
		list->head->prev = new;
		list->head = new;
		return new;
	}

	/* Insertion is made at middle of the access_list. */
	new->next = point;
	new->prev = point->prev;

	if (point->prev)
		point->prev->next = new;
	point->prev = new;

	return new;
}

struct community_list *community_list_lookup(struct community_list_handler *ch,
					     const char *name,
					     uint32_t name_hash,
					     int master)
{
	struct community_list lookup;
	struct community_list_master *cm;

	if (!name)
		return NULL;

	cm = community_list_master_lookup(ch, master);
	if (!cm)
		return NULL;

	lookup.name = (char *)name;
	lookup.name_hash = name_hash;
	return hash_get(cm->hash, &lookup, NULL);
}

static struct community_list *
community_list_get(struct community_list_handler *ch, const char *name,
		   int master)
{
	struct community_list *list;

	list = community_list_lookup(ch, name, 0, master);
	if (!list)
		list = community_list_insert(ch, name, master);
	return list;
}

static void community_list_delete(struct community_list_master *cm,
				  struct community_list *list)
{
	struct community_list_list *clist;
	struct community_entry *entry, *next;

	for (entry = list->head; entry; entry = next) {
		next = entry->next;
		community_entry_free(entry);
	}

	clist = list->parent;

	if (list->next)
		list->next->prev = list->prev;
	else
		clist->tail = list->prev;

	if (list->prev)
		list->prev->next = list->next;
	else
		clist->head = list->next;

	hash_release(cm->hash, list);
	community_list_free(list);
}

static bool community_list_empty_p(struct community_list *list)
{
	return list->head == NULL && list->tail == NULL;
}

/* Delete community-list entry from the list.  */
static void community_list_entry_delete(struct community_list_master *cm,
					struct community_list *list,
					struct community_entry *entry)
{
	if (entry->next)
		entry->next->prev = entry->prev;
	else
		list->tail = entry->prev;

	if (entry->prev)
		entry->prev->next = entry->next;
	else
		list->head = entry->next;

	community_entry_free(entry);

	if (community_list_empty_p(list))
		community_list_delete(cm, list);
}

/*
 * Replace community-list entry in the list. Note that entry is the new one
 * and replace is one one being replaced.
 */
static void community_list_entry_replace(struct community_list *list,
					 struct community_entry *replace,
					 struct community_entry *entry)
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

	community_entry_free(replace);
}

/* Add community-list entry to the list.  */
static void community_list_entry_add(struct community_list *list,
				     struct community_entry *entry,
				     struct community_list_handler *ch,
				     int master)
{
	struct community_entry *replace;
	struct community_entry *point;

	/* Automatic assignment of seq no. */
	if (entry->seq == COMMUNITY_SEQ_NUMBER_AUTO)
		entry->seq = bgp_clist_new_seq_get(list);

	if (list->tail && entry->seq > list->tail->seq)
		point = NULL;
	else {
		replace = bgp_clist_seq_check(list, entry->seq);
		if (replace) {
			community_list_entry_replace(list, replace, entry);
			return;
		}

		/* Check insert point. */
		for (point = list->head; point; point = point->next)
			if (point->seq >= entry->seq)
				break;
	}

	/* In case of this is the first element of the list. */
	entry->next = point;

	if (point) {
		if (point->prev)
			point->prev->next = entry;
		else
			list->head = entry;

		entry->prev = point->prev;
		point->prev = entry;
	} else {
		if (list->tail)
			list->tail->next = entry;
		else
			list->head = entry;

		entry->prev = list->tail;
		list->tail = entry;
	}
}

/* Lookup community-list entry from the list.  */
static struct community_entry *
community_list_entry_lookup(struct community_list *list, const void *arg,
			    int direct)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		switch (entry->style) {
		case COMMUNITY_LIST_STANDARD:
			if (entry->direct == direct
			    && community_cmp(entry->u.com, arg))
				return entry;
			break;
		case EXTCOMMUNITY_LIST_STANDARD:
			if (entry->direct == direct
			    && ecommunity_cmp(entry->u.ecom, arg))
				return entry;
			break;
		case LARGE_COMMUNITY_LIST_STANDARD:
			if (entry->direct == direct
			    && lcommunity_cmp(entry->u.lcom, arg))
				return entry;
			break;
		case COMMUNITY_LIST_EXPANDED:
		case EXTCOMMUNITY_LIST_EXPANDED:
		case LARGE_COMMUNITY_LIST_EXPANDED:
			if (entry->direct == direct
			    && strcmp(entry->config, arg) == 0)
				return entry;
			break;
		default:
			break;
		}
	}
	return NULL;
}

static char *community_str_get(struct community *com, int i)
{
	uint32_t comval;
	uint16_t as;
	uint16_t val;
	char *str;

	memcpy(&comval, com_nthval(com, i), sizeof(uint32_t));
	comval = ntohl(comval);

	switch (comval) {
	case COMMUNITY_GSHUT:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "graceful-shutdown");
		break;
	case COMMUNITY_ACCEPT_OWN:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "accept-own");
		break;
	case COMMUNITY_ROUTE_FILTER_TRANSLATED_v4:
		str = XSTRDUP(MTYPE_COMMUNITY_STR,
			      "route-filter-translated-v4");
		break;
	case COMMUNITY_ROUTE_FILTER_v4:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "route-filter-v4");
		break;
	case COMMUNITY_ROUTE_FILTER_TRANSLATED_v6:
		str = XSTRDUP(MTYPE_COMMUNITY_STR,
			      "route-filter-translated-v6");
		break;
	case COMMUNITY_ROUTE_FILTER_v6:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "route-filter-v6");
		break;
	case COMMUNITY_LLGR_STALE:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "llgr-stale");
		break;
	case COMMUNITY_NO_LLGR:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "no-llgr");
		break;
	case COMMUNITY_ACCEPT_OWN_NEXTHOP:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "accept-own-nexthop");
		break;
	case COMMUNITY_BLACKHOLE:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "blackhole");
		break;
	case COMMUNITY_NO_EXPORT:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "no-export");
		break;
	case COMMUNITY_NO_ADVERTISE:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "no-advertise");
		break;
	case COMMUNITY_LOCAL_AS:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "local-AS");
		break;
	case COMMUNITY_NO_PEER:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "no-peer");
		break;
	default:
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "65536:65535");
		as = CHECK_FLAG((comval >> 16), 0xFFFF);
		val = CHECK_FLAG(comval, 0xFFFF);
		snprintf(str, strlen(str), "%u:%d", as, val);
		break;
	}

	return str;
}

/* Internal function to perform regular expression match for
 * a single community. */
static bool community_regexp_include(regex_t *reg, struct community *com, int i)
{
	char *str;
	int rv;

	/* When there is no communities attribute it is treated as empty string.
	 */
	if (com == NULL || com->size == 0)
		str = XSTRDUP(MTYPE_COMMUNITY_STR, "");
	else
		str = community_str_get(com, i);

	/* Regular expression match.  */
	rv = regexec(reg, str, 0, NULL, 0);

	XFREE(MTYPE_COMMUNITY_STR, str);

	return rv == 0;
}

/* Internal function to perform regular expression match for community
   attribute.  */
static bool community_regexp_match(struct community *com, regex_t *reg)
{
	const char *str;
	char *regstr;
	int rv;

	/* When there is no communities attribute it is treated as empty
	   string.  */
	if (com == NULL || com->size == 0)
		str = "";
	else
		str = community_str(com, false, true);

	regstr = bgp_alias2community_str(str);

	/* Regular expression match.  */
	rv = regexec(reg, regstr, 0, NULL, 0);

	XFREE(MTYPE_TMP, regstr);

	return rv == 0;
}

static char *lcommunity_str_get(struct lcommunity *lcom, int i)
{
	struct lcommunity_val lcomval;
	uint32_t globaladmin;
	uint32_t localdata1;
	uint32_t localdata2;
	char *str;
	const uint8_t *ptr;

	ptr = lcom->val + (i * LCOMMUNITY_SIZE);

	memcpy(&lcomval, ptr, LCOMMUNITY_SIZE);

	/* Allocate memory.  48 bytes taken off bgp_lcommunity.c */
	ptr = (uint8_t *)lcomval.val;
	ptr = ptr_get_be32(ptr, &globaladmin);
	ptr = ptr_get_be32(ptr, &localdata1);
	ptr = ptr_get_be32(ptr, &localdata2);
	(void)ptr; /* consume value */

	str = XMALLOC(MTYPE_LCOMMUNITY_STR, 48);
	snprintf(str, 48, "%u:%u:%u", globaladmin, localdata1, localdata2);

	return str;
}

/* Internal function to perform regular expression match for
 * a single community. */
static bool lcommunity_regexp_include(regex_t *reg, struct lcommunity *lcom,
				      int i)
{
	char *str;

	/* When there is no communities attribute it is treated as empty string.
	 */
	if (lcom == NULL || lcom->size == 0)
		str = XSTRDUP(MTYPE_LCOMMUNITY_STR, "");
	else
		str = lcommunity_str_get(lcom, i);

	/* Regular expression match.  */
	if (regexec(reg, str, 0, NULL, 0) == 0) {
		XFREE(MTYPE_LCOMMUNITY_STR, str);
		return true;
	}

	XFREE(MTYPE_LCOMMUNITY_STR, str);
	/* No match.  */
	return false;
}

static bool lcommunity_regexp_match(struct lcommunity *com, regex_t *reg)
{
	const char *str;
	char *regstr;
	int rv;

	/* When there is no communities attribute it is treated as empty
	   string.  */
	if (com == NULL || com->size == 0)
		str = "";
	else
		str = lcommunity_str(com, false, true);

	regstr = bgp_alias2community_str(str);

	/* Regular expression match.  */
	rv = regexec(reg, regstr, 0, NULL, 0);

	XFREE(MTYPE_TMP, regstr);

	return rv == 0;
}


static bool ecommunity_regexp_match(struct ecommunity *ecom, regex_t *reg)
{
	const char *str;

	/* When there is no communities attribute it is treated as empty
	   string.  */
	if (ecom == NULL || ecom->size == 0)
		str = "";
	else
		str = ecommunity_str(ecom);

	/* Regular expression match.  */
	if (regexec(reg, str, 0, NULL, 0) == 0)
		return true;

	/* No match.  */
	return false;
}

/* When given community attribute matches to the community-list return
   1 else return 0.  */
bool community_list_match(struct community *com, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry->style == COMMUNITY_LIST_STANDARD) {
			if (community_match(com, entry->u.com))
				return entry->direct == COMMUNITY_PERMIT;
		} else if (entry->style == COMMUNITY_LIST_EXPANDED) {
			if (community_regexp_match(com, entry->reg))
				return entry->direct == COMMUNITY_PERMIT;
		}
	}
	return false;
}

bool lcommunity_list_match(struct lcommunity *lcom, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry->style == LARGE_COMMUNITY_LIST_STANDARD) {
			if (lcommunity_match(lcom, entry->u.lcom))
				return entry->direct == COMMUNITY_PERMIT;
		} else if (entry->style == LARGE_COMMUNITY_LIST_EXPANDED) {
			if (lcommunity_regexp_match(lcom, entry->reg))
				return entry->direct == COMMUNITY_PERMIT;
		}
	}
	return false;
}


/* Perform exact matching.  In case of expanded large-community-list, do
 * same thing as lcommunity_list_match().
 */
bool lcommunity_list_exact_match(struct lcommunity *lcom,
				 struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry->style == LARGE_COMMUNITY_LIST_STANDARD) {
			if (lcommunity_cmp(lcom, entry->u.lcom))
				return entry->direct == COMMUNITY_PERMIT;
		} else if (entry->style == LARGE_COMMUNITY_LIST_EXPANDED) {
			if (lcommunity_regexp_match(lcom, entry->reg))
				return entry->direct == COMMUNITY_PERMIT;
		}
	}
	return false;
}

bool ecommunity_list_match(struct ecommunity *ecom, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry->style == EXTCOMMUNITY_LIST_STANDARD) {
			if (ecommunity_match(ecom, entry->u.ecom))
				return entry->direct == COMMUNITY_PERMIT;
		} else if (entry->style == EXTCOMMUNITY_LIST_EXPANDED) {
			if (ecommunity_regexp_match(ecom, entry->reg))
				return entry->direct == COMMUNITY_PERMIT;
		}
	}
	return false;
}

/* Perform exact matching.  In case of expanded community-list, do
   same thing as community_list_match().  */
bool community_list_exact_match(struct community *com,
				struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry->style == COMMUNITY_LIST_STANDARD) {
			if (community_cmp(com, entry->u.com))
				return entry->direct == COMMUNITY_PERMIT;
		} else if (entry->style == COMMUNITY_LIST_EXPANDED) {
			if (community_regexp_match(com, entry->reg))
				return entry->direct == COMMUNITY_PERMIT;
		}
	}
	return false;
}

bool community_list_any_match(struct community *com, struct community_list *list)
{
	struct community_entry *entry;
	uint32_t val;
	int i;

	for (i = 0; i < com->size; i++) {
		val = community_val_get(com, i);

		for (entry = list->head; entry; entry = entry->next) {
			if (entry->style == COMMUNITY_LIST_STANDARD &&
			    community_include(entry->u.com, val))
				return entry->direct == COMMUNITY_PERMIT;
			if ((entry->style == COMMUNITY_LIST_EXPANDED) &&
			    community_regexp_include(entry->reg, com, i))
				return entry->direct == COMMUNITY_PERMIT;
		}
	}
	return false;
}

/* Delete all permitted communities in the list from com.  */
struct community *community_list_match_delete(struct community *com,
					      struct community_list *list)
{
	struct community_entry *entry;
	uint32_t val;
	uint32_t com_index_to_delete[com->size];
	int delete_index = 0;
	int i;

	/* Loop over each community value and evaluate each against the
	 * community-list.  If we need to delete a community value add its index
	 * to com_index_to_delete.
	 */
	for (i = 0; i < com->size; i++) {
		val = community_val_get(com, i);

		for (entry = list->head; entry; entry = entry->next) {
			if ((entry->style == COMMUNITY_LIST_STANDARD) &&
			    community_include(entry->u.com, val)) {
				if (entry->direct == COMMUNITY_PERMIT) {
					com_index_to_delete[delete_index] = i;
					delete_index++;
				}
				break;
			} else if ((entry->style == COMMUNITY_LIST_EXPANDED) &&
				   community_regexp_include(entry->reg, com, i)) {
				if (entry->direct == COMMUNITY_PERMIT) {
					com_index_to_delete[delete_index] = i;
					delete_index++;
				}
				break;
			}
		}
	}

	/* Delete all of the communities we flagged for deletion */
	for (i = delete_index - 1; i >= 0; i--) {
		val = community_val_get(com, com_index_to_delete[i]);
		val = htonl(val);
		community_del_val(com, &val);
	}

	return com;
}

/* To avoid duplicated entry in the community-list, this function
   compares specified entry to existing entry.  */
static bool community_list_dup_check(struct community_list *list,
				     struct community_entry *new)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry->style != new->style)
			continue;

		if (entry->direct != new->direct)
			continue;

		switch (entry->style) {
		case COMMUNITY_LIST_STANDARD:
			if (community_cmp(entry->u.com, new->u.com))
				return true;
			break;
		case LARGE_COMMUNITY_LIST_STANDARD:
			if (lcommunity_cmp(entry->u.lcom, new->u.lcom))
				return true;
			break;
		case EXTCOMMUNITY_LIST_STANDARD:
			if (ecommunity_cmp(entry->u.ecom, new->u.ecom))
				return true;
			break;
		case COMMUNITY_LIST_EXPANDED:
		case EXTCOMMUNITY_LIST_EXPANDED:
		case LARGE_COMMUNITY_LIST_EXPANDED:
			if (strcmp(entry->config, new->config) == 0)
				return true;
			break;
		default:
			break;
		}
	}
	return false;
}

/* Set community-list.  */
int community_list_set(struct community_list_handler *ch, const char *name,
		       const char *str, const char *seq, int direct, int style)
{
	struct community_entry *entry = NULL;
	struct community_list *list;
	struct community *com = NULL;
	regex_t *regex = NULL;
	int64_t seqnum = COMMUNITY_SEQ_NUMBER_AUTO;

	if (seq)
		seqnum = (int64_t)atol(seq);

	/* Get community list. */
	list = community_list_get(ch, name, COMMUNITY_LIST_MASTER);

	/* When community-list already has entry, new entry should have same
	   style.  If you want to have mixed style community-list, you can
	   comment out this check.  */
	if (!community_list_empty_p(list)) {
		struct community_entry *first;

		first = list->head;

		if (style != first->style) {
			return (first->style == COMMUNITY_LIST_STANDARD
					? COMMUNITY_LIST_ERR_STANDARD_CONFLICT
					: COMMUNITY_LIST_ERR_EXPANDED_CONFLICT);
		}
	}

	if (style == COMMUNITY_LIST_STANDARD)
		com = community_str2com(str);
	else
		regex = bgp_regcomp(str);

	if (!com && !regex)
		return COMMUNITY_LIST_ERR_MALFORMED_VAL;

	entry = community_entry_new();
	entry->direct = direct;
	entry->style = style;
	entry->u.com = com;
	entry->reg = regex;
	entry->seq = seqnum;
	entry->config =
		(regex ? XSTRDUP(MTYPE_COMMUNITY_LIST_CONFIG, str) : NULL);

	/* Do not put duplicated community entry.  */
	if (community_list_dup_check(list, entry))
		community_entry_free(entry);
	else {
		community_list_entry_add(list, entry, ch,
					 COMMUNITY_LIST_MASTER);
		route_map_notify_dependencies(name, RMAP_EVENT_CLIST_ADDED);
	}

	return 0;
}

/* Unset community-list */
void community_list_unset(struct community_list_handler *ch, const char *name,
			  const char *str, const char *seq, int direct,
			  int style)
{
	struct community_list_master *cm = NULL;
	struct community_entry *entry = NULL;
	struct community_list *list;
	struct community *com = NULL;

	/* Lookup community list.  */
	list = community_list_lookup(ch, name, 0, COMMUNITY_LIST_MASTER);
	if (list == NULL)
		return;

	cm = community_list_master_lookup(ch, COMMUNITY_LIST_MASTER);
	/* Delete all of entry belongs to this community-list.  */
	if (!str) {
		community_list_delete(cm, list);
		route_map_notify_dependencies(name, RMAP_EVENT_CLIST_DELETED);
		return;
	}

	if (style == COMMUNITY_LIST_STANDARD)
		com = community_str2com(str);

	if (com) {
		entry = community_list_entry_lookup(list, com, direct);
		community_free(&com);
	} else
		entry = community_list_entry_lookup(list, str, direct);

	if (!entry)
		return;

	community_list_entry_delete(cm, list, entry);
	route_map_notify_dependencies(name, RMAP_EVENT_CLIST_DELETED);
}

bool lcommunity_list_any_match(struct lcommunity *lcom,
			       struct community_list *list)
{
	struct community_entry *entry;
	uint8_t *ptr;
	int i;

	for (i = 0; i < lcom->size; i++) {
		ptr = lcom->val + (i * LCOMMUNITY_SIZE);

		for (entry = list->head; entry; entry = entry->next) {
			if ((entry->style == LARGE_COMMUNITY_LIST_STANDARD) &&
			    lcommunity_include(entry->u.lcom, ptr))
				return entry->direct == COMMUNITY_PERMIT;
			if ((entry->style == LARGE_COMMUNITY_LIST_EXPANDED) &&
			    lcommunity_regexp_include(entry->reg, lcom, i))
				return entry->direct == COMMUNITY_PERMIT;
		}
	}
	return false;
}

/* Delete all permitted large communities in the list from com.  */
struct lcommunity *lcommunity_list_match_delete(struct lcommunity *lcom,
						struct community_list *list)
{
	struct community_entry *entry;
	uint32_t com_index_to_delete[lcom->size];
	uint8_t *ptr;
	int delete_index = 0;
	int i;

	/* Loop over each lcommunity value and evaluate each against the
	 * community-list.  If we need to delete a community value add its index
	 * to com_index_to_delete.
	 */
	for (i = 0; i < lcom->size; i++) {
		ptr = lcom->val + (i * LCOMMUNITY_SIZE);
		for (entry = list->head; entry; entry = entry->next) {
			if ((entry->style == LARGE_COMMUNITY_LIST_STANDARD) &&
			    lcommunity_include(entry->u.lcom, ptr)) {
				if (entry->direct == COMMUNITY_PERMIT) {
					com_index_to_delete[delete_index] = i;
					delete_index++;
				}
				break;
			}

			else if ((entry->style ==
				  LARGE_COMMUNITY_LIST_EXPANDED) &&
				 lcommunity_regexp_include(entry->reg, lcom,
							   i)) {
				if (entry->direct == COMMUNITY_PERMIT) {
					com_index_to_delete[delete_index] = i;
					delete_index++;
				}
				break;
			}
		}
	}

	/* Delete all of the communities we flagged for deletion */
	for (i = delete_index - 1; i >= 0; i--) {
		ptr = lcom->val + (com_index_to_delete[i] * LCOMMUNITY_SIZE);
		lcommunity_del_val(lcom, ptr);
	}

	return lcom;
}

/* Delete all permitted extended communities in the list from ecom.*/
struct ecommunity *ecommunity_list_match_delete(struct ecommunity *ecom,
						struct community_list *list)
{
	struct community_entry *entry;
	uint32_t com_index_to_delete[ecom->size];
	uint8_t *ptr;
	uint32_t delete_index = 0;
	uint32_t i;
	struct ecommunity local_ecom = {.size = 1};
	struct ecommunity_val local_eval = {0};

	for (i = 0; i < ecom->size; i++) {
		local_ecom.val = ecom->val + (i * ECOMMUNITY_SIZE);
		for (entry = list->head; entry; entry = entry->next) {
			if (((entry->style == EXTCOMMUNITY_LIST_STANDARD) &&
			     ecommunity_include(entry->u.ecom, &local_ecom)) ||
			   ((entry->style == EXTCOMMUNITY_LIST_EXPANDED) &&
			    ecommunity_regexp_match(ecom, entry->reg))) {
				if (entry->direct == COMMUNITY_PERMIT) {
					com_index_to_delete[delete_index] = i;
					delete_index++;
				}
				break;
			}
		}
	}

	/* Delete all of the extended communities we flagged for deletion */
	for (i = delete_index; i > 0; i--) {
		ptr = ecom->val + (com_index_to_delete[i-1] * ECOMMUNITY_SIZE);
		memcpy(&local_eval.val, ptr, sizeof(local_eval.val));
		ecommunity_del_val(ecom, &local_eval);
	}

	return ecom;
}

/* Helper to check if every octet do not exceed UINT_MAX */
bool lcommunity_list_valid(const char *community, int style)
{
	int octets;
	char **splits, **communities;
	char *endptr;
	int num, num_communities;
	regex_t *regres;
	int invalid = 0;

	frrstr_split(community, " ", &communities, &num_communities);

	for (int j = 0; j < num_communities; j++) {
		octets = 0;
		frrstr_split(communities[j], ":", &splits, &num);

		for (int i = 0; i < num; i++) {
			if (strlen(splits[i]) == 0)
				/* There is no digit to check */
				invalid++;

			if (style == LARGE_COMMUNITY_LIST_STANDARD) {
				if (*splits[i] == '-')
					/* Must not be negative */
					invalid++;
				else if (strtoul(splits[i], &endptr, 10)
					 > UINT_MAX)
					/* Larger than 4 octets */
					invalid++;
				else if (*endptr)
					/* Not all characters were digits */
					invalid++;
			} else {
				regres = bgp_regcomp(communities[j]);
				if (!regres)
					/* malformed regex */
					invalid++;
				else
					bgp_regex_free(regres);
			}

			octets++;
			XFREE(MTYPE_TMP, splits[i]);
		}
		XFREE(MTYPE_TMP, splits);

		if (octets != 3)
			invalid++;

		XFREE(MTYPE_TMP, communities[j]);
	}
	XFREE(MTYPE_TMP, communities);

	return (invalid > 0) ? false : true;
}

/* Set lcommunity-list.  */
int lcommunity_list_set(struct community_list_handler *ch, const char *name,
			const char *str, const char *seq, int direct, int style)
{
	struct community_entry *entry = NULL;
	struct community_list *list;
	struct lcommunity *lcom = NULL;
	regex_t *regex = NULL;
	int64_t seqnum = COMMUNITY_SEQ_NUMBER_AUTO;

	if (seq)
		seqnum = (int64_t)atol(seq);

	/* Get community list. */
	list = community_list_get(ch, name, LARGE_COMMUNITY_LIST_MASTER);

	/* When community-list already has entry, new entry should have same
	   style.  If you want to have mixed style community-list, you can
	   comment out this check.  */
	if (!community_list_empty_p(list)) {
		struct community_entry *first;

		first = list->head;

		if (style != first->style) {
			return (first->style == COMMUNITY_LIST_STANDARD
					? COMMUNITY_LIST_ERR_STANDARD_CONFLICT
					: COMMUNITY_LIST_ERR_EXPANDED_CONFLICT);
		}
	}

	if (str) {
		if (style == LARGE_COMMUNITY_LIST_STANDARD)
			lcom = lcommunity_str2com(str);
		else
			regex = bgp_regcomp(str);

		if (!lcom && !regex)
			return COMMUNITY_LIST_ERR_MALFORMED_VAL;
	}

	entry = community_entry_new();
	entry->direct = direct;
	entry->style = style;
	entry->u.lcom = lcom;
	entry->reg = regex;
	entry->seq = seqnum;
	entry->config =
		(regex ? XSTRDUP(MTYPE_COMMUNITY_LIST_CONFIG, str) : NULL);

	/* Do not put duplicated community entry.  */
	if (community_list_dup_check(list, entry))
		community_entry_free(entry);
	else {
		community_list_entry_add(list, entry, ch,
					 LARGE_COMMUNITY_LIST_MASTER);
		route_map_notify_dependencies(name, RMAP_EVENT_LLIST_ADDED);
	}

	return 0;
}

/* Unset community-list.  When str is NULL, delete all of
   community-list entry belongs to the specified name.  */
void lcommunity_list_unset(struct community_list_handler *ch, const char *name,
			   const char *str, const char *seq, int direct,
			   int style)
{
	struct community_list_master *cm = NULL;
	struct community_entry *entry = NULL;
	struct community_list *list;
	struct lcommunity *lcom = NULL;
	regex_t *regex = NULL;

	/* Lookup community list.  */
	list = community_list_lookup(ch, name, 0, LARGE_COMMUNITY_LIST_MASTER);
	if (list == NULL)
		return;

	cm = community_list_master_lookup(ch, LARGE_COMMUNITY_LIST_MASTER);
	/* Delete all of entry belongs to this community-list.  */
	if (!str) {
		community_list_delete(cm, list);
		route_map_notify_dependencies(name, RMAP_EVENT_LLIST_DELETED);
		return;
	}

	if (style == LARGE_COMMUNITY_LIST_STANDARD)
		lcom = lcommunity_str2com(str);
	else
		regex = bgp_regcomp(str);

	if (!lcom && !regex)
		return;

	if (lcom)
		entry = community_list_entry_lookup(list, lcom, direct);
	else
		entry = community_list_entry_lookup(list, str, direct);

	if (lcom)
		lcommunity_free(&lcom);
	if (regex)
		bgp_regex_free(regex);

	if (!entry)
		return;

	community_list_entry_delete(cm, list, entry);
	route_map_notify_dependencies(name, RMAP_EVENT_LLIST_DELETED);
}

/* Set extcommunity-list.  */
int extcommunity_list_set(struct community_list_handler *ch, const char *name,
			  const char *str, const char *seq, int direct,
			  int style)
{
	struct community_entry *entry = NULL;
	struct community_list *list;
	struct ecommunity *ecom = NULL;
	regex_t *regex = NULL;
	int64_t seqnum = COMMUNITY_SEQ_NUMBER_AUTO;

	if (seq)
		seqnum = (int64_t)atol(seq);

	if (str == NULL)
		return COMMUNITY_LIST_ERR_MALFORMED_VAL;

	/* Get community list. */
	list = community_list_get(ch, name, EXTCOMMUNITY_LIST_MASTER);

	/* When community-list already has entry, new entry should have same
	   style.  If you want to have mixed style community-list, you can
	   comment out this check.  */
	if (!community_list_empty_p(list)) {
		struct community_entry *first;

		first = list->head;

		if (style != first->style) {
			return (first->style == EXTCOMMUNITY_LIST_STANDARD
					? COMMUNITY_LIST_ERR_STANDARD_CONFLICT
					: COMMUNITY_LIST_ERR_EXPANDED_CONFLICT);
		}
	}

	if (style == EXTCOMMUNITY_LIST_STANDARD)
		ecom = ecommunity_str2com(str, 0, 1);
	else
		regex = bgp_regcomp(str);

	if (!ecom && !regex)
		return COMMUNITY_LIST_ERR_MALFORMED_VAL;

	if (ecom)
		ecom->str =
			ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);

	entry = community_entry_new();
	entry->direct = direct;
	entry->style = style;
	if (ecom)
		entry->config = ecommunity_ecom2str(
			ecom, ECOMMUNITY_FORMAT_COMMUNITY_LIST, 0);
	else if (regex)
		entry->config = XSTRDUP(MTYPE_COMMUNITY_LIST_CONFIG, str);

	entry->u.ecom = ecom;
	entry->reg = regex;
	entry->seq = seqnum;

	/* Do not put duplicated community entry.  */
	if (community_list_dup_check(list, entry))
		community_entry_free(entry);
	else {
		community_list_entry_add(list, entry, ch,
					 EXTCOMMUNITY_LIST_MASTER);
		route_map_notify_dependencies(name, RMAP_EVENT_ECLIST_ADDED);
	}

	return 0;
}

/* Unset extcommunity-list.
 *
 * When str is NULL, delete all extcommunity-list entries belonging to the
 * specified name.
 */
void extcommunity_list_unset(struct community_list_handler *ch,
			     const char *name, const char *str, const char *seq,
			     int direct, int style)
{
	struct community_list_master *cm = NULL;
	struct community_entry *entry = NULL;
	struct community_list *list;
	struct ecommunity *ecom = NULL;

	/* Lookup extcommunity list.  */
	list = community_list_lookup(ch, name, 0, EXTCOMMUNITY_LIST_MASTER);
	if (list == NULL)
		return;

	cm = community_list_master_lookup(ch, EXTCOMMUNITY_LIST_MASTER);
	/* Delete all of entry belongs to this extcommunity-list.  */
	if (!str) {
		community_list_delete(cm, list);
		route_map_notify_dependencies(name, RMAP_EVENT_ECLIST_DELETED);
		return;
	}

	if (style == EXTCOMMUNITY_LIST_STANDARD)
		ecom = ecommunity_str2com(str, 0, 1);

	if (ecom) {
		entry = community_list_entry_lookup(list, ecom, direct);
		ecommunity_free(&ecom);
	} else
		entry = community_list_entry_lookup(list, str, direct);

	if (!entry)
		return;

	community_list_entry_delete(cm, list, entry);
	route_map_notify_dependencies(name, RMAP_EVENT_ECLIST_DELETED);
}

/* Initializa community-list.  Return community-list handler.  */
struct community_list_handler *community_list_init(void)
{
	struct community_list_handler *ch;
	ch = XCALLOC(MTYPE_COMMUNITY_LIST_HANDLER,
		     sizeof(struct community_list_handler));

	ch->community_list.hash =
		hash_create_size(4, bgp_clist_hash_key_community_list,
				 bgp_clist_hash_cmp_community_list,
				 "Community List Number Quick Lookup");

	ch->extcommunity_list.hash =
		hash_create_size(4, bgp_clist_hash_key_community_list,
				 bgp_clist_hash_cmp_community_list,
				 "Extended Community List Quick Lookup");

	ch->lcommunity_list.hash =
		hash_create_size(4, bgp_clist_hash_key_community_list,
				 bgp_clist_hash_cmp_community_list,
				 "Large Community List Quick Lookup");

	return ch;
}

/* Terminate community-list.  */
void community_list_terminate(struct community_list_handler *ch)
{
	struct community_list_master *cm;
	struct community_list *list;

	cm = &ch->community_list;
	while ((list = cm->num.head) != NULL)
		community_list_delete(cm, list);
	while ((list = cm->str.head) != NULL)
		community_list_delete(cm, list);
	hash_free(cm->hash);

	cm = &ch->lcommunity_list;
	while ((list = cm->num.head) != NULL)
		community_list_delete(cm, list);
	while ((list = cm->str.head) != NULL)
		community_list_delete(cm, list);
	hash_free(cm->hash);

	cm = &ch->extcommunity_list;
	while ((list = cm->num.head) != NULL)
		community_list_delete(cm, list);
	while ((list = cm->str.head) != NULL)
		community_list_delete(cm, list);
	hash_free(cm->hash);

	XFREE(MTYPE_COMMUNITY_LIST_HANDLER, ch);
}

static int bgp_community_list_vector_walker(struct hash_bucket *bucket,
					    void *data)
{
	vector *comps = data;
	struct community_list *list = bucket->data;

	vector_set(*comps, XSTRDUP(MTYPE_COMPLETION, list->name));

	return 1;
}

static void bgp_community_list_cmd_completion(vector comps,
					      struct cmd_token *token)
{
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist, COMMUNITY_LIST_MASTER);

	hash_walk(cm->hash, bgp_community_list_vector_walker, &comps);
}

static void bgp_lcommunity_list_cmd_completion(vector comps,
					       struct cmd_token *token)
{
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist,
					  LARGE_COMMUNITY_LIST_MASTER);

	hash_walk(cm->hash, bgp_community_list_vector_walker, &comps);
}

static void bgp_extcommunity_list_cmd_completion(vector comps,
						 struct cmd_token *token)
{
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist, EXTCOMMUNITY_LIST_MASTER);

	hash_walk(cm->hash, bgp_community_list_vector_walker, &comps);
}

static const struct cmd_variable_handler community_list_handlers[] = {
	{.tokenname = "COMMUNITY_LIST_NAME",
	 .completions = bgp_community_list_cmd_completion},
	{.completions = NULL}};

static const struct cmd_variable_handler lcommunity_list_handlers[] = {
	{.tokenname = "LCOMMUNITY_LIST_NAME",
	 .completions = bgp_lcommunity_list_cmd_completion},
	{.completions = NULL}};

static const struct cmd_variable_handler extcommunity_list_handlers[] = {
	{.tokenname = "EXTCOMMUNITY_LIST_NAME",
	 .completions = bgp_extcommunity_list_cmd_completion},
	{.completions = NULL}};

void bgp_community_list_command_completion_setup(void)
{
	cmd_variable_handler_register(community_list_handlers);
	cmd_variable_handler_register(lcommunity_list_handlers);
	cmd_variable_handler_register(extcommunity_list_handlers);
}
