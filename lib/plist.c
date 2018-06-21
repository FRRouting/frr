/* Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "command.h"
#include "memory.h"
#include "plist.h"
#include "sockunion.h"
#include "buffer.h"
#include "log.h"
#include "routemap.h"
#include "lib/json.h"
#include "libfrr.h"

#include "plist_int.h"

DEFINE_MTYPE_STATIC(LIB, PREFIX_LIST, "Prefix List")
DEFINE_MTYPE_STATIC(LIB, MPREFIX_LIST_STR, "Prefix List Str")
DEFINE_MTYPE_STATIC(LIB, PREFIX_LIST_ENTRY, "Prefix List Entry")
DEFINE_MTYPE_STATIC(LIB, PREFIX_LIST_TRIE, "Prefix List Trie Table")

/* not currently changeable, code assumes bytes further down */
#define PLC_BITS	8
#define PLC_LEN		(1 << PLC_BITS)
#define PLC_MAXLEVELV4	2	/* /24 for IPv4 */
#define PLC_MAXLEVELV6	4	/* /48 for IPv6 */
#define PLC_MAXLEVEL	4	/* max(v4,v6) */

struct pltrie_entry {
	union {
		struct pltrie_table *next_table;
		struct prefix_list_entry *final_chain;
	};

	struct prefix_list_entry *up_chain;
};

struct pltrie_table {
	struct pltrie_entry entries[PLC_LEN];
};

/* List of struct prefix_list. */
struct prefix_list_list {
	struct prefix_list *head;
	struct prefix_list *tail;
};

/* Master structure of prefix_list. */
struct prefix_master {
	/* List of prefix_list which name is number. */
	struct prefix_list_list num;

	/* List of prefix_list which name is string. */
	struct prefix_list_list str;

	/* Whether sequential number is used. */
	bool seqnum;

	/* The latest update. */
	struct prefix_list *recent;

	/* Hook function which is executed when new prefix_list is added. */
	void (*add_hook)(struct prefix_list *);

	/* Hook function which is executed when prefix_list is deleted. */
	void (*delete_hook)(struct prefix_list *);

	/* number of bytes that have a trie level */
	size_t trie_depth;
};

/* Static structure of IPv4 prefix_list's master. */
static struct prefix_master prefix_master_ipv4 = {
	{NULL, NULL}, {NULL, NULL}, 1, NULL, NULL, NULL, PLC_MAXLEVELV4,
};

/* Static structure of IPv6 prefix-list's master. */
static struct prefix_master prefix_master_ipv6 = {
	{NULL, NULL}, {NULL, NULL}, 1, NULL, NULL, NULL, PLC_MAXLEVELV6,
};

/* Static structure of BGP ORF prefix_list's master. */
static struct prefix_master prefix_master_orf_v4 = {
	{NULL, NULL}, {NULL, NULL}, 1, NULL, NULL, NULL, PLC_MAXLEVELV4,
};

/* Static structure of BGP ORF prefix_list's master. */
static struct prefix_master prefix_master_orf_v6 = {
	{NULL, NULL}, {NULL, NULL}, 1, NULL, NULL, NULL, PLC_MAXLEVELV6,
};

static struct prefix_master *prefix_master_get(afi_t afi, int orf)
{
	if (afi == AFI_IP)
		return orf ? &prefix_master_orf_v4 : &prefix_master_ipv4;
	if (afi == AFI_IP6)
		return orf ? &prefix_master_orf_v6 : &prefix_master_ipv6;
	return NULL;
}

const char *prefix_list_name(struct prefix_list *plist)
{
	return plist->name;
}

afi_t prefix_list_afi(struct prefix_list *plist)
{
	if (plist->master == &prefix_master_ipv4
	    || plist->master == &prefix_master_orf_v4)
		return AFI_IP;
	return AFI_IP6;
}

/* Lookup prefix_list from list of prefix_list by name. */
static struct prefix_list *prefix_list_lookup_do(afi_t afi, int orf,
						 const char *name)
{
	struct prefix_list *plist;
	struct prefix_master *master;

	if (name == NULL)
		return NULL;

	master = prefix_master_get(afi, orf);
	if (master == NULL)
		return NULL;

	for (plist = master->num.head; plist; plist = plist->next)
		if (strcmp(plist->name, name) == 0)
			return plist;

	for (plist = master->str.head; plist; plist = plist->next)
		if (strcmp(plist->name, name) == 0)
			return plist;

	return NULL;
}

struct prefix_list *prefix_list_lookup(afi_t afi, const char *name)
{
	return prefix_list_lookup_do(afi, 0, name);
}

struct prefix_list *prefix_bgp_orf_lookup(afi_t afi, const char *name)
{
	return prefix_list_lookup_do(afi, 1, name);
}

static struct prefix_list *prefix_list_new(void)
{
	struct prefix_list *new;

	new = XCALLOC(MTYPE_PREFIX_LIST, sizeof(struct prefix_list));
	return new;
}

static void prefix_list_free(struct prefix_list *plist)
{
	XFREE(MTYPE_PREFIX_LIST, plist);
}

static struct prefix_list_entry *prefix_list_entry_new(void)
{
	struct prefix_list_entry *new;

	new = XCALLOC(MTYPE_PREFIX_LIST_ENTRY,
		      sizeof(struct prefix_list_entry));
	return new;
}

static void prefix_list_entry_free(struct prefix_list_entry *pentry)
{
	XFREE(MTYPE_PREFIX_LIST_ENTRY, pentry);
}

/* Insert new prefix list to list of prefix_list.  Each prefix_list
   is sorted by the name. */
static struct prefix_list *prefix_list_insert(afi_t afi, int orf,
					      const char *name)
{
	unsigned int i;
	long number;
	struct prefix_list *plist;
	struct prefix_list *point;
	struct prefix_list_list *list;
	struct prefix_master *master;

	master = prefix_master_get(afi, orf);
	if (master == NULL)
		return NULL;

	/* Allocate new prefix_list and copy given name. */
	plist = prefix_list_new();
	plist->name = XSTRDUP(MTYPE_MPREFIX_LIST_STR, name);
	plist->master = master;
	plist->trie =
		XCALLOC(MTYPE_PREFIX_LIST_TRIE, sizeof(struct pltrie_table));

	/* If name is made by all digit character.  We treat it as
	   number. */
	for (number = 0, i = 0; i < strlen(name); i++) {
		if (isdigit((int)name[i]))
			number = (number * 10) + (name[i] - '0');
		else
			break;
	}

	/* In case of name is all digit character */
	if (i == strlen(name)) {
		plist->type = PREFIX_TYPE_NUMBER;

		/* Set prefix_list to number list. */
		list = &master->num;

		for (point = list->head; point; point = point->next)
			if (atol(point->name) >= number)
				break;
	} else {
		plist->type = PREFIX_TYPE_STRING;

		/* Set prefix_list to string list. */
		list = &master->str;

		/* Set point to insertion point. */
		for (point = list->head; point; point = point->next)
			if (strcmp(point->name, name) >= 0)
				break;
	}

	/* In case of this is the first element of master. */
	if (list->head == NULL) {
		list->head = list->tail = plist;
		return plist;
	}

	/* In case of insertion is made at the tail of access_list. */
	if (point == NULL) {
		plist->prev = list->tail;
		list->tail->next = plist;
		list->tail = plist;
		return plist;
	}

	/* In case of insertion is made at the head of access_list. */
	if (point == list->head) {
		plist->next = list->head;
		list->head->prev = plist;
		list->head = plist;
		return plist;
	}

	/* Insertion is made at middle of the access_list. */
	plist->next = point;
	plist->prev = point->prev;

	if (point->prev)
		point->prev->next = plist;
	point->prev = plist;

	return plist;
}

static struct prefix_list *prefix_list_get(afi_t afi, int orf, const char *name)
{
	struct prefix_list *plist;

	plist = prefix_list_lookup_do(afi, orf, name);

	if (plist == NULL)
		plist = prefix_list_insert(afi, orf, name);
	return plist;
}

static void prefix_list_trie_del(struct prefix_list *plist,
				 struct prefix_list_entry *pentry);

/* Delete prefix-list from prefix_list_master and free it. */
static void prefix_list_delete(struct prefix_list *plist)
{
	struct prefix_list_list *list;
	struct prefix_master *master;
	struct prefix_list_entry *pentry;
	struct prefix_list_entry *next;

	/* If prefix-list contain prefix_list_entry free all of it. */
	for (pentry = plist->head; pentry; pentry = next) {
		next = pentry->next;
		prefix_list_trie_del(plist, pentry);
		prefix_list_entry_free(pentry);
		plist->count--;
	}

	master = plist->master;

	if (plist->type == PREFIX_TYPE_NUMBER)
		list = &master->num;
	else
		list = &master->str;

	if (plist->next)
		plist->next->prev = plist->prev;
	else
		list->tail = plist->prev;

	if (plist->prev)
		plist->prev->next = plist->next;
	else
		list->head = plist->next;

	if (plist->desc)
		XFREE(MTYPE_TMP, plist->desc);

	/* Make sure master's recent changed prefix-list information is
	   cleared. */
	master->recent = NULL;

	route_map_notify_dependencies(plist->name, RMAP_EVENT_PLIST_DELETED);

	if (master->delete_hook)
		(*master->delete_hook)(plist);

	if (plist->name)
		XFREE(MTYPE_MPREFIX_LIST_STR, plist->name);

	XFREE(MTYPE_PREFIX_LIST_TRIE, plist->trie);

	prefix_list_free(plist);
}

static struct prefix_list_entry *
prefix_list_entry_make(struct prefix *prefix, enum prefix_list_type type,
		       int64_t seq, int le, int ge, int any)
{
	struct prefix_list_entry *pentry;

	pentry = prefix_list_entry_new();

	if (any)
		pentry->any = 1;

	prefix_copy(&pentry->prefix, prefix);
	pentry->type = type;
	pentry->seq = seq;
	pentry->le = le;
	pentry->ge = ge;

	return pentry;
}

/* Add hook function. */
void prefix_list_add_hook(void (*func)(struct prefix_list *plist))
{
	prefix_master_ipv4.add_hook = func;
	prefix_master_ipv6.add_hook = func;
}

/* Delete hook function. */
void prefix_list_delete_hook(void (*func)(struct prefix_list *plist))
{
	prefix_master_ipv4.delete_hook = func;
	prefix_master_ipv6.delete_hook = func;
}

/* Calculate new sequential number. */
static int64_t prefix_new_seq_get(struct prefix_list *plist)
{
	int64_t maxseq;
	int64_t newseq;
	struct prefix_list_entry *pentry;

	maxseq = newseq = 0;

	for (pentry = plist->head; pentry; pentry = pentry->next) {
		if (maxseq < pentry->seq)
			maxseq = pentry->seq;
	}

	newseq = ((maxseq / 5) * 5) + 5;

	return newseq;
}

/* Return prefix list entry which has same seq number. */
static struct prefix_list_entry *prefix_seq_check(struct prefix_list *plist,
						  int64_t seq)
{
	struct prefix_list_entry *pentry;

	for (pentry = plist->head; pentry; pentry = pentry->next)
		if (pentry->seq == seq)
			return pentry;
	return NULL;
}

static struct prefix_list_entry *
prefix_list_entry_lookup(struct prefix_list *plist, struct prefix *prefix,
			 enum prefix_list_type type, int64_t seq,
			 int le, int ge)
{
	struct prefix_list_entry *pentry;

	for (pentry = plist->head; pentry; pentry = pentry->next)
		if (prefix_same(&pentry->prefix, prefix)
		    && pentry->type == type) {
			if (seq >= 0 && pentry->seq != seq)
				continue;

			if (pentry->le != le)
				continue;
			if (pentry->ge != ge)
				continue;

			return pentry;
		}

	return NULL;
}

static void trie_walk_affected(size_t validbits, struct pltrie_table *table,
			       uint8_t byte, struct prefix_list_entry *object,
			       void (*fn)(struct prefix_list_entry *object,
					  struct prefix_list_entry **updptr))
{
	uint8_t mask;
	uint16_t bwalk;

	if (validbits > PLC_BITS) {
		fn(object, &table->entries[byte].final_chain);
		return;
	}

	mask = (1 << (8 - validbits)) - 1;
	for (bwalk = byte & ~mask; bwalk <= byte + mask; bwalk++) {
		fn(object, &table->entries[bwalk].up_chain);
	}
}

static void trie_uninstall_fn(struct prefix_list_entry *object,
			      struct prefix_list_entry **updptr)
{
	for (; *updptr; updptr = &(*updptr)->next_best)
		if (*updptr == object) {
			*updptr = object->next_best;
			break;
		}
}

static int trie_table_empty(struct pltrie_table *table)
{
	size_t i;
	for (i = 0; i < PLC_LEN; i++)
		if (table->entries[i].next_table || table->entries[i].up_chain)
			return 0;
	return 1;
}

static void prefix_list_trie_del(struct prefix_list *plist,
				 struct prefix_list_entry *pentry)
{
	size_t depth, maxdepth = plist->master->trie_depth;
	uint8_t *bytes = pentry->prefix.u.val;
	size_t validbits = pentry->prefix.prefixlen;
	struct pltrie_table *table, **tables[PLC_MAXLEVEL];

	table = plist->trie;
	for (depth = 0; validbits > PLC_BITS && depth < maxdepth - 1; depth++) {
		uint8_t byte = bytes[depth];
		assert(table->entries[byte].next_table);

		tables[depth + 1] = &table->entries[byte].next_table;
		table = table->entries[byte].next_table;

		validbits -= PLC_BITS;
	}

	trie_walk_affected(validbits, table, bytes[depth], pentry,
			   trie_uninstall_fn);

	for (; depth > 0; depth--)
		if (trie_table_empty(*tables[depth])) {
			XFREE(MTYPE_PREFIX_LIST_TRIE, *tables[depth]);
			*tables[depth] = NULL;
		}
}


static void prefix_list_entry_delete(struct prefix_list *plist,
				     struct prefix_list_entry *pentry,
				     int update_list)
{
	if (plist == NULL || pentry == NULL)
		return;

	prefix_list_trie_del(plist, pentry);

	if (pentry->prev)
		pentry->prev->next = pentry->next;
	else
		plist->head = pentry->next;
	if (pentry->next)
		pentry->next->prev = pentry->prev;
	else
		plist->tail = pentry->prev;

	prefix_list_entry_free(pentry);

	plist->count--;

	if (update_list) {
		route_map_notify_dependencies(plist->name,
					      RMAP_EVENT_PLIST_DELETED);
		if (plist->master->delete_hook)
			(*plist->master->delete_hook)(plist);

		if (plist->head == NULL && plist->tail == NULL
		    && plist->desc == NULL)
			prefix_list_delete(plist);
		else
			plist->master->recent = plist;
	}
}

static void trie_install_fn(struct prefix_list_entry *object,
			    struct prefix_list_entry **updptr)
{
	while (*updptr) {
		if (*updptr == object)
			return;
		if ((*updptr)->prefix.prefixlen < object->prefix.prefixlen)
			break;
		if ((*updptr)->prefix.prefixlen == object->prefix.prefixlen
		    && (*updptr)->seq > object->seq)
			break;
		updptr = &(*updptr)->next_best;
	}

	if (!object->next_best)
		object->next_best = *updptr;
	else
		assert(object->next_best == *updptr || !*updptr);

	*updptr = object;
}

static void prefix_list_trie_add(struct prefix_list *plist,
				 struct prefix_list_entry *pentry)
{
	size_t depth = plist->master->trie_depth;
	uint8_t *bytes = pentry->prefix.u.val;
	size_t validbits = pentry->prefix.prefixlen;
	struct pltrie_table *table;

	table = plist->trie;
	while (validbits > PLC_BITS && depth > 1) {
		if (!table->entries[*bytes].next_table)
			table->entries[*bytes].next_table =
				XCALLOC(MTYPE_PREFIX_LIST_TRIE,
					sizeof(struct pltrie_table));
		table = table->entries[*bytes].next_table;
		bytes++;
		depth--;
		validbits -= PLC_BITS;
	}

	trie_walk_affected(validbits, table, *bytes, pentry, trie_install_fn);
}

static void prefix_list_entry_add(struct prefix_list *plist,
				  struct prefix_list_entry *pentry)
{
	struct prefix_list_entry *replace;
	struct prefix_list_entry *point;

	/* Automatic asignment of seq no. */
	if (pentry->seq == -1)
		pentry->seq = prefix_new_seq_get(plist);

	if (plist->tail && pentry->seq > plist->tail->seq)
		point = NULL;
	else {
		/* Is there any same seq prefix list entry? */
		replace = prefix_seq_check(plist, pentry->seq);
		if (replace)
			prefix_list_entry_delete(plist, replace, 0);

		/* Check insert point. */
		for (point = plist->head; point; point = point->next)
			if (point->seq >= pentry->seq)
				break;
	}

	/* In case of this is the first element of the list. */
	pentry->next = point;

	if (point) {
		if (point->prev)
			point->prev->next = pentry;
		else
			plist->head = pentry;

		pentry->prev = point->prev;
		point->prev = pentry;
	} else {
		if (plist->tail)
			plist->tail->next = pentry;
		else
			plist->head = pentry;

		pentry->prev = plist->tail;
		plist->tail = pentry;
	}

	prefix_list_trie_add(plist, pentry);

	/* Increment count. */
	plist->count++;

	/* Run hook function. */
	if (plist->master->add_hook)
		(*plist->master->add_hook)(plist);

	route_map_notify_dependencies(plist->name, RMAP_EVENT_PLIST_ADDED);
	plist->master->recent = plist;
}

/* Return string of prefix_list_type. */
static const char *prefix_list_type_str(struct prefix_list_entry *pentry)
{
	switch (pentry->type) {
	case PREFIX_PERMIT:
		return "permit";
	case PREFIX_DENY:
		return "deny";
	default:
		return "";
	}
}

static int prefix_list_entry_match(struct prefix_list_entry *pentry,
				   struct prefix *p)
{
	int ret;

	if (pentry->prefix.family != p->family)
		return 0;

	ret = prefix_match(&pentry->prefix, p);
	if (!ret)
		return 0;

	/* In case of le nor ge is specified, exact match is performed. */
	if (!pentry->le && !pentry->ge) {
		if (pentry->prefix.prefixlen != p->prefixlen)
			return 0;
	} else {
		if (pentry->le)
			if (p->prefixlen > pentry->le)
				return 0;

		if (pentry->ge)
			if (p->prefixlen < pentry->ge)
				return 0;
	}
	return 1;
}

enum prefix_list_type prefix_list_apply_which_prefix(struct prefix_list *plist,
						     struct prefix **which,
						     void *object)
{
	struct prefix_list_entry *pentry, *pbest = NULL;

	struct prefix *p = (struct prefix *)object;
	uint8_t *byte = p->u.val;
	size_t depth;
	size_t validbits = p->prefixlen;
	struct pltrie_table *table;

	if (plist == NULL) {
		if (which)
			*which = NULL;
		return PREFIX_DENY;
	}

	if (plist->count == 0) {
		if (which)
			*which = NULL;
		return PREFIX_PERMIT;
	}

	depth = plist->master->trie_depth;
	table = plist->trie;
	while (1) {
		for (pentry = table->entries[*byte].up_chain; pentry;
		     pentry = pentry->next_best) {
			if (pbest && pbest->seq < pentry->seq)
				continue;
			if (prefix_list_entry_match(pentry, p))
				pbest = pentry;
		}

		if (validbits <= PLC_BITS)
			break;
		validbits -= PLC_BITS;

		if (--depth) {
			if (!table->entries[*byte].next_table)
				break;

			table = table->entries[*byte].next_table;
			byte++;
			continue;
		}

		for (pentry = table->entries[*byte].final_chain; pentry;
		     pentry = pentry->next_best) {
			if (pbest && pbest->seq < pentry->seq)
				continue;
			if (prefix_list_entry_match(pentry, p))
				pbest = pentry;
		}
		break;
	}

	if (which) {
		if (pbest)
			*which = &pbest->prefix;
		else
			*which = NULL;
	}

	if (pbest == NULL)
		return PREFIX_DENY;

	return pbest->type;
}

static void __attribute__((unused)) prefix_list_print(struct prefix_list *plist)
{
	struct prefix_list_entry *pentry;

	if (plist == NULL)
		return;

	printf("ip prefix-list %s: %d entries\n", plist->name, plist->count);

	for (pentry = plist->head; pentry; pentry = pentry->next) {
		if (pentry->any)
			printf("any %s\n", prefix_list_type_str(pentry));
		else {
			struct prefix *p;
			char buf[BUFSIZ];

			p = &pentry->prefix;

			printf("  seq %" PRId64 " %s %s/%d", pentry->seq,
			       prefix_list_type_str(pentry),
			       inet_ntop(p->family, p->u.val, buf, BUFSIZ),
			       p->prefixlen);
			if (pentry->ge)
				printf(" ge %d", pentry->ge);
			if (pentry->le)
				printf(" le %d", pentry->le);
			printf("\n");
		}
	}
}

/* Retrun 1 when plist already include pentry policy. */
static struct prefix_list_entry *
prefix_entry_dup_check(struct prefix_list *plist, struct prefix_list_entry *new)
{
	size_t depth, maxdepth = plist->master->trie_depth;
	uint8_t byte, *bytes = new->prefix.u.val;
	size_t validbits = new->prefix.prefixlen;
	struct pltrie_table *table;
	struct prefix_list_entry *pentry;
	int64_t seq = 0;

	if (new->seq == -1)
		seq = prefix_new_seq_get(plist);
	else
		seq = new->seq;

	table = plist->trie;
	for (depth = 0; validbits > PLC_BITS && depth < maxdepth - 1; depth++) {
		byte = bytes[depth];
		if (!table->entries[byte].next_table)
			return NULL;

		table = table->entries[byte].next_table;
		validbits -= PLC_BITS;
	}

	byte = bytes[depth];
	if (validbits > PLC_BITS)
		pentry = table->entries[byte].final_chain;
	else
		pentry = table->entries[byte].up_chain;

	for (; pentry; pentry = pentry->next_best) {
		if (prefix_same(&pentry->prefix, &new->prefix)
		    && pentry->type == new->type && pentry->le == new->le
		    && pentry->ge == new->ge && pentry->seq != seq)
			return pentry;
	}
	return NULL;
}

static int vty_invalid_prefix_range(struct vty *vty, const char *prefix)
{
	vty_out(vty,
		"%% Invalid prefix range for %s, make sure: len < ge-value <= le-value\n",
		prefix);
	return CMD_WARNING_CONFIG_FAILED;
}

static int vty_prefix_list_install(struct vty *vty, afi_t afi, const char *name,
				   const char *seq, const char *typestr,
				   const char *prefix, const char *ge,
				   const char *le)
{
	int ret;
	enum prefix_list_type type;
	struct prefix_list *plist;
	struct prefix_list_entry *pentry;
	struct prefix_list_entry *dup;
	struct prefix p, p_tmp;
	int any = 0;
	int64_t seqnum = -1;
	int lenum = 0;
	int genum = 0;

	if (name == NULL || prefix == NULL || typestr == NULL) {
		vty_out(vty, "%% Missing prefix or type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Sequential number. */
	if (seq)
		seqnum = (int64_t)atol(seq);

	/* ge and le number */
	if (ge)
		genum = atoi(ge);
	if (le)
		lenum = atoi(le);

	/* Check filter type. */
	if (strncmp("permit", typestr, 1) == 0)
		type = PREFIX_PERMIT;
	else if (strncmp("deny", typestr, 1) == 0)
		type = PREFIX_DENY;
	else {
		vty_out(vty, "%% prefix type must be permit or deny\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* "any" is special token for matching any IPv4 addresses.  */
	switch (afi) {
	case AFI_IP:
		if (strncmp("any", prefix, strlen(prefix)) == 0) {
			ret = str2prefix_ipv4("0.0.0.0/0",
					      (struct prefix_ipv4 *)&p);
			genum = 0;
			lenum = IPV4_MAX_BITLEN;
			any = 1;
		} else
			ret = str2prefix_ipv4(prefix, (struct prefix_ipv4 *)&p);

		if (ret <= 0) {
			vty_out(vty, "%% Malformed IPv4 prefix\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* make a copy to verify prefix matches mask length */
		prefix_copy(&p_tmp, &p);
		apply_mask_ipv4((struct prefix_ipv4 *)&p_tmp);

		break;
	case AFI_IP6:
		if (strncmp("any", prefix, strlen(prefix)) == 0) {
			ret = str2prefix_ipv6("::/0", (struct prefix_ipv6 *)&p);
			genum = 0;
			lenum = IPV6_MAX_BITLEN;
			any = 1;
		} else
			ret = str2prefix_ipv6(prefix, (struct prefix_ipv6 *)&p);

		if (ret <= 0) {
			vty_out(vty, "%% Malformed IPv6 prefix\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* make a copy to verify prefix matches mask length */
		prefix_copy(&p_tmp, &p);
		apply_mask_ipv6((struct prefix_ipv6 *)&p_tmp);

		break;
	case AFI_L2VPN:
	default:
		vty_out(vty, "%% Unrecognized AFI (%d)\n", afi);
		return CMD_WARNING_CONFIG_FAILED;
		break;
	}

	/* If prefix has bits not under the mask, adjust it to fit */
	if (!prefix_same(&p_tmp, &p)) {
		char buf[PREFIX2STR_BUFFER];
		char buf_tmp[PREFIX2STR_BUFFER];
		prefix2str(&p, buf, sizeof(buf));
		prefix2str(&p_tmp, buf_tmp, sizeof(buf_tmp));
		zlog_warn(
			"Prefix-list %s prefix changed from %s to %s to match length",
			name, buf, buf_tmp);
		p = p_tmp;
	}

	/* ge and le check. */
	if (genum && (genum <= p.prefixlen))
		return vty_invalid_prefix_range(vty, prefix);

	if (lenum && (lenum < p.prefixlen))
		return vty_invalid_prefix_range(vty, prefix);

	if (lenum && (genum > lenum))
		return vty_invalid_prefix_range(vty, prefix);

	if (genum && (lenum == (afi == AFI_IP ? 32 : 128)))
		lenum = 0;

	/* Get prefix_list with name. */
	plist = prefix_list_get(afi, 0, name);

	/* Make prefix entry. */
	pentry = prefix_list_entry_make(&p, type, seqnum, lenum, genum, any);

	/* Check same policy. */
	dup = prefix_entry_dup_check(plist, pentry);

	if (dup) {
		prefix_list_entry_free(pentry);
		return CMD_SUCCESS;
	}

	/* Install new filter to the access_list. */
	prefix_list_entry_add(plist, pentry);

	return CMD_SUCCESS;
}

static int vty_prefix_list_uninstall(struct vty *vty, afi_t afi,
				     const char *name, const char *seq,
				     const char *typestr, const char *prefix,
				     const char *ge, const char *le)
{
	int ret;
	enum prefix_list_type type;
	struct prefix_list *plist;
	struct prefix_list_entry *pentry;
	struct prefix p;
	int64_t seqnum = -1;
	int lenum = 0;
	int genum = 0;

	/* Check prefix list name. */
	plist = prefix_list_lookup(afi, name);
	if (!plist) {
		vty_out(vty, "%% Can't find specified prefix-list\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Only prefix-list name specified, delete the entire prefix-list. */
	if (seq == NULL && typestr == NULL && prefix == NULL && ge == NULL
	    && le == NULL) {
		prefix_list_delete(plist);
		return CMD_SUCCESS;
	}

	/* We must have, at a minimum, both the type and prefix here */
	if ((typestr == NULL) || (prefix == NULL)) {
		vty_out(vty, "%% Both prefix and type required\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check sequence number. */
	if (seq)
		seqnum = (int64_t)atol(seq);

	/* ge and le number */
	if (ge)
		genum = atoi(ge);
	if (le)
		lenum = atoi(le);

	/* Check of filter type. */
	if (strncmp("permit", typestr, 1) == 0)
		type = PREFIX_PERMIT;
	else if (strncmp("deny", typestr, 1) == 0)
		type = PREFIX_DENY;
	else {
		vty_out(vty, "%% prefix type must be permit or deny\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* "any" is special token for matching any IPv4 addresses.  */
	if (afi == AFI_IP) {
		if (strncmp("any", prefix, strlen(prefix)) == 0) {
			ret = str2prefix_ipv4("0.0.0.0/0",
					      (struct prefix_ipv4 *)&p);
			genum = 0;
			lenum = IPV4_MAX_BITLEN;
		} else
			ret = str2prefix_ipv4(prefix, (struct prefix_ipv4 *)&p);

		if (ret <= 0) {
			vty_out(vty, "%% Malformed IPv4 prefix\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else if (afi == AFI_IP6) {
		if (strncmp("any", prefix, strlen(prefix)) == 0) {
			ret = str2prefix_ipv6("::/0", (struct prefix_ipv6 *)&p);
			genum = 0;
			lenum = IPV6_MAX_BITLEN;
		} else
			ret = str2prefix_ipv6(prefix, (struct prefix_ipv6 *)&p);

		if (ret <= 0) {
			vty_out(vty, "%% Malformed IPv6 prefix\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Lookup prefix entry. */
	pentry =
		prefix_list_entry_lookup(plist, &p, type, seqnum, lenum, genum);

	if (pentry == NULL) {
		vty_out(vty, "%% Can't find specified prefix-list\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Install new filter to the access_list. */
	prefix_list_entry_delete(plist, pentry, 1);

	return CMD_SUCCESS;
}

static int vty_prefix_list_desc_unset(struct vty *vty, afi_t afi,
				      const char *name)
{
	struct prefix_list *plist;

	plist = prefix_list_lookup(afi, name);
	if (!plist) {
		vty_out(vty, "%% Can't find specified prefix-list\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (plist->desc) {
		XFREE(MTYPE_TMP, plist->desc);
		plist->desc = NULL;
	}

	if (plist->head == NULL && plist->tail == NULL && plist->desc == NULL)
		prefix_list_delete(plist);

	return CMD_SUCCESS;
}

enum display_type {
	normal_display,
	summary_display,
	detail_display,
	sequential_display,
	longer_display,
	first_match_display
};

static void vty_show_prefix_entry(struct vty *vty, afi_t afi,
				  struct prefix_list *plist,
				  struct prefix_master *master,
				  enum display_type dtype, int seqnum)
{
	struct prefix_list_entry *pentry;

	/* Print the name of the protocol */
	vty_out(vty, "%s: ", frr_protoname);

	if (dtype == normal_display) {
		vty_out(vty, "ip%s prefix-list %s: %d entries\n",
			afi == AFI_IP ? "" : "v6", plist->name, plist->count);
		if (plist->desc)
			vty_out(vty, "   Description: %s\n", plist->desc);
	} else if (dtype == summary_display || dtype == detail_display) {
		vty_out(vty, "ip%s prefix-list %s:\n",
			afi == AFI_IP ? "" : "v6", plist->name);

		if (plist->desc)
			vty_out(vty, "   Description: %s\n", plist->desc);

		vty_out(vty,
			"   count: %d, range entries: %d, sequences: %" PRId64 " - %" PRId64 "\n",
			plist->count, plist->rangecount,
			plist->head ? plist->head->seq : 0,
			plist->tail ? plist->tail->seq : 0);
	}

	if (dtype != summary_display) {
		for (pentry = plist->head; pentry; pentry = pentry->next) {
			if (dtype == sequential_display
			    && pentry->seq != seqnum)
				continue;

			vty_out(vty, "   ");

			if (master->seqnum)
				vty_out(vty, "seq %" PRId64 " ", pentry->seq);

			vty_out(vty, "%s ", prefix_list_type_str(pentry));

			if (pentry->any)
				vty_out(vty, "any");
			else {
				struct prefix *p = &pentry->prefix;
				char buf[BUFSIZ];

				vty_out(vty, "%s/%d",
					inet_ntop(p->family, p->u.val, buf,
						  BUFSIZ),
					p->prefixlen);

				if (pentry->ge)
					vty_out(vty, " ge %d", pentry->ge);
				if (pentry->le)
					vty_out(vty, " le %d", pentry->le);
			}

			if (dtype == detail_display
			    || dtype == sequential_display)
				vty_out(vty, " (hit count: %ld, refcount: %ld)",
					pentry->hitcnt, pentry->refcnt);

			vty_out(vty, "\n");
		}
	}
}

static int vty_show_prefix_list(struct vty *vty, afi_t afi, const char *name,
				const char *seq, enum display_type dtype)
{
	struct prefix_list *plist;
	struct prefix_master *master;
	int64_t seqnum = 0;

	master = prefix_master_get(afi, 0);
	if (master == NULL)
		return CMD_WARNING;

	if (seq)
		seqnum = (int64_t)atol(seq);

	if (name) {
		plist = prefix_list_lookup(afi, name);
		if (!plist) {
			vty_out(vty, "%% Can't find specified prefix-list\n");
			return CMD_WARNING;
		}
		vty_show_prefix_entry(vty, afi, plist, master, dtype, seqnum);
	} else {
		if (dtype == detail_display || dtype == summary_display) {
			if (master->recent)
				vty_out(vty,
					"Prefix-list with the last deletion/insertion: %s\n",
					master->recent->name);
		}

		for (plist = master->num.head; plist; plist = plist->next)
			vty_show_prefix_entry(vty, afi, plist, master, dtype,
					      seqnum);

		for (plist = master->str.head; plist; plist = plist->next)
			vty_show_prefix_entry(vty, afi, plist, master, dtype,
					      seqnum);
	}

	return CMD_SUCCESS;
}

static int vty_show_prefix_list_prefix(struct vty *vty, afi_t afi,
				       const char *name, const char *prefix,
				       enum display_type type)
{
	struct prefix_list *plist;
	struct prefix_list_entry *pentry;
	struct prefix p;
	int ret;
	int match;

	plist = prefix_list_lookup(afi, name);
	if (!plist) {
		vty_out(vty, "%% Can't find specified prefix-list\n");
		return CMD_WARNING;
	}

	ret = str2prefix(prefix, &p);
	if (ret <= 0) {
		vty_out(vty, "%% prefix is malformed\n");
		return CMD_WARNING;
	}

	for (pentry = plist->head; pentry; pentry = pentry->next) {
		match = 0;

		if (type == normal_display || type == first_match_display)
			if (prefix_same(&p, &pentry->prefix))
				match = 1;

		if (type == longer_display) {
			if ((p.family == pentry->prefix.family)
			    && (prefix_match(&p, &pentry->prefix)))
				match = 1;
		}

		if (match) {
			vty_out(vty, "   seq %" PRId64 " %s ", pentry->seq,
				prefix_list_type_str(pentry));

			if (pentry->any)
				vty_out(vty, "any");
			else {
				struct prefix *p = &pentry->prefix;
				char buf[BUFSIZ];

				vty_out(vty, "%s/%d",
					inet_ntop(p->family, p->u.val, buf,
						  BUFSIZ),
					p->prefixlen);

				if (pentry->ge)
					vty_out(vty, " ge %d", pentry->ge);
				if (pentry->le)
					vty_out(vty, " le %d", pentry->le);
			}

			if (type == normal_display
			    || type == first_match_display)
				vty_out(vty, " (hit count: %ld, refcount: %ld)",
					pentry->hitcnt, pentry->refcnt);

			vty_out(vty, "\n");

			if (type == first_match_display)
				return CMD_SUCCESS;
		}
	}
	return CMD_SUCCESS;
}

static int vty_clear_prefix_list(struct vty *vty, afi_t afi, const char *name,
				 const char *prefix)
{
	struct prefix_master *master;
	struct prefix_list *plist;
	struct prefix_list_entry *pentry;
	int ret;
	struct prefix p;

	master = prefix_master_get(afi, 0);
	if (master == NULL)
		return CMD_WARNING;

	if (name == NULL && prefix == NULL) {
		for (plist = master->num.head; plist; plist = plist->next)
			for (pentry = plist->head; pentry;
			     pentry = pentry->next)
				pentry->hitcnt = 0;

		for (plist = master->str.head; plist; plist = plist->next)
			for (pentry = plist->head; pentry;
			     pentry = pentry->next)
				pentry->hitcnt = 0;
	} else {
		plist = prefix_list_lookup(afi, name);
		if (!plist) {
			vty_out(vty, "%% Can't find specified prefix-list\n");
			return CMD_WARNING;
		}

		if (prefix) {
			ret = str2prefix(prefix, &p);
			if (ret <= 0) {
				vty_out(vty, "%% prefix is malformed\n");
				return CMD_WARNING;
			}
		}

		for (pentry = plist->head; pentry; pentry = pentry->next) {
			if (prefix) {
				if (pentry->prefix.family == p.family
				    && prefix_match(&pentry->prefix, &p))
					pentry->hitcnt = 0;
			} else
				pentry->hitcnt = 0;
		}
	}
	return CMD_SUCCESS;
}

#ifndef VTYSH_EXTRACT_PL
#include "lib/plist_clippy.c"
#endif

DEFPY (ip_prefix_list,
       ip_prefix_list_cmd,
       "ip prefix-list WORD [seq (1-4294967295)] <deny|permit>$action <any$dest|A.B.C.D/M$dest [{ge (0-32)|le (0-32)}]>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
	return vty_prefix_list_install(vty, AFI_IP, prefix_list, seq_str,
				       action, dest, ge_str, le_str);
}

DEFPY (no_ip_prefix_list,
       no_ip_prefix_list_cmd,
       "no ip prefix-list WORD [seq (1-4294967295)] <deny|permit>$action <any$dest|A.B.C.D/M$dest [{ge (0-32)|le (0-32)}]>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
	return vty_prefix_list_uninstall(vty, AFI_IP, prefix_list, seq_str,
					 action, dest, ge_str, le_str);
}

DEFPY (no_ip_prefix_list_all,
       no_ip_prefix_list_all_cmd,
       "no ip prefix-list WORD",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
	return vty_prefix_list_uninstall(vty, AFI_IP, prefix_list, NULL, NULL,
					 NULL, NULL, NULL);
}

DEFPY (ip_prefix_list_sequence_number,
       ip_prefix_list_sequence_number_cmd,
       "[no] ip prefix-list sequence-number",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
	prefix_master_ipv4.seqnum = no ? false : true;
	return CMD_SUCCESS;
}

DEFUN (ip_prefix_list_description,
       ip_prefix_list_description_cmd,
       "ip prefix-list WORD description LINE...",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
	int idx_word = 2;
	int idx_line = 4;
	struct prefix_list *plist;

	plist = prefix_list_get(AFI_IP, 0, argv[idx_word]->arg);

	if (plist->desc) {
		XFREE(MTYPE_TMP, plist->desc);
		plist->desc = NULL;
	}
	plist->desc = argv_concat(argv, argc, idx_line);

	return CMD_SUCCESS;
}

DEFUN (no_ip_prefix_list_description,
       no_ip_prefix_list_description_cmd,
       "no ip prefix-list WORD description",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")
{
	int idx_word = 3;
	return vty_prefix_list_desc_unset(vty, AFI_IP, argv[idx_word]->arg);
}

/* ALIAS_FIXME */
DEFUN (no_ip_prefix_list_description_comment,
       no_ip_prefix_list_description_comment_cmd,
       "no ip prefix-list WORD description LINE...",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
	return no_ip_prefix_list_description(self, vty, argc, argv);
}

DEFPY (show_ip_prefix_list,
       show_ip_prefix_list_cmd,
       "show ip prefix-list [WORD [seq$dseq (1-4294967295)$arg]]",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")
{
	enum display_type dtype = normal_display;
	if (dseq)
		dtype = sequential_display;

	return vty_show_prefix_list(vty, AFI_IP, prefix_list, arg_str, dtype);
}

DEFPY (show_ip_prefix_list_prefix,
       show_ip_prefix_list_prefix_cmd,
       "show ip prefix-list WORD A.B.C.D/M$prefix [longer$dl|first-match$dfm]",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Lookup longer prefix\n"
       "First matched prefix\n")
{
	enum display_type dtype = normal_display;
	if (dl)
		dtype = longer_display;
	else if (dfm)
		dtype = first_match_display;

	return vty_show_prefix_list_prefix(vty, AFI_IP, prefix_list, prefix_str,
					   dtype);
}

DEFPY (show_ip_prefix_list_summary,
       show_ip_prefix_list_summary_cmd,
       "show ip prefix-list summary [WORD$prefix_list]",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")
{
	return vty_show_prefix_list(vty, AFI_IP, prefix_list, NULL,
				    summary_display);
}

DEFPY (show_ip_prefix_list_detail,
       show_ip_prefix_list_detail_cmd,
       "show ip prefix-list detail [WORD$prefix_list]",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")
{
	return vty_show_prefix_list(vty, AFI_IP, prefix_list, NULL,
				    detail_display);
}

DEFPY (clear_ip_prefix_list,
       clear_ip_prefix_list_cmd,
       "clear ip prefix-list [WORD [A.B.C.D/M$prefix]]",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
	return vty_clear_prefix_list(vty, AFI_IP, prefix_list, prefix_str);
}

DEFPY (ipv6_prefix_list,
       ipv6_prefix_list_cmd,
       "ipv6 prefix-list WORD [seq (1-4294967295)] <deny|permit>$action <any$dest|X:X::X:X/M$dest [{ge (0-128)|le (0-128)}]>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
	return vty_prefix_list_install(vty, AFI_IP6, prefix_list, seq_str,
				       action, dest, ge_str, le_str);
}

DEFPY (no_ipv6_prefix_list,
       no_ipv6_prefix_list_cmd,
       "no ipv6 prefix-list WORD [seq (1-4294967295)] <deny|permit>$action <any$dest|X:X::X:X/M$dest [{ge (0-128)|le (0-128)}]>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
	return vty_prefix_list_uninstall(vty, AFI_IP6, prefix_list, seq_str,
					 action, dest, ge_str, le_str);
}

DEFPY (no_ipv6_prefix_list_all,
       no_ipv6_prefix_list_all_cmd,
       "no ipv6 prefix-list WORD",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
	return vty_prefix_list_uninstall(vty, AFI_IP6, prefix_list, NULL, NULL,
					 NULL, NULL, NULL);
}

DEFPY (ipv6_prefix_list_sequence_number,
       ipv6_prefix_list_sequence_number_cmd,
       "[no] ipv6 prefix-list sequence-number",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
	prefix_master_ipv6.seqnum = no ? false : true;
	return CMD_SUCCESS;
}

DEFUN (ipv6_prefix_list_description,
       ipv6_prefix_list_description_cmd,
       "ipv6 prefix-list WORD description LINE...",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
	int idx_word = 2;
	int iddx_line = 4;
	struct prefix_list *plist;

	plist = prefix_list_get(AFI_IP6, 0, argv[idx_word]->arg);

	if (plist->desc) {
		XFREE(MTYPE_TMP, plist->desc);
		plist->desc = NULL;
	}
	plist->desc = argv_concat(argv, argc, iddx_line);

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_prefix_list_description,
       no_ipv6_prefix_list_description_cmd,
       "no ipv6 prefix-list WORD description",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")
{
	int idx_word = 3;
	return vty_prefix_list_desc_unset(vty, AFI_IP6, argv[idx_word]->arg);
}

/* ALIAS_FIXME */
DEFUN (no_ipv6_prefix_list_description_comment,
       no_ipv6_prefix_list_description_comment_cmd,
       "no ipv6 prefix-list WORD description LINE...",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
	return no_ipv6_prefix_list_description(self, vty, argc, argv);
}


DEFPY (show_ipv6_prefix_list,
       show_ipv6_prefix_list_cmd,
       "show ipv6 prefix-list [WORD [seq$dseq (1-4294967295)$arg]]",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")
{
	enum display_type dtype = normal_display;
	if (dseq)
		dtype = sequential_display;

	return vty_show_prefix_list(vty, AFI_IP6, prefix_list, arg_str, dtype);
}

DEFPY (show_ipv6_prefix_list_prefix,
       show_ipv6_prefix_list_prefix_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M$prefix [longer$dl|first-match$dfm]",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Lookup longer prefix\n"
       "First matched prefix\n")
{
	enum display_type dtype = normal_display;
	if (dl)
		dtype = longer_display;
	else if (dfm)
		dtype = first_match_display;

	return vty_show_prefix_list_prefix(vty, AFI_IP6, prefix_list,
					   prefix_str, dtype);
}

DEFPY (show_ipv6_prefix_list_summary,
       show_ipv6_prefix_list_summary_cmd,
       "show ipv6 prefix-list summary [WORD$prefix-list]",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")
{
	return vty_show_prefix_list(vty, AFI_IP6, prefix_list, NULL,
				    summary_display);
}

DEFPY (show_ipv6_prefix_list_detail,
       show_ipv6_prefix_list_detail_cmd,
       "show ipv6 prefix-list detail [WORD$prefix-list]",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")
{
	return vty_show_prefix_list(vty, AFI_IP6, prefix_list, NULL,
				    detail_display);
}

DEFPY (clear_ipv6_prefix_list,
       clear_ipv6_prefix_list_cmd,
       "clear ipv6 prefix-list [WORD [X:X::X:X/M$prefix]]",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
	return vty_clear_prefix_list(vty, AFI_IP6, prefix_list, prefix_str);
}

/* Configuration write function. */
static int config_write_prefix_afi(afi_t afi, struct vty *vty)
{
	struct prefix_list *plist;
	struct prefix_list_entry *pentry;
	struct prefix_master *master;
	int write = 0;

	master = prefix_master_get(afi, 0);
	if (master == NULL)
		return 0;

	if (!master->seqnum) {
		vty_out(vty, "no ip%s prefix-list sequence-number\n",
			afi == AFI_IP ? "" : "v6");
		vty_out(vty, "!\n");
	}

	for (plist = master->num.head; plist; plist = plist->next) {
		if (plist->desc) {
			vty_out(vty, "ip%s prefix-list %s description %s\n",
				afi == AFI_IP ? "" : "v6", plist->name,
				plist->desc);
			write++;
		}

		for (pentry = plist->head; pentry; pentry = pentry->next) {
			vty_out(vty, "ip%s prefix-list %s ",
				afi == AFI_IP ? "" : "v6", plist->name);

			if (master->seqnum)
				vty_out(vty, "seq %" PRId64 " ", pentry->seq);

			vty_out(vty, "%s ", prefix_list_type_str(pentry));

			if (pentry->any)
				vty_out(vty, "any");
			else {
				struct prefix *p = &pentry->prefix;
				char buf[BUFSIZ];

				vty_out(vty, "%s/%d",
					inet_ntop(p->family, p->u.val, buf,
						  BUFSIZ),
					p->prefixlen);

				if (pentry->ge)
					vty_out(vty, " ge %d", pentry->ge);
				if (pentry->le)
					vty_out(vty, " le %d", pentry->le);
			}
			vty_out(vty, "\n");
			write++;
		}
		/* vty_out (vty, "!\n"); */
	}

	for (plist = master->str.head; plist; plist = plist->next) {
		if (plist->desc) {
			vty_out(vty, "ip%s prefix-list %s description %s\n",
				afi == AFI_IP ? "" : "v6", plist->name,
				plist->desc);
			write++;
		}

		for (pentry = plist->head; pentry; pentry = pentry->next) {
			vty_out(vty, "ip%s prefix-list %s ",
				afi == AFI_IP ? "" : "v6", plist->name);

			if (master->seqnum)
				vty_out(vty, "seq %" PRId64 " ", pentry->seq);

			vty_out(vty, "%s", prefix_list_type_str(pentry));

			if (pentry->any)
				vty_out(vty, " any");
			else {
				struct prefix *p = &pentry->prefix;
				char buf[BUFSIZ];

				vty_out(vty, " %s/%d",
					inet_ntop(p->family, p->u.val, buf,
						  BUFSIZ),
					p->prefixlen);

				if (pentry->ge)
					vty_out(vty, " ge %d", pentry->ge);
				if (pentry->le)
					vty_out(vty, " le %d", pentry->le);
			}
			vty_out(vty, "\n");
			write++;
		}
	}

	return write;
}

struct stream *prefix_bgp_orf_entry(struct stream *s, struct prefix_list *plist,
				    uint8_t init_flag, uint8_t permit_flag,
				    uint8_t deny_flag)
{
	struct prefix_list_entry *pentry;

	if (!plist)
		return s;

	for (pentry = plist->head; pentry; pentry = pentry->next) {
		uint8_t flag = init_flag;
		struct prefix *p = &pentry->prefix;

		flag |= (pentry->type == PREFIX_PERMIT ? permit_flag
						       : deny_flag);
		stream_putc(s, flag);
		stream_putl(s, (uint32_t)pentry->seq);
		stream_putc(s, (uint8_t)pentry->ge);
		stream_putc(s, (uint8_t)pentry->le);
		stream_put_prefix(s, p);
	}

	return s;
}

int prefix_bgp_orf_set(char *name, afi_t afi, struct orf_prefix *orfp,
		       int permit, int set)
{
	struct prefix_list *plist;
	struct prefix_list_entry *pentry;

	/* ge and le value check */
	if (orfp->ge && orfp->ge <= orfp->p.prefixlen)
		return CMD_WARNING_CONFIG_FAILED;
	if (orfp->le && orfp->le <= orfp->p.prefixlen)
		return CMD_WARNING_CONFIG_FAILED;
	if (orfp->le && orfp->ge > orfp->le)
		return CMD_WARNING_CONFIG_FAILED;

	if (orfp->ge && orfp->le == (afi == AFI_IP ? 32 : 128))
		orfp->le = 0;

	plist = prefix_list_get(afi, 1, name);
	if (!plist)
		return CMD_WARNING_CONFIG_FAILED;

	if (set) {
		pentry = prefix_list_entry_make(
			&orfp->p, (permit ? PREFIX_PERMIT : PREFIX_DENY),
			orfp->seq, orfp->le, orfp->ge, 0);

		if (prefix_entry_dup_check(plist, pentry)) {
			prefix_list_entry_free(pentry);
			return CMD_WARNING_CONFIG_FAILED;
		}

		prefix_list_entry_add(plist, pentry);
	} else {
		pentry = prefix_list_entry_lookup(
			plist, &orfp->p, (permit ? PREFIX_PERMIT : PREFIX_DENY),
			orfp->seq, orfp->le, orfp->ge);

		if (!pentry)
			return CMD_WARNING_CONFIG_FAILED;

		prefix_list_entry_delete(plist, pentry, 1);
	}

	return CMD_SUCCESS;
}

void prefix_bgp_orf_remove_all(afi_t afi, char *name)
{
	struct prefix_list *plist;

	plist = prefix_bgp_orf_lookup(afi, name);
	if (plist)
		prefix_list_delete(plist);
}

/* return prefix count */
int prefix_bgp_show_prefix_list(struct vty *vty, afi_t afi, char *name,
				uint8_t use_json)
{
	struct prefix_list *plist;
	struct prefix_list_entry *pentry;
	json_object *json = NULL;
	json_object *json_prefix = NULL;
	json_object *json_list = NULL;

	plist = prefix_bgp_orf_lookup(afi, name);
	if (!plist)
		return 0;

	if (!vty)
		return plist->count;

	if (use_json) {
		json = json_object_new_object();
		json_prefix = json_object_new_object();
		json_list = json_object_new_object();

		json_object_int_add(json_prefix, "prefixListCounter",
				    plist->count);
		json_object_string_add(json_prefix, "prefixListName",
				       plist->name);

		for (pentry = plist->head; pentry; pentry = pentry->next) {
			struct prefix *p = &pentry->prefix;
			char buf_a[BUFSIZ];
			char buf_b[BUFSIZ];

			sprintf(buf_a, "%s/%d",
				inet_ntop(p->family, p->u.val, buf_b,
					  BUFSIZ),
				p->prefixlen);

			json_object_int_add(json_list, "seq", pentry->seq);
			json_object_string_add(json_list, "seqPrefixListType",
					       prefix_list_type_str(pentry));

			if (pentry->ge)
				json_object_int_add(json_list, "ge",
						    pentry->ge);
			if (pentry->le)
				json_object_int_add(json_list, "le",
						    pentry->le);

			json_object_object_add(json_prefix, buf_a, json_list);
		}
		if (afi == AFI_IP)
			json_object_object_add(json, "ipPrefixList",
					       json_prefix);
		else
			json_object_object_add(json, "ipv6PrefixList",
					       json_prefix);

		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		vty_out(vty, "ip%s prefix-list %s: %d entries\n",
			afi == AFI_IP ? "" : "v6", plist->name, plist->count);

		for (pentry = plist->head; pentry; pentry = pentry->next) {
			struct prefix *p = &pentry->prefix;
			char buf[BUFSIZ];

			vty_out(vty, "   seq %" PRId64 " %s %s/%d",
				pentry->seq,
				prefix_list_type_str(pentry),
				inet_ntop(p->family, p->u.val, buf, BUFSIZ),
				p->prefixlen);

			if (pentry->ge)
				vty_out(vty, " ge %d", pentry->ge);
			if (pentry->le)
				vty_out(vty, " le %d", pentry->le);

			vty_out(vty, "\n");
		}
	}
	return plist->count;
}

static void prefix_list_reset_afi(afi_t afi, int orf)
{
	struct prefix_list *plist;
	struct prefix_list *next;
	struct prefix_master *master;

	master = prefix_master_get(afi, orf);
	if (master == NULL)
		return;

	for (plist = master->num.head; plist; plist = next) {
		next = plist->next;
		prefix_list_delete(plist);
	}
	for (plist = master->str.head; plist; plist = next) {
		next = plist->next;
		prefix_list_delete(plist);
	}

	assert(master->num.head == NULL);
	assert(master->num.tail == NULL);

	assert(master->str.head == NULL);
	assert(master->str.tail == NULL);

	master->seqnum = 1;
	master->recent = NULL;
}


/* Prefix-list node. */
static struct cmd_node prefix_node = {PREFIX_NODE,
				      "", /* Prefix list has no interface. */
				      1};

static int config_write_prefix_ipv4(struct vty *vty)
{
	return config_write_prefix_afi(AFI_IP, vty);
}

static void plist_autocomplete_afi(afi_t afi, vector comps,
				   struct cmd_token *token)
{
	struct prefix_list *plist;
	struct prefix_master *master;

	master = prefix_master_get(afi, 0);
	if (master == NULL)
		return;

	for (plist = master->str.head; plist; plist = plist->next)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, plist->name));
	for (plist = master->num.head; plist; plist = plist->next)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, plist->name));
}

static void plist_autocomplete(vector comps, struct cmd_token *token)
{
	plist_autocomplete_afi(AFI_IP, comps, token);
	plist_autocomplete_afi(AFI_IP6, comps, token);
}

static const struct cmd_variable_handler plist_var_handlers[] = {
	{/* "prefix-list WORD" */
	 .varname = "prefix_list",
	 .completions = plist_autocomplete},
	{.completions = NULL}};


static void prefix_list_init_ipv4(void)
{
	install_node(&prefix_node, config_write_prefix_ipv4);

	install_element(CONFIG_NODE, &ip_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ip_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ip_prefix_list_all_cmd);

	install_element(CONFIG_NODE, &ip_prefix_list_description_cmd);
	install_element(CONFIG_NODE, &no_ip_prefix_list_description_cmd);
	install_element(CONFIG_NODE,
			&no_ip_prefix_list_description_comment_cmd);

	install_element(CONFIG_NODE, &ip_prefix_list_sequence_number_cmd);

	install_element(VIEW_NODE, &show_ip_prefix_list_cmd);
	install_element(VIEW_NODE, &show_ip_prefix_list_prefix_cmd);
	install_element(VIEW_NODE, &show_ip_prefix_list_summary_cmd);
	install_element(VIEW_NODE, &show_ip_prefix_list_detail_cmd);

	install_element(ENABLE_NODE, &clear_ip_prefix_list_cmd);
}

/* Prefix-list node. */
static struct cmd_node prefix_ipv6_node = {
	PREFIX_IPV6_NODE, "", /* Prefix list has no interface. */
	1};

static int config_write_prefix_ipv6(struct vty *vty)
{
	return config_write_prefix_afi(AFI_IP6, vty);
}

static void prefix_list_init_ipv6(void)
{
	install_node(&prefix_ipv6_node, config_write_prefix_ipv6);

	install_element(CONFIG_NODE, &ipv6_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_prefix_list_all_cmd);

	install_element(CONFIG_NODE, &ipv6_prefix_list_description_cmd);
	install_element(CONFIG_NODE, &no_ipv6_prefix_list_description_cmd);
	install_element(CONFIG_NODE,
			&no_ipv6_prefix_list_description_comment_cmd);

	install_element(CONFIG_NODE, &ipv6_prefix_list_sequence_number_cmd);

	install_element(VIEW_NODE, &show_ipv6_prefix_list_cmd);
	install_element(VIEW_NODE, &show_ipv6_prefix_list_prefix_cmd);
	install_element(VIEW_NODE, &show_ipv6_prefix_list_summary_cmd);
	install_element(VIEW_NODE, &show_ipv6_prefix_list_detail_cmd);

	install_element(ENABLE_NODE, &clear_ipv6_prefix_list_cmd);
}

void prefix_list_init()
{
	cmd_variable_handler_register(plist_var_handlers);

	prefix_list_init_ipv4();
	prefix_list_init_ipv6();
}

void prefix_list_reset()
{
	prefix_list_reset_afi(AFI_IP, 0);
	prefix_list_reset_afi(AFI_IP6, 0);
	prefix_list_reset_afi(AFI_IP, 1);
	prefix_list_reset_afi(AFI_IP6, 1);
}
