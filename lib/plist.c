// SPDX-License-Identifier: GPL-2.0-or-later
/* Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#include <typesafe.h>
#include "plist_int.h"

DEFINE_MTYPE_STATIC(LIB, PREFIX_LIST, "Prefix List");
DEFINE_MTYPE_STATIC(LIB, MPREFIX_LIST_STR, "Prefix List Str");
DEFINE_MTYPE_STATIC(LIB, PREFIX_LIST_ENTRY, "Prefix List Entry");
DEFINE_MTYPE_STATIC(LIB, PREFIX_LIST_TRIE, "Prefix List Trie Table");

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

/* Master structure of prefix_list. */
struct prefix_master {
	/* The latest update. */
	struct prefix_list *recent;

	/* Hook function which is executed when new prefix_list is added. */
	void (*add_hook)(struct prefix_list *);

	/* Hook function which is executed when prefix_list is deleted. */
	void (*delete_hook)(struct prefix_list *);

	/* number of bytes that have a trie level */
	size_t trie_depth;

	struct plist_head str;
};
static int prefix_list_compare_func(const struct prefix_list *a,
				    const struct prefix_list *b);
DECLARE_RBTREE_UNIQ(plist, struct prefix_list, plist_item,
		    prefix_list_compare_func);

/* Static structure of IPv4 prefix_list's master. */
static struct prefix_master prefix_master_ipv4 = {
	NULL, NULL, NULL, PLC_MAXLEVELV4,
};

/* Static structure of IPv6 prefix-list's master. */
static struct prefix_master prefix_master_ipv6 = {
	NULL, NULL, NULL, PLC_MAXLEVELV6,
};

/* Static structure of BGP ORF prefix_list's master. */
static struct prefix_master prefix_master_orf_v4 = {
	NULL, NULL, NULL, PLC_MAXLEVELV4,
};

/* Static structure of BGP ORF prefix_list's master. */
static struct prefix_master prefix_master_orf_v6 = {
	NULL, NULL, NULL, PLC_MAXLEVELV6,
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

static int prefix_list_compare_func(const struct prefix_list *a,
				    const struct prefix_list *b)
{
	return strcmp(a->name, b->name);
}

/* Lookup prefix_list from list of prefix_list by name. */
static struct prefix_list *prefix_list_lookup_do(afi_t afi, int orf,
						 const char *name)
{
	struct prefix_list *plist, lookup;
	struct prefix_master *master;

	if (name == NULL)
		return NULL;

	master = prefix_master_get(afi, orf);
	if (master == NULL)
		return NULL;

	lookup.name = XSTRDUP(MTYPE_TMP, name);
	plist = plist_find(&master->str, &lookup);
	XFREE(MTYPE_TMP, lookup.name);
	return plist;
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

struct prefix_list_entry *prefix_list_entry_new(void)
{
	struct prefix_list_entry *new;

	new = XCALLOC(MTYPE_PREFIX_LIST_ENTRY,
		      sizeof(struct prefix_list_entry));
	return new;
}

void prefix_list_entry_free(struct prefix_list_entry *pentry)
{
	XFREE(MTYPE_PREFIX_LIST_ENTRY, pentry);
}

/* Insert new prefix list to list of prefix_list.  Each prefix_list
   is sorted by the name. */
static struct prefix_list *prefix_list_insert(afi_t afi, int orf,
					      const char *name)
{
	struct prefix_list *plist;
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

	plist_add(&master->str, plist);

	return plist;
}

struct prefix_list *prefix_list_get(afi_t afi, int orf, const char *name)
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
void prefix_list_delete(struct prefix_list *plist)
{
	struct prefix_master *master;
	struct prefix_list_entry *pentry;
	struct prefix_list_entry *next;

	/* If prefix-list contain prefix_list_entry free all of it. */
	for (pentry = plist->head; pentry; pentry = next) {
		route_map_notify_pentry_dependencies(plist->name, pentry,
						     RMAP_EVENT_PLIST_DELETED);
		next = pentry->next;
		prefix_list_trie_del(plist, pentry);
		prefix_list_entry_free(pentry);
		plist->count--;
	}

	master = plist->master;

	plist_del(&master->str, plist);

	XFREE(MTYPE_TMP, plist->desc);

	/* Make sure master's recent changed prefix-list information is
	   cleared. */
	master->recent = NULL;

	route_map_notify_dependencies(plist->name, RMAP_EVENT_PLIST_DELETED);

	if (master->delete_hook)
		(*master->delete_hook)(plist);

	XFREE(MTYPE_MPREFIX_LIST_STR, plist->name);

	XFREE(MTYPE_PREFIX_LIST_TRIE, plist->trie);

	prefix_list_free(plist);
}

static struct prefix_list_entry *
prefix_list_entry_make(struct prefix *prefix, enum prefix_list_type type,
		       int64_t seq, int le, int ge, bool any)
{
	struct prefix_list_entry *pentry;

	pentry = prefix_list_entry_new();

	if (any)
		pentry->any = true;

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
int64_t prefix_new_seq_get(struct prefix_list *plist)
{
	int64_t maxseq;
	int64_t newseq;
	struct prefix_list_entry *pentry;

	maxseq = 0;

	for (pentry = plist->head; pentry; pentry = pentry->next) {
		if (maxseq < pentry->seq)
			maxseq = pentry->seq;
	}

	newseq = ((maxseq / 5) * 5) + 5;

	return (newseq > UINT_MAX) ? UINT_MAX : newseq;
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

struct prefix_list_entry *
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
		}
}

/**
 * Find duplicated prefix entry (same prefix but different entry) in prefix
 * list.
 */
static bool prefix_list_entry_is_duplicated(struct prefix_list *list,
					    struct prefix_list_entry *entry)
{
	size_t depth, maxdepth = list->master->trie_depth;
	uint8_t byte, *bytes = entry->prefix.u.val;
	size_t validbits = entry->prefix.prefixlen;
	struct pltrie_table *table = list->trie;
	struct prefix_list_entry *pentry;

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
		if (pentry == entry)
			continue;
		if (prefix_same(&pentry->prefix, &entry->prefix))
			return true;
	}

	return false;
}

void prefix_list_entry_delete(struct prefix_list *plist,
			      struct prefix_list_entry *pentry,
			      int update_list)
{
	bool duplicate;

	if (plist == NULL || pentry == NULL)
		return;

	duplicate = prefix_list_entry_is_duplicated(plist, pentry);

	prefix_list_trie_del(plist, pentry);

	if (pentry->prev)
		pentry->prev->next = pentry->next;
	else
		plist->head = pentry->next;
	if (pentry->next)
		pentry->next->prev = pentry->prev;
	else
		plist->tail = pentry->prev;

	if (!duplicate)
		route_map_notify_pentry_dependencies(plist->name, pentry,
						     RMAP_EVENT_PLIST_DELETED);

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

	route_map_notify_pentry_dependencies(plist->name, pentry,
					     RMAP_EVENT_PLIST_ADDED);

	/* Run hook function. */
	if (plist->master->add_hook)
		(*plist->master->add_hook)(plist);

	route_map_notify_dependencies(plist->name, RMAP_EVENT_PLIST_ADDED);
	plist->master->recent = plist;
}

/**
 * Prefix list entry update start procedure:
 * Remove entry from previosly installed master list, tries and notify
 * observers.
 *
 * \param[in] ple prefix list entry.
 */
void prefix_list_entry_update_start(struct prefix_list_entry *ple)
{
	struct prefix_list *pl = ple->pl;
	bool duplicate;

	/* Not installed, nothing to do. */
	if (!ple->installed)
		return;

	duplicate = prefix_list_entry_is_duplicated(pl, ple);

	prefix_list_trie_del(pl, ple);

	/* List manipulation: shameless copy from `prefix_list_entry_delete`. */
	if (ple->prev)
		ple->prev->next = ple->next;
	else
		pl->head = ple->next;
	if (ple->next)
		ple->next->prev = ple->prev;
	else
		pl->tail = ple->prev;

	if (!duplicate)
		route_map_notify_pentry_dependencies(pl->name, ple,
						     RMAP_EVENT_PLIST_DELETED);
	pl->count--;

	route_map_notify_dependencies(pl->name, RMAP_EVENT_PLIST_DELETED);
	if (pl->master->delete_hook)
		(*pl->master->delete_hook)(pl);

	if (pl->head || pl->tail || pl->desc)
		pl->master->recent = pl;

	ple->next_best = NULL;
	ple->installed = false;
}

/**
 * Prefix list entry update finish procedure:
 * Add entry back master list, to the trie, notify observers and call master
 * hook.
 *
 * \param[in] ple prefix list entry.
 */
void prefix_list_entry_update_finish(struct prefix_list_entry *ple)
{
	struct prefix_list *pl = ple->pl;
	struct prefix_list_entry *point;

	/* Already installed, nothing to do. */
	if (ple->installed)
		return;

	/*
	 * Check if the entry is installable:
	 * We can only install entry if at least the prefix is provided (IPv4
	 * or IPv6).
	 */
	if (ple->prefix.family != AF_INET && ple->prefix.family != AF_INET6)
		return;

	/* List manipulation: shameless copy from `prefix_list_entry_add`. */
	if (pl->tail && ple->seq > pl->tail->seq)
		point = NULL;
	else {
		/* Check insert point. */
		for (point = pl->head; point; point = point->next)
			if (point->seq >= ple->seq)
				break;
	}

	/* In case of this is the first element of the list. */
	ple->next = point;

	if (point) {
		if (point->prev)
			point->prev->next = ple;
		else
			pl->head = ple;

		ple->prev = point->prev;
		point->prev = ple;
	} else {
		if (pl->tail)
			pl->tail->next = ple;
		else
			pl->head = ple;

		ple->prev = pl->tail;
		pl->tail = ple;
	}

	prefix_list_trie_add(pl, ple);
	pl->count++;

	route_map_notify_pentry_dependencies(pl->name, ple,
					     RMAP_EVENT_PLIST_ADDED);

	/* Run hook function. */
	if (pl->master->add_hook)
		(*pl->master->add_hook)(pl);

	route_map_notify_dependencies(pl->name, RMAP_EVENT_PLIST_ADDED);
	pl->master->recent = pl;

	ple->installed = true;
}

/**
 * Same as `prefix_list_entry_delete` but without `free()`ing the list if its
 * empty.
 *
 * \param[in] ple prefix list entry.
 */
void prefix_list_entry_delete2(struct prefix_list_entry *ple)
{
	/* Does the boiler plate list removal and entry removal notification. */
	prefix_list_entry_update_start(ple);

	/* Effective `free()` memory. */
	prefix_list_entry_free(ple);
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
				   const struct prefix *p, bool address_mode)
{
	int ret;

	if (pentry->prefix.family != p->family)
		return 0;

	ret = prefix_match(&pentry->prefix, p);
	if (!ret)
		return 0;

	if (address_mode)
		return 1;

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

enum prefix_list_type prefix_list_apply_ext(
	struct prefix_list *plist,
	const struct prefix_list_entry **which,
	union prefixconstptr object,
	bool address_mode)
{
	struct prefix_list_entry *pentry, *pbest = NULL;

	const struct prefix *p = object.p;
	const uint8_t *byte = p->u.val;
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
			if (prefix_list_entry_match(pentry, p, address_mode))
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
			if (prefix_list_entry_match(pentry, p, address_mode))
				pbest = pentry;
		}
		break;
	}

	if (which) {
		if (pbest)
			*which = pbest;
		else
			*which = NULL;
	}

	if (pbest == NULL)
		return PREFIX_DENY;

	pbest->hitcnt++;
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

			p = &pentry->prefix;

			printf("  seq %lld %s %pFX", (long long)pentry->seq,
			       prefix_list_type_str(pentry), p);
			if (pentry->ge)
				printf(" ge %d", pentry->ge);
			if (pentry->le)
				printf(" le %d", pentry->le);
			printf("\n");
		}
	}
}

/* Return 1 when plist already include pentry policy. */
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

enum display_type {
	normal_display,
	summary_display,
	detail_display,
	sequential_display,
	longer_display,
	first_match_display
};

static void vty_show_prefix_entry(struct vty *vty, json_object *json, afi_t afi,
				  struct prefix_list *plist,
				  struct prefix_master *master,
				  enum display_type dtype, int seqnum)
{
	struct prefix_list_entry *pentry;
	json_object *json_pl = NULL;

	/* Print the name of the protocol */
	if (json) {
		json_pl = json_object_new_object();
		json_object_object_add(json, plist->name, json_pl);
	} else
		vty_out(vty, "%s: ", frr_protoname);

	if (dtype == normal_display) {
		if (json) {
			json_object_string_add(json_pl, "addressFamily",
					       afi2str(afi));
			json_object_int_add(json_pl, "entries", plist->count);
			if (plist->desc)
				json_object_string_add(json_pl, "description",
						       plist->desc);
		} else {
			vty_out(vty, "ip%s prefix-list %s: %d entries\n",
				afi == AFI_IP ? "" : "v6", plist->name,
				plist->count);
			if (plist->desc)
				vty_out(vty, "   Description: %s\n",
					plist->desc);
		}
	} else if (dtype == summary_display || dtype == detail_display) {
		if (json) {
			json_object_string_add(json_pl, "addressFamily",
					       afi2str(afi));
			if (plist->desc)
				json_object_string_add(json_pl, "description",
						       plist->desc);
			json_object_int_add(json_pl, "count", plist->count);
			json_object_int_add(json_pl, "rangeEntries",
					    plist->rangecount);
			json_object_int_add(json_pl, "sequenceStart",
					    plist->head ? plist->head->seq : 0);
			json_object_int_add(json_pl, "sequenceEnd",
					    plist->tail ? plist->tail->seq : 0);
		} else {
			vty_out(vty, "ip%s prefix-list %s:\n",
				afi == AFI_IP ? "" : "v6", plist->name);

			if (plist->desc)
				vty_out(vty, "   Description: %s\n",
					plist->desc);

			vty_out(vty,
				"   count: %d, range entries: %d, sequences: %" PRId64
				" - %" PRId64 "\n",
				plist->count, plist->rangecount,
				plist->head ? plist->head->seq : 0,
				plist->tail ? plist->tail->seq : 0);
		}
	}

	if (dtype != summary_display) {
		json_object *json_entries = NULL;

		if (json) {
			json_entries = json_object_new_array();
			json_object_object_add(json_pl, "entries",
					       json_entries);
		}

		for (pentry = plist->head; pentry; pentry = pentry->next) {
			if (dtype == sequential_display
			    && pentry->seq != seqnum)
				continue;

			if (json) {
				json_object *json_entry;

				json_entry = json_object_new_object();
				json_object_array_add(json_entries, json_entry);

				json_object_int_add(json_entry,
						    "sequenceNumber",
						    pentry->seq);
				json_object_string_add(
					json_entry, "type",
					prefix_list_type_str(pentry));
				json_object_string_addf(json_entry, "prefix",
							"%pFX",
							&pentry->prefix);

				if (pentry->ge)
					json_object_int_add(
						json_entry,
						"minimumPrefixLength",
						pentry->ge);
				if (pentry->le)
					json_object_int_add(
						json_entry,
						"maximumPrefixLength",
						pentry->le);

				if (dtype == detail_display
				    || dtype == sequential_display) {
					json_object_int_add(json_entry,
							    "hitCount",
							    pentry->hitcnt);
					json_object_int_add(json_entry,
							    "referenceCount",
							    pentry->refcnt);
				}
			} else {
				vty_out(vty, "   ");

				vty_out(vty, "seq %" PRId64 " ", pentry->seq);

				vty_out(vty, "%s ",
					prefix_list_type_str(pentry));

				if (pentry->any)
					vty_out(vty, "any");
				else {
					struct prefix *p = &pentry->prefix;

					vty_out(vty, "%pFX", p);

					if (pentry->ge)
						vty_out(vty, " ge %d",
							pentry->ge);
					if (pentry->le)
						vty_out(vty, " le %d",
							pentry->le);
				}

				if (dtype == detail_display
				    || dtype == sequential_display)
					vty_out(vty,
						" (hit count: %ld, refcount: %ld)",
						pentry->hitcnt, pentry->refcnt);

				vty_out(vty, "\n");
			}
		}
	}
}

static int vty_show_prefix_list(struct vty *vty, afi_t afi, const char *name,
				const char *seq, enum display_type dtype,
				bool uj)
{
	struct prefix_list *plist;
	struct prefix_master *master;
	int64_t seqnum = 0;
	json_object *json = NULL;
	json_object *json_proto = NULL;

	master = prefix_master_get(afi, 0);
	if (master == NULL)
		return CMD_WARNING;

	if (uj) {
		json = json_object_new_object();
		json_proto = json_object_new_object();
		json_object_object_add(json, frr_protoname, json_proto);
	}

	if (seq)
		seqnum = (int64_t)atol(seq);

	if (name) {
		plist = prefix_list_lookup(afi, name);
		if (!plist) {
			if (!uj)
				vty_out(vty,
					"%% Can't find specified prefix-list\n");
			return CMD_WARNING;
		}
		vty_show_prefix_entry(vty, json_proto, afi, plist, master,
				      dtype, seqnum);
	} else {
		if (dtype == detail_display || dtype == summary_display) {
			if (master->recent && !uj)
				vty_out(vty,
					"Prefix-list with the last deletion/insertion: %s\n",
					master->recent->name);
		}

		frr_each (plist, &master->str, plist)
			vty_show_prefix_entry(vty, json_proto, afi, plist,
					      master, dtype, seqnum);
	}

	return vty_json(vty, json);
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
				struct prefix *pf = &pentry->prefix;

				vty_out(vty, "%pFX", pf);

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
		frr_each (plist, &master->str, plist)
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

#include "lib/plist_clippy.c"

DEFPY (show_ip_prefix_list,
       show_ip_prefix_list_cmd,
       "show ip prefix-list [PREFIXLIST4_NAME$name [seq$dseq (1-4294967295)$arg]] [json$uj]",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       JSON_STR)
{
	enum display_type dtype = normal_display;
	if (dseq)
		dtype = sequential_display;

	return vty_show_prefix_list(vty, AFI_IP, name, arg_str, dtype,
				    !!uj);
}

DEFPY (show_ip_prefix_list_prefix,
       show_ip_prefix_list_prefix_cmd,
       "show ip prefix-list PREFIXLIST4_NAME$name A.B.C.D/M$prefix [longer$dl|first-match$dfm]",
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

	return vty_show_prefix_list_prefix(vty, AFI_IP, name, prefix_str,
					   dtype);
}

DEFPY (show_ip_prefix_list_summary,
       show_ip_prefix_list_summary_cmd,
       "show ip prefix-list summary [PREFIXLIST4_NAME$name] [json$uj]",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n"
       JSON_STR)
{
	return vty_show_prefix_list(vty, AFI_IP, name, NULL,
				    summary_display, !!uj);
}

DEFPY (show_ip_prefix_list_detail,
       show_ip_prefix_list_detail_cmd,
       "show ip prefix-list detail [PREFIXLIST4_NAME$name] [json$uj]",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n"
       JSON_STR)
{
	return vty_show_prefix_list(vty, AFI_IP, name, NULL,
				    detail_display, !!uj);
}

DEFPY (clear_ip_prefix_list,
       clear_ip_prefix_list_cmd,
       "clear ip prefix-list [PREFIXLIST4_NAME$name [A.B.C.D/M$prefix]]",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
	return vty_clear_prefix_list(vty, AFI_IP, name, prefix_str);
}

DEFPY (show_ipv6_prefix_list,
       show_ipv6_prefix_list_cmd,
       "show ipv6 prefix-list [PREFIXLIST6_NAME$name [seq$dseq (1-4294967295)$arg]] [json$uj]",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       JSON_STR)
{
	enum display_type dtype = normal_display;
	if (dseq)
		dtype = sequential_display;

	return vty_show_prefix_list(vty, AFI_IP6, name, arg_str, dtype,
				    !!uj);
}

DEFPY (show_ipv6_prefix_list_prefix,
       show_ipv6_prefix_list_prefix_cmd,
       "show ipv6 prefix-list PREFIXLIST6_NAME$name X:X::X:X/M$prefix [longer$dl|first-match$dfm]",
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

	return vty_show_prefix_list_prefix(vty, AFI_IP6, name,
					   prefix_str, dtype);
}

DEFPY (show_ipv6_prefix_list_summary,
       show_ipv6_prefix_list_summary_cmd,
       "show ipv6 prefix-list summary [PREFIXLIST6_NAME$name] [json$uj]",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n"
       JSON_STR)
{
	return vty_show_prefix_list(vty, AFI_IP6, name, NULL,
				    summary_display, !!uj);
}

DEFPY (show_ipv6_prefix_list_detail,
       show_ipv6_prefix_list_detail_cmd,
       "show ipv6 prefix-list detail [PREFIXLIST6_NAME$name] [json$uj]",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n"
       JSON_STR)
{
	return vty_show_prefix_list(vty, AFI_IP6, name, NULL,
				    detail_display, !!uj);
}

DEFPY (clear_ipv6_prefix_list,
       clear_ipv6_prefix_list_cmd,
       "clear ipv6 prefix-list [PREFIXLIST6_NAME$name [X:X::X:X/M$prefix]]",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
	return vty_clear_prefix_list(vty, AFI_IP6, name, prefix_str);
}

DEFPY (debug_prefix_list_match,
       debug_prefix_list_match_cmd,
       "debug prefix-list WORD$prefix-list match <A.B.C.D/M|X:X::X:X/M>"
       " [address-mode$addr_mode]",
       DEBUG_STR
       "Prefix-list test access\n"
       "Name of a prefix list\n"
       "Test prefix for prefix list result\n"
       "Prefix to test in ip prefix-list\n"
       "Prefix to test in ipv6 prefix-list\n"
       "Use address matching mode (PIM RP)\n")
{
	struct prefix_list *plist;
	const struct prefix_list_entry *entry = NULL;
	enum prefix_list_type ret;

	plist = prefix_list_lookup(family2afi(match->family), prefix_list);
	if (!plist) {
		vty_out(vty, "%% no prefix list named %s for AFI %s\n",
			prefix_list, afi2str(family2afi(match->family)));
		return CMD_WARNING;
	}

	ret = prefix_list_apply_ext(plist, &entry, match, !!addr_mode);

	vty_out(vty, "%s prefix list %s yields %s for %pFX, ",
		afi2str(family2afi(match->family)), prefix_list,
		ret == PREFIX_DENY ? "DENY" : "PERMIT", match);

	if (!entry)
		vty_out(vty, "no match found\n");
	else {
		vty_out(vty, "matching entry #%"PRId64": %pFX", entry->seq,
			&entry->prefix);
		if (entry->ge)
			vty_out(vty, " ge %d", entry->ge);
		if (entry->le)
			vty_out(vty, " le %d", entry->le);
		vty_out(vty, "\n");
	}

	/* allow using this in scripts for quick prefix-list member tests */
	return (ret == PREFIX_PERMIT) ? CMD_SUCCESS : CMD_WARNING;
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
	if (orfp->ge && orfp->ge < orfp->p.prefixlen)
		return CMD_WARNING_CONFIG_FAILED;
	if (orfp->le && orfp->le < orfp->p.prefixlen)
		return CMD_WARNING_CONFIG_FAILED;
	if (orfp->le && orfp->ge > orfp->le)
		return CMD_WARNING_CONFIG_FAILED;

	if (orfp->ge && orfp->le == (afi == AFI_IP ? 32 : 128))
		orfp->le = 0;

	plist = prefix_list_get(afi, 1, name);
	if (!plist)
		return CMD_WARNING_CONFIG_FAILED;

	apply_mask(&orfp->p);

	if (set) {
		pentry = prefix_list_entry_make(
			&orfp->p, (permit ? PREFIX_PERMIT : PREFIX_DENY),
			orfp->seq, orfp->le, orfp->ge, false);

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
				bool use_json)
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

			snprintf(buf_a, sizeof(buf_a), "%pFX", p);

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

		vty_json(vty, json);
	} else {
		vty_out(vty, "ip%s prefix-list %s: %d entries\n",
			afi == AFI_IP ? "" : "v6", plist->name, plist->count);

		for (pentry = plist->head; pentry; pentry = pentry->next) {
			struct prefix *p = &pentry->prefix;

			vty_out(vty, "   seq %" PRId64 " %s %pFX", pentry->seq,
				prefix_list_type_str(pentry), p);

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
	struct prefix_master *master;

	master = prefix_master_get(afi, orf);
	if (master == NULL)
		return;

	while ((plist = plist_first(&master->str))) {
		prefix_list_delete(plist);
	}

	master->recent = NULL;
}

/* Prefix-list node. */
static struct cmd_node prefix_node = {
	.name = "ipv4 prefix list",
	.node = PREFIX_NODE,
	.prompt = "",
};

static void plist_autocomplete_afi(afi_t afi, vector comps,
				   struct cmd_token *token)
{
	struct prefix_list *plist;
	struct prefix_master *master;

	master = prefix_master_get(afi, 0);
	if (master == NULL)
		return;

	frr_each (plist, &master->str, plist)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, plist->name));
}

static void plist_autocomplete(vector comps, struct cmd_token *token)
{
	plist_autocomplete_afi(AFI_IP, comps, token);
	plist_autocomplete_afi(AFI_IP6, comps, token);
}

static void plist4_autocomplete(vector comps, struct cmd_token *token)
{
	plist_autocomplete_afi(AFI_IP, comps, token);
}

static void plist6_autocomplete(vector comps, struct cmd_token *token)
{
	plist_autocomplete_afi(AFI_IP6, comps, token);
}

static const struct cmd_variable_handler plist_var_handlers[] = {
	{/* "prefix-list WORD" */
	 .varname = "prefix_list",
	 .completions = plist_autocomplete},
	{.tokenname = "PREFIXLIST_NAME",
	 .completions = plist_autocomplete},
	{.tokenname = "PREFIXLIST4_NAME",
	 .completions = plist4_autocomplete},
	{.tokenname = "PREFIXLIST6_NAME",
	 .completions = plist6_autocomplete},
	{.completions = NULL}};


static void prefix_list_init_ipv4(void)
{
	install_node(&prefix_node);

	install_element(VIEW_NODE, &show_ip_prefix_list_cmd);
	install_element(VIEW_NODE, &show_ip_prefix_list_prefix_cmd);
	install_element(VIEW_NODE, &show_ip_prefix_list_summary_cmd);
	install_element(VIEW_NODE, &show_ip_prefix_list_detail_cmd);

	install_element(ENABLE_NODE, &clear_ip_prefix_list_cmd);
}

/* Prefix-list node. */
static struct cmd_node prefix_ipv6_node = {
	.name = "ipv6 prefix list",
	.node = PREFIX_IPV6_NODE,
	.prompt = "",
};

static void prefix_list_init_ipv6(void)
{
	install_node(&prefix_ipv6_node);

	install_element(VIEW_NODE, &show_ipv6_prefix_list_cmd);
	install_element(VIEW_NODE, &show_ipv6_prefix_list_prefix_cmd);
	install_element(VIEW_NODE, &show_ipv6_prefix_list_summary_cmd);
	install_element(VIEW_NODE, &show_ipv6_prefix_list_detail_cmd);
	install_element(VIEW_NODE, &debug_prefix_list_match_cmd);

	install_element(ENABLE_NODE, &clear_ipv6_prefix_list_cmd);
}

void prefix_list_init(void)
{
	plist_init(&prefix_master_ipv4.str);
	plist_init(&prefix_master_orf_v4.str);
	plist_init(&prefix_master_ipv6.str);
	plist_init(&prefix_master_orf_v6.str);

	cmd_variable_handler_register(plist_var_handlers);

	prefix_list_init_ipv4();
	prefix_list_init_ipv6();
}

void prefix_list_reset(void)
{
	prefix_list_reset_afi(AFI_IP, 0);
	prefix_list_reset_afi(AFI_IP6, 0);
	prefix_list_reset_afi(AFI_IP, 1);
	prefix_list_reset_afi(AFI_IP6, 1);
}
