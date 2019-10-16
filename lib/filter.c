/* Route filtering function.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
#include "filter.h"
#include "memory.h"
#include "command.h"
#include "sockunion.h"
#include "buffer.h"
#include "log.h"
#include "routemap.h"
#include "libfrr.h"

DEFINE_MTYPE_STATIC(LIB, ACCESS_LIST, "Access List")
DEFINE_MTYPE_STATIC(LIB, ACCESS_LIST_STR, "Access List Str")
DEFINE_MTYPE_STATIC(LIB, ACCESS_FILTER, "Access Filter")

struct filter_cisco {
	/* Cisco access-list */
	int extended;
	struct in_addr addr;
	struct in_addr addr_mask;
	struct in_addr mask;
	struct in_addr mask_mask;
};

struct filter_zebra {
	/* If this filter is "exact" match then this flag is set. */
	int exact;

	/* Prefix information. */
	struct prefix prefix;
};

/* Filter element of access list */
struct filter {
	/* For doubly linked list. */
	struct filter *next;
	struct filter *prev;

	/* Filter type information. */
	enum filter_type type;

	/* Sequence number */
	int64_t seq;

	/* Cisco access-list */
	int cisco;

	union {
		struct filter_cisco cfilter;
		struct filter_zebra zfilter;
	} u;
};

/* List of access_list. */
struct access_list_list {
	struct access_list *head;
	struct access_list *tail;
};

/* Master structure of access_list. */
struct access_master {
	/* List of access_list which name is number. */
	struct access_list_list num;

	/* List of access_list which name is string. */
	struct access_list_list str;

	/* Hook function which is executed when new access_list is added. */
	void (*add_hook)(struct access_list *);

	/* Hook function which is executed when access_list is deleted. */
	void (*delete_hook)(struct access_list *);
};

/* Static structure for mac access_list's master. */
static struct access_master access_master_mac = {
	{NULL, NULL},
	{NULL, NULL},
	NULL,
	NULL,
};

/* Static structure for IPv4 access_list's master. */
static struct access_master access_master_ipv4 = {
	{NULL, NULL},
	{NULL, NULL},
	NULL,
	NULL,
};

/* Static structure for IPv6 access_list's master. */
static struct access_master access_master_ipv6 = {
	{NULL, NULL},
	{NULL, NULL},
	NULL,
	NULL,
};

static struct access_master *access_master_get(afi_t afi)
{
	if (afi == AFI_IP)
		return &access_master_ipv4;
	else if (afi == AFI_IP6)
		return &access_master_ipv6;
	else if (afi == AFI_L2VPN)
		return &access_master_mac;
	return NULL;
}

/* Allocate new filter structure. */
static struct filter *filter_new(void)
{
	return XCALLOC(MTYPE_ACCESS_FILTER, sizeof(struct filter));
}

static void filter_free(struct filter *filter)
{
	XFREE(MTYPE_ACCESS_FILTER, filter);
}

/* Return string of filter_type. */
static const char *filter_type_str(struct filter *filter)
{
	switch (filter->type) {
	case FILTER_PERMIT:
		return "permit";
		break;
	case FILTER_DENY:
		return "deny";
		break;
	case FILTER_DYNAMIC:
		return "dynamic";
		break;
	default:
		return "";
		break;
	}
}

/* If filter match to the prefix then return 1. */
static int filter_match_cisco(struct filter *mfilter, const struct prefix *p)
{
	struct filter_cisco *filter;
	struct in_addr mask;
	uint32_t check_addr;
	uint32_t check_mask;

	filter = &mfilter->u.cfilter;
	check_addr = p->u.prefix4.s_addr & ~filter->addr_mask.s_addr;

	if (filter->extended) {
		masklen2ip(p->prefixlen, &mask);
		check_mask = mask.s_addr & ~filter->mask_mask.s_addr;

		if (memcmp(&check_addr, &filter->addr.s_addr, 4) == 0
		    && memcmp(&check_mask, &filter->mask.s_addr, 4) == 0)
			return 1;
	} else if (memcmp(&check_addr, &filter->addr.s_addr, 4) == 0)
		return 1;

	return 0;
}

/* If filter match to the prefix then return 1. */
static int filter_match_zebra(struct filter *mfilter, const struct prefix *p)
{
	struct filter_zebra *filter = NULL;

	filter = &mfilter->u.zfilter;

	if (filter->prefix.family == p->family) {
		if (filter->exact) {
			if (filter->prefix.prefixlen == p->prefixlen)
				return prefix_match(&filter->prefix, p);
			else
				return 0;
		} else
			return prefix_match(&filter->prefix, p);
	} else
		return 0;
}

/* Allocate new access list structure. */
static struct access_list *access_list_new(void)
{
	return XCALLOC(MTYPE_ACCESS_LIST, sizeof(struct access_list));
}

/* Free allocated access_list. */
static void access_list_free(struct access_list *access)
{
	XFREE(MTYPE_ACCESS_LIST, access);
}

/* Delete access_list from access_master and free it. */
static void access_list_delete(struct access_list *access)
{
	struct filter *filter;
	struct filter *next;
	struct access_list_list *list;
	struct access_master *master;

	for (filter = access->head; filter; filter = next) {
		next = filter->next;
		filter_free(filter);
	}

	master = access->master;

	if (access->type == ACCESS_TYPE_NUMBER)
		list = &master->num;
	else
		list = &master->str;

	if (access->next)
		access->next->prev = access->prev;
	else
		list->tail = access->prev;

	if (access->prev)
		access->prev->next = access->next;
	else
		list->head = access->next;

	XFREE(MTYPE_ACCESS_LIST_STR, access->name);

	XFREE(MTYPE_TMP, access->remark);

	access_list_free(access);
}

/* Insert new access list to list of access_list.  Each acceess_list
   is sorted by the name. */
static struct access_list *access_list_insert(afi_t afi, const char *name)
{
	unsigned int i;
	long number;
	struct access_list *access;
	struct access_list *point;
	struct access_list_list *alist;
	struct access_master *master;

	master = access_master_get(afi);
	if (master == NULL)
		return NULL;

	/* Allocate new access_list and copy given name. */
	access = access_list_new();
	access->name = XSTRDUP(MTYPE_ACCESS_LIST_STR, name);
	access->master = master;

	/* If name is made by all digit character.  We treat it as
	   number. */
	for (number = 0, i = 0; i < strlen(name); i++) {
		if (isdigit((unsigned char)name[i]))
			number = (number * 10) + (name[i] - '0');
		else
			break;
	}

	/* In case of name is all digit character */
	if (i == strlen(name)) {
		access->type = ACCESS_TYPE_NUMBER;

		/* Set access_list to number list. */
		alist = &master->num;

		for (point = alist->head; point; point = point->next)
			if (atol(point->name) >= number)
				break;
	} else {
		access->type = ACCESS_TYPE_STRING;

		/* Set access_list to string list. */
		alist = &master->str;

		/* Set point to insertion point. */
		for (point = alist->head; point; point = point->next)
			if (strcmp(point->name, name) >= 0)
				break;
	}

	/* In case of this is the first element of master. */
	if (alist->head == NULL) {
		alist->head = alist->tail = access;
		return access;
	}

	/* In case of insertion is made at the tail of access_list. */
	if (point == NULL) {
		access->prev = alist->tail;
		alist->tail->next = access;
		alist->tail = access;
		return access;
	}

	/* In case of insertion is made at the head of access_list. */
	if (point == alist->head) {
		access->next = alist->head;
		alist->head->prev = access;
		alist->head = access;
		return access;
	}

	/* Insertion is made at middle of the access_list. */
	access->next = point;
	access->prev = point->prev;

	if (point->prev)
		point->prev->next = access;
	point->prev = access;

	return access;
}

/* Lookup access_list from list of access_list by name. */
struct access_list *access_list_lookup(afi_t afi, const char *name)
{
	struct access_list *access;
	struct access_master *master;

	if (name == NULL)
		return NULL;

	master = access_master_get(afi);
	if (master == NULL)
		return NULL;

	for (access = master->num.head; access; access = access->next)
		if (strcmp(access->name, name) == 0)
			return access;

	for (access = master->str.head; access; access = access->next)
		if (strcmp(access->name, name) == 0)
			return access;

	return NULL;
}

/* Get access list from list of access_list.  If there isn't matched
   access_list create new one and return it. */
static struct access_list *access_list_get(afi_t afi, const char *name)
{
	struct access_list *access;

	access = access_list_lookup(afi, name);
	if (access == NULL)
		access = access_list_insert(afi, name);
	return access;
}

/* Apply access list to object (which should be struct prefix *). */
enum filter_type access_list_apply(struct access_list *access,
				   const void *object)
{
	struct filter *filter;
	const struct prefix *p = (const struct prefix *)object;

	if (access == NULL)
		return FILTER_DENY;

	for (filter = access->head; filter; filter = filter->next) {
		if (filter->cisco) {
			if (filter_match_cisco(filter, p))
				return filter->type;
		} else {
			if (filter_match_zebra(filter, p))
				return filter->type;
		}
	}

	return FILTER_DENY;
}

/* Add hook function. */
void access_list_add_hook(void (*func)(struct access_list *access))
{
	access_master_ipv4.add_hook = func;
	access_master_ipv6.add_hook = func;
	access_master_mac.add_hook = func;
}

/* Delete hook function. */
void access_list_delete_hook(void (*func)(struct access_list *access))
{
	access_master_ipv4.delete_hook = func;
	access_master_ipv6.delete_hook = func;
	access_master_mac.delete_hook = func;
}

/* Calculate new sequential number. */
static int64_t filter_new_seq_get(struct access_list *access)
{
	int64_t maxseq;
	int64_t newseq;
	struct filter *filter;

	maxseq = newseq = 0;

	for (filter = access->head; filter; filter = filter->next) {
		if (maxseq < filter->seq)
			maxseq = filter->seq;
	}

	newseq = ((maxseq / 5) * 5) + 5;

	return (newseq > UINT_MAX) ? UINT_MAX : newseq;
}

/* Return access list entry which has same seq number. */
static struct filter *filter_seq_check(struct access_list *access,
						  int64_t seq)
{
	struct filter *filter;

	for (filter = access->head; filter; filter = filter->next)
		if (filter->seq == seq)
			return filter;
	return NULL;
}

/* If access_list has no filter then return 1. */
static int access_list_empty(struct access_list *access)
{
	if (access->head == NULL && access->tail == NULL)
		return 1;
	else
		return 0;
}

/* Delete filter from specified access_list.  If there is hook
   function execute it. */
static void access_list_filter_delete(struct access_list *access,
				      struct filter *filter)
{
	struct access_master *master;

	master = access->master;

	if (filter->next)
		filter->next->prev = filter->prev;
	else
		access->tail = filter->prev;

	if (filter->prev)
		filter->prev->next = filter->next;
	else
		access->head = filter->next;

	filter_free(filter);

	route_map_notify_dependencies(access->name, RMAP_EVENT_FILTER_DELETED);
	/* Run hook function. */
	if (master->delete_hook)
		(*master->delete_hook)(access);

	/* If access_list becomes empty delete it from access_master. */
	if (access_list_empty(access))
		access_list_delete(access);
}

/* Add new filter to the end of specified access_list. */
static void access_list_filter_add(struct access_list *access,
				   struct filter *filter)
{
	struct filter *replace;
	struct filter *point;

	/* Automatic asignment of seq no. */
	if (filter->seq == -1)
		filter->seq = filter_new_seq_get(access);

	if (access->tail && filter->seq > access->tail->seq)
		point = NULL;
	else {
		/* Is there any same seq access list filter? */
		replace = filter_seq_check(access, filter->seq);
		if (replace)
			access_list_filter_delete(access, replace);

		/* Check insert point. */
		for (point = access->head; point; point = point->next)
			if (point->seq >= filter->seq)
				break;
	}

	/* In case of this is the first element of the list. */
	filter->next = point;

	if (point) {
		if (point->prev)
			point->prev->next = filter;
		else
			access->head = filter;

		filter->prev = point->prev;
		point->prev = filter;
	} else {
		if (access->tail)
			access->tail->next = filter;
		else
			access->head = filter;

		filter->prev = access->tail;
		access->tail = filter;
	}

	/* Run hook function. */
	if (access->master->add_hook)
		(*access->master->add_hook)(access);
	route_map_notify_dependencies(access->name, RMAP_EVENT_FILTER_ADDED);
}

/*
  deny    Specify packets to reject
  permit  Specify packets to forward
  dynamic ?
*/

/*
  Hostname or A.B.C.D  Address to match
  any                  Any source host
  host                 A single host address
*/

static struct filter *filter_lookup_cisco(struct access_list *access,
					  struct filter *mnew)
{
	struct filter *mfilter;
	struct filter_cisco *filter;
	struct filter_cisco *new;

	new = &mnew->u.cfilter;

	for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
		filter = &mfilter->u.cfilter;

		if (filter->extended) {
			if (mfilter->type == mnew->type
			    && filter->addr.s_addr == new->addr.s_addr
			    && filter->addr_mask.s_addr == new->addr_mask.s_addr
			    && filter->mask.s_addr == new->mask.s_addr
			    && filter->mask_mask.s_addr
				       == new->mask_mask.s_addr)
				return mfilter;
		} else {
			if (mfilter->type == mnew->type
			    && filter->addr.s_addr == new->addr.s_addr
			    && filter->addr_mask.s_addr
				       == new->addr_mask.s_addr)
				return mfilter;
		}
	}

	return NULL;
}

static struct filter *filter_lookup_zebra(struct access_list *access,
					  struct filter *mnew)
{
	struct filter *mfilter;
	struct filter_zebra *filter;
	struct filter_zebra *new;

	new = &mnew->u.zfilter;

	for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
		filter = &mfilter->u.zfilter;

		if (filter->exact == new->exact
		    && mfilter->type == mnew->type) {
			if (prefix_same(&filter->prefix, &new->prefix))
				return mfilter;
		}
	}
	return NULL;
}

static int vty_access_list_remark_unset(struct vty *vty, afi_t afi,
					const char *name)
{
	struct access_list *access;

	access = access_list_lookup(afi, name);
	if (!access) {
		vty_out(vty, "%% access-list %s doesn't exist\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (access->remark) {
		XFREE(MTYPE_TMP, access->remark);
		access->remark = NULL;
	}

	if (access->head == NULL && access->tail == NULL)
		access_list_delete(access);

	return CMD_SUCCESS;
}

static int filter_set_cisco(struct vty *vty, const char *name_str,
			    const char *seq, const char *type_str,
			    const char *addr_str, const char *addr_mask_str,
			    const char *mask_str, const char *mask_mask_str,
			    int extended, int set)
{
	int ret;
	enum filter_type type = FILTER_DENY;
	struct filter *mfilter;
	struct filter_cisco *filter;
	struct access_list *access;
	struct in_addr addr;
	struct in_addr addr_mask;
	struct in_addr mask;
	struct in_addr mask_mask;
	int64_t seqnum = -1;

	if (seq)
		seqnum = (int64_t)atol(seq);

	/* Check of filter type. */
	if (type_str) {
		if (strncmp(type_str, "p", 1) == 0)
			type = FILTER_PERMIT;
		else if (strncmp(type_str, "d", 1) == 0)
			type = FILTER_DENY;
		else {
			vty_out(vty, "%% filter type must be permit or deny\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	ret = inet_aton(addr_str, &addr);
	if (ret <= 0) {
		vty_out(vty, "%%Inconsistent address and mask\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = inet_aton(addr_mask_str, &addr_mask);
	if (ret <= 0) {
		vty_out(vty, "%%Inconsistent address and mask\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (extended) {
		ret = inet_aton(mask_str, &mask);
		if (ret <= 0) {
			vty_out(vty, "%%Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		ret = inet_aton(mask_mask_str, &mask_mask);
		if (ret <= 0) {
			vty_out(vty, "%%Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	mfilter = filter_new();
	mfilter->type = type;
	mfilter->cisco = 1;
	mfilter->seq = seqnum;
	filter = &mfilter->u.cfilter;
	filter->extended = extended;
	filter->addr.s_addr = addr.s_addr & ~addr_mask.s_addr;
	filter->addr_mask.s_addr = addr_mask.s_addr;

	if (extended) {
		filter->mask.s_addr = mask.s_addr & ~mask_mask.s_addr;
		filter->mask_mask.s_addr = mask_mask.s_addr;
	}

	/* Install new filter to the access_list. */
	access = access_list_get(AFI_IP, name_str);

	if (set) {
		if (filter_lookup_cisco(access, mfilter))
			filter_free(mfilter);
		else
			access_list_filter_add(access, mfilter);
	} else {
		struct filter *delete_filter;

		delete_filter = filter_lookup_cisco(access, mfilter);
		if (delete_filter)
			access_list_filter_delete(access, delete_filter);

		filter_free(mfilter);
	}

	return CMD_SUCCESS;
}

/* Standard access-list */
DEFUN (access_list_standard,
       access_list_standard_cmd,
       "access-list <(1-99)|(1300-1999)> [seq (1-4294967295)] <deny|permit> A.B.C.D A.B.C.D",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Address to match\n"
       "Wildcard bits\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *address = NULL;
	char *wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		address = argv[idx]->arg;
		wildcard = argv[idx + 1]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				address, wildcard, NULL, NULL, 0, 1);
}

DEFUN (access_list_standard_nomask,
       access_list_standard_nomask_cmd,
       "access-list <(1-99)|(1300-1999)> [seq (1-4294967295)] <deny|permit> A.B.C.D",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Address to match\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *address = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx)
		address = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				address, "0.0.0.0", NULL, NULL, 0, 1);
}

DEFUN (access_list_standard_host,
       access_list_standard_host_cmd,
       "access-list <(1-99)|(1300-1999)> [seq (1-4294967295)] <deny|permit> host A.B.C.D",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "A single host address\n"
       "Address to match\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *address = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx)
		address = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				address, "0.0.0.0", NULL, NULL, 0, 1);
}

DEFUN (access_list_standard_any,
       access_list_standard_any_cmd,
       "access-list <(1-99)|(1300-1999)> [seq (1-4294967295)] <deny|permit> any",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any source host\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				"0.0.0.0", "255.255.255.255", NULL, NULL, 0, 1);
}

DEFUN (no_access_list_standard,
       no_access_list_standard_cmd,
       "no access-list <(1-99)|(1300-1999)> [seq (1-4294967295)] <deny|permit> A.B.C.D A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Address to match\n"
       "Wildcard bits\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *address = NULL;
	char *wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		address = argv[idx]->arg;
		wildcard = argv[idx + 1]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				address, wildcard, NULL, NULL, 0, 0);
}

DEFUN (no_access_list_standard_nomask,
       no_access_list_standard_nomask_cmd,
       "no access-list <(1-99)|(1300-1999)> [seq (1-4294967295)] <deny|permit> A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Address to match\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *address = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx)
		address = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				address, "0.0.0.0", NULL, NULL, 0, 0);
}

DEFUN (no_access_list_standard_host,
       no_access_list_standard_host_cmd,
       "no access-list <(1-99)|(1300-1999)> [seq (1-4294967295)] <deny|permit> host A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "A single host address\n"
       "Address to match\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *address = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx)
		address = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				address, "0.0.0.0", NULL, NULL, 0, 0);
}

DEFUN (no_access_list_standard_any,
       no_access_list_standard_any_cmd,
       "no access-list <(1-99)|(1300-1999)> [seq (1-4294967295)] <deny|permit> any",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP standard access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any source host\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				"0.0.0.0", "255.255.255.255", NULL, NULL, 0, 0);
}

/* Extended access-list */
DEFUN (access_list_extended,
       access_list_extended_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip A.B.C.D A.B.C.D A.B.C.D A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *dst = NULL;
	char *src_wildcard = NULL;
	char *dst_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		src_wildcard = argv[idx + 1]->arg;
		dst = argv[idx + 2]->arg;
		dst_wildcard = argv[idx + 3]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				src_wildcard, dst, dst_wildcard, 1, 1);
}

DEFUN (access_list_extended_mask_any,
       access_list_extended_mask_any_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip A.B.C.D A.B.C.D any",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "Any destination host\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *src_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		src_wildcard = argv[idx + 1]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				src_wildcard, "0.0.0.0", "255.255.255.255", 1,
				1);
}

DEFUN (access_list_extended_any_mask,
       access_list_extended_any_mask_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip any A.B.C.D A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *dst = NULL;
	char *dst_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		dst = argv[idx]->arg;
		dst_wildcard = argv[idx + 1]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				"0.0.0.0", "255.255.255.255", dst, dst_wildcard,
				1, 1);
}

DEFUN (access_list_extended_any_any,
       access_list_extended_any_any_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip any any",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "Any destination host\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				"0.0.0.0", "255.255.255.255", "0.0.0.0",
				"255.255.255.255", 1, 1);
}

DEFUN (access_list_extended_mask_host,
       access_list_extended_mask_host_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip A.B.C.D A.B.C.D host A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "A single destination host\n"
       "Destination address\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *dst = NULL;
	char *src_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		src_wildcard = argv[idx + 1]->arg;
		dst = argv[idx + 3]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				src_wildcard, dst, "0.0.0.0", 1, 1);
}

DEFUN (access_list_extended_host_mask,
       access_list_extended_host_mask_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip host A.B.C.D A.B.C.D A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *dst = NULL;
	char *dst_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		dst = argv[idx + 1]->arg;
		dst_wildcard = argv[idx + 2]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				"0.0.0.0", dst, dst_wildcard, 1, 1);
}

DEFUN (access_list_extended_host_host,
       access_list_extended_host_host_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip host A.B.C.D host A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "A single destination host\n"
       "Destination address\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *dst = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		dst = argv[idx + 2]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				"0.0.0.0", dst, "0.0.0.0", 1, 1);
}

DEFUN (access_list_extended_any_host,
       access_list_extended_any_host_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip any host A.B.C.D",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "A single destination host\n"
       "Destination address\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *dst = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx)
		dst = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				"0.0.0.0", "255.255.255.255", dst, "0.0.0.0", 1,
				1);
}

DEFUN (access_list_extended_host_any,
       access_list_extended_host_any_cmd,
       "access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip host A.B.C.D any",
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "Any destination host\n")
{
	int idx_acl = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx)
		src = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				"0.0.0.0", "0.0.0.0", "255.255.255.255", 1, 1);
}

DEFUN (no_access_list_extended,
       no_access_list_extended_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip A.B.C.D A.B.C.D A.B.C.D A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *dst = NULL;
	char *src_wildcard = NULL;
	char *dst_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		src_wildcard = argv[idx + 1]->arg;
		dst = argv[idx + 2]->arg;
		dst_wildcard = argv[idx + 3]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				src_wildcard, dst, dst_wildcard, 1, 0);
}

DEFUN (no_access_list_extended_mask_any,
       no_access_list_extended_mask_any_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip A.B.C.D A.B.C.D any",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "Any destination host\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *src_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		src_wildcard = argv[idx + 1]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				src_wildcard, "0.0.0.0", "255.255.255.255", 1,
				0);
}

DEFUN (no_access_list_extended_any_mask,
       no_access_list_extended_any_mask_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip any A.B.C.D A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *dst = NULL;
	char *dst_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		dst = argv[idx]->arg;
		dst_wildcard = argv[idx + 1]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				"0.0.0.0", "255.255.255.255", dst, dst_wildcard,
				1, 0);
}

DEFUN (no_access_list_extended_any_any,
       no_access_list_extended_any_any_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip any any",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "Any destination host\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				"0.0.0.0", "255.255.255.255", "0.0.0.0",
				"255.255.255.255", 1, 0);
}

DEFUN (no_access_list_extended_mask_host,
       no_access_list_extended_mask_host_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip A.B.C.D A.B.C.D host A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Source address\n"
       "Source wildcard bits\n"
       "A single destination host\n"
       "Destination address\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *dst = NULL;
	char *src_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		src_wildcard = argv[idx + 1]->arg;
		dst = argv[idx + 3]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				src_wildcard, dst, "0.0.0.0", 1, 0);
}

DEFUN (no_access_list_extended_host_mask,
       no_access_list_extended_host_mask_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip host A.B.C.D A.B.C.D A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "Destination address\n"
       "Destination Wildcard bits\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *dst = NULL;
	char *dst_wildcard = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		dst = argv[idx + 1]->arg;
		dst_wildcard = argv[idx + 2]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				"0.0.0.0", dst, dst_wildcard, 1, 0);
}

DEFUN (no_access_list_extended_host_host,
       no_access_list_extended_host_host_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip host A.B.C.D host A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "A single destination host\n"
       "Destination address\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;
	char *dst = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx) {
		src = argv[idx]->arg;
		dst = argv[idx + 2]->arg;
	}

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				"0.0.0.0", dst, "0.0.0.0", 1, 0);
}

DEFUN (no_access_list_extended_any_host,
       no_access_list_extended_any_host_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip any host A.B.C.D",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "Any source host\n"
       "A single destination host\n"
       "Destination address\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *dst = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx)
		dst = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny,
				"0.0.0.0", "255.255.255.255", dst, "0.0.0.0", 1,
				0);
}

DEFUN (no_access_list_extended_host_any,
       no_access_list_extended_host_any_cmd,
       "no access-list <(100-199)|(2000-2699)> [seq (1-4294967295)] <deny|permit> ip host A.B.C.D any",
       NO_STR
       "Add an access list entry\n"
       "IP extended access list\n"
       "IP extended access list (expanded range)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any Internet Protocol\n"
       "A single source host\n"
       "Source address\n"
       "Any destination host\n")
{
	int idx_acl = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *src = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D", &idx);
	if (idx)
		src = argv[idx]->arg;

	return filter_set_cisco(vty, argv[idx_acl]->arg, seq, permit_deny, src,
				"0.0.0.0", "0.0.0.0", "255.255.255.255", 1, 0);
}

static int filter_set_zebra(struct vty *vty, const char *name_str,
			    const char *seq, const char *type_str, afi_t afi,
			    const char *prefix_str, int exact, int set)
{
	int ret;
	enum filter_type type = FILTER_DENY;
	struct filter *mfilter;
	struct filter_zebra *filter;
	struct access_list *access;
	struct prefix p;
	int64_t seqnum = -1;

	if (strlen(name_str) > ACL_NAMSIZ) {
		vty_out(vty,
			"%% ACL name %s is invalid: length exceeds "
			"%d characters\n",
			name_str, ACL_NAMSIZ);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (seq)
		seqnum = (int64_t)atol(seq);

	/* Check of filter type. */
	if (type_str) {
		if (strncmp(type_str, "p", 1) == 0)
			type = FILTER_PERMIT;
		else if (strncmp(type_str, "d", 1) == 0)
			type = FILTER_DENY;
		else {
			vty_out(vty, "filter type must be [permit|deny]\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Check string format of prefix and prefixlen. */
	if (afi == AFI_IP) {
		ret = str2prefix_ipv4(prefix_str, (struct prefix_ipv4 *)&p);
		if (ret <= 0) {
			vty_out(vty,
				"IP address prefix/prefixlen is malformed\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else if (afi == AFI_IP6) {
		ret = str2prefix_ipv6(prefix_str, (struct prefix_ipv6 *)&p);
		if (ret <= 0) {
			vty_out(vty,
				"IPv6 address prefix/prefixlen is malformed\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else if (afi == AFI_L2VPN) {
		ret = str2prefix_eth(prefix_str, (struct prefix_eth *)&p);
		if (ret <= 0) {
			vty_out(vty, "MAC address is malformed\n");
			return CMD_WARNING;
		}
	} else
		return CMD_WARNING_CONFIG_FAILED;

	mfilter = filter_new();
	mfilter->type = type;
	mfilter->seq = seqnum;
	filter = &mfilter->u.zfilter;
	prefix_copy(&filter->prefix, &p);

	/* "exact-match" */
	if (exact)
		filter->exact = 1;

	/* Install new filter to the access_list. */
	access = access_list_get(afi, name_str);

	if (set) {
		if (filter_lookup_zebra(access, mfilter))
			filter_free(mfilter);
		else
			access_list_filter_add(access, mfilter);
	} else {
		struct filter *delete_filter;
		delete_filter = filter_lookup_zebra(access, mfilter);
		if (delete_filter)
			access_list_filter_delete(access, delete_filter);

		filter_free(mfilter);
	}

	return CMD_SUCCESS;
}

DEFUN (mac_access_list,
       mac_access_list_cmd,
       "mac access-list WORD [seq (1-4294967295)] <deny|permit> X:X:X:X:X:X",
       "Add a mac access-list\n"
       "Add an access list entry\n"
       "MAC zebra access-list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "MAC address to match. e.g. 00:01:00:01:00:01\n")
{
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *mac = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "X:X:X:X:X:X", &idx);
	if (idx)
		mac = argv[idx]->arg;
	assert(mac);

	return filter_set_zebra(vty, argv[2]->arg, seq, permit_deny, AFI_L2VPN,
				mac, 0, 1);
}

DEFUN (no_mac_access_list,
       no_mac_access_list_cmd,
       "no mac access-list WORD [seq (1-4294967295)] <deny|permit> X:X:X:X:X:X",
       NO_STR
       "Remove a mac access-list\n"
       "Remove an access list entry\n"
       "MAC zebra access-list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "MAC address to match. e.g. 00:01:00:01:00:01\n")
{
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *mac = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "X:X:X:X:X:X", &idx);
	if (idx)
		mac = argv[idx]->arg;
	assert(mac);

	return filter_set_zebra(vty, argv[2]->arg, seq, permit_deny, AFI_L2VPN,
				mac, 0, 0);
}

DEFUN (mac_access_list_any,
       mac_access_list_any_cmd,
       "mac access-list WORD [seq (1-4294967295)] <deny|permit> any",
       "Add a mac access-list\n"
       "Add an access list entry\n"
       "MAC zebra access-list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "MAC address to match. e.g. 00:01:00:01:00:01\n")
{
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_zebra(vty, argv[2]->arg, seq, permit_deny, AFI_L2VPN,
				"00:00:00:00:00:00", 0, 1);
}

DEFUN (no_mac_access_list_any,
       no_mac_access_list_any_cmd,
       "no mac access-list WORD [seq (1-4294967295)] <deny|permit> any",
       NO_STR
       "Remove a mac access-list\n"
       "Remove an access list entry\n"
       "MAC zebra access-list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "MAC address to match. e.g. 00:01:00:01:00:01\n")
{
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_zebra(vty, argv[2]->arg, seq, permit_deny, AFI_L2VPN,
				"00:00:00:00:00:00", 0, 0);
}

DEFUN (access_list_exact,
       access_list_exact_cmd,
       "access-list WORD [seq (1-4294967295)] <deny|permit> A.B.C.D/M [exact-match]",
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n"
       "Exact match of the prefixes\n")
{
	int idx = 0;
	int exact = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *prefix = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D/M", &idx);
	if (idx)
		prefix = argv[idx]->arg;
	assert(prefix);

	idx = 0;
	if (argv_find(argv, argc, "exact-match", &idx))
		exact = 1;

	return filter_set_zebra(vty, argv[1]->arg, seq, permit_deny,
				AFI_IP, prefix, exact, 1);
}

DEFUN (access_list_any,
       access_list_any_cmd,
       "access-list WORD [seq (1-4294967295)] <deny|permit> any",
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n")
{
	int idx_word = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_zebra(vty, argv[idx_word]->arg, seq, permit_deny,
				AFI_IP, "0.0.0.0/0", 0, 1);
}

DEFUN (no_access_list_exact,
       no_access_list_exact_cmd,
       "no access-list WORD [seq (1-4294967295)] <deny|permit> A.B.C.D/M [exact-match]",
       NO_STR
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n"
       "Exact match of the prefixes\n")
{
	int idx = 0;
	int exact = 0;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *prefix = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "A.B.C.D/M", &idx);
	if (idx)
		prefix = argv[idx]->arg;
	assert(prefix);

	idx = 0;
	if (argv_find(argv, argc, "exact-match", &idx))
		exact = 1;

	return filter_set_zebra(vty, argv[2]->arg, seq, permit_deny,
				AFI_IP, prefix, exact, 0);
}

DEFUN (no_access_list_any,
       no_access_list_any_cmd,
       "no access-list WORD [seq (1-4294967295)] <deny|permit> any",
       NO_STR
       "Add an access list entry\n"
       "IP zebra access-list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n")
{
	int idx_word = 1;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_zebra(vty, argv[idx_word]->arg, seq, permit_deny,
				AFI_IP, "0.0.0.0/0", 0, 0);
}

DEFUN (no_access_list_all,
       no_access_list_all_cmd,
       "no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)|WORD>",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list name\n")
{
	int idx_acl = 2;
	struct access_list *access;
	struct access_master *master;

	/* Looking up access_list. */
	access = access_list_lookup(AFI_IP, argv[idx_acl]->arg);
	if (access == NULL) {
		vty_out(vty, "%% access-list %s doesn't exist\n",
			argv[idx_acl]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	master = access->master;

	route_map_notify_dependencies(access->name, RMAP_EVENT_FILTER_DELETED);
	/* Run hook function. */
	if (master->delete_hook)
		(*master->delete_hook)(access);

	/* Delete all filter from access-list. */
	access_list_delete(access);

	return CMD_SUCCESS;
}

DEFUN (access_list_remark,
       access_list_remark_cmd,
       "access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)|WORD> remark LINE...",
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")
{
	int idx_acl = 1;
	int idx_remark = 3;
	struct access_list *access;

	access = access_list_get(AFI_IP, argv[idx_acl]->arg);

	if (access->remark) {
		XFREE(MTYPE_TMP, access->remark);
		access->remark = NULL;
	}
	access->remark = argv_concat(argv, argc, idx_remark);

	return CMD_SUCCESS;
}

DEFUN (no_access_list_remark,
       no_access_list_remark_cmd,
       "no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)|WORD> remark",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n"
       "Access list entry comment\n")
{
	int idx_acl = 2;
	return vty_access_list_remark_unset(vty, AFI_IP, argv[idx_acl]->arg);
}

/* ALIAS_FIXME */
DEFUN (no_access_list_remark_comment,
       no_access_list_remark_comment_cmd,
       "no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)|WORD> remark LINE...",
       NO_STR
       "Add an access list entry\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")
{
	return no_access_list_remark(self, vty, argc, argv);
}

DEFUN (ipv6_access_list_exact,
       ipv6_access_list_exact_cmd,
       "ipv6 access-list WORD [seq (1-4294967295)] <deny|permit> X:X::X:X/M [exact-match]",
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix\n"
       "Exact match of the prefixes\n")
{
	int idx = 0;
	int exact = 0;
	int idx_word = 2;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *prefix = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "X:X::X:X/M", &idx);
	if (idx)
		prefix = argv[idx]->arg;

	idx = 0;
	if (argv_find(argv, argc, "exact-match", &idx))
		exact = 1;

	return filter_set_zebra(vty, argv[idx_word]->arg, seq, permit_deny,
				AFI_IP6, prefix, exact, 1);
}

DEFUN (ipv6_access_list_any,
       ipv6_access_list_any_cmd,
       "ipv6 access-list WORD [seq (1-4294967295)] <deny|permit> any",
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any prefixi to match\n")
{
	int idx_word = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_zebra(vty, argv[idx_word]->arg, seq, permit_deny,
				AFI_IP6, "::/0", 0, 1);
}

DEFUN (no_ipv6_access_list_exact,
       no_ipv6_access_list_exact_cmd,
       "no ipv6 access-list WORD [seq (1-4294967295)] <deny|permit> X:X::X:X/M [exact-match]",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n"
       "Exact match of the prefixes\n")
{
	int idx = 0;
	int exact = 0;
	int idx_word = 2;
	char *seq = NULL;
	char *permit_deny = NULL;
	char *prefix = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "X:X::X:X/M", &idx);
	if (idx)
		prefix = argv[idx]->arg;
	assert(prefix);

	idx = 0;
	if (argv_find(argv, argc, "exact-match", &idx))
		exact = 1;

	return filter_set_zebra(vty, argv[idx_word]->arg, seq, permit_deny,
				AFI_IP6, prefix, exact, 0);
}

DEFUN (no_ipv6_access_list_any,
       no_ipv6_access_list_any_cmd,
       "no ipv6 access-list WORD [seq (1-4294967295)] <deny|permit> any",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Any prefixi to match\n")
{
	int idx_word = 2;
	int idx = 0;
	char *seq = NULL;
	char *permit_deny = NULL;

	argv_find(argv, argc, "(1-4294967295)", &idx);
	if (idx)
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx)
		permit_deny = argv[idx]->arg;

	return filter_set_zebra(vty, argv[idx_word]->arg, seq, permit_deny,
				AFI_IP6, "::/0", 0, 0);
}


DEFUN (no_ipv6_access_list_all,
       no_ipv6_access_list_all_cmd,
       "no ipv6 access-list WORD",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n")
{
	int idx_word = 3;
	struct access_list *access;
	struct access_master *master;

	/* Looking up access_list. */
	access = access_list_lookup(AFI_IP6, argv[idx_word]->arg);
	if (access == NULL) {
		vty_out(vty, "%% access-list %s doesn't exist\n",
			argv[idx_word]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	master = access->master;

	route_map_notify_dependencies(access->name, RMAP_EVENT_FILTER_DELETED);
	/* Run hook function. */
	if (master->delete_hook)
		(*master->delete_hook)(access);

	/* Delete all filter from access-list. */
	access_list_delete(access);

	return CMD_SUCCESS;
}

DEFUN (ipv6_access_list_remark,
       ipv6_access_list_remark_cmd,
       "ipv6 access-list WORD remark LINE...",
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")
{
	int idx_word = 2;
	int idx_line = 4;
	struct access_list *access;

	access = access_list_get(AFI_IP6, argv[idx_word]->arg);

	if (access->remark) {
		XFREE(MTYPE_TMP, access->remark);
		access->remark = NULL;
	}
	access->remark = argv_concat(argv, argc, idx_line);

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_access_list_remark,
       no_ipv6_access_list_remark_cmd,
       "no ipv6 access-list WORD remark",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Access list entry comment\n")
{
	int idx_word = 3;
	return vty_access_list_remark_unset(vty, AFI_IP6, argv[idx_word]->arg);
}

/* ALIAS_FIXME */
DEFUN (no_ipv6_access_list_remark_comment,
       no_ipv6_access_list_remark_comment_cmd,
       "no ipv6 access-list WORD remark LINE...",
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "IPv6 zebra access-list\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")
{
	return no_ipv6_access_list_remark(self, vty, argc, argv);
}

void config_write_access_zebra(struct vty *, struct filter *);
void config_write_access_cisco(struct vty *, struct filter *);

/* show access-list command. */
static int filter_show(struct vty *vty, const char *name, afi_t afi)
{
	struct access_list *access;
	struct access_master *master;
	struct filter *mfilter;
	struct filter_cisco *filter;
	int write = 0;

	master = access_master_get(afi);
	if (master == NULL)
		return 0;

	/* Print the name of the protocol */
	vty_out(vty, "%s:\n", frr_protoname);

	for (access = master->num.head; access; access = access->next) {
		if (name && strcmp(access->name, name) != 0)
			continue;

		write = 1;

		for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
			filter = &mfilter->u.cfilter;

			if (write) {
				vty_out(vty, "%s %s access list %s\n",
					mfilter->cisco ? (filter->extended
								  ? "Extended"
								  : "Standard")
						       : "Zebra",
					(afi == AFI_IP)
						? ("IP")
						: ((afi == AFI_IP6) ? ("IPv6 ")
								    : ("MAC ")),
					access->name);
				write = 0;
			}

			vty_out(vty, "    seq %" PRId64, mfilter->seq);
			vty_out(vty, " %s%s", filter_type_str(mfilter),
				mfilter->type == FILTER_DENY ? "  " : "");

			if (!mfilter->cisco)
				config_write_access_zebra(vty, mfilter);
			else if (filter->extended)
				config_write_access_cisco(vty, mfilter);
			else {
				if (filter->addr_mask.s_addr == 0xffffffff)
					vty_out(vty, " any\n");
				else {
					vty_out(vty, " %s",
						inet_ntoa(filter->addr));
					if (filter->addr_mask.s_addr != 0)
						vty_out(vty,
							", wildcard bits %s",
							inet_ntoa(
								filter->addr_mask));
					vty_out(vty, "\n");
				}
			}
		}
	}

	for (access = master->str.head; access; access = access->next) {
		if (name && strcmp(access->name, name) != 0)
			continue;

		write = 1;

		for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
			filter = &mfilter->u.cfilter;

			if (write) {
				vty_out(vty, "%s %s access list %s\n",
					mfilter->cisco ? (filter->extended
								  ? "Extended"
								  : "Standard")
						       : "Zebra",
					(afi == AFI_IP)
						? ("IP")
						: ((afi == AFI_IP6) ? ("IPv6 ")
								    : ("MAC ")),
					access->name);
				write = 0;
			}

			vty_out(vty, "    seq %" PRId64, mfilter->seq);
			vty_out(vty, " %s%s", filter_type_str(mfilter),
				mfilter->type == FILTER_DENY ? "  " : "");

			if (!mfilter->cisco)
				config_write_access_zebra(vty, mfilter);
			else if (filter->extended)
				config_write_access_cisco(vty, mfilter);
			else {
				if (filter->addr_mask.s_addr == 0xffffffff)
					vty_out(vty, " any\n");
				else {
					vty_out(vty, " %s",
						inet_ntoa(filter->addr));
					if (filter->addr_mask.s_addr != 0)
						vty_out(vty,
							", wildcard bits %s",
							inet_ntoa(
								filter->addr_mask));
					vty_out(vty, "\n");
				}
			}
		}
	}
	return CMD_SUCCESS;
}

/* show MAC access list - this only has MAC filters for now*/
DEFUN (show_mac_access_list,
       show_mac_access_list_cmd,
       "show mac access-list",
       SHOW_STR
       "mac access lists\n"
       "List mac access lists\n")
{
	return filter_show(vty, NULL, AFI_L2VPN);
}

DEFUN (show_mac_access_list_name,
       show_mac_access_list_name_cmd,
       "show mac access-list WORD",
       SHOW_STR
       "mac access lists\n"
       "List mac access lists\n"
       "mac address\n")
{
	return filter_show(vty, argv[3]->arg, AFI_L2VPN);
}

DEFUN (show_ip_access_list,
       show_ip_access_list_cmd,
       "show ip access-list",
       SHOW_STR
       IP_STR
       "List IP access lists\n")
{
	return filter_show(vty, NULL, AFI_IP);
}

DEFUN (show_ip_access_list_name,
       show_ip_access_list_name_cmd,
       "show ip access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)|WORD>",
       SHOW_STR
       IP_STR
       "List IP access lists\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n")
{
	int idx_acl = 3;
	return filter_show(vty, argv[idx_acl]->arg, AFI_IP);
}

DEFUN (show_ipv6_access_list,
       show_ipv6_access_list_cmd,
       "show ipv6 access-list",
       SHOW_STR
       IPV6_STR
       "List IPv6 access lists\n")
{
	return filter_show(vty, NULL, AFI_IP6);
}

DEFUN (show_ipv6_access_list_name,
       show_ipv6_access_list_name_cmd,
       "show ipv6 access-list WORD",
       SHOW_STR
       IPV6_STR
       "List IPv6 access lists\n"
       "IPv6 zebra access-list\n")
{
	int idx_word = 3;
	return filter_show(vty, argv[idx_word]->arg, AFI_IP6);
}

void config_write_access_cisco(struct vty *vty, struct filter *mfilter)
{
	struct filter_cisco *filter;

	filter = &mfilter->u.cfilter;

	if (filter->extended) {
		vty_out(vty, " ip");
		if (filter->addr_mask.s_addr == 0xffffffff)
			vty_out(vty, " any");
		else if (filter->addr_mask.s_addr == 0)
			vty_out(vty, " host %s", inet_ntoa(filter->addr));
		else {
			vty_out(vty, " %s", inet_ntoa(filter->addr));
			vty_out(vty, " %s", inet_ntoa(filter->addr_mask));
		}

		if (filter->mask_mask.s_addr == 0xffffffff)
			vty_out(vty, " any");
		else if (filter->mask_mask.s_addr == 0)
			vty_out(vty, " host %s", inet_ntoa(filter->mask));
		else {
			vty_out(vty, " %s", inet_ntoa(filter->mask));
			vty_out(vty, " %s", inet_ntoa(filter->mask_mask));
		}
		vty_out(vty, "\n");
	} else {
		if (filter->addr_mask.s_addr == 0xffffffff)
			vty_out(vty, " any\n");
		else {
			vty_out(vty, " %s", inet_ntoa(filter->addr));
			if (filter->addr_mask.s_addr != 0)
				vty_out(vty, " %s",
					inet_ntoa(filter->addr_mask));
			vty_out(vty, "\n");
		}
	}
}

void config_write_access_zebra(struct vty *vty, struct filter *mfilter)
{
	struct filter_zebra *filter;
	struct prefix *p;
	char buf[BUFSIZ];

	filter = &mfilter->u.zfilter;
	p = &filter->prefix;

	if (p->prefixlen == 0 && !filter->exact)
		vty_out(vty, " any");
	else if (p->family == AF_INET6 || p->family == AF_INET)
		vty_out(vty, " %s/%d%s",
			inet_ntop(p->family, &p->u.prefix, buf, BUFSIZ),
			p->prefixlen, filter->exact ? " exact-match" : "");
	else if (p->family == AF_ETHERNET) {
		if (p->prefixlen == 0)
			vty_out(vty, " any");
		else
			vty_out(vty, " %s", prefix_mac2str(&(p->u.prefix_eth),
							   buf, sizeof(buf)));
	}

	vty_out(vty, "\n");
}

static int config_write_access(struct vty *vty, afi_t afi)
{
	struct access_list *access;
	struct access_master *master;
	struct filter *mfilter;
	int write = 0;

	master = access_master_get(afi);
	if (master == NULL)
		return 0;

	for (access = master->num.head; access; access = access->next) {
		if (access->remark) {
			vty_out(vty, "%saccess-list %s remark %s\n",
				(afi == AFI_IP) ? ("")
						: ((afi == AFI_IP6) ? ("ipv6 ")
								    : ("mac ")),
				access->name, access->remark);
			write++;
		}

		for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
			vty_out(vty, "%saccess-list %s seq %" PRId64 " %s",
				(afi == AFI_IP) ? ("")
						: ((afi == AFI_IP6) ? ("ipv6 ")
								    : ("mac ")),
				access->name, mfilter->seq,
				filter_type_str(mfilter));

			if (mfilter->cisco)
				config_write_access_cisco(vty, mfilter);
			else
				config_write_access_zebra(vty, mfilter);

			write++;
		}
	}

	for (access = master->str.head; access; access = access->next) {
		if (access->remark) {
			vty_out(vty, "%saccess-list %s remark %s\n",
				(afi == AFI_IP) ? ("")
						: ((afi == AFI_IP6) ? ("ipv6 ")
								    : ("mac ")),
				access->name, access->remark);
			write++;
		}

		for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
			vty_out(vty, "%saccess-list %s seq %" PRId64 " %s",
				(afi == AFI_IP) ? ("")
						: ((afi == AFI_IP6) ? ("ipv6 ")
								    : ("mac ")),
				access->name, mfilter->seq,
				filter_type_str(mfilter));

			if (mfilter->cisco)
				config_write_access_cisco(vty, mfilter);
			else
				config_write_access_zebra(vty, mfilter);

			write++;
		}
	}
	return write;
}

static struct cmd_node access_mac_node = {
	ACCESS_MAC_NODE, "", /* Access list has no interface. */
	1};

static int config_write_access_mac(struct vty *vty)
{
	return config_write_access(vty, AFI_L2VPN);
}

static void access_list_reset_mac(void)
{
	struct access_list *access;
	struct access_list *next;
	struct access_master *master;

	master = access_master_get(AFI_L2VPN);
	if (master == NULL)
		return;

	for (access = master->num.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}
	for (access = master->str.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}

	assert(master->num.head == NULL);
	assert(master->num.tail == NULL);

	assert(master->str.head == NULL);
	assert(master->str.tail == NULL);
}

/* Install vty related command. */
static void access_list_init_mac(void)
{
	install_node(&access_mac_node, config_write_access_mac);

	install_element(ENABLE_NODE, &show_mac_access_list_cmd);
	install_element(ENABLE_NODE, &show_mac_access_list_name_cmd);

	/* Zebra access-list */
	install_element(CONFIG_NODE, &mac_access_list_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_cmd);
	install_element(CONFIG_NODE, &mac_access_list_any_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_any_cmd);
}

/* Access-list node. */
static struct cmd_node access_node = {ACCESS_NODE,
				      "", /* Access list has no interface. */
				      1};

static int config_write_access_ipv4(struct vty *vty)
{
	return config_write_access(vty, AFI_IP);
}

static void access_list_reset_ipv4(void)
{
	struct access_list *access;
	struct access_list *next;
	struct access_master *master;

	master = access_master_get(AFI_IP);
	if (master == NULL)
		return;

	for (access = master->num.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}
	for (access = master->str.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}

	assert(master->num.head == NULL);
	assert(master->num.tail == NULL);

	assert(master->str.head == NULL);
	assert(master->str.tail == NULL);
}

/* Install vty related command. */
static void access_list_init_ipv4(void)
{
	install_node(&access_node, config_write_access_ipv4);

	install_element(ENABLE_NODE, &show_ip_access_list_cmd);
	install_element(ENABLE_NODE, &show_ip_access_list_name_cmd);

	/* Zebra access-list */
	install_element(CONFIG_NODE, &access_list_exact_cmd);
	install_element(CONFIG_NODE, &access_list_any_cmd);
	install_element(CONFIG_NODE, &no_access_list_exact_cmd);
	install_element(CONFIG_NODE, &no_access_list_any_cmd);

	/* Standard access-list */
	install_element(CONFIG_NODE, &access_list_standard_cmd);
	install_element(CONFIG_NODE, &access_list_standard_nomask_cmd);
	install_element(CONFIG_NODE, &access_list_standard_host_cmd);
	install_element(CONFIG_NODE, &access_list_standard_any_cmd);
	install_element(CONFIG_NODE, &no_access_list_standard_cmd);
	install_element(CONFIG_NODE, &no_access_list_standard_nomask_cmd);
	install_element(CONFIG_NODE, &no_access_list_standard_host_cmd);
	install_element(CONFIG_NODE, &no_access_list_standard_any_cmd);

	/* Extended access-list */
	install_element(CONFIG_NODE, &access_list_extended_cmd);
	install_element(CONFIG_NODE, &access_list_extended_any_mask_cmd);
	install_element(CONFIG_NODE, &access_list_extended_mask_any_cmd);
	install_element(CONFIG_NODE, &access_list_extended_any_any_cmd);
	install_element(CONFIG_NODE, &access_list_extended_host_mask_cmd);
	install_element(CONFIG_NODE, &access_list_extended_mask_host_cmd);
	install_element(CONFIG_NODE, &access_list_extended_host_host_cmd);
	install_element(CONFIG_NODE, &access_list_extended_any_host_cmd);
	install_element(CONFIG_NODE, &access_list_extended_host_any_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_any_mask_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_mask_any_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_any_any_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_host_mask_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_mask_host_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_host_host_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_any_host_cmd);
	install_element(CONFIG_NODE, &no_access_list_extended_host_any_cmd);

	install_element(CONFIG_NODE, &access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_all_cmd);
	install_element(CONFIG_NODE, &no_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_remark_comment_cmd);
}

static struct cmd_node access_ipv6_node = {ACCESS_IPV6_NODE, "", 1};

static int config_write_access_ipv6(struct vty *vty)
{
	return config_write_access(vty, AFI_IP6);
}

static void access_list_reset_ipv6(void)
{
	struct access_list *access;
	struct access_list *next;
	struct access_master *master;

	master = access_master_get(AFI_IP6);
	if (master == NULL)
		return;

	for (access = master->num.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}
	for (access = master->str.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}

	assert(master->num.head == NULL);
	assert(master->num.tail == NULL);

	assert(master->str.head == NULL);
	assert(master->str.tail == NULL);
}

static void access_list_init_ipv6(void)
{
	install_node(&access_ipv6_node, config_write_access_ipv6);

	install_element(ENABLE_NODE, &show_ipv6_access_list_cmd);
	install_element(ENABLE_NODE, &show_ipv6_access_list_name_cmd);

	install_element(CONFIG_NODE, &ipv6_access_list_exact_cmd);
	install_element(CONFIG_NODE, &ipv6_access_list_any_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_exact_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_any_cmd);

	install_element(CONFIG_NODE, &no_ipv6_access_list_all_cmd);
	install_element(CONFIG_NODE, &ipv6_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_remark_comment_cmd);
}

void access_list_init(void)
{
	access_list_init_ipv4();
	access_list_init_ipv6();
	access_list_init_mac();
}

void access_list_reset(void)
{
	access_list_reset_ipv4();
	access_list_reset_ipv6();
	access_list_reset_mac();
}
