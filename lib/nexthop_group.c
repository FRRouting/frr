// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Nexthop Group structure definition.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 */
#include <zebra.h>

#include <vrf.h>
#include <sockunion.h>
#include <nexthop.h>
#include <nexthop_group.h>
#include <nexthop_group_private.h>
#include <vty.h>
#include <command.h>
#include <jhash.h>

#include "lib/nexthop_group_clippy.c"

DEFINE_MTYPE_STATIC(LIB, NEXTHOP_GROUP, "Nexthop Group");

/*
 * Internal struct used to hold nhg config strings
 */
struct nexthop_hold {
	char *nhvrf_name;
	union sockunion *addr;
	char *intf;
	bool onlink;
	char *labels;
	vni_t vni;
	uint32_t weight;
	char *backup_str;
};

struct nexthop_group_hooks {
	void (*new)(const char *name);
	void (*modify)(const struct nexthop_group_cmd *nhgc);
	void (*add_nexthop)(const struct nexthop_group_cmd *nhg,
			    const struct nexthop *nhop);
	void (*del_nexthop)(const struct nexthop_group_cmd *nhg,
			    const struct nexthop *nhop);
	void (*delete)(const char *name);
};

static struct nexthop_group_hooks nhg_hooks;

static inline int
nexthop_group_cmd_compare(const struct nexthop_group_cmd *nhgc1,
			  const struct nexthop_group_cmd *nhgc2);
RB_GENERATE(nhgc_entry_head, nexthop_group_cmd, nhgc_entry,
	    nexthop_group_cmd_compare)

static struct nhgc_entry_head nhgc_entries;

static inline int
nexthop_group_cmd_compare(const struct nexthop_group_cmd *nhgc1,
			  const struct nexthop_group_cmd *nhgc2)
{
	return strcmp(nhgc1->name, nhgc2->name);
}

static struct nexthop *nexthop_group_tail(const struct nexthop_group *nhg)
{
	struct nexthop *nexthop = nhg->nexthop;

	while (nexthop && nexthop->next)
		nexthop = nexthop->next;

	return nexthop;
}

uint16_t nexthop_group_nexthop_num(const struct nexthop_group *nhg)
{
	struct nexthop *nhop;
	uint16_t num = 0;

	for (ALL_NEXTHOPS_PTR(nhg, nhop))
		num++;

	return num;
}

static uint16_t nexthop_group_nexthop_num_no_recurse(const struct nexthop_group *nhg)
{
	struct nexthop *nhop;
	uint16_t num = 0;

	for (nhop = nhg->nexthop; nhop; nhop = nhop->next)
		num++;

	return num;
}

uint16_t nexthop_group_active_nexthop_num(const struct nexthop_group *nhg)
{
	struct nexthop *nhop;
	uint16_t num = 0;

	for (ALL_NEXTHOPS_PTR(nhg, nhop)) {
		if (CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_ACTIVE))
			num++;
	}

	return num;
}

bool nexthop_group_has_label(const struct nexthop_group *nhg)
{
	struct nexthop *nhop;

	for (ALL_NEXTHOPS_PTR(nhg, nhop)) {
		if (nhop->nh_label)
			return true;
	}

	return false;
}

struct nexthop *nexthop_exists(const struct nexthop_group *nhg,
			       const struct nexthop *nh)
{
	struct nexthop *nexthop;

	for (nexthop = nhg->nexthop; nexthop; nexthop = nexthop->next) {
		if (nexthop_same(nh, nexthop))
			return nexthop;
	}

	return NULL;
}

/*
 * Helper that locates a nexthop in an nhg config list. Note that
 * this uses a specific matching / equality rule that's different from
 * the complete match performed by 'nexthop_same()'.
 */
static struct nexthop *nhg_nh_find(const struct nexthop_group *nhg,
				   const struct nexthop *nh)
{
	struct nexthop *nexthop;
	int ret;

	/* We compare: vrf, gateway, and interface */

	for (nexthop = nhg->nexthop; nexthop; nexthop = nexthop->next) {

		/* Compare vrf and type */
		if (nexthop->vrf_id != nh->vrf_id)
			continue;
		if (nexthop->type != nh->type)
			continue;

		/* Compare gateway */
		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV6:
			ret = nexthop_g_addr_cmp(nexthop->type,
						 &nexthop->gate, &nh->gate);
			if (ret != 0)
				continue;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			ret = nexthop_g_addr_cmp(nexthop->type,
						 &nexthop->gate, &nh->gate);
			if (ret != 0)
				continue;
			fallthrough;
		case NEXTHOP_TYPE_IFINDEX:
			if (nexthop->ifindex != nh->ifindex)
				continue;
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			if (nexthop->bh_type != nh->bh_type)
				continue;
			break;
		}

		return nexthop;
	}

	return NULL;
}

static bool nexthop_group_equal_common(
	const struct nexthop_group *nhg1, const struct nexthop_group *nhg2,
	uint16_t (*nexthop_group_nexthop_num_func)(const struct nexthop_group *nhg))
{
	if (nhg1 && !nhg2)
		return false;

	if (!nhg1 && nhg2)
		return false;

	if (nhg1 == nhg2)
		return true;

	if (nexthop_group_nexthop_num_func(nhg1)
	    != nexthop_group_nexthop_num_func(nhg2))
		return false;

	return true;
}

/* This assumes ordered */
bool nexthop_group_equal_no_recurse(const struct nexthop_group *nhg1,
				    const struct nexthop_group *nhg2)
{
	struct nexthop *nh1 = NULL;
	struct nexthop *nh2 = NULL;

	if (!nexthop_group_equal_common(nhg1, nhg2,
					&nexthop_group_nexthop_num_no_recurse))
		return false;

	for (nh1 = nhg1->nexthop, nh2 = nhg2->nexthop; nh1 || nh2;
	     nh1 = nh1->next, nh2 = nh2->next) {
		if (nh1 && !nh2)
			return false;
		if (!nh1 && nh2)
			return false;
		if (!nexthop_same(nh1, nh2))
			return false;
	}

	return true;
}

/* This assumes ordered */
bool nexthop_group_equal(const struct nexthop_group *nhg1,
			 const struct nexthop_group *nhg2)
{
	struct nexthop *nh1 = NULL;
	struct nexthop *nh2 = NULL;

	if (!nexthop_group_equal_common(nhg1, nhg2, &nexthop_group_nexthop_num))
		return false;

	for (nh1 = nhg1->nexthop, nh2 = nhg2->nexthop; nh1 || nh2;
	     nh1 = nexthop_next(nh1), nh2 = nexthop_next(nh2)) {
		if (nh1 && !nh2)
			return false;
		if (!nh1 && nh2)
			return false;
		if (!nexthop_same(nh1, nh2))
			return false;
	}

	return true;
}
struct nexthop_group *nexthop_group_new(void)
{
	return XCALLOC(MTYPE_NEXTHOP_GROUP, sizeof(struct nexthop_group));
}

void nexthop_group_copy(struct nexthop_group *to,
			const struct nexthop_group *from)
{
	to->nhgr = from->nhgr;
	/* Copy everything, including recursive info */
	copy_nexthops(&to->nexthop, from->nexthop, NULL);
}

void nexthop_group_delete(struct nexthop_group **nhg)
{
	/* OK to call with NULL group */
	if ((*nhg) == NULL)
		return;

	if ((*nhg)->nexthop)
		nexthops_free((*nhg)->nexthop);

	XFREE(MTYPE_NEXTHOP_GROUP, *nhg);
}

/* Add nexthop to the end of a nexthop list.  */
void _nexthop_add(struct nexthop **target, struct nexthop *nexthop)
{
	struct nexthop *last;

	for (last = *target; last && last->next; last = last->next)
		;
	if (last)
		last->next = nexthop;
	else
		*target = nexthop;
	nexthop->prev = last;
}

/* Add nexthop to sorted list of nexthops */
static void _nexthop_add_sorted(struct nexthop **head,
				struct nexthop *nexthop)
{
	struct nexthop *position, *prev;

	assert(!nexthop->next);

	for (position = *head, prev = NULL; position;
	     prev = position, position = position->next) {
		if (nexthop_cmp(position, nexthop) > 0) {
			nexthop->next = position;
			nexthop->prev = prev;

			if (nexthop->prev)
				nexthop->prev->next = nexthop;
			else
				*head = nexthop;

			position->prev = nexthop;
			return;
		}
	}

	nexthop->prev = prev;
	if (prev)
		prev->next = nexthop;
	else
		*head = nexthop;
}

void nexthop_group_add_sorted(struct nexthop_group *nhg,
			      struct nexthop *nexthop)
{
	struct nexthop *tail;

	assert(!nexthop->next);

	/* Try to just append to the end first;
	 * trust the list is already sorted
	 */
	tail = nexthop_group_tail(nhg);

	if (tail && (nexthop_cmp(tail, nexthop) < 0)) {
		tail->next = nexthop;
		nexthop->prev = tail;

		return;
	}

	_nexthop_add_sorted(&nhg->nexthop, nexthop);
}

/* Add nexthop to sorted list of nexthops.
 * The difference with _nexthop_add_sorted is that it filters out duplicate nexthops.
 */
static bool _nexthop_add_no_dup(struct nexthop **head, struct nexthop *nexthop)
{
	struct nexthop *position, *prev;
	int ret = 0;

	assert(!nexthop->next);

	for (position = *head, prev = NULL; position; prev = position, position = position->next) {
		ret = nexthop_cmp(position, nexthop);
		if (ret == 0)
			return false;
		else if (nexthop_cmp(position, nexthop) > 0) {
			nexthop->next = position;
			nexthop->prev = prev;

			if (nexthop->prev)
				nexthop->prev->next = nexthop;
			else
				*head = nexthop;

			position->prev = nexthop;
			return true;
		}
	}

	nexthop->prev = prev;
	if (prev)
		prev->next = nexthop;
	else
		*head = nexthop;
	return true;
}

bool nexthop_group_add_sorted_nodup(struct nexthop_group *nhg, struct nexthop *nexthop)
{
	struct nexthop *tail;
	int ret = 0;

	assert(!nexthop->next);

	/* Try to just append to the end first;
	 * trust the list is already sorted
	 */
	tail = nexthop_group_tail(nhg);
	if (tail) {
		ret = nexthop_cmp(tail, nexthop);
		if (ret == 0)
			return false;
		if (ret < 0) {
			tail->next = nexthop;
			nexthop->prev = tail;
			return true;
		}
	}

	return _nexthop_add_no_dup(&nhg->nexthop, nexthop);
}

/* Delete nexthop from a nexthop list.  */
void _nexthop_del(struct nexthop_group *nhg, struct nexthop *nh)
{
	struct nexthop *nexthop;

	for (nexthop = nhg->nexthop; nexthop; nexthop = nexthop->next) {
		if (nexthop_same(nh, nexthop))
			break;
	}

	assert(nexthop);

	if (nexthop->prev)
		nexthop->prev->next = nexthop->next;
	else
		nhg->nexthop = nexthop->next;

	if (nexthop->next)
		nexthop->next->prev = nexthop->prev;

	nh->prev = NULL;
	nh->next = NULL;
}

/* Unlink a nexthop from the list it's on, unconditionally */
static void nexthop_unlink(struct nexthop_group *nhg, struct nexthop *nexthop)
{

	if (nexthop->prev)
		nexthop->prev->next = nexthop->next;
	else {
		assert(nhg->nexthop == nexthop);
		assert(nexthop->prev == NULL);
		nhg->nexthop = nexthop->next;
	}

	if (nexthop->next)
		nexthop->next->prev = nexthop->prev;

	nexthop->prev = NULL;
	nexthop->next = NULL;
}

/*
 * Copy a list of nexthops in 'nh' to an nhg, enforcing canonical sort order
 */
void nexthop_group_copy_nh_sorted(struct nexthop_group *nhg,
				  const struct nexthop *nh)
{
	struct nexthop *nexthop, *tail;
	const struct nexthop *nh1;

	/* We'll try to append to the end of the new list;
	 * if the original list in nh is already sorted, this eliminates
	 * lots of comparison operations.
	 */
	tail = nexthop_group_tail(nhg);

	for (nh1 = nh; nh1; nh1 = nh1->next) {
		nexthop = nexthop_dup(nh1, NULL);

		if (tail && (nexthop_cmp(tail, nexthop) < 0)) {
			tail->next = nexthop;
			nexthop->prev = tail;

			tail = nexthop;
			continue;
		}

		_nexthop_add_sorted(&nhg->nexthop, nexthop);

		if (tail == NULL)
			tail = nexthop;
	}
}

/* Copy a list of nexthops, no effort made to sort or order them. */
void copy_nexthops(struct nexthop **tnh, const struct nexthop *nh,
		   struct nexthop *rparent)
{
	struct nexthop *nexthop;
	const struct nexthop *nh1;

	for (nh1 = nh; nh1; nh1 = nh1->next) {
		nexthop = nexthop_dup(nh1, rparent);
		_nexthop_add(tnh, nexthop);
	}
}

/* Copy a list of nexthops, filtered the part of context. */
void copy_nexthops_nocontext(struct nexthop **tnh, const struct nexthop *nh, struct nexthop *rparent)
{
	struct nexthop *nexthop;
	const struct nexthop *nh1;

	for (nh1 = nh; nh1; nh1 = nh1->next) {
		nexthop = nexthop_dup_no_context(nh1, rparent);
		_nexthop_add(tnh, nexthop);
	}
}

uint32_t nexthop_group_hash_no_recurse(const struct nexthop_group *nhg)
{
	struct nexthop *nh;
	uint32_t key = 0;

	/*
	 * We are not interested in hashing over any recursively
	 * resolved nexthops
	 */
	for (nh = nhg->nexthop; nh; nh = nh->next)
		key = jhash_1word(nexthop_hash(nh), key);

	return key;
}

uint32_t nexthop_group_hash(const struct nexthop_group *nhg)
{
	struct nexthop *nh;
	uint32_t key = 0;

	for (ALL_NEXTHOPS_PTR(nhg, nh))
		key = jhash_1word(nexthop_hash(nh), key);

	return key;
}

void nexthop_group_mark_duplicates(struct nexthop_group *nhg)
{
	struct nexthop *nexthop, *prev;

	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE);
		for (ALL_NEXTHOPS_PTR(nhg, prev)) {
			if (prev == nexthop)
				break;
			if (nexthop_same(nexthop, prev)) {
				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_DUPLICATE);
				break;
			}
		}
	}
}

static void nhgc_delete_nexthops(struct nexthop_group_cmd *nhgc)
{
	struct nexthop *nexthop;

	nexthop = nhgc->nhg.nexthop;
	while (nexthop) {
		struct nexthop *next = nexthop_next(nexthop);

		_nexthop_del(&nhgc->nhg, nexthop);
		if (nhg_hooks.del_nexthop)
			nhg_hooks.del_nexthop(nhgc, nexthop);

		nexthop_free(nexthop);

		nexthop = next;
	}
}

struct nexthop_group_cmd *nhgc_find(const char *name)
{
	struct nexthop_group_cmd find;

	strlcpy(find.name, name, sizeof(find.name));

	return RB_FIND(nhgc_entry_head, &nhgc_entries, &find);
}

static int nhgc_cmp_helper(const char *a, const char *b)
{
	if (!a && !b)
		return 0;

	if (a && !b)
		return -1;

	if (!a && b)
		return 1;

	return strcmp(a, b);
}

static int nhgc_addr_cmp_helper(const union sockunion *a, const union sockunion *b)
{
	if (!a && !b)
		return 0;

	if (a && !b)
		return -1;

	if (!a && b)
		return 1;

	return sockunion_cmp(a, b);
}

static int nhgl_cmp(struct nexthop_hold *nh1, struct nexthop_hold *nh2)
{
	int ret;

	ret = nhgc_addr_cmp_helper(nh1->addr, nh2->addr);
	if (ret)
		return ret;

	ret = nhgc_cmp_helper(nh1->intf, nh2->intf);
	if (ret)
		return ret;

	ret = nhgc_cmp_helper(nh1->nhvrf_name, nh2->nhvrf_name);
	if (ret)
		return ret;

	ret = ((int)nh2->onlink) - ((int)nh1->onlink);
	if (ret)
		return ret;

	return nhgc_cmp_helper(nh1->labels, nh2->labels);
}

static void nhgl_delete(struct nexthop_hold *nh)
{
	XFREE(MTYPE_TMP, nh->intf);

	XFREE(MTYPE_TMP, nh->nhvrf_name);

	if (nh->addr)
		sockunion_free(nh->addr);

	XFREE(MTYPE_TMP, nh->labels);

	XFREE(MTYPE_TMP, nh);
}

static struct nexthop_group_cmd *nhgc_get(const char *name)
{
	struct nexthop_group_cmd *nhgc;

	nhgc = nhgc_find(name);
	if (!nhgc) {
		nhgc = XCALLOC(MTYPE_TMP, sizeof(*nhgc));
		strlcpy(nhgc->name, name, sizeof(nhgc->name));

		QOBJ_REG(nhgc, nexthop_group_cmd);
		RB_INSERT(nhgc_entry_head, &nhgc_entries, nhgc);

		nhgc->nhg_list = list_new();
		nhgc->nhg_list->cmp = (int (*)(void *, void *))nhgl_cmp;
		nhgc->nhg_list->del = (void (*)(void *))nhgl_delete;

		if (nhg_hooks.new)
			nhg_hooks.new(name);
	}

	return nhgc;
}

static void nhgc_delete(struct nexthop_group_cmd *nhgc)
{
	nhgc_delete_nexthops(nhgc);

	if (nhg_hooks.delete)
		nhg_hooks.delete(nhgc->name);

	RB_REMOVE(nhgc_entry_head, &nhgc_entries, nhgc);

	list_delete(&nhgc->nhg_list);

	QOBJ_UNREG(nhgc);
	XFREE(MTYPE_TMP, nhgc);
}

DEFINE_QOBJ_TYPE(nexthop_group_cmd);

DEFUN_NOSH(nexthop_group, nexthop_group_cmd, "nexthop-group NHGNAME",
	   "Enter into the nexthop-group submode\n"
	   "Specify the NAME of the nexthop-group\n")
{
	const char *nhg_name = argv[1]->arg;
	struct nexthop_group_cmd *nhgc = NULL;

	nhgc = nhgc_get(nhg_name);
	VTY_PUSH_CONTEXT(NH_GROUP_NODE, nhgc);

	return CMD_SUCCESS;
}

DEFUN_NOSH(no_nexthop_group, no_nexthop_group_cmd, "no nexthop-group NHGNAME",
	   NO_STR
	   "Delete the nexthop-group\n"
	   "Specify the NAME of the nexthop-group\n")
{
	const char *nhg_name = argv[2]->arg;
	struct nexthop_group_cmd *nhgc = NULL;

	nhgc = nhgc_find(nhg_name);
	if (nhgc)
		nhgc_delete(nhgc);

	return CMD_SUCCESS;
}

DEFPY(nexthop_group_backup, nexthop_group_backup_cmd,
      "backup-group WORD$name",
      "Specify a group name containing backup nexthops\n"
      "The name of the backup group\n")
{
	VTY_DECLVAR_CONTEXT(nexthop_group_cmd, nhgc);

	strlcpy(nhgc->backup_list_name, name, sizeof(nhgc->backup_list_name));

	return CMD_SUCCESS;
}

DEFPY(no_nexthop_group_backup, no_nexthop_group_backup_cmd,
      "no backup-group [WORD$name]",
      NO_STR
      "Clear group name containing backup nexthops\n"
      "The name of the backup group\n")
{
	VTY_DECLVAR_CONTEXT(nexthop_group_cmd, nhgc);

	nhgc->backup_list_name[0] = 0;

	return CMD_SUCCESS;
}

DEFPY(nexthop_group_resilience,
      nexthop_group_resilience_cmd,
      "resilient buckets (1-256) idle-timer (1-4294967295) unbalanced-timer (1-4294967295)",
      "A resilient Nexthop Group\n"
      "Buckets in the Hash for this Group\n"
      "Number of buckets\n"
      "The Idle timer for this Resilient Nexthop Group in seconds\n"
      "Number of seconds of Idle time\n"
      "The length of time that the Nexthop Group can be unbalanced\n"
      "Number of seconds of Unbalanced time\n")
{
	VTY_DECLVAR_CONTEXT(nexthop_group_cmd, nhgc);

	nhgc->nhg.nhgr.buckets = buckets;
	nhgc->nhg.nhgr.idle_timer = idle_timer;
	nhgc->nhg.nhgr.unbalanced_timer = unbalanced_timer;

	if (nhg_hooks.modify)
		nhg_hooks.modify(nhgc);

	return CMD_SUCCESS;
}

DEFPY(no_nexthop_group_resilience,
      no_nexthop_group_resilience_cmd,
      "no resilient [buckets (1-256) idle-timer (1-4294967295) unbalanced-timer (1-4294967295)]",
      NO_STR
      "A resilient Nexthop Group\n"
      "Buckets in the Hash for this Group\n"
      "Number of buckets\n"
      "The Idle timer for this Resilient Nexthop Group in seconds\n"
      "Number of seconds of Idle time\n"
      "The length of time that the Nexthop Group can be unbalanced\n"
      "Number of seconds of Unbalanced time\n")
{
	VTY_DECLVAR_CONTEXT(nexthop_group_cmd, nhgc);

	nhgc->nhg.nhgr.buckets = 0;
	nhgc->nhg.nhgr.idle_timer = 0;
	nhgc->nhg.nhgr.unbalanced_timer = 0;

	return CMD_SUCCESS;
}

static void nexthop_group_save_nhop(struct nexthop_group_cmd *nhgc,
				    const char *nhvrf_name,
				    const union sockunion *addr,
				    const char *intf, bool onlink,
				    const char *labels, const uint32_t weight,
				    const char *backup_str)
{
	struct nexthop_hold *nh;

	nh = XCALLOC(MTYPE_TMP, sizeof(*nh));

	if (nhvrf_name)
		nh->nhvrf_name = XSTRDUP(MTYPE_TMP, nhvrf_name);
	if (intf)
		nh->intf = XSTRDUP(MTYPE_TMP, intf);
	if (addr)
		nh->addr = sockunion_dup(addr);
	if (labels)
		nh->labels = XSTRDUP(MTYPE_TMP, labels);

	nh->onlink = onlink;

	nh->weight = weight;

	if (backup_str)
		nh->backup_str = XSTRDUP(MTYPE_TMP, backup_str);

	listnode_add_sort(nhgc->nhg_list, nh);
}

/*
 * Remove config info about a nexthop from group 'nhgc'. Note that we
 * use only a subset of the available attributes here to determine
 * a 'match'.
 * Note that this doesn't change the list of nexthops, only the config
 * information.
 */
static void nexthop_group_unsave_nhop(struct nexthop_group_cmd *nhgc,
				      const char *nhvrf_name,
				      const union sockunion *addr,
				      const char *intf)
{
	struct nexthop_hold *nh;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nh)) {
		if (nhgc_cmp_helper(nhvrf_name, nh->nhvrf_name) == 0
		    && nhgc_addr_cmp_helper(addr, nh->addr) == 0
		    && nhgc_cmp_helper(intf, nh->intf) == 0)
			break;
	}

	/*
	 * Something has gone seriously wrong, fail gracefully
	 */
	if (!nh)
		return;

	list_delete_node(nhgc->nhg_list, node);
	nhgl_delete(nh);
}

/*
 * Parse the config strings we support for a single nexthop. This gets used
 * in a couple of different ways, and we distinguish between transient
 * failures - such as a still-unprocessed interface - and fatal errors
 * from label-string parsing.
 */
static bool nexthop_group_parse_nexthop(struct nexthop *nhop,
					const union sockunion *addr,
					const char *intf, bool onlink,
					const char *name, const char *labels,
					vni_t vni, int *lbl_ret,
					uint32_t weight, const char *backup_str)
{
	int ret = 0;
	struct vrf *vrf;
	int num;
	uint8_t labelnum = 0;

	memset(nhop, 0, sizeof(*nhop));

	if (name)
		vrf = vrf_lookup_by_name(name);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (!vrf)
		return false;

	nhop->vrf_id = vrf->vrf_id;

	if (intf) {
		nhop->ifindex = ifname2ifindex(intf, vrf->vrf_id);
		if (nhop->ifindex == IFINDEX_INTERNAL)
			return false;
	}

	if (onlink)
		SET_FLAG(nhop->flags, NEXTHOP_FLAG_ONLINK);

	if (addr) {
		if (addr->sa.sa_family == AF_INET) {
			nhop->gate.ipv4.s_addr = addr->sin.sin_addr.s_addr;
			if (intf)
				nhop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			else
				nhop->type = NEXTHOP_TYPE_IPV4;
		} else {
			nhop->gate.ipv6 = addr->sin6.sin6_addr;
			if (intf)
				nhop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			else
				nhop->type = NEXTHOP_TYPE_IPV6;
		}
	} else
		nhop->type = NEXTHOP_TYPE_IFINDEX;

	if (labels) {
		mpls_label_t larray[MPLS_MAX_LABELS];

		ret = mpls_str2label(labels, &labelnum, larray);

		/* Return label parse result */
		if (lbl_ret)
			*lbl_ret = ret;

		if (ret < 0)
			return false;
		else if (labelnum > 0)
			nexthop_add_labels(nhop, ZEBRA_LSP_NONE, labelnum,
					   larray);
	} else if (vni) {
		mpls_label_t label = MPLS_INVALID_LABEL;

		vni2label(vni, &label);
		nexthop_add_labels(nhop, ZEBRA_LSP_EVPN, 1, &label);
	}

	nhop->weight = weight;

	if (backup_str) {
		/* Parse backup indexes */
		ret = nexthop_str2backups(backup_str,
					  &num, nhop->backup_idx);
		if (ret == 0) {
			SET_FLAG(nhop->flags, NEXTHOP_FLAG_HAS_BACKUP);
			nhop->backup_num = num;
		} else
			return false;
	}

	return true;
}

/*
 * Wrapper to parse the strings in a 'nexthop_hold'
 */
static bool nexthop_group_parse_nhh(struct nexthop *nhop,
				    const struct nexthop_hold *nhh)
{
	return (nexthop_group_parse_nexthop(
		nhop, nhh->addr, nhh->intf, nhh->onlink, nhh->nhvrf_name,
		nhh->labels, nhh->vni, NULL, nhh->weight, nhh->backup_str));
}

DEFPY(ecmp_nexthops, ecmp_nexthops_cmd,
      "[no] nexthop\
        <\
	  <A.B.C.D|X:X::X:X>$addr [INTERFACE$intf [onlink$onlink]]\
	  |INTERFACE$intf\
	>\
	[{ \
	   nexthop-vrf NAME$vrf_name \
	   |label WORD \
	   |vni (1-16777215) \
           |weight (1-255) \
           |backup-idx WORD \
	}]",
      NO_STR
      "Specify one of the nexthops in this ECMP group\n"
      "v4 Address\n"
      "v6 Address\n"
      "Interface to use\n"
      "Treat nexthop as directly attached to the interface\n"
      "Interface to use\n"
      "If the nexthop is in a different vrf tell us\n"
      "The nexthop-vrf Name\n"
      "Specify label(s) for this nexthop\n"
      "One or more labels in the range (16-1048575) separated by '/'\n"
      "Specify VNI(s) for this nexthop\n"
      "VNI in the range (1-16777215)\n"
      "Weight to be used by the nexthop for purposes of ECMP\n"
      "Weight value to be used\n"
      "Specify backup nexthop indexes in another group\n"
      "One or more indexes in the range (0-254) separated by ','\n")
{
	VTY_DECLVAR_CONTEXT(nexthop_group_cmd, nhgc);
	struct nexthop nhop;
	struct nexthop *nh;
	int lbl_ret = 0;
	bool legal;
	int num;
	uint8_t backups[NEXTHOP_MAX_BACKUPS];
	bool yes = !no;

	/* Pre-parse backup string to validate */
	if (backup_idx) {
		lbl_ret = nexthop_str2backups(backup_idx, &num, backups);
		if (lbl_ret < 0) {
			vty_out(vty, "%% Invalid backups\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	legal = nexthop_group_parse_nexthop(&nhop, addr, intf, !!onlink,
					    vrf_name, label, vni, &lbl_ret,
					    weight, backup_idx);

	if (nhop.type == NEXTHOP_TYPE_IPV6
	    && IN6_IS_ADDR_LINKLOCAL(&nhop.gate.ipv6)) {
		vty_out(vty,
			"Specified a v6 LL with no interface, rejecting\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Handle label-string errors */
	if (!legal && lbl_ret < 0) {
		switch (lbl_ret) {
		case -1:
			vty_out(vty, "%% Malformed label(s)\n");
			break;
		case -2:
			vty_out(vty,
				"%% Cannot use reserved label(s) (%d-%d)\n",
				MPLS_LABEL_RESERVED_MIN,
				MPLS_LABEL_RESERVED_MAX);
			break;
		case -3:
			vty_out(vty,
				"%% Too many labels. Enter %d or fewer\n",
				MPLS_MAX_LABELS);
			break;
		}
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Look for an existing nexthop in the config. Note that the test
	 * here tests only some attributes - it's not a complete comparison.
	 * Note that we've got two kinds of objects to manage: 'nexthop_hold'
	 * that represent config that may or may not be valid (yet), and
	 * actual nexthops that have been validated and parsed.
	 */
	nh = nhg_nh_find(&nhgc->nhg, &nhop);

	/* Always attempt to remove old config info. */
	nexthop_group_unsave_nhop(nhgc, vrf_name, addr, intf);

	/* Remove any existing nexthop, for delete and replace cases. */
	if (nh) {
		nexthop_unlink(&nhgc->nhg, nh);

		if (nhg_hooks.del_nexthop)
			nhg_hooks.del_nexthop(nhgc, nh);

		nexthop_free(nh);
	}
	if (yes) {
		/* Add/replace case: capture nexthop if valid, and capture
		 * config info always.
		 */
		if (legal) {
			nh = nexthop_new();

			memcpy(nh, &nhop, sizeof(nhop));
			_nexthop_add(&nhgc->nhg.nexthop, nh);
		}

		/* Save config always */
		nexthop_group_save_nhop(nhgc, vrf_name, addr, intf, !!onlink,
					label, weight, backup_idx);

		if (legal && nhg_hooks.add_nexthop)
			nhg_hooks.add_nexthop(nhgc, nh);
	}

	return CMD_SUCCESS;
}

static int nexthop_group_write(struct vty *vty);
static struct cmd_node nexthop_group_node = {
	.name = "nexthop-group",
	.node = NH_GROUP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-nh-group)# ",
	.config_write = nexthop_group_write,
};

void nexthop_group_write_nexthop_simple(struct vty *vty,
					const struct nexthop *nh,
					char *altifname)
{
	char *ifname;

	vty_out(vty, "nexthop ");

	if (altifname)
		ifname = altifname;
	else
		ifname = (char *)ifindex2ifname(nh->ifindex, nh->vrf_id);

	switch (nh->type) {
	case NEXTHOP_TYPE_IFINDEX:
		vty_out(vty, "%s", ifname);
		break;
	case NEXTHOP_TYPE_IPV4:
		vty_out(vty, "%pI4", &nh->gate.ipv4);
		break;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, "%pI4 %s", &nh->gate.ipv4, ifname);
		break;
	case NEXTHOP_TYPE_IPV6:
		vty_out(vty, "%pI6", &nh->gate.ipv6);
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		vty_out(vty, "%pI6 %s", &nh->gate.ipv6, ifname);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		vty_out(vty, "%s", "drop");
		break;
	}
}

void nexthop_group_write_nexthop(struct vty *vty, const struct nexthop *nh)
{
	struct vrf *vrf;
	int i;

	nexthop_group_write_nexthop_simple(vty, nh, NULL);

	if (nh->vrf_id != VRF_DEFAULT) {
		vrf = vrf_lookup_by_id(nh->vrf_id);
		vty_out(vty, " nexthop-vrf %s", VRF_LOGNAME(vrf));
	}

	if (nh->nh_label && nh->nh_label->num_labels > 0) {
		char buf[200];

		mpls_label2str(nh->nh_label->num_labels, nh->nh_label->label,
			       buf, sizeof(buf), nh->nh_label_type, 0);
		vty_out(vty, " label %s", buf);
	}

	if (nh->weight)
		vty_out(vty, " weight %u", nh->weight);

	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
		vty_out(vty, " backup-idx %d", nh->backup_idx[0]);

		for (i = 1; i < nh->backup_num; i++)
			vty_out(vty, ",%d", nh->backup_idx[i]);
	}

	vty_out(vty, "\n");
}

void nexthop_group_json_nexthop(json_object *j, const struct nexthop *nh)
{
	struct vrf *vrf;
	json_object *json_backups = NULL;
	int i;

	switch (nh->type) {
	case NEXTHOP_TYPE_IFINDEX:
		json_object_string_add(j, "nexthop",
				       ifindex2ifname(nh->ifindex, nh->vrf_id));
		break;
	case NEXTHOP_TYPE_IPV4:
		json_object_string_addf(j, "nexthop", "%pI4", &nh->gate.ipv4);
		break;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		json_object_string_addf(j, "nexthop", "%pI4", &nh->gate.ipv4);
		json_object_string_add(j, "vrfId",
				       ifindex2ifname(nh->ifindex, nh->vrf_id));
		break;
	case NEXTHOP_TYPE_IPV6:
		json_object_string_addf(j, "nexthop", "%pI6", &nh->gate.ipv6);
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		json_object_string_addf(j, "nexthop", "%pI6", &nh->gate.ipv6);
		json_object_string_add(j, "vrfId",
				       ifindex2ifname(nh->ifindex, nh->vrf_id));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}

	if (nh->vrf_id != VRF_DEFAULT) {
		vrf = vrf_lookup_by_id(nh->vrf_id);
		json_object_string_add(j, "targetVrf", vrf->name);
	}

	if (nh->nh_label && nh->nh_label->num_labels > 0) {
		char buf[200];

		mpls_label2str(nh->nh_label->num_labels, nh->nh_label->label,
			       buf, sizeof(buf), nh->nh_label_type, 0);
		json_object_string_add(j, "label", buf);
	}

	if (nh->weight)
		json_object_int_add(j, "weight", nh->weight);

	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
		json_backups = json_object_new_array();
		for (i = 0; i < nh->backup_num; i++)
			json_object_array_add(
				json_backups,
				json_object_new_int(nh->backup_idx[i]));

		json_object_object_add(j, "backupIdx", json_backups);
	}
}

static void nexthop_group_write_nexthop_internal(struct vty *vty,
						 const struct nexthop_hold *nh)
{
	vty_out(vty, "nexthop");

	if (nh->addr)
		vty_out(vty, " %pSU", nh->addr);

	if (nh->intf)
		vty_out(vty, " %s", nh->intf);

	if (nh->onlink)
		vty_out(vty, " onlink");

	if (nh->nhvrf_name)
		vty_out(vty, " nexthop-vrf %s", nh->nhvrf_name);

	if (nh->labels)
		vty_out(vty, " label %s", nh->labels);

	if (nh->vni)
		vty_out(vty, " vni %u", nh->vni);

	if (nh->weight)
		vty_out(vty, " weight %u", nh->weight);

	if (nh->backup_str)
		vty_out(vty, " backup-idx %s", nh->backup_str);

	vty_out(vty, "\n");
}

static int nexthop_group_write(struct vty *vty)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop_hold *nh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		struct listnode *node;

		vty_out(vty, "nexthop-group %s\n", nhgc->name);

		if (nhgc->nhg.nhgr.buckets)
			vty_out(vty,
				" resilient buckets %u idle-timer %u unbalanced-timer %u\n",
				nhgc->nhg.nhgr.buckets,
				nhgc->nhg.nhgr.idle_timer,
				nhgc->nhg.nhgr.unbalanced_timer);

		if (nhgc->backup_list_name[0])
			vty_out(vty, " backup-group %s\n",
				nhgc->backup_list_name);

		for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nh)) {
			vty_out(vty, " ");
			nexthop_group_write_nexthop_internal(vty, nh);
		}

		vty_out(vty, "exit\n");
		vty_out(vty, "!\n");
	}

	return 1;
}

void nexthop_group_enable_vrf(struct vrf *vrf)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop_hold *nhh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nhh)) {
			struct nexthop nhop;
			struct nexthop *nh;

			if (!nexthop_group_parse_nhh(&nhop, nhh))
				continue;

			nh = nexthop_exists(&nhgc->nhg, &nhop);

			if (nh)
				continue;

			if (nhop.vrf_id != vrf->vrf_id)
				continue;

			nh = nexthop_new();

			memcpy(nh, &nhop, sizeof(nhop));
			_nexthop_add(&nhgc->nhg.nexthop, nh);

			if (nhg_hooks.add_nexthop)
				nhg_hooks.add_nexthop(nhgc, nh);
		}
	}
}

void nexthop_group_disable_vrf(struct vrf *vrf)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop_hold *nhh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		struct listnode *node, *nnode;

		for (ALL_LIST_ELEMENTS(nhgc->nhg_list, node, nnode, nhh)) {
			struct nexthop nhop;
			struct nexthop *nh;

			if (!nexthop_group_parse_nhh(&nhop, nhh))
				continue;

			nh = nexthop_exists(&nhgc->nhg, &nhop);

			if (!nh)
				continue;

			if (nh->vrf_id != vrf->vrf_id)
				continue;

			_nexthop_del(&nhgc->nhg, nh);

			if (nhg_hooks.del_nexthop)
				nhg_hooks.del_nexthop(nhgc, nh);

			nexthop_free(nh);

			list_delete_node(nhgc->nhg_list, node);

			nhgl_delete(nhh);
		}
	}
}

void nexthop_group_interface_state_change(struct interface *ifp,
					  ifindex_t oldifindex)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop_hold *nhh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		struct listnode *node;
		struct nexthop *nh;

		if (if_is_up(ifp)) {
			for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nhh)) {
				struct nexthop nhop;

				if (!nexthop_group_parse_nhh(&nhop, nhh))
					continue;

				switch (nhop.type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_BLACKHOLE:
					continue;
				case NEXTHOP_TYPE_IFINDEX:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					break;
				}
				nh = nexthop_exists(&nhgc->nhg, &nhop);

				if (nh)
					continue;

				if (ifp->ifindex != nhop.ifindex)
					continue;

				nh = nexthop_new();

				memcpy(nh, &nhop, sizeof(nhop));
				_nexthop_add(&nhgc->nhg.nexthop, nh);

				if (nhg_hooks.add_nexthop)
					nhg_hooks.add_nexthop(nhgc, nh);
			}
		} else {
			struct nexthop *next_nh;

			for (nh = nhgc->nhg.nexthop; nh; nh = next_nh) {
				next_nh = nh->next;
				switch (nh->type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_BLACKHOLE:
					continue;
				case NEXTHOP_TYPE_IFINDEX:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					break;
				}

				if (oldifindex != nh->ifindex)
					continue;

				_nexthop_del(&nhgc->nhg, nh);

				if (nhg_hooks.del_nexthop)
					nhg_hooks.del_nexthop(nhgc, nh);

				nexthop_free(nh);
			}
		}
	}
}

static void nhg_name_autocomplete(vector comps, struct cmd_token *token)
{
	struct nexthop_group_cmd *nhgc;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, nhgc->name));
	}
}

static const struct cmd_variable_handler nhg_name_handlers[] = {
	{.tokenname = "NHGNAME", .completions = nhg_name_autocomplete},
	{.completions = NULL}};

void nexthop_group_init(void (*new)(const char *name),
			void (*modify)(const struct nexthop_group_cmd *nhgc),
			void (*add_nexthop)(const struct nexthop_group_cmd *nhg,
					    const struct nexthop *nhop),
			void (*del_nexthop)(const struct nexthop_group_cmd *nhg,
					    const struct nexthop *nhop),
			void (*delete)(const char *name))
{
	RB_INIT(nhgc_entry_head, &nhgc_entries);

	cmd_variable_handler_register(nhg_name_handlers);

	install_node(&nexthop_group_node);
	install_element(CONFIG_NODE, &nexthop_group_cmd);
	install_element(CONFIG_NODE, &no_nexthop_group_cmd);

	install_default(NH_GROUP_NODE);
	install_element(NH_GROUP_NODE, &nexthop_group_backup_cmd);
	install_element(NH_GROUP_NODE, &no_nexthop_group_backup_cmd);
	install_element(NH_GROUP_NODE, &ecmp_nexthops_cmd);

	install_element(NH_GROUP_NODE, &nexthop_group_resilience_cmd);
	install_element(NH_GROUP_NODE, &no_nexthop_group_resilience_cmd);

	memset(&nhg_hooks, 0, sizeof(nhg_hooks));

	if (new)
		nhg_hooks.new = new;
	if (modify)
		nhg_hooks.modify = modify;
	if (add_nexthop)
		nhg_hooks.add_nexthop = add_nexthop;
	if (del_nexthop)
		nhg_hooks.del_nexthop = del_nexthop;
	if (delete)
		nhg_hooks.delete = delete;
}
