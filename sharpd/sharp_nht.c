// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SHARP - code to track nexthops
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include "memory.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "vty.h"
#include "typesafe.h"
#include "zclient.h"

#include "sharp_nht.h"
#include "sharp_globals.h"
#include "sharp_zebra.h"

DEFINE_MTYPE_STATIC(SHARPD, NH_TRACKER, "Nexthop Tracker");
DEFINE_MTYPE_STATIC(SHARPD, NHG, "Nexthop Group");

struct sharp_nh_tracker *sharp_nh_tracker_get(struct prefix *p)
{
	struct listnode *node;
	struct sharp_nh_tracker *nht;

	for (ALL_LIST_ELEMENTS_RO(sg.nhs, node, nht)) {
		if (prefix_same(&nht->p, p))
			break;
	}

	if (nht)
		return nht;

	nht = XCALLOC(MTYPE_NH_TRACKER, sizeof(*nht));
	prefix_copy(&nht->p, p);

	listnode_add(sg.nhs, nht);
	return nht;
}

void sharp_nh_tracker_free(struct sharp_nh_tracker *nht)
{
	XFREE(MTYPE_NH_TRACKER, nht);
}

void sharp_nh_tracker_dump(struct vty *vty)
{
	struct listnode *node;
	struct sharp_nh_tracker *nht;

	for (ALL_LIST_ELEMENTS_RO(sg.nhs, node, nht))
		vty_out(vty, "%pFX: Nexthops: %u Updates: %u\n", &nht->p,
			nht->nhop_num, nht->updates);
}

PREDECL_RBTREE_UNIQ(sharp_nhg_rb);

struct sharp_nhg {
	struct sharp_nhg_rb_item mylistitem;

	uint32_t id;

#define NHG_NAME_LEN 256
	char name[NHG_NAME_LEN];

	bool installed;
	bool to_be_removed;
};

static uint32_t nhg_id;

static uint32_t sharp_get_next_nhid(void)
{
	zlog_debug("NHG ID assigned: %u", nhg_id);
	return nhg_id++;
}

struct sharp_nhg_rb_head nhg_head;

static int sharp_nhg_compare_func(const struct sharp_nhg *a,
				  const struct sharp_nhg *b)
{
	return strncmp(a->name, b->name, NHG_NAME_LEN);
}

DECLARE_RBTREE_UNIQ(sharp_nhg_rb, struct sharp_nhg, mylistitem,
		    sharp_nhg_compare_func);

static struct sharp_nhg *sharp_nhgroup_find_id(uint32_t id)
{
	struct sharp_nhg *lookup;

	/* Yea its just a for loop, I don't want add complexity
	 * to sharpd with another RB tree for just IDs
	 */

	frr_each (sharp_nhg_rb, &nhg_head, lookup) {
		if (lookup->id == id)
			return lookup;
	}

	return NULL;
}

static void sharp_nhgroup_add_cb(const char *name)
{
	struct sharp_nhg *snhg;

	snhg = XCALLOC(MTYPE_NHG, sizeof(*snhg));
	snhg->id = sharp_get_next_nhid();
	strlcpy(snhg->name, name, sizeof(snhg->name));

	sharp_nhg_rb_add(&nhg_head, snhg);
}

static void sharp_nhgroup_modify_cb(const struct nexthop_group_cmd *nhgc)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;
	struct nexthop_group_cmd *bnhgc = NULL;

	strlcpy(lookup.name, nhgc->name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);

	if (!nhgc->nhg.nexthop)
		return;

	if (nhgc->backup_list_name[0])
		bnhgc = nhgc_find(nhgc->backup_list_name);

	nhg_add(snhg->id, nhgc, (bnhgc ? &bnhgc->nhg : NULL));
}

static void
sharp_nhgroup_child_add_nexthop_cb(const struct nexthop_group_cmd *nhgc)
{
	struct listnode *node;
	struct sharp_nhg lookup;
	char *child_group;
	struct sharp_nhg *snhg, *snhg_tmp;
	uint32_t id, nh_num = 0;

	if (!listcount(nhgc->nhg_child_group_list))
		return;

	strlcpy(lookup.name, nhgc->name, sizeof(nhgc->name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
	if (!snhg || !snhg->id)
		return;
	id = snhg->id;

	for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_child_group_list, node,
				  child_group)) {
		strlcpy(lookup.name, child_group, sizeof(lookup.name));
		snhg_tmp = sharp_nhg_rb_find(&nhg_head, &lookup);
		if (!snhg_tmp) {
			zlog_debug("%s() : nhg %s, child group %s not found",
				   __func__, nhgc->name, child_group);
			continue;
		}
		if (!snhg_tmp->id) {
			zlog_debug("%s() : nhg %s, child group %s has no valid id %p",
				   __func__, nhgc->name, child_group, snhg_tmp);
			continue;
		}
		if (!sharp_nhgroup_id_is_installed(snhg_tmp->id)) {
			zlog_debug("%s() : nhg %s, child group %s not installed (%u)",
				   __func__, nhgc->name, child_group,
				   snhg_tmp->id);
			continue;
		}

		if (sharp_nhgroup_id_needs_removal(snhg_tmp->id))
			continue;

		/* assumption a dependent next-hop has only 1 next-hop */
		nh_num++;
	}
	if (nh_num)
		nhg_add(id, nhgc, NULL);
}

static void
sharp_nhgroup_child_del_nexthop_cb(const struct nexthop_group_cmd *nhgc)
{
	struct listnode *node;
	struct sharp_nhg lookup;
	char *child_group;
	struct sharp_nhg *snhg;
	int nh_num = 0, id = 0;

	if (!listcount(nhgc->nhg_child_group_list))
		return;

	for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_child_group_list, node,
				  child_group)) {
		strlcpy(lookup.name, child_group, sizeof(lookup.name));
		snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
		if (!snhg) {
			zlog_debug("%s() : nhg %s, child group %s not found",
				   __func__, nhgc->name, child_group);
			continue;
		}
		if (!snhg->id) {
			zlog_debug("%s() : nhg %s, child group %s has no valid id %p",
				   __func__, nhgc->name, child_group, snhg);
			continue;
		}

		if (sharp_nhgroup_id_needs_removal(snhg->id))
			continue;

		/* assumption a dependent next-hop has only 1 next-hop */
		nh_num++;
	}
	strlcpy(lookup.name, nhgc->name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
	if (snhg)
		id = snhg->id;
	if (nh_num) {
		zlog_debug("%s() : nhg %s, id %u needs update, now has %u groups",
			   __func__, nhgc->name, id, nh_num);
		nhg_add(snhg->id, nhgc, NULL);
	} else if (sharp_nhgroup_id_is_installed(snhg->id)) {
		zlog_debug("%s() : nhg %s, id %u needs delete, no valid nh_num",
			   __func__, nhgc->name, id);
		nhg_del(snhg->id);
	}
}

static void sharp_nhgroup_add_nexthop_cb(const struct nexthop_group_cmd *nhgc,
					 const struct nexthop *nhop)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;
	struct nexthop_group_cmd *bnhgc = NULL;

	strlcpy(lookup.name, nhgc->name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
	if (!snhg) {
		zlog_debug("%s() : nexthop %s not found", __func__, snhg->name);
		return;
	}
	if (!snhg->id) {
		zlog_debug("%s() : nexthop %s has no valid id %p", __func__,
			   snhg->name, snhg);
		return;
	}
	if (!listcount(nhgc->nhg_child_group_list)) {
		if (nhgc->backup_list_name[0])
			bnhgc = nhgc_find(nhgc->backup_list_name);
		nhg_add(snhg->id, nhgc, (bnhgc ? &bnhgc->nhg : NULL));
	}

	/* lookup dependent nexthops */
	if (nhop) {
		nexthop_group_child_group_match(nhgc->name,
						sharp_nhgroup_child_add_nexthop_cb);
		return;
	}
	sharp_nhgroup_child_add_nexthop_cb(nhgc);
}

static void sharp_nhgroup_del_nexthop_cb(const struct nexthop_group_cmd *nhgc,
					 const struct nexthop *nhop)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;
	struct nexthop_group_cmd *bnhgc = NULL;
	struct nexthop *nh = NULL;
	int nh_num = 0;

	if (!listcount(nhgc->nhg_child_group_list)) {
		strlcpy(lookup.name, nhgc->name, sizeof(lookup.name));
		snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
		if (nhgc->backup_list_name[0])
			bnhgc = nhgc_find(nhgc->backup_list_name);

		for (ALL_NEXTHOPS_PTR(&nhgc->nhg, nh)) {
			if (nh_num >= MULTIPATH_NUM) {
				zlog_warn("%s: number of nexthops greater than max multipath size, truncating",
					  __func__);
				break;
			}

			/* Unresolved nexthops will lead to failure - only send
			 * nexthops that zebra will consider valid.
			 */
			if (nh->ifindex == 0)
				continue;

			nh_num++;
		}
		if (nh_num == 0 && sharp_nhgroup_id_is_installed(snhg->id)) {
			/* before deleting, notify other users */
			snhg->to_be_removed = true;
			nexthop_group_child_group_match(nhgc->name,
							sharp_nhgroup_child_del_nexthop_cb);
			zlog_debug("%s: nhg %s, id %u: no nexthops, deleting nexthop group",
				   __func__, nhgc->name, snhg->id);
			nhg_del(snhg->id);
			snhg->to_be_removed = false;
			return;
		}

		nhg_add(snhg->id, nhgc, (bnhgc ? &bnhgc->nhg : NULL));
	}

	/* lookup dependent nexthops */
	if (nhop) {
		nexthop_group_child_group_match(nhgc->name,
						sharp_nhgroup_child_del_nexthop_cb);
		return;
	}
	sharp_nhgroup_child_del_nexthop_cb(nhgc);
}

static void sharp_nhgroup_delete_cb(const char *name)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;

	strlcpy(lookup.name, name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
	if (!snhg)
		return;

	if (sharp_nhgroup_id_is_installed(snhg->id))
		nhg_del(snhg->id);
	sharp_nhg_rb_del(&nhg_head, snhg);
	XFREE(MTYPE_NHG, snhg);
}

uint32_t sharp_nhgroup_get_id(const char *name)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;

	strlcpy(lookup.name, name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
	if (!snhg)
		return 0;

	return snhg->id;
}

void sharp_nhgroup_child_trigger_add_nexthop(uint32_t id)
{
	struct sharp_nhg *snhg;

	snhg = sharp_nhgroup_find_id(id);
	if (!snhg)
		return;
	/* lookup dependent nexthops */
	nexthop_group_child_group_match(snhg->name,
					sharp_nhgroup_child_add_nexthop_cb);
}

void sharp_nhgroup_id_set_installed(uint32_t id, bool installed)
{
	struct sharp_nhg *snhg;

	snhg = sharp_nhgroup_find_id(id);
	if (!snhg) {
		zlog_debug("%s: nhg %u not found", __func__, id);
		return;
	}

	snhg->installed = installed;
}

bool sharp_nhgroup_id_is_installed(uint32_t id)
{
	struct sharp_nhg *snhg;

	snhg = sharp_nhgroup_find_id(id);
	if (!snhg) {
		zlog_debug("%s: nhg %u not found", __func__, id);
		return false;
	}

	return snhg->installed;
}

bool sharp_nhgroup_id_needs_removal(uint32_t id)
{
	struct sharp_nhg *snhg;

	snhg = sharp_nhgroup_find_id(id);
	if (!snhg) {
		zlog_debug("%s: nhg %u not found", __func__, id);
		return false;
	}
	return snhg->to_be_removed;
}

void sharp_nhgroup_init(void)
{
	sharp_nhg_rb_init(&nhg_head);
	nhg_id = zclient_get_nhg_start(ZEBRA_ROUTE_SHARP);

	nexthop_group_init(sharp_nhgroup_add_cb, sharp_nhgroup_modify_cb,
			   sharp_nhgroup_add_nexthop_cb,
			   sharp_nhgroup_del_nexthop_cb,
			   sharp_nhgroup_delete_cb);
}
