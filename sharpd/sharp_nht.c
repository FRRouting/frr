/*
 * SHARP - code to track nexthops
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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

DEFINE_MTYPE_STATIC(SHARPD, NH_TRACKER, "Nexthop Tracker")
DEFINE_MTYPE_STATIC(SHARPD, NHG, "Nexthop Group")

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

void sharp_nh_tracker_dump(struct vty *vty)
{
	struct listnode *node;
	struct sharp_nh_tracker *nht;

	for (ALL_LIST_ELEMENTS_RO(sg.nhs, node, nht)) {
		char buf[PREFIX_STRLEN];

		vty_out(vty, "%s: Nexthops: %u Updates: %u\n",
			prefix2str(&nht->p, buf, sizeof(buf)),
			nht->nhop_num,
			nht->updates);
	}
}

PREDECL_RBTREE_UNIQ(sharp_nhg_rb);

struct sharp_nhg {
	struct sharp_nhg_rb_item mylistitem;

	uint32_t id;

	char name[256];

	bool installable;
};

static uint32_t nhg_id;

static uint32_t sharp_get_next_nhid(void)
{
	zlog_debug("Id assigned: %u", nhg_id);
	return nhg_id++;
}

struct sharp_nhg_rb_head nhg_head;

static int sharp_nhg_compare_func(const struct sharp_nhg *a,
				  const struct sharp_nhg *b)
{
	return strncmp(a->name, b->name, strlen(a->name));
}

DECLARE_RBTREE_UNIQ(sharp_nhg_rb, struct sharp_nhg, mylistitem,
		    sharp_nhg_compare_func);

static void sharp_nhgroup_add_cb(const char *name)
{
	struct sharp_nhg *snhg;

	snhg = XCALLOC(MTYPE_NHG, sizeof(*snhg));
	snhg->id = sharp_get_next_nhid();
	strncpy(snhg->name, name, sizeof(snhg->name));

	sharp_nhg_rb_add(&nhg_head, snhg);
	return;
}

static void sharp_nhgroup_add_nexthop_cb(const struct nexthop_group_cmd *nhgc,
					 const struct nexthop *nhop)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;

	strncpy(lookup.name, nhgc->name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);

	if (snhg->installable)
		nhg_add(snhg->id, &nhgc->nhg);

	return;
}

static void sharp_nhgroup_del_nexthop_cb(const struct nexthop_group_cmd *nhgc,
					 const struct nexthop *nhop)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;

	strncpy(lookup.name, nhgc->name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);

	if (snhg->installable)
		nhg_add(snhg->id, &nhgc->nhg);

	return;
}

static void sharp_nhgroup_delete_cb(const char *name)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;

	strncpy(lookup.name, name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
	if (!snhg)
		return;

	if (snhg->installable)
		nhg_del(snhg->id);

	sharp_nhg_rb_del(&nhg_head, snhg);
	XFREE(MTYPE_NHG, snhg);
	return;
}

static void sharp_nhgroup_installable_cb(const struct nexthop_group_cmd *nhgc)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;

	strncpy(lookup.name, nhgc->name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
	if (!snhg)
		return;

	snhg->installable = nhgc->installable;

	if (snhg->installable)
		nhg_add(snhg->id, &nhgc->nhg);
	else
		nhg_del(snhg->id);

	return;
}

uint32_t sharp_nhgroup_get_id(const char *name)
{
	struct sharp_nhg lookup;
	struct sharp_nhg *snhg;

	strncpy(lookup.name, name, sizeof(lookup.name));
	snhg = sharp_nhg_rb_find(&nhg_head, &lookup);
	if (!snhg)
		return 0;

	if (!snhg->installable)
		return 0;

	return snhg->id;
}

void sharp_nhgroup_init(void)
{
	sharp_nhg_rb_init(&nhg_head);
	nhg_id = zclient_get_nhg_start(ZEBRA_ROUTE_SHARP);

	nexthop_group_init(sharp_nhgroup_add_cb, sharp_nhgroup_add_nexthop_cb,
			   sharp_nhgroup_del_nexthop_cb,
			   sharp_nhgroup_delete_cb,
			   sharp_nhgroup_installable_cb);
}
