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

#include "sharp_nht.h"
#include "sharp_globals.h"

DEFINE_MTYPE_STATIC(SHARPD, NH_TRACKER, "Nexthop Tracker")

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
