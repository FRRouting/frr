/*
 * Nexthop Group structure definition.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <nexthop.h>
#include <nexthop_group.h>
#include <vty.h>
#include <command.h>

#ifndef VTYSH_EXTRACT_PL
#include "lib/nexthop_group_clippy.c"
#endif

/* Add nexthop to the end of a nexthop list.  */
void nexthop_add(struct nexthop **target, struct nexthop *nexthop)
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

void copy_nexthops(struct nexthop **tnh, struct nexthop *nh,
		   struct nexthop *rparent)
{
	struct nexthop *nexthop;
	struct nexthop *nh1;

	for (nh1 = nh; nh1; nh1 = nh1->next) {
		nexthop = nexthop_new();
		nexthop->vrf_id = nh1->vrf_id;
		nexthop->ifindex = nh1->ifindex;
		nexthop->type = nh1->type;
		nexthop->flags = nh1->flags;
		memcpy(&nexthop->gate, &nh1->gate, sizeof(nh1->gate));
		memcpy(&nexthop->src, &nh1->src, sizeof(nh1->src));
		memcpy(&nexthop->rmap_src, &nh1->rmap_src,
		       sizeof(nh1->rmap_src));
		nexthop->rparent = rparent;
		if (nh1->nh_label)
			nexthop_add_labels(nexthop, nh1->nh_label_type,
					   nh1->nh_label->num_labels,
					   &nh1->nh_label->label[0]);
		nexthop_add(tnh, nexthop);

		if (CHECK_FLAG(nh1->flags, NEXTHOP_FLAG_RECURSIVE))
			copy_nexthops(&nexthop->resolved, nh1->resolved,
				      nexthop);
	}
}

DEFPY (nexthop_group,
       nexthop_group_cmd,
       "nexthop-group NAME",
       "Enter into the nexthop-group submode\n"
       "Specify the NAME of the nexthop-group\n")
{
	return CMD_SUCCESS;
}

struct cmd_node nexthop_group_node = {
	NH_GROUP_NODE,
	"%s(config-nh-group)# ",
	1
};

static int nexthop_group_write(struct vty *vty)
{
	vty_out(vty, "!\n");

	return 1;
}

void nexthop_group_init(void)
{
	install_node(&nexthop_group_node, nexthop_group_write);
	install_element(CONFIG_NODE, &nexthop_group_cmd);
}
