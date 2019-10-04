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

#ifndef __NEXTHOP_GROUP__
#define __NEXTHOP_GROUP__

#include <vty.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * What is a nexthop group?
 *
 * A nexthop group is a collection of nexthops that make up
 * the ECMP path for the route.
 *
 * This module provides a proper abstraction to this idea.
 */
struct nexthop_group {
	struct nexthop *nexthop;
};

struct nexthop_group *nexthop_group_new(void);
void nexthop_group_delete(struct nexthop_group **nhg);

void nexthop_group_copy(struct nexthop_group *to,
			struct nexthop_group *from);
void copy_nexthops(struct nexthop **tnh, const struct nexthop *nh,
		   struct nexthop *rparent);

uint32_t nexthop_group_hash_no_recurse(const struct nexthop_group *nhg);
uint32_t nexthop_group_hash(const struct nexthop_group *nhg);
void nexthop_group_mark_duplicates(struct nexthop_group *nhg);

/* The following for loop allows to iterate over the nexthop
 * structure of routes.
 *
 * head:      The pointer to the first nexthop in the chain.
 *
 * nexthop:   The pointer to the current nexthop, either in the
 *            top-level chain or in a resolved chain.
 */
#define ALL_NEXTHOPS(head, nhop)					\
	(nhop) = (head.nexthop);					\
	(nhop);								\
	(nhop) = nexthop_next(nhop)

#define ALL_NEXTHOPS_PTR(head, nhop)					\
	(nhop) = ((head)->nexthop);					\
	(nhop);								\
	(nhop) = nexthop_next(nhop)


struct nexthop_hold {
	char *nhvrf_name;
	union sockunion *addr;
	char *intf;
};

struct nexthop_group_cmd {

	RB_ENTRY(nexthop_group_cmd) nhgc_entry;

	char name[80];

	struct nexthop_group nhg;

	struct list *nhg_list;

	QOBJ_FIELDS
};
RB_HEAD(nhgc_entry_head, nexthp_group_cmd);
RB_PROTOTYPE(nhgc_entry_head, nexthop_group_cmd, nhgc_entry,
	     nexthop_group_cmd_compare)
DECLARE_QOBJ_TYPE(nexthop_group_cmd)

/*
 * Initialize nexthop_groups.  If you are interested in when
 * a nexthop_group is added/deleted/modified, then set the
 * appropriate callback functions to handle it in your
 * code
 */
void nexthop_group_init(
	void (*create)(const char *name),
	void (*add_nexthop)(const struct nexthop_group_cmd *nhgc,
			    const struct nexthop *nhop),
	void (*del_nexthop)(const struct nexthop_group_cmd *nhgc,
			    const struct nexthop *nhop),
	void (*destroy)(const char *name));

void nexthop_group_enable_vrf(struct vrf *vrf);
void nexthop_group_disable_vrf(struct vrf *vrf);
void nexthop_group_interface_state_change(struct interface *ifp,
					  ifindex_t oldifindex);

extern struct nexthop *nexthop_exists(const struct nexthop_group *nhg,
				      const struct nexthop *nh);
/* This assumes ordered */
extern bool nexthop_group_equal_no_recurse(const struct nexthop_group *nhg1,
					   const struct nexthop_group *nhg2);

/* This assumes ordered */
extern bool nexthop_group_equal(const struct nexthop_group *nhg1,
				const struct nexthop_group *nhg2);

extern struct nexthop_group_cmd *nhgc_find(const char *name);

extern void nexthop_group_write_nexthop(struct vty *vty, struct nexthop *nh);

/* Return the number of nexthops in this nhg */
extern uint8_t nexthop_group_nexthop_num(const struct nexthop_group *nhg);
extern uint8_t
nexthop_group_nexthop_num_no_recurse(const struct nexthop_group *nhg);
extern uint8_t
nexthop_group_active_nexthop_num(const struct nexthop_group *nhg);
extern uint8_t
nexthop_group_active_nexthop_num_no_recurse(const struct nexthop_group *nhg);

#ifdef __cplusplus
}
#endif

#endif
