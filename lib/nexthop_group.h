// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Nexthop Group structure definition.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 */

#ifndef __NEXTHOP_GROUP__
#define __NEXTHOP_GROUP__

#include <vty.h>
#include "json.h"

#ifdef __cplusplus
extern "C" {
#endif

struct nhg_resilience {
	uint16_t buckets;
	uint32_t idle_timer;
	uint32_t unbalanced_timer;
	uint64_t unbalanced_time;
};

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

	struct nhg_resilience nhgr;
};

struct nexthop_group *nexthop_group_new(void);
void nexthop_group_delete(struct nexthop_group **nhg);

void nexthop_group_copy(struct nexthop_group *to,
			const struct nexthop_group *from);

/*
 * Copy a list of nexthops in 'nh' to an nhg, enforcing canonical sort order
 */
void nexthop_group_copy_nh_sorted(struct nexthop_group *nhg,
				  const struct nexthop *nh);

void copy_nexthops(struct nexthop **tnh, const struct nexthop *nh,
		   struct nexthop *rparent);

void copy_nexthops_nocontext(struct nexthop **tnh, const struct nexthop *nh,
			     struct nexthop *rparent);
bool nexthop_group_add_sorted_nodup(struct nexthop_group *nhg, struct nexthop *nexthop);

uint32_t nexthop_group_hash_no_recurse(const struct nexthop_group *nhg);
uint32_t nexthop_group_hash(const struct nexthop_group *nhg);
void nexthop_group_mark_duplicates(struct nexthop_group *nhg);

/* Add a nexthop to a list, enforcing the canonical sort order. */
void nexthop_group_add_sorted(struct nexthop_group *nhg,
			      struct nexthop *nexthop);

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


#define NHGC_NAME_SIZE 80

struct nexthop_group_cmd {

	RB_ENTRY(nexthop_group_cmd) nhgc_entry;

	char name[NHGC_NAME_SIZE];

	/* Name of group containing backup nexthops (if set) */
	char backup_list_name[NHGC_NAME_SIZE];

	struct nexthop_group nhg;

	struct list *nhg_list;

	QOBJ_FIELDS;
};
RB_HEAD(nhgc_entry_head, nexthp_group_cmd);
RB_PROTOTYPE(nhgc_entry_head, nexthop_group_cmd, nhgc_entry,
	     nexthop_group_cmd_compare)
DECLARE_QOBJ_TYPE(nexthop_group_cmd);

/*
 * Initialize nexthop_groups.  If you are interested in when
 * a nexthop_group is added/deleted/modified, then set the
 * appropriate callback functions to handle it in your
 * code
 *
 * create - The creation of the nexthop group
 * modify - Modification of the nexthop group when not changing a nexthop
 *          ( resilience as an example )
 * add_nexthop - A nexthop is added to the NHG
 * del_nexthop - A nexthop is deleted from the NHG
 * destroy - The NHG is deleted
 */
void nexthop_group_init(
	void (*create)(const char *name),
	void (*modify)(const struct nexthop_group_cmd *nhgc),
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

extern void nexthop_group_write_nexthop_simple(struct vty *vty,
					       const struct nexthop *nh,
					       char *altifname);
extern void nexthop_group_write_nexthop(struct vty *vty,
					const struct nexthop *nh);

extern void nexthop_group_json_nexthop(json_object *j,
				       const struct nexthop *nh);

/* Return the number of nexthops in this nhg */
extern uint16_t nexthop_group_nexthop_num(const struct nexthop_group *nhg);
extern uint16_t nexthop_group_active_nexthop_num(const struct nexthop_group *nhg);

extern bool nexthop_group_has_label(const struct nexthop_group *nhg);

#ifdef __cplusplus
}
#endif

#endif
