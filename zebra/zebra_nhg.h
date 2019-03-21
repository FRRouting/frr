/* Zebra Nexthop Group header.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 *                    Stephen Worley
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef __ZEBRA_NHG_H__
#define __ZEBRA_NHG_H__

#include "zebra/rib.h"
#include "lib/nexthop_group.h"

#include "zebra/zebra_dplane.h"

struct nhg_hash_entry {
	uint32_t id;
	afi_t afi;
	vrf_id_t vrf_id;
	bool is_kernel_nh;

	struct nexthop_group nhg;

	/* If this is not a group, it
	 * will be a single nexthop
	 * and must have an interface
	 * associated with it.
	 * Otherwise, this will be null.
	 */
	struct interface *ifp;

	uint32_t refcnt;
	uint32_t dplane_ref;

	uint32_t flags;

	/* Dependency list for other entries.
	 * For instance a group with two
	 * nexthops will have two dependencies
	 * pointing to those nhg_hash_entries.
	 */
	struct list *nhg_depends;
/*
 * Is this nexthop group valid, ie all nexthops are fully resolved.
 * What is fully resolved?  It's a nexthop that is either self contained
 * and correct( ie no recursive pointer ) or a nexthop that is recursively
 * resolved and correct.
 */
#define NEXTHOP_GROUP_VALID 0x1
/*
 * Has this nexthop group been installed?  At this point in time, this
 * means that the data-plane has been told about this nexthop group
 * and it's possible usage by a route entry.
 */
#define NEXTHOP_GROUP_INSTALLED 0x2
/*
 * Has the nexthop group been queued to be send to the FIB?
 * The NEXTHOP_GROUP_VALID flag should also be set by this point.
 */
#define NEXTHOP_GROUP_QUEUED 0x4
};

/* Struct for dependency nexthop */
struct nhg_depend {
	struct nhg_hash_entry *nhe;
};


void zebra_nhg_init(void);
void zebra_nhg_terminate(void);

extern struct nhg_depend *nhg_depend_add(struct list *nhg_depends,
					 struct nhg_hash_entry *depend);
extern struct nhg_depend *nhg_depend_new(void);
extern void nhg_depend_free(struct nhg_depend *depends);

extern struct list *nhg_depend_new_list(void);

extern struct nhg_hash_entry *zebra_nhg_lookup_id(uint32_t id);
extern int zebra_nhg_insert_id(struct nhg_hash_entry *nhe);

extern uint32_t zebra_nhg_hash_key(const void *arg);
extern uint32_t zebra_nhg_id_key(const void *arg);

extern bool zebra_nhg_hash_equal(const void *arg1, const void *arg2);
extern bool zebra_nhg_hash_id_equal(const void *arg1, const void *arg2);

extern struct nhg_hash_entry *zebra_nhg_find(struct nexthop_group *nhg,
					     vrf_id_t vrf_id, afi_t afi,
					     uint32_t id);
extern struct nhg_hash_entry *zebra_nhg_find_id(uint32_t id,
						struct nexthop_group *nhg);
void zebra_nhg_free(void *arg);
void zebra_nhg_release(struct nhg_hash_entry *nhe);
void zebra_nhg_decrement_ref(struct nhg_hash_entry *nhe);

extern int nexthop_active_update(struct route_node *rn, struct route_entry *re);

void zebra_nhg_install_kernel(struct nhg_hash_entry *nhe);
void zebra_nhg_uninstall_kernel(struct nhg_hash_entry *nhe);

void zebra_nhg_cleanup_tables(void);

void zebra_nhg_dplane_result(struct zebra_dplane_ctx *ctx);
#endif
