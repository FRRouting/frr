/*
 * PBR-map Header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#ifndef __PBR_MAP_H__
#define __PBR_MAP_H__

#include <bitfield.h>

#include "pbr_vrf.h"

struct pbr_map {
	/*
	 * RB Tree of the pbr_maps
	 */
	RB_ENTRY(pbr_map) pbr_map_entry;

	/*
	 * The name of the PBR_MAP
	 */
#define PBR_MAP_NAMELEN 100
	char name[PBR_MAP_NAMELEN];

	struct list *seqnumbers;

	/*
	 * The list of incoming interfaces that
	 * we will apply this policy map onto
	 */
	struct list *incoming;

	bitfield_t ifi_bitfield;
	/*
	 * If valid is true we think the pbr_map is valid,
	 * If false, look in individual pbrms to see
	 * what we think is the invalid reason
	 */
	bool valid;
};

RB_HEAD(pbr_map_entry_head, pbr_map);
RB_PROTOTYPE(pbr_map_entry_head, pbr_map, pbr_map_entry, pbr_map_compare)

struct pbr_map_interface {
	uint32_t install_bit;

	struct interface *ifp;

	struct pbr_map *pbrm;

	bool delete;
};

struct pbr_map_sequence {
	struct pbr_map *parent;

	/*
	 * The Unique identifier of this specific pbrms
	 */
	uint32_t unique;

	/*
	 * The sequence of where we are for display
	 */
	uint32_t seqno;

	/*
	 * The rule number to install into
	 */
	uint32_t ruleno;

	/*
	 * Our policy Catchers
	 */
	struct prefix *src;
	struct prefix *dst;
	uint32_t mark;

	/*
	 * Family of the src/dst.  Needed when deleting since we clear them
	 */
	unsigned char family;

	/*
	 * Use interface's vrf.
	 */
	bool vrf_unchanged;

	/*
	 * The vrf to lookup in was directly configured.
	 */
	bool vrf_lookup;

	/*
	 * VRF to lookup.
	 */
	char vrf_name[VRF_NAMSIZ + 1];

	/*
	 * The nexthop group we auto create
	 * for when the user specifies a individual
	 * nexthop
	 */
	struct nexthop_group *nhg;
	char *internal_nhg_name;

	/*
	 * The name of the nexthop group
	 * configured in the pbr-map
	 */
	char *nhgrp_name;

	/*
	 * Do we think are nexthops are installed
	 */
	bool nhs_installed;

	/*
	 * Are we installed
	 */
	uint64_t installed;

	/*
	 * A reason of 0 means we think the pbr_map_sequence is good to go
	 * We can accumuluate multiple failure states
	 */
#define PBR_MAP_VALID_SEQUENCE_NUMBER    0
#define PBR_MAP_INVALID_NEXTHOP_GROUP    (1 << 0)
#define PBR_MAP_INVALID_NEXTHOP          (1 << 1)
#define PBR_MAP_INVALID_NO_NEXTHOPS      (1 << 2)
#define PBR_MAP_INVALID_BOTH_NHANDGRP    (1 << 3)
#define PBR_MAP_INVALID_EMPTY            (1 << 4)
#define PBR_MAP_INVALID_VRF              (1 << 5)
	uint64_t reason;

	QOBJ_FIELDS
};

DECLARE_QOBJ_TYPE(pbr_map_sequence)

extern struct pbr_map_entry_head pbr_maps;

extern struct pbr_map_sequence *pbrms_get(const char *name, uint32_t seqno);
extern struct pbr_map_sequence *
pbrms_lookup_unique(uint32_t unique, ifindex_t ifindex,
		    struct pbr_map_interface **ppmi);

extern struct pbr_map *pbrm_find(const char *name);
extern void pbr_map_delete(struct pbr_map_sequence *pbrms);
extern void pbr_map_delete_nexthops(struct pbr_map_sequence *pbrms);
extern void pbr_map_delete_vrf(struct pbr_map_sequence *pbrms);
extern void pbr_map_add_interface(struct pbr_map *pbrm, struct interface *ifp);
extern void pbr_map_interface_delete(struct pbr_map *pbrm,
				     struct interface *ifp);

/* Update maps installed on interface */
extern void pbr_map_policy_interface_update(const struct interface *ifp,
					    bool state_up);

extern void pbr_map_final_interface_deletion(struct pbr_map *pbrm,
					     struct pbr_map_interface *pmi);

extern void pbr_map_vrf_update(const struct pbr_vrf *pbr_vrf);

extern void pbr_map_write_interfaces(struct vty *vty, struct interface *ifp);
extern void pbr_map_init(void);

extern bool pbr_map_check_valid(const char *name);

extern void pbr_map_check(struct pbr_map_sequence *pbrms);
extern void pbr_map_check_nh_group_change(const char *nh_group);
extern void pbr_map_reason_string(unsigned int reason, char *buf, int size);

extern void pbr_map_schedule_policy_from_nhg(const char *nh_group);

extern void pbr_map_install(struct pbr_map *pbrm);

extern void pbr_map_policy_install(const char *name);
extern void pbr_map_policy_delete(struct pbr_map *pbrm,
				  struct pbr_map_interface *pmi);
#endif
