// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PBR-map Header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 * Portions:
 *	Copyright (c) 2023 LabN Consulting, L.L.C.
 *	Copyright (c) 2021 The MITRE Corporation
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

enum pbr_forwarding_type {
	PBR_FT_UNSPEC = 0,
	PBR_FT_VRF_UNCHANGED,
	PBR_FT_SETVRF,
	PBR_FT_NEXTHOP_GROUP,
	PBR_FT_NEXTHOP_SINGLE,
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


	/*****************************************************************
	 * Filter fields
	 * gpz 230716: I hope to replace all of the filter fields with
	 * 'struct pbr_filter' from lib/pbr.h.
	 *****************************************************************/

	/*
	 * same bit definitions as in lib/pbr.h
	 */
	uint32_t filter_bm;

	/* Family of the src/dst. Needed when deleting since we clear them */
	unsigned char family;

	/* src and dst IP addresses */
	struct prefix *src;
	struct prefix *dst;

	/* src and dst UDP/TCP ports */
	uint16_t src_prt;
	uint16_t dst_prt;

	uint8_t ip_proto;

	uint8_t match_pcp;
	uint16_t match_vlan_id; /* bits defined in lib/pbr.h */

	uint16_t match_vlan_flags;

	uint8_t dsfield;
	uint32_t mark;

	/*****************************************************************
	 * Action fields
	 *****************************************************************/

	/*
	 * same bit definitions as in lib/pbr.h
	 */
	uint32_t action_bm;

	union sockunion action_src;
	union sockunion action_dst;

	uint16_t action_src_port;
	uint16_t action_dst_port;

	uint8_t action_dscp;
	uint8_t action_ecn;

	uint8_t action_pcp;
	uint8_t action_vlan_id;

#define PBR_MAP_UNDEFINED_QUEUE_ID 0
	uint32_t action_queue_id;

	enum pbr_forwarding_type forwarding_type;

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
#define PBR_MAP_INVALID_SET_STRIP_VLAN (1 << 6)
	uint64_t reason;

	QOBJ_FIELDS;
};

DECLARE_QOBJ_TYPE(pbr_map_sequence);

extern struct pbr_map_entry_head pbr_maps;

extern struct pbr_map_sequence *pbrms_get(const char *name, uint32_t seqno);
extern struct pbr_map_sequence *
pbrms_lookup_unique(uint32_t unique, char *ifname,
		    struct pbr_map_interface **ppmi);

extern struct pbr_map *pbrm_find(const char *name);
extern void pbr_map_delete(struct pbr_map_sequence *pbrms);
extern void pbr_map_delete_nexthops(struct pbr_map_sequence *pbrms);
extern void pbr_map_delete_vrf(struct pbr_map_sequence *pbrms);
extern void pbr_map_add_interface(struct pbr_map *pbrm, struct interface *ifp);
extern void pbr_map_interface_delete(struct pbr_map *pbrm,
				     struct interface *ifp);

extern uint8_t pbr_map_decode_dscp_enum(const char *name);

/* Update maps installed on interface */
extern void pbr_map_policy_interface_update(const struct interface *ifp,
					    bool state_up);

extern void pbr_map_final_interface_deletion(struct pbr_map *pbrm,
					     struct pbr_map_interface *pmi);

extern void pbr_map_vrf_update(const struct pbr_vrf *pbr_vrf);

extern void pbr_map_write_interfaces(struct vty *vty, struct interface *ifp);
extern void pbr_map_init(void);

extern bool pbr_map_check_valid(const char *name);

/**
 * Re-check the pbr map for validity.
 *
 * Install if valid, remove if not.
 *
 * If changed is set, the config on the on the map has changed somewhere
 * and the rules need to be replaced if valid.
 */
extern void pbr_map_check(struct pbr_map_sequence *pbrms, bool changed);
extern void pbr_map_check_nh_group_change(const char *nh_group);
extern void pbr_map_reason_string(unsigned int reason, char *buf, int size);

extern void pbr_map_schedule_policy_from_nhg(const char *nh_group,
					     bool installed);

extern void pbr_map_install(struct pbr_map *pbrm);

extern void pbr_map_policy_install(const char *name);
extern void pbr_map_policy_delete(struct pbr_map *pbrm,
				  struct pbr_map_interface *pmi);

extern void pbr_map_sequence_delete(struct pbr_map_sequence *pbrms);

extern void pbr_map_check_vrf_nh_group_change(const char *nh_group,
					      struct pbr_vrf *pbr_vrf,
					      uint32_t old_vrf_id);
extern void pbr_map_check_interface_nh_group_change(const char *nh_group,
						    struct interface *ifp,
						    ifindex_t oldifindex);
#endif
