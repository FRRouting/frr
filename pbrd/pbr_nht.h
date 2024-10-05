// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PBR-nht Header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __PBR_NHT_H__
#define __PBR_NHT_H__

#include <lib/zclient.h>
#include <lib/nexthop_group.h>

#include "pbr_map.h"
#include "json.h"

#define PBR_NHC_NAMELEN PBR_MAP_NAMELEN + 10

extern struct hash *pbr_nhg_hash;

struct pbr_nexthop_group_cache {
	char name[PBR_NHC_NAMELEN];

	uint32_t table_id;

	struct hash *nhh;

	/*
	 * If all nexthops are considered valid
	 */
	bool valid;

	bool installed;
};

struct pbr_nexthop_cache {
	struct pbr_nexthop_group_cache *parent;

	char vrf_name[VRF_NAMSIZ + 1];
	char intf_name[IFNAMSIZ + 1];

	struct nexthop nexthop;

	bool looked_at;
	bool valid;
	bool nhr_matched;
};

extern void pbr_nht_write_table_range(struct vty *vty);
#define PBR_NHT_DEFAULT_LOW_TABLEID 10000
#define PBR_NHT_DEFAULT_HIGH_TABLEID 11000
extern void pbr_nht_set_tableid_range(uint32_t low, uint32_t high);

/*
 * Find and reserve the next available table for installation;
 * Sequential calls to this function will reserve sequential table numbers
 * until the configured range is exhausted; calls made after exhaustion always
 * return 0
 */
extern uint32_t
pbr_nht_reserve_next_table_id(struct pbr_nexthop_group_cache *nhgc);
/*
 * Get the next tableid to use for installation to kernel
 */
extern uint32_t pbr_nht_find_next_unallocated_table_id(void);
/*
 * Calculate where the next table representing a nhg will go in kernel
 */
extern void pbr_nht_update_next_unallocated_table_id(void);
/*
 * Indicate if there are free spots to install a table to kernel within the
 * configured PBR table range
 */
extern bool pbr_nht_has_unallocated_table(void);
/*
 * Get the next rule number to use for installation
 */
extern void pbr_nht_write_rule_range(struct vty *vty);

#define PBR_NHT_DEFAULT_LOW_RULE 300
#define PBR_NHT_DEFAULT_HIGH_RULE 1300
extern void pbr_nht_set_rule_range(uint32_t low, uint32_t high);

extern uint32_t pbr_nht_get_next_rule(uint32_t seqno);

extern void pbr_nhgroup_add_cb(const char *name);
extern void pbr_nhgroup_modify_cb(const struct nexthop_group_cmd *nhgc);
extern void pbr_nhgroup_add_nexthop_cb(const struct nexthop_group_cmd *nhg,
				       const struct nexthop *nhop);
extern void pbr_nhgroup_del_nexthop_cb(const struct nexthop_group_cmd *nhg,
				       const struct nexthop *nhop);
extern void pbr_nhgroup_delete_cb(const char *name);

extern bool pbr_nht_nexthop_valid(struct nexthop_group *nhg);
extern bool pbr_nht_nexthop_group_valid(const char *name);

extern struct pbr_nexthop_group_cache *pbr_nht_add_group(const char *name);
extern void pbr_nht_change_group(const char *name);
extern void pbr_nht_delete_group(const char *name);

extern void pbr_nht_set_seq_nhg_data(struct pbr_map_sequence *pbrms,
				     const struct nexthop_group_cmd *nhgc);
extern void pbr_nht_set_seq_nhg(struct pbr_map_sequence *pbrms,
				const char *name);

extern void pbr_nht_add_individual_nexthop(struct pbr_map_sequence *pbrms,
					   const struct nexthop *nhop);
extern void pbr_nht_delete_individual_nexthop(struct pbr_map_sequence *pbrms);
/*
 * Given the tableid of the installed default
 * route, find the nexthop-group associated with
 * it, then find all pbr-maps that use it and
 * install/delete them as well.
 */
extern void pbr_nht_route_installed_for_table(uint32_t table_id);
extern void pbr_nht_route_removed_for_table(uint32_t table_id);

/*
 * Given the nexthop group name, lookup the associated
 * tableid with it
 */
extern uint32_t pbr_nht_get_table(const char *name);

extern bool pbr_nht_get_installed(const char *name);

extern char *pbr_nht_nexthop_make_name(char *name, size_t l, uint32_t seqno,
				       char *buffer);

extern void pbr_nht_show_nexthop_group(struct vty *vty, const char *name);
extern void pbr_nht_json_nexthop_group(json_object *j, const char *name);

/*
 * When we get a callback from zebra about a nexthop changing
 */
extern void pbr_nht_nexthop_update(struct zapi_route *nhr);

/*
 * When we get a callback from zebra about an interface status update.
 */
extern void pbr_nht_nexthop_interface_update(struct interface *ifp);

extern void pbr_nht_init(void);

extern void pbr_nht_vrf_update(struct pbr_vrf *pbr_vrf);
extern void pbr_nht_interface_update(struct interface *ifp);
#endif
