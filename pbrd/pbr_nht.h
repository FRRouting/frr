/*
 * PBR-nht Header
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
#ifndef __PBR_NHT_H__
#define __PBR_NHT_H__

#include <lib/zclient.h>
#include <lib/nexthop_group.h>

#include "pbr_map.h"

#define PBR_NHC_NAMELEN PBR_MAP_NAMELEN + 10

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

	struct nexthop *nexthop;

	bool valid;
};

extern void pbr_nht_write_table_range(struct vty *vty);
#define PBR_NHT_DEFAULT_LOW_TABLEID 10000
#define PBR_NHT_DEFAULT_HIGH_TABLEID 11000
extern void pbr_nht_set_tableid_range(uint32_t low, uint32_t high);

/*
 * Get the next tableid to use for installation.
 *
 * peek
 *    If set to true, retrieves the next ID without marking it used. The next
 *    call will return the same ID.
 */
extern uint32_t pbr_nht_get_next_tableid(bool peek);
/*
 * Get the next rule number to use for installation
 */
extern void pbr_nht_write_rule_range(struct vty *vty);

#define PBR_NHT_DEFAULT_LOW_RULE 300
#define PBR_NHT_DEFAULT_HIGH_RULE 1300
extern void pbr_nht_set_rule_range(uint32_t low, uint32_t high);

extern uint32_t pbr_nht_get_next_rule(uint32_t seqno);

extern void pbr_nhgroup_add_cb(const char *name);
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

extern void pbr_nht_add_individual_nexthop(struct pbr_map_sequence *pbrms);
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

/*
 * When we get a callback from zebra about a nexthop changing
 */
extern void pbr_nht_nexthop_update(struct zapi_route *nhr);

extern void pbr_nht_init(void);
#endif
