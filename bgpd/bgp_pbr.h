/*
 * BGP pbr
 * Copyright (C) 6WIND
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
#ifndef __BGP_PBR_H__
#define __BGP_PBR_H__

#include "nexthop.h"
#include "zclient.h"

struct bgp_pbr_match {
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];

	/* mapped on enum ipset_type
	 */
	uint32_t type;

#define MATCH_IP_SRC_SET    1 << 0
#define MATCH_IP_DST_SET    1 << 1
	uint32_t flags;

	vrf_id_t vrf_id;

	/* unique identifier for ipset create transaction
	 */
	uint32_t unique;

	/* unique identifier for iptable add transaction
	 */
	uint32_t unique2;

	bool installed;
	bool install_in_progress;

	bool installed_in_iptable;
	bool install_iptable_in_progress;

	struct hash *entry_hash;

	struct bgp_pbr_action *action;

};

struct bgp_pbr_match_entry {
	struct bgp_pbr_match *backpointer;

	uint32_t unique;

	struct prefix src;
	struct prefix dst;

	bool installed;
	bool install_in_progress;
};

struct bgp_pbr_action {

	/*
	 * The Unique identifier of this specific pbrms
	 */
	uint32_t unique;

	uint32_t fwmark;

	uint32_t table_id;

	float rate;

	/*
	 * nexthop information, or drop information
	 * contains src vrf_id and nh contains dest vrf_id
	 */
	vrf_id_t vrf_id;
	struct nexthop nh;

	bool installed;
	bool install_in_progress;

};

extern struct bgp_pbr_action *bgp_pbr_action_rule_lookup(uint32_t unique);

extern struct bgp_pbr_match *bgp_pbr_match_ipset_lookup(vrf_id_t vrf_id,
							uint32_t unique);

extern struct bgp_pbr_match_entry *bgp_pbr_match_ipset_entry_lookup(
					    vrf_id_t vrf_id, char *name,
					    uint32_t unique);

extern void bgp_pbr_init(struct bgp *bgp);

extern uint32_t bgp_pbr_action_hash_key(void *arg);
extern int bgp_pbr_action_hash_equal(const void *arg1,
				     const void *arg2);
extern uint32_t bgp_pbr_match_entry_hash_key(void *arg);
extern int bgp_pbr_match_entry_hash_equal(const void *arg1,
					  const void *arg2);
extern uint32_t bgp_pbr_match_hash_key(void *arg);
extern int bgp_pbr_match_hash_equal(const void *arg1,
				    const void *arg2);

#endif /* __BGP_PBR_H__ */
