/*
 * OSPF AS Boundary Router functions.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_OSPF_ASBR_H
#define _ZEBRA_OSPF_ASBR_H

struct route_map_set_values {
	int32_t metric;
	int32_t metric_type;
};

/* Redistributed external information. */
struct external_info {
	/* Type of source protocol. */
	uint8_t type;

	unsigned short instance;

	/* Prefix. */
	struct prefix_ipv4 p;

	/* Interface index. */
	ifindex_t ifindex;

	/* Nexthop address. */
	struct in_addr nexthop;

	/* Additional Route tag. */
	route_tag_t tag;

	/* Actual tag received from zebra*/
	route_tag_t orig_tag;

	struct route_map_set_values route_map_set;
#define ROUTEMAP_METRIC(E) (E)->route_map_set.metric
#define ROUTEMAP_METRIC_TYPE(E) (E)->route_map_set.metric_type

	/* Back pointer to summary address */
	struct ospf_external_aggr_rt *aggr_route;

	/* To identify the routes to be originated
	 * after a summary address deletion.
	 */
	bool to_be_processed;
};

#define OSPF_EXTL_AGGR_DEFAULT_DELAY 5

#define OSPF_EXTERNAL_RT_COUNT(aggr)                                           \
	(((struct ospf_external_aggr_rt *)aggr)->match_extnl_hash->count)

enum ospf_aggr_action_t {
	OSPF_ROUTE_AGGR_NONE = 0,
	OSPF_ROUTE_AGGR_ADD,
	OSPF_ROUTE_AGGR_DEL,
	OSPF_ROUTE_AGGR_MODIFY
};

#define OSPF_SUCCESS 1
#define OSPF_FAILURE 0
#define OSPF_INVALID -1

#define OSPF_EXTERNAL_AGGRT_NO_ADVERTISE 0x1
#define OSPF_EXTERNAL_AGGRT_ORIGINATED 0x2

/* Data structures for external route aggregator */
struct ospf_external_aggr_rt {
	/* Prefix. */
	struct prefix_ipv4 p;

	/* Bit 1 : Dont advertise.
	 * Bit 2 : Originated as Type-5
	 */
	uint8_t flags;

	/* Tag for summary route */
	route_tag_t tag;

	/* Action to be done at the delay
	 * timer expairy.
	 */
	enum ospf_aggr_action_t action;

	/* Hash Table of external routes */
	struct hash *match_extnl_hash;
};

#define OSPF_ASBR_CHECK_DELAY 30
#define OSPF_ASBR_NSSA_REDIST_UPDATE_DELAY 9

extern void ospf_external_route_remove(struct ospf *, struct prefix_ipv4 *);
extern struct external_info *ospf_external_info_new(uint8_t, unsigned short);
extern void ospf_reset_route_map_set_values(struct route_map_set_values *);
extern int ospf_route_map_set_compare(struct route_map_set_values *,
				      struct route_map_set_values *);
extern struct external_info *ospf_external_info_add(struct ospf *, uint8_t,
						    unsigned short,
						    struct prefix_ipv4,
						    ifindex_t, struct in_addr,
						    route_tag_t);
extern void ospf_external_info_delete(struct ospf *, uint8_t, unsigned short,
				      struct prefix_ipv4);
extern struct external_info *ospf_external_info_lookup(struct ospf *, uint8_t,
						       unsigned short,
						       struct prefix_ipv4 *);
extern void ospf_asbr_status_update(struct ospf *, uint8_t);
extern void ospf_schedule_asbr_nssa_redist_update(struct ospf *ospf);

extern void ospf_redistribute_withdraw(struct ospf *, uint8_t, unsigned short);
extern void ospf_asbr_check(void);
extern void ospf_schedule_asbr_check(void);
extern void ospf_asbr_route_install_lsa(struct ospf_lsa *);
extern struct ospf_lsa *ospf_external_info_find_lsa(struct ospf *,
						    struct prefix_ipv4 *p);

/* External Route Aggregator */
extern void ospf_asbr_external_aggregator_init(struct ospf *instance);
extern void ospf_external_aggregator_free(struct ospf_external_aggr_rt *aggr);
extern bool is_valid_summary_addr(struct prefix_ipv4 *p);
extern struct ospf_external_aggr_rt *
ospf_external_aggr_match(struct ospf *ospf, struct prefix_ipv4 *p);
extern void ospf_unlink_ei_from_aggr(struct ospf *ospf,
				     struct ospf_external_aggr_rt *aggr,
				     struct external_info *ei);
extern struct ospf_lsa *
ospf_originate_summary_lsa(struct ospf *ospf,
			   struct ospf_external_aggr_rt *aggr,
			   struct external_info *ei);
extern int ospf_external_aggregator_timer_set(struct ospf *ospf,
					      unsigned int interval);
extern void ospf_external_aggrigator_free(struct ospf_external_aggr_rt *aggr);

extern struct ospf_external_aggr_rt *
ospf_extrenal_aggregator_lookup(struct ospf *ospf, struct prefix_ipv4 *p);

void ospf_unset_all_aggr_flag(struct ospf *ospf);

extern int ospf_asbr_external_aggregator_set(struct ospf *ospf,
					     struct prefix_ipv4 *p,
					     route_tag_t tag);
extern int ospf_asbr_external_aggregator_unset(struct ospf *ospf,
					       struct prefix_ipv4 *p,
					       route_tag_t tag);
extern int ospf_asbr_external_rt_no_advertise(struct ospf *ospf,
					      struct prefix_ipv4 *p);
extern int ospf_asbr_external_rt_advertise(struct ospf *ospf,
					   struct prefix_ipv4 *p);
#endif /* _ZEBRA_OSPF_ASBR_H */
