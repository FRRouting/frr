// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF ABR functions.
 * Copyright (C) 1999 Alex Zinin
 */

#ifndef _ZEBRA_OSPF_ABR_H
#define _ZEBRA_OSPF_ABR_H

#define OSPF_ABR_TASK_DELAY 	5
#define OSPF_ABR_DNA_TIMER 10
/* Delay in announceing Non-DNA routers
 * so that LSAs are completely synced
 * before generating indication LSAs.
 */

#define OSPF_AREA_RANGE_ADVERTISE	(1 << 0)
#define OSPF_AREA_RANGE_SUBSTITUTE	(1 << 1)
#define OSPF_AREA_RANGE_NSSA		(1 << 2)

/* Area range. */
struct ospf_area_range {
	/* Area range address. */
	struct in_addr addr;

	/* Area range masklen. */
	uint8_t masklen;

	/* Flags. */
	uint8_t flags;

	/* Number of more specific prefixes. */
	int specifics;

	/* Addr and masklen to substitute. */
	struct in_addr subst_addr;
	uint8_t subst_masklen;

	/* Range cost. */
	uint32_t cost;

	/* Configured range cost. */
	uint32_t cost_config;
};

/* Prototypes. */
extern struct ospf_area_range *ospf_area_range_lookup(struct ospf_area *,
						      struct route_table *,
						      struct prefix_ipv4 *);
extern struct ospf_area_range *
ospf_area_range_lookup_next(struct ospf_area *, struct in_addr *, int);

extern int ospf_area_range_set(struct ospf *, struct ospf_area *,
			       struct route_table *, struct prefix_ipv4 *, int,
			       bool);
extern int ospf_area_range_cost_set(struct ospf *, struct ospf_area *,
				    struct route_table *, struct prefix_ipv4 *,
				    uint32_t);
extern int ospf_area_range_unset(struct ospf *, struct ospf_area *,
				 struct route_table *, struct prefix_ipv4 *);
extern int ospf_area_range_substitute_set(struct ospf *, struct ospf_area *,
					  struct prefix_ipv4 *,
					  struct prefix_ipv4 *);
extern int ospf_area_range_substitute_unset(struct ospf *, struct ospf_area *,
					    struct prefix_ipv4 *);
extern struct ospf_area_range *ospf_area_range_match_any(struct ospf *,
							 struct prefix_ipv4 *);
extern int ospf_area_range_active(struct ospf_area_range *);
extern int ospf_act_bb_connection(struct ospf *);

extern void ospf_check_abr_status(struct ospf *);
extern void ospf_abr_task(struct ospf *);
extern void ospf_abr_nssa_task(struct ospf *ospf);
extern void ospf_schedule_abr_task(struct ospf *);

extern void ospf_abr_announce_network_to_area(struct prefix_ipv4 *, uint32_t,
					      struct ospf_area *);
extern void ospf_abr_nssa_type7_defaults(struct ospf *ospf);
extern void ospf_abr_nssa_check_status(struct ospf *ospf);
extern void ospf_abr_generate_indication_lsa(struct ospf *ospf,
					     const struct ospf_area *area);
extern void ospf_flush_indication_lsas(struct ospf *ospf);
extern void ospf_generate_indication_lsa(struct ospf *ospf,
					 struct ospf_area *area);
extern bool ospf_check_fr_enabled_all(struct ospf *ospf);
extern void ospf_recv_indication_lsa_flush(struct ospf_lsa *lsa);

/** @brief Static inline functions.
 *  @param Area pointer.
 *  @return area Flood Reduction status.
 */
static inline bool ospf_check_area_fr_enabled(const struct ospf_area *area)
{
	return area->fr_info.enabled ? true : false;
}
#endif /* _ZEBRA_OSPF_ABR_H */
