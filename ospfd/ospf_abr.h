// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF ABR functions.
 * Copyright (C) 1999 Alex Zinin
 */

#ifndef _ZEBRA_OSPF_ABR_H
#define _ZEBRA_OSPF_ABR_H

#define OSPF_ABR_TASK_DELAY 	5

#define OSPF_AREA_RANGE_ADVERTISE	(1 << 0)
#define OSPF_AREA_RANGE_SUBSTITUTE	(1 << 1)

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
						      struct prefix_ipv4 *);

extern struct ospf_area_range *ospf_some_area_range_match(struct prefix_ipv4 *);

extern struct ospf_area_range *
ospf_area_range_lookup_next(struct ospf_area *, struct in_addr *, int);

extern int ospf_area_range_set(struct ospf *, struct in_addr,
			       struct prefix_ipv4 *, int);
extern int ospf_area_range_cost_set(struct ospf *, struct in_addr,
				    struct prefix_ipv4 *, uint32_t);
extern int ospf_area_range_unset(struct ospf *, struct in_addr,
				 struct prefix_ipv4 *);
extern int ospf_area_range_substitute_set(struct ospf *, struct in_addr,
					  struct prefix_ipv4 *,
					  struct prefix_ipv4 *);
extern int ospf_area_range_substitute_unset(struct ospf *, struct in_addr,
					    struct prefix_ipv4 *);
extern struct ospf_area_range *ospf_area_range_match_any(struct ospf *,
							 struct prefix_ipv4 *);
extern int ospf_area_range_active(struct ospf_area_range *);
extern int ospf_act_bb_connection(struct ospf *);

extern void ospf_check_abr_status(struct ospf *);
extern void ospf_abr_task(struct ospf *);
extern void ospf_schedule_abr_task(struct ospf *);

extern void ospf_abr_announce_network_to_area(struct prefix_ipv4 *, uint32_t,
					      struct ospf_area *);
extern void ospf_abr_nssa_check_status(struct ospf *ospf);
#endif /* _ZEBRA_OSPF_ABR_H */
