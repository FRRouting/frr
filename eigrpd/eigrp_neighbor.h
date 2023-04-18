// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP Neighbor Handling.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
 */

#ifndef _ZEBRA_EIGRP_NEIGHBOR_H
#define _ZEBRA_EIGRP_NEIGHBOR_H

/* Prototypes */
extern struct eigrp_neighbor *eigrp_nbr_get(struct eigrp_interface *ei,
					    struct eigrp_header *,
					    struct ip *addr);
extern struct eigrp_neighbor *eigrp_nbr_new(struct eigrp_interface *ei);
extern void eigrp_nbr_delete(struct eigrp_neighbor *neigh);

extern void holddown_timer_expired(struct event *thread);

extern int eigrp_neighborship_check(struct eigrp_neighbor *neigh,
				    struct TLV_Parameter_Type *tlv);
extern void eigrp_nbr_state_update(struct eigrp_neighbor *neigh);
extern void eigrp_nbr_state_set(struct eigrp_neighbor *neigh, uint8_t state);
extern uint8_t eigrp_nbr_state_get(struct eigrp_neighbor *neigh);
extern int eigrp_nbr_count_get(struct eigrp *eigrp);
extern const char *eigrp_nbr_state_str(struct eigrp_neighbor *neigh);
extern struct eigrp_neighbor *
eigrp_nbr_lookup_by_addr(struct eigrp_interface *ei, struct in_addr *addr);
extern struct eigrp_neighbor *
eigrp_nbr_lookup_by_addr_process(struct eigrp *eigrp, struct in_addr addr);
extern void eigrp_nbr_hard_restart(struct eigrp_neighbor *nbr, struct vty *vty);

extern int eigrp_nbr_split_horizon_check(struct eigrp_route_descriptor *ne,
					 struct eigrp_interface *ei);
#endif /* _ZEBRA_EIGRP_NEIGHBOR_H */
