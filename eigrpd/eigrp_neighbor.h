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

#ifndef _ZEBRA_EIGRP_NEIGHBOR_H
#define _ZEBRA_EIGRP_NEIGHBOR_H

/* Prototypes */
extern struct eigrp_neighbor *eigrp_nbr_get(struct eigrp_interface *,
					    struct eigrp_header *, struct ip *);
extern struct eigrp_neighbor *eigrp_nbr_new(struct eigrp_interface *);
extern void eigrp_nbr_delete(struct eigrp_neighbor *);

extern int holddown_timer_expired(struct thread *);

extern int eigrp_neighborship_check(struct eigrp_neighbor *,
				    struct TLV_Parameter_Type *);
extern void eigrp_nbr_state_update(struct eigrp_neighbor *);
extern void eigrp_nbr_state_set(struct eigrp_neighbor *, uint8_t state);
extern uint8_t eigrp_nbr_state_get(struct eigrp_neighbor *);
extern int eigrp_nbr_count_get(void);
extern const char *eigrp_nbr_state_str(struct eigrp_neighbor *);
extern struct eigrp_neighbor *eigrp_nbr_lookup_by_addr(struct eigrp_interface *,
						       struct in_addr *);
extern struct eigrp_neighbor *eigrp_nbr_lookup_by_addr_process(struct eigrp *,
							       struct in_addr);
extern void eigrp_nbr_hard_restart(struct eigrp_neighbor *nbr, struct vty *vty);

extern int eigrp_nbr_split_horizon_check(struct eigrp_nexthop_entry *ne,
					 struct eigrp_interface *ei);
#endif /* _ZEBRA_EIGRP_NEIGHBOR_H */
