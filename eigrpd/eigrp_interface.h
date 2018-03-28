/*
 * EIGRP Interface Functions.
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

#ifndef _ZEBRA_EIGRP_INTERFACE_H_
#define _ZEBRA_EIGRP_INTERFACE_H_

/*Prototypes*/
extern void eigrp_if_init(void);
extern int eigrp_if_new_hook(struct interface *);
extern int eigrp_if_delete_hook(struct interface *);

extern bool eigrp_if_is_passive(struct eigrp_interface *ei);
extern void eigrp_del_if_params(struct eigrp_if_params *);
extern struct eigrp_interface *eigrp_if_new(struct eigrp *, struct interface *,
					    struct prefix *);
extern int eigrp_if_up(struct eigrp_interface *);
extern void eigrp_if_stream_set(struct eigrp_interface *);
extern void eigrp_if_set_multicast(struct eigrp_interface *);
extern uint8_t eigrp_default_iftype(struct interface *);
extern void eigrp_if_free(struct eigrp_interface *, int);
extern int eigrp_if_down(struct eigrp_interface *);
extern void eigrp_if_stream_unset(struct eigrp_interface *);

extern struct eigrp_interface *eigrp_if_lookup_by_local_addr(struct eigrp *,
							     struct interface *,
							     struct in_addr);
extern struct eigrp_interface *eigrp_if_lookup_by_name(struct eigrp *,
						       const char *);

/* Simulate down/up on the interface. */
extern void eigrp_if_reset(struct interface *);

extern uint32_t eigrp_bandwidth_to_scaled(uint32_t);
extern uint32_t eigrp_scaled_to_bandwidth(uint32_t);
extern uint32_t eigrp_delay_to_scaled(uint32_t);
extern uint32_t eigrp_scaled_to_delay(uint32_t);


#endif /* ZEBRA_EIGRP_INTERFACE_H_ */
