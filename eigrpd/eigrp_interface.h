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

extern bool eigrp_if_is_passive(eigrp_interface_t *ei);
extern void eigrp_del_if_params(struct eigrp_if_params *);
extern eigrp_interface_t *eigrp_if_new(eigrp_t *, struct interface *,
				       struct prefix *);
extern int  eigrp_if_up(eigrp_interface_t *);
extern void eigrp_if_update(struct interface *);
extern void eigrp_if_stream_set(eigrp_interface_t *);
extern void eigrp_if_set_multicast(eigrp_interface_t *);
extern uint8_t eigrp_default_iftype(struct interface *);
extern void eigrp_if_free(eigrp_t *, eigrp_interface_t *, int);
extern int eigrp_if_down(eigrp_interface_t *);
extern void eigrp_if_stream_unset(eigrp_interface_t *);

extern eigrp_interface_t *eigrp_if_lookup_by_local_addr(eigrp_t *,
							struct interface *,
							struct in_addr);
extern eigrp_interface_t *eigrp_if_lookup_by_name(eigrp_t *, const char *);

/* Simulate down/up on the interface. */
extern void eigrp_if_reset(struct interface *);

extern int eigrp_if_add_allspfrouters(eigrp_t *, struct prefix *,
				      unsigned int);
extern int eigrp_if_drop_allspfrouters(eigrp_t *top, struct prefix *p,
				       unsigned int ifindex);


#endif /* ZEBRA_EIGRP_INTERFACE_H_ */
