// SPDX-License-Identifier: GPL-2.0-or-later
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

#endif /* ZEBRA_EIGRP_INTERFACE_H_ */
