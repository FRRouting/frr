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
extern int eigrp_if_new_hook(struct interface *ifp);
extern int eigrp_if_delete_hook(struct interface *ifp);

extern bool eigrp_if_is_passive(struct eigrp_interface *ei);
extern void eigrp_del_if_params(struct eigrp_if_params *eip);
extern struct eigrp_interface *eigrp_if_new(struct eigrp *eigrp, struct interface *ifp,
					    struct prefix *p);
extern int eigrp_if_up(struct eigrp_interface *ei);
extern void eigrp_if_stream_set(struct eigrp_interface *ei);
extern void eigrp_if_set_multicast(struct eigrp_interface *ei);
extern uint8_t eigrp_default_iftype(struct interface *ifp);
extern void eigrp_if_free(struct eigrp_interface *ei, int source);
extern int eigrp_if_down(struct eigrp_interface *ei);
extern void eigrp_if_stream_unset(struct eigrp_interface *ei);

extern struct eigrp_interface *
eigrp_if_lookup_by_local_addr(struct eigrp *eigrp, struct interface *ifp, struct in_addr address);
extern struct eigrp_interface *eigrp_if_lookup_by_name(struct eigrp *eigrp, const char *ifname);

/* Simulate down/up on the interface. */
extern void eigrp_if_reset(struct interface *ifp);

extern int eigrp_interface_cmp(const struct eigrp_interface *a, const struct eigrp_interface *b);
extern uint32_t eigrp_interface_hash(const struct eigrp_interface *ei);

DECLARE_HASH(eigrp_interface_hash, struct eigrp_interface, eif_item, eigrp_interface_cmp,
	     eigrp_interface_hash);

#endif /* ZEBRA_EIGRP_INTERFACE_H_ */
