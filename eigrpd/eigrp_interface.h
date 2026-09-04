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

/*
 * Accessors for the per-interface EIGRP data hung off ifp->info.
 *
 * Modeled on ospfd's IF_OSPF_IF_INFO()/IF_DEF_PARAMS()/IF_OIFS().  Note that
 * ifp->info is a struct eigrp_if_info (interface scope), not a struct
 * eigrp_interface (address scope) as it was historically.
 */
#define IF_EIGRP_IF_INFO(I) ((struct eigrp_if_info *)((I)->info))
#define EIGRP_IF_DEF_PARAMS(I) (IF_EIGRP_IF_INFO(I)->def_params)
#define EIGRP_IF_EIFS(I) (IF_EIGRP_IF_INFO(I)->eifs)

/*
 * Interface configuration lifecycle.
 *
 * eigrp_if_info_get() allocates the per-interface data on demand, so
 * configuration can be stored whether or not EIGRP is running on the
 * interface.  That is what fixes issue #11301.
 */
extern struct eigrp_if_params *eigrp_new_if_params(void);
extern struct eigrp_if_info *eigrp_if_info_get(struct interface *ifp);
extern void eigrp_if_info_free(struct interface *ifp);

/*
 * Tear down the running instances on an interface while keeping its
 * configuration.  Use this when EIGRP stops on an interface; only interface
 * deletion should discard the configuration as well.
 */
extern void eigrp_if_free_all(struct interface *ifp);

/*
 * Look up the running EIGRP instance on an interface.
 *
 * Transitional: EIGRP currently runs on at most one connected prefix per
 * interface, so this returns that single instance.  Once per-address
 * instances land, callers that are address-specific must look up by prefix
 * in EIGRP_IF_EIFS() instead.
 */
extern struct eigrp_interface *eigrp_if_lookup_by_ifp(struct interface *ifp);
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
