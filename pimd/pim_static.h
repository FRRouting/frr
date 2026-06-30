// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga: add the ability to configure multicast static routes
 * Copyright (C) 2014  Nathan Bahr, ATCorp
 */

#ifndef PIM_STATIC_H_
#define PIM_STATIC_H_

#include <zebra.h>

#include "typesafe.h"

#include "pim_mroute.h"
#include "pim_oil.h"
#include "if.h"

PREDECL_DLIST(pim_static_route_cfgs);

struct static_route {
	/* Each static route is unique by these pair of addresses */
	pim_addr group;
	pim_addr source;

	struct channel_oil c_oil;
	ifindex_t iif;
	unsigned char oif_ttls[MAXVIFS];
};

/*
 * Static mroute configuration deferred until both the input and output
 * interfaces exist and have valid multicast VIF indices (e.g. at boot).
 * Identified purely by interface name, which is the configuration identity.
 */
struct static_route_config {
	struct pim_static_route_cfgs_item item;

	char iifname[IF_NAMESIZE];
	char oifname[IF_NAMESIZE];
	pim_addr group;
	pim_addr source;
};

DECLARE_DLIST(pim_static_route_cfgs, struct static_route_config, item);

void pim_static_route_free(struct static_route *s_route);
void pim_static_route_config_free(struct static_route_config *cfg);
void pim_static_route_configs_fini(struct pim_instance *pim);

int pim_static_add(struct pim_instance *pim, struct interface *iif, struct interface *oif,
		   const char *oifname, pim_addr group, pim_addr source);
int pim_static_del(struct pim_instance *pim, struct interface *iif, struct interface *oif,
		   const char *oifname, pim_addr group, pim_addr source);
void pim_static_reconcile(struct pim_instance *pim);
int pim_static_write_mroute(struct pim_instance *pim, struct vty *vty,
			    struct interface *ifp);

int pim_static_nocache_resolve(struct pim_instance *pim, struct interface *ifp, pim_sgaddr *sg);

#endif /* PIM_STATIC_H_ */
