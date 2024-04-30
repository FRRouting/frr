// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga: add the ability to configure multicast static routes
 * Copyright (C) 2014  Nathan Bahr, ATCorp
 */

#ifndef PIM_STATIC_H_
#define PIM_STATIC_H_

#include <zebra.h>
#include "pim_mroute.h"
#include "pim_oil.h"
#include "if.h"

struct static_route {
	/* Each static route is unique by these pair of addresses */
	pim_addr group;
	pim_addr source;

	struct channel_oil c_oil;
	ifindex_t iif;
	unsigned char oif_ttls[MAXVIFS];
};

void pim_static_route_free(struct static_route *s_route);

int pim_static_add(struct pim_instance *pim, struct interface *iif,
		   struct interface *oif, pim_addr group, pim_addr source);
int pim_static_del(struct pim_instance *pim, struct interface *iif,
		   struct interface *oif, pim_addr group, pim_addr source);
int pim_static_write_mroute(struct pim_instance *pim, struct vty *vty,
			    struct interface *ifp);

#endif /* PIM_STATIC_H_ */
