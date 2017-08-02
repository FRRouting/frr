/*
 * PIM for Quagga: add the ability to configure multicast static routes
 * Copyright (C) 2014  Nathan Bahr, ATCorp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef PIM_STATIC_H_
#define PIM_STATIC_H_

#include <zebra.h>
#include "pim_mroute.h"
#include "if.h"

struct static_route {
	/* Each static route is unique by these pair of addresses */
	struct in_addr group;
	struct in_addr source;

	struct channel_oil c_oil;
	ifindex_t iif;
	unsigned char oif_ttls[MAXVIFS];
};

void pim_static_route_free(struct static_route *s_route);

int pim_static_add(struct pim_instance *pim, struct interface *iif,
		   struct interface *oif, struct in_addr group,
		   struct in_addr source);
int pim_static_del(struct pim_instance *pim, struct interface *iif,
		   struct interface *oif, struct in_addr group,
		   struct in_addr source);
int pim_static_write_mroute(struct pim_instance *pim, struct vty *vty,
			    struct interface *ifp);

#endif /* PIM_STATIC_H_ */
