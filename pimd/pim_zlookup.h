/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

#ifndef PIM_ZLOOKUP_H
#define PIM_ZLOOKUP_H

#include <zebra.h>

#include "zclient.h"

#define PIM_NEXTHOP_LOOKUP_MAX (3) /* max. recursive route lookup */

struct pim_zlookup_nexthop {
	struct prefix nexthop_addr;
	ifindex_t ifindex;
	uint32_t route_metric;
	uint8_t protocol_distance;
};

void zclient_lookup_new(void);
void zclient_lookup_free(void);

int zclient_lookup_nexthop(struct pim_instance *pim,
			   struct pim_zlookup_nexthop nexthop_tab[],
			   const int tab_size, struct in_addr addr,
			   int max_lookup);

void pim_zlookup_show_ip_multicast(struct vty *vty);

int pim_zlookup_sg_statistics(struct channel_oil *c_oil);
#endif /* PIM_ZLOOKUP_H */
