// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_ZLOOKUP_H
#define PIM_ZLOOKUP_H

#include <zebra.h>

#include "zclient.h"

#define PIM_NEXTHOP_LOOKUP_MAX (3) /* max. recursive route lookup */

struct channel_oil;

struct pim_zlookup_nexthop {
	vrf_id_t vrf_id;
	pim_addr nexthop_addr;
	ifindex_t ifindex;
	uint32_t route_metric;
	uint8_t protocol_distance;
};

void zclient_lookup_new(void);
void zclient_lookup_free(void);

int zclient_lookup_nexthop(struct pim_instance *pim,
			   struct pim_zlookup_nexthop nexthop_tab[],
			   const int tab_size, pim_addr addr,
			   int max_lookup);

void pim_zlookup_show_ip_multicast(struct vty *vty);

int pim_zlookup_sg_statistics(struct channel_oil *c_oil);
#endif /* PIM_ZLOOKUP_H */
