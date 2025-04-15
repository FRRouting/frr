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
	uint16_t prefix_len;
};

/*
 * Structure that holds all necessary arguments to call the zebra
 * next hop lookup API.
 */
struct zclient_next_hop_args {
	/* (Input) PIM instance doing the request */
	struct pim_instance *pim;
	/* (Input) (Optional) zebra client doing the lookup */
	struct zclient *zlookup;
	/* (Input) Address to lookup */
	pim_addr address;
	/* (Input) (Optional) Group to derive lookup mode
	 *         (unicast, multicast or both)
	 */
	pim_addr group;

	/* (Output) Next hop information */
	struct pim_zlookup_nexthop next_hops[MULTIPATH_NUM];
};

void zclient_lookup_new(void);
void zclient_lookup_free(void);

int zclient_lookup_nexthop(struct zclient_next_hop_args *args, int max_lookup);

void pim_zlookup_show_ip_multicast(struct vty *vty);

int pim_zlookup_sg_statistics(struct channel_oil *c_oil);
#endif /* PIM_ZLOOKUP_H */
