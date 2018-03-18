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

#ifndef PIM_RPF_H
#define PIM_RPF_H

#include <zebra.h>

#include "pim_upstream.h"
#include "pim_neighbor.h"

/*
  RFC 4601:

  Metric Preference
    Preference value assigned to the unicast routing protocol that
    provided the route to the multicast source or Rendezvous-Point.

  Metric
    The unicast routing table metric associated with the route used to
    reach the multicast source or Rendezvous-Point.  The metric is in
    units applicable to the unicast routing protocol used.
*/
struct pim_nexthop {
	struct in_addr last_lookup;
	long long last_lookup_time;
	struct interface *interface;     /* RPF_interface(S) */
	struct prefix mrib_nexthop_addr; /* MRIB.next_hop(S) */
	uint32_t mrib_metric_preference; /* MRIB.pref(S) */
	uint32_t mrib_route_metric;      /* MRIB.metric(S) */
	struct pim_neighbor *nbr;
};

struct pim_rpf {
	struct pim_nexthop source_nexthop;
	struct prefix rpf_addr; /* RPF'(S,G) */
};

enum pim_rpf_result { PIM_RPF_OK = 0, PIM_RPF_CHANGED, PIM_RPF_FAILURE };

struct pim_upstream;

unsigned int pim_rpf_hash_key(void *arg);
int pim_rpf_equal(const void *arg1, const void *arg2);

int pim_nexthop_lookup(struct pim_instance *pim, struct pim_nexthop *nexthop,
		       struct in_addr addr, int neighbor_needed);
enum pim_rpf_result pim_rpf_update(struct pim_instance *pim,
				   struct pim_upstream *up, struct pim_rpf *old,
				   uint8_t is_new);

int pim_rpf_addr_is_inaddr_none(struct pim_rpf *rpf);
int pim_rpf_addr_is_inaddr_any(struct pim_rpf *rpf);

int pim_rpf_is_same(struct pim_rpf *rpf1, struct pim_rpf *rpf2);
void pim_rpf_set_refresh_time(struct pim_instance *pim);
#endif /* PIM_RPF_H */
