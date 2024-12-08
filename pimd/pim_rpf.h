// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_RPF_H
#define PIM_RPF_H

#include <zebra.h>
#include "pim_str.h"

struct pim_instance;
struct pim_upstream;

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
	pim_addr last_lookup;
	long long last_lookup_time;
	struct interface *interface;     /* RPF_interface(S) */
	pim_addr mrib_nexthop_addr;      /* MRIB.next_hop(S) */
	uint32_t mrib_metric_preference; /* MRIB.pref(S) */
	uint32_t mrib_route_metric;      /* MRIB.metric(S) */
	struct pim_neighbor *nbr;
};

struct pim_rpf {
	struct pim_nexthop source_nexthop;
	pim_addr rpf_addr; /* RPF'(S,G) */
};

enum pim_rpf_result { PIM_RPF_OK = 0, PIM_RPF_CHANGED, PIM_RPF_FAILURE };

/* RPF lookup behaviour */
enum pim_rpf_lookup_mode {
	MCAST_MRIB_ONLY = 0,  /* MRIB only */
	MCAST_URIB_ONLY,      /* URIB only */
	MCAST_MIX_MRIB_FIRST, /* MRIB, if nothing at all then URIB */
	MCAST_MIX_DISTANCE,   /* MRIB & URIB, lower distance wins */
	MCAST_MIX_PFXLEN,     /* MRIB & URIB, longer prefix wins */
	/* on equal value, MRIB wins for last 2 */
	MCAST_NO_CONFIG, /* MIX_MRIB_FIRST, but no show in config write */
};

enum pim_rpf_result pim_rpf_update(struct pim_instance *pim,
				   struct pim_upstream *up,
				   struct pim_rpf *old, const char *caller);
void pim_upstream_rpf_clear(struct pim_instance *pim,
			    struct pim_upstream *up);
int pim_rpf_addr_is_inaddr_any(struct pim_rpf *rpf);

int pim_rpf_is_same(struct pim_rpf *rpf1, struct pim_rpf *rpf2);
void pim_rpf_set_refresh_time(struct pim_instance *pim);
#endif /* PIM_RPF_H */
