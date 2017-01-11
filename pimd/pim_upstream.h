/*
  PIM for Quagga
  Copyright (C) 2008  Everton da Silva Marques

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA
*/

#ifndef PIM_UPSTREAM_H
#define PIM_UPSTREAM_H

#include <zebra.h>

#define PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED         (1 << 0)
#define PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED (2 << 0)

#define PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED_UPDATED(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)

#define PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED_UPDATED(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)

#define PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED_UPDATED(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)

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
  struct interface *interface;              /* RPF_interface(S) */
  struct in_addr    mrib_nexthop_addr;      /* MRIB.next_hop(S) */
  uint32_t          mrib_metric_preference; /* MRIB.pref(S) */
  uint32_t          mrib_route_metric;      /* MRIB.metric(S) */
};

struct pim_rpf {
  struct pim_nexthop source_nexthop;
  struct in_addr     rpf_addr;               /* RPF'(S,G) */
};

enum pim_rpf_result {
  PIM_RPF_OK = 0,
  PIM_RPF_CHANGED,
  PIM_RPF_FAILURE
};

enum pim_upstream_state {
  PIM_UPSTREAM_NOTJOINED,
  PIM_UPSTREAM_JOINED
};

enum pim_upstream_sptbit {
  PIM_UPSTREAM_SPTBIT_FALSE,
  PIM_UPSTREAM_SPTBIT_TRUE
};

/*
  Upstream (S,G) channel in Joined state
  
  (S,G) in the "Not Joined" state is not represented
  
  See RFC 4601: 4.5.7.  Sending (S,G) Join/Prune Message
*/
struct pim_upstream {
  struct in_addr           upstream_addr;/* Who we are talking to */
  struct in_addr           source_addr;  /* (S,G) source key */
  struct in_addr           group_addr;   /* (S,G) group key */
  uint32_t                 flags;
  struct channel_oil      *channel_oil;

  enum pim_upstream_state  join_state;
  enum pim_upstream_sptbit sptbit;

  int                      ref_count;

  struct pim_rpf           rpf;

  struct thread           *t_join_timer;

  /*
   * KAT(S,G)
   */
  struct thread           *t_ka_timer;
#define PIM_KEEPALIVE_PERIOD  (210)
#define PIM_RP_KEEPALIVE_PERIOD ( 3 * qpim_register_suppress_time + qpim_register_probe_time )

  int64_t                  state_transition; /* Record current state uptime */
};

void pim_upstream_free(struct pim_upstream *up);
void pim_upstream_delete(struct pim_upstream *up);
struct pim_upstream *pim_upstream_find(struct in_addr source_addr,
				       struct in_addr group_addr);
struct pim_upstream *pim_upstream_add(struct in_addr source_addr,
				      struct in_addr group_addr,
				      struct interface *ifp);
void pim_upstream_del(struct pim_upstream *up);

int pim_upstream_evaluate_join_desired(struct pim_upstream *up);
void pim_upstream_update_join_desired(struct pim_upstream *up);

void pim_upstream_join_suppress(struct pim_upstream *up,
				struct in_addr rpf_addr,
				int holdtime);
void pim_upstream_join_timer_decrease_to_t_override(const char *debug_label,
						    struct pim_upstream *up,
						    struct in_addr rpf_addr);
void pim_upstream_join_timer_restart(struct pim_upstream *up);
void pim_upstream_rpf_genid_changed(struct in_addr neigh_addr);
void pim_upstream_rpf_interface_changed(struct pim_upstream *up,
					struct interface *old_rpf_ifp);

void pim_upstream_update_could_assert(struct pim_upstream *up);
void pim_upstream_update_my_assert_metric(struct pim_upstream *up);

void pim_upstream_keep_alive_timer_start (struct pim_upstream *up, uint32_t time);

int pim_upstream_switch_to_spt_desired (struct in_addr source, struct in_addr group);
#define SwitchToSptDesired(S,G) pim_upstream_switch_to_spt_desired ((S), (G))

#endif /* PIM_UPSTREAM_H */
