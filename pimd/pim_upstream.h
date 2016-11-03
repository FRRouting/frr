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
#include <prefix.h>

#include <pimd/pim_rpf.h>

#define PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED         (1 << 0)
#define PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED (1 << 1)
#define PIM_UPSTREAM_FLAG_MASK_FHR                     (1 << 2)
#define PIM_UPSTREAM_FLAG_MASK_SRC_IGMP                (1 << 3)
#define PIM_UPSTREAM_FLAG_MASK_SRC_PIM                 (1 << 4)
#define PIM_UPSTREAM_FLAG_MASK_SRC_STREAM              (1 << 5)
#define PIM_UPSTREAM_FLAG_MASK_CREATED_BY_UPSTREAM     (1 << 6)

#define PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED_UPDATED(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)
#define PIM_UPSTREAM_FLAG_TEST_FHR(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_FHR)
#define PIM_UPSTREAM_FLAG_TEST_SRC_IGMP(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
#define PIM_UPSTREAM_FLAG_TEST_SRC_PIM(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_PIM)
#define PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_STREAM)
#define PIM_UPSTREAM_FLAG_TEST_CREATED_BY_UPSTREAM(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_CREATED_BY_UPSTREAM)

#define PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED_UPDATED(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)
#define PIM_UPSTREAM_FLAG_SET_FHR(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_FHR)
#define PIM_UPSTREAM_FLAG_SET_SRC_IGMP(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
#define PIM_UPSTREAM_FLAG_SET_SRC_PIM(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_PIM)
#define PIM_UPSTREAM_FLAG_SET_SRC_STREAM(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_STREAM)
#define PIM_UPSTREAM_FLAG_SET_CREATED_BY_UPSTREAM(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_CREATED_BY_UPSTREAM)

#define PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED_UPDATED(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)
#define PIM_UPSTREAM_FLAG_UNSET_FHR(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_FHR)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_IGMP(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_PIM(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_PIM)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_STREAM(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_STREAM)
#define PIM_UPSTREAM_FLAG_UNSET_CREATED_BY_UPSTREAM(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_CREATED_BY_UPSTREAM)

enum pim_upstream_state {
  PIM_UPSTREAM_NOTJOINED,
  PIM_UPSTREAM_JOINED,
  PIM_UPSTREAM_JOIN_PENDING,
  PIM_UPSTREAM_PRUNE,
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
  struct pim_upstream      *parent;
  struct in_addr           upstream_addr;/* Who we are talking to */
  struct in_addr           upstream_register; /*Who we received a register from*/
  struct prefix_sg         sg;           /* (S,G) group key */
  uint32_t                 flags;
  struct channel_oil      *channel_oil;
  struct list             *sources;

  enum pim_upstream_state  join_state;
  enum pim_upstream_sptbit sptbit;

  int                      ref_count;

  struct pim_rpf           rpf;

  struct thread           *t_join_timer;

  /*
   * RST(S,G)
   */
  struct thread           *t_rs_timer;
#define PIM_REGISTER_SUPPRESSION_PERIOD (60)
#define PIM_REGISTER_PROBE_PERIOD        (5)

  /*
   * KAT(S,G)
   */
  struct thread           *t_ka_timer;
#define PIM_KEEPALIVE_PERIOD  (210)
#define PIM_RP_KEEPALIVE_PERIOD ( 3 * qpim_register_suppress_time + qpim_register_probe_time )

  int64_t                  state_transition; /* Record current state uptime */
};

struct list *pim_upstream_list;
struct hash *pim_upstream_hash;

void pim_upstream_free(struct pim_upstream *up);
struct pim_upstream *pim_upstream_find (struct prefix_sg *sg);
struct pim_upstream *pim_upstream_add (struct prefix_sg *sg,
				       struct interface *ifp, int flags,
				       const char *name);
void pim_upstream_del(struct pim_upstream *up, const char *name);

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

int pim_upstream_switch_to_spt_desired (struct prefix_sg *sg);
#define SwitchToSptDesired(sg) pim_upstream_switch_to_spt_desired (sg)
int pim_upstream_is_sg_rpt (struct pim_upstream *up);

void pim_upstream_set_sptbit (struct pim_upstream *up, struct interface *incoming);

void pim_upstream_start_register_stop_timer (struct pim_upstream *up, int null_register);

void pim_upstream_send_join (struct pim_upstream *up);

void pim_upstream_switch (struct pim_upstream *up, enum pim_upstream_state new_state);

const char *pim_upstream_state2str (enum pim_upstream_state join_state);

int pim_upstream_inherited_olist (struct pim_upstream *up);
int pim_upstream_empty_inherited_olist (struct pim_upstream *up);

void pim_upstream_find_new_rpf (void);

void pim_upstream_init (void);
void pim_upstream_terminate (void);
#endif /* PIM_UPSTREAM_H */
