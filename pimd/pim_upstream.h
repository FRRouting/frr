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

#ifndef PIM_UPSTREAM_H
#define PIM_UPSTREAM_H

#include <zebra.h>
#include <prefix.h>
#include "plist.h"

#include <pimd/pim_rpf.h>
#include "pim_str.h"
#include "pim_ifchannel.h"

#define PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED         (1 << 0)
#define PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED (1 << 1)
#define PIM_UPSTREAM_FLAG_MASK_FHR                     (1 << 2)
#define PIM_UPSTREAM_FLAG_MASK_SRC_IGMP                (1 << 3)
#define PIM_UPSTREAM_FLAG_MASK_SRC_PIM                 (1 << 4)
#define PIM_UPSTREAM_FLAG_MASK_SRC_STREAM              (1 << 5)
#define PIM_UPSTREAM_FLAG_MASK_SRC_MSDP                (1 << 6)
#define PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE       (1 << 7)
#define PIM_UPSTREAM_FLAG_MASK_SRC_LHR                 (1 << 8)
#define PIM_UPSTREAM_FLAG_ALL 0xFFFFFFFF

#define PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED_UPDATED(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)
#define PIM_UPSTREAM_FLAG_TEST_FHR(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_FHR)
#define PIM_UPSTREAM_FLAG_TEST_SRC_IGMP(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
#define PIM_UPSTREAM_FLAG_TEST_SRC_PIM(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_PIM)
#define PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_STREAM)
#define PIM_UPSTREAM_FLAG_TEST_SRC_MSDP(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_MSDP)
#define PIM_UPSTREAM_FLAG_TEST_SEND_SG_RPT_PRUNE(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE)
#define PIM_UPSTREAM_FLAG_TEST_SRC_LHR(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_LHR)

#define PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED_UPDATED(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)
#define PIM_UPSTREAM_FLAG_SET_FHR(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_FHR)
#define PIM_UPSTREAM_FLAG_SET_SRC_IGMP(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
#define PIM_UPSTREAM_FLAG_SET_SRC_PIM(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_PIM)
#define PIM_UPSTREAM_FLAG_SET_SRC_STREAM(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_STREAM)
#define PIM_UPSTREAM_FLAG_SET_SRC_MSDP(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_MSDP)
#define PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE)
#define PIM_UPSTREAM_FLAG_SET_SRC_LHR(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_LHR)

#define PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED_UPDATED(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)
#define PIM_UPSTREAM_FLAG_UNSET_FHR(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_FHR)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_IGMP(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_PIM(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_PIM)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_STREAM(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_STREAM)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_MSDP(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_MSDP)
#define PIM_UPSTREAM_FLAG_UNSET_SEND_SG_RPT_PRUNE(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_LHR(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_LHR)

enum pim_upstream_state {
	PIM_UPSTREAM_NOTJOINED,
	PIM_UPSTREAM_JOINED,
};

enum pim_reg_state {
	PIM_REG_NOINFO,
	PIM_REG_JOIN,
	PIM_REG_JOIN_PENDING,
	PIM_REG_PRUNE,
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
	struct pim_upstream *parent;
	struct in_addr upstream_addr;     /* Who we are talking to */
	struct in_addr upstream_register; /*Who we received a register from*/
	struct prefix_sg sg;		  /* (S,G) group key */
	char sg_str[PIM_SG_LEN];
	uint32_t flags;
	struct channel_oil *channel_oil;
	struct list *sources;
	struct list *ifchannels;

	enum pim_upstream_state join_state;
	enum pim_reg_state reg_state;
	enum pim_upstream_sptbit sptbit;

	int ref_count;

	struct pim_rpf rpf;

	struct thread *t_join_timer;

	/*
	 * RST(S,G)
	 */
	struct thread *t_rs_timer;
#define PIM_REGISTER_SUPPRESSION_PERIOD (60)
#define PIM_REGISTER_PROBE_PERIOD        (5)

	/*
	 * KAT(S,G)
	 */
	struct thread *t_ka_timer;
#define PIM_KEEPALIVE_PERIOD  (210)
#define PIM_RP_KEEPALIVE_PERIOD ( 3 * qpim_register_suppress_time + qpim_register_probe_time )

	/* on the RP we restart a timer to indicate if registers are being rxed
	 * for
	 * SG. This is needed by MSDP to determine its local SA cache */
	struct thread *t_msdp_reg_timer;
#define PIM_MSDP_REG_RXED_PERIOD (3 * (1.5 * qpim_register_suppress_time))

	int64_t state_transition; /* Record current state uptime */
};

struct pim_upstream *pim_upstream_find(struct pim_instance *pim,
				       struct prefix_sg *sg);
struct pim_upstream *pim_upstream_find_or_add(struct prefix_sg *sg,
					      struct interface *ifp, int flags,
					      const char *name);
struct pim_upstream *pim_upstream_add(struct pim_instance *pim,
				      struct prefix_sg *sg,
				      struct interface *ifp, int flags,
				      const char *name,
				      struct pim_ifchannel *ch);
void pim_upstream_ref(struct pim_upstream *up, int flags, const char *name);
struct pim_upstream *pim_upstream_del(struct pim_instance *pim,
				      struct pim_upstream *up,
				      const char *name);

int pim_upstream_evaluate_join_desired(struct pim_instance *pim,
				       struct pim_upstream *up);
int pim_upstream_evaluate_join_desired_interface(struct pim_upstream *up,
						 struct pim_ifchannel *ch,
						 struct pim_ifchannel *starch);
void pim_upstream_update_join_desired(struct pim_instance *pim,
				      struct pim_upstream *up);

void pim_upstream_join_suppress(struct pim_upstream *up,
				struct in_addr rpf_addr, int holdtime);

void pim_upstream_join_timer_decrease_to_t_override(const char *debug_label,
						    struct pim_upstream *up);

void pim_upstream_join_timer_restart(struct pim_upstream *up,
				     struct pim_rpf *old);
void pim_upstream_rpf_genid_changed(struct pim_instance *pim,
				    struct in_addr neigh_addr);
void pim_upstream_rpf_interface_changed(struct pim_upstream *up,
					struct interface *old_rpf_ifp);

void pim_upstream_update_could_assert(struct pim_upstream *up);
void pim_upstream_update_my_assert_metric(struct pim_upstream *up);

void pim_upstream_keep_alive_timer_start(struct pim_upstream *up,
					 uint32_t time);

int pim_upstream_switch_to_spt_desired(struct pim_instance *pim,
				       struct prefix_sg *sg);
#define SwitchToSptDesired(pim, sg) pim_upstream_switch_to_spt_desired (pim, sg)
int pim_upstream_is_sg_rpt(struct pim_upstream *up);

void pim_upstream_set_sptbit(struct pim_upstream *up,
			     struct interface *incoming);

void pim_upstream_start_register_stop_timer(struct pim_upstream *up,
					    int null_register);

void pim_upstream_send_join(struct pim_upstream *up);

void pim_upstream_switch(struct pim_instance *pim, struct pim_upstream *up,
			 enum pim_upstream_state new_state);

const char *pim_upstream_state2str(enum pim_upstream_state join_state);
#define PIM_REG_STATE_STR_LEN 12
const char *pim_reg_state2str(enum pim_reg_state state, char *state_str);

int pim_upstream_inherited_olist_decide(struct pim_instance *pim,
					struct pim_upstream *up);
int pim_upstream_inherited_olist(struct pim_instance *pim,
				 struct pim_upstream *up);
int pim_upstream_empty_inherited_olist(struct pim_upstream *up);

void pim_upstream_find_new_rpf(struct pim_instance *pim);
void pim_upstream_msdp_reg_timer_start(struct pim_upstream *up);

void pim_upstream_init(struct pim_instance *pim);
void pim_upstream_terminate(struct pim_instance *pim);

void join_timer_start(struct pim_upstream *up);
int pim_upstream_compare(void *arg1, void *arg2);
void pim_upstream_register_reevaluate(struct pim_instance *pim);

void pim_upstream_add_lhr_star_pimreg(struct pim_instance *pim);
void pim_upstream_remove_lhr_star_pimreg(struct pim_instance *pim,
					 const char *nlist);

void pim_upstream_spt_prefix_list_update(struct pim_instance *pim,
					 struct prefix_list *pl);

unsigned int pim_upstream_hash_key(void *arg);
int pim_upstream_equal(const void *arg1, const void *arg2);
#endif /* PIM_UPSTREAM_H */
