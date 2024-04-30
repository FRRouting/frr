// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_UPSTREAM_H
#define PIM_UPSTREAM_H

#include <zebra.h>
#include <prefix.h>
#include "plist.h"

#include "pim_rpf.h"
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
/* In the case of pim vxlan we prime the pump by registering the
 * vxlan source and keeping the SPT (FHR-RP) alive by sending periodic
 * NULL registers. So we need to prevent KAT expiry because of the
 * lack of BUM traffic.
 */
#define PIM_UPSTREAM_FLAG_MASK_DISABLE_KAT_EXPIRY      (1 << 9)
/* for pim vxlan we need to pin the IIF to lo or MLAG-ISL on the
 * originating VTEP. This flag allows that by setting IIF to the
 * value specified and preventing next-hop-tracking on the entry
 */
#define PIM_UPSTREAM_FLAG_MASK_STATIC_IIF              (1 << 10)
#define PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL        (1 << 11)
/* Disable pimreg encasulation for a flow */
#define PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA          (1 << 12)
/* For some MDTs we need to register the router as a source even
 * if the not DR or directly connected on the IIF. This is typically
 * needed on a VxLAN-AA (MLAG) setup.
 */
#define PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG            (1 << 13)
/* VxLAN origination mroute - SG was registered by EVPN where S is the
 * local VTEP IP and G is the BUM multicast group address
 */
#define PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG          (1 << 14)
/* VxLAN termination mroute - *G entry where G is the BUM multicast group
 * address
 */
#define PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM          (1 << 15)
/* MLAG mroute - synced to the MLAG peer and subject to DF (designated
 * forwarder) election
 */
#define PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN              (1 << 16)
/* MLAG mroute that lost the DF election with peer and is installed in
 * a dormant state i.e. MLAG OIFs are removed from the MFC.
 * In most cases the OIL is empty (but not not always) simply
 * blackholing the traffic pulled down to the LHR.
 */
#define PIM_UPSTREAM_FLAG_MASK_MLAG_NON_DF             (1 << 17)
/* MLAG mroute rxed from the peer MLAG switch */
#define PIM_UPSTREAM_FLAG_MASK_MLAG_PEER               (1 << 18)
/*
 * We are creating a non-joined upstream data structure
 * for this S,G as that we want to have a channel oil
 * associated with an upstream
 */
#define PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE             (1 << 19)
/* By default as SG entry will use the SPT for forwarding traffic
 * unless it was setup as a result of a Prune(S,G,rpt) from a
 * downstream router and has JoinDesired(S,G) as False.
 * This flag is only relevant for (S,G) entries.
 */
#define PIM_UPSTREAM_FLAG_MASK_USE_RPT                 (1 << 20)
/* PIM Syncs upstream entries to peer Nodes via MLAG in 2 cases.
 * one is to support plain PIM Redundancy and another one is to support
 * PIM REdundancy.
 */
#define PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE          (1 << 21)


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
#define PIM_UPSTREAM_FLAG_TEST_DISABLE_KAT_EXPIRY(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_DISABLE_KAT_EXPIRY)
#define PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_STATIC_IIF)
#define PIM_UPSTREAM_FLAG_TEST_ALLOW_IIF_IN_OIL(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL)
#define PIM_UPSTREAM_FLAG_TEST_NO_PIMREG_DATA(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA)
#define PIM_UPSTREAM_FLAG_TEST_FORCE_PIMREG(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG)
#define PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG)
#define PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_TERM(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM)
#define PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN(flags) ((flags) & (PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG | PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM))
#define PIM_UPSTREAM_FLAG_TEST_MLAG_VXLAN(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN)
#define PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_MLAG_NON_DF)
#define PIM_UPSTREAM_FLAG_TEST_MLAG_PEER(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_MLAG_PEER)
#define PIM_UPSTREAM_FLAG_TEST_SRC_NOCACHE(flags) ((flags) &PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE)
#define PIM_UPSTREAM_FLAG_TEST_USE_RPT(flags) ((flags) & PIM_UPSTREAM_FLAG_MASK_USE_RPT)
#define PIM_UPSTREAM_FLAG_TEST_CAN_BE_LHR(flags) ((flags) & (PIM_UPSTREAM_FLAG_MASK_SRC_IGMP | PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM))
#define PIM_UPSTREAM_FLAG_TEST_MLAG_INTERFACE(flags) ((flags)&PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE)

#define PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED_UPDATED(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)
#define PIM_UPSTREAM_FLAG_SET_FHR(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_FHR)
#define PIM_UPSTREAM_FLAG_SET_SRC_IGMP(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
#define PIM_UPSTREAM_FLAG_SET_SRC_PIM(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_PIM)
#define PIM_UPSTREAM_FLAG_SET_SRC_STREAM(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_STREAM)
#define PIM_UPSTREAM_FLAG_SET_SRC_MSDP(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_MSDP)
#define PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE)
#define PIM_UPSTREAM_FLAG_SET_SRC_LHR(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_LHR)
#define PIM_UPSTREAM_FLAG_SET_DISABLE_KAT_EXPIRY(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_DISABLE_KAT_EXPIRY)
#define PIM_UPSTREAM_FLAG_SET_STATIC_IIF(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_STATIC_IIF)
#define PIM_UPSTREAM_FLAG_SET_ALLOW_IIF_IN_OIL(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL)
#define PIM_UPSTREAM_FLAG_SET_NO_PIMREG_DATA(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA)
#define PIM_UPSTREAM_FLAG_SET_FORCE_PIMREG(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG)
#define PIM_UPSTREAM_FLAG_SET_SRC_VXLAN_ORIG(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG)
#define PIM_UPSTREAM_FLAG_SET_SRC_VXLAN_TERM(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM)
#define PIM_UPSTREAM_FLAG_SET_MLAG_VXLAN(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN)
#define PIM_UPSTREAM_FLAG_SET_MLAG_NON_DF(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_MLAG_NON_DF)
#define PIM_UPSTREAM_FLAG_SET_MLAG_PEER(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_MLAG_PEER)
#define PIM_UPSTREAM_FLAG_SET_USE_RPT(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_USE_RPT)
#define PIM_UPSTREAM_FLAG_SET_MLAG_INTERFACE(flags) ((flags) |= PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE)

#define PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED)
#define PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED_UPDATED(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED)
#define PIM_UPSTREAM_FLAG_UNSET_FHR(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_FHR)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_IGMP(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_PIM(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_PIM)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_STREAM(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_STREAM)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_MSDP(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_MSDP)
#define PIM_UPSTREAM_FLAG_UNSET_SEND_SG_RPT_PRUNE(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_LHR(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_LHR)
#define PIM_UPSTREAM_FLAG_UNSET_DISABLE_KAT_EXPIRY(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_DISABLE_KAT_EXPIRY)
#define PIM_UPSTREAM_FLAG_UNSET_STATIC_IIF(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_STATIC_IIF)
#define PIM_UPSTREAM_FLAG_UNSET_ALLOW_IIF_IN_OIL(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL)
#define PIM_UPSTREAM_FLAG_UNSET_NO_PIMREG_DATA(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA)
#define PIM_UPSTREAM_FLAG_UNSET_FORCE_PIMREG(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_VXLAN_ORIG(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_VXLAN_TERM(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM)
#define PIM_UPSTREAM_FLAG_UNSET_MLAG_VXLAN(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN)
#define PIM_UPSTREAM_FLAG_UNSET_MLAG_NON_DF(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_MLAG_NON_DF)
#define PIM_UPSTREAM_FLAG_UNSET_MLAG_PEER(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_MLAG_PEER)
#define PIM_UPSTREAM_FLAG_UNSET_SRC_NOCACHE(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE)
#define PIM_UPSTREAM_FLAG_UNSET_USE_RPT(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_USE_RPT)
#define PIM_UPSTREAM_FLAG_UNSET_MLAG_INTERFACE(flags) ((flags) &= ~PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE)

/* The RPF cost is incremented by 10 if the RPF interface is the peerlink-rif.
 * This is used to force the MLAG switch with the lowest cost to the RPF
 * to become the MLAG DF.
 */
#define PIM_UPSTREAM_MLAG_PEERLINK_PLUS_METRIC 10

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

struct pim_up_mlag {
	/* MRIB.metric(S) from the peer switch. This is used for DF election
	 * and switch with the lowest cost wins.
	 */
	uint32_t peer_mrib_metric;
};

PREDECL_RBTREE_UNIQ(rb_pim_upstream);
/*
  Upstream (S,G) channel in Joined state
  (S,G) in the "Not Joined" state is not represented
  See RFC 4601: 4.5.7.  Sending (S,G) Join/Prune Message

  upstream_addr : Who we are talking to.
  For (*, G), upstream_addr is RP address or INADDR_ANY(if RP not configured)
  For (S, G), upstream_addr is source address

  rpf: contains the nexthop information to whom we are talking to.

  join_state: JOINED/NOTJOINED

  In the case when FRR receives IGMP/PIM (*, G) join for group G and RP is not
  configured, then create a pim_upstream with the below information.
  pim_upstream->upstream address: INADDR_ANY
  pim_upstream->rpf: Unknown
  pim_upstream->state: NOTJOINED

  When a new RP gets configured for G, find the corresponding pim upstream (*,G)
  entries and update the upstream address as new RP address if it the better one
  for the group G.

  When RP becomes reachable, populate the nexthop information in
  pim_upstream->rpf and update the state to JOINED.

*/
struct pim_upstream {
	struct pim_instance *pim;
	struct rb_pim_upstream_item upstream_rb;
	struct pim_upstream *parent;
	pim_addr upstream_addr;		  /* Who we are talking to */
	pim_addr upstream_register;       /*Who we received a register from*/
	pim_sgaddr sg;			  /* (S,G) group key */
	char sg_str[PIM_SG_LEN];
	uint32_t flags;
	struct channel_oil *channel_oil;
	struct list *sources;
	struct list *ifchannels;
	/* Counter for Dual active ifchannels*/
	uint32_t dualactive_ifchannel_count;

	enum pim_upstream_state join_state;
	enum pim_reg_state reg_state;
	enum pim_upstream_sptbit sptbit;

	int ref_count;

	struct pim_rpf rpf;

	struct pim_up_mlag mlag;

	struct event *t_join_timer;

	/*
	 * RST(S,G)
	 */
	struct event *t_rs_timer;
#define PIM_REGISTER_SUPPRESSION_PERIOD (60)
#define PIM_REGISTER_PROBE_PERIOD        (5)

	/*
	 * KAT(S,G)
	 */
	struct event *t_ka_timer;
#define PIM_KEEPALIVE_PERIOD  (210)
#define PIM_RP_KEEPALIVE_PERIOD                                                \
	(3 * router->register_suppress_time + router->register_probe_time)

	/* on the RP we restart a timer to indicate if registers are being rxed
	 * for
	 * SG. This is needed by MSDP to determine its local SA cache */
	struct event *t_msdp_reg_timer;
#define PIM_MSDP_REG_RXED_PERIOD (3 * (1.5 * router->register_suppress_time))

	int64_t state_transition; /* Record current state uptime */
};

static inline bool pim_upstream_is_kat_running(struct pim_upstream *up)
{
	return (up->t_ka_timer != NULL);
}

static inline bool pim_up_mlag_is_local(struct pim_upstream *up)
{
	/* XXX: extend this to also return true if the channel-oil has
	 * any AA devices
	 */
	return (up->flags & (PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN
			     | PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE));
}

struct pim_upstream *pim_upstream_find(struct pim_instance *pim,
				       pim_sgaddr *sg);
struct pim_upstream *pim_upstream_find_or_add(pim_sgaddr *sg,
					      struct interface *ifp, int flags,
					      const char *name);
struct pim_upstream *pim_upstream_add(struct pim_instance *pim, pim_sgaddr *sg,
				      struct interface *ifp, int flags,
				      const char *name,
				      struct pim_ifchannel *ch);
void pim_upstream_ref(struct pim_upstream *up,
		int flags, const char *name);
struct pim_upstream *pim_upstream_del(struct pim_instance *pim,
				      struct pim_upstream *up,
				      const char *name);

bool pim_upstream_evaluate_join_desired(struct pim_instance *pim,
					struct pim_upstream *up);
int pim_upstream_evaluate_join_desired_interface(struct pim_upstream *up,
						 struct pim_ifchannel *ch,
						 struct pim_ifchannel *starch);
int pim_upstream_eval_inherit_if(struct pim_upstream *up,
						 struct pim_ifchannel *ch,
						 struct pim_ifchannel *starch);
void pim_upstream_update_join_desired(struct pim_instance *pim,
				      struct pim_upstream *up);

void pim_update_suppress_timers(uint32_t suppress_time);
void pim_upstream_join_suppress(struct pim_upstream *up, pim_addr rpf,
				int holdtime);

void pim_upstream_join_timer_decrease_to_t_override(const char *debug_label,
						    struct pim_upstream *up);

void pim_upstream_join_timer_restart(struct pim_upstream *up,
				     struct pim_rpf *old);
void pim_upstream_rpf_genid_changed(struct pim_instance *pim,
				    pim_addr neigh_addr);
void pim_upstream_rpf_interface_changed(struct pim_upstream *up,
					struct interface *old_rpf_ifp);

void pim_upstream_update_could_assert(struct pim_upstream *up);
void pim_upstream_update_my_assert_metric(struct pim_upstream *up);

void pim_upstream_keep_alive_timer_start(struct pim_upstream *up,
					 uint32_t time);

int pim_upstream_switch_to_spt_desired_on_rp(struct pim_instance *pim,
					     pim_sgaddr *sg);
#define SwitchToSptDesiredOnRp(pim, sg) pim_upstream_switch_to_spt_desired_on_rp (pim, sg)
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
const char *pim_reg_state2str(enum pim_reg_state state, char *state_str,
			      size_t state_str_len);

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
int pim_upstream_compare(const struct pim_upstream *up1,
			 const struct pim_upstream *up2);
DECLARE_RBTREE_UNIQ(rb_pim_upstream, struct pim_upstream, upstream_rb,
		    pim_upstream_compare);

void pim_upstream_register_reevaluate(struct pim_instance *pim);

void pim_upstream_add_lhr_star_pimreg(struct pim_instance *pim);
void pim_upstream_remove_lhr_star_pimreg(struct pim_instance *pim,
					 const char *nlist);

void pim_upstream_spt_prefix_list_update(struct pim_instance *pim,
					 struct prefix_list *pl);

unsigned int pim_upstream_hash_key(const void *arg);
bool pim_upstream_equal(const void *arg1, const void *arg2);
struct pim_upstream *pim_upstream_keep_alive_timer_proc(
		struct pim_upstream *up);
void pim_upstream_fill_static_iif(struct pim_upstream *up,
				struct interface *incoming);
void pim_upstream_update_use_rpt(struct pim_upstream *up,
		bool update_mroute);
uint32_t pim_up_mlag_local_cost(struct pim_upstream *up);
uint32_t pim_up_mlag_peer_cost(struct pim_upstream *up);
void pim_upstream_reeval_use_rpt(struct pim_instance *pim);
int pim_upstream_could_register(struct pim_upstream *up);
bool pim_sg_is_reevaluate_oil_req(struct pim_instance *pim,
				  struct pim_upstream *up);
#endif /* PIM_UPSTREAM_H */
