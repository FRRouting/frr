// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_IFACE_H
#define PIM_IFACE_H

#include <zebra.h>

#include "if.h"
#include "vty.h"
#include "vrf.h"
#include "zclient.h"
#include "ferr.h"

#include "pim_igmp.h"
#include "pim_upstream.h"
#include "bfd.h"
#include "pim_str.h"

#define PIM_IF_IS_DELETED(ifp) ((ifp)->ifindex == IFINDEX_INTERNAL)

#define PIM_I_am_DR(pim_ifp)                                                   \
	!pim_addr_cmp((pim_ifp)->pim_dr_addr, (pim_ifp)->primary_address)
#define PIM_I_am_DualActive(pim_ifp) (pim_ifp)->activeactive == true

/* Macros for interface flags */

/*
 * PIM needs to know if hello is required to send before other PIM messages
 * like Join, prune, assert would go out
 */
#define PIM_IF_FLAG_HELLO_SENT (1 << 0)

#define PIM_IF_FLAG_TEST_HELLO_SENT(flags) ((flags)&PIM_IF_FLAG_HELLO_SENT)

#define PIM_IF_FLAG_SET_HELLO_SENT(flags) ((flags) |= PIM_IF_FLAG_HELLO_SENT)

#define PIM_IF_FLAG_UNSET_HELLO_SENT(flags) ((flags) &= ~PIM_IF_FLAG_HELLO_SENT)

struct pim_iface_upstream_switch {
	pim_addr address;
	struct list *us;
};

enum pim_secondary_addr_flags {
	PIM_SEC_ADDRF_NONE = 0,
	PIM_SEC_ADDRF_STALE = (1 << 0)
};

struct pim_secondary_addr {
	struct prefix addr;
	enum pim_secondary_addr_flags flags;
};

struct gm_if;

struct pim_interface {
	bool pim_enable : 1;
	bool pim_can_disable_join_suppression : 1;
	bool pim_passive_enable : 1;

	bool gm_enable : 1;

	ifindex_t mroute_vif_index;
	struct pim_instance *pim;

#if PIM_IPV == 6
	/* link-locals: MLD uses lowest addr, PIM uses highest... */
	pim_addr ll_lowest;
	pim_addr ll_highest;
#endif

	pim_addr primary_address;       /* remember addr to detect change */
	struct list *sec_addr_list;     /* list of struct pim_secondary_addr */
	pim_addr update_source;		/* user can statically set the primary
					 * address of the interface */

	int igmp_version;		     /* IGMP version */
	int mld_version;
	int gm_default_robustness_variable;  /* IGMP or MLD QRV */
	int gm_default_query_interval;       /* IGMP or MLD secs between general
						  queries */
	int gm_query_max_response_time_dsec; /* IGMP or MLD Max Response Time in
						  dsecs for general queries */
	int gm_specific_query_max_response_time_dsec; /* IGMP or MLD Max
							 Response Time in dsecs
							 called as last member
							 query interval, defines
							 the maximum response
							 time advertised in IGMP
							 group-specific
							 queries */
	int gm_last_member_query_count;		      /* IGMP or MLD last member
							 query count
						       */
	struct list *gm_socket_list; /* list of struct IGMP or MLD sock */
	struct list *gm_join_list;   /* list of struct IGMP or MLD join */
	struct list *gm_group_list;  /* list of struct IGMP or MLD group */
	struct hash *gm_group_hash;

	struct gm_if *mld;

	int pim_sock_fd;		/* PIM socket file descriptor */
	struct event *t_pim_sock_read;	/* thread for reading PIM socket */
	int64_t pim_sock_creation;      /* timestamp of PIM socket creation */

	struct event *t_pim_hello_timer;
	int pim_hello_period;
	int pim_default_holdtime;
	int pim_triggered_hello_delay;
	uint32_t pim_generation_id;
	uint16_t pim_propagation_delay_msec; /* config */
	uint16_t pim_override_interval_msec; /* config */
	struct list *pim_neighbor_list;      /* list of struct pim_neighbor */
	struct list *upstream_switch_list;
	struct pim_ifchannel_rb ifchannel_rb;

	/* neighbors without lan_delay */
	int pim_number_of_nonlandelay_neighbors;
	uint16_t pim_neighbors_highest_propagation_delay_msec;
	uint16_t pim_neighbors_highest_override_interval_msec;

	/* DR Election */
	int64_t pim_dr_election_last; /* timestamp */
	int pim_dr_election_count;
	int pim_dr_election_changes;
	pim_addr pim_dr_addr;
	uint32_t pim_dr_priority;	  /* config */
	int pim_dr_num_nondrpri_neighbors; /* neighbors without dr_pri */

	/* boundary prefix-list */
	char *boundary_oil_plist;

	/* Turn on Active-Active for this interface */
	bool activeactive;
	bool am_i_dr;

	int64_t pim_ifstat_start; /* start timestamp for stats */
	uint64_t pim_ifstat_bsm_rx;
	uint64_t pim_ifstat_bsm_tx;
	uint32_t pim_ifstat_hello_sent;
	uint32_t pim_ifstat_hello_sendfail;
	uint32_t pim_ifstat_hello_recv;
	uint32_t pim_ifstat_hello_recvfail;
	uint32_t pim_ifstat_join_recv;
	uint32_t pim_ifstat_join_send;
	uint32_t pim_ifstat_prune_recv;
	uint32_t pim_ifstat_prune_send;
	uint32_t pim_ifstat_reg_recv;
	uint32_t pim_ifstat_reg_send;
	uint32_t pim_ifstat_reg_stop_recv;
	uint32_t pim_ifstat_reg_stop_send;
	uint32_t pim_ifstat_assert_recv;
	uint32_t pim_ifstat_assert_send;
	uint32_t pim_ifstat_bsm_cfg_miss;
	uint32_t pim_ifstat_ucast_bsm_cfg_miss;
	uint32_t pim_ifstat_bsm_invalid_sz;
	uint8_t flags;
	bool bsm_enable; /* bsm processing enable */
	bool ucast_bsm_accept; /* ucast bsm processing */

	uint32_t igmp_ifstat_joins_sent;
	uint32_t igmp_ifstat_joins_failed;
	uint32_t igmp_peak_group_count;

	struct {
		bool enabled;
		uint32_t min_rx;
		uint32_t min_tx;
		uint8_t detection_multiplier;
		char *profile;
	} bfd_config;
};

/*
 * if default_holdtime is set (>= 0), use it;
 * otherwise default_holdtime is 3.5 * hello_period
 */
#define PIM_IF_DEFAULT_HOLDTIME(pim_ifp)                                       \
	(((pim_ifp)->pim_default_holdtime < 0)                                 \
		 ? ((pim_ifp)->pim_hello_period * 7 / 2)                       \
		 : ((pim_ifp)->pim_default_holdtime))

void pim_if_init(struct pim_instance *pim);
void pim_if_terminate(struct pim_instance *pim);

struct pim_interface *pim_if_new(struct interface *ifp, bool igmp, bool pim,
				 bool ispimreg, bool is_vxlan_term);
void pim_if_delete(struct interface *ifp);
void pim_if_addr_add(struct connected *ifc);
void pim_if_addr_del(struct connected *ifc, int force_prim_as_any);
void pim_if_addr_add_all(struct interface *ifp);
void pim_if_addr_del_all(struct interface *ifp);
void pim_if_addr_del_all_igmp(struct interface *ifp);

int pim_if_add_vif(struct interface *ifp, bool ispimreg, bool is_vxlan_term);
int pim_if_del_vif(struct interface *ifp);
void pim_if_add_vif_all(struct pim_instance *pim);
void pim_if_del_vif_all(struct pim_instance *pim);

struct interface *pim_if_find_by_vif_index(struct pim_instance *pim,
					   ifindex_t vif_index);
int pim_if_find_vifindex_by_ifindex(struct pim_instance *pim,
				    ifindex_t ifindex);

int pim_if_lan_delay_enabled(struct interface *ifp);
uint16_t pim_if_effective_propagation_delay_msec(struct interface *ifp);
uint16_t pim_if_effective_override_interval_msec(struct interface *ifp);
uint16_t pim_if_jp_override_interval_msec(struct interface *ifp);
struct pim_neighbor *pim_if_find_neighbor(struct interface *ifp, pim_addr addr);

long pim_if_t_suppressed_msec(struct interface *ifp);
int pim_if_t_override_msec(struct interface *ifp);

pim_addr pim_find_primary_addr(struct interface *ifp);

ferr_r pim_if_gm_join_add(struct interface *ifp, pim_addr group_addr,
			  pim_addr source_addr);
int pim_if_gm_join_del(struct interface *ifp, pim_addr group_addr,
		       pim_addr source_addr);

void pim_if_update_could_assert(struct interface *ifp);

void pim_if_assert_on_neighbor_down(struct interface *ifp, pim_addr neigh_addr);

void pim_if_rpf_interface_changed(struct interface *old_rpf_ifp,
				  struct pim_upstream *up);

void pim_if_update_join_desired(struct pim_interface *pim_ifp);

void pim_if_update_assert_tracking_desired(struct interface *ifp);

void pim_if_create_pimreg(struct pim_instance *pim);

struct prefix *pim_if_connected_to_source(struct interface *ifp, pim_addr src);
int pim_update_source_set(struct interface *ifp, pim_addr source);

bool pim_if_is_vrf_device(struct interface *ifp);

int pim_if_ifchannel_count(struct pim_interface *pim_ifp);

void pim_iface_init(void);
void pim_pim_interface_delete(struct interface *ifp);
void pim_gm_interface_delete(struct interface *ifp);

#endif /* PIM_IFACE_H */
