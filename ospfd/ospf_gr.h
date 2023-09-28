// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF Graceful Restart helper functions.
 *
 * Copyright (C) 2020-21 Vmware, Inc.
 * Rajesh Kumar Girada
 */

#ifndef _ZEBRA_OSPF_GR_H
#define _ZEBRA_OSPF_GR_H

#define OSPF_GR_NOT_HELPER 0
#define OSPF_GR_ACTIVE_HELPER 1

#define OSPF_GR_HELPER_NO_LSACHECK 0
#define OSPF_GR_HELPER_LSACHECK 1

#define OSPF_MAX_GRACE_INTERVAL 1800
#define OSPF_MIN_GRACE_INTERVAL 1
#define OSPF_DFLT_GRACE_INTERVAL 120

enum ospf_helper_exit_reason {
	OSPF_GR_HELPER_EXIT_NONE = 0,
	OSPF_GR_HELPER_INPROGRESS,
	OSPF_GR_HELPER_TOPO_CHG,
	OSPF_GR_HELPER_GRACE_TIMEOUT,
	OSPF_GR_HELPER_COMPLETED
};

enum ospf_gr_restart_reason {
	OSPF_GR_UNKNOWN_RESTART = 0,
	OSPF_GR_SW_RESTART = 1,
	OSPF_GR_SW_UPGRADE = 2,
	OSPF_GR_SWITCH_REDUNDANT_CARD = 3,
	OSPF_GR_INVALID_REASON_CODE = 4
};

enum ospf_gr_helper_rejected_reason {
	OSPF_HELPER_REJECTED_NONE,
	OSPF_HELPER_SUPPORT_DISABLED,
	OSPF_HELPER_NOT_A_VALID_NEIGHBOUR,
	OSPF_HELPER_PLANNED_ONLY_RESTART,
	OSPF_HELPER_TOPO_CHANGE_RTXMT_LIST,
	OSPF_HELPER_LSA_AGE_MORE,
	OSPF_HELPER_RESTARTING,
};

/* Ref RFC3623 appendex-A */
/* Grace period TLV */
#define GRACE_PERIOD_TYPE 1
#define GRACE_PERIOD_LENGTH 4

struct grace_tlv_graceperiod {
	struct tlv_header header;
	uint32_t interval;
};

/* Restart reason TLV */
#define RESTART_REASON_TYPE 2
#define RESTART_REASON_LENGTH 1

struct grace_tlv_restart_reason {
	struct tlv_header header;
	uint8_t reason;
	uint8_t reserved[3];
};

/* Restarter ip address TLV */
#define RESTARTER_IP_ADDR_TYPE 3
#define RESTARTER_IP_ADDR_LEN 4

struct grace_tlv_restart_addr {
	struct tlv_header header;
	struct in_addr addr;
};

struct ospf_helper_info {

	/* Grace interval received from
	 * Restarting Router.
	 */
	uint32_t recvd_grace_period;

	/* Grace interval used for grace
	 * gracetimer.
	 */
	uint32_t actual_grace_period;

	/* Grace timer,This Router acts as
	 * helper until this timer until
	 * this timer expires.
	 */
	struct event *t_grace_timer;

	/* Helper status */
	uint32_t gr_helper_status;

	/* Helper exit reason*/
	enum ospf_helper_exit_reason helper_exit_reason;

	/* Planned/Unplanned restart*/
	enum ospf_gr_restart_reason  gr_restart_reason;

	/* Helper rejected reason */
	enum ospf_gr_helper_rejected_reason rejected_reason;
};

struct advRtr {
	struct in_addr advRtrAddr;
};

#define OSPF_HELPER_ENABLE_RTR_COUNT(ospf) (ospf->enable_rtr_list->count)

/* Check for planned restart */
#define OSPF_GR_IS_PLANNED_RESTART(reason)                                     \
	((reason == OSPF_GR_SW_RESTART) || (reason == OSPF_GR_SW_UPGRADE))

/* Check the router is HELPER for current neighbour */
#define OSPF_GR_IS_ACTIVE_HELPER(N)                                                         \
	((N)->gr_helper_info.gr_helper_status == OSPF_GR_ACTIVE_HELPER)

/* Check the LSA is GRACE LSA */
#define IS_GRACE_LSA(lsa)                                                      \
	((lsa->data->type == OSPF_OPAQUE_LINK_LSA)                             \
	 && (GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr))                      \
	     == OPAQUE_TYPE_GRACE_LSA))

/* Check neighbour is in FULL state */
#define IS_NBR_STATE_FULL(nbr) (nsm_should_adj(nbr) && (nbr->state == NSM_Full))

/* Check neighbour is DR_OTHER and state is 2_WAY */
#define IS_NBR_STATE_2_WAY_WITH_DROTHER(nbr)                                   \
	((ospf_get_nbr_ism_role(nbr) == ISM_DROther)                           \
	 && (nbr->state == NSM_TwoWay))

#define OSPF_GR_FALSE false
#define OSPF_GR_TRUE true

#define OSPF_GR_SUCCESS 1
#define OSPF_GR_FAILURE 0
#define OSPF_GR_INVALID -1

const char *ospf_exit_reason2str(unsigned int reason);
const char *ospf_restart_reason2str(unsigned int reason);
const char *ospf_rejected_reason2str(unsigned int reason);

extern void ospf_gr_helper_instance_init(struct ospf *ospf);
extern void ospf_gr_helper_instance_stop(struct ospf *ospf);
extern void ospf_gr_helper_init(void);
extern void ospf_gr_helper_stop(void);
extern int ospf_process_grace_lsa(struct ospf *ospf, struct ospf_lsa *lsa,
				  struct ospf_neighbor *nbr);
extern void ospf_gr_helper_exit(struct ospf_neighbor *nbr,
				enum ospf_helper_exit_reason reason);
extern void ospf_process_maxage_grace_lsa(struct ospf *ospf,
					  struct ospf_lsa *lsa,
					  struct ospf_neighbor *nbr);
extern void ospf_helper_handle_topo_chg(struct ospf *ospf,
					struct ospf_lsa *lsa);
extern void ospf_gr_helper_support_set(struct ospf *ospf, bool support);
extern void ospf_gr_helper_support_set_per_routerid(struct ospf *ospf,
						    struct in_addr *rid,
						    bool support);
extern void ospf_gr_helper_lsa_check_set(struct ospf *ospf, bool lsacheck);
extern void ospf_gr_helper_supported_gracetime_set(struct ospf *ospf,
						   uint32_t interval);
extern void ospf_gr_helper_set_supported_planned_only_restart(struct ospf *ospf,
							     bool planned_only);
extern void ospf_gr_iface_send_grace_lsa(struct event *thread);
extern void ospf_gr_restart_enter(struct ospf *ospf,
				  enum ospf_gr_restart_reason reason,
				  time_t timestamp);
extern void ospf_gr_check_lsdb_consistency(struct ospf *ospf,
						  struct ospf_area *area);
extern void ospf_gr_check_adjs(struct ospf *ospf);
extern void ospf_gr_nvm_read(struct ospf *ospf);
extern void ospf_gr_nvm_delete(struct ospf *ospf);
extern void ospf_gr_unplanned_start_interface(struct ospf_interface *oi);
extern void ospf_gr_init(void);

#endif /* _ZEBRA_OSPF_GR_H */
