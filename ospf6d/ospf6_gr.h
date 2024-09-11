// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF6 Graceful Restart helper functions.
 * Ref RFC 5187
 *
 * Copyright (C) 2021-22 Vmware, Inc.
 * Rajesh Kumar Girada
 */

#ifndef OSPF6_GR_H
#define OSPF6_GR_H

#define OSPF6_GR_NOT_HELPER 0
#define OSPF6_GR_ACTIVE_HELPER 1

#define OSPF6_GR_HELPER_NO_LSACHECK 0
#define OSPF6_GR_HELPER_LSACHECK 1

#define OSPF6_MAX_GRACE_INTERVAL 1800
#define OSPF6_MIN_GRACE_INTERVAL 1
#define OSPF6_DFLT_GRACE_INTERVAL 120

/* Forward declaration(s). */
struct ospf6_neighbor;

/* Debug option */
extern unsigned char conf_debug_ospf6_gr;

#define OSPF6_DEBUG_GR 0x01

#define OSPF6_DEBUG_GR_ON() (conf_debug_ospf6_gr |= OSPF6_DEBUG_GR)

#define OSPF6_DEBUG_GR_OFF() (conf_debug_ospf6_gr &= ~OSPF6_DEBUG_GR)

#define IS_DEBUG_OSPF6_GR conf_debug_ospf6_gr


enum ospf6_helper_exit_reason {
	OSPF6_GR_HELPER_EXIT_NONE = 0,
	OSPF6_GR_HELPER_INPROGRESS,
	OSPF6_GR_HELPER_TOPO_CHG,
	OSPF6_GR_HELPER_GRACE_TIMEOUT,
	OSPF6_GR_HELPER_COMPLETED
};

enum ospf6_gr_restart_reason {
	OSPF6_GR_UNKNOWN_RESTART = 0,
	OSPF6_GR_SW_RESTART = 1,
	OSPF6_GR_SW_UPGRADE = 2,
	OSPF6_GR_SWITCH_REDUNDANT_CARD = 3,
	OSPF6_GR_INVALID_REASON_CODE = 4
};

enum ospf6_gr_helper_rejected_reason {
	OSPF6_HELPER_REJECTED_NONE,
	OSPF6_HELPER_SUPPORT_DISABLED,
	OSPF6_HELPER_NOT_A_VALID_NEIGHBOUR,
	OSPF6_HELPER_PLANNED_ONLY_RESTART,
	OSPF6_HELPER_TOPO_CHANGE_RTXMT_LIST,
	OSPF6_HELPER_LSA_AGE_MORE,
	OSPF6_HELPER_RESTARTING,
};


#define GRACE_PERIOD_TLV_SIZE	      sizeof(struct tlv_grace_period)
#define GRACE_RESTART_REASON_TLV_SIZE sizeof(struct tlv_grace_restart_reason)

#define OSPF6_GRACE_LSA_MIN_SIZE                                               \
	GRACE_PERIOD_TLV_SIZE + GRACE_RESTART_REASON_TLV_SIZE

struct ospf6_grace_lsa {
	struct tlv_grace_period tlv_period;
	struct tlv_grace_restart_reason tlv_reason;
};

struct advRtr {
	in_addr_t advRtrAddr;
};

#define OSPF6_HELPER_ENABLE_RTR_COUNT(ospf)                                    \
	(ospf6->ospf6_helper_cfg.enable_rtr_list->count)

/* Check , it is a planned restart */
#define OSPF6_GR_IS_PLANNED_RESTART(reason)                                    \
	((reason == OSPF6_GR_SW_RESTART) || (reason == OSPF6_GR_SW_UPGRADE))

/* Check the router is HELPER for current neighbour */
#define OSPF6_GR_IS_ACTIVE_HELPER(N)                                           \
	((N)->gr_helper_info.gr_helper_status == OSPF6_GR_ACTIVE_HELPER)

/* Check the LSA is GRACE LSA */
#define IS_GRACE_LSA(lsa) (ntohs(lsa->header->type) == OSPF6_LSTYPE_GRACE_LSA)

/* Check neighbour is in FULL state */
#define IS_NBR_STATE_FULL(nbr) (nbr->state == OSPF6_NEIGHBOR_FULL)

extern const char *ospf6_exit_reason_desc[];
extern const char *ospf6_restart_reason_desc[];
extern const char *ospf6_rejected_reason_desc[];

extern void ospf6_gr_helper_config_init(void);
extern void ospf6_gr_helper_init(struct ospf6 *ospf6);
extern void ospf6_gr_helper_deinit(struct ospf6 *ospf6);
extern void ospf6_gr_helper_exit(struct ospf6_neighbor *nbr,
				 enum ospf6_helper_exit_reason reason);
extern int ospf6_process_grace_lsa(struct ospf6 *ospf6, struct ospf6_lsa *lsa,
				   struct ospf6_neighbor *nbr);
extern void ospf6_process_maxage_grace_lsa(struct ospf6 *ospf,
					   struct ospf6_lsa *lsa,
					   struct ospf6_neighbor *nbr);
extern void ospf6_helper_handle_topo_chg(struct ospf6 *ospf6,
					 struct ospf6_lsa *lsa);
extern int config_write_ospf6_gr(struct vty *vty, struct ospf6 *ospf6);
extern int config_write_ospf6_gr_helper(struct vty *vty, struct ospf6 *ospf6);
extern int config_write_ospf6_debug_gr_helper(struct vty *vty);

extern void ospf6_gr_iface_send_grace_lsa(struct event *thread);
extern void ospf6_gr_restart_enter(struct ospf6 *ospf6,
				   enum ospf6_gr_restart_reason reason,
				   time_t timestamp);
extern void ospf6_gr_check_lsdb_consistency(struct ospf6 *ospf,
					    struct ospf6_area *area);
extern void ospf6_gr_nvm_read(struct ospf6 *ospf);
extern void ospf6_gr_nvm_delete(struct ospf6 *ospf6);
extern void ospf6_gr_unplanned_start_interface(struct ospf6_interface *oi);
extern void ospf6_gr_init(void);

#endif /* OSPF6_GR_H */
