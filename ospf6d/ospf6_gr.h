/*
 * OSPF6 Graceful Retsart helper functions.
 *
 * Copyright (C) 2021-22 Vmware, Inc.
 * Rajesh Kumar Girada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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

#ifdef roundup
#define ROUNDUP(val, gran) roundup(val, gran)
#else /* roundup */
#define ROUNDUP(val, gran) (((val)-1 | (gran)-1) + 1)
#endif /* roundup */

/*
 * Generic TLV (type, length, value) macros
 */
struct tlv_header {
	uint16_t type;   /* Type of Value */
	uint16_t length; /* Length of Value portion only, in bytes */
};

#define TLV_HDR_SIZE (sizeof(struct tlv_header))

#define TLV_BODY_SIZE(tlvh) (ROUNDUP(ntohs((tlvh)->length), sizeof(uint32_t)))

#define TLV_SIZE(tlvh) (uint32_t)(TLV_HDR_SIZE + TLV_BODY_SIZE(tlvh))

#define TLV_HDR_TOP(lsah)                                                      \
	(struct tlv_header *)((char *)(lsah) + OSPF6_LSA_HEADER_SIZE)

#define TLV_HDR_NEXT(tlvh)                                                     \
	(struct tlv_header *)((char *)(tlvh) + TLV_SIZE(tlvh))

/* Ref RFC5187 appendix-A */
/* Grace period TLV */
#define GRACE_PERIOD_TYPE 1
#define GRACE_PERIOD_LENGTH 4
struct grace_tlv_graceperiod {
	struct tlv_header header;
	uint32_t interval;
};
#define GRACE_PERIOD_TLV_SIZE sizeof(struct grace_tlv_graceperiod)

/* Restart reason TLV */
#define RESTART_REASON_TYPE 2
#define RESTART_REASON_LENGTH 1
struct grace_tlv_restart_reason {
	struct tlv_header header;
	uint8_t reason;
	uint8_t reserved[3];
};
#define GRACE_RESTART_REASON_TLV_SIZE sizeof(struct grace_tlv_restart_reason)

#define OSPF6_GRACE_LSA_MIN_SIZE                                               \
	GRACE_PERIOD_TLV_SIZE + GRACE_RESTART_REASON_TLV_SIZE

struct ospf6_grace_lsa {
	struct grace_tlv_graceperiod tlv_period;
	struct grace_tlv_restart_reason tlv_reason;
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

extern void ospf6_gr_check_lsdb_consistency(struct ospf6 *ospf,
					    struct ospf6_area *area);
extern void ospf6_gr_nvm_read(struct ospf6 *ospf);
extern void ospf6_gr_init(void);

#endif /* OSPF6_GR_H */
