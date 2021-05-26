/*
 * pim_bsm.h: PIM BSM handling related
 *
 * Copyright (C) 2018-19 Vmware, Inc.
 * Saravanan K
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#ifndef __PIM_BSM_H__
#define __PIM_BSM_H__

#include "if.h"
#include "vty.h"
#include "typesafe.h"
#include "table.h"
#include "pim_rp.h"
#include "pim_msg.h"

/* Defines */
#define PIM_GBL_SZ_ID 0		    /* global scope zone id set to 0 */
#define PIM_BS_TIME 60		    /* RFC 5059 - Sec 5 */
#define PIM_BSR_DEFAULT_TIMEOUT 130 /* RFC 5059 - Sec 5 */

/* These structures are only encoded IPv4 specific */
#define PIM_BSM_HDR_LEN sizeof(struct bsm_hdr)
#define PIM_BSM_GRP_LEN sizeof(struct bsmmsg_grpinfo)
#define PIM_BSM_RP_LEN sizeof(struct bsmmsg_rpinfo)

#define PIM_MIN_BSM_LEN \
	(PIM_HDR_LEN + PIM_BSM_HDR_LEN + PIM_BSM_GRP_LEN + PIM_BSM_RP_LEN)

/* Datastructures
 * ==============
 */

/* Non candidate BSR states */
enum ncbsr_state {
	NO_INFO = 0,
	ACCEPT_ANY,
	ACCEPT_PREFERRED
};

PREDECL_DLIST(bsm_frags);

/* BSM scope - bsm processing is per scope */
struct bsm_scope {
	int sz_id;			/* scope zone id */
	enum ncbsr_state state;		/* non candidate BSR state */
	bool accept_nofwd_bsm;		/* no fwd bsm accepted for scope */
	struct in_addr current_bsr;     /* current elected BSR for the sz */
	uint32_t current_bsr_prio;      /* current BSR priority */
	int64_t current_bsr_first_ts;   /* current BSR elected time */
	int64_t current_bsr_last_ts;    /* Last BSM received from E-BSR */
	uint16_t bsm_frag_tag;		/* Last received frag tag from E-BSR */
	uint8_t hashMasklen;		/* Mask in hash calc RFC 7761 4.7.2 */
	struct pim_instance *pim;       /* Back pointer to pim instance */

	/* current set of fragments for forwarding */
	struct bsm_frags_head bsm_frags[1];

	struct route_table *bsrp_table; /* group2rp mapping rcvd from BSR */
	struct thread *bs_timer;	/* Boot strap timer */
};

/* BSM packet (= fragment) - this is stored as list in bsm_frags inside scope
 * This is used for forwarding to new neighbors or restarting mcast routers
 */
struct bsm_frag {
	struct bsm_frags_item item;

	uint32_t size;	 /* size of the packet */
	uint8_t data[0]; /* Actual packet (dyn size) */
};

DECLARE_DLIST(bsm_frags, struct bsm_frag, item);

PREDECL_SORTLIST_UNIQ(bsm_rpinfos);

/* This is the group node of the bsrp table in scope.
 * this node maintains the list of rp for the group.
 */
struct bsgrp_node {
	struct prefix group;		/* Group range */
	struct bsm_scope *scope;	/* Back ptr to scope */

	/* RPs advertised by BSR, and temporary list while receiving new set */
	struct bsm_rpinfos_head bsrp_list[1];
	struct bsm_rpinfos_head partial_bsrp_list[1];

	int pend_rp_cnt;		/* Total RP - Received RP */
	uint16_t frag_tag;		/* frag tag to identify the fragment */
};

/* Items on [partial_]bsrp_list above.
 * Holds info of each candidate RP received for the bsgrp_node's prefix.
 */
struct bsm_rpinfo {
	struct bsm_rpinfos_item item;

	uint32_t hash;                  /* Hash Value as per RFC 7761 4.7.2 */
	uint32_t elapse_time;           /* upd at expiry of elected RP node */
	uint16_t rp_prio;               /* RP priority */
	uint16_t rp_holdtime;           /* RP holdtime - g2rp timer value */
	struct in_addr rp_address;      /* RP Address */
	struct bsgrp_node *bsgrp_node;  /* Back ptr to bsgrp_node */
	struct thread *g2rp_timer;      /* Run only for elected RP node */
};

extern int pim_bsm_rpinfo_cmp(const struct bsm_rpinfo *a,
			      const struct bsm_rpinfo *b);
DECLARE_SORTLIST_UNIQ(bsm_rpinfos, struct bsm_rpinfo, item, pim_bsm_rpinfo_cmp);

/*  Structures to extract Bootstrap Message header and Grp to RP Mappings
 *  =====================================================================
 *  BSM Format:
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |PIM Ver| Type  |N|  Reserved   |           Checksum            | PIM HDR
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Fragment Tag          | Hash Mask Len | BSR Priority  | BS HDR(1)
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             BSR Address (Encoded-Unicast format)              | BS HDR(2)
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Group Address 1 (Encoded-Group format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | RP Count 1    | Frag RP Cnt 1 |         Reserved              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             RP Address 1 (Encoded-Unicast format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          RP1 Holdtime         | RP1 Priority  |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             RP Address 2 (Encoded-Unicast format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          RP2 Holdtime         | RP2 Priority  |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               .                               |
 *  |                               .                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             RP Address m (Encoded-Unicast format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          RPm Holdtime         | RPm Priority  |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Group Address 2 (Encoded-Group format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               .                               |
 *  |                               .                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Group Address n (Encoded-Group format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | RP Count n    | Frag RP Cnt n |          Reserved             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             RP Address 1 (Encoded-Unicast format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          RP1 Holdtime         | RP1 Priority  |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             RP Address 2 (Encoded-Unicast format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          RP2 Holdtime         | RP2 Priority  |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               .                               |
 *  |                               .                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             RP Address m (Encoded-Unicast format)             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          RPm Holdtime         | RPm Priority  |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct bsm_hdr {
	uint16_t frag_tag;
	uint8_t hm_len;
	uint8_t bsr_prio;
	struct pim_encoded_ipv4_unicast bsr_addr;
} __attribute__((packed));

struct bsmmsg_grpinfo {
	struct pim_encoded_group_ipv4 group;
	uint8_t rp_count;
	uint8_t frag_rp_count;
	uint16_t reserved;
} __attribute__((packed));

struct bsmmsg_rpinfo {
	struct pim_encoded_ipv4_unicast rpaddr;
	uint16_t rp_holdtime;
	uint8_t rp_pri;
	uint8_t reserved;
} __attribute__((packed));

/* API */
void pim_bsm_proc_init(struct pim_instance *pim);
void pim_bsm_proc_free(struct pim_instance *pim);
void pim_bsm_write_config(struct vty *vty, struct interface *ifp);
int  pim_bsm_process(struct interface *ifp,
		     struct ip *ip_hdr,
		     uint8_t *buf,
		     uint32_t buf_size,
		     bool no_fwd);
bool pim_bsm_new_nbr_fwd(struct pim_neighbor *neigh, struct interface *ifp);
struct bsgrp_node *pim_bsm_get_bsgrp_node(struct bsm_scope *scope,
					  struct prefix *grp);
void pim_bs_timer_stop(struct bsm_scope *scope);
void pim_bsm_frags_free(struct bsm_scope *scope);
void pim_bsm_rpinfos_free(struct bsm_rpinfos_head *head);
void pim_free_bsgrp_data(struct bsgrp_node *bsgrp_node);
void pim_free_bsgrp_node(struct route_table *rt, struct prefix *grp);
#endif
