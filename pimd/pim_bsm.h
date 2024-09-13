// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_bsm.h: PIM BSM handling related
 *
 * Copyright (C) 2018-19 Vmware, Inc.
 * Saravanan K
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

/* number of times to include rp-count = 0 ranges */
#define PIM_BSR_DEAD_COUNT 3

#define PIM_CRP_ADV_TRIGCOUNT 3
#define PIM_CRP_ADV_INTERVAL  60
#define PIM_CRP_HOLDTIME      150

/* These structures are only encoded IPv4 specific */
#define PIM_BSM_HDR_LEN sizeof(struct bsm_hdr)
#define PIM_BSM_GRP_LEN sizeof(struct bsmmsg_grpinfo)
#define PIM_BSM_RP_LEN sizeof(struct bsmmsg_rpinfo)

#define PIM_MIN_BSM_LEN \
	(PIM_HDR_LEN + PIM_BSM_HDR_LEN + PIM_BSM_GRP_LEN + PIM_BSM_RP_LEN)

/* Datastructures
 * ==============
 */

/* BSR states
 *
 * Candidate BSR starts at BSR_PENDING, moves to AP or E depending on
 * loss/win.  Will never go into AA (because in that case it'd become BSR
 * itself.)
 *
 * Non-Candidate BSR starts at NO_INFO, moves to AP & AA depending on
 * a BSR being available or not.
 */
enum bsr_state {
	NO_INFO = 0,
	ACCEPT_ANY,
	ACCEPT_PREFERRED, /* = same as C-BSR if candidate */
	BSR_PENDING,
	BSR_ELECTED,
};

enum cand_addr {
	CAND_ADDR_LO = 0,
	CAND_ADDR_ANY,
	CAND_ADDR_IFACE,
	CAND_ADDR_EXPLICIT,
};

/* used separately for Cand-RP and Cand-BSR */
struct cand_addrsel {
	bool cfg_enable;
	enum cand_addr cfg_mode : 8;

	/* only valid for mode==CAND_ADDR_IFACE */
	char cfg_ifname[IFNAMSIZ];
	/* only valid for mode==CAND_ADDR_EXPLICIT */
	pim_addr cfg_addr;

	/* running state updated based on above on zebra events */
	pim_addr run_addr;
	bool run;
};


PREDECL_DLIST(bsm_frags);
PREDECL_RBTREE_UNIQ(cand_rp_groups);

/* n*m "table" accessed both by-RP and by-group */
PREDECL_RBTREE_UNIQ(bsr_crp_rps);
PREDECL_RBTREE_UNIQ(bsr_crp_groups);

PREDECL_RBTREE_UNIQ(bsr_crp_rp_groups);
PREDECL_RBTREE_UNIQ(bsr_crp_group_rps);

/* BSM scope - bsm processing is per scope */
struct bsm_scope {
	int sz_id;			/* scope zone id */
	enum bsr_state state;		/* BSR state */

	bool accept_nofwd_bsm;		/* no fwd bsm accepted for scope */
	pim_addr current_bsr;		/* current elected BSR for the sz */
	uint32_t current_bsr_prio;      /* current BSR priority */
	int64_t current_bsr_first_ts;   /* current BSR elected time */
	int64_t current_bsr_last_ts;    /* Last BSM received from E-BSR */
	uint16_t bsm_frag_tag;		/* Last received frag tag from E-BSR */
	uint8_t hashMasklen;		/* Mask in hash calc RFC 7761 4.7.2 */
	struct pim_instance *pim;       /* Back pointer to pim instance */

	/* current set of fragments for forwarding */
	struct bsm_frags_head bsm_frags[1];

	struct route_table *bsrp_table; /* group2rp mapping rcvd from BSR */
	struct event *bs_timer;		/* Boot strap timer */

	/* Candidate BSR config */
	struct cand_addrsel bsr_addrsel;
	uint8_t cand_bsr_prio;

	/* Candidate BSR state */
	uint8_t current_cand_bsr_prio;
	/* if nothing changed from Cand-RP data we received, less work... */
	bool elec_rp_data_changed;

	/* data that the E-BSR keeps - not to be confused with Candidate-RP
	 * stuff below.  These two here are the info about all the Cand-RPs
	 * that we as a BSR received information for in Cand-RP-adv packets.
	 */
	struct bsr_crp_rps_head ebsr_rps[1];
	struct bsr_crp_groups_head ebsr_groups[1];

	/* set if we have any group ranges where we're currently advertising
	 * rp-count = 0 (includes both ranges without any RPs as well as
	 * ranges with only NHT-unreachable RPs)
	 */
	bool ebsr_have_dead_pending;
	unsigned int changed_bsm_trigger;

	struct event *t_ebsr_regen_bsm;

	/* Candidate RP config */
	struct cand_addrsel cand_rp_addrsel;
	uint8_t cand_rp_prio;
	unsigned int cand_rp_interval; /* default: PIM_CRP_ADV_INTERVAL=60 */
	/* holdtime is not configurable, always 2.5 * interval. */
	struct cand_rp_groups_head cand_rp_groups[1];

	/* Candidate RP state */
	int unicast_sock;
	struct event *unicast_read;
	struct event *cand_rp_adv_timer;
	unsigned int cand_rp_adv_trigger; /* # trigg. C-RP-Adv left to send */

	/* for sending holdtime=0 zap */
	pim_addr cand_rp_prev_addr;
};

struct cand_rp_group {
	struct cand_rp_groups_item item;

	prefix_pim p;
};

struct bsr_crp_group {
	struct bsr_crp_groups_item item;

	prefix_pim range;
	struct bsr_crp_group_rps_head rps[1];

	size_t n_selected;
	bool deleted_selected : 1;

	/* number of times we've advertised this range with rp-count = 0 */
	unsigned int dead_count;
};

struct bsr_crp_rp {
	struct bsr_crp_rps_item item;

	pim_addr addr;
	struct bsr_crp_rp_groups_head groups[1];

	struct bsm_scope *scope;
	struct event *t_hold;
	time_t seen_first;
	time_t seen_last;

	uint16_t holdtime;
	uint8_t prio;
	bool nht_ok;
};

/* "n * m" RP<->Group tie-in */
struct bsr_crp_item {
	struct bsr_crp_rp_groups_item r_g_item;
	struct bsr_crp_group_rps_item g_r_item;

	struct bsr_crp_group *group;
	struct bsr_crp_rp *rp;

	bool selected : 1;
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
	pim_addr rp_address;		/* RP Address */
	struct bsgrp_node *bsgrp_node;  /* Back ptr to bsgrp_node */
	struct event *g2rp_timer;	/* Run only for elected RP node */
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
#if PIM_IPV == 4
	struct pim_encoded_ipv4_unicast bsr_addr;
#else
	struct pim_encoded_ipv6_unicast bsr_addr;
#endif
} __attribute__((packed));

struct bsmmsg_grpinfo {
#if PIM_IPV == 4
	struct pim_encoded_group_ipv4 group;
#else
	struct pim_encoded_group_ipv6 group;
#endif
	uint8_t rp_count;
	uint8_t frag_rp_count;
	uint16_t reserved;
} __attribute__((packed));

struct bsmmsg_rpinfo {
#if PIM_IPV == 4
	struct pim_encoded_ipv4_unicast rpaddr;
#else
	struct pim_encoded_ipv6_unicast rpaddr;
#endif
	uint16_t rp_holdtime;
	uint8_t rp_pri;
	uint8_t reserved;
} __attribute__((packed));

struct cand_rp_msg {
	uint8_t prefix_cnt;
	uint8_t rp_prio;
	uint16_t rp_holdtime;
	pim_encoded_unicast rp_addr;
	pim_encoded_group groups[0];
} __attribute__((packed));

/* API */
void pim_bsm_proc_init(struct pim_instance *pim);
void pim_bsm_proc_free(struct pim_instance *pim);
void pim_bsm_clear(struct pim_instance *pim);
void pim_bsm_write_config(struct vty *vty, struct interface *ifp);
int pim_bsm_process(struct interface *ifp, pim_sgaddr *sg, uint8_t *buf,
		    uint32_t buf_size, bool no_fwd);
bool pim_bsm_new_nbr_fwd(struct pim_neighbor *neigh, struct interface *ifp);
struct bsgrp_node *pim_bsm_get_bsgrp_node(struct bsm_scope *scope,
					  struct prefix *grp);

void pim_bsm_generate(struct bsm_scope *scope);
void pim_bsm_changed(struct bsm_scope *scope);
void pim_bsm_sent(struct bsm_scope *scope);
void pim_bsm_frags_free(struct bsm_scope *scope);

bool pim_bsm_parse_install_g2rp(struct bsm_scope *scope, uint8_t *buf,
				int buflen, uint16_t bsm_frag_tag);

void pim_cand_bsr_apply(struct bsm_scope *scope);
void pim_cand_rp_apply(struct bsm_scope *scope);
void pim_cand_rp_trigger(struct bsm_scope *scope);
void pim_cand_rp_grp_add(struct bsm_scope *scope, const prefix_pim *p);
void pim_cand_rp_grp_del(struct bsm_scope *scope, const prefix_pim *p);

void pim_cand_addrs_changed(void);

int pim_crp_process(struct interface *ifp, pim_sgaddr *src_dst, uint8_t *buf,
		    uint32_t buf_size);

struct pim_nexthop_cache;
void pim_crp_nht_update(struct pim_instance *pim, struct pim_nexthop_cache *pnc);

void pim_crp_db_clear(struct bsm_scope *scope);
int pim_crp_db_show(struct vty *vty, struct bsm_scope *scope, bool json);
int pim_crp_groups_show(struct vty *vty, struct bsm_scope *scope, bool json);

int pim_cand_config_write(struct pim_instance *pim, struct vty *vty);

DECLARE_MTYPE(PIM_BSM_FRAG);

DECLARE_MTYPE(PIM_BSM_FRAG);

DECLARE_MTYPE(PIM_BSM_FRAG);

#endif
