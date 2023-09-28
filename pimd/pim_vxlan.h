// SPDX-License-Identifier: GPL-2.0-or-later
/* PIM support for VxLAN BUM flooding
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 */

#ifndef PIM_VXLAN_H
#define PIM_VXLAN_H

#include "pim_instance.h"

/* global timer used for miscellaneous staggered processing */
#define PIM_VXLAN_WORK_TIME 1
/* number of SG entries processed at one shot */
#define PIM_VXLAN_WORK_MAX 500
/* frequency of periodic NULL registers */
#define PIM_VXLAN_NULL_REG_INTERVAL 60 /* seconds */

#define vxlan_mlag (vxlan_info.mlag)

enum pim_vxlan_sg_flags {
	PIM_VXLAN_SGF_NONE = 0,
	PIM_VXLAN_SGF_DEL_IN_PROG = (1 << 0),
	PIM_VXLAN_SGF_OIF_INSTALLED = (1 << 1)
};

struct pim_vxlan_sg {
	struct pim_instance *pim;

	/* key */
	pim_sgaddr sg;
	char sg_str[PIM_SG_LEN];

	enum pim_vxlan_sg_flags flags;
	struct pim_upstream *up;
	struct listnode *work_node; /* to pim_vxlan.work_list */

	/* termination info (only applicable to termination XG mroutes)
	 * term_if - termination device ipmr-lo is added to the OIL
	 * as local/IGMP membership to allow termination of vxlan traffic
	 */
	struct interface *term_oif;

	/* origination info
	 * iif - lo/vrf or peerlink (on MLAG setups)
	 * peerlink_oif - added to the OIL to send encapsulated BUM traffic to
	 * the MLAG peer switch
	 */
	struct interface *iif;
	/* on a MLAG setup the peerlink is added as a static OIF */
	struct interface *orig_oif;
};

enum pim_vxlan_mlag_flags {
	PIM_VXLAN_MLAGF_NONE = 0,
	PIM_VXLAN_MLAGF_ENABLED = (1 << 0),
	PIM_VXLAN_MLAGF_DO_REG = (1 << 1)
};

struct pim_vxlan_mlag {
	enum pim_vxlan_mlag_flags flags;
	/* XXX - remove this variable from here */
	int role;
	bool peer_state;
	/* routed interface setup on top of MLAG peerlink */
	struct interface *peerlink_rif;
	struct in_addr reg_addr;
};

enum pim_vxlan_flags {
	PIM_VXLANF_NONE = 0,
	PIM_VXLANF_WORK_INITED = (1 << 0)
};

struct pim_vxlan {
	enum pim_vxlan_flags flags;

	struct event *work_timer;
	struct list *work_list;
	struct listnode *next_work;
	int max_work_cnt;

	struct pim_vxlan_mlag mlag;
};

/* zebra adds-
 * 1. one (S, G) entry where S=local-VTEP-IP and G==BUM-mcast-grp for
 * each BUM MDT. This is the origination entry.
 * 2. and one (*, G) entry each MDT. This is the termination place holder.
 *
 * Note: This doesn't mean that only (*, G) mroutes are used for tunnel
 * termination. (S, G) mroutes with ipmr-lo in the OIL can also be
 * used for tunnel termiation if SPT switchover happens; however such
 * SG entries are created by traffic and will NOT be a part of the vxlan SG
 * database.
 */
static inline bool pim_vxlan_is_orig_mroute(struct pim_vxlan_sg *vxlan_sg)
{
	return !pim_addr_is_any(vxlan_sg->sg.src);
}

static inline bool pim_vxlan_is_local_sip(struct pim_upstream *up)
{
	return !pim_addr_is_any(up->sg.src) &&
	       up->rpf.source_nexthop.interface &&
	       if_is_loopback(up->rpf.source_nexthop.interface);
}

static inline bool pim_vxlan_is_term_dev_cfg(struct pim_instance *pim,
			struct interface *ifp)
{
	return pim->vxlan.term_if_cfg == ifp;
}

extern struct pim_vxlan *pim_vxlan_p;
extern struct pim_vxlan_sg *pim_vxlan_sg_find(struct pim_instance *pim,
					      pim_sgaddr *sg);
extern struct pim_vxlan_sg *pim_vxlan_sg_add(struct pim_instance *pim,
					     pim_sgaddr *sg);
extern void pim_vxlan_sg_del(struct pim_instance *pim, pim_sgaddr *sg);
extern void pim_vxlan_update_sg_reg_state(struct pim_instance *pim,
		struct pim_upstream *up, bool reg_join);
extern struct pim_interface *pim_vxlan_get_term_ifp(struct pim_instance *pim);
extern void pim_vxlan_add_vif(struct interface *ifp);
extern void pim_vxlan_del_vif(struct interface *ifp);
extern void pim_vxlan_add_term_dev(struct pim_instance *pim,
		struct interface *ifp);
extern void pim_vxlan_del_term_dev(struct pim_instance *pim);
extern bool pim_vxlan_get_register_src(struct pim_instance *pim,
		struct pim_upstream *up, struct in_addr *src_p);
extern void pim_vxlan_mlag_update(bool enable, bool peer_state, uint32_t role,
				struct interface *peerlink_rif,
				struct in_addr *reg_addr);
extern bool pim_vxlan_do_mlag_reg(void);
extern void pim_vxlan_inherit_mlag_flags(struct pim_instance *pim,
		struct pim_upstream *up, bool inherit);

extern void pim_vxlan_rp_info_is_alive(struct pim_instance *pim,
				       struct pim_rpf *rpg_changed);

/* Shutdown of PIM stop the thread */
extern void pim_vxlan_terminate(void);
#endif /* PIM_VXLAN_H */
