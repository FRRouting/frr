// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_dm.h: PIM Dense Mode
 *
 * Copyright (C) 2024 ATCorp
 * Jafar Al-Gharaibeh
 */

#ifndef PIM_DM_H
#define PIM_DM_H

#define PIM_DM_STANDARD_RANGE "232.0.0.0/8" // need to check it

struct pim_instance;

/* DM error codes */
enum pim_dm_err {
	PIM_DM_ERR_NONE = 0,
	PIM_DM_ERR_DUP = -1,
};

struct pim_dm {
	char *plist_name; /* prefix list of group ranges */
};

void pim_dm_change_iif_mode(struct interface *ifp, enum pim_iface_mode mode);
void pim_dm_graft_send(struct pim_rpf rpf, struct pim_upstream *up);
void pim_dm_prune_wrongif(struct interface *ifp, pim_sgaddr sg, struct pim_upstream *up);
void pim_dm_prune_send(struct pim_rpf rpf, struct pim_upstream *up, bool is_join);
bool pim_dm_check_gm_group_list(struct interface *ifp);
bool pim_gm_has_igmp_join(struct interface *ifp, pim_addr group_addr);
void pim_dm_recv_graft(struct interface *ifp, pim_sgaddr *sg);
void pim_dm_recv_prune(struct interface *ifp, struct pim_neighbor *neigh, uint16_t holdtime,
		       pim_addr upstream, pim_sgaddr *sg, uint8_t source_flags);
void pim_dm_prune_iff_on_timer(struct event *t);
void pim_dm_prefix_list_update(struct pim_instance *pim, struct prefix_list *plist);
bool pim_is_grp_dm(struct pim_instance *pim, pim_addr group_addr);
bool pim_is_dm_prefix_filter(struct pim_instance *pim, pim_addr group_addr);
bool pim_iface_grp_dm(struct pim_interface *pim_ifp, pim_addr group_addr);
int pim_dm_range_set(struct pim_instance *pim, const char *plist_name);
void pim_dm_init(struct pim_instance *pim);
void pim_dm_terminate(struct pim_instance *pim);
#endif
