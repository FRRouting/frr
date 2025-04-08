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
bool pim_dm_check_gm_group_list(struct interface *ifp);
void pim_dm_prefix_list_update(struct pim_instance *pim, struct prefix_list *plist);
bool pim_is_grp_dm(struct pim_instance *pim, pim_addr group_addr);
int pim_dm_range_set(struct pim_instance *pim, const char *plist_name);
void pim_dm_init(struct pim_instance *pim);
void pim_dm_terminate(struct pim_instance *pim);
#endif
