// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IP SSM ranges for FRR
 * Copyright (C) 2017 Cumulus Networks, Inc.
 */
#ifndef PIM_SSM_H
#define PIM_SSM_H

#define PIM_SSM_STANDARD_RANGE "232.0.0.0/8"

struct pim_instance;

/* SSM error codes */
enum pim_ssm_err {
	PIM_SSM_ERR_NONE = 0,
	PIM_SSM_ERR_NO_VRF = -1,
	PIM_SSM_ERR_DUP = -2,
};

struct pim_ssm {
	char *plist_name; /* prefix list of group ranges */
};

void pim_ssm_prefix_list_update(struct pim_instance *pim,
				struct prefix_list *plist);
extern int pim_is_grp_ssm(struct pim_instance *pim, pim_addr group_addr);
int pim_ssm_range_set(struct pim_instance *pim, vrf_id_t vrf_id,
		      const char *plist_name);
void *pim_ssm_init(void);
void pim_ssm_terminate(struct pim_ssm *ssm);
#endif
