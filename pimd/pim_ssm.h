/*
 * IP SSM ranges for FRR
 * Copyright (C) 2017 Cumulus Networks, Inc.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef PIM_SSM_H
#define PIM_SSM_H

#define PIM_SSM_STANDARD_RANGE "232.0.0.0/8"

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
int pim_is_grp_ssm(struct pim_instance *pim, struct in_addr group_addr);
int pim_ssm_range_set(struct pim_instance *pim, vrf_id_t vrf_id,
		      const char *plist_name);
void *pim_ssm_init(void);
void pim_ssm_terminate(struct pim_ssm *ssm);
#endif
