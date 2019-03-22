/* PIM support for VxLAN BUM flooding
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef PIM_VXLAN_H
#define PIM_VXLAN_H

enum pim_vxlan_sg_flags {
	PIM_VXLAN_SGF_NONE = 0,
	PIM_VXLAN_SGF_DEL_IN_PROG = (1 << 0),
	PIM_VXLAN_SGF_OIF_INSTALLED = (1 << 1)
};

struct pim_vxlan_sg {
	struct pim_instance *pim;

	/* key */
	struct prefix_sg sg;
	char sg_str[PIM_SG_LEN];

	enum pim_vxlan_sg_flags flags;
	struct pim_upstream *up;

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
	PIM_VXLAN_MLAGF_ENABLED = (1 << 0)
};

enum pim_vxlan_mlag_role {
	PIM_VXLAN_MLAG_ROLE_SECONDARY = 0,
	PIM_VXLAN_MLAG_ROLE_PRIMARY
};

struct pim_vxlan_mlag {
	enum pim_vxlan_mlag_flags flags;
	enum pim_vxlan_mlag_role role;
	bool peer_state;
	/* routed interface setup on top of MLAG peerlink */
	struct interface *peerlink_rif;
	struct in_addr reg_addr;
};

struct pim_vxlan {
	struct pim_vxlan_mlag mlag;
};

extern struct pim_vxlan_sg *pim_vxlan_sg_find(struct pim_instance *pim,
					    struct prefix_sg *sg);
extern struct pim_vxlan_sg *pim_vxlan_sg_add(struct pim_instance *pim,
					   struct prefix_sg *sg);
extern void pim_vxlan_sg_del(struct pim_instance *pim, struct prefix_sg *sg);

#endif /* PIM_VXLAN_H */
