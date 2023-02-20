// SPDX-License-Identifier: GPL-2.0-or-later
/* PIM support for VxLAN BUM flooding
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *
 */

#ifndef PIM_VXLAN_INSTANCE_H
#define PIM_VXLAN_INSTANCE_H

/* pim termination device is expected to include the substring ipmr-lo */
#define PIM_VXLAN_TERM_DEV_NAME "ipmr-lo"

struct pim_vxlan_instance {
	struct hash *sg_hash;

	/* this is lo for default instance and vrf-dev for non-default
	 * instances
	 */
	struct interface *default_iif;

	/* In a MLAG/VxLAN-AA setup the peerlink sub-interface (ISL-rif) is
	 * used as the IIF in
	 */
	struct interface *peerlink_rif;

	/* device used by the dataplane to terminate multicast encapsulated
	 * vxlan traffic
	 */
	struct interface *term_if_cfg;
	struct interface *term_if;
};

extern void pim_vxlan_init(struct pim_instance *pim);
extern void pim_vxlan_exit(struct pim_instance *pim);

#endif /* PIM_VXLAN_INSTANCE_H */
