/* PIM support for VxLAN BUM flooding
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
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
