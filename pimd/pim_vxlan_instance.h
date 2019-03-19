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

struct pim_vxlan_instance {
	struct hash *sg_hash;
};

extern void pim_vxlan_init(struct pim_instance *pim);
extern void pim_vxlan_exit(struct pim_instance *pim);

#endif /* PIM_VXLAN_INSTANCE_H */
