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

struct pim_vxlan_sg {
	struct pim_instance *pim;

	/* key */
	struct prefix_sg sg;
	char sg_str[PIM_SG_LEN];
};

extern struct pim_vxlan_sg *pim_vxlan_sg_find(struct pim_instance *pim,
					    struct prefix_sg *sg);
extern struct pim_vxlan_sg *pim_vxlan_sg_add(struct pim_instance *pim,
					   struct prefix_sg *sg);
extern void pim_vxlan_sg_del(struct pim_instance *pim, struct prefix_sg *sg);

#endif /* PIM_VXLAN_H */
