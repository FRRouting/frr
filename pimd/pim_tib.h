/*
 * TIB (Tree Information Base) - just PIM <> IGMP/MLD glue for now
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_PIM_GLUE_H
#define _FRR_PIM_GLUE_H

#include "pim_addr.h"

struct pim_instance;
struct channel_oil;

extern bool tib_sg_gm_join(struct pim_instance *pim, pim_sgaddr sg,
			   struct interface *oif, struct channel_oil **oilp);
extern void tib_sg_gm_prune(struct pim_instance *pim, pim_sgaddr sg,
			    struct interface *oif, struct channel_oil **oilp);

#endif /* _FRR_PIM_GLUE_H */
