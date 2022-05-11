/*
 * PIMv6 temporary stubs
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

#include <zebra.h>

#include "pimd.h"
#include "pim_nht.h"
#include "pim_zlookup.h"
#include "pim_pim.h"
#include "pim_register.h"
#include "pim_cmd.h"
#include "pim_bsm.h"

/*
 * NH lookup / NHT
 */
void pim_nht_bsr_add(struct pim_instance *pim, struct in_addr addr)
{
}

void pim_nht_bsr_del(struct pim_instance *pim, struct in_addr addr)
{
}

bool pim_bsm_new_nbr_fwd(struct pim_neighbor *neigh, struct interface *ifp)
{
	return false;
}

void pim_bsm_proc_free(struct pim_instance *pim)
{
}

void pim_bsm_proc_init(struct pim_instance *pim)
{
}

struct bsgrp_node *pim_bsm_get_bsgrp_node(struct bsm_scope *scope,
					  struct prefix *grp)
{
	return NULL;
}

void pim_bsm_write_config(struct vty *vty, struct interface *ifp)
{
}

int pim_bsm_process(struct interface *ifp, pim_sgaddr *sg, uint8_t *buf,
		    uint32_t buf_size, bool no_fwd)
{
	return 0;
}
