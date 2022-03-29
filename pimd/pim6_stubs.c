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

/*
 * NH lookup / NHT
 */
void pim_nht_bsr_add(struct pim_instance *pim, struct in_addr addr)
{
}

void pim_nht_bsr_del(struct pim_instance *pim, struct in_addr addr)
{
}

int zclient_lookup_nexthop(struct pim_instance *pim,
			   struct pim_zlookup_nexthop nexthop_tab[],
			   const int tab_size, pim_addr addr,
			   int max_lookup)
{
	return -1;
}

void zclient_lookup_new(void)
{
}

void zclient_lookup_free(void)
{
}

/*
 * PIM register
 */
void pim_register_join(struct pim_upstream *up)
{
}

void pim_null_register_send(struct pim_upstream *up)
{
}

void pim_reg_del_on_couldreg_fail(struct interface *ifp)
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

void pim_register_send(const uint8_t *buf, int buf_size, pim_addr src,
		       struct pim_rpf *rpg, int null_register,
		       struct pim_upstream *up)
{
}

void pim_register_stop_send(struct interface *ifp, pim_sgaddr *sg, pim_addr src,
			    pim_addr originator)
{
}

int pim_register_recv(struct interface *ifp, pim_addr dest_addr,
		      pim_addr src_addr, uint8_t *tlv_buf, int tlv_buf_size)
{
	return 0;
}

int pim_register_stop_recv(struct interface *ifp, uint8_t *buf, int buf_size)
{
	return 0;
}
