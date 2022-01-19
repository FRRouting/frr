/*
 * pim_bfd.c: PIM BFD handling routines
 *
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/json.h"
#include "command.h"
#include "vty.h"
#include "zclient.h"

#include "pim_instance.h"
#include "pim_neighbor.h"
#include "pim_vty.h"
#include "pim_iface.h"
#include "pim_bfd.h"
#include "bfd.h"
#include "pimd.h"
#include "pim_zebra.h"

/*
 * pim_bfd_write_config - Write the interface BFD configuration.
 */
void pim_bfd_write_config(struct vty *vty, struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (!pim_ifp || !pim_ifp->bfd_config.enabled)
		return;

#if HAVE_BFDD == 0
	if (pim_ifp->bfd_config.detection_multiplier != BFD_DEF_DETECT_MULT
	    || pim_ifp->bfd_config.min_rx != BFD_DEF_MIN_RX
	    || pim_ifp->bfd_config.min_tx != BFD_DEF_MIN_TX)
		vty_out(vty, " " PIM_AF_NAME " pim bfd %d %d %d\n",
			pim_ifp->bfd_config.detection_multiplier,
			pim_ifp->bfd_config.min_rx, pim_ifp->bfd_config.min_tx);
	else
#endif /* ! HAVE_BFDD */
		vty_out(vty, " " PIM_AF_NAME " pim bfd\n");

	if (pim_ifp->bfd_config.profile)
		vty_out(vty, " " PIM_AF_NAME " pim bfd profile %s\n",
			pim_ifp->bfd_config.profile);
}

static void pim_neighbor_bfd_cb(struct bfd_session_params *bsp,
				const struct bfd_session_status *bss, void *arg)
{
	struct pim_neighbor *nbr = arg;

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: status %s old_status %s", __func__,
			   bfd_get_status_str(bss->state),
			   bfd_get_status_str(bss->previous_state));
	}

	if (bss->state == BFD_STATUS_DOWN
	    && bss->previous_state == BFD_STATUS_UP)
		pim_neighbor_delete(nbr->interface, nbr, "BFD Session Expired");
}

/*
 * pim_bfd_info_nbr_create - Create/update BFD information for a neighbor.
 */
void pim_bfd_info_nbr_create(struct pim_interface *pim_ifp,
			     struct pim_neighbor *neigh)
{
	/* Check if Pim Interface BFD is enabled */
	if (!pim_ifp || !pim_ifp->bfd_config.enabled)
		return;

	if (neigh->bfd_session == NULL)
		neigh->bfd_session = bfd_sess_new(pim_neighbor_bfd_cb, neigh);

	bfd_sess_set_timers(
		neigh->bfd_session, pim_ifp->bfd_config.detection_multiplier,
		pim_ifp->bfd_config.min_rx, pim_ifp->bfd_config.min_tx);
#if PIM_IPV == 4
	bfd_sess_set_ipv4_addrs(neigh->bfd_session, NULL, &neigh->source_addr);
#else
	bfd_sess_set_ipv6_addrs(neigh->bfd_session, NULL, &neigh->source_addr);
#endif
	bfd_sess_set_interface(neigh->bfd_session, neigh->interface->name);
	bfd_sess_set_vrf(neigh->bfd_session, neigh->interface->vrf->vrf_id);
	bfd_sess_set_profile(neigh->bfd_session, pim_ifp->bfd_config.profile);
	bfd_sess_install(neigh->bfd_session);
}

/*
 * pim_bfd_reg_dereg_all_nbr - Register/Deregister all neighbors associated
 *                              with a interface with BFD through
 *                              zebra for starting/stopping the monitoring of
 *                              the neighbor rechahability.
 */
void pim_bfd_reg_dereg_all_nbr(struct interface *ifp)
{
	struct pim_interface *pim_ifp = NULL;
	struct listnode *node = NULL;
	struct pim_neighbor *neigh = NULL;

	pim_ifp = ifp->info;
	if (!pim_ifp)
		return;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, node, neigh)) {
		if (pim_ifp->bfd_config.enabled)
			pim_bfd_info_nbr_create(pim_ifp, neigh);
		else
			bfd_sess_free(&neigh->bfd_session);
	}
}

void pim_bfd_init(void)
{
	bfd_protocol_integration_init(pim_zebra_zclient_get(), router->master);
}
