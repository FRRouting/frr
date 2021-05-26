/*
 * pim_bfd.h: PIM BFD definitions and structures
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

#ifndef PIM_BFD_H
#define PIM_BFD_H

#include "if.h"

/**
 * Initializes PIM BFD integration code.
 */
void pim_bfd_init(void);

/**
 * Write configuration to `show running-config`.
 *
 * \param vty the vty output pointer.
 * \param ifp the interface pointer that has the configuration.
 */
void pim_bfd_write_config(struct vty *vty, struct interface *ifp);

/**
 * Enables or disables all peers BFD sessions.
 *
 * \param ifp interface pointer.
 * \param enable session state to set.
 */
void pim_bfd_reg_dereg_all_nbr(struct interface *ifp);

/**
 * Create and configure peer BFD session if it does not exist. It will use
 * the interface configured parameters as the peer configuration.
 *
 * \param pim_ifp the interface configuration pointer.
 * \param neigh the neighbor configuration pointer.
 */
void pim_bfd_info_nbr_create(struct pim_interface *pim_ifp,
			     struct pim_neighbor *neigh);

#endif /* _PIM_BFD_H */
