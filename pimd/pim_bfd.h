// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_bfd.h: PIM BFD definitions and structures
 *
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
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
