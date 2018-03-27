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

void pim_bfd_init(void);
void pim_bfd_write_config(struct vty *vty, struct interface *ifp);
void pim_bfd_show_info(struct vty *vty, void *bfd_info, json_object *json_obj,
		       uint8_t use_json, int param_only);
void pim_bfd_if_param_set(struct interface *ifp, uint32_t min_rx,
			  uint32_t min_tx, uint8_t detect_mult, int defaults);
int pim_bfd_reg_dereg_all_nbr(struct interface *ifp, int command);
void pim_bfd_trigger_event(struct pim_interface *pim_ifp,
			   struct pim_neighbor *nbr, uint8_t nbr_up);
void pim_bfd_info_nbr_create(struct pim_interface *pim_ifp,
			     struct pim_neighbor *neigh);
void pim_bfd_info_free(void **bfd_info);
#endif /* _PIM_BFD_H */
