/**
 * ospf_bfd.h: OSPF BFD definitions and structures
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_OSPF_BFD_H
#define _ZEBRA_OSPF_BFD_H

#include "json.h"

extern void ospf_bfd_init(void);

extern void ospf_bfd_write_config(struct vty *vty,
				  struct ospf_if_params *params);

extern void ospf_bfd_trigger_event(struct ospf_neighbor *nbr, int old_state,
				   int state);

extern void ospf_bfd_interface_show(struct vty *vty, struct interface *ifp,
				    json_object *json_interface_sub,
				    uint8_t use_json);

extern void ospf_bfd_info_nbr_create(struct ospf_interface *oi,
				     struct ospf_neighbor *nbr);

extern void ospf_bfd_show_info(struct vty *vty, void *bfd_info,
			       json_object *json_obj, uint8_t use_json,
			       int param_only);

extern void ospf_bfd_info_free(void **bfd_info);

#endif /* _ZEBRA_OSPF_BFD_H */
