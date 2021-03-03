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

#include "ospfd/ospf_interface.h"
#include "json.h"

extern void ospf_bfd_init(struct thread_master *tm);

extern void ospf_bfd_write_config(struct vty *vty,
				  const struct ospf_if_params *params);

extern void ospf_bfd_trigger_event(struct ospf_neighbor *nbr, int old_state,
				   int state);

/**
 * Legacy information: it is the peers who actually have this information
 * and the protocol should not need to know about timers.
 */
extern void ospf_interface_bfd_show(struct vty *vty,
				    const struct interface *ifp,
				    struct json_object *json);

/**
 * Disables interface BFD configuration and remove settings from all peers.
 */
extern void ospf_interface_disable_bfd(struct interface *ifp,
				       struct ospf_if_params *oip);

/**
 * Create/update BFD session for this OSPF neighbor.
 */
extern void ospf_neighbor_bfd_apply(struct ospf_neighbor *nbr);

#endif /* _ZEBRA_OSPF_BFD_H */
