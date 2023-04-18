// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * ospf_bfd.h: OSPF BFD definitions and structures
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_OSPF_BFD_H
#define _ZEBRA_OSPF_BFD_H

#include "ospfd/ospf_interface.h"
#include "json.h"

extern void ospf_bfd_init(struct event_loop *tm);

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
