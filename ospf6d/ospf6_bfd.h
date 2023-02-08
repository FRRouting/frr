// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * ospf6_bfd.h: OSPF6 BFD definitions and structures
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */
#include "lib/json.h"
#ifndef OSPF6_BFD_H
#define OSPF6_BFD_H
#include "lib/json.h"

/**
 * Initialize BFD integration.
 */
extern void ospf6_bfd_init(void);

extern void ospf6_bfd_trigger_event(struct ospf6_neighbor *nbr, int old_state,
				    int state);

extern void ospf6_bfd_write_config(struct vty *vty, struct ospf6_interface *oi);

extern void ospf6_bfd_info_nbr_create(struct ospf6_interface *oi,
				      struct ospf6_neighbor *on);

#endif /* OSPF6_BFD_H */
