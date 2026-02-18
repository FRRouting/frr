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

extern unsigned char conf_debug_ospf6_bfd;
#define OSPF6_DEBUG_BFD_ON() (conf_debug_ospf6_bfd = 1)
#define OSPF6_DEBUG_BFD_OFF() (conf_debug_ospf6_bfd = 0)
#define IS_OSPF6_DEBUG_BFD (conf_debug_ospf6_bfd)

/**
 * Initialize BFD integration.
 */
extern void ospf6_bfd_init(void);

extern void ospf6_bfd_trigger_event(struct ospf6_neighbor *nbr, int old_state,
				    int state);

extern void ospf6_bfd_write_config(struct vty *vty, struct ospf6_interface *oi);

extern void ospf6_bfd_info_nbr_create(struct ospf6_interface *oi,
				      struct ospf6_neighbor *on);

extern int config_write_ospf6_debug_bfd(struct vty *vty);
extern void install_element_ospf6_debug_bfd(void);

#endif /* OSPF6_BFD_H */
