/* BGP VTY interface.
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGP_VTY_H
#define _QUAGGA_BGP_VTY_H

#include "bgpd/bgpd.h"

#define CMD_AS_RANGE "<1-4294967295>"
#define DYNAMIC_NEIGHBOR_LIMIT_RANGE "<1-5000>"
#define BGP_INSTANCE_CMD "(view|vrf) WORD"
#define BGP_INSTANCE_HELP_STR "BGP view\nBGP VRF\nView/VRF name\n"
#define BGP_INSTANCE_ALL_CMD "(view|vrf) all"
#define BGP_INSTANCE_ALL_HELP_STR "BGP view\nBGP VRF\nAll Views/VRFs\n"

extern void bgp_vty_init (void);
extern const char *afi_safi_print (afi_t, safi_t);
extern int bgp_config_write_update_delay (struct vty *, struct bgp *);
extern int bgp_config_write_wpkt_quanta(struct vty *vty, struct bgp *bgp);
extern int bgp_config_write_listen(struct vty *vty, struct bgp *bgp);
extern int bgp_config_write_coalesce_time(struct vty *vty, struct bgp *bgp);
extern int bgp_vty_return (struct vty *vty, int ret);
extern struct peer *
peer_and_group_lookup_vty (struct vty *vty, const char *peer_str);

#endif /* _QUAGGA_BGP_VTY_H */
