/**
 * bgp_bfd.h: BGP BFD definitions and structures
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

#ifndef _QUAGGA_BGP_BFD_H
#define _QUAGGA_BGP_BFD_H

extern void bgp_bfd_init(void);

extern void bgp_bfd_peer_group2peer_copy(struct peer *conf, struct peer *peer);

extern void bgp_bfd_register_peer(struct peer *peer);

extern void bgp_bfd_deregister_peer(struct peer *peer);

extern void bgp_bfd_peer_config_write(struct vty *vty, struct peer *peer,
				      char *addr);

extern void bgp_bfd_show_info(struct vty *vty, struct peer *peer,
			      uint8_t use_json, json_object *json_neigh);

extern int bgp_bfd_is_peer_multihop(struct peer *peer);

#endif /* _QUAGGA_BGP_BFD_H */
