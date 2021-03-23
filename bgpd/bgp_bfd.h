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

#define PEER_IS_MULTIHOP(peer)                                                 \
	((((peer)->sort == BGP_PEER_IBGP) && !(peer)->shared_network)          \
	 || is_ebgp_multihop_configured((peer)))

extern void bgp_bfd_init(struct thread_master *tm);

extern void bgp_bfd_peer_config_write(struct vty *vty, const struct peer *peer,
				      const char *addr);

/**
 * Show BFD information helper.
 *
 * \param vty the VTY pointer.
 * \param peer the BGP configuration pointer.
 * \param use_json unused.
 * \param json_neigh JSON object when called as JSON command.
 */
extern void bgp_bfd_show_info(struct vty *vty, const struct peer *peer,
			      json_object *json_neigh);

/**
 * When called on a group it applies configuration to all peers in that group,
 * otherwise just applies the configuration to a single peer.
 *
 * This function should be called when configuration changes either on group
 * or peer.
 *
 * \param p the BGP peer pointer.
 * \param pg the BGP group to copy configuration from (it is usually
 *           `p->group` exception when copying new group configuration
 *           see `peer_group2peer_config_copy` function case).
 */
extern void bgp_peer_config_apply(struct peer *p, struct peer_group *pg);

/**
 * Allocates and configure BFD session for peer. If it is already configured,
 * then it does nothing.
 *
 * Always call `bgp_peer_config_apply` afterwards if you need the changes
 * immediately applied.
 */
extern void bgp_peer_configure_bfd(struct peer *p, bool manual);

/**
 * Removes BFD configuration from either peer or peer group.
 */
extern void bgp_peer_remove_bfd_config(struct peer *p);

/**
 * Special function to handle the case of changing source address. This
 * happens when the peer/group is configured with `neigbor X update-source Y`.
 */
extern void bgp_peer_bfd_update_source(struct peer *p);

#endif /* _QUAGGA_BGP_BFD_H */
