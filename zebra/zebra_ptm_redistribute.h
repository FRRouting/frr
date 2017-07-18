/**
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


#ifndef _ZEBRA_PTM_REDISTRIBUTE_H
#define _ZEBRA_PTM_REDISTRIBUTE_H
extern void zebra_interface_bfd_update(struct interface *, struct prefix *,
				       struct prefix *, int, vrf_id_t);
extern void zebra_bfd_peer_replay_req(void);
#endif /* _ZEBRA_PTM_REDISTRIBUTE_H */
