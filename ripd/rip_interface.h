/* RIP interface routines
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_RIP_INTERFACE_H
#define _QUAGGA_RIP_INTERFACE_H

extern int rip_interface_down(int, struct zclient *, zebra_size_t, vrf_id_t);
extern int rip_interface_up(int, struct zclient *, zebra_size_t, vrf_id_t);
extern int rip_interface_add(int, struct zclient *, zebra_size_t, vrf_id_t);
extern int rip_interface_delete(int, struct zclient *, zebra_size_t, vrf_id_t);
extern int rip_interface_address_add(int, struct zclient *, zebra_size_t,
				     vrf_id_t);
extern int rip_interface_address_delete(int, struct zclient *, zebra_size_t,
					vrf_id_t);

#endif /* _QUAGGA_RIP_INTERFACE_H */
