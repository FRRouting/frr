/*
 * Copyright 2015-2016, LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_VNC_TYPES_H
#define _QUAGGA_BGP_VNC_TYPES_H

#if ENABLE_BGP_VNC
typedef enum {
	BGP_VNC_SUBTLV_TYPE_LIFETIME = 1,
	BGP_VNC_SUBTLV_TYPE_RFPOPTION = 2, /* deprecated */
} bgp_vnc_subtlv_types;

/*
 * VNC Attribute subtlvs
 */
struct bgp_vnc_subtlv_lifetime {
	uint32_t lifetime;
};

struct bgp_vnc_subtlv_unaddr {
	struct prefix un_address; /* IPv4 or IPv6; pfx length ignored */
};

#endif /* ENABLE_BGP_VNC */
#endif /* _QUAGGA_BGP_VNC_TYPES_H */
