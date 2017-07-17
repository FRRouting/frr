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

#ifndef _QUAGGA_BGP_RFAPI_ENCAP_TLV_H
#define _QUAGGA_BGP_RFAPI_ENCAP_TLV_H

#define RFAPI_BGP_ENCAP_TYPE_DEFAULT BGP_ENCAP_TYPE_IP_IN_IP

extern bgp_encap_types
rfapi_tunneltype_option_to_tlv(struct bgp *bgp, struct rfapi_ip_addr *ea,
			       struct rfapi_tunneltype_option *tto,
			       struct attr *attr, int always_add);

extern struct rfapi_un_option *rfapi_encap_tlv_to_un_option(struct attr *attr);

extern void rfapi_print_tunneltype_option(void *stream, int column_offset,
					  struct rfapi_tunneltype_option *tto);


#endif /* _QUAGGA_BGP_RFAPI_ENCAP_TLV_H */
