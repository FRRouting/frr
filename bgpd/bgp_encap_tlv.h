/*
 * Copyright 2015, LabN Consulting, L.L.C.
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

#ifndef _QUAGGA_BGP_ENCAP_TLV_H
#define _QUAGGA_BGP_ENCAP_TLV_H

/***********************************************************************
 *		TUNNEL TYPE-SPECIFIC TLV ENCODE
 ***********************************************************************/

extern void
bgp_encap_type_l2tpv3overip_to_tlv(struct bgp_encap_type_l2tpv3_over_ip *bet,
				   struct attr *attr);

extern void bgp_encap_type_gre_to_tlv(struct bgp_encap_type_gre *bet,
				      struct attr *attr);

extern void bgp_encap_type_ip_in_ip_to_tlv(struct bgp_encap_type_ip_in_ip *bet,
					   struct attr *attr);

extern void bgp_encap_type_transmit_tunnel_endpoint(
	struct bgp_encap_type_transmit_tunnel_endpoint *bet, struct attr *attr);

extern void bgp_encap_type_ipsec_in_tunnel_mode_to_tlv(
	struct bgp_encap_type_ipsec_in_tunnel_mode *bet, struct attr *attr);

extern void bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode_to_tlv(
	struct bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode *bet,
	struct attr *attr);

extern void bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode_to_tlv(
	struct bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode *bet,
	struct attr *attr);

extern void bgp_encap_type_pbb_to_tlv(struct bgp_encap_type_pbb *bet,
				      struct attr *attr);

extern void bgp_encap_type_vxlan_to_tlv(struct bgp_encap_type_vxlan *bet,
					struct attr *attr);

extern void bgp_encap_type_nvgre_to_tlv(struct bgp_encap_type_nvgre *bet,
					struct attr *attr);

extern void bgp_encap_type_mpls_to_tlv(struct bgp_encap_type_mpls *bet,
				       struct attr *attr);

extern void
bgp_encap_type_mpls_in_gre_to_tlv(struct bgp_encap_type_mpls_in_gre *bet,
				  struct attr *attr);

extern void
bgp_encap_type_vxlan_gpe_to_tlv(struct bgp_encap_type_vxlan_gpe *bet,
				struct attr *attr);

extern void
bgp_encap_type_mpls_in_udp_to_tlv(struct bgp_encap_type_mpls_in_udp *bet,
				  struct attr *attr);

/***********************************************************************
 *		TUNNEL TYPE-SPECIFIC TLV DECODE
 ***********************************************************************/

extern int tlv_to_bgp_encap_type_l2tpv3overip(
	struct bgp_attr_encap_subtlv *stlv,	 /* subtlv chain */
	struct bgp_encap_type_l2tpv3_over_ip *bet); /* caller-allocated */

extern int tlv_to_bgp_encap_type_gre(
	struct bgp_attr_encap_subtlv *stlv, /* subtlv chain */
	struct bgp_encap_type_gre *bet);    /* caller-allocated */

extern int tlv_to_bgp_encap_type_ip_in_ip(
	struct bgp_attr_encap_subtlv *stlv,   /* subtlv chain */
	struct bgp_encap_type_ip_in_ip *bet); /* caller-allocated */

extern int tlv_to_bgp_encap_type_transmit_tunnel_endpoint(
	struct bgp_attr_encap_subtlv *stlv,
	struct bgp_encap_type_transmit_tunnel_endpoint *bet);

extern int tlv_to_bgp_encap_type_ipsec_in_tunnel_mode(
	struct bgp_attr_encap_subtlv *stlv,		  /* subtlv chain */
	struct bgp_encap_type_ipsec_in_tunnel_mode *bet); /* caller-allocated */

extern int tlv_to_bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode(
	struct bgp_attr_encap_subtlv *stlv,
	struct bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode *bet);

extern int tlv_to_bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode(
	struct bgp_attr_encap_subtlv *stlv,
	struct bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode *bet);

extern int tlv_to_bgp_encap_type_vxlan(struct bgp_attr_encap_subtlv *stlv,
				       struct bgp_encap_type_vxlan *bet);

extern int tlv_to_bgp_encap_type_nvgre(struct bgp_attr_encap_subtlv *stlv,
				       struct bgp_encap_type_nvgre *bet);

extern int tlv_to_bgp_encap_type_mpls(struct bgp_attr_encap_subtlv *stlv,
				      struct bgp_encap_type_mpls *bet);

extern int tlv_to_bgp_encap_type_mpls(struct bgp_attr_encap_subtlv *stlv,
				      struct bgp_encap_type_mpls *bet);

extern int
tlv_to_bgp_encap_type_mpls_in_gre(struct bgp_attr_encap_subtlv *stlv,
				  struct bgp_encap_type_mpls_in_gre *bet);

extern int
tlv_to_bgp_encap_type_vxlan_gpe(struct bgp_attr_encap_subtlv *stlv,
				struct bgp_encap_type_vxlan_gpe *bet);

extern int
tlv_to_bgp_encap_type_mpls_in_udp(struct bgp_attr_encap_subtlv *stlv,
				  struct bgp_encap_type_mpls_in_udp *bet);

extern int tlv_to_bgp_encap_type_pbb(
	struct bgp_attr_encap_subtlv *stlv, /* subtlv chain */
	struct bgp_encap_type_pbb *bet);    /* caller-allocated */

#endif /* _QUAGGA_BGP_ENCAP_TLV_H */
