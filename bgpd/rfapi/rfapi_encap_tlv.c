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

#include "lib/zebra.h"

#include "lib/memory.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/vty.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"

#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_encap_tlv.h"

#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_encap_tlv.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/vnc_debug.h"

static void rfapi_add_endpoint_address_to_subtlv(
	struct bgp *bgp, struct rfapi_ip_addr *ea,
	struct bgp_tea_subtlv_remote_endpoint *subtlv)
{
	subtlv->family = ea->addr_family;
	if (subtlv->family == AF_INET)
		subtlv->ip_address.v4 = ea->addr.v4;
	else
		subtlv->ip_address.v6 = ea->addr.v6;
	subtlv->as4 = htonl(bgp->as);
}

bgp_encap_types
rfapi_tunneltype_option_to_tlv(struct bgp *bgp, struct rfapi_ip_addr *ea,
			       struct rfapi_tunneltype_option *tto,
			       struct attr *attr, int always_add)
{

#define _RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(ttype)                                \
	if ((always_add                                                        \
	     || (bgp->rfapi_cfg                                                \
		 && !CHECK_FLAG(bgp->rfapi_cfg->flags,                         \
				BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP)))          \
	    && ea                                                              \
	    && !CHECK_SUBTLV_FLAG(&tto->bgpinfo.ttype,                         \
				  BGP_TEA_SUBTLV_REMOTE_ENDPOINT)) {           \
		rfapi_add_endpoint_address_to_subtlv(                          \
			bgp, ea, &tto->bgpinfo.ttype.st_endpoint);             \
		SET_SUBTLV_FLAG(&tto->bgpinfo.ttype,                           \
				BGP_TEA_SUBTLV_REMOTE_ENDPOINT);               \
	}

	struct rfapi_tunneltype_option dto;
	if (tto == NULL) { /* create default type */
		tto = &dto;
		memset(tto, 0, sizeof(dto));
		tto->type = RFAPI_BGP_ENCAP_TYPE_DEFAULT;
	}
	switch (tto->type) {
	case BGP_ENCAP_TYPE_L2TPV3_OVER_IP:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(l2tpv3_ip);
		bgp_encap_type_l2tpv3overip_to_tlv(&tto->bgpinfo.l2tpv3_ip,
						   attr);
		break;

	case BGP_ENCAP_TYPE_GRE:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(gre);
		bgp_encap_type_gre_to_tlv(&tto->bgpinfo.gre, attr);
		break;

	case BGP_ENCAP_TYPE_TRANSMIT_TUNNEL_ENDPOINT:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(transmit_tunnel_endpoint);
		bgp_encap_type_transmit_tunnel_endpoint(
			&tto->bgpinfo.transmit_tunnel_endpoint, attr);
		break;

	case BGP_ENCAP_TYPE_IPSEC_IN_TUNNEL_MODE:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(ipsec_tunnel);
		bgp_encap_type_ipsec_in_tunnel_mode_to_tlv(
			&tto->bgpinfo.ipsec_tunnel, attr);
		break;

	case BGP_ENCAP_TYPE_IP_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(ip_ipsec);
		bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode_to_tlv(
			&tto->bgpinfo.ip_ipsec, attr);
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(mpls_ipsec);
		bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode_to_tlv(
			&tto->bgpinfo.mpls_ipsec, attr);
		break;

	case BGP_ENCAP_TYPE_IP_IN_IP:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(ip_ip);
		bgp_encap_type_ip_in_ip_to_tlv(&tto->bgpinfo.ip_ip, attr);
		break;

	case BGP_ENCAP_TYPE_VXLAN:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(vxlan);
		bgp_encap_type_vxlan_to_tlv(&tto->bgpinfo.vxlan, attr);
		break;

	case BGP_ENCAP_TYPE_NVGRE:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(nvgre);
		bgp_encap_type_nvgre_to_tlv(&tto->bgpinfo.nvgre, attr);
		break;

	case BGP_ENCAP_TYPE_MPLS:
		/* nothing to do for MPLS */
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_GRE:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(mpls_gre);
		bgp_encap_type_mpls_in_gre_to_tlv(&tto->bgpinfo.mpls_gre, attr);
		break;

	case BGP_ENCAP_TYPE_VXLAN_GPE:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(vxlan_gpe);
		bgp_encap_type_vxlan_gpe_to_tlv(&tto->bgpinfo.vxlan_gpe, attr);
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_UDP:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(mpls_udp);
		bgp_encap_type_mpls_in_udp_to_tlv(&tto->bgpinfo.mpls_udp, attr);
		break;

	case BGP_ENCAP_TYPE_PBB:
		_RTTO_MAYBE_ADD_ENDPOINT_ADDRESS(pbb);
		bgp_encap_type_pbb_to_tlv(&tto->bgpinfo.pbb, attr);
		break;

	default:
		assert(0);
	}
	return tto->type;
}

struct rfapi_un_option *rfapi_encap_tlv_to_un_option(struct attr *attr)
{
	struct rfapi_un_option *uo = NULL;
	struct rfapi_tunneltype_option *tto;
	int rc;
	struct bgp_attr_encap_subtlv *stlv;

	/* no tunnel encap attr stored */
	if (!attr->encap_tunneltype)
		return NULL;

	stlv = attr->encap_subtlvs;

	uo = XCALLOC(MTYPE_RFAPI_UN_OPTION, sizeof(struct rfapi_un_option));
	assert(uo);
	uo->type = RFAPI_UN_OPTION_TYPE_TUNNELTYPE;
	uo->v.tunnel.type = attr->encap_tunneltype;
	tto = &uo->v.tunnel;

	switch (attr->encap_tunneltype) {
	case BGP_ENCAP_TYPE_L2TPV3_OVER_IP:
		rc = tlv_to_bgp_encap_type_l2tpv3overip(
			stlv, &tto->bgpinfo.l2tpv3_ip);
		break;

	case BGP_ENCAP_TYPE_GRE:
		rc = tlv_to_bgp_encap_type_gre(stlv, &tto->bgpinfo.gre);
		break;

	case BGP_ENCAP_TYPE_TRANSMIT_TUNNEL_ENDPOINT:
		rc = tlv_to_bgp_encap_type_transmit_tunnel_endpoint(
			stlv, &tto->bgpinfo.transmit_tunnel_endpoint);
		break;

	case BGP_ENCAP_TYPE_IPSEC_IN_TUNNEL_MODE:
		rc = tlv_to_bgp_encap_type_ipsec_in_tunnel_mode(
			stlv, &tto->bgpinfo.ipsec_tunnel);
		break;

	case BGP_ENCAP_TYPE_IP_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE:
		rc = tlv_to_bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode(
			stlv, &tto->bgpinfo.ip_ipsec);
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE:
		rc = tlv_to_bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode(
			stlv, &tto->bgpinfo.mpls_ipsec);
		break;

	case BGP_ENCAP_TYPE_IP_IN_IP:
		rc = tlv_to_bgp_encap_type_ip_in_ip(stlv, &tto->bgpinfo.ip_ip);
		break;

	case BGP_ENCAP_TYPE_VXLAN:
		rc = tlv_to_bgp_encap_type_vxlan(stlv, &tto->bgpinfo.vxlan);
		break;

	case BGP_ENCAP_TYPE_NVGRE:
		rc = tlv_to_bgp_encap_type_nvgre(stlv, &tto->bgpinfo.nvgre);
		break;

	case BGP_ENCAP_TYPE_MPLS:
		rc = tlv_to_bgp_encap_type_mpls(stlv, &tto->bgpinfo.mpls);
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_GRE:
		rc = tlv_to_bgp_encap_type_mpls_in_gre(stlv,
						       &tto->bgpinfo.mpls_gre);
		break;

	case BGP_ENCAP_TYPE_VXLAN_GPE:
		rc = tlv_to_bgp_encap_type_vxlan_gpe(stlv,
						     &tto->bgpinfo.vxlan_gpe);
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_UDP:
		rc = tlv_to_bgp_encap_type_mpls_in_udp(stlv,
						       &tto->bgpinfo.mpls_udp);
		break;

	case BGP_ENCAP_TYPE_PBB:
		rc = tlv_to_bgp_encap_type_pbb(stlv, &tto->bgpinfo.pbb);
		break;

	default:
		vnc_zlog_debug_verbose("%s: unknown tunnel type %d", __func__,
				       attr->encap_tunneltype);
		rc = -1;
		break;
	}
	if (rc) {
		XFREE(MTYPE_RFAPI_UN_OPTION, uo);
		uo = NULL;
	}
	return uo;
}

/***********************************************************************
 *			SUBTLV PRINT
 ***********************************************************************/

static void subtlv_print_encap_l2tpv3_over_ip(
	void *stream, int column_offset,
	struct bgp_tea_subtlv_encap_l2tpv3_over_ip *st)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!st)
		return;

	fp(out, "%*s%s%s", column_offset, "", "SubTLV: Encap(L2TPv3 over IP)",
	   vty_newline);
	fp(out, "%*s  SessionID: %d%s", column_offset, "", st->sessionid,
	   vty_newline);
	fp(out, "%*s  Cookie: (length %d)%s", column_offset, "",
	   st->cookie_length, vty_newline);
}

static void subtlv_print_encap_gre(void *stream, int column_offset,
				   struct bgp_tea_subtlv_encap_gre_key *st)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!st)
		return;

	fp(out, "%*s%s%s", column_offset, "", "SubTLV: Encap(GRE)",
	   vty_newline);
	fp(out, "%*s  GRE key: %d (0x%x)%s", column_offset, "", st->gre_key,
	   st->gre_key, vty_newline);
}

static void subtlv_print_encap_pbb(void *stream, int column_offset,
				   struct bgp_tea_subtlv_encap_pbb *st)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!st)
		return;

	fp(out, "%*s%s%s", column_offset, "", "SubTLV: Encap(PBB)",
	   vty_newline);
	if (st->flag_isid) {
		fp(out, "%*s  ISID: %d (0x%x)%s", column_offset, "", st->isid,
		   st->isid, vty_newline);
	}
	if (st->flag_vid) {
		fp(out, "%*s  VID: %d (0x%x)%s", column_offset, "", st->vid,
		   st->vid, vty_newline);
	}
	fp(out, "%*s  MACADDR %02x:%02x:%02x:%02x:%02x:%02x%s", column_offset,
	   "", st->macaddr[0], st->macaddr[1], st->macaddr[2], st->macaddr[3],
	   st->macaddr[4], st->macaddr[5], vty_newline);
}

static void subtlv_print_proto_type(void *stream, int column_offset,
				    struct bgp_tea_subtlv_proto_type *st)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!st)
		return;

	fp(out, "%*s%s%s", column_offset, "", "SubTLV: Encap(Proto Type)",
	   vty_newline);
	fp(out, "%*s  Proto %d (0x%x)%s", column_offset, "", st->proto,
	   st->proto, vty_newline);
}

static void subtlv_print_color(void *stream, int column_offset,
			       struct bgp_tea_subtlv_color *st)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!st)
		return;

	fp(out, "%*s%s%s", column_offset, "", "SubTLV: Color", vty_newline);
	fp(out, "%*s  Color: %d (0x%x)", column_offset, "", st->color,
	   st->color, vty_newline);
}

static void subtlv_print_ipsec_ta(void *stream, int column_offset,
				  struct bgp_tea_subtlv_ipsec_ta *st)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!st)
		return;

	fp(out, "%*s%s%s", column_offset, "", "SubTLV: IPSEC TA", vty_newline);
	fp(out, "%*s  Authenticator Type: %d (0x%x)", column_offset, "",
	   st->authenticator_type, st->authenticator_type, vty_newline);
	fp(out, "%*s  Authenticator: (length %d)", column_offset, "",
	   st->authenticator_length, vty_newline);
}

/***********************************************************************
 *			TLV PRINT
 ***********************************************************************/

static void
print_encap_type_l2tpv3overip(void *stream, int column_offset,
			      struct bgp_encap_type_l2tpv3_over_ip *bet)
{
	const char *type = "L2TPv3 over IP";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	subtlv_print_encap_l2tpv3_over_ip(stream, column_offset + 2,
					  &bet->st_encap);
	subtlv_print_proto_type(stream, column_offset + 2, &bet->st_proto);
	subtlv_print_color(stream, column_offset + 2, &bet->st_color);
}

static void print_encap_type_gre(void *stream, int column_offset,
				 struct bgp_encap_type_gre *bet)
{
	const char *type = "GRE";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	subtlv_print_encap_gre(stream, column_offset + 2, &bet->st_encap);
	subtlv_print_proto_type(stream, column_offset + 2, &bet->st_proto);
	subtlv_print_color(stream, column_offset + 2, &bet->st_color);
}

static void print_encap_type_ip_in_ip(void *stream, int column_offset,
				      struct bgp_encap_type_ip_in_ip *bet)
{
	const char *type = "IP in IP";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	subtlv_print_proto_type(stream, column_offset + 2, &bet->st_proto);
	subtlv_print_color(stream, column_offset + 2, &bet->st_color);
}

static void print_encap_type_transmit_tunnel_endpoint(
	void *stream, int column_offset,
	struct bgp_encap_type_transmit_tunnel_endpoint *bet)
{
	const char *type = "Transmit Tunnel Endpoint";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	/* no subtlvs for this type */
}

static void print_encap_type_ipsec_in_tunnel_mode(
	void *stream, int column_offset,
	struct bgp_encap_type_ipsec_in_tunnel_mode *bet)
{
	const char *type = "IPSEC in Tunnel mode";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);
	subtlv_print_ipsec_ta(stream, column_offset + 2, &bet->st_ipsec_ta);
}

static void print_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode(
	void *stream, int column_offset,
	struct bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode *bet)
{
	const char *type = "IP in IP Tunnel with IPSEC transport mode";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	subtlv_print_ipsec_ta(stream, column_offset + 2, &bet->st_ipsec_ta);
}

static void print_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode(
	void *stream, int column_offset,
	struct bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode *bet)
{
	const char *type = "MPLS in IP Tunnel with IPSEC transport mode";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	subtlv_print_ipsec_ta(stream, column_offset + 2, &bet->st_ipsec_ta);
}


static void print_encap_type_pbb(void *stream, int column_offset,
				 struct bgp_encap_type_pbb *bet)
{
	const char *type = "PBB";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	subtlv_print_encap_pbb(stream, column_offset + 2, &bet->st_encap);
}


static void print_encap_type_vxlan(void *stream, int column_offset,
				   struct bgp_encap_type_vxlan *bet)
{
	const char *type = "VXLAN";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	/* no subtlvs for this type */
}


static void print_encap_type_nvgre(void *stream, int column_offset,
				   struct bgp_encap_type_nvgre *bet)
{
	const char *type = "NVGRE";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	/* no subtlvs for this type */
}

static void print_encap_type_mpls(void *stream, int column_offset,
				  struct bgp_encap_type_mpls *bet)
{
	const char *type = "MPLS";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	/* no subtlvs for this type */
}

static void print_encap_type_mpls_in_gre(void *stream, int column_offset,
					 struct bgp_encap_type_mpls_in_gre *bet)
{
	const char *type = "MPLS in GRE";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	/* no subtlvs for this type */
}

static void print_encap_type_vxlan_gpe(void *stream, int column_offset,
				       struct bgp_encap_type_vxlan_gpe *bet)
{
	const char *type = "VXLAN GPE";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	/* no subtlvs for this type */
}

static void print_encap_type_mpls_in_udp(void *stream, int column_offset,
					 struct bgp_encap_type_mpls_in_udp *bet)
{
	const char *type = "MPLS in UDP";
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bet)
		return;

	fp(out, "%*sTEA type %s%s", column_offset, "", type, vty_newline);

	/* no subtlvs for this type */
}

void rfapi_print_tunneltype_option(void *stream, int column_offset,
				   struct rfapi_tunneltype_option *tto)
{
	switch (tto->type) {
	case BGP_ENCAP_TYPE_L2TPV3_OVER_IP:
		print_encap_type_l2tpv3overip(stream, column_offset,
					      &tto->bgpinfo.l2tpv3_ip);
		break;

	case BGP_ENCAP_TYPE_GRE:
		print_encap_type_gre(stream, column_offset, &tto->bgpinfo.gre);
		break;

	case BGP_ENCAP_TYPE_TRANSMIT_TUNNEL_ENDPOINT:
		print_encap_type_transmit_tunnel_endpoint(
			stream, column_offset,
			&tto->bgpinfo.transmit_tunnel_endpoint);
		break;

	case BGP_ENCAP_TYPE_IPSEC_IN_TUNNEL_MODE:
		print_encap_type_ipsec_in_tunnel_mode(
			stream, column_offset, &tto->bgpinfo.ipsec_tunnel);
		break;

	case BGP_ENCAP_TYPE_IP_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE:
		print_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode(
			stream, column_offset, &tto->bgpinfo.ip_ipsec);
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE:
		print_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode(
			stream, column_offset, &tto->bgpinfo.mpls_ipsec);
		break;

	case BGP_ENCAP_TYPE_IP_IN_IP:
		print_encap_type_ip_in_ip(stream, column_offset,
					  &tto->bgpinfo.ip_ip);
		break;

	case BGP_ENCAP_TYPE_VXLAN:
		print_encap_type_vxlan(stream, column_offset,
				       &tto->bgpinfo.vxlan);
		break;

	case BGP_ENCAP_TYPE_NVGRE:
		print_encap_type_nvgre(stream, column_offset,
				       &tto->bgpinfo.nvgre);
		break;

	case BGP_ENCAP_TYPE_MPLS:
		print_encap_type_mpls(stream, column_offset,
				      &tto->bgpinfo.mpls);
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_GRE:
		print_encap_type_mpls_in_gre(stream, column_offset,
					     &tto->bgpinfo.mpls_gre);
		break;

	case BGP_ENCAP_TYPE_VXLAN_GPE:
		print_encap_type_vxlan_gpe(stream, column_offset,
					   &tto->bgpinfo.vxlan_gpe);
		break;

	case BGP_ENCAP_TYPE_MPLS_IN_UDP:
		print_encap_type_mpls_in_udp(stream, column_offset,
					     &tto->bgpinfo.mpls_udp);
		break;

	case BGP_ENCAP_TYPE_PBB:
		print_encap_type_pbb(stream, column_offset, &tto->bgpinfo.pbb);
		break;

	default:
		assert(0);
	}
}
