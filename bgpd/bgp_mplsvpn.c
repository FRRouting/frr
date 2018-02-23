/* MPLS-VPN
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "queue.h"
#include "filter.h"
#include "lib/json.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_vpn.h"

#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

extern int argv_find_and_parse_vpnvx(struct cmd_token **argv, int argc,
				     int *index, afi_t *afi)
{
	int ret = 0;
	if (argv_find(argv, argc, "vpnv4", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP;
	} else if (argv_find(argv, argc, "vpnv6", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP6;
	}
	return ret;
}

u_int32_t decode_label(mpls_label_t *label_pnt)
{
	u_int32_t l;
	u_char *pnt = (u_char *)label_pnt;

	l = ((u_int32_t)*pnt++ << 12);
	l |= (u_int32_t)*pnt++ << 4;
	l |= (u_int32_t)((*pnt & 0xf0) >> 4);
	return l;
}

void encode_label(mpls_label_t label, mpls_label_t *label_pnt)
{
	u_char *pnt = (u_char *)label_pnt;
	if (pnt == NULL)
		return;
	*pnt++ = (label >> 12) & 0xff;
	*pnt++ = (label >> 4) & 0xff;
	*pnt++ = ((label << 4) + 1) & 0xff; /* S=1 */
}

int bgp_nlri_parse_vpn(struct peer *peer, struct attr *attr,
		       struct bgp_nlri *packet)
{
	u_char *pnt;
	u_char *lim;
	struct prefix p;
	int psize = 0;
	int prefixlen;
	u_int16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	struct prefix_rd prd;
	mpls_label_t label;
	afi_t afi;
	safi_t safi;
	int addpath_encoded;
	u_int32_t addpath_id;

	/* Check peer status. */
	if (peer->status != Established)
		return 0;

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_encoded =
		(CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV)
		 && CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ADDPATH_AF_TX_RCV));

#define VPN_PREFIXLEN_MIN_BYTES (3 + 8) /* label + RD */
	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(struct prefix));

		if (addpath_encoded) {

			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return -1;

			addpath_id = ntohl(*((uint32_t *)pnt));
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Fetch prefix length. */
		prefixlen = *pnt++;
		p.family = afi2family(packet->afi);
		psize = PSIZE(prefixlen);

		if (prefixlen < VPN_PREFIXLEN_MIN_BYTES * 8) {
			zlog_err(
				"%s [Error] Update packet error / VPN (prefix length %d less than VPN min length)",
				peer->host, prefixlen);
			return -1;
		}

		/* sanity check against packet data */
		if ((pnt + psize) > lim) {
			zlog_err(
				"%s [Error] Update packet error / VPN (prefix length %d exceeds packet size %u)",
				peer->host, prefixlen, (uint)(lim - pnt));
			return -1;
		}

		/* sanity check against storage for the IP address portion */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > (ssize_t)sizeof(p.u)) {
			zlog_err(
				"%s [Error] Update packet error / VPN (psize %d exceeds storage size %zu)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				sizeof(p.u));
			return -1;
		}

		/* Sanity check against max bitlen of the address family */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > prefix_blen(&p)) {
			zlog_err(
				"%s [Error] Update packet error / VPN (psize %d exceeds family (%u) max byte len %u)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				p.family, prefix_blen(&p));
			return -1;
		}

		/* Copy label to prefix. */
		memcpy(&label, pnt, BGP_LABEL_BYTES);
		bgp_set_valid_label(&label);

		/* Copy routing distinguisher to rd. */
		memcpy(&prd.val, pnt + BGP_LABEL_BYTES, 8);

		/* Decode RD type. */
		type = decode_rd_type(pnt + BGP_LABEL_BYTES);

		switch (type) {
		case RD_TYPE_AS:
			decode_rd_as(pnt + 5, &rd_as);
			break;

		case RD_TYPE_AS4:
			decode_rd_as4(pnt + 5, &rd_as);
			break;

		case RD_TYPE_IP:
			decode_rd_ip(pnt + 5, &rd_ip);
			break;

#if ENABLE_BGP_VNC
		case RD_TYPE_VNC_ETH:
			break;
#endif

		default:
			zlog_err("Unknown RD type %d", type);
			break; /* just report */
		}

		p.prefixlen =
			prefixlen
			- VPN_PREFIXLEN_MIN_BYTES * 8; /* exclude label & RD */
		memcpy(&p.u.prefix, pnt + VPN_PREFIXLEN_MIN_BYTES,
		       psize - VPN_PREFIXLEN_MIN_BYTES);

		if (attr) {
			bgp_update(peer, &p, addpath_id, attr, packet->afi,
				   SAFI_MPLS_VPN, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, &prd, &label, 1, 0, NULL);
		} else {
			bgp_withdraw(peer, &p, addpath_id, attr, packet->afi,
				     SAFI_MPLS_VPN, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, &prd, &label, 1, NULL);
		}
	}
	/* Packet length consistency check. */
	if (pnt != lim) {
		zlog_err(
			"%s [Error] Update packet error / VPN (%zu data remaining after parsing)",
			peer->host, lim - pnt);
		return -1;
	}

	return 0;
#undef VPN_PREFIXLEN_MIN_BYTES
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (vpnv4_network,
       vpnv4_network_cmd,
       "network A.B.C.D/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575)",
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n")
{
	int idx_ipv4_prefixlen = 1;
	int idx_ext_community = 3;
	int idx_label = 5;
	return bgp_static_set_safi(
		AFI_IP, SAFI_MPLS_VPN, vty, argv[idx_ipv4_prefixlen]->arg,
		argv[idx_ext_community]->arg, argv[idx_label]->arg, NULL, 0,
		NULL, NULL, NULL, NULL);
}

DEFUN (vpnv4_network_route_map,
       vpnv4_network_route_map_cmd,
       "network A.B.C.D/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575) route-map WORD",
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n"
       "route map\n"
       "route map name\n")
{
	int idx_ipv4_prefixlen = 1;
	int idx_ext_community = 3;
	int idx_label = 5;
	int idx_word_2 = 7;
	return bgp_static_set_safi(
		AFI_IP, SAFI_MPLS_VPN, vty, argv[idx_ipv4_prefixlen]->arg,
		argv[idx_ext_community]->arg, argv[idx_label]->arg,
		argv[idx_word_2]->arg, 0, NULL, NULL, NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv4_network,
       no_vpnv4_network_cmd,
       "no network A.B.C.D/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575)",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n")
{
	int idx_ipv4_prefixlen = 2;
	int idx_ext_community = 4;
	int idx_label = 6;
	return bgp_static_unset_safi(AFI_IP, SAFI_MPLS_VPN, vty,
				     argv[idx_ipv4_prefixlen]->arg,
				     argv[idx_ext_community]->arg,
				     argv[idx_label]->arg, 0, NULL, NULL, NULL);
}

DEFUN (vpnv6_network,
       vpnv6_network_cmd,
       "network X:X::X:X/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575) [route-map WORD]",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n"
       "route map\n"
       "route map name\n")
{
	int idx_ipv6_prefix = 1;
	int idx_ext_community = 3;
	int idx_label = 5;
	int idx_word_2 = 7;
	if (argc == 8)
		return bgp_static_set_safi(
			AFI_IP6, SAFI_MPLS_VPN, vty, argv[idx_ipv6_prefix]->arg,
			argv[idx_ext_community]->arg, argv[idx_label]->arg,
			argv[idx_word_2]->arg, 0, NULL, NULL, NULL, NULL);
	else
		return bgp_static_set_safi(
			AFI_IP6, SAFI_MPLS_VPN, vty, argv[idx_ipv6_prefix]->arg,
			argv[idx_ext_community]->arg, argv[idx_label]->arg,
			NULL, 0, NULL, NULL, NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv6_network,
       no_vpnv6_network_cmd,
       "no network X:X::X:X/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575)",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n")
{
	int idx_ipv6_prefix = 2;
	int idx_ext_community = 4;
	int idx_label = 6;
	return bgp_static_unset_safi(AFI_IP6, SAFI_MPLS_VPN, vty,
				     argv[idx_ipv6_prefix]->arg,
				     argv[idx_ext_community]->arg,
				     argv[idx_label]->arg, 0, NULL, NULL, NULL);
}

int bgp_show_mpls_vpn(struct vty *vty, afi_t afi, struct prefix_rd *prd,
		      enum bgp_show_type type, void *output_arg, int tags,
		      u_char use_json)
{
	struct bgp *bgp;
	struct bgp_table *table;

	bgp = bgp_get_default();
	if (bgp == NULL) {
		if (!use_json)
			vty_out(vty, "No BGP process is configured\n");
		else
			vty_out(vty, "{}\n");
		return CMD_WARNING;
	}
	table = bgp->rib[afi][SAFI_MPLS_VPN];
	return bgp_show_table_rd(vty, bgp, SAFI_MPLS_VPN, table, prd, type,
				 output_arg, use_json);
}

DEFUN (show_bgp_ip_vpn_all_rd,
       show_bgp_ip_vpn_all_rd_cmd,
       "show bgp "BGP_AFI_CMD_STR" vpn all [rd ASN:NN_OR_IP-ADDRESS:NN] [json]",
       SHOW_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display VPN NLRI specific information\n"
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       JSON_STR)
{
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		if (argv_find(argv, argc, "rd", &idx)) {
			ret = str2prefix_rd(argv[idx + 1]->arg, &prd);
			if (!ret) {
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
				return CMD_WARNING;
			}
			return bgp_show_mpls_vpn(vty, afi, &prd,
						 bgp_show_type_normal, NULL, 0,
						 use_json(argc, argv));
		} else {
			return bgp_show_mpls_vpn(vty, afi, NULL,
						 bgp_show_type_normal, NULL, 0,
						 use_json(argc, argv));
		}
	}
	return CMD_SUCCESS;
}

ALIAS(show_bgp_ip_vpn_all_rd,
      show_bgp_ip_vpn_rd_cmd,
       "show bgp "BGP_AFI_CMD_STR" vpn rd ASN:NN_OR_IP-ADDRESS:NN [json]",
       SHOW_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       JSON_STR)

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN (show_ip_bgp_vpn_rd,
       show_ip_bgp_vpn_rd_cmd,
       "show ip bgp "BGP_AFI_CMD_STR" vpn rd ASN:NN_OR_IP-ADDRESS:NN",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_AFI_HELP_STR
       "Address Family modifier\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")
{
	int idx_ext_community = argc - 1;
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
		return bgp_show_mpls_vpn(vty, afi, &prd, bgp_show_type_normal,
					 NULL, 0, 0);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_all,
       show_ip_bgp_vpn_all_cmd,
       "show [ip] bgp <vpnv4|vpnv6>",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR)
{
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi))
		return bgp_show_mpls_vpn(vty, afi, NULL, bgp_show_type_normal,
					 NULL, 0, 0);
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_all_tags,
       show_ip_bgp_vpn_all_tags_cmd,
       "show [ip] bgp <vpnv4|vpnv6> all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information about all VPNv4/VPNV6 NLRIs\n"
       "Display BGP tags for prefixes\n")
{
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi))
		return bgp_show_mpls_vpn(vty, afi, NULL, bgp_show_type_normal,
					 NULL, 1, 0);
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_rd_tags,
       show_ip_bgp_vpn_rd_tags_cmd,
       "show [ip] bgp <vpnv4|vpnv6> rd ASN:NN_OR_IP-ADDRESS:NN tags",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
	int idx_ext_community = 5;
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
		return bgp_show_mpls_vpn(vty, afi, &prd, bgp_show_type_normal,
					 NULL, 1, 0);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_all_neighbor_routes,
       show_ip_bgp_vpn_all_neighbor_routes_cmd,
       "show [ip] bgp <vpnv4|vpnv6> all neighbors A.B.C.D routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information about all VPNv4/VPNv6 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n"
       JSON_STR)
{
	int idx_ipv4 = 6;
	union sockunion su;
	struct peer *peer;
	int ret;
	u_char uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2sockunion(argv[idx_ipv4]->arg, &su);
		if (ret < 0) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(json_no, "warning",
						       "Malformed address");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty, "Malformed address: %s\n",
					argv[idx_ipv4]->arg);
			return CMD_WARNING;
		}

		peer = peer_lookup(NULL, &su);
		if (!peer || !peer->afc[afi][SAFI_MPLS_VPN]) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"No such neighbor or address family");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% No such neighbor or address family\n");
			return CMD_WARNING;
		}

		return bgp_show_mpls_vpn(vty, afi, NULL, bgp_show_type_neighbor,
					 &su, 0, uj);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_rd_neighbor_routes,
       show_ip_bgp_vpn_rd_neighbor_routes_cmd,
       "show [ip] bgp <vpnv4|vpnv6> rd ASN:NN_OR_IP-ADDRESS:NN neighbors A.B.C.D routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n"
       JSON_STR)
{
	int idx_ext_community = 5;
	int idx_ipv4 = 7;
	int ret;
	union sockunion su;
	struct peer *peer;
	struct prefix_rd prd;
	u_char uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"Malformed Route Distinguisher");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}

		ret = str2sockunion(argv[idx_ipv4]->arg, &su);
		if (ret < 0) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(json_no, "warning",
						       "Malformed address");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty, "Malformed address: %s\n",
					argv[idx_ext_community]->arg);
			return CMD_WARNING;
		}

		peer = peer_lookup(NULL, &su);
		if (!peer || !peer->afc[afi][SAFI_MPLS_VPN]) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"No such neighbor or address family");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% No such neighbor or address family\n");
			return CMD_WARNING;
		}

		return bgp_show_mpls_vpn(vty, afi, &prd, bgp_show_type_neighbor,
					 &su, 0, uj);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_all_neighbor_advertised_routes,
       show_ip_bgp_vpn_all_neighbor_advertised_routes_cmd,
       "show [ip] bgp <vpnv4|vpnv6> all neighbors A.B.C.D advertised-routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information about all VPNv4/VPNv6 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n"
       JSON_STR)
{
	int idx_ipv4 = 6;
	int ret;
	struct peer *peer;
	union sockunion su;
	u_char uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2sockunion(argv[idx_ipv4]->arg, &su);
		if (ret < 0) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(json_no, "warning",
						       "Malformed address");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty, "Malformed address: %s\n",
					argv[idx_ipv4]->arg);
			return CMD_WARNING;
		}
		peer = peer_lookup(NULL, &su);
		if (!peer || !peer->afc[afi][SAFI_MPLS_VPN]) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"No such neighbor or address family");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% No such neighbor or address family\n");
			return CMD_WARNING;
		}
		return show_adj_route_vpn(vty, peer, NULL, AFI_IP,
					  SAFI_MPLS_VPN, uj);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_rd_neighbor_advertised_routes,
       show_ip_bgp_vpn_rd_neighbor_advertised_routes_cmd,
       "show [ip] bgp <vpnv4|vpnv6> rd ASN:NN_OR_IP-ADDRESS:NN neighbors A.B.C.D advertised-routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n"
       JSON_STR)
{
	int idx_ext_community = 5;
	int idx_ipv4 = 7;
	int ret;
	struct peer *peer;
	struct prefix_rd prd;
	union sockunion su;
	u_char uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2sockunion(argv[idx_ipv4]->arg, &su);
		if (ret < 0) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(json_no, "warning",
						       "Malformed address");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty, "Malformed address: %s\n",
					argv[idx_ext_community]->arg);
			return CMD_WARNING;
		}
		peer = peer_lookup(NULL, &su);
		if (!peer || !peer->afc[afi][SAFI_MPLS_VPN]) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"No such neighbor or address family");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% No such neighbor or address family\n");
			return CMD_WARNING;
		}

		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"Malformed Route Distinguisher");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}

		return show_adj_route_vpn(vty, peer, &prd, AFI_IP,
					  SAFI_MPLS_VPN, uj);
	}
	return CMD_SUCCESS;
}
#endif /* KEEP_OLD_VPN_COMMANDS */

void bgp_mplsvpn_init(void)
{
	install_element(BGP_VPNV4_NODE, &vpnv4_network_cmd);
	install_element(BGP_VPNV4_NODE, &vpnv4_network_route_map_cmd);
	install_element(BGP_VPNV4_NODE, &no_vpnv4_network_cmd);

	install_element(BGP_VPNV6_NODE, &vpnv6_network_cmd);
	install_element(BGP_VPNV6_NODE, &no_vpnv6_network_cmd);

	install_element(VIEW_NODE, &show_bgp_ip_vpn_all_rd_cmd);
	install_element(VIEW_NODE, &show_bgp_ip_vpn_rd_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(VIEW_NODE, &show_ip_bgp_vpn_rd_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_all_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_all_tags_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_rd_tags_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_all_neighbor_routes_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_rd_neighbor_routes_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_vpn_all_neighbor_advertised_routes_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_vpn_rd_neighbor_advertised_routes_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
}
