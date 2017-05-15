/* Ethernet-VPN Packet and vty Processing File
 * Copyright (C) 2017 6WIND
 *
 * This file is part of FRRouting
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
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
#include "lib/json.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vpn.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_zebra.h"

#define SHOW_DISPLAY_STANDARD 0
#define SHOW_DISPLAY_TAGS 1
#define SHOW_DISPLAY_OVERLAY 2

static int
bgp_show_ethernet_vpn(struct vty *vty, struct prefix_rd *prd,
		      enum bgp_show_type type, void *output_arg, int option,
		      u_char use_json)
{
	afi_t afi = AFI_L2VPN;
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_node *rn;
	struct bgp_node *rm;
	struct bgp_info *ri;
	int rd_header;
	int header = 1;

	unsigned long output_count = 0;
	unsigned long total_count = 0;
	json_object *json = NULL;
	json_object *json_nroute = NULL;
	json_object *json_array = NULL;
	json_object *json_scode = NULL;
	json_object *json_ocode = NULL;

	bgp = bgp_get_default();
	if (bgp == NULL) {
		if (!use_json)
			vty_outln (vty,"No BGP process is configured");
		return CMD_WARNING;
	}

	if (use_json) {
		json_scode = json_object_new_object();
		json_ocode = json_object_new_object();
		json = json_object_new_object();
		json_nroute = json_object_new_object();

		json_object_string_add(json_scode, "suppressed", "s");
		json_object_string_add(json_scode, "damped", "d");
		json_object_string_add(json_scode, "history", "h");
		json_object_string_add(json_scode, "valid", "*");
		json_object_string_add(json_scode, "best", ">");
		json_object_string_add(json_scode, "internal", "i");

		json_object_string_add(json_ocode, "igp", "i");
		json_object_string_add(json_ocode, "egp", "e");
		json_object_string_add(json_ocode, "incomplete", "?");
	}

	for (rn = bgp_table_top(bgp->rib[afi][SAFI_EVPN]); rn;
	     rn = bgp_route_next(rn)) {
		if (use_json)
			continue;	/* XXX json TODO */

		if (prd && memcmp(rn->p.u.val, prd->val, 8) != 0)
			continue;

		if ((table = rn->info) != NULL) {
			rd_header = 1;

			for (rm = bgp_table_top(table); rm;
			     rm = bgp_route_next(rm))
				for (ri = rm->info; ri; ri = ri->next) {
					total_count++;
					if (type == bgp_show_type_neighbor) {
						union sockunion *su =
						    output_arg;

						if (ri->peer->su_remote == NULL
						    || !sockunion_same(ri->
								       peer->
								       su_remote,
								       su))
							continue;
					}
					if (header == 0) {
						if (use_json) {
							if (option ==
							    SHOW_DISPLAY_TAGS) {
								json_object_int_add
								    (json,
								     "bgpTableVersion",
								     0);
								json_object_string_add
								    (json,
								     "bgpLocalRouterId",
								     inet_ntoa
								     (bgp->
								      router_id));
								json_object_object_add
								    (json,
								     "bgpStatusCodes",
								     json_scode);
								json_object_object_add
								    (json,
								     "bgpOriginCodes",
								     json_ocode);
							}
						} else {
							if (option ==
							    SHOW_DISPLAY_TAGS)
								vty_outln(vty, V4_HEADER_TAG);
							else if (option ==
								 SHOW_DISPLAY_OVERLAY)
								vty_outln(vty, V4_HEADER_OVERLAY);
							else {
								vty_outln (vty,
									"BGP table version is 0, local router ID is %s",
									inet_ntoa(bgp->router_id));
								vty_outln (vty,
									"Status codes: s suppressed, d damped, h history, * valid, > best, i - internal");
								vty_outln (vty,
									"Origin codes: i - IGP, e - EGP, ? - incomplete%s",
									VTYNL);
								vty_outln(vty, V4_HEADER);
							}
						}
						header = 0;
					}
					if (rd_header) {
						u_int16_t type;
						struct rd_as rd_as;
						struct rd_ip rd_ip;
						u_char *pnt;

						pnt = rn->p.u.val;

						/* Decode RD type. */
						type = decode_rd_type(pnt);
						/* Decode RD value. */
						if (type == RD_TYPE_AS)
							decode_rd_as(pnt + 2,
								     &rd_as);
						else if (type == RD_TYPE_AS4)
							decode_rd_as4(pnt + 2,
								      &rd_as);
						else if (type == RD_TYPE_IP)
							decode_rd_ip(pnt + 2,
								     &rd_ip);
						if (use_json) {
							char buffer[BUFSIZ];
							if (type == RD_TYPE_AS
							    || type ==
							    RD_TYPE_AS4)
								sprintf(buffer,
									"%u:%d",
									rd_as.
									as,
									rd_as.
									val);
							else if (type ==
								 RD_TYPE_IP)
								sprintf(buffer,
									"%s:%d",
									inet_ntoa
									(rd_ip.
									 ip),
									rd_ip.
									val);
							json_object_string_add
							    (json_nroute,
							     "routeDistinguisher",
							     buffer);
						} else {
							vty_out(vty,
								"Route Distinguisher: ");
							if (type == RD_TYPE_AS)
								vty_out(vty,
									"as2 %u:%d",
									rd_as.
									as,
									rd_as.
									val);
							else if (type ==
								 RD_TYPE_AS4)
								vty_out(vty,
									"as4 %u:%d",
									rd_as.
									as,
									rd_as.
									val);
							else if (type ==
								 RD_TYPE_IP)
								vty_out(vty,
									"ip %s:%d",
									inet_ntoa
									(rd_ip.
									 ip),
									rd_ip.
									val);
							vty_outln (vty, VTYNL);
						}
						rd_header = 0;
					}
					if (use_json)
						json_array =
						    json_object_new_array();
					else
						json_array = NULL;
					if (option == SHOW_DISPLAY_TAGS)
						route_vty_out_tag(vty, &rm->p,
								  ri, 0,
								  SAFI_EVPN,
								  json_array);
					else if (option == SHOW_DISPLAY_OVERLAY)
						route_vty_out_overlay(vty,
								      &rm->p,
								      ri, 0,
								      json_array);
					else
						route_vty_out(vty, &rm->p, ri,
							      0, SAFI_EVPN,
							      json_array);
					output_count++;
				}
			/* XXX json */
		}
	}
	if (output_count == 0)
		vty_outln (vty, "No prefixes displayed, %ld exist",
			  total_count);
	else
		vty_outln (vty, "%sDisplayed %ld out of %ld total prefixes",
			VTYNL, output_count, total_count);
	return CMD_SUCCESS;
}

DEFUN(show_ip_bgp_l2vpn_evpn,
      show_ip_bgp_l2vpn_evpn_cmd,
      "show [ip] bgp l2vpn evpn [json]",
      SHOW_STR IP_STR BGP_STR L2VPN_HELP_STR EVPN_HELP_STR JSON_STR)
{
	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal, NULL, 0,
				     use_json(argc, argv));
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd,
      show_ip_bgp_l2vpn_evpn_rd_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:nn_or_IP-address:nn [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n" JSON_STR)
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;

	argv_find (argv, argc, "ASN:nn_or_IP-address:nn", &idx_ext_community);

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		vty_outln (vty, "%% Malformed Route Distinguisher");
		return CMD_WARNING;
	}
	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_normal, NULL, 0,
				     use_json(argc, argv));
}

DEFUN(show_ip_bgp_l2vpn_evpn_all_tags,
      show_ip_bgp_l2vpn_evpn_all_tags_cmd,
      "show [ip] bgp l2vpn evpn all tags",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Display BGP tags for prefixes\n")
{
	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal, NULL, 1,
				     0);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_tags,
      show_ip_bgp_l2vpn_evpn_rd_tags_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:nn_or_IP-address:nn tags",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n" "Display BGP tags for prefixes\n")
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;

	argv_find (argv, argc, "ASN:nn_or_IP-address:nn", &idx_ext_community);

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		vty_outln (vty, "%% Malformed Route Distinguisher");
		return CMD_WARNING;
	}
	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_normal, NULL, 1,
				     0);
}

DEFUN(show_ip_bgp_l2vpn_evpn_all_neighbor_routes,
      show_ip_bgp_l2vpn_evpn_all_neighbor_routes_cmd,
      "show [ip] bgp l2vpn evpn all neighbors A.B.C.D routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Display routes learned from neighbor\n" JSON_STR)
{
	int idx_ipv4 = 0;
	union sockunion su;
	struct peer *peer;
	int ret;
	u_char uj = use_json(argc, argv);

	argv_find (argv, argc, "A.B.C.D", &idx_ipv4);

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty, "Malformed address: %s",
				argv[idx_ipv4]->arg);
		return CMD_WARNING;
	}

	peer = peer_lookup(NULL, &su);
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor or address family");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty,
				  "%% No such neighbor or address family");
		return CMD_WARNING;
	}

	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_neighbor, &su, 0,
				     uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_neighbor_routes,
      show_ip_bgp_l2vpn_evpn_rd_neighbor_routes_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:nn_or_IP-address:nn neighbors A.B.C.D routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Display routes learned from neighbor\n" JSON_STR)
{
	int idx_ext_community = 0;
	int idx_ipv4 = 0;
	int ret;
	union sockunion su;
	struct peer *peer;
	struct prefix_rd prd;
	u_char uj = use_json(argc, argv);

	argv_find (argv, argc, "ASN:nn_or_IP-address:nn", &idx_ext_community);
	argv_find (argv, argc, "A.B.C.D", &idx_ipv4);

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed Route Distinguisher");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty,"%% Malformed Route Distinguisher");
		return CMD_WARNING;
	}

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty, "Malformed address: %s",
				argv[idx_ext_community]->arg);
		return CMD_WARNING;
	}

	peer = peer_lookup(NULL, &su);
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor or address family");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty,
				  "%% No such neighbor or address family");
		return CMD_WARNING;
	}

	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_neighbor, &su, 0,
				     uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_all_neighbor_advertised_routes,
      show_ip_bgp_l2vpn_evpn_all_neighbor_advertised_routes_cmd,
      "show [ip] bgp l2vpn evpn all neighbors A.B.C.D advertised-routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Display the routes advertised to a BGP neighbor\n" JSON_STR)
{
	int idx_ipv4 = 0;
	int ret;
	struct peer *peer;
	union sockunion su;
	u_char uj = use_json(argc, argv);

	argv_find (argv, argc, "A.B.C.D", &idx_ipv4);

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty, "Malformed address: %s",
				argv[idx_ipv4]->arg);
		return CMD_WARNING;
	}
	peer = peer_lookup(NULL, &su);
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor or address family");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty,
				  "%% No such neighbor or address family");
		return CMD_WARNING;
	}

	return show_adj_route_vpn(vty, peer, NULL, AFI_L2VPN, SAFI_EVPN, uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes,
      show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:nn_or_IP-address:nn neighbors A.B.C.D advertised-routes [json]",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Display the routes advertised to a BGP neighbor\n" JSON_STR)
{
	int idx_ext_community = 0;
	int idx_ipv4 = 0;
	int ret;
	struct peer *peer;
	struct prefix_rd prd;
	union sockunion su;
	u_char uj = use_json(argc, argv);

	argv_find (argv, argc, "ASN:nn_or_IP-address:nn", &idx_ext_community);
	argv_find (argv, argc, "A.B.C.D", &idx_ipv4);

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty, "Malformed address: %s",
				argv[idx_ext_community]->arg);
		return CMD_WARNING;
	}
	peer = peer_lookup(NULL, &su);
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor or address family");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty,
				  "%% No such neighbor or address family");
		return CMD_WARNING;
	}

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed Route Distinguisher");
			vty_outln (vty, "%s",
				json_object_to_json_string(json_no));
			json_object_free(json_no);
		} else
			vty_outln (vty,"%% Malformed Route Distinguisher");
		return CMD_WARNING;
	}

	return show_adj_route_vpn(vty, peer, &prd, AFI_L2VPN, SAFI_EVPN, uj);
}

DEFUN(show_ip_bgp_l2vpn_evpn_all_overlay,
      show_ip_bgp_l2vpn_evpn_all_overlay_cmd,
      "show [ip] bgp l2vpn evpn all overlay",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information about all EVPN NLRIs\n"
      "Display BGP Overlay Information for prefixes\n")
{
	return bgp_show_ethernet_vpn(vty, NULL, bgp_show_type_normal, NULL,
				     SHOW_DISPLAY_OVERLAY, use_json(argc,
								    argv));
}

DEFUN(show_ip_bgp_evpn_rd_overlay,
      show_ip_bgp_evpn_rd_overlay_cmd,
      "show [ip] bgp l2vpn evpn rd ASN:nn_or_IP-address:nn overlay",
      SHOW_STR
      IP_STR
      BGP_STR
      L2VPN_HELP_STR
      EVPN_HELP_STR
      "Display information for a route distinguisher\n"
      "VPN Route Distinguisher\n"
      "Display BGP Overlay Information for prefixes\n")
{
	int idx_ext_community = 0;
	int ret;
	struct prefix_rd prd;

	argv_find (argv, argc, "ASN:nn_or_IP-address:nn", &idx_ext_community);

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		vty_outln (vty, "%% Malformed Route Distinguisher");
		return CMD_WARNING;
	}
	return bgp_show_ethernet_vpn(vty, &prd, bgp_show_type_normal, NULL,
				     SHOW_DISPLAY_OVERLAY, use_json(argc,
								    argv));
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN(evpnrt5_network,
      evpnrt5_network_cmd,
      "network <A.B.C.D/M|X:X::X:X/M> rd ASN:nn_or_IP-address:nn ethtag WORD label WORD esi WORD gwip <A.B.C.D|X:X::X:X> routermac WORD [route-map WORD]",
      "Specify a network to announce via BGP\n"
      "IP prefix\n"
      "IPv6 prefix\n"
      "Specify Route Distinguisher\n"
      "VPN Route Distinguisher\n"
      "Ethernet Tag\n"
      "Ethernet Tag Value\n"
      "BGP label\n"
      "label value\n"
      "Ethernet Segment Identifier\n"
      "ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
      "Gateway IP\n"
      "Gateway IP ( A.B.C.D )\n"
      "Gateway IPv6 ( X:X::X:X )\n"
      "Router Mac Ext Comm\n"
      "Router Mac address Value ( aa:bb:cc:dd:ee:ff format)\n"
      "Route-map to modify the attributes\n"
      "Name of the route map\n")
{
	int idx_ipv4_prefixlen = 1;
	int idx_ext_community = 3;
	int idx_word = 7;
	int idx_esi = 9;
	int idx_gwip = 11;
	int idx_ethtag = 5;
	int idx_routermac = 13;
	int idx_rmap = 15;
	return bgp_static_set_safi(AFI_L2VPN, SAFI_EVPN, vty,
				   argv[idx_ipv4_prefixlen]->arg,
				   argv[idx_ext_community]->arg,
				   argv[idx_word]->arg,
				   argv[idx_rmap] ? argv[idx_gwip]->arg : NULL,
				   EVPN_IP_PREFIX, argv[idx_esi]->arg,
				   argv[idx_gwip]->arg, argv[idx_ethtag]->arg,
				   argv[idx_routermac]->arg);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN(no_evpnrt5_network,
      no_evpnrt5_network_cmd,
      "no network <A.B.C.D/M|X:X::X:X/M> rd ASN:nn_or_IP-address:nn ethtag WORD label WORD esi WORD gwip <A.B.C.D|X:X::X:X>",
      NO_STR
      "Specify a network to announce via BGP\n"
      "IP prefix\n"
      "IPv6 prefix\n"
      "Specify Route Distinguisher\n"
      "VPN Route Distinguisher\n"
      "Ethernet Tag\n"
      "Ethernet Tag Value\n"
      "BGP label\n"
      "label value\n"
      "Ethernet Segment Identifier\n"
      "ESI value ( 00:11:22:33:44:55:66:77:88:99 format) \n"
      "Gateway IP\n" "Gateway IP ( A.B.C.D )\n" "Gateway IPv6 ( X:X::X:X )\n")
{
	int idx_ipv4_prefixlen = 2;
	int idx_ext_community = 4;
	int idx_label = 8;
	int idx_ethtag = 6;
	int idx_esi = 10;
	int idx_gwip = 12;
	return bgp_static_unset_safi(AFI_L2VPN, SAFI_EVPN, vty,
				     argv[idx_ipv4_prefixlen]->arg,
				     argv[idx_ext_community]->arg,
				     argv[idx_label]->arg, EVPN_IP_PREFIX,
				     argv[idx_esi]->arg, argv[idx_gwip]->arg,
				     argv[idx_ethtag]->arg);
}

/*
 * EVPN (VNI advertisement) enabled. Register with zebra.
 */
static void
evpn_set_advertise_all_vni (struct bgp *bgp)
{
  bgp->advertise_all_vni = 1;
  bgp_zebra_advertise_all_vni (bgp, bgp->advertise_all_vni);
}

/*
 * EVPN (VNI advertisement) disabled. De-register with zebra. Cleanup VNI
 * cache, EVPN routes (delete and withdraw from peers).
 */
static void
evpn_unset_advertise_all_vni (struct bgp *bgp)
{
  bgp->advertise_all_vni = 0;
  bgp_zebra_advertise_all_vni (bgp, bgp->advertise_all_vni);
  bgp_evpn_cleanup_on_disable (bgp);
}

DEFUN (bgp_evpn_advertise_all_vni,
       bgp_evpn_advertise_all_vni_cmd,
       "advertise-all-vni",
       "Advertise All local VNIs\n")
{
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);

  if (!bgp)
    return CMD_WARNING;
  evpn_set_advertise_all_vni (bgp);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_advertise_all_vni,
       no_bgp_evpn_advertise_all_vni_cmd,
       "no advertise-all-vni",
       NO_STR
       "Advertise All local VNIs\n")
{
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);

  if (!bgp)
    return CMD_WARNING;
  evpn_unset_advertise_all_vni (bgp);
  return CMD_SUCCESS;
}

void bgp_ethernetvpn_init(void)
{
  install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_cmd);
  install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_cmd);
  install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_tags_cmd);
  install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_tags_cmd);
  install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_neighbor_routes_cmd);
  install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_neighbor_routes_cmd);
  install_element(VIEW_NODE,
                  &show_ip_bgp_l2vpn_evpn_all_neighbor_advertised_routes_cmd);
  install_element(VIEW_NODE,
                  &show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes_cmd);
  install_element(VIEW_NODE, &show_ip_bgp_evpn_rd_overlay_cmd);
  install_element(VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_overlay_cmd);
  install_element(BGP_EVPN_NODE, &no_evpnrt5_network_cmd);
  install_element(BGP_EVPN_NODE, &evpnrt5_network_cmd);
  install_element (BGP_EVPN_NODE, &bgp_evpn_advertise_all_vni_cmd);
  install_element (BGP_EVPN_NODE, &no_bgp_evpn_advertise_all_vni_cmd);
}
