/* Ethernet-VPN Packet and vty Processing File
   Copyright (C) 2017 6WIND

This file is part of Free Range Routing

Free Range Routing is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

Free Range Routing is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with Free Range Routing; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

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

#define L2VPN_HELP_STR        "Layer 2 Virtual Private Network\n"
#define EVPN_HELP_STR        "Ethernet Virtual Private Network\n"

#define SHOW_DISPLAY_STANDARD 0
#define SHOW_DISPLAY_TAGS 1
#define SHOW_DISPLAY_OVERLAY 2

static int
bgp_show_ethernet_vpn (struct vty *vty, struct prefix_rd *prd, enum bgp_show_type type,
		   void *output_arg, int option, u_char use_json)
{
  afi_t afi = AFI_L2VPN;
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  int rd_header;
  int header = 1;
  char v4_header[] = "   Network          Next Hop            Metric LocPrf Weight Path%s";
  char v4_header_tag[] = "   Network          Next Hop      In tag/Out tag%s";
  char v4_header_overlay[] = "   Network          Next Hop      EthTag    Overlay Index   RouterMac%s";

  unsigned long output_count = 0;
  unsigned long total_count  = 0;
  json_object *json = NULL;
  json_object *json_nroute = NULL;
  json_object *json_array = NULL;
  json_object *json_scode = NULL;
  json_object *json_ocode = NULL;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      if (!use_json)
        vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (use_json)
    {
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

  for (rn = bgp_table_top (bgp->rib[afi][SAFI_EVPN]); rn; rn = bgp_route_next (rn))
    {
      if (use_json)
        continue; /* XXX json TODO */

      if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
	continue;

      if ((table = rn->info) != NULL)
	{
	  rd_header = 1;

	  for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
	    for (ri = rm->info; ri; ri = ri->next)
	      {
                total_count++;
		if (type == bgp_show_type_neighbor)
		  {
		    union sockunion *su = output_arg;

		    if (ri->peer->su_remote == NULL || ! sockunion_same(ri->peer->su_remote, su))
		      continue;
		  }
                if (header == 0)
                  {
                    if (use_json)
                      {
                        if (option == SHOW_DISPLAY_TAGS)
                          {
                            json_object_int_add(json, "bgpTableVersion", 0);
                            json_object_string_add(json, "bgpLocalRouterId", inet_ntoa (bgp->router_id));
                            json_object_object_add(json, "bgpStatusCodes", json_scode);
                            json_object_object_add(json, "bgpOriginCodes", json_ocode);
                          }
                      }
                    else
                      {
                        if (option == SHOW_DISPLAY_TAGS)
                          vty_out (vty, v4_header_tag, VTY_NEWLINE);
                        else if (option == SHOW_DISPLAY_OVERLAY)
                          vty_out (vty, v4_header_overlay, VTY_NEWLINE);
                        else
                          {
                            vty_out (vty, "BGP table version is 0, local router ID is %s%s",
                                     inet_ntoa (bgp->router_id), VTY_NEWLINE);
                            vty_out (vty, "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal%s",
                                     VTY_NEWLINE);
                            vty_out (vty, "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s",
                                     VTY_NEWLINE, VTY_NEWLINE);
                            vty_out (vty, v4_header, VTY_NEWLINE);
                          }
                      }
                    header = 0;
                  }
                if (rd_header)
                  {
                    u_int16_t type;
                    struct rd_as rd_as;
                    struct rd_ip rd_ip;
                    u_char *pnt;

                    pnt = rn->p.u.val;

                    /* Decode RD type. */
                    type = decode_rd_type (pnt);
                    /* Decode RD value. */
                    if (type == RD_TYPE_AS)
                      decode_rd_as (pnt + 2, &rd_as);
                    else if (type == RD_TYPE_AS4)
                      decode_rd_as4 (pnt + 2, &rd_as);
                    else if (type == RD_TYPE_IP)
                      decode_rd_ip (pnt + 2, &rd_ip);
                    if (use_json)
                      {
                        char buffer[BUFSIZ];
                        if (type == RD_TYPE_AS || type == RD_TYPE_AS4)
                          sprintf (buffer, "%u:%d", rd_as.as, rd_as.val);
                        else if (type == RD_TYPE_IP)
                          sprintf (buffer, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
                        json_object_string_add(json_nroute, "routeDistinguisher", buffer);
                      }
                    else
                      {
                        vty_out (vty, "Route Distinguisher: ");
                        if (type == RD_TYPE_AS)
                          vty_out (vty, "as2 %u:%d", rd_as.as, rd_as.val);
                        else if (type == RD_TYPE_AS4)
                          vty_out (vty, "as4 %u:%d", rd_as.as, rd_as.val);
                        else if (type == RD_TYPE_IP)
                          vty_out (vty, "ip %s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
                        vty_out (vty, "%s", VTY_NEWLINE);
                      }
                    rd_header = 0;
                  }
                if (use_json)
                  json_array = json_object_new_array();
                else
                  json_array = NULL;
                if (option == SHOW_DISPLAY_TAGS)
                  route_vty_out_tag (vty, &rm->p, ri, 0, SAFI_EVPN, json_array);
                else if (option == SHOW_DISPLAY_OVERLAY)
                  route_vty_out_overlay (vty, &rm->p, ri, 0, json_array);
                else
                  route_vty_out (vty, &rm->p, ri, 0, SAFI_EVPN, json_array);
                output_count++;
              }
          /* XXX json */
        }
    }
  if (output_count == 0)
    vty_out (vty, "No prefixes displayed, %ld exist%s", total_count, VTY_NEWLINE);
  else
    vty_out (vty, "%sDisplayed %ld out of %ld total prefixes%s",
             VTY_NEWLINE, output_count, total_count, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_l2vpn_evpn,
       show_ip_bgp_l2vpn_evpn_cmd,
       "show [ip] bgp l2vpn evpn [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       L2VPN_HELP_STR
       EVPN_HELP_STR
       JSON_STR)
{
  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_normal, NULL, 0, use_json (argc, argv));
}

DEFUN (show_ip_bgp_l2vpn_evpn_rd,
       show_ip_bgp_l2vpn_evpn_rd_cmd,
       "show [ip] bgp l2vpn evpn rd ASN:nn_or_IP-address:nn [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       L2VPN_HELP_STR
       EVPN_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       JSON_STR)
{
  int idx_ext_community = 6;
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_ext_community]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_ethernet_vpn (vty, &prd, bgp_show_type_normal, NULL, 0, use_json (argc, argv));
}

DEFUN (show_ip_bgp_l2vpn_evpn_all_tags,
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
  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_normal, NULL,  1, 0);
}

DEFUN (show_ip_bgp_l2vpn_evpn_rd_tags,
       show_ip_bgp_l2vpn_evpn_rd_tags_cmd,
       "show [ip] bgp l2vpn evpn rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       IP_STR
       BGP_STR
       L2VPN_HELP_STR
       EVPN_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
  int idx_ext_community = 6;
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_ext_community]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_ethernet_vpn (vty,&prd, bgp_show_type_normal, NULL, 1, 0);
}

DEFUN (show_ip_bgp_l2vpn_evpn_all_neighbor_routes,
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
       "Display routes learned from neighbor\n"
       JSON_STR)
{
  int idx_ipv4 = 6;
  union sockunion su;
  struct peer *peer;
  int ret;
  u_char uj = use_json(argc, argv);

  ret = str2sockunion (argv[idx_ipv4]->arg, &su);
  if (ret < 0)
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "Malformed address");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "Malformed address: %s%s", argv[idx_ipv4]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "No such neighbor or address family");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_neighbor, &su, 0, uj);
}

DEFUN (show_ip_bgp_l2vpn_evpn_rd_neighbor_routes,
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
       "Display routes learned from neighbor\n"
       JSON_STR)
{
  int idx_ext_community = 6;
  int idx_ipv4 = 8;
  int ret;
  union sockunion su;
  struct peer *peer;
  struct prefix_rd prd;
  u_char uj = use_json(argc, argv);

  ret = str2prefix_rd (argv[idx_ext_community]->arg, &prd);
  if (! ret)
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "Malformed Route Distinguisher");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2sockunion (argv[idx_ipv4]->arg, &su);
  if (ret < 0)
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "Malformed address");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "Malformed address: %s%s", argv[idx_ext_community]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "No such neighbor or address family");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_ethernet_vpn (vty, &prd, bgp_show_type_neighbor, &su, 0, uj);
}

DEFUN (show_ip_bgp_l2vpn_evpn_all_neighbor_advertised_routes,
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
       "Display the routes advertised to a BGP neighbor\n"
       JSON_STR)
{
  int idx_ipv4 = 7;
  int ret;
  struct peer *peer;
  union sockunion su;
  u_char uj = use_json(argc, argv);

  ret = str2sockunion (argv[idx_ipv4]->arg, &su);
  if (ret < 0)
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "Malformed address");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "Malformed address: %s%s", argv[idx_ipv4]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "No such neighbor or address family");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_vpn (vty, peer, NULL, AFI_L2VPN, SAFI_EVPN, uj);
}

DEFUN (show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes,
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
       "Display the routes advertised to a BGP neighbor\n"
       JSON_STR)
{
  int idx_ext_community = 6;
  int idx_ipv4 = 8;
  int ret;
  struct peer *peer;
  struct prefix_rd prd;
  union sockunion su;
  u_char uj = use_json(argc, argv);

  ret = str2sockunion (argv[idx_ipv4]->arg, &su);
  if (ret < 0)
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "Malformed address");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "Malformed address: %s%s", argv[idx_ext_community]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_L2VPN][SAFI_EVPN])
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "No such neighbor or address family");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_rd (argv[idx_ext_community]->arg, &prd);
  if (! ret)
    {
      if (uj)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "Malformed Route Distinguisher");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_vpn (vty, peer, &prd, AFI_L2VPN, SAFI_EVPN, uj);
}

DEFUN (show_ip_bgp_l2vpn_evpn_all_overlay,
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
  return bgp_show_ethernet_vpn (vty, NULL, bgp_show_type_normal, NULL,
                                SHOW_DISPLAY_OVERLAY, use_json (argc, argv));
}

DEFUN (show_ip_bgp_evpn_rd_overlay,
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
  int idx_ext_community = 6;
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_ext_community]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_ethernet_vpn (vty, &prd, bgp_show_type_normal, NULL,
                                SHOW_DISPLAY_OVERLAY, use_json (argc, argv));
}


void
bgp_ethernetvpn_init (void)
{
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_rd_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_evpn_rd_overlay_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_l2vpn_evpn_all_overlay_cmd);
}
