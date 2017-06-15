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
#include "bgpd/bgp_vty.h"

#define SHOW_DISPLAY_STANDARD 0
#define SHOW_DISPLAY_TAGS 1
#define SHOW_DISPLAY_OVERLAY 2

/*
 * Context for VNI hash walk - used by callbacks.
 */
struct vni_walk_ctx
{
  struct bgp *bgp;
  struct vty *vty;
  struct in_addr vtep_ip;
};

struct evpn_config_write
{
  int write;
  struct vty *vty;
};

static void
display_import_rt (struct vty *vty, struct irt_node *irt)
{
  u_char *pnt;
  u_char type, sub_type;
  struct ecommunity_as
  {
    as_t as;
    u_int32_t val;
  } eas;
  struct ecommunity_ip
  {
    struct in_addr ip;
    u_int16_t val;
  } eip;
  struct listnode *node, *nnode;
  struct bgpevpn *tmp_vpn;


  /* TODO: This needs to go into a function */

  pnt = (u_char *)&irt->rt.val;
  type = *pnt++;
  sub_type = *pnt++;
  if (sub_type != ECOMMUNITY_ROUTE_TARGET)
    return;

  switch (type)
    {
      case ECOMMUNITY_ENCODE_AS:
        eas.as = (*pnt++ << 8);
        eas.as |= (*pnt++);

        eas.val = (*pnt++ << 24);
        eas.val |= (*pnt++ << 16);
        eas.val |= (*pnt++ << 8);
        eas.val |= (*pnt++);

        vty_out (vty, "Route-target: %u:%u", eas.as, eas.val);
        break;

      case ECOMMUNITY_ENCODE_IP:
        memcpy (&eip.ip, pnt, 4);
        pnt += 4;
        eip.val = (*pnt++ << 8);
        eip.val |= (*pnt++);

        vty_out (vty, "Route-target: %s:%u",
                 inet_ntoa (eip.ip), eip.val);
        break;

      case ECOMMUNITY_ENCODE_AS4:
        eas.as = (*pnt++ << 24);
        eas.as |= (*pnt++ << 16);
        eas.as |= (*pnt++ << 8);
        eas.as |= (*pnt++);

        eas.val = (*pnt++ << 8);
        eas.val |= (*pnt++);

        vty_out (vty, "Route-target: %u:%u", eas.as, eas.val);
        break;

      default:
        return;
    }

  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "List of VNIs importing routes with this route-target:%s",
           VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS (irt->vnis, node, nnode, tmp_vpn))
    vty_out (vty, "  %u%s", tmp_vpn->vni, VTY_NEWLINE);
}

static void
show_import_rt_entry (struct hash_backet *backet, struct vty *vty)
{
  struct irt_node *irt = (struct irt_node *) backet->data;
  display_import_rt (vty, irt);
}

static void
bgp_evpn_show_route_rd_header (struct vty *vty, struct bgp_node *rd_rn)
{
  u_int16_t type;
  struct rd_as rd_as;
  struct rd_ip rd_ip;
  u_char *pnt;

  pnt = rd_rn->p.u.val;

  /* Decode RD type. */
  type = decode_rd_type (pnt);

  vty_out (vty, "Route Distinguisher: ");

  switch (type)
    {
      case RD_TYPE_AS:
        decode_rd_as (pnt + 2, &rd_as);
        vty_out (vty, "%u:%d", rd_as.as, rd_as.val);
        break;

      case RD_TYPE_IP:
        decode_rd_ip (pnt + 2, &rd_ip);
        vty_out (vty, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
        break;

      default:
        vty_out (vty, "Unknown RD type");
        break;
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}

static void
bgp_evpn_show_route_header (struct vty *vty, struct bgp *bgp)
{
  char ri_header[] = "   Network          Next Hop            Metric LocPrf Weight Path%s";

  vty_out (vty, "BGP table version is 0, local router ID is %s%s",
           inet_ntoa (bgp->router_id), VTY_NEWLINE);
  vty_out (vty, "Status codes: s suppressed, d damped, h history, "
           "* valid, > best, i - internal%s", VTY_NEWLINE);
  vty_out (vty, "Origin codes: i - IGP, e - EGP, ? - incomplete%s",
           VTY_NEWLINE);
  vty_out (vty, "EVPN type-2 prefix: [2]:[ESI]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]%s",
           VTY_NEWLINE);
  vty_out (vty, "EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]%s%s",
           VTY_NEWLINE, VTY_NEWLINE);
  vty_out (vty, ri_header, VTY_NEWLINE);
}

static void
display_vni (struct vty *vty, struct bgpevpn *vpn)
{
  char buf1[INET6_ADDRSTRLEN];
  char *ecom_str;
  struct listnode *node, *nnode;
  struct ecommunity *ecom;

  vty_out (vty, "VNI: %d", vpn->vni);
  if (is_vni_live (vpn))
    vty_out (vty, " (known to the kernel)");
  vty_out (vty, "%s", VTY_NEWLINE);

  vty_out (vty, "  RD: %s%s",
           prefix_rd2str (&vpn->prd, buf1, RD_ADDRSTRLEN),
           VTY_NEWLINE);
  vty_out (vty, "  Originator IP: %s%s",
           inet_ntoa(vpn->originator_ip), VTY_NEWLINE);

  vty_out (vty, "  Import Route Target:%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS (vpn->import_rtl, node, nnode, ecom))
    {
      ecom_str = ecommunity_ecom2str (ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
      vty_out (vty, "    %s%s", ecom_str, VTY_NEWLINE);
      XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
    }

  vty_out (vty, "  Export Route Target:%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS (vpn->export_rtl, node, nnode, ecom))
    {
      ecom_str = ecommunity_ecom2str (ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
      vty_out (vty, "    %s%s", ecom_str, VTY_NEWLINE);
      XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
    }
}

static void
show_vni_routes (struct bgp *bgp, struct bgpevpn *vpn, int type,
                 struct vty *vty, struct in_addr vtep_ip)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  int header = 1;
  u_int32_t prefix_cnt, path_cnt;

  prefix_cnt = path_cnt = 0;

  for (rn = bgp_table_top (vpn->route_table); rn; rn = bgp_route_next (rn))
    {
      struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

      if (type &&
          evp->prefix.route_type != type)
        continue;

      if (rn->info)
        {
          /* Overall header/legend displayed once. */
          if (header)
            {
              bgp_evpn_show_route_header (vty, bgp);
              header = 0;
            }

          prefix_cnt++;
        }

      /* For EVPN, the prefix is displayed for each path (to fit in
       * with code that already exists).
       */
      for (ri = rn->info; ri; ri = ri->next)
        {
          if (vtep_ip.s_addr &&
              !IPV4_ADDR_SAME(&(vtep_ip), &(ri->attr->nexthop)))
            continue;

          path_cnt++;
          route_vty_out (vty, &rn->p, ri, 0, SAFI_EVPN, NULL);
        }
    }

  if (prefix_cnt == 0)
    vty_out (vty, "No EVPN prefixes %sexist for this VNI%s",
             type ? "(of requested type) " : "", VTY_NEWLINE);
  else
    vty_out (vty, "%sDisplayed %u prefixes (%u paths)%s%s",
             VTY_NEWLINE, prefix_cnt, path_cnt,
             type ? " (of requested type)" : "", VTY_NEWLINE);
}

static void
show_vni_routes_hash (struct hash_backet *backet, void *arg)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  struct vni_walk_ctx *wctx = arg;
  struct vty *vty = wctx->vty;

  vty_out (vty, "%sVNI: %d%s%s", VTY_NEWLINE, vpn->vni, VTY_NEWLINE, VTY_NEWLINE);
  show_vni_routes (wctx->bgp, vpn, 0, wctx->vty, wctx->vtep_ip);
}

static void
show_vni_entry (struct hash_backet *backet, struct vty *vty)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  char buf1[10];
  char buf2[INET6_ADDRSTRLEN];
  char rt_buf[25];
  char *ecom_str;
  struct listnode *node, *nnode;
  struct ecommunity *ecom;

  buf1[0] = '\0';
  if (is_vni_live (vpn))
    sprintf (buf1, "*");

  vty_out(vty, "%-1s %-10u %-15s %-21s",
          buf1, vpn->vni, inet_ntoa(vpn->originator_ip),
          prefix_rd2str (&vpn->prd, buf2, RD_ADDRSTRLEN));

  for (ALL_LIST_ELEMENTS (vpn->import_rtl, node, nnode, ecom))
    {
      ecom_str = ecommunity_ecom2str (ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

      if (listcount(vpn->import_rtl) > 1)
        sprintf (rt_buf, "%s, ...", ecom_str);
      else
        sprintf (rt_buf, "%s", ecom_str);
      vty_out (vty, " %-25s", rt_buf);

      XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
      break;
    }

  for (ALL_LIST_ELEMENTS (vpn->export_rtl, node, nnode, ecom))
    {
      ecom_str = ecommunity_ecom2str (ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

      if (listcount(vpn->export_rtl) > 1)
        sprintf (rt_buf, "%s, ...", ecom_str);
      else
        sprintf (rt_buf, "%s", ecom_str);
      vty_out (vty, " %-25s", rt_buf);

      XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
      break;
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

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
	char v4_header[] =
	    "   Network          Next Hop            Metric LocPrf Weight Path%s";
	char v4_header_tag[] =
	    "   Network          Next Hop      In tag/Out tag%s";
	char v4_header_overlay[] =
	    "   Network          Next Hop      EthTag    Overlay Index   RouterMac%s";

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
			vty_out(vty, "No BGP process is configured%s",
				VTY_NEWLINE);
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
								vty_out(vty,
									v4_header_tag,
									VTY_NEWLINE);
							else if (option ==
								 SHOW_DISPLAY_OVERLAY)
								vty_out(vty,
									v4_header_overlay,
									VTY_NEWLINE);
							else {
								vty_out(vty,
									"BGP table version is 0, local router ID is %s%s",
									inet_ntoa
									(bgp->
									 router_id),
									VTY_NEWLINE);
								vty_out(vty,
									"Status codes: s suppressed, d damped, h history, * valid, > best, i - internal%s",
									VTY_NEWLINE);
								vty_out(vty,
									"Origin codes: i - IGP, e - EGP, ? - incomplete%s%s",
									VTY_NEWLINE,
									VTY_NEWLINE);
								vty_out(vty,
									v4_header,
									VTY_NEWLINE);
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
							vty_out(vty, "%s",
								VTY_NEWLINE);
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
		vty_out(vty, "No prefixes displayed, %ld exist%s", total_count,
			VTY_NEWLINE);
	else
		vty_out(vty, "%sDisplayed %ld out of %ld total prefixes%s",
			VTY_NEWLINE, output_count, total_count, VTY_NEWLINE);
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
		vty_out(vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
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
		vty_out(vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
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
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "Malformed address: %s%s",
				argv[idx_ipv4]->arg, VTY_NEWLINE);
		return CMD_WARNING;
	}

	peer = peer_lookup(NULL, &su);
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor or address family");
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family%s",
				VTY_NEWLINE);
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
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "%% Malformed Route Distinguisher%s",
				VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed address");
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "Malformed address: %s%s",
				argv[idx_ext_community]->arg, VTY_NEWLINE);
		return CMD_WARNING;
	}

	peer = peer_lookup(NULL, &su);
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor or address family");
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family%s",
				VTY_NEWLINE);
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
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "Malformed address: %s%s",
				argv[idx_ipv4]->arg, VTY_NEWLINE);
		return CMD_WARNING;
	}
	peer = peer_lookup(NULL, &su);
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor or address family");
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family%s",
				VTY_NEWLINE);
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
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "Malformed address: %s%s",
				argv[idx_ext_community]->arg, VTY_NEWLINE);
		return CMD_WARNING;
	}
	peer = peer_lookup(NULL, &su);
	if (!peer || !peer->afc[AFI_L2VPN][SAFI_EVPN]) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor or address family");
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "%% No such neighbor or address family%s",
				VTY_NEWLINE);
		return CMD_WARNING;
	}

	ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
	if (!ret) {
		if (uj) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "Malformed Route Distinguisher");
			vty_out(vty, "%s%s",
				json_object_to_json_string(json_no),
				VTY_NEWLINE);
			json_object_free(json_no);
		} else
			vty_out(vty, "%% Malformed Route Distinguisher%s",
				VTY_NEWLINE);
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
		vty_out(vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
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
				   BGP_EVPN_IP_PREFIX_ROUTE, argv[idx_esi]->arg,
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
				     argv[idx_label]->arg, BGP_EVPN_IP_PREFIX_ROUTE,
				     argv[idx_esi]->arg, argv[idx_gwip]->arg,
				     argv[idx_ethtag]->arg);
}

static void
evpn_rt_delete_auto (struct bgp *bgp, struct bgpevpn *vpn, struct list *rtl)
{
  struct listnode *node, *nnode, *node_to_del;
  struct ecommunity *ecom, *ecom_auto;
  struct ecommunity_val eval;

  encode_route_target_as ((bgp->as & 0xFFFF), vpn->vni, &eval);

  ecom_auto = ecommunity_new ();
  ecommunity_add_val (ecom_auto, &eval);
  node_to_del = NULL;

  for (ALL_LIST_ELEMENTS (rtl, node, nnode, ecom))
    {
      if (ecommunity_match (ecom, ecom_auto))
        {
          ecommunity_free (&ecom);
          node_to_del = node;
        }
    }

  if (node_to_del)
    list_delete_node(rtl, node_to_del);

  ecommunity_free(&ecom_auto);
}

static void
evpn_import_rt_delete_auto (struct bgp *bgp, struct bgpevpn *vpn)
{
  evpn_rt_delete_auto (bgp, vpn, vpn->import_rtl);
}

static void
evpn_export_rt_delete_auto (struct bgp *bgp, struct bgpevpn *vpn)
{
  evpn_rt_delete_auto (bgp, vpn, vpn->export_rtl);
}

/*
 * Configure the Import RTs for a VNI (vty handler). Caller expected to
 * check that this is a change.
 */
static void
evpn_configure_import_rt (struct bgp *bgp, struct bgpevpn *vpn,
                          struct ecommunity *ecomadd)
{
  /* If the VNI is "live", we need to uninstall routes using the current
   * import RT(s) first before we update the import RT, and subsequently
   * install routes.
   */
  if (is_vni_live (vpn))
    bgp_evpn_uninstall_routes (bgp, vpn);

  /* Cleanup the RT to VNI mapping and get rid of existing import RT. */
  bgp_evpn_unmap_vni_from_its_rts (bgp, vpn);

  /* If the auto route-target is in use we must remove it */
  evpn_import_rt_delete_auto(bgp, vpn);

  /* Add new RT and rebuild the RT to VNI mapping */
  listnode_add_sort (vpn->import_rtl, ecomadd);

  SET_FLAG (vpn->flags, VNI_FLAG_IMPRT_CFGD);
  bgp_evpn_map_vni_to_its_rts (bgp, vpn);

  /* Install routes that match new import RT */
  if (is_vni_live (vpn))
    bgp_evpn_install_routes (bgp, vpn);
}

/*
 * Unconfigure Import RT(s) for a VNI (vty handler).
 */
static void
evpn_unconfigure_import_rt (struct bgp *bgp, struct bgpevpn *vpn,
                            struct ecommunity *ecomdel)
{
  struct listnode *node, *nnode, *node_to_del;
  struct ecommunity *ecom;

  /* Along the lines of "configure" except we have to reset to the
   * automatic value.
   */
  if (is_vni_live (vpn))
    bgp_evpn_uninstall_routes (bgp, vpn);

  /* Cleanup the RT to VNI mapping and get rid of existing import RT. */
  bgp_evpn_unmap_vni_from_its_rts (bgp, vpn);

  /* Delete all import RTs */
  if (ecomdel == NULL)
    {
      for (ALL_LIST_ELEMENTS (vpn->import_rtl, node, nnode, ecom))
        ecommunity_free (&ecom);

      list_delete_all_node(vpn->import_rtl);
    }

  /* Delete a specific import RT */
  else
    {
      node_to_del = NULL;

      for (ALL_LIST_ELEMENTS (vpn->import_rtl, node, nnode, ecom))
        {
          if (ecommunity_match (ecom, ecomdel))
            {
              ecommunity_free (&ecom);
              node_to_del = node;
              break;
            }
        }

      if (node_to_del)
        list_delete_node(vpn->import_rtl, node_to_del);
    }

  /* Reset to auto RT - this also rebuilds the RT to VNI mapping */
  if (list_isempty(vpn->import_rtl))
    {
      UNSET_FLAG (vpn->flags, VNI_FLAG_IMPRT_CFGD);
      bgp_evpn_derive_auto_rt_import (bgp, vpn);
    }
  /* Rebuild the RT to VNI mapping */
  else
    bgp_evpn_map_vni_to_its_rts (bgp, vpn);

  /* Install routes that match new import RT */
  if (is_vni_live (vpn))
    bgp_evpn_install_routes (bgp, vpn);
}

/*
 * Configure the Export RT for a VNI (vty handler). Caller expected to
 * check that this is a change. Note that only a single export RT is
 * allowed for a VNI and any change to configuration is implemented as
 * a "replace" (similar to other configuration).
 */
static void
evpn_configure_export_rt (struct bgp *bgp, struct bgpevpn *vpn,
                          struct ecommunity *ecomadd)
{
  /* If the auto route-target is in use we must remove it */
  evpn_export_rt_delete_auto (bgp, vpn);

  listnode_add_sort (vpn->export_rtl, ecomadd);
  SET_FLAG (vpn->flags, VNI_FLAG_EXPRT_CFGD);

  if (is_vni_live (vpn))
    bgp_evpn_handle_export_rt_change (bgp, vpn);
}

/*
 * Unconfigure the Export RT for a VNI (vty handler)
 */
static void
evpn_unconfigure_export_rt (struct bgp *bgp, struct bgpevpn *vpn,
                            struct ecommunity *ecomdel)
{
  struct listnode *node, *nnode, *node_to_del;
  struct ecommunity *ecom;

  /* Delete all export RTs */
  if (ecomdel == NULL)
    {
      /* Reset to default and process all routes. */
      for (ALL_LIST_ELEMENTS (vpn->export_rtl, node, nnode, ecom))
        ecommunity_free (&ecom);

      list_delete_all_node(vpn->export_rtl);
    }

  /* Delete a specific export RT */
  else
    {
      node_to_del = NULL;

      for (ALL_LIST_ELEMENTS (vpn->export_rtl, node, nnode, ecom))
        {
          if (ecommunity_match (ecom, ecomdel))
            {
              ecommunity_free (&ecom);
              node_to_del = node;
              break;
            }
        }

      if (node_to_del)
        list_delete_node(vpn->export_rtl, node_to_del);
    }

  if (list_isempty(vpn->export_rtl))
    {
      UNSET_FLAG (vpn->flags, VNI_FLAG_EXPRT_CFGD);
      bgp_evpn_derive_auto_rt_export (bgp, vpn);
    }

  if (is_vni_live (vpn))
    bgp_evpn_handle_export_rt_change (bgp, vpn);
}

/*
 * Configure RD for a VNI (vty handler)
 */
static void
evpn_configure_rd (struct bgp *bgp, struct bgpevpn *vpn,
                   struct prefix_rd *rd)
{
  /* If the VNI is "live", we need to delete and withdraw this VNI's
   * local routes with the prior RD first. Then, after updating RD,
   * need to re-advertise.
   */
  if (is_vni_live (vpn))
    bgp_evpn_handle_rd_change (bgp, vpn, 1);

  /* update RD */
  memcpy(&vpn->prd, rd, sizeof (struct prefix_rd));
  SET_FLAG (vpn->flags, VNI_FLAG_RD_CFGD);

  if (is_vni_live (vpn))
    bgp_evpn_handle_rd_change (bgp, vpn, 0);
}

/*
 * Unconfigure RD for a VNI (vty handler)
 */
static void
evpn_unconfigure_rd (struct bgp *bgp, struct bgpevpn *vpn)
{
  /* If the VNI is "live", we need to delete and withdraw this VNI's
   * local routes with the prior RD first. Then, after resetting RD
   * to automatic value, need to re-advertise.
   */
  if (is_vni_live (vpn))
    bgp_evpn_handle_rd_change (bgp, vpn, 1);

  /* reset RD to default */
  bgp_evpn_derive_auto_rd (bgp, vpn);

  if (is_vni_live (vpn))
    bgp_evpn_handle_rd_change (bgp, vpn, 0);
}

/*
 * Create VNI, if not already present (VTY handler). Mark as configured.
 */
static struct bgpevpn *
evpn_create_update_vni (struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    return NULL;

  vpn = bgp_evpn_lookup_vni (bgp, vni);
  if (!vpn)
    {
      vpn = bgp_evpn_new (bgp, vni, bgp->router_id);
      if (!vpn)
        {
          zlog_err ("%u: Failed to allocate VNI entry for VNI %u - at Config",
                    bgp->vrf_id, vni);
          return NULL;
        }
    }

  /* Mark as configured. */
  SET_FLAG (vpn->flags, VNI_FLAG_CFGD);
  return vpn;
}

/*
 * Delete VNI. If VNI does not exist in the system (i.e., just
 * configuration), all that is needed is to free it. Otherwise,
 * any parameters configured for the VNI need to be reset (with
 * appropriate action) and the VNI marked as unconfigured; the
 * VNI will continue to exist, purely as a "learnt" entity.
 */
static int
evpn_delete_vni (struct bgp *bgp, struct bgpevpn *vpn)
{
  assert (bgp->vnihash);

  if (!is_vni_live (vpn))
    {
      bgp_evpn_free (bgp, vpn);
      return 0;
    }

  /* We need to take the unconfigure action for each parameter of this VNI
   * that is configured. Some optimization is possible, but not worth the
   * additional code for an operation that should be pretty rare.
   */
  UNSET_FLAG (vpn->flags, VNI_FLAG_CFGD);

  /* First, deal with the export side - RD and export RT changes. */
  if (is_rd_configured (vpn))
    evpn_unconfigure_rd (bgp, vpn);
  if (is_export_rt_configured (vpn))
    evpn_unconfigure_export_rt (bgp, vpn, NULL);

  /* Next, deal with the import side. */
  if (is_import_rt_configured (vpn))
    evpn_unconfigure_import_rt (bgp, vpn, NULL);

  return 0;
}

/*
 * Display import RT mapping to VNIs (vty handler)
 */
static void
evpn_show_import_rts (struct vty *vty, struct bgp *bgp)
{
  hash_iterate (bgp->import_rt_hash,
                (void (*) (struct hash_backet *, void *))
                show_import_rt_entry, vty);
}

/*
 * Display EVPN routes for all VNIs - vty handler.
 */
static void
evpn_show_routes_vni_all (struct vty *vty, struct bgp *bgp, struct in_addr vtep_ip)
{
  u_int32_t num_vnis;
  struct vni_walk_ctx wctx;

  num_vnis = hashcount(bgp->vnihash);
  if (!num_vnis)
    return;
  memset (&wctx, 0, sizeof (struct vni_walk_ctx));
  wctx.bgp = bgp;
  wctx.vty = vty;
  wctx.vtep_ip = vtep_ip;
  hash_iterate (bgp->vnihash,
                (void (*) (struct hash_backet *, void *))
                show_vni_routes_hash, &wctx);
}

/*
 * Display EVPN routes for a VNI -- for specific type-3 route (vty handler).
 */
static void
evpn_show_route_vni_multicast (struct vty *vty, struct bgp *bgp,
                               vni_t vni, struct in_addr orig_ip)
{
  struct bgpevpn *vpn;
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct bgp_info *ri;
  u_int32_t path_cnt = 0;
  afi_t afi;
  safi_t safi;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;

  /* Locate VNI. */
  vpn = bgp_evpn_lookup_vni (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "VNI not found%s", VTY_NEWLINE);
      return;
    }

  /* See if route exists. */
  build_evpn_type3_prefix (&p, orig_ip);
  rn = bgp_node_lookup (vpn->route_table, (struct prefix *)&p);
  if (!rn || !rn->info)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return;
    }

  /* Prefix and num paths displayed once per prefix. */
  route_vty_out_detail_header (vty, bgp, rn, NULL, afi, safi, NULL);

  /* Display each path for this prefix. */
  for (ri = rn->info; ri; ri = ri->next)
    {
      route_vty_out_detail (vty, bgp, &rn->p, ri, afi, safi, NULL);
      path_cnt++;
    }

  vty_out (vty, "%sDisplayed %u paths for requested prefix%s",
           VTY_NEWLINE, path_cnt, VTY_NEWLINE);
}

/*
 * Display EVPN routes for a VNI -- for specific MAC and/or IP (vty handler).
 * By definition, only matching type-2 route will be displayed.
 */
static void
evpn_show_route_vni_macip (struct vty *vty, struct bgp *bgp,
                           vni_t vni, struct ethaddr *mac,
                           struct ipaddr *ip)
{
  struct bgpevpn *vpn;
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct bgp_info *ri;
  u_int32_t path_cnt = 0;
  afi_t afi;
  safi_t safi;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;

  /* Locate VNI. */
  vpn = bgp_evpn_lookup_vni (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "VNI not found%s", VTY_NEWLINE);
      return;
    }

  /* See if route exists. Look for both non-sticky and sticky. */
  build_evpn_type2_prefix (&p, mac, ip);
  rn = bgp_node_lookup (vpn->route_table, (struct prefix *)&p);
  if (!rn || !rn->info)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return;
    }

  /* Prefix and num paths displayed once per prefix. */
  route_vty_out_detail_header (vty, bgp, rn, NULL, afi, safi, NULL);

  /* Display each path for this prefix. */
  for (ri = rn->info; ri; ri = ri->next)
    {
      route_vty_out_detail (vty, bgp, &rn->p, ri, afi, safi, NULL);
      path_cnt++;
    }

  vty_out (vty, "%sDisplayed %u paths for requested prefix%s",
           VTY_NEWLINE, path_cnt, VTY_NEWLINE);
}

/*
 * Display EVPN routes for a VNI - vty handler.
 * If 'type' is non-zero, only routes matching that type are shown.
 * If the vtep_ip is non zero, only routes behind that vtep are shown
 */
static void
evpn_show_routes_vni (struct vty *vty, struct bgp *bgp,
                      vni_t vni, int type, struct in_addr vtep_ip)
{
  struct bgpevpn *vpn;

  /* Locate VNI. */
  vpn = bgp_evpn_lookup_vni (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "VNI not found%s", VTY_NEWLINE);
      return;
    }

  /* Walk this VNI's route table and display appropriate routes. */
  show_vni_routes (bgp, vpn, type, vty, vtep_ip);
}

/*
 * Display BGP EVPN routing table -- for specific RD and MAC and/or
 * IP (vty handler). By definition, only matching type-2 route will be
 * displayed.
 */
static void
evpn_show_route_rd_macip (struct vty *vty, struct bgp *bgp,
                          struct prefix_rd *prd, struct ethaddr *mac,
                          struct ipaddr *ip)
{
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct bgp_info *ri;
  afi_t afi;
  safi_t safi;
  u_int32_t path_cnt = 0;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;

  /* See if route exists. Look for both non-sticky and sticky. */
  build_evpn_type2_prefix (&p, mac, ip);
  rn = bgp_afi_node_lookup (bgp->rib[afi][safi], afi, safi,
                            (struct prefix *)&p, prd);
  if (!rn || !rn->info)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return;
    }

  /* Prefix and num paths displayed once per prefix. */
  route_vty_out_detail_header (vty, bgp, rn, prd, afi, safi, NULL);

  /* Display each path for this prefix. */
  for (ri = rn->info; ri; ri = ri->next)
    {
      route_vty_out_detail (vty, bgp, &rn->p, ri, afi, safi, NULL);
      path_cnt++;
    }

  vty_out (vty, "%sDisplayed %u paths for requested prefix%s",
           VTY_NEWLINE, path_cnt, VTY_NEWLINE);
}

/*
 * Display BGP EVPN routing table -- for specific RD (vty handler)
 * If 'type' is non-zero, only routes matching that type are shown.
 */
static void
evpn_show_route_rd (struct vty *vty, struct bgp *bgp,
                    struct prefix_rd *prd, int type)
{
  struct bgp_node *rd_rn;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_info *ri;
  int rd_header = 1;
  afi_t afi;
  safi_t safi;
  u_int32_t prefix_cnt, path_cnt;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;
  prefix_cnt = path_cnt = 0;

  rd_rn = bgp_node_lookup (bgp->rib[afi][safi], (struct prefix *) prd);
  if (!rd_rn)
    return;
  table = (struct bgp_table *)rd_rn->info;
  if (table == NULL)
    return;

  /* Display all prefixes with this RD. */
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

      if (type &&
          evp->prefix.route_type != type)
        continue;

      if (rn->info)
        {
          /* RD header and legend - once overall. */
          if (rd_header)
            {
              vty_out (vty, "EVPN type-2 prefix: [2]:[ESI]:[EthTag]:[MAClen]:"
                       "[MAC]%s", VTY_NEWLINE);
              vty_out (vty, "EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:"
                       "[OrigIP]%s%s", VTY_NEWLINE, VTY_NEWLINE);
              rd_header = 0;
            }

          /* Prefix and num paths displayed once per prefix. */
          route_vty_out_detail_header (vty, bgp, rn, prd, afi, safi, NULL);

          prefix_cnt++;
        }

      /* Display each path for this prefix. */
      for (ri = rn->info; ri; ri = ri->next)
        {
          route_vty_out_detail (vty, bgp, &rn->p, ri, afi, safi, NULL);
          path_cnt++;
        }
    }

  if (prefix_cnt == 0)
    vty_out (vty, "No prefixes exist with this RD%s%s",
             type ? " (of requested type)" : "", VTY_NEWLINE);
  else
    vty_out (vty, "%sDisplayed %u prefixes (%u paths) with this RD%s%s",
             VTY_NEWLINE, prefix_cnt, path_cnt,
             type ? " (of requested type)" : "", VTY_NEWLINE);
}

/*
 * Display BGP EVPN routing table - all routes (vty handler).
 * If 'type' is non-zero, only routes matching that type are shown.
 */
static void
evpn_show_all_routes (struct vty *vty, struct bgp *bgp, int type)
{
  struct bgp_node *rd_rn;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_info *ri;
  int header = 1;
  int rd_header;
  afi_t afi;
  safi_t safi;
  u_int32_t prefix_cnt, path_cnt;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;
  prefix_cnt = path_cnt = 0;

  /* EVPN routing table is a 2-level table with the first level being
   * the RD.
   */
  for (rd_rn = bgp_table_top (bgp->rib[afi][safi]); rd_rn;
       rd_rn = bgp_route_next (rd_rn))
    {
      table = (struct bgp_table *)rd_rn->info;
      if (table == NULL)
        continue;

      rd_header = 1;

      /* Display all prefixes for an RD */
      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
        {
          struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

          if (type &&
              evp->prefix.route_type != type)
            continue;

          if (rn->info)
            {
              /* Overall header/legend displayed once. */
              if (header)
                {
                  bgp_evpn_show_route_header (vty, bgp);
                  header = 0;
                }

              /* RD header - per RD. */
              if (rd_header)
                {
                  bgp_evpn_show_route_rd_header (vty, rd_rn);
                  rd_header = 0;
                }

              prefix_cnt++;
            }

          /* For EVPN, the prefix is displayed for each path (to fit in
           * with code that already exists).
           */
          for (ri = rn->info; ri; ri = ri->next)
            {
              path_cnt++;
              route_vty_out (vty, &rn->p, ri, 0, SAFI_EVPN, NULL);
            }
        }
    }

  if (prefix_cnt == 0)
    vty_out (vty, "No EVPN prefixes %sexist%s",
             type ? "(of requested type) " : "", VTY_NEWLINE);
  else
    vty_out (vty, "%sDisplayed %u prefixes (%u paths)%s%s",
             VTY_NEWLINE, prefix_cnt, path_cnt,
             type ? " (of requested type)" : "", VTY_NEWLINE);
}

/*
 * Display specified VNI (vty handler)
 */
static void
evpn_show_vni (struct vty *vty, struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  vpn = bgp_evpn_lookup_vni (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "VNI not found%s", VTY_NEWLINE);
      return;
    }

  display_vni (vty, vpn);
}

/*
 * Display a VNI (upon user query).
 */
static void
evpn_show_all_vnis (struct vty *vty, struct bgp *bgp)
{
  u_int32_t num_vnis;

  num_vnis = hashcount(bgp->vnihash);
  if (!num_vnis)
    return;
  vty_out(vty, "Number of VNIs: %u%s",
          num_vnis, VTY_NEWLINE);
  vty_out(vty, "Flags: * - Kernel %s", VTY_NEWLINE);
  vty_out(vty, "  %-10s %-15s %-21s %-25s %-25s%s",
          "VNI", "Orig IP", "RD", "Import RT", "Export RT", VTY_NEWLINE);
  hash_iterate (bgp->vnihash,
                (void (*) (struct hash_backet *, void *))
                show_vni_entry, vty);
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

static void
write_vni_config (struct vty *vty, struct bgpevpn *vpn, int *write)
{
  char buf1[INET6_ADDRSTRLEN];
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;
  char *ecom_str;
  struct listnode *node, *nnode;
  struct ecommunity *ecom;

  if (is_vni_configured (vpn))
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, "  vni %d%s", vpn->vni, VTY_NEWLINE);
      if (is_rd_configured (vpn))
          vty_out (vty, "   rd %s%s",
                        prefix_rd2str (&vpn->prd, buf1, RD_ADDRSTRLEN),
                        VTY_NEWLINE);

      if (is_import_rt_configured (vpn))
        {
          for (ALL_LIST_ELEMENTS (vpn->import_rtl, node, nnode, ecom))
            {
              ecom_str = ecommunity_ecom2str (ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
              vty_out (vty, "   route-target import %s%s", ecom_str, VTY_NEWLINE);
              XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
            }
        }

      if (is_export_rt_configured (vpn))
        {
          for (ALL_LIST_ELEMENTS (vpn->export_rtl, node, nnode, ecom))
            {
              ecom_str = ecommunity_ecom2str (ecom, ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
              vty_out (vty, "   route-target export %s%s", ecom_str, VTY_NEWLINE);
              XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
            }
        }

      vty_out (vty, "  exit-vni%s", VTY_NEWLINE);
    }
}

static void
write_vni_config_for_entry (struct hash_backet *backet,
                            struct evpn_config_write *cfg)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  write_vni_config (cfg->vty, vpn, &cfg->write);
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

DEFUN (show_bgp_evpn_vni,
       show_bgp_evpn_vni_cmd,
       "show bgp evpn vni",
       SHOW_STR
       BGP_STR
       EVPN_HELP_STR
       "Show VNI\n")
{
  struct bgp *bgp;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  vty_out (vty, "Advertise All VNI flag: %s%s",
           bgp->advertise_all_vni? "Enabled" : "Disabled", VTY_NEWLINE);

  evpn_show_all_vnis (vty, bgp);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_evpn_vni_num,
       show_bgp_evpn_vni_num_cmd,
       "show bgp evpn vni (1-16777215)",
       SHOW_STR
       BGP_STR
       "Address family modifier\n"
       "Show VNI\n"
       "VNI number\n")
{
  vni_t vni;
  struct bgp *bgp;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("VNI", vni, argv[4]->arg, 1, VNI_MAX);

  evpn_show_vni (vty, bgp, vni);
  return CMD_SUCCESS;
}

/* `show bgp evpn summary' commands. */
DEFUN (show_bgp_evpn_summary,
       show_bgp_evpn_summary_cmd,
       "show bgp evpn summary [json]",
       SHOW_STR
       BGP_STR
       "EVPN\n"
       "Summary of BGP neighbor status\n"
       "JavaScript Object Notation\n")
{
  u_char uj = use_json(argc, argv);
  return bgp_show_summary_vty (vty, NULL, AFI_L2VPN, SAFI_EVPN, uj);
}

/* Show bgp evpn route */
DEFUN (show_bgp_evpn_route,
       show_bgp_evpn_route_cmd,
       "show bgp evpn route [type <macip|multicast>]",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Display EVPN route information\n"
       "Specify Route type\n"
       "MAC-IP (Type-2) route\n"
       "Multicast (Type-3) route\n")
{
  struct bgp *bgp;
  int type = 0;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  if (argc == 6)
    {
      if (strncmp (argv[5]->arg, "ma", 2) == 0)
        type = BGP_EVPN_MAC_IP_ROUTE;
      else if (strncmp (argv[5]->arg, "mu", 2) == 0)
        type = BGP_EVPN_IMET_ROUTE;
      else
        return CMD_WARNING;
    }

  evpn_show_all_routes (vty, bgp, type);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_evpn_route_rd,
       show_bgp_evpn_route_rd_cmd,
       "show bgp evpn route rd ASN:nn_or_IP-address:nn [type <macip|multicast>]",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Display EVPN route information\n"
       "Route Distinguisher\n"
       "ASN:XX or A.B.C.D:XX\n"
       "Specify Route type\n"
       "MAC-IP (Type-2) route\n"
       "Multicast (Type-3) route\n")
{
  struct bgp *bgp;
  int ret;
  struct prefix_rd prd;
  int type = 0;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  ret = str2prefix_rd (argv[5]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 8)
    {
      if (strncmp (argv[7]->arg, "ma", 2) == 0)
        type = BGP_EVPN_MAC_IP_ROUTE;
      else if (strncmp (argv[7]->arg, "mu", 2) == 0)
        type = BGP_EVPN_IMET_ROUTE;
      else
        return CMD_WARNING;
    }

  evpn_show_route_rd (vty, bgp, &prd, type);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_evpn_route_rd_macip,
       show_bgp_evpn_route_rd_macip_cmd,
       "show bgp evpn route rd ASN:nn_or_IP-address:nn mac WORD [ip WORD]",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Display EVPN route information\n"
       "Route Distinguisher\n"
       "ASN:XX or A.B.C.D:XX\n"
       "MAC\n"
       "MAC address (e.g., 00:e0:ec:20:12:62)\n"
       "IP\n"
       "IP address (IPv4 or IPv6)\n")
{
  struct bgp *bgp;
  int ret;
  struct prefix_rd prd;
  struct ethaddr mac;
  struct ipaddr ip;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  ret = str2prefix_rd (argv[5]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (!prefix_str2mac (argv[7]->arg, &mac))
    {
      vty_out (vty, "%% Malformed MAC address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  memset (&ip, 0, sizeof (ip));
  if (argc == 10 && argv[9]->arg != NULL)
    {
      if (str2ipaddr (argv[9]->arg, &ip) != 0)
        {
          vty_out (vty, "%% Malformed IP address%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  evpn_show_route_rd_macip (vty, bgp, &prd, &mac, &ip);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_evpn_route_vni,
       show_bgp_evpn_route_vni_cmd,
       "show bgp evpn route vni (1-16777215) [<type <macip|multicast> | vtep A.B.C.D>]",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Display EVPN route information\n"
       "VXLAN Network Identifier\n"
       "VNI number\n"
       "Specify Route type\n"
       "MAC-IP (Type-2) route\n"
       "Multicast (Type-3) route\n"
       "Remote VTEP\n"
       "Remote VTEP IP address\n")
{
  vni_t vni;
  struct bgp *bgp;
  struct in_addr vtep_ip;
  int type = 0;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  vtep_ip.s_addr  = 0;

  VTY_GET_INTEGER_RANGE ("VNI", vni, argv[5]->arg, 1, VNI_MAX);

  if (argc == 8 && argv[6]->arg)
    {
      if (strncmp (argv[6]->arg, "type", 4) == 0)
        {
          if (strncmp (argv[7]->arg, "ma", 2) == 0)
            type = BGP_EVPN_MAC_IP_ROUTE;
          else if (strncmp (argv[7]->arg, "mu", 2) == 0)
            type = BGP_EVPN_IMET_ROUTE;
          else
            return CMD_WARNING;
        }
      else if (strncmp (argv[6]->arg, "vtep", 4) == 0)
        {
          if (!inet_aton (argv[7]->arg, &vtep_ip))
            {
              vty_out (vty, "%% Malformed VTEP IP address%s", VTY_NEWLINE);
              return CMD_WARNING;
            }
        }
      else
        return CMD_WARNING;
    }

  evpn_show_routes_vni (vty, bgp, vni, type, vtep_ip);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_evpn_route_vni_macip,
       show_bgp_evpn_route_vni_macip_cmd,
       "show bgp evpn route vni (1-16777215) mac WORD [ip WORD]",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Display EVPN route information\n"
       "VXLAN Network Identifier\n"
       "VNI number\n"
       "MAC\n"
       "MAC address (e.g., 00:e0:ec:20:12:62)\n"
       "IP\n"
       "IP address (IPv4 or IPv6)\n")
{
  vni_t vni;
  struct bgp *bgp;
  struct ethaddr mac;
  struct ipaddr ip;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("VNI", vni, argv[5]->arg, 1, VNI_MAX);
  if (!prefix_str2mac (argv[7]->arg, &mac))
    {
      vty_out (vty, "%% Malformed MAC address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  memset (&ip, 0, sizeof (ip));
  if (argc == 10 && argv[9]->arg != NULL)
    {
      if (str2ipaddr (argv[9]->arg, &ip) != 0)
        {
          vty_out (vty, "%% Malformed IP address%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  evpn_show_route_vni_macip (vty, bgp, vni, &mac, &ip);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_evpn_route_vni_multicast,
       show_bgp_evpn_route_vni_multicast_cmd,
       "show bgp evpn route vni (1-16777215) multicast A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Display EVPN route information\n"
       "VXLAN Network Identifier\n"
       "VNI number\n"
       "Multicast (Type-3) route\n"
       "Originating Router IP address\n")
{
  vni_t vni;
  struct bgp *bgp;
  int ret;
  struct in_addr orig_ip;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("VNI", vni, argv[5]->arg, 1, VNI_MAX);
  ret = inet_aton (argv[7]->arg, &orig_ip);
  if (!ret)
    {
      vty_out (vty, "%% Malformed Originating Router IP address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  evpn_show_route_vni_multicast (vty, bgp, vni, orig_ip);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_evpn_route_vni_all,
       show_bgp_evpn_route_vni_all_cmd,
       "show bgp evpn route vni all [vtep A.B.C.D]",
       SHOW_STR
       BGP_STR
       "Address Family Modifier\n"
       "Display EVPN route information\n"
       "VXLAN Network Identifier\n"
       "All VNIs\n"
       "Remote VTEP\n"
       "Remote VTEP IP address\n")
{
  struct bgp *bgp;
  struct in_addr vtep_ip;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  vtep_ip.s_addr  = 0;
  if (argc == 8 && argv[7]->arg)
    {
      if (!inet_aton (argv[7]->arg, &vtep_ip))
        {
          vty_out (vty, "%% Malformed VTEP IP address%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  evpn_show_routes_vni_all (vty, bgp, vtep_ip);
  return CMD_SUCCESS;
}

DEFUN (show_bgp_evpn_import_rt,
       show_bgp_evpn_import_rt_cmd,
       "show bgp evpn import-rt",
       SHOW_STR
       BGP_STR
       "Address family modifier\n"
       "Show import route target\n")
{
  struct bgp *bgp;

  bgp = bgp_get_default();
  if (!bgp)
    return CMD_WARNING;

  evpn_show_import_rts (vty, bgp);
  return CMD_SUCCESS;
}

DEFUN_NOSH (bgp_evpn_vni,
            bgp_evpn_vni_cmd,
            "vni (1-16777215)",
            "VXLAN Network Identifier\n"
            "VNI number\n")
{
  vni_t vni;
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);
  struct bgpevpn *vpn;

  if (!bgp)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("VNI", vni, argv[1]->arg, 1, VNI_MAX);

  /* Create VNI, or mark as configured. */
  vpn = evpn_create_update_vni (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "%% Failed to create VNI %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  VTY_PUSH_CONTEXT_SUB (BGP_EVPN_VNI_NODE, vpn);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni,
       no_bgp_evpn_vni_cmd,
       "no vni (1-16777215)",
       NO_STR
       "VXLAN Network Identifier\n"
       "VNI number\n")
{
  vni_t vni;
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);
  struct bgpevpn *vpn;

  if (!bgp)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("VNI", vni, argv[2]->arg, 1, VNI_MAX);

  /* Check if we should disallow. */
  vpn = bgp_evpn_lookup_vni (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "%% Specified VNI does not exist%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (!is_vni_configured (vpn))
    {
      vty_out (vty, "%% Specified VNI is not configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  evpn_delete_vni (bgp, vpn);
  return CMD_SUCCESS;
}

DEFUN_NOSH (exit_vni,
            exit_vni_cmd,
            "exit-vni",
            "Exit from VNI mode\n")
{
  if (vty->node == BGP_EVPN_VNI_NODE)
    vty->node = BGP_EVPN_NODE;
  return CMD_SUCCESS;
}

DEFUN (bgp_evpn_vni_rd,
       bgp_evpn_vni_rd_cmd,
       "rd ASN:nn_or_IP-address:nn",
       "Route Distinguisher\n"
       "ASN:XX or A.B.C.D:XX\n")
{
  struct prefix_rd prd;
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);
  VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
  int ret;

  if (!bgp || !vpn)
    return CMD_WARNING;

  ret = str2prefix_rd (argv[1]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* If same as existing value, there is nothing more to do. */
  if (bgp_evpn_rd_matches_existing (vpn, &prd))
    return CMD_SUCCESS;

  /* Configure or update the RD. */
  evpn_configure_rd (bgp, vpn, &prd);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rd,
       no_bgp_evpn_vni_rd_cmd,
       "no rd ASN:nn_or_IP-address:nn",
       NO_STR
       "Route Distinguisher\n"
       "ASN:XX or A.B.C.D:XX\n")
{
  struct prefix_rd prd;
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);
  VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
  int ret;

  if (!bgp || !vpn)
    return CMD_WARNING;

  ret = str2prefix_rd (argv[2]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check if we should disallow. */
  if (!is_rd_configured (vpn))
    {
      vty_out (vty, "%% RD is not configured for this VNI%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!bgp_evpn_rd_matches_existing(vpn, &prd))
    {
      vty_out (vty, "%% RD specified does not match configuration for this VNI%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  evpn_unconfigure_rd (bgp, vpn);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rd_without_val,
       no_bgp_evpn_vni_rd_without_val_cmd,
       "no rd",
       NO_STR
       "Route Distinguisher\n")
{
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);
  VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);

  if (!bgp || !vpn)
    return CMD_WARNING;

  /* Check if we should disallow. */
  if (!is_rd_configured (vpn))
    {
      vty_out (vty, "%% RD is not configured for this VNI%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  evpn_unconfigure_rd (bgp, vpn);
  return CMD_SUCCESS;
}

/*
 * Loop over all extended-communities in the route-target list rtl and
 * return 1 if we find ecomtarget
 */
static int
bgp_evpn_rt_matches_existing (struct list *rtl,
                              struct ecommunity *ecomtarget)
{
  struct listnode *node, *nnode;
  struct ecommunity *ecom;

  for (ALL_LIST_ELEMENTS (rtl, node, nnode, ecom))
    {
      if (ecommunity_match (ecom, ecomtarget))
        return 1;
    }

  return 0;
}


DEFUN (bgp_evpn_vni_rt,
       bgp_evpn_vni_rt_cmd,
       "route-target <both|import|export> RT",
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "Route target (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);
  VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
  int rt_type;
  struct ecommunity *ecomadd = NULL;

  if (!bgp || !vpn)
    return CMD_WARNING;

  if (!strcmp (argv[1]->arg, "import"))
    rt_type = RT_TYPE_IMPORT;
  else if (!strcmp (argv[1]->arg, "export"))
    rt_type = RT_TYPE_EXPORT;
  else if (!strcmp (argv[1]->arg, "both"))
    rt_type = RT_TYPE_BOTH;
  else
    {
      vty_out (vty, "%% Invalid Route Target type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Add/update the import route-target */
  if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_IMPORT)
    {
      ecomadd = ecommunity_str2com (argv[2]->arg,
                                    ECOMMUNITY_ROUTE_TARGET, 0);
      ecommunity_str(ecomadd);
      if (!ecomadd)
        {
          vty_out (vty, "%% Malformed Route Target list%s", VTY_NEWLINE);
          return CMD_WARNING;
        }

      /* Do nothing if we already have this import route-target */
      if (! bgp_evpn_rt_matches_existing (vpn->import_rtl, ecomadd))
        evpn_configure_import_rt (bgp, vpn, ecomadd);
    }

  /* Add/update the export route-target */
  if (rt_type == RT_TYPE_BOTH || rt_type == RT_TYPE_EXPORT)
    {
      ecomadd = ecommunity_str2com (argv[2]->arg,
                                    ECOMMUNITY_ROUTE_TARGET, 0);
      ecommunity_str(ecomadd);
      if (!ecomadd)
        {
          vty_out (vty, "%% Malformed Route Target list%s", VTY_NEWLINE);
          return CMD_WARNING;
        }

      /* Do nothing if we already have this export route-target */
      if (! bgp_evpn_rt_matches_existing (vpn->export_rtl, ecomadd))
        evpn_configure_export_rt (bgp, vpn, ecomadd);
    }

  return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rt,
       no_bgp_evpn_vni_rt_cmd,
       "no route-target <both|import|export> RT",
       NO_STR
       "Route Target\n"
       "import and export\n"
       "import\n"
       "export\n"
       "ASN:XX or A.B.C.D:XX\n")
{
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);
  VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
  int rt_type, found_ecomdel;
  struct ecommunity *ecomdel = NULL;

  if (!bgp || !vpn)
    return CMD_WARNING;

  if (!strcmp (argv[2]->arg, "import"))
    rt_type = RT_TYPE_IMPORT;
  else if (!strcmp (argv[2]->arg, "export"))
    rt_type = RT_TYPE_EXPORT;
  else if (!strcmp (argv[2]->arg, "both"))
    rt_type = RT_TYPE_BOTH;
  else
    {
      vty_out (vty, "%% Invalid Route Target type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* The user did "no route-target import", check to see if there are any
   * import route-targets configured. */
  if (rt_type == RT_TYPE_IMPORT)
    {
      if (!is_import_rt_configured (vpn))
        {
          vty_out (vty, "%% Import RT is not configured for this VNI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else if (rt_type == RT_TYPE_EXPORT)
    {
      if (!is_export_rt_configured (vpn))
        {
          vty_out (vty, "%% Export RT is not configured for this VNI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else if (rt_type == RT_TYPE_BOTH)
    {
      if (!is_import_rt_configured (vpn) && !is_export_rt_configured (vpn))
        {
          vty_out (vty, "%% Import/Export RT is not configured for this VNI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  ecomdel = ecommunity_str2com (argv[3]->arg, ECOMMUNITY_ROUTE_TARGET, 0);
  ecommunity_str(ecomdel);
  if (!ecomdel)
    {
      vty_out (vty, "%% Malformed Route Target list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (rt_type == RT_TYPE_IMPORT)
    {
      if (!bgp_evpn_rt_matches_existing (vpn->import_rtl, ecomdel))
        {
          vty_out (vty, "%% RT specified does not match configuration for this VNI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      evpn_unconfigure_import_rt (bgp, vpn, ecomdel);
    }
  else if (rt_type == RT_TYPE_EXPORT)
    {
      if (!bgp_evpn_rt_matches_existing (vpn->export_rtl, ecomdel))
        {
          vty_out (vty, "%% RT specified does not match configuration for this VNI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      evpn_unconfigure_export_rt (bgp, vpn, ecomdel);
    }
  else if (rt_type == RT_TYPE_BOTH)
    {
      found_ecomdel = 0;

      if (bgp_evpn_rt_matches_existing (vpn->import_rtl, ecomdel))
        {
          evpn_unconfigure_import_rt (bgp, vpn, ecomdel);
          found_ecomdel = 1;
        }

      if (bgp_evpn_rt_matches_existing (vpn->export_rtl, ecomdel))
        {
          evpn_unconfigure_export_rt (bgp, vpn, ecomdel);
          found_ecomdel = 1;
        }

      if (! found_ecomdel)
        {
          vty_out (vty, "%% RT specified does not match configuration for this VNI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  return CMD_SUCCESS;
}

DEFUN (no_bgp_evpn_vni_rt_without_val,
       no_bgp_evpn_vni_rt_without_val_cmd,
       "no route-target <import|export>",
       NO_STR
       "Route Target\n"
       "import\n"
       "export\n")
{
  struct bgp *bgp = VTY_GET_CONTEXT(bgp);
  VTY_DECLVAR_CONTEXT_SUB(bgpevpn, vpn);
  int rt_type;

  if (!bgp || !vpn)
    return CMD_WARNING;

  if (!strcmp (argv[2]->arg, "import"))
    {
      rt_type = RT_TYPE_IMPORT;
    }
  else if (!strcmp (argv[2]->arg, "export"))
    {
      rt_type = RT_TYPE_EXPORT;
    }
  else
    {
      vty_out (vty, "%% Invalid Route Target type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check if we should disallow. */
  if (rt_type == RT_TYPE_IMPORT)
    {
      if (!is_import_rt_configured (vpn))
        {
          vty_out (vty, "%% Import RT is not configured for this VNI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      if (!is_export_rt_configured (vpn))
        {
          vty_out (vty, "%% Export RT is not configured for this VNI%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  /* Unconfigure the RT. */
  if (rt_type == RT_TYPE_IMPORT)
    evpn_unconfigure_import_rt (bgp, vpn, NULL);
  else
    evpn_unconfigure_export_rt (bgp, vpn, NULL);
  return CMD_SUCCESS;
}

/*
 * Output EVPN configuration information.
 */
void
bgp_config_write_evpn_info (struct vty *vty, struct bgp *bgp, afi_t afi,
                            safi_t safi, int *write)
{
  struct evpn_config_write cfg;

  if (bgp->vnihash)
    {
      cfg.write = *write;
      cfg.vty = vty;
      hash_iterate (bgp->vnihash,
                    (void (*) (struct hash_backet *, void *))
                    write_vni_config_for_entry, &cfg);
      *write = cfg.write;
    }

  if (bgp->advertise_all_vni)
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, "  advertise-all-vni%s", VTY_NEWLINE);
    }
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

  /* "show bgp evpn" commands. */
  install_element (VIEW_NODE, &show_bgp_evpn_vni_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_vni_num_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_summary_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_route_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_route_rd_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_route_rd_macip_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_route_vni_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_route_vni_multicast_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_route_vni_macip_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_route_vni_all_cmd);
  install_element (VIEW_NODE, &show_bgp_evpn_import_rt_cmd);

  install_element (BGP_EVPN_NODE, &bgp_evpn_vni_cmd);
  install_element (BGP_EVPN_NODE, &no_bgp_evpn_vni_cmd);
  install_element (BGP_EVPN_VNI_NODE, &exit_vni_cmd);
  install_element (BGP_EVPN_VNI_NODE, &bgp_evpn_vni_rd_cmd);
  install_element (BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rd_cmd);
  install_element (BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rd_without_val_cmd);
  install_element (BGP_EVPN_VNI_NODE, &bgp_evpn_vni_rt_cmd);
  install_element (BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rt_cmd);
  install_element (BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rt_without_val_cmd);
}
