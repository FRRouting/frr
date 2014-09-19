/* MPLS-VPN
   Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "queue.h"

#include "lib/json.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"

static u_int16_t
decode_rd_type (u_char *pnt)
{
  u_int16_t v;
  
  v = ((u_int16_t) *pnt++ << 8);
  v |= (u_int16_t) *pnt;
  return v;
}

u_int32_t
decode_label (u_char *pnt)
{
  u_int32_t l;

  l = ((u_int32_t) *pnt++ << 12);
  l |= (u_int32_t) *pnt++ << 4;
  l |= (u_int32_t) ((*pnt & 0xf0) >> 4);
  return l;
}

static void
decode_rd_as (u_char *pnt, struct rd_as *rd_as)
{
  rd_as->as = (u_int16_t) *pnt++ << 8;
  rd_as->as |= (u_int16_t) *pnt++;
  
  rd_as->val = ((u_int32_t) *pnt++ << 24);
  rd_as->val |= ((u_int32_t) *pnt++ << 16);
  rd_as->val |= ((u_int32_t) *pnt++ << 8);
  rd_as->val |= (u_int32_t) *pnt;
}

static void
decode_rd_ip (u_char *pnt, struct rd_ip *rd_ip)
{
  memcpy (&rd_ip->ip, pnt, 4);
  pnt += 4;
  
  rd_ip->val = ((u_int16_t) *pnt++ << 8);
  rd_ip->val |= (u_int16_t) *pnt;
}

int
bgp_nlri_parse_vpnv4 (struct peer *peer, struct attr *attr, 
		      struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  struct prefix p;
  int psize;
  int prefixlen;
  u_int16_t type;
  struct rd_as rd_as;
  struct rd_ip rd_ip;
  struct prefix_rd prd;
  u_char *tagpnt;
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

  addpath_encoded = (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) &&
                     CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV));

#define VPN_PREFIXLEN_MIN_BYTES (3 + 8) /* label + RD */
  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      if (addpath_encoded)
        {

          /* When packet overflow occurs return immediately. */
          if (pnt + BGP_ADDPATH_ID_LEN > lim)
            return -1;

          addpath_id = ntohl(*((uint32_t*) pnt));
          pnt += BGP_ADDPATH_ID_LEN;
        }

      if (prefixlen < 88)
	{
	  zlog_err ("prefix length is less than 88: %d", prefixlen);
	  return -1;
	}

      /* XXX: Not doing anything with the label */
      decode_label (pnt);

      /* Fetch prefix length. */
      prefixlen = *pnt++;
      p.family = afi2family (packet->afi);
      psize = PSIZE (prefixlen);
      
      /* sanity check against packet data */
      if (prefixlen < VPN_PREFIXLEN_MIN_BYTES*8 || (pnt + psize) > lim)
        {
          zlog_err ("prefix length (%d) is less than 88"
                    " or larger than received (%u)",
                    prefixlen, (uint)(lim-pnt));
          return -1;
        }
      
      /* sanity check against storage for the IP address portion */
      if ((psize - VPN_PREFIXLEN_MIN_BYTES) > (ssize_t) sizeof(p.u))
        {
          zlog_err ("prefix length (%d) exceeds prefix storage (%zu)",
                    prefixlen - VPN_PREFIXLEN_MIN_BYTES*8, sizeof(p.u));
          return -1;
        }
      
      /* Sanity check against max bitlen of the address family */
      if ((psize - VPN_PREFIXLEN_MIN_BYTES) > prefix_blen (&p))
        {
          zlog_err ("prefix length (%d) exceeds family (%u) max byte length (%u)",
                    prefixlen - VPN_PREFIXLEN_MIN_BYTES*8, 
                    p.family, prefix_blen (&p));
          return -1;
                  
        }
      
      /* Copyr label to prefix. */
      tagpnt = pnt;

      /* Copy routing distinguisher to rd. */
      memcpy (&prd.val, pnt + 3, 8);

      /* Decode RD type. */
      type = decode_rd_type (pnt + 3);

      /* Decode RD value. */
      if (type == RD_TYPE_AS)
	decode_rd_as (pnt + 5, &rd_as);
      else if (type == RD_TYPE_IP)
	decode_rd_ip (pnt + 5, &rd_ip);
      else
	{
	  zlog_err ("Invalid RD type %d", type);
	  return -1;
	}

      p.prefixlen = prefixlen - VPN_PREFIXLEN_MIN_BYTES*8;
      memcpy (&p.u.prefix, pnt + VPN_PREFIXLEN_MIN_BYTES, 
              psize - VPN_PREFIXLEN_MIN_BYTES);

#if 0
      if (type == RD_TYPE_AS)
	zlog_info ("prefix %ld:%ld:%ld:%s/%d", label, rd_as.as, rd_as.val,
		   inet_ntoa (p.u.prefix4), p.prefixlen);
      else if (type == RD_TYPE_IP)
	zlog_info ("prefix %ld:%s:%ld:%s/%d", label, inet_ntoa (rd_ip.ip),
		   rd_ip.val, inet_ntoa (p.u.prefix4), p.prefixlen);
#endif /* 0 */

      if (attr)
	bgp_update (peer, &p, addpath_id, attr, AFI_IP, SAFI_MPLS_VPN,
		    ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, tagpnt, 0);
      else
	bgp_withdraw (peer, &p, addpath_id, attr, AFI_IP, SAFI_MPLS_VPN,
		      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, tagpnt);
    }
  /* Packet length consistency check. */
  if (pnt != lim)
    return -1;
  
  return 0;
#undef VPN_PREFIXLEN_MIN_BYTES
}

int
str2prefix_rd (const char *str, struct prefix_rd *prd)
{
  int ret;
  char *p;
  char *p2;
  struct stream *s;
  char *half;
  struct in_addr addr;

  s = stream_new (8);

  prd->family = AF_UNSPEC;
  prd->prefixlen = 64;

  p = strchr (str, ':');
  if (! p)
    return 0;

  if (! all_digit (p + 1))
    return 0;

  half = XMALLOC (MTYPE_TMP, (p - str) + 1);
  memcpy (half, str, (p - str));
  half[p - str] = '\0';

  p2 = strchr (str, '.');

  if (! p2)
    {
      if (! all_digit (half))
	{
	  XFREE (MTYPE_TMP, half);
	  return 0;
	}
      stream_putw (s, RD_TYPE_AS);
      stream_putw (s, atoi (half));
      stream_putl (s, atol (p + 1));
    }
  else
    {
      ret = inet_aton (half, &addr);
      if (! ret)
	{
	  XFREE (MTYPE_TMP, half);
	  return 0;
	}
      stream_putw (s, RD_TYPE_IP);
      stream_put_in_addr (s, &addr);
      stream_putw (s, atol (p + 1));
    }
  memcpy (prd->val, s->data, 8);

  XFREE(MTYPE_TMP, half);
  return 1;
}

int
str2tag (const char *str, u_char *tag)
{
  unsigned long l;
  char *endptr;
  u_int32_t t;

  if (*str == '-')
    return 0;
  
  errno = 0;
  l = strtoul (str, &endptr, 10);

  if (*endptr != '\0' || errno || l > UINT32_MAX)
    return 0;

  t = (u_int32_t) l;
  
  tag[0] = (u_char)(t >> 12);
  tag[1] = (u_char)(t >> 4);
  tag[2] = (u_char)(t << 4);

  return 1;
}

char *
prefix_rd2str (struct prefix_rd *prd, char *buf, size_t size)
{
  u_char *pnt;
  u_int16_t type;
  struct rd_as rd_as;
  struct rd_ip rd_ip;

  if (size < RD_ADDRSTRLEN)
    return NULL;

  pnt = prd->val;

  type = decode_rd_type (pnt);

  if (type == RD_TYPE_AS)
    {
      decode_rd_as (pnt + 2, &rd_as);
      snprintf (buf, size, "%u:%d", rd_as.as, rd_as.val);
      return buf;
    }
  else if (type == RD_TYPE_IP)
    {
      decode_rd_ip (pnt + 2, &rd_ip);
      snprintf (buf, size, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
      return buf;
    }

  return NULL;
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (vpnv4_network,
       vpnv4_network_cmd,
       "network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_set_vpnv4 (vty, argv[0], argv[1], argv[2]);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv4_network,
       no_vpnv4_network_cmd,
       "no network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_unset_vpnv4 (vty, argv[0], argv[1], argv[2]);
}

static int
show_adj_route_vpn (struct vty *vty, struct peer *peer, struct prefix_rd *prd, u_char use_json)
{
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct attr *attr;
  int rd_header;
  int header = 1;
  char v4_header[] = "   Network          Next Hop            Metric LocPrf Weight Path%s";
  json_object *json = NULL;
  json_object *json_scode = NULL;
  json_object *json_ocode = NULL;
  json_object *json_routes = NULL;
  json_object *json_array = NULL;

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
      json_routes = json_object_new_object();
      json = json_object_new_object();

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

  for (rn = bgp_table_top (bgp->rib[AFI_IP][SAFI_MPLS_VPN]); rn;
       rn = bgp_route_next (rn))
    {
      if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
        continue;

      if ((table = rn->info) != NULL)
        {
          if (use_json)
            json_array = json_object_new_array();
          else
            json_array = NULL;

          rd_header = 1;

          for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
            {
              if ((attr = rm->info) != NULL)
                {
                  if (header)
                    {
                      if (use_json)
                        {
                          json_object_int_add(json, "bgpTableVersion", 0);
                          json_object_string_add(json, "bgpLocalRouterId", inet_ntoa (bgp->router_id));
                          json_object_object_add(json, "bgpStatusCodes", json_scode);
                          json_object_object_add(json, "bgpOriginCodes", json_ocode);
                        }
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
                      header = 0;
                    }

                  if (rd_header)
                    {
                      u_int16_t type;
                      struct rd_as rd_as;
                      struct rd_ip rd_ip = { 0, { 0 }, 0};
                      u_char *pnt;

                      pnt = rn->p.u.val;

                      /* Decode RD type. */
                      type = decode_rd_type (pnt);
                      /* Decode RD value. */
                      if (type == RD_TYPE_AS)
                        decode_rd_as (pnt + 2, &rd_as);
                      else if (type == RD_TYPE_IP)
                        decode_rd_ip (pnt + 2, &rd_ip);

                      if (use_json)
                        {
                          char buffer[BUFSIZ];
                          if (type == RD_TYPE_AS)
                            sprintf (buffer, "%u:%d", rd_as.as, rd_as.val);
                          else if (type == RD_TYPE_IP)
                            sprintf (buffer, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
                          json_object_string_add(json_routes, "routeDistinguisher", buffer);
                        }
                      else
                        {
                          vty_out (vty, "Route Distinguisher: ");

                          if (type == RD_TYPE_AS)
                            vty_out (vty, "%u:%d", rd_as.as, rd_as.val);
                          else if (type == RD_TYPE_IP)
                            vty_out (vty, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);

                          vty_out (vty, "%s", VTY_NEWLINE);
                        }
                      rd_header = 0;
                    }
                  route_vty_out_tmp (vty, &rm->p, attr, SAFI_MPLS_VPN, use_json, json_array);
                }
            }
          if (use_json)
            {
              struct prefix *p;
              char buf_a[BUFSIZ];
              char buf_b[BUFSIZ];
              p = &rm->p;
              sprintf(buf_a, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf_b, BUFSIZ), p->prefixlen);
              json_object_object_add(json_routes, buf_a, json_array);
            }
        }
    }
  if (use_json)
    {
      json_object_object_add(json, "routes", json_routes);
      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  return CMD_SUCCESS;
}

enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_neighbor,
  bgp_show_type_cidr_only,
  bgp_show_type_prefix_longer,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact
};

static int
bgp_show_mpls_vpn (struct vty *vty, struct prefix_rd *prd, enum bgp_show_type type,
		   void *output_arg, int tags, u_char use_json)
{
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  int rd_header;
  int header = 1;
  char v4_header[] = "   Network          Next Hop            Metric LocPrf Weight Path%s";
  char v4_header_tag[] = "   Network          Next Hop      In tag/Out tag%s";
  json_object *json = NULL;
  json_object *json_mroute = NULL;
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
      json_mroute = json_object_new_object();
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

 for (rn = bgp_table_top (bgp->rib[AFI_IP][SAFI_MPLS_VPN]); rn; rn = bgp_route_next (rn))
    {
      if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
	continue;

      if ((table = rn->info) != NULL)
	{
	  rd_header = 1;

	  for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
	    {
              if (use_json)
                json_array = json_object_new_array();
              else
                json_array = NULL;

              for (ri = rm->info; ri; ri = ri->next)
	        {
		  if (type == bgp_show_type_neighbor)
		    {
		      union sockunion *su = output_arg;

		      if (ri->peer->su_remote == NULL || ! sockunion_same(ri->peer->su_remote, su))
		        continue;
                    }
		  if (header)
		    {
                      if (use_json)
                        {
                          if (!tags)
                            {
                              json_object_int_add(json, "bgpTableVersion", 0);
                              json_object_string_add(json, "bgpLocalRouterId", inet_ntoa (bgp->router_id));
                              json_object_object_add(json, "bgpStatusCodes", json_scode);
                              json_object_object_add(json, "bgpOriginCodes", json_ocode);
                            }
                        }
                      else
                        {
		          if (tags)
		            vty_out (vty, v4_header_tag, VTY_NEWLINE);
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
		      struct rd_ip rd_ip = { 0, { 0 }, 0};
		      u_char *pnt;

		      pnt = rn->p.u.val;

	              /* Decode RD type. */
		      type = decode_rd_type (pnt);
		      /* Decode RD value. */
		      if (type == RD_TYPE_AS)
		        decode_rd_as (pnt + 2, &rd_as);
		      else if (type == RD_TYPE_IP)
		        decode_rd_ip (pnt + 2, &rd_ip);

                      if (use_json)
                        {
                          char buffer[BUFSIZ];
                          if (type == RD_TYPE_AS)
                            sprintf (buffer, "%u:%d", rd_as.as, rd_as.val);
                          else if (type == RD_TYPE_IP)
                            sprintf (buffer, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
                          json_object_string_add(json_nroute, "routeDistinguisher", buffer);
                        }
                      else
                        {
		          vty_out (vty, "Route Distinguisher: ");

		          if (type == RD_TYPE_AS)
		            vty_out (vty, "%u:%d", rd_as.as, rd_as.val);
		          else if (type == RD_TYPE_IP)
		            vty_out (vty, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
		          vty_out (vty, "%s", VTY_NEWLINE);
                        }
		      rd_header = 0;
		    }
	          if (tags)
		    route_vty_out_tag (vty, &rm->p, ri, 0, SAFI_MPLS_VPN, json_array);
	          else
		    route_vty_out (vty, &rm->p, ri, 0, SAFI_MPLS_VPN, json_array);
                }

              if (use_json)
                {
                  struct prefix *p;
                  char buf_a[BUFSIZ];
                  char buf_b[BUFSIZ];
                  p = &rm->p;
                  sprintf(buf_a, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf_b, BUFSIZ), p->prefixlen);
                  json_object_object_add(json_mroute, buf_a, json_array);
                }
	    }

          if (use_json)
            {
              struct prefix *p;
              char buf_a[BUFSIZ];
              char buf_b[BUFSIZ];
              p = &rn->p;
              sprintf(buf_a, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf_b, BUFSIZ), p->prefixlen);
              json_object_object_add(json_nroute, buf_a, json_mroute);
            }
        }
    }

  if (use_json)
    {
      json_object_object_add(json, "routes", json_nroute);
      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpnv4_all,
       show_ip_bgp_vpnv4_all_cmd,
       "show ip bgp vpnv4 all",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n")
{
  return bgp_show_mpls_vpn (vty, NULL, bgp_show_type_normal, NULL, 0, 0);
}

DEFUN (show_ip_bgp_vpnv4_rd,
       show_ip_bgp_vpnv4_rd_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_mpls_vpn (vty, &prd, bgp_show_type_normal, NULL, 0, 0);
}

DEFUN (show_ip_bgp_vpnv4_all_tags,
       show_ip_bgp_vpnv4_all_tags_cmd,
       "show ip bgp vpnv4 all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_mpls_vpn (vty, NULL, bgp_show_type_normal, NULL,  1, 0);
}

DEFUN (show_ip_bgp_vpnv4_rd_tags,
       show_ip_bgp_vpnv4_rd_tags_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_mpls_vpn (vty, &prd, bgp_show_type_normal, NULL, 1, 0);
}

DEFUN (show_ip_bgp_vpnv4_all_neighbor_routes,
       show_ip_bgp_vpnv4_all_neighbor_routes_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D routes {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n"
       "JavaScript Object Notation\n")
{
  union sockunion su;
  struct peer *peer;
  int ret;
  u_char uj = use_json(argc, argv);

  ret = str2sockunion (argv[0], &su);
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
        vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_MPLS_VPN])
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

  return bgp_show_mpls_vpn (vty, NULL, bgp_show_type_neighbor, &su, 0, uj);
}

DEFUN (show_ip_bgp_vpnv4_rd_neighbor_routes,
       show_ip_bgp_vpnv4_rd_neighbor_routes_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors A.B.C.D routes {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n"
       "JavaScript Object Notation\n")
{
  int ret;
  union sockunion su;
  struct peer *peer;
  struct prefix_rd prd;
  u_char uj = use_json(argc, argv);

  ret = str2prefix_rd (argv[0], &prd);
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

  ret = str2sockunion (argv[1], &su);
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
        vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_MPLS_VPN])
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

  return bgp_show_mpls_vpn (vty, &prd, bgp_show_type_neighbor, &su, 0, uj);
}

DEFUN (show_ip_bgp_vpnv4_all_neighbor_advertised_routes,
       show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D advertised-routes {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n"
       "JavaScript Object Notation\n")
{
  int ret;
  struct peer *peer;
  union sockunion su;
  u_char uj = use_json(argc, argv);

  ret = str2sockunion (argv[0], &su);
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
        vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_MPLS_VPN])
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

  return show_adj_route_vpn (vty, peer, NULL, uj);
}

DEFUN (show_ip_bgp_vpnv4_rd_neighbor_advertised_routes,
       show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors A.B.C.D advertised-routes {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n"
       "JavaScript Object Notation\n")
{
  int ret;
  struct peer *peer;
  struct prefix_rd prd;
  union sockunion su;
  u_char uj = use_json(argc, argv);

  ret = str2sockunion (argv[1], &su);
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
        vty_out (vty, "Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_MPLS_VPN])
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

  ret = str2prefix_rd (argv[0], &prd);
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

  return show_adj_route_vpn (vty, peer, &prd, uj);
}

void
bgp_mplsvpn_init (void)
{
  install_element (BGP_VPNV4_NODE, &vpnv4_network_cmd);
  install_element (BGP_VPNV4_NODE, &no_vpnv4_network_cmd);


  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_tags_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd);

  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_tags_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_tags_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd);
}
