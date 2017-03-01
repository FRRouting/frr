
/*
 * This file created by LabN Consulting, L.L.C.
 *
 *
 * This file is based on bgp_mplsvpn.c which is Copyright (C) 2000
 * Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 */

/* 

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
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_encap.h"

#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

static void
ecom2prd(struct ecommunity *ecom, struct prefix_rd *prd)
{
    int	i;

    memset(prd, 0, sizeof(struct prefix_rd));
    prd->family = AF_UNSPEC;
    prd->prefixlen = 64;

    if (!ecom)
	return;

    for (i = 0; i < (ecom->size * ECOMMUNITY_SIZE); i += ECOMMUNITY_SIZE) {

	uint8_t *ep;

	ep = ecom->val + i;

	switch (ep[0]) {
	    default:
		continue;

	    case 0x80:
	    case 0x81:
	    case 0x82:
		if (ep[1] == 0x0) {
		    prd->val[1] = ep[0] & 0x03;
		    memcpy(prd->val + 2, ep + 2, 6);
		    return;
		}
	}
    }
}

int
bgp_nlri_parse_encap(
    struct peer		*peer,
    struct attr		*attr,
    struct bgp_nlri	*packet)
{
  u_char *pnt;
  u_char *lim;
  afi_t afi = packet->afi;
  struct prefix p;
  int psize = 0;
  int prefixlen;
  struct rd_as rd_as;
  struct rd_ip rd_ip;
  struct prefix_rd prd;
  struct ecommunity *pEcom = NULL;
  u_int16_t rdtype = 0xffff;
  char buf[BUFSIZ];

  /* Check peer status. */
  if (peer->status != Established)
    return 0;
  
  /* Make prefix_rd */
  if (attr && attr->extra && attr->extra->ecommunity)
      pEcom = attr->extra->ecommunity;

  ecom2prd(pEcom, &prd);
  memset(&rd_as, 0, sizeof(rd_as));
  memset(&rd_ip, 0, sizeof(rd_ip));

  if (pEcom) {

      rdtype = (prd.val[0] << 8) | prd.val[1];

      /* Decode RD value. */
      if (rdtype == RD_TYPE_AS)
	decode_rd_as (prd.val + 2, &rd_as);
      else if (rdtype == RD_TYPE_IP)
	decode_rd_ip (prd.val + 2, &rd_ip);
      else if (rdtype == RD_TYPE_AS4)
	decode_rd_as4 (prd.val + 2, &rd_as);
      else
	{
	  zlog_err ("Invalid RD type %d", rdtype);
	}

  }

  /*
   * NB: this code was based on the MPLS VPN code, which supported RDs.
   * For the moment we are retaining the underlying RIB structure that
   * keeps a per-RD radix tree, but since the RDs are not carried over
   * the wire, we set the RD internally to 0.
   */
  prd.family = AF_UNSPEC;
  prd.prefixlen = 64;
  memset(prd.val, 0, sizeof(prd.val));

  pnt = packet->nlri;
  lim = pnt + packet->length;

  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      /* Fetch prefix length. */
      prefixlen = *pnt++;
      p.family = afi2family(afi);
      if (p.family == 0) {
	/* bad afi, shouldn't happen */
	zlog_warn("%s: bad afi %d, dropping incoming route", __func__, afi);
	continue;
      }
      psize = PSIZE (prefixlen);

      p.prefixlen = prefixlen;
      memcpy (&p.u.prefix, pnt, psize);

      if (pnt + psize > lim)
	return -1;


      if (rdtype == RD_TYPE_AS)
	zlog_info ("rd-as %u:%u prefix %s/%d", rd_as.as, rd_as.val,
		   inet_ntop (p.family, &p.u.prefix, buf, BUFSIZ),
		   p.prefixlen);
      else if (rdtype == RD_TYPE_IP)
	zlog_info ("rd-ip %s:%u prefix %s/%d", inet_ntoa (rd_ip.ip),
		   rd_ip.val,
		   inet_ntop (p.family, &p.u.prefix, buf, BUFSIZ),
		   p.prefixlen);
      else if (rdtype == RD_TYPE_AS4)
	zlog_info ("rd-as4 %u:%u prefix %s/%d", rd_as.as, rd_as.val,
		   inet_ntop (p.family, &p.u.prefix, buf, BUFSIZ),
		   p.prefixlen);
      else
	zlog_info ("rd unknown, default to 0:0 prefix %s/%d",
	    inet_ntop (p.family, &p.u.prefix, buf, BUFSIZ),
	    p.prefixlen);

      if (attr) {
	bgp_update (peer, &p, 0, attr, afi, SAFI_ENCAP,
		    ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0, NULL);
      } else {
	bgp_withdraw (peer, &p, 0, attr, afi, SAFI_ENCAP,
		      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, NULL);
      }
    }

  /* Packet length consistency check. */
  if (pnt != lim)
    return -1;

  return 0;
}


/* TBD: these routes should probably all be host routes */

/* For testing purpose, static route of ENCAP. */
DEFUN (encap_network,
       encap_network_cmd,
       "network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify Route Distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  int idx_ipv4 = 1;
  int idx_rd = 3;
  int idx_word = 5;
  return bgp_static_set_safi (SAFI_ENCAP, vty, argv[idx_ipv4]->arg, argv[idx_rd]->arg, argv[idx_word]->arg,
                              NULL, 0, NULL, NULL, NULL, NULL);
}

/* For testing purpose, static route of ENCAP. */
DEFUN (no_encap_network,
       no_encap_network_cmd,
       "no network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify Route Distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  int idx_ipv4 = 2;
  int idx_rd = 4;
  int idx_word = 6;
  return bgp_static_unset_safi (SAFI_ENCAP, vty, argv[idx_ipv4]->arg, argv[idx_rd]->arg, argv[idx_word]->arg,
                                0, NULL, NULL, NULL);
}

static int
show_adj_route_encap (struct vty *vty, struct peer *peer, struct prefix_rd *prd)
{
  struct bgp *bgp;
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct attr *attr;
  int rd_header;
  int header = 1;
  char v4_header[] = "   Network          Next Hop            Metric LocPrf Weight Path%s";

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (rn = bgp_table_top (bgp->rib[AFI_IP][SAFI_ENCAP]); rn;
       rn = bgp_route_next (rn))
    {
      if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
        continue;

      if ((table = rn->info) != NULL)
        {
          rd_header = 1;

          for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
            if ((attr = rm->info) != NULL)
              {
                if (header)
                  {
                    vty_out (vty, "BGP table version is 0, local router ID is %s%s",
                             inet_ntoa (bgp->router_id), VTY_NEWLINE);
                    vty_out (vty, "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal%s",
                             VTY_NEWLINE);
                    vty_out (vty, "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s",
                             VTY_NEWLINE, VTY_NEWLINE);
                    vty_out (vty, v4_header, VTY_NEWLINE);
                    header = 0;
                  }

                if (rd_header)
                  {
                    u_int16_t type;
                    struct rd_as rd_as;
                    struct rd_ip rd_ip;
                    u_char *pnt;

                    pnt = rn->p.u.val;

                    vty_out (vty, "Route Distinguisher: ");

                    /* Decode RD type. */
                    type = decode_rd_type (pnt);

		    switch (type) {

		    case RD_TYPE_AS:
                      decode_rd_as (pnt + 2, &rd_as);
                      vty_out (vty, "%u:%d", rd_as.as, rd_as.val);
		      break;

		    case RD_TYPE_IP:
                      decode_rd_ip (pnt + 2, &rd_ip);
                      vty_out (vty, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
		      break;

		    default:
                      vty_out (vty, "unknown RD type");
		    }


                    vty_out (vty, "%s", VTY_NEWLINE);
                    rd_header = 0;
                  }
                route_vty_out_tmp (vty, &rm->p, attr, SAFI_ENCAP, 0, NULL);
              }
        }
    }
  return CMD_SUCCESS;
}

int
bgp_show_encap (
    struct vty *vty,
    afi_t afi,
    struct prefix_rd *prd,
    enum bgp_show_type type,
    void *output_arg,
    int tags)
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

  unsigned long output_count = 0;
  unsigned long total_count  = 0;

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ((afi != AFI_IP) && (afi != AFI_IP6)) {
      vty_out (vty, "Afi %d not supported%s", afi, VTY_NEWLINE);
      return CMD_WARNING;
  }
  
  for (rn = bgp_table_top (bgp->rib[afi][SAFI_ENCAP]); rn; rn = bgp_route_next (rn))
    {
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
		if (header)
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

		    vty_out (vty, "Route Distinguisher: ");

		    switch (type) {

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
		    rd_header = 0;
		  }
	        if (tags)
		  route_vty_out_tag (vty, &rm->p, ri, 0, SAFI_ENCAP, NULL);
	        else
		  route_vty_out (vty, &rm->p, ri, 0, SAFI_ENCAP, NULL);
                output_count++;
	      }
        }
    }

  if (output_count == 0)
    {
        vty_out (vty, "No prefixes displayed, %ld exist%s", total_count, VTY_NEWLINE);
    }
  else
    vty_out (vty, "%sDisplayed %ld routes and %ld total paths%s",
	     VTY_NEWLINE, output_count, total_count, VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (show_bgp_ipv4_encap_rd,
       show_bgp_ipv4_encap_rd_cmd,
       "show [ip] bgp ipv4 encap rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n")
{
  int idx_rd = 5;
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_rd]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_encap (vty, AFI_IP, &prd, bgp_show_type_normal, NULL, 0);
}

DEFUN (show_bgp_ipv6_encap_rd,
       show_bgp_ipv6_encap_rd_cmd,
       "show [ip] bgp ipv6 encap rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
  int idx_rd = 5;
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_rd]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_encap (vty, AFI_IP6, &prd, bgp_show_type_normal, NULL, 0);
}

DEFUN (show_bgp_ipv4_encap_tags,
       show_bgp_ipv4_encap_tags_cmd,
       "show [ip] bgp ipv4 encap tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_encap (vty, AFI_IP, NULL, bgp_show_type_normal, NULL,  1);
}

DEFUN (show_bgp_ipv6_encap_tags,
       show_bgp_ipv6_encap_tags_cmd,
       "show [ip] bgp ipv6 encap tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_encap (vty, AFI_IP6, NULL, bgp_show_type_normal, NULL,  1);
}

DEFUN (show_bgp_ipv4_encap_rd_tags,
       show_bgp_ipv4_encap_rd_tags_cmd,
       "show [ip] bgp ipv4 encap rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
  int idx_rd = 5;
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_rd]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_encap (vty, AFI_IP, &prd, bgp_show_type_normal, NULL, 1);
}

DEFUN (show_bgp_ipv6_encap_rd_tags,
       show_bgp_ipv6_encap_rd_tags_cmd,
       "show [ip] bgp ipv6 encap rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
  int idx_rd = 5;
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_rd]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_encap (vty, AFI_IP6, &prd, bgp_show_type_normal, NULL, 1);
}

DEFUN (show_bgp_ipv4_encap_neighbor_routes,
       show_bgp_ipv4_encap_neighbor_routes_cmd,
       "show [ip] bgp ipv4 encap neighbors A.B.C.D routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  int idx_peer = 0;
  union sockunion *su;
  struct peer *peer;

  argv_find(argv, argc, "A.B.C.D", &idx_peer);
  su = sockunion_str2su (argv[idx_peer]->arg);

  if (!su)
    {
      vty_out (vty, "Malformed address: %s%s", argv[idx_peer]->arg, VTY_NEWLINE);
               return CMD_WARNING;
    }

  peer = peer_lookup (NULL, su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_ENCAP])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_encap (vty, AFI_IP, NULL, bgp_show_type_neighbor, su, 0);
}

DEFUN (show_bgp_ipv6_encap_neighbor_routes,
       show_bgp_ipv6_encap_neighbor_routes_cmd,
       "show [ip] bgp ipv6 encap neighbors A.B.C.D routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  int idx_peer = 5;
  union sockunion su;
  struct peer *peer;
  
  if (str2sockunion(argv[idx_peer]->arg, &su))
    {
      vty_out (vty, "Malformed address: %s%s", argv[idx_peer]->arg, VTY_NEWLINE);
               return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP6][SAFI_ENCAP])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_encap (vty, AFI_IP6, NULL, bgp_show_type_neighbor, &su, 0);
}

DEFUN (show_bgp_ipv4_encap_rd_neighbor_routes,
       show_bgp_ipv4_encap_rd_neighbor_routes_cmd,
       "show [ip] bgp ipv4 encap rd ASN:nn_or_IP-address:nn neighbors <A.B.C.D|X:X::X:X> routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  int idx_rd = 5;
  int idx_peer = 7;
  int ret;
  union sockunion su;
  struct peer *peer;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_rd]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (str2sockunion(argv[idx_peer]->arg, &su))
    {
      vty_out (vty, "Malformed address: %s%s", argv[idx_peer]->arg, VTY_NEWLINE);
               return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_ENCAP])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_encap (vty, AFI_IP, &prd, bgp_show_type_neighbor, &su, 0);
}

DEFUN (show_bgp_ipv6_encap_rd_neighbor_routes,
       show_bgp_ipv6_encap_rd_neighbor_routes_cmd,
       "show [ip] bgp ipv6 encap rd ASN:nn_or_IP-address:nn neighbors <A.B.C.D|X:X::X:X> routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  int idx_rd = 5;
  int idx_peer = 7;
  int ret;
  union sockunion su;
  struct peer *peer;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[idx_rd]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (str2sockunion(argv[idx_peer]->arg, &su))
    {
      vty_out (vty, "Malformed address: %s%s", argv[idx_peer]->arg, VTY_NEWLINE);
               return CMD_WARNING;
    }

  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP6][SAFI_ENCAP])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_encap (vty, AFI_IP6, &prd, bgp_show_type_neighbor, &su, 0);
}

DEFUN (show_bgp_ipv4_encap_neighbor_advertised_routes,
       show_bgp_ipv4_encap_neighbor_advertised_routes_cmd,
       "show [ip] bgp ipv4 encap neighbors A.B.C.D advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  int idx_peer = 5;
  int ret;
  struct peer *peer;
  union sockunion su;

  ret = str2sockunion (argv[idx_peer]->arg, &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[idx_peer]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_ENCAP])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_encap (vty, peer, NULL);
}

DEFUN (show_bgp_ipv6_encap_neighbor_advertised_routes,
       show_bgp_ipv6_encap_neighbor_advertised_routes_cmd,
       "show [ip] bgp ipv6 encap neighbors A.B.C.D advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  int idx_peer = 5;
  int ret;
  struct peer *peer;
  union sockunion su;

  ret = str2sockunion (argv[idx_peer]->arg, &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[idx_peer]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP6][SAFI_ENCAP])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_encap (vty, peer, NULL);
}

DEFUN (show_bgp_ipv4_encap_rd_neighbor_advertised_routes,
       show_bgp_ipv4_encap_rd_neighbor_advertised_routes_cmd,
       "show [ip] bgp ipv4 encap rd ASN:nn_or_IP-address:nn neighbors <A.B.C.D|X:X::X:X> advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  int idx_rd = 5;
  int idx_peer = 7;
  int ret;
  struct peer *peer;
  struct prefix_rd prd;
  union sockunion su;

  ret = str2sockunion (argv[idx_peer]->arg, &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[idx_peer]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP][SAFI_ENCAP])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_rd (argv[idx_rd]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_encap (vty, peer, &prd);
}

DEFUN (show_bgp_ipv6_encap_rd_neighbor_advertised_routes,
       show_bgp_ipv6_encap_rd_neighbor_advertised_routes_cmd,
       "show [ip] bgp ipv6 encap rd ASN:nn_or_IP-address:nn neighbors <A.B.C.D|X:X::X:X> advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display ENCAP NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "ENCAP Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  int idx_rd = 5;
  int idx_peer = 7;
  int ret;
  struct peer *peer;
  struct prefix_rd prd;
  union sockunion su;

  ret = str2sockunion (argv[idx_peer]->arg, &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[idx_peer]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup (NULL, &su);
  if (! peer || ! peer->afc[AFI_IP6][SAFI_ENCAP])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_rd (argv[idx_rd]->arg, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return show_adj_route_encap (vty, peer, &prd);
}

void
bgp_encap_init (void)
{
  install_element (BGP_ENCAP_NODE, &encap_network_cmd);
  install_element (BGP_ENCAP_NODE, &no_encap_network_cmd);

  install_element (VIEW_NODE, &show_bgp_ipv4_encap_rd_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_encap_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_encap_rd_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_encap_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_encap_rd_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_encap_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_encap_rd_neighbor_advertised_routes_cmd);

  install_element (VIEW_NODE, &show_bgp_ipv6_encap_rd_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_encap_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_encap_rd_tags_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_encap_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_encap_rd_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_encap_neighbor_advertised_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_encap_rd_neighbor_advertised_routes_cmd);
}
