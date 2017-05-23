
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

void
bgp_encap_init (void)
{
}
