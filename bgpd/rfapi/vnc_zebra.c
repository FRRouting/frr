/* 
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

/*
 * File:	vnc_zebra.c
 * Purpose:	Handle exchange of routes between VNC and Zebra
 */

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/log.h"
#include "lib/command.h"
#include "lib/zclient.h"
#include "lib/stream.h"
#include "lib/memory.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_advertise.h"

#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/vnc_zebra.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/rfapi_backend.h"

static struct rfapi_descriptor vncHD1VR;        /* Single-VR export dummy nve descr */
static struct zclient *zclient_vnc = NULL;

/***********************************************************************
 *	REDISTRIBUTE: Zebra sends updates/withdraws to BGPD
 ***********************************************************************/

/*
 * Routes coming from zebra get added to VNC here
 */
static void
vnc_redistribute_add (
    struct prefix	*p,
    struct in_addr	*nexthop,
    u_int32_t		metric,
    uint8_t		type)
{
  struct bgp *bgp = bgp_get_default ();
  struct prefix_rd prd;
  struct rfapi_ip_addr vnaddr;
  afi_t afi;
  uint32_t local_pref = rfp_cost_to_localpref (metric > 255 ? 255 : metric);

  if (!bgp)
    return;

  if (!bgp->rfapi_cfg)
    {
      zlog_debug ("%s: bgp->rfapi_cfg is NULL, skipping", __func__);
      return;
    }

  afi = family2afi (p->family);
  if (!afi)
    {
      zlog_debug ("%s: unknown prefix address family %d", __func__,
                  p->family);
      return;
    }

  if (!bgp->rfapi_cfg->redist[afi][type])
    {
      zlog_debug
        ("%s: bgp->rfapi_cfg->redist[afi=%d][type=%d] is 0, skipping",
         __func__, afi, type);
      return;
    }
  if (!bgp->rfapi_cfg->rfg_redist)
    {
      zlog_debug ("%s: no redist nve group, skipping", __func__);
      return;
    }

  /*
   * Assume nve group's configured VN address prefix is a host
   * route which also happens to give the NVE VN address to use
   * for redistributing into VNC.
   */
  vnaddr.addr_family = bgp->rfapi_cfg->rfg_redist->vn_prefix.family;
  switch (bgp->rfapi_cfg->rfg_redist->vn_prefix.family)
    {
    case AF_INET:
      if (bgp->rfapi_cfg->rfg_redist->vn_prefix.prefixlen != 32)
        {
          zlog_debug
            ("%s: redist nve group VN prefix len (%d) != 32, skipping",
             __func__, bgp->rfapi_cfg->rfg_redist->vn_prefix.prefixlen);
          return;
        }
      vnaddr.addr.v4 = bgp->rfapi_cfg->rfg_redist->vn_prefix.u.prefix4;
      break;
    case AF_INET6:
      if (bgp->rfapi_cfg->rfg_redist->vn_prefix.prefixlen != 128)
        {
          zlog_debug
            ("%s: redist nve group VN prefix len (%d) != 128, skipping",
             __func__, bgp->rfapi_cfg->rfg_redist->vn_prefix.prefixlen);
          return;
        }
      vnaddr.addr.v6 = bgp->rfapi_cfg->rfg_redist->vn_prefix.u.prefix6;
      break;
    default:
      zlog_debug
        ("%s: no redist nve group VN host prefix configured, skipping",
         __func__);
      return;
    }

  /*
   * Assume nve group's configured UN address prefix is a host
   * route which also happens to give the NVE UN address to use
   * for redistributing into VNC.
   */

  /*
   * Set UN address in dummy nve descriptor so add_vnc_route
   * can use it in VNC tunnel SubTLV
   */
  {
    struct rfapi_ip_prefix pfx_un;

    rfapiQprefix2Rprefix (&bgp->rfapi_cfg->rfg_redist->un_prefix, &pfx_un);

    switch (pfx_un.prefix.addr_family)
      {
      case AF_INET:
        if (pfx_un.length != 32)
          {
            zlog_debug
              ("%s: redist nve group UN prefix len (%d) != 32, skipping",
               __func__, pfx_un.length);
            return;
          }
        break;
      case AF_INET6:
        if (pfx_un.length != 128)
          {
            zlog_debug
              ("%s: redist nve group UN prefix len (%d) != 128, skipping",
               __func__, pfx_un.length);
            return;
          }
        break;
      default:
        zlog_debug
          ("%s: no redist nve group UN host prefix configured, skipping",
           __func__);
        return;
      }

    vncHD1VR.un_addr = pfx_un.prefix;

    if (!vncHD1VR.peer)
      {
        /*
         * Same setup as in rfapi_open()
         */
        vncHD1VR.peer = peer_new (bgp);
        vncHD1VR.peer->status = Established;    /* keep bgp core happy */
        bgp_sync_delete (vncHD1VR.peer);        /* don't need these */
        if (vncHD1VR.peer->ibuf)
          {
            stream_free (vncHD1VR.peer->ibuf);  /* don't need it */
            vncHD1VR.peer->ibuf = NULL;
          }
        if (vncHD1VR.peer->obuf)
          {
            stream_fifo_free (vncHD1VR.peer->obuf);     /* don't need it */
            vncHD1VR.peer->obuf = NULL;
          }
        if (vncHD1VR.peer->work)
          {
            stream_free (vncHD1VR.peer->work);  /* don't need it */
            vncHD1VR.peer->work = NULL;
          }
        /* base code assumes have valid host pointer */
        vncHD1VR.peer->host = XSTRDUP (MTYPE_BGP_PEER_HOST, ".zebra.");

        /* Mark peer as belonging to HD */
        SET_FLAG (vncHD1VR.peer->flags, PEER_FLAG_IS_RFAPI_HD);
      }
  }

  memset (&prd, 0, sizeof (prd));
  prd = bgp->rfapi_cfg->rfg_redist->rd;
  prd.family = AF_UNSPEC;
  prd.prefixlen = 64;

  add_vnc_route (&vncHD1VR,     /* cookie + UN addr */
                 bgp, SAFI_MPLS_VPN, p, &prd, &vnaddr, &local_pref, &(bgp->rfapi_cfg->redist_lifetime), NULL,   /* RFP options */
                 NULL,          /* struct rfapi_un_option */
                 NULL,          /* struct rfapi_vn_option */
                 bgp->rfapi_cfg->rfg_redist->rt_export_list, NULL, NULL,        /* label: default */
                 type, BGP_ROUTE_REDISTRIBUTE, 0);      /* flags */
}

/*
 * Route deletions from zebra propagate to VNC here
 */
static void
vnc_redistribute_delete (struct prefix *p, uint8_t type)
{
  struct bgp *bgp = bgp_get_default ();
  struct prefix_rd prd;
  afi_t afi;

  if (!bgp)
    return;

  if (!bgp->rfapi_cfg)
    {
      zlog_debug ("%s: bgp->rfapi_cfg is NULL, skipping", __func__);
      return;
    }
  afi = family2afi (p->family);
  if (!afi)
    {
      zlog_debug ("%s: unknown prefix address family %d", __func__,
                  p->family);
      return;
    }
  if (!bgp->rfapi_cfg->redist[afi][type])
    {
      zlog_debug
        ("%s: bgp->rfapi_cfg->redist[afi=%d][type=%d] is 0, skipping",
         __func__, afi, type);
      return;
    }
  if (!bgp->rfapi_cfg->rfg_redist)
    {
      zlog_debug ("%s: no redist nve group, skipping", __func__);
      return;
    }

  memset (&prd, 0, sizeof (prd));
  prd = bgp->rfapi_cfg->rfg_redist->rd;
  prd.family = AF_UNSPEC;
  prd.prefixlen = 64;

  del_vnc_route (&vncHD1VR,     /* use dummy ptr as cookie */
                 vncHD1VR.peer,
                 bgp,
                 SAFI_MPLS_VPN,
                 p, &prd, type, BGP_ROUTE_REDISTRIBUTE, NULL, 0);
}

/*
 * Flush all redistributed routes of type <type>
 */
static void
vnc_redistribute_withdraw (struct bgp *bgp, afi_t afi, uint8_t type)
{
  struct prefix_rd prd;
  struct bgp_table *table;
  struct bgp_node *prn;
  struct bgp_node *rn;

  zlog_debug ("%s: entry", __func__);

  if (!bgp)
    return;
  if (!bgp->rfapi_cfg)
    {
      zlog_debug ("%s: bgp->rfapi_cfg is NULL, skipping", __func__);
      return;
    }

  /*
   * Loop over all the RDs
   */
  for (prn = bgp_table_top (bgp->rib[afi][SAFI_MPLS_VPN]); prn;
       prn = bgp_route_next (prn))
    {
      memset (&prd, 0, sizeof (prd));
      prd.family = AF_UNSPEC;
      prd.prefixlen = 64;
      memcpy (prd.val, prn->p.u.val, 8);

      /* This is the per-RD table of prefixes */
      table = prn->info;

      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
        {

          struct bgp_info *ri;

          for (ri = rn->info; ri; ri = ri->next)
            {
              if (ri->type == type)
                {               /* has matching redist type */
                  break;
                }
            }
          if (ri)
            {
              del_vnc_route (&vncHD1VR, /* use dummy ptr as cookie */
                             vncHD1VR.peer,
                             bgp,
                             SAFI_MPLS_VPN,
                             &(rn->p),
                             &prd, type, BGP_ROUTE_REDISTRIBUTE, NULL, 0);
            }
        }
    }
  zlog_debug ("%s: return", __func__);
}

/*
 * Zebra route add and delete treatment.
 *
 * Assumes 1 nexthop
 */
static int
vnc_zebra_read_ipv4 (
    int			command,
    struct zclient	*zclient,
    zebra_size_t	length,
    vrf_id_t		vrf_id)
{
  struct stream *s;
  struct zapi_ipv4 api;
  unsigned long ifindex;
  struct in_addr nexthop;
  struct prefix_ipv4 p;

  s = zclient->ibuf;
  ifindex = 0;
  nexthop.s_addr = 0;

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv4 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      nexthop.s_addr = stream_get_ipv4 (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      ifindex = stream_getl (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  if (command == ZEBRA_IPV4_ROUTE_ADD)
    {
      if (BGP_DEBUG (zebra, ZEBRA))
        {
          char buf[2][INET_ADDRSTRLEN];
          zlog_debug
            ("%s: Zebra rcvd: IPv4 route add %s %s/%d nexthop %s metric %u",
             __func__, zebra_route_string (api.type), inet_ntop (AF_INET,
                                                                 &p.prefix,
                                                                 buf[0],
                                                                 sizeof (buf
                                                                         [0])),
             p.prefixlen, inet_ntop (AF_INET, &nexthop, buf[1],
                                     sizeof (buf[1])), api.metric);
        }
      vnc_redistribute_add ((struct prefix *) &p, &nexthop, api.metric,
                            api.type);
    }
  else
    {
      if (BGP_DEBUG (zebra, ZEBRA))
        {
          char buf[2][INET_ADDRSTRLEN];
          zlog_debug ("%s: Zebra rcvd: IPv4 route delete %s %s/%d "
                      "nexthop %s metric %u",
                      __func__,
                      zebra_route_string (api.type),
                      inet_ntop (AF_INET, &p.prefix, buf[0], sizeof (buf[0])),
                      p.prefixlen,
                      inet_ntop (AF_INET, &nexthop, buf[1], sizeof (buf[1])),
                      api.metric);
        }
      vnc_redistribute_delete ((struct prefix *) &p, api.type);
    }

  return 0;
}

/* Zebra route add and delete treatment. */
static int
vnc_zebra_read_ipv6 (
    int			command,
    struct zclient	*zclient,
    zebra_size_t	length,
    vrf_id_t		vrf_id)
{
  struct stream *s;
  struct zapi_ipv6 api;
  unsigned long ifindex;
  struct in6_addr nexthop;
  struct prefix_ipv6 p;

  s = zclient->ibuf;
  ifindex = 0;
  memset (&nexthop, 0, sizeof (struct in6_addr));

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv6 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      stream_get (&nexthop, s, 16);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      ifindex = stream_getl (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  else
    api.distance = 0;
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  /* Simply ignore link-local address. */
  if (IN6_IS_ADDR_LINKLOCAL (&p.prefix))
    return 0;

  if (command == ZEBRA_IPV6_ROUTE_ADD)
    {
      if (BGP_DEBUG (zebra, ZEBRA))
        {
          char buf[INET6_ADDRSTRLEN];
          zlog_debug ("Zebra rcvd: IPv6 route add %s %s/%d metric %u",
                      zebra_route_string (api.type),
                      inet_ntop (AF_INET6, &p.prefix, buf, sizeof (buf)),
                      p.prefixlen, api.metric);
        }
      vnc_redistribute_add ((struct prefix *) &p, NULL, api.metric, api.type);
    }
  else
    {
      if (BGP_DEBUG (zebra, ZEBRA))
        {
          char buf[INET6_ADDRSTRLEN];
          zlog_debug ("Zebra rcvd: IPv6 route delete %s %s/%d metric %u",
                      zebra_route_string (api.type),
                      inet_ntop (AF_INET6, &p.prefix, buf, sizeof (buf)),
                      p.prefixlen, api.metric);
        }
      vnc_redistribute_delete ((struct prefix *) &p, api.type);
    }

  return 0;
}

/***********************************************************************
 *	vnc_bgp_zebra_*: VNC sends updates/withdraws to Zebra
 ***********************************************************************/

/*
 * low-level message builder
 */
static void
vnc_zebra_route_msg (
    struct prefix	*p,
    int			nhp_count,
    void		*nhp_ary,
    int			add)   /* 1 = add, 0 = del */
{
  if (!nhp_count)
    {
      zlog_debug ("%s: empty nexthop list, skipping", __func__);
      return;
    }

  if (p->family == AF_INET)
    {

      struct zapi_ipv4 api;

      api.flags = 0;
      api.vrf_id = VRF_DEFAULT;
      api.type = ZEBRA_ROUTE_VNC;
      api.message = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);     /* TBD what's it mean? */
      api.nexthop_num = nhp_count;
      api.nexthop = nhp_ary;
      api.ifindex_num = 0;

      if (BGP_DEBUG (zebra, ZEBRA))
        {

          char buf[INET_ADDRSTRLEN];
          zlog_debug ("%s: Zebra send: IPv4 route %s %s/%d, nhp_count=%d",
                      __func__,
                      (add ? "add" : "del"),
                      inet_ntop (AF_INET, &p->u.prefix4, buf, sizeof (buf)),
                      p->prefixlen, nhp_count);
        }

      zapi_ipv4_route ((add ? ZEBRA_IPV4_NEXTHOP_ADD :
                        ZEBRA_IPV4_NEXTHOP_DELETE), zclient_vnc,
                       (struct prefix_ipv4 *) p, &api);

    }
  else if (p->family == AF_INET6)
    {

      struct zapi_ipv6 api;
      ifindex_t ifindex = 0;

      /* Make Zebra API structure. */
      api.flags = 0;
      api.vrf_id = VRF_DEFAULT;
      api.type = ZEBRA_ROUTE_VNC;
      api.message = 0;
      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);     /* TBD means? */
      api.nexthop_num = nhp_count;
      api.nexthop = nhp_ary;
      SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
      api.ifindex_num = 1;
      api.ifindex = &ifindex;

      if (BGP_DEBUG (zebra, ZEBRA))
        {

          char buf[INET6_ADDRSTRLEN];
          zlog_debug ("%s: Zebra send: IPv6 route %s %s/%d nhp_count=%d",
                      __func__,
                      (add ? "add" : "del"),
                      inet_ntop (AF_INET6, &p->u.prefix6, buf, sizeof (buf)),
                      p->prefixlen, nhp_count);
        }

      zapi_ipv6_route ((add ? ZEBRA_IPV6_NEXTHOP_ADD :
                        ZEBRA_IPV6_NEXTHOP_DELETE), zclient_vnc,
                       (struct prefix_ipv6 *) p, &api);
    }
  else
    {
      zlog_debug ("%s: unknown prefix address family, skipping", __func__);
      return;
    }
}


static void
nve_list_to_nh_array (
    u_char	family,
    struct list	*nve_list,
    int		*nh_count_ret,
    void	**nh_ary_ret,	/* returned address array */
    void	**nhp_ary_ret)	/* returned pointer array */
{
  int nve_count = listcount (nve_list);

  *nh_count_ret = 0;
  *nh_ary_ret = NULL;
  *nhp_ary_ret = NULL;

  if (!nve_count)
    {
      zlog_debug ("%s: empty nve_list, skipping", __func__);
      return;
    }

  if (family == AF_INET)
    {
      struct listnode *ln;
      struct in_addr *iap;
      struct in_addr **v;

      /* 
       * Array of nexthop addresses
       */
      *nh_ary_ret = XCALLOC (MTYPE_TMP, nve_count * sizeof (struct in_addr));

      /*
       * Array of pointers to nexthop addresses
       */
      *nhp_ary_ret =
        XCALLOC (MTYPE_TMP, nve_count * sizeof (struct in_addr *));
      iap = *nh_ary_ret;
      v = *nhp_ary_ret;

      for (ln = listhead (nve_list); ln; ln = listnextnode (ln))
        {

          struct rfapi_descriptor *irfd;
          struct prefix nhp;

          irfd = listgetdata (ln);

          if (rfapiRaddr2Qprefix (&irfd->vn_addr, &nhp))
            continue;

          *iap = nhp.u.prefix4;
          *v = iap;
          zlog_debug ("%s: ipadr: (%p)<-0x%x, ptr: (%p)<-%p",
                      __func__, iap, nhp.u.prefix4.s_addr, v, iap);

          ++iap;
          ++v;
          ++*nh_count_ret;
        }

    }
  else if (family == AF_INET6)
    {

      struct listnode *ln;

      *nh_ary_ret = XCALLOC (MTYPE_TMP, nve_count * sizeof (struct in6_addr));

      *nhp_ary_ret = XCALLOC (MTYPE_TMP,
                              nve_count * sizeof (struct in6_addr *));

      for (ln = listhead (nve_list); ln; ln = listnextnode (ln))
        {

          struct rfapi_descriptor *irfd;
          struct in6_addr *iap = *nh_ary_ret;
          struct in6_addr **v = *nhp_ary_ret;
          struct prefix nhp;

          irfd = listgetdata (ln);

          if (rfapiRaddr2Qprefix (&irfd->vn_addr, &nhp))
            continue;

          *iap = nhp.u.prefix6;
          *v = iap;

          ++iap;
          ++v;
          ++*nh_count_ret;
        }
    }
}

static void
import_table_to_nve_list_zebra (
    struct bgp			*bgp,
    struct rfapi_import_table	*it,
    struct list			**nves,
    uint8_t			family)
{
  struct listnode *node;
  struct rfapi_rfg_name *rfgn;

  /*
   * Loop over the list of NVE-Groups configured for
   * exporting to direct-bgp.
   *
   * Build a list of NVEs that use this import table
   */
  *nves = NULL;
  for (ALL_LIST_ELEMENTS_RO (bgp->rfapi_cfg->rfg_export_zebra_l, node, rfgn))
    {

      /*
       * If this NVE-Group's import table matches the current one
       */
      if (rfgn->rfg && rfgn->rfg->nves && rfgn->rfg->rfapi_import_table == it)
        {

          nve_group_to_nve_list (rfgn->rfg, nves, family);
        }
    }
}

static void
vnc_zebra_add_del_prefix (
    struct bgp			*bgp,
    struct rfapi_import_table	*import_table,
    struct route_node		*rn,
    int				add)	/* !0 = add, 0 = del */
{
  struct list *nves;

  int nexthop_count = 0;
  void *nh_ary = NULL;
  void *nhp_ary = NULL;

  zlog_debug ("%s: entry, add=%d", __func__, add);

  if (zclient_vnc->sock < 0)
    return;

  if (rn->p.family != AF_INET
      && rn->p.family != AF_INET6)
    {
      zlog_err ("%s: invalid route node addr family", __func__);
      return;
    }

  if (!zclient_vnc->redist[family2afi(rn->p.family)][ZEBRA_ROUTE_VNC])
    return;

  if (!bgp->rfapi_cfg)
    {
      zlog_debug ("%s: bgp->rfapi_cfg is NULL, skipping", __func__);
      return;
    }
  if (!listcount (bgp->rfapi_cfg->rfg_export_zebra_l))
    {
      zlog_debug ("%s: no zebra export nve group, skipping", __func__);
      return;
    }

  import_table_to_nve_list_zebra (bgp, import_table, &nves, rn->p.family);

  if (nves)
    {
      nve_list_to_nh_array (rn->p.family,
                            nves, &nexthop_count, &nh_ary, &nhp_ary);

      list_delete (nves);

      if (nexthop_count)
        vnc_zebra_route_msg (&rn->p, nexthop_count, nhp_ary, add);
    }

  if (nhp_ary)
    XFREE (MTYPE_TMP, nhp_ary);
  if (nh_ary)
    XFREE (MTYPE_TMP, nh_ary);
}

void
vnc_zebra_add_prefix (
    struct bgp			*bgp,
    struct rfapi_import_table	*import_table,
    struct route_node		*rn)
{
  vnc_zebra_add_del_prefix (bgp, import_table, rn, 1);
}

void
vnc_zebra_del_prefix (
    struct bgp			*bgp,
    struct rfapi_import_table	*import_table,
    struct route_node		*rn)
{
  vnc_zebra_add_del_prefix (bgp, import_table, rn, 0);
}



static void
vnc_zebra_add_del_nve (
    struct bgp			*bgp,
    struct rfapi_descriptor	*rfd,
    int				add)  /* 0 = del, !0 = add */
{
  struct listnode *node;
  struct rfapi_rfg_name *rfgn;
  struct rfapi_nve_group_cfg *rfg = rfd->rfg;
  afi_t afi = family2afi (rfd->vn_addr.addr_family);
  struct prefix nhp;
//    struct prefix             *nhpp;
  void *pAddr;

  zlog_debug ("%s: entry, add=%d", __func__, add);

  if (zclient_vnc->sock < 0)
    return;

  if (!zclient_vnc->redist[afi][ZEBRA_ROUTE_VNC])
    return;

  if (afi != AFI_IP && afi != AFI_IP6)
    {
      zlog_err ("%s: invalid vn addr family", __func__);
      return;
    }

  if (!bgp)
    return;
  if (!bgp->rfapi_cfg)
    {
      zlog_debug ("%s: bgp->rfapi_cfg is NULL, skipping", __func__);
      return;
    }

  if (rfapiRaddr2Qprefix (&rfd->vn_addr, &nhp))
    {
      zlog_debug ("%s: can't convert vn address, skipping", __func__);
      return;
    }

  pAddr = &nhp.u.prefix4;

  /*
   * Loop over the list of NVE-Groups configured for
   * exporting to zebra and see if this new NVE's
   * group is among them.
   */
  for (ALL_LIST_ELEMENTS_RO (bgp->rfapi_cfg->rfg_export_zebra_l, node, rfgn))
    {

      /*
       * Yes, this NVE's group is configured for export to zebra
       */
      if (rfgn->rfg == rfg)
        {

          struct route_table *rt = NULL;
          struct route_node *rn;
          struct rfapi_import_table *import_table;
          import_table = rfg->rfapi_import_table;

          zlog_debug ("%s: this nve's group is in zebra export list",
                      __func__);

          rt = import_table->imported_vpn[afi];

          /* 
           * Walk the NVE-Group's VNC Import table
           */
          for (rn = route_top (rt); rn; rn = route_next (rn))
            {

              if (rn->info)
                {

                  zlog_debug ("%s: sending %s", __func__,
                              (add ? "add" : "del"));
                  vnc_zebra_route_msg (&rn->p, 1, &pAddr, add);
                }
            }
        }
    }
}

void
vnc_zebra_add_nve (struct bgp *bgp, struct rfapi_descriptor *rfd)
{
  vnc_zebra_add_del_nve (bgp, rfd, 1);
}

void
vnc_zebra_del_nve (struct bgp *bgp, struct rfapi_descriptor *rfd)
{
  vnc_zebra_add_del_nve (bgp, rfd, 0);
}

static void
vnc_zebra_add_del_group_afi (
    struct bgp			*bgp,
    struct rfapi_nve_group_cfg	*rfg,
    afi_t			afi,
    int				add)
{
  struct route_table *rt = NULL;
  struct route_node *rn;
  struct rfapi_import_table *import_table;
  uint8_t family = afi2family (afi);

  struct list *nves = NULL;
  int nexthop_count = 0;
  void *nh_ary = NULL;
  void *nhp_ary = NULL;

  zlog_debug ("%s: entry", __func__);
  import_table = rfg->rfapi_import_table;
  if (!import_table)
    {
      zlog_debug ("%s: import table not defined, returning", __func__);
      return;
    }

  if (afi == AFI_IP
      || afi == AFI_IP6)
    {
      rt = import_table->imported_vpn[afi];
    }
  else
    {
      zlog_err ("%s: bad afi %d", __func__, afi);
      return;
    }

  if (!family)
    {
      zlog_err ("%s: computed bad family: %d", __func__, family);
      return;
    }

  if (!rfg->nves)
    {
      /* avoid segfault below if list doesn't exist */
      zlog_debug ("%s: no NVEs in this group", __func__);
      return;
    }

  nve_group_to_nve_list (rfg, &nves, family);
  if (nves)
    {
      zlog_debug ("%s: have nves", __func__);
      nve_list_to_nh_array (family, nves, &nexthop_count, &nh_ary, &nhp_ary);

      zlog_debug ("%s: family: %d, nve count: %d", __func__, family,
                  nexthop_count);

      list_delete (nves);

      if (nexthop_count)
        {
          /* 
           * Walk the NVE-Group's VNC Import table
           */
          for (rn = route_top (rt); rn; rn = route_next (rn))
            {
              if (rn->info)
                {
                  vnc_zebra_route_msg (&rn->p, nexthop_count, nhp_ary, add);
                }
            }
        }
      if (nhp_ary)
        XFREE (MTYPE_TMP, nhp_ary);
      if (nh_ary)
        XFREE (MTYPE_TMP, nh_ary);
    }
}

void
vnc_zebra_add_group (struct bgp *bgp, struct rfapi_nve_group_cfg *rfg)
{
  vnc_zebra_add_del_group_afi (bgp, rfg, AFI_IP, 1);
  vnc_zebra_add_del_group_afi (bgp, rfg, AFI_IP6, 1);
}

void
vnc_zebra_del_group (struct bgp *bgp, struct rfapi_nve_group_cfg *rfg)
{
  zlog_debug ("%s: entry", __func__);
  vnc_zebra_add_del_group_afi (bgp, rfg, AFI_IP, 0);
  vnc_zebra_add_del_group_afi (bgp, rfg, AFI_IP6, 0);
}

void
vnc_zebra_reexport_group_afi (
    struct bgp			*bgp,
    struct rfapi_nve_group_cfg	*rfg,
    afi_t			afi)
{
  struct listnode *node;
  struct rfapi_rfg_name *rfgn;

  for (ALL_LIST_ELEMENTS_RO (bgp->rfapi_cfg->rfg_export_zebra_l, node, rfgn))
    {

      if (rfgn->rfg == rfg)
        {
          vnc_zebra_add_del_group_afi (bgp, rfg, afi, 0);
          vnc_zebra_add_del_group_afi (bgp, rfg, afi, 1);
          break;
        }
    }
}


/***********************************************************************
 *			CONTROL INTERFACE
 ***********************************************************************/


/* Other routes redistribution into BGP. */
int
vnc_redistribute_set (struct bgp *bgp, afi_t afi, int type)
{
  if (!bgp->rfapi_cfg)
    {
      return CMD_WARNING;
    }

  /* Set flag to BGP instance. */
  bgp->rfapi_cfg->redist[afi][type] = 1;

//  bgp->redist[afi][type] = 1;

  /* Return if already redistribute flag is set. */
  if (zclient_vnc->redist[afi][type])
    return CMD_WARNING;

  vrf_bitmap_set (zclient_vnc->redist[afi][type], VRF_DEFAULT);

  //zclient_vnc->redist[afi][type] = 1; 

  /* Return if zebra connection is not established. */
  if (zclient_vnc->sock < 0)
    return CMD_WARNING;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug ("Zebra send: redistribute add %s", zebra_route_string (type));

  /* Send distribute add message to zebra. */
  zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient_vnc, afi, type, 0, VRF_DEFAULT);

  return CMD_SUCCESS;
}

/* Unset redistribution.  */
int
vnc_redistribute_unset (struct bgp *bgp, afi_t afi, int type)
{
  zlog_debug ("%s: type=%d entry", __func__, type);

  if (!bgp->rfapi_cfg)
    {
      zlog_debug ("%s: return (no rfapi_cfg)", __func__);
      return CMD_WARNING;
    }

  /* Unset flag from BGP instance. */
  bgp->rfapi_cfg->redist[afi][type] = 0;

  /* Return if zebra connection is disabled. */
  if (!zclient_vnc->redist[afi][type])
    return CMD_WARNING;
  zclient_vnc->redist[afi][type] = 0;

  if (bgp->rfapi_cfg->redist[AFI_IP][type] == 0
      && bgp->rfapi_cfg->redist[AFI_IP6][type] == 0 && zclient_vnc->sock >= 0)
    {
      /* Send distribute delete message to zebra. */
      if (BGP_DEBUG (zebra, ZEBRA))
        zlog_debug ("Zebra send: redistribute delete %s",
                    zebra_route_string (type));
      zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient_vnc, afi, type,
                               0, VRF_DEFAULT);
    }

  /* Withdraw redistributed routes from current BGP's routing table. */
  vnc_redistribute_withdraw (bgp, afi, type);

  zlog_debug ("%s: return", __func__);

  return CMD_SUCCESS;
}


/*
 * Modeled after bgp_zebra.c'bgp_zebra_init()
 * Charriere asks, "Is it possible to carry two?"
 */
void
vnc_zebra_init (struct thread_master *master)
{
  /* Set default values. */
  zclient_vnc = zclient_new (master);
  zclient_init (zclient_vnc, ZEBRA_ROUTE_VNC, 0);

  zclient_vnc->redistribute_route_ipv4_add = vnc_zebra_read_ipv4;
  zclient_vnc->redistribute_route_ipv4_del = vnc_zebra_read_ipv4;
  zclient_vnc->redistribute_route_ipv6_add = vnc_zebra_read_ipv6;
  zclient_vnc->redistribute_route_ipv6_del = vnc_zebra_read_ipv6;
}

void
vnc_zebra_destroy (void)
{
  if (zclient_vnc == NULL)
    return;
  zclient_stop (zclient_vnc);
  zclient_free (zclient_vnc);
  zclient_vnc = NULL;
}
