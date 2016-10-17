/* Kernel routing table updates using netlink over GNU/Linux system.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>
#include <net/if_arp.h>

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "zebra_memory.h"
#include "rib.h"
#include "thread.h"
#include "privs.h"
#include "nexthop.h"
#include "vrf.h"
#include "mpls.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"

/* TODO - Temporary definitions, need to refine. */
#ifndef AF_MPLS
#define AF_MPLS 28
#endif

#ifndef RTA_VIA
#define RTA_VIA		18
#endif

#ifndef RTA_NEWDST
#define RTA_NEWDST	19
#endif

#ifndef RTA_ENCAP_TYPE
#define RTA_ENCAP_TYPE	21
#endif

#ifndef RTA_ENCAP
#define RTA_ENCAP	22
#endif

#ifndef LWTUNNEL_ENCAP_MPLS
#define LWTUNNEL_ENCAP_MPLS  1
#endif

#ifndef MPLS_IPTUNNEL_DST
#define MPLS_IPTUNNEL_DST  1
#endif
/* End of temporary definitions */

struct gw_family_t
{
  u_int16_t     filler;
  u_int16_t     family;
  union g_addr  gate;
};

/*
Pending: create an efficient table_id (in a tree/hash) based lookup)
 */
static vrf_id_t
vrf_lookup_by_table (u_int32_t table_id)
{
  struct zebra_vrf *zvrf;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((zvrf = vrf_iter2info (iter)) == NULL ||
          (zvrf->table_id != table_id))
        continue;

      return zvrf->vrf_id;
    }

  return VRF_DEFAULT;
}

/* Looking up routing table by netlink interface. */
static int
netlink_routing_table (struct sockaddr_nl *snl, struct nlmsghdr *h,
                       ns_id_t ns_id)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb[RTA_MAX + 1];
  u_char flags = 0;
  struct prefix p;
  vrf_id_t vrf_id = VRF_DEFAULT;

  char anyaddr[16] = { 0 };

  int index;
  int table;
  int metric;
  u_int32_t mtu = 0;

  void *dest;
  void *gate;
  void *src;

  rtm = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWROUTE)
    return 0;
  if (rtm->rtm_type != RTN_UNICAST)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct rtmsg));
  if (len < 0)
    return -1;

  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);

  if (rtm->rtm_flags & RTM_F_CLONED)
    return 0;
  if (rtm->rtm_protocol == RTPROT_REDIRECT)
    return 0;
  if (rtm->rtm_protocol == RTPROT_KERNEL)
    return 0;

  if (rtm->rtm_src_len != 0)
    return 0;

  /* We don't care about change notifications for the MPLS table. */
  /* TODO: Revisit this. */
  if (rtm->rtm_family == AF_MPLS)
    return 0;

  /* Table corresponding to route. */
  if (tb[RTA_TABLE])
    table = *(int *) RTA_DATA (tb[RTA_TABLE]);
  else
    table = rtm->rtm_table;

  /* Map to VRF */
  vrf_id = vrf_lookup_by_table(table);
  if (vrf_id == VRF_DEFAULT)
    {
      if (!is_zebra_valid_kernel_table(table) &&
          !is_zebra_main_routing_table(table))
        return 0;
    }

  /* Route which inserted by Zebra. */
  if (rtm->rtm_protocol == RTPROT_ZEBRA)
    flags |= ZEBRA_FLAG_SELFROUTE;

  index = 0;
  metric = 0;
  dest = NULL;
  gate = NULL;
  src = NULL;

  if (tb[RTA_OIF])
    index = *(int *) RTA_DATA (tb[RTA_OIF]);

  if (tb[RTA_DST])
    dest = RTA_DATA (tb[RTA_DST]);
  else
    dest = anyaddr;

  if (tb[RTA_PREFSRC])
    src = RTA_DATA (tb[RTA_PREFSRC]);

  if (tb[RTA_GATEWAY])
    gate = RTA_DATA (tb[RTA_GATEWAY]);

  if (tb[RTA_PRIORITY])
    metric = *(int *) RTA_DATA(tb[RTA_PRIORITY]);

  if (tb[RTA_METRICS])
    {
      struct rtattr *mxrta[RTAX_MAX+1];

      memset (mxrta, 0, sizeof mxrta);
      netlink_parse_rtattr (mxrta, RTAX_MAX, RTA_DATA(tb[RTA_METRICS]),
                            RTA_PAYLOAD(tb[RTA_METRICS]));

      if (mxrta[RTAX_MTU])
        mtu = *(u_int32_t *) RTA_DATA(mxrta[RTAX_MTU]);
    }

  if (rtm->rtm_family == AF_INET)
    {
      p.family = AF_INET;
      memcpy (&p.u.prefix4, dest, 4);
      p.prefixlen = rtm->rtm_dst_len;

      if (!tb[RTA_MULTIPATH])
	rib_add (AFI_IP, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL,
		 0, flags, &p, gate, src, index,
		 table, metric, mtu, 0);
      else
        {
          /* This is a multipath route */

          struct rib *rib;
          struct rtnexthop *rtnh =
            (struct rtnexthop *) RTA_DATA (tb[RTA_MULTIPATH]);

          len = RTA_PAYLOAD (tb[RTA_MULTIPATH]);

          rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
          rib->type = ZEBRA_ROUTE_KERNEL;
          rib->distance = 0;
          rib->flags = flags;
          rib->metric = metric;
          rib->mtu = mtu;
          rib->vrf_id = vrf_id;
          rib->table = table;
          rib->nexthop_num = 0;
          rib->uptime = time (NULL);

          for (;;)
            {
              if (len < (int) sizeof (*rtnh) || rtnh->rtnh_len > len)
                break;

              index = rtnh->rtnh_ifindex;
              gate = 0;
              if (rtnh->rtnh_len > sizeof (*rtnh))
                {
                  memset (tb, 0, sizeof (tb));
                  netlink_parse_rtattr (tb, RTA_MAX, RTNH_DATA (rtnh),
                                        rtnh->rtnh_len - sizeof (*rtnh));
                  if (tb[RTA_GATEWAY])
                    gate = RTA_DATA (tb[RTA_GATEWAY]);
                }

              if (gate)
                {
                  if (index)
                    rib_nexthop_ipv4_ifindex_add (rib, gate, src, index);
                  else
                    rib_nexthop_ipv4_add (rib, gate, src);
                }
              else
                rib_nexthop_ifindex_add (rib, index);

              len -= NLMSG_ALIGN(rtnh->rtnh_len);
              rtnh = RTNH_NEXT(rtnh);
            }

	  zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
				 rib->nexthop_num);
          if (rib->nexthop_num == 0)
            XFREE (MTYPE_RIB, rib);
          else
            rib_add_multipath (AFI_IP, SAFI_UNICAST, &p, rib);
        }
    }
  if (rtm->rtm_family == AF_INET6)
    {
      p.family = AF_INET6;
      memcpy (&p.u.prefix6, dest, 16);
      p.prefixlen = rtm->rtm_dst_len;

      rib_add (AFI_IP6, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL,
	       0, flags, &p, gate, src, index,
	       table, metric, mtu, 0);
    }

  return 0;
}

/* Routing information change from the kernel. */
int
netlink_route_change (struct sockaddr_nl *snl, struct nlmsghdr *h,
                      ns_id_t ns_id)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb[RTA_MAX + 1];
  u_char zebra_flags = 0;
  struct prefix p;
  vrf_id_t vrf_id = VRF_DEFAULT;
  
  char anyaddr[16] = { 0 };

  int index;
  int table;
  int metric;
  u_int32_t mtu = 0;

  void *dest;
  void *gate;
  void *src;

  rtm = NLMSG_DATA (h);

  if (!(h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE))
    {
      /* If this is not route add/delete message print warning. */
      zlog_warn ("Kernel message: %d", h->nlmsg_type);
      return 0;
    }

  /* Connected route. */
  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_debug ("%s %s %s proto %s",
               h->nlmsg_type ==
               RTM_NEWROUTE ? "RTM_NEWROUTE" : "RTM_DELROUTE",
               rtm->rtm_family == AF_INET ? "ipv4" : "ipv6",
               rtm->rtm_type == RTN_UNICAST ? "unicast" : "multicast",
               nl_rtproto_to_str (rtm->rtm_protocol));

  if (rtm->rtm_type != RTN_UNICAST)
    {
      return 0;
    }

  /* We don't care about change notifications for the MPLS table. */
  /* TODO: Revisit this. */
  if (rtm->rtm_family == AF_MPLS)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct rtmsg));
  if (len < 0)
    return -1;

  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);

  if (rtm->rtm_flags & RTM_F_CLONED)
    return 0;
  if (rtm->rtm_protocol == RTPROT_REDIRECT)
    return 0;
  if (rtm->rtm_protocol == RTPROT_KERNEL)
    return 0;

  if (rtm->rtm_protocol == RTPROT_ZEBRA && h->nlmsg_type == RTM_NEWROUTE)
    return 0;
  if (rtm->rtm_protocol == RTPROT_ZEBRA)
    SET_FLAG(zebra_flags, ZEBRA_FLAG_SELFROUTE);

  if (rtm->rtm_src_len != 0)
    {
      zlog_warn ("netlink_route_change(): no src len");
      return 0;
    }

  /* Table corresponding to route. */
  if (tb[RTA_TABLE])
    table = *(int *) RTA_DATA (tb[RTA_TABLE]);
  else
    table = rtm->rtm_table;

  /* Map to VRF */
  vrf_id = vrf_lookup_by_table(table);
  if (vrf_id == VRF_DEFAULT)
    {
      if (!is_zebra_valid_kernel_table(table) &&
          !is_zebra_main_routing_table(table))
        return 0;
    }

  index = 0;
  metric = 0;
  dest = NULL;
  gate = NULL;
  src = NULL;

  if (tb[RTA_OIF])
    index = *(int *) RTA_DATA (tb[RTA_OIF]);

  if (tb[RTA_DST])
    dest = RTA_DATA (tb[RTA_DST]);
  else
    dest = anyaddr;

  if (tb[RTA_GATEWAY])
    gate = RTA_DATA (tb[RTA_GATEWAY]);

  if (tb[RTA_PREFSRC])
    src = RTA_DATA (tb[RTA_PREFSRC]);

  if (h->nlmsg_type == RTM_NEWROUTE)
    {
      if (tb[RTA_PRIORITY])
        metric = *(int *) RTA_DATA(tb[RTA_PRIORITY]);

      if (tb[RTA_METRICS])
        {
          struct rtattr *mxrta[RTAX_MAX+1];

          memset (mxrta, 0, sizeof mxrta);
          netlink_parse_rtattr (mxrta, RTAX_MAX, RTA_DATA(tb[RTA_METRICS]),
                                RTA_PAYLOAD(tb[RTA_METRICS]));

          if (mxrta[RTAX_MTU])
            mtu = *(u_int32_t *) RTA_DATA(mxrta[RTAX_MTU]);
        }
    }

  if (rtm->rtm_family == AF_INET)
    {
      p.family = AF_INET;
      memcpy (&p.u.prefix4, dest, 4);
      p.prefixlen = rtm->rtm_dst_len;

      if (IS_ZEBRA_DEBUG_KERNEL)
        {
          char buf[PREFIX_STRLEN];
          zlog_debug ("%s %s vrf %u",
                      h->nlmsg_type == RTM_NEWROUTE ? "RTM_NEWROUTE" : "RTM_DELROUTE",
                      prefix2str (&p, buf, sizeof(buf)), vrf_id);
        }

      if (h->nlmsg_type == RTM_NEWROUTE)
        {
          if (!tb[RTA_MULTIPATH])
            rib_add (AFI_IP, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL,
		     0, 0, &p, gate, src, index,
		     table, metric, mtu, 0);
          else
            {
              /* This is a multipath route */

              struct rib *rib;
              struct rtnexthop *rtnh =
                (struct rtnexthop *) RTA_DATA (tb[RTA_MULTIPATH]);

              len = RTA_PAYLOAD (tb[RTA_MULTIPATH]);

              rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
              rib->type = ZEBRA_ROUTE_KERNEL;
              rib->distance = 0;
              rib->flags = 0;
              rib->metric = metric;
              rib->mtu = mtu;
              rib->vrf_id = vrf_id;
              rib->table = table;
              rib->nexthop_num = 0;
              rib->uptime = time (NULL);

              for (;;)
                {
                  if (len < (int) sizeof (*rtnh) || rtnh->rtnh_len > len)
                    break;

                  index = rtnh->rtnh_ifindex;
                  gate = 0;
                  if (rtnh->rtnh_len > sizeof (*rtnh))
                    {
                      memset (tb, 0, sizeof (tb));
                      netlink_parse_rtattr (tb, RTA_MAX, RTNH_DATA (rtnh),
                                            rtnh->rtnh_len - sizeof (*rtnh));
                      if (tb[RTA_GATEWAY])
                        gate = RTA_DATA (tb[RTA_GATEWAY]);
                    }

                  if (gate)
                    {
                      if (index)
                        rib_nexthop_ipv4_ifindex_add (rib, gate, src, index);
                      else
                        rib_nexthop_ipv4_add (rib, gate, src);
                    }
                  else
                    rib_nexthop_ifindex_add (rib, index);

                  len -= NLMSG_ALIGN(rtnh->rtnh_len);
                  rtnh = RTNH_NEXT(rtnh);
                }

	      zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
				     rib->nexthop_num);

              if (rib->nexthop_num == 0)
                XFREE (MTYPE_RIB, rib);
              else
                rib_add_multipath (AFI_IP, SAFI_UNICAST, &p, rib);
            }
        }
      else
        rib_delete (AFI_IP, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL, 0, zebra_flags,
		    &p, gate, index, table);
    }

  if (rtm->rtm_family == AF_INET6)
    {
      struct prefix p;

      p.family = AF_INET6;
      memcpy (&p.u.prefix6, dest, 16);
      p.prefixlen = rtm->rtm_dst_len;

      if (IS_ZEBRA_DEBUG_KERNEL)
        {
	  char buf[PREFIX_STRLEN];
          zlog_debug ("%s %s vrf %u",
                      h->nlmsg_type == RTM_NEWROUTE ? "RTM_NEWROUTE" : "RTM_DELROUTE",
                      prefix2str (&p, buf, sizeof(buf)), vrf_id);
        }

      if (h->nlmsg_type == RTM_NEWROUTE)
        rib_add (AFI_IP6, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL,
		 0, 0, &p, gate, src, index,
		 table, metric, mtu, 0);
      else
        rib_delete (AFI_IP6, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL,
		    0, zebra_flags, &p, gate, index, table);
    }

  return 0;
}

/* Routing table read function using netlink interface.  Only called
   bootstrap time. */
int
netlink_route_read (struct zebra_ns *zns)
{
  int ret;

  /* Get IPv4 routing table. */
  ret = netlink_request (AF_INET, RTM_GETROUTE, &zns->netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_routing_table, &zns->netlink_cmd, zns, 0);
  if (ret < 0)
    return ret;

#ifdef HAVE_IPV6
  /* Get IPv6 routing table. */
  ret = netlink_request (AF_INET6, RTM_GETROUTE, &zns->netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_routing_table, &zns->netlink_cmd, zns, 0);
  if (ret < 0)
    return ret;
#endif /* HAVE_IPV6 */

  return 0;
}

static void
_netlink_route_nl_add_gateway_info (u_char route_family, u_char gw_family,
                                    struct nlmsghdr *nlmsg,
                                    size_t req_size, int bytelen,
                                    struct nexthop *nexthop)
{
  if (route_family == AF_MPLS)
    {
      struct gw_family_t gw_fam;

      gw_fam.family = gw_family;
      if (gw_family == AF_INET)
        memcpy (&gw_fam.gate.ipv4, &nexthop->gate.ipv4, bytelen);
      else
        memcpy (&gw_fam.gate.ipv6, &nexthop->gate.ipv6, bytelen);
      addattr_l (nlmsg, req_size, RTA_VIA, &gw_fam.family, bytelen+2);
    }
  else
    {
      if (gw_family == AF_INET)
        addattr_l (nlmsg, req_size, RTA_GATEWAY, &nexthop->gate.ipv4, bytelen);
      else
        addattr_l (nlmsg, req_size, RTA_GATEWAY, &nexthop->gate.ipv6, bytelen);
    }
}

static void
_netlink_route_rta_add_gateway_info (u_char route_family, u_char gw_family,
                                     struct rtattr *rta, struct rtnexthop *rtnh,
                                     size_t req_size, int bytelen,
                                     struct nexthop *nexthop)
{
  if (route_family == AF_MPLS)
    {
      struct gw_family_t gw_fam;

      gw_fam.family = gw_family;
      if (gw_family == AF_INET)
        memcpy (&gw_fam.gate.ipv4, &nexthop->gate.ipv4, bytelen);
      else
        memcpy (&gw_fam.gate.ipv6, &nexthop->gate.ipv6, bytelen);
      rta_addattr_l (rta, req_size, RTA_VIA, &gw_fam.family, bytelen+2);
      rtnh->rtnh_len += RTA_LENGTH (bytelen + 2);
    }
  else
    {
      if (gw_family == AF_INET)
        rta_addattr_l (rta, req_size, RTA_GATEWAY, &nexthop->gate.ipv4, bytelen);
      else
        rta_addattr_l (rta, req_size, RTA_GATEWAY, &nexthop->gate.ipv6, bytelen);
      rtnh->rtnh_len += sizeof (struct rtattr) + bytelen;
    }
}

/* This function takes a nexthop as argument and adds
 * the appropriate netlink attributes to an existing
 * netlink message.
 *
 * @param routedesc: Human readable description of route type
 *                   (direct/recursive, single-/multipath)
 * @param bytelen: Length of addresses in bytes.
 * @param nexthop: Nexthop information
 * @param nlmsg: nlmsghdr structure to fill in.
 * @param req_size: The size allocated for the message.
 */
static void
_netlink_route_build_singlepath(
        const char *routedesc,
        int bytelen,
        struct nexthop *nexthop,
        struct nlmsghdr *nlmsg,
        struct rtmsg *rtmsg,
        size_t req_size,
	int cmd)
{
  struct nexthop_label *nh_label;
  mpls_lse_t out_lse[MPLS_MAX_LABELS];
  char label_buf[100];

  if (rtmsg->rtm_family == AF_INET &&
      (nexthop->type == NEXTHOP_TYPE_IPV6
      || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX))
    {
      char buf[16] = "169.254.0.1";
      struct in_addr ipv4_ll;

      inet_pton (AF_INET, buf, &ipv4_ll);
      rtmsg->rtm_flags |= RTNH_F_ONLINK;
      addattr_l (nlmsg, req_size, RTA_GATEWAY, &ipv4_ll, 4);
      addattr32 (nlmsg, req_size, RTA_OIF, nexthop->ifindex);

      if (nexthop->rmap_src.ipv4.s_addr && (cmd == RTM_NEWROUTE))
        addattr_l (nlmsg, req_size, RTA_PREFSRC,
                   &nexthop->rmap_src.ipv4, bytelen);
      else if (nexthop->src.ipv4.s_addr && (cmd == RTM_NEWROUTE))
        addattr_l (nlmsg, req_size, RTA_PREFSRC,
                   &nexthop->src.ipv4, bytelen);

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug(" 5549: _netlink_route_build_singlepath() (%s): "
                   "nexthop via %s if %u",
                   routedesc, buf, nexthop->ifindex);
      return;
    }

  label_buf[0] = '\0';
  /* outgoing label - either as NEWDST (in the case of LSR) or as ENCAP
   * (in the case of LER)
   */
  nh_label = nexthop->nh_label;
  if (rtmsg->rtm_family == AF_MPLS)
    {
      assert (nh_label);
      assert (nh_label->num_labels == 1);
    }

  if (nh_label && nh_label->num_labels)
    {
      int i, num_labels = 0;
      u_int32_t bos;
      char label_buf1[20];
 
      for (i = 0; i < nh_label->num_labels; i++)
        {
          if (nh_label->label[i] != MPLS_IMP_NULL_LABEL)
            {
              bos = ((i == (nh_label->num_labels - 1)) ? 1 : 0);
              out_lse[i] = mpls_lse_encode (nh_label->label[i], 0, 0, bos);
              if (!num_labels)
                sprintf (label_buf, "label %d", nh_label->label[i]);
              else
                {
                  sprintf (label_buf1, "/%d", nh_label->label[i]);
                  strcat (label_buf, label_buf1);
                }
              num_labels++;
            }
        }
      if (num_labels)
        {
          if (rtmsg->rtm_family == AF_MPLS)
            addattr_l (nlmsg, req_size, RTA_NEWDST,
                       &out_lse, num_labels * sizeof(mpls_lse_t));
          else
            {
              struct rtattr *nest;
              u_int16_t encap = LWTUNNEL_ENCAP_MPLS;

              addattr_l(nlmsg, req_size, RTA_ENCAP_TYPE,
                        &encap, sizeof (u_int16_t));
              nest = addattr_nest(nlmsg, req_size, RTA_ENCAP);
              addattr_l (nlmsg, req_size, MPLS_IPTUNNEL_DST,
                         &out_lse, num_labels * sizeof(mpls_lse_t));
              addattr_nest_end(nlmsg, nest);
            }
        }
    }

  if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ONLINK))
    rtmsg->rtm_flags |= RTNH_F_ONLINK;

  if (nexthop->type == NEXTHOP_TYPE_IPV4
      || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
    {
      _netlink_route_nl_add_gateway_info (rtmsg->rtm_family, AF_INET, nlmsg,
                                          req_size, bytelen, nexthop);

      if (cmd == RTM_NEWROUTE)
	{
	  if (nexthop->rmap_src.ipv4.s_addr)
	    addattr_l (nlmsg, req_size, RTA_PREFSRC,
		       &nexthop->rmap_src.ipv4, bytelen);
	  else if (nexthop->src.ipv4.s_addr)
	    addattr_l (nlmsg, req_size, RTA_PREFSRC,
		       &nexthop->src.ipv4, bytelen);
	}

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug("netlink_route_multipath() (%s): "
                   "nexthop via %s %s if %u",
                   routedesc,
                   inet_ntoa (nexthop->gate.ipv4),
                   label_buf, nexthop->ifindex);
    }
  if (nexthop->type == NEXTHOP_TYPE_IPV6
      || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
    {
      _netlink_route_nl_add_gateway_info (rtmsg->rtm_family, AF_INET6, nlmsg,
                                          req_size, bytelen, nexthop);

      if (cmd == RTM_NEWROUTE)
	{
	  if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6))
	    addattr_l (nlmsg, req_size, RTA_PREFSRC,
		       &nexthop->rmap_src.ipv6, bytelen);
	  else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6))
	    addattr_l (nlmsg, req_size, RTA_PREFSRC,
		       &nexthop->src.ipv6, bytelen);
	}

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug("netlink_route_multipath() (%s): "
                   "nexthop via %s %s if %u",
                   routedesc,
                   inet6_ntoa (nexthop->gate.ipv6),
                   label_buf, nexthop->ifindex);
    }
  if (nexthop->type == NEXTHOP_TYPE_IFINDEX
      || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
    {
      addattr32 (nlmsg, req_size, RTA_OIF, nexthop->ifindex);

      if (cmd == RTM_NEWROUTE)
	{
	  if (nexthop->rmap_src.ipv4.s_addr)
	    addattr_l (nlmsg, req_size, RTA_PREFSRC,
		       &nexthop->rmap_src.ipv4, bytelen);
	  else if (nexthop->src.ipv4.s_addr)
	    addattr_l (nlmsg, req_size, RTA_PREFSRC,
		       &nexthop->src.ipv4, bytelen);
	}

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug("netlink_route_multipath() (%s): "
                   "nexthop via if %u", routedesc, nexthop->ifindex);
    }

  if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
    {
      addattr32 (nlmsg, req_size, RTA_OIF, nexthop->ifindex);

      if (cmd == RTM_NEWROUTE)
	{
	  if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6))
	    addattr_l (nlmsg, req_size, RTA_PREFSRC,
		       &nexthop->rmap_src.ipv6, bytelen);
	  else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6))
	    addattr_l (nlmsg, req_size, RTA_PREFSRC,
		       &nexthop->src.ipv6, bytelen);
	}

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug("netlink_route_multipath() (%s): "
                   "nexthop via if %u", routedesc, nexthop->ifindex);
    }
}

/* This function takes a nexthop as argument and
 * appends to the given rtattr/rtnexthop pair the
 * representation of the nexthop. If the nexthop
 * defines a preferred source, the src parameter
 * will be modified to point to that src, otherwise
 * it will be kept unmodified.
 *
 * @param routedesc: Human readable description of route type
 *                   (direct/recursive, single-/multipath)
 * @param bytelen: Length of addresses in bytes.
 * @param nexthop: Nexthop information
 * @param rta: rtnetlink attribute structure
 * @param rtnh: pointer to an rtnetlink nexthop structure
 * @param src: pointer pointing to a location where
 *             the prefsrc should be stored.
 */
static void
_netlink_route_build_multipath(
        const char *routedesc,
        int bytelen,
        struct nexthop *nexthop,
        struct rtattr *rta,
        struct rtnexthop *rtnh,
        struct rtmsg *rtmsg,
        union g_addr **src)
{
  struct nexthop_label *nh_label;
  mpls_lse_t out_lse[MPLS_MAX_LABELS];
  char label_buf[100];

  rtnh->rtnh_len = sizeof (*rtnh);
  rtnh->rtnh_flags = 0;
  rtnh->rtnh_hops = 0;
  rta->rta_len += rtnh->rtnh_len;

  if (rtmsg->rtm_family == AF_INET &&
      (nexthop->type == NEXTHOP_TYPE_IPV6
      || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX))
    {
      char buf[16] = "169.254.0.1";
      struct in_addr ipv4_ll;

      inet_pton (AF_INET, buf, &ipv4_ll);
      bytelen = 4;
      rtnh->rtnh_flags |= RTNH_F_ONLINK;
      rta_addattr_l (rta, NL_PKT_BUF_SIZE, RTA_GATEWAY,
                     &ipv4_ll, bytelen);
      rtnh->rtnh_len += sizeof (struct rtattr) + bytelen;
      rtnh->rtnh_ifindex = nexthop->ifindex;

      if (nexthop->rmap_src.ipv4.s_addr)
        *src = &nexthop->rmap_src;
      else if (nexthop->src.ipv4.s_addr)
         *src = &nexthop->src;

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug(" 5549: netlink_route_build_multipath() (%s): "
                   "nexthop via %s if %u",
                   routedesc, buf, nexthop->ifindex);
      return;
    }

  label_buf[0] = '\0';
  /* outgoing label - either as NEWDST (in the case of LSR) or as ENCAP
   * (in the case of LER)
   */
  nh_label = nexthop->nh_label;
  if (rtmsg->rtm_family == AF_MPLS)
    {
      assert (nh_label);
      assert (nh_label->num_labels == 1);
    }

  if (nh_label && nh_label->num_labels)
    {
      int i, num_labels = 0;
      u_int32_t bos;
      char label_buf1[20];

      for (i = 0; i < nh_label->num_labels; i++)
        {
          if (nh_label->label[i] != MPLS_IMP_NULL_LABEL)
            {
              bos = ((i == (nh_label->num_labels - 1)) ? 1 : 0);
              out_lse[i] = mpls_lse_encode (nh_label->label[i], 0, 0, bos);
              if (!num_labels)
                sprintf (label_buf, "label %d", nh_label->label[i]);
              else
                {
                  sprintf (label_buf1, "/%d", nh_label->label[i]);
                  strcat (label_buf, label_buf1);
                }
              num_labels++;
            }
        }
      if (num_labels)
        {
          if (rtmsg->rtm_family == AF_MPLS)
            {
              rta_addattr_l (rta, NL_PKT_BUF_SIZE, RTA_NEWDST,
                             &out_lse, num_labels * sizeof(mpls_lse_t));
              rtnh->rtnh_len += RTA_LENGTH (num_labels * sizeof(mpls_lse_t));
            }
          else
            {
              struct rtattr *nest;
              u_int16_t encap = LWTUNNEL_ENCAP_MPLS;
              int len = rta->rta_len;

              rta_addattr_l(rta, NL_PKT_BUF_SIZE, RTA_ENCAP_TYPE,
                            &encap, sizeof (u_int16_t));
              nest = rta_nest(rta, NL_PKT_BUF_SIZE, RTA_ENCAP);
              rta_addattr_l (rta, NL_PKT_BUF_SIZE, MPLS_IPTUNNEL_DST,
                             &out_lse, num_labels * sizeof(mpls_lse_t));
              rta_nest_end(rta, nest);
              rtnh->rtnh_len += rta->rta_len - len;
            }
        }
    }

  if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ONLINK))
    rtnh->rtnh_flags |= RTNH_F_ONLINK;

  if (nexthop->type == NEXTHOP_TYPE_IPV4
      || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
    {
      _netlink_route_rta_add_gateway_info (rtmsg->rtm_family, AF_INET, rta,
                                     rtnh, NL_PKT_BUF_SIZE, bytelen, nexthop);
      if (nexthop->rmap_src.ipv4.s_addr)
        *src = &nexthop->rmap_src;
      else if (nexthop->src.ipv4.s_addr)
         *src = &nexthop->src;

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug("netlink_route_multipath() (%s): "
                   "nexthop via %s %s if %u",
                   routedesc,
                   inet_ntoa (nexthop->gate.ipv4),
                   label_buf, nexthop->ifindex);
    }
  if (nexthop->type == NEXTHOP_TYPE_IPV6
      || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
    {
      _netlink_route_rta_add_gateway_info (rtmsg->rtm_family, AF_INET6, rta,
                                       rtnh, NL_PKT_BUF_SIZE, bytelen, nexthop);

      if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6))
        *src = &nexthop->rmap_src;
      else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6))
	*src = &nexthop->src;

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug("netlink_route_multipath() (%s): "
                   "nexthop via %s %s if %u",
                   routedesc,
                   inet6_ntoa (nexthop->gate.ipv6),
                   label_buf, nexthop->ifindex);
    }
  /* ifindex */
  if (nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX
      || nexthop->type == NEXTHOP_TYPE_IFINDEX)
    {
      rtnh->rtnh_ifindex = nexthop->ifindex;

      if (nexthop->rmap_src.ipv4.s_addr)
        *src = &nexthop->rmap_src;
      else if (nexthop->src.ipv4.s_addr)
        *src = &nexthop->src;

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug("netlink_route_multipath() (%s): "
                   "nexthop via if %u", routedesc, nexthop->ifindex);
    }
  else if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
    {
      rtnh->rtnh_ifindex = nexthop->ifindex;

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug("netlink_route_multipath() (%s): "
                   "nexthop via if %u", routedesc, nexthop->ifindex);
    }
  else
    {
      rtnh->rtnh_ifindex = 0;
    }
}

static inline void
_netlink_mpls_build_singlepath(
        const char *routedesc,
        zebra_nhlfe_t *nhlfe,
        struct nlmsghdr *nlmsg,
        struct rtmsg *rtmsg,
        size_t req_size,
	int cmd)
{
  int bytelen;
  u_char family;

  family = NHLFE_FAMILY (nhlfe);
  bytelen = (family == AF_INET ? 4 : 16);
  _netlink_route_build_singlepath(routedesc, bytelen, nhlfe->nexthop,
                                  nlmsg, rtmsg, req_size, cmd);
}


static inline void
_netlink_mpls_build_multipath(
        const char *routedesc,
        zebra_nhlfe_t *nhlfe,
        struct rtattr *rta,
        struct rtnexthop *rtnh,
        struct rtmsg *rtmsg,
        union g_addr **src)
{
  int bytelen;
  u_char family;

  family = NHLFE_FAMILY (nhlfe);
  bytelen = (family == AF_INET ? 4 : 16);
  _netlink_route_build_multipath(routedesc, bytelen, nhlfe->nexthop,
                                 rta, rtnh, rtmsg, src);
}


/* Log debug information for netlink_route_multipath
 * if debug logging is enabled.
 *
 * @param cmd: Netlink command which is to be processed
 * @param p: Prefix for which the change is due
 * @param nexthop: Nexthop which is currently processed
 * @param routedesc: Semantic annotation for nexthop
 *                     (recursive, multipath, etc.)
 * @param family: Address family which the change concerns
 */
static void
_netlink_route_debug(
        int cmd,
        struct prefix *p,
        struct nexthop *nexthop,
        const char *routedesc,
        int family,
        struct zebra_vrf *zvrf)
{
  if (IS_ZEBRA_DEBUG_KERNEL)
    {
      char buf[PREFIX_STRLEN];
      zlog_debug ("netlink_route_multipath() (%s): %s %s vrf %u type %s",
		  routedesc,
		  nl_msg_type_to_str (cmd),
		  prefix2str (p, buf, sizeof(buf)), zvrf->vrf_id,
		  (nexthop) ? nexthop_type_to_str (nexthop->type) : "UNK");
    }
}

static void
_netlink_mpls_debug(
        int cmd,
        u_int32_t label,
        const char *routedesc)
{
  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_debug ("netlink_mpls_multipath() (%s): %s %u/20",
                routedesc, nl_msg_type_to_str (cmd), label);
}

static int
netlink_neigh_update (int cmd, int ifindex, uint32_t addr, char *lla, int llalen)
{
  struct {
      struct nlmsghdr         n;
      struct ndmsg            ndm;
      char                    buf[256];
  } req;

  struct zebra_ns *zns = zebra_ns_lookup (NS_DEFAULT);

  memset(&req.n, 0, sizeof(req.n));
  memset(&req.ndm, 0, sizeof(req.ndm));

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
  req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
  req.n.nlmsg_type = cmd; //RTM_NEWNEIGH or RTM_DELNEIGH
  req.ndm.ndm_family = AF_INET;
  req.ndm.ndm_state = NUD_PERMANENT;
  req.ndm.ndm_ifindex = ifindex;
  req.ndm.ndm_type = RTN_UNICAST;

  addattr_l(&req.n, sizeof(req), NDA_DST, &addr, 4);
  addattr_l(&req.n, sizeof(req), NDA_LLADDR, lla, llalen);

  return netlink_talk (&req.n, &zns->netlink_cmd, zns);
}

/* Routing table change via netlink interface. */
/* Update flag indicates whether this is a "replace" or not. */
static int
netlink_route_multipath (int cmd, struct prefix *p, struct rib *rib,
                         int family, int update)
{
  int bytelen;
  struct sockaddr_nl snl;
  struct nexthop *nexthop = NULL, *tnexthop;
  int recursing;
  int nexthop_num;
  int discard;
  const char *routedesc;
  int setsrc = 0;
  union g_addr src;

  struct
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[NL_PKT_BUF_SIZE];
  } req;

  struct zebra_ns *zns = zebra_ns_lookup (NS_DEFAULT);
  struct zebra_vrf *zvrf = vrf_info_lookup (rib->vrf_id);

  memset (&req, 0, sizeof req - NL_PKT_BUF_SIZE);

  bytelen = (family == AF_INET ? 4 : 16);

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
  req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
  if ((cmd == RTM_NEWROUTE) && update)
    req.n.nlmsg_flags |= NLM_F_REPLACE;
  req.n.nlmsg_type = cmd;
  req.r.rtm_family = family;
  req.r.rtm_dst_len = p->prefixlen;
  req.r.rtm_protocol = RTPROT_ZEBRA;
  req.r.rtm_scope = RT_SCOPE_UNIVERSE;

  if ((rib->flags & ZEBRA_FLAG_BLACKHOLE) || (rib->flags & ZEBRA_FLAG_REJECT))
    discard = 1;
  else
    discard = 0;

  if (cmd == RTM_NEWROUTE)
    {
      if (discard)
        {
          if (rib->flags & ZEBRA_FLAG_BLACKHOLE)
            req.r.rtm_type = RTN_BLACKHOLE;
          else if (rib->flags & ZEBRA_FLAG_REJECT)
            req.r.rtm_type = RTN_UNREACHABLE;
          else
            assert (RTN_BLACKHOLE != RTN_UNREACHABLE);  /* false */
        }
      else
        req.r.rtm_type = RTN_UNICAST;
    }

  addattr_l (&req.n, sizeof req, RTA_DST, &p->u.prefix, bytelen);

  /* Metric. */
  /* Hardcode the metric for all routes coming from zebra. Metric isn't used
   * either by the kernel or by zebra. Its purely for calculating best path(s)
   * by the routing protocol and for communicating with protocol peers.
   */
  addattr32 (&req.n, sizeof req, RTA_PRIORITY, NL_DEFAULT_ROUTE_METRIC);

  /* Table corresponding to this route. */
  if (rib->table < 256)
    req.r.rtm_table = rib->table;
  else
    {
      req.r.rtm_table = RT_TABLE_UNSPEC;
      addattr32(&req.n, sizeof req, RTA_TABLE, rib->table);
    }

  if (rib->mtu || rib->nexthop_mtu)
    {
      char buf[NL_PKT_BUF_SIZE];
      struct rtattr *rta = (void *) buf;
      u_int32_t mtu = rib->mtu;
      if (!mtu || (rib->nexthop_mtu && rib->nexthop_mtu < mtu))
        mtu = rib->nexthop_mtu;
      rta->rta_type = RTA_METRICS;
      rta->rta_len = RTA_LENGTH(0);
      rta_addattr_l (rta, NL_PKT_BUF_SIZE, RTAX_MTU, &mtu, sizeof mtu);
      addattr_l (&req.n, NL_PKT_BUF_SIZE, RTA_METRICS, RTA_DATA (rta),
                 RTA_PAYLOAD (rta));
    }

  if (discard)
    {
      if (cmd == RTM_NEWROUTE)
        for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
          {
            /* We shouldn't encounter recursive nexthops on discard routes,
             * but it is probably better to handle that case correctly anyway.
             */
            if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
              continue;
          }
      goto skip;
    }

  /* Count overall nexthops so we can decide whether to use singlepath
   * or multipath case. */
  nexthop_num = 0;
  for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
    {
      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
        continue;
      if (cmd == RTM_NEWROUTE && !CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
        continue;
      if (cmd == RTM_DELROUTE && !CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
        continue;

      nexthop_num++;
    }

  /* Singlepath case. */
  if (nexthop_num == 1 || MULTIPATH_NUM == 1)
    {
      nexthop_num = 0;
      for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
        {
          if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
              if (!setsrc)
                 {
		   if (family == AF_INET)
		     {
		       if (nexthop->rmap_src.ipv4.s_addr != 0)
			 {
			   src.ipv4 = nexthop->rmap_src.ipv4;
			   setsrc = 1;
			 }
		       else if (nexthop->src.ipv4.s_addr != 0)
			 {
			   src.ipv4 = nexthop->src.ipv4;
			   setsrc = 1;
			 }
		     }
		   else if (family == AF_INET6)
		     {
		       if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6))
			 {
			   src.ipv6 = nexthop->rmap_src.ipv6;
			   setsrc = 1;
			 }
		       else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6))
			 {
			   src.ipv6 = nexthop->src.ipv6;
			   setsrc = 1;
			 }
		     }
                 }
              continue;
	    }

          if ((cmd == RTM_NEWROUTE
               && CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
              || (cmd == RTM_DELROUTE
                  && CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)))
            {
              routedesc = recursing ? "recursive, 1 hop" : "single hop";

              _netlink_route_debug(cmd, p, nexthop, routedesc, family, zvrf);
              _netlink_route_build_singlepath(routedesc, bytelen,
                                              nexthop, &req.n, &req.r,
                                              sizeof req, cmd);
              nexthop_num++;
              break;
            }
        }
      if (setsrc && (cmd == RTM_NEWROUTE))
	{
	  if (family == AF_INET)
	    addattr_l (&req.n, sizeof req, RTA_PREFSRC, &src.ipv4, bytelen);
	  else if (family == AF_INET6)
	    addattr_l (&req.n, sizeof req, RTA_PREFSRC, &src.ipv6, bytelen);
	}
    }
  else
    {
      char buf[NL_PKT_BUF_SIZE];
      struct rtattr *rta = (void *) buf;
      struct rtnexthop *rtnh;
      union g_addr *src1 = NULL;

      rta->rta_type = RTA_MULTIPATH;
      rta->rta_len = RTA_LENGTH (0);
      rtnh = RTA_DATA (rta);

      nexthop_num = 0;
      for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
        {
          if (nexthop_num >= MULTIPATH_NUM)
            break;

          if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	    {
              /* This only works for IPv4 now */
              if (!setsrc)
                 {
		   if (family == AF_INET)
		     {
		       if (nexthop->rmap_src.ipv4.s_addr != 0)
			 {
			   src.ipv4 = nexthop->rmap_src.ipv4;
			   setsrc = 1;
			 }
		       else if (nexthop->src.ipv4.s_addr != 0)
			 {
			   src.ipv4 = nexthop->src.ipv4;
			   setsrc = 1;
			 }
		     }
		   else if (family == AF_INET6)
		     {
		       if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6))
			 {
			   src.ipv6 = nexthop->rmap_src.ipv6;
			   setsrc = 1;
			 }
		       else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6))
			 {
			   src.ipv6 = nexthop->src.ipv6;
			   setsrc = 1;
			 }
		     }
                 }
	      continue;
	    }

          if ((cmd == RTM_NEWROUTE
               && CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
              || (cmd == RTM_DELROUTE
                  && CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)))
            {
              routedesc = recursing ? "recursive, multihop" : "multihop";
              nexthop_num++;

              _netlink_route_debug(cmd, p, nexthop,
                                   routedesc, family, zvrf);
              _netlink_route_build_multipath(routedesc, bytelen,
                                             nexthop, rta, rtnh, &req.r, &src1);
              rtnh = RTNH_NEXT (rtnh);

	      if (!setsrc && src1)
		{
		  if (family == AF_INET)
		    src.ipv4 = src1->ipv4;
		  else if (family == AF_INET6)
		    src.ipv6 = src1->ipv6;

		  setsrc = 1;
		}
            }
        }
      if (setsrc && (cmd == RTM_NEWROUTE))
	{
	  if (family == AF_INET)
	    addattr_l (&req.n, sizeof req, RTA_PREFSRC, &src.ipv4, bytelen);
	  else if (family == AF_INET6)
	    addattr_l (&req.n, sizeof req, RTA_PREFSRC, &src.ipv6, bytelen);
          if (IS_ZEBRA_DEBUG_KERNEL)
	    zlog_debug("Setting source");
	}

      if (rta->rta_len > RTA_LENGTH (0))
        addattr_l (&req.n, NL_PKT_BUF_SIZE, RTA_MULTIPATH, RTA_DATA (rta),
                   RTA_PAYLOAD (rta));
    }

  /* If there is no useful nexthop then return. */
  if (nexthop_num == 0)
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("netlink_route_multipath(): No useful nexthop.");
      return 0;
    }

skip:

  /* Destination netlink address. */
  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  /* Talk to netlink socket. */
  return netlink_talk (&req.n, &zns->netlink_cmd, zns);
}

int
kernel_add_ipv4 (struct prefix *p, struct rib *rib)
{
  return netlink_route_multipath (RTM_NEWROUTE, p, rib, AF_INET, 0);
}

int
kernel_update_ipv4 (struct prefix *p, struct rib *rib)
{
  return netlink_route_multipath (RTM_NEWROUTE, p, rib, AF_INET, 1);
}

int
kernel_delete_ipv4 (struct prefix *p, struct rib *rib)
{
  return netlink_route_multipath (RTM_DELROUTE, p, rib, AF_INET, 0);
}

#ifdef HAVE_IPV6
int
kernel_add_ipv6 (struct prefix *p, struct rib *rib)
{
    {
      return netlink_route_multipath (RTM_NEWROUTE, p, rib, AF_INET6, 0);
    }
}

int
kernel_update_ipv6 (struct prefix *p, struct rib *rib)
{
#if defined (HAVE_V6_RR_SEMANTICS)
  return netlink_route_multipath (RTM_NEWROUTE, p, rib, AF_INET6, 1);
#else
  kernel_delete_ipv6 (p, rib);
  return kernel_add_ipv6 (p, rib);
#endif
}

int
kernel_delete_ipv6 (struct prefix *p, struct rib *rib)
{
    {
      return netlink_route_multipath (RTM_DELROUTE, p, rib, AF_INET6, 0);
    }
}
#endif /* HAVE_IPV6 */

int
kernel_neigh_update (int add, int ifindex, uint32_t addr, char *lla, int llalen)
{
  return netlink_neigh_update(add ? RTM_NEWNEIGH : RTM_DELNEIGH, ifindex, addr,
			      lla, llalen);
}

/*
 * MPLS label forwarding table change via netlink interface.
 */
int
netlink_mpls_multipath (int cmd, zebra_lsp_t *lsp)
{
  mpls_lse_t lse;
  zebra_nhlfe_t *nhlfe;
  struct nexthop *nexthop = NULL;
  int nexthop_num;
  const char *routedesc;
  struct zebra_ns *zns = zebra_ns_lookup (NS_DEFAULT);

  struct
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[NL_PKT_BUF_SIZE];
  } req;

  memset (&req, 0, sizeof req - NL_PKT_BUF_SIZE);


  /*
   * Count # nexthops so we can decide whether to use singlepath
   * or multipath case.
   */
  nexthop_num = 0;
  for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
    {
      nexthop = nhlfe->nexthop;
      if (!nexthop)
        continue;
      if (cmd == RTM_NEWROUTE)
        {
          /* Count all selected NHLFEs */
          if (CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_SELECTED) &&
              CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
            nexthop_num++;
        }
      else /* DEL */
        {
          /* Count all installed NHLFEs */
          if (CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED) &&
              CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            nexthop_num++;
        }
    }

  if (nexthop_num == 0) // unexpected
    return 0;

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
  req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
  req.n.nlmsg_type = cmd;
  req.r.rtm_family = AF_MPLS;
  req.r.rtm_table = RT_TABLE_MAIN;
  req.r.rtm_dst_len = MPLS_LABEL_LEN_BITS;
  req.r.rtm_protocol = RTPROT_ZEBRA;
  req.r.rtm_scope = RT_SCOPE_UNIVERSE;
  req.r.rtm_type = RTN_UNICAST;

  if (cmd == RTM_NEWROUTE)
    /* We do a replace to handle update. */
    req.n.nlmsg_flags |= NLM_F_REPLACE;

  /* Fill destination */
  lse = mpls_lse_encode (lsp->ile.in_label, 0, 0, 1);
  addattr_l (&req.n, sizeof req, RTA_DST, &lse, sizeof(mpls_lse_t));

  /* Fill nexthops (paths) based on single-path or multipath. The paths
   * chosen depend on the operation.
   */
  if (nexthop_num == 1 || MULTIPATH_NUM == 1)
    {
      routedesc = "single hop";
      _netlink_mpls_debug(cmd, lsp->ile.in_label, routedesc);

      nexthop_num = 0;
      for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
        {
          nexthop = nhlfe->nexthop;
          if (!nexthop)
            continue;

          if ((cmd == RTM_NEWROUTE &&
               (CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_SELECTED) &&
                CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))) ||
              (cmd == RTM_DELROUTE &&
               (CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED) &&
                CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))))
            {
              /* Add the gateway */
              _netlink_mpls_build_singlepath(routedesc, nhlfe,
                                             &req.n, &req.r, sizeof req, cmd);
              if (cmd == RTM_NEWROUTE)
                {
                  SET_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED);
                  SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
                }
              else
                {
                  UNSET_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED);
                  UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
                }
              nexthop_num++;
              break;
            }
        }
    }
  else /* Multipath case */
    {
      char buf[NL_PKT_BUF_SIZE];
      struct rtattr *rta = (void *) buf;
      struct rtnexthop *rtnh;
      union g_addr *src1 = NULL;

      rta->rta_type = RTA_MULTIPATH;
      rta->rta_len = RTA_LENGTH (0);
      rtnh = RTA_DATA (rta);

      routedesc = "multihop";
      _netlink_mpls_debug(cmd, lsp->ile.in_label, routedesc);

      nexthop_num = 0;
      for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
        {
          nexthop = nhlfe->nexthop;
          if (!nexthop)
            continue;

          if (MULTIPATH_NUM != 0 && nexthop_num >= MULTIPATH_NUM)
            break;

          if ((cmd == RTM_NEWROUTE &&
               (CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_SELECTED) &&
                CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))) ||
              (cmd == RTM_DELROUTE &&
               (CHECK_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED) &&
                CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))))
            {
              nexthop_num++;

              /* Build the multipath */
              _netlink_mpls_build_multipath(routedesc, nhlfe, rta,
                                            rtnh, &req.r, &src1);
              rtnh = RTNH_NEXT (rtnh);

              if (cmd == RTM_NEWROUTE)
                {
                  SET_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED);
                  SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
                }
              else
                {
                  UNSET_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED);
                  UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
                }

            }
        }

      /* Add the multipath */
      if (rta->rta_len > RTA_LENGTH (0))
        addattr_l (&req.n, NL_PKT_BUF_SIZE, RTA_MULTIPATH, RTA_DATA (rta),
                   RTA_PAYLOAD (rta));
    }

  /* Talk to netlink socket. */
  return netlink_talk (&req.n, &zns->netlink_cmd, zns);
}

/*
 * Handle failure in LSP install, clear flags for NHLFE.
 */
void
clear_nhlfe_installed (zebra_lsp_t *lsp)
{
  zebra_nhlfe_t *nhlfe;
  struct nexthop *nexthop;

  for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
    {
      nexthop = nhlfe->nexthop;
      if (!nexthop)
        continue;

      UNSET_FLAG (nhlfe->flags, NHLFE_FLAG_INSTALLED);
      UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
    }
}
