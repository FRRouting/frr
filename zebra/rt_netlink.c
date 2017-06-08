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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "vty.h"
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
#include "zebra/zebra_mroute.h"


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

#ifndef RTA_EXPIRES
#define RTA_EXPIRES     23
#endif

#ifndef LWTUNNEL_ENCAP_MPLS
#define LWTUNNEL_ENCAP_MPLS  1
#endif

#ifndef MPLS_IPTUNNEL_DST
#define MPLS_IPTUNNEL_DST  1
#endif

#ifndef NDA_MASTER
#define NDA_MASTER   9
#endif
/* End of temporary definitions */

struct gw_family_t
{
  u_int16_t     filler;
  u_int16_t     family;
  union g_addr  gate;
};

char ipv4_ll_buf[16] = "169.254.0.1";
struct in_addr ipv4_ll;

/*
 * The ipv4_ll data structure is used for all 5549
 * additions to the kernel.  Let's figure out the
 * correct value one time instead for every
 * install/remove of a 5549 type route
 */
void
rt_netlink_init (void)
{
  inet_pton (AF_INET, ipv4_ll_buf, &ipv4_ll);
}

static inline int is_selfroute(int proto)
{
  if ((proto == RTPROT_BGP) || (proto == RTPROT_OSPF) ||
      (proto == RTPROT_STATIC) || (proto == RTPROT_ZEBRA) ||
      (proto == RTPROT_ISIS) || (proto == RTPROT_RIPNG) ||
      (proto == RTPROT_NHRP) || (proto == RTPROT_EIGRP) ||
      (proto == RTPROT_LDP)) {
    return 1;
  }

  return 0;
}

static inline int get_rt_proto(int proto)
{
  switch (proto) {
  case ZEBRA_ROUTE_BGP:
    proto = RTPROT_BGP;
    break;
  case ZEBRA_ROUTE_OSPF:
  case ZEBRA_ROUTE_OSPF6:
    proto = RTPROT_OSPF;
    break;
  case ZEBRA_ROUTE_STATIC:
    proto = RTPROT_STATIC;
    break;
  case ZEBRA_ROUTE_ISIS:
    proto = RTPROT_ISIS;
    break;
  case ZEBRA_ROUTE_RIP:
    proto = RTPROT_RIP;
    break;
  case ZEBRA_ROUTE_RIPNG:
    proto = RTPROT_RIPNG;
    break;
  case ZEBRA_ROUTE_NHRP:
    proto = RTPROT_NHRP;
    break;
  case ZEBRA_ROUTE_EIGRP:
    proto = RTPROT_EIGRP;
    break;
  case ZEBRA_ROUTE_LDP:
    proto = RTPROT_LDP;
    break;
  default:
    proto = RTPROT_ZEBRA;
    break;
  }

  return proto;
}

/*
Pending: create an efficient table_id (in a tree/hash) based lookup)
 */
static vrf_id_t
vrf_lookup_by_table (u_int32_t table_id)
{
  struct vrf *vrf;
  struct zebra_vrf *zvrf;

  RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id)
    {
      if ((zvrf = vrf->info) == NULL ||
          (zvrf->table_id != table_id))
        continue;

      return zvrf_id (zvrf);
    }

  return VRF_DEFAULT;
}

/* Looking up routing table by netlink interface. */
static int
netlink_route_change_read_unicast (struct sockaddr_nl *snl, struct nlmsghdr *h,
                                   ns_id_t ns_id, int startup)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb[RTA_MAX + 1];
  u_char flags = 0;
  struct prefix p;
  struct prefix_ipv6 src_p;
  vrf_id_t vrf_id = VRF_DEFAULT;

  char anyaddr[16] = { 0 };

  int index = 0;
  int table;
  int metric = 0;
  u_int32_t mtu = 0;

  void *dest = NULL;
  void *gate = NULL;
  void *prefsrc = NULL;		/* IPv4 preferred source host address */
  void *src = NULL;		/* IPv6 srcdest   source prefix */

  rtm = NLMSG_DATA (h);

  if (startup && h->nlmsg_type != RTM_NEWROUTE)
    return 0;
  if (startup && rtm->rtm_type != RTN_UNICAST)
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

  if (!startup &&
      is_selfroute (rtm->rtm_protocol) &&
      h->nlmsg_type == RTM_NEWROUTE)
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
  if (is_selfroute(rtm->rtm_protocol))
    flags |= ZEBRA_FLAG_SELFROUTE;

  if (tb[RTA_OIF])
    index = *(int *) RTA_DATA (tb[RTA_OIF]);

  if (tb[RTA_DST])
    dest = RTA_DATA (tb[RTA_DST]);
  else
    dest = anyaddr;

  if (tb[RTA_SRC])
    src = RTA_DATA (tb[RTA_SRC]);
  else
    src = anyaddr;

  if (tb[RTA_PREFSRC])
    prefsrc = RTA_DATA (tb[RTA_PREFSRC]);

  if (tb[RTA_GATEWAY])
    gate = RTA_DATA (tb[RTA_GATEWAY]);

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
    }
  else if (rtm->rtm_family == AF_INET6)
    {
      p.family = AF_INET6;
      memcpy (&p.u.prefix6, dest, 16);
      p.prefixlen = rtm->rtm_dst_len;

      src_p.family = AF_INET6;
      memcpy (&src_p.prefix, src, 16);
      src_p.prefixlen = rtm->rtm_src_len;
    }

  if (rtm->rtm_src_len != 0)
    {
      char buf[PREFIX_STRLEN];
      zlog_warn ("unsupported IPv[4|6] sourcedest route (dest %s vrf %u)",
                 prefix2str (&p, buf, sizeof(buf)), vrf_id);
      return 0;
    }

  if (IS_ZEBRA_DEBUG_KERNEL)
    {
      char buf[PREFIX_STRLEN];
      char buf2[PREFIX_STRLEN];
      zlog_debug ("%s %s%s%s vrf %u",
                  nl_msg_type_to_str (h->nlmsg_type),
                  prefix2str (&p, buf, sizeof(buf)),
                  src_p.prefixlen ? " from " : "",
                  src_p.prefixlen ? prefix2str(&src_p, buf2, sizeof(buf2)) : "",
                  vrf_id);
    }

  afi_t afi = AFI_IP;
  if (rtm->rtm_family == AF_INET6)
    afi = AFI_IP6;

  if (h->nlmsg_type == RTM_NEWROUTE)
    {
      if (!tb[RTA_MULTIPATH])
        rib_add (afi, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL,
                 0, flags, &p, NULL, gate, prefsrc, index,
                 table, metric, mtu, 0);
      else
        {
          /* This is a multipath route */

          struct route_entry *re;
          struct rtnexthop *rtnh =
            (struct rtnexthop *) RTA_DATA (tb[RTA_MULTIPATH]);

          len = RTA_PAYLOAD (tb[RTA_MULTIPATH]);

          re = XCALLOC (MTYPE_RE, sizeof (struct route_entry));
          re->type = ZEBRA_ROUTE_KERNEL;
          re->distance = 0;
          re->flags = flags;
          re->metric = metric;
          re->mtu = mtu;
          re->vrf_id = vrf_id;
          re->table = table;
          re->nexthop_num = 0;
          re->uptime = time (NULL);

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
                  if (rtm->rtm_family == AF_INET)
                    {
                      if (index)
                        route_entry_nexthop_ipv4_ifindex_add (re, gate, prefsrc, index);
                      else
                        route_entry_nexthop_ipv4_add (re, gate, prefsrc);
                    }
                  else if (rtm->rtm_family == AF_INET6)
                    {
                      if (index)
                        route_entry_nexthop_ipv6_ifindex_add (re, gate, index);
                      else
                        route_entry_nexthop_ipv6_add (re,gate);
                    }
                }
              else
                route_entry_nexthop_ifindex_add (re, index);

              len -= NLMSG_ALIGN(rtnh->rtnh_len);
              rtnh = RTNH_NEXT(rtnh);
            }

          zserv_nexthop_num_warn(__func__, (const struct prefix *)&p,
                                 re->nexthop_num);
          if (re->nexthop_num == 0)
            XFREE (MTYPE_RE, re);
          else
            rib_add_multipath (AFI_IP, SAFI_UNICAST, &p, NULL, re);
        }
    }
  else
    {
      if (!tb[RTA_MULTIPATH])
        rib_delete (afi, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL, 0, flags,
                    &p, NULL, gate, index, table);
      else
        {
          struct rtnexthop *rtnh =
            (struct rtnexthop *) RTA_DATA (tb[RTA_MULTIPATH]);

          len = RTA_PAYLOAD (tb[RTA_MULTIPATH]);

          for (;;)
            {
              if (len < (int) sizeof (*rtnh) || rtnh->rtnh_len > len)
                break;

              gate = NULL;
              if (rtnh->rtnh_len > sizeof (*rtnh))
                {
                  memset (tb, 0, sizeof (tb));
                  netlink_parse_rtattr (tb, RTA_MAX, RTNH_DATA (rtnh),
                                        rtnh->rtnh_len - sizeof (*rtnh));
                  if (tb[RTA_GATEWAY])
                    gate = RTA_DATA (tb[RTA_GATEWAY]);
                }

              if (gate)
                rib_delete (afi, SAFI_UNICAST, vrf_id, ZEBRA_ROUTE_KERNEL, 0, flags,
                            &p, NULL, gate, index, table);

              len -= NLMSG_ALIGN(rtnh->rtnh_len);
              rtnh = RTNH_NEXT(rtnh);
            }
        }
    }

  return 0;
}

static struct mcast_route_data *mroute = NULL;

static int
netlink_route_change_read_multicast (struct sockaddr_nl *snl, struct nlmsghdr *h,
                                     ns_id_t ns_id, int startup)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb[RTA_MAX + 1];
  struct mcast_route_data *m;
  struct mcast_route_data mr;
  int iif = 0;
  int count;
  int oif[256];
  int oif_count = 0;
  char sbuf[40];
  char gbuf[40];
  char oif_list[256] = "\0";
  vrf_id_t vrf = ns_id;

  if (mroute)
    m = mroute;
  else
    {
      memset (&mr, 0, sizeof (mr));
      m = &mr;
    }

  rtm = NLMSG_DATA (h);

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct rtmsg));

  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);

  if (tb[RTA_IIF])
    iif = *(int *)RTA_DATA (tb[RTA_IIF]);

  if (tb[RTA_SRC])
    m->sg.src = *(struct in_addr *)RTA_DATA (tb[RTA_SRC]);

  if (tb[RTA_DST])
    m->sg.grp = *(struct in_addr *)RTA_DATA (tb[RTA_DST]);

  if ((RTA_EXPIRES <= RTA_MAX) && tb[RTA_EXPIRES])
    m->lastused = *(unsigned long long *)RTA_DATA (tb[RTA_EXPIRES]);

  if (tb[RTA_MULTIPATH])
    {
      struct rtnexthop *rtnh =
        (struct rtnexthop *)RTA_DATA (tb[RTA_MULTIPATH]);

      len = RTA_PAYLOAD (tb[RTA_MULTIPATH]);
      for (;;)
        {
          if (len < (int) sizeof (*rtnh) || rtnh->rtnh_len > len)
	    break;

	  oif[oif_count] = rtnh->rtnh_ifindex;
          oif_count++;

	  len -= NLMSG_ALIGN (rtnh->rtnh_len);
	  rtnh = RTNH_NEXT (rtnh);
        }
    }

  if (IS_ZEBRA_DEBUG_KERNEL)
    {
      struct interface *ifp;
      strcpy (sbuf, inet_ntoa (m->sg.src));
      strcpy (gbuf, inet_ntoa (m->sg.grp));
      for (count = 0; count < oif_count; count++)
	{
	  ifp = if_lookup_by_index (oif[count], vrf);
	  char temp[256];

	  sprintf (temp, "%s ", ifp->name);
	  strcat (oif_list, temp);
	}
      ifp = if_lookup_by_index (iif, vrf);
      zlog_debug ("MCAST %s (%s,%s) IIF: %s OIF: %s jiffies: %lld",
		  nl_msg_type_to_str(h->nlmsg_type), sbuf, gbuf, ifp->name, oif_list, m->lastused);
    }
  return 0;
}

int
netlink_route_change (struct sockaddr_nl *snl, struct nlmsghdr *h,
		      ns_id_t ns_id, int startup)
{
  int len;
  vrf_id_t vrf_id = ns_id;
  struct rtmsg *rtm;

  rtm = NLMSG_DATA (h);

  if (!(h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE))
    {
      /* If this is not route add/delete message print warning. */
      zlog_warn ("Kernel message: %d vrf %u\n", h->nlmsg_type, vrf_id);
      return 0;
    }

  /* Connected route. */
  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_debug ("%s %s %s proto %s vrf %u",
		nl_msg_type_to_str (h->nlmsg_type),
		nl_family_to_str (rtm->rtm_family),
		nl_rttype_to_str (rtm->rtm_type),
		nl_rtproto_to_str (rtm->rtm_protocol),
		vrf_id);

  /* We don't care about change notifications for the MPLS table. */
  /* TODO: Revisit this. */
  if (rtm->rtm_family == AF_MPLS)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct rtmsg));
  if (len < 0)
    return -1;

  switch (rtm->rtm_type)
    {
    case RTN_UNICAST:
      netlink_route_change_read_unicast (snl, h, ns_id, startup);
      break;
    case RTN_MULTICAST:
      netlink_route_change_read_multicast (snl, h, ns_id, startup);
      break;
    default:
      return 0;
      break;
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
  ret = netlink_parse_info (netlink_route_change_read_unicast, &zns->netlink_cmd, zns, 0, 1);
  if (ret < 0)
    return ret;

  /* Get IPv6 routing table. */
  ret = netlink_request (AF_INET6, RTM_GETROUTE, &zns->netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_route_change_read_unicast, &zns->netlink_cmd, zns, 0, 1);
  if (ret < 0)
    return ret;

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

  /*
   * label_buf is *only* currently used within debugging.
   * As such when we assign it we are guarding it inside
   * a debug test.  If you want to change this make sure
   * you fix this assumption
   */
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
	      if (IS_ZEBRA_DEBUG_KERNEL)
		{
		  if (!num_labels)
		    sprintf (label_buf, "label %d", nh_label->label[i]);
		  else
		    {
		      sprintf (label_buf1, "/%d", nh_label->label[i]);
		      strcat (label_buf, label_buf1);
		    }
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

  if (rtmsg->rtm_family == AF_INET &&
      (nexthop->type == NEXTHOP_TYPE_IPV6
      || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX))
    {
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
                   "nexthop via %s %s if %u",
                   routedesc, ipv4_ll_buf, label_buf, nexthop->ifindex);
      return;
    }

  if (nexthop->type == NEXTHOP_TYPE_IPV4
      || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
    {
      /* Send deletes to the kernel without specifying the next-hop */
      if (cmd != RTM_DELROUTE)
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

  /*
   * label_buf is *only* currently used within debugging.
   * As such when we assign it we are guarding it inside
   * a debug test.  If you want to change this make sure
   * you fix this assumption
   */
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
	      if (IS_ZEBRA_DEBUG_KERNEL)
		{
		  if (!num_labels)
		    sprintf (label_buf, "label %d", nh_label->label[i]);
		  else
		    {
		      sprintf (label_buf1, "/%d", nh_label->label[i]);
		      strcat (label_buf, label_buf1);
		    }
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

  if (rtmsg->rtm_family == AF_INET &&
      (nexthop->type == NEXTHOP_TYPE_IPV6
      || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX))
    {
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
                   "nexthop via %s %s if %u",
                   routedesc, ipv4_ll_buf, label_buf, nexthop->ifindex);
      return;
    }

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
		  prefix2str (p, buf, sizeof(buf)), zvrf_id (zvrf),
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

  return netlink_talk (netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0);
}

/* Routing table change via netlink interface. */
/* Update flag indicates whether this is a "replace" or not. */
static int
netlink_route_multipath (int cmd, struct prefix *p, struct prefix *src_p,
                         struct route_entry *re, int update)
{
  int bytelen;
  struct sockaddr_nl snl;
  struct nexthop *nexthop = NULL, *tnexthop;
  int recursing;
  unsigned int nexthop_num;
  int discard;
  int family = PREFIX_FAMILY(p);
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
  struct zebra_vrf *zvrf = vrf_info_lookup (re->vrf_id);

  memset (&req, 0, sizeof req - NL_PKT_BUF_SIZE);

  bytelen = (family == AF_INET ? 4 : 16);

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
  req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
  if ((cmd == RTM_NEWROUTE) && update)
    req.n.nlmsg_flags |= NLM_F_REPLACE;
  req.n.nlmsg_type = cmd;
  req.r.rtm_family = family;
  req.r.rtm_dst_len = p->prefixlen;
  req.r.rtm_src_len = src_p ? src_p->prefixlen : 0;
  req.r.rtm_protocol = get_rt_proto(re->type);
  req.r.rtm_scope = RT_SCOPE_UNIVERSE;

  if ((re->flags & ZEBRA_FLAG_BLACKHOLE) || (re->flags & ZEBRA_FLAG_REJECT))
    discard = 1;
  else
    discard = 0;

  if (cmd == RTM_NEWROUTE)
    {
      if (discard)
        {
          if (re->flags & ZEBRA_FLAG_BLACKHOLE)
            req.r.rtm_type = RTN_BLACKHOLE;
          else if (re->flags & ZEBRA_FLAG_REJECT)
            req.r.rtm_type = RTN_UNREACHABLE;
          else
            assert (RTN_BLACKHOLE != RTN_UNREACHABLE);  /* false */
        }
      else
        req.r.rtm_type = RTN_UNICAST;
    }

  addattr_l (&req.n, sizeof req, RTA_DST, &p->u.prefix, bytelen);
  if (src_p)
    addattr_l (&req.n, sizeof req, RTA_SRC, &src_p->u.prefix, bytelen);

  /* Metric. */
  /* Hardcode the metric for all routes coming from zebra. Metric isn't used
   * either by the kernel or by zebra. Its purely for calculating best path(s)
   * by the routing protocol and for communicating with protocol peers.
   */
  addattr32 (&req.n, sizeof req, RTA_PRIORITY, NL_DEFAULT_ROUTE_METRIC);

  /* Table corresponding to this route. */
  if (re->table < 256)
    req.r.rtm_table = re->table;
  else
    {
      req.r.rtm_table = RT_TABLE_UNSPEC;
      addattr32(&req.n, sizeof req, RTA_TABLE, re->table);
    }

  if (re->mtu || re->nexthop_mtu)
    {
      char buf[NL_PKT_BUF_SIZE];
      struct rtattr *rta = (void *) buf;
      u_int32_t mtu = re->mtu;
      if (!mtu || (re->nexthop_mtu && re->nexthop_mtu < mtu))
        mtu = re->nexthop_mtu;
      rta->rta_type = RTA_METRICS;
      rta->rta_len = RTA_LENGTH(0);
      rta_addattr_l (rta, NL_PKT_BUF_SIZE, RTAX_MTU, &mtu, sizeof mtu);
      addattr_l (&req.n, NL_PKT_BUF_SIZE, RTA_METRICS, RTA_DATA (rta),
                 RTA_PAYLOAD (rta));
    }

  if (discard)
    {
      if (cmd == RTM_NEWROUTE)
        for (ALL_NEXTHOPS_RO(re->nexthop, nexthop, tnexthop, recursing))
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
  for (ALL_NEXTHOPS_RO(re->nexthop, nexthop, tnexthop, recursing))
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
  if (nexthop_num == 1 || multipath_num == 1)
    {
      nexthop_num = 0;
      for (ALL_NEXTHOPS_RO(re->nexthop, nexthop, tnexthop, recursing))
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
      for (ALL_NEXTHOPS_RO(re->nexthop, nexthop, tnexthop, recursing))
        {
          if (nexthop_num >= multipath_num)
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
  return netlink_talk (netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0);
}

int
kernel_get_ipmr_sg_stats (void *in)
{
  int suc = 0;
  struct mcast_route_data *mr = (struct mcast_route_data *)in;
  struct {
      struct nlmsghdr         n;
      struct ndmsg            ndm;
      char                    buf[256];
  } req;

  mroute = mr;
  struct zebra_ns *zns = zebra_ns_lookup (NS_DEFAULT);

  memset(&req.n, 0, sizeof(req.n));
  memset(&req.ndm, 0, sizeof(req.ndm));

  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST;
  req.ndm.ndm_family = AF_INET;
  req.n.nlmsg_type = RTM_GETROUTE;

  addattr_l (&req.n, sizeof (req), RTA_IIF, &mroute->ifindex, 4);
  addattr_l (&req.n, sizeof (req), RTA_OIF, &mroute->ifindex, 4);
  addattr_l (&req.n, sizeof (req), RTA_SRC, &mroute->sg.src.s_addr, 4);
  addattr_l (&req.n, sizeof (req), RTA_DST, &mroute->sg.grp.s_addr, 4);

  suc = netlink_talk (netlink_route_change_read_multicast, &req.n, &zns->netlink_cmd, zns, 0);

  mroute = NULL;
  return suc;
}

int
kernel_route_rib (struct prefix *p, struct prefix *src_p,
                  struct route_entry *old, struct route_entry *new)
{
  if (!old && new)
    return netlink_route_multipath (RTM_NEWROUTE, p, src_p, new, 0);
  if (old && !new)
    return netlink_route_multipath (RTM_DELROUTE, p, src_p, old, 0);

  return netlink_route_multipath (RTM_NEWROUTE, p, src_p, new, 1);
}

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
  unsigned int nexthop_num;
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
  if (nexthop_num == 1 || multipath_num == 1)
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

          if (nexthop_num >= multipath_num)
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
  return netlink_talk (netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0);
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
