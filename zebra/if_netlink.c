/*
 * Interface looking up by netlink.
 * Copyright (C) 1998 Kunihiro Ishiguro
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
#include "rtnetlink.h"

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
#include "zebra/if_netlink.h"


/* Note: on netlink systems, there should be a 1-to-1 mapping between interface
   names and ifindex values. */
static void
set_ifindex(struct interface *ifp, ifindex_t ifi_index, struct zebra_ns *zns)
{
  struct interface *oifp;

  if (((oifp = if_lookup_by_index_per_ns (zns, ifi_index)) != NULL) && (oifp != ifp))
    {
      if (ifi_index == IFINDEX_INTERNAL)
        zlog_err("Netlink is setting interface %s ifindex to reserved "
		 "internal value %u", ifp->name, ifi_index);
      else
        {
	  if (IS_ZEBRA_DEBUG_KERNEL)
	    zlog_debug("interface index %d was renamed from %s to %s",
                      ifi_index, oifp->name, ifp->name);
	  if (if_is_up(oifp))
	    zlog_err("interface rename detected on up interface: index %d "
		     "was renamed from %s to %s, results are uncertain!",
                    ifi_index, oifp->name, ifp->name);
	  if_delete_update(oifp);
        }
    }
  ifp->ifindex = ifi_index;
}

/* Utility function to parse hardware link-layer address and update ifp */
static void
netlink_interface_update_hw_addr (struct rtattr **tb, struct interface *ifp)
{
  int i;

  if (tb[IFLA_ADDRESS])
    {
      int hw_addr_len;

      hw_addr_len = RTA_PAYLOAD (tb[IFLA_ADDRESS]);

      if (hw_addr_len > INTERFACE_HWADDR_MAX)
        zlog_warn ("Hardware address is too large: %d", hw_addr_len);
      else
        {
          ifp->hw_addr_len = hw_addr_len;
          memcpy (ifp->hw_addr, RTA_DATA (tb[IFLA_ADDRESS]), hw_addr_len);

          for (i = 0; i < hw_addr_len; i++)
            if (ifp->hw_addr[i] != 0)
              break;

          if (i == hw_addr_len)
            ifp->hw_addr_len = 0;
          else
            ifp->hw_addr_len = hw_addr_len;
        }
    }
}

static enum zebra_link_type
netlink_to_zebra_link_type (unsigned int hwt)
{
  switch (hwt)
  {
    case ARPHRD_ETHER: return ZEBRA_LLT_ETHER;
    case ARPHRD_EETHER: return ZEBRA_LLT_EETHER;
    case ARPHRD_AX25: return ZEBRA_LLT_AX25;
    case ARPHRD_PRONET: return ZEBRA_LLT_PRONET;
    case ARPHRD_IEEE802: return ZEBRA_LLT_IEEE802;
    case ARPHRD_ARCNET: return ZEBRA_LLT_ARCNET;
    case ARPHRD_APPLETLK: return ZEBRA_LLT_APPLETLK;
    case ARPHRD_DLCI: return ZEBRA_LLT_DLCI;
    case ARPHRD_ATM: return ZEBRA_LLT_ATM;
    case ARPHRD_METRICOM: return ZEBRA_LLT_METRICOM;
    case ARPHRD_IEEE1394: return ZEBRA_LLT_IEEE1394;
    case ARPHRD_EUI64: return ZEBRA_LLT_EUI64;
    case ARPHRD_INFINIBAND: return ZEBRA_LLT_INFINIBAND;
    case ARPHRD_SLIP: return ZEBRA_LLT_SLIP;
    case ARPHRD_CSLIP: return ZEBRA_LLT_CSLIP;
    case ARPHRD_SLIP6: return ZEBRA_LLT_SLIP6;
    case ARPHRD_CSLIP6: return ZEBRA_LLT_CSLIP6;
    case ARPHRD_RSRVD: return ZEBRA_LLT_RSRVD;
    case ARPHRD_ADAPT: return ZEBRA_LLT_ADAPT;
    case ARPHRD_ROSE: return ZEBRA_LLT_ROSE;
    case ARPHRD_X25: return ZEBRA_LLT_X25;
    case ARPHRD_PPP: return ZEBRA_LLT_PPP;
    case ARPHRD_CISCO: return ZEBRA_LLT_CHDLC;
    case ARPHRD_LAPB: return ZEBRA_LLT_LAPB;
    case ARPHRD_RAWHDLC: return ZEBRA_LLT_RAWHDLC;
    case ARPHRD_TUNNEL: return ZEBRA_LLT_IPIP;
    case ARPHRD_TUNNEL6: return ZEBRA_LLT_IPIP6;
    case ARPHRD_FRAD: return ZEBRA_LLT_FRAD;
    case ARPHRD_SKIP: return ZEBRA_LLT_SKIP;
    case ARPHRD_LOOPBACK: return ZEBRA_LLT_LOOPBACK;
    case ARPHRD_LOCALTLK: return ZEBRA_LLT_LOCALTLK;
    case ARPHRD_FDDI: return ZEBRA_LLT_FDDI;
    case ARPHRD_SIT: return ZEBRA_LLT_SIT;
    case ARPHRD_IPDDP: return ZEBRA_LLT_IPDDP;
    case ARPHRD_IPGRE: return ZEBRA_LLT_IPGRE;
    case ARPHRD_PIMREG: return ZEBRA_LLT_PIMREG;
    case ARPHRD_HIPPI: return ZEBRA_LLT_HIPPI;
    case ARPHRD_ECONET: return ZEBRA_LLT_ECONET;
    case ARPHRD_IRDA: return ZEBRA_LLT_IRDA;
    case ARPHRD_FCPP: return ZEBRA_LLT_FCPP;
    case ARPHRD_FCAL: return ZEBRA_LLT_FCAL;
    case ARPHRD_FCPL: return ZEBRA_LLT_FCPL;
    case ARPHRD_FCFABRIC: return ZEBRA_LLT_FCFABRIC;
    case ARPHRD_IEEE802_TR: return ZEBRA_LLT_IEEE802_TR;
    case ARPHRD_IEEE80211: return ZEBRA_LLT_IEEE80211;
    case ARPHRD_IEEE802154: return ZEBRA_LLT_IEEE802154;
#ifdef ARPHRD_IP6GRE
    case ARPHRD_IP6GRE: return ZEBRA_LLT_IP6GRE;
#endif
#ifdef ARPHRD_IEEE802154_PHY
    case ARPHRD_IEEE802154_PHY: return ZEBRA_LLT_IEEE802154_PHY;
#endif

    default: return ZEBRA_LLT_UNKNOWN;
  }
}

#define parse_rtattr_nested(tb, max, rta) \
          netlink_parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta))

static void
netlink_vrf_change (struct nlmsghdr *h, struct rtattr *tb, const char *name)
{
  struct ifinfomsg *ifi;
  struct rtattr *linkinfo[IFLA_INFO_MAX+1];
  struct rtattr *attr[IFLA_VRF_MAX+1];
  struct vrf *vrf;
  struct zebra_vrf *zvrf;
  u_int32_t nl_table_id;

  ifi = NLMSG_DATA (h);

  memset (linkinfo, 0, sizeof linkinfo);
  parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb);

  if (!linkinfo[IFLA_INFO_DATA]) {
    if (IS_ZEBRA_DEBUG_KERNEL)
      zlog_debug ("%s: IFLA_INFO_DATA missing from VRF message: %s", __func__, name);
    return;
  }

  memset (attr, 0, sizeof attr);
  parse_rtattr_nested(attr, IFLA_VRF_MAX, linkinfo[IFLA_INFO_DATA]);
  if (!attr[IFLA_VRF_TABLE]) {
    if (IS_ZEBRA_DEBUG_KERNEL)
      zlog_debug ("%s: IFLA_VRF_TABLE missing from VRF message: %s", __func__, name);
    return;
  }

  nl_table_id = *(u_int32_t *)RTA_DATA(attr[IFLA_VRF_TABLE]);

  if (h->nlmsg_type == RTM_NEWLINK)
    {
      /* If VRF already exists, we just return; status changes are handled
       * against the VRF "interface".
       */
      vrf = vrf_lookup ((vrf_id_t)ifi->ifi_index);
      if (vrf && vrf->info)
        return;

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("RTM_NEWLINK for VRF %s(%u) table %u",
                    name, ifi->ifi_index, nl_table_id);

      /*
       * vrf_get is implied creation if it does not exist
       */
      vrf = vrf_get((vrf_id_t)ifi->ifi_index, name); // It would create vrf
      if (!vrf)
        {
          zlog_err ("VRF %s id %u not created", name, ifi->ifi_index);
          return;
        }

      /* Enable the created VRF. */
      if (!vrf_enable (vrf))
        {
          zlog_err ("Failed to enable VRF %s id %u", name, ifi->ifi_index);
          return;
        }

      /*
       * This is the only place that we get the actual kernel table_id
       * being used.  We need it to set the table_id of the routes
       * we are passing to the kernel.... And to throw some totally
       * awesome parties. that too.
       */
      zvrf = (struct zebra_vrf *)vrf->info;
      zvrf->table_id = nl_table_id;
    }
  else //h->nlmsg_type == RTM_DELLINK
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("RTM_DELLINK for VRF %s(%u)", name, ifi->ifi_index);

      vrf = vrf_lookup ((vrf_id_t)ifi->ifi_index);

      if (!vrf)
        {
	  zlog_warn ("%s: vrf not found", __func__);
	  return;
	}

      vrf_delete (vrf);
    }
}

/* Called from interface_lookup_netlink().  This function is only used
   during bootstrap. */
static int
netlink_interface (struct sockaddr_nl *snl, struct nlmsghdr *h,
                   ns_id_t ns_id)
{
  int len;
  struct ifinfomsg *ifi;
  struct rtattr *tb[IFLA_MAX + 1];
  struct rtattr *linkinfo[IFLA_MAX + 1];
  struct interface *ifp;
  char *name = NULL;
  char *kind = NULL;
  char *slave_kind = NULL;
  int vrf_device = 0;
  struct zebra_ns *zns;
  vrf_id_t vrf_id = VRF_DEFAULT;

  zns = zebra_ns_lookup (ns_id);
  ifi = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWLINK)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifinfomsg));
  if (len < 0)
    return -1;

  if (ifi->ifi_family == AF_BRIDGE)
    return 0;

  /* Looking up interface name. */
  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA (ifi), len);

#ifdef IFLA_WIRELESS
  /* check for wireless messages to ignore */
  if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0))
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("%s: ignoring IFLA_WIRELESS message", __func__);
      return 0;
    }
#endif /* IFLA_WIRELESS */

  if (tb[IFLA_IFNAME] == NULL)
    return -1;
  name = (char *) RTA_DATA (tb[IFLA_IFNAME]);

  if (tb[IFLA_LINKINFO])
    {
      memset (linkinfo, 0, sizeof linkinfo);
      parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

      if (linkinfo[IFLA_INFO_KIND])
        kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);

#if HAVE_DECL_IFLA_INFO_SLAVE_KIND
      if (linkinfo[IFLA_INFO_SLAVE_KIND])
         slave_kind = RTA_DATA(linkinfo[IFLA_INFO_SLAVE_KIND]);
#endif

      if (kind && strcmp(kind, "vrf") == 0)
        {
          vrf_device = 1;
          netlink_vrf_change(h, tb[IFLA_LINKINFO], name);
          vrf_id = (vrf_id_t)ifi->ifi_index;
        }
    }

  if (tb[IFLA_MASTER])
    {
      if (slave_kind && (strcmp(slave_kind, "vrf") == 0))
        vrf_id = *(u_int32_t *)RTA_DATA(tb[IFLA_MASTER]);
    }

  /* Add interface. */
  ifp = if_get_by_name_vrf (name, vrf_id);
  set_ifindex(ifp, ifi->ifi_index, zns);
  ifp->flags = ifi->ifi_flags & 0x0000fffff;
  if (vrf_device)
    SET_FLAG(ifp->status, ZEBRA_INTERFACE_VRF_LOOPBACK);
  ifp->mtu6 = ifp->mtu = *(uint32_t *) RTA_DATA (tb[IFLA_MTU]);
  ifp->metric = 0;
  ifp->ptm_status = ZEBRA_PTM_STATUS_UNKNOWN;

  /* Hardware type and address. */
  ifp->ll_type = netlink_to_zebra_link_type (ifi->ifi_type);
  netlink_interface_update_hw_addr (tb, ifp);

  if_add_update (ifp);

  return 0;
}

/* Interface lookup by netlink socket. */
int
interface_lookup_netlink (struct zebra_ns *zns)
{
  int ret;

  /* Get interface information. */
  ret = netlink_request (AF_PACKET, RTM_GETLINK, &zns->netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface, &zns->netlink_cmd, zns, 0);
  if (ret < 0)
    return ret;

  /* Get IPv4 address of the interfaces. */
  ret = netlink_request (AF_INET, RTM_GETADDR, &zns->netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface_addr, &zns->netlink_cmd, zns, 0);
  if (ret < 0)
    return ret;

#ifdef HAVE_IPV6
  /* Get IPv6 address of the interfaces. */
  ret = netlink_request (AF_INET6, RTM_GETADDR, &zns->netlink_cmd);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface_addr, &zns->netlink_cmd, zns, 0);
  if (ret < 0)
    return ret;
#endif /* HAVE_IPV6 */

  return 0;
}

/* Interface address modification. */
static int
netlink_address (int cmd, int family, struct interface *ifp,
                 struct connected *ifc)
{
  int bytelen;
  struct prefix *p;

  struct
  {
    struct nlmsghdr n;
    struct ifaddrmsg ifa;
    char buf[NL_PKT_BUF_SIZE];
  } req;

  struct zebra_ns *zns = zebra_ns_lookup (NS_DEFAULT);

  p = ifc->address;
  memset (&req, 0, sizeof req - NL_PKT_BUF_SIZE);

  bytelen = (family == AF_INET ? 4 : 16);

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST;
  req.n.nlmsg_type = cmd;
  req.ifa.ifa_family = family;

  req.ifa.ifa_index = ifp->ifindex;
  req.ifa.ifa_prefixlen = p->prefixlen;

  addattr_l (&req.n, sizeof req, IFA_LOCAL, &p->u.prefix, bytelen);

  if (family == AF_INET && cmd == RTM_NEWADDR)
    {
      if (!CONNECTED_PEER(ifc) && ifc->destination)
        {
          p = ifc->destination;
          addattr_l (&req.n, sizeof req, IFA_BROADCAST, &p->u.prefix,
                     bytelen);
        }
    }

  if (CHECK_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY))
    SET_FLAG (req.ifa.ifa_flags, IFA_F_SECONDARY);

  if (ifc->label)
    addattr_l (&req.n, sizeof req, IFA_LABEL, ifc->label,
               strlen (ifc->label) + 1);

  return netlink_talk (&req.n, &zns->netlink_cmd, zns);
}

int
kernel_address_add_ipv4 (struct interface *ifp, struct connected *ifc)
{
  return netlink_address (RTM_NEWADDR, AF_INET, ifp, ifc);
}

int
kernel_address_delete_ipv4 (struct interface *ifp, struct connected *ifc)
{
  return netlink_address (RTM_DELADDR, AF_INET, ifp, ifc);
}

int
netlink_interface_addr (struct sockaddr_nl *snl, struct nlmsghdr *h,
                        ns_id_t ns_id)
{
  int len;
  struct ifaddrmsg *ifa;
  struct rtattr *tb[IFA_MAX + 1];
  struct interface *ifp;
  void *addr;
  void *broad;
  u_char flags = 0;
  char *label = NULL;
  struct zebra_ns *zns;

  zns = zebra_ns_lookup (ns_id);
  ifa = NLMSG_DATA (h);

  if (ifa->ifa_family != AF_INET
#ifdef HAVE_IPV6
      && ifa->ifa_family != AF_INET6
#endif /* HAVE_IPV6 */
    )
    return 0;

  if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifaddrmsg));
  if (len < 0)
    return -1;

  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, IFA_MAX, IFA_RTA (ifa), len);

  ifp = if_lookup_by_index_per_ns (zns, ifa->ifa_index);
  if (ifp == NULL)
    {
      zlog_err ("netlink_interface_addr can't find interface by index %d",
                ifa->ifa_index);
      return -1;
    }

  if (IS_ZEBRA_DEBUG_KERNEL)    /* remove this line to see initial ifcfg */
    {
      char buf[BUFSIZ];
      zlog_debug ("netlink_interface_addr %s %s flags 0x%x:",
                 nl_msg_type_to_str (h->nlmsg_type), ifp->name,
                 ifa->ifa_flags);
      if (tb[IFA_LOCAL])
        zlog_debug ("  IFA_LOCAL     %s/%d",
		    inet_ntop (ifa->ifa_family, RTA_DATA (tb[IFA_LOCAL]),
			       buf, BUFSIZ), ifa->ifa_prefixlen);
      if (tb[IFA_ADDRESS])
        zlog_debug ("  IFA_ADDRESS   %s/%d",
		    inet_ntop (ifa->ifa_family, RTA_DATA (tb[IFA_ADDRESS]),
                               buf, BUFSIZ), ifa->ifa_prefixlen);
      if (tb[IFA_BROADCAST])
        zlog_debug ("  IFA_BROADCAST %s/%d",
		    inet_ntop (ifa->ifa_family, RTA_DATA (tb[IFA_BROADCAST]),
			       buf, BUFSIZ), ifa->ifa_prefixlen);
      if (tb[IFA_LABEL] && strcmp (ifp->name, RTA_DATA (tb[IFA_LABEL])))
        zlog_debug ("  IFA_LABEL     %s", (char *)RTA_DATA (tb[IFA_LABEL]));

      if (tb[IFA_CACHEINFO])
        {
          struct ifa_cacheinfo *ci = RTA_DATA (tb[IFA_CACHEINFO]);
          zlog_debug ("  IFA_CACHEINFO pref %d, valid %d",
                      ci->ifa_prefered, ci->ifa_valid);
        }
    }

  /* logic copied from iproute2/ip/ipaddress.c:print_addrinfo() */
  if (tb[IFA_LOCAL] == NULL)
    tb[IFA_LOCAL] = tb[IFA_ADDRESS];
  if (tb[IFA_ADDRESS] == NULL)
    tb[IFA_ADDRESS] = tb[IFA_LOCAL];

  /* local interface address */
  addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

  /* is there a peer address? */
  if (tb[IFA_ADDRESS] &&
      memcmp(RTA_DATA(tb[IFA_ADDRESS]), RTA_DATA(tb[IFA_LOCAL]), RTA_PAYLOAD(tb[IFA_ADDRESS])))
    {
      broad = RTA_DATA(tb[IFA_ADDRESS]);
      SET_FLAG (flags, ZEBRA_IFA_PEER);
    }
  else
    /* seeking a broadcast address */
    broad = (tb[IFA_BROADCAST] ? RTA_DATA(tb[IFA_BROADCAST]) : NULL);

  /* addr is primary key, SOL if we don't have one */
  if (addr == NULL)
    {
      zlog_debug ("%s: NULL address", __func__);
      return -1;
    }

  /* Flags. */
  if (ifa->ifa_flags & IFA_F_SECONDARY)
    SET_FLAG (flags, ZEBRA_IFA_SECONDARY);

  /* Label */
  if (tb[IFA_LABEL])
    label = (char *) RTA_DATA (tb[IFA_LABEL]);

  if (ifp && label && strcmp (ifp->name, label) == 0)
    label = NULL;

  /* Register interface address to the interface. */
  if (ifa->ifa_family == AF_INET)
    {
      if (h->nlmsg_type == RTM_NEWADDR)
        connected_add_ipv4 (ifp, flags,
                            (struct in_addr *) addr, ifa->ifa_prefixlen,
                            (struct in_addr *) broad, label);
      else
        connected_delete_ipv4 (ifp, flags,
                               (struct in_addr *) addr, ifa->ifa_prefixlen,
                               (struct in_addr *) broad);
    }
#ifdef HAVE_IPV6
  if (ifa->ifa_family == AF_INET6)
    {
      if (h->nlmsg_type == RTM_NEWADDR)
        {
          /* Only consider valid addresses; we'll not get a notification from
           * the kernel till IPv6 DAD has completed, but at init time, Quagga
           * does query for and will receive all addresses.
           */
          if (!(ifa->ifa_flags & (IFA_F_DADFAILED | IFA_F_TENTATIVE)))
            connected_add_ipv6 (ifp, flags, (struct in6_addr *) addr,
                    ifa->ifa_prefixlen, (struct in6_addr *) broad, label);
        }
      else
        connected_delete_ipv6 (ifp,
                               (struct in6_addr *) addr, ifa->ifa_prefixlen,
                               (struct in6_addr *) broad);
    }
#endif /* HAVE_IPV6 */

  return 0;
}

int
netlink_link_change (struct sockaddr_nl *snl, struct nlmsghdr *h,
                     ns_id_t ns_id)
{
  int len;
  struct ifinfomsg *ifi;
  struct rtattr *tb[IFLA_MAX + 1];
  struct rtattr *linkinfo[IFLA_MAX + 1];
  struct interface *ifp;
  char *name = NULL;
  char *kind = NULL;
  char *slave_kind = NULL;
  int vrf_device = 0;
  struct zebra_ns *zns;
  vrf_id_t vrf_id = VRF_DEFAULT;

  zns = zebra_ns_lookup (ns_id);
  ifi = NLMSG_DATA (h);

  if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK))
    {
      /* If this is not link add/delete message so print warning. */
      zlog_warn ("netlink_link_change: wrong kernel message %d",
                 h->nlmsg_type);
      return 0;
    }

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifinfomsg));
  if (len < 0)
    return -1;

  if (ifi->ifi_family == AF_BRIDGE)
    return 0;

  /* Looking up interface name. */
  memset (tb, 0, sizeof tb);
  netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA (ifi), len);

#ifdef IFLA_WIRELESS
  /* check for wireless messages to ignore */
  if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0))
    {
      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("%s: ignoring IFLA_WIRELESS message", __func__);
      return 0;
    }
#endif /* IFLA_WIRELESS */

  if (tb[IFLA_IFNAME] == NULL)
    return -1;
  name = (char *) RTA_DATA (tb[IFLA_IFNAME]);

  if (tb[IFLA_LINKINFO])
    {
      memset (linkinfo, 0, sizeof linkinfo);
      parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);

      if (linkinfo[IFLA_INFO_KIND])
        kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);

#if HAVE_DECL_IFLA_INFO_SLAVE_KIND
      if (linkinfo[IFLA_INFO_SLAVE_KIND])
          slave_kind = RTA_DATA(linkinfo[IFLA_INFO_SLAVE_KIND]);
#endif

      if (kind && strcmp(kind, "vrf") == 0)
        {
          vrf_device = 1;
          netlink_vrf_change(h, tb[IFLA_LINKINFO], name);
          vrf_id = (vrf_id_t)ifi->ifi_index;
        }
    }

  /* See if interface is present. */
  ifp = if_lookup_by_index_per_ns (zns, ifi->ifi_index);

  if (h->nlmsg_type == RTM_NEWLINK)
    {
      if (tb[IFLA_MASTER])
	{
          if (slave_kind && (strcmp(slave_kind, "vrf") == 0))
            vrf_id = *(u_int32_t *)RTA_DATA(tb[IFLA_MASTER]);
	}

      if (ifp == NULL || !CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
        {
          /* Add interface notification from kernel */
          if (IS_ZEBRA_DEBUG_KERNEL)
            zlog_debug ("RTM_NEWLINK for %s(%u) (ifp %p) vrf_id %u flags 0x%x",
                        name, ifi->ifi_index, ifp, vrf_id, ifi->ifi_flags);

          if (ifp == NULL)
            {
              /* unknown interface */
              ifp = if_get_by_name_vrf (name, vrf_id);
            }
          else
            {
              /* pre-configured interface, learnt now */
              if (ifp->vrf_id != vrf_id)
                if_update_vrf (ifp, name, strlen(name), vrf_id);
            }

          /* Update interface information. */
          set_ifindex(ifp, ifi->ifi_index, zns);
          ifp->flags = ifi->ifi_flags & 0x0000fffff;
          if (vrf_device)
            SET_FLAG(ifp->status, ZEBRA_INTERFACE_VRF_LOOPBACK);
          ifp->mtu6 = ifp->mtu = *(int *) RTA_DATA (tb[IFLA_MTU]);
          ifp->metric = 0;
          ifp->ptm_status = ZEBRA_PTM_STATUS_UNKNOWN;

          netlink_interface_update_hw_addr (tb, ifp);

          /* Inform clients, install any configured addresses. */
          if_add_update (ifp);
        }
      else if (ifp->vrf_id != vrf_id)
        {
          /* VRF change for an interface. */
          if (IS_ZEBRA_DEBUG_KERNEL)
            zlog_debug ("RTM_NEWLINK vrf-change for %s(%u) "
                        "vrf_id %u -> %u flags 0x%x",
                        name, ifp->ifindex, ifp->vrf_id,
                        vrf_id, ifi->ifi_flags);

          if_handle_vrf_change (ifp, vrf_id);
        }
      else
        {
          /* Interface status change. */
          if (IS_ZEBRA_DEBUG_KERNEL)
             zlog_debug ("RTM_NEWLINK status for %s(%u) flags 0x%x",
                          name, ifp->ifindex, ifi->ifi_flags);

          set_ifindex(ifp, ifi->ifi_index, zns);
          ifp->mtu6 = ifp->mtu = *(int *) RTA_DATA (tb[IFLA_MTU]);
          ifp->metric = 0;

          netlink_interface_update_hw_addr (tb, ifp);

          if (if_is_no_ptm_operative (ifp))
            {
              ifp->flags = ifi->ifi_flags & 0x0000fffff;
              if (!if_is_no_ptm_operative (ifp))
                if_down (ifp);
	      else if (if_is_operative (ifp))
		/* Must notify client daemons of new interface status. */
	        zebra_interface_up_update (ifp);
            }
          else
            {
              ifp->flags = ifi->ifi_flags & 0x0000fffff;
              if (if_is_operative (ifp))
                if_up (ifp);
            }
        }
    }
  else
    {
      /* Delete interface notification from kernel */
      if (ifp == NULL)
        {
          zlog_warn ("RTM_DELLINK for unknown interface %s(%u)",
                     name, ifi->ifi_index);
          return 0;
        }

      if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("RTM_DELLINK for %s(%u)", name, ifp->ifindex);

      UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_VRF_LOOPBACK);

      if (!vrf_device)
        if_delete_update (ifp);
    }

  return 0;
}

/* Interface information read by netlink. */
void
interface_list (struct zebra_ns *zns)
{
  interface_lookup_netlink (zns);
}
