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

#include "rt_netlink.h"

static const struct message nlmsg_str[] = {
  {RTM_NEWROUTE, "RTM_NEWROUTE"},
  {RTM_DELROUTE, "RTM_DELROUTE"},
  {RTM_GETROUTE, "RTM_GETROUTE"},
  {RTM_NEWLINK,  "RTM_NEWLINK"},
  {RTM_DELLINK,  "RTM_DELLINK"},
  {RTM_GETLINK,  "RTM_GETLINK"},
  {RTM_NEWADDR,  "RTM_NEWADDR"},
  {RTM_DELADDR,  "RTM_DELADDR"},
  {RTM_GETADDR,  "RTM_GETADDR"},
  {RTM_NEWNEIGH, "RTM_NEWNEIGH"},
  {RTM_DELNEIGH, "RTM_DELNEIGH"},
  {RTM_GETNEIGH, "RTM_GETNEIGH"},
  {0, NULL}
};

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

#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((u_char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

#ifndef RTA_TAIL
#define RTA_TAIL(rta) \
        ((struct rtattr *) (((u_char *) (rta)) + RTA_ALIGN((rta)->rta_len)))
#endif

struct gw_family_t
{
  u_int16_t     filler;
  u_int16_t     family;
  union g_addr  gate;
};

extern struct zebra_privs_t zserv_privs;

extern u_int32_t nl_rcvbufsize;

/* Note: on netlink systems, there should be a 1-to-1 mapping between interface
   names and ifindex values. */
static void
set_ifindex(struct interface *ifp, ifindex_t ifi_index)
{
  struct interface *oifp;
  struct zebra_ns *zns = zebra_ns_lookup (NS_DEFAULT);

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

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE  (33)
#endif

static int
netlink_recvbuf (struct nlsock *nl, uint32_t newsize)
{
  u_int32_t oldsize;
  socklen_t newlen = sizeof(newsize);
  socklen_t oldlen = sizeof(oldsize);
  int ret;

  ret = getsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &oldsize, &oldlen);
  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't get %s receive buffer size: %s", nl->name,
	    safe_strerror (errno));
      return -1;
    }

  /* Try force option (linux >= 2.6.14) and fall back to normal set */
  if ( zserv_privs.change (ZPRIVS_RAISE) )
    zlog_err ("routing_socket: Can't raise privileges");
  ret = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUFFORCE, &nl_rcvbufsize,
		   sizeof(nl_rcvbufsize));
  if ( zserv_privs.change (ZPRIVS_LOWER) )
    zlog_err ("routing_socket: Can't lower privileges");
  if (ret < 0)
     ret = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &nl_rcvbufsize,
		      sizeof(nl_rcvbufsize));
  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't set %s receive buffer size: %s", nl->name,
	    safe_strerror (errno));
      return -1;
    }

  ret = getsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &newsize, &newlen);
  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't get %s receive buffer size: %s", nl->name,
	    safe_strerror (errno));
      return -1;
    }

  zlog (NULL, LOG_INFO,
	"Setting netlink socket receive buffer size: %u -> %u",
	oldsize, newsize);
  return 0;
}

/* Make socket for Linux netlink interface. */
static int
netlink_socket (struct nlsock *nl, unsigned long groups, ns_id_t ns_id)
{
  int ret;
  struct sockaddr_nl snl;
  int sock;
  int namelen;
  int save_errno;

  if (zserv_privs.change (ZPRIVS_RAISE))
    {
      zlog (NULL, LOG_ERR, "Can't raise privileges");
      return -1;
    }

  sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0)
    {
      zlog (NULL, LOG_ERR, "Can't open %s socket: %s", nl->name,
            safe_strerror (errno));
      return -1;
    }

  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;
  snl.nl_groups = groups;

  /* Bind the socket to the netlink structure for anything. */
  ret = bind (sock, (struct sockaddr *) &snl, sizeof snl);
  save_errno = errno;
  if (zserv_privs.change (ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't bind %s socket to group 0x%x: %s",
            nl->name, snl.nl_groups, safe_strerror (save_errno));
      close (sock);
      return -1;
    }

  /* multiple netlink sockets will have different nl_pid */
  namelen = sizeof snl;
  ret = getsockname (sock, (struct sockaddr *) &snl, (socklen_t *) &namelen);
  if (ret < 0 || namelen != sizeof snl)
    {
      zlog (NULL, LOG_ERR, "Can't get %s socket name: %s", nl->name,
            safe_strerror (errno));
      close (sock);
      return -1;
    }

  nl->snl = snl;
  nl->sock = sock;
  return ret;
}

/* Get type specified information from netlink. */
static int
netlink_request (int family, int type, struct nlsock *nl)
{
  int ret;
  struct sockaddr_nl snl;
  int save_errno;

  struct
  {
    struct nlmsghdr nlh;
    struct rtgenmsg g;
  } req;

  /* Check netlink socket. */
  if (nl->sock < 0)
    {
      zlog (NULL, LOG_ERR, "%s socket isn't active.", nl->name);
      return -1;
    }

  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  memset (&req, 0, sizeof req);
  req.nlh.nlmsg_len = sizeof req;
  req.nlh.nlmsg_type = type;
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
  req.nlh.nlmsg_pid = nl->snl.nl_pid;
  req.nlh.nlmsg_seq = ++nl->seq;
  req.g.rtgen_family = family;

  /* linux appears to check capabilities on every message 
   * have to raise caps for every message sent
   */
  if (zserv_privs.change (ZPRIVS_RAISE))
    {
      zlog (NULL, LOG_ERR, "Can't raise privileges");
      return -1;
    }

  ret = sendto (nl->sock, (void *) &req, sizeof req, 0,
		(struct sockaddr *) &snl, sizeof snl);
  save_errno = errno;

  if (zserv_privs.change (ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "%s sendto failed: %s", nl->name,
            safe_strerror (save_errno));
      return -1;
    }

  return 0;
}

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

/* Receive message from netlink interface and pass those information
   to the given function. */
static int
netlink_parse_info (int (*filter) (struct sockaddr_nl *, struct nlmsghdr *,
                                   ns_id_t),
                    struct nlsock *nl, struct zebra_ns *zns, int count)
{
  int status;
  int ret = 0;
  int error;
  int read_in = 0;

  while (1)
    {
      char buf[NL_PKT_BUF_SIZE];
      struct iovec iov = {
        .iov_base = buf,
        .iov_len = sizeof buf
      };
      struct sockaddr_nl snl;
      struct msghdr msg = {
        .msg_name = (void *) &snl,
        .msg_namelen = sizeof snl,
        .msg_iov = &iov,
        .msg_iovlen = 1
      };
      struct nlmsghdr *h;

      if (count && read_in >= count)
        return 0;

      status = recvmsg (nl->sock, &msg, 0);
      if (status < 0)
        {
          if (errno == EINTR)
            continue;
          if (errno == EWOULDBLOCK || errno == EAGAIN)
            break;
          zlog (NULL, LOG_ERR, "%s recvmsg overrun: %s",
	  	nl->name, safe_strerror(errno));
          /*
           *  In this case we are screwed.
           *  There is no good way to
           *  recover zebra at this point.
           */
          exit (-1);
          continue;
        }

      if (status == 0)
        {
          zlog (NULL, LOG_ERR, "%s EOF", nl->name);
          return -1;
        }

      if (msg.msg_namelen != sizeof snl)
        {
          zlog (NULL, LOG_ERR, "%s sender address length error: length %d",
                nl->name, msg.msg_namelen);
          return -1;
        }

      if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV)
        {
          zlog_debug("%s: << netlink message dump [recv]", __func__);
          zlog_hexdump(&msg, sizeof(msg));
        }

      read_in++;
      for (h = (struct nlmsghdr *) buf; NLMSG_OK (h, (unsigned int) status);
           h = NLMSG_NEXT (h, status))
        {
          /* Finish of reading. */
          if (h->nlmsg_type == NLMSG_DONE)
            return ret;

          /* Error handling. */
          if (h->nlmsg_type == NLMSG_ERROR)
            {
              struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
	      int errnum = err->error;
	      int msg_type = err->msg.nlmsg_type;

              /* If the error field is zero, then this is an ACK */
              if (err->error == 0)
                {
                  if (IS_ZEBRA_DEBUG_KERNEL)
                    {
                      zlog_debug ("%s: %s ACK: type=%s(%u), seq=%u, pid=%u",
                                 __FUNCTION__, nl->name,
                                 lookup (nlmsg_str, err->msg.nlmsg_type),
                                 err->msg.nlmsg_type, err->msg.nlmsg_seq,
                                 err->msg.nlmsg_pid);
                    }

                  /* return if not a multipart message, otherwise continue */
                  if (!(h->nlmsg_flags & NLM_F_MULTI))
                    return 0;
                  continue;
                }

              if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr)))
                {
                  zlog (NULL, LOG_ERR, "%s error: message truncated",
                        nl->name);
                  return -1;
                }

              /* Deal with errors that occur because of races in link handling */
	      if (nl == &zns->netlink_cmd
		  && ((msg_type == RTM_DELROUTE &&
		       (-errnum == ENODEV || -errnum == ESRCH))
		      || (msg_type == RTM_NEWROUTE && -errnum == EEXIST)))
		{
		  if (IS_ZEBRA_DEBUG_KERNEL)
		    zlog_debug ("%s: error: %s type=%s(%u), seq=%u, pid=%u",
				nl->name, safe_strerror (-errnum),
				lookup (nlmsg_str, msg_type),
				msg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid);
		  return 0;
		}

              /* We see RTM_DELNEIGH when shutting down an interface with an IPv4
               * link-local.  The kernel should have already deleted the neighbor
               * so do not log these as an error.
               */
              if (msg_type == RTM_DELNEIGH ||
                  (nl == &zns->netlink_cmd && msg_type == RTM_NEWROUTE &&
                   (-errnum == ESRCH || -errnum == ENETUNREACH)))
		{
                  /* This is known to happen in some situations, don't log
                   * as error.
                   */
		  if (IS_ZEBRA_DEBUG_KERNEL)
	            zlog_debug ("%s error: %s, type=%s(%u), seq=%u, pid=%u",
                                nl->name, safe_strerror (-errnum),
                                lookup (nlmsg_str, msg_type),
                                msg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid);
                }
              else
	        zlog_err ("%s error: %s, type=%s(%u), seq=%u, pid=%u",
			nl->name, safe_strerror (-errnum),
			lookup (nlmsg_str, msg_type),
			msg_type, err->msg.nlmsg_seq, err->msg.nlmsg_pid);

              return -1;
            }

          /* OK we got netlink message. */
          if (IS_ZEBRA_DEBUG_KERNEL)
            zlog_debug ("netlink_parse_info: %s type %s(%u), len=%d, seq=%u, pid=%u",
                       nl->name,
                       lookup (nlmsg_str, h->nlmsg_type), h->nlmsg_type,
                       h->nlmsg_len, h->nlmsg_seq, h->nlmsg_pid);

          /* skip unsolicited messages originating from command socket
           * linux sets the originators port-id for {NEW|DEL}ADDR messages,
           * so this has to be checked here. */
          if (nl != &zns->netlink_cmd
              && h->nlmsg_pid == zns->netlink_cmd.snl.nl_pid
              && (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR))
            {
              if (IS_ZEBRA_DEBUG_KERNEL)
                zlog_debug ("netlink_parse_info: %s packet comes from %s",
                            zns->netlink_cmd.name, nl->name);
              continue;
            }

          error = (*filter) (&snl, h, zns->ns_id);
          if (error < 0)
            {
              zlog (NULL, LOG_ERR, "%s filter function error", nl->name);
              ret = error;
            }
        }

      /* After error care. */
      if (msg.msg_flags & MSG_TRUNC)
        {
          zlog (NULL, LOG_ERR, "%s error: message truncated", nl->name);
          continue;
        }
      if (status)
        {
          zlog (NULL, LOG_ERR, "%s error: data remnant size %d", nl->name,
                status);
          return -1;
        }
    }
  return ret;
}

/* Utility function for parse rtattr. */
static void
netlink_parse_rtattr (struct rtattr **tb, int max, struct rtattr *rta,
                      int len)
{
  while (RTA_OK (rta, len))
    {
      if (rta->rta_type <= max)
        tb[rta->rta_type] = rta;
      rta = RTA_NEXT (rta, len);
    }
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

  parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb);

  if (!linkinfo[IFLA_INFO_DATA]) {
    if (IS_ZEBRA_DEBUG_KERNEL)
      zlog_debug ("%s: IFLA_INFO_DATA missing from VRF message: %s", __func__, name);
    return;
  }

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
    vrf_id_t vrf_id)
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
      if ((kind && strcmp(kind, "vrf") == 0) ||
          (slave_kind && strcmp(slave_kind, "vrf") == 0))
        vrf_id = *(u_int32_t *)RTA_DATA(tb[IFLA_MASTER]);
      else
	vrf_id = VRF_DEFAULT;
    }

  /* Add interface. */
  ifp = if_get_by_name_vrf (name, vrf_id);
  set_ifindex(ifp, ifi->ifi_index);
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

/* Lookup interface IPv4/IPv6 address. */
static int
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

  vrf_id_t vrf_id = ns_id;

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

  ifp = if_lookup_by_index_per_ns (zebra_ns_lookup (ns_id), ifa->ifa_index);
  if (ifp == NULL)
    {
      zlog_err ("netlink_interface_addr can't find interface by index %d vrf %u",
                ifa->ifa_index, vrf_id);
      return -1;
    }

  if (IS_ZEBRA_DEBUG_KERNEL)    /* remove this line to see initial ifcfg */
    {
      char buf[BUFSIZ];
      zlog_debug ("netlink_interface_addr %s %s vrf %u flags 0x%x:",
                 lookup (nlmsg_str, h->nlmsg_type), ifp->name,
                 vrf_id, ifa->ifa_flags);
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

/* Looking up routing table by netlink interface. */
static int
netlink_routing_table (struct sockaddr_nl *snl, struct nlmsghdr *h,
    vrf_id_t vrf_id)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb[RTA_MAX + 1];
  u_char flags = 0;
  struct prefix p;

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

static const struct message rtproto_str[] = {
  {RTPROT_REDIRECT, "redirect"},
  {RTPROT_KERNEL,   "kernel"},
  {RTPROT_BOOT,     "boot"},
  {RTPROT_STATIC,   "static"},
  {RTPROT_GATED,    "GateD"},
  {RTPROT_RA,       "router advertisement"},
  {RTPROT_MRT,      "MRT"},
  {RTPROT_ZEBRA,    "Zebra"},
#ifdef RTPROT_BIRD
  {RTPROT_BIRD,     "BIRD"},
#endif /* RTPROT_BIRD */
  {0,               NULL}
};

/* Routing information change from the kernel. */
static int
netlink_route_change (struct sockaddr_nl *snl, struct nlmsghdr *h,
                      ns_id_t ns_id)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb[RTA_MAX + 1];
  u_char zebra_flags = 0;
  struct prefix p;
  
  char anyaddr[16] = { 0 };

  int index;
  int table;
  int metric;
  u_int32_t mtu = 0;

  void *dest;
  void *gate;
  void *src;

  vrf_id_t vrf_id = ns_id;

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
               h->nlmsg_type ==
               RTM_NEWROUTE ? "RTM_NEWROUTE" : "RTM_DELROUTE",
               rtm->rtm_family == AF_INET ? "ipv4" : "ipv6",
               rtm->rtm_type == RTN_UNICAST ? "unicast" : "multicast",
               lookup (rtproto_str, rtm->rtm_protocol),
               vrf_id);

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
      zlog_warn ("netlink_route_change(): no src len, vrf %u", vrf_id);
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

static int
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

  vrf_id_t vrf_id = ns_id;

  ifi = NLMSG_DATA (h);

  if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK))
    {
      /* If this is not link add/delete message so print warning. */
      zlog_warn ("netlink_link_change: wrong kernel message %d vrf %u\n",
                 h->nlmsg_type, vrf_id);
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
        zlog_debug ("%s: ignoring IFLA_WIRELESS message, vrf %u", __func__,
                    vrf_id);
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
  ifp = if_lookup_by_index_per_ns (zebra_ns_lookup (NS_DEFAULT), ifi->ifi_index);

  if (h->nlmsg_type == RTM_NEWLINK)
    {
      if (tb[IFLA_MASTER])
	{
          if ((kind && strcmp(kind, "vrf") == 0) ||
              (slave_kind && strcmp(slave_kind, "vrf") == 0))
            vrf_id = *(u_int32_t *)RTA_DATA(tb[IFLA_MASTER]);
	  else
	    vrf_id = VRF_DEFAULT;
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
          set_ifindex(ifp, ifi->ifi_index);
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

          set_ifindex(ifp, ifi->ifi_index);
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

static int
netlink_information_fetch (struct sockaddr_nl *snl, struct nlmsghdr *h,
    ns_id_t ns_id)
{
  /* JF: Ignore messages that aren't from the kernel */
  if ( snl->nl_pid != 0 )
    {
      zlog ( NULL, LOG_ERR, "Ignoring message from pid %u", snl->nl_pid );
      return 0;
    }

  switch (h->nlmsg_type)
    {
    case RTM_NEWROUTE:
      return netlink_route_change (snl, h, ns_id);
      break;
    case RTM_DELROUTE:
      return netlink_route_change (snl, h, ns_id);
      break;
    case RTM_NEWLINK:
      return netlink_link_change (snl, h, ns_id);
      break;
    case RTM_DELLINK:
      return netlink_link_change (snl, h, ns_id);
      break;
    case RTM_NEWADDR:
      return netlink_interface_addr (snl, h, ns_id);
      break;
    case RTM_DELADDR:
      return netlink_interface_addr (snl, h, ns_id);
      break;
    default:
      zlog_warn ("Unknown netlink nlmsg_type %d vrf %u\n", h->nlmsg_type,
                 ns_id);
      break;
    }
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

/* Utility function  comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int
addattr_l (struct nlmsghdr *n, unsigned int maxlen, int type, void *data, int alen)
{
  int len;
  struct rtattr *rta;

  len = RTA_LENGTH (alen);

  if (NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len) > maxlen)
    return -1;

  rta = (struct rtattr *) (((char *) n) + NLMSG_ALIGN (n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA (rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len);

  return 0;
}

int
rta_addattr_l (struct rtattr *rta, int maxlen, int type, void *data, int alen)
{
  int len;
  struct rtattr *subrta;

  len = RTA_LENGTH (alen);

  if (RTA_ALIGN (rta->rta_len) + RTA_ALIGN (len) > maxlen)
    return -1;

  subrta = (struct rtattr *) (((char *) rta) + RTA_ALIGN (rta->rta_len));
  subrta->rta_type = type;
  subrta->rta_len = len;
  memcpy (RTA_DATA (subrta), data, alen);
  rta->rta_len = NLMSG_ALIGN (rta->rta_len) + RTA_ALIGN (len);

  return 0;
}

/* Utility function comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int
addattr32 (struct nlmsghdr *n, unsigned int maxlen, int type, int data)
{
  return addattr_l(n, maxlen, type, &data, sizeof(u_int32_t));
}

/* Some more utility functions from iproute2 */
static struct rtattr *
addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
  struct rtattr *nest = NLMSG_TAIL(n);

  addattr_l(n, maxlen, type, NULL, 0);
  return nest;
}

static int
addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
  nest->rta_len = (u_char *)NLMSG_TAIL(n) - (u_char *)nest;
  return n->nlmsg_len;
}

static struct rtattr *
rta_nest(struct rtattr *rta, int maxlen, int type)
{
  struct rtattr *nest = RTA_TAIL(rta);

  rta_addattr_l(rta, maxlen, type, NULL, 0);
  return nest;
}

static int
rta_nest_end(struct rtattr *rta, struct rtattr *nest)
{
  nest->rta_len = (u_char *)RTA_TAIL(rta) - (u_char *)nest;
  return rta->rta_len;
}

static int
netlink_talk_filter (struct sockaddr_nl *snl, struct nlmsghdr *h,
    ns_id_t ns_id)
{
  zlog_warn ("netlink_talk: ignoring message type 0x%04x NS %u", h->nlmsg_type,
             ns_id);
  return 0;
}

/* sendmsg() to netlink socket then recvmsg(). */
static int
netlink_talk (struct nlmsghdr *n, struct nlsock *nl, struct zebra_ns *zns)
{
  int status;
  struct sockaddr_nl snl;
  struct iovec iov = {
    .iov_base = (void *) n,
    .iov_len = n->nlmsg_len
  };
  struct msghdr msg = {
    .msg_name = (void *) &snl,
    .msg_namelen = sizeof snl,
    .msg_iov = &iov,
    .msg_iovlen = 1,
  };
  int save_errno;

  memset (&snl, 0, sizeof snl);
  snl.nl_family = AF_NETLINK;

  n->nlmsg_seq = ++nl->seq;

  /* Request an acknowledgement by setting NLM_F_ACK */
  n->nlmsg_flags |= NLM_F_ACK;

  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_debug ("netlink_talk: %s type %s(%u), len=%d seq=%u flags 0x%x",
               nl->name,
               lookup (nlmsg_str, n->nlmsg_type), n->nlmsg_type,
               n->nlmsg_len, n->nlmsg_seq, n->nlmsg_flags);

  /* Send message to netlink interface. */
  if (zserv_privs.change (ZPRIVS_RAISE))
    zlog (NULL, LOG_ERR, "Can't raise privileges");
  status = sendmsg (nl->sock, &msg, 0);
  save_errno = errno;
  if (zserv_privs.change (ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
    {
      zlog_debug("%s: >> netlink message dump [sent]", __func__);
      zlog_hexdump(&msg, sizeof(msg));
    }

  if (status < 0)
    {
      zlog (NULL, LOG_ERR, "netlink_talk sendmsg() error: %s",
            safe_strerror (save_errno));
      return -1;
    }


  /* 
   * Get reply from netlink socket. 
   * The reply should either be an acknowlegement or an error.
   */
  return netlink_parse_info (netlink_talk_filter, nl, zns, 0);
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
		  lookup (nlmsg_str, cmd),
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
                routedesc, lookup (nlmsg_str, cmd), label);
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

extern struct thread_master *master;

/* Kernel route reflection. */
static int
kernel_read (struct thread *thread)
{
  struct zebra_ns *zns = (struct zebra_ns *)THREAD_ARG (thread);
  netlink_parse_info (netlink_information_fetch, &zns->netlink, zns, 5);
  zns->t_netlink = thread_add_read (zebrad.master, kernel_read, zns,
                                     zns->netlink.sock);

  return 0;
}

/* Filter out messages from self that occur on listener socket,
   caused by our actions on the command socket
 */
static void netlink_install_filter (int sock, __u32 pid)
{
  struct sock_filter filter[] = {
    /* 0: ldh [4]	          */
    BPF_STMT(BPF_LD|BPF_ABS|BPF_H, offsetof(struct nlmsghdr, nlmsg_type)),
    /* 1: jeq 0x18 jt 3 jf 6  */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(RTM_NEWROUTE), 1, 0),
    /* 2: jeq 0x19 jt 3 jf 6  */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(RTM_DELROUTE), 0, 3),
    /* 3: ldw [12]		  */
    BPF_STMT(BPF_LD|BPF_ABS|BPF_W, offsetof(struct nlmsghdr, nlmsg_pid)),
    /* 4: jeq XX  jt 5 jf 6   */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htonl(pid), 0, 1),
    /* 5: ret 0    (skip)     */
    BPF_STMT(BPF_RET|BPF_K, 0),
    /* 6: ret 0xffff (keep)   */
    BPF_STMT(BPF_RET|BPF_K, 0xffff),
  };

  struct sock_fprog prog = {
    .len = array_size(filter),
    .filter = filter,
  };

  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
    zlog_warn ("Can't install socket filter: %s\n", safe_strerror(errno));
}

/* Exported interface function.  This function simply calls
   netlink_socket (). */
void
kernel_init (struct zebra_ns *zns)
{
  unsigned long groups;

  groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR;
#ifdef HAVE_IPV6
  groups |= RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
#endif /* HAVE_IPV6 */
  netlink_socket (&zns->netlink, groups, zns->ns_id);
  netlink_socket (&zns->netlink_cmd, 0, zns->ns_id);

  /* Register kernel socket. */
  if (zns->netlink.sock > 0)
    {
      /* Only want non-blocking on the netlink event socket */
      if (fcntl (zns->netlink.sock, F_SETFL, O_NONBLOCK) < 0)
        zlog_err ("Can't set %s socket flags: %s", zns->netlink.name,
                  safe_strerror (errno));

      /* Set receive buffer size if it's set from command line */
      if (nl_rcvbufsize)
        netlink_recvbuf (&zns->netlink, nl_rcvbufsize);

      netlink_install_filter (zns->netlink.sock, zns->netlink_cmd.snl.nl_pid);
      zns->t_netlink = thread_add_read (zebrad.master, kernel_read, zns,
                                         zns->netlink.sock);
    }
}

void
kernel_terminate (struct zebra_ns *zns)
{
  THREAD_READ_OFF (zns->t_netlink);

  if (zns->netlink.sock >= 0)
    {
      close (zns->netlink.sock);
      zns->netlink.sock = -1;
    }

  if (zns->netlink_cmd.sock >= 0)
    {
      close (zns->netlink_cmd.sock);
      zns->netlink_cmd.sock = -1;
    }
}

/*
 * nl_msg_type_to_str
 */
const char *
nl_msg_type_to_str (uint16_t msg_type)
{
  return lookup (nlmsg_str, msg_type);
}

/*
 * nl_rtproto_to_str
 */
const char *
nl_rtproto_to_str (u_char rtproto)
{
  return lookup (rtproto_str, rtproto);
}
