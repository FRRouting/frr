/* Zebra daemon server routine.
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include <zebra.h>

#include "prefix.h"
#include "command.h"
#include "if.h"
#include "thread.h"
#include "stream.h"
#include "memory.h"
#include "table.h"
#include "rib.h"
#include "network.h"
#include "sockunion.h"
#include "log.h"
#include "zclient.h"
#include "privs.h"

#include "zebra/zserv.h"
#include "zebra/router-id.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/ipforward.h"

/* Event list of zebra. */
enum event { ZEBRA_SERV, ZEBRA_READ, ZEBRA_WRITE };

extern struct zebra_t zebrad;

static void zebra_event (enum event event, int sock, struct zserv *client);

extern struct zebra_privs_t zserv_privs;

/* For logging of zebra meesages. */
static const char *zebra_command_str [] =
{
  "NULL",
  "ZEBRA_INTERFACE_ADD",
  "ZEBRA_INTERFACE_DELETE",
  "ZEBRA_INTERFACE_ADDRESS_ADD",
  "ZEBRA_INTERFACE_ADDRESS_DELETE",
  "ZEBRA_INTERFACE_UP",
  "ZEBRA_INTERFACE_DOWN",
  "ZEBRA_IPV4_ROUTE_ADD",
  "ZEBRA_IPV4_ROUTE_DELETE",
  "ZEBRA_IPV6_ROUTE_ADD",
  "ZEBRA_IPV6_ROUTE_DELETE",
  "ZEBRA_REDISTRIBUTE_ADD",
  "ZEBRA_REDISTRIBUTE_DELETE",
  "ZEBRA_REDISTRIBUTE_DEFAULT_ADD",
  "ZEBRA_REDISTRIBUTE_DEFAULT_DELETE",
  "ZEBRA_IPV4_NEXTHOP_LOOKUP",
  "ZEBRA_IPV6_NEXTHOP_LOOKUP",
  "ZEBRA_IPV4_IMPORT_LOOKUP",
  "ZEBRA_IPV6_IMPORT_LOOKUP",
  "ZEBRA_ROUTER_ID_ADD",
  "ZEBRA_ROUTER_ID_DELETE",
  "ZEBRA_ROUTER_ID_UPDATE"
};

struct zebra_message_queue
{
  struct nsm_message_queue *next;
  struct nsm_message_queue *prev;

  u_char *buf;
  u_int16_t length;
  u_int16_t written;
};

struct thread *t_write;
struct fifo message_queue;

int
zebra_server_dequeue (struct thread *t)
{
  int sock;
  int nbytes;
  struct zebra_message_queue *queue;

  sock = THREAD_FD (t);
  t_write = NULL;

  queue = (struct zebra_message_queue *) FIFO_HEAD (&message_queue);
  if (queue)
    {
      nbytes = write (sock, queue->buf + queue->written,
		      queue->length - queue->written);

      if (nbytes <= 0)
        {
          if (errno != EAGAIN)
	    return -1;
        }
      else if (nbytes != (queue->length - queue->written))
	{
	  queue->written += nbytes;
	}
      else
        {
          FIFO_DEL (queue);
          XFREE (MTYPE_TMP, queue->buf);
          XFREE (MTYPE_TMP, queue);
        }
    }

  if (FIFO_TOP (&message_queue))
    THREAD_WRITE_ON (zebrad.master, t_write, zebra_server_dequeue, 
                     NULL, sock);

  return 0;
}

/* Enqueu message.  */
void
zebra_server_enqueue (int sock, u_char *buf, unsigned long length,
		      unsigned long written)
{
  struct zebra_message_queue *queue;

  queue = XCALLOC (MTYPE_TMP, sizeof (struct zebra_message_queue));
  queue->buf = XMALLOC (MTYPE_TMP, length);
  memcpy (queue->buf, buf, length);
  queue->length = length;
  queue->written = written;

  FIFO_ADD (&message_queue, queue);

  THREAD_WRITE_ON (zebrad.master, t_write, zebra_server_dequeue, NULL, sock);
}

int
zebra_server_send_message (int sock, u_char *buf, unsigned long length)
{
  int nbytes;

  if (FIFO_TOP (&message_queue))
    {
      zebra_server_enqueue (sock, buf, length, 0);
      return 0;
    }

  /* Send message.  */
  nbytes = write (sock, buf, length);

  if (nbytes <= 0)
    {
      if (errno == EAGAIN)
        zebra_server_enqueue (sock, buf, length, 0);
      else
	return -1;
    }
  /* It's clear that nbytes is positive at this point. */
  else if ((unsigned) nbytes != length)
    zebra_server_enqueue (sock, buf, length, nbytes);

  return 0;
}

/* Interface is added. Send ZEBRA_INTERFACE_ADD to client. */
/*
 * This function is called in the following situations:
 * - in response to a 3-byte ZEBRA_INTERFACE_ADD request
 *   from the client.
 * - at startup, when zebra figures out the available interfaces
 * - when an interface is added (where support for
 *   RTM_IFANNOUNCE or AF_NETLINK sockets is available), or when
 *   an interface is marked IFF_UP (i.e., an RTM_IFINFO message is
 *   received)
 */
int
zsend_interface_add (struct zserv *client, struct interface *ifp)
{
  struct stream *s;

  /* Check this client need interface information. */
  if (! client->ifinfo)
    return -1;

  s = client->obuf;
  stream_reset (s);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Message type. */
  stream_putc (s, ZEBRA_INTERFACE_ADD);

  /* Interface information. */
  stream_put (s, ifp->name, INTERFACE_NAMSIZ);
  stream_putl (s, ifp->ifindex);
  stream_putc (s, ifp->status);
  stream_putl (s, ifp->flags);
  stream_putl (s, ifp->metric);
  stream_putl (s, ifp->mtu);
  stream_putl (s, ifp->mtu6);
  stream_putl (s, ifp->bandwidth);
#ifdef HAVE_SOCKADDR_DL
  stream_put (s, &ifp->sdl, sizeof (ifp->sdl));
#else
  stream_putl (s, ifp->hw_addr_len);
  if (ifp->hw_addr_len)
    stream_put (s, ifp->hw_addr, ifp->hw_addr_len);
#endif /* HAVE_SOCKADDR_DL */

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  zebra_server_send_message (client->sock, s->data, stream_get_endp (s));

  return 0;
}

/* Interface deletion from zebra daemon. */
/*
 * This function is only called  when support for 
 * RTM_IFANNOUNCE or AF_NETLINK sockets (RTM_DELLINK message)
 * is available. It is not called on Solaris.
 */
#if (defined(RTM_IFANNOUNCE) || defined(HAVE_NETLINK))
int
zsend_interface_delete (struct zserv *client, struct interface *ifp)
{
  struct stream *s;

  /* Check this client need interface information. */
  if (! client->ifinfo)
    return -1;

  s = client->obuf;
  stream_reset (s);

  /* Packet length placeholder. */
  stream_putw (s, 0);

  /* Interface information. */
  stream_putc (s, ZEBRA_INTERFACE_DELETE);
  stream_put (s, ifp->name, INTERFACE_NAMSIZ);
  stream_putl (s, ifp->ifindex);
  stream_putc (s, ifp->status);
  stream_putl (s, ifp->flags);
  stream_putl (s, ifp->metric);
  stream_putl (s, ifp->mtu);
  stream_putl (s, ifp->mtu6);
  stream_putl (s, ifp->bandwidth);

  /* Write packet length. */
  stream_putw_at (s, 0, stream_get_endp (s));

  zebra_server_send_message (client->sock, s->data, stream_get_endp (s));

  return 0;
}
#endif /* (defined(RTM_IFANNOUNCE) || defined(HAVE_LINUX_RTNETLINK_H)) */

/* Interface address is added/deleted. Send ZEBRA_INTERFACE_ADDRESS_ADD or
 * ZEBRA_INTERFACE_ADDRESS_DELETE to the client. 
 *
 * A ZEBRA_INTERFACE_ADDRESS_ADD is sent in the following situations:
 * - in response to a 3-byte ZEBRA_INTERFACE_ADD request
 *   from the client, after the ZEBRA_INTERFACE_ADD has been
 *   sent from zebra to the client
 * - redistribute new address info to all clients in the following situations
 *    - at startup, when zebra figures out the available interfaces
 *    - when an interface is added (where support for
 *      RTM_IFANNOUNCE or AF_NETLINK sockets is available), or when
 *      an interface is marked IFF_UP (i.e., an RTM_IFINFO message is
 *      received)
 *    - for the vty commands "ip address A.B.C.D/M [<secondary>|<label LINE>]"
 *      and "no bandwidth <1-10000000>", "ipv6 address X:X::X:X/M"
 *    - when an RTM_NEWADDR message is received from the kernel,
 * 
 * The call tree that triggers ZEBRA_INTERFACE_ADDRESS_DELETE: 
 *
 *                   zsend_interface_address(DELETE)
 *                           ^                         
 *                           |                        
 *          zebra_interface_address_delete_update    
 *             ^                        ^      ^
 *             |                        |      if_delete_update (not called on 
 *             |                        |                         Solaris)
 *         ip_address_uninstall        connected_delete_ipv4
 *         [ipv6_addresss_uninstall]   [connected_delete_ipv6]
 *             ^                        ^
 *             |                        |
 *             |                  RTM_NEWADDR on routing/netlink socket
 *             |
 *         vty commands:
 *     "no ip address A.B.C.D/M [label LINE]"
 *     "no ip address A.B.C.D/M secondary"
 *     ["no ipv6 address X:X::X:X/M"]
 *
 */
int
zsend_interface_address (int cmd, struct zserv *client, 
                         struct interface *ifp, struct connected *ifc)
{
  int blen;
  struct stream *s;
  struct prefix *p;

  /* Check this client need interface information. */
  if (! client->ifinfo)
    return -1;

  s = client->obuf;
  stream_reset (s);

  /* Place holder for size. */
  stream_putw (s, 0);

  stream_putc (s, cmd);
  stream_putl (s, ifp->ifindex);

  /* Interface address flag. */
  stream_putc (s, ifc->flags);

  /* Prefix information. */
  p = ifc->address;
  stream_putc (s, p->family);
  blen = prefix_blen (p);
  stream_put (s, &p->u.prefix, blen);

  /* 
   * XXX gnu version does not send prefixlen for ZEBRA_INTERFACE_ADDRESS_DELETE
   * but zebra_interface_address_delete_read() in the gnu version 
   * expects to find it
   */
  stream_putc (s, p->prefixlen);

  /* Destination. */
  p = ifc->destination;
  if (p)
    stream_put (s, &p->u.prefix, blen);
  else
    stream_put (s, NULL, blen);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  zebra_server_send_message (client->sock, s->data, stream_get_endp (s));

  return 0;
}

/*
 * The cmd passed to zsend_interface_update  may be ZEBRA_INTERFACE_UP or
 * ZEBRA_INTERFACE_DOWN.
 *
 * The ZEBRA_INTERFACE_UP message is sent from the zebra server to
 * the clients in one of 2 situations:
 *   - an if_up is detected e.g., as a result of an RTM_IFINFO message
 *   - a vty command modifying the bandwidth of an interface is received.
 * The ZEBRA_INTERFACE_DOWN message is sent when an if_down is detected.
 */
int
zsend_interface_update (int cmd, struct zserv *client, struct interface *ifp)
{
  struct stream *s;

  /* Check this client need interface information. */
  if (! client->ifinfo)
    return -1;

  s = client->obuf;
  stream_reset (s);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Zebra command. */
  stream_putc (s, cmd);

  /* Interface information. */
  stream_put (s, ifp->name, INTERFACE_NAMSIZ);
  stream_putl (s, ifp->ifindex);
  stream_putc (s, ifp->status);
  stream_putl (s, ifp->flags);
  stream_putl (s, ifp->metric);
  stream_putl (s, ifp->mtu);
  stream_putl (s, ifp->mtu6);
  stream_putl (s, ifp->bandwidth);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  zebra_server_send_message (client->sock, s->data, stream_get_endp (s));

  return 0;
}

/*
 * The zebra server sends the clients  a ZEBRA_IPV4_ROUTE_ADD or a
 * ZEBRA_IPV6_ROUTE_ADD via zsend_route_multipath in the following
 * situations:
 * - when the client starts up, and requests default information
 *   by sending a ZEBRA_REDISTRIBUTE_DEFAULT_ADD to the zebra server, in the
 * - case of rip, ripngd, ospfd and ospf6d, when the client sends a
 *   ZEBRA_REDISTRIBUTE_ADD as a result of the "redistribute" vty cmd,
 * - when the zebra server redistributes routes after it updates its rib
 *
 * The zebra server sends clients a ZEBRA_IPV4_ROUTE_DELETE or a
 * ZEBRA_IPV6_ROUTE_DELETE via zsend_route_multipath when:
 * - a "ip route"  or "ipv6 route" vty command is issued, a prefix is
 * - deleted from zebra's rib, and this info
 *   has to be redistributed to the clients 
 * 
 * XXX The ZEBRA_IPV*_ROUTE_ADD message is also sent by the client to the
 * zebra server when the client wants to tell the zebra server to add a
 * route to the kernel (zapi_ipv4_add etc. ).  Since it's essentially the
 * same message being sent back and forth, this function and
 * zapi_ipv{4,6}_{add, delete} should be re-written to avoid code
 * duplication.
 */
int
zsend_route_multipath (int cmd, struct zserv *client, struct prefix *p,
                       struct rib *rib)
{
  int psize;
  struct stream *s;
  struct nexthop *nexthop;
  unsigned long nhnummark = 0;
  int nhnum = 0;
  u_char zapi_flags = ZAPI_MESSAGE_NEXTHOP | ZAPI_MESSAGE_IFINDEX;
  
  s = client->obuf;
  stream_reset (s);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Put command, type and nexthop. */
  stream_putc (s, cmd);
  stream_putc (s, rib->type);
  stream_putc (s, rib->flags);

  /* 
   * XXX no need to set ZAPI_MESSAGE_NEXTHOP if we are going to
   * send empty nexthop?
   */
  if (cmd == ZEBRA_IPV4_ROUTE_ADD || ZEBRA_IPV6_ROUTE_ADD)
    zapi_flags |= ZAPI_MESSAGE_METRIC;

  stream_putc (s, zapi_flags);

  /* Prefix. */
  psize = PSIZE (p->prefixlen);
  stream_putc (s, p->prefixlen);
  stream_write (s, (u_char *) & p->u.prefix, psize);

  /* 
   * XXX The message format sent by zebra below does not match the format
   * of the corresponding message expected by the zebra server
   * itself (e.g., see zread_ipv4_add). The nexthop_num is not set correctly,
   * (is there a bug on the client side if more than one segment is sent?)
   * nexthop ZEBRA_NEXTHOP_IPV4 is never set, ZEBRA_NEXTHOP_IFINDEX 
   * is hard-coded.
   */
  /* Nexthop */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
        {
          nhnummark = stream_get_putp (s);
          stream_putc (s, 1); /* placeholder */
          nhnum++;

          switch(nexthop->type) 
            {
              case NEXTHOP_TYPE_IPV4:
              case NEXTHOP_TYPE_IPV4_IFINDEX:
                stream_put_in_addr (s, &nexthop->gate.ipv4);
                break;
#ifdef HAVE_IPV6
              case NEXTHOP_TYPE_IPV6:
              case NEXTHOP_TYPE_IPV6_IFINDEX:
              case NEXTHOP_TYPE_IPV6_IFNAME:
                stream_write (s, (u_char *) &nexthop->gate.ipv6, 16);
                break;
#endif
              default:
                if (cmd == ZEBRA_IPV4_ROUTE_ADD 
                    || cmd == ZEBRA_IPV4_ROUTE_DELETE)
                  {
                    struct in_addr empty;
                    memset (&empty, 0, sizeof (struct in_addr));
                    stream_write (s, (u_char *) &empty, IPV4_MAX_BYTELEN);
                  }
                else
                  {
                    struct in6_addr empty;
                    memset (&empty, 0, sizeof (struct in6_addr));
                    stream_write (s, (u_char *) &empty, IPV6_MAX_BYTELEN);
                  }
              }

          /* Interface index. */
          stream_putc (s, 1);
          stream_putl (s, nexthop->ifindex);

          break;
        }
    }

  /* Metric */
  stream_putl (s, rib->metric);

  /* Write next-hop number */
  if (nhnummark)
    stream_putc_at (s, nhnummark, nhnum);
  
  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  zebra_server_send_message (client->sock, s->data, stream_get_endp (s));

  return 0;
}

#ifdef HAVE_IPV6
int
zsend_ipv6_nexthop_lookup (struct zserv *client, struct in6_addr *addr)
{
  struct stream *s;
  struct rib *rib;
  unsigned long nump;
  u_char num;
  struct nexthop *nexthop;

  /* Lookup nexthop. */
  rib = rib_match_ipv6 (addr);

  /* Get output stream. */
  s = client->obuf;
  stream_reset (s);

  /* Fill in result. */
  stream_putw (s, 0);
  stream_putc (s, ZEBRA_IPV6_NEXTHOP_LOOKUP);
  stream_put (s, &addr, 16);

  if (rib)
    {
      stream_putl (s, rib->metric);
      num = 0;
      nump = s->putp;
      stream_putc (s, 0);
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
	  {
	    stream_putc (s, nexthop->type);
	    switch (nexthop->type)
	      {
	      case ZEBRA_NEXTHOP_IPV6:
		stream_put (s, &nexthop->gate.ipv6, 16);
		break;
	      case ZEBRA_NEXTHOP_IPV6_IFINDEX:
	      case ZEBRA_NEXTHOP_IPV6_IFNAME:
		stream_put (s, &nexthop->gate.ipv6, 16);
		stream_putl (s, nexthop->ifindex);
		break;
	      case ZEBRA_NEXTHOP_IFINDEX:
	      case ZEBRA_NEXTHOP_IFNAME:
		stream_putl (s, nexthop->ifindex);
		break;
	      default:
                /* do nothing */
		break;
	      }
	    num++;
	  }
      stream_putc_at (s, nump, num);
    }
  else
    {
      stream_putl (s, 0);
      stream_putc (s, 0);
    }

  stream_putw_at (s, 0, stream_get_endp (s));
  
  zebra_server_send_message (client->sock, s->data, stream_get_endp (s));

  return 0;
}
#endif /* HAVE_IPV6 */

static int
zsend_ipv4_nexthop_lookup (struct zserv *client, struct in_addr addr)
{
  struct stream *s;
  struct rib *rib;
  unsigned long nump;
  u_char num;
  struct nexthop *nexthop;

  /* Lookup nexthop. */
  rib = rib_match_ipv4 (addr);

  /* Get output stream. */
  s = client->obuf;
  stream_reset (s);

  /* Fill in result. */
  stream_putw (s, 0);
  stream_putc (s, ZEBRA_IPV4_NEXTHOP_LOOKUP);
  stream_put_in_addr (s, &addr);

  if (rib)
    {
      stream_putl (s, rib->metric);
      num = 0;
      nump = s->putp;
      stream_putc (s, 0);
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
	  {
	    stream_putc (s, nexthop->type);
	    switch (nexthop->type)
	      {
	      case ZEBRA_NEXTHOP_IPV4:
		stream_put_in_addr (s, &nexthop->gate.ipv4);
		break;
	      case ZEBRA_NEXTHOP_IFINDEX:
	      case ZEBRA_NEXTHOP_IFNAME:
		stream_putl (s, nexthop->ifindex);
		break;
	      default:
                /* do nothing */
		break;
	      }
	    num++;
	  }
      stream_putc_at (s, nump, num);
    }
  else
    {
      stream_putl (s, 0);
      stream_putc (s, 0);
    }

  stream_putw_at (s, 0, stream_get_endp (s));
  
  zebra_server_send_message (client->sock, s->data, stream_get_endp (s));

  return 0;
}

static int
zsend_ipv4_import_lookup (struct zserv *client, struct prefix_ipv4 *p)
{
  struct stream *s;
  struct rib *rib;
  unsigned long nump;
  u_char num;
  struct nexthop *nexthop;

  /* Lookup nexthop. */
  rib = rib_lookup_ipv4 (p);

  /* Get output stream. */
  s = client->obuf;
  stream_reset (s);

  /* Fill in result. */
  stream_putw (s, 0);
  stream_putc (s, ZEBRA_IPV4_IMPORT_LOOKUP);
  stream_put_in_addr (s, &p->prefix);

  if (rib)
    {
      stream_putl (s, rib->metric);
      num = 0;
      nump = s->putp;
      stream_putc (s, 0);
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
	  {
	    stream_putc (s, nexthop->type);
	    switch (nexthop->type)
	      {
	      case ZEBRA_NEXTHOP_IPV4:
		stream_put_in_addr (s, &nexthop->gate.ipv4);
		break;
	      case ZEBRA_NEXTHOP_IFINDEX:
	      case ZEBRA_NEXTHOP_IFNAME:
		stream_putl (s, nexthop->ifindex);
		break;
	      default:
                /* do nothing */
		break;
	      }
	    num++;
	  }
      stream_putc_at (s, nump, num);
    }
  else
    {
      stream_putl (s, 0);
      stream_putc (s, 0);
    }

  stream_putw_at (s, 0, stream_get_endp (s));
  
  zebra_server_send_message (client->sock, s->data, stream_get_endp (s));

  return 0;
}

/* Router-id is updated. Send ZEBRA_ROUTER_ID_ADD to client. */
int
zsend_router_id_update (struct zserv *client, struct prefix *p)
{
  struct stream *s;
  int blen;

  /* Check this client need interface information. */
  if (!client->ridinfo)
    return -1;

  s = client->obuf;
  stream_reset (s);

  /* Place holder for size. */
  stream_putw (s, 0);

  /* Message type. */
  stream_putc (s, ZEBRA_ROUTER_ID_UPDATE);

  /* Prefix information. */
  stream_putc (s, p->family);
  blen = prefix_blen (p);
  stream_put (s, &p->u.prefix, blen);
  stream_putc (s, p->prefixlen);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  return writen (client->sock, s->data, stream_get_endp (s));
}

/* Register zebra server interface information.  Send current all
   interface and address information. */
static void
zread_interface_add (struct zserv *client, u_short length)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *c;

  /* Interface information is needed. */
  client->ifinfo = 1;

  for (ifnode = listhead (iflist); ifnode; ifnode = nextnode (ifnode))
    {
      ifp = getdata (ifnode);

      /* Skip pseudo interface. */
      if (! CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
	continue;

      zsend_interface_add (client, ifp);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  c = getdata (cnode);
	  if (CHECK_FLAG (c->conf, ZEBRA_IFC_REAL))
	    zsend_interface_address (ZEBRA_INTERFACE_ADDRESS_ADD, client, 
				     ifp, c);
	}
    }
}

/* Unregister zebra server interface information. */
static void
zread_interface_delete (struct zserv *client, u_short length)
{
  client->ifinfo = 0;
}

/* This function support multiple nexthop. */
/* 
 * Parse the ZEBRA_IPV4_ROUTE_ADD sent from client. Update rib and
 * add kernel route. 
 */
static void
zread_ipv4_add (struct zserv *client, u_short length)
{
  int i;
  struct rib *rib;
  struct prefix_ipv4 p;
  u_char message;
  struct in_addr nexthop;
  u_char nexthop_num;
  u_char nexthop_type;
  struct stream *s;
  unsigned int ifindex;
  u_char ifname_len;

  /* Get input stream.  */
  s = client->ibuf;

  /* Allocate new rib. */
  rib = XMALLOC (MTYPE_RIB, sizeof (struct rib));
  memset (rib, 0, sizeof (struct rib));

  /* Type, flags, message. */
  rib->type = stream_getc (s);
  rib->flags = stream_getc (s);
  message = stream_getc (s); 
  rib->uptime = time (NULL);

  /* IPv4 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop parse. */
  if (CHECK_FLAG (message, ZAPI_MESSAGE_NEXTHOP))
    {
      nexthop_num = stream_getc (s);

      for (i = 0; i < nexthop_num; i++)
	{
	  nexthop_type = stream_getc (s);

	  switch (nexthop_type)
	    {
	    case ZEBRA_NEXTHOP_IFINDEX:
	      ifindex = stream_getl (s);
	      nexthop_ifindex_add (rib, ifindex);
	      break;
	    case ZEBRA_NEXTHOP_IFNAME:
	      ifname_len = stream_getc (s);
	      stream_forward (s, ifname_len);
	      break;
	    case ZEBRA_NEXTHOP_IPV4:
	      nexthop.s_addr = stream_get_ipv4 (s);
	      nexthop_ipv4_add (rib, &nexthop);
	      break;
	    case ZEBRA_NEXTHOP_IPV6:
	      stream_forward (s, IPV6_MAX_BYTELEN);
	      break;
      case ZEBRA_NEXTHOP_BLACKHOLE:
        nexthop_blackhole_add (rib);
        break;
	    }
	}
    }

  /* Distance. */
  if (CHECK_FLAG (message, ZAPI_MESSAGE_DISTANCE))
    rib->distance = stream_getc (s);

  /* Metric. */
  if (CHECK_FLAG (message, ZAPI_MESSAGE_METRIC))
    rib->metric = stream_getl (s);
    
  rib_add_ipv4_multipath (&p, rib);
}

/* Zebra server IPv4 prefix delete function. */
static void
zread_ipv4_delete (struct zserv *client, u_short length)
{
  int i;
  struct stream *s;
  struct zapi_ipv4 api;
  struct in_addr nexthop;
  unsigned long ifindex;
  struct prefix_ipv4 p;
  u_char nexthop_num;
  u_char nexthop_type;
  u_char ifname_len;
  
  s = client->ibuf;
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
      nexthop_num = stream_getc (s);

      for (i = 0; i < nexthop_num; i++)
	{
	  nexthop_type = stream_getc (s);

	  switch (nexthop_type)
	    {
	    case ZEBRA_NEXTHOP_IFINDEX:
	      ifindex = stream_getl (s);
	      break;
	    case ZEBRA_NEXTHOP_IFNAME:
	      ifname_len = stream_getc (s);
	      stream_forward (s, ifname_len);
	      break;
	    case ZEBRA_NEXTHOP_IPV4:
	      nexthop.s_addr = stream_get_ipv4 (s);
	      break;
	    case ZEBRA_NEXTHOP_IPV6:
	      stream_forward (s, IPV6_MAX_BYTELEN);
	      break;
	    }
	}
    }

  /* Distance. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  else
    api.distance = 0;

  /* Metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;
    
  rib_delete_ipv4 (api.type, api.flags, &p, &nexthop, ifindex,
		   client->rtm_table);
}

/* Nexthop lookup for IPv4. */
static void
zread_ipv4_nexthop_lookup (struct zserv *client, u_short length)
{
  struct in_addr addr;

  addr.s_addr = stream_get_ipv4 (client->ibuf);
  zsend_ipv4_nexthop_lookup (client, addr);
}

/* Nexthop lookup for IPv4. */
static void
zread_ipv4_import_lookup (struct zserv *client, u_short length)
{
  struct prefix_ipv4 p;

  p.family = AF_INET;
  p.prefixlen = stream_getc (client->ibuf);
  p.prefix.s_addr = stream_get_ipv4 (client->ibuf);

  zsend_ipv4_import_lookup (client, &p);
}

#ifdef HAVE_IPV6
/* Zebra server IPv6 prefix add function. */
static void
zread_ipv6_add (struct zserv *client, u_short length)
{
  int i;
  struct stream *s;
  struct zapi_ipv6 api;
  struct in6_addr nexthop;
  unsigned long ifindex;
  struct prefix_ipv6 p;
  
  s = client->ibuf;
  ifindex = 0;
  memset (&nexthop, 0, sizeof (struct in6_addr));

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv4 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      u_char nexthop_type;

      api.nexthop_num = stream_getc (s);
      for (i = 0; i < api.nexthop_num; i++)
	{
	  nexthop_type = stream_getc (s);

	  switch (nexthop_type)
	    {
	    case ZEBRA_NEXTHOP_IPV6:
	      stream_get (&nexthop, s, 16);
	      break;
	    case ZEBRA_NEXTHOP_IFINDEX:
	      ifindex = stream_getl (s);
	      break;
	    }
	}
    }

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  else
    api.distance = 0;

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;
    
  if (IN6_IS_ADDR_UNSPECIFIED (&nexthop))
    rib_add_ipv6 (api.type, api.flags, &p, NULL, ifindex, 0);
  else
    rib_add_ipv6 (api.type, api.flags, &p, &nexthop, ifindex, 0);
}

/* Zebra server IPv6 prefix delete function. */
static void
zread_ipv6_delete (struct zserv *client, u_short length)
{
  int i;
  struct stream *s;
  struct zapi_ipv6 api;
  struct in6_addr nexthop;
  unsigned long ifindex;
  struct prefix_ipv6 p;
  
  s = client->ibuf;
  ifindex = 0;
  memset (&nexthop, 0, sizeof (struct in6_addr));

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv4 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      u_char nexthop_type;

      api.nexthop_num = stream_getc (s);
      for (i = 0; i < api.nexthop_num; i++)
	{
	  nexthop_type = stream_getc (s);

	  switch (nexthop_type)
	    {
	    case ZEBRA_NEXTHOP_IPV6:
	      stream_get (&nexthop, s, 16);
	      break;
	    case ZEBRA_NEXTHOP_IFINDEX:
	      ifindex = stream_getl (s);
	      break;
	    }
	}
    }

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  else
    api.distance = 0;
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;
    
  if (IN6_IS_ADDR_UNSPECIFIED (&nexthop))
    rib_delete_ipv6 (api.type, api.flags, &p, NULL, ifindex, 0);
  else
    rib_delete_ipv6 (api.type, api.flags, &p, &nexthop, ifindex, 0);
}

void
zebra_read_ipv6 (int command, struct zserv *client, u_short length)
{
  u_char type;
  u_char flags;
  struct in6_addr nexthop, *gate;
  u_char *lim;
  u_char *pnt;
  unsigned int ifindex;

  pnt = stream_pnt (client->ibuf);
  lim = pnt + length;

  type = stream_getc (client->ibuf);
  flags = stream_getc (client->ibuf);
  stream_get (&nexthop, client->ibuf, sizeof (struct in6_addr));
  
  while (stream_pnt (client->ibuf) < lim)
    {
      int size;
      struct prefix_ipv6 p;
      
      ifindex = stream_getl (client->ibuf);

      memset (&p, 0, sizeof (struct prefix_ipv6));
      p.family = AF_INET6;
      p.prefixlen = stream_getc (client->ibuf);
      size = PSIZE(p.prefixlen);
      stream_get (&p.prefix, client->ibuf, size);

      if (IN6_IS_ADDR_UNSPECIFIED (&nexthop))
        gate = NULL;
      else
        gate = &nexthop;

      if (command == ZEBRA_IPV6_ROUTE_ADD)
        rib_add_ipv6 (type, flags, &p, gate, ifindex, 0);
      else
        rib_delete_ipv6 (type, flags, &p, gate, ifindex, 0);
    }
}

static void
zread_ipv6_nexthop_lookup (struct zserv *client, u_short length)
{
  struct in6_addr addr;
  char buf[BUFSIZ];

  stream_get (&addr, client->ibuf, 16);
  printf ("DEBUG %s\n", inet_ntop (AF_INET6, &addr, buf, BUFSIZ));

  zsend_ipv6_nexthop_lookup (client, &addr);
}
#endif /* HAVE_IPV6 */

/* Register zebra server router-id information.  Send current router-id */
void
zread_router_id_add (struct zserv *client, u_short length)
{
  struct prefix p;

  /* Router-id information is needed. */
  client->ridinfo = 1;

  router_id_get (&p);

  zsend_router_id_update (client,&p);
}

/* Unregister zebra server router-id information. */
void
zread_router_id_delete (struct zserv *client, u_short length)
{
  client->ridinfo = 0;
}

/* Close zebra client. */
static void
zebra_client_close (struct zserv *client)
{
  /* Close file descriptor. */
  if (client->sock)
    {
      close (client->sock);
      client->sock = -1;
    }

  /* Free stream buffers. */
  if (client->ibuf)
    stream_free (client->ibuf);
  if (client->obuf)
    stream_free (client->obuf);

  /* Release threads. */
  if (client->t_read)
    thread_cancel (client->t_read);
  if (client->t_write)
    thread_cancel (client->t_write);

  /* Free client structure. */
  listnode_delete (zebrad.client_list, client);
  XFREE (0, client);
}

/* Make new client. */
static void
zebra_client_create (int sock)
{
  struct zserv *client;

  client = XCALLOC (0, sizeof (struct zserv));

  /* Make client input/output buffer. */
  client->sock = sock;
  client->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  client->obuf = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Set table number. */
  client->rtm_table = zebrad.rtm_table_default;

  /* Add this client to linked list. */
  listnode_add (zebrad.client_list, client);
  
  /* Make new read thread. */
  zebra_event (ZEBRA_READ, sock, client);
}

/* Handler of zebra service request. */
static int
zebra_client_read (struct thread *thread)
{
  int sock;
  struct zserv *client;
  int nbyte;
  u_short length;
  u_char command;

  /* Get thread data.  Reset reading thread because I'm running. */
  sock = THREAD_FD (thread);
  client = THREAD_ARG (thread);
  client->t_read = NULL;

  /* Read length and command. */
  nbyte = stream_read (client->ibuf, sock, 3);
  if (nbyte <= 0) 
    {
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog_debug ("connection closed socket [%d]", sock);
      zebra_client_close (client);
      return -1;
    }
  length = stream_getw (client->ibuf);
  command = stream_getc (client->ibuf);

  if (length < 3) 
    {
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog_debug ("length %d is less than 3 ", length);
      zebra_client_close (client);
      return -1;
    }

  length -= 3;

  /* Read rest of data. */
  if (length)
    {
      nbyte = stream_read (client->ibuf, sock, length);
      if (nbyte <= 0) 
	{
	  if (IS_ZEBRA_DEBUG_EVENT)
	    zlog_debug ("connection closed [%d] when reading zebra data", sock);
	  zebra_client_close (client);
	  return -1;
	}
    }

  /* Debug packet information. */
  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("zebra message comes from socket [%d]", sock);

  if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
    zlog_debug ("zebra message received [%s] %d", 
	       zebra_command_str[command], length);

  switch (command) 
    {
    case ZEBRA_ROUTER_ID_ADD:
      zread_router_id_add (client, length);
      break;
    case ZEBRA_ROUTER_ID_DELETE:
      zread_router_id_delete (client, length);
      break;
    case ZEBRA_INTERFACE_ADD:
      zread_interface_add (client, length);
      break;
    case ZEBRA_INTERFACE_DELETE:
      zread_interface_delete (client, length);
      break;
    case ZEBRA_IPV4_ROUTE_ADD:
      zread_ipv4_add (client, length);
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      zread_ipv4_delete (client, length);
      break;
#ifdef HAVE_IPV6
    case ZEBRA_IPV6_ROUTE_ADD:
      zread_ipv6_add (client, length);
      break;
    case ZEBRA_IPV6_ROUTE_DELETE:
      zread_ipv6_delete (client, length);
      break;
#endif /* HAVE_IPV6 */
    case ZEBRA_REDISTRIBUTE_ADD:
      zebra_redistribute_add (command, client, length);
      break;
    case ZEBRA_REDISTRIBUTE_DELETE:
      zebra_redistribute_delete (command, client, length);
      break;
    case ZEBRA_REDISTRIBUTE_DEFAULT_ADD:
      zebra_redistribute_default_add (command, client, length);
      break;
    case ZEBRA_REDISTRIBUTE_DEFAULT_DELETE:
      zebra_redistribute_default_delete (command, client, length);
      break;
    case ZEBRA_IPV4_NEXTHOP_LOOKUP:
      zread_ipv4_nexthop_lookup (client, length);
      break;
#ifdef HAVE_IPV6
    case ZEBRA_IPV6_NEXTHOP_LOOKUP:
      zread_ipv6_nexthop_lookup (client, length);
      break;
#endif /* HAVE_IPV6 */
    case ZEBRA_IPV4_IMPORT_LOOKUP:
      zread_ipv4_import_lookup (client, length);
      break;
    default:
      zlog_info ("Zebra received unknown command %d", command);
      break;
    }

  stream_reset (client->ibuf);
  zebra_event (ZEBRA_READ, sock, client);

  return 0;
}


/* Accept code of zebra server socket. */
static int
zebra_accept (struct thread *thread)
{
  int val;
  int accept_sock;
  int client_sock;
  struct sockaddr_in client;
  socklen_t len;

  accept_sock = THREAD_FD (thread);

  len = sizeof (struct sockaddr_in);
  client_sock = accept (accept_sock, (struct sockaddr *) &client, &len);

  if (client_sock < 0)
    {
      zlog_warn ("Can't accept zebra socket: %s", safe_strerror (errno));
      return -1;
    }

  /* Make client socket non-blocking.  */
  /* XXX: We dont requeue failed writes, so this leads to inconsistencies.
   * for now socket must remain blocking, regardless of risk of deadlocks.
   */
  /*
  val = fcntl (client_sock, F_GETFL, 0);
  fcntl (client_sock, F_SETFL, (val | O_NONBLOCK));
  */
  
  /* Create new zebra client. */
  zebra_client_create (client_sock);

  /* Register myself. */
  zebra_event (ZEBRA_SERV, accept_sock, NULL);

  return 0;
}

#ifdef HAVE_TCP_ZEBRA
/* Make zebra's server socket. */
static void
zebra_serv ()
{
  int ret;
  int accept_sock;
  struct sockaddr_in addr;

  accept_sock = socket (AF_INET, SOCK_STREAM, 0);

  if (accept_sock < 0) 
    {
      zlog_warn ("Can't bind to socket: %s", safe_strerror (errno));
      zlog_warn ("zebra can't provice full functionality due to above error");
      return;
    }

  memset (&addr, 0, sizeof (struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (ZEBRA_PORT);
#ifdef HAVE_SIN_LEN
  addr.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  sockopt_reuseaddr (accept_sock);
  sockopt_reuseport (accept_sock);

  if ( zserv_privs.change(ZPRIVS_RAISE) )
    zlog (NULL, LOG_ERR, "Can't raise privileges");
    
  ret  = bind (accept_sock, (struct sockaddr *)&addr, 
	       sizeof (struct sockaddr_in));
  if (ret < 0)
    {
      zlog_warn ("Can't bind to socket: %s", safe_strerror (errno));
      zlog_warn ("zebra can't provice full functionality due to above error");
      close (accept_sock);      /* Avoid sd leak. */
      return;
    }
    
  if ( zserv_privs.change(ZPRIVS_LOWER) )
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  ret = listen (accept_sock, 1);
  if (ret < 0)
    {
      zlog_warn ("Can't listen to socket: %s", safe_strerror (errno));
      zlog_warn ("zebra can't provice full functionality due to above error");
      close (accept_sock);	/* Avoid sd leak. */
      return;
    }

  zebra_event (ZEBRA_SERV, accept_sock, NULL);
}
#endif /* HAVE_TCP_ZEBRA */

/* For sockaddr_un. */
#include <sys/un.h>

/* zebra server UNIX domain socket. */
static void
zebra_serv_un (const char *path)
{
  int ret;
  int sock, len;
  struct sockaddr_un serv;
  mode_t old_mask;

  /* First of all, unlink existing socket */
  unlink (path);

  /* Set umask */
  old_mask = umask (0077);

  /* Make UNIX domain socket. */
  sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
      perror ("sock");
      return;
    }

  /* Make server socket. */
  memset (&serv, 0, sizeof (struct sockaddr_un));
  serv.sun_family = AF_UNIX;
  strncpy (serv.sun_path, path, strlen (path));
#ifdef HAVE_SUN_LEN
  len = serv.sun_len = SUN_LEN(&serv);
#else
  len = sizeof (serv.sun_family) + strlen (serv.sun_path);
#endif /* HAVE_SUN_LEN */

  ret = bind (sock, (struct sockaddr *) &serv, len);
  if (ret < 0)
    {
      perror ("bind");
      close (sock);
      return;
    }

  ret = listen (sock, 5);
  if (ret < 0)
    {
      perror ("listen");
      close (sock);
      return;
    }

  umask (old_mask);

  zebra_event (ZEBRA_SERV, sock, NULL);
}


static void
zebra_event (enum event event, int sock, struct zserv *client)
{
  switch (event)
    {
    case ZEBRA_SERV:
      thread_add_read (zebrad.master, zebra_accept, client, sock);
      break;
    case ZEBRA_READ:
      client->t_read = 
	thread_add_read (zebrad.master, zebra_client_read, client, sock);
      break;
    case ZEBRA_WRITE:
      /**/
      break;
    }
}

/* Display default rtm_table for all clients. */
DEFUN (show_table,
       show_table_cmd,
       "show table",
       SHOW_STR
       "default routing table to use for all clients\n")
{
  vty_out (vty, "table %d%s", zebrad.rtm_table_default,
	   VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (config_table, 
       config_table_cmd,
       "table TABLENO",
       "Configure target kernel routing table\n"
       "TABLE integer\n")
{
  zebrad.rtm_table_default = strtol (argv[0], (char**)0, 10);
  return CMD_SUCCESS;
}

DEFUN (ip_forwarding,
       ip_forwarding_cmd,
       "ip forwarding",
       IP_STR
       "Turn on IP forwarding")
{
  int ret;

  ret = ipforward ();
  if (ret == 0)
    ret = ipforward_on ();

  if (ret == 0)
    {
      vty_out (vty, "Can't turn on IP forwarding%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (no_ip_forwarding,
       no_ip_forwarding_cmd,
       "no ip forwarding",
       NO_STR
       IP_STR
       "Turn off IP forwarding")
{
  int ret;

  ret = ipforward ();
  if (ret != 0)
    ret = ipforward_off ();

  if (ret != 0)
    {
      vty_out (vty, "Can't turn off IP forwarding%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* This command is for debugging purpose. */
DEFUN (show_zebra_client,
       show_zebra_client_cmd,
       "show zebra client",
       SHOW_STR
       "Zebra information"
       "Client information")
{
  struct listnode *node;
  struct zserv *client;

  for (node = listhead (zebrad.client_list); node; nextnode (node))
    {
      client = getdata (node);
      vty_out (vty, "Client fd %d%s", client->sock, VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

/* Table configuration write function. */
static int
config_write_table (struct vty *vty)
{
  if (zebrad.rtm_table_default)
    vty_out (vty, "table %d%s", zebrad.rtm_table_default,
	     VTY_NEWLINE);
  return 0;
}

/* table node for routing tables. */
struct cmd_node table_node =
{
  TABLE_NODE,
  "",				/* This node has no interface. */
  1
};

/* Only display ip forwarding is enabled or not. */
DEFUN (show_ip_forwarding,
       show_ip_forwarding_cmd,
       "show ip forwarding",
       SHOW_STR
       IP_STR
       "IP forwarding status\n")
{
  int ret;

  ret = ipforward ();

  if (ret == 0)
    vty_out (vty, "IP forwarding is off%s", VTY_NEWLINE);
  else
    vty_out (vty, "IP forwarding is on%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
/* Only display ipv6 forwarding is enabled or not. */
DEFUN (show_ipv6_forwarding,
       show_ipv6_forwarding_cmd,
       "show ipv6 forwarding",
       SHOW_STR
       "IPv6 information\n"
       "Forwarding status\n")
{
  int ret;

  ret = ipforward_ipv6 ();

  switch (ret)
    {
    case -1:
      vty_out (vty, "ipv6 forwarding is unknown%s", VTY_NEWLINE);
      break;
    case 0:
      vty_out (vty, "ipv6 forwarding is %s%s", "off", VTY_NEWLINE);
      break;
    case 1:
      vty_out (vty, "ipv6 forwarding is %s%s", "on", VTY_NEWLINE);
      break;
    default:
      vty_out (vty, "ipv6 forwarding is %s%s", "off", VTY_NEWLINE);
      break;
    }
  return CMD_SUCCESS;
}

DEFUN (ipv6_forwarding,
       ipv6_forwarding_cmd,
       "ipv6 forwarding",
       IPV6_STR
       "Turn on IPv6 forwarding")
{
  int ret;

  ret = ipforward_ipv6 ();
  if (ret == 0)
    ret = ipforward_ipv6_on ();

  if (ret == 0)
    {
      vty_out (vty, "Can't turn on IPv6 forwarding%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_forwarding,
       no_ipv6_forwarding_cmd,
       "no ipv6 forwarding",
       NO_STR
       IPV6_STR
       "Turn off IPv6 forwarding")
{
  int ret;

  ret = ipforward_ipv6 ();
  if (ret != 0)
    ret = ipforward_ipv6_off ();

  if (ret != 0)
    {
      vty_out (vty, "Can't turn off IPv6 forwarding%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

#endif /* HAVE_IPV6 */

/* IPForwarding configuration write function. */
int
config_write_forwarding (struct vty *vty)
{
  /* FIXME: Find better place for that. */
  router_id_write (vty);

  if (ipforward ())
    vty_out (vty, "ip forwarding%s", VTY_NEWLINE);
#ifdef HAVE_IPV6
  if (ipforward_ipv6 ())
    vty_out (vty, "ipv6 forwarding%s", VTY_NEWLINE);
#endif /* HAVE_IPV6 */
  vty_out (vty, "!%s", VTY_NEWLINE);
  return 0;
}

/* table node for routing tables. */
struct cmd_node forwarding_node =
{
  FORWARDING_NODE,
  "",				/* This node has no interface. */
  1
};


/* Initialisation of zebra and installation of commands. */
void
zebra_init ()
{
  /* Client list init. */
  zebrad.client_list = list_new ();

  /* Make zebra server socket. */
#ifdef HAVE_TCP_ZEBRA
  zebra_serv ();
#else
  zebra_serv_un (ZEBRA_SERV_PATH);
#endif /* HAVE_TCP_ZEBRA */

  /* Install configuration write function. */
  install_node (&table_node, config_write_table);
  install_node (&forwarding_node, config_write_forwarding);

  install_element (VIEW_NODE, &show_ip_forwarding_cmd);
  install_element (ENABLE_NODE, &show_ip_forwarding_cmd);
  install_element (CONFIG_NODE, &ip_forwarding_cmd);
  install_element (CONFIG_NODE, &no_ip_forwarding_cmd);
  install_element (ENABLE_NODE, &show_zebra_client_cmd);

#ifdef HAVE_NETLINK
  install_element (VIEW_NODE, &show_table_cmd);
  install_element (ENABLE_NODE, &show_table_cmd);
  install_element (CONFIG_NODE, &config_table_cmd);
#endif /* HAVE_NETLINK */

#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &show_ipv6_forwarding_cmd);
  install_element (ENABLE_NODE, &show_ipv6_forwarding_cmd);
  install_element (CONFIG_NODE, &ipv6_forwarding_cmd);
  install_element (CONFIG_NODE, &no_ipv6_forwarding_cmd);
#endif /* HAVE_IPV6 */

  FIFO_INIT(&message_queue);
  t_write = NULL;
}
