/* ICMP Router Discovery Messages
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
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

#include <netinet/ip_icmp.h>

#include "if.h"
#include "stream.h"
#include "memory.h"
#include "command.h"
#include "log.h"
#include "sockunion.h"
#include "sockopt.h"

#include "zebra/irdp.h"

/* Default does nothing. */
int irdp_mode = IRDP_NONE;

/* Timer interval of irdp. */
int irdp_timer_interval = IRDP_DEFAULT_INTERVAL;

/* Max solicitations */
int max_solicitations = MAX_SOLICITATIONS;

#define IRDP_SOLICIT_PACKET_SIZE 8

static struct irdp *irdp_head = NULL;

extern int in_cksum (void *ptr, int nbytes);

char *icmp_type_str[] = 
{
  "Echo Reply",
  "ICMP 1",
  "ICMP 2",
  "Dest Unreachable",
  "Source Quench",
  "Redirect",
  "ICMP 6",
  "ICMP 7",
  "Echo",
  "Router Advertise",
  "Router Solicitation",
  "Time Exceeded",
  "Parameter Problem",
  "Timestamp",
  "Timestamp Reply",
  "Info Request",
  "Info Reply",
  "Netmask Request",
  "Netmask Reply",
};

char *
icmp_type (int type)
{
  if (type < 0 || type >= (sizeof icmp_type_str / sizeof (char *))) {
    return "OUT-OF-RANGE";
  }
  return icmp_type_str [type];
}

/* */
void
irdp_add_interface ()
{
  ;
}

/* */
void
irdp_delete_interface ()
{

}

struct irdp *
irdp_route_new ()
{
  struct irdp *new = XMALLOC (0, sizeof (struct irdp));
  memset (new, 0, sizeof (struct irdp));
  return new;
}

void
irdp_route_free (struct irdp *route)
{
  XFREE (0, route);
}

void
route_delete ()
{

}

void
route_init ()
{
  
}

void
route_add (struct in_addr addr, unsigned long pref)
{
  struct irdp *new = irdp_route_new();
  
  new->prefix = addr;
  new->pref = pref;

  printf ("address %s\n", inet_ntoa (new->prefix));
  printf ("pref %ld\n", new->pref);
}

void
route_age (int time)
{
  struct irdp *p;

  for (p = irdp_head; p != NULL; p = p->next) {
    if (p->timer < time) {
      /* fire */
    } else {
      p->timer -= time;
    }
  }
}

#define FLAG_TEST(a)  ((ifp->flags & (a)) == (a))

void
send_multicast (struct interface *ifp, int sock, struct stream *s, int size)
{
  struct sockaddr_in sin;
  struct in_addr addr;
  int nbytes;
  struct connected *connected;
  listnode node;
  
  for (node = listhead (ifp->connected); node; nextnode (node))
    {
      connected = getdata (node);
    }

  if (setsockopt_multicast_ipv4 (sock, IP_MULTICAST_IF,
		  addr, 0, ifp->ifindex) < 0) 
    {
      perror ("setsockopt");
      exit (1);
    }

  sin.sin_addr.s_addr = htonl (INADDR_ALLRTRS_GROUP);
  sin.sin_family = AF_INET;

  nbytes = sendto (sock, s->data, size, 0,
		   (struct sockaddr *) &sin, sizeof (struct sockaddr));

  if (nbytes != size) 
    {
      perror ("sendto");
      exit (1);
    }
}

void
send_broadcast ()
{
  struct sockaddr_in sin;

  printf ("broadcast\n");
  inet_aton ("255.255.255.255", &sin.sin_addr);
}

void
irdp_send_solicit (int sock, struct stream *s, int size)
{
  struct interface *ifp;
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (FLAG_TEST (IFF_UP | IFF_MULTICAST)) 
	{
	  send_multicast (ifp, sock, s, size);
	}
      else if (FLAG_TEST (IFF_UP | IFF_BROADCAST)) 
	{
	  send_broadcast ();
	}
    }
}

int
ipv4_multicast_join (int sock, 
		     struct in_addr group, 
		     struct in_addr ifa,
		     unsigned int ifindex)
{
  int ret;

  ret = setsockopt_multicast_ipv4 (sock, IP_ADD_MEMBERSHIP, 
		    ifa, group.saddr, ifindex);

  if (ret < 0) 
    zlog (NULL, LOG_INFO, "can't setsockopt IP_ADD_MEMBERSHIP");

  return ret;
}

/* multicast packet recieve socket */
int
irdp_multicast_socket (int sock, struct in_addr group)
{
  struct interface *ifp;
  listnode node;
  struct in_addr addr;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      if ((ifp->flags & IFF_UP) && (ifp->flags & IFF_MULTICAST)) 
	{
	  ipv4_multicast_join (sock, group, addr, ifp->ifindex);
	}
    }
  return 0;
}

struct 
{
  u_char type;
  u_char code;
  u_int16_t checksum;
  u_char number;
  u_char entry;
  u_int16_t lifetime;
} radv;

void
irdp_set (int sock)
{
  struct in_addr irdp_group;

  switch (irdp_mode) 
    {
    case IRDP_HOST:
      irdp_group.s_addr = htonl (INADDR_ALLHOSTS_GROUP);
      break;
    case IRDP_ROUTER:
      irdp_group.s_addr = htonl (INADDR_ALLRTRS_GROUP);
      break;
    case IRDP_NONE:
    default:
      return;
    }
  irdp_multicast_socket (sock, irdp_group);
}

/* Make ICMP Router Solicitation Message. */
int
make_solicit_packet (struct stream *s)
{
  int size;
  int checksum;

  stream_putc (s, ICMP_ROUTERSOLICIT); /* Type. */
  stream_putc (s, 0);		/* Code. */
  stream_putw (s, 0);		/* Checksum. */
  stream_putl (s, 0);		/* Reserved. */

  /* in_cksum return network byte order value */
  size = IRDP_SOLICIT_PACKET_SIZE;
  checksum = in_cksum (s->data, size);
  stream_putw_at (s, checksum, 2);

  return IRDP_SOLICIT_PACKET_SIZE;
}

void
irdp_solicit (int sock)
{
  struct stream *s;

  s = stream_new (IRDP_SOLICIT_PACKET_SIZE);
  make_solicit_packet (s);
  irdp_send_solicit (sock, s, IRDP_SOLICIT_PACKET_SIZE);
}

#define ICMP_MINLEN 8

/* check validity of the packet */
int
irdp_valid_check (char *packet, size_t size, struct sockaddr_in *from)
{
  struct icmp *icmp;

  icmp = (struct icmp *) packet;

  if (in_cksum (packet, size)) {
    zlog_warn ("ICMP %s packet from %s: Bad checksum, silently ignored",
	       icmp_type (icmp->icmp_type),
	       inet_ntoa (from->sin_addr));
    return -1;
  }

  if (icmp->icmp_code != 0) {
    zlog_warn ("ICMP %s packet from %s: Bad ICMP type code, silently ignored",
	       icmp_type (icmp->icmp_type),
	       inet_ntoa (from->sin_addr));
    return -1;
  }

  if (size < ICMP_MINLEN) {
    zlog_warn ("ICMP %s packet from %s: IMCP message length is short",
	       icmp_type (icmp->icmp_type),
	       inet_ntoa (from->sin_addr));
    return -1;
  }
  return 0;
}

int
irdp_solicit_recv (struct stream *s, int size, struct sockaddr_in *from)
{
  if (irdp_valid_check (s->data, size, from)) {
    return 1;
  }
  return 0;
}

void
irdp_advert_recv (struct stream *s, int size, struct sockaddr_in *from)
{
  int i;
  struct in_addr addr;
  long pref;

  if (irdp_valid_check (s->data, size, from) < 0) {
    return;
  }

  radv.type = stream_getc (s);
  radv.code =  stream_getc (s);
  radv.checksum = stream_getw (s);
  radv.number = stream_getc (s);
  radv.entry = stream_getc (s);
  radv.lifetime = stream_getw (s);

  printf ("type : %s\n", icmp_type (radv.type));
  printf ("number: %d\n", radv.number);
  printf ("entry: %d\n", radv.entry);
  printf ("lifetime: %d\n", radv.entry);

  for (i = 0; i < radv.number; i++) 
    {
      addr.s_addr = stream_getl (s);
      pref = stream_getl (s);
      route_add (addr, ntohl (pref));
    }
  /* Packet size check is needed at here. */
}

void
irdp_packet_process (char *buf, int size, struct sockaddr_in *from)
{
  struct ip *ip;
  struct icmp *icmp;
  int hlen;
  struct stream *s = NULL;

  ip = (struct ip *)buf;
  hlen = ip->ip_hl << 2;

  if (size < hlen + ICMP_MINLEN)
    zlog_err ("ICMP relpy length is short\n");

  icmp = (struct icmp *)(buf + hlen);

  stream_forward (s, hlen);
  
  switch (icmp->icmp_type) 
    {
    case ICMP_ROUTERADVERT:
      irdp_advert_recv (s, size - hlen, from);
      break;
    case ICMP_ROUTERSOLICIT:
      irdp_solicit_recv (s, size - hlen, from);
      break;
    }
}

/* Make socket for ICMP Router Discovery. */
int
irdp_make_socket ()
{
  int sock;
  struct protoent *pent;

  if ((pent = getprotobyname ("icmp")) == NULL) {
    perror ("getprotobyname");
    exit (1);
  }

  if ((sock = socket (AF_INET, SOCK_RAW, pent->p_proto)) < 0) 
    {
      perror ("socket");
      exit (1);
    }

  return sock;
}

/* recv routine */
int
irdp_recv (int sock)
{
#define PACKET_BUF 4096
  int nbytes;
  struct sockaddr_in from;
  int fromlen;
  char buf[PACKET_BUF];

  fromlen = sizeof (from);
  nbytes = recvfrom (sock, (char *)buf, PACKET_BUF, 0,
		     (struct sockaddr *)&from, &fromlen);

  if (nbytes < 0) 
    {
      perror ("recvfrom");
      exit (1);
    }

  irdp_packet_process (buf, nbytes, &from);

  return 0;
}

/* irdp packet recv loop */
void
irdp_loop (int sock)
{
  while (1) 
    {
      irdp_recv (sock);
    }
}

DEFUN (ip_irdp,
       ip_irdp_cmd,
       "ip irdp",
       IP_STR
       "ICMP Router discovery on this interface\n")
{
  return CMD_SUCCESS;
}

DEFUN (ip_irdp_multicast,
       ip_irdp_multicast_cmd,
       "ip irdp multicast",
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Send IRDP advertisement to the multicast address\n")
{
  return CMD_SUCCESS;
}

DEFUN (ip_irdp_holdtime,
       ip_irdp_holdtime_cmd,
       "ip irdp holdtime <0-9000>",
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Set holdtime value\n"
       "Holdtime value in seconds. Default is 1800 seconds\n")
{
  return CMD_SUCCESS;
}

DEFUN (ip_irdp_maxadvertinterval,
       ip_irdp_maxadvertinterval_cmd,
       "ip irdp maxadvertinterval (0|<4-1800>)",
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Set maximum time between advertisement\n"
       "Maximum advertisement interval in seconds\n")
{
  return CMD_SUCCESS;
}

DEFUN (ip_irdp_minadvertinterval,
       ip_irdp_minadvertinterval_cmd,
       "ip irdp minadvertinterval <3-1800>",
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Set minimum time between advertisement\n"
       "Minimum advertisement interval in seconds\n")
{
  return CMD_SUCCESS;
}

DEFUN (ip_irdp_preference,
       ip_irdp_preference_cmd,
       /* "ip irdp preference <-2147483648-2147483647>", */
       "ip irdp preference <0-2147483647>",
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Set default preference level for this interface\n"
       "Preference level\n")
{
  return CMD_SUCCESS;
}

#if 0
DEFUN (ip_irdp_address,
       ip_irdp_address_cmd,
       "ip irdp address A.B.C.D",
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Specify IRDP address and preference to proxy-advertise\n"
       "Set IRDP address for proxy-advertise\n")
{
  return CMD_SUCCESS;
}
#endif /* 0 */

DEFUN (ip_irdp_address_preference,
       ip_irdp_address_preference_cmd,
       "ip irdp address A.B.C.D <0-2147483647>",
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Specify IRDP address and preference to proxy-advertise\n"
       "Set IRDP address for proxy-advertise\n"
       "Preference level\n")
{
  return CMD_SUCCESS;
}

void
irdp_init ()
{
  install_element (INTERFACE_NODE, &ip_irdp_cmd);
  install_element (INTERFACE_NODE, &ip_irdp_multicast_cmd);
  install_element (INTERFACE_NODE, &ip_irdp_holdtime_cmd);
  install_element (INTERFACE_NODE, &ip_irdp_maxadvertinterval_cmd);
  install_element (INTERFACE_NODE, &ip_irdp_minadvertinterval_cmd);
  install_element (INTERFACE_NODE, &ip_irdp_preference_cmd);
  install_element (INTERFACE_NODE, &ip_irdp_address_preference_cmd);
}
