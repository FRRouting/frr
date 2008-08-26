/*
 * $Quagga: $Format:%an, %ai, %h$ $
 *
 * GNU Zebra client test main routine.
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#include "prefix.h"
#include "stream.h"
#include "zclient.h"
#include "thread.h"
#include "table.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"

struct thread *master;

/* Zebra client structure. */
struct zclient *zclient = NULL;

/* Zebra socket. */
int sock;

/* IPv4 route add and delete test. */
void
zebra_test_ipv4 (int command, int type, char *prefix, char *gateway,
		 u_char distance)
{
  struct zapi_ipv4 api;
  struct prefix_ipv4 p;
  struct in_addr gate;
  struct in_addr *gpnt;

  str2prefix_ipv4 (prefix, &p);
  inet_aton (gateway, &gate);
  gpnt = &gate;

  api.type = type;
  api.flags = 0;

  api.message = 0;
  SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
  api.nexthop_num = 1;
  api.nexthop = &gpnt;
  api.ifindex_num = 0;
  if (distance)
    {
      SET_FLAG (api.message, ZAPI_MESSAGE_DISTANCE);
      api.distance = distance;
    }
  

  switch (command)
    {
    case ZEBRA_IPV4_ROUTE_ADD:
      zapi_ipv4_add (zclient, &p, &api);
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      zapi_ipv4_delete (zclient, &p, &api);
      break;
    }
}

#ifdef HAVE_IPV6
/* IPv6 route add and delete test. */
void
zebra_test_v6 (int sock)
{
  struct prefix_ipv6 p;
  struct in6_addr nexthop;

  str2prefix_ipv6 ("3ffe:506::2/128", &p);
  inet_pton (AF_INET6, "::1", &nexthop);

  /* zebra_ipv6_add (sock, ZEBRA_ROUTE_STATIC, 0, &p, &nexthop, 1); */

  sleep (5);
  /* zebra_ipv6_delete (sock, ZEBRA_ROUTE_STATIC, 0, &p, &nexthop, 1); */
}
#endif /* HAVE_IPV6 */

/* Print out usage and exit. */
void
usage_exit ()
{
  fprintf (stderr, "Usage: client filename\n");
  exit (1);
}

struct zebra_info 
{
  char *str;
  int type;
} zebra_type[] = 
{
  { "static", ZEBRA_ROUTE_STATIC },
  { "rip",    ZEBRA_ROUTE_RIP },
  { "ripng",  ZEBRA_ROUTE_RIPNG },
  { "ospf",   ZEBRA_ROUTE_OSPF },
  { "ospf6",  ZEBRA_ROUTE_OSPF6 },
  { "bgp",    ZEBRA_ROUTE_BGP },
  { NULL,     0 }
};

/* Zebra route simulator. */
void
zebra_sim (FILE *fp)
{
  char buf[BUFSIZ];
  char distance_str[BUFSIZ];
  u_char distance;

  while (fgets (buf, sizeof buf, fp))
    {
      int i;
      int ret;
      int type;
      char str[BUFSIZ], command[BUFSIZ], prefix[BUFSIZ], gateway[BUFSIZ];

      distance = 0;

      if (*buf == '#')
	continue;

      type = ZEBRA_ROUTE_STATIC;

      ret = sscanf (buf, "%s %s %s %s %s\n", command, str, prefix, gateway,
		    distance_str);

      if (ret == 5)
	{
	  distance = atoi (distance_str);
	}
      else
	{
	  ret = sscanf (buf, "%s %s %s %s\n", command, str, prefix, gateway);

	  if (ret != 4)
	    continue;
	}

      for (i = 0; i < 10; i++)
	{
	  if (!zebra_type[i].str)
	    break;
	  if (strcmp (zebra_type[i].str, str) == 0)
	    {
	      type = zebra_type[i].type;
	      break;
	    }
	}
      
      if (strcmp (command, "add") == 0)
	{
	  zebra_test_ipv4 (ZEBRA_IPV4_ROUTE_ADD, type, prefix, gateway,
			   distance);
	  printf ("%s", buf);
	  continue;
	}

      if (strcmp (command, "del") == 0)
	{
	  zebra_test_ipv4 (ZEBRA_IPV4_ROUTE_DELETE, type, prefix, gateway,
			   distance);
	  printf ("%s", buf);
	  continue;
	}
    }
}

/* Test zebra client main routine. */
int
main (int argc, char **argv)
{
  FILE *fp;

  if (argc == 1)
      usage_exit ();

  /* Establish connection to zebra. */
  zclient = zclient_new ();
  zclient->enable = 1;
#ifdef HAVE_TCP_ZEBRA
  zclient->sock = zclient_socket ();
#else
  zclient->sock = zclient_socket_un (ZEBRA_SERV_PATH);
#endif /* HAVE_TCP_ZEBRA */

  /* Open simulation file. */
  fp = fopen (argv[1], "r");
  if (fp == NULL)
    {
      fprintf (stderr, "can't open %s\n", argv[1]);
      exit (1);
    }

  /* Do main work. */
  zebra_sim (fp);

  sleep (100);

  fclose (fp);
  close (sock);

  return 0;
}
