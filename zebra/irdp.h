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

/* ICMP Messages */
#ifndef ICMP_ROUTERADVERT
#define ICMP_ROUTERADVERT 9
#endif /* ICMP_ROUTERADVERT */

#ifndef ICMP_ROUTERSOLICIT
#define ICMP_ROUTERSOLICIT 10
#endif /* ICMP_ROUTERSOLICT */

/* Multicast groups */
#ifndef INADDR_ALLHOSTS_GROUP
#define INADDR_ALLHOSTS_GROUP 0xe0000001    /* 224.0.0.1 */
#endif /* INADDR_ALLHOSTS_GROUP */

#ifndef INADDR_ALLRTRS_GROUP
#define INADDR_ALLRTRS_GROUP  0xe0000002    /* 224.0.0.2 */
#endif /* INADDR_ALLRTRS_GROUP */

/* Comments comes from RFC1256 ICMP Router Discovery Messages. */
struct irdp_router_interface 
{
  /* The IP destination address to be used for multicast Router
     Advertisements sent from the interface.  The only permissible
     values are the all-systems multicast address, 224.0.0.1, or the
     limited-broadcast address, 255.255.255.255.  (The all-systems
     address is preferred wherever possible, i.e., on any link where
     all listening hosts support IP multicast.)

     Default: 224.0.0.1 if the router supports IP multicast on the
     interface, else 255.255.255.255 */

  struct in_addr AdvertisementAddress;

  /* The maximum time allowed between sending multicast Router
     Advertisements from the interface, in seconds.  Must be no less
     than 4 seconds and no greater than 1800 seconds.

     Default: 600 seconds */

  unsigned long MaxAdvertisementInterval;

  /* The minimum time allowed between sending unsolicited multicast
     Router Advertisements from the interface, in seconds.  Must be no
     less than 3 seconds and no greater than MaxAdvertisementInterval.

     Default: 0.75 * MaxAdvertisementInterval */

  unsigned long MinAdvertisementInterval;


  /* The value to be placed in the Lifetime field of Router
     Advertisements sent from the interface, in seconds.  Must be no
     less than MaxAdvertisementInterval and no greater than 9000
     seconds.

     Default: 3 * MaxAdvertisementInterval */

  unsigned long AdvertisementLifetime;

  /* A flag indicating whether or not the address is to be advertised.

     Default: TRUE */

  int Advertise;


  /* The preferability of the address as a default router address,
     relative to other router addresses on the same subnet.  A 32-bit,
     signed, twos-complement integer, with higher values meaning more
     preferable.  The minimum value (hex 80000000) is used to indicate
     that the address, even though it may be advertised, is not to be
     used by neighboring hosts as a default router address.

     Default: 0 */

  unsigned long PreferenceLevel;
};

struct irdp_host_interface 
{
  /* A flag indicating whether or not the host is to perform ICMP router
     discovery on the interface. */
  int PerformRouerDiscovery;
  
  /* The IP destination address to be used for sending Router
     Solicitations from the interface.  The only permissible values
     are the all-routers multicast address, 224.0.0.2, or the
     limited-broadcast address, 255.255.255.255.  (The all-routers
     address is preferred wherever possible, i.e., on any link where
     all advertising routers support IP multicast.)  */
  unsigned long SolicitationAddress;
};


/* Route preference structure */
struct irdp 
{
  struct in_addr prefix;
  long pref;		/* preference level */
  long timer;			/* lifetime timer */

  struct irdp *next;		/* doubly linked list */
  struct irdp *prev;		/* doubly linked list */
};

/* Default irdp packet interval */
#define IRDP_DEFAULT_INTERVAL 300

/* Router constants from RFC1256 */
#define MAX_INITIAL_ADVERT_INTERVAL 16
#define MAX_INITIAL_ADVERTISEMENTS   3
#define MAX_RESPONSE_DELAY           2

/* Host constants from RFC1256 */
#define MAX_SOLICITATION_DELAY       1
#define SOLICITATION_INTERVAL        3
#define MAX_SOLICITATIONS            3

enum
{
  IRDP_NONE,
  IRDP_ROUTER,
  IRDP_HOST,
};

/* default is host mode */
extern int irdp_mode;
