/*
 * Common ioctl functions for Solaris.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "ioctl.h"
#include "log.h"
#include "privs.h"

#include "zebra/rib.h"
#include "zebra/rt.h"

extern struct zebra_privs_t zserv_privs;

/* clear and set interface name string */
void
lifreq_set_name (struct lifreq *lifreq, struct interface *ifp)
{
  strncpy (lifreq->lifr_name, ifp->name, IFNAMSIZ);
}

/* call ioctl system call */
int
if_ioctl (u_long request, caddr_t buffer)
{
  int sock;
  int ret;
  int err;

  if (zserv_privs.change(ZPRIVS_RAISE))
    zlog (NULL, LOG_ERR, "Can't raise privileges");
    
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      if (zserv_privs.change(ZPRIVS_LOWER))
        zlog (NULL, LOG_ERR, "Can't lower privileges");
      perror ("socket");
      exit (1);
    }

  if ((ret = ioctl (sock, request, buffer)) < 0)
    err = errno;
  
  if (zserv_privs.change(ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  close (sock);

  if (ret < 0)
    {
      errno = err;
      return ret;
    }
  return 0;
}


int
if_ioctl_ipv6 (u_long request, caddr_t buffer)
{
#ifdef HAVE_IPV6
  int sock;
  int ret;
  int err;

  if (zserv_privs.change(ZPRIVS_RAISE))
    zlog (NULL, LOG_ERR, "Can't raise privileges");

  sock = socket (AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      if (zserv_privs.change(ZPRIVS_LOWER))
        zlog (NULL, LOG_ERR, "Can't lower privileges");
      perror ("socket");
      exit (1);
    }

  if ((ret = ioctl (sock, request, buffer)) < 0)
    err = errno;

  if (zserv_privs.change(ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");

  close (sock);

  if (ret < 0)
    {
      errno = err;
      return ret;
    }
#endif /* HAVE_IPV6 */

  return 0;
}

/*
 * get interface metric
 *   -- if value is not avaliable set -1
 */
void
if_get_metric (struct interface *ifp)
{
  struct lifreq lifreq;
  int ret;

  lifreq_set_name (&lifreq, ifp);

  if (ifp->flags & IFF_IPV4)
    ret = AF_IOCTL (AF_INET, SIOCGLIFMETRIC, (caddr_t) & lifreq);
#ifdef SOLARIS_IPV6
  else if (ifp->flags & IFF_IPV6)
    ret = AF_IOCTL (AF_INET6, SIOCGLIFMETRIC, (caddr_t) & lifreq);
#endif /* SOLARIS_IPV6 */
  else
    ret = -1;
    
  if (ret < 0)
    return;

  ifp->metric = lifreq.lifr_metric;

  if (ifp->metric == 0)
    ifp->metric = 1;
}

/* get interface MTU */
void
if_get_mtu (struct interface *ifp)
{
  struct lifreq lifreq;
  int ret;
  
  if (ifp->flags & IFF_IPV4)
    {
      lifreq_set_name (&lifreq, ifp);
      ret = AF_IOCTL (AF_INET, SIOCGLIFMTU, (caddr_t) & lifreq);
      if (ret < 0)
        {
          zlog_info ("Can't lookup mtu on %s by ioctl(SIOCGLIFMTU)",
                     ifp->name);
          ifp->mtu = -1;
        }
      else
        {
          ifp->mtu = lifreq.lifr_metric;
        }
    }

#ifdef HAVE_IPV6
  if ((ifp->flags & IFF_IPV6) == 0)
    return;
    
  memset(&lifreq, 0, sizeof(lifreq));
  lifreq_set_name (&lifreq, ifp);

  ret = AF_IOCTL (AF_INET6, SIOCGLIFMTU, (caddr_t) & lifreq);
  if (ret < 0)
    {
      zlog_info ("Can't lookup mtu6 on %s by ioctl(SIOCGIFMTU)", ifp->name);
      ifp->mtu6 = -1;
    }
  else
    {
      ifp->mtu6 = lifreq.lifr_metric;
    }
#endif /* HAVE_IPV6 */
}

/* Set up interface's address, netmask (and broadcast? ).
   Solaris uses ifname:number semantics to set IP address aliases. */
int
if_set_prefix (struct interface *ifp, struct connected *ifc)
{
  int ret;
  struct ifreq ifreq;
  struct sockaddr_in addr;
  struct sockaddr_in broad;
  struct sockaddr_in mask;
  struct prefix_ipv4 ifaddr;
  struct prefix_ipv4 *p;

  p = (struct prefix_ipv4 *) ifc->address;

  ifaddr = *p;

  strncpy (ifreq.ifr_name, ifp->name, IFNAMSIZ);

  addr.sin_addr = p->prefix;
  addr.sin_family = p->family;
  memcpy (&ifreq.ifr_addr, &addr, sizeof (struct sockaddr_in));

  ret = if_ioctl (SIOCSIFADDR, (caddr_t) & ifreq);

  if (ret < 0)
    return ret;

  /* We need mask for make broadcast addr. */
  masklen2ip (p->prefixlen, &mask.sin_addr);

  if (if_is_broadcast (ifp))
    {
      apply_mask_ipv4 (&ifaddr);
      addr.sin_addr = ifaddr.prefix;

      broad.sin_addr.s_addr = (addr.sin_addr.s_addr | ~mask.sin_addr.s_addr);
      broad.sin_family = p->family;

      memcpy (&ifreq.ifr_broadaddr, &broad, sizeof (struct sockaddr_in));
      ret = if_ioctl (SIOCSIFBRDADDR, (caddr_t) & ifreq);
      if (ret < 0)
        return ret;
    }

  mask.sin_family = p->family;
#ifdef SUNOS_5
  memcpy (&mask, &ifreq.ifr_addr, sizeof (mask));
#else
  memcpy (&ifreq.ifr_netmask, &mask, sizeof (struct sockaddr_in));
#endif /* SUNOS_5 */
  ret = if_ioctl (SIOCSIFNETMASK, (caddr_t) & ifreq);

  return ((ret < 0) ? ret : 0);
}

/* Set up interface's address, netmask (and broadcast).
   Solaris uses ifname:number semantics to set IP address aliases. */
int
if_unset_prefix (struct interface *ifp, struct connected *ifc)
{
  int ret;
  struct ifreq ifreq;
  struct sockaddr_in addr;
  struct prefix_ipv4 *p;

  p = (struct prefix_ipv4 *) ifc->address;

  strncpy (ifreq.ifr_name, ifp->name, IFNAMSIZ);

  memset (&addr, 0, sizeof (struct sockaddr_in));
  addr.sin_family = p->family;
  memcpy (&ifreq.ifr_addr, &addr, sizeof (struct sockaddr_in));

  ret = if_ioctl (SIOCSIFADDR, (caddr_t) & ifreq);
  
  if (ret < 0)
    return ret;

  return 0;
}

/* get interface flags */
void
if_get_flags (struct interface *ifp)
{
  int ret;
  struct lifreq lifreq;
  unsigned long flags4 = 0, flags6 = 0;

  if (ifp->flags & IFF_IPV4)
    {
      lifreq_set_name (&lifreq, ifp);
      
      ret = AF_IOCTL (AF_INET, SIOCGLIFFLAGS, (caddr_t) & lifreq);

      flags4 = (lifreq.lifr_flags & 0xffffffff);
      if (!(flags4 & IFF_UP))
        flags4 &= ~IFF_IPV4;
    }

  if (ifp->flags & IFF_IPV6)
    {
      lifreq_set_name (&lifreq, ifp);
      
      ret = AF_IOCTL (AF_INET6, SIOCGLIFFLAGS, (caddr_t) & lifreq);
              
      flags6 = (lifreq.lifr_flags & 0xffffffff);
      if (!(flags6 & IFF_UP))
        flags6 &= ~IFF_IPV6;
    }

  ifp->flags = (flags4 | flags6);
}

/* Set interface flags */
int
if_set_flags (struct interface *ifp, unsigned long flags)
{
  int ret;
  struct lifreq lifreq;

  lifreq_set_name (&lifreq, ifp);

  lifreq.lifr_flags = ifp->flags;
  lifreq.lifr_flags |= flags;

  if (ifp->flags & IFF_IPV4)
    ret = AF_IOCTL (AF_INET, SIOCSLIFFLAGS, (caddr_t) & lifreq);
  else if (ifp->flags & IFF_IPV6)
    ret = AF_IOCTL (AF_INET6, SIOCSLIFFLAGS, (caddr_t) & lifreq);
  else
    ret = -1;

  if (ret < 0)
    zlog_info ("can't set interface flags on %s: %s", ifp->name,
               safe_strerror (errno));
  else
    ret = 0;
    
  return ret;
}

/* Unset interface's flag. */
int
if_unset_flags (struct interface *ifp, unsigned long flags)
{
  int ret;
  struct lifreq lifreq;

  lifreq_set_name (&lifreq, ifp);

  lifreq.lifr_flags = ifp->flags;
  lifreq.lifr_flags &= ~flags;

  if (ifp->flags & IFF_IPV4)
    ret = AF_IOCTL (AF_INET, SIOCSLIFFLAGS, (caddr_t) & lifreq);
  else if (ifp->flags & IFF_IPV6)
    ret = AF_IOCTL (AF_INET6, SIOCSLIFFLAGS, (caddr_t) & lifreq);
  else
    ret = -1;

  if (ret < 0)
    zlog_info ("can't unset interface flags");
  else
    ret = 0;
  
  return ret;
}

#ifdef HAVE_IPV6

/* Interface's address add/delete functions. */
int
if_prefix_add_ipv6 (struct interface *ifp, struct connected *ifc)
{
  char addrbuf[INET_ADDRSTRLEN];

  inet_ntop (AF_INET6, &(((struct prefix_ipv6 *) (ifc->address))->prefix),
             addrbuf, sizeof (addrbuf));
  zlog_warn ("Can't set %s on interface %s", addrbuf, ifp->name);

  return 0;

}

int
if_prefix_delete_ipv6 (struct interface *ifp, struct connected *ifc)
{
  char addrbuf[INET_ADDRSTRLEN];

  inet_ntop (AF_INET6, &(((struct prefix_ipv6 *) (ifc->address))->prefix),
             addrbuf, sizeof (addrbuf));
  zlog_warn ("Can't delete %s on interface %s", addrbuf, ifp->name);

  return 0;

}

#endif /* HAVE_IPV6 */
