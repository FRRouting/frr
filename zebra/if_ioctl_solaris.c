/*
 * Interface looking up by ioctl () on Solaris.
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

#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "ioctl.h"
#include "connected.h"
#include "memory.h"
#include "log.h"
#include "privs.h"

#include "zebra/interface.h"

void lifreq_set_name (struct lifreq *, struct interface *);
static int if_get_addr (struct interface *, struct sockaddr *);
static void interface_info_ioctl (struct interface *);
extern struct zebra_privs_t zserv_privs;

int
interface_list_ioctl (int af)
{
  int ret;
  int sock;
#define IFNUM_BASE 32
  struct lifnum lifn;
  int ifnum;
  struct lifreq *lifreq;
  struct lifconf lifconf;
  struct interface *ifp;
  int n;
  int save_errno;
  size_t needed, lastneeded = 0;
  char *buf = NULL;

  if (zserv_privs.change(ZPRIVS_RAISE))
    zlog (NULL, LOG_ERR, "Can't raise privileges");
  
  sock = socket (af, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      zlog_warn ("Can't make %s socket stream: %s",
                 (af == AF_INET ? "AF_INET" : "AF_INET6"), safe_strerror (errno));
                 
      if (zserv_privs.change(ZPRIVS_LOWER))
        zlog (NULL, LOG_ERR, "Can't lower privileges");
        
      return -1;
    }

calculate_lifc_len:     /* must hold privileges to enter here */
  lifn.lifn_family = af;
  lifn.lifn_flags = 0;
  ret = ioctl (sock, SIOCGLIFNUM, &lifn);
  save_errno = errno;
  
  if (zserv_privs.change(ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");
 
  if (ret < 0)
    {
      zlog_warn ("interface_list_ioctl: SIOCGLIFNUM failed %s",
                 safe_strerror (save_errno));
      close (sock);
      return -1;
    }
  ifnum = lifn.lifn_count;

  /*
   * When calculating the buffer size needed, add a small number
   * of interfaces to those we counted.  We do this to capture
   * the interface status of potential interfaces which may have
   * been plumbed between the SIOCGLIFNUM and the SIOCGLIFCONF.
   */
  needed = (ifnum + 4) * sizeof (struct lifreq);
  if (needed > lastneeded || needed < lastneeded / 2)
    {
      if (buf != NULL)
        XFREE (MTYPE_TMP, buf);
      if ((buf = XMALLOC (MTYPE_TMP, needed)) == NULL)
        {
          zlog_warn ("interface_list_ioctl: malloc failed");
          close (sock);
          return -1;
        }
    }
  lastneeded = needed;

  lifconf.lifc_family = af;
  lifconf.lifc_flags = 0;
  lifconf.lifc_len = needed;
  lifconf.lifc_buf = buf;

  if (zserv_privs.change(ZPRIVS_RAISE))
    zlog (NULL, LOG_ERR, "Can't raise privileges");
    
  ret = ioctl (sock, SIOCGLIFCONF, &lifconf);

  if (ret < 0)
    {
      if (errno == EINVAL)
        goto calculate_lifc_len; /* deliberately hold privileges */

      zlog_warn ("SIOCGLIFCONF: %s", safe_strerror (errno));

      if (zserv_privs.change(ZPRIVS_LOWER))
        zlog (NULL, LOG_ERR, "Can't lower privileges");

      goto end;
    }

  if (zserv_privs.change(ZPRIVS_LOWER))
    zlog (NULL, LOG_ERR, "Can't lower privileges");
    
  /* Allocate interface. */
  lifreq = lifconf.lifc_req;

  for (n = 0; n < lifconf.lifc_len; n += sizeof (struct lifreq))
    {
      ifp = if_get_by_name (lifreq->lifr_name);

      if (lifreq->lifr_addr.ss_family == AF_INET)
        ifp->flags |= IFF_IPV4;

      if (lifreq->lifr_addr.ss_family == AF_INET6)
        {
#ifdef HAVE_IPV6
          ifp->flags |= IFF_IPV6;
#else
          lifreq++;
          continue;
#endif /* HAVE_IPV6 */
        }
        
      if_add_update (ifp);

      interface_info_ioctl (ifp);
      if_get_addr (ifp, (struct sockaddr *) &lifreq->lifr_addr);
      lifreq++;
    }

end:
  close (sock);
  XFREE (MTYPE_TMP, lifconf.lifc_buf);
  return ret;
}

/* Get interface's index by ioctl. */
int
if_get_index (struct interface *ifp)
{
  int ret;
  struct lifreq lifreq;

  lifreq_set_name (&lifreq, ifp);

  if (ifp->flags & IFF_IPV4)
    ret = AF_IOCTL (AF_INET, SIOCGLIFINDEX, (caddr_t) & lifreq);
  else if (ifp->flags & IFF_IPV6)
    ret = AF_IOCTL (AF_INET6, SIOCGLIFINDEX, (caddr_t) & lifreq);
  else
    ret = -1;

  if (ret < 0)
    {
      zlog_warn ("SIOCGLIFINDEX(%s) failed", ifp->name);
      return ret;
    }

  /* OK we got interface index. */
#ifdef ifr_ifindex
  ifp->ifindex = lifreq.lifr_ifindex;
#else
  ifp->ifindex = lifreq.lifr_index;
#endif
  return ifp->ifindex;

}


/* Interface address lookup by ioctl.  This function only looks up
   IPv4 address. */
#define ADDRLEN(sa) (((sa)->sa_family == AF_INET ?  \
                sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6)))

#define SIN(s) ((struct sockaddr_in *)(s))
#define SIN6(s) ((struct sockaddr_in6 *)(s))

static int
if_get_addr (struct interface *ifp, struct sockaddr *addr)
{
  int ret;
  struct lifreq lifreq;
  struct sockaddr_storage mask, dest;
  char *dest_pnt = NULL;
  u_char prefixlen = 0;
  afi_t af;

  /* Interface's name and address family. */
  strncpy (lifreq.lifr_name, ifp->name, IFNAMSIZ);

  /* Interface's address. */
  memcpy (&lifreq.lifr_addr, addr, ADDRLEN (addr));
  af = addr->sa_family;

  /* Point to point or broad cast address pointer init. */
  dest_pnt = NULL;

  if (ifp->flags & IFF_POINTOPOINT)
    {
      ret = AF_IOCTL (af, SIOCGLIFDSTADDR, (caddr_t) & lifreq);
        
      if (ret < 0)
        {
          zlog_warn ("SIOCGLIFDSTADDR (%s) fail: %s",
                     ifp->name, safe_strerror (errno));
          return ret;
        }
      memcpy (&dest, &lifreq.lifr_dstaddr, ADDRLEN (addr));
      if (af == AF_INET)
        dest_pnt = (char *) &(SIN (&dest)->sin_addr);
      else
        dest_pnt = (char *) &(SIN6 (&dest)->sin6_addr);
    }

  if (af == AF_INET)
    {
      ret = if_ioctl (SIOCGLIFNETMASK, (caddr_t) & lifreq);
      
      if (ret < 0)
        {
          if (errno != EADDRNOTAVAIL)
            {
              zlog_warn ("SIOCGLIFNETMASK (%s) fail: %s", ifp->name,
                         safe_strerror (errno));
              return ret;
            }
          return 0;
        }
      memcpy (&mask, &lifreq.lifr_addr, ADDRLEN (addr));

      prefixlen = ip_masklen (SIN (&mask)->sin_addr);
      if (ifp->flags & IFF_BROADCAST)
        {
          ret = if_ioctl (SIOCGLIFBRDADDR, (caddr_t) & lifreq);
          if (ret < 0)
            {
              if (errno != EADDRNOTAVAIL)
                {
                  zlog_warn ("SIOCGLIFBRDADDR (%s) fail: %s",
                             ifp->name, safe_strerror (errno));
                  return ret;
                }
              return 0;
            }
          memcpy (&dest, &lifreq.lifr_broadaddr, sizeof (struct sockaddr_in));
          dest_pnt = (char *) &SIN (&dest)->sin_addr;
        }
    }
#ifdef HAVE_IPV6
  else if (af == AF_INET6)
    {
      if (ifp->flags & IFF_POINTOPOINT)
        {
          prefixlen = IPV6_MAX_BITLEN;
        }
      else
        {
          ret = if_ioctl_ipv6 (SIOCGLIFSUBNET, (caddr_t) & lifreq);
          if (ret < 0)
            {
              zlog_warn ("SIOCGLIFSUBNET (%s) fail: %s",
                         ifp->name, safe_strerror (errno));
            }
          else
            {
              prefixlen = lifreq.lifr_addrlen;
            }
        }
    }
#endif /* HAVE_IPV6 */

  /* Set address to the interface. */
  if (af == AF_INET)
    connected_add_ipv4 (ifp, 0, &SIN (addr)->sin_addr, prefixlen,
                        (struct in_addr *) dest_pnt, NULL);
#ifdef HAVE_IPV6
  else if (af == AF_INET6)
    connected_add_ipv6 (ifp, &SIN6 (addr)->sin6_addr, prefixlen,
                        (struct in6_addr *) dest_pnt);
#endif /* HAVE_IPV6 */

  return 0;
}

/* Fetch interface information via ioctl(). */
static void
interface_info_ioctl (struct interface *ifp)
{
  if_get_index (ifp);
  if_get_flags (ifp);
  if_get_mtu (ifp);
  if_get_metric (ifp);
}

/* Lookup all interface information. */
void
interface_list ()
{
  interface_list_ioctl (AF_INET);
  interface_list_ioctl (AF_INET6);
}

struct connected *
if_lookup_linklocal (struct interface *ifp)
{
#ifdef HAVE_IPV6
  struct listnode *node;
  struct connected *ifc;

  if (ifp == NULL)
    return NULL;

  LIST_LOOP (ifp->connected, ifc, node)
    {
      if ((ifc->address->family == AF_INET6) &&
          (IN6_IS_ADDR_LINKLOCAL (&ifc->address->u.prefix6)))
        return ifc;
    }
#endif /* HAVE_IPV6 */

  return NULL;
}
