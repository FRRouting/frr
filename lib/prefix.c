/*
 * Prefix related functions.
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

#include "prefix.h"
#include "vty.h"
#include "sockunion.h"
#include "memory.h"
#include "log.h"

/* Maskbit. */
static const u_char maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
			         0xf8, 0xfc, 0xfe, 0xff};
static const u_int32_t maskbytes_host[] =
{
  0x00000000, /* /0  0.0.0.0         */
  0x80000000, /* /1  128.0.0.0       */
  0xc0000000, /* /2  192.0.0.0       */
  0xe0000000, /* /3  224.0.0.0       */
  0xf0000000, /* /4  240.0.0.0       */
  0xf8000000, /* /5  248.0.0.0       */
  0xfc000000, /* /6  252.0.0.0       */
  0xfe000000, /* /7  254.0.0.0       */
  0xff000000, /* /8  255.0.0.0       */
  0xff800000, /* /9  255.128.0.0     */
  0xffc00000, /* /10 255.192.0.0     */
  0xffe00000, /* /11 255.224.0.0     */
  0xfff00000, /* /12 255.240.0.0     */
  0xfff80000, /* /13 255.248.0.0     */
  0xfffc0000, /* /14 255.252.0.0     */
  0xfffe0000, /* /15 255.254.0.0     */
  0xffff0000, /* /16 255.255.0.0     */
  0xffff8000, /* /17 255.255.128.0   */
  0xffffc000, /* /18 255.255.192.0   */
  0xffffe000, /* /19 255.255.224.0   */
  0xfffff000, /* /20 255.255.240.0   */
  0xfffff800, /* /21 255.255.248.0   */
  0xfffffc00, /* /22 255.255.252.0   */
  0xfffffe00, /* /23 255.255.254.0   */
  0xffffff00, /* /24 255.255.255.0   */
  0xffffff80, /* /25 255.255.255.128 */
  0xffffffc0, /* /26 255.255.255.192 */
  0xffffffe0, /* /27 255.255.255.224 */
  0xfffffff0, /* /28 255.255.255.240 */
  0xfffffff8, /* /29 255.255.255.248 */
  0xfffffffc, /* /30 255.255.255.252 */
  0xfffffffe, /* /31 255.255.255.254 */
  0xffffffff  /* /32 255.255.255.255 */
};
static const u_int32_t maskbytes_network[] =
{
  0x00000000, /* /0  0.0.0.0         */
  0x00000080, /* /1  128.0.0.0       */
  0x000000c0, /* /2  192.0.0.0       */
  0x000000e0, /* /3  224.0.0.0       */
  0x000000f0, /* /4  240.0.0.0       */
  0x000000f8, /* /5  248.0.0.0       */
  0x000000fc, /* /6  252.0.0.0       */
  0x000000fe, /* /7  254.0.0.0       */
  0x000000ff, /* /8  255.0.0.0       */
  0x000080ff, /* /9  255.128.0.0     */
  0x0000c0ff, /* /10 255.192.0.0     */
  0x0000e0ff, /* /11 255.224.0.0     */
  0x0000f0ff, /* /12 255.240.0.0     */
  0x0000f8ff, /* /13 255.248.0.0     */
  0x0000fcff, /* /14 255.252.0.0     */
  0x0000feff, /* /15 255.254.0.0     */
  0x0000ffff, /* /16 255.255.0.0     */
  0x0080ffff, /* /17 255.255.128.0   */
  0x00c0ffff, /* /18 255.255.192.0   */
  0x00e0ffff, /* /19 255.255.224.0   */
  0x00f0ffff, /* /20 255.255.240.0   */
  0x00f8ffff, /* /21 255.255.248.0   */
  0x00fcffff, /* /22 255.255.252.0   */
  0x00feffff, /* /23 255.255.254.0   */
  0x00ffffff, /* /24 255.255.255.0   */
  0x80ffffff, /* /25 255.255.255.128 */
  0xc0ffffff, /* /26 255.255.255.192 */
  0xe0ffffff, /* /27 255.255.255.224 */
  0xf0ffffff, /* /28 255.255.255.240 */
  0xf8ffffff, /* /29 255.255.255.248 */
  0xfcffffff, /* /30 255.255.255.252 */
  0xfeffffff, /* /31 255.255.255.254 */
  0xffffffff  /* /32 255.255.255.255 */
};

/* Number of bits in prefix type. */
#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

#define MASKBIT(offset)  ((0xff << (PNBBY - (offset))) & 0xff)

/* Address Famiy Identifier to Address Family converter. */
int
afi2family (afi_t afi)
{
  if (afi == AFI_IP)
    return AF_INET;
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    return AF_INET6;
#endif /* HAVE_IPV6 */
  return 0;
}

afi_t
family2afi (int family)
{
  if (family == AF_INET)
    return AFI_IP;
#ifdef HAVE_IPV6
  else if (family == AF_INET6)
    return AFI_IP6;
#endif /* HAVE_IPV6 */
  return 0;
}

/* If n includes p prefix then return 1 else return 0. */
int
prefix_match (const struct prefix *n, const struct prefix *p)
{
  int offset;
  int shift;
  const u_char *np, *pp;

  /* If n's prefix is longer than p's one return 0. */
  if (n->prefixlen > p->prefixlen)
    return 0;

  /* Set both prefix's head pointer. */
  np = (const u_char *)&n->u.prefix;
  pp = (const u_char *)&p->u.prefix;
  
  offset = n->prefixlen / PNBBY;
  shift =  n->prefixlen % PNBBY;

  if (shift)
    if (maskbit[shift] & (np[offset] ^ pp[offset]))
      return 0;
  
  while (offset--)
    if (np[offset] != pp[offset])
      return 0;
  return 1;
}

/* Copy prefix from src to dest. */
void
prefix_copy (struct prefix *dest, const struct prefix *src)
{
  dest->family = src->family;
  dest->prefixlen = src->prefixlen;

  if (src->family == AF_INET)
    dest->u.prefix4 = src->u.prefix4;
#ifdef HAVE_IPV6
  else if (src->family == AF_INET6)
    dest->u.prefix6 = src->u.prefix6;
#endif /* HAVE_IPV6 */
  else if (src->family == AF_UNSPEC)
    {
      dest->u.lp.id = src->u.lp.id;
      dest->u.lp.adv_router = src->u.lp.adv_router;
    }
  else
    {
      zlog (NULL, LOG_ERR, "prefix_copy(): Unknown address family %d",
	      src->family);
      assert (0);
    }
}

/* 
 * Return 1 if the address/netmask contained in the prefix structure
 * is the same, and else return 0.  For this routine, 'same' requires
 * that not only the prefix length and the network part be the same,
 * but also the host part.  Thus, 10.0.0.1/8 and 10.0.0.2/8 are not
 * the same.  Note that this routine has the same return value sense
 * as '==' (which is different from prefix_cmp).
 */
int
prefix_same (const struct prefix *p1, const struct prefix *p2)
{
  if (p1->family == p2->family && p1->prefixlen == p2->prefixlen)
    {
      if (p1->family == AF_INET)
	if (IPV4_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
	  return 1;
#ifdef HAVE_IPV6
      if (p1->family == AF_INET6 )
	if (IPV6_ADDR_SAME (&p1->u.prefix, &p2->u.prefix))
	  return 1;
#endif /* HAVE_IPV6 */
    }
  return 0;
}

/*
 * Return 0 if the network prefixes represented by the struct prefix
 * arguments are the same prefix, and 1 otherwise.  Network prefixes
 * are considered the same if the prefix lengths are equal and the
 * network parts are the same.  Host bits (which are considered masked
 * by the prefix length) are not significant.  Thus, 10.0.0.1/8 and
 * 10.0.0.2/8 are considered equivalent by this routine.  Note that
 * this routine has the same return sense as strcmp (which is different
 * from prefix_same).
 */
int
prefix_cmp (const struct prefix *p1, const struct prefix *p2)
{
  int offset;
  int shift;

  /* Set both prefix's head pointer. */
  const u_char *pp1 = (const u_char *)&p1->u.prefix;
  const u_char *pp2 = (const u_char *)&p2->u.prefix;

  if (p1->family != p2->family || p1->prefixlen != p2->prefixlen)
    return 1;

  offset = p1->prefixlen / 8;
  shift = p1->prefixlen % 8;

  if (shift)
    if (maskbit[shift] & (pp1[offset] ^ pp2[offset]))
      return 1;

  while (offset--)
    if (pp1[offset] != pp2[offset])
      return 1;

  return 0;
}

/* Return prefix family type string. */
const char *
prefix_family_str (const struct prefix *p)
{
  if (p->family == AF_INET)
    return "inet";
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    return "inet6";
#endif /* HAVE_IPV6 */
  return "unspec";
}

/* Allocate new prefix_ipv4 structure. */
struct prefix_ipv4 *
prefix_ipv4_new ()
{
  struct prefix_ipv4 *p;

  /* Call prefix_new to allocate a full-size struct prefix to avoid problems
     where the struct prefix_ipv4 is cast to struct prefix and unallocated
     bytes were being referenced (e.g. in structure assignments). */
  p = (struct prefix_ipv4 *)prefix_new();
  p->family = AF_INET;
  return p;
}

/* Free prefix_ipv4 structure. */
void
prefix_ipv4_free (struct prefix_ipv4 *p)
{
  prefix_free((struct prefix *)p);
}

/* When string format is invalid return 0. */
int
str2prefix_ipv4 (const char *str, struct prefix_ipv4 *p)
{
  int ret;
  int plen;
  char *pnt;
  char *cp;

  /* Find slash inside string. */
  pnt = strchr (str, '/');

  /* String doesn't contail slash. */
  if (pnt == NULL) 
    {
      /* Convert string to prefix. */
      ret = inet_aton (str, &p->prefix);
      if (ret == 0)
	return 0;

      /* If address doesn't contain slash we assume it host address. */
      p->family = AF_INET;
      p->prefixlen = IPV4_MAX_BITLEN;

      return ret;
    }
  else
    {
      cp = XMALLOC (MTYPE_TMP, (pnt - str) + 1);
      strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';
      ret = inet_aton (cp, &p->prefix);
      XFREE (MTYPE_TMP, cp);

      /* Get prefix length. */
      plen = (u_char) atoi (++pnt);
      if (plen > IPV4_MAX_PREFIXLEN)
	return 0;

      p->family = AF_INET;
      p->prefixlen = plen;
    }

  return ret;
}

/* Convert masklen into IP address's netmask (network byte order). */
void
masklen2ip (const int masklen, struct in_addr *netmask)
{
  assert (masklen >= 0 && masklen <= 32);
  netmask->s_addr = maskbytes_network[masklen];
}

/* Convert IP address's netmask into integer. We assume netmask is
   sequential one. Argument netmask should be network byte order. */
u_char
ip_masklen (struct in_addr netmask)
{
  u_char len;
  u_char *pnt;
  u_char *end;
  u_char val;

  len = 0;
  pnt = (u_char *) &netmask;
  end = pnt + 4;

  while ((pnt < end) && (*pnt == 0xff))
    {
      len+= 8;
      pnt++;
    } 

  if (pnt < end)
    {
      val = *pnt;
      while (val)
	{
	  len++;
	  val <<= 1;
	}
    }
  return len;
}

/* Apply mask to IPv4 prefix. */
void
apply_mask_ipv4 (struct prefix_ipv4 *p)
{
  u_char *pnt;
  int index;
  int offset;

  index = p->prefixlen / 8;

  if (index < 4)
    {
      pnt = (u_char *) &p->prefix;
      offset = p->prefixlen % 8;

      pnt[index] &= maskbit[offset];
      index++;

      while (index < 4)
	pnt[index++] = 0;
    }
}

/* If prefix is 0.0.0.0/0 then return 1 else return 0. */
int
prefix_ipv4_any (const struct prefix_ipv4 *p)
{
  return (p->prefix.s_addr == 0 && p->prefixlen == 0);
}

#ifdef HAVE_IPV6

/* Allocate a new ip version 6 route */
struct prefix_ipv6 *
prefix_ipv6_new (void)
{
  struct prefix_ipv6 *p;

  /* Allocate a full-size struct prefix to avoid problems with structure
     size mismatches. */
  p = (struct prefix_ipv6 *)prefix_new();
  p->family = AF_INET6;
  return p;
}

/* Free prefix for IPv6. */
void
prefix_ipv6_free (struct prefix_ipv6 *p)
{
  prefix_free((struct prefix *)p);
}

/* If given string is valid return pin6 else return NULL */
int
str2prefix_ipv6 (const char *str, struct prefix_ipv6 *p)
{
  char *pnt;
  char *cp;
  int ret;

  pnt = strchr (str, '/');

  /* If string doesn't contain `/' treat it as host route. */
  if (pnt == NULL) 
    {
      ret = inet_pton (AF_INET6, str, &p->prefix);
      if (ret == 0)
	return 0;
      p->prefixlen = IPV6_MAX_BITLEN;
    }
  else 
    {
      int plen;

      cp = XMALLOC (0, (pnt - str) + 1);
      strncpy (cp, str, pnt - str);
      *(cp + (pnt - str)) = '\0';
      ret = inet_pton (AF_INET6, cp, &p->prefix);
      free (cp);
      if (ret == 0)
	return 0;
      plen = (u_char) atoi (++pnt);
      if (plen > 128)
	return 0;
      p->prefixlen = plen;
    }
  p->family = AF_INET6;

  return ret;
}

/* Convert struct in6_addr netmask into integer.
 * FIXME return u_char as ip_maskleni() does. */
int
ip6_masklen (struct in6_addr netmask)
{
  int len = 0;
  unsigned char val;
  unsigned char *pnt;
  
  pnt = (unsigned char *) & netmask;

  while ((*pnt == 0xff) && len < 128) 
    {
      len += 8;
      pnt++;
    } 
  
  if (len < 128) 
    {
      val = *pnt;
      while (val) 
	{
	  len++;
	  val <<= 1;
	}
    }
  return len;
}

void
masklen2ip6 (int masklen, struct in6_addr *netmask)
{
  unsigned char *pnt;
  int bit;
  int offset;

  memset (netmask, 0, sizeof (struct in6_addr));
  pnt = (unsigned char *) netmask;

  offset = masklen / 8;
  bit = masklen % 8;

  while (offset--)
    *pnt++ = 0xff;

  if (bit)
    *pnt = maskbit[bit];
}

void
apply_mask_ipv6 (struct prefix_ipv6 *p)
{
  u_char *pnt;
  int index;
  int offset;

  index = p->prefixlen / 8;

  if (index < 16)
    {
      pnt = (u_char *) &p->prefix;
      offset = p->prefixlen % 8;

      pnt[index] &= maskbit[offset];
      index++;

      while (index < 16)
	pnt[index++] = 0;
    }
}

void
str2in6_addr (const char *str, struct in6_addr *addr)
{
  int i;
  unsigned int x;

  /* %x must point to unsinged int */
  for (i = 0; i < 16; i++)
    {
      sscanf (str + (i * 2), "%02x", &x);
      addr->s6_addr[i] = x & 0xff;
    }
}
#endif /* HAVE_IPV6 */

void
apply_mask (struct prefix *p)
{
  switch (p->family)
    {
      case AF_INET:
        apply_mask_ipv4 ((struct prefix_ipv4 *)p);
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        apply_mask_ipv6 ((struct prefix_ipv6 *)p);
        break;
#endif /* HAVE_IPV6 */
      default:
        break;
    }
  return;
}

/* Utility function of convert between struct prefix <=> union sockunion.
 * FIXME This function isn't used anywhere. */
struct prefix *
sockunion2prefix (const union sockunion *dest,
		  const union sockunion *mask)
{
  if (dest->sa.sa_family == AF_INET)
    {
      struct prefix_ipv4 *p;

      p = prefix_ipv4_new ();
      p->family = AF_INET;
      p->prefix = dest->sin.sin_addr;
      p->prefixlen = ip_masklen (mask->sin.sin_addr);
      return (struct prefix *) p;
    }
#ifdef HAVE_IPV6
  if (dest->sa.sa_family == AF_INET6)
    {
      struct prefix_ipv6 *p;

      p = prefix_ipv6_new ();
      p->family = AF_INET6;
      p->prefixlen = ip6_masklen (mask->sin6.sin6_addr);
      memcpy (&p->prefix, &dest->sin6.sin6_addr, sizeof (struct in6_addr));
      return (struct prefix *) p;
    }
#endif /* HAVE_IPV6 */
  return NULL;
}

/* Utility function of convert between struct prefix <=> union sockunion. */
struct prefix *
sockunion2hostprefix (const union sockunion *su)
{
  if (su->sa.sa_family == AF_INET)
    {
      struct prefix_ipv4 *p;

      p = prefix_ipv4_new ();
      p->family = AF_INET;
      p->prefix = su->sin.sin_addr;
      p->prefixlen = IPV4_MAX_BITLEN;
      return (struct prefix *) p;
    }
#ifdef HAVE_IPV6
  if (su->sa.sa_family == AF_INET6)
    {
      struct prefix_ipv6 *p;

      p = prefix_ipv6_new ();
      p->family = AF_INET6;
      p->prefixlen = IPV6_MAX_BITLEN;
      memcpy (&p->prefix, &su->sin6.sin6_addr, sizeof (struct in6_addr));
      return (struct prefix *) p;
    }
#endif /* HAVE_IPV6 */
  return NULL;
}

int
prefix_blen (const struct prefix *p)
{
  switch (p->family) 
    {
    case AF_INET:
      return IPV4_MAX_BYTELEN;
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      return IPV6_MAX_BYTELEN;
      break;
#endif /* HAVE_IPV6 */
    }
  return 0;
}

/* Generic function for conversion string to struct prefix. */
int
str2prefix (const char *str, struct prefix *p)
{
  int ret;

  /* First we try to convert string to struct prefix_ipv4. */
  ret = str2prefix_ipv4 (str, (struct prefix_ipv4 *) p);
  if (ret)
    return ret;

#ifdef HAVE_IPV6
  /* Next we try to convert string to struct prefix_ipv6. */
  ret = str2prefix_ipv6 (str, (struct prefix_ipv6 *) p);
  if (ret)
    return ret;
#endif /* HAVE_IPV6 */

  return 0;
}

int
prefix2str (const struct prefix *p, char *str, int size)
{
  char buf[BUFSIZ];

  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ);
  snprintf (str, size, "%s/%d", buf, p->prefixlen);
  return 0;
}

struct prefix *
prefix_new ()
{
  struct prefix *p;

  p = XCALLOC (MTYPE_PREFIX, sizeof *p);
  return p;
}

/* Free prefix structure. */
void
prefix_free (struct prefix *p)
{
  XFREE (MTYPE_PREFIX, p);
}

/* Utility function.  Check the string only contains digit
 * character.
 * FIXME str.[c|h] would be better place for this function. */
int
all_digit (const char *str)
{
  for (; *str != '\0'; str++)
    if (!isdigit ((int) *str))
      return 0;
  return 1;
}

/* Utility function to convert ipv4 prefixes to Classful prefixes */
void apply_classful_mask_ipv4 (struct prefix_ipv4 *p)
{

  u_int32_t destination;
  
  destination = ntohl (p->prefix.s_addr);
  
  if (p->prefixlen == IPV4_MAX_PREFIXLEN);
  /* do nothing for host routes */
  else if (IN_CLASSC (destination)) 
    {
      p->prefixlen=24;
      apply_mask_ipv4(p);
    }
  else if (IN_CLASSB(destination)) 
    {
      p->prefixlen=16;
      apply_mask_ipv4(p);
    }
  else 
    {
      p->prefixlen=8;
      apply_mask_ipv4(p);
    }
}

in_addr_t
ipv4_network_addr (in_addr_t hostaddr, int masklen)
{
  struct in_addr mask;

  masklen2ip (masklen, &mask);
  return hostaddr & mask.s_addr;
}

in_addr_t
ipv4_broadcast_addr (in_addr_t hostaddr, int masklen)
{
  struct in_addr mask;

  masklen2ip (masklen, &mask);
  return (masklen != IPV4_MAX_PREFIXLEN-1) ?
	 /* normal case */
         (hostaddr | ~mask.s_addr) :
	 /* special case for /31 */
         (hostaddr ^ ~mask.s_addr);
}

/* Utility function to convert ipv4 netmask to prefixes 
   ex.) "1.1.0.0" "255.255.0.0" => "1.1.0.0/16"
   ex.) "1.0.0.0" NULL => "1.0.0.0/8"                   */
int
netmask_str2prefix_str (const char *net_str, const char *mask_str,
			char *prefix_str)
{
  struct in_addr network;
  struct in_addr mask;
  u_char prefixlen;
  u_int32_t destination;
  int ret;

  ret = inet_aton (net_str, &network);
  if (! ret)
    return 0;

  if (mask_str)
    {
      ret = inet_aton (mask_str, &mask);
      if (! ret)
        return 0;

      prefixlen = ip_masklen (mask);
    }
  else 
    {
      destination = ntohl (network.s_addr);

      if (network.s_addr == 0)
	prefixlen = 0;
      else if (IN_CLASSC (destination))
	prefixlen = 24;
      else if (IN_CLASSB (destination))
	prefixlen = 16;
      else if (IN_CLASSA (destination))
	prefixlen = 8;
      else
	return 0;
    }

  sprintf (prefix_str, "%s/%d", net_str, prefixlen);

  return 1;
}

#ifdef HAVE_IPV6
/* Utility function for making IPv6 address string. */
const char *
inet6_ntoa (struct in6_addr addr)
{
  static char buf[INET6_ADDRSTRLEN];

  inet_ntop (AF_INET6, &addr, buf, INET6_ADDRSTRLEN);
  return buf;
}
#endif /* HAVE_IPV6 */
