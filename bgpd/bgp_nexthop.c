/* BGP nexthop scan
   Copyright (C) 2000 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "command.h"
#include "thread.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "hash.h"
#include "jhash.h"
#include "nexthop.h"
#include "queue.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_damp.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"	/* For ZEBRA_SERV_PATH. */



/* Route table for next-hop lookup cache. */
struct bgp_table *bgp_nexthop_cache_table[AFI_MAX];

/* Route table for connected route. */
static struct bgp_table *bgp_connected_table[AFI_MAX];

/* Route table for import-check */
struct bgp_table *bgp_import_check_table[AFI_MAX];

char *
bnc_str (struct bgp_nexthop_cache *bnc, char *buf, int size)
{
  prefix2str(&(bnc->node->p), buf, size);
  return buf;
}

void
bnc_nexthop_free (struct bgp_nexthop_cache *bnc)
{
  struct nexthop *nexthop;
  struct nexthop *next = NULL;

  for (nexthop = bnc->nexthop; nexthop; nexthop = next)
    {
      next = nexthop->next;
      XFREE (MTYPE_NEXTHOP, nexthop);
    }
}

struct bgp_nexthop_cache *
bnc_new (void)
{
  struct bgp_nexthop_cache *bnc;

  bnc = XCALLOC (MTYPE_BGP_NEXTHOP_CACHE, sizeof (struct bgp_nexthop_cache));
  LIST_INIT(&(bnc->paths));
  return bnc;
}

void
bnc_free (struct bgp_nexthop_cache *bnc)
{
  bnc_nexthop_free (bnc);
  XFREE (MTYPE_BGP_NEXTHOP_CACHE, bnc);
}

/* If nexthop exists on connected network return 1. */
int
bgp_nexthop_onlink (afi_t afi, struct attr *attr)
{
  struct bgp_node *rn;
  
  /* Lookup the address is onlink or not. */
  if (afi == AFI_IP)
    {
      rn = bgp_node_match_ipv4 (bgp_connected_table[AFI_IP], &attr->nexthop);
      if (rn)
	{
	  bgp_unlock_node (rn);
	  return 1;
	}
    }
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    {
      if (attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
	return 1;
      else if (attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL)
	{
	  if (IN6_IS_ADDR_LINKLOCAL (&attr->extra->mp_nexthop_global))
	    return 1;

	  rn = bgp_node_match_ipv6 (bgp_connected_table[AFI_IP6],
				      &attr->extra->mp_nexthop_global);
	  if (rn)
	    {
	      bgp_unlock_node (rn);
	      return 1;
	    }
	}
    }
#endif /* HAVE_IPV6 */
  return 0;
}

/* Reset and free all BGP nexthop cache. */
static void
bgp_nexthop_cache_reset (struct bgp_table *table)
{
  struct bgp_node *rn;
  struct bgp_nexthop_cache *bnc;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if ((bnc = rn->info) != NULL)
      {
	bnc_free (bnc);
	rn->info = NULL;
	bgp_unlock_node (rn);
      }
}

/* BGP own address structure */
struct bgp_addr
{
  struct in_addr addr;
  int refcnt;
};

static struct hash *bgp_address_hash;

static void *
bgp_address_hash_alloc (void *p)
{
  const struct in_addr *val = (const struct in_addr *)p;
  struct bgp_addr *addr;

  addr = XMALLOC (MTYPE_BGP_ADDR, sizeof (struct bgp_addr));
  addr->refcnt = 0;
  addr->addr.s_addr = val->s_addr;

  return addr;
}

static unsigned int
bgp_address_hash_key_make (void *p)
{
  const struct bgp_addr *addr = p;

  return jhash_1word(addr->addr.s_addr, 0);
}

static int
bgp_address_hash_cmp (const void *p1, const void *p2)
{
  const struct bgp_addr *addr1 = p1;
  const struct bgp_addr *addr2 = p2;

  return addr1->addr.s_addr == addr2->addr.s_addr;
}

void
bgp_address_init (void)
{
  bgp_address_hash = hash_create (bgp_address_hash_key_make,
                                  bgp_address_hash_cmp);
}

static void
bgp_address_add (struct prefix *p)
{
  struct bgp_addr tmp;
  struct bgp_addr *addr;

  tmp.addr = p->u.prefix4;

  addr = hash_get (bgp_address_hash, &tmp, bgp_address_hash_alloc);
  if (!addr)
    return;

  addr->refcnt++;
}

static void
bgp_address_del (struct prefix *p)
{
  struct bgp_addr tmp;
  struct bgp_addr *addr;

  tmp.addr = p->u.prefix4;

  addr = hash_lookup (bgp_address_hash, &tmp);
  /* may have been deleted earlier by bgp_interface_down() */
  if (addr == NULL)
    return;

  addr->refcnt--;

  if (addr->refcnt == 0)
    {
      hash_release (bgp_address_hash, addr);
      XFREE (MTYPE_BGP_ADDR, addr);
    }
}


struct bgp_connected_ref
{
  unsigned int refcnt;
};

void
bgp_connected_add (struct connected *ifc)
{
  struct prefix p;
  struct prefix *addr;
  struct interface *ifp;
  struct bgp_node *rn;
  struct bgp_connected_ref *bc;

  ifp = ifc->ifp;

  if (! ifp)
    return;

  if (if_is_loopback (ifp))
    return;

  addr = ifc->address;

  if (addr->family == AF_INET)
    {
      PREFIX_COPY_IPV4(&p, CONNECTED_PREFIX(ifc));
      apply_mask_ipv4 ((struct prefix_ipv4 *) &p);

      if (prefix_ipv4_any ((struct prefix_ipv4 *) &p))
	return;

      bgp_address_add (addr);

      rn = bgp_node_get (bgp_connected_table[AFI_IP], (struct prefix *) &p);
      if (rn->info)
	{
	  bc = rn->info;
	  bc->refcnt++;
	}
      else
	{
	  bc = XCALLOC (MTYPE_BGP_CONN, sizeof (struct bgp_connected_ref));
	  bc->refcnt = 1;
	  rn->info = bc;
	}
    }
#ifdef HAVE_IPV6
  else if (addr->family == AF_INET6)
    {
      PREFIX_COPY_IPV6(&p, CONNECTED_PREFIX(ifc));
      apply_mask_ipv6 ((struct prefix_ipv6 *) &p);

      if (IN6_IS_ADDR_UNSPECIFIED (&p.u.prefix6))
	return;

      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
	return;

      rn = bgp_node_get (bgp_connected_table[AFI_IP6], (struct prefix *) &p);
      if (rn->info)
	{
	  bc = rn->info;
	  bc->refcnt++;
	}
      else
	{
	  bc = XCALLOC (MTYPE_BGP_CONN, sizeof (struct bgp_connected_ref));
	  bc->refcnt = 1;
	  rn->info = bc;
	}
    }
#endif /* HAVE_IPV6 */
}

void
bgp_connected_delete (struct connected *ifc)
{
  struct prefix p;
  struct prefix *addr;
  struct interface *ifp;
  struct bgp_node *rn;
  struct bgp_connected_ref *bc;

  ifp = ifc->ifp;

  if (if_is_loopback (ifp))
    return;

  addr = ifc->address;

  if (addr->family == AF_INET)
    {
      PREFIX_COPY_IPV4(&p, CONNECTED_PREFIX(ifc));
      apply_mask_ipv4 ((struct prefix_ipv4 *) &p);

      if (prefix_ipv4_any ((struct prefix_ipv4 *) &p))
	return;

      bgp_address_del (addr);

      rn = bgp_node_lookup (bgp_connected_table[AFI_IP], &p);
      if (! rn)
	return;

      bc = rn->info;
      bc->refcnt--;
      if (bc->refcnt == 0)
	{
	  XFREE (MTYPE_BGP_CONN, bc);
	  rn->info = NULL;
	}
      bgp_unlock_node (rn);
      bgp_unlock_node (rn);
    }
#ifdef HAVE_IPV6
  else if (addr->family == AF_INET6)
    {
      PREFIX_COPY_IPV6(&p, CONNECTED_PREFIX(ifc));
      apply_mask_ipv6 ((struct prefix_ipv6 *) &p);

      if (IN6_IS_ADDR_UNSPECIFIED (&p.u.prefix6))
	return;

      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
	return;

      rn = bgp_node_lookup (bgp_connected_table[AFI_IP6], (struct prefix *) &p);
      if (! rn)
	return;

      bc = rn->info;
      bc->refcnt--;
      if (bc->refcnt == 0)
	{
	  XFREE (MTYPE_BGP_CONN, bc);
	  rn->info = NULL;
	}
      bgp_unlock_node (rn);
      bgp_unlock_node (rn);
    }
#endif /* HAVE_IPV6 */
}

int
bgp_nexthop_self (struct attr *attr)
{
  struct bgp_addr tmp, *addr;

  tmp.addr = attr->nexthop;

  addr = hash_lookup (bgp_address_hash, &tmp);
  if (addr)
    return 1;

  return 0;
}


int
bgp_multiaccess_check_v4 (struct in_addr nexthop, struct peer *peer)
{
  struct bgp_node *rn1;
  struct bgp_node *rn2;
  struct prefix p;
  int ret;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = nexthop;

  rn1 = bgp_node_match (bgp_connected_table[AFI_IP], &p);
  if (!rn1)
    return 0;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = peer->su.sin.sin_addr;

  rn2 = bgp_node_match (bgp_connected_table[AFI_IP], &p);
  if (!rn2)
    {
      bgp_unlock_node(rn1);
      return 0;
    }

  ret = (rn1 == rn2) ? 1 : 0;

  bgp_unlock_node(rn1);
  bgp_unlock_node(rn2);

  return (ret);
}

static int
show_ip_bgp_nexthop_table (struct vty *vty, int detail)
{
  struct bgp_node *rn;
  struct bgp_nexthop_cache *bnc;
  char buf[INET6_ADDRSTRLEN];
  struct nexthop *nexthop;
  time_t tbuf;

  vty_out (vty, "Current BGP nexthop cache:%s", VTY_NEWLINE);
  for (rn = bgp_table_top (bgp_nexthop_cache_table[AFI_IP]); rn; rn = bgp_route_next (rn))
    if ((bnc = rn->info) != NULL)
      {
	if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID))
	{
	  vty_out (vty, " %s valid [IGP metric %d], #paths %d%s",
		   inet_ntop (AF_INET, &rn->p.u.prefix4, buf, INET6_ADDRSTRLEN),
		   bnc->metric, bnc->path_count, VTY_NEWLINE);
	  if (detail)
	    for (nexthop = bnc->nexthop; nexthop; nexthop = nexthop->next)
	      switch (nexthop->type)
		{
		case NEXTHOP_TYPE_IPV4:
		  vty_out (vty, "  gate %s%s",
			   inet_ntop (AF_INET, &nexthop->gate.ipv4, buf,
				      INET6_ADDRSTRLEN), VTY_NEWLINE);
		  break;
		case NEXTHOP_TYPE_IFINDEX:
		  vty_out (vty, "  if %s%s",
			   ifindex2ifname(nexthop->ifindex), VTY_NEWLINE);
		  break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		  vty_out (vty, "  gate %s, if %s%s",
			   inet_ntop(AF_INET, &nexthop->gate.ipv4, buf,
				     INET6_ADDRSTRLEN),
			   ifindex2ifname(nexthop->ifindex), VTY_NEWLINE);
		  break;
		default:
		  vty_out (vty, "  invalid nexthop type %u%s",
			   nexthop->type, VTY_NEWLINE);
		}
	}
	else
          {
	    vty_out (vty, " %s invalid%s",
		     inet_ntop (AF_INET, &rn->p.u.prefix4, buf, INET6_ADDRSTRLEN), VTY_NEWLINE);

            if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED))
              vty_out (vty, "  Must be Connected%s", VTY_NEWLINE);
          }
#ifdef HAVE_CLOCK_MONOTONIC
	tbuf = time(NULL) - (bgp_clock() - bnc->last_update);
	vty_out (vty, "  Last update: %s", ctime(&tbuf));
#else
	vty_out (vty, "  Last update: %s", ctime(&bnc->uptime));
#endif /* HAVE_CLOCK_MONOTONIC */

	vty_out(vty, "%s", VTY_NEWLINE);
      }

#ifdef HAVE_IPV6
  {
    for (rn = bgp_table_top (bgp_nexthop_cache_table[AFI_IP6]);
         rn;
         rn = bgp_route_next (rn))
      if ((bnc = rn->info) != NULL)
	{
	  if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID))
	  {
	    vty_out (vty, " %s valid [IGP metric %d]%s",
		     inet_ntop (AF_INET6, &rn->p.u.prefix6, buf,
				INET6_ADDRSTRLEN),
		     bnc->metric, VTY_NEWLINE);
	    if (detail)
	      for (nexthop = bnc->nexthop; nexthop; nexthop = nexthop->next)
		switch (nexthop->type)
		  {
		  case NEXTHOP_TYPE_IPV6:
		    vty_out (vty, "  gate %s%s",
			     inet_ntop (AF_INET6, &nexthop->gate.ipv6,
					buf, INET6_ADDRSTRLEN), VTY_NEWLINE);
		    break;
		  case NEXTHOP_TYPE_IPV6_IFINDEX:
		    vty_out(vty, "  gate %s, if %s%s",
			    inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf,
				      INET6_ADDRSTRLEN),
			    ifindex2ifname(nexthop->ifindex),
			    VTY_NEWLINE);
		    break;
		  case NEXTHOP_TYPE_IFINDEX:
		    vty_out (vty, "  ifidx %u%s", nexthop->ifindex,
			     VTY_NEWLINE);
		    break;
		  default:
		    vty_out (vty, "  invalid nexthop type %u%s",
			     nexthop->type, VTY_NEWLINE);
		  }
	  }
	  else
            {
	      vty_out (vty, " %s invalid%s",
		       inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, INET6_ADDRSTRLEN),
		       VTY_NEWLINE);

              if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_CONNECTED))
                vty_out (vty, "  Must be Connected%s", VTY_NEWLINE);
            }
#ifdef HAVE_CLOCK_MONOTONIC
	  tbuf = time(NULL) - (bgp_clock() - bnc->last_update);
	  vty_out (vty, "  Last update: %s", ctime(&tbuf));
#else
	  vty_out (vty, "  Last update: %s", ctime(&bnc->uptime));
#endif /* HAVE_CLOCK_MONOTONIC */

	  vty_out(vty, "%s", VTY_NEWLINE);
	}
  }
#endif /* HAVE_IPV6 */
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_nexthop,
       show_ip_bgp_nexthop_cmd,
       "show ip bgp nexthop",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP nexthop table\n")
{
  return show_ip_bgp_nexthop_table (vty, 0);
}

DEFUN (show_ip_bgp_nexthop_detail,
       show_ip_bgp_nexthop_detail_cmd,
       "show ip bgp nexthop detail",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP nexthop table\n")
{
  return show_ip_bgp_nexthop_table (vty, 1);
}

void
bgp_scan_init (void)
{
  bgp_nexthop_cache_table[AFI_IP] = bgp_table_init (AFI_IP, SAFI_UNICAST);
  bgp_connected_table[AFI_IP] = bgp_table_init (AFI_IP, SAFI_UNICAST);
  bgp_import_check_table[AFI_IP] = bgp_table_init (AFI_IP, SAFI_UNICAST);

#ifdef HAVE_IPV6
  bgp_nexthop_cache_table[AFI_IP6] = bgp_table_init (AFI_IP6, SAFI_UNICAST);
  bgp_connected_table[AFI_IP6] = bgp_table_init (AFI_IP6, SAFI_UNICAST);
  bgp_import_check_table[AFI_IP6] = bgp_table_init (AFI_IP6, SAFI_UNICAST);
#endif /* HAVE_IPV6 */

}

void
bgp_scan_vty_init (void)
{
  install_element (ENABLE_NODE, &show_ip_bgp_nexthop_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_nexthop_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_nexthop_detail_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_nexthop_detail_cmd);
}

void
bgp_scan_finish (void)
{
  /* Only the current one needs to be reset. */
  bgp_nexthop_cache_reset (bgp_nexthop_cache_table[AFI_IP]);

  bgp_table_unlock (bgp_nexthop_cache_table[AFI_IP]);
  bgp_nexthop_cache_table[AFI_IP] = NULL;

  bgp_table_unlock (bgp_connected_table[AFI_IP]);
  bgp_connected_table[AFI_IP] = NULL;

  bgp_table_unlock (bgp_import_check_table[AFI_IP]);
  bgp_import_check_table[AFI_IP] = NULL;

#ifdef HAVE_IPV6
  /* Only the current one needs to be reset. */
  bgp_nexthop_cache_reset (bgp_nexthop_cache_table[AFI_IP6]);

  bgp_table_unlock (bgp_nexthop_cache_table[AFI_IP6]);
  bgp_nexthop_cache_table[AFI_IP6] = NULL;

  bgp_table_unlock (bgp_connected_table[AFI_IP6]);
  bgp_connected_table[AFI_IP6] = NULL;

  bgp_table_unlock (bgp_import_check_table[AFI_IP6]);
  bgp_import_check_table[AFI_IP6] = NULL;
#endif /* HAVE_IPV6 */
}
