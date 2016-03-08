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
#include "bgpd/bgp_fsm.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"	/* For ZEBRA_SERV_PATH. */



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
bgp_address_init (struct bgp *bgp)
{
  bgp->address_hash = hash_create (bgp_address_hash_key_make,
                                  bgp_address_hash_cmp);
}

static void
bgp_address_add (struct bgp *bgp, struct prefix *p)
{
  struct bgp_addr tmp;
  struct bgp_addr *addr;

  tmp.addr = p->u.prefix4;

  addr = hash_get (bgp->address_hash, &tmp, bgp_address_hash_alloc);
  if (!addr)
    return;

  addr->refcnt++;
}

static void
bgp_address_del (struct bgp *bgp, struct prefix *p)
{
  struct bgp_addr tmp;
  struct bgp_addr *addr;

  tmp.addr = p->u.prefix4;

  addr = hash_lookup (bgp->address_hash, &tmp);
  /* may have been deleted earlier by bgp_interface_down() */
  if (addr == NULL)
    return;

  addr->refcnt--;

  if (addr->refcnt == 0)
    {
      hash_release (bgp->address_hash, addr);
      XFREE (MTYPE_BGP_ADDR, addr);
    }
}


struct bgp_connected_ref
{
  unsigned int refcnt;
};

void
bgp_connected_add (struct bgp *bgp, struct connected *ifc)
{
  struct prefix p;
  struct prefix *addr;
  struct bgp_node *rn;
  struct bgp_connected_ref *bc;
  struct listnode *node, *nnode;
  struct peer *peer;

  addr = ifc->address;

  p = *(CONNECTED_PREFIX(ifc));
  if (addr->family == AF_INET)
    {
      apply_mask_ipv4 ((struct prefix_ipv4 *) &p);

      if (prefix_ipv4_any ((struct prefix_ipv4 *) &p))
	return;

      bgp_address_add (bgp, addr);

      rn = bgp_node_get (bgp->connected_table[AFI_IP], (struct prefix *) &p);
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

      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
        {
          if (peer->conf_if && (strcmp (peer->conf_if, ifc->ifp->name) == 0) &&
              !CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))
            {
              if (peer_active(peer))
                BGP_EVENT_ADD (peer, BGP_Stop);
              BGP_EVENT_ADD (peer, BGP_Start);
            }
        }
    }
#ifdef HAVE_IPV6
  else if (addr->family == AF_INET6)
    {
      apply_mask_ipv6 ((struct prefix_ipv6 *) &p);

      if (IN6_IS_ADDR_UNSPECIFIED (&p.u.prefix6))
	return;

      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
	return;

      rn = bgp_node_get (bgp->connected_table[AFI_IP6], (struct prefix *) &p);
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
bgp_connected_delete (struct bgp *bgp, struct connected *ifc)
{
  struct prefix p;
  struct prefix *addr;
  struct bgp_node *rn;
  struct bgp_connected_ref *bc;

  addr = ifc->address;

  p = *(CONNECTED_PREFIX(ifc));
  if (addr->family == AF_INET)
    {
      apply_mask_ipv4 ((struct prefix_ipv4 *) &p);

      if (prefix_ipv4_any ((struct prefix_ipv4 *) &p))
	return;

      bgp_address_del (bgp, addr);

      rn = bgp_node_lookup (bgp->connected_table[AFI_IP], &p);
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
      apply_mask_ipv6 ((struct prefix_ipv6 *) &p);

      if (IN6_IS_ADDR_UNSPECIFIED (&p.u.prefix6))
	return;

      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
	return;

      rn = bgp_node_lookup (bgp->connected_table[AFI_IP6], (struct prefix *) &p);
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
bgp_nexthop_self (struct bgp *bgp, struct attr *attr)
{
  struct bgp_addr tmp, *addr;

  tmp.addr = attr->nexthop;

  addr = hash_lookup (bgp->address_hash, &tmp);
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

  rn1 = bgp_node_match (peer->bgp->connected_table[AFI_IP], &p);
  if (!rn1)
    return 0;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = peer->su.sin.sin_addr;

  rn2 = bgp_node_match (peer->bgp->connected_table[AFI_IP], &p);
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
show_ip_bgp_nexthop_table (struct vty *vty, const char *name, int detail)
{
  struct bgp_node *rn;
  struct bgp_nexthop_cache *bnc;
  char buf[PREFIX2STR_BUFFER];
  struct nexthop *nexthop;
  time_t tbuf;
  afi_t afi;
 struct bgp *bgp;

 if (name)
   bgp = bgp_lookup_by_name (name);
 else
   bgp = bgp_get_default ();
 if (!bgp)
   {
     vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
     return CMD_WARNING;
   }

  vty_out (vty, "Current BGP nexthop cache:%s", VTY_NEWLINE);
  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
    {
      for (rn = bgp_table_top (bgp->nexthop_cache_table[afi]); rn; rn = bgp_route_next (rn))
	{
	  if ((bnc = rn->info) != NULL)
	    {
	      if (CHECK_FLAG(bnc->flags, BGP_NEXTHOP_VALID))
		{
		  vty_out (vty, " %s valid [IGP metric %d], #paths %d%s",
			   inet_ntop (rn->p.family, &rn->p.u.prefix, buf, sizeof (buf)),
			   bnc->metric, bnc->path_count, VTY_NEWLINE);
		  if (detail)
		    for (nexthop = bnc->nexthop; nexthop; nexthop = nexthop->next)
		      switch (nexthop->type)
			{
			case NEXTHOP_TYPE_IPV6:
			  vty_out (vty, "  gate %s%s",
				   inet_ntop (AF_INET6, &nexthop->gate.ipv6,
					      buf, sizeof (buf)), VTY_NEWLINE);
			  break;
			case NEXTHOP_TYPE_IPV6_IFINDEX:
			  vty_out(vty, "  gate %s, if %s%s",
				  inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf,
					    sizeof (buf)),
				  ifindex2ifname(nexthop->ifindex),
				  VTY_NEWLINE);
			  break;
			case NEXTHOP_TYPE_IPV4:
			  vty_out (vty, "  gate %s%s",
				   inet_ntop (AF_INET, &nexthop->gate.ipv4, buf,
					      sizeof (buf)), VTY_NEWLINE);
			  break;
			case NEXTHOP_TYPE_IFINDEX:
			  vty_out (vty, "  if %s%s",
				   ifindex2ifname(nexthop->ifindex), VTY_NEWLINE);
			  break;
			case NEXTHOP_TYPE_IPV4_IFINDEX:
			  vty_out (vty, "  gate %s, if %s%s",
				   inet_ntop(AF_INET, &nexthop->gate.ipv4, buf,
					     sizeof (buf)),
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
			   inet_ntop (rn->p.family, &rn->p.u.prefix,
				      buf, sizeof (buf)), VTY_NEWLINE);
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
    }
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
  return show_ip_bgp_nexthop_table (vty, NULL, 0);
}

DEFUN (show_ip_bgp_nexthop_detail,
       show_ip_bgp_nexthop_detail_cmd,
       "show ip bgp nexthop detail",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP nexthop table\n")
{
  return show_ip_bgp_nexthop_table (vty, NULL, 1);
}

DEFUN (show_ip_bgp_view_nexthop,
       show_ip_bgp_view_nexthop_cmd,
       "show ip bgp (view|vrf) WORD nexthop",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\nBGP VRF\n"
       "View/VRF name\n"
       "BGP nexthop table\n")
{
  return show_ip_bgp_nexthop_table (vty, argv[1], 0);
}

DEFUN (show_ip_bgp_view_nexthop_detail,
       show_ip_bgp_view_nexthop_detail_cmd,
       "show ip bgp (view|vrf) WORD nexthop detail",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\nBGP VRF\n"
       "View/VRF name\n"
       "BGP nexthop table\n")
{
  return show_ip_bgp_nexthop_table (vty, argv[1], 1);
}

void
bgp_scan_init (struct bgp *bgp)
{
  bgp->nexthop_cache_table[AFI_IP] = bgp_table_init (AFI_IP, SAFI_UNICAST);
  bgp->connected_table[AFI_IP] = bgp_table_init (AFI_IP, SAFI_UNICAST);
  bgp->import_check_table[AFI_IP] = bgp_table_init (AFI_IP, SAFI_UNICAST);

#ifdef HAVE_IPV6
  bgp->nexthop_cache_table[AFI_IP6] = bgp_table_init (AFI_IP6, SAFI_UNICAST);
  bgp->connected_table[AFI_IP6] = bgp_table_init (AFI_IP6, SAFI_UNICAST);
  bgp->import_check_table[AFI_IP6] = bgp_table_init (AFI_IP6, SAFI_UNICAST);
#endif /* HAVE_IPV6 */

}

void
bgp_scan_vty_init (void)
{
  install_element (ENABLE_NODE, &show_ip_bgp_nexthop_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_nexthop_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_nexthop_detail_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_nexthop_detail_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_nexthop_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_nexthop_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_nexthop_detail_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_nexthop_detail_cmd);
}

void
bgp_scan_finish (struct bgp *bgp)
{
  /* Only the current one needs to be reset. */
  bgp_nexthop_cache_reset (bgp->nexthop_cache_table[AFI_IP]);

  bgp_table_unlock (bgp->nexthop_cache_table[AFI_IP]);
  bgp->nexthop_cache_table[AFI_IP] = NULL;

  bgp_table_unlock (bgp->connected_table[AFI_IP]);
  bgp->connected_table[AFI_IP] = NULL;

  bgp_table_unlock (bgp->import_check_table[AFI_IP]);
  bgp->import_check_table[AFI_IP] = NULL;

#ifdef HAVE_IPV6
  /* Only the current one needs to be reset. */
  bgp_nexthop_cache_reset (bgp->nexthop_cache_table[AFI_IP6]);

  bgp_table_unlock (bgp->nexthop_cache_table[AFI_IP6]);
  bgp->nexthop_cache_table[AFI_IP6] = NULL;

  bgp_table_unlock (bgp->connected_table[AFI_IP6]);
  bgp->connected_table[AFI_IP6] = NULL;

  bgp_table_unlock (bgp->import_check_table[AFI_IP6]);
  bgp->import_check_table[AFI_IP6] = NULL;
#endif /* HAVE_IPV6 */
}
