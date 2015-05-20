/* Zebra next hop tracking code
 * Copyright (C) 2013 Cumulus Networks, Inc.
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
#include "table.h"
#include "memory.h"
#include "str.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "nexthop.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"

#define lookup_rnh_table(v, f)		         \
({						 \
  struct vrf *vrf;                               \
  struct route_table *t = NULL;                  \
  vrf = vrf_lookup(v);                           \
  if (vrf)                                       \
    t = vrf->rnh_table[family2afi(f)];	         \
  t;                                             \
})

static void free_state(struct rib *rib);
static void copy_state(struct rnh *rnh, struct rib *rib);
static int compare_state(struct rib *r1, struct rib *r2);
static int send_client(struct rnh *rnh, struct zserv *client);
static void print_rnh(struct route_node *rn, struct vty *vty);

char *
rnh_str (struct rnh *rnh, char *buf, int size)
{
  prefix2str(&(rnh->node->p), buf, size);
  return buf;
}

struct rnh *
zebra_add_rnh (struct prefix *p, u_int32_t vrfid)
{
  struct route_table *table;
  struct route_node *rn;
  struct rnh *rnh = NULL;

  if (IS_ZEBRA_DEBUG_NHT)
    {
      char buf[INET6_ADDRSTRLEN];
      prefix2str(p, buf, INET6_ADDRSTRLEN);
      zlog_debug("add rnh %s in vrf %d", buf, vrfid);
    }
  table = lookup_rnh_table(vrfid, PREFIX_FAMILY(p));
  if (!table)
    {
      zlog_debug("add_rnh: rnh table not found\n");
      return NULL;
    }

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask (p);

  /* Lookup (or add) route node.*/
  rn = route_node_get (table, p);

  if (!rn->info)
    {
      rnh = XCALLOC(MTYPE_RNH, sizeof(struct rnh));
      rnh->client_list = list_new();
      route_lock_node (rn);
      rn->info = rnh;
      rnh->node = rn;
    }

  route_unlock_node (rn);
  return (rn->info);
}

struct rnh *
zebra_lookup_rnh (struct prefix *p, u_int32_t vrfid)
{
  struct route_table *table;
  struct route_node *rn;

  table = lookup_rnh_table(vrfid, PREFIX_FAMILY(p));
  if (!table)
    return NULL;

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask (p);

  /* Lookup route node.*/
  rn = route_node_lookup (table, p);
  if (!rn)
    return NULL;

  route_unlock_node (rn);
  return (rn->info);
}

void
zebra_delete_rnh (struct rnh *rnh)
{
  struct route_node *rn;

  if (!rnh || !(rn = rnh->node))
    return;

  if (IS_ZEBRA_DEBUG_NHT)
    {
      char buf[INET6_ADDRSTRLEN];
      zlog_debug("delete rnh %s", rnh_str(rnh, buf, INET6_ADDRSTRLEN));
    }

  list_free(rnh->client_list);
  free_state(rnh->state);
  XFREE(MTYPE_RNH, rn->info);
  rn->info = NULL;
  route_unlock_node (rn);
  return;
}

void
zebra_add_rnh_client (struct rnh *rnh, struct zserv *client)
{
  if (IS_ZEBRA_DEBUG_NHT)
    {
      char buf[INET6_ADDRSTRLEN];
      zlog_debug("client %s registers rnh %s",
		 zebra_route_string(client->proto),
		 rnh_str(rnh, buf, INET6_ADDRSTRLEN));
    }
  if (!listnode_lookup(rnh->client_list, client))
    {
      listnode_add(rnh->client_list, client);
      send_client(rnh, client);
    }
}

void
zebra_remove_rnh_client (struct rnh *rnh, struct zserv *client)
{
  if (IS_ZEBRA_DEBUG_NHT)
    {
      char buf[INET6_ADDRSTRLEN];
      zlog_debug("client %s unregisters rnh %s",
		 zebra_route_string(client->proto),
		 rnh_str(rnh, buf, INET6_ADDRSTRLEN));
    }
  listnode_delete(rnh->client_list, client);
  if (list_isempty(rnh->client_list))
    zebra_delete_rnh(rnh);
}

int
zebra_evaluate_rnh_table (int vrfid, int family)
{
  struct route_table *ptable;
  struct route_table *ntable;
  struct route_node *prn;
  struct route_node *nrn;
  struct rnh *rnh;
  struct zserv *client;
  struct listnode *node;
  struct rib *rib;

  ntable = lookup_rnh_table(vrfid, family);
  if (!ntable)
    {
      zlog_debug("evaluate_rnh_table: rnh table not found\n");
      return -1;
    }

  ptable = vrf_table(family2afi(family), SAFI_UNICAST, vrfid);
  if (!ptable)
    {
      zlog_debug("evaluate_rnh_table: prefix table not found\n");
      return -1;
    }

  for (nrn = route_top (ntable); nrn; nrn = route_next (nrn))
    {
      if (!nrn->info)
	  continue;

      prn = route_node_match(ptable, &nrn->p);
      if (!prn)
	rib = NULL;
      else
	{
	  RNODE_FOREACH_RIB(prn, rib)
	    {
	      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
		continue;
	      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
		break;
	    }
	}

      rnh = nrn->info;
      if (compare_state(rib, rnh->state))
	{
	  if (IS_ZEBRA_DEBUG_NHT)
	    {
	      char bufn[INET6_ADDRSTRLEN];
	      char bufp[INET6_ADDRSTRLEN];
	      prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
	      if (prn)
		prefix2str(&prn->p, bufp, INET6_ADDRSTRLEN);
	      else
		strcpy(bufp, "null");
	      zlog_debug("rnh %s resolved through route %s - sending "
			 "nexthop %s event to clients", bufn, bufp,
			 rib ? "reachable" : "unreachable");
	    }
	  copy_state(rnh, rib);
	  for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client))
	    send_client(rnh, client);
	}
    }
  return 1;
}

int
zebra_dispatch_rnh_table (int vrfid, int family, struct zserv *client)
{
  struct route_table *ntable;
  struct route_node *nrn;
  struct rnh *rnh;

  ntable = lookup_rnh_table(vrfid, family);
  if (!ntable)
    {
      zlog_debug("dispatch_rnh_table: rnh table not found\n");
      return -1;
    }

  for (nrn = route_top (ntable); nrn; nrn = route_next (nrn))
    {
      if (!nrn->info)
	  continue;

      rnh = nrn->info;
      if (IS_ZEBRA_DEBUG_NHT)
	{
	  char bufn[INET6_ADDRSTRLEN];
	  prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
	  zlog_debug("rnh %s - sending nexthop %s event to client %s", bufn,
		     rnh->state ? "reachable" : "unreachable",
		     zebra_route_string(client->proto));
	}
      send_client(rnh, client);
    }
  return 1;
}

void
zebra_print_rnh_table (int vrfid, int af, struct vty *vty)
{
  struct route_table *table;
  struct route_node *rn;

  table = lookup_rnh_table(vrfid, af);
  if (!table)
    {
      zlog_debug("print_rnhs: rnh table not found\n");
      return;
    }

  for (rn = route_top(table); rn; rn = route_next(rn))
      if (rn->info)
	print_rnh(rn, vty);
}

int
zebra_cleanup_rnh_client (int vrfid, int family, struct zserv *client)
{
  struct route_table *ntable;
  struct route_node *nrn;
  struct rnh *rnh;

  ntable = lookup_rnh_table(vrfid, family);
  if (!ntable)
    {
      zlog_debug("cleanup_rnh_client: rnh table not found\n");
      return -1;
    }

  for (nrn = route_top (ntable); nrn; nrn = route_next (nrn))
    {
      if (!nrn->info)
	  continue;

      rnh = nrn->info;
      if (IS_ZEBRA_DEBUG_NHT)
	{
	  char bufn[INET6_ADDRSTRLEN];
	  prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
	  zlog_debug("rnh %s - cleaning state for client %s", bufn,
		     zebra_route_string(client->proto));
	}
      zebra_remove_rnh_client(rnh, client);
    }
  return 1;
}

/**
 * free_state - free up the rib structure associated with the rnh.
 */
static void
free_state (struct rib *rib)
{
  struct nexthop *nexthop, *next;

  if (!rib)
    return;

  /* free RIB and nexthops */
  for (nexthop = rib->nexthop; nexthop; nexthop = next)
    {
      next = nexthop->next;
      nexthop_free (nexthop);
    }
  XFREE (MTYPE_RIB, rib);
}

/**
 * copy_nexthop - copy a nexthop to the rib structure.
 */
static void
copy_nexthop (struct rib *state, struct nexthop *nh)
{
  struct nexthop *nexthop;

  nexthop = nexthop_new();
  nexthop->flags = nh->flags;
  nexthop->type = nh->type;
  nexthop->ifindex = nh->ifindex;
  if (nh->ifname)
    nexthop->ifname = XSTRDUP(0, nh->ifname);
  memcpy(&(nexthop->gate), &(nh->gate), sizeof(union g_addr));
  memcpy(&(nexthop->src), &(nh->src), sizeof(union g_addr));

  nexthop_add(state, nexthop);
}

static void
copy_state (struct rnh *rnh, struct rib *rib)
{
  struct rib *state;
  struct nexthop *nh;

  if (rnh->state)
    {
      free_state(rnh->state);
      rnh->state = NULL;
    }

  if (!rib)
    return;

  state = XCALLOC (MTYPE_RIB, sizeof (struct rib));
  state->type = rib->type;
  state->metric = rib->metric;

  for (nh = rib->nexthop; nh; nh = nh->next)
    copy_nexthop(state, nh);
  rnh->state = state;
}

static int
compare_state (struct rib *r1, struct rib *r2)
{
  struct nexthop *nh1;
  struct nexthop *nh2;
  u_char found_nh = 0;

  if (!r1 && !r2)
    return 0;

  if ((!r1 && r2) || (r1 && !r2))
      return 1;

  if (r1->metric != r2->metric)
      return 1;

  if (r1->nexthop_num != r2->nexthop_num)
      return 1;

  /* We need to verify that the nexthops for r1 match the nexthops for r2.
   * Since it is possible for a rib entry to have the same nexthop multiple
   * times (Example: [a,a]) we need to keep track of which r2 nexthops we have
   * already used as a match against a r1 nexthop.  We track this
   * via NEXTHOP_FLAG_MATCHED. Clear this flag for all r2 nexthops when you
   * are finished.
   *
   * TRUE:  r1 [a,b], r2 [a,b]
   * TRUE:  r1 [a,b], r2 [b,a]
   * FALSE: r1 [a,b], r2 [a,c]
   * FALSE: r1 [a,a], r2 [a,b]
   */
  for (nh1 = r1->nexthop; nh1; nh1 = nh1->next)
    {
      found_nh = 0;
      for (nh2 = r2->nexthop; nh2; nh2 = nh2->next)
        {
          if (CHECK_FLAG (nh2->flags, NEXTHOP_FLAG_MATCHED))
            continue;

          if (nexthop_same_no_recurse(nh1, nh2))
            {
              SET_FLAG (nh2->flags, NEXTHOP_FLAG_MATCHED);
              found_nh = 1;
              break;
            }
        }

      if (!found_nh)
        {
          for (nh2 = r2->nexthop; nh2; nh2 = nh2->next)
            if (CHECK_FLAG (nh2->flags, NEXTHOP_FLAG_MATCHED))
              UNSET_FLAG (nh2->flags, NEXTHOP_FLAG_MATCHED);
          return 1;
        }
    }

  for (nh2 = r2->nexthop; nh2; nh2 = nh2->next)
    if (CHECK_FLAG (nh2->flags, NEXTHOP_FLAG_MATCHED))
      UNSET_FLAG (nh2->flags, NEXTHOP_FLAG_MATCHED);

  return 0;
}

static int
send_client (struct rnh *rnh, struct zserv *client)
{
  struct stream *s;
  struct rib *rib;
  unsigned long nump;
  u_char num;
  struct nexthop *nexthop;
  struct route_node *rn;

  rn = rnh->node;
  rib = rnh->state;

  /* Get output stream. */
  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, ZEBRA_NEXTHOP_UPDATE);

  stream_putw(s, rn->p.family);
  stream_put_prefix (s, &rn->p);

  if (rib)
    {
      stream_putl (s, rib->metric);
      num = 0;
      nump = stream_get_endp(s);
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
	      case ZEBRA_NEXTHOP_IPV4_IFINDEX:
	      case ZEBRA_NEXTHOP_IPV4_IFNAME:
		stream_put_in_addr (s, &nexthop->gate.ipv4);
		stream_putl (s, nexthop->ifindex);
		break;
#ifdef HAVE_IPV6
	      case ZEBRA_NEXTHOP_IPV6:
		stream_put (s, &nexthop->gate.ipv6, 16);
		break;
	      case ZEBRA_NEXTHOP_IPV6_IFINDEX:
	      case ZEBRA_NEXTHOP_IPV6_IFNAME:
		stream_put (s, &nexthop->gate.ipv6, 16);
		stream_putl (s, nexthop->ifindex);
		break;
#endif /* HAVE_IPV6 */
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
  return zebra_server_send_message(client);
}

static void
print_nh (struct nexthop *nexthop, struct vty *vty)
{
  char buf[BUFSIZ];

  switch (nexthop->type)
    {
    case NEXTHOP_TYPE_IPV4:
    case NEXTHOP_TYPE_IPV4_IFINDEX:
      vty_out (vty, " via %s", inet_ntoa (nexthop->gate.ipv4));
      if (nexthop->ifindex)
	vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
      break;
    case NEXTHOP_TYPE_IPV6:
    case NEXTHOP_TYPE_IPV6_IFINDEX:
    case NEXTHOP_TYPE_IPV6_IFNAME:
      vty_out (vty, " %s",
	       inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
      if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
	vty_out (vty, ", %s", nexthop->ifname);
      else if (nexthop->ifindex)
	vty_out (vty, ", via %s", ifindex2ifname (nexthop->ifindex));
      break;
    case NEXTHOP_TYPE_IFINDEX:
      vty_out (vty, " is directly connected, %s",
	       ifindex2ifname (nexthop->ifindex));
      break;
    case NEXTHOP_TYPE_IFNAME:
      vty_out (vty, " is directly connected, %s", nexthop->ifname);
      break;
    case NEXTHOP_TYPE_BLACKHOLE:
      vty_out (vty, " is directly connected, Null0");
      break;
    default:
      break;
    }
  vty_out(vty, "%s", VTY_NEWLINE);
}

static void
print_rnh (struct route_node *rn, struct vty *vty)
{
  struct rnh *rnh;
  struct nexthop *nexthop;
  struct listnode *node;
  struct zserv *client;
  char buf[BUFSIZ];

  rnh = rn->info;
  vty_out(vty, "%s%s", inet_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ),
	  VTY_NEWLINE);
  if (rnh->state)
    {
      vty_out(vty, " resolved via %s%s",
	      zebra_route_string(rnh->state->type), VTY_NEWLINE);
      for (nexthop = rnh->state->nexthop; nexthop; nexthop = nexthop->next)
	print_nh(nexthop, vty);
    }
  else
    vty_out(vty, " unresolved%s", VTY_NEWLINE);

  vty_out(vty, " Client list:");
  for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client))
    vty_out(vty, " %s(fd %d)", zebra_route_string(client->proto),
	    client->sock);
  vty_out(vty, "%s", VTY_NEWLINE);
}
