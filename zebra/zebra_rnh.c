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
#include "vrf.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"

/* Default rtm_table for all clients */
extern struct zebra_t zebrad;

static void free_state(struct rib *rib, struct route_node *rn);
static void copy_state(struct rnh *rnh, struct rib *rib,
		       struct route_node *rn);
#define lookup_rnh_table(v, f)		         \
({						 \
  struct zebra_vrf *zvrf;                        \
  struct route_table *t = NULL;                  \
  zvrf = zebra_vrf_lookup(v);                    \
  if (zvrf)                                      \
    t = zvrf->rnh_table[family2afi(f)];	         \
  t;                                             \
})

static int compare_state(struct rib *r1, struct rib *r2);
static int send_client(struct rnh *rnh, struct zserv *client, rnh_type_t type,
                       vrf_id_t vrf_id);
static void print_rnh(struct route_node *rn, struct vty *vty);

int zebra_rnh_ip_default_route = 0;
int zebra_rnh_ipv6_default_route = 0;

static inline struct route_table *get_rnh_table(vrf_id_t vrfid, int family,
						rnh_type_t type)
{
  struct zebra_vrf *zvrf;
  struct route_table *t = NULL;

  zvrf = zebra_vrf_lookup(vrfid);
  if (zvrf)
    switch (type)
      {
      case RNH_NEXTHOP_TYPE:
	t = zvrf->rnh_table[family2afi(family)];
	break;
      case RNH_IMPORT_CHECK_TYPE:
	t = zvrf->import_check_table[family2afi(family)];
	break;
      }

  return t;
}

char *rnh_str (struct rnh *rnh, char *buf, int size)
{
  prefix2str(&(rnh->node->p), buf, size);
  return buf;
}

struct rnh *
zebra_add_rnh (struct prefix *p, vrf_id_t vrfid, rnh_type_t type)
{
  struct route_table *table;
  struct route_node *rn;
  struct rnh *rnh = NULL;

  if (IS_ZEBRA_DEBUG_NHT)
    {
      char buf[PREFIX2STR_BUFFER];
      prefix2str(p, buf, sizeof (buf));
      zlog_debug("add rnh %s in vrf %d", buf, vrfid);
    }
  table = get_rnh_table(vrfid, PREFIX_FAMILY(p), type);
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
      rnh->zebra_static_route_list = list_new();
      route_lock_node (rn);
      rn->info = rnh;
      rnh->node = rn;
    }

  route_unlock_node (rn);
  return (rn->info);
}

struct rnh *
zebra_lookup_rnh (struct prefix *p, vrf_id_t vrfid, rnh_type_t type)
{
  struct route_table *table;
  struct route_node *rn;

  table = get_rnh_table(vrfid, PREFIX_FAMILY(p), type);
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
zebra_delete_rnh (struct rnh *rnh, rnh_type_t type)
{
  struct route_node *rn;

  if (!rnh || (rnh->flags & ZEBRA_NHT_DELETED) || !(rn = rnh->node))
    return;

  if (IS_ZEBRA_DEBUG_NHT)
    {
      char buf[PREFIX2STR_BUFFER];
      zlog_debug("delete rnh %s", rnh_str(rnh, buf, sizeof (buf)));
    }

  rnh->flags |= ZEBRA_NHT_DELETED;
  list_free(rnh->client_list);
  list_free(rnh->zebra_static_route_list);
  free_state(rnh->state, rn);
  XFREE(MTYPE_RNH, rn->info);
  rn->info = NULL;
  route_unlock_node (rn);
  return;
}

void
zebra_add_rnh_client (struct rnh *rnh, struct zserv *client, rnh_type_t type,
                      vrf_id_t vrf_id)
{
  if (IS_ZEBRA_DEBUG_NHT)
    {
      char buf[PREFIX2STR_BUFFER];
      zlog_debug("client %s registers rnh %s",
		 zebra_route_string(client->proto),
		 rnh_str(rnh, buf, sizeof (buf)));
    }
  if (!listnode_lookup(rnh->client_list, client))
    {
      listnode_add(rnh->client_list, client);
      send_client(rnh, client, type, vrf_id); // Pending: check if its needed
    }
}

void
zebra_remove_rnh_client (struct rnh *rnh, struct zserv *client, rnh_type_t type)
{
  if (IS_ZEBRA_DEBUG_NHT)
    {
      char buf[PREFIX2STR_BUFFER];
      zlog_debug("client %s unregisters rnh %s",
		 zebra_route_string(client->proto),
		 rnh_str(rnh, buf, sizeof (buf)));
    }
  listnode_delete(rnh->client_list, client);
  if (list_isempty(rnh->client_list) &&
      list_isempty(rnh->zebra_static_route_list))
    zebra_delete_rnh(rnh, type);
}

void
zebra_register_rnh_static_nh(struct prefix *nh, struct route_node *static_rn)
{
  struct rnh *rnh;

  rnh = zebra_add_rnh(nh, 0, RNH_NEXTHOP_TYPE);
  if (rnh && !listnode_lookup(rnh->zebra_static_route_list, static_rn))
    {
      listnode_add(rnh->zebra_static_route_list, static_rn);
    }
}

void
zebra_deregister_rnh_static_nh(struct prefix *nh, struct route_node *static_rn)
{
  struct rnh *rnh;

  rnh = zebra_lookup_rnh(nh, 0, RNH_NEXTHOP_TYPE);
  if (!rnh || (rnh->flags & ZEBRA_NHT_DELETED))
    return;

  listnode_delete(rnh->zebra_static_route_list, static_rn);

  if (list_isempty(rnh->client_list) &&
      list_isempty(rnh->zebra_static_route_list))
    zebra_delete_rnh(rnh, RNH_NEXTHOP_TYPE);
}

void
zebra_deregister_rnh_static_nexthops (struct nexthop *nexthop, struct route_node *rn)
{
  struct nexthop *nh;
  struct prefix nh_p;

  for (nh = nexthop; nh ; nh = nh->next)
    {
      if (nh->type == NEXTHOP_TYPE_IPV4)
        {
          nh_p.family = AF_INET;
          nh_p.prefixlen = IPV4_MAX_BITLEN;
          nh_p.u.prefix4 = nh->gate.ipv4;
        }
      else if (nh->type == NEXTHOP_TYPE_IPV6)
        {
          nh_p.family = AF_INET6;
          nh_p.prefixlen = IPV6_MAX_BITLEN;
          nh_p.u.prefix6 = nh->gate.ipv6;
        }
      zebra_deregister_rnh_static_nh(&nh_p, rn);
    }
}

static int
zebra_evaluate_rnh_nexthops(int family, struct rib *rib, struct route_node *prn,
			    int proto)
{
  int at_least_one = 0;
  int rmap_family;	       /* Route map has diff AF family enum */
  struct nexthop *nexthop;
  int ret;

  rmap_family = (family == AF_INET) ? AFI_IP : AFI_IP6;

  if (prn && rib)
    {
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	{
	  ret = zebra_nht_route_map_check(rmap_family, proto, &prn->p, rib,
					  nexthop);
	  if (ret != RMAP_DENYMATCH)
	    {
	      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	      at_least_one++; /* at least one valid NH */
	    }
	  else
	    {
	      UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	    }
	}
    }
  return (at_least_one);
}

int
zebra_evaluate_rnh (vrf_id_t vrfid, int family, int force, rnh_type_t type,
		    struct prefix *p)
{
  struct route_table *ptable;
  struct route_table *ntable;
  struct route_node *prn = NULL;
  struct route_node *nrn = NULL;
  struct rnh *rnh;
  struct zserv *client;
  struct listnode *node;
  struct rib *rib, *srib;
  int state_changed = 0;
  int at_least_one = 0;
  char bufn[PREFIX2STR_BUFFER];
  char bufp[PREFIX2STR_BUFFER];
  char bufs[PREFIX2STR_BUFFER];
  struct route_node *static_rn;
  struct nexthop *nexthop, *tnexthop;
  int recursing;

  ntable = get_rnh_table(vrfid, family, type);
  if (!ntable)
    {
      zlog_debug("evaluate_rnh_table: rnh table not found\n");
      return -1;
    }

  ptable = zebra_vrf_table(family2afi(family), SAFI_UNICAST, vrfid);
  if (!ptable)
    {
      zlog_debug("evaluate_rnh_table: prefix table not found\n");
      return -1;
    }

  if (p)
    nrn = route_node_lookup(ntable, p);
  else
    nrn = route_top (ntable);

  while (nrn != NULL)
    {
      if (!nrn->info)
	goto loopend;

      rnh = nrn->info;
      at_least_one = 0;

      /* free stale stuff first */
      if (prn)
	route_unlock_node(prn);

      prn = route_node_match(ptable, &nrn->p);

      /* Do not resolve over default route unless allowed &&
       * match route to be exact if so specified
       */
      if (!prn)
	rib = NULL;
      else if ((type == RNH_NEXTHOP_TYPE) &&
               (is_default_prefix (&prn->p) &&
                !nh_resolve_via_default(prn->p.family)))
	rib = NULL;
      else if ((type == RNH_IMPORT_CHECK_TYPE) &&
	       ((is_default_prefix(&prn->p)) ||
		((CHECK_FLAG(rnh->flags, ZEBRA_NHT_EXACT_MATCH)) &&
		 !prefix_same(&nrn->p, &prn->p))))
	rib = NULL;
      else
	{
	  RNODE_FOREACH_RIB(prn, rib)
	    {
	      if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
		continue;
	      if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
		{
		  if (CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED))
		    {
		      if (rib->type == ZEBRA_ROUTE_CONNECT)
			break;
		    }
		  else if ((type == RNH_IMPORT_CHECK_TYPE) &&
			   (rib->type == ZEBRA_ROUTE_BGP))
		    continue;
		  else
		    break;
		}
	    }
	}

      state_changed = 0;

      /* Handle import check first as its simpler */
      if (type == RNH_IMPORT_CHECK_TYPE)
	{
	  if (rib && (rnh->state == NULL))
	    {
	      for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
		if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
		  {
		    state_changed = 1;
		    break;
		  }
	    }
	  else if (!rib && (rnh->state != NULL))
	    state_changed = 1;

	  if (compare_state(rib, rnh->state))
	    copy_state(rnh, rib, nrn);

	  if (state_changed || force)
	    {
	      if (IS_ZEBRA_DEBUG_NHT)
		{
		  prefix2str(&nrn->p, bufn, sizeof (bufn));
		  zlog_debug("rnh import check %s for %s, notifying clients\n",
			     rnh->state ? "passed" : "failed", bufn);
		}
	      /* state changed, notify clients */
	      for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client))
		{
		  send_client(rnh, client, RNH_IMPORT_CHECK_TYPE, vrfid);
		}
	    }

	  goto loopend;
	}

      /* If nexthop cannot be resolved and that is also the existing state,
       * there is nothing further to do.
       */
      if (!rib && rnh->state == NULL)
        goto loopend;

      /* Ensure prefixes we're resolving over have stayed the same */
      if (!prefix_same(&rnh->resolved_route, &prn->p))
	{
	  if (rib)
	    UNSET_FLAG(rib->status, RIB_ENTRY_NEXTHOPS_CHANGED);

	  if (prn)
	    prefix_copy(&rnh->resolved_route, &prn->p);
	  else
	    memset(&rnh->resolved_route, 0, sizeof(struct prefix));

	  copy_state(rnh, rib, nrn);
	  state_changed = 1;
	}
      else if (compare_state(rib, rnh->state))
	{
         if (rib)
           UNSET_FLAG(rib->status, RIB_ENTRY_NEXTHOPS_CHANGED);

	  copy_state(rnh, rib, nrn);
	  state_changed = 1;
	}

      if (IS_ZEBRA_DEBUG_NHT && (state_changed || force))
	{
	  prefix2str(&nrn->p, bufn, sizeof (bufn));
	  if (prn)
	    prefix2str(&prn->p, bufp, sizeof (bufp));
	  else
	    strcpy(bufp, "null");

	  zlog_debug("%s: State changed for %s/%s", __FUNCTION__, bufn, bufp);

	}

      /* Notify registered clients */
      rib = rnh->state;

      if (state_changed || force)
	{
	  for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client))
	    {
	      if (prn && rib)
		{
		  at_least_one = zebra_evaluate_rnh_nexthops(family, rib, prn,
							     client->proto);
		  if (at_least_one)
		    rnh->filtered[client->proto] = 0;
		  else
		    rnh->filtered[client->proto] = 1;
		}
	      else if (state_changed)
		rnh->filtered[client->proto] = 0;

	      if (IS_ZEBRA_DEBUG_NHT && (state_changed || force))
		zlog_debug("%srnh %s resolved through route %s - sending "
			   "nexthop %s event to clients",
			   at_least_one ? "":"(filtered)", bufn, bufp,
			   rib ? "reachable" : "unreachable");

	      send_client(rnh, client, RNH_NEXTHOP_TYPE, vrfid); /* Route-map passed */
	    }

	  /* Now evaluate static client */
	  if (prn && rib)
	    {
	      at_least_one = zebra_evaluate_rnh_nexthops(family, rib, prn,
							 ZEBRA_ROUTE_STATIC);
	      if (at_least_one)
		rnh->filtered[ZEBRA_ROUTE_STATIC] = 0;
	      else
		rnh->filtered[ZEBRA_ROUTE_STATIC] = 1;
	    }
	  else if (state_changed)
	    rnh->filtered[ZEBRA_ROUTE_STATIC] = 0;

	  for (ALL_LIST_ELEMENTS_RO(rnh->zebra_static_route_list, node,
				    static_rn))
	    {
	      RNODE_FOREACH_RIB(static_rn, srib)
		{
                  if (srib->type == ZEBRA_ROUTE_STATIC)
                    break;	/* currently works for only 1 static route. */
		}

	      if (!srib)
		{
		  if (IS_ZEBRA_DEBUG_NHT)
		    {
		      prefix2str(&static_rn->p, bufs, sizeof (bufs));
		      zlog_debug("%s: Unable to find RIB for static route %s, skipping NH resolution",
				 __FUNCTION__, bufs);
		      continue;
		    }
		}

	      /* Mark the appropriate static route's NH as filtered */
	      for (nexthop = srib->nexthop; nexthop; nexthop = nexthop->next)
		{
		  switch (nexthop->type)
		    {
		    case NEXTHOP_TYPE_IPV4:
		    case NEXTHOP_TYPE_IPV4_IFINDEX:
		      /* Don't see a use case for *_IFNAME */
		      if (nexthop->gate.ipv4.s_addr == nrn->p.u.prefix4.s_addr)
			{
			  if (at_least_one)
			    UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FILTERED);
			  else
			    SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FILTERED);
			}
		      break;
		    case NEXTHOP_TYPE_IPV6:
		    case NEXTHOP_TYPE_IPV6_IFINDEX:
		      /* Don't see a use case for *_IFNAME */
		      if (memcmp(&nexthop->gate.ipv6,&nrn->p.u.prefix6, 16) == 0)
			{
			  if (at_least_one)
			    UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FILTERED);
			  else
			    SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FILTERED);
			}
		      break;
		    default:
		      break;
		    }
		}

	      if (IS_ZEBRA_DEBUG_NHT && (state_changed || force))
		zlog_debug("%srnh %s resolved through route %s - sending "
			   "nexthop %s event to zebra",
			   at_least_one ? "":"(filtered)", bufn, bufp,
			   rib ? "reachable" : "unreachable");

	      if (srib && (state_changed || force))
		{
		  SET_FLAG(srib->flags, ZEBRA_FLAG_CHANGED);
		  SET_FLAG(srib->status, RIB_ENTRY_NEXTHOPS_CHANGED);
		  rib_queue_add(&zebrad, static_rn);
		}
	    }
	}
    loopend:
      if (p)
	{
	  route_unlock_node(nrn);
	  nrn = NULL;
	}
      else
	{
	  /* route_next takes care of unlocking nrn */
	  nrn = route_next(nrn);
	}
    }

  if (prn)
    route_unlock_node(prn);

  return 1;
}

int
zebra_dispatch_rnh_table (vrf_id_t vrf_id, int family, struct zserv *client,
			  rnh_type_t type)
{
  struct route_table *ntable;
  struct route_node *nrn;
  struct rnh *rnh;

  ntable = get_rnh_table(vrf_id, family, type);
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
	  char bufn[PREFIX2STR_BUFFER];
	  prefix2str(&nrn->p, bufn, sizeof (bufn));
	  zlog_debug("rnh %s - sending nexthop %s event to client %s", bufn,
		     rnh->state ? "reachable" : "unreachable",
		     zebra_route_string(client->proto));
	}
      send_client(rnh, client, RNH_NEXTHOP_TYPE, vrf_id);
    }
  return 1;
}

void
zebra_print_rnh_table (vrf_id_t vrfid, int af, struct vty *vty, rnh_type_t type)
{
  struct route_table *table;
  struct route_node *rn;

  table = get_rnh_table(vrfid, af, type);
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
zebra_cleanup_rnh_client (vrf_id_t vrfid, int family, struct zserv *client,
			  rnh_type_t type)
{
  struct route_table *ntable;
  struct route_node *nrn;
  struct rnh *rnh;

  ntable = get_rnh_table(vrfid, family, type);
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
	  char bufn[PREFIX2STR_BUFFER];
	  prefix2str(&nrn->p, bufn, sizeof (bufn));
	  zlog_debug("rnh %s - cleaning state for client %s", bufn,
		     zebra_route_string(client->proto));
	}
      zebra_remove_rnh_client(rnh, client, type);
    }
  return 1;
}

/**
 * free_state - free up the rib structure associated with the rnh.
 */
static void
free_state (struct rib *rib, struct route_node *rn)
{

  if (!rib)
    return;

  /* free RIB and nexthops */
  nexthops_free(rib->nexthop);
  zebra_deregister_rnh_static_nexthops (rib->nexthop, rn);
  XFREE (MTYPE_RIB, rib);
}

static void
copy_state (struct rnh *rnh, struct rib *rib, struct route_node *rn)
{
  struct rib *state;
  struct nexthop *nh;

  if (rnh->state)
    {
      free_state(rnh->state, rn);
      rnh->state = NULL;
    }

  if (!rib)
    return;

  state = XCALLOC (MTYPE_RIB, sizeof (struct rib));
  state->type = rib->type;
  state->metric = rib->metric;

  for (nh = rib->nexthop; nh; nh = nh->next)
    rib_copy_nexthops(state, nh);
  rnh->state = state;
}

static int
compare_state (struct rib *r1, struct rib *r2)
{

  if (!r1 && !r2)
    return 0;

  if ((!r1 && r2) || (r1 && !r2))
      return 1;

  if (r1->metric != r2->metric)
      return 1;

  if (r1->nexthop_num != r2->nexthop_num)
      return 1;

  if (CHECK_FLAG(r1->status, RIB_ENTRY_NEXTHOPS_CHANGED))
    return 1;

  return 0;
}

static int
send_client (struct rnh *rnh, struct zserv *client, rnh_type_t type, vrf_id_t vrf_id)
{
  struct stream *s;
  struct rib *rib;
  unsigned long nump;
  u_char num;
  struct nexthop *nexthop;
  struct route_node *rn;
  int cmd = (type == RNH_IMPORT_CHECK_TYPE)
    ? ZEBRA_IMPORT_CHECK_UPDATE : ZEBRA_NEXTHOP_UPDATE;

  rn = rnh->node;
  rib = rnh->state;

  /* Get output stream. */
  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, cmd, vrf_id);

  stream_putw(s, rn->p.family);
  switch (rn->p.family)
    {
    case AF_INET:
      stream_putc(s, rn->p.prefixlen);
      stream_put_in_addr(s, &rn->p.u.prefix4);
      break;
    case AF_INET6:
      stream_putc(s, rn->p.prefixlen);
      stream_put(s, &rn->p.u.prefix6, IPV6_MAX_BYTELEN);
      break;
    default:
      zlog_err("%s: Unknown family (%d) notification attempted\n",
	       __FUNCTION__, rn->p.family);
      break;
    }
  if (rib)
    {
      stream_putl (s, rib->metric);
      num = 0;
      nump = stream_get_endp(s);
      stream_putc (s, 0);
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	if ((CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ||
             CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE)) &&
	    CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
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

  client->nh_last_upd_time = quagga_time(NULL);
  client->last_write_cmd = cmd;
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
  vty_out(vty, "%s%s%s", inet_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ),
	  CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED) ? "(Connected)" : "",
	  VTY_NEWLINE);
  if (rnh->state)
    {
      vty_out(vty, " resolved via %s%s",
	      zebra_route_string(rnh->state->type), VTY_NEWLINE);
      for (nexthop = rnh->state->nexthop; nexthop; nexthop = nexthop->next)
	print_nh(nexthop, vty);
    }
  else
    vty_out(vty, " unresolved%s%s",
	    CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED) ? "(Connected)" : "",
	    VTY_NEWLINE);

  vty_out(vty, " Client list:");
  for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client))
    vty_out(vty, " %s(fd %d)%s", zebra_route_string(client->proto),
	    client->sock, rnh->filtered[client->proto] ? "(filtered)" : "");
  if (!list_isempty(rnh->zebra_static_route_list))
    vty_out(vty, " zebra%s", rnh->filtered[ZEBRA_ROUTE_STATIC] ? "(filtered)" : "");
  vty_out(vty, "%s", VTY_NEWLINE);
}
