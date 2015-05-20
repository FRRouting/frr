/* BGP routing information
   Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro

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
#include <json/json.h>

#include "prefix.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "str.h"
#include "log.h"
#include "routemap.h"
#include "buffer.h"
#include "sockunion.h"
#include "plist.h"
#include "thread.h"
#include "workqueue.h"
#include "queue.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_updgrp.h"

/* Extern from bgp_dump.c */
extern const char *bgp_origin_str[];
extern const char *bgp_origin_long_str[];

static struct bgp_node *
bgp_afi_node_get (struct bgp_table *table, afi_t afi, safi_t safi, struct prefix *p,
		  struct prefix_rd *prd)
{
  struct bgp_node *rn;
  struct bgp_node *prn = NULL;
  
  assert (table);
  if (!table)
    return NULL;
  
  if (safi == SAFI_MPLS_VPN)
    {
      prn = bgp_node_get (table, (struct prefix *) prd);

      if (prn->info == NULL)
	prn->info = bgp_table_init (afi, safi);
      else
	bgp_unlock_node (prn);
      table = prn->info;
    }

  rn = bgp_node_get (table, p);

  if (safi == SAFI_MPLS_VPN)
    rn->prn = prn;

  return rn;
}

/* Allocate bgp_info_extra */
static struct bgp_info_extra *
bgp_info_extra_new (void)
{
  struct bgp_info_extra *new;
  new = XCALLOC (MTYPE_BGP_ROUTE_EXTRA, sizeof (struct bgp_info_extra));
  return new;
}

static void
bgp_info_extra_free (struct bgp_info_extra **extra)
{
  if (extra && *extra)
    {
      if ((*extra)->damp_info)
        bgp_damp_info_free ((*extra)->damp_info, 0);
      
      (*extra)->damp_info = NULL;
      
      XFREE (MTYPE_BGP_ROUTE_EXTRA, *extra);
      
      *extra = NULL;
    }
}

/* Get bgp_info extra information for the given bgp_info, lazy allocated
 * if required.
 */
struct bgp_info_extra *
bgp_info_extra_get (struct bgp_info *ri)
{
  if (!ri->extra)
    ri->extra = bgp_info_extra_new();
  return ri->extra;
}

/* Free bgp route information. */
static void
bgp_info_free (struct bgp_info *binfo)
{
  if (binfo->attr)
    bgp_attr_unintern (&binfo->attr);

  bgp_unlink_nexthop(binfo);
  bgp_info_extra_free (&binfo->extra);
  bgp_info_mpath_free (&binfo->mpath);

  peer_unlock (binfo->peer); /* bgp_info peer reference */

  XFREE (MTYPE_BGP_ROUTE, binfo);
}

struct bgp_info *
bgp_info_lock (struct bgp_info *binfo)
{
  binfo->lock++;
  return binfo;
}

struct bgp_info *
bgp_info_unlock (struct bgp_info *binfo)
{
  assert (binfo && binfo->lock > 0);
  binfo->lock--;
  
  if (binfo->lock == 0)
    {
#if 0
      zlog_debug ("%s: unlocked and freeing", __func__);
      zlog_backtrace (LOG_DEBUG);
#endif
      bgp_info_free (binfo);
      return NULL;
    }

#if 0
  if (binfo->lock == 1)
    {
      zlog_debug ("%s: unlocked to 1", __func__);
      zlog_backtrace (LOG_DEBUG);
    }
#endif
  
  return binfo;
}

void
bgp_info_add (struct bgp_node *rn, struct bgp_info *ri)
{
  struct bgp_info *top;

  top = rn->info;
  
  ri->next = rn->info;
  ri->prev = NULL;
  if (top)
    top->prev = ri;
  rn->info = ri;
  
  bgp_info_lock (ri);
  bgp_lock_node (rn);
  peer_lock (ri->peer); /* bgp_info peer reference */
}

/* Do the actual removal of info from RIB, for use by bgp_process 
   completion callback *only* */
static void
bgp_info_reap (struct bgp_node *rn, struct bgp_info *ri)
{
  if (ri->next)
    ri->next->prev = ri->prev;
  if (ri->prev)
    ri->prev->next = ri->next;
  else
    rn->info = ri->next;
  
  bgp_info_mpath_dequeue (ri);
  bgp_info_unlock (ri);
  bgp_unlock_node (rn);
}

void
bgp_info_delete (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_info_set_flag (rn, ri, BGP_INFO_REMOVED);
  /* set of previous already took care of pcount */
  UNSET_FLAG (ri->flags, BGP_INFO_VALID);
}

/* undo the effects of a previous call to bgp_info_delete; typically
   called when a route is deleted and then quickly re-added before the
   deletion has been processed */
static void
bgp_info_restore (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_info_unset_flag (rn, ri, BGP_INFO_REMOVED);
  /* unset of previous already took care of pcount */
  SET_FLAG (ri->flags, BGP_INFO_VALID);
}

/* Adjust pcount as required */   
static void
bgp_pcount_adjust (struct bgp_node *rn, struct bgp_info *ri)
{
  struct bgp_table *table;

  assert (rn && bgp_node_table (rn));
  assert (ri && ri->peer && ri->peer->bgp);

  table = bgp_node_table (rn);

  /* Ignore 'pcount' for RS-client tables */
  if (table->type != BGP_TABLE_MAIN
      || ri->peer == ri->peer->bgp->peer_self)
    return;
    
  if (!BGP_INFO_COUNTABLE (ri)
      && CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
    {
          
      UNSET_FLAG (ri->flags, BGP_INFO_COUNTED);
      
      /* slight hack, but more robust against errors. */
      if (ri->peer->pcount[table->afi][table->safi])
        ri->peer->pcount[table->afi][table->safi]--;
      else
        {
          zlog_warn ("%s: Asked to decrement 0 prefix count for peer %s",
                     __func__, ri->peer->host);
          zlog_backtrace (LOG_WARNING);
          zlog_warn ("%s: Please report to Quagga bugzilla", __func__);
        }      
    }
  else if (BGP_INFO_COUNTABLE (ri)
           && !CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
    {
      SET_FLAG (ri->flags, BGP_INFO_COUNTED);
      ri->peer->pcount[table->afi][table->safi]++;
    }
}


/* Set/unset bgp_info flags, adjusting any other state as needed.
 * This is here primarily to keep prefix-count in check.
 */
void
bgp_info_set_flag (struct bgp_node *rn, struct bgp_info *ri, u_int32_t flag)
{
  SET_FLAG (ri->flags, flag);
  
  /* early bath if we know it's not a flag that changes countability state */
  if (!CHECK_FLAG (flag, BGP_INFO_VALID|BGP_INFO_HISTORY|BGP_INFO_REMOVED))
    return;
  
  bgp_pcount_adjust (rn, ri);
}

void
bgp_info_unset_flag (struct bgp_node *rn, struct bgp_info *ri, u_int32_t flag)
{
  UNSET_FLAG (ri->flags, flag);
  
  /* early bath if we know it's not a flag that changes countability state */
  if (!CHECK_FLAG (flag, BGP_INFO_VALID|BGP_INFO_HISTORY|BGP_INFO_REMOVED))
    return;
  
  bgp_pcount_adjust (rn, ri);
}

/* Get MED value.  If MED value is missing and "bgp bestpath
   missing-as-worst" is specified, treat it as the worst value. */
static u_int32_t
bgp_med_value (struct attr *attr, struct bgp *bgp)
{
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    return attr->med;
  else
    {
      if (bgp_flag_check (bgp, BGP_FLAG_MED_MISSING_AS_WORST))
	return BGP_MED_MAX;
      else
	return 0;
    }
}

/* Compare two bgp route entity.  If 'new' is preferable over 'exist' return 1. */
static int
bgp_info_cmp (struct bgp *bgp, struct bgp_info *new, struct bgp_info *exist,
	      int *paths_eq, struct bgp_maxpaths_cfg *mpath_cfg, int debug,
              char *pfx_buf)
{
  struct attr *newattr, *existattr;
  struct attr_extra *newattre, *existattre;
  bgp_peer_sort_t new_sort;
  bgp_peer_sort_t exist_sort;
  u_int32_t new_pref;
  u_int32_t exist_pref;
  u_int32_t new_med;
  u_int32_t exist_med;
  u_int32_t new_weight;
  u_int32_t exist_weight;
  uint32_t newm, existm;
  struct in_addr new_id;
  struct in_addr exist_id;
  int new_cluster;
  int exist_cluster;
  int internal_as_route;
  int confed_as_route;
  int ret;

  *paths_eq = 0;

  /* 0. Null check. */
  if (new == NULL)
    {
      if (debug)
        zlog_debug("%s: new is NULL", pfx_buf);
      return 0;
    }

  if (exist == NULL)
    {
      if (debug)
        zlog_debug("%s: path %s is the initial bestpath",
                   pfx_buf, new->peer->host);
      return 1;
    }

  newattr = new->attr;
  existattr = exist->attr;
  newattre = newattr->extra;
  existattre = existattr->extra;

  /* 1. Weight check. */
  new_weight = exist_weight = 0;

  if (newattre)
    new_weight = newattre->weight;
  if (existattre)
    exist_weight = existattre->weight;

  if (new_weight > exist_weight)
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to weight %d > %d",
                   pfx_buf, new->peer->host, exist->peer->host, new_weight,
                   exist_weight);
      return 1;
    }

  if (new_weight < exist_weight)
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to weight %d < %d",
                   pfx_buf, new->peer->host, exist->peer->host, new_weight,
                   exist_weight);
      return 0;
    }

  /* 2. Local preference check. */
  new_pref = exist_pref = bgp->default_local_pref;

  if (newattr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    new_pref = newattr->local_pref;
  if (existattr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    exist_pref = existattr->local_pref;

  if (new_pref > exist_pref)
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to localpref %d > %d",
                   pfx_buf, new->peer->host, exist->peer->host, new_pref,
                   exist_pref);
      return 1;
    }

  if (new_pref < exist_pref)
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to localpref %d < %d",
                   pfx_buf, new->peer->host, exist->peer->host, new_pref,
                   exist_pref);
      return 0;
    }

  /* 3. Local route check. We prefer:
   *  - BGP_ROUTE_STATIC
   *  - BGP_ROUTE_AGGREGATE
   *  - BGP_ROUTE_REDISTRIBUTE
   */
  if (! (new->sub_type == BGP_ROUTE_NORMAL))
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to preferred BGP_ROUTE type",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 1;
    }

  if (! (exist->sub_type == BGP_ROUTE_NORMAL))
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to preferred BGP_ROUTE type",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 0;
    }

  /* 4. AS path length check. */
  if (! bgp_flag_check (bgp, BGP_FLAG_ASPATH_IGNORE))
    {
      int exist_hops = aspath_count_hops (existattr->aspath);
      int exist_confeds = aspath_count_confeds (existattr->aspath);
      
      if (bgp_flag_check (bgp, BGP_FLAG_ASPATH_CONFED))
	{
	  int aspath_hops;
	  
	  aspath_hops = aspath_count_hops (newattr->aspath);
          aspath_hops += aspath_count_confeds (newattr->aspath);
          
	  if ( aspath_hops < (exist_hops + exist_confeds))
            {
              if (debug)
                zlog_debug("%s: path %s wins over path %s due to aspath (with confeds) hopcount %d < %d",
                           pfx_buf, new->peer->host, exist->peer->host,
                           aspath_hops, (exist_hops + exist_confeds));
	      return 1;
            }

	  if ( aspath_hops > (exist_hops + exist_confeds))
            {
              if (debug)
                zlog_debug("%s: path %s loses to path %s due to aspath (with confeds) hopcount %d > %d",
                           pfx_buf, new->peer->host, exist->peer->host,
                           aspath_hops, (exist_hops + exist_confeds));
	      return 0;
            }
	}
      else
	{
	  int newhops = aspath_count_hops (newattr->aspath);
	  
	  if (newhops < exist_hops)
            {
              if (debug)
                zlog_debug("%s: path %s wins over path %s due to aspath hopcount %d < %d",
                           pfx_buf, new->peer->host, exist->peer->host,
                           newhops, exist_hops);
	      return 1;
            }

          if (newhops > exist_hops)
            {
              if (debug)
                zlog_debug("%s: path %s loses to path %s due to aspath hopcount %d > %d",
                           pfx_buf, new->peer->host, exist->peer->host,
                           newhops, exist_hops);
	      return 0;
            }
	}
    }

  /* 5. Origin check. */
  if (newattr->origin < existattr->origin)
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to ORIGIN %s < %s",
                   pfx_buf, new->peer->host, exist->peer->host,
                   bgp_origin_long_str[newattr->origin],
                   bgp_origin_long_str[existattr->origin]);
      return 1;
    }

  if (newattr->origin > existattr->origin)
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to ORIGIN %s > %s",
                   pfx_buf, new->peer->host, exist->peer->host,
                   bgp_origin_long_str[newattr->origin],
                   bgp_origin_long_str[existattr->origin]);
      return 0;
    }

  /* 6. MED check. */
  internal_as_route = (aspath_count_hops (newattr->aspath) == 0
		      && aspath_count_hops (existattr->aspath) == 0);
  confed_as_route = (aspath_count_confeds (newattr->aspath) > 0
		    && aspath_count_confeds (existattr->aspath) > 0
		    && aspath_count_hops (newattr->aspath) == 0
		    && aspath_count_hops (existattr->aspath) == 0);
  
  if (bgp_flag_check (bgp, BGP_FLAG_ALWAYS_COMPARE_MED)
      || (bgp_flag_check (bgp, BGP_FLAG_MED_CONFED)
	 && confed_as_route)
      || aspath_cmp_left (newattr->aspath, existattr->aspath)
      || aspath_cmp_left_confed (newattr->aspath, existattr->aspath)
      || internal_as_route)
    {
      new_med = bgp_med_value (new->attr, bgp);
      exist_med = bgp_med_value (exist->attr, bgp);

      if (new_med < exist_med)
        {
          if (debug)
            zlog_debug("%s: path %s wins over path %s due to MED %d < %d",
                       pfx_buf, new->peer->host, exist->peer->host, new_med,
                       exist_med);
	  return 1;
        }

      if (new_med > exist_med)
        {
          if (debug)
            zlog_debug("%s: path %s loses to path %s due to MED %d > %d",
                       pfx_buf, new->peer->host, exist->peer->host, new_med,
                       exist_med);
	  return 0;
        }
    }

  /* 7. Peer type check. */
  new_sort = new->peer->sort;
  exist_sort = exist->peer->sort;

  if (new_sort == BGP_PEER_EBGP
      && (exist_sort == BGP_PEER_IBGP || exist_sort == BGP_PEER_CONFED))
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to eBGP peer > iBGP peeer",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 1;
    }

  if (exist_sort == BGP_PEER_EBGP
      && (new_sort == BGP_PEER_IBGP || new_sort == BGP_PEER_CONFED))
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to iBGP peer < eBGP peeer",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 0;
    }

  /* 8. IGP metric check. */
  newm = existm = 0;

  if (new->extra)
    newm = new->extra->igpmetric;
  if (exist->extra)
    existm = exist->extra->igpmetric;

  if (newm < existm)
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to IGP metric %d < %d",
                   pfx_buf, new->peer->host, exist->peer->host, newm, existm);
      ret = 1;
    }

  if (newm > existm)
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to IGP metric %d > %d",
                   pfx_buf, new->peer->host, exist->peer->host, newm, existm);
      ret = 0;
    }

  /* 8.1. Same IGP metric. Compare the cluster list length as
     representative of IGP hops metric. Rewrite the metric value
     pair (newm, existm) with the cluster list length. Prefer the
     path with smaller cluster list length.                       */
  if (newm == existm)
    {
      if (peer_sort (new->peer) == BGP_PEER_IBGP
	  && peer_sort (exist->peer) == BGP_PEER_IBGP
	  && CHECK_FLAG (mpath_cfg->ibgp_flags,
			 BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN))
	{
	  newm = BGP_CLUSTER_LIST_LENGTH(new->attr);
	  existm = BGP_CLUSTER_LIST_LENGTH(exist->attr);

	  if (newm < existm)
            {
              if (debug)
                zlog_debug("%s: path %s wins over path %s due to CLUSTER_LIST length %d < %d",
                           pfx_buf, new->peer->host, exist->peer->host, newm,
                           existm);
	      ret = 1;
            }

	  if (newm > existm)
            {
              if (debug)
                zlog_debug("%s: path %s loses to path %s due to CLUSTER_LIST length %d > %d",
                           pfx_buf, new->peer->host, exist->peer->host, newm,
                           existm);
	      ret = 0;
            }
	}
    }

  /* 9. Maximum path check. */
  if (newm == existm)
    {
      if (bgp_flag_check(bgp, BGP_FLAG_ASPATH_MULTIPATH_RELAX))
        {

	  /*
	   * For the two paths, all comparison steps till IGP metric
	   * have succeeded - including AS_PATH hop count. Since 'bgp
	   * bestpath as-path multipath-relax' knob is on, we don't need
	   * an exact match of AS_PATH. Thus, mark the paths are equal.
	   * That will trigger both these paths to get into the multipath
	   * array.
	   */
	  *paths_eq = 1;

          if (debug)
            zlog_debug("%s: path %s and path %s are equal via multipath-relax",
                       pfx_buf, new->peer->host, exist->peer->host);
        }
      else if (new->peer->sort == BGP_PEER_IBGP)
	{
	  if (aspath_cmp (new->attr->aspath, exist->attr->aspath))
            {
	      *paths_eq = 1;

              if (debug)
                zlog_debug("%s: path %s and path %s are equal via matching aspaths",
                           pfx_buf, new->peer->host, exist->peer->host);
            }
	}
      else if (new->peer->as == exist->peer->as)
        {
	  *paths_eq = 1;

          if (debug)
            zlog_debug("%s: path %s and path %s are equal via same remote-as",
                       pfx_buf, new->peer->host, exist->peer->host);
        }
    }
  else
    {
      /*
       * TODO: If unequal cost ibgp multipath is enabled we can
       * mark the paths as equal here instead of returning
       */
      return ret;
    }

  /* 10. If both paths are external, prefer the path that was received
     first (the oldest one).  This step minimizes route-flap, since a
     newer path won't displace an older one, even if it was the
     preferred route based on the additional decision criteria below.  */
  if (! bgp_flag_check (bgp, BGP_FLAG_COMPARE_ROUTER_ID)
      && new_sort == BGP_PEER_EBGP
      && exist_sort == BGP_PEER_EBGP)
    {
      if (CHECK_FLAG (new->flags, BGP_INFO_SELECTED))
        {
          if (debug)
              zlog_debug("%s: path %s wins over path %s due to oldest external",
                         pfx_buf, new->peer->host, exist->peer->host);
	  return 1;
        }

      if (CHECK_FLAG (exist->flags, BGP_INFO_SELECTED))
        {
          if (debug)
              zlog_debug("%s: path %s loses to path %s due to oldest external",
                         pfx_buf, new->peer->host, exist->peer->host);
	  return 0;
        }
    }

  /* 11. Router-ID comparision. */
  /* If one of the paths is "stale", the corresponding peer router-id will
   * be 0 and would always win over the other path. If originator id is
   * used for the comparision, it will decide which path is better.
   */
  if (newattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
    new_id.s_addr = newattre->originator_id.s_addr;
  else
    new_id.s_addr = new->peer->remote_id.s_addr;
  if (existattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
    exist_id.s_addr = existattre->originator_id.s_addr;
  else
    exist_id.s_addr = exist->peer->remote_id.s_addr;

  if (ntohl (new_id.s_addr) < ntohl (exist_id.s_addr))
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to Router-ID comparison",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 1;
    }

  if (ntohl (new_id.s_addr) > ntohl (exist_id.s_addr))
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to Router-ID comparison",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 0;
    }

  /* 12. Cluster length comparision. */
  new_cluster = BGP_CLUSTER_LIST_LENGTH(new->attr);
  exist_cluster = BGP_CLUSTER_LIST_LENGTH(exist->attr);

  if (new_cluster < exist_cluster)
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to CLUSTER_LIST length %d < %d",
                   pfx_buf, new->peer->host, exist->peer->host, new_cluster,
                   exist_cluster);
      return 1;
    }

  if (new_cluster > exist_cluster)
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to CLUSTER_LIST length %d > %d",
                   pfx_buf, new->peer->host, exist->peer->host, new_cluster,
                   exist_cluster);
      return 0;
    }

  /* 13. Neighbor address comparision. */
  /* Do this only if neither path is "stale" as stale paths do not have
   * valid peer information (as the connection may or may not be up).
   */
  if (CHECK_FLAG (exist->flags, BGP_INFO_STALE))
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to latter path being STALE",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 1;
    }

  if (CHECK_FLAG (new->flags, BGP_INFO_STALE))
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to former path being STALE",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 0;
    }

  ret = sockunion_cmp (new->peer->su_remote, exist->peer->su_remote);

  if (ret == 1)
    {
      if (debug)
        zlog_debug("%s: path %s loses to path %s due to Neighor IP comparison",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 0;
    }

  if (ret == -1)
    {
      if (debug)
        zlog_debug("%s: path %s wins over path %s due to Neighor IP comparison",
                   pfx_buf, new->peer->host, exist->peer->host);
      return 1;
    }

  if (debug)
    zlog_debug("%s: path %s wins over path %s due to nothing left to compare",
               pfx_buf, new->peer->host, exist->peer->host);

  return 1;
}

static enum filter_type
bgp_input_filter (struct peer *peer, struct prefix *p, struct attr *attr,
		  afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;

  filter = &peer->filter[afi][safi];

#define FILTER_EXIST_WARN(F,f,filter) \
  if (BGP_DEBUG (update, UPDATE_IN) \
      && !(F ## _IN (filter))) \
    zlog_warn ("%s: Could not find configured input %s-list %s!", \
               peer->host, #f, F ## _IN_NAME(filter));
  
  if (DISTRIBUTE_IN_NAME (filter)) {
    FILTER_EXIST_WARN(DISTRIBUTE, distribute, filter);
      
    if (access_list_apply (DISTRIBUTE_IN (filter), p) == FILTER_DENY)
      return FILTER_DENY;
  }

  if (PREFIX_LIST_IN_NAME (filter)) {
    FILTER_EXIST_WARN(PREFIX_LIST, prefix, filter);
    
    if (prefix_list_apply (PREFIX_LIST_IN (filter), p) == PREFIX_DENY)
      return FILTER_DENY;
  }
  
  if (FILTER_LIST_IN_NAME (filter)) {
    FILTER_EXIST_WARN(FILTER_LIST, as, filter);
    
    if (as_list_apply (FILTER_LIST_IN (filter), attr->aspath)== AS_FILTER_DENY)
      return FILTER_DENY;
  }
  
  return FILTER_PERMIT;
#undef FILTER_EXIST_WARN
}

static enum filter_type
bgp_output_filter (struct peer *peer, struct prefix *p, struct attr *attr,
		   afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;

  filter = &peer->filter[afi][safi];

#define FILTER_EXIST_WARN(F,f,filter) \
  if (BGP_DEBUG (update, UPDATE_OUT) \
      && !(F ## _OUT (filter))) \
    zlog_warn ("%s: Could not find configured output %s-list %s!", \
               peer->host, #f, F ## _OUT_NAME(filter));

  if (DISTRIBUTE_OUT_NAME (filter)) {
    FILTER_EXIST_WARN(DISTRIBUTE, distribute, filter);
    
    if (access_list_apply (DISTRIBUTE_OUT (filter), p) == FILTER_DENY)
      return FILTER_DENY;
  }

  if (PREFIX_LIST_OUT_NAME (filter)) {
    FILTER_EXIST_WARN(PREFIX_LIST, prefix, filter);
    
    if (prefix_list_apply (PREFIX_LIST_OUT (filter), p) == PREFIX_DENY)
      return FILTER_DENY;
  }

  if (FILTER_LIST_OUT_NAME (filter)) {
    FILTER_EXIST_WARN(FILTER_LIST, as, filter);
    
    if (as_list_apply (FILTER_LIST_OUT (filter), attr->aspath) == AS_FILTER_DENY)
      return FILTER_DENY;
  }

  return FILTER_PERMIT;
#undef FILTER_EXIST_WARN
}

/* If community attribute includes no_export then return 1. */
static int
bgp_community_filter (struct peer *peer, struct attr *attr)
{
  if (attr->community)
    {
      /* NO_ADVERTISE check. */
      if (community_include (attr->community, COMMUNITY_NO_ADVERTISE))
	return 1;

      /* NO_EXPORT check. */
      if (peer->sort == BGP_PEER_EBGP &&
	  community_include (attr->community, COMMUNITY_NO_EXPORT))
	return 1;

      /* NO_EXPORT_SUBCONFED check. */
      if (peer->sort == BGP_PEER_EBGP
	  || peer->sort == BGP_PEER_CONFED)
	if (community_include (attr->community, COMMUNITY_NO_EXPORT_SUBCONFED))
	  return 1;
    }
  return 0;
}

/* Route reflection loop check.  */
static int
bgp_cluster_filter (struct peer *peer, struct attr *attr)
{
  struct in_addr cluster_id;

  if (attr->extra && attr->extra->cluster)
    {
      if (peer->bgp->config & BGP_CONFIG_CLUSTER_ID)
	cluster_id = peer->bgp->cluster_id;
      else
	cluster_id = peer->bgp->router_id;
      
      if (cluster_loop_check (attr->extra->cluster, cluster_id))
	return 1;
    }
  return 0;
}

static int
bgp_input_modifier (struct peer *peer, struct prefix *p, struct attr *attr,
		    afi_t afi, safi_t safi, char *rmap_name)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;
  struct route_map *rmap = NULL;

  filter = &peer->filter[afi][safi];

  /* Apply default weight value. */
  if (peer->weight)
    (bgp_attr_extra_get (attr))->weight = peer->weight;

  if (rmap_name)
    {
      rmap = route_map_lookup_by_name(rmap_name);
    }
  else
    {
      if (ROUTE_MAP_IN_NAME(filter))
	rmap = ROUTE_MAP_IN (filter);
    }

  /* Route map apply. */
  if (rmap)
    {
      /* Duplicate current value to new strucutre for modification. */
      info.peer = peer;
      info.attr = attr;

      SET_FLAG (peer->rmap_type, PEER_RMAP_TYPE_IN); 

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (rmap, p, RMAP_BGP, &info);

      peer->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
	{
	  /* Free newly generated AS path and community by route-map. */
	  bgp_attr_flush (attr);
	  return RMAP_DENY;
	}
    }
  return RMAP_PERMIT;
}

static int
bgp_output_modifier (struct peer *peer, struct prefix *p, struct attr *attr,
		     afi_t afi, safi_t safi, char *rmap_name)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;
  struct route_map *rmap = NULL;

  filter = &peer->filter[afi][safi];

  /* Apply default weight value. */
  if (peer->weight)
    (bgp_attr_extra_get (attr))->weight = peer->weight;

  if (rmap_name)
    {
      rmap = route_map_lookup_by_name(rmap_name);
    }
  else
    {
      if (ROUTE_MAP_OUT_NAME(filter))
	rmap = ROUTE_MAP_OUT (filter);
    }

  /* Route map apply. */
  if (rmap)
    {
      /* Duplicate current value to new strucutre for modification. */
      info.peer = peer;
      info.attr = attr;

      SET_FLAG (peer->rmap_type, PEER_RMAP_TYPE_OUT);

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (rmap, p, RMAP_BGP, &info);

      peer->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
	/* caller has multiple error paths with bgp_attr_flush() */
	return RMAP_DENY;
    }
  return RMAP_PERMIT;
}

static int
bgp_export_modifier (struct peer *rsclient, struct peer *peer,
        struct prefix *p, struct attr *attr, afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;

  filter = &peer->filter[afi][safi];

  /* Route map apply. */
  if (ROUTE_MAP_EXPORT_NAME (filter))
    {
      /* Duplicate current value to new strucutre for modification. */
      info.peer = rsclient;
      info.attr = attr;

      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_EXPORT);

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (ROUTE_MAP_EXPORT (filter), p, RMAP_BGP, &info);

      rsclient->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
        {
          /* Free newly generated AS path and community by route-map. */
          bgp_attr_flush (attr);
          return RMAP_DENY;
        }
    }
  return RMAP_PERMIT;
}

static int
bgp_import_modifier (struct peer *rsclient, struct peer *peer,
        struct prefix *p, struct attr *attr, afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;

  filter = &rsclient->filter[afi][safi];

  /* Apply default weight value. */
  if (peer->weight)
    (bgp_attr_extra_get (attr))->weight = peer->weight;

  /* Route map apply. */
  if (ROUTE_MAP_IMPORT_NAME (filter))
    {
      /* Duplicate current value to new strucutre for modification. */
      info.peer = peer;
      info.attr = attr;

      SET_FLAG (peer->rmap_type, PEER_RMAP_TYPE_IMPORT);

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (ROUTE_MAP_IMPORT (filter), p, RMAP_BGP, &info);

      peer->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
        {
          /* Free newly generated AS path and community by route-map. */
          bgp_attr_flush (attr);
          return RMAP_DENY;
        }
    }
  return RMAP_PERMIT;
}


/* If this is an EBGP peer with remove-private-AS */
void
bgp_peer_remove_private_as(struct bgp *bgp, afi_t afi, safi_t safi,
                           struct peer *peer, struct attr *attr)
{
  if (peer->sort == BGP_PEER_EBGP &&
      peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS))
    {
      // Take action on the entire aspath
      if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
        {
          if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
            attr->aspath = aspath_replace_private_asns (attr->aspath, bgp->as);

          // The entire aspath consists of private ASNs so create an empty aspath
          else if (aspath_private_as_check (attr->aspath))
            attr->aspath = aspath_empty_get ();

          // There are some public and some private ASNs, remove the private ASNs
          else
            attr->aspath = aspath_remove_private_asns (attr->aspath);
        }

      // 'all' was not specified so the entire aspath must be private ASNs
      // for us to do anything
      else if (aspath_private_as_check (attr->aspath))
        {
          if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
            attr->aspath = aspath_replace_private_asns (attr->aspath, bgp->as);
          else
            attr->aspath = aspath_empty_get ();
        }
    }
}

/* If this is an EBGP peer with as-override */
static void
bgp_peer_as_override(struct bgp *bgp, afi_t afi, safi_t safi,
                     struct peer *peer, struct attr *attr)
{
  if (peer->sort == BGP_PEER_EBGP &&
      peer_af_flag_check (peer, afi, safi, PEER_FLAG_AS_OVERRIDE))
    {
      if (aspath_single_asn_check (attr->aspath, peer->as))
        attr->aspath = aspath_replace_specific_asn (attr->aspath, peer->as, bgp->as);
    }
}

static int
bgp_announce_check (struct bgp_info *ri, struct peer *peer, struct prefix *p,
		    struct attr *attr, afi_t afi, safi_t safi)
{
  int ret;
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  struct peer *from;
  struct bgp *bgp;
  int transparent;
  int reflect;
  struct attr *riattr;

  from = ri->peer;
  filter = &peer->filter[afi][safi];
  bgp = peer->bgp;
  riattr = bgp_info_mpath_count (ri) ? bgp_info_mpath_attr (ri) : ri->attr;
  
  if (DISABLE_BGP_ANNOUNCE)
    return 0;

  /* Do not send announces to RS-clients from the 'normal' bgp_table. */
  if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
    return 0;

  /* Do not send back route to sender. */
  if (from == peer)
    return 0;

  /* Aggregate-address suppress check. */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      return 0;

  /* Default route check.  */
  if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE))
    {
      if (p->family == AF_INET && p->u.prefix4.s_addr == INADDR_ANY)
	return 0;
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6 && p->prefixlen == 0)
	return 0;
#endif /* HAVE_IPV6 */
    }

  /* Transparency check. */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT)
      && CHECK_FLAG (from->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
    transparent = 1;
  else
    transparent = 0;

  /* If community is not disabled check the no-export and local. */
  if (! transparent && bgp_community_filter (peer, riattr))
    return 0;

  /* If the attribute has originator-id and it is same as remote
     peer's id. */
  if (riattr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      if (IPV4_ADDR_SAME (&peer->remote_id, &riattr->extra->originator_id))
	{
          if (bgp_debug_update(peer, p, NULL, 0))
	    zlog_debug("%s [Update:SEND] %s/%d originator-id is same as remote router-id",
		       peer->host,
		       inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		       p->prefixlen);
	  return 0;
	}
    }
 
  /* ORF prefix-list filter check */
  if (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
      && (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
	  || CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
    if (peer->orf_plist[afi][safi])
      {
	if (prefix_list_apply (peer->orf_plist[afi][safi], p) == PREFIX_DENY)
          return 0;
      }

  /* Output filter check. */
  if (bgp_output_filter (peer, p, riattr, afi, safi) == FILTER_DENY)
    {
      if (bgp_debug_update(peer, p, NULL, 0))
	zlog_debug("%s [Update:SEND] %s/%d is filtered",
	           peer->host,
	           inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	           p->prefixlen);
      return 0;
    }

#ifdef BGP_SEND_ASPATH_CHECK
  /* AS path loop check. */
  if (aspath_loop_check (riattr->aspath, peer->as))
    {
      if (bgp_debug_update(peer, p, NULL, 0))
        zlog_debug("%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
	           peer->host, peer->as);
      return 0;
    }
#endif /* BGP_SEND_ASPATH_CHECK */

  /* If we're a CONFED we need to loop check the CONFED ID too */
  if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
    {
      if (aspath_loop_check(riattr->aspath, bgp->confed_id))
	{
          if (bgp_debug_update(peer, p, NULL, 0))
	    zlog_debug("%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
		       peer->host,
		       bgp->confed_id);
	  return 0;
	}      
    }

  /* Route-Reflect check. */
  if (from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP)
    reflect = 1;
  else
    reflect = 0;

  /* IBGP reflection check. */
  if (reflect)
    {
      /* A route from a Client peer. */
      if (CHECK_FLAG (from->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
	{
	  /* Reflect to all the Non-Client peers and also to the
             Client peers other than the originator.  Originator check
             is already done.  So there is noting to do. */
	  /* no bgp client-to-client reflection check. */
	  if (bgp_flag_check (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT))
	    if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
	      return 0;
	}
      else
	{
	  /* A route from a Non-client peer. Reflect to all other
	     clients. */
	  if (! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
	    return 0;
	}
    }
  
  /* For modify attribute, copy it to temporary structure. */
  bgp_attr_dup (attr, riattr);
  
  /* If local-preference is not set. */
  if ((peer->sort == BGP_PEER_IBGP
       || peer->sort == BGP_PEER_CONFED)
      && (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))))
    {
      attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
      attr->local_pref = bgp->default_local_pref;
    }

  /* If originator-id is not set and the route is to be reflected,
     set the originator id */
  if (peer && from && peer->sort == BGP_PEER_IBGP &&
      from->sort == BGP_PEER_IBGP &&
      (! (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))))
    {
      attr->extra = bgp_attr_extra_get(attr);
      IPV4_ADDR_COPY(&(attr->extra->originator_id), &(from->remote_id));
      SET_FLAG(attr->flag, BGP_ATTR_ORIGINATOR_ID);
    }

  /* Remove MED if its an EBGP peer - will get overwritten by route-maps */
  if (peer->sort == BGP_PEER_EBGP
      && attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    {
      if (ri->peer != bgp->peer_self && ! transparent
	  && ! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
	attr->flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC));
    }

  /* next-hop-set */
  if (transparent
      || (reflect && ! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF_ALL))
      || (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_UNCHANGED)
	  && ((p->family == AF_INET && attr->nexthop.s_addr)
#ifdef HAVE_IPV6
	      || (p->family == AF_INET6 && 
                  ! IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
#endif /* HAVE_IPV6 */
	      )))
    {
      /* NEXT-HOP Unchanged. */
    }
  else if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF)
	   || (p->family == AF_INET && attr->nexthop.s_addr == 0)
#ifdef HAVE_IPV6
	   || (p->family == AF_INET6 && 
               IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
#endif /* HAVE_IPV6 */
	   || (peer->sort == BGP_PEER_EBGP
               && (bgp_multiaccess_check_v4 (attr->nexthop, peer) == 0)))
    {
      /* Set IPv4 nexthop. */
      if (p->family == AF_INET)
	{
	  if (safi == SAFI_MPLS_VPN)
	    memcpy (&attr->extra->mp_nexthop_global_in, &peer->nexthop.v4,
	            IPV4_MAX_BYTELEN);
	  else
	    memcpy (&attr->nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);
	}
#ifdef HAVE_IPV6
      /* Set IPv6 nexthop. */
      if (p->family == AF_INET6)
	{
	  /* IPv6 global nexthop must be included. */
	  memcpy (&attr->extra->mp_nexthop_global, &peer->nexthop.v6_global, 
		  IPV6_MAX_BYTELEN);
	  attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
	}
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      /* Left nexthop_local unchanged if so configured. */ 
      if ( CHECK_FLAG (peer->af_flags[afi][safi], 
           PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED) )
        {
          if ( IN6_IS_ADDR_LINKLOCAL (&attr->extra->mp_nexthop_local) )
            attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
          else
            attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
        }

      /* Default nexthop_local treatment for non-RS-Clients */
      else 
        {
      /* Link-local address should not be transit to different peer. */
      attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;

      /* Set link-local address for shared network peer. */
      if (peer->shared_network 
	  && ! IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
	{
	  memcpy (&attr->extra->mp_nexthop_local, &peer->nexthop.v6_local, 
		  IPV6_MAX_BYTELEN);
	  attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
	}

      /* If bgpd act as BGP-4+ route-reflector, do not send link-local
	 address.*/
      if (reflect)
	attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;

      /* If BGP-4+ link-local nexthop is not link-local nexthop. */
      if (! IN6_IS_ADDR_LINKLOCAL (&peer->nexthop.v6_local))
	attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
    }

    }
#endif /* HAVE_IPV6 */

  bgp_peer_remove_private_as(bgp, afi, safi, peer, attr);
  bgp_peer_as_override(bgp, afi, safi, peer, attr);

  /* Route map & unsuppress-map apply. */
  if (ROUTE_MAP_OUT_NAME (filter)
      || (ri->extra && ri->extra->suppress) )
    {
      struct bgp_info info;
      struct attr dummy_attr;
      struct attr_extra dummy_extra;

      dummy_attr.extra = &dummy_extra;

      info.peer = peer;
      info.attr = attr;

      /* The route reflector is not allowed to modify the attributes
	 of the reflected IBGP routes. */
      if ((from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP) &&
	  !bgp_flag_check(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
	{
	  bgp_attr_dup (&dummy_attr, attr);
	  info.attr = &dummy_attr;
	}

      SET_FLAG (peer->rmap_type, PEER_RMAP_TYPE_OUT); 

      if (ri->extra && ri->extra->suppress)
	ret = route_map_apply (UNSUPPRESS_MAP (filter), p, RMAP_BGP, &info);
      else
	ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info);

      peer->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
	{
	  bgp_attr_flush (attr);
	  return 0;
	}
    }
  return 1;
}

static void
subgroup_announce_reset_nhop (u_char family, struct attr *attr)
{
  if (family == AF_INET)
    attr->nexthop.s_addr = 0;
#ifdef HAVE_IPV6
  if (family == AF_INET6)
    memset (&attr->extra->mp_nexthop_global, 0, IPV6_MAX_BYTELEN);
#endif
}

int
subgroup_announce_check (struct bgp_info *ri, struct update_subgroup *subgrp,
			 struct prefix *p, struct attr *attr)
{
  struct bgp_filter *filter;
  struct peer *from;
  struct peer *peer;
  struct peer *onlypeer;
  struct bgp *bgp;
  struct attr *riattr;
  struct peer_af *paf;
  char buf[SU_ADDRSTRLEN];
  int ret;
  int transparent;
  int reflect;
  afi_t afi;
  safi_t safi;

  if (DISABLE_BGP_ANNOUNCE)
    return 0;

  afi = SUBGRP_AFI(subgrp);
  safi = SUBGRP_SAFI(subgrp);
  peer = SUBGRP_PEER(subgrp);
  onlypeer = NULL;
  if (CHECK_FLAG (peer->flags, PEER_FLAG_LONESOUL))
    onlypeer = SUBGRP_PFIRST(subgrp)->peer;

  from = ri->peer;
  filter = &peer->filter[afi][safi];
  bgp = SUBGRP_INST(subgrp);
  riattr = bgp_info_mpath_count (ri) ? bgp_info_mpath_attr (ri) : ri->attr;

  /* Aggregate-address suppress check. */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      {
	return 0;
      }

  /* Do not send announces to RS-clients from the 'normal' bgp_table. */
  if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
    {
      return 0;
    }

  /* Do not send back route to sender. */
  if (onlypeer && from == onlypeer)
    {
      return 0;
    }

  /* Transparency check. */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT)
      && CHECK_FLAG (from->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
    transparent = 1;
  else
    transparent = 0;

  /* If community is not disabled check the no-export and local. */
  if (! transparent && bgp_community_filter (peer, riattr))
    {
      if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
	zlog_debug ("subgrpannouncecheck: community filter check fail");
      return 0;
    }

  /* If the attribute has originator-id and it is same as remote
     peer's id. */
  if (onlypeer &&
      riattr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID) &&
      (IPV4_ADDR_SAME (&onlypeer->remote_id, &riattr->extra->originator_id)))
	{
          if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
	    zlog_debug ("%s [Update:SEND] %s/%d originator-id is same as "
		  "remote router-id",
		  onlypeer->host,
		  inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		  p->prefixlen);
	  return 0;
	}

  /* ORF prefix-list filter check */
  if (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
      && (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
	  || CHECK_FLAG (peer->af_cap[afi][safi],
			 PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
    if (peer->orf_plist[afi][safi])
      {
	if (prefix_list_apply (peer->orf_plist[afi][safi], p) == PREFIX_DENY)
	  {
	    return 0;
	  }
      }

  /* Output filter check. */
  if (bgp_output_filter (peer, p, riattr, afi, safi) == FILTER_DENY)
    {
      if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
	zlog_debug ("%s [Update:SEND] %s/%d is filtered",
	      peer->host,
	      inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	      p->prefixlen);
      return 0;
    }

#ifdef BGP_SEND_ASPATH_CHECK
  /* AS path loop check. */
  if (onlypeer && aspath_loop_check (riattr->aspath, onlypeer->as))
    {
      if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
        zlog_debug ("%s [Update:SEND] suppress announcement to peer AS %u "
	      "that is part of AS path.",
	      onlypeer->host, onlypeer->as);
      return 0;
    }
#endif /* BGP_SEND_ASPATH_CHECK */

  /* If we're a CONFED we need to loop check the CONFED ID too */
  if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
    {
      if (aspath_loop_check(riattr->aspath, bgp->confed_id))
	{
          if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
	    zlog_debug ("%s [Update:SEND] suppress announcement to peer AS %u"
		  " is AS path.",
		  peer->host,
		  bgp->confed_id);
	  return 0;
	}
    }

  /* Route-Reflect check. */
  if (from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP)
    reflect = 1;
  else
    reflect = 0;

  /* IBGP reflection check. */
  if (reflect)
    {
      /* A route from a Client peer. */
      if (CHECK_FLAG (from->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
	{
	  /* Reflect to all the Non-Client peers and also to the
             Client peers other than the originator.  Originator check
             is already done.  So there is noting to do. */
	  /* no bgp client-to-client reflection check. */
	  if (bgp_flag_check (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT))
	    if (CHECK_FLAG (peer->af_flags[afi][safi],
			    PEER_FLAG_REFLECTOR_CLIENT))
	      return 0;
	}
      else
	{
	  /* A route from a Non-client peer. Reflect to all other
	     clients. */
	  if (! CHECK_FLAG (peer->af_flags[afi][safi],
			    PEER_FLAG_REFLECTOR_CLIENT))
	    return 0;
	}
    }

  /* For modify attribute, copy it to temporary structure. */
  bgp_attr_dup (attr, riattr);

  /* If local-preference is not set. */
  if ((peer->sort == BGP_PEER_IBGP
       || peer->sort == BGP_PEER_CONFED)
      && (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))))
    {
      attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
      attr->local_pref = bgp->default_local_pref;
    }

  /* If originator-id is not set and the route is to be reflected,
     set the originator id */
  if (reflect && (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))))
    {
      attr->extra = bgp_attr_extra_get(attr);
      IPV4_ADDR_COPY(&(attr->extra->originator_id), &(from->remote_id));
      SET_FLAG(attr->flag, BGP_ATTR_ORIGINATOR_ID);
    }

  /* Remove MED if its an EBGP peer - will get overwritten by route-maps */
  if (peer->sort == BGP_PEER_EBGP
      && attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    {
      if (ri->peer != bgp->peer_self && ! transparent
	  && ! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
	attr->flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC));
    }

  /* Since the nexthop attribute can vary per peer, it is not explicitly set
   * in announce check, only certain flags and length (or number of nexthops
   * -- for IPv6/MP_REACH) are set here in order to guide the update formation
   * code in setting the nexthop(s) on a per peer basis in reformat_peer().
   * Typically, the source nexthop in the attribute is preserved but in the
   * scenarios where we know it will always be overwritten, we reset the
   * nexthop to "0" in an attempt to achieve better Update packing. An
   * example of this is when a prefix from each of 2 IBGP peers needs to be
   * announced to an EBGP peer (and they have the same attributes barring
   * their nexthop).
   */
  if (reflect)
    SET_FLAG(attr->rmap_change_flags, BATTR_REFLECTED);

#ifdef HAVE_IPV6
  /* IPv6/MP starts with 1 nexthop, the link-local address is passed only if
   * we're not reflecting the route and the peer (group) to whom we're going
   * to announce is on a shared network (directly connected peers) or the
   * peer (group) is configured to receive link-local nexthop and it is
   * available in the prefix.
   * Of course, the operator can always set it through the route-map, if
   * so desired.
   */
  if (p->family == AF_INET6)
    {
      attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
      if (!reflect)
        {
          if (peer->shared_network ||
              (CHECK_FLAG (peer->af_flags[afi][safi],
                           PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED) &&
               IN6_IS_ADDR_LINKLOCAL (&attr->extra->mp_nexthop_local)))
            attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
        }

      /* Clear off link-local nexthop in source, if not needed. This may help
       * more prefixes share the same attribute for announcement.
       */
      if (!(CHECK_FLAG (peer->af_flags[afi][safi],
            PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)))
        memset (&attr->extra->mp_nexthop_local, 0, IPV6_MAX_BYTELEN);
    }
#endif /* HAVE_IPV6 */

  bgp_peer_remove_private_as(bgp, afi, safi, peer, attr);
  bgp_peer_as_override(bgp, afi, safi, peer, attr);

  /* Route map & unsuppress-map apply. */
  if (ROUTE_MAP_OUT_NAME (filter)
      || (ri->extra && ri->extra->suppress) )
    {
      struct bgp_info info;
      struct attr dummy_attr;
      struct attr_extra dummy_extra;

      dummy_attr.extra = &dummy_extra;

      info.peer = peer;
      info.attr = attr;
      /* don't confuse inbound and outbound setting */
      RESET_FLAG(attr->rmap_change_flags);

      /*
       * The route reflector is not allowed to modify the attributes
       * of the reflected IBGP routes unless explicitly allowed.
       */
      if ((from->sort == BGP_PEER_IBGP && peer->sort == BGP_PEER_IBGP)
        && !bgp_flag_check(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
        {
          bgp_attr_dup (&dummy_attr, attr);
          info.attr = &dummy_attr;
        }

      SET_FLAG (peer->rmap_type, PEER_RMAP_TYPE_OUT);

      if (ri->extra && ri->extra->suppress)
	ret = route_map_apply (UNSUPPRESS_MAP (filter), p, RMAP_BGP, &info);
      else
	ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info);

      peer->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
	{
	  bgp_attr_flush (attr);
	  return 0;
	}
    }

  /* After route-map has been applied, we check to see if the nexthop to
   * be carried in the attribute (that is used for the announcement) can
   * be cleared off or not. We do this in all cases where we would be
   * setting the nexthop to "ourselves". For IPv6, we only need to consider
   * the global nexthop here; the link-local nexthop would have been cleared
   * already, and if not, it is required by the update formation code.
   * Also see earlier comments in this function.
   */
  if (!(CHECK_FLAG(attr->rmap_change_flags, BATTR_RMAP_NEXTHOP_CHANGED) ||
        CHECK_FLAG(attr->rmap_change_flags, BATTR_RMAP_NEXTHOP_UNCHANGED) ||
        CHECK_FLAG(riattr->rmap_change_flags, BATTR_RMAP_NEXTHOP_UNCHANGED) ||
        transparent ||
        CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_UNCHANGED)))
    {
      if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF))
        {
          if (!reflect ||
              CHECK_FLAG (peer->af_flags[afi][safi],
                          PEER_FLAG_FORCE_NEXTHOP_SELF))
            subgroup_announce_reset_nhop (p->family, attr);
        }
      else if (peer->sort == BGP_PEER_EBGP)
        {
          SUBGRP_FOREACH_PEER (subgrp, paf)
            {
              if (bgp_multiaccess_check_v4 (riattr->nexthop, paf->peer))
                break;
            }
          if (!paf)
            subgroup_announce_reset_nhop (p->family, attr);
        }
    }

  return 1;
}

static int
bgp_announce_check_rsclient (struct bgp_info *ri, struct peer *rsclient,
        struct prefix *p, struct attr *attr, afi_t afi, safi_t safi)
{
  int ret;
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  struct bgp_info info;
  struct peer *from;
  struct attr *riattr;

  from = ri->peer;
  filter = &rsclient->filter[afi][safi];
  riattr = bgp_info_mpath_count (ri) ? bgp_info_mpath_attr (ri) : ri->attr;

  if (DISABLE_BGP_ANNOUNCE)
    return 0;

  /* Do not send back route to sender. */
  if (from == rsclient)
    return 0;

  /* Aggregate-address suppress check. */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      return 0;

  /* Default route check.  */
  if (CHECK_FLAG (rsclient->af_sflags[afi][safi],
          PEER_STATUS_DEFAULT_ORIGINATE))
    {
      if (p->family == AF_INET && p->u.prefix4.s_addr == INADDR_ANY)
        return 0;
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6 && p->prefixlen == 0)
        return 0;
#endif /* HAVE_IPV6 */
    }

  /* If the attribute has originator-id and it is same as remote
     peer's id. */
  if (riattr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      if (IPV4_ADDR_SAME (&rsclient->remote_id,
                          &riattr->extra->originator_id))
        {
          if (bgp_debug_update(rsclient, p, NULL, 0))
            zlog_debug ("%s [Update:SEND] %s/%d originator-id is same as remote router-id",
                 rsclient->host,
                 inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                 p->prefixlen);
          return 0;
       }
    }

  /* ORF prefix-list filter check */
  if (CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
      && (CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
         || CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
    if (rsclient->orf_plist[afi][safi])
      {
       if (prefix_list_apply (rsclient->orf_plist[afi][safi], p) == PREFIX_DENY)
          return 0;
      }

  /* Output filter check. */
  if (bgp_output_filter (rsclient, p, riattr, afi, safi) == FILTER_DENY)
    {
      if (bgp_debug_update(rsclient, p, NULL, 0))
        zlog_debug ("%s [Update:SEND] %s/%d is filtered",
             rsclient->host,
             inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
             p->prefixlen);
      return 0;
    }

#ifdef BGP_SEND_ASPATH_CHECK
  /* AS path loop check. */
  if (aspath_loop_check (riattr->aspath, rsclient->as))
    {
      if (bgp_debug_update(rsclient, p, NULL, 0))
        zlog_debug ("%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
             rsclient->host, rsclient->as);
      return 0;
    }
#endif /* BGP_SEND_ASPATH_CHECK */

  /* For modify attribute, copy it to temporary structure. */
  bgp_attr_dup (attr, riattr);

  /* next-hop-set */
  if ((p->family == AF_INET && attr->nexthop.s_addr == 0)
#ifdef HAVE_IPV6
          || (p->family == AF_INET6 &&
              IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
#endif /* HAVE_IPV6 */
     )
  {
    /* Set IPv4 nexthop. */
    if (p->family == AF_INET)
      {
        if (safi == SAFI_MPLS_VPN)
          memcpy (&attr->extra->mp_nexthop_global_in, &rsclient->nexthop.v4,
                  IPV4_MAX_BYTELEN);
        else
          memcpy (&attr->nexthop, &rsclient->nexthop.v4, IPV4_MAX_BYTELEN);
      }
#ifdef HAVE_IPV6
    /* Set IPv6 nexthop. */
    if (p->family == AF_INET6)
      {
        /* IPv6 global nexthop must be included. */
        memcpy (&attr->extra->mp_nexthop_global, &rsclient->nexthop.v6_global,
                IPV6_MAX_BYTELEN);
        attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
      }
#endif /* HAVE_IPV6 */
  }

#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      struct attr_extra *attre = attr->extra;

      /* Left nexthop_local unchanged if so configured. */
      if ( CHECK_FLAG (rsclient->af_flags[afi][safi],
           PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED) )
        {
          if ( IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local) )
            attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
          else
            attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
        }

      /* Default nexthop_local treatment for RS-Clients */
      else
        {
          /* Announcer and RS-Client are both in the same network */
          if (rsclient->shared_network && from->shared_network &&
              (rsclient->ifindex == from->ifindex))
            {
              if ( IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local) )
                attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
              else
                attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
            }

          /* Set link-local address for shared network peer. */
          else if (rsclient->shared_network
              && IN6_IS_ADDR_LINKLOCAL (&rsclient->nexthop.v6_local))
            {
              memcpy (&attre->mp_nexthop_local, &rsclient->nexthop.v6_local,
                      IPV6_MAX_BYTELEN);
              attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
            }

          else
            attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
        }

    }
#endif /* HAVE_IPV6 */


  /* If this is EBGP peer and remove-private-AS is set.  */
  if (rsclient->sort == BGP_PEER_EBGP
      && peer_af_flag_check (rsclient, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS)
      && aspath_private_as_check (attr->aspath))
    attr->aspath = aspath_empty_get ();

  /* Route map & unsuppress-map apply. */
  if (ROUTE_MAP_OUT_NAME (filter) || (ri->extra && ri->extra->suppress) )
    {
      info.peer = rsclient;
      info.attr = attr;

      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_OUT);

      if (ri->extra && ri->extra->suppress)
        ret = route_map_apply (UNSUPPRESS_MAP (filter), p, RMAP_BGP, &info);
      else
        ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info);

      rsclient->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
       {
         bgp_attr_flush (attr);
         return 0;
       }
    }

  return 1;
}

static int
subgroup_announce_check_rsclient (struct bgp_info *ri,
				  struct update_subgroup *subgrp,
				  struct prefix *p, struct attr *attr)
{
  int ret;
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  struct bgp_info info;
  struct peer *from;
  struct peer *rsclient;
  struct peer *onlypeer;
  struct attr *riattr;
  struct bgp *bgp;
  afi_t afi;
  safi_t safi;

  if (DISABLE_BGP_ANNOUNCE)
    return 0;

  afi = SUBGRP_AFI(subgrp);
  safi = SUBGRP_SAFI(subgrp);
  rsclient = SUBGRP_PEER(subgrp);
  onlypeer = ((SUBGRP_PCOUNT(subgrp) == 1) ?
	      (SUBGRP_PFIRST(subgrp))->peer : NULL);
  from = ri->peer;
  filter = &rsclient->filter[afi][safi];
  bgp = rsclient->bgp;
  riattr = bgp_info_mpath_count (ri) ? bgp_info_mpath_attr (ri) : ri->attr;

  /* Do not send back route to sender. */
  if (onlypeer && (from == onlypeer))
    return 0;

  /* Aggregate-address suppress check. */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      return 0;

  /* Default route check.  */
  if (CHECK_FLAG (rsclient->af_sflags[afi][safi],
          PEER_STATUS_DEFAULT_ORIGINATE))
    {
      if (p->family == AF_INET && p->u.prefix4.s_addr == INADDR_ANY)
        return 0;
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6 && p->prefixlen == 0)
        return 0;
#endif /* HAVE_IPV6 */
    }

  /* If the attribute has originator-id and it is same as remote
     peer's id. */
  if (onlypeer && riattr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      if (IPV4_ADDR_SAME (&onlypeer->remote_id,
                          &riattr->extra->originator_id))
        {
          if (bgp_debug_update(rsclient, p, subgrp->update_group, 0))
            zlog_debug ("%s [Update:SEND] %s/%d originator-id is same as remote router-id",
                 onlypeer->host,
                        inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                        p->prefixlen);
         return 0;
       }
    }

  /* ORF prefix-list filter check */
  if (CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV)
      && (CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
         || CHECK_FLAG (rsclient->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV)))
    if (rsclient->orf_plist[afi][safi])
      {
       if (prefix_list_apply (rsclient->orf_plist[afi][safi], p) == PREFIX_DENY)
          return 0;
      }

  /* Output filter check. */
  if (bgp_output_filter (rsclient, p, riattr, afi, safi) == FILTER_DENY)
    {
      if (bgp_debug_update(rsclient, p, subgrp->update_group, 0))
        zlog_debug ("%s [Update:SEND] %s/%d is filtered",
                    rsclient->host,
                    inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                    p->prefixlen);
      return 0;
    }

#ifdef BGP_SEND_ASPATH_CHECK
  /* AS path loop check. */
  if (onlypeer && aspath_loop_check (riattr->aspath, onlypeer->as))
    {
      if (bgp_debug_update(rsclient, p, subgrp->update_group, 0))
        zlog_debug ("%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
                    onlypeer->host, onlypeer->as);
      return 0;
    }
#endif /* BGP_SEND_ASPATH_CHECK */

  /* For modify attribute, copy it to temporary structure. */
  bgp_attr_dup (attr, riattr);

  /* next-hop-set */
  if ((p->family == AF_INET && attr->nexthop.s_addr == 0)
#ifdef HAVE_IPV6
          || (p->family == AF_INET6 &&
              IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
#endif /* HAVE_IPV6 */
     )
  {
    /* Set IPv4 nexthop. */
    if (p->family == AF_INET)
      {
        if (safi == SAFI_MPLS_VPN)
          memcpy (&attr->extra->mp_nexthop_global_in, &rsclient->nexthop.v4,
                  IPV4_MAX_BYTELEN);
        else
          memcpy (&attr->nexthop, &rsclient->nexthop.v4, IPV4_MAX_BYTELEN);
      }
#ifdef HAVE_IPV6
    /* Set IPv6 nexthop. */
    if (p->family == AF_INET6)
      {
        /* IPv6 global nexthop must be included. */
        memcpy (&attr->extra->mp_nexthop_global, &rsclient->nexthop.v6_global,
                IPV6_MAX_BYTELEN);
        attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
      }
#endif /* HAVE_IPV6 */
  }

#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      struct attr_extra *attre = attr->extra;

      /* Left nexthop_local unchanged if so configured. */
      if ( CHECK_FLAG (rsclient->af_flags[afi][safi],
           PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED) )
        {
          if ( IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local) )
            attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
          else
            attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
        }

      /* Default nexthop_local treatment for RS-Clients */
      else
        {
          /* Announcer and RS-Client are both in the same network */
          if (rsclient->shared_network && from->shared_network &&
              (rsclient->ifindex == from->ifindex))
            {
              if ( IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local) )
                attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
              else
                attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
            }

          /* Set link-local address for shared network peer. */
          else if (rsclient->shared_network
              && IN6_IS_ADDR_LINKLOCAL (&rsclient->nexthop.v6_local))
            {
              memcpy (&attre->mp_nexthop_local, &rsclient->nexthop.v6_local,
                      IPV6_MAX_BYTELEN);
              attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
            }

          else
            attre->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
        }

    }
#endif /* HAVE_IPV6 */

  bgp_peer_remove_private_as(bgp, afi, safi, rsclient, attr);
  bgp_peer_as_override(bgp, afi, safi, rsclient, attr);

  /* Route map & unsuppress-map apply. */
  if (ROUTE_MAP_OUT_NAME (filter) || (ri->extra && ri->extra->suppress) )
    {
      info.peer = rsclient;
      info.attr = attr;

      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_OUT);

      if (ri->extra && ri->extra->suppress)
        ret = route_map_apply (UNSUPPRESS_MAP (filter), p, RMAP_BGP, &info);
      else
        ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info);

      rsclient->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
       {
         bgp_attr_flush (attr);
         return 0;
       }
    }

  return 1;
}

struct bgp_info_pair
{
  struct bgp_info *old;
  struct bgp_info *new;
};

static void
bgp_best_selection (struct bgp *bgp, struct bgp_node *rn,
		    struct bgp_maxpaths_cfg *mpath_cfg,
		    struct bgp_info_pair *result)
{
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info *ri;
  struct bgp_info *ri1;
  struct bgp_info *ri2;
  struct bgp_info *nextri = NULL;
  int paths_eq, do_mpath, debug;
  struct list mp_list;
  char buf[INET6_BUFSIZ];
  char pfx_buf[INET6_ADDRSTRLEN];

  bgp_mp_list_init (&mp_list);
  do_mpath = (mpath_cfg->maxpaths_ebgp != BGP_DEFAULT_MAXPATHS ||
	      mpath_cfg->maxpaths_ibgp != BGP_DEFAULT_MAXPATHS);

  debug = bgp_debug_bestpath(&rn->p);

  if (debug)
    prefix2str (&rn->p, pfx_buf, sizeof (pfx_buf));

  /* bgp deterministic-med */
  new_select = NULL;
  if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED))
    for (ri1 = rn->info; ri1; ri1 = ri1->next)
      {
	if (CHECK_FLAG (ri1->flags, BGP_INFO_DMED_CHECK))
	  continue;
	if (BGP_INFO_HOLDDOWN (ri1))
	  continue;
        if (ri1->peer && ri1->peer != bgp->peer_self)
          if (ri1->peer->status != Established)
            continue;

	new_select = ri1;
	old_select = CHECK_FLAG (ri1->flags, BGP_INFO_SELECTED) ? ri1 : NULL;
	if (ri1->next)
	  for (ri2 = ri1->next; ri2; ri2 = ri2->next)
	    {
	      if (CHECK_FLAG (ri2->flags, BGP_INFO_DMED_CHECK))
		continue;
	      if (BGP_INFO_HOLDDOWN (ri2))
		continue;
              if (ri2->peer &&
                  ri2->peer != bgp->peer_self &&
                  !CHECK_FLAG (ri2->peer->sflags, PEER_STATUS_NSF_WAIT))
                if (ri2->peer->status != Established)
                  continue;

	      if (aspath_cmp_left (ri1->attr->aspath, ri2->attr->aspath)
		  || aspath_cmp_left_confed (ri1->attr->aspath,
					     ri2->attr->aspath))
		{
		  if (CHECK_FLAG (ri2->flags, BGP_INFO_SELECTED))
		    old_select = ri2;
		  if (bgp_info_cmp (bgp, ri2, new_select, &paths_eq,
				    mpath_cfg, debug, pfx_buf))
		    {
		      bgp_info_unset_flag (rn, new_select, BGP_INFO_DMED_SELECTED);
		      new_select = ri2;
		    }

		  bgp_info_set_flag (rn, ri2, BGP_INFO_DMED_CHECK);
		}
	    }
	bgp_info_set_flag (rn, new_select, BGP_INFO_DMED_CHECK);
	bgp_info_set_flag (rn, new_select, BGP_INFO_DMED_SELECTED);
      }

  /* Check old selected route and new selected route. */
  old_select = NULL;
  new_select = NULL;
  for (ri = rn->info; (ri != NULL) && (nextri = ri->next, 1); ri = nextri)
    {
      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
	old_select = ri;

      if (BGP_INFO_HOLDDOWN (ri))
        {
          /* reap REMOVED routes, if needs be 
           * selected route must stay for a while longer though
           */
          if (CHECK_FLAG (ri->flags, BGP_INFO_REMOVED)
              && (ri != old_select))
              bgp_info_reap (rn, ri);
          
          continue;
        }

      if (ri->peer &&
          ri->peer != bgp->peer_self &&
          !CHECK_FLAG (ri->peer->sflags, PEER_STATUS_NSF_WAIT))
        if (ri->peer->status != Established)
          continue;

      if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED)
          && (! CHECK_FLAG (ri->flags, BGP_INFO_DMED_SELECTED)))
	{
	  bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_CHECK);
	  continue;
        }
      bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_CHECK);
      bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_SELECTED);

      if (bgp_info_cmp (bgp, ri, new_select, &paths_eq, mpath_cfg, debug, pfx_buf))
	{
	  new_select = ri;
	}
    }
    
  /* Now that we know which path is the bestpath see if any of the other paths
   * qualify as multipaths
   */
  if (do_mpath && new_select)
    {
      if (debug)
        zlog_debug("%s: path %s is the bestpath, now find multipaths",
                   pfx_buf, new_select->peer->host);

      for (ri = rn->info; (ri != NULL) && (nextri = ri->next, 1); ri = nextri)
        {
          if (ri == new_select)
            {
              if (debug)
                zlog_debug("%s: path %s is the bestpath, add to the multipath list",
                           pfx_buf, ri->peer->host);
	      bgp_mp_list_add (&mp_list, ri);
              continue;
            }

          if (BGP_INFO_HOLDDOWN (ri))
            continue;

          if (ri->peer &&
              ri->peer != bgp->peer_self &&
              !CHECK_FLAG (ri->peer->sflags, PEER_STATUS_NSF_WAIT))
            if (ri->peer->status != Established)
              continue;

          if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED)
              && (! CHECK_FLAG (ri->flags, BGP_INFO_DMED_SELECTED)))
	      continue;

          bgp_info_cmp (bgp, ri, new_select, &paths_eq, mpath_cfg, debug, pfx_buf);

          if (paths_eq)
            {
              if (debug)
                zlog_debug("%s: %s path is equivalent to the bestpath, add to the multipath list",
                           pfx_buf, ri->peer->host);
	      bgp_mp_list_add (&mp_list, ri);
            }
        }
    }

  if (!bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED))
    bgp_info_mpath_update (rn, new_select, old_select, &mp_list, mpath_cfg);

  bgp_info_mpath_aggregate_update (new_select, old_select);
  bgp_mp_list_clear (&mp_list);

  result->old = old_select;
  result->new = new_select;

  return;
}

/*
 * A new route/change in bestpath of an existing route. Evaluate the path
 * for advertisement to the subgroup.
 */
int
subgroup_process_announce_selected (struct update_subgroup *subgrp,
				    struct bgp_info *selected,
				    struct bgp_node *rn)
{
  struct prefix *p;
  struct peer_af *paf;
  struct peer *onlypeer;
  struct attr attr;
  struct attr_extra extra;
  afi_t afi;
  safi_t safi;

  p = &rn->p;
  afi = SUBGRP_AFI(subgrp);
  safi = SUBGRP_SAFI(subgrp);
  onlypeer = ((SUBGRP_PCOUNT(subgrp) == 1) ?
	      (SUBGRP_PFIRST(subgrp))->peer : NULL);

  /* First update is deferred until ORF or ROUTE-REFRESH is received */
  if (onlypeer && CHECK_FLAG (onlypeer->af_sflags[afi][safi],
			      PEER_STATUS_ORF_WAIT_REFRESH))
    return 0;

  /* It's initialized in bgp_announce_[check|check_rsclient]() */
  attr.extra = &extra;

  switch (bgp_node_table (rn)->type)
    {
      case BGP_TABLE_MAIN:
      /* Announcement to the subgroup.  If the route is filtered,
         withdraw it. */
	if (selected && subgroup_announce_check(selected, subgrp, p, &attr))
	  bgp_adj_out_set_subgroup(rn, subgrp, &attr, selected);
        else
	  bgp_adj_out_unset_subgroup(rn, subgrp);

        break;
      case BGP_TABLE_RSCLIENT:
        /* Announcement to peer->conf.  If the route is filtered,
           withdraw it. */
        if (selected &&
            subgroup_announce_check_rsclient (selected, subgrp, p, &attr))
          bgp_adj_out_set_subgroup (rn, subgrp, &attr, selected);
        else
	  bgp_adj_out_unset_subgroup(rn, subgrp);
        break;
    }

  return 0;
}

struct bgp_process_queue
{
  struct bgp *bgp;
  struct bgp_node *rn;
  afi_t afi;
  safi_t safi;
};

static wq_item_status
bgp_process_rsclient (struct work_queue *wq, void *data)
{
  struct bgp_process_queue *pq = data;
  struct bgp *bgp = pq->bgp;
  struct bgp_node *rn = pq->rn;
  afi_t afi = pq->afi;
  safi_t safi = pq->safi;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info_pair old_and_new;
  struct listnode *node, *nnode;
  struct peer *rsclient;
  struct peer_af *paf;
  struct update_subgroup *subgrp;

  /* Is it end of initial update? (after startup) */
  if (!rn)
    {
      /* This is just to keep the display sane in case all the peers are
         rsclients only */
      quagga_timestamp(3, bgp->update_delay_zebra_resume_time,
                       sizeof(bgp->update_delay_zebra_resume_time));

      bgp->rsclient_peers_update_hold = 0;
      bgp_start_routeadv(bgp);
      return WQ_SUCCESS;
    }

  rsclient = bgp_node_table (rn)->owner;

  /* Best path selection. */
  bgp_best_selection (bgp, rn, &bgp->maxpaths[afi][safi], &old_and_new);
  new_select = old_and_new.new;
  old_select = old_and_new.old;

  if (CHECK_FLAG (rsclient->sflags, PEER_STATUS_GROUP))
    {
      if (rsclient->group)
        for (ALL_LIST_ELEMENTS (rsclient->group->peer, node, nnode, rsclient))
          {
            /* Nothing to do. */
            if (old_select && old_select == new_select)
              if (!CHECK_FLAG (old_select->flags, BGP_INFO_ATTR_CHANGED))
                continue;

            if (old_select)
              bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
            if (new_select)
              {
                bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
                bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
		UNSET_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG);
             }

	    paf = peer_af_find(rsclient, afi, safi);
	    assert(paf);
	    subgrp = PAF_SUBGRP(paf);
	    if (!subgrp) /* not an established session */
	      continue;
            subgroup_process_announce_selected (subgrp, new_select, rn);
          }
    }
  else
    {
      if (old_select)
	bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
      if (new_select)
	{
	  bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
	  bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
	  UNSET_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG);
	}
      paf = peer_af_find(rsclient, afi, safi);
      if (paf && (subgrp = PAF_SUBGRP(paf))) /* if an established session */
	subgroup_process_announce_selected (subgrp, new_select, rn);
    }

  if (old_select && CHECK_FLAG (old_select->flags, BGP_INFO_REMOVED))
    bgp_info_reap (rn, old_select);

  UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
  return WQ_SUCCESS;
}

static wq_item_status
bgp_process_main (struct work_queue *wq, void *data)
{
  struct bgp_process_queue *pq = data;
  struct bgp *bgp = pq->bgp;
  struct bgp_node *rn = pq->rn;
  afi_t afi = pq->afi;
  safi_t safi = pq->safi;
  struct prefix *p = &rn->p;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info_pair old_and_new;
  struct listnode *node, *nnode;
  struct peer *peer;

  /* Is it end of initial update? (after startup) */
  if (!rn)
    {
      quagga_timestamp(3, bgp->update_delay_zebra_resume_time,
                       sizeof(bgp->update_delay_zebra_resume_time));

      bgp->main_zebra_update_hold = 0;
      for (afi = AFI_IP; afi < AFI_MAX; afi++)
        for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
          {
            bgp_zebra_announce_table(bgp, afi, safi);
          }
      bgp->main_peers_update_hold = 0;

      bgp_start_routeadv(bgp);
      return WQ_SUCCESS;
    }

  /* Best path selection. */
  bgp_best_selection (bgp, rn, &bgp->maxpaths[afi][safi], &old_and_new);
  old_select = old_and_new.old;
  new_select = old_and_new.new;

  /* Nothing to do. */
  if (old_select && old_select == new_select && !CHECK_FLAG(rn->flags, BGP_NODE_USER_CLEAR))
    {
      if (! CHECK_FLAG (old_select->flags, BGP_INFO_ATTR_CHANGED))
        {
          if (CHECK_FLAG (old_select->flags, BGP_INFO_IGP_CHANGED) ||
	      CHECK_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG))
            bgp_zebra_announce (p, old_select, bgp, afi, safi);
          
	  UNSET_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG);
          UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
          return WQ_SUCCESS;
        }
    }

  /* If the user did "clear ip bgp prefix x.x.x.x" this flag will be set */
  UNSET_FLAG(rn->flags, BGP_NODE_USER_CLEAR);

  /* bestpath has changed; bump version */
  if (old_select || new_select)
    bgp_bump_version(rn);

  if (old_select)
    bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
  if (new_select)
    {
      bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
      bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
      UNSET_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG);
    }

  group_announce_route(bgp, afi, safi, rn, new_select);

  /* FIB update. */
  if ((safi == SAFI_UNICAST || safi == SAFI_MULTICAST) && (! bgp->name &&
      ! bgp_option_check (BGP_OPT_NO_FIB)))
    {
      if (new_select 
	  && new_select->type == ZEBRA_ROUTE_BGP 
	  && (new_select->sub_type == BGP_ROUTE_NORMAL ||
              new_select->sub_type == BGP_ROUTE_AGGREGATE))
	bgp_zebra_announce (p, new_select, bgp, afi, safi);
      else
	{
	  /* Withdraw the route from the kernel. */
	  if (old_select 
	      && old_select->type == ZEBRA_ROUTE_BGP
	      && (old_select->sub_type == BGP_ROUTE_NORMAL ||
                  old_select->sub_type == BGP_ROUTE_AGGREGATE))
	    bgp_zebra_withdraw (p, old_select, safi);
	}
    }
    
  /* Reap old select bgp_info, it it has been removed */
  if (old_select && CHECK_FLAG (old_select->flags, BGP_INFO_REMOVED))
    bgp_info_reap (rn, old_select);
  
  UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
  return WQ_SUCCESS;
}

static void
bgp_processq_del (struct work_queue *wq, void *data)
{
  struct bgp_process_queue *pq = data;
  struct bgp_table *table;

  bgp_unlock (pq->bgp);
  if (pq->rn)
    {
      table = bgp_node_table (pq->rn);
      bgp_unlock_node (pq->rn);
      bgp_table_unlock (table);
    }
  XFREE (MTYPE_BGP_PROCESS_QUEUE, pq);
}

void
bgp_process_queue_init (void)
{
  bm->process_main_queue
    = work_queue_new (bm->master, "process_main_queue");
  bm->process_rsclient_queue
    = work_queue_new (bm->master, "process_rsclient_queue");
  
  if ( !(bm->process_main_queue && bm->process_rsclient_queue) )
    {
      zlog_err ("%s: Failed to allocate work queue", __func__);
      exit (1);
    }
  
  bm->process_main_queue->spec.workfunc = &bgp_process_main;
  bm->process_main_queue->spec.del_item_data = &bgp_processq_del;
  bm->process_main_queue->spec.max_retries = 0;
  bm->process_main_queue->spec.hold = 50;
  /* Use a higher yield value of 50ms for main queue processing */
  bm->process_main_queue->spec.yield = 50 * 1000L;
  
  memcpy (bm->process_rsclient_queue, bm->process_main_queue,
          sizeof (struct work_queue *));
  bm->process_rsclient_queue->spec.workfunc = &bgp_process_rsclient;
}

void
bgp_process (struct bgp *bgp, struct bgp_node *rn, afi_t afi, safi_t safi)
{
  struct bgp_process_queue *pqnode;
  
  /* already scheduled for processing? */
  if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED))
    return;
  
  if ( (bm->process_main_queue == NULL) ||
       (bm->process_rsclient_queue == NULL) )
    bgp_process_queue_init ();
  
  pqnode = XCALLOC (MTYPE_BGP_PROCESS_QUEUE, 
                    sizeof (struct bgp_process_queue));
  if (!pqnode)
    return;

  /* all unlocked in bgp_processq_del */
  bgp_table_lock (bgp_node_table (rn));
  pqnode->rn = bgp_lock_node (rn);
  pqnode->bgp = bgp;
  bgp_lock (bgp);
  pqnode->afi = afi;
  pqnode->safi = safi;
  
  switch (bgp_node_table (rn)->type)
    {
      case BGP_TABLE_MAIN:
        work_queue_add (bm->process_main_queue, pqnode);
        break;
      case BGP_TABLE_RSCLIENT:
        work_queue_add (bm->process_rsclient_queue, pqnode);
        break;
    }
  
  SET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
  return;
}

void
bgp_add_eoiu_mark (struct bgp *bgp, bgp_table_t type)
{
  struct bgp_process_queue *pqnode;

  if ( (bm->process_main_queue == NULL) ||
       (bm->process_rsclient_queue == NULL) )
    bgp_process_queue_init ();

  pqnode = XCALLOC (MTYPE_BGP_PROCESS_QUEUE,
                    sizeof (struct bgp_process_queue));
  if (!pqnode)
    return;

  pqnode->rn = NULL;
  pqnode->bgp = bgp;
  bgp_lock (bgp);
  switch (type)
    {
      case BGP_TABLE_MAIN:
        work_queue_add (bm->process_main_queue, pqnode);
        break;
      case BGP_TABLE_RSCLIENT:
        work_queue_add (bm->process_rsclient_queue, pqnode);
        break;
    }

  return;
}

static int
bgp_maximum_prefix_restart_timer (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_pmax_restart = NULL;

  if (bgp_debug_neighbor_events(peer))
    zlog_debug ("%s Maximum-prefix restart timer expired, restore peering",
		peer->host);

  peer_clear (peer, NULL);

  return 0;
}

int
bgp_maximum_prefix_overflow (struct peer *peer, afi_t afi, 
                             safi_t safi, int always)
{
  if (!CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX))
    return 0;

  if (peer->pcount[afi][safi] > peer->pmax[afi][safi])
    {
      if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT)
         && ! always)
       return 0;

      zlog_info ("%%MAXPFXEXCEED: No. of %s prefix received from %s %ld exceed, "
	         "limit %ld", afi_safi_print (afi, safi), peer->host,
	         peer->pcount[afi][safi], peer->pmax[afi][safi]);
      SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT);

      if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_WARNING))
       return 0;

      {
       u_int8_t ndata[7];

       if (safi == SAFI_MPLS_VPN)
         safi = SAFI_MPLS_LABELED_VPN;
         
       ndata[0] = (afi >>  8);
       ndata[1] = afi;
       ndata[2] = safi;
       ndata[3] = (peer->pmax[afi][safi] >> 24);
       ndata[4] = (peer->pmax[afi][safi] >> 16);
       ndata[5] = (peer->pmax[afi][safi] >> 8);
       ndata[6] = (peer->pmax[afi][safi]);

       SET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
       bgp_notify_send_with_data (peer, BGP_NOTIFY_CEASE,
                                  BGP_NOTIFY_CEASE_MAX_PREFIX, ndata, 7);
      }

      /* Dynamic peers will just close their connection. */
      if (peer_dynamic_neighbor (peer))
        return 1;

      /* restart timer start */
      if (peer->pmax_restart[afi][safi])
	{
	  peer->v_pmax_restart = peer->pmax_restart[afi][safi] * 60;

          if (bgp_debug_neighbor_events(peer))
	    zlog_debug ("%s Maximum-prefix restart timer started for %d secs",
			peer->host, peer->v_pmax_restart);

	  BGP_TIMER_ON (peer->t_pmax_restart, bgp_maximum_prefix_restart_timer,
			peer->v_pmax_restart);
	}

      return 1;
    }
  else
    UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT);

  if (peer->pcount[afi][safi] > (peer->pmax[afi][safi] * peer->pmax_threshold[afi][safi] / 100))
    {
      if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD)
         && ! always)
       return 0;

      zlog_info ("%%MAXPFX: No. of %s prefix received from %s reaches %ld, max %ld",
	         afi_safi_print (afi, safi), peer->host, peer->pcount[afi][safi],
	         peer->pmax[afi][safi]);
      SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD);
    }
  else
    UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD);
  return 0;
}

/* Unconditionally remove the route from the RIB, without taking
 * damping into consideration (eg, because the session went down)
 */
static void
bgp_rib_remove (struct bgp_node *rn, struct bgp_info *ri, struct peer *peer,
		afi_t afi, safi_t safi)
{
  bgp_aggregate_decrement (peer->bgp, &rn->p, ri, afi, safi);
  
  if (!CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    bgp_info_delete (rn, ri); /* keep historical info */
    
  bgp_process (peer->bgp, rn, afi, safi);
}

static void
bgp_rib_withdraw (struct bgp_node *rn, struct bgp_info *ri, struct peer *peer,
		  afi_t afi, safi_t safi)
{
  int status = BGP_DAMP_NONE;

  /* apply dampening, if result is suppressed, we'll be retaining 
   * the bgp_info in the RIB for historical reference.
   */
  if (CHECK_FLAG (peer->bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
      && peer->sort == BGP_PEER_EBGP)
    if ( (status = bgp_damp_withdraw (ri, rn, afi, safi, 0)) 
         == BGP_DAMP_SUPPRESSED)
      {
        bgp_aggregate_decrement (peer->bgp, &rn->p, ri, afi, safi);
        return;
      }
    
  bgp_rib_remove (rn, ri, peer, afi, safi);
}

static struct bgp_info *
info_make (int type, int sub_type, u_short instance, struct peer *peer, struct attr *attr,
	   struct bgp_node *rn)
{
  struct bgp_info *new;

  /* Make new BGP info. */
  new = XCALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_info));
  new->type = type;
  new->instance = instance;
  new->sub_type = sub_type;
  new->peer = peer;
  new->attr = attr;
  new->uptime = bgp_clock ();
  new->net = rn;
  return new;
}

static void
bgp_info_addpath_rx_str(struct bgp_info *ri, char *buf)
{
  if (ri && ri->addpath_rx_id)
    sprintf(buf, " with addpath ID %d", ri->addpath_rx_id);
  else
    sprintf(buf, "");
}

static void
bgp_update_rsclient (struct peer *rsclient, u_int32_t addpath_id,
                     afi_t afi, safi_t safi, struct attr *attr,
                     struct peer *peer, struct prefix *p, int type,
                     int sub_type, struct prefix_rd *prd, u_char *tag)
{
  struct bgp_node *rn;
  struct bgp *bgp;
  struct attr new_attr;
  struct attr_extra new_extra;
  struct attr *attr_new;
  struct attr *attr_new2;
  struct bgp_info *ri;
  struct bgp_info *new;
  const char *reason;
  char buf[SU_ADDRSTRLEN];
  char buf2[30];

  /* Do not insert announces from a rsclient into its own 'bgp_table'. */
  if (peer == rsclient)
    return;

  bgp = peer->bgp;
  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, prd);

  /* Check previously received route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type &&
        ri->addpath_rx_id == addpath_id)
      break;

  /* AS path loop check. */
  if (aspath_loop_check (attr->aspath, rsclient->as) > rsclient->allowas_in[afi][safi])
    {
      reason = "as-path contains our own AS;";
      goto filtered;
    }

  /* Route reflector originator ID check.  */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID)
      && IPV4_ADDR_SAME (&rsclient->remote_id, &attr->extra->originator_id))
    {
      reason = "originator is us;";
      goto filtered;
    }
  
  new_attr.extra = &new_extra;
  bgp_attr_dup (&new_attr, attr);

  /* Apply export policy. */
  if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT) &&
        bgp_export_modifier (rsclient, peer, p, &new_attr, afi, safi) == RMAP_DENY)
    {
      reason = "export-policy;";
      goto filtered;
    }

  attr_new2 = bgp_attr_intern (&new_attr);
  
  /* Apply import policy. */
  if (bgp_import_modifier (rsclient, peer, p, &new_attr, afi, safi) == RMAP_DENY)
    {
      bgp_attr_unintern (&attr_new2);

      reason = "import-policy;";
      goto filtered;
    }

  attr_new = bgp_attr_intern (&new_attr);
  bgp_attr_unintern (&attr_new2);

  /* IPv4 unicast next hop check.  */
  if ((afi == AFI_IP) && ((safi == SAFI_UNICAST) || safi == SAFI_MULTICAST))
    {
     /* Next hop must not be 0.0.0.0 nor Class D/E address. */
      if (new_attr.nexthop.s_addr == 0
         || IPV4_CLASS_DE (ntohl (new_attr.nexthop.s_addr)))
       {
         bgp_attr_unintern (&attr_new);

         reason = "martian next-hop;";
         goto filtered;
       }
    }

  /* If the update is implicit withdraw. */
  if (ri)
    {
      ri->uptime = bgp_clock ();

      /* Same attribute comes in. */
      if (!CHECK_FLAG(ri->flags, BGP_INFO_REMOVED)
          && attrhash_cmp (ri->attr, attr_new))
        {

          if (bgp_debug_update(peer, p, NULL, 1))
            {
              bgp_info_addpath_rx_str(ri, buf2);
              zlog_debug ("%s rcvd %s/%d%s for RS-client %s...duplicate ignored",
                          peer->host,
                          inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                          p->prefixlen, buf2, rsclient->host);
            }

          bgp_unlock_node (rn);
          bgp_attr_unintern (&attr_new);

          return;
        }

      /* Withdraw/Announce before we fully processed the withdraw */
      if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
        bgp_info_restore (rn, ri);
      
      /* Received Logging. */
      if (bgp_debug_update(peer, p, NULL, 1))
        {
          bgp_info_addpath_rx_str(ri, buf2);
          zlog_debug ("%s rcvd %s/%d%s for RS-client %s",
                      peer->host,
                      inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                      p->prefixlen, buf2, rsclient->host);
        }

      /* The attribute is changed. */
      bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

      /* Update to new attribute.  */
      bgp_attr_unintern (&ri->attr);
      ri->attr = attr_new;

      /* Update MPLS tag.  */
      if (safi == SAFI_MPLS_VPN)
        memcpy ((bgp_info_extra_get (ri))->tag, tag, 3);

      bgp_info_set_flag (rn, ri, BGP_INFO_VALID);

      /* Process change. */
      bgp_process (bgp, rn, afi, safi);
      bgp_unlock_node (rn);

      return;
    }

  /* Received Logging. */
  if (bgp_debug_update(peer, p, NULL, 1))
    {
      bgp_info_addpath_rx_str(ri, buf2);
      zlog_debug ("%s rcvd %s/%d%s for RS-client %s",
                  peer->host,
                  inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                  p->prefixlen, buf2, rsclient->host);
    }

  new = info_make(type, sub_type, 0, peer, attr_new, rn);

  /* Update MPLS tag. */
  if (safi == SAFI_MPLS_VPN)
    memcpy ((bgp_info_extra_get (new))->tag, tag, 3);

  bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);
  
  /* Process change. */
  bgp_process (bgp, rn, afi, safi);

  return;

 filtered: 

  /* This BGP update is filtered.  Log the reason then update BGP entry.  */
  if (bgp_debug_update(peer, p, NULL, 1))
    {
      bgp_info_addpath_rx_str(ri, buf2);
      zlog_debug ("%s rcvd UPDATE about %s/%d%s -- DENIED for RS-client %s due to: %s",
                  peer->host,
                  inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                  p->prefixlen, buf2, rsclient->host, reason);
    }

  if (ri)
    bgp_rib_remove (rn, ri, peer, afi, safi);

  bgp_unlock_node (rn);

  return;
}

static void
bgp_withdraw_rsclient (struct peer *rsclient, u_int32_t addpath_id,
                       afi_t afi, safi_t safi, struct peer *peer,
                       struct prefix *p, int type, int sub_type,
                       struct prefix_rd *prd, u_char *tag)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  char buf[SU_ADDRSTRLEN];

  if (rsclient == peer)
    return;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, prd);

  /* Lookup withdrawn route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type &&
        ri->addpath_rx_id == addpath_id)
      break;

  /* Withdraw specified route from routing table. */
  if (ri && ! CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    bgp_rib_withdraw (rn, ri, peer, afi, safi);
  else if (bgp_debug_update(peer, p, NULL, 1))
    zlog_debug ("%s Can't find the route %s/%d", peer->host,
                inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                p->prefixlen);

  /* Unlock bgp_node_get() lock. */
  bgp_unlock_node (rn);
}

static int
bgp_update_main (struct peer *peer, struct prefix *p, u_int32_t addpath_id,
                 struct attr *attr, afi_t afi, safi_t safi, int type,
                 int sub_type, struct prefix_rd *prd, u_char *tag,
                 int soft_reconfig)
{
  int ret;
  int aspath_loop_count = 0;
  struct bgp_node *rn;
  struct bgp *bgp;
  struct attr new_attr;
  struct attr_extra new_extra;
  struct attr *attr_new;
  struct bgp_info *ri;
  struct bgp_info *new;
  const char *reason;
  char buf[SU_ADDRSTRLEN];
  char buf2[30];
  int connected = 0;

  bgp = peer->bgp;
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);
  
  /* When peer's soft reconfiguration enabled.  Record input packet in
     Adj-RIBs-In.  */
  if (! soft_reconfig && CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
      && peer != bgp->peer_self)
    bgp_adj_in_set (rn, peer, attr, addpath_id);

  /* Check previously received route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type &&
        ri->addpath_rx_id == addpath_id)
      break;

  /* AS path local-as loop check. */
  if (peer->change_local_as)
    {
      if (! CHECK_FLAG (peer->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND))
	aspath_loop_count = 1;

      if (aspath_loop_check (attr->aspath, peer->change_local_as) > aspath_loop_count) 
	{
	  reason = "as-path contains our own AS;";
	  goto filtered;
	}
    }

  /* AS path loop check. */
  if (aspath_loop_check (attr->aspath, bgp->as) > peer->allowas_in[afi][safi]
      || (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
	  && aspath_loop_check(attr->aspath, bgp->confed_id)
	  > peer->allowas_in[afi][safi]))
    {
      reason = "as-path contains our own AS;";
      goto filtered;
    }

  /* Route reflector originator ID check.  */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID)
      && IPV4_ADDR_SAME (&bgp->router_id, &attr->extra->originator_id))
    {
      reason = "originator is us;";
      goto filtered;
    }

  /* Route reflector cluster ID check.  */
  if (bgp_cluster_filter (peer, attr))
    {
      reason = "reflected from the same cluster;";
      goto  filtered;
    }

  /* Apply incoming filter.  */
  if (bgp_input_filter (peer, p, attr, afi, safi) == FILTER_DENY)
    {
      reason = "filter;";
      goto filtered;
    }

  new_attr.extra = &new_extra;
  bgp_attr_dup (&new_attr, attr);

  /* Apply incoming route-map.
   * NB: new_attr may now contain newly allocated values from route-map "set"
   * commands, so we need bgp_attr_flush in the error paths, until we intern
   * the attr (which takes over the memory references) */
  if (bgp_input_modifier (peer, p, &new_attr, afi, safi, NULL) == RMAP_DENY)
    {
      reason = "route-map;";
      bgp_attr_flush (&new_attr);
      goto filtered;
    }

  /* IPv4 unicast next hop check.  */
  if (afi == AFI_IP && safi == SAFI_UNICAST)
    {
      /* Next hop must not be 0.0.0.0 nor Class D/E address. Next hop
	 must not be my own address.  */
      if (new_attr.nexthop.s_addr == 0
	  || IPV4_CLASS_DE (ntohl (new_attr.nexthop.s_addr))
	  || bgp_nexthop_self (&new_attr))
	{
	  reason = "martian next-hop;";
	  bgp_attr_flush (&new_attr);
	  goto filtered;
	}
    }

  attr_new = bgp_attr_intern (&new_attr);

  /* If the update is implicit withdraw. */
  if (ri)
    {
      ri->uptime = bgp_clock ();

      /* Same attribute comes in. */
      if (!CHECK_FLAG (ri->flags, BGP_INFO_REMOVED) 
          && attrhash_cmp (ri->attr, attr_new))
	{
	  if (CHECK_FLAG (bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
	      && peer->sort == BGP_PEER_EBGP
	      && CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
	    {
	      if (bgp_debug_update(peer, p, NULL, 1))
                {
                  bgp_info_addpath_rx_str(ri, buf2);
		  zlog_debug ("%s rcvd %s/%d%s",
		              peer->host,
		              inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		              p->prefixlen, buf2);
                }

	      if (bgp_damp_update (ri, rn, afi, safi) != BGP_DAMP_SUPPRESSED)
	        {
                  bgp_aggregate_increment (bgp, p, ri, afi, safi);
                  bgp_process (bgp, rn, afi, safi);
                }
	    }
          else /* Duplicate - odd */
	    {
	      if (bgp_debug_update(peer, p, NULL, 1))
                {
                if (!peer->rcvd_attr_printed)
                  {
                    zlog_debug ("%s rcvd UPDATE w/ attr: %s", peer->host, peer->rcvd_attr_str);
                    peer->rcvd_attr_printed = 1;
                  }

                  bgp_info_addpath_rx_str(ri, buf2);
		  zlog_debug ("%s rcvd %s/%d%s...duplicate ignored",
		              peer->host,
		              inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		              p->prefixlen, buf2);
                }

	      /* graceful restart STALE flag unset. */
	      if (CHECK_FLAG (ri->flags, BGP_INFO_STALE))
		{
		  bgp_info_unset_flag (rn, ri, BGP_INFO_STALE);
		  bgp_process (bgp, rn, afi, safi);
		}
	    }

	  bgp_unlock_node (rn);
	  bgp_attr_unintern (&attr_new);

	  return 0;
	}

      /* Withdraw/Announce before we fully processed the withdraw */
      if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
        {
          if (bgp_debug_update(peer, p, NULL, 1))
            {
              bgp_info_addpath_rx_str(ri, buf2);
              zlog_debug ("%s rcvd %s/%d%s, flapped quicker than processing",
                          peer->host,
                          inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                          p->prefixlen, buf2);
            }
          bgp_info_restore (rn, ri);
        }

      /* Received Logging. */
      if (bgp_debug_update(peer, p, NULL, 1))
        {
          bgp_info_addpath_rx_str(ri, buf2);
	  zlog_debug ("%s rcvd %s/%d%s",
	            peer->host,
	            inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	            p->prefixlen, buf2);
        }

      /* graceful restart STALE flag unset. */
      if (CHECK_FLAG (ri->flags, BGP_INFO_STALE))
	bgp_info_unset_flag (rn, ri, BGP_INFO_STALE);

      /* The attribute is changed. */
      bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
      
      /* implicit withdraw, decrement aggregate and pcount here.
       * only if update is accepted, they'll increment below.
       */
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      
      /* Update bgp route dampening information.  */
      if (CHECK_FLAG (bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
	  && peer->sort == BGP_PEER_EBGP)
	{
	  /* This is implicit withdraw so we should update dampening
	     information.  */
	  if (! CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
	    bgp_damp_withdraw (ri, rn, afi, safi, 1);  
	}
	
      /* Update to new attribute.  */
      bgp_attr_unintern (&ri->attr);
      ri->attr = attr_new;

      /* Update MPLS tag.  */
      if (safi == SAFI_MPLS_VPN)
        memcpy ((bgp_info_extra_get (ri))->tag, tag, 3);

      /* Update bgp route dampening information.  */
      if (CHECK_FLAG (bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING)
	  && peer->sort == BGP_PEER_EBGP)
	{
	  /* Now we do normal update dampening.  */
	  ret = bgp_damp_update (ri, rn, afi, safi);
	  if (ret == BGP_DAMP_SUPPRESSED)
	    {
	      bgp_unlock_node (rn);
	      return 0;
	    }
	}

      /* Nexthop reachability check. */
      if ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST)
	{
	  if (peer->sort == BGP_PEER_EBGP && peer->ttl == 1 &&
	      ! CHECK_FLAG (peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
	      && ! bgp_flag_check(bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
	    connected = 1;
	  else
	    connected = 0;

	  if (bgp_find_or_add_nexthop (bgp, afi, ri, NULL, connected))
	    bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
	  else
	    {
	      if (BGP_DEBUG(nht, NHT))
		{
		  char buf1[INET6_ADDRSTRLEN];
		  inet_ntop(AF_INET, (const void *)&attr_new->nexthop, buf1, INET6_ADDRSTRLEN);
		  zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
		}
	      bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
	    }
	}
      else
	bgp_info_set_flag (rn, ri, BGP_INFO_VALID);

      /* Process change. */
      bgp_aggregate_increment (bgp, p, ri, afi, safi);

      bgp_process (bgp, rn, afi, safi);
      bgp_unlock_node (rn);

      return 0;
    } // End of implicit withdraw

  /* Received Logging. */
  if (bgp_debug_update(peer, p, NULL, 1))
    {
      if (!peer->rcvd_attr_printed)
        {
          zlog_debug ("%s rcvd UPDATE w/ attr: %s", peer->host, peer->rcvd_attr_str);
          peer->rcvd_attr_printed = 1;
        }

      bgp_info_addpath_rx_str(ri, buf2);
      zlog_debug ("%s rcvd %s/%d%s",
	          peer->host,
	          inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	          p->prefixlen, buf2);
    }

  /* Make new BGP info. */
  new = info_make(type, sub_type, 0, peer, attr_new, rn);

  /* Update MPLS tag. */
  if (safi == SAFI_MPLS_VPN)
    memcpy ((bgp_info_extra_get (new))->tag, tag, 3);

  /* Nexthop reachability check. */
  if ((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST)
    {
      if (peer->sort == BGP_PEER_EBGP && peer->ttl == 1 &&
	  ! CHECK_FLAG (peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
	  && ! bgp_flag_check(bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
	connected = 1;
      else
	connected = 0;

      if (bgp_find_or_add_nexthop (bgp, afi, new, NULL, connected))
	bgp_info_set_flag (rn, new, BGP_INFO_VALID);
      else
	{
	  if (BGP_DEBUG(nht, NHT))
	    {
	      char buf1[INET6_ADDRSTRLEN];
	      inet_ntop(AF_INET, (const void *)&attr_new->nexthop, buf1, INET6_ADDRSTRLEN);
	      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
	    }
	  bgp_info_unset_flag (rn, new, BGP_INFO_VALID);
	}
    }
  else
    bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Addpath ID */
  new->addpath_rx_id = addpath_id;
  new->addpath_tx_id = 0;

  /* Increment prefix */
  bgp_aggregate_increment (bgp, p, new, afi, safi);
  
  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);

  /* If maximum prefix count is configured and current prefix
     count exeed it. */
  if (bgp_maximum_prefix_overflow (peer, afi, safi, 0))
    return -1;

  /* Process change. */
  bgp_process (bgp, rn, afi, safi);

  return 0;

  /* This BGP update is filtered.  Log the reason then update BGP
     entry.  */
 filtered:
  if (bgp_debug_update(peer, p, NULL, 1))
    {
      if (!peer->rcvd_attr_printed)
        {
          zlog_debug ("%s rcvd UPDATE w/ attr: %s", peer->host, peer->rcvd_attr_str);
          peer->rcvd_attr_printed = 1;
        }

      bgp_info_addpath_rx_str(ri, buf2);
      zlog_debug ("%s rcvd UPDATE about %s/%d%s -- DENIED due to: %s",
                  peer->host,
                  inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                  p->prefixlen, buf2, reason);
    }

  if (ri)
    bgp_rib_remove (rn, ri, peer, afi, safi);

  bgp_unlock_node (rn);

  return 0;
}

int
bgp_update (struct peer *peer, struct prefix *p, u_int32_t addpath_id,
            struct attr *attr, afi_t afi, safi_t safi, int type, int sub_type,
            struct prefix_rd *prd, u_char *tag, int soft_reconfig)
{
  struct peer *rsclient;
  struct listnode *node, *nnode;
  struct bgp *bgp;
  int ret;

  ret = bgp_update_main (peer, p, addpath_id, attr, afi, safi, type, sub_type,
                         prd, tag, soft_reconfig);

  bgp = peer->bgp;

  /* Process the update for each RS-client. */
  for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
    {
      if (CHECK_FLAG (rsclient->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        bgp_update_rsclient (rsclient, addpath_id, afi, safi, attr, peer, p,
                             type, sub_type, prd, tag);
    }

  return ret;
}

int
bgp_withdraw (struct peer *peer, struct prefix *p, u_int32_t addpath_id,
              struct attr *attr, afi_t afi, safi_t safi, int type, int sub_type,
	      struct prefix_rd *prd, u_char *tag)
{
  struct bgp *bgp;
  char buf[SU_ADDRSTRLEN];
  char buf2[30];
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct peer *rsclient;
  struct listnode *node, *nnode;

  bgp = peer->bgp;

  /* Process the withdraw for each RS-client. */
  for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
    {
      if (CHECK_FLAG (rsclient->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        bgp_withdraw_rsclient (rsclient, addpath_id, afi, safi, peer, p, type,
                               sub_type, prd, tag);
    }

  /* Lookup node. */
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* If peer is soft reconfiguration enabled.  Record input packet for
     further calculation. */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
      && peer != bgp->peer_self)
    bgp_adj_in_unset (rn, peer, addpath_id);

  /* Lookup withdrawn route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type &&
        ri->addpath_rx_id == addpath_id)
      break;

  /* Logging. */
  if (bgp_debug_update(peer, p, NULL, 1))
    {
      bgp_info_addpath_rx_str(ri, buf2);
      zlog_debug ("%s rcvd UPDATE about %s/%d%s -- withdrawn",
	        peer->host,
	        inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	        p->prefixlen, buf2);
    }

  /* Withdraw specified route from routing table. */
  if (ri && ! CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    bgp_rib_withdraw (rn, ri, peer, afi, safi);
  else if (bgp_debug_update(peer, p, NULL, 1))
    zlog_debug ("%s Can't find the route %s/%d", peer->host,
	        inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	        p->prefixlen);

  /* Unlock bgp_node_get() lock. */
  bgp_unlock_node (rn);

  return 0;
}

void
bgp_default_originate (struct peer *peer, afi_t afi, safi_t safi, int withdraw)
{
  struct update_subgroup *subgrp;
  subgrp = peer_subgroup(peer, afi, safi);
  subgroup_default_originate(subgrp, withdraw);
}


/*
 * bgp_stop_announce_route_timer
 */
void
bgp_stop_announce_route_timer (struct peer_af *paf)
{
  if (!paf->t_announce_route)
    return;
 
  THREAD_TIMER_OFF (paf->t_announce_route);
}

/*
 * bgp_announce_route_timer_expired
 *
 * Callback that is invoked when the route announcement timer for a
 * peer_af expires.
 */
static int
bgp_announce_route_timer_expired (struct thread *t)
{
  struct peer_af *paf;
  struct peer *peer;


  paf = THREAD_ARG (t);
  peer = paf->peer;

  assert (paf->t_announce_route);
  paf->t_announce_route = NULL;

  if (peer->status != Established)
    return 0;

  if (!peer->afc_nego[paf->afi][paf->safi])
    return 0;

  peer_af_announce_route (paf, 1);
  return 0;
}

/*
 * bgp_announce_route
 *
 * *Triggers* announcement of routes of a given AFI/SAFI to a peer.
 */
void
bgp_announce_route (struct peer *peer, afi_t afi, safi_t safi)
{
  struct peer_af *paf;
  struct update_subgroup *subgrp;

  paf = peer_af_find (peer, afi, safi);
  if (!paf)
    return;
  subgrp = PAF_SUBGRP(paf);

  /*
   * Ignore if subgroup doesn't exist (implies AF is not negotiated)
   * or a refresh has already been triggered.
   */
  if (!subgrp || paf->t_announce_route)
    return;

  /*
   * Start a timer to stagger/delay the announce. This serves
   * two purposes - announcement can potentially be combined for
   * multiple peers and the announcement doesn't happen in the
   * vty context.
   */
  THREAD_TIMER_MSEC_ON (master, paf->t_announce_route,
			bgp_announce_route_timer_expired, paf,
                        (subgrp->peer_count == 1) ?
			BGP_ANNOUNCE_ROUTE_SHORT_DELAY_MS :
			BGP_ANNOUNCE_ROUTE_DELAY_MS);
}

/*
 * Announce routes from all AF tables to a peer.
 *
 * This should ONLY be called when there is a need to refresh the
 * routes to the peer based on a policy change for this peer alone
 * or a route refresh request received from the peer.
 * The operation will result in splitting the peer from its existing
 * subgroups and putting it in new subgroups.
 */
void
bgp_announce_route_all (struct peer *peer)
{
  struct peer_af *paf;
  int af;
  afi_t afi;
  safi_t safi;
  
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_announce_route (peer, afi, safi);
}

static void
bgp_soft_reconfig_table_rsclient (struct peer *rsclient, afi_t afi,
        safi_t safi, struct bgp_table *table, struct prefix_rd *prd)
{
  struct bgp_node *rn;
  struct bgp_adj_in *ain;

  if (! table)
    table = rsclient->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain; ain = ain->next)
      {
        struct bgp_info *ri = rn->info;
        u_char *tag = (ri && ri->extra) ? ri->extra->tag : NULL;

        bgp_update_rsclient (rsclient, ri->addpath_rx_id, afi, safi, ain->attr,
                             ain->peer, &rn->p, ZEBRA_ROUTE_BGP,
                             BGP_ROUTE_NORMAL, prd, tag);
      }
}

void
bgp_soft_reconfig_rsclient (struct peer *rsclient, afi_t afi, safi_t safi)
{
  struct bgp_table *table;
  struct bgp_node *rn;
  
  if (safi != SAFI_MPLS_VPN)
    bgp_soft_reconfig_table_rsclient (rsclient, afi, safi, NULL, NULL);

  else
    for (rn = bgp_table_top (rsclient->bgp->rib[afi][safi]); rn;
            rn = bgp_route_next (rn))
      if ((table = rn->info) != NULL)
        {
          struct prefix_rd prd;
          prd.family = AF_UNSPEC;
          prd.prefixlen = 64;
          memcpy(&prd.val, rn->p.u.val, 8);

          bgp_soft_reconfig_table_rsclient (rsclient, afi, safi, table, &prd);
        }
}

static void
bgp_soft_reconfig_table (struct peer *peer, afi_t afi, safi_t safi,
			 struct bgp_table *table, struct prefix_rd *prd)
{
  int ret;
  struct bgp_node *rn;
  struct bgp_adj_in *ain;

  if (! table)
    table = peer->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain; ain = ain->next)
      {
	if (ain->peer == peer)
	  {
	    struct bgp_info *ri = rn->info;
	    u_char *tag = (ri && ri->extra) ? ri->extra->tag : NULL;

	    ret = bgp_update (peer, &rn->p, ain->addpath_rx_id, ain->attr,
                              afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
			      prd, tag, 1);

	    if (ret < 0)
	      {
		bgp_unlock_node (rn);
		return;
	      }
	  }
      }
}

void
bgp_soft_reconfig_in (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_table *table;

  if (peer->status != Established)
    return;

  if (safi != SAFI_MPLS_VPN)
    bgp_soft_reconfig_table (peer, afi, safi, NULL, NULL);
  else
    for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
	 rn = bgp_route_next (rn))
      if ((table = rn->info) != NULL)
        {
          struct prefix_rd prd;
          prd.family = AF_UNSPEC;
          prd.prefixlen = 64;
          memcpy(&prd.val, rn->p.u.val, 8);

          bgp_soft_reconfig_table (peer, afi, safi, table, &prd);
        }
}


struct bgp_clear_node_queue
{
  struct bgp_node *rn;
  enum bgp_clear_route_type purpose;
};

static wq_item_status
bgp_clear_route_node (struct work_queue *wq, void *data)
{
  struct bgp_clear_node_queue *cnq = data;
  struct bgp_node *rn = cnq->rn;
  struct peer *peer = wq->spec.data;
  struct bgp_info *ri;
  afi_t afi = bgp_node_table (rn)->afi;
  safi_t safi = bgp_node_table (rn)->safi;
  
  assert (rn && peer);
  
  /* It is possible that we have multiple paths for a prefix from a peer
   * if that peer is using AddPath.
   */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer || cnq->purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
      {
        /* graceful restart STALE flag set. */
        if (CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT)
            && peer->nsf[afi][safi]
            && ! CHECK_FLAG (ri->flags, BGP_INFO_STALE)
            && ! CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
          bgp_info_set_flag (rn, ri, BGP_INFO_STALE);
        else
          bgp_rib_remove (rn, ri, peer, afi, safi);
      }
  return WQ_SUCCESS;
}

static void
bgp_clear_node_queue_del (struct work_queue *wq, void *data)
{
  struct bgp_clear_node_queue *cnq = data;
  struct bgp_node *rn = cnq->rn;
  struct bgp_table *table = bgp_node_table (rn);
  
  bgp_unlock_node (rn); 
  bgp_table_unlock (table);
  XFREE (MTYPE_BGP_CLEAR_NODE_QUEUE, cnq);
}

static void
bgp_clear_node_complete (struct work_queue *wq)
{
  struct peer *peer = wq->spec.data;
  
  /* Tickle FSM to start moving again */
  BGP_EVENT_ADD (peer, Clearing_Completed);

  peer_unlock (peer); /* bgp_clear_route */
}

static void
bgp_clear_node_queue_init (struct peer *peer)
{
  char wname[sizeof("clear xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx")];
  
  snprintf (wname, sizeof(wname), "clear %s", peer->host);
#undef CLEAR_QUEUE_NAME_LEN

  if ( (peer->clear_node_queue = work_queue_new (bm->master, wname)) == NULL)
    {
      zlog_err ("%s: Failed to allocate work queue", __func__);
      exit (1);
    }
  peer->clear_node_queue->spec.hold = 10;
  peer->clear_node_queue->spec.workfunc = &bgp_clear_route_node;
  peer->clear_node_queue->spec.del_item_data = &bgp_clear_node_queue_del;
  peer->clear_node_queue->spec.completion_func = &bgp_clear_node_complete;
  peer->clear_node_queue->spec.max_retries = 0;
  
  /* we only 'lock' this peer reference when the queue is actually active */
  peer->clear_node_queue->spec.data = peer;
}

static void
bgp_clear_route_table (struct peer *peer, afi_t afi, safi_t safi,
                       struct bgp_table *table, struct peer *rsclient,
                       enum bgp_clear_route_type purpose)
{
  struct bgp_node *rn;
  
  
  if (! table)
    table = (rsclient) ? rsclient->rib[afi][safi] : peer->bgp->rib[afi][safi];
  
  /* If still no table => afi/safi isn't configured at all or smth. */
  if (! table)
    return;
  
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      struct bgp_info *ri;
      struct bgp_adj_in *ain;
      struct bgp_adj_in *ain_next;
      struct bgp_adj_out *aout;

      /* XXX:TODO: This is suboptimal, every non-empty route_node is
       * queued for every clearing peer, regardless of whether it is
       * relevant to the peer at hand.
       *
       * Overview: There are 3 different indices which need to be
       * scrubbed, potentially, when a peer is removed:
       *
       * 1 peer's routes visible via the RIB (ie accepted routes)
       * 2 peer's routes visible by the (optional) peer's adj-in index
       * 3 other routes visible by the peer's adj-out index
       *
       * 3 there is no hurry in scrubbing, once the struct peer is
       * removed from bgp->peer, we could just GC such deleted peer's
       * adj-outs at our leisure.
       *
       * 1 and 2 must be 'scrubbed' in some way, at least made
       * invisible via RIB index before peer session is allowed to be
       * brought back up. So one needs to know when such a 'search' is
       * complete.
       *
       * Ideally:
       *
       * - there'd be a single global queue or a single RIB walker
       * - rather than tracking which route_nodes still need to be
       *   examined on a peer basis, we'd track which peers still
       *   aren't cleared
       *
       * Given that our per-peer prefix-counts now should be reliable,
       * this may actually be achievable. It doesn't seem to be a huge
       * problem at this time,
       *
       * It is possible that we have multiple paths for a prefix from a peer
       * if that peer is using AddPath.
       */
      ain = rn->adj_in;
      while (ain)
        {
          ain_next = ain->next;

          if (ain->peer == peer || purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
            {
              bgp_adj_in_remove (rn, ain);
              bgp_unlock_node (rn);
            }

          ain = ain_next;
        }

      /*
       * Can't do this anymore. adj-outs are not maintained per peer.
       *
      for (aout = rn->adj_out; aout; aout = aout->next)
        if (aout->peer == peer || purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
          {
            bgp_adj_out_remove (rn, aout, peer, afi, safi);
            bgp_unlock_node (rn);
            break;
          }
      */
      for (ri = rn->info; ri; ri = ri->next)
        if (ri->peer == peer || purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
          {
            struct bgp_clear_node_queue *cnq;

            /* both unlocked in bgp_clear_node_queue_del */
            bgp_table_lock (bgp_node_table (rn));
            bgp_lock_node (rn);
            cnq = XCALLOC (MTYPE_BGP_CLEAR_NODE_QUEUE,
                           sizeof (struct bgp_clear_node_queue));
            cnq->rn = rn;
            cnq->purpose = purpose;
            work_queue_add (peer->clear_node_queue, cnq);
            break;
          }
    }
  return;
}

void
bgp_clear_route (struct peer *peer, afi_t afi, safi_t safi,
                 enum bgp_clear_route_type purpose)
{
  struct bgp_node *rn;
  struct bgp_table *table;
  struct peer *rsclient;
  struct listnode *node, *nnode;

  if (peer->clear_node_queue == NULL)
    bgp_clear_node_queue_init (peer);
  
  /* bgp_fsm.c keeps sessions in state Clearing, not transitioning to
   * Idle until it receives a Clearing_Completed event. This protects
   * against peers which flap faster than we can we clear, which could
   * lead to:
   *
   * a) race with routes from the new session being installed before
   *    clear_route_node visits the node (to delete the route of that
   *    peer)
   * b) resource exhaustion, clear_route_node likely leads to an entry
   *    on the process_main queue. Fast-flapping could cause that queue
   *    to grow and grow.
   */
  if (!peer->clear_node_queue->thread)
    peer_lock (peer); /* bgp_clear_node_complete */

  switch (purpose)
    {
    case BGP_CLEAR_ROUTE_NORMAL:
      if (safi != SAFI_MPLS_VPN)
        bgp_clear_route_table (peer, afi, safi, NULL, NULL, purpose);
      else
        for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
             rn = bgp_route_next (rn))
          if ((table = rn->info) != NULL)
            bgp_clear_route_table (peer, afi, safi, table, NULL, purpose);

      for (ALL_LIST_ELEMENTS (peer->bgp->rsclient, node, nnode, rsclient))
        if (CHECK_FLAG(rsclient->af_flags[afi][safi],
                       PEER_FLAG_RSERVER_CLIENT))
          bgp_clear_route_table (peer, afi, safi, NULL, rsclient, purpose);
      break;

    case BGP_CLEAR_ROUTE_MY_RSCLIENT:
      bgp_clear_route_table (peer, afi, safi, NULL, peer, purpose);
      break;

    default:
      assert (0);
      break;
    }
  
  /* If no routes were cleared, nothing was added to workqueue, the
   * completion function won't be run by workqueue code - call it here. 
   * XXX: Actually, this assumption doesn't hold, see
   * bgp_clear_route_table(), we queue all non-empty nodes.
   *
   * Additionally, there is a presumption in FSM that clearing is only
   * really needed if peer state is Established - peers in
   * pre-Established states shouldn't have any route-update state
   * associated with them (in or out).
   *
   * We still can get here in pre-Established though, through
   * peer_delete -> bgp_fsm_change_status, so this is a useful sanity
   * check to ensure the assumption above holds.
   *
   * At some future point, this check could be move to the top of the
   * function, and do a quick early-return when state is
   * pre-Established, avoiding above list and table scans. Once we're
   * sure it is safe..
   */
  if (!peer->clear_node_queue->thread)
    bgp_clear_node_complete (peer->clear_node_queue);
}
  
void
bgp_clear_route_all (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_clear_route (peer, afi, safi, BGP_CLEAR_ROUTE_NORMAL);
}

void
bgp_clear_adj_in (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_adj_in *ain;
  struct bgp_adj_in *ain_next;

  table = peer->bgp->rib[afi][safi];

  /* It is possible that we have multiple paths for a prefix from a peer
   * if that peer is using AddPath.
   */
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      ain = rn->adj_in;

      while (ain)
        {
          ain_next = ain->next;

          if (ain->peer == peer)
            {
              bgp_adj_in_remove (rn, ain);
              bgp_unlock_node (rn);
	    }

          ain = ain_next;
        }
    }
}

void
bgp_clear_stale_route (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_table *table;

  table = peer->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->next)
	if (ri->peer == peer)
	  {
	    if (CHECK_FLAG (ri->flags, BGP_INFO_STALE))
	      bgp_rib_remove (rn, ri, peer, afi, safi);
	    break;
	  }
    }
}

/* Delete all kernel routes. */
void
bgp_cleanup_routes (void)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_info *ri;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      table = bgp->rib[AFI_IP][SAFI_UNICAST];

      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
	for (ri = rn->info; ri; ri = ri->next)
	  if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
	      && ri->type == ZEBRA_ROUTE_BGP 
	      && (ri->sub_type == BGP_ROUTE_NORMAL ||
	          ri->sub_type == BGP_ROUTE_AGGREGATE))
	    bgp_zebra_withdraw (&rn->p, ri,SAFI_UNICAST);

      table = bgp->rib[AFI_IP6][SAFI_UNICAST];

      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
	for (ri = rn->info; ri; ri = ri->next)
	  if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
	      && ri->type == ZEBRA_ROUTE_BGP 
	      && (ri->sub_type == BGP_ROUTE_NORMAL ||
	          ri->sub_type == BGP_ROUTE_AGGREGATE))
	    bgp_zebra_withdraw (&rn->p, ri,SAFI_UNICAST);
    }
}

void
bgp_reset (void)
{
  vty_reset ();
  bgp_zclient_reset ();
  access_list_reset ();
  prefix_list_reset ();
}

/* Parse NLRI stream.  Withdraw NLRI is recognized by NULL attr
   value. */
int
bgp_nlri_parse (struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  struct prefix p;
  int psize;
  int ret;
  afi_t afi;
  safi_t safi;
  u_char addpath_encoded;
  u_int32_t addpath_id;

  /* Check peer status. */
  if (peer->status != Established)
    return 0;
  
  pnt = packet->nlri;
  lim = pnt + packet->length;
  afi = packet->afi;
  safi = packet->safi;
  addpath_id = 0;

  addpath_encoded = (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) &&
                     CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV));

  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      if (addpath_encoded)
        {

          /* When packet overflow occurs return immediately. */
          if (pnt + BGP_ADDPATH_ID_LEN > lim)
            return -1;

          addpath_id = ntohl(*((uint32_t*) pnt));
          pnt += BGP_ADDPATH_ID_LEN;
        }

      /* Fetch prefix length. */
      p.prefixlen = *pnt++;
      p.family = afi2family (afi);
      
      /* Already checked in nlri_sanity_check().  We do double check
         here. */
      if ((afi == AFI_IP && p.prefixlen > 32)
	  || (afi == AFI_IP6 && p.prefixlen > 128))
	return -1;

      /* Packet size overflow check. */
      psize = PSIZE (p.prefixlen);

      /* When packet overflow occur return immediately. */
      if (pnt + psize > lim)
	return -1;

      /* Fetch prefix from NLRI packet. */
      memcpy (&p.u.prefix, pnt, psize);

      /* Check address. */
      if (afi == AFI_IP && safi == SAFI_UNICAST)
	{
	  if (IN_CLASSD (ntohl (p.u.prefix4.s_addr)))
	    {
	     /* 
 	      * From draft-ietf-idr-bgp4-22, Section 6.3: 
	      * If a BGP router receives an UPDATE message with a
	      * semantically incorrect NLRI field, in which a prefix is
	      * semantically incorrect (eg. an unexpected multicast IP
	      * address), it should ignore the prefix.
	      */
	      zlog_err ("IPv4 unicast NLRI is multicast address %s",
		        inet_ntoa (p.u.prefix4));

	      return -1;
	    }
	}

#ifdef HAVE_IPV6
      /* Check address. */
      if (afi == AFI_IP6 && safi == SAFI_UNICAST)
	{
	  if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
	    {
	      char buf[BUFSIZ];

	      zlog_warn ("IPv6 link-local NLRI received %s ignore this NLRI",
		         inet_ntop (AF_INET6, &p.u.prefix6, buf, BUFSIZ));

	      continue;
	    }
	}
#endif /* HAVE_IPV6 */

      /* Normal process. */
      if (attr)
	ret = bgp_update (peer, &p, addpath_id, attr, afi, safi,
			  ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL, 0);
      else
	ret = bgp_withdraw (peer, &p, addpath_id, attr, afi, safi,
			    ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL);

      /* Address family configuration mismatch or maximum-prefix count
         overflow. */
      if (ret < 0)
	return -1;
    }

  /* Packet length consistency check. */
  if (pnt != lim)
    return -1;

  return 0;
}

/* NLRI encode syntax check routine. */
int
bgp_nlri_sanity_check (struct peer *peer, int afi, safi_t safi, u_char *pnt,
		       bgp_size_t length, int *numpfx)
{
  u_char *end;
  u_char prefixlen;
  int psize;
  u_char addpath_encoded;

  *numpfx = 0;
  end = pnt + length;

  addpath_encoded = (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) &&
                     CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV));

  /* RFC1771 6.3 The NLRI field in the UPDATE message is checked for
     syntactic validity.  If the field is syntactically incorrect,
     then the Error Subcode is set to Invalid Network Field. */

  while (pnt < end)
    {

      /* If the NLRI is encoded using addpath then the first 4 bytes are
       * the addpath ID. */
      if (addpath_encoded)
        {
          if (pnt + BGP_ADDPATH_ID_LEN > end)
	    {
              zlog_err ("%s [Error] Update packet error"
                        " (prefix data addpath overflow)",
                        peer->host);
              bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR,
                               BGP_NOTIFY_UPDATE_INVAL_NETWORK);
              return -1;
            }
          pnt += BGP_ADDPATH_ID_LEN;
        }

      prefixlen = *pnt++;
      
      /* Prefix length check. */
      if ((afi == AFI_IP && prefixlen > 32)
	  || (afi == AFI_IP6 && prefixlen > 128))
	{
	  zlog_err ("%s [Error] Update packet error (wrong prefix length %d)",
		    peer->host, prefixlen);
	  bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_INVAL_NETWORK);
	  return -1;
	}

      /* Packet size overflow check. */
      psize = PSIZE (prefixlen);

      if (pnt + psize > end)
	{
	  zlog_err ("%s [Error] Update packet error"
		    " (prefix data overflow prefix size is %d)",
		    peer->host, psize);
	  bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_INVAL_NETWORK);
	  return -1;
	}

      pnt += psize;
      (*numpfx)++;
    }

  /* Packet length consistency check. */
  if (pnt != end)
    {
      zlog_err ("%s [Error] Update packet error"
		" (prefix length mismatch with total length)",
		peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_INVAL_NETWORK);
      return -1;
    }
  return 0;
}

static struct bgp_static *
bgp_static_new (void)
{
  return XCALLOC (MTYPE_BGP_STATIC, sizeof (struct bgp_static));
}

static void
bgp_static_free (struct bgp_static *bgp_static)
{
  if (bgp_static->rmap.name)
    free (bgp_static->rmap.name);
  XFREE (MTYPE_BGP_STATIC, bgp_static);
}

static void
bgp_static_withdraw_rsclient (struct bgp *bgp, struct peer *rsclient,
        struct prefix *p, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, NULL);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
       && ri->type == ZEBRA_ROUTE_BGP
       && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

static void
bgp_static_update_rsclient (struct peer *rsclient, struct prefix *p,
                            struct bgp_static *bgp_static,
                            afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_info *new;
  struct bgp_info info;
  struct attr *attr_new;
  struct attr attr;
  struct attr new_attr;
  struct attr_extra new_extra;
  struct bgp *bgp;
  int ret;
  char buf[SU_ADDRSTRLEN];

  bgp = rsclient->bgp;

  assert (bgp_static);
  if (!bgp_static)
    return;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, NULL);

  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);

  attr.nexthop = bgp_static->igpnexthop;
  attr.med = bgp_static->igpmetric;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
  
  if (bgp_static->atomic)
    attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);
  
  /* Apply network route-map for export to this rsclient. */
  if (bgp_static->rmap.name)
    {
      struct attr attr_tmp = attr;
      info.peer = rsclient;
      info.attr = &attr_tmp;
      
      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_EXPORT);
      SET_FLAG (rsclient->rmap_type, PEER_RMAP_TYPE_NETWORK);

      ret = route_map_apply (bgp_static->rmap.map, p, RMAP_BGP, &info);

      rsclient->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
        {
          /* Free uninterned attribute. */
          bgp_attr_flush (&attr_tmp);

          /* Unintern original. */
          aspath_unintern (&attr.aspath);
          bgp_static_withdraw_rsclient (bgp, rsclient, p, afi, safi);
          bgp_attr_extra_free (&attr);
          
          return;
        }
      attr_new = bgp_attr_intern (&attr_tmp);
    }
  else
    attr_new = bgp_attr_intern (&attr);

  new_attr.extra = &new_extra;
  bgp_attr_dup(&new_attr, attr_new);
  
  SET_FLAG (bgp->peer_self->rmap_type, PEER_RMAP_TYPE_NETWORK);

  if (bgp_import_modifier (rsclient, bgp->peer_self, p, &new_attr, afi, safi) 
        == RMAP_DENY)
    {
      /* This BGP update is filtered.  Log the reason then update BGP entry.  */
      if (bgp_debug_update(rsclient, p, NULL, 1))
        zlog_debug ("Static UPDATE about %s/%d -- DENIED for RS-client %s due to: import-policy",
                    inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                    p->prefixlen, rsclient->host);

      bgp->peer_self->rmap_type = 0;

      bgp_attr_unintern (&attr_new);
      aspath_unintern (&attr.aspath);
      bgp_attr_extra_free (&attr);

      bgp_static_withdraw_rsclient (bgp, rsclient, p, afi, safi);
      
      return;
    }

  bgp->peer_self->rmap_type = 0;

  bgp_attr_unintern (&attr_new);
  attr_new = bgp_attr_intern (&new_attr);

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self && ri->type == ZEBRA_ROUTE_BGP
            && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  if (ri)
       {
      if (attrhash_cmp (ri->attr, attr_new) &&
	  !CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
        {
          bgp_unlock_node (rn);
          bgp_attr_unintern (&attr_new);
          aspath_unintern (&attr.aspath);
          bgp_attr_extra_free (&attr);
          return;
       }
      else
        {
          /* The attribute is changed. */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* Rewrite BGP route information. */
	  if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
	    bgp_info_restore(rn, ri);
          bgp_attr_unintern (&ri->attr);
          ri->attr = attr_new;
          ri->uptime = bgp_clock ();

	  /* Nexthop reachability check. */
	  if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
	    {
	      if (bgp_find_or_add_nexthop (bgp, afi, ri, NULL, 0))
		bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
	      else
		{
		  if (BGP_DEBUG(nht, NHT))
		    {
		      char buf1[INET6_ADDRSTRLEN];
		      inet_ntop(AF_INET, (const void *)&attr_new->nexthop,
				buf1, INET6_ADDRSTRLEN);
		      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
		    }
		  bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
		}
	    }
          /* Process change. */
          bgp_process (bgp, rn, afi, safi);
          bgp_unlock_node (rn);
          aspath_unintern (&attr.aspath);
          bgp_attr_extra_free (&attr);
          return;
        }
    }

  /* Make new BGP info. */
  new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, bgp->peer_self,
		  attr_new, rn);
  /* Nexthop reachability check. */
  if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
    {
      if (bgp_find_or_add_nexthop (bgp, afi, new, NULL, 0))
	bgp_info_set_flag (rn, new, BGP_INFO_VALID);
      else
	{
	  if (BGP_DEBUG(nht, NHT))
	    {
	      char buf1[INET6_ADDRSTRLEN];
	      inet_ntop(AF_INET, (const void *)&attr_new->nexthop,
			buf1, INET6_ADDRSTRLEN);
	      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
	    }
	  bgp_info_unset_flag (rn, new, BGP_INFO_VALID);
	}
    }
  else
    bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);
  
  /* Process change. */
  bgp_process (bgp, rn, afi, safi);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

static void
bgp_static_update_main (struct bgp *bgp, struct prefix *p,
			struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_info *new;
  struct bgp_info info;
  struct attr attr;
  struct attr *attr_new;
  int ret;

  assert (bgp_static);
  if (!bgp_static)
    return;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, NULL);

  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
  
  attr.nexthop = bgp_static->igpnexthop;
  attr.med = bgp_static->igpmetric;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  if (bgp_static->atomic)
    attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  /* Apply route-map. */
  if (bgp_static->rmap.name)
    {
      struct attr attr_tmp = attr;
      info.peer = bgp->peer_self;
      info.attr = &attr_tmp;

      SET_FLAG (bgp->peer_self->rmap_type, PEER_RMAP_TYPE_NETWORK);

      ret = route_map_apply (bgp_static->rmap.map, p, RMAP_BGP, &info);

      bgp->peer_self->rmap_type = 0;

      if (ret == RMAP_DENYMATCH)
	{    
	  /* Free uninterned attribute. */
	  bgp_attr_flush (&attr_tmp);

	  /* Unintern original. */
	  aspath_unintern (&attr.aspath);
	  bgp_attr_extra_free (&attr);
	  bgp_static_withdraw (bgp, p, afi, safi);
	  return;
	}
      attr_new = bgp_attr_intern (&attr_tmp);
    }
  else
    attr_new = bgp_attr_intern (&attr);

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self && ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_STATIC)
      break;

  if (ri)
    {
      if (attrhash_cmp (ri->attr, attr_new) &&
	  !CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
	{
	  bgp_unlock_node (rn);
	  bgp_attr_unintern (&attr_new);
	  aspath_unintern (&attr.aspath);
	  bgp_attr_extra_free (&attr);
	  return;
	}
      else
	{
	  /* The attribute is changed. */
	  bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

	  /* Rewrite BGP route information. */
	  if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
	    bgp_info_restore(rn, ri);
	  else
	    bgp_aggregate_decrement (bgp, p, ri, afi, safi);
	  bgp_attr_unintern (&ri->attr);
	  ri->attr = attr_new;
	  ri->uptime = bgp_clock ();

	  /* Nexthop reachability check. */
	  if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
	    {
	      if (bgp_find_or_add_nexthop (bgp, afi, ri, NULL, 0))
		bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
	      else
		{
		  if (BGP_DEBUG(nht, NHT))
		    {
		      char buf1[INET6_ADDRSTRLEN];
		      inet_ntop(AF_INET, (const void *)&attr_new->nexthop,
				buf1, INET6_ADDRSTRLEN);
		      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
		    }
		  bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
		}
	    }
	  /* Process change. */
	  bgp_aggregate_increment (bgp, p, ri, afi, safi);
	  bgp_process (bgp, rn, afi, safi);
	  bgp_unlock_node (rn);
	  aspath_unintern (&attr.aspath);
	  bgp_attr_extra_free (&attr);
	  return;
	}
    }

  /* Make new BGP info. */
  new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, bgp->peer_self, attr_new,
		  rn);
  /* Nexthop reachability check. */
  if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
    {
      if (bgp_find_or_add_nexthop (bgp, afi, new, NULL, 0))
	bgp_info_set_flag (rn, new, BGP_INFO_VALID);
      else
	{
	  if (BGP_DEBUG(nht, NHT))
	    {
	      char buf1[INET6_ADDRSTRLEN];
	      inet_ntop(AF_INET, (const void *)&attr_new->nexthop, buf1,
			INET6_ADDRSTRLEN);
	      zlog_debug("%s(%s): NH unresolved", __FUNCTION__, buf1);
	    }
	  bgp_info_unset_flag (rn, new, BGP_INFO_VALID);
	}
    }
  else
    bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Aggregate address increment. */
  bgp_aggregate_increment (bgp, p, new, afi, safi);
  
  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);
  
  /* Process change. */
  bgp_process (bgp, rn, afi, safi);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

void
bgp_static_update (struct bgp *bgp, struct prefix *p,
                  struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
  struct peer *rsclient;
  struct listnode *node, *nnode;

  bgp_static_update_main (bgp, p, bgp_static, afi, safi);

  for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
    {
      if (CHECK_FLAG (rsclient->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        bgp_static_update_rsclient (rsclient, p, bgp_static, afi, safi);
    }
}

static void
bgp_static_update_vpnv4 (struct bgp *bgp, struct prefix *p, afi_t afi,
			 safi_t safi, struct prefix_rd *prd, u_char *tag)
{
  struct bgp_node *rn;
  struct bgp_info *new;
  
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* Make new BGP info. */
  new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, bgp->peer_self,
		  bgp_attr_default_intern(BGP_ORIGIN_IGP), rn);

  SET_FLAG (new->flags, BGP_INFO_VALID);
  new->extra = bgp_info_extra_new();
  memcpy (new->extra->tag, tag, 3);

  /* Aggregate address increment. */
  bgp_aggregate_increment (bgp, p, new, afi, safi);
  
  /* Register new BGP information. */
  bgp_info_add (rn, new);

  /* route_node_get lock */
  bgp_unlock_node (rn);
  
  /* Process change. */
  bgp_process (bgp, rn, afi, safi);
}

void
bgp_static_withdraw (struct bgp *bgp, struct prefix *p, afi_t afi,
		     safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, NULL);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_unlink_nexthop(ri);
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

void
bgp_check_local_routes_rsclient (struct peer *rsclient, afi_t afi, safi_t safi)
{
  struct bgp_static *bgp_static;
  struct bgp *bgp;
  struct bgp_node *rn;
  struct prefix *p;

  bgp = rsclient->bgp;

  for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn))
    if ((bgp_static = rn->info) != NULL)
      {
        p = &rn->p;

        bgp_static_update_rsclient (rsclient, p, bgp_static,
                afi, safi);
      }
}

static void
bgp_static_withdraw_vpnv4 (struct bgp *bgp, struct prefix *p, afi_t afi,
			   safi_t safi, struct prefix_rd *prd, u_char *tag)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

/* Configure static BGP network.  When user don't run zebra, static
   route should be installed as valid.  */
static int
bgp_static_set (struct vty *vty, struct bgp *bgp, const char *ip_str, 
                afi_t afi, safi_t safi, const char *rmap, int backdoor)
{
  int ret;
  struct prefix p;
  struct bgp_static *bgp_static;
  struct bgp_node *rn;
  u_char need_update = 0;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
#ifdef HAVE_IPV6
  if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
    {
      vty_out (vty, "%% Malformed prefix (link-local address)%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif /* HAVE_IPV6 */

  apply_mask (&p);

  /* Set BGP static route configuration. */
  rn = bgp_node_get (bgp->route[afi][safi], &p);

  if (rn->info)
    {
      /* Configuration change. */
      bgp_static = rn->info;

      /* Check previous routes are installed into BGP.  */
      if (bgp_static->valid && bgp_static->backdoor != backdoor)
        need_update = 1;
      
      bgp_static->backdoor = backdoor;
      
      if (rmap)
	{
	  if (bgp_static->rmap.name)
	    free (bgp_static->rmap.name);
	  bgp_static->rmap.name = strdup (rmap);
	  bgp_static->rmap.map = route_map_lookup_by_name (rmap);
	}
      else
	{
	  if (bgp_static->rmap.name)
	    free (bgp_static->rmap.name);
	  bgp_static->rmap.name = NULL;
	  bgp_static->rmap.map = NULL;
	  bgp_static->valid = 0;
	}
      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration. */
      bgp_static = bgp_static_new ();
      bgp_static->backdoor = backdoor;
      bgp_static->valid = 0;
      bgp_static->igpmetric = 0;
      bgp_static->igpnexthop.s_addr = 0;
      
      if (rmap)
	{
	  if (bgp_static->rmap.name)
	    free (bgp_static->rmap.name);
	  bgp_static->rmap.name = strdup (rmap);
	  bgp_static->rmap.map = route_map_lookup_by_name (rmap);
	}
      rn->info = bgp_static;
    }

  bgp_static->valid = 1;
  if (need_update)
    bgp_static_withdraw (bgp, &p, afi, safi);

  if (! bgp_static->backdoor)
    bgp_static_update (bgp, &p, bgp_static, afi, safi);

  return CMD_SUCCESS;
}

/* Configure static BGP network. */
static int
bgp_static_unset (struct vty *vty, struct bgp *bgp, const char *ip_str,
		  afi_t afi, safi_t safi)
{
  int ret;
  struct prefix p;
  struct bgp_static *bgp_static;
  struct bgp_node *rn;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
#ifdef HAVE_IPV6
  if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
    {
      vty_out (vty, "%% Malformed prefix (link-local address)%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif /* HAVE_IPV6 */

  apply_mask (&p);

  rn = bgp_node_lookup (bgp->route[afi][safi], &p);
  if (! rn)
    {
      vty_out (vty, "%% Can't find specified static route configuration.%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_static = rn->info;
  
  /* Update BGP RIB. */
  if (! bgp_static->backdoor)
    bgp_static_withdraw (bgp, &p, afi, safi);

  /* Clear configuration. */
  bgp_static_free (bgp_static);
  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

/* Called from bgp_delete().  Delete all static routes from the BGP
   instance. */
void
bgp_static_delete (struct bgp *bgp)
{
  afi_t afi;
  safi_t safi;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_table *table;
  struct bgp_static *bgp_static;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn))
	if (rn->info != NULL)
	  {      
	    if (safi == SAFI_MPLS_VPN)
	      {
		table = rn->info;

		for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
		  {
		    bgp_static = rn->info;
		    bgp_static_withdraw_vpnv4 (bgp, &rm->p,
					       AFI_IP, SAFI_MPLS_VPN,
					       (struct prefix_rd *)&rn->p,
					       bgp_static->tag);
		    bgp_static_free (bgp_static);
		    rn->info = NULL;
		    bgp_unlock_node (rn);
		  }
	      }
	    else
	      {
		bgp_static = rn->info;
		bgp_static_withdraw (bgp, &rn->p, afi, safi);
		bgp_static_free (bgp_static);
		rn->info = NULL;
		bgp_unlock_node (rn);
	      }
	  }
}

int
bgp_static_set_vpnv4 (struct vty *vty, const char *ip_str, const char *rd_str,
		      const char *tag_str)
{
  int ret;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp *bgp;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  u_char tag[3];

  bgp = vty->index;

  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  ret = str2prefix_rd (rd_str, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed rd%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2tag (tag_str, tag);
  if (! ret)
    {
      vty_out (vty, "%% Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  prn = bgp_node_get (bgp->route[AFI_IP][SAFI_MPLS_VPN],
			(struct prefix *)&prd);
  if (prn->info == NULL)
    prn->info = bgp_table_init (AFI_IP, SAFI_MPLS_VPN);
  else
    bgp_unlock_node (prn);
  table = prn->info;

  rn = bgp_node_get (table, &p);

  if (rn->info)
    {
      vty_out (vty, "%% Same network configuration exists%s", VTY_NEWLINE);
      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration. */
      bgp_static = bgp_static_new ();
      bgp_static->valid = 1;
      memcpy (bgp_static->tag, tag, 3);
      rn->info = bgp_static;

      bgp_static_update_vpnv4 (bgp, &p, AFI_IP, SAFI_MPLS_VPN, &prd, tag);
    }

  return CMD_SUCCESS;
}

/* Configure static BGP network. */
int
bgp_static_unset_vpnv4 (struct vty *vty, const char *ip_str, 
                        const char *rd_str, const char *tag_str)
{
  int ret;
  struct bgp *bgp;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  u_char tag[3];

  bgp = vty->index;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  ret = str2prefix_rd (rd_str, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed rd%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2tag (tag_str, tag);
  if (! ret)
    {
      vty_out (vty, "%% Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  prn = bgp_node_get (bgp->route[AFI_IP][SAFI_MPLS_VPN],
			(struct prefix *)&prd);
  if (prn->info == NULL)
    prn->info = bgp_table_init (AFI_IP, SAFI_MPLS_VPN);
  else
    bgp_unlock_node (prn);
  table = prn->info;

  rn = bgp_node_lookup (table, &p);

  if (rn)
    {
      bgp_static_withdraw_vpnv4 (bgp, &p, AFI_IP, SAFI_MPLS_VPN, &prd, tag);

      bgp_static = rn->info;
      bgp_static_free (bgp_static);
      rn->info = NULL;
      bgp_unlock_node (rn);
      bgp_unlock_node (rn);
    }
  else
    vty_out (vty, "%% Can't find the route%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

static int
bgp_table_map_set (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
                   const char *rmap_name)
{
  struct bgp_rmap *rmap;

  rmap = &bgp->table_map[afi][safi];
  if (rmap_name)
    {
      if (rmap->name)
        free (rmap->name);
      rmap->name = strdup (rmap_name);
      rmap->map = route_map_lookup_by_name (rmap_name);
    }
  else
    {
      if (rmap->name)
        free (rmap->name);
      rmap->name = NULL;
      rmap->map = NULL;
    }

  bgp_zebra_announce_table(bgp, afi, safi);

  return CMD_SUCCESS;
}

static int
bgp_table_map_unset (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
                     const char *rmap_name)
{
  struct bgp_rmap *rmap;

  rmap = &bgp->table_map[afi][safi];
  if (rmap->name)
    free (rmap->name);
  rmap->name = NULL;
  rmap->map = NULL;

  bgp_zebra_announce_table(bgp, afi, safi);

  return CMD_SUCCESS;
}

int
bgp_config_write_table_map (struct vty *vty, struct bgp *bgp, afi_t afi,
			   safi_t safi, int *write)
{
  if (bgp->table_map[afi][safi].name)
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, " table-map %s%s",
	       bgp->table_map[afi][safi].name, VTY_NEWLINE);
    }

  return 0;
}


DEFUN (bgp_table_map,
       bgp_table_map_cmd,
       "table-map WORD",
       "BGP table to RIB route download filter\n"
       "Name of the route map\n")
{
  return bgp_table_map_set (vty, vty->index,
             bgp_node_afi (vty), bgp_node_safi (vty), argv[0]);
}
DEFUN (no_bgp_table_map,
       no_bgp_table_map_cmd,
       "no table-map WORD",
       "BGP table to RIB route download filter\n"
       "Name of the route map\n")
{
  return bgp_table_map_unset (vty, vty->index,
             bgp_node_afi (vty), bgp_node_safi (vty), argv[0]);
}

DEFUN (bgp_network,
       bgp_network_cmd,
       "network A.B.C.D/M",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
			 AFI_IP, bgp_node_safi (vty), NULL, 0);
}

DEFUN (bgp_network_route_map,
       bgp_network_route_map_cmd,
       "network A.B.C.D/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
			 AFI_IP, bgp_node_safi (vty), argv[1], 0);
}

DEFUN (bgp_network_backdoor,
       bgp_network_backdoor_cmd,
       "network A.B.C.D/M backdoor",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (bgp_network_mask,
       bgp_network_mask_cmd,
       "network A.B.C.D mask A.B.C.D",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
			 AFI_IP, bgp_node_safi (vty), NULL, 0);
}

DEFUN (bgp_network_mask_route_map,
       bgp_network_mask_route_map_cmd,
       "network A.B.C.D mask A.B.C.D route-map WORD",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
			 AFI_IP, bgp_node_safi (vty), argv[2], 0);
}

DEFUN (bgp_network_mask_backdoor,
       bgp_network_mask_backdoor_cmd,
       "network A.B.C.D mask A.B.C.D backdoor",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n")
{
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str, AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (bgp_network_mask_natural,
       bgp_network_mask_natural_cmd,
       "network A.B.C.D",
       "Specify a network to announce via BGP\n"
       "Network number\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
			 AFI_IP, bgp_node_safi (vty), NULL, 0);
}

DEFUN (bgp_network_mask_natural_route_map,
       bgp_network_mask_natural_route_map_cmd,
       "network A.B.C.D route-map WORD",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
			 AFI_IP, bgp_node_safi (vty), argv[1], 0);
}

DEFUN (bgp_network_mask_natural_backdoor,
       bgp_network_mask_natural_backdoor_cmd,
       "network A.B.C.D backdoor",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str, AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network A.B.C.D/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP, 
			   bgp_node_safi (vty));
}

ALIAS (no_bgp_network,
       no_bgp_network_route_map_cmd,
       "no network A.B.C.D/M route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network,
       no_bgp_network_backdoor_cmd,
       "no network A.B.C.D/M backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")

DEFUN (no_bgp_network_mask,
       no_bgp_network_mask_cmd,
       "no network A.B.C.D mask A.B.C.D",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_unset (vty, vty->index, prefix_str, AFI_IP, 
			   bgp_node_safi (vty));
}

ALIAS (no_bgp_network_mask,
       no_bgp_network_mask_route_map_cmd,
       "no network A.B.C.D mask A.B.C.D route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network_mask,
       no_bgp_network_mask_backdoor_cmd,
       "no network A.B.C.D mask A.B.C.D backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n")

DEFUN (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_cmd,
       "no network A.B.C.D",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_unset (vty, vty->index, prefix_str, AFI_IP, 
			   bgp_node_safi (vty));
}

ALIAS (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_route_map_cmd,
       "no network A.B.C.D route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_backdoor_cmd,
       "no network A.B.C.D backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n")

#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_network,
       ipv6_bgp_network_cmd,
       "network X:X::X:X/M",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6, bgp_node_safi(vty),
                         NULL, 0);
}

DEFUN (ipv6_bgp_network_route_map,
       ipv6_bgp_network_route_map_cmd,
       "network X:X::X:X/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6,
			 bgp_node_safi (vty), argv[1], 0);
}

DEFUN (no_ipv6_bgp_network,
       no_ipv6_bgp_network_cmd,
       "no network X:X::X:X/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP6, bgp_node_safi(vty));
}

ALIAS (no_ipv6_bgp_network,
       no_ipv6_bgp_network_route_map_cmd,
       "no network X:X::X:X/M route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (ipv6_bgp_network,
       old_ipv6_bgp_network_cmd,
       "ipv6 bgp network X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

ALIAS (no_ipv6_bgp_network,
       old_no_ipv6_bgp_network_cmd,
       "no ipv6 bgp network X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
#endif /* HAVE_IPV6 */

/* stubs for removed AS-Pathlimit commands, kept for config compatibility */
ALIAS_DEPRECATED (bgp_network,
       bgp_network_ttl_cmd,
       "network A.B.C.D/M pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_backdoor,
       bgp_network_backdoor_ttl_cmd,
       "network A.B.C.D/M backdoor pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_mask,
       bgp_network_mask_ttl_cmd,
       "network A.B.C.D mask A.B.C.D pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_mask_backdoor,
       bgp_network_mask_backdoor_ttl_cmd,
       "network A.B.C.D mask A.B.C.D backdoor pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_mask_natural,
       bgp_network_mask_natural_ttl_cmd,
       "network A.B.C.D pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (bgp_network_mask_natural_backdoor,
       bgp_network_mask_natural_backdoor_ttl_cmd,
       "network A.B.C.D backdoor pathlimit <1-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_ttl_cmd,
       "no network A.B.C.D/M pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_backdoor_ttl_cmd,
       "no network A.B.C.D/M backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_mask_ttl_cmd,
       "no network A.B.C.D mask A.B.C.D pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network_mask,
       no_bgp_network_mask_backdoor_ttl_cmd,
       "no network A.B.C.D mask A.B.C.D  backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_ttl_cmd,
       "no network A.B.C.D pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_backdoor_ttl_cmd,
       "no network A.B.C.D backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
#ifdef HAVE_IPV6
ALIAS_DEPRECATED (ipv6_bgp_network,
       ipv6_bgp_network_ttl_cmd,
       "network X:X::X:X/M pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
ALIAS_DEPRECATED (no_ipv6_bgp_network,
       no_ipv6_bgp_network_ttl_cmd,
       "no network X:X::X:X/M pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
#endif /* HAVE_IPV6 */

/* Aggreagete address:

  advertise-map  Set condition to advertise attribute
  as-set         Generate AS set path information
  attribute-map  Set attributes of aggregate
  route-map      Set parameters of aggregate
  summary-only   Filter more specific routes from updates
  suppress-map   Conditionally filter more specific routes from updates
  <cr>
 */
struct bgp_aggregate
{
  /* Summary-only flag. */
  u_char summary_only;

  /* AS set generation. */
  u_char as_set;

  /* Route-map for aggregated route. */
  struct route_map *map;

  /* Suppress-count. */
  unsigned long count;

  /* SAFI configuration. */
  safi_t safi;
};

static struct bgp_aggregate *
bgp_aggregate_new (void)
{
  return XCALLOC (MTYPE_BGP_AGGREGATE, sizeof (struct bgp_aggregate));
}

static void
bgp_aggregate_free (struct bgp_aggregate *aggregate)
{
  XFREE (MTYPE_BGP_AGGREGATE, aggregate);
}     

/* Update an aggregate as routes are added/removed from the BGP table */
static void
bgp_aggregate_route (struct bgp *bgp, struct prefix *p, struct bgp_info *rinew,
		     afi_t afi, safi_t safi, struct bgp_info *del, 
		     struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  u_char origin;
  struct aspath *aspath = NULL;
  struct aspath *asmerge = NULL;
  struct community *community = NULL;
  struct community *commerge = NULL;
  struct in_addr nexthop;
  u_int32_t med = 0;
  struct bgp_info *ri;
  struct bgp_info *new;
  int first = 1;
  unsigned long match = 0;
  u_char atomic_aggregate = 0;

  /* Record adding route's nexthop and med. */
  if (rinew)
    {
      nexthop = rinew->attr->nexthop;
      med = rinew->attr->med;
    }

  /* ORIGIN attribute: If at least one route among routes that are
     aggregated has ORIGIN with the value INCOMPLETE, then the
     aggregated route must have the ORIGIN attribute with the value
     INCOMPLETE. Otherwise, if at least one route among routes that
     are aggregated has ORIGIN with the value EGP, then the aggregated
     route must have the origin attribute with the value EGP. In all
     other case the value of the ORIGIN attribute of the aggregated
     route is INTERNAL. */
  origin = BGP_ORIGIN_IGP;

  table = bgp->rib[afi][safi];

  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
	match = 0;

	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (BGP_INFO_HOLDDOWN (ri))
	      continue;

	    if (del && ri == del)
	      continue;

	    if (! rinew && first)
	      {
		nexthop = ri->attr->nexthop;
		med = ri->attr->med;
		first = 0;
	      }

#ifdef AGGREGATE_NEXTHOP_CHECK
	    if (! IPV4_ADDR_SAME (&ri->attr->nexthop, &nexthop)
		|| ri->attr->med != med)
	      {
		if (aspath)
		  aspath_free (aspath);
		if (community)
		  community_free (community);
		bgp_unlock_node (rn);
		bgp_unlock_node (top);
		return;
	      }
#endif /* AGGREGATE_NEXTHOP_CHECK */

            if (ri->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
              atomic_aggregate = 1;

	    if (ri->sub_type != BGP_ROUTE_AGGREGATE)
	      {
		if (aggregate->summary_only)
		  {
		    (bgp_info_extra_get (ri))->suppress++;
		    bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
		    match++;
		  }

		aggregate->count++;

		if (origin < ri->attr->origin)
		  origin = ri->attr->origin;

		if (aggregate->as_set)
		  {
		    if (aspath)
		      {
			asmerge = aspath_aggregate (aspath, ri->attr->aspath);
			aspath_free (aspath);
			aspath = asmerge;
		      }
		    else
		      aspath = aspath_dup (ri->attr->aspath);

		    if (ri->attr->community)
		      {
			if (community)
			  {
			    commerge = community_merge (community,
							ri->attr->community);
			    community = community_uniq_sort (commerge);
			    community_free (commerge);
			  }
			else
			  community = community_dup (ri->attr->community);
		      }
		  }
	      }
	  }
	if (match)
	  bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  if (rinew)
    {
      aggregate->count++;
      
      if (aggregate->summary_only)
        (bgp_info_extra_get (rinew))->suppress++;

      if (origin < rinew->attr->origin)
        origin = rinew->attr->origin;

      if (aggregate->as_set)
	{
	  if (aspath)
	    {
	      asmerge = aspath_aggregate (aspath, rinew->attr->aspath);
	      aspath_free (aspath);
	      aspath = asmerge;
	    }
	  else
	    aspath = aspath_dup (rinew->attr->aspath);

	  if (rinew->attr->community)
	    {
	      if (community)
		{
		  commerge = community_merge (community,
					      rinew->attr->community);
		  community = community_uniq_sort (commerge);
		  community_free (commerge);
		}
	      else
		community = community_dup (rinew->attr->community);
	    }
	}
    }

  if (aggregate->count > 0)
    {
      rn = bgp_node_get (table, p);
      new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_AGGREGATE, 0, bgp->peer_self,
		      bgp_attr_aggregate_intern(bgp, origin, aspath, community,
						aggregate->as_set,
                                                atomic_aggregate), rn);
      SET_FLAG (new->flags, BGP_INFO_VALID);

      bgp_info_add (rn, new);
      bgp_unlock_node (rn);
      bgp_process (bgp, rn, afi, safi);
    }
  else
    {
      if (aspath)
	aspath_free (aspath);
      if (community)
	community_free (community);
    }
}

void bgp_aggregate_delete (struct bgp *, struct prefix *, afi_t, safi_t,
			   struct bgp_aggregate *);

void
bgp_aggregate_increment (struct bgp *bgp, struct prefix *p,
			 struct bgp_info *ri, afi_t afi, safi_t safi)
{
  struct bgp_node *child;
  struct bgp_node *rn;
  struct bgp_aggregate *aggregate;
  struct bgp_table *table;

  /* MPLS-VPN aggregation is not yet supported. */
  if (safi == SAFI_MPLS_VPN)
    return;

  table = bgp->aggregate[afi][safi];

  /* No aggregates configured. */
  if (bgp_table_top_nolock (table) == NULL)
    return;

  if (p->prefixlen == 0)
    return;

  if (BGP_INFO_HOLDDOWN (ri))
    return;

  child = bgp_node_get (table, p);

  /* Aggregate address configuration check. */
  for (rn = child; rn; rn = bgp_node_parent_nolock (rn))
    if ((aggregate = rn->info) != NULL && rn->p.prefixlen < p->prefixlen)
      {
	bgp_aggregate_delete (bgp, &rn->p, afi, safi, aggregate);
	bgp_aggregate_route (bgp, &rn->p, ri, afi, safi, NULL, aggregate);
      }
  bgp_unlock_node (child);
}

void
bgp_aggregate_decrement (struct bgp *bgp, struct prefix *p, 
			 struct bgp_info *del, afi_t afi, safi_t safi)
{
  struct bgp_node *child;
  struct bgp_node *rn;
  struct bgp_aggregate *aggregate;
  struct bgp_table *table;

  /* MPLS-VPN aggregation is not yet supported. */
  if (safi == SAFI_MPLS_VPN)
    return;

  table = bgp->aggregate[afi][safi];

  /* No aggregates configured. */
  if (bgp_table_top_nolock (table) == NULL)
    return;

  if (p->prefixlen == 0)
    return;

  child = bgp_node_get (table, p);

  /* Aggregate address configuration check. */
  for (rn = child; rn; rn = bgp_node_parent_nolock (rn))
    if ((aggregate = rn->info) != NULL && rn->p.prefixlen < p->prefixlen)
      {
	bgp_aggregate_delete (bgp, &rn->p, afi, safi, aggregate);
	bgp_aggregate_route (bgp, &rn->p, NULL, afi, safi, del, aggregate);
      }
  bgp_unlock_node (child);
}

/* Called via bgp_aggregate_set when the user configures aggregate-address */
static void
bgp_aggregate_add (struct bgp *bgp, struct prefix *p, afi_t afi, safi_t safi,
		   struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  struct bgp_info *new;
  struct bgp_info *ri;
  unsigned long match;
  u_char origin = BGP_ORIGIN_IGP;
  struct aspath *aspath = NULL;
  struct aspath *asmerge = NULL;
  struct community *community = NULL;
  struct community *commerge = NULL;
  u_char atomic_aggregate = 0;

  table = bgp->rib[afi][safi];

  /* Sanity check. */
  if (afi == AFI_IP && p->prefixlen == IPV4_MAX_BITLEN)
    return;
  if (afi == AFI_IP6 && p->prefixlen == IPV6_MAX_BITLEN)
    return;
    
  /* If routes exists below this node, generate aggregate routes. */
  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
	match = 0;

	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (BGP_INFO_HOLDDOWN (ri))
	      continue;

            if (ri->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
              atomic_aggregate = 1;

	    if (ri->sub_type != BGP_ROUTE_AGGREGATE)
	      {
		/* summary-only aggregate route suppress aggregated
		   route announcement.  */
		if (aggregate->summary_only)
		  {
		    (bgp_info_extra_get (ri))->suppress++;
		    bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
		    match++;
		  }

                /* If at least one route among routes that are aggregated has
                 * ORIGIN with the value INCOMPLETE, then the aggregated route
                 * MUST have the ORIGIN attribute with the value INCOMPLETE.
                 * Otherwise, if at least one route among routes that are
                 * aggregated has ORIGIN with the value EGP, then the aggregated
                 * route MUST have the ORIGIN attribute with the value EGP.
                 */
                if (origin < ri->attr->origin)
                    origin = ri->attr->origin;

		/* as-set aggregate route generate origin, as path,
		   community aggregation.  */
		if (aggregate->as_set)
		  {
		    if (aspath)
		      {
			asmerge = aspath_aggregate (aspath, ri->attr->aspath);
			aspath_free (aspath);
			aspath = asmerge;
		      }
		    else
		      aspath = aspath_dup (ri->attr->aspath);

		    if (ri->attr->community)
		      {
			if (community)
			  {
			    commerge = community_merge (community,
							ri->attr->community);
			    community = community_uniq_sort (commerge);
			    community_free (commerge);
			  }
			else
			  community = community_dup (ri->attr->community);
		      }
		  }
		aggregate->count++;
	      }
	  }
	
	/* If this node is suppressed, process the change. */
	if (match)
	  bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  /* Add aggregate route to BGP table. */
  if (aggregate->count)
    {
      rn = bgp_node_get (table, p);
      new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_AGGREGATE, 0, bgp->peer_self,
		      bgp_attr_aggregate_intern(bgp, origin, aspath, community,
						aggregate->as_set,
                                                atomic_aggregate), rn);
      SET_FLAG (new->flags, BGP_INFO_VALID);

      bgp_info_add (rn, new);
      bgp_unlock_node (rn);
      
      /* Process change. */
      bgp_process (bgp, rn, afi, safi);
    }
}

void
bgp_aggregate_delete (struct bgp *bgp, struct prefix *p, afi_t afi, 
		      safi_t safi, struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  struct bgp_info *ri;
  unsigned long match;

  table = bgp->rib[afi][safi];

  if (afi == AFI_IP && p->prefixlen == IPV4_MAX_BITLEN)
    return;
  if (afi == AFI_IP6 && p->prefixlen == IPV6_MAX_BITLEN)
    return;

  /* If routes exists below this node, generate aggregate routes. */
  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
	match = 0;

	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (BGP_INFO_HOLDDOWN (ri))
	      continue;

	    if (ri->sub_type != BGP_ROUTE_AGGREGATE)
	      {
		if (aggregate->summary_only && ri->extra)
		  {
		    ri->extra->suppress--;

		    if (ri->extra->suppress == 0)
		      {
			bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
			match++;
		      }
		  }
		aggregate->count--;
	      }
	  }

	/* If this node was suppressed, process the change. */
	if (match)
	  bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  /* Delete aggregate route from BGP table. */
  rn = bgp_node_get (table, p);

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_AGGREGATE)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

/* Aggregate route attribute. */
#define AGGREGATE_SUMMARY_ONLY 1
#define AGGREGATE_AS_SET       1

static int
bgp_aggregate_unset (struct vty *vty, const char *prefix_str,
                     afi_t afi, safi_t safi)
{
  int ret;
  struct prefix p;
  struct bgp_node *rn;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  /* Get BGP structure. */
  bgp = vty->index;

  /* Old configuration check. */
  rn = bgp_node_lookup (bgp->aggregate[afi][safi], &p);
  if (! rn)
    {
      vty_out (vty, "%% There is no aggregate-address configuration.%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  aggregate = rn->info;
  if (aggregate->safi & SAFI_UNICAST)
    bgp_aggregate_delete (bgp, &p, afi, SAFI_UNICAST, aggregate);
  if (aggregate->safi & SAFI_MULTICAST)
    bgp_aggregate_delete (bgp, &p, afi, SAFI_MULTICAST, aggregate);

  /* Unlock aggregate address configuration. */
  rn->info = NULL;
  bgp_aggregate_free (aggregate);
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

static int
bgp_aggregate_set (struct vty *vty, const char *prefix_str,
                   afi_t afi, safi_t safi,
		   u_char summary_only, u_char as_set)
{
  int ret;
  struct prefix p;
  struct bgp_node *rn;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  /* Get BGP structure. */
  bgp = vty->index;

  /* Old configuration check. */
  rn = bgp_node_get (bgp->aggregate[afi][safi], &p);

  if (rn->info)
    {
      vty_out (vty, "There is already same aggregate network.%s", VTY_NEWLINE);
      /* try to remove the old entry */
      ret = bgp_aggregate_unset (vty, prefix_str, afi, safi);
      if (ret)
        {
          vty_out (vty, "Error deleting aggregate.%s", VTY_NEWLINE);
	  bgp_unlock_node (rn);
	  return CMD_WARNING;
        }
    }

  /* Make aggregate address structure. */
  aggregate = bgp_aggregate_new ();
  aggregate->summary_only = summary_only;
  aggregate->as_set = as_set;
  aggregate->safi = safi;
  rn->info = aggregate;

  /* Aggregate address insert into BGP routing table. */
  if (safi & SAFI_UNICAST)
    bgp_aggregate_add (bgp, &p, afi, SAFI_UNICAST, aggregate);
  if (safi & SAFI_MULTICAST)
    bgp_aggregate_add (bgp, &p, afi, SAFI_MULTICAST, aggregate);

  return CMD_SUCCESS;
}

DEFUN (aggregate_address,
       aggregate_address_cmd,
       "aggregate-address A.B.C.D/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty), 0, 0);
}

DEFUN (aggregate_address_mask,
       aggregate_address_mask_cmd,
       "aggregate-address A.B.C.D A.B.C.D",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
			    0, 0);
}

DEFUN (aggregate_address_summary_only,
       aggregate_address_summary_only_cmd,
       "aggregate-address A.B.C.D/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
			    AGGREGATE_SUMMARY_ONLY, 0);
}

DEFUN (aggregate_address_mask_summary_only,
       aggregate_address_mask_summary_only_cmd,
       "aggregate-address A.B.C.D A.B.C.D summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
			    AGGREGATE_SUMMARY_ONLY, 0);
}

DEFUN (aggregate_address_as_set,
       aggregate_address_as_set_cmd,
       "aggregate-address A.B.C.D/M as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
			    0, AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_mask_as_set,
       aggregate_address_mask_as_set_cmd,
       "aggregate-address A.B.C.D A.B.C.D as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
			    0, AGGREGATE_AS_SET);
}


DEFUN (aggregate_address_as_set_summary,
       aggregate_address_as_set_summary_cmd,
       "aggregate-address A.B.C.D/M as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
			    AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

ALIAS (aggregate_address_as_set_summary,
       aggregate_address_summary_as_set_cmd,
       "aggregate-address A.B.C.D/M summary-only as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (aggregate_address_mask_as_set_summary,
       aggregate_address_mask_as_set_summary_cmd,
       "aggregate-address A.B.C.D A.B.C.D as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
			    AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

ALIAS (aggregate_address_mask_as_set_summary,
       aggregate_address_mask_summary_as_set_cmd,
       "aggregate-address A.B.C.D A.B.C.D summary-only as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (no_aggregate_address,
       no_aggregate_address_cmd,
       "no aggregate-address A.B.C.D/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP, bgp_node_safi (vty));
}

ALIAS (no_aggregate_address,
       no_aggregate_address_summary_only_cmd,
       "no aggregate-address A.B.C.D/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_as_set_cmd,
       "no aggregate-address A.B.C.D/M as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_as_set_summary_cmd,
       "no aggregate-address A.B.C.D/M as-set summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_summary_as_set_cmd,
       "no aggregate-address A.B.C.D/M summary-only as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (no_aggregate_address_mask,
       no_aggregate_address_mask_cmd,
       "no aggregate-address A.B.C.D A.B.C.D",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_unset (vty, prefix_str, AFI_IP, bgp_node_safi (vty));
}

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_summary_only_cmd,
       "no aggregate-address A.B.C.D A.B.C.D summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_as_set_cmd,
       "no aggregate-address A.B.C.D A.B.C.D as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_as_set_summary_cmd,
       "no aggregate-address A.B.C.D A.B.C.D as-set summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_summary_as_set_cmd,
       "no aggregate-address A.B.C.D A.B.C.D summary-only as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

#ifdef HAVE_IPV6
DEFUN (ipv6_aggregate_address,
       ipv6_aggregate_address_cmd,
       "aggregate-address X:X::X:X/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP6, SAFI_UNICAST, 0, 0);
}

DEFUN (ipv6_aggregate_address_summary_only,
       ipv6_aggregate_address_summary_only_cmd,
       "aggregate-address X:X::X:X/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP6, SAFI_UNICAST, 
			    AGGREGATE_SUMMARY_ONLY, 0);
}

DEFUN (no_ipv6_aggregate_address,
       no_ipv6_aggregate_address_cmd,
       "no aggregate-address X:X::X:X/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP6, SAFI_UNICAST);
}

DEFUN (no_ipv6_aggregate_address_summary_only,
       no_ipv6_aggregate_address_summary_only_cmd,
       "no aggregate-address X:X::X:X/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP6, SAFI_UNICAST);
}

ALIAS (ipv6_aggregate_address,
       old_ipv6_aggregate_address_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

ALIAS (ipv6_aggregate_address_summary_only,
       old_ipv6_aggregate_address_summary_only_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

ALIAS (no_ipv6_aggregate_address,
       old_no_ipv6_aggregate_address_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

ALIAS (no_ipv6_aggregate_address_summary_only,
       old_no_ipv6_aggregate_address_summary_only_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
#endif /* HAVE_IPV6 */

/* Redistribute route treatment. */
void
bgp_redistribute_add (struct prefix *p, const struct in_addr *nexthop,
		      const struct in6_addr *nexthop6, unsigned int ifindex,
		      u_int32_t metric, u_char type, u_short instance, u_short tag)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  struct bgp_info *new;
  struct bgp_info *bi;
  struct bgp_info info;
  struct bgp_node *bn;
  struct attr attr;
  struct attr *new_attr;
  afi_t afi;
  int ret;
  struct bgp_redist *red;

  /* Make default attribute. */
  bgp_attr_default_set (&attr, BGP_ORIGIN_INCOMPLETE);
  if (nexthop)
    attr.nexthop = *nexthop;
  attr.nh_ifindex = ifindex;

#ifdef HAVE_IPV6
  if (nexthop6)
    {
      struct attr_extra *extra = bgp_attr_extra_get(&attr);
      extra->mp_nexthop_global = *nexthop6;
      extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
    }
#endif

  attr.med = metric;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
  attr.extra->tag = tag;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      afi = family2afi (p->family);

      red = bgp_redist_lookup(bgp, afi, type, instance);
      if (red)
	{
	  struct attr attr_new;
	  struct attr_extra extra_new;

	  /* Copy attribute for modification. */
	  attr_new.extra = &extra_new;
	  bgp_attr_dup (&attr_new, &attr);

	  if (red->redist_metric_flag)
	    attr_new.med = red->redist_metric;

	  /* Apply route-map. */
	  if (red->rmap.map)
	    {
	      info.peer = bgp->peer_self;
	      info.attr = &attr_new;

              SET_FLAG (bgp->peer_self->rmap_type, PEER_RMAP_TYPE_REDISTRIBUTE);

	      ret = route_map_apply (red->rmap.map, p, RMAP_BGP, &info);

              bgp->peer_self->rmap_type = 0;

	      if (ret == RMAP_DENYMATCH)
		{
		  /* Free uninterned attribute. */
		  bgp_attr_flush (&attr_new);

		  /* Unintern original. */
		  aspath_unintern (&attr.aspath);
		  bgp_attr_extra_free (&attr);
		  bgp_redistribute_delete (p, type, instance);
		  return;
		}
	    }

          bn = bgp_afi_node_get (bgp->rib[afi][SAFI_UNICAST], 
                                 afi, SAFI_UNICAST, p, NULL);
          
	  new_attr = bgp_attr_intern (&attr_new);

 	  for (bi = bn->info; bi; bi = bi->next)
 	    if (bi->peer == bgp->peer_self
 		&& bi->sub_type == BGP_ROUTE_REDISTRIBUTE)
 	      break;
 
 	  if (bi)
 	    {
 	      if (attrhash_cmp (bi->attr, new_attr) &&
		  !CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
 		{
 		  bgp_attr_unintern (&new_attr);
 		  aspath_unintern (&attr.aspath);
 		  bgp_attr_extra_free (&attr);
 		  bgp_unlock_node (bn);
 		  return;
 		}
 	      else
 		{
 		  /* The attribute is changed. */
 		  bgp_info_set_flag (bn, bi, BGP_INFO_ATTR_CHANGED);
 
 		  /* Rewrite BGP route information. */
		  if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
		    bgp_info_restore(bn, bi);
		  else
		    bgp_aggregate_decrement (bgp, p, bi, afi, SAFI_UNICAST);
 		  bgp_attr_unintern (&bi->attr);
 		  bi->attr = new_attr;
 		  bi->uptime = bgp_clock ();
 
 		  /* Process change. */
 		  bgp_aggregate_increment (bgp, p, bi, afi, SAFI_UNICAST);
 		  bgp_process (bgp, bn, afi, SAFI_UNICAST);
 		  bgp_unlock_node (bn);
 		  aspath_unintern (&attr.aspath);
 		  bgp_attr_extra_free (&attr);
 		  return;
		}
 	    }

	  new = info_make(type, BGP_ROUTE_REDISTRIBUTE, instance, bgp->peer_self,
			  new_attr, bn);
	  SET_FLAG (new->flags, BGP_INFO_VALID);

	  bgp_aggregate_increment (bgp, p, new, afi, SAFI_UNICAST);
	  bgp_info_add (bn, new);
	  bgp_unlock_node (bn);
	  bgp_process (bgp, bn, afi, SAFI_UNICAST);
	}
    }

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

void
bgp_redistribute_delete (struct prefix *p, u_char type, u_short instance)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  afi_t afi;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_redist *red;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      afi = family2afi (p->family);

      red = bgp_redist_lookup(bgp, afi, type, instance);
      if (red)
	{
         rn = bgp_afi_node_get (bgp->rib[afi][SAFI_UNICAST], afi, SAFI_UNICAST, p, NULL);

	  for (ri = rn->info; ri; ri = ri->next)
	    if (ri->peer == bgp->peer_self
		&& ri->type == type)
	      break;

	  if (ri)
	    {
	      bgp_aggregate_decrement (bgp, p, ri, afi, SAFI_UNICAST);
	      bgp_info_delete (rn, ri);
	      bgp_process (bgp, rn, afi, SAFI_UNICAST);
	    }
	  bgp_unlock_node (rn);
	}
    }
}

/* Withdraw specified route type's route. */
void
bgp_redistribute_withdraw (struct bgp *bgp, afi_t afi, int type, u_short instance)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_table *table;

  table = bgp->rib[afi][SAFI_UNICAST];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->next)
	if (ri->peer == bgp->peer_self
	    && ri->type == type
            && ri->instance == instance)
	  break;

      if (ri)
	{
	  bgp_aggregate_decrement (bgp, &rn->p, ri, afi, SAFI_UNICAST);
	  bgp_info_delete (rn, ri);
	  bgp_process (bgp, rn, afi, SAFI_UNICAST);
	}
    }
}

/* Static function to display route. */
static void
route_vty_out_route (struct prefix *p, struct vty *vty)
{
  int len;
  u_int32_t destination; 
  char buf[BUFSIZ];

  if (p->family == AF_INET)
    {
      len = vty_out (vty, "%s", inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ));
      destination = ntohl (p->u.prefix4.s_addr);

      if ((IN_CLASSC (destination) && p->prefixlen == 24)
	  || (IN_CLASSB (destination) && p->prefixlen == 16)
	  || (IN_CLASSA (destination) && p->prefixlen == 8)
	  || p->u.prefix4.s_addr == 0)
	{
	  /* When mask is natural, mask is not displayed. */
	}
      else
	len += vty_out (vty, "/%d", p->prefixlen);
    }
  else
    len = vty_out (vty, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		   p->prefixlen);

  len = 17 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 20, " ");
  else
    vty_out (vty, "%*s", len, " ");
}

enum bgp_display_type
{
  normal_list,
};

/* Print the short form route status for a bgp_info */
static void
route_vty_short_status_out (struct vty *vty, struct bgp_info *binfo,
                            json_object *json_path)
{
  json_object *json_boolean_false;
  json_object *json_boolean_true;

  if (json_path)
    {
      json_boolean_false = json_object_new_boolean(0);
      json_boolean_true = json_object_new_boolean(1);

      /* Route status display. */
      if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
        json_object_object_add(json_path, "removed", json_boolean_true);

      if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE))
        json_object_object_add(json_path, "stale", json_boolean_true);

      if (binfo->extra && binfo->extra->suppress)
        json_object_object_add(json_path, "suppressed", json_boolean_true);

      if (CHECK_FLAG (binfo->flags, BGP_INFO_VALID) &&
               ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        json_object_object_add(json_path, "valid", json_boolean_true);

      /* Selected */
      if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        json_object_object_add(json_path, "history", json_boolean_true);

      if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
        json_object_object_add(json_path, "damped", json_boolean_true);

      if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
        json_object_object_add(json_path, "bestpath", json_boolean_true);

      if (CHECK_FLAG (binfo->flags, BGP_INFO_MULTIPATH))
        json_object_object_add(json_path, "multipath", json_boolean_true);

      /* Internal route. */
      if ((binfo->peer->as) && (binfo->peer->as == binfo->peer->local_as))
        json_object_object_add(json_path, "internal", json_boolean_true);
      else
        json_object_object_add(json_path, "external", json_boolean_true);

      return;
    }

 /* Route status display. */
  if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
    vty_out (vty, "R");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE))
    vty_out (vty, "S");
  else if (binfo->extra && binfo->extra->suppress)
    vty_out (vty, "s");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_VALID) &&
           ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "*");
  else
    vty_out (vty, " ");

  /* Selected */
  if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "h");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
    vty_out (vty, "d");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
    vty_out (vty, ">");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_MULTIPATH))
    vty_out (vty, "=");
  else
    vty_out (vty, " ");

  /* Internal route. */
  if ((binfo->peer->as) && (binfo->peer->as == binfo->peer->local_as))
    vty_out (vty, "i");
  else
    vty_out (vty, " ");
}

/* called from terminal list command */
void
route_vty_out (struct vty *vty, struct prefix *p,
	       struct bgp_info *binfo, int display, safi_t safi,
               json_object *json_paths)
{
  struct attr *attr;
  json_object *json_path;
  json_object *json_int;
  json_object *json_string;

  if (json_paths)
    json_path = json_object_new_object();
  else
    json_path = NULL;

  /* short status lead text */
  route_vty_short_status_out (vty, binfo, json_path);

  if (!json_paths)
    {
      /* print prefix and mask */
      if (! display)
        route_vty_out_route (p, vty);
      else
        vty_out (vty, "%*s", 17, " ");
    }

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {

      /* IPv4 Next Hop */
      if (p->family == AF_INET)
	{
          if (json_paths)
            {
	      if (safi == SAFI_MPLS_VPN)
                {
                  json_string = json_object_new_string(inet_ntoa (attr->extra->mp_nexthop_global_in));
                  json_object_object_add(json_path, "nexthop", json_string);
                }
              else
                {
                  json_string = json_object_new_string(inet_ntoa (attr->nexthop));
                  json_object_object_add(json_path, "nexthop", json_string);
                }
            }
          else
            {
	      if (safi == SAFI_MPLS_VPN)
	        vty_out (vty, "%-16s",
                         inet_ntoa (attr->extra->mp_nexthop_global_in));
	      else
	        vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
            }
	}

#ifdef HAVE_IPV6
      /* IPv6 Next Hop */
      else if (p->family == AF_INET6)
	{
	  int len;
	  char buf[BUFSIZ];

          if (json_paths)
            {
              json_string = json_object_new_string(inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global, buf, BUFSIZ));
              json_object_object_add(json_path, "nexthop", json_string);
            }
          else
            {
	      len = vty_out (vty, "%s",
			     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
			     buf, BUFSIZ));
	      len = 16 - len;
	      if (len < 1)
	        vty_out (vty, "%s%*s", VTY_NEWLINE, 36, " ");
	      else
	        vty_out (vty, "%*s", len, " ");
            }
	}
#endif /* HAVE_IPV6 */

      /* MED/Metric */
      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
        if (json_paths)
          {
            json_int = json_object_new_int(attr->med);
            json_object_object_add(json_path, "med", json_int);
          }
        else
	  vty_out (vty, "%10u", attr->med);
      else
        if (!json_paths)
	  vty_out (vty, "          ");

      /* Local Pref */
      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
        if (json_paths)
          {
            json_int = json_object_new_int(attr->local_pref);
            json_object_object_add(json_path, "localpref", json_int);
          }
        else
	  vty_out (vty, "%7u", attr->local_pref);
      else
        if (!json_paths)
	  vty_out (vty, "       ");

      if (json_paths)
        {
          if (attr->extra)
            json_int = json_object_new_int(attr->extra->weight);
          else
            json_int = json_object_new_int(0);

          json_object_object_add(json_path, "weight", json_int);
        }
      else
        vty_out (vty, "%7u ", (attr->extra ? attr->extra->weight : 0));

      /* Print aspath */
      if (attr->aspath)
        {
          if (json_paths)
            {
	      if (!attr->aspath->str || aspath_count_hops (attr->aspath) == 0)
                json_string = json_object_new_string("Local");
              else
                json_string = json_object_new_string(attr->aspath->str);
              json_object_object_add(json_path, "aspath", json_string);
            }
          else
            {
              aspath_print_vty (vty, "%s", attr->aspath, " ");
            }
        }

      /* Print origin */
      if (json_paths)
        {
          json_string = json_object_new_string(bgp_origin_str[attr->origin]);
          json_object_object_add(json_path, "origin", json_string);
        }
      else
        vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }

  if (json_paths)
    json_object_array_add(json_paths, json_path);
  else
    vty_out (vty, "%s", VTY_NEWLINE);
}  

/* called from terminal list command */
void
route_vty_out_tmp (struct vty *vty, struct prefix *p,
		   struct attr *attr, safi_t safi)
{
  /* Route status display. */
  vty_out (vty, "*");
  vty_out (vty, ">");
  vty_out (vty, " ");

  /* print prefix and mask */
  route_vty_out_route (p, vty);

  /* Print attribute */
  if (attr) 
    {
      if (p->family == AF_INET)
	{
	  if (safi == SAFI_MPLS_VPN)
	    vty_out (vty, "%-16s",
                     inet_ntoa (attr->extra->mp_nexthop_global_in));
	  else
	    vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
	}
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6)
        {
          int len;
          char buf[BUFSIZ];
          
          assert (attr->extra);

          len = vty_out (vty, "%s",
                         inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                         buf, BUFSIZ));
          len = 16 - len;
          if (len < 1)
            vty_out (vty, "%s%*s", VTY_NEWLINE, 36, " ");
          else
            vty_out (vty, "%*s", len, " ");
        }
#endif /* HAVE_IPV6 */

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
	vty_out (vty, "%10u", attr->med);
      else
	vty_out (vty, "          ");

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
	vty_out (vty, "%7u", attr->local_pref);
      else
	vty_out (vty, "       ");
      
      vty_out (vty, "%7u ", (attr->extra ? attr->extra->weight : 0));
      
      /* Print aspath */
      if (attr->aspath)
        aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}  

void
route_vty_out_tag (struct vty *vty, struct prefix *p,
		   struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  u_int32_t label = 0;
  
  if (!binfo->extra)
    return;
  
  /* short status lead text */ 
  route_vty_short_status_out (vty, binfo, NULL);
    
  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {
      if (p->family == AF_INET)
	{
	  if (safi == SAFI_MPLS_VPN)
	    vty_out (vty, "%-16s",
                     inet_ntoa (attr->extra->mp_nexthop_global_in));
	  else
	    vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
	}
#ifdef HAVE_IPV6      
      else if (p->family == AF_INET6)
	{
	  assert (attr->extra);
	  char buf[BUFSIZ];
	  char buf1[BUFSIZ];
	  if (attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL)
	    vty_out (vty, "%s", 
		     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                     buf, BUFSIZ));
	  else if (attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
	    vty_out (vty, "%s(%s)",
		     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
		                buf, BUFSIZ),
		     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
		                buf1, BUFSIZ));
	  
	}
#endif /* HAVE_IPV6 */
    }

  label = decode_label (binfo->extra->tag);

  vty_out (vty, "notag/%d", label);

  vty_out (vty, "%s", VTY_NEWLINE);
}  

/* dampening route */
static void
damp_route_vty_out (struct vty *vty, struct prefix *p,
		    struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  int len;
  char timebuf[BGP_UPTIME_LEN];

  /* short status lead text */ 
  route_vty_short_status_out (vty, binfo, NULL);
  
  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", binfo->peer->host);
  len = 17 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 34, " ");
  else
    vty_out (vty, "%*s", len, " ");

  vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN));

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      /* Print aspath */
      if (attr->aspath)
	aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

/* flap route */
static void
flap_route_vty_out (struct vty *vty, struct prefix *p,
		    struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  struct bgp_damp_info *bdi;
  char timebuf[BGP_UPTIME_LEN];
  int len;
  
  if (!binfo->extra)
    return;
  
  bdi = binfo->extra->damp_info;

  /* short status lead text */
  route_vty_short_status_out (vty, binfo, NULL);
  
  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", binfo->peer->host);
  len = 16 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 33, " ");
  else
    vty_out (vty, "%*s", len, " ");

  len = vty_out (vty, "%d", bdi->flap);
  len = 5 - len;
  if (len < 1)
    vty_out (vty, " ");
  else
    vty_out (vty, "%*s ", len, " ");
    
  vty_out (vty, "%s ", peer_uptime (bdi->start_time,
	   timebuf, BGP_UPTIME_LEN));

  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED)
      && ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN));
  else
    vty_out (vty, "%*s ", 8, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      /* Print aspath */
      if (attr->aspath)
	aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

static void
route_vty_out_detail (struct vty *vty, struct bgp *bgp, struct prefix *p, 
		      struct bgp_info *binfo, afi_t afi, safi_t safi,
                      json_object *json_paths)
{
  char buf[INET6_ADDRSTRLEN];
  char buf1[BUFSIZ];
  struct attr *attr;
  int sockunion_vty_out (struct vty *, union sockunion *);
#ifdef HAVE_CLOCK_MONOTONIC
  time_t tbuf;
#endif
  json_object *json_int;
  json_object *json_string;
  json_object *json_path;
  json_object *json_boolean_false;
  json_object *json_boolean_true;
  json_object *json_cluster_list;

  if (json_paths)
    {
      json_path = json_object_new_object();
      json_boolean_false = json_object_new_boolean(0);
      json_boolean_true = json_object_new_boolean(1);
      json_cluster_list = json_object_new_array();
    }

  attr = binfo->attr;

  if (attr)
    {
      /* Line1 display AS-path, Aggregator */
      if (attr->aspath)
	{
          if (!json_paths)
	    vty_out (vty, "  ");

	  if (aspath_count_hops (attr->aspath) == 0)
            {
              if (json_paths)
                json_string = json_object_new_string("Local");
              else
	        vty_out (vty, "Local");
            }
	  else
            {
              if (json_paths)
                json_string = json_object_new_string(attr->aspath->str);
              else
	        aspath_print_vty (vty, "%s", attr->aspath, "");
            }

            if (json_paths)
              json_object_object_add(json_path, "aspath", json_string);
	}

      if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
        {
          if (json_paths)
            json_object_object_add(json_path, "removed", json_boolean_true);
          else
            vty_out (vty, ", (removed)");
        }

      if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE))
        {
          if (json_paths)
            json_object_object_add(json_path, "stale", json_boolean_true);
          else
	    vty_out (vty, ", (stale)");
        }

      if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)))
        {
          if (json_paths)
            {
              json_int = json_object_new_int(attr->extra->aggregator_as);
              json_string = json_object_new_string(inet_ntoa (attr->extra->aggregator_addr));
              json_object_object_add(json_path, "aggregator-as", json_int);
              json_object_object_add(json_path, "aggregator-id", json_string);
            }
          else
            {
	      vty_out (vty, ", (aggregated by %u %s)",
	               attr->extra->aggregator_as,
		       inet_ntoa (attr->extra->aggregator_addr));
            }
        }

      if (CHECK_FLAG (binfo->peer->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT))
        {
          if (json_paths)
            json_object_object_add(json_path, "rxed-from-rr-client", json_boolean_true);
          else
	    vty_out (vty, ", (Received from a RR-client)");
        }

      if (CHECK_FLAG (binfo->peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        {
          if (json_paths)
            json_object_object_add(json_path, "rxed-from-rs-client", json_boolean_true);
          else
	    vty_out (vty, ", (Received from a RS-client)");
        }

      if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        {
          if (json_paths)
            json_object_object_add(json_path, "dampening-history-entry", json_boolean_true);
          else
	    vty_out (vty, ", (history entry)");
        }
      else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
        {
          if (json_paths)
            json_object_object_add(json_path, "dampening-suppressed", json_boolean_true);
          else
	    vty_out (vty, ", (suppressed due to dampening)");
        }

      if (!json_paths)
        vty_out (vty, "%s", VTY_NEWLINE);
	  
      /* Line2 display Next-hop, Neighbor, Router-id */
      if (p->family == AF_INET)
	{
          if (safi == SAFI_MPLS_VPN)
            {
              if (json_paths)
                json_string = json_object_new_string(inet_ntoa (attr->extra->mp_nexthop_global_in));
              else
	        vty_out (vty, "    %s", inet_ntoa (attr->extra->mp_nexthop_global_in));
            }
          else
            {
              if (json_paths)
                json_string = json_object_new_string(inet_ntoa (attr->nexthop));
              else
	        vty_out (vty, "    %s", inet_ntoa (attr->nexthop));
            }

          if (json_paths)
            json_object_object_add(json_path, "nexthop", json_string);
	}
#ifdef HAVE_IPV6
      else
	{
	  assert (attr->extra);
          if (json_paths)
            {
              json_string = json_object_new_string(inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                                                          buf, INET6_ADDRSTRLEN));
              json_object_object_add(json_path, "nexthop", json_string);
            }
          else
            {
	      vty_out (vty, "    %s",
		       inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
			          buf, INET6_ADDRSTRLEN));
            }
	}
#endif /* HAVE_IPV6 */

      if (binfo->peer == bgp->peer_self)
	{

          if (p->family == AF_INET)
            {
              if (json_paths)
                json_string = json_object_new_string("0.0.0.0");
              else
	        vty_out (vty, " from 0.0.0.0 ");
            }
          else
            {
              if (json_paths)
                json_string = json_object_new_string("::");
              else
	        vty_out (vty, " from :: ");
            }

          if (json_paths)
            {
              json_object_object_add(json_path, "peer-ip", json_string);
              json_string = json_object_new_string(inet_ntoa(bgp->router_id));
              json_object_object_add(json_path, "peer-id", json_string);
            }
          else
            {
	      vty_out (vty, "(%s)", inet_ntoa(bgp->router_id));
            }
	}
      else
	{
	  if (! CHECK_FLAG (binfo->flags, BGP_INFO_VALID))
            {
              if (json_paths)
                json_object_object_add(json_path, "nexthop-accessible", json_boolean_false);
              else
	        vty_out (vty, " (inaccessible)");
            }
	  else if (binfo->extra && binfo->extra->igpmetric)
            {
              if (json_paths)
                {
                  json_int = json_object_new_int(binfo->extra->igpmetric);
                  json_object_object_add(json_path, "nexthop-igp-cost", json_int);
                  json_object_object_add(json_path, "nexthop-accessible", json_boolean_true);
                }
              else
                {
	          vty_out (vty, " (metric %u)", binfo->extra->igpmetric);
                }
            }

          /* IGP cost to nexthop is 0 */
          else
            if (json_paths)
              json_object_object_add(json_path, "nexthop-accessible", json_boolean_true);

          if (json_paths)
            {
              json_string = json_object_new_string(sockunion2str (&binfo->peer->su, buf, SU_ADDRSTRLEN));
              json_object_object_add(json_path, "peer-ip", json_string);
            }
          else
            {
	      vty_out (vty, " from %s", sockunion2str (&binfo->peer->su, buf, SU_ADDRSTRLEN));

	      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
	        vty_out (vty, " (%s)", inet_ntoa (attr->extra->originator_id));
	      else
	        vty_out (vty, " (%s)", inet_ntop (AF_INET, &binfo->peer->remote_id, buf1, BUFSIZ));
            }

          /* Always encode the peer's router-id in the json output.  We will
           * include the originator-id later if this is a reflected route.
           */
          if (json_paths)
            {
              json_string = json_object_new_string(inet_ntop (AF_INET, &binfo->peer->remote_id, buf1, BUFSIZ));
              json_object_object_add(json_path, "peer-id", json_string);
            }
	}

      if (!json_paths)
        vty_out (vty, "%s", VTY_NEWLINE);

#ifdef HAVE_IPV6
      /* display nexthop local */
      if (attr->extra && attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
	{
          if (json_paths)
            {
              json_string = json_object_new_string(inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
                                                              buf, INET6_ADDRSTRLEN));
              json_object_object_add(json_path, "nexthop-local", json_string);
            }
          else
            {
	      vty_out (vty, "    (%s)%s",
		       inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
			          buf, INET6_ADDRSTRLEN),
		       VTY_NEWLINE);
            }
	}
#endif /* HAVE_IPV6 */

      /* Line 3 display Origin, Med, Locpref, Weight, Tag, valid, Int/Ext/Local, Atomic, best */
      if (json_paths)
        {
          json_string = json_object_new_string(bgp_origin_long_str[attr->origin]);
          json_object_object_add(json_path, "origin", json_string);
        }
      else
        {
          vty_out (vty, "      Origin %s", bgp_origin_long_str[attr->origin]);
        }
	  
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
        {
          if (json_paths)
            {
              json_int = json_object_new_int(attr->med);
              json_object_object_add(json_path, "med", json_int);
            }
          else
            {
	      vty_out (vty, ", metric %u", attr->med);
            }
        }
	  
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
        {
          if (json_paths)
            {
              json_int = json_object_new_int(attr->local_pref);
              json_object_object_add(json_path, "localpref", json_int);
            }
          else
            {
	      vty_out (vty, ", localpref %u", attr->local_pref);
            }
        }
      else
        {
          if (json_paths)
            {
              json_int = json_object_new_int(bgp->default_local_pref);
              json_object_object_add(json_path, "localpref", json_int);
            }
          else
            {
	      vty_out (vty, ", localpref %u", bgp->default_local_pref);
            }
        }

      if (attr->extra && attr->extra->weight != 0)
        {
          if (json_paths)
            {
              json_int = json_object_new_int(attr->extra->weight);
              json_object_object_add(json_path, "weight", json_int);
            }
          else
            {
	      vty_out (vty, ", weight %u", attr->extra->weight);
            }
        }

      if (attr->extra && attr->extra->tag != 0)
        {
          if (json_paths)
            {
              json_int = json_object_new_int(attr->extra->tag);
              json_object_object_add(json_path, "tag", json_int);
            }
          else
            {
              vty_out (vty, ", tag %d", attr->extra->tag);
            }
        }
	
      if (! CHECK_FLAG (binfo->flags, BGP_INFO_VALID))
        {
          if (json_paths)
            json_object_object_add(json_path, "valid", json_boolean_false);
          else
	    vty_out (vty, ", invalid");
        }
      else if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        {
          if (json_paths)
            json_object_object_add(json_path, "valid", json_boolean_true);
          else
	    vty_out (vty, ", valid");
        }

      if (binfo->peer != bgp->peer_self)
	{
	  if (binfo->peer->as == binfo->peer->local_as)
            {
              if (json_paths)
                json_object_object_add(json_path, "internal", json_boolean_true);
              else
	        vty_out (vty, ", internal");
            }
	  else 
            {
              if (bgp_confederation_peers_check(bgp, binfo->peer->as))
                {
                  if (json_paths)
                    json_object_object_add(json_path, "confed-external", json_boolean_true);
                  else
	            vty_out (vty, ", confed-external");
                }
              else
                {
                  if (json_paths)
                    json_object_object_add(json_path, "external", json_boolean_true);
                  else
	            vty_out (vty, ", external");
                }
            }
	}
      else if (binfo->sub_type == BGP_ROUTE_AGGREGATE)
        {
          if (json_paths)
            {
              json_object_object_add(json_path, "aggregated", json_boolean_true);
              json_object_object_add(json_path, "local", json_boolean_true);
            }
          else
            {
	      vty_out (vty, ", aggregated, local");
            }
        }
      else if (binfo->type != ZEBRA_ROUTE_BGP)
        {
          if (json_paths)
            json_object_object_add(json_path, "sourced", json_boolean_true);
          else
	    vty_out (vty, ", sourced");
        }
      else
        {
          if (json_paths)
            {
              json_object_object_add(json_path, "sourced", json_boolean_true);
              json_object_object_add(json_path, "local", json_boolean_true);
            }
          else
            {
	      vty_out (vty, ", sourced, local");
            }
        }

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
        {
          if (json_paths)
            json_object_object_add(json_path, "atomic-aggregate", json_boolean_true);
          else
	    vty_out (vty, ", atomic-aggregate");
        }
	  
      if (CHECK_FLAG (binfo->flags, BGP_INFO_MULTIPATH) ||
	  (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED) &&
	   bgp_info_mpath_count (binfo)))
        {
          if (json_paths)
            json_object_object_add(json_path, "multipath", json_boolean_true);
          else
	    vty_out (vty, ", multipath");
        }

      if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
        {
          if (json_paths)
            json_object_object_add(json_path, "bestpath", json_boolean_true);
          else
	    vty_out (vty, ", best");
        }

      if (!json_paths)
        vty_out (vty, "%s", VTY_NEWLINE);
	  
      /* Line 4 display Community */
      if (attr->community)
        {
          if (json_paths)
            {
              json_string = json_object_new_string(attr->community->str);
              json_object_object_add(json_path, "community", json_string);
            }
          else
            {
	      vty_out (vty, "      Community: %s%s", attr->community->str,
		       VTY_NEWLINE);
            }
        }
	  
      /* Line 5 display Extended-community */
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))
        {
          if (json_paths)
            {
              json_string = json_object_new_string(attr->extra->ecommunity->str);
              json_object_object_add(json_path, "extended-community", json_string);
            }
          else
            {
	       vty_out (vty, "      Extended Community: %s%s",
	                attr->extra->ecommunity->str, VTY_NEWLINE);
            }
        }

      /* Line 6 display Originator, Cluster-id */
      if ((attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)) ||
	  (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST)))
	{
	  assert (attr->extra);
	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
            {
              if (json_paths)
                {
                  json_string = json_object_new_string(inet_ntoa (attr->extra->originator_id));
                  json_object_object_add(json_path, "originator-id", json_string);
                }
              else
                {
	          vty_out (vty, "      Originator: %s",
	                   inet_ntoa (attr->extra->originator_id));
                }
            }

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
	    {
	      int i;

              if (json_paths)
                {
	          for (i = 0; i < attr->extra->cluster->length / 4; i++)
                    {
                      json_string = json_object_new_string(inet_ntoa (attr->extra->cluster->list[i]));
                      json_object_array_add(json_cluster_list, json_string);
                    }
                  json_object_object_add(json_path, "cluster-list", json_cluster_list);
                }
              else
                {
	          vty_out (vty, ", Cluster list: ");

	          for (i = 0; i < attr->extra->cluster->length / 4; i++)
                    {
		       vty_out (vty, "%s ",
		                inet_ntoa (attr->extra->cluster->list[i]));
                    }
                }
	    }

          if (!json_paths)
	    vty_out (vty, "%s", VTY_NEWLINE);
	}

      if (binfo->extra && binfo->extra->damp_info)
	bgp_damp_info_vty (vty, binfo, json_path);

      /* Line 7 display Addpath IDs */
      if (binfo->addpath_rx_id || binfo->addpath_tx_id)
        {
          if (json_paths)
            {
              json_int = json_object_new_int(binfo->addpath_rx_id);
              json_object_object_add(json_path, "addpath-rx-id", json_int);

              json_int = json_object_new_int(binfo->addpath_tx_id);
              json_object_object_add(json_path, "addpath-tx-id", json_int);
            }
          else
            {
              vty_out (vty, "      AddPath ID: RX %u, TX %u%s",
                       binfo->addpath_rx_id, binfo->addpath_tx_id,
                       VTY_NEWLINE);
            }
        }

      /* Line 8 display Uptime */
#ifdef HAVE_CLOCK_MONOTONIC
      tbuf = time(NULL) - (bgp_clock() - binfo->uptime);
      if (json_paths)
        json_string = json_object_new_string(ctime(&tbuf));
      else
        vty_out (vty, "      Last update: %s", ctime(&tbuf));
#else
      if (json_paths)
        json_string = json_object_new_string(ctime(&binfo->uptime));
      else
        vty_out (vty, "      Last update: %s", ctime(&binfo->uptime));
#endif /* HAVE_CLOCK_MONOTONIC */
      if (json_paths)
        json_object_object_add(json_path, "last-update", json_string);
    }

  /* We've constructed the json object for this path, add it to the json
   * array of paths
   */
  if (json_paths)
    json_object_array_add(json_paths, json_path);
  else
    vty_out (vty, "%s", VTY_NEWLINE);
}

#define BGP_SHOW_HEADER_CSV "Flags, Network, Next Hop, Metric, LocPrf, Weight, Path%s"
#define BGP_SHOW_DAMP_HEADER "   Network          From             Reuse    Path%s"
#define BGP_SHOW_FLAP_HEADER "   Network          From            Flaps Duration Reuse    Path%s"

enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_route_map,
  bgp_show_type_neighbor,
  bgp_show_type_cidr_only,
  bgp_show_type_prefix_longer,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact,
  bgp_show_type_flap_statistics,
  bgp_show_type_flap_address,
  bgp_show_type_flap_prefix,
  bgp_show_type_flap_cidr_only,
  bgp_show_type_flap_regexp,
  bgp_show_type_flap_filter_list,
  bgp_show_type_flap_prefix_list,
  bgp_show_type_flap_prefix_longer,
  bgp_show_type_flap_route_map,
  bgp_show_type_flap_neighbor,
  bgp_show_type_dampend_paths,
  bgp_show_type_damp_neighbor
};

static int
bgp_show_table (struct vty *vty, struct bgp_table *table, struct in_addr *router_id,
		enum bgp_show_type type, void *output_arg, u_char use_json)
{
  struct bgp_info *ri;
  struct bgp_node *rn;
  int header = 1;
  int display;
  unsigned long output_count;
  struct prefix *p;
  char buf[BUFSIZ];
  char buf2[BUFSIZ];
  json_object *json;
  json_object *json_int;
  json_object *json_paths;
  json_object *json_routes;
  json_object *json_string;

  if (use_json)
    {
      json = json_object_new_object();
      json_int = json_object_new_int(table->version);
      json_object_object_add(json, "table-version", json_int);

      json_string = json_object_new_string(inet_ntoa (*router_id));
      json_object_object_add(json, "router-id", json_string);

      json_routes = json_object_new_object();
    }

  /* This is first entry point, so reset total line. */
  output_count = 0;

  /* Start processing of routes. */
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn)) 
    if (rn->info != NULL)
      {
	display = 0;

        if (use_json)
          json_paths = json_object_new_array();
        else
          json_paths = NULL;

	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (type == bgp_show_type_flap_statistics
		|| type == bgp_show_type_flap_address
		|| type == bgp_show_type_flap_prefix
		|| type == bgp_show_type_flap_cidr_only
		|| type == bgp_show_type_flap_regexp
		|| type == bgp_show_type_flap_filter_list
		|| type == bgp_show_type_flap_prefix_list
		|| type == bgp_show_type_flap_prefix_longer
		|| type == bgp_show_type_flap_route_map
		|| type == bgp_show_type_flap_neighbor
		|| type == bgp_show_type_dampend_paths
		|| type == bgp_show_type_damp_neighbor)
	      {
		if (!(ri->extra && ri->extra->damp_info))
		  continue;
	      }
	    if (type == bgp_show_type_regexp
		|| type == bgp_show_type_flap_regexp)
	      {
		regex_t *regex = output_arg;
		    
		if (bgp_regexec (regex, ri->attr->aspath) == REG_NOMATCH)
		  continue;
	      }
	    if (type == bgp_show_type_prefix_list
		|| type == bgp_show_type_flap_prefix_list)
	      {
		struct prefix_list *plist = output_arg;
		    
		if (prefix_list_apply (plist, &rn->p) != PREFIX_PERMIT)
		  continue;
	      }
	    if (type == bgp_show_type_filter_list
		|| type == bgp_show_type_flap_filter_list)
	      {
		struct as_list *as_list = output_arg;

		if (as_list_apply (as_list, ri->attr->aspath) != AS_FILTER_PERMIT)
		  continue;
	      }
	    if (type == bgp_show_type_route_map
		|| type == bgp_show_type_flap_route_map)
	      {
		struct route_map *rmap = output_arg;
		struct bgp_info binfo;
		struct attr dummy_attr;
		struct attr_extra dummy_extra;
		int ret;

		dummy_attr.extra = &dummy_extra;
		bgp_attr_dup (&dummy_attr, ri->attr);

		binfo.peer = ri->peer;
		binfo.attr = &dummy_attr;

		ret = route_map_apply (rmap, &rn->p, RMAP_BGP, &binfo);
		if (ret == RMAP_DENYMATCH)
		  continue;
	      }
	    if (type == bgp_show_type_neighbor
		|| type == bgp_show_type_flap_neighbor
		|| type == bgp_show_type_damp_neighbor)
	      {
		union sockunion *su = output_arg;

		if (ri->peer->su_remote == NULL || ! sockunion_same(ri->peer->su_remote, su))
		  continue;
	      }
	    if (type == bgp_show_type_cidr_only
		|| type == bgp_show_type_flap_cidr_only)
	      {
		u_int32_t destination;

		destination = ntohl (rn->p.u.prefix4.s_addr);
		if (IN_CLASSC (destination) && rn->p.prefixlen == 24)
		  continue;
		if (IN_CLASSB (destination) && rn->p.prefixlen == 16)
		  continue;
		if (IN_CLASSA (destination) && rn->p.prefixlen == 8)
		  continue;
	      }
	    if (type == bgp_show_type_prefix_longer
		|| type == bgp_show_type_flap_prefix_longer)
	      {
		struct prefix *p = output_arg;

		if (! prefix_match (p, &rn->p))
		  continue;
	      }
	    if (type == bgp_show_type_community_all)
	      {
		if (! ri->attr->community)
		  continue;
	      }
	    if (type == bgp_show_type_community)
	      {
		struct community *com = output_arg;

		if (! ri->attr->community ||
		    ! community_match (ri->attr->community, com))
		  continue;
	      }
	    if (type == bgp_show_type_community_exact)
	      {
		struct community *com = output_arg;

		if (! ri->attr->community ||
		    ! community_cmp (ri->attr->community, com))
		  continue;
	      }
	    if (type == bgp_show_type_community_list)
	      {
		struct community_list *list = output_arg;

		if (! community_list_match (ri->attr->community, list))
		  continue;
	      }
	    if (type == bgp_show_type_community_list_exact)
	      {
		struct community_list *list = output_arg;

		if (! community_list_exact_match (ri->attr->community, list))
		  continue;
	      }
	    if (type == bgp_show_type_flap_address
		|| type == bgp_show_type_flap_prefix)
	      {
		struct prefix *p = output_arg;

		if (! prefix_match (&rn->p, p))
		  continue;

		if (type == bgp_show_type_flap_prefix)
		  if (p->prefixlen != rn->p.prefixlen)
		    continue;
	      }
	    if (type == bgp_show_type_dampend_paths
		|| type == bgp_show_type_damp_neighbor)
	      {
		if (! CHECK_FLAG (ri->flags, BGP_INFO_DAMPED)
		    || CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
		  continue;
	      }

	    if (!use_json && header)
	      {
		vty_out (vty, "BGP table version is %llu, local router ID is %s%s", table->version, inet_ntoa (*router_id), VTY_NEWLINE);
		vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
		vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
		if (type == bgp_show_type_dampend_paths
		    || type == bgp_show_type_damp_neighbor)
		  vty_out (vty, BGP_SHOW_DAMP_HEADER, VTY_NEWLINE);
		else if (type == bgp_show_type_flap_statistics
			 || type == bgp_show_type_flap_address
			 || type == bgp_show_type_flap_prefix
			 || type == bgp_show_type_flap_cidr_only
			 || type == bgp_show_type_flap_regexp
			 || type == bgp_show_type_flap_filter_list
			 || type == bgp_show_type_flap_prefix_list
			 || type == bgp_show_type_flap_prefix_longer
			 || type == bgp_show_type_flap_route_map
			 || type == bgp_show_type_flap_neighbor)
		  vty_out (vty, BGP_SHOW_FLAP_HEADER, VTY_NEWLINE);
		else
		  vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
		header = 0;
	      }

	    if (type == bgp_show_type_dampend_paths
		|| type == bgp_show_type_damp_neighbor)
	      damp_route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST);
	    else if (type == bgp_show_type_flap_statistics
		     || type == bgp_show_type_flap_address
		     || type == bgp_show_type_flap_prefix
		     || type == bgp_show_type_flap_cidr_only
		     || type == bgp_show_type_flap_regexp
		     || type == bgp_show_type_flap_filter_list
		     || type == bgp_show_type_flap_prefix_list
		     || type == bgp_show_type_flap_prefix_longer
		     || type == bgp_show_type_flap_route_map
		     || type == bgp_show_type_flap_neighbor)
	      flap_route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST);
	    else
	      route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST, json_paths);
	    display++;
	  }

        if (use_json)
          {
            p = &rn->p;
            sprintf(buf2, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ), p->prefixlen);
            json_object_object_add(json_routes, buf2, json_paths);
          }

	if (display)
	  output_count++;
      }

  if (use_json)
    {
      json_object_object_add(json, "routes", json_routes);
      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);

      // Recursively free all json structures
      json_object_put(json);
    }
  else
    {
      /* No route is displayed */
      if (output_count == 0)
        {
          if (type == bgp_show_type_normal)
	    vty_out (vty, "No BGP network exists%s", VTY_NEWLINE);
        }
      else
        vty_out (vty, "%sTotal number of prefixes %ld%s",
	         VTY_NEWLINE, output_count, VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

static int
bgp_show (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
	  enum bgp_show_type type, void *output_arg, u_char use_json)
{
  struct bgp_table *table;

  if (bgp == NULL) {
    bgp = bgp_get_default ();
  }

  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }


  table = bgp->rib[afi][safi];

  return bgp_show_table (vty, table, &bgp->router_id, type, output_arg, use_json);
}

/* Header of detailed BGP route information */
static void
route_vty_out_detail_header (struct vty *vty, struct bgp *bgp,
			     struct bgp_node *rn,
                             struct prefix_rd *prd, afi_t afi, safi_t safi,
                             json_object *json)
{
  struct bgp_info *ri;
  struct prefix *p;
  struct peer *peer;
  struct listnode *node, *nnode;
  char buf1[INET6_ADDRSTRLEN];
  char buf2[INET6_ADDRSTRLEN];
  int count = 0;
  int best = 0;
  int suppress = 0;
  int no_export = 0;
  int no_advertise = 0;
  int local_as = 0;
  int first = 0;
  json_object *json_string;
  json_object *json_int;
  json_object *json_adv_to;

  p = &rn->p;

  if (json)
    {
      json_string = json_object_new_string(inet_ntop (p->family, &p->u.prefix, buf2, INET6_ADDRSTRLEN));
      json_object_object_add(json, "prefix", json_string);

      json_int = json_object_new_int(p->prefixlen);
      json_object_object_add(json, "prefixlen", json_int);
      json_adv_to = json_object_new_array();
    }
  else
    {
      vty_out (vty, "BGP routing table entry for %s%s%s/%d%s",
	       (safi == SAFI_MPLS_VPN ?
	       prefix_rd2str (prd, buf1, RD_ADDRSTRLEN) : ""),
	       safi == SAFI_MPLS_VPN ? ":" : "",
	       inet_ntop (p->family, &p->u.prefix, buf2, INET6_ADDRSTRLEN),
	       p->prefixlen, VTY_NEWLINE);
    }

  for (ri = rn->info; ri; ri = ri->next)
    {
      count++;
      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
	{
	  best = count;
	  if (ri->extra && ri->extra->suppress)
	    suppress = 1;
	  if (ri->attr->community != NULL)
	    {
	      if (community_include (ri->attr->community, COMMUNITY_NO_ADVERTISE))
		no_advertise = 1;
	      if (community_include (ri->attr->community, COMMUNITY_NO_EXPORT))
		no_export = 1;
	      if (community_include (ri->attr->community, COMMUNITY_LOCAL_AS))
		local_as = 1;
	    }
	}
    }

  if (!json)
    {
      vty_out (vty, "Paths: (%d available", count);
      if (best)
        {
          vty_out (vty, ", best #%d", best);
          if (safi == SAFI_UNICAST)
	    vty_out (vty, ", table Default-IP-Routing-Table");
        }
      else
        vty_out (vty, ", no best path");

      if (no_advertise)
        vty_out (vty, ", not advertised to any peer");
      else if (no_export)
        vty_out (vty, ", not advertised to EBGP peer");
      else if (local_as)
        vty_out (vty, ", not advertised outside local AS");

      if (suppress)
        vty_out (vty, ", Advertisements suppressed by an aggregate.");
      vty_out (vty, ")%s", VTY_NEWLINE);
    }

  /* advertised peer */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (bgp_adj_out_lookup (peer, p, afi, safi, rn))
	{
          if (json)
            {
              json_string = json_object_new_string(sockunion2str (&peer->su, buf1, SU_ADDRSTRLEN));
              json_object_array_add(json_adv_to, json_string);
            }
          else
            {
	      if (! first)
	        vty_out (vty, "  Advertised to non peer-group peers:%s ", VTY_NEWLINE);
	      vty_out (vty, " %s", sockunion2str (&peer->su, buf1, SU_ADDRSTRLEN));
            }
	    first = 1;
	}
    }

  if (json)
    {
      if (first)
        {
          json_object_object_add(json, "advertised-to", json_adv_to);
        }
    }
  else
    {
      if (!first)
        vty_out (vty, "  Not advertised to any peer");
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

/* Display specified route of BGP table. */
static int
bgp_show_route_in_table (struct vty *vty, struct bgp *bgp, 
                         struct bgp_table *rib, const char *ip_str,
                         afi_t afi, safi_t safi, struct prefix_rd *prd,
                         int prefix_check, enum bgp_path_type pathtype,
                         u_char use_json)
{
  int ret;
  int header;
  int display = 0;
  struct prefix match;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_table *table;
  json_object *json;
  json_object *json_paths;

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = afi2family (afi);

  if (use_json)
    {
      json = json_object_new_object();
      json_paths = json_object_new_array();
    }
  else
    {
      json = NULL;
      json_paths = NULL;
    }

  if (safi == SAFI_MPLS_VPN)
    {
      for (rn = bgp_table_top (rib); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

          if ((table = rn->info) != NULL)
            {
              header = 1;

              if ((rm = bgp_node_match (table, &match)) != NULL)
                {
                  if (prefix_check && rm->p.prefixlen != match.prefixlen)
                    {
                      bgp_unlock_node (rm);
                      continue;
                    }

                  for (ri = rm->info; ri; ri = ri->next)
                    {
                      if (header)
                        {
                          route_vty_out_detail_header (vty, bgp, rm, (struct prefix_rd *)&rn->p,
                                                       AFI_IP, SAFI_MPLS_VPN, json);

                          header = 0;
                        }
                      display++;

                      if (pathtype == BGP_PATH_ALL ||
                          (pathtype == BGP_PATH_BESTPATH && CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)) ||
                          (pathtype == BGP_PATH_MULTIPATH &&
                           (CHECK_FLAG (ri->flags, BGP_INFO_MULTIPATH) || CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))))
                        route_vty_out_detail (vty, bgp, &rm->p, ri, AFI_IP, SAFI_MPLS_VPN, json_paths);
                    }

                  bgp_unlock_node (rm);
                }
            }
        }
    }
  else
    {
      header = 1;

      if ((rn = bgp_node_match (rib, &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              for (ri = rn->info; ri; ri = ri->next)
                {
                  if (header)
                    {
                      route_vty_out_detail_header (vty, bgp, rn, NULL, afi, safi, json);
                      header = 0;
                    }
                  display++;

                  if (pathtype == BGP_PATH_ALL ||
                      (pathtype == BGP_PATH_BESTPATH && CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)) ||
                      (pathtype == BGP_PATH_MULTIPATH &&
                       (CHECK_FLAG (ri->flags, BGP_INFO_MULTIPATH) || CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))))
                    route_vty_out_detail (vty, bgp, &rn->p, ri, afi, safi, json_paths);
                }
            }

          bgp_unlock_node (rn);
        }
    }

  if (use_json)
    {
      if (display)
        json_object_object_add(json, "paths", json_paths);

      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);

      // Recursively free all json structures
      json_object_put(json);
    }
  else
    {
      if (!display)
        {
          vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  return CMD_SUCCESS;
}

/* Display specified route of Main RIB */
static int
bgp_show_route (struct vty *vty, const char *view_name, const char *ip_str,
		afi_t afi, safi_t safi, struct prefix_rd *prd,
		int prefix_check, enum bgp_path_type pathtype,
                u_char use_json)
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
 
  return bgp_show_route_in_table (vty, bgp, bgp->rib[afi][safi], ip_str, 
                                  afi, safi, prd, prefix_check, pathtype,
                                  use_json);
}

/* BGP route print out function. */
DEFUN (show_ip_bgp,
       show_ip_bgp_cmd,
       "show ip bgp {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[0] != NULL);
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL, use_json);
}

DEFUN (show_ip_bgp_ipv4,
       show_ip_bgp_ipv4_cmd,
       "show ip bgp ipv4 (unicast|multicast) {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);

  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST, bgp_show_type_normal,
                     NULL, use_json);
 
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL, use_json);
}

ALIAS (show_ip_bgp_ipv4,
       show_bgp_ipv4_safi_cmd,
       "show bgp ipv4 (unicast|multicast) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "JavaScript Object Notation\n")

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show ip bgp A.B.C.D {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, use_json);
}

DEFUN (show_ip_bgp_route_pathtype,
       show_ip_bgp_route_pathtype_cmd,
       "show ip bgp A.B.C.D (bestpath|multipath) {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);

  if (strncmp (argv[1], "b", 1) == 0)
    return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_BESTPATH, use_json);
  else
    return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_MULTIPATH, use_json);
}

DEFUN (show_bgp_ipv4_safi_route_pathtype,
       show_bgp_ipv4_safi_route_pathtype_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D (bestpath|multipath) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[3] != NULL);

  if (strncmp (argv[0], "m", 1) == 0)
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 0, BGP_PATH_BESTPATH, use_json);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 0, BGP_PATH_MULTIPATH, use_json);
  else
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_BESTPATH, use_json);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_MULTIPATH, use_json);
}

DEFUN (show_ip_bgp_ipv4_route,
       show_ip_bgp_ipv4_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);

  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 0, BGP_PATH_ALL, use_json);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, use_json);
}

ALIAS (show_ip_bgp_ipv4_route,
       show_bgp_ipv4_safi_route_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")

DEFUN (show_ip_bgp_vpnv4_all_route,
       show_ip_bgp_vpnv4_all_route_cmd,
       "show ip bgp vpnv4 all A.B.C.D {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_MPLS_VPN, NULL, 0, BGP_PATH_ALL, use_json);
}


DEFUN (show_ip_bgp_vpnv4_rd_route,
       show_ip_bgp_vpnv4_rd_route_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn A.B.C.D {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  int ret;
  struct prefix_rd prd;
  u_char use_json = (argv[2] != NULL);

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MPLS_VPN, &prd, 0, BGP_PATH_ALL, use_json);
}

DEFUN (show_ip_bgp_prefix,
       show_ip_bgp_prefix_cmd,
       "show ip bgp A.B.C.D/M {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, use_json);
}

DEFUN (show_ip_bgp_prefix_pathtype,
       show_ip_bgp_prefix_pathtype_cmd,
       "show ip bgp A.B.C.D/M (bestpath|multipath) {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  if (strncmp (argv[1], "b", 1) == 0)
    return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_BESTPATH, use_json);
  else
    return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_MULTIPATH, use_json);
}

DEFUN (show_ip_bgp_ipv4_prefix,
       show_ip_bgp_ipv4_prefix_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);

  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 1, BGP_PATH_ALL, use_json);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, use_json);
}

ALIAS (show_ip_bgp_ipv4_prefix,
       show_bgp_ipv4_safi_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D/M {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "JavaScript Object Notation\n")

DEFUN (show_ip_bgp_ipv4_prefix_pathtype,
       show_ip_bgp_ipv4_prefix_pathtype_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M (bestpath|multipath) {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[3] != NULL);

  if (strncmp (argv[0], "m", 1) == 0)
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 1, BGP_PATH_BESTPATH, use_json);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 1, BGP_PATH_MULTIPATH, use_json);
  else
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_BESTPATH, use_json);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_MULTIPATH, use_json);
}

ALIAS (show_ip_bgp_ipv4_prefix_pathtype,
       show_bgp_ipv4_safi_prefix_pathtype_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D/M (bestpath|multipath) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")

DEFUN (show_ip_bgp_vpnv4_all_prefix,
       show_ip_bgp_vpnv4_all_prefix_cmd,
       "show ip bgp vpnv4 all A.B.C.D/M {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_MPLS_VPN, NULL, 1, BGP_PATH_ALL, use_json);
}

DEFUN (show_ip_bgp_vpnv4_rd_prefix,
       show_ip_bgp_vpnv4_rd_prefix_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn A.B.C.D/M {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "JavaScript Object Notation\n")
{
  int ret;
  struct prefix_rd prd;
  u_char use_json = (argv[2] != NULL);

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MPLS_VPN, &prd, 0, BGP_PATH_ALL, use_json);
}

DEFUN (show_ip_bgp_view,
       show_ip_bgp_view_cmd,
       "show ip bgp view WORD {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "JavaScript Object Notation\n")
{
  struct bgp *bgp;
  u_char use_json = (argv[1] != NULL);

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}

  return bgp_show (vty, bgp, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL, use_json);
}

DEFUN (show_ip_bgp_view_route,
       show_ip_bgp_view_route_cmd,
       "show ip bgp view WORD A.B.C.D {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, use_json);
}

DEFUN (show_ip_bgp_view_prefix,
       show_ip_bgp_view_prefix_cmd,
       "show ip bgp view WORD A.B.C.D/M {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, use_json);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp,
       show_bgp_cmd,
       "show bgp {json}",
       SHOW_STR
       BGP_STR
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[0] != NULL);
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal,
                   NULL, use_json);
}

ALIAS (show_bgp,
       show_bgp_ipv6_cmd,
       "show bgp ipv6 {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "JavaScript Object Notation\n")

DEFUN (show_bgp_ipv6_safi,
       show_bgp_ipv6_safi_cmd,
       "show bgp ipv6 (unicast|multicast) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST, bgp_show_type_normal,
                     NULL, use_json);

  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal, NULL, use_json);
}

/* old command */
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[0] != NULL);
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal,
                   NULL, use_json);
}

DEFUN (show_bgp_route,
       show_bgp_route_cmd,
       "show bgp X:X::X:X {json}",
       SHOW_STR
       BGP_STR
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, use_json);
}

ALIAS (show_bgp_route,
       show_bgp_ipv6_route_cmd,
       "show bgp ipv6 X:X::X:X {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")

DEFUN (show_bgp_ipv6_safi_route,
       show_bgp_ipv6_safi_route_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 0, BGP_PATH_ALL, use_json);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, use_json);
}

DEFUN (show_bgp_route_pathtype,
       show_bgp_route_pathtype_cmd,
       "show bgp X:X::X:X (bestpath|multipath) {json}",
       SHOW_STR
       BGP_STR
       "Network in the BGP routing table to display\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  if (strncmp (argv[1], "b", 1) == 0)
    return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_BESTPATH, use_json);
  else
    return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_MULTIPATH, use_json);
}

ALIAS (show_bgp_route_pathtype,
       show_bgp_ipv6_route_pathtype_cmd,
       "show bgp ipv6 X:X::X:X (bestpath|multipath) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Network in the BGP routing table to display\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")

DEFUN (show_bgp_ipv6_safi_route_pathtype,
       show_bgp_ipv6_safi_route_pathtype_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X (bestpath|multipath) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[3] != NULL);
  if (strncmp (argv[0], "m", 1) == 0)
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 0, BGP_PATH_BESTPATH, use_json);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 0, BGP_PATH_MULTIPATH, use_json);
  else
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_BESTPATH, use_json);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_MULTIPATH, use_json);
}

/* old command */
DEFUN (show_ipv6_bgp_route,
       show_ipv6_bgp_route_cmd,
       "show ipv6 bgp X:X::X:X {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, use_json);
}

DEFUN (show_bgp_prefix,
       show_bgp_prefix_cmd,
       "show bgp X:X::X:X/M {json}",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, use_json);
}

ALIAS (show_bgp_prefix,
       show_bgp_ipv6_prefix_cmd,
       "show bgp ipv6 X:X::X:X/M {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n"
       "JavaScript Object Notation\n")

DEFUN (show_bgp_ipv6_safi_prefix,
       show_bgp_ipv6_safi_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X/M {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 1, BGP_PATH_ALL, use_json);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, use_json);
}

DEFUN (show_bgp_prefix_pathtype,
       show_bgp_prefix_pathtype_cmd,
       "show bgp X:X::X:X/M (bestpath|multipath) {json}",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  if (strncmp (argv[1], "b", 1) == 0)
    return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_BESTPATH, use_json);
  else
    return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_MULTIPATH, use_json);
}

ALIAS (show_bgp_prefix_pathtype,
       show_bgp_ipv6_prefix_pathtype_cmd,
       "show bgp ipv6 X:X::X:X/M (bestpath|multipath) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")

DEFUN (show_bgp_ipv6_safi_prefix_pathtype,
       show_bgp_ipv6_safi_prefix_pathtype_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X/M (bestpath|multipath) {json}",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[3] != NULL);
  if (strncmp (argv[0], "m", 1) == 0)
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 1, BGP_PATH_BESTPATH, use_json);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 1, BGP_PATH_MULTIPATH, use_json);
  else
    if (strncmp (argv[2], "b", 1) == 0)
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_BESTPATH, use_json);
    else
      return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_MULTIPATH, use_json);
}

/* old command */
DEFUN (show_ipv6_bgp_prefix,
       show_ipv6_bgp_prefix_cmd,
       "show ipv6 bgp X:X::X:X/M {json}",
       SHOW_STR
       IP_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, use_json);
}

DEFUN (show_bgp_view,
       show_bgp_view_cmd,
       "show bgp view WORD {json}",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "JavaScript Object Notation\n")
{
  struct bgp *bgp;
  u_char use_json = (argv[1] != NULL);

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
  
  return bgp_show (vty, bgp, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal, NULL, use_json);
}

ALIAS (show_bgp_view,
       show_bgp_view_ipv6_cmd,
       "show bgp view WORD ipv6 {json}",
       SHOW_STR
       BGP_STR             
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "JavaScript Object Notation\n")
  
DEFUN (show_bgp_view_route,
       show_bgp_view_route_cmd,
       "show bgp view WORD X:X::X:X {json}",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, use_json);
}

ALIAS (show_bgp_view_route,
       show_bgp_view_ipv6_route_cmd,
       "show bgp view WORD ipv6 X:X::X:X {json}",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Network in the BGP routing table to display\n"
       "JavaScript Object Notation\n")

DEFUN (show_bgp_view_prefix,
       show_bgp_view_prefix_cmd,
       "show bgp view WORD X:X::X:X/M {json}",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"       
       "IPv6 prefix <network>/<length>\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[2] != NULL);
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, use_json);
}

ALIAS (show_bgp_view_prefix,
       show_bgp_view_ipv6_prefix_cmd,
       "show bgp view WORD ipv6 X:X::X:X/M {json}",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "IPv6 prefix <network>/<length>\n"
       "JavaScript Object Notation\n")

/* old command */
DEFUN (show_ipv6_mbgp,
       show_ipv6_mbgp_cmd,
       "show ipv6 mbgp {json}",
       SHOW_STR
       IP_STR
       MBGP_STR
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[0] != NULL);
  return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST, bgp_show_type_normal,
                   NULL, use_json);
}

/* old command */
DEFUN (show_ipv6_mbgp_route,
       show_ipv6_mbgp_route_cmd,
       "show ipv6 mbgp X:X::X:X {json}",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Network in the MBGP routing table to display\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MULTICAST, NULL, 0, BGP_PATH_ALL, use_json);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix,
       show_ipv6_mbgp_prefix_cmd,
       "show ipv6 mbgp X:X::X:X/M {json}",
       SHOW_STR
       IP_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "JavaScript Object Notation\n")
{
  u_char use_json = (argv[1] != NULL);
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MULTICAST, NULL, 1, BGP_PATH_ALL, use_json);
}
#endif


static int
bgp_show_regexp (struct vty *vty, int argc, const char **argv, afi_t afi,
		 safi_t safi, enum bgp_show_type type)
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;
  regex_t *regex;
  int rc;
  
  first = 0;
  b = buffer_new (1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	{
	  if ((strcmp (argv[i], "unicast") == 0) || (strcmp (argv[i], "multicast") == 0))
	    continue;
	  first = 1;
	}

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  regex = bgp_regcomp (regstr);
  XFREE(MTYPE_TMP, regstr);
  if (! regex)
    {
      vty_out (vty, "Can't compile regexp %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  rc = bgp_show (vty, NULL, afi, safi, type, regex, 0);
  bgp_regex_free (regex);
  return rc;
}

DEFUN (show_ip_bgp_regexp, 
       show_ip_bgp_regexp_cmd,
       "show ip bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

DEFUN (show_ip_bgp_flap_regexp, 
       show_ip_bgp_flap_regexp_cmd,
       "show ip bgp flap-statistics regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
			  bgp_show_type_flap_regexp);
}

DEFUN (show_ip_bgp_ipv4_regexp, 
       show_ip_bgp_ipv4_regexp_cmd,
       "show ip bgp ipv4 (unicast|multicast) regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_MULTICAST,
			    bgp_show_type_regexp);

  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_regexp, 
       show_bgp_regexp_cmd,
       "show bgp regexp .LINE",
       SHOW_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

ALIAS (show_bgp_regexp, 
       show_bgp_ipv6_regexp_cmd,
       "show bgp ipv6 regexp .LINE",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

/* old command */
DEFUN (show_ipv6_bgp_regexp, 
       show_ipv6_bgp_regexp_cmd,
       "show ipv6 bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_UNICAST,
			  bgp_show_type_regexp);
}

/* old command */
DEFUN (show_ipv6_mbgp_regexp, 
       show_ipv6_mbgp_regexp_cmd,
       "show ipv6 mbgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the MBGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_MULTICAST,
			  bgp_show_type_regexp);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_prefix_list (struct vty *vty, const char *prefix_list_str, afi_t afi,
		      safi_t safi, enum bgp_show_type type)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (afi, prefix_list_str);
  if (plist == NULL)
    {
      vty_out (vty, "%% %s is not a valid prefix-list name%s",
               prefix_list_str, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, plist, 0);
}

DEFUN (show_ip_bgp_prefix_list, 
       show_ip_bgp_prefix_list_cmd,
       "show ip bgp prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

DEFUN (show_ip_bgp_flap_prefix_list, 
       show_ip_bgp_flap_prefix_list_cmd,
       "show ip bgp flap-statistics prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_flap_prefix_list);
}

DEFUN (show_ip_bgp_ipv4_prefix_list, 
       show_ip_bgp_ipv4_prefix_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_prefix_list (vty, argv[1], AFI_IP, SAFI_MULTICAST,
			         bgp_show_type_prefix_list);

  return bgp_show_prefix_list (vty, argv[1], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_prefix_list, 
       show_bgp_prefix_list_cmd,
       "show bgp prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Display routes conforming to the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

ALIAS (show_bgp_prefix_list, 
       show_bgp_ipv6_prefix_list_cmd,
       "show bgp ipv6 prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes conforming to the prefix-list\n"
       "IPv6 prefix-list name\n")

/* old command */
DEFUN (show_ipv6_bgp_prefix_list, 
       show_ipv6_bgp_prefix_list_cmd,
       "show ipv6 bgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_prefix_list);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix_list, 
       show_ipv6_mbgp_prefix_list_cmd,
       "show ipv6 mbgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
			       bgp_show_type_prefix_list);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_filter_list (struct vty *vty, const char *filter, afi_t afi,
		      safi_t safi, enum bgp_show_type type)
{
  struct as_list *as_list;

  as_list = as_list_lookup (filter);
  if (as_list == NULL)
    {
      vty_out (vty, "%% %s is not a valid AS-path access-list name%s", filter, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, as_list, 0);
}

DEFUN (show_ip_bgp_filter_list, 
       show_ip_bgp_filter_list_cmd,
       "show ip bgp filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

DEFUN (show_ip_bgp_flap_filter_list, 
       show_ip_bgp_flap_filter_list_cmd,
       "show ip bgp flap-statistics filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_flap_filter_list);
}

DEFUN (show_ip_bgp_ipv4_filter_list, 
       show_ip_bgp_ipv4_filter_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_filter_list (vty, argv[1], AFI_IP, SAFI_MULTICAST,
			         bgp_show_type_filter_list);
  
  return bgp_show_filter_list (vty, argv[1], AFI_IP, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_filter_list, 
       show_bgp_filter_list_cmd,
       "show bgp filter-list WORD",
       SHOW_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

ALIAS (show_bgp_filter_list, 
       show_bgp_ipv6_filter_list_cmd,
       "show bgp ipv6 filter-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

/* old command */
DEFUN (show_ipv6_bgp_filter_list, 
       show_ipv6_bgp_filter_list_cmd,
       "show ipv6 bgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			       bgp_show_type_filter_list);
}

/* old command */
DEFUN (show_ipv6_mbgp_filter_list, 
       show_ipv6_mbgp_filter_list_cmd,
       "show ipv6 mbgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
			       bgp_show_type_filter_list);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_route_map (struct vty *vty, const char *rmap_str, afi_t afi,
		    safi_t safi, enum bgp_show_type type)
{
  struct route_map *rmap;

  rmap = route_map_lookup_by_name (rmap_str);
  if (! rmap)
    {
      vty_out (vty, "%% %s is not a valid route-map name%s",
	       rmap_str, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, rmap, 0);
}

DEFUN (show_ip_bgp_route_map, 
       show_ip_bgp_route_map_cmd,
       "show ip bgp route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP, SAFI_UNICAST,
			     bgp_show_type_route_map);
}

DEFUN (show_ip_bgp_flap_route_map, 
       show_ip_bgp_flap_route_map_cmd,
       "show ip bgp flap-statistics route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP, SAFI_UNICAST,
			     bgp_show_type_flap_route_map);
}

DEFUN (show_ip_bgp_ipv4_route_map, 
       show_ip_bgp_ipv4_route_map_cmd,
       "show ip bgp ipv4 (unicast|multicast) route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route_map (vty, argv[1], AFI_IP, SAFI_MULTICAST,
			       bgp_show_type_route_map);

  return bgp_show_route_map (vty, argv[1], AFI_IP, SAFI_UNICAST,
			     bgp_show_type_route_map);
}

DEFUN (show_bgp_route_map, 
       show_bgp_route_map_cmd,
       "show bgp route-map WORD",
       SHOW_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP6, SAFI_UNICAST,
			     bgp_show_type_route_map);
}

ALIAS (show_bgp_route_map, 
       show_bgp_ipv6_route_map_cmd,
       "show bgp ipv6 route-map WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")

DEFUN (show_ip_bgp_cidr_only,
       show_ip_bgp_cidr_only_cmd,
       "show ip bgp cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display only routes with non-natural netmasks\n")
{
    return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		     bgp_show_type_cidr_only, NULL, 0);
}

DEFUN (show_ip_bgp_flap_cidr_only,
       show_ip_bgp_flap_cidr_only_cmd,
       "show ip bgp flap-statistics cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display only routes with non-natural netmasks\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		   bgp_show_type_flap_cidr_only, NULL, 0);
}

DEFUN (show_ip_bgp_ipv4_cidr_only,
       show_ip_bgp_ipv4_cidr_only_cmd,
       "show ip bgp ipv4 (unicast|multicast) cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display only routes with non-natural netmasks\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
		     bgp_show_type_cidr_only, NULL, 0);

  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		   bgp_show_type_cidr_only, NULL, 0);
}

DEFUN (show_ip_bgp_community_all,
       show_ip_bgp_community_all_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		   bgp_show_type_community_all, NULL, 0);
}

DEFUN (show_ip_bgp_ipv4_community_all,
       show_ip_bgp_ipv4_community_all_cmd,
       "show ip bgp ipv4 (unicast|multicast) community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
		     bgp_show_type_community_all, NULL, 0);
 
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		   bgp_show_type_community_all, NULL, 0);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_community_all,
       show_bgp_community_all_cmd,
       "show bgp community",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST,
		   bgp_show_type_community_all, NULL, 0);
}

ALIAS (show_bgp_community_all,
       show_bgp_ipv6_community_all_cmd,
       "show bgp ipv6 community",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n")

/* old command */
DEFUN (show_ipv6_bgp_community_all,
       show_ipv6_bgp_community_all_cmd,
       "show ipv6 bgp community",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST,
		   bgp_show_type_community_all, NULL, 0);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_all,
       show_ipv6_mbgp_community_all_cmd,
       "show ipv6 mbgp community",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST,
		   bgp_show_type_community_all, NULL, 0);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_community (struct vty *vty, const char *view_name, int argc,
		    const char **argv, int exact, afi_t afi, safi_t safi)
{
  struct community *com;
  struct buffer *b;
  struct bgp *bgp;
  int i;
  char *str;
  int first = 0;

  /* BGP structure lookup */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  b = buffer_new (1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
        buffer_putc (b, ' ');
      else
	{
	  if ((strcmp (argv[i], "unicast") == 0) || (strcmp (argv[i], "multicast") == 0))
	    continue;
	  first = 1;
	}
      
      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  com = community_str2com (str);
  XFREE (MTYPE_TMP, str);
  if (! com)
    {
      vty_out (vty, "%% Community malformed: %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, bgp, afi, safi,
                   (exact ? bgp_show_type_community_exact :
		    bgp_show_type_community), com, 0);
}

DEFUN (show_ip_bgp_community,
       show_ip_bgp_community_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community2_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_community,
       show_ip_bgp_community3_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_community,
       show_ip_bgp_community4_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community2_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community3_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community4_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_bgp_view_afi_safi_community_all,
       show_bgp_view_afi_safi_community_all_cmd,
#ifdef HAVE_IPV6
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community",
#else
       "show bgp view WORD ipv4 (unicast|multicast) community",
#endif
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
#ifdef HAVE_IPV6
       "Address family\n"
#endif
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")
{
  int afi;
  int safi;
  struct bgp *bgp;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
    {
      vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

#ifdef HAVE_IPV6
  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
#else
  afi = AFI_IP;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
#endif
  return bgp_show (vty, bgp, afi, safi, bgp_show_type_community_all, NULL, 0);
}

DEFUN (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community_cmd,
#ifdef HAVE_IPV6
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
#else
       "show bgp view WORD ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
#endif
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
#ifdef HAVE_IPV6
       "Address family\n"
#endif
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  int afi;
  int safi;

#ifdef HAVE_IPV6
  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  return bgp_show_community (vty, argv[0], argc-3, &argv[3], 0, afi, safi);
#else
  afi = AFI_IP;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  return bgp_show_community (vty, argv[0], argc-2, &argv[2], 0, afi, safi);
#endif
}

ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community2_cmd,
#ifdef HAVE_IPV6
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
#else
       "show bgp view WORD ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
#endif
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
#ifdef HAVE_IPV6
       "Address family\n"
#endif
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community3_cmd,
#ifdef HAVE_IPV6
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
#else
       "show bgp view WORD ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
#endif
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
#ifdef HAVE_IPV6
       "Address family\n"
#endif
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community4_cmd,
#ifdef HAVE_IPV6
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
#else
       "show bgp view WORD ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
#endif
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
#ifdef HAVE_IPV6
       "Address family\n"
#endif
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_ip_bgp_community_exact,
       show_ip_bgp_community_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community2_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community3_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community4_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community2_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community3_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
       
ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community4_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

#ifdef HAVE_IPV6
DEFUN (show_bgp_community,
       show_bgp_community_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community,
       show_bgp_ipv6_community_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community2_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community2_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_bgp_community,
       show_bgp_community3_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community3_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community4_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community4_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
DEFUN (show_ipv6_bgp_community,
       show_ipv6_bgp_community_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_UNICAST);
}

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community2_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community3_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community4_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_bgp_community_exact,
       show_bgp_community_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community2_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community2_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community3_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community3_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community4_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
 
ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community4_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
DEFUN (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_UNICAST);
}

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community2_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community3_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community4_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
 
/* old command */
DEFUN (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_MULTICAST);
}

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community2_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community3_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community4_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
DEFUN (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_MULTICAST);
}

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community2_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community3_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community4_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
#endif /* HAVE_IPV6 */

static int
bgp_show_community_list (struct vty *vty, const char *com, int exact,
			 afi_t afi, safi_t safi)
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, com, COMMUNITY_LIST_MASTER);
  if (list == NULL)
    {
      vty_out (vty, "%% %s is not a valid community-list name%s", com,
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi,
                   (exact ? bgp_show_type_community_list_exact :
		    bgp_show_type_community_list), list, 0);
}

DEFUN (show_ip_bgp_community_list,
       show_ip_bgp_community_list_cmd,
       "show ip bgp community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_community_list,
       show_ip_bgp_ipv4_community_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_MULTICAST);
  
  return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_community_list_exact,
       show_ip_bgp_community_list_exact_cmd,
       "show ip bgp community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_community_list_exact,
       show_ip_bgp_ipv4_community_list_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_UNICAST);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_community_list,
       show_bgp_community_list_cmd,
       "show bgp community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community_list,
       show_bgp_ipv6_community_list_cmd,
       "show bgp ipv6 community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")

/* old command */
DEFUN (show_ipv6_bgp_community_list,
       show_ipv6_bgp_community_list_cmd,
       "show ipv6 bgp community-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_UNICAST);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_list,
       show_ipv6_mbgp_community_list_cmd,
       "show ipv6 mbgp community-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_MULTICAST);
}

DEFUN (show_bgp_community_list_exact,
       show_bgp_community_list_exact_cmd,
       "show bgp community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community_list_exact,
       show_bgp_ipv6_community_list_exact_cmd,
       "show bgp ipv6 community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")

/* old command */
DEFUN (show_ipv6_bgp_community_list_exact,
       show_ipv6_bgp_community_list_exact_cmd,
       "show ipv6 bgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_UNICAST);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_list_exact,
       show_ipv6_mbgp_community_list_exact_cmd,
       "show ipv6 mbgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_MULTICAST);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_prefix_longer (struct vty *vty, const char *prefix, afi_t afi,
			safi_t safi, enum bgp_show_type type)
{
  int ret;
  struct prefix *p;

  p = prefix_new();

  ret = str2prefix (prefix, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = bgp_show (vty, NULL, afi, safi, type, p, 0);
  prefix_free(p);
  return ret;
}

DEFUN (show_ip_bgp_prefix_longer,
       show_ip_bgp_prefix_longer_cmd,
       "show ip bgp A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

DEFUN (show_ip_bgp_flap_prefix_longer,
       show_ip_bgp_flap_prefix_longer_cmd,
       "show ip bgp flap-statistics A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_flap_prefix_longer);
}

DEFUN (show_ip_bgp_ipv4_prefix_longer,
       show_ip_bgp_ipv4_prefix_longer_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_prefix_longer (vty, argv[1], AFI_IP, SAFI_MULTICAST,
				   bgp_show_type_prefix_longer);

  return bgp_show_prefix_longer (vty, argv[1], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

DEFUN (show_ip_bgp_flap_address,
       show_ip_bgp_flap_address_cmd,
       "show ip bgp flap-statistics A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_flap_address);
}

DEFUN (show_ip_bgp_flap_prefix,
       show_ip_bgp_flap_prefix_cmd,
       "show ip bgp flap-statistics A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
				 bgp_show_type_flap_prefix);
}
#ifdef HAVE_IPV6
DEFUN (show_bgp_prefix_longer,
       show_bgp_prefix_longer_cmd,
       "show bgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

ALIAS (show_bgp_prefix_longer,
       show_bgp_ipv6_prefix_longer_cmd,
       "show bgp ipv6 X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n"
       "Display route and more specific routes\n")

/* old command */
DEFUN (show_ipv6_bgp_prefix_longer,
       show_ipv6_bgp_prefix_longer_cmd,
       "show ipv6 bgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_UNICAST,
				 bgp_show_type_prefix_longer);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix_longer,
       show_ipv6_mbgp_prefix_longer_cmd,
       "show ipv6 mbgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
				 bgp_show_type_prefix_longer);
}
#endif /* HAVE_IPV6 */

static struct peer *
peer_lookup_in_view (struct vty *vty, const char *view_name, 
                     const char *ip_str)
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;
  union sockunion su;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (! bgp)
        {
          vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
          return NULL;
        }      
    }
  else
    {
      bgp = bgp_get_default ();
      if (! bgp)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return NULL;
        }
    }

  /* Get peer sockunion. */  
  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      peer = peer_lookup_by_conf_if (bgp, ip_str);
      if (!peer)
        {
          vty_out (vty, "%% Malformed address or name: %s%s", ip_str, VTY_NEWLINE);
          return NULL;
        }
      return peer;
    }

  /* Peer structure lookup. */
  peer = peer_lookup (bgp, &su);
  if (! peer)
    {
      vty_out (vty, "No such neighbor%s", VTY_NEWLINE);
      return NULL;
    }
  
  return peer;
}

enum bgp_stats
{
  BGP_STATS_MAXBITLEN = 0,
  BGP_STATS_RIB,
  BGP_STATS_PREFIXES,
  BGP_STATS_TOTPLEN,
  BGP_STATS_UNAGGREGATEABLE,
  BGP_STATS_MAX_AGGREGATEABLE,
  BGP_STATS_AGGREGATES,
  BGP_STATS_SPACE,
  BGP_STATS_ASPATH_COUNT,
  BGP_STATS_ASPATH_MAXHOPS,
  BGP_STATS_ASPATH_TOTHOPS,
  BGP_STATS_ASPATH_MAXSIZE,
  BGP_STATS_ASPATH_TOTSIZE,
  BGP_STATS_ASN_HIGHEST,
  BGP_STATS_MAX,
};

static const char *table_stats_strs[] =
{
  [BGP_STATS_PREFIXES]            = "Total Prefixes",
  [BGP_STATS_TOTPLEN]             = "Average prefix length",
  [BGP_STATS_RIB]                 = "Total Advertisements",
  [BGP_STATS_UNAGGREGATEABLE]     = "Unaggregateable prefixes",
  [BGP_STATS_MAX_AGGREGATEABLE]   = "Maximum aggregateable prefixes",
  [BGP_STATS_AGGREGATES]          = "BGP Aggregate advertisements",
  [BGP_STATS_SPACE]               = "Address space advertised",
  [BGP_STATS_ASPATH_COUNT]        = "Advertisements with paths",
  [BGP_STATS_ASPATH_MAXHOPS]      = "Longest AS-Path (hops)",
  [BGP_STATS_ASPATH_MAXSIZE]      = "Largest AS-Path (bytes)",
  [BGP_STATS_ASPATH_TOTHOPS]      = "Average AS-Path length (hops)",
  [BGP_STATS_ASPATH_TOTSIZE]      = "Average AS-Path size (bytes)",
  [BGP_STATS_ASN_HIGHEST]         = "Highest public ASN",
  [BGP_STATS_MAX] = NULL,
};

struct bgp_table_stats
{
  struct bgp_table *table;
  unsigned long long counts[BGP_STATS_MAX];
};

#if 0
#define TALLY_SIGFIG 100000
static unsigned long
ravg_tally (unsigned long count, unsigned long oldavg, unsigned long newval)
{
  unsigned long newtot = (count-1) * oldavg + (newval * TALLY_SIGFIG);
  unsigned long res = (newtot * TALLY_SIGFIG) / count;
  unsigned long ret = newtot / count;
  
  if ((res % TALLY_SIGFIG) > (TALLY_SIGFIG/2))
    return ret + 1;
  else
    return ret;
}
#endif

static int
bgp_table_stats_walker (struct thread *t)
{
  struct bgp_node *rn;
  struct bgp_node *top;
  struct bgp_table_stats *ts = THREAD_ARG (t);
  unsigned int space = 0;
  
  if (!(top = bgp_table_top (ts->table)))
    return 0;

  switch (top->p.family)
    {
      case AF_INET:
        space = IPV4_MAX_BITLEN;
        break;
      case AF_INET6:
        space = IPV6_MAX_BITLEN;
        break;
    }
    
  ts->counts[BGP_STATS_MAXBITLEN] = space;

  for (rn = top; rn; rn = bgp_route_next (rn))
    {
      struct bgp_info *ri;
      struct bgp_node *prn = bgp_node_parent_nolock (rn);
      unsigned int rinum = 0;
      
      if (rn == top)
        continue;
      
      if (!rn->info)
        continue;
      
      ts->counts[BGP_STATS_PREFIXES]++;
      ts->counts[BGP_STATS_TOTPLEN] += rn->p.prefixlen;

#if 0
      ts->counts[BGP_STATS_AVGPLEN]
        = ravg_tally (ts->counts[BGP_STATS_PREFIXES],
                      ts->counts[BGP_STATS_AVGPLEN],
                      rn->p.prefixlen);
#endif
      
      /* check if the prefix is included by any other announcements */
      while (prn && !prn->info)
        prn = bgp_node_parent_nolock (prn);
      
      if (prn == NULL || prn == top)
        {
          ts->counts[BGP_STATS_UNAGGREGATEABLE]++;
          /* announced address space */
          if (space)
            ts->counts[BGP_STATS_SPACE] += 1 << (space - rn->p.prefixlen);
        }
      else if (prn->info)
        ts->counts[BGP_STATS_MAX_AGGREGATEABLE]++;
      
      for (ri = rn->info; ri; ri = ri->next)
        {
          rinum++;
          ts->counts[BGP_STATS_RIB]++;
          
          if (ri->attr &&
              (CHECK_FLAG (ri->attr->flag,
                           ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE))))
            ts->counts[BGP_STATS_AGGREGATES]++;
          
          /* as-path stats */
          if (ri->attr && ri->attr->aspath)
            {
              unsigned int hops = aspath_count_hops (ri->attr->aspath);
              unsigned int size = aspath_size (ri->attr->aspath);
              as_t highest = aspath_highest (ri->attr->aspath);
              
              ts->counts[BGP_STATS_ASPATH_COUNT]++;
              
              if (hops > ts->counts[BGP_STATS_ASPATH_MAXHOPS])
                ts->counts[BGP_STATS_ASPATH_MAXHOPS] = hops;
              
              if (size > ts->counts[BGP_STATS_ASPATH_MAXSIZE])
                ts->counts[BGP_STATS_ASPATH_MAXSIZE] = size;
              
              ts->counts[BGP_STATS_ASPATH_TOTHOPS] += hops;
              ts->counts[BGP_STATS_ASPATH_TOTSIZE] += size;
#if 0
              ts->counts[BGP_STATS_ASPATH_AVGHOPS] 
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGHOPS],
                              hops);
              ts->counts[BGP_STATS_ASPATH_AVGSIZE]
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGSIZE],
                              size);
#endif
              if (highest > ts->counts[BGP_STATS_ASN_HIGHEST])
                ts->counts[BGP_STATS_ASN_HIGHEST] = highest;
            }
        }
    }
  return 0;
}

static int
bgp_table_stats (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi)
{
  struct bgp_table_stats ts;
  unsigned int i;
  
  if (!bgp->rib[afi][safi])
    {
      vty_out (vty, "%% No RIB exist for the AFI/SAFI%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  memset (&ts, 0, sizeof (ts));
  ts.table = bgp->rib[afi][safi];
  thread_execute (bm->master, bgp_table_stats_walker, &ts, 0);

  vty_out (vty, "BGP %s RIB statistics%s%s",
           afi_safi_print (afi, safi), VTY_NEWLINE, VTY_NEWLINE);
  
  for (i = 0; i < BGP_STATS_MAX; i++)
    {
      if (!table_stats_strs[i])
        continue;
      
      switch (i)
        {
#if 0
          case BGP_STATS_ASPATH_AVGHOPS:
          case BGP_STATS_ASPATH_AVGSIZE:
          case BGP_STATS_AVGPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     (float)ts.counts[i] / (float)TALLY_SIGFIG);
            break;
#endif
          case BGP_STATS_ASPATH_TOTHOPS:
          case BGP_STATS_ASPATH_TOTSIZE:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     ts.counts[i] ?
                     (float)ts.counts[i] / 
                      (float)ts.counts[BGP_STATS_ASPATH_COUNT]
                     : 0);
            break;
          case BGP_STATS_TOTPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     ts.counts[i] ?
                     (float)ts.counts[i] / 
                      (float)ts.counts[BGP_STATS_PREFIXES]
                     : 0);
            break;
          case BGP_STATS_SPACE:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12llu%s", ts.counts[i], VTY_NEWLINE);
            if (ts.counts[BGP_STATS_MAXBITLEN] < 9)
              break;
            vty_out (vty, "%30s: ", "%% announced ");
            vty_out (vty, "%12.2f%s", 
                     100 * (float)ts.counts[BGP_STATS_SPACE] / 
                       (float)((uint64_t)1UL << ts.counts[BGP_STATS_MAXBITLEN]),
                       VTY_NEWLINE);
            vty_out (vty, "%30s: ", "/8 equivalent ");
            vty_out (vty, "%12.2f%s", 
                     (float)ts.counts[BGP_STATS_SPACE] / 
                       (float)(1UL << (ts.counts[BGP_STATS_MAXBITLEN] - 8)),
                     VTY_NEWLINE);
            if (ts.counts[BGP_STATS_MAXBITLEN] < 25)
              break;
            vty_out (vty, "%30s: ", "/24 equivalent ");
            vty_out (vty, "%12.2f", 
                     (float)ts.counts[BGP_STATS_SPACE] / 
                       (float)(1UL << (ts.counts[BGP_STATS_MAXBITLEN] - 24)));
            break;
          default:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12llu", ts.counts[i]);
        }
        
      vty_out (vty, "%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

static int
bgp_table_stats_vty (struct vty *vty, const char *name,
                     const char *afi_str, const char *safi_str)
{
  struct bgp *bgp;
  afi_t afi;
  safi_t safi;
  
 if (name)
    bgp = bgp_lookup_by_name (name);
  else
    bgp = bgp_get_default ();

  if (!bgp)
    {
      vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (strncmp (afi_str, "ipv", 3) == 0)
    {
      if (strncmp (afi_str, "ipv4", 4) == 0)
        afi = AFI_IP;
      else if (strncmp (afi_str, "ipv6", 4) == 0)
        afi = AFI_IP6;
      else
        {
          vty_out (vty, "%% Invalid address family %s%s",
                   afi_str, VTY_NEWLINE);
          return CMD_WARNING;
        }
      if (strncmp (safi_str, "m", 1) == 0)
        safi = SAFI_MULTICAST;
      else if (strncmp (safi_str, "u", 1) == 0)
        safi = SAFI_UNICAST;
      else if (strncmp (safi_str, "vpnv4", 5) == 0 || strncmp (safi_str, "vpnv6", 5) == 0)
        safi = SAFI_MPLS_LABELED_VPN;
      else
        {
          vty_out (vty, "%% Invalid subsequent address family %s%s",
                   safi_str, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      vty_out (vty, "%% Invalid address family %s%s",
               afi_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_table_stats (vty, bgp, afi, safi);
}

DEFUN (show_bgp_statistics,
       show_bgp_statistics_cmd,
       "show bgp (ipv4|ipv6) (unicast|multicast) statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  return bgp_table_stats_vty (vty, NULL, argv[0], argv[1]);
}

ALIAS (show_bgp_statistics,
       show_bgp_statistics_vpnv4_cmd,
       "show bgp (ipv4) (vpnv4) statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")

DEFUN (show_bgp_statistics_view,
       show_bgp_statistics_view_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  return bgp_table_stats_vty (vty, NULL, argv[0], argv[1]);
}

ALIAS (show_bgp_statistics_view,
       show_bgp_statistics_view_vpnv4_cmd,
       "show bgp view WORD (ipv4) (vpnv4) statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "Address family\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")

enum bgp_pcounts
{
  PCOUNT_ADJ_IN = 0,
  PCOUNT_DAMPED,
  PCOUNT_REMOVED,
  PCOUNT_HISTORY,
  PCOUNT_STALE,
  PCOUNT_VALID,
  PCOUNT_ALL,
  PCOUNT_COUNTED,
  PCOUNT_PFCNT, /* the figure we display to users */
  PCOUNT_MAX,
};

static const char *pcount_strs[] =
{
  [PCOUNT_ADJ_IN]  = "Adj-in",
  [PCOUNT_DAMPED]  = "Damped",
  [PCOUNT_REMOVED] = "Removed",
  [PCOUNT_HISTORY] = "History",
  [PCOUNT_STALE]   = "Stale",
  [PCOUNT_VALID]   = "Valid",
  [PCOUNT_ALL]     = "All RIB",
  [PCOUNT_COUNTED] = "PfxCt counted",
  [PCOUNT_PFCNT]   = "Useable",
  [PCOUNT_MAX]     = NULL,
};

struct peer_pcounts
{
  unsigned int count[PCOUNT_MAX];
  const struct peer *peer;
  const struct bgp_table *table;
};

static int
bgp_peer_count_walker (struct thread *t)
{
  struct bgp_node *rn;
  struct peer_pcounts *pc = THREAD_ARG (t);
  const struct peer *peer = pc->peer;
  
  for (rn = bgp_table_top (pc->table); rn; rn = bgp_route_next (rn))
    {
      struct bgp_adj_in *ain;
      struct bgp_info *ri;
      
      for (ain = rn->adj_in; ain; ain = ain->next)
        if (ain->peer == peer)
          pc->count[PCOUNT_ADJ_IN]++;

      for (ri = rn->info; ri; ri = ri->next)
        {
          char buf[SU_ADDRSTRLEN];
          
          if (ri->peer != peer)
            continue;
          
          pc->count[PCOUNT_ALL]++;
          
          if (CHECK_FLAG (ri->flags, BGP_INFO_DAMPED))
            pc->count[PCOUNT_DAMPED]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
            pc->count[PCOUNT_HISTORY]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_REMOVED))
            pc->count[PCOUNT_REMOVED]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_STALE))
            pc->count[PCOUNT_STALE]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_VALID))
            pc->count[PCOUNT_VALID]++;
          if (!CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
            pc->count[PCOUNT_PFCNT]++;
          
          if (CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
            {
              pc->count[PCOUNT_COUNTED]++;
              if (CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
                zlog_warn ("%s [pcount] %s/%d is counted but flags 0x%x",
                           peer->host,
                           inet_ntop(rn->p.family, &rn->p.u.prefix,
                                     buf, SU_ADDRSTRLEN),
                           rn->p.prefixlen,
                           ri->flags);
            }
          else
            {
              if (!CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
                zlog_warn ("%s [pcount] %s/%d not counted but flags 0x%x",
                           peer->host,
                           inet_ntop(rn->p.family, &rn->p.u.prefix,
                                     buf, SU_ADDRSTRLEN),
                           rn->p.prefixlen,
                           ri->flags);
            }
        }
    }
  return 0;
}

static int
bgp_peer_counts (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi)
{
  struct peer_pcounts pcounts = { .peer = peer };
  unsigned int i;
  
  if (!peer || !peer->bgp || !peer->afc[afi][safi]
      || !peer->bgp->rib[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  memset (&pcounts, 0, sizeof(pcounts));
  pcounts.peer = peer;
  pcounts.table = peer->bgp->rib[afi][safi];
  
  /* in-place call via thread subsystem so as to record execution time
   * stats for the thread-walk (i.e. ensure this can't be blamed on
   * on just vty_read()).
   */
  thread_execute (bm->master, bgp_peer_count_walker, &pcounts, 0);
  
  vty_out (vty, "Prefix counts for %s, %s%s", 
           peer->host, afi_safi_print (afi, safi), VTY_NEWLINE);
  vty_out (vty, "PfxCt: %ld%s", peer->pcount[afi][safi], VTY_NEWLINE);
  vty_out (vty, "%sCounts from RIB table walk:%s%s", 
           VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

  for (i = 0; i < PCOUNT_MAX; i++)
      vty_out (vty, "%20s: %-10d%s",
               pcount_strs[i], pcounts.count[i], VTY_NEWLINE);

  if (pcounts.count[PCOUNT_PFCNT] != peer->pcount[afi][safi])
    {
      vty_out (vty, "%s [pcount] PfxCt drift!%s",
               peer->host, VTY_NEWLINE);
      vty_out (vty, "Please report this bug, with the above command output%s",
              VTY_NEWLINE);
    }
               
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbor_prefix_counts,
       show_ip_bgp_neighbor_prefix_counts_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);  
  if (! peer) 
    return CMD_WARNING;
 
  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_bgp_ipv6_neighbor_prefix_counts,
       show_bgp_ipv6_neighbor_prefix_counts_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) prefix-counts",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);  
  if (! peer) 
    return CMD_WARNING;
 
  return bgp_peer_counts (vty, peer, AFI_IP6, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_neighbor_prefix_counts,
       show_ip_bgp_ipv4_neighbor_prefix_counts_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_peer_counts (vty, peer, AFI_IP, SAFI_MULTICAST);

  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_vpnv4_neighbor_prefix_counts,
       show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd,
       "show ip bgp vpnv4 all neighbors (A.B.C.D|X:X::X:X|WORD) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
  
  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_MPLS_VPN);
}

static void
show_adj_route (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
		int in, char *rmap_name)
{
  struct bgp_table *table;
  struct bgp_adj_in *ain;
  struct bgp_adj_out *adj;
  unsigned long output_count;
  unsigned long filtered_count;
  struct bgp_node *rn;
  int header1 = 1;
  struct bgp *bgp;
  int header2 = 1;
  struct attr attr;
  struct attr_extra extra;
  int ret;

  bgp = peer->bgp;

  if (! bgp)
    return;

  table = bgp->rib[afi][safi];

  output_count = filtered_count = 0;

  if (! in && CHECK_FLAG (peer->af_sflags[afi][safi],
			  PEER_STATUS_DEFAULT_ORIGINATE))
    {
      vty_out (vty, "BGP table version is %llu, local router ID is %s%s", table->version, inet_ntoa (bgp->router_id), VTY_NEWLINE);
      vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
      vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);

      vty_out (vty, "Originating default network 0.0.0.0%s%s",
	       VTY_NEWLINE, VTY_NEWLINE);
      header1 = 0;
    }

  attr.extra = &extra;
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if (in)
      {
	for (ain = rn->adj_in; ain; ain = ain->next)
	  if (ain->peer == peer)
	    {
	      if (header1)
		{
		  vty_out (vty, "BGP table version is 0, local router ID is %s%s", inet_ntoa (bgp->router_id), VTY_NEWLINE);
		  vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
		  vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
		  header1 = 0;
		}
	      if (header2)
		{
		  vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
		  header2 = 0;
		}
	      if (ain->attr)
		{
		  bgp_attr_dup(&attr, ain->attr);
		  if (bgp_input_modifier(peer, &rn->p, &attr, afi,
					 safi, rmap_name) != RMAP_DENY)
		    {
		      route_vty_out_tmp (vty, &rn->p, &attr, safi);
		      output_count++;
		    }
		  else
		    filtered_count++;
		}
	    }
      }
    else
      {
	adj = bgp_adj_peer_lookup(peer, rn);
	if (adj)
	  {
	    if (header1)
	      {
		vty_out (vty, "BGP table version is %llu, local router ID "
			 "is %s%s", table->version,
			 inet_ntoa (bgp->router_id), VTY_NEWLINE);
		vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
		vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
		header1 = 0;
	      }
	    if (header2)
	      {
		vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
		header2 = 0;
	      }
	    if (adj->attr)
	      {
		if (!CHECK_FLAG(peer->af_flags[afi][safi],
				PEER_FLAG_REFLECTOR_CLIENT)
		    || bgp_flag_check(bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
		  {
		    bgp_attr_dup(&attr, adj->attr);
		    ret = bgp_output_modifier(peer, &rn->p, &attr, afi,
					      safi, rmap_name);
		  }
		else
		  ret = RMAP_PERMIT;

		if (ret != RMAP_DENY)
		  {
		    route_vty_out_tmp (vty, &rn->p, &attr, safi);
		    output_count++;
		  }
		else
		  filtered_count++;
	      }
	  }
      }

  if (output_count != 0)
    vty_out (vty, "%sTotal number of prefixes %ld%s",
	     VTY_NEWLINE, output_count, VTY_NEWLINE);
}

static int
peer_adj_routes (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
		 int in, char *rmap_name)
{    
  if (! peer || ! peer->afc[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (in && ! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
    {
      vty_out (vty, "%% Inbound soft reconfiguration not enabled%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!in && (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_REFLECTOR_CLIENT)
	      && !bgp_flag_check(peer->bgp, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY)))
    {
      vty_out (vty, "%% Cannot apply outgoing route-map on route-reflector clients%s",
	       VTY_NEWLINE);
      vty_out (vty, "%% Enable bgp route-reflector allow-outbound-policy flag%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  show_adj_route (vty, peer, afi, safi, in, rmap_name);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_view_neighbor_advertised_route,
       show_ip_bgp_view_neighbor_advertised_route_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer) 
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 0, NULL);
}

DEFUN (show_ip_bgp_neighbor_advertised_route,
       show_ip_bgp_neighbor_advertised_route_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")

{
  struct peer *peer;
  char *rmap_name = NULL;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (argc == 2)
    rmap_name = argv[1];

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 0, rmap_name);
}

ALIAS (show_ip_bgp_neighbor_advertised_route,
       show_ip_bgp_neighbor_advertised_route_rmap_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFUN (show_ip_bgp_ipv4_neighbor_advertised_route,
       show_ip_bgp_ipv4_neighbor_advertised_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;
  char *rmap_name = NULL;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (argc == 3)
    rmap_name = argv[2];

  if (strncmp (argv[0], "m", 1) == 0)
    return peer_adj_routes (vty, peer, AFI_IP, SAFI_MULTICAST, 0, rmap_name);

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 0, rmap_name);
}

ALIAS (show_ip_bgp_ipv4_neighbor_advertised_route,
       show_ip_bgp_ipv4_neighbor_advertised_route_rmap_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n"
       "Route-map to control what is displayed\n")

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_neighbor_advertised_route,
       show_bgp_view_neighbor_advertised_route_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 0, NULL);
}

ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_view_ipv6_neighbor_advertised_route_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFUN (show_bgp_neighbor_advertised_route,
       show_bgp_neighbor_advertised_route_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")

{
  struct peer *peer;
  char *rmap_name = NULL;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (argc == 2)
    rmap_name = argv[1];

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 0, rmap_name);
}

ALIAS (show_bgp_neighbor_advertised_route,
       show_bgp_neighbor_advertised_route_rmap_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes route-map WORD",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")

ALIAS (show_bgp_neighbor_advertised_route,
       show_bgp_ipv6_neighbor_advertised_route_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")

ALIAS (show_bgp_neighbor_advertised_route,
       show_bgp_ipv6_neighbor_advertised_route_rmap_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes route-map WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")

/* old command */
ALIAS (show_bgp_neighbor_advertised_route,
       ipv6_bgp_neighbor_advertised_route_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")
  
/* old command */
DEFUN (ipv6_mbgp_neighbor_advertised_route,
       ipv6_mbgp_neighbor_advertised_route_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X|WORD) advertised-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Neighbor on bgp configured interface\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;  

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_MULTICAST, 0, NULL);
}
#endif /* HAVE_IPV6 */

DEFUN (show_bgp_view_neighbor_received_routes,
       show_bgp_view_neighbor_received_routes_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 1, NULL);
}

DEFUN (show_ip_bgp_view_neighbor_received_routes,
       show_ip_bgp_view_neighbor_received_routes_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 1, NULL);
}

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_view_ipv6_neighbor_received_routes_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

DEFUN (show_ip_bgp_neighbor_received_routes,
       show_ip_bgp_neighbor_received_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

{
  struct peer *peer;
  char *rmap_name = NULL;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (argc == 2)
    rmap_name = argv[1];

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 1, rmap_name);
}

ALIAS (show_ip_bgp_neighbor_received_routes,
       show_ip_bgp_neighbor_received_routes_rmap_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) received-routes route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

DEFUN (show_ip_bgp_ipv4_neighbor_received_routes,
       show_ip_bgp_ipv4_neighbor_received_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;
  char *rmap_name = NULL;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (argc == 3)
    rmap_name = argv[2];

  if (strncmp (argv[0], "m", 1) == 0)
    return peer_adj_routes (vty, peer, AFI_IP, SAFI_MULTICAST, 1, rmap_name);

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 1, rmap_name);
}

ALIAS (show_ip_bgp_ipv4_neighbor_received_routes,
       show_ip_bgp_ipv4_neighbor_received_routes_rmap_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) received-routes route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

DEFUN (show_bgp_view_afi_safi_neighbor_adv_recd_routes,
       show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd,
#ifdef HAVE_IPV6
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) (advertised-routes|received-routes)",
#else
       "show bgp view WORD ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) (advertised-routes|received-routes)",
#endif
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
#ifdef HAVE_IPV6
       "Address family\n"
#endif
       "Address family modifier\n"
       "Address family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the advertised routes to neighbor\n"
       "Display the received routes from neighbor\n")
{
  int afi;
  int safi;
  int in;
  struct peer *peer;

#ifdef HAVE_IPV6
    peer = peer_lookup_in_view (vty, argv[0], argv[3]);
#else
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
#endif

  if (! peer)
    return CMD_WARNING;

#ifdef HAVE_IPV6
  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  in = (strncmp (argv[4], "r", 1) == 0) ? 1 : 0;
#else
  afi = AFI_IP;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  in = (strncmp (argv[3], "r", 1) == 0) ? 1 : 0;
#endif

  return peer_adj_routes (vty, peer, afi, safi, in, NULL);
}

DEFUN (show_ip_bgp_neighbor_received_prefix_filter,
       show_ip_bgp_neighbor_received_prefix_filter_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) received prefix-filter",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      peer = peer_lookup_by_conf_if (NULL, argv[0]);
      if (!peer)
        {
          vty_out (vty, "Malformed address or name: %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      peer = peer_lookup (NULL, &su);
      if (! peer)
        return CMD_WARNING;
    }

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv4 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP, name);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_neighbor_received_prefix_filter,
       show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) received prefix-filter",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;

  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      peer = peer_lookup_by_conf_if (NULL, argv[1]);
      if (!peer)
        {
          vty_out (vty, "Malformed address or name: %s%s", argv[1], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      peer = peer_lookup (NULL, &su);
      if (! peer)
        return CMD_WARNING;
    }

  if (strncmp (argv[0], "m", 1) == 0)
    {
      sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_MULTICAST);
      count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
      if (count)
	{
	  vty_out (vty, "Address family: IPv4 Multicast%s", VTY_NEWLINE);
	  prefix_bgp_show_prefix_list (vty, AFI_IP, name);
	}
    }
  else 
    {
      sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_UNICAST);
      count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
      if (count)
	{
	  vty_out (vty, "Address family: IPv4 Unicast%s", VTY_NEWLINE);
	  prefix_bgp_show_prefix_list (vty, AFI_IP, name);
	}
    }

  return CMD_SUCCESS;
}


#ifdef HAVE_IPV6
ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_neighbor_received_routes_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_ipv6_neighbor_received_routes_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_neighbor_received_routes_rmap_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) received-routes route-map WORD",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_ipv6_neighbor_received_routes_rmap_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) received-routes route-map WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

DEFUN (show_bgp_neighbor_received_prefix_filter,
       show_bgp_neighbor_received_prefix_filter_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) received prefix-filter",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      peer = peer_lookup_by_conf_if (NULL, argv[0]);
      if (!peer)
        {
          vty_out (vty, "Malformed address or name: %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      peer = peer_lookup (NULL, &su);
      if (! peer)
        return CMD_WARNING;
    }

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
    }

  return CMD_SUCCESS;
}

ALIAS (show_bgp_neighbor_received_prefix_filter,
       show_bgp_ipv6_neighbor_received_prefix_filter_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) received prefix-filter",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")

/* old command */
ALIAS (show_bgp_view_neighbor_received_routes,
       ipv6_bgp_neighbor_received_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_received_routes,
       ipv6_mbgp_neighbor_received_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X|WORD) received-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_MULTICAST, 1, NULL);
}

DEFUN (show_bgp_view_neighbor_received_prefix_filter,
       show_bgp_view_neighbor_received_prefix_filter_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X|WORD) received prefix-filter",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  struct bgp *bgp;
  int count, ret;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
  {  
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
  
  ret = str2sockunion (argv[1], &su);
  if (ret < 0)
    {
      peer = peer_lookup_by_conf_if (bgp, argv[1]);
      if (!peer)
        {
          vty_out (vty, "%% Malformed address or name: %s%s", argv[1], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      peer = peer_lookup (bgp, &su);
      if (! peer)
        return CMD_WARNING;
    }

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
    }

  return CMD_SUCCESS;
}

ALIAS (show_bgp_view_neighbor_received_prefix_filter,
       show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) received prefix-filter",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
#endif /* HAVE_IPV6 */

static int
bgp_show_neighbor_route (struct vty *vty, struct peer *peer, afi_t afi,
			 safi_t safi, enum bgp_show_type type)
{
  if (! peer || ! peer->afc[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, peer->bgp, afi, safi, type, &peer->su, 0);
}

DEFUN (show_ip_bgp_neighbor_routes,
       show_ip_bgp_neighbor_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
				  bgp_show_type_neighbor);
}

DEFUN (show_ip_bgp_neighbor_flap,
       show_ip_bgp_neighbor_flap_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
				  bgp_show_type_flap_neighbor);
}

DEFUN (show_ip_bgp_neighbor_damp,
       show_ip_bgp_neighbor_damp_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X|WORD) dampened-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
    
  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
				  bgp_show_type_damp_neighbor);
}

DEFUN (show_ip_bgp_ipv4_neighbor_routes,
       show_ip_bgp_ipv4_neighbor_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X|WORD) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;
 
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_MULTICAST,
				    bgp_show_type_neighbor);

  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
				  bgp_show_type_neighbor);
}

DEFUN (show_ip_bgp_view_rsclient,
       show_ip_bgp_view_rsclient_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3)
{
  struct bgp_table *table;
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP][SAFI_UNICAST];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal,
			 NULL, 0);
}

ALIAS (show_ip_bgp_view_rsclient,
       show_ip_bgp_rsclient_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3)

DEFUN (show_bgp_view_ipv4_safi_rsclient,
       show_bgp_view_ipv4_safi_rsclient_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3)
{
  struct bgp_table *table;
  struct peer *peer;
  safi_t safi;

  if (argc == 3) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP][safi];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal,
			 NULL, 0);
}

ALIAS (show_bgp_view_ipv4_safi_rsclient,
       show_bgp_ipv4_safi_rsclient_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3)

DEFUN (show_ip_bgp_view_rsclient_route,
       show_ip_bgp_view_rsclient_route_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X|WORD) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }
 
  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][SAFI_UNICAST], 
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, 0);
}

ALIAS (show_ip_bgp_view_rsclient_route,
       show_ip_bgp_rsclient_route_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X|WORD) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_ipv4_safi_rsclient_route,
       show_bgp_view_ipv4_safi_rsclient_route_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD) A.B.C.D",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP, safi, NULL, 0, BGP_PATH_ALL, 0);
}

ALIAS (show_bgp_view_ipv4_safi_rsclient_route,
       show_bgp_ipv4_safi_rsclient_route_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD) A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "Network in the BGP routing table to display\n")

DEFUN (show_ip_bgp_view_rsclient_prefix,
       show_ip_bgp_view_rsclient_prefix_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X|WORD) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
  peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;
    
  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
{
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }
    
  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][SAFI_UNICAST], 
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, 0);
}

ALIAS (show_ip_bgp_view_rsclient_prefix,
       show_ip_bgp_rsclient_prefix_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X|WORD) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_view_ipv4_safi_rsclient_prefix_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
{
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP, safi, NULL, 1, BGP_PATH_ALL, 0);
}

ALIAS (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_ipv4_safi_rsclient_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_neighbor_routes,
       show_bgp_view_neighbor_routes_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X|WORD) routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);
   
  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_neighbor);
}

ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_view_ipv6_neighbor_routes_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display routes learned from neighbor\n")

DEFUN (show_bgp_view_neighbor_damp,
       show_bgp_view_neighbor_damp_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X|WORD) dampened-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_damp_neighbor);
}

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_view_ipv6_neighbor_damp_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) dampened-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the dampened routes received from neighbor\n")

DEFUN (show_bgp_view_neighbor_flap,
       show_bgp_view_neighbor_flap_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X|WORD) flap-statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
				  bgp_show_type_flap_neighbor);
}

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_view_ipv6_neighbor_flap_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) flap-statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display flap statistics of the routes learned from neighbor\n")
       
ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_neighbor_routes_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display routes learned from neighbor\n")


ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_ipv6_neighbor_routes_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display routes learned from neighbor\n")

/* old command */
ALIAS (show_bgp_view_neighbor_routes,
       ipv6_bgp_neighbor_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X|WORD) routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display routes learned from neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_routes,
       ipv6_mbgp_neighbor_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X|WORD) routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;
 
  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_MULTICAST,
				  bgp_show_type_neighbor);
}

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_neighbor_flap_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) flap-statistics",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_ipv6_neighbor_flap_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) flap-statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_neighbor_damp_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X|WORD) dampened-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the dampened routes received from neighbor\n")

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_ipv6_neighbor_damp_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X|WORD) dampened-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on bgp configured interface\n"
       "Display the dampened routes received from neighbor\n")

DEFUN (show_bgp_view_rsclient,
       show_bgp_view_rsclient_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X|WORD)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3)
{
  struct bgp_table *table;
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP6][SAFI_UNICAST];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal,
			 NULL, 0);
}

ALIAS (show_bgp_view_rsclient,
       show_bgp_rsclient_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X|WORD)",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3)

DEFUN (show_bgp_view_ipv6_safi_rsclient,
       show_bgp_view_ipv6_safi_rsclient_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3)
{
  struct bgp_table *table;
  struct peer *peer;
  safi_t safi;

  if (argc == 3) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP6][safi];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal,
			 NULL, 0);
}

ALIAS (show_bgp_view_ipv6_safi_rsclient,
       show_bgp_ipv6_safi_rsclient_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3)

DEFUN (show_bgp_view_rsclient_route,
       show_bgp_view_rsclient_route_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X|WORD) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP6, SAFI_UNICAST, NULL, 0, BGP_PATH_ALL, 0);
}

ALIAS (show_bgp_view_rsclient_route,
       show_bgp_rsclient_route_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X|WORD) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_ipv6_safi_rsclient_route,
       show_bgp_view_ipv6_safi_rsclient_route_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "Network in the BGP routing table to display\n")
{
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP6, safi, NULL, 0, BGP_PATH_ALL, 0);
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_route,
       show_bgp_ipv6_safi_rsclient_route_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_rsclient_prefix,
       show_bgp_view_rsclient_prefix_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X|WORD) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP6, SAFI_UNICAST, NULL, 1, BGP_PATH_ALL, 0);
}

ALIAS (show_bgp_view_rsclient_prefix,
       show_bgp_rsclient_prefix_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X|WORD) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

DEFUN (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_view_ipv6_safi_rsclient_prefix_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
{
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP6, safi, NULL, 1, BGP_PATH_ALL, 0);
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_ipv6_safi_rsclient_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X|WORD) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR3
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")

#endif /* HAVE_IPV6 */

struct bgp_table *bgp_distance_table;

struct bgp_distance
{
  /* Distance value for the IP source prefix. */
  u_char distance;

  /* Name of the access-list to be matched. */
  char *access_list;
};

static struct bgp_distance *
bgp_distance_new (void)
{
  return XCALLOC (MTYPE_BGP_DISTANCE, sizeof (struct bgp_distance));
}

static void
bgp_distance_free (struct bgp_distance *bdistance)
{
  XFREE (MTYPE_BGP_DISTANCE, bdistance);
}

static int
bgp_distance_set (struct vty *vty, const char *distance_str, 
                  const char *ip_str, const char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  u_char distance;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  /* Get BGP distance node. */
  rn = bgp_node_get (bgp_distance_table, (struct prefix *) &p);
  if (rn->info)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);
    }
  else
    {
      bdistance = bgp_distance_new ();
      rn->info = bdistance;
    }

  /* Set distance value. */
  bdistance->distance = distance;

  /* Reset access-list configuration. */
  if (bdistance->access_list)
    {
      free (bdistance->access_list);
      bdistance->access_list = NULL;
    }
  if (access_list_str)
    bdistance->access_list = strdup (access_list_str);

  return CMD_SUCCESS;
}

static int
bgp_distance_unset (struct vty *vty, const char *distance_str, 
                    const char *ip_str, const char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  u_char distance;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  rn = bgp_node_lookup (bgp_distance_table, (struct prefix *)&p);
  if (! rn)
    {
      vty_out (vty, "Can't find specified prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bdistance = rn->info;

  if (bdistance->access_list)
    free (bdistance->access_list);
  bgp_distance_free (bdistance);

  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

/* Apply BGP information to distance method. */
u_char
bgp_distance_apply (struct prefix *p, struct bgp_info *rinfo, struct bgp *bgp)
{
  struct bgp_node *rn;
  struct prefix_ipv4 q;
  struct peer *peer;
  struct bgp_distance *bdistance;
  struct access_list *alist;
  struct bgp_static *bgp_static;

  if (! bgp)
    return 0;

  if (p->family != AF_INET)
    return 0;

  peer = rinfo->peer;

  if (peer->su.sa.sa_family != AF_INET)
    return 0;

  memset (&q, 0, sizeof (struct prefix_ipv4));
  q.family = AF_INET;
  q.prefix = peer->su.sin.sin_addr;
  q.prefixlen = IPV4_MAX_BITLEN;

  /* Check source address. */
  rn = bgp_node_match (bgp_distance_table, (struct prefix *) &q);
  if (rn)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);

      if (bdistance->access_list)
	{
	  alist = access_list_lookup (AFI_IP, bdistance->access_list);
	  if (alist && access_list_apply (alist, p) == FILTER_PERMIT)
	    return bdistance->distance;
	}
      else
	return bdistance->distance;
    }

  /* Backdoor check. */
  rn = bgp_node_lookup (bgp->route[AFI_IP][SAFI_UNICAST], p);
  if (rn)
    {
      bgp_static = rn->info;
      bgp_unlock_node (rn);

      if (bgp_static->backdoor)
	{
	  if (bgp->distance_local)
	    return bgp->distance_local;
	  else
	    return ZEBRA_IBGP_DISTANCE_DEFAULT;
	}
    }

  if (peer->sort == BGP_PEER_EBGP)
    {
      if (bgp->distance_ebgp)
	return bgp->distance_ebgp;
      return ZEBRA_EBGP_DISTANCE_DEFAULT;
    }
  else
    {
      if (bgp->distance_ibgp)
	return bgp->distance_ibgp;
      return ZEBRA_IBGP_DISTANCE_DEFAULT;
    }
}

DEFUN (bgp_distance,
       bgp_distance_cmd,
       "distance bgp <1-255> <1-255> <1-255>",
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->distance_ebgp = atoi (argv[0]);
  bgp->distance_ibgp = atoi (argv[1]);
  bgp->distance_local = atoi (argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance,
       no_bgp_distance_cmd,
       "no distance bgp <1-255> <1-255> <1-255>",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->distance_ebgp= 0;
  bgp->distance_ibgp = 0;
  bgp->distance_local = 0;
  return CMD_SUCCESS;
}

ALIAS (no_bgp_distance,
       no_bgp_distance2_cmd,
       "no distance bgp",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n")

DEFUN (bgp_distance_source,
       bgp_distance_source_cmd,
       "distance <1-255> A.B.C.D/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_set (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source,
       no_bgp_distance_source_cmd,
       "no distance <1-255> A.B.C.D/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (bgp_distance_source_access_list,
       bgp_distance_source_access_list_cmd,
       "distance <1-255> A.B.C.D/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_set (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source_access_list,
       no_bgp_distance_source_access_list_cmd,
       "no distance <1-255> A.B.C.D/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

DEFUN (bgp_damp_set,
       bgp_damp_set_cmd,
       "bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
  struct bgp *bgp;
  int half = DEFAULT_HALF_LIFE * 60;
  int reuse = DEFAULT_REUSE;
  int suppress = DEFAULT_SUPPRESS;
  int max = 4 * half;

  if (argc == 4)
    {
      half = atoi (argv[0]) * 60;
      reuse = atoi (argv[1]);
      suppress = atoi (argv[2]);
      max = atoi (argv[3]) * 60;
    }
  else if (argc == 1)
    {
      half = atoi (argv[0]) * 60;
      max = 4 * half;
    }

  bgp = vty->index;
  return bgp_damp_enable (bgp, bgp_node_afi (vty), bgp_node_safi (vty),
			  half, reuse, suppress, max);
}

ALIAS (bgp_damp_set,
       bgp_damp_set2_cmd,
       "bgp dampening <1-45>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n")

ALIAS (bgp_damp_set,
       bgp_damp_set3_cmd,
       "bgp dampening",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")

DEFUN (bgp_damp_unset,
       bgp_damp_unset_cmd,
       "no bgp dampening",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  return bgp_damp_disable (bgp, bgp_node_afi (vty), bgp_node_safi (vty));
}

ALIAS (bgp_damp_unset,
       bgp_damp_unset2_cmd,
       "no bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")

DEFUN (show_ip_bgp_dampened_paths,
       show_ip_bgp_dampened_paths_cmd,
       "show ip bgp dampened-paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display paths suppressed due to dampening\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_dampend_paths,
                   NULL, 0);
}

DEFUN (show_ip_bgp_flap_statistics,
       show_ip_bgp_flap_statistics_cmd,
       "show ip bgp flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
                   bgp_show_type_flap_statistics, NULL, 0);
}

/* Display specified route of BGP table. */
static int
bgp_clear_damp_route (struct vty *vty, const char *view_name, 
                      const char *ip_str, afi_t afi, safi_t safi, 
                      struct prefix_rd *prd, int prefix_check)
{
  int ret;
  struct prefix match;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_info *ri_temp;
  struct bgp *bgp;
  struct bgp_table *table;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
	{
	  vty_out (vty, "%% Can't find BGP view %s%s", view_name, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "%% No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "%% address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = afi2family (afi);

  if (safi == SAFI_MPLS_VPN)
    {
      for (rn = bgp_table_top (bgp->rib[AFI_IP][SAFI_MPLS_VPN]); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

	  if ((table = rn->info) != NULL)
	    if ((rm = bgp_node_match (table, &match)) != NULL)
              {
                if (! prefix_check || rm->p.prefixlen == match.prefixlen)
                  {
                    ri = rm->info;
                    while (ri)
                      {
                        if (ri->extra && ri->extra->damp_info)
                          {
                            ri_temp = ri->next;
                            bgp_damp_info_free (ri->extra->damp_info, 1);
                            ri = ri_temp;
                          }
                        else
                          ri = ri->next;
                      }
                  }

                bgp_unlock_node (rm);
              }
        }
    }
  else
    {
      if ((rn = bgp_node_match (bgp->rib[afi][safi], &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              ri = rn->info;
              while (ri)
                {
                  if (ri->extra && ri->extra->damp_info)
                    {
                      ri_temp = ri->next;
                      bgp_damp_info_free (ri->extra->damp_info, 1);
                      ri = ri_temp;
                    }
                  else
                    ri = ri->next;
                }
            }

          bgp_unlock_node (rn);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening,
       clear_ip_bgp_dampening_cmd,
       "clear ip bgp dampening",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n")
{
  bgp_damp_info_clean ();
  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening_prefix,
       clear_ip_bgp_dampening_prefix_cmd,
       "clear ip bgp dampening A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_clear_damp_route (vty, NULL, argv[0], AFI_IP,
			       SAFI_UNICAST, NULL, 1);
}

DEFUN (clear_ip_bgp_dampening_address,
       clear_ip_bgp_dampening_address_cmd,
       "clear ip bgp dampening A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n")
{
  return bgp_clear_damp_route (vty, NULL, argv[0], AFI_IP,
			       SAFI_UNICAST, NULL, 0);
}

DEFUN (clear_ip_bgp_dampening_address_mask,
       clear_ip_bgp_dampening_address_mask_cmd,
       "clear ip bgp dampening A.B.C.D A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_clear_damp_route (vty, NULL, prefix_str, AFI_IP,
			       SAFI_UNICAST, NULL, 0);
}

static int
bgp_config_write_network_vpnv4 (struct vty *vty, struct bgp *bgp,
				afi_t afi, safi_t safi, int *write)
{
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct prefix *p;
  struct prefix_rd *prd;
  struct bgp_static *bgp_static;
  u_int32_t label;
  char buf[SU_ADDRSTRLEN];
  char rdbuf[RD_ADDRSTRLEN];
  
  /* Network configuration. */
  for (prn = bgp_table_top (bgp->route[afi][safi]); prn; prn = bgp_route_next (prn))
    if ((table = prn->info) != NULL)
      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn)) 
	if ((bgp_static = rn->info) != NULL)
	  {
	    p = &rn->p;
	    prd = (struct prefix_rd *) &prn->p;

	    /* "address-family" display.  */
	    bgp_config_write_family_header (vty, afi, safi, write);

	    /* "network" configuration display.  */
	    prefix_rd2str (prd, rdbuf, RD_ADDRSTRLEN);
	    label = decode_label (bgp_static->tag);

	    vty_out (vty, " network %s/%d rd %s tag %d",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN), 
		     p->prefixlen,
		     rdbuf, label);
	    vty_out (vty, "%s", VTY_NEWLINE);
	  }
  return 0;
}

/* Configuration of static route announcement and aggregate
   information. */
int
bgp_config_write_network (struct vty *vty, struct bgp *bgp,
			  afi_t afi, safi_t safi, int *write)
{
  struct bgp_node *rn;
  struct prefix *p;
  struct bgp_static *bgp_static;
  struct bgp_aggregate *bgp_aggregate;
  char buf[SU_ADDRSTRLEN];
  
  if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
    return bgp_config_write_network_vpnv4 (vty, bgp, afi, safi, write);

  /* Network configuration. */
  for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn)) 
    if ((bgp_static = rn->info) != NULL)
      {
	p = &rn->p;

	/* "address-family" display.  */
	bgp_config_write_family_header (vty, afi, safi, write);

	/* "network" configuration display.  */
	if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && afi == AFI_IP)
	  {
	    u_int32_t destination; 
	    struct in_addr netmask;

	    destination = ntohl (p->u.prefix4.s_addr);
	    masklen2ip (p->prefixlen, &netmask);
	    vty_out (vty, " network %s",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN));

	    if ((IN_CLASSC (destination) && p->prefixlen == 24)
		|| (IN_CLASSB (destination) && p->prefixlen == 16)
		|| (IN_CLASSA (destination) && p->prefixlen == 8)
		|| p->u.prefix4.s_addr == 0)
	      {
		/* Natural mask is not display. */
	      }
	    else
	      vty_out (vty, " mask %s", inet_ntoa (netmask));
	  }
	else
	  {
	    vty_out (vty, " network %s/%d",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN), 
		     p->prefixlen);
	  }

	if (bgp_static->rmap.name)
	  vty_out (vty, " route-map %s", bgp_static->rmap.name);
	else 
	  {
	    if (bgp_static->backdoor)
	      vty_out (vty, " backdoor");
          }

	vty_out (vty, "%s", VTY_NEWLINE);
      }

  /* Aggregate-address configuration. */
  for (rn = bgp_table_top (bgp->aggregate[afi][safi]); rn; rn = bgp_route_next (rn))
    if ((bgp_aggregate = rn->info) != NULL)
      {
	p = &rn->p;

	/* "address-family" display.  */
	bgp_config_write_family_header (vty, afi, safi, write);

	if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && afi == AFI_IP)
	  {
	    struct in_addr netmask;

	    masklen2ip (p->prefixlen, &netmask);
	    vty_out (vty, " aggregate-address %s %s",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		     inet_ntoa (netmask));
	  }
	else
	  {
	    vty_out (vty, " aggregate-address %s/%d",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		     p->prefixlen);
	  }

	if (bgp_aggregate->as_set)
	  vty_out (vty, " as-set");
	
	if (bgp_aggregate->summary_only)
	  vty_out (vty, " summary-only");

	vty_out (vty, "%s", VTY_NEWLINE);
      }

  return 0;
}

int
bgp_config_write_distance (struct vty *vty, struct bgp *bgp)
{
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  /* Distance configuration. */
  if (bgp->distance_ebgp
      && bgp->distance_ibgp
      && bgp->distance_local
      && (bgp->distance_ebgp != ZEBRA_EBGP_DISTANCE_DEFAULT
	  || bgp->distance_ibgp != ZEBRA_IBGP_DISTANCE_DEFAULT
	  || bgp->distance_local != ZEBRA_IBGP_DISTANCE_DEFAULT))
    vty_out (vty, " distance bgp %d %d %d%s",
	     bgp->distance_ebgp, bgp->distance_ibgp, bgp->distance_local,
	     VTY_NEWLINE);
  
  for (rn = bgp_table_top (bgp_distance_table); rn; rn = bgp_route_next (rn))
    if ((bdistance = rn->info) != NULL)
      {
	vty_out (vty, " distance %d %s/%d %s%s", bdistance->distance,
		 inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
		 bdistance->access_list ? bdistance->access_list : "",
		 VTY_NEWLINE);
      }

  return 0;
}

/* Allocate routing table structure and install commands. */
void
bgp_route_init (void)
{
  /* Init BGP distance table. */
  bgp_distance_table = bgp_table_init (AFI_IP, SAFI_UNICAST);

  /* IPv4 BGP commands. */
  install_element (BGP_NODE, &bgp_table_map_cmd);
  install_element (BGP_NODE, &bgp_network_cmd);
  install_element (BGP_NODE, &bgp_network_mask_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_cmd);
  install_element (BGP_NODE, &bgp_network_route_map_cmd);
  install_element (BGP_NODE, &bgp_network_mask_route_map_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_NODE, &bgp_network_backdoor_cmd);
  install_element (BGP_NODE, &bgp_network_mask_backdoor_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_backdoor_cmd);
  install_element (BGP_NODE, &no_bgp_table_map_cmd);
  install_element (BGP_NODE, &no_bgp_network_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_cmd);
  install_element (BGP_NODE, &no_bgp_network_route_map_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_route_map_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_NODE, &no_bgp_network_backdoor_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_backdoor_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_backdoor_cmd);

  install_element (BGP_NODE, &aggregate_address_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_NODE, &aggregate_address_summary_only_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_summary_only_cmd);
  install_element (BGP_NODE, &aggregate_address_as_set_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_as_set_cmd);
  install_element (BGP_NODE, &aggregate_address_as_set_summary_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_NODE, &aggregate_address_summary_as_set_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_summary_as_set_cmd);
  install_element (BGP_NODE, &no_aggregate_address_cmd);
  install_element (BGP_NODE, &no_aggregate_address_summary_only_cmd);
  install_element (BGP_NODE, &no_aggregate_address_as_set_cmd);
  install_element (BGP_NODE, &no_aggregate_address_as_set_summary_cmd);
  install_element (BGP_NODE, &no_aggregate_address_summary_as_set_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_summary_only_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_as_set_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_summary_as_set_cmd);

  /* IPv4 unicast configuration.  */
  install_element (BGP_IPV4_NODE, &bgp_table_map_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_natural_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_route_map_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_route_map_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_table_map_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_natural_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_route_map_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_route_map_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_natural_route_map_cmd);
  
  install_element (BGP_IPV4_NODE, &aggregate_address_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_summary_only_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_summary_only_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_as_set_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_as_set_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_as_set_summary_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_summary_as_set_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_summary_as_set_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_summary_only_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_as_set_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_as_set_summary_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_summary_as_set_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_summary_only_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_as_set_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_summary_as_set_cmd);

  /* IPv4 multicast configuration.  */
  install_element (BGP_IPV4M_NODE, &bgp_table_map_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_natural_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_table_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_natural_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_natural_route_map_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_summary_only_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_summary_only_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_as_set_summary_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_summary_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_summary_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_summary_only_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_as_set_summary_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_summary_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_summary_only_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_as_set_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_as_set_summary_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_summary_as_set_cmd);

  install_element (VIEW_NODE, &show_ip_bgp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_rd_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_map_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_route_map_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_cidr_only_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_cidr_only_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community2_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community3_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community2_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community3_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community_all_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_community4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_advertised_route_rmap_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_advertised_route_rmap_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_received_routes_rmap_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_received_routes_rmap_cmd);
  install_element (VIEW_NODE, &show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_dampened_paths_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_statistics_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_address_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_cidr_only_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_flap_route_map_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_rsclient_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv4_safi_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv4_safi_rsclient_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv4_safi_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv4_safi_rsclient_prefix_cmd);
  
  /* Restricted node: VIEW_NODE - (set of dangerous commands) */
  install_element (RESTRICTED_NODE, &show_ip_bgp_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_view_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_view_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community2_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community3_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community4_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community2_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community3_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community_all_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_afi_safi_community4_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_ipv4_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_view_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv4_safi_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_ip_bgp_view_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv4_safi_rsclient_prefix_cmd);

  install_element (ENABLE_NODE, &show_ip_bgp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_route_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_route_pathtype_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_prefix_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_prefix_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_prefix_pathtype_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_rd_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_regexp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_route_map_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_route_map_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_cidr_only_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_cidr_only_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_all_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_all_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community2_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community3_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community4_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community2_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community3_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community4_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_afi_safi_community_all_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_afi_safi_community_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_afi_safi_community2_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_afi_safi_community3_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_afi_safi_community4_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_list_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_list_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_advertised_route_rmap_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbor_advertised_route_rmap_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_received_routes_rmap_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbor_received_routes_rmap_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_received_prefix_filter_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_dampened_paths_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_statistics_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_address_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_cidr_only_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_regexp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_flap_route_map_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_flap_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_damp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_rsclient_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_rsclient_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_rsclient_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_rsclient_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_rsclient_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv4_safi_rsclient_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_rsclient_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv4_safi_rsclient_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_rsclient_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv4_safi_rsclient_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_rsclient_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv4_safi_rsclient_prefix_cmd);

 /* BGP dampening clear commands */
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_prefix_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_address_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_address_mask_cmd);

  /* prefix count */
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_prefix_counts_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbor_prefix_counts_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd);
#ifdef HAVE_IPV6
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbor_prefix_counts_cmd);

  /* New config IPv6 BGP commands.  */
  install_element (BGP_IPV6_NODE, &bgp_table_map_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_network_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_network_route_map_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_table_map_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_network_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_network_route_map_cmd);

  install_element (BGP_IPV6_NODE, &ipv6_aggregate_address_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_aggregate_address_summary_only_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_aggregate_address_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_aggregate_address_summary_only_cmd);

  install_element (BGP_IPV6M_NODE, &ipv6_bgp_network_cmd);
  install_element (BGP_IPV6M_NODE, &no_ipv6_bgp_network_cmd);

  /* Old config IPv6 BGP commands.  */
  install_element (BGP_NODE, &old_ipv6_bgp_network_cmd);
  install_element (BGP_NODE, &old_no_ipv6_bgp_network_cmd);

  install_element (BGP_NODE, &old_ipv6_aggregate_address_cmd);
  install_element (BGP_NODE, &old_ipv6_aggregate_address_summary_only_cmd);
  install_element (BGP_NODE, &old_no_ipv6_aggregate_address_cmd);
  install_element (BGP_NODE, &old_no_ipv6_aggregate_address_summary_only_cmd);

  install_element (VIEW_NODE, &show_bgp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_cmd);
  install_element (VIEW_NODE, &show_bgp_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_route_cmd);
  install_element (VIEW_NODE, &show_bgp_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_route_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_prefix_pathtype_cmd);
  install_element (VIEW_NODE, &show_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_regexp_cmd);
  install_element (VIEW_NODE, &show_bgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_prefix_list_cmd);
  install_element (VIEW_NODE, &show_bgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_filter_list_cmd);
  install_element (VIEW_NODE, &show_bgp_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_route_map_cmd);
  install_element (VIEW_NODE, &show_bgp_community_all_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community_all_cmd);
  install_element (VIEW_NODE, &show_bgp_community_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community_cmd);
  install_element (VIEW_NODE, &show_bgp_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community2_cmd);
  install_element (VIEW_NODE, &show_bgp_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community3_cmd);
  install_element (VIEW_NODE, &show_bgp_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community4_cmd);
  install_element (VIEW_NODE, &show_bgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community2_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community3_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community4_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_community_list_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community_list_cmd);
  install_element (VIEW_NODE, &show_bgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_bgp_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_bgp_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_ipv6_safi_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_cmd);
  install_element (VIEW_NODE, &show_bgp_view_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_flap_cmd);
  install_element (VIEW_NODE, &show_bgp_view_neighbor_damp_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_neighbor_damp_cmd); 
  install_element (VIEW_NODE, &show_bgp_view_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_safi_rsclient_cmd);
  install_element (VIEW_NODE, &show_bgp_view_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_safi_rsclient_route_cmd);
  install_element (VIEW_NODE, &show_bgp_view_rsclient_prefix_cmd);
  install_element (VIEW_NODE, &show_bgp_view_ipv6_safi_rsclient_prefix_cmd);
  
  /* Restricted:
   * VIEW_NODE - (set of dangerous commands) - (commands dependent on prev) 
   */
  install_element (RESTRICTED_NODE, &show_bgp_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_route_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_prefix_pathtype_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community2_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community3_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community4_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community2_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community3_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_community4_exact_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_neighbor_received_prefix_filter_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_safi_rsclient_route_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_rsclient_prefix_cmd);
  install_element (RESTRICTED_NODE, &show_bgp_view_ipv6_safi_rsclient_prefix_cmd);

  install_element (ENABLE_NODE, &show_bgp_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_cmd);
  install_element (ENABLE_NODE, &show_bgp_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_route_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_route_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_route_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_prefix_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_prefix_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_prefix_pathtype_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_regexp_cmd);
  install_element (ENABLE_NODE, &show_bgp_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_bgp_filter_list_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_filter_list_cmd);
  install_element (ENABLE_NODE, &show_bgp_route_map_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_route_map_cmd);
  install_element (ENABLE_NODE, &show_bgp_community_all_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community_all_cmd);
  install_element (ENABLE_NODE, &show_bgp_community_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community_cmd);
  install_element (ENABLE_NODE, &show_bgp_community2_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community2_cmd);
  install_element (ENABLE_NODE, &show_bgp_community3_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community3_cmd);
  install_element (ENABLE_NODE, &show_bgp_community4_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community4_cmd);
  install_element (ENABLE_NODE, &show_bgp_community_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_community_list_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community_list_cmd);
  install_element (ENABLE_NODE, &show_bgp_community_list_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_community_list_exact_cmd);
  install_element (ENABLE_NODE, &show_bgp_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_bgp_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &show_bgp_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &show_bgp_neighbor_received_prefix_filter_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbor_received_prefix_filter_cmd);
  install_element (ENABLE_NODE, &show_bgp_neighbor_flap_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbor_flap_cmd);
  install_element (ENABLE_NODE, &show_bgp_neighbor_damp_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbor_damp_cmd);
  install_element (ENABLE_NODE, &show_bgp_rsclient_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_rsclient_cmd);
  install_element (ENABLE_NODE, &show_bgp_rsclient_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_rsclient_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_rsclient_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_ipv6_safi_rsclient_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_neighbor_received_prefix_filter_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_neighbor_flap_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_neighbor_flap_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_neighbor_damp_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_neighbor_damp_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_rsclient_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_safi_rsclient_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_rsclient_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_safi_rsclient_route_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_rsclient_prefix_cmd);
  install_element (ENABLE_NODE, &show_bgp_view_ipv6_safi_rsclient_prefix_cmd);
  
  /* Statistics */
  install_element (ENABLE_NODE, &show_bgp_statistics_cmd);
  install_element (ENABLE_NODE, &show_bgp_statistics_vpnv4_cmd);
  install_element (ENABLE_NODE, &show_bgp_statistics_view_cmd);
  install_element (ENABLE_NODE, &show_bgp_statistics_view_vpnv4_cmd);
  
  /* old command */
  install_element (VIEW_NODE, &show_ipv6_bgp_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community2_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community3_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community4_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community2_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community3_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community4_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_longer_cmd);
  
  /* old command */
  install_element (ENABLE_NODE, &show_ipv6_bgp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_all_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community2_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community3_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community4_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_list_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_all_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community2_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community3_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community4_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_list_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_prefix_longer_cmd);

  /* old command */
  install_element (VIEW_NODE, &ipv6_bgp_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &ipv6_bgp_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_advertised_route_cmd);

  /* old command */
  install_element (VIEW_NODE, &ipv6_bgp_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &ipv6_bgp_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_received_routes_cmd);

  /* old command */
  install_element (VIEW_NODE, &ipv6_bgp_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &ipv6_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_routes_cmd);
#endif /* HAVE_IPV6 */

  install_element (BGP_NODE, &bgp_distance_cmd);
  install_element (BGP_NODE, &no_bgp_distance_cmd);
  install_element (BGP_NODE, &no_bgp_distance2_cmd);
  install_element (BGP_NODE, &bgp_distance_source_cmd);
  install_element (BGP_NODE, &no_bgp_distance_source_cmd);
  install_element (BGP_NODE, &bgp_distance_source_access_list_cmd);
  install_element (BGP_NODE, &no_bgp_distance_source_access_list_cmd);

  install_element (BGP_NODE, &bgp_damp_set_cmd);
  install_element (BGP_NODE, &bgp_damp_set2_cmd);
  install_element (BGP_NODE, &bgp_damp_set3_cmd);
  install_element (BGP_NODE, &bgp_damp_unset_cmd);
  install_element (BGP_NODE, &bgp_damp_unset2_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_set_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_set2_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_set3_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_unset_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_unset2_cmd);
  
  /* Deprecated AS-Pathlimit commands */
  install_element (BGP_NODE, &bgp_network_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_mask_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_backdoor_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_NODE, &bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_NODE, &no_bgp_network_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_backdoor_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_NODE, &no_bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_IPV4_NODE, &bgp_network_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_backdoor_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_IPV4_NODE, &bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_IPV4_NODE, &no_bgp_network_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_backdoor_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_IPV4M_NODE, &bgp_network_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_backdoor_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_network_mask_natural_backdoor_ttl_cmd);
  
  install_element (BGP_IPV4M_NODE, &no_bgp_network_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_natural_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_backdoor_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_backdoor_ttl_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_network_mask_natural_backdoor_ttl_cmd);

#ifdef HAVE_IPV6
  install_element (BGP_IPV6_NODE, &ipv6_bgp_network_ttl_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_network_ttl_cmd);
#endif
}

void
bgp_route_finish (void)
{
  bgp_table_unlock (bgp_distance_table);
  bgp_distance_table = NULL;
}
