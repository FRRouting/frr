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

#include "prefix.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "log.h"
#include "routemap.h"
#include "buffer.h"
#include "sockunion.h"
#include "plist.h"
#include "thread.h"
#include "workqueue.h"
#include "queue.h"
#include "memory.h"
#include "lib/json.h"

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

#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#endif

/* Extern from bgp_dump.c */
extern const char *bgp_origin_str[];
extern const char *bgp_origin_long_str[];

struct bgp_node *
bgp_afi_node_get (struct bgp_table *table, afi_t afi, safi_t safi, struct prefix *p,
		  struct prefix_rd *prd)
{
  struct bgp_node *rn;
  struct bgp_node *prn = NULL;
  
  assert (table);
  if (!table)
    return NULL;
  
  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
    {
      prn = bgp_node_get (table, (struct prefix *) prd);

      if (prn->info == NULL)
	prn->info = bgp_table_init (afi, safi);
      else
	bgp_unlock_node (prn);
      table = prn->info;
    }

  rn = bgp_node_get (table, p);

  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
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

/* Allocate new bgp info structure. */
struct bgp_info *
bgp_info_new (void)
{
  return XCALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_info));
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
void
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

  if (ri->peer == ri->peer->bgp->peer_self)
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

void
bgp_info_path_with_addpath_rx_str (struct bgp_info *ri, char *buf)
{
  if (ri->addpath_rx_id)
    sprintf(buf, "path %s (addpath rxid %d)", ri->peer->host, ri->addpath_rx_id);
  else
    sprintf(buf, "path %s", ri->peer->host);
}

/* Compare two bgp route entity.  If 'new' is preferable over 'exist' return 1. */
static int
bgp_info_cmp (struct bgp *bgp, struct bgp_info *new, struct bgp_info *exist,
	      int *paths_eq, struct bgp_maxpaths_cfg *mpath_cfg, int debug,
              const char *pfx_buf)
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
  char new_buf[PATH_ADDPATH_STR_BUFFER];
  char exist_buf[PATH_ADDPATH_STR_BUFFER];

  *paths_eq = 0;

  /* 0. Null check. */
  if (new == NULL)
    {
      if (debug)
        zlog_debug("%s: new is NULL", pfx_buf);
      return 0;
    }

  if (debug)
    bgp_info_path_with_addpath_rx_str (new, new_buf);

  if (exist == NULL)
    {
      if (debug)
        zlog_debug("%s: %s is the initial bestpath", pfx_buf, new_buf);
      return 1;
    }

  if (debug)
    {
      bgp_info_path_with_addpath_rx_str (exist, exist_buf);
      zlog_debug("%s: Comparing %s flags 0x%x with %s flags 0x%x",
                 pfx_buf, new_buf, new->flags, exist_buf, exist->flags);
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
        zlog_debug("%s: %s wins over %s due to weight %d > %d",
                   pfx_buf, new_buf, exist_buf, new_weight, exist_weight);
      return 1;
    }

  if (new_weight < exist_weight)
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to weight %d < %d",
                   pfx_buf, new_buf, exist_buf, new_weight, exist_weight);
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
        zlog_debug("%s: %s wins over %s due to localpref %d > %d",
                   pfx_buf, new_buf, exist_buf, new_pref, exist_pref);
      return 1;
    }

  if (new_pref < exist_pref)
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to localpref %d < %d",
                   pfx_buf, new_buf, exist_buf, new_pref, exist_pref);
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
        zlog_debug("%s: %s wins over %s due to preferred BGP_ROUTE type",
                   pfx_buf, new_buf, exist_buf);
      return 1;
    }

  if (! (exist->sub_type == BGP_ROUTE_NORMAL))
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to preferred BGP_ROUTE type",
                   pfx_buf, new_buf, exist_buf);
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
                zlog_debug("%s: %s wins over %s due to aspath (with confeds) hopcount %d < %d",
                           pfx_buf, new_buf, exist_buf,
                           aspath_hops, (exist_hops + exist_confeds));
	      return 1;
            }

	  if ( aspath_hops > (exist_hops + exist_confeds))
            {
              if (debug)
                zlog_debug("%s: %s loses to %s due to aspath (with confeds) hopcount %d > %d",
                           pfx_buf, new_buf, exist_buf,
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
                zlog_debug("%s: %s wins over %s due to aspath hopcount %d < %d",
                           pfx_buf, new_buf, exist_buf, newhops, exist_hops);
	      return 1;
            }

          if (newhops > exist_hops)
            {
              if (debug)
                zlog_debug("%s: %s loses to %s due to aspath hopcount %d > %d",
                           pfx_buf, new_buf, exist_buf, newhops, exist_hops);
	      return 0;
            }
	}
    }

  /* 5. Origin check. */
  if (newattr->origin < existattr->origin)
    {
      if (debug)
        zlog_debug("%s: %s wins over %s due to ORIGIN %s < %s",
                   pfx_buf, new_buf, exist_buf,
                   bgp_origin_long_str[newattr->origin],
                   bgp_origin_long_str[existattr->origin]);
      return 1;
    }

  if (newattr->origin > existattr->origin)
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to ORIGIN %s > %s",
                   pfx_buf, new_buf, exist_buf,
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
            zlog_debug("%s: %s wins over %s due to MED %d < %d",
                       pfx_buf, new_buf, exist_buf, new_med, exist_med);
	  return 1;
        }

      if (new_med > exist_med)
        {
          if (debug)
            zlog_debug("%s: %s loses to %s due to MED %d > %d",
                       pfx_buf, new_buf, exist_buf, new_med, exist_med);
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
        zlog_debug("%s: %s wins over %s due to eBGP peer > iBGP peer",
                   pfx_buf, new_buf, exist_buf);
      return 1;
    }

  if (exist_sort == BGP_PEER_EBGP
      && (new_sort == BGP_PEER_IBGP || new_sort == BGP_PEER_CONFED))
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to iBGP peer < eBGP peer",
                   pfx_buf, new_buf, exist_buf);
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
        zlog_debug("%s: %s wins over %s due to IGP metric %d < %d",
                   pfx_buf, new_buf, exist_buf, newm, existm);
      ret = 1;
    }

  if (newm > existm)
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to IGP metric %d > %d",
                   pfx_buf, new_buf, exist_buf, newm, existm);
      ret = 0;
    }

  /* 9. Same IGP metric. Compare the cluster list length as
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
                zlog_debug("%s: %s wins over %s due to CLUSTER_LIST length %d < %d",
                           pfx_buf, new_buf, exist_buf, newm, existm);
	      ret = 1;
            }

	  if (newm > existm)
            {
              if (debug)
                zlog_debug("%s: %s loses to %s due to CLUSTER_LIST length %d > %d",
                           pfx_buf, new_buf, exist_buf, newm, existm);
	      ret = 0;
            }
	}
    }

  /* 10. confed-external vs. confed-internal */
  if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
    {
      if (new_sort == BGP_PEER_CONFED && exist_sort == BGP_PEER_IBGP)
        {
          if (debug)
            zlog_debug("%s: %s wins over %s due to confed-external peer > confed-internal peer",
                       pfx_buf, new_buf, exist_buf);
          return 1;
        }

      if (exist_sort == BGP_PEER_CONFED && new_sort == BGP_PEER_IBGP)
        {
          if (debug)
            zlog_debug("%s: %s loses to %s due to confed-internal peer < confed-external peer",
                       pfx_buf, new_buf, exist_buf);
          return 0;
        }
    }

  /* 11. Maximum path check. */
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
            zlog_debug("%s: %s and %s are equal via multipath-relax",
                       pfx_buf, new_buf, exist_buf);
        }
      else if (new->peer->sort == BGP_PEER_IBGP)
	{
	  if (aspath_cmp (new->attr->aspath, exist->attr->aspath))
            {
	      *paths_eq = 1;

              if (debug)
                zlog_debug("%s: %s and %s are equal via matching aspaths",
                           pfx_buf, new_buf, exist_buf);
            }
	}
      else if (new->peer->as == exist->peer->as)
        {
	  *paths_eq = 1;

          if (debug)
            zlog_debug("%s: %s and %s are equal via same remote-as",
                       pfx_buf, new_buf, exist_buf);
        }
    }
  else
    {
      /*
       * TODO: If unequal cost ibgp multipath is enabled we can
       * mark the paths as equal here instead of returning
       */
      if (debug)
        {
          if (ret == 1)
            zlog_debug("%s: %s wins over %s after IGP metric comparison",
                       pfx_buf, new_buf, exist_buf);
          else
            zlog_debug("%s: %s loses to %s after IGP metric comparison",
                       pfx_buf, new_buf, exist_buf);
        }
      return ret;
    }

  /* 12. If both paths are external, prefer the path that was received
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
              zlog_debug("%s: %s wins over %s due to oldest external",
                         pfx_buf, new_buf, exist_buf);
	  return 1;
        }

      if (CHECK_FLAG (exist->flags, BGP_INFO_SELECTED))
        {
          if (debug)
              zlog_debug("%s: %s loses to %s due to oldest external",
                         pfx_buf, new_buf, exist_buf);
	  return 0;
        }
    }

  /* 13. Router-ID comparision. */
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
        zlog_debug("%s: %s wins over %s due to Router-ID comparison",
                   pfx_buf, new_buf, exist_buf);
      return 1;
    }

  if (ntohl (new_id.s_addr) > ntohl (exist_id.s_addr))
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to Router-ID comparison",
                   pfx_buf, new_buf, exist_buf);
      return 0;
    }

  /* 14. Cluster length comparision. */
  new_cluster = BGP_CLUSTER_LIST_LENGTH(new->attr);
  exist_cluster = BGP_CLUSTER_LIST_LENGTH(exist->attr);

  if (new_cluster < exist_cluster)
    {
      if (debug)
        zlog_debug("%s: %s wins over %s due to CLUSTER_LIST length %d < %d",
                   pfx_buf, new_buf, exist_buf, new_cluster, exist_cluster);
      return 1;
    }

  if (new_cluster > exist_cluster)
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to CLUSTER_LIST length %d > %d",
                   pfx_buf, new_buf, exist_buf, new_cluster, exist_cluster);
      return 0;
    }

  /* 15. Neighbor address comparision. */
  /* Do this only if neither path is "stale" as stale paths do not have
   * valid peer information (as the connection may or may not be up).
   */
  if (CHECK_FLAG (exist->flags, BGP_INFO_STALE))
    {
      if (debug)
        zlog_debug("%s: %s wins over %s due to latter path being STALE",
                   pfx_buf, new_buf, exist_buf);
      return 1;
    }

  if (CHECK_FLAG (new->flags, BGP_INFO_STALE))
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to former path being STALE",
                   pfx_buf, new_buf, exist_buf);
      return 0;
    }

  /* locally configured routes to advertise do not have su_remote */
  if (new->peer->su_remote == NULL)
    return 0;
  if (exist->peer->su_remote == NULL)
    return 1;
  
  ret = sockunion_cmp (new->peer->su_remote, exist->peer->su_remote);

  if (ret == 1)
    {
      if (debug)
        zlog_debug("%s: %s loses to %s due to Neighor IP comparison",
                   pfx_buf, new_buf, exist_buf);
      return 0;
    }

  if (ret == -1)
    {
      if (debug)
        zlog_debug("%s: %s wins over %s due to Neighor IP comparison",
                   pfx_buf, new_buf, exist_buf);
      return 1;
    }

  if (debug)
    zlog_debug("%s: %s wins over %s due to nothing left to compare",
               pfx_buf, new_buf, exist_buf);

  return 1;
}

/* Compare two bgp route entity.  Return -1 if new is preferred, 1 if exist
 * is preferred, or 0 if they are the same (usually will only occur if
 * multipath is enabled 
 * This version is compatible with */
int
bgp_info_cmp_compatible (struct bgp *bgp, struct bgp_info *new, struct bgp_info *exist,
                         afi_t afi, safi_t safi)
{
  int paths_eq;
  struct bgp_maxpaths_cfg mpath_cfg;
  int ret;
  ret = bgp_info_cmp (bgp, new, exist, &paths_eq, &mpath_cfg, 0, __func__);

  if (paths_eq)
    ret = 0;
  else 
    {
      if (ret == 1)
        ret = -1;
      else 
        ret = 1;
    }
  return ret;
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
		    afi_t afi, safi_t safi, const char *rmap_name)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;
  struct route_map *rmap = NULL;

  filter = &peer->filter[afi][safi];

  /* Apply default weight value. */
  if (peer->weight[afi][safi])
    (bgp_attr_extra_get (attr))->weight = peer->weight[afi][safi];

  if (rmap_name)
    {
      rmap = route_map_lookup_by_name(rmap_name);

      if (rmap == NULL)
	    return RMAP_DENY;
    }
  else
    {
      if (ROUTE_MAP_IN_NAME(filter))
        {
          rmap = ROUTE_MAP_IN (filter);

          if (rmap == NULL)
	        return RMAP_DENY;
        }
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
		     afi_t afi, safi_t safi, const char *rmap_name)
{
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;
  struct route_map *rmap = NULL;

  filter = &peer->filter[afi][safi];

  /* Apply default weight value. */
  if (peer->weight[afi][safi])
    (bgp_attr_extra_get (attr))->weight = peer->weight[afi][safi];

  if (rmap_name)
    {
      rmap = route_map_lookup_by_name(rmap_name);

      if (rmap == NULL)
	    return RMAP_DENY;
    }
  else
    {
      if (ROUTE_MAP_OUT_NAME(filter))
        {
          rmap = ROUTE_MAP_OUT (filter);

          if (rmap == NULL)
	        return RMAP_DENY;
        }
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

/* If this is an EBGP peer with remove-private-AS */
static void
bgp_peer_remove_private_as(struct bgp *bgp, afi_t afi, safi_t safi,
                           struct peer *peer, struct attr *attr)
{
  if (peer->sort == BGP_PEER_EBGP &&
      (peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE) ||
       peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE) ||
       peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_ALL) ||
       peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS)))
    {
      // Take action on the entire aspath
      if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE) ||
          peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
        {
          if (peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
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
  int samepeer_safe = 0;	/* for synthetic mplsvpns routes */

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

#if ENABLE_BGP_VNC
  if (((afi == AFI_IP) || (afi == AFI_IP6)) && (safi == SAFI_MPLS_VPN) &&
      ((ri->type == ZEBRA_ROUTE_BGP_DIRECT) ||
       (ri->type == ZEBRA_ROUTE_BGP_DIRECT_EXT))) {

    /*
     * direct and direct_ext type routes originate internally even
     * though they can have peer pointers that reference other systems
     */
    char    buf[BUFSIZ];
    prefix2str(p, buf, BUFSIZ);
    zlog_debug("%s: pfx %s bgp_direct->vpn route peer safe", __func__, buf);
    samepeer_safe = 1;
  }
#endif

  /* With addpath we may be asked to TX all kinds of paths so make sure
   * ri is valid */
  if (!CHECK_FLAG (ri->flags, BGP_INFO_VALID) ||
      CHECK_FLAG (ri->flags, BGP_INFO_HISTORY) ||
      CHECK_FLAG (ri->flags, BGP_INFO_REMOVED))
    {
      return 0;
    }

  /* If this is not the bestpath then check to see if there is an enabled addpath
   * feature that requires us to advertise it */
  if (! CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
    {
      if (! bgp_addpath_tx_path(peer, afi, safi, ri))
        {
          return 0;
        }
    }

  /* Aggregate-address suppress check. */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      {
	return 0;
      }

  /* Do not send back route to sender. */
  if (onlypeer && from == onlypeer)
    {
      return 0;
    }

  /* Do not send the default route in the BGP table if the neighbor is
   * configured for default-originate */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_DEFAULT_ORIGINATE))
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
            if (bgp_debug_update(NULL, p, subgrp->update_group, 0))
              zlog_debug ("%s [Update:SEND] %s/%d is filtered via ORF",
                          peer->host,
                          inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                          p->prefixlen);
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
  if (reflect && !samepeer_safe)
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
      if (from != bgp->peer_self && ! transparent
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
#define NEXTHOP_IS_V6 (\
    (safi != SAFI_ENCAP && \
     (p->family == AF_INET6 || peer_cap_enhe(peer))) || \
    (safi == SAFI_ENCAP && attr->extra->mp_nexthop_len == 16))

  /* IPv6/MP starts with 1 nexthop. The link-local address is passed only if
   * the peer (group) is configured to receive link-local nexthop unchanged
   * and it is available in the prefix OR we're not reflecting the route and
   * the peer (group) to whom we're going to announce is on a shared network
   * and this is either a self-originated route or the peer is EBGP.
   */
  if (NEXTHOP_IS_V6)
    {
      attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
      if ((CHECK_FLAG (peer->af_flags[afi][safi],
                       PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED) &&
           IN6_IS_ADDR_LINKLOCAL (&attr->extra->mp_nexthop_local)) ||
          (!reflect && peer->shared_network &&
           (from == bgp->peer_self || peer->sort == BGP_PEER_EBGP)))
        {
          attr->extra->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
        }

      /* Clear off link-local nexthop in source, whenever it is not needed to
       * ensure more prefixes share the same attribute for announcement.
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
  /*
   * If route-map has performed some operation on the nexthop or the peer
   * configuration says to pass it unchanged, we cannot reset the nexthop
   * here, so only attempt to do it if these aren't true. Note that the
   * route-map handler itself might have cleared the nexthop, if for example,
   * it is configured as 'peer-address'.
   */
  if (!bgp_rmap_nhop_changed(attr->rmap_change_flags,
                             riattr->rmap_change_flags) &&
      !transparent &&
      !CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_UNCHANGED))
    {
      /* We can reset the nexthop, if setting (or forcing) it to 'self' */
      if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF) ||
          CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_FORCE_NEXTHOP_SELF))
        {
          if (!reflect ||
              CHECK_FLAG (peer->af_flags[afi][safi],
                          PEER_FLAG_FORCE_NEXTHOP_SELF))
            subgroup_announce_reset_nhop ((peer_cap_enhe(peer) ?
                          AF_INET6 : p->family), attr);
        }
      else if (peer->sort == BGP_PEER_EBGP)
        {
          /* Can also reset the nexthop if announcing to EBGP, but only if
           * no peer in the subgroup is on a shared subnet.
           * Note: 3rd party nexthop currently implemented for IPv4 only.
           */
          SUBGRP_FOREACH_PEER (subgrp, paf)
            {
              if (bgp_multiaccess_check_v4 (riattr->nexthop, paf->peer))
                break;
            }
          if (!paf)
            subgroup_announce_reset_nhop ((peer_cap_enhe(peer) ? AF_INET6 : p->family), attr);
        }
      /* If IPv6/MP and nexthop does not have any override and happens to
       * be a link-local address, reset it so that we don't pass along the
       * source's link-local IPv6 address to recipients who may not be on
       * the same interface.
       */
      if (p->family == AF_INET6 || peer_cap_enhe(peer))
        {
          if (IN6_IS_ADDR_LINKLOCAL (&attr->extra->mp_nexthop_global))
            subgroup_announce_reset_nhop (AF_INET6, attr);
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
  char pfx_buf[PREFIX2STR_BUFFER];
  char path_buf[PATH_ADDPATH_STR_BUFFER];

  bgp_mp_list_init (&mp_list);
  do_mpath = (mpath_cfg->maxpaths_ebgp > 1 || mpath_cfg->maxpaths_ibgp > 1);

  debug = bgp_debug_bestpath(&rn->p);

  if (debug)
    prefix2str (&rn->p, pfx_buf, sizeof (pfx_buf));

  /* bgp deterministic-med */
  new_select = NULL;
  if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED))
    {

      /* Clear BGP_INFO_DMED_SELECTED for all paths */
      for (ri1 = rn->info; ri1; ri1 = ri1->next)
        bgp_info_unset_flag (rn, ri1, BGP_INFO_DMED_SELECTED);

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
          if (ri1->next)
            {
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
                      if (bgp_info_cmp (bgp, ri2, new_select, &paths_eq,
                                        mpath_cfg, debug, pfx_buf))
                        {
                          bgp_info_unset_flag (rn, new_select, BGP_INFO_DMED_SELECTED);
                          new_select = ri2;
                        }

                      bgp_info_set_flag (rn, ri2, BGP_INFO_DMED_CHECK);
                    }
                }
            }
          bgp_info_set_flag (rn, new_select, BGP_INFO_DMED_CHECK);
          bgp_info_set_flag (rn, new_select, BGP_INFO_DMED_SELECTED);

          if (debug)
            {
              bgp_info_path_with_addpath_rx_str (new_select, path_buf);
              zlog_debug("%s: %s is the bestpath from AS %d",
                         pfx_buf, path_buf, aspath_get_first_as(new_select->attr->aspath));
            }
        }
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

      if (bgp_info_cmp (bgp, ri, new_select, &paths_eq, mpath_cfg, debug, pfx_buf))
	{
	  new_select = ri;
	}
    }
    
  /* Now that we know which path is the bestpath see if any of the other paths
   * qualify as multipaths
   */
  if (debug)
    {
      if (new_select)
        bgp_info_path_with_addpath_rx_str (new_select, path_buf);
      else
        sprintf (path_buf, "NONE");
      zlog_debug("%s: After path selection, newbest is %s oldbest was %s",
                 pfx_buf, path_buf,
                 old_select ? old_select->peer->host : "NONE");
    }

  if (do_mpath && new_select)
    {
      for (ri = rn->info; (ri != NULL) && (nextri = ri->next, 1); ri = nextri)
        {

          if (debug)
            bgp_info_path_with_addpath_rx_str (ri, path_buf);

          if (ri == new_select)
            {
              if (debug)
                zlog_debug("%s: %s is the bestpath, add to the multipath list",
                           pfx_buf, path_buf);
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

          if (!bgp_info_nexthop_cmp (ri, new_select))
            {
              if (debug)
                zlog_debug("%s: %s has the same nexthop as the bestpath, skip it",
                           pfx_buf, path_buf);
              continue;
            }

          bgp_info_cmp (bgp, ri, new_select, &paths_eq, mpath_cfg, debug, pfx_buf);

          if (paths_eq)
            {
              if (debug)
                zlog_debug("%s: %s is equivalent to the bestpath, add to the multipath list",
                           pfx_buf, path_buf);
	      bgp_mp_list_add (&mp_list, ri);
            }
        }
    }

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
				    struct bgp_node *rn,
                                    u_int32_t addpath_tx_id)
{
  struct prefix *p;
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

  /* It's initialized in bgp_announce_check() */
  attr.extra = &extra;

  /* Announcement to the subgroup.  If the route is filtered withdraw it. */
  if (selected)
    {
      if (subgroup_announce_check(selected, subgrp, p, &attr))
        bgp_adj_out_set_subgroup(rn, subgrp, &attr, selected);
      else
        bgp_adj_out_unset_subgroup(rn, subgrp, 1, selected->addpath_tx_id);
    }

  /* If selected is NULL we must withdraw the path using addpath_tx_id */
  else
    {
      bgp_adj_out_unset_subgroup(rn, subgrp, 1, addpath_tx_id);
    }

  return 0;
}

/*
 * Clear IGP changed flag and attribute changed flag for a route (all paths).
 * This is called at the end of route processing.
 */
static void
bgp_zebra_clear_route_change_flags (struct bgp_node *rn)
{
  struct bgp_info *ri;

  for (ri = rn->info; ri; ri = ri->next)
    {
	if (BGP_INFO_HOLDDOWN (ri))
          continue;
        UNSET_FLAG (ri->flags, BGP_INFO_IGP_CHANGED);
        UNSET_FLAG (ri->flags, BGP_INFO_ATTR_CHANGED);
    }
}

/*
 * Has the route changed from the RIB's perspective? This is invoked only
 * if the route selection returns the same best route as earlier - to
 * determine if we need to update zebra or not.
 */
static int
bgp_zebra_has_route_changed (struct bgp_node *rn, struct bgp_info *selected)
{
  struct bgp_info *mpinfo;

  /* If this is multipath, check all selected paths for any nexthop change or
   * attribute change. Some attribute changes (e.g., community) aren't of
   * relevance to the RIB, but we'll update zebra to ensure we handle the
   * case of BGP nexthop change. This is the behavior when the best path has
   * an attribute change anyway.
   */
  if (CHECK_FLAG (selected->flags, BGP_INFO_IGP_CHANGED) ||
      CHECK_FLAG (selected->flags, BGP_INFO_MULTIPATH_CHG))
    return 1;

  /* If this is multipath, check all selected paths for any nexthop change */
  for (mpinfo = bgp_info_mpath_first (selected); mpinfo;
       mpinfo = bgp_info_mpath_next (mpinfo))
    {
      if (CHECK_FLAG (mpinfo->flags, BGP_INFO_IGP_CHANGED)
          || CHECK_FLAG (mpinfo->flags, BGP_INFO_ATTR_CHANGED))
        return 1;
    }

  /* Nothing has changed from the RIB's perspective. */
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
  if (old_select && old_select == new_select &&
      !CHECK_FLAG(rn->flags, BGP_NODE_USER_CLEAR) &&
      !CHECK_FLAG(old_select->flags, BGP_INFO_ATTR_CHANGED) &&
      !bgp->addpath_tx_used[afi][safi])
    {
      if (bgp_zebra_has_route_changed (rn, old_select))
        {
#if ENABLE_BGP_VNC
              vnc_import_bgp_add_route(bgp, p, old_select);
              vnc_import_bgp_exterior_add_route(bgp, p, old_select);
#endif
        bgp_zebra_announce (p, old_select, bgp, afi, safi);
        }
      UNSET_FLAG (old_select->flags, BGP_INFO_MULTIPATH_CHG);
      bgp_zebra_clear_route_change_flags (rn);
      UNSET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
      return WQ_SUCCESS;
    }

  /* If the user did "clear ip bgp prefix x.x.x.x" this flag will be set */
  UNSET_FLAG(rn->flags, BGP_NODE_USER_CLEAR);

  /* bestpath has changed; bump version */
  if (old_select || new_select)
    {
      bgp_bump_version(rn);

      if (!bgp->t_rmap_def_originate_eval)
        {
          bgp_lock (bgp);
          THREAD_TIMER_ON(bm->master, bgp->t_rmap_def_originate_eval,
                          update_group_refresh_default_originate_route_map,
                          bgp, RMAP_DEFAULT_ORIGINATE_EVAL_TIMER);
        }
    }

  if (old_select)
    bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
  if (new_select)
    {
      bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
      bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
      UNSET_FLAG (new_select->flags, BGP_INFO_MULTIPATH_CHG);
    }

#if ENABLE_BGP_VNC
  if ((afi == AFI_IP || afi == AFI_IP6) && (safi == SAFI_UNICAST)) {
    if (old_select != new_select) {
      if (old_select) {
        vnc_import_bgp_exterior_del_route(bgp, p, old_select);
        vnc_import_bgp_del_route(bgp, p, old_select);
      }
      if (new_select) {
        vnc_import_bgp_exterior_add_route(bgp, p, new_select);
        vnc_import_bgp_add_route(bgp, p, new_select);
      }
    }
  }
#endif

  group_announce_route(bgp, afi, safi, rn, new_select);

  /* FIB update. */
  if ((safi == SAFI_UNICAST || safi == SAFI_MULTICAST) &&
      (bgp->inst_type != BGP_INSTANCE_TYPE_VIEW) &&
      !bgp_option_check (BGP_OPT_NO_FIB))
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

  /* Clear any route change flags. */
  bgp_zebra_clear_route_change_flags (rn);

  /* Reap old select bgp_info, if it has been removed */
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
  if (!bm->process_main_queue)
    {
      bm->process_main_queue
	= work_queue_new (bm->master, "process_main_queue");

      if ( !bm->process_main_queue)
        {
          zlog_err ("%s: Failed to allocate work queue", __func__);
          exit (1);
        }
    }
  
  bm->process_main_queue->spec.workfunc = &bgp_process_main;
  bm->process_main_queue->spec.del_item_data = &bgp_processq_del;
  bm->process_main_queue->spec.max_retries = 0;
  bm->process_main_queue->spec.hold = 50;
  /* Use a higher yield value of 50ms for main queue processing */
  bm->process_main_queue->spec.yield = 50 * 1000L;
}

void
bgp_process (struct bgp *bgp, struct bgp_node *rn, afi_t afi, safi_t safi)
{
  struct bgp_process_queue *pqnode;
  
  /* already scheduled for processing? */
  if (CHECK_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED))
    return;

  if (bm->process_main_queue == NULL)
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
  work_queue_add (bm->process_main_queue, pqnode);
  SET_FLAG (rn->flags, BGP_NODE_PROCESS_SCHEDULED);
  return;
}

void
bgp_add_eoiu_mark (struct bgp *bgp)
{
  struct bgp_process_queue *pqnode;

  if (bm->process_main_queue == NULL)
    bgp_process_queue_init ();

  pqnode = XCALLOC (MTYPE_BGP_PROCESS_QUEUE,
                    sizeof (struct bgp_process_queue));
  if (!pqnode)
    return;

  pqnode->rn = NULL;
  pqnode->bgp = bgp;
  bgp_lock (bgp);
  work_queue_add (bm->process_main_queue, pqnode);
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
		  afi_t afi, safi_t safi, struct prefix_rd *prd)
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
    
#if ENABLE_BGP_VNC
    if (safi == SAFI_MPLS_VPN) {
	struct bgp_node		*prn = NULL;
	struct bgp_table	*table = NULL;

	prn = bgp_node_get(peer->bgp->rib[afi][safi], (struct prefix *) prd);
	if (prn->info) {
	    table = (struct bgp_table *)(prn->info);

	    vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
		peer->bgp,
		prd,
		table,
		&rn->p,
		ri);
	}
	bgp_unlock_node(prn);
    }
    if ((afi == AFI_IP || afi == AFI_IP6) && (safi == SAFI_UNICAST)) {
        if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)) {

	    vnc_import_bgp_del_route(peer->bgp, &rn->p, ri);
	    vnc_import_bgp_exterior_del_route(peer->bgp, &rn->p, ri);
	}
    }
#endif    
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
  new->addpath_tx_id = ++peer->bgp->addpath_tx_id;
  return new;
}

static void
bgp_info_addpath_rx_str(u_int32_t addpath_id, char *buf)
{
  if (addpath_id)
    sprintf(buf, " with addpath ID %d", addpath_id);
}


/* Check if received nexthop is valid or not. */
static int
bgp_update_martian_nexthop (struct bgp *bgp, afi_t afi, safi_t safi, struct attr *attr)
{
  struct attr_extra *attre = attr->extra;
  int ret = 0;

  /* Only validated for unicast and multicast currently. */
  if (safi != SAFI_UNICAST && safi != SAFI_MULTICAST)
    return 0;

  /* If NEXT_HOP is present, validate it. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP))
    {
      if (attr->nexthop.s_addr == 0 ||
          IPV4_CLASS_DE (ntohl (attr->nexthop.s_addr)) ||
          bgp_nexthop_self (bgp, attr))
        ret = 1;
    }

  /* If MP_NEXTHOP is present, validate it. */
  /* Note: For IPv6 nexthops, we only validate the global (1st) nexthop;
   * there is code in bgp_attr.c to ignore the link-local (2nd) nexthop if
   * it is not an IPv6 link-local address.
   */
  if (attre && attre->mp_nexthop_len)
    {
      switch (attre->mp_nexthop_len)
        {
        case BGP_ATTR_NHLEN_IPV4:
        case BGP_ATTR_NHLEN_VPNV4:
          ret = (attre->mp_nexthop_global_in.s_addr == 0 ||
                 IPV4_CLASS_DE (ntohl (attre->mp_nexthop_global_in.s_addr)));
          break;

#ifdef HAVE_IPV6
        case BGP_ATTR_NHLEN_IPV6_GLOBAL:
        case BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL:
          ret = (IN6_IS_ADDR_UNSPECIFIED(&attre->mp_nexthop_global) ||
                 IN6_IS_ADDR_LOOPBACK(&attre->mp_nexthop_global)    ||
                 IN6_IS_ADDR_MULTICAST(&attre->mp_nexthop_global));
          break;
#endif /* HAVE_IPV6 */

        default:
          ret = 1;
          break;
        }
    }

  return ret;
}

int
bgp_update (struct peer *peer, struct prefix *p, u_int32_t addpath_id,
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
  int do_loop_check = 1;
#if ENABLE_BGP_VNC
  int vnc_implicit_withdraw = 0;
#endif

  memset (&new_attr, 0, sizeof(struct attr));
  memset (&new_extra, 0, sizeof(struct attr_extra));

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

  /* If the peer is configured for "allowas-in origin" and the last ASN in the
   * as-path is our ASN then we do not need to call aspath_loop_check
   */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN_ORIGIN))
      if (aspath_get_last_as(attr->aspath) == bgp->as)
        do_loop_check = 0;

  /* AS path loop check. */
  if (do_loop_check)
    {
      if (aspath_loop_check (attr->aspath, bgp->as) > peer->allowas_in[afi][safi]
          || (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
              && aspath_loop_check(attr->aspath, bgp->confed_id) > peer->allowas_in[afi][safi]))
        {
          reason = "as-path contains our own AS;";
          goto filtered;
        }
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

  /* next hop check.  */
  if (bgp_update_martian_nexthop (bgp, afi, safi, &new_attr))
    {
       reason = "martian or self next-hop;";
       bgp_attr_flush (&new_attr);
       goto filtered;
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
                  bgp_info_addpath_rx_str(addpath_id, buf2);
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

                  bgp_info_addpath_rx_str(addpath_id, buf2);
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
              bgp_info_addpath_rx_str(addpath_id, buf2);
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
          bgp_info_addpath_rx_str(addpath_id, buf2);
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
#if ENABLE_BGP_VNC
    if (safi == SAFI_MPLS_VPN) {
	struct bgp_node		*prn = NULL;
	struct bgp_table	*table = NULL;

	prn = bgp_node_get(bgp->rib[afi][safi], (struct prefix *) prd);
	if (prn->info) {
	    table = (struct bgp_table *)(prn->info);

	    vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
		bgp,
		prd,
		table,
		p,
		ri);
	}
	bgp_unlock_node(prn);
    }
    if ((afi == AFI_IP || afi == AFI_IP6) && (safi == SAFI_UNICAST)) {
        if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)) {
	    /*
	     * Implicit withdraw case.
	     */
	    ++vnc_implicit_withdraw;
	    vnc_import_bgp_del_route(bgp, p, ri);
	    vnc_import_bgp_exterior_del_route(bgp, p, ri);
	}
    }
#endif
	
      /* Update to new attribute.  */
      bgp_attr_unintern (&ri->attr);
      ri->attr = attr_new;

      /* Update MPLS tag.  */
      if (safi == SAFI_MPLS_VPN)
        memcpy ((bgp_info_extra_get (ri))->tag, tag, 3);

#if ENABLE_BGP_VNC
      if ((afi == AFI_IP || afi == AFI_IP6) && (safi == SAFI_UNICAST)) 
        {
          if (vnc_implicit_withdraw) 
            {
              /*
               * Add back the route with its new attributes (e.g., nexthop).
               * The route is still selected, until the route selection
               * queued by bgp_process actually runs. We have to make this
               * update to the VNC side immediately to avoid racing against
               * configuration changes (e.g., route-map changes) which
               * trigger re-importation of the entire RIB.
               */
              vnc_import_bgp_add_route(bgp, p, ri);
              vnc_import_bgp_exterior_add_route(bgp, p, ri);
            }
        }
#endif

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

#if ENABLE_BGP_VNC
      if (safi == SAFI_MPLS_VPN) 
        {
          struct bgp_node		*prn = NULL;
          struct bgp_table	*table = NULL;

          prn = bgp_node_get(bgp->rib[afi][safi], (struct prefix *) prd);
          if (prn->info) 
            {
              table = (struct bgp_table *)(prn->info);

              vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
		bgp,
                    prd,
                    table,
                    p,
                    ri);
            }
          bgp_unlock_node(prn);
        }
#endif

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

      bgp_info_addpath_rx_str(addpath_id, buf2);
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

  /* Increment prefix */
  bgp_aggregate_increment (bgp, p, new, afi, safi);
  
  /* Register new BGP information. */
  bgp_info_add (rn, new);
  
  /* route_node_get lock */
  bgp_unlock_node (rn);

#if ENABLE_BGP_VNC
  if (safi == SAFI_MPLS_VPN) 
    {
      struct bgp_node		*prn = NULL;
      struct bgp_table	*table = NULL;
    
      prn = bgp_node_get(bgp->rib[afi][safi], (struct prefix *) prd);
      if (prn->info) 
        {
          table = (struct bgp_table *)(prn->info);
      
          vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
                             bgp,
                             prd,
                             table,
                             p,
                             new);
        }
      bgp_unlock_node(prn);
    }
#endif

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

      bgp_info_addpath_rx_str(addpath_id, buf2);
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
bgp_withdraw (struct peer *peer, struct prefix *p, u_int32_t addpath_id,
              struct attr *attr, afi_t afi, safi_t safi, int type, int sub_type,
	      struct prefix_rd *prd, u_char *tag)
{
  struct bgp *bgp;
  char buf[SU_ADDRSTRLEN];
  char buf2[30];
  struct bgp_node *rn;
  struct bgp_info *ri;

  bgp = peer->bgp;

  /* Lookup node. */
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* If peer is soft reconfiguration enabled.  Record input packet for
   * further calculation.
   *
   * Cisco IOS 12.4(24)T4 on session establishment sends withdraws for all
   * routes that are filtered.  This tanks out Quagga RS pretty badly due to
   * the iteration over all RS clients.
   * Since we need to remove the entry from adj_in anyway, do that first and
   * if there was no entry, we don't need to do anything more.
   */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG)
      && peer != bgp->peer_self)
    if (!bgp_adj_in_unset (rn, peer, addpath_id))
      {
        if (bgp_debug_update (peer, p, NULL, 1))
          zlog_debug ("%s withdrawing route %s/%d "
		      "not in adj-in", peer->host,
		      inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		      p->prefixlen);
        bgp_unlock_node (rn);
        return 0;
      }

  /* Lookup withdrawn route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type &&
        ri->addpath_rx_id == addpath_id)
      break;

  /* Logging. */
  if (bgp_debug_update(peer, p, NULL, 1))
    {
      bgp_info_addpath_rx_str(addpath_id, buf2);
      zlog_debug ("%s rcvd UPDATE about %s/%d%s -- withdrawn",
	        peer->host,
	        inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	        p->prefixlen, buf2);
    }

  /* Withdraw specified route from routing table. */
  if (ri && ! CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    bgp_rib_withdraw (rn, ri, peer, afi, safi, prd);
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
  THREAD_TIMER_MSEC_ON (bm->master, paf->t_announce_route,
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
  afi_t afi;
  safi_t safi;
  
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_announce_route (peer, afi, safi);
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

  if ((safi != SAFI_MPLS_VPN) && (safi != SAFI_ENCAP))
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
    if (ri->peer == peer)
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
                       struct bgp_table *table)
{
  struct bgp_node *rn;
  int force = bm->process_main_queue ? 0 : 1;
  
  if (! table)
    table = peer->bgp->rib[afi][safi];
  
  /* If still no table => afi/safi isn't configured at all or smth. */
  if (! table)
    return;
  
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      struct bgp_info *ri, *next;
      struct bgp_adj_in *ain;
      struct bgp_adj_in *ain_next;

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

          if (ain->peer == peer)
            {
              bgp_adj_in_remove (rn, ain);
              bgp_unlock_node (rn);
            }

          ain = ain_next;
        }

      for (ri = rn->info; ri; ri = next)
	{
	  next = ri->next;
	  if (ri->peer != peer)
	    continue;

	  if (force)
	    bgp_info_reap (rn, ri);
	  else
	    {
	      struct bgp_clear_node_queue *cnq;

	      /* both unlocked in bgp_clear_node_queue_del */
	      bgp_table_lock (bgp_node_table (rn));
	      bgp_lock_node (rn);
	      cnq = XCALLOC (MTYPE_BGP_CLEAR_NODE_QUEUE,
			     sizeof (struct bgp_clear_node_queue));
	      cnq->rn = rn;
	      work_queue_add (peer->clear_node_queue, cnq);
	      break;
	    }
	}
    }
  return;
}

void
bgp_clear_route (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_table *table;

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

  /* lock peer in assumption that clear-node-queue will get nodes; if so,
   * the unlock will happen upon work-queue completion; other wise, the
   * unlock happens at the end of this function.
   */
  if (!peer->clear_node_queue->thread)
    peer_lock (peer);

  if (safi != SAFI_MPLS_VPN && safi != SAFI_ENCAP)
    bgp_clear_route_table (peer, afi, safi, NULL);
  else
    for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
         rn = bgp_route_next (rn))
      if ((table = rn->info) != NULL)
        bgp_clear_route_table (peer, afi, safi, table);

  /* unlock if no nodes got added to the clear-node-queue. */
  if (!peer->clear_node_queue->thread)
    peer_unlock (peer);

}
  
void
bgp_clear_route_all (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_clear_route (peer, afi, safi);

#if ENABLE_BGP_VNC
  rfapiProcessPeerDown(peer);
#endif
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

static void
bgp_cleanup_table(struct bgp_table *table, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_info *next;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ri = rn->info; ri; ri = next)
      {
        next = ri->next;
        if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
            && ri->type == ZEBRA_ROUTE_BGP
            && (ri->sub_type == BGP_ROUTE_NORMAL ||
                ri->sub_type == BGP_ROUTE_AGGREGATE))
          {
#if ENABLE_BGP_VNC
            if (table->owner && table->owner->bgp)
              vnc_import_bgp_del_route(table->owner->bgp, &rn->p, ri);
#endif
            bgp_zebra_withdraw (&rn->p, ri, safi);
            bgp_info_reap (rn, ri);
          }
      }
}

/* Delete all kernel routes. */
void
bgp_cleanup_routes (struct bgp *bgp)
{
  afi_t afi;

  for (afi = AFI_IP; afi < AFI_MAX; ++afi)
    {
      struct bgp_node *rn;

      bgp_cleanup_table(bgp->rib[afi][SAFI_UNICAST], SAFI_UNICAST);

      /*
       * VPN and ENCAP tables are two-level (RD is top level)
       */
      for (rn = bgp_table_top(bgp->rib[afi][SAFI_MPLS_VPN]); rn;
	   rn = bgp_route_next (rn))
	{
	  if (rn->info)
	    {
	      bgp_cleanup_table((struct bgp_table *)(rn->info), SAFI_MPLS_VPN);
	      bgp_table_finish ((struct bgp_table **)&(rn->info));
	      rn->info = NULL;
	      bgp_unlock_node(rn);
	    }
	}

      for (rn = bgp_table_top(bgp->rib[afi][SAFI_ENCAP]); rn;
	   rn = bgp_route_next (rn))
	{
	  if (rn->info)
	    {
	      bgp_cleanup_table((struct bgp_table *)(rn->info), SAFI_ENCAP);
	      bgp_table_finish ((struct bgp_table **)&(rn->info));
	      rn->info = NULL;
	      bgp_unlock_node(rn);
	    }
	}
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

static int
bgp_addpath_encode_rx (struct peer *peer, afi_t afi, safi_t safi)
{
  return (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) &&
          CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV));
}

/* Parse NLRI stream.  Withdraw NLRI is recognized by NULL attr
   value. */
int
bgp_nlri_parse_ip (struct peer *peer, struct attr *attr,
                   struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  struct prefix p;
  int psize;
  int ret;
  afi_t afi;
  safi_t safi;
  int addpath_encoded;
  u_int32_t addpath_id;

  /* Check peer status. */
  if (peer->status != Established)
    return 0;
  
  pnt = packet->nlri;
  lim = pnt + packet->length;
  afi = packet->afi;
  safi = packet->safi;
  addpath_id = 0;
  addpath_encoded = bgp_addpath_encode_rx (peer, afi, safi);

  /* RFC4771 6.3 The NLRI field in the UPDATE message is checked for
     syntactic validity.  If the field is syntactically incorrect,
     then the Error Subcode is set to Invalid Network Field. */
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
      /* afi/safi validity already verified by caller, bgp_update_receive */
      p.family = afi2family (afi);

      /* Prefix length check. */
      if (p.prefixlen > prefix_blen (&p) * 8)
        {
          zlog_err("%s [Error] Update packet error (wrong perfix length %d for afi %u)",
                   peer->host, p.prefixlen, packet->afi);
          return -1;
        }

      /* Packet size overflow check. */
      psize = PSIZE (p.prefixlen);

      /* When packet overflow occur return immediately. */
      if (pnt + psize > lim)
        {
          zlog_err("%s [Error] Update packet error (prefix length %d overflows packet)",
                   peer->host, p.prefixlen);
          return -1;
        }

      /* Defensive coding, double-check the psize fits in a struct prefix */
      if (psize > (ssize_t) sizeof(p.u))
        {
          zlog_err("%s [Error] Update packet error (prefix length %d too large for prefix storage %zu)",
                   peer->host, p.prefixlen, sizeof(p.u));
          return -1;
        }

      /* Fetch prefix from NLRI packet. */
      memcpy (&p.u.prefix, pnt, psize);

      /* Check address. */
      if (afi == AFI_IP && safi == SAFI_UNICAST)
	{
	  if (IN_CLASSD (ntohl (p.u.prefix4.s_addr)))
	    {
	      /* From RFC4271 Section 6.3:
	       *
	       * If a prefix in the NLRI field is semantically incorrect
	       * (e.g., an unexpected multicast IP address), an error SHOULD
	       * be logged locally, and the prefix SHOULD be ignored.
	        */
	      zlog_err ("%s: IPv4 unicast NLRI is multicast address %s, ignoring",
	                peer->host, inet_ntoa (p.u.prefix4));
	      continue;
	    }
	}

#ifdef HAVE_IPV6
      /* Check address. */
      if (afi == AFI_IP6 && safi == SAFI_UNICAST)
	{
	  if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
	    {
	      char buf[BUFSIZ];

	      zlog_err ("%s: IPv6 unicast NLRI is link-local address %s, ignoring",
	                peer->host, inet_ntop (AF_INET6, &p.u.prefix6, buf, BUFSIZ));

	      continue;
	    }
	  if (IN6_IS_ADDR_MULTICAST (&p.u.prefix6))
	    {
	      char buf[BUFSIZ];

	      zlog_err ("%s: IPv6 unicast NLRI is multicast address %s, ignoring",
	                peer->host, inet_ntop (AF_INET6, &p.u.prefix6, buf, BUFSIZ));

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
    {
      zlog_err ("%s [Error] Update packet error (prefix length mismatch with total length)",
                peer->host);
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
    XFREE(MTYPE_ROUTE_MAP_NAME, bgp_static->rmap.name);
  XFREE (MTYPE_BGP_STATIC, bgp_static);
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
#if ENABLE_BGP_VNC
  int vnc_implicit_withdraw = 0;
#endif

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
	  !CHECK_FLAG(ri->flags, BGP_INFO_REMOVED) &&
	  !bgp_flag_check(bgp, BGP_FLAG_FORCE_STATIC_PROCESS))
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
#if ENABLE_BGP_VNC
          if ((afi == AFI_IP || afi == AFI_IP6) && (safi == SAFI_UNICAST)) 
            {
              if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)) 
                {
                  /*
                   * Implicit withdraw case.
                   * We have to do this before ri is changed
                   */
                  ++vnc_implicit_withdraw;
                  vnc_import_bgp_del_route(bgp, p, ri);
                  vnc_import_bgp_exterior_del_route(bgp, p, ri);
                }
            }
#endif
	  bgp_attr_unintern (&ri->attr);
	  ri->attr = attr_new;
	  ri->uptime = bgp_clock ();
#if ENABLE_BGP_VNC
          if ((afi == AFI_IP || afi == AFI_IP6) && (safi == SAFI_UNICAST)) 
            {
              if (vnc_implicit_withdraw) 
                {
                  vnc_import_bgp_add_route(bgp, p, ri);
                  vnc_import_bgp_exterior_add_route(bgp, p, ri);
                }
            }
#endif

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
		      inet_ntop(p->family, &p->u.prefix, buf1,
				INET6_ADDRSTRLEN);
		      zlog_debug("%s(%s): Route not in table, not advertising",
				 __FUNCTION__, buf1);
		    }
		  bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
		}
	    }
	  else
	    {
	      /* Delete the NHT structure if any, if we're toggling between
	       * enabling/disabling import check. We deregister the route
	       * from NHT to avoid overloading NHT and the process interaction
	       */
	      bgp_unlink_nexthop(ri);
	      bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
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
	      inet_ntop(p->family, &p->u.prefix, buf1,
			INET6_ADDRSTRLEN);
	      zlog_debug("%s(%s): Route not in table, not advertising",
			 __FUNCTION__, buf1);
	    }
	  bgp_info_unset_flag (rn, new, BGP_INFO_VALID);
	}
    }
  else
    {
      /* Delete the NHT structure if any, if we're toggling between
       * enabling/disabling import check. We deregister the route
       * from NHT to avoid overloading NHT and the process interaction
       */
      bgp_unlink_nexthop(new);

      bgp_info_set_flag (rn, new, BGP_INFO_VALID);
    }

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
  bgp_static_update_main (bgp, p, bgp_static, afi, safi);
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

/*
 * Used for SAFI_MPLS_VPN and SAFI_ENCAP
 */
static void
bgp_static_withdraw_safi (struct bgp *bgp, struct prefix *p, afi_t afi,
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
#if ENABLE_BGP_VNC
	rfapiProcessWithdraw(
	    ri->peer,
	    NULL,
	    p,
	    prd,
	    ri->attr,
	    afi,
	    safi,
	    ri->type,
	    1);		/* Kill, since it is an administrative change */
#endif
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

static void
bgp_static_update_safi (struct bgp *bgp, struct prefix *p,
                        struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *new;
  struct attr *attr_new;
  struct attr attr = { 0 };
  struct bgp_info *ri;
#if ENABLE_BGP_VNC
  u_int32_t        label = 0;
#endif

  assert (bgp_static);

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, &bgp_static->prd);

  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);

  attr.nexthop = bgp_static->igpnexthop;
  attr.med = bgp_static->igpmetric;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  /* Apply route-map. */
  if (bgp_static->rmap.name)
    {
      struct attr attr_tmp = attr;
      struct bgp_info info;
      int ret;

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
          bgp_static_withdraw_safi (bgp, p, afi, safi, &bgp_static->prd,
                                    bgp_static->tag);
          return;
        }

      attr_new = bgp_attr_intern (&attr_tmp);
    }
  else
    {
      attr_new = bgp_attr_intern (&attr);
    }

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
#if ENABLE_BGP_VNC
          if (ri->extra)
              label = decode_label (ri->extra->tag);
#endif

          /* Process change. */
          bgp_aggregate_increment (bgp, p, ri, afi, safi);
          bgp_process (bgp, rn, afi, safi);
#if ENABLE_BGP_VNC
          rfapiProcessUpdate(ri->peer, NULL, p, &bgp_static->prd,
                             ri->attr, afi, safi, 
                             ri->type, ri->sub_type, &label);
#endif
          bgp_unlock_node (rn);
          aspath_unintern (&attr.aspath);
          bgp_attr_extra_free (&attr);
          return;
        }
    }


  /* Make new BGP info. */
  new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, bgp->peer_self, attr_new,
		  rn);
  SET_FLAG (new->flags, BGP_INFO_VALID);
  new->extra = bgp_info_extra_new();
  memcpy (new->extra->tag, bgp_static->tag, 3);
#if ENABLE_BGP_VNC
  label = decode_label (bgp_static->tag);
#endif

  /* Aggregate address increment. */
  bgp_aggregate_increment (bgp, p, new, afi, safi);

  /* Register new BGP information. */
  bgp_info_add (rn, new);

  /* route_node_get lock */
  bgp_unlock_node (rn);

  /* Process change. */
  bgp_process (bgp, rn, afi, safi);

#if ENABLE_BGP_VNC
  rfapiProcessUpdate(new->peer, NULL, p, &bgp_static->prd,
                     new->attr, afi, safi, 
                     new->type, new->sub_type, &label);
#endif

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

/* Configure static BGP network.  When user don't run zebra, static
   route should be installed as valid.  */
static int
bgp_static_set (struct vty *vty, const char *ip_str, 
                afi_t afi, safi_t safi, const char *rmap, int backdoor)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
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
	    XFREE(MTYPE_ROUTE_MAP_NAME, bgp_static->rmap.name);
	  bgp_static->rmap.name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
	  bgp_static->rmap.map = route_map_lookup_by_name (rmap);
	}
      else
	{
	  if (bgp_static->rmap.name)
	    XFREE(MTYPE_ROUTE_MAP_NAME, bgp_static->rmap.name);
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
	    XFREE(MTYPE_ROUTE_MAP_NAME, bgp_static->rmap.name);
	  bgp_static->rmap.name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
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
bgp_static_unset (struct vty *vty, const char *ip_str,
		  afi_t afi, safi_t safi)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
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

void
bgp_static_add (struct bgp *bgp)
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
                    bgp_static_update_safi (bgp, &rm->p, bgp_static, afi, safi);
		  }
	      }
	    else
	      {
		bgp_static_update (bgp, &rn->p, rn->info, afi, safi);
	      }
	  }
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
	    if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
	      {
		table = rn->info;

		for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
		  {
		    bgp_static = rn->info;
		    bgp_static_withdraw_safi (bgp, &rm->p,
					       AFI_IP, safi,
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

void
bgp_static_redo_import_check (struct bgp *bgp)
{
  afi_t afi;
  safi_t safi;
  struct bgp_node *rn;
  struct bgp_static *bgp_static;

  /* Use this flag to force reprocessing of the route */
  bgp_flag_set(bgp, BGP_FLAG_FORCE_STATIC_PROCESS);
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn))
	if (rn->info != NULL)
	  {
	    bgp_static = rn->info;
	    bgp_static_update (bgp, &rn->p, bgp_static, afi, safi);
	  }
  bgp_flag_unset(bgp, BGP_FLAG_FORCE_STATIC_PROCESS);
}

static void
bgp_purge_af_static_redist_routes (struct bgp *bgp, afi_t afi, safi_t safi)
{
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_info *ri;

  table = bgp->rib[afi][safi];
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->next)
        {
          if (ri->peer == bgp->peer_self &&
              ((ri->type == ZEBRA_ROUTE_BGP &&
                ri->sub_type == BGP_ROUTE_STATIC) ||
               (ri->type != ZEBRA_ROUTE_BGP &&
                ri->sub_type == BGP_ROUTE_REDISTRIBUTE)))
            {
              bgp_aggregate_decrement (bgp, &rn->p, ri, afi, safi);
              bgp_unlink_nexthop(ri);
              bgp_info_delete (rn, ri);
              bgp_process (bgp, rn, afi, safi);
            }
        }
    }
}

/*
 * Purge all networks and redistributed routes from routing table.
 * Invoked upon the instance going down.
 */
void
bgp_purge_static_redist_routes (struct bgp *bgp)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_purge_af_static_redist_routes (bgp, afi, safi);
}

/*
 * gpz 110624
 * Currently this is used to set static routes for VPN and ENCAP.
 * I think it can probably be factored with bgp_static_set.
 */
int
bgp_static_set_safi (safi_t safi, struct vty *vty, const char *ip_str,
                     const char *rd_str, const char *tag_str,
                     const char *rmap_str)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  int ret;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  u_char tag[3];

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

  prn = bgp_node_get (bgp->route[AFI_IP][safi],
			(struct prefix *)&prd);
  if (prn->info == NULL)
    prn->info = bgp_table_init (AFI_IP, safi);
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
      bgp_static->backdoor = 0;
      bgp_static->valid = 0;
      bgp_static->igpmetric = 0;
      bgp_static->igpnexthop.s_addr = 0;
      memcpy(bgp_static->tag, tag, 3);
      bgp_static->prd = prd;

      if (rmap_str)
	{
	  if (bgp_static->rmap.name)
	    free (bgp_static->rmap.name);
	  bgp_static->rmap.name = strdup (rmap_str);
	  bgp_static->rmap.map = route_map_lookup_by_name (rmap_str);
	}
      rn->info = bgp_static;

      bgp_static->valid = 1;
      bgp_static_update_safi (bgp, &p, bgp_static, AFI_IP, safi);
    }

  return CMD_SUCCESS;
}

/* Configure static BGP network. */
int
bgp_static_unset_safi(safi_t safi, struct vty *vty, const char *ip_str,
                      const char *rd_str, const char *tag_str)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  int ret;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  u_char tag[3];

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

  prn = bgp_node_get (bgp->route[AFI_IP][safi],
			(struct prefix *)&prd);
  if (prn->info == NULL)
    prn->info = bgp_table_init (AFI_IP, safi);
  else
    bgp_unlock_node (prn);
  table = prn->info;

  rn = bgp_node_lookup (table, &p);

  if (rn)
    {
      bgp_static_withdraw_safi (bgp, &p, AFI_IP, safi, &prd, tag);

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
bgp_table_map_set (struct vty *vty, afi_t afi, safi_t safi,
                   const char *rmap_name)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  struct bgp_rmap *rmap;

  rmap = &bgp->table_map[afi][safi];
  if (rmap_name)
    {
      if (rmap->name)
        XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
      rmap->name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_name);
      rmap->map = route_map_lookup_by_name (rmap_name);
    }
  else
    {
      if (rmap->name)
        XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
      rmap->name = NULL;
      rmap->map = NULL;
    }

  bgp_zebra_announce_table(bgp, afi, safi);

  return CMD_SUCCESS;
}

static int
bgp_table_map_unset (struct vty *vty, afi_t afi, safi_t safi,
                     const char *rmap_name)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  struct bgp_rmap *rmap;

  rmap = &bgp->table_map[afi][safi];
  if (rmap->name)
    XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
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
      vty_out (vty, "  table-map %s%s",
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
  int idx_word = 1;
  return bgp_table_map_set (vty,
             bgp_node_afi (vty), bgp_node_safi (vty), argv[idx_word]->arg);
}
DEFUN (no_bgp_table_map,
       no_bgp_table_map_cmd,
       "no table-map WORD",
       NO_STR
       "BGP table to RIB route download filter\n"
       "Name of the route map\n")
{
  int idx_word = 2;
  return bgp_table_map_unset (vty,
             bgp_node_afi (vty), bgp_node_safi (vty), argv[idx_word]->arg);
}

DEFUN (bgp_network,
       bgp_network_cmd,
       "network A.B.C.D/M",
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n")
{
  int idx_ipv4_prefixlen = 1;
  return bgp_static_set (vty, argv[idx_ipv4_prefixlen]->arg,
			 AFI_IP, bgp_node_safi (vty), NULL, 0);
}

DEFUN (bgp_network_route_map,
       bgp_network_route_map_cmd,
       "network A.B.C.D/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int idx_ipv4_prefixlen = 1;
  int idx_word = 3;
  return bgp_static_set (vty, argv[idx_ipv4_prefixlen]->arg,
			 AFI_IP, bgp_node_safi (vty), argv[idx_word]->arg, 0);
}

DEFUN (bgp_network_backdoor,
       bgp_network_backdoor_cmd,
       "network A.B.C.D/M backdoor",
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify a BGP backdoor route\n")
{
  int idx_ipv4_prefixlen = 1;
  return bgp_static_set (vty, argv[idx_ipv4_prefixlen]->arg, AFI_IP, SAFI_UNICAST,
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
  int idx_ipv4 = 1;
  int idx_ipv4_2 = 3;
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, argv[idx_ipv4_2]->arg, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, prefix_str,
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
  int idx_ipv4 = 1;
  int idx_ipv4_2 = 3;
  int idx_word = 5;
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, argv[idx_ipv4_2]->arg, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, prefix_str,
			 AFI_IP, bgp_node_safi (vty), argv[idx_word]->arg, 0);
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
  int idx_ipv4 = 1;
  int idx_ipv4_2 = 3;
  int ret;
  char prefix_str[BUFSIZ];
  
  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, argv[idx_ipv4_2]->arg, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, prefix_str, AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (bgp_network_mask_natural,
       bgp_network_mask_natural_cmd,
       "network A.B.C.D",
       "Specify a network to announce via BGP\n"
       "Network number\n")
{
  int idx_ipv4 = 1;
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, prefix_str,
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
  int idx_ipv4 = 1;
  int idx_word = 3;
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, prefix_str,
			 AFI_IP, bgp_node_safi (vty), argv[idx_word]->arg, 0);
}

DEFUN (bgp_network_mask_natural_backdoor,
       bgp_network_mask_natural_backdoor_cmd,
       "network A.B.C.D backdoor",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n")
{
  int idx_ipv4 = 1;
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, prefix_str, AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network A.B.C.D/M [<backdoor|route-map WORD>]",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify a BGP backdoor route\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int idx_ipv4_prefixlen = 2;
  return bgp_static_unset (vty, argv[idx_ipv4_prefixlen]->arg, AFI_IP, 
			   bgp_node_safi (vty));
}

DEFUN (no_bgp_network_mask,
       no_bgp_network_mask_cmd,
       "no network A.B.C.D mask A.B.C.D [<backdoor|route-map WORD>]",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int idx_ipv4 = 2;
  int idx_ipv4_2 = 4;
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, argv[idx_ipv4_2]->arg, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_unset (vty, prefix_str, AFI_IP, 
			   bgp_node_safi (vty));
}

DEFUN (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_cmd,
       "no network A.B.C.D [<backdoor|route-map WORD>]",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int idx_ipv4 = 2;
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_unset (vty, prefix_str, AFI_IP, 
			   bgp_node_safi (vty));
}

DEFUN (ipv6_bgp_network,
       ipv6_bgp_network_cmd,
       "network X:X::X:X/M",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix\n")
{
  int idx_ipv6_prefixlen = 1;
  return bgp_static_set (vty, argv[idx_ipv6_prefixlen]->arg, AFI_IP6, bgp_node_safi(vty),
                         NULL, 0);
}

DEFUN (ipv6_bgp_network_route_map,
       ipv6_bgp_network_route_map_cmd,
       "network X:X::X:X/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int idx_ipv6_prefixlen = 1;
  int idx_word = 3;
  return bgp_static_set (vty, argv[idx_ipv6_prefixlen]->arg, AFI_IP6,
			 bgp_node_safi (vty), argv[idx_word]->arg, 0);
}

DEFUN (no_ipv6_bgp_network,
       no_ipv6_bgp_network_cmd,
       "no network X:X::X:X/M [route-map WORD]",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int idx_ipv6_prefixlen = 2;
  return bgp_static_unset (vty, argv[idx_ipv6_prefixlen]->arg, AFI_IP6, bgp_node_safi(vty));
}

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
#if defined(AGGREGATE_NEXTHOP_CHECK)
  struct in_addr nexthop;
  u_int32_t med = 0;
#endif
  struct bgp_info *ri;
  struct bgp_info *new;
  int first = 1;
  unsigned long match = 0;
  u_char atomic_aggregate = 0;

  /* Record adding route's nexthop and med. */
 if (rinew)
   {
#if defined(AGGREGATE_NEXTHOP_CHECK)
     nexthop = rinew->attr->nexthop;
     med = rinew->attr->med;
#endif
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
#if defined(AGGREGATE_NEXTHOP_CHECK)
		nexthop = ri->attr->nexthop;
		med = ri->attr->med;
#endif
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
  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
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
  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
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
  else
    {
      if (aspath)
	aspath_free (aspath);
      if (community)
	community_free (community);
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
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  int ret;
  struct prefix p;
  struct bgp_node *rn;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

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
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  int ret;
  struct prefix p;
  struct bgp_node *rn;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

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
       "aggregate-address A.B.C.D/M [<as-set [summary-only]|summary-only [as-set]>]",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")
{
  int idx = 0;
  argv_find (argv, argc, "A.B.C.D/M", &idx);
  char *prefix = argv[idx]->arg;
  int as_set = argv_find (argv, argc, "as-set", &idx) ? AGGREGATE_AS_SET : 0;
  idx = 0;
  int summary_only = argv_find (argv, argc, "summary-only", &idx) ? AGGREGATE_SUMMARY_ONLY : 0;

  return bgp_aggregate_set (vty, prefix, AFI_IP, bgp_node_safi (vty), summary_only, as_set);
}

DEFUN (aggregate_address_mask,
       aggregate_address_mask_cmd,
       "aggregate-address A.B.C.D A.B.C.D [<as-set [summary-only]|summary-only [as-set]>]",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")
{
  int idx = 0;
  argv_find (argv, argc, "A.B.C.D", &idx);
  char *prefix = argv[idx++]->arg;
  argv_find (argv, argc, "A.B.C.D", &idx);
  char *mask = argv[idx]->arg;
  int as_set = argv_find (argv, argc, "as-set", &idx) ? AGGREGATE_AS_SET : 0;
  idx = 0;
  int summary_only = argv_find (argv, argc, "summary-only", &idx) ? AGGREGATE_SUMMARY_ONLY : 0;

  char prefix_str[BUFSIZ];
  int ret = netmask_str2prefix_str (prefix, mask, prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty), summary_only, as_set);
}

DEFUN (no_aggregate_address,
       no_aggregate_address_cmd,
       "no aggregate-address A.B.C.D/M [<as-set [summary-only]|summary-only [as-set]>]",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")
{
  int idx = 0;
  argv_find (argv, argc, "A.B.C.D/M", &idx);
  char *prefix = argv[idx]->arg;
  return bgp_aggregate_unset (vty, prefix, AFI_IP, bgp_node_safi (vty));
}

DEFUN (no_aggregate_address_mask,
       no_aggregate_address_mask_cmd,
       "no aggregate-address A.B.C.D A.B.C.D [<as-set [summary-only]|summary-only [as-set]>]",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")
{
  int idx = 0;
  argv_find (argv, argc, "A.B.C.D", &idx);
  char *prefix = argv[idx++]->arg;
  argv_find (argv, argc, "A.B.C.D", &idx);
  char *mask = argv[idx]->arg;

  char prefix_str[BUFSIZ];
  int ret = netmask_str2prefix_str (prefix, mask, prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_unset (vty, prefix_str, AFI_IP, bgp_node_safi (vty));
}

DEFUN (ipv6_aggregate_address,
       ipv6_aggregate_address_cmd,
       "aggregate-address X:X::X:X/M [summary-only]",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  int idx = 0;
  argv_find (argv, argc, "X:X::X:X/M", &idx);
  char *prefix = argv[idx]->arg;
  int sum_only = argv_find (argv, argc, "summary-only", &idx) ? AGGREGATE_SUMMARY_ONLY : 0;
  return bgp_aggregate_set (vty, prefix, AFI_IP6, SAFI_UNICAST, sum_only, 0);
}

DEFUN (no_ipv6_aggregate_address,
       no_ipv6_aggregate_address_cmd,
       "no aggregate-address X:X::X:X/M [summary-only]",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  int idx = 0;
  argv_find (argv, argc, "X:X::X:X/M", &idx);
  char *prefix = argv[idx]->arg;
  return bgp_aggregate_unset (vty, prefix, AFI_IP6, SAFI_UNICAST);
}

/* Redistribute route treatment. */
void
bgp_redistribute_add (struct bgp *bgp, struct prefix *p, const struct in_addr *nexthop,
		      const struct in6_addr *nexthop6, unsigned int ifindex,
		      u_int32_t metric, u_char type, u_short instance, route_tag_t tag)
{
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
      if (red->rmap.name)
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
              bgp_redistribute_delete (bgp, p, type, instance);
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
          /* Ensure the (source route) type is updated. */
          bi->type = type;
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

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);
}

void
bgp_redistribute_delete (struct bgp *bgp, struct prefix *p, u_char type, u_short instance)
{
  afi_t afi;
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_redist *red;

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
  if (json_path)
    {

      /* Route status display. */
      if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
        json_object_boolean_true_add(json_path, "removed");

      if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE))
        json_object_boolean_true_add(json_path, "stale");

      if (binfo->extra && binfo->extra->suppress)
        json_object_boolean_true_add(json_path, "suppressed");

      if (CHECK_FLAG (binfo->flags, BGP_INFO_VALID) &&
               ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        json_object_boolean_true_add(json_path, "valid");

      /* Selected */
      if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        json_object_boolean_true_add(json_path, "history");

      if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
        json_object_boolean_true_add(json_path, "damped");

      if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
        json_object_boolean_true_add(json_path, "bestpath");

      if (CHECK_FLAG (binfo->flags, BGP_INFO_MULTIPATH))
        json_object_boolean_true_add(json_path, "multipath");

      /* Internal route. */
      if ((binfo->peer->as) && (binfo->peer->as == binfo->peer->local_as))
        json_object_string_add(json_path, "pathFrom", "internal");
      else
        json_object_string_add(json_path, "pathFrom", "external");

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
  json_object *json_path = NULL;
  json_object *json_nexthops = NULL;
  json_object *json_nexthop_global = NULL;
  json_object *json_nexthop_ll = NULL;

  if (json_paths)
    json_path = json_object_new_object();

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
      /*
       * For ENCAP routes, nexthop address family is not
       * neccessarily the same as the prefix address family.
       * Both SAFI_MPLS_VPN and SAFI_ENCAP use the MP nexthop field
       */
      if ((safi == SAFI_ENCAP) || (safi == SAFI_MPLS_VPN))
        {
	  if (attr->extra)
            {
	      char buf[BUFSIZ];
              int af = NEXTHOP_FAMILY(attr->extra->mp_nexthop_len);

              switch (af)
                {
                  case AF_INET:
                    vty_out (vty, "%s", inet_ntop(af,
                             &attr->extra->mp_nexthop_global_in, buf, BUFSIZ));
                  break;
#if HAVE_IPV6
                  case AF_INET6:
                    vty_out (vty, "%s", inet_ntop(af,
                             &attr->extra->mp_nexthop_global, buf, BUFSIZ));
                  break;
#endif
                  default:
                    vty_out(vty, "?");
                  break;
                }
            }
          else
            vty_out(vty, "?");
        }
      /* IPv4 Next Hop */
      else if (p->family == AF_INET && !BGP_ATTR_NEXTHOP_AFI_IP6(attr))
	{
          if (json_paths)
            {
              json_nexthop_global = json_object_new_object();

	      if (safi == SAFI_MPLS_VPN)
                json_object_string_add(json_nexthop_global, "ip", inet_ntoa (attr->extra->mp_nexthop_global_in));
              else
                json_object_string_add(json_nexthop_global, "ip", inet_ntoa (attr->nexthop));

              json_object_string_add(json_nexthop_global, "afi", "ipv4");
              json_object_boolean_true_add(json_nexthop_global, "used");
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

      /* IPv6 Next Hop */
      else if (p->family == AF_INET6 || BGP_ATTR_NEXTHOP_AFI_IP6(attr))
	{
	  int len;
	  char buf[BUFSIZ];

          if (json_paths)
            {
              json_nexthop_global = json_object_new_object();
              json_object_string_add(json_nexthop_global, "ip",
                                     inet_ntop (AF_INET6,
                                                &attr->extra->mp_nexthop_global,
                                                buf, BUFSIZ));
              json_object_string_add(json_nexthop_global, "afi", "ipv6");
              json_object_string_add(json_nexthop_global, "scope", "global");

              /* We display both LL & GL if both have been received */
              if ((attr->extra->mp_nexthop_len == 32) || (binfo->peer->conf_if))
                {
                  json_nexthop_ll = json_object_new_object();
                  json_object_string_add(json_nexthop_ll, "ip",
                                         inet_ntop (AF_INET6,
                                                    &attr->extra->mp_nexthop_local,
                                                    buf, BUFSIZ));
                  json_object_string_add(json_nexthop_ll, "afi", "ipv6");
                  json_object_string_add(json_nexthop_ll, "scope", "link-local");

                  if ((IPV6_ADDR_CMP (&attr->extra->mp_nexthop_global,
                                      &attr->extra->mp_nexthop_local) != 0) &&
                                      !attr->extra->mp_nexthop_prefer_global)
                    json_object_boolean_true_add(json_nexthop_ll, "used");
                  else
                    json_object_boolean_true_add(json_nexthop_global, "used");
                }
              else
                json_object_boolean_true_add(json_nexthop_global, "used");
            }
          else
            {
              /* Display LL if LL/Global both in table unless prefer-global is set */
	      if (((attr->extra->mp_nexthop_len == 32) &&
                   !attr->extra->mp_nexthop_prefer_global) ||
                   (binfo->peer->conf_if))
		{
		  if (binfo->peer->conf_if)
		    {
		      len = vty_out (vty, "%s",
				     binfo->peer->conf_if);
		      len = 7 - len; /* len of IPv6 addr + max len of def ifname */

		      if (len < 1)
			vty_out (vty, "%s%*s", VTY_NEWLINE, 45, " ");
		      else
			vty_out (vty, "%*s", len, " ");
		    }
		  else
		    {
		      len = vty_out (vty, "%s",
				     inet_ntop (AF_INET6,
						&attr->extra->mp_nexthop_local,
						buf, BUFSIZ));
		      len = 16 - len;

		      if (len < 1)
			vty_out (vty, "%s%*s", VTY_NEWLINE, 36, " ");
		      else
			vty_out (vty, "%*s", len, " ");
		    }
		}
 	      else
		{
		  len = vty_out (vty, "%s",
				 inet_ntop (AF_INET6,
					    &attr->extra->mp_nexthop_global,
					    buf, BUFSIZ));
		  len = 16 - len;

		  if (len < 1)
		    vty_out (vty, "%s%*s", VTY_NEWLINE, 36, " ");
		  else
		    vty_out (vty, "%*s", len, " ");
		}
            }
	}

      /* MED/Metric */
      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
        if (json_paths)
          json_object_int_add(json_path, "med", attr->med);
        else
	  vty_out (vty, "%10u", attr->med);
      else
        if (!json_paths)
	  vty_out (vty, "          ");

      /* Local Pref */
      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
        if (json_paths)
          json_object_int_add(json_path, "localpref", attr->local_pref);
        else
	  vty_out (vty, "%7u", attr->local_pref);
      else
        if (!json_paths)
	  vty_out (vty, "       ");

      if (json_paths)
        {
          if (attr->extra)
            json_object_int_add(json_path, "weight", attr->extra->weight);
          else
            json_object_int_add(json_path, "weight", 0);
        }
      else
        vty_out (vty, "%7u ", (attr->extra ? attr->extra->weight : 0));

      if (json_paths) {
	char buf[BUFSIZ];
	json_object_string_add(json_path, "peerId", sockunion2str (&binfo->peer->su, buf, SU_ADDRSTRLEN));
      }

      /* Print aspath */
      if (attr->aspath)
        {
          if (json_paths)
            json_object_string_add(json_path, "aspath", attr->aspath->str);
          else
            aspath_print_vty (vty, "%s", attr->aspath, " ");
        }

      /* Print origin */
      if (json_paths)
        json_object_string_add(json_path, "origin", bgp_origin_long_str[attr->origin]);
      else
        vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }
  else
    {
      if (json_paths)
        json_object_string_add(json_path, "alert", "No attributes");
      else
        vty_out (vty, "No attributes to print%s", VTY_NEWLINE);
    }

  if (json_paths)
    {
      if (json_nexthop_global || json_nexthop_ll)
        {
          json_nexthops = json_object_new_array();

          if (json_nexthop_global)
            json_object_array_add(json_nexthops, json_nexthop_global);

          if (json_nexthop_ll)
            json_object_array_add(json_nexthops, json_nexthop_ll);

          json_object_object_add(json_path, "nexthops", json_nexthops);
        }

      json_object_array_add(json_paths, json_path);
    }
  else
    {
    vty_out (vty, "%s", VTY_NEWLINE);
#if ENABLE_BGP_VNC
      /* prints an additional line, indented, with VNC info, if present */
      if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
        rfapi_vty_out_vncinfo(vty, p, binfo, safi);
#endif
    }
}  

/* called from terminal list command */
void
route_vty_out_tmp (struct vty *vty, struct prefix *p, struct attr *attr, safi_t safi,
                   u_char use_json, json_object *json_ar)
{
  json_object *json_status = NULL;
  json_object *json_net = NULL;
  char buff[BUFSIZ];
  /* Route status display. */
  if (use_json)
    {
      json_status = json_object_new_object();
      json_net = json_object_new_object();
    }
  else
    {
      vty_out (vty, "*");
      vty_out (vty, ">");
      vty_out (vty, " ");
    }

  /* print prefix and mask */
  if (use_json)
    json_object_string_add(json_net, "addrPrefix", inet_ntop (p->family, &p->u.prefix, buff, BUFSIZ));
  else
    route_vty_out_route (p, vty);

  /* Print attribute */
  if (attr) 
    {
      if (use_json)
        {
          if (p->family == AF_INET &&
              (safi == SAFI_MPLS_VPN ||
               safi == SAFI_ENCAP ||
               !BGP_ATTR_NEXTHOP_AFI_IP6(attr)))
            {
              if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
                json_object_string_add(json_net, "nextHop", inet_ntoa (attr->extra->mp_nexthop_global_in));
              else
                json_object_string_add(json_net, "nextHop", inet_ntoa (attr->nexthop));
            }
#ifdef HAVE_IPV6
          else if (p->family == AF_INET6 || BGP_ATTR_NEXTHOP_AFI_IP6(attr))
            {
              char buf[BUFSIZ];

              json_object_string_add(json_net, "netHopGloabal", inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                                  buf, BUFSIZ));
            }
#endif /* HAVE_IPV6 */

          if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
            json_object_int_add(json_net, "metric", attr->med);

          if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
            json_object_int_add(json_net, "localPref", attr->local_pref);

          if (attr->extra)
            json_object_int_add(json_net, "weight", attr->extra->weight);
          else
            json_object_int_add(json_net, "weight", 0);

          /* Print aspath */
          if (attr->aspath)
            json_object_string_add(json_net, "asPath", attr->aspath->str);

          /* Print origin */
          json_object_string_add(json_net, "bgpOriginCode", bgp_origin_str[attr->origin]);
        }
      else
        {
          if (p->family == AF_INET &&
              (safi == SAFI_MPLS_VPN ||
               safi == SAFI_ENCAP ||
               !BGP_ATTR_NEXTHOP_AFI_IP6(attr)))
            {
              if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
                vty_out (vty, "%-16s",
                         inet_ntoa (attr->extra->mp_nexthop_global_in));
              else
                vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
            }
#ifdef HAVE_IPV6
          else if (p->family == AF_INET6 || BGP_ATTR_NEXTHOP_AFI_IP6(attr))
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
    }
  if (use_json)
    {
      json_object_boolean_true_add(json_status, "*");
      json_object_boolean_true_add(json_status, ">");
      json_object_object_add(json_net, "appliedStatusSymbols", json_status);
      char buf_cut[BUFSIZ];
      json_object_object_add(json_ar, inet_ntop (p->family, &p->u.prefix, buf_cut, BUFSIZ), json_net);
    }
  else
    vty_out (vty, "%s", VTY_NEWLINE);
}  

void
route_vty_out_tag (struct vty *vty, struct prefix *p,
		   struct bgp_info *binfo, int display, safi_t safi, json_object *json)
{
  json_object *json_out = NULL;
  struct attr *attr;
  u_int32_t label = 0;
  
  if (!binfo->extra)
    return;

  if (json)
    json_out = json_object_new_object();
  
  /* short status lead text */ 
  route_vty_short_status_out (vty, binfo, json_out);
    
  /* print prefix and mask */
  if (json == NULL)
    {
      if (! display)
        route_vty_out_route (p, vty);
      else
        vty_out (vty, "%*s", 17, " ");
    }

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {
      if (p->family == AF_INET
          && (safi == SAFI_MPLS_VPN || !BGP_ATTR_NEXTHOP_AFI_IP6(attr)))
	{
	  if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
            {
              if (json)
                json_object_string_add(json_out, "mpNexthopGlobalIn", inet_ntoa (attr->extra->mp_nexthop_global_in));
              else
                vty_out (vty, "%-16s", inet_ntoa (attr->extra->mp_nexthop_global_in));
            }
	  else
            {
              if (json)
                json_object_string_add(json_out, "nexthop", inet_ntoa (attr->nexthop));
              else
                vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
            }
	}
#ifdef HAVE_IPV6      
      else if (p->family == AF_INET6 || BGP_ATTR_NEXTHOP_AFI_IP6(attr))
	{
	  assert (attr->extra);
	  char buf_a[BUFSIZ];
	  char buf_b[BUFSIZ];
          char buf_c[BUFSIZ];
	  if (attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL)
            {
              if (json)
                json_object_string_add(json_out, "mpNexthopGlobalIn",
                                       inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global, buf_a, BUFSIZ));
              else
                vty_out (vty, "%s",
                         inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                                    buf_a, BUFSIZ));
            }
	  else if (attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
            {
              if (json)
                {
                  inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                             buf_a, BUFSIZ);
                  inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
                             buf_b, BUFSIZ);
                  sprintf(buf_c, "%s(%s)", buf_a, buf_b);
                  json_object_string_add(json_out, "mpNexthopGlobalLocal", buf_c);
                }
              else
                vty_out (vty, "%s(%s)",
                         inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                                    buf_a, BUFSIZ),
                         inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
                                    buf_b, BUFSIZ));
            }

	}
#endif /* HAVE_IPV6 */
    }

  label = decode_label (binfo->extra->tag);

  if (json)
    {
      if (label)
        json_object_int_add(json_out, "notag", label);
      json_object_array_add(json, json_out);
    }
  else
    {
      vty_out (vty, "notag/%d", label);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}  

/* dampening route */
static void
damp_route_vty_out (struct vty *vty, struct prefix *p, struct bgp_info *binfo,
                    int display, safi_t safi, u_char use_json, json_object *json)
{
  struct attr *attr;
  int len;
  char timebuf[BGP_UPTIME_LEN];

  /* short status lead text */ 
  route_vty_short_status_out (vty, binfo, json);
  
  /* print prefix and mask */
  if (!use_json)
    {
      if (! display)
        route_vty_out_route (p, vty);
      else
        vty_out (vty, "%*s", 17, " ");
    }

  len = vty_out (vty, "%s", binfo->peer->host);
  len = 17 - len;
  if (len < 1)
    {
      if (!use_json)
        vty_out (vty, "%s%*s", VTY_NEWLINE, 34, " ");
    }
  else
    {
      if (use_json)
        json_object_int_add(json, "peerHost", len);
      else
        vty_out (vty, "%*s", len, " ");
    }

  if (use_json)
    bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN, use_json, json);
  else
    vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN, use_json, json));

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      /* Print aspath */
      if (attr->aspath)
        {
          if (use_json)
            json_object_string_add(json, "asPath", attr->aspath->str);
          else
            aspath_print_vty (vty, "%s", attr->aspath, " ");
        }

      /* Print origin */
      if (use_json)
        json_object_string_add(json, "origin", bgp_origin_str[attr->origin]);
      else
        vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }
  if (!use_json)
    vty_out (vty, "%s", VTY_NEWLINE);
}

/* flap route */
static void
flap_route_vty_out (struct vty *vty, struct prefix *p, struct bgp_info *binfo,
                    int display, safi_t safi, u_char use_json, json_object *json)
{
  struct attr *attr;
  struct bgp_damp_info *bdi;
  char timebuf[BGP_UPTIME_LEN];
  int len;
  
  if (!binfo->extra)
    return;
  
  bdi = binfo->extra->damp_info;

  /* short status lead text */
  route_vty_short_status_out (vty, binfo, json);
  
  /* print prefix and mask */
  if (!use_json)
    {
      if (! display)
        route_vty_out_route (p, vty);
      else
        vty_out (vty, "%*s", 17, " ");
    }

  len = vty_out (vty, "%s", binfo->peer->host);
  len = 16 - len;
  if (len < 1)
    {
      if (!use_json)
        vty_out (vty, "%s%*s", VTY_NEWLINE, 33, " ");
    }
  else
    {
      if (use_json)
        json_object_int_add(json, "peerHost", len);
      else
        vty_out (vty, "%*s", len, " ");
    }

  len = vty_out (vty, "%d", bdi->flap);
  len = 5 - len;
  if (len < 1)
    {
      if (!use_json)
        vty_out (vty, " ");
    }
  else
    {
      if (use_json)
        json_object_int_add(json, "bdiFlap", len);
      else
        vty_out (vty, "%*s", len, " ");
    }

  if (use_json)
    peer_uptime (bdi->start_time, timebuf, BGP_UPTIME_LEN, use_json, json);
  else
    vty_out (vty, "%s ", peer_uptime (bdi->start_time,
             timebuf, BGP_UPTIME_LEN, 0, NULL));

  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED)
      && ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    {
      if (use_json)
        bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN, use_json, json);
      else
        vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN, use_json, json));
    }
  else
    {
      if (!use_json)
        vty_out (vty, "%*s ", 8, " ");
    }

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      /* Print aspath */
      if (attr->aspath)
        {
          if (use_json)
            json_object_string_add(json, "asPath", attr->aspath->str);
          else
            aspath_print_vty (vty, "%s", attr->aspath, " ");
        }

      /* Print origin */
      if (use_json)
        json_object_string_add(json, "origin", bgp_origin_str[attr->origin]);
      else
        vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    }
  if (!use_json)
    vty_out (vty, "%s", VTY_NEWLINE);
}

static void
route_vty_out_advertised_to (struct vty *vty, struct peer *peer, int *first,
                             const char *header, json_object *json_adv_to)
{
  char buf1[INET6_ADDRSTRLEN];
  json_object *json_peer = NULL;

  if (json_adv_to)
    {
      /* 'advertised-to' is a dictionary of peers we have advertised this
       * prefix too.  The key is the peer's IP or swpX, the value is the
       * hostname if we know it and "" if not.
       */
      json_peer = json_object_new_object();

      if (peer->hostname)
        json_object_string_add(json_peer, "hostname", peer->hostname);

      if (peer->conf_if)
        json_object_object_add(json_adv_to, peer->conf_if, json_peer);
      else
        json_object_object_add(json_adv_to,
                               sockunion2str (&peer->su, buf1, SU_ADDRSTRLEN),
                               json_peer);
    }
  else
    {
      if (*first)
        {
          vty_out (vty, "%s", header);
          *first = 0;
        }

      if (peer->hostname && bgp_flag_check(peer->bgp, BGP_FLAG_SHOW_HOSTNAME))
        {
          if (peer->conf_if)
            vty_out (vty, " %s(%s)", peer->hostname, peer->conf_if);
          else
            vty_out (vty, " %s(%s)", peer->hostname,
                     sockunion2str (&peer->su, buf1, SU_ADDRSTRLEN));
        }
      else
        {
          if (peer->conf_if)
            vty_out (vty, " %s", peer->conf_if);
          else
            vty_out (vty, " %s", sockunion2str (&peer->su, buf1, SU_ADDRSTRLEN));
        }
    }
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
  json_object *json_bestpath = NULL;
  json_object *json_cluster_list = NULL;
  json_object *json_cluster_list_list = NULL;
  json_object *json_ext_community = NULL;
  json_object *json_last_update = NULL;
  json_object *json_nexthop_global = NULL;
  json_object *json_nexthop_ll = NULL;
  json_object *json_nexthops = NULL;
  json_object *json_path = NULL;
  json_object *json_peer = NULL;
  json_object *json_string = NULL;
  json_object *json_adv_to = NULL;
  int first = 0;
  struct listnode *node, *nnode;
  struct peer *peer;
  int addpath_capable;
  int has_adj;
  unsigned int first_as;

  if (json_paths)
    {
      json_path = json_object_new_object();
      json_peer = json_object_new_object();
      json_nexthop_global = json_object_new_object();
    }

  attr = binfo->attr;

  if (attr)
    {
      /* Line1 display AS-path, Aggregator */
      if (attr->aspath)
	{
          if (json_paths)
           {
            json_object_lock(attr->aspath->json);
            json_object_object_add(json_path, "aspath", attr->aspath->json);
           }
          else
            {
              if (attr->aspath->segments)
                aspath_print_vty (vty, "  %s", attr->aspath, "");
              else
                vty_out (vty, "  Local");
            }
	}

      if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "removed");
          else
            vty_out (vty, ", (removed)");
        }

      if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE))
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "stale");
          else
	    vty_out (vty, ", (stale)");
        }

      if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)))
        {
          if (json_paths)
            {
              json_object_int_add(json_path, "aggregatorAs", attr->extra->aggregator_as);
              json_object_string_add(json_path, "aggregatorId", inet_ntoa (attr->extra->aggregator_addr));
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
            json_object_boolean_true_add(json_path, "rxedFromRrClient");
          else
	    vty_out (vty, ", (Received from a RR-client)");
        }

      if (CHECK_FLAG (binfo->peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT))
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "rxedFromRsClient");
          else
	    vty_out (vty, ", (Received from a RS-client)");
        }

      if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "dampeningHistoryEntry");
          else
	    vty_out (vty, ", (history entry)");
        }
      else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "dampeningSuppressed");
          else
	    vty_out (vty, ", (suppressed due to dampening)");
        }

      if (!json_paths)
        vty_out (vty, "%s", VTY_NEWLINE);
	  
      /* Line2 display Next-hop, Neighbor, Router-id */
      /* Display the nexthop */
      if (p->family == AF_INET &&
          (safi == SAFI_MPLS_VPN ||
           safi == SAFI_ENCAP ||
           !BGP_ATTR_NEXTHOP_AFI_IP6(attr)))
	{
          if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
            {
              if (json_paths)
                json_object_string_add(json_nexthop_global, "ip", inet_ntoa (attr->extra->mp_nexthop_global_in));
              else
	        vty_out (vty, "    %s", inet_ntoa (attr->extra->mp_nexthop_global_in));
            }
          else
            {
              if (json_paths)
                json_object_string_add(json_nexthop_global, "ip", inet_ntoa (attr->nexthop));
              else
	        vty_out (vty, "    %s", inet_ntoa (attr->nexthop));
            }

          if (json_paths)
            json_object_string_add(json_nexthop_global, "afi", "ipv4");
	}
      else
	{
	  assert (attr->extra);
          if (json_paths)
            {
              json_object_string_add(json_nexthop_global, "ip",
                                     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                                                buf, INET6_ADDRSTRLEN));
              json_object_string_add(json_nexthop_global, "afi", "ipv6");
              json_object_string_add(json_nexthop_global, "scope", "global");
            }
          else
            {
	      vty_out (vty, "    %s",
		       inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
			          buf, INET6_ADDRSTRLEN));
            }
	}

      /* Display the IGP cost or 'inaccessible' */
      if (! CHECK_FLAG (binfo->flags, BGP_INFO_VALID))
        {
          if (json_paths)
            json_object_boolean_false_add(json_nexthop_global, "accessible");
          else
            vty_out (vty, " (inaccessible)");
        }
      else
        {
          if (binfo->extra && binfo->extra->igpmetric)
            {
              if (json_paths)
                json_object_int_add(json_nexthop_global, "metric", binfo->extra->igpmetric);
              else
                vty_out (vty, " (metric %u)", binfo->extra->igpmetric);
            }

          /* IGP cost is 0, display this only for json */
          else
            {
              if (json_paths)
                json_object_int_add(json_nexthop_global, "metric", 0);
            }

          if (json_paths)
            json_object_boolean_true_add(json_nexthop_global, "accessible");
        }

      /* Display peer "from" output */
      /* This path was originated locally */
      if (binfo->peer == bgp->peer_self)
	{

          if (p->family == AF_INET && !BGP_ATTR_NEXTHOP_AFI_IP6(attr))
            {
              if (json_paths)
                json_object_string_add(json_peer, "peerId", "0.0.0.0");
              else
	        vty_out (vty, " from 0.0.0.0 ");
            }
          else
            {
              if (json_paths)
                json_object_string_add(json_peer, "peerId", "::");
              else
	        vty_out (vty, " from :: ");
            }

          if (json_paths)
            json_object_string_add(json_peer, "routerId", inet_ntoa(bgp->router_id));
          else
	    vty_out (vty, "(%s)", inet_ntoa(bgp->router_id));
	}

      /* We RXed this path from one of our peers */
      else
	{

          if (json_paths)
            {
              json_object_string_add(json_peer, "peerId", sockunion2str (&binfo->peer->su, buf, SU_ADDRSTRLEN));
              json_object_string_add(json_peer, "routerId", inet_ntop (AF_INET, &binfo->peer->remote_id, buf1, BUFSIZ));

              if (binfo->peer->hostname)
                json_object_string_add(json_peer, "hostname", binfo->peer->hostname);

              if (binfo->peer->domainname)
                json_object_string_add(json_peer, "domainname", binfo->peer->domainname);

              if (binfo->peer->conf_if)
                json_object_string_add(json_peer, "interface", binfo->peer->conf_if);
            }
          else
            {
              if (binfo->peer->conf_if)
		{
		  if (binfo->peer->hostname &&
		      bgp_flag_check(binfo->peer->bgp, BGP_FLAG_SHOW_HOSTNAME))
		    vty_out (vty, " from %s(%s)", binfo->peer->hostname,
			     binfo->peer->conf_if);
		  else
		    vty_out (vty, " from %s", binfo->peer->conf_if);
		}
              else
		{
		  if (binfo->peer->hostname &&
		      bgp_flag_check(binfo->peer->bgp, BGP_FLAG_SHOW_HOSTNAME))
		    vty_out (vty, " from %s(%s)", binfo->peer->hostname,
			     binfo->peer->host);
		  else
		    vty_out (vty, " from %s", sockunion2str (&binfo->peer->su, buf, SU_ADDRSTRLEN));
		}

              if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
                vty_out (vty, " (%s)", inet_ntoa (attr->extra->originator_id));
              else
                vty_out (vty, " (%s)", inet_ntop (AF_INET, &binfo->peer->remote_id, buf1, BUFSIZ));
            }
	}

      if (!json_paths)
        vty_out (vty, "%s", VTY_NEWLINE);

      /* display the link-local nexthop */
      if (attr->extra && attr->extra->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
	{
          if (json_paths)
            {
              json_nexthop_ll = json_object_new_object();
              json_object_string_add(json_nexthop_ll, "ip",
                                     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
                                                buf, INET6_ADDRSTRLEN));
              json_object_string_add(json_nexthop_ll, "afi", "ipv6");
              json_object_string_add(json_nexthop_ll, "scope", "link-local");

              json_object_boolean_true_add(json_nexthop_ll, "accessible");

              if (!attr->extra->mp_nexthop_prefer_global)
                json_object_boolean_true_add(json_nexthop_ll, "used");
              else
                json_object_boolean_true_add(json_nexthop_global, "used");
            }
          else
            {
	      vty_out (vty, "    (%s) %s%s",
                       inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
			          buf, INET6_ADDRSTRLEN),
                       attr->extra->mp_nexthop_prefer_global ?
                                   "(prefer-global)" : "(used)",
		       VTY_NEWLINE);
            }
	}
      /* If we do not have a link-local nexthop then we must flag the global as "used" */
      else
        {
          if (json_paths)
            json_object_boolean_true_add(json_nexthop_global, "used");
        }

      /* Line 3 display Origin, Med, Locpref, Weight, Tag, valid, Int/Ext/Local, Atomic, best */
      if (json_paths)
        json_object_string_add(json_path, "origin", bgp_origin_long_str[attr->origin]);
      else
        vty_out (vty, "      Origin %s", bgp_origin_long_str[attr->origin]);
	  
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
        {
          if (json_paths)
            json_object_int_add(json_path, "med", attr->med);
          else
	    vty_out (vty, ", metric %u", attr->med);
        }
	  
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
        {
          if (json_paths)
            json_object_int_add(json_path, "localpref", attr->local_pref);
          else
	    vty_out (vty, ", localpref %u", attr->local_pref);
        }
      else
        {
          if (json_paths)
            json_object_int_add(json_path, "localpref", bgp->default_local_pref);
          else
	    vty_out (vty, ", localpref %u", bgp->default_local_pref);
        }

      if (attr->extra && attr->extra->weight != 0)
        {
          if (json_paths)
            json_object_int_add(json_path, "weight", attr->extra->weight);
          else
	    vty_out (vty, ", weight %u", attr->extra->weight);
        }

      if (attr->extra && attr->extra->tag != 0)
        {
          if (json_paths)
            json_object_int_add(json_path, "tag", attr->extra->tag);
          else
            vty_out (vty, ", tag %"ROUTE_TAG_PRI, attr->extra->tag);
        }
	
      if (! CHECK_FLAG (binfo->flags, BGP_INFO_VALID))
        {
          if (json_paths)
            json_object_boolean_false_add(json_path, "valid");
          else
	    vty_out (vty, ", invalid");
        }
      else if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "valid");
          else
	    vty_out (vty, ", valid");
        }

      if (binfo->peer != bgp->peer_self)
	{
          if (binfo->peer->as == binfo->peer->local_as)
            {
              if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
                {
                  if (json_paths)
                    json_object_string_add(json_peer, "type", "confed-internal");
                  else
                    vty_out (vty, ", confed-internal");
                }
              else
                {
                  if (json_paths)
                    json_object_string_add(json_peer, "type", "internal");
                  else
                    vty_out (vty, ", internal");
                }
            }
          else
            {
              if (bgp_confederation_peers_check(bgp, binfo->peer->as))
                {
                  if (json_paths)
                    json_object_string_add(json_peer, "type", "confed-external");
                  else
                    vty_out (vty, ", confed-external");
                }
              else
                {
                  if (json_paths)
                    json_object_string_add(json_peer, "type", "external");
                  else
                    vty_out (vty, ", external");
                }
            }
	}
      else if (binfo->sub_type == BGP_ROUTE_AGGREGATE)
        {
          if (json_paths)
            {
              json_object_boolean_true_add(json_path, "aggregated");
              json_object_boolean_true_add(json_path, "local");
            }
          else
            {
	      vty_out (vty, ", aggregated, local");
            }
        }
      else if (binfo->type != ZEBRA_ROUTE_BGP)
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "sourced");
          else
	    vty_out (vty, ", sourced");
        }
      else
        {
          if (json_paths)
            {
              json_object_boolean_true_add(json_path, "sourced");
              json_object_boolean_true_add(json_path, "local");
            }
          else
            {
	      vty_out (vty, ", sourced, local");
            }
        }

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "atomicAggregate");
          else
	    vty_out (vty, ", atomic-aggregate");
        }
	  
      if (CHECK_FLAG (binfo->flags, BGP_INFO_MULTIPATH) ||
	  (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED) &&
	   bgp_info_mpath_count (binfo)))
        {
          if (json_paths)
            json_object_boolean_true_add(json_path, "multipath");
          else
	    vty_out (vty, ", multipath");
        }

      // Mark the bestpath(s)
      if (CHECK_FLAG (binfo->flags, BGP_INFO_DMED_SELECTED))
        {
          first_as = aspath_get_first_as(attr->aspath);

          if (json_paths)
            {
              if (!json_bestpath)
                json_bestpath = json_object_new_object();
              json_object_int_add(json_bestpath, "bestpathFromAs", first_as);
            }
          else
            {
              if (first_as)
	        vty_out (vty, ", bestpath-from-AS %d", first_as);
              else
	        vty_out (vty, ", bestpath-from-AS Local");
            }
        }

      if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
        {
          if (json_paths)
            {
              if (!json_bestpath)
                json_bestpath = json_object_new_object();
              json_object_boolean_true_add(json_bestpath, "overall");
            }
          else
	    vty_out (vty, ", best");
        }

      if (json_bestpath)
        json_object_object_add(json_path, "bestpath", json_bestpath);

      if (!json_paths)
        vty_out (vty, "%s", VTY_NEWLINE);
	  
      /* Line 4 display Community */
      if (attr->community)
        {
          if (json_paths)
            {
              json_object_lock(attr->community->json);
              json_object_object_add(json_path, "community", attr->community->json);
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
              json_ext_community = json_object_new_object();
              json_object_string_add(json_ext_community, "string", attr->extra->ecommunity->str);
              json_object_object_add(json_path, "extendedCommunity", json_ext_community);
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
                json_object_string_add(json_path, "originatorId", inet_ntoa (attr->extra->originator_id));
              else
	        vty_out (vty, "      Originator: %s",
	                 inet_ntoa (attr->extra->originator_id));
            }

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
	    {
	      int i;

              if (json_paths)
                {
                  json_cluster_list = json_object_new_object();
                  json_cluster_list_list = json_object_new_array();

	          for (i = 0; i < attr->extra->cluster->length / 4; i++)
                    {
                      json_string = json_object_new_string(inet_ntoa (attr->extra->cluster->list[i]));
                      json_object_array_add(json_cluster_list_list, json_string);
                    }

                  /* struct cluster_list does not have "str" variable like
                   * aspath and community do.  Add this someday if someone
                   * asks for it.
                  json_object_string_add(json_cluster_list, "string", attr->extra->cluster->str);
                   */
                  json_object_object_add(json_cluster_list, "list", json_cluster_list_list);
                  json_object_object_add(json_path, "clusterList", json_cluster_list);
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
              json_object_int_add(json_path, "addpathRxId", binfo->addpath_rx_id);
              json_object_int_add(json_path, "addpathTxId", binfo->addpath_tx_id);
            }
          else
            {
              vty_out (vty, "      AddPath ID: RX %u, TX %u%s",
                       binfo->addpath_rx_id, binfo->addpath_tx_id,
                       VTY_NEWLINE);
            }
        }

      /* If we used addpath to TX a non-bestpath we need to display
       * "Advertised to" on a path-by-path basis */
      if (bgp->addpath_tx_used[afi][safi])
        {
          first = 1;

          for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
            {
              addpath_capable = bgp_addpath_encode_tx (peer, afi, safi);
              has_adj = bgp_adj_out_lookup (peer, binfo->net, binfo->addpath_tx_id);

              if ((addpath_capable && has_adj) ||
                  (!addpath_capable && has_adj && CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED)))
                {
                    if (json_path && !json_adv_to)
                      json_adv_to = json_object_new_object();

                    route_vty_out_advertised_to(vty, peer, &first,
                                                "      Advertised to:",
                                                json_adv_to);
                }
            }

          if (json_path)
            {
              if (json_adv_to)
                {
                  json_object_object_add(json_path, "advertisedTo", json_adv_to);
                }
            }
          else
            {
              if (!first)
                {
	          vty_out (vty, "%s", VTY_NEWLINE);
                }
            }
        }

      /* Line 8 display Uptime */
#ifdef HAVE_CLOCK_MONOTONIC
      tbuf = time(NULL) - (bgp_clock() - binfo->uptime);
      if (json_paths)
        {
          json_last_update = json_object_new_object();
          json_object_int_add(json_last_update, "epoch", tbuf);
          json_object_string_add(json_last_update, "string", ctime(&tbuf));
          json_object_object_add(json_path, "lastUpdate", json_last_update);
        }
      else
        vty_out (vty, "      Last update: %s", ctime(&tbuf));
#else
      if (json_paths)
        {
          json_last_update = json_object_new_object();
          json_object_int_add(json_last_update, "epoch", tbuf);
          json_object_string_add(json_last_update, "string", ctime(&binfo->uptime));
          json_object_object_add(json_path, "lastUpdate", json_last_update);
        }
      else
        vty_out (vty, "      Last update: %s", ctime(&binfo->uptime));
#endif /* HAVE_CLOCK_MONOTONIC */
    }

  /* We've constructed the json object for this path, add it to the json
   * array of paths
   */
  if (json_paths)
    {
      if (json_nexthop_global || json_nexthop_ll)
        {
          json_nexthops = json_object_new_array();

          if (json_nexthop_global)
            json_object_array_add(json_nexthops, json_nexthop_global);

          if (json_nexthop_ll)
            json_object_array_add(json_nexthops, json_nexthop_ll);

          json_object_object_add(json_path, "nexthops", json_nexthops);
        }

      json_object_object_add(json_path, "peer", json_peer);
      json_object_array_add(json_paths, json_path);
    }
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
  bgp_show_type_flap_neighbor,
  bgp_show_type_dampend_paths,
  bgp_show_type_damp_neighbor
};

static int
bgp_show_prefix_list (struct vty *vty, const char *name,
                      const char *prefix_list_str, afi_t afi,
                      safi_t safi, enum bgp_show_type type);
static int
bgp_show_filter_list (struct vty *vty, const char *name,
                      const char *filter, afi_t afi,
                      safi_t safi, enum bgp_show_type type);
static int
bgp_show_route_map (struct vty *vty, const char *name,
                    const char *rmap_str, afi_t afi,
                    safi_t safi, enum bgp_show_type type);
static int
bgp_show_community_list (struct vty *vty, const char *name,
                         const char *com, int exact,
                         afi_t afi, safi_t safi);
static int
bgp_show_prefix_longer (struct vty *vty, const char *name,
                        const char *prefix, afi_t afi,
                        safi_t safi, enum bgp_show_type type);
static int
bgp_show_regexp (struct vty *vty, const char *regstr, afi_t afi,
		 safi_t safi, enum bgp_show_type type);
static int
bgp_show_community (struct vty *vty, const char *view_name, int argc,
		    struct cmd_token **argv, int exact, afi_t afi, safi_t safi);

static int
bgp_show_table (struct vty *vty, struct bgp *bgp, struct bgp_table *table,
                enum bgp_show_type type, void *output_arg, u_char use_json)
{
  struct bgp_info *ri;
  struct bgp_node *rn;
  int header = 1;
  int display;
  unsigned long output_count;
  unsigned long total_count;
  struct prefix *p;
  char buf[BUFSIZ];
  char buf2[BUFSIZ];
  json_object *json_paths = NULL;
  int first = 1;

  if (use_json)
    {
      vty_out (vty, "{ \"vrfId\": %d, \"vrfName\": \"%s\", \"tableVersion\": %" PRId64 ", \"routerId\": \"%s\", \"routes\": { ",
	       bgp->vrf_id == VRF_UNKNOWN ? -1 : bgp->vrf_id,
	       bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT ? "Default" : bgp->name,
	       table->version, inet_ntoa (bgp->router_id));
      json_paths = json_object_new_object();
    }

  /* This is first entry point, so reset total line. */
  output_count = 0;
  total_count  = 0;

  /* Start processing of routes. */
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn)) 
    if (rn->info != NULL)
      {
        display = 0;
	if (!first && use_json)
	  {
	    vty_out (vty, ",");
	  }
        if (use_json)
          json_paths = json_object_new_array();
        else
          json_paths = NULL;

        for (ri = rn->info; ri; ri = ri->next)
          {
            total_count++;
            if (type == bgp_show_type_flap_statistics
                || type == bgp_show_type_flap_neighbor
                || type == bgp_show_type_dampend_paths
                || type == bgp_show_type_damp_neighbor)
              {
                if (!(ri->extra && ri->extra->damp_info))
                  continue;
              }
            if (type == bgp_show_type_regexp)
              {
                regex_t *regex = output_arg;

                if (bgp_regexec (regex, ri->attr->aspath) == REG_NOMATCH)
                  continue;
              }
            if (type == bgp_show_type_prefix_list)
              {
                struct prefix_list *plist = output_arg;

                if (prefix_list_apply (plist, &rn->p) != PREFIX_PERMIT)
                  continue;
              }
            if (type == bgp_show_type_filter_list)
              {
                struct as_list *as_list = output_arg;

                if (as_list_apply (as_list, ri->attr->aspath) != AS_FILTER_PERMIT)
                  continue;
              }
            if (type == bgp_show_type_route_map)
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
            if (type == bgp_show_type_cidr_only)
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
            if (type == bgp_show_type_prefix_longer)
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
            if (type == bgp_show_type_dampend_paths
                || type == bgp_show_type_damp_neighbor)
              {
                if (! CHECK_FLAG (ri->flags, BGP_INFO_DAMPED)
                    || CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
                  continue;
              }

            if (!use_json && header)
              {
                vty_out (vty, "BGP table version is %" PRIu64 ", local router ID is %s%s", table->version, inet_ntoa (bgp->router_id), VTY_NEWLINE);
                vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                if (type == bgp_show_type_dampend_paths
                    || type == bgp_show_type_damp_neighbor)
                  vty_out (vty, BGP_SHOW_DAMP_HEADER, VTY_NEWLINE);
                else if (type == bgp_show_type_flap_statistics
                         || type == bgp_show_type_flap_neighbor)
                  vty_out (vty, BGP_SHOW_FLAP_HEADER, VTY_NEWLINE);
                else
                  vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
                header = 0;
              }

            if (type == bgp_show_type_dampend_paths
                || type == bgp_show_type_damp_neighbor)
              damp_route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST, use_json, json_paths);
            else if (type == bgp_show_type_flap_statistics
                     || type == bgp_show_type_flap_neighbor)
              flap_route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST, use_json, json_paths);
            else
              route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST, json_paths);
            display++;
          }

        if (display)
          {
            output_count++;
            if (use_json)
              {
                p = &rn->p;
                sprintf(buf2, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ), p->prefixlen);
		vty_out (vty, "\"%s\": ", buf2);
		vty_out (vty, "%s", json_object_to_json_string (json_paths));
		json_object_free (json_paths);
		first = 0;

              }
          }
        }

  if (use_json)
    {
      json_object_free (json_paths);
      vty_out (vty, " } }%s", VTY_NEWLINE);
    }
  else
    {
      /* No route is displayed */
      if (output_count == 0)
        {
          if (type == bgp_show_type_normal)
            vty_out (vty, "No BGP prefixes displayed, %ld exist%s", total_count, VTY_NEWLINE);
        }
      else
        vty_out (vty, "%sDisplayed  %ld out of %ld total prefixes%s",
                 VTY_NEWLINE, output_count, total_count, VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

static int
bgp_show (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
          enum bgp_show_type type, void *output_arg, u_char use_json)
{
  struct bgp_table *table;

  if (bgp == NULL)
    {
      bgp = bgp_get_default ();
    }

  if (bgp == NULL)
    {
      if (!use_json)
        vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = bgp->rib[afi][safi];

  return bgp_show_table (vty, bgp, table, type, output_arg,
                         use_json);
}

static void
bgp_show_all_instances_routes_vty (struct vty *vty, afi_t afi, safi_t safi,
                                   u_char use_json)
{
  struct listnode *node, *nnode;
  struct bgp *bgp;
  struct bgp_table *table;
  int is_first = 1;

  if (use_json)
    vty_out (vty, "{%s", VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      if (use_json)
        {
          if (! is_first)
            vty_out (vty, ",%s", VTY_NEWLINE);
          else
            is_first = 0;

          vty_out(vty, "\"%s\":", (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                  ? "Default" : bgp->name);
        }
      else
        {
          vty_out (vty, "%sInstance %s:%s",
                   VTY_NEWLINE,
                   (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                   ? "Default" : bgp->name,
                   VTY_NEWLINE);
        }
      table = bgp->rib[afi][safi];
      bgp_show_table (vty, bgp, table,
                      bgp_show_type_normal, NULL, use_json);

    }

  if (use_json)
    vty_out (vty, "}%s", VTY_NEWLINE);
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
  int first = 1;
  json_object *json_adv_to = NULL;

  p = &rn->p;

  if (json)
    {
      json_object_string_add(json, "prefix", inet_ntop (p->family, &p->u.prefix, buf2, INET6_ADDRSTRLEN));
      json_object_int_add(json, "prefixlen", p->prefixlen);
    }
  else
    {
      vty_out (vty, "BGP routing table entry for %s%s%s/%d%s",
	       ((safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP) ?
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
            vty_out (vty, ", table %s",
                     (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
                     ? "Default-IP-Routing-Table" : bgp->name);
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

  /* If we are not using addpath then we can display Advertised to and that will
   * show what peers we advertised the bestpath to.  If we are using addpath
   * though then we must display Advertised to on a path-by-path basis. */
  if (!bgp->addpath_tx_used[afi][safi])
    {
      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
        {
          if (bgp_adj_out_lookup (peer, rn, 0))
            {
              if (json && !json_adv_to)
                json_adv_to = json_object_new_object();

              route_vty_out_advertised_to(vty, peer, &first,
                                          "  Advertised to non peer-group peers:\n ",
                                          json_adv_to);
            }
        }

      if (json)
        {
          if (json_adv_to)
            {
              json_object_object_add(json, "advertisedTo", json_adv_to);
            }
        }
      else
        {
          if (first)
            vty_out (vty, "  Not advertised to any peer");
          vty_out (vty, "%s", VTY_NEWLINE);
        }
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
  json_object *json = NULL;
  json_object *json_paths = NULL;

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

  if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP)
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
                                                       AFI_IP, safi, json);
                          header = 0;
                        }
                      display++;

                      if (pathtype == BGP_PATH_ALL ||
                          (pathtype == BGP_PATH_BESTPATH && CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)) ||
                          (pathtype == BGP_PATH_MULTIPATH &&
                           (CHECK_FLAG (ri->flags, BGP_INFO_MULTIPATH) || CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))))
                        route_vty_out_detail (vty, bgp, &rm->p, ri, AFI_IP, safi, json_paths);
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

      vty_out (vty, "%s%s", json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY), VTY_NEWLINE);
      json_object_free(json);
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
	  vty_out (vty, "Can't find BGP instance %s%s", view_name, VTY_NEWLINE);
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
DEFUN (show_ip_bgp_ipv4,
       show_ip_bgp_ipv4_cmd,
       "show [ip] bgp [<view|vrf> WORD] [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>]\
          [<\
             cidr-only\
             |dampening <flap-statistics|dampened-paths|parameters>\
             |route-map WORD\
             |prefix-list WORD\
             |filter-list WORD\
             |community [<AA:NN|local-AS|no-advertise|no-export> [exact-match]]\
             |community-list <(1-500)|WORD> [exact-match]\
             |A.B.C.D/M longer-prefixes\
             |X:X::X:X/M longer-prefixes\
           >]\
          [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Display only routes with non-natural netmasks\n"
       "Display detailed information about dampening\n"
       "Display flap statistics of routes\n"
       "Display paths suppressed due to dampening\n"
       "Display dampening parameters\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n"
       "Display routes conforming to the prefix-list\n"
       "Prefix-list name\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n"
       "Display routes matching the communities\n"
       COMMUNITY_AANN_STR
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n"
       "IPv4 prefix\n"
       "Display route and more specific routes\n"
       "IPv6 prefix\n"
       "Display route and more specific routes\n"
       JSON_STR)
{
  char *vrf = NULL;
  afi_t afi = AFI_IP6;
  safi_t safi = SAFI_UNICAST;
  int exact_match = 0;
  enum bgp_show_type sh_type = bgp_show_type_normal;

  int idx = 0;

  if (argv_find (argv, argc, "ip", &idx))
    afi = AFI_IP;
  if (argv_find (argv, argc, "view", &idx) || argv_find (argv, argc, "vrf", &idx))
    vrf = argv[++idx]->arg;
  if (argv_find (argv, argc, "ipv4", &idx) || argv_find (argv, argc, "ipv6", &idx))
  {
    afi = strmatch(argv[idx]->text, "ipv6") ? AFI_IP6 : AFI_IP;
    if (argv_find (argv, argc, "unicast", &idx) || argv_find (argv, argc, "multicast", &idx))
      safi = strmatch (argv[idx]->text, "unicast") ? SAFI_UNICAST : SAFI_MULTICAST;
  }
  else if (argv_find (argv, argc, "encap", &idx) || argv_find (argv, argc, "vpnv4", &idx))
  {
    afi = AFI_IP;
    safi = strmatch (argv[idx]->text, "encap") ? SAFI_ENCAP : SAFI_MPLS_VPN;
    // advance idx if necessary
    argv_find (argv, argc, "unicast", &idx);
  }

  int uj = use_json (argc, argv);
  if (uj) argc--;

  struct bgp *bgp = bgp_lookup_by_name (vrf);
  if (bgp == NULL)
   {
     vty_out (vty, "Can't find BGP instance %s%s", vrf, VTY_NEWLINE);
     return CMD_WARNING;
   }

  if (++idx < argc)
  {
    if (strmatch(argv[idx]->text, "cidr-only"))
      return bgp_show (vty, bgp, afi, safi, bgp_show_type_cidr_only, NULL, uj);

    else if (strmatch(argv[idx]->text, "dampening"))
    {
      if (argv_find (argv, argc, "dampened-paths", &idx))
        return bgp_show (vty, bgp, afi, safi, bgp_show_type_dampend_paths, NULL, uj);
      else if (argv_find (argv, argc, "flap-statistics", &idx))
        return bgp_show (vty, bgp, afi, safi, bgp_show_type_flap_statistics, NULL, uj);
      else if (argv_find (argv, argc, "parameters", &idx))
        return bgp_show_dampening_parameters (vty, AFI_IP, SAFI_UNICAST);
    }

    else if (strmatch(argv[idx]->text, "prefix-list"))
      return bgp_show_prefix_list (vty, vrf, argv[idx + 1]->arg, afi, safi, bgp_show_type_prefix_list);

    else if (strmatch(argv[idx]->text, "filter-list"))
      return bgp_show_filter_list (vty, vrf, argv[idx + 1]->arg, afi, safi, bgp_show_type_filter_list);

    else if (strmatch(argv[idx]->text, "route-map"))
      return bgp_show_route_map (vty, vrf, argv[idx + 1]->arg, afi, safi, bgp_show_type_route_map);

    else if (strmatch(argv[idx]->text, "community"))
    {
      /* show a specific community */
      if (argv[idx + 1]->type == VARIABLE_TKN ||
          strmatch(argv[idx + 1]->text, "local-AS") ||
          strmatch(argv[idx + 1]->text, "no-advertise") ||
          strmatch(argv[idx + 1]->text, "no-export"))
        {
          if (strmatch(argv[idx + 2]->text, "exact_match")) 
            exact_match = 1;
          return bgp_show_community (vty, vrf, argc, argv, exact_match, afi, safi);
        }
      /* show all communities */
      else
        return bgp_show (vty, bgp, afi, safi, bgp_show_type_community_all, NULL, uj);
    }
    else if (strmatch(argv[idx]->text, "community-list"))
      {
        const char *clist_number_or_name = argv[++idx]->arg;
        if (++idx < argc && strmatch (argv[idx]->arg, "exact-match"))
          exact_match = 1;
        return bgp_show_community_list (vty, vrf, clist_number_or_name, exact_match, afi, safi);
      }
    /* prefix-longer */
    else if (argv[idx]->type == IPV4_TKN || argv[idx]->type == IPV6_TKN)
      return bgp_show_prefix_longer (vty, vrf, argv[idx + 1]->arg, afi, safi, bgp_show_type_prefix_longer);
  }

  return bgp_show (vty, bgp, afi, safi, sh_type, NULL, uj);
}

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show [ip] bgp [<view|vrf> WORD] [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>]"
       "<A.B.C.D|A.B.C.D/M|X:X::X:X|X:X::X:X/M> [<bestpath|multipath>] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n"
       "IPv4 prefix\n"
       "Network in the BGP routing table to display\n"
       "IPv6 prefix\n"
       "Display only the bestpath\n"
       "Display only multipaths\n"
       JSON_STR)
{
  int prefix_check = 0;

  afi_t afi = AFI_IP6;
  safi_t safi = SAFI_UNICAST;
  char *vrf = NULL;
  char *prefix = NULL;

  enum bgp_path_type path_type;
  u_char uj = use_json(argc, argv);

  int idx = 0;

  /* show [ip] bgp */
  if (argv_find (argv, argc, "ip", &idx))
    afi = AFI_IP;
  /* [<view|vrf> WORD] */
  if (argv_find (argv, argc, "view", &idx) || argv_find (argv, argc, "vrf", &idx))
    vrf = argv[++idx]->arg;
  /* [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] */
  if (argv_find (argv, argc, "ipv4", &idx) || argv_find (argv, argc, "ipv6", &idx))
  {
    afi = strmatch(argv[idx]->text, "ipv6") ? AFI_IP6 : AFI_IP;
    if (argv_find (argv, argc, "unicast", &idx) || argv_find (argv, argc, "multicast", &idx))
      safi = strmatch (argv[idx]->text, "unicast") ? SAFI_UNICAST : SAFI_MULTICAST;
  }
  else if (argv_find (argv, argc, "encap", &idx) || argv_find (argv, argc, "vpnv4", &idx))
  {
    afi = AFI_IP;
    safi = strmatch (argv[idx]->text, "encap") ? SAFI_ENCAP : SAFI_MPLS_VPN;
    // advance idx if necessary
    argv_find (argv, argc, "unicast", &idx);
  }

  /* <A.B.C.D|A.B.C.D/M|X:X::X:X|X:X::X:X/M> */
  if (argv_find (argv, argc, "A.B.C.D", &idx) || argv_find (argv, argc, "X:X::X:X", &idx))
    prefix_check = 0;
  else if (argv_find (argv, argc, "A.B.C.D/M", &idx) || argv_find (argv, argc, "X:X::X:X/M", &idx))
    prefix_check = 1;

  if ((argv[idx]->type == IPV6_TKN || argv[idx]->type == IPV6_PREFIX_TKN) && afi != AFI_IP6)
  {
    vty_out (vty, "%% Cannot specify IPv6 address or prefix with IPv4 AFI%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  if ((argv[idx]->type == IPV4_TKN || argv[idx]->type == IPV4_PREFIX_TKN) && afi != AFI_IP)
  {
    vty_out (vty, "%% Cannot specify IPv4 address or prefix with IPv6 AFI%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  prefix = argv[idx]->arg;

  /* [<bestpath|multipath>] */
  if (argv_find (argv, argc, "bestpath", &idx))
    path_type = BGP_PATH_BESTPATH;
  else if (argv_find (argv, argc, "multipath", &idx))
    path_type = BGP_PATH_MULTIPATH;
  else
    path_type = BGP_PATH_ALL;

  return bgp_show_route (vty, vrf, prefix, afi, safi, NULL, prefix_check, path_type, uj);
}

DEFUN (show_ip_bgp_regexp,
       show_ip_bgp_regexp_cmd,
       "show [ip] bgp [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] regexp REGEX...",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  afi_t afi = AFI_IP6;
  safi_t safi = SAFI_UNICAST;

  int idx = 0;

  /* [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] */
  if (argv_find (argv, argc, "ipv4", &idx) || argv_find (argv, argc, "ipv6", &idx))
  {
    afi = strmatch(argv[idx]->text, "ipv6") ? AFI_IP6 : AFI_IP;
    if (argv_find (argv, argc, "unicast", &idx) || argv_find (argv, argc, "multicast", &idx))
      safi = strmatch (argv[idx]->text, "unicast") ? SAFI_UNICAST : SAFI_MULTICAST;
  }
  else if (argv_find (argv, argc, "encap", &idx) || argv_find (argv, argc, "vpnv4", &idx))
  {
    afi = AFI_IP;
    safi = strmatch (argv[idx]->text, "encap") ? SAFI_ENCAP : SAFI_MPLS_VPN;
    // advance idx if necessary
    argv_find (argv, argc, "unicast", &idx);
  }

  // get index of regex
  argv_find (argv, argc, "regexp", &idx);
  idx++;

  char *regstr = argv_concat (argv, argc, idx);
  int rc = bgp_show_regexp (vty, (const char *) regstr, afi, safi, bgp_show_type_regexp);
  XFREE (MTYPE_TMP, regstr);
  return rc;
}

DEFUN (show_ip_bgp_instance_all,
       show_ip_bgp_instance_all_cmd,
       "show [ip] bgp <view|vrf> all [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       JSON_STR)
{
  afi_t afi = AFI_IP;
  safi_t safi = SAFI_UNICAST;

  int idx = 0;

  /* show [ip] bgp */
  if (argv_find (argv, argc, "ip", &idx))
    afi = AFI_IP;
  /* [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] */
  if (argv_find (argv, argc, "ipv4", &idx) || argv_find (argv, argc, "ipv6", &idx))
  {
    afi = strmatch(argv[idx]->text, "ipv6") ? AFI_IP6 : AFI_IP;
    if (argv_find (argv, argc, "unicast", &idx) || argv_find (argv, argc, "multicast", &idx))
      safi = strmatch (argv[idx]->text, "unicast") ? SAFI_UNICAST : SAFI_MULTICAST;
  }
  else if (argv_find (argv, argc, "encap", &idx) || argv_find (argv, argc, "vpnv4", &idx))
  {
    afi = AFI_IP;
    safi = strmatch (argv[idx]->text, "encap") ? SAFI_ENCAP : SAFI_MPLS_VPN;
    // advance idx if necessary
    argv_find (argv, argc, "unicast", &idx);
  }

  u_char uj = use_json(argc, argv);

  bgp_show_all_instances_routes_vty (vty, afi, safi, uj);
  return CMD_SUCCESS;
}


static int
bgp_show_regexp (struct vty *vty, const char *regstr, afi_t afi,
		 safi_t safi, enum bgp_show_type type)
{
  return CMD_SUCCESS;

  regex_t *regex;
  int rc;
  
  regex = bgp_regcomp (regstr);
  if (! regex)
    {
      vty_out (vty, "Can't compile regexp %s%s", regstr, VTY_NEWLINE);
      return CMD_WARNING;
    }

  rc = bgp_show (vty, NULL, afi, safi, type, regex, 0);
  bgp_regex_free (regex);
  return rc;
}

static int
bgp_show_prefix_list (struct vty *vty, const char *name,
                      const char *prefix_list_str, afi_t afi,
		      safi_t safi, enum bgp_show_type type)
{
  struct prefix_list *plist;
  struct bgp *bgp = NULL;

  if (name && !(bgp = bgp_lookup_by_name(name)))
    {
      vty_out (vty, "%% No such BGP instance exists%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  plist = prefix_list_lookup (afi, prefix_list_str);
  if (plist == NULL)
    {
      vty_out (vty, "%% %s is not a valid prefix-list name%s",
               prefix_list_str, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, bgp, afi, safi, type, plist, 0);
}

static int
bgp_show_filter_list (struct vty *vty, const char *name,
                      const char *filter, afi_t afi,
		      safi_t safi, enum bgp_show_type type)
{
  struct as_list *as_list;
  struct bgp *bgp = NULL;

  if (name && !(bgp = bgp_lookup_by_name(name)))
    {
      vty_out (vty, "%% No such BGP instance exists%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  as_list = as_list_lookup (filter);
  if (as_list == NULL)
    {
      vty_out (vty, "%% %s is not a valid AS-path access-list name%s", filter, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, bgp, afi, safi, type, as_list, 0);
}

DEFUN (show_ip_bgp_dampening_info,
       show_ip_bgp_dampening_params_cmd,
       "show [ip] bgp dampening parameters",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display detailed information about dampening\n"
       "Display detail of configured dampening parameters\n")
{
    return bgp_show_dampening_parameters (vty, AFI_IP, SAFI_UNICAST);
}


DEFUN (show_ip_bgp_ipv4_dampening_parameters,
       show_ip_bgp_ipv4_dampening_parameters_cmd,
       "show [ip] bgp ipv4 <unicast|multicast> dampening parameters",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display detailed information about dampening\n"
       "Display detail of configured dampening parameters\n")
{
  int idx_safi = 4;
    if (strncmp(argv[idx_safi]->arg, "m", 1) == 0)
      return bgp_show_dampening_parameters (vty, AFI_IP, SAFI_MULTICAST);

    return bgp_show_dampening_parameters (vty, AFI_IP, SAFI_UNICAST);
}

static int
bgp_show_route_map (struct vty *vty, const char *name,
                    const char *rmap_str, afi_t afi,
		    safi_t safi, enum bgp_show_type type)
{
  struct route_map *rmap;
  struct bgp *bgp = NULL;

  if (name && !(bgp = bgp_lookup_by_name(name)))
    {


      vty_out (vty, "%% No such BGP instance exists%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rmap = route_map_lookup_by_name (rmap_str);
  if (! rmap)
    {
      vty_out (vty, "%% %s is not a valid route-map name%s",
	       rmap_str, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  return bgp_show (vty, bgp, afi, safi, type, rmap, 0);
}

static int
bgp_show_community (struct vty *vty, const char *view_name, int argc,
		    struct cmd_token **argv, int exact, afi_t afi, safi_t safi)
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
	  vty_out (vty, "Can't find BGP instance %s%s", view_name, VTY_NEWLINE);
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
	  if ((strcmp (argv[i]->arg, "unicast") == 0) || (strcmp (argv[i]->arg, "multicast") == 0))
	    continue;
	  first = 1;
	}
      
      buffer_putstr (b, argv[i]->arg);
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

static int
bgp_show_community_list (struct vty *vty, const char *name,
                         const char *com, int exact,
			 afi_t afi, safi_t safi)
{
  struct community_list *list;
  struct bgp *bgp = NULL;

  if (name && !(bgp = bgp_lookup_by_name(name)))
    {
      vty_out (vty, "%% No such BGP instance exists%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  list = community_list_lookup (bgp_clist, com, COMMUNITY_LIST_MASTER);
  if (list == NULL)
    {
      vty_out (vty, "%% %s is not a valid community-list name%s", com,
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, bgp, afi, safi,
                   (exact ? bgp_show_type_community_list_exact :
		    bgp_show_type_community_list), list, 0);
}

static int
bgp_show_prefix_longer (struct vty *vty, const char *name,
                        const char *prefix, afi_t afi,
			safi_t safi, enum bgp_show_type type)
{
  int ret;
  struct prefix *p;
  struct bgp *bgp = NULL;

  if (name && !(bgp = bgp_lookup_by_name(name)))
    {
      vty_out (vty, "%% No such BGP instance exists%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  p = prefix_new();

  ret = str2prefix (prefix, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = bgp_show (vty, bgp, afi, safi, type, p, 0);
  prefix_free(p);
  return ret;
}

static struct peer *
peer_lookup_in_view (struct vty *vty, const char *view_name, 
                     const char *ip_str, u_char use_json)
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
          if (use_json)
            {
              json_object *json_no = NULL;
              json_no = json_object_new_object();
              json_object_string_add(json_no, "warning", "Can't find BGP view");
              vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
              json_object_free(json_no);
            }
          else
            vty_out (vty, "Can't find BGP instance %s%s", view_name, VTY_NEWLINE);
          return NULL;
        }      
    }
  else
    {
      bgp = bgp_get_default ();
      if (! bgp)
        {
          if (use_json)
            {
              json_object *json_no = NULL;
              json_no = json_object_new_object();
              json_object_string_add(json_no, "warning", "No BGP process configured");
              vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
              json_object_free(json_no);
            }
          else
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
          peer = peer_lookup_by_hostname(bgp, ip_str);

          if (!peer)
            {
              if (use_json)
                {
                  json_object *json_no = NULL;
                  json_no = json_object_new_object();
                  json_object_string_add(json_no, "malformedAddressOrName", ip_str);
                  vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
                  json_object_free(json_no);
                }
              else
                vty_out (vty, "%% Malformed address or name: %s%s", ip_str, VTY_NEWLINE);
              return NULL;
            }
        }
      return peer;
    }

  /* Peer structure lookup. */
  peer = peer_lookup (bgp, &su);
  if (! peer)
    {
      if (use_json)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning","No such neighbor");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
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
      vty_out (vty, "%% No RIB exist's for the AFI(%d)/SAFI(%d)%s",
	       afi, safi, VTY_NEWLINE);
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
      else if (strncmp (safi_str, "e", 1) == 0)
        safi = SAFI_ENCAP;
      else if (strncmp (safi_str, "vpnv4", 5) == 0 || strncmp (safi_str, "vpnv6", 5) == 0)
        safi = SAFI_MPLS_VPN;
      else
        {
          vty_out (vty, "%% Invalid subsequent address family %s%s",
                   safi_str, VTY_NEWLINE);
            return CMD_WARNING;
      }
    }
  else
    {
      vty_out (vty, "%% Invalid address family \"%s\"%s",
               afi_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_table_stats (vty, bgp, afi, safi);
}

DEFUN (show_bgp_statistics,
       show_bgp_statistics_cmd,
       "show [ip] bgp <ipv4|ipv6> <encap|multicast|unicast|vpn> statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  int idx_afi = 2;
  int idx_safi = 3;
  return bgp_table_stats_vty (vty, NULL, argv[idx_afi]->arg, argv[idx_safi]->arg);
}

DEFUN (show_bgp_statistics_view,
       show_bgp_statistics_view_cmd,
       "show [ip] bgp <view|vrf> WORD <ipv4|ipv6> <unicast|multicast|vpn|encap> statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address Family\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  int idx_word = 3;
  int idx_afi = 4;
  return bgp_table_stats_vty (vty, NULL, argv[idx_word]->arg, argv[idx_afi]->arg);
}

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
bgp_peer_counts (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi, u_char use_json)
{
  struct peer_pcounts pcounts = { .peer = peer };
  unsigned int i;
  json_object *json = NULL;
  json_object *json_loop = NULL;

  if (use_json)
    {
      json = json_object_new_object();
      json_loop = json_object_new_object();
    }
  
  if (!peer || !peer->bgp || !peer->afc[afi][safi]
      || !peer->bgp->rib[afi][safi])
    {
      if (use_json)
        {
          json_object_string_add(json, "warning", "No such neighbor or address family");
          vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
          json_object_free(json);
        }
      else
        vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);

      return CMD_WARNING;
    }
  
  memset (&pcounts, 0, sizeof(pcounts));
  pcounts.peer = peer;
  pcounts.table = peer->bgp->rib[afi][safi];
  
  /* in-place call via thread subsystem so as to record execution time
 *    * stats for the thread-walk (i.e. ensure this can't be blamed on
 *       * on just vty_read()).
 *          */
  thread_execute (bm->master, bgp_peer_count_walker, &pcounts, 0);

  if (use_json)
    {
      json_object_string_add(json, "prefixCountsFor", peer->host);
      json_object_string_add(json, "multiProtocol", afi_safi_print (afi, safi));
      json_object_int_add(json, "pfxCounter", peer->pcount[afi][safi]);

      for (i = 0; i < PCOUNT_MAX; i++)
        json_object_int_add(json_loop, pcount_strs[i], pcounts.count[i]);

      json_object_object_add(json, "ribTableWalkCounters", json_loop);

      if (pcounts.count[PCOUNT_PFCNT] != peer->pcount[afi][safi])
        {
          json_object_string_add(json, "pfxctDriftFor", peer->host);
          json_object_string_add(json, "recommended", "Please report this bug, with the above command output");
        }
      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  else
    {

      if (peer->hostname && bgp_flag_check(peer->bgp, BGP_FLAG_SHOW_HOSTNAME))
        {
          vty_out (vty, "Prefix counts for %s/%s, %s%s",
                   peer->hostname, peer->host, afi_safi_print (afi, safi),
                   VTY_NEWLINE);
        }
      else
        {
          vty_out (vty, "Prefix counts for %s, %s%s",
                   peer->host, afi_safi_print (afi, safi), VTY_NEWLINE);
        }

      vty_out (vty, "PfxCt: %ld%s", peer->pcount[afi][safi], VTY_NEWLINE);
      vty_out (vty, "%sCounts from RIB table walk:%s%s",
               VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

      for (i = 0; i < PCOUNT_MAX; i++)
        vty_out (vty, "%20s: %-10d%s", pcount_strs[i], pcounts.count[i], VTY_NEWLINE);

      if (pcounts.count[PCOUNT_PFCNT] != peer->pcount[afi][safi])
        {
          vty_out (vty, "%s [pcount] PfxCt drift!%s",
                   peer->host, VTY_NEWLINE);
          vty_out (vty, "Please report this bug, with the above command output%s",
                   VTY_NEWLINE);
        }
    }
               
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbor_prefix_counts,
       show_ip_bgp_neighbor_prefix_counts_cmd,
       "show [ip] bgp neighbors <A.B.C.D|X:X::X:X|WORD> prefix-counts [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display detailed prefix count information\n"
       JSON_STR)
{
  int idx_peer = 4;
  struct peer *peer;
  u_char uj = use_json(argc, argv);

  peer = peer_lookup_in_view (vty, NULL, argv[idx_peer]->arg, uj);
  if (! peer) 
    return CMD_WARNING;
 
  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST, uj);
}

DEFUN (show_ip_bgp_instance_neighbor_prefix_counts,
       show_ip_bgp_instance_neighbor_prefix_counts_cmd,
       "show [ip] bgp <view|vrf> WORD neighbors <A.B.C.D|X:X::X:X|WORD> prefix-counts [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display detailed prefix count information\n"
       JSON_STR)
{
  int idx_word = 4;
  int idx_peer = 6;
  struct peer *peer;
  u_char uj = use_json(argc, argv);

  peer = peer_lookup_in_view (vty, argv[idx_word]->arg, argv[idx_peer]->arg, uj);
  if (! peer)
    return CMD_WARNING;

  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST, uj);
}

DEFUN (show_bgp_ipv6_neighbor_prefix_counts,
       show_bgp_ipv6_neighbor_prefix_counts_cmd,
       "show [ip] bgp ipv6 neighbors <A.B.C.D|X:X::X:X|WORD> prefix-counts [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display detailed prefix count information\n"
       JSON_STR)
{
  int idx_peer = 4;
  struct peer *peer;
  u_char uj = use_json(argc, argv);

  peer = peer_lookup_in_view (vty, NULL, argv[idx_peer]->arg, uj);
  if (! peer) 
    return CMD_WARNING;
 
  return bgp_peer_counts (vty, peer, AFI_IP6, SAFI_UNICAST, uj);
}

DEFUN (show_bgp_instance_ipv6_neighbor_prefix_counts,
       show_bgp_instance_ipv6_neighbor_prefix_counts_cmd,
       "show [ip] bgp <view|vrf> WORD ipv6 neighbors <A.B.C.D|X:X::X:X|WORD> prefix-counts [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address Family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display detailed prefix count information\n"
       JSON_STR)
{
  int idx_word = 3;
  int idx_peer = 6;
  struct peer *peer;
  u_char uj = use_json(argc, argv);

  peer = peer_lookup_in_view (vty, argv[idx_word]->arg, argv[idx_peer]->arg, uj);
  if (! peer)
    return CMD_WARNING;

  return bgp_peer_counts (vty, peer, AFI_IP6, SAFI_UNICAST, uj);
}

DEFUN (show_ip_bgp_ipv4_neighbor_prefix_counts,
       show_ip_bgp_ipv4_neighbor_prefix_counts_cmd,
       "show [ip] bgp ipv4 <unicast|multicast> neighbors <A.B.C.D|X:X::X:X|WORD> prefix-counts [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display detailed prefix count information\n"
       JSON_STR)
{
  int idx_safi = 4;
  int idx_peer = 6;
  struct peer *peer;
  u_char uj = use_json(argc, argv);

  peer = peer_lookup_in_view (vty, NULL, argv[idx_peer]->arg, uj);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[idx_safi]->arg, "m", 1) == 0)
    return bgp_peer_counts (vty, peer, AFI_IP, SAFI_MULTICAST, uj);

  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST, uj);
}

DEFUN (show_ip_bgp_vpnv4_neighbor_prefix_counts,
       show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd,
       "show [ip] bgp vpnv4 all neighbors <A.B.C.D|X:X::X:X|WORD> prefix-counts [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display detailed prefix count information\n"
       JSON_STR)
{
  int idx_peer = 6;
  struct peer *peer;
  u_char uj = use_json(argc, argv);

  peer = peer_lookup_in_view (vty, NULL, argv[idx_peer]->arg, uj);
  if (! peer)
    return CMD_WARNING;
  
  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_MPLS_VPN, uj);
}

DEFUN (show_ip_bgp_vpnv4_all_route_prefix,
       show_ip_bgp_vpnv4_all_route_prefix_cmd,
       "show [ip] bgp vpnv4 all <A.B.C.D|A.B.C.D/M> [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Display information about all VPNv4 NLRIs\n"
       "Network in the BGP routing table to display\n"
       "Network in the BGP routing table to display\n"
       JSON_STR)
{
  int idx = 0;
  char *network = NULL;
  network = argv_find (argv, argc, "A.B.C.D", &idx) ? argv[idx]->arg : NULL;
  network = argv_find (argv, argc, "A.B.C.D/M", &idx) ? argv[idx]->arg : NULL;
  return bgp_show_route (vty, NULL, network, AFI_IP, SAFI_MPLS_VPN, NULL, 0, BGP_PATH_ALL, use_json(argc, argv));
}

static void
show_adj_route (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
                int in, const char *rmap_name, u_char use_json, json_object *json)
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
  struct update_subgroup *subgrp;
  json_object *json_scode = NULL;
  json_object *json_ocode = NULL;
  json_object *json_ar = NULL;
  struct peer_af *paf;

  if (use_json)
    {
      json_scode = json_object_new_object();
      json_ocode = json_object_new_object();
      json_ar = json_object_new_object();

      json_object_string_add(json_scode, "suppressed", "s");
      json_object_string_add(json_scode, "damped", "d");
      json_object_string_add(json_scode, "history", "h");
      json_object_string_add(json_scode, "valid", "*");
      json_object_string_add(json_scode, "best", ">");
      json_object_string_add(json_scode, "multipath", "=");
      json_object_string_add(json_scode, "internal", "i");
      json_object_string_add(json_scode, "ribFailure", "r");
      json_object_string_add(json_scode, "stale", "S");
      json_object_string_add(json_scode, "removed", "R");

      json_object_string_add(json_ocode, "igp", "i");
      json_object_string_add(json_ocode, "egp", "e");
      json_object_string_add(json_ocode, "incomplete", "?");
    }

  bgp = peer->bgp;

  if (! bgp)
    {
      if (use_json)
        {
          json_object_string_add(json, "alert", "no BGP");
          vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
          json_object_free(json);
        }
      else
        vty_out (vty, "%% No bgp%s", VTY_NEWLINE);
      return;
    }

  table = bgp->rib[afi][safi];

  output_count = filtered_count = 0;
  subgrp = peer_subgroup(peer, afi, safi);

  if (!in && subgrp && CHECK_FLAG (subgrp->sflags, SUBGRP_STATUS_DEFAULT_ORIGINATE))
    {
      if (use_json)
        {
          json_object_int_add(json, "bgpTableVersion", table->version);
          json_object_string_add(json, "bgpLocalRouterId", inet_ntoa (bgp->router_id));
          json_object_object_add(json, "bgpStatusCodes", json_scode);
          json_object_object_add(json, "bgpOriginCodes", json_ocode);
          json_object_string_add(json, "bgpOriginatingDefaultNetwork", "0.0.0.0");
        }
      else
        {
          vty_out (vty, "BGP table version is %" PRIu64 ", local router ID is %s%s", table->version, inet_ntoa (bgp->router_id), VTY_NEWLINE);
          vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
          vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);

          vty_out (vty, "Originating default network 0.0.0.0%s%s",
                   VTY_NEWLINE, VTY_NEWLINE);
        }
      header1 = 0;
    }

  attr.extra = &extra;
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      if (in)
        {
          for (ain = rn->adj_in; ain; ain = ain->next)
            {
              if (ain->peer == peer)
                {
                  if (header1)
                    {
                      if (use_json)
                        {
                          json_object_int_add(json, "bgpTableVersion", 0);
                          json_object_string_add(json, "bgpLocalRouterId", inet_ntoa (bgp->router_id));
                          json_object_object_add(json, "bgpStatusCodes", json_scode);
                          json_object_object_add(json, "bgpOriginCodes", json_ocode);
                        }
                      else
                        {
                          vty_out (vty, "BGP table version is 0, local router ID is %s%s", inet_ntoa (bgp->router_id), VTY_NEWLINE);
                          vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                          vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                        }
                      header1 = 0;
                    }
                  if (header2)
                    {
                      if (!use_json)
                        vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
                      header2 = 0;
                    }
                  if (ain->attr)
                    {
                      bgp_attr_dup(&attr, ain->attr);
                      if (bgp_input_modifier(peer, &rn->p, &attr, afi, safi, rmap_name) != RMAP_DENY)
                        {
                          route_vty_out_tmp (vty, &rn->p, &attr, safi, use_json, json_ar);
                          output_count++;
                        }
                      else
                        filtered_count++;
                    }
                }
            }
        }
      else
        {
          for (adj = rn->adj_out; adj; adj = adj->next)
            SUBGRP_FOREACH_PEER(adj->subgroup, paf)
              if (paf->peer == peer)
                {
                  if (header1)
                    {
                      if (use_json)
                        {
                          json_object_int_add(json, "bgpTableVersion", table->version);
                          json_object_string_add(json, "bgpLocalRouterId", inet_ntoa (bgp->router_id));
                          json_object_object_add(json, "bgpStatusCodes", json_scode);
                          json_object_object_add(json, "bgpOriginCodes", json_ocode);
                        }
                      else
                        {
                          vty_out (vty, "BGP table version is %" PRIu64 ", local router ID is %s%s", table->version,
                                   inet_ntoa (bgp->router_id), VTY_NEWLINE);
                          vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                          vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                        }
                      header1 = 0;
                    }

                  if (header2)
                    {
                      if (!use_json)
                        vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
                      header2 = 0;
                    }

                  if (adj->attr)
                    {
                      bgp_attr_dup(&attr, adj->attr);
                      ret = bgp_output_modifier(peer, &rn->p, &attr, afi, safi, rmap_name);
                      if (ret != RMAP_DENY)
                        {
                          route_vty_out_tmp (vty, &rn->p, &attr, safi, use_json, json_ar);
                          output_count++;
                        }
                      else
                        filtered_count++;
                    }
                }
        }
    }
  if (use_json)
    json_object_object_add(json, "advertisedRoutes", json_ar);

  if (output_count != 0)
    {
      if (use_json)
        json_object_int_add(json, "totalPrefixCounter", output_count);
      else
        vty_out (vty, "%sTotal number of prefixes %ld%s",
                 VTY_NEWLINE, output_count, VTY_NEWLINE);
    }
  if (use_json)
    {
      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }

}

static int
peer_adj_routes (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
                 int in, const char *rmap_name, u_char use_json)
{
  json_object *json = NULL;

  if (use_json)
    json = json_object_new_object();

  if (!peer || !peer->afc[afi][safi])
    {
      if (use_json)
        {
          json_object_string_add(json, "warning", "No such neighbor or address family");
          vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
          json_object_free(json);
        }
      else
        vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);

      return CMD_WARNING;
    }

  if (in && !CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
    {
      if (use_json)
        {
          json_object_string_add(json, "warning", "Inbound soft reconfiguration not enabled");
          vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
          json_object_free(json);
        }
      else
        vty_out (vty, "%% Inbound soft reconfiguration not enabled%s", VTY_NEWLINE);

      return CMD_WARNING;
    }

  show_adj_route (vty, peer, afi, safi, in, rmap_name, use_json, json);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_instance_neighbor_advertised_route,
       show_ip_bgp_instance_neighbor_advertised_route_cmd,
       "show [ip] bgp [<view|vrf> WORD] [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] neighbors <A.B.C.D|X:X::X:X|WORD> [<received-routes|advertised-routes> [route-map WORD]] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display the received routes from neighbor\n"
       "Display the routes advertised to a BGP neighbor\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n"
       JSON_STR)
{
  afi_t afi = AFI_IP6;
  safi_t safi = SAFI_UNICAST;
  char *vrf = NULL;
  char *rmap_name = NULL;
  char *peerstr = NULL;
  int rcvd = 0;

  struct peer *peer;

  int idx = 0;

  /* show [ip] bgp */
  if (argv_find (argv, argc, "ip", &idx))
    afi = AFI_IP;
  /* [<view|vrf> WORD] */
  if (argv_find (argv, argc, "view", &idx) || argv_find (argv, argc, "vrf", &idx))
    vrf = argv[++idx]->arg;
  /* [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] */
  if (argv_find (argv, argc, "ipv4", &idx) || argv_find (argv, argc, "ipv6", &idx))
  {
    afi = strmatch(argv[idx]->text, "ipv6") ? AFI_IP6 : AFI_IP;
    if (argv_find (argv, argc, "unicast", &idx) || argv_find (argv, argc, "multicast", &idx))
      safi = strmatch (argv[idx]->text, "unicast") ? SAFI_UNICAST : SAFI_MULTICAST;
  }
  else if (argv_find (argv, argc, "encap", &idx) || argv_find (argv, argc, "vpnv4", &idx))
  {
    afi = AFI_IP;
    safi = strmatch (argv[idx]->text, "encap") ? SAFI_ENCAP : SAFI_MPLS_VPN;
    // advance idx if necessary
    argv_find (argv, argc, "unicast", &idx);
  }

  /* neighbors <A.B.C.D|X:X::X:X|WORD> */
  argv_find (argv, argc, "neighbors", &idx);
  peerstr = argv[++idx]->arg;

  u_char uj = use_json(argc, argv);

  peer = peer_lookup_in_view (vty, vrf, peerstr, uj);

  if (! peer) 
    {
      vty_out (vty, "No such neighbor%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argv_find (argv, argc, "received-routes", &idx))
    rcvd = 1;
  if (argv_find (argv, argc, "advertised-routes", &idx))
    rcvd = 0;
  if (argv_find (argv, argc, "route-map", &idx))
    rmap_name = argv[++idx]->arg;

  return peer_adj_routes (vty, peer, afi, safi, rcvd, rmap_name, uj);
}

DEFUN (show_ip_bgp_neighbor_received_prefix_filter,
       show_ip_bgp_neighbor_received_prefix_filter_cmd,
       "show [ip] bgp [<ipv4|ipv6> [unicast]] neighbors <A.B.C.D|X:X::X:X|WORD> received prefix-filter [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address Family\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n"
       JSON_STR)
{
  afi_t afi = AFI_IP6;
  safi_t safi = SAFI_UNICAST;
  char *peerstr = NULL;

  char name[BUFSIZ];
  union sockunion su;
  struct peer *peer;
  int count, ret;

  int idx = 0;

  /* show [ip] bgp */
  if (argv_find (argv, argc, "ip", &idx))
    afi = AFI_IP;
  /* [<ipv4|ipv6> [unicast]] */
  if (argv_find (argv, argc, "ipv4", &idx))
    afi = AFI_IP;
  if (argv_find (argv, argc, "ipv6", &idx))
    afi = AFI_IP6;
  /* neighbors <A.B.C.D|X:X::X:X|WORD> */
  argv_find (argv, argc, "neighbors", &idx);
  peerstr = argv[++idx]->arg;

  u_char uj = use_json(argc, argv);

  ret = str2sockunion (peerstr, &su);
  if (ret < 0)
    {
      peer = peer_lookup_by_conf_if (NULL, peerstr);
      if (! peer)
        {
          if (uj)
            vty_out (vty, "{}%s", VTY_NEWLINE);
          else
            vty_out (vty, "%% Malformed address or name: %s%s", peerstr, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      peer = peer_lookup (NULL, &su);
      if (! peer)
        {
          if (uj)
            vty_out (vty, "{}%s", VTY_NEWLINE);
          else
            vty_out (vty, "No peer%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  sprintf (name, "%s.%d.%d", peer->host, afi, safi);
  count =  prefix_bgp_show_prefix_list (NULL, afi, name, uj);
  if (count)
    {
      if (!uj)
        vty_out (vty, "Address Family: %s%s", afi_safi_print(afi, safi), VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, afi, name, uj);
    }
  else
    {
      if (uj)
        vty_out (vty, "{}%s", VTY_NEWLINE);
      else
        vty_out (vty, "No functional output%s", VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

static int
bgp_show_neighbor_route (struct vty *vty, struct peer *peer, afi_t afi,
			 safi_t safi, enum bgp_show_type type, u_char use_json)
{
  if (! peer || ! peer->afc[afi][safi])
    {
      if (use_json)
        {
          json_object *json_no = NULL;
          json_no = json_object_new_object();
          json_object_string_add(json_no, "warning", "No such neighbor or address family");
          vty_out (vty, "%s%s", json_object_to_json_string(json_no), VTY_NEWLINE);
          json_object_free(json_no);
        }
      else
        vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, peer->bgp, afi, safi, type, &peer->su, use_json);
}

DEFUN (show_ip_bgp_neighbor_routes,
       show_ip_bgp_neighbor_routes_cmd,
       "show [ip] bgp [<view|vrf> WORD] [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] neighbors <A.B.C.D|X:X::X:X|WORD> <flap-statistics|dampened-routes|routes> [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Address Family\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display flap statistics of the routes learned from neighbor\n"
       "Display the dampened routes received from neighbor\n"
       "Display routes learned from neighbor\n"
       JSON_STR)
{
  char *vrf = NULL;
  char *peerstr = NULL;

  afi_t afi = AFI_IP6;
  safi_t safi = SAFI_UNICAST;
  struct peer *peer;
  enum bgp_show_type sh_type = bgp_show_type_neighbor;

  int idx = 0;

  /* show [ip] bgp */
  if (argv_find (argv, argc, "ip", &idx))
    afi = AFI_IP;
  /* [<view|vrf> WORD] */
  if (argv_find (argv, argc, "view", &idx) || argv_find (argv, argc, "vrf", &idx))
    vrf = argv[++idx]->arg;
  /* [<ipv4 [<unicast|multicast>]|ipv6 [<unicast|multicast>]|encap [unicast]|vpnv4 [unicast]>] */
  if (argv_find (argv, argc, "ipv4", &idx) || argv_find (argv, argc, "ipv6", &idx))
  {
    afi = strmatch(argv[idx]->text, "ipv6") ? AFI_IP6 : AFI_IP;
    if (argv_find (argv, argc, "unicast", &idx) || argv_find (argv, argc, "multicast", &idx))
      safi = strmatch (argv[idx]->text, "unicast") ? SAFI_UNICAST : SAFI_MULTICAST;
  }
  else if (argv_find (argv, argc, "encap", &idx) || argv_find (argv, argc, "vpnv4", &idx))
  {
    afi = AFI_IP;
    safi = strmatch (argv[idx]->text, "encap") ? SAFI_ENCAP : SAFI_MPLS_VPN;
    // advance idx if necessary
    argv_find (argv, argc, "unicast", &idx);
  }
  /* neighbors <A.B.C.D|X:X::X:X|WORD> */
  argv_find (argv, argc, "neighbors", &idx);
  peerstr = argv[++idx]->arg;

  u_char uj = use_json(argc, argv);

  peer = peer_lookup_in_view (vty, vrf, peerstr, uj);
  if (! peer)
    {
      vty_out (vty, "No such neighbor%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argv_find (argv, argc, "flap-statistics", &idx))
    sh_type = bgp_show_type_flap_neighbor;
  else if (argv_find (argv, argc, "dampened-routes", &idx))
    sh_type = bgp_show_type_damp_neighbor;
  else if (argv_find (argv, argc, "routes", &idx))
    sh_type = bgp_show_type_neighbor;

  return bgp_show_neighbor_route (vty, peer, afi, safi, sh_type, uj);
}

struct bgp_table *bgp_distance_table[AFI_MAX][SAFI_MAX];

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
  afi_t afi;
  safi_t safi;
  struct prefix p;
  u_char distance;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  afi = bgp_node_afi (vty);
  safi = bgp_node_safi (vty);

  ret = str2prefix (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  /* Get BGP distance node. */
  rn = bgp_node_get (bgp_distance_table[afi][safi], (struct prefix *) &p);
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
      XFREE(MTYPE_AS_LIST, bdistance->access_list);
      bdistance->access_list = NULL;
    }
  if (access_list_str)
    bdistance->access_list = XSTRDUP(MTYPE_AS_LIST, access_list_str);

  return CMD_SUCCESS;
}

static int
bgp_distance_unset (struct vty *vty, const char *distance_str, 
                    const char *ip_str, const char *access_list_str)
{
  int ret;
  afi_t afi;
  safi_t safi;
  struct prefix p;
  int distance;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  afi = bgp_node_afi (vty);
  safi = bgp_node_safi (vty);

  ret = str2prefix (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = bgp_node_lookup (bgp_distance_table[afi][safi], (struct prefix *)&p);
  if (! rn)
    {
      vty_out (vty, "Can't find specified prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bdistance = rn->info;
  distance = atoi(distance_str);

  if (bdistance->distance != distance)
    {
       vty_out (vty, "Distance does not match configured%s", VTY_NEWLINE);
       return CMD_WARNING;
    }

  if (bdistance->access_list)
    XFREE(MTYPE_AS_LIST, bdistance->access_list);
  bgp_distance_free (bdistance);

  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

/* Apply BGP information to distance method. */
u_char
bgp_distance_apply (struct prefix *p, struct bgp_info *rinfo, afi_t afi,
		    safi_t safi, struct bgp *bgp)
{
  struct bgp_node *rn;
  struct prefix q;
  struct peer *peer;
  struct bgp_distance *bdistance;
  struct access_list *alist;
  struct bgp_static *bgp_static;

  if (! bgp)
    return 0;

  peer = rinfo->peer;

  /* Check source address. */
  sockunion2hostprefix (&peer->su, &q);
  rn = bgp_node_match (bgp_distance_table[afi][safi], &q);
  if (rn)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);

      if (bdistance->access_list)
	{
	  alist = access_list_lookup (afi, bdistance->access_list);
	  if (alist && access_list_apply (alist, p) == FILTER_PERMIT)
	    return bdistance->distance;
	}
      else
	return bdistance->distance;
    }

  /* Backdoor check. */
  rn = bgp_node_lookup (bgp->route[afi][safi], p);
  if (rn)
    {
      bgp_static = rn->info;
      bgp_unlock_node (rn);

      if (bgp_static->backdoor)
	{
	  if (bgp->distance_local[afi][safi])
	    return bgp->distance_local[afi][safi];
	  else
	    return ZEBRA_IBGP_DISTANCE_DEFAULT;
	}
    }

  if (peer->sort == BGP_PEER_EBGP)
    {
      if (bgp->distance_ebgp[afi][safi])
	return bgp->distance_ebgp[afi][safi];
      return ZEBRA_EBGP_DISTANCE_DEFAULT;
    }
  else
    {
      if (bgp->distance_ibgp[afi][safi])
	return bgp->distance_ibgp[afi][safi];
      return ZEBRA_IBGP_DISTANCE_DEFAULT;
    }
}

DEFUN (bgp_distance,
       bgp_distance_cmd,
       "distance bgp (1-255) (1-255) (1-255)",
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  int idx_number = 2;
  int idx_number_2 = 3;
  int idx_number_3 = 4;
  afi_t afi;
  safi_t safi;

  afi = bgp_node_afi (vty);
  safi = bgp_node_safi (vty);

  bgp->distance_ebgp[afi][safi] = atoi (argv[idx_number]->arg);
  bgp->distance_ibgp[afi][safi] = atoi (argv[idx_number_2]->arg);
  bgp->distance_local[afi][safi] = atoi (argv[idx_number_3]->arg);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance,
       no_bgp_distance_cmd,
       "no distance bgp [(1-255) (1-255) (1-255)]",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  afi_t afi;
  safi_t safi;

  afi = bgp_node_afi (vty);
  safi = bgp_node_safi (vty);

  bgp->distance_ebgp[afi][safi] = 0;
  bgp->distance_ibgp[afi][safi] = 0;
  bgp->distance_local[afi][safi] = 0;
  return CMD_SUCCESS;
}


DEFUN (bgp_distance_source,
       bgp_distance_source_cmd,
       "distance (1-255) A.B.C.D/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  int idx_number = 1;
  int idx_ipv4_prefixlen = 2;
  bgp_distance_set (vty, argv[idx_number]->arg, argv[idx_ipv4_prefixlen]->arg, NULL);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source,
       no_bgp_distance_source_cmd,
       "no distance (1-255) A.B.C.D/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  int idx_number = 2;
  int idx_ipv4_prefixlen = 3;
  bgp_distance_unset (vty, argv[idx_number]->arg, argv[idx_ipv4_prefixlen]->arg, NULL);
  return CMD_SUCCESS;
}

DEFUN (bgp_distance_source_access_list,
       bgp_distance_source_access_list_cmd,
       "distance (1-255) A.B.C.D/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  int idx_number = 1;
  int idx_ipv4_prefixlen = 2;
  int idx_word = 3;
  bgp_distance_set (vty, argv[idx_number]->arg, argv[idx_ipv4_prefixlen]->arg, argv[idx_word]->arg);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source_access_list,
       no_bgp_distance_source_access_list_cmd,
       "no distance (1-255) A.B.C.D/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  int idx_number = 2;
  int idx_ipv4_prefixlen = 3;
  int idx_word = 4;
  bgp_distance_unset (vty, argv[idx_number]->arg, argv[idx_ipv4_prefixlen]->arg, argv[idx_word]->arg);
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_distance_source,
       ipv6_bgp_distance_source_cmd,
       "distance (1-255) X:X::X:X/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_set (vty, argv[1]->arg, argv[2]->arg, NULL);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_distance_source,
       no_ipv6_bgp_distance_source_cmd,
       "no distance (1-255) X:X::X:X/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_unset (vty, argv[2]->arg, argv[3]->arg, NULL);
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_distance_source_access_list,
       ipv6_bgp_distance_source_access_list_cmd,
       "distance (1-255) X:X::X:X/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_set (vty, argv[1]->arg, argv[2]->arg, argv[3]->arg);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_distance_source_access_list,
       no_ipv6_bgp_distance_source_access_list_cmd,
       "no distance (1-255) X:X::X:X/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_unset (vty, argv[2]->arg, argv[3]->arg, argv[4]->arg);
  return CMD_SUCCESS;
}

DEFUN (bgp_damp_set,
       bgp_damp_set_cmd,
       "bgp dampening [(1-45) [(1-20000) (1-20000) (1-255)]]",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  int idx_half_life = 2;
  int idx_reuse = 3;
  int idx_suppress = 4;
  int idx_max_suppress = 5;
  int half = DEFAULT_HALF_LIFE * 60;
  int reuse = DEFAULT_REUSE;
  int suppress = DEFAULT_SUPPRESS;
  int max = 4 * half;

  if (argc == 6)
    {
      half = atoi (argv[idx_half_life]->arg) * 60;
      reuse = atoi (argv[idx_reuse]->arg);
      suppress = atoi (argv[idx_suppress]->arg);
      max = atoi (argv[idx_max_suppress]->arg) * 60;
    }
  else if (argc == 3)
    {
      half = atoi (argv[idx_half_life]->arg) * 60;
      max = 4 * half;
    }

  if (suppress < reuse)
    {
      vty_out (vty, "Suppress value cannot be less than reuse value %s",
                    VTY_NEWLINE);
      return 0;
    }

  return bgp_damp_enable (bgp, bgp_node_afi (vty), bgp_node_safi (vty),
			  half, reuse, suppress, max);
}

DEFUN (bgp_damp_unset,
       bgp_damp_unset_cmd,
       "no bgp dampening [(1-45) [(1-20000) (1-20000) (1-255)]]",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  return bgp_damp_disable (bgp, bgp_node_afi (vty), bgp_node_safi (vty));
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
	  vty_out (vty, "%% Can't find BGP instance %s%s", view_name, VTY_NEWLINE);
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

  if ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP))
    {
      for (rn = bgp_table_top (bgp->rib[AFI_IP][safi]); rn; rn = bgp_route_next (rn))
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
       "IPv4 prefix\n")
{
  int idx_ipv4_prefixlen = 4;
  return bgp_clear_damp_route (vty, NULL, argv[idx_ipv4_prefixlen]->arg, AFI_IP,
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
  int idx_ipv4 = 4;
  return bgp_clear_damp_route (vty, NULL, argv[idx_ipv4]->arg, AFI_IP,
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
  int idx_ipv4 = 4;
  int idx_ipv4_2 = 5;
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[idx_ipv4]->arg, argv[idx_ipv4_2]->arg, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_clear_damp_route (vty, NULL, prefix_str, AFI_IP,
			       SAFI_UNICAST, NULL, 0);
}

/* also used for encap safi */
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

	    vty_out (vty, "  network %s/%d rd %s tag %d",
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
  
  if (afi == AFI_IP && ((safi == SAFI_MPLS_VPN) || (safi == SAFI_ENCAP)))
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
	    vty_out (vty, "  network %s",
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
	    vty_out (vty, "  network %s/%d",
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
	    vty_out (vty, "  aggregate-address %s %s",
		     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		     inet_ntoa (netmask));
	  }
	else
	  {
	    vty_out (vty, "  aggregate-address %s/%d",
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
bgp_config_write_distance (struct vty *vty, struct bgp *bgp, afi_t afi,
			   safi_t safi, int *write)
{
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  /* Distance configuration. */
  if (bgp->distance_ebgp[afi][safi]
      && bgp->distance_ibgp[afi][safi]
      && bgp->distance_local[afi][safi]
      && (bgp->distance_ebgp[afi][safi] != ZEBRA_EBGP_DISTANCE_DEFAULT
	  || bgp->distance_ibgp[afi][safi] != ZEBRA_IBGP_DISTANCE_DEFAULT
	  || bgp->distance_local[afi][safi] != ZEBRA_IBGP_DISTANCE_DEFAULT))
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, "  distance bgp %d %d %d%s",
	       bgp->distance_ebgp[afi][safi], bgp->distance_ibgp[afi][safi],
	       bgp->distance_local[afi][safi], VTY_NEWLINE);
    }

  for (rn = bgp_table_top (bgp_distance_table[afi][safi]); rn;
       rn = bgp_route_next (rn))
    if ((bdistance = rn->info) != NULL)
      {
	char buf[PREFIX_STRLEN];

	bgp_config_write_family_header (vty, afi, safi, write);
	vty_out (vty, "  distance %d %s %s%s", bdistance->distance,
		 prefix2str (&rn->p, buf, sizeof (buf)),
		 bdistance->access_list ? bdistance->access_list : "",
		 VTY_NEWLINE);
      }

  return *write;
}

/* Allocate routing table structure and install commands. */
void
bgp_route_init (void)
{
  afi_t afi;
  safi_t safi;

  /* Init BGP distance table. */
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_distance_table[afi][safi] = bgp_table_init (afi, safi);

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

  install_element (BGP_NODE, &aggregate_address_cmd);
  install_element (BGP_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_NODE, &no_aggregate_address_cmd);
  install_element (BGP_NODE, &no_aggregate_address_mask_cmd);

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
  
  install_element (BGP_IPV4_NODE, &aggregate_address_cmd);
  install_element (BGP_IPV4_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_cmd);
  install_element (BGP_IPV4_NODE, &no_aggregate_address_mask_cmd);

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
  install_element (BGP_IPV4M_NODE, &aggregate_address_cmd);
  install_element (BGP_IPV4M_NODE, &aggregate_address_mask_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_cmd);
  install_element (BGP_IPV4M_NODE, &no_aggregate_address_mask_cmd);

  install_element (VIEW_NODE, &show_ip_bgp_instance_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_regexp_cmd);

  install_element (VIEW_NODE, &show_ip_bgp_instance_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_dampening_params_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_dampening_parameters_cmd);
  
  /* Restricted node: VIEW_NODE - (set of dangerous commands) */
  install_element (VIEW_NODE, &show_ip_bgp_instance_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_instance_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbor_received_prefix_filter_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_dampening_params_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_dampening_parameters_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_route_prefix_cmd);

 /* BGP dampening clear commands */
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_prefix_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_address_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_dampening_address_mask_cmd);

  /* prefix count */
  install_element (ENABLE_NODE, &show_ip_bgp_neighbor_prefix_counts_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_instance_neighbor_prefix_counts_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbor_prefix_counts_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd);
#ifdef HAVE_IPV6
  install_element (ENABLE_NODE, &show_bgp_ipv6_neighbor_prefix_counts_cmd);
  install_element (ENABLE_NODE, &show_bgp_instance_ipv6_neighbor_prefix_counts_cmd);

  /* New config IPv6 BGP commands.  */
  install_element (BGP_IPV6_NODE, &bgp_table_map_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_network_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_network_route_map_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_table_map_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_network_cmd);

  install_element (BGP_IPV6_NODE, &ipv6_aggregate_address_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_aggregate_address_cmd);

  install_element (BGP_IPV6M_NODE, &ipv6_bgp_network_cmd);
  install_element (BGP_IPV6M_NODE, &no_ipv6_bgp_network_cmd);

  /* Statistics */
  install_element (ENABLE_NODE, &show_bgp_statistics_cmd);
  install_element (ENABLE_NODE, &show_bgp_statistics_view_cmd);
#endif /* HAVE_IPV6 */

  install_element (BGP_NODE, &bgp_distance_cmd);
  install_element (BGP_NODE, &no_bgp_distance_cmd);
  install_element (BGP_NODE, &bgp_distance_source_cmd);
  install_element (BGP_NODE, &no_bgp_distance_source_cmd);
  install_element (BGP_NODE, &bgp_distance_source_access_list_cmd);
  install_element (BGP_NODE, &no_bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV4_NODE, &bgp_distance_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_distance_cmd);
  install_element (BGP_IPV4_NODE, &bgp_distance_source_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_distance_source_cmd);
  install_element (BGP_IPV4_NODE, &bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV4_NODE, &no_bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_distance_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_distance_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_distance_source_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_distance_source_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV4M_NODE, &no_bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV6_NODE, &bgp_distance_cmd);
  install_element (BGP_IPV6_NODE, &no_bgp_distance_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_distance_source_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_distance_source_cmd);
  install_element (BGP_IPV6_NODE, &ipv6_bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV6_NODE, &no_ipv6_bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV6M_NODE, &bgp_distance_cmd);
  install_element (BGP_IPV6M_NODE, &no_bgp_distance_cmd);
  install_element (BGP_IPV6M_NODE, &ipv6_bgp_distance_source_cmd);
  install_element (BGP_IPV6M_NODE, &no_ipv6_bgp_distance_source_cmd);
  install_element (BGP_IPV6M_NODE, &ipv6_bgp_distance_source_access_list_cmd);
  install_element (BGP_IPV6M_NODE, &no_ipv6_bgp_distance_source_access_list_cmd);

  install_element (BGP_NODE, &bgp_damp_set_cmd);
  install_element (BGP_NODE, &bgp_damp_unset_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_set_cmd);
  install_element (BGP_IPV4_NODE, &bgp_damp_unset_cmd);

  /* IPv4 Multicast Mode */
  install_element (BGP_IPV4M_NODE, &bgp_damp_set_cmd);
  install_element (BGP_IPV4M_NODE, &bgp_damp_unset_cmd);
}

void
bgp_route_finish (void)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      {
	bgp_table_unlock (bgp_distance_table[afi][safi]);
	bgp_distance_table[afi][safi] = NULL;
      }
}
