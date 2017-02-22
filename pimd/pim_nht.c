/*
 * PIM for Quagga
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#include <zebra.h>
#include "network.h"
#include "zclient.h"
#include "stream.h"
#include "nexthop.h"
#include "if.h"
#include "hash.h"
#include "jhash.h"

#include "pimd.h"
#include "pimd/pim_nht.h"
#include "log.h"
#include "pim_time.h"
#include "pim_oil.h"
#include "pim_ifchannel.h"
#include "pim_mroute.h"
#include "pim_zebra.h"
#include "pim_upstream.h"
#include "pim_join.h"
#include "pim_jp_agg.h"
#include "pim_zebra.h"

/**
 * pim_sendmsg_zebra_rnh -- Format and send a nexthop register/Unregister
 *   command to Zebra.
 */
static void
pim_sendmsg_zebra_rnh (struct zclient *zclient, struct pim_nexthop_cache *pnc,
                       int command)
{
  struct stream *s;
  struct prefix *p;
  int ret;

  /* Check socket. */
  if (!zclient || zclient->sock < 0)
    return;

  p = &(pnc->rpf.rpf_addr);
  s = zclient->obuf;
  stream_reset (s);
  zclient_create_header (s, command, VRF_DEFAULT);
  /* get update for all routes for a prefix */
  stream_putc (s, 0);

  stream_putw (s, PREFIX_FAMILY (p));
  stream_putc (s, p->prefixlen);
  switch (PREFIX_FAMILY (p))
    {
    case AF_INET:
      stream_put_in_addr (s, &p->u.prefix4);
      break;
    case AF_INET6:
      stream_put (s, &(p->u.prefix6), 16);
      break;
    default:
      break;
    }
  stream_putw_at (s, 0, stream_get_endp (s));

  ret = zclient_send_message (zclient);
  if (ret < 0)
    zlog_warn ("sendmsg_nexthop: zclient_send_message() failed");


  if (PIM_DEBUG_TRACE)
    {
      char buf[PREFIX2STR_BUFFER];
      prefix2str (p, buf, sizeof (buf));
      zlog_debug ("%s: NHT Addr %s %sregistered with Zebra ret:%d ",
                  __PRETTY_FUNCTION__, buf,
                  (command == ZEBRA_NEXTHOP_REGISTER) ? " " : "de", ret);
    }

  return;
}

struct pim_nexthop_cache *
pim_nexthop_cache_find (struct pim_rpf *rpf)
{
  struct pim_nexthop_cache *pnc = NULL;
  struct pim_nexthop_cache lookup;

  lookup.rpf.rpf_addr.family = rpf->rpf_addr.family;
  lookup.rpf.rpf_addr.prefixlen = rpf->rpf_addr.prefixlen;
  lookup.rpf.rpf_addr.u.prefix4.s_addr = rpf->rpf_addr.u.prefix4.s_addr;

  pnc = hash_lookup (pimg->rpf_hash, &lookup);

  return pnc;

}

static int
pim_rp_list_cmp (void *v1, void *v2)
{
  struct rp_info *rp1 = (struct rp_info *) v1;
  struct rp_info *rp2 = (struct rp_info *) v2;

  if (rp1 == rp2)
    return 0;

  if (!rp1 && rp2)
    return -1;

  if (rp1 && !rp2)
    return 1;

  /*
   * Sort by RP IP address
   */
  if (rp1->rp.rpf_addr.u.prefix4.s_addr < rp2->rp.rpf_addr.u.prefix4.s_addr)
    return -1;

  if (rp1->rp.rpf_addr.u.prefix4.s_addr > rp2->rp.rpf_addr.u.prefix4.s_addr)
    return 1;

  /*
   * Sort by group IP address
   */
  if (rp1->group.u.prefix4.s_addr < rp2->group.u.prefix4.s_addr)
    return -1;

  if (rp1->group.u.prefix4.s_addr > rp2->group.u.prefix4.s_addr)
    return 1;

  return -1;
}

struct pim_nexthop_cache *
pim_nexthop_cache_add (struct pim_rpf *rpf_addr)
{
  struct pim_nexthop_cache *pnc;

  pnc = XCALLOC (MTYPE_PIM_NEXTHOP_CACHE, sizeof (struct pim_nexthop_cache));
  if (!pnc)
    {
      zlog_err ("%s: NHT PIM XCALLOC failure ", __PRETTY_FUNCTION__);
      return NULL;
    }
  pnc->rpf.rpf_addr.family = rpf_addr->rpf_addr.family;
  pnc->rpf.rpf_addr.prefixlen = rpf_addr->rpf_addr.prefixlen;
  pnc->rpf.rpf_addr.u.prefix4.s_addr = rpf_addr->rpf_addr.u.prefix4.s_addr;

  pnc = hash_get (pimg->rpf_hash, pnc, hash_alloc_intern);

  pnc->rp_list = list_new ();
  pnc->rp_list->cmp = pim_rp_list_cmp;

  pnc->upstream_list = list_new ();
  pnc->upstream_list->cmp = pim_upstream_compare;

  if (PIM_DEBUG_ZEBRA)
    {
      char rpf_str[PREFIX_STRLEN];
      pim_addr_dump ("<nht?>", &rpf_addr->rpf_addr, rpf_str,
                     sizeof (rpf_str));
      zlog_debug ("%s: NHT hash node, RP and UP lists allocated for %s ",
                  __PRETTY_FUNCTION__, rpf_str);
    }

  return pnc;
}

/* This API is used to Register an address with Zebra */
int
pim_find_or_track_nexthop (struct prefix *addr, struct pim_upstream *up,
                           struct rp_info *rp)
{
  struct pim_nexthop_cache *pnc = NULL;
  struct pim_rpf rpf;
  struct listnode *ch_node = NULL;
  struct zclient *zclient = NULL;

  zclient = pim_zebra_zclient_get ();
  memset (&rpf, 0, sizeof (struct pim_rpf));
  rpf.rpf_addr.family = addr->family;
  rpf.rpf_addr.prefixlen = addr->prefixlen;
  rpf.rpf_addr.u.prefix4 = addr->u.prefix4;

  pnc = pim_nexthop_cache_find (&rpf);
  if (!pnc)
    {
      if (PIM_DEBUG_ZEBRA)
        {
          char buf[PREFIX2STR_BUFFER];
          prefix2str (&rpf.rpf_addr, buf, sizeof (buf));
          zlog_debug ("%s: NHT New PNC allocated for addr %s ",
                      __PRETTY_FUNCTION__, buf);
        }
      pnc = pim_nexthop_cache_add (&rpf);
      if (pnc)
        pim_sendmsg_zebra_rnh (zclient, pnc,
                               ZEBRA_NEXTHOP_REGISTER);
      else
        {
          zlog_warn ("%s: pnc node allocation failed. ", __PRETTY_FUNCTION__);
        }
    }

  if (rp != NULL)
    {
      ch_node = listnode_lookup (pnc->rp_list, rp);
      if (ch_node == NULL)
        {
          if (PIM_DEBUG_ZEBRA)
            {
              char rp_str[PREFIX_STRLEN];
              pim_addr_dump ("<rp?>", &rp->rp.rpf_addr, rp_str,
                             sizeof (rp_str));
              zlog_debug ("%s: NHT add RP %s node to cached list",
                          __PRETTY_FUNCTION__, rp_str);
            }
          listnode_add_sort (pnc->rp_list, rp);
        }
    }

  if (up != NULL)
    {
      ch_node = listnode_lookup (pnc->upstream_list, up);
      if (ch_node == NULL)
        {
          if (PIM_DEBUG_ZEBRA)
            {
              char buf[PREFIX2STR_BUFFER];
              prefix2str (addr, buf, sizeof (buf));
              zlog_debug
                ("%s: NHT add upstream %s node to cached list, rpf %s",
                 __PRETTY_FUNCTION__, up->sg_str, buf);
            }
          listnode_add_sort (pnc->upstream_list, up);
        }
    }

  if (CHECK_FLAG (pnc->flags, PIM_NEXTHOP_VALID))
    return 1;

  return 0;
}

void
pim_delete_tracked_nexthop (struct prefix *addr, struct pim_upstream *up,
                            struct rp_info *rp)
{
  struct pim_nexthop_cache *pnc = NULL;
  struct pim_nexthop_cache lookup;
  struct zclient *zclient = NULL;

  zclient = pim_zebra_zclient_get ();

  /* Remove from RPF hash if it is the last entry */
  lookup.rpf.rpf_addr = *addr;
  pnc = hash_lookup (pimg->rpf_hash, &lookup);
  if (pnc)
    {
      if (rp)
        listnode_delete (pnc->rp_list, rp);
      if (up)
        listnode_delete (pnc->upstream_list, up);

      if (PIM_DEBUG_ZEBRA)
        zlog_debug ("%s: NHT rp_list count:%d upstream_list count:%d ",
                    __PRETTY_FUNCTION__, pnc->rp_list->count,
                    pnc->upstream_list->count);

      if (pnc->rp_list->count == 0 && pnc->upstream_list->count == 0)
        {
          pim_sendmsg_zebra_rnh (zclient, pnc,
                                 ZEBRA_NEXTHOP_UNREGISTER);

          list_delete (pnc->rp_list);
          list_delete (pnc->upstream_list);

          hash_release (pimg->rpf_hash, pnc);
          if (pnc->nexthop)
            nexthops_free (pnc->nexthop);
          XFREE (MTYPE_PIM_NEXTHOP_CACHE, pnc);
        }
    }
}

/* Update RP nexthop info based on Nexthop update received from Zebra.*/
static int
pim_update_rp_nh (struct pim_nexthop_cache *pnc)
{
  struct listnode *node = NULL;
  struct rp_info *rp_info = NULL;
  int ret = 0;

  /*Traverse RP list and update each RP Nexthop info */
  for (ALL_LIST_ELEMENTS_RO (pnc->rp_list, node, rp_info))
    {
      if (rp_info->rp.rpf_addr.u.prefix4.s_addr == INADDR_NONE)
        continue;

      if (pim_nexthop_lookup (&rp_info->rp.source_nexthop,
                              rp_info->rp.rpf_addr.u.prefix4, 1) != 0)
        {
          if (PIM_DEBUG_PIM_TRACE)
            zlog_debug ("Unable to lookup nexthop for rp specified");
          ret++;
          continue;
        }

      if (PIM_DEBUG_TRACE)
        {
          char rp_str[PREFIX_STRLEN];
          pim_addr_dump ("<rp?>", &rp_info->rp.rpf_addr, rp_str,
                         sizeof (rp_str));
          zlog_debug ("%s: NHT update nexthop for RP %s to interface %s ",
                      __PRETTY_FUNCTION__, rp_str,
                      rp_info->rp.source_nexthop.interface->name);
        }
    }

  if (ret)
    return 0;

  return 1;

}

/* Update Upstream nexthop info based on Nexthop update received from Zebra.*/
static int
pim_update_upstream_nh (struct pim_nexthop_cache *pnc)
{
  struct listnode     *up_node;
  struct listnode     *ifnode;
  struct listnode     *up_nextnode;
  struct listnode     *node;
  struct pim_upstream *up;
  struct interface    *ifp;
  int                 vif_index = 0;

  for (ALL_LIST_ELEMENTS (pnc->upstream_list, up_node, up_nextnode, up))
    {
      enum pim_rpf_result rpf_result;
      struct pim_rpf old;

      if (up == NULL)
        {
          zlog_debug ("%s: Upstream node is NULL ", __PRETTY_FUNCTION__);
          continue;
        }

      old.source_nexthop.interface = up->rpf.source_nexthop.interface;
      rpf_result = pim_rpf_update (up, &old, 0);
      if (rpf_result == PIM_RPF_FAILURE)
        continue;

      if (rpf_result == PIM_RPF_CHANGED)
        {

          /*
           * We have detected a case where we might need to rescan
           * the inherited o_list so do it.
           */
          if (up->channel_oil && up->channel_oil->oil_inherited_rescan)
            {
              pim_upstream_inherited_olist_decide (up);
              up->channel_oil->oil_inherited_rescan = 0;
            }

          if (up->join_state == PIM_UPSTREAM_JOINED)
            {
              /*
               * If we come up real fast we can be here
               * where the mroute has not been installed
               * so install it.
               */
              if (up->channel_oil && !up->channel_oil->installed)
                pim_mroute_add (up->channel_oil, __PRETTY_FUNCTION__);

              /*
                 RFC 4601: 4.5.7.  Sending (S,G) Join/Prune Messages

                 Transitions from Joined State

                 RPF'(S,G) changes not due to an Assert

                 The upstream (S,G) state machine remains in Joined
                 state. Send Join(S,G) to the new upstream neighbor, which is
                 the new value of RPF'(S,G).  Send Prune(S,G) to the old
                 upstream neighbor, which is the old value of RPF'(S,G).  Set
                 the Join Timer (JT) to expire after t_periodic seconds.
               */
              pim_jp_agg_switch_interface (&old, &up->rpf, up);

              pim_upstream_join_timer_restart (up, &old);
            }                   /* up->join_state == PIM_UPSTREAM_JOINED */

          /* FIXME can join_desired actually be changed by pim_rpf_update()
             returning PIM_RPF_CHANGED ? */
          pim_upstream_update_join_desired (up);

        } /* PIM_RPF_CHANGED */

      if (PIM_DEBUG_TRACE)
        {
          zlog_debug ("%s: NHT upstream %s old ifp %s new ifp %s",
                      __PRETTY_FUNCTION__, up->sg_str,
                      old.source_nexthop.interface->name,
                      up->rpf.source_nexthop.interface->name);
        }
      /* update kernel multicast forwarding cache (MFC) */
      if (up->channel_oil)
        {
          vif_index =
            pim_if_find_vifindex_by_ifindex (up->rpf.
                                             source_nexthop.interface->
                                             ifindex);
          /* Pass Current selected NH vif index to mroute download */
          if (vif_index)
            pim_scan_individual_oil (up->channel_oil, vif_index);
          else
            {
              if (PIM_DEBUG_ZEBRA)
                zlog_debug ("%s: NHT upstream %s channel_oil IIF %s vif_index is not valid",
                      __PRETTY_FUNCTION__, up->sg_str,
                      up->rpf.source_nexthop.interface->name);
            }
        }

    } /* for (pnc->upstream_list) */

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (VRF_DEFAULT), ifnode, ifp))
    if (ifp->info)
      {
        struct pim_interface *pim_ifp = ifp->info;
        struct pim_iface_upstream_switch *us;

        for (ALL_LIST_ELEMENTS_RO (pim_ifp->upstream_switch_list, node, us))
          {
            struct pim_rpf rpf;
            rpf.source_nexthop.interface = ifp;
            rpf.rpf_addr.u.prefix4 = us->address;
            pim_joinprune_send (&rpf, us->us);
            pim_jp_agg_clear_group (us->us);
          }
      }

  return 0;
}

/* This API is used to parse Registered address nexthop update coming from Zebra */
void
pim_parse_nexthop_update (struct zclient *zclient, int command,
                          vrf_id_t vrf_id)
{
  struct stream *s;
  struct prefix p;
  struct nexthop *nexthop;
  struct nexthop *oldnh;
  struct nexthop *nhlist_head = NULL;
  struct nexthop *nhlist_tail = NULL;
  uint32_t metric, distance;
  u_char nexthop_num = 0;
  int i;
  struct pim_rpf rpf;
  struct pim_nexthop_cache *pnc = NULL;
  struct pim_neighbor *nbr = NULL;
  struct interface *ifp = NULL;

  s = zclient->ibuf;
  memset (&p, 0, sizeof (struct prefix));
  p.family = stream_getw (s);
  p.prefixlen = stream_getc (s);
  switch (p.family)
    {
    case AF_INET:
      p.u.prefix4.s_addr = stream_get_ipv4 (s);
      break;
    case AF_INET6:
      stream_get (&p.u.prefix6, s, 16);
      break;
    default:
      break;
    }

  if (command == ZEBRA_NEXTHOP_UPDATE)
    {
      rpf.rpf_addr.family = p.family;
      rpf.rpf_addr.prefixlen = p.prefixlen;
      rpf.rpf_addr.u.prefix4.s_addr = p.u.prefix4.s_addr;
      pnc = pim_nexthop_cache_find (&rpf);
      if (!pnc)
        {
          if (PIM_DEBUG_TRACE)
            {
              char buf[PREFIX2STR_BUFFER];
              prefix2str (&rpf.rpf_addr, buf, sizeof (buf));
              zlog_debug ("%s: NHT addr %s is not in local cached DB.",
                          __PRETTY_FUNCTION__, buf);
            }
          return;
        }
    }

  pnc->last_update = pim_time_monotonic_sec ();
  distance = stream_getc (s);
  metric = stream_getl (s);
  nexthop_num = stream_getc (s);

  if (PIM_DEBUG_TRACE)
    {
      char buf[PREFIX2STR_BUFFER];
      prefix2str (&p, buf, sizeof (buf));
      zlog_debug ("%s: NHT Update for %s nexthop_num %d vrf:%d upcount %d rpcount %d",
                  __PRETTY_FUNCTION__, buf, nexthop_num, vrf_id,
                  listcount (pnc->upstream_list), listcount (pnc->rp_list));
    }

  if (nexthop_num)
    {
      pnc->flags |= PIM_NEXTHOP_VALID;
      pnc->distance = distance;
      pnc->metric = metric;
      pnc->nexthop_num = nexthop_num;

      for (i = 0; i < nexthop_num; i++)
        {
          nexthop = nexthop_new ();
          nexthop->type = stream_getc (s);
          switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
              nexthop->gate.ipv4.s_addr = stream_get_ipv4 (s);
              nexthop->ifindex = stream_getl (s);
              break;
            case NEXTHOP_TYPE_IFINDEX:
              nexthop->ifindex = stream_getl (s);
              break;
            case NEXTHOP_TYPE_IPV4_IFINDEX:
              nexthop->gate.ipv4.s_addr = stream_get_ipv4 (s);
              nexthop->ifindex = stream_getl (s);
              break;
            case NEXTHOP_TYPE_IPV6:
              stream_get (&nexthop->gate.ipv6, s, 16);
              break;
            case NEXTHOP_TYPE_IPV6_IFINDEX:
              stream_get (&nexthop->gate.ipv6, s, 16);
              nexthop->ifindex = stream_getl (s);
              nbr =
                pim_neighbor_find_if (if_lookup_by_index_vrf
                                      (nexthop->ifindex, VRF_DEFAULT));
              /* Overwrite with Nbr address as NH addr */
              if (nbr)
                nexthop->gate.ipv4 = nbr->source_addr;

              break;
            default:
              /* do nothing */
              break;
            }

          if (PIM_DEBUG_TRACE)
            {
              char p_str[PREFIX2STR_BUFFER];
              prefix2str (&p, p_str, sizeof (p_str));
              zlog_debug ("%s: NHT addr %s %d-nhop via %s type %d",
                          __PRETTY_FUNCTION__, p_str, i + 1,
                          inet_ntoa (nexthop->gate.ipv4), nexthop->type);
            }

          ifp = if_lookup_by_index (nexthop->ifindex);
          if (!ifp)
            {
              if (PIM_DEBUG_ZEBRA)
                {
                  char buf[NEXTHOP_STRLEN];
                  zlog_debug("%s: could not find interface for ifindex %d (addr %s)",
                         __PRETTY_FUNCTION__,
                         nexthop->ifindex, nexthop2str (nexthop, buf, sizeof (buf)));
                }
              nexthop_free (nexthop);
              continue;
            }

          if (!ifp->info)
            {
              if (PIM_DEBUG_ZEBRA)
                {
                  char buf[NEXTHOP_STRLEN];
                  zlog_debug
                    ("%s: multicast not enabled on input interface %s (ifindex=%d, addr %s)",
                     __PRETTY_FUNCTION__, ifp->name, nexthop->ifindex,
                     nexthop2str (nexthop, buf, sizeof (buf)));
                }
              nexthop_free (nexthop);
              continue;
            }

          if (nhlist_tail)
            {
              nhlist_tail->next = nexthop;
              nhlist_tail = nexthop;
            }
          else
            {
              nhlist_tail = nexthop;
              nhlist_head = nexthop;
            }

          for (oldnh = pnc->nexthop; oldnh; oldnh = oldnh->next)
            if (nexthop_same_no_recurse (oldnh, nexthop))
              break;
        }
      /* Reset existing pnc->nexthop before assigning new list */
      nexthops_free (pnc->nexthop);
      pnc->nexthop = nhlist_head;
    }
  else
    {
      pnc->flags &= ~PIM_NEXTHOP_VALID;
      pnc->nexthop_num = nexthop_num;
      nexthops_free (pnc->nexthop);
      pnc->nexthop = NULL;
    }

  pim_rpf_set_refresh_time ();

  if (listcount (pnc->rp_list))
    pim_update_rp_nh (pnc);
  if (listcount (pnc->upstream_list))
    pim_update_upstream_nh (pnc);

}
