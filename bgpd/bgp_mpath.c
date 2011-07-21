/* $QuaggaId: Format:%an, %ai, %h$ $
 *
 * BGP Multipath
 * Copyright (C) 2010 Google Inc.
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "linklist.h"
#include "sockunion.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mpath.h"

/*
 * bgp_maximum_paths_set
 *
 * Record maximum-paths configuration for BGP instance
 */
int
bgp_maximum_paths_set (struct bgp *bgp, afi_t afi, safi_t safi,
                       int peertype, u_int16_t maxpaths)
{
  if (!bgp || (afi >= AFI_MAX) || (safi >= SAFI_MAX))
    return -1;

  switch (peertype)
    {
    case BGP_PEER_IBGP:
      bgp->maxpaths[afi][safi].maxpaths_ibgp = maxpaths;
      break;
    case BGP_PEER_EBGP:
      bgp->maxpaths[afi][safi].maxpaths_ebgp = maxpaths;
      break;
    default:
      return -1;
    }

  return 0;
}

/*
 * bgp_maximum_paths_unset
 *
 * Remove maximum-paths configuration from BGP instance
 */
int
bgp_maximum_paths_unset (struct bgp *bgp, afi_t afi, safi_t safi,
                         int peertype)
{
  if (!bgp || (afi >= AFI_MAX) || (safi >= SAFI_MAX))
    return -1;

  switch (peertype)
    {
    case BGP_PEER_IBGP:
      bgp->maxpaths[afi][safi].maxpaths_ibgp = BGP_DEFAULT_MAXPATHS;
      break;
    case BGP_PEER_EBGP:
      bgp->maxpaths[afi][safi].maxpaths_ebgp = BGP_DEFAULT_MAXPATHS;
      break;
    default:
      return -1;
    }

  return 0;
}

/*
 * bgp_info_nexthop_cmp
 *
 * Compare the nexthops of two paths. Return value is less than, equal to,
 * or greater than zero if bi1 is respectively less than, equal to,
 * or greater than bi2.
 */
static int
bgp_info_nexthop_cmp (struct bgp_info *bi1, struct bgp_info *bi2)
{
  struct attr_extra *ae1, *ae2;
  int compare;

  ae1 = bgp_attr_extra_get (bi1->attr);
  ae2 = bgp_attr_extra_get (bi2->attr);

  compare = IPV4_ADDR_CMP (&bi1->attr->nexthop, &bi2->attr->nexthop);

  if (!compare && ae1 && ae2 && (ae1->mp_nexthop_len == ae2->mp_nexthop_len))
    {
      switch (ae1->mp_nexthop_len)
        {
        case 4:
        case 12:
          compare = IPV4_ADDR_CMP (&ae1->mp_nexthop_global_in,
                                   &ae2->mp_nexthop_global_in);
          break;
#ifdef HAVE_IPV6
        case 16:
          compare = IPV6_ADDR_CMP (&ae1->mp_nexthop_global,
                                   &ae2->mp_nexthop_global);
          break;
        case 32:
          compare = IPV6_ADDR_CMP (&ae1->mp_nexthop_global,
                                   &ae2->mp_nexthop_global);
          if (!compare)
            compare = IPV6_ADDR_CMP (&ae1->mp_nexthop_local,
                                     &ae2->mp_nexthop_local);
          break;
#endif /* HAVE_IPV6 */
        }
    }

  return compare;
}

/*
 * bgp_info_mpath_cmp
 *
 * This function determines our multipath list ordering. By ordering
 * the list we can deterministically select which paths are included
 * in the multipath set. The ordering also helps in detecting changes
 * in the multipath selection so we can detect whether to send an
 * update to zebra.
 *
 * The order of paths is determined first by received nexthop, and then
 * by peer address if the nexthops are the same.
 */
static int
bgp_info_mpath_cmp (void *val1, void *val2)
{
  struct bgp_info *bi1, *bi2;
  int compare;

  bi1 = val1;
  bi2 = val2;

  compare = bgp_info_nexthop_cmp (bi1, bi2);

  if (!compare)
    compare = sockunion_cmp (bi1->peer->su_remote, bi2->peer->su_remote);

  return compare;
}

/*
 * bgp_mp_list_init
 *
 * Initialize the mp_list, which holds the list of multipaths
 * selected by bgp_best_selection
 */
void
bgp_mp_list_init (struct list *mp_list)
{
  assert (mp_list);
  memset (mp_list, 0, sizeof (struct list));
  mp_list->cmp = bgp_info_mpath_cmp;
}

/*
 * bgp_mp_list_clear
 *
 * Clears all entries out of the mp_list
 */
void
bgp_mp_list_clear (struct list *mp_list)
{
  assert (mp_list);
  list_delete_all_node (mp_list);
}

/*
 * bgp_mp_list_add
 *
 * Adds a multipath entry to the mp_list
 */
void
bgp_mp_list_add (struct list *mp_list, struct bgp_info *mpinfo)
{
  assert (mp_list && mpinfo);
  listnode_add_sort (mp_list, mpinfo);
}
