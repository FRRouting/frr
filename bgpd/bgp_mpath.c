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

#include "bgpd/bgpd.h"
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
