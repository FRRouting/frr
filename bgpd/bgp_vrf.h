/* BGP VRF definition header
   Copyright (C) 2016, 6WIND

This file is part of GNU Quagga.

GNU Quagga is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Quagga is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Quagga; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGP_VRF_H
#define _QUAGGA_BGP_VRF_H


#include "qobj.h"
#include "linklist.h"
#include "prefix.h"

#include "bgpd.h"
#include "bgp_table.h"
#include "bgp_ecommunity.h"

/* for vrf importation */
#define BGP_VRF_IMPORT_ROUTE_INFO_TO_UPDATE 2
#define BGP_VRF_IMPORT_ROUTE_INFO_TO_REMOVE 1
#define BGP_VRF_IMPORT_ROUTE_INFO_TO_ADD    0

/* for debugging */
#define BGP_DEBUG_BGPVRF                 0x01


struct bgp_rt_sub
{
  struct ecommunity_val rt;

  struct list *vrfs;
};

struct bgp_vrf
{
  struct bgp *bgp;

  char *name;

  /* RD used for route advertisements */
  struct prefix_rd outbound_rd;

  /* import and export lists */
  struct ecommunity *rt_import;
  struct ecommunity *rt_export;

  /* BGP routing information base.  */
  struct bgp_table *rib[AFI_MAX];

  /* Static route configuration.  */
  struct bgp_table *route[AFI_MAX];

  /* internal flag */
#define BGP_VRF_RD_UNSET 1
  uint16_t flag;

  QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(bgp_vrf)


/* for debugging */
extern unsigned long conf_bgp_debug_bgp_vrf;
extern unsigned long term_bgp_debug_bgp_vrf;

extern void bgp_bgpvrf_vty (void);
extern void bgp_bgpvrf_init (struct bgp *bgp);
extern void bgp_bgpvrf_delete (struct bgp *bgp);
extern void bgp_config_write_bgpvrf (struct vty *vty, struct bgp *bgp);

extern void bgp_vrf_context_delete (struct bgp_vrf *vrf);
extern void bgp_vrf_delete_rd (struct bgp_vrf *vrf);
extern struct bgp_vrf *bgp_vrf_update_rd (struct bgp *bgp, struct bgp_vrf *vrf, struct prefix_rd *outbound_rd);
extern struct bgp_vrf *bgp_vrf_lookup (struct bgp *bgp, struct prefix_rd *outbound_rd);
extern struct bgp_vrf *bgp_vrf_lookup_per_name (struct bgp *bgp, const char *name, int create);
extern struct bgp_vrf *bgp_vrf_lookup_per_rn (struct bgp *bgp, int afi, struct bgp_node *vrf_rn);
extern void bgp_vrf_rt_export_set (struct bgp_vrf *vrf, struct ecommunity *rt_export);
extern void bgp_vrf_rt_import_set (struct bgp_vrf *vrf, struct ecommunity *rt_import);
extern void bgp_vrf_apply_new_imports (struct bgp_vrf *vrf, afi_t afi);
extern void bgp_vrf_rt_import_unset (struct bgp_vrf *vrf);
extern void bgp_vrf_rt_export_unset (struct bgp_vrf *vrf);

extern void
bgp_vrf_process_imports (struct bgp *bgp, afi_t afi, safi_t safi,
                         struct bgp_node *rn,
                         struct bgp_info *old_select,
                         struct bgp_info *new_select);

extern void
bgp_vrf_update (struct bgp_vrf *vrf, afi_t afi, struct bgp_node *rn,
                struct bgp_info *selected, uint8_t announce);

#endif /* _QUAGGA_BGP_VRF */

