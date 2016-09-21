/*
 * Copyright (C) 2016 CumulusNetworks
 *                    Donald Sharp
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>

#include "log.h"
#include "linklist.h"

#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"
#include "zebra/router-id.h"
#include "zebra/zebra_static.h"

extern struct zebra_t zebrad;
struct list *zvrf_list;

/* VRF information update. */
static void
zebra_vrf_add_update (struct zebra_vrf *zvrf)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_VRF_ADD %s", zvrf->name);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    zsend_vrf_add (client, zvrf);
}

static void
zebra_vrf_delete_update (struct zebra_vrf *zvrf)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_debug ("MESSAGE: ZEBRA_VRF_DELETE %s", zvrf->name);

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    zsend_vrf_delete (client, zvrf);
}

void
zebra_vrf_update_all (struct zserv *client)
{
  struct vrf *vrf;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      if ((vrf = vrf_iter2vrf (iter)) && vrf->vrf_id)
        zsend_vrf_add (client, vrf_info_lookup (vrf->vrf_id));
    }
}

/* Callback upon creating a new VRF. */
static int
zebra_vrf_new (vrf_id_t vrf_id, const char *name, void **info)
{
  struct zebra_vrf *zvrf = *info;

  if (IS_ZEBRA_DEBUG_EVENT)
    zlog_info ("ZVRF %s with id %u", name, vrf_id);

  if (! zvrf)
    {
      zvrf = zebra_vrf_list_lookup_by_name (name);
      if (!zvrf)
	{
	  zvrf = zebra_vrf_alloc (vrf_id, name);
	  zvrf->zns = zebra_ns_lookup (NS_DEFAULT); /* Point to the global (single) NS */
	  *info = (void *)zvrf;
	  router_id_init (zvrf);
	  listnode_add_sort (zvrf_list, zvrf);
	}
      else
        {
          *info = (void *)zvrf;
	  router_id_init (zvrf);
        }
    }

  if (zvrf->vrf_id == VRF_UNKNOWN)
    zvrf->vrf_id = vrf_id;

  return 0;
}

/*
 * Moving an interface amongst different vrf's
 * causes the interface to get a new ifindex
 * so we need to find static routes with
 * the old ifindex and replace with new
 * ifindex to insert back into the table
 */
void
zebra_vrf_static_route_interface_fixup (struct interface *ifp)
{
  afi_t afi;
  safi_t safi;
  struct zebra_vrf *zvrf = zebra_vrf_lookup (ifp->vrf_id);
  struct route_table *stable = NULL;
  struct route_node *rn = NULL;
  struct static_route *si = NULL;

  if (!zvrf)
    return;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
        {
          stable = zvrf->stable[afi][safi];
          if (stable)
	    for (rn = route_top (stable); rn; rn = route_next (rn))
	      {
		if (rn->info)
		  {
		    si = rn->info;
		    if ((strcmp (si->ifname, ifp->name) == 0) &&
			(si->ifindex != ifp->ifindex))
		      {
			si->ifindex = ifp->ifindex;
			static_install_route (afi, safi, &rn->p, si);
		      }	  
		  }
	      }
	}
    }
  
}

/* Callback upon enabling a VRF. */
static int
zebra_vrf_enable (vrf_id_t vrf_id, const char *name, void **info)
{
  struct zebra_vrf *zvrf = (struct zebra_vrf *) (*info);
  struct route_table *stable = NULL;
  struct route_node *rn = NULL;
  struct static_route *si = NULL;
  struct interface *ifp = NULL;
  afi_t afi;
  safi_t safi;

  assert (zvrf);

  zebra_vrf_add_update (zvrf);

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
	{
	  stable = zvrf->stable[afi][safi];
	  if (stable)
	    {
	      for (rn = route_top (stable); rn; rn = route_next (rn))
		{
		  if (rn->info)
		    {
		      si = rn->info;
		      si->vrf_id = vrf_id;
		      if (si->ifindex)
		        {
                          ifp = if_lookup_by_name_vrf (si->ifname, si->vrf_id);
			  if (ifp)
                            si->ifindex = ifp->ifindex;
                          else
			    continue;
                        }
		      static_install_route (afi, safi, &rn->p, si);
		    }
		}
	    }
	}
    }
  return 0;
}

/* Callback upon disabling a VRF. */
static int
zebra_vrf_disable (vrf_id_t vrf_id, const char *name, void **info)
{
  struct zebra_vrf *zvrf = (struct zebra_vrf *)(*info);
  struct route_table *stable = NULL;
  struct route_node *rn = NULL;
  afi_t afi;
  safi_t safi;

  if (IS_ZEBRA_DEBUG_KERNEL)
    zlog_debug ("VRF %s id %u is now disabled.",
                zvrf->name, zvrf->vrf_id);

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
	{
	  stable = zvrf->stable[afi][safi];
	  if (stable)
	    {
	      for (rn = route_top (stable); rn; rn = route_next (rn))
		{
                  if (rn->info)
		    static_uninstall_route(afi, safi, &rn->p, rn->info);
		}
	    }
	}
    }
  return 0;
}

static int
zebra_vrf_delete (vrf_id_t vrf_id, const char *name, void **info)
{
  struct zebra_vrf *zvrf = (struct zebra_vrf *) (*info);

  assert (zvrf);

  zebra_vrf_delete_update (zvrf);

  rib_close_table (zvrf->table[AFI_IP][SAFI_UNICAST]);
  rib_close_table (zvrf->table[AFI_IP6][SAFI_UNICAST]);

  list_delete_all_node (zvrf->rid_all_sorted_list);
  list_delete_all_node (zvrf->rid_lo_sorted_list);

  zvrf->vrf_id = VRF_UNKNOWN;

  *info = NULL;
  return 0;
}

/* Lookup the routing table in a VRF based on both VRF-Id and table-id.
 * NOTE: Table-id is relevant only in the Default VRF.
 */
struct route_table *
zebra_vrf_table_with_table_id (afi_t afi, safi_t safi,
                               vrf_id_t vrf_id, u_int32_t table_id)
{
  struct route_table *table = NULL;

  if (afi >= AFI_MAX || safi >= SAFI_MAX)
    return NULL;

  if (vrf_id == VRF_DEFAULT)
    {
      if (table_id == RT_TABLE_MAIN ||
          table_id == zebrad.rtm_table_default)
        table = zebra_vrf_table (afi, safi, vrf_id);
      else
        table = zebra_vrf_other_route_table (afi, table_id, vrf_id);
    }
  else
      table = zebra_vrf_table (afi, safi, vrf_id);

  return table;
}

/*
 * Create a routing table for the specific AFI/SAFI in the given VRF.
 */
static void
zebra_vrf_table_create (struct zebra_vrf *zvrf, afi_t afi, safi_t safi)
{
  rib_table_info_t *info;
  struct route_table *table;

  assert (!zvrf->table[afi][safi]);

  table = route_table_init ();
  zvrf->table[afi][safi] = table;

  info = XCALLOC (MTYPE_RIB_TABLE_INFO, sizeof (*info));
  info->zvrf = zvrf;
  info->afi = afi;
  info->safi = safi;
  table->info = info;
}

/* Allocate new zebra VRF. */
struct zebra_vrf *
zebra_vrf_alloc (vrf_id_t vrf_id, const char *name)
{
  struct zebra_vrf *zvrf;

  zvrf = XCALLOC (MTYPE_ZEBRA_VRF, sizeof (struct zebra_vrf));

  /* Allocate routing table and static table.  */
  zebra_vrf_table_create (zvrf, AFI_IP, SAFI_UNICAST);
  zebra_vrf_table_create (zvrf, AFI_IP6, SAFI_UNICAST);
  zvrf->stable[AFI_IP][SAFI_UNICAST] = route_table_init ();
  zvrf->stable[AFI_IP6][SAFI_UNICAST] = route_table_init ();
  zebra_vrf_table_create (zvrf, AFI_IP, SAFI_MULTICAST);
  zebra_vrf_table_create (zvrf, AFI_IP6, SAFI_MULTICAST);
  zvrf->stable[AFI_IP][SAFI_MULTICAST] = route_table_init ();
  zvrf->stable[AFI_IP6][SAFI_MULTICAST] = route_table_init ();

  zvrf->rnh_table[AFI_IP] = route_table_init();
  zvrf->rnh_table[AFI_IP6] = route_table_init();

  zvrf->import_check_table[AFI_IP] = route_table_init();
  zvrf->import_check_table[AFI_IP6] = route_table_init();

  /* Set VRF ID */
  zvrf->vrf_id = vrf_id;

  if (name)
    {
      strncpy (zvrf->name, name, strlen(name));
      zvrf->name[strlen(name)] = '\0';
    }

  return zvrf;
}

/* Lookup VRF by identifier.  */
struct zebra_vrf *
zebra_vrf_lookup (vrf_id_t vrf_id)
{
  return vrf_info_lookup (vrf_id);
}

/* Lookup the zvrf in the zvrf_list. */
struct zebra_vrf *
zebra_vrf_list_lookup_by_name (const char *name)
{
  struct listnode *node;
  struct zebra_vrf *zvrf;

  if (!name)
    name = VRF_DEFAULT_NAME;

  for (ALL_LIST_ELEMENTS_RO (zvrf_list, node, zvrf))
    {
      if (strcmp(name, zvrf->name) == 0)
        return zvrf;
    }
  return NULL;
}

/* Lookup the routing table in an enabled VRF. */
struct route_table *
zebra_vrf_table (afi_t afi, safi_t safi, vrf_id_t vrf_id)
{
  struct zebra_vrf *zvrf = vrf_info_lookup (vrf_id);

  if (!zvrf)
    return NULL;

  if (afi >= AFI_MAX || safi >= SAFI_MAX)
    return NULL;

  return zvrf->table[afi][safi];
}

/* Lookup the static routing table in a VRF. */
struct route_table *
zebra_vrf_static_table (afi_t afi, safi_t safi, struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return NULL;

  if (afi >= AFI_MAX || safi >= SAFI_MAX)
    return NULL;

  return zvrf->stable[afi][safi];
}

struct route_table *
zebra_vrf_other_route_table (afi_t afi, u_int32_t table_id, vrf_id_t vrf_id)
{
  struct zebra_vrf *zvrf;
  rib_table_info_t *info;
  struct route_table *table;

  zvrf = vrf_info_lookup (vrf_id);
  if (! zvrf)
    return NULL;

  if(afi >= AFI_MAX)
    return NULL;

  if (table_id >= ZEBRA_KERNEL_TABLE_MAX)
    return NULL;

  if ((vrf_id == VRF_DEFAULT) && (table_id != RT_TABLE_MAIN) && (table_id != zebrad.rtm_table_default))
    {
      if (zvrf->other_table[afi][table_id] == NULL)
        {
          table = route_table_init();
          info = XCALLOC (MTYPE_RIB_TABLE_INFO, sizeof (*info));
          info->zvrf = zvrf;
          info->afi = afi;
          info->safi = SAFI_UNICAST;
          table->info = info;
          zvrf->other_table[afi][table_id] = table;
        }

      return (zvrf->other_table[afi][table_id]);
    }

  return zvrf->table[afi][SAFI_UNICAST];
}

/* Zebra VRF initialization. */
void
zebra_vrf_init (void)
{
  vrf_add_hook (VRF_NEW_HOOK, zebra_vrf_new);
  vrf_add_hook (VRF_ENABLE_HOOK, zebra_vrf_enable);
  vrf_add_hook (VRF_DISABLE_HOOK, zebra_vrf_disable);
  vrf_add_hook (VRF_DELETE_HOOK, zebra_vrf_delete);

  zvrf_list = list_new ();

  vrf_init ();
}
