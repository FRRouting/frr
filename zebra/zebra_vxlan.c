/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"
#include "vlan.h"
#include "vxlan.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_ns.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_l2.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZVNI,      "VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, ZVNI_VTEP, "VNI remote VTEP");

/* definitions */


/* static function declarations */
static unsigned int
vni_hash_keymake (void *p);
static int
vni_hash_cmp (const void *p1, const void *p2);
static void *
zvni_alloc (void *p);
static zebra_vni_t *
zvni_lookup (struct zebra_vrf *zvrf, vni_t vni);
static zebra_vni_t *
zvni_add (struct zebra_vrf *zvrf, vni_t vni);
static int
zvni_del (struct zebra_vrf *zvrf, zebra_vni_t *zvni);
static int
zvni_send_add_to_client (struct zebra_vrf *zvrf, zebra_vni_t *zvni);
static int
zvni_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni);
static void
zvni_build_hash_table (struct zebra_vrf *zvrf);
static int
zvni_vtep_match (struct in_addr *vtep_ip, zebra_vtep_t *zvtep);
static zebra_vtep_t *
zvni_vtep_find (zebra_vni_t *zvni, struct in_addr *vtep_ip);
static zebra_vtep_t *
zvni_vtep_add (zebra_vni_t *zvni, struct in_addr *vtep_ip);
static int
zvni_vtep_del (zebra_vni_t *zvni, zebra_vtep_t *zvtep);
static int
zvni_vtep_del_all (zebra_vni_t *zvni, int uninstall);
static int
zvni_vtep_install (zebra_vni_t *zvni, struct in_addr *vtep_ip);
static int
zvni_vtep_uninstall (zebra_vni_t *zvni, struct in_addr *vtep_ip);


/* Private functions */

/*
 * Hash function for VNI.
 */
static unsigned int
vni_hash_keymake (void *p)
{
  const zebra_vni_t *zvni = p;

  return (jhash_1word(zvni->vni, 0));
}

/*
 * Compare 2 VNI hash entries.
 */
static int
vni_hash_cmp (const void *p1, const void *p2)
{
  const zebra_vni_t *zvni1 = p1;
  const zebra_vni_t *zvni2 = p2;

  return (zvni1->vni == zvni2->vni);
}

/*
 * Callback to allocate VNI hash entry.
 */
static void *
zvni_alloc (void *p)
{
  const zebra_vni_t *tmp_vni = p;
  zebra_vni_t *zvni;

  zvni = XCALLOC (MTYPE_ZVNI, sizeof(zebra_vni_t));
  zvni->vni = tmp_vni->vni;
  return ((void *)zvni);
}

/*
 * Look up VNI hash entry.
 */
static zebra_vni_t *
zvni_lookup (struct zebra_vrf *zvrf, vni_t vni)
{
  zebra_vni_t tmp_vni;
  zebra_vni_t *zvni = NULL;

  memset (&tmp_vni, 0, sizeof (zebra_vni_t));
  tmp_vni.vni = vni;
  zvni = hash_lookup (zvrf->vni_table, &tmp_vni);

  return zvni;
}

/*
 * Add VNI hash entry.
 */
static zebra_vni_t *
zvni_add (struct zebra_vrf *zvrf, vni_t vni)
{
  zebra_vni_t tmp_zvni;
  zebra_vni_t *zvni = NULL;

  memset (&tmp_zvni, 0, sizeof (zebra_vni_t));
  tmp_zvni.vni = vni;
  zvni = hash_get (zvrf->vni_table, &tmp_zvni, zvni_alloc);
  assert (zvni);

  return zvni;
}

/*
 * Delete VNI hash entry.
 */
static int
zvni_del (struct zebra_vrf *zvrf, zebra_vni_t *zvni)
{
  zebra_vni_t *tmp_zvni;

  zvni->vxlan_if = NULL;

  /* Free the VNI hash entry and allocated memory. */
  tmp_zvni = hash_release (zvrf->vni_table, zvni);
  if (tmp_zvni)
    XFREE(MTYPE_ZVNI, tmp_zvni);

  return 0;
}

/*
 * Inform BGP about local VNI addition.
 */
static int
zvni_send_add_to_client (struct zebra_vrf *zvrf,
                         zebra_vni_t *zvni)
{
  struct zserv *client;
  struct stream *s;

  client = zebra_find_client (ZEBRA_ROUTE_BGP);
  /* BGP may not be running. */
  if (!client)
    return 0;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, ZEBRA_VNI_ADD, zvrf_id (zvrf));
  stream_putl (s, zvni->vni);
  stream_put_in_addr (s, &zvni->local_vtep_ip);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send VNI_ADD %u %s to %s",
                zvrf_id (zvrf), zvni->vni,
                inet_ntoa(zvni->local_vtep_ip),
                zebra_route_string (client->proto));

  client->vniadd_cnt++;
  return zebra_server_send_message(client);
}

/*
 * Inform BGP about local VNI deletion.
 */
static int
zvni_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni)
{
  struct zserv *client;
  struct stream *s;

  client = zebra_find_client (ZEBRA_ROUTE_BGP);
  /* BGP may not be running. */
  if (!client)
    return 0;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, ZEBRA_VNI_DEL, zvrf_id (zvrf));
  stream_putl (s, vni);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send VNI_DEL %u to %s", zvrf_id (zvrf), vni,
                zebra_route_string (client->proto));

  client->vnidel_cnt++;
  return zebra_server_send_message(client);
}

/*
 * Build the VNI hash table by going over the VxLAN interfaces. This
 * is called when EVPN (advertise-all-vni) is enabled.
 */
static void
zvni_build_hash_table (struct zebra_vrf *zvrf)
{
  struct listnode *node;
  struct interface *ifp;

  /* Walk VxLAN interfaces and create VNI hash. */
  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (zvrf_id (zvrf)), node, ifp))
    {
      struct zebra_if *zif;
      struct zebra_l2info_vxlan *vxl;
      zebra_vni_t *zvni;
      vni_t vni;

      zif = ifp->info;
      if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
        continue;
      vxl = &zif->l2info.vxl;

      vni = vxl->vni;

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Create VNI hash for intf %s(%u) VNI %u local IP %s",
                    zvrf_id (zvrf), ifp->name, ifp->ifindex, vni,
                    inet_ntoa (vxl->vtep_ip));

      /* VNI hash entry is not expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (zvni)
        {
          zlog_err ("VNI hash already present for VRF %d IF %s(%u) VNI %u",
                    zvrf_id (zvrf), ifp->name, ifp->ifindex, vni);
          continue;
        }

      zvni = zvni_add (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to add VNI hash, VRF %d IF %s(%u) VNI %u",
                    zvrf_id (zvrf), ifp->name, ifp->ifindex, vni);
          return;
        }

      zvni->local_vtep_ip = vxl->vtep_ip;
      zvni->vxlan_if = ifp;

      /* Inform BGP if interface is up and mapped to bridge. */
      if (if_is_operative (ifp) &&
          zif->brslave_info.br_if)
        zvni_send_add_to_client (zvrf, zvni);
    }
}

/*
 * See if remote VTEP matches with prefix.
 */
static int
zvni_vtep_match (struct in_addr *vtep_ip, zebra_vtep_t *zvtep)
{
  return (IPV4_ADDR_SAME (vtep_ip, &zvtep->vtep_ip));
}

/*
 * Locate remote VTEP in VNI hash table.
 */
static zebra_vtep_t *
zvni_vtep_find (zebra_vni_t *zvni, struct in_addr *vtep_ip)
{
  zebra_vtep_t *zvtep;

  if (!zvni)
    return NULL;

  for (zvtep = zvni->vteps; zvtep; zvtep = zvtep->next)
    {
      if (zvni_vtep_match (vtep_ip, zvtep))
        break;
    }

  return zvtep;
}

/*
 * Add remote VTEP to VNI hash table.
 */
static zebra_vtep_t *
zvni_vtep_add (zebra_vni_t *zvni, struct in_addr *vtep_ip)
{
  zebra_vtep_t *zvtep;

  zvtep = XCALLOC (MTYPE_ZVNI_VTEP, sizeof(zebra_vtep_t));
  if (!zvtep)
    {
      zlog_err ("Failed to alloc VTEP entry, VNI %u", zvni->vni);
      return NULL;
    }

  zvtep->vtep_ip = *vtep_ip;

  if (zvni->vteps)
    zvni->vteps->prev = zvtep;
  zvtep->next = zvni->vteps;
  zvni->vteps = zvtep;

  return zvtep;
}

/*
 * Remove remote VTEP from VNI hash table.
 */
static int
zvni_vtep_del (zebra_vni_t *zvni, zebra_vtep_t *zvtep)
{
  if (zvtep->next)
    zvtep->next->prev = zvtep->prev;
  if (zvtep->prev)
    zvtep->prev->next = zvtep->next;
  else
    zvni->vteps = zvtep->next;

  zvtep->prev = zvtep->next = NULL;
  XFREE (MTYPE_ZVNI_VTEP, zvtep);

  return 0;
}

/*
 * Delete all remote VTEPs for this VNI (upon VNI delete). Also
 * uninstall from kernel if asked to.
 */
static int
zvni_vtep_del_all (zebra_vni_t *zvni, int uninstall)
{
  zebra_vtep_t *zvtep, *zvtep_next;

  if (!zvni)
    return -1;

  for (zvtep = zvni->vteps; zvtep; zvtep = zvtep_next)
    {
      zvtep_next = zvtep->next;
      if (uninstall)
        zvni_vtep_uninstall (zvni, &zvtep->vtep_ip);
      zvni_vtep_del (zvni, zvtep);
    }

  return 0;
}

/*
 * Install remote VTEP into the kernel.
 */
static int
zvni_vtep_install (zebra_vni_t *zvni, struct in_addr *vtep_ip)
{
  return kernel_add_vtep (zvni->vni, zvni->vxlan_if, vtep_ip);
}

/*
 * Uninstall remote VTEP from the kernel.
 */
static int
zvni_vtep_uninstall (zebra_vni_t *zvni, struct in_addr *vtep_ip)
{
  if (!zvni->vxlan_if)
    {
      zlog_err ("VNI %u hash %p couldn't be uninstalled - no intf",
                zvni->vni, zvni);
      return -1;
    }

  return kernel_del_vtep (zvni->vni, zvni->vxlan_if, vtep_ip);
}

/*
 * Cleanup VNI/VTEP and update kernel
 */
static void
zvni_cleanup_all (struct hash_backet *backet, void *zvrf)
{
  zebra_vni_t *zvni;

  zvni = (zebra_vni_t *) backet->data;
  if (!zvni)
    return;

  /* Free up all remote VTEPs, if any. */
  zvni_vtep_del_all (zvni, 1);

  /* Delete the hash entry. */
  zvni_del (zvrf, zvni);
}


/* Public functions */

/*
 * Handle message from client to delete a remote VTEP for a VNI.
 */
int zebra_vxlan_remote_vtep_del (struct zserv *client, int sock,
                                 u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  u_short l = 0;
  vni_t vni;
  struct in_addr vtep_ip;
  zebra_vni_t *zvni;
  zebra_vtep_t *zvtep;

  s = client->ibuf;

  while (l < length)
    {
      /* Obtain each remote VTEP and process. */
      vni = (vni_t) stream_getl (s);
      l += 4;
      vtep_ip.s_addr = stream_get_ipv4 (s);
      l += IPV4_MAX_BYTELEN;

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Recv VTEP_DEL %s VNI %u from %s",
                    zvrf_id (zvrf), inet_ntoa (vtep_ip),
                    vni, zebra_route_string (client->proto));

      /* Locate VNI hash entry - expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (!zvni)
        {
          if (IS_ZEBRA_DEBUG_VXLAN)
            zlog_debug ("Failed to locate VNI hash upon remote VTEP DEL, "
                        "VRF %d VNI %u", zvrf_id (zvrf), vni);
          continue;
        }

      /* If the remote VTEP does not exist, there's nothing more to do.
       * Otherwise, uninstall any remote MACs pointing to this VTEP and
       * then, the VTEP entry itself and remove it.
       */
      zvtep = zvni_vtep_find (zvni, &vtep_ip);
      if (!zvtep)
        continue;

      zvni_vtep_uninstall (zvni, &vtep_ip);
      zvni_vtep_del (zvni, zvtep);
    }

  return 0;
}

/*
 * Handle message from client to add a remote VTEP for a VNI.
 */
int zebra_vxlan_remote_vtep_add (struct zserv *client, int sock,
                                 u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  u_short l = 0;
  vni_t vni;
  struct in_addr vtep_ip;
  zebra_vni_t *zvni;

  assert (EVPN_ENABLED (zvrf));

  s = client->ibuf;

  while (l < length)
    {
      /* Obtain each remote VTEP and process. */
      vni = (vni_t) stream_getl (s);
      l += 4;
      vtep_ip.s_addr = stream_get_ipv4 (s);
      l += IPV4_MAX_BYTELEN;

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Recv VTEP_ADD %s VNI %u from %s",
                    zvrf_id (zvrf), inet_ntoa (vtep_ip),
                    vni, zebra_route_string (client->proto));

      /* Locate VNI hash entry - expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to locate VNI hash upon remote VTEP ADD, VRF %d VNI %u",
                    zvrf_id (zvrf), vni);
          continue;
        }
      if (!zvni->vxlan_if)
        {
          zlog_err ("VNI %u hash %p doesn't have intf upon remote VTEP ADD",
                    zvni->vni, zvni);
          continue;
        }


      /* If the remote VTEP already exists, or the local VxLAN interface is
       * not up (should be a transient event),  there's nothing more to do.
       * Otherwise, add and install the entry.
       */
      if (zvni_vtep_find (zvni, &vtep_ip))
        continue;

      if (!if_is_operative (zvni->vxlan_if))
        continue;

      if (zvni_vtep_add (zvni, &vtep_ip) == NULL)
        {
          zlog_err ("Failed to add remote VTEP, VRF %d VNI %u zvni %p",
                    zvrf_id (zvrf), vni, zvni);
          continue;
        }

      zvni_vtep_install (zvni, &vtep_ip);
    }

  return 0;
}

/*
 * Handle VxLAN interface down - update BGP if required, and do
 * internal cleanup.
 */
int
zebra_vxlan_if_down (struct interface *ifp)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  zebra_vni_t *zvni;
  struct zebra_l2info_vxlan *vxl;
  vni_t vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* If EVPN is not enabled, nothing further to be done. */
  if (!EVPN_ENABLED(zvrf))
    return 0;

  zif = ifp->info;
  assert(zif);
  vxl = &zif->l2info.vxl;
  vni = vxl->vni;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Intf %s(%u) VNI %u is DOWN",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash at DOWN, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return -1;
    }

  assert (zvni->vxlan_if == ifp);

  /* Delete this VNI from BGP. */
  zvni_send_del_to_client (zvrf, zvni->vni);

  /* Free up all remote VTEPs, if any. */
  zvni_vtep_del_all (zvni, 1);

  return 0;
}

/*
 * Handle VxLAN interface up - update BGP if required.
 */
int
zebra_vxlan_if_up (struct interface *ifp)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  zebra_vni_t *zvni;
  struct zebra_l2info_vxlan *vxl;
  vni_t vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* If EVPN is not enabled, nothing further to be done. */
  if (!EVPN_ENABLED(zvrf))
    return 0;

  zif = ifp->info;
  assert(zif);
  vxl = &zif->l2info.vxl;
  vni = vxl->vni;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Intf %s(%u) VNI %u is UP",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash at UP, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return -1;
    }

  assert (zvni->vxlan_if == ifp);

  /* If part of a bridge, inform BGP about this VNI. */
  if (zif->brslave_info.br_if)
    zvni_send_add_to_client (zvrf, zvni);

  return 0;
}

/*
 * Handle VxLAN interface delete. Locate and remove entry in hash table
 * and update BGP, if required.
 */
int
zebra_vxlan_if_del (struct interface *ifp)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  zebra_vni_t *zvni;
  struct zebra_l2info_vxlan *vxl;
  vni_t vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* If EVPN is not enabled, nothing further to be done. */
  if (!EVPN_ENABLED(zvrf))
    return 0;

  zif = ifp->info;
  assert(zif);
  vxl = &zif->l2info.vxl;
  vni = vxl->vni;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Del intf %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash at del, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return 0;
    }

  /* Delete VNI from BGP. */
  zvni_send_del_to_client (zvrf, zvni->vni);

  /* Free up all remote VTEPs, if any. */
  zvni_vtep_del_all (zvni, 0);

  /* Delete the hash entry. */
  if (zvni_del (zvrf, zvni))
    {
      zlog_err ("Failed to del VNI hash %p, VRF %d IF %s(%u) VNI %u",
                zvni, ifp->vrf_id, ifp->name, ifp->ifindex, zvni->vni);
      return -1;
    }

  return 0;
}

/*
 * Handle VxLAN interface update - change to tunnel IP, master or VLAN.
 */
int
zebra_vxlan_if_update (struct interface *ifp, u_int16_t chgflags)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  zebra_vni_t *zvni;
  struct zebra_l2info_vxlan *vxl;
  vni_t vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* If EVPN is not enabled, nothing further to be done. */
  if (!EVPN_ENABLED(zvrf))
    return 0;

  zif = ifp->info;
  assert(zif);
  vxl = &zif->l2info.vxl;
  vni = vxl->vni;

  /* Update VNI hash. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to find VNI hash on update, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return -1;
    }

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Update intf %s(%u) VNI %u VLAN %u local IP %s "
                "master %u chg 0x%x",
                ifp->vrf_id, ifp->name, ifp->ifindex,
                vni, vxl->access_vlan,
                inet_ntoa (vxl->vtep_ip),
                zif->brslave_info.bridge_ifindex, chgflags);

  /* Removed from bridge? */
  if ((chgflags & ZEBRA_VXLIF_MASTER_CHANGE) &&
      (zif->brslave_info.bridge_ifindex == IFINDEX_INTERNAL))
    {
      /* Delete from client, remove all remote VTEPs */
      zvni_send_del_to_client (zvrf, zvni->vni);
      zvni_vtep_del_all (zvni, 1);
    }

  zvni->local_vtep_ip = vxl->vtep_ip;
  zvni->vxlan_if = ifp;

  /* Take further actions needed. Note that if we are here, there is a
   * change of interest.
   */
  /* If down or not mapped to a bridge, we're done. */
  if (!if_is_operative (ifp) || !zif->brslave_info.br_if)
    return 0;

  /* Inform BGP. */
  zvni_send_add_to_client (zvrf, zvni);

  return 0;
}

/*
 * Handle VxLAN interface add.
 */
int
zebra_vxlan_if_add (struct interface *ifp)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  zebra_vni_t *zvni;
  struct zebra_l2info_vxlan *vxl;
  vni_t vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* If EVPN is not enabled, nothing further to be done. */
  if (!EVPN_ENABLED(zvrf))
    return 0;

  zif = ifp->info;
  assert(zif);
  vxl = &zif->l2info.vxl;
  vni = vxl->vni;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Add intf %s(%u) VNI %u VLAN %u local IP %s master %u",
                ifp->vrf_id, ifp->name, ifp->ifindex,
                vni, vxl->access_vlan,
                inet_ntoa (vxl->vtep_ip),
                zif->brslave_info.bridge_ifindex);

  /* Create or update VNI hash. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zvni = zvni_add (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to add VNI hash, VRF %d IF %s(%u) VNI %u",
                    ifp->vrf_id, ifp->name, ifp->ifindex, vni);
          return -1;
        }
    }

  zvni->local_vtep_ip = vxl->vtep_ip;
  zvni->vxlan_if = ifp;

  /* If down or not mapped to a bridge, we're done. */
  if (!if_is_operative (ifp) || !zif->brslave_info.br_if)
    return 0;

  /* Inform BGP */
  zvni_send_add_to_client (zvrf, zvni);

  return 0;
}

/*
 * Handle message from client to learn (or stop learning) about VNIs and MACs.
 * When enabled, the VNI hash table will be built and MAC FDB table read;
 * when disabled, the entries should be deleted and remote VTEPs and MACs
 * uninstalled from the kernel.
 */
int zebra_vxlan_advertise_all_vni (struct zserv *client, int sock,
                                   u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  int advertise;

  s = client->ibuf;
  advertise = stream_getc (s);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:EVPN VNI Adv %s, currently %s",
                zvrf_id (zvrf), advertise ? "enabled" : "disabled",
                EVPN_ENABLED(zvrf) ? "enabled" : "disabled");

  if (zvrf->advertise_all_vni == advertise)
    return 0;

  zvrf->advertise_all_vni = advertise;
  if (EVPN_ENABLED(zvrf))
    {
      /* Build VNI hash table and inform BGP. */
      zvni_build_hash_table (zvrf);
    }
  else
    {
      /* Cleanup VTEPs for all VNIs - uninstall from
       * kernel and free entries.
       */
      hash_iterate (zvrf->vni_table, zvni_cleanup_all, zvrf);
    }

  return 0;
}

/*
 * Allocate VNI hash table for this VRF and do other initialization.
 * NOTE: Currently supported only for default VRF.
 */
void
zebra_vxlan_init_tables (struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return;
  zvrf->vni_table = hash_create(vni_hash_keymake,
				vni_hash_cmp,
				"Zebra VRF VNI Table");
}

/* Close all VNI handling */
void
zebra_vxlan_close_tables (struct zebra_vrf *zvrf)
{
  hash_iterate (zvrf->vni_table, zvni_cleanup_all, zvrf);
}
