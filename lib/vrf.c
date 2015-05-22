/*
 * VRF functions.
 * Copyright (C) 2014 6WIND S.A.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>

#include "vrf.h"
#include "prefix.h"
#include "table.h"
#include "log.h"
#include "memory.h"

struct vrf
{
  /* Identifier, same as the vector index */
  vrf_id_t vrf_id;
  /* Name */
  char *name;

  /* User data */
  void *info;
};

/* Holding VRF hooks  */
struct vrf_master
{
  int (*vrf_new_hook) (vrf_id_t, void **);
  int (*vrf_delete_hook) (vrf_id_t, void **);
} vrf_master = {0,};

/* VRF table */
struct route_table *vrf_table = NULL;

/* Build the table key */
static void
vrf_build_key (vrf_id_t vrf_id, struct prefix *p)
{
  p->family = AF_INET;
  p->prefixlen = IPV4_MAX_BITLEN;
  p->u.prefix4.s_addr = vrf_id;
}

/* Get a VRF. If not found, create one. */
static struct vrf *
vrf_get (vrf_id_t vrf_id)
{
  struct prefix p;
  struct route_node *rn;
  struct vrf *vrf;

  vrf_build_key (vrf_id, &p);
  rn = route_node_get (vrf_table, &p);
  if (rn->info)
    {
      vrf = (struct vrf *)rn->info;
      route_unlock_node (rn); /* get */
      return vrf;
    }

  vrf = XCALLOC (MTYPE_VRF, sizeof (struct vrf));
  vrf->vrf_id = vrf_id;
  rn->info = vrf;

  zlog_info ("VRF %u is created.", vrf_id);

  if (vrf_master.vrf_new_hook)
    (*vrf_master.vrf_new_hook) (vrf_id, &vrf->info);

  return vrf;
}

/* Delete a VRF. This is called in vrf_terminate(). */
static void
vrf_delete (struct vrf *vrf)
{
  zlog_info ("VRF %u is to be deleted.", vrf->vrf_id);

  if (vrf_master.vrf_delete_hook)
    (*vrf_master.vrf_delete_hook) (vrf->vrf_id, &vrf->info);

  if (vrf->name)
    XFREE (MTYPE_VRF_NAME, vrf->name);

  XFREE (MTYPE_VRF, vrf);
}

/* Look up a VRF by identifier. */
static struct vrf *
vrf_lookup (vrf_id_t vrf_id)
{
  struct prefix p;
  struct route_node *rn;
  struct vrf *vrf = NULL;

  vrf_build_key (vrf_id, &p);
  rn = route_node_lookup (vrf_table, &p);
  if (rn)
    {
      vrf = (struct vrf *)rn->info;
      route_unlock_node (rn); /* lookup */
    }
  return vrf;
}

/* Add a VRF hook. Please add hooks before calling vrf_init(). */
void
vrf_add_hook (int type, int (*func)(vrf_id_t, void **))
{
  switch (type) {
  case VRF_NEW_HOOK:
    vrf_master.vrf_new_hook = func;
    break;
  case VRF_DELETE_HOOK:
    vrf_master.vrf_delete_hook = func;
    break;
  default:
    break;
  }
}

/* Return the iterator of the first VRF. */
vrf_iter_t
vrf_first (void)
{
  struct route_node *rn;

  for (rn = route_top (vrf_table); rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* top/next */
        return (vrf_iter_t)rn;
      }
  return VRF_ITER_INVALID;
}

/* Return the next VRF iterator to the given iterator. */
vrf_iter_t
vrf_next (vrf_iter_t iter)
{
  struct route_node *rn = NULL;

  /* Lock it first because route_next() will unlock it. */
  if (iter != VRF_ITER_INVALID)
    rn = route_next (route_lock_node ((struct route_node *)iter));

  for (; rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* next */
        return (vrf_iter_t)rn;
      }
  return VRF_ITER_INVALID;
}

/* Return the VRF iterator of the given VRF ID. If it does not exist,
 * the iterator of the next existing VRF is returned. */
vrf_iter_t
vrf_iterator (vrf_id_t vrf_id)
{
  struct prefix p;
  struct route_node *rn;

  vrf_build_key (vrf_id, &p);
  rn = route_node_get (vrf_table, &p);
  if (rn->info)
    {
      /* OK, the VRF exists. */
      route_unlock_node (rn); /* get */
      return (vrf_iter_t)rn;
    }

  /* Find the next VRF. */
  for (rn = route_next (rn); rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* next */
        return (vrf_iter_t)rn;
      }

  return VRF_ITER_INVALID;
}

/* Obtain the VRF ID from the given VRF iterator. */
vrf_id_t
vrf_iter2id (vrf_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct vrf *)rn->info)->vrf_id : VRF_DEFAULT;
}

/* Obtain the data pointer from the given VRF iterator. */
void *
vrf_iter2info (vrf_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct vrf *)rn->info)->info : NULL;
}

/* Get the data pointer of the specified VRF. If not found, create one. */
void *
vrf_info_get (vrf_id_t vrf_id)
{
  struct vrf *vrf = vrf_get (vrf_id);
  return vrf->info;
}

/* Look up the data pointer of the specified VRF. */
void *
vrf_info_lookup (vrf_id_t vrf_id)
{
  struct vrf *vrf = vrf_lookup (vrf_id);
  return vrf ? vrf->info : NULL;
}

/* Initialize VRF module. */
void
vrf_init (void)
{
  struct vrf *default_vrf;

  /* Allocate VRF table.  */
  vrf_table = route_table_init ();

  /* The default VRF always exists. */
  default_vrf = vrf_get (VRF_DEFAULT);
  if (!default_vrf)
    {
      zlog_err ("vrf_init: failed to create the default VRF!");
      exit (1);
    }

  /* Set the default VRF name. */
  default_vrf->name = XSTRDUP (MTYPE_VRF_NAME, "Default-IP-Routing-Table");
}

/* Terminate VRF module. */
void
vrf_terminate (void)
{
  struct route_node *rn;
  struct vrf *vrf;

  for (rn = route_top (vrf_table); rn; rn = route_next (rn))
    if ((vrf = rn->info) != NULL)
      vrf_delete (vrf);

  route_table_finish (vrf_table);
  vrf_table = NULL;
}

