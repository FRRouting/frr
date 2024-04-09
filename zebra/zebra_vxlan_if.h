/*
 * Zebra VxLAN (EVPN) interface data structures and definitions
 * These are public definitions referenced by other files.
 * Copyright (C) 2021 Cumulus Networks, Inc.
 * Sharath Ramamurthy
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

#ifndef _ZEBRA_VXLAN_IF_H
#define _ZEBRA_VXLAN_IF_H

#include <zebra.h>
#include <zebra/zebra_router.h>

#include "linklist.h"
#include "if.h"
#include "vlan.h"
#include "vxlan.h"

#include "lib/json.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zserv.h"
#include "zebra/zebra_dplane.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void *zebra_vxlan_vni_alloc(void *p);
extern void zebra_vxlan_vni_free(void *arg);
extern struct hash *zebra_vxlan_vni_table_create(void);
extern void zebra_vxlan_vni_table_destroy(struct hash *vni_table);
extern int zebra_vxlan_if_vni_table_create(struct zebra_if *zif);
extern int zebra_vxlan_if_vni_table_destroy(struct zebra_if *zif);
extern struct zebra_vxlan_vni *
zebra_vxlan_if_vni_find(const struct zebra_if *zif, vni_t vni);
extern struct zebra_vxlan_vni *
zebra_vxlan_if_vlanid_vni_find(struct zebra_if *zif, vlanid_t vni);
extern void zebra_vxlan_if_vni_iterate(struct zebra_if *zif,
				       int (*func)(struct zebra_if *zif,
						   struct zebra_vxlan_vni *,
						   void *),
				       void *arg);
extern void zebra_vxlan_if_vni_walk(struct zebra_if *zif,
				    int (*func)(struct zebra_if *zif,
						struct zebra_vxlan_vni *,
						void *),
				    void *arg);
extern vni_t zebra_vxlan_if_access_vlan_vni_find(struct zebra_if *zif,
						 struct interface *br_if);
extern int
zebra_vxlan_if_vni_mcast_group_add_update(struct interface *ifp, vni_t vni_id,
					  struct in_addr *mcast_group);
extern int zebra_vxlan_if_vni_mcast_group_del(struct interface *ifp,
					      vni_t vni_id,
					      struct in_addr *mcast_group);
extern int zebra_vxlan_if_vni_down(struct interface *ifp,
				   struct zebra_vxlan_vni *vni);
extern int zebra_vxlan_if_down(struct interface *ifp);
extern int zebra_vxlan_if_vni_up(struct interface *ifp,
				 struct zebra_vxlan_vni *vni);
extern int zebra_vxlan_if_up(struct interface *ifp);
extern int zebra_vxlan_if_vni_del(struct interface *ifp, vni_t vni);
extern int zebra_vxlan_if_del(struct interface *ifp);
extern int zebra_vxlan_if_vni_table_add_update(struct interface *ifp,
					       struct hash *vni_table);
extern int zebra_vxlan_if_vni_update(struct interface *ifp,
				     struct zebra_vxlan_vni *vni,
				     uint16_t chgflags);
extern int zebra_vxlan_if_update(struct interface *ifp,
				 struct zebra_vxlan_if_update_ctx *ctx);
extern int zebra_vxlan_if_vni_add(struct interface *ifp,
				  struct zebra_vxlan_vni *vni);
extern int zebra_vxlan_if_add(struct interface *ifp);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_VXLAN_IF_H */
