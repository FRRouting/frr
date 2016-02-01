/*
 * Redistribution Handler
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _ZEBRA_REDISTRIBUTE_H
#define _ZEBRA_REDISTRIBUTE_H

#include "table.h"
#include "zserv.h"
#include "vty.h"
#include "vrf.h"

extern void zebra_redistribute_add (int, struct zserv *, int, vrf_id_t);
extern void zebra_redistribute_delete (int, struct zserv *, int, vrf_id_t);

extern void zebra_redistribute_default_add (int, struct zserv *, int,
    vrf_id_t);
extern void zebra_redistribute_default_delete (int, struct zserv *, int,
    vrf_id_t);

extern void redistribute_update (struct prefix *, struct rib *, struct rib *);
extern void redistribute_delete (struct prefix *, struct rib *);

extern void zebra_interface_up_update (struct interface *);
extern void zebra_interface_down_update (struct interface *);

extern void zebra_vrf_add_update (struct vrf *);
extern void zebra_vrf_update_all (struct zserv *);
extern void zebra_vrf_delete_update (struct vrf *);
extern void zebra_interface_add_update (struct interface *);
extern void zebra_interface_delete_update (struct interface *);

extern void zebra_interface_address_add_update (struct interface *,
					 	struct connected *);
extern void zebra_interface_address_delete_update (struct interface *,
						   struct connected *c);
extern int zebra_import_table (afi_t afi, u_int32_t table_id,
			       u_int32_t metric, int add);

extern int zebra_add_import_table_entry (struct route_node *rn,
					 struct rib *rib);
extern int zebra_del_import_table_entry (struct route_node *rn,
					 struct rib *rib);
extern int is_zebra_import_table_enabled(afi_t, u_int32_t table_id);

extern int zebra_import_table_config(struct vty *);

extern int is_default (struct prefix *);

#endif /* _ZEBRA_REDISTRIBUTE_H */

