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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_REDISTRIBUTE_H
#define _ZEBRA_REDISTRIBUTE_H

#include "table.h"
#include "vty.h"
#include "vrf.h"

#include "zebra/zserv.h"
#include "zebra/rib.h"

/* ZAPI command handlers */
extern void zebra_redistribute_add(ZAPI_HANDLER_ARGS);
extern void zebra_redistribute_delete(ZAPI_HANDLER_ARGS);
extern void zebra_redistribute_default_add(ZAPI_HANDLER_ARGS);
extern void zebra_redistribute_default_delete(ZAPI_HANDLER_ARGS);
/* ----------------- */

extern void redistribute_update(struct prefix *, struct prefix *,
				struct route_entry *, struct route_entry *);
extern void redistribute_delete(struct prefix *, struct prefix *,
				struct route_entry *);

extern void zebra_interface_up_update(struct interface *);
extern void zebra_interface_down_update(struct interface *);

extern void zebra_interface_add_update(struct interface *);
extern void zebra_interface_delete_update(struct interface *);

extern void zebra_interface_address_add_update(struct interface *,
					       struct connected *);
extern void zebra_interface_address_delete_update(struct interface *,
						  struct connected *c);
extern void zebra_interface_parameters_update(struct interface *);
extern void zebra_interface_vrf_update_del(struct interface *,
					   vrf_id_t new_vrf_id);
extern void zebra_interface_vrf_update_add(struct interface *,
					   vrf_id_t old_vrf_id);

extern int zebra_import_table(afi_t afi, uint32_t table_id, uint32_t distance,
			      const char *rmap_name, int add);

extern int zebra_add_import_table_entry(struct route_node *rn,
					struct route_entry *re,
					const char *rmap_name);
extern int zebra_del_import_table_entry(struct route_node *rn,
					struct route_entry *re);
extern int is_zebra_import_table_enabled(afi_t, uint32_t table_id);

extern int zebra_import_table_config(struct vty *);

extern void zebra_import_table_rm_update(void);

#endif /* _ZEBRA_REDISTRIBUTE_H */
