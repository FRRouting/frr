/* 
 * Copyright (C) 2006 Sun Microsystems, Inc.
 *
 * This file is part of Quagga.
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
#include "zebra/rib.h"
#include "zebra/zserv.h"

#include "zebra/redistribute.h"

void zebra_redistribute_add (int a, struct zserv *b, int c,
			     struct zebra_vrf *zvrf)
{ return; }
void zebra_redistribute_delete  (int a, struct zserv *b, int c,
				 struct zebra_vrf *zvrf)
{ return; }
void zebra_redistribute_default_add (int a, struct zserv *b, int c,
				     struct zebra_vrf *zvrf)
{ return; }
void zebra_redistribute_default_delete (int a, struct zserv *b, int c,
					struct zebra_vrf *zvrf)
{ return; }

void redistribute_update (struct prefix *a, struct rib *b, struct rib *c)
{ return; }
void redistribute_delete (struct prefix *a, struct rib *b)
{ return; }

void zebra_interface_up_update (struct interface *a)
{ return; }
void zebra_interface_down_update  (struct interface *a)
{ return; }
void zebra_interface_add_update (struct interface *a)
{ return; }
void zebra_interface_delete_update (struct interface *a)
{ return; }


void zebra_interface_address_add_update (struct interface *a,
					 	struct connected *b)
{ return; }
void zebra_interface_address_delete_update (struct interface *a,
                                                struct connected *b)
{ return; }

/* Interface parameters update */
void zebra_interface_parameters_update (struct interface *ifp)
{ return; };

void zebra_interface_vrf_update_del (struct interface *a, vrf_id_t new_vrf_id)
{ return; }

void zebra_interface_vrf_update_add (struct interface *a, vrf_id_t old_vrf_id)
{ return; }

int zebra_import_table (afi_t afi, u_int32_t table_id, u_int32_t distance,
			const char *rmap_name, int add)
{ return 0; }

int zebra_add_import_table_entry (struct route_node *rn, struct rib *rib, const char *rmap_name)
{ return 0; }

int zebra_del_import_table_entry (struct route_node *rn, struct rib *rib)
{ return 0; }

int is_zebra_import_table_enabled(afi_t afi, u_int32_t table_id)
{ return 0; }

int zebra_import_table_config(struct vty *vty)
{ return 0; }

void zebra_import_table_rm_update()
{ return; }
