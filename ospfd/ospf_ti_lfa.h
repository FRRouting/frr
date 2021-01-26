/*
 * OSPF calculation.
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Sascha Kattelmann
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _OSPF_TI_LFA_H
#define _OSPF_TI_LFA_H

#define PROTECTED_RESOURCE_STRLEN 100

extern void ospf_ti_lfa_compute(struct ospf_area *area,
				struct route_table *new_table,
				enum protection_type protection_type);

/* unit testing */
extern void ospf_ti_lfa_generate_p_spaces(struct ospf_area *area,
					  enum protection_type protection_type);
extern void ospf_ti_lfa_insert_backup_paths(struct ospf_area *area,
					    struct route_table *new_table);
extern void ospf_ti_lfa_free_p_spaces(struct ospf_area *area);
void ospf_print_protected_resource(
	struct protected_resource *protected_resource, char *buf);

#endif /* _OSPF_TI_LFA_H */
