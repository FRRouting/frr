// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF calculation.
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Sascha Kattelmann
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
