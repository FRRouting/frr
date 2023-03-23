// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF AS External route calculation.
 * Copyright (C) 1999, 2000 Alex Zinin, Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_ASE_H
#define _ZEBRA_OSPF_ASE_H

extern struct ospf_route *
ospf_find_asbr_route(struct ospf *, struct route_table *, struct prefix_ipv4 *);
extern struct ospf_route *
ospf_find_asbr_route_through_area(struct route_table *, struct prefix_ipv4 *,
				  struct ospf_area *);

extern int ospf_ase_calculate_route(struct ospf *, struct ospf_lsa *);
extern void ospf_ase_calculate_schedule(struct ospf *);
extern void ospf_ase_calculate_timer_add(struct ospf *);

extern void ospf_ase_external_lsas_finish(struct route_table *);
extern void ospf_ase_incremental_update(struct ospf *, struct ospf_lsa *);
extern void ospf_ase_register_external_lsa(struct ospf_lsa *, struct ospf *);
extern void ospf_ase_unregister_external_lsa(struct ospf_lsa *, struct ospf *);

#endif /* _ZEBRA_OSPF_ASE_H */
