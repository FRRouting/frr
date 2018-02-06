/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

#ifndef OSPF6_TOP_H
#define OSPF6_TOP_H

#include "qobj.h"
#include "routemap.h"

/* OSPFv3 top level data structure */
struct ospf6 {
	/* my router id */
	u_int32_t router_id;

	/* static router id */
	u_int32_t router_id_static;

	/* start time */
	struct timeval starttime;

	/* list of areas */
	struct list *area_list;
	struct ospf6_area *backbone;

	/* AS scope link state database */
	struct ospf6_lsdb *lsdb;
	struct ospf6_lsdb *lsdb_self;

	struct ospf6_route_table *route_table;
	struct ospf6_route_table *brouter_table;

	struct ospf6_route_table *external_table;
	struct route_table *external_id_table;
	u_int32_t external_id;

	/* redistribute route-map */
	struct {
		char *name;
		struct route_map *map;
	} rmap[ZEBRA_ROUTE_MAX];

	u_char flag;

	/* Configured flags */
	u_char config_flags;
#define OSPF6_LOG_ADJACENCY_CHANGES      (1 << 0)
#define OSPF6_LOG_ADJACENCY_DETAIL       (1 << 1)

	/* LSA timer parameters */
	unsigned int lsa_minarrival; /* LSA minimum arrival in milliseconds. */

	/* SPF parameters */
	unsigned int spf_delay;	/* SPF delay time. */
	unsigned int spf_holdtime;     /* SPF hold time. */
	unsigned int spf_max_holdtime; /* SPF maximum-holdtime */
	unsigned int
		spf_hold_multiplier; /* Adaptive multiplier for hold time */
	unsigned int spf_reason;     /* reason bits while scheduling SPF */

	struct timeval ts_spf;		/* SPF calculation time stamp. */
	struct timeval ts_spf_duration; /* Execution time of last SPF */
	unsigned int last_spf_reason;   /* Last SPF reason */

	/* Threads */
	struct thread *t_spf_calc; /* SPF calculation timer. */
	struct thread *t_ase_calc; /* ASE calculation timer. */
	struct thread *maxage_remover;
	struct thread *t_distribute_update; /* Distirbute update timer. */

	u_int32_t ref_bandwidth;

	/* Distance parameters */
	u_char distance_all;
	u_char distance_intra;
	u_char distance_inter;
	u_char distance_external;

	struct route_table *distance_table;

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(ospf6)

#define OSPF6_DISABLED    0x01
#define OSPF6_STUB_ROUTER 0x02

/* global pointer for OSPF top data structure */
extern struct ospf6 *ospf6;

/* prototypes */
extern void ospf6_top_init(void);
extern void ospf6_delete(struct ospf6 *o);

extern void ospf6_maxage_remove(struct ospf6 *o);

#endif /* OSPF6_TOP_H */
