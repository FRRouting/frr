/*
 * OSPFv3 NSSA
 * Copyright (c) 2019-2020, Niral Networks.
 * Kaushik Nath
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
#ifndef OSPF6_NSSA_H
#define OSPF6_NSSA_H

#define OSPF6_OPTION_NP   	     0x08
#define OSPF6_LS_INFINITY            0xffffff

#define OSPF6_OPT_N  (1 << 3)   /* Handling Type-7 LSA Capability */

#define OSPF6_DEBUG_NSSA         0x09
/* Debug option */
extern unsigned char config_debug_ospf6_nssa;

#define OSPF6_DEBUG_NSSA_ON() 		(config_debug_ospf6_nssa = 1)
#define OSPF6_DEBUG_NSSA_OFF() 		(config_debug_ospf6_nssa = 0)
#define IS_OSPF6_DEBUG_NSSA             config_debug_ospf6_nssa

#define CHECK_LSA_TYPE_1_TO_5_OR_7(type)                                                  \
       ((type == OSPF6_ROUTER_LSA_MIN_SIZE) || (type == OSPF6_NETWORK_LSA_MIN_SIZE)       \
        || (type == OSPF6_LINK_LSA_MIN_SIZE) || (type == OSPF6_INTRA_PREFIX_LSA_MIN_SIZE) \
        || (type == OSPF6_AS_NSSA_LSA))

#define OSPF6_LSA_APPROVED          	0x08
#define OSPF6_LSA_LOCAL_XLT         	0x40

#define OSPF6_ABR_TASK_DELAY     	7

struct ospf6 *ospf6;
struct ospf6_area *area;

int ospf6_area_nssa_no_summary_set(struct ospf6 *ospf6, struct in_addr area_id);
int ospf6_area_nssa_unset(struct ospf6 *ospf6, struct ospf6_area *area);
int ospf6_area_nssa_set(struct ospf6 *ospf6, struct ospf6_area *area);

extern void ospf6_nssa_lsa_flush(struct ospf6 *ospf6, struct prefix_ipv6 *p);
extern struct ospf6_lsa *ospf6_translated_nssa_refresh(struct ospf6 *,
                                                      struct ospf6_lsa *,
                                                      struct ospf6_lsa *);
extern struct ospf6_lsa *ospf6_translated_nssa_originate(struct ospf6 *,
                                                       struct ospf6_lsa *);

extern void ospf6_asbr_nssa_redist_task(struct ospf6 *ospf6);

void ospf6_schedule_abr_task(struct ospf6 *ospf6);
void ospf6_asbr_prefix_readvertise(struct ospf6 *ospf6);
extern void ospf6_nssa_lsa_originate(struct ospf6_route *route, struct ospf6_area *area);
extern void install_element_ospf6_debug_nssa(void);
int ospf6_redistribute_check(struct ospf6 *ospf6, struct ospf6_route *route, int type);
#endif /* OSPF6_NSSA_H */
