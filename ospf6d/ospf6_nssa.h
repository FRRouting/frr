// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 Not So Stubby Area implementation.
 *
 * Copyright (C) 2021 Kaushik Nath
 * Copyright (C) 2021 Soman K.S
 */

#ifndef OSPF6_NSSA_H
#define OSPF6_NSSA_H

/* Debug option */
extern unsigned char config_debug_ospf6_nssa;

#define OSPF6_DEBUG_NSSA_ON() (config_debug_ospf6_nssa = 1)
#define OSPF6_DEBUG_NSSA_OFF() (config_debug_ospf6_nssa = 0)
#define IS_OSPF6_DEBUG_NSSA config_debug_ospf6_nssa

int ospf6_area_nssa_no_summary_set(struct ospf6 *ospf6, struct in_addr area_id);
int ospf6_area_nssa_unset(struct ospf6 *ospf6, struct ospf6_area *area);
int ospf6_area_nssa_set(struct ospf6 *ospf6, struct ospf6_area *area);

extern void ospf6_nssa_lsa_flush(struct ospf6 *ospf6, struct prefix_ipv6 *p);
extern struct ospf6_lsa *ospf6_translated_nssa_refresh(struct ospf6_area *oa,
						       struct ospf6_lsa *type7,
						       struct ospf6_lsa *type5);

extern void ospf6_asbr_nssa_redist_task(struct ospf6 *ospf6);

extern void ospf6_area_nssa_update(struct ospf6_area *area);
extern void ospf6_nssa_lsa_originate(struct ospf6_route *route,
				     struct ospf6_area *area, bool p_bit);
extern void install_element_ospf6_debug_nssa(void);
extern void ospf6_abr_nssa_type_7_defaults(struct ospf6 *osof6);
extern void ospf6_abr_nssa_task(struct ospf6 *ospf6);
extern void ospf6_abr_check_translate_nssa(struct ospf6_area *area,
					   struct ospf6_lsa *lsa);
extern void ospf6_abr_nssa_check_status(struct ospf6 *ospf6);
extern void config_write_ospf6_debug_nssa(struct vty *vty);
#endif /* OSPF6_NSSA_H */
