// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_INTRA_H
#define OSPF6_INTRA_H

/* Debug option */
extern unsigned char conf_debug_ospf6_brouter;
extern in_addr_t conf_debug_ospf6_brouter_specific_router_id;
extern in_addr_t conf_debug_ospf6_brouter_specific_area_id;
#define OSPF6_DEBUG_BROUTER_SUMMARY         0x01
#define OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER 0x02
#define OSPF6_DEBUG_BROUTER_SPECIFIC_AREA   0x04

#define OSPF6_DEBUG_BROUTER_ON()                                               \
	(conf_debug_ospf6_brouter |= OSPF6_DEBUG_BROUTER_SUMMARY)

#define OSPF6_DEBUG_BROUTER_OFF()                                              \
	(conf_debug_ospf6_brouter &= ~OSPF6_DEBUG_BROUTER_SUMMARY)

#define IS_OSPF6_DEBUG_BROUTER                                                 \
	(conf_debug_ospf6_brouter & OSPF6_DEBUG_BROUTER_SUMMARY)

#define OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ON(router_id)                      \
	do {                                                                   \
		conf_debug_ospf6_brouter_specific_router_id = (router_id);     \
		conf_debug_ospf6_brouter |=                                    \
			OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER;                   \
	} while (0)

#define OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_OFF()                              \
	do {                                                                   \
		conf_debug_ospf6_brouter_specific_router_id = 0;               \
		conf_debug_ospf6_brouter &=                                    \
			~OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER;                  \
	} while (0)

#define IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER                                 \
	(conf_debug_ospf6_brouter & OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER)

#define IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID(router_id)                   \
	(IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER                                \
	 && conf_debug_ospf6_brouter_specific_router_id == (router_id))

#define OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ON(area_id)                          \
	do {                                                                   \
		conf_debug_ospf6_brouter_specific_area_id = (area_id);         \
		conf_debug_ospf6_brouter |= OSPF6_DEBUG_BROUTER_SPECIFIC_AREA; \
	} while (0)

#define OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_OFF()                                \
	do {                                                                   \
		conf_debug_ospf6_brouter_specific_area_id = 0;                 \
		conf_debug_ospf6_brouter &=                                    \
			~OSPF6_DEBUG_BROUTER_SPECIFIC_AREA;                    \
	} while (0)

#define IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA                                   \
	(conf_debug_ospf6_brouter & OSPF6_DEBUG_BROUTER_SPECIFIC_AREA)

#define IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID(area_id)                       \
	(IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA                                  \
	 && conf_debug_ospf6_brouter_specific_area_id == (area_id))

enum stub_router_mode {
	OSPF6_NOT_STUB_ROUTER,
	OSPF6_IS_STUB_ROUTER,
	OSPF6_IS_STUB_ROUTER_V6,
};

#define ROUTER_LSDESC_IS_TYPE(t, x)                                            \
	((((struct ospf6_router_lsdesc *)(x))->type                            \
	  == OSPF6_ROUTER_LSDESC_##t)                                          \
		 ? 1                                                           \
		 : 0)
#define ROUTER_LSDESC_GET_METRIC(x)                                            \
	(ntohs(((struct ospf6_router_lsdesc *)(x))->metric))

#define ROUTER_LSDESC_GET_IFID(x)                                              \
	(ntohl(((struct ospf6_router_lsdesc *)(x))->interface_id))

#define ROUTER_LSDESC_GET_NBR_IFID(x)                                          \
	(ntohl(((struct ospf6_router_lsdesc *)(x))->neighbor_interface_id))

#define ROUTER_LSDESC_GET_NBR_ROUTERID(x)                                      \
	(((struct ospf6_router_lsdesc *)(x))->neighbor_router_id)


#define OSPF6_ROUTER_LSA_SCHEDULE(oa)                                          \
	do {                                                                   \
		if (CHECK_FLAG((oa)->flag, OSPF6_AREA_ENABLE))                 \
			event_add_event(master, ospf6_router_lsa_originate,    \
					oa, 0, &(oa)->thread_router_lsa);      \
	} while (0)

#define OSPF6_NETWORK_LSA_SCHEDULE(oi)                                         \
	do {                                                                   \
		if (!CHECK_FLAG((oi)->flag, OSPF6_INTERFACE_DISABLE))          \
			event_add_event(master, ospf6_network_lsa_originate,   \
					oi, 0, &(oi)->thread_network_lsa);     \
	} while (0)

#define OSPF6_LINK_LSA_SCHEDULE(oi)                                            \
	do {                                                                   \
		if (!CHECK_FLAG((oi)->flag, OSPF6_INTERFACE_DISABLE))          \
			event_add_event(master, ospf6_link_lsa_originate, oi,  \
					0, &(oi)->thread_link_lsa);            \
	} while (0)

#define OSPF6_INTRA_PREFIX_LSA_SCHEDULE_STUB(oa)                               \
	do {                                                                   \
		if (CHECK_FLAG((oa)->flag, OSPF6_AREA_ENABLE))                 \
			event_add_event(                                       \
				master, ospf6_intra_prefix_lsa_originate_stub, \
				oa, 0, &(oa)->thread_intra_prefix_lsa);        \
	} while (0)

#define OSPF6_INTRA_PREFIX_LSA_SCHEDULE_TRANSIT(oi)                            \
	do {                                                                   \
		if (!CHECK_FLAG((oi)->flag, OSPF6_INTERFACE_DISABLE))          \
			event_add_event(                                       \
				master,                                        \
				ospf6_intra_prefix_lsa_originate_transit, oi,  \
				0, &(oi)->thread_intra_prefix_lsa);            \
	} while (0)

#define OSPF6_AS_EXTERN_LSA_SCHEDULE(oi)                                       \
	do {                                                                   \
		if (!CHECK_FLAG((oi)->flag, OSPF6_INTERFACE_DISABLE))          \
			event_add_event(master, ospf6_orig_as_external_lsa,    \
					oi, 0, &(oi)->thread_as_extern_lsa);   \
	} while (0)

#define OSPF6_ROUTER_LSA_EXECUTE(oa)                                           \
	do {                                                                   \
		if (CHECK_FLAG((oa)->flag, OSPF6_AREA_ENABLE))                 \
			event_execute(master, ospf6_router_lsa_originate, oa,  \
				      0, NULL);                                \
	} while (0)

#define OSPF6_NETWORK_LSA_EXECUTE(oi)                                          \
	do {                                                                   \
		EVENT_OFF((oi)->thread_network_lsa);                           \
		event_execute(master, ospf6_network_lsa_originate, oi, 0,      \
			      NULL);                                           \
	} while (0)

#define OSPF6_LINK_LSA_EXECUTE(oi)                                             \
	do {                                                                   \
		if (!CHECK_FLAG((oi)->flag, OSPF6_INTERFACE_DISABLE))          \
			event_execute(master, ospf6_link_lsa_originate, oi,    \
				      0, NULL);                                \
	} while (0)

#define OSPF6_INTRA_PREFIX_LSA_EXECUTE_TRANSIT(oi)                             \
	do {                                                                   \
		EVENT_OFF((oi)->thread_intra_prefix_lsa);                      \
		event_execute(master,                                          \
			      ospf6_intra_prefix_lsa_originate_transit, oi,    \
			      0, NULL);                                        \
	} while (0)

#define OSPF6_AS_EXTERN_LSA_EXECUTE(oi)                                        \
	do {                                                                   \
		EVENT_OFF((oi)->thread_as_extern_lsa);                         \
		event_execute(master, ospf6_orig_as_external_lsa, oi, 0, NULL);\
	} while (0)

/* Function Prototypes */
extern char *ospf6_router_lsdesc_lookup(uint8_t type, uint32_t interface_id,
					uint32_t neighbor_interface_id,
					uint32_t neighbor_router_id,
					struct ospf6_lsa *lsa);
extern char *ospf6_network_lsdesc_lookup(uint32_t router_id,
					 struct ospf6_lsa *lsa);

extern int ospf6_router_is_stub_router(struct ospf6_lsa *lsa);
extern void ospf6_router_lsa_originate(struct event *thread);
extern void ospf6_network_lsa_originate(struct event *thread);
extern void ospf6_link_lsa_originate(struct event *thread);
extern void ospf6_intra_prefix_lsa_originate_transit(struct event *thread);
extern void ospf6_intra_prefix_lsa_originate_stub(struct event *thread);
extern void ospf6_intra_prefix_lsa_add(struct ospf6_lsa *lsa);
extern void ospf6_intra_prefix_lsa_remove(struct ospf6_lsa *lsa);
extern void ospf6_orig_as_external_lsa(struct event *thread);
extern void ospf6_intra_route_calculation(struct ospf6_area *oa);
extern void ospf6_intra_brouter_calculation(struct ospf6_area *oa);
extern void ospf6_intra_prefix_route_ecmp_path(struct ospf6_area *oa,
					       struct ospf6_route *old,
					       struct ospf6_route *route);

extern void ospf6_intra_init(void);

extern int config_write_ospf6_debug_brouter(struct vty *vty);
extern void install_element_ospf6_debug_brouter(void);

#endif /* OSPF6_LSA_H */
