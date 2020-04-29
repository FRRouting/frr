// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_INTERFACE_H
#define OSPF6_INTERFACE_H

#include "qobj.h"
#include "hook.h"
#include "if.h"
#include "ospf6d.h"

DECLARE_MTYPE(OSPF6_AUTH_MANUAL_KEY);

/* Debug option */
extern unsigned char conf_debug_ospf6_interface;
#define OSPF6_DEBUG_INTERFACE_ON() (conf_debug_ospf6_interface = 1)
#define OSPF6_DEBUG_INTERFACE_OFF() (conf_debug_ospf6_interface = 0)
#define IS_OSPF6_DEBUG_INTERFACE (conf_debug_ospf6_interface)

struct ospf6_auth_data {
	/* config data */
	uint8_t hash_algo; /* hash algorithm type */
	uint16_t key_id;   /* key-id used as SA in auth packet */
	char *auth_key;    /* Auth key */
	char *keychain;    /* keychain name */

	/* operational data */
	uint8_t flags; /* Flags related to auth config */

	/* Counters and Statistics */
	uint32_t tx_drop; /* Pkt drop due to auth fail while sending */
	uint32_t rx_drop; /* Pkt drop due to auth fail while reading */
};

PREDECL_RBTREE_UNIQ(ospf6_if_p2xp_neighcfgs);

struct ospf6_if_p2xp_neighcfg {
	struct ospf6_if_p2xp_neighcfgs_item item;

	struct ospf6_interface *ospf6_if;
	struct in6_addr addr;

	bool cfg_cost : 1;

	uint32_t cost;
	uint16_t poll_interval;

	/* NULL if down */
	struct ospf6_neighbor *active;

	struct event *t_unicast_hello;
};

/* Interface structure */
struct ospf6_interface {
	/* IF info from zebra */
	struct interface *interface;

	/* back pointer */
	struct ospf6_area *area;

	uint32_t area_id;
	int area_id_format;

	/* list of ospf6 neighbor */
	struct list *neighbor_list;

	/* linklocal address of this I/F */
	struct in6_addr *linklocal_addr;

	/* Interface ID; use interface->ifindex */

	/* ospf6 instance id */
	uint8_t instance_id;

	/* I/F transmission delay */
	uint32_t transdelay;

	/* Packet send buffer. */
	struct ospf6_fifo *obuf; /* Output queue */

	/* Network Type */
	uint8_t type;
	bool type_cfg;

	/* P2P/P2MP behavior: */

	/* disable hellos on standard multicast? */
	bool p2xp_no_multicast_hello;
	/* only allow explicitly configured neighbors? */
	bool p2xp_only_cfg_neigh;
	/* override mode default for advertising connected prefixes.
	 * both false by default (= do include for PtP, exclude for PtMP)
	 */
	bool p2xp_connected_pfx_include;
	bool p2xp_connected_pfx_exclude;

	struct ospf6_if_p2xp_neighcfgs_head p2xp_neighs;

	/* Router Priority */
	uint8_t priority;

	/* Time Interval */
	uint16_t hello_interval;
	uint16_t dead_interval;
	uint32_t rxmt_interval;

	/* Graceful-Restart data. */
	struct {
		struct {
			uint16_t interval;
			uint16_t elapsed_seconds;
			struct event *t_grace_send;
		} hello_delay;
	} gr;

	uint32_t state_change;

	/* Cost */
	uint32_t cost;

	/* I/F MTU */
	uint32_t ifmtu;

	/* Configured MTU */
	uint32_t c_ifmtu;

	/* Interface State */
	uint8_t state;

	/* Interface socket setting trial counter, resets on success */
	uint8_t sso_try_cnt;
	struct event *thread_sso;

	/* OSPF6 Interface flag */
	char flag;

	/* MTU mismatch check */
	uint8_t mtu_ignore;

	/* Authentication trailer related config */
	struct ospf6_auth_data at_data;

	/* Decision of DR Election */
	in_addr_t drouter;
	in_addr_t bdrouter;
	in_addr_t prev_drouter;
	in_addr_t prev_bdrouter;

	/* Linklocal LSA Database: includes Link-LSA */
	struct ospf6_lsdb *lsdb;
	struct ospf6_lsdb *lsdb_self;

	struct ospf6_lsdb *lsupdate_list;
	struct ospf6_lsdb *lsack_list;

	/* Ongoing Tasks */
	struct event *thread_send_hello;
	struct event *thread_send_lsupdate;
	struct event *thread_send_lsack;

	struct event *thread_network_lsa;
	struct event *thread_link_lsa;
	struct event *thread_intra_prefix_lsa;
	struct event *thread_as_extern_lsa;
	struct event *thread_wait_timer;

	struct ospf6_route_table *route_connected;

	/* last hello sent */
	struct timeval last_hello;

	/* prefix-list name to filter connected prefix */
	char *plist_name;

	/* BFD information */
	struct {
		bool enabled;
		uint8_t detection_multiplier;
		uint32_t min_rx;
		uint32_t min_tx;
		char *profile;
	} bfd_config;

	int on_write_q;

	/* Statistics Fields */
	uint32_t hello_in;
	uint32_t hello_out;
	uint32_t db_desc_in;
	uint32_t db_desc_out;
	uint32_t ls_req_in;
	uint32_t ls_req_out;
	uint32_t ls_upd_in;
	uint32_t ls_upd_out;
	uint32_t ls_ack_in;
	uint32_t ls_ack_out;
	uint32_t discarded;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(ospf6_interface);

/* interface state */
#define OSPF6_INTERFACE_NONE               0
#define OSPF6_INTERFACE_DOWN               1
#define OSPF6_INTERFACE_LOOPBACK           2
#define OSPF6_INTERFACE_WAITING            3
#define OSPF6_INTERFACE_POINTTOPOINT       4
#define OSPF6_INTERFACE_POINTTOMULTIPOINT  5
#define OSPF6_INTERFACE_DROTHER            6
#define OSPF6_INTERFACE_BDR                7
#define OSPF6_INTERFACE_DR                 8
#define OSPF6_INTERFACE_MAX                9

extern const char *const ospf6_interface_state_str[];

/* flags */
#define OSPF6_INTERFACE_DISABLE      0x01
#define OSPF6_INTERFACE_PASSIVE      0x02
#define OSPF6_INTERFACE_NOAUTOCOST   0x04

/* default values */
#define OSPF6_INTERFACE_HELLO_INTERVAL 10
#define OSPF6_INTERFACE_DEAD_INTERVAL  40
#define OSPF6_INTERFACE_RXMT_INTERVAL  5
#define OSPF6_INTERFACE_COST           1
#define OSPF6_INTERFACE_PRIORITY       1
#define OSPF6_INTERFACE_TRANSDELAY     1
#define OSPF6_INTERFACE_INSTANCE_ID    0
#define OSPF6_INTERFACE_BANDWIDTH      10000   /* Mbps */
#define OSPF6_REFERENCE_BANDWIDTH      100000  /* Kbps */
#define OSPF6_INTERFACE_SSO_RETRY_INT  1
#define OSPF6_INTERFACE_SSO_RETRY_MAX  5

/* Function Prototypes */

extern void ospf6_interface_start(struct ospf6_interface *oi);
extern void ospf6_interface_stop(struct ospf6_interface *oi);

extern struct ospf6_interface *
ospf6_interface_lookup_by_ifindex(ifindex_t, vrf_id_t vrf_id);
extern struct ospf6_interface *ospf6_interface_create(struct interface *ifp);
extern void ospf6_interface_delete(struct ospf6_interface *oi);

extern void ospf6_interface_enable(struct ospf6_interface *oi);
extern void ospf6_interface_disable(struct ospf6_interface *oi);

extern void ospf6_interface_state_update(struct interface *ifp);
extern void ospf6_interface_connected_route_update(struct interface *ifp);
extern struct in6_addr *
ospf6_interface_get_global_address(struct interface *ifp);

/* interface event */
extern void interface_up(struct event *thread);
extern void interface_down(struct event *thread);
extern void wait_timer(struct event *thread);
extern void backup_seen(struct event *thread);
extern void neighbor_change(struct event *thread);

extern void ospf6_interface_init(void);
extern void ospf6_interface_clear(struct interface *ifp);

extern void install_element_ospf6_clear_interface(void);

extern int config_write_ospf6_debug_interface(struct vty *vty);
extern void install_element_ospf6_debug_interface(void);
extern int ospf6_interface_neighbor_count(struct ospf6_interface *oi);
extern uint8_t dr_election(struct ospf6_interface *oi);

extern void ospf6_interface_auth_trailer_cmd_init(void);
extern void ospf6_auth_write_config(struct vty *vty,
				    struct ospf6_auth_data *at_data);
DECLARE_HOOK(ospf6_interface_change,
	     (struct ospf6_interface * oi, int state, int old_state),
	     (oi, state, old_state));

#endif /* OSPF6_INTERFACE_H */
