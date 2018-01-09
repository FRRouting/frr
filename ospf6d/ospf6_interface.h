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

#ifndef OSPF6_INTERFACE_H
#define OSPF6_INTERFACE_H

#include "qobj.h"
#include "hook.h"
#include "if.h"

/* Debug option */
extern unsigned char conf_debug_ospf6_interface;
#define OSPF6_DEBUG_INTERFACE_ON() (conf_debug_ospf6_interface = 1)
#define OSPF6_DEBUG_INTERFACE_OFF() (conf_debug_ospf6_interface = 0)
#define IS_OSPF6_DEBUG_INTERFACE (conf_debug_ospf6_interface)

/* Interface structure */
struct ospf6_interface {
	/* IF info from zebra */
	struct interface *interface;

	/* back pointer */
	struct ospf6_area *area;

	/* list of ospf6 neighbor */
	struct list *neighbor_list;

	/* linklocal address of this I/F */
	struct in6_addr *linklocal_addr;

	/* Interface ID; use interface->ifindex */

	/* ospf6 instance id */
	u_char instance_id;

	/* I/F transmission delay */
	u_int32_t transdelay;

	/* Network Type */
	u_char type;

	/* Router Priority */
	u_char priority;

	/* Time Interval */
	u_int16_t hello_interval;
	u_int16_t dead_interval;
	u_int32_t rxmt_interval;

	u_int32_t state_change;

	/* Cost */
	u_int32_t cost;

	/* I/F MTU */
	u_int32_t ifmtu;

	/* Configured MTU */
	u_int32_t c_ifmtu;

	/* Interface State */
	u_char state;

	/* Interface socket setting trial counter, resets on success */
	u_char sso_try_cnt;

	/* OSPF6 Interface flag */
	char flag;

	/* MTU mismatch check */
	u_char mtu_ignore;

	/* Decision of DR Election */
	u_int32_t drouter;
	u_int32_t bdrouter;
	u_int32_t prev_drouter;
	u_int32_t prev_bdrouter;

	/* Linklocal LSA Database: includes Link-LSA */
	struct ospf6_lsdb *lsdb;
	struct ospf6_lsdb *lsdb_self;

	struct ospf6_lsdb *lsupdate_list;
	struct ospf6_lsdb *lsack_list;

	/* Ongoing Tasks */
	struct thread *thread_send_hello;
	struct thread *thread_send_lsupdate;
	struct thread *thread_send_lsack;

	struct thread *thread_network_lsa;
	struct thread *thread_link_lsa;
	struct thread *thread_intra_prefix_lsa;

	struct ospf6_route_table *route_connected;

	/* prefix-list name to filter connected prefix */
	char *plist_name;

	/* BFD information */
	void *bfd_info;

	/* Statistics Fields */
	u_int32_t hello_in;
	u_int32_t hello_out;
	u_int32_t db_desc_in;
	u_int32_t db_desc_out;
	u_int32_t ls_req_in;
	u_int32_t ls_req_out;
	u_int32_t ls_upd_in;
	u_int32_t ls_upd_out;
	u_int32_t ls_ack_in;
	u_int32_t ls_ack_out;
	u_int32_t discarded;

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(ospf6_interface)

/* interface state */
#define OSPF6_INTERFACE_NONE             0
#define OSPF6_INTERFACE_DOWN             1
#define OSPF6_INTERFACE_LOOPBACK         2
#define OSPF6_INTERFACE_WAITING          3
#define OSPF6_INTERFACE_POINTTOPOINT     4
#define OSPF6_INTERFACE_DROTHER          5
#define OSPF6_INTERFACE_BDR              6
#define OSPF6_INTERFACE_DR               7
#define OSPF6_INTERFACE_MAX              8

extern const char *ospf6_interface_state_str[];

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
#define OSPF6_REFERENCE_BANDWIDTH      100000  /* Mbps */
#define OSPF6_INTERFACE_SSO_RETRY_INT  1
#define OSPF6_INTERFACE_SSO_RETRY_MAX  5

/* Function Prototypes */

extern struct ospf6_interface *ospf6_interface_lookup_by_ifindex(ifindex_t);
extern struct ospf6_interface *ospf6_interface_create(struct interface *);
extern void ospf6_interface_delete(struct ospf6_interface *);

extern void ospf6_interface_enable(struct ospf6_interface *);
extern void ospf6_interface_disable(struct ospf6_interface *);

extern void ospf6_interface_if_add(struct interface *);
extern void ospf6_interface_if_del(struct interface *);
extern void ospf6_interface_state_update(struct interface *);
extern void ospf6_interface_connected_route_update(struct interface *);

/* interface event */
extern int interface_up(struct thread *);
extern int interface_down(struct thread *);
extern int wait_timer(struct thread *);
extern int backup_seen(struct thread *);
extern int neighbor_change(struct thread *);

extern void ospf6_interface_init(void);

extern void install_element_ospf6_clear_interface(void);

extern int config_write_ospf6_debug_interface(struct vty *vty);
extern void install_element_ospf6_debug_interface(void);

DECLARE_HOOK(ospf6_interface_change,
	     (struct ospf6_interface * oi, int state, int old_state),
	     (oi, state, old_state))

#endif /* OSPF6_INTERFACE_H */
