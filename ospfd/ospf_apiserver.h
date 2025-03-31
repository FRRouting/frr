// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Server side of OSPF API.
 * Copyright (C) 2001, 2002 Ralph Keller
 */

#ifndef _OSPF_APISERVER_H
#define _OSPF_APISERVER_H

#include <zebra.h>
#include "ospf_api.h"
#include "ospf_lsdb.h"

/* List of opaque types that application registered */
struct registered_opaque_type {
	uint8_t lsa_type;
	uint8_t opaque_type;
};


/* Server instance for each accepted client connection. */
struct ospf_apiserver {
	/* Socket connections for synchronous commands and asynchronous
	   notifications */
	int fd_sync; /* synchronous requests */
	struct sockaddr_in peer_sync;

	int fd_async; /* asynchronous notifications */
	struct sockaddr_in peer_async;

	/* List of all opaque types that application registers to use. Using
	   a single connection with the OSPF daemon, multiple
	   <lsa,opaque_type> pairs can be registered. However, each
	   combination can only be registered once by all applications. */
	struct list *opaque_types; /* of type registered_opaque_type */

	/* Temporary storage for LSA instances to be refreshed. */
	struct ospf_lsdb reserve;

	/* Sync reachable routers */
	bool reachable_sync;

	/* filter for LSA update/delete notifies */
	struct lsa_filter_type *filter;

	/* Fifo buffers for outgoing messages */
	struct msg_fifo *out_sync_fifo;
	struct msg_fifo *out_async_fifo;

	/* Read and write threads */
	struct event *t_sync_read;
#ifdef USE_ASYNC_READ
	struct event *t_async_read;
#endif /* USE_ASYNC_READ */
	struct event *t_sync_write;
	struct event *t_async_write;
};

enum ospf_apiserver_event {
	OSPF_APISERVER_ACCEPT,
	OSPF_APISERVER_SYNC_READ,
#ifdef USE_ASYNC_READ
	OSPF_APISERVER_ASYNC_READ,
#endif /* USE_ASYNC_READ */
	OSPF_APISERVER_SYNC_WRITE,
	OSPF_APISERVER_ASYNC_WRITE
};

/* -----------------------------------------------------------
 * External definitions for OSPF API ospfd parameters.
 * -----------------------------------------------------------
 */

extern int ospf_apiserver_enable;
extern struct in_addr ospf_apiserver_addr;

/* -----------------------------------------------------------
 * Following are functions to manage client connections.
 * -----------------------------------------------------------
 */

extern unsigned short ospf_apiserver_getport(void);
extern int ospf_apiserver_init(void);
extern void ospf_apiserver_term(void);
extern struct ospf_apiserver *ospf_apiserver_new(int fd_sync, int fd_async);
extern void ospf_apiserver_free(struct ospf_apiserver *apiserv);
extern void ospf_apiserver_event(enum ospf_apiserver_event event, int fd,
				 struct ospf_apiserver *apiserv);
extern int ospf_apiserver_serv_sock_family(unsigned short port, int family);
extern void ospf_apiserver_accept(struct event *thread);
extern void ospf_apiserver_read(struct event *thread);
extern void ospf_apiserver_sync_write(struct event *thread);
extern void ospf_apiserver_async_write(struct event *thread);
extern int ospf_apiserver_send_reply(struct ospf_apiserver *apiserv,
				     uint32_t seqnr, uint8_t rc);

/* -----------------------------------------------------------
 * Following are message handler functions
 * -----------------------------------------------------------
 */

extern int ospf_apiserver_lsa9_originator(void *arg);
extern int ospf_apiserver_lsa10_originator(void *arg);
extern int ospf_apiserver_lsa11_originator(void *arg);

extern void ospf_apiserver_clients_notify_all(struct msg *msg);

extern void
ospf_apiserver_clients_notify_ready_type9(struct ospf_interface *oi);
extern void ospf_apiserver_clients_notify_ready_type10(struct ospf_area *area);
extern void ospf_apiserver_clients_notify_ready_type11(struct ospf *top);

extern void ospf_apiserver_clients_notify_new_if(struct ospf_interface *oi);
extern void ospf_apiserver_clients_notify_del_if(struct ospf_interface *oi);
extern void ospf_apiserver_clients_notify_ism_change(struct ospf_interface *oi);
extern void ospf_apiserver_clients_notify_nsm_change(struct ospf_neighbor *nbr);
extern void
ospf_apiserver_clients_notify_router_id_change(struct in_addr router_id);

extern int ospf_apiserver_is_ready_type9(struct ospf_interface *oi);
extern int ospf_apiserver_is_ready_type10(struct ospf_area *area);
extern int ospf_apiserver_is_ready_type11(struct ospf *ospf);

extern void ospf_apiserver_notify_ready_type9(struct ospf_apiserver *apiserv);
extern void ospf_apiserver_notify_ready_type10(struct ospf_apiserver *apiserv);
extern void ospf_apiserver_notify_ready_type11(struct ospf_apiserver *apiserv);

extern int ospf_apiserver_handle_msg(struct ospf_apiserver *apiserv,
				     struct msg *msg);
extern int
ospf_apiserver_handle_register_opaque_type(struct ospf_apiserver *apiserv,
					   struct msg *msg);
extern int
ospf_apiserver_handle_unregister_opaque_type(struct ospf_apiserver *apiserv,
					     struct msg *msg);
extern int ospf_apiserver_handle_register_event(struct ospf_apiserver *apiserv,
						struct msg *msg);
extern int
ospf_apiserver_handle_originate_request(struct ospf_apiserver *apiserv,
					struct msg *msg);
extern int ospf_apiserver_handle_delete_request(struct ospf_apiserver *apiserv,
						struct msg *msg);
extern int ospf_apiserver_handle_sync_lsdb(struct ospf_apiserver *apiserv,
					   struct msg *msg);
extern int ospf_apiserver_handle_sync_reachable(struct ospf_apiserver *apiserv,
						struct msg *msg);
extern int ospf_apiserver_handle_sync_ism(struct ospf_apiserver *apiserv,
					  struct msg *msg);
extern int ospf_apiserver_handle_sync_nsm(struct ospf_apiserver *apiserv,
					  struct msg *msg);
extern int ospf_apiserver_handle_sync_router_id(struct ospf_apiserver *apiserv,
						struct msg *msg);

extern void ospf_apiserver_notify_reachable(struct route_table *ort,
					    struct route_table *nrt);

/* -----------------------------------------------------------
 * Following are functions for LSA origination/deletion
 * -----------------------------------------------------------
 */

extern int ospf_apiserver_register_opaque_type(struct ospf_apiserver *apiserver,
					       uint8_t lsa_type,
					       uint8_t opaque_type);
extern int
ospf_apiserver_unregister_opaque_type(struct ospf_apiserver *apiserver,
				      uint8_t lsa_type, uint8_t opaque_type);
extern struct ospf_lsa *
ospf_apiserver_opaque_lsa_new(struct ospf_area *area, struct ospf_interface *oi,
			      struct lsa_header *protolsa);
extern struct ospf_interface *
ospf_apiserver_if_lookup_by_addr(struct in_addr address);
extern struct ospf_interface *
ospf_apiserver_if_lookup_by_ifp(struct interface *ifp);
extern int ospf_apiserver_originate1(struct ospf_lsa *lsa,
				     struct ospf_lsa *old);
extern void ospf_apiserver_flood_opaque_lsa(struct ospf_lsa *lsa);


/* -----------------------------------------------------------
 * Following are callback functions to handle opaque types
 * -----------------------------------------------------------
 */

extern int ospf_apiserver_new_if(struct interface *ifp);
extern int ospf_apiserver_del_if(struct interface *ifp);
extern void ospf_apiserver_ism_change(struct ospf_interface *oi,
				      int old_status);
extern void ospf_apiserver_nsm_change(struct ospf_neighbor *nbr,
				      int old_status);
extern void ospf_apiserver_config_write_router(struct vty *vty);
extern void ospf_apiserver_config_write_if(struct vty *vty,
					   struct interface *ifp);
extern void ospf_apiserver_show_info(struct vty *vty, struct json_object *json,
				     struct ospf_lsa *lsa);
extern int ospf_ospf_apiserver_lsa_originator(void *arg);
extern struct ospf_lsa *ospf_apiserver_lsa_refresher(struct ospf_lsa *lsa);
extern void ospf_apiserver_flush_opaque_lsa(struct ospf_apiserver *apiserv,
					    uint8_t lsa_type,
					    uint8_t opaque_type);

/* -----------------------------------------------------------
 * Following are hooks when LSAs are updated or deleted
 * -----------------------------------------------------------
 */


/* Hooks that are invoked from ospf opaque module */

extern int ospf_apiserver_lsa_update(struct ospf_lsa *lsa);
extern int ospf_apiserver_lsa_delete(struct ospf_lsa *lsa);

#endif /* _OSPF_APISERVER_H */
