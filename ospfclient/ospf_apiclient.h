// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Client side of OSPF API.
 * Copyright (C) 2001, 2002, 2003 Ralph Keller
 */

#ifndef _OSPF_APICLIENT_H
#define _OSPF_APICLIENT_H

/* Structure for the OSPF API client */
struct ospf_apiclient {

	/* Sockets for sync requests and async notifications */
	int fd_sync;
	int fd_async;

	/* Pointer to callback functions */
	void (*ready_notify)(uint8_t lsa_type, uint8_t opaque_type,
			     struct in_addr addr);
	void (*new_if)(struct in_addr ifaddr, struct in_addr area_id);
	void (*del_if)(struct in_addr ifaddr);
	void (*ism_change)(struct in_addr ifaddr, struct in_addr area_id,
			   uint8_t status);
	void (*nsm_change)(struct in_addr ifaddr, struct in_addr nbraddr,
			   struct in_addr router_id, uint8_t status);
	void (*update_notify)(struct in_addr ifaddr, struct in_addr area_id,
			      uint8_t self_origin, struct lsa_header *lsa);
	void (*delete_notify)(struct in_addr ifaddr, struct in_addr area_id,
			      uint8_t self_origin, struct lsa_header *lsa);
};


/* ---------------------------------------------------------
 * API function prototypes.
 * --------------------------------------------------------- */

/* Open connection to OSPF daemon. Two ports will be allocated on
   client, sync channel at syncport and reverse channel at syncport+1 */
struct ospf_apiclient *ospf_apiclient_connect(char *host, int syncport);

/* Shutdown connection to OSPF daemon. */
int ospf_apiclient_close(struct ospf_apiclient *oclient);

/* Synchronous request to register opaque type. */
int ospf_apiclient_register_opaque_type(struct ospf_apiclient *oclient,
					uint8_t ltype, uint8_t otype);

/* Synchronous request to register event mask. */
int ospf_apiclient_register_events(struct ospf_apiclient *oclient,
				   uint32_t mask);

/* Register callback functions.*/
void ospf_apiclient_register_callback(
	struct ospf_apiclient *oclient,
	void (*ready_notify)(uint8_t lsa_type, uint8_t opaque_type,
			     struct in_addr addr),
	void (*new_if)(struct in_addr ifaddr, struct in_addr area_id),
	void (*del_if)(struct in_addr ifaddr),
	void (*ism_change)(struct in_addr ifaddr, struct in_addr area_id,
			   uint8_t status),
	void (*nsm_change)(struct in_addr ifaddr, struct in_addr nbraddr,
			   struct in_addr router_id, uint8_t status),
	void (*update_notify)(struct in_addr ifaddr, struct in_addr area_id,
			      uint8_t selforig, struct lsa_header *lsa),
	void (*delete_notify)(struct in_addr ifaddr, struct in_addr area_id,
			      uint8_t selforig, struct lsa_header *lsa));

/* Synchronous request to synchronize LSDB. */
int ospf_apiclient_sync_lsdb(struct ospf_apiclient *oclient);

/* Synchronous request to originate or update opaque LSA. */
int ospf_apiclient_lsa_originate(struct ospf_apiclient *oclient,
				 struct in_addr ifaddr, struct in_addr area_id,
				 uint8_t lsa_type, uint8_t opaque_type,
				 uint32_t opaque_id, void *opaquedata,
				 int opaquelen);


/* Synchronous request to delete opaque LSA. Parameter opaque_id is in
   host byte order */
int ospf_apiclient_lsa_delete(struct ospf_apiclient *oclient,
			      struct in_addr addr, uint8_t lsa_type,
			      uint8_t opaque_type, uint32_t opaque_id,
			      uint8_t flags);

/* Fetch async message and handle it  */
int ospf_apiclient_handle_async(struct ospf_apiclient *oclient);

#endif /* _OSPF_APICLIENT_H */
