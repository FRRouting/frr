// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 */

#ifndef _ZEBRA_SRV6_H
#define _ZEBRA_SRV6_H

#include <zebra.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "qobj.h"
#include "prefix.h"
#include <pthread.h>
#include <plist.h>

/* SRv6 instance structure. */
struct zebra_srv6 {
	struct list *locators;

	/* Source address for SRv6 encapsulation */
	struct in6_addr encap_src_addr;
};

/* declare hooks for the basic API, so that it can be specialized or served
 * externally. Also declare a hook when those functions have been registered,
 * so that any external module wanting to replace those can react
 */

DECLARE_HOOK(srv6_manager_client_connect,
	    (struct zserv *client, vrf_id_t vrf_id),
	    (client, vrf_id));
DECLARE_HOOK(srv6_manager_client_disconnect,
	     (struct zserv *client), (client));
DECLARE_HOOK(srv6_manager_get_chunk,
	     (struct srv6_locator **loc,
	      struct zserv *client,
	      const char *locator_name,
	      vrf_id_t vrf_id),
	     (mc, client, keep, size, base, vrf_id));
DECLARE_HOOK(srv6_manager_release_chunk,
	     (struct zserv *client,
	      const char *locator_name,
	      vrf_id_t vrf_id),
	     (client, locator_name, vrf_id));


extern void zebra_srv6_locator_add(struct srv6_locator *locator);
extern void zebra_srv6_locator_delete(struct srv6_locator *locator);
extern struct srv6_locator *zebra_srv6_locator_lookup(const char *name);

void zebra_notify_srv6_locator_add(struct srv6_locator *locator);
void zebra_notify_srv6_locator_delete(struct srv6_locator *locator);

extern void zebra_srv6_init(void);
extern void zebra_srv6_terminate(void);
extern struct zebra_srv6 *zebra_srv6_get_default(void);
extern bool zebra_srv6_is_enable(void);

extern void srv6_manager_client_connect_call(struct zserv *client,
					     vrf_id_t vrf_id);
extern void srv6_manager_get_locator_chunk_call(struct srv6_locator **loc,
						struct zserv *client,
						const char *locator_name,
						vrf_id_t vrf_id);
extern void srv6_manager_release_locator_chunk_call(struct zserv *client,
						    const char *locator_name,
						    vrf_id_t vrf_id);
extern int srv6_manager_client_disconnect_cb(struct zserv *client);
extern int release_daemon_srv6_locator_chunks(struct zserv *client);

extern void zebra_srv6_encap_src_addr_set(struct in6_addr *src_addr);
extern void zebra_srv6_encap_src_addr_unset(void);

#endif /* _ZEBRA_SRV6_H */
