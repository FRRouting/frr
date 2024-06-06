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

/* Default config for SRv6 SID `usid-f3216` format */
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_NAME	      "usid-f3216"
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN    32
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_NODE_LEN     16
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN 16
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_ARGUMENT_LEN 0
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_LIB_START    0xE000
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_ELIB_START   0xFE00
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_ELIB_END     0xFEFF
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_WLIB_START   0xFFF0
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_WLIB_END     0xFFF7
#define ZEBRA_SRV6_SID_FORMAT_USID_F3216_EWLIB_START  0xFFF7

/* Default config for SRv6 SID `uncompressed` format */
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME		      "uncompressed-f4024"
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_BLOCK_LEN	      40
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE_LEN	      24
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNCTION_LEN	      16
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_ARGUMENT_LEN	      0
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START 0xFF00
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNC_UNRESERVED_MIN  0x40

/* SRv6 instance structure. */
struct zebra_srv6 {
	struct list *locators;

	/* Source address for SRv6 encapsulation */
	struct in6_addr encap_src_addr;

	/* SRv6 SID formats */
	struct list *sid_formats;
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

void zebra_srv6_sid_format_register(struct zebra_srv6_sid_format *format);
void zebra_srv6_sid_format_unregister(struct zebra_srv6_sid_format *format);
struct zebra_srv6_sid_format *zebra_srv6_sid_format_lookup(const char *name);

#endif /* _ZEBRA_SRV6_H */
