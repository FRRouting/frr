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
#define SRV6_SID_FORMAT_USID_F3216_NAME		"usid-f3216"
#define SRV6_SID_FORMAT_USID_F3216_BLOCK_LEN	32
#define SRV6_SID_FORMAT_USID_F3216_NODE_LEN	16
#define SRV6_SID_FORMAT_USID_F3216_FUNCTION_LEN 16
#define SRV6_SID_FORMAT_USID_F3216_ARGUMENT_LEN 0
#define SRV6_SID_FORMAT_USID_F3216_LIB_START	0xE000
#define SRV6_SID_FORMAT_USID_F3216_ELIB_START	0xFE00
#define SRV6_SID_FORMAT_USID_F3216_ELIB_END	0xFEFF
#define SRV6_SID_FORMAT_USID_F3216_WLIB_START	0xFFF0
#define SRV6_SID_FORMAT_USID_F3216_WLIB_END	0xFFF7
#define SRV6_SID_FORMAT_USID_F3216_EWLIB_START	0xFFF7

/* Default config for SRv6 SID `uncompressed` format */
#define SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NAME			"uncompressed-f4024"
#define SRV6_SID_FORMAT_UNCOMPRESSED_F4024_BLOCK_LEN		40
#define SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE_LEN		24
#define SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNCTION_LEN		16
#define SRV6_SID_FORMAT_UNCOMPRESSED_F4024_ARGUMENT_LEN		0
#define SRV6_SID_FORMAT_UNCOMPRESSED_F4024_EXPLICIT_RANGE_START 0xFF00
#define SRV6_SID_FORMAT_UNCOMPRESSED_F4024_FUNC_UNRESERVED_MIN	0x40

/* uSID Wide LIB */
struct wide_lib {
	uint32_t func;
	uint32_t num_func_allocated;
	uint32_t first_available_func;
	struct list *func_allocated;
	struct list *func_released;
};

/*
 * SRv6 SID block.
 *
 * A SID block is an IPv6 prefix from which SRv6 SIDs are allocated.
 * Example:
 *   SID block = fc00:0::/32
 *   SID 1 = fc00:0:1:e000::
 *   SID 2 = fc00:0:1:fe00::
 *   ...
 */
struct zebra_srv6_sid_block {
	/*  Prefix of this block, e.g. fc00:0::/32 */
	struct prefix_ipv6 prefix;

	/* Reference counter */
	unsigned long refcnt;

	/*
	 * Pointer to the SID format that defines the structure of the SIDs
	 * allocated from this block
	 */
	struct srv6_sid_format *sid_format;

	/*
	 * Run-time information/state of this SID block.
	 *
	 * This includes stuff like how many SID functions have been allocated
	 * from this block, which functions are still available to be allocated
	 * and so on...
	 */
	union {
		/* Information/state for compressed uSID format */
		struct {
			/* uSID Local ID Block (LIB) */
			struct {
				uint32_t num_func_allocated;
				uint32_t first_available_func;
				struct list *func_allocated;
				struct list *func_released;
			} lib;

			/* uSID Wide LIB */
			struct wide_lib *wide_lib;
		} usid;

		/* Information/state for uncompressed SID format */
		struct {
			uint32_t num_func_allocated;
			uint32_t first_available_func;
			struct list *func_allocated;
			struct list *func_released;
		} uncompressed;
	} u;
};

/**
 * The function part of an SRv6 SID can be allocated in one
 * of the following ways:
 *  - dynamic: allocate any available function
 *  - explicit: allocate a specific function
 */
enum srv6_sid_alloc_mode {
	SRV6_SID_ALLOC_MODE_UNSPEC = 0,
	/* Dynamic SID allocation */
	SRV6_SID_ALLOC_MODE_DYNAMIC = 1,
	/* Explicit SID allocation */
	SRV6_SID_ALLOC_MODE_EXPLICIT = 2,
	SRV6_SID_ALLOC_MODE_MAX = 3,
};

/**
 * Convert SID allocation mode to string.
 *
 * @param alloc_mode SID allocation mode
 * @return String representing the allocation mode
 */
static inline const char *
srv6_sid_alloc_mode2str(enum srv6_sid_alloc_mode alloc_mode)
{
	switch (alloc_mode) {
	case SRV6_SID_ALLOC_MODE_EXPLICIT:
		return "explicit";
	case SRV6_SID_ALLOC_MODE_DYNAMIC:
		return "dynamic";
	case SRV6_SID_ALLOC_MODE_UNSPEC:
		return "unspec";
	case SRV6_SID_ALLOC_MODE_MAX:
	default:
		return "unknown";
	}
}

/* SRv6 SID instance. */
struct zebra_srv6_sid {
	/*
	 * SID context associated with the SID.
	 * Defines behavior and attributes of the SID.
	 */
	struct zebra_srv6_sid_ctx *ctx;

	/* SID value (e.g. fc00:0:1:e000::) */
	struct in6_addr value;

	/* Pointer to the SRv6 locator from which the SID has been allocated */
	struct srv6_locator *locator;

	/* Pointer to the SRv6 block from which the SID has been allocated */
	struct zebra_srv6_sid_block *block;

	/*
	 * Function part of the SID
	 * Example:
	 *   SID = fc00:0:1:e000:: => func = e000
	 */
	uint32_t func;

	/* SID wide function. */
	uint32_t wide_func;

	/* SID allocation mode: dynamic or explicit */
	enum srv6_sid_alloc_mode alloc_mode;

	/* List of clients that are using the SID */
	struct list *client_list;
};

/*
 * Zebra SRv6 SID context.
 * A context defines a behavior and (optionally) some behavior-specific
 * attributes. Client daemons (bgp, isis, ...) ask SRv6 Manager to allocate
 * a SID for a particular context. SRv6 Manager is responsible for allocating
 * a SID from a given SID block and associating with the context.
 *
 * Example:
 *    bgp asks to associate a SID to the context {behavior=End.DT46 vrf=Vrf10}.
 *    SRv6 Manager allocate SID fc00:0:1:e000:: for that context.
 */
struct zebra_srv6_sid_ctx {
	/* SRv6 SID context information. */
	struct srv6_sid_ctx ctx;

	/* SID associated with the context. */
	struct zebra_srv6_sid *sid;
};

/* SRv6 instance structure. */
struct zebra_srv6 {
	struct list *locators;

	/* Source address for SRv6 encapsulation */
	struct in6_addr encap_src_addr;

	/* SRv6 SID formats */
	struct list *sid_formats;

	/* SRv6 SIDs */
	struct list *sids;

	/* SRv6 SID blocks */
	struct list *sid_blocks;
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

DECLARE_HOOK(srv6_manager_get_sid,
	     (struct zebra_srv6_sid **sid, struct zserv *client,
	      struct srv6_sid_ctx *ctx, struct in6_addr *sid_value,
	      const char *locator_name),
	     (sid, client, ctx, sid_value, locator_name));
DECLARE_HOOK(srv6_manager_release_sid,
	     (struct zserv *client, struct srv6_sid_ctx *ctx), (client, ctx));
DECLARE_HOOK(srv6_manager_get_locator,
	     (struct srv6_locator **locator, struct zserv *client,
	      const char *locator_name),
	     (locator, client, locator_name));

extern void zebra_srv6_locator_add(struct srv6_locator *locator);
extern void zebra_srv6_locator_delete(struct srv6_locator *locator);
extern void zebra_srv6_prefix_delete(struct srv6_locator *locator);
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

void srv6_sid_format_register(struct srv6_sid_format *format);
void srv6_sid_format_unregister(struct srv6_sid_format *format);
struct srv6_sid_format *srv6_sid_format_lookup(const char *name);
void zebra_srv6_locator_format_set(struct srv6_locator *locator,
				   struct srv6_sid_format *format);
void zebra_srv6_sid_format_changed_cb(struct srv6_sid_format *format);

uint32_t *zebra_srv6_sid_func_alloc(uint32_t func);
void zebra_srv6_sid_func_free(uint32_t *func);
void delete_zebra_srv6_sid_func(void *val);

extern struct zebra_srv6_sid_block *
zebra_srv6_sid_block_alloc(struct srv6_sid_format *format,
			   struct prefix_ipv6 *prefix);
extern void zebra_srv6_sid_block_free(struct zebra_srv6_sid_block *block);
extern void delete_zebra_srv6_sid_block(void *val);
extern struct zebra_srv6_sid_block *
zebra_srv6_sid_block_lookup(struct prefix_ipv6 *prefix);

extern struct zebra_srv6_sid *
zebra_srv6_sid_alloc(struct zebra_srv6_sid_ctx *ctx, struct in6_addr *sid_value,
		     struct srv6_locator *locator,
		     struct zebra_srv6_sid_block *sid_block, uint32_t sid_func,
		     enum srv6_sid_alloc_mode alloc_mode);
extern void zebra_srv6_sid_free(struct zebra_srv6_sid *sid);
extern void delete_zebra_srv6_sid(void *val);

extern void srv6_manager_get_sid_call(struct zebra_srv6_sid **sid,
				      struct zserv *client,
				      struct srv6_sid_ctx *ctx,
				      struct in6_addr *sid_value,
				      const char *locator_name);
extern void srv6_manager_release_sid_call(struct zserv *client,
					  struct srv6_sid_ctx *ctx);

extern void srv6_manager_get_locator_call(struct srv6_locator **locator,
					  struct zserv *client,
					  const char *locator_name);

extern int get_srv6_sid(struct zebra_srv6_sid **sid, struct srv6_sid_ctx *ctx,
			struct in6_addr *sid_value, const char *locator_name);
extern int release_srv6_sid(struct zserv *client,
			    struct zebra_srv6_sid_ctx *zctx);
extern int release_daemon_srv6_sids(struct zserv *client);
extern int srv6_manager_get_sid_response(struct zebra_srv6_sid *sid,
					 struct zserv *client);

extern struct zebra_srv6_sid_ctx *zebra_srv6_sid_ctx_alloc(void);
extern void zebra_srv6_sid_ctx_free(struct zebra_srv6_sid_ctx *ctx);
extern void delete_zebra_srv6_sid_ctx(void *val);

#endif /* _ZEBRA_SRV6_H */
