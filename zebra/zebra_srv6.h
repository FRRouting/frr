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

#define SRV6_SID_FORMAT_NAME_SIZE 512

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
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_NAME			"uncompressed"
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_BLOCK_LEN		40
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_NODE_LEN		24
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNCTION_LEN		16
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_ARGUMENT_LEN		0
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_EXPLICIT_RANGE_START 0xFF00
#define ZEBRA_SRV6_SID_FORMAT_UNCOMPRESSED_FUNC_UNRESERVED_MIN	0x40

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
	struct zebra_srv6_sid_format *sid_format;

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

/* SID format type */
enum zebra_srv6_sid_format_type {
	ZEBRA_SRV6_SID_FORMAT_TYPE_UNSPEC = 0,
	/* SRv6 SID uncompressed format */
	ZEBRA_SRV6_SID_FORMAT_TYPE_UNCOMPRESSED = 1,
	/* SRv6 SID compressed uSID format */
	ZEBRA_SRV6_SID_FORMAT_TYPE_COMPRESSED_USID = 2,
};

/* SRv6 SID format */
struct zebra_srv6_sid_format {
	/* Name of the format */
	char name[SRV6_SID_FORMAT_NAME_SIZE];

	/* Format type: uncompressed vs compressed */
	enum zebra_srv6_sid_format_type type;

	/* Lengths of block/node/function/argument parts of the SIDs allocated using this format */
	uint8_t block_len;
	uint8_t node_len;
	uint8_t function_len;
	uint8_t argument_len;

	union {
		/* Configuration settings for compressed uSID format type */
		struct {
			/* Start of the Local ID Block (LIB) range */
			uint32_t lib_start;

			/* Start/End of the Explicit LIB range */
			uint32_t elib_start;
			uint32_t elib_end;

			/* Start/End of the Wide LIB range */
			uint32_t wlib_start;
			uint32_t wlib_end;

			/* Start/End of the Explicit Wide LIB range */
			uint32_t ewlib_start;
		} usid;

		/* Configuration settings for uncompressed format type */
		struct {
			/* Start of the Explicit range */
			uint32_t explicit_start;
		} uncompressed;
	} config;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(zebra_srv6_sid_format);

/* Zebra SRv6 locator. */
struct zebra_srv6_locator {
	/* SRv6 locator information. */
	struct srv6_locator locator;

	/*
	 * Pointer to the SID format that defines the structure of the SIDs
	 * allocated from this locator.
	 */
	struct zebra_srv6_sid_format *sid_format;

	/* Pointer to the parent SID block of the locator. */
	struct zebra_srv6_sid_block *sid_block;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(zebra_srv6_locator);

/* SRv6 instance structure. */
struct zebra_srv6 {
	struct list *locators;

	/* Source address for SRv6 encapsulation */
	struct in6_addr encap_src_addr;

	/* SRv6 SID formats */
	struct list *sid_formats;

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

extern struct zebra_srv6_locator *zebra_srv6_locator_alloc(const char *name);
extern void zebra_srv6_locator_free(struct zebra_srv6_locator *locator);

extern void zebra_srv6_locator_add(struct zebra_srv6_locator *locator);
extern void zebra_srv6_locator_delete(struct zebra_srv6_locator *locator);
extern struct zebra_srv6_locator *zebra_srv6_locator_lookup(const char *name);

void zebra_notify_srv6_locator_add(struct zebra_srv6_locator *locator);
void zebra_notify_srv6_locator_delete(struct zebra_srv6_locator *locator);

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

extern struct zebra_srv6_sid_format *
zebra_srv6_sid_format_alloc(const char *name);
extern void zebra_srv6_sid_format_free(struct zebra_srv6_sid_format *format);
extern void delete_zebra_srv6_sid_format(void *format);
void zebra_srv6_sid_format_add(struct zebra_srv6_sid_format *sid_format);
void zebra_srv6_sid_format_delete(struct zebra_srv6_sid_format *sid_format);
struct zebra_srv6_sid_format *zebra_srv6_sid_format_lookup(const char *name);
void zebra_srv6_sid_format_changed_cb(struct zebra_srv6_sid_format *format);

uint32_t *zebra_srv6_sid_func_alloc(void);
void zebra_srv6_sid_func_free(uint32_t *func);
void delete_zebra_srv6_sid_func(void *val);

extern struct zebra_srv6_sid_block *
zebra_srv6_sid_block_alloc(struct zebra_srv6_sid_format *format);
extern void zebra_srv6_sid_block_free(struct zebra_srv6_sid_block *block);
extern void delete_zebra_srv6_sid_block(void *val);
extern struct zebra_srv6_sid_block *
zebra_srv6_sid_block_lookup(struct prefix_ipv6 *prefix);

#endif /* _ZEBRA_SRV6_H */
