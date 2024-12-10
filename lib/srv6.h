// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 */

#ifndef _FRR_SRV6_H
#define _FRR_SRV6_H

#include <zebra.h>
#include "prefix.h"
#include "json.h"
#include "vrf.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#define SRV6_MAX_SIDS	  16
#define SRV6_MAX_SEGS	  8
#define SRV6_LOCNAME_SIZE 256
#define SRH_BASE_HEADER_LENGTH 8
#define SRH_SEGMENT_LENGTH     16

#define SRV6_SID_FORMAT_NAME_SIZE 512

#ifdef __cplusplus
extern "C" {
#endif

#define sid2str(sid, str, size) \
	inet_ntop(AF_INET6, sid, str, size)

/* SRv6 flavors manipulation macros */
#define CHECK_SRV6_FLV_OP(OPS,OP)      ((OPS) & (1 << OP))
#define SET_SRV6_FLV_OP(OPS,OP)        (OPS) |= (1 << OP)
#define UNSET_SRV6_FLV_OP(OPS,OP)      (OPS) &= ~(1 << OP)
#define RESET_SRV6_FLV_OP(OPS)         (OPS) = 0

/* SRv6 Flavors default values */
#define ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCBLOCK_LEN 32
#define ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCNODE_FN_LEN 16

enum seg6_mode_t {
	INLINE,
	ENCAP,
	L2ENCAP,
};

enum seg6local_action_t {
	ZEBRA_SEG6_LOCAL_ACTION_UNSPEC       = 0,
	ZEBRA_SEG6_LOCAL_ACTION_END          = 1,
	ZEBRA_SEG6_LOCAL_ACTION_END_X        = 2,
	ZEBRA_SEG6_LOCAL_ACTION_END_T        = 3,
	ZEBRA_SEG6_LOCAL_ACTION_END_DX2      = 4,
	ZEBRA_SEG6_LOCAL_ACTION_END_DX6      = 5,
	ZEBRA_SEG6_LOCAL_ACTION_END_DX4      = 6,
	ZEBRA_SEG6_LOCAL_ACTION_END_DT6      = 7,
	ZEBRA_SEG6_LOCAL_ACTION_END_DT4      = 8,
	ZEBRA_SEG6_LOCAL_ACTION_END_B6       = 9,
	ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP = 10,
	ZEBRA_SEG6_LOCAL_ACTION_END_BM       = 11,
	ZEBRA_SEG6_LOCAL_ACTION_END_S        = 12,
	ZEBRA_SEG6_LOCAL_ACTION_END_AS       = 13,
	ZEBRA_SEG6_LOCAL_ACTION_END_AM       = 14,
	ZEBRA_SEG6_LOCAL_ACTION_END_BPF      = 15,
	ZEBRA_SEG6_LOCAL_ACTION_END_DT46     = 16,
};

/* Flavor operations for SRv6 End* Behaviors */
enum seg6local_flavor_op {
	ZEBRA_SEG6_LOCAL_FLV_OP_UNSPEC       = 0,
	/* PSP Flavor as per RFC 8986 section #4.16.1 */
	ZEBRA_SEG6_LOCAL_FLV_OP_PSP          = 1,
	/* USP Flavor as per RFC 8986 section #4.16.2 */
	ZEBRA_SEG6_LOCAL_FLV_OP_USP          = 2,
	/* USD Flavor as per RFC 8986 section #4.16.3 */
	ZEBRA_SEG6_LOCAL_FLV_OP_USD          = 3,
	/* NEXT-C-SID Flavor as per draft-ietf-spring-srv6-srh-compression-03
	   section 4.1 */
	ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID    = 4,
};

#define SRV6_SEG_STRLEN 1024

struct seg6_segs {
	size_t num_segs;
	struct in6_addr segs[256];
};

struct seg6local_flavors_info {
	/* Flavor operations */
	uint32_t flv_ops;

	/* Locator-Block length, expressed in bits */
	uint8_t lcblock_len;
	/* Locator-Node Function length, expressed in bits */
	uint8_t lcnode_func_len;
};

struct seg6_seg_stack {
	uint8_t num_segs;
	struct in6_addr seg[0]; /* 1 or more segs */
};

struct seg6local_context {
	struct in_addr nh4;
	struct in6_addr nh6;
	uint32_t table;
	struct seg6local_flavors_info flv;
	uint8_t block_len;
	uint8_t node_len;
	uint8_t function_len;
	uint8_t argument_len;
};

struct srv6_locator {
	char name[SRV6_LOCNAME_SIZE];
	struct prefix_ipv6 prefix;

	/*
	 * Bit length of SRv6 locator described in
	 * draft-ietf-bess-srv6-services-05#section-3.2.1
	 */
	uint8_t block_bits_length;
	uint8_t node_bits_length;
	uint8_t function_bits_length;
	uint8_t argument_bits_length;

	int algonum;
	uint64_t current;
	bool status_up;
	struct list *chunks;
	struct list *sids;

	uint8_t flags;
#define SRV6_LOCATOR_USID (1 << 0) /* The SRv6 Locator is a uSID Locator */

	/* Pointer to the SID format. */
	struct srv6_sid_format *sid_format;

	/* Pointer to the parent SID block of the locator. */
	void *sid_block;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(srv6_locator);

struct srv6_locator_chunk {
	char locator_name[SRV6_LOCNAME_SIZE];
	struct prefix_ipv6 prefix;

	/*
	 * Bit length of SRv6 locator described in
	 * draft-ietf-bess-srv6-services-05#section-3.2.1
	 */
	uint8_t block_bits_length;
	uint8_t node_bits_length;
	uint8_t function_bits_length;
	uint8_t argument_bits_length;

	/*
	 * For Zclient communication values
	 */
	uint8_t keep;
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;

	uint8_t flags;
};

struct seg6_sid {
	enum seg6local_action_t sidaction;
	char vrfName[VRF_NAMSIZ + 1];
	struct prefix_ipv6 ipv6Addr;
	char sidstr[PREFIX_STRLEN];
};
/*
 * SRv6 Endpoint Behavior codepoints, as defined by IANA in
 * https://www.iana.org/assignments/segment-routing/segment-routing.xhtml
 */
enum srv6_endpoint_behavior_codepoint {
	SRV6_ENDPOINT_BEHAVIOR_RESERVED         = 0x0000,
	SRV6_ENDPOINT_BEHAVIOR_END              = 0x0001,
	SRV6_ENDPOINT_BEHAVIOR_END_X            = 0x0005,
	SRV6_ENDPOINT_BEHAVIOR_END_DT6          = 0x0012,
	SRV6_ENDPOINT_BEHAVIOR_END_DT4          = 0x0013,
	SRV6_ENDPOINT_BEHAVIOR_END_DT46         = 0x0014,
	SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID    = 0x002B,
	SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID  = 0x002C,
	SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID     = 0x003E,
	SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID     = 0x003F,
	SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID    = 0x0040,
	SRV6_ENDPOINT_BEHAVIOR_OPAQUE           = 0xFFFF,
};

struct nexthop_srv6 {
	/* SRv6 localsid info for Endpoint-behaviour */
	enum seg6local_action_t seg6local_action;
	struct seg6local_context seg6local_ctx;

	/* SRv6 Headend-behaviour */
	struct seg6_seg_stack *seg6_segs;
};

/* SID format type */
enum srv6_sid_format_type {
	SRV6_SID_FORMAT_TYPE_UNSPEC = 0,
	/* SRv6 SID uncompressed format */
	SRV6_SID_FORMAT_TYPE_UNCOMPRESSED = 1,
	/* SRv6 SID compressed uSID format */
	SRV6_SID_FORMAT_TYPE_USID = 2,
};

/* SRv6 SID format */
struct srv6_sid_format {
	/* Name of the format */
	char name[SRV6_SID_FORMAT_NAME_SIZE];

	/* Format type: uncompressed vs compressed */
	enum srv6_sid_format_type type;

	/*
	 * Lengths of block/node/function/argument parts of the SIDs allocated
	 * using this format
	 */
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
DECLARE_QOBJ_TYPE(srv6_sid_format);

/* Context for an SRv6 SID */
struct srv6_sid_ctx {
	/* Behavior associated with the SID */
	enum seg6local_action_t behavior;

	/* Behavior-specific attributes */
	struct in_addr nh4;
	struct in6_addr nh6;
	vrf_id_t vrf_id;
};

static inline const char *seg6_mode2str(enum seg6_mode_t mode)
{
	switch (mode) {
	case INLINE:
		return "INLINE";
	case ENCAP:
		return "ENCAP";
	case L2ENCAP:
		return "L2ENCAP";
	default:
		return "unknown";
	}
}

static inline bool sid_same(
		const struct in6_addr *a,
		const struct in6_addr *b)
{
	if (!a && !b)
		return true;
	else if (!(a && b))
		return false;
	else
		return memcmp(a, b, sizeof(struct in6_addr)) == 0;
}

static inline bool sid_diff(
		const struct in6_addr *a,
		const struct in6_addr *b)
{
	return !sid_same(a, b);
}


static inline bool sid_zero(const struct seg6_seg_stack *a)
{
	struct in6_addr zero = {};

	assert(a);

	return sid_same(&a->seg[0], &zero);
}

static inline bool sid_zero_ipv6(const struct in6_addr *a)
{
	struct in6_addr zero = {};

	return sid_same(&a[0], &zero);
}

static inline void *sid_copy(struct in6_addr *dst,
		const struct in6_addr *src)
{
	return memcpy(dst, src, sizeof(struct in6_addr));
}

const char *
seg6local_action2str(uint32_t action);

const char *seg6local_context2str(char *str, size_t size,
				  const struct seg6local_context *ctx,
				  uint32_t action);
void seg6local_context2json(const struct seg6local_context *ctx,
			    uint32_t action, json_object *json);

static inline const char *srv6_sid_ctx2str(char *str, size_t size,
					   const struct srv6_sid_ctx *ctx)
{
	int len = 0;

	len += snprintf(str + len, size - len, "%s",
			seg6local_action2str(ctx->behavior));

	switch (ctx->behavior) {
	case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
		break;

	case ZEBRA_SEG6_LOCAL_ACTION_END:
		snprintf(str + len, size - len, " USP");
		break;

	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		snprintfrr(str + len, size - len, " nh6 %pI6", &ctx->nh6);
		break;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		snprintfrr(str + len, size - len, " nh4 %pI4", &ctx->nh4);
		break;

	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		snprintf(str + len, size - len, " vrf_id %u", ctx->vrf_id);
		break;

	case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
	case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_S:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
	case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
	case ZEBRA_SEG6_LOCAL_ACTION_END_BPF:
	default:
		snprintf(str + len, size - len, " unknown(%s)", __func__);
	}

	return str;
}

int snprintf_seg6_segs(char *str,
		size_t size, const struct seg6_segs *segs);

extern void combine_sid(struct srv6_locator *locator, struct in6_addr *sid_addr,
			struct in6_addr *result_addr);
extern void srv6_locator_del(struct srv6_locator *locator);

extern struct srv6_locator *srv6_locator_alloc(const char *name);
extern struct srv6_locator_chunk *srv6_locator_chunk_alloc(void);
extern struct seg6_sid *srv6_locator_sid_alloc(void);
extern void srv6_locator_sid_free(struct seg6_sid *sid);
extern void srv6_locator_free(struct srv6_locator *locator);
extern void srv6_locator_chunk_list_free(void *data);
extern void srv6_locator_chunk_free(struct srv6_locator_chunk **chunk);
extern void srv6_locator_copy(struct srv6_locator *copy,
			      const struct srv6_locator *locator);
json_object *srv6_locator_chunk_json(const struct srv6_locator_chunk *chunk);
json_object *srv6_locator_json(const struct srv6_locator *loc);
json_object *srv6_locator_detailed_json(const struct srv6_locator *loc);
json_object *
srv6_locator_chunk_detailed_json(const struct srv6_locator_chunk *chunk);
json_object *srv6_locator_sid_detailed_json(const struct srv6_locator *locator,
					    const struct seg6_sid *sid);

extern struct srv6_sid_format *srv6_sid_format_alloc(const char *name);
extern void srv6_sid_format_free(struct srv6_sid_format *format);
extern void delete_srv6_sid_format(void *format);

extern struct srv6_sid_ctx *srv6_sid_ctx_alloc(enum seg6local_action_t behavior,
					       struct in_addr *nh4,
					       struct in6_addr *nh6,
					       vrf_id_t vrf_id);
extern void srv6_sid_ctx_free(struct srv6_sid_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
