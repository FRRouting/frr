// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 *
 * flex_algo.h: Flexible Algorithm library
 *
 * Authors
 * -------
 * Hiroki Shirokura
 * Masakazu Asama
 * Louis Scalbert
 */

#ifndef _FRR_FLEX_ALGO_H
#define _FRR_FLEX_ALGO_H

#include "admin_group.h"
#include "linklist.h"
#include "prefix.h"
#include "segment_routing.h"

#define FLEX_ALGO_PRIO_MIN 0
#define FLEX_ALGO_PRIO_DEFAULT 128
#define FLEX_ALGO_PRIO_MAX 255

enum flex_algo_calc_type {
	CALC_TYPE_MIN = 0,
	CALC_TYPE_SPF  = CALC_TYPE_MIN,
	CALC_TYPE_MAX,
};

#define CALC_TYPE_DEFAULT		CALC_TYPE_SPF
#define CALC_TYPE_SPF_STR		"spf"

static const char *flexalgo_ct2str[CALC_TYPE_MAX] = {
	CALC_TYPE_SPF_STR, /* CALC_TYPE_SPF */
};

static inline const char*
flex_algo_calc_type2str(enum flex_algo_calc_type ct)
{
	switch(ct) {
	case CALC_TYPE_SPF:
		return flexalgo_ct2str[ct];
	case CALC_TYPE_MAX:
	default:
		break;
	}

	return "Invalid";
}

static inline enum flex_algo_calc_type
flex_algo_str2calc_type(const char* str)
{
	size_t len = strlen(str);
	enum flex_algo_calc_type ct;

	for (ct = CALC_TYPE_MIN; ct < CALC_TYPE_MAX; ct++) {
		if (!strncmp(str, flexalgo_ct2str[ct], len))
			return ct;
	}

	return CALC_TYPE_MAX;
}

/* flex-algo definition flags */

/* M-flag (aka. prefix-metric)
 * Flex-Algorithm specific prefix and ASBR metric MUST be used
 */
#define FAD_FLAG_M 0x80

#define FLEX_ALGO_PREFIX_METRIC_SET(fad)				\
	((fad)->flags & FAD_FLAG_M)

/*
 * Metric Type values from RFC9350 section 5.1
 */
enum flex_algo_metric_type {
	MT_MIN = 0,
	MT_IGP = MT_MIN,
	MT_MIN_UNI_LINK_DELAY = 1,
	MT_TE_DEFAULT = 2,
	MT_MAX
};

#define MT_DEFAULT			MT_IGP
#define MT_IGP_STR			"igp"
#define MT_MIN_UNI_LINK_DELAY_STR	"delay"
#define MT_TE_DEFAULT_STR		"te"

static const char *flexalgo_mt2str[MT_MAX] = {
	MT_IGP_STR, /* MT_IGP */
	MT_MIN_UNI_LINK_DELAY_STR, /* MT_MIN_UNI_LINK_DELAY */
	MT_TE_DEFAULT_STR, /* MT_TE_DEFAULT */
};

static inline const char*
flex_algo_metric_type2str(enum flex_algo_metric_type mt)
{
	switch(mt) {
	case MT_IGP:
	case MT_MIN_UNI_LINK_DELAY:
	case MT_TE_DEFAULT:
		return flexalgo_mt2str[mt];
	case MT_MAX:
	default:
		break;
	}

	return "Invalid";
}

static inline enum flex_algo_metric_type
flex_algo_str2metric_type(const char* str)
{
	size_t len = strlen(str);
	enum flex_algo_metric_type mt;

	for (mt = MT_MIN; mt < MT_MAX; mt++) {
		if (!strncmp(str, flexalgo_mt2str[mt], len))
			return mt;
	}

	return MT_MAX;
}

/* Flex-Algo data about a given algorithm.
 * It includes the definition and some local data.
 */
struct flex_algo {
	/* Flex-Algo definition */
	uint8_t algorithm;
	enum flex_algo_metric_type metric_type;
	uint8_t calc_type;
	uint8_t priority;
	uint8_t flags;

	/* extended admin-groups */
	struct admin_group admin_group_exclude_any;
	struct admin_group admin_group_include_any;
	struct admin_group admin_group_include_all;

	/* Exclude SRLG Sub-TLV is not yet supported by IS-IS
	 * True if a Exclude SRLG Sub-TLV has been found
	 */
	bool exclude_srlg;
	/*
	 * For now used admin_groups for Exclude SRLGs.
	 */
	struct admin_group srlgs_exclude;

	/*
	 * The prefix advertise metric to be added to the corresponding
	  * FAPM SubTLVs. Applicable only when the M-Flag is set for
	  * the Flex-Algo Definition.
	 */
	uint32_t prefix_adv_metric;

	/* True if an unsupported sub-TLV other Exclude SRLG
	 * has been received.
	 * A router that receives an unsupported definition
	 * that is elected must not participate in the algorithm.
	 * This boolean prevents future sub-TLV from being considered
	 * as supported.
	 */
	bool unsupported_subtlv;

	/* Flex-Algo local data */

	/* True if the local definition must be advertised */
	bool advertise_definition;

	/* which dataplane must be used for the algorithm */
#define FLEX_ALGO_SR_MPLS 0x01
#define FLEX_ALGO_SRV6 0x02
#define FLEX_ALGO_IP 0x04
	uint8_t dataplanes;

	/* True if the Algorithm is locally enabled (ie. a definition has been
	 * found and is supported).
	 */
	bool state;

	/*
	 * This property can be freely extended among different routing
	 * protocols. Since Flex-Algo is an IGP protocol agnostic, both IS-IS
	 * and OSPF can implement Flex-Algo. The struct flex_algo thus provides
	 * the general data structure of Flex-Algo, and the value of extending
	 * it with the IGP protocol is provided by this property.
	 */
	void *data;
};

#define FLEX_ALGO_ALGO_MIN	128
#define FLEX_ALGO_ALGO_MAX	255

#define FOREACH_FLEX_ALGO_ADMIN_GROUP(admngrps, admingroup) 		\
	FOREACH_ADMIN_GROUP_BITS(admngrps, admingroup)

#define FOREACH_FLEX_ALGO_SRLG(srlgs, srlg) 				\
	FOREACH_ADMIN_GROUP_BITS(srlgs, srlg)

typedef void *(*flex_algo_allocator_t)(void *);
typedef void (*flex_algo_releaser_t)(void *);

struct flex_algos {
	flex_algo_allocator_t allocator;
	flex_algo_releaser_t releaser;
	struct list *flex_algos;
};

#define FOREACH_FLEX_ALGO_DEFN(flxalgs, node, nnode, flexalgo)		\
	for (ALL_LIST_ELEMENTS ((flxalgs)->flex_algos, node, nnode, 	\
				flexalgo))

static inline size_t
flex_algos_count(struct flex_algos *flex_algos)
{
	return (flex_algos->flex_algos ? flex_algos->flex_algos->count : 0);
}

static inline bool
flex_algos_empty(struct flex_algos *flex_algos)
{
	return (flex_algos_count(flex_algos) ? false : true);
}

/*
 * Flex-Algo Utilities
 */
struct flex_algos *flex_algos_alloc(flex_algo_allocator_t allocator,
				    flex_algo_releaser_t releaser);
void flex_algos_free(struct flex_algos *flex_algos);
struct flex_algo *flex_algo_alloc(struct flex_algos *flex_algos,
				  uint8_t algorithm, void *arg);
struct flex_algo *flex_algo_lookup(struct flex_algos *flex_algos,
				   uint8_t algorithm);
bool flex_algo_definition_cmp(struct flex_algo *fa1, struct flex_algo *fa2);
void flex_algo_delete(struct flex_algos *flex_algos, uint8_t algorithm);
bool flex_algo_id_valid(uint16_t algorithm);
char *flex_algo_metric_type_print(char *type_str, size_t sz,
				  enum flex_algo_metric_type metric_type);

bool flex_algo_get_state(struct flex_algos *flex_algos, uint8_t algorithm);

void flex_algo_set_state(struct flex_algos *flex_algos, uint8_t algorithm,
			 bool state);

static inline void
flex_algo_set_prefix_metric(struct flex_algo *fa, uint32_t metric)
{
	fa->flags |= FAD_FLAG_M;
	fa->prefix_adv_metric = metric;
}

static inline void
flex_algo_reset_prefix_metric(struct flex_algo *fa)
{
	fa->flags &= ~FAD_FLAG_M;
	fa->prefix_adv_metric = 0;
}

static inline void
flex_algo_encode_admin_group(struct admin_group *ag, uint8_t *buf,
			     uint16_t *buflen)
{
	bf_encode_to_buf(&ag->bitmap, buf, buflen);
}

static inline void
flex_algo_decode_admin_group(struct admin_group *ag, uint8_t *buf,
			     uint16_t buflen)
{
	bf_decode_from_buf(&ag->bitmap, buf, buflen);
}

#endif /* _FRR_FLEX_ALGO_H */
