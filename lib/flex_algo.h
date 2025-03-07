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

#define FLEX_ALGO_PRIO_DEFAULT 128

#define CALC_TYPE_SPF 0

/* flex-algo definition flags */

/* M-flag (aka. prefix-metric)
 * Flex-Algorithm specific prefix and ASBR metric MUST be used
 */
#define FAD_FLAG_M 0x80

/*
 * Metric Type values from RFC9350 section 5.1
 */
enum flex_algo_metric_type {
	MT_IGP = 0,
	MT_MIN_UNI_LINK_DELAY = 1,
	MT_TE_DEFAULT = 2,
};


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

typedef void *(*flex_algo_allocator_t)(void *);
typedef void (*flex_algo_releaser_t)(void *);

struct flex_algos {
	flex_algo_allocator_t allocator;
	flex_algo_releaser_t releaser;
	struct list *flex_algos;
};

/*
 * Flex-Algo Utilities
 */
struct flex_algos *flex_algos_alloc(flex_algo_allocator_t allocator,
				    flex_algo_releaser_t releaser);
void flex_algos_free(struct flex_algos *flex_algos);
struct flex_algo *flex_algo_alloc(struct flex_algos *flex_algos,
				  uint8_t algorithm, void *arg);
void flex_algo_free(struct flex_algos *flex_algos, struct flex_algo *fa);
struct flex_algo *flex_algo_lookup(struct flex_algos *flex_algos,
				   uint8_t algorithm);
bool flex_algo_definition_cmp(struct flex_algo *fa1, struct flex_algo *fa2);
bool flex_algo_id_valid(uint16_t algorithm);
char *flex_algo_metric_type_print(char *type_str, size_t sz,
				  enum flex_algo_metric_type metric_type);

bool flex_algo_get_state(struct flex_algos *flex_algos, uint8_t algorithm);

void flex_algo_set_state(struct flex_algos *flex_algos, uint8_t algorithm,
			 bool state);
#endif /* _FRR_FLEX_ALGO_H */
