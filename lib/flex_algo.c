// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 *
 * flex_algo.c: Flexible Algorithm library
 *
 * Authors
 * -------
 * Hiroki Shirokura
 * Masakazu Asama
 * Louis Scalbert
 */

#include "zebra.h"

#include "flex_algo.h"

DEFINE_MTYPE_STATIC(LIB, FLEX_ALGO_DATABASE, "Flex-Algo database");
DEFINE_MTYPE_STATIC(LIB, FLEX_ALGO, "Flex-Algo algorithm information");

struct flex_algos *flex_algos_alloc(flex_algo_allocator_t allocator,
				    flex_algo_releaser_t releaser)
{
	struct flex_algos *flex_algos;

	flex_algos =
		XCALLOC(MTYPE_FLEX_ALGO_DATABASE, sizeof(struct flex_algos));
	flex_algos->flex_algos = list_new();
	flex_algos->allocator = allocator;
	flex_algos->releaser = releaser;
	return flex_algos;
}

void flex_algos_free(struct flex_algos *flex_algos)
{
	struct listnode *node, *nnode;
	struct flex_algo *fa;

	for (ALL_LIST_ELEMENTS(flex_algos->flex_algos, node, nnode, fa))
		flex_algo_free(flex_algos, fa);
	list_delete(&flex_algos->flex_algos);
	XFREE(MTYPE_FLEX_ALGO_DATABASE, flex_algos);
}

struct flex_algo *flex_algo_alloc(struct flex_algos *flex_algos,
				  uint8_t algorithm, void *arg)
{
	struct flex_algo *fa;

	fa = XCALLOC(MTYPE_FLEX_ALGO, sizeof(struct flex_algo));
	fa->algorithm = algorithm;
	if (flex_algos->allocator)
		fa->data = flex_algos->allocator(arg);
	admin_group_init(&fa->admin_group_exclude_any);
	admin_group_init(&fa->admin_group_include_any);
	admin_group_init(&fa->admin_group_include_all);
	listnode_add(flex_algos->flex_algos, fa);
	return fa;
}

void flex_algo_free(struct flex_algos *flex_algos, struct flex_algo *fa)
{
	if (flex_algos->releaser)
		flex_algos->releaser(fa->data);
	admin_group_term(&fa->admin_group_exclude_any);
	admin_group_term(&fa->admin_group_include_any);
	admin_group_term(&fa->admin_group_include_all);
	listnode_delete(flex_algos->flex_algos, fa);
	XFREE(MTYPE_FLEX_ALGO, fa);
}

/**
 * @brief Look up the local flex-algo object by its algorithm number.
 * @param algorithm flex-algo algorithm number
 * @param area area pointer of flex-algo
 * @return local flex-algo object if exist, else NULL
 */
struct flex_algo *flex_algo_lookup(struct flex_algos *flex_algos,
				   uint8_t algorithm)
{
	struct listnode *node;
	struct flex_algo *fa;

	for (ALL_LIST_ELEMENTS_RO(flex_algos->flex_algos, node, fa))
		if (fa->algorithm == algorithm)
			return fa;
	return NULL;
}

/**
 * @brief Compare two Flex-Algo Definitions (FAD)
 * @param Flex algo 1
 * @param Flex algo 2
 * @return true if the definition is equal, else false
 */
bool flex_algo_definition_cmp(struct flex_algo *fa1, struct flex_algo *fa2)
{
	if (fa1->algorithm != fa2->algorithm)
		return false;
	if (fa1->calc_type != fa2->calc_type)
		return false;
	if (fa1->metric_type != fa2->metric_type)
		return false;
	if (fa1->exclude_srlg != fa2->exclude_srlg)
		return false;
	if (fa1->flags != fa2->flags)
		return false;
	if (fa1->unsupported_subtlv != fa2->unsupported_subtlv)
		return false;

	if (!admin_group_cmp(&fa1->admin_group_exclude_any,
			     &fa2->admin_group_exclude_any))
		return false;
	if (!admin_group_cmp(&fa1->admin_group_include_all,
			     &fa2->admin_group_include_all))
		return false;
	if (!admin_group_cmp(&fa1->admin_group_include_any,
			     &fa2->admin_group_include_any))
		return false;

	return true;
}

/**
 * Check SR Algorithm is Flex-Algo
 * according to RFC9350 section 4
 *
 * @param algorithm SR Algorithm
 */
bool flex_algo_id_valid(uint16_t algorithm)
{
	return algorithm >= SR_ALGORITHM_FLEX_MIN &&
	       algorithm <= SR_ALGORITHM_FLEX_MAX;
}

char *flex_algo_metric_type_print(char *type_str, size_t sz,
				  enum flex_algo_metric_type metric_type)
{
	switch (metric_type) {
	case MT_IGP:
		snprintf(type_str, sz, "igp");
		break;
	case MT_MIN_UNI_LINK_DELAY:
		snprintf(type_str, sz, "delay");
		break;
	case MT_TE_DEFAULT:
		snprintf(type_str, sz, "te");
		break;
	}
	return type_str;
}

bool flex_algo_get_state(struct flex_algos *flex_algos, uint8_t algorithm)
{
	struct flex_algo *fa = flex_algo_lookup(flex_algos, algorithm);

	if (!fa)
		return false;

	return fa->state;
}

void flex_algo_set_state(struct flex_algos *flex_algos, uint8_t algorithm,
			 bool state)
{
	struct flex_algo *fa = flex_algo_lookup(flex_algos, algorithm);

	if (!fa)
		return;

	fa->state = state;
}
