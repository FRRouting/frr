// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 *
 * isis_flex_algo.c: IS-IS Flexible Algorithm
 *
 * Authors
 * -------
 * Hiroki Shirokura
 * Masakazu Asama
 * Louis Scalbert
 */

#include <zebra.h>

#include "memory.h"
#include "stream.h"
#include "sbuf.h"
#include "network.h"
#include "command.h"
#include "bitfield.h"

#include "isisd/isisd.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_common.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_te.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_flex_algo.h"

#ifndef FABRICD
DEFINE_MTYPE_STATIC(ISISD, FLEX_ALGO, "ISIS Flex Algo");

void *isis_flex_algo_data_alloc(void *voidarg)
{
	struct isis_flex_algo_alloc_arg *arg = voidarg;
	struct isis_flex_algo_data *data;

	data = XCALLOC(MTYPE_FLEX_ALGO, sizeof(struct isis_flex_algo_data));

	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			if (!(arg->area->is_type & level))
				continue;
			data->spftree[tree][level - 1] = isis_spftree_new(
				arg->area, &arg->area->lspdb[level - 1],
				arg->area->isis->sysid, level, tree,
				SPF_TYPE_FORWARD, 0, arg->algorithm);
		}
	}

	return data;
}

void isis_flex_algo_data_free(void *voiddata)
{
	struct isis_flex_algo_data *data = voiddata;

	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++)
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++)
			if (data->spftree[tree][level - 1])
				isis_spftree_del(
					data->spftree[tree][level - 1]);
	XFREE(MTYPE_FLEX_ALGO, data);
}

static struct isis_router_cap_fad *
isis_flex_algo_definition_cmp(struct isis_router_cap_fad *elected,
			      struct isis_router_cap_fad *fa)
{
	if (!elected || fa->fad.priority > elected->fad.priority ||
	    (fa->fad.priority == elected->fad.priority &&
	     lsp_id_cmp(fa->sysid, elected->sysid) > 0))
		return fa;

	return elected;
}

/**
 * @brief Look up the flex-algo definition with the highest priority in the LSP
 * Database (LSDB). If the value of priority is the same, the flex-algo
 * definition with the highest sysid will be selected.
 * @param algorithm flex-algo algorithm number
 * @param area pointer
 * @param local router capability Flex-Algo Definition (FAD) double pointer.
 *    - fad is NULL: use the local router capability FAD from LSDB for the
 *      election.
 *    - fad is not NULL and *fad is NULL: use no local router capability FAD for
 *      the election.
 *    - fad and *fad are not NULL: uses the *fad local definition instead of the
 *      local definition from LSDB for the election.
 * @return elected flex-algo-definition object if exist, else NULL
 */
static struct isis_router_cap_fad *
_isis_flex_algo_elected(int algorithm, const struct isis_area *area,
			struct isis_router_cap_fad **fad)
{
	struct flex_algo *flex_ago;
	const struct isis_lsp *lsp;
	struct isis_router_cap_fad *fa, *elected = NULL;

	if (!flex_algo_id_valid(algorithm))
		return NULL;

	/* No elected FAD if the algorithm is not locally configured */
	flex_ago = flex_algo_lookup(area->flex_algos, algorithm);
	if (!flex_ago)
		return NULL;

	/* No elected FAD if no data-plane is enabled
	 * Currently, only Segment-Routing MPLS is supported.
	 * Segment-Routing SRv6 and IP will be configured in the future.
	 */
	if (!CHECK_FLAG(flex_ago->dataplanes, FLEX_ALGO_SR_MPLS))
		return NULL;

	/*
	 * Perform FAD comparison. First, compare the priority, and if they are
	 * the same, compare the sys-id.
	 */
	frr_each (lspdb_const, &area->lspdb[ISIS_LEVEL1 - 1], lsp) {
		if (!lsp->tlvs || !lsp->tlvs->router_cap)
			continue;

		if (lsp->own_lsp && fad)
			continue;

		fa = lsp->tlvs->router_cap->fads[algorithm];

		if (!fa)
			continue;

		assert(algorithm == fa->fad.algorithm);

		memcpy(fa->sysid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN + 2);

		elected = isis_flex_algo_definition_cmp(elected, fa);
	}

	if (fad && *fad)
		elected = isis_flex_algo_definition_cmp(elected, *fad);

	return elected;
}

struct isis_router_cap_fad *isis_flex_algo_elected(int algorithm,
						   const struct isis_area *area)
{
	return _isis_flex_algo_elected(algorithm, area, NULL);
}

/**
 * @brief Check the Flex-Algo Definition is supported by the current FRR version
 * @param flex-algo
 * @return true if supported else false
 */
bool isis_flex_algo_supported(struct flex_algo *fad)
{
	if (fad->calc_type != CALC_TYPE_SPF)
		return false;
	if (fad->metric_type != MT_IGP)
		return false;
	if (fad->flags != 0)
		return false;
	if (fad->exclude_srlg)
		return false;
	if (fad->unsupported_subtlv)
		return false;

	return true;
}

/**
 * @brief Look for the elected Flex-Algo Definition and check that it is
 * supported by the current FRR version
 * @param algorithm flex-algo algorithm number
 * @param area pointer
 * @param local router capability Flex-Algo Definition (FAD) double pointer.
 * @return elected flex-algo-definition object if exist and supported, else NULL
 */
static struct isis_router_cap_fad *
_isis_flex_algo_elected_supported(int algorithm, const struct isis_area *area,
				  struct isis_router_cap_fad **fad)
{
	struct isis_router_cap_fad *elected_fad;

	elected_fad = _isis_flex_algo_elected(algorithm, area, fad);
	if (!elected_fad)
		return NULL;

	if (isis_flex_algo_supported(&elected_fad->fad))
		return elected_fad;

	return NULL;
}

struct isis_router_cap_fad *
isis_flex_algo_elected_supported(int algorithm, const struct isis_area *area)
{
	return _isis_flex_algo_elected_supported(algorithm, area, NULL);
}

struct isis_router_cap_fad *
isis_flex_algo_elected_supported_local_fad(int algorithm,
					   const struct isis_area *area,
					   struct isis_router_cap_fad **fad)
{
	return _isis_flex_algo_elected_supported(algorithm, area, fad);
}

/**
 * Check LSP is participating specified SR Algorithm
 *
 * @param lsp        IS-IS lsp
 * @param algorithm  SR Algorithm
 * @return           Return true if sr-algorithm tlv includes specified
 *                   algorithm in router capability tlv
 */
bool sr_algorithm_participated(const struct isis_lsp *lsp, uint8_t algorithm)
{
	if (!lsp || !lsp->tlvs || !lsp->tlvs->router_cap)
		return false;
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		if (lsp->tlvs->router_cap->algo[i] == algorithm)
			return true;
	return false;
}

bool isis_flex_algo_constraint_drop(struct isis_spftree *spftree,
				    struct isis_lsp *lsp,
				    struct isis_extended_reach *reach)
{
	bool ret;
	struct isis_ext_subtlvs *subtlvs = reach->subtlvs;
	struct isis_router_cap_fad *fad;
	struct isis_asla_subtlvs *asla;
	struct listnode *node;
	uint32_t *link_admin_group = NULL;
	uint32_t link_ext_admin_group_bitmap0;
	struct admin_group *link_ext_admin_group = NULL;

	fad = isis_flex_algo_elected_supported(spftree->algorithm,
					       spftree->area);
	if (!fad)
		return true;

	for (ALL_LIST_ELEMENTS_RO(subtlvs->aslas, node, asla)) {
		if (!CHECK_FLAG(asla->standard_apps, ISIS_SABM_FLAG_X))
			continue;
		if (asla->legacy) {
			if (IS_SUBTLV(subtlvs, EXT_ADM_GRP))
				link_admin_group = &subtlvs->adm_group;

			if (IS_SUBTLV(subtlvs, EXT_EXTEND_ADM_GRP) &&
			    admin_group_nb_words(&subtlvs->ext_admin_group) !=
				    0)
				link_ext_admin_group =
					&subtlvs->ext_admin_group;
		} else {
			if (IS_SUBTLV(asla, EXT_ADM_GRP))
				link_admin_group = &asla->admin_group;
			if (IS_SUBTLV(asla, EXT_EXTEND_ADM_GRP) &&
			    admin_group_nb_words(&asla->ext_admin_group) != 0)
				link_ext_admin_group = &asla->ext_admin_group;
		}
		break;
	}

	/* RFC7308 section 2.3.1
	 * A receiving node that notices that the AG differs from the first 32
	 * bits of the EAG SHOULD report this mismatch to the operator.
	 */
	if (link_admin_group && link_ext_admin_group) {
		link_ext_admin_group_bitmap0 =
			admin_group_get_offset(link_ext_admin_group, 0);
		if (*link_admin_group != link_ext_admin_group_bitmap0)
			zlog_warn(
				"ISIS-SPF: LSP from %pPN neighbor %pPN. Admin-group 0x%08x differs from ext admin-group 0x%08x.",
				lsp->hdr.lsp_id, reach->id, *link_admin_group,
				link_ext_admin_group_bitmap0);
	}

	/*
	 * Exclude Any
	 */
	if (!admin_group_zero(&fad->fad.admin_group_exclude_any)) {
		ret = admin_group_match_any(&fad->fad.admin_group_exclude_any,
					    link_admin_group,
					    link_ext_admin_group);
		if (ret)
			return true;
	}

	/*
	 * Include Any
	 */
	if (!admin_group_zero(&fad->fad.admin_group_include_any)) {
		ret = admin_group_match_any(&fad->fad.admin_group_include_any,
					    link_admin_group,
					    link_ext_admin_group);
		if (!ret)
			return true;
	}

	/*
	 * Include All
	 */
	if (!admin_group_zero(&fad->fad.admin_group_include_all)) {
		ret = admin_group_match_all(&fad->fad.admin_group_include_all,
					    link_admin_group,
					    link_ext_admin_group);
		if (!ret)
			return true;
	}

	return false;
}

#endif /* ifndef FABRICD */
