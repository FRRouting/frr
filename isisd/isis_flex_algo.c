/*
 * IS-IS Flexible Algorithm implementation
 * Copyright (C) 2022  Hiroki Shirokura, LINE Corporation
 * Copyright (C) 2022  Masakazu Asama
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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

DEFINE_MTYPE_STATIC(ISISD, FLEX_ALGO, "ISIS Flex Algo");

void *isis_flex_algo_data_alloc(void *voidarg)
{
	struct isis_flex_algo_alloc_arg *arg = voidarg;
	struct isis_flex_algo_data *data;

	data = XCALLOC(MTYPE_FLEX_ALGO, sizeof(*data));

	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			if (!(arg->area->is_type & level))
				continue;
			data->spftree[tree][level - 1] = isis_spftree_new(
				arg->area, &arg->area->lspdb[level - 1],
				arg->area->isis->sysid, level, tree,
				SPF_TYPE_FLEX_ALGO, 0, arg->algorithm);
			data->spftree[tree][level - 1]->algorithm = arg->algorithm;
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
}

/**
 * @brief Look up the flex-algo definition with the highest priority in the LSP
 * Database (LSDB). If the value of priority is the same, the flex-algo
 * definition with the highest sysid will be selected.
 * @param algorithm flex-algo algorithm number
 * @param area pointer
 * @return elected flex-algo-definition object if exist, else NULL
 */
struct isis_router_cap_fad *isis_flex_algo_elected(int algorithm,
						       struct isis_area *area)
{
	struct isis_lsp *lsp;
	struct isis_router_cap_fad *fa, *elected = NULL;

	/*
	 * Perform FAD comparison. First, compare the priority, and if they are
	 * the same, compare the sys-id.
	 */
	frr_each (lspdb, &area->lspdb[ISIS_LEVEL1 - 1], lsp) {
		if (!lsp->tlvs || !lsp->tlvs->router_cap)
			continue;

		fa = lsp->tlvs->router_cap->fads[algorithm];
		if (!fa)
			continue;

		assert(algorithm == fa->fad.algorithm);

		memcpy(fa->sysid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN + 2);

		if (!elected ||
				fa->fad.priority > elected->fad.priority ||
				(fa->fad.priority == elected->fad.priority &&
						lsp_id_cmp(fa->sysid, elected->sysid) > 0))
			elected = fa;
	}

	return elected;
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
	if (fad->m_flag != false)
		return false;

	return true;
}

/**
 * @brief Look for the elected Flex-Algo Definition and check that it is
 * supported by the current FRR version
 * @param algorithm flex-algo algorithm number
 * @param area area pointer of flex-algo
 * @return elected flex-algo-definition object if exist and supported, else NULL
 */
struct isis_router_cap_fad *isis_flex_algo_elected_supported(int algorithm,
						       struct isis_area *area)
{
	struct isis_router_cap_fad *elected_fad;

	elected_fad = isis_flex_algo_elected(algorithm, area);
	if (!elected_fad)
		return NULL;

	if (isis_flex_algo_supported(&elected_fad->fad))
		return elected_fad;

	return NULL;
}

bool isis_flex_algo_constraint_drop(struct isis_spftree *spftree,
				    struct isis_ext_subtlvs *subtlvs)
{
	bool ret;
	struct isis_router_cap_fad *fad;

	fad = isis_flex_algo_elected(spftree->algorithm, spftree->area);
	if (!fad) {
		return true;
	}

	/*
	 * Exclude Any
	 */
	if (!admin_group_zero(&fad->fad.admin_group_exclude_any)) {
		ret = admin_group_match_any(&fad->fad.admin_group_exclude_any,
					    &subtlvs->asla_ext_admin_group);
		if (ret)
			return true;
	}

	/*
	 * Include Any
	 */
	if (!admin_group_zero(&fad->fad.admin_group_include_any)) {
		ret = admin_group_match_any(&fad->fad.admin_group_include_any,
					    &subtlvs->asla_ext_admin_group);
		if (!ret)
			return true;
	}

	/*
	 * Include All
	 */
	if (!admin_group_zero(&fad->fad.admin_group_include_all)) {
		ret = admin_group_match_all(&fad->fad.admin_group_include_all,
					    &subtlvs->asla_ext_admin_group);
		if (!ret)
			return true;
	}

	return false;
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
