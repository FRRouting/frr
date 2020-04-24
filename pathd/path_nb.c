/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#include "northbound.h"
#include "libfrr.h"

#include "pathd/path_nb.h"

static int dummy_create(struct nb_cb_create_args *args);
static int dummy_modify(struct nb_cb_modify_args *args);
static int dummy_destroy(struct nb_cb_destroy_args *args);

/* clang-format off */
const struct frr_yang_module_info frr_pathd_info = {
	.name = "frr-pathd",
	.nodes = {
		{
			.xpath = "/frr-pathd:pathd",
			.cbs = {
				.apply_finish = pathd_apply_finish,
			},
			.priority = NB_DFLT_PRIORITY + 1
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list",
			.cbs = {
				.create = pathd_te_segment_list_create,
				.cli_show = cli_show_te_path_segment_list,
				.destroy = pathd_te_segment_list_destroy,
				.get_next = pathd_te_segment_list_get_next,
				.get_keys = pathd_te_segment_list_get_keys,
				.lookup_entry = pathd_te_segment_list_lookup_entry,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/protocol-origin",
			.cbs = {
				.modify = pathd_te_segment_list_protocol_origin_modify,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/segment",
			.cbs = {
				.create = pathd_te_segment_list_segment_create,
				.cli_show = cli_show_te_path_segment_list_segment,
				.destroy = pathd_te_segment_list_segment_destroy,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/segment/sid-value",
			.cbs = {
				.modify = pathd_te_segment_list_segment_sid_value_modify,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/segment/nai",
			.cbs = {
				.create = dummy_create,
				.destroy = pathd_te_segment_list_segment_nai_destroy,
				.apply_finish = pathd_te_segment_list_segment_nai_apply_finish
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/segment/nai/type",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/segment/nai/local-address",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/segment/nai/local-interface",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/segment/nai/remote-address",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/segment/nai/remote-interface",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy",
			.cbs = {
				.create = pathd_te_sr_policy_create,
				.cli_show = cli_show_te_path_sr_policy,
				.destroy = pathd_te_sr_policy_destroy,
				.get_next = pathd_te_sr_policy_get_next,
				.get_keys = pathd_te_sr_policy_get_keys,
				.lookup_entry = pathd_te_sr_policy_lookup_entry,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/name",
			.cbs = {
				.modify = pathd_te_sr_policy_name_modify,
				.cli_show = cli_show_te_path_sr_policy_name,
				.destroy = pathd_te_sr_policy_name_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/binding-sid",
			.cbs = {
				.modify = pathd_te_sr_policy_binding_sid_modify,
				.cli_show = cli_show_te_path_sr_policy_binding_sid,
				.destroy = pathd_te_sr_policy_binding_sid_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/is-operational",
			.cbs = {
				.get_elem = pathd_te_sr_policy_is_operational_get_elem
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path",
			.cbs = {
				.create = pathd_te_sr_policy_candidate_path_create,
				.cli_show = cli_show_te_path_sr_policy_candidate_path,
				.destroy = pathd_te_sr_policy_candidate_path_destroy,
				.get_next = pathd_te_sr_policy_candidate_path_get_next,
				.get_keys = pathd_te_sr_policy_candidate_path_get_keys,
				.lookup_entry = pathd_te_sr_policy_candidate_path_lookup_entry,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/name",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_name_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/is-best-candidate-path",
			.cbs = {
				.get_elem = pathd_te_sr_policy_candidate_path_is_best_candidate_path_get_elem,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/protocol-origin",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_protocol_origin_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/originator",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_originator_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/discriminator",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_discriminator_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/type",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_type_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/segment-list-name",
			.cbs = {
				.destroy = pathd_te_sr_policy_candidate_path_segment_list_name_destroy,
				.modify = pathd_te_sr_policy_candidate_path_segment_list_name_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/metrics",
			.cbs = {
				.create = dummy_create,
				.destroy = pathd_te_sr_policy_candidate_path_metrics_destroy,
				.apply_finish = pathd_te_sr_policy_candidate_path_metrics_apply_finish
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/metrics/value",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/metrics/is-bound",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/metrics/is-computed",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = NULL,
		},
	}
};

int dummy_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int dummy_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int dummy_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}
