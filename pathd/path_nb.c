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

/* clang-format off */
const struct frr_yang_module_info frr_pathd_info = {
	.name = "frr-pathd",
	.nodes = {
		{
			.xpath = "/frr-pathd:pathd/segment-list",
			.cbs = {
				.create = pathd_te_segment_list_create,
				.destroy = pathd_te_segment_list_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/label",
			.cbs = {
				.create = pathd_te_segment_list_label_create,
				.destroy = pathd_te_segment_list_label_destroy,
		                .move = pathd_te_segment_list_label_move,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy",
			.cbs = {
				.create = pathd_te_sr_policy_create,
				.destroy = pathd_te_sr_policy_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/color",
			.cbs = {
				.modify = pathd_te_sr_policy_color_modify,
				.destroy = pathd_te_sr_policy_color_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/endpoint",
			.cbs = {
				.modify = pathd_te_sr_policy_endpoint_modify,
				.destroy = pathd_te_sr_policy_endpoint_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/binding-sid",
			.cbs = {
				.modify = pathd_te_sr_policy_binding_sid_modify,
				.destroy = pathd_te_sr_policy_binding_sid_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path",
			.cbs = {
				.create = pathd_te_sr_policy_candidate_path_create,
				.destroy = pathd_te_sr_policy_candidate_path_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/protocol-origin",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_protocol_origin_modify,
				.destroy = pathd_te_sr_policy_candidate_path_protocol_origin_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/originator",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_originator_modify,
				.destroy = pathd_te_sr_policy_candidate_path_originator_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/dynamic-flag",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_dynamic_flag_modify,
				.destroy = pathd_te_sr_policy_candidate_path_dynamic_flag_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/segment-list-name",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_segment_list_name_modify,
				.destroy = pathd_te_sr_policy_candidate_path_segment_list_name_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
