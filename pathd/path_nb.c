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
				.cli_show = cli_show_te_path_segment_list,
				.destroy = pathd_te_segment_list_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/segment-list/label",
			.cbs = {
				.create = pathd_te_segment_list_label_create,
				.move = pathd_te_segment_list_label_move,
				.cli_show = cli_show_te_path_segment_list_label,
				.destroy = pathd_te_segment_list_label_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy",
			.cbs = {
				.create = pathd_te_sr_policy_create,
				.cli_show = cli_show_te_path_sr_policy,
				.destroy = pathd_te_sr_policy_destroy,
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
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path",
			.cbs = {
				.create = pathd_te_sr_policy_candidate_path_create,
				.cli_show = cli_show_te_path_sr_policy_candidate_path,
				.destroy = pathd_te_sr_policy_candidate_path_destroy,
				.apply_finish = pathd_te_sr_policy_candidate_path_apply_finish,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/name",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_name_modify,
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
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/type",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_type_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/sr-policy/candidate-path/segment-list-name",
			.cbs = {
				.modify = pathd_te_sr_policy_candidate_path_segment_list_name_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
