// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"

#include "pathd/path_nb.h"

static int iter_objfun_cb(const struct lyd_node *dnode, void *arg);
static int dummy_create(struct nb_cb_create_args *args);
static int dummy_modify(struct nb_cb_modify_args *args);
static int dummy_destroy(struct nb_cb_destroy_args *args);

struct of_cb_pref {
	uint32_t index;
	enum objfun_type type;
	struct of_cb_pref *next;
};

struct of_cb_args {
	struct of_cb_pref *first;
	uint32_t free_slot;
	struct of_cb_pref prefs[MAX_OBJFUN_TYPE];
};

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
			.xpath = "/frr-pathd:pathd/srte/segment-list",
			.cbs = {
				.create = pathd_srte_segment_list_create,
				.cli_show = cli_show_srte_segment_list,
				.cli_show_end = cli_show_srte_segment_list_end,
				.destroy = pathd_srte_segment_list_destroy,
				.get_next = pathd_srte_segment_list_get_next,
				.get_keys = pathd_srte_segment_list_get_keys,
				.lookup_entry = pathd_srte_segment_list_lookup_entry,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/protocol-origin",
			.cbs = {
				.modify = pathd_srte_segment_list_protocol_origin_modify,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/originator",
			.cbs = {
				.modify = pathd_srte_segment_list_originator_modify,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment",
			.cbs = {
				.create = pathd_srte_segment_list_segment_create,
				.cli_show = cli_show_srte_segment_list_segment,
				.destroy = pathd_srte_segment_list_segment_destroy,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/sid-value",
			.cbs = {
				.modify = pathd_srte_segment_list_segment_sid_value_modify,
				.destroy = pathd_srte_segment_list_segment_sid_value_destroy,
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/nai",
			.cbs = {
				.create = dummy_create,
				.destroy = pathd_srte_segment_list_segment_nai_destroy,
				.apply_finish = pathd_srte_segment_list_segment_nai_apply_finish
			},
			.priority = NB_DFLT_PRIORITY - 1
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/nai/type",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/nai/local-address",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/nai/local-interface",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/nai/local-prefix-len",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/nai/remote-address",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/nai/remote-interface",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/segment-list/segment/nai/algorithm",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy",
			.cbs = {
				.create = pathd_srte_policy_create,
				.cli_show = cli_show_srte_policy,
				.cli_show_end = cli_show_srte_policy_end,
				.destroy = pathd_srte_policy_destroy,
				.get_next = pathd_srte_policy_get_next,
				.get_keys = pathd_srte_policy_get_keys,
				.lookup_entry = pathd_srte_policy_lookup_entry,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/name",
			.cbs = {
				.modify = pathd_srte_policy_name_modify,
				.cli_show = cli_show_srte_policy_name,
				.destroy = pathd_srte_policy_name_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/binding-sid",
			.cbs = {
				.modify = pathd_srte_policy_binding_sid_modify,
				.cli_show = cli_show_srte_policy_binding_sid,
				.destroy = pathd_srte_policy_binding_sid_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/is-operational",
			.cbs = {
				.get_elem = pathd_srte_policy_is_operational_get_elem
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path",
			.cbs = {
				.create = pathd_srte_policy_candidate_path_create,
				.cli_show = cli_show_srte_policy_candidate_path,
				.cli_show_end = cli_show_srte_policy_candidate_path_end,
				.destroy = pathd_srte_policy_candidate_path_destroy,
				.get_next = pathd_srte_policy_candidate_path_get_next,
				.get_keys = pathd_srte_policy_candidate_path_get_keys,
				.lookup_entry = pathd_srte_policy_candidate_path_lookup_entry,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/name",
			.cbs = {
				.modify = pathd_srte_policy_candidate_path_name_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/is-best-candidate-path",
			.cbs = {
				.get_elem = pathd_srte_policy_candidate_path_is_best_candidate_path_get_elem,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/protocol-origin",
			.cbs = {
				.modify = pathd_srte_policy_candidate_path_protocol_origin_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/originator",
			.cbs = {
				.modify = pathd_srte_policy_candidate_path_originator_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/discriminator",
			.cbs = {
				.get_elem = pathd_srte_policy_candidate_path_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/type",
			.cbs = {
				.modify = pathd_srte_policy_candidate_path_type_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/segment-list-name",
			.cbs = {
				.destroy = pathd_srte_policy_candidate_path_segment_list_name_destroy,
				.modify = pathd_srte_policy_candidate_path_segment_list_name_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/bandwidth",
			.cbs = {
				.create = dummy_create,
				.destroy = pathd_srte_policy_candidate_path_bandwidth_destroy,
				.apply_finish = pathd_srte_policy_candidate_path_bandwidth_apply_finish
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/bandwidth/required",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/bandwidth/value",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/affinity/exclude-any",
			.cbs = {
				.modify = pathd_srte_policy_candidate_path_exclude_any_modify,
				.destroy = pathd_srte_policy_candidate_path_exclude_any_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/affinity/include-any",
			.cbs = {
				.modify = pathd_srte_policy_candidate_path_include_any_modify,
				.destroy = pathd_srte_policy_candidate_path_include_any_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/affinity/include-all",
			.cbs = {
				.modify = pathd_srte_policy_candidate_path_include_all_modify,
				.destroy = pathd_srte_policy_candidate_path_include_all_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/metrics",
			.cbs = {
				.create = dummy_create,
				.destroy = pathd_srte_policy_candidate_path_metrics_destroy,
				.apply_finish = pathd_srte_policy_candidate_path_metrics_apply_finish
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/metrics/value",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/metrics/required",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/metrics/is-bound",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/metrics/is-computed",
			.cbs = {.modify = dummy_modify, .destroy = dummy_destroy}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/objective-function",
			.cbs = {
				.create = dummy_create,
				.destroy = pathd_srte_policy_candidate_path_objfun_destroy,
				.apply_finish = pathd_srte_policy_candidate_path_objfun_apply_finish
			}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/objective-function/required",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = "/frr-pathd:pathd/srte/policy/candidate-path/constraints/objective-function/type",
			.cbs = {.modify = dummy_modify}
		},
		{
			.xpath = NULL,
		},
	}
};

void iter_objfun_prefs(const struct lyd_node *dnode, const char* path,
		       of_pref_cp_t fun, void *arg)
{
	struct of_cb_args args = {0};
	struct of_cb_pref *p;

	yang_dnode_iterate(iter_objfun_cb, &args, dnode, "%s", path);
	for (p = args.first; p != NULL; p = p->next)
		fun(p->type, arg);
}

int iter_objfun_cb(const struct lyd_node *dnode, void *arg)
{
	struct of_cb_args *of_arg = arg;
	struct of_cb_pref *pref;
	struct of_cb_pref **p;

	if (of_arg->free_slot >= MAX_OBJFUN_TYPE)
		return YANG_ITER_STOP;

	pref = &of_arg->prefs[of_arg->free_slot++];

	pref->index = yang_dnode_get_uint32(dnode, "index");
	pref->type = yang_dnode_get_enum(dnode, "type");

	/* Simplistic insertion sort */
	p = &of_arg->first;
	while (true) {
		if (*p == NULL) {
			*p = pref;
			break;
		}
		if ((*p)->index >= pref->index) {
			pref->next = *p;
			*p = pref;
			break;
		}
		p = &(*p)->next;
	}

	return YANG_ITER_CONTINUE;
}

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
