/*
 * Copyright (C) 2020  NetDEF, Inc.
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

#include <northbound.h>
#include <yang.h>
#include <printfrr.h>
#include "pceplib/pcep_msg_objects.h"
#include "pathd/pathd.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_config.h"
#include "pathd/path_pcep_debug.h"
#include "thread.h"

#define MAX_XPATH 256
#define MAX_FLOAT_LEN 22
#define INETADDR4_MAXLEN 16
#define INETADDR6_MAXLEN 40
#define INITIATED_CANDIDATE_PREFERENCE 255
#define INITIATED_POLICY_COLOR 1


static void copy_candidate_objfun_info(struct srte_candidate *candidate,
				       struct path *path);
static void copy_candidate_affinity_filters(struct srte_candidate *candidate,
					    struct path *path);
static struct path_hop *
path_pcep_config_list_path_hops(struct srte_segment_list *segment_list);
static struct srte_candidate *lookup_candidate(struct lsp_nb_key *key);
static char *candidate_name(struct srte_candidate *candidate);
static enum pcep_lsp_operational_status
status_int_to_ext(enum srte_policy_status status);
static enum pcep_sr_subobj_nai pcep_nai_type(enum srte_segment_nai_type type);
static enum srte_segment_nai_type srte_nai_type(enum pcep_sr_subobj_nai type);

void path_pcep_refine_path(struct path *path)
{
	struct srte_candidate *candidate = lookup_candidate(&path->nbkey);
	struct srte_lsp *lsp;

	if (candidate == NULL)
		return;

	lsp = candidate->lsp;

	if (path->name == NULL)
		path->name = candidate_name(candidate);
	if (path->type == SRTE_CANDIDATE_TYPE_UNDEFINED)
		path->type = candidate->type;
	if (path->create_origin == SRTE_ORIGIN_UNDEFINED)
		path->create_origin = candidate->protocol_origin;
	if ((path->update_origin == SRTE_ORIGIN_UNDEFINED)
	    && (lsp->segment_list != NULL))
		path->update_origin = lsp->segment_list->protocol_origin;
}

struct path *path_pcep_config_get_path(struct lsp_nb_key *key)
{
	struct srte_candidate *candidate = lookup_candidate(key);
	if (candidate == NULL)
		return NULL;
	return candidate_to_path(candidate);
}

void path_pcep_config_list_path(path_list_cb_t cb, void *arg)
{
	struct path *path;
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		RB_FOREACH (candidate, srte_candidate_head,
			    &policy->candidate_paths) {
			path = candidate_to_path(candidate);
			if (!cb(path, arg))
				return;
		}
	}
}

struct path *candidate_to_path(struct srte_candidate *candidate)
{
	char *name;
	struct path *path;
	struct path_hop *hop = NULL;
	struct path_metric *metric = NULL;
	struct srte_policy *policy;
	struct srte_lsp *lsp;
	enum pcep_lsp_operational_status status;
	enum srte_protocol_origin update_origin = 0;
	char *originator = NULL;

	policy = candidate->policy;
	lsp = candidate->lsp;

	if (lsp->segment_list != NULL) {
		hop = path_pcep_config_list_path_hops(lsp->segment_list);
		update_origin = lsp->segment_list->protocol_origin;
		originator = XSTRDUP(MTYPE_PCEP, lsp->segment_list->originator);
	}
	path = pcep_new_path();
	name = candidate_name(candidate);
	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_BEST)) {
		status = status_int_to_ext(policy->status);
	} else {
		status = PCEP_LSP_OPERATIONAL_DOWN;
	}
	for (uint32_t i = 0; i < MAX_METRIC_TYPE; i++) {
		struct path_metric *path_metric;
		struct srte_metric *srte_metric = &lsp->metrics[i];
		if (CHECK_FLAG(srte_metric->flags, F_METRIC_IS_DEFINED)) {
			path_metric = pcep_new_metric();
			path_metric->next = metric;
			metric = path_metric;
			metric->type = i + 1;
			metric->value = srte_metric->value;
			metric->enforce = CHECK_FLAG(srte_metric->flags,
						     F_METRIC_IS_REQUIRED);
			metric->is_bound = CHECK_FLAG(srte_metric->flags,
						      F_METRIC_IS_BOUND);
			metric->is_computed = CHECK_FLAG(srte_metric->flags,
							 F_METRIC_IS_COMPUTED);
		}
	}
	*path = (struct path){
		.nbkey = (struct lsp_nb_key){.color = policy->color,
					     .endpoint = policy->endpoint,
					     .preference =
						     candidate->preference},
		.create_origin = lsp->protocol_origin,
		.update_origin = update_origin,
		.originator = originator,
		.plsp_id = 0,
		.name = name,
		.type = candidate->type,
		.srp_id = policy->srp_id,
		.req_id = 0,
		.binding_sid = policy->binding_sid,
		.status = status,
		.do_remove = false,
		.go_active = false,
		.was_created = false,
		.was_removed = false,
		.is_synching = false,
		.is_delegated = false,
		.first_hop = hop,
		.first_metric = metric};

	path->has_bandwidth = CHECK_FLAG(lsp->flags, F_CANDIDATE_HAS_BANDWIDTH);
	if (path->has_bandwidth) {
		path->enforce_bandwidth =
			CHECK_FLAG(lsp->flags, F_CANDIDATE_REQUIRED_BANDWIDTH);
		path->bandwidth = lsp->bandwidth;
	} else {
		path->enforce_bandwidth = true;
		path->bandwidth = 0;
	}

	copy_candidate_objfun_info(candidate, path);
	copy_candidate_affinity_filters(candidate, path);

	return path;
}

void copy_candidate_objfun_info(struct srte_candidate *candidate,
				struct path *path)
{
	struct srte_lsp *lsp = candidate->lsp;

	if (lsp != NULL) {
		if (CHECK_FLAG(lsp->flags, F_CANDIDATE_HAS_OBJFUN)) {
			path->has_pce_objfun = true;
			path->pce_objfun = lsp->objfun;
		} else {
			path->has_pce_objfun = false;
			path->pce_objfun = OBJFUN_UNDEFINED;
		}
	}
	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_OBJFUN)) {
		path->has_pcc_objfun = true;
		path->pcc_objfun = candidate->objfun;
		path->enforce_pcc_objfun = CHECK_FLAG(
			candidate->flags, F_CANDIDATE_REQUIRED_OBJFUN);

	} else {
		path->has_pcc_objfun = false;
		path->pcc_objfun = OBJFUN_UNDEFINED;
		UNSET_FLAG(candidate->flags, F_CANDIDATE_REQUIRED_OBJFUN);
	}
}

void copy_candidate_affinity_filters(struct srte_candidate *candidate,
				     struct path *path)
{
	bool eany = CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_EXCLUDE_ANY);
	bool iany = CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_INCLUDE_ANY);
	bool iall = CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_INCLUDE_ALL);
	path->has_affinity_filters = eany || iany || iall;
	path->affinity_filters[AFFINITY_FILTER_EXCLUDE_ANY - 1] =
		eany ? candidate->affinity_filters[AFFINITY_FILTER_EXCLUDE_ANY
						   - 1]
		     : 0;
	path->affinity_filters[AFFINITY_FILTER_INCLUDE_ANY - 1] =
		iany ? candidate->affinity_filters[AFFINITY_FILTER_INCLUDE_ANY
						   - 1]
		     : 0;
	path->affinity_filters[AFFINITY_FILTER_INCLUDE_ALL - 1] =
		iall ? candidate->affinity_filters[AFFINITY_FILTER_INCLUDE_ALL
						   - 1]
		     : 0;
}

struct path_hop *
path_pcep_config_list_path_hops(struct srte_segment_list *segment_list)
{
	struct srte_segment_entry *segment;
	struct path_hop *hop = NULL, *last_hop = NULL;

	RB_FOREACH_REVERSE (segment, srte_segment_entry_head,
			    &segment_list->segments) {
		hop = pcep_new_hop();
		*hop = (struct path_hop){
			.next = last_hop,
			.is_loose = false,
			.has_sid = true,
			.is_mpls = true,
			.has_attribs = false,
			.sid = {.mpls = {.label = segment->sid_value}},
			.has_nai =
				segment->nai_type != SRTE_SEGMENT_NAI_TYPE_NONE,
			.nai = {.type = pcep_nai_type(segment->nai_type)}};
		switch (segment->nai_type) {
		case SRTE_SEGMENT_NAI_TYPE_IPV4_NODE:
		case SRTE_SEGMENT_NAI_TYPE_IPV6_NODE:
		case SRTE_SEGMENT_NAI_TYPE_IPV4_LOCAL_IFACE:
		case SRTE_SEGMENT_NAI_TYPE_IPV6_LOCAL_IFACE:
		case SRTE_SEGMENT_NAI_TYPE_IPV4_ALGORITHM:
		case SRTE_SEGMENT_NAI_TYPE_IPV6_ALGORITHM:
			memcpy(&hop->nai.local_addr, &segment->nai_local_addr,
			       sizeof(struct ipaddr));
			break;
		case SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY:
		case SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY:
			memcpy(&hop->nai.local_addr, &segment->nai_local_addr,
			       sizeof(struct ipaddr));
			memcpy(&hop->nai.remote_addr, &segment->nai_remote_addr,
			       sizeof(struct ipaddr));
			break;
		case SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY:
			memcpy(&hop->nai.local_addr, &segment->nai_local_addr,
			       sizeof(struct ipaddr));
			hop->nai.local_iface = segment->nai_local_iface;
			memcpy(&hop->nai.remote_addr, &segment->nai_remote_addr,
			       sizeof(struct ipaddr));
			hop->nai.remote_iface = segment->nai_remote_iface;
			break;
		default:
			break;
		}
		last_hop = hop;
	}
	return hop;
}

int path_pcep_config_initiate_path(struct path *path)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	if (path->do_remove) {
		zlog_warn("PCE %s tried to REMOVE pce-initiate a path ",
			  path->originator);
		candidate = lookup_candidate(&path->nbkey);
		if (candidate) {
			if (!path->is_delegated) {
				zlog_warn(
					"(%s)PCE tried to REMOVE but it's not Delegated!",
					__func__);
				return ERROR_19_1;
			}
			if (candidate->type != SRTE_CANDIDATE_TYPE_DYNAMIC) {
				zlog_warn(
					"(%s)PCE tried to REMOVE but it's not PCE origin!",
					__func__);
				return ERROR_19_9;
			}
			zlog_warn(
				"(%s)PCE tried to REMOVE found candidate!, let's remove",
				__func__);
			candidate->policy->srp_id = path->srp_id;
			SET_FLAG(candidate->policy->flags, F_POLICY_DELETED);
			SET_FLAG(candidate->flags, F_CANDIDATE_DELETED);
		} else {
			zlog_warn("(%s)PCE tried to REMOVE not existing LSP!",
				  __func__);
			return ERROR_19_3;
		}
		srte_apply_changes();
	} else {
		assert(!IS_IPADDR_NONE(&path->nbkey.endpoint));

		if (path->nbkey.preference == 0)
			path->nbkey.preference = INITIATED_CANDIDATE_PREFERENCE;

		if (path->nbkey.color == 0)
			path->nbkey.color = INITIATED_POLICY_COLOR;

		candidate = lookup_candidate(&path->nbkey);
		if (!candidate) {
			policy = srte_policy_add(
				path->nbkey.color, &path->nbkey.endpoint,
				SRTE_ORIGIN_PCEP, path->originator);
			strlcpy(policy->name, path->name, sizeof(policy->name));
			policy->binding_sid = path->binding_sid;
			SET_FLAG(policy->flags, F_POLICY_NEW);
			candidate = srte_candidate_add(
				policy, path->nbkey.preference,
				SRTE_ORIGIN_PCEP, path->originator);
			candidate->policy->srp_id = path->srp_id;
			strlcpy(candidate->name, path->name,
				sizeof(candidate->name));
			SET_FLAG(candidate->flags, F_CANDIDATE_NEW);
		} else {
			policy = candidate->policy;
			if ((path->originator != candidate->originator)
			    || (path->originator != policy->originator)) {
				/* There is already an initiated path from
				 * another PCE, show a warning and regect the
				 * initiated path */
				zlog_warn(
					"PCE %s tried to initiate a path already initiated by PCE %s",
					path->originator,
					candidate->originator);
				return 1;
			}
			if ((policy->protocol_origin != SRTE_ORIGIN_PCEP)
			    || (candidate->protocol_origin
				!= SRTE_ORIGIN_PCEP)) {
				/* There is already an initiated path from
				 * another PCE, show a warning and regect the
				 * initiated path */
				zlog_warn(
					"PCE %s tried to initiate a path created localy",
					path->originator);
				return 1;
			}
		}
		return path_pcep_config_update_path(path);
	}
	return 0;
}

int path_pcep_config_update_path(struct path *path)
{
	assert(path != NULL);
	assert(path->nbkey.preference != 0);
	assert(path->nbkey.endpoint.ipa_type == IPADDR_V4);

	int number_of_sid_clashed = 0;
	struct path_hop *hop;
	struct path_metric *metric;
	int index;
	char segment_list_name_buff[64 + 1 + 64 + 1 + 11 + 1];
	char *segment_list_name = NULL;
	struct srte_candidate *candidate;
	struct srte_segment_list *segment_list = NULL;
	struct srte_segment_entry *segment;

	candidate = lookup_candidate(&path->nbkey);

	// if there is no candidate to update we are done
	if (!candidate)
		return 0;

	candidate->policy->srp_id = path->srp_id;
	// first clean up old segment list if present
	if (candidate->lsp->segment_list) {
		SET_FLAG(candidate->lsp->segment_list->flags,
			 F_SEGMENT_LIST_DELETED);
		srte_segment_list_del(candidate->lsp->segment_list);
		candidate->lsp->segment_list = NULL;
	}

	if (path->first_hop == NULL)
		return PATH_NB_ERR;

	snprintf(segment_list_name_buff, sizeof(segment_list_name_buff),
		 "%s-%u", path->name, path->plsp_id);
	segment_list_name = segment_list_name_buff;

	segment_list = srte_segment_list_add(segment_list_name);
	segment_list->protocol_origin = path->update_origin;
	strlcpy(segment_list->originator, path->originator,
		sizeof(segment_list->originator));
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_NEW);
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	for (hop = path->first_hop, index = 10; hop != NULL;
	     hop = hop->next, index += 10) {
		assert(hop->has_sid);
		assert(hop->is_mpls);

		segment = srte_segment_entry_add(segment_list, index);

		segment->sid_value = (mpls_label_t)hop->sid.mpls.label;
		SET_FLAG(segment->segment_list->flags, F_SEGMENT_LIST_MODIFIED);

		if (!hop->has_nai)
			continue;
		if (srte_segment_entry_set_nai(
			    segment, srte_nai_type(hop->nai.type),
			    &hop->nai.local_addr, hop->nai.local_iface,
			    &hop->nai.remote_addr, hop->nai.remote_iface, 0, 0)
		    == PATH_SID_ERROR)
			/* TED queries don't match PCE */
			/* Don't apply srte,zebra changes */
			number_of_sid_clashed++;
	}

	candidate->lsp->segment_list = segment_list;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	for (metric = path->first_metric; metric != NULL; metric = metric->next)
		srte_lsp_set_metric(
			candidate->lsp,
			(enum srte_candidate_metric_type)metric->type,
			metric->value, metric->enforce, metric->is_bound,
			metric->is_computed);

	if (path->has_bandwidth)
		srte_lsp_set_bandwidth(candidate->lsp, path->bandwidth,
				       path->enforce_bandwidth);

	if (path->has_pce_objfun) {
		SET_FLAG(candidate->lsp->flags, F_CANDIDATE_HAS_OBJFUN);
		candidate->lsp->objfun = path->pce_objfun;
	}

	if (number_of_sid_clashed)
		SET_FLAG(segment_list->flags, F_SEGMENT_LIST_SID_CONFLICT);
	else
		srte_apply_changes();

	return 0;
}

struct srte_candidate *lookup_candidate(struct lsp_nb_key *key)
{
	struct srte_policy *policy = NULL;
	policy = srte_policy_find(key->color, &key->endpoint);
	if (policy == NULL)
		return NULL;
	return srte_candidate_find(policy, key->preference);
}

char *candidate_name(struct srte_candidate *candidate)
{
	if (candidate->protocol_origin == SRTE_ORIGIN_PCEP
	    || candidate->protocol_origin == SRTE_ORIGIN_BGP)
		return asprintfrr(MTYPE_PCEP, "%s", candidate->policy->name);
	else
		return asprintfrr(MTYPE_PCEP, "%s-%s", candidate->policy->name,
				  candidate->name);
}

enum pcep_lsp_operational_status
status_int_to_ext(enum srte_policy_status status)
{
	switch (status) {
	case SRTE_POLICY_STATUS_UP:
		return PCEP_LSP_OPERATIONAL_ACTIVE;
	case SRTE_POLICY_STATUS_GOING_UP:
		return PCEP_LSP_OPERATIONAL_GOING_UP;
	case SRTE_POLICY_STATUS_GOING_DOWN:
		return PCEP_LSP_OPERATIONAL_GOING_DOWN;
	default:
		return PCEP_LSP_OPERATIONAL_DOWN;
	}
}

enum pcep_sr_subobj_nai pcep_nai_type(enum srte_segment_nai_type type)
{
	switch (type) {
	case SRTE_SEGMENT_NAI_TYPE_NONE:
		return PCEP_SR_SUBOBJ_NAI_ABSENT;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_NODE:
		return PCEP_SR_SUBOBJ_NAI_IPV4_NODE;
	case SRTE_SEGMENT_NAI_TYPE_IPV6_NODE:
		return PCEP_SR_SUBOBJ_NAI_IPV6_NODE;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY:
		return PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY;
	case SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY:
		return PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY:
		return PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY;
	case SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY_LINK_LOCAL_ADDRESSES:
		return PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_LOCAL_IFACE:
		return PCEP_SR_SUBOBJ_NAI_IPV4_NODE;
	case SRTE_SEGMENT_NAI_TYPE_IPV6_LOCAL_IFACE:
		return PCEP_SR_SUBOBJ_NAI_IPV6_NODE;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_ALGORITHM:
		return PCEP_SR_SUBOBJ_NAI_IPV4_NODE;
	case SRTE_SEGMENT_NAI_TYPE_IPV6_ALGORITHM:
		return PCEP_SR_SUBOBJ_NAI_IPV6_NODE;
	default:
		return PCEP_SR_SUBOBJ_NAI_UNKNOWN;
	}
}

enum srte_segment_nai_type srte_nai_type(enum pcep_sr_subobj_nai type)
{
	switch (type) {
	case PCEP_SR_SUBOBJ_NAI_ABSENT:
		return SRTE_SEGMENT_NAI_TYPE_NONE;
	case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
		return SRTE_SEGMENT_NAI_TYPE_IPV4_NODE;
	case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
		return SRTE_SEGMENT_NAI_TYPE_IPV6_NODE;
	case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
		return SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY;
	case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
		return SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY;
	case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
		return SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY;
	default:
		return SRTE_SEGMENT_NAI_TYPE_NONE;
	}
}
