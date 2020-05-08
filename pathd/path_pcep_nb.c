/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
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

#include <northbound.h>
#include <yang.h>
#include <printfrr.h>
#include <pcep-objects.h>
#include "pathd/pathd.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"

#define MAX_XPATH 256
#define MAX_FLOAT_LEN 22
#define INETADDR4_MAXLEN 16
#define INETADDR6_MAXLEN 40

struct path_nb_list_path_cb_arg {
	void *arg;
	path_list_cb_t cb;
};


static int path_nb_list_path_cb(const struct lyd_node *dnode, void *int_arg);
static struct path_hop *
path_nb_list_path_hops(struct srte_segment_list *segment_list);

static int path_nb_commit_candidate_config(struct nb_config *candidate_config,
					   const char *comment);
static void path_nb_edit_candidate_config(struct nb_config *candidate_config,
					  const char *xpath,
					  enum nb_operation operation,
					  const char *value);
static void path_nb_delete_candidate_segment_list(struct nb_config *config,
						  struct lsp_nb_key *key,
						  const char* originator);
static void path_nb_add_segment_list_segment(struct nb_config *config,
					     const char *segment_list_name,
					     uint32_t index, uint32_t label);
static void
path_nb_add_segment_list_segment_no_nai(struct nb_config *config,
					const char *segment_list_name,
					uint32_t index);
static void path_nb_add_segment_list_segment_nai_ipv4_node(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *ip);
static void path_nb_add_segment_list_segment_nai_ipv6_node(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *ip);
static void path_nb_add_segment_list_segment_nai_ipv4_adj(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *local_ip, struct ipaddr *remote_ip);
static void path_nb_add_segment_list_segment_nai_ipv6_adj(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *local_ip, struct ipaddr *remote_ip);
static void path_nb_add_segment_list_segment_nai_ipv4_unnumbered_adj(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *local_ip, uint32_t local_iface, struct ipaddr *remote_ip,
	uint32_t remote_iface);
static void path_nb_create_segment_list(struct nb_config *config,
					const char *segment_list_name,
					enum srte_protocol_origin protocol,
					const char *originator);
static void path_nb_update_candidate_path(struct nb_config *config,
					  struct lsp_nb_key *key,
					  const char *segment_list_name);
static void
path_nb_add_candidate_path_metric(struct nb_config *config, uint32_t color,
				  struct ipaddr *endpoint, uint32_t preference,
				  enum pcep_metric_types type, float value,
				  bool is_bound, bool is_computed);
static void
path_nb_set_candidate_path_bandwidth(struct nb_config *config,
				     uint32_t color,
				     struct ipaddr *endpoint,
				     uint32_t preference, float value);

static struct srte_candidate* lookup_candidate(struct lsp_nb_key *key);
static char *candidate_name(struct srte_candidate *candidate);
static enum pcep_lsp_operational_status
status_int_to_ext(enum srte_policy_status status);
static const char *metric_name(enum pcep_metric_types type);
static const char *protocol_origin_name(enum srte_protocol_origin origin);
static enum pcep_sr_subobj_nai pcep_nai_type(enum srte_segment_nai_type type);

void path_nb_lookup(struct path *path)
{
	struct srte_candidate *candidate = lookup_candidate(&path->nbkey);
	if (candidate == NULL)
		return;
	if (path->name == NULL)
		path->name = candidate_name(candidate);
	if (path->type == SRTE_CANDIDATE_TYPE_UNDEFINED)
		path->type = candidate->type;
	if (path->create_origin == SRTE_ORIGIN_UNDEFINED)
		path->create_origin = candidate->protocol_origin;
	if ((path->update_origin == SRTE_ORIGIN_UNDEFINED)
	    && (candidate->segment_list != NULL))
		path->update_origin = candidate->segment_list->protocol_origin;
}

struct path *path_nb_get_path(struct lsp_nb_key *key)
{
	struct srte_candidate *candidate = lookup_candidate(key);
	if (candidate == NULL)
		return NULL;
	return candidate_to_path(candidate);
}

void path_nb_list_path(path_list_cb_t cb, void *arg)
{
	struct path_nb_list_path_cb_arg int_arg = {.arg = arg, .cb = cb};
	yang_dnode_iterate(path_nb_list_path_cb, &int_arg,
			   running_config->dnode, "/frr-pathd:pathd/sr-policy");
}

int path_nb_list_path_cb(const struct lyd_node *dnode, void *int_arg)
{
	struct path *path;
	path_list_cb_t cb = ((struct path_nb_list_path_cb_arg *)int_arg)->cb;
	void *ext_arg = ((struct path_nb_list_path_cb_arg *)int_arg)->arg;
	struct srte_policy *policy;
	struct srte_candidate *candidate;

	policy = nb_running_get_entry(dnode, NULL, true);
	RB_FOREACH (candidate, srte_candidate_head, &policy->candidate_paths) {
		path = candidate_to_path(candidate);
		if (!cb(path, ext_arg))
			return 0;
	}

	return 1;
}

struct path *candidate_to_path(struct srte_candidate *candidate)
{
	char *name;
	struct path *path;
	struct path_hop *hop = NULL;
	struct path_metric *metric = NULL;
	struct srte_policy *policy;
	struct srte_segment_list *segment_list, key = {};
	enum pcep_lsp_operational_status status;
	enum srte_protocol_origin update_origin = 0;
	char *originator = NULL;

	policy = candidate->policy;

	if (candidate->segment_list != NULL) {
		strlcpy(key.name, candidate->segment_list->name,
			sizeof(key.name));
		segment_list = RB_FIND(srte_segment_list_head,
				       &srte_segment_lists, &key);
		assert(segment_list != NULL);
		hop = path_nb_list_path_hops(segment_list);
		update_origin = segment_list->protocol_origin;
		originator = XSTRDUP(MTYPE_PCEP, segment_list->originator);
	}
	path = pcep_new_path();
	name = candidate_name(candidate);
	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_BEST)) {
		status = status_int_to_ext(policy->status);
	} else {
		status = PCEP_LSP_OPERATIONAL_DOWN;
	}
	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_METRIC_ABC_RT)) {
		struct path_metric *new_metric = pcep_new_metric();
		new_metric->next = metric;
		metric = new_metric;
		metric->type = PCEP_METRIC_AGGREGATE_BW;
		metric->value = candidate->metric_abc_rt;
		metric->is_bound = CHECK_FLAG(candidate->flags,
					      F_CANDIDATE_METRIC_ABC_BOUND_RT);
		metric->is_computed = CHECK_FLAG(
			candidate->flags, F_CANDIDATE_METRIC_ABC_COMPUTED_RT);
	}
	if (CHECK_FLAG(candidate->flags, F_CANDIDATE_HAS_METRIC_TE_RT)) {
		struct path_metric *new_metric = pcep_new_metric();
		new_metric->next = metric;
		metric = new_metric;
		metric->type = PCEP_METRIC_TE;
		metric->value = candidate->metric_te_rt;
		metric->is_bound = CHECK_FLAG(candidate->flags,
					      F_CANDIDATE_METRIC_TE_BOUND_RT);
		metric->is_computed = CHECK_FLAG(
			candidate->flags, F_CANDIDATE_METRIC_TE_COMPUTED_RT);
	}
	*path = (struct path){
		.nbkey = (struct lsp_nb_key){.color = policy->color,
					     .endpoint = policy->endpoint,
					     .preference =
						     candidate->preference},
		.create_origin = candidate->protocol_origin,
		.update_origin = update_origin,
		.originator = originator,
		.plsp_id = 0,
		.name = name,
		.type = candidate->type,
		.srp_id = 0,
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

	path->has_bandwidth = CHECK_FLAG(candidate->flags,
					 F_CANDIDATE_HAS_BANDWIDTH_RT);
	path->bandwidth = candidate->bandwidth;

	return path;
}

struct path_hop *path_nb_list_path_hops(struct srte_segment_list *segment_list)
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

int path_nb_update_path(struct path *path)
{
	assert(path != NULL);
	assert(path->nbkey.preference != 0);
	assert(path->nbkey.endpoint.ipa_type == IPADDR_V4);

	int ret;
	struct path_hop *hop;
	struct path_metric *metric;
	int index;
	char segment_list_name_buff[64 + 1 + 64 + 1 + 11 + 1];
	char *segment_list_name = NULL;
	struct nb_config *config = nb_config_dup(running_config);

	if (path->first_hop != NULL) {
		path_nb_delete_candidate_segment_list(config, &path->nbkey,
						      path->originator);

		snprintf(segment_list_name_buff, sizeof(segment_list_name_buff),
			 "%s-%u", path->name, path->plsp_id);
		segment_list_name = segment_list_name_buff;
		path_nb_create_segment_list(config, segment_list_name,
					    path->update_origin,
					    path->originator);
		for (hop = path->first_hop, index = 10; hop != NULL;
		     hop = hop->next, index += 10) {
			assert(hop->has_sid);
			assert(hop->is_mpls);
			path_nb_add_segment_list_segment(
				config, segment_list_name, index,
				hop->sid.mpls.label);
			if (hop->has_nai) {
				switch (hop->nai.type) {
				case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
					path_nb_add_segment_list_segment_nai_ipv4_node(
						config, segment_list_name,
						index, &hop->nai.local_addr);
					break;
				case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
					path_nb_add_segment_list_segment_nai_ipv6_node(
						config, segment_list_name,
						index, &hop->nai.local_addr);
					break;
				case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
					path_nb_add_segment_list_segment_nai_ipv4_adj(
						config, segment_list_name,
						index, &hop->nai.local_addr,
						&hop->nai.remote_addr);
					break;
				case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
					path_nb_add_segment_list_segment_nai_ipv6_adj(
						config, segment_list_name,
						index, &hop->nai.local_addr,
						&hop->nai.remote_addr);
					break;
				case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
					path_nb_add_segment_list_segment_nai_ipv4_unnumbered_adj(
						config, segment_list_name,
						index, &hop->nai.local_addr,
						hop->nai.local_iface,
						&hop->nai.remote_addr,
						hop->nai.remote_iface);
					break;
				default:
					path_nb_add_segment_list_segment_no_nai(
						config, segment_list_name,
						index);
					break;
				}
			}
		}
	}

	path_nb_update_candidate_path(
		config, &path->nbkey, segment_list_name);

	for (metric = path->first_metric; metric != NULL;
	     metric = metric->next) {
		path_nb_add_candidate_path_metric(
			config, path->nbkey.color, &path->nbkey.endpoint,
			path->nbkey.preference, metric->type, metric->value,
			metric->is_bound, metric->is_computed);
	}

	if (path->has_bandwidth) {
		path_nb_set_candidate_path_bandwidth(config, path->nbkey.color,
						     &path->nbkey.endpoint,
						     path->nbkey.preference,
						     path->bandwidth);
	}

	ret = path_nb_commit_candidate_config(config, "SR Policy Candidate Path");
	nb_config_free(config);
	return ret;
}

int path_nb_commit_candidate_config(struct nb_config *candidate_config,
				    const char *comment)
{
	struct nb_context context = {};
	char errmsg[BUFSIZ] = {0};

	context.client = NB_CLIENT_PCEP;
	int ret = nb_candidate_commit(&context, candidate_config, false,
				      comment, NULL, errmsg, sizeof(errmsg));
	switch (ret) {
	case NB_OK: return PATH_NB_OK;
	case NB_ERR_NO_CHANGES: return PATH_NB_NO_CHANGE;
	default: return PATH_NB_ERR;
	}
}

void path_nb_edit_candidate_config(struct nb_config *candidate_config,
				   const char *xpath,
				   enum nb_operation operation,
				   const char *value)
{
	struct nb_node *nb_node;
	struct yang_data *data;

	/* Find the northbound node associated to the data path. */
	nb_node = nb_node_find(xpath);

	data = yang_data_new(xpath, value);

	/*
	 * Ignore "not found" errors when editing the candidate
	 * configuration.
	 */
	nb_candidate_edit(candidate_config, nb_node, operation, xpath, NULL,
			  data);

	yang_data_free(data);
}

/* Delete the candidate path segment list if it was created through PCEP
   and by the given originator */
void path_nb_delete_candidate_segment_list(struct nb_config *config,
					   struct lsp_nb_key *key,
					   const char* originator)
{
	struct srte_candidate *candidate = lookup_candidate(key);
	struct srte_segment_list *sl;
	// struct srte_segment_entry *segment, *safe_seg;
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char endpoint_str[INET_ADDRSTRLEN];

	if ((candidate == NULL) || (candidate->segment_list == NULL))
		return;
	sl = candidate->segment_list;

	/* Removing the segment list from the candidate path */
	ipaddr2str(&key->endpoint, endpoint_str, sizeof(endpoint_str));
	snprintf(xpath, sizeof(xpath),
		"/frr-pathd:pathd/sr-policy[color='%u'][endpoint='%s']/candidate-path[preference='%u']/segment-list-name",
		key->color, endpoint_str, key->preference);
	path_nb_edit_candidate_config(config, xpath, NB_OP_DESTROY, NULL);

	/* Checks we can destroy the segment list */
	if (sl->protocol_origin != SRTE_ORIGIN_PCEP) {
		zlog_warn("Prevented from deleting segment list %s because it "
			  "wasn't created through PCEP", sl->name);
		return;
	}
	if (strcmp(originator, sl->originator) != 0) {
		zlog_warn("Prevented from deleting segment list %s because it "
			  "was created by a different originator", sl->name);
		return;
	}

	/* Destroy the segment list */
	snprintf(xpath_base, sizeof(xpath_base),
		 "/frr-pathd:pathd/segment-list[name='%s']", sl->name);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_DESTROY, NULL);

}

void path_nb_add_segment_list_segment(struct nb_config *config,
				      const char *segment_list_name,
				      uint32_t index, uint32_t label)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char label_str[(sizeof(uint32_t) * 8) + 1];

	snprintf(label_str, sizeof(label_str), "%u", label);

	snprintf(xpath_base, sizeof(xpath_base),
		 "/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']",
		 segment_list_name, index);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "%s/sid-value", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, label_str);
}

void path_nb_add_segment_list_segment_no_nai(struct nb_config *config,
					     const char *segment_list_name,
					     uint32_t index)
{
	char xpath[XPATH_MAXLEN];
	snprintf(
		xpath, sizeof(xpath),
		"/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']/nai",
		segment_list_name, index);
	path_nb_edit_candidate_config(config, xpath, NB_OP_DESTROY, NULL);
}

void path_nb_add_segment_list_segment_nai_ipv4_node(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *ip)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char address[INETADDR4_MAXLEN];

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']/nai",
		segment_list_name, index);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);
	snprintf(xpath, sizeof(xpath), "%s/type", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, "ipv4_node");
	snprintf(xpath, sizeof(xpath), "%s/local-address", xpath_base);
	snprintfrr(address, sizeof(address), "%pI4", &ip->ipaddr_v4);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
}

void path_nb_add_segment_list_segment_nai_ipv6_node(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *ip)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char address[INETADDR6_MAXLEN];

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']/nai",
		segment_list_name, index);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);
	snprintf(xpath, sizeof(xpath), "%s/type", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, "ipv6_node");
	snprintf(xpath, sizeof(xpath), "%s/local-address", xpath_base);
	snprintfrr(address, sizeof(address), "%pI6", &ip->ipaddr_v6);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
}

void path_nb_add_segment_list_segment_nai_ipv4_adj(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *local_ip, struct ipaddr *remote_ip)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char address[INETADDR4_MAXLEN];

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']/nai",
		segment_list_name, index);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);
	snprintf(xpath, sizeof(xpath), "%s/type", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      "ipv4_adjacency");
	snprintf(xpath, sizeof(xpath), "%s/local-address", xpath_base);
	snprintfrr(address, sizeof(address), "%pI4", &local_ip->ipaddr_v4);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
	snprintf(xpath, sizeof(xpath), "%s/remote-address", xpath_base);
	snprintfrr(address, sizeof(address), "%pI4", &remote_ip->ipaddr_v4);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
}

void path_nb_add_segment_list_segment_nai_ipv6_adj(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *local_ip, struct ipaddr *remote_ip)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char address[INETADDR6_MAXLEN];

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']/nai",
		segment_list_name, index);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);
	snprintf(xpath, sizeof(xpath), "%s/type", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      "ipv6_adjacency");
	snprintf(xpath, sizeof(xpath), "%s/local-address", xpath_base);
	snprintfrr(address, sizeof(address), "%pI6", &local_ip->ipaddr_v6);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
	snprintf(xpath, sizeof(xpath), "%s/remote-address", xpath_base);
	snprintfrr(address, sizeof(address), "%pI6", &remote_ip->ipaddr_v6);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
}

void path_nb_add_segment_list_segment_nai_ipv4_unnumbered_adj(
	struct nb_config *config, const char *segment_list_name, uint32_t index,
	struct ipaddr *local_ip, uint32_t local_iface, struct ipaddr *remote_ip,
	uint32_t remote_iface)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char address[INETADDR4_MAXLEN];

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/segment-list[name='%s']/segment[index='%u']/nai",
		segment_list_name, index);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);
	snprintf(xpath, sizeof(xpath), "%s/type", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      "ipv4_unnumbered_adjacency");
	snprintf(xpath, sizeof(xpath), "%s/local-address", xpath_base);
	snprintfrr(address, sizeof(address), "%pI4", &local_ip->ipaddr_v4);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
	snprintf(xpath, sizeof(xpath), "%s/local-interface", xpath_base);
	snprintf(address, sizeof(address), "%u", local_iface);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
	snprintf(xpath, sizeof(xpath), "%s/remote-address", xpath_base);
	snprintfrr(address, sizeof(address), "%pI4", &remote_ip->ipaddr_v4);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
	snprintf(xpath, sizeof(xpath), "%s/remote-interface", xpath_base);
	snprintf(address, sizeof(address), "%u", remote_iface);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, address);
}

void path_nb_create_segment_list(struct nb_config *config,
				 const char *segment_list_name,
				 enum srte_protocol_origin protocol,
				 const char *originator)
{
	char xpath_base[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];

	snprintf(xpath_base, sizeof(xpath_base),
		 "/frr-pathd:pathd/segment-list[name='%s']", segment_list_name);
	path_nb_edit_candidate_config(config, xpath_base, NB_OP_CREATE, NULL);
	snprintf(xpath, sizeof(xpath), "%s/protocol-origin", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      protocol_origin_name(protocol));
	snprintf(xpath, sizeof(xpath), "%s/originator", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, originator);
}

void path_nb_update_candidate_path(struct nb_config *config,
				   struct lsp_nb_key *key,
				   const char *segment_list_name)
{
	char xpath[XPATH_MAXLEN];
	char xpath_base[XPATH_MAXLEN];
	char endpoint_str[INET_ADDRSTRLEN];

	ipaddr2str(&key->endpoint, endpoint_str, sizeof(endpoint_str));

	snprintf(
		xpath_base, sizeof(xpath_base),
		"/frr-pathd:pathd/sr-policy[color='%u'][endpoint='%s']/candidate-path[preference='%u']",
		key->color, endpoint_str, key->preference);

	snprintf(xpath, sizeof(xpath), "%s/segment-list-name", xpath_base);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      segment_list_name);
}

void path_nb_add_candidate_path_metric(struct nb_config *config, uint32_t color,
				       struct ipaddr *endpoint,
				       uint32_t preference,
				       enum pcep_metric_types type, float value,
				       bool is_bound, bool is_computed)
{
	char base_xpath[XPATH_MAXLEN];
	char xpath[XPATH_MAXLEN];
	char endpoint_str[INET_ADDRSTRLEN];
	char value_str[MAX_FLOAT_LEN];
	const char *name;

	ipaddr2str(endpoint, endpoint_str, sizeof(endpoint_str));

	name = metric_name(type);
	if (NULL == name)
		return;

	snprintf(
		base_xpath, sizeof(base_xpath),
		"/frr-pathd:pathd/sr-policy[color='%u'][endpoint='%s']/candidate-path[preference='%u']/metrics[type='%s']",
		color, endpoint_str, preference, name);
	snprintf(xpath, sizeof(xpath), "%s/value", base_xpath);
	snprintf(value_str, sizeof(value_str), "%.6f", value);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, value_str);
	snprintf(xpath, sizeof(xpath), "%s/is-bound", base_xpath);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      is_bound ? "true" : "false");
	snprintf(xpath, sizeof(xpath), "%s/is-computed", base_xpath);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY,
				      is_computed ? "true" : "false");
}

void path_nb_set_candidate_path_bandwidth(struct nb_config *config,
					  uint32_t color,
					  struct ipaddr *endpoint,
					  uint32_t preference, float value)
{
	char xpath[XPATH_MAXLEN];
	char endpoint_str[INET_ADDRSTRLEN];
	char value_str[MAX_FLOAT_LEN];

	ipaddr2str(endpoint, endpoint_str, sizeof(endpoint_str));

	snprintf(
		xpath, sizeof(xpath),
		"/frr-pathd:pathd/sr-policy[color='%u'][endpoint='%s']/candidate-path[preference='%u']/bandwidth",
		color, endpoint_str, preference);
	snprintf(value_str, sizeof(value_str), "%.6f", value);
	path_nb_edit_candidate_config(config, xpath, NB_OP_MODIFY, value_str);
}

struct srte_candidate* lookup_candidate(struct lsp_nb_key *key)
{
	struct srte_policy *policy = NULL;
	policy = srte_policy_find(key->color, &key->endpoint);
	if (policy == NULL)
		return NULL;
	return srte_candidate_find(policy, key->preference);
}

char *candidate_name(struct srte_candidate *candidate)
{
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

const char *metric_name(enum pcep_metric_types type)
{
	switch (type) {
	case PCEP_METRIC_IGP:
		return "igp";
	case PCEP_METRIC_TE:
		return "te";
	case PCEP_METRIC_HOP_COUNT:
		return "hc";
	case PCEP_METRIC_AGGREGATE_BW:
		return "abc";
	default:
		return "unknown";
	}
}

const char *protocol_origin_name(enum srte_protocol_origin origin)
{
	switch (origin) {
	case SRTE_ORIGIN_PCEP:
		return "pcep";
	case SRTE_ORIGIN_BGP:
		return "bgp";
	case SRTE_ORIGIN_LOCAL:
		return "local";
	default:
		return "unknown";
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
	default:
		return PCEP_SR_SUBOBJ_NAI_UNKNOWN;
	}
}
