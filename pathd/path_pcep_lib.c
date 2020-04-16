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

#include <debug.h>
#include <pcep_utils_counters.h>
#include "pathd/path_errors.h"
#include "pathd/path_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_debug.h"

#define CLASS_TYPE(CLASS, TYPE) (((CLASS) << 16) | (TYPE))

/* pceplib logging callback */
static int pceplib_logging_cb(int level, const char *fmt, va_list args);

/* Internal functions */
static double_linked_list *pcep_lib_format_path(struct path *path);
static void pcep_lib_parse_open(struct pcep_caps *caps,
				struct pcep_object_open *open);
static void pcep_lib_parse_rp(struct path *path, struct pcep_object_rp *rp);
static void pcep_lib_parse_srp(struct path *path, struct pcep_object_srp *srp);
static void pcep_lib_parse_lsp(struct path *path, struct pcep_object_lsp *lsp);
static void pcep_lib_parse_ero(struct path *path, struct pcep_object_ro *ero);
static struct path_hop *pcep_lib_parse_ero_sr(struct path_hop *next,
					      struct pcep_ro_subobj_sr *sr);
static struct counters_group *copy_counter_group(struct counters_group *from);
static struct counters_subgroup *
copy_counter_subgroup(struct counters_subgroup *from);
static struct counter *copy_counter(struct counter *from);
static void free_counter_group(struct counters_group *group);
static void free_counter_subgroup(struct counters_subgroup *subgroup);
static void free_counter(struct counter *counter);


/* ------------ API Functions ------------ */

int pcep_lib_initialize(void)
{
	PCEP_DEBUG("Initializing pceplib");
	if (!initialize_pcc()) {
		flog_err(EC_PATH_PCEP_PCC_INIT, "failed to initialize pceplib");
		return 1;
	}

	/* Register pceplib logging callback */
	register_logger(pceplib_logging_cb);
	return 0;
}

void pcep_lib_finalize(void)
{
	PCEP_DEBUG("Finalizing pceplib");
	if (!destroy_pcc()) {
		flog_err(EC_PATH_PCEP_PCC_FINI, "failed to finalize pceplib");
	}
}


pcep_session *pcep_lib_connect(struct pcc_opts *pcc_opts,
			       struct pce_opts *pce_opts)
{
	assert(NULL != pcc_opts);
	assert(NULL != pce_opts);

	pcep_configuration *config;
	pcep_session *sess;

	config = create_default_pcep_configuration();
	config->dst_pcep_port = pce_opts->port;
	config->src_pcep_port = pcc_opts->port;
	if (IS_IPADDR_V6(&pcc_opts->addr)) {
		config->is_src_ipv6 = true;
		memcpy(&config->src_ip.src_ipv6, &pcc_opts->addr.ipaddr_v6,
		       sizeof(struct in6_addr));
	} else {
		config->is_src_ipv6 = false;
		config->src_ip.src_ipv4 = pcc_opts->addr.ipaddr_v4;
	}

	config->support_stateful_pce_lsp_update = !pcc_opts->force_stateless;
	config->support_pce_lsp_instantiation = false;
	config->support_include_db_version = false;
	config->support_lsp_triggered_resync = false;
	config->support_lsp_delta_sync = false;
	config->support_pce_triggered_initial_sync = false;
	config->support_sr_te_pst = true;
	config->pcc_can_resolve_nai_to_sid = false;

	config->pcep_msg_versioning->draft_ietf_pce_segment_routing_07 =
		pce_opts->draft07;

	if (IS_IPADDR_V6(&pce_opts->addr)) {
		sess = connect_pce_ipv6(config, &pce_opts->addr.ipaddr_v6);
	} else {
		sess = connect_pce(config, &pce_opts->addr.ipaddr_v4);
	}
	destroy_pcep_configuration(config);
	return sess;
}

void pcep_lib_disconnect(pcep_session *sess)
{
	assert(NULL != sess);
	disconnect_pce(sess);
}

struct pcep_message *pcep_lib_format_report(struct path *path)
{
	double_linked_list *objs = pcep_lib_format_path(path);
	return pcep_msg_create_report(objs);
}

struct pcep_message *pcep_lib_format_request(uint32_t reqid, struct ipaddr *src,
					     struct ipaddr *dst)
{
	assert(src->ipa_type == dst->ipa_type);

	double_linked_list *rp_tlvs;
	struct pcep_object_tlv_path_setup_type *setup_type_tlv;
	struct pcep_object_rp *rp;
	struct pcep_object_endpoints_ipv4 *endpoints_ipv4;
	struct pcep_object_endpoints_ipv6 *endpoints_ipv6;

	rp_tlvs = dll_initialize();
	setup_type_tlv = pcep_tlv_create_path_setup_type(SR_TE_PST);
	dll_append(rp_tlvs, setup_type_tlv);

	rp = pcep_obj_create_rp(0, false, false, false, reqid, rp_tlvs);
	if (IS_IPADDR_V6(src)) {
		endpoints_ipv6 = pcep_obj_create_endpoint_ipv6(&src->ipaddr_v6,
							       &dst->ipaddr_v6);
		return pcep_msg_create_request_ipv6(rp, endpoints_ipv6, NULL);
	} else {
		endpoints_ipv4 = pcep_obj_create_endpoint_ipv4(&src->ipaddr_v4,
							       &dst->ipaddr_v4);
		return pcep_msg_create_request(rp, endpoints_ipv4, NULL);
	}
}

struct path *pcep_lib_parse_path(struct pcep_message *msg)
{
	struct path *path;
	double_linked_list *objs = msg->obj_list;
	double_linked_list_node *node;

	struct pcep_object_header *obj;
	struct pcep_object_rp *rp = NULL;
	struct pcep_object_srp *srp = NULL;
	struct pcep_object_lsp *lsp = NULL;
	struct pcep_object_ro *ero = NULL;

	path = pcep_new_path();

	for (node = objs->head; node != NULL; node = node->next_node) {
		obj = (struct pcep_object_header *)node->data;
		switch (CLASS_TYPE(obj->object_class, obj->object_type)) {
		case CLASS_TYPE(PCEP_OBJ_CLASS_RP, PCEP_OBJ_TYPE_RP):
			assert(NULL == rp);
			rp = (struct pcep_object_rp *)obj;
			pcep_lib_parse_rp(path, rp);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP):
			assert(NULL == srp);
			srp = (struct pcep_object_srp *)obj;
			pcep_lib_parse_srp(path, srp);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP):
			/* Only support single LSP per message */
			assert(NULL == lsp);
			lsp = (struct pcep_object_lsp *)obj;
			pcep_lib_parse_lsp(path, lsp);
			break;
		case CLASS_TYPE(PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO):
			/* Only support single ERO per message */
			assert(NULL == ero);
			ero = (struct pcep_object_ro *)obj;
			pcep_lib_parse_ero(path, ero);
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_OBJECT,
				  "Unexpected PCEP object %s (%u) / %s (%u)",
				  pcep_object_class_name(obj->object_class),
				  obj->object_class,
				  pcep_object_type_name(obj->object_class,
							obj->object_type),
				  obj->object_type);
			break;
		}
	}

	return path;
}

void pcep_lib_parse_capabilities(struct pcep_message *msg,
				 struct pcep_caps *caps)
{
	double_linked_list *objs = msg->obj_list;
	double_linked_list_node *node;

	struct pcep_object_header *obj;
	struct pcep_object_open *open = NULL;

	for (node = objs->head; node != NULL; node = node->next_node) {
		obj = (struct pcep_object_header *)node->data;
		switch (CLASS_TYPE(obj->object_class, obj->object_type)) {
		case CLASS_TYPE(PCEP_OBJ_CLASS_OPEN, PCEP_OBJ_TYPE_OPEN):
			assert(NULL == open);
			open = (struct pcep_object_open *)obj;
			pcep_lib_parse_open(caps, open);
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_OBJECT,
				  "Unexpected PCEP object %s (%u) / %s (%u)",
				  pcep_object_class_name(obj->object_class),
				  obj->object_class,
				  pcep_object_type_name(obj->object_class,
							obj->object_type),
				  obj->object_type);
			break;
		}
	}
}

struct counters_group *pcep_lib_copy_counters(pcep_session *sess)
{
	if( !sess || !sess->pcep_session_counters) {
		return NULL;
	}

	return copy_counter_group(sess->pcep_session_counters);
}

void pcep_lib_free_counters(struct counters_group *counters)
{
	free_counter_group(counters);
}


/* ------------ pceplib logging callback ------------ */

int pceplib_logging_cb(int priority, const char *fmt, va_list args)
{
	char buffer[1024];
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	PCEP_DEBUG_PCEPLIB(priority, "pceplib: %s", buffer);
	return 0;
}


/* ------------ Internal Functions ------------ */

double_linked_list *pcep_lib_format_path(struct path *path)
{
	struct in_addr addr_null;
	double_linked_list *objs, *srp_tlvs, *lsp_tlvs, *ero_objs;
	struct pcep_object_tlv_header *tlv;
	struct pcep_object_ro_subobj *ero_obj;
	struct pcep_object_srp *srp;
	struct pcep_object_lsp *lsp;
	struct pcep_object_ro *ero;

	memset(&addr_null, 0, sizeof(addr_null));

	objs = dll_initialize();

	/* SRP object */
	srp_tlvs = dll_initialize();
	tlv = (struct pcep_object_tlv_header *)pcep_tlv_create_path_setup_type(
		SR_TE_PST);
	assert(NULL != tlv);
	dll_append(srp_tlvs, tlv);
	srp = pcep_obj_create_srp(path->do_remove, path->srp_id, srp_tlvs);
	assert(NULL != srp);
	dll_append(objs, srp);
	/* LSP object */
	lsp_tlvs = dll_initialize();
	if (NULL != path->name) {
		tlv = (struct pcep_object_tlv_header *)
			pcep_tlv_create_symbolic_path_name(path->name,
							   strlen(path->name));
		dll_append(lsp_tlvs, tlv);
	}
	tlv = (struct pcep_object_tlv_header *)
		pcep_tlv_create_ipv4_lsp_identifiers(&addr_null, &addr_null, 0,
						     0, &addr_null);
	assert(NULL != tlv);
	dll_append(lsp_tlvs, tlv);
	lsp = pcep_obj_create_lsp(
		path->plsp_id, path->status, path->was_created /* C Flag */,
		path->go_active /* A Flag */, path->was_removed /* R Flag */,
		path->is_synching /* S Flag */, path->is_delegated /* D Flag */,
		lsp_tlvs);
	assert(NULL != lsp);
	dll_append(objs, lsp);
	/*   ERO object */
	ero_objs = dll_initialize();
	for (struct path_hop *hop = path->first; NULL != hop; hop = hop->next) {
		uint32_t sid;

		/* Only supporting MPLS hops with both sid and nai */
		assert(hop->is_mpls);
		assert(hop->has_sid);

		if (hop->has_attribs) {
			sid = ENCODE_SR_ERO_SID(hop->sid.mpls.label,
						hop->sid.mpls.traffic_class,
						hop->sid.mpls.is_bottom,
						hop->sid.mpls.ttl);
		} else {
			sid = ENCODE_SR_ERO_SID(hop->sid.mpls.label, 0, 0, 0);
		}

		if (hop->has_nai) {
			/* Only supporting IPv4 nodes */
			assert(PCEP_SR_SUBOBJ_NAI_IPV4_NODE == hop->nai_type);
			ero_obj = (struct pcep_object_ro_subobj *)
				pcep_obj_create_ro_subobj_sr_ipv4_node(
					hop->is_loose, !hop->has_sid,
					hop->has_attribs, /* C Flag */
					hop->is_mpls,	  /* M Flag */
					sid, &hop->nai.ipv4_node.addr);
		} else {
			ero_obj = (struct pcep_object_ro_subobj *)
				pcep_obj_create_ro_subobj_sr_nonai(
					hop->is_loose, sid,
					hop->has_attribs, /* C Flag */
					hop->is_mpls);	  /* M Flag */
		}
		assert(NULL != ero_obj);
		dll_append(ero_objs, ero_obj);
	}
	ero = pcep_obj_create_ero(ero_objs);
	assert(NULL != ero);
	dll_append(objs, ero);

	return objs;
}

void pcep_lib_parse_open(struct pcep_caps *caps, struct pcep_object_open *open)
{
	double_linked_list *tlvs = open->header.tlv_list;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv_header;
	struct pcep_object_tlv_stateful_pce_capability *tlv;

	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv_header = (struct pcep_object_tlv_header *)node->data;
		switch (tlv_header->type) {
		case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
			tlv = (struct pcep_object_tlv_stateful_pce_capability *)
				tlv_header;
			caps->is_stateful = tlv->flag_u_lsp_update_capability;
			break;
		case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
				  "Unexpected OPEN's TLV %s (%u)",
				  pcep_tlv_type_name(tlv_header->type),
				  tlv_header->type);
			break;
		}
	}
}

void pcep_lib_parse_rp(struct path *path, struct pcep_object_rp *rp)
{
	double_linked_list *tlvs = rp->header.tlv_list;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	/* We ignore flags and priority for now */
	path->req_id = rp->request_id;

	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *)node->data;
		switch (tlv->type) {
		case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
			// TODO: enforce the path setup type is SR_TE_PST
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
				  "Unexpected RP's TLV %s (%u)",
				  pcep_tlv_type_name(tlv->type), tlv->type);
			break;
		}
	}
}

void pcep_lib_parse_srp(struct path *path, struct pcep_object_srp *srp)
{
	double_linked_list *tlvs = srp->header.tlv_list;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	path->do_remove = srp->flag_lsp_remove;
	path->srp_id = srp->srp_id_number;

	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *)node->data;
		switch (tlv->type) {
		case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
			// TODO: enforce the path setup type is SR_TE_PST
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
				  "Unexpected SRP's TLV %s (%u)",
				  pcep_tlv_type_name(tlv->type), tlv->type);
			break;
		}
	}
}

void pcep_lib_parse_lsp(struct path *path, struct pcep_object_lsp *lsp)
{
	double_linked_list *tlvs = lsp->header.tlv_list;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	path->plsp_id = lsp->plsp_id;
	path->status = lsp->operational_status;
	path->go_active = lsp->flag_a;
	path->was_created = lsp->flag_c;
	path->was_removed = lsp->flag_r;
	path->is_synching = lsp->flag_a;
	path->is_delegated = lsp->flag_d;

	if (NULL == tlvs)
		return;

	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *)node->data;
		switch (tlv->type) {
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_TLV,
				  "Unexpected LSP TLV %s (%u)",
				  pcep_tlv_type_name(tlv->type), tlv->type);
			break;
		}
	}
}

void pcep_lib_parse_ero(struct path *path, struct pcep_object_ro *ero)
{
	struct path_hop *hop = NULL;
	double_linked_list *objs = ero->sub_objects;
	double_linked_list_node *node;
	struct pcep_object_ro_subobj *obj;

	for (node = objs->tail; node != NULL; node = node->prev_node) {
		obj = (struct pcep_object_ro_subobj *)node->data;
		switch (obj->ro_subobj_type) {
		case RO_SUBOBJ_TYPE_SR_DRAFT07:
		case RO_SUBOBJ_TYPE_SR:
			hop = pcep_lib_parse_ero_sr(
				hop, (struct pcep_ro_subobj_sr *)obj);
			break;
		default:
			flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_ERO_SUBOBJ,
				  "Unexpected ERO sub-object %s (%u)",
				  pcep_ro_type_name(obj->ro_subobj_type),
				  obj->ro_subobj_type);
			break;
		}
	}

	path->first = hop;
}

struct path_hop *pcep_lib_parse_ero_sr(struct path_hop *next,
				       struct pcep_ro_subobj_sr *sr)
{
	struct path_hop *hop = NULL;

	/* Only support IPv4 node with SID */
	assert(!sr->flag_s);

	hop = pcep_new_hop();
	*hop = (struct path_hop){
		.next = next,
		.is_loose = sr->ro_subobj.flag_subobj_loose_hop,
		.has_sid = !sr->flag_s,
		.is_mpls = sr->flag_m,
		.has_attribs = sr->flag_c,
		.sid = {.mpls = {.label = GET_SR_ERO_SID_LABEL(sr->sid),
				 .traffic_class = GET_SR_ERO_SID_TC(sr->sid),
				 .is_bottom = GET_SR_ERO_SID_S(sr->sid),
				 .ttl = GET_SR_ERO_SID_TTL(sr->sid)}},
		.has_nai = !sr->flag_f,
		.nai_type = sr->nai_type};

	if (!sr->flag_f) {
		/* Only support IPv4 node with IPv4 NAI */
		assert(PCEP_SR_SUBOBJ_NAI_IPV4_NODE == sr->nai_type);
		assert(NULL != sr->nai_list);
		assert(NULL != sr->nai_list->head);
		assert(NULL != sr->nai_list->head->data);
		struct in_addr *addr =
			(struct in_addr *)sr->nai_list->head->data;
		hop->nai = (union nai){
			.ipv4_node = {.addr = {.s_addr = addr->s_addr}}};
	}

	return hop;
}

struct counters_group *copy_counter_group(struct counters_group *from)
{
	int size, i;
	struct counters_group *result;
	if (NULL == from)
		return NULL;
	assert(from->max_subgroups >= from->num_subgroups);
	result = XCALLOC(MTYPE_PCEP, sizeof(*result));
	memcpy(result, from, sizeof(*result));
	size = sizeof(struct counters_subgroup *) * from->max_subgroups;
	result->subgroups = XCALLOC(MTYPE_PCEP, size);
	for (i = 0; i <= from->num_subgroups; i++)
		result->subgroups[i] =
			copy_counter_subgroup(from->subgroups[i]);
	return result;
}

struct counters_subgroup *copy_counter_subgroup(struct counters_subgroup *from)
{
	int size, i;
	struct counters_subgroup *result;
	if (NULL == from)
		return NULL;
	assert(from->max_counters >= from->num_counters);
	result = XCALLOC(MTYPE_PCEP, sizeof(*result));
	memcpy(result, from, sizeof(*result));
	size = sizeof(struct counter *) * from->max_counters;
	result->counters = XCALLOC(MTYPE_PCEP, size);
	for (i = 0; i <= from->num_counters; i++)
		result->counters[i] = copy_counter(from->counters[i]);
	return result;
}

struct counter *copy_counter(struct counter *from)
{
	struct counter *result;
	if (NULL == from)
		return NULL;
	result = XCALLOC(MTYPE_PCEP, sizeof(*result));
	memcpy(result, from, sizeof(*result));
	return result;
}

void free_counter_group(struct counters_group *group)
{
	int i;
	if (NULL == group)
		return;
	for (i = 0; i <= group->num_subgroups; i++)
		free_counter_subgroup(group->subgroups[i]);
	XFREE(MTYPE_PCEP, group);
}

void free_counter_subgroup(struct counters_subgroup *subgroup)
{
	int i;
	if (NULL == subgroup)
		return;
	for (i = 0; i <= subgroup->num_counters; i++)
		free_counter(subgroup->counters[i]);
	XFREE(MTYPE_PCEP, subgroup);
}

void free_counter(struct counter *counter)
{
	if (NULL == counter)
		return;
	XFREE(MTYPE_PCEP, counter);
}
