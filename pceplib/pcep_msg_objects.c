// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * This is the implementation of a High Level PCEP message object API.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <unistd.h>

#include "pcep_msg_objects.h"
#include "pcep_msg_tlvs.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

/* Internal common function used to create a pcep_object and populate the header
 */
static struct pcep_object_header *pcep_obj_create_common_with_tlvs(
	uint8_t obj_length, enum pcep_object_classes object_class,
	enum pcep_object_types object_type, double_linked_list *tlv_list)
{
	uint8_t *buffer = pceplib_malloc(PCEPLIB_MESSAGES, obj_length);
	memset(buffer, 0, obj_length);

	/* The flag_p and flag_i flags will be set externally */
	struct pcep_object_header *hdr = (struct pcep_object_header *)buffer;
	hdr->object_class = object_class;
	hdr->object_type = object_type;
	hdr->tlv_list = tlv_list;

	return hdr;
}

static struct pcep_object_header *
pcep_obj_create_common(uint8_t obj_length,
		       enum pcep_object_classes object_class,
		       enum pcep_object_types object_type)
{
	return pcep_obj_create_common_with_tlvs(obj_length, object_class,
						object_type, NULL);
}

struct pcep_object_open *pcep_obj_create_open(uint8_t keepalive,
					      uint8_t deadtimer, uint8_t sid,
					      double_linked_list *tlv_list)
{
	struct pcep_object_open *open =
		(struct pcep_object_open *)pcep_obj_create_common_with_tlvs(
			sizeof(struct pcep_object_open), PCEP_OBJ_CLASS_OPEN,
			PCEP_OBJ_TYPE_OPEN, tlv_list);

	open->open_version =
		PCEP_OBJECT_OPEN_VERSION; /* PCEP version. Current version is 1
					     /No flags are currently defined. */
	open->open_keepalive =
		keepalive; /* Maximum period of time between two consecutive
			      PCEP messages sent by the sender. */
	open->open_deadtimer = deadtimer; /* Specifies the amount of time before
					     closing the session down. */
	open->open_sid = sid; /* PCEP session number that identifies the current
				 session. */

	return open;
}

struct pcep_object_rp *pcep_obj_create_rp(uint8_t priority, bool flag_r,
					  bool flag_b, bool flag_s,
					  bool flag_of, uint32_t reqid,
					  double_linked_list *tlv_list)
{
	if (priority > OBJECT_RP_MAX_PRIORITY) {
		pcep_log(
			LOG_INFO,
			"%s: Error creating RP object, invalid priority [%d], max priority [%d].",
			__func__, priority, OBJECT_RP_MAX_PRIORITY);
		return NULL;
	}

	struct pcep_object_rp *obj =
		(struct pcep_object_rp *)pcep_obj_create_common_with_tlvs(
			sizeof(struct pcep_object_rp), PCEP_OBJ_CLASS_RP,
			PCEP_OBJ_TYPE_RP, tlv_list);

	obj->priority = priority;
	obj->flag_reoptimization = flag_r;
	obj->flag_bidirectional = flag_b;
	obj->flag_strict = flag_s;
	obj->flag_of = flag_of;
	obj->request_id = reqid;

	return obj;
}

struct pcep_object_notify *
pcep_obj_create_notify(enum pcep_notification_types notification_type,
		       enum pcep_notification_values notification_value)
{
	struct pcep_object_notify *obj =
		(struct pcep_object_notify *)pcep_obj_create_common(
			sizeof(struct pcep_object_notify), PCEP_OBJ_CLASS_NOTF,
			PCEP_OBJ_TYPE_NOTF);

	obj->notification_type = notification_type;
	obj->notification_value = notification_value;

	return obj;
}

struct pcep_object_nopath *
pcep_obj_create_nopath(uint8_t ni, bool flag_c,
		       enum pcep_nopath_tlv_err_codes error_code)
{
	struct pcep_object_tlv_nopath_vector *tlv =
		pcep_tlv_create_nopath_vector(error_code);
	double_linked_list *tlv_list = dll_initialize();
	dll_append(tlv_list, tlv);

	struct pcep_object_nopath *obj =
		(struct pcep_object_nopath *)pcep_obj_create_common_with_tlvs(
			sizeof(struct pcep_object_nopath),
			PCEP_OBJ_CLASS_NOPATH, PCEP_OBJ_TYPE_NOPATH, tlv_list);

	obj->ni = ni;
	obj->flag_c = flag_c;
	obj->err_code = error_code;

	return obj;
}

struct pcep_object_association_ipv4 *
pcep_obj_create_association_ipv4(bool r_flag, uint16_t association_type,
				 uint16_t association_id, struct in_addr src)
{
	struct pcep_object_association_ipv4 *obj =
		(struct pcep_object_association_ipv4 *)pcep_obj_create_common(
			sizeof(struct pcep_object_association_ipv4),
			PCEP_OBJ_CLASS_ASSOCIATION,
			PCEP_OBJ_TYPE_ASSOCIATION_IPV4);

	obj->R_flag = r_flag;
	obj->association_type = association_type;
	obj->association_id = association_id;
	obj->src = src;

	return obj;
}
struct pcep_object_association_ipv6 *
pcep_obj_create_association_ipv6(bool r_flag, uint16_t association_type,
				 uint16_t association_id, struct in6_addr src)
{
	struct pcep_object_association_ipv6 *obj =
		(struct pcep_object_association_ipv6 *)pcep_obj_create_common(
			sizeof(struct pcep_object_association_ipv6),
			PCEP_OBJ_CLASS_ASSOCIATION,
			PCEP_OBJ_TYPE_ASSOCIATION_IPV6);

	obj->R_flag = r_flag;
	obj->association_type = association_type;
	obj->association_id = association_id;
	obj->src = src;

	return obj;
}
struct pcep_object_endpoints_ipv4 *
pcep_obj_create_endpoint_ipv4(const struct in_addr *src_ipv4,
			      const struct in_addr *dst_ipv4)
{
	if (src_ipv4 == NULL || dst_ipv4 == NULL) {
		return NULL;
	}

	struct pcep_object_endpoints_ipv4 *obj =
		(struct pcep_object_endpoints_ipv4 *)pcep_obj_create_common(
			sizeof(struct pcep_object_endpoints_ipv4),
			PCEP_OBJ_CLASS_ENDPOINTS, PCEP_OBJ_TYPE_ENDPOINT_IPV4);

	obj->src_ipv4.s_addr = src_ipv4->s_addr;
	obj->dst_ipv4.s_addr = dst_ipv4->s_addr;

	return obj;
}

struct pcep_object_endpoints_ipv6 *
pcep_obj_create_endpoint_ipv6(const struct in6_addr *src_ipv6,
			      const struct in6_addr *dst_ipv6)
{
	if (src_ipv6 == NULL || dst_ipv6 == NULL) {
		return NULL;
	}

	struct pcep_object_endpoints_ipv6 *obj =
		(struct pcep_object_endpoints_ipv6 *)pcep_obj_create_common(
			sizeof(struct pcep_object_endpoints_ipv6),
			PCEP_OBJ_CLASS_ENDPOINTS, PCEP_OBJ_TYPE_ENDPOINT_IPV6);

	memcpy(&obj->src_ipv6, src_ipv6, sizeof(struct in6_addr));
	memcpy(&obj->dst_ipv6, dst_ipv6, sizeof(struct in6_addr));

	return obj;
}

struct pcep_object_bandwidth *pcep_obj_create_bandwidth(float bandwidth)
{
	struct pcep_object_bandwidth *obj =
		(struct pcep_object_bandwidth *)pcep_obj_create_common(
			sizeof(struct pcep_object_bandwidth),
			PCEP_OBJ_CLASS_BANDWIDTH, PCEP_OBJ_TYPE_BANDWIDTH_REQ);

	obj->bandwidth = bandwidth;

	return obj;
}

struct pcep_object_metric *pcep_obj_create_metric(enum pcep_metric_types type,
						  bool flag_b, bool flag_c,
						  float value)
{
	struct pcep_object_metric *obj =
		(struct pcep_object_metric *)pcep_obj_create_common(
			sizeof(struct pcep_object_metric),
			PCEP_OBJ_CLASS_METRIC, PCEP_OBJ_TYPE_METRIC);

	obj->flag_b = flag_b;
	obj->flag_c = flag_c;
	obj->type = type;
	obj->value = value;

	return obj;
}

struct pcep_object_lspa *
pcep_obj_create_lspa(uint32_t exclude_any, uint32_t include_any,
		     uint32_t include_all, uint8_t setup_priority,
		     uint8_t holding_priority, bool flag_local_protection)
{
	struct pcep_object_lspa *obj =
		(struct pcep_object_lspa *)pcep_obj_create_common(
			sizeof(struct pcep_object_lspa), PCEP_OBJ_CLASS_LSPA,
			PCEP_OBJ_TYPE_LSPA);

	obj->lspa_exclude_any = exclude_any;
	obj->lspa_include_any = include_any;
	obj->lspa_include_all = include_all;
	obj->setup_priority = setup_priority;
	obj->holding_priority = holding_priority;
	obj->flag_local_protection = flag_local_protection;

	return obj;
}

struct pcep_object_svec *
pcep_obj_create_svec(bool srlg, bool node, bool link,
		     double_linked_list *request_id_list)
{
	if (request_id_list == NULL) {
		return NULL;
	}

	struct pcep_object_svec *obj =
		(struct pcep_object_svec *)pcep_obj_create_common(
			sizeof(struct pcep_object_svec), PCEP_OBJ_CLASS_SVEC,
			PCEP_OBJ_TYPE_SVEC);

	obj->flag_srlg_diverse = srlg;
	obj->flag_node_diverse = node;
	obj->flag_link_diverse = link;
	obj->request_id_list = request_id_list;

	return obj;
}

struct pcep_object_error *
pcep_obj_create_error(enum pcep_error_type error_type,
		      enum pcep_error_value error_value)
{
	struct pcep_object_error *obj =
		(struct pcep_object_error *)pcep_obj_create_common(
			sizeof(struct pcep_object_error), PCEP_OBJ_CLASS_ERROR,
			PCEP_OBJ_TYPE_ERROR);

	obj->error_type = error_type;
	obj->error_value = error_value;

	return obj;
}

struct pcep_object_close *pcep_obj_create_close(enum pcep_close_reason reason)
{
	struct pcep_object_close *obj =
		(struct pcep_object_close *)pcep_obj_create_common(
			sizeof(struct pcep_object_close), PCEP_OBJ_CLASS_CLOSE,
			PCEP_OBJ_TYPE_CLOSE);

	obj->reason = reason;

	return obj;
}

struct pcep_object_srp *pcep_obj_create_srp(bool lsp_remove,
					    uint32_t srp_id_number,
					    double_linked_list *tlv_list)
{
	struct pcep_object_srp *obj =
		(struct pcep_object_srp *)pcep_obj_create_common_with_tlvs(
			sizeof(struct pcep_object_srp), PCEP_OBJ_CLASS_SRP,
			PCEP_OBJ_TYPE_SRP, tlv_list);

	obj->flag_lsp_remove = lsp_remove;
	obj->srp_id_number = srp_id_number;

	return obj;
}

struct pcep_object_lsp *
pcep_obj_create_lsp(uint32_t plsp_id, enum pcep_lsp_operational_status status,
		    bool c_flag, bool a_flag, bool r_flag, bool s_flag,
		    bool d_flag, double_linked_list *tlv_list)
{
	/* The plsp_id is only 20 bits */
	if (plsp_id > MAX_PLSP_ID) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_obj_create_lsp invalid plsp_id [%d] max value [%d]",
			__func__, plsp_id, MAX_PLSP_ID);
		return NULL;
	}

	/* The status is only 3 bits */
	if (status > MAX_LSP_STATUS) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_obj_create_lsp invalid status [%d] max value [%d]",
			__func__, plsp_id, MAX_PLSP_ID);
		return NULL;
	}

	struct pcep_object_lsp *obj =
		(struct pcep_object_lsp *)pcep_obj_create_common_with_tlvs(
			sizeof(struct pcep_object_lsp), PCEP_OBJ_CLASS_LSP,
			PCEP_OBJ_TYPE_LSP, tlv_list);

	obj->plsp_id = plsp_id;
	obj->operational_status = status;
	obj->flag_c = c_flag;
	obj->flag_a = a_flag;
	obj->flag_r = r_flag;
	obj->flag_s = s_flag;
	obj->flag_d = d_flag;

	return obj;
}

struct pcep_object_vendor_info *
pcep_obj_create_vendor_info(uint32_t enterprise_number,
			    uint32_t enterprise_spec_info)
{
	struct pcep_object_vendor_info *obj =
		(struct pcep_object_vendor_info *)pcep_obj_create_common(
			sizeof(struct pcep_object_vendor_info),
			PCEP_OBJ_CLASS_VENDOR_INFO, PCEP_OBJ_TYPE_VENDOR_INFO);

	obj->enterprise_number = enterprise_number;
	obj->enterprise_specific_info = enterprise_spec_info;

	return obj;
}

struct pcep_object_inter_layer *
pcep_obj_create_inter_layer(bool flag_i, bool flag_m, bool flag_t)
{
	struct pcep_object_inter_layer *obj =
		(struct pcep_object_inter_layer *)pcep_obj_create_common(
			sizeof(struct pcep_object_inter_layer),
			PCEP_OBJ_CLASS_INTER_LAYER, PCEP_OBJ_TYPE_INTER_LAYER);

	obj->flag_i = flag_i;
	obj->flag_m = flag_m;
	obj->flag_t = flag_t;

	return obj;
}

struct pcep_object_switch_layer *
pcep_obj_create_switch_layer(double_linked_list *switch_layer_rows)
{
	struct pcep_object_switch_layer *obj =
		(struct pcep_object_switch_layer *)pcep_obj_create_common(
			sizeof(struct pcep_object_switch_layer),
			PCEP_OBJ_CLASS_SWITCH_LAYER,
			PCEP_OBJ_TYPE_SWITCH_LAYER);

	obj->switch_layer_rows = switch_layer_rows;

	return obj;
}

struct pcep_object_req_adap_cap *
pcep_obj_create_req_adap_cap(enum pcep_switching_capability sw_cap,
			     enum pcep_lsp_encoding_type encoding)
{
	struct pcep_object_req_adap_cap *obj =
		(struct pcep_object_req_adap_cap *)pcep_obj_create_common(
			sizeof(struct pcep_object_req_adap_cap),
			PCEP_OBJ_CLASS_REQ_ADAP_CAP,
			PCEP_OBJ_TYPE_REQ_ADAP_CAP);

	obj->switching_capability = sw_cap;
	obj->encoding = encoding;

	return obj;
}

struct pcep_object_server_indication *
pcep_obj_create_server_indication(enum pcep_switching_capability sw_cap,
				  enum pcep_lsp_encoding_type encoding,
				  double_linked_list *tlv_list)
{
	struct pcep_object_server_indication *obj =
		(struct pcep_object_server_indication *)
			pcep_obj_create_common_with_tlvs(
				sizeof(struct pcep_object_server_indication),
				PCEP_OBJ_CLASS_SERVER_IND,
				PCEP_OBJ_TYPE_SERVER_IND, tlv_list);

	obj->switching_capability = sw_cap;
	obj->encoding = encoding;

	return obj;
}

struct pcep_object_objective_function *
pcep_obj_create_objective_function(uint16_t of_code,
				   double_linked_list *tlv_list)
{
	struct pcep_object_objective_function *obj =
		(struct pcep_object_objective_function *)
			pcep_obj_create_common_with_tlvs(
				sizeof(struct pcep_object_objective_function),
				PCEP_OBJ_CLASS_OF, PCEP_OBJ_TYPE_OF, tlv_list);

	obj->of_code = of_code;

	return obj;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_ro *pcep_obj_create_ero(double_linked_list *ero_list)
{
	struct pcep_object_ro *ero =
		(struct pcep_object_ro *)pcep_obj_create_common(
			sizeof(struct pcep_object_ro), PCEP_OBJ_CLASS_ERO,
			PCEP_OBJ_TYPE_ERO);
	ero->sub_objects = ero_list;

	return ero;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_ro *pcep_obj_create_iro(double_linked_list *iro_list)
{
	struct pcep_object_ro *iro =
		(struct pcep_object_ro *)pcep_obj_create_common(
			sizeof(struct pcep_object_ro), PCEP_OBJ_CLASS_IRO,
			PCEP_OBJ_TYPE_IRO);
	iro->sub_objects = iro_list;

	return iro;
}

/* Wrap a list of ro subobjects in a structure with an object header */
struct pcep_object_ro *pcep_obj_create_rro(double_linked_list *rro_list)
{
	struct pcep_object_ro *rro =
		(struct pcep_object_ro *)pcep_obj_create_common(
			sizeof(struct pcep_object_ro), PCEP_OBJ_CLASS_RRO,
			PCEP_OBJ_TYPE_RRO);
	rro->sub_objects = rro_list;

	return rro;
}

/*
 * Route Object Sub-object creation functions
 */

static struct pcep_object_ro_subobj *
pcep_obj_create_ro_subobj_common(uint8_t subobj_size,
				 enum pcep_ro_subobj_types ro_subobj_type,
				 bool flag_subobj_loose_hop)
{
	struct pcep_object_ro_subobj *ro_subobj =
		pceplib_malloc(PCEPLIB_MESSAGES, subobj_size);
	memset(ro_subobj, 0, subobj_size);
	ro_subobj->flag_subobj_loose_hop = flag_subobj_loose_hop;
	ro_subobj->ro_subobj_type = ro_subobj_type;

	return ro_subobj;
}

struct pcep_ro_subobj_ipv4 *
pcep_obj_create_ro_subobj_ipv4(bool loose_hop, const struct in_addr *rro_ipv4,
			       uint8_t prefix_length, bool flag_local_prot)
{
	if (rro_ipv4 == NULL) {
		return NULL;
	}

	struct pcep_ro_subobj_ipv4 *obj =
		(struct pcep_ro_subobj_ipv4 *)pcep_obj_create_ro_subobj_common(
			sizeof(struct pcep_ro_subobj_ipv4), RO_SUBOBJ_TYPE_IPV4,
			loose_hop);
	obj->ip_addr.s_addr = rro_ipv4->s_addr;
	obj->prefix_length = prefix_length;
	obj->flag_local_protection = flag_local_prot;

	return obj;
}

struct pcep_ro_subobj_ipv6 *
pcep_obj_create_ro_subobj_ipv6(bool loose_hop, const struct in6_addr *rro_ipv6,
			       uint8_t prefix_length, bool flag_local_prot)
{
	if (rro_ipv6 == NULL) {
		return NULL;
	}

	struct pcep_ro_subobj_ipv6 *obj =
		(struct pcep_ro_subobj_ipv6 *)pcep_obj_create_ro_subobj_common(
			sizeof(struct pcep_ro_subobj_ipv6), RO_SUBOBJ_TYPE_IPV6,
			loose_hop);
	obj->prefix_length = prefix_length;
	obj->flag_local_protection = flag_local_prot;
	memcpy(&obj->ip_addr, rro_ipv6, sizeof(struct in6_addr));

	return obj;
}

struct pcep_ro_subobj_unnum *
pcep_obj_create_ro_subobj_unnum(struct in_addr *router_id, uint32_t if_id)
{
	if (router_id == NULL) {
		return NULL;
	}

	struct pcep_ro_subobj_unnum *obj =
		(struct pcep_ro_subobj_unnum *)pcep_obj_create_ro_subobj_common(
			sizeof(struct pcep_ro_subobj_unnum),
			RO_SUBOBJ_TYPE_UNNUM, false);
	obj->interface_id = if_id;
	obj->router_id.s_addr = router_id->s_addr;

	return obj;
}

struct pcep_ro_subobj_32label *
pcep_obj_create_ro_subobj_32label(bool flag_global_label, uint8_t class_type,
				  uint32_t label)
{
	struct pcep_ro_subobj_32label *obj = (struct pcep_ro_subobj_32label *)
		pcep_obj_create_ro_subobj_common(
			sizeof(struct pcep_ro_subobj_32label),
			RO_SUBOBJ_TYPE_LABEL, false);
	obj->class_type = class_type;
	obj->flag_global_label = flag_global_label;
	obj->label = label;

	return obj;
}

struct pcep_ro_subobj_asn *pcep_obj_create_ro_subobj_asn(uint16_t asn)
{
	struct pcep_ro_subobj_asn *obj =
		(struct pcep_ro_subobj_asn *)pcep_obj_create_ro_subobj_common(
			sizeof(struct pcep_ro_subobj_asn), RO_SUBOBJ_TYPE_ASN,
			false);
	obj->asn = asn;

	return obj;
}

/* Internal util function to create pcep_ro_subobj_sr sub-objects */
static struct pcep_ro_subobj_sr *
pcep_obj_create_ro_subobj_sr_common(enum pcep_sr_subobj_nai nai_type,
				    bool loose_hop, bool f_flag, bool s_flag,
				    bool c_flag_in, bool m_flag_in)
{
	struct pcep_ro_subobj_sr *obj =
		(struct pcep_ro_subobj_sr *)pcep_obj_create_ro_subobj_common(
			sizeof(struct pcep_ro_subobj_sr), RO_SUBOBJ_TYPE_SR,
			loose_hop);

	/* Flag logic according to draft-ietf-pce-segment-routing-16 */
	bool c_flag = c_flag_in;
	bool m_flag = m_flag_in;
	if (s_flag) {
		c_flag = false;
		m_flag = false;
	}

	if (m_flag == false) {
		c_flag = false;
	}

	obj->nai_type = nai_type;
	obj->flag_f = f_flag;
	obj->flag_s = s_flag;
	obj->flag_c = c_flag;
	obj->flag_m = m_flag;

	return obj;
}

struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_nonai(bool loose_hop,
							     uint32_t sid,
							     bool c_flag,
							     bool m_flag)
{
	/* According to draft-ietf-pce-segment-routing-16#section-5.2.1
	 * If NT=0, the F bit MUST be 1, the S bit MUST be zero and the
	 * Length MUST be 8. */
	struct pcep_ro_subobj_sr *obj = pcep_obj_create_ro_subobj_sr_common(
		PCEP_SR_SUBOBJ_NAI_ABSENT, loose_hop, true, false, c_flag,
		m_flag);
	obj->sid = sid;

	return obj;
}

struct pcep_ro_subobj_sr *
pcep_obj_create_ro_subobj_sr_ipv4_node(bool loose_hop, bool sid_absent,
				       bool c_flag, bool m_flag, uint32_t sid,
				       struct in_addr *ipv4_node_id)
{
	if (ipv4_node_id == NULL) {
		return NULL;
	}

	/* According to draft-ietf-pce-segment-routing-16#section-5.2.1
	 * If NT=1, the F bit MUST be zero.  If the S bit is 1, the Length
	 * MUST be 8, otherwise the Length MUST be 12 */
	struct pcep_ro_subobj_sr *obj = pcep_obj_create_ro_subobj_sr_common(
		PCEP_SR_SUBOBJ_NAI_IPV4_NODE, loose_hop, false, sid_absent,
		c_flag, m_flag);

	if (!sid_absent) {
		obj->sid = sid;
	}
	obj->nai_list = dll_initialize();
	/* Since the IP has to be stored in the list, copy it so the caller
	 * doesn't have any restrictions about the type of memory used
	 * externally for the IP. This memory will be freed with the object is
	 * freed. */
	struct in_addr *ipv4_node_id_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct in_addr));
	ipv4_node_id_copy->s_addr = ipv4_node_id->s_addr;
	dll_append(obj->nai_list, ipv4_node_id_copy);

	return obj;
}

struct pcep_ro_subobj_sr *
pcep_obj_create_ro_subobj_sr_ipv6_node(bool loose_hop, bool sid_absent,
				       bool c_flag, bool m_flag, uint32_t sid,
				       struct in6_addr *ipv6_node_id)
{
	if (ipv6_node_id == NULL) {
		return NULL;
	}

	/* According to draft-ietf-pce-segment-routing-16#section-5.2.1
	 * If NT=2, the F bit MUST be zero.  If the S bit is 1, the Length
	 * MUST be 20, otherwise the Length MUST be 24. */
	struct pcep_ro_subobj_sr *obj = pcep_obj_create_ro_subobj_sr_common(
		PCEP_SR_SUBOBJ_NAI_IPV6_NODE, loose_hop, false, sid_absent,
		c_flag, m_flag);

	if (!sid_absent) {
		obj->sid = sid;
	}
	obj->nai_list = dll_initialize();
	struct in6_addr *ipv6_node_id_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct in6_addr));
	memcpy(ipv6_node_id_copy, ipv6_node_id, sizeof(struct in6_addr));
	dll_append(obj->nai_list, ipv6_node_id_copy);

	return obj;
}

struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_ipv4_adj(
	bool loose_hop, bool sid_absent, bool c_flag, bool m_flag, uint32_t sid,
	struct in_addr *local_ipv4, struct in_addr *remote_ipv4)
{
	if (local_ipv4 == NULL || remote_ipv4 == NULL) {
		return NULL;
	}

	/* According to draft-ietf-pce-segment-routing-16#section-5.2.1
	 * If NT=3, the F bit MUST be zero.  If the S bit is 1, the Length
	 * MUST be 12, otherwise the Length MUST be 16 */
	struct pcep_ro_subobj_sr *obj = pcep_obj_create_ro_subobj_sr_common(
		PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY, loose_hop, false, sid_absent,
		c_flag, m_flag);

	if (!sid_absent) {
		obj->sid = sid;
	}
	obj->nai_list = dll_initialize();
	struct in_addr *local_ipv4_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct in_addr));
	struct in_addr *remote_ipv4_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct in_addr));
	local_ipv4_copy->s_addr = local_ipv4->s_addr;
	remote_ipv4_copy->s_addr = remote_ipv4->s_addr;
	dll_append(obj->nai_list, local_ipv4_copy);
	dll_append(obj->nai_list, remote_ipv4_copy);

	return obj;
}

struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_ipv6_adj(
	bool loose_hop, bool sid_absent, bool c_flag, bool m_flag, uint32_t sid,
	struct in6_addr *local_ipv6, struct in6_addr *remote_ipv6)
{
	if (local_ipv6 == NULL || remote_ipv6 == NULL) {
		return NULL;
	}

	/* According to draft-ietf-pce-segment-routing-16#section-5.2.1
	 * If NT=4, the F bit MUST be zero.  If the S bit is 1, the Length
	 * MUST be 36, otherwise the Length MUST be 40 */
	struct pcep_ro_subobj_sr *obj = pcep_obj_create_ro_subobj_sr_common(
		PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY, loose_hop, false, sid_absent,
		c_flag, m_flag);

	if (!sid_absent) {
		obj->sid = sid;
	}
	obj->nai_list = dll_initialize();
	struct in6_addr *local_ipv6_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct in6_addr));
	struct in6_addr *remote_ipv6_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct in6_addr));
	memcpy(local_ipv6_copy, local_ipv6, sizeof(struct in6_addr));
	memcpy(remote_ipv6_copy, remote_ipv6, sizeof(struct in6_addr));
	dll_append(obj->nai_list, local_ipv6_copy);
	dll_append(obj->nai_list, remote_ipv6_copy);

	return obj;
}

struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
	bool loose_hop, bool sid_absent, bool c_flag, bool m_flag, uint32_t sid,
	uint32_t local_node_id, uint32_t local_if_id, uint32_t remote_node_id,
	uint32_t remote_if_id)
{
	/* According to draft-ietf-pce-segment-routing-16#section-5.2.1
	 * If NT=5, the F bit MUST be zero.  If the S bit is 1, the Length
	 * MUST be 20, otherwise the Length MUST be 24. */
	struct pcep_ro_subobj_sr *obj = pcep_obj_create_ro_subobj_sr_common(
		PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY, loose_hop, false,
		sid_absent, c_flag, m_flag);

	if (!sid_absent) {
		obj->sid = sid;
	}

	obj->nai_list = dll_initialize();
	uint32_t *local_node_id_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
	*local_node_id_copy = local_node_id;
	dll_append(obj->nai_list, local_node_id_copy);

	uint32_t *local_if_id_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
	*local_if_id_copy = local_if_id;
	dll_append(obj->nai_list, local_if_id_copy);

	uint32_t *remote_node_id_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
	*remote_node_id_copy = remote_node_id;
	dll_append(obj->nai_list, remote_node_id_copy);

	uint32_t *remote_if_id_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
	*remote_if_id_copy = remote_if_id;
	dll_append(obj->nai_list, remote_if_id_copy);

	return obj;
}

struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
	bool loose_hop, bool sid_absent, bool c_flag, bool m_flag, uint32_t sid,
	struct in6_addr *local_ipv6, uint32_t local_if_id,
	struct in6_addr *remote_ipv6, uint32_t remote_if_id)
{
	if (local_ipv6 == NULL || remote_ipv6 == NULL) {
		return NULL;
	}

	/* According to draft-ietf-pce-segment-routing-16#section-5.2.1
	 * If NT=6, the F bit MUST be zero.  If the S bit is 1, the Length
	 * MUST be 44, otherwise the Length MUST be 48 */
	struct pcep_ro_subobj_sr *obj = pcep_obj_create_ro_subobj_sr_common(
		PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY, loose_hop, false,
		sid_absent, c_flag, m_flag);

	if (!sid_absent) {
		obj->sid = sid;
	}
	obj->nai_list = dll_initialize();
	struct in6_addr *local_ipv6_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct in6_addr));
	memcpy(local_ipv6_copy, local_ipv6, sizeof(struct in6_addr));
	dll_append(obj->nai_list, local_ipv6_copy);

	uint32_t *local_if_id_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
	*local_if_id_copy = local_if_id;
	dll_append(obj->nai_list, local_if_id_copy);

	struct in6_addr *remote_ipv6_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct in6_addr));
	memcpy(remote_ipv6_copy, remote_ipv6, sizeof(struct in6_addr));
	dll_append(obj->nai_list, remote_ipv6_copy);

	uint32_t *remote_if_id_copy =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
	*remote_if_id_copy = remote_if_id;
	dll_append(obj->nai_list, remote_if_id_copy);

	return obj;
}
