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
#include "pathd/path_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_debug.h"

static void pcep_lib_parse_srp(path_t *path, struct pcep_object_srp* srp);
static void pcep_lib_parse_lsp(path_t *path, struct pcep_object_lsp* lsp);
static void pcep_lib_parse_ero(path_t *path, struct pcep_object_ro* ero);
static path_hop_t *pcep_lib_parse_ero_sr(path_hop_t *next,
					 struct pcep_ro_subobj_sr *sr);

int pcep_lib_connect(pcc_state_t *pcc_state)
{
	assert(NULL != pcc_state);
	assert(NULL != pcc_state->pcc_opts);
	assert(NULL != pcc_state->pce_opts);
	assert(NULL == pcc_state->config);
	assert(NULL == pcc_state->sess);

	pcep_configuration *config;
	pcep_session *sess;

	config = create_default_pcep_configuration();
	config->support_stateful_pce_lsp_update = true;
	config->support_sr_te_pst = true;
	config->use_pcep_sr_draft07 = true;
	config->dst_pcep_port = pcc_state->pce_opts->port;
	config->src_pcep_port = pcc_state->pcc_opts->port;
	config->src_ip = pcc_state->pcc_opts->addr;
	//TODO: Figure out if we want that for now
	config->support_include_db_version = false;
	config->support_pce_lsp_instantiation = false;
	config->support_lsp_triggered_resync = false;
	config->support_lsp_delta_sync = false;
	config->support_pce_triggered_initial_sync = false;

	sess = connect_pce(config, &pcc_state->pce_opts->addr);

	if (NULL == sess) return 1;

	pcc_state->config = config;
	pcc_state->sess = sess;

	return 0;
}

void pcep_lib_disconnect(pcc_state_t *pcc_state)
{
	assert(NULL != pcc_state);
	assert(NULL != pcc_state->config);
	assert(NULL != pcc_state->sess);

	disconnect_pce(pcc_state->sess);

	free(pcc_state->config);
	pcc_state->config = NULL;
	pcc_state->sess = NULL;
}

double_linked_list *pcep_lib_format_path(path_t *path)
{
	struct in_addr addr_null;
	double_linked_list *objs, *srp_tlvs, *lsp_tlvs, *ero_objs;
	struct pcep_object_tlv *tlv;
	struct pcep_object_ro_subobj *ero_obj;
	struct pcep_object_srp* srp;
	struct pcep_object_lsp* lsp;
	struct pcep_object_ro* ero;

	memset(&addr_null, 0, sizeof(addr_null));

	objs = dll_initialize();

	/* SRP object */
	srp_tlvs = dll_initialize();
	tlv = pcep_tlv_create_path_setup_type(SR_TE_PST);
	dll_append(srp_tlvs, tlv);
	srp = pcep_obj_create_srp(path->do_remove, path->srp_id, srp_tlvs);
	assert(NULL != srp);
	dll_append(objs, srp);
	dll_destroy_with_data(srp_tlvs);
	/* LSP object */
	lsp_tlvs = dll_initialize();
	if (NULL != path->name) {
		tlv = pcep_tlv_create_symbolic_path_name(path->name,
							 strlen(path->name));
		dll_append(lsp_tlvs, tlv);
	}
	tlv = pcep_tlv_create_ipv4_lsp_identifiers(&addr_null, &addr_null, 0, 0, 0);
	assert(NULL != tlv);
	dll_append(lsp_tlvs, tlv);
	lsp = pcep_obj_create_lsp(path->plsp_id,
				  path->status,
				  path->was_created   /* C Flag */,
				  path->go_active     /* A Flag */,
				  path->was_removed   /* R Flag */,
				  path->is_synching   /* S Flag */,
				  path->is_delegated  /* D Flag */,
				  lsp_tlvs);
	assert(NULL != lsp);
	dll_append(objs, lsp);
	dll_destroy_with_data(lsp_tlvs);
	/*   ERO object */
	ero_objs = dll_initialize();
	for (path_hop_t *hop = path->first; NULL != hop; hop = hop->next) {
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

			ero_obj = pcep_obj_create_ro_subobj_sr_ipv4_node(
					hop->is_loose,
					!hop->has_sid,
					hop->has_attribs,
					hop->is_mpls,
					sid,
					&hop->nai.ipv4_node.addr,
					true);
		} else {
			ero_obj = pcep_obj_create_ro_subobj_sr_nonai(
					hop->is_loose, sid, true);
		}
		/* ODL only supports Draft 07 that has a different type */
		ero_obj->subobj.sr.header.type = RO_SUBOBJ_TYPE_SR_DRAFT07;
		assert(NULL != ero_obj);
		dll_append(ero_objs, ero_obj);
	}
	ero = pcep_obj_create_ero(ero_objs);
	assert(NULL != ero);
	dll_append(objs, ero);
	dll_destroy_with_data(ero_objs);

	return objs;
}

path_t *pcep_lib_parse_path(double_linked_list *objs)
{
	path_t *path;
	double_linked_list_node *node;

	struct pcep_object_header *obj;
	struct pcep_object_srp* srp = NULL;
	struct pcep_object_lsp* lsp = NULL;
	struct pcep_object_ro* ero = NULL;

	path = XCALLOC(MTYPE_PCEP, sizeof(*path));

	for (node = objs->head; node != NULL; node = node->next_node) {
		obj = (struct pcep_object_header *) node->data;
		switch (CLASS_TYPE(obj->object_class, obj->object_type)) {
			case CLASS_TYPE(PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP):
				assert(NULL == srp);
				srp = (struct pcep_object_srp*) obj;
				pcep_lib_parse_srp(path, srp);
				break;
			case CLASS_TYPE(PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP):
				/* Only support single LSP per message */
				assert(NULL == lsp);
				lsp = (struct pcep_object_lsp*) obj;
				pcep_lib_parse_lsp(path, lsp);
				break;
			case CLASS_TYPE(PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO):
				/* Only support single ERO per message */
				assert(NULL == ero);
				ero = (struct pcep_object_ro*) obj;
				pcep_lib_parse_ero(path, ero);
				break;
			default:
				PCEP_DEBUG("Unexpected PCEP object %s (%u) / %s (%u)",
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

void pcep_lib_parse_srp(path_t *path, struct pcep_object_srp* srp)
{
	double_linked_list *tlvs;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	path->do_remove = srp->lsp_remove;
	path->srp_id = srp->srp_id_number;

	tlvs = pcep_obj_get_tlvs(&srp->header);
	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *) node->data;
		switch (tlv->type) {
			case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
				//TODO: enforce the path setup type is SR_TE_PST
				break;
			default:
				PCEP_DEBUG("Unexpected SRP's TLV %s (%u)",
					pcep_tlv_type_name(tlv->type),
					tlv->type);
				break;

		}
	}

	dll_destroy(tlvs);
}

void pcep_lib_parse_lsp(path_t *path, struct pcep_object_lsp* lsp)
{
	double_linked_list *tlvs;
	double_linked_list_node *node;
	struct pcep_object_tlv_header *tlv;

	path->plsp_id = GET_LSP_PCEPID(lsp);
	path->status = lsp->plsp_id_flags & MAX_LSP_STATUS;
	path->go_active = (lsp->plsp_id_flags & PCEP_LSP_A_FLAG) != 0;
	path->was_created = (lsp->plsp_id_flags & PCEP_LSP_C_FLAG) != 0;
	path->was_removed = (lsp->plsp_id_flags & PCEP_LSP_R_FLAG) != 0;
	path->is_synching = (lsp->plsp_id_flags & PCEP_LSP_S_FLAG) != 0;
	path->is_delegated = (lsp->plsp_id_flags & PCEP_LSP_D_FLAG) != 0;

	tlvs = pcep_obj_get_tlvs(&lsp->header);
	for (node = tlvs->head; node != NULL; node = node->next_node) {
		tlv = (struct pcep_object_tlv_header *) node->data;
		switch (tlv->type) {
			default:
				PCEP_DEBUG("Unexpected LSP TLV %s (%u)",
					pcep_tlv_type_name(tlv->type),
					tlv->type);
				break;

		}
	}

	dll_destroy(tlvs);
}

void pcep_lib_parse_ero(path_t *path, struct pcep_object_ro* ero)
{
	path_hop_t *hop = NULL;
	double_linked_list *objs;
	double_linked_list_node *node;
	struct pcep_ro_subobj_hdr *obj;

	objs = pcep_obj_get_ro_subobjects(&ero->header);
	for (node = objs->tail; node != NULL; node = node->prev_node) {
		obj = (struct pcep_ro_subobj_hdr *) node->data;
		switch (GET_RO_SUBOBJ_TYPE(obj)) {
			case RO_SUBOBJ_TYPE_SR_DRAFT07:
			case RO_SUBOBJ_TYPE_SR:
				hop = pcep_lib_parse_ero_sr(hop,
					(struct pcep_ro_subobj_sr *) obj);
				break;
			default:
				PCEP_DEBUG("Unexpected ERO sub-object %s (%u)",
					pcep_ro_type_name(obj->type),
					obj->type);
				break;

		}
	}

	path->first = hop;

	dll_destroy(objs);
}

path_hop_t *pcep_lib_parse_ero_sr(path_hop_t *next,
				  struct pcep_ro_subobj_sr *sr)
{
	path_hop_t *hop = NULL;
	uint16_t flags;
	bool has_nai;
	enum pcep_sr_subobj_nai nai_type = PCEP_SR_SUBOBJ_NAI_ABSENT;
	nai_t nai;


	hop = XCALLOC(MTYPE_PCEP, sizeof(*hop));
	flags = GET_SR_SUBOBJ_FLAGS(sr);

	/* Only support IPv4 node with SID */
	assert((flags & PCEP_SR_SUBOBJ_S_FLAG) == 0);

	memset(&nai, 0, sizeof(nai));
	has_nai = (flags & PCEP_SR_SUBOBJ_F_FLAG) == 0;
	if (has_nai) {
		/* Only support IPv4 node with IPv4 NAI */
		nai_type = GET_SR_SUBOBJ_NT(sr);
		assert(PCEP_SR_SUBOBJ_NAI_IPV4_NODE == nai_type);
		nai = (nai_t) {.ipv4_node = {.addr = {
				.s_addr = sr->sid_nai[1]}}};
	}

	*hop = (path_hop_t) {.next = next,
			     .is_loose = GET_RO_SUBOBJ_LFLAG(&sr->header),
			     .has_sid = (flags & PCEP_SR_SUBOBJ_S_FLAG) == 0,
			     .is_mpls = (flags & PCEP_SR_SUBOBJ_M_FLAG) != 0,
			     .has_attribs = (flags & PCEP_SR_SUBOBJ_C_FLAG) != 0,
			     .sid = {.mpls = {
				.label = GET_SR_ERO_SID_LABEL(sr->sid_nai[0]),
				.traffic_class = GET_SR_ERO_SID_TC(sr->sid_nai[0]),
				.is_bottom = GET_SR_ERO_SID_S(sr->sid_nai[0]),
				.ttl = GET_SR_ERO_SID_TTL(sr->sid_nai[0])}},
			     .has_nai = has_nai,
			     .nai_type = nai_type,
			     .nai = nai};

	return hop;
}

void pcep_lib_free_path(path_t *path)
{
	path_hop_t *hop;

	hop = path->first;
	while (NULL != hop) {
		path_hop_t *next = hop->next;
		XFREE(MTYPE_PCEP, hop);
		hop = next;
	}
	if (NULL != path->name) {
		XFREE(MTYPE_PCEP, path->name);
	}
	XFREE(MTYPE_PCEP, path);
}
