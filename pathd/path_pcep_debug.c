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

#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <libyang/libyang.h>

#include "printfrr.h"
#include "ipaddr.h"

#include "pathd/path_pcep_debug.h"

#ifdef __GNUC__
#define THREAD_DATA __thread
#else
#define THREAD_DATA
#endif

#define DEBUG_IDENT_SIZE 4
#define DEBUG_BUFF_SIZE 4096
#define TUP(A, B) ((((uint32_t)(A)) << 16) | ((uint32_t)(B)))
#define PCEP_FORMAT_INIT() _debug_buff[0] = 0
#define PCEP_FORMAT(fmt, ...) csnprintfrr(_debug_buff, DEBUG_BUFF_SIZE, fmt, ##__VA_ARGS__)
#define PCEP_FORMAT_FINI() _debug_buff
THREAD_DATA char _debug_buff[DEBUG_BUFF_SIZE];

static void _format_pcc_opts(int ps, pcc_opts_t *ops);
static void _format_pcc_state(int ps, pcc_state_t *state);
static void _format_ctrl_state(int ps, ctrl_state_t *state);
static void _format_path(int ps, path_t *path);
static void _format_path_hop(int ps, path_hop_t *hop);
static void _format_pcep_event(int ps, pcep_event *event);
static void _format_pcep_message(int ps, pcep_message *msg);
static void _format_pcep_objects(int ps, double_linked_list *objs);
static void _format_pcep_object(int ps, struct pcep_object_header *obj);
static void _format_pcep_object_details(int ps, struct pcep_object_header *obj);
static void _format_pcep_object_error(int ps, struct pcep_object_error *obj);
static void _format_pcep_object_open(int ps, struct pcep_object_open *obj);
static void _format_pcep_object_srp(int ps, struct pcep_object_srp *obj);
static void _format_pcep_object_lsp(int psps, struct pcep_object_lsp *obj);
static void _format_pcep_object_ipv4_endpoint(int ps,
		struct pcep_object_endpoints_ipv4* obj);
static void _format_pcep_object_ro(int ps, struct pcep_object_header *obj);
static void _format_pcep_object_ro_details(int ps,
		struct pcep_ro_subobj_hdr *ro);
static void _format_pcep_object_ro_ipv4(int ps,
		struct pcep_ro_subobj_ipv4 *obj);
static void _format_pcep_object_ro_sr(int ps, struct pcep_ro_subobj_sr *obj);
static void _format_pcep_object_tlvs(int ps,
		struct pcep_object_header *obj, size_t size);
static void _format_pcep_object_tlv(int ps, struct pcep_object_tlv *tlv);
static void _format_pcep_object_tlv_details(int ps,
		struct pcep_object_tlv *tlv);

const char *pcc_status_name(pcc_status_t status)
{
	switch (status) {
		case INITIALIZED: return "INITIALIZED";
		case DISCONNECTED: return "DISCONNECTED";
		case CONNECTING: return "CONNECTING";
		case SYNCHRONIZING: return "SYNCHRONIZING";
		case OPERATING: return "OPERATING";
		default: return "UNKNOWN";
	}
}

const char *pcep_event_type_name(pcep_event_type event_type)
{
	switch (event_type) {
		case MESSAGE_RECEIVED:
			return "MESSAGE_RECEIVED";
		case PCE_CLOSED_SOCKET:
			return "PCE_CLOSED_SOCKET";
		case PCE_SENT_PCEP_CLOSE:
			return "PCE_SENT_PCEP_CLOSE";
		case PCE_DEAD_TIMER_EXPIRED:
			return "PCE_DEAD_TIMER_EXPIRED";
		case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
			return "PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED";
		case PCC_CONNECTED_TO_PCE:
			return "PCC_CONNECTED_TO_PCE";
		case PCC_PCEP_SESSION_CLOSED:
			return "PCC_PCEP_SESSION_CLOSED";
		case PCC_RCVD_INVALID_OPEN:
			return "PCC_RCVD_INVALID_OPEN";
		case PCC_RCVD_MAX_INVALID_MSGS:
			return "PCC_RCVD_MAX_INVALID_MSGS";
		case PCC_RCVD_MAX_UNKOWN_MSGS:
			return "PCC_RCVD_MAX_UNKOWN_MSGS";
		default:
			return "UNKNOWN";
	}
}

const char *pcep_error_type_name(enum pcep_error_type error_type)
{
	switch (error_type) {
		case PCEP_ERRT_SESSION_FAILURE:
			return "SESSION_FAILURE";
		case PCEP_ERRT_CAPABILITY_NOT_SUPPORTED:
			return "CAPABILITY_NOT_SUPPORTED";
		case PCEP_ERRT_UNKNOW_OBJECT:
			return "UNKNOW_OBJECT";
		case PCEP_ERRT_NOT_SUPPORTED_OBJECT:
			return "NOT_SUPPORTED_OBJECT";
		case PCEP_ERRT_POLICY_VIOLATION:
			return "POLICY_VIOLATION";
		case PCEP_ERRT_MANDATORY_OBJECT_MISSING:
			return "MANDATORY_OBJECT_MISSING";
		case PCEP_ERRT_SYNC_PC_REQ_MISSING:
			return "SYNC_PC_REQ_MISSING";
		case PCEP_ERRT_UNKNOWN_REQ_REF:
			return "UNKNOWN_REQ_REF";
		case PCEP_ERRT_ATTEMPT_TO_ESTABLISH_2ND_PCEP_SESSION:
			return "ATTEMPT_TO_ESTABLISH_2ND_PCEP_SESSION";
		case PCEP_ERRT_RECEPTION_OF_INV_OBJECT:
			return "RECEPTION_OF_INV_OBJECT";
		default:
			return "UNKNOWN";
	}
}

const char *pcep_error_value_name(enum pcep_error_type error_type,
				  enum pcep_error_value error_value)
{
	switch (TUP(error_type, error_value)) {
		case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_INVALID_OPEN_MSG):
			return "INVALID_OPEN_MSG";
		case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_OPENWAIT_TIMED_OUT):
			return "OPENWAIT_TIMED_OUT";
		case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_UNACCEPTABLE_OPEN_MSG_NO_NEG):
			return "UNACCEPTABLE_OPEN_MSG_NO_NEG";
		case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_UNACCEPTABLE_OPEN_MSG_NEG):
			return "UNACCEPTABLE_OPEN_MSG_NEG";
		case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_SECOND_OPEN_MSG_UNACCEPTABLE):
			return "RECVD_SECOND_OPEN_MSG_UNACCEPTABLE";
		case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_PCERR):
			return "RECVD_PCERR";
		case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_KEEPALIVEWAIT_TIMED_OUT):
			return "KEEPALIVEWAIT_TIMED_OUT";

		case TUP(PCEP_ERRT_UNKNOW_OBJECT,
			 PCEP_ERRV_UNREC_OBJECT_CLASS):
			return "UNREC_OBJECT_CLASS";
		case TUP(PCEP_ERRT_UNKNOW_OBJECT,
			 PCEP_ERRV_UNREC_OBJECT_TYPE):
			return "UNREC_OBJECT_TYPE";

		case TUP(PCEP_ERRT_NOT_SUPPORTED_OBJECT,
			 PCEP_ERRV_NOT_SUPPORTED_OBJECT_CLASS):
			return "NOT_SUPPORTED_OBJECT_CLASS";
		case TUP(PCEP_ERRT_NOT_SUPPORTED_OBJECT,
			 PCEP_ERRV_NOT_SUPPORTED_OBJECT_TYPE):
			return "NOT_SUPPORTED_OBJECT_TYPE";

		case TUP(PCEP_ERRT_POLICY_VIOLATION,
			 PCEP_ERRV_C_BIT_SET_IN_METRIC_OBJECT):
			return "C_BIT_SET_IN_METRIC_OBJECT";
		case TUP(PCEP_ERRT_POLICY_VIOLATION,
			 PCEP_ERRV_O_BIt_CLEARD_IN_RP_OBJECT):
			return "O_BIT_CLEARD_IN_RP_OBJECT";

		case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
			 PCEP_ERRV_RP_OBJECT_MISSING):
			return "RP_OBJECT_MISSING";
		case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
			 PCEP_ERRV_RRO_OBJECT_MISSING_FOR_REOP):
			return "RRO_OBJECT_MISSING_FOR_REOP";
		case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
			 PCEP_ERRV_EP_OBJECT_MISSING):
			return "EP_OBJECT_MISSING";
		//TODO: Add constants to PCEPLib
		case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING, 8):
			return "LSP_OBJECT_MISSING";
		case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING, 9):
			return "ERO_OBJECT_MISSING";
		case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING, 11):
			return "LSP_IDENTIFIERS_TLV_MISSING";

		//TODO: The conbstant PCEP_ERRV_P_FLAG_NOT_CORRECT_IN_OBJECT
		// was removed in pceplib ... how to replace it?
		//case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		//	 PCEP_ERRV_P_FLAG_NOT_CORRECT_IN_OBJECT):
		//	return "P_FLAG_NOT_CORRECT_IN_OBJECT";

		default:
			return "UNKNOWN";
	}
}

const char *pcep_message_type_name(enum pcep_types pcep_type)
{
	switch (pcep_type) {
		case PCEP_TYPE_OPEN: return "OPEN";
		case PCEP_TYPE_KEEPALIVE: return "KEEPALIVE";
		case PCEP_TYPE_PCREQ: return "PCREQ";
		case PCEP_TYPE_PCREP: return "PCREP";
		case PCEP_TYPE_PCNOTF: return "PCNOTF";
		case PCEP_TYPE_ERROR: return "ERROR";
		case PCEP_TYPE_CLOSE: return "CLOSE";
		case PCEP_TYPE_REPORT: return "REPORT";
		case PCEP_TYPE_UPDATE: return "UPDATE";
		case PCEP_TYPE_INITIATE: return "INITIATE";
		default: return "UNKNOWN";
	}
}

const char *pcep_object_class_name(enum pcep_object_class obj_class)
{
	switch (obj_class) {
		case PCEP_OBJ_CLASS_OPEN: return "OPEN";
		case PCEP_OBJ_CLASS_RP: return "RP";
		case PCEP_OBJ_CLASS_NOPATH: return "NOPATH";
		case PCEP_OBJ_CLASS_ENDPOINTS: return "ENDPOINTS";
		case PCEP_OBJ_CLASS_BANDWIDTH: return "BANDWIDTH";
		case PCEP_OBJ_CLASS_METRIC: return "METRIC";
		case PCEP_OBJ_CLASS_ERO: return "ERO";
		case PCEP_OBJ_CLASS_RRO: return "RRO";
		case PCEP_OBJ_CLASS_LSPA: return "LSPA";
		case PCEP_OBJ_CLASS_IRO: return "IRO";
		case PCEP_OBJ_CLASS_SVEC: return "SVEC";
		case PCEP_OBJ_CLASS_NOTF: return "NOTF";
		case PCEP_OBJ_CLASS_ERROR: return "ERROR";
		case PCEP_OBJ_CLASS_CLOSE: return "CLOSE";
		case PCEP_OBJ_CLASS_LSP: return "LSP";
		case PCEP_OBJ_CLASS_SRP: return "SRP";
		default: return "UNKNOWN";
	}
}

const char *pcep_object_type_name(enum pcep_object_class obj_class,
				  enum pcep_object_types obj_type)
{
	switch (TUP(obj_class, obj_type)) {
		case TUP(PCEP_OBJ_CLASS_OPEN, PCEP_OBJ_TYPE_OPEN):
			return "OPEN";
		case TUP(PCEP_OBJ_CLASS_RP, PCEP_OBJ_TYPE_RP):
			return "RP";
		case TUP(PCEP_OBJ_CLASS_NOPATH, PCEP_OBJ_TYPE_NOPATH):
			return "NOPATH";
		case TUP(PCEP_OBJ_CLASS_ENDPOINTS, PCEP_OBJ_TYPE_ENDPOINT_IPV4):
			return "ENDPOINT_IPV4";
		case TUP(PCEP_OBJ_CLASS_ENDPOINTS, PCEP_OBJ_TYPE_ENDPOINT_IPV6):
			return "ENDPOINT_IPV6";
		case TUP(PCEP_OBJ_CLASS_BANDWIDTH, PCEP_OBJ_TYPE_BANDWIDTH_REQ):
			return "BANDWIDTH_REQ";
		case TUP(PCEP_OBJ_CLASS_BANDWIDTH, PCEP_OBJ_TYPE_BANDWIDTH_TELSP):
			return "BANDWIDTH_TELSP";
		case TUP(PCEP_OBJ_CLASS_METRIC, PCEP_OBJ_TYPE_METRIC):
			return "METRIC";
		case TUP(PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO):
			return "ERO";
		case TUP(PCEP_OBJ_CLASS_RRO, PCEP_OBJ_TYPE_RRO):
			return "RRO";
		case TUP(PCEP_OBJ_CLASS_LSPA, PCEP_OBJ_TYPE_LSPA):
			return "LSPA";
		case TUP(PCEP_OBJ_CLASS_IRO, PCEP_OBJ_TYPE_IRO):
			return "IRO";
		case TUP(PCEP_OBJ_CLASS_SVEC, PCEP_OBJ_TYPE_SVEC):
			return "SVEC";
		case TUP(PCEP_OBJ_CLASS_NOTF, PCEP_OBJ_TYPE_NOTF):
			return "NOTF";
		case TUP(PCEP_OBJ_CLASS_ERROR, PCEP_OBJ_TYPE_ERROR):
			return "ERROR";
		case TUP(PCEP_OBJ_CLASS_CLOSE, PCEP_OBJ_TYPE_CLOSE):
			return "CLOSE";
		case TUP(PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP):
			return "LSP";
		case TUP(PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP):
			return "SRP";
		default:
			return "UNKNOWN";
	}
}

const char *pcep_lsp_status_name(enum pcep_lsp_operational_status status)
{
	switch (status) {
		case PCEP_LSP_OPERATIONAL_DOWN: return "DOWN";
		case PCEP_LSP_OPERATIONAL_UP: return "UP";
		case PCEP_LSP_OPERATIONAL_ACTIVE: return "ACTIVE";
		case PCEP_LSP_OPERATIONAL_GOING_DOWN: return "GOING_DOWN";
		case PCEP_LSP_OPERATIONAL_GOING_UP: return "GOING_UP";
		default:
			return "UNKNOWN";
	}
}


const char *pcep_tlv_type_name(enum pcep_object_tlv_types tlv_type)
{
	switch (tlv_type) {
		case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
			return "STATEFUL_PCE_CAPABILITY";
		case PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME:
			return "SYMBOLIC_PATH_NAME";
		case PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS:
			return "IPV4_LSP_IDENTIFIERS";
		case PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS:
			return "IPV6_LSP_IDENTIFIERS";
		case PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE:
			return "LSP_ERROR_CODE";
		case PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC:
			return "RSVP_ERROR_SPEC";
		case PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION:
			return "LSP_DB_VERSION";
		case PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID:
			return "SPEAKER_ENTITY_ID";
		case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
			return "SR_PCE_CAPABILITY";
		case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
			return "PATH_SETUP_TYPE";
		default:
			return "UNKNOWN";
	}
}

const char *pcep_ro_type_name(enum pcep_ro_subobj_types ro_type)
{
	switch (ro_type) {
		case RO_SUBOBJ_TYPE_IPV4: return "IPV4";
		case RO_SUBOBJ_TYPE_IPV6: return "IPV6";
		case RO_SUBOBJ_TYPE_LABEL: return "LABEL";
		case RO_SUBOBJ_TYPE_UNNUM: return "UNNUM";
		case RO_SUBOBJ_TYPE_BORDER: return "BORDER";
		case RO_SUBOBJ_TYPE_ASN: return "ASN";
		case RO_SUBOBJ_TYPE_SR_DRAFT07: return "SR_DRAFT07";
		case RO_SUBOBJ_TYPE_SR: return "SR";
		default: return "UNKNOWN";
	}
}

const char *pcep_nai_type_name(enum pcep_sr_subobj_nai nai_type)
{
	switch (nai_type) {
		case PCEP_SR_SUBOBJ_NAI_ABSENT:
			return "ABSENT";
		case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
			return "IPV4_NODE";
		case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
			return "IPV6_NODE";
		case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
			return "IPV4_ADJACENCY";
		case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
			return "IPV6_ADJACENCY";
		case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
			return "UNNUMBERED_IPV4_ADJACENCY";
		case PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY:
			return "LINK_LOCAL_IPV6_ADJACENCY";
		default:
			return "UNKNOWN";
	}
}

const char *format_pcc_opts(pcc_opts_t *opts)
{
	PCEP_FORMAT_INIT();
	_format_pcc_opts(0, opts);
	return PCEP_FORMAT_FINI();
}

const char *format_pcc_state(pcc_state_t *state)
{
	PCEP_FORMAT_INIT();
	_format_pcc_state(0, state);
	return PCEP_FORMAT_FINI();
}

const char *format_ctrl_state(ctrl_state_t *state)
{
	PCEP_FORMAT_INIT();
	_format_ctrl_state(0, state);
	return PCEP_FORMAT_FINI();
}

const char *format_path(path_t *path)
{
	PCEP_FORMAT_INIT();
	_format_path(0, path);
	return PCEP_FORMAT_FINI();
}

const char *format_pcep_event(pcep_event *event)
{
	PCEP_FORMAT_INIT();
	_format_pcep_event(0, event);
	return PCEP_FORMAT_FINI();
}

const char *format_pcep_message(pcep_message *msg)
{
	PCEP_FORMAT_INIT();
	_format_pcep_message(0, msg);
	return PCEP_FORMAT_FINI();
}

const char *format_yang_dnode(struct lyd_node *dnode)
{
	char *buff;
	int len;

	lyd_print_mem(&buff, dnode, LYD_JSON, LYP_FORMAT);
	len = strlen(buff);
	memcpy(_debug_buff, buff, len);
	free(buff);
	return _debug_buff;
}

void _format_pcc_opts(int ps, pcc_opts_t *opts)
{
	if (NULL == opts) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*saddr: %pI4\n", ps2, "", &opts->addr);
		PCEP_FORMAT("%*sport: %i\n", ps2, "", opts->port);
		PCEP_FORMAT("%*s}\n", ps, "");
	}
}

void _format_pcc_state(int ps, pcc_state_t *state)
{
	if (NULL == state) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*sstatus: %s\n", ps2, "",
			    pcc_status_name(state->status));
		PCEP_FORMAT("%*sopts: ", ps2, "");
		_format_pcc_opts(ps2, state->opts);
		if (NULL == state->sess) {
			PCEP_FORMAT("%*ssess: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*ssess: <PCC SESSION %p>\n", ps2, "",
				    state->sess);
		}
	}
}

void _format_ctrl_state(int ps, ctrl_state_t *state)
{
	if (NULL == state) {
		PCEP_FORMAT("NULL\n");
	} else {
		int i;
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int ps3 = ps2 + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		if (NULL == state->main) {
			PCEP_FORMAT("%*smain: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*smain: <THREAD MASTER %p>\n", ps2, "",
				    state->main);
		}
		if (NULL == state->self) {
			PCEP_FORMAT("%*sself: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*sself: <THREAD MASTER %p>\n", ps2, "",
				    state->self);
		}
		if (NULL == state->t_poll) {
			PCEP_FORMAT("%*st_poll: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*st_poll: <THREAD %p>\n", ps2, "",
				    state->t_poll);
		}
		PCEP_FORMAT("%*spcc_count: %d\n", ps2, "", state->pcc_count);
		PCEP_FORMAT("%*spcc:\n", ps2, "");
		for (i = 0; i < state->pcc_count; i++) {
			PCEP_FORMAT("%*s- ", ps3 - 2, "");
			_format_pcc_state(ps3, state->pcc[i]);
		}
	}
}

void _format_path(int ps, path_t *path)
{
	if (NULL == path) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int ps3 = ps2 + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*snbkey: \n", ps2, "");
		PCEP_FORMAT("%*scolor: %u\n", ps3, "",
			    path->nbkey.color);
		switch (path->nbkey.endpoint.ipa_type) {
			case IPADDR_V4:
				PCEP_FORMAT("%*sendpoint: %pI4\n", ps3, "",
					    &path->nbkey.endpoint.ipaddr_v4);
				break;
			case IPADDR_V6:
				PCEP_FORMAT("%*sendpoint: %pI6\n", ps3, "",
					    &path->nbkey.endpoint.ipaddr_v6);
				break;
			default:
				PCEP_FORMAT("%*sendpoint: NONE\n", ps3, "");
				break;
		}
		PCEP_FORMAT("%*spreference: %u\n", ps3, "",
			    path->nbkey.preference);
		PCEP_FORMAT("%*splsp_id: %u\n", ps2, "", path->plsp_id);
		if (NULL == path->name) {
			PCEP_FORMAT("%*sname: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*sname: %s\n", ps2, "",
				    path->name);
		}
		PCEP_FORMAT("%*ssrp_id: %u\n", ps2, "", path->srp_id);
		PCEP_FORMAT("%*sstatus: %s (%u)\n", ps2, "",
			    pcep_lsp_status_name(path->status), path->status);
		PCEP_FORMAT("%*sdo_remove: %u\n", ps2, "", path->do_remove);
		PCEP_FORMAT("%*sgo_active: %u\n", ps2, "", path->go_active);
		PCEP_FORMAT("%*swas_created: %u\n", ps2, "", path->was_created);
		PCEP_FORMAT("%*swas_removed: %u\n", ps2, "", path->was_removed);
		PCEP_FORMAT("%*sis_synching: %u\n", ps2, "", path->is_synching);
		PCEP_FORMAT("%*sis_delegated: %u\n", ps2, "", path->is_delegated);

		if (NULL == path->first) {
			PCEP_FORMAT("%*shops: []", ps2, "");
		} else {
			PCEP_FORMAT("%*shops: \n", ps2, "");
			for (path_hop_t *hop = path->first;
			     NULL != hop;
			     hop = hop->next) {
				PCEP_FORMAT("%*s- ", ps3 - 2, "");
				_format_path_hop(ps3, hop);
			}
		}
	}
}

void _format_path_hop(int ps, path_hop_t *hop)
{
	PCEP_FORMAT("is_loose: %u\n", hop->is_loose);
	PCEP_FORMAT("%*shas_sid: %u\n", ps, "", hop->has_sid);

	if (hop->has_sid) {
		PCEP_FORMAT("%*sis_mpls: %u\n", ps, "", hop->is_mpls);
		if (hop->is_mpls) {
			PCEP_FORMAT("%*shas_attribs: %u\n", ps, "",
				    hop->has_attribs);
			PCEP_FORMAT("%*slabel: %u\n", ps, "",
				    hop->sid.mpls.label);
			if (hop->has_attribs) {
				PCEP_FORMAT("%*straffic_class: %u\n", ps, "",
					    hop->sid.mpls.traffic_class);
				PCEP_FORMAT("%*sis_bottom: %u\n", ps, "",
					    hop->sid.mpls.is_bottom);
				PCEP_FORMAT("%*sttl: %u\n", ps, "",
					    hop->sid.mpls.ttl);
			}
		} else {
			PCEP_FORMAT("%*sSID: %u\n", ps, "", hop->sid.value);
		}
	}

	PCEP_FORMAT("%*shas_nai: %u\n", ps, "", hop->has_nai);
	if (hop->has_nai) {
		PCEP_FORMAT("%*snai_type: %s (%u)\n", ps, "",
			    pcep_nai_type_name(hop->nai_type), hop->nai_type);
		switch (hop->nai_type) {
			case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
				PCEP_FORMAT("%*sNAI: %pI4\n", ps, "",
					    &hop->nai.ipv4_node.addr);
				break;
			default:
				PCEP_FORMAT("%*sNAI: UNSUPPORTED\n", ps, "");
				break;
		}
	}
}

void _format_pcep_event(int ps, pcep_event *event)
{
	if (NULL == event) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*sevent_type: %s\n", ps2, "",
			    pcep_event_type_name(event->event_type));
		PCEP_FORMAT("%*sevent_time: %s", ps2, "",
			    ctime(&event->event_time));
		if (NULL == event->session) {
			PCEP_FORMAT("%*ssession: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*ssession: <PCC SESSION %p>\n", ps2, "",
				    event->session);
		}
		PCEP_FORMAT("%*smessage: ", ps2, "");
		_format_pcep_message(ps2, event->message);
	}
}

void _format_pcep_message(int ps, pcep_message *msg)
{
	if (NULL == msg) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int ps3 = ps2 + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*sheader: \n", ps2, "");
		PCEP_FORMAT("%*sver_flags: %u\n", ps3, "",
			    msg->header->ver_flags);
		PCEP_FORMAT("%*stype: %s (%u)\n", ps3, "",
		    pcep_message_type_name(msg->header->type),
		    msg->header->type);
		PCEP_FORMAT("%*ssize: %u\n", ps3, "", msg->header->length);
		PCEP_FORMAT("%*sobjects: ", ps2, "");
		_format_pcep_objects(ps2, msg->obj_list);
	}
}

void _format_pcep_objects(int ps, double_linked_list *objs)
{
	if (NULL == objs) {
		PCEP_FORMAT("NULL\n");
	} else {
		double_linked_list_node *node;
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int i;

		if (0 == objs->num_entries) {
			PCEP_FORMAT("[]\n");
			return;
		}

		PCEP_FORMAT("\n");
		for (node = objs->head, i = 0;
		     node != NULL;
		     node = node->next_node, i++) {
			struct pcep_object_header *obj =
				(struct pcep_object_header *) node->data;
			PCEP_FORMAT("%*s- ", ps2 - 2, "");
			_format_pcep_object(ps2, obj);
		}
	}
}

void _format_pcep_object(int ps, struct pcep_object_header *obj)
{
	if (NULL == obj) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;

		//TODO: Remove when TLV unpacking is done at parsing time
		struct pcep_object_header *local_obj;
		local_obj = malloc(obj->object_length);
		memcpy(local_obj, obj, obj->object_length);
		obj = local_obj;

		PCEP_FORMAT("header: \n");
		PCEP_FORMAT("%*sobject_class: %s (%u)\n", ps2, "",
			    pcep_object_class_name(obj->object_class),
			    obj->object_class);
		PCEP_FORMAT("%*sobject_flags: %u\n", ps2, "",
			    obj->object_flags);
		PCEP_FORMAT("%*sobject_type: %s (%u)\n", ps2, "",
		    pcep_object_type_name(obj->object_class, obj->object_type),
		    obj->object_type);
		PCEP_FORMAT("%*sobject_length: %u\n", ps2, "",
			    obj->object_length);
		_format_pcep_object_details(ps, obj);

		//TODO: Remove when TLV unpacking is done at parsing time
		free(local_obj);
	}
}

void _format_pcep_object_details(int ps, struct pcep_object_header *obj)
{
	switch (TUP(obj->object_class, obj->object_type)) {
		case TUP(PCEP_OBJ_CLASS_ERROR, PCEP_OBJ_TYPE_ERROR):
			_format_pcep_object_error(ps,
				(struct pcep_object_error*)obj);
			break;
		case TUP(PCEP_OBJ_CLASS_OPEN, PCEP_OBJ_TYPE_OPEN):
			_format_pcep_object_open(ps,
				(struct pcep_object_open*)obj);
			break;
		case TUP(PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP):
			_format_pcep_object_srp(ps,
				(struct pcep_object_srp*)obj);
			break;
		case TUP(PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP):
			_format_pcep_object_lsp(ps,
				(struct pcep_object_lsp*)obj);
			break;
		case TUP(PCEP_OBJ_CLASS_ENDPOINTS, PCEP_OBJ_TYPE_ENDPOINT_IPV4):
			_format_pcep_object_ipv4_endpoint(ps,
				(struct pcep_object_endpoints_ipv4*)obj);
			break;
		case TUP(PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO):
			_format_pcep_object_ro(ps, obj);
			break;
		default:
			PCEP_FORMAT("%*s...\n", ps, "");
			break;
	}
}

void _format_pcep_object_error(int ps, struct pcep_object_error *obj)
{
	PCEP_FORMAT("%*sflags: %u\n", ps, "", obj->flags);
	PCEP_FORMAT("%*serror_type: %s (%u)\n", ps, "",
		    pcep_error_type_name(obj->error_type), obj->error_type);
	PCEP_FORMAT("%*serror_value: %s (%u)\n", ps, "",
		    pcep_error_value_name(obj->error_type, obj->error_value),
		    obj->error_value);
	_format_pcep_object_tlvs(ps, &obj->header, sizeof(*obj));
}


void _format_pcep_object_open(int ps, struct pcep_object_open *obj)
{
	PCEP_FORMAT("%*sopen_ver_flags: %u\n", ps, "", obj->open_ver_flags);
	PCEP_FORMAT("%*sopen_keepalive: %u\n", ps, "", obj->open_keepalive);
	PCEP_FORMAT("%*sopen_deadtimer: %u\n", ps, "", obj->open_deadtimer);
	PCEP_FORMAT("%*sopen_sid: %u\n", ps, "", obj->open_sid);
	_format_pcep_object_tlvs(ps, &obj->header, sizeof(*obj));
}

void _format_pcep_object_srp(int ps, struct pcep_object_srp *obj)
{
	PCEP_FORMAT("%*slsp_remove: %u\n", ps, "", obj->lsp_remove);
	PCEP_FORMAT("%*ssrp_id_number: %u\n", ps, "", obj->srp_id_number);
	_format_pcep_object_tlvs(ps, &obj->header, sizeof(*obj));
}

void _format_pcep_object_lsp(int ps, struct pcep_object_lsp *obj)
{
	uint32_t plsp_id = GET_LSP_PCEPID(obj);
	PCEP_FORMAT("%*splsp_id: %u\n", ps, "", plsp_id);
	PCEP_FORMAT("%*sstatus: %s\n", ps, "",
		    pcep_lsp_status_name(obj->plsp_id_flags & MAX_LSP_STATUS));
	PCEP_FORMAT("%*sC: %u\n", ps, "",
		    (obj->plsp_id_flags & PCEP_LSP_C_FLAG) != 0);
	PCEP_FORMAT("%*sA: %u\n", ps, "",
		    (obj->plsp_id_flags & PCEP_LSP_A_FLAG) != 0);
	PCEP_FORMAT("%*sR: %u\n", ps, "",
		    (obj->plsp_id_flags & PCEP_LSP_R_FLAG) != 0);
	PCEP_FORMAT("%*sS: %u\n", ps, "",
		    (obj->plsp_id_flags & PCEP_LSP_S_FLAG) != 0);
	PCEP_FORMAT("%*sD: %u\n", ps, "",
		    (obj->plsp_id_flags & PCEP_LSP_D_FLAG) != 0);
	_format_pcep_object_tlvs(ps, &obj->header, sizeof(*obj));
}

void _format_pcep_object_ipv4_endpoint(int ps,
	struct pcep_object_endpoints_ipv4* obj)
{
	PCEP_FORMAT("%*ssrc_ipv4: %pI4\n", ps, "", &obj->src_ipv4);
	PCEP_FORMAT("%*sdst_ipv4: %pI4\n", ps, "", &obj->dst_ipv4);
	_format_pcep_object_tlvs(ps, &obj->header, sizeof(*obj));
}

void _format_pcep_object_ro(int ps, struct pcep_object_header *obj)
{
	double_linked_list *obj_list;
	double_linked_list_node *node;
	struct pcep_ro_subobj_hdr *header;
	int ps2 = ps + DEBUG_IDENT_SIZE;
	int ps3 = ps2 + DEBUG_IDENT_SIZE;
	int i;

	obj_list = pcep_obj_get_ro_subobjects(obj);
	if ((NULL == obj_list) || (0 == obj_list->num_entries)) {
		PCEP_FORMAT("%*ssub_objs: []\n", ps, "");
		return;
	}

	PCEP_FORMAT("%*ssub_objs:\n", ps, "");

	for (node = obj_list->head, i = 0;
	     node != NULL;
	     node = node->next_node, i++) {
		header = (struct pcep_ro_subobj_hdr *) node->data;
		PCEP_FORMAT("%*s- header: \n", ps2 - 2, "");
		PCEP_FORMAT("%*stype: %s (%u)\n", ps3 , "",
		    pcep_ro_type_name(header->type), header->type);
		PCEP_FORMAT("%*slength: %u\n", ps3 , "", header->length);
		_format_pcep_object_ro_details(ps2, header);
	}

	dll_destroy(obj_list);
}

void _format_pcep_object_ro_details(int ps, struct pcep_ro_subobj_hdr *ro)
{
	switch (ro->type) {
	//FIXME: Enable when pceplib is updated
	// switch (GET_RO_SUBOBJ_TYPE(ro->type)) {
		case RO_SUBOBJ_TYPE_IPV4:
			_format_pcep_object_ro_ipv4(ps,
				(struct pcep_ro_subobj_ipv4*) ro);
			break;
		case RO_SUBOBJ_TYPE_SR_DRAFT07:
		case RO_SUBOBJ_TYPE_SR:
			_format_pcep_object_ro_sr(ps,
				(struct pcep_ro_subobj_sr*) ro);
			break;
		default:
			PCEP_FORMAT("%*s...\n", ps, "");
			break;
	}
}

void _format_pcep_object_ro_ipv4(int ps, struct pcep_ro_subobj_ipv4 *obj)
{
	PCEP_FORMAT("%*sip_addr: %pI4\n", ps, "", &obj->ip_addr);
	PCEP_FORMAT("%*sprefix_length: %u\n", ps, "", obj->prefix_length);
}

void _format_pcep_object_ro_sr(int ps, struct pcep_ro_subobj_sr *obj)
{
	bool has_sid, has_nai, is_mpls, has_attr;
	uint32_t nai_type;
	uint32_t *p = obj->sid_nai;
	struct in_addr ipv4a;

	nai_type = GET_SR_SUBOBJ_NT(obj);
	has_sid = (GET_SR_SUBOBJ_FLAGS(obj) & PCEP_SR_SUBOBJ_S_FLAG) == 0;
	has_nai = (GET_SR_SUBOBJ_FLAGS(obj) & PCEP_SR_SUBOBJ_F_FLAG) == 0;
	is_mpls = (GET_SR_SUBOBJ_FLAGS(obj) & PCEP_SR_SUBOBJ_M_FLAG) != 0;
	has_attr = (GET_SR_SUBOBJ_FLAGS(obj) & PCEP_SR_SUBOBJ_C_FLAG) != 0;

	PCEP_FORMAT("%*snai_type = %s (%u)\n", ps, "",
		    pcep_nai_type_name(nai_type), nai_type);
	//FIXME: uncoment when pceplib is updated
	// PCEP_FORMAT("%*sL: %u\n", ps, "", GET_RO_SUBOBJ_LFLAG(&sr->header));
	PCEP_FORMAT("%*sS: %u\n", ps, "", has_sid);
	PCEP_FORMAT("%*sF: %u\n", ps, "", has_nai);
	PCEP_FORMAT("%*sM: %u\n", ps, "", is_mpls);
	PCEP_FORMAT("%*sC: %u\n", ps, "", has_attr);

	if (has_sid) {
		PCEP_FORMAT("%*sSID: %u\n", ps, "", *p);
		if (is_mpls) {
			PCEP_FORMAT("%*slabel: %u\n", ps, "",
				    GET_SR_ERO_SID_LABEL(*p));
			if (has_attr) {
				PCEP_FORMAT("%*sTC: %u\n", ps, "",
					    GET_SR_ERO_SID_TC(*p));
				PCEP_FORMAT("%*sS: %u\n", ps, "",
					    GET_SR_ERO_SID_S(*p));
				PCEP_FORMAT("%*sTTL: %u\n", ps, "",
					    GET_SR_ERO_SID_TTL(*p));
			}
		}
		p++;
	}

	if (has_nai) {
		switch (nai_type) {
			case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
				ipv4a.s_addr = *p;
				PCEP_FORMAT("%*sNAI: %pI4\n", ps, "", &ipv4a);
				break;
			default:
				PCEP_FORMAT("%*sNAI: UNSUPPORTED\n", ps, "");
				break;
		}
	}
}

void _format_pcep_object_tlvs(int ps, struct pcep_object_header *obj,
			      size_t size)
{
	struct pcep_object_tlv *tlv;
	double_linked_list *tlv_list;
	double_linked_list_node *node;
	int ps2 = ps + DEBUG_IDENT_SIZE;
	int i = 0;

	tlv_list = pcep_obj_get_tlvs(obj);

	if (NULL == tlv_list) return;
	if (0 == tlv_list->num_entries) {
		PCEP_FORMAT("%*stlvs: []\n", ps, "");
		return;
	}

	PCEP_FORMAT("%*stlvs:\n", ps, "");

	for (node = tlv_list->head, i = 0;
	     node != NULL;
	     node = node->next_node, i++) {
		tlv = (struct pcep_object_tlv *) node->data;
		PCEP_FORMAT("%*s- ", ps2 - 2, "");
		_format_pcep_object_tlv(ps2, tlv);
	}

	dll_destroy(tlv_list);
}

void _format_pcep_object_tlv(int ps, struct pcep_object_tlv *tlv)
{
	int ps2 = ps + DEBUG_IDENT_SIZE;

	PCEP_FORMAT("header: \n");
	PCEP_FORMAT("%*stype: %s (%u)\n", ps2, "",
		    pcep_tlv_type_name(tlv->header.type), tlv->header.type);
	PCEP_FORMAT("%*slength: %u\n", ps2, "", tlv->header.length);
	_format_pcep_object_tlv_details(ps, tlv);
}

void _format_pcep_object_tlv_details(int ps, struct pcep_object_tlv *tlv)
{
	switch (tlv->header.type) {
		case PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME:
			PCEP_FORMAT("%*svalue: %.*s\n", ps, "",
				    tlv->header.length, (char*)&tlv->value);
			break;
		case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
		case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
		case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
			PCEP_FORMAT("%*svalue: %u\n", ps, "", *tlv->value);
			break;
		default:
			PCEP_FORMAT("%*s...\n", ps, "");
			break;
	}
}
