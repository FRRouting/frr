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
#define PCEP_FORMAT(fmt, ...)                                                  \
	csnprintfrr(_debug_buff, DEBUG_BUFF_SIZE, fmt, ##__VA_ARGS__)
#define PCEP_FORMAT_FINI() _debug_buff
THREAD_DATA char _debug_buff[DEBUG_BUFF_SIZE];

static void _format_pcc_opts(int ps, struct pcc_opts *ops);
static void _format_pce_opts(int ps, struct pce_opts *ops);
static void _format_pcc_caps(int ps, struct pcep_caps *caps);
static void _format_pcc_state(int ps, struct pcc_state *state);
static void _format_ctrl_state(int ps, struct ctrl_state *state);
static void _format_path(int ps, struct path *path);
static void _format_path_hop(int ps, struct path_hop *hop);
static void _format_path_metric(int ps, struct path_metric *metric);
static void _format_pcep_event(int ps, pcep_event *event);
static void _format_pcep_message(int ps, struct pcep_message *msg);
static void _format_pcep_objects(int ps, double_linked_list *objs);
static void _format_pcep_object(int ps, struct pcep_object_header *obj);
static void _format_pcep_object_details(int ps, struct pcep_object_header *obj);
static void _format_pcep_object_error(int ps, struct pcep_object_error *obj);
static void _format_pcep_object_open(int ps, struct pcep_object_open *obj);
static void _format_pcep_object_rp(int ps, struct pcep_object_rp *obj);
static void _format_pcep_object_srp(int ps, struct pcep_object_srp *obj);
static void _format_pcep_object_lsp(int psps, struct pcep_object_lsp *obj);
static void
_format_pcep_object_ipv4_endpoint(int ps,
				  struct pcep_object_endpoints_ipv4 *obj);
static void _format_pcep_object_metric(int ps, struct pcep_object_metric *obj);
static void _format_pcep_object_bandwidth(int ps, struct pcep_object_bandwidth *obj);
static void _format_pcep_object_ro(int ps, struct pcep_object_ro *obj);
static void _format_pcep_object_ro_details(int ps,
					   struct pcep_object_ro_subobj *ro);
static void _format_pcep_object_ro_ipv4(int ps,
					struct pcep_ro_subobj_ipv4 *obj);
static void _format_pcep_object_ro_sr(int ps, struct pcep_ro_subobj_sr *obj);
static void _format_pcep_object_tlvs(int ps, struct pcep_object_header *obj);
static void _format_pcep_object_tlv(int ps,
				    struct pcep_object_tlv_header *tlv_header);
static void
_format_pcep_object_tlv_details(int ps,
				struct pcep_object_tlv_header *tlv_header);
static void _format_pcep_object_tlv_symbolic_path_name(
	int ps, struct pcep_object_tlv_symbolic_path_name *tlv);
static void _format_pcep_object_tlv_stateful_pce_capability(
	int ps, struct pcep_object_tlv_stateful_pce_capability *tlv);
static void _format_pcep_object_tlv_sr_pce_capability(
	int ps, struct pcep_object_tlv_sr_pce_capability *tlv);
static void _format_pcep_object_tlv_path_setup_type(
	int ps, struct pcep_object_tlv_path_setup_type *tlv);

const char *pcc_status_name(enum pcc_status status)
{
	switch (status) {
	case PCEP_PCC_INITIALIZED:
		return "INITIALIZED";
	case PCEP_PCC_DISCONNECTED:
		return "DISCONNECTED";
	case PCEP_PCC_CONNECTING:
		return "CONNECTING";
	case PCEP_PCC_SYNCHRONIZING:
		return "SYNCHRONIZING";
	case PCEP_PCC_OPERATING:
		return "OPERATING";
	default:
		return "UNKNOWN";
	}
}

const char *srte_protocol_origin_name(enum srte_protocol_origin origin)
{
	switch (origin) {
	case SRTE_ORIGIN_UNDEFINED:
		return "UNDEFINED";
	case SRTE_ORIGIN_PCEP:
		return "PCEP";
	case SRTE_ORIGIN_BGP:
		return "BGP";
	case SRTE_ORIGIN_LOCAL:
		return "LOCAL";
	default:
		return "UNKNOWN";
	}
}

const char *srte_candidate_type_name(enum srte_candidate_type type)
{
	switch (type) {
	case SRTE_CANDIDATE_TYPE_EXPLICIT:
		return "EXPLICIT";
	case SRTE_CANDIDATE_TYPE_DYNAMIC:
		return "DYNAMIC";
	case SRTE_CANDIDATE_TYPE_UNDEFINED:
		return "UNDEFINED";
	default:
		return "UNKNOWN";
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
	case PCEP_ERRT_INVALID_OPERATION:
		return "INVALID_OPERATION";
	case PCEP_ERRT_LSP_STATE_SYNC_ERROR:
		return "LSP_STATE_SYNC_ERROR";
	case PCEP_ERRT_BAD_PARAMETER_VALUE:
		return "BAD_PARAMETER_VALUE";
	case PCEP_ERRT_LSP_INSTANTIATE_ERROR:
		return "LSP_INSTANTIATE_ERROR";
	default:
		return "UNKNOWN";
	}
}

const char *pcep_error_value_name(enum pcep_error_type error_type,
				  enum pcep_error_value error_value)
{
	switch (TUP(error_type, error_value)) {

	case TUP(PCEP_ERRT_CAPABILITY_NOT_SUPPORTED, PCEP_ERRV_UNASSIGNED):
	case TUP(PCEP_ERRT_SYNC_PC_REQ_MISSING, PCEP_ERRV_UNASSIGNED):
	case TUP(PCEP_ERRT_UNKNOWN_REQ_REF, PCEP_ERRV_UNASSIGNED):
	case TUP(PCEP_ERRT_ATTEMPT_TO_ESTABLISH_2ND_PCEP_SESSION,
		 PCEP_ERRV_UNASSIGNED):
		return "UNASSIGNED";

	case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_INVALID_OPEN_MSG):
		return "RECVD_INVALID_OPEN_MSG";
	case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_OPENWAIT_TIMED_OUT):
		return "OPENWAIT_TIMED_OUT";
	case TUP(PCEP_ERRT_SESSION_FAILURE,
		 PCEP_ERRV_UNACCEPTABLE_OPEN_MSG_NO_NEG):
		return "UNACCEPTABLE_OPEN_MSG_NO_NEG";
	case TUP(PCEP_ERRT_SESSION_FAILURE,
		 PCEP_ERRV_UNACCEPTABLE_OPEN_MSG_NEG):
		return "UNACCEPTABLE_OPEN_MSG_NEG";
	case TUP(PCEP_ERRT_SESSION_FAILURE,
		 PCEP_ERRV_RECVD_SECOND_OPEN_MSG_UNACCEPTABLE):
		return "RECVD_SECOND_OPEN_MSG_UNACCEPTABLE";
	case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_RECVD_PCERR):
		return "RECVD_PCERR";
	case TUP(PCEP_ERRT_SESSION_FAILURE, PCEP_ERRV_KEEPALIVEWAIT_TIMED_OUT):
		return "KEEPALIVEWAIT_TIMED_OUT";

	case TUP(PCEP_ERRT_UNKNOW_OBJECT, PCEP_ERRV_UNREC_OBJECT_CLASS):
		return "UNREC_OBJECT_CLASS";
	case TUP(PCEP_ERRT_UNKNOW_OBJECT, PCEP_ERRV_UNREC_OBJECT_TYPE):
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
		 PCEP_ERRV_O_BIT_CLEARD_IN_RP_OBJECT):
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
	case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
		 PCEP_ERRV_LSP_OBJECT_MISSING):
		return "LSP_OBJECT_MISSING";
	case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
		 PCEP_ERRV_ERO_OBJECT_MISSING):
		return "ERO_OBJECT_MISSING";
	case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
		 PCEP_ERRV_SRP_OBJECT_MISSING):
		return "SRP_OBJECT_MISSING";
	case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
		 PCEP_ERRV_LSP_ID_TLV_MISSING):
		return "LSP_ID_TLV_MISSING";

	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_P_FLAG_NOT_CORRECT_IN_OBJECT):
		return "P_FLAG_NOT_CORRECT_IN_OBJECT";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_PCC_SYMBOLIC_PATH_NAME_TLV_MISSING):
		return "PCC_SYMBOLIC_PATH_NAME_TLV_MISSING";

	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_UPDATE_FOR_NON_DELEGATED_LSP):
		return "LSP_UPDATE_FOR_NON_DELEGATED_LSP";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_UPDATE_NON_ADVERTISED_PCE):
		return "LSP_UPDATE_NON_ADVERTISED_PCE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_UPDATE_UNKNOWN_PLSP_ID):
		return "LSP_UPDATE_UNKNOWN_PLSP_ID";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_REPORT_NON_ADVERTISED_PCE):
		return "LSP_REPORT_NON_ADVERTISED_PCE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_PCE_INIT_LSP_LIMIT_REACHED):
		return "PCE_INIT_LSP_LIMIT_REACHED";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_PCE_INIT_LSP_DELEGATION_CANT_REVOKE):
		return "PCE_INIT_LSP_DELEGATION_CANT_REVOKE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_INIT_NON_ZERO_PLSP_ID):
		return "LSP_INIT_NON_ZERO_PLSP_ID";
	case TUP(PCEP_ERRT_INVALID_OPERATION, PCEP_ERRV_LSP_NOT_PCE_INITIATED):
		return "LSP_NOT_PCE_INITIATED";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_PCE_INIT_OP_FREQ_LIMIT_REACHED):
		return "PCE_INIT_OP_FREQ_LIMIT_REACHED";

	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_PCE_CANT_PROCESS_LSP_REPORT):
		return "PCE_CANT_PROCESS_LSP_REPORT";
	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_PCC_CANT_COMPLETE_STATE_SYNC):
		return "PCC_CANT_COMPLETE_STATE_SYNC";

	case TUP(PCEP_ERRT_BAD_PARAMETER_VALUE,
		 PCEP_ERRV_SYMBOLIC_PATH_NAME_IN_USE):
		return "SYMBOLIC_PATH_NAME_IN_USE";
	case TUP(PCEP_ERRT_BAD_PARAMETER_VALUE,
		 PCEP_ERRV_LSP_SPEAKER_ID_NOT_PCE_INITIATED):
		return "LSP_SPEAKER_ID_NOT_PCE_INITIATED";

	case TUP(PCEP_ERRT_LSP_INSTANTIATE_ERROR,
		 PCEP_ERRV_UNACCEPTABLE_INSTANTIATE_ERROR):
		return "UNACCEPTABLE_INSTANTIATE_ERROR";
	case TUP(PCEP_ERRT_LSP_INSTANTIATE_ERROR, PCEP_ERRV_INTERNAL_ERROR):
		return "INTERNAL_ERROR";
	case TUP(PCEP_ERRT_LSP_INSTANTIATE_ERROR, PCEP_ERRV_SIGNALLING_ERROR):
		return "SIGNALLING_ERROR";

	default:
		return "UNKNOWN";
	}
}

const char *pcep_message_type_name(enum pcep_message_types pcep_message_type)
{
	switch (pcep_message_type) {

	case PCEP_TYPE_OPEN:
		return "OPEN";
	case PCEP_TYPE_KEEPALIVE:
		return "KEEPALIVE";
	case PCEP_TYPE_PCREQ:
		return "PCREQ";
	case PCEP_TYPE_PCREP:
		return "PCREP";
	case PCEP_TYPE_PCNOTF:
		return "PCNOTF";
	case PCEP_TYPE_ERROR:
		return "ERROR";
	case PCEP_TYPE_CLOSE:
		return "CLOSE";
	case PCEP_TYPE_REPORT:
		return "REPORT";
	case PCEP_TYPE_UPDATE:
		return "UPDATE";
	case PCEP_TYPE_INITIATE:
		return "INITIATE";
	case PCEP_TYPE_UNKOWN_MSG:
		return "UNKOWN_MSG";
	default:
		return "UNKNOWN";
	}
}

const char *pcep_object_class_name(enum pcep_object_classes obj_class)
{
	switch (obj_class) {
	case PCEP_OBJ_CLASS_OPEN:
		return "OPEN";
	case PCEP_OBJ_CLASS_RP:
		return "RP";
	case PCEP_OBJ_CLASS_NOPATH:
		return "NOPATH";
	case PCEP_OBJ_CLASS_ENDPOINTS:
		return "ENDPOINTS";
	case PCEP_OBJ_CLASS_BANDWIDTH:
		return "BANDWIDTH";
	case PCEP_OBJ_CLASS_METRIC:
		return "METRIC";
	case PCEP_OBJ_CLASS_ERO:
		return "ERO";
	case PCEP_OBJ_CLASS_RRO:
		return "RRO";
	case PCEP_OBJ_CLASS_LSPA:
		return "LSPA";
	case PCEP_OBJ_CLASS_IRO:
		return "IRO";
	case PCEP_OBJ_CLASS_SVEC:
		return "SVEC";
	case PCEP_OBJ_CLASS_NOTF:
		return "NOTF";
	case PCEP_OBJ_CLASS_ERROR:
		return "ERROR";
	case PCEP_OBJ_CLASS_CLOSE:
		return "CLOSE";
	case PCEP_OBJ_CLASS_LSP:
		return "LSP";
	case PCEP_OBJ_CLASS_SRP:
		return "SRP";
	default:
		return "UNKNOWN";
	}
}

const char *pcep_object_type_name(enum pcep_object_classes obj_class,
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
	case TUP(PCEP_OBJ_CLASS_BANDWIDTH, PCEP_OBJ_TYPE_BANDWIDTH_CISCO):
		return "BANDWIDTH_CISCO";
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
	case PCEP_LSP_OPERATIONAL_DOWN:
		return "DOWN";
	case PCEP_LSP_OPERATIONAL_UP:
		return "UP";
	case PCEP_LSP_OPERATIONAL_ACTIVE:
		return "ACTIVE";
	case PCEP_LSP_OPERATIONAL_GOING_DOWN:
		return "GOING_DOWN";
	case PCEP_LSP_OPERATIONAL_GOING_UP:
		return "GOING_UP";
	default:
		return "UNKNOWN";
	}
}


const char *pcep_tlv_type_name(enum pcep_object_tlv_types tlv_type)
{
	switch (tlv_type) {
	case PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR:
		return "NO_PATH_VECTOR";
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
	case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY:
		return "PATH_SETUP_TYPE_CAPABILITY";
	default:
		return "UNKNOWN";
	}
}

const char *pcep_ro_type_name(enum pcep_ro_subobj_types ro_type)
{
	switch (ro_type) {

	case RO_SUBOBJ_TYPE_IPV4:
		return "IPV4";
	case RO_SUBOBJ_TYPE_IPV6:
		return "IPV6";
	case RO_SUBOBJ_TYPE_LABEL:
		return "LABEL";
	case RO_SUBOBJ_TYPE_UNNUM:
		return "UNNUM";
	case RO_SUBOBJ_TYPE_ASN:
		return "ASN";
	case RO_SUBOBJ_TYPE_SR:
		return "SR";
	case RO_SUBOBJ_TYPE_SR_DRAFT07:
		return "SR_DRAFT07";
	default:
		return "UNKNOWN";
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

const char *pcep_metric_type_name(enum pcep_metric_types type)
{
	switch (type) {
	case PCEP_METRIC_IGP:
		return "IGP";
	case PCEP_METRIC_TE:
		return "TE";
	case PCEP_METRIC_HOP_COUNT:
		return "HOP_COUNT";
	case PCEP_METRIC_AGGREGATE_BW:
		return "AGGREGATE_BW";
	case PCEP_METRIC_MOST_LOADED_LINK:
		return "MOST_LOADED_LINK";
	case PCEP_METRIC_CUMULATIVE_IGP:
		return "CUMULATIVE_IGP";
	case PCEP_METRIC_CUMULATIVE_TE:
		return "CUMULATIVE_TE";
	case PCEP_METRIC_P2MP_IGP:
		return "P2MP_IGP";
	case PCEP_METRIC_P2MP_TE:
		return "P2MP_TE";
	case PCEP_METRIC_P2MP_HOP_COUNT:
		return "P2MP_HOP_COUNT";
	case PCEP_METRIC_SEGMENT_ID_DEPTH:
		return "SEGMENT_ID_DEPTH";
	case PCEP_METRIC_PATH_DELAY:
		return "PATH_DELAY";
	case PCEP_METRIC_PATH_DELAY_VARIATION:
		return "PATH_DELAY_VARIATION";
	case PCEP_METRIC_PATH_LOSS:
		return "PATH_LOSS";
	case PCEP_METRIC_P2MP_PATH_DELAY:
		return "P2MP_PATH_DELAY";
	case PCEP_METRIC_P2MP_PATH_DELAY_VARIATION:
		return "P2MP_PATH_DELAY_VARIATION";
	case PCEP_METRIC_P2MP_PATH_LOSS:
		return "P2MP_PATH_LOSS";
	case PCEP_METRIC_NUM_PATH_ADAPTATIONS:
		return "NUM_PATH_ADAPTATIONS";
	case PCEP_METRIC_NUM_PATH_LAYERS:
		return "NUM_PATH_LAYERS";
	case PCEP_METRIC_DOMAIN_COUNT:
		return "DOMAIN_COUNT";
	case PCEP_METRIC_BORDER_NODE_COUNT:
		return "BORDER_NODE_COUNT";
	default:
		return "UNKNOWN";
	}
}

const char *format_pcc_opts(struct pcc_opts *opts)
{
	PCEP_FORMAT_INIT();
	_format_pcc_opts(0, opts);
	return PCEP_FORMAT_FINI();
}

const char *format_pcc_state(struct pcc_state *state)
{
	PCEP_FORMAT_INIT();
	_format_pcc_state(0, state);
	return PCEP_FORMAT_FINI();
}

const char *format_ctrl_state(struct ctrl_state *state)
{
	PCEP_FORMAT_INIT();
	_format_ctrl_state(0, state);
	return PCEP_FORMAT_FINI();
}

const char *format_path(struct path *path)
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

const char *format_pcep_message(struct pcep_message *msg)
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

void _format_pcc_opts(int ps, struct pcc_opts *opts)
{
	if (opts == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		if (CHECK_FLAG(opts->flags, F_PCC_OPTS_IPV4)) {
			PCEP_FORMAT("%*saddr_v4: %pI4\n", ps2, "",
				    &opts->addr_v4);
		} else {
			PCEP_FORMAT("%*saddr_v4: undefined", ps2, "");
		}
		if (CHECK_FLAG(opts->flags, F_PCC_OPTS_IPV6)) {
			PCEP_FORMAT("%*saddr_v6: %pI6\n", ps2, "",
				    &opts->addr_v6);
		} else {
			PCEP_FORMAT("%*saddr_v6: undefined", ps2, "");
		}
		PCEP_FORMAT("%*sport: %i\n", ps2, "", opts->port);
		PCEP_FORMAT("%*smsd: %i\n", ps2, "", opts->msd);
	}
}

void _format_pce_opts(int ps, struct pce_opts *opts)
{
	if (opts == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		if (IS_IPADDR_V6(&opts->addr)) {
			PCEP_FORMAT("%*saddr: %pI6\n", ps2, "",
				    &opts->addr.ipaddr_v6);
		} else {
			PCEP_FORMAT("%*saddr: %pI4\n", ps2, "",
				    &opts->addr.ipaddr_v4);
		}
		PCEP_FORMAT("%*sport: %i\n", ps2, "", opts->port);
	}
}

void _format_pcc_caps(int ps, struct pcep_caps *caps)
{
	int ps2 = ps + DEBUG_IDENT_SIZE;
	PCEP_FORMAT("\n");
	PCEP_FORMAT("%*sis_stateful: %d\n", ps2, "", caps->is_stateful);
}

void _format_pcc_state(int ps, struct pcc_state *state)
{
	if (state == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*sstatus: %s\n", ps2, "",
			    pcc_status_name(state->status));
		PCEP_FORMAT("%*spcc_opts: ", ps2, "");
		_format_pcc_opts(ps2, state->pcc_opts);
		PCEP_FORMAT("%*spce_opts: ", ps2, "");
		_format_pce_opts(ps2, state->pce_opts);
		if (state->sess == NULL) {
			PCEP_FORMAT("%*ssess: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*ssess: <PCC SESSION %p>\n", ps2, "",
				    state->sess);
		}
		PCEP_FORMAT("%*scaps: ", ps2, "");
		_format_pcc_caps(ps2, &state->caps);
	}
}

void _format_ctrl_state(int ps, struct ctrl_state *state)
{
	if (state == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		int i;
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int ps3 = ps2 + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		if (state->main == NULL) {
			PCEP_FORMAT("%*smain: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*smain: <THREAD MASTER %p>\n", ps2, "",
				    state->main);
		}
		if (state->self == NULL) {
			PCEP_FORMAT("%*sself: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*sself: <THREAD MASTER %p>\n", ps2, "",
				    state->self);
		}
		PCEP_FORMAT("%*spcc_count: %d\n", ps2, "", state->pcc_count);
		PCEP_FORMAT("%*spcc:\n", ps2, "");
		for (i = 0; i < state->pcc_count; i++) {
			PCEP_FORMAT("%*s- ", ps3 - 2, "");
			_format_pcc_state(ps3, state->pcc[i]);
		}
	}
}

void _format_path(int ps, struct path *path)
{
	if (path == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int ps3 = ps2 + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*snbkey: \n", ps2, "");
		PCEP_FORMAT("%*scolor: %u\n", ps3, "", path->nbkey.color);
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

		if (path->sender.ipa_type == IPADDR_V4) {
			PCEP_FORMAT("%*ssender: %pI4\n", ps2, "",
				    &path->sender.ipaddr_v4);
		} else if (path->sender.ipa_type == IPADDR_V6) {
			PCEP_FORMAT("%*ssender: %pI6\n", ps2, "",
				    &path->sender.ipaddr_v6);
		} else {
			PCEP_FORMAT("%*ssender: UNDEFINED\n", ps2, "");
		}
		if (path->pcc_addr.ipa_type == IPADDR_V4) {
			PCEP_FORMAT("%*spcc_addr: %pI4\n", ps2, "",
				    &path->pcc_addr.ipaddr_v4);
		} else if (path->pcc_addr.ipa_type == IPADDR_V6) {
			PCEP_FORMAT("%*spcc_addr: %pI6\n", ps2, "",
				    &path->pcc_addr.ipaddr_v6);
		} else {
			PCEP_FORMAT("%*spcc_addr: UNDEFINED\n", ps2, "");
		}
		PCEP_FORMAT("%*spcc_id: %u\n", ps2, "", path->pcc_id);
		PCEP_FORMAT("%*screate_origin: %s (%u)\n", ps2, "",
			    srte_protocol_origin_name(path->create_origin),
			    path->create_origin);
		PCEP_FORMAT("%*supdate_origin: %s (%u)\n", ps2, "",
			    srte_protocol_origin_name(path->update_origin),
			    path->update_origin);
		if (path->originator != NULL) {
			PCEP_FORMAT("%*soriginator: %s\n", ps2, "",
				    path->originator);
		} else {
			PCEP_FORMAT("%*soriginator: UNDEFINED\n", ps2, "");
		}
		PCEP_FORMAT("%*stype: %s (%u)\n", ps2, "",
			    srte_candidate_type_name(path->type), path->type);
		PCEP_FORMAT("%*splsp_id: %u\n", ps2, "", path->plsp_id);
		if (path->name == NULL) {
			PCEP_FORMAT("%*sname: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*sname: %s\n", ps2, "", path->name);
		}
		PCEP_FORMAT("%*ssrp_id: %u\n", ps2, "", path->srp_id);
		PCEP_FORMAT("%*sreq_id: %u\n", ps2, "", path->req_id);
		PCEP_FORMAT("%*sstatus: %s (%u)\n", ps2, "",
			    pcep_lsp_status_name(path->status), path->status);
		PCEP_FORMAT("%*sdo_remove: %u\n", ps2, "", path->do_remove);
		PCEP_FORMAT("%*sgo_active: %u\n", ps2, "", path->go_active);
		PCEP_FORMAT("%*swas_created: %u\n", ps2, "", path->was_created);
		PCEP_FORMAT("%*swas_removed: %u\n", ps2, "", path->was_removed);
		PCEP_FORMAT("%*sis_synching: %u\n", ps2, "", path->is_synching);
		PCEP_FORMAT("%*sis_delegated: %u\n", ps2, "",
			    path->is_delegated);
		PCEP_FORMAT("%*shas_bandwidth: %u\n", ps2, "",
			    path->has_bandwidth);
		if (path->has_bandwidth) {
			PCEP_FORMAT("%*sbandwidth: %f\n", ps2, "",
			            path->bandwidth);
		}

		if (path->first_hop == NULL) {
			PCEP_FORMAT("%*shops: []\n", ps2, "");
		} else {
			PCEP_FORMAT("%*shops: \n", ps2, "");
			for (struct path_hop *hop = path->first_hop;
			     hop != NULL; hop = hop->next) {
				PCEP_FORMAT("%*s- ", ps3 - 2, "");
				_format_path_hop(ps3, hop);
			}
		}
		if (path->first_metric == NULL) {
			PCEP_FORMAT("%*smetrics: []\n", ps2, "");
		} else {
			PCEP_FORMAT("%*smetrics: \n", ps2, "");
			for (struct path_metric *metric = path->first_metric;
			     NULL != metric; metric = metric->next) {
				PCEP_FORMAT("%*s- ", ps3 - 2, "");
				_format_path_metric(ps3, metric);
			}
		}
	}
}

void _format_path_metric(int ps, struct path_metric *metric)
{
	PCEP_FORMAT("type: %s (%u)\n", pcep_metric_type_name(metric->type),
		    metric->type);
	PCEP_FORMAT("%*sis_bound: %u\n", ps, "", metric->is_bound);
	PCEP_FORMAT("%*sis_computed: %u\n", ps, "", metric->is_computed);
	PCEP_FORMAT("%*svalue: %f\n", ps, "", metric->value);
}

void _format_path_hop(int ps, struct path_hop *hop)
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
			    pcep_nai_type_name(hop->nai.type), hop->nai.type);
		switch (hop->nai.type) {
		case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
			PCEP_FORMAT("%*sNAI: %pI4\n", ps, "",
				    &hop->nai.local_addr.ipaddr_v4);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
			PCEP_FORMAT("%*sNAI: %pI6\n", ps, "",
				    &hop->nai.local_addr.ipaddr_v6);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
			PCEP_FORMAT("%*sNAI: %pI4/%pI4\n", ps, "",
				    &hop->nai.local_addr.ipaddr_v4,
				    &hop->nai.remote_addr.ipaddr_v4);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
			PCEP_FORMAT("%*sNAI: %pI6/%pI6\n", ps, "",
				    &hop->nai.local_addr.ipaddr_v6,
				    &hop->nai.remote_addr.ipaddr_v6);
			break;
		case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
			PCEP_FORMAT("%*sNAI: %pI4(%u)/%pI4(%u)\n", ps, "",
				    &hop->nai.local_addr.ipaddr_v6,
				    hop->nai.local_iface,
				    &hop->nai.remote_addr.ipaddr_v6,
				    hop->nai.remote_iface);
			break;
		default:
			PCEP_FORMAT("%*sNAI: UNSUPPORTED\n", ps, "");
			break;
		}
	}
}

void _format_pcep_event(int ps, pcep_event *event)
{
	if (event == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*sevent_type: %s\n", ps2, "",
			    pcep_event_type_name(event->event_type));
		PCEP_FORMAT("%*sevent_time: %s", ps2, "",
			    ctime(&event->event_time));
		if (event->session == NULL) {
			PCEP_FORMAT("%*ssession: NULL\n", ps2, "");
		} else {
			PCEP_FORMAT("%*ssession: <PCC SESSION %p>\n", ps2, "",
				    event->session);
		}
		PCEP_FORMAT("%*smessage: ", ps2, "");
		_format_pcep_message(ps2, event->message);
	}
}

void _format_pcep_message(int ps, struct pcep_message *msg)
{
	if (msg == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PCEP_FORMAT("\n");
		PCEP_FORMAT("%*spcep_version: %u\n", ps2, "",
			    msg->msg_header->pcep_version);
		PCEP_FORMAT("%*stype: %s (%u)\n", ps2, "",
			    pcep_message_type_name(msg->msg_header->type),
			    msg->msg_header->type);
		PCEP_FORMAT("%*sobjects: ", ps2, "");
		_format_pcep_objects(ps2, msg->obj_list);
	}
}

void _format_pcep_objects(int ps, double_linked_list *objs)
{
	if (objs == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		double_linked_list_node *node;
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int i;

		if (objs->num_entries == 0) {
			PCEP_FORMAT("[]\n");
			return;
		}

		PCEP_FORMAT("\n");
		for (node = objs->head, i = 0; node != NULL;
		     node = node->next_node, i++) {
			struct pcep_object_header *obj =
				(struct pcep_object_header *)node->data;
			PCEP_FORMAT("%*s- ", ps2 - 2, "");
			_format_pcep_object(ps2, obj);
		}
	}
}

void _format_pcep_object(int ps, struct pcep_object_header *obj)
{
	if (obj == NULL) {
		PCEP_FORMAT("NULL\n");
	} else {
		PCEP_FORMAT("object_class: %s (%u)\n",
			    pcep_object_class_name(obj->object_class),
			    obj->object_class);
		PCEP_FORMAT("%*sobject_type: %s (%u)\n", ps, "",
			    pcep_object_type_name(obj->object_class,
						  obj->object_type),
			    obj->object_type);
		PCEP_FORMAT("%*sflag_p: %u\n", ps, "", obj->flag_p);
		PCEP_FORMAT("%*sflag_i: %u\n", ps, "", obj->flag_i);
		_format_pcep_object_details(ps, obj);
		_format_pcep_object_tlvs(ps, obj);
	}
}

void _format_pcep_object_details(int ps, struct pcep_object_header *obj)
{
	switch (TUP(obj->object_class, obj->object_type)) {
	case TUP(PCEP_OBJ_CLASS_ERROR, PCEP_OBJ_TYPE_ERROR):
		_format_pcep_object_error(ps, (struct pcep_object_error *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_OPEN, PCEP_OBJ_TYPE_OPEN):
		_format_pcep_object_open(ps, (struct pcep_object_open *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_RP, PCEP_OBJ_TYPE_RP):
		_format_pcep_object_rp(ps, (struct pcep_object_rp *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP):
		_format_pcep_object_srp(ps, (struct pcep_object_srp *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP):
		_format_pcep_object_lsp(ps, (struct pcep_object_lsp *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_ENDPOINTS, PCEP_OBJ_TYPE_ENDPOINT_IPV4):
		_format_pcep_object_ipv4_endpoint(
			ps, (struct pcep_object_endpoints_ipv4 *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO):
		_format_pcep_object_ro(ps, (struct pcep_object_ro *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_METRIC, PCEP_OBJ_TYPE_METRIC):
		_format_pcep_object_metric(ps,
					   (struct pcep_object_metric *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_BANDWIDTH, PCEP_OBJ_TYPE_BANDWIDTH_REQ):
	case TUP(PCEP_OBJ_CLASS_BANDWIDTH, PCEP_OBJ_TYPE_BANDWIDTH_CISCO):
		_format_pcep_object_bandwidth(ps,
					   (struct pcep_object_bandwidth *)obj);
		break;
	default:
		PCEP_FORMAT("%*s...\n", ps, "");
		break;
	}
}

void _format_pcep_object_error(int ps, struct pcep_object_error *obj)
{
	PCEP_FORMAT("%*serror_type: %s (%u)\n", ps, "",
		    pcep_error_type_name(obj->error_type), obj->error_type);
	PCEP_FORMAT("%*serror_value: %s (%u)\n", ps, "",
		    pcep_error_value_name(obj->error_type, obj->error_value),
		    obj->error_value);
}


void _format_pcep_object_open(int ps, struct pcep_object_open *obj)
{
	PCEP_FORMAT("%*sopen_version: %u\n", ps, "", obj->open_version);
	PCEP_FORMAT("%*sopen_keepalive: %u\n", ps, "", obj->open_keepalive);
	PCEP_FORMAT("%*sopen_deadtimer: %u\n", ps, "", obj->open_deadtimer);
	PCEP_FORMAT("%*sopen_sid: %u\n", ps, "", obj->open_sid);
}

void _format_pcep_object_rp(int ps, struct pcep_object_rp *obj)
{
	PCEP_FORMAT("%*spriority: %u\n", ps, "", obj->priority);
	PCEP_FORMAT("%*sflag_reoptimization: %u\n", ps, "",
		    obj->flag_reoptimization);
	PCEP_FORMAT("%*sflag_bidirectional: %u\n", ps, "",
		    obj->flag_bidirectional);
	PCEP_FORMAT("%*sflag_strict: %u\n", ps, "", obj->flag_strict);
	PCEP_FORMAT("%*srequest_id: %u\n", ps, "", obj->request_id);
}


void _format_pcep_object_srp(int ps, struct pcep_object_srp *obj)
{
	PCEP_FORMAT("%*sflag_lsp_remove: %u\n", ps, "", obj->flag_lsp_remove);
	PCEP_FORMAT("%*ssrp_id_number: %u\n", ps, "", obj->srp_id_number);
}

void _format_pcep_object_lsp(int ps, struct pcep_object_lsp *obj)
{
	PCEP_FORMAT("%*splsp_id: %u\n", ps, "", obj->plsp_id);
	PCEP_FORMAT("%*sstatus: %s\n", ps, "",
		    pcep_lsp_status_name(obj->operational_status));
	PCEP_FORMAT("%*sflag_d: %u\n", ps, "", obj->flag_d);
	PCEP_FORMAT("%*sflag_s: %u\n", ps, "", obj->flag_s);
	PCEP_FORMAT("%*sflag_r: %u\n", ps, "", obj->flag_r);
	PCEP_FORMAT("%*sflag_a: %u\n", ps, "", obj->flag_a);
	PCEP_FORMAT("%*sflag_c: %u\n", ps, "", obj->flag_c);
}

void _format_pcep_object_ipv4_endpoint(int ps,
				       struct pcep_object_endpoints_ipv4 *obj)
{
	PCEP_FORMAT("%*ssrc_ipv4: %pI4\n", ps, "", &obj->src_ipv4);
	PCEP_FORMAT("%*sdst_ipv4: %pI4\n", ps, "", &obj->dst_ipv4);
}

void _format_pcep_object_metric(int ps, struct pcep_object_metric *obj)
{
	PCEP_FORMAT("%*stype: %s (%u)\n", ps, "",
		    pcep_metric_type_name(obj->type), obj->type);
	PCEP_FORMAT("%*sflag_b: %u\n", ps, "", obj->flag_b);
	PCEP_FORMAT("%*sflag_c: %u\n", ps, "", obj->flag_c);
	PCEP_FORMAT("%*svalue: %f\n", ps, "", obj->value);
}

void _format_pcep_object_bandwidth(int ps, struct pcep_object_bandwidth *obj)
{
	PCEP_FORMAT("%*sbandwidth: %f\n", ps, "", obj->bandwidth);
}

void _format_pcep_object_ro(int ps, struct pcep_object_ro *obj)
{
	double_linked_list *obj_list = obj->sub_objects;
	double_linked_list_node *node;
	struct pcep_object_ro_subobj *sub_obj;

	int ps2 = ps + DEBUG_IDENT_SIZE;
	int i;

	if ((obj_list == NULL) || (obj_list->num_entries == 0)) {
		PCEP_FORMAT("%*ssub_objects: []\n", ps, "");
		return;
	}

	PCEP_FORMAT("%*ssub_objects:\n", ps, "");

	for (node = obj_list->head, i = 0; node != NULL;
	     node = node->next_node, i++) {
		sub_obj = (struct pcep_object_ro_subobj *)node->data;
		PCEP_FORMAT("%*s- flag_subobj_loose_hop: %u\n", ps2 - 2, "",
			    sub_obj->flag_subobj_loose_hop);
		PCEP_FORMAT("%*sro_subobj_type: %s (%u)\n", ps2, "",
			    pcep_ro_type_name(sub_obj->ro_subobj_type),
			    sub_obj->ro_subobj_type);
		_format_pcep_object_ro_details(ps2, sub_obj);
	}
}

void _format_pcep_object_ro_details(int ps, struct pcep_object_ro_subobj *ro)
{
	switch (ro->ro_subobj_type) {
	case RO_SUBOBJ_TYPE_IPV4:
		_format_pcep_object_ro_ipv4(ps,
					    (struct pcep_ro_subobj_ipv4 *)ro);
		break;
	case RO_SUBOBJ_TYPE_SR_DRAFT07:
	case RO_SUBOBJ_TYPE_SR:
		_format_pcep_object_ro_sr(ps, (struct pcep_ro_subobj_sr *)ro);
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
	PCEP_FORMAT("%*sflag_local_protection: %u\n", ps, "",
		    obj->flag_local_protection);
}

void _format_pcep_object_ro_sr(int ps, struct pcep_ro_subobj_sr *obj)
{
	PCEP_FORMAT("%*snai_type = %s (%u)\n", ps, "",
		    pcep_nai_type_name(obj->nai_type), obj->nai_type);
	PCEP_FORMAT("%*sflag_f: %u\n", ps, "", obj->flag_f);
	PCEP_FORMAT("%*sflag_s: %u\n", ps, "", obj->flag_s);
	PCEP_FORMAT("%*sflag_c: %u\n", ps, "", obj->flag_c);
	PCEP_FORMAT("%*sflag_m: %u\n", ps, "", obj->flag_m);

	if (!obj->flag_s) {
		PCEP_FORMAT("%*sSID: %u\n", ps, "", obj->sid);
		if (obj->flag_m) {
			PCEP_FORMAT("%*slabel: %u\n", ps, "",
				    GET_SR_ERO_SID_LABEL(obj->sid));
			if (obj->flag_c) {
				PCEP_FORMAT("%*sTC: %u\n", ps, "",
					    GET_SR_ERO_SID_TC(obj->sid));
				PCEP_FORMAT("%*sS: %u\n", ps, "",
					    GET_SR_ERO_SID_S(obj->sid));
				PCEP_FORMAT("%*sTTL: %u\n", ps, "",
					    GET_SR_ERO_SID_TTL(obj->sid));
			}
		}
	}

	if (!obj->flag_f) {
		struct in_addr *laddr4, *raddr4;
		struct in6_addr *laddr6, *raddr6;
		uint32_t *liface, *riface;
		assert(obj->nai_list != NULL);
		double_linked_list_node *n = obj->nai_list->head;
		assert(n != NULL);
		assert(n->data != NULL);
		switch (obj->nai_type) {
		case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
			laddr4 = (struct in_addr *)n->data;
			PCEP_FORMAT("%*sNAI: %pI4\n", ps, "", laddr4);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
			laddr6 = (struct in6_addr *)n->data;
			PCEP_FORMAT("%*sNAI: %pI6\n", ps, "", laddr6);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
			assert(n->next_node != NULL);
			assert(n->next_node->data != NULL);
			laddr4 = (struct in_addr *)n->data;
			raddr4 = (struct in_addr *)n->next_node->data;
			PCEP_FORMAT("%*sNAI: %pI4/%pI4\n", ps, "", laddr4,
				    raddr4);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
			assert(n->next_node != NULL);
			assert(n->next_node->data != NULL);
			laddr6 = (struct in6_addr *)n->data;
			raddr6 = (struct in6_addr *)n->next_node->data;
			PCEP_FORMAT("%*sNAI: %pI6/%pI6\n", ps, "", laddr6,
				    raddr6);
			break;
		case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
			laddr4 = (struct in_addr *)n->data;
			n = n->next_node;
			assert(n != NULL);
			assert(n->data != NULL);
			liface = (uint32_t *)n->data;
			n = n->next_node;
			assert(n != NULL);
			assert(n->data != NULL);
			raddr4 = (struct in_addr *)n->data;
			assert(n != NULL);
			assert(n->data != NULL);
			riface = (uint32_t *)n->data;
			PCEP_FORMAT("%*sNAI: %pI4(%u)/%pI4(%u)\n", ps, "",
				    laddr4, *liface, raddr4, *riface);
			break;
		default:
			PCEP_FORMAT("%*sNAI: UNSUPPORTED\n", ps, "");
			break;
		}
	}
}

void _format_pcep_object_tlvs(int ps, struct pcep_object_header *obj)
{
	double_linked_list *tlv_list = obj->tlv_list;
	struct pcep_object_tlv_header *tlv;
	double_linked_list_node *node;
	int ps2 = ps + DEBUG_IDENT_SIZE;
	int i = 0;

	if (tlv_list == NULL)
		return;
	if (tlv_list->num_entries == 0) {
		PCEP_FORMAT("%*stlvs: []\n", ps, "");
		return;
	}

	PCEP_FORMAT("%*stlvs:\n", ps, "");

	for (node = tlv_list->head, i = 0; node != NULL;
	     node = node->next_node, i++) {
		tlv = (struct pcep_object_tlv_header *)node->data;
		PCEP_FORMAT("%*s- ", ps2 - 2, "");
		_format_pcep_object_tlv(ps2, tlv);
	}
}

void _format_pcep_object_tlv(int ps, struct pcep_object_tlv_header *tlv_header)
{
	PCEP_FORMAT("type: %s (%u)\n", pcep_tlv_type_name(tlv_header->type),
		    tlv_header->type);
	_format_pcep_object_tlv_details(ps, tlv_header);
}

void _format_pcep_object_tlv_details(int ps,
				     struct pcep_object_tlv_header *tlv_header)
{
	switch (tlv_header->type) {
	case PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME:
		_format_pcep_object_tlv_symbolic_path_name(
			ps, (struct pcep_object_tlv_symbolic_path_name *)
				    tlv_header);
		break;
	case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
		_format_pcep_object_tlv_stateful_pce_capability(
			ps, (struct pcep_object_tlv_stateful_pce_capability *)
				    tlv_header);
		break;
	case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
		_format_pcep_object_tlv_sr_pce_capability(
			ps,
			(struct pcep_object_tlv_sr_pce_capability *)tlv_header);
		break;
	case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
		_format_pcep_object_tlv_path_setup_type(
			ps,
			(struct pcep_object_tlv_path_setup_type *)tlv_header);
		break;
	default:
		PCEP_FORMAT("%*s...\n", ps, "");
		break;
	}
}

void _format_pcep_object_tlv_symbolic_path_name(
	int ps, struct pcep_object_tlv_symbolic_path_name *tlv)
{
	PCEP_FORMAT("%*ssymbolic_path_name: %.*s\n", ps, "",
		    tlv->symbolic_path_name_length, tlv->symbolic_path_name);
}

void _format_pcep_object_tlv_stateful_pce_capability(
	int ps, struct pcep_object_tlv_stateful_pce_capability *tlv)
{
	PCEP_FORMAT("%*sflag_u_lsp_update_capability: %u\n", ps, "",
		    tlv->flag_u_lsp_update_capability);
	PCEP_FORMAT("%*sflag_s_include_db_version: %u\n", ps, "",
		    tlv->flag_s_include_db_version);
	PCEP_FORMAT("%*sflag_i_lsp_instantiation_capability: %u\n", ps, "",
		    tlv->flag_i_lsp_instantiation_capability);
	PCEP_FORMAT("%*sflag_t_triggered_resync: %u\n", ps, "",
		    tlv->flag_t_triggered_resync);
	PCEP_FORMAT("%*sflag_d_delta_lsp_sync: %u\n", ps, "",
		    tlv->flag_d_delta_lsp_sync);
	PCEP_FORMAT("%*sflag_f_triggered_initial_sync: %u\n", ps, "",
		    tlv->flag_f_triggered_initial_sync);
}

void _format_pcep_object_tlv_sr_pce_capability(
	int ps, struct pcep_object_tlv_sr_pce_capability *tlv)
{

	PCEP_FORMAT("%*sflag_n: %u\n", ps, "", tlv->flag_n);
	PCEP_FORMAT("%*sflag_x: %u\n", ps, "", tlv->flag_x);
	PCEP_FORMAT("%*smax_sid_depth: %u\n", ps, "", tlv->max_sid_depth);
}

void _format_pcep_object_tlv_path_setup_type(
	int ps, struct pcep_object_tlv_path_setup_type *tlv)
{
	PCEP_FORMAT("%*spath_setup_type: %u\n", ps, "", tlv->path_setup_type);
}
