// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#include <zebra.h>

#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <libyang/libyang.h>

#include "printfrr.h"
#include "ipaddr.h"

#include "pathd/path_pcep_debug.h"

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
static void _format_pcep_object_lspa(int psps, struct pcep_object_lspa *obj);
static void
_format_pcep_object_ipv4_endpoint(int ps,
				  struct pcep_object_endpoints_ipv4 *obj);
static void _format_pcep_object_metric(int ps, struct pcep_object_metric *obj);
static void _format_pcep_object_bandwidth(int ps,
					  struct pcep_object_bandwidth *obj);
static void _format_pcep_object_nopath(int ps, struct pcep_object_nopath *obj);
static void
_format_pcep_object_objfun(int ps, struct pcep_object_objective_function *obj);
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
	}

	assert(!"Reached end of function where we do not expect to");
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
	case PCC_CONNECTION_FAILURE:
		return "PCC_CONNECTION_FAILURE";
	case PCC_SENT_INVALID_OPEN:
		return "PCC_SENT_INVALID_OPEN";
	}

	assert(!"Reached end of function where we do not expect to");
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
	case PCEP_ERRT_UNRECOGNIZED_EXRS_SUBOBJ:
		return "UNRECOGNIZED_EXRS_SUBOBJ";
	case PCEP_ERRT_DIFFSERV_AWARE_TE_ERROR:
		return "DIFFSERV_AWARE_TE_ERROR";
	case PCEP_ERRT_BRPC_PROC_COMPLETION_ERROR:
		return "BRPC_PROC_COMPLETION_ERROR";
	case PCEP_ERRT_UNASSIGNED14:
		return "UNASSIGNED14";
	case PCEP_ERRT_GLOBAL_CONCURRENT_ERROR:
		return "GLOBAL_CONCURRENT_ERROR";
	case PCEP_ERRT_P2PMP_CAP_ERROR:
		return "P2PMP_CAP_ERROR";
	case PCEP_ERRT_P2P_ENDPOINTS_ERROR:
		return "P2P_ENDPOINTS_ERROR";
	case PCEP_ERRT_P2P_FRAGMENTATION_ERROR:
		return "P2P_FRAGMENTATION_ERROR";
	case PCEP_ERRT_INVALID_OPERATION:
		return "INVALID_OPERATION";
	case PCEP_ERRT_LSP_STATE_SYNC_ERROR:
		return "LSP_STATE_SYNC_ERROR";
	case PCEP_ERRT_INVALID_TE_PATH_SETUP_TYPE:
		return "INVALID_TE_PATH_SETUP_TYPE";
	case PCEP_ERRT_UNASSIGNED22:
		return "UNASSIGNED22";
	case PCEP_ERRT_BAD_PARAMETER_VALUE:
		return "BAD_PARAMETER_VALUE";
	case PCEP_ERRT_LSP_INSTANTIATE_ERROR:
		return "LSP_INSTANTIATE_ERROR";
	case PCEP_ERRT_START_TLS_FAILURE:
		return "START_TLS_FAILURE";
	case PCEP_ERRT_ASSOCIATION_ERROR:
		return "ASSOCIATION_ERROR";
	case PCEP_ERRT_WSON_RWA_ERROR:
		return "WSON_RWA_ERROR";
	case PCEP_ERRT_H_PCE_ERROR:
		return "H_PCE_ERROR";
	case PCEP_ERRT_PATH_COMP_FAILURE:
		return "PATH_COMP_FAILURE";
	case PCEP_ERRT_UNASSIGNED30:
		return "UNASSIGNED30";
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
	case TUP(PCEP_ERRT_UNRECOGNIZED_EXRS_SUBOBJ, PCEP_ERRV_UNASSIGNED):
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
	case TUP(PCEP_ERRT_SESSION_FAILURE,
		 PCEP_ERRV_PCEP_VERSION_NOT_SUPPORTED):
		return "PCEP_VERSION_NOT_SUPPORTED";

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
	case TUP(PCEP_ERRT_NOT_SUPPORTED_OBJECT, PCEP_ERRV_UNSUPPORTED_PARAM):
		return "UNSUPPORTED_PARAM";
	case TUP(PCEP_ERRT_NOT_SUPPORTED_OBJECT,
		 PCEP_ERRV_UNSUPPORTED_NW_PERF_CONSTRAINT):
		return "UNSUPPORTED_NW_PERF_CONSTRAINT";
	case TUP(PCEP_ERRT_NOT_SUPPORTED_OBJECT,
		 PCEP_ERRV_NOT_SUPPORTED_BW_OBJECT_3_4):
		return "NOT_SUPPORTED_BW_OBJECT_3_4";
	case TUP(PCEP_ERRT_NOT_SUPPORTED_OBJECT,
		 PCEP_ERRV_UNSUPPORTED_ENDPOINT_TYPE):
		return "UNSUPPORTED_ENDPOINT_TYPE";
	case TUP(PCEP_ERRT_NOT_SUPPORTED_OBJECT,
		 PCEP_ERRV_UNSUPPORTED_ENDPOINT_TLV):
		return "UNSUPPORTED_ENDPOINT_TLV";
	case TUP(PCEP_ERRT_NOT_SUPPORTED_OBJECT,
		 PCEP_ERRV_UNSUPPORTED_RP_FLAG_GRANULARITY):
		return "UNSUPPORTED_RP_FLAG_GRANULARITY";

	case TUP(PCEP_ERRT_POLICY_VIOLATION,
		 PCEP_ERRV_C_BIT_SET_IN_METRIC_OBJECT):
		return "C_BIT_SET_IN_METRIC_OBJECT";
	case TUP(PCEP_ERRT_POLICY_VIOLATION,
		 PCEP_ERRV_O_BIT_CLEARD_IN_RP_OBJECT):
		return "O_BIT_CLEARD_IN_RP_OBJECT";
	case TUP(PCEP_ERRT_POLICY_VIOLATION,
		 PCEP_ERRV_OBJECTIVE_FUNC_NOT_ALLOWED):
		return "OBJECTIVE_FUNC_NOT_ALLOWED";
	case TUP(PCEP_ERRT_POLICY_VIOLATION, PCEP_ERRV_RP_OF_BIT_SET):
		return "RP_OF_BIT_SET";
	case TUP(PCEP_ERRT_POLICY_VIOLATION,
		 PCEP_ERRV_GLOBAL_CONCURRENCY_NOT_ALLOWED):
		return "GLOBAL_CONCURRENCY_NOT_ALLOWED";
	case TUP(PCEP_ERRT_POLICY_VIOLATION, PCEP_ERRV_MONITORING_MSG_REJECTED):
		return "MONITORING_MSG_REJECTED";
	case TUP(PCEP_ERRT_POLICY_VIOLATION,
		 PCEP_ERRV_P2MP_PATH_COMP_NOT_ALLOWED):
		return "P2MP_PATH_COMP_NOT_ALLOWED";
	case TUP(PCEP_ERRT_POLICY_VIOLATION,
		 PCEP_ERRV_UNALLOWED_NW_PERF_CONSTRAINT):
		return "UNALLOWED_NW_PERF_CONSTRAINT";

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
		 PCEP_ERRV_MONITOR_OBJECT_MISSING):
		return "MONITOR_OBJECT_MISSING";
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
	case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
		 PCEP_ERRV_LSP_DB_TLV_MISSING):
		return "LSP_DB_TLV_MISSING";
	case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
		 PCEP_ERRV_S2LS_OBJECT_MISSING):
		return "S2LS_OBJECT_MISSING";
	case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
		 PCEP_ERRV_P2MP_LSP_ID_TLV_MISSING):
		return "P2MP_LSP_ID_TLV_MISSING";
	case TUP(PCEP_ERRT_MANDATORY_OBJECT_MISSING,
		 PCEP_ERRV_DISJOINTED_CONF_TLV_MISSING):
		return "DISJOINTED_CONF_TLV_MISSING";

	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_P_FLAG_NOT_CORRECT_IN_OBJECT):
		return "P_FLAG_NOT_CORRECT_IN_OBJECT";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_BAD_LABEL_VALUE):
		return "BAD_LABEL_VALUE";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_UNSUPPORTED_NUM_SR_ERO_SUBOBJECTS):
		return "UNSUPPORTED_NUM_SR_ERO_SUBOBJECTS";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_BAD_LABEL_FORMAT):
		return "BAD_LABEL_FORMAT";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_ERO_SR_ERO_MIX):
		return "ERO_SR_ERO_MIX";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_SR_ERO_SID_NAI_ABSENT):
		return "SR_ERO_SID_NAI_ABSENT";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_SR_RRO_SID_NAI_ABSENT):
		return "SR_RRO_SID_NAI_ABSENT";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_SYMBOLIC_PATH_NAME_TLV_MISSING):
		return "SYMBOLIC_PATH_NAME_TLV_MISSING";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_MSD_EXCEEDS_PCEP_SESSION_MAX):
		return "MSD_EXCEEDS_PCEP_SESSION_MAX";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_RRO_SR_RRO_MIX):
		return "RRO_SR_RRO_MIX";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_MALFORMED_OBJECT):
		return "MALFORMED_OBJECT";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_MISSING_PCE_SR_CAP_TLV):
		return "MISSING_PCE_SR_CAP_TLV";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_UNSUPPORTED_NAI):
		return "UNSUPPORTED_NAI";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_UNKNOWN_SID):
		return "UNKNOWN_SID";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_CANNOT_RESOLVE_NAI_TO_SID):
		return "CANNOT_RESOLVE_NAI_TO_SID";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_COULD_NOT_FIND_SRGB):
		return "COULD_NOT_FIND_SRGB";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_SID_EXCEEDS_SRGB):
		return "SID_EXCEEDS_SRGB";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_COULD_NOT_FIND_SRLB):
		return "COULD_NOT_FIND_SRLB";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_SID_EXCEEDS_SRLB):
		return "SID_EXCEEDS_SRLB";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT, PCEP_ERRV_INCONSISTENT_SID):
		return "INCONSISTENT_SID";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_MSD_MUST_BE_NONZERO):
		return "MSD_MUST_BE_NONZERO";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_MISMATCH_O_S2LS_LSP):
		return "MISMATCH_O_S2LS_LSP";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_INCOMPATIBLE_H_PCE_OF):
		return "INCOMPATIBLE_H_PCE_OF";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_BAD_BANDWIDTH_TYPE_3_4):
		return "BAD_BANDWIDTH_TYPE_3_4";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_UNSUPPORTED_LSP_PROT_FLAGS):
		return "UNSUPPORTED_LSP_PROT_FLAGS";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_UNSUPPORTED_2ND_LSP_PROT_FLAGS):
		return "UNSUPPORTED_2ND_LSP_PROT_FLAGS";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_UNSUPPORTED_LINK_PROT_TYPE):
		return "UNSUPPORTED_LINK_PROT_TYPE";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_LABEL_SET_TLV_NO_RP_R):
		return "LABEL_SET_TLV_NO_RP_R";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_WRONG_LABEL_SET_TLV_O_L_SET):
		return "WRONG_LABEL_SET_TLV_O_L_SET";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_WRONG_LABEL_SET_O_SET):
		return "WRONG_LABEL_SET_O_SET";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_MISSING_GMPLS_CAP_TLV):
		return "MISSING_GMPLS_CAP_TLV";
	case TUP(PCEP_ERRT_RECEPTION_OF_INV_OBJECT,
		 PCEP_ERRV_INCOMPATIBLE_OF_CODE):
		return "INCOMPATIBLE_OF_CODE";

	case TUP(PCEP_ERRT_DIFFSERV_AWARE_TE_ERROR,
		 PCEP_ERRV_UNSUPPORTED_CLASS_TYPE):
		return "UNSUPPORTED_CLASS_TYPE";
	case TUP(PCEP_ERRT_DIFFSERV_AWARE_TE_ERROR,
		 PCEP_ERRV_INVALID_CLASS_TYPE):
		return "INVALID_CLASS_TYPE";
	case TUP(PCEP_ERRT_DIFFSERV_AWARE_TE_ERROR,
		 PCEP_ERRV_CLASS_SETUP_TYPE_NOT_TE_CLASS):
		return "CLASS_SETUP_TYPE_NOT_TE_CLASS";

	case TUP(PCEP_ERRT_BRPC_PROC_COMPLETION_ERROR,
		 PCEP_ERRV_BRPC_PROC_NOT_SUPPORTED):
		return "BRPC_PROC_NOT_SUPPORTED";

	case TUP(PCEP_ERRT_GLOBAL_CONCURRENT_ERROR,
		 PCEP_ERRV_INSUFFICIENT_MEMORY):
		return "INSUFFICIENT_MEMORY";
	case TUP(PCEP_ERRT_GLOBAL_CONCURRENT_ERROR,
		 PCEP_ERRV_GLOBAL_CONCURRENT_OPT_NOT_SUPPORTED):
		return "GLOBAL_CONCURRENT_OPT_NOT_SUPPORTED";

	case TUP(PCEP_ERRT_P2PMP_CAP_ERROR, PCEP_ERRV_PCE_INSUFFICIENT_MEMORY):
		return "PCE_INSUFFICIENT_MEMORY";
	case TUP(PCEP_ERRT_P2PMP_CAP_ERROR,
		 PCEP_ERRV_PCE_NOT_CAPABLE_P2MP_COMP):
		return "PCE_NOT_CAPABLE_P2MP_COMP";

	case TUP(PCEP_ERRT_P2P_ENDPOINTS_ERROR,
		 PCEP_ERRV_NO_EP_WITH_LEAF_TYPE2):
		return "NO_EP_WITH_LEAF_TYPE2";
	case TUP(PCEP_ERRT_P2P_ENDPOINTS_ERROR,
		 PCEP_ERRV_NO_EP_WITH_LEAF_TYPE3):
		return "NO_EP_WITH_LEAF_TYPE3";
	case TUP(PCEP_ERRT_P2P_ENDPOINTS_ERROR,
		 PCEP_ERRV_NO_EP_WITH_LEAF_TYPE4):
		return "NO_EP_WITH_LEAF_TYPE4";
	case TUP(PCEP_ERRT_P2P_ENDPOINTS_ERROR, PCEP_ERRV_INCONSITENT_EP):
		return "INCONSITENT_EP";

	case TUP(PCEP_ERRT_P2P_FRAGMENTATION_ERROR,
		 PCEP_ERRV_FRAG_REQUEST_FAILURE):
		return "FRAG_REQUEST_FAILURE";
	case TUP(PCEP_ERRT_P2P_FRAGMENTATION_ERROR,
		 PCEP_ERRV_FRAG_REPORT_FAILURE):
		return "FRAG_REPORT_FAILURE";
	case TUP(PCEP_ERRT_P2P_FRAGMENTATION_ERROR,
		 PCEP_ERRV_FRAG_UPDATE_FAILURE):
		return "FRAG_UPDATE_FAILURE";
	case TUP(PCEP_ERRT_P2P_FRAGMENTATION_ERROR,
		 PCEP_ERRV_FRAG_INSTANTIATION_FAILURE):
		return "FRAG_INSTANTIATION_FAILURE";

	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_UPDATE_FOR_NON_DELEGATED_LSP):
		return "LSP_UPDATE_FOR_NON_DELEGATED_LS";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_UPDATE_NON_ADVERTISED_PCE):
		return "LSP_UPDATE_NON_ADVERTISED_PC";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_UPDATE_UNKNOWN_PLSP_ID):
		return "LSP_UPDATE_UNKNOWN_PLSP_I";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_REPORT_NON_ADVERTISED_PCE):
		return "LSP_REPORT_NON_ADVERTISED_PC";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_PCE_INIT_LSP_LIMIT_REACHED):
		return "PCE_INIT_LSP_LIMIT_REACHE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_PCE_INIT_LSP_DELEGATION_CANT_REVOKE):
		return "PCE_INIT_LSP_DELEGATION_CANT_REVOK";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_INIT_NON_ZERO_PLSP_ID):
		return "LSP_INIT_NON_ZERO_PLSP_I";
	case TUP(PCEP_ERRT_INVALID_OPERATION, PCEP_ERRV_LSP_NOT_PCE_INITIATED):
		return "LSP_NOT_PCE_INITIATE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_PCE_INIT_OP_FREQ_LIMIT_REACHED):
		return "PCE_INIT_OP_FREQ_LIMIT_REACHE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_REPORT_P2MP_NOT_ADVERTISED):
		return "LSP_REPORT_P2MP_NOT_ADVERTISE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_UPDATE_P2MP_NOT_ADVERTISED):
		return "LSP_UPDATE_P2MP_NOT_ADVERTISE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_LSP_INSTANTIATION_P2MP_NOT_ADVERTISED):
		return "LSP_INSTANTIATION_P2MP_NOT_ADVERTISE";
	case TUP(PCEP_ERRT_INVALID_OPERATION,
		 PCEP_ERRV_AUTO_BW_CAP_NOT_ADVERTISED):
		return "AUTO_BW_CAP_NOT_ADVERTISE";

	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_PCE_CANT_PROCESS_LSP_REPORT):
		return "PCE_CANT_PROCESS_LSP_REPORT";
	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_LSP_DB_VERSION_MISMATCH):
		return "LSP_DB_VERSION_MISMATCH";
	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_TRIGGER_ATTEMPT_BEFORE_PCE_TRIGGER):
		return "TRIGGER_ATTEMPT_BEFORE_PCE_TRIGGER";
	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_TRIGGER_ATTEMPT_NO_PCE_TRIGGER_CAP):
		return "TRIGGER_ATTEMPT_NO_PCE_TRIGGER_CAP";
	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_PCC_CANT_COMPLETE_STATE_SYNC):
		return "PCC_CANT_COMPLETE_STATE_SYNC";
	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_INVALID_LSP_DB_VERSION_NUMBER):
		return "INVALID_LSP_DB_VERSION_NUMBER";
	case TUP(PCEP_ERRT_LSP_STATE_SYNC_ERROR,
		 PCEP_ERRV_INVALID_SPEAKER_ENTITY_ID):
		return "INVALID_SPEAKER_ENTITY_ID";

	case TUP(PCEP_ERRT_INVALID_TE_PATH_SETUP_TYPE,
		 PCEP_ERRV_UNSUPPORTED_PATH_SETUP_TYPE):
		return "UNSUPPORTED_PATH_SETUP_TYPE";
	case TUP(PCEP_ERRT_INVALID_TE_PATH_SETUP_TYPE,
		 PCEP_ERRV_MISMATCHED_PATH_SETUP_TYPE):
		return "MISMATCHED_PATH_SETUP_TYPE";

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

	case TUP(PCEP_ERRT_START_TLS_FAILURE,
		 PCEP_ERRV_START_TLS_AFTER_PCEP_EXCHANGE):
		return "START_TLS_AFTER_PCEP_EXCHANGE";
	case TUP(PCEP_ERRT_START_TLS_FAILURE,
		 PCEP_ERRV_MSG_NOT_START_TLS_OPEN_ERROR):
		return "MSG_NOT_START_TLS_OPEN_ERROR";
	case TUP(PCEP_ERRT_START_TLS_FAILURE,
		 PCEP_ERRV_CONNECTION_WO_TLS_NOT_POSSIBLE):
		return "CONNECTION_WO_TLS_NOT_POSSIBLE";
	case TUP(PCEP_ERRT_START_TLS_FAILURE,
		 PCEP_ERRV_CONNECTION_WO_TLS_IS_POSSIBLE):
		return "CONNECTION_WO_TLS_IS_POSSIBLE";
	case TUP(PCEP_ERRT_START_TLS_FAILURE,
		 PCEP_ERRV_NO_START_TLS_BEFORE_START_TLS_WAIT_TIMER):
		return "NO_START_TLS_BEFORE_START_TLS_WAIT_TIMER";

	case TUP(PCEP_ERRT_ASSOCIATION_ERROR,
		 PCEP_ERRV_ASSOC_TYPE_NOT_SUPPORTED):
		return "ASSOC_TYPE_NOT_SUPPORTED";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR,
		 PCEP_ERRV_TOO_MANY_LSPS_IN_ASSOC_GRP):
		return "TOO_MANY_LSPS_IN_ASSOC_GRP";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR, PCEP_ERRV_TOO_MANY_ASSOC_GROUPS):
		return "TOO_MANY_ASSOC_GROUPS";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR, PCEP_ERRV_ASSOCIATION_UNKNOWN):
		return "ASSOCIATION_UNKNOWN";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR,
		 PCEP_ERRV_OP_CONF_ASSOC_INFO_MISMATCH):
		return "OP_CONF_ASSOC_INFO_MISMATCH";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR, PCEP_ERRV_ASSOC_INFO_MISMATCH):
		return "ASSOC_INFO_MISMATCH";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR,
		 PCEP_ERRV_CANNOT_JOIN_ASSOC_GROUP):
		return "CANNOT_JOIN_ASSOC_GROUP";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR, PCEP_ERRV_ASSOC_ID_NOT_IN_RANGE):
		return "ASSOC_ID_NOT_IN_RANGE";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR,
		 PCEP_ERRV_TUNNEL_EP_MISMATCH_PATH_PROT_ASSOC):
		return "TUNNEL_EP_MISMATCH_PATH_PROT_ASSOC";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR,
		 PCEP_ERRV_ATTEMPTED_ADD_LSP_PATH_PROT_ASSOC):
		return "ATTEMPTED_ADD_LSP_PATH_PROT_ASSOC";
	case TUP(PCEP_ERRT_ASSOCIATION_ERROR,
		 PCEP_ERRV_PROTECTION_TYPE_NOT_SUPPORTED):
		return "PROTECTION_TYPE_NOT_SUPPORTED";

	case TUP(PCEP_ERRT_WSON_RWA_ERROR, PCEP_ERRV_RWA_INSUFFICIENT_MEMORY):
		return "RWA_INSUFFICIENT_MEMORY";
	case TUP(PCEP_ERRT_WSON_RWA_ERROR, PCEP_ERRV_RWA_COMP_NOT_SUPPORTED):
		return "RWA_COMP_NOT_SUPPORTED";
	case TUP(PCEP_ERRT_WSON_RWA_ERROR, PCEP_ERRV_SYNTAX_ENC_ERROR):
		return "SYNTAX_ENC_ERROR";

	case TUP(PCEP_ERRT_H_PCE_ERROR, PCEP_ERRV_H_PCE_CAP_NOT_ADVERTISED):
		return "H_PCE_CAP_NOT_ADVERTISED";
	case TUP(PCEP_ERRT_H_PCE_ERROR,
		 PCEP_ERRV_PARENT_PCE_CAP_CANT_BE_PROVIDED):
		return "PARENT_PCE_CAP_CANT_BE_PROVIDED";

	case TUP(PCEP_ERRT_PATH_COMP_FAILURE,
		 PCEP_ERRV_UNACCEPTABLE_REQUEST_MSG):
		return "UNACCEPTABLE_REQUEST_MSG";
	case TUP(PCEP_ERRT_PATH_COMP_FAILURE,
		 PCEP_ERRV_GENERALIZED_BW_VAL_NOT_SUPPORTED):
		return "GENERALIZED_BW_VAL_NOT_SUPPORTED";
	case TUP(PCEP_ERRT_PATH_COMP_FAILURE,
		 PCEP_ERRV_LABEL_SET_CONSTRAINT_COULD_NOT_BE_MET):
		return "LABEL_SET_CONSTRAINT_COULD_NOT_BE_MET";
	case TUP(PCEP_ERRT_PATH_COMP_FAILURE,
		 PCEP_ERRV_LABEL_CONSTRAINT_COULD_NOT_BE_MET):
		return "LABEL_CONSTRAINT_COULD_NOT_BE_MET";

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
	case PCEP_TYPE_START_TLS:
		return "START_TLS";
	case PCEP_TYPE_MAX:
		return "UNKNOWN";
	}

	assert(!"Reached end of function where we are not expecting to");
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
	case PCEP_OBJ_CLASS_OF:
		return "OF";
	case PCEP_OBJ_CLASS_LSP:
		return "LSP";
	case PCEP_OBJ_CLASS_SRP:
		return "SRP";
	case PCEP_OBJ_CLASS_VENDOR_INFO:
		return "VENDOR_INFO";
	case PCEP_OBJ_CLASS_INTER_LAYER:
		return "INTER_LAYER";
	case PCEP_OBJ_CLASS_SWITCH_LAYER:
		return "SWITCH_LAYER";
	case PCEP_OBJ_CLASS_REQ_ADAP_CAP:
		return "REQ_ADAP_CAP";
	case PCEP_OBJ_CLASS_SERVER_IND:
		return "SERVER_IND";
	case PCEP_OBJ_CLASS_ASSOCIATION:
		return "ASSOCIATION";
	case PCEP_OBJ_CLASS_MAX:
		return "UNKNOWN";
	}

	assert(!"Reached end of function where we are not expecting to");
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
	case TUP(PCEP_OBJ_CLASS_INTER_LAYER, PCEP_OBJ_TYPE_INTER_LAYER):
		return "INTER_LAYER";
	case TUP(PCEP_OBJ_CLASS_SWITCH_LAYER, PCEP_OBJ_TYPE_SWITCH_LAYER):
		return "SWITCH_LAYER";
	case TUP(PCEP_OBJ_CLASS_REQ_ADAP_CAP, PCEP_OBJ_TYPE_REQ_ADAP_CAP):
		return "REQ_ADAP_CAP";
	case TUP(PCEP_OBJ_CLASS_SERVER_IND, PCEP_OBJ_TYPE_SERVER_IND):
		return "SERVER_IND";
	case TUP(PCEP_OBJ_CLASS_ASSOCIATION, PCEP_OBJ_TYPE_ASSOCIATION_IPV4):
		return "ASSOCIATION_IPV4";
	case TUP(PCEP_OBJ_CLASS_ASSOCIATION, PCEP_OBJ_TYPE_ASSOCIATION_IPV6):
		return "ASSOCIATION_IPV6";
	case TUP(PCEP_OBJ_CLASS_OF, PCEP_OBJ_TYPE_OF):
		return "OF";
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
	}

	assert(!"Reached end of function where we do not expect to");
}


const char *pcep_tlv_type_name(enum pcep_object_tlv_types tlv_type)
{
	switch (tlv_type) {
	case PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR:
		return "NO_PATH_VECTOR";
	case PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST:
		return "OBJECTIVE_FUNCTION_LIST";
	case PCEP_OBJ_TLV_TYPE_VENDOR_INFO:
		return "VENDOR_INFO";
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
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID:
		return "SRPOLICY_POL_ID";
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME:
		return "SRPOLICY_POL_NAME";
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID:
		return "SRPOLICY_CPATH_ID";
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE:
		return "SRPOLICY_CPATH_PREFERENCE";
	case PCEP_OBJ_TLV_TYPE_UNKNOWN:
		return "UNKNOWN";
	case PCEP_OBJ_TLV_TYPE_ARBITRARY:
		return "ARBITRARY";
	case PCEP_OBJ_TYPE_CISCO_BSID:
		return "CISCO_BSID";
	}

	assert(!"Reached end of function where we do not expect to");
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
	case RO_SUBOBJ_UNKNOWN:
		return "UNKNOWN";
	}

	assert(!"Reached end of function where we do not expect to");
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
	case PCEP_SR_SUBOBJ_NAI_UNKNOWN:
		return "UNKNOWN";
	}

	assert(!"Reached end of function where we do not expect to");
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

const char *pcep_nopath_tlv_err_code_name(enum pcep_nopath_tlv_err_codes type)
{
	switch (type) {
	case PCEP_NOPATH_TLV_ERR_NO_TLV:
		return "NO_TLV";
	case PCEP_NOPATH_TLV_ERR_PCE_UNAVAILABLE:
		return "PCE_UNAVAILABLE";
	case PCEP_NOPATH_TLV_ERR_UNKNOWN_DST:
		return "UNKNOWN_DST";
	case PCEP_NOPATH_TLV_ERR_UNKNOWN_SRC:
		return "UNKNOWN_SRC";
	default:
		return "UNKNOWN";
	}
}

const char *format_objfun_set(uint32_t flags)
{
	int i, c;
	PATHD_FORMAT_INIT();
	for (i = 1, c = 0; i <= MAX_OBJFUN_TYPE; i++) {
		if (CHECK_FLAG(flags, i)) {
			if (c > 0)
				PATHD_FORMAT(", %s", objfun_type_name(i));
			else
				PATHD_FORMAT("%s", objfun_type_name(i));
			c++;
		}
	}
	return PATHD_FORMAT_FINI();
}


const char *format_pcc_opts(struct pcc_opts *opts)
{
	PATHD_FORMAT_INIT();
	_format_pcc_opts(0, opts);
	return PATHD_FORMAT_FINI();
}

const char *format_pcc_state(struct pcc_state *state)
{
	PATHD_FORMAT_INIT();
	_format_pcc_state(0, state);
	return PATHD_FORMAT_FINI();
}

const char *format_ctrl_state(struct ctrl_state *state)
{
	PATHD_FORMAT_INIT();
	_format_ctrl_state(0, state);
	return PATHD_FORMAT_FINI();
}

const char *format_path(struct path *path)
{
	PATHD_FORMAT_INIT();
	_format_path(0, path);
	return PATHD_FORMAT_FINI();
}

const char *format_pcep_event(pcep_event *event)
{
	PATHD_FORMAT_INIT();
	_format_pcep_event(0, event);
	return PATHD_FORMAT_FINI();
}

const char *format_pcep_message(struct pcep_message *msg)
{
	PATHD_FORMAT_INIT();
	_format_pcep_message(0, msg);
	return PATHD_FORMAT_FINI();
}

void _format_pcc_opts(int ps, struct pcc_opts *opts)
{
	if (opts == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PATHD_FORMAT("\n");
		if (IS_IPADDR_V4(&opts->addr)) {
			PATHD_FORMAT("%*saddr_v4: %pI4\n", ps2, "",
				     &opts->addr.ipaddr_v4);
		} else {
			PATHD_FORMAT("%*saddr_v4: undefined", ps2, "");
		}
		if (IS_IPADDR_V6(&opts->addr)) {
			PATHD_FORMAT("%*saddr_v6: %pI6\n", ps2, "",
				     &opts->addr.ipaddr_v6);
		} else {
			PATHD_FORMAT("%*saddr_v6: undefined", ps2, "");
		}
		PATHD_FORMAT("%*sport: %i\n", ps2, "", opts->port);
		PATHD_FORMAT("%*smsd: %i\n", ps2, "", opts->msd);
	}
}

void _format_pce_opts(int ps, struct pce_opts *opts)
{
	if (opts == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PATHD_FORMAT("\n");
		if (IS_IPADDR_V6(&opts->addr)) {
			PATHD_FORMAT("%*saddr: %pI6\n", ps2, "",
				     &opts->addr.ipaddr_v6);
		} else {
			PATHD_FORMAT("%*saddr: %pI4\n", ps2, "",
				     &opts->addr.ipaddr_v4);
		}
		PATHD_FORMAT("%*sport: %i\n", ps2, "", opts->port);
	}
}

void _format_pcc_caps(int ps, struct pcep_caps *caps)
{
	int ps2 = ps + DEBUG_IDENT_SIZE;
	PATHD_FORMAT("\n");
	PATHD_FORMAT("%*sis_stateful: %d\n", ps2, "", caps->is_stateful);
}

void _format_pcc_state(int ps, struct pcc_state *state)
{
	if (state == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PATHD_FORMAT("\n");
		PATHD_FORMAT("%*sstatus: %s\n", ps2, "",
			     pcc_status_name(state->status));
		PATHD_FORMAT("%*spcc_opts: ", ps2, "");
		_format_pcc_opts(ps2, state->pcc_opts);
		PATHD_FORMAT("%*spce_opts: ", ps2, "");
		_format_pce_opts(ps2, state->pce_opts);
		if (state->sess == NULL) {
			PATHD_FORMAT("%*ssess: NULL\n", ps2, "");
		} else {
			PATHD_FORMAT("%*ssess: <PCC SESSION %p>\n", ps2, "",
				     state->sess);
		}
		PATHD_FORMAT("%*scaps: ", ps2, "");
		_format_pcc_caps(ps2, &state->caps);
	}
}

void _format_ctrl_state(int ps, struct ctrl_state *state)
{
	if (state == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		int i;
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int ps3 = ps2 + DEBUG_IDENT_SIZE;
		PATHD_FORMAT("\n");
		if (state->main == NULL) {
			PATHD_FORMAT("%*smain: NULL\n", ps2, "");
		} else {
			PATHD_FORMAT("%*smain: <THREAD MASTER %p>\n", ps2, "",
				     state->main);
		}
		if (state->self == NULL) {
			PATHD_FORMAT("%*sself: NULL\n", ps2, "");
		} else {
			PATHD_FORMAT("%*sself: <THREAD MASTER %p>\n", ps2, "",
				     state->self);
		}
		PATHD_FORMAT("%*spcc_count: %d\n", ps2, "", state->pcc_count);
		PATHD_FORMAT("%*spcc:\n", ps2, "");
		for (i = 0; i < MAX_PCC; i++) {
			if (state->pcc[i]) {
				PATHD_FORMAT("%*s- ", ps3 - 2, "");
				_format_pcc_state(ps3, state->pcc[i]);
			}
		}
	}
}

void _format_path(int ps, struct path *path)
{
	if (path == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int ps3 = ps2 + DEBUG_IDENT_SIZE;
		PATHD_FORMAT("\n");
		PATHD_FORMAT("%*snbkey: \n", ps2, "");
		PATHD_FORMAT("%*scolor: %u\n", ps3, "", path->nbkey.color);
		switch (path->nbkey.endpoint.ipa_type) {
		case IPADDR_V4:
			PATHD_FORMAT("%*sendpoint: %pI4\n", ps3, "",
				     &path->nbkey.endpoint.ipaddr_v4);
			break;
		case IPADDR_V6:
			PATHD_FORMAT("%*sendpoint: %pI6\n", ps3, "",
				     &path->nbkey.endpoint.ipaddr_v6);
			break;
		case IPADDR_NONE:
			PATHD_FORMAT("%*sendpoint: NONE\n", ps3, "");
			break;
		}
		PATHD_FORMAT("%*spreference: %u\n", ps3, "",
			     path->nbkey.preference);

		if (path->sender.ipa_type == IPADDR_V4) {
			PATHD_FORMAT("%*ssender: %pI4\n", ps2, "",
				     &path->sender.ipaddr_v4);
		} else if (path->sender.ipa_type == IPADDR_V6) {
			PATHD_FORMAT("%*ssender: %pI6\n", ps2, "",
				     &path->sender.ipaddr_v6);
		} else {
			PATHD_FORMAT("%*ssender: UNDEFINED\n", ps2, "");
		}
		if (path->pcc_addr.ipa_type == IPADDR_V4) {
			PATHD_FORMAT("%*spcc_addr: %pI4\n", ps2, "",
				     &path->pcc_addr.ipaddr_v4);
		} else if (path->pcc_addr.ipa_type == IPADDR_V6) {
			PATHD_FORMAT("%*spcc_addr: %pI6\n", ps2, "",
				     &path->pcc_addr.ipaddr_v6);
		} else {
			PATHD_FORMAT("%*spcc_addr: UNDEFINED\n", ps2, "");
		}
		PATHD_FORMAT("%*spcc_id: %u\n", ps2, "", path->pcc_id);
		PATHD_FORMAT("%*screate_origin: %s (%u)\n", ps2, "",
			     srte_protocol_origin_name(path->create_origin),
			     path->create_origin);
		PATHD_FORMAT("%*supdate_origin: %s (%u)\n", ps2, "",
			     srte_protocol_origin_name(path->update_origin),
			     path->update_origin);
		if (path->originator != NULL) {
			PATHD_FORMAT("%*soriginator: %s\n", ps2, "",
				     path->originator);
		} else {
			PATHD_FORMAT("%*soriginator: UNDEFINED\n", ps2, "");
		}
		PATHD_FORMAT("%*stype: %s (%u)\n", ps2, "",
			     srte_candidate_type_name(path->type), path->type);
		PATHD_FORMAT("%*splsp_id: %u\n", ps2, "", path->plsp_id);
		if (path->name == NULL) {
			PATHD_FORMAT("%*sname: NULL\n", ps2, "");
		} else {
			PATHD_FORMAT("%*sname: %s\n", ps2, "", path->name);
		}
		PATHD_FORMAT("%*ssrp_id: %u\n", ps2, "", path->srp_id);
		PATHD_FORMAT("%*sreq_id: %u\n", ps2, "", path->req_id);
		PATHD_FORMAT("%*sstatus: %s (%u)\n", ps2, "",
			     pcep_lsp_status_name(path->status), path->status);
		PATHD_FORMAT("%*sdo_remove: %u\n", ps2, "", path->do_remove);
		PATHD_FORMAT("%*sgo_active: %u\n", ps2, "", path->go_active);
		PATHD_FORMAT("%*swas_created: %u\n", ps2, "",
			     path->was_created);
		PATHD_FORMAT("%*swas_removed: %u\n", ps2, "",
			     path->was_removed);
		PATHD_FORMAT("%*sis_synching: %u\n", ps2, "",
			     path->is_synching);
		PATHD_FORMAT("%*sis_delegated: %u\n", ps2, "",
			     path->is_delegated);
		PATHD_FORMAT("%*shas_bandwidth: %u\n", ps2, "",
			     path->has_bandwidth);
		if (path->has_bandwidth) {
			PATHD_FORMAT("%*senforce_bandwidth: %u\n", ps2, "",
				     path->enforce_bandwidth);
			PATHD_FORMAT("%*sbandwidth: %f\n", ps2, "",
				     path->bandwidth);
		}
		PATHD_FORMAT("%*shas_pcc_objfun: %u\n", ps2, "",
			     path->has_pcc_objfun);
		if (path->has_pcc_objfun) {
			PATHD_FORMAT("%*senforce_pcc_objfun: %d\n", ps2, "",
				     path->enforce_pcc_objfun);
			PATHD_FORMAT("%*spcc_objfun: %s (%u)\n", ps2, "",
				     objfun_type_name(path->pcc_objfun),
				     path->pcc_objfun);
		}
		PATHD_FORMAT("%*shas_pce_objfun: %u\n", ps2, "",
			     path->has_pce_objfun);
		if (path->has_pce_objfun)
			PATHD_FORMAT("%*spce_objfun: %s (%u)\n", ps2, "",
				     objfun_type_name(path->pce_objfun),
				     path->pce_objfun);
		PATHD_FORMAT("%*shas_affinity_filters: %u\n", ps2, "",
			     path->has_affinity_filters);
		if (path->has_affinity_filters) {
			PATHD_FORMAT("%*sexclude_any: 0x%08x\n", ps2, "",
				     path->affinity_filters
					     [AFFINITY_FILTER_EXCLUDE_ANY - 1]);
			PATHD_FORMAT("%*sinclude_any: 0x%08x\n", ps2, "",
				     path->affinity_filters
					     [AFFINITY_FILTER_INCLUDE_ANY - 1]);
			PATHD_FORMAT("%*sinclude_all: 0x%08x\n", ps2, "",
				     path->affinity_filters
					     [AFFINITY_FILTER_INCLUDE_ALL - 1]);
		}

		if (path->first_hop == NULL) {
			PATHD_FORMAT("%*shops: []\n", ps2, "");
		} else {
			PATHD_FORMAT("%*shops: \n", ps2, "");
			for (struct path_hop *hop = path->first_hop;
			     hop != NULL; hop = hop->next) {
				PATHD_FORMAT("%*s- ", ps3 - 2, "");
				_format_path_hop(ps3, hop);
			}
		}
		if (path->first_metric == NULL) {
			PATHD_FORMAT("%*smetrics: []\n", ps2, "");
		} else {
			PATHD_FORMAT("%*smetrics: \n", ps2, "");
			for (struct path_metric *metric = path->first_metric;
			     NULL != metric; metric = metric->next) {
				PATHD_FORMAT("%*s- ", ps3 - 2, "");
				_format_path_metric(ps3, metric);
			}
		}
	}
}

void _format_path_metric(int ps, struct path_metric *metric)
{
	PATHD_FORMAT("type: %s (%u)\n", pcep_metric_type_name(metric->type),
		     metric->type);
	PATHD_FORMAT("%*senforce: %u\n", ps, "", metric->enforce);
	PATHD_FORMAT("%*sis_bound: %u\n", ps, "", metric->is_bound);
	PATHD_FORMAT("%*sis_computed: %u\n", ps, "", metric->is_computed);
	PATHD_FORMAT("%*svalue: %f\n", ps, "", metric->value);
}

void _format_path_hop(int ps, struct path_hop *hop)
{
	PATHD_FORMAT("is_loose: %u\n", hop->is_loose);
	PATHD_FORMAT("%*shas_sid: %u\n", ps, "", hop->has_sid);

	if (hop->has_sid) {
		PATHD_FORMAT("%*sis_mpls: %u\n", ps, "", hop->is_mpls);
		if (hop->is_mpls) {
			PATHD_FORMAT("%*shas_attribs: %u\n", ps, "",
				     hop->has_attribs);
			PATHD_FORMAT("%*slabel: %u\n", ps, "",
				     hop->sid.mpls.label);
			if (hop->has_attribs) {
				PATHD_FORMAT("%*straffic_class: %u\n", ps, "",
					     hop->sid.mpls.traffic_class);
				PATHD_FORMAT("%*sis_bottom: %u\n", ps, "",
					     hop->sid.mpls.is_bottom);
				PATHD_FORMAT("%*sttl: %u\n", ps, "",
					     hop->sid.mpls.ttl);
			}
		} else {
			PATHD_FORMAT("%*sSID: %u\n", ps, "", hop->sid.value);
		}
	}

	PATHD_FORMAT("%*shas_nai: %u\n", ps, "", hop->has_nai);
	if (hop->has_nai) {
		PATHD_FORMAT("%*snai_type: %s (%u)\n", ps, "",
			     pcep_nai_type_name(hop->nai.type), hop->nai.type);
		switch (hop->nai.type) {
		case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
			PATHD_FORMAT("%*sNAI: %pI4\n", ps, "",
				     &hop->nai.local_addr.ipaddr_v4);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
			PATHD_FORMAT("%*sNAI: %pI6\n", ps, "",
				     &hop->nai.local_addr.ipaddr_v6);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
			PATHD_FORMAT("%*sNAI: %pI4/%pI4\n", ps, "",
				     &hop->nai.local_addr.ipaddr_v4,
				     &hop->nai.remote_addr.ipaddr_v4);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
			PATHD_FORMAT("%*sNAI: %pI6/%pI6\n", ps, "",
				     &hop->nai.local_addr.ipaddr_v6,
				     &hop->nai.remote_addr.ipaddr_v6);
			break;
		case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
			PATHD_FORMAT("%*sNAI: %pI6(%u)/%pI6(%u)\n", ps, "",
				     &hop->nai.local_addr.ipaddr_v6,
				     hop->nai.local_iface,
				     &hop->nai.remote_addr.ipaddr_v6,
				     hop->nai.remote_iface);
			break;
		case PCEP_SR_SUBOBJ_NAI_ABSENT:
		case PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY:
		case PCEP_SR_SUBOBJ_NAI_UNKNOWN:
			PATHD_FORMAT("%*sNAI: UNSUPPORTED\n", ps, "");
			break;
		}
	}
}

void _format_pcep_event(int ps, pcep_event *event)
{
	char buf[32];

	if (event == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PATHD_FORMAT("\n");
		PATHD_FORMAT("%*sevent_type: %s\n", ps2, "",
			     pcep_event_type_name(event->event_type));
		PATHD_FORMAT("%*sevent_time: %s", ps2, "",
			     ctime_r(&event->event_time, buf));
		if (event->session == NULL) {
			PATHD_FORMAT("%*ssession: NULL\n", ps2, "");
		} else {
			PATHD_FORMAT("%*ssession: <PCC SESSION %p>\n", ps2, "",
				     event->session);
		}
		PATHD_FORMAT("%*smessage: ", ps2, "");
		_format_pcep_message(ps2, event->message);
	}
}

void _format_pcep_message(int ps, struct pcep_message *msg)
{
	if (msg == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		int ps2 = ps + DEBUG_IDENT_SIZE;
		PATHD_FORMAT("\n");
		PATHD_FORMAT("%*spcep_version: %u\n", ps2, "",
			     msg->msg_header->pcep_version);
		PATHD_FORMAT("%*stype: %s (%u)\n", ps2, "",
			     pcep_message_type_name(msg->msg_header->type),
			     msg->msg_header->type);
		PATHD_FORMAT("%*sobjects: ", ps2, "");
		_format_pcep_objects(ps2, msg->obj_list);
	}
}

void _format_pcep_objects(int ps, double_linked_list *objs)
{
	if (objs == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		double_linked_list_node *node;
		int ps2 = ps + DEBUG_IDENT_SIZE;
		int i;

		if (objs->num_entries == 0) {
			PATHD_FORMAT("[]\n");
			return;
		}

		PATHD_FORMAT("\n");
		for (node = objs->head, i = 0; node != NULL;
		     node = node->next_node, i++) {
			struct pcep_object_header *obj =
				(struct pcep_object_header *)node->data;
			PATHD_FORMAT("%*s- ", ps2 - 2, "");
			_format_pcep_object(ps2, obj);
		}
	}
}

void _format_pcep_object(int ps, struct pcep_object_header *obj)
{
	if (obj == NULL) {
		PATHD_FORMAT("NULL\n");
	} else {
		PATHD_FORMAT("object_class: %s (%u)\n",
			     pcep_object_class_name(obj->object_class),
			     obj->object_class);
		PATHD_FORMAT("%*sobject_type: %s (%u)\n", ps, "",
			     pcep_object_type_name(obj->object_class,
						   obj->object_type),
			     obj->object_type);
		PATHD_FORMAT("%*sflag_p: %u\n", ps, "", obj->flag_p);
		PATHD_FORMAT("%*sflag_i: %u\n", ps, "", obj->flag_i);
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
	case TUP(PCEP_OBJ_CLASS_LSPA, PCEP_OBJ_TYPE_LSPA):
		_format_pcep_object_lspa(ps, (struct pcep_object_lspa *)obj);
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
		_format_pcep_object_bandwidth(
			ps, (struct pcep_object_bandwidth *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_NOPATH, PCEP_OBJ_TYPE_NOPATH):
		_format_pcep_object_nopath(ps,
					   (struct pcep_object_nopath *)obj);
		break;
	case TUP(PCEP_OBJ_CLASS_OF, PCEP_OBJ_TYPE_OF):
		_format_pcep_object_objfun(
			ps, (struct pcep_object_objective_function *)obj);
		break;
	default:
		PATHD_FORMAT("%*s...\n", ps, "");
		break;
	}
}

void _format_pcep_object_error(int ps, struct pcep_object_error *obj)
{
	PATHD_FORMAT("%*serror_type: %s (%u)\n", ps, "",
		     pcep_error_type_name(obj->error_type), obj->error_type);
	PATHD_FORMAT("%*serror_value: %s (%u)\n", ps, "",
		     pcep_error_value_name(obj->error_type, obj->error_value),
		     obj->error_value);
}


void _format_pcep_object_open(int ps, struct pcep_object_open *obj)
{
	PATHD_FORMAT("%*sopen_version: %u\n", ps, "", obj->open_version);
	PATHD_FORMAT("%*sopen_keepalive: %u\n", ps, "", obj->open_keepalive);
	PATHD_FORMAT("%*sopen_deadtimer: %u\n", ps, "", obj->open_deadtimer);
	PATHD_FORMAT("%*sopen_sid: %u\n", ps, "", obj->open_sid);
}

void _format_pcep_object_rp(int ps, struct pcep_object_rp *obj)
{
	PATHD_FORMAT("%*spriority: %u\n", ps, "", obj->priority);
	PATHD_FORMAT("%*sflag_reoptimization: %u\n", ps, "",
		     obj->flag_reoptimization);
	PATHD_FORMAT("%*sflag_bidirectional: %u\n", ps, "",
		     obj->flag_bidirectional);
	PATHD_FORMAT("%*sflag_strict: %u\n", ps, "", obj->flag_strict);
	PATHD_FORMAT("%*sflag_of: %u\n", ps, "", obj->flag_of);
	PATHD_FORMAT("%*srequest_id: %u\n", ps, "", obj->request_id);
}


void _format_pcep_object_srp(int ps, struct pcep_object_srp *obj)
{
	PATHD_FORMAT("%*sflag_lsp_remove: %u\n", ps, "", obj->flag_lsp_remove);
	PATHD_FORMAT("%*ssrp_id_number: %u\n", ps, "", obj->srp_id_number);
}

void _format_pcep_object_lsp(int ps, struct pcep_object_lsp *obj)
{
	PATHD_FORMAT("%*splsp_id: %u\n", ps, "", obj->plsp_id);
	PATHD_FORMAT("%*sstatus: %s\n", ps, "",
		     pcep_lsp_status_name(obj->operational_status));
	PATHD_FORMAT("%*sflag_d: %u\n", ps, "", obj->flag_d);
	PATHD_FORMAT("%*sflag_s: %u\n", ps, "", obj->flag_s);
	PATHD_FORMAT("%*sflag_r: %u\n", ps, "", obj->flag_r);
	PATHD_FORMAT("%*sflag_a: %u\n", ps, "", obj->flag_a);
	PATHD_FORMAT("%*sflag_c: %u\n", ps, "", obj->flag_c);
}

void _format_pcep_object_lspa(int ps, struct pcep_object_lspa *obj)
{
	PATHD_FORMAT("%*slspa_exclude_any: 0x%08x\n", ps, "",
		     obj->lspa_exclude_any);
	PATHD_FORMAT("%*slspa_include_any: 0x%08x\n", ps, "",
		     obj->lspa_include_any);
	PATHD_FORMAT("%*slspa_include_all: 0x%08x\n", ps, "",
		     obj->lspa_include_all);
	PATHD_FORMAT("%*ssetup_priority: %u\n", ps, "", obj->setup_priority);
	PATHD_FORMAT("%*sholding_priority: %u\n", ps, "",
		     obj->holding_priority);
	PATHD_FORMAT("%*sflag_local_protection: %u\n", ps, "",
		     obj->flag_local_protection);
}

void _format_pcep_object_ipv4_endpoint(int ps,
				       struct pcep_object_endpoints_ipv4 *obj)
{
	PATHD_FORMAT("%*ssrc_ipv4: %pI4\n", ps, "", &obj->src_ipv4);
	PATHD_FORMAT("%*sdst_ipv4: %pI4\n", ps, "", &obj->dst_ipv4);
}

void _format_pcep_object_metric(int ps, struct pcep_object_metric *obj)
{
	PATHD_FORMAT("%*stype: %s (%u)\n", ps, "",
		     pcep_metric_type_name(obj->type), obj->type);
	PATHD_FORMAT("%*sflag_b: %u\n", ps, "", obj->flag_b);
	PATHD_FORMAT("%*sflag_c: %u\n", ps, "", obj->flag_c);
	PATHD_FORMAT("%*svalue: %f\n", ps, "", obj->value);
}

void _format_pcep_object_bandwidth(int ps, struct pcep_object_bandwidth *obj)
{
	PATHD_FORMAT("%*sbandwidth: %f\n", ps, "", obj->bandwidth);
}

void _format_pcep_object_nopath(int ps, struct pcep_object_nopath *obj)
{
	PATHD_FORMAT("%*sni: %u\n", ps, "", obj->ni);
	PATHD_FORMAT("%*sflag_c: %u\n", ps, "", obj->flag_c);
	PATHD_FORMAT("%*serr_code: %s (%u)\n", ps, "",
		     pcep_nopath_tlv_err_code_name(obj->err_code),
		     obj->err_code);
}

void _format_pcep_object_objfun(int ps,
				struct pcep_object_objective_function *obj)
{
	PATHD_FORMAT("%*sof_code: %s (%u)\n", ps, "",
		     objfun_type_name(obj->of_code), obj->of_code);
}

void _format_pcep_object_ro(int ps, struct pcep_object_ro *obj)
{
	double_linked_list *obj_list = obj->sub_objects;
	double_linked_list_node *node;
	struct pcep_object_ro_subobj *sub_obj;

	int ps2 = ps + DEBUG_IDENT_SIZE;
	int i;

	if ((obj_list == NULL) || (obj_list->num_entries == 0)) {
		PATHD_FORMAT("%*ssub_objects: []\n", ps, "");
		return;
	}

	PATHD_FORMAT("%*ssub_objects:\n", ps, "");

	for (node = obj_list->head, i = 0; node != NULL;
	     node = node->next_node, i++) {
		sub_obj = (struct pcep_object_ro_subobj *)node->data;
		PATHD_FORMAT("%*s- flag_subobj_loose_hop: %u\n", ps2 - 2, "",
			     sub_obj->flag_subobj_loose_hop);
		PATHD_FORMAT("%*sro_subobj_type: %s (%u)\n", ps2, "",
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
	case RO_SUBOBJ_TYPE_SR:
		_format_pcep_object_ro_sr(ps, (struct pcep_ro_subobj_sr *)ro);
		break;
	case RO_SUBOBJ_TYPE_IPV6:
	case RO_SUBOBJ_TYPE_LABEL:
	case RO_SUBOBJ_TYPE_UNNUM:
	case RO_SUBOBJ_TYPE_ASN:
	case RO_SUBOBJ_UNKNOWN:
		PATHD_FORMAT("%*s...\n", ps, "");
		break;
	}
}

void _format_pcep_object_ro_ipv4(int ps, struct pcep_ro_subobj_ipv4 *obj)
{
	PATHD_FORMAT("%*sip_addr: %pI4\n", ps, "", &obj->ip_addr);
	PATHD_FORMAT("%*sprefix_length: %u\n", ps, "", obj->prefix_length);
	PATHD_FORMAT("%*sflag_local_protection: %u\n", ps, "",
		     obj->flag_local_protection);
}

void _format_pcep_object_ro_sr(int ps, struct pcep_ro_subobj_sr *obj)
{
	PATHD_FORMAT("%*snai_type = %s (%u)\n", ps, "",
		     pcep_nai_type_name(obj->nai_type), obj->nai_type);
	PATHD_FORMAT("%*sflag_f: %u\n", ps, "", obj->flag_f);
	PATHD_FORMAT("%*sflag_s: %u\n", ps, "", obj->flag_s);
	PATHD_FORMAT("%*sflag_c: %u\n", ps, "", obj->flag_c);
	PATHD_FORMAT("%*sflag_m: %u\n", ps, "", obj->flag_m);

	if (!obj->flag_s) {
		PATHD_FORMAT("%*sSID: %u\n", ps, "", obj->sid);
		if (obj->flag_m) {
			PATHD_FORMAT("%*slabel: %u\n", ps, "",
				     GET_SR_ERO_SID_LABEL(obj->sid));
			if (obj->flag_c) {
				PATHD_FORMAT("%*sTC: %u\n", ps, "",
					     GET_SR_ERO_SID_TC(obj->sid));
				PATHD_FORMAT("%*sS: %u\n", ps, "",
					     GET_SR_ERO_SID_S(obj->sid));
				PATHD_FORMAT("%*sTTL: %u\n", ps, "",
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
			PATHD_FORMAT("%*sNAI: %pI4\n", ps, "", laddr4);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
			laddr6 = (struct in6_addr *)n->data;
			PATHD_FORMAT("%*sNAI: %pI6\n", ps, "", laddr6);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
			assert(n->next_node != NULL);
			assert(n->next_node->data != NULL);
			laddr4 = (struct in_addr *)n->data;
			raddr4 = (struct in_addr *)n->next_node->data;
			PATHD_FORMAT("%*sNAI: %pI4/%pI4\n", ps, "", laddr4,
				     raddr4);
			break;
		case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
			assert(n->next_node != NULL);
			assert(n->next_node->data != NULL);
			laddr6 = (struct in6_addr *)n->data;
			raddr6 = (struct in6_addr *)n->next_node->data;
			PATHD_FORMAT("%*sNAI: %pI6/%pI6\n", ps, "", laddr6,
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
			PATHD_FORMAT("%*sNAI: %pI4(%u)/%pI4(%u)\n", ps, "",
				     laddr4, *liface, raddr4, *riface);
			break;
		case PCEP_SR_SUBOBJ_NAI_ABSENT:
		case PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY:
		case PCEP_SR_SUBOBJ_NAI_UNKNOWN:
			PATHD_FORMAT("%*sNAI: UNSUPPORTED\n", ps, "");
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
		PATHD_FORMAT("%*stlvs: []\n", ps, "");
		return;
	}

	PATHD_FORMAT("%*stlvs:\n", ps, "");

	for (node = tlv_list->head, i = 0; node != NULL;
	     node = node->next_node, i++) {
		tlv = (struct pcep_object_tlv_header *)node->data;
		PATHD_FORMAT("%*s- ", ps2 - 2, "");
		_format_pcep_object_tlv(ps2, tlv);
	}
}

void _format_pcep_object_tlv(int ps, struct pcep_object_tlv_header *tlv_header)
{
	PATHD_FORMAT("type: %s (%u)\n", pcep_tlv_type_name(tlv_header->type),
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
	case PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR:
	case PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST:
	case PCEP_OBJ_TLV_TYPE_VENDOR_INFO:
	case PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS:
	case PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS:
	case PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE:
	case PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC:
	case PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION:
	case PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID:
	case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY:
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID:
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME:
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID:
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE:
	case PCEP_OBJ_TLV_TYPE_UNKNOWN:
	case PCEP_OBJ_TYPE_CISCO_BSID:
	case PCEP_OBJ_TLV_TYPE_ARBITRARY:
		PATHD_FORMAT("%*s...\n", ps, "");
		break;
	}
}

void _format_pcep_object_tlv_symbolic_path_name(
	int ps, struct pcep_object_tlv_symbolic_path_name *tlv)
{
	PATHD_FORMAT("%*ssymbolic_path_name: %.*s\n", ps, "",
		     tlv->symbolic_path_name_length, tlv->symbolic_path_name);
}

void _format_pcep_object_tlv_stateful_pce_capability(
	int ps, struct pcep_object_tlv_stateful_pce_capability *tlv)
{
	PATHD_FORMAT("%*sflag_u_lsp_update_capability: %u\n", ps, "",
		     tlv->flag_u_lsp_update_capability);
	PATHD_FORMAT("%*sflag_s_include_db_version: %u\n", ps, "",
		     tlv->flag_s_include_db_version);
	PATHD_FORMAT("%*sflag_i_lsp_instantiation_capability: %u\n", ps, "",
		     tlv->flag_i_lsp_instantiation_capability);
	PATHD_FORMAT("%*sflag_t_triggered_resync: %u\n", ps, "",
		     tlv->flag_t_triggered_resync);
	PATHD_FORMAT("%*sflag_d_delta_lsp_sync: %u\n", ps, "",
		     tlv->flag_d_delta_lsp_sync);
	PATHD_FORMAT("%*sflag_f_triggered_initial_sync: %u\n", ps, "",
		     tlv->flag_f_triggered_initial_sync);
}

void _format_pcep_object_tlv_sr_pce_capability(
	int ps, struct pcep_object_tlv_sr_pce_capability *tlv)
{

	PATHD_FORMAT("%*sflag_n: %u\n", ps, "", tlv->flag_n);
	PATHD_FORMAT("%*sflag_x: %u\n", ps, "", tlv->flag_x);
	PATHD_FORMAT("%*smax_sid_depth: %u\n", ps, "", tlv->max_sid_depth);
}

void _format_pcep_object_tlv_path_setup_type(
	int ps, struct pcep_object_tlv_path_setup_type *tlv)
{
	PATHD_FORMAT("%*spath_setup_type: %u\n", ps, "", tlv->path_setup_type);
}
