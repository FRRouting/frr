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
 * PCEP session logic counters configuration.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>

#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_utils_counters.h"
#include "pcep_utils_logging.h"

void increment_message_counters(pcep_session *session,
				struct pcep_message *message, bool is_rx);

void create_session_counters(pcep_session *session)
{
	/*
	 * Message RX and TX counters
	 */
	struct counters_subgroup *rx_msg_subgroup = create_counters_subgroup(
		"RX Message counters", COUNTER_SUBGROUP_ID_RX_MSG,
		PCEP_TYPE_MAX + 1);
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_OPEN, "Message Open",
				"messageOpen");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_KEEPALIVE,
				"Message KeepAlive", "messageKeepalive");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_PCREQ,
				"Message PcReq", "messagePcReq");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_PCREP,
				"Message PcRep", "messagePcRep");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_PCNOTF,
				"Message Notify", "messageNotify");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_ERROR,
				"Message Error", "messageError");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_CLOSE,
				"Message Close", "messageClose");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_REPORT,
				"Message Report", "messageReport");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_UPDATE,
				"Message Update", "messageUpdate");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_INITIATE,
				"Message Initiate", "messageInitiate");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_START_TLS,
				"Message StartTls", "messageStartTls");
	create_subgroup_counter(rx_msg_subgroup, PCEP_TYPE_MAX,
				"Message Erroneous", "messageErroneous");

	struct counters_subgroup *tx_msg_subgroup =
		clone_counters_subgroup(rx_msg_subgroup, "TX Message counters",
					COUNTER_SUBGROUP_ID_TX_MSG);

	/*
	 * Object RX and TX counters
	 */

	/* For the Endpoints, the ID will be either 64 or 65, so setting
	 * num_counters to 100 */
	struct counters_subgroup *rx_obj_subgroup = create_counters_subgroup(
		"RX Object counters", COUNTER_SUBGROUP_ID_RX_OBJ, 100);
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_OPEN,
				"Object Open", "objectOpen");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_RP, "Object RP",
				"objectRP");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_NOPATH,
				"Object Nopath", "objectNopath");
	create_subgroup_counter(rx_obj_subgroup,
				((PCEP_OBJ_CLASS_ENDPOINTS << 4) |
				 PCEP_OBJ_TYPE_ENDPOINT_IPV4),
				"Object Endpoint IPv4", "objectEndpointIPv4");
	create_subgroup_counter(rx_obj_subgroup,
				((PCEP_OBJ_CLASS_ENDPOINTS << 4) |
				 PCEP_OBJ_TYPE_ENDPOINT_IPV6),
				"Object Endpoint IPv6", "objectEndpointIPv6");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_BANDWIDTH,
				"Object Bandwidth", "objectBandwidth");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_METRIC,
				"Object Metric", "objectMetric");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_ERO,
				"Object ERO", "objectERO");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_RRO,
				"Object RRO", "objectRRO");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_LSPA,
				"Object LSPA", "objectLSPA");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_IRO,
				"Object IRO", "objectIRO");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_SVEC,
				"Object SVEC", "objectSVEC");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_NOTF,
				"Object Notify", "objectNotify");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_ERROR,
				"Object Error", "objectError");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_CLOSE,
				"Object Close", "objectClose");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_LSP,
				"Object LSP", "objectLSP");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_SRP,
				"Object SRP", "objectSRP");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_VENDOR_INFO,
				"Object Vendor Info", "objectVendorInfo");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_INTER_LAYER,
				"Object Inter-Layer", "objectInterLayer");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_SWITCH_LAYER,
				"Object Switch-Layer", "objectSwitchLayer");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_REQ_ADAP_CAP,
				"Object Requested Adap-Cap",
				"objectRequestedAdapCap");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_SERVER_IND,
				"Object Server-Indication",
				"objectServerIndication");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_ASSOCIATION,
				"Object Association", "objectAssociation");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_MAX,
				"Object Unknown", "objectUnknown");
	create_subgroup_counter(rx_obj_subgroup, PCEP_OBJ_CLASS_MAX + 1,
				"Object Erroneous", "objectErroneous");

	struct counters_subgroup *tx_obj_subgroup =
		clone_counters_subgroup(rx_obj_subgroup, "TX Object counters",
					COUNTER_SUBGROUP_ID_TX_OBJ);

	/*
	 * Sub-Object RX and TX counters
	 */
	struct counters_subgroup *rx_subobj_subgroup = create_counters_subgroup(
		"RX RO Sub-Object counters", COUNTER_SUBGROUP_ID_RX_SUBOBJ,
		RO_SUBOBJ_UNKNOWN + 2);
	create_subgroup_counter(rx_subobj_subgroup, RO_SUBOBJ_TYPE_IPV4,
				"RO Sub-Object IPv4", "ROSubObjectIPv4");
	create_subgroup_counter(rx_subobj_subgroup, RO_SUBOBJ_TYPE_IPV6,
				"RO Sub-Object IPv6", "ROSubObjectIPv6");
	create_subgroup_counter(rx_subobj_subgroup, RO_SUBOBJ_TYPE_LABEL,
				"RO Sub-Object Label", "ROSubObjectLabel");
	create_subgroup_counter(rx_subobj_subgroup, RO_SUBOBJ_TYPE_UNNUM,
				"RO Sub-Object Unnum", "ROSubObjectUnnum");
	create_subgroup_counter(rx_subobj_subgroup, RO_SUBOBJ_TYPE_ASN,
				"RO Sub-Object ASN", "ROSubObjectASN");
	create_subgroup_counter(rx_subobj_subgroup, RO_SUBOBJ_TYPE_SR,
				"RO Sub-Object SR", "ROSubObjectSR");
	create_subgroup_counter(rx_subobj_subgroup, RO_SUBOBJ_UNKNOWN,
				"RO Sub-Object Unknown", "ROSubObjectUnknown");
	create_subgroup_counter(rx_subobj_subgroup, RO_SUBOBJ_UNKNOWN + 1,
				"RO Sub-Object Erroneous",
				"ROSubObjectErroneous");

	struct counters_subgroup *tx_subobj_subgroup = clone_counters_subgroup(
		rx_subobj_subgroup, "TX RO Sub-Object counters",
		COUNTER_SUBGROUP_ID_TX_SUBOBJ);

	/*
	 * RO SR Sub-Object RX and TX counters
	 */
	struct counters_subgroup *rx_subobj_sr_nai_subgroup =
		create_counters_subgroup("RX RO SR NAI Sub-Object counters",
					 COUNTER_SUBGROUP_ID_RX_RO_SR_SUBOBJ,
					 PCEP_SR_SUBOBJ_NAI_UNKNOWN + 1);
	create_subgroup_counter(rx_subobj_sr_nai_subgroup,
				PCEP_SR_SUBOBJ_NAI_ABSENT,
				"RO Sub-Object SR NAI absent",
				"ROSubObjectSRNAIAbsent");
	create_subgroup_counter(rx_subobj_sr_nai_subgroup,
				PCEP_SR_SUBOBJ_NAI_IPV4_NODE,
				"RO Sub-Object SR NAI IPv4 Node",
				"ROSubObjectSRNAIIPv4Node");
	create_subgroup_counter(rx_subobj_sr_nai_subgroup,
				PCEP_SR_SUBOBJ_NAI_IPV6_NODE,
				"RO Sub-Object SR NAI IPv6 Node",
				"ROSubObjectSRNAIIPv6Node");
	create_subgroup_counter(rx_subobj_sr_nai_subgroup,
				PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY,
				"RO Sub-Object SR NAI IPv4 Adj",
				"ROSubObjectSRNAIIPv4Adj");
	create_subgroup_counter(rx_subobj_sr_nai_subgroup,
				PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY,
				"RO Sub-Object SR NAI IPv6 Adj",
				"ROSubObjectSRNAIIPv6Adj");
	create_subgroup_counter(rx_subobj_sr_nai_subgroup,
				PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY,
				"RO Sub-Object SR NAI Unnumbered IPv4 Adj",
				"ROSubObjectSRNAIUnnumberedIPv4Adj");
	create_subgroup_counter(rx_subobj_sr_nai_subgroup,
				PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY,
				"RO Sub-Object SR NAI Link Local IPv6 Adj",
				"ROSubObjectSRNAILinkLocalIPv6Adj");
	create_subgroup_counter(rx_subobj_sr_nai_subgroup,
				PCEP_SR_SUBOBJ_NAI_UNKNOWN,
				"RO Sub-Object SR NAI Unknown",
				"ROSubObjectSRNAIUnknown");

	struct counters_subgroup *tx_subobj_sr_nai_subgroup =
		clone_counters_subgroup(rx_subobj_sr_nai_subgroup,
					"TX RO SR NAI Sub-Object counters",
					COUNTER_SUBGROUP_ID_TX_RO_SR_SUBOBJ);

	/*
	 * TLV RX and TX counters
	 */
	struct counters_subgroup *rx_tlv_subgroup = create_counters_subgroup(
		"RX TLV counters", COUNTER_SUBGROUP_ID_RX_TLV,
		PCEP_OBJ_TLV_TYPE_UNKNOWN + 1);
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR,
				"TLV No Path Vector", "TLVNoPathVector");
	create_subgroup_counter(rx_tlv_subgroup, PCEP_OBJ_TLV_TYPE_VENDOR_INFO,
				"TLV Vendor Info", "TLVVendorInfo");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY,
				"TLV Stateful PCE Capability",
				"TLVStatefulPCCapability");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME,
				"TLV Symbolic Path Name", "TLVSymbolicPathName");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS,
				"TLV IPv4 LSP Identifier",
				"TLVIPv4LSPIdentifier");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS,
				"TLV IPv6 LSP Identifier",
				"TLVIPv6LSPIdentifier");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE,
				"TLV LSP Error Code", "TLVLSPErrorCode");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC,
				"TLV RSVP Error Spec", "TLVRSVPErrorSpec");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION,
				"TLV LSP DB Version", "TLVLSPDBVersion");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID,
				"TLV Speaker Entity ID", "TLVSpeakerEntityId");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY,
				"TLV SR PCE Capability", "TLVSRPCECapability");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE,
				"TLV Path Setup Type", "TLVPathSetupType");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY,
				"TLV Path Setup Type Capability",
				"TLVPathSetupTypeCapability");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID,
				"TLV SR Policy PolId", "TLVSRPolicyPolId");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME,
				"TLV SR Policy PolName", "TLVSRPolicyPolName");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID,
				"TLV SR Policy CpathId", "TLVSRPolicyCpathId");
	create_subgroup_counter(rx_tlv_subgroup,
				PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE,
				"TLV SR Policy CpathRef", "TLVSRPolicyCpathRef");
	create_subgroup_counter(rx_tlv_subgroup, PCEP_OBJ_TLV_TYPE_UNKNOWN,
				"TLV Unknown", "TLVUnknown");

	struct counters_subgroup *tx_tlv_subgroup = clone_counters_subgroup(
		rx_tlv_subgroup, "TX TLV counters", COUNTER_SUBGROUP_ID_TX_TLV);

	/*
	 * PCEP Event counters
	 */
	struct counters_subgroup *events_subgroup = create_counters_subgroup(
		"Events counters", COUNTER_SUBGROUP_ID_EVENT, MAX_COUNTERS);
	create_subgroup_counter(events_subgroup,
				PCEP_EVENT_COUNTER_ID_PCC_CONNECT,
				"PCC connect", "PCCConnect");
	create_subgroup_counter(events_subgroup,
				PCEP_EVENT_COUNTER_ID_PCE_CONNECT,
				"PCE connect", "PCEConnect");
	create_subgroup_counter(events_subgroup,
				PCEP_EVENT_COUNTER_ID_PCC_DISCONNECT,
				"PCC disconnect", "PCCDisconnect");
	create_subgroup_counter(events_subgroup,
				PCEP_EVENT_COUNTER_ID_PCE_DISCONNECT,
				"PCE disconnect", "PCEDisconnect");
	create_subgroup_counter(events_subgroup,
				PCEP_EVENT_COUNTER_ID_TIMER_KEEPALIVE,
				"Timer KeepAlive expired",
				"timerKeepAliveExpired");
	create_subgroup_counter(events_subgroup,
				PCEP_EVENT_COUNTER_ID_TIMER_DEADTIMER,
				"Timer DeadTimer expired",
				"timerDeadTimerExpired");
	create_subgroup_counter(events_subgroup,
				PCEP_EVENT_COUNTER_ID_TIMER_OPENKEEPWAIT,
				"Timer OpenKeepWait expired",
				"timerOpenKeepWaitExpired");
	create_subgroup_counter(events_subgroup,
				PCEP_EVENT_COUNTER_ID_TIMER_OPENKEEPALIVE,
				"Timer OpenKeepAlive expired",
				"timerOpenKeepAliveExpired");

	/*
	 * Create the parent counters group
	 */
	time_t now = time(NULL);
	char counters_name[MAX_COUNTER_STR_LENGTH] = {0};
	char ip_str[40] = {0};
	if (session->socket_comm_session->is_ipv6) {
		inet_ntop(AF_INET6,
			  &session->socket_comm_session->dest_sock_addr
				   .dest_sock_addr_ipv6.sin6_addr,
			  ip_str, 40);
	} else {
		inet_ntop(AF_INET,
			  &session->socket_comm_session->dest_sock_addr
				   .dest_sock_addr_ipv4.sin_addr,
			  ip_str, 40);
	}
	snprintf(counters_name, MAX_COUNTER_STR_LENGTH,
		 "PCEP Session [%d], connected to [%s] for [%u seconds]",
		 session->session_id, ip_str,
		 (uint32_t)(now - session->time_connected));
	/* The (time(NULL) - session->time_connected) will probably be 0,
	 * so the group name will be updated when the counters are dumped */
	session->pcep_session_counters =
		create_counters_group(counters_name, MAX_COUNTER_GROUPS);

	/*
	 * Add all the subgroups to the parent counters group
	 */
	add_counters_subgroup(session->pcep_session_counters, rx_msg_subgroup);
	add_counters_subgroup(session->pcep_session_counters, tx_msg_subgroup);
	add_counters_subgroup(session->pcep_session_counters, rx_obj_subgroup);
	add_counters_subgroup(session->pcep_session_counters, tx_obj_subgroup);
	add_counters_subgroup(session->pcep_session_counters,
			      rx_subobj_subgroup);
	add_counters_subgroup(session->pcep_session_counters,
			      tx_subobj_subgroup);
	add_counters_subgroup(session->pcep_session_counters,
			      rx_subobj_sr_nai_subgroup);
	add_counters_subgroup(session->pcep_session_counters,
			      tx_subobj_sr_nai_subgroup);
	add_counters_subgroup(session->pcep_session_counters, rx_tlv_subgroup);
	add_counters_subgroup(session->pcep_session_counters, tx_tlv_subgroup);
	add_counters_subgroup(session->pcep_session_counters, events_subgroup);
}

/* Internal util function used by increment_message_rx_counters or
 * increment_message_tx_counters */
void increment_message_counters(pcep_session *session,
				struct pcep_message *message, bool is_rx)
{
	uint16_t counter_subgroup_id_msg = (is_rx ? COUNTER_SUBGROUP_ID_RX_MSG
						  : COUNTER_SUBGROUP_ID_TX_MSG);
	uint16_t counter_subgroup_id_obj = (is_rx ? COUNTER_SUBGROUP_ID_RX_OBJ
						  : COUNTER_SUBGROUP_ID_TX_OBJ);
	uint16_t counter_subgroup_id_subobj =
		(is_rx ? COUNTER_SUBGROUP_ID_RX_SUBOBJ
		       : COUNTER_SUBGROUP_ID_TX_SUBOBJ);
	uint16_t counter_subgroup_id_ro_sr_subobj =
		(is_rx ? COUNTER_SUBGROUP_ID_RX_RO_SR_SUBOBJ
		       : COUNTER_SUBGROUP_ID_TX_RO_SR_SUBOBJ);
	uint16_t counter_subgroup_id_tlv = (is_rx ? COUNTER_SUBGROUP_ID_RX_TLV
						  : COUNTER_SUBGROUP_ID_TX_TLV);

	increment_counter(session->pcep_session_counters,
			  counter_subgroup_id_msg, message->msg_header->type);

	/* Iterate the objects */
	double_linked_list_node *obj_node =
		(message->obj_list == NULL ? NULL : message->obj_list->head);
	for (; obj_node != NULL; obj_node = obj_node->next_node) {
		struct pcep_object_header *obj =
			(struct pcep_object_header *)obj_node->data;

		/* Handle class: PCEP_OBJ_CLASS_ENDPOINTS,
		 *        type:  PCEP_OBJ_TYPE_ENDPOINT_IPV4 or
		 * PCEP_OBJ_TYPE_ENDPOINT_IPV6 */
		uint16_t obj_counter_id =
			(obj->object_class == PCEP_OBJ_CLASS_ENDPOINTS
				 ? (obj->object_class << 4) | obj->object_type
				 : obj->object_class);

		increment_counter(session->pcep_session_counters,
				  counter_subgroup_id_obj, obj_counter_id);

		/* Iterate the RO Sub-objects */
		if (obj->object_class == PCEP_OBJ_CLASS_ERO
		    || obj->object_class == PCEP_OBJ_CLASS_IRO
		    || obj->object_class == PCEP_OBJ_CLASS_RRO) {
			struct pcep_object_ro *ro_obj =
				(struct pcep_object_ro *)obj;

			double_linked_list_node *ro_subobj_node =
				(ro_obj->sub_objects == NULL
					 ? NULL
					 : ro_obj->sub_objects->head);
			for (; ro_subobj_node != NULL;
			     ro_subobj_node = ro_subobj_node->next_node) {
				struct pcep_object_ro_subobj *ro_subobj =
					(struct pcep_object_ro_subobj *)
						ro_subobj_node->data;
				increment_counter(
					session->pcep_session_counters,
					counter_subgroup_id_subobj,
					ro_subobj->ro_subobj_type);

				/* Handle the ro subobj type RO_SUBOBJ_TYPE_SR
				 * different NAI types */
				if (ro_subobj->ro_subobj_type
				    == RO_SUBOBJ_TYPE_SR) {
					struct pcep_ro_subobj_sr *ro_sr_subobj =
						(struct pcep_ro_subobj_sr *)
							ro_subobj;
					increment_counter(
						session->pcep_session_counters,
						counter_subgroup_id_ro_sr_subobj,
						ro_sr_subobj->nai_type);
				}
			}
		}

		/* Iterate the TLVs */
		double_linked_list_node *tlv_node =
			(obj->tlv_list == NULL ? NULL : obj->tlv_list->head);
		for (; tlv_node != NULL; tlv_node = tlv_node->next_node) {
			struct pcep_object_tlv_header *tlv =
				(struct pcep_object_tlv_header *)tlv_node->data;
			increment_counter(session->pcep_session_counters,
					  counter_subgroup_id_tlv, tlv->type);
		}
	}
}

void increment_message_rx_counters(pcep_session *session,
				   struct pcep_message *message)
{
	increment_message_counters(session, message, true);
}

void increment_message_tx_counters(pcep_session *session,
				   struct pcep_message *message)
{
	increment_message_counters(session, message, false);
}

void increment_event_counters(
	pcep_session *session,
	pcep_session_counters_event_counter_ids counter_id)
{
	increment_counter(session->pcep_session_counters,
			  COUNTER_SUBGROUP_ID_EVENT, counter_id);
}
