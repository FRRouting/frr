/*
 * BGP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Don Slice
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

#include "lib/ferr.h"
#include "bgp_errors.h"

DEFINE_LOGCAT(BGP_ERR_ATTR_FLAG, ROOT, "BGP attribute flag is incorrect",
	.description = "BGP attribute flag is set to the wrong value (Optional/Transitive/Partial)",
	.suggestion = "Determine the soure of the attribute and determine why the attribute flag has been set incorrectly",
)
DEFINE_LOGCAT(BGP_ERR_ATTR_LEN, ROOT, "BGP attribute length is incorrect",
	.description = "BGP attribute length is incorrect",
	.suggestion = "Determine the soure of the attribute and determine why the attribute length has been set incorrectly",
)
DEFINE_LOGCAT(BGP_ERR_ATTR_ORIGIN, ROOT, "BGP attribute origin value invalid",
	.description = "BGP attribute origin value is invalid",
	.suggestion = "Determine the soure of the attribute and determine why the origin attribute has been set incorrectly",
)
DEFINE_LOGCAT(BGP_ERR_ATTR_MAL_AS_PATH, ROOT, "BGP as path is invalid",
	.description = "BGP as path has been malformed",
	.suggestion = "Determine the soure of the update and determine why the as path has been set incorrectly",
)
DEFINE_LOGCAT(BGP_ERR_ATTR_FIRST_AS, ROOT, "BGP as path first as is invalid",
	.description = "BGP update has invalid first as in as path",
	.suggestion = "Determine the soure of the update and determine why the as path first as value has been set incorrectly",
)
DEFINE_LOGCAT(BGP_ERR_ATTR_PMSI_TYPE, ROOT, "BGP PMSI tunnel attribute type is invalid",
	.description = "BGP update has invalid type for PMSI tunnel",
	.suggestion = "Determine the soure of the update and determine why the PMSI tunnel attribute type has been set incorrectly",
)
DEFINE_LOGCAT(BGP_ERR_ATTR_PMSI_LEN, ROOT, "BGP PMSI tunnel attribute length is invalid",
	.description = "BGP update has invalid length for PMSI tunnel",
	.suggestion = "Determine the soure of the update and determine why the PMSI tunnel attribute length has been set incorrectly",
)
DEFINE_LOGCAT(BGP_ERR_ATTR_NH_SEND_LEN, ROOT, "")
DEFINE_LOGCAT(BGP_ERR_ATTR_MARTIAN_NH, ROOT, "")
DEFINE_LOGCAT(BGP_ERR_PEER_GROUP, ROOT, "BGP peergroup operated on in error",
	.description = "BGP operating on peer-group instead of peers included",
	.suggestion = "Ensure the config doesn't contain peergroups contained within peergroups",
)
DEFINE_LOGCAT(BGP_ERR_PEER_DELETE, ROOT, "BGP failed to delete peer structure",
	.description = "BGP was unable to delete peer structure when address-family removed",
	.suggestion = "Determine if all expected peers are removed and restart FRR if not. Most likely a bug",
)
DEFINE_LOGCAT(BGP_ERR_TABLE_CHUNK, ROOT, "BGP failed to get table chunk memory",
	.description = "BGP unable to get chunk memory for table manager",
	.suggestion = "Ensure there is adequate memory on the device to support the table requirements",
)
DEFINE_LOGCAT(BGP_ERR_MACIP_LEN, ROOT, "BGP received MACIP with invalid IP addr len",
	.description = "BGP received MACIP with invalid IP addr len from Zebra",
	.suggestion = "Verify MACIP entries inserted in Zebra are correct.  Most likely a bug",
)
DEFINE_LOGCAT(BGP_ERR_LM_ERROR, ROOT, "BGP received invalid label manager message",
	.description = "BGP received invalid label manager message from label manager",
	.suggestion = "Label manager sent invalid essage to BGP for wrong protocol, instance, etc. Most likely a bug",
)
DEFINE_LOGCAT(BGP_ERR_JSON_MEM_ERROR, ROOT, "BGP unable to allocate memory for JSON output",
	.description = "BGP attempted to generate JSON output and was unable to allocate the memory required",
	.suggestion = "Ensure that the device has adequate memory to suport the required functions",
)
DEFINE_LOGCAT(BGP_ERR_UPDGRP_ATTR_LEN, ROOT, "BGP update had attributes too long to send",
	.description = "BGP attempted to send an update but the attributes were too long to fit",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_UPDGRP_CREATE, ROOT, "BGP update group creation failed",
	.description = "BGP attempted to create an update group but was unable to",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_UPDATE_SND, ROOT, "BGP error creating update packet",
	.description = "BGP attempted to create an update packet but was unable to",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_PKT_OPEN, ROOT, "BGP error receiving open packet",
	.description = "BGP received an open from a peer that was invalid",
	.suggestion = "Determine the sending peer and correct his invalid open packet",
)
DEFINE_LOGCAT(BGP_ERR_SND_FAIL, ROOT, "BGP error sending to peer",
	.description = "BGP attempted to respond to open from a peer and failed",
	.suggestion = "BGP attempted to respond to an open and could not sene the packet. Check local IP address for source",
)
DEFINE_LOGCAT(BGP_ERR_INVALID_STATUS, ROOT, "BGP error receiving from  peer",
	.description = "BGP received an update from a peer but status was incorrect",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_UPDATE_RCV, ROOT, "BGP error receiving update packet",
	.description = "BGP received an invalid update packet",
	.suggestion = "Determine the source of the update and resolve the invalid update being sent",
)
DEFINE_LOGCAT(BGP_ERR_NO_CAP, ROOT, "BGP error due to capability not enabled",
	.description = "BGP attempted a function that did not have the capability enabled",
	.suggestion = "Enable the capability if this functionality is desired",
)
DEFINE_LOGCAT(BGP_ERR_NOTIFY_RCV, ROOT, "BGP error receiving notify message",
	.description = "BGP unable to process notification message",
	.suggestion = "BGP notify received while in stopped state. If the problem persists, report for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_KEEP_RCV, ROOT, "BGP error receiving keepalive packet",
	.description = "BGP unable to process keepalive packet",
	.suggestion = "BGP keepalive received while in stopped state. If the problem persists, report for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_RFSH_RCV, ROOT, "BGP error receiving route refresh message",
	.description = "BGP unable to process route refresh message",
	.suggestion = "BGP route refresh received while in stopped state. If the problem persists, report for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_CAP_RCV, ROOT, "BGP error capability message",
	.description = "BGP unable to process received capability",
	.suggestion = "BGP capability message received while in stopped state. If the problem persists, report for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_NH_UPD, ROOT, "BGP error with nexthopo update",
	.description = "BGP unable to process nexthop update",
	.suggestion = "BGP received nexthop update but nexthop is not reachable in this bgp instance. Report for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_LABEL, ROOT, "Failure to apply label",
	.description = "BGP attempted to attempted to apply a label but could not",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_MULTIPATH, ROOT, "Multipath specified is invalid",
	.description = "BGP was started with an invalid ecmp/multipath value",
	.suggestion = "Correct the ecmp/multipath value supplied when starting the BGP daemon",
)
DEFINE_LOGCAT(BGP_ERR_PKT_PROCESS, ROOT, "Failure to process a packet",
	.description = "BGP attempted to process a received packet but could not",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_CONNECT, ROOT, "Failure to connect to peer",
	.description = "BGP attempted to send open to peer but couldn't connect",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_FSM, ROOT, "BGP FSM issue",
	.description = "BGP neighbor transition problem",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_VNI, ROOT, "BGP VNI creation issue",
	.description = "BGP could not create a new VNI",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_NO_DFLT, ROOT, "BGP default instance missing",
	.description = "BGP could not find default instance",
	.suggestion = "Define a default instance of BGP since some feature requires it's existence",
)
DEFINE_LOGCAT(BGP_ERR_VTEP_INVALID, ROOT, "BGP remote VTEP invalid",
	.description = "BGP remote VTEP is invalid and cannot be used",
	.suggestion = "Correct remote VTEP configuration or resolve the source of the problem",
)
DEFINE_LOGCAT(BGP_ERR_ES_INVALID, ROOT, "BGP ES route error",
	.description = "BGP ES route incorrect, learned both local and remote",
	.suggestion = "Correct configuration or addressing so that same not learned both local and remote",
)
DEFINE_LOGCAT(BGP_ERR_EVPN_ROUTE_DELETE, ROOT, "BGP EVPN route delete error",
	.description = "BGP attempted to delete an EVPN route and failed",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_EVPN_FAIL, ROOT, "BGP EVPN install/uninstall error",
	.description = "BGP attempted to install or uninstall an EVPN prefix and failed",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_EVPN_ROUTE_INVALID, ROOT, "BGP EVPN route received with invalid contents",
	.description = "BGP received an EVPN route with invalid contents",
	.suggestion = "Determine the source of the EVPN route and resolve whatever is causing invalid contents",
)
DEFINE_LOGCAT(BGP_ERR_EVPN_ROUTE_CREATE, ROOT, "BGP EVPN route create error",
	.description = "BGP attempted to create an EVPN route and failed",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_ES_CREATE, ROOT, "BGP EVPN ES entry create error",
	.description = "BGP attempted to create an EVPN ES entry and failed",
	.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting",
)
DEFINE_LOGCAT(BGP_ERR_MULTI_INSTANCE, ROOT, "BGP config multi-instance issue",
	.description = "BGP configuration attempting multiple instances without enabling the feature",
	.suggestion = "Correct the configuration so that bgp multiple-instance is enabled if desired",
)
DEFINE_LOGCAT(BGP_ERR_EVPN_AS_MISMATCH, ROOT, "BGP AS configuration issue",
	.description = "BGP configuration attempted for a different AS than currently configured",
	.suggestion = "Correct the configuration so that the correct BGP AS number is used",
)
DEFINE_LOGCAT(BGP_ERR_EVPN_INSTANCE_MISMATCH, ROOT, "BGP EVPN AS and process name mismatch",
	.description = "BGP configuration has AS and process name mismatch",
	.suggestion = "Correct the configuration so that the BGP AS number and instance name are consistent",
)
DEFINE_LOGCAT(BGP_ERR_FLOWSPEC_PACKET, ROOT, "BGP Flowspec packet processing error",
	.description = "The BGP flowspec subsystem has detected a error in the send or receive of a packet",
	.suggestion = "Gather log files from both sides of the peering relationship and open an issue",
)
DEFINE_LOGCAT(BGP_ERR_FLOWSPEC_INSTALLATION, ROOT, "BGP Flowspec Installation/removal Error",
	.description = "The BGP flowspec subsystem has detected that there was a failure for installation/removal/modification of Flowspec from the dataplane",
	.suggestion = "Gather log files from the router and open an issue, Restart FRR",
)
