/*
 * bgp_errors - code for error messages that may occur in the
 *              bgp process
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Don Slice
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include <bgp_errors.h>

static struct ferr_ref ferr_bgp_err[] = {
	{
		.code = BGP_ERR_ATTR_FLAG,
		.title = "BGP attribute flag is incorrect",
		.description = "BGP attribute flag is set to the wrong value (Optional/Transitive/Partial)",
		.suggestion = "Determine the soure of the attribute and determine why the attribute\n flag has been set incorrectly"
	},
	{
		.code = BGP_ERR_ATTR_LEN,
		.title = "BGP attribute length is incorrect",
		.description = "BGP attribute length is incorrect)",
		.suggestion = "Determine the soure of the attribute and determine why the attribute\nlength has been set incorrectly"
	},
	{
		.code = BGP_ERR_ATTR_ORIGIN,
		.title = "BGP attribute origin value invalid",
		.description = "BGP attribute origin value is invalid",
		.suggestion = "Determine the soure of the attribute and determine why the origin\nattribute has been set incorrectly"
	},
	{
		.code = BGP_ERR_ATTR_MAL_AS_PATH,
		.title = "BGP as path is invalid",
		.description = "BGP as path has been malformed",
		.suggestion = "Determine the soure of the update and determine why the as path has\nbeen set incorrectly"
	},
	{
		.code = BGP_ERR_ATTR_FIRST_AS,
		.title = "BGP as path first as is invalid",
		.description = "BGP update has invalid first as in as path",
		.suggestion = "Determine the soure of the update and determine why the as path first\nas value has been set incorrectly"
	},
	{
		.code = BGP_ERR_ATTR_PMSI_TYPE,
		.title = "BGP PMSI tunnel attribute type is invalid",
		.description = "BGP update has invalid type for PMSI tunnel",
		.suggestion = "Determine the soure of the update and determine why the PMSI tunnel\nattribute type has been set incorrectly"
	},
	{
		.code = BGP_ERR_ATTR_PMSI_LEN,
		.title = "BGP PMSI tunnel attribute length is invalid",
		.description = "BGP update has invalid length for PMSI tunnel",
		.suggestion = "Determine the soure of the update and determine why the PMSI tunnel\nattribute length has been set incorrectly"
	},
	{
		.code = BGP_ERR_PEER_GROUP,
		.title = "BGP peergroup operated on in error",
		.description = "BGP operating on peer-group instead of peers included",
		.suggestion = "Ensure the config doesn't contain peergroups contained within peergroups"
	},
	{
		.code = BGP_ERR_PEER_DELETE,
		.title = "BGP failed to delete peer structure",
		.description = "BGP was unable to delete peer structure when address-family removed",
		.suggestion = "Determine if all expected peers are removed and restart FRR if not.\nMost likely a bug"
	},
	{
		.code = BGP_ERR_TABLE_CHUNK,
		.title = "BGP failed to get table chunk memory",
		.description = "BGP unable to get chunk memory for table manager",
		.suggestion = "Ensure there is adequate memory on the device to support the table\nrequirements"
	},
	{
		.code = BGP_ERR_MACIP_LEN,
		.title = "BGP received MACIP with invalid IP addr len",
		.description = "BGP received MACIP with invalid IP addr len from Zebra",
		.suggestion = "Verify MACIP entries inserted in Zebra are correct.  Most likely a bug"
	},
	{
		.code = BGP_ERR_LM_ERROR,
		.title = "BGP received invalid label manager message",
		.description = "BGP received nvalid label manager message from label manager",
		.suggestion = "Label manager sent invalid essage to BGP for wrong protocol, instance, etc.\nMost likely a bug"
	},
	{
		.code = BGP_ERR_JSON_MEM_ERROR,
		.title = "BGP unable to allocate memory for JSON output",
		.description = "BGP attempted to generate JSON output and was unable to allocate\nthe memory required",
		.suggestion = "Ensure that the device has adequate memory to suport the required functions"
	},
	{
		.code = BGP_ERR_UPDGRP_ATTR_LEN,
		.title = "BGP update had attributes too long to send",
		.description = "BGP attempted to send an update but the attributes were too long to fit",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_UPDGRP_CREATE,
		.title = "BGP update group creation failed",
		.description = "BGP attempted to create an update group but was unable to",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_UPDATE_SND,
		.title = "BGP error creating update packet",
		.description = "BGP attempted to create an update packet but was unable to",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_PKT_OPEN,
		.title = "BGP error receiving open packet",
		.description = "BGP received an open from a peer that was invalid",
		.suggestion = "Determine the sending peer and correct his invalid open packet"
	},
	{
		.code = BGP_ERR_SND_FAIL,
		.title = "BGP error sending to peer",
		.description = "BGP attempted to respond to open from a peer and failed",
		.suggestion = "BGP attempted to respond to an open and could not sene the packet.\nCheck local IP address for source"
	},
	{
		.code = BGP_ERR_INVALID_STATUS,
		.title = "BGP error receiving from  peer",
		.description = "BGP received an update from a peer but status was incorrect",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_UPDATE_RCV,
		.title = "BGP error receiving update packet",
		.description = "BGP received an invalid update packet",
		.suggestion = "Determine the source of the update and resolve the invalid update being sent"
	},
	{
		.code = BGP_ERR_NO_CAP,
		.title = "BGP error due to capability not enabled",
		.description = "BGP attempted a function that did not have the capability enabled",
		.suggestion = "Enable the capability if this functionality is desired"
	},
	{
		.code = BGP_ERR_NOTIFY_RCV,
		.title = "BGP error receiving notify message",
		.description = "BGP unable to process notification message",
		.suggestion = "BGP notify received while in stopped state. If the problem persists,\nreport for troubleshooting"
	},
	{
		.code = BGP_ERR_KEEP_RCV,
		.title = "BGP error receiving keepalive packet",
		.description = "BGP unable to process keepalive packet",
		.suggestion = "BGP keepalive received while in stopped state. If the problem persists,\nreport for troubleshooting"
	},
	{
		.code = BGP_ERR_RFSH_RCV,
		.title = "BGP error receiving route refresh message",
		.description = "BGP unable to process route refresh message",
		.suggestion = "BGP route refresh received while in stopped state. If the problem persists,\nreport for troubleshooting"},
	{
		.code = BGP_ERR_CAP_RCV,
		.title = "BGP error capability message",
		.description = "BGP unable to process received capability",
		 .suggestion = "BGP capability message received while in stopped state. If the problem\npersists, report for troubleshooting"
	},
	{
		.code = BGP_ERR_NH_UPD,
		.title = "BGP error with nexthopo update",
		.description = "BGP unable to process nexthop update",
		.suggestion = "BGP received nexthop update but nexthop is not reachable in this bgp\ninstance. Report for troubleshooting"
	},
	{
		.code = BGP_ERR_LABEL,
		.title = "Failure to apply label",
		.description = "BGP attempted to attempted to apply a label but could not",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_MULTIPATH,
		.title = "Multipath specified is invalid",
		.description = "BGP was started with an invalid ecmp/multipath value",
		.suggestion = "Correct the ecmp/multipath value supplied when starting the BGP daemon"
	},
	{
		.code = BGP_ERR_PKT_PROCESS,
		.title = "Failure to process a packet",
		.description = "BGP attempted to process a received packet but could not",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_CONNECT,
		.title = "Failure to connect to peer",
		.description = "BGP attempted to send open to peer but couldn't connect",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_FSM,
		.title = "BGP FSM issue",
		.description = "BGP neighbor transition problem",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_VNI,
		.title = "BGP VNI creation issue",
		.description = "BGP could not create a new VNI",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_NO_DFLT,
		.title = "BGP default instance missing",
		.description = "BGP could not find default instance",
		.suggestion = "Define a default instance of BGP since some feature requires it's existence"
	},
	{
		.code = BGP_ERR_VTEP_INVALID,
		.title = "BGP remote VTEP invalid",
		.description = "BGP remote VTEP is invalid and cannot be used",
		.suggestion = "Correct remote VTEP configuration or resolve the source of the problem"
	},
	{
		.code = BGP_ERR_ES_INVALID,
		.title = "BGP ES route error",
		.description = "BGP ES route incorrect, learned both local and remote",
		.suggestion = "Correct configuration or addressing so that same not learned both local and remote"
	},
	{
		.code = BGP_ERR_EVPN_ROUTE_DELETE,
		.title = "BGP EVPN route delete error",
		.description = "BGP attempted to delete an EVPN route and failed",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_EVPN_FAIL,
		.title = "BGP EVPN install/uninstall error",
		.description = "BGP attempted to install or uninstall an EVPN prefix and failed",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_EVPN_ROUTE_INVALID,
		.title = "BGP EVPN route received with invalid contents",
		.description = "BGP received an EVPN route with invalid contents",
		.suggestion = "Determine the source of the EVPN route and resolve whatever is causing\ninvalid contents"
	},
	{
		.code = BGP_ERR_EVPN_ROUTE_CREATE,
		.title = "BGP EVPN route create error",
		.description = "BGP attempted to create an EVPN route and failed",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_ES_CREATE,
		.title = "BGP EVPN ES entry create error",
		.description = "BGP attempted to create an EVPN ES entry and failed",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = BGP_ERR_MULTI_INSTANCE,
		.title = "BGP config multi-instance issue",
		.description = "BGP configuration attempting multiple instances without enabling the feature",
		.suggestion = "Correct the configuration so that bgp multiple-instance is enabled if desired"
	},
	{
		.code = BGP_ERR_EVPN_AS_MISMATCH,
		.title = "BGP AS configuration issue",
		.description = "BGP configuration attempted for a different AS than currently configured",
		.suggestion = "Correct the configuration so that the correct BGP AS number is used"
	},
	{
		.code = BGP_ERR_EVPN_INSTANCE_MISMATCH,
		.title = "BGP EVPN AS and process name mismatch",
		.description = "BGP configuration has AS and process name mismatch",
		.suggestion = "Correct the configuration so that the BGP AS number and instance\nname are consistent"
	},
	{
		.code = END_FERR,
	}
};

void bgp_error_init(void)
{
	ferr_ref_init();

	ferr_ref_add(ferr_bgp_err);
}
