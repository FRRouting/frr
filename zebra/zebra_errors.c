/*
 * Zebra-specific error messages.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
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
#include "zebra_errors.h"

/* clang-format off */
static struct log_ref ferr_zebra_err[] = {
	{
		.code = EC_ZEBRA_LM_RESPONSE,
		.title = "Error reading response from label manager",
		.description = "Zebra could not read the ZAPI header from the label manager",
		.suggestion = "Wait for the error to resolve on its own. If it does not resolve, restart Zebra.",
	},
	{
		.code = EC_ZEBRA_LM_NO_SUCH_CLIENT,
		.title = "Label manager could not find ZAPI client",
		.description = "Zebra was unable to find a ZAPI client matching the given protocol and instance number.",
		.suggestion = "Ensure clients which use the label manager are properly configured and running.",
	},
	{
		.code = EC_ZEBRA_LM_RELAY_FAILED,
		.title = "Zebra could not relay label manager response",
		.description = "Zebra found the client and instance to relay the label manager response or request to, but was not able to do so, possibly because the connection was closed.",
		.suggestion = "Ensure clients which use the label manager are properly configured and running.",
	},
	{
		.code = EC_ZEBRA_LM_BAD_INSTANCE,
		.title = "Mismatch between ZAPI instance and encoded message instance",
		.description = "While relaying a request to the external label manager, Zebra noticed that the instance number encoded in the message did not match the client instance number.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_LM_EXHAUSTED_LABELS,
		.title = "Zebra label manager used all available labels",
		.description = "Zebra is unable to assign additional label chunks because it has exhausted its assigned label range.",
		.suggestion = "Make the label range bigger and restart Zebra.",
	},
	{
		.code = EC_ZEBRA_LM_DAEMON_MISMATCH,
		.title = "Daemon mismatch when releasing label chunks",
		.description = "Zebra noticed a mismatch between a label chunk and a protocol daemon number or instance when releasing unused label chunks.",
		.suggestion = "Ignore this error.",
	},
	{
		.code = EC_ZEBRA_LM_UNRELEASED_CHUNK,
		.title = "Zebra did not free any label chunks",
		.description = "Zebra's chunk cleanup procedure ran, but no label chunks were released.",
		.suggestion = "Ignore this error.",
	},
	{
		.code = EC_ZEBRA_DP_INVALID_RC,
		.title = "Dataplane returned invalid status code",
		.description = "The underlying dataplane responded to a Zebra message or other interaction with an unrecognized, unknown or invalid status code.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_WQ_NONEXISTENT,
		.title = "A necessary work queue does not exist.",
		.description = "A necessary work queue does not exist.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_FEC_ADD_FAILED,
		.title = "Failed to add FEC for MPLS client",
		.description = "A client requested a label binding for a new FEC, but Zebra was unable to add the FEC to its internal table.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_FEC_LABEL_INDEX_LABEL_CONFLICT,
		.title = "Refused to add FEC for MPLS client with both label index and label specified",
		.description = "A client requested a label binding for a new FEC specifying a label index and a label at the same time.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_FEC_RM_FAILED,
		.title = "Failed to remove FEC for MPLS client",
		.description = "Zebra was unable to find and remove a FEC in its internal table.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_IRDP_LEN_MISMATCH,
		.title = "IRDP message length mismatch",
		.description = "The length encoded in the IP TLV does not match the length of the packet received.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_RNH_UNKNOWN_FAMILY,
		.title = "Attempted to perform nexthop update for unknown address family",
		.description = "Zebra attempted to perform a nexthop update for unknown address family",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_DP_INSTALL_FAIL,
		.title = "Dataplane installation failure",
		.description = "Installation of routes to underlying dataplane failed.",
		.suggestion = "Check all configuration parameters for correctness.",
	},
	{
		.code = EC_ZEBRA_DP_DELETE_FAIL,
		.title = "Dataplane deletion failure",
		.description = "Deletion of routes from underlying dataplane failed.",
		.suggestion = "Check all configuration parameters for correctness.",
	},
	{
		.code = EC_ZEBRA_TABLE_LOOKUP_FAILED,
		.title = "Zebra table lookup failed",
		.description = "Zebra attempted to look up a table for a particular address family and subsequent address family, but didn't find anything.",
		.suggestion = "If you entered a command to trigger this error, make sure you entered the arguments correctly. Check your config file for any potential errors. If these look correct, seek help.",
	},
	{
		.code = EC_ZEBRA_NETLINK_NOT_AVAILABLE,
		.title = "Netlink backend not available",
		.description = "FRR was not compiled with support for Netlink. Any operations that require Netlink will fail.",
		.suggestion = "Recompile FRR with Netlink, or install a package that supports this feature.",
	},
	{
		.code = EC_ZEBRA_PROTOBUF_NOT_AVAILABLE,
		.title = "Protocol Buffers backend not available",
		.description = "FRR was not compiled with support for Protocol Buffers. Any operations that require Protobuf will fail.",
		.suggestion = "Recompile FRR with Protobuf support, or install a package that supports this feature.",
	},
	{
		.code = EC_ZEBRA_TM_EXHAUSTED_IDS,
		.title = "Table manager used all available IDs",
		.description = "Zebra's table manager used up all IDs available to it and can't assign any more.",
		.suggestion = "Reconfigure Zebra with a larger range of table IDs.",
	},
	{
		.code = EC_ZEBRA_TM_DAEMON_MISMATCH,
		.title = "Daemon mismatch when releasing table chunks",
		.description = "Zebra noticed a mismatch between a table ID chunk and a protocol daemon number instance when releasing unused table chunks.",
		.suggestion = "Ignore this error.",
	},
	{
		.code = EC_ZEBRA_TM_UNRELEASED_CHUNK,
		.title = "Zebra did not free any table chunks",
		.description = "Zebra's table chunk cleanup procedure ran, but no table chunks were released.",
		.suggestion = "Ignore this error.",
	},
	{
		.code = EC_ZEBRA_UNKNOWN_FAMILY,
		.title = "Address family specifier unrecognized",
		.description = "Zebra attempted to process information from somewhere that included an address family specifier, but did not recognize the provided specifier.",
		.suggestion = "Ensure that your configuration is correct. If it is, notify a developer.",
	},
	{
		.code = EC_ZEBRA_TM_WRONG_PROTO,
		.title = "Incorrect protocol for table manager client",
		.description = "Zebra's table manager only accepts connections from daemons managing dynamic routing protocols, but received a connection attempt from a daemon that does not meet this criterion.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_PROTO_OR_INSTANCE_MISMATCH,
		.title = "Mismatch between message and client protocol and/or instance",
		.description = "Zebra detected a mismatch between a client's protocol and/or instance numbers versus those stored in a message transiting its socket.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_LM_CANNOT_ASSIGN_CHUNK,
		.title = "Label manager unable to assign label chunk",
		.description = "Zebra's label manager was unable to assign a label chunk to client.",
		.suggestion = "Ensure that Zebra has a sufficient label range available and that there is not a range collision.",
	},
	{
		.code = EC_ZEBRA_LM_ALIENS,
		.title = "Label request from unidentified client",
		.description = "Zebra's label manager received a label request from an unidentified client.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_TM_CANNOT_ASSIGN_CHUNK,
		.title = "Table manager unable to assign table chunk",
		.description = "Zebra's table manager was unable to assign a table chunk to a client.",
		.suggestion = "Ensure that Zebra has sufficient table ID range available and that there is not a range collision.",
	},
	{
		.code = EC_ZEBRA_TM_ALIENS,
		.title = "Table request from unidentified client",
		.description = "Zebra's table manager received a table request from an unidentified client.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_RECVBUF,
		.title = "Cannot set receive buffer size",
		.description = "Socket receive buffer size could not be set in the kernel",
		.suggestion = "Ignore this error.",
	},
	{
		.code = EC_ZEBRA_UNKNOWN_NLMSG,
		.title = "Unknown Netlink message type",
		.description = "Zebra received a Netlink message with an unrecognized type field.",
		.suggestion = "Verify that you are running the latest version of FRR to ensure kernel compatibility. If the problem persists, notify a developer.",
	},
	{
		.code = EC_ZEBRA_RECVMSG_OVERRUN,
		.title = "Receive buffer overrun",
		.description = "The kernel's buffer for a socket has been overrun, rendering the socket invalid.",
		.suggestion = "Zebra will restart itself. Notify a developer if this issue shows up frequently.",
	},
	{
		.code = EC_ZEBRA_NETLINK_LENGTH_ERROR,
		.title = "Netlink message length mismatch",
		.description = "Zebra received a Netlink message with incorrect length fields.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_NETLINK_LENGTH_ERROR,
		.title = "Netlink message length mismatch",
		.description = "Zebra received a Netlink message with incorrect length fields.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_UNEXPECTED_MESSAGE,
		.title = "Received unexpected response from kernel",
		.description = "Received unexpected response from the kernel via Netlink.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_NETLINK_BAD_SEQUENCE,
		.title = "Bad sequence number in Netlink message",
		.description = "Zebra received a Netlink message with a bad sequence number.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_BAD_MULTIPATH_NUM,
		.title = "Multipath number was out of valid range",
		.description = "Multipath number specified to Zebra must be in the appropriate range",
		.suggestion = "Provide a multipath number that is within its accepted range",
	},
	{
		.code = EC_ZEBRA_PREFIX_PARSE_ERROR,
		.title = "String could not be parsed as IP prefix",
		.description = "There was an attempt to parse a string as an IPv4 or IPv6 prefix, but the string could not be parsed and this operation failed.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_MAC_ADD_FAILED,
		.title = "Failed to add MAC address to interface",
		.description = "Zebra attempted to assign a MAC address to a vxlan interface but failed",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_VNI_DEL_FAILED,
		.title = "Failed to delete VNI",
		.description = "Zebra attempted to delete a VNI entry and failed",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_VTEP_ADD_FAILED,
		.title = "Adding remote VTEP failed",
		.description = "Zebra attempted to add a remote VTEP and failed.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_VNI_ADD_FAILED,
		.title = "Adding VNI failed",
		.description = "Zebra attempted to add a VNI hash to an interface and failed",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_NS_NOTIFY_READ,
		.title = "Zebra failed to read namespace inotify information",
		.description = "Zebra received an event from inotify, but failed to read what it was.",
		.suggestion = "Notify a developer.",
	},
	{
		.code = EC_ZEBRA_NHG_TABLE_INSERT_FAILED,
		.title =
			"Nexthop Group Hash Table Insert Failure",
		.description =
			"Zebra failed in inserting a Nexthop Group into its hash tables.",
		.suggestion =
			"Check to see if the entry already exists or if the netlink message was parsed incorrectly."
	},
	{
		.code = EC_ZEBRA_NHG_SYNC,
		.title =
			"Zebra's Nexthop Groups are out of sync",
		.description =
			"Zebra's nexthop group tables are out of sync with the nexthop groups in the fib.",
		.suggestion =
			"Check the current status of the kernels nexthop groups and compare it to Zebra's."
	},
	{
		.code = EC_ZEBRA_NHG_FIB_UPDATE,
		.title =
			"Zebra failed updating the fib with Nexthop Group",
		.description =
			"Zebra was not able to successfully install a new nexthop group into the fib",
		.suggestion =
			"Check to see if the nexthop group on the route you tried to install is valid."
	},
	{
		.code = EC_ZEBRA_IF_LOOKUP_FAILED,
		.title = "Zebra interface lookup failed",
		.description = "Zebra attempted to look up a interface for a particular vrf_id and interface index, but didn't find anything.",
		.suggestion = "If you entered a command to trigger this error, make sure you entered the arguments correctly. Check your config file for any potential errors. If these look correct, seek help.",
	},
	/* Warnings */
	{
		.code = EC_ZEBRAING_LM_PROTO_MISMATCH,
		.title =
			"Zebra label manager received malformed label request",
		.description =
			"Zebra's label manager received a label request from a client whose protocol type does not match the protocol field received in the message.",
		.suggestion =
			"This is a bug. Please report it.",
	},
	{
		.code = EC_ZEBRA_LSP_INSTALL_FAILURE,
		.title =
			"Zebra failed to install LSP into the kernel",
		.description =
			"Zebra made an attempt to install a label switched path, but the kernel indicated that the installation was not successful.",
		.suggestion =
			"Wait for Zebra to reattempt installation.",
	},
	{
		.code = EC_ZEBRA_LSP_DELETE_FAILURE,
		.title =
			"Zebra failed to remove LSP from the kernel",
		.description =
			"Zebra made an attempt to remove a label switched path, but the kernel indicated that the deletion was not successful.",
		.suggestion =
			"Wait for Zebra to reattempt deletion.",
	},
	{
		.code = EC_ZEBRA_MPLS_SUPPORT_DISABLED,
		.title =
			"Zebra will not run with MPLS support",
		.description =
			"Zebra noticed that the running kernel does not support MPLS, so it disabled MPLS support.",
		.suggestion =
			"If you want MPLS support, upgrade the kernel to a version that provides MPLS support.",
	},
	{
		.code = EC_ZEBRA_SYSCTL_FAILED,
		.title = "A call to sysctl() failed",
		.description =
			"sysctl() returned a nonzero exit code, indicating an error.",
		.suggestion =
			"The log message should contain further details on the specific error that occurred; investigate the reported error.",
	},
	{
		.code = EC_ZEBRA_NS_VRF_CREATION_FAILED,
		.title =
			"Zebra failed to create namespace VRF",
		.description =
			"Zebra failed to create namespace VRF",
		.suggestion = "",
	},
	{
		.code = EC_ZEBRA_NS_DELETION_FAILED_NO_VRF,
		.title =
			"Zebra attempted to delete nonexistent namespace",
		.description =
			"Zebra attempted to delete a particular namespace, but no VRF associated with that namespace could be found to delete.",
		.suggestion = "Please report this bug.",
	},
	{
		.code = EC_ZEBRA_IFLIST_FAILED,
		.title =
			"Zebra interface listing failed",
		.description =
			"Zebra encountered an error attempting to query sysctl for a list of interfaces on the system.",
		.suggestion =
			"Check that Zebra is running with the appropriate permissions. If it is, please report this as a bug.",
	},
	{
		.code = EC_ZEBRA_IRDP_BAD_CHECKSUM,
		.title =
			"Zebra received ICMP packet with invalid checksum",
		.description =
			"Zebra received an ICMP packet with a bad checksum and has silently ignored it.",
		.suggestion =
			"If the problem continues to occur, investigate the source of the bad ICMP packets.",
	},
	{
		.code = EC_ZEBRA_IRDP_BAD_TYPE_CODE,
		.title =
			"Zebra received ICMP packet with bad type code",
		.description =
			"Zebra received an ICMP packet with a bad code for the message type and has silently ignored it.",
		.suggestion =
			"If the problem continues to occur, investigate the source of the bad ICMP packets.",
	},
	{
		.code = EC_ZEBRA_IRDP_BAD_RX_FLAGS,
		.title =
			"Zebra received IRDP packet while operating in wrong mode",
		.description =
			"Zebra received a multicast IRDP packet while operating in unicast mode, or vice versa.",
		.suggestion =
			"If you wish to receive the messages, change your IRDP settings accordingly.",
	},
	{
		.code = EC_ZEBRA_RNH_NO_TABLE,
		.title =
			"Zebra could not find table for next hop",
		.description =
			"Zebra attempted to add a next hop but could not find the appropriate table to install it in.",
		.suggestion = "Please report this bug.",
	},
	{
		.code = EC_ZEBRA_FPM_FORMAT_UNKNOWN,
		.title =
			"Unknown message format for Zebra's FPM module",
		.description =
			"Zebra's FPM module takes an argument which specifies the message format to use, but the format was either not provided or was not a valid format. The FPM interface will be disabled.",
		.suggestion =
			"Provide or correct the module argument to provide a valid format. See documentation for further information.",
	},
	{
		.code = EC_ZEBRA_CLIENT_IO_ERROR,
		.title =
			"Zebra client connection failed",
		.description =
			"A Zebra client encountered an I/O error and is shutting down. This can occur under normal circumstances, such as when FRR is restarting or shutting down; it can also happen if the daemon crashed. Usually this warning can be ignored.",
		.suggestion =
			"Ignore this warning, it is mostly informational.",
	},
	{
		.code = EC_ZEBRA_CLIENT_WRITE_FAILED,
		.title =
			"Zebra failed to send message to client",
		.description =
			"Zebra attempted to send a message to one of its clients, but the write operation failed. The connection will be closed.",
		.suggestion =
			"Ignore this warning, it is mostly informational.",
	},
	{
		.code = EC_ZEBRA_NETLINK_INVALID_AF,
		.title =
			"Zebra received Netlink message with invalid family",
		.description =
			"Zebra received a Netlink message with an invalid address family.",
		.suggestion =
			"Inspect the logged address family and submit it with a bug report.",
	},
	{
		.code = EC_ZEBRA_REMOVE_ADDR_UNKNOWN_SUBNET,
		.title =
			"Zebra tried to remove address from unknown subnet",
		.description =
			"Zebra attempted to remove an address from an unknown subnet.",
		.suggestion =
			"This is a bug, please report it.",
	},
	{
		.code = EC_ZEBRA_REMOVE_UNREGISTERED_ADDR,
		.title =
			"Zebra tried to remove unregistered address",
		.description =
			"Zebra attempted to remove an address from a subnet it was not registered on.",
		.suggestion =
			"This is a bug, please report it.",
	},
	{
		.code = EC_ZEBRA_PTM_NOT_READY,
		.title =
			"Interface is up but PTM check has not completed",
		.description =
			"Zebra noticed that an interface came up and attempted to perform its usual setup procedures, but the PTM check failed and the operation was aborted.",
		.suggestion =
			"If the problem persists, ensure that the interface is actually up and that PTM is functioning properly.",
	},
	{
		.code = EC_ZEBRA_UNSUPPORTED_V4_SRCDEST,
		.title =
			"Kernel rejected sourcedest route",
		.description =
			"Zebra attempted to install a sourcedest route into the kernel, but the kernel did not acknowledge its installation. The route is unsupported.",
		.suggestion =
			"Check configuration values for correctness",
	},
	{
		.code = EC_ZEBRA_UNKNOWN_INTERFACE,
		.title =
			"Zebra encountered an unknown interface specifier",
		.description =
			"Zebra was asked to look up an interface with a given name or index, but could not find the interface corresponding to the given name or index.",
		.suggestion =
			"Check configuration values for correctness.",
	},
	{
		.code = EC_ZEBRA_VRF_NOT_FOUND,
		.title =
			"Zebra could not find the specified VRF",
		.description =
			"Zebra tried to look up a VRF, either by name or ID, and could not find it. This could be due to internal inconsistency (a bug) or a configuration error.",
		.suggestion =
			"Check configuration values for correctness. If values are correct, please file a bug report.",
	},
	{
		.code = EC_ZEBRA_MORE_NH_THAN_MULTIPATH,
		.title =
			"More nexthops were provided than the configured multipath limit",
		.description =
			"A route with multiple nexthops was given, but the number of nexthops exceeded the configured multipath limit.",
		.suggestion =
			"Reduce the number of nexthops, or increase the multipath limit.",
	},
	{
		.code = EC_ZEBRA_NEXTHOP_CREATION_FAILED,
		.title =
			"Zebra failed to create one or more nexthops",
		.description =
			"While attempting to create nexthops for a route installation operation, Zebra found that it was unable to create one or more of the given nexthops.",
		.suggestion =
			"Check configuration values for correctness. If they are correct, report this as a bug.",
	},
	{
		.code = EC_ZEBRA_RX_ROUTE_NO_NEXTHOPS,
		.title =
			"Zebra received an installation request for a route without nexthops",
		.description =
			"Zebra received a message from a client requesting a route installation, but the route is invalid since it doesn't have any nexthop address or interface.",
		.suggestion =
			"This is a bug; please report it.",
	},
	{
		.code = EC_ZEBRA_RX_SRCDEST_WRONG_AFI,
		.title =
			"Zebra received sourcedest route install without IPv6 address family",
		.description =
			"Zebra received a message from a client requesting a sourcedest route installation, but the address family was not set to IPv6. Only IPv6 is supported for sourcedest routing.",
		.suggestion =
			"This is a bug; please report it.",
	},
	{
		.code = EC_ZEBRA_PSEUDOWIRE_EXISTS,
		.title =
			"Zebra received an installation / creation request for a pseudowire that already exists",
		.description =
			"Zebra received an installation or creation request for a pseudowire that already exists, so the installation / creation has been skipped.",
		.suggestion =
			"This message is informational.",
	},
	{
		.code = EC_ZEBRA_PSEUDOWIRE_NONEXISTENT,
		.title =
			"Zebra received an uninstallation / deletion request for a pseudowire that already exists",
		.description =
			"Zebra received an uninstallation / deletion request for a pseudowire that doesn't exist, so the uninstallation / deletion has been skipped.",
		.suggestion =
			"This message is informational.",
	},
	{
		.code = EC_ZEBRA_PSEUDOWIRE_UNINSTALL_NOT_FOUND,
		.title =
			"Zebra received uninstall request for a pseudowire that doesn't exist",
		.description =
			"Zebra received an uninstall request for a pseudowire that doesn't exist, so the uninstallation has been skipped.",
		.suggestion =
			"This message is informational.",
	},
	{
		.code = EC_ZEBRA_NO_IFACE_ADDR,
		.title = "No address on interface",
		.description =
			"Zebra attempted to retrieve a connected address for an interface, but the interface had no connected addresses.",
		.suggestion =
			"This warning is situational; it is usually informative but can indicate a misconfiguration.",
	},
	{
		.code = EC_ZEBRA_IFACE_ADDR_ADD_FAILED,
		.title =
			"Zebra failed to add address to interface",
		.description =
			"Zebra attempted to add an address to an interface but was unsuccessful.",
		.suggestion =
			"Check configuration values for correctness.",
	},
	{
		.code = EC_ZEBRA_IRDP_CANNOT_ACTIVATE_IFACE,
		.title =
			"Zebra could not enable IRDP on interface",
		.description =
			"Zebra attempted to enable IRDP on an interface, but could not create the IRDP socket. The system may be out of socket resources, or privilege elevation may have failed.",
		.suggestion =
			"Verify that Zebra has the appropriate privileges and that the system has sufficient socket resources.",
	},
	{
		.code = EC_ZEBRA_IRDP_IFACE_DOWN,
		.title =
			"Zebra attempted to enable IRDP on an interface, but the interface was down",
		.description = "Zebra attempted to enable IRDP on an interface, but the interface was down.",
		.suggestion =
			"Bring up the interface that IRDP is desired on.",
	},
	{
		.code = EC_ZEBRA_IRDP_IFACE_MCAST_DISABLED,
		.title =
			"Zebra cannot enable IRDP on interface because multicast is disabled",
		.description =
			"Zebra attempted to enable IRDP on an interface, but multicast functionality was not enabled on the interface.",
		.suggestion =
			"Enable multicast on the interface.",
	},
	{
		.code = EC_ZEBRA_NETLINK_EXTENDED_WARNING,
		.title =
			"Zebra received warning message from Netlink",
		.description =
			"Zebra received a warning message from Netlink",
		.suggestion =
			"This message is informational. See the Netlink error message for details.",
	},
	{
		.code = EC_ZEBRA_NAMESPACE_DIR_INACCESSIBLE,
		.title =
			"Zebra could not access /var/run/netns",
		.description =
			"Zebra tried to verify that the run directory for Linux network namespaces existed, but this test failed.",
		.suggestion =
			"Ensure that Zebra has the proper privileges to access this directory.",
	},
	{
		.code = EC_ZEBRA_CONNECTED_AFI_UNKNOWN,
		.title =
			"Zebra received unknown address family on interface",
		.description =
			"Zebra received a notification of a connected prefix on an interface but did not recognize the address family as IPv4 or IPv6",
		.suggestion =
			"This message is informational.",
	},
	{
		.code = EC_ZEBRA_IFACE_SAME_LOCAL_AS_PEER,
		.title =
			"Zebra route has same destination address as local interface",
		.description =
			"Zebra noticed that a route on an interface has the same destination address as an address on the interface itself, which may cause issues with routing protocols.",
		.suggestion =
			"Investigate the source of the route to determine why the destination and interface addresses are the same.",
	},
	{
		.code = EC_ZEBRA_BCAST_ADDR_MISMATCH,
		.title =
			"Zebra broadcast address sanity check failed",
		.description =
			"Zebra computed the broadcast address for a connected prefix based on the netmask and found that it did not match the broadcast address it received for the prefix on that interface",
		.suggestion =
			"Investigate the source of the broadcast address to determine why it does not match the computed address.",
	},
	{
		.code = EC_ZEBRA_REDISTRIBUTE_UNKNOWN_AF,
		.title =
			"Zebra encountered unknown address family during redistribution",
		.description =
			"During a redistribution operation Zebra encountered an unknown address family.",
		.suggestion =
			"This warning can be ignored; the redistribution operation will skip the unknown address family.",
	},
	{
		.code = EC_ZEBRA_ADVERTISING_UNUSABLE_ADDR,
		.title =
			"Zebra advertising unusable interface address",
		.description =
			"Zebra is advertising an address on an interface that is not yet fully installed on the interface.",
		.suggestion =
			"This message is informational. The address should show up on the interface shortly after advertisement.",
	},
	{
		.code = EC_ZEBRA_RA_PARAM_MISMATCH,
		.title =
			"Zebra received route advertisement with parameter mismatch",
		.description =
			"Zebra received a router advertisement, but one of the non-critical parameters (AdvCurHopLimit, AdvManagedFlag, AdvOtherConfigFlag, AdvReachableTime or AdvRetransTimer) does not match Zebra's local settings.",
		.suggestion =
			"This message is informational; the route advertisement will be processed as normal. If issues arise due to the parameter mismatch, check Zebra's router advertisement configuration.",
	},
	{
		.code = EC_ZEBRA_RTM_VERSION_MISMATCH,
		.title =
			"Zebra received kernel message with unknown version",
		.description =
			"Zebra received a message from the kernel with a message version that does not match Zebra's internal version. Depending on version compatibility, this may cause issues sending and receiving messages to the kernel.",
		.suggestion =
			"If issues arise, check if there is a version of FRR available for your kernel version.",
	},
	{
		.code = EC_ZEBRA_RTM_NO_GATEWAY,
		.title =
			"Zebra could not determine proper gateway for kernel route",
		.description =
			"Zebra attempted to install a route into the kernel, but noticed it had no gateway and no interface with a gateway could be located.",
		.suggestion =
			"Check configuration values for correctness.",
	},
	{
		.code = EC_ZEBRA_MAX_LABELS_PUSH,
		.title =
			"Zebra exceeded maximum LSP labels for a single rtmsg",
		.description =
			"Zebra attempted to push more than one label into the kernel; the maximum on OpenBSD is 1 label.",
		.suggestion =
			"This message is informational.",
	},
	{
		.code = EC_ZEBRA_STICKY_MAC_ALREADY_LEARNT,
		.title =
			"EVPN MAC already learnt as remote sticky MAC",
		.description =
			"Zebra tried to handle a local MAC addition but noticed that it had already learnt the MAC from a remote peer.",
		.suggestion =
			"Check configuration values for correctness.",
	},
	{
		.code = EC_ZEBRA_UNSUPPORTED_V6_SRCDEST,
		.title =
			"Kernel does not support IPv6 sourcedest routes",
		.description =
			"Zebra attempted to install a sourcedest route into the kernel, but IPv6 sourcedest routes are not supported on the current kernel.",
		.suggestion =
			"Do not use v6 sourcedest routes, or upgrade your kernel.",
	},
	{
		.code = EC_ZEBRA_DUP_MAC_DETECTED,
		.title =
			"EVPN MAC is detected duplicate",
		.description =
			"Zebra has hit duplicate address detection threshold which means host MAC is moving.",
		.suggestion =
			"Check network topology to detect duplicate host MAC for correctness.",
	},
	{
		.code = EC_ZEBRA_DUP_IP_INHERIT_DETECTED,
		.title =
			"EVPN IP is detected duplicate by MAC",
		.description =
			"Zebra has hit duplicate address detection threshold which means MAC-IP pair is moving.",
		.suggestion =
			"Check network topology to detect duplicate host MAC for correctness.",
	},
	{
		.code = EC_ZEBRA_DUP_IP_DETECTED,
		.title =
			"EVPN IP is detected duplicate",
		.description =
			"Zebra has hit duplicate address detection threshold which means host IP is moving.",
		.suggestion =
			"Check network topology to detect duplicate host IP for correctness.",
	},
	{
		.code = EC_ZEBRA_BAD_NHG_MESSAGE,
		.title =
			"Bad Nexthop Group Message",
		.description =
			"Zebra received Nexthop Group message from the kernel that it cannot process.",
		.suggestion =
			"Check the kernel's link states and routing table to see how it matches ours."
	},
	{
		.code = EC_ZEBRA_DUPLICATE_NHG_MESSAGE,
		.title =
			"Duplicate Nexthop Group Message",
		.description =
			"Zebra received Nexthop Group message from the kernel that it is identical to one it/we already have but with a different ID.",
		.suggestion =
			"See if the nexthop you are trying to add is already present in the fib."
	},
	{
		.code = END_FERR,
	}
};
/* clang-format on */


void zebra_error_init(void)
{
	log_ref_add(ferr_zebra_err);
}
