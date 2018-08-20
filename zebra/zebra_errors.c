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

DEFINE_LOGCAT(ZEBRA_ERR_LM_RESPONSE, ROOT, "Error reading response from label manager",
	.description = "Zebra could not read the ZAPI header from the label manager",
	.suggestion = "Wait for the error to resolve on its own. If it does not resolve, restart Zebra.",
)
DEFINE_LOGCAT(ZEBRA_ERR_LM_NO_SUCH_CLIENT, ROOT, "Label manager could not find ZAPI client",
	.description = "Zebra was unable to find a ZAPI client matching the given protocol and instance number.",
	.suggestion = "Ensure clients which use the label manager are properly configured and running.",
)
DEFINE_LOGCAT(ZEBRA_ERR_LM_NO_SOCKET, ROOT, "")
DEFINE_LOGCAT(ZEBRA_ERR_LM_CLIENT_CONNECTION_FAILED, ROOT, "")
DEFINE_LOGCAT(ZEBRA_ERR_LM_RELAY_FAILED, ROOT, "Zebra could not relay label manager response",
	.description = "Zebra found the client and instance to relay the label manager response or request to, but was not able to do so, possibly because the connection was closed.",
	.suggestion = "Ensure clients which use the label manager are properly configured and running.",
)
DEFINE_LOGCAT(ZEBRA_ERR_LM_BAD_INSTANCE, ROOT, "Mismatch between ZAPI instance and encoded message instance",
	.description = "While relaying a request to the external label manager, Zebra noticed that the instance number encoded in the message did not match the client instance number.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_LM_EXHAUSTED_LABELS, ROOT, "Zebra label manager used all available labels",
	.description = "Zebra is unable to assign additional label chunks because it has exhausted its assigned label range.",
	.suggestion = "Make the label range bigger and restart Zebra.",
)
DEFINE_LOGCAT(ZEBRA_ERR_LM_DAEMON_MISMATCH, ROOT, "Daemon mismatch when releasing label chunks",
	.description = "Zebra noticed a mismatch between a label chunk and a protocol daemon number or instance when releasing unused label chunks.",
	.suggestion = "Ignore this error.",
)
DEFINE_LOGCAT(ZEBRA_ERR_LM_UNRELEASED_CHUNK, ROOT, "Zebra did not free any label chunks",
	.description = "Zebra's chunk cleanup procedure ran, but no label chunks were released.",
	.suggestion = "Ignore this error.",
)
DEFINE_LOGCAT(ZEBRA_ERR_DP_INVALID_RC, ROOT, "Dataplane returned invalid status code",
	.description = "The underlying dataplane responded to a Zebra message or other interaction with an unrecognized, unknown or invalid status code.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_WQ_NONEXISTENT, ROOT, "A necessary work queue does not exist.",
	.description = "A necessary work queue does not exist.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_FEC_ADD_FAILED, ROOT, "Failed to add FEC for MPLS client",
	.description = "A client requested a label binding for a new FEC, but Zebra was unable to add the FEC to its internal table.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_FEC_RM_FAILED, ROOT, "Failed to remove FEC for MPLS client",
	.description = "Zebra was unable to find and remove a FEC in its internal table.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_IRDP_LEN_MISMATCH, ROOT, "IRDP message length mismatch",
	.description = "The length encoded in the IP TLV does not match the length of the packet received.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_RNH_UNKNOWN_FAMILY, ROOT, "Attempted to perform nexthop update for unknown address family",
	.description = "Zebra attempted to perform a nexthop update for unknown address family",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_DP_INSTALL_FAIL, ROOT, "Dataplane installation failure",
	.description = "Installation of routes to underlying dataplane failed.",
	.suggestion = "Check all configuration parameters for correctness.",
)
DEFINE_LOGCAT(ZEBRA_ERR_TABLE_LOOKUP_FAILED, ROOT, "Zebra table lookup failed",
	.description = "Zebra attempted to look up a table for a particular address family and subsequent address family, but didn't find anything.",
	.suggestion = "If you entered a command to trigger this error, make sure you entered the arguments correctly. Check your config file for any potential errors. If these look correct, seek help.",
)
DEFINE_LOGCAT(ZEBRA_ERR_NETLINK_NOT_AVAILABLE, ROOT, "Netlink backend not available",
	.description = "FRR was not compiled with support for Netlink. Any operations that require Netlink will fail.",
	.suggestion = "Recompile FRR with Netlink, or install a package that supports this feature.",
)
DEFINE_LOGCAT(ZEBRA_ERR_PROTOBUF_NOT_AVAILABLE, ROOT, "Protocol Buffers backend not available",
	.description = "FRR was not compiled with support for Protocol Buffers. Any operations that require Protobuf will fail.",
	.suggestion = "Recompile FRR with Protobuf support, or install a package that supports this feature.",
)
DEFINE_LOGCAT(ZEBRA_ERR_TM_EXHAUSTED_IDS, ROOT, "Table manager used all available IDs",
	.description = "Zebra's table manager used up all IDs available to it and can't assign any more.",
	.suggestion = "Reconfigure Zebra with a larger range of table IDs.",
)
DEFINE_LOGCAT(ZEBRA_ERR_TM_DAEMON_MISMATCH, ROOT, "Daemon mismatch when releasing table chunks",
	.description = "Zebra noticed a mismatch between a table ID chunk and a protocol daemon number instance when releasing unused table chunks.",
	.suggestion = "Ignore this error.",
)
DEFINE_LOGCAT(ZEBRA_ERR_TM_UNRELEASED_CHUNK, ROOT, "Zebra did not free any table chunks",
	.description = "Zebra's table chunk cleanup procedure ran, but no table chunks were released.",
	.suggestion = "Ignore this error.",
)
DEFINE_LOGCAT(ZEBRA_ERR_UNKNOWN_FAMILY, ROOT, "Address family specifier unrecognized",
	.description = "Zebra attempted to process information from somewhere that included an address family specifier, but did not recognize the provided specifier.",
	.suggestion = "Ensure that your configuration is correct. If it is, notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_TM_WRONG_PROTO, ROOT, "Incorrect protocol for table manager client",
	.description = "Zebra's table manager only accepts connections from daemons managing dynamic routing protocols, but received a connection attempt from a daemon that does not meet this criterion.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_PROTO_OR_INSTANCE_MISMATCH, ROOT, "Mismatch between message and client protocol and/or instance",
	.description = "Zebra detected a mismatch between a client's protocol and/or instance numbers versus those stored in a message transiting its socket.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_LM_CANNOT_ASSIGN_CHUNK, ROOT, "Label manager unable to assign label chunk",
	.description = "Zebra's label manager was unable to assign a label chunk to client.",
	.suggestion = "Ensure that Zebra has a sufficient label range available and that there is not a range collision.",
)
DEFINE_LOGCAT(ZEBRA_ERR_LM_ALIENS, ROOT, "Label request from unidentified client",
	.description = "Zebra's label manager received a label request from an unidentified client.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_TM_CANNOT_ASSIGN_CHUNK, ROOT, "Table manager unable to assign table chunk",
	.description = "Zebra's table manager was unable to assign a table chunk to a client.",
	.suggestion = "Ensure that Zebra has sufficient table ID range available and that there is not a range collision.",
)
DEFINE_LOGCAT(ZEBRA_ERR_TM_ALIENS, ROOT, "Table request from unidentified client",
	.description = "Zebra's table manager received a table request from an unidentified client.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_RECVBUF, ROOT, "Cannot set receive buffer size",
	.description = "Socket receive buffer size could not be set in the kernel",
	.suggestion = "Ignore this error.",
)
DEFINE_LOGCAT(ZEBRA_ERR_UNKNOWN_NLMSG, ROOT, "Unknown Netlink message type",
	.description = "Zebra received a Netlink message with an unrecognized type field.",
	.suggestion = "Verify that you are running the latest version of FRR to ensure kernel compatibility. If the problem persists, notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_RECVMSG_OVERRUN, ROOT, "Receive buffer overrun",
	.description = "The kernel's buffer for a socket has been overrun, rendering the socket invalid.",
	.suggestion = "Zebra will restart itself. Notify a developer if this issue shows up frequently.",
)
DEFINE_LOGCAT(ZEBRA_ERR_NETLINK_LENGTH_ERROR, ROOT, "Netlink message length mismatch",
	.description = "Zebra received a Netlink message with incorrect length fields.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_UNEXPECTED_MESSAGE, ROOT, "Received unexpected response from kernel",
	.description = "Received unexpected response from the kernel via Netlink.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_NETLINK_BAD_SEQUENCE, ROOT, "Bad sequence number in Netlink message",
	.description = "Zebra received a Netlink message with a bad sequence number.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_BAD_MULTIPATH_NUM, ROOT, "Multipath number was out of valid range",
	.description = "Multipath number specified to Zebra must be in the appropriate range",
	.suggestion = "Provide a multipath number that is within its accepted range",
)
DEFINE_LOGCAT(ZEBRA_ERR_PREFIX_PARSE_ERROR, ROOT, "String could not be parsed as IP prefix",
	.description = "There was an attempt to parse a string as an IPv4 or IPv6 prefix, but the string could not be parsed and this operation failed.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_MAC_ADD_FAILED, ROOT, "Failed to add MAC address to interface",
	.description = "Zebra attempted to assign a MAC address to a vxlan interface but failed",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_VNI_DEL_FAILED, ROOT, "Failed to delete VNI",
	.description = "Zebra attempted to delete a VNI entry and failed",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_VTEP_ADD_FAILED, ROOT, "Adding remote VTEP failed",
	.description = "Zebra attempted to add a remote VTEP and failed.",
	.suggestion = "Notify a developer.",
)
DEFINE_LOGCAT(ZEBRA_ERR_VNI_ADD_FAILED, ROOT, "Adding VNI failed",
	.description = "Zebra attempted to add a VNI hash to an interface and failed",
	.suggestion = "Notify a developer.",
)
