// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *		Chirag Shah
 */

#include <zebra.h>

#include "lib/ferr.h"
#include "ospf_errors.h"

/* clang-format off */
static struct log_ref ferr_ospf_warn[] = {
	{
		.code = EC_OSPF_SET_METRIC_PLUS,
		.title = "OSPF does not support `set metric +rtt/-rtt`",
		.description = "This implementation of OSPF does not currently support `set metric +rtt/-rtt`",
		.suggestion = "Do not use this particular set command for an ospf route-map",
	},
	{
		.code = EC_OSPF_AUTH,
		.title = "OSPF has noticed an authentication issue",
		.description = "Something has gone wrong with the calculation of the authentication data",
		.suggestion = "Ensure your key is correct, gather log data from this side as well as peer and open an Issue",
	},
	{
		.code = EC_OSPF_PACKET,
		.title = "OSPF has detected packet information mismatch",
		.description = "OSPF has detected that packet information received is incorrect",
		.suggestion = "Ensure interface configuration is correct, gather log files from here and the peer and open an Issue",
	},
	{
		.code = EC_OSPF_LARGE_LSA,
		.title = "OSPF has determined that a LSA packet will be too large",
		.description = "OSPF has received data that is causing it to recalculate how large packets should be and has discovered that the packet size needed would be too large and we will need to fragment packets",
		.suggestion = "Further divide up your network with areas",
	},
	{
		.code = EC_OSPF_LSA_UNEXPECTED,
		.title = "OSPF has received a LSA-type that it was not expecting",
		.description = "OSPF has received a LSA-type that it was not expecting during processing",
		.suggestion = "Gather log data from this machine and it's peer and open an Issue",
	},
	{
		.code = EC_OSPF_LSA,
		.title = "OSPF has discovered inconsistent internal state for a LSA",
		.description = "During handling of a LSA, OSPF has discovered that the LSA's internal state is inconsistent",
		.suggestion = "Gather log data and open an Issue",
	},
	{
		.code = EC_OSPF_OPAQUE_REGISTRATION,
		.title = "OSPF has failed to properly register Opaque Handler",
		.description = "During initialization OSPF has detected a failure to install an opaque handler",
		.suggestion = "Gather log data and open an Issue",
	},
	{
		.code = EC_OSPF_TE_UNEXPECTED,
		.title = "OSPF has received TE information that it was not expecting",
		.description = "OSPF has received TE information that it was not expecting during normal processing of data",
		.suggestion = "Gather log data from this machine and it's peer and open an Issue",
	},
	{
		.code = EC_OSPF_LSA_INSTALL_FAILURE,
		.title = "OSPF was unable to save the LSA into it's database",
		.description = "During processing of a new lsa and attempting to save the lsa into the OSPF database, this process failed.",
		.suggestion = "Gather log data from this machine and open an Issue",
	},
	{
		.code = EC_OSPF_LSA_NULL,
		.title = "OSPF has received a NULL lsa pointer",
		.description = "When processing a LSA update we have found and noticed an internal error where we are passing around a NULL pointer",
		.suggestion = "Gather data from this machine and it's peer and open an Issue",
	},
	{
		.code = EC_OSPF_EXT_LSA_UNEXPECTED,
		.title = "OSPF has received EXT information that leaves it in an unexpected state",
		.description = "While processing EXT LSA information, OSPF has noticed that the internal state of OSPF has gotten inconsistent",
		.suggestion = "Gather data from this machine and it's peer and open an Issue",
	},
	{
		.code = EC_OSPF_LSA_MISSING,
		.title = "OSPF attempted to look up a LSA and it was not found",
		.description = "During processing of new LSA information, we attempted to look up an old LSA and it was not found",
		.suggestion = "Gather data from this machine and open an Issue",
	},
	{
		.code = EC_OSPF_PTP_NEIGHBOR,
		.title = "OSPF has detected more than 1 neighbor on a P2P interface",
		.description = "If you configure a ospf interface as P2P we should not detect more than one neighbor on the interface",
		.suggestion = "Fix your config",
	},
	{
		.code = EC_OSPF_LSA_SIZE,
		.title = "OSPF has detected an invalid LSA size",
		.description = "OSPF has detected a state where we are attempting to grow a LSA but the LSA has reached it's maximum size",
		.suggestion = "Gather data and open an Issue",
	},
	{
		.code = END_FERR,
	}
};

static struct log_ref ferr_ospf_err[] = {
	{
		.code = EC_OSPF_PKT_PROCESS,
		.title = "Failure to process a packet",
		.description = "OSPF attempted to process a received packet but could not",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_ROUTER_LSA_MISMATCH,
		.title = "Failure to process Router LSA",
		.description = "OSPF attempted to process a Router LSA but Advertising ID mismatch with link id",
		.suggestion = "Check OSPF network config for any config issue, If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_DOMAIN_CORRUPT,
		.title = "OSPF Domain Corruption",
		.description = "OSPF attempted to process a Router LSA but Advertising ID mismatch with link id",
		.suggestion = "Check OSPF network Database for corrupted LSA, If the problem persists, shutdown OSPF domain and report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_INIT_FAIL,
		.title = "OSPF Initialization failure",
		.description = "OSPF failed to initialized OSPF default insance",
		.suggestion = "Ensure there is adequate memory on the device. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_SR_INVALID_DB,
		.title = "OSPF SR Invalid DB",
		.description = "OSPF Segment Routing Database is invalid",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_SR_NODE_CREATE,
		.title = "OSPF SR hash node creation failed",
		.description = "OSPF Segment Routing node creation failed",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_SR_INVALID_LSA_ID,
		.title = "OSPF SR Invalid LSA ID",
		.description = "OSPF Segment Routing invalid lsa id",
		.suggestion = "Restart OSPF instance, If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_SR_SID_OVERFLOW,
		.title = "OSPF SR Segment-ID overflow",
		.description = "OSPF Segment Routing ID index or label exceed Global or Local Block Range",
		.suggestion = "Restart OSPF instance, If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_INVALID_ALGORITHM,
		.title = "OSPF SR Invalid Algorithm",
		.description = "OSPF Segment Routing invalid Algorithm",
		.suggestion = "Most likely a bug. If the problem persists, report the problem for troubleshooting"
	},
	{
		.code = EC_OSPF_FSM_INVALID_STATE,
		.title = "OSPF FSM invalid state detected",
		.description = "OSPF has attempted to change states when it should not be able to",
		.suggestion = "Gather log files and open an issue",
	},
	{
		.code = EC_OSPF_LARGE_HELLO,
		.title = "OSPF Encountered a Large Hello",
		.description = "OSPF attempted to send a Hello larger than MTU but did not",
		.suggestion = "Too many neighbors configured on a single interface. Suggestion is to decrease the number of neighbors on a single interface/subnet"
	},
	{
		.code = END_FERR,
	}
};
/* clang-format on */

void ospf_error_init(void)
{
	log_ref_add(ferr_ospf_warn);
	log_ref_add(ferr_ospf_err);
}
