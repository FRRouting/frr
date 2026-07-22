// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information VTY commands
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "json.h"
#include "vrf.h"
#include "vty.h"
#include <time.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_unreach.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_trace.h"

#include "bgpd/bgp_unreach_vty_clippy.c"

DEFPY_HIDDEN(
	bgp_inject_unreachability, bgp_inject_unreachability_cmd,
	"bgp inject unreachability [vrf NAME$vrf_name] <ipv4|ipv6>$afi_str <A.B.C.D/M|X:X::X:X/M>$prefix_str [reason-code <unspecified|policy-blocked|security-filtered|rpki-invalid|no-export-policy|martian-address|bogon-prefix|maintenance|local-admin-action|local-link-down|(0-65535)>$reason_str]",
	BGP_STR "Inject test data\n"
		"Unreachability information\n"
		VRF_CMD_HELP_STR
		"IPv4\n"
		"IPv6\n"
		"IPv4 prefix\n"
		"IPv6 prefix\n"
		"Unreachability Reason Code (Sub-TLV Type 1)\n"
		"Unspecified reason (0)\n"
		"Blocked by policy (1)\n"
		"Filtered for security reasons (2)\n"
		"RPKI validation failed (3)\n"
		"No export policy (4)\n"
		"Martian address (5)\n"
		"Bogon prefix (6)\n"
		"Maintenance (7)\n"
		"Local administrative action (8)\n"
		"Local link down (9)\n"
		"Numeric reason code value\n")
{
	struct bgp *bgp;
	struct bgp_unreach_nlri unreach;
	afi_t afi;

	if (!vrf_name || strmatch(vrf_name, VRF_DEFAULT_NAME))
		bgp = bgp_get_default();
	else
		bgp = bgp_lookup_by_name(vrf_name);
	if (!bgp) {
		vty_out(vty, "%% BGP instance not found%s%s\n",
			vrf_name ? " for VRF " : "",
			vrf_name ? vrf_name : "");
		return CMD_WARNING;
	}

	afi = bgp_vty_afi_from_str(afi_str);
	if (afi == AFI_MAX)
		return CMD_WARNING;

	/* Build unreachability NLRI */
	memset(&unreach, 0, sizeof(unreach));
	prefix_copy(&unreach.prefix, prefix_str);

	/*
	 * Reporter TLV (Type 1): Reporter ID + Reporter AS + Sub-TLVs.
	 * Auto-populated from local BGP instance.
	 */
	unreach.reporter = bgp->router_id;
	unreach.has_reporter = true;
	unreach.reporter_as = bgp->as;
	unreach.has_reporter_as = true;

	/* Sub-TLV Type 1: Reason Code (defaults to UNSPECIFIED if not provided) */
	if (reason_str) {
		if (bgp_unreach_reason_str2code(reason_str, &unreach.reason_code) < 0) {
			unreach.reason_code = atoi(reason_str);
			if (unreach.reason_code >= 10 && unreach.reason_code <= 64535) {
				vty_out(vty, "%% Reason code %u is reserved\n",
					unreach.reason_code);
				return CMD_WARNING;
			}
		}
	} else {
		unreach.reason_code = BGP_UNREACH_REASON_UNSPECIFIED;
	}
	unreach.has_reason_code = true;

	/* Sub-TLV Type 2: Timestamp (ALWAYS attached) */
	unreach.timestamp = time(NULL);
	unreach.has_timestamp = true;

	/* Add to UI-RIB */
	if (bgp_unreach_info_add(bgp, afi, &unreach, NULL) < 0) {
		vty_out(vty, "%% Failed to inject unreachability info\n");
		return CMD_WARNING;
	}

	char reporter_str[INET_ADDRSTRLEN];
	const char *reason_name =
		bgp_unreach_reason_str(unreach.reason_code);

	inet_ntop(AF_INET, &unreach.reporter, reporter_str, sizeof(reporter_str));
	vty_out(vty, "Injected unreachability for %pFX (reporter: %s, reason-code: %u (%s))\n",
		prefix_str, reporter_str, unreach.reason_code, reason_name);

	zlog_info("Injected unreachability for %pFX (reason: %u - %s)", prefix_str,
		  unreach.reason_code, reason_name);

	frrtrace(6, frr_bgp, unreach_vty_inject, bgp->name_pretty, &unreach.prefix,
		 &unreach.reporter, unreach.reporter_as, unreach.reason_code,
		 unreach.timestamp);

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(no_bgp_inject_unreachability, no_bgp_inject_unreachability_cmd,
	     "no bgp inject unreachability [vrf NAME$vrf_name] <ipv4|ipv6>$afi_str <A.B.C.D/M|X:X::X:X/M>$prefix_str",
	     NO_STR BGP_STR "Remove injected data\n"
			    "Unreachability information\n"
			    VRF_CMD_HELP_STR
			    "IPv4\n"
			    "IPv6\n"
			    "IPv4 prefix\n"
			    "IPv6 prefix\n")
{
	struct bgp *bgp;
	afi_t afi;

	if (!vrf_name || strmatch(vrf_name, VRF_DEFAULT_NAME))
		bgp = bgp_get_default();
	else
		bgp = bgp_lookup_by_name(vrf_name);
	if (!bgp) {
		vty_out(vty, "%% BGP instance not found%s%s\n",
			vrf_name ? " for VRF " : "",
			vrf_name ? vrf_name : "");
		return CMD_WARNING;
	}

	afi = bgp_vty_afi_from_str(afi_str);
	if (afi == AFI_MAX)
		return CMD_WARNING;

	zlog_info("Removed injected unreachability for %pFX", prefix_str);

	/* Remove from UI-RIB */
	bgp_unreach_info_delete(bgp, afi, prefix_str);

	frrtrace(2, frr_bgp, unreach_vty_delete, bgp->name_pretty, prefix_str);

	vty_out(vty, "Removed unreachability for %pFX\n", prefix_str);

	return CMD_SUCCESS;
}

void bgp_unreach_vty_init(void)
{
	/* Inject commands for testing - available at enable mode like clear bgp */
	install_element(ENABLE_NODE, &bgp_inject_unreachability_cmd);
	install_element(ENABLE_NODE, &no_bgp_inject_unreachability_cmd);
}
