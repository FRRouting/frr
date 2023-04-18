// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "pcep_msg_object_error_types.h"
#include "pcep_utils_logging.h"

/* All of these values were copied from:
 *     https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-error-object
 * Which was last updated 2020-06-02 */

static const char *error_type_strings[] = {
	"Reserved",
	"PCEP session establishment failure",
	"Capability not supported",
	"Unknown Object",
	"Not supported object",
	"Policy violation",
	"Mandatory Object missing",
	"Synchronized path computation request missing",
	"Unknown request reference",
	"Attempt to establish a second PCEP session",

	"Reception of an invalid object", /* 10 */
	"Unrecognized EXRS subobject",
	"Diffserv-aware TE error",
	"BRPC procedure completion failure",
	"Unassigned 14",
	"Global Concurrent Optimization Error",
	"P2MP Capability Error",
	"P2MP END-POINTS Error",
	"P2MP Fragmentation Error",
	"Invalid Operation",

	"LSP State Synchronization Error", /* 20 */
	"Invalid traffic engineering path setup type",
	"Unassigned 22",
	"Bad parameter value",
	"LSP instantiation error",
	"PCEP StartTLS failure",
	"Association Error",
	"WSON RWA Error",
	"H-PCE Error",
	"Path computation failure",
	"Unassigned 30"};

static const char *error_value_strings[MAX_ERROR_TYPE][MAX_ERROR_VALUE] = {

	/* 0   Reserved */
	{"Unassigned"},

	/* 1   PCEP session establishment failure */
	{
		"Unassigned",
		"reception of an invalid Open message or a non Open message.",
		"no Open message received before the expiration of the OpenWait timer",
		"unacceptable and non negotiable session characteristics",
		"unacceptable but negotiable session characteristics",
		"reception of a second Open message with still unacceptable session characteristics",
		"reception of a PCErr message proposing unacceptable session characteristics",
		"No Keepalive or PCErr message received before the expiration of the KeepWait timer",
		"PCEP version not supported",
	},

	/* 2   Capability not supported */
	{"Unassigned"},

	/* 3   Unknown Object */
	{
		"Unassigned",
		"Unrecognized object class",
		"Unrecognized object Type",
	},

	/* 4   Not supported object */
	{
		"Unassigned",
		"Not supported object class",
		"Not supported object Type",
		"Unassigned",
		"Unsupported parameter",
		"Unsupported network performance constraint",
		"Bandwidth Object type 3 or 4 not supported",
		"Unsupported endpoint type in END-POINTS Generalized Endpoint object type",
		"Unsupported TLV present in END-POINTS Generalized Endpoint object type",
		"Unsupported granularity in the RP object flags",
	},

	/* 5   Policy violation */
	{
		"Unassigned",
		"C bit of the METRIC object set (request rejected)",
		"O bit of the RP object cleared (request rejected)",
		"objective function not allowed (request rejected)",
		"OF bit of the RP object set (request rejected)",
		"Global concurrent optimization not allowed",
		"Monitoring message supported but rejected due to policy violation",
		"P2MP Path computation is not allowed",
		"Not allowed network performance constraint",
	},

	/* 6   Mandatory Object missing */
	{
		"Unassigned",
		"RP object missing",
		"RRO missing for a reoptimization request (R bit of the RP object set)",
		"END-POINTS object missing",
		"MONITORING object missing",
		"Unassigned",
		"Unassigned",
		"Unassigned",
		"LSP object missing",
		"ERO object missing",
		"SRP object missing",
		"LSP-IDENTIFIERS TLV missing",
		"LSP-DB-VERSION TLV missing",
		"S2LS object missing",
		"P2MP-LSP-IDENTIFIERS TLV missing",
		"DISJOINTNESS-CONFIGURATION TLV missing",
	},

	/* 7   Synchronized path computation request missing */
	{"Unassigned"},

	/* 8   Unknown request reference */
	{"Unassigned"},

	/* 9   Attempt to establish a second PCEP session */
	{"Unassigned"},

	/* 10  Reception of an invalid object */
	{
		"Unassigned",
		"reception of an object with P flag not set although the P-flag must be set according to this specification.",
		"Bad label value",
		"Unsupported number of SR-ERO subobjects",
		"Bad label format",
		"ERO mixes SR-ERO subobjects with other subobject types",
		"Both SID and NAI are absent in the SR-ERO subobject",
		"Both SID and NAI are absent in the SR-RRO subobject",
		"SYMBOLIC-PATH-NAME TLV missing",
		"MSD exceeds the default for the PCEP session",
		"RRO mixes SR-RRO subobjects with other subobject types",
		"Malformed object",
		"Missing PCE-SR-CAPABILITY sub-TLV",
		"Unsupported NAI Type in the SR-ERO/SR-RRO subobject",
		"Unknown SID",
		"NAI cannot be resolved to a SID",
		"Could not find SRGB",
		"SID index exceeds SRGB size",
		"Could not find SRLB",
		"SID index exceeds SRLB size",
		"Inconsistent SIDs in SR-ERO / SR-RRO subobjects",
		"MSD must be nonzero",
		"Mismatch of O field in S2LS and LSP object",
		"Incompatible OF codes in H-PCE",
		"Bad Bandwidth Object type 3 (Generalized bandwidth) or 4 (Generalized bandwidth of existing TE-LSP for which a reoptimization is requested)",
		"Unsupported LSP Protection Flags in PROTECTION-ATTRIBUTE TLV",
		"Unsupported Secondary LSP Protection Flags in PROTECTION-ATTRIBUTE TLV",
		"Unsupported Link Protection Type in PROTECTION-ATTRIBUTE TLV",
		"LABEL-SET TLV present with 0 bit set but without R bit set in RP",
		"Wrong LABEL-SET TLV present with 0 and L bit set",
		"Wrong LABEL-SET with O bit set and wrong format",
		"Missing GMPLS-CAPABILITY TLV",
		"Incompatible OF code",
	},

	/* 11  Unrecognized EXRS subobject */
	{"Unassigned"},

	/* 12  Diffserv-aware TE error */
	{
		"Unassigned",
		"Unsupported class-type",
		"Invalid class-type",
		"Class-Type and setup priority do not form a configured TE-class",
	},

	/* 13  BRPC procedure completion failure */
	{
		"Unassigned",
		"BRPC procedure not supported by one or more PCEs along the domain path",
	},

	/* 14  Unassigned */
	{"Unassigned"},

	/* 15  Global Concurrent Optimization Error */
	{
		"Unassigned",
		"Insufficient memory",
		"Global concurrent optimization not supported",
	},

	/* 16  P2MP Capability Error */
	{
		"Unassigned",
		"The PCE cannot satisfy the request due to insufficient memory",
		"The PCE is not capable of P2MP computation",
	},

	/* 17  P2MP END-POINTS Error */
	{
		"Unassigned",
		"The PCE cannot satisfy the request due to no END-POINTS with leaf type 2",
		"The PCE cannot satisfy the request due to no END-POINTS with leaf type 3",
		"The PCE cannot satisfy the request due to no END-POINTS with leaf type 4",
		"The PCE cannot satisfy the request due to inconsistent END-POINTS",
	},

	/* 18  P2MP Fragmentation Error */
	{
		"Unassigned",
		"Fragmented request failure",
		"Fragmented Report failure",
		"Fragmented Update failure",
		"Fragmented Instantiation failure",
	},

	/* 19  Invalid Operation */
	{
		"Unassigned",
		"Attempted LSP Update Request for a non-delegated LSP. The PCEP-ERROR object is followed by the LSP object that identifies the LSP.",
		"Attempted LSP Update Request if the stateful PCE capability was not advertised.",
		"Attempted LSP Update Request for an LSP identified by an unknown PLSP-ID.",
		"Unassigned",
		"Attempted LSP State Report if active stateful PCE capability was not advertised.",
		"PCE-initiated LSP limit reached",
		"Delegation for PCE-initiated LSP cannot be revoked",
		"Non-zero PLSP-ID in LSP Initiate Request",
		"LSP is not PCE initiated",
		"PCE-initiated operation-frequency limit reached",
		"Attempted LSP State Report for P2MP if stateful PCE capability for P2MP was not advertised",
		"Attempted LSP Update Request for P2MP if active stateful PCE capability for P2MP was not advertised",
		"Attempted LSP Instantiation Request for P2MP if stateful PCE instantiation capability for P2MP was not advertised",
		"Auto-Bandwidth capability was not advertised",
	},

	/* 20  LSP State Synchronization Error */
	{
		"Unassigned",
		"A PCE indicates to a PCC that it cannot process (an otherwise valid) LSP State Report. The PCEP- ERROR object is followed by the LSP object that identifies the LSP.",
		"LSP-DB version mismatch.",
		"Attempt to trigger synchronization before PCE trigger.",
		"Attempt to trigger a synchronization when the PCE triggered synchronization capability has not been advertised.",
		"A PCC indicates to a PCE that it cannot complete the State Synchronization.",
		"Received an invalid LSP-DB Version Number.",
		"Received an invalid Speaker Entity Identifier.",
	},

	/* 21  Invalid traffic engineering path setup type */
	{
		"Unassigned",
		"Unsupported path setup type",
		"Mismatched path setup type",
	},

	/* 22  Unassigned */
	{"Unassigned"},

	/* 23  Bad parameter value */
	{
		"Unassigned",
		"SYMBOLIC-PATH-NAME in use",
		"Speaker identity included for an LSP that is not PCE initiated",
	},

	/* 24  LSP instantiation error */
	{
		"Unassigned",
		"Unacceptable instantiation parameters",
		"Internal error",
		"Signaling error",
	},

	/* 25  PCEP StartTLS failure */
	{
		"Unassigned",
		"Reception of StartTLS after any PCEP exchange",
		"Reception of any other message apart from StartTLS, Open, or PCErr",
		"Failure, connection without TLS is not possible",
		"Failure, connection without TLS is possible",
		"No StartTLS message (nor PCErr/Open) before StartTLSWait timer expiry",
	},

	/* 26  Association Error */
	{
		"Unassigned",
		"Association Type is not supported",
		"Too many LSPs in the association group",
		"Too many association groups",
		"Association unknown",
		"Operator-configured association information mismatch",
		"Association information mismatch",
		"Cannot join the association group",
		"Association ID not in range",
		"Tunnel ID or End points mismatch for Path Protection Association",
		"Attempt to add another working/protection LSP for Path Protection Association",
		"Protection type is not supported",
	},

	/* 27  WSON RWA Error */
	{
		"Unassigned",
		"Insufficient Memory",
		"RWA computation Not supported",
		"Syntactical Encoding error",
	},

	/* 28  H-PCE Error */
	{
		"Unassigned",
		"H-PCE Capability not advertised",
		"Parent PCE Capability cannot be provided",
	},

	/* 29  Path computation failure */
	{
		"Unassigned",
		"Unacceptable request message",
		"Generalized bandwidth value not supported",
		"Label Set constraint could not be met",
		"Label constraint could not be met",
	}

	/* 30-255  Unassigned */
};


const char *get_error_type_str(enum pcep_error_type error_type)
{
	if (error_type < 0 || error_type >= MAX_ERROR_TYPE) {
		pcep_log(
			LOG_DEBUG,
			"%s: get_error_type_str: error_type [%d] out of range [0..%d]",
			__func__, error_type, MAX_ERROR_TYPE);

		return NULL;
	}

	return error_type_strings[error_type];
}

const char *get_error_value_str(enum pcep_error_type error_type,
				enum pcep_error_value error_value)
{
	if (error_type < 0 || error_type >= MAX_ERROR_TYPE) {
		pcep_log(
			LOG_DEBUG,
			"%s: get_error_value_str: error_type [%d] out of range [0..%d]",
			__func__, error_type, MAX_ERROR_TYPE);

		return NULL;
	}

	if (error_value < 0 || error_value >= MAX_ERROR_VALUE) {
		pcep_log(
			LOG_DEBUG,
			"%s: get_error_value_str: error_value [%d] out of range [0..%d]",
			__func__, error_value, MAX_ERROR_VALUE);

		return NULL;
	}

	if (error_value_strings[error_type][error_value] == NULL) {
		return "Unassigned";
	}

	return error_value_strings[error_type][error_value];
}
