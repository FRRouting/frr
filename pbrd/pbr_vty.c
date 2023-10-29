// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PBR - vty code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 * Portions:
 *		Copyright (c) 2021 The MITRE Corporation.
 *		Copyright (c) 2023 LabN Consulting, L.L.C.
 */
#include <zebra.h>

#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "vrf.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "nexthop_group_private.h"
#include "log.h"
#include "json.h"
#include "debug.h"
#include "pbr.h"

#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_map.h"
#include "pbrd/pbr_zebra.h"
#include "pbrd/pbr_vty.h"
#include "pbrd/pbr_debug.h"
#include "pbrd/pbr_vty_clippy.c"

/* clang-format off */
DEFPY  (pbr_set_table_range,
	pbr_set_table_range_cmd,
	"pbr table range (10000-4294966272)$lb (10000-4294966272)$ub",
	PBR_STR
	"Set table ID range\n"
	"Set table ID range\n"
	"Lower bound for table ID range\n"
	"Upper bound for table ID range\n")
{
	/* clang-format on */
	/* upper bound is 2^32 - 2^10 */
	int ret = CMD_WARNING;
	const int minrange = 1000;

	/* validate given bounds */
	if (lb > ub)
		vty_out(vty, "%% Lower bound must be less than upper bound\n");
	else if (ub - lb < minrange)
		vty_out(vty, "%% Range breadth must be at least %d\n", minrange);
	else {
		ret = CMD_SUCCESS;
		pbr_nht_set_tableid_range((uint32_t)lb, (uint32_t)ub);
	}

	return ret;
}

/* clang-format off */
DEFPY  (no_pbr_set_table_range,
	no_pbr_set_table_range_cmd,
	"no pbr table range [(10000-4294966272)$lb (10000-4294966272)$ub]",
	NO_STR
	PBR_STR
	"Set table ID range\n"
	"Set table ID range\n"
	"Lower bound for table ID range\n"
	"Upper bound for table ID range\n")
{
	/* clang-format on */
	pbr_nht_set_tableid_range(PBR_NHT_DEFAULT_LOW_TABLEID,
				  PBR_NHT_DEFAULT_HIGH_TABLEID);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFUN_NOSH(pbr_map,
	   pbr_map_cmd,
	   "pbr-map PBRMAP seq (1-700)",
	   "Create pbr-map or enter pbr-map command mode\n"
	   "The name of the PBR MAP\n"
	   "Sequence to insert in existing pbr-map entry\n"
	   "Sequence number\n")
{
	/* clang-format on */
	const char *pbrm_name = argv[1]->arg;
	uint32_t seqno = atoi(argv[3]->arg);
	struct pbr_map_sequence *pbrms;

	pbrms = pbrms_get(pbrm_name, seqno);
	VTY_PUSH_CONTEXT(PBRMAP_NODE, pbrms);

	return CMD_SUCCESS;
}

/* clang-format off */
DEFUN_NOSH(no_pbr_map,
	   no_pbr_map_cmd,
	   "no pbr-map PBRMAP [seq (1-700)]",
	   NO_STR
	   "Delete pbr-map\n"
	   "The name of the PBR MAP\n"
	   "Sequence to delete from existing pbr-map entry\n"
	   "Sequence number\n")
{
	/* clang-format on */
	const char *pbrm_name = argv[2]->arg;
	uint32_t seqno = 0;
	struct pbr_map *pbrm = pbrm_find(pbrm_name);
	struct pbr_map_sequence *pbrms;
	struct listnode *node, *next_node;

	if (argc > 3)
		seqno = atoi(argv[4]->arg);

	if (!pbrm) {
		vty_out(vty, "pbr-map %s not found\n", pbrm_name);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS(pbrm->seqnumbers, node, next_node, pbrms)) {
		if (seqno && pbrms->seqno != seqno)
			continue;

		pbr_map_delete(pbrms);
		pbr_map_sequence_delete(pbrms);
	}

	return CMD_SUCCESS;
}

/***********************************************************************
 *		pbrms/rule Match L3 Fields
 ***********************************************************************/

/*
 * Address Family Matters
 *
 * Linux Kernel constraints
 * ------------------------
 * The underlying linux kernel dataplane requires that rules be
 * installed into an IPv4-specific or an IPv6-specific database.
 *
 * Not only do we need to designate an address-family for rule
 * installation, but we ALSO must have the same address-family
 * available to be able to delete the rule from the correct kernel
 * database.
 *
 * Determining the address-family
 * ------------------------------
 * In the current code, we do our best to infer the correct family
 * from any configured IP-address match or set clauses in a rule.
 * Absent any of those fields, the NHT code also tries to glean the
 * address family from resolved nexthops or nexthop-groups. All of
 * those opportunistic address-family determinations are stored in
 * the "family" field of struct pbr_map_sequence.
 *
 * This "family" field value is needed particularly when deleting
 * a rule piece-by-piece because at the end, the match/set fields
 * will be empty. Maybe it would be possible to handle this issue
 * as an internal zebra matter in the future.
 *
 * We also attempt to maintain address-family consistency among the
 * various configured fields in a rule. So far, these fields are
 * src/dst IP-address match/set values.
 *
 * It is probably possible to perform the same address-family check in
 * the CLI for single nexthops (set nexthop A.B.C.D|X:X::X:X) but the
 * address-family is not immediately available for nexthop-groups.
 * In both the single-nexthop and nexthop-group, the NHT resolution code
 * sets the "family" field of struct pbr_map_sequence asynchronously.
 *
 * There isn't currently any flagging of rules that have a consistent
 * set of src/dst IP-address match/set values but an asynchronously-resolved
 * nexthop-group that has a different address-family.
 *
 * The match/set IP-address handlers below blindly set "family"; it's
 * probably possible to wrongly set "family" to, e.g., IPv4 this way after
 * a v6 NHG has been resolved and break rule removal. It's not clear
 * how to best address this potential issue.
 */
static bool pbr_family_consistent(struct pbr_map_sequence *pbrms,
				  uint8_t family, uint32_t skip_filter_bm,
				  uint32_t skip_action_bm, const char **msg)
{
	uint32_t filter_bm = pbrms->filter_bm & ~skip_filter_bm;
	uint32_t action_bm = pbrms->action_bm & ~skip_action_bm;

	if (CHECK_FLAG(filter_bm, PBR_FILTER_SRC_IP) &&
	    (family != pbrms->src->family)) {
		if (msg)
			*msg = "match src-ip";
		return false;
	}
	if (CHECK_FLAG(filter_bm, PBR_FILTER_DST_IP) &&
	    (family != pbrms->dst->family)) {
		if (msg)
			*msg = "match dst-ip";
		return false;
	}
	if (CHECK_FLAG(action_bm, PBR_ACTION_SRC_IP) &&
	    (family != sockunion_family(&pbrms->action_src))) {
		if (msg)
			*msg = "set src-ip";
		return false;
	}
	if (CHECK_FLAG(filter_bm, PBR_ACTION_DST_IP) &&
	    (family != sockunion_family(&pbrms->action_dst))) {
		if (msg)
			*msg = "set dst-ip";
		return false;
	}
	return true;
}


/* clang-format off */
DEFPY  (pbr_map_match_src,
	pbr_map_match_src_cmd,
	"[no] match src-ip ![<A.B.C.D/M|X:X::X:X/M>$prefix]",
	NO_STR
	"Match the rest of the command\n"
	"Choose the src ipv4 or ipv6 prefix to use\n"
	"v4 Prefix\n"
	"v6 Prefix\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	const char *fmsg = NULL;

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_IP))
			return CMD_SUCCESS;
		prefix_free(&pbrms->src);
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_IP);
		goto check;
	}

	assert(prefix);
	if (!pbr_family_consistent(pbrms, prefix->family, PBR_FILTER_SRC_IP, 0,
				   &fmsg)) {
		vty_out(vty, "Address family mismatch (%s)\n", fmsg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	pbrms->family = prefix->family;

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_IP)) {
		if (prefix_same(pbrms->src, prefix))
			return CMD_SUCCESS;
	} else
		pbrms->src = prefix_new();

	prefix_copy(pbrms->src, prefix);
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_IP);

check:
	pbr_map_check(pbrms, true);

	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_match_dst,
	pbr_map_match_dst_cmd,
	"[no] match dst-ip ![<A.B.C.D/M|X:X::X:X/M>$prefix]",
	NO_STR
	"Match the rest of the command\n"
	"Choose the dst ipv4 or ipv6 prefix to use\n"
	"v4 Prefix\n"
	"v6 Prefix\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	const char *fmsg = NULL;

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_IP))
			return CMD_SUCCESS;
		prefix_free(&pbrms->dst);
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_DST_IP);
		goto check;
	}

	assert(prefix);
	if (!pbr_family_consistent(pbrms, prefix->family, PBR_FILTER_DST_IP, 0,
				   &fmsg)) {
		vty_out(vty, "Address family mismatch (%s)\n", fmsg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	pbrms->family = prefix->family;

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_IP)) {
		if (prefix_same(pbrms->dst, prefix))
			return CMD_SUCCESS;
	} else
		pbrms->dst = prefix_new();

	prefix_copy(pbrms->dst, prefix);
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_DST_IP);

check:
	pbr_map_check(pbrms, true);

	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_match_ip_proto,
	pbr_map_match_ip_proto_cmd,
	"[no] match ip-protocol ![PROTO$ip_proto]",
	NO_STR
	"Match the rest of the command\n"
	"Choose an ip-protocol\n"
	"Protocol name\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	struct protoent *p = NULL;

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_IP_PROTOCOL))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_IP_PROTOCOL);
		goto check;
	}

	if (ip_proto)
		p = getprotobyname(ip_proto);

	if (!ip_proto || !p) {
		vty_out(vty, "Unable to convert %s to proto id\n",
			(ip_proto ? ip_proto : "(null)"));
		return CMD_WARNING_CONFIG_FAILED;
	}

	pbrms->ip_proto = p->p_proto;
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_IP_PROTOCOL);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_match_src_port,
	pbr_map_match_src_port_cmd,
	"[no] match src-port ![(1-65535)$port]",
	NO_STR
	"Match the rest of the command\n"
	"Choose the source port to use\n"
	"The Source Port\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_PORT))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_PORT);
		goto check;
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_PORT) &&
	    (pbrms->src_prt == port)) {
		return CMD_SUCCESS;
	}
	pbrms->src_prt = port;
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_PORT);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_match_dst_port,
	pbr_map_match_dst_port_cmd,
	"[no] match dst-port ![(1-65535)$port]",
	NO_STR
	"Match the rest of the command\n"
	"Choose the destination port to use\n"
	"The Destination Port\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_PORT))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_DST_PORT);
		goto check;
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_PORT) &&
	    (pbrms->dst_prt == port)) {
		return CMD_SUCCESS;
	}
	pbrms->dst_prt = port;
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_DST_PORT);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_match_dscp,
	pbr_map_match_dscp_cmd,
	"[no] match dscp ![DSCP$dscp]",
	NO_STR
	"Match the rest of the command\n"
	"Match based on IP DSCP field\n"
	"DSCP value (below 64) or standard codepoint name\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DSCP))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_DSCP);
		pbrms->dsfield &= ~PBR_DSFIELD_DSCP;
		goto check;
	}

	unsigned long ul_dscp;
	char *pend = NULL;
	uint8_t shifted_dscp;

	assert(dscp);
	ul_dscp = strtoul(dscp, &pend, 0);
	if (pend && *pend)
		ul_dscp = pbr_map_decode_dscp_enum(dscp);

	if (ul_dscp > (PBR_DSFIELD_DSCP >> 2)) {
		vty_out(vty, "Invalid dscp value: %s%s\n", dscp,
			((pend && *pend) ? "" : " (numeric value must be in range 0-63)"));
		return CMD_WARNING_CONFIG_FAILED;
	}

	shifted_dscp = (ul_dscp << 2) & PBR_DSFIELD_DSCP;

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DSCP) &&
	    ((pbrms->dsfield & PBR_DSFIELD_DSCP) == shifted_dscp)) {
		return CMD_SUCCESS;
	}

	/* Set the DSCP bits of the DSField */
	pbrms->dsfield = (pbrms->dsfield & ~PBR_DSFIELD_DSCP) | shifted_dscp;
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_DSCP);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_match_ecn,
	pbr_map_match_ecn_cmd,
	"[no] match ecn ![(0-3)$ecn]",
	NO_STR
	"Match the rest of the command\n"
	"Match based on IP ECN field\n"
	"Explicit Congestion Notification\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_ECN))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_ECN);
		pbrms->dsfield &= ~PBR_DSFIELD_ECN;
		goto check;
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_ECN) &&
	    ((pbrms->dsfield & PBR_DSFIELD_ECN) == ecn)) {
		return CMD_SUCCESS;
	}

	/* Set the ECN bits of the DSField */
	pbrms->dsfield = (pbrms->dsfield & ~PBR_DSFIELD_ECN) | ecn;
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_ECN);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/***********************************************************************
 *		pbrms/rule Match L2 fields
 ***********************************************************************/

/* clang-format off */
DEFPY  (pbr_map_match_pcp,
	pbr_map_match_pcp_cmd,
	"[no] match pcp ![(0-7)$pcp]",
	NO_STR
	"Match spec follows\n"
	"Match based on 802.1p Priority Code Point (PCP) value\n"
	"PCP value to match\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_PCP))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_PCP);
		goto check;
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_PCP) &&
	    (pbrms->match_pcp == pcp)) {
		return CMD_SUCCESS;
	}

	pbrms->match_pcp = pcp;
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_PCP);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_match_vlan_id,
	pbr_map_match_vlan_id_cmd,
	"[no] match vlan ![(1-4094)$vlan_id]",
	NO_STR
	"Match spec follows\n"
	"Match based on VLAN ID\n"
	"VLAN ID to match\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_ID))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_ID);
		goto check;
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_ID) &&
	    (pbrms->match_vlan_id == vlan_id)) {
		return CMD_SUCCESS;
	}

	/*
	 * Maintaining previous behavior: setting a vlan_id match
	 * automatically clears any vlan_flags matching.
	 */
	UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_FLAGS);
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_ID);
	pbrms->match_vlan_id = vlan_id;

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_match_vlan_tag,
	pbr_map_match_vlan_tag_cmd,
	"[no] match vlan ![<tagged|untagged|untagged-or-zero>$tag_type]",
	NO_STR
	"Match the rest of the command\n"
	"Match based on VLAN tagging\n"
	"Match all tagged frames\n"
	"Match all untagged frames\n"
	"Match untagged frames, or tagged frames with id zero\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	uint16_t vlan_flags;

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_FLAGS))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_FLAGS);
		goto check;
	}

	assert(tag_type);
	if (strmatch(tag_type, "tagged"))
		vlan_flags = PBR_VLAN_FLAGS_TAGGED;
	else if (strmatch(tag_type, "untagged"))
		vlan_flags = PBR_VLAN_FLAGS_UNTAGGED;
	else if (strmatch(tag_type, "untagged-or-zero"))
		vlan_flags = PBR_VLAN_FLAGS_UNTAGGED_0;
	else {
		vty_out(vty, "unknown vlan flag\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_FLAGS) &&
	    (pbrms->match_vlan_flags == vlan_flags)) {
		return CMD_SUCCESS;
	}

	/*
	 * Maintaining previous behavior: setting a vlan_flags match
	 * automatically clears any vlan_id matching.
	 */
	UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_ID);
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_FLAGS);
	pbrms->match_vlan_flags = vlan_flags;

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/***********************************************************************
 *		pbrms/rule Match meta
 ***********************************************************************/

/* clang-format off */
DEFPY  (pbr_map_match_mark,
	pbr_map_match_mark_cmd,
	"[no] match mark ![(1-4294967295)$mark]",
	NO_STR
	"Match the rest of the command\n"
	"Choose the mark value to use\n"
	"mark\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

#ifndef GNU_LINUX
	vty_out(vty, "pbr marks are not supported on this platform\n");
	return CMD_WARNING_CONFIG_FAILED;
#endif

	if (no) {
		if (!CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_FWMARK))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->filter_bm, PBR_FILTER_FWMARK);
		goto check;
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_FWMARK) &&
	    (pbrms->mark == (uint32_t)mark)) {
		return CMD_SUCCESS;
	}

	pbrms->mark = (uint32_t)mark;
	SET_FLAG(pbrms->filter_bm, PBR_FILTER_FWMARK);

check:
	pbr_map_check(pbrms, true);

	return CMD_SUCCESS;
}

/***********************************************************************
 *		pbrms/rule Action Set L3 Fields
 ***********************************************************************/

/* clang-format off */
DEFPY  (pbr_map_action_src,
	pbr_map_action_src_cmd,
	"[no] set src-ip ![<A.B.C.D|X:X::X:X>$su]",
	NO_STR
	"Set command\n"
	"Set the src ipv4 or ipv6 prefix\n"
	"v4 Prefix\n"
	"v6 Prefix\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	const char *fmsg = NULL;

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_IP))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_SRC_IP);
		goto check;
	}

	assert(su);
	if (!pbr_family_consistent(pbrms, sockunion_family(su),
				   PBR_ACTION_SRC_IP, 0, &fmsg)) {
		vty_out(vty, "Address family mismatch (%s)\n", fmsg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	pbrms->family = sockunion_family(su);

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_IP) &&
	    (sockunion_same(&pbrms->action_src, su))) {
		return CMD_SUCCESS;
	}
	pbrms->action_src = *su;
	SET_FLAG(pbrms->action_bm, PBR_ACTION_SRC_IP);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_action_dst,
	pbr_map_action_dst_cmd,
	"[no] set dst-ip ![<A.B.C.D|X:X::X:X>$su]",
	NO_STR
	"Set command\n"
	"Set the dst ipv4 or ipv6 prefix\n"
	"v4 Prefix\n"
	"v6 Prefix\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	const char *fmsg = NULL;

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_IP))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_DST_IP);
		goto check;
	}

	assert(su);
	if (!pbr_family_consistent(pbrms, sockunion_family(su),
				   PBR_ACTION_DST_IP, 0, &fmsg)) {
		vty_out(vty, "Address family mismatch (%s)\n", fmsg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	pbrms->family = sockunion_family(su);

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_IP) &&
	    (sockunion_same(&pbrms->action_dst, su))) {
		return CMD_SUCCESS;
	}
	pbrms->action_dst = *su;
	SET_FLAG(pbrms->action_bm, PBR_ACTION_DST_IP);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_action_src_port,
	pbr_map_action_src_port_cmd,
	"[no] set src-port ![(1-65535)$port]",
	NO_STR
	"Set command\n"
	"Set Source Port\n"
	"The Source Port\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_PORT))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_SRC_PORT);
		goto check;
	}

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_PORT) &&
	    (pbrms->action_src_port == port))
		return CMD_SUCCESS;

	pbrms->action_src_port = port;
	SET_FLAG(pbrms->action_bm, PBR_ACTION_SRC_PORT);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_action_dst_port,
	pbr_map_action_dst_port_cmd,
	"[no] set dst-port ![(1-65535)$port]",
	NO_STR
	"Set command\n"
	"Set Destination Port\n"
	"The Destination Port\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_PORT))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_DST_PORT);
		goto check;
	}
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_PORT) &&
	    (pbrms->action_dst_port == port))
		return CMD_SUCCESS;

	SET_FLAG(pbrms->action_bm, PBR_ACTION_DST_PORT);
	pbrms->action_dst_port = port;

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_action_dscp,
	pbr_map_action_dscp_cmd,
	"[no] set dscp ![DSCP$dscp]",
	NO_STR
	"Set command\n"
	"Set IP DSCP field\n"
	"DSCP numeric value (0-63) or standard codepoint name\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DSCP))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_DSCP);
		goto check;
	}

	unsigned long ul_dscp;
	char *pend = NULL;
	uint8_t shifted_dscp;

	assert(dscp);
	ul_dscp = strtoul(dscp, &pend, 0);
	if (pend && *pend)
		ul_dscp = pbr_map_decode_dscp_enum(dscp);

	if (ul_dscp > (PBR_DSFIELD_DSCP >> 2)) {
		vty_out(vty, "Invalid dscp value: %s%s\n", dscp,
			((pend && *pend) ? "" : " (numeric value must be in range 0-63)"));
		return CMD_WARNING_CONFIG_FAILED;
	}

	shifted_dscp = (ul_dscp << 2) & PBR_DSFIELD_DSCP;

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DSCP) &&
	    (pbrms->action_dscp == shifted_dscp)) {
		return CMD_SUCCESS;
	}
	SET_FLAG(pbrms->action_bm, PBR_ACTION_DSCP);
	pbrms->action_dscp = shifted_dscp;

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_action_ecn,
	pbr_map_action_ecn_cmd,
	"[no] set ecn ![(0-3)$ecn]",
	NO_STR
	"Set command\n"
	"Set IP ECN field\n"
	"Explicit Congestion Notification value\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_ECN))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_ECN);
		goto check;
	}
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_ECN) &&
	    (pbrms->action_ecn == ecn)) {
		return CMD_SUCCESS;
	}
	SET_FLAG(pbrms->action_bm, PBR_ACTION_ECN);
	pbrms->action_ecn = ecn;

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}


/***********************************************************************
 *		pbrms/rule Action Set Meta
 ***********************************************************************/

/* clang-format off */
DEFPY  (pbr_map_action_queue_id,
	pbr_map_action_queue_id_cmd,
	"[no] set queue-id ![(1-65535)$queue_id]",
	NO_STR
	"Set the rest of the command\n"
	"Set based on egress port queue id\n"
	"A valid value in range 1..65535 \n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_QUEUE_ID))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_QUEUE_ID);
		goto check;
	}

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_QUEUE_ID) &&
	    (pbrms->action_queue_id == (uint32_t)queue_id)) {
		return CMD_SUCCESS;
	}
	pbrms->action_queue_id = (uint32_t)queue_id;
	SET_FLAG(pbrms->action_bm, PBR_ACTION_QUEUE_ID);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}


/***********************************************************************
 *		pbrms/rule Action Set L2 Fields
 ***********************************************************************/

/* clang-format off */
DEFPY  (pbr_map_action_pcp,
	pbr_map_action_pcp_cmd,
	"[no] set pcp ![(0-7)$pcp]",
	NO_STR
	"Set the rest of the command\n"
	"Set based on 802.1p Priority Code Point (PCP) value\n"
	"A valid value in range 0..7\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_PCP))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_PCP);
		goto check;
	}

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_PCP) &&
	    pbrms->action_pcp == pcp) {
		return CMD_SUCCESS;
	}

	pbrms->action_pcp = pcp;
	SET_FLAG(pbrms->action_bm, PBR_ACTION_PCP);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_action_vlan_id,
	pbr_map_action_vlan_id_cmd,
	"[no] set vlan ![(1-4094)$vlan_id]",
	NO_STR
	"Set the rest of the command\n"
	"Set action for VLAN tagging\n"
	"A valid value in range 1..4094\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_ID))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_ID);
		goto check;
	}

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_ID) &&
	    (pbrms->action_vlan_id == vlan_id)) {
		return CMD_SUCCESS;
	}

	/*
	 * Setting a vlan_id action automatically clears any strip-inner action
	 */
	pbrms->action_vlan_id = vlan_id;
	UNSET_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_STRIP_INNER_ANY);
	SET_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_ID);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_action_strip_vlan,
	pbr_map_action_strip_vlan_cmd,
	"[no] strip vlan",
	NO_STR
	"Strip the vlan tags from frame\n"
	"Strip any inner vlan tag\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		if (!CHECK_FLAG(pbrms->action_bm,
				PBR_ACTION_VLAN_STRIP_INNER_ANY))
			return CMD_SUCCESS;
		UNSET_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_STRIP_INNER_ANY);
		goto check;
	}
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_STRIP_INNER_ANY))
		return CMD_SUCCESS;

	/*
	 * Setting a strip-inner action automatically clears any vlan_id action
	 */
	UNSET_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_ID);
	SET_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_STRIP_INNER_ANY);

check:
	pbr_map_check(pbrms, true);
	return CMD_SUCCESS;
}


/***********************************************************************
 *		pbrms/rule Action Forwarding
 ***********************************************************************/

static void pbrms_clear_set_vrf_config(struct pbr_map_sequence *pbrms)
{
	if (pbrms->vrf_lookup || pbrms->vrf_unchanged) {
		pbr_map_delete_vrf(pbrms);
		pbrms->vrf_name[0] = '\0';
		pbrms->vrf_lookup = false;
		pbrms->vrf_unchanged = false;
	}
}

static void pbrms_clear_set_nhg_config(struct pbr_map_sequence *pbrms)
{
	if (pbrms->nhgrp_name)
		pbr_map_delete_nexthops(pbrms);
}

static void pbrms_clear_set_nexthop_config(struct pbr_map_sequence *pbrms)
{
	if (pbrms->nhg)
		pbr_nht_delete_individual_nexthop(pbrms);
}

static void pbrms_clear_set_config(struct pbr_map_sequence *pbrms)
{
	pbrms_clear_set_vrf_config(pbrms);
	pbrms_clear_set_nhg_config(pbrms);
	pbrms_clear_set_nexthop_config(pbrms);

	pbrms->nhs_installed = false;

	pbrms->forwarding_type = PBR_FT_UNSPEC;

	/* clear advisory flag indicating nexthop == blackhole */
	UNSET_FLAG(pbrms->action_bm, PBR_ACTION_DROP);
}



DEFPY(pbr_map_nexthop_group, pbr_map_nexthop_group_cmd,
      "set nexthop-group NHGNAME$name",
      "Set for the PBR-MAP\n"
      "nexthop-group to use\n"
      "The name of the nexthop-group\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	struct nexthop_group_cmd *nhgc;

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	nhgc = nhgc_find(name);
	if (!nhgc) {
		vty_out(vty, "Specified nexthop-group %s does not exist\n",
			name);
		vty_out(vty,
			"PBR-MAP will not be applied until it is created\n");
	}

	if (pbrms->nhgrp_name && strcmp(name, pbrms->nhgrp_name) == 0)
		return CMD_SUCCESS;

	/* This is new/replacement config */
	pbrms_clear_set_config(pbrms);

	pbr_nht_set_seq_nhg(pbrms, name);

	pbr_map_check(pbrms, true);

	return CMD_SUCCESS;
}

DEFPY(no_pbr_map_nexthop_group, no_pbr_map_nexthop_group_cmd,
      "no set nexthop-group [NHGNAME$name]",
      NO_STR
      "Set for the PBR-MAP\n"
      "nexthop-group to use\n"
      "The name of the nexthop-group\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	pbrms_clear_set_config(pbrms);

	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (pbr_map_nexthop,
	pbr_map_nexthop_cmd,
	"set nexthop\
        <\
	  <A.B.C.D|X:X::X:X>$addr [INTERFACE$intf]\
	  |INTERFACE$intf\
	  |blackhole$bh\
	>\
        [nexthop-vrf NAME$vrf_name]",
	"Set for the PBR-MAP\n"
	"Specify one of the nexthops in this map\n"
	"v4 Address\n"
	"v6 Address\n"
	"Interface to use\n"
	"Interface to use\n"
	"Blackhole route\n"
	"If the nexthop is in a different vrf tell us\n"
	"The nexthop-vrf Name\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);
	struct vrf *vrf;
	struct nexthop nhop;
	struct nexthop *nh = NULL;

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	if (vrf_name)
		vrf = vrf_lookup_by_name(vrf_name);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (!vrf) {
		vty_out(vty, "Specified VRF: %s is non-existent\n", vrf_name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	memset(&nhop, 0, sizeof(nhop));
	nhop.vrf_id = vrf->vrf_id;

	if (intf) {
		struct interface *ifp = NULL;
		struct interface *ifptmp;
		struct vrf *vrftmp;
		int count = 0;

		if (vrf_is_backend_netns() && vrf_name) {
			ifp = if_lookup_by_name_vrf(intf, vrf);
		} else {
			RB_FOREACH (vrftmp, vrf_name_head, &vrfs_by_name) {
				ifptmp = if_lookup_by_name_vrf(intf, vrftmp);
				if (ifptmp) {
					ifp = ifptmp;
					count++;
					if (!vrf_is_backend_netns())
						break;
				}
			}
		}

		if (!ifp) {
			vty_out(vty, "Specified Intf %s does not exist\n",
				intf);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (count > 1) {
			vty_out(vty,
				"Specified Intf %s exists in multiple VRFs\n",
				intf);
			vty_out(vty, "You must specify the nexthop-vrf\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (ifp->vrf->vrf_id != vrf->vrf_id)
			vty_out(vty,
				"Specified Intf %s is not in vrf %s but is in vrf %s, using actual vrf\n",
				ifp->name, vrf->name, ifp->vrf->name);
		nhop.ifindex = ifp->ifindex;
		nhop.vrf_id = ifp->vrf->vrf_id;
	}

	if (addr) {
		if (addr->sa.sa_family == AF_INET) {
			nhop.gate.ipv4.s_addr = addr->sin.sin_addr.s_addr;
			if (intf)
				nhop.type = NEXTHOP_TYPE_IPV4_IFINDEX;
			else
				nhop.type = NEXTHOP_TYPE_IPV4;
		} else {
			nhop.gate.ipv6 = addr->sin6.sin6_addr;
			if (intf)
				nhop.type = NEXTHOP_TYPE_IPV6_IFINDEX;
			else {
				if (IN6_IS_ADDR_LINKLOCAL(&nhop.gate.ipv6)) {
					vty_out(vty,
						"Specified a v6 LL with no interface, rejecting\n");
					return CMD_WARNING_CONFIG_FAILED;
				}
				nhop.type = NEXTHOP_TYPE_IPV6;
			}
		}
	} else if (bh) {
		nhop.type = NEXTHOP_TYPE_BLACKHOLE;
		/* advisory flag for non-linux dataplanes */
		SET_FLAG(pbrms->action_bm, PBR_ACTION_DROP);
	} else {
		nhop.type = NEXTHOP_TYPE_IFINDEX;
	}

	if (pbrms->nhg)
		nh = nexthop_exists(pbrms->nhg, &nhop);

	if (nh) /* Same config re-entered */
		goto done;

	/* This is new/replacement config */
	pbrms_clear_set_config(pbrms);

	pbr_nht_add_individual_nexthop(pbrms, &nhop);

	pbr_map_check(pbrms, true);

done:
	if (nhop.type == NEXTHOP_TYPE_IFINDEX
	    || (nhop.type == NEXTHOP_TYPE_IPV6_IFINDEX
		&& IN6_IS_ADDR_LINKLOCAL(&nhop.gate.ipv6))) {
		struct interface *ifp;

		ifp = if_lookup_by_index(nhop.ifindex, nhop.vrf_id);
		if (ifp)
			pbr_nht_nexthop_interface_update(ifp);
	}

	return CMD_SUCCESS;
}

/* clang-format off */
DEFPY  (no_pbr_map_nexthop,
	no_pbr_map_nexthop_cmd,
	"no set nexthop\
        [<\
	  <A.B.C.D|X:X::X:X>$addr [INTERFACE$intf]\
	  |INTERFACE$intf\
	  |blackhole$bh\
	>\
        [nexthop-vrf NAME$vrf_name]]",
	NO_STR
	"Set for the PBR-MAP\n"
	"Specify one of the nexthops in this map\n"
	"v4 Address\n"
	"v6 Address\n"
	"Interface to use\n"
	"Interface to use\n"
	"Blackhole route\n"
	"If the nexthop is in a different vrf tell us\n"
	"The nexthop-vrf Name\n")
{
	/* clang-format on */
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	pbrms_clear_set_config(pbrms);

	return CMD_SUCCESS;
}

DEFPY(pbr_map_vrf, pbr_map_vrf_cmd,
      "set vrf <NAME$vrf_name|unchanged>",
      "Set for the PBR-MAP\n"
      "Specify the VRF for this map\n"
      "The VRF Name\n"
      "Use the interface's VRF for lookup\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * If an equivalent set vrf * exists, just return success.
	 */
	if ((pbrms->forwarding_type == PBR_FT_SETVRF) &&
	    vrf_name &&
	    strncmp(pbrms->vrf_name, vrf_name, sizeof(pbrms->vrf_name)) == 0)
		return CMD_SUCCESS;
	else if (!vrf_name && (pbrms->forwarding_type == PBR_FT_VRF_UNCHANGED))
		/* Unchanged already set */
		return CMD_SUCCESS;

	if (vrf_name && !pbr_vrf_lookup_by_name(vrf_name)) {
		vty_out(vty, "Specified: %s is non-existent\n", vrf_name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* This is new/replacement config */
	pbrms_clear_set_config(pbrms);

	if (vrf_name) {
		pbrms->vrf_lookup = true;
		pbrms->forwarding_type = PBR_FT_SETVRF;
		strlcpy(pbrms->vrf_name, vrf_name, sizeof(pbrms->vrf_name));
	} else {
		pbrms->forwarding_type = PBR_FT_VRF_UNCHANGED;
		pbrms->vrf_unchanged = true;
	}

	pbr_map_check(pbrms, true);

	return CMD_SUCCESS;
}

DEFPY(no_pbr_map_vrf, no_pbr_map_vrf_cmd,
      "no set vrf [<NAME$vrf_name|unchanged>]",
      NO_STR
      "Set for the PBR-MAP\n"
      "Specify the VRF for this map\n"
      "The VRF Name\n"
      "Use the interface's VRF for lookup\n")
{
	struct pbr_map_sequence *pbrms = VTY_GET_CONTEXT(pbr_map_sequence);

	if (!pbrms)
		return CMD_WARNING_CONFIG_FAILED;

	pbrms_clear_set_config(pbrms);

	return CMD_SUCCESS;
}

/***********************************************************************
 *			Policy
 ***********************************************************************/

/* clang-format off */
DEFPY  (pbr_policy,
	pbr_policy_cmd,
	"[no] pbr-policy PBRMAP$mapname",
	NO_STR
	"Policy to use\n"
	"Name of the pbr-map to apply\n")
{
	/* clang-format on */
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct pbr_map *pbrm, *old_pbrm;
	struct pbr_interface *pbr_ifp = ifp->info;

	old_pbrm = NULL;
	pbrm = pbrm_find(mapname);

	if (!pbr_ifp) {
		/* we don't want one and we don't have one, so... */
		if (no)
			return CMD_SUCCESS;

		/* Some one could have fat fingered the interface name */
		pbr_ifp = pbr_if_new(ifp);
	}

	if (no) {
		if (strcmp(pbr_ifp->mapname, mapname) == 0) {
			pbr_ifp->mapname[0] = '\0';
			if (pbrm)
				pbr_map_interface_delete(pbrm, ifp);
		}
	} else {
		if (strcmp(pbr_ifp->mapname, "") != 0) {
			old_pbrm = pbrm_find(pbr_ifp->mapname);

			/*
			 * So if we have an old pbrm we should only
			 * delete it if we are actually deleting and
			 * moving to a new pbrm
			 */
			if (old_pbrm && old_pbrm != pbrm)
				pbr_map_interface_delete(old_pbrm, ifp);
		}
		snprintf(pbr_ifp->mapname, sizeof(pbr_ifp->mapname),
			 "%s", mapname);

		/*
		 * So only reinstall if the old_pbrm and this pbrm are
		 * different.
		 */
		if (pbrm && pbrm != old_pbrm)
			pbr_map_add_interface(pbrm, ifp);
	}

	return CMD_SUCCESS;
}

DEFPY (show_pbr,
	show_pbr_cmd,
	"show pbr",
	SHOW_STR
	PBR_STR)
{
	pbr_nht_write_table_range(vty);
	pbr_nht_write_rule_range(vty);

	return CMD_SUCCESS;
}

static void
pbrms_nexthop_group_write_individual_nexthop(
	struct vty *vty, const struct pbr_map_sequence *pbrms)
{
	struct pbr_nexthop_group_cache find;
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_cache lookup;
	struct pbr_nexthop_cache *pnhc;

	memset(&find, 0, sizeof(find));
	strlcpy(find.name, pbrms->internal_nhg_name, sizeof(find.name));

	pnhgc = hash_lookup(pbr_nhg_hash, &find);
	assert(pnhgc);

	lookup.nexthop = *pbrms->nhg->nexthop;
	pnhc = hash_lookup(pnhgc->nhh, &lookup);

	nexthop_group_write_nexthop_simple(
		vty, pbrms->nhg->nexthop,
		pnhc->nexthop.ifindex != 0 ? pnhc->intf_name : NULL);
	if (pnhc->nexthop.vrf_id != VRF_DEFAULT)
		vty_out(vty, " nexthop-vrf %s", pnhc->vrf_name);

	vty_out(vty, "\n");
}

static void vty_show_pbrms(struct vty *vty,
			   const struct pbr_map_sequence *pbrms, bool detail)
{
	char rbuf[64];

	if (pbrms->reason)
		pbr_map_reason_string(pbrms->reason, rbuf, sizeof(rbuf));

	vty_out(vty, "    Seq: %u rule: %u\n", pbrms->seqno, pbrms->ruleno);

	if (detail)
		vty_out(vty, "        Installed: %" PRIu64 "(%u) Reason: %s\n",
			pbrms->installed, pbrms->unique,
			pbrms->reason ? rbuf : "Valid");
	else
		vty_out(vty, "        Installed: %s Reason: %s\n",
			pbrms->installed ? "yes" : "no",
			pbrms->reason ? rbuf : "Valid");

	/* match clauses first */

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_IP_PROTOCOL)) {
		struct protoent *p;

		p = getprotobynumber(pbrms->ip_proto);
		vty_out(vty, "        IP Protocol Match: %s\n", p->p_name);
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_IP))
		vty_out(vty, "        SRC IP Match: %pFX\n", pbrms->src);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_IP))
		vty_out(vty, "        DST IP Match: %pFX\n", pbrms->dst);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_PORT))
		vty_out(vty, "        SRC Port Match: %u\n", pbrms->src_prt);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_PORT))
		vty_out(vty, "        DST Port Match: %u\n", pbrms->dst_prt);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DSCP))
		vty_out(vty, "        DSCP Match: %u\n",
			(pbrms->dsfield & PBR_DSFIELD_DSCP) >> 2);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_ECN))
		vty_out(vty, "        ECN Match: %u\n",
			pbrms->dsfield & PBR_DSFIELD_ECN);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_FWMARK))
		vty_out(vty, "        MARK Match: %u\n", pbrms->mark);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_PCP))
		vty_out(vty, "        PCP Match: %d\n", pbrms->match_pcp);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_ID))
		vty_out(vty, "        Match VLAN ID: %u\n",
			pbrms->match_vlan_id);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_FLAGS)) {
		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_TAGGED)
			vty_out(vty, "        Match VLAN tagged frames\n");
		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_UNTAGGED)
			vty_out(vty, "        Match VLAN untagged frames\n");
		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_UNTAGGED_0)
			vty_out(vty, "        Match VLAN untagged or ID 0\n");
	}

	/* set actions */

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_IP))
		vty_out(vty, "        Set SRC IP: %pSU\n", &pbrms->action_src);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_IP))
		vty_out(vty, "        Set DST IP: %pSU\n", &pbrms->action_dst);

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_PORT))
		vty_out(vty, "        Set Src port: %u\n",
			pbrms->action_src_port);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_PORT))
		vty_out(vty, "        Set Dst port: %u\n",
			pbrms->action_dst_port);

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DSCP))
		vty_out(vty, "        Set DSCP: %u\n", (pbrms->action_dscp) >> 2);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_ECN))
		vty_out(vty, "        Set ECN: %u\n", pbrms->action_ecn);

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_ID))
		vty_out(vty, "        Set VLAN ID %u\n", pbrms->action_vlan_id);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_STRIP_INNER_ANY))
		vty_out(vty, "        Strip VLAN ID\n");
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_PCP))
		vty_out(vty, "        Set PCP %u\n", pbrms->action_pcp);

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_QUEUE_ID))
		vty_out(vty, "        Set Queue ID: %u\n",
			pbrms->action_queue_id);


	switch (pbrms->forwarding_type) {
	case PBR_FT_UNSPEC:
		vty_out(vty, "        Nexthop-Group: Unknown Installed: no\n");
		break;
	case PBR_FT_VRF_UNCHANGED:
		vty_out(vty, "        VRF Unchanged (use interface vrf)\n");
		break;
	case PBR_FT_SETVRF:
		assert(pbrms->vrf_name);
		vty_out(vty, "        VRF Lookup: %s\n", pbrms->vrf_name);
		break;
	case PBR_FT_NEXTHOP_GROUP:
		assert(pbrms->nhgrp_name);
		vty_out(vty, "        Nexthop-Group: %s\n", pbrms->nhgrp_name);

		if (detail)
			vty_out(vty,
				"          Installed: %u(%d) Tableid: %u\n",
				pbrms->nhs_installed,
				pbr_nht_get_installed(pbrms->nhgrp_name),
				pbr_nht_get_table(pbrms->nhgrp_name));
		else
			vty_out(vty, "          Installed: %s Tableid: %u\n",
				pbr_nht_get_installed(pbrms->nhgrp_name) ? "yes"
									 : "no",
				pbr_nht_get_table(pbrms->nhgrp_name));
		break;
	case PBR_FT_NEXTHOP_SINGLE:
		assert(pbrms->internal_nhg_name);
		vty_out(vty, "        ");
		pbrms_nexthop_group_write_individual_nexthop(vty, pbrms);
		if (detail)
			vty_out(vty,
				"          Installed: %u(%d) Tableid: %u\n",
				pbrms->nhs_installed,
				pbr_nht_get_installed(pbrms->internal_nhg_name),
				pbr_nht_get_table(pbrms->internal_nhg_name));
		else
			vty_out(vty, "          Installed: %s Tableid: %u\n",
				pbr_nht_get_installed(pbrms->internal_nhg_name)
					? "yes"
					: "no",
				pbr_nht_get_table(pbrms->internal_nhg_name));
		break;
	}
}

static void vty_json_pbrms(json_object *j, struct vty *vty,
			   const struct pbr_map_sequence *pbrms)
{
	json_object *jpbrm, *nexthop_group;
	char *nhg_name = pbrms->nhgrp_name ? pbrms->nhgrp_name
					   : pbrms->internal_nhg_name;
	char rbuf[64];

	jpbrm = json_object_new_object();

	json_object_int_add(jpbrm, "id", pbrms->unique);

	if (pbrms->reason)
		pbr_map_reason_string(pbrms->reason, rbuf, sizeof(rbuf));

	json_object_int_add(jpbrm, "sequenceNumber", pbrms->seqno);
	json_object_int_add(jpbrm, "ruleNumber", pbrms->ruleno);
	json_object_boolean_add(jpbrm, "vrfUnchanged", pbrms->vrf_unchanged);
	json_object_boolean_add(jpbrm, "installed",
				pbr_nht_get_installed(nhg_name));
	json_object_string_add(jpbrm, "installedReason",
			       pbrms->reason ? rbuf : "Valid");

	switch (pbrms->forwarding_type) {
	case PBR_FT_UNSPEC:
		break;
	case PBR_FT_VRF_UNCHANGED:
		break;
	case PBR_FT_SETVRF:
		assert(pbrms->vrf_name);
		json_object_string_add(jpbrm, "vrfName", pbrms->vrf_name);
		break;
	case PBR_FT_NEXTHOP_GROUP:
	case PBR_FT_NEXTHOP_SINGLE:
		assert(nhg_name);
		nexthop_group = json_object_new_object();

		json_object_int_add(nexthop_group, "tableId",
				    pbr_nht_get_table(nhg_name));
		json_object_string_add(nexthop_group, "name", nhg_name);
		json_object_boolean_add(nexthop_group, "installed",
					pbr_nht_get_installed(nhg_name));
		json_object_int_add(nexthop_group, "installedInternally",
				    pbrms->nhs_installed);

		json_object_object_add(jpbrm, "nexthopGroup", nexthop_group);
		break;
	}


	/*
	 * Match clauses
	 */

	/* IP Header */
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_IP_PROTOCOL))
		json_object_int_add(jpbrm, "matchIpProtocol", pbrms->ip_proto);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_IP))
		json_object_string_addf(jpbrm, "matchSrc", "%pFX", pbrms->src);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_IP))
		json_object_string_addf(jpbrm, "matchDst", "%pFX", pbrms->dst);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_PORT))
		json_object_int_add(jpbrm, "matchSrcPort", pbrms->src_prt);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_PORT))
		json_object_int_add(jpbrm, "matchDstPort", pbrms->dst_prt);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DSCP))
		json_object_int_add(jpbrm, "matchDscp",
				    (pbrms->dsfield & PBR_DSFIELD_DSCP) >> 2);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_ECN))
		json_object_int_add(jpbrm, "matchEcn",
				    pbrms->dsfield & PBR_DSFIELD_ECN);

	/* L2 headers */
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_PCP))
		json_object_int_add(jpbrm, "matchPcp", pbrms->match_pcp);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_ID))
		json_object_int_add(jpbrm, "matchVlanId", pbrms->match_vlan_id);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_FLAGS)) {
		const char *p = "?";

		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_TAGGED)
			p = "tagged";
		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_UNTAGGED)
			p = "untagged";
		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_UNTAGGED_0)
			p = "untagged-or-0";

		json_object_string_addf(jpbrm, "matchVlanFlags", "%s", p);
	}

	/* meta */
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_FWMARK))
		json_object_int_add(jpbrm, "matchMark", pbrms->mark);

	/*
	 * action clauses
	 */

	/* IP header fields */
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_IP))
		json_object_string_addf(jpbrm, "actionSetSrcIpAddr", "%pSU",
					&pbrms->action_src);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_IP))
		json_object_string_addf(jpbrm, "actionSetDstIpAddr", "%pSU",
					&pbrms->action_dst);

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_PORT))
		json_object_int_add(jpbrm, "actionSetSrcPort",
				    pbrms->action_src_port);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_PORT))
		json_object_int_add(jpbrm, "actionSetDstPort",
				    pbrms->action_dst_port);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DSCP))
		json_object_int_add(jpbrm, "actionSetDscp",
				    pbrms->action_dscp >> 2);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_ECN))
		json_object_int_add(jpbrm, "actionSetEcn", pbrms->action_ecn);

	/* L2 header fields */
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_STRIP_INNER_ANY))
		json_object_boolean_true_add(jpbrm, "actionVlanStripInnerAny");
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_ID))
		json_object_int_add(jpbrm, "actionSetVlanId",
				    pbrms->action_vlan_id);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_PCP))
		json_object_int_add(jpbrm, "actionSetPcp", pbrms->action_pcp);

	/* meta */
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_QUEUE_ID))
		json_object_int_add(jpbrm, "actionSetQueueId",
				    pbrms->action_queue_id);

	json_object_array_add(j, jpbrm);
}

static void vty_show_pbr_map(struct vty *vty, const struct pbr_map *pbrm,
			     bool detail)
{
	struct pbr_map_sequence *pbrms;
	struct listnode *node;

	vty_out(vty, "  pbr-map %s valid: %s\n", pbrm->name,
		pbrm->valid ? "yes" : "no");

	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms))
		vty_show_pbrms(vty, pbrms, detail);
}

static void vty_json_pbr_map(json_object *j, struct vty *vty,
			     const struct pbr_map *pbrm)
{
	struct pbr_map_sequence *pbrms;
	struct listnode *node;
	json_object *jpbrms;

	json_object_string_add(j, "name", pbrm->name);
	json_object_boolean_add(j, "valid", pbrm->valid);

	jpbrms = json_object_new_array();

	for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms))
		vty_json_pbrms(jpbrms, vty, pbrms);

	json_object_object_add(j, "policies", jpbrms);
}

DEFPY (show_pbr_map,
	show_pbr_map_cmd,
	"show pbr map [NAME$name] [detail$detail] [json$json]",
	SHOW_STR
	PBR_STR
	"PBR Map\n"
	"PBR Map Name\n"
	"Detailed information\n"
	JSON_STR)
{
	struct pbr_map *pbrm;
	json_object *j = NULL;

	if (json)
		j = json_object_new_array();

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		json_object *this_map = NULL;
		if (name && strcmp(name, pbrm->name) != 0)
			continue;

		if (j)
			this_map = json_object_new_object();

		if (this_map) {
			vty_json_pbr_map(this_map, vty, pbrm);

			json_object_array_add(j, this_map);
			continue;
		}

		vty_show_pbr_map(vty, pbrm, detail);
	}

	if (j)
		vty_json(vty, j);

	return CMD_SUCCESS;
}

DEFPY(show_pbr_nexthop_group,
      show_pbr_nexthop_group_cmd,
      "show pbr nexthop-groups [WORD$word] [json$json]",
      SHOW_STR
      PBR_STR
      "Nexthop Groups\n"
      "Optional Name of the nexthop group\n"
      JSON_STR)
{
	json_object *j = NULL;

	if (json)
		j = json_object_new_array();

	if (j) {
		pbr_nht_json_nexthop_group(j, word);

		vty_json(vty, j);
	} else
		pbr_nht_show_nexthop_group(vty, word);


	return CMD_SUCCESS;
}

DEFPY (show_pbr_interface,
	show_pbr_interface_cmd,
	"show pbr interface [NAME$name] [json$json]",
	SHOW_STR
	PBR_STR
	"PBR Interface\n"
	"PBR Interface Name\n"
	JSON_STR)
{
	struct interface *ifp;
	struct vrf *vrf;
	struct pbr_interface *pbr_ifp;
	json_object *j = NULL;

	if (json)
		j = json_object_new_array();

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES(vrf, ifp) {
			struct pbr_map *pbrm;
			json_object *this_iface = NULL;

			if (j)
				this_iface = json_object_new_object();

			if (!ifp->info) {
				json_object_free(this_iface);
				continue;
			}

			if (name && strcmp(ifp->name, name) != 0) {
				json_object_free(this_iface);
				continue;
			}

			pbr_ifp = ifp->info;

			if (strcmp(pbr_ifp->mapname, "") == 0) {
				json_object_free(this_iface);
				continue;
			}

			pbrm = pbrm_find(pbr_ifp->mapname);

			if (this_iface) {
				json_object_string_add(this_iface, "name",
						       ifp->name);
				json_object_int_add(this_iface, "index",
						    ifp->ifindex);
				json_object_string_add(this_iface, "policy",
						       pbr_ifp->mapname);
				json_object_boolean_add(this_iface, "valid",
							pbrm);

				json_object_array_add(j, this_iface);
				continue;
			}

			vty_out(vty, "  %s(%d) with pbr-policy %s", ifp->name,
				ifp->ifindex, pbr_ifp->mapname);
			if (!pbrm)
				vty_out(vty, " (map doesn't exist)");
			vty_out(vty, "\n");
		}
	}

	if (j)
		vty_json(vty, j);

	return CMD_SUCCESS;
}

/* PBR debugging CLI ------------------------------------------------------- */

static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = pbr_debug_config_write,
};

DEFPY(debug_pbr,
      debug_pbr_cmd,
      "[no] debug pbr [{map$map|zebra$zebra|nht$nht|events$events}]",
      NO_STR
      DEBUG_STR
      PBR_STR
      "Policy maps\n"
      "PBRD <-> Zebra communications\n"
      "Nexthop tracking\n"
      "Events\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	if (map)
		DEBUG_MODE_SET(&pbr_dbg_map, mode, !no);
	if (zebra)
		DEBUG_MODE_SET(&pbr_dbg_zebra, mode, !no);
	if (nht)
		DEBUG_MODE_SET(&pbr_dbg_nht, mode, !no);
	if (events)
		DEBUG_MODE_SET(&pbr_dbg_event, mode, !no);

	/* no specific debug --> act on all of them */
	if (strmatch(argv[argc - 1]->text, "pbr"))
		pbr_debug_set_all(mode, !no);

	return CMD_SUCCESS;
}

DEFUN_NOSH(show_debugging_pbr,
	   show_debugging_pbr_cmd,
	   "show debugging [pbr]",
	   SHOW_STR
	   DEBUG_STR
	   PBR_STR)
{
	vty_out(vty, "PBR debugging status:\n");

	pbr_debug_config_write_helper(vty, false);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

/* ------------------------------------------------------------------------- */


static int pbr_interface_config_write(struct vty *vty)
{
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if_vty_config_start(vty, ifp);

			if (ifp->desc)
				vty_out(vty, " description %s\n", ifp->desc);

			pbr_map_write_interfaces(vty, ifp);

			if_vty_config_end(vty);
		}
	}

	return 1;
}

static int pbr_vty_map_config_write(struct vty *vty);
/* PBR map node structure. */
static struct cmd_node pbr_map_node = {
	.name = "pbr-map",
	.node = PBRMAP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-pbr-map)# ",
	.config_write = pbr_vty_map_config_write,
};

static int pbr_vty_map_config_write_sequence(struct vty *vty,
					     struct pbr_map *pbrm,
					     struct pbr_map_sequence *pbrms)
{
	vty_out(vty, "pbr-map %s seq %u\n", pbrm->name, pbrms->seqno);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_IP_PROTOCOL)) {
		struct protoent *p;

		p = getprotobynumber(pbrms->ip_proto);
		vty_out(vty, " match ip-protocol %s\n", p->p_name);
	}

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_IP))
		vty_out(vty, " match src-ip %pFX\n", pbrms->src);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_IP))
		vty_out(vty, " match dst-ip %pFX\n", pbrms->dst);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_SRC_PORT))
		vty_out(vty, " match src-port %u\n", pbrms->src_prt);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DST_PORT))
		vty_out(vty, " match dst-port %u\n", pbrms->dst_prt);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_DSCP))
		vty_out(vty, " match dscp %u\n",
			(pbrms->dsfield & PBR_DSFIELD_DSCP) >> 2);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_ECN))
		vty_out(vty, " match ecn %u\n",
			pbrms->dsfield & PBR_DSFIELD_ECN);

	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_PCP))
		vty_out(vty, " match pcp %d\n", pbrms->match_pcp);

	/* L2 headers */
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_ID))
		vty_out(vty, " match vlan %u\n", pbrms->match_vlan_id);
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_VLAN_FLAGS)) {
		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_TAGGED)
			vty_out(vty, " match vlan tagged\n");
		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_UNTAGGED)
			vty_out(vty, " match vlan untagged\n");
		if (pbrms->match_vlan_flags == PBR_VLAN_FLAGS_UNTAGGED_0)
			vty_out(vty, " match vlan untagged-or-zero\n");
	}

	/* meta */
	if (CHECK_FLAG(pbrms->filter_bm, PBR_FILTER_FWMARK))
		vty_out(vty, " match mark %u\n", pbrms->mark);

	/*
	 * action clauses
	 */

	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_IP))
		vty_out(vty, " set src-ip %pSU\n", &pbrms->action_src);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_IP))
		vty_out(vty, " set dst-ip %pSU\n", &pbrms->action_dst);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_SRC_PORT))
		vty_out(vty, " set src-port %d\n", pbrms->action_src_port);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DST_PORT))
		vty_out(vty, " set dst-port %d\n", pbrms->action_dst_port);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_DSCP))
		vty_out(vty, " set dscp %u\n", (pbrms->action_dscp) >> 2);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_ECN))
		vty_out(vty, " set ecn %u\n", pbrms->action_ecn);

	/* L2 header fields */
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_STRIP_INNER_ANY))
		vty_out(vty, " strip vlan any\n");
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_VLAN_ID))
		vty_out(vty, " set vlan %u\n", pbrms->action_vlan_id);
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_PCP))
		vty_out(vty, " set pcp %d\n", pbrms->action_pcp);

	/* meta */
	if (CHECK_FLAG(pbrms->action_bm, PBR_ACTION_QUEUE_ID))
		vty_out(vty, " set queue-id %d\n", pbrms->action_queue_id);

	switch (pbrms->forwarding_type) {
	case PBR_FT_UNSPEC:
		break;
	case PBR_FT_VRF_UNCHANGED:
		vty_out(vty, " set vrf unchanged\n");
		break;
	case PBR_FT_SETVRF:
		assert(pbrms->vrf_name);
		vty_out(vty, " set vrf %s\n", pbrms->vrf_name);
		break;
	case PBR_FT_NEXTHOP_GROUP:
		assert(pbrms->nhgrp_name);
		vty_out(vty, " set nexthop-group %s\n", pbrms->nhgrp_name);
		break;
	case PBR_FT_NEXTHOP_SINGLE:
		assert(pbrms->nhg);
		vty_out(vty, " set ");
		pbrms_nexthop_group_write_individual_nexthop(vty, pbrms);
		break;
	}

	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
	return 1;
}

static int pbr_vty_map_config_write(struct vty *vty)
{
	struct pbr_map *pbrm;

	pbr_nht_write_table_range(vty);
	pbr_nht_write_rule_range(vty);

	RB_FOREACH(pbrm, pbr_map_entry_head, &pbr_maps) {
		struct pbr_map_sequence *pbrms;
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, node, pbrms))
			pbr_vty_map_config_write_sequence(vty, pbrm, pbrms);
	}

	return 1;
}

static void pbr_map_completer(vector comps, struct cmd_token *token)
{
	struct pbr_map *pbrm;

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, pbrm->name));
}

static const struct cmd_variable_handler pbr_map_name[] = {
	{
		.tokenname = "PBRMAP", .completions = pbr_map_completer,
	},
	{
		.completions = NULL
	}
};

extern struct zebra_privs_t pbr_privs;

void pbr_vty_init(void)
{
	cmd_variable_handler_register(pbr_map_name);

	vrf_cmd_init(NULL);

	if_cmd_init(pbr_interface_config_write);

	install_node(&pbr_map_node);

	/* debug */
	install_node(&debug_node);
	install_element(ENABLE_NODE, &debug_pbr_cmd);
	install_element(CONFIG_NODE, &debug_pbr_cmd);
	install_element(ENABLE_NODE, &show_debugging_pbr_cmd);

	install_default(PBRMAP_NODE);

	install_element(CONFIG_NODE, &pbr_map_cmd);
	install_element(CONFIG_NODE, &no_pbr_map_cmd);
	install_element(CONFIG_NODE, &pbr_set_table_range_cmd);
	install_element(CONFIG_NODE, &no_pbr_set_table_range_cmd);
	install_element(INTERFACE_NODE, &pbr_policy_cmd);

	install_element(PBRMAP_NODE, &pbr_map_match_ip_proto_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_src_port_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_dst_port_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_src_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_dst_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_dscp_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_ecn_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_vlan_id_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_vlan_tag_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_pcp_cmd);
	install_element(PBRMAP_NODE, &pbr_map_match_mark_cmd);

	install_element(PBRMAP_NODE, &pbr_map_action_queue_id_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_strip_vlan_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_vlan_id_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_pcp_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_src_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_dst_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_dscp_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_ecn_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_src_port_cmd);
	install_element(PBRMAP_NODE, &pbr_map_action_dst_port_cmd);

	install_element(PBRMAP_NODE, &pbr_map_nexthop_group_cmd);
	install_element(PBRMAP_NODE, &no_pbr_map_nexthop_group_cmd);
	install_element(PBRMAP_NODE, &pbr_map_nexthop_cmd);
	install_element(PBRMAP_NODE, &no_pbr_map_nexthop_cmd);
	install_element(PBRMAP_NODE, &pbr_map_vrf_cmd);
	install_element(PBRMAP_NODE, &no_pbr_map_vrf_cmd);
	install_element(VIEW_NODE, &show_pbr_cmd);
	install_element(VIEW_NODE, &show_pbr_map_cmd);
	install_element(VIEW_NODE, &show_pbr_interface_cmd);
	install_element(VIEW_NODE, &show_pbr_nexthop_group_cmd);
}
