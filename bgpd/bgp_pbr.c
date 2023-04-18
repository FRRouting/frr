// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP pbr
 * Copyright (C) 6WIND
 */

#include "zebra.h"
#include "prefix.h"
#include "zclient.h"
#include "jhash.h"
#include "pbr.h"

#include "lib/printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_pbr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_flowspec_private.h"
#include "bgpd/bgp_errors.h"

DEFINE_MTYPE_STATIC(BGPD, PBR_MATCH_ENTRY, "PBR match entry");
DEFINE_MTYPE_STATIC(BGPD, PBR_MATCH, "PBR match");
DEFINE_MTYPE_STATIC(BGPD, PBR_ACTION, "PBR action");
DEFINE_MTYPE_STATIC(BGPD, PBR_RULE, "PBR rule");
DEFINE_MTYPE_STATIC(BGPD, PBR, "BGP PBR Context");
DEFINE_MTYPE_STATIC(BGPD, PBR_VALMASK, "BGP PBR Val Mask Value");

/* chain strings too long to fit in one line */
#define FSPEC_ACTION_EXCEED_LIMIT "flowspec actions exceeds limit"
#define IPV6_FRAGMENT_INVALID "fragment not valid for IPv6 for this implementation"

RB_GENERATE(bgp_pbr_interface_head, bgp_pbr_interface,
	    id_entry, bgp_pbr_interface_compare);
struct bgp_pbr_interface_head ifaces_by_name_ipv4 =
	RB_INITIALIZER(&ifaces_by_name_ipv4);

static int bgp_pbr_match_counter_unique;
static int bgp_pbr_match_entry_counter_unique;
static int bgp_pbr_action_counter_unique;
static int bgp_pbr_match_iptable_counter_unique;

struct bgp_pbr_match_iptable_unique {
	uint32_t unique;
	struct bgp_pbr_match *bpm_found;
};

struct bgp_pbr_match_entry_unique {
	uint32_t unique;
	struct bgp_pbr_match_entry *bpme_found;
};

struct bgp_pbr_action_unique {
	uint32_t unique;
	struct bgp_pbr_action *bpa_found;
};

struct bgp_pbr_rule_unique {
	uint32_t unique;
	struct bgp_pbr_rule *bpr_found;
};

static int bgp_pbr_rule_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct bgp_pbr_rule *bpr = (struct bgp_pbr_rule *)bucket->data;
	struct bgp_pbr_rule_unique *bpru = (struct bgp_pbr_rule_unique *)
		arg;
	uint32_t unique = bpru->unique;

	if (bpr->unique == unique) {
		bpru->bpr_found = bpr;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int bgp_pbr_action_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct bgp_pbr_action *bpa = (struct bgp_pbr_action *)bucket->data;
	struct bgp_pbr_action_unique *bpau = (struct bgp_pbr_action_unique *)
		arg;
	uint32_t unique = bpau->unique;

	if (bpa->unique == unique) {
		bpau->bpa_found = bpa;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int bgp_pbr_match_entry_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct bgp_pbr_match_entry *bpme =
		(struct bgp_pbr_match_entry *)bucket->data;
	struct bgp_pbr_match_entry_unique *bpmeu =
		(struct bgp_pbr_match_entry_unique *)arg;
	uint32_t unique = bpmeu->unique;

	if (bpme->unique == unique) {
		bpmeu->bpme_found = bpme;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct bgp_pbr_match_ipsetname {
	char *ipsetname;
	struct bgp_pbr_match *bpm_found;
};

static int bgp_pbr_match_pername_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)bucket->data;
	struct bgp_pbr_match_ipsetname *bpmi =
		(struct bgp_pbr_match_ipsetname *)arg;
	char *ipset_name = bpmi->ipsetname;

	if (!strncmp(ipset_name, bpm->ipset_name,
		     ZEBRA_IPSET_NAME_SIZE)) {
		bpmi->bpm_found = bpm;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int bgp_pbr_match_iptable_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)bucket->data;
	struct bgp_pbr_match_iptable_unique *bpmiu =
		(struct bgp_pbr_match_iptable_unique *)arg;
	uint32_t unique = bpmiu->unique;

	if (bpm->unique2 == unique) {
		bpmiu->bpm_found = bpm;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct bgp_pbr_match_unique {
	uint32_t unique;
	struct bgp_pbr_match *bpm_found;
};

static int bgp_pbr_match_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)bucket->data;
	struct bgp_pbr_match_unique *bpmu = (struct bgp_pbr_match_unique *)
		arg;
	uint32_t unique = bpmu->unique;

	if (bpm->unique == unique) {
		bpmu->bpm_found = bpm;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int snprintf_bgp_pbr_match_val(char *str, int len,
				      struct bgp_pbr_match_val *mval,
				      const char *prepend)
{
	char *ptr = str;
	int delta;

	if (prepend) {
		delta = snprintf(ptr, len, "%s", prepend);
		ptr += delta;
		len -= delta;
	} else {
		if (mval->unary_operator & OPERATOR_UNARY_OR) {
			delta = snprintf(ptr, len, ", or ");
			ptr += delta;
			len -= delta;
		}
		if (mval->unary_operator & OPERATOR_UNARY_AND) {
			delta = snprintf(ptr, len, ", and ");
			ptr += delta;
			len -= delta;
		}
	}
	if (mval->compare_operator & OPERATOR_COMPARE_LESS_THAN) {
		delta = snprintf(ptr, len, "<");
		ptr += delta;
		len -= delta;
	}
	if (mval->compare_operator & OPERATOR_COMPARE_GREATER_THAN) {
		delta = snprintf(ptr, len, ">");
		ptr += delta;
		len -= delta;
	}
	if (mval->compare_operator & OPERATOR_COMPARE_EQUAL_TO) {
		delta = snprintf(ptr, len, "=");
		ptr += delta;
		len -= delta;
	}
	if (mval->compare_operator & OPERATOR_COMPARE_EXACT_MATCH) {
		delta = snprintf(ptr, len, "match");
		ptr += delta;
		len -= delta;
	}
	ptr += snprintf(ptr, len, " %u", mval->value);
	return (int)(ptr - str);
}

#define INCREMENT_DISPLAY(_ptr, _cnt, _len) do {	\
		int sn_delta;				\
							\
		if (_cnt) {				\
			sn_delta = snprintf((_ptr), (_len), "; ");\
			(_len) -= sn_delta;		\
			(_ptr) += sn_delta;		\
		}				\
		(_cnt)++;	\
	} while (0)

/* this structure can be used for port range,
 * but also for other values range like packet length range
 */
struct bgp_pbr_range_port {
	uint16_t min_port;
	uint16_t max_port;
};

/* this structure can be used to filter with a mask
 * for instance it supports not instructions like for
 * tcpflags
 */
struct bgp_pbr_val_mask {
	uint16_t val;
	uint16_t mask;
};

/* this structure is used to pass instructs
 * so that BGP can create pbr instructions to ZEBRA
 */
struct bgp_pbr_filter {
	uint8_t type;
	vrf_id_t vrf_id;
	uint8_t family;
	struct prefix *src;
	struct prefix *dst;
	uint8_t bitmask_iprule;
	uint8_t protocol;
	struct bgp_pbr_range_port *pkt_len;
	struct bgp_pbr_range_port *src_port;
	struct bgp_pbr_range_port *dst_port;
	struct bgp_pbr_val_mask *tcp_flags;
	struct bgp_pbr_val_mask *dscp;
	struct bgp_pbr_val_mask *flow_label;
	struct bgp_pbr_val_mask *pkt_len_val;
	struct bgp_pbr_val_mask *fragment;
};

/* this structure is used to contain OR instructions
 * so that BGP can create multiple pbr instructions
 * to ZEBRA
 */
struct bgp_pbr_or_filter {
	struct list *tcpflags;
	struct list *dscp;
	struct list *flowlabel;
	struct list *pkt_len;
	struct list *fragment;
	struct list *icmp_type;
	struct list *icmp_code;
};

static void bgp_pbr_policyroute_add_to_zebra_unit(struct bgp *bgp,
						  struct bgp_path_info *path,
						  struct bgp_pbr_filter *bpf,
						  struct nexthop *nh,
						  float *rate);

static void bgp_pbr_dump_entry(struct bgp_pbr_filter *bpf, bool add);

static bool bgp_pbr_extract_enumerate_unary_opposite(
				 uint8_t unary_operator,
				 struct bgp_pbr_val_mask *and_valmask,
				 struct list *or_valmask, uint32_t value,
				 uint8_t type_entry)
{
	if (unary_operator == OPERATOR_UNARY_AND && and_valmask) {
		if (type_entry == FLOWSPEC_TCP_FLAGS) {
			and_valmask->mask |=
				TCP_HEADER_ALL_FLAGS &
				~(value);
		} else if (type_entry == FLOWSPEC_DSCP ||
			   type_entry == FLOWSPEC_FLOW_LABEL ||
			   type_entry == FLOWSPEC_PKT_LEN ||
			   type_entry == FLOWSPEC_FRAGMENT) {
			and_valmask->val = value;
			and_valmask->mask = 1; /* inverse */
		}
	} else if (unary_operator == OPERATOR_UNARY_OR && or_valmask) {
		and_valmask = XCALLOC(MTYPE_PBR_VALMASK,
				      sizeof(struct bgp_pbr_val_mask));
		if (type_entry == FLOWSPEC_TCP_FLAGS) {
			and_valmask->val = TCP_HEADER_ALL_FLAGS;
			and_valmask->mask |=
				TCP_HEADER_ALL_FLAGS &
				~(value);
		} else if (type_entry == FLOWSPEC_DSCP ||
			   type_entry == FLOWSPEC_FLOW_LABEL ||
			   type_entry == FLOWSPEC_FRAGMENT ||
			   type_entry == FLOWSPEC_PKT_LEN) {
			and_valmask->val = value;
			and_valmask->mask = 1; /* inverse */
		}
		listnode_add(or_valmask, and_valmask);
	} else if (type_entry == FLOWSPEC_ICMP_CODE ||
		   type_entry == FLOWSPEC_ICMP_TYPE)
		return false;
	return true;
}

/* TCP : FIN and SYN -> val = ALL; mask = 3
 * TCP : not (FIN and SYN) -> val = ALL; mask = ALL & ~(FIN|RST)
 * other variables type: dscp, pkt len, fragment, flow label
 * - value is copied in bgp_pbr_val_mask->val value
 * - if negate form is identifierd, bgp_pbr_val_mask->mask set to 1
 */
static bool bgp_pbr_extract_enumerate_unary(struct bgp_pbr_match_val list[],
					    int num, uint8_t unary_operator,
					    void *valmask, uint8_t type_entry)
{
	int i = 0;
	struct bgp_pbr_val_mask *and_valmask = NULL;
	struct list *or_valmask = NULL;
	bool ret;

	if (valmask) {
		if (unary_operator == OPERATOR_UNARY_AND) {
			and_valmask = (struct bgp_pbr_val_mask *)valmask;
			memset(and_valmask, 0, sizeof(struct bgp_pbr_val_mask));
		} else if (unary_operator == OPERATOR_UNARY_OR) {
			or_valmask = (struct list *)valmask;
		}
	}
	for (i = 0; i < num; i++) {
		if (i != 0 && list[i].unary_operator !=
		    unary_operator)
			return false;
		if (!(list[i].compare_operator &
		    OPERATOR_COMPARE_EQUAL_TO) &&
		    !(list[i].compare_operator &
		      OPERATOR_COMPARE_EXACT_MATCH)) {
			if ((list[i].compare_operator &
			     OPERATOR_COMPARE_LESS_THAN) &&
			    (list[i].compare_operator &
			     OPERATOR_COMPARE_GREATER_THAN)) {
				ret = bgp_pbr_extract_enumerate_unary_opposite(
						 unary_operator, and_valmask,
						 or_valmask, list[i].value,
						 type_entry);
				if (!ret)
					return ret;
				continue;
			}
			return false;
		}
		if (unary_operator == OPERATOR_UNARY_AND && and_valmask) {
			if (type_entry == FLOWSPEC_TCP_FLAGS)
				and_valmask->mask |=
					TCP_HEADER_ALL_FLAGS & list[i].value;
		} else if (unary_operator == OPERATOR_UNARY_OR && or_valmask) {
			and_valmask = XCALLOC(MTYPE_PBR_VALMASK,
					      sizeof(struct bgp_pbr_val_mask));
			if (type_entry == FLOWSPEC_TCP_FLAGS) {
				and_valmask->val = TCP_HEADER_ALL_FLAGS;
				and_valmask->mask |=
					TCP_HEADER_ALL_FLAGS & list[i].value;
			} else if (type_entry == FLOWSPEC_DSCP ||
				   type_entry == FLOWSPEC_FLOW_LABEL ||
				   type_entry == FLOWSPEC_ICMP_TYPE ||
				   type_entry == FLOWSPEC_ICMP_CODE ||
				   type_entry == FLOWSPEC_FRAGMENT ||
				   type_entry == FLOWSPEC_PKT_LEN)
				and_valmask->val = list[i].value;
			listnode_add(or_valmask, and_valmask);
		}
	}
	if (unary_operator == OPERATOR_UNARY_AND && and_valmask
	    && type_entry == FLOWSPEC_TCP_FLAGS)
		and_valmask->val = TCP_HEADER_ALL_FLAGS;
	return true;
}

/* if unary operator can either be UNARY_OR/AND/OR-AND.
 * in the latter case, combinationf of both is not handled
 */
static bool bgp_pbr_extract_enumerate(struct bgp_pbr_match_val list[],
				      int num, uint8_t unary_operator,
				      void *valmask, uint8_t type_entry)
{
	bool ret;
	uint8_t unary_operator_val;
	bool double_check = false;

	if ((unary_operator & OPERATOR_UNARY_OR) &&
	    (unary_operator & OPERATOR_UNARY_AND)) {
		unary_operator_val = OPERATOR_UNARY_AND;
		double_check = true;
	} else
		unary_operator_val = unary_operator;
	ret = bgp_pbr_extract_enumerate_unary(list, num, unary_operator_val,
					      valmask, type_entry);
	if (!ret && double_check)
		ret = bgp_pbr_extract_enumerate_unary(list, num,
						      OPERATOR_UNARY_OR,
						      valmask,
						      type_entry);
	return ret;
}

/* returns the unary operator that is in the list
 * return 0 if both operators are used
 */
static uint8_t bgp_pbr_match_val_get_operator(struct bgp_pbr_match_val list[],
					      int num)

{
	int i;
	uint8_t unary_operator = OPERATOR_UNARY_AND;

	for (i = 0; i < num; i++) {
		if (i == 0)
			continue;
		if (list[i].unary_operator & OPERATOR_UNARY_OR)
			unary_operator = OPERATOR_UNARY_OR;
		if ((list[i].unary_operator & OPERATOR_UNARY_AND
		     && unary_operator == OPERATOR_UNARY_OR) ||
		    (list[i].unary_operator & OPERATOR_UNARY_OR
		     && unary_operator == OPERATOR_UNARY_AND))
			return 0;
	}
	return unary_operator;
}


/* return true if extraction ok
 */
static bool bgp_pbr_extract(struct bgp_pbr_match_val list[],
			    int num,
			    struct bgp_pbr_range_port *range)
{
	int i = 0;
	bool exact_match = false;

	if (range)
		memset(range, 0, sizeof(struct bgp_pbr_range_port));

	if (num > 2)
		return false;
	for (i = 0; i < num; i++) {
		if (i != 0 && (list[i].compare_operator ==
			       OPERATOR_COMPARE_EQUAL_TO))
			return false;
		if (i == 0 && (list[i].compare_operator ==
			       OPERATOR_COMPARE_EQUAL_TO)) {
			if (range)
				range->min_port = list[i].value;
			exact_match = true;
		}
		if (exact_match && i > 0)
			return false;
		if (list[i].compare_operator ==
		    (OPERATOR_COMPARE_GREATER_THAN +
		     OPERATOR_COMPARE_EQUAL_TO)) {
			if (range)
				range->min_port = list[i].value;
		} else if (list[i].compare_operator ==
			   (OPERATOR_COMPARE_LESS_THAN +
			    OPERATOR_COMPARE_EQUAL_TO)) {
			if (range)
				range->max_port = list[i].value;
		} else if (list[i].compare_operator ==
			   OPERATOR_COMPARE_LESS_THAN) {
			if (range)
				range->max_port = list[i].value - 1;
		} else if (list[i].compare_operator ==
			   OPERATOR_COMPARE_GREATER_THAN) {
			if (range)
				range->min_port = list[i].value + 1;
		}
	}
	return true;
}

static int bgp_pbr_validate_policy_route(struct bgp_pbr_entry_main *api)
{
	bool enumerate_icmp = false;

	if (api->type ==  BGP_PBR_UNDEFINED) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: pbr entry undefined. cancel.");
		return 0;
	}
	/* because bgp pbr entry may contain unsupported
	 * combinations, a message will be displayed here if
	 * not supported.
	 * for now, only match/set supported is
	 * - combination src/dst => redirect nexthop [ + rate]
	 * - combination src/dst => redirect VRF [ + rate]
	 * - combination src/dst => drop
	 * - combination srcport + @IP
	 */
	if (api->match_protocol_num > 1) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match protocol operations:multiple protocols ( %d). ignoring.",
				 api->match_protocol_num);
		return 0;
	}
	if (api->src_prefix_offset > 0 ||
	    api->dst_prefix_offset > 0) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match prefix offset:"
				   "implementation does not support it.");
		return 0;
	}
	if (api->match_protocol_num == 1 &&
	    api->protocol[0].value != PROTOCOL_UDP &&
	    api->protocol[0].value != PROTOCOL_ICMP &&
	    api->protocol[0].value != PROTOCOL_ICMPV6 &&
	    api->protocol[0].value != PROTOCOL_TCP) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match protocol operations:protocol (%d) not supported. ignoring",
				   api->match_protocol_num);
		return 0;
	}
	if (!bgp_pbr_extract(api->src_port, api->match_src_port_num, NULL)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match src port operations:too complex. ignoring.");
		return 0;
	}
	if (!bgp_pbr_extract(api->dst_port, api->match_dst_port_num, NULL)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match dst port operations:too complex. ignoring.");
		return 0;
	}
	if (!bgp_pbr_extract_enumerate(api->tcpflags,
				       api->match_tcpflags_num,
				       OPERATOR_UNARY_AND |
				       OPERATOR_UNARY_OR, NULL,
				       FLOWSPEC_TCP_FLAGS)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match tcp flags:too complex. ignoring.");
		return 0;
	}
	if (!bgp_pbr_extract(api->icmp_type, api->match_icmp_type_num, NULL)) {
		if (!bgp_pbr_extract_enumerate(api->icmp_type,
					       api->match_icmp_type_num,
					       OPERATOR_UNARY_OR, NULL,
					       FLOWSPEC_ICMP_TYPE)) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match icmp type operations:too complex. ignoring.");
			return 0;
		}
		enumerate_icmp = true;
	}
	if (!bgp_pbr_extract(api->icmp_code, api->match_icmp_code_num, NULL)) {
		if (!bgp_pbr_extract_enumerate(api->icmp_code,
					       api->match_icmp_code_num,
					       OPERATOR_UNARY_OR, NULL,
					       FLOWSPEC_ICMP_CODE)) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match icmp code operations:too complex. ignoring.");
			return 0;
		} else if (api->match_icmp_type_num > 1 &&
			   !enumerate_icmp) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match icmp code is enumerate, and icmp type is not. too complex. ignoring.");
			return 0;
		}
	}
	if (!bgp_pbr_extract(api->port, api->match_port_num, NULL)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match port operations:too complex. ignoring.");
		return 0;
	}
	if (api->match_packet_length_num) {
		bool ret;

		ret = bgp_pbr_extract(api->packet_length,
				      api->match_packet_length_num, NULL);
		if (!ret)
			ret = bgp_pbr_extract_enumerate(api->packet_length,
						api->match_packet_length_num,
						OPERATOR_UNARY_OR
						| OPERATOR_UNARY_AND,
						NULL, FLOWSPEC_PKT_LEN);
		if (!ret) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match packet length operations:too complex. ignoring.");
			return 0;
		}
	}
	if (api->match_dscp_num) {
		if (!bgp_pbr_extract_enumerate(api->dscp, api->match_dscp_num,
				OPERATOR_UNARY_OR | OPERATOR_UNARY_AND,
					       NULL, FLOWSPEC_DSCP)) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match DSCP operations:too complex. ignoring.");
			return 0;
		}
	}
	if (api->match_flowlabel_num) {
		if (api->afi == AFI_IP) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match Flow Label operations:"
					   "Not for IPv4.");
			return 0;
		}
		if (!bgp_pbr_extract_enumerate(api->flow_label,
					       api->match_flowlabel_num,
				OPERATOR_UNARY_OR | OPERATOR_UNARY_AND,
					       NULL, FLOWSPEC_FLOW_LABEL)) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match FlowLabel operations:"
					   "too complex. ignoring.");
			return 0;
		}
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match FlowLabel operations "
				   "not supported. ignoring.");
		return 0;
	}
	if (api->match_fragment_num) {
		char fail_str[64];
		bool success;

		success = bgp_pbr_extract_enumerate(api->fragment,
						    api->match_fragment_num,
						    OPERATOR_UNARY_OR
						    | OPERATOR_UNARY_AND,
						    NULL, FLOWSPEC_FRAGMENT);
		if (success) {
			int i;

			for (i = 0; i < api->match_fragment_num; i++) {
				if (api->fragment[i].value != 1 &&
				    api->fragment[i].value != 2 &&
				    api->fragment[i].value != 4 &&
				    api->fragment[i].value != 8) {
					success = false;
					snprintf(
						fail_str, sizeof(fail_str),
						"Value not valid (%d) for this implementation",
						api->fragment[i].value);
				}
				if (api->afi == AFI_IP6 &&
				    api->fragment[i].value == 1) {
					success = false;
					snprintf(fail_str, sizeof(fail_str),
						 "IPv6 dont fragment match invalid (%d)",
						 api->fragment[i].value);
				}
			}
			if (api->afi == AFI_IP6) {
				success = false;
				snprintf(fail_str, sizeof(fail_str),
					 "%s", IPV6_FRAGMENT_INVALID);
			}
		} else
			snprintf(fail_str, sizeof(fail_str),
				 "too complex. ignoring");
		if (!success) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match fragment operation (%d) %s",
					   api->match_fragment_num,
					   fail_str);
			return 0;
		}
	}

	/* no combinations with both src_port and dst_port
	 * or port with src_port and dst_port
	 */
	if (api->match_src_port_num + api->match_dst_port_num +
	    api->match_port_num > 3) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match multiple port operations: too complex. ignoring.");
		return 0;
	}
	if ((api->match_src_port_num || api->match_dst_port_num
	     || api->match_port_num) && (api->match_icmp_type_num
					 || api->match_icmp_code_num)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match multiple port/imcp operations: too complex. ignoring.");
		return 0;
	}
	/* iprule only supports redirect IP */
	if (api->type == BGP_PBR_IPRULE) {
		int i;

		for (i = 0; i < api->action_num; i++) {
			if (api->actions[i].action == ACTION_TRAFFICRATE &&
			    api->actions[i].u.r.rate == 0) {
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_debug("BGP: iprule match actions drop not supported");
				}
				return 0;
			}
			if (api->actions[i].action == ACTION_MARKING) {
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_warn("PBR: iprule set DSCP/Flow Label %u not supported",
						api->actions[i].u.marking_dscp);
				}
			}
			if (api->actions[i].action == ACTION_REDIRECT) {
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_warn("PBR: iprule redirect VRF %u not supported",
						api->actions[i].u.redirect_vrf);
				}
			}
		}

	} else if (!(api->match_bitmask & PREFIX_SRC_PRESENT) &&
		   !(api->match_bitmask & PREFIX_DST_PRESENT)) {
		if (BGP_DEBUG(pbr, PBR)) {
			bgp_pbr_print_policy_route(api);
			zlog_debug("BGP: match actions without src or dst address can not operate. ignoring.");
		}
		return 0;
	}
	return 1;
}

/* return -1 if build or validation failed */

int bgp_pbr_build_and_validate_entry(const struct prefix *p,
				     struct bgp_path_info *path,
				     struct bgp_pbr_entry_main *api)
{
	int ret;
	uint32_t i, action_count = 0;
	struct ecommunity *ecom;
	struct ecommunity_val *ecom_eval;
	struct bgp_pbr_entry_action *api_action;
	struct prefix *src = NULL, *dst = NULL;
	int valid_prefix = 0;
	struct bgp_pbr_entry_action *api_action_redirect_ip = NULL;
	bool discard_action_found = false;
	afi_t afi = family2afi(p->u.prefix_flowspec.family);

	/* extract match from flowspec entries */
	ret = bgp_flowspec_match_rules_fill((uint8_t *)p->u.prefix_flowspec.ptr,
					    p->u.prefix_flowspec.prefixlen, api, afi);
	if (ret < 0)
		return -1;
	/* extract actiosn from flowspec ecom list */
	if (path && bgp_attr_get_ecommunity(path->attr)) {
		ecom = bgp_attr_get_ecommunity(path->attr);
		for (i = 0; i < ecom->size; i++) {
			ecom_eval = (struct ecommunity_val *)
				(ecom->val + (i * ECOMMUNITY_SIZE));
			action_count++;
			if (action_count > ACTIONS_MAX_NUM) {
				if (BGP_DEBUG(pbr, PBR_ERROR))
					flog_err(
						EC_BGP_FLOWSPEC_PACKET,
						"%s: %s (max %u)",
						__func__,
						FSPEC_ACTION_EXCEED_LIMIT,
						action_count);
				break;
			}
			api_action = &api->actions[action_count - 1];

			if ((ecom_eval->val[1] ==
			     (char)ECOMMUNITY_REDIRECT_VRF) &&
			    (ecom_eval->val[0] ==
			     (char)ECOMMUNITY_ENCODE_TRANS_EXP ||
			     ecom_eval->val[0] ==
			     (char)ECOMMUNITY_EXTENDED_COMMUNITY_PART_2 ||
			     ecom_eval->val[0] ==
			     (char)ECOMMUNITY_EXTENDED_COMMUNITY_PART_3)) {
				struct ecommunity *eckey = ecommunity_new();
				struct ecommunity_val ecom_copy;

				memcpy(&ecom_copy, ecom_eval,
				       sizeof(struct ecommunity_val));
				ecom_copy.val[0] &=
					~ECOMMUNITY_ENCODE_TRANS_EXP;
				ecom_copy.val[1] = ECOMMUNITY_ROUTE_TARGET;
				ecommunity_add_val(eckey, &ecom_copy,
						   false, false);

				api_action->action = ACTION_REDIRECT;
				api_action->u.redirect_vrf =
					get_first_vrf_for_redirect_with_rt(
								eckey);
				ecommunity_free(&eckey);
			} else if ((ecom_eval->val[0] ==
				    (char)ECOMMUNITY_ENCODE_REDIRECT_IP_NH) &&
				   (ecom_eval->val[1] ==
				    (char)ECOMMUNITY_REDIRECT_IP_NH)) {
				/* in case the 2 ecom present,
				 * do not overwrite
				 * draft-ietf-idr-flowspec-redirect
				 */
				if (api_action_redirect_ip &&
				    p->u.prefix_flowspec.family == AF_INET) {
					if (api_action_redirect_ip->u
					    .zr.redirect_ip_v4.s_addr
					    != INADDR_ANY)
						continue;
					if (path->attr->nexthop.s_addr
					    == INADDR_ANY)
						continue;
					api_action_redirect_ip->u.zr
						.redirect_ip_v4.s_addr =
						path->attr->nexthop.s_addr;
					api_action_redirect_ip->u.zr.duplicate
						= ecom_eval->val[7];
					continue;
				} else if (api_action_redirect_ip &&
				    p->u.prefix_flowspec.family == AF_INET6) {
					if (memcmp(&api_action_redirect_ip->u
						   .zr.redirect_ip_v6,
						   &in6addr_any,
						   sizeof(struct in6_addr)))
						continue;
					if (path->attr->mp_nexthop_len == 0 ||
					    path->attr->mp_nexthop_len ==
					    BGP_ATTR_NHLEN_IPV4 ||
					    path->attr->mp_nexthop_len ==
					    BGP_ATTR_NHLEN_VPNV4)
						continue;
					memcpy(&api_action_redirect_ip->u
					       .zr.redirect_ip_v6,
					       &path->attr->mp_nexthop_global,
					       sizeof(struct in6_addr));
					api_action_redirect_ip->u.zr.duplicate
						= ecom_eval->val[7];
					continue;
				} else if (p->u.prefix_flowspec.family ==
					   AF_INET) {
					api_action->action = ACTION_REDIRECT_IP;
					api_action->u.zr.redirect_ip_v4.s_addr =
						path->attr->nexthop.s_addr;
					api_action->u.zr.duplicate =
						ecom_eval->val[7];
					api_action_redirect_ip = api_action;
				} else if (p->u.prefix_flowspec.family ==
					   AF_INET6) {
					api_action->action = ACTION_REDIRECT_IP;
					memcpy(&api_action->u
					       .zr.redirect_ip_v6,
					       &path->attr->mp_nexthop_global,
					       sizeof(struct in6_addr));
					api_action->u.zr.duplicate
						= ecom_eval->val[7];
					api_action_redirect_ip = api_action;
				}
			} else if ((ecom_eval->val[0] ==
				    (char)ECOMMUNITY_ENCODE_IP) &&
				   (ecom_eval->val[1] ==
				    (char)ECOMMUNITY_FLOWSPEC_REDIRECT_IPV4)) {
				/* in case the 2 ecom present,
				 * overwrite simpson draft
				 * update redirect ip fields
				 */
				if (api_action_redirect_ip) {
					memcpy(&(api_action_redirect_ip->u
						 .zr.redirect_ip_v4.s_addr),
					       (ecom_eval->val+2), 4);
					api_action_redirect_ip->u
						.zr.duplicate =
						ecom_eval->val[7];
					continue;
				} else {
					api_action->action = ACTION_REDIRECT_IP;
					memcpy(&(api_action->u
						 .zr.redirect_ip_v4.s_addr),
					       (ecom_eval->val+2), 4);
					api_action->u.zr.duplicate =
						ecom_eval->val[7];
					api_action_redirect_ip = api_action;
				}
			} else {
				if (ecom_eval->val[0] !=
				    (char)ECOMMUNITY_ENCODE_TRANS_EXP)
					continue;
				ret = ecommunity_fill_pbr_action(ecom_eval,
								 api_action,
								 afi);
				if (ret != 0)
					continue;
				if ((api_action->action == ACTION_TRAFFICRATE)
				    && api->actions[i].u.r.rate == 0)
					discard_action_found = true;
			}
			api->action_num++;
		}
	}
	if (path && path->attr && bgp_attr_get_ipv6_ecommunity(path->attr)) {
		struct ecommunity_val_ipv6 *ipv6_ecom_eval;

		ecom = bgp_attr_get_ipv6_ecommunity(path->attr);
		for (i = 0; i < ecom->size; i++) {
			ipv6_ecom_eval = (struct ecommunity_val_ipv6 *)
				(ecom->val + (i * ecom->unit_size));
			action_count++;
			if (action_count > ACTIONS_MAX_NUM) {
				if (BGP_DEBUG(pbr, PBR_ERROR))
					flog_err(
						EC_BGP_FLOWSPEC_PACKET,
						"%s: flowspec actions exceeds limit (max %u)",
						__func__, action_count);
				break;
			}
			api_action = &api->actions[action_count - 1];
			if ((ipv6_ecom_eval->val[1] ==
			     (char)ECOMMUNITY_FLOWSPEC_REDIRECT_IPV6) &&
			    (ipv6_ecom_eval->val[0] ==
			     (char)ECOMMUNITY_ENCODE_TRANS_EXP)) {
				struct ecommunity *eckey = ecommunity_new();
				struct ecommunity_val_ipv6 ecom_copy;

				eckey->unit_size = IPV6_ECOMMUNITY_SIZE;
				memcpy(&ecom_copy, ipv6_ecom_eval,
				       sizeof(struct ecommunity_val_ipv6));
				ecom_copy.val[1] = ECOMMUNITY_ROUTE_TARGET;
				ecommunity_add_val_ipv6(eckey, &ecom_copy,
							false, false);
				api_action->action = ACTION_REDIRECT;
				api_action->u.redirect_vrf =
					get_first_vrf_for_redirect_with_rt(
								eckey);
				ecommunity_free(&eckey);
				api->action_num++;
			}
		}
	}
	/* if ECOMMUNITY_TRAFFIC_RATE = 0 as action
	 * then reduce the API action list to that action
	 */
	if (api->action_num > 1 && discard_action_found) {
		api->action_num = 1;
		memset(&api->actions[0], 0,
		       sizeof(struct bgp_pbr_entry_action));
		api->actions[0].action = ACTION_TRAFFICRATE;
	}

	/* validate if incoming matc/action is compatible
	 * with our policy routing engine
	 */
	if (!bgp_pbr_validate_policy_route(api))
		return -1;

	/* check inconsistency in the match rule */
	if (api->match_bitmask & PREFIX_SRC_PRESENT) {
		src = &api->src_prefix;
		afi = family2afi(src->family);
		valid_prefix = 1;
	}
	if (api->match_bitmask & PREFIX_DST_PRESENT) {
		dst = &api->dst_prefix;
		if (valid_prefix && afi != family2afi(dst->family)) {
			if (BGP_DEBUG(pbr, PBR)) {
				bgp_pbr_print_policy_route(api);
				zlog_debug("%s: inconsistency: no match for afi src and dst (%u/%u)",
				     __func__, afi, family2afi(dst->family));
			}
			return -1;
		}
	}
	return 0;
}

static void bgp_pbr_match_entry_free(void *arg)
{
	struct bgp_pbr_match_entry *bpme;

	bpme = (struct bgp_pbr_match_entry *)arg;

	if (bpme->installed) {
		bgp_send_pbr_ipset_entry_match(bpme, false);
		bpme->installed = false;
		bpme->backpointer = NULL;
	}
	XFREE(MTYPE_PBR_MATCH_ENTRY, bpme);
}

static void bgp_pbr_match_free(void *arg)
{
	struct bgp_pbr_match *bpm;

	bpm = (struct bgp_pbr_match *)arg;

	hash_clean(bpm->entry_hash, bgp_pbr_match_entry_free);

	if (hashcount(bpm->entry_hash) == 0) {
		/* delete iptable entry first */
		/* then delete ipset match */
		if (bpm->installed) {
			if (bpm->installed_in_iptable) {
				bgp_send_pbr_iptable(bpm->action,
						     bpm, false);
				bpm->installed_in_iptable = false;
				bpm->action->refcnt--;
			}
			bgp_send_pbr_ipset_match(bpm, false);
			bpm->installed = false;
			bpm->action = NULL;
		}
	}
	hash_clean_and_free(&bpm->entry_hash, NULL);

	XFREE(MTYPE_PBR_MATCH, bpm);
}

static void *bgp_pbr_match_alloc_intern(void *arg)
{
	struct bgp_pbr_match *bpm, *new;

	bpm = (struct bgp_pbr_match *)arg;

	new = XCALLOC(MTYPE_PBR_MATCH, sizeof(*new));
	memcpy(new, bpm, sizeof(*bpm));

	return new;
}

static void bgp_pbr_rule_free(void *arg)
{
	struct bgp_pbr_rule *bpr;

	bpr = (struct bgp_pbr_rule *)arg;

	/* delete iprule */
	if (bpr->installed) {
		bgp_send_pbr_rule_action(bpr->action, bpr, false);
		bpr->installed = false;
		bpr->action->refcnt--;
		bpr->action = NULL;
	}
	XFREE(MTYPE_PBR_RULE, bpr);
}

static void *bgp_pbr_rule_alloc_intern(void *arg)
{
	struct bgp_pbr_rule *bpr, *new;

	bpr = (struct bgp_pbr_rule *)arg;

	new = XCALLOC(MTYPE_PBR_RULE, sizeof(*new));
	memcpy(new, bpr, sizeof(*bpr));

	return new;
}

static void bgp_pbr_bpa_remove(struct bgp_pbr_action *bpa)
{
	if ((bpa->refcnt == 0) && bpa->installed && bpa->table_id != 0) {
		bgp_send_pbr_rule_action(bpa, NULL, false);
		bgp_zebra_announce_default(bpa->bgp, &bpa->nh, bpa->afi,
					   bpa->table_id, false);
		bpa->installed = false;
	}
}

static void bgp_pbr_bpa_add(struct bgp_pbr_action *bpa)
{
	if (!bpa->installed && !bpa->install_in_progress) {
		bgp_send_pbr_rule_action(bpa, NULL, true);
		bgp_zebra_announce_default(bpa->bgp, &bpa->nh, bpa->afi,
					   bpa->table_id, true);
	}
}

static void bgp_pbr_action_free(void *arg)
{
	struct bgp_pbr_action *bpa = arg;

	bgp_pbr_bpa_remove(bpa);

	XFREE(MTYPE_PBR_ACTION, bpa);
}

static void *bgp_pbr_action_alloc_intern(void *arg)
{
	struct bgp_pbr_action *bpa, *new;

	bpa = (struct bgp_pbr_action *)arg;

	new = XCALLOC(MTYPE_PBR_ACTION, sizeof(*new));

	memcpy(new, bpa, sizeof(*bpa));

	return new;
}

static void *bgp_pbr_match_entry_alloc_intern(void *arg)
{
	struct bgp_pbr_match_entry *bpme, *new;

	bpme = (struct bgp_pbr_match_entry *)arg;

	new = XCALLOC(MTYPE_PBR_MATCH_ENTRY, sizeof(*new));

	memcpy(new, bpme, sizeof(*bpme));

	return new;
}

uint32_t bgp_pbr_match_hash_key(const void *arg)
{
	const struct bgp_pbr_match *pbm = arg;
	uint32_t key;

	key = jhash_1word(pbm->vrf_id, 0x4312abde);
	key = jhash_1word(pbm->flags, key);
	key = jhash_1word(pbm->family, key);
	key = jhash(&pbm->pkt_len_min, 2, key);
	key = jhash(&pbm->pkt_len_max, 2, key);
	key = jhash(&pbm->tcp_flags, 2, key);
	key = jhash(&pbm->tcp_mask_flags, 2, key);
	key = jhash(&pbm->dscp_value, 1, key);
	key = jhash(&pbm->flow_label, 2, key);
	key = jhash(&pbm->fragment, 1, key);
	key = jhash(&pbm->protocol, 1, key);
	return jhash_1word(pbm->type, key);
}

bool bgp_pbr_match_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_match *r1, *r2;

	r1 = (const struct bgp_pbr_match *)arg1;
	r2 = (const struct bgp_pbr_match *)arg2;

	if (r1->vrf_id != r2->vrf_id)
		return false;

	if (r1->family != r2->family)
		return false;

	if (r1->type != r2->type)
		return false;

	if (r1->flags != r2->flags)
		return false;

	if (r1->action != r2->action)
		return false;

	if (r1->pkt_len_min != r2->pkt_len_min)
		return false;

	if (r1->pkt_len_max != r2->pkt_len_max)
		return false;

	if (r1->tcp_flags != r2->tcp_flags)
		return false;

	if (r1->tcp_mask_flags != r2->tcp_mask_flags)
		return false;

	if (r1->dscp_value != r2->dscp_value)
		return false;

	if (r1->flow_label != r2->flow_label)
		return false;

	if (r1->fragment != r2->fragment)
		return false;

	if (r1->protocol != r2->protocol)
		return false;
	return true;
}

uint32_t bgp_pbr_rule_hash_key(const void *arg)
{
	const struct bgp_pbr_rule *pbr = arg;
	uint32_t key;

	key = prefix_hash_key(&pbr->src);
	key = jhash_1word(pbr->vrf_id, key);
	key = jhash_1word(pbr->flags, key);
	return jhash_1word(prefix_hash_key(&pbr->dst), key);
}

bool bgp_pbr_rule_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_rule *r1, *r2;

	r1 = (const struct bgp_pbr_rule *)arg1;
	r2 = (const struct bgp_pbr_rule *)arg2;

	if (r1->vrf_id != r2->vrf_id)
		return false;

	if (r1->flags != r2->flags)
		return false;

	if (r1->action != r2->action)
		return false;

	if ((r1->flags & MATCH_IP_SRC_SET) &&
	    !prefix_same(&r1->src, &r2->src))
		return false;

	if ((r1->flags & MATCH_IP_DST_SET) &&
	    !prefix_same(&r1->dst, &r2->dst))
		return false;

	return true;
}

uint32_t bgp_pbr_match_entry_hash_key(const void *arg)
{
	const struct bgp_pbr_match_entry *pbme;
	uint32_t key;

	pbme = arg;
	key = prefix_hash_key(&pbme->src);
	key = jhash_1word(prefix_hash_key(&pbme->dst), key);
	key = jhash(&pbme->dst_port_min, 2, key);
	key = jhash(&pbme->src_port_min, 2, key);
	key = jhash(&pbme->dst_port_max, 2, key);
	key = jhash(&pbme->src_port_max, 2, key);
	key = jhash(&pbme->proto, 1, key);

	return key;
}

bool bgp_pbr_match_entry_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_match_entry *r1, *r2;

	r1 = (const struct bgp_pbr_match_entry *)arg1;
	r2 = (const struct bgp_pbr_match_entry *)arg2;

	/*
	 * on updates, comparing backpointer is not necessary
	 * unique value is self calculated
	 * rate is ignored for now
	 */

	if (!prefix_same(&r1->src, &r2->src))
		return false;

	if (!prefix_same(&r1->dst, &r2->dst))
		return false;

	if (r1->src_port_min != r2->src_port_min)
		return false;

	if (r1->dst_port_min != r2->dst_port_min)
		return false;

	if (r1->src_port_max != r2->src_port_max)
		return false;

	if (r1->dst_port_max != r2->dst_port_max)
		return false;

	if (r1->proto != r2->proto)
		return false;

	return true;
}

uint32_t bgp_pbr_action_hash_key(const void *arg)
{
	const struct bgp_pbr_action *pbra;
	uint32_t key;

	pbra = arg;
	key = jhash_1word(pbra->table_id, 0x4312abde);
	key = jhash_1word(pbra->fwmark, key);
	key = jhash_1word(pbra->afi, key);
	return key;
}

bool bgp_pbr_action_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_action *r1, *r2;

	r1 = (const struct bgp_pbr_action *)arg1;
	r2 = (const struct bgp_pbr_action *)arg2;

	/* unique value is self calculated
	 * table and fwmark is self calculated
	 * rate is ignored
	 */
	if (r1->vrf_id != r2->vrf_id)
		return false;

	if (r1->afi != r2->afi)
		return false;

	return nexthop_same(&r1->nh, &r2->nh);
}

struct bgp_pbr_rule *bgp_pbr_rule_lookup(vrf_id_t vrf_id,
					 uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_rule_unique bpru;

	if (!bgp || unique == 0)
		return NULL;
	bpru.unique = unique;
	bpru.bpr_found = NULL;
	hash_walk(bgp->pbr_rule_hash, bgp_pbr_rule_walkcb, &bpru);
	return bpru.bpr_found;
}

struct bgp_pbr_action *bgp_pbr_action_rule_lookup(vrf_id_t vrf_id,
						  uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_action_unique bpau;

	if (!bgp || unique == 0)
		return NULL;
	bpau.unique = unique;
	bpau.bpa_found = NULL;
	hash_walk(bgp->pbr_action_hash, bgp_pbr_action_walkcb, &bpau);
	return bpau.bpa_found;
}

struct bgp_pbr_match *bgp_pbr_match_ipset_lookup(vrf_id_t vrf_id,
						 uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_match_unique bpmu;

	if (!bgp || unique == 0)
		return NULL;
	bpmu.unique = unique;
	bpmu.bpm_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_match_walkcb, &bpmu);
	return bpmu.bpm_found;
}

struct bgp_pbr_match_entry *bgp_pbr_match_ipset_entry_lookup(vrf_id_t vrf_id,
						       char *ipset_name,
						       uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_match_entry_unique bpmeu;
	struct bgp_pbr_match_ipsetname bpmi;

	if (!bgp || unique == 0)
		return NULL;
	bpmi.ipsetname = XCALLOC(MTYPE_TMP, ZEBRA_IPSET_NAME_SIZE);
	snprintf(bpmi.ipsetname, ZEBRA_IPSET_NAME_SIZE, "%s", ipset_name);
	bpmi.bpm_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_match_pername_walkcb, &bpmi);
	XFREE(MTYPE_TMP, bpmi.ipsetname);
	if (!bpmi.bpm_found)
		return NULL;
	bpmeu.bpme_found = NULL;
	bpmeu.unique = unique;
	hash_walk(bpmi.bpm_found->entry_hash,
		  bgp_pbr_match_entry_walkcb, &bpmeu);
	return bpmeu.bpme_found;
}

struct bgp_pbr_match *bgp_pbr_match_iptable_lookup(vrf_id_t vrf_id,
						   uint32_t unique)
{
	struct bgp *bgp = bgp_lookup_by_vrf_id(vrf_id);
	struct bgp_pbr_match_iptable_unique bpmiu;

	if (!bgp || unique == 0)
		return NULL;
	bpmiu.unique = unique;
	bpmiu.bpm_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_match_iptable_walkcb, &bpmiu);
	return bpmiu.bpm_found;
}

void bgp_pbr_cleanup(struct bgp *bgp)
{
	hash_clean_and_free(&bgp->pbr_match_hash, bgp_pbr_match_free);
	hash_clean_and_free(&bgp->pbr_rule_hash, bgp_pbr_rule_free);
	hash_clean_and_free(&bgp->pbr_action_hash, bgp_pbr_action_free);

	if (bgp->bgp_pbr_cfg == NULL)
		return;

	bgp_pbr_reset(bgp, AFI_IP);
	bgp_pbr_reset(bgp, AFI_IP6);
	XFREE(MTYPE_PBR, bgp->bgp_pbr_cfg);
}

void bgp_pbr_init(struct bgp *bgp)
{
	bgp->pbr_match_hash =
		hash_create_size(8, bgp_pbr_match_hash_key,
				 bgp_pbr_match_hash_equal,
				 "Match Hash");
	bgp->pbr_action_hash =
		hash_create_size(8, bgp_pbr_action_hash_key,
				 bgp_pbr_action_hash_equal,
				 "Match Hash Entry");

	bgp->pbr_rule_hash =
		hash_create_size(8, bgp_pbr_rule_hash_key,
				 bgp_pbr_rule_hash_equal,
				 "Match Rule");

	bgp->bgp_pbr_cfg = XCALLOC(MTYPE_PBR, sizeof(struct bgp_pbr_config));
	bgp->bgp_pbr_cfg->pbr_interface_any_ipv4 = true;
}

void bgp_pbr_print_policy_route(struct bgp_pbr_entry_main *api)
{
	int i = 0;
	char return_string[512];
	char *ptr = return_string;
	int nb_items = 0;
	int delta, len = sizeof(return_string);

	delta = snprintf(ptr, sizeof(return_string),  "MATCH : ");
	len -= delta;
	ptr += delta;
	if (api->match_bitmask & PREFIX_SRC_PRESENT) {
		struct prefix *p = &(api->src_prefix);

		if (api->src_prefix_offset)
			delta = snprintfrr(ptr, len, "@src %pFX/off%u", p,
					   api->src_prefix_offset);
		else
			delta = snprintfrr(ptr, len, "@src %pFX", p);
		len -= delta;
		ptr += delta;
		INCREMENT_DISPLAY(ptr, nb_items, len);
	}
	if (api->match_bitmask & PREFIX_DST_PRESENT) {
		struct prefix *p = &(api->dst_prefix);

		INCREMENT_DISPLAY(ptr, nb_items, len);
		if (api->dst_prefix_offset)
			delta = snprintfrr(ptr, len, "@dst %pFX/off%u", p,
					   api->dst_prefix_offset);
		else
			delta = snprintfrr(ptr, len, "@dst %pFX", p);
		len -= delta;
		ptr += delta;
	}

	if (api->match_protocol_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_protocol_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->protocol[i],
						   i > 0 ? NULL : "@proto ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_src_port_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_src_port_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->src_port[i],
						   i > 0 ? NULL : "@srcport ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_dst_port_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_dst_port_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->dst_port[i],
						   i > 0 ? NULL : "@dstport ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_port_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_port_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->port[i],
						   i > 0 ? NULL : "@port ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_icmp_type_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_icmp_type_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->icmp_type[i],
						   i > 0 ? NULL : "@icmptype ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_icmp_code_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_icmp_code_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->icmp_code[i],
						   i > 0 ? NULL : "@icmpcode ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_packet_length_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_packet_length_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len,
						   &api->packet_length[i],
						   i > 0 ? NULL : "@plen ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_dscp_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_dscp_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->dscp[i],
						   i > 0 ? NULL : "@dscp ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_flowlabel_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_flowlabel_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len,
						  &api->flow_label[i],
						  i > 0 ? NULL : "@flowlabel ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_tcpflags_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_tcpflags_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->tcpflags[i],
						   i > 0 ? NULL : "@tcpflags ");
		len -= delta;
		ptr += delta;
	}

	if (api->match_fragment_num)
		INCREMENT_DISPLAY(ptr, nb_items, len);
	for (i = 0; i < api->match_fragment_num; i++) {
		delta = snprintf_bgp_pbr_match_val(ptr, len, &api->fragment[i],
						   i > 0 ? NULL : "@fragment ");
		len -= delta;
		ptr += delta;
	}

	len = sizeof(return_string);
	if (!nb_items) {
		ptr = return_string;
	} else {
		len -= (ptr - return_string);
		delta = snprintf(ptr, len, "; ");
		len -= delta;
		ptr += delta;
	}
	if (api->action_num) {
		delta = snprintf(ptr, len, "SET : ");
		len -= delta;
		ptr += delta;
	}
	nb_items = 0;
	for (i = 0; i < api->action_num; i++) {
		switch (api->actions[i].action) {
		case ACTION_TRAFFICRATE:
			INCREMENT_DISPLAY(ptr, nb_items, len);
			delta = snprintf(ptr, len, "@set rate %f",
					api->actions[i].u.r.rate);
			len -= delta;
			ptr += delta;
			break;
		case ACTION_TRAFFIC_ACTION:
			INCREMENT_DISPLAY(ptr, nb_items, len);
			delta = snprintf(ptr, len, "@action ");
			len -= delta;
			ptr += delta;
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_TERMINATE) {
				delta = snprintf(ptr, len,
						 " terminate (apply filter(s))");
				len -= delta;
				ptr += delta;
			}
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_DISTRIBUTE) {
				delta = snprintf(ptr, len, " distribute");
				len -= delta;
				ptr += delta;
			}
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_SAMPLE) {
				delta = snprintf(ptr, len, " sample");
				len -= delta;
				ptr += delta;
			}
			break;
		case ACTION_REDIRECT_IP: {
			char local_buff[INET6_ADDRSTRLEN];
			void *ptr_ip;

			INCREMENT_DISPLAY(ptr, nb_items, len);
			if (api->afi == AF_INET)
				ptr_ip = &api->actions[i].u.zr.redirect_ip_v4;
			else
				ptr_ip = &api->actions[i].u.zr.redirect_ip_v6;
			if (inet_ntop(afi2family(api->afi), ptr_ip, local_buff,
				      sizeof(local_buff)) != NULL) {
				delta = snprintf(ptr, len,
					  "@redirect ip nh %s", local_buff);
				len -= delta;
				ptr += delta;
			}
			break;
		}
		case ACTION_REDIRECT: {
			struct vrf *vrf;

			vrf = vrf_lookup_by_id(api->actions[i].u.redirect_vrf);
			INCREMENT_DISPLAY(ptr, nb_items, len);
			delta = snprintf(ptr, len, "@redirect vrf %s(%u)",
					 VRF_LOGNAME(vrf),
					 api->actions[i].u.redirect_vrf);
			len -= delta;
			ptr += delta;
			break;
		}
		case ACTION_MARKING:
			INCREMENT_DISPLAY(ptr, nb_items, len);
			delta = snprintf(ptr, len, "@set dscp/flowlabel %u",
					 api->actions[i].u.marking_dscp);
			len -= delta;
			ptr += delta;
			break;
		default:
			break;
		}
	}
	zlog_info("%s", return_string);
}

static void bgp_pbr_flush_iprule(struct bgp *bgp, struct bgp_pbr_action *bpa,
				  struct bgp_pbr_rule *bpr)
{
	/* if bpr is null, do nothing
	 */
	if (bpr == NULL)
		return;
	if (bpr->installed) {
		bgp_send_pbr_rule_action(bpa, bpr, false);
		bpr->installed = false;
		bpr->action->refcnt--;
		bpr->action = NULL;
		if (bpr->path) {
			struct bgp_path_info *path;
			struct bgp_path_info_extra *extra;

			/* unlink path to bpme */
			path = (struct bgp_path_info *)bpr->path;
			extra = bgp_path_info_extra_get(path);
			if (extra->bgp_fs_iprule)
				listnode_delete(extra->bgp_fs_iprule, bpr);
			bpr->path = NULL;
		}
	}
	hash_release(bgp->pbr_rule_hash, bpr);
	bgp_pbr_bpa_remove(bpa);
}

static void bgp_pbr_flush_entry(struct bgp *bgp, struct bgp_pbr_action *bpa,
				struct bgp_pbr_match *bpm,
				struct bgp_pbr_match_entry *bpme)
{
	/* if bpme is null, bpm is also null
	 */
	if (bpme == NULL)
		return;
	/* ipset del entry */
	if (bpme->installed) {
		bgp_send_pbr_ipset_entry_match(bpme, false);
		bpme->installed = false;
		bpme->backpointer = NULL;
		if (bpme->path) {
			struct bgp_path_info *path;
			struct bgp_path_info_extra *extra;

			/* unlink path to bpme */
			path = (struct bgp_path_info *)bpme->path;
			extra = bgp_path_info_extra_get(path);
			if (extra->bgp_fs_pbr)
				listnode_delete(extra->bgp_fs_pbr, bpme);
			bpme->path = NULL;
		}
	}
	hash_release(bpm->entry_hash, bpme);
	if (hashcount(bpm->entry_hash) == 0) {
		/* delete iptable entry first */
		/* then delete ipset match */
		if (bpm->installed) {
			if (bpm->installed_in_iptable) {
				bgp_send_pbr_iptable(bpm->action,
						     bpm, false);
				bpm->installed_in_iptable = false;
				bpm->action->refcnt--;
			}
			bgp_send_pbr_ipset_match(bpm, false);
			bpm->installed = false;
			bpm->action = NULL;
		}
		hash_release(bgp->pbr_match_hash, bpm);
		/* XXX release pbr_match_action if not used
		 * note that drop does not need to call send_pbr_action
		 */
	}
	bgp_pbr_bpa_remove(bpa);
}

struct bgp_pbr_match_entry_remain {
	struct bgp_pbr_match_entry *bpme_to_match;
	struct bgp_pbr_match_entry *bpme_found;
};

struct bgp_pbr_rule_remain {
	struct bgp_pbr_rule *bpr_to_match;
	struct bgp_pbr_rule *bpr_found;
};

static int bgp_pbr_get_same_rule(struct hash_bucket *bucket, void *arg)
{
	struct bgp_pbr_rule *r1 = (struct bgp_pbr_rule *)bucket->data;
	struct bgp_pbr_rule_remain *ctxt =
		(struct bgp_pbr_rule_remain *)arg;
	struct bgp_pbr_rule *r2;

	r2 = ctxt->bpr_to_match;

	if (r1->vrf_id != r2->vrf_id)
		return HASHWALK_CONTINUE;

	if (r1->flags != r2->flags)
		return HASHWALK_CONTINUE;

	if ((r1->flags & MATCH_IP_SRC_SET) &&
	    !prefix_same(&r1->src, &r2->src))
		return HASHWALK_CONTINUE;

	if ((r1->flags & MATCH_IP_DST_SET) &&
	    !prefix_same(&r1->dst, &r2->dst))
		return HASHWALK_CONTINUE;

	/* this function is used for two cases:
	 * - remove an entry upon withdraw request
	 * (case r2->action is null)
	 * - replace an old iprule with different action
	 * (case r2->action is != null)
	 * the old one is removed after the new one
	 * this is to avoid disruption in traffic
	 */
	if (r2->action == NULL ||
	    r1->action != r2->action) {
		ctxt->bpr_found = r1;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int bgp_pbr_get_remaining_entry(struct hash_bucket *bucket, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)bucket->data;
	struct bgp_pbr_match_entry_remain *bpmer =
		(struct bgp_pbr_match_entry_remain *)arg;
	struct bgp_pbr_match *bpm_temp;
	struct bgp_pbr_match_entry *bpme = bpmer->bpme_to_match;

	if (!bpme->backpointer ||
	    bpm == bpme->backpointer ||
	    bpme->backpointer->action == bpm->action)
		return HASHWALK_CONTINUE;
	/* ensure bpm other characteristics are equal */
	bpm_temp = bpme->backpointer;
	if (bpm_temp->vrf_id != bpm->vrf_id ||
	    bpm_temp->type != bpm->type ||
	    bpm_temp->flags != bpm->flags ||
	    bpm_temp->tcp_flags != bpm->tcp_flags ||
	    bpm_temp->tcp_mask_flags != bpm->tcp_mask_flags ||
	    bpm_temp->pkt_len_min != bpm->pkt_len_min ||
	    bpm_temp->pkt_len_max != bpm->pkt_len_max ||
	    bpm_temp->dscp_value != bpm->dscp_value ||
	    bpm_temp->flow_label != bpm->flow_label ||
	    bpm_temp->family != bpm->family ||
	    bpm_temp->fragment != bpm->fragment)
		return HASHWALK_CONTINUE;

	/* look for remaining bpme */
	bpmer->bpme_found = hash_lookup(bpm->entry_hash, bpme);
	if (!bpmer->bpme_found)
		return HASHWALK_CONTINUE;
	return HASHWALK_ABORT;
}

static void bgp_pbr_policyroute_remove_from_zebra_unit(
	struct bgp *bgp, struct bgp_path_info *path, struct bgp_pbr_filter *bpf)
{
	struct bgp_pbr_match temp;
	struct bgp_pbr_match_entry temp2;
	struct bgp_pbr_rule pbr_rule;
	struct bgp_pbr_rule *bpr;
	struct bgp_pbr_match *bpm;
	struct bgp_pbr_match_entry *bpme;
	struct bgp_pbr_match_entry_remain bpmer;
	struct bgp_pbr_range_port *src_port;
	struct bgp_pbr_range_port *dst_port;
	struct bgp_pbr_range_port *pkt_len;
	struct bgp_pbr_rule_remain bprr;

	if (!bpf)
		return;
	src_port = bpf->src_port;
	dst_port = bpf->dst_port;
	pkt_len = bpf->pkt_len;

	if (BGP_DEBUG(zebra, ZEBRA))
		bgp_pbr_dump_entry(bpf, false);

	/* as we don't know information from EC
	 * look for bpm that have the bpm
	 * with vrf_id characteristics
	 */
	memset(&temp2, 0, sizeof(temp2));
	memset(&temp, 0, sizeof(temp));

	if (bpf->type == BGP_PBR_IPRULE) {
		memset(&pbr_rule, 0, sizeof(pbr_rule));
		pbr_rule.vrf_id = bpf->vrf_id;
		if (bpf->src) {
			prefix_copy(&pbr_rule.src, bpf->src);
			pbr_rule.flags |= MATCH_IP_SRC_SET;
		}
		if (bpf->dst) {
			prefix_copy(&pbr_rule.dst, bpf->dst);
			pbr_rule.flags |= MATCH_IP_DST_SET;
		}
		bpr = &pbr_rule;
		/* A previous entry may already exist
		 * flush previous entry if necessary
		 */
		bprr.bpr_to_match = bpr;
		bprr.bpr_found = NULL;
		hash_walk(bgp->pbr_rule_hash, bgp_pbr_get_same_rule, &bprr);
		if (bprr.bpr_found) {
			static struct bgp_pbr_rule *local_bpr;
			static struct bgp_pbr_action *local_bpa;

			local_bpr = bprr.bpr_found;
			local_bpa = local_bpr->action;
			bgp_pbr_flush_iprule(bgp, local_bpa,
					     local_bpr);
		}
		return;
	}

	temp.family = bpf->family;
	if (bpf->src) {
		temp.flags |= MATCH_IP_SRC_SET;
		prefix_copy(&temp2.src, bpf->src);
	} else
		temp2.src.family = bpf->family;
	if (bpf->dst) {
		temp.flags |= MATCH_IP_DST_SET;
		prefix_copy(&temp2.dst, bpf->dst);
	} else
		temp2.dst.family = bpf->family;
	if (src_port && (src_port->min_port || bpf->protocol == IPPROTO_ICMP)) {
		if (bpf->protocol == IPPROTO_ICMP)
			temp.flags |= MATCH_ICMP_SET;
		temp.flags |= MATCH_PORT_SRC_SET;
		temp2.src_port_min = src_port->min_port;
		if (src_port->max_port) {
			temp.flags |= MATCH_PORT_SRC_RANGE_SET;
			temp2.src_port_max = src_port->max_port;
		}
	}
	if (dst_port && (dst_port->min_port || bpf->protocol == IPPROTO_ICMP)) {
		if (bpf->protocol == IPPROTO_ICMP)
			temp.flags |= MATCH_ICMP_SET;
		temp.flags |= MATCH_PORT_DST_SET;
		temp2.dst_port_min = dst_port->min_port;
		if (dst_port->max_port) {
			temp.flags |= MATCH_PORT_DST_RANGE_SET;
			temp2.dst_port_max = dst_port->max_port;
		}
	}
	temp2.proto = bpf->protocol;

	if (pkt_len) {
		temp.pkt_len_min = pkt_len->min_port;
		if (pkt_len->max_port)
			temp.pkt_len_max = pkt_len->max_port;
	} else if (bpf->pkt_len_val) {
		if (bpf->pkt_len_val->mask)
			temp.flags |= MATCH_PKT_LEN_INVERSE_SET;
		temp.pkt_len_min = bpf->pkt_len_val->val;
	}
	if (bpf->tcp_flags) {
		temp.tcp_flags = bpf->tcp_flags->val;
		temp.tcp_mask_flags = bpf->tcp_flags->mask;
	}
	if (bpf->dscp) {
		if (bpf->dscp->mask)
			temp.flags |= MATCH_DSCP_INVERSE_SET;
		else
			temp.flags |= MATCH_DSCP_SET;
		temp.dscp_value = bpf->dscp->val;
	}
	if (bpf->flow_label) {
		if (bpf->flow_label->mask)
			temp.flags |= MATCH_FLOW_LABEL_INVERSE_SET;
		else
			temp.flags |= MATCH_FLOW_LABEL_SET;
		temp.flow_label = bpf->flow_label->val;
	}

	if (bpf->fragment) {
		if (bpf->fragment->mask)
			temp.flags |= MATCH_FRAGMENT_INVERSE_SET;
		temp.fragment = bpf->fragment->val;
	}

	if (bpf->src == NULL || bpf->dst == NULL) {
		if (temp.flags & (MATCH_PORT_DST_SET | MATCH_PORT_SRC_SET))
			temp.type = IPSET_NET_PORT;
		else
			temp.type = IPSET_NET;
	} else {
		if (temp.flags & (MATCH_PORT_DST_SET | MATCH_PORT_SRC_SET))
			temp.type = IPSET_NET_PORT_NET;
		else
			temp.type = IPSET_NET_NET;
	}
	if (bpf->vrf_id == VRF_UNKNOWN) /* XXX case BGP destroy */
		temp.vrf_id = VRF_DEFAULT;
	else
		temp.vrf_id = bpf->vrf_id;
	bpme = &temp2;
	bpm = &temp;
	bpme->backpointer = bpm;
	/* right now, a previous entry may already exist
	 * flush previous entry if necessary
	 */
	bpmer.bpme_to_match = bpme;
	bpmer.bpme_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_get_remaining_entry, &bpmer);
	if (bpmer.bpme_found) {
		static struct bgp_pbr_match *local_bpm;
		static struct bgp_pbr_action *local_bpa;

		local_bpm = bpmer.bpme_found->backpointer;
		local_bpa = local_bpm->action;
		bgp_pbr_flush_entry(bgp, local_bpa,
				    local_bpm, bpmer.bpme_found);
	}
}

static uint8_t bgp_pbr_next_type_entry(uint8_t type_entry)
{
	if (type_entry == FLOWSPEC_TCP_FLAGS)
		return FLOWSPEC_DSCP;
	if (type_entry == FLOWSPEC_DSCP)
		return FLOWSPEC_FLOW_LABEL;
	if (type_entry == FLOWSPEC_FLOW_LABEL)
		return FLOWSPEC_PKT_LEN;
	if (type_entry == FLOWSPEC_PKT_LEN)
		return FLOWSPEC_FRAGMENT;
	if (type_entry == FLOWSPEC_FRAGMENT)
		return FLOWSPEC_ICMP_TYPE;
	return 0;
}

static void bgp_pbr_icmp_action(struct bgp *bgp, struct bgp_path_info *path,
				struct bgp_pbr_filter *bpf,
				struct bgp_pbr_or_filter *bpof, bool add,
				struct nexthop *nh, float *rate)
{
	struct bgp_pbr_range_port srcp, dstp;
	struct bgp_pbr_val_mask *icmp_type, *icmp_code;
	struct listnode *tnode, *cnode;

	if (!bpf)
		return;
	if (bpf->protocol != IPPROTO_ICMP)
		return;

	memset(&srcp, 0, sizeof(srcp));
	memset(&dstp, 0, sizeof(dstp));
	bpf->src_port = &srcp;
	bpf->dst_port = &dstp;
	/* parse icmp type and lookup appropriate icmp code
	 * if no icmp code found, create as many entryes as
	 * there are listed icmp codes for that icmp type
	 */
	if (!bpof->icmp_type) {
		srcp.min_port = 0;
		srcp.max_port = 255;
		for (ALL_LIST_ELEMENTS_RO(bpof->icmp_code, cnode, icmp_code)) {
			dstp.min_port = icmp_code->val;
			if (add)
				bgp_pbr_policyroute_add_to_zebra_unit(
					bgp, path, bpf, nh, rate);
			else
				bgp_pbr_policyroute_remove_from_zebra_unit(
					bgp, path, bpf);
		}
		return;
	}
	for (ALL_LIST_ELEMENTS_RO(bpof->icmp_type, tnode, icmp_type)) {
		srcp.min_port = icmp_type->val;
		srcp.max_port = 0;
		dstp.max_port = 0;
		/* only icmp type. create an entry only with icmp type */
		if (!bpof->icmp_code) {
			/* icmp type is not one of the above
			 * forge an entry only based on the icmp type
			 */
			dstp.min_port = 0;
			dstp.max_port = 255;
			if (add)
				bgp_pbr_policyroute_add_to_zebra_unit(
					bgp, path, bpf, nh, rate);
			else
				bgp_pbr_policyroute_remove_from_zebra_unit(
					bgp, path, bpf);
			continue;
		}
		for (ALL_LIST_ELEMENTS_RO(bpof->icmp_code, cnode, icmp_code)) {
			dstp.min_port = icmp_code->val;
			if (add)
				bgp_pbr_policyroute_add_to_zebra_unit(
					bgp, path, bpf, nh, rate);
			else
				bgp_pbr_policyroute_remove_from_zebra_unit(
					bgp, path, bpf);
		}
	}

	bpf->src_port = NULL;
	bpf->dst_port = NULL;
}

static void bgp_pbr_policyroute_remove_from_zebra_recursive(
	struct bgp *bgp, struct bgp_path_info *path, struct bgp_pbr_filter *bpf,
	struct bgp_pbr_or_filter *bpof, uint8_t type_entry)
{
	struct listnode *node, *nnode;
	struct bgp_pbr_val_mask *valmask;
	uint8_t next_type_entry;
	struct list *orig_list;
	struct bgp_pbr_val_mask **target_val;

	if (type_entry == 0) {
		bgp_pbr_policyroute_remove_from_zebra_unit(bgp, path, bpf);
		return;
	}
	next_type_entry = bgp_pbr_next_type_entry(type_entry);
	if (type_entry == FLOWSPEC_TCP_FLAGS && bpof->tcpflags) {
		orig_list = bpof->tcpflags;
		target_val = &bpf->tcp_flags;
	} else if (type_entry == FLOWSPEC_DSCP && bpof->dscp) {
		orig_list = bpof->dscp;
		target_val = &bpf->dscp;
	} else if (type_entry == FLOWSPEC_FLOW_LABEL && bpof->flowlabel) {
		orig_list = bpof->flowlabel;
		target_val = &bpf->flow_label;
	} else if (type_entry == FLOWSPEC_PKT_LEN && bpof->pkt_len) {
		orig_list = bpof->pkt_len;
		target_val = &bpf->pkt_len_val;
	} else if (type_entry == FLOWSPEC_FRAGMENT && bpof->fragment) {
		orig_list = bpof->fragment;
		target_val = &bpf->fragment;
	} else if (type_entry == FLOWSPEC_ICMP_TYPE &&
		   (bpof->icmp_type || bpof->icmp_code)) {
		/* enumerate list for icmp - must be last one  */
		bgp_pbr_icmp_action(bgp, path, bpf, bpof, false, NULL, NULL);
		return;
	} else {
		bgp_pbr_policyroute_remove_from_zebra_recursive(
			bgp, path, bpf, bpof, next_type_entry);
		return;
	}
	for (ALL_LIST_ELEMENTS(orig_list, node, nnode, valmask)) {
		*target_val = valmask;
		bgp_pbr_policyroute_remove_from_zebra_recursive(
			bgp, path, bpf, bpof, next_type_entry);
	}
}

static void bgp_pbr_policyroute_remove_from_zebra(
	struct bgp *bgp, struct bgp_path_info *path, struct bgp_pbr_filter *bpf,
	struct bgp_pbr_or_filter *bpof)
{
	if (!bpof) {
		bgp_pbr_policyroute_remove_from_zebra_unit(bgp, path, bpf);
		return;
	}
	if (bpof->tcpflags)
		bgp_pbr_policyroute_remove_from_zebra_recursive(
			bgp, path, bpf, bpof, FLOWSPEC_TCP_FLAGS);
	else if (bpof->dscp)
		bgp_pbr_policyroute_remove_from_zebra_recursive(
			bgp, path, bpf, bpof, FLOWSPEC_DSCP);
	else if (bpof->flowlabel)
		bgp_pbr_policyroute_remove_from_zebra_recursive(
			bgp, path, bpf, bpof, FLOWSPEC_FLOW_LABEL);
	else if (bpof->pkt_len)
		bgp_pbr_policyroute_remove_from_zebra_recursive(
			bgp, path, bpf, bpof, FLOWSPEC_PKT_LEN);
	else if (bpof->fragment)
		bgp_pbr_policyroute_remove_from_zebra_recursive(
			bgp, path, bpf, bpof, FLOWSPEC_FRAGMENT);
	else if (bpof->icmp_type || bpof->icmp_code)
		bgp_pbr_policyroute_remove_from_zebra_recursive(
			bgp, path, bpf, bpof, FLOWSPEC_ICMP_TYPE);
	else
		bgp_pbr_policyroute_remove_from_zebra_unit(bgp, path, bpf);
	/* flush bpof */
	if (bpof->tcpflags)
		list_delete_all_node(bpof->tcpflags);
	if (bpof->dscp)
		list_delete_all_node(bpof->dscp);
	if (bpof->flowlabel)
		list_delete_all_node(bpof->flowlabel);
	if (bpof->pkt_len)
		list_delete_all_node(bpof->pkt_len);
	if (bpof->fragment)
		list_delete_all_node(bpof->fragment);
}

static void bgp_pbr_dump_entry(struct bgp_pbr_filter *bpf, bool add)
{
	struct bgp_pbr_range_port *src_port;
	struct bgp_pbr_range_port *dst_port;
	struct bgp_pbr_range_port *pkt_len;
	char bufsrc[64], bufdst[64];
	char buffer[64];
	int remaining_len = 0;
	char protocol_str[16];

	if (!bpf)
		return;
	src_port = bpf->src_port;
	dst_port = bpf->dst_port;
	pkt_len = bpf->pkt_len;

	protocol_str[0] = '\0';
	if (bpf->tcp_flags && bpf->tcp_flags->mask)
		bpf->protocol = IPPROTO_TCP;
	if (bpf->protocol)
		snprintf(protocol_str, sizeof(protocol_str),
			 "proto %d", bpf->protocol);
	buffer[0] = '\0';
	if (bpf->protocol == IPPROTO_ICMP && src_port && dst_port)
		remaining_len += snprintf(buffer, sizeof(buffer),
					  "type %d, code %d",
					  src_port->min_port,
					  dst_port->min_port);
	else if (bpf->protocol == IPPROTO_UDP ||
		 bpf->protocol == IPPROTO_TCP) {

		if (src_port && src_port->min_port)
			remaining_len += snprintf(buffer,
						  sizeof(buffer),
						  "from [%u:%u]",
						  src_port->min_port,
						  src_port->max_port ?
						  src_port->max_port :
						  src_port->min_port);
		if (dst_port && dst_port->min_port)
			remaining_len += snprintf(buffer +
						  remaining_len,
						  sizeof(buffer)
						  - remaining_len,
						  "to [%u:%u]",
						  dst_port->min_port,
						  dst_port->max_port ?
						  dst_port->max_port :
						  dst_port->min_port);
	}
	if (pkt_len && (pkt_len->min_port || pkt_len->max_port)) {
		remaining_len += snprintf(buffer + remaining_len,
					  sizeof(buffer)
					  - remaining_len,
					  " len [%u:%u]",
					  pkt_len->min_port,
					  pkt_len->max_port ?
					  pkt_len->max_port :
					  pkt_len->min_port);
	} else if (bpf->pkt_len_val) {
		remaining_len += snprintf(buffer + remaining_len,
					  sizeof(buffer)
					  - remaining_len,
					  " %s len %u",
					  bpf->pkt_len_val->mask
					  ? "!" : "",
					  bpf->pkt_len_val->val);
	}
	if (bpf->tcp_flags) {
		remaining_len += snprintf(buffer + remaining_len,
					  sizeof(buffer)
					  - remaining_len,
					  "tcpflags %x/%x",
					  bpf->tcp_flags->val,
					  bpf->tcp_flags->mask);
	}
	if (bpf->dscp) {
		snprintf(buffer + remaining_len,
			 sizeof(buffer)
			 - remaining_len,
			 "%s dscp %d",
			 bpf->dscp->mask
			 ? "!" : "",
			 bpf->dscp->val);
	}
	if (bpf->flow_label) {
		snprintf(buffer + remaining_len,
			 sizeof(buffer)
			 - remaining_len,
			 "%s flow_label %d",
			 bpf->flow_label->mask
			 ? "!" : "",
			 bpf->flow_label->val);
	}
	zlog_debug("BGP: %s FS PBR from %s to %s, %s %s",
		  add ? "adding" : "removing",
		  bpf->src == NULL ? "<all>" :
		  prefix2str(bpf->src, bufsrc, sizeof(bufsrc)),
		  bpf->dst == NULL ? "<all>" :
		  prefix2str(bpf->dst, bufdst, sizeof(bufdst)),
		  protocol_str, buffer);

}

static void bgp_pbr_policyroute_add_to_zebra_unit(struct bgp *bgp,
						  struct bgp_path_info *path,
						  struct bgp_pbr_filter *bpf,
						  struct nexthop *nh,
						  float *rate)
{
	struct bgp_pbr_match temp;
	struct bgp_pbr_match_entry temp2;
	struct bgp_pbr_match *bpm;
	struct bgp_pbr_match_entry *bpme = NULL;
	struct bgp_pbr_action temp3;
	struct bgp_pbr_action *bpa = NULL;
	struct bgp_pbr_match_entry_remain bpmer;
	struct bgp_pbr_rule_remain bprr;
	struct bgp_pbr_range_port *src_port;
	struct bgp_pbr_range_port *dst_port;
	struct bgp_pbr_range_port *pkt_len;
	struct bgp_pbr_rule pbr_rule;
	struct bgp_pbr_rule *bpr;
	bool bpr_found = false;
	bool bpme_found = false;
	struct vrf *vrf = NULL;

	if (!bpf)
		return;
	src_port = bpf->src_port;
	dst_port = bpf->dst_port;
	pkt_len = bpf->pkt_len;

	if (BGP_DEBUG(zebra, ZEBRA))
		bgp_pbr_dump_entry(bpf, true);

	/* look for bpa first */
	memset(&temp3, 0, sizeof(temp3));
	if (rate)
		temp3.rate = *rate;
	if (nh)
		memcpy(&temp3.nh, nh, sizeof(struct nexthop));
	temp3.vrf_id = bpf->vrf_id;
	temp3.afi = family2afi(bpf->family);
	bpa = hash_get(bgp->pbr_action_hash, &temp3,
		       bgp_pbr_action_alloc_intern);

	if (nh)
		vrf = vrf_lookup_by_id(nh->vrf_id);
	if (bpa->fwmark == 0) {
		/* drop is handled by iptable */
		if (nh && nh->type == NEXTHOP_TYPE_BLACKHOLE) {
			bpa->table_id = 0;
			bpa->installed = true;
		} else {
			bpa->fwmark = bgp_zebra_tm_get_id();
			/* if action is redirect-vrf, then
			 * use directly table_id of vrf
			 */
			if (nh && vrf && !vrf_is_backend_netns()
			    && bpf->vrf_id != vrf->vrf_id)
				bpa->table_id = vrf->data.l.table_id;
			else
				bpa->table_id = bpa->fwmark;
			bpa->installed = false;
		}
		bpa->bgp = bgp;
		bpa->unique = ++bgp_pbr_action_counter_unique;
		/* 0 value is forbidden */
		bpa->install_in_progress = false;
	}
	if (bpf->type == BGP_PBR_IPRULE) {
		memset(&pbr_rule, 0, sizeof(pbr_rule));
		pbr_rule.vrf_id = bpf->vrf_id;
		pbr_rule.priority = 20;
		if (bpf->src) {
			pbr_rule.flags |= MATCH_IP_SRC_SET;
			prefix_copy(&pbr_rule.src, bpf->src);
		}
		if (bpf->dst) {
			pbr_rule.flags |= MATCH_IP_DST_SET;
			prefix_copy(&pbr_rule.dst, bpf->dst);
		}
		pbr_rule.action = bpa;
		bpr = hash_get(bgp->pbr_rule_hash, &pbr_rule,
			       bgp_pbr_rule_alloc_intern);
		if (bpr->unique == 0) {
			bpr->unique = ++bgp_pbr_action_counter_unique;
			bpr->installed = false;
			bpr->install_in_progress = false;
			/* link bgp info to bpr */
			bpr->path = (void *)path;
		} else
			bpr_found = true;
		/* already installed */
		if (bpr_found) {
			struct bgp_path_info_extra *extra =
				bgp_path_info_extra_get(path);

			if (extra &&
			    listnode_lookup_nocheck(extra->bgp_fs_iprule,
						    bpr)) {
				if (BGP_DEBUG(pbr, PBR_ERROR))
					zlog_err("%s: entry %p/%p already installed in bgp pbr iprule",
						 __func__, path, bpr);
				return;
			}
		}

		bgp_pbr_bpa_add(bpa);

		/* ip rule add */
		if (!bpr->installed)
			bgp_send_pbr_rule_action(bpa, bpr, true);

		/* A previous entry may already exist
		 * flush previous entry if necessary
		 */
		bprr.bpr_to_match = bpr;
		bprr.bpr_found = NULL;
		hash_walk(bgp->pbr_rule_hash, bgp_pbr_get_same_rule, &bprr);
		if (bprr.bpr_found) {
			static struct bgp_pbr_rule *local_bpr;
			static struct bgp_pbr_action *local_bpa;

			local_bpr = bprr.bpr_found;
			local_bpa = local_bpr->action;
			bgp_pbr_flush_iprule(bgp, local_bpa,
					     local_bpr);
		}
		return;
	}
	/* then look for bpm */
	memset(&temp, 0, sizeof(temp));
	temp.vrf_id = bpf->vrf_id;
	temp.family = bpf->family;
	if (bpf->src)
		temp.flags |= MATCH_IP_SRC_SET;
	if (bpf->dst)
		temp.flags |= MATCH_IP_DST_SET;

	if (src_port && (src_port->min_port || bpf->protocol == IPPROTO_ICMP)) {
		if (bpf->protocol == IPPROTO_ICMP)
			temp.flags |= MATCH_ICMP_SET;
		temp.flags |= MATCH_PORT_SRC_SET;
	}
	if (dst_port && (dst_port->min_port || bpf->protocol == IPPROTO_ICMP)) {
		if (bpf->protocol == IPPROTO_ICMP)
			temp.flags |= MATCH_ICMP_SET;
		temp.flags |= MATCH_PORT_DST_SET;
	}
	if (src_port && src_port->max_port)
		temp.flags |= MATCH_PORT_SRC_RANGE_SET;
	if (dst_port && dst_port->max_port)
		temp.flags |= MATCH_PORT_DST_RANGE_SET;

	if (bpf->src == NULL || bpf->dst == NULL) {
		if (temp.flags & (MATCH_PORT_DST_SET | MATCH_PORT_SRC_SET))
			temp.type = IPSET_NET_PORT;
		else
			temp.type = IPSET_NET;
	} else {
		if (temp.flags & (MATCH_PORT_DST_SET | MATCH_PORT_SRC_SET))
			temp.type = IPSET_NET_PORT_NET;
		else
			temp.type = IPSET_NET_NET;
	}
	if (pkt_len) {
		temp.pkt_len_min = pkt_len->min_port;
		if (pkt_len->max_port)
			temp.pkt_len_max = pkt_len->max_port;
	} else if (bpf->pkt_len_val) {
		if (bpf->pkt_len_val->mask)
			temp.flags |= MATCH_PKT_LEN_INVERSE_SET;
		temp.pkt_len_min = bpf->pkt_len_val->val;
	}
	if (bpf->tcp_flags) {
		temp.tcp_flags = bpf->tcp_flags->val;
		temp.tcp_mask_flags = bpf->tcp_flags->mask;
	}
	if (bpf->dscp) {
		if (bpf->dscp->mask)
			temp.flags |= MATCH_DSCP_INVERSE_SET;
		else
			temp.flags |= MATCH_DSCP_SET;
		temp.dscp_value = bpf->dscp->val;
	}
	if (bpf->flow_label) {
		if (bpf->flow_label->mask)
			temp.flags |= MATCH_FLOW_LABEL_INVERSE_SET;
		else
			temp.flags |= MATCH_FLOW_LABEL_SET;
		temp.flow_label = bpf->flow_label->val;
	}
	if (bpf->fragment) {
		if (bpf->fragment->mask)
			temp.flags |= MATCH_FRAGMENT_INVERSE_SET;
		temp.fragment = bpf->fragment->val;
	}
	if (bpf->protocol) {
		temp.protocol = bpf->protocol;
		temp.flags |= MATCH_PROTOCOL_SET;
	}
	temp.action = bpa;
	bpm = hash_get(bgp->pbr_match_hash, &temp,
		       bgp_pbr_match_alloc_intern);

	/* new, then self allocate ipset_name and unique */
	if (bpm->unique == 0) {
		bpm->unique = ++bgp_pbr_match_counter_unique;
		/* 0 value is forbidden */
		snprintf(bpm->ipset_name, sizeof(bpm->ipset_name),
			 "match%p", bpm);
		bpm->entry_hash = hash_create_size(8,
				   bgp_pbr_match_entry_hash_key,
				   bgp_pbr_match_entry_hash_equal,
				   "Match Entry Hash");
		bpm->installed = false;

		/* unique2 should be updated too */
		bpm->unique2 = ++bgp_pbr_match_iptable_counter_unique;
		bpm->installed_in_iptable = false;
		bpm->install_in_progress = false;
		bpm->install_iptable_in_progress = false;
	}

	memset(&temp2, 0, sizeof(temp2));
	if (bpf->src)
		prefix_copy(&temp2.src, bpf->src);
	else
		temp2.src.family = bpf->family;
	if (bpf->dst)
		prefix_copy(&temp2.dst, bpf->dst);
	else
		temp2.dst.family = bpf->family;
	temp2.src_port_min = src_port ? src_port->min_port : 0;
	temp2.dst_port_min = dst_port ? dst_port->min_port : 0;
	temp2.src_port_max = src_port ? src_port->max_port : 0;
	temp2.dst_port_max = dst_port ? dst_port->max_port : 0;
	temp2.proto = bpf->protocol;
	bpme = hash_get(bpm->entry_hash, &temp2,
			bgp_pbr_match_entry_alloc_intern);
	if (bpme->unique == 0) {
		bpme->unique = ++bgp_pbr_match_entry_counter_unique;
		/* 0 value is forbidden */
		bpme->backpointer = bpm;
		bpme->installed = false;
		bpme->install_in_progress = false;
		/* link bgp info to bpme */
		bpme->path = (void *)path;
	} else
		bpme_found = true;

	/* already installed */
	if (bpme_found) {
		struct bgp_path_info_extra *extra =
			bgp_path_info_extra_get(path);

		if (extra &&
		    listnode_lookup_nocheck(extra->bgp_fs_pbr, bpme)) {
			if (BGP_DEBUG(pbr, PBR_ERROR))
				zlog_err(
					"%s: entry %p/%p already installed in bgp pbr",
					__func__, path, bpme);
			return;
		}
	}
	/* BGP FS: append entry to zebra
	 * - policies are not routing entries and as such
	 * route replace semantics don't necessarily follow
	 * through to policy entries
	 * - because of that, not all policing information will be stored
	 * into zebra. and non selected policies will be suppressed from zebra
	 * - as consequence, in order to bring consistency
	 * a policy will be added, then ifan ecmp policy exists,
	 * it will be suppressed subsequently
	 */
	/* ip rule add */
	bgp_pbr_bpa_add(bpa);

	/* ipset create */
	if (!bpm->installed)
		bgp_send_pbr_ipset_match(bpm, true);
	/* ipset add */
	if (!bpme->installed)
		bgp_send_pbr_ipset_entry_match(bpme, true);

	/* iptables */
	if (!bpm->installed_in_iptable)
		bgp_send_pbr_iptable(bpa, bpm, true);

	/* A previous entry may already exist
	 * flush previous entry if necessary
	 */
	bpmer.bpme_to_match = bpme;
	bpmer.bpme_found = NULL;
	hash_walk(bgp->pbr_match_hash, bgp_pbr_get_remaining_entry, &bpmer);
	if (bpmer.bpme_found) {
		static struct bgp_pbr_match *local_bpm;
		static struct bgp_pbr_action *local_bpa;

		local_bpm = bpmer.bpme_found->backpointer;
		local_bpa = local_bpm->action;
		bgp_pbr_flush_entry(bgp, local_bpa,
				    local_bpm, bpmer.bpme_found);
	}


}

static void bgp_pbr_policyroute_add_to_zebra_recursive(
	struct bgp *bgp, struct bgp_path_info *path, struct bgp_pbr_filter *bpf,
	struct bgp_pbr_or_filter *bpof, struct nexthop *nh, float *rate,
	uint8_t type_entry)
{
	struct listnode *node, *nnode;
	struct bgp_pbr_val_mask *valmask;
	uint8_t next_type_entry;
	struct list *orig_list;
	struct bgp_pbr_val_mask **target_val;

	if (type_entry == 0) {
		bgp_pbr_policyroute_add_to_zebra_unit(bgp, path, bpf, nh, rate);
		return;
	}
	next_type_entry = bgp_pbr_next_type_entry(type_entry);
	if (type_entry == FLOWSPEC_TCP_FLAGS && bpof->tcpflags) {
		orig_list = bpof->tcpflags;
		target_val = &bpf->tcp_flags;
	} else if (type_entry == FLOWSPEC_DSCP && bpof->dscp) {
		orig_list = bpof->dscp;
		target_val = &bpf->dscp;
	} else if (type_entry == FLOWSPEC_PKT_LEN && bpof->pkt_len) {
		orig_list = bpof->pkt_len;
		target_val = &bpf->pkt_len_val;
	} else if (type_entry == FLOWSPEC_FRAGMENT && bpof->fragment) {
		orig_list = bpof->fragment;
		target_val = &bpf->fragment;
	} else if (type_entry == FLOWSPEC_ICMP_TYPE &&
		   (bpof->icmp_type || bpof->icmp_code)) {
		/* enumerate list for icmp - must be last one  */
		bgp_pbr_icmp_action(bgp, path, bpf, bpof, true, nh, rate);
		return;
	} else {
		bgp_pbr_policyroute_add_to_zebra_recursive(
			bgp, path, bpf, bpof, nh, rate, next_type_entry);
		return;
	}
	for (ALL_LIST_ELEMENTS(orig_list, node, nnode, valmask)) {
		*target_val = valmask;
		bgp_pbr_policyroute_add_to_zebra_recursive(
			bgp, path, bpf, bpof, nh, rate, next_type_entry);
	}
}

static void bgp_pbr_policyroute_add_to_zebra(struct bgp *bgp,
					     struct bgp_path_info *path,
					     struct bgp_pbr_filter *bpf,
					     struct bgp_pbr_or_filter *bpof,
					     struct nexthop *nh, float *rate)
{
	if (!bpof) {
		bgp_pbr_policyroute_add_to_zebra_unit(bgp, path, bpf, nh, rate);
		return;
	}
	if (bpof->tcpflags)
		bgp_pbr_policyroute_add_to_zebra_recursive(
			bgp, path, bpf, bpof, nh, rate, FLOWSPEC_TCP_FLAGS);
	else if (bpof->dscp)
		bgp_pbr_policyroute_add_to_zebra_recursive(
			bgp, path, bpf, bpof, nh, rate, FLOWSPEC_DSCP);
	else if (bpof->pkt_len)
		bgp_pbr_policyroute_add_to_zebra_recursive(
			bgp, path, bpf, bpof, nh, rate, FLOWSPEC_PKT_LEN);
	else if (bpof->fragment)
		bgp_pbr_policyroute_add_to_zebra_recursive(
			bgp, path, bpf, bpof, nh, rate, FLOWSPEC_FRAGMENT);
	else if (bpof->icmp_type || bpof->icmp_code)
		bgp_pbr_policyroute_add_to_zebra_recursive(
			bgp, path, bpf, bpof, nh, rate, FLOWSPEC_ICMP_TYPE);
	else
		bgp_pbr_policyroute_add_to_zebra_unit(bgp, path, bpf, nh, rate);
	/* flush bpof */
	if (bpof->tcpflags)
		list_delete_all_node(bpof->tcpflags);
	if (bpof->dscp)
		list_delete_all_node(bpof->dscp);
	if (bpof->pkt_len)
		list_delete_all_node(bpof->pkt_len);
	if (bpof->fragment)
		list_delete_all_node(bpof->fragment);
	if (bpof->icmp_type)
		list_delete_all_node(bpof->icmp_type);
	if (bpof->icmp_code)
		list_delete_all_node(bpof->icmp_code);
}

static void bgp_pbr_handle_entry(struct bgp *bgp, struct bgp_path_info *path,
				 struct bgp_pbr_entry_main *api, bool add)
{
	struct nexthop nh;
	int i = 0;
	int continue_loop = 1;
	float rate = 0;
	struct prefix *src = NULL, *dst = NULL;
	uint8_t proto = 0;
	struct bgp_pbr_range_port *srcp = NULL, *dstp = NULL;
	struct bgp_pbr_range_port range, range_icmp_code;
	struct bgp_pbr_range_port pkt_len;
	struct bgp_pbr_filter bpf;
	uint8_t kind_enum;
	struct bgp_pbr_or_filter bpof;
	struct bgp_pbr_val_mask bpvm;

	memset(&range, 0, sizeof(range));
	memset(&nh, 0, sizeof(nh));
	memset(&bpf, 0, sizeof(bpf));
	memset(&bpof, 0, sizeof(bpof));
	if (api->match_bitmask & PREFIX_SRC_PRESENT ||
	    (api->type == BGP_PBR_IPRULE &&
	     api->match_bitmask_iprule & PREFIX_SRC_PRESENT))
		src = &api->src_prefix;
	if (api->match_bitmask & PREFIX_DST_PRESENT ||
	    (api->type == BGP_PBR_IPRULE &&
	     api->match_bitmask_iprule & PREFIX_DST_PRESENT))
		dst = &api->dst_prefix;
	if (api->type == BGP_PBR_IPRULE)
		bpf.type = api->type;
	memset(&nh, 0, sizeof(nh));
	nh.vrf_id = VRF_UNKNOWN;
	if (api->match_protocol_num) {
		proto = (uint8_t)api->protocol[0].value;
		if (api->afi == AF_INET6 && proto == IPPROTO_ICMPV6)
			proto = IPPROTO_ICMP;
	}
	/* if match_port is selected, then either src or dst port will be parsed
	 * but not both at the same time
	 */
	if (api->match_port_num >= 1) {
		bgp_pbr_extract(api->port,
				api->match_port_num,
				&range);
		srcp = dstp = &range;
	} else if (api->match_src_port_num >= 1) {
		bgp_pbr_extract(api->src_port,
				api->match_src_port_num,
				&range);
		srcp = &range;
		dstp = NULL;
	} else if (api->match_dst_port_num >= 1) {
		bgp_pbr_extract(api->dst_port,
				api->match_dst_port_num,
				&range);
		dstp = &range;
		srcp = NULL;
	}
	if (api->match_icmp_type_num >= 1) {
		proto = IPPROTO_ICMP;
		if (bgp_pbr_extract(api->icmp_type,
				    api->match_icmp_type_num,
				    &range))
			srcp = &range;
		else {
			bpof.icmp_type = list_new();
			bgp_pbr_extract_enumerate(api->icmp_type,
						  api->match_icmp_type_num,
						  OPERATOR_UNARY_OR,
						  bpof.icmp_type,
						  FLOWSPEC_ICMP_TYPE);
		}
	}
	if (api->match_icmp_code_num >= 1) {
		proto = IPPROTO_ICMP;
		if (bgp_pbr_extract(api->icmp_code,
				    api->match_icmp_code_num,
				    &range_icmp_code))
			dstp = &range_icmp_code;
		else {
			bpof.icmp_code = list_new();
			bgp_pbr_extract_enumerate(api->icmp_code,
						  api->match_icmp_code_num,
						  OPERATOR_UNARY_OR,
						  bpof.icmp_code,
						  FLOWSPEC_ICMP_CODE);
		}
	}

	if (api->match_tcpflags_num) {
		kind_enum = bgp_pbr_match_val_get_operator(api->tcpflags,
						   api->match_tcpflags_num);
		if (kind_enum == OPERATOR_UNARY_AND) {
			bpf.tcp_flags = &bpvm;
			bgp_pbr_extract_enumerate(api->tcpflags,
						  api->match_tcpflags_num,
						  OPERATOR_UNARY_AND,
						  bpf.tcp_flags,
						  FLOWSPEC_TCP_FLAGS);
		} else if (kind_enum == OPERATOR_UNARY_OR) {
			bpof.tcpflags = list_new();
			bgp_pbr_extract_enumerate(api->tcpflags,
						  api->match_tcpflags_num,
						  OPERATOR_UNARY_OR,
						  bpof.tcpflags,
						  FLOWSPEC_TCP_FLAGS);
		}
	}
	if (api->match_packet_length_num) {
		bool ret;

		ret = bgp_pbr_extract(api->packet_length,
				      api->match_packet_length_num,
				      &pkt_len);
		if (ret)
			bpf.pkt_len = &pkt_len;
		else {
			bpof.pkt_len = list_new();
			bgp_pbr_extract_enumerate(api->packet_length,
						  api->match_packet_length_num,
						  OPERATOR_UNARY_OR,
						  bpof.pkt_len,
						  FLOWSPEC_PKT_LEN);
		}
	}
	if (api->match_dscp_num >= 1) {
		bpof.dscp = list_new();
		bgp_pbr_extract_enumerate(api->dscp, api->match_dscp_num,
					  OPERATOR_UNARY_OR,
					  bpof.dscp, FLOWSPEC_DSCP);
	}
	if (api->match_fragment_num) {
		bpof.fragment = list_new();
		bgp_pbr_extract_enumerate(api->fragment,
					  api->match_fragment_num,
					  OPERATOR_UNARY_OR,
					  bpof.fragment,
					  FLOWSPEC_FRAGMENT);
	}
	bpf.vrf_id = api->vrf_id;
	bpf.src = src;
	bpf.dst = dst;
	bpf.protocol = proto;
	bpf.src_port = srcp;
	bpf.dst_port = dstp;
	bpf.family = afi2family(api->afi);
	if (!add) {
		bgp_pbr_policyroute_remove_from_zebra(bgp, path, &bpf, &bpof);
		return;
	}
	/* no action for add = true */
	for (i = 0; i < api->action_num; i++) {
		switch (api->actions[i].action) {
		case ACTION_TRAFFICRATE:
			/* drop packet */
			if (api->actions[i].u.r.rate == 0) {
				nh.vrf_id = api->vrf_id;
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				bgp_pbr_policyroute_add_to_zebra(
					bgp, path, &bpf, &bpof, &nh, &rate);
			} else {
				/* update rate. can be reentrant */
				rate = api->actions[i].u.r.rate;
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_warn("PBR: ignoring Set action rate %f",
						  api->actions[i].u.r.rate);
				}
			}
			break;
		case ACTION_TRAFFIC_ACTION:
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_SAMPLE) {
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_warn("PBR: Sample action Ignored");
				}
			}
			/* terminate action: run other filters
			 */
			break;
		case ACTION_REDIRECT_IP:
			nh.vrf_id = api->vrf_id;
			if (api->afi == AFI_IP) {
				nh.type = NEXTHOP_TYPE_IPV4;
				nh.gate.ipv4.s_addr =
					api->actions[i].u.zr.
					redirect_ip_v4.s_addr;
			} else {
				nh.type = NEXTHOP_TYPE_IPV6;
				memcpy(&nh.gate.ipv6,
				       &api->actions[i].u.zr.redirect_ip_v6,
				       sizeof(struct in6_addr));
			}
			bgp_pbr_policyroute_add_to_zebra(bgp, path, &bpf, &bpof,
							 &nh, &rate);
			/* XXX combination with REDIRECT_VRF
			 * + REDIRECT_NH_IP not done
			 */
			continue_loop = 0;
			break;
		case ACTION_REDIRECT:
			if (api->afi == AFI_IP)
				nh.type = NEXTHOP_TYPE_IPV4;
			else
				nh.type = NEXTHOP_TYPE_IPV6;
			nh.vrf_id = api->actions[i].u.redirect_vrf;
			bgp_pbr_policyroute_add_to_zebra(bgp, path, &bpf, &bpof,
							 &nh, &rate);
			continue_loop = 0;
			break;
		case ACTION_MARKING:
			if (BGP_DEBUG(pbr, PBR)) {
				bgp_pbr_print_policy_route(api);
				zlog_warn("PBR: Set DSCP/FlowLabel %u Ignored",
					  api->actions[i].u.marking_dscp);
			}
			break;
		default:
			break;
		}
		if (continue_loop == 0)
			break;
	}
}

void bgp_pbr_update_entry(struct bgp *bgp, const struct prefix *p,
			  struct bgp_path_info *info, afi_t afi, safi_t safi,
			  bool nlri_update)
{
	struct bgp_pbr_entry_main api;

	if (safi != SAFI_FLOWSPEC)
		return; /* not supported */
	/* Make Zebra API structure. */
	memset(&api, 0, sizeof(api));
	api.vrf_id = bgp->vrf_id;
	api.afi = afi;

	if (!bgp_zebra_tm_chunk_obtained()) {
		if (BGP_DEBUG(pbr, PBR_ERROR))
			flog_err(EC_BGP_TABLE_CHUNK,
				 "%s: table chunk not obtained yet", __func__);
		return;
	}

	if (bgp_pbr_build_and_validate_entry(p, info, &api) < 0) {
		if (BGP_DEBUG(pbr, PBR_ERROR))
			flog_err(EC_BGP_FLOWSPEC_INSTALLATION,
				 "%s: cancel updating entry %p in bgp pbr",
				 __func__, info);
		return;
	}
	bgp_pbr_handle_entry(bgp, info, &api, nlri_update);
}

int bgp_pbr_interface_compare(const struct bgp_pbr_interface *a,
			  const struct bgp_pbr_interface *b)
{
	return strcmp(a->name, b->name);
}

struct bgp_pbr_interface *bgp_pbr_interface_lookup(const char *name,
					   struct bgp_pbr_interface_head *head)
{
	struct bgp_pbr_interface pbr_if;

	strlcpy(pbr_if.name, name, sizeof(pbr_if.name));
	return (RB_FIND(bgp_pbr_interface_head,
			head, &pbr_if));
}

/* this function resets to the default policy routing
 * go back to default status
 */
void bgp_pbr_reset(struct bgp *bgp, afi_t afi)
{
	struct bgp_pbr_config *bgp_pbr_cfg = bgp->bgp_pbr_cfg;
	struct bgp_pbr_interface_head *head;
	struct bgp_pbr_interface *pbr_if;

	if (!bgp_pbr_cfg)
		return;
	if (afi == AFI_IP)
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv4);
	else
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv6);
	while (!RB_EMPTY(bgp_pbr_interface_head, head)) {
		pbr_if = RB_ROOT(bgp_pbr_interface_head, head);
		RB_REMOVE(bgp_pbr_interface_head, head, pbr_if);
		XFREE(MTYPE_TMP, pbr_if);
	}
}
