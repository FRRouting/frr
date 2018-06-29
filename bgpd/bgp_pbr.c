/*
 * BGP pbr
 * Copyright (C) 6WIND
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

#include "zebra.h"
#include "prefix.h"
#include "zclient.h"
#include "jhash.h"
#include "pbr.h"

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

DEFINE_MTYPE_STATIC(BGPD, PBR_MATCH_ENTRY, "PBR match entry")
DEFINE_MTYPE_STATIC(BGPD, PBR_MATCH, "PBR match")
DEFINE_MTYPE_STATIC(BGPD, PBR_ACTION, "PBR action")
DEFINE_MTYPE_STATIC(BGPD, PBR, "BGP PBR Context")
DEFINE_MTYPE_STATIC(BGPD, PBR_VALMASK, "BGP PBR Val Mask Value")

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

static int bgp_pbr_action_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_action *bpa = (struct bgp_pbr_action *)backet->data;
	struct bgp_pbr_action_unique *bpau = (struct bgp_pbr_action_unique *)
		arg;
	uint32_t unique = bpau->unique;

	if (bpa->unique == unique) {
		bpau->bpa_found = bpa;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int bgp_pbr_match_entry_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match_entry *bpme =
		(struct bgp_pbr_match_entry *)backet->data;
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

static int bgp_pbr_match_pername_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)backet->data;
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

static int bgp_pbr_match_iptable_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)backet->data;
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

static int bgp_pbr_match_walkcb(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)backet->data;
	struct bgp_pbr_match_unique *bpmu = (struct bgp_pbr_match_unique *)
		arg;
	uint32_t unique = bpmu->unique;

	if (bpm->unique == unique) {
		bpmu->bpm_found = bpm;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int sprintf_bgp_pbr_match_val(char *str, struct bgp_pbr_match_val *mval,
				     const char *prepend)
{
	char *ptr = str;

	if (prepend)
		ptr += sprintf(ptr, "%s", prepend);
	else {
		if (mval->unary_operator & OPERATOR_UNARY_OR)
			ptr += sprintf(ptr, ", or ");
		if (mval->unary_operator & OPERATOR_UNARY_AND)
			ptr += sprintf(ptr, ", and ");
	}
	if (mval->compare_operator & OPERATOR_COMPARE_LESS_THAN)
		ptr += sprintf(ptr, "<");
	if (mval->compare_operator & OPERATOR_COMPARE_GREATER_THAN)
		ptr += sprintf(ptr, ">");
	if (mval->compare_operator & OPERATOR_COMPARE_EQUAL_TO)
		ptr += sprintf(ptr, "=");
	if (mval->compare_operator & OPERATOR_COMPARE_EXACT_MATCH)
		ptr += sprintf(ptr, "match");
	ptr += sprintf(ptr, " %u", mval->value);
	return (int)(ptr - str);
}

#define INCREMENT_DISPLAY(_ptr, _cnt) do { \
		if (_cnt) \
			(_ptr) += sprintf((_ptr), "; "); \
		_cnt++; \
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
	vrf_id_t vrf_id;
	struct prefix *src;
	struct prefix *dst;
	uint8_t protocol;
	struct bgp_pbr_range_port *pkt_len;
	struct bgp_pbr_range_port *src_port;
	struct bgp_pbr_range_port *dst_port;
	struct bgp_pbr_val_mask *tcp_flags;
	struct bgp_pbr_val_mask *dscp;
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
	struct list *pkt_len;
	struct list *fragment;
	struct list *icmp_type;
	struct list *icmp_code;
};

static void bgp_pbr_policyroute_add_to_zebra_unit(struct bgp *bgp,
						  struct bgp_info *binfo,
						  struct bgp_pbr_filter *bpf,
						  struct nexthop *nh,
						  float *rate);

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
 * other variables type: dscp, pkt len, fragment
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
				if (ret == false)
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
	uint8_t unary_operator_val = unary_operator;
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
		if (exact_match == true && i > 0)
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
			zlog_debug("BGP: match protocol operations:"
				 "multiple protocols ( %d). ignoring.",
				 api->match_protocol_num);
		return 0;
	}
	if (api->match_protocol_num == 1 &&
	    api->protocol[0].value != PROTOCOL_UDP &&
	    api->protocol[0].value != PROTOCOL_ICMP &&
	    api->protocol[0].value != PROTOCOL_TCP) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match protocol operations:"
				   "protocol (%d) not supported. ignoring",
				   api->match_protocol_num);
		return 0;
	}
	if (!bgp_pbr_extract(api->src_port, api->match_src_port_num, NULL)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match src port operations:"
				   "too complex. ignoring.");
		return 0;
	}
	if (!bgp_pbr_extract(api->dst_port, api->match_dst_port_num, NULL)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match dst port operations:"
				   "too complex. ignoring.");
		return 0;
	}
	if (!bgp_pbr_extract_enumerate(api->tcpflags,
				       api->match_tcpflags_num,
				       OPERATOR_UNARY_AND |
				       OPERATOR_UNARY_OR, NULL,
				       FLOWSPEC_TCP_FLAGS)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match tcp flags:"
				   "too complex. ignoring.");
		return 0;
	}
	if (!bgp_pbr_extract(api->icmp_type, api->match_icmp_type_num, NULL)) {
		if (!bgp_pbr_extract_enumerate(api->icmp_type,
					       api->match_icmp_type_num,
					       OPERATOR_UNARY_OR, NULL,
					       FLOWSPEC_ICMP_TYPE)) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match icmp type operations:"
					   "too complex. ignoring.");
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
				zlog_debug("BGP: match icmp code operations:"
					   "too complex. ignoring.");
			return 0;
		} else if (api->match_icmp_type_num > 1 &&
			   enumerate_icmp == false) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match icmp code is enumerate"
					   ", and icmp type is not."
					   " too complex. ignoring.");
			return 0;
		}
	}
	if (!bgp_pbr_extract(api->port, api->match_port_num, NULL)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match port operations:"
				 "too complex. ignoring.");
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
				zlog_debug("BGP: match packet length operations:"
				   "too complex. ignoring.");
			return 0;
		}
	}
	if (api->match_dscp_num) {
		if (!bgp_pbr_extract_enumerate(api->dscp, api->match_dscp_num,
				OPERATOR_UNARY_OR | OPERATOR_UNARY_AND,
					       NULL, FLOWSPEC_DSCP)) {
			if (BGP_DEBUG(pbr, PBR))
				zlog_debug("BGP: match DSCP operations:"
					   "too complex. ignoring.");
			return 0;
		}
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
					sprintf(fail_str,
						"Value not valid (%d) for this implementation",
						api->fragment[i].value);
				}
			}
		} else
			sprintf(fail_str, "too complex. ignoring");
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
			zlog_debug("BGP: match multiple port operations:"
				 " too complex. ignoring.");
		return 0;
	}
	if ((api->match_src_port_num || api->match_dst_port_num
	     || api->match_port_num) && (api->match_icmp_type_num
					 || api->match_icmp_code_num)) {
		if (BGP_DEBUG(pbr, PBR))
			zlog_debug("BGP: match multiple port/imcp operations:"
				 " too complex. ignoring.");
		return 0;
	}
	if (!(api->match_bitmask & PREFIX_SRC_PRESENT) &&
	    !(api->match_bitmask & PREFIX_DST_PRESENT)) {
		if (BGP_DEBUG(pbr, PBR)) {
			bgp_pbr_print_policy_route(api);
			zlog_debug("BGP: match actions without src"
				 " or dst address can not operate."
				 " ignoring.");
		}
		return 0;
	}
	return 1;
}

/* return -1 if build or validation failed */
static int bgp_pbr_build_and_validate_entry(struct prefix *p,
					    struct bgp_info *info,
					    struct bgp_pbr_entry_main *api)
{
	int ret;
	int i, action_count = 0;
	struct ecommunity *ecom;
	struct ecommunity_val *ecom_eval;
	struct bgp_pbr_entry_action *api_action;
	struct prefix *src = NULL, *dst = NULL;
	int valid_prefix = 0;
	afi_t afi = AFI_IP;

	/* extract match from flowspec entries */
	ret = bgp_flowspec_match_rules_fill((uint8_t *)p->u.prefix_flowspec.ptr,
				     p->u.prefix_flowspec.prefixlen, api);
	if (ret < 0)
		return -1;
	/* extract actiosn from flowspec ecom list */
	if (info && info->attr && info->attr->ecommunity) {
		ecom = info->attr->ecommunity;
		for (i = 0; i < ecom->size; i++) {
			ecom_eval = (struct ecommunity_val *)
				(ecom->val + (i * ECOMMUNITY_SIZE));
			action_count++;
			if (action_count > ACTIONS_MAX_NUM) {
				if (BGP_DEBUG(pbr, PBR_ERROR))
					zlog_err("%s: flowspec actions exceeds limit (max %u)",
						 __func__, action_count);
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
				ecommunity_add_val(eckey, &ecom_copy);

				api_action->action = ACTION_REDIRECT;
				api_action->u.redirect_vrf =
					get_first_vrf_for_redirect_with_rt(
								eckey);
				ecommunity_free(&eckey);
			} else if ((ecom_eval->val[0] ==
				    (char)ECOMMUNITY_ENCODE_REDIRECT_IP_NH) &&
				   (ecom_eval->val[1] ==
				    (char)ECOMMUNITY_REDIRECT_IP_NH)) {
				api_action->action = ACTION_REDIRECT_IP;
				api_action->u.zr.redirect_ip_v4.s_addr =
					info->attr->nexthop.s_addr;
				api_action->u.zr.duplicate = ecom_eval->val[7];
			} else {
				if (ecom_eval->val[0] !=
				    (char)ECOMMUNITY_ENCODE_TRANS_EXP)
					continue;
				ret = ecommunity_fill_pbr_action(ecom_eval,
								 api_action);
				if (ret != 0)
					continue;
			}
			api->action_num++;
		}
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
				zlog_debug("%s: inconsistency:"
				     " no match for afi src and dst (%u/%u)",
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
	hash_free(bpm->entry_hash);

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

static void bgp_pbr_action_free(void *arg)
{
	struct bgp_pbr_action *bpa;

	bpa = (struct bgp_pbr_action *)arg;

	if (bpa->refcnt == 0) {
		if (bpa->installed && bpa->table_id != 0) {
			bgp_send_pbr_rule_action(bpa, false);
			bgp_zebra_announce_default(bpa->bgp, &(bpa->nh),
						   AFI_IP,
						   bpa->table_id,
						   false);
			bpa->installed = false;
		}
	}
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

uint32_t bgp_pbr_match_hash_key(void *arg)
{
	struct bgp_pbr_match *pbm = (struct bgp_pbr_match *)arg;
	uint32_t key;

	key = jhash_1word(pbm->vrf_id, 0x4312abde);
	key = jhash_1word(pbm->flags, key);
	key = jhash_1word(pbm->pkt_len_min, key);
	key = jhash_1word(pbm->pkt_len_max, key);
	key = jhash_1word(pbm->tcp_flags, key);
	key = jhash_1word(pbm->tcp_mask_flags, key);
	key = jhash_1word(pbm->dscp_value, key);
	key = jhash_1word(pbm->fragment, key);
	return jhash_1word(pbm->type, key);
}

int bgp_pbr_match_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_match *r1, *r2;

	r1 = (const struct bgp_pbr_match *)arg1;
	r2 = (const struct bgp_pbr_match *)arg2;

	if (r1->vrf_id != r2->vrf_id)
		return 0;

	if (r1->type != r2->type)
		return 0;

	if (r1->flags != r2->flags)
		return 0;

	if (r1->action != r2->action)
		return 0;

	if (r1->pkt_len_min != r2->pkt_len_min)
		return 0;

	if (r1->pkt_len_max != r2->pkt_len_max)
		return 0;

	if (r1->tcp_flags != r2->tcp_flags)
		return 0;

	if (r1->tcp_mask_flags != r2->tcp_mask_flags)
		return 0;

	if (r1->dscp_value != r2->dscp_value)
		return 0;

	if (r1->fragment != r2->fragment)
		return 0;
	return 1;
}

uint32_t bgp_pbr_match_entry_hash_key(void *arg)
{
	struct bgp_pbr_match_entry *pbme;
	uint32_t key;

	pbme = (struct bgp_pbr_match_entry *)arg;
	key = prefix_hash_key(&pbme->src);
	key = jhash_1word(prefix_hash_key(&pbme->dst), key);
	key = jhash(&pbme->dst_port_min, 2, key);
	key = jhash(&pbme->src_port_min, 2, key);
	key = jhash(&pbme->dst_port_max, 2, key);
	key = jhash(&pbme->src_port_max, 2, key);
	key = jhash(&pbme->proto, 1, key);

	return key;
}

int bgp_pbr_match_entry_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_match_entry *r1, *r2;

	r1 = (const struct bgp_pbr_match_entry *)arg1;
	r2 = (const struct bgp_pbr_match_entry *)arg2;

	/* on updates, comparing
	 * backpointer is not necessary
	 */

	/* unique value is self calculated
	 */

	/* rate is ignored for now
	 */

	if (!prefix_same(&r1->src, &r2->src))
		return 0;

	if (!prefix_same(&r1->dst, &r2->dst))
		return 0;

	if (r1->src_port_min != r2->src_port_min)
		return 0;

	if (r1->dst_port_min != r2->dst_port_min)
		return 0;

	if (r1->src_port_max != r2->src_port_max)
		return 0;

	if (r1->dst_port_max != r2->dst_port_max)
		return 0;

	if (r1->proto != r2->proto)
		return 0;

	return 1;
}

uint32_t bgp_pbr_action_hash_key(void *arg)
{
	struct bgp_pbr_action *pbra;
	uint32_t key;

	pbra = (struct bgp_pbr_action *)arg;
	key = jhash_1word(pbra->table_id, 0x4312abde);
	key = jhash_1word(pbra->fwmark, key);
	return key;
}

int bgp_pbr_action_hash_equal(const void *arg1, const void *arg2)
{
	const struct bgp_pbr_action *r1, *r2;

	r1 = (const struct bgp_pbr_action *)arg1;
	r2 = (const struct bgp_pbr_action *)arg2;

	/* unique value is self calculated
	 * table and fwmark is self calculated
	 * rate is ignored
	 */
	if (r1->vrf_id != r2->vrf_id)
		return 0;

	if (memcmp(&r1->nh, &r2->nh, sizeof(struct nexthop)))
		return 0;
	return 1;
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
	if (bgp->pbr_match_hash) {
		hash_clean(bgp->pbr_match_hash, bgp_pbr_match_free);
		hash_free(bgp->pbr_match_hash);
		bgp->pbr_match_hash = NULL;
	}
	if (bgp->pbr_action_hash) {
		hash_clean(bgp->pbr_action_hash, bgp_pbr_action_free);
		hash_free(bgp->pbr_action_hash);
		bgp->pbr_action_hash = NULL;
	}
	if (bgp->bgp_pbr_cfg == NULL)
		return;
	bgp_pbr_reset(bgp, AFI_IP);
	XFREE(MTYPE_PBR, bgp->bgp_pbr_cfg);
	bgp->bgp_pbr_cfg = NULL;
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

	bgp->bgp_pbr_cfg = XCALLOC(MTYPE_PBR, sizeof(struct bgp_pbr_config));
	bgp->bgp_pbr_cfg->pbr_interface_any_ipv4 = true;
}

void bgp_pbr_print_policy_route(struct bgp_pbr_entry_main *api)
{
	int i = 0;
	char return_string[512];
	char *ptr = return_string;
	char buff[64];
	int nb_items = 0;

	ptr += sprintf(ptr, "MATCH : ");
	if (api->match_bitmask & PREFIX_SRC_PRESENT) {
		struct prefix *p = &(api->src_prefix);

		ptr += sprintf(ptr, "@src %s", prefix2str(p, buff, 64));
		INCREMENT_DISPLAY(ptr, nb_items);
	}
	if (api->match_bitmask & PREFIX_DST_PRESENT) {
		struct prefix *p = &(api->dst_prefix);

		INCREMENT_DISPLAY(ptr, nb_items);
		ptr += sprintf(ptr, "@dst %s", prefix2str(p, buff, 64));
	}

	if (api->match_protocol_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_protocol_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->protocol[i],
					i > 0 ? NULL : "@proto ");

	if (api->match_src_port_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_src_port_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->src_port[i],
					i > 0 ? NULL : "@srcport ");

	if (api->match_dst_port_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_dst_port_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->dst_port[i],
					 i > 0 ? NULL : "@dstport ");

	if (api->match_port_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_port_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->port[i],
					 i > 0 ? NULL : "@port ");

	if (api->match_icmp_type_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_icmp_type_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->icmp_type[i],
					 i > 0 ? NULL : "@icmptype ");

	if (api->match_icmp_code_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_icmp_code_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->icmp_code[i],
					 i > 0 ? NULL : "@icmpcode ");

	if (api->match_packet_length_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_packet_length_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->packet_length[i],
					 i > 0 ? NULL : "@plen ");

	if (api->match_dscp_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_dscp_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->dscp[i],
					i > 0 ? NULL : "@dscp ");

	if (api->match_tcpflags_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_tcpflags_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->tcpflags[i],
					 i > 0 ? NULL : "@tcpflags ");

	if (api->match_fragment_num)
		INCREMENT_DISPLAY(ptr, nb_items);
	for (i = 0; i < api->match_fragment_num; i++)
		ptr += sprintf_bgp_pbr_match_val(ptr, &api->fragment[i],
					 i > 0 ? NULL : "@fragment ");
	if (!nb_items)
		ptr = return_string;
	else
		ptr += sprintf(ptr, "; ");
	if (api->action_num)
		ptr += sprintf(ptr, "SET : ");
	nb_items = 0;
	for (i = 0; i < api->action_num; i++) {
		switch (api->actions[i].action) {
		case ACTION_TRAFFICRATE:
			INCREMENT_DISPLAY(ptr, nb_items);
			ptr += sprintf(ptr, "@set rate %f",
				       api->actions[i].u.r.rate);
			break;
		case ACTION_TRAFFIC_ACTION:
			INCREMENT_DISPLAY(ptr, nb_items);
			ptr += sprintf(ptr, "@action ");
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_TERMINATE)
				ptr += sprintf(ptr,
					       " terminate (apply filter(s))");
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_DISTRIBUTE)
				ptr += sprintf(ptr, " distribute");
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_SAMPLE)
				ptr += sprintf(ptr, " sample");
			break;
		case ACTION_REDIRECT_IP:
			INCREMENT_DISPLAY(ptr, nb_items);
			char local_buff[INET_ADDRSTRLEN];

			if (inet_ntop(AF_INET,
				      &api->actions[i].u.zr.redirect_ip_v4,
				      local_buff, INET_ADDRSTRLEN) != NULL)
				ptr += sprintf(ptr,
					  "@redirect ip nh %s", local_buff);
			break;
		case ACTION_REDIRECT:
			INCREMENT_DISPLAY(ptr, nb_items);
			ptr += sprintf(ptr, "@redirect vrf %u",
				       api->actions[i].u.redirect_vrf);
			break;
		case ACTION_MARKING:
			INCREMENT_DISPLAY(ptr, nb_items);
			ptr += sprintf(ptr, "@set dscp %u",
				  api->actions[i].u.marking_dscp);
			break;
		default:
			break;
		}
	}
	zlog_info("%s", return_string);
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
		if (bpme->bgp_info) {
			struct bgp_info *bgp_info;
			struct bgp_info_extra *extra;

			/* unlink bgp_info to bpme */
			bgp_info = (struct bgp_info *)bpme->bgp_info;
			extra = bgp_info_extra_get(bgp_info);
			extra->bgp_fs_pbr = NULL;
			bpme->bgp_info = NULL;
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
	if (bpa->refcnt == 0) {
		if (bpa->installed && bpa->table_id != 0) {
			bgp_send_pbr_rule_action(bpa, false);
			bgp_zebra_announce_default(bpa->bgp, &(bpa->nh),
						   AFI_IP,
						   bpa->table_id,
						   false);
			bpa->installed = false;
		}
	}
}

struct bgp_pbr_match_entry_remain {
	struct bgp_pbr_match_entry *bpme_to_match;
	struct bgp_pbr_match_entry *bpme_found;
};

static int bgp_pbr_get_remaining_entry(struct hash_backet *backet, void *arg)
{
	struct bgp_pbr_match *bpm = (struct bgp_pbr_match *)backet->data;
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
	    bpm_temp->flags != bpm->flags)
		return HASHWALK_CONTINUE;

	/* look for remaining bpme */
	bpmer->bpme_found = hash_lookup(bpm->entry_hash, bpme);
	if (!bpmer->bpme_found)
		return HASHWALK_CONTINUE;
	return HASHWALK_ABORT;
}

static void bgp_pbr_policyroute_remove_from_zebra_unit(struct bgp *bgp,
				struct bgp_info *binfo,
				struct bgp_pbr_filter *bpf)
{
	struct bgp_pbr_match temp;
	struct bgp_pbr_match_entry temp2;
	struct bgp_pbr_match *bpm;
	struct bgp_pbr_match_entry *bpme;
	struct bgp_pbr_match_entry_remain bpmer;
	struct bgp_pbr_range_port *src_port;
	struct bgp_pbr_range_port *dst_port;
	struct bgp_pbr_range_port *pkt_len;

	if (!bpf)
		return;
	src_port = bpf->src_port;
	dst_port = bpf->dst_port;
	pkt_len = bpf->pkt_len;

	/* as we don't know information from EC
	 * look for bpm that have the bpm
	 * with vrf_id characteristics
	 */
	memset(&temp2, 0, sizeof(temp2));
	memset(&temp, 0, sizeof(temp));
	if (bpf->src) {
		temp.flags |= MATCH_IP_SRC_SET;
		prefix_copy(&temp2.src, bpf->src);
	} else
		temp2.src.family = AF_INET;
	if (bpf->dst) {
		temp.flags |= MATCH_IP_DST_SET;
		prefix_copy(&temp2.dst, bpf->dst);
	} else
		temp2.dst.family = AF_INET;
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
		temp.vrf_id = 0;
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
		return FLOWSPEC_PKT_LEN;
	if (type_entry == FLOWSPEC_PKT_LEN)
		return FLOWSPEC_FRAGMENT;
	if (type_entry == FLOWSPEC_FRAGMENT)
		return FLOWSPEC_ICMP_TYPE;
	return 0;
}

static void  bgp_pbr_icmp_action(struct bgp *bgp,
				 struct bgp_info *binfo,
				 struct bgp_pbr_filter *bpf,
				 struct bgp_pbr_or_filter *bpof,
				 bool add,
				 struct nexthop *nh,
				 float *rate)
{
	struct bgp_pbr_range_port srcp, dstp;
	struct bgp_pbr_val_mask *icmp_type, *icmp_code;
	struct listnode *tnode, *cnode;

	if (!bpf)
		return;
	if (bpf->protocol != IPPROTO_ICMP)
		return;
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
				bgp_pbr_policyroute_add_to_zebra_unit(bgp, binfo,
							bpf, nh, rate);
			else
				bgp_pbr_policyroute_remove_from_zebra_unit(
							bgp, binfo, bpf);
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
							bgp, binfo,
							bpf, nh, rate);
			else
				bgp_pbr_policyroute_remove_from_zebra_unit(bgp,
							      binfo, bpf);
			continue;
		}
		for (ALL_LIST_ELEMENTS_RO(bpof->icmp_code, cnode, icmp_code)) {
			dstp.min_port = icmp_code->val;
			if (add)
				bgp_pbr_policyroute_add_to_zebra_unit(
							bgp, binfo,
							bpf, nh, rate);
			else
				bgp_pbr_policyroute_remove_from_zebra_unit(
							   bgp, binfo, bpf);
		}
	}
}

static void bgp_pbr_policyroute_remove_from_zebra_recursive(struct bgp *bgp,
			struct bgp_info *binfo,
			struct bgp_pbr_filter *bpf,
			struct bgp_pbr_or_filter *bpof,
			uint8_t type_entry)
{
	struct listnode *node, *nnode;
	struct bgp_pbr_val_mask *valmask;
	uint8_t next_type_entry;
	struct list *orig_list;
	struct bgp_pbr_val_mask **target_val;

	if (type_entry == 0)
		return bgp_pbr_policyroute_remove_from_zebra_unit(bgp,
							binfo, bpf);
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
		bgp_pbr_icmp_action(bgp, binfo, bpf, bpof, false, NULL, NULL);
		return;
	} else {
		return bgp_pbr_policyroute_remove_from_zebra_recursive(bgp,
							binfo,
							bpf, bpof,
							next_type_entry);
	}
	for (ALL_LIST_ELEMENTS(orig_list, node, nnode, valmask)) {
		*target_val = valmask;
		bgp_pbr_policyroute_remove_from_zebra_recursive(bgp, binfo,
							bpf, bpof,
							next_type_entry);
	}
}

static void bgp_pbr_policyroute_remove_from_zebra(struct bgp *bgp,
				struct bgp_info *binfo,
				struct bgp_pbr_filter *bpf,
				struct bgp_pbr_or_filter *bpof)
{
	if (!bpof)
		return bgp_pbr_policyroute_remove_from_zebra_unit(bgp,
								  binfo,
								  bpf);
	if (bpof->tcpflags)
		bgp_pbr_policyroute_remove_from_zebra_recursive(bgp, binfo,
							bpf, bpof,
							FLOWSPEC_TCP_FLAGS);
	else if (bpof->dscp)
		bgp_pbr_policyroute_remove_from_zebra_recursive(bgp, binfo,
							bpf, bpof,
							FLOWSPEC_DSCP);
	else if (bpof->pkt_len)
		bgp_pbr_policyroute_remove_from_zebra_recursive(bgp, binfo,
							bpf, bpof,
							FLOWSPEC_PKT_LEN);
	else if (bpof->fragment)
		bgp_pbr_policyroute_remove_from_zebra_recursive(bgp, binfo,
							bpf, bpof,
							FLOWSPEC_FRAGMENT);
	else if (bpof->icmp_type || bpof->icmp_code)
		bgp_pbr_policyroute_remove_from_zebra_recursive(bgp, binfo,
							bpf, bpof,
							FLOWSPEC_ICMP_TYPE);
	else
		bgp_pbr_policyroute_remove_from_zebra_unit(bgp, binfo, bpf);
	/* flush bpof */
	if (bpof->tcpflags)
		list_delete_all_node(bpof->tcpflags);
	if (bpof->dscp)
		list_delete_all_node(bpof->dscp);
	if (bpof->pkt_len)
		list_delete_all_node(bpof->pkt_len);
	if (bpof->fragment)
		list_delete_all_node(bpof->fragment);
}

static void bgp_pbr_policyroute_add_to_zebra_unit(struct bgp *bgp,
				     struct bgp_info *binfo,
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
	struct bgp_pbr_range_port *src_port;
	struct bgp_pbr_range_port *dst_port;
	struct bgp_pbr_range_port *pkt_len;

	if (!bpf)
		return;
	src_port = bpf->src_port;
	dst_port = bpf->dst_port;
	pkt_len = bpf->pkt_len;

	if (BGP_DEBUG(zebra, ZEBRA)) {
		char bufsrc[64], bufdst[64];
		char buffer[64];
		int remaining_len = 0;
		char protocol_str[16];

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
				 src_port->min_port, dst_port->min_port);
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
		zlog_info("BGP: adding FS PBR from %s to %s, %s %s",
			  bpf->src == NULL ? "<all>" :
			  prefix2str(bpf->src, bufsrc, sizeof(bufsrc)),
			  bpf->dst == NULL ? "<all>" :
			  prefix2str(bpf->dst, bufdst, sizeof(bufdst)),
			  protocol_str, buffer);
	}
	/* look for bpa first */
	memset(&temp3, 0, sizeof(temp3));
	if (rate)
		temp3.rate = *rate;
	if (nh)
		memcpy(&temp3.nh, nh, sizeof(struct nexthop));
	temp3.vrf_id = bpf->vrf_id;
	bpa = hash_get(bgp->pbr_action_hash, &temp3,
		       bgp_pbr_action_alloc_intern);

	if (bpa->fwmark == 0) {
		/* drop is handled by iptable */
		if (nh && nh->type == NEXTHOP_TYPE_BLACKHOLE) {
			bpa->table_id = 0;
			bpa->installed = true;
		} else {
			bpa->fwmark = bgp_zebra_tm_get_id();
			bpa->table_id = bpa->fwmark;
			bpa->installed = false;
		}
		bpa->bgp = bgp;
		bpa->unique = ++bgp_pbr_action_counter_unique;
		/* 0 value is forbidden */
		bpa->install_in_progress = false;
	}

	/* then look for bpm */
	memset(&temp, 0, sizeof(temp));
	temp.vrf_id = bpf->vrf_id;
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
	if (bpf->fragment) {
		if (bpf->fragment->mask)
			temp.flags |= MATCH_FRAGMENT_INVERSE_SET;
		temp.fragment = bpf->fragment->val;
	}
	temp.action = bpa;
	bpm = hash_get(bgp->pbr_match_hash, &temp,
		       bgp_pbr_match_alloc_intern);

	/* new, then self allocate ipset_name and unique */
	if (bpm && bpm->unique == 0) {
		bpm->unique = ++bgp_pbr_match_counter_unique;
		/* 0 value is forbidden */
		sprintf(bpm->ipset_name, "match%p", bpm);
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
		temp2.src.family = AF_INET;
	if (bpf->dst)
		prefix_copy(&temp2.dst, bpf->dst);
	else
		temp2.dst.family = AF_INET;
	temp2.src_port_min = src_port ? src_port->min_port : 0;
	temp2.dst_port_min = dst_port ? dst_port->min_port : 0;
	temp2.src_port_max = src_port ? src_port->max_port : 0;
	temp2.dst_port_max = dst_port ? dst_port->max_port : 0;
	temp2.proto = bpf->protocol;
	if (bpm)
		bpme = hash_get(bpm->entry_hash, &temp2,
				bgp_pbr_match_entry_alloc_intern);
	if (bpme && bpme->unique == 0) {
		bpme->unique = ++bgp_pbr_match_entry_counter_unique;
		/* 0 value is forbidden */
		bpme->backpointer = bpm;
		bpme->installed = false;
		bpme->install_in_progress = false;
		/* link bgp info to bpme */
		bpme->bgp_info = (void *)binfo;
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
	if (!bpa->installed && !bpa->install_in_progress) {
		bgp_send_pbr_rule_action(bpa, true);
		bgp_zebra_announce_default(bgp, nh,
					   AFI_IP, bpa->table_id, true);
	}

	/* ipset create */
	if (bpm && !bpm->installed)
		bgp_send_pbr_ipset_match(bpm, true);
	/* ipset add */
	if (bpme && !bpme->installed)
		bgp_send_pbr_ipset_entry_match(bpme, true);

	/* iptables */
	if (bpm && !bpm->installed_in_iptable)
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

static void bgp_pbr_policyroute_add_to_zebra_recursive(struct bgp *bgp,
			struct bgp_info *binfo,
			struct bgp_pbr_filter *bpf,
			struct bgp_pbr_or_filter *bpof,
			struct nexthop *nh,
			float *rate,
			uint8_t type_entry)
{
	struct listnode *node, *nnode;
	struct bgp_pbr_val_mask *valmask;
	uint8_t next_type_entry;
	struct list *orig_list;
	struct bgp_pbr_val_mask **target_val;

	if (type_entry == 0)
		return bgp_pbr_policyroute_add_to_zebra_unit(bgp, binfo, bpf,
							     nh, rate);
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
		bgp_pbr_icmp_action(bgp, binfo, bpf, bpof, true, nh, rate);
		return;
	} else {
		return bgp_pbr_policyroute_add_to_zebra_recursive(bgp, binfo,
						bpf, bpof, nh, rate,
						next_type_entry);
	}
	for (ALL_LIST_ELEMENTS(orig_list, node, nnode, valmask)) {
		*target_val = valmask;
		bgp_pbr_policyroute_add_to_zebra_recursive(bgp, binfo,
							bpf, bpof,
							nh, rate,
							next_type_entry);
	}
}

static void bgp_pbr_policyroute_add_to_zebra(struct bgp *bgp,
				     struct bgp_info *binfo,
				     struct bgp_pbr_filter *bpf,
				     struct bgp_pbr_or_filter *bpof,
				     struct nexthop *nh,
				     float *rate)
{
	if (!bpof)
		return bgp_pbr_policyroute_add_to_zebra_unit(bgp, binfo,
							     bpf, nh, rate);
	if (bpof->tcpflags)
		bgp_pbr_policyroute_add_to_zebra_recursive(bgp, binfo,
							   bpf, bpof,
							   nh, rate,
							   FLOWSPEC_TCP_FLAGS);
	else if (bpof->dscp)
		bgp_pbr_policyroute_add_to_zebra_recursive(bgp, binfo,
							   bpf, bpof,
							   nh, rate,
							   FLOWSPEC_DSCP);
	else if (bpof->pkt_len)
		bgp_pbr_policyroute_add_to_zebra_recursive(bgp, binfo,
							   bpf, bpof,
							   nh, rate,
							   FLOWSPEC_PKT_LEN);
	else if (bpof->fragment)
		bgp_pbr_policyroute_add_to_zebra_recursive(bgp, binfo,
							   bpf, bpof,
							   nh, rate,
							   FLOWSPEC_FRAGMENT);
	else if (bpof->icmp_type || bpof->icmp_code)
		bgp_pbr_policyroute_add_to_zebra_recursive(bgp, binfo,
						   bpf, bpof, nh, rate,
						   FLOWSPEC_ICMP_TYPE);
	else
		bgp_pbr_policyroute_add_to_zebra_unit(bgp, binfo, bpf,
						      nh, rate);
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

static void bgp_pbr_handle_entry(struct bgp *bgp,
				struct bgp_info *binfo,
				struct bgp_pbr_entry_main *api,
				bool add)
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

	memset(&nh, 0, sizeof(struct nexthop));
	memset(&bpf, 0, sizeof(struct bgp_pbr_filter));
	memset(&bpof, 0, sizeof(struct bgp_pbr_or_filter));
	if (api->match_bitmask & PREFIX_SRC_PRESENT)
		src = &api->src_prefix;
	if (api->match_bitmask & PREFIX_DST_PRESENT)
		dst = &api->dst_prefix;
	memset(&nh, 0, sizeof(struct nexthop));
	nh.vrf_id = VRF_UNKNOWN;
	if (api->match_protocol_num)
		proto = (uint8_t)api->protocol[0].value;
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
	if (!add)
		return bgp_pbr_policyroute_remove_from_zebra(bgp,
							     binfo,
							     &bpf, &bpof);
	/* no action for add = true */
	for (i = 0; i < api->action_num; i++) {
		switch (api->actions[i].action) {
		case ACTION_TRAFFICRATE:
			/* drop packet */
			if (api->actions[i].u.r.rate == 0) {
				nh.vrf_id = api->vrf_id;
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				bgp_pbr_policyroute_add_to_zebra(bgp, binfo,
								 &bpf, &bpof,
								 &nh, &rate);
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
#if 0
			if (api->actions[i].u.za.filter
			    & TRAFFIC_ACTION_DISTRIBUTE) {
				if (BGP_DEBUG(pbr, PBR)) {
					bgp_pbr_print_policy_route(api);
					zlog_warn("PBR: Distribute action Applies");
				}
				continue_loop = 0;
				/* continue forwarding entry as before
				 * no action
				 */
			}
#endif /* XXX to confirm behaviour of traffic action. for now , ignore */
			/* terminate action: run other filters
			 */
			break;
		case ACTION_REDIRECT_IP:
			nh.type = NEXTHOP_TYPE_IPV4;
			nh.gate.ipv4.s_addr =
				api->actions[i].u.zr.redirect_ip_v4.s_addr;
			nh.vrf_id = api->vrf_id;
			bgp_pbr_policyroute_add_to_zebra(bgp, binfo,
							 &bpf, &bpof,
							 &nh, &rate);
			/* XXX combination with REDIRECT_VRF
			 * + REDIRECT_NH_IP not done
			 */
			continue_loop = 0;
			break;
		case ACTION_REDIRECT:
			nh.vrf_id = api->actions[i].u.redirect_vrf;
			nh.type = NEXTHOP_TYPE_IPV4;
			bgp_pbr_policyroute_add_to_zebra(bgp, binfo,
							 &bpf, &bpof,
							 &nh, &rate);
			continue_loop = 0;
			break;
		case ACTION_MARKING:
			if (BGP_DEBUG(pbr, PBR)) {
				bgp_pbr_print_policy_route(api);
				zlog_warn("PBR: Set DSCP %u Ignored",
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

void bgp_pbr_update_entry(struct bgp *bgp, struct prefix *p,
			 struct bgp_info *info, afi_t afi, safi_t safi,
			 bool nlri_update)
{
	struct bgp_pbr_entry_main api;
	struct bgp_info_extra *extra = bgp_info_extra_get(info);

	if (afi == AFI_IP6)
		return; /* IPv6 not supported */
	if (safi != SAFI_FLOWSPEC)
		return; /* not supported */
	/* Make Zebra API structure. */
	memset(&api, 0, sizeof(api));
	api.vrf_id = bgp->vrf_id;
	api.afi = afi;

	if (!bgp_zebra_tm_chunk_obtained()) {
		if (BGP_DEBUG(pbr, PBR_ERROR))
			zlog_err("%s: table chunk not obtained yet",
				 __func__);
		return;
	}
	/* already installed */
	if (nlri_update && extra->bgp_fs_pbr) {
		if (BGP_DEBUG(pbr, PBR_ERROR))
			zlog_err("%s: entry %p already installed in bgp pbr",
				 __func__, info);
		return;
	}

	if (bgp_pbr_build_and_validate_entry(p, info, &api) < 0) {
		if (BGP_DEBUG(pbr, PBR_ERROR))
			zlog_err("%s: cancel updating entry %p in bgp pbr",
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

	if (!bgp_pbr_cfg || afi != AFI_IP)
		return;
	head = &(bgp_pbr_cfg->ifaces_by_name_ipv4);

	while (!RB_EMPTY(bgp_pbr_interface_head, head)) {
		pbr_if = RB_ROOT(bgp_pbr_interface_head, head);
		RB_REMOVE(bgp_pbr_interface_head, head, pbr_if);
		XFREE(MTYPE_TMP, pbr_if);
	}
}
